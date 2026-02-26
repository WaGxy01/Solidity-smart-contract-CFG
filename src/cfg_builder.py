from collections import deque
from typing import Dict, List, Set, Tuple, Optional
from src.bb import build_basic_blocks, BasicBlock, Instruction, TERMINATORS
import time

# 终止指令（无后继）
TERMINATING_OPS = frozenset({
    0x00,  # STOP
    0xf3,  # RETURN
    0xfd,  # REVERT
    0xfe,  # INVALID
    0xff,  # SELFDESTRUCT
})

# 跳转指令
JUMP_OP = 0x56
JUMPI_OP = 0x57

# PUSH指令范围 - 支持PUSH1到PUSH4作为跳转目标
PUSH1_OP = 0x60
PUSH2_OP = 0x61
PUSH3_OP = 0x62
PUSH4_OP = 0x63

# 用于跳转目标的PUSH指令范围（通常是PUSH1-PUSH4足够了）
JUMP_TARGET_PUSH_OPS = frozenset({PUSH1_OP, PUSH2_OP, PUSH3_OP, PUSH4_OP})


class CFGNode:
    """控制流图节点，包装基本块并添加前驱/后继信息"""
    
    def __init__(self, block: BasicBlock):
        self.block = block
        self.block_id = block.block_id
        self.predecessors: Set[int] = set()  # 前驱块地址集合
        self.successors: Set[int] = set()    # 后继块地址集合
        self.used_push_indices: Set[int] = set()  # 已使用的PUSH指令在块内的索引
        
    @property
    def start(self) -> int:
        return self.block.start
    
    @property
    def last_instruction(self) -> Instruction:
        return self.block.last
    
    @property
    def instructions(self) -> List[Instruction]:
        return self.block.instructions
    
    def __repr__(self) -> str:
        pred_str = ', '.join(f'0x{p:x}' for p in sorted(self.predecessors))
        succ_str = ', '.join(f'0x{s:x}' for s in sorted(self.successors))
        return (f"CFGNode 0x{self.block_id:x}:\n"
                f"  Predecessors: [{pred_str}]\n"
                f"  Successors: [{succ_str}]\n"
                f"  Instructions:\n" +
                '\n'.join(f"    {ins}" for ins in self.instructions))
    
    def __lt__(self, other):
        return self.block_id < other.block_id


class ControlFlowGraphBuilder:
    """控制流图构建器"""
    
    def __init__(self, bytecode: bytes):
        self.bytecode = bytecode
        self.basic_blocks = build_basic_blocks(bytecode)
        self.nodes: Dict[int, CFGNode] = {}
        self.valid_targets: Set[int] = set()  # 有效的跳转目标（JUMPDEST位置）
        
        # 全局已使用的PUSH2记录：(block_addr, instruction_index) -> bool
        self.used_push2: Set[Tuple[int, int]] = set()
        
        # 初始化节点
        self._initialize_nodes()
        
    def _initialize_nodes(self):
        """初始化所有CFG节点"""
        for bb in self.basic_blocks:
            node = CFGNode(bb)
            self.nodes[bb.block_id] = node
            # 检查是否为有效跳转目标（以JUMPDEST开始）
            if bb.instructions and bb.instructions[0].op == 0x5b:
                self.valid_targets.add(bb.block_id)
        # 地址0也可能是有效目标（程序入口）
        if 0 in self.nodes:
            self.valid_targets.add(0)
            
    def _get_sorted_block_addresses(self) -> List[int]:
        """获取排序后的基本块地址列表"""
        return sorted(self.nodes.keys())
    
    def _get_next_sequential_block(self, current_addr: int) -> Optional[int]:
        """获取顺序上的下一个基本块地址"""
        addrs = self._get_sorted_block_addresses()
        try:
            idx = addrs.index(current_addr)
            if idx + 1 < len(addrs):
                return addrs[idx + 1]
        except ValueError:
            pass
        return None
    
    def _is_push_jump_target_and_unused(self, block_addr: int, ins_index: int) -> bool:
        """检查指定位置的指令是否为未使用的PUSH（用于跳转目标）"""
        if (block_addr, ins_index) in self.used_push2:
            return False
        node = self.nodes.get(block_addr)
        if node is None or ins_index < 0 or ins_index >= len(node.instructions):
            return False
        ins = node.instructions[ins_index]
        return ins.op in JUMP_TARGET_PUSH_OPS
    
    def _mark_push2_used(self, block_addr: int, ins_index: int):
        """标记PUSH2指令为已使用"""
        self.used_push2.add((block_addr, ins_index))
        
    def _get_push_value(self, block_addr: int, ins_index: int) -> Optional[int]:
        """获取PUSH指令的值（用于跳转目标）"""
        node = self.nodes.get(block_addr)
        if node is None or ins_index < 0 or ins_index >= len(node.instructions):
            return None
        ins = node.instructions[ins_index]
        if ins.op in JUMP_TARGET_PUSH_OPS and ins.arg is not None:
            return ins.arg_int()
        return None
    
    def _is_valid_jump_target(self, addr: int) -> bool:
        """检查地址是否为有效的跳转目标"""
        return addr in self.valid_targets
    
    def _add_edge(self, from_addr: int, to_addr: int):
        """添加CFG边"""
        if from_addr in self.nodes and to_addr in self.nodes:
            self.nodes[from_addr].successors.add(to_addr)
            self.nodes[to_addr].predecessors.add(from_addr)
    
    def _find_push2_in_block(self, block_addr: int, before_index: int = -1) -> List[Tuple[int, int]]:
        """
        在基本块中查找PUSH2指令
        返回: [(指令索引, PUSH2值), ...]，按索引降序排列（离末尾最近的在前）
        """
        node = self.nodes.get(block_addr)
        if node is None:
            return []
        
        results = []
        end_index = before_index if before_index >= 0 else len(node.instructions) - 1
        
        for i in range(end_index, -1, -1):
            ins = node.instructions[i]
            if ins.op == PUSH2_OP:
                val = ins.arg_int()
                if val is not None:
                    results.append((i, val))
        
        return results
    
    def _find_nearest_unused_push2_in_predecessors(
        self, 
        start_block: int,
        exclude_blocks: Set[int] = None
    ) -> List[Tuple[int, int, int, int]]:
        """
        在前驱路径中查找最近的未使用PUSH2
        使用BFS按距离层级查找
        返回: [(block_addr, ins_index, push2_value, distance), ...]
        """
        if exclude_blocks is None:
            exclude_blocks = set()
            
        results = []
        visited = {start_block} | exclude_blocks
        queue = deque()
        
        # 初始化：当前块的所有前驱，距离为1
        for pred_addr in self.nodes[start_block].predecessors:
            if pred_addr not in visited:
                queue.append((pred_addr, 1))
                visited.add(pred_addr)
        
        current_distance = None
        
        while queue:
            block_addr, distance = queue.popleft()
            
            # 如果已经找到了某个距离的结果，且当前距离更远，则停止
            if current_distance is not None and distance > current_distance:
                break
                
            node = self.nodes.get(block_addr)
            if node is None:
                continue
            
            # 在当前块中查找未使用的PUSH2
            push2_list = self._find_push2_in_block(block_addr)
            for ins_index, push2_val in push2_list:
                if not self._is_push2_used(block_addr, ins_index):
                    if push2_val != 0x100:  # 排除0x100
                        results.append((block_addr, ins_index, push2_val, distance))
                        current_distance = distance
            
            # 如果在当前距离层找到了结果，继续处理同距离的其他块
            # 但不再添加更远的前驱
            if current_distance is None:
                for pred_addr in node.predecessors:
                    if pred_addr not in visited:
                        queue.append((pred_addr, distance + 1))
                        visited.add(pred_addr)
        
        return results
    
    def _is_push2_used(self, block_addr: int, ins_index: int) -> bool:
        """检查PUSH2是否已使用"""
        return (block_addr, ins_index) in self.used_push2
    
    def _process_jumpi(self, node: CFGNode):
        """处理JUMPI指令的后继"""
        block_addr = node.block_id
        instructions = node.instructions
        
        # 1. Fall-through：下一个顺序块
        next_block = self._get_next_sequential_block(block_addr)
        if next_block is not None:
            self._add_edge(block_addr, next_block)
        
        # 2. 跳转目标：检查倒数第二条指令是否为未使用的PUSH2
        if len(instructions) >= 2:
            second_last = instructions[-2]
            if second_last.op == PUSH2_OP:
                ins_index = len(instructions) - 2
                if not self._is_push2_used(block_addr, ins_index):
                    jump_target = second_last.arg_int()
                    if jump_target is not None and self._is_valid_jump_target(jump_target):
                        self._add_edge(block_addr, jump_target)
                        self._mark_push2_used(block_addr, ins_index)
    
    def _process_jump(self, node: CFGNode):
        """处理JUMP指令的后继"""
        block_addr = node.block_id
        instructions = node.instructions
        
        # 1. 首先在当前基本块中查找离JUMP最近的PUSH2
        push2_list = self._find_push2_in_block(block_addr, len(instructions) - 2)
        
        for ins_index, push2_val in push2_list:
            if not self._is_push2_used(block_addr, ins_index):
                if push2_val != 0x100 and self._is_valid_jump_target(push2_val):
                    self._add_edge(block_addr, push2_val)
                    self._mark_push2_used(block_addr, ins_index)
                    return  # 找到后返回
        
        # 2. 如果当前块没有找到，反向查找前驱路径
        if node.predecessors:
            candidates = self._find_nearest_unused_push2_in_predecessors(block_addr)
            
            if candidates:
                # 按距离分组
                min_distance = min(c[3] for c in candidates)
                nearest_candidates = [c for c in candidates if c[3] == min_distance]
                
                for pred_addr, ins_index, push2_val, _ in nearest_candidates:
                    if self._is_valid_jump_target(push2_val):
                        self._add_edge(block_addr, push2_val)
                        self._mark_push2_used(pred_addr, ins_index)
    
    def _first_pass(self):
        """第一遍：基本的CFG构建"""
        sorted_addrs = self._get_sorted_block_addresses()
        
        for i, block_addr in enumerate(sorted_addrs):
            node = self.nodes[block_addr]
            last_ins = node.last_instruction
            last_op = last_ins.op
            
            # (1) 非终止/非跳转指令：后继为顺序下一个块
            if last_op not in TERMINATORS:
                next_block = self._get_next_sequential_block(block_addr)
                if next_block is not None:
                    self._add_edge(block_addr, next_block)
            
            # (2) 终止指令：无后继
            elif last_op in TERMINATING_OPS:
                pass  # 不添加任何边
            
            # (3) JUMPI指令
            elif last_op == JUMPI_OP:
                self._process_jumpi(node)
            
            # (4) JUMP指令
            elif last_op == JUMP_OP:
                self._process_jump(node)
    
    def _find_unused_push2_instructions(self) -> List[Tuple[int, int, int]]:
        """
        查找所有未使用的PUSH2指令
        返回: [(block_addr, ins_index, push2_value), ...]
        """
        results = []
        for block_addr in self._get_sorted_block_addresses():
            node = self.nodes[block_addr]
            for i, ins in enumerate(node.instructions):
                if ins.op == PUSH2_OP:
                    if not self._is_push2_used(block_addr, i):
                        val = ins.arg_int()
                        if val is not None:
                            results.append((block_addr, i, val))
        return results
    
    def _find_path_to_terminal(self, start_addr: int, visited: Set[int] = None) -> List[List[int]]:
        """
        从start_addr开始，沿后继路径查找没有后继的基本块
        返回所有路径（每条路径是地址列表）
        """
        if visited is None:
            visited = set()
            
        if start_addr in visited:
            return []
            
        visited.add(start_addr)
        node = self.nodes.get(start_addr)
        
        if node is None:
            return []
        
        # 如果没有后继，这就是终点
        if not node.successors:
            return [[start_addr]]
        
        paths = []
        for succ_addr in node.successors:
            sub_paths = self._find_path_to_terminal(succ_addr, visited.copy())
            for sub_path in sub_paths:
                paths.append([start_addr] + sub_path)
        
        return paths
    
    def _find_nearest_push2_on_path(
        self, 
        path: List[int], 
        terminal_addr: int
    ) -> Optional[Tuple[int, int, int, int]]:
        """
        在路径上反向查找离terminal_addr最近的未使用PUSH2
        返回: (block_addr, ins_index, push2_value, distance) 或 None
        """
        # 从路径末尾（terminal）开始反向查找
        try:
            terminal_idx = path.index(terminal_addr)
        except ValueError:
            return None
        
        # 从terminal前一个块开始查找
        for dist, i in enumerate(range(terminal_idx - 1, -1, -1), start=1):
            block_addr = path[i]
            push2_list = self._find_push2_in_block(block_addr)
            
            for ins_index, push2_val in push2_list:
                if not self._is_push2_used(block_addr, ins_index):
                    if push2_val != 0x100:
                        return (block_addr, ins_index, push2_val, dist)
        
        return None
    
    def _second_pass(self):
        """
        第二遍：处理未使用的PUSH2指令
        找到PUSH2所在块的后继路径上没有后继的块，
        反向查找最近的PUSH2作为该块的后继
        """
        changed = True
        iterations = 0
        max_iterations = 100  # 防止无限循环
        
        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            
            unused_push2_list = self._find_unused_push2_instructions()
            
            for push2_block_addr, push2_ins_index, push2_val in unused_push2_list:
                # 跳过已被使用的
                if self._is_push2_used(push2_block_addr, push2_ins_index):
                    continue
                
                # 从PUSH2所在块开始，沿后继路径查找
                paths = self._find_path_to_terminal(push2_block_addr, set())
                
                if not paths:
                    continue
                
                for path in paths:
                    if len(path) < 2:
                        continue
                    
                    terminal_addr = path[-1]
                    terminal_node = self.nodes.get(terminal_addr)
                    
                    if terminal_node is None:
                        continue
                    
                    # 检查终点是否真的没有后继（或以终止指令结束）
                    if terminal_node.successors:
                        continue
                    
                    # 检查是否以终止指令结束（不需要添加后继）
                    if terminal_node.last_instruction.op in TERMINATING_OPS:
                        continue
                    
                    # 在路径上反向查找最近的未使用PUSH2
                    result = self._find_nearest_push2_on_path(path, terminal_addr)
                    
                    if result:
                        block_addr, ins_index, target_val, _ = result
                        
                        if self._is_valid_jump_target(target_val):
                            # 添加边
                            self._add_edge(terminal_addr, target_val)
                            self._mark_push2_used(block_addr, ins_index)
                            changed = True
    
    def build(self) -> Dict[int, CFGNode]:
        """构建控制流图"""
        print(f"开始构建CFG，共 {len(self.basic_blocks)} 个基本块")
        print(f"有效跳转目标: {sorted(self.valid_targets)}")
        
        # 第一遍
        print("\n=== 第一遍：基本CFG构建 ===")
        self._first_pass()
        
        # 统计第一遍结果
        edges_count = sum(len(n.successors) for n in self.nodes.values())
        print(f"第一遍完成，共 {edges_count} 条边")
        
        # 第二遍
        print("\n=== 第二遍：处理未使用的PUSH2 ===")
        self._second_pass()
        
        # 统计最终结果
        edges_count = sum(len(n.successors) for n in self.nodes.values())
        print(f"第二遍完成，共 {edges_count} 条边")
        
        return self.nodes
    
    def to_dot(self) -> str:
        """生成DOT格式的图形表示"""
        lines = ['digraph CFG {']
        lines.append('    rankdir=TB;')
        lines.append('    node [shape=box, fontname="Courier"];')
        lines.append('')
        
        for addr in self._get_sorted_block_addresses():
            node = self.nodes[addr]
            
            # 构建节点标签
            ins_text = '\\l'.join(
                f'{ins.addr:04x}: {ins.name}' + 
                (f' 0x{ins.arg_int():x}' if ins.arg else '')
                for ins in node.instructions
            )
            
            pred_str = ', '.join(f'{p:x}' for p in sorted(node.predecessors)) or 'None'
            succ_str = ', '.join(f'{s:x}' for s in sorted(node.successors)) or 'None'
            
            label = f'Block 0x{addr:x}\\lPred: [{pred_str}]\\lSucc: [{succ_str}]\\l{ins_text}\\l'
            
            # 根据最后一条指令着色
            last_op = node.last_instruction.op
            if last_op in TERMINATING_OPS:
                color = 'red'
            elif last_op == JUMP_OP:
                color = 'blue'
            elif last_op == JUMPI_OP:
                color = 'green'
            else:
                color = 'black'
            
            lines.append(f'    n{addr} [label="{label}", color={color}];')
        
        lines.append('')
        
        # 添加边
        for addr in self._get_sorted_block_addresses():
            node = self.nodes[addr]
            for succ in sorted(node.successors):
                lines.append(f'    n{addr} -> n{succ};')
        
        lines.append('}')
        return '\n'.join(lines)
    
    def print_cfg(self):
        """打印CFG信息"""
        print("\n" + "="*60)
        print("控制流图")
        print("="*60)
        
        for addr in self._get_sorted_block_addresses():
            node = self.nodes[addr]
            print(f"\n基本块 0x{addr:x}:")
            print(f"  前驱: {[f'0x{p:x}' for p in sorted(node.predecessors)]}")
            print(f"  后继: {[f'0x{s:x}' for s in sorted(node.successors)]}")
            print("  指令:")

            for ins in node.instructions:
                used_marker = ""
                if ins.op == PUSH2_OP:
                    idx = node.instructions.index(ins)
                    if self._is_push2_used(addr, idx):
                        used_marker = " [USED]"
                print(f"    {ins}{used_marker}")



def build_cfg_from_bytecode(hex_bytecode: str) -> ControlFlowGraphBuilder:
    """从十六进制字节码字符串构建CFG"""
    hex_code = hex_bytecode.strip().replace('\n', '').replace(' ', '')
    if hex_code.startswith('0x'):
        hex_code = hex_code[2:]
    bytecode = bytes.fromhex(hex_code)
    
    builder = ControlFlowGraphBuilder(bytecode)
    builder.build()
    return builder


# ─────────────────────────────────────────────────────────────
# 测试代码
# ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    # 测试用的字节码（来自bb.py的示例）
    start_time = time.time()
    HEX_BYTECODE = """
        6080604052600436106100555760003560e01c806313af40351461005a5780639003adfe146100ab578063a2f9eac6146100d6578063a60f35881461018b578063b69ef8a8146101b6578063d014c01f146101e1575b600080fd5b34801561006657600080fd5b506100a96004803603602081101561007d57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610225565b005b3480156100b757600080fd5b506100c06102c0565b6040518082815260200191505060405180910390f35b3480156100e257600080fd5b5061010f600480360360208110156100f957600080fd5b81019080803590602001909291905050506102c6565b604051808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018381526020018273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001935050505060405180910390f35b34801561019757600080fd5b506101a061033d565b6040518082815260200191505060405180910390f35b3480156101c257600080fd5b506101cb610343565b6040518082815260200191505060405180910390f35b610223600480360360208110156101f757600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610349565b005b600460009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614156102bd5780600460006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b50565b60025481565b600081815481106102d357fe5b90600052602060002090600302016000915090508060000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060010154908060020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905083565b60015481565b60035481565b66b1a2bc2ec500003410156103a4573373ffffffffffffffffffffffffffffffffffffffff166108fc349081150290604051600060405180830381858888f1935050505015801561039e573d6000803e3d6000fd5b506106c5565b600068d8d726b7177a80000034111561041a573373ffffffffffffffffffffffffffffffffffffffff166108fc68d8d726b7177a80000034039081150290604051600060405180830381858888f19350505050158015610408573d6000803e3d6000fd5b5068d8d726b7177a800000905061041e565b3490505b600080805490509050600160008181805490500191508161043f91906106c8565b50336000828154811061044e57fe5b906000526020600020906003020160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555081600082815481106104ab57fe5b906000526020600020906003020160010181905550600060026000828254019250508190555060008260025401905060006064605d8302816104e957fe5b0490508082039150600460009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f19350505050158015610559573d6000803e3d6000fd5b508473ffffffffffffffffffffffffffffffffffffffff166108fc839081150290604051600060405180830381858888f193505050501580156105a0573d6000803e3d6000fd5b5060006002819055505b60b460646000600154815481106105bd57fe5b906000526020600020906003020160010154816105d657fe5b040260035411156106c057600060b460646000600154815481106105f657fe5b9060005260206000209060030201600101548161060f57fe5b0402905060006001548154811061062257fe5b906000526020600020906003020160000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f19350505050158015610699573d6000803e3d6000fd5b508060036000828254039250508190555060018060008282540192505081905550506105aa565b505050505b50565b8154818355818111156106f5576003028160030283600052602060002091820191016106f491906106fa565b5b505050565b61076c91905b8082111561076857600080820160006101000a81549073ffffffffffffffffffffffffffffffffffffffff021916905560018201600090556002820160006101000a81549073ffffffffffffffffffffffffffffffffffffffff021916905550600301610700565b5090565b9056fea265627a7a723058207d24fb6cee0277753f22c194da19771862c8f7cda89b1db99bdab0095e6f94d364736f6c634300050a0032

        """
    
    builder = build_cfg_from_bytecode(HEX_BYTECODE)
    builder.print_cfg()

    elapsed_time = time.time() - start_time
    print(f"漏洞检测完成，耗时: {elapsed_time:.2f} 秒")
