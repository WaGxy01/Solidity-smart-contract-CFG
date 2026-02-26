opcodes = {
    0x00: ['STOP'],
    0x01: ['ADD'],
    0x02: ['MUL'],
    0x03: ['SUB'],
    0x04: ['DIV'],
    0x05: ['SDIV'],
    0x06: ['MOD'],
    0x07: ['SMOD'],
    0x08: ['ADDMOD'],
    0x09: ['MULMOD'],
    0x0a: ['EXP'],
    0x0b: ['SIGNEXTEND'],
    0x10: ['LT'],
    0x11: ['GT'],
    0x12: ['SLT'],
    0x13: ['SGT'],
    0x14: ['EQ'],
    0x15: ['ISZERO'],
    0x16: ['AND'],
    0x17: ['OR'],
    0x18: ['XOR'],
    0x19: ['NOT'],
    0x1a: ['BYTE'],
    0x1b: ['SHL'],
    0x1c: ['SHR'],
    0x1d: ['SAR'],
    0x1e: ['CLZ'],
    0x20: ['KECCAK256'],
    0x30: ['ADDRESS'],
    0x31: ['BALANCE'],
    0x32: ['ORIGIN'],
    0x33: ['CALLER'],
    0x34: ['CALLVALUE'],
    0x35: ['CALLDATALOAD'],
    0x36: ['CALLDATASIZE'],
    0x37: ['CALLDATACOPY'],
    0x38: ['CODESIZE'],
    0x39: ['CODECOPY'],
    0x3a: ['GASPRICE'],
    0x3b: ['EXTCODESIZE'],
    0x3c: ['EXTCODECOPY'],
    0x3d: ['RETURNDATASIZE'],
    0x3e: ['RETURNDATACOPY'],
    0x40: ['BLOCKHASH'],
    0x41: ['COINBASE'],
    0x42: ['TIMESTAMP'],
    0x43: ['NUMBER'],
    0x44: ['PREVRANDAO'],
    0x46: ['CHAINID'],
    0x47: ['SELFBALANCE'],
    0x48: ['BASEFEE'],
    0x49: ['BLOBHASH'],
    0x4a: ['BLOBBASEFEE'],
    0x50: ['POP'],
    0x51: ['MLOAD'],
    0x52: ['MSTORE'],
    0x53: ['MSTORE8'],
    0x54: ['SLOAD'],
    0x55: ['SSTORE'],
    0x56: ['JUMP'],
    0x57: ['JUMPI'],
    0x58: ['PC'],
    0x59: ['MSIZE'],
    0x5a: ['GAS'],
    0x5b: ['JUMPDEST'],
    0x5c: ['TLOAD'],
    0x5d: ['TSTORE'],
    0x5e: ['MCOPY'],
    0x5f: ['PUSH0'],
    0xa0: ['LOG0'],
    0xa1: ['LOG1'],
    0xa2: ['LOG2'],
    0xa3: ['LOG3'],
    0xa4: ['LOG4'],
    0xe1: ['SLOADBYTES'],
    0xe2: ['SSTOREBYTES'],
    0xe3: ['SSIZE'],
    0xf0: ['CREATE'],
    0xf1: ['CALL'],
    0xf2: ['CALLCODE'],
    0xf3: ['RETURN'],
    0xf4: ['DELEGATECALL'],
    0xf5: ['CREATE2'],
    0xfa: ['STATICCALL'],
    0xfd: ['REVERT'],
    0xfe: ['INVALID'],
    0xff: ['SELFDESTRUCT'],
}

for i in range(1, 33):
    opcodes[0x5f + i] = ['PUSH' + str(i)]

for i in range(1, 17):
    opcodes[0x7f + i] = ['DUP' + str(i)]
    opcodes[0x8f + i] = ['SWAP' + str(i)]


# ─────────────────────────────────────────────────────────────
# 终止指令集合
# ─────────────────────────────────────────────────────────────

TERMINATORS = frozenset({
    0x00,  # STOP
    0x56,  # JUMP
    0x57,  # JUMPI
    0xf3,  # RETURN
    0xfd,  # REVERT
    0xfe,  # INVALID
    0xff,  # SELFDESTRUCT
})


# ─────────────────────────────────────────────────────────────
# Instruction：单条 EVM 指令
# ─────────────────────────────────────────────────────────────

class Instruction:
    """
    单条 EVM 指令。

    属性：
        addr      (int)        : 指令在字节码中的字节偏移
        op        (int)        : 操作码字节值
        name      (str)        : 操作码助记符，如 'PUSH1'、'JUMPI'
        arg       (bytes|None) : PUSH 指令的立即数字节；其余指令为 None
        next_addr (int)        : 本指令之后下一条指令的字节偏移
    """

    def __init__(self, addr: int, op: int, arg: bytes | None):
        self.addr = addr
        self.op   = op
        self.arg  = arg

        info      = opcodes.get(op)
        self.name = info[0] if info else f'UNKNOWN_0x{op:02x}'

        # next_addr：跳过当前指令本身（1字节）及 PUSH 立即数字节
        if 0x60 <= op <= 0x7f:          # PUSH1~PUSH32
            self.next_addr = addr + 1 + (op - 0x5f)
        else:                            # 其余指令（含 PUSH0）均为单字节
            self.next_addr = addr + 1

    def arg_int(self) -> int | None:
        """将 PUSH 立即数解析为整数，非 PUSH 指令返回 None。"""
        return int.from_bytes(self.arg, byteorder='big') if self.arg is not None else None

    def __repr__(self) -> str:
        if self.arg is not None:
            return f'0x{self.addr:x}: {self.name} 0x{self.arg_int():x}'
        return f'0x{self.addr:x}: {self.name}'


# ─────────────────────────────────────────────────────────────
# BasicBlock：基本块
# ─────────────────────────────────────────────────────────────

class BasicBlock:
    """
    基本块。

    属性：
        block_id     (int)             : 基本块编号 = 第一条指令的字节偏移
        instructions (list[Instruction]): 块内有序指令列表
    """

    def __init__(self, instructions: list):
        assert instructions, "BasicBlock must contain at least one instruction"
        self.instructions = instructions
        self.block_id     = instructions[0].addr   # 第一条指令地址作为块号

    @property
    def start(self) -> int:
        """块起始地址（与 block_id 相同）。"""
        return self.block_id

    @property
    def end(self) -> int:
        """块最后一条指令的地址。"""
        return self.instructions[-1].addr

    @property
    def last(self) -> Instruction:
        """块最后一条指令。"""
        return self.instructions[-1]

    def __repr__(self) -> str:
        lines = [f'BasicBlock 0x{self.block_id:x}:']
        for ins in self.instructions:
            lines.append(f'    {ins}')
        return '\n'.join(lines)

    def __lt__(self, other):
        return self.block_id < other.block_id


# ─────────────────────────────────────────────────────────────
# disassemble_from：从指定偏移反汇编一个基本块的指令序列
# ─────────────────────────────────────────────────────────────

def disassemble_from(code: bytes, start: int) -> list:
    """
    从 start 偏移开始顺序解码指令，直到遇到块边界为止。

    返回该基本块的 Instruction 列表（至少含一条指令）。
    """
    instructions = []
    i = start

    while i < len(code):
        op  = code[i]
        arg = None

        # 未知操作码：停止解析
        if op not in opcodes:
            break

        # 解析 PUSH1~PUSH32 的立即数
        if 0x60 <= op <= 0x7f:
            arg_len = op - 0x5f                      # PUSH1→1字节, PUSH32→32字节
            arg     = code[i + 1: i + 1 + arg_len]
            if len(arg) < arg_len:                   # 立即数不完整时补零
                arg = arg + b'\x00' * (arg_len - len(arg))

        ins = Instruction(i, op, arg)
        instructions.append(ins)

        # ── 块结束条件 1：当前指令是终止指令 ──
        if op in TERMINATORS:
            break

        # 移动到下一条指令位置
        i = ins.next_addr

        # ── 块结束条件 2：下一条指令是 JUMPDEST → 当前块到此结束 ──
        if i < len(code) and code[i] == 0x5b:
            break

    return instructions


# ─────────────────────────────────────────────────────────────
# build_basic_blocks：主入口，构建所有基本块
# ─────────────────────────────────────────────────────────────

def build_basic_blocks(code: bytes) -> list:
    """
    对整段字节码进行基本块划分。

    步骤：
      1. 扫描字节码，收集所有 leader 地址：
           - 位置 0
           - 每个 JUMPDEST 的位置
           - 每个 JUMPI 之后的 fall-through 位置
      2. 对每个 leader 调用 disassemble_from，生成 BasicBlock。
      3. 按地址升序排序后返回。

    Args:
        code (bytes): EVM 字节码

    Returns:
        list[BasicBlock]: 按起始地址升序排列的基本块列表
    """
    if not code:
        return []

    # ── 步骤 1：收集所有 leader ──
    leaders = {0}   # 位置 0 始终是 leader

    i = 0
    while i < len(code):
        op = code[i]

        if op == 0x5b:
            # JUMPDEST 本身是 leader
            leaders.add(i)

        elif op == 0x57:
            # JUMPI 的 fall-through（下一字节）是 leader
            fall_through = i + 1
            if fall_through < len(code):
                leaders.add(fall_through)

        # 跳过 PUSH 立即数，避免误把立即数字节当作操作码
        if 0x60 <= op <= 0x7f:
            i += 1 + (op - 0x5f)
        else:
            i += 1

    # ── 步骤 2：对每个 leader 生成基本块 ──
    blocks = []
    for leader in sorted(leaders):
        if leader >= len(code):
            continue
        instructions = disassemble_from(code, leader)
        if instructions:
            blocks.append(BasicBlock(instructions))

    # ── 步骤 3：升序返回 ──
    blocks.sort()
    return blocks


# ─────────────────────────────────────────────────────────────
# 命令行调试入口
# ─────────────────────────────────────────────────────────────
'''
if __name__ == '__main__':
    # ── 在此处粘贴你的字节码（十六进制字符串，有无 0x 前缀均可）──
    HEX_BYTECODE = """
        6080604052600436106100345760003560e01c806327e235e3146100395780632e1a7d4d1461009e578063d0e30db0146100d9575b600080fd5b34801561004557600080fd5b506100886004803603602081101561005c57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506100e3565b6040518082815260200191505060405180910390f35b3480156100aa57600080fd5b506100d7600480360360208110156100c157600080fd5b81019080803590602001909291905050506100fb565b005b6100e16102db565b005b60006020528060005260406000206000915090505481565b806000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410156101af576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260148152602001807f496e73756666696369656e742062616c616e636500000000000000000000000081525060200191505060405180910390fd5b60003373ffffffffffffffffffffffffffffffffffffffff168260405180600001905060006040518083038185875af1925050503d806000811461020f576040519150601f19603f3d011682016040523d82523d6000602084013e610214565b606091505b505090508061028b576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600f8152602001807f5472616e73666572206661696c6564000000000000000000000000000000000081525060200191505060405180910390fd5b816000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825403925050819055505050565b346000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828254019250508190555056fea2646970667358221220585b2ea8b858aa6ddc51fa575d71057a0c4d82052e469e5ce375d5141990154964736f6c63430007000033
    """
    # ────────────────────────────────────────────────────────────

    hex_code = HEX_BYTECODE.strip().replace('\n', '').replace(' ', '').removeprefix('0x')
    bytecode = bytes.fromhex(hex_code)

    basic_blocks = build_basic_blocks(bytecode)
    print(f"共生成 {len(basic_blocks)} 个基本块：\n")
    for bb in basic_blocks:
        print(bb)
        print()
'''






