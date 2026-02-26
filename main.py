#!/usr/bin/env python3
"""
main.py - EVM 字节码控制流图可视化工具

用法:
    python main.py <bytecode_file> [-o output_file] [--format png|svg|pdf]

示例:
    python main.py contract.bin
    python main.py contract.hex -o my_cfg.png
    python main.py contract.bin --format svg
"""

import argparse
import subprocess
import sys
import os



from src.bb import build_basic_blocks
from src.cfg_builder import ControlFlowGraphBuilder, TERMINATING_OPS, JUMP_OP, JUMPI_OP, PUSH2_OP


def read_bytecode_file(filepath: str) -> bytes:
    """
    读取字节码文件，支持以下格式：
    1. 二进制文件 (.bin)
    2. 十六进制文本文件 (.hex, .txt 或其他)
    """
    with open(filepath, 'rb') as f:
        content = f.read()
    
    # 尝试判断是否为纯十六进制文本
    try:
        # 尝试解码为文本并解析十六进制
        text = content.decode('utf-8', errors='strict').strip()
        # 移除可能的 0x 前缀和空白字符
        hex_str = text.replace('\n', '').replace('\r', '').replace(' ', '').replace('\t', '')
        if hex_str.startswith('0x') or hex_str.startswith('0X'):
            hex_str = hex_str[2:]
        # 验证是否为有效的十六进制字符串
        if all(c in '0123456789abcdefABCDEF' for c in hex_str):
            return bytes.fromhex(hex_str)
    except (UnicodeDecodeError, ValueError):
        pass
    
    # 如果不是有效的十六进制文本，则视为二进制文件
    return content


def generate_dot(builder: ControlFlowGraphBuilder) -> str:
    """生成美化的 DOT 格式图形表示"""
    lines = ['digraph CFG {']
    lines.append('    rankdir=TB;')
    lines.append('    bgcolor="white";')
    lines.append('    node [shape=box, fontname="Courier New", fontsize=10, style=filled];')
    lines.append('    edge [fontname="Arial", fontsize=9];')
    lines.append('')
    
    sorted_addrs = sorted(builder.nodes.keys())
    
    for addr in sorted_addrs:
        node = builder.nodes[addr]
        
        # 构建节点标签（使用 HTML-like 标签以获得更好的格式）
        ins_lines = []
        for ins in node.instructions:
            if ins.arg is not None:
                ins_lines.append(f'{ins.addr:04x}: {ins.name} 0x{ins.arg_int():x}')
            else:
                ins_lines.append(f'{ins.addr:04x}: {ins.name}')
        
        ins_text = '\\l'.join(ins_lines) + '\\l'
        
        pred_str = ', '.join(f'{p:x}' for p in sorted(node.predecessors)) or 'None'
        succ_str = ', '.join(f'{s:x}' for s in sorted(node.successors)) or 'None'
        
        label = f'BB 0x{addr:x}\\l──────────\\lPred: [{pred_str}]\\lSucc: [{succ_str}]\\l──────────\\l{ins_text}'
        
        # 根据最后一条指令类型着色
        last_op = node.last_instruction.op
        if last_op in TERMINATING_OPS:
            fillcolor = '#ffcccc'  # 浅红色 - 终止块
            color = '#cc0000'
        elif last_op == JUMP_OP:
            fillcolor = '#cce5ff'  # 浅蓝色 - 无条件跳转
            color = '#0066cc'
        elif last_op == JUMPI_OP:
            fillcolor = '#ccffcc'  # 浅绿色 - 条件跳转
            color = '#00cc00'
        else:
            fillcolor = '#ffffcc'  # 浅黄色 - 普通块
            color = '#666666'
        
        lines.append(f'    n{addr} [label="{label}", fillcolor="{fillcolor}", color="{color}"];')
    
    lines.append('')
    
    # 添加边，区分条件跳转的两种边
    for addr in sorted_addrs:
        node = builder.nodes[addr]
        last_op = node.last_instruction.op
        
        successors = sorted(node.successors)
        
        if last_op == JUMPI_OP and len(successors) == 2:
            # 条件跳转：区分 true/false 分支
            next_seq = addr + sum(1 + (ins.op - 0x5f if 0x60 <= ins.op <= 0x7f else 0) 
                                  for ins in node.instructions)
            
            for succ in successors:
                if succ == successors[0]:
                    # Fall-through (false 分支)
                    lines.append(f'    n{addr} -> n{succ} [color="#cc0000", label="F"];')
                else:
                    # Jump target (true 分支)
                    lines.append(f'    n{addr} -> n{succ} [color="#00cc00", label="T"];')
        else:
            for succ in successors:
                lines.append(f'    n{addr} -> n{succ};')
    
    lines.append('}')
    return '\n'.join(lines)


def render_dot_to_image(dot_content: str, output_path: str, fmt: str = 'png') -> bool:
    """
    使用 Graphviz 将 DOT 内容渲染为图片
    
    返回: True 如果成功，False 如果失败
    """
    # 写入临时 DOT 文件
    dot_file = output_path.rsplit('.', 1)[0] + '.dot'
    
    with open(dot_file, 'w', encoding='utf-8') as f:
        f.write(dot_content)
    
    print(f"DOT 文件已保存: {dot_file}")
    
    # 调用 Graphviz 的 dot 命令
    try:
        result = subprocess.run(
            ['dot', f'-T{fmt}', dot_file, '-o', output_path],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode != 0:
            print(f"Graphviz 错误: {result.stderr}")
            return False
        
        print(f"图片已生成: {output_path}")
        return True
        
    except FileNotFoundError:
        print("错误: 未找到 Graphviz (dot 命令)。请先安装 Graphviz:")
        print("  Ubuntu/Debian: sudo apt-get install graphviz")
        print("  macOS: brew install graphviz")
        print("  Windows: https://graphviz.org/download/")
        return False
    except subprocess.TimeoutExpired:
        print("错误: Graphviz 渲染超时")
        return False


def main():
    parser = argparse.ArgumentParser(
        description='EVM 字节码控制流图可视化工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
    python main.py contract.bin
    python main.py contract.hex -o my_cfg.png
    python main.py contract.bin --format svg

支持的输入格式:
    - 二进制字节码文件 (.bin)
    - 十六进制文本文件 (.hex, .txt)

节点颜色说明:
    - 红色: 终止块 (STOP, RETURN, REVERT, etc.)
    - 蓝色: 无条件跳转 (JUMP)
    - 绿色: 条件跳转 (JUMPI)
    - 黄色: 普通块 (顺序执行)
'''
    )
    
    parser.add_argument('input', help='输入的字节码文件路径')
    parser.add_argument('-o', '--output', help='输出图片路径 (默认: cfg.png)')
    parser.add_argument('--format', choices=['png', 'svg', 'pdf'], default='png',
                        help='输出格式 (默认: png)')
    parser.add_argument('--dot-only', action='store_true',
                        help='仅生成 DOT 文件，不渲染图片')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='显示详细信息')
    
    args = parser.parse_args()
    
    # 检查输入文件
    if not os.path.exists(args.input):
        print(f"错误: 文件不存在: {args.input}")
        sys.exit(1)
    
    # 确定输出路径
    if args.output:
        output_path = args.output
    else:
        base_name = os.path.splitext(os.path.basename(args.input))[0]
        output_path = f"{base_name}_cfg.{args.format}"
    
    # 读取字节码
    print(f"读取字节码文件: {args.input}")
    try:
        bytecode = read_bytecode_file(args.input)
    except Exception as e:
        print(f"错误: 无法读取文件: {e}")
        sys.exit(1)
    
    print(f"字节码长度: {len(bytecode)} 字节")
    
    # 构建控制流图
    print("\n构建控制流图...")
    builder = ControlFlowGraphBuilder(bytecode)
    builder.build()
    
    # 显示统计信息
    num_blocks = len(builder.nodes)
    num_edges = sum(len(n.successors) for n in builder.nodes.values())
    print(f"\n统计: {num_blocks} 个基本块, {num_edges} 条边")
    
    if args.verbose:
        builder.print_cfg()
    
    # 生成 DOT
    print("\n生成 DOT 格式...")
    dot_content = generate_dot(builder)
    
    if args.dot_only:
        dot_file = output_path.rsplit('.', 1)[0] + '.dot'
        with open(dot_file, 'w', encoding='utf-8') as f:
            f.write(dot_content)
        print(f"DOT 文件已保存: {dot_file}")
    else:
        # 渲染图片
        print("\n渲染图片...")
        if render_dot_to_image(dot_content, output_path, args.format):
            print(f"\n✓ 完成! 控制流图已保存到: {output_path}")
        else:
            # 如果渲染失败，至少保存 DOT 文件
            dot_file = output_path.rsplit('.', 1)[0] + '.dot'
            with open(dot_file, 'w', encoding='utf-8') as f:
                f.write(dot_content)
            print(f"\n图片渲染失败，但 DOT 文件已保存: {dot_file}")
            print("你可以手动使用以下命令生成图片:")
            print(f"  dot -T{args.format} {dot_file} -o {output_path}")
            sys.exit(1)


if __name__ == '__main__':
    main()
