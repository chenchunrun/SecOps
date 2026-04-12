#!/usr/bin/env python3
"""
ROP Gadgets 搜索和利用链生成
用法: python3 rop_finder.py <binary>
"""

import sys
from pwn import *

def find_gadgets(elf):
    """查找常用 gadgets"""
    rop = ROP(elf)

    gadgets = {}

    # 常用 gadgets
    patterns = [
        ['pop rdi', 'ret'],
        ['pop rsi', 'ret'],
        ['pop rsi', 'pop r15', 'ret'],
        ['pop rdx', 'ret'],
        ['pop rdx', 'pop rbx', 'ret'],
        ['pop rax', 'ret'],
        ['pop rbx', 'ret'],
        ['pop rcx', 'ret'],
        ['pop rbp', 'ret'],
        ['pop rsp', 'ret'],
        ['ret'],
        ['leave', 'ret'],
        ['syscall'],
        ['syscall', 'ret'],
        ['int 0x80'],
    ]

    for pattern in patterns:
        try:
            addr = rop.find_gadget(pattern)
            if addr:
                name = ' ; '.join(pattern)
                gadgets[name] = hex(addr[0])
        except:
            pass

    return gadgets


def find_magic_gadgets(elf):
    """查找特殊 gadgets"""
    magic = {}

    # call rax / jmp rax
    try:
        raw = elf.read(elf.address, elf.get_section_by_name('.text').data_size)
        # call rax: ff d0
        # jmp rax: ff e0
        if b'\xff\xd0' in raw:
            magic['call rax'] = "found"
        if b'\xff\xe0' in raw:
            magic['jmp rax'] = "found"
    except:
        pass

    return magic


def print_gadgets(binary_path):
    """打印所有 gadgets"""
    elf = ELF(binary_path)

    print(f"\n{'='*50}")
    print(f"ROP Gadgets: {binary_path}")
    print(f"{'='*50}")

    print(f"\n[基本信息]")
    print(f"  Arch: {elf.arch}")
    print(f"  Bits: {elf.bits}")
    print(f"  PIE:  {elf.pie}")

    print(f"\n[常用 Gadgets]")
    gadgets = find_gadgets(elf)
    for name, addr in gadgets.items():
        print(f"  {addr}: {name}")

    print(f"\n[重要符号]")
    important = ['main', 'win', 'flag', 'shell', 'system', 'execve']
    for sym in important:
        if sym in elf.symbols:
            print(f"  {hex(elf.symbols[sym])}: {sym}")

    print(f"\n[GOT 表]")
    for name, addr in list(elf.got.items())[:10]:
        print(f"  {hex(addr)}: {name}")

    print(f"\n[PLT 表]")
    for name, addr in list(elf.plt.items())[:10]:
        print(f"  {hex(addr)}: {name}")


def generate_rop_template(binary_path):
    """生成 ROP 利用模板"""
    elf = ELF(binary_path)
    rop = ROP(elf)

    template = f'''#!/usr/bin/env python3
from pwn import *

elf = ELF("{binary_path}")
rop = ROP(elf)

# Gadgets
'''

    gadgets = find_gadgets(elf)
    for name, addr in gadgets.items():
        var_name = name.replace(' ', '_').replace(';', '').replace('0x', 'int_')
        template += f'{var_name} = {addr}\n'

    template += '''
# 构造 ROP 链
offset = 64  # 修改为实际偏移

payload = flat([
    b"A" * offset,
    # 在这里添加 ROP 链
])

p = process(elf.path)
p.sendline(payload)
p.interactive()
'''

    return template


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <binary>")
        sys.exit(1)

    context.log_level = 'error'
    print_gadgets(sys.argv[1])

    if "--template" in sys.argv:
        print("\n" + "="*50)
        print("ROP 利用模板")
        print("="*50)
        print(generate_rop_template(sys.argv[1]))
