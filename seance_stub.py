# This program has been cut up and split between seance.py and seance_api.py. It's left purely for reference, as it works in its current state.
import angr
import argparse
from seance_api import *
from struct import pack

found = 0
opcode = ''

def hook_block(state):
    # tareting state.block().capstone.insns[n].insn.bytes, a byte array which is the opcode we're looking for
    global found
    global opcode
    block = state.block()
    instrs = block.capstone.insns
    
    for instr in instrs:
        byts = instr.insn.bytes
        byts = byts.hex()
        if byts == opcode:
            found = block.addr
            

def construct_op_code(off):
    off = off - 5
    op = pack('<l', off)
    op = op.hex()
    op = 'e8' + op
    global opcode
    opcode = op

def input_check(args):
    symbol = ''
    addr = 0
    off = 0
    b = ''
    
    if args.symbol:
        sym = args.symbol
    elif args.address:
        addr = args.address
    else:
        print("Need to provide a symbol or address for the outer function.")
        return -1, -1, -1, -1
    if args.offset:
        off = args.offset
        if args.negative == 1:
            off = -off
    else:
        print("Need to provide an offset for the inner function.")
        return -1, -1, -1, -1
    if args.binary:
        b = args.binary
    else:
        print("Need to provide a binary to analyze.")
        return -1, -1, -1, -1
        
    return symbol, addr, off, b
    
def hex_conv(a):
    return int(a, 16)

def main(args):
    symbol, address, offset, binary = input_check(args)
    # construct opcode to find from given offset
    construct_op_code(offset)
    
    if address == -1:
        return
        
    # Use this one if working with mach-o files, like the objc dylibs
    #proj = angr.Project(binary, load_options={'auto_load_libs':False, 'main_opts': {'backend':'mach-o', 'base_addr':0x0}})
    proj = angr.Project(binary)
    init_reg_dict(proj.arch)

    base = proj.loader.main_object.min_addr
    
    if symbol != '':
        a, _, _ = get_symbol_addr(symbol, proj)
    elif address > 0:
        a = address + base
    else:
        print("Error, no symbol or address")
        return
    
    state = proj.factory.entry_state(addr = a)
    
    for opt in angr.options.symbolic:
        state.options.add(opt)
    #state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    #state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    #state.options.add(angr.sim_options.CALLLESS)
    
    state.inspect.b('irsb', when = angr.BP_AFTER, action = hook_block)
    print(state)
    
    simgr = proj.factory.simgr(state)
    print(simgr)
    global found
    simgr.explore(find=lambda s: found > 0)
    print(simgr)
        
    if found != 0:
        print('Found!')
        print('%x'%found)
    else:
        print("Did not find")
    


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Find a target basic block in the binary.")
    parser.add_argument('-b', '--binary', metavar='B', type=str, help='The binary we want to analyze.')
    parser.add_argument('-o', '--offset', metavar='O', type=hex_conv, help='The offset of the inner function we want to target (E.g. if the call instruction is "call 0x100" @ address 0x90, off = 0x10).')
    parser.add_argument('-s', '--symbol', metavar='S', type=str, help='Symbol for the outer function we want to target.')
    parser.add_argument('-a', '--address', metavar='A', type=hex_conv, help='The address of the outer function function, as an offset from the base address.')
    parser.add_argument('-n', '--negative', metavar='N', type=int, default=0, help='Flag if the offset is negative.')
    args = parser.parse_args()
    main(args)
