import angr
from angrutils import *
import seance_jparse
import sys
import os
import json
import logging
from struct import pack

l = logging.getLogger(__name__)
write_info = {'addr': [],
              'expr': [],
              'leng': [],
              'cond': [],
              'block': []}
read_info = {'addr': [],
             'expr': [],
             'leng': [],
             'cond': [],
             'block': []}

register_dict = {}

emulation = False

mem_bases = []

#Useful global vars, used when locating basic block containing a given call instruction
# opcode: holds the opcode we construct from the given offset
# matching_block: holds the address of the basic block containing the opcode
# matching_address: holds the address of the opcode itself
opcode = ''
matching_block= 0
matching_address = 0

matching_addresses = []
func_addr = 0

collect_addrs = []

def emulating():
    global emulation
    emulation = not emulation

def init_reg_dict(arch):
    global register_dict
    register_dict = arch._get_register_dict()

def zero_reg_dict():
    global register_dict
    register_dict = {}

def zero_info():
    global write_info
    global read_info
    write_info = {'addr': [],
                  'expr': [],
                  'leng': [],
                  'cond': [],
                  'block': []}
    read_info = {'addr': [],
                 'expr': [],
                 'leng': [],
                 'cond': [],
                 'block': []}

def zero_opcode():
    global opcode
    opcode = ''

def zero_func():
    global func_addr
    func_addr = 0
    
def zero_found_matching():
    global matching_block
    global matching_address
    global matching_addresses
    matching_block = 0
    matching_address = 0
    matching_addresses = []

    return 0, 0, []
    
def set_opcode(op):
    zero_opcode()
    global opcode
    opcode = op
    return op

def set_func(func):
    zero_func()
    global func_addr
    func_addr = func
    return func
    
def lookup_func(proj, symbol):
    filename = proj.filename
    dirname = os.path.dirname(filename)
    ret_sym = '0'
    ret_off = '0'
    addr = 0
    end = 0
    closest = 0xffffffffffffffff
    for f in os.listdir(dirname):
        if f.startswith('gvars'):
            gvars = open(os.path.join(dirname, f), 'r')
            lines = gvars.readlines()
            for l in lines:
                spl = l.split(',')
                if symbol == spl[0]:
                    ret_sym = spl[0]
                    ret_off = spl[1]
                    gvars.close()
                    break
            addr = int(ret_off, 16)
            for l in lines:
                spl = l.split(',')
                a = int(spl[1], 16)
                if (a - addr) > 0 and a < closest:
                    closest = a
            
                
    if ret_sym != '0':
        addr = int(ret_off,16) + proj.loader.main_object.min_addr
        end = closest + proj.loader.main_object.min_addr
    return addr, end

def two_comp(num, bits):
    if(num & ( 1 << (bits-1)))!=0:
        num = num - (1 << bits)
    return num

def flip(bytes):
    res = ''
    for i in range(0, len(bytes), 2):
        temp = bytes[i:i+2]
        res = temp + res
    return res

def try_addr(a, i):
    if a == flip(i):
        return True
    elif a == flip(i[0:int(len(i)/2)]):
        return True
    elif a == flip(i[0:int(len(i)/4)]):
        return True
    else:
        return False

def get_call_target(bytes):
    off = '0'
    addr = '0'
    op = ''
    l = 0
    if bytes[0:2] == 'e8':
        off = flip(bytes[2:])
        op = 'e8'
        l = len(bytes[2:]) * 4
    elif bytes[0:2] == 'ff':
        off = flip(bytes[4:])
        addr = flip(bytes[4:])
        op = 'ff'
        l = len(bytes[4:]) * 4
    elif bytes[0:2] == '9a':
        addr = flip(bytes[2:])
        op = '9a'
        l = len(bytes[2:]) * 4
    elif bytes[0:1] == '4' and bytes[2:4] == 'ff':
        off = flip(bytes[6:])
        op = 'ff'
        l = len(bytes[6:]) * 4
    else:
        sys.exit("Bad call instruction")

    off = int(off, 16)
    addr = int(addr, 16)
    
    return off, addr, op, l
             
def hook_block_opcode(state):
    # tareting state.block().capstone.insns[n].insn.bytes, a byte array which is the opcode we're looking for
    global matching_block
    global opcode
    global matching_address
    block = state.block()
    instrs = block.capstone.insns
    
    for instr in instrs:
        byts = instr.insn.bytes
        byts = byts.hex()
        if byts == opcode:
            matching_block = block.addr
            matching_address = instr.insn.address
            
def hook_block(state):
    global matching_address
    global matching_block
    global matching_addresses
    global collect_addrs
    global func_addr
    print("Block Hook")
    block = state.block()
    jump = block.vex.jumpkind
    
    if block.addr == 0x1c00b4f0d:
        input("In The right block")
    if block.addr == 0x1c0042c42:
        input("Close to the right address")
    #    input("Gottem")
    #if '%x'%block.addr not in collect_addrs:
    #    collect_addrs.append('%x'%block.addr)
    #collect_addrs.sort()
    #print(collect_addrs)
    if jump == 'Ijk_Call':
        matching_addresses.append([block.addr, block.instruction_addrs[-1]])
        insns = block.capstone.insns
        for instr in insns:
            i = instr.insn
            op = i.mnemonic
            if op == 'call':
                
                off, addr, op, size = get_call_target(i.bytes.hex())
                rip = i.address + i.size
                if block.addr == 0x1c00b4f0d:
                    print('Offset, addr, and op: <%x, %x, %s>')
                    print('Instruction: %s'%(instr.bytes.hex()))
                    print('Target: %x'%func_addr)
                    input("")
                if off:
                    t_off = two_comp(off, size)
                    found = (rip + t_off) == func_addr
                if addr and not found:
                    found = addr == func_addr
                
                if found:
                    print("Found the call we wanted in block %x, instruction %x"%(block.addr, block.instruction_addrs[-1]))
                    matching_address = block.instruction_addrs[-1]
                    matching_block = block.addr
                    
    
def hook_mwrite(state):
    #print('Hooking mem_write')
    global write_info
    global emulation
    if not emulation:
        return
    address = ''
    try:
        address = state.solver.eval_one(state.inspect.mem_write_address)
    except:
        l.warning("Could not evaluate to single address for state %s"%state)
        return
    try:
        length = state.solver.eval(state.inspect.mem_write_length)
    except:
        length = 4
    temp = []
    for b in state.history.bbl_addrs:
        temp.append(b)
    l.warning("Hooking memory write at addr 0x%x | %s"%(address, state.inspect.mem_write_expr))    
    write_info['addr'].append(state.inspect.mem_write_address)
    write_info['expr'].append(state.inspect.mem_write_expr)
    write_info['leng'].append(length)
    write_info['cond'].append(state.inspect.mem_write_condition)
    write_info['block'].append(temp)

def hook_rwrite(state):
    #print('Hooking mem_write')
    global write_info
    global register_dict
    global emulation
    if not emulation:
        return
    address = ''
    try:
        address = state.solver.eval_one(state.inspect.reg_write_offset)
    except:
        l.warning("Could not evaluate to single address for state %s"%state)
        return
    
    offset = state.inspect.reg_write_offset

    try:
        length = state.solver.eval(state.inspect.reg_write_length)
    except:
        length = 4

    temp = []
    for b in state.history.bbl_addrs:
        temp.append(b)

    found = 0
    for k, v in register_dict.items():
        if v == (offset, length):
            if k == 'rip' or k == 'ip' or k == 'eip':
                return
            write_info['addr'].append(k)
            found = 1
            break
    if not found:
        write_info['addr'].append('-1')
        


    l.warning("Hooking reg write in reg %s | %s"%(k, state.inspect.reg_write_expr))
    write_info['expr'].append(state.inspect.reg_write_expr)
    write_info['leng'].append(length)
    write_info['block'].append(temp)
    write_info['cond'].append(state.inspect.reg_write_condition)

def hook_mread(state):
    global read_info
    global emulation
    if not emulation:
        return
    address = ''
    try:
        address = state.solver.eval_one(state.inspect.mem_read_address)
    except:
        l.warning("Could not evaluate to single address for state %s"%state)
        return
    try:
        length = state.solver.eval(state.inspect.mem_write_length)
    except:
        length = 4
    temp = []
    for b in state.history.bbl_addrs:
        temp.append(b)
    l.warning("Hooking memory read at addr 0x%x | %s"%(address, state.inspect.mem_read_expr))
    read_info['addr'].append(state.inspect.mem_read_address)
    read_info['leng'].append(state.inspect.mem_read_length)
    read_info['expr'].append(state.inspect.mem_read_expr)
    read_info['cond'].append(state.inspect.mem_read_condition)
    read_info['block'].append(temp)

def hook_rread(state):
    global read_info
    global register_dict
    global emulation
    if not emulation:
        return
    address = ''
    
    try:
        address = state.solver.eval_one(state.inspect.reg_read_offset)
    except:
        l.warning("Could not evaluate to single address for state %s"%state)
        return
    
    offset = state.inspect.reg_read_offset

    try:
        length = state.solver.eval(state.inspect.reg_read_length)
    except:
        length = 4

    temp = []
    for b in state.history.bbl_addrs:
        temp.append(b)

    found = 0
    for k, v in register_dict.items():
        if v == (offset, length):
            read_info['addr'].append(k)
            found = 1
            break
    if not found:
        read_info['addr'].append('-1')
        
    l.warning("Hooking memory read at addr %s | %s"%(k, state.inspect.mem_read_expr))
    read_info['expr'].append(state.inspect.reg_read_expr)
    read_info['leng'].append(length)
    read_info['block'].append(temp)
    read_info['cond'].append(state.inspect.reg_read_condition)

def get_symbol_addr(symbol, proj):
    #sym here is the string name of the symbol
    addr = -1
    end = -1
    print('Target: %s'%symbol)
    try:
        #try and do things the sane way
        sym = proj.loader.find_symbol(symbol)
        addr = sym.rebased_addr
        size = sym.size
        end = get_symbol_end(sym, proj)
    except:
        try:
            #in case of angr giving a bad result, do it manually
            for so in proj.loader.all_objects:
                if so is proj.loader._extern_object:
                    continue
                sym = so.get_symbol(symbol)
            if isinstance(sym, list):
                sym = sym[0]
            addr = sym.rebased_addr
            size = sym.size
            end = get_symbol_end(sym, proj)
        except:
            # in case of this not working, try looking up in the PDB file, if it exists
            try:
                # find the gvars file in the directory (make sure it's in the same directory as your binary)
                addr, end = lookup_func(proj, symbol)
                    
            except:
                print('Could not locate symbol')
    #print('%x : %x : %s'%(addr, end, symbol))
    return addr, end, symbol
    
def get_symbol_end(sym, proj):
    #sym here is the symbol object
    addr = sym.rebased_addr
    found = sym
    for s in proj.loader.symbols:
        if s.rebased_addr > addr:
            found = s
            break
    if found.rebased_addr == addr:
        #input("Found address equal to known address")
        return -1
    block = proj.factory.block(found.rebased_addr - 1)
    bytes_as_string = block.bytes.hex()
    search_addr = found.rebased_addr - 1
    while bytes_as_string[0:2] in ["cc", "90"] and search_addr != addr:
        search_addr -= 1
        block = proj.factory.block(search_addr)
        bytes_as_string = block.bytes.hex()
        
    if bytes_as_string[0:2] == "c3" or bytes_as_string[0:2] in ["cc", "90"]:
        return search_addr
    else:
        block = proj.factory.block(search_addr - 3)
        bytes_as_string = block.bytes.hex()
        if bytes_as_string[0:2] == "c2" or bytes_as_string[0:2] in ["cc", "90"]:
            return search_addr - 3
        else:
            #input("Found address isn't ret. found: %x"%searc_addr)
            return -1


def check_call(proj, insn, targs):
    ret = []
    
    # First check if the address is present as a string the in the operation (This can happen for e8 or 9a calls)
    if targs[0] in insn.op_str:
        # If we are not at the end of our list, check the next basic block for the next call in the list, passing in the tail of the list
        # the return from this should be a [[basic_block_start, final_instruction_addr]]
        # where the final_instruction_addr is the address of the call instruction to the last target in our list
        if(len(targs)>1):
            
            next_block = proj.factory.block(insn.address + insn.size)
            _, temp = find_call(proj, next_block, targs[1:], [])
            
            # If we get a result back, grab the last address, wrap it in a list, and return it
            if temp != []:
                ret = [temp[-1][-1]]
                
        # If we are at the end of the list, return [our_address] to be propogated back up the recursive calls
        else:
            ret = [insn.address]
    
    # If the instruction doesn't contain the exact string, try and reconstruct the target address from the instruction. Check for REX byte and ff opcode to decide which bytes
    # to use to reconstruct the address
    elif insn.bytes.hex()[0:2] == 'ff':
        t_bytes = insn.bytes.hex()[4:]
        t_bytes = flip(t_bytes)
        if t_bytes != '':
            comp = two_comp(int(t_bytes, 16), len(t_bytes)*4)
            if '0x%x'%(comp + insn.address + insn.size) == targs[0]:
                # If we are not at the end of our list, check the next basic block for the next call in the list, passing in the tail of the list
                # the return from this should be a [[basic_block_start, final_instruction_addr]]
                # where the final_instruction_addr is the address of the call instruction to the last target in our list
                if(len(targs)>1):
                    next_block = proj.factory.block(insn.address + insn.size)
                    _, temp = find_call(proj, next_block, targs[1:], [])
                    
                    # If we get a result back, grab the last address, wrap it in a list, and return it
                    if temp != []:
                        ret = [temp[-1][-1]]
                        
                # If we are at the end of the list, return [our_address] to be propogated back up the recursive calls
                else:
                    ret = [insn.address]
    elif insn.rex:
        t_bytes = insn.bytes.hex()[6:]
        t_bytes = flip(t_bytes)
        if t_bytes != '':
            comp = two_comp(int(t_bytes, 16), len(t_bytes)*4)
            if '0x%x'%(comp + insn.address + insn.size) == targs[0]:
                if(len(targs)>1):
                    next_block = proj.factory.block(insn.address + insn.size)
                    _, temp = find_call(proj, next_block, targs[1:], [])
                    if temp != []:
                        ret = [temp[-1][-1]]
                else:
                    ret = [insn.address]

    # return either an empty list of a list containing the address of the last targeted call instruction
    return ret


def find_call(proj, block, targs, found):

    insns = block.capstone.insns
    #if block.addr == 0x1c00b4f12:
    #    print(insns)
    #    for i in insns:
    #        print('%s : %x'%(i.bytes.hex(), i.address))
            
        #input('')
    for insn in insns:
        if insn.mnemonic == 'call':
            
            #if len(targs)==1:
            #    print("Checking for %s"%(targs[0]))
            f = check_call(proj, insn, targs)
            if f != []:
                #print("Found:")
                #input(f)
                
                # bundle the address found (should be the final adress in the basic block containing the last targeted call)
                # with the first adress of this block and return it.
                # what is finally returned should be the basic block address of the basic block containing the first call 
                # we're targeting
                found.append([block.addr, f[-1]])
            
    next_block_addr = insns[-1].size + insns[-1].address
    return next_block_addr, found


def find_jump(proj, block, found):
    
    jumps = ['ja', 'jae', 'jb', 'jbe', 'jc', 'jcxz', 'jecxz', 'jrcxz', 'je', 'jg', 'jge', 'jl',
     'jna', 'jnae', 'jnb', 'jnbe', 'jnc', 'jne', 'jng', 'jnge', 'jnl', 'jnle', 'jno', 'jnp', 
     'jns', 'jnz', 'jo', 'jp', 'jpe', 'jpo', 'js', 'jz']


    insns = block.capstone.insns
    
    for insn in insns:
        if insn.mnemonic in jumps:
            try:
                addr = insn.op_str
                a = int(addr, 16)
                found.append(a)
            except:
                print("Could not convert %s to int"%insn.op_str)
                input('')
    #print(found)
    next_block_addr = insns[-1].size + insns[-1].address
    return next_block_addr, found
    
def find_jumps_out(proj, func):

    base, max_addr = lookup_func(proj, func)
    
    #max_addr = 0x1c0043030    
    #block = proj.factory.block(0x1c0042a08)
    block = proj.factory.block(base)
    found = []
    
    while block.addr < max_addr:
        #next_block_addr, _ = find_call(block, targs, found, proj)
        next_block_addr, _ = find_jump(proj, block, found)
        try:
            block = proj.factory.block(next_block_addr)
        except:
            break
        while(block.capstone.insns == [] and next_block_addr < max_addr):
            next_block_addr += 1
            try:
                block = proj.factory.block(next_block_addr)
            except:
                break
    
    ret = []
    
    for f in found:
        if f not in range(base, max_addr) and f not in ret:
            ret.append(f)
    ret.sort()
    pretty_list = []
    for r in ret:
        pretty_list.append('%x'%r)
    print(pretty_list)
    return ret
            
# Function to find a basic block containing a "call t_func" instruction, given a list of function names or addresses, targs            
# Specifically, find basic blocks that start with the first call and hit every call in the targs list, in sequence.
def find_bb_containing(proj, targs):
    zero_found_matching()
        
    base = proj.loader.main_object.min_addr
    
    block = proj.factory.block(base)
    found = []
    #targs = ['0x1c0079f80', '0x1c0201188']
    
    t_addrs = []
    
    for t in targs:
        try:
            temp = int(t, 16)
            t_addrs.append(t)
        except:
            temp = lookup_func(proj, t)
            if not temp:
                print("Could not find one of the desired funcs in the PDB, aborting")
                sys.exit()
            t_addrs.append('0x%x'%temp[0])
            

    print(t_addrs)    
    while block.addr < proj.loader.max_addr:
        if block.capstone.insns == []:
            break
        next_block_addr, _ = find_call(proj, block, t_addrs, found)
        try:
            block = proj.factory.block(next_block_addr)
        except:
            break
        while(block.capstone.insns == [] and next_block_addr < proj.loader.max_addr):
            next_block_addr += 1
            try:
                block = proj.factory.block(next_block_addr)
                
            except:
                break
    #print(found)
    #input('')
    
    #return list found= [[start, end], [start, end], ....]
    return found
        
def get_jump_regions(jumps):
    regions = []
    l_bound = jumps[0]
    limit = 0x200
    for i in range(0, len(jumps)):
        if(i+1 == len(jumps)):
            regions.append([l_bound, jumps[i]])
        elif jumps[i+1] - jumps[i] > limit:
            regions.append([l_bound, jumps[i]])
            l_bound = jumps[i+1]
    return regions
        
def get_leaves(graph):
    nodes  = graph.model.nodes()
    leaves = []
    for n in nodes:
        if n.successors == []:
            leaves.append(n)
    return leaves
        
def get_last_addr(addrs):
    last  = ''
    for a in addrs:
        last = a
        #break
    return last

def get_dead_ends(dends, proj):
    ends = []
    for dend in dends:
        print(dend)
        last = ''
        if dend.instruction_addrs != []:
            last = get_last_addr(dend.instruction_addrs)
            if last != '':
                ends.append(last)
        else:
            block = proj.factory.block(dend.addr)
            if block.instruction_addrs != []:
                last = get_last_addr(block.instruction_addrs)
                if last != '':
                    ends.append(last)
    return ends
    
def handle_stashes(stashes, proj, arch):
    mem_const = {'state'  : [],
                 'write'  : [],
                 'read': []}
    permit = []
    global write_info
    for stash in stashes:
        for s in stashes[stash]:
            hist = []
            for b in s.history.bbl_addrs:
                hist.append(b)
                
            # We collect all of the writes relevant to the end state we are currently looking at
            # To do this, we iterate over all of the memory writes, select writes who's basic blocks histories are contained
            # completely in the current state's basic block history, and add those writes to a list
            tcount = 0
            cont = 0
                
            # target_writes = [ [ address, length_of_history_match, expr, length ], ... ]
            target_writes = []
            for ad in write_info['addr']:
                l_temp = compare_hist(hist, write_info['block'][tcount])
                if l_temp > 0:
                    target_writes.append([ad, l_temp, write_info['expr'][tcount], write_info['leng'][tcount]])
                tcount += 1

            target_reads = []
            tcount = 0
            for ad in read_info['addr']:
                l_temp = compare_hist(hist, read_info['block'][tcount])
                if l_temp > 0:
                    target_reads.append([ad, l_temp, read_info['expr'][tcount], read_info['leng'][tcount]])
                tcount += 1
            # constrs = [ [0xAddress, 0xEval_Result_As_Int, 'Eval_Result_As_String', b'\\0xEv\\0xAl\\0xAs\\0xBy\\0xTe' ], [second], ... ]
            # Constraint solve all of the writes to memory, and save integer, string, and byte representations of the result
            constrs = get_constraints(s, target_writes, proj, arch)
            rconstrs = get_constraints(s, target_reads, proj, 0)

            # Un-comment these lines to print out all of the memory writes
            #for c in constrs:
            #    print(c)
            #cont = input('')

            blocks = []
            inf = get_state_info(s)
            # For all of the blocks visited in the emulation, add them to a permit list for the CFG construction
            # Also save the blocks for future analysis
            for b in inf['blocks']:
                blocks.append(b)
                # We need to convert from string to int
                xb = int(b, 16)
                if xb not in permit:
                    permit.append(xb)
                    
            # We save the state and corresponding evals
            mem_const['state'].append(blocks)
            mem_const['write'].append(constrs)
            mem_const['read'].append(rconstrs)
            
            
                
    return mem_const, permit
                                

# Gets all the information of each state's given a set of states
def get_state_info(state):
    sim_state_info = {'address'   : '',
                      'history'   : [],
                      'jumps'     : [],
                      'conditions': [],
                      'blocks'    : []}

    hist = state.history.descriptions
    jg = state.history.jump_guards
    jmps = state.history.jumpkinds
    evs = state.history.events
    blocks = state.history.bbl_addrs
    try:
        addr = '%x'%state.addr
    except:
        addr = 'did_not_eval_one'

    sim_state_info['address'] = addr
    
    for h in hist:
        sim_state_info['history'].append(h)
    
    for j in jmps:
        sim_state_info['jumps'].append(j)

    for j in jg:
        sim_state_info['conditions'].append(str(j))

    for b in blocks:
        sim_state_info['blocks'].append('%x'%b)
    
    return sim_state_info
    
########################################
########################################
# All of the graph-y functions between this set of double #'s and the next
# should not be used, as they don't work. I was messing with some fancier graph analysis
# but it didn't go anywhere, and I didn't finish checking/implementing the functions and have
# forgotten where I left off.
def traverse_graph_from_node(node, visited):
    if node not in visited:
        visited.append(node)
        for n in node.successors:
            if n not in visited:
                traverse_graph_from_node(node, visited)
    return visited
        
def get_roots(nodes, exclude = []):
    roots = []
    for node in nodes:
        preds = []
        for p in node.predecessors:
            if p not in exclude:
                preds.append(p)
        if preds == []:
            roots.append(node)
    return roots
    
def k_connected(nodes, k):
    two_conn = False
    for node in nodes:
        t_nodes = []
        for n in nodes:
            if n != node:
                t_nodes.append(n)
        t_roots = get_roots(t_nodes, exclude=[node])
        v_sets = []
        for root in t_roots:
            v_sets.append(traverse_graph_from_node(root))
        for v_set in v_sets:
            v_sets.remove(v_set)
            for vs in v_sets:
                overlap = False
                for n in v_set:
                    if n in vs:
                        overlap = True
                if not overlap:
                    return
########################################
########################################

# This is the shiny, new cfg analysis function, and what is used by seance.py at the moment.
def n_analyze_cfg(cfg):
    ret = { 'num_nodes': 0,
            'num_ends': 0,
            'num_funcs': 0}
    nodes = cfg.model.nodes()
    ret['num_nodes'] = len(nodes)
    try:
        ends = cfg.deadends
    except:
        ends = []
    ret['num_ends'] = len(ends)
    
    funcs = cfg.functions
    ret['num_funcs'] = len(funcs)
     
    return ret


# This function is bad and old, probably don't use it
def analyze_cfg(cfg, a):
    print('\n\nCFG @ %x'%a)
    nodes = get_all_nodes(cfg)
    terminators = cfg.deadends
        
    final_state_info = get_final_states(terminators)
    ords = []
    all_sat = []
    all_unsat = []
    for node in nodes:
        order = get_order(node)
        ords.append([node, order])
    for term in terminators:
        sat, unsat = get_sat(term)
        for s in sat:
            all_sat.append(s)
        for u in unsat:
            all_unsat.append(u)
    mx = ['', 0]
    mn = ['',100]
    avg = 0.0
    for i in ords:
        if i[1] >mx[1]:
            mx[1] = i[1]
            mx[0] = i[0]
        if i[1] < mn[1]:
            mn[1] = i[1]
            mn[0] = i[0]
        avg += i[1]
    avg = avg /len(ords)
    print('Max:')
    print(mx)
    print('Min:')
    print(mn)
    print('Average: %f'%avg)
    print('SAT: %d\nUNSAT: %d'%(len(all_sat), len(all_unsat)))
    #for info in final_state_info:
    #    print('State at address %s touched addresses:'%info['address'])
    #    print(info['blocks'])


def get_regs_32(state):
    regs = {'eax': '',
            'ebx': '',
            'ecx': '',
            'edx': '',
            'edi': '',
            'esi': '',
            'ebp': '',
            'esp': '',
            'eip': '',
            'eflags': ''}
    rets = []
    regs['eax'] = state.regs.eax
    regs['ebx'] = state.regs.ebx
    regs['ecx'] = state.regs.ecx
    regs['edx'] = state.regs.edx

    regs['edi'] = state.regs.edi
    regs['esi'] = state.regs.esi

    regs['ebp'] = state.regs.ebp
    regs['esp'] = state.regs.esp
    regs['eip'] = state.regs.eip

    regs['eflags'] = state.regs.eflags

    for r in regs:
        ret = -1
        ret_byte = 'Did_Not_Eval'
        ret_str = 'Did_Not_Eval'
        
        reg = r
        try:
            ret = state.solver.eval(regs[r])
        except:
            pass
            #print('Could not eval memory @ %s, %d' %(r, 4))
        try:
            ret_byte = state.solver.eval(regs[r], cast_to=bytes)
            ret_str = "b'{}'".format(''.join('\\x{:02x}'.format(b) for b in ret_byte))
            ret_byte = '%s'%ret_byte
            ret_byte = ret_byte.strip("b'")
        except:
            pass
            #print('Could not eval memory @ %s, %d as bytes' %(r, 4))

        rets.append([reg, '%x'%ret, ret_byte, ret_str])
    return rets

def get_regs_64(state, get_reg = None):

    regs = {'rax': '',
            'rbx': '',
            'rcx': '',
            'rdx': '',
            'r8' : '',
            'r9' : '',
            'r10': '',
            'r11': '',
            'r12': '',
            'r13': '',
            'r14': '',
            'r15': '',
            'rdi': '',
            'rsi': '',
            'rbp': '',
            'rsp': '',
            'rip': '',
            'eflags': ''}

    rets = []
    regs['rax'] = state.regs.rax
    regs['rbx'] = state.regs.rbx
    regs['rcx'] = state.regs.rcx
    regs['rdx'] = state.regs.rdx
    regs['r8'] = state.regs.r8
    regs['r9'] = state.regs.r9
    regs['r10'] = state.regs.r10
    regs['r11'] = state.regs.r11
    regs['r12'] = state.regs.r12
    regs['r13'] = state.regs.r13
    regs['r14'] = state.regs.r14
    regs['r15'] = state.regs.r15

    regs['rdi'] = state.regs.rdi
    regs['rsi'] = state.regs.rsi

    regs['rbp'] = state.regs.rbp
    regs['rsp'] = state.regs.rsp
    regs['rip'] = state.regs.rip

    if isinstance(get_reg, str):
        if get_reg in regs:
            return True
        else:
            return False

    regs['eflags'] = state.regs.eflags

    for r in regs:
        ret = -1
        ret_byte = 'Did_Not_Eval'
        ret_str = 'Did_Not_Eval'
        
        reg = r
        try:
            ret = state.solver.eval(regs[r])
        except:
            pass
            #print('Could not eval register %s, %d' %(r, 4))
        try:
            ret_byte = state.solver.eval(regs[r], cast_to=bytes)
            ret_str = "b'{}'".format(''.join('\\x{:02x}'.format(b) for b in ret_byte))
            ret_byte = '%s'%ret_byte
            ret_byte = ret_byte.strip("b'")
        except:
            pass
            #print('Could not eval register %s, %d as bytes' %(r, 4))

        rets.append([reg, '%x'%ret, ret_byte, ret_str])
    return rets

def try_cfg(proj, ff, starts, call, steps, ks, perm):
    # Keep trying to generate the CFG starting at the hook address, using steps - 5 each time until it works
    found = 0
    while not found:
        try:
            #for s in starts:
                #s.inspect.b('irsb', when = angr.BP_AFTER, action = hook_block)

            cfg = proj.analyses.CFGEmulated(fail_fast = ff, starts = starts, call_depth = call, max_steps = steps, keep_state=ks, normalize = True, address_whitelist = perm)
            found = 1
        except:
            print(sys.exc_info())
            cfg = ''
            print('Could not construct CFG with max steps %d, and keep_state = %r'%(steps, ks))
            found = 0
            print('Trying again with max steps: %d'%(steps))

    return found, cfg

def generate_cfg(addr, proj, permit):
    # Parameters used by CFG emulated, can be tweaked to change behavior, e.g. if the graph is too large
    call = None
    steps = None
    ks = True
    found = 0
    ff = False
    perm = permit

    # Used to name the CFG plots
    run = 0

    #create a starting state
    sstate = proj.factory.blank_state(addr = addr, stdin = angr.SimFile)
    
    # Where we try and generate the CFG initially
    found, cfg = try_cfg(proj, ff, [sstate], call, steps, ks, perm)
        
    if cfg != '':
        address = addr
        control_flow = cfg
        print('Graph has %d nodes and %d edges'%(len(cfg.graph.nodes()), len(cfg.graph.edges())))
        return address, control_flow

    else:
        return -1, -1

def print_cfg(cfg, name, out):
    # Generate the CFG images
    name = os.path.join(out, name)
    if not os.path.exists(name):
        plot_cfg(cfg, name, asminst=True, remove_path_terminator=True)
    else:
        print('CFG already exists, skipping')

def hex_conv(a):
    return int(a, 16)

def parse_config(config):
    f = open(config, 'r')
    
    lines = f.readlines()
    args = {'syms': '',
            'bin': '',
            'params': ''}
    
    for line in lines:
        parsed = line.split(':')
        args[parsed[0].strip()]=parsed[1].strip()
    
    t1 = args['syms'].split(' ')
    args['syms'] = []
    for e in t1:
        if e != '':
            args['syms'].append(e)
            
    t1 = args['params'].split(' ')
    args['params'] = []
    for e in t1:
        if e != '':
            args['params'].append(int(e))
    f.close()
    
    return args['syms'], args['bin'], args['params']

def handle_input(args):
    MAX_LEN = args.length
    binary = ''
    syms = []
    params = []
    start_addr = 0
    end_addr = 0
    target_funcs = []
    zfr = args.registerzero
    zfm = args.memoryzero
    nocall = args.nocall
    
    if args.config:
        syms, binary, params = parse_config(args.config)
    if args.symbol:
        syms = args.symbol
    if args.address:
        start_addr = args.address
    if args.end:
        end_addr = args.end
    if not args.symbol and not args.address and not args.target:
        print("No addresses -> no analysis")
        sys.exit("No address given")

    if not args.binary:
        print("No file -> no analysis")
        sys.exit("No file given")
    else:
        binary = args.binary
    try:
        f = open(binary, 'r')
        f.close()
    except:
        pwd = os.getcwd()
        binary = os.path.join(pwd, binary)
        try:
            f = open(binary, 'r')
            f.close()
        except:
            print('Could not open file, exiting')
            sys.exit("Could not open file")
            
    if args.parameters:
        for p in args.parameters:
            params.append(int(p))
    else:
        params = [1, 2, 3, 4, 5, 6, 7, 8, 9]
    

    
    if args.target:
        target_funcs = args.target
            
    return MAX_LEN, binary, syms, params, start_addr, end_addr, target_funcs, zfr, zfm, nocall
        
def get_all_nodes(cfg):
    ret = []
    nodes = cfg.model.nodes()
    for n in nodes:
        ret.append(n)
    return ret

def get_final_states(nodes):
    ret = []
    for n in nodes:
        s = n.input_state
        if s.callstack:
            try:
                print('Ret addr: %x'%s.callstack.ret_addr)
            except:
                print('Could not print return address')
        else:
            print('No callstack?')
        ret.append(get_state_info(s))
    return ret

def get_order(node):
    ret = len(node.successors) + len(node.predecessors)
    return ret

def compare_hist(state_hist, block_list):
    contained = 1
    for b in block_list:
        if b not in state_hist:
            contained = 0
    if contained:
        return len(block_list)
    else:
        return -1

def solve_constraint(state, constr, proj):
    # write = [ [ address, length_of_history_match, expr, expr_len ], ... ]
    addr = -1
    ret = -1
    ret_str = 'Did_Not_Eval'
    ret_byte = 'Did_Not_Eval'
    exprs = []
    
    try:
        addr = state.solver.eval(constr[0])
    except Exception as e:
        #print("During address discover got exception: %s" %e)
        pass
    if get_regs_64(state, get_reg = constr[0]) and addr < 0:
        reg = '%s'%constr[0]
    else:
        reg = 0
    length = constr[3]

    if addr<proj.loader.main_object.min_addr or addr> proj.loader.main_object.max_addr:
         if addr < 0 and not reg:
             return addr, ret, ret_byte, ret_str
         else:
            if reg:
                mem = state.solver.BVS(reg, len(constr[2]))
            else:
                mem = state.solver.BVS('%x'%addr, len(constr[2]))
            if len(constr[2]) > 0:
                state.solver.add(mem == constr[2])
            else:
                print('invalid constraint')
                return addr, ret, ret_byte, ret_str

    else:
        mem = state.memory.load(addr, length)
            
    try:
        ret = state.solver.eval(mem)
    except Exception as e:
        #print("During memory evalutation got exception: %s" %e)

        pass
        
    try:
        ret_byte = state.solver.eval(mem, cast_to=bytes)
        ret_str = "b'{}'".format(''.join('\\x{:02x}'.format(b) for b in ret_byte))
        ret_byte = '%s'%ret_byte
        ret_byte = ret_byte.strip("b'")
    except Exception as e:
        #print("When attempting to cast solution to bytes, got exception: %s" %e)
        pass
        #print('Could not eval memory @ %x, %d as bytes' %(addr, length))
    if reg:
        addr = reg
    else:
        addr = '%x'%addr
    return addr, ret, ret_byte, ret_str

def get_constraints(s, targets, proj, bits):
    constrs = []
    reg_constrs = []
    for e in targets:
        a, c, c_string, c_byte = solve_constraint(s, e, proj)
        if a == -1:
            pass
        else:
            constrs.append( [ a, '%x'%c, c_string, c_byte ] )
        
    if bits == 32:
        reg_constrs = get_regs_32(s)
    elif bits == 64:
        reg_constrs = get_regs_64(s)
    else:
        pass
        
    for c in reg_constrs:
        constrs.append(c)
    return constrs

def get_sat(node):
    sat = []
    unsat = []
    s = node.input_state
    if s.satisfiable():
        sat.append(s)
    else:
        unsat.append(s)
    return sat, unsat

