import json
import argparse
import os
import angr
from angrutils import *
import graphviz
import pydot
import seance_jparse
from seance_api import *
from seance_find_parameters import *
from seance_meta import *
from pyvex.lifting.gym import seance_spotter
import magic
import sys

def main(args):

    MAX_LEN, binary, syms, params, start_addr, end_addr, target_calls, zfr, zfm, nocall = handle_input(args)
    arch = magic.from_file(binary)
    temp_proj = angr.Project(binary)
    t_arch = temp_proj.loader.main_object

    gout_dir = '%s_emu_out'%binary
    if not os.path.isdir(gout_dir):
        os.mkdir(gout_dir)

    # Use this one if working with mach-o files, like the objc dylibs
    # TODO: switch parameter order on mac vs windows usage
    if "Mach-O" in arch:
        proj = angr.Project(binary, load_options={'auto_load_libs':False, 'main_opts': {'backend':'mach-o', 'base_addr':0x0}})
    # Else (for instance PE files) use this one. Very possible there needs to be other cases, but this is what I worked on.
    else:
        proj = angr.Project(binary)
    init_reg_dict(proj.arch)
    base = proj.loader.main_object.min_addr
    addrs = []

    # If we are given an opcode, first we attempt to retrieve the basic block containing the target call instruction, using the start
    # address of that block as the starting addr, and the address of the call as the ending addr
    if syms != [] and target_calls != []:
        candidate_list = find_bb_containing(proj, target_calls)
        if candidate_list == []:
            print("Could not find basic block containing this address")
            sys.exit()

        jumps_out = []
        for s in syms:
            temp = find_jumps_out(proj, s)
            for t in temp:
                jumps_out.append(t)
        regions = []
        if jumps_out != []:
            regions = get_jump_regions(jumps_out)
        s, e = lookup_func(proj, syms[0])
        regions.append([s, e])
        for c in candidate_list:
            
            for r in regions:
                if c[0] in range(r[0], r[1]):
                    
                    if c[0] == c[1] and args.under:
                        t_block = proj.factory.block(c[0])
                        insn = t_block.capstone.insns[-1].insn
                        next = insn.size + insn.address
                        c[0] = next
                        c[1] = proj.factory.block(next).capstone.insns[-1].address
                    addrs.append([c[0], c[1], '%x'%c[0]])
        if addrs == []:
            sys.exit("No matches found")
        
    # If we were not given an opcode, but we were given an address range, use that range as our starting and ending address.
    elif start_addr > 0 and end_addr > 0:
        if syms != []:
            n = syms[0]
        else:
            n = '%x'%start_addr
        addrs.append([start_addr + base, end_addr + base, n])
    # If we are not given an address range, but we are given a list of symbols, resolve those symbols and use the starting/ending addresses for each of them
    elif syms != []:
        for sym in syms:
            a, e, sym_o = get_symbol_addr(sym, proj)
            print("Symbol addr: %x" %a)
            print("Symbol end: %x" %e)
            #if e == -1:
            #    e = a + 0x100
            addrs.append([a, e, sym])
            if not os.path.isdir(os.path.join(gout_dir, sym)):
                os.mkdir(os.path.join(gout_dir, sym))
                
    # For reference: addr = [start_addr: int, end_addr: int, sym_name: str]
    for addr in addrs:
        print("%x : %x | %s"%(addr[0], addr[1], addr[2]))
        out_dir = os.path.join(gout_dir, addr[2])
        if not os.path.isfile(out_dir) and not os.path.isdir(out_dir):
            os.mkdir(out_dir)
        #graph = proj.analyses.CFGEmulated(starts=[addr[0]], enable_advanced_backward_slicing=True, keep_state=True)
        #input("CFG generated")

        
        graph = proj.analyses.CFGFast(regions = [(addr[0], addr[1])])

        graph_analysis = n_analyze_cfg(graph)
        fname = 'cfg_analysis_%s_%x.json'%(addr[2], addr[0])
        make_json(fname, out_dir, graph_analysis)
        
        ends = []
        
        #Collect up all of the ending addresses of all of the dead-end blocks reached (sort of..........)
        try:
            ends = get_dead_ends(graph.deadends, proj)
        except:
            dends = get_leaves(graph)
            ends = get_dead_ends(dends, proj)
            

        name = '%s_%x_cfg'%(addr[2], addr[0])
        name = os.path.join(out_dir, name)

        try:
            plot_cfg(graph, name, asminst=True, remove_path_terminator=False)
        except Exception as e:
            print(e)
        #input("CFG generated")
        if addr[1] not in ends:
            ends.append(addr[1])
            
        

        # Use the collected ending addresses to set limits on emulation, running a new emulation instance for each ending addr
        for end in ends:
            if end == -1:
                continue
            zero_info()
            emulating()
        
            state = proj.factory.entry_state(addr = addr[0])
            print(state)
            print('end: %x' %end)
            #input('')

            # Add state options to make symbolic execution not horrible maybe
            for opt in angr.options.symbolic:
                state.options.add(opt)
                
            # Mess with in the future, MIGHT be cleaner than current memory access tracking
            #for opt in angr.options.refs:
            #    state.options.add(opt)
            
            if zfr == 1:
                # Toggle first if something isn't working
                print('Zero-filling registers')
                state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
            
            if zfm == 1:
                #Probably won't fix anything, but you can try it
                print('Zero-filling memory')
                state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
            if nocall == 1:
                # Skip function calls, toggle this to try fixing things
                print('Skipping function calls')
                state.options.add(angr.sim_options.CALLLESS)
            
            
            #state.options.add(angr.options.CONCRETIZE)
            
            # helpful tip given in angr slack, used for debugging with state.solver.unsat_core (Don't know how though)
            #state.options.add(angr.options.CONSTRAINT_TRACKING_IN_SOLVER)
                
            # Add callbacks for reads and writes
            state.inspect.b('mem_write', when = angr.BP_AFTER, action = hook_mwrite)
            state.inspect.b('reg_write', when = angr.BP_AFTER, action = hook_rwrite)
            state.inspect.b('mem_read', when = angr.BP_AFTER, action = hook_mread)
            state.inspect.b('reg_read', when = angr.BP_AFTER, action = hook_rread)
            
            simgr = proj.factory.simgr(state, save_unsat=True, save_unconstrained=True)
            #simgr = proj.factory.simgr(state)
            regs = get_regs_64(state)
            for r in regs:
                if r[0] == 'rsp':
                    mem_base = r[1]

            # Explore with custom exploration technique that maybe is better for what we want than what is already provided
            #simgr.use_technique(angr.exploration_techniques.Seance_Explore(max_length=MAX_LEN, addr=end))
            # Explore using built in 'explore' technique, which might behave better
            simgr.explore(find=addr[1])
            #print(simgr.stashes)
            #input('')
            #simgr.run()
            emulating()
            
            
            # Collect all of the memory constraints from each stash we have
            stashes = simgr.stashes
 
            mem_constr, permit = handle_stashes(stashes, proj, 64)
        
            state_files = []
            temp = []
            # Temporary dict for holding constraint information
            tmem_constr = { 'state': [], 'write': [], 'read':[]}
        
            # Save a constraint file for each ending state
            sync = 0
            for s in mem_constr['state']:
                b = ''
                
                # Extract blocks from state name to flatten to a string for naming the file
                for block in s:
                    b += '-%s'%block
                fname = 'end_state_%s_%x%s'%(addr[2], addr[0], b)
                
                # Record the name of the file we just made
                #t_name = truncate(fname)
                #t_t_name = t_name
                #count = 2
                #while(t_name in state_files):
                #    print("renaming file %s" %t_name)
                #    t_t_name = '%d_'%count + t_name
                #    count += 1
                #fname = t_t_name
                state_files.append(fname)
                
                # Decompose the constraints into a more useful form (one file per state which holds constraints relevant only to that state)
                tmem_constr['state'] = s
                tmem_constr['write'] = mem_constr['write'][sync]
                tmem_constr['read'] = mem_constr['read'][sync]
                make_json(fname, out_dir, tmem_constr)
                sync += 1
            
            for r in regs:
                temp.append(r)
            for m in mem_constr['write']:
                for e in m:
                    temp.append(e)
            #regs.append(mem_constr['evals'])
            tmem_constr['write'] = temp
            temp = []
            for m in mem_constr['read']:
                for e in m:
                    temp.append(e)
            tmem_constr['read'] = temp

            fname = 'emu_info_%s_%x.json'%(addr[2],addr[0])
            make_json(fname, out_dir, tmem_constr)
        
            offsets = []
            p_offsets = []
            r_offsets = []
            for f in state_files:
                o, p, r = sort_access(os.path.join(out_dir,f), params)
                if o != []:
                    pfname = 'params_' + f.strip('end_state_')
                    param_file = os.path.join(out_dir, pfname)
                    print_param_access(o, param_file)
                    offsets.append(o)
                pgname = 'pointer_offsets_' + f.strip('end_state_')
                pointer_file = os.path.join(out_dir, pgname)
                print_param_access(p, pointer_file, "Pointer")
                p_offsets.append(p)
                
                prname = 'traced_pointer_offsets_' + f.strip('end_state_')
                references_file = os.path.join(out_dir, prname)
                print_param_access(r, references_file, "Traced Pointer")
                r_offsets.append(r)
                    
            gname = 'pointer_%s_%x.json'%(addr[2], addr[0])
            fname = 'offset_%s_%x.json'%(addr[2],addr[0])
            rname = 'traced_pointer_%s_%x.json'%(addr[2],addr[0])
            make_json(fname, out_dir, offsets)
            make_json(gname, out_dir, p_offsets)
            make_json(rname, out_dir, r_offsets)
            
            
            
            # Generate the CFG using the permit list we made to keep it under control
            address, cfg = generate_cfg(addr[0], proj, permit)
        
        
            # Generate the CFG and perform some analysis, if a reasonable CFG was generated
            if address != -1:
                name = 'END_%x_%s_%x_cfg'%(end, addr[2], addr[0])
                print_cfg(cfg, name, out_dir)
                analyze_cfg(cfg, addr[0])
            else:
                print("CFG generation went wrong")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Kick off Seance for symbol analysis")
    parser.add_argument('-c', '--config', metavar = 'C', type=str, help='Config file to parse.')
    parser.add_argument('-s', '--symbol', metavar = 'S', nargs='+', help='Names of the functions we want. Given as a space-separated list. (Usually just 1)')
    parser.add_argument('-a', '--address', metavar = 'A', type=hex_conv, help='Address (as offset from base address) of the function we want (E.g. if the base address is 0x100 and the function is at 0x160, give 0x60).')
    parser.add_argument('-e', '--end', metavar = 'E', type=hex_conv, help='Ending address (as offset from base address) of the function we want (E.g. if the base address is 0x100 and the function ends at 0x160, give 0x60).')
    parser.add_argument('-t', '--target', metavar='T', nargs='+', help='List of addresses or function names to target with the basic block discovery code. Given as a space-separated list.')
    parser.add_argument('-u', '--under', metavar='U', type=int, default = 1, help='Set to 1 if you want to get the basic block under (after) the single call targeted with -t, set to 0 if you want the previous one')
    parser.add_argument('-b', '--binary', metavar='B', type=str, help='The binary we want to analyze.')
    parser.add_argument('-l', '--length', metavar = 'L', type=int, default = 5, help='The maximum depth to analyse.')
    parser.add_argument('-p', '--parameters', metavar = 'P', nargs='*', help='The parameters to look at.')
    parser.add_argument('-r', '--registerzero', metavar = 'R', type=int, default=1, help='Zero fill unconstrained registers (default 1, zero fill registers).')
    parser.add_argument('-m', '--memoryzero', metavar = 'M', type=int, default=0, help='Zero fill unconstrained memory (default 0, non-zero filled).')
    parser.add_argument('-n', '--nocall', metavar = 'N', type=int, default=0, help='Skip function calls (default 0, no skip).')

    args = parser.parse_args()
    main(args)
