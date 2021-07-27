import json
import argparse
import os
import angr

proj = ''

def parse_apihooks_json(jason):
    try:
        f = open(jason, "r")
    except:
        print("Couldn't open the JSON file \_('_')_/ sry m8")
        return

    j = json.load(f)

    proc            = j['columns'].index("Process")
    pid_index       = j['columns'].index("PID")
    hook_address    = j['columns'].index("HookAddress")
    victim_module   = j['columns'].index("VictimModule")
    victim_function = j['columns'].index("Function")

    hooks_info = {}

        # there can be multiple entries per hook if control flow redirection is disassembled correctly
    seen = set()

        # build a hash table of pid -> (hook address, victim mod, victim function name) for all hooks
    for hook in j['rows']:
        if hook[0] == "Kernel":
            continue

        pid = hook[pid_index]

        key = "%d|%s" % (hook[hook_address], hook[victim_function])
        if key in seen:
            continue
        seen.add(key)

        if not pid in hooks_info:
            hooks_info[pid] = []
            
        hooks_info[pid].append((hook[proc],
                                hook[hook_address],
                                hook[victim_module],
                                hook[victim_function]))

    return hooks_info

def get_addr_range(f):
    comps = f.split('.')
    for c in comps:
        if '0x' in c:
            addrs = c.split('-')
            if len(addrs) == 2:
                lows = addrs[0].split('x')
                highs = addrs[1].split('x')

                low = lows[1]
                high = highs[1]

                low = int(low, 16)
                high = int(high, 16)
                return low, high
            else:
                print('found not-two potential addresses')

def get_proc_name(f):
    comps = f.split('.')

    c = comps[0].split('_')
    return c[1]

def get_segments(files):
    offset = 0
    ret = []
    for f in sorted(files):
        #print('File: %s' %f)
        low, high = get_addr_range(f)
        #print('Low: %x\nHigh: %x\nOffset: %x'%(low, high, offset))
        segment = low
        size = high - low

        seg = '%x'%segment
        s = '%x'%size
        off = '%x'%offset

        seg = int(seg, 16)
        s = int(s, 16)
        off = int(off, 16)
        
        triple = (off, seg, s)
        ret.append(triple)
        offset = offset + size + 1
    return ret

