import os
import sys
import json
import argparse

g_params = {'rdi': 1,
            'rsi': 2,
            'rdx': 3,
            'rcx': 4,
            'r8':  5,
            'r9':  6,
            'rbp': 7,
            'r10': 8,
            'r14': 9}
            
            
def analyze_pointers(reads, mwrites, mreads, targets):
    pointers = calculate_offsets(mwrites, mreads, targets, 0)
    
    provenance = find_pointer_source(reads, reads, pointers)
    d_reads = []
    for tup in provenance:
        try:
            temp = int(tup[1], 16)
            d_reads.append(tup)
        except:
            pass
    #print("Still pointers after tracing:")
    #print(d_reads)
    #print("Double pointer sources:")
    d_points = find_pointer_source(reads, d_reads, pointers)

    tie = []
    for tup in provenance:
        found = 0
        for d_tup in d_points:
            if d_tup[0] == tup[1]:
                found = 1
                #temp = '%s -> %s -> %s'%(d_tup[1], d_tup[0], tup[0])
                temp = [tup[0], d_tup[0], d_tup[1]]
                tie.append(temp)
        if not found:
            #temp = '%s -> %s'%(tup[1], tup[0])
            tie.append(tup)
            
    #print("Pointer provenance:")
    #print(tie)
    
    references = {}
    for t in tie:
        try:
            p = pointers[t[0]]
            rev = t[::-1]
            s = ''
            for r in rev:
                s = s + '%s -> '%r
            s = s.strip(' ->')
            references[s] = pointers[t[0]]
        except:
            pass
    print_param_access(references, '/dev/null', "Traced Pointer")
    return pointers, references
            
def find_pointer_source(reads, pointers, offsets):
    track = {}
    ret = []
    for p in pointers:
        track[p[1]] = []
    #print("Pointers:")
    #print(ret)
    for p in pointers:
        found = []
        for o in offsets:
            i = int(o, 16)
            for off in offsets[o]:
                i_off = int(off, 16)
                if i + i_off == int(p[1], 16):
                    #print("Found!")
                    #print(o)
                    found.append(o)
        for f in found:
            for r in reads:
                if r[1] == f and r[0] not in track[p[1]]:
                    track[p[1]].append(r[0])
                    ret.append([p[1], r[0]])
    #print(ret)
    return ret
    
def print_param_access(access, fname, kind = "Register"):
    global g_params
    f = open(fname, 'w')
    
    
    print('\n> %s Access:'%kind)
    f.write('\n> %s Access:'%kind)
    for r in access:
        print('    %s %s'%(kind, r))
        f.write('    %s %s'%(kind, r))
        

        
        print('    Accesses occured at offsets: %s'%access[r])
        f.write('    Accesses occured at offsets: %s'%access[r])
    f.close()
    

def track_parameters(reads, plist):
    global g_params
    params = {'rdi': '',
              'rsi': '',
              'rdx': '',
              'rcx': '',
              'r8':  '',
              'r9':  '',
              'rbp': '',
              'r10': '',
              'r14': ''}
    ret = []
    
    for read in reads:
        if read[0] in params:
            if params[read[0]] == '':
                if g_params[read[0]] in plist:
                    params[read[0]] = read
                    ret.append(read)

    return ret
            

def calculate_offsets(writes, reads, targets, t_type):
    global g_params
    # keep things sane
    wrap = 0xffffffffffffffff
    limit = 1000
    
    p = []
    ret = {}

    if t_type:
        index = 0
        kind = "Register"
    else:
        index = 1
        kind = "Pointer"
    for pointer in targets:
        #print(pointer)
        ret[pointer[index]] = []
    p = targets

    for param in p:
        p_val = int(param[1], 16)
        if p_val < 0:
            continue
        offs = []
        for access in writes + reads:
            try:
                loc = int(access[0], 16)
            except:
                print("Could not convert to int (find_parameters.py)")
                continue
            if loc-p_val < limit and p_val-loc < limit:
                offs.append('%x'%(loc-p_val))
            elif loc < limit and wrap - p_val < limit:
                offs.append('%x'%((wrap - p_val)+loc+1))
            
        for off in offs:
            if off not in ret[param[index]]:
                ret[param[index]].append(off)


    #print('\n> %s Access:'%kind)
    #for r in ret:
    #    print('    %s %s'%(kind, r))
    #    print('    Accesses occured at offsets: %s'%ret[r])
    #for r in ret:
    #    print('%x: '%r[0], end = '', flush = True)
    #    r[1] = sorted(r[1])
    #    temp = []
    #    for e in r[1]:
    #        print('%x, '%e, end = '', flush = True)
    #    print('')
    empty = 1
    for r in ret:
        if ret[r] != []:
            empty = 0
    if not empty:
        return ret
    else:
        return []
    
def sort_access(jason, plist=[1,2,3,4,5,6,7,8,9]):
    if not jason:
        print("Need json file to operate")
        return
    regs = ['rax', 'rbx', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rdi', 'rsi', 'rbp', 'rsp', 'rip', 'eflags']
    f = open(jason, 'r')
    j = json.load(f)

    state = j["state"]
    writes = j["write"]
    reads = j["read"]
    rwrites = []
    rreads = []
    mwrites = []
    mreads = []

    for w in writes:
        if w[0] in regs:
            rwrites.append(w)
        else:
            mwrites.append(w)
    for r in reads:
        if r[0] in regs:
            rreads.append(r)
        else:
            mreads.append(r)
            

    print('State through blocks', end = '', flush = True)
    for block in state:
        print(' %s '%block, end = '', flush=True)
    print('\n')
    
    params = track_parameters(rreads, plist)
    #pointers = track_parameters(rwrites, plist, 1)
    #print(pointers)
    offs = calculate_offsets(mwrites, mreads, params, 1)
    pointers, references = analyze_pointers(reads, mwrites, mreads, reads)
    
    ret = []
    
    f.close()
    
    return offs, pointers, references

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Parse the supplied JSON and analyze")
    parser.add_argument('-j', '--json', metavar = 'J', type=str, help='JSON to parse')

    args = parser.parse_args()
    sort_access(args.json)
