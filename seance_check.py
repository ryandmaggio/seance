import json
import sys
import os

def collect_offs(offsets):
    params =   {'rdi': [],
                   'rsi': [],
                   'rdx': [],
                   'rcx': [],
                   'r8':  [],
                   'r9':  []}
    for reglist in offsets:
        for reg in reglist:
            for off in reglist[reg]:
                if off not in params[reg]:
                    params[reg].append(off)
    return params
def main(sfile, tdir):



    sf = open(sfile, 'r')
    database = json.load(sf)
    
    g_found = 0
    db_params =   {'rdi': [],
                   'rsi': [],
                   'rdx': [],
                   'rcx': [],
                   'r8':  [],
                   'r9':  []}
    last_params = {'rdi': [],
                   'rsi': [],
                   'rdx': [],
                   'rcx': [],
                   'r8':  [],
                   'r9':  []}
    omatch_files = []
    gmatch_files = []
    pmatch_files = []
    spmatch_files = []                  
    for subdir in os.listdir(tdir):
        if 'json' in subdir:
            fname = os.path.join(tdir, subdir)
            f = open(fname, 'r')
            if 'offset' in subdir:
                j = json.load(f)
                
                for entry in database:
                    if entry['offsets'] == j:
                        #print('Found offset match!')
                        omatch_files.append(entry['file'])
                    else:
                        dparam = collect_offs(entry['offsets'])
                        tparam = collect_offs(j)
                        if dparam == tparam:
                            pmatch_files.append(entry['file'])
                        else:
                            temp = []
                            for reg in dparam:
                                if dparam[reg] != [] and dparam[reg] == tparam[reg]:
                                    temp.append(reg)
                            if temp != []:
                                spmatch_files.append([entry['file'], temp])
                                    
            if 'cfg_analysis' in subdir:
                j = json.load(f)
                
                for entry in database:
                    if entry['cfg_info'] == j:
                        #print('Found CFG match!')
                        gmatch_files.append(entry['file'])
            f.close()
    for of in omatch_files:
        if of in gmatch_files:
            print('Fingerprint matches %s'%of)
        else:
            print('Matches offsets of %s but the CFG changed'%of)
            
    for pf in pmatch_files:
        print('Raw offsets match %s'%pf)
    
    for sf in spmatch_files:
        print('Specific parameter match on %s for '%sf[0], end = '', flush=False)
        print(sf[1])

    if omatch_files == []:
        print('Fingerprint does not match anything in database')
        
                
                     

if __name__ == "__main__":
    sfile = sys.argv[1]
    tfile = sys.argv[2]
    main(sfile, tfile)
