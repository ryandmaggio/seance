import json
import os

def dir_iter(sdir, sym, test):
    result = []

    for subdir in os.listdir(sdir):
        if 'emu' in subdir and subdir not in test:
            it = os.path.join(sdir, subdir)
            for subsubdir in os.listdir(it):
                i = os.path.join(it, subsubdir)
                if sym in subsubdir:
                    temp = { 'file': '',
                             'offsets': [],
                             'cfg_info': []}
                    for d in os.listdir(i):
                        if 'json' in d and 'offset' in d:
                            dname = os.path.join(i, d)
                            f = open(dname, 'r')
                            j = json.load(f)
                            f.close()
                            temp['offsets'] = j
                            temp['file'] = subdir.strip('_emu_out')
                        elif 'json' in d and 'cfg_analysis' in d:
                            dname = os.path.join(i, d)
                            f = open(dname, 'r')
                            j = json.load(f)
                            f.close()
                            temp['cfg_info'] = j
                    result.append(temp)
    return result

def main():
    sdir = 'dylibs'
    oname = 'database'
    test = [ '5.dylib-x86_64_emu_out', '6.dylib-x86_64_emu_out', '3.dylib-x86_64_emu_out', '16.dylib-x86_64_emu_out', '17.dylib-x86_64_emu_out', '19.dylib-x86_64_emu_out' ]
    result = []
    symfile = open('target_syms.txt', 'r')
    lines = symfile.readlines()
    for line in lines:
        print("line: %s"%line)
        line = line.strip('\n')
        result = dir_iter(sdir, line, test)
        out = open(oname + '_'+line, 'w')
        json.dump(result, out)
        out.close()

if __name__ == "__main__":
    main()
