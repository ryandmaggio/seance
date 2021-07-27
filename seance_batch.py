import os
import sys
def loop(sym):
    sdir = 'dylibs'
    t_block = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 18, 20]
    block = []
    for b in t_block:
         block.append(str(b)+'.dylib-x86_64')
    #syms = 'target_syms.txt'
    rprobsym = ['_ivar_getTypeEncoding', '_ivar_getName', '_ivar_getOffset', '_method_getImplementation', '_method_getName', '_object_getClass', '__ZL14removeSubclassP10objc_classS0_']
    mprobsym = ['_NXEmptyHashTable']
    for n in os.listdir(sdir):
        dest = os.path.join(sdir, n + '_emu_out')
        dest = os.path.join(dest, sym)
        
        if n not in block and "dylib" in n and "emu" not in n and "dup" not in n:

            rflag = ''
            mflag = ''
            if sym in rprobsym:
                rflag = '-r 0'
            if sym in mprobsym:
                mflag = '-m 1'
            n = os.path.join(sdir, n)
            print("\n++++++++TRYING %s"%n)
            os.system("python seance.py -b %s -s %s -p 1 2 3 4 5 6 -l 7 %s %s 2>/dev/null" %(n, sym, rflag, mflag))
            
def main(targ):
    with open(targ, 'r') as f:
        lines = f.readlines()
        for line in lines:
            line= line.strip('\n')
            print(line)
            loop(line)            
if __name__ == '__main__':
    sym = sys.argv[1]
    main(sym)
