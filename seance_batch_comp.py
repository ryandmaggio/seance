import os
import sys
def main(targ_dir):
    with open('target_syms.txt', 'r') as f:
        lines = f.readlines()
        test = [ '5.dylib-x86_64_emu_out', '6.dylib-x86_64_emu_out', '3.dylib-x86_64_emu_out', '16.dylib-x86_64_emu_out', '17.dylib-x86_64_emu_out', '19.dylib-x86_64_emu_out' ]
        for t in test:
            ts = t.split('.')
            out = ts[0] + '.result'
            targ = os.path.join(targ_dir, t)
            dump = os.path.join(targ, out)
            os.system("rm %s"%dump)
            
            for line in lines:
                line = line.strip('\n')
                db = 'database_'+line
                temp = os.path.join(targ, line)
                print("Testing %s (%s) against %s"%(line, db, temp))
                os.system("echo '%s' >> %s"%(line, dump))
                os.system('python seance_check.py %s %s >> %s'%(db, temp, dump))
                os.system("echo '\n' >> %s"%dump)
                
if __name__ == "__main__":
    targ_dir = sys.argv[1]
    main(targ_dir)
