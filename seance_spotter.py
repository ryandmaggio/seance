import logging
from ..util.lifter_helper import GymratLifter
from ..util.instr_helper import Instruction
from .. import register

l = logging.getLogger(__name__)

class KernelInstr(Instruction):
    pass
    
class Instruction_CR8Read(KernelInstr):
    name = "CR8Read"
    bin_format = "010001000000111100100000rrrrrrrr"
    def compute_result(self):
        self.put(0, int(self.data['r'], 2))
        
class KernSpotter(GymratLifter):
    kern_instrs = [
        Instruction_CR8Read,
        ]
        
    instrs = None
    
    def lift(self, disassemble=False, dumb_irsb=False):
        self.instrs = kern_instrs
        super(KernSpotter, self).lift(disassemble, dump_irsb)
        
register(KernSpotter, "AMD64")
