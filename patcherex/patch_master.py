from canary_patcher import CanaryPatcher

class PatchMaster():
    
    def __init__(self,infile):
        self.infile = infile

    def run(self):
        #TODO file stuff
        cp = CanaryPatcher(self.infile,"/tmp/poutfile")
        cp.apply_to_entire_bin()

        return [open("/tmp/poutfile").read()]

