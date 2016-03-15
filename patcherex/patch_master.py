from canary_patcher import CanaryPatcher

class PatchMaster():
    
    def __init__(self,infile):
        self.infile = infile

    def run(self):
        #TODO file stuff
        cp = CanaryPatcher(self.infile,"/tmp/poutfile")
        cp.apply_to_entire_bin()

        original_blob = open(self.infile).read()

        #TODO also add 1 byte patch
        return [original_blob,open("/tmp/poutfile").read()]

