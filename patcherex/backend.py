
import logging

import angr

l = logging.getLogger('backend')

class Backend(object):
    """
    Patcher backend.
    """

    def __init__(self, filename):
        """
        Constructor

        :param str filename: The binary file to patch
        """

        # file info
        self.filename = filename
        self.project = angr.Project(filename)
        with open(filename, "rb") as f:
            self.ocontent = f.read()

        self.cfg = self._generate_cfg()
        self.ordered_nodes = self._get_ordered_nodes()

    #
    # Public methods
    #

    def apply_patches(self, patches):
        """
        Apply all patches on this binary

        :param list patches: A list of patches to apply
        :return: None
        """

        raise NotImplementedError()

    def save(self, filename=None):
        """
        Save the patched binary onto disk.

        :param str filename: The new file path to save to. If None, the original binary will be overwritten.
        :return: None
        """

        raise NotImplementedError()

    def get_final_content(self):
        """
        Get the patched binary as a byte string.

        :return: The patched binary as a byte string.
        :rtype: str
        """

        raise NotImplementedError()

    #
    # Private methods
    #

    def _generate_cfg(self):
        """
        Generate a control flow graph, make sure necessary steps are performed, and return a CFG.

        :return: The CFG object
        :rtype: angr.analyses.CFG
        """

        # TODO
        # 1) ida-like cfg
        # 2) with some strategies we don't need the cfg, we should be able to apply those strategies even if the cfg fails
        l.info("CFG start...")
        cfg = self.project.analyses.CFGFast(normalize=True)
        l.info("... CFG end")

        return cfg

    def _get_ordered_nodes(self):
        prev_addr = None
        ordered_nodes = []
        for n in sorted(self.cfg.nodes(), key=lambda x: x.addr):
            if n.addr == prev_addr:
                continue
            prev_addr = n.addr
            ordered_nodes.append(n.addr)
        return ordered_nodes
