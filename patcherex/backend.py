
import logging

import angr

l = logging.getLogger('patcherex.backend')

FIND_FUNCS = (
    'malloc',
    'printf',
    'fdprintf',
    'fprintf',
    'sprintf',
    'snprintf',
)


class Backend(object):
    """
    Patcher backend.
    """

    def __init__(self, filename, try_pdf_removal=True, project_options=None):
        """
        Constructor

        :param str filename: The binary file to patch
        """

        project_options = {} if project_options is None else project_options

        # file info
        self.filename = filename
        self.try_pdf_removal = try_pdf_removal
        self.pdf_removed = False # has the pdf actually been removed?
        self.project = angr.Project(filename, load_options={"auto_load_libs": False}, **project_options)
        self._identifer = None
        with open(filename, "rb") as f:
            self.ocontent = f.read()

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

    @property
    def identifier(self):
        if self._identifer is None:
            self._identifer = self.project.analyses.Identifier(self.cfg, require_predecessors=False)
            list(self._identifer.run(only_find=FIND_FUNCS))
        return self._identifer


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
        cfg = self.project.analyses.CFGFast(normalize=True, data_references=True)
        l.info("... CFG end")

        return cfg

    def _get_ordered_nodes(self, cfg):
        prev_addr = None
        ordered_nodes = []
        for n in sorted(cfg.model.nodes(), key=lambda x: x.addr):
            if n.addr == prev_addr:
                continue
            prev_addr = n.addr
            ordered_nodes.append(n.addr)
        return ordered_nodes
