
import logging

import angr
import cle

l = logging.getLogger('patcherex.backend')

FIND_FUNCS = (
    'malloc',
    'printf',
    'fdprintf',
    'fprintf',
    'sprintf',
    'snprintf',
)

def better_symbol_repr(sym: cle.Symbol):
    """
    Returns a string representation of a symbol containing all relevant information.
    """
    # pylint: disable=multiple-statements
    attrs = []
    if sym.is_static:   attrs.append('static')
    if sym.is_common:   attrs.append('common')
    if sym.is_import:   attrs.append('import')
    if sym.is_export:   attrs.append('export')
    if sym.is_local:    attrs.append('local')
    if sym.is_weak:     attrs.append('weak')
    if sym.is_extern:   attrs.append('extern')
    if sym.is_forward:  attrs.append('forward')

    return f"{sym.name=:<40} {sym.type=:<20} {sym.relative_addr=:<16} {sym.size=:<10} {attrs=}"

class Backend:
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
        self.project = angr.Project(
            filename,
            load_options={"auto_load_libs": False},
            **project_options)
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

        :param str filename: The new file path to save to. If None,
                             the original binary will be overwritten.
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
            cfg = self._generate_cfg()
            self._identifer = self.project.analyses.Identifier(cfg, require_predecessors=False)
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
        # 2) with some strategies we don't need the cfg, we should be able
        #    to apply those strategies even if the cfg fails
        l.info("CFG start...")
        cfg = self.project.analyses.CFGFast(normalize=True, data_references=True)
        l.info("... CFG end")

        return cfg

    def _default_symbols(self, patches=None):
        """
        Get the default symbols for this binary.

        :return: A list of default symbols
        :rtype: list
        """

        default_syms = {}

        loader: cle.loader.Loader = self.project.loader
        obj = loader.main_object
        if not isinstance(obj, cle.backends.ELF):
            l.warning("Default symbols are only available for ELF binaries, disabling...")
            return {}

        for sym in obj.symbols:
            if sym.is_import:
                continue
            if sym.type not in {cle.SymbolType.TYPE_FUNCTION, cle.SymbolType.TYPE_OBJECT}:
                continue

            if sym.relative_addr == 0:
                r = better_symbol_repr(sym)
                assert False, f"Symbol {sym!r} has relative address 0: {r}"
            default_syms[sym.name] = sym.relative_addr

        for name, addr in obj.plt.items():
            default_syms[name] = addr

        return default_syms

    def _get_ordered_nodes(self, cfg):
        prev_addr = None
        ordered_nodes = []
        for n in sorted(cfg.model.nodes(), key=lambda x: x.addr):
            if n.addr == prev_addr:
                continue
            prev_addr = n.addr
            ordered_nodes.append(n.addr)
        return ordered_nodes
