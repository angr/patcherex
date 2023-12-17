from .binary_analyzer import BinaryAnalyzer
from headless_ida import HeadlessIdaRemote


class Ida(BinaryAnalyzer):
    _DEFAULT_LOAD_BASE = 0x0

    def __init__(self, binary_path, **kwargs) -> None:
        self.binary_path = binary_path
        self.kwargs = kwargs
        self.ida_server_host = (
            kwargs["ida_server_host"] if "ida_server_host" in kwargs else "localhost"
        )
        self.ida_server_port = (
            kwargs["ida_server_port"] if "ida_server_port" in kwargs else 1337
        )
        self._headlessida = HeadlessIdaRemote(
            self.ida_server_host, self.ida_server_port, self.binary_path
        )
        ida_libs = [
            "idc",
            "idautils",
            "idaapi",
            "ida_funcs",
            "ida_xref",
            "ida_nalt",
            "ida_auto",
            "ida_hexrays",
            "ida_name",
            "ida_expr",
            "ida_struct",
            "ida_typeinf",
            "ida_loader",
            "ida_lines",
            "ida_segment",
            "ida_gdl",
        ]
        for lib in ida_libs:
            setattr(self, lib, self._headlessida.import_module(lib))

    def mem_addr_to_file_offset(self, addr):
        return self.ida_loader.get_fileregion_offset(addr)

    def get_basic_block(self, addr):
        func = self.ida_funcs.get_func(addr)
        instr_addrs = list(func.code_items())
        assert addr in instr_addrs, "Invalid address"
        flowchart = self.ida_gdl.FlowChart(f=func, flags=self.ida_gdl.FC_PREDS)

        for block in flowchart:
            if block.start_ea <= addr < block.end_ea:
                return {
                    "start": block.start_ea,
                    "end": block.end_ea,
                    "size": block.end_ea - block.start_ea,
                    "instruction_addrs": [
                        ea for ea in instr_addrs if block.start_ea <= ea < block.end_ea
                    ],
                }

    def get_instr_bytes_at(self, addr):
        return self.p.factory.block(addr, num_inst=1).bytes
