import logging

logger = logging.getLogger(__name__)


class BinFmtTool:
    def __init__(self, p, binary_path):
        self.p = p
        self.binary_path = binary_path

    def _init_memory_analysis(self):
        raise NotImplementedError()

    def save_binary(self, filename=None):
        raise NotImplementedError()

    def update_binary_content(self, offset, new_content):
        raise NotImplementedError()

    def append_to_binary_content(self, new_content):
        raise NotImplementedError()
