import os, requests, tempfile, tarfile, logging
from pathlib import Path

logger = logging.getLogger(__name__)


class Assets:
    ASSETS_DIR = Path(__file__).parent
    ASSETS = {
        "bcc": {
            "url": "https://f002.backblazeb2.com/file/patcherex/assets/bcc-2.2.4-gcc-linux64.tar.xz",
            "path": ASSETS_DIR / "bcc" / "bcc-2.2.4-gcc" / "bin",
        },
        "ppc_vle": {
            "url": "https://f002.backblazeb2.com/file/patcherex/assets/powerpc-eabivle.tgz",
            "path": ASSETS_DIR / "ppc_vle" / "bin",
        },
    }

    def __init__(self, name):
        self.name = name
        self.url = self.ASSETS[name]["url"]
        self.path = self.ASSETS[name]["path"]
        if not os.path.exists(self.ASSETS_DIR / self.name):
            logger.info(f"{self.name} not found, downloading...")
            self.download()

    def download(self):
        r = requests.get(self.url)
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "asset.tar.xz"), "wb") as f:
                f.write(r.content)
            with tarfile.open(os.path.join(td, "asset.tar.xz")) as tar:
                tar.extractall(path=self.ASSETS_DIR / self.name)
