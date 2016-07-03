
class Technique(object):
    """
    Base class of all defense techniques.

    :ivar Backend backend: The patching backend.
    """

    def __init__(self, filename, backend):
        self.filename = filename
        self.backend = backend

    @property
    def patcher(self):
        return self.backend

    def get_patches(self):
        """
        Get all patches in order to apply this technique on the binary.

        :return: A list of patches.
        :rtype: list
        """

        raise NotImplementedError()
