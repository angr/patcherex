import logging
logging.getLogger('patcherex').addHandler(logging.NullHandler())


def get_backdoorpov():
    import os

    self_location_folder = os.path.dirname(os.path.realpath(__file__))
    backdoorpov_fname = os.path.join(self_location_folder,"../backdoor_stuff/backdoor_pov.pov")
    with open(backdoorpov_fname, "rb") as fp:
        content = fp.read()
    return content
