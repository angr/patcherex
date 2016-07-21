import fidget

def fidget_it(infile, outfile, mode='safe'):
    if mode == 'normal':
        technique = fidget.FidgetDefaultTechnique()
    elif mode == 'safe':
        technique = fidget.FidgetDefaultTechnique(safe=True)
    elif mode == 'huge':
        technique = fidget.FidgetDefaultTechnique(largemode=True)
    elif mode == 'hugesafe':
        technique = fidget.FidgetDefaultTechnique(safe=True, largemode=True)

    fidgetress = fidget.Fidget(infile)
    fidgetress.patch_stack(technique)
    fidgetress.apply_patches(outfile)
