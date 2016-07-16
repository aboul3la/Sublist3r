#!/usr/bin/env python
# coding: utf-8

import sys

def banner():
    #Import Colour Scheme
    G,Y,B,R,W = colour()

    print """%s
                 ____        _     _ _     _   _____
                / ___| _   _| |__ | (_)___| |_|___ / _ __
                \___ \| | | | '_ \| | / __| __| |_ \| '__|
                 ___) | |_| | |_) | | \__ \ |_ ___) | |
                |____/ \__,_|_.__/|_|_|___/\__|____/|_|%s%s

                 # Coded By Ahmed Aboul-Ela - @aboul3la
    """%(R,W,Y)

def colour():
    #Check if we are running this on windows platform
    is_windows = sys.platform.startswith('win')

    #Console Colors
    if is_windows:
        G = Y = B = R = W = G = Y = B = R = W = '' #use no terminal colors on windows
    else:
        G = '\033[92m' #green
        Y = '\033[93m' #yellow
        B = '\033[94m' #blue
        R = '\033[91m' #red
        W = '\033[0m'  #white

        return G,Y,B,R,W
