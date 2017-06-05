class Logger:
    def __init__(self, is_windows, is_verbose):
        self.is_verbose = is_verbose
        self.is_windows = is_windows

        # Console Colors
        if self.is_windows:
            # Windows deserve coloring too :D
            self.G = '\033[92m'  # green
            self.Y = '\033[93m'  # yellow
            self.B = '\033[94m'  # blue
            self.R = '\033[91m'  # red
            self.W = '\033[0m'  # white
            try:
                import win_unicode_console, colorama
                win_unicode_console.enable()
                colorama.init()
                # Now the unicode will work ^_^
            except:
                print("[!] Error: Coloring libraries not installed ,no coloring will be used [Check the readme]")
                G = Y = B = R = W = G = Y = B = R = W = ''


        else:
            self.G = '\033[92m'  # green
            self.Y = '\033[93m'  # yellow
            self.B = '\033[94m'  # blue
            self.R = '\033[91m'  # red
            self.W = '\033[0m'  # white

    def banner(self):
        print("""%s
                     ____        _     _ _     _   _____
                    / ___| _   _| |__ | (_)___| |_|___ / _ __
                    \___ \| | | | '_ \| | / __| __| |_ \| '__|
                     ___) | |_| | |_) | | \__ \ |_ ___) | |
                    |____/ \__,_|_.__/|_|_|___/\__|____/|_|%s%s

                    # Coded By Ahmed Aboul-Ela - @aboul3la
        """ % (self.R, self.W, self.Y))