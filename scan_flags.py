class ScanParams:
    Silent = Verbose = BruteForce = TakeoverCheck = False
    ThreadCount = 20
    Engines = None
    Ports = SaveFile = ""

    def __init__(self, silent=False, verbose=False, brute_force=False, takeover_check=False, thread_count=20,
                 engines=None, ports="", savefile=""):
        self.Silent = silent
        self.Verbose = verbose
        self.Engines = engines
        self.BruteForce = brute_force
        self.TakeoverCheck = takeover_check
        self.ThreadCount = thread_count
        self. Engines = engines
        self.Ports = ports
        self.SaveFile = savefile
