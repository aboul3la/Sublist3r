class ScanParams:

    def __init__(self, silent=False, verbose=False, brute_force=False, thread_count=20,
                 engines=None, ports="", savefile=""):
        self.Silent = silent
        self.Verbose = verbose
        self.Engines = engines
        self.BruteForce = brute_force
        self.ThreadCount = thread_count
        self. Engines = engines
        self.Ports = ports
        self.SaveFile = savefile
