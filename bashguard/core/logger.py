class Logger:
    """
    Singleton Logger
    """
    
    _debug: bool = False
    _verbose: bool = False

    @classmethod
    def init(cls, verbose: bool | int, debug: bool | int):
        cls._verbose = bool(verbose)
        cls._debug = bool(debug)

    @classmethod
    def d(cls, msg: str):
        if cls._debug:
            print(msg)

    @classmethod
    def v(cls, msg: str):
        if cls._verbose:
            print(msg)
