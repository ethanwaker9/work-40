class Meter:
    def __init__(self):
        self.enabled = False
        self.calls = {}
        self.nbytes = {}

    def add(self, name, calls, nbytes):
        if self.enabled:
            self.calls[name] = self.calls.get(name, 0) + calls
            self.nbytes[name] = self.nbytes.get(name, 0) + nbytes

    def reset(self):
        self.calls = {}
        self.nbytes = {}

    def snapshot(self):
        return dict(self.calls), dict(self.nbytes)


METER = Meter()
