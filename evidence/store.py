
class EvidenceStore:
    def __init__(self):
        self.items = []

    def add(self, **kwargs):
        self.items.append(kwargs)
