from core.finding_deduplicator import FindingDeduplicator

class EvidenceStore:
    def __init__(self):
        self.items = [] # Raw findings for backward compatibility if needed
        self.deduplicator = FindingDeduplicator()

    def add(self, **kwargs):
        # 1. Store raw
        self.items.append(kwargs)
        
        # 2. Process for deduplication
        self.deduplicator.add_finding(**kwargs)

    def get_findings(self):
        """Returns the deduplicated set of findings."""
        return self.deduplicator.get_deduplicated_findings()
