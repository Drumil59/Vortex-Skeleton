
class RiskEngine:
    MAP = {
        "SQL Injection": ("HIGH", "CWE-89"),
        "Reflected XSS": ("MEDIUM", "CWE-79"),
    }

    def rate(self, name):
        return self.MAP.get(name, ("INFO", "N/A"))
