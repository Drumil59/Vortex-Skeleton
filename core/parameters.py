
import re

class ParameterClassifier:
    def classify(self, name):
        name = name.lower()

        if re.search(r"id|uid|user", name):
            return "identifier"
        if "file" in name:
            return "file"
        if "search" in name or name == "q":
            return "search"

        return "generic"
