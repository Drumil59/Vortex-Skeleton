
class BasePlugin:
    name = "base"

    def should_run(self, endpoint):
        return True

    def run(self, http, endpoint, analyzer, evidence):
        raise NotImplementedError
