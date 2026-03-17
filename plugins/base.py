
class BasePlugin:
    name = "base"

    def should_run(self, endpoint):
        return True

    def detect(self, http, endpoint, payload_intel):


        findings = []
        raise NotImplementedError
        return findings