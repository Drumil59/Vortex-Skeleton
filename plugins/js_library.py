from .base import BasePlugin
import re

class LibraryScannerPlugin(BasePlugin):
    """
    Scans response text for outdated or vulnerable JavaScript libraries.
    """
    name = "Outdated JS Library"

    SIGNATURES = [
        (r"jquery[/-]([0-9]+\.[0-9]+\.[0-9]+)", "jQuery", "3.5.0"),
        (r"bootstrap[/-]([0-9]+\.[0-9]+\.[0-9]+)", "Bootstrap", "4.5.0"),
        (r"angular[/-]([0-9]+\.[0-9]+\.[0-9]+)", "AngularJS", "1.8.0"),
        (r"react[/-]([0-9]+\.[0-9]+\.[0-9]+)", "React", "16.14.0"),
        (r"vue[/-]([0-9]+\.[0-9]+\.[0-9]+)", "Vue.js", "2.6.14")
    ]

    def should_run(self, endpoint):
        return True

    def run(self, http, endpoint, analyzer, evidence):
        try:
            resp = http.request("GET", endpoint.url)
            if not resp: return

            text = resp.text.lower()

            for regex, lib_name, min_safe_version in self.SIGNATURES:
                matches = re.findall(regex, text)
                for version in matches:
                    if self._is_outdated(version, min_safe_version):
                        evidence.add(
                            plugin=self.name,
                            endpoint=endpoint.url,
                            payload=None,
                            evidence=f"Outdated {lib_name} version: {version}",
                            confidence="LOW",
                            details=f"Found version {version}, generic safe version is > {min_safe_version}"
                        )

        except Exception:
            pass

    def _is_outdated(self, version, min_safe):
        try:
            v_parts = [int(x) for x in version.split('.')]
            safe_parts = [int(x) for x in min_safe.split('.')]
            
            return v_parts < safe_parts
        except:
            return False
