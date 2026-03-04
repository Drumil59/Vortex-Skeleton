import re

class ResponseAnalyzer:
    
    SQL_ERRORS = {
        "MySQL": [r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."],
        "PostgreSQL": [r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."],
        "MSSQL": [r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver"],
        "Oracle": [r"\bORA-[0-9]{4}", r"Oracle error", r"Oracle.*Driver"],
        "SQLite": [r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException"],
    }

    def check_heuristics(self, response) -> dict:
        findings = []
        if not response: return {}

        text = response.text

        # 1. SQL Errors
        for db, regexes in self.SQL_ERRORS.items():
            for pattern in regexes:
                if re.search(pattern, text, re.IGNORECASE):
                    findings.append(f"SQL Error ({db})")
                    break
        
        return {"errors": findings}

    def diff(self, baseline, injected):
        if not baseline or not injected:
            return {"status_changed": False, "length_changed": False, "heuristics": []}

        # Check for error signatures in the injected response (that weren't in baseline)
        baseline_heuristics = self.check_heuristics(baseline)["errors"]
        injected_heuristics = self.check_heuristics(injected)["errors"]
        
        new_errors = [e for e in injected_heuristics if e not in baseline_heuristics]

        result = {
            "status_changed": baseline.status_code != injected.status_code,
            "length_changed": abs(len(baseline.text) - len(injected.text)) > 50, # Increased tolerance
            "heuristics": new_errors
        }
        return result