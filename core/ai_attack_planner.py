from typing import List, Dict
from .attack_surface_db import Endpoint

class AIAttackPlanner:
    """
    Simulates AI-driven attack planning by analyzing the attack surface 
    and generating targeted testing strategies.
    Improved version: recommends specific vulnerability classes.
    """
    
    def generate_plan(self, endpoints: List[Endpoint]) -> Dict[str, List[str]]:
        plan = {
            "critical_targets": [],
            "api_test_strategy": [],
            "auth_test_strategy": [],
            "injection_targets": [],
            "ai_recommendations": []
        }
        
        for ep in endpoints:
            # 1. Identify Critical Targets (High Priority)
            if ep.priority > 20:
                plan["critical_targets"].append(f"Targeting high-risk endpoint: {ep.url} ({ep.method})")
            
            # 2. API Strategy
            if "api" in ep.tags or "graphql" in ep.tags or "api" in ep.url.lower():
                plan["api_test_strategy"].append(f"Perform deep schema analysis and parameter fuzzing on {ep.url}")
                plan["ai_recommendations"].append(f"{ep.url} -> test for IDOR, test for BOLA, test for SQL injection")
            
            # 3. Auth Strategy
            if any(k in ep.url.lower() for k in ["login", "auth", "session", "admin"]):
                plan["auth_test_strategy"].append(f"Analyze session management and check for bypass on {ep.url}")
                plan["ai_recommendations"].append(f"{ep.url} -> test for authorization bypass, test for weak session tokens")
                
            # 4. Injection Strategy
            if ep.params:
                plan["injection_targets"].append(f"Fuzz parameters {', '.join(p['name'] for p in ep.params)} on {ep.url} for injection vectors.")
                if any(p['name'].lower() in ['id', 'user_id', 'account'] for p in ep.params):
                    plan["ai_recommendations"].append(f"{ep.url} -> test for IDOR, test for SQL injection")

        # Deduplicate recommendations
        plan["ai_recommendations"] = list(set(plan["ai_recommendations"]))
        return plan

    def print_plan(self, plan: Dict[str, List[str]]):
        print("\n\033[95m[AI ATTACK PLAN]\033[0m")
        for category, items in plan.items():
            if items:
                print(f"\n> {category.upper().replace('_', ' ')}:")
                for item in items[:5]: # Limit output
                    print(f"  - {item}")
        print("-" * 30)
