"""
llm_planner.py — LLM-Based Red Team Attack Planner
=====================================================
Implemented and executed inside the controlled Kali Linux lab VM.
Uses a locally hosted LLM via Ollama to generate structured attack
scenario recommendations based on the lab environment context.

Requirements:
    - Ollama running locally at http://localhost:11434
    - Model: mistral
    - pip install requests
"""

import requests, json

def generate_attack_plan(phase, objective):
    env = {
        "domain": "scientificpharmacy.local",
        "dc_ip": "192.168.79.131",
        "clients": ["192.168.79.132 FINANCE-PC01", "192.168.79.133 IT-PC01"],
        "users": ["alice.finance", "bob.finance", "charlie.it", "dave.it (Domain Admin)"],
        "asset_criticality": {"DC01": "Critical", "FINANCE-PC01": "High", "IT-PC01": "Medium"}
    }
    prompt = f"""You are a controlled red team planner for a cybersecurity lab.
Environment: {json.dumps(env)}
Attack phase: {phase}
Objective: {objective}
Constraints: controlled lab only, non-destructive

Reply ONLY with this JSON and nothing else:
{{
  "scenario": "attack scenario name",
  "target": "target IP or hostname",
  "next_step": "specific action to take",
  "expected_indicators": ["event 1", "event 2"],
  "mitre_technique": "TXXXX - name",
  "reason": "why this scenario"
}}"""

    r = requests.post("http://localhost:11434/api/generate",
        json={"model": "mistral", "prompt": prompt, "stream": False})
    raw = r.json()["response"]
    plan = json.loads(raw[raw.find("{"):raw.rfind("}")+1])
    return plan

if __name__ == "__main__":
    print("=== LLM Attack Planner ===")
    phase = input("Attack phase (initial access / lateral movement / privilege escalation): ")
    obj   = input("Testing objective: ")
    print("\nGenerating plan...\n")
    plan = generate_attack_plan(phase, obj)
    print(json.dumps(plan, indent=2))
    with open("attack_plan_output.json", "w") as f:
        json.dump(plan, f, indent=2)
    print("\nSaved to attack_plan_output.json")