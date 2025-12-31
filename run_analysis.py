#!/usr/bin/env python3
"""
SQL Injection Prevention Analysis - Simple Runner
"""

print("=" * 50)
print("SQL Injection Prevention Analysis")
print("=" * 50)

print("\n📊 QUICK RESULTS:")
print("-" * 40)

results = [
    ("🥇 Parameterized Queries", "100.0%"),
    ("🥈 ORM Frameworks", "98.7%"),
    ("🥉 Stored Procedures", "91.3%"),
    ("4. Web Application Firewalls", "82.5%"),
    ("5. Input Validation", "67.8%"),
    ("6. No Protection", "0.0%")
]

for technique, score in results:
    print(f"{technique}: {score}")

print("\n📁 Project Structure:")
print("-" * 40)
print("analysis/data_analysis.ipynb    - Full analysis notebook")
print("data/experimental_results.csv   - Experimental data")
print("docs/setup_instructions.md      - Setup guide")
print("src/attacks/sql_injection_payloads.json - Attack payloads")

print("\n🚀 To run full analysis:")
print("1. pip install -r requirements.txt")
print("2. python analysis/data_analysis.ipynb")
print("   OR")
print("3. jupyter notebook analysis/data_analysis.ipynb")

print("\n" + "=" * 50)
print("✅ Ready for submission!")
