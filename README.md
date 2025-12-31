# SQL-Injection-Prevention-Analysis
Experimental evaluation of SQL injection prevention techniques - parameterized queries, WAF, input validation, ORM frameworks, and stored procedures


## Project Overview
A comprehensive, data-driven analysis of SQL injection prevention techniques evaluating security effectiveness, performance impact, and implementation trade-offs.

## Live Demo & Results
[![Security Effectiveness](docs/security_effectiveness.png)](analysis/data_analysis.ipynb)
*Click image to view interactive analysis*

## Key Findings
| Technique | Security Score | Performance Overhead | Best Use Case |
|-----------|---------------|---------------------|---------------|
| 1. **Parameterized Queries** | 100% | 19.4% | New projects, high-security apps |
| 2. **ORM Frameworks** | 98.7% | 38.8% | Developer productivity |
| 3. **Stored Procedures** | 91.3% | 50.4% | Database-heavy operations |
| **WAF** | 82.5% | 50.8% | Legacy systems, quick deployment |
| **Input Validation** | 67.8% | 9.1% | Supplementary protection only |

## Quick Start

### Prerequisites
- Python 3.8+
- Jupyter Notebook

### Installation
```bash
# Clone repository
git clone https://github.com/jiaxuan9513/SQL-Injection-Prevention-Analysis.git
cd SQL-Injection-Prevention-Analysis

# Install dependencies
pip install -r requirements.txt

# Launch Jupyter Notebook
jupyter notebook analysis/data_analysis.ipynb
