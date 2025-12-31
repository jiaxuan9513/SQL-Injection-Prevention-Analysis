# SQL-Injection-Prevention-Analysis
Experimental evaluation of SQL injection prevention techniques - parameterized queries, WAF, input validation, ORM frameworks, and stored procedures

## Project Overview
This repository contains experimental code, datasets, and analysis scripts for the research paper **"Comparative Evaluation of SQL Injection Prevention Techniques in Database Management Systems"**.

The study evaluates five prevention techniques:
1. **Parameterized Queries** - Architectural prevention
2. **ORM Frameworks** - Abstraction layer protection  
3. **Stored Procedures** - Database-level encapsulation
4. **Web Application Firewalls (WAF)** - Filtering-based detection
5. **Input Validation** - Data sanitization approach

## Key Experimental Findings
| Technique | Security Effectiveness | Performance Overhead | Implementation Difficulty |
|-----------|-----------------------|---------------------|--------------------------|
| Parameterized Queries | 100% | +19.4% | High |
| ORM Framework | 98.7% | +39.5% | Medium |
| Stored Procedures | 95.6% | +34.7% | High |
| Web Application Firewall | 86.5% | +50.8% | Low |
| Input Validation | 67.8% | +22.6% | Medium |

## Repository Structure
