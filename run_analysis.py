#!/usr/bin/env python3
"""
Simple script to run SQL Injection Prevention Analysis
"""

import pandas as pd
import matplotlib.pyplot as plt
import json
import os

def main():
    print("🔍 Starting SQL Injection Prevention Analysis...")
    print("=" * 60)
    
    # Check files
    if not os.path.exists('data/experimental_results.csv'):
        print("❌ Error: data/experimental_results.csv not found")
        return
    
    # Load data
    df = pd.read_csv('data/experimental_results.csv')
    print(f"✅ Data loaded: {len(df)} techniques")
    
    # Calculate security scores
    security_cols = ['AuthBypass', 'DataExtraction', 'DBManipulation', 'SystemCompromise']
    df['SecurityScore'] = df[security_cols].mean(axis=1)
    
    # Display results
    print("\n📊 SECURITY RANKING:")
    print("=" * 40)
    df_sorted = df.sort_values('SecurityScore', ascending=False)
    
    for idx, row in df_sorted.iterrows():
        rank = idx + 1
        medal = "🥇" if rank == 1 else "🥈" if rank == 2 else "🥉" if rank == 3 else f"{rank}."
        print(f"{medal} {row['Technique']}: {row['SecurityScore']:.1f}%")
    
    # Save results
    results = {
        'top_technique': df_sorted.iloc[0]['Technique'],
        'security_scores': df_sorted[['Technique', 'SecurityScore']].to_dict('records')
    }
    
    with open('data/analysis_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print("\n✅ Analysis complete!")
    print("Results saved to data/analysis_results.json")
    print("=" * 60)
    print("\n📊 For full analysis with visualizations:")
    print("Run: jupyter notebook analysis/data_analysis.ipynb")

if __name__ == "__main__":
    main()
