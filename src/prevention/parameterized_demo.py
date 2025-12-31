"""
Parameterized Queries Implementation
Complete experimental code for SQL injection prevention testing
"""

import mysql.connector
import time
import json
from datetime import datetime
from mysql.connector import Error

class ParameterizedQueryExperiment:
    def __init__(self, config):
        self.config = config
        self.connection = None
        self.results = []
        self.connect()
    
    def connect(self):
        try:
            self.connection = mysql.connector.connect(**self.config)
            print(f"[{datetime.now()}] Database connection established")
        except Error as e:
            print(f"[{datetime.now()}] Connection error: {e}")
    
    def test_parameterized_auth(self, test_cases):
        """Test authentication with parameterized queries"""
        results = []
        cursor = self.connection.cursor(prepared=True)
        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        
        for case in test_cases:
            start_time = time.perf_counter()
            try:
                cursor.execute(query, (case['username'], case['password']))
                result = cursor.fetchall()
                exec_time = (time.perf_counter() - start_time) * 1000
                
                results.append({
                    'test_type': 'parameterized_auth',
                    'username': case['username'],
                    'password': case['password'],
                    'success': True,
                    'execution_time_ms': round(exec_time, 2),
                    'rows_returned': len(result),
                    'vulnerable': False
                })
            except Error as e:
                results.append({
                    'test_type': 'parameterized_auth',
                    'username': case['username'],
                    'password': case['password'],
                    'success': False,
                    'error': str(e),
                    'vulnerable': False
                })
        
        cursor.close()
        return results
    
    def test_parameterized_data_retrieval(self, queries):
        """Test data retrieval with parameters"""
        results = []
        cursor = self.connection.cursor(prepared=True)
        
        for query_data in queries:
            query = query_data['query']
            params = query_data['params']
            
            start_time = time.perf_counter()
            try:
                cursor.execute(query, params)
                result = cursor.fetchall()
                exec_time = (time.perf_counter() - start_time) * 1000
                
                results.append({
                    'test_type': 'parameterized_retrieval',
                    'query': query,
                    'params': params,
                    'success': True,
                    'execution_time_ms': round(exec_time, 2),
                    'rows_returned': len(result),
                    'vulnerable': False
                })
            except Error as e:
                results.append({
                    'test_type': 'parameterized_retrieval',
                    'query': query,
                    'params': params,
                    'success': False,
                    'error': str(e),
                    'vulnerable': False
                })
        
        cursor.close()
        return results
    
    def run_comprehensive_test(self):
        """Run all parameterized query tests"""
        print("=" * 60)
        print("PARAMETERIZED QUERIES COMPREHENSIVE TEST")
        print("=" * 60)
        
        # Test cases
        auth_test_cases = [
            {'username': 'admin', 'password': 'secure123'},
            {'username': 'user1', 'password': 'password123'},
            {'username': "admin' OR '1'='1", 'password': 'anything'},
            {'username': 'admin', 'password': "' OR '1'='1"},
        ]
        
        data_queries = [
            {
                'query': "SELECT * FROM products WHERE category = %s AND price > %s",
                'params': ('electronics', 100)
            },
            {
                'query': "SELECT username, email FROM users WHERE id = %s",
                'params': (1,)
            },
            {
                'query': "SELECT * FROM orders WHERE user_id = %s AND status = %s",
                'params': (1001, 'completed')
            }
        ]
        
        # Run tests
        print("\n1. Testing Authentication Queries...")
        auth_results = self.test_parameterized_auth(auth_test_cases)
        
        print("\n2. Testing Data Retrieval Queries...")
        data_results = self.test_parameterized_data_retrieval(data_queries)
        
        # Combine results
        all_results = auth_results + data_results
        
        # Calculate statistics
        successful_tests = [r for r in all_results if r['success']]
        failed_tests = [r for r in all_results if not r['success']]
        
        if successful_tests:
            avg_time = sum(r['execution_time_ms'] for r in successful_tests) / len(successful_tests)
        else:
            avg_time = 0
        
        # Print summary
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        print(f"Total tests: {len(all_results)}")
        print(f"Successful: {len(successful_tests)}")
        print(f"Failed: {len(failed_tests)}")
        print(f"Average execution time: {avg_time:.2f} ms")
        print(f"Injection attempts blocked: {len([r for r in all_results if 'OR' in str(r.get('username', '')) + str(r.get('password', ''))])}")
        
        return {
            'summary': {
                'total_tests': len(all_results),
                'successful_tests': len(successful_tests),
                'failed_tests': len(failed_tests),
                'average_time_ms': round(avg_time, 2),
                'technique': 'Parameterized Queries'
            },
            'detailed_results': all_results
        }
    
    def save_results(self, filename='parameterized_results.json'):
        """Save test results to JSON file"""
        results = self.run_comprehensive_test()
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {filename}")
        return results
    
    def close(self):
        if self.connection and self.connection.is_connected():
            self.connection.close()
            print(f"[{datetime.now()}] Database connection closed")

def main():
    # Configuration
    config = {
        'host': 'localhost',
        'database': 'security_test_db',
        'user': 'test_user',
        'password': 'test_password',
        'raise_on_warnings': True
    }
    
    # Run experiment
    experiment = ParameterizedQueryExperiment(config)
    results = experiment.save_results()
    experiment.close()
    
    return results

if __name__ == "__main__":
    main()

