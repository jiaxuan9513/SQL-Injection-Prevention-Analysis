"""
Input Validation Techniques for SQL Injection Prevention
Complete implementation with performance testing
"""

import re
import time
import json
from datetime import datetime

class InputValidationTester:
    """Comprehensive input validation testing framework"""
    
    def __init__(self):
        self.results = []
        self.test_count = 0
    
    def whitelist_validation(self, input_str, pattern=None):
        """Allow only specific characters (safest approach)"""
        if pattern is None:
            # Default: alphanumeric, underscore, dot, hyphen, space
            pattern = r'^[a-zA-Z0-9_@.\-\s]+$'
        
        start_time = time.perf_counter()
        is_valid = bool(re.match(pattern, input_str))
        exec_time = (time.perf_counter() - start_time) * 1000
        
        self.test_count += 1
        
        return {
            'test_id': self.test_count,
            'method': 'whitelist_validation',
            'input': input_str,
            'is_valid': is_valid,
            'execution_time_ms': round(exec_time, 4),
            'pattern_used': pattern,
            'vulnerability': 'none' if is_valid else 'potential'
        }
    
    def blacklist_validation(self, input_str):
        """Remove dangerous patterns (less secure)"""
        dangerous_patterns = [
            (r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE)\b)", '[SQL]'),
            (r"(\b(CREATE|ALTER|UNION|JOIN|WHERE)\b)", '[SQL]'),
            (r"(['\"\\])", ''),
            (r"(--|#|;|\/\*|\*\/)", '[COMMENT]'),
            (r"(OR\s+'1'='1'|OR\s+'x'='x')", '[TAUTOLOGY]')
        ]
        
        start_time = time.perf_counter()
        cleaned = input_str
        patterns_found = []
        
        for pattern, replacement in dangerous_patterns:
            original = cleaned
            cleaned = re.sub(pattern, replacement, cleaned, flags=re.IGNORECASE)
            if cleaned != original:
                patterns_found.append(pattern)
        
        exec_time = (time.perf_counter() - start_time) * 1000
        self.test_count += 1
        
        return {
            'test_id': self.test_count,
            'method': 'blacklist_validation',
            'input': input_str,
            'is_valid': len(patterns_found) == 0,
            'execution_time_ms': round(exec_time, 4),
            'cleaned_output': cleaned,
            'patterns_detected': patterns_found,
            'vulnerability': 'blocked' if patterns_found else 'none'
        }
    
    def type_validation(self, input_str, expected_type):
        """Validate based on expected data type"""
        start_time = time.perf_counter()
        
        if expected_type == 'integer':
            try:
                value = int(input_str)
                is_valid = True
                converted = value
            except ValueError:
                is_valid = False
                converted = None
        elif expected_type == 'float':
            try:
                value = float(input_str)
                is_valid = True
                converted = value
            except ValueError:
                is_valid = False
                converted = None
        elif expected_type == 'email':
            pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            is_valid = bool(re.match(pattern, input_str))
            converted = input_str if is_valid else None
        else:  # string with length check
            is_valid = 1 <= len(input_str) <= 255
            converted = input_str if is_valid else None
        
        exec_time = (time.perf_counter() - start_time) * 1000
        self.test_count += 1
        
        return {
            'test_id': self.test_count,
            'method': f'type_validation_{expected_type}',
            'input': input_str,
            'is_valid': is_valid,
            'execution_time_ms': round(exec_time, 4),
            'expected_type': expected_type,
            'converted_value': converted,
            'vulnerability': 'none' if is_valid else 'type_mismatch'
        }
    
    def length_validation(self, input_str, min_len=1, max_len=255):
        """Validate input length constraints"""
        start_time = time.perf_counter()
        length = len(input_str)
        is_valid = min_len <= length <= max_len
        exec_time = (time.perf_counter() - start_time) * 1000
        
        self.test_count += 1
        
        return {
            'test_id': self.test_count,
            'method': 'length_validation',
            'input': input_str,
            'is_valid': is_valid,
            'execution_time_ms': round(exec_time, 4),
            'actual_length': length,
            'min_allowed': min_len,
            'max_allowed': max_len,
            'vulnerability': 'buffer_overflow' if length > max_len else 'none'
        }
    
    def sql_keyword_detection(self, input_str, threshold=1):
        """Detect SQL keywords with configurable sensitivity"""
        sql_keywords = [
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'TRUNCATE',
            'CREATE', 'ALTER', 'UNION', 'JOIN', 'WHERE', 'FROM', 'TABLE',
            'DATABASE', 'GRANT', 'REVOKE', 'EXEC', 'EXECUTE',
            'OR', 'AND', 'NOT', 'LIKE', 'IN', 'BETWEEN', 'NULL',
            '--', '#', ';', '/*', '*/'
        ]
        
        start_time = time.perf_counter()
        input_upper = input_str.upper()
        detected_keywords = []
        
        for keyword in sql_keywords:
            # Use word boundaries to avoid false positives
            if re.search(r'\b' + re.escape(keyword) + r'\b', input_upper):
                detected_keywords.append(keyword)
        
        exec_time = (time.perf_counter() - start_time) * 1000
        self.test_count += 1
        
        is_suspicious = len(detected_keywords) >= threshold
        
        return {
            'test_id': self.test_count,
            'method': 'sql_keyword_detection',
            'input': input_str,
            'is_valid': not is_suspicious,
            'execution_time_ms': round(exec_time, 4),
            'detected_keywords': detected_keywords,
            'keyword_count': len(detected_keywords),
            'suspicion_threshold': threshold,
            'is_suspicious': is_suspicious,
            'vulnerability': 'sql_injection' if is_suspicious else 'none'
        }
    
    def run_comprehensive_suite(self, test_inputs):
        """Run all validation methods on provided inputs"""
        print("=" * 70)
        print("COMPREHENSIVE INPUT VALIDATION TEST SUITE")
        print("=" * 70)
        print(f"Test started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Number of test inputs: {len(test_inputs)}")
        
        all_results = []
        method_performance = {}
        
        for idx, input_str in enumerate(test_inputs, 1):
            print(f"\n[{idx}/{len(test_inputs)}] Testing: '{input_str[:50]}{'...' if len(input_str) > 50 else ''}'")
            
            # Run all validation methods
            methods = [
                self.whitelist_validation(input_str),
                self.blacklist_validation(input_str),
                self.type_validation(input_str, 'string'),
                self.length_validation(input_str),
                self.sql_keyword_detection(input_str)
            ]
            
            all_results.extend(methods)
            
            # Track method performance
            for method_result in methods:
                method_name = method_result['method']
                if method_name not in method_performance:
                    method_performance[method_name] = {
                        'total_time': 0,
                        'count': 0,
                        'valid_count': 0
                    }
                method_performance[method_name]['total_time'] += method_result['execution_time_ms']
                method_performance[method_name]['count'] += 1
                if method_result['is_valid']:
                    method_performance[method_name]['valid_count'] += 1
        
        # Generate comprehensive statistics
        total_tests = len(all_results)
        valid_tests = sum(1 for r in all_results if r['is_valid'])
        vulnerability_count = sum(1 for r in all_results if r.get('vulnerability') not in ['none', 'type_mismatch'])
        
        print("\n" + "=" * 70)
        print("PERFORMANCE ANALYSIS BY VALIDATION METHOD")
        print("=" * 70)
        
        for method, stats in method_performance.items():
            avg_time = stats['total_time'] / stats['count']
            valid_rate = (stats['valid_count'] / stats['count']) * 100
            print(f"{method:<25} | Avg: {avg_time:>7.4f} ms | Valid: {valid_rate:>6.1f}% | Tests: {stats['count']}")
        
        print("\n" + "=" * 70)
        print("OVERALL TEST SUMMARY")
        print("=" * 70)
        print(f"Total validation tests: {total_tests}")
        print(f"Valid results: {valid_tests} ({valid_tests/total_tests*100:.1f}%)")
        print(f"Potential vulnerabilities detected: {vulnerability_count}")
        print(f"Test completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        summary = {
            'test_summary': {
                'total_tests': total_tests,
                'valid_results': valid_tests,
                'valid_percentage': round(valid_tests/total_tests*100, 2),
                'vulnerabilities_detected': vulnerability_count,
                'test_duration_seconds': round(time.perf_counter() - start_time, 2),
                'technique': 'Input Validation'
            },
            'method_performance': {
                method: {
                    'average_time_ms': round(stats['total_time']/stats['count'], 4),
                    'valid_percentage': round(stats['valid_count']/stats['count']*100, 2),
                    'test_count': stats['count']
                }
                for method, stats in method_performance.items()
            },
            'detailed_results': all_results
        }
        
        return summary
    
    def save_test_results(self, filename='input_validation_results.json'):
        """Save complete test results to JSON file"""
        # Representative test inputs covering various attack vectors
        test_inputs = [
            # Legitimate inputs
            "admin",
            "john_doe123",
            "test@example.com",
            "normal_password",
            "12345",
            "user-input",
            
            # SQL injection attempts
            "admin' OR '1'='1",
            "' OR '1'='1' --",
            "'; DROP TABLE users; --",
            "admin' --",
            "' UNION SELECT username, password FROM users --",
            "' OR 'a'='a",
            
            # Other malicious patterns
            "<script>alert('xss')</script>",
            "../../etc/passwd",
            "very'long'input'with'many'quotes",
            "SELECT * FROM users WHERE id = 1",
            "normal_input_with_SELECT_keyword",  # False positive test
        ]
        
        print("Initializing comprehensive input validation test suite...")
        results = self.run_comprehensive_suite(test_inputs)
        
        # Save to file
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n✓ Test results saved to: {filename}")
        print(f"✓ Total test cases processed: {len(test_inputs)}")
        print(f"✓ Individual validations performed: {results['test_summary']['total_tests']}")
        
        return results

def demonstrate_validation_effectiveness():
    """Quick demonstration function"""
    tester = InputValidationTester()
    
    print("DEMONSTRATION: Input Validation vs SQL Injection")
    print("-" * 50)
    
    test_cases = [
        ("admin", "Legitimate username"),
        ("admin' OR '1'='1", "SQL Injection attempt"),
        ("'; DROP TABLE users; --", "Destructive SQL"),
        ("normal_user", "Another legitimate input")
    ]
    
    for input_str, description in test_cases:
        print(f"\nInput: {input_str}")
        print(f"Description: {description}")
        
        # Test with whitelist
        whitelist_result = tester.whitelist_validation(input_str)
        print(f"  Whitelist: {'VALID' if whitelist_result['is_valid'] else 'INVALID'}")
        
        # Test with blacklist
        blacklist_result = tester.blacklist_validation(input_str)
        print(f"  Blacklist: {'VALID' if blacklist_result['is_valid'] else 'INVALID'}")
        
        # Test SQL detection
        sql_result = tester.sql_keyword_detection(input_str)
        print(f"  SQL Detection: {'SAFE' if sql_result['is_valid'] else 'SUSPICIOUS'}")
    
    return tester

def main():
    """Main execution function"""
    print("=" * 70)
    print("INPUT VALIDATION TESTING FRAMEWORK")
    print("=" * 70)
    
    # Run demonstration
    demonstrate_validation_effectiveness()
    
    # Run comprehensive tests
    tester = InputValidationTester()
    results = tester.save_test_results()
    
    print("\n" + "=" * 70)
    print("KEY FINDINGS:")
    print("=" * 70)
    print("1. Whitelist validation is most secure but may reject valid inputs")
    print("2. Blacklist validation is faster but can be bypassed")
    print("3. SQL keyword detection helps identify injection attempts")
    print("4. Combined approaches provide best security coverage")
    
    return results

if __name__ == "__main__":
    results = main()
    print("\n✓ Input validation testing completed successfully!")
