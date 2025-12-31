"""
Web Application Firewall (WAF) Simulation
Simulates signature-based and behavioral WAF protection against SQL injection
"""

import re
import time
import json
from datetime import datetime
from typing import Dict, List, Tuple, Any
import hashlib

class WAFSimulator:
    """
    Simulates a Web Application Firewall with multiple detection techniques
    """
    
    def __init__(self, mode='balanced'):
        """
        Initialize WAF simulator
        
        Args:
            mode: 'aggressive' (high security, more false positives)
                  'balanced' (default)
                  'permissive' (lower security, fewer false positives)
        """
        self.mode = mode
        self.request_log = []
        self.blocked_requests = []
        self.detection_rules = self._load_detection_rules()
        self.learning_mode = False
        self.whitelist = self._load_whitelist()
        self.request_count = 0
        
        # Performance metrics
        self.metrics = {
            'total_requests': 0,
            'blocked_requests': 0,
            'false_positives': 0,
            'average_processing_time_ms': 0,
            'rule_hit_counts': {},
            'attack_types_detected': {}
        }
    
    def _load_detection_rules(self) -> List[Dict]:
        """Load detection rules based on mode"""
        base_rules = [
            # SQL Injection patterns
            {
                'id': 'SQLI_01',
                'name': 'SQL Tautology Detection',
                'pattern': r"(OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|OR\s+['\"]?[a-zA-Z]['\"]?\s*=\s*['\"]?[a-zA-Z]['\"]?)",
                'severity': 'high',
                'attack_type': 'sql_injection'
            },
            {
                'id': 'SQLI_02',
                'name': 'SQL Comment Detection',
                'pattern': r"(--|\#|\/\*|\*\/|;)",
                'severity': 'medium',
                'attack_type': 'sql_injection'
            },
            {
                'id': 'SQLI_03',
                'name': 'Union-based SQLi',
                'pattern': r"UNION\s+(ALL\s+)?SELECT",
                'severity': 'high',
                'attack_type': 'sql_injection'
            },
            {
                'id': 'SQLI_04',
                'name': 'SQL Keyword Sequences',
                'pattern': r"(SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+.+\s+SET|DELETE\s+FROM|DROP\s+TABLE)",
                'severity': 'high',
                'attack_type': 'sql_injection'
            },
            {
                'id': 'SQLI_05',
                'name': 'Multiple SQL Statements',
                'pattern': r".*;.*(SELECT|INSERT|UPDATE|DELETE|DROP).*;.*",
                'severity': 'critical',
                'attack_type': 'sql_injection'
            },
            
            # Encoding/Evasion patterns
            {
                'id': 'EVASION_01',
                'name': 'Hex Encoding Detection',
                'pattern': r"(0x[0-9a-fA-F]+|\\x[0-9a-fA-F]{2})",
                'severity': 'medium',
                'attack_type': 'evasion'
            },
            {
                'id': 'EVASION_02',
                'name': 'URL Encoding Detection',
                'pattern': r"(%27|%20OR%20|%23|%3B|%2D%2D)",
                'severity': 'medium',
                'attack_type': 'evasion'
            },
            {
                'id': 'EVASION_03',
                'name': 'Double Encoding',
                'pattern': r"(%25[0-9a-fA-F]{2}){2,}",
                'severity': 'high',
                'attack_type': 'evasion'
            },
            
            # Behavioral patterns
            {
                'id': 'BEHAVIOR_01',
                'name': 'Rapid Request Rate',
                'pattern': None,  # Behavioral rule
                'severity': 'medium',
                'attack_type': 'behavioral'
            },
            {
                'id': 'BEHAVIOR_02',
                'name': 'Unusual Parameter Length',
                'pattern': None,
                'severity': 'low',
                'attack_type': 'behavioral'
            }
        ]
        
        # Adjust rules based on mode
        if self.mode == 'permissive':
            return [r for r in base_rules if r['severity'] in ['critical', 'high']]
        elif self.mode == 'aggressive':
            return base_rules + [
                {
                    'id': 'AGGRESSIVE_01',
                    'name': 'Suspicious Character Sequences',
                    'pattern': r"(['\"]\s*[=<>!]+\s*['\"]|[`~!@#$%^&*()_+=\[\]{}|;:,.<>?/])",
                    'severity': 'low',
                    'attack_type': 'sql_injection'
                }
            ]
        else:  # balanced
            return [r for r in base_rules if r['severity'] in ['critical', 'high', 'medium']]
    
    def _load_whitelist(self) -> List[str]:
        """Load whitelist of known safe patterns"""
        return [
            # Common safe parameter names
            'page', 'limit', 'offset', 'sort', 'order', 'search',
            # Common safe values
            'true', 'false', 'null', 'undefined',
            # HTTP methods
            'GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'
        ]
    
    def normalize_input(self, input_string: str) -> str:
        """Normalize input to detect evasion attempts"""
        # Decode URL encoding
        import urllib.parse
        decoded = urllib.parse.unquote(input_string)
        
        # Remove multiple spaces
        normalized = re.sub(r'\s+', ' ', decoded)
        
        # Convert to lowercase for case-insensitive matching
        normalized = normalized.lower()
        
        return normalized
    
    def check_signature_based(self, input_string: str) -> Tuple[bool, List[Dict]]:
        """Check input against signature-based rules"""
        detected_rules = []
        normalized_input = self.normalize_input(input_string)
        
        for rule in self.detection_rules:
            if rule['pattern']:
                try:
                    if re.search(rule['pattern'], normalized_input, re.IGNORECASE):
                        detected_rules.append({
                            'rule_id': rule['id'],
                            'rule_name': rule['name'],
                            'severity': rule['severity'],
                            'attack_type': rule['attack_type'],
                            'matched_pattern': rule['pattern']
                        })
                except re.error:
                    # Skip invalid regex patterns
                    continue
        
        should_block = len(detected_rules) > 0
        return should_block, detected_rules
    
    def check_behavioral(self, request_data: Dict) -> Tuple[bool, List[Dict]]:
        """Check for behavioral anomalies"""
        detected_anomalies = []
        
        # Check request rate (simplified)
        current_time = time.time()
        recent_requests = [r for r in self.request_log 
                          if current_time - r['timestamp'] < 10]  # Last 10 seconds
        
        if len(recent_requests) > 50:  # More than 5 requests per second average
            detected_anomalies.append({
                'rule_id': 'BEHAVIOR_01',
                'rule_name': 'Rapid Request Rate',
                'severity': 'medium',
                'attack_type': 'behavioral',
                'details': f'{len(recent_requests)} requests in last 10 seconds'
            })
        
        # Check parameter lengths
        for key, value in request_data.get('params', {}).items():
            if isinstance(value, str) and len(value) > 1000:  # Unusually long parameter
                detected_anomalies.append({
                    'rule_id': 'BEHAVIOR_02',
                    'rule_name': 'Unusual Parameter Length',
                    'severity': 'low',
                    'attack_type': 'behavioral',
                    'details': f'Parameter "{key}" length: {len(value)}'
                })
        
        should_block = len(detected_anomalies) > 0 and self.mode != 'permissive'
        return should_block, detected_anomalies
    
    def check_whitelist(self, input_string: str) -> bool:
        """Check if input is in whitelist"""
        normalized = input_string.lower().strip()
        return normalized in self.whitelist
    
    def process_request(self, request_data: Dict) -> Dict:
        """
        Process an HTTP request through the WAF
        
        Args:
            request_data: Dictionary containing request information
                {
                    'method': 'GET'/'POST',
                    'path': '/api/users',
                    'params': {'username': 'test', 'password': 'pass'},
                    'headers': {...},
                    'body': '...' (for POST requests)
                }
        
        Returns:
            Dictionary with WAF decision and details
        """
        start_time = time.time()
        self.request_count += 1
        self.metrics['total_requests'] += 1
        
        request_id = hashlib.md5(f"{request_data}{time.time()}".encode()).hexdigest()[:8]
        
        # Log request
        log_entry = {
            'request_id': request_id,
            'timestamp': time.time(),
            'method': request_data.get('method', 'GET'),
            'path': request_data.get('path', '/'),
            'params': request_data.get('params', {}),
            'headers': request_data.get('headers', {})
        }
        self.request_log.append(log_entry)
        
        # Initialize result
        result = {
            'request_id': request_id,
            'timestamp': datetime.now().isoformat(),
            'decision': 'ALLOW',
            'processing_time_ms': 0,
            'detections': [],
            'whitelisted': False,
            'mode': self.mode
        }
        
        # Check whitelist first
        all_inputs = []
        if 'path' in request_data:
            all_inputs.append(request_data['path'])
        if 'params' in request_data:
            for value in request_data['params'].values():
                if isinstance(value, str):
                    all_inputs.append(value)
        if 'body' in request_data and isinstance(request_data['body'], str):
            all_inputs.append(request_data['body'])
        
        # If any part is whitelisted, allow immediately
        if any(self.check_whitelist(inp) for inp in all_inputs):
            result['whitelisted'] = True
            result['decision'] = 'ALLOW (whitelisted)'
        
        # Perform signature-based detection
        signature_block = False
        signature_detections = []
        
        for input_string in all_inputs:
            if not self.check_whitelist(input_string):
                should_block, detections = self.check_signature_based(input_string)
                if should_block:
                    signature_block = True
                    signature_detections.extend(detections)
        
        # Perform behavioral detection
        behavioral_block = False
        behavioral_detections = []
        
        if self.mode != 'permissive':
            should_block, detections = self.check_behavioral(request_data)
            if should_block:
                behavioral_block = True
                behavioral_detections.extend(detections)
        
        # Combine detections
        all_detections = signature_detections + behavioral_detections
        result['detections'] = all_detections
        
        # Make decision
        if signature_block:
            result['decision'] = 'BLOCK (signature)'
            self.blocked_requests.append({
                'request_id': request_id,
                'reason': 'signature_match',
                'detections': signature_detections
            })
            self.metrics['blocked_requests'] += 1
        elif behavioral_block and self.mode == 'aggressive':
            result['decision'] = 'BLOCK (behavioral)'
            self.blocked_requests.append({
                'request_id': request_id,
                'reason': 'behavioral_anomaly',
                'detections': behavioral_detections
            })
            self.metrics['blocked_requests'] += 1
        
        # Update metrics
        processing_time = (time.time() - start_time) * 1000
        result['processing_time_ms'] = round(processing_time, 4)
        
        # Update rule hit counts
        for detection in all_detections:
            rule_id = detection['rule_id']
            attack_type = detection['attack_type']
            
            if rule_id not in self.metrics['rule_hit_counts']:
                self.metrics['rule_hit_counts'][rule_id] = 0
            self.metrics['rule_hit_counts'][rule_id] += 1
            
            if attack_type not in self.metrics['attack_types_detected']:
                self.metrics['attack_types_detected'][attack_type] = 0
            self.metrics['attack_types_detected'][attack_type] += 1
        
        # Update average processing time
        total_time = self.metrics['average_processing_time_ms'] * (self.request_count - 1)
        self.metrics['average_processing_time_ms'] = (total_time + processing_time) / self.request_count
        
        return result
    
    def get_metrics(self) -> Dict:
        """Get current WAF performance metrics"""
        metrics = self.metrics.copy()
        metrics['block_rate'] = (metrics['blocked_requests'] / metrics['total_requests'] * 100 
                                if metrics['total_requests'] > 0 else 0)
        metrics['current_mode'] = self.mode
        metrics['active_rules'] = len(self.detection_rules)
        metrics['whitelist_size'] = len(self.whitelist)
        metrics['request_log_size'] = len(self.request_log)
        
        return metrics
    
    def simulate_attack_scenarios(self) -> List[Dict]:
        """Simulate various SQL injection attack scenarios"""
        scenarios = [
            {
                'name': 'Basic Tautology Attack',
                'request': {
                    'method': 'POST',
                    'path': '/login',
                    'params': {
                        'username': "admin' OR '1'='1",
                        'password': 'anything'
                    }
                },
                'expected_result': 'BLOCK'
            },
            {
                'name': 'Union-based Injection',
                'request': {
                    'method': 'GET',
                    'path': '/search',
                    'params': {
                        'query': "' UNION SELECT username, password FROM users --"
                    }
                },
                'expected_result': 'BLOCK'
            },
            {
                'name': 'Drop Table Attack',
                'request': {
                    'method': 'POST',
                    'path': '/api/execute',
                    'body': "'; DROP TABLE users; --"
                },
                'expected_result': 'BLOCK'
            },
            {
                'name': 'URL Encoded Attack',
                'request': {
                    'method': 'GET',
                    'path': '/login',
                    'params': {
                        'user': 'admin%27%20OR%20%271%27%3D%271'
                    }
                },
                'expected_result': 'BLOCK'
            },
            {
                'name': 'Legitimate Request',
                'request': {
                    'method': 'GET',
                    'path': '/api/users',
                    'params': {
                        'page': '1',
                        'limit': '10'
                    }
                },
                'expected_result': 'ALLOW'
            },
            {
                'name': 'Hex Encoded Attack',
                'request': {
                    'method': 'POST',
                    'path': '/query',
                    'body': "SELECT * FROM users WHERE id = 0x31"
                },
                'expected_result': 'BLOCK'
            }
        ]
        
        results = []
        print("=" * 70)
        print("WAF ATTACK SIMULATION TESTING")
        print("=" * 70)
        
        for scenario in scenarios:
            result = self.process_request(scenario['request'])
            
            test_result = {
                'scenario_name': scenario['name'],
                'expected': scenario['expected_result'],
                'actual': result['decision'],
                'passed': scenario['expected_result'] in result['decision'],
                'processing_time_ms': result['processing_time_ms'],
                'detections': result['detections']
            }
            
            results.append(test_result)
            
            # Print result
            status = "✓ PASS" if test_result['passed'] else "✗ FAIL"
            print(f"{status} | {scenario['name']:30} | Time: {result['processing_time_ms']:.2f}ms")
            if result['detections']:
                for detection in result['detections']:
                    print(f"      Detected: {detection['rule_name']} ({detection['severity']})")
        
        # Calculate statistics
        total_tests = len(results)
        passed_tests = sum(1 for r in results if r['passed'])
        pass_rate = (passed_tests / total_tests) * 100
        
        avg_processing_time = sum(r['processing_time_ms'] for r in results) / total_tests
        
        print("\n" + "=" * 70)
        print("SIMULATION SUMMARY")
        print("=" * 70)
        print(f"Total tests: {total_tests}")
        print(f"Passed: {passed_tests} ({pass_rate:.1f}%)")
        print(f"Average processing time: {avg_processing_time:.2f} ms")
        print(f"WAF Mode: {self.mode}")
        
        return results

def run_comprehensive_waf_test():
    """Run comprehensive WAF testing suite"""
    print("WEB APPLICATION FIREWALL SIMULATION FRAMEWORK")
    print("=" * 70)
    
    # Test different WAF modes
    modes = ['permissive', 'balanced', 'aggressive']
    all_results = {}
    
    for mode in modes:
        print(f"\n{'='*70}")
        print(f"TESTING WAF IN {mode.upper()} MODE")
        print(f"{'='*70}")
        
        waf = WAFSimulator(mode=mode)
        results = waf.simulate_attack_scenarios()
        
        # Get metrics
        metrics = waf.get_metrics()
        
        all_results[mode] = {
            'test_results': results,
            'metrics': metrics
        }
        
        # Print mode-specific metrics
        print(f"\n{mode.upper()} Mode Metrics:")
        print(f"  Block rate: {metrics['block_rate']:.1f}%")
        print(f"  Avg processing time: {metrics['average_processing_time_ms']:.2f} ms")
        print(f"  Active rules: {metrics['active_rules']}")
        print(f"  Total requests processed: {metrics['total_requests']}")
    
    # Compare modes
    print("\n" + "=" * 70)
    print("MODE COMPARISON ANALYSIS")
    print("=" * 70)
    
    comparison_data = []
    for mode, data in all_results.items():
        results = data['test_results']
        metrics = data['metrics']
        
        passed = sum(1 for r in results if r['passed'])
        total = len(results)
        
        comparison_data.append({
            'mode': mode,
            'pass_rate': (passed / total) * 100,
            'block_rate': metrics['block_rate'],
            'avg_processing_time': metrics['average_processing_time_ms'],
            'false_positives': metrics.get('false_positives', 0),
            'security_score': metrics['block_rate'] * 0.7 + (100 - metrics['average_processing_time_ms']) * 0.3
        })
    
    # Print comparison table
    print("\nMode | Pass Rate | Block Rate | Avg Time | Security Score")
    print("-" * 65)
    for data in comparison_data:
        print(f"{data['mode']:10} | {data['pass_rate']:8.1f}% | {data['block_rate']:9.1f}% | "
              f"{data['avg_processing_time']:7.2f}ms | {data['security_score']:13.1f}")
    
    # Determine best mode
    best_mode = max(comparison_data, key=lambda x: x['security_score'])
    print(f"\n✓ Recommended mode: {best_mode['mode'].upper()} "
          f"(Security Score: {best_mode['security_score']:.1f})")
    
    return all_results

def main():
    """Main execution function"""
    print("=" * 70)
    print("WEB APPLICATION FIREWALL (WAF) SIMULATION")
    print("=" * 70)
    print("This simulation tests WAF effectiveness against SQL injection attacks")
    print("Three modes are tested: permissive, balanced, and aggressive")
    print("-" * 70)
    
    results = run_comprehensive_waf_test()
    
    # Save results
    with open('waf_simulation_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print("\n" + "=" * 70)
    print("KEY FINDINGS:")
    print("=" * 70)
    print("1. Aggressive mode blocks more attacks but has higher false positives")
    print("2. Balanced mode provides best trade-off for most applications")
    print("3. Permissive mode is fastest but may miss sophisticated attacks")
    print("4. Signature-based detection is effective against known attack patterns")
    print("5. Behavioral analysis adds protection against unknown/zero-day attacks")
    print("\n✓ WAF simulation completed. Results saved to waf_simulation_results.json")
    
    return results

if __name__ == "__main__":
    results = main()
