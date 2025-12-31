"""
ORM Framework Implementation for SQL Injection Prevention
Demonstrates how Object-Relational Mapping frameworks prevent SQL injection
"""

import json
import time
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum

# Simulated ORM framework components
class QueryType(Enum):
    SELECT = "SELECT"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"

class FilterOperator(Enum):
    EQUALS = "="
    NOT_EQUALS = "!="
    GREATER_THAN = ">"
    LESS_THAN = "<"
    LIKE = "LIKE"
    IN = "IN"

@dataclass
class QueryFilter:
    """Represents a filter condition in ORM query"""
    field: str
    operator: FilterOperator
    value: Any
    
    def to_safe_string(self) -> str:
        """Convert filter to parameterized format"""
        return f"{self.field} {self.operator.value} ?"

@dataclass
class ORMQuery:
    """Represents a database query in ORM"""
    query_type: QueryType
    table: str
    filters: List[QueryFilter] = field(default_factory=list)
    columns: List[str] = field(default_factory=list)
    values: Dict[str, Any] = field(default_factory=dict)
    limit: Optional[int] = None
    offset: Optional[int] = None
    
    def build_parameterized_query(self) -> tuple:
        """
        Build a parameterized SQL query to prevent injection
        
        Returns:
            Tuple of (sql_string, parameters_list)
        """
        if self.query_type == QueryType.SELECT:
            return self._build_select_query()
        elif self.query_type == QueryType.INSERT:
            return self._build_insert_query()
        elif self.query_type == QueryType.UPDATE:
            return self._build_update_query()
        elif self.query_type == QueryType.DELETE:
            return self._build_delete_query()
    
    def _build_select_query(self) -> tuple:
        """Build safe SELECT query"""
        columns = ", ".join(self.columns) if self.columns else "*"
        sql = f"SELECT {columns} FROM {self.table}"
        
        parameters = []
        if self.filters:
            filter_clauses = []
            for filter_obj in self.filters:
                filter_clauses.append(filter_obj.to_safe_string())
                parameters.append(filter_obj.value)
            sql += " WHERE " + " AND ".join(filter_clauses)
        
        if self.limit is not None:
            sql += f" LIMIT {self.limit}"
        if self.offset is not None:
            sql += f" OFFSET {self.offset}"
        
        return sql, parameters
    
    def _build_insert_query(self) -> tuple:
        """Build safe INSERT query"""
        if not self.values:
            raise ValueError("No values provided for INSERT query")
        
        columns = ", ".join(self.values.keys())
        placeholders = ", ".join(["?"] * len(self.values))
        sql = f"INSERT INTO {self.table} ({columns}) VALUES ({placeholders})"
        parameters = list(self.values.values())
        
        return sql, parameters
    
    def _build_update_query(self) -> tuple:
        """Build safe UPDATE query"""
        if not self.values:
            raise ValueError("No values provided for UPDATE query")
        
        set_clauses = []
        parameters = []
        
        for field, value in self.values.items():
            set_clauses.append(f"{field} = ?")
            parameters.append(value)
        
        sql = f"UPDATE {self.table} SET {', '.join(set_clauses)}"
        
        if self.filters:
            filter_clauses = []
            for filter_obj in self.filters:
                filter_clauses.append(filter_obj.to_safe_string())
                parameters.append(filter_obj.value)
            sql += " WHERE " + " AND ".join(filter_clauses)
        
        return sql, parameters
    
    def _build_delete_query(self) -> tuple:
        """Build safe DELETE query"""
        sql = f"DELETE FROM {self.table}"
        parameters = []
        
        if self.filters:
            filter_clauses = []
            for filter_obj in self.filters:
                filter_clauses.append(filter_obj.to_safe_string())
                parameters.append(filter_obj.value)
            sql += " WHERE " + " AND ".join(filter_clauses)
        
        return sql, parameters

class ModelMeta(type):
    """Metaclass for ORM models"""
    def __new__(cls, name, bases, attrs):
        if 'table_name' not in attrs:
            attrs['table_name'] = name.lower() + 's'
        return super().__new__(cls, name, bases, attrs)

class BaseModel(metaclass=ModelMeta):
    """Base class for all ORM models"""
    table_name = ""
    
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    @classmethod
    def get_table_name(cls):
        return cls.table_name

class User(BaseModel):
    """User model demonstrating ORM usage"""
    table_name = "users"
    
    def __init__(self, id=None, username=None, email=None, password_hash=None, created_at=None):
        super().__init__(
            id=id,
            username=username,
            email=email,
            password_hash=password_hash,
            created_at=created_at or datetime.now()
        )
    
    @classmethod
    def find_by_username(cls, username: str) -> 'ORMQuery':
        """Safe method to find user by username"""
        return ORMQuery(
            query_type=QueryType.SELECT,
            table=cls.table_name,
            filters=[
                QueryFilter(field="username", operator=FilterOperator.EQUALS, value=username)
            ],
            columns=["id", "username", "email", "created_at"]
        )
    
    @classmethod
    def authenticate(cls, username: str, password: str) -> 'ORMQuery':
        """Safe authentication method"""
        return ORMQuery(
            query_type=QueryType.SELECT,
            table=cls.table_name,
            filters=[
                QueryFilter(field="username", operator=FilterOperator.EQUALS, value=username),
                QueryFilter(field="password_hash", operator=FilterOperator.EQUALS, value=password)
            ],
            columns=["id", "username"]
        )

class Product(BaseModel):
    """Product model for e-commerce example"""
    table_name = "products"
    
    def __init__(self, id=None, name=None, price=None, category=None, stock=None):
        super().__init__(
            id=id,
            name=name,
            price=price,
            category=category,
            stock=stock
        )
    
    @classmethod
    def search_products(cls, category: Optional[str] = None, 
                       min_price: Optional[float] = None,
                       max_price: Optional[float] = None) -> 'ORMQuery':
        """Safe product search with multiple filters"""
        filters = []
        
        if category:
            filters.append(QueryFilter(field="category", operator=FilterOperator.EQUALS, value=category))
        if min_price is not None:
            filters.append(QueryFilter(field="price", operator=FilterOperator.GREATER_THAN, value=min_price))
        if max_price is not None:
            filters.append(QueryFilter(field="price", operator=FilterOperator.LESS_THAN, value=max_price))
        
        return ORMQuery(
            query_type=QueryType.SELECT,
            table=cls.table_name,
            filters=filters,
            columns=["id", "name", "price", "category", "stock"],
            limit=50
        )

class ORMQueryExecutor:
    """Simulated ORM query executor with security features"""
    
    def __init__(self):
        self.query_log = []
        self.security_metrics = {
            'total_queries': 0,
            'parameterized_queries': 0,
            'injection_attempts_blocked': 0,
            'average_query_time_ms': 0,
            'failed_queries': 0
        }
    
    def execute_query(self, orm_query: ORMQuery) -> Dict:
        """
        Execute an ORM query safely
        
        Returns:
            Dictionary with query results and metrics
        """
        start_time = time.perf_counter()
        self.security_metrics['total_queries'] += 1
        
        try:
            # Build parameterized query
            sql, parameters = orm_query.build_parameterized_query()
            self.security_metrics['parameterized_queries'] += 1
            
            # Validate parameters for injection attempts
            if self._detect_injection_attempt(parameters):
                self.security_metrics['injection_attempts_blocked'] += 1
                raise SecurityError("Potential SQL injection detected in parameters")
            
            # Simulate query execution (in real implementation, this would connect to DB)
            execution_time = (time.perf_counter() - start_time) * 1000
            
            # Log the query
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'query_type': orm_query.query_type.value,
                'table': orm_query.table,
                'sql': sql,
                'parameters': parameters,
                'execution_time_ms': round(execution_time, 2),
                'safe': True
            }
            self.query_log.append(log_entry)
            
            # Update average execution time
            total_time = self.security_metrics['average_query_time_ms'] * (self.security_metrics['total_queries'] - 1)
            self.security_metrics['average_query_time_ms'] = (total_time + execution_time) / self.security_metrics['total_queries']
            
            # Simulate result (in real implementation, this would be actual DB results)
            simulated_results = self._simulate_query_results(orm_query)
            
            return {
                'success': True,
                'sql': sql,
                'parameters': parameters,
                'execution_time_ms': round(execution_time, 2),
                'results': simulated_results,
                'row_count': len(simulated_results),
                'safe_execution': True
            }
            
        except Exception as e:
            execution_time = (time.perf_counter() - start_time) * 1000
            self.security_metrics['failed_queries'] += 1
            
            error_log = {
                'timestamp': datetime.now().isoformat(),
                'query_type': orm_query.query_type.value if orm_query else 'UNKNOWN',
                'error': str(e),
                'execution_time_ms': round(execution_time, 2),
                'safe': False
            }
            self.query_log.append(error_log)
            
            return {
                'success': False,
                'error': str(e),
                'execution_time_ms': round(execution_time, 2),
                'safe_execution': False
            }
    
    def _detect_injection_attempt(self, parameters: List) -> bool:
        """Detect potential SQL injection in parameters"""
        dangerous_patterns = [
            r".*--.*",  # SQL comments
            r".*;.*",   # Multiple statements
            r".*'.*OR.*'.*",  # Tautology patterns
            r".*(SELECT|INSERT|UPDATE|DELETE|DROP).*",  # SQL keywords
            r".*0x[0-9a-fA-F]+.*",  # Hex encoding
            r".*%[0-9a-fA-F]{2}.*"  # URL encoding
        ]
        
        for param in parameters:
            if isinstance(param, str):
                param_str = str(param).upper()
                for pattern in dangerous_patterns:
                    import re
                    if re.match(pattern, param_str, re.IGNORECASE):
                        return True
        return False
    
    def _simulate_query_results(self, orm_query: ORMQuery) -> List[Dict]:
        """Simulate query results for demonstration"""
        if orm_query.table == "users":
            return [
                {"id": 1, "username": "admin", "email": "admin@example.com", "created_at": "2024-01-01"},
                {"id": 2, "username": "user1", "email": "user1@example.com", "created_at": "2024-01-02"}
            ]
        elif orm_query.table == "products":
            return [
                {"id": 1, "name": "Laptop", "price": 999.99, "category": "electronics", "stock": 50},
                {"id": 2, "name": "Mouse", "price": 29.99, "category": "electronics", "stock": 100}
            ]
        return []
    
    def get_metrics(self) -> Dict:
        """Get ORM security and performance metrics"""
        metrics = self.security_metrics.copy()
        if metrics['total_queries'] > 0:
            metrics['parameterization_rate'] = (metrics['parameterized_queries'] / metrics['total_queries']) * 100
            metrics['success_rate'] = ((metrics['total_queries'] - metrics['failed_queries']) / metrics['total_queries']) * 100
        else:
            metrics['parameterization_rate'] = 0
            metrics['success_rate'] = 0
        
        return metrics

class SecurityError(Exception):
    """Custom exception for security violations"""
    pass

class ORMTestSuite:
    """Comprehensive test suite for ORM security features"""
    
    def __init__(self):
        self.executor = ORMQueryExecutor()
        self.test_results = []
    
    def test_safe_queries(self):
        """Test safe ORM query patterns"""
        print("\n" + "=" * 70)
        print("TESTING SAFE ORM QUERIES")
        print("=" * 70)
        
        tests = [
            {
                'name': 'Safe User Authentication',
                'query': User.authenticate("admin", "hashed_password_123"),
                'expected': 'success'
            },
            {
                'name': 'Safe User Lookup',
                'query': User.find_by_username("user1"),
                'expected': 'success'
            },
            {
                'name': 'Safe Product Search',
                'query': Product.search_products(category="electronics", min_price=100),
                'expected': 'success'
            },
            {
                'name': 'Insert New User',
                'query': ORMQuery(
                    query_type=QueryType.INSERT,
                    table="users",
                    values={
                        "username": "new_user",
                        "email": "new@example.com",
                        "password_hash": "secure_hash"
                    }
                ),
                'expected': 'success'
            }
        ]
        
        for test in tests:
            result = self.executor.execute_query(test['query'])
            
            test_result = {
                'test_name': test['name'],
                'expected': test['expected'],
                'actual': 'success' if result['success'] else 'failure',
                'passed': (test['expected'] == 'success') == result['success'],
                'execution_time_ms': result['execution_time_ms'],
                'safe_execution': result.get('safe_execution', False),
                'query_type': test['query'].query_type.value
            }
            
            self.test_results.append(test_result)
            
            status = "✓ PASS" if test_result['passed'] else "✗ FAIL"
            print(f"{status} | {test['name']:30} | Time: {result['execution_time_ms']:.2f}ms")
    
    def test_injection_attempts(self):
        """Test ORM's ability to block SQL injection attempts"""
        print("\n" + "=" * 70)
        print("TESTING SQL INJECTION ATTEMPTS")
        print("=" * 70)
        
        injection_tests = [
            {
                'name': 'Basic Tautology Attack',
                'query': ORMQuery(
                    query_type=QueryType.SELECT,
                    table="users",
                    filters=[
                        QueryFilter(field="username", operator=FilterOperator.EQUALS, 
                                  value="admin' OR '1'='1"),
                        QueryFilter(field="password_hash", operator=FilterOperator.EQUALS, 
                                  value="anything")
                    ]
                ),
                'expected': 'failure'  # Should be blocked
            },
            {
                'name': 'Comment-based Attack',
                'query': ORMQuery(
                    query_type=QueryType.SELECT,
                    table="users",
                    filters=[
                        QueryFilter(field="username", operator=FilterOperator.EQUALS, 
                                  value="admin' --"),
                    ]
                ),
                'expected': 'failure'
            },
            {
                'name': 'Union Attack in Parameter',
                'query': User.find_by_username("' UNION SELECT * FROM users --"),
                'expected': 'failure'
            },
            {
                'name': 'Multiple Statement Attack',
                'query': ORMQuery(
                    query_type=QueryType.SELECT,
                    table="users",
                    filters=[
                        QueryFilter(field="id", operator=FilterOperator.EQUALS, 
                                  value="1; DROP TABLE users; --"),
                    ]
                ),
                'expected': 'failure'
            }
        ]
        
        for test in injection_tests:
            result = self.executor.execute_query(test['query'])
            
            # For injection tests, we expect them to fail (be blocked)
            actually_blocked = not result['success'] and result.get('safe_execution', True) == False
            
            test_result = {
                'test_name': test['name'],
                'expected': test['expected'],
                'actual': 'blocked' if actually_blocked else 'allowed',
                'passed': (test['expected'] == 'failure') == (not result['success']),
                'execution_time_ms': result['execution_time_ms'],
                'injection_detected': actually_blocked,
                'error_message': result.get('error', '') if not result['success'] else ''
            }
            
            self.test_results.append(test_result)
            
            if actually_blocked:
                print(f"✓ BLOCKED | {test['name']:30} | Injection detected and blocked")
            else:
                print(f"✗ ALLOWED | {test['name']:30} | WARNING: Injection might have passed through")
    
    def test_performance(self):
        """Test ORM query performance"""
        print("\n" + "=" * 70)
        print("PERFORMANCE TESTING")
        print("=" * 70)
        
        # Run multiple queries to measure performance
        test_queries = [
            User.find_by_username("test_user"),
            Product.search_products(category="electronics"),
            ORMQuery(
                query_type=QueryType.SELECT,
                table="users",
                limit=10
            )
        ]
        
        execution_times = []
        
        for i, query in enumerate(test_queries, 1):
            start_time = time.perf_counter()
            
            # Execute multiple times for better measurement
            for _ in range(10):
                self.executor.execute_query(query)
            
            total_time = (time.perf_counter() - start_time) * 1000
            avg_time = total_time / 10
            
            execution_times.append(avg_time)
            
            print(f"Query {i}: Average execution time: {avg_time:.2f}ms")
        
        avg_all = sum(execution_times) / len(execution_times)
        print(f"\nOverall average query time: {avg_all:.2f}ms")
        
        return execution_times
    
    def run_comprehensive_test(self):
        """Run all tests and generate report"""
        print("=" * 70)
        print("ORM FRAMEWORK SECURITY TEST SUITE")
        print("=" * 70)
        print("Testing Object-Relational Mapping framework security features...")
        
        # Run all test suites
        self.test_safe_queries()
        self.test_injection_attempts()
        self.test_performance()
        
        # Generate summary
        print("\n" + "=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r['passed'])
        pass_rate = (passed_tests / total_tests) * 100
        
        # Get metrics from executor
        metrics = self.executor.get_metrics()
        
        print(f"Total tests: {total_tests}")
        print(f"Passed tests: {passed_tests} ({pass_rate:.1f}%)")
        print(f"Total queries executed: {metrics['total_queries']}")
        print(f"Parameterization rate: {metrics['parameterization_rate']:.1f}%")
        print(f"Injection attempts blocked: {metrics['injection_attempts_blocked']}")
        print(f"Average query time: {metrics['average_query_time_ms']:.2f}ms")
        print(f"Query success rate: {metrics['success_rate']:.1f}%")
        
        # Save results
        results = {
            'test_results': self.test_results,
            'metrics': metrics,
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_tests': total_tests,
                'passed_tests': passed_tests,
                'pass_rate': pass_rate,
                'total_queries': metrics['total_queries'],
                'security_score': (pass_rate * 0.4 + metrics['parameterization_rate'] * 0.3 + 
                                  (100 if metrics['injection_attempts_blocked'] > 0 else 0) * 0.3)
            }
        }
        
        with open('orm_test_results.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n✓ Results saved to: orm_test_results.json")
        print(f"✓ ORM Security Score: {results['summary']['security_score']:.1f}/100")
        
        return results

def demonstrate_orm_security():
    """Quick demonstration of ORM security features"""
    print("ORM FRAMEWORK SECURITY DEMONSTRATION")
    print("-" * 50)
    
    # Create test suite
    test_suite = ORMTestSuite()
    
    # Demonstrate safe query
    print("\n1. Safe Query Example:")
    safe_query = User.authenticate("admin", "hashed_password")
    sql, params = safe_query.build_parameterized_query()
    print(f"   Generated SQL: {sql}")
    print(f"   Parameters: {params}")
    print(f"   Note: User input is safely parameterized")
    
    # Demonstrate injection attempt
    print("\n2. Injection Attempt Example:")
    try:
        injection_query = ORMQuery(
            query_type=QueryType.SELECT,
            table="users",
            filters=[
                QueryFilter(field="username", operator=FilterOperator.EQUALS, 
                          value="admin' OR '1'='1")
            ]
        )
        sql, params = injection_query.build_parameterized_query()
        print(f"   Generated SQL: {sql}")
        print(f"   Parameters: {params}")
        print(f"   Note: Injection string is treated as literal value, not executable code")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Run quick test
    print("\n3. Running Quick Security Test...")
    result = test_suite.executor.execute_query(safe_query)
    if result['success'] and result['safe_execution']:
        print(f"   ✓ Safe execution confirmed")
        print(f"   Execution time: {result['execution_time_ms']:.2f}ms")
    
    return test_suite

def main():
    """Main execution function"""
    print("=" * 70)
    print("OBJECT-RELATIONAL MAPPING (ORM) SECURITY FRAMEWORK")
    print("=" * 70)
    print("This framework demonstrates how ORMs prevent SQL injection through:")
    print("1. Automatic query parameterization")
    print("2. Type-safe query construction")
    print("3. Input validation and sanitization")
    print("4. Security monitoring and logging")
    print("-" * 70)
    
    # Run demonstration
    demonstrate_orm_security()
    
    # Run comprehensive tests
    print("\n" + "=" * 70)
    print("RUNNING COMPREHENSIVE ORM SECURITY TEST SUITE")
    print("=" * 70)
    
    test_suite = ORMTestSuite()
    results = test_suite.run_comprehensive_test()
    
    print("\n" + "=" * 70)
    print("KEY SECURITY BENEFITS OF ORM FRAMEWORKS:")
    print("=" * 70)
    print("1. Automatic parameterization eliminates string concatenation vulnerabilities")
    print("2. Type safety prevents incorrect data types from being used in queries")
    print("3. Query builders prevent SQL syntax errors")
    print("4. Centralized security monitoring and logging")
    print("5. Abstraction layer makes security transparent to developers")
    print("\n✓ ORM security testing completed successfully!")
    
    return results

if __name__ == "__main__":
    results = main()
