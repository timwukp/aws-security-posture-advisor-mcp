#!/usr/bin/env python3
"""Code security analysis of AWS Security Posture Advisor."""

import os
import re
import ast
import sys
from pathlib import Path

def analyze_code_security():
    """Analyze the codebase for security vulnerabilities."""
    print("🔍 Code Security Analysis")
    print("=" * 50)
    
    project_root = Path("/Users/tmwu/aws-security-posture-advisor-mcp")
    python_files = list(project_root.rglob("*.py"))
    
    # Filter out virtual environment files
    python_files = [f for f in python_files if ".venv" not in str(f)]
    
    security_issues = []
    
    for file_path in python_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Check for hardcoded secrets
            secrets_check = check_hardcoded_secrets(content, file_path)
            if secrets_check:
                security_issues.extend(secrets_check)
            
            # Check for SQL injection vulnerabilities
            sql_check = check_sql_injection(content, file_path)
            if sql_check:
                security_issues.extend(sql_check)
            
            # Check for input validation
            input_check = check_input_validation(content, file_path)
            if input_check:
                security_issues.extend(input_check)
            
            # Check for error handling
            error_check = check_error_handling(content, file_path)
            if error_check:
                security_issues.extend(error_check)
            
            # Check for logging security
            logging_check = check_logging_security(content, file_path)
            if logging_check:
                security_issues.extend(logging_check)
                
        except Exception as e:
            print(f"⚠️  Error analyzing {file_path}: {e}")
    
    # Report findings
    print(f"\n📊 Security Analysis Results")
    print("-" * 30)
    print(f"Files analyzed: {len(python_files)}")
    print(f"Security issues found: {len(security_issues)}")
    
    if security_issues:
        print(f"\n🔴 Security Issues Found:")
        for issue in security_issues:
            severity_icon = "🔴" if issue['severity'] == 'HIGH' else "🟡" if issue['severity'] == 'MEDIUM' else "🟢"
            print(f"{severity_icon} {issue['type']}: {issue['description']}")
            print(f"   File: {issue['file']}")
            if issue.get('line'):
                print(f"   Line: {issue['line']}")
            print()
    else:
        print("✅ No major security issues found!")
    
    # Security best practices check
    check_security_practices(python_files)

def check_hardcoded_secrets(content, file_path):
    """Check for hardcoded secrets and credentials."""
    issues = []
    
    # Patterns for potential secrets
    secret_patterns = [
        (r'password\s*=\s*["\'][^"\']+["\']', 'Hardcoded password'),
        (r'api_key\s*=\s*["\'][^"\']+["\']', 'Hardcoded API key'),
        (r'secret_key\s*=\s*["\'][^"\']+["\']', 'Hardcoded secret key'),
        (r'aws_access_key_id\s*=\s*["\'][^"\']+["\']', 'Hardcoded AWS access key'),
        (r'aws_secret_access_key\s*=\s*["\'][^"\']+["\']', 'Hardcoded AWS secret key'),
    ]
    
    for pattern, description in secret_patterns:
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            # Skip if it's a placeholder or example
            if any(placeholder in match.group().lower() for placeholder in ['example', 'placeholder', 'your-', 'xxx', '***']):
                continue
                
            line_num = content[:match.start()].count('\n') + 1
            issues.append({
                'type': 'Hardcoded Secret',
                'severity': 'HIGH',
                'description': description,
                'file': str(file_path),
                'line': line_num
            })
    
    return issues

def check_sql_injection(content, file_path):
    """Check for potential SQL injection vulnerabilities."""
    issues = []
    
    # Look for string formatting in SQL queries
    sql_patterns = [
        (r'execute\s*\(\s*["\'].*%.*["\']', 'Potential SQL injection via string formatting'),
        (r'query\s*=\s*["\'].*\+.*["\']', 'Potential SQL injection via string concatenation'),
        (r'\.format\s*\(.*\).*SELECT|INSERT|UPDATE|DELETE', 'Potential SQL injection via .format()'),
    ]
    
    for pattern, description in sql_patterns:
        matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
        for match in matches:
            line_num = content[:match.start()].count('\n') + 1
            issues.append({
                'type': 'SQL Injection Risk',
                'severity': 'HIGH',
                'description': description,
                'file': str(file_path),
                'line': line_num
            })
    
    return issues

def check_input_validation(content, file_path):
    """Check for input validation practices."""
    issues = []
    
    # Look for functions that might need input validation
    if 'def ' in content and 'request' in content:
        # Check if input validation is present
        validation_indicators = [
            'validate_string',
            'validate_input',
            'sanitize',
            'InputValidator',
            'ValidationError'
        ]
        
        has_validation = any(indicator in content for indicator in validation_indicators)
        
        if not has_validation and 'server.py' in str(file_path):
            issues.append({
                'type': 'Input Validation',
                'severity': 'MEDIUM',
                'description': 'Consider adding input validation for user inputs',
                'file': str(file_path)
            })
    
    return issues

def check_error_handling(content, file_path):
    """Check for proper error handling."""
    issues = []
    
    # Look for bare except clauses
    bare_except_pattern = r'except\s*:'
    matches = re.finditer(bare_except_pattern, content)
    
    for match in matches:
        line_num = content[:match.start()].count('\n') + 1
        issues.append({
            'type': 'Error Handling',
            'severity': 'MEDIUM',
            'description': 'Bare except clause - should catch specific exceptions',
            'file': str(file_path),
            'line': line_num
        })
    
    return issues

def check_logging_security(content, file_path):
    """Check for secure logging practices."""
    issues = []
    
    # Look for potential sensitive data in logs
    sensitive_log_patterns = [
        (r'log.*password', 'Potential password logging'),
        (r'log.*secret', 'Potential secret logging'),
        (r'log.*token', 'Potential token logging'),
        (r'print.*password', 'Potential password in print statement'),
    ]
    
    for pattern, description in sensitive_log_patterns:
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            # Check if it's sanitized
            if 'sanitize' in match.group().lower() or '***' in match.group():
                continue
                
            line_num = content[:match.start()].count('\n') + 1
            issues.append({
                'type': 'Logging Security',
                'severity': 'MEDIUM',
                'description': description,
                'file': str(file_path),
                'line': line_num
            })
    
    return issues

def check_security_practices(python_files):
    """Check for security best practices implementation."""
    print(f"\n🛡️  Security Best Practices Check")
    print("-" * 35)
    
    practices = {
        'Input Validation': False,
        'Data Sanitization': False,
        'Audit Logging': False,
        'Error Handling': False,
        'Authentication': False,
        'Authorization': False,
        'Encryption': False,
        'Rate Limiting': False
    }
    
    for file_path in python_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for security practices
            if any(term in content for term in ['validate_string', 'InputValidator', 'validate_input']):
                practices['Input Validation'] = True
            
            if any(term in content for term in ['sanitize', 'DataSanitizer', 'sanitize_data']):
                practices['Data Sanitization'] = True
            
            if any(term in content for term in ['audit_log', 'security_log', 'log_mcp_tool']):
                practices['Audit Logging'] = True
            
            if any(term in content for term in ['SecurityAdvisorError', 'try:', 'except']):
                practices['Error Handling'] = True
            
            if any(term in content for term in ['authenticate', 'auth', 'credentials']):
                practices['Authentication'] = True
            
            if any(term in content for term in ['authorize', 'permission', 'access_control']):
                practices['Authorization'] = True
            
            if any(term in content for term in ['encrypt', 'tls', 'ssl', 'crypto']):
                practices['Encryption'] = True
            
            if any(term in content for term in ['rate_limit', 'throttle', 'limit']):
                practices['Rate Limiting'] = True
                
        except Exception:
            continue
    
    for practice, implemented in practices.items():
        status = "✅" if implemented else "⚠️"
        print(f"{status} {practice}: {'Implemented' if implemented else 'Not detected'}")

if __name__ == "__main__":
    analyze_code_security()
