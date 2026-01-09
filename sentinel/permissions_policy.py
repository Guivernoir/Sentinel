"""
Permissions-Policy analysis. Feature access control.
Because every API should prove it needs camera access.
"""

from typing import Tuple, List
from sentinel.models import HeaderQuality


class PermissionsPolicyAnalyzer:
    """Permissions-Policy analyzer. The feature bouncer."""
    
    # Features that should almost never be '*'
    SENSITIVE_FEATURES = {
        'camera', 'microphone', 'geolocation', 'payment',
        'usb', 'serial', 'bluetooth', 'midi', 'magnetometer',
        'accelerometer', 'gyroscope', 'ambient-light-sensor'
    }
    
    # Features commonly over-restricted
    COMMON_FEATURES = {
        'autoplay', 'fullscreen', 'picture-in-picture',
        'clipboard-read', 'clipboard-write'
    }
    
    ISSUE_TYPE_WILDCARD = "wildcard_permission"
    ISSUE_TYPE_EMPTY = "empty_directive"
    ISSUE_TYPE_SENSITIVE = "overly_permissive"
    ISSUE_TYPE_MALFORMED = "malformed_directive"
    
    @classmethod
    def analyze(cls, policy_value: str) -> Tuple[HeaderQuality, List[str], List[str], set]:
        """Analyze Permissions-Policy configuration. Feature access is a privilege."""
        issues = []
        recommendations = []
        issue_types = set()
        
        policy_value = policy_value.strip()
        
        if not policy_value:
            issues.append("Empty Permissions-Policy provides no restriction")
            recommendations.append("Define policy for sensitive features")
            issue_types.add(cls.ISSUE_TYPE_EMPTY)
            return HeaderQuality.WEAK, issues, recommendations, issue_types
        
        # Parse policy: feature=(allowlist) or feature=allowlist
        directives = [d.strip() for d in policy_value.split(',') if d.strip()]
        
        wildcard_features = []
        sensitive_permissive = []
        malformed = []
        
        for directive in directives:
            if '=' not in directive:
                malformed.append(directive)
                continue
            
            parts = directive.split('=', 1)
            if len(parts) != 2:
                malformed.append(directive)
                continue
            
            feature = parts[0].strip()
            allowlist = parts[1].strip()
            
            # Strip parentheses if present
            if allowlist.startswith('(') and allowlist.endswith(')'):
                allowlist = allowlist[1:-1].strip()
            
            # Check for wildcards
            if '*' in allowlist:
                wildcard_features.append(feature)
                issue_types.add(cls.ISSUE_TYPE_WILDCARD)
                
                # Extra concern for sensitive features
                if feature in cls.SENSITIVE_FEATURES:
                    sensitive_permissive.append(feature)
                    issue_types.add(cls.ISSUE_TYPE_SENSITIVE)
        
        if malformed:
            issues.append(f"Malformed directives: {', '.join(malformed)}")
            recommendations.append("Use format: feature=(allowlist) or feature=allowlist")
            issue_types.add(cls.ISSUE_TYPE_MALFORMED)
        
        if sensitive_permissive:
            issues.append(
                f"Sensitive features allow all origins: {', '.join(sensitive_permissive)}"
            )
            recommendations.append(
                f"Restrict {', '.join(sensitive_permissive)} to 'self' or specific origins"
            )
        
        if wildcard_features and not sensitive_permissive:
            issues.append(f"Wildcard permissions for: {', '.join(wildcard_features)}")
            recommendations.append("Replace wildcards with specific origins or 'self'")
        
        # Quality assessment - tactical evaluation
        if sensitive_permissive:
            quality = HeaderQuality.DANGEROUS
        elif wildcard_features or malformed:
            quality = HeaderQuality.WEAK
        elif issues:
            quality = HeaderQuality.GOOD
        else:
            quality = HeaderQuality.EXCELLENT
        
        return quality, issues, recommendations, issue_types