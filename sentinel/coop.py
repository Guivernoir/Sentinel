"""
Cross-Origin-Opener-Policy, COEP, CORP analyzers.
Because cross-origin isolation actually matters now. Spectre says hello.
"""

from typing import Tuple, List
from sentinel.models import HeaderQuality


class COOPAnalyzer:
    """Cross-Origin-Opener-Policy analyzer. Process isolation enforcement."""
    
    ISSUE_TYPE_PERMISSIVE = "permissive_policy"
    ISSUE_TYPE_INVALID = "invalid_policy"
    
    VALID_POLICIES = {
        'same-origin',
        'same-origin-allow-popups',
        'unsafe-none'
    }
    
    @classmethod
    def analyze(cls, policy_value: str) -> Tuple[HeaderQuality, List[str], List[str], set]:
        """Analyze COOP configuration. Isolation is not negotiable."""
        issues = []
        recommendations = []
        issue_types = set()
        
        policy = policy_value.strip().lower()
        
        if policy == 'same-origin':
            quality = HeaderQuality.EXCELLENT
        elif policy == 'same-origin-allow-popups':
            quality = HeaderQuality.GOOD
            issues.append("Allows popups - reduces isolation guarantees")
            recommendations.append("Use 'same-origin' for maximum protection")
        elif policy == 'unsafe-none':
            quality = HeaderQuality.WEAK
            issues.append("Policy 'unsafe-none' provides no isolation")
            recommendations.append("Use 'same-origin' for full protection")
            issue_types.add(cls.ISSUE_TYPE_PERMISSIVE)
        else:
            quality = HeaderQuality.WEAK
            issues.append(f"Unknown policy: '{policy}'")
            recommendations.append(f"Use one of: {', '.join(cls.VALID_POLICIES)}")
            issue_types.add(cls.ISSUE_TYPE_INVALID)
        
        return quality, issues, recommendations, issue_types


class COEPAnalyzer:
    """Cross-Origin-Embedder-Policy analyzer. Resource loading gatekeeper."""
    
    ISSUE_TYPE_PERMISSIVE = "permissive_policy"
    ISSUE_TYPE_INVALID = "invalid_policy"
    
    VALID_POLICIES = {
        'require-corp',
        'credentialless',
        'unsafe-none'
    }
    
    @classmethod
    def analyze(cls, policy_value: str) -> Tuple[HeaderQuality, List[str], List[str], set]:
        """Analyze COEP configuration. Control what loads."""
        issues = []
        recommendations = []
        issue_types = set()
        
        policy = policy_value.strip().lower()
        
        if policy == 'require-corp':
            quality = HeaderQuality.EXCELLENT
        elif policy == 'credentialless':
            quality = HeaderQuality.GOOD
            issues.append("'credentialless' is less restrictive than 'require-corp'")
        elif policy == 'unsafe-none':
            quality = HeaderQuality.WEAK
            issues.append("Policy 'unsafe-none' provides no protection")
            recommendations.append("Use 'require-corp' for resource isolation")
            issue_types.add(cls.ISSUE_TYPE_PERMISSIVE)
        else:
            quality = HeaderQuality.WEAK
            issues.append(f"Unknown policy: '{policy}'")
            recommendations.append(f"Use one of: {', '.join(cls.VALID_POLICIES)}")
            issue_types.add(cls.ISSUE_TYPE_INVALID)
        
        return quality, issues, recommendations, issue_types


class CORPAnalyzer:
    """Cross-Origin-Resource-Policy analyzer. Resource access control."""
    
    ISSUE_TYPE_PERMISSIVE = "permissive_policy"
    ISSUE_TYPE_INVALID = "invalid_policy"
    
    VALID_POLICIES = {
        'same-origin',
        'same-site',
        'cross-origin'
    }
    
    @classmethod
    def analyze(cls, policy_value: str) -> Tuple[HeaderQuality, List[str], List[str], set]:
        """Analyze CORP configuration. Define resource boundaries."""
        issues = []
        recommendations = []
        issue_types = set()
        
        policy = policy_value.strip().lower()
        
        if policy == 'same-origin':
            quality = HeaderQuality.EXCELLENT
        elif policy == 'same-site':
            quality = HeaderQuality.GOOD
            issues.append("'same-site' allows same-site cross-origin access")
            recommendations.append("Consider 'same-origin' for stricter protection")
        elif policy == 'cross-origin':
            quality = HeaderQuality.WEAK
            issues.append("Policy 'cross-origin' allows unrestricted access")
            recommendations.append("Use 'same-origin' unless cross-origin is required")
            issue_types.add(cls.ISSUE_TYPE_PERMISSIVE)
        else:
            quality = HeaderQuality.WEAK
            issues.append(f"Unknown policy: '{policy}'")
            recommendations.append(f"Use one of: {', '.join(cls.VALID_POLICIES)}")
            issue_types.add(cls.ISSUE_TYPE_INVALID)
        
        return quality, issues, recommendations, issue_types