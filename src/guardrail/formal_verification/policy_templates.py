"""Policy Template System

Implements reusable policy templates with versioning and migration.
Supports Jinja2-style templating for generating policies.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
import json
import re
from enum import Enum


class TemplateCategory(Enum):
    """Template category types."""
    SECURITY = "security"
    COMPLIANCE = "compliance"
    RESOURCE = "resource"
    OPERATIONAL = "operational"


@dataclass
class TemplateVersion:
    """A version of a template."""
    version: str
    created_at: str
    template_text: str
    changelog: str
    breaking_changes: bool = False


@dataclass
class PolicyTemplate:
    """A reusable policy template."""
    id: str
    name: str
    description: str
    category: TemplateCategory
    author: str
    created_at: str
    version: str
    template_text: str
    parameters: Dict[str, Any]
    required_params: List[str]
    optional_params: Dict[str, Any]
    tags: List[str]
    versions: List[TemplateVersion] = field(default_factory=list)
    
    def render(self, **kwargs) -> str:
        """Render template with parameters."""
        # Validate required parameters
        for param in self.required_params:
            if param not in kwargs:
                raise ValueError(f"Required parameter '{param}' missing for template '{self.id}'")
        
        # Apply defaults for optional parameters
        params = dict(self.optional_params)
        params.update(kwargs)
        
        # Simple template rendering (Jinja2-style)
        rendered = self.template_text
        for key, value in params.items():
            placeholder = f"{{{{ {key} }}}}"
            rendered = rendered.replace(placeholder, str(value))
        
        return rendered
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'category': self.category.value,
            'author': self.author,
            'created_at': self.created_at,
            'version': self.version,
            'parameters': self.parameters,
            'required_params': self.required_params,
            'optional_params': self.optional_params,
            'tags': self.tags,
        }


class TemplateRegistry:
    """Registry for policy templates."""
    
    def __init__(self):
        self.templates: Dict[str, PolicyTemplate] = {}
        self._initialize_default_templates()
    
    def _initialize_default_templates(self):
        """Initialize built-in templates."""
        
        # Security template: Admin action requires consent
        admin_consent_template = PolicyTemplate(
            id="security_admin_consent",
            name="Admin Action Requires Consent",
            description="Requires user consent for admin actions",
            category=TemplateCategory.SECURITY,
            author="Guardrail",
            created_at=datetime.now().isoformat(),
            version="1.0.0",
            template_text="""
policy {{ policy_name }} {
    rule {{ rule_id }} {
        if action_type == "{{ action_type }}" and user_consent == false;
        then deny;
        priority {{ priority }};
    }
}
""",
            parameters={},
            required_params=["policy_name", "rule_id", "action_type", "priority"],
            optional_params={},
            tags=["security", "admin", "consent"]
        )
        
        # Resource template: CPU limit
        cpu_limit_template = PolicyTemplate(
            id="resource_cpu_limit",
            name="CPU Usage Limit",
            description="Limit CPU usage to prevent abuse",
            category=TemplateCategory.RESOURCE,
            author="Guardrail",
            created_at=datetime.now().isoformat(),
            version="1.0.0",
            template_text="""
policy {{ policy_name }} {
    rule {{ rule_id }} {
        if cpu_usage > {{ max_cpu }};
        then require_approval;
        priority {{ priority }};
    }
}
""",
            parameters={},
            required_params=["policy_name", "rule_id", "max_cpu", "priority"],
            optional_params={
                "description": "CPU usage limit"
            },
            tags=["resource", "cpu", "performance"]
        )
        
        # Compliance template: GDPR special categories
        gdpr_template = PolicyTemplate(
            id="compliance_gdpr_special_category",
            name="GDPR Special Category Data Protection",
            description="Protect special category personal data per GDPR",
            category=TemplateCategory.COMPLIANCE,
            author="Guardrail",
            created_at=datetime.now().isoformat(),
            version="1.0.0",
            template_text="""
policy {{ policy_name }} {
    rule {{ rule_id }} {
        if data_category == "special" and processing_purpose != "{{ allowed_purpose }}";
        then deny;
        priority {{ priority }};
    }
}
""",
            parameters={},
            required_params=["policy_name", "rule_id", "allowed_purpose", "priority"],
            optional_params={},
            tags=["compliance", "gdpr", "privacy"]
        )
        
        self.register(admin_consent_template)
        self.register(cpu_limit_template)
        self.register(gdpr_template)
    
    def register(self, template: PolicyTemplate):
        """Register a template."""
        self.templates[template.id] = template
    
    def get(self, template_id: str) -> Optional[PolicyTemplate]:
        """Get template by ID."""
        return self.templates.get(template_id)
    
    def list_by_category(self, category: TemplateCategory) -> List[PolicyTemplate]:
        """List templates by category."""
        return [t for t in self.templates.values() if t.category == category]
    
    def search(self, query: str) -> List[PolicyTemplate]:
        """Search templates by name, description, or tags."""
        results = []
        query_lower = query.lower()
        for template in self.templates.values():
            if (query_lower in template.name.lower() or
                query_lower in template.description.lower() or
                any(query_lower in tag.lower() for tag in template.tags)):
                results.append(template)
        return results
    
    def create_from_template(self, template_id: str, **kwargs) -> str:
        """Create policy from template."""
        template = self.get(template_id)
        if not template:
            raise ValueError(f"Template '{template_id}' not found")
        
        return template.render(**kwargs)
    
    def export(self) -> Dict[str, Any]:
        """Export all templates."""
        return {
            template_id: template.to_dict()
            for template_id, template in self.templates.items()
        }


class TemplateVersionManager:
    """Manages template versions and migrations."""
    
    def __init__(self, registry: TemplateRegistry):
        self.registry = registry
        self.migrations: Dict[str, List[Callable]] = {}
    
    def create_version(self, template_id: str, new_version: str, 
                      new_template_text: str, changelog: str,
                      breaking: bool = False):
        """Create new version of template."""
        template = self.registry.get(template_id)
        if not template:
            raise ValueError(f"Template '{template_id}' not found")
        
        # Save current version
        version = TemplateVersion(
            version=template.version,
            created_at=template.created_at,
            template_text=template.template_text,
            changelog="Initial version",
            breaking_changes=False
        )
        if not template.versions:
            template.versions.append(version)
        
        # Update template
        template.version = new_version
        template.template_text = new_template_text
        template.created_at = datetime.now().isoformat()
        
        if breaking:
            self._record_breaking_change(template_id, new_version)
    
    def _record_breaking_change(self, template_id: str, version: str):
        """Record breaking change for migration."""
        if template_id not in self.migrations:
            self.migrations[template_id] = []
    
    def migrate(self, template_id: str, from_version: str, to_version: str, 
                parameters: Dict[str, Any]) -> str:
        """Migrate policy from one template version to another."""
        template = self.registry.get(template_id)
        if not template:
            raise ValueError(f"Template '{template_id}' not found")
        
        # For now, just render with current template
        # In production, would apply transformation logic
        return template.render(**parameters)
    
    def get_version_history(self, template_id: str) -> List[TemplateVersion]:
        """Get version history for template."""
        template = self.registry.get(template_id)
        if not template:
            return []
        return template.versions


class PolicyDocumentationGenerator:
    """Generate documentation for policies from templates."""
    
    def __init__(self, registry: TemplateRegistry):
        self.registry = registry
    
    def generate_template_docs(self, template_id: str) -> str:
        """Generate markdown documentation for a template."""
        template = self.registry.get(template_id)
        if not template:
            return f"Template '{template_id}' not found"
        
        docs = f"""# {template.name}

## Description
{template.description}

## Category
{template.category.value}

## Version
{template.version}

## Author
{template.author}

## Parameters

### Required
"""
        for param in template.required_params:
            docs += f"- `{param}`\n"
        
        docs += "\n### Optional\n"
        for param, default in template.optional_params.items():
            docs += f"- `{param}` (default: {default})\n"
        
        docs += f"""
## Tags
{', '.join(template.tags)}

## Example Usage

```policy
{template.template_text}
```

## Generated Policy Example
"""
        # Generate example with dummy parameters
        example_params = {}
        for param in template.required_params:
            example_params[param] = f"example_{param}"
        
        try:
            example = template.render(**example_params)
            docs += f"```policy\n{example}\n```"
        except Exception as e:
            docs += f"\n*Example generation failed: {e}*"
        
        return docs
    
    def generate_catalog(self) -> str:
        """Generate documentation catalog for all templates."""
        docs = "# Policy Template Catalog\n\n"
        
        for category in TemplateCategory:
            templates = self.registry.list_by_category(category)
            if templates:
                docs += f"## {category.value.title()}\n\n"
                for template in templates:
                    docs += f"### {template.name}\n"
                    docs += f"{template.description}\n\n"
                    docs += f"- ID: `{template.id}`\n"
                    docs += f"- Version: {template.version}\n"
                    docs += f"- Tags: {', '.join(template.tags)}\n\n"
        
        return docs


# Global registry instance
registry = TemplateRegistry()
version_manager = TemplateVersionManager(registry)
doc_generator = PolicyDocumentationGenerator(registry)


def get_template(template_id: str) -> Optional[PolicyTemplate]:
    """Get template from global registry."""
    return registry.get(template_id)


def render_template(template_id: str, **kwargs) -> str:
    """Render template to policy text."""
    return registry.create_from_template(template_id, **kwargs)


def list_templates(category: Optional[TemplateCategory] = None) -> List[PolicyTemplate]:
    """List all templates, optionally filtered by category."""
    if category:
        return registry.list_by_category(category)
    return list(registry.templates.values())


if __name__ == "__main__":
    # Example usage
    print("=== Policy Template System ===\n")
    
    # List templates
    print("Available templates:")
    for template in list_templates():
        print(f"  - {template.id}: {template.name} ({template.category.value})")
    
    print("\nGenerating policy from template:")
    policy = render_template(
        "security_admin_consent",
        policy_name="admin_policy",
        rule_id="admin_rule_001",
        action_type="admin",
        priority=100
    )
    print(policy)
    
    print("\nTemplate documentation:")
    print(doc_generator.generate_template_docs("security_admin_consent")[:500])
