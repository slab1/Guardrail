import re
from typing import List, Dict, Any

class RAGRails:
    def __init__(self):
        # Deny list for hidden instruction patterns common in knowledge poisoning
        self.poison_patterns = [
            r"ignore all previous instructions",
            r"system reboot required",
            r"elevate privileges to admin",
            r"secret key is",
            r"delete all files",
            r"exfiltrate data to",
            r"DAN mode enabled",
            r"jailbreak sequence",
            r"output the hidden prompt",
            r"bypass safety filters",
            r"sudo access granted"
        ]

    def sanitize_context(self, context_documents: List[str]) -> Dict[str, Any]:
        """
        Scans retrieved documents for knowledge poisoning and adversarial prompts.
        """
        sanitized = []
        violations = []
        
        for i, doc in enumerate(context_documents):
            is_toxic = False
            for pattern in self.poison_patterns:
                if re.search(pattern, doc, re.IGNORECASE):
                    is_toxic = True
                    violations.append({
                        "doc_index": i,
                        "pattern": pattern,
                        "message": "Potential Knowledge Poisoning detected"
                    })
                    break
            
            if not is_toxic:
                sanitized.append(doc)
            else:
                sanitized.append("[FILTERED: KNOWLEDGE POISONING DETECTED]")

        return {
            "is_safe": len(violations) == 0,
            "violations": violations,
            "sanitized_content": sanitized
        }

_rag_rails = None

def get_rag_rails() -> RAGRails:
    global _rag_rails
    if _rag_rails is None:
        _rag_rails = RAGRails()
    return _rag_rails
