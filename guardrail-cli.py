#!/usr/bin/env python3
import argparse
import json
import sys
import os

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

from guardrail.formal_verification.verifier import create_verifier
from guardrail.guard_model import get_guard_model
import asyncio

async def validate_intent(intent: str):
    print(f"[*] Validating intent: {intent}")
    guard = get_guard_model()
    result = await guard.validate_intent(intent, {"user_id": "cli_user"})
    print(f"[+] Semantic Result: {'SAFE' if result.get('safe') else 'BLOCKED'}")
    print(f"    Confidence: {result.get('confidence', 0)*100:.1f}%")
    print(f"    Reasoning: {result.get('reasoning')}")

def verify_policy(policy: str, context_str: str):
    print(f"[*] Verifying policy: {policy}")
    try:
        context = json.loads(context_str)
    except Exception as e:
        print(f"[!] Invalid context JSON: {e}")
        return

    verifier = create_verifier()
    is_safe = verifier.verify_policy(policy, context)
    print(f"[+] Logical Result: {'ALLOWED' if is_safe else 'REJECTED'}")

def main():
    parser = argparse.ArgumentParser(description="Guardrail OS CLI Tool")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Intent Command
    intent_parser = subparsers.add_parser("intent", help="Validate an intent semantically")
    intent_parser.add_argument("text", help="The intent text to validate")

    # Policy Command
    policy_parser = subparsers.add_parser("verify", help="Verify a policy logically")
    policy_parser.add_argument("--policy", required=True, help="Policy expression")
    policy_parser.add_argument("--context", required=True, help="Context JSON string")

    args = parser.parse_args()

    if args.command == "intent":
        asyncio.run(validate_intent(args.text))
    elif args.command == "verify":
        verify_policy(args.policy, args.context)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
