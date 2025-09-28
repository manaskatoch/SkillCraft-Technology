#!/usr/bin/env python3
import re
import string
import math
import random
import json
import argparse
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

class AdvancedPasswordChecker:
    def __init__(self,
                 min_length: int = 8,
                 require_classes: Optional[Dict[str, bool]] = None,
                 dictionary_path: Optional[Path] = None):
        self.min_length = min_length
        default_require = {'lower': True, 'upper': True, 'digit': True, 'special': False}
        self.require_classes = require_classes if require_classes is not None else default_require
        self.special_chars = string.punctuation
        self.common_passwords = set()
        if dictionary_path:
            self.load_dictionary(dictionary_path)
        else:
            self._load_builtin_common_passwords()

    def _load_builtin_common_passwords(self):
        sample = [
            "123456", "password", "12345678", "qwerty", "abc123", "football",
            "monkey", "letmein", "dragon", "111111", "baseball", "iloveyou",
            "master", "sunshine", "ashley", "bailey", "passw0rd", "shadow"
        ]
        self.common_passwords = set(sample)

    def load_dictionary(self, path: Path):
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                self.common_passwords = set(line.strip() for line in f if line.strip())
        except Exception:
            self._load_builtin_common_passwords()

    def has_lowercase(self, pwd: str) -> bool:
        return bool(re.search(r"[a-z]", pwd))

    def has_uppercase(self, pwd: str) -> bool:
        return bool(re.search(r"[A-Z]", pwd))

    def has_digit(self, pwd: str) -> bool:
        return bool(re.search(r"\d", pwd))

    def has_special_char(self, pwd: str) -> bool:
        return bool(re.search(rf"[{re.escape(self.special_chars)}]", pwd))

    def consecutive_repeat_penalty(self, pwd: str, limit: int = 3) -> int:
        max_penalty = 4
        penalty = 0
        pattern = r"(.)\1+"
        for m in re.finditer(pattern, pwd):
            length = len(m.group(0))
            if length > limit:
                penalty += min(max_penalty, length - limit)
        return penalty

    def sequential_chars_penalty(self, pwd: str, seq_len: int = 3) -> int:
        pwd_lower = pwd.lower()
        alpha = string.ascii_lowercase
        digits = string.digits
        penalty = 0
        for i in range(len(pwd_lower) - seq_len + 1):
            seg = pwd_lower[i:i+seq_len]
            if seg in alpha or seg[::-1] in alpha or seg in digits or seg[::-1] in digits:
                penalty += 1
        return penalty

    def estimate_shannon_entropy(self, pwd: str) -> float:
        if not pwd:
            return 0.0
        freq = {}
        for ch in pwd:
            freq[ch] = freq.get(ch, 0) + 1
        entropy = 0.0
        length = len(pwd)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        entropy_bit_total = entropy * length
        return entropy_bit_total

    def estimate_pool_entropy(self, pwd: str) -> float:
        pool = 0
        if self.has_lowercase(pwd):
            pool += 26
        if self.has_uppercase(pwd):
            pool += 26
        if self.has_digit(pwd):
            pool += 10
        if self.has_special_char(pwd):
            pool += len(self.special_chars)
        if pool == 0:
            return 0.0
        return len(pwd) * math.log2(pool)

    def dictionary_check(self, pwd: str) -> bool:
        return pwd.lower() in self.common_passwords

    def similarity_to_common(self, pwd: str) -> int:
        score = 0
        low = pwd.lower()
        for common in self.common_passwords:
            if common in low or low in common:
                score += 2
            else:
                common_root = common.rstrip("0123456789")
                if common_root and common_root in low:
                    score += 1
        return score

    def assess_strength(self, password: str) -> Dict[str, Any]:
        issues = {}
        issues['too_short'] = len(password) < self.min_length
        issues['missing_lower'] = self.require_classes.get('lower', True) and not self.has_lowercase(password)
        issues['missing_upper'] = self.require_classes.get('upper', True) and not self.has_uppercase(password)
        issues['missing_digit'] = self.require_classes.get('digit', True) and not self.has_digit(password)
        issues['missing_special'] = self.require_classes.get('special', False) and not self.has_special_char(password)
        issues['repeated_seq'] = self.consecutive_repeat_penalty(password) > 0
        issues['sequential_chars'] = self.sequential_chars_penalty(password) > 0
        issues['dictionary_match'] = self.dictionary_check(password)
        issues['similar_common'] = self.similarity_to_common(password) > 0

        entropy_shannon = round(self.estimate_shannon_entropy(password), 2)
        entropy_pool = round(self.estimate_pool_entropy(password), 2)

        score = 100
        if issues['too_short']:
            score -= 25
        if issues['missing_lower']:
            score -= 8
        if issues['missing_upper']:
            score -= 8
        if issues['missing_digit']:
            score -= 10
        if issues['missing_special']:
            score -= 7
        score -= min(10, self.consecutive_repeat_penalty(password) * 2)
        score -= min(15, self.sequential_chars_penalty(password) * 3)
        if issues['dictionary_match']:
            score -= 40
        if issues['similar_common']:
            score -= 15

        if entropy_pool < 28:
            score -= 15
        elif entropy_pool < 50:
            score -= 5

        score = max(0, min(100, score))

        if score >= 90:
            level = "Very Strong"
        elif score >= 75:
            level = "Strong"
        elif score >= 50:
            level = "Moderate"
        elif score >= 25:
            level = "Weak"
        else:
            level = "Very Weak"

        suggestions = []
        if issues['too_short']:
            suggestions.append(f"Make it at least {self.min_length} characters long.")
        if issues['missing_lower']:
            suggestions.append("Add lowercase letters.")
        if issues['missing_upper']:
            suggestions.append("Add uppercase letters.")
        if issues['missing_digit']:
            suggestions.append("Include digits.")
        if issues['missing_special']:
            suggestions.append("Include special characters (e.g., !@#$%).")
        if issues['repeated_seq']:
            suggestions.append("Avoid long repeated characters.")
        if issues['sequential_chars']:
            suggestions.append("Avoid simple sequences like 'abc' or '123'.")
        if issues['dictionary_match'] or issues['similar_common']:
            suggestions.append("Avoid common words or passwords; use a unique passphrase.")
        if entropy_pool < 50:
            suggestions.append("Increase length and character variety to raise entropy.")

        return {
            "password": password,
            "length": len(password),
            "entropy_shannon_bits": entropy_shannon,
            "entropy_pool_bits": entropy_pool,
            "score": score,
            "level": level,
            "issues": issues,
            "suggestions": suggestions,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    def generate_strong_password(self,
                                 length: int = 16,
                                 use_lower: bool = True,
                                 use_upper: bool = True,
                                 use_digits: bool = True,
                                 use_special: bool = True) -> str:
        pool = ""
        if use_lower:
            pool += string.ascii_lowercase
        if use_upper:
            pool += string.ascii_uppercase
        if use_digits:
            pool += string.digits
        if use_special:
            pool += self.special_chars
        if not pool:
            pool = string.ascii_letters + string.digits
        while True:
            pwd = ''.join(random.choice(pool) for _ in range(length))
            if (not use_lower or any(c in string.ascii_lowercase for c in pwd)) and \
               (not use_upper or any(c in string.ascii_uppercase for c in pwd)) and \
               (not use_digits or any(c in string.digits for c in pwd)) and \
               (not use_special or any(c in self.special_chars for c in pwd)):
                return pwd

def parse_args():
    p = argparse.ArgumentParser(description="Advanced Password Strength Checker")
    p.add_argument("--min-length", type=int, default=8, help="Minimum required password length")
    p.add_argument("--no-lower", action="store_true", help="Do not require lowercase letters")
    p.add_argument("--no-upper", action="store_true", help="Do not require uppercase letters")
    p.add_argument("--no-digit", action="store_true", help="Do not require digits")
    p.add_argument("--require-special", action="store_true", help="Require special characters")
    p.add_argument("--dictionary", type=Path, help="Path to file with common passwords (one per line)")
    p.add_argument("--password", type=str, help="Password to evaluate (interactive if omitted)")
    p.add_argument("--batch-file", type=Path, help="Path to file with passwords to evaluate (one per line)")
    p.add_argument("--output", type=Path, help="Write JSON report to file")
    p.add_argument("--json", action="store_true", help="Emit JSON to stdout instead of pretty text")
    p.add_argument("--generate", type=int, nargs='?', const=16, help="Generate a strong password of optional length")
    return p.parse_args()

def pretty_print_report(rep: Dict[str, Any]):
    print(f"Password: {rep['password']}")
    print(f"Length: {rep['length']}  |  Score: {rep['score']}/100  |  Level: {rep['level']}")
    print(f"Entropy (Shannon, bits): {rep['entropy_shannon_bits']}")
    print(f"Entropy (Pool estimate, bits): {rep['entropy_pool_bits']}")
    print("Issues:")
    for k, v in rep['issues'].items():
        print(f"  - {k}: {'Yes' if v else 'No'}")
    if rep['suggestions']:
        print("Suggestions:")
        for s in rep['suggestions']:
            print(f"  - {s}")
    print(f"Checked at: {rep['timestamp']}")

def main():
    args = parse_args()
    requires = {
        'lower': not args.no_lower,
        'upper': not args.no_upper,
        'digit': not args.no_digit,
        'special': args.require_special
    }
    checker = AdvancedPasswordChecker(min_length=args.min_length, require_classes=requires, dictionary_path=args.dictionary)

    reports = []

    if args.generate is not None:
        gen = checker.generate_strong_password(length=args.generate,
                                               use_lower=requires['lower'],
                                               use_upper=requires['upper'],
                                               use_digits=requires['digit'],
                                               use_special=requires['special'])
        print(gen)
        return

    if args.batch_file:
        try:
            with args.batch_file.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    pwd = line.rstrip("\n\r")
                    if not pwd:
                        continue
                    rep = checker.assess_strength(pwd)
                    reports.append(rep)
        except Exception as e:
            print(f"Failed to read batch file: {e}")
            return
    else:
        if args.password:
            rep = checker.assess_strength(args.password)
            reports.append(rep)
        else:
            print("Interactive mode. Type 'exit' or press Ctrl+C to quit.")
            while True:
                try:
                    pwd = input("Enter password to evaluate: ")
                except (KeyboardInterrupt, EOFError):
                    print("\nExiting.")
                    break
                if pwd.strip().lower() == "exit":
                    break
                if not pwd:
                    continue
                rep = checker.assess_strength(pwd)
                reports.append(rep)
                if args.json:
                    print(json.dumps(rep, ensure_ascii=False))
                else:
                    pretty_print_report(rep)
                    print("-" * 60)

    if args.output:
        try:
            with args.output.open("w", encoding="utf-8") as f:
                json.dump(reports, f, ensure_ascii=False, indent=2)
            print(f"Wrote report to {args.output}")
        except Exception as e:
            print(f"Failed to write output file: {e}")
    else:
        if args.json and not args.batch_file:
            if reports:
                print(json.dumps(reports[-1], ensure_ascii=False))
        elif args.json and args.batch_file:
            print(json.dumps(reports, ensure_ascii=False, indent=2))
        else:
            if args.batch_file:
                for rep in reports:
                    pretty_print_report(rep)
                    print("-" * 40)

if __name__ == "__main__":
    main()