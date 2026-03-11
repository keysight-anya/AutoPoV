from pathlib import Path

path = Path('/home/user/AutoPoV/app/agent_graph.py')
text = path.read_text(encoding='utf-8')

# Update PHP mapping to php (not javascript)
text = text.replace("        '.php': 'javascript',  # PHP - no native CodeQL support, use JS as fallback\n        '.phtml': 'javascript',\n        '.php3': 'javascript',\n        '.php4': 'javascript',\n        '.php5': 'javascript'\n", "        '.php': 'php',\n        '.phtml': 'php',\n        '.php3': 'php',\n        '.php4': 'php',\n        '.php5': 'php'\n")

# Insert CodeQL unsupported-language guard
marker = '            self._log(state, f"Detected language: {detected_lang}")\n\n            # Create CodeQL database once for all queries\n'
if marker in text and 'Language {detected_lang} not supported by CodeQL' not in text:
    insert = (
        '            supported_codeql = {"python", "javascript", "java", "cpp"}\n'
        '            if detected_lang not in supported_codeql:\n'
        '                self._log(state, f"Language {detected_lang} not supported by CodeQL; using Semgrep fallback only")\n'
        '                findings = []\n'
        '                for cwe in state["cwes"]:\n'
        '                    findings.extend(self._run_semgrep_fallback(state, cwe, detected_lang))\n'
        '                state["findings"] = findings\n'
        '                return state\n\n'
    )
    text = text.replace(marker, marker.replace('\n\n            # Create CodeQL database once for all queries\n', '\n') + insert + '            # Create CodeQL database once for all queries\n')

path.write_text(text, encoding='utf-8')
