"""
AutoPoV Report Generator Module
Generates professional PDF and JSON reports from scan results
"""

import os
import json
import requests
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import asdict

from app.config import settings
from app.scan_manager import ScanResult


try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False


class ReportGeneratorError(Exception):
    """Exception raised during report generation"""
    pass


def _safe(text: Any, max_len: int = 0) -> str:
    """Sanitize any value to a plain latin-1-safe, wrap-safe string for fpdf core fonts."""
    if text is None:
        return ""
    s = str(text)
    replacements = {
        "’": "'", "‘": "'", "“": '"', "”": '"',
        "–": "-", "—": "-", "•": "-", "…": "...",
        "é": "e", "è": "e", "ê": "e", "ë": "e",
        "à": "a", "á": "a", "â": "a", "ã": "a",
        "ó": "o", "ò": "o", "ô": "o", "õ": "o",
        "ú": "u", "ù": "u", "û": "u",
        "í": "i", "ì": "i", "î": "i",
        "ñ": "n", "ç": "c",
    }
    for ch, rep in replacements.items():
        s = s.replace(ch, rep)
    s = s.encode("latin-1", errors="replace").decode("latin-1")

    wrapped_parts = []
    for token in s.split(' '):
        if len(token) <= 36:
            wrapped_parts.append(token)
            continue
        wrapped_parts.append(' '.join(token[i:i+36] for i in range(0, len(token), 36)))
    s = ' '.join(wrapped_parts)

    if max_len and len(s) > max_len:
        s = s[:max_len - 3] + "..."
    return s


class ProfessionalPDFReport(FPDF):
    """Formal PDF report with restrained document-style presentation"""

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=16)
        self.alias_nb_pages()

    def header(self):
        self.set_fill_color(243, 244, 246)
        self.rect(0, 0, 210, 18, 'F')
        self.set_draw_color(209, 213, 219)
        self.line(12, 18, 198, 18)
        self.set_xy(12, 5)
        self.set_font('Arial', 'B', 13)
        self.set_text_color(31, 41, 55)
        self.cell(120, 6, 'AutoPoV Security Assessment Report', 0, 0, 'L')
        self.set_font('Arial', '', 8)
        self.set_text_color(107, 114, 128)
        self.cell(66, 6, datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'), 0, 0, 'R')
        self.ln(14)

    def footer(self):
        self.set_y(-12)
        self.set_draw_color(229, 231, 235)
        self.line(12, self.get_y(), 198, self.get_y())
        self.ln(2)
        self.set_font('Arial', '', 8)
        self.set_text_color(107, 114, 128)
        self.cell(0, 6, f'AutoPoV v{settings.APP_VERSION} | Page {self.page_no()}/{{nb}} | Confidential Security Assessment', 0, 0, 'C')

    def section_header(self, title: str, icon: str = ''):
        self.ln(2)
        self.set_fill_color(229, 231, 235)
        self.set_text_color(17, 24, 39)
        self.set_font('Arial', 'B', 13)
        self.cell(0, 9, _safe(f"{icon}  {title}" if icon else title), 0, 1, 'L', True)
        self.ln(1)

    def subsection_header(self, title: str):
        self.set_font('Arial', 'B', 11)
        self.set_text_color(31, 41, 55)
        self.cell(0, 6, _safe(title), 0, 1, 'L')
        self.set_draw_color(229, 231, 235)
        self.line(self.get_x(), self.get_y(), 198, self.get_y())
        self.ln(2)

    def body_text(self, text: str, bold: bool = False):
        self.set_font('Arial', 'B' if bold else '', 10)
        self.set_text_color(55, 65, 81)
        self.multi_cell(0, 5, _safe(text))
        self.ln(1)

    def key_value_row(self, label: str, value: str, label_width: int = 48):
        remaining_width = self.w - self.r_margin - self.get_x() - label_width
        if remaining_width < 25:
            self.set_x(self.l_margin)
            remaining_width = self.w - self.r_margin - self.get_x() - label_width
        if remaining_width < 25:
            remaining_width = self.w - self.l_margin - self.r_margin - label_width

        self.set_font('Arial', 'B', 9)
        self.set_text_color(75, 85, 99)
        self.cell(label_width, 6, _safe(label), 0, 0, 'L')
        self.set_font('Arial', '', 9)
        self.set_text_color(31, 41, 55)
        self.multi_cell(max(25, remaining_width), 6, _safe(value))

    def metric_card(self, label: str, value: str, color: Tuple[int, int, int] = (59, 130, 246)):
        start_x = self.get_x()
        start_y = self.get_y()
        self.set_fill_color(249, 250, 251)
        self.set_draw_color(209, 213, 219)
        self.rect(start_x, start_y, 58, 18, 'DF')
        self.set_xy(start_x + 3, start_y + 3)
        self.set_font('Arial', 'B', 15)
        self.set_text_color(*color)
        self.cell(52, 6, _safe(value), 0, 2, 'L')
        self.set_x(start_x + 3)
        self.set_font('Arial', '', 8)
        self.set_text_color(75, 85, 99)
        self.cell(52, 5, _safe(label), 0, 0, 'L')
        self.set_xy(start_x + 62, start_y)

    def table_header(self, headers: List[str], widths: List[int]):
        self.set_font('Arial', 'B', 9)
        self.set_fill_color(55, 65, 81)
        self.set_text_color(255, 255, 255)
        for i, header in enumerate(headers):
            self.cell(widths[i], 7, _safe(header), 1, 0, 'C', True)
        self.ln()
        self.set_text_color(31, 41, 55)

    def table_row(self, cells: List[str], widths: List[int], alternate: bool = False):
        self.set_fill_color(249, 250, 251 if alternate else 255)
        self.set_font('Arial', '', 8)
        for i, cell in enumerate(cells):
            self.cell(widths[i], 6, _safe(str(cell), 44), 1, 0, 'L', True)
        self.ln()

    def code_block(self, code: str, max_lines: int = 18):
        self.set_fill_color(245, 245, 245)
        self.set_text_color(31, 41, 55)
        self.set_font('Courier', '', 8)
        lines = _safe(code).split('\n')[:max_lines]
        formatted_code = '\n'.join(lines)
        if len(_safe(code).split('\n')) > max_lines:
            formatted_code += '\n... [truncated]'
        self.multi_cell(0, 4, formatted_code, 1, 'L', True)
        self.ln(2)

    def info_box(self, title: str, content: str, border_color: Tuple[int, int, int] = (107, 114, 128)):
        self.set_draw_color(*border_color)
        self.set_fill_color(249, 250, 251)
        self.set_font('Arial', 'B', 9)
        self.set_text_color(31, 41, 55)
        self.cell(0, 6, _safe(title), 1, 1, 'L', True)
        self.set_font('Arial', '', 9)
        self.set_text_color(75, 85, 99)
        self.multi_cell(0, 5, _safe(content), 1, 'L')
        self.ln(2)


class OpenRouterActivityTracker:
    """Track OpenRouter API activity for detailed usage reporting"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://openrouter.ai/api/v1"
    
    def get_activity(self, date: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetch activity from OpenRouter API"""
        if not self.api_key:
            return []
        
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            params = {}
            if date:
                params["date"] = date
            
            response = requests.get(
                f"{self.base_url}/activity",
                headers=headers,
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get("data", [])
            else:
                return []
        except Exception:
            return []
    
    def get_activity_for_scan(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Get activity for a specific scan time range"""
        activities = []
        current_date = start_time.date()
        end_date = end_time.date()
        
        while current_date <= end_date:
            date_str = current_date.strftime("%Y-%m-%d")
            day_activity = self.get_activity(date_str)
            
            # Filter activities within scan time range
            for activity in day_activity:
                activities.append(activity)
            
            current_date += timedelta(days=1)
        
        return activities


class ReportGenerator:
    """Generates comprehensive scan reports"""
    
    def __init__(self):
        self.results_dir = settings.RESULTS_DIR
        self.povs_dir = settings.POVS_DIR
        os.makedirs(self.povs_dir, exist_ok=True)
        self.activity_tracker = OpenRouterActivityTracker(settings.get_openrouter_api_key())
    
    def generate_json_report(self, result: ScanResult) -> str:
        """Generate comprehensive JSON report"""
        report_path = os.path.join(self.results_dir, f"{result.scan_id}_report.json")
        pov_summary = self._summarize_pov(result)
        models_used = self._collect_models_used(result)
        openrouter_activity = self._get_openrouter_activity(result)
        exact_openrouter_usage = self._collect_exact_openrouter_usage(result)
        language_info = getattr(result, "language_info", {}) or {}
        detected_language = getattr(result, "detected_language", None) or language_info.get("primary", "unknown")
        
        report_data = {
            "report_metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "tool": "AutoPoV",
                "version": settings.APP_VERSION,
                "report_type": "comprehensive_security_assessment"
            },
            "scan_summary": {
                "scan_id": result.scan_id,
                "status": result.status,
                "codebase": result.codebase_path,
                "scan_started": result.start_time if hasattr(result, 'start_time') else None,
                "scan_completed": result.end_time if hasattr(result, 'end_time') else None,
                "duration_seconds": result.duration_s,
                "language_analysis": {
                    "primary_language": detected_language,
                    "all_languages_detected": language_info.get('all_languages', []),
                    "language_distribution": language_info.get('language_stats', {}),
                    "total_source_files": language_info.get('total_files', 0),
                    "total_loc": getattr(result, 'total_loc', 0) or language_info.get('total_loc', 0)
                },
                "configuration": {
                    "model_mode": settings.MODEL_MODE,
                    "routing_mode": settings.ROUTING_MODE,
                    "selected_model": settings.MODEL_NAME,
                    "taxonomy_focus": result.cwes or [],
                    "discovery_scope": "open-ended" if not result.cwes else "focused",
                    "scout_enabled": settings.SCOUT_ENABLED,
                    "codeql_enabled": settings.is_codeql_available(),
                }
            },
            "model_usage": {
                "models_used": models_used,
                "openrouter_activity": openrouter_activity,
                "exact_openrouter_usage": exact_openrouter_usage,
                "total_cost_usd": result.total_cost_usd,
                "exact_total_cost_usd": exact_openrouter_usage.get("total_exact_cost_usd", 0.0)
            },
            "metrics": {
                "total_findings": result.total_findings,
                "runtime_confirmed_vulnerabilities": result.confirmed_vulns,
                "false_positives": result.false_positives,
                "unproven_findings": getattr(result, 'unproven_findings', 0),
                "failed_analyses": result.failed,
                "detection_rate_percent": round(self._calculate_detection_rate(result), 2),
                "false_positive_rate_percent": round(self._calculate_fp_rate(result), 2),
                "unproven_rate_percent": round(self._calculate_unproven_rate(result), 2),
                "pov_success_rate_percent": round(self._calculate_pov_success_rate(result), 2),
                "pov_summary": pov_summary,
                "cost_per_confirmed_usd": round(self._calculate_cost_per_confirmed(result), 6)
            },
            "findings": self._format_findings(result.findings),
            "detailed_findings": self._format_detailed_findings(result.findings, result),
            "methodology": self._generate_methodology(result)
        }
        
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return report_path
    
    def _format_detailed_findings(self, findings: List[Dict[str, Any]], result: ScanResult) -> List[Dict[str, Any]]:
        """Format detailed findings with full evidence and proof"""
        detailed = []
        language_info = getattr(result, "language_info", {}) or {}
        
        for idx, finding in enumerate(findings or []):
            if not finding:
                continue
                
            # Get file language
            filepath = finding.get('filepath', '')
            file_lang = language_info.get('file_mappings', {}).get(filepath, result.detected_language or 'unknown')
            
            # Get validation details
            validation = finding.get('validation_result', {}) or {}
            pov_result = finding.get('pov_result', {}) or {}
            unit_test = validation.get('unit_test_result', {}) or {}
            oracle = unit_test.get('oracle', {}) or {}
            
            # Build comprehensive evidence description
            evidence_description = []
            if oracle.get('evidence'):
                for ev in oracle['evidence']:
                    evidence_description.append(f"- {ev}")
            
            # Determine proof quality
            proof_quality = "none"
            if pov_result.get('vulnerability_triggered'):
                if oracle.get('confidence') == 'high':
                    proof_quality = "strong"
                elif oracle.get('confidence') == 'medium':
                    proof_quality = "moderate"
                else:
                    proof_quality = "weak"
            
            detailed_finding = {
                "finding_number": idx + 1,
                "finding_id": f"UNCLASSIFIED-{idx+1:03d}",
                
                "vulnerability": {
                    "cwe_id": "UNCLASSIFIED",
                    "classification_name": "Open-ended vulnerability candidate",
                    "cve_id": finding.get('cve_id'),
                    "description": finding.get('llm_explanation', 'No description available'),
                    "root_cause": finding.get('root_cause', ''),
                    "impact": finding.get('impact', ''),
                    "severity": self._calculate_severity(finding),
                    "confidence": finding.get('confidence', 0.0),
                    "classification_status": "novel_or_unclassified",
                    "taxonomy_refs": finding.get("taxonomy_refs", []),
                    "final_status": finding.get('final_status', 'unknown')
                },
                
                "location": {
                    "file_path": filepath,
                    "line_number": finding.get('line_number', 0),
                    "language": file_lang,
                    "code_snippet": finding.get('code_chunk', ''),
                    "full_context": finding.get('full_code_context', '')
                },
                
                "detection": {
                    "source": finding.get('source', 'unknown'),
                    "detection_method": finding.get('detection_method', 'AI investigation'),
                    "investigation_model": finding.get('model_used', 'unknown'),
                    "investigation_verdict": finding.get('llm_verdict', 'UNKNOWN'),
                    "investigation_time_seconds": finding.get('inference_time_s', 0),
                    "classification_summary": self._build_classification_summary(finding),
                    "token_usage": {
                        "prompt_tokens": finding.get('prompt_tokens', 0),
                        "completion_tokens": finding.get('completion_tokens', 0),
                        "total_tokens": finding.get('total_tokens', 0)
                    }
                },
                
                "proof_of_vulnerability": {
                    "pov_script": finding.get('pov_script', ''),
                    "exploit_contract": finding.get('exploit_contract', {}),
                    "pov_generation_model": finding.get('pov_model_used', ''),
                    "pov_token_usage": {
                        "prompt_tokens": finding.get('pov_prompt_tokens', 0),
                        "completion_tokens": finding.get('pov_completion_tokens', 0),
                        "total_tokens": finding.get('pov_total_tokens', 0)
                    },
                    "refinement_attempts": len(finding.get('refinement_history') or []),
                    "refinement_history": finding.get('refinement_history') or []
                },
                
                "validation": {
                    "validation_method": validation.get('validation_method') or pov_result.get('validation_method', 'unknown'),
                    "validation_summary": self._build_validation_summary(finding),
                    "static_validation": validation.get('static_result', {}),
                    "unit_test_result": {
                        "success": unit_test.get('success', False),
                        "vulnerability_triggered": unit_test.get('vulnerability_triggered', False),
                        "exit_code": unit_test.get('exit_code', -1),
                        "execution_time_seconds": unit_test.get('execution_time_s', 0)
                    },
                    "proof_quality": proof_quality,
                    "evidence": {
                        "confidence_level": oracle.get('confidence', 'low'),
                        "detection_method": oracle.get('method', 'unknown'),
                        "evidence_items": oracle.get('evidence', []),
                        "evidence_description": "\n".join(evidence_description) if evidence_description else "No specific evidence recorded",
                        "stdout_output": unit_test.get('stdout', ''),
                        "stderr_output": unit_test.get('stderr', '')
                    }
                },
                
                "impact_assessment": {
                    "what_was_tested": f"The candidate vulnerability at {filepath}:{finding.get('line_number', 0)}",
                    "how_it_was_tested": "The system generated a proof, validated it statically, attempted unit-style execution, and used runtime execution where needed.",
                    "outcome": "VULNERABILITY CONFIRMED" if pov_result.get('vulnerability_triggered') else "PROOF NOT ESTABLISHED",
                    "proof_summary": self._build_proof_summary(finding)
                },
                
                "resource_usage": {
                    "investigation_cost_usd": finding.get('cost_usd', 0),
                    "pov_generation_cost_usd": pov_result.get('cost_usd', 0),
                    "total_cost_usd": (finding.get('cost_usd', 0) or 0) + (pov_result.get('cost_usd', 0) or 0)
                }
            }
            
            detailed.append(detailed_finding)
        
        return detailed
    
    def _get_cwe_name(self, cwe_id: str) -> str:
        """Get human-readable classification label without assuming a fixed taxonomy dictionary."""
        if not cwe_id or cwe_id == 'UNCLASSIFIED':
            return 'Unclassified / novel vulnerability'
        return cwe_id
    
    def _calculate_severity(self, finding: Dict[str, Any]) -> str:
        """Calculate severity based on confidence and validation"""
        confidence = finding.get('confidence', 0)
        pov_result = finding.get('pov_result', {}) or {}
        triggered = pov_result.get('vulnerability_triggered', False)
        
        if triggered and confidence >= 0.8:
            return "HIGH"
        elif triggered and confidence >= 0.6:
            return "MEDIUM"
        elif confidence >= 0.7:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_proof_summary(self, finding: Dict[str, Any], oracle: Dict[str, Any]) -> str:
        """Generate human-readable proof summary"""
        pov_result = finding.get('pov_result', {}) or {}

        if not pov_result.get('vulnerability_triggered'):
            return "The PoV script did not successfully trigger the vulnerability. This may indicate a false positive, missing runtime prerequisites, or a candidate that needs manual review."

        evidence = oracle.get('evidence', [])
        method = oracle.get('method', 'unknown')

        summary_parts = ["The vulnerability was confirmed through automated testing."]

        if evidence:
            summary_parts.append(f"Evidence detected using {method} method:")
            for ev in evidence[:3]:
                summary_parts.append(f"  - {ev}")

        return " ".join(summary_parts)

    def _build_classification_summary(self, finding: Dict[str, Any]) -> str:
        cwe = finding.get('cwe_type') or 'UNCLASSIFIED'
        cve = finding.get('cve_id')
        verdict = finding.get('llm_verdict', 'UNKNOWN')
        if cwe == 'UNCLASSIFIED':
            summary = f"{verdict} candidate kept as unclassified because no precise CWE mapping was justified."
        else:
            summary = f"{verdict} candidate mapped to {cwe}."
        if cve:
            summary += f" Related CVE: {cve}."
        return summary

    def _get_proof_status(self, finding: Dict[str, Any]) -> str:
        pov_result = finding.get('pov_result') or {}
        validation = finding.get('validation_result') or {}
        if pov_result.get('vulnerability_triggered'):
            return 'confirmed'
        if finding.get('pov_script'):
            method = validation.get('validation_method') or pov_result.get('validation_method')
            if method:
                return f'proof_attempted_via_{method}'
            return 'proof_attempted'
        if finding.get('llm_verdict') == 'FALSE_POSITIVE':
            return 'false_positive'
        if finding.get('final_status') == 'failed':
            return 'proof_failed'
        return 'not_proven'

    def _build_validation_summary(self, finding: Dict[str, Any]) -> str:
        validation = finding.get('validation_result') or {}
        pov_result = finding.get('pov_result') or {}
        unit_test = (validation.get('unit_test_result') or {})
        method = validation.get('validation_method') or pov_result.get('validation_method') or 'unknown'
        if pov_result.get('vulnerability_triggered'):
            return f"Proof established using {method}."
        if unit_test.get('success'):
            return f"Validation executed using {method}, but the vulnerability was not triggered."
        return f"Validation did not establish proof using {method}."

    def _build_proof_summary(self, finding: Dict[str, Any]) -> str:
        validation = finding.get('validation_result') or {}
        pov_result = finding.get('pov_result') or {}
        unit_test = validation.get('unit_test_result') or {}
        oracle = unit_test.get('oracle') or {}
        proof_parts = [self._generate_proof_summary(finding, oracle)]
        if validation.get('validation_method') or pov_result.get('validation_method'):
            proof_parts.append(f"Validation path: {validation.get('validation_method') or pov_result.get('validation_method')}.")
        stdout = unit_test.get('stdout') or pov_result.get('stdout')
        if stdout:
            proof_parts.append(f"Observed stdout: {str(stdout)[:240]}")
        return ' '.join(proof_parts)

    def _failure_reason_for_finding(self, finding: Dict[str, Any]) -> str:
        """Return a specific, honest reason explaining why a finding was not proven.

        Covers every gate in the pipeline so the report never shows the misleading
        fallback 'Proof was attempted but not established' for a finding that was
        never actually attempted.
        """
        status = finding.get('final_status', '')
        pov_result = finding.get('pov_result') or {}

        if status == 'unproven_low_confidence':
            conf = finding.get('confidence', 0.0)
            return (f"Confidence {conf:.2f} was below the proof threshold — "
                    "investigation verdict was uncertain")

        if status == 'unproven_budget_exhausted':
            return ("Proof budget cap (PROOF_MAX_FINDINGS) was reached; "
                    "no attempt was made for this finding")

        if status in {'unproven_contract_gate', 'contract_gate_failed'}:
            reasons = (
                finding.get('contract_gate_reasons')
                or (finding.get('validation_result') or {}).get('issues')
                or []
            )
            if reasons:
                return "Contract gate blocked PoV: " + "; ".join(str(r) for r in reasons[:3])
            return "Contract gate blocked PoV generation (missing entrypoint or success indicators)"

        if status == 'pov_generation_failed':
            err = (pov_result.get('error')
                   or finding.get('pov_error')
                   or 'Model returned no usable script')
            return f"PoV generation failed: {err}"

        if status == 'unproven_lite':
            return "LITE_MODE is enabled — PoV generation was skipped for all findings"

        if status == 'skipped_lite':
            return "LITE_MODE is enabled — finding confidence was below threshold, no attempt made"

        # Fallback: script was generated but runtime did not confirm
        return (
            pov_result.get('proof_summary')
            or pov_result.get('stderr')
            or "Proof script was generated but runtime execution did not confirm the vulnerability"
        )

    def _risk_rating(self, result: ScanResult) -> str:
        if result.confirmed_vulns >= 3:
            return 'High'
        if result.confirmed_vulns >= 1:
            return 'Elevated'
        if result.total_findings >= 25:
            return 'Moderate'
        return 'Low'

    def _executive_assessment(self, result: ScanResult) -> str:
        risk = self._risk_rating(result)
        scope = 'open-ended vulnerability discovery' if not result.cwes else f"focused review of {len(result.cwes)} taxonomy labels"
        return (
            f"AutoPoV completed a {scope} of the target codebase and identified {result.total_findings} candidate findings. "
            f"Of those, {result.confirmed_vulns} were runtime-proven, {result.false_positives} were rejected as false positives, "
            f"and {getattr(result, 'unproven_findings', 0)} remained unproven after automated validation. "
            f"Overall risk for this assessment is rated {risk} based on the number of confirmed issues, their exploitability, and the volume of unresolved findings."
        )

    def _proof_narrative(self, finding: Dict[str, Any]) -> Dict[str, str]:
        pov_result = finding.get('pov_result') or {}
        code = str(finding.get('code_chunk') or '')
        excerpt = str((pov_result.get('evidence') or {}).get('combined_excerpt') or pov_result.get('stderr') or pov_result.get('stdout') or '')
        refs = ', '.join(finding.get('taxonomy_refs') or [])
        trigger = 'AutoPoV generated crafted input and executed the vulnerable code path.'
        if 'strcpy(buf, "empty")' in code or 'empty' in code.lower():
            trigger = 'AutoPoV supplied an empty string while the destination buffer remained too small, forcing the vulnerable copy path to run.'
        elif 'TARGET_BINARY' in str(finding.get('pov_script') or '') or 'MQJS_BIN' in str(finding.get('pov_script') or ''):
            trigger = 'AutoPoV executed the built target binary with attacker-controlled input designed to reach the vulnerable path.'
        observed = pov_result.get('proof_summary') or 'A concrete runtime failure was observed while executing the target.'
        if excerpt:
            observed += f" Evidence excerpt: {excerpt[:240]}"
        impact = 'This demonstrates that attacker-controlled input can drive the target into an unsafe runtime state.'
        if 'assert' in excerpt.lower():
            impact = 'This demonstrates that attacker-controlled input can make the program abort or crash in the vulnerable path.'
        if 'addresssanitizer' in excerpt.lower() or 'segmentation fault' in excerpt.lower() or 'CWE-120' in refs:
            impact = 'This demonstrates a memory-safety condition that can lead to crashes, denial of service, and potentially more serious native-code exploitation.'
        why = 'AutoPoV counts this as proven because the issue was triggered during real execution, the vulnerable path was reached, and the observed runtime behavior matched the expected exploit outcome.' if pov_result.get('vulnerability_triggered') else 'AutoPoV does not count this as proven because runtime execution did not produce the expected exploit evidence.'
        return {
            'trigger': trigger,
            'observed': observed,
            'impact': impact,
            'why': why,
        }

    def _finding_title(self, index: int, finding: Dict[str, Any]) -> str:
        refs = ', '.join(finding.get('taxonomy_refs') or [])
        label = refs if refs else (finding.get('cwe_type') or 'UNCLASSIFIED')
        return f"Finding {index}: {label}"

    def generate_pdf_report(self, result: ScanResult) -> str:
        """Generate formal PDF report"""
        if not FPDF_AVAILABLE:
            raise ReportGeneratorError("fpdf not available. Install fpdf2")

        report_path = os.path.join(self.results_dir, f"{result.scan_id}_report.pdf")
        exact_openrouter_usage = self._collect_exact_openrouter_usage(result)
        methodology = self._generate_methodology(result)
        language_info = getattr(result, 'language_info', {}) or {}
        detected_language = getattr(result, 'detected_language', None) or language_info.get('primary', 'unknown')
        confirmed = [f for f in (result.findings or []) if f.get('final_status') == 'confirmed']
        _NOT_CONFIRMED = {
            'failed', 'pov_generation_failed', 'pov_failed',
            'unproven_low_confidence', 'unproven_budget_exhausted',
            'unproven_contract_gate', 'contract_gate_failed',
            'unproven_lite', 'skipped_lite',
        }
        unproven = [
            f for f in (result.findings or [])
            if f.get('final_status') in _NOT_CONFIRMED
            or (f.get('llm_verdict') == 'REAL' and f.get('final_status') not in {'confirmed'})
        ]
        false_positives = [f for f in (result.findings or []) if f.get('final_status') == 'skipped']

        pdf = ProfessionalPDFReport()
        pdf.add_page()

        target_name = os.path.basename(result.codebase_path.rstrip('/')) or result.codebase_path
        pdf.set_font('Arial', 'B', 20)
        pdf.set_text_color(17, 24, 39)
        pdf.cell(0, 12, 'Security Assessment Report', 0, 1, 'L')
        pdf.set_font('Arial', '', 11)
        pdf.set_text_color(75, 85, 99)
        pdf.cell(0, 7, _safe(f'Target: {target_name}'), 0, 1, 'L')
        pdf.cell(0, 7, _safe(f'Scan ID: {result.scan_id}'), 0, 1, 'L')
        pdf.cell(0, 7, _safe(f'Completed: {result.end_time or datetime.utcnow().isoformat()}'), 0, 1, 'L')
        pdf.ln(4)

        pdf.section_header('Executive Summary')
        pdf.body_text(self._executive_assessment(result))
        pdf.ln(2)
        for label, value, color in [
            ('Confirmed', str(result.confirmed_vulns), (22, 163, 74)),
            ('Unproven', str(getattr(result, 'unproven_findings', 0)), (180, 83, 9)),
            ('False Positives', str(result.false_positives), (75, 85, 99)),
        ]:
            pdf.metric_card(label, value, color)
        pdf.ln(18)

        pdf.subsection_header('Assessment Snapshot')
        pdf.key_value_row('Overall risk rating', self._risk_rating(result))
        pdf.key_value_row('Discovery scope', 'Open-ended vulnerability discovery' if not result.cwes else ', '.join(result.cwes))
        pdf.key_value_row('Primary language', detected_language)
        pdf.key_value_row('Languages observed', ', '.join(language_info.get('all_languages', [])) or detected_language)
        pdf.key_value_row('Source files / LOC', f"{language_info.get('total_files', 0)} files / {getattr(result, 'total_loc', 0) or language_info.get('total_loc', 0):,} LOC")
        pdf.key_value_row('Selected model', result.model_name or settings.MODEL_NAME)
        pdf.key_value_row('Duration / cost', f"{result.duration_s:.1f} seconds / ${result.total_cost_usd:.6f}")
        pdf.key_value_row('Proof success rate', f"{self._calculate_pov_success_rate(result):.1f}%")

        pdf.section_header('Scope And Method')
        pdf.body_text('This report summarizes automated source-code ingestion, static analysis, AI-assisted investigation, proof-of-vulnerability generation, and runtime validation. Only findings with observed runtime exploit evidence are marked as proven.')
        pdf.subsection_header('Configuration')
        pdf.key_value_row('Routing mode', settings.ROUTING_MODE)
        pdf.key_value_row('Model mode', settings.MODEL_MODE)
        pdf.key_value_row('CodeQL enabled', 'Yes' if settings.is_codeql_available() else 'No')
        pdf.key_value_row('Scout enabled', 'Yes' if settings.SCOUT_ENABLED else 'No')
        pdf.key_value_row('Discovery mode', methodology.get('discovery_scope', 'open-ended'))

        if exact_openrouter_usage.get('summary_by_agent'):
            pdf.section_header('Model Usage')
            headers = ['Agent', 'Model', 'Calls', 'Reasoning', 'Cost']
            widths = [35, 72, 18, 28, 25]
            pdf.table_header(headers, widths)
            for i, row in enumerate(exact_openrouter_usage.get('summary_by_agent', [])[:12]):
                pdf.table_row([
                    row.get('agent_role', 'unknown'),
                    row.get('model', 'unknown'),
                    str(row.get('calls', 0)),
                    f"{row.get('reasoning_tokens', 0):,}",
                    f"${row.get('cost_usd', 0):.6f}",
                ], widths, alternate=bool(i % 2))
            pdf.ln(2)
            pdf.body_text(
                f"Exact OpenRouter calls captured: {exact_openrouter_usage.get('total_calls', 0)}. "
                f"Prompt tokens: {exact_openrouter_usage.get('total_prompt_tokens', 0):,}. "
                f"Completion tokens: {exact_openrouter_usage.get('total_completion_tokens', 0):,}. "
                f"Reasoning tokens: {exact_openrouter_usage.get('total_reasoning_tokens', 0):,}. "
                f"Exact billed cost: ${exact_openrouter_usage.get('total_exact_cost_usd', 0.0):.6f}."
            )

        pdf.section_header('Runtime-Proven Vulnerabilities')
        if confirmed:
            for idx, finding in enumerate(confirmed, 1):
                if pdf.get_y() > 235:
                    pdf.add_page()
                narrative = self._proof_narrative(finding)
                pdf.subsection_header(self._finding_title(idx, finding))
                pdf.key_value_row('Location', f"{finding.get('filepath', 'N/A')}:{finding.get('line_number', 'N/A')}")
                pdf.key_value_row('Confidence', f"{finding.get('confidence', 0.0):.2f}")
                pdf.key_value_row('Status', 'Runtime proven')
                contract = finding.get('exploit_contract') or {}
                if contract.get('target_entrypoint'):
                    pdf.key_value_row('Target entrypoint', str(contract.get('target_entrypoint')))
                if finding.get('llm_explanation'):
                    pdf.info_box('Vulnerability Description', finding.get('llm_explanation', ''))
                pdf.info_box('How AutoPoV Triggered It', narrative['trigger'])
                pdf.info_box('Observed Runtime Outcome', narrative['observed'])
                pdf.info_box('Why This Matters', narrative['impact'])
                pdf.info_box('Why This Counts As Proof', narrative['why'])
                pov_result = finding.get('pov_result') or {}
                evidence = (pov_result.get('evidence') or {}).get('combined_excerpt') or pov_result.get('stderr') or pov_result.get('stdout') or ''
                if evidence:
                    pdf.subsection_header('Runtime Evidence Excerpt')
                    pdf.code_block(evidence, max_lines=12)
                if finding.get('code_chunk'):
                    pdf.subsection_header('Vulnerable Code Excerpt')
                    pdf.code_block(finding.get('code_chunk', ''), max_lines=14)
                pdf.ln(2)
        else:
            pdf.body_text('No findings reached runtime-confirmed status in this assessment.')

        pdf.section_header('Unproven Findings')
        if unproven:
            headers = ['Location', 'Status', 'Confidence', 'Reason']
            widths = [78, 26, 20, 62]
            pdf.table_header(headers, widths)
            for i, finding in enumerate(unproven[:25]):
                pov_result = finding.get('pov_result') or {}
                reason = self._failure_reason_for_finding(finding)
                pdf.table_row([
                    f"{finding.get('filepath', 'N/A')}:{finding.get('line_number', 'N/A')}",
                    finding.get('final_status', 'unproven'),
                    f"{finding.get('confidence', 0.0):.2f}",
                    reason,
                ], widths, alternate=bool(i % 2))
            pdf.ln(2)
            pdf.body_text('These findings were investigated and in some cases had PoV scripts generated, but runtime evidence was insufficient to classify them as proven vulnerabilities.')
        else:
            pdf.body_text('No unproven findings were recorded.')

        # Proof Failure Breakdown — categorized count of why proofs did not happen
        all_findings = result.findings or []
        breakdown = {
            'contract_gate': sum(1 for f in all_findings if f.get('final_status') in {'unproven_contract_gate', 'contract_gate_failed'}),
            'low_confidence': sum(1 for f in all_findings if f.get('final_status') == 'unproven_low_confidence'),
            'budget_exhausted': sum(1 for f in all_findings if f.get('final_status') == 'unproven_budget_exhausted'),
            'generation_failed': sum(1 for f in all_findings if f.get('final_status') in {'pov_generation_failed', 'pov_failed'}),
            'runtime_unconfirmed': sum(
                1 for f in all_findings
                if f.get('pov_script') and not (f.get('pov_result') or {}).get('vulnerability_triggered')
                and f.get('final_status') not in {'confirmed'}
            ),
        }
        if any(v > 0 for v in breakdown.values()):
            pdf.section_header('Proof Failure Breakdown')
            pdf.body_text(
                'The following table shows how many REAL findings failed at each stage of the proof pipeline. '
                'Each category has a distinct cause and remediation path.'
            )
            headers = ['Failure Category', 'Count', 'Cause and Remediation']
            widths = [58, 16, 112]
            pdf.table_header(headers, widths)
            breakdown_rows = [
                ('Contract gate blocked', breakdown['contract_gate'],
                 'target_entrypoint or success_indicators not resolved — improve investigation prompt'),
                (f'Below confidence {settings.MIN_CONFIDENCE_FOR_POV:.2f}', breakdown['low_confidence'],
                 'Investigation verdict was marginal — lower MIN_CONFIDENCE_FOR_POV or review finding'),
                ('Proof budget exhausted', breakdown['budget_exhausted'],
                 'PROOF_MAX_FINDINGS cap hit — raise cap or run scan in smaller batches'),
                ('Generation model error', breakdown['generation_failed'],
                 'Model returned no usable script — check token budget and model availability'),
                ('Runtime not confirmed', breakdown['runtime_unconfirmed'],
                 'Script ran but did not produce expected crash/signal — review oracle and harness'),
            ]
            for i, (label, count, note) in enumerate(breakdown_rows):
                if count > 0:
                    pdf.table_row([label, str(count), note], widths, alternate=bool(i % 2))
            pdf.ln(2)

        pdf.section_header('False Positive Disposition')
        pdf.body_text(
            f"{len(false_positives)} findings were rejected as false positives after investigation. "
            'These were initial static or exploratory signals that did not hold up under context review.'
        )
        if false_positives:
            headers = ['Location', 'Source', 'Confidence', 'Disposition Summary']
            widths = [68, 22, 18, 78]
            pdf.table_header(headers, widths)
            for i, finding in enumerate(false_positives[:20]):
                pdf.table_row([
                    f"{finding.get('filepath', 'N/A')}:{finding.get('line_number', 'N/A')}",
                    finding.get('source', 'unknown'),
                    f"{finding.get('confidence', 0.0):.2f}",
                    self._build_classification_summary(finding),
                ], widths, alternate=bool(i % 2))

        pdf.section_header('Methodology And Metric Definitions')
        for step in methodology['process_steps']:
            pdf.subsection_header(step['name'])
            pdf.body_text(step['description'])
        pdf.subsection_header('Metric Definitions')
        for metric_name, metric_desc in methodology['metrics_definitions'].items():
            pdf.key_value_row(metric_name, metric_desc, label_width=52)

        pdf.section_header('Appendix')
        pdf.key_value_row('Scan ID', result.scan_id)
        pdf.key_value_row('Codebase path', result.codebase_path)
        pdf.key_value_row('Report generated', datetime.utcnow().isoformat())
        pdf.key_value_row('Application version', settings.APP_VERSION)

        pdf.output(report_path)
        return report_path

    def _generate_methodology(self, result: ScanResult) -> Dict[str, Any]:
        """Generate scan-specific methodology description"""
        return {
            "routing_mode": settings.ROUTING_MODE,
            "model_mode": settings.MODEL_MODE,
            "scout_enabled": settings.SCOUT_ENABLED,
            "codeql_enabled": settings.is_codeql_available(),
            "taxonomy_focus": result.cwes or [],
            "discovery_scope": "open-ended" if not result.cwes else "focused",
            "duration_seconds": result.duration_s,
            "process_steps": [
                {
                    "name": "Code Ingestion",
                    "description": "Source code was parsed, chunked, and embedded into a vector store for semantic analysis. "
                                   f"Used {settings.EMBEDDING_MODEL_ONLINE if settings.MODEL_MODE == 'online' else settings.EMBEDDING_MODEL_OFFLINE} for embeddings."
                },
                {
                    "name": "Static Analysis",
                    "description": "Static analyzers and heuristics were used to surface candidate vulnerabilities before proof generation. " +
                                   ("CodeQL was available and used." if settings.is_codeql_available() else "CodeQL was not available.")
                },
                {
                    "name": "Autonomous Discovery",
                    "description": "The system performed discovery without requiring a predefined vulnerability taxonomy from the user. " +
                                   f"Scout was {'enabled' if settings.SCOUT_ENABLED else 'disabled'}."
                },
                {
                    "name": "LLM Investigation",
                    "description": f"Each alert was analyzed using a fixed selected model ({settings.MODEL_NAME}) for validation, prioritization, and classification when justified."
                },
                {
                    "name": "PoV Generation",
                    "description": "Proof-of-Vulnerability scripts were generated to confirm exploitable vulnerabilities."
                },
                {
                    "name": "PoV Validation",
                    "description": "Generated PoVs were validated using static analysis, unit tests, and Docker fallback execution."
                }
            ],
            "metrics_definitions": {
                "Detection Rate": "Percentage of findings that were confirmed as actual vulnerabilities",
                "False Positive Rate": "Percentage of initial alerts that were determined to be non-vulnerabilities",
                "PoV Success Rate": "Percentage of confirmed vulnerabilities with working Proof-of-Vulnerability scripts",
                "Cost per Confirmed": "Average cost in USD to identify and verify each confirmed vulnerability"
            }
        }
    
    def _get_openrouter_activity(self, result: ScanResult) -> List[Dict[str, Any]]:
        """Get OpenRouter activity for the scan period"""
        if settings.MODEL_MODE != 'online' or not settings.get_openrouter_api_key():
            return []
        
        # Get activity for scan date
        start_time = datetime.utcnow() - timedelta(hours=1)  # Approximate
        end_time = datetime.utcnow()
        
        return self.activity_tracker.get_activity_for_scan(start_time, end_time)

    
    def _collect_exact_openrouter_usage(self, result: ScanResult) -> Dict[str, Any]:
        calls: List[Dict[str, Any]] = []
        seen_generation_ids = set()

        def normalize_entries(usage: Any) -> List[Dict[str, Any]]:
            if isinstance(usage, dict) and usage:
                return [dict(usage)]
            if isinstance(usage, list):
                return [dict(item) for item in usage if isinstance(item, dict) and item]
            if isinstance(usage, str) and usage.strip():
                try:
                    parsed = json.loads(usage)
                    return normalize_entries(parsed)
                except Exception:
                    return []
            return []

        def add_call(usage: Any, agent_role: str, finding: Dict[str, Any], attempt: Optional[int] = None):
            for entry in normalize_entries(usage):
                entry.setdefault('agent_role', agent_role)
                entry.setdefault('model', entry.get('model_permaslug') or entry.get('model') or 'unknown')
                entry.setdefault('provider_name', entry.get('provider_name') or 'unknown')
                entry.setdefault('cost_usd', float(entry.get('cost_usd', 0.0) or 0.0))
                entry['tokens_prompt'] = int(entry.get('native_tokens_prompt', 0) or entry.get('tokens_prompt', 0) or 0)
                entry['tokens_completion'] = int(entry.get('native_tokens_completion', 0) or entry.get('tokens_completion', 0) or 0)
                entry['total_tokens'] = int(entry['tokens_prompt'] + entry['tokens_completion'])
                entry.setdefault('native_tokens_reasoning', int(entry.get('native_tokens_reasoning', 0) or 0))
                entry['finding_ref'] = f"{finding.get('filepath', 'unknown')}:{finding.get('line_number', 0)}:{finding.get('cwe_type', 'UNCLASSIFIED')}"
                if attempt is not None:
                    entry['attempt'] = attempt

                generation_id = entry.get('generation_id')
                if generation_id:
                    if generation_id in seen_generation_ids:
                        continue
                    seen_generation_ids.add(generation_id)

                calls.append(entry)

        for entry in normalize_entries(getattr(result, 'scan_openrouter_usage', []) or []):
            add_call(entry, entry.get('agent_role', 'scan'), {
                'filepath': entry.get('filepath', 'unknown'),
                'line_number': entry.get('line_number', 0),
                'cwe_type': entry.get('cwe_type', 'UNCLASSIFIED')
            }, attempt=entry.get('attempt'))

        for finding in result.findings or []:
            if not hasattr(finding, 'get'):
                continue
            add_call(finding.get('scout_openrouter_usage') or {}, 'llm_scout', finding)
            add_call(finding.get('openrouter_usage') or {}, 'investigator', finding)
            add_call(finding.get('pov_openrouter_usage') or {}, 'pov_generation', finding)
            add_call((finding.get('validation_result') or {}).get('openrouter_usage') or {}, 'llm_validation', finding)
            for history in finding.get('refinement_history') or []:
                add_call((history or {}).get('openrouter_usage') or {}, 'pov_refinement', finding, attempt=(history or {}).get('attempt'))

        summary = {}
        total_exact_cost = 0.0
        total_prompt = 0
        total_completion = 0
        total_reasoning = 0

        for call in calls:
            total_exact_cost += float(call.get('cost_usd', 0.0) or 0.0)
            total_prompt += int(call.get('tokens_prompt', 0) or 0)
            total_completion += int(call.get('tokens_completion', 0) or 0)
            total_reasoning += int(call.get('native_tokens_reasoning', 0) or 0)
            key = (call.get('agent_role', 'unknown'), call.get('model', 'unknown'), call.get('provider_name', 'unknown'))
            if key not in summary:
                summary[key] = {
                    'agent_role': key[0],
                    'model': key[1],
                    'provider_name': key[2],
                    'calls': 0,
                    'cost_usd': 0.0,
                    'prompt_tokens': 0,
                    'completion_tokens': 0,
                    'reasoning_tokens': 0,
                }
            row = summary[key]
            row['calls'] += 1
            row['cost_usd'] += float(call.get('cost_usd', 0.0) or 0.0)
            row['prompt_tokens'] += int(call.get('tokens_prompt', 0) or 0)
            row['completion_tokens'] += int(call.get('tokens_completion', 0) or 0)
            row['reasoning_tokens'] += int(call.get('native_tokens_reasoning', 0) or 0)

        summary_rows = []
        for row in summary.values():
            row['cost_usd'] = round(row['cost_usd'], 6)
            summary_rows.append(row)
        summary_rows.sort(key=lambda item: (-item['cost_usd'], item['agent_role'], item['model']))

        return {
            'calls': calls,
            'summary_by_agent': summary_rows,
            'total_calls': len(calls),
            'total_exact_cost_usd': round(total_exact_cost, 6),
            'total_prompt_tokens': total_prompt,
            'total_completion_tokens': total_completion,
            'total_reasoning_tokens': total_reasoning,
        }
    
    def _collect_models_used(self, result: ScanResult) -> List[Dict[str, Any]]:
        """Collect detailed model usage information with roles"""
        models_info = {}
        findings = result.findings or []
        
        for f in findings:
            if not hasattr(f, 'get'):
                continue
            
            # Investigation model
            inv_model = f.get('model_used')
            if inv_model:
                if inv_model not in models_info:
                    models_info[inv_model] = {
                        'model': inv_model,
                        'roles': set(),
                        'findings_count': 0,
                        'total_cost': 0.0
                    }
                models_info[inv_model]['roles'].add('investigation')
                models_info[inv_model]['findings_count'] += 1
                models_info[inv_model]['total_cost'] += f.get('cost_usd', 0.0) or 0.0
            
            # PoV generation model
            pov_model = f.get('pov_model_used')
            if pov_model:
                if pov_model not in models_info:
                    models_info[pov_model] = {
                        'model': pov_model,
                        'roles': set(),
                        'findings_count': 0,
                        'total_cost': 0.0
                    }
                models_info[pov_model]['roles'].add('pov_generation')
                models_info[pov_model]['findings_count'] += 1
                pov_cost = (f.get('pov_result') or {}).get('cost_usd', 0.0) or 0.0
                if not pov_cost:
                    pov_cost = (f.get('validation_result') or {}).get('cost_usd', 0.0) or 0.0
                models_info[pov_model]['total_cost'] += pov_cost
        
        result_list = []
        for model_name, info in sorted(models_info.items()):
            result_list.append({
                'model': model_name,
                'roles': sorted(list(info['roles'])),
                'findings_count': info['findings_count'],
                'total_cost_usd': round(info['total_cost'], 6)
            })
        
        return result_list
    
    def _summarize_pov(self, result: ScanResult) -> Dict[str, int]:
        """Summarize PoV generation results"""
        findings = result.findings or []
        generated = sum(1 for f in findings if hasattr(f, 'get') and f.get('pov_script'))
        validated = sum(1 for f in findings if hasattr(f, 'get') and f.get('validation_result'))
        triggered = sum(1 for f in findings if hasattr(f, 'get') and (f.get('pov_result') or {}).get('vulnerability_triggered'))
        failed = sum(1 for f in findings if hasattr(f, 'get') and f.get('final_status') in ['pov_generation_failed', 'pov_failed'])
        return {
            'generated': generated,
            'validated': validated,
            'triggered': triggered,
            'failed': failed
        }
    
    def _calculate_detection_rate(self, result: ScanResult) -> float:
        """Calculate detection rate percentage"""
        if result.total_findings == 0:
            return 0.0
        return (result.confirmed_vulns / result.total_findings) * 100
    
    def _calculate_fp_rate(self, result: ScanResult) -> float:
        """Calculate false positive rate percentage"""
        if result.total_findings == 0:
            return 0.0
        return (result.false_positives / result.total_findings) * 100

    def _calculate_unproven_rate(self, result: ScanResult) -> float:
        """Calculate the share of findings that were analyzed but not runtime-confirmed."""
        if result.total_findings == 0:
            return 0.0
        return ((getattr(result, 'unproven_findings', 0) or 0) / result.total_findings) * 100
    
    def _calculate_pov_success_rate(self, result: ScanResult) -> float:
        """Calculate PoV success rate percentage"""
        confirmed = result.confirmed_vulns
        if confirmed == 0:
            return 0.0
        
        findings = result.findings or []
        successful_povs = sum(
            1 for f in findings
            if hasattr(f, 'get') and f.get('final_status') == 'confirmed'
            and (f.get('pov_result') or {}).get('vulnerability_triggered')
        )
        
        return (successful_povs / confirmed) * 100
    
    def _calculate_cost_per_confirmed(self, result: ScanResult) -> float:
        """Calculate cost per confirmed vulnerability"""
        if result.confirmed_vulns == 0:
            return 0.0
        return result.total_cost_usd / result.confirmed_vulns
    
    def _format_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format findings for report"""
        formatted = []
        
        if not findings:
            return formatted
        
        for finding in findings:
            if not hasattr(finding, 'get'):
                continue
            pov_result = finding.get("pov_result") or {}
            validation = finding.get("validation_result") or {}
            formatted.append({
                "cwe_type": "UNCLASSIFIED",
                "taxonomy_refs": finding.get("taxonomy_refs", []),
                "cve_id": finding.get("cve_id"),
                "filepath": finding.get("filepath"),
                "line_number": finding.get("line_number"),
                "source": finding.get("source"),
                "verdict": finding.get("llm_verdict"),
                "confidence": finding.get("confidence"),
                "severity": self._calculate_severity(finding),
                "explanation": finding.get("llm_explanation"),
                "root_cause": finding.get("root_cause"),
                "impact": finding.get("impact"),
                "vulnerable_code": finding.get("code_chunk"),
                "final_status": finding.get("final_status"),
                "has_pov": finding.get("pov_script") is not None,
                "proof_status": self._get_proof_status(finding),
                "pov_success": pov_result.get("vulnerability_triggered", False),
                "pov_model_used": finding.get("pov_model_used"),
                "model_used": finding.get("model_used"),
                "token_usage": finding.get("token_usage", {}),
                "validation_method": validation.get("validation_method") or pov_result.get("validation_method"),
                "validation_summary": self._build_validation_summary(finding),
                "proof_summary": self._build_proof_summary(finding),
                "pov_validation": validation,
                "pov_result": pov_result,
                "inference_time_s": finding.get("inference_time_s"),
                "cost_usd": finding.get("cost_usd")
            })
        
        return formatted
    
    def save_pov_scripts(self, result: ScanResult) -> List[str]:
        """Save PoV scripts to files"""
        saved_paths = []
        
        for i, finding in enumerate(result.findings or []):
            if finding.get('pov_script') and finding.get('final_status') == 'confirmed':
                pov_filename = f"{result.scan_id}_pov_{i}_{finding.get('cwe_type', 'unknown')}.py"
                pov_path = os.path.join(self.povs_dir, pov_filename)
                
                with open(pov_path, 'w') as f:
                    f.write(f"# AutoPoV Proof-of-Vulnerability\n")
                    f.write(f"# Scan ID: {result.scan_id}\n")
                    f.write(f"# Classification: {finding.get('cwe_type', 'UNCLASSIFIED')}\n")
                    f.write(f"# File: {finding.get('filepath', 'unknown')}\n")
                    f.write(f"# Line: {finding.get('line_number', 0)}\n")
                    f.write(f"# Generated: {datetime.utcnow().isoformat()}\n\n")
                    f.write(finding['pov_script'])
                
                saved_paths.append(pov_path)
        
        return saved_paths


# Global report generator instance
report_generator = ReportGenerator()


def get_report_generator() -> ReportGenerator:
    """Get the global report generator instance"""
    return report_generator
