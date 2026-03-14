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
    """Sanitize any value to a plain latin-1-safe string for fpdf core fonts."""
    if text is None:
        return ""
    s = str(text)
    # Replace common problematic characters
    replacements = {
        "\u2019": "'", "\u2018": "'", "\u201c": '"', "\u201d": '"',
        "\u2013": "-", "\u2014": "-", "\u2022": "-", "\u2026": "...",
        "\u00e9": "e", "\u00e8": "e", "\u00ea": "e", "\u00eb": "e",
        "\u00e0": "a", "\u00e1": "a", "\u00e2": "a", "\u00e3": "a",
        "\u00f3": "o", "\u00f2": "o", "\u00f4": "o", "\u00f5": "o",
        "\u00fa": "u", "\u00f9": "u", "\u00fb": "u",
        "\u00ed": "i", "\u00ec": "i", "\u00ee": "i",
        "\u00f1": "n", "\u00e7": "c",
    }
    for ch, rep in replacements.items():
        s = s.replace(ch, rep)
    # Strip any remaining non-latin-1 characters
    s = s.encode("latin-1", errors="replace").decode("latin-1")
    if max_len and len(s) > max_len:
        s = s[:max_len - 3] + "..."
    return s


class ProfessionalPDFReport(FPDF):
    """Professional PDF report with modern design"""
    
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        
    def header(self):
        """Professional header with branding"""
        # Logo/Brand area
        self.set_fill_color(30, 41, 59)  # Dark slate
        self.rect(0, 0, 210, 25, 'F')
        
        self.set_font('Arial', 'B', 16)
        self.set_text_color(255, 255, 255)
        self.set_xy(15, 8)
        self.cell(0, 10, 'AutoPoV Security Scan Report', 0, 0, 'L')
        
        self.set_font('Arial', '', 10)
        self.set_text_color(200, 200, 200)
        self.set_xy(-50, 8)
        self.cell(0, 10, datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'), 0, 0, 'R')
        self.ln(20)
    
    def footer(self):
        """Professional footer"""
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()} | AutoPoV v{settings.APP_VERSION} | Confidential', 0, 0, 'C')
    
    def section_header(self, title: str, icon: str = ""):
        """Add styled section header"""
        self.set_font('Arial', 'B', 14)
        self.set_text_color(30, 41, 59)
        self.set_fill_color(241, 245, 249)
        self.cell(0, 12, f"{icon}  {title}" if icon else title, 0, 1, 'L', True)
        self.ln(3)
    
    def subsection_header(self, title: str):
        """Add subsection header"""
        self.set_font('Arial', 'B', 12)
        self.set_text_color(51, 65, 85)
        self.cell(0, 8, title, 0, 1, 'L')
        self.ln(1)
    
    def body_text(self, text: str, bold: bool = False):
        """Add body text"""
        self.set_font('Arial', 'B' if bold else '', 10)
        self.set_text_color(75, 85, 99)
        self.multi_cell(0, 5, _safe(text))
        self.ln(2)
    
    def metric_card(self, label: str, value: str, color: Tuple[int, int, int] = (59, 130, 246)):
        """Add metric card"""
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font('Arial', 'B', 20)
        self.cell(40, 12, value, 0, 0, 'C', True)
        self.set_text_color(75, 85, 99)
        self.set_font('Arial', '', 9)
        self.cell(50, 12, label, 0, 1, 'L')
        self.ln(2)
    
    def table_header(self, headers: List[str], widths: List[int]):
        """Add styled table header"""
        self.set_font('Arial', 'B', 10)
        self.set_fill_color(51, 65, 85)
        self.set_text_color(255, 255, 255)
        for i, header in enumerate(headers):
            self.cell(widths[i], 8, header, 1, 0, 'C', True)
        self.ln()
        self.set_text_color(75, 85, 99)
    
    def table_row(self, cells: List[str], widths: List[int], alternate: bool = False):
        """Add table row with alternating colors"""
        if alternate:
            self.set_fill_color(248, 250, 252)
        else:
            self.set_fill_color(255, 255, 255)
        
        self.set_font('Arial', '', 9)
        for i, cell in enumerate(cells):
            self.cell(widths[i], 7, str(cell)[:30], 1, 0, 'L', True)
        self.ln()
    
    def code_block(self, code: str, max_lines: int = 30):
        """Add code block with styling"""
        self.set_fill_color(30, 41, 59)
        self.set_text_color(226, 232, 240)
        self.set_font('Courier', '', 8)
        
        lines = _safe(code).split('\n')[:max_lines]
        formatted_code = '\n'.join(lines)
        if len(_safe(code).split('\n')) > max_lines:
            formatted_code += "\n\n... [truncated for brevity]"
        
        self.multi_cell(0, 4, formatted_code, fill=True)
        self.ln(3)
    
    def info_box(self, title: str, content: str, border_color: Tuple[int, int, int] = (59, 130, 246)):
        """Add info box with border"""
        self.set_draw_color(*border_color)
        self.set_line_width(0.5)
        
        self.set_font('Arial', 'B', 10)
        self.set_text_color(30, 41, 59)
        self.cell(0, 6, title, 0, 1, 'L')
        
        self.set_font('Arial', '', 9)
        self.set_text_color(75, 85, 99)
        self.multi_cell(0, 5, content)
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
                    "total_source_files": language_info.get('total_files', 0)
                },
                "configuration": {
                    "model_mode": settings.MODEL_MODE,
                    "routing_mode": settings.ROUTING_MODE,
                    "auto_router_model": settings.AUTO_ROUTER_MODEL,
                    "cwes_checked": result.cwes,
            "discovery_scope": result.cwes if result.cwes else 'open-ended',
                    "scout_enabled": settings.SCOUT_ENABLED,
                    "codeql_enabled": settings.is_codeql_available(),
                }
            },
            "model_usage": {
                "models_used": models_used,
                "openrouter_activity": openrouter_activity,
                "total_cost_usd": result.total_cost_usd
            },
            "metrics": {
                "total_findings": result.total_findings,
                "confirmed_vulnerabilities": result.confirmed_vulns,
                "false_positives": result.false_positives,
                "failed_analyses": result.failed,
                "detection_rate_percent": round(self._calculate_detection_rate(result), 2),
                "false_positive_rate_percent": round(self._calculate_fp_rate(result), 2),
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
                "finding_id": f"{finding.get('cwe_type', 'UNKNOWN')}-{idx+1:03d}",
                
                "vulnerability": {
                    "cwe_id": finding.get('cwe_type', 'UNCLASSIFIED'),
                    "cwe_name": self._get_cwe_name(finding.get('cwe_type', '')),
                    "cve_id": finding.get('cve_id'),
                    "description": finding.get('llm_explanation', 'No description available'),
                    "root_cause": finding.get('root_cause', ''),
                    "impact": finding.get('impact', ''),
                    "severity": self._calculate_severity(finding),
                    "confidence": finding.get('confidence', 0.0),
                    "classification_status": 'mapped' if finding.get('cwe_type') and finding.get('cwe_type') != 'UNCLASSIFIED' else 'unclassified',
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
                    "refinement_attempts": len(finding.get('refinement_history', [])),
                    "refinement_history": finding.get('refinement_history', [])
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
        """Get human-readable CWE name"""
        cwe_names = {
            "CWE-22": "Path Traversal",
            "CWE-78": "OS Command Injection",
            "CWE-79": "Cross-site Scripting (XSS)",
            "CWE-89": "SQL Injection",
            "CWE-94": "Code Injection",
            "CWE-502": "Deserialization of Untrusted Data",
            "CWE-611": "XML External Entity (XXE) Injection",
            "CWE-200": "Information Exposure",
            "CWE-287": "Improper Authentication",
            "CWE-352": "Cross-Site Request Forgery (CSRF)",
            "CWE-416": "Use After Free",
            "CWE-119": "Buffer Overflow",
            "CWE-190": "Integer Overflow"
        }
        if not cwe_id or cwe_id == 'UNCLASSIFIED':
            return 'Unclassified / novel vulnerability'
        return cwe_names.get(cwe_id, f"{cwe_id} - Unknown Vulnerability Type")
    
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
        if finding.get('final_status') == 'skipped':
            return 'false_positive'
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

    def generate_pdf_report(self, result: ScanResult) -> str:
        """Generate professional PDF report"""
        if not FPDF_AVAILABLE:
            raise ReportGeneratorError("fpdf not available. Install fpdf2")
        
        report_path = os.path.join(self.results_dir, f"{result.scan_id}_report.pdf")
        pov_summary = self._summarize_pov(result)
        models_used = self._collect_models_used(result)
        openrouter_activity = self._get_openrouter_activity(result)
        methodology = self._generate_methodology(result)
        
        pdf = ProfessionalPDFReport()
        
        # ===== COVER PAGE =====
        pdf.add_page()
        pdf.set_fill_color(30, 41, 59)
        pdf.rect(0, 0, 210, 297, 'F')
        
        pdf.set_y(80)
        pdf.set_font('Arial', 'B', 32)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 20, 'Security Assessment Report', 0, 1, 'C')
        
        pdf.set_font('Arial', '', 14)
        pdf.set_text_color(156, 163, 175)
        pdf.cell(0, 10, 'Powered by AutoPoV', 0, 1, 'C')
        pdf.ln(20)
        
        pdf.set_font('Arial', '', 12)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 8, f'Scan ID: {result.scan_id}', 0, 1, 'C')
        pdf.cell(0, 8, f'Generated: {datetime.utcnow().strftime("%B %d, %Y at %H:%M UTC")}', 0, 1, 'C')
        pdf.cell(0, 8, f'Target: {os.path.basename(result.codebase_path)}', 0, 1, 'C')
        pdf.ln(10)
        
        # Key metrics on cover
        pdf.set_font('Arial', 'B', 16)
        pdf.set_text_color(34, 197, 94)
        pdf.cell(0, 10, f'{result.confirmed_vulns} Confirmed Vulnerabilities', 0, 1, 'C')
        
        # ===== EXECUTIVE SUMMARY =====
        pdf.add_page()
        pdf.section_header('Executive Summary')
        
        # Key findings summary
        pdf.subsection_header('Assessment Overview')
        # Extract repo name from codebase path
        codebase_name = result.codebase_path
        if '/' in codebase_name:
            parts = codebase_name.split('/')
            # Get last meaningful part (repo name)
            codebase_name = parts[-1] if parts[-1] else parts[-2] if len(parts) > 1 else codebase_name
        # Remove .git suffix if present
        if codebase_name.endswith('.git'):
            codebase_name = codebase_name[:-4]
        
        summary_text = (
            f"This security assessment analyzed '{codebase_name}' "
            f"for {'an open-ended vulnerability search' if not result.cwes else str(len(result.cwes)) + ' focused vulnerability classes'} using AutoPoV's hybrid "
            f"agentic framework. The scan completed in {result.duration_s:.1f} seconds "
            f"with a total cost of ${result.total_cost_usd:.4f} USD."
        )
        pdf.body_text(summary_text)
        
        # Metrics grid
        pdf.subsection_header('Key Metrics')
        metrics_data = [
            ('Total Findings', str(result.total_findings), (59, 130, 246)),
            ('Confirmed', str(result.confirmed_vulns), (34, 197, 94)),
            ('False Positives', str(result.false_positives), (245, 158, 11)),
            ('Failed', str(result.failed), (239, 68, 68))
        ]
        
        for label, value, color in metrics_data:
            pdf.metric_card(label, value, color)
        
        # Success rates
        pdf.ln(5)
        pdf.subsection_header('Success Metrics')
        pdf.body_text(
            f"Detection Rate: {self._calculate_detection_rate(result):.1f}% | "
            f"False Positive Rate: {self._calculate_fp_rate(result):.1f}% | "
            f"PoV Success Rate: {self._calculate_pov_success_rate(result):.1f}%"
        )
        
        # ===== MODEL USAGE =====
        pdf.add_page()
        pdf.section_header('AI Model Usage')
        
        # Use OpenRouter activity if available for actual model names
        if openrouter_activity:
            pdf.subsection_header('Actual Models Used (from OpenRouter)')
            headers = ['Model', 'Requests', 'Tokens', 'Cost (USD)']
            widths = [70, 30, 50, 40]
            pdf.table_header(headers, widths)
            
            for i, activity in enumerate(openrouter_activity[:15]):  # Limit to 15 entries
                cells = [
                    _safe(activity.get('model', 'N/A'), 28),
                    str(activity.get('requests', 0)),
                    f"{activity.get('prompt_tokens', 0) + activity.get('completion_tokens', 0):,}",
                    f"${activity.get('usage', 0):.6f}"
                ]
                pdf.table_row(cells, widths, alternate=(i % 2 == 1))
            
            pdf.ln(5)
            pdf.set_font('Arial', 'I', 9)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 6, f"Total API calls: {len(openrouter_activity)} | Data from OpenRouter activity API", 0, 1)
        
        # Show internal model tracking
        if models_used:
            pdf.ln(10)
            pdf.subsection_header('Internal Model Tracking')
            headers = ['Model/Router', 'Roles', 'Findings', 'Cost (USD)']
            widths = [70, 50, 30, 40]
            pdf.table_header(headers, widths)
            
            for i, model in enumerate(models_used):
                roles = ', '.join(model.get('roles', []))
                cells = [
                    _safe(model.get('model', 'N/A'), 25),
                    _safe(roles, 20),
                    str(model.get('findings_count', 0)),
                    f"${model.get('total_cost_usd', 0):.6f}"
                ]
                pdf.table_row(cells, widths, alternate=(i % 2 == 1))
        
        # ===== CONFIRMED VULNERABILITIES =====
        if result.confirmed_vulns > 0:
            pdf.add_page()
            pdf.section_header('Confirmed Vulnerabilities')
            
            confirmed = [f for f in (result.findings or []) if f.get('final_status') == 'confirmed']
            
            for i, finding in enumerate(confirmed, 1):
                if pdf.get_y() > 250:
                    pdf.add_page()
                
                # Vulnerability header
                cwe = finding.get('cwe_type', 'UNCLASSIFIED')
                cve = finding.get('cve_id')
                pdf.set_font('Arial', 'B', 12)
                pdf.set_text_color(239, 68, 68)
                heading = f"Finding #{i}: {cwe}" + (f" | {cve}" if cve else '')
                pdf.cell(0, 8, _safe(heading), 0, 1)
                
                # Location
                pdf.set_font('Arial', '', 10)
                pdf.set_text_color(75, 85, 99)
                filepath = finding.get('filepath', 'N/A')
                line = finding.get('line_number', 'N/A')
                pdf.cell(0, 6, _safe(f"Location: {filepath}:{line}"), 0, 1)
                
                # Confidence and model
                confidence = finding.get('confidence', 0)
                model_used = finding.get('model_used', 'N/A')
                pdf.cell(0, 6, _safe(f"Confidence: {confidence:.2f} | Detected by: {model_used}"), 0, 1)
                pdf.cell(0, 6, _safe(f"Classification: {self._build_classification_summary(finding)}"), 0, 1)
                pdf.ln(2)
                
                # Explanation
                pdf.set_font('Arial', 'B', 10)
                pdf.set_text_color(51, 65, 85)
                pdf.cell(0, 6, 'Vulnerability Description:', 0, 1)
                pdf.set_font('Arial', '', 10)
                pdf.set_text_color(75, 85, 99)
                pdf.multi_cell(0, 5, _safe(finding.get('llm_explanation', 'No explanation available.')))
                if finding.get('root_cause'):
                    pdf.cell(0, 6, _safe(f"Root Cause: {finding.get('root_cause')}"), 0, 1)
                if finding.get('impact'):
                    pdf.cell(0, 6, _safe(f"Impact: {finding.get('impact')}"), 0, 1)
                contract = finding.get('exploit_contract') or {}
                if contract.get('goal'):
                    pdf.cell(0, 6, _safe(f"Exploit Goal: {contract.get('goal')}"), 0, 1)
                pdf.ln(3)
                
                # PoV Status and Validation Evidence
                pov_result = finding.get('pov_result') or {}
                validation = finding.get('validation_result') or {}
                
                triggered = pov_result.get('vulnerability_triggered', False)
                status_color = (34, 197, 94) if triggered else (245, 158, 11)
                status_text = "CONFIRMED - VULNERABILITY TRIGGERED" if triggered else "NOT TRIGGERED"
                
                pdf.set_font('Arial', 'B', 11)
                pdf.set_text_color(*status_color)
                pdf.cell(0, 7, f"Validation Result: {status_text}", 0, 1)
                
                # Validation details
                pdf.set_font('Arial', '', 10)
                pdf.set_text_color(75, 85, 99)
                
                validation_method = validation.get('validation_method') or pov_result.get('validation_method')
                if validation_method:
                    pdf.cell(0, 6, _safe(f"Validation Method: {validation_method}"), 0, 1)
                
                if validation.get('execution_time_s'):
                    pdf.cell(0, 6, f"Execution Time: {validation.get('execution_time_s'):.2f} seconds", 0, 1)
                
                pdf.ln(2)
                
                # Validation Evidence/Reasoning
                pdf.set_font('Arial', 'B', 10)
                pdf.set_text_color(51, 65, 85)
                pdf.cell(0, 6, 'Validation Evidence:', 0, 1)
                pdf.set_font('Arial', '', 10)
                pdf.set_text_color(75, 85, 99)
                
                if triggered:
                    evidence_text = (
                        "The PoV script successfully demonstrated the vulnerability by executing "
                        "exploitation code that confirmed the security weakness. "
                    )
                    if validation.get('stdout'):
                        evidence_text += "The execution produced expected output indicating successful exploitation."
                else:
                    evidence_text = (
                        "The PoV script did not trigger the vulnerability. This could mean:\n"
                        "- The vulnerability requires specific conditions not met in the test environment\n"
                        "- The vulnerability is context-dependent and the PoV needs refinement\n"
                        "- The finding may be a false positive that requires manual review"
                    )
                pdf.multi_cell(0, 5, _safe(evidence_text))
                
                # Show stdout/stderr if available
                if validation.get('stdout') or validation.get('stderr') or pov_result.get('stdout') or pov_result.get('stderr'):
                    pdf.ln(2)
                    pdf.set_font('Arial', 'B', 10)
                    pdf.set_text_color(51, 65, 85)
                    pdf.cell(0, 6, 'Execution Output:', 0, 1)
                    
                    if validation.get('stdout'):
                        pdf.set_font('Arial', 'I', 9)
                        pdf.cell(0, 5, 'Standard Output:', 0, 1)
                        pdf.code_block(validation.get('stdout'), max_lines=10)
                    
                    if validation.get('stderr'):
                        pdf.set_font('Arial', 'I', 9)
                        pdf.cell(0, 5, 'Standard Error:', 0, 1)
                        pdf.code_block(validation.get('stderr'), max_lines=10)
                
                # PoV Script (if available)
                if finding.get('pov_script'):
                    pdf.ln(2)
                    pdf.set_font('Arial', 'B', 10)
                    pdf.set_text_color(51, 65, 85)
                    pdf.cell(0, 6, 'Proof-of-Vulnerability Script:', 0, 1)
                    pdf.code_block(finding['pov_script'], max_lines=20)
                
                pdf.ln(5)
        
        # ===== FALSE POSITIVES =====
        pdf.add_page()
        pdf.section_header('False Positives Analysis')
        
        if result.false_positives > 0:
            false_positives = [f for f in (result.findings or []) if f.get('final_status') == 'skipped']
            
            pdf.body_text(
                f"The following {len(false_positives)} finding(s) were classified as false positives "
                f"after automated analysis. These represent initial alerts that were determined "
                f"not to be actual vulnerabilities."
            )
            pdf.ln(3)
            
            for i, finding in enumerate(false_positives, 1):
                if pdf.get_y() > 240:
                    pdf.add_page()
                
                cwe = finding.get('cwe_type', 'Unknown')
                pdf.set_font('Arial', 'B', 12)
                pdf.set_text_color(245, 158, 11)
                pdf.cell(0, 8, _safe(f"False Positive #{i}: {cwe}"), 0, 1)
                
                pdf.set_font('Arial', '', 10)
                pdf.set_text_color(75, 85, 99)
                pdf.cell(0, 6, _safe(f"File: {finding.get('filepath', 'N/A')}"), 0, 1)
                pdf.cell(0, 6, _safe(f"Line: {finding.get('line_number', 'N/A')}"), 0, 1)
                
                confidence = finding.get('confidence', 0)
                model_used = finding.get('model_used', 'N/A')
                pdf.cell(0, 6, _safe(f"Initial Confidence: {confidence:.2f} | Analyzed by: {model_used}"), 0, 1)
                pdf.ln(2)
                
                pdf.set_font('Arial', 'B', 10)
                pdf.set_text_color(51, 65, 85)
                pdf.cell(0, 6, 'Why this was marked as false positive:', 0, 1)
                pdf.set_font('Arial', '', 10)
                pdf.set_text_color(75, 85, 99)
                pdf.multi_cell(0, 5, _safe(finding.get('llm_explanation', 'No explanation available.')))
                
                # Show the code that was flagged
                if finding.get('code_chunk'):
                    pdf.ln(2)
                    pdf.set_font('Arial', 'B', 10)
                    pdf.set_text_color(51, 65, 85)
                    pdf.cell(0, 6, 'Flagged Code:', 0, 1)
                    pdf.code_block(finding.get('code_chunk'), max_lines=15)
                
                pdf.ln(5)
        else:
            pdf.body_text("No false positives were identified in this scan.")
        
        # ===== METHODOLOGY =====
        pdf.add_page()
        pdf.section_header('Methodology')
        
        # Scan-specific methodology
        pdf.subsection_header('Scan Configuration')
        config_text = (
            f"This assessment used the following configuration:\n\n"
            f"- Routing Mode: {methodology['routing_mode']}\n"
            f"- Model Mode: {methodology['model_mode']}\n"
            f"- Scout Enabled: {methodology['scout_enabled']}\n"
            f"- CodeQL Enabled: {methodology['codeql_enabled']}\n"
            f"- CWEs Checked: {', '.join(methodology['cwes_checked'])}\n"
            f"- Duration: {methodology['duration_seconds']:.1f} seconds"
        )
        pdf.body_text(config_text)
        
        # Process flow
        pdf.subsection_header('Assessment Process')
        for i, step in enumerate(methodology['process_steps'], 1):
            pdf.set_font('Arial', 'B', 10)
            pdf.set_text_color(59, 130, 246)
            pdf.cell(0, 6, f"Step {i}: {step['name']}", 0, 1)
            pdf.set_font('Arial', '', 10)
            pdf.set_text_color(75, 85, 99)
            pdf.multi_cell(0, 5, step['description'])
            pdf.ln(2)
        
        # Metrics definitions
        pdf.subsection_header('Metrics Definitions')
        for metric_name, metric_desc in methodology['metrics_definitions'].items():
            pdf.set_font('Arial', 'B', 10)
            pdf.set_text_color(51, 65, 85)
            pdf.cell(0, 6, f"{metric_name}:", 0, 1)
            pdf.set_font('Arial', '', 10)
            pdf.set_text_color(75, 85, 99)
            pdf.multi_cell(0, 5, metric_desc)
            pdf.ln(1)
        
        # ===== APPENDIX =====
        pdf.add_page()
        pdf.section_header('Appendix')
        
        pdf.subsection_header('Technical Details')
        tech_details = (
            f"Scan ID: {result.scan_id}\n"
            f"Codebase Path: {result.codebase_path}\n"
            f"AutoPoV Version: {settings.APP_VERSION}\n"
            f"Report Generated: {datetime.utcnow().isoformat()}"
        )
        pdf.body_text(tech_details)
        
        pdf.output(report_path)
        return report_path
    
    def _generate_methodology(self, result: ScanResult) -> Dict[str, Any]:
        """Generate scan-specific methodology description"""
        return {
            "routing_mode": settings.ROUTING_MODE,
            "model_mode": settings.MODEL_MODE,
            "scout_enabled": settings.SCOUT_ENABLED,
            "codeql_enabled": settings.is_codeql_available(),
            "cwes_checked": result.cwes,
            "discovery_scope": result.cwes if result.cwes else 'open-ended',
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
                    "description": "The system performed open-ended vulnerability discovery and only treated CWE selection as an optional focus filter. " +
                                   f"Scout was {'enabled' if settings.SCOUT_ENABLED else 'disabled'}."
                },
                {
                    "name": "LLM Investigation",
                    "description": f"Each alert was analyzed using {settings.ROUTING_MODE} routing via {settings.AUTO_ROUTER_MODEL} "
                                   "for validation and classification."
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
                "cwe_type": finding.get("cwe_type") or "UNCLASSIFIED",
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
                    f.write(f"# CWE: {finding.get('cwe_type', 'unknown')}\n")
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
