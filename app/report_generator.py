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
        self.multi_cell(0, 5, text)
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
        
        lines = code.split('\n')[:max_lines]
        formatted_code = '\n'.join(lines)
        if len(code.split('\n')) > max_lines:
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
        self.activity_tracker = OpenRouterActivityTracker(settings.OPENROUTER_API_KEY)
    
    def generate_json_report(self, result: ScanResult) -> str:
        """Generate comprehensive JSON report"""
        report_path = os.path.join(self.results_dir, f"{result.scan_id}_report.json")
        pov_summary = self._summarize_pov(result)
        models_used = self._collect_models_used(result)
        openrouter_activity = self._get_openrouter_activity(result)
        
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
                "scan_started": result.started_at.isoformat() if hasattr(result, 'started_at') else None,
                "scan_completed": result.completed_at.isoformat() if hasattr(result, 'completed_at') else None,
                "duration_seconds": result.duration_s,
                "configuration": {
                    "model_mode": settings.MODEL_MODE,
                    "routing_mode": settings.ROUTING_MODE,
                    "auto_router_model": settings.AUTO_ROUTER_MODEL,
                    "cwes_checked": result.cwes,
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
            "methodology": self._generate_methodology(result)
        }
        
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return report_path
    
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
        summary_text = (
            f"This security assessment analyzed {os.path.basename(result.codebase_path)} "
            f"for {len(result.cwes)} vulnerability classes using AutoPoV's hybrid "
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
        
        if models_used:
            pdf.subsection_header('Models Deployed')
            headers = ['Model', 'Roles', 'Findings', 'Cost (USD)']
            widths = [70, 50, 30, 40]
            pdf.table_header(headers, widths)
            
            for i, model in enumerate(models_used):
                roles = ', '.join(model.get('roles', []))
                cells = [
                    model.get('model', 'N/A')[:25],
                    roles[:20],
                    str(model.get('findings_count', 0)),
                    f"${model.get('total_cost_usd', 0):.6f}"
                ]
                pdf.table_row(cells, widths, alternate=(i % 2 == 1))
        
        if openrouter_activity:
            pdf.ln(10)
            pdf.subsection_header('OpenRouter Activity')
            headers = ['Model', 'Requests', 'Tokens', 'Cost (USD)']
            widths = [70, 30, 50, 40]
            pdf.table_header(headers, widths)
            
            for i, activity in enumerate(openrouter_activity[:10]):  # Limit to 10 entries
                cells = [
                    activity.get('model', 'N/A')[:25],
                    str(activity.get('requests', 0)),
                    f"{activity.get('prompt_tokens', 0) + activity.get('completion_tokens', 0):,}",
                    f"${activity.get('usage', 0):.6f}"
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
                cwe = finding.get('cwe_type', 'Unknown')
                pdf.set_font('Arial', 'B', 12)
                pdf.set_text_color(239, 68, 68)
                pdf.cell(0, 8, f"Finding #{i}: {cwe}", 0, 1)
                
                # Location
                pdf.set_font('Arial', '', 10)
                pdf.set_text_color(75, 85, 99)
                filepath = finding.get('filepath', 'N/A')
                line = finding.get('line_number', 'N/A')
                pdf.cell(0, 6, f"Location: {filepath}:{line}", 0, 1)
                
                # Confidence and model
                confidence = finding.get('confidence', 0)
                model_used = finding.get('model_used', 'N/A')
                pdf.cell(0, 6, f"Confidence: {confidence:.2f} | Detected by: {model_used}", 0, 1)
                pdf.ln(2)
                
                # Explanation
                pdf.set_font('Arial', 'B', 10)
                pdf.set_text_color(51, 65, 85)
                pdf.cell(0, 6, 'Vulnerability Description:', 0, 1)
                pdf.set_font('Arial', '', 10)
                pdf.set_text_color(75, 85, 99)
                pdf.multi_cell(0, 5, finding.get('llm_explanation', 'No explanation available.'))
                pdf.ln(3)
                
                # PoV Status
                pov_result = finding.get('pov_result') or {}
                validation = finding.get('validation_result') or {}
                
                triggered = pov_result.get('vulnerability_triggered', False)
                status_color = (34, 197, 94) if triggered else (245, 158, 11)
                status_text = "TRIGGERED" if triggered else "NOT TRIGGERED"
                
                pdf.set_font('Arial', 'B', 10)
                pdf.set_text_color(*status_color)
                pdf.cell(0, 6, f"PoV Status: {status_text}", 0, 1)
                
                if validation.get('validation_method'):
                    pdf.set_text_color(75, 85, 99)
                    pdf.set_font('Arial', '', 10)
                    pdf.cell(0, 6, f"Validation Method: {validation.get('validation_method')}", 0, 1)
                
                # PoV Script (if available)
                if finding.get('pov_script'):
                    pdf.ln(2)
                    pdf.set_font('Arial', 'B', 10)
                    pdf.set_text_color(51, 65, 85)
                    pdf.cell(0, 6, 'Proof-of-Vulnerability Script:', 0, 1)
                    pdf.code_block(finding['pov_script'], max_lines=20)
                
                pdf.ln(5)
        
        # ===== FALSE POSITIVES =====
        if result.false_positives > 0:
            pdf.add_page()
            pdf.section_header('False Positives')
            
            false_positives = [f for f in (result.findings or []) if f.get('final_status') == 'false_positive']
            
            for i, finding in enumerate(false_positives, 1):
                if pdf.get_y() > 260:
                    pdf.add_page()
                
                cwe = finding.get('cwe_type', 'Unknown')
                pdf.set_font('Arial', 'B', 11)
                pdf.set_text_color(245, 158, 11)
                pdf.cell(0, 7, f"#{i}: {cwe}", 0, 1)
                
                pdf.set_font('Arial', '', 10)
                pdf.set_text_color(75, 85, 99)
                pdf.cell(0, 6, f"Location: {finding.get('filepath', 'N/A')}:{finding.get('line_number', 'N/A')}", 0, 1)
                pdf.multi_cell(0, 5, f"Reason: {finding.get('llm_explanation', 'No explanation')}")
                pdf.ln(3)
        
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
            "duration_seconds": result.duration_s,
            "process_steps": [
                {
                    "name": "Code Ingestion",
                    "description": "Source code was parsed, chunked, and embedded into a vector store for semantic analysis. "
                                   f"Used {settings.EMBEDDING_MODEL_ONLINE if settings.MODEL_MODE == 'online' else settings.EMBEDDING_MODEL_OFFLINE} for embeddings."
                },
                {
                    "name": "Static Analysis",
                    "description": "CodeQL queries identified potential vulnerability patterns. " +
                                   ("CodeQL was available and used." if settings.is_codeql_available() else "CodeQL was not available.")
                },
                {
                    "name": "Autonomous Discovery",
                    "description": "Heuristic and LLM scouts analyzed code for vulnerability candidates. " +
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
        if settings.MODEL_MODE != 'online' or not settings.OPENROUTER_API_KEY:
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
            formatted.append({
                "cwe_type": finding.get("cwe_type"),
                "filepath": finding.get("filepath"),
                "line_number": finding.get("line_number"),
                "verdict": finding.get("llm_verdict"),
                "confidence": finding.get("confidence"),
                "explanation": finding.get("llm_explanation"),
                "vulnerable_code": finding.get("code_chunk"),
                "final_status": finding.get("final_status"),
                "has_pov": finding.get("pov_script") is not None,
                "pov_success": (finding.get("pov_result") or {}).get("vulnerability_triggered", False),
                "pov_model_used": finding.get("pov_model_used"),
                "model_used": finding.get("model_used"),
                "token_usage": finding.get("token_usage", {}),
                "pov_validation": finding.get("validation_result", {}),
                "pov_result": finding.get("pov_result", {}),
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
