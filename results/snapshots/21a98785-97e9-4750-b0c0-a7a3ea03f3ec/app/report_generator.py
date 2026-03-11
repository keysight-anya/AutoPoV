"""
AutoPoV Report Generator Module
Generates PDF and JSON reports from scan results
"""

import os
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import asdict

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False

from app.config import settings
from app.scan_manager import ScanResult


class ReportGeneratorError(Exception):
    """Exception raised during report generation"""
    pass


class PDFReport(FPDF):
    """Custom PDF report class"""
    
    def header(self):
        """Header on each page"""
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'AutoPoV Security Scan Report', 0, 0, 'L')
        self.cell(0, 10, datetime.utcnow().strftime('%Y-%m-%d'), 0, 1, 'R')
        self.ln(5)
    
    def footer(self):
        """Footer on each page"""
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')
    
    def chapter_title(self, title):
        """Add chapter title"""
        self.set_font('Arial', 'B', 14)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 10, title, 0, 1, 'L', True)
        self.ln(4)
    
    def chapter_body(self, body):
        """Add chapter body text"""
        self.set_font('Arial', '', 11)
        self.multi_cell(0, 5, body)
        self.ln()
    
    def table_row(self, cells, widths=None, bold=False):
        """Add a table row"""
        self.set_font('Arial', 'B' if bold else '', 10)
        
        if widths is None:
            widths = [40] * len(cells)
        
        for i, cell in enumerate(cells):
            self.cell(widths[i], 7, str(cell), 1, 0, 'L')
        self.ln()


class ReportGenerator:
    """Generates scan reports"""
    
    def __init__(self):
        self.results_dir = settings.RESULTS_DIR
        self.povs_dir = settings.POVS_DIR
        os.makedirs(self.povs_dir, exist_ok=True)
    
    def generate_json_report(self, result: ScanResult) -> str:
        """
        Generate JSON report
        
        Args:
            result: Scan result
        
        Returns:
            Path to generated JSON file
        """
        report_path = os.path.join(self.results_dir, f"{result.scan_id}_report.json")
        
        report_data = {
            "report_metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "tool": "AutoPoV",
                "version": settings.APP_VERSION
            },
            "scan_summary": {
                "scan_id": result.scan_id,
                "status": result.status,
                "codebase": result.codebase_path,
                "model": result.model_name,
                "cwes_checked": result.cwes,
                "duration_seconds": result.duration_s,
                "total_cost_usd": result.total_cost_usd
            },
            "metrics": {
                "total_findings": result.total_findings,
                "confirmed_vulnerabilities": result.confirmed_vulns,
                "false_positives": result.false_positives,
                "failed_analyses": result.failed,
                "detection_rate": self._calculate_detection_rate(result),
                "false_positive_rate": self._calculate_fp_rate(result),
                "pov_success_rate": self._calculate_pov_success_rate(result)
            },
            "findings": self._format_findings(result.findings)
        }
        
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return report_path
    
    def generate_pdf_report(self, result: ScanResult) -> str:
        """
        Generate PDF report
        
        Args:
            result: Scan result
        
        Returns:
            Path to generated PDF file
        """
        if not FPDF_AVAILABLE:
            raise ReportGeneratorError("fpdf not available. Install fpdf2")
        
        report_path = os.path.join(self.results_dir, f"{result.scan_id}_report.pdf")
        
        pdf = PDFReport()
        pdf.add_page()
        
        # Cover Page
        pdf.set_font('Arial', 'B', 24)
        pdf.cell(0, 20, 'AutoPoV Security Scan Report', 0, 1, 'C')
        pdf.ln(10)
        
        pdf.set_font('Arial', '', 14)
        pdf.cell(0, 10, f'Scan ID: {result.scan_id}', 0, 1, 'C')
        pdf.cell(0, 10, f'Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}', 0, 1, 'C')
        pdf.ln(20)
        
        # Executive Summary
        pdf.chapter_title('Executive Summary')
        
        summary = f"""
This report presents the findings from an automated vulnerability scan using AutoPoV.

Scan Configuration:
- Model: {result.model_name}
- CWEs Checked: {', '.join(result.cwes)}
- Duration: {result.duration_s:.2f} seconds
- Total Cost: ${result.total_cost_usd:.4f} USD

Results Overview:
- Total Findings: {result.total_findings}
- Confirmed Vulnerabilities: {result.confirmed_vulns}
- False Positives: {result.false_positives}
- Failed Analyses: {result.failed}

Detection Rate: {self._calculate_detection_rate(result):.1f}%
False Positive Rate: {self._calculate_fp_rate(result):.1f}%
PoV Success Rate: {self._calculate_pov_success_rate(result):.1f}%
"""
        pdf.chapter_body(summary)
        
        # Metrics Table
        pdf.chapter_title('Metrics Summary')
        
        headers = ['Metric', 'Value']
        widths = [80, 60]
        pdf.table_row(headers, widths, bold=True)
        
        metrics = [
            ['Total Findings', str(result.total_findings)],
            ['Confirmed Vulnerabilities', str(result.confirmed_vulns)],
            ['False Positives', str(result.false_positives)],
            ['Failed Analyses', str(result.failed)],
            ['Detection Rate', f'{self._calculate_detection_rate(result):.1f}%'],
            ['False Positive Rate', f'{self._calculate_fp_rate(result):.1f}%'],
            ['PoV Success Rate', f'{self._calculate_pov_success_rate(result):.1f}%'],
            ['Total Cost (USD)', f'${result.total_cost_usd:.4f}'],
            ['Duration (seconds)', f'{result.duration_s:.2f}']
        ]
        
        for row in metrics:
            pdf.table_row(row, widths)
        
        pdf.ln(10)
        
        # Findings Details
        if result.findings:
            pdf.add_page()
            pdf.chapter_title('Confirmed Vulnerabilities')
            
            confirmed = [f for f in result.findings if f.get('final_status') == 'confirmed']
            
            if confirmed:
                for i, finding in enumerate(confirmed, 1):
                    pdf.set_font('Arial', 'B', 12)
                    pdf.cell(0, 10, f'Finding #{i}: {finding.get("cwe_type", "Unknown")}', 0, 1)
                    
                    pdf.set_font('Arial', '', 10)
                    pdf.cell(0, 6, f"File: {finding.get('filepath', 'N/A')}", 0, 1)
                    pdf.cell(0, 6, f"Line: {finding.get('line_number', 'N/A')}", 0, 1)
                    pdf.cell(0, 6, f"Confidence: {finding.get('confidence', 0):.2f}", 0, 1)
                    pdf.ln(2)
                    
                    pdf.set_font('Arial', 'B', 10)
                    pdf.cell(0, 6, 'Explanation:', 0, 1)
                    pdf.set_font('Arial', '', 10)
                    pdf.multi_cell(0, 5, finding.get('llm_explanation', 'N/A'))
                    pdf.ln(2)
                    
                    if finding.get('pov_script'):
                        pdf.set_font('Arial', 'B', 10)
                        pdf.cell(0, 6, 'PoV Script:', 0, 1)
                        pdf.set_font('Courier', '', 8)
                        
                        # Truncate if too long
                        pov = finding['pov_script']
                        if len(pov) > 2000:
                            pov = pov[:2000] + "\n... [truncated]"
                        
                        pdf.multi_cell(0, 4, pov)
                        pdf.ln(5)
                    
                    if i < len(confirmed):
                        pdf.ln(5)
            else:
                pdf.chapter_body('No confirmed vulnerabilities found.')
        
        # Methodology
        pdf.add_page()
        pdf.chapter_title('Methodology')
        
        methodology = """
AutoPoV uses a hybrid agentic framework combining static analysis with AI-powered 
vulnerability detection and Proof-of-Vulnerability (PoV) generation.

Scanning Process:
1. Code Ingestion: Source code is chunked and embedded into a vector store
2. Static Analysis: CodeQL queries identify potential vulnerability patterns
3. LLM Investigation: Each alert is analyzed by a language model for validation
4. PoV Generation: Python scripts are generated to confirm vulnerabilities
5. Docker Execution: PoVs run in isolated containers for safe verification

Metrics Definitions:
- Detection Rate: Percentage of known vulnerabilities correctly identified
- False Positive Rate: Percentage of alerts that are not real vulnerabilities  
- PoV Success Rate: Percentage of confirmed vulnerabilities with working PoVs
- Cost per Verified: Average cost to find and verify each vulnerability

Supported CWE Classes:
- CWE-119: Buffer Overflow
- CWE-89: SQL Injection
- CWE-416: Use After Free
- CWE-190: Integer Overflow
"""
        pdf.chapter_body(methodology)
        
        # Save PDF
        pdf.output(report_path)
        
        return report_path
    
    def save_pov_scripts(self, result: ScanResult) -> List[str]:
        """
        Save PoV scripts to files
        
        Args:
            result: Scan result
        
        Returns:
            List of saved PoV file paths
        """
        saved_paths = []
        
        for i, finding in enumerate(result.findings):
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
        
        # Count findings with successful PoV results
        successful_povs = sum(
            1 for f in result.findings
            if f.get('final_status') == 'confirmed'
            and f.get('pov_result', {}).get('vulnerability_triggered')
        )
        
        return (successful_povs / confirmed) * 100
    
    def _format_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format findings for report"""
        formatted = []
        
        for finding in findings:
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
                "pov_success": finding.get("pov_result", {}).get("vulnerability_triggered", False),
                "inference_time_s": finding.get("inference_time_s"),
                "cost_usd": finding.get("cost_usd")
            })
        
        return formatted


# Global report generator instance
report_generator = ReportGenerator()


def get_report_generator() -> ReportGenerator:
    """Get the global report generator instance"""
    return report_generator
