"""
AutoPoV Analysis Module
Analyzes scan results and generates benchmark summaries
"""

import os
import json
import csv
from typing import List, Dict, Any
from datetime import datetime
from dataclasses import dataclass
from collections import defaultdict

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

from app.config import settings


@dataclass
class BenchmarkResult:
    """Benchmark result for a single scan"""
    scan_id: str
    model_name: str
    total_findings: int
    confirmed_vulns: int
    false_positives: int
    failed: int
    total_cost_usd: float
    duration_s: float
    detection_rate: float
    fp_rate: float
    cost_per_confirmed: float


class BenchmarkAnalyzer:
    """Analyzes scan results for benchmarking"""
    
    def __init__(self, results_dir: str = None):
        self.results_dir = results_dir or settings.RESULTS_DIR
        self.runs_dir = settings.RUNS_DIR
    
    def load_scan_results(self) -> List[Dict[str, Any]]:
        """Load all scan results from CSV history"""
        results = []
        csv_path = os.path.join(self.runs_dir, "scan_history.csv")
        
        if not os.path.exists(csv_path):
            print(f"No scan history found at {csv_path}")
            return results
        
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                results.append(row)
        
        return results
    
    def load_json_result(self, scan_id: str) -> Dict[str, Any]:
        """Load a specific scan result from JSON"""
        json_path = os.path.join(self.runs_dir, f"{scan_id}.json")
        
        if not os.path.exists(json_path):
            return None
        
        with open(json_path, 'r') as f:
            return json.load(f)
    
    def calculate_metrics(self, result: Dict[str, Any]) -> BenchmarkResult:
        """Calculate benchmark metrics from a scan result"""
        total = int(result.get('total_findings', 0))
        confirmed = int(result.get('confirmed_vulns', 0))
        fp = int(result.get('false_positives', 0))
        failed = int(result.get('failed', 0))
        cost = float(result.get('total_cost_usd', 0))
        duration = float(result.get('duration_s', 0))
        
        # Calculate rates
        detection_rate = (confirmed / total * 100) if total > 0 else 0
        fp_rate = (fp / total * 100) if total > 0 else 0
        cost_per_confirmed = (cost / confirmed) if confirmed > 0 else 0
        
        return BenchmarkResult(
            scan_id=result.get('scan_id', ''),
            model_name=result.get('model_name', ''),
            total_findings=total,
            confirmed_vulns=confirmed,
            false_positives=fp,
            failed=failed,
            total_cost_usd=cost,
            duration_s=duration,
            detection_rate=detection_rate,
            fp_rate=fp_rate,
            cost_per_confirmed=cost_per_confirmed
        )
    
    def analyze_by_model(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze results grouped by model"""
        if PANDAS_AVAILABLE:
            return self._analyze_with_pandas(results)
        else:
            return self._analyze_without_pandas(results)
    
    def _analyze_with_pandas(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze using pandas"""
        df = pd.DataFrame(results)
        
        # Convert numeric columns
        numeric_cols = ['total_findings', 'confirmed_vulns', 'false_positives', 
                       'failed', 'total_cost_usd', 'duration_s']
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')
        
        # Calculate derived metrics
        df['detection_rate'] = df.apply(
            lambda row: (row['confirmed_vulns'] / row['total_findings'] * 100) 
            if row['total_findings'] > 0 else 0, axis=1
        )
        df['fp_rate'] = df.apply(
            lambda row: (row['false_positives'] / row['total_findings'] * 100) 
            if row['total_findings'] > 0 else 0, axis=1
        )
        df['cost_per_confirmed'] = df.apply(
            lambda row: (row['total_cost_usd'] / row['confirmed_vulns']) 
            if row['confirmed_vulns'] > 0 else 0, axis=1
        )
        
        # Group by model
        grouped = df.groupby('model_name').agg({
            'scan_id': 'count',
            'confirmed_vulns': 'sum',
            'false_positives': 'sum',
            'total_findings': 'sum',
            'total_cost_usd': 'sum',
            'duration_s': 'mean',
            'detection_rate': 'mean',
            'fp_rate': 'mean',
            'cost_per_confirmed': 'mean'
        }).reset_index()
        
        grouped.columns = [
            'model_name', 'num_scans', 'total_confirmed', 'total_fp',
            'total_findings', 'total_cost', 'avg_duration_s',
            'avg_detection_rate', 'avg_fp_rate', 'avg_cost_per_confirmed'
        ]
        
        return {
            'by_model': grouped.to_dict('records'),
            'summary': {
                'total_scans': len(df),
                'total_models': df['model_name'].nunique(),
                'total_confirmed': df['confirmed_vulns'].sum(),
                'total_cost': df['total_cost_usd'].sum()
            }
        }
    
    def _analyze_without_pandas(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze without pandas (fallback)"""
        by_model = defaultdict(lambda: {
            'num_scans': 0,
            'confirmed_vulns': [],
            'false_positives': [],
            'total_findings': [],
            'total_cost_usd': [],
            'duration_s': [],
            'detection_rates': [],
            'fp_rates': [],
            'costs_per_confirmed': []
        })
        
        for result in results:
            model = result.get('model_name', 'unknown')
            metrics = self.calculate_metrics(result)
            
            by_model[model]['num_scans'] += 1
            by_model[model]['confirmed_vulns'].append(metrics.confirmed_vulns)
            by_model[model]['false_positives'].append(metrics.false_positives)
            by_model[model]['total_findings'].append(metrics.total_findings)
            by_model[model]['total_cost_usd'].append(metrics.total_cost_usd)
            by_model[model]['duration_s'].append(metrics.duration_s)
            by_model[model]['detection_rates'].append(metrics.detection_rate)
            by_model[model]['fp_rates'].append(metrics.fp_rate)
            by_model[model]['costs_per_confirmed'].append(metrics.cost_per_confirmed)
        
        # Calculate averages
        summary_by_model = []
        for model, data in by_model.items():
            n = data['num_scans']
            summary_by_model.append({
                'model_name': model,
                'num_scans': n,
                'total_confirmed': sum(data['confirmed_vulns']),
                'total_fp': sum(data['false_positives']),
                'total_findings': sum(data['total_findings']),
                'total_cost': sum(data['total_cost_usd']),
                'avg_duration_s': sum(data['duration_s']) / n if n > 0 else 0,
                'avg_detection_rate': sum(data['detection_rates']) / n if n > 0 else 0,
                'avg_fp_rate': sum(data['fp_rates']) / n if n > 0 else 0,
                'avg_cost_per_confirmed': sum(data['costs_per_confirmed']) / n if n > 0 else 0
            })
        
        return {
            'by_model': summary_by_model,
            'summary': {
                'total_scans': len(results),
                'total_models': len(by_model),
                'total_confirmed': sum(r.get('confirmed_vulns', 0) for r in results),
                'total_cost': sum(float(r.get('total_cost_usd', 0)) for r in results)
            }
        }
    
    def generate_summary_csv(self, output_path: str = None):
        """Generate benchmark summary CSV"""
        if output_path is None:
            output_path = os.path.join(self.results_dir, "benchmark_summary.csv")
        
        results = self.load_scan_results()
        analysis = self.analyze_by_model(results)
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Model', 'Scans', 'Confirmed', 'FP', 'Total Findings',
                'Detection Rate %', 'FP Rate %', 'Total Cost $',
                'Avg Cost/Confirmed $', 'Avg Duration s'
            ])
            
            for model_data in analysis['by_model']:
                writer.writerow([
                    model_data['model_name'],
                    model_data['num_scans'],
                    model_data['total_confirmed'],
                    model_data.get('total_fp', model_data.get('false_positives', 0)),
                    model_data['total_findings'],
                    f"{model_data['avg_detection_rate']:.2f}",
                    f"{model_data['avg_fp_rate']:.2f}",
                    f"{model_data['total_cost']:.4f}",
                    f"{model_data['avg_cost_per_confirmed']:.4f}",
                    f"{model_data['avg_duration_s']:.2f}"
                ])
        
        print(f"Benchmark summary saved to: {output_path}")
        return output_path
    
    def generate_report(self, output_path: str = None):
        """Generate detailed benchmark report"""
        if output_path is None:
            output_path = os.path.join(self.results_dir, "benchmark_report.json")
        
        results = self.load_scan_results()
        analysis = self.analyze_by_model(results)
        
        report = {
            'generated_at': datetime.utcnow().isoformat(),
            'analysis': analysis,
            'recommendations': self._generate_recommendations(analysis)
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"Benchmark report saved to: {output_path}")
        return report
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on analysis"""
        recommendations = []
        
        models = analysis.get('by_model', [])
        if not models:
            return recommendations
        
        # Find best detection rate
        best_detection = max(models, key=lambda x: x.get('avg_detection_rate', 0))
        recommendations.append(
            f"Best detection rate: {best_detection['model_name']} "
            f"({best_detection['avg_detection_rate']:.1f}%)"
        )
        
        # Find lowest FP rate
        best_fp = min(models, key=lambda x: x.get('avg_fp_rate', 100))
        recommendations.append(
            f"Lowest false positive rate: {best_fp['model_name']} "
            f"({best_fp['avg_fp_rate']:.1f}%)"
        )
        
        # Find most cost-effective
        cheapest = min(models, key=lambda x: x.get('avg_cost_per_confirmed', float('inf')))
        recommendations.append(
            f"Most cost-effective: {cheapest['model_name']} "
            f"(${cheapest['avg_cost_per_confirmed']:.4f} per confirmed vuln)"
        )
        
        return recommendations
    
    def compare_models(self, model_names: List[str]) -> Dict[str, Any]:
        """Compare specific models"""
        results = self.load_scan_results()
        filtered = [r for r in results if r.get('model_name') in model_names]
        
        return self.analyze_by_model(filtered)


def main():
    """CLI entry point for analysis"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyze AutoPoV benchmark results')
    parser.add_argument('--csv', action='store_true', help='Generate CSV summary')
    parser.add_argument('--report', action='store_true', help='Generate JSON report')
    parser.add_argument('--compare', nargs='+', help='Compare specific models')
    
    args = parser.parse_args()
    
    analyzer = BenchmarkAnalyzer()
    
    if args.compare:
        comparison = analyzer.compare_models(args.compare)
        print(json.dumps(comparison, indent=2))
    elif args.csv:
        analyzer.generate_summary_csv()
    elif args.report:
        analyzer.generate_report()
    else:
        # Default: show summary
        results = analyzer.load_scan_results()
        analysis = analyzer.analyze_by_model(results)
        
        print("\n" + "="*60)
        print("AutoPoV Benchmark Summary")
        print("="*60)
        print(f"\nTotal Scans: {analysis['summary']['total_scans']}")
        print(f"Models Tested: {analysis['summary']['total_models']}")
        print(f"Total Confirmed Vulnerabilities: {analysis['summary']['total_confirmed']}")
        print(f"Total Cost: ${analysis['summary']['total_cost']:.4f}")
        
        print("\n" + "-"*60)
        print("Results by Model:")
        print("-"*60)
        
        for model in analysis['by_model']:
            print(f"\n{model['model_name']}:")
            print(f"  Scans: {model['num_scans']}")
            print(f"  Detection Rate: {model['avg_detection_rate']:.1f}%")
            print(f"  FP Rate: {model['avg_fp_rate']:.1f}%")
            print(f"  Avg Cost/Confirmed: ${model['avg_cost_per_confirmed']:.4f}")
        
        print("\n" + "="*60)


if __name__ == '__main__':
    main()
