#!/usr/bin/env python3
"""
VANTABLACK Reverse Engineering CLI
==================================

Command-line interface for phishlet analysis and signature generation.
"""

import asyncio
import argparse
import json
import sys
from pathlib import Path

from .analyzer import PhishletAnalyzer
from .signature_generator import SignatureGenerator
from .pattern_extractor import PatternExtractor


async def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="VANTABLACK Phishlet Reverse Engineering Tool"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze phishlet files')
    analyze_parser.add_argument('input', help='Input phishlet file or directory')
    analyze_parser.add_argument('--output', '-o', help='Output file for results')
    analyze_parser.add_argument('--format', choices=['json', 'yaml'], default='json',
                               help='Output format')
    
    # Signature generation command
    sig_parser = subparsers.add_parser('signatures', help='Generate detection signatures')
    sig_parser.add_argument('input', help='Analyzed phishlet data (JSON)')
    sig_parser.add_argument('--output', '-o', help='Output file for signatures')
    sig_parser.add_argument('--type', choices=['all', 'yara', 'snort', 'regex', 'ioc'],
                           default='all', help='Signature type to generate')
    sig_parser.add_argument('--format', choices=['json', 'yara', 'snort'], default='json',
                           help='Output format')
    
    # Pattern extraction command
    pattern_parser = subparsers.add_parser('patterns', help='Extract attack patterns')
    pattern_parser.add_argument('input', help='Analyzed phishlet data (JSON)')
    pattern_parser.add_argument('--output', '-o', help='Output file for patterns')
    pattern_parser.add_argument('--mitre', action='store_true',
                               help='Generate MITRE ATT&CK report')
    
    # Batch analysis command
    batch_parser = subparsers.add_parser('batch', help='Batch analyze directory')
    batch_parser.add_argument('directory', help='Directory containing phishlets')
    batch_parser.add_argument('--output-dir', help='Output directory for results')
    batch_parser.add_argument('--signatures', action='store_true',
                            help='Also generate signatures')
    batch_parser.add_argument('--patterns', action='store_true',
                            help='Also extract patterns')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.command == 'analyze':
            await analyze_command(args)
        elif args.command == 'signatures':
            await signatures_command(args)
        elif args.command == 'patterns':
            await patterns_command(args)
        elif args.command == 'batch':
            await batch_command(args)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


async def analyze_command(args):
    """Handle analyze command"""
    analyzer = PhishletAnalyzer()
    
    input_path = Path(args.input)
    
    if input_path.is_file():
        # Analyze single file
        result = await analyzer.analyze_phishlet(str(input_path))
        results = [result]
    else:
        # Analyze directory
        results = await analyzer.batch_analyze(str(input_path))
    
    # Convert to dict for JSON serialization
    output_data = []
    for result in results:
        output_data.append({
            'name': result.name,
            'target_domain': result.target_domain,
            'auth_subdomains': result.auth_subdomains,
            'login_paths': result.login_paths,
            'post_data_paths': result.post_data_paths,
            'javascript_patterns': result.javascript_patterns,
            'anti_detection': result.anti_detection,
            'data_extraction': result.data_extraction,
            'risk_score': result.risk_score
        })
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"Analysis results saved to {args.output}")
    else:
        print(json.dumps(output_data, indent=2))


async def signatures_command(args):
    """Handle signatures command"""
    # Load analyzed data
    with open(args.input, 'r') as f:
        phishlet_data = json.load(f)
    
    # Reconstruct PhishletStructure objects
    from .analyzer import PhishletStructure
    phishlets = []
    for data in phishlet_data:
        phishlets.append(PhishletStructure(**data))
    
    # Generate signatures
    sig_gen = SignatureGenerator()
    all_signatures = []
    
    for phishlet in phishlets:
        signatures = sig_gen.generate_all_signatures(phishlet)
        
        if args.type != 'all':
            signatures = [s for s in signatures if s.signature_type == args.type]
        
        all_signatures.extend(signatures)
    
    # Export signatures
    if args.format == 'json':
        output = sig_gen.export_signatures(all_signatures, 'json')
    elif args.format == 'yara':
        output = sig_gen.export_signatures(all_signatures, 'yara')
    elif args.format == 'snort':
        output = sig_gen.export_signatures(all_signatures, 'snort')
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Signatures saved to {args.output}")
    else:
        print(output)


async def patterns_command(args):
    """Handle patterns command"""
    # Load analyzed data
    with open(args.input, 'r') as f:
        phishlet_data = json.load(f)
    
    # Reconstruct PhishletStructure objects
    from .analyzer import PhishletStructure
    phishlets = []
    for data in phishlet_data:
        phishlets.append(PhishletStructure(**data))
    
    # Extract patterns
    extractor = PatternExtractor()
    
    if args.mitre:
        # Generate MITRE report
        all_patterns = []
        for phishlet in phishlets:
            patterns = extractor.extract_patterns(phishlet)
            all_patterns.extend(patterns)
        
        report = extractor.generate_mitre_report(all_patterns)
        output = json.dumps(report, indent=2, default=str)
    else:
        # Extract patterns for each phishlet
        results = []
        for phishlet in phishlets:
            patterns = extractor.extract_patterns(phishlet)
            results.append({
                'phishlet': phishlet.name,
                'patterns': [
                    {
                        'name': p.name,
                        'description': p.description,
                        'attack_flow': p.attack_flow,
                        'techniques': p.techniques,
                        'confidence': p.confidence,
                        'severity': p.severity
                    }
                    for p in patterns
                ]
            })
        
        output = json.dumps(results, indent=2)
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Pattern analysis saved to {args.output}")
    else:
        print(output)


async def batch_command(args):
    """Handle batch analysis command"""
    analyzer = PhishletAnalyzer()
    sig_gen = SignatureGenerator()
    extractor = PatternExtractor()
    
    # Create output directory
    output_dir = Path(args.output_dir) if args.output_dir else Path('./batch_output')
    output_dir.mkdir(exist_ok=True)
    
    print(f"Analyzing phishlets in {args.directory}...")
    
    # Analyze all phishlets
    phishlets = await analyzer.batch_analyze(args.directory)
    print(f"Analyzed {len(phishlets)} phishlets")
    
    # Save analysis results
    analysis_file = output_dir / 'analysis.json'
    analysis_data = []
    for phishlet in phishlets:
        analysis_data.append({
            'name': phishlet.name,
            'target_domain': phishlet.target_domain,
            'auth_subdomains': phishlet.auth_subdomains,
            'login_paths': phishlet.login_paths,
            'post_data_paths': phishlet.post_data_paths,
            'javascript_patterns': phishlet.javascript_patterns,
            'anti_detection': phishlet.anti_detection,
            'data_extraction': phishlet.data_extraction,
            'risk_score': phishlet.risk_score
        })
    
    with open(analysis_file, 'w') as f:
        json.dump(analysis_data, f, indent=2)
    print(f"Analysis saved to {analysis_file}")
    
    # Generate signatures if requested
    if args.signatures:
        print("Generating signatures...")
        all_signatures = []
        
        for phishlet in phishlets:
            signatures = sig_gen.generate_all_signatures(phishlet)
            all_signatures.extend(signatures)
        
        # Save signatures in different formats
        for fmt in ['json', 'yara', 'snort']:
            sig_file = output_dir / f'signatures.{fmt}'
            output = sig_gen.export_signatures(all_signatures, fmt)
            with open(sig_file, 'w') as f:
                f.write(output)
            print(f"Signatures ({fmt}) saved to {sig_file}")
    
    # Extract patterns if requested
    if args.patterns:
        print("Extracting patterns...")
        batch_patterns = extractor.batch_extract_patterns(phishlets)
        
        # Save pattern analysis
        patterns_file = output_dir / 'patterns.json'
        with open(patterns_file, 'w') as f:
            json.dump(batch_patterns, f, indent=2, default=str)
        print(f"Patterns saved to {patterns_file}")
        
        # Generate MITRE report
        mitre_file = output_dir / 'mitre_report.json'
        mitre_report = extractor.generate_mitre_report(batch_patterns['patterns'])
        with open(mitre_file, 'w') as f:
            json.dump(mitre_report, f, indent=2, default=str)
        print(f"MITRE report saved to {mitre_file}")
    
    print(f"Batch analysis complete. Results saved to {output_dir}")


if __name__ == '__main__':
    asyncio.run(main())
