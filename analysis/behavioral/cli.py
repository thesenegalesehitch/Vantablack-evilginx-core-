#!/usr/bin/env python3
"""
VANTABLACK Behavioral Analysis CLI
===================================

Command-line interface for behavioral analysis and optimization.
"""

import asyncio
import argparse
import json
import sys
from pathlib import Path

from .analyzer import BehavioralAnalyzer
from .tracker import UserTracker
from .optimizer import CampaignOptimizer
from .predictor import BehaviorPredictor


async def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="VANTABLACK Behavioral Analysis Tool"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze behavioral data')
    analyze_parser.add_argument('--sessions', required=True, help='Sessions data file (JSON)')
    analyze_parser.add_argument('--interactions', help='Interactions data file (JSON)')
    analyze_parser.add_argument('--conversions', help='Conversions data file (JSON)')
    analyze_parser.add_argument('--output', '-o', help='Output file for analysis')
    
    # Track command
    track_parser = subparsers.add_parser('track', help='Generate tracking script')
    track_parser.add_argument('--endpoint', required=True, help='Tracking endpoint URL')
    track_parser.add_argument('--session-id', help='Specific session ID')
    track_parser.add_argument('--output', '-o', help='Output file for script')
    
    # Optimize command
    optimize_parser = subparsers.add_parser('optimize', help='Generate optimization recommendations')
    optimize_parser.add_argument('--behavioral-data', required=True, help='Behavioral data file (JSON)')
    optimize_parser.add_argument('--page-data', help='Page data file (JSON)')
    optimize_parser.add_argument('--email-data', help='Email data file (JSON)')
    optimize_parser.add_argument('--output', '-o', help='Output file for recommendations')
    
    # Predict command
    predict_parser = subparsers.add_parser('predict', help='Make predictions')
    predict_parser.add_argument('--model', choices=['conversion', 'timing', 'segments'], 
                               required=True, help='Prediction model to use')
    predict_parser.add_argument('--data', required=True, help='Input data file (JSON)')
    predict_parser.add_argument('--output', '-o', help='Output file for predictions')
    predict_parser.add_argument('--train', action='store_true', help='Train model before prediction')
    predict_parser.add_argument('--training-data', help='Training data file (JSON)')
    
    # AB test command
    abtest_parser = subparsers.add_parser('abtest', help='A/B testing management')
    abtest_parser.add_argument('--action', choices=['create', 'analyze', 'list'], 
                              required=True, help='Action to perform')
    abtest_parser.add_argument('--name', help='Test name')
    abtest_parser.add_argument('--description', help='Test description')
    abtest_parser.add_argument('--variants', help='Variants file (JSON)')
    abtest_parser.add_argument('--test-id', help='Test ID for analysis')
    abtest_parser.add_argument('--output', '-o', help='Output file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.command == 'analyze':
            await analyze_command(args)
        elif args.command == 'track':
            await track_command(args)
        elif args.command == 'optimize':
            await optimize_command(args)
        elif args.command == 'predict':
            await predict_command(args)
        elif args.command == 'abtest':
            await abtest_command(args)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


async def analyze_command(args):
    """Handle analyze command"""
    analyzer = BehavioralAnalyzer()
    
    # Load data
    analyzer.load_data_from_json(
        args.sessions,
        args.interactions or '[]',
        args.conversions or '[]'
    )
    
    # Perform analysis
    print("Analyzing behavioral data...")
    metrics = analyzer.analyze_campaign_performance()
    
    # Generate recommendations
    recommendations = analyzer.generate_optimization_recommendations()
    
    # Export report
    report = analyzer.export_analysis_report(args.output)
    
    if args.output:
        print(f"Analysis report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2, default=str))


async def track_command(args):
    """Handle track command"""
    tracker = UserTracker()
    
    # Generate tracking script
    script = tracker.generate_tracking_script(args.endpoint, args.session_id)
    
    # Output script
    if args.output:
        with open(args.output, 'w') as f:
            f.write(script)
        print(f"Tracking script saved to {args.output}")
    else:
        print(script)


async def optimize_command(args):
    """Handle optimize command"""
    optimizer = CampaignOptimizer()
    
    # Load behavioral data
    with open(args.behavioral_data, 'r') as f:
        behavioral_data = json.load(f)
    
    # Generate recommendations
    recommendations = optimizer.generate_optimization_recommendations(behavioral_data)
    
    # Page optimization
    page_suggestions = {}
    if args.page_data:
        with open(args.page_data, 'r') as f:
            page_data = json.load(f)
        page_suggestions = optimizer.optimize_landing_page(page_data, behavioral_data)
    
    # Email optimization
    email_suggestions = {}
    if args.email_data:
        with open(args.email_data, 'r') as f:
            email_data = json.load(f)
        performance_data = behavioral_data.get('email_performance', {})
        email_suggestions = optimizer.optimize_email_campaign(email_data, performance_data)
    
    # Compile results
    results = {
        'recommendations': [r.__dict__ for r in recommendations],
        'page_optimization': page_suggestions,
        'email_optimization': email_suggestions,
        'optimization_score': optimizer.get_optimization_score(behavioral_data)
    }
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"Optimization report saved to {args.output}")
    else:
        print(json.dumps(results, indent=2, default=str))


async def predict_command(args):
    """Handle predict command"""
    predictor = BehaviorPredictor()
    
    # Train model if requested
    if args.train:
        if not args.training_data:
            print("Error: --training-data required when using --train")
            sys.exit(1)
        
        with open(args.training_data, 'r') as f:
            training_data = json.load(f)
        
        print(f"Training {args.model} model...")
        if args.model == 'conversion':
            result = predictor.train_conversion_model(training_data)
        elif args.model == 'timing':
            result = predictor.train_timing_model(training_data)
        else:
            print("Training not supported for segments model")
            result = {}
        
        print(f"Training completed: {result}")
    
    # Load input data
    with open(args.data, 'r') as f:
        input_data = json.load(f)
    
    # Make predictions
    print(f"Making {args.model} predictions...")
    
    if args.model == 'conversion':
        if isinstance(input_data, list):
            predictions = [predictor.predict_conversion_probability(user) for user in input_data]
        else:
            predictions = predictor.predict_conversion_probability(input_data)
    
    elif args.model == 'timing':
        if isinstance(input_data, list):
            predictions = [predictor.predict_optimal_timing(user) for user in input_data]
        else:
            predictions = predictor.predict_optimal_timing(input_data)
    
    elif args.model == 'segments':
        if not isinstance(input_data, list):
            print("Segments model requires list of users")
            sys.exit(1)
        predictions = predictor.predict_user_segments(input_data)
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            if args.model == 'segments':
                json.dump([s.__dict__ for s in predictions], f, indent=2, default=str)
            else:
                if isinstance(predictions, list):
                    json.dump([p.__dict__ for p in predictions], f, indent=2, default=str)
                else:
                    json.dump(predictions.__dict__, f, indent=2, default=str)
        print(f"Predictions saved to {args.output}")
    else:
        if args.model == 'segments':
            print(json.dumps([s.__dict__ for s in predictions], indent=2, default=str))
        else:
            if isinstance(predictions, list):
                print(json.dumps([p.__dict__ for p in predictions], indent=2, default=str))
            else:
                print(json.dumps(predictions.__dict__, indent=2, default=str))


async def abtest_command(args):
    """Handle A/B testing command"""
    optimizer = CampaignOptimizer()
    
    if args.action == 'create':
        if not args.name or not args.variants:
            print("Error: --name and --variants required for create action")
            sys.exit(1)
        
        with open(args.variants, 'r') as f:
            variants = json.load(f)
        
        test_id = optimizer.create_ab_test(
            name=args.name,
            description=args.description or '',
            variants=variants
        )
        
        result = {'test_id': test_id, 'status': 'created'}
        print(f"A/B test created with ID: {test_id}")
    
    elif args.action == 'analyze':
        if not args.test_id:
            print("Error: --test-id required for analyze action")
            sys.exit(1)
        
        result = optimizer.analyze_ab_test(args.test_id)
        print(f"A/B test analysis: {result}")
    
    elif args.action == 'list':
        result = optimizer.export_optimization_report()
        result = {'tests': result['ab_tests']}
        print(f"Active A/B tests: {len(result['tests'])}")
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        print(f"A/B test results saved to {args.output}")
    else:
        print(json.dumps(result, indent=2, default=str))


if __name__ == '__main__':
    asyncio.run(main())
