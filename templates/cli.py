#!/usr/bin/env python3
"""
Template System CLI - Command Line Interface
==========================================

Command line interface for template management:
- Template generation and optimization
- A/B testing management
- Marketplace operations
- Template analysis and reporting
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import time

from .generator import TemplateGenerator, TemplateConfig
from .ab_testing import ABTestManager, ABTestConfig
from .optimizer import TemplateOptimizer, OptimizationConfig
from .marketplace import TemplateMarketplace, TemplateCategory, TemplateStatus


class TemplateCLI:
    """Command line interface for template system"""
    
    def __init__(self):
        self.generator = TemplateGenerator()
        self.ab_tester = ABTestManager()
        self.optimizer = TemplateOptimizer()
        self.marketplace = TemplateMarketplace()
    
    def run(self, args: List[str] = None) -> int:
        """Main CLI entry point"""
        parser = argparse.ArgumentParser(
            description="VANTABLACK Template System CLI",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s generate --platform twitter --type login
  %(prog)s optimize --template template_id --goal conversion_rate
  %(prog)s test --variants variant1 variant2 --duration 48
  %(prog)s marketplace submit --name "Twitter Login" --author "John Doe"
  %(prog)s marketplace search --query "twitter" --category login
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Generate command
        generate_parser = subparsers.add_parser('generate', help='Generate templates')
        generate_parser.add_argument('--platform', required=True, 
                                   help='Target platform (twitter, google, facebook, etc.)')
        generate_parser.add_argument('--type', default='login',
                                   choices=['login', 'register', 'payment', 'survey'],
                                   help='Template type')
        generate_parser.add_argument('--personalization', default='medium',
                                   choices=['low', 'medium', 'high'],
                                   help='Personalization level')
        generate_parser.add_argument('--optimization', default='advanced',
                                   choices=['basic', 'advanced', 'maximum'],
                                   help='Optimization level')
        generate_parser.add_argument('--responsive', action='store_true',
                                   help='Make responsive design')
        generate_parser.add_argument('--output', help='Output file path')
        generate_parser.add_argument('--count', type=int, default=1,
                                   help='Number of templates to generate')
        
        # Optimize command
        optimize_parser = subparsers.add_parser('optimize', help='Optimize templates')
        optimize_parser.add_argument('--template', required=True,
                                    help='Template ID to optimize')
        optimize_parser.add_argument('--goal', default='conversion_rate',
                                    choices=['conversion_rate', 'revenue', 'engagement', 'bounce_rate'],
                                    help='Optimization goal')
        optimize_parser.add_argument('--improvement', type=float, default=0.2,
                                    help='Target improvement percentage')
        optimize_parser.add_argument('--variants', type=int, default=4,
                                    help='Maximum number of variants')
        optimize_parser.add_argument('--duration', type=int, default=48,
                                    help='Test duration in hours')
        optimize_parser.add_argument('--output', help='Output file path')
        
        # Test command
        test_parser = subparsers.add_parser('test', help='Manage A/B tests')
        test_parser.add_argument('--variants', nargs='+', required=True,
                                help='Template variant IDs')
        test_parser.add_argument('--duration', type=int, default=48,
                                help='Test duration in hours')
        test_parser.add_argument('--confidence', type=float, default=0.95,
                                help='Confidence level')
        test_parser.add_argument('--min-samples', type=int, default=100,
                                help='Minimum sample size')
        test_parser.add_argument('--metric', default='conversion_rate',
                                choices=['conversion_rate', 'revenue', 'engagement_time', 'bounce_rate'],
                                help='Success metric')
        test_parser.add_argument('--name', help='Test name')
        test_parser.add_argument('--description', help='Test description')
        
        # Marketplace commands
        marketplace_parser = subparsers.add_parser('marketplace', help='Marketplace operations')
        marketplace_subparsers = marketplace_parser.add_subparsers(dest='marketplace_command')
        
        # Submit command
        submit_parser = marketplace_subparsers.add_parser('submit', help='Submit template to marketplace')
        submit_parser.add_argument('--name', required=True, help='Template name')
        submit_parser.add_argument('--description', required=True, help='Template description')
        submit_parser.add_argument('--author', required=True, help='Author name')
        submit_parser.add_argument('--email', required=True, help='Author email')
        submit_parser.add_argument('--category', required=True,
                                  choices=[cat.value for cat in TemplateCategory],
                                  help='Template category')
        submit_parser.add_argument('--platform', required=True, help='Target platform')
        submit_parser.add_argument('--html', required=True, help='HTML content file')
        submit_parser.add_argument('--css', help='CSS content file')
        submit_parser.add_argument('--js', help='JavaScript content file')
        submit_parser.add_argument('--tags', nargs='*', help='Template tags')
        submit_parser.add_argument('--license', default='MIT', help='License type')
        submit_parser.add_argument('--price', type=float, default=0.0, help='Template price')
        submit_parser.add_argument('--premium', action='store_true', help='Premium template')
        
        # Search command
        search_parser = marketplace_subparsers.add_parser('search', help='Search marketplace')
        search_parser.add_argument('--query', help='Search query')
        search_parser.add_argument('--category', choices=[cat.value for cat in TemplateCategory],
                                   help='Template category')
        search_parser.add_argument('--platform', help='Target platform')
        search_parser.add_argument('--tags', nargs='*', help='Template tags')
        search_parser.add_argument('--min-rating', type=float, help='Minimum rating')
        search_parser.add_argument('--max-price', type=float, help='Maximum price')
        search_parser.add_argument('--featured', action='store_true', help='Featured only')
        search_parser.add_argument('--limit', type=int, default=20, help='Result limit')
        
        # Download command
        download_parser = marketplace_subparsers.add_parser('download', help='Download template')
        download_parser.add_argument('--template', required=True, help='Template ID')
        download_parser.add_argument('--output', help='Output directory')
        
        # Review command
        review_parser = marketplace_subparsers.add_parser('review', help='Add review')
        review_parser.add_argument('--template', required=True, help='Template ID')
        review_parser.add_argument('--reviewer', required=True, help='Reviewer name')
        review_parser.add_argument('--rating', type=int, required=True, choices=range(1, 6),
                                  help='Rating (1-5)')
        review_parser.add_argument('--comment', required=True, help='Review comment')
        review_parser.add_argument('--pros', nargs='*', help='Pros list')
        review_parser.add_argument('--cons', nargs='*', help='Cons list')
        
        # Stats command
        stats_parser = marketplace_subparsers.add_parser('stats', help='Marketplace statistics')
        
        # Admin commands
        admin_parser = subparsers.add_parser('admin', help='Admin operations')
        admin_subparsers = admin_parser.add_subparsers(dest='admin_command')
        
        # Approve command
        approve_parser = admin_subparsers.add_parser('approve', help='Approve template')
        approve_parser.add_argument('--template', required=True, help='Template ID')
        approve_parser.add_argument('--reviewer', required=True, help='Reviewer name')
        approve_parser.add_argument('--notes', help='Approval notes')
        
        # Reject command
        reject_parser = admin_subparsers.add_parser('reject', help='Reject template')
        reject_parser.add_argument('--template', required=True, help='Template ID')
        reject_parser.add_argument('--reviewer', required=True, help='Reviewer name')
        reject_parser.add_argument('--reason', help='Rejection reason')
        
        # Feature command
        feature_parser = admin_subparsers.add_parser('feature', help='Feature template')
        feature_parser.add_argument('--template', required=True, help='Template ID')
        feature_parser.add_argument('--featured', action='store_true', help='Set as featured')
        
        # Parse arguments
        parsed_args = parser.parse_args(args)
        
        # Execute command
        if parsed_args.command == 'generate':
            return self._handle_generate(parsed_args)
        elif parsed_args.command == 'optimize':
            return self._handle_optimize(parsed_args)
        elif parsed_args.command == 'test':
            return self._handle_test(parsed_args)
        elif parsed_args.command == 'marketplace':
            return self._handle_marketplace(parsed_args)
        elif parsed_args.command == 'admin':
            return self._handle_admin(parsed_args)
        else:
            parser.print_help()
            return 1
    
    def _handle_generate(self, args: argparse.Namespace) -> int:
        """Handle template generation"""
        try:
            print(f"Generating {args.count} template(s) for {args.platform}...")
            
            templates = []
            for i in range(args.count):
                config = TemplateConfig(
                    target_platform=args.platform,
                    template_type=args.type,
                    personalization_level=args.personalization,
                    responsive=args.responsive,
                    optimization_level=args.optimization,
                    compliance_checks=['gdpr', 'accessibility'],
                    custom_variables={}
                )
                
                template = self.generator.generate_template(config)
                templates.append(template)
                
                print(f"  ✓ Generated template: {template.template_id}")
            
            # Save templates
            if args.output:
                output_path = Path(args.output)
                if len(templates) == 1:
                    # Single template
                    self._save_template(templates[0], output_path)
                else:
                    # Multiple templates
                    output_path.mkdir(exist_ok=True)
                    for i, template in enumerate(templates):
                        template_path = output_path / f"template_{i+1}"
                        self._save_template(template, template_path)
                
                print(f"  ✓ Saved to: {args.output}")
            else:
                # Print template info
                for template in templates:
                    print(f"\nTemplate: {template.template_id}")
                    print(f"Name: {template.name}")
                    print(f"Platform: {template.config.target_platform}")
                    print(f"Type: {template.config.template_type}")
                    print(f"Performance Score: {template.performance_score:.3f}")
                    print(f"Compliance Score: {template.compliance_score:.3f}")
            
            return 0
            
        except Exception as e:
            print(f"Error generating templates: {e}")
            return 1
    
    def _handle_optimize(self, args: argparse.Namespace) -> int:
        """Handle template optimization"""
        try:
            print(f"Optimizing template {args.template} for {args.goal}...")
            
            # Load template (for demo, create a sample template)
            config = TemplateConfig(
                target_platform='twitter',
                template_type='login',
                personalization_level='medium',
                responsive=True,
                optimization_level='advanced',
                compliance_checks=['gdpr', 'accessibility'],
                custom_variables={}
            )
            
            base_template = self.generator.generate_template(config)
            base_template.template_id = args.template
            
            # Create optimization config
            opt_config = OptimizationConfig(
                optimization_goal=args.goal,
                target_improvement=args.improvement,
                max_variants=args.variants,
                test_duration_hours=args.duration,
                personalization_level='high',
                optimization_techniques=['headline_optimization', 'form_optimization', 'personalization'],
                budget_constraints={},
                custom_variables={}
            )
            
            # Run optimization
            result = self.optimizer.optimize_template(base_template, opt_config)
            
            print(f"  ✓ Optimization completed: {result.optimization_id}")
            print(f"  ✓ Performance gain: {result.performance_gain:.3f}")
            print(f"  ✓ Improvement: {result.improvement_metrics.get('improvement', 0):.1f}%")
            
            # Save results
            if args.output:
                output_path = Path(args.output)
                self._save_optimization_result(result, output_path)
                print(f"  ✓ Saved to: {args.output}")
            
            return 0
            
        except Exception as e:
            print(f"Error optimizing template: {e}")
            return 1
    
    def _handle_test(self, args: argparse.Namespace) -> int:
        """Handle A/B testing"""
        try:
            print(f"Creating A/B test with {len(args.variants)} variants...")
            
            # Create test config
            test_config = ABTestConfig(
                test_id=f"test_{int(time.time())}",
                name=args.name or f"A/B Test - {args.metric}",
                description=args.description or f"Testing {args.metric} optimization",
                template_variants=args.variants,
                traffic_split=[1.0 / len(args.variants)] * len(args.variants),
                confidence_level=args.confidence,
                min_sample_size=args.min_samples,
                test_duration_hours=args.duration,
                success_metric=args.metric,
                created_at=datetime.now()
            )
            
            # Create test
            test_id = self.ab_tester.create_test(test_config)
            
            print(f"  ✓ Test created: {test_id}")
            print(f"  ✓ Duration: {args.duration} hours")
            print(f"  ✓ Confidence level: {args.confidence}")
            print(f"  ✓ Minimum samples: {args.min_samples}")
            
            # Show test summary
            summary = self.ab_tester.get_test_summary(test_id)
            print(f"\nTest Summary:")
            print(f"  Name: {summary['config']['name']}")
            print(f"  Variants: {', '.join(summary['config']['template_variants'])}")
            print(f"  Traffic split: {', '.join(f'{x:.1%}' for x in summary['config']['traffic_split'])}")
            
            return 0
            
        except Exception as e:
            print(f"Error creating A/B test: {e}")
            return 1
    
    def _handle_marketplace(self, args: argparse.Namespace) -> int:
        """Handle marketplace operations"""
        try:
            if args.marketplace_command == 'submit':
                return self._handle_marketplace_submit(args)
            elif args.marketplace_command == 'search':
                return self._handle_marketplace_search(args)
            elif args.marketplace_command == 'download':
                return self._handle_marketplace_download(args)
            elif args.marketplace_command == 'review':
                return self._handle_marketplace_review(args)
            elif args.marketplace_command == 'stats':
                return self._handle_marketplace_stats(args)
            else:
                print("Unknown marketplace command")
                return 1
                
        except Exception as e:
            print(f"Error in marketplace operation: {e}")
            return 1
    
    def _handle_marketplace_submit(self, args: argparse.Namespace) -> int:
        """Handle marketplace template submission"""
        print(f"Submitting template '{args.name}' to marketplace...")
        
        # Read template files
        html_content = Path(args.html).read_text()
        css_content = Path(args.css).read_text() if args.css else ""
        js_content = Path(args.js).read_text() if args.js else ""
        
        # Submit template
        template_id = self.marketplace.submit_template(
            name=args.name,
            description=args.description,
            author=args.author,
            author_email=args.email,
            category=TemplateCategory(args.category),
            target_platform=args.platform,
            html_content=html_content,
            css_content=css_content,
            js_content=js_content,
            tags=args.tags or [],
            license=args.license,
            price=args.price,
            is_premium=args.premium
        )
        
        print(f"  ✓ Template submitted: {template_id}")
        print(f"  ✓ Status: Pending approval")
        
        return 0
    
    def _handle_marketplace_search(self, args: argparse.Namespace) -> int:
        """Handle marketplace search"""
        print(f"Searching marketplace...")
        
        # Build search parameters
        category = TemplateCategory(args.category) if args.category else None
        
        # Search templates
        results = self.marketplace.search_templates(
            query=args.query or "",
            category=category,
            platform=args.platform or "",
            tags=args.tags or [],
            min_rating=args.min_rating or 0.0,
            max_price=args.max_price,
            featured_only=args.featured,
            limit=args.limit
        )
        
        print(f"  ✓ Found {len(results)} templates")
        
        if results:
            print(f"\n{'ID':<8} {'Name':<20} {'Author':<15} {'Rating':<8} {'Downloads':<10} {'Price':<8}")
            print("-" * 80)
            
            for template in results:
                price_str = f"${template.price:.2f}" if template.price > 0 else "Free"
                print(f"{template.template_id[:7]:<8} {template.name[:18]:<20} {template.author[:13]:<15} "
                      f"{template.rating:.1f:<8} {template.download_count:<10} {price_str:<8}")
        
        return 0
    
    def _handle_marketplace_download(self, args: argparse.Namespace) -> int:
        """Handle marketplace template download"""
        print(f"Downloading template {args.template}...")
        
        # Download template
        template_data = self.marketplace.download_template(args.template, "cli_user")
        
        if template_data:
            output_dir = Path(args.output or ".")
            output_dir.mkdir(exist_ok=True)
            
            # Save template files
            template_path = output_dir / f"{template_data['template_id']}"
            template_path.mkdir(exist_ok=True)
            
            (template_path / "index.html").write_text(template_data['html_content'])
            (template_path / "style.css").write_text(template_data['css_content'])
            (template_path / "script.js").write_text(template_data['js_content'])
            
            # Save metadata
            metadata = {
                'template_id': template_data['template_id'],
                'name': template_data['name'],
                'author': template_data['author'],
                'category': template_data['category'],
                'target_platform': template_data['target_platform'],
                'tags': template_data['tags'],
                'version': template_data['version'],
                'license': template_data['license'],
                'checksum': template_data['checksum']
            }
            
            (template_path / "metadata.json").write_text(json.dumps(metadata, indent=2))
            
            print(f"  ✓ Downloaded to: {template_path}")
            return 0
        else:
            print(f"  ✗ Template not found or not available")
            return 1
    
    def _handle_marketplace_review(self, args: argparse.Namespace) -> int:
        """Handle marketplace review submission"""
        print(f"Adding review for template {args.template}...")
        
        # Add review
        review_id = self.marketplace.add_review(
            template_id=args.template,
            reviewer=args.reviewer,
            rating=args.rating,
            comment=args.comment,
            pros=args.pros or [],
            cons=args.cons or []
        )
        
        if review_id:
            print(f"  ✓ Review added: {review_id}")
            return 0
        else:
            print(f"  ✗ Failed to add review")
            return 1
    
    def _handle_marketplace_stats(self, args: argparse.Namespace) -> int:
        """Handle marketplace statistics"""
        print("Marketplace Statistics:")
        
        stats = self.marketplace.get_marketplace_stats()
        
        print(f"  Total templates: {stats.total_templates}")
        print(f"  Active templates: {stats.active_templates}")
        print(f"  Pending templates: {stats.pending_templates}")
        print(f"  Total downloads: {stats.total_downloads}")
        print(f"  Total authors: {stats.total_authors}")
        print(f"  Average rating: {stats.average_rating:.2f}")
        
        if stats.top_categories:
            print(f"\nTop Categories:")
            for cat in stats.top_categories:
                print(f"  {cat['category']}: {cat['count']} templates")
        
        if stats.recent_activity:
            print(f"\nRecent Activity:")
            for activity in stats.recent_activity[:5]:
                print(f"  {activity['type']}: {activity.get('name', activity.get('template_id', 'Unknown'))}")
        
        return 0
    
    def _handle_admin(self, args: argparse.Namespace) -> int:
        """Handle admin operations"""
        try:
            if args.admin_command == 'approve':
                return self._handle_admin_approve(args)
            elif args.admin_command == 'reject':
                return self._handle_admin_reject(args)
            elif args.admin_command == 'feature':
                return self._handle_admin_feature(args)
            else:
                print("Unknown admin command")
                return 1
                
        except Exception as e:
            print(f"Error in admin operation: {e}")
            return 1
    
    def _handle_admin_approve(self, args: argparse.Namespace) -> int:
        """Handle template approval"""
        print(f"Approving template {args.template}...")
        
        success = self.marketplace.approve_template(args.template, args.reviewer, args.notes or "")
        
        if success:
            print(f"  ✓ Template approved")
            return 0
        else:
            print(f"  ✗ Failed to approve template")
            return 1
    
    def _handle_admin_reject(self, args: argparse.Namespace) -> int:
        """Handle template rejection"""
        print(f"Rejecting template {args.template}...")
        
        success = self.marketplace.reject_template(args.template, args.reviewer, args.reason or "")
        
        if success:
            print(f"  ✓ Template rejected")
            return 0
        else:
            print(f"  ✗ Failed to reject template")
            return 1
    
    def _handle_admin_feature(self, args: argparse.Namespace) -> int:
        """Handle template featuring"""
        print(f"Featuring template {args.template}...")
        
        success = self.marketplace.feature_template(args.template, args.featured)
        
        if success:
            status = "featured" if args.featured else "unfeatured"
            print(f"  ✓ Template {status}")
            return 0
        else:
            print(f"  ✗ Failed to {status} template")
            return 1
    
    def _save_template(self, template, output_path: Path) -> None:
        """Save template to files"""
        output_path.mkdir(exist_ok=True)
        
        # Save HTML
        (output_path / "index.html").write_text(template.html_content)
        
        # Save CSS
        (output_path / "style.css").write_text(template.css_content)
        
        # Save JavaScript
        (output_path / "script.js").write_text(template.js_content)
        
        # Save metadata
        metadata = {
            'template_id': template.template_id,
            'name': template.name,
            'description': template.description,
            'config': {
                'target_platform': template.config.target_platform,
                'template_type': template.config.template_type,
                'personalization_level': template.config.personalization_level,
                'responsive': template.config.responsive,
                'optimization_level': template.config.optimization_level
            },
            'performance_score': template.performance_score,
            'compliance_score': template.compliance_score,
            'created_at': template.created_at.isoformat(),
            'variables_used': template.variables_used
        }
        
        (output_path / "metadata.json").write_text(json.dumps(metadata, indent=2))
    
    def _save_optimization_result(self, result, output_path: Path) -> None:
        """Save optimization result to file"""
        result_data = {
            'optimization_id': result.optimization_id,
            'original_template': {
                'template_id': result.original_template.template_id,
                'name': result.original_template.name,
                'performance_score': result.original_template.performance_score
            },
            'optimized_template': {
                'template_id': result.optimized_template.template_id,
                'name': result.optimized_template.name,
                'performance_score': result.optimized_template.performance_score
            },
            'improvement_metrics': result.improvement_metrics,
            'ab_test_results': result.ab_test_results,
            'optimization_techniques_applied': result.optimization_techniques_applied,
            'performance_gain': result.performance_gain,
            'created_at': result.created_at.isoformat()
        }
        
        output_path.write_text(json.dumps(result_data, indent=2))


def main():
    """Main entry point"""
    cli = TemplateCLI()
    return cli.run()


if __name__ == '__main__':
    sys.exit(main())
