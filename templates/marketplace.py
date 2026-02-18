"""
Template Marketplace - Community Template Sharing
==============================================

Community-driven template marketplace:
- Template submission and review
- Rating and feedback system
- Template categorization
- Search and discovery
- Download and integration
"""

import json
import uuid
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import os


class TemplateStatus(Enum):
    """Template status in marketplace"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    FLAGGED = "flagged"


class TemplateCategory(Enum):
    """Template categories"""
    LOGIN = "login"
    REGISTER = "register"
    PAYMENT = "payment"
    SURVEY = "survey"
    CONTACT = "contact"
    DOWNLOAD = "download"
    VERIFICATION = "verification"
    CUSTOM = "custom"


@dataclass
class MarketplaceTemplate:
    """Template in marketplace"""
    template_id: str
    name: str
    description: str
    author: str
    author_email: str
    category: TemplateCategory
    target_platform: str
    html_content: str
    css_content: str
    js_content: str
    preview_image: str
    tags: List[str]
    status: TemplateStatus
    rating: float
    download_count: int
    created_at: datetime
    updated_at: datetime
    file_size: int
    checksum: str
    version: str
    license: str
    price: float
    is_premium: bool
    featured: bool
    metadata: Dict[str, Any]


@dataclass
class TemplateReview:
    """Template review"""
    review_id: str
    template_id: str
    reviewer: str
    rating: int  # 1-5
    comment: str
    pros: List[str]
    cons: List[str]
    created_at: datetime
    helpful_count: int


@dataclass
class MarketplaceStats:
    """Marketplace statistics"""
    total_templates: int
    active_templates: int
    pending_templates: int
    total_downloads: int
    total_authors: int
    average_rating: float
    top_categories: List[Dict[str, Any]]
    recent_activity: List[Dict[str, Any]]


class TemplateMarketplace:
    """
    Community template marketplace.
    Manages template sharing, reviews, and distribution.
    """
    
    def __init__(self, storage_path: str = "marketplace_data"):
        self.storage_path = storage_path
        self.templates = {}
        self.reviews = {}
        self.authors = {}
        self.categories = {}
        self.stats = MarketplaceStats(
            total_templates=0,
            active_templates=0,
            pending_templates=0,
            total_downloads=0,
            total_authors=0,
            average_rating=0.0,
            top_categories=[],
            recent_activity=[]
        )
        
        # Initialize storage
        self._initialize_storage()
        
        # Load existing data
        self._load_data()
    
    def _initialize_storage(self) -> None:
        """Initialize storage directories"""
        os.makedirs(self.storage_path, exist_ok=True)
        os.makedirs(f"{self.storage_path}/templates", exist_ok=True)
        os.makedirs(f"{self.storage_path}/previews", exist_ok=True)
        os.makedirs(f"{self.storage_path}/reviews", exist_ok=True)
    
    def _load_data(self) -> None:
        """Load existing marketplace data"""
        try:
            # Load templates
            templates_file = f"{self.storage_path}/templates.json"
            if os.path.exists(templates_file):
                with open(templates_file, 'r') as f:
                    templates_data = json.load(f)
                    for template_data in templates_data:
                        template = self._deserialize_template(template_data)
                        self.templates[template.template_id] = template
            
            # Load reviews
            reviews_file = f"{self.storage_path}/reviews.json"
            if os.path.exists(reviews_file):
                with open(reviews_file, 'r') as f:
                    reviews_data = json.load(f)
                    for review_data in reviews_data:
                        review = self._deserialize_review(review_data)
                        self.reviews[review.review_id] = review
            
            # Update statistics
            self._update_statistics()
            
        except Exception as e:
            print(f"Error loading marketplace data: {e}")
    
    def _save_data(self) -> None:
        """Save marketplace data to storage"""
        try:
            # Save templates
            templates_file = f"{self.storage_path}/templates.json"
            templates_data = [self._serialize_template(template) for template in self.templates.values()]
            with open(templates_file, 'w') as f:
                json.dump(templates_data, f, indent=2, default=str)
            
            # Save reviews
            reviews_file = f"{self.storage_path}/reviews.json"
            reviews_data = [self._serialize_review(review) for review in self.reviews.values()]
            with open(reviews_file, 'w') as f:
                json.dump(reviews_data, f, indent=2, default=str)
            
        except Exception as e:
            print(f"Error saving marketplace data: {e}")
    
    def submit_template(self, name: str, description: str, author: str, author_email: str,
                       category: TemplateCategory, target_platform: str, html_content: str,
                       css_content: str, js_content: str, tags: List[str],
                       license: str = "MIT", price: float = 0.0, is_premium: bool = False) -> str:
        """Submit a new template to the marketplace"""
        template_id = str(uuid.uuid4())
        
        # Calculate checksum
        content = f"{html_content}{css_content}{js_content}"
        checksum = hashlib.sha256(content.encode()).hexdigest()
        
        # Calculate file size
        file_size = len(html_content.encode()) + len(css_content.encode()) + len(js_content.encode())
        
        # Create template
        template = MarketplaceTemplate(
            template_id=template_id,
            name=name,
            description=description,
            author=author,
            author_email=author_email,
            category=category,
            target_platform=target_platform,
            html_content=html_content,
            css_content=css_content,
            js_content=js_content,
            preview_image="",  # Would be generated/uploaded
            tags=tags,
            status=TemplateStatus.PENDING,
            rating=0.0,
            download_count=0,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            file_size=file_size,
            checksum=checksum,
            version="1.0.0",
            license=license,
            price=price,
            is_premium=is_premium,
            featured=False,
            metadata={
                'submission_ip': '127.0.0.1',  # Would be actual IP
                'submission_user_agent': 'VANTABLACK-Marketplace/1.0'
            }
        )
        
        # Store template
        self.templates[template_id] = template
        
        # Save data
        self._save_data()
        
        # Update statistics
        self._update_statistics()
        
        return template_id
    
    def approve_template(self, template_id: str, reviewer: str, notes: str = "") -> bool:
        """Approve a pending template"""
        if template_id not in self.templates:
            return False
        
        template = self.templates[template_id]
        if template.status != TemplateStatus.PENDING:
            return False
        
        template.status = TemplateStatus.APPROVED
        template.updated_at = datetime.now()
        
        # Add approval metadata
        template.metadata['approved_by'] = reviewer
        template.metadata['approved_at'] = datetime.now().isoformat()
        template.metadata['approval_notes'] = notes
        
        # Save data
        self._save_data()
        
        # Update statistics
        self._update_statistics()
        
        return True
    
    def reject_template(self, template_id: str, reviewer: str, reason: str = "") -> bool:
        """Reject a pending template"""
        if template_id not in self.templates:
            return False
        
        template = self.templates[template_id]
        if template.status != TemplateStatus.PENDING:
            return False
        
        template.status = TemplateStatus.REJECTED
        template.updated_at = datetime.now()
        
        # Add rejection metadata
        template.metadata['rejected_by'] = reviewer
        template.metadata['rejected_at'] = datetime.now().isoformat()
        template.metadata['rejection_reason'] = reason
        
        # Save data
        self._save_data()
        
        # Update statistics
        self._update_statistics()
        
        return True
    
    def flag_template(self, template_id: str, reporter: str, reason: str = "") -> bool:
        """Flag a template for review"""
        if template_id not in self.templates:
            return False
        
        template = self.templates[template_id]
        if template.status != TemplateStatus.APPROVED:
            return False
        
        template.status = TemplateStatus.FLAGGED
        template.updated_at = datetime.now()
        
        # Add flag metadata
        template.metadata['flagged_by'] = reporter
        template.metadata['flagged_at'] = datetime.now().isoformat()
        template.metadata['flag_reason'] = reason
        
        # Save data
        self._save_data()
        
        return True
    
    def download_template(self, template_id: str, downloader: str) -> Optional[Dict[str, Any]]:
        """Download a template"""
        if template_id not in self.templates:
            return None
        
        template = self.templates[template_id]
        if template.status != TemplateStatus.APPROVED:
            return None
        
        # Increment download count
        template.download_count += 1
        template.updated_at = datetime.now()
        
        # Add download metadata
        template.metadata.setdefault('downloads', []).append({
            'downloader': downloader,
            'timestamp': datetime.now().isoformat(),
            'ip_address': '127.0.0.1'  # Would be actual IP
        })
        
        # Save data
        self._save_data()
        
        # Return template data
        return {
            'template_id': template.template_id,
            'name': template.name,
            'description': template.description,
            'author': template.author,
            'category': template.category.value,
            'target_platform': template.target_platform,
            'html_content': template.html_content,
            'css_content': template.css_content,
            'js_content': template.js_content,
            'tags': template.tags,
            'version': template.version,
            'license': template.license,
            'checksum': template.checksum
        }
    
    def add_review(self, template_id: str, reviewer: str, rating: int, comment: str,
                  pros: List[str] = None, cons: List[str] = None) -> str:
        """Add a review for a template"""
        if template_id not in self.templates:
            return None
        
        template = self.templates[template_id]
        if template.status != TemplateStatus.APPROVED:
            return None
        
        # Check if user already reviewed
        for review in self.reviews.values():
            if review.template_id == template_id and review.reviewer == reviewer:
                return None  # User already reviewed
        
        review_id = str(uuid.uuid4())
        
        review = TemplateReview(
            review_id=review_id,
            template_id=template_id,
            reviewer=reviewer,
            rating=rating,
            comment=comment,
            pros=pros or [],
            cons=cons or [],
            created_at=datetime.now(),
            helpful_count=0
        )
        
        # Store review
        self.reviews[review_id] = review
        
        # Update template rating
        self._update_template_rating(template_id)
        
        # Save data
        self._save_data()
        
        return review_id
    
    def search_templates(self, query: str = "", category: TemplateCategory = None,
                        platform: str = "", tags: List[str] = None,
                        min_rating: float = 0.0, max_price: float = None,
                        featured_only: bool = False, limit: int = 50) -> List[MarketplaceTemplate]:
        """Search templates with filters"""
        results = []
        
        for template in self.templates.values():
            if template.status != TemplateStatus.APPROVED:
                continue
            
            # Text search
            if query:
                query_lower = query.lower()
                if (query_lower not in template.name.lower() and
                    query_lower not in template.description.lower() and
                    query_lower not in template.author.lower() and
                    not any(query_lower in tag.lower() for tag in template.tags)):
                    continue
            
            # Category filter
            if category and template.category != category:
                continue
            
            # Platform filter
            if platform and platform.lower() not in template.target_platform.lower():
                continue
            
            # Tags filter
            if tags and not any(tag in template.tags for tag in tags):
                continue
            
            # Rating filter
            if template.rating < min_rating:
                continue
            
            # Price filter
            if max_price is not None and template.price > max_price:
                continue
            
            # Featured filter
            if featured_only and not template.featured:
                continue
            
            results.append(template)
        
        # Sort by rating and download count
        results.sort(key=lambda t: (t.rating, t.download_count), reverse=True)
        
        return results[:limit]
    
    def get_template_details(self, template_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed template information"""
        if template_id not in self.templates:
            return None
        
        template = self.templates[template_id]
        
        # Get reviews
        template_reviews = [review for review in self.reviews.values() 
                          if review.template_id == template_id]
        
        # Calculate rating distribution
        rating_distribution = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
        for review in template_reviews:
            rating_distribution[review.rating] += 1
        
        return {
            'template': asdict(template),
            'reviews': [asdict(review) for review in template_reviews],
            'rating_distribution': rating_distribution,
            'similar_templates': self._get_similar_templates(template_id)
        }
    
    def _get_similar_templates(self, template_id: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Get similar templates"""
        if template_id not in self.templates:
            return []
        
        template = self.templates[template_id]
        similar = []
        
        for other_template in self.templates.values():
            if (other_template.template_id != template_id and
                other_template.status == TemplateStatus.APPROVED):
                
                # Calculate similarity score
                score = 0.0
                
                # Same category
                if other_template.category == template.category:
                    score += 0.3
                
                # Same platform
                if other_template.target_platform == template.target_platform:
                    score += 0.2
                
                # Shared tags
                shared_tags = set(template.tags) & set(other_template.tags)
                score += len(shared_tags) * 0.1
                
                # Similar rating
                rating_diff = abs(other_template.rating - template.rating)
                score += max(0, 1.0 - rating_diff) * 0.1
                
                if score > 0.1:  # Minimum similarity threshold
                    similar.append({
                        'template_id': other_template.template_id,
                        'name': other_template.name,
                        'author': other_template.author,
                        'rating': other_template.rating,
                        'download_count': other_template.download_count,
                        'similarity_score': score
                    })
        
        # Sort by similarity score
        similar.sort(key=lambda x: x['similarity_score'], reverse=True)
        
        return similar[:limit]
    
    def get_popular_templates(self, category: TemplateCategory = None, 
                            platform: str = "", limit: int = 10) -> List[Dict[str, Any]]:
        """Get popular templates"""
        templates = self.search_templates(category=category, platform=platform, limit=100)
        
        # Sort by download count and rating
        templates.sort(key=lambda t: (t.download_count, t.rating), reverse=True)
        
        return [
            {
                'template_id': t.template_id,
                'name': t.name,
                'author': t.author,
                'category': t.category.value,
                'target_platform': t.target_platform,
                'rating': t.rating,
                'download_count': t.download_count,
                'price': t.price,
                'featured': t.featured,
                'tags': t.tags
            }
            for t in templates[:limit]
        ]
    
    def get_featured_templates(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get featured templates"""
        featured = [t for t in self.templates.values() 
                   if t.status == TemplateStatus.APPROVED and t.featured]
        
        # Sort by rating and download count
        featured.sort(key=lambda t: (t.rating, t.download_count), reverse=True)
        
        return [
            {
                'template_id': t.template_id,
                'name': t.name,
                'author': t.author,
                'category': t.category.value,
                'target_platform': t.target_platform,
                'rating': t.rating,
                'download_count': t.download_count,
                'price': t.price,
                'tags': t.tags,
                'description': t.description
            }
            for t in featured[:limit]
        ]
    
    def get_author_templates(self, author: str) -> List[Dict[str, Any]]:
        """Get templates by author"""
        author_templates = [t for t in self.templates.values() if t.author == author]
        
        return [
            {
                'template_id': t.template_id,
                'name': t.name,
                'category': t.category.value,
                'target_platform': t.target_platform,
                'status': t.status.value,
                'rating': t.rating,
                'download_count': t.download_count,
                'created_at': t.created_at.isoformat(),
                'updated_at': t.updated_at.isoformat()
            }
            for t in author_templates
        ]
    
    def get_marketplace_stats(self) -> MarketplaceStats:
        """Get marketplace statistics"""
        return self.stats
    
    def _update_statistics(self) -> None:
        """Update marketplace statistics"""
        total_templates = len(self.templates)
        active_templates = len([t for t in self.templates.values() 
                               if t.status == TemplateStatus.APPROVED])
        pending_templates = len([t for t in self.templates.values() 
                                if t.status == TemplateStatus.PENDING])
        total_downloads = sum(t.download_count for t in self.templates.values())
        total_authors = len(set(t.author for t in self.templates.values()))
        
        # Calculate average rating
        approved_templates = [t for t in self.templates.values() 
                            if t.status == TemplateStatus.APPROVED]
        average_rating = sum(t.rating for t in approved_templates) / len(approved_templates) if approved_templates else 0.0
        
        # Top categories
        category_counts = {}
        for template in approved_templates:
            category_counts[template.category.value] = category_counts.get(template.category.value, 0) + 1
        
        top_categories = sorted([
            {'category': cat, 'count': count}
            for cat, count in category_counts.items()
        ], key=lambda x: x['count'], reverse=True)[:5]
        
        # Recent activity (last 7 days)
        recent_activity = []
        cutoff_date = datetime.now() - timedelta(days=7)
        
        for template in self.templates.values():
            if template.updated_at > cutoff_date:
                recent_activity.append({
                    'type': 'template_updated',
                    'template_id': template.template_id,
                    'name': template.name,
                    'timestamp': template.updated_at.isoformat()
                })
        
        for review in self.reviews.values():
            if review.created_at > cutoff_date:
                recent_activity.append({
                    'type': 'review_added',
                    'template_id': review.template_id,
                    'reviewer': review.reviewer,
                    'rating': review.rating,
                    'timestamp': review.created_at.isoformat()
                })
        
        recent_activity.sort(key=lambda x: x['timestamp'], reverse=True)
        
        self.stats = MarketplaceStats(
            total_templates=total_templates,
            active_templates=active_templates,
            pending_templates=pending_templates,
            total_downloads=total_downloads,
            total_authors=total_authors,
            average_rating=average_rating,
            top_categories=top_categories,
            recent_activity=recent_activity[:10]
        )
    
    def _update_template_rating(self, template_id: str) -> None:
        """Update template rating based on reviews"""
        if template_id not in self.templates:
            return
        
        template = self.templates[template_id]
        template_reviews = [review for review in self.reviews.values() 
                          if review.template_id == template_id]
        
        if template_reviews:
            template.rating = sum(review.rating for review in template_reviews) / len(template_reviews)
        else:
            template.rating = 0.0
        
        template.updated_at = datetime.now()
    
    def _serialize_template(self, template: MarketplaceTemplate) -> Dict[str, Any]:
        """Serialize template for storage"""
        data = asdict(template)
        data['category'] = template.category.value
        data['status'] = template.status.value
        data['created_at'] = template.created_at.isoformat()
        data['updated_at'] = template.updated_at.isoformat()
        return data
    
    def _deserialize_template(self, data: Dict[str, Any]) -> MarketplaceTemplate:
        """Deserialize template from storage"""
        data['category'] = TemplateCategory(data['category'])
        data['status'] = TemplateStatus(data['status'])
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        data['updated_at'] = datetime.fromisoformat(data['updated_at'])
        return MarketplaceTemplate(**data)
    
    def _serialize_review(self, review: TemplateReview) -> Dict[str, Any]:
        """Serialize review for storage"""
        data = asdict(review)
        data['created_at'] = review.created_at.isoformat()
        return data
    
    def _deserialize_review(self, data: Dict[str, Any]) -> TemplateReview:
        """Deserialize review from storage"""
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        return TemplateReview(**data)
    
    def feature_template(self, template_id: str, featured: bool = True) -> bool:
        """Feature or unfeature a template"""
        if template_id not in self.templates:
            return False
        
        template = self.templates[template_id]
        template.featured = featured
        template.updated_at = datetime.now()
        
        # Save data
        self._save_data()
        
        return True
    
    def get_pending_templates(self) -> List[Dict[str, Any]]:
        """Get templates pending approval"""
        pending = [t for t in self.templates.values() if t.status == TemplateStatus.PENDING]
        
        return [
            {
                'template_id': t.template_id,
                'name': t.name,
                'author': t.author,
                'author_email': t.author_email,
                'category': t.category.value,
                'target_platform': t.target_platform,
                'description': t.description,
                'tags': t.tags,
                'created_at': t.created_at.isoformat(),
                'file_size': t.file_size
            }
            for t in pending
        ]
    
    def get_flagged_templates(self) -> List[Dict[str, Any]]:
        """Get flagged templates needing review"""
        flagged = [t for t in self.templates.values() if t.status == TemplateStatus.FLAGGED]
        
        return [
            {
                'template_id': t.template_id,
                'name': t.name,
                'author': t.author,
                'category': t.category.value,
                'target_platform': t.target_platform,
                'rating': t.rating,
                'download_count': t.download_count,
                'flagged_at': t.metadata.get('flagged_at'),
                'flag_reason': t.metadata.get('flag_reason', '')
            }
            for t in flagged
        ]
    
    def export_template_package(self, template_id: str) -> Optional[Dict[str, Any]]:
        """Export template as a package"""
        if template_id not in self.templates:
            return None
        
        template = self.templates[template_id]
        if template.status != TemplateStatus.APPROVED:
            return None
        
        # Create package
        package = {
            'package_info': {
                'name': template.name,
                'version': template.version,
                'description': template.description,
                'author': template.author,
                'license': template.license,
                'created_at': template.created_at.isoformat(),
                'package_format': 'vantablack_template_v1'
            },
            'template': {
                'category': template.category.value,
                'target_platform': template.target_platform,
                'tags': template.tags,
                'html_content': template.html_content,
                'css_content': template.css_content,
                'js_content': template.js_content
            },
            'metadata': {
                'checksum': template.checksum,
                'file_size': template.file_size,
                'rating': template.rating,
                'download_count': template.download_count
            }
        }
        
        return package
    
    def import_template_package(self, package_data: Dict[str, Any], 
                               importer: str) -> Optional[str]:
        """Import a template package"""
        try:
            package_info = package_data['package_info']
            template_data = package_data['template']
            metadata = package_data['metadata']
            
            # Validate package format
            if package_info.get('package_format') != 'vantablack_template_v1':
                return None
            
            # Submit as new template
            template_id = self.submit_template(
                name=package_info['name'],
                description=package_info['description'],
                author=importer,
                author_email=f"{importer}@vantablack.local",
                category=TemplateCategory(template_data['category']),
                target_platform=template_data['target_platform'],
                html_content=template_data['html_content'],
                css_content=template_data['css_content'],
                js_content=template_data['js_content'],
                tags=template_data['tags'],
                license=package_info.get('license', 'MIT'),
                price=0.0,  # Imported templates are free
                is_premium=False
            )
            
            # Add import metadata
            if template_id and template_id in self.templates:
                template = self.templates[template_id]
                template.metadata['imported_from'] = package_info.get('name', 'Unknown')
                template.metadata['imported_at'] = datetime.now().isoformat()
                template.metadata['original_author'] = package_info.get('author', 'Unknown')
                template.metadata['original_checksum'] = metadata.get('checksum', '')
            
            return template_id
            
        except Exception as e:
            print(f"Error importing template package: {e}")
            return None
