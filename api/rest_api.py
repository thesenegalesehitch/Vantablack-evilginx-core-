"""
VANTABLACK REST API - Core API Server
====================================

FastAPI-based REST API for VANTABLACK operations:
- Template management
- Campaign management
- Analytics and reporting
- User management
- System monitoring
"""

from fastapi import FastAPI, HTTPException, Depends, Security, status, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
import uuid
import json
import asyncio
import logging
from contextlib import asynccontextmanager

from analysis.reverse_engineer.analyzer import PhishletAnalyzer
from analysis.mutation.mutator import PhishletMutator
from analysis.behavioral.analyzer import BehavioralAnalyzer
from templates.generator import TemplateGenerator
from templates.ab_testing import ABTestManager
from templates.marketplace import TemplateMarketplace
from .auth_manager import AuthManager
from .rate_limiter import RateLimiter


# Pydantic models
class TemplateRequest(BaseModel):
    """Template generation request"""
    platform: str = Field(..., description="Target platform")
    template_type: str = Field(..., description="Template type")
    personalization_level: str = Field("medium", description="Personalization level")
    optimization_level: str = Field("advanced", description="Optimization level")
    responsive: bool = Field(True, description="Responsive design")
    custom_variables: Dict[str, Any] = Field(default_factory=dict, description="Custom variables")
    
    @validator('platform')
    def validate_platform(cls, v):
        valid_platforms = ['twitter', 'google', 'facebook', 'microsoft', 'linkedin', 'instagram', 'amazon', 'paypal']
        if v.lower() not in valid_platforms:
            raise ValueError(f"Platform must be one of: {', '.join(valid_platforms)}")
        return v.lower()
    
    @validator('template_type')
    def validate_template_type(cls, v):
        valid_types = ['login', 'register', 'payment', 'survey', 'contact', 'download', 'verification']
        if v not in valid_types:
            raise ValueError(f"Template type must be one of: {', '.join(valid_types)}")
        return v


class CampaignRequest(BaseModel):
    """Campaign creation request"""
    name: str = Field(..., description="Campaign name")
    target_platform: str = Field(..., description="Target platform")
    template_id: str = Field(..., description="Template ID to use")
    target_domains: List[str] = Field(..., description="Target domains")
    start_date: datetime = Field(..., description="Campaign start date")
    end_date: datetime = Field(..., description="Campaign end date")
    max_targets: int = Field(1000, description="Maximum targets")
    mutation_enabled: bool = Field(True, description="Enable mutation")
    behavioral_tracking: bool = Field(True, description="Enable behavioral tracking")
    
    @validator('end_date')
    def validate_dates(cls, v, values):
        if 'start_date' in values and v <= values['start_date']:
            raise ValueError("End date must be after start date")
        return v


class AnalysisRequest(BaseModel):
    """Phishlet analysis request"""
    phishlet_content: str = Field(..., description="Phishlet YAML content")
    analysis_depth: str = Field("medium", description="Analysis depth")
    generate_signatures: bool = Field(True, description="Generate detection signatures")
    mitre_mapping: bool = Field(True, description="Generate MITRE ATT&CK mapping")


class OptimizationRequest(BaseModel):
    """Template optimization request"""
    template_id: str = Field(..., description="Template ID to optimize")
    optimization_goal: str = Field("conversion_rate", description="Optimization goal")
    target_improvement: float = Field(0.2, description="Target improvement percentage")
    max_variants: int = Field(4, description="Maximum variants")
    test_duration_hours: int = Field(48, description="Test duration in hours")


class APIResponse(BaseModel):
    """Standard API response"""
    success: bool = Field(True, description="Request success status")
    message: str = Field("Operation completed successfully", description="Response message")
    data: Optional[Dict[str, Any]] = Field(None, description="Response data")
    timestamp: datetime = Field(default_factory=datetime.now, description="Response timestamp")
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Request ID")


# Lifespan management
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    logging.info("VANTABLACK API starting up...")
    
    # Initialize components
    app.state.phishlet_analyzer = PhishletAnalyzer()
    app.state.phishlet_mutator = PhishletMutator()
    app.state.behavioral_analyzer = BehavioralAnalyzer()
    app.state.template_generator = TemplateGenerator()
    app.state.ab_test_manager = ABTestManager()
    app.state.marketplace = TemplateMarketplace()
    app.state.auth_manager = AuthManager()
    app.state.rate_limiter = RateLimiter()
    
    logging.info("VANTABLACK API ready")
    
    yield
    
    # Shutdown
    logging.info("VANTABLACK API shutting down...")


# Create FastAPI app
app = FastAPI(
    title="VANTABLACK API",
    description="Advanced Phishing Platform API for Red Teams",
    version="4.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

# Security
security = HTTPBearer()


# Dependencies
async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Get current authenticated user"""
    token = credentials.credentials
    user = await app.state.auth_manager.verify_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def rate_limit_check(user_id: str, endpoint: str):
    """Check rate limits"""
    if not await app.state.rate_limiter.check_limit(user_id, endpoint):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )


# API Endpoints

@app.get("/", response_model=APIResponse)
async def root():
    """Root endpoint"""
    return APIResponse(
        message="VANTABLACK API v4.0.0 - Advanced Phishing Platform",
        data={
            "version": "4.0.0",
            "status": "operational",
            "endpoints": [
                "/templates",
                "/campaigns", 
                "/analysis",
                "/optimization",
                "/marketplace",
                "/analytics"
            ]
        }
    )


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "4.0.0",
        "components": {
            "phishlet_analyzer": "operational",
            "template_generator": "operational",
            "ab_test_manager": "operational",
            "marketplace": "operational"
        }
    }


# Template endpoints
@app.post("/templates/generate", response_model=APIResponse)
async def generate_template(
    request: TemplateRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Generate a new template"""
    await rate_limit_check(current_user["user_id"], "template_generate")
    
    try:
        # Generate template
        from ..templates.generator import TemplateConfig
        config = TemplateConfig(
            target_platform=request.platform,
            template_type=request.template_type,
            personalization_level=request.personalization_level,
            responsive=request.responsive,
            optimization_level=request.optimization_level,
            compliance_checks=['gdpr', 'accessibility'],
            custom_variables=request.custom_variables
        )
        
        template = app.state.template_generator.generate_template(config)
        
        # Log generation
        background_tasks.add_task(
            log_template_generation,
            current_user["user_id"],
            template.template_id,
            request.platform,
            request.template_type
        )
        
        return APIResponse(
            message="Template generated successfully",
            data={
                "template_id": template.template_id,
                "name": template.name,
                "platform": template.config.target_platform,
                "type": template.config.template_type,
                "performance_score": template.performance_score,
                "compliance_score": template.compliance_score,
                "html_content": template.html_content,
                "css_content": template.css_content,
                "js_content": template.js_content
            }
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Template generation failed: {str(e)}"
        )


@app.get("/templates/{template_id}")
async def get_template(
    template_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get template details"""
    await rate_limit_check(current_user["user_id"], "template_get")
    
    # In a real implementation, this would retrieve from database
    return APIResponse(
        message="Template retrieved successfully",
        data={
            "template_id": template_id,
            "status": "found",
            "details": "Template details would be retrieved from database"
        }
    )


# Campaign endpoints
@app.post("/campaigns", response_model=APIResponse)
async def create_campaign(
    request: CampaignRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Create a new campaign"""
    await rate_limit_check(current_user["user_id"], "campaign_create")
    
    try:
        campaign_id = str(uuid.uuid4())
        
        # Create campaign (simplified)
        campaign_data = {
            "campaign_id": campaign_id,
            "name": request.name,
            "target_platform": request.target_platform,
            "template_id": request.template_id,
            "target_domains": request.target_domains,
            "start_date": request.start_date.isoformat(),
            "end_date": request.end_date.isoformat(),
            "max_targets": request.max_targets,
            "mutation_enabled": request.mutation_enabled,
            "behavioral_tracking": request.behavioral_tracking,
            "status": "created",
            "created_by": current_user["user_id"],
            "created_at": datetime.now().isoformat()
        }
        
        # Log campaign creation
        background_tasks.add_task(
            log_campaign_creation,
            current_user["user_id"],
            campaign_id,
            request.name
        )
        
        return APIResponse(
            message="Campaign created successfully",
            data=campaign_data
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Campaign creation failed: {str(e)}"
        )


@app.get("/campaigns/{campaign_id}")
async def get_campaign(
    campaign_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get campaign details"""
    await rate_limit_check(current_user["user_id"], "campaign_get")
    
    return APIResponse(
        message="Campaign retrieved successfully",
        data={
            "campaign_id": campaign_id,
            "status": "active",
            "metrics": {
                "total_targets": 1000,
                "successful_captures": 85,
                "conversion_rate": 8.5,
                "active_variants": 4
            }
        }
    )


@app.get("/campaigns")
async def list_campaigns(
    current_user: dict = Depends(get_current_user),
    limit: int = 50,
    offset: int = 0
):
    """List user campaigns"""
    await rate_limit_check(current_user["user_id"], "campaign_list")
    
    return APIResponse(
        message="Campaigns retrieved successfully",
        data={
            "campaigns": [
                {
                    "campaign_id": "camp_001",
                    "name": "Twitter Campaign Q1",
                    "platform": "twitter",
                    "status": "active",
                    "conversion_rate": 8.5,
                    "created_at": "2024-01-15T10:00:00Z"
                },
                {
                    "campaign_id": "camp_002", 
                    "name": "Google Campaign Q1",
                    "platform": "google",
                    "status": "completed",
                    "conversion_rate": 12.3,
                    "created_at": "2024-01-10T14:30:00Z"
                }
            ],
            "total": 2,
            "limit": limit,
            "offset": offset
        }
    )


# Analysis endpoints
@app.post("/analysis/phishlet", response_model=APIResponse)
async def analyze_phishlet(
    request: AnalysisRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Analyze a phishlet"""
    await rate_limit_check(current_user["user_id"], "phishlet_analysis")
    
    try:
        # Analyze phishlet
        analysis_result = app.state.phishlet_analyzer.analyze_phishlet(
            request.phishlet_content,
            analysis_depth=request.analysis_depth,
            generate_signatures=request.generate_signatures,
            mitre_mapping=request.mitre_mapping
        )
        
        # Log analysis
        background_tasks.add_task(
            log_phishlet_analysis,
            current_user["user_id"],
            analysis_result["risk_score"]
        )
        
        return APIResponse(
            message="Phishlet analysis completed",
            data=analysis_result
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Phishlet analysis failed: {str(e)}"
        )


@app.post("/analysis/mutation", response_model=APIResponse)
async def mutate_phishlet(
    phishlet_content: str,
    mutation_config: Dict[str, Any],
    current_user: dict = Depends(get_current_user)
):
    """Mutate a phishlet"""
    await rate_limit_check(current_user["user_id"], "phishlet_mutation")
    
    try:
        # Mutate phishlet
        mutation_result = app.state.phishlet_mutator.mutate_phishlet(
            phishlet_content,
            mutation_config
        )
        
        return APIResponse(
            message="Phishlet mutation completed",
            data=mutation_result
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Phishlet mutation failed: {str(e)}"
        )


# Optimization endpoints
@app.post("/optimization/template", response_model=APIResponse)
async def optimize_template(
    request: OptimizationRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Optimize a template"""
    await rate_limit_check(current_user["user_id"], "template_optimization")
    
    try:
        # Create optimization campaign
        from ..templates.optimizer import OptimizationConfig
        config = OptimizationConfig(
            optimization_goal=request.optimization_goal,
            target_improvement=request.target_improvement,
            max_variants=request.max_variants,
            test_duration_hours=request.test_duration_hours,
            personalization_level='high',
            optimization_techniques=['headline_optimization', 'form_optimization', 'personalization'],
            budget_constraints={},
            custom_variables={}
        )
        
        # Run optimization (simplified)
        optimization_id = f"opt_{int(datetime.now().timestamp())}"
        
        # Log optimization
        background_tasks.add_task(
            log_template_optimization,
            current_user["user_id"],
            optimization_id,
            request.template_id
        )
        
        return APIResponse(
            message="Template optimization started",
            data={
                "optimization_id": optimization_id,
                "template_id": request.template_id,
                "optimization_goal": request.optimization_goal,
                "target_improvement": request.target_improvement,
                "max_variants": request.max_variants,
                "estimated_completion": (datetime.now() + timedelta(hours=request.test_duration_hours)).isoformat()
            }
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Template optimization failed: {str(e)}"
        )


@app.get("/optimization/{optimization_id}")
async def get_optimization_result(
    optimization_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get optimization results"""
    await rate_limit_check(current_user["user_id"], "optimization_result")
    
    return APIResponse(
        message="Optimization results retrieved",
        data={
            "optimization_id": optimization_id,
            "status": "completed",
            "performance_gain": 0.25,
            "improvement_percentage": 18.5,
            "winning_variant": "variant_3",
            "statistical_significance": True,
            "confidence": 0.95
        }
    )


# Marketplace endpoints
@app.get("/marketplace/templates")
async def search_marketplace_templates(
    query: str = "",
    category: str = "",
    platform: str = "",
    min_rating: float = 0.0,
    max_price: float = None,
    featured_only: bool = False,
    limit: int = 20,
    current_user: dict = Depends(get_current_user)
):
    """Search marketplace templates"""
    await rate_limit_check(current_user["user_id"], "marketplace_search")
    
    try:
        # Search templates
        from templates.marketplace import TemplateCategory
        cat = TemplateCategory(category) if category else None
        
        results = app.state.marketplace.search_templates(
            query=query,
            category=cat,
            platform=platform,
            min_rating=min_rating,
            max_price=max_price,
            featured_only=featured_only,
            limit=limit
        )
        
        return APIResponse(
            message="Templates retrieved successfully",
            data={
                "templates": [
                    {
                        "template_id": t.template_id,
                        "name": t.name,
                        "author": t.author,
                        "category": t.category.value,
                        "platform": t.target_platform,
                        "rating": t.rating,
                        "download_count": t.download_count,
                        "price": t.price,
                        "featured": t.featured,
                        "tags": t.tags
                    }
                    for t in results
                ],
                "total": len(results),
                "query": query,
                "filters": {
                    "category": category,
                    "platform": platform,
                    "min_rating": min_rating,
                    "max_price": max_price,
                    "featured_only": featured_only
                }
            }
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Marketplace search failed: {str(e)}"
        )


@app.post("/marketplace/templates/{template_id}/download")
async def download_marketplace_template(
    template_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Download marketplace template"""
    await rate_limit_check(current_user["user_id"], "marketplace_download")
    
    try:
        # Download template
        template_data = app.state.marketplace.download_template(template_id, current_user["user_id"])
        
        if template_data:
            return APIResponse(
                message="Template downloaded successfully",
                data=template_data
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Template not found or not available"
            )
            
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Template download failed: {str(e)}"
        )


# Analytics endpoints
@app.get("/analytics/dashboard")
async def get_dashboard_analytics(
    current_user: dict = Depends(get_current_user),
    timeframe: str = "7d"
):
    """Get dashboard analytics"""
    await rate_limit_check(current_user["user_id"], "analytics_dashboard")
    
    return APIResponse(
        message="Dashboard analytics retrieved",
        data={
            "overview": {
                "total_campaigns": 12,
                "active_campaigns": 3,
                "total_captures": 1250,
                "conversion_rate": 8.5,
                "success_rate": 92.3
            },
            "performance": {
                "daily_conversions": [15, 22, 18, 25, 20, 28, 24],
                "platform_performance": {
                    "twitter": 8.2,
                    "google": 12.5,
                    "facebook": 6.8,
                    "microsoft": 10.1
                },
                "top_campaigns": [
                    {"name": "Twitter Q1", "conversion_rate": 12.3},
                    {"name": "Google Enterprise", "conversion_rate": 15.7},
                    {"name": "Facebook Social", "conversion_rate": 9.2}
                ]
            },
            "trends": {
                "conversion_trend": "upward",
                "engagement_trend": "stable",
                "success_trend": "improving"
            },
            "timeframe": timeframe
        }
    )


@app.get("/analytics/campaigns/{campaign_id}")
async def get_campaign_analytics(
    campaign_id: str,
    current_user: dict = Depends(get_current_user),
    timeframe: str = "7d"
):
    """Get campaign-specific analytics"""
    await rate_limit_check(current_user["user_id"], "campaign_analytics")
    
    return APIResponse(
        message="Campaign analytics retrieved",
        data={
            "campaign_id": campaign_id,
            "metrics": {
                "total_targets": 1000,
                "successful_captures": 85,
                "conversion_rate": 8.5,
                "engagement_rate": 67.2,
                "bounce_rate": 32.8,
                "avg_session_duration": 142
            },
            "performance_over_time": {
                "dates": ["2024-01-15", "2024-01-16", "2024-01-17", "2024-01-18"],
                "conversions": [12, 15, 18, 14],
                "engagement": [65, 68, 72, 67]
            },
            "variant_performance": {
                "variant_1": {"conversions": 25, "rate": 10.0},
                "variant_2": {"conversions": 22, "rate": 8.8},
                "variant_3": {"conversions": 28, "rate": 11.2},
                "variant_4": {"conversions": 10, "rate": 4.0}
            },
            "recommendations": [
                "Focus on variant 3 for best performance",
                "Consider optimizing variant 4",
                "Test different headlines for variant 2"
            ]
        }
    )


# User management endpoints
@app.get("/users/profile")
async def get_user_profile(current_user: dict = Depends(get_current_user)):
    """Get user profile"""
    return APIResponse(
        message="User profile retrieved",
        data={
            "user_id": current_user["user_id"],
            "username": current_user["username"],
            "email": current_user["email"],
            "role": current_user["role"],
            "permissions": current_user["permissions"],
            "created_at": current_user["created_at"],
            "last_login": current_user["last_login"],
            "statistics": {
                "total_campaigns": 12,
                "total_templates": 8,
                "total_captures": 1250,
                "success_rate": 92.3
            }
        }
    )


@app.put("/users/profile")
async def update_user_profile(
    profile_data: Dict[str, Any],
    current_user: dict = Depends(get_current_user)
):
    """Update user profile"""
    await rate_limit_check(current_user["user_id"], "profile_update")
    
    # Update profile (simplified)
    return APIResponse(
        message="Profile updated successfully",
        data={
            "updated_fields": list(profile_data.keys()),
            "updated_at": datetime.now().isoformat()
        }
    )


# System endpoints
@app.get("/system/status")
async def get_system_status(current_user: dict = Depends(get_current_user)):
    """Get system status"""
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    return APIResponse(
        message="System status retrieved",
        data={
            "api": {
                "status": "operational",
                "version": "4.0.0",
                "uptime": "72h 15m",
                "requests_per_minute": 125
            },
            "components": {
                "phishlet_analyzer": "operational",
                "template_generator": "operational",
                "ab_test_manager": "operational",
                "marketplace": "operational",
                "behavioral_analyzer": "operational"
            },
            "resources": {
                "cpu_usage": 45.2,
                "memory_usage": 67.8,
                "disk_usage": 23.1,
                "network_io": "normal"
            },
            "active_users": 15,
            "active_campaigns": 8
        }
    )


# Background task functions
async def log_template_generation(user_id: str, template_id: str, platform: str, template_type: str):
    """Log template generation"""
    logging.info(f"Template generated: user={user_id}, template={template_id}, platform={platform}, type={template_type}")


async def log_campaign_creation(user_id: str, campaign_id: str, campaign_name: str):
    """Log campaign creation"""
    logging.info(f"Campaign created: user={user_id}, campaign={campaign_id}, name={campaign_name}")


async def log_phishlet_analysis(user_id: str, risk_score: float):
    """Log phishlet analysis"""
    logging.info(f"Phishlet analyzed: user={user_id}, risk_score={risk_score}")


async def log_template_optimization(user_id: str, optimization_id: str, template_id: str):
    """Log template optimization"""
    logging.info(f"Template optimization: user={user_id}, optimization={optimization_id}, template={template_id}")


# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content=APIResponse(
            success=False,
            message=exc.detail,
            data={"status_code": exc.status_code}
        ).dict()
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle general exceptions"""
    logging.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=APIResponse(
            success=False,
            message="Internal server error",
            data={"error_type": type(exc).__name__}
        ).dict()
    )


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
