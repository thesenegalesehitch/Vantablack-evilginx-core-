"""
VANTABLACK Behavioral Analysis Module
=====================================

Advanced victim behavior analysis and campaign optimization:
- User interaction tracking
- Behavioral pattern recognition
- Campaign performance analytics
- Conversion rate optimization
- A/B testing analytics
- Attack vector prediction (Markov, Bayes, Poisson, Ensemble)
"""

from .analyzer import BehavioralAnalyzer
from .optimizer import CampaignOptimizer
from .predictor import (
    ATTACK_STATES,
    BehaviorPredictor,
    BivariatePoissonTimingModel,
    EnsembleMetaLearner,
    EnsemblePrediction,
    MarkovChainAttackPredictor,
    NaiveBayesAttackClassifier,
    PredictionResult,
    UserSegment,
)
from .tracker import UserTracker

__all__ = [
    "ATTACK_STATES",
    "BehaviorPredictor",
    "BehavioralAnalyzer",
    "BivariatePoissonTimingModel",
    "CampaignOptimizer",
    "EnsembleMetaLearner",
    "EnsemblePrediction",
    "MarkovChainAttackPredictor",
    "NaiveBayesAttackClassifier",
    "PredictionResult",
    "UserSegment",
    "UserTracker",
]
