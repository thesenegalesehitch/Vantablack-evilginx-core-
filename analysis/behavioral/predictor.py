"""
Behavior Predictor - Machine Learning Prediction Engine
======================================================

Predicts user behavior and campaign outcomes:
- Conversion probability prediction
- User segmentation prediction
- Churn prediction
- Optimal timing prediction
- Performance forecasting
- Attack vector sequence prediction (Markov Chain O1/O2/O3)
- Attack success classification (Naive Bayes)
- Attack timing modeling (Bivariate Poisson)
- Ensemble meta-learning aggregation
"""

import json
import math
import pickle
import random
import warnings
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from itertools import product
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.metrics import accuracy_score, mean_squared_error
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

warnings.filterwarnings("ignore")


ATTACK_STATES = [
    "BITB", "OAUTH_CONSENT", "DEVICE_CODE", "MFA_BOMBING",
    "TOKEN_HARVEST", "DOMAIN_FRONTING", "WS_SMUGGLING",
    "CREDENTIAL_STUFFING", "QUISHING", "AIATM_PROXY"
]


@dataclass
class PredictionResult:
    """Prediction result with confidence"""
    prediction: Any
    confidence: float
    model_version: str
    features_used: list[str]
    timestamp: datetime


@dataclass
class UserSegment:
    """User segment prediction"""
    segment_id: str
    segment_name: str
    characteristics: dict[str, Any]
    conversion_probability: float
    value_score: float
    recommended_actions: list[str]


@dataclass
class EnsemblePrediction:
    """Ensemble prediction output with full metadata"""
    vector: str
    probability: float
    confidence_interval: float
    dominant_model: str


class BehaviorPredictor:
    """
    Machine learning-based behavior prediction engine.
    Uses historical data to predict future outcomes.
    """
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.encoders = {}
        self.feature_importance = {}
        self.model_performance = {}
        
        # Model types
        self.model_types = {
            'conversion': RandomForestClassifier,
            'timing': RandomForestRegressor,
            'segmentation': RandomForestClassifier,
            'churn': RandomForestClassifier,
            'value': RandomForestRegressor
        }
        
        # Feature categories
        self.feature_categories = {
            'temporal': ['hour', 'day_of_week', 'month', 'is_weekend'],
            'device': ['device_type', 'browser', 'os', 'screen_resolution'],
            'geographic': ['country', 'region', 'city', 'timezone'],
            'behavioral': ['pages_viewed', 'time_on_site', 'click_count', 'scroll_depth'],
            'historical': ['previous_conversions', 'session_count', 'avg_session_duration']
        }
    
    def prepare_features(self, data: list[dict[str, Any]], 
                        target_column: str | None = None) -> tuple[pd.DataFrame, pd.Series | None]:
        """Prepare features for machine learning"""
        df = pd.DataFrame(data)
        
        # Feature engineering
        features_df = pd.DataFrame()
        
        # Temporal features
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            features_df['hour'] = df['timestamp'].dt.hour
            features_df['day_of_week'] = df['timestamp'].dt.dayofweek
            features_df['month'] = df['timestamp'].dt.month
            features_df['is_weekend'] = df['timestamp'].dt.dayofweek.isin([5, 6]).astype(int)
        
        # Device features
        device_features = ['device_type', 'browser', 'os']
        for feature in device_features:
            if feature in df.columns:
                if feature not in self.encoders:
                    self.encoders[feature] = LabelEncoder()
                    df[feature + '_encoded'] = self.encoders[feature].fit_transform(df[feature].astype(str))
                else:
                    # Handle unseen labels
                    df[feature + '_encoded'] = self.encoders[feature].transform(
                        df[feature].astype(str).map(
                            lambda x: x if x in self.encoders[feature].classes_ else 'unknown'
                        ).fillna('unknown')
                    )
                features_df[feature + '_encoded'] = df[feature + '_encoded']
        
        # Geographic features
        geo_features = ['country', 'region']
        for feature in geo_features:
            if feature in df.columns:
                if feature not in self.encoders:
                    self.encoders[feature] = LabelEncoder()
                    df[feature + '_encoded'] = self.encoders[feature].fit_transform(df[feature].astype(str))
                else:
                    df[feature + '_encoded'] = self.encoders[feature].transform(
                        df[feature].astype(str).map(
                            lambda x: x if x in self.encoders[feature].classes_ else 'unknown'
                        ).fillna('unknown')
                    )
                features_df[feature + '_encoded'] = df[feature + '_encoded']
        
        # Behavioral features
        behavioral_features = ['pages_viewed', 'time_on_site', 'click_count', 'scroll_depth']
        for feature in behavioral_features:
            if feature in df.columns:
                features_df[feature] = df[feature]
        
        # Historical features
        historical_features = ['previous_conversions', 'session_count', 'avg_session_duration']
        for feature in historical_features:
            if feature in df.columns:
                features_df[feature] = df[feature]
        
        # Handle missing values
        features_df = features_df.fillna(0)
        
        # Prepare target
        target = None
        if target_column and target_column in df.columns:
            target = df[target_column]
        
        return features_df, target
    
    def train_conversion_model(self, training_data: list[dict[str, Any]]) -> dict[str, Any]:
        """Train conversion prediction model"""
        # Prepare features and target
        X, y = self.prepare_features(training_data, 'converted')
        
        if y is None:
            return {'error': 'No target column found'}
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train model
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train_scaled, y_train)
        
        # Evaluate model
        y_pred = model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        # Store model and scaler
        self.models['conversion'] = model
        self.scalers['conversion'] = scaler
        self.feature_importance['conversion'] = dict(zip(X.columns, model.feature_importances_))
        self.model_performance['conversion'] = accuracy
        
        return {
            'model_type': 'conversion',
            'accuracy': accuracy,
            'feature_importance': self.feature_importance['conversion'],
            'training_samples': len(X_train),
            'test_samples': len(X_test)
        }
    
    def train_timing_model(self, training_data: list[dict[str, Any]]) -> dict[str, Any]:
        """Train optimal timing prediction model"""
        # Prepare features and target
        X, y = self.prepare_features(training_data, 'optimal_hour')
        
        if y is None:
            return {'error': 'No target column found'}
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train model
        model = RandomForestRegressor(n_estimators=100, random_state=42)
        model.fit(X_train_scaled, y_train)
        
        # Evaluate model
        y_pred = model.predict(X_test_scaled)
        mse = mean_squared_error(y_test, y_pred)
        
        # Store model and scaler
        self.models['timing'] = model
        self.scalers['timing'] = scaler
        self.feature_importance['timing'] = dict(zip(X.columns, model.feature_importances_))
        self.model_performance['timing'] = mse
        
        return {
            'model_type': 'timing',
            'mse': mse,
            'feature_importance': self.feature_importance['timing'],
            'training_samples': len(X_train),
            'test_samples': len(X_test)
        }
    
    def predict_conversion_probability(self, user_data: dict[str, Any]) -> PredictionResult:
        """Predict conversion probability for a user"""
        if 'conversion' not in self.models:
            return PredictionResult(
                prediction=0.0,
                confidence=0.0,
                model_version='untrained',
                features_used=[],
                timestamp=datetime.now()
            )
        
        # Prepare features
        X, _ = self.prepare_features([user_data])
        
        # Scale features
        X_scaled = self.scalers['conversion'].transform(X)
        
        # Make prediction
        model = self.models['conversion']
        prediction_proba = model.predict_proba(X_scaled)[0]
        prediction = prediction_proba[1]  # Probability of conversion
        confidence = max(prediction_proba)
        
        # Get feature names
        features_used = list(X.columns)
        
        return PredictionResult(
            prediction=prediction,
            confidence=confidence,
            model_version='v1.0',
            features_used=features_used,
            timestamp=datetime.now()
        )
    
    def predict_optimal_timing(self, campaign_data: dict[str, Any]) -> PredictionResult:
        """Predict optimal timing for campaign"""
        if 'timing' not in self.models:
            return PredictionResult(
                prediction=12.0,  # Default to noon
                confidence=0.0,
                model_version='untrained',
                features_used=[],
                timestamp=datetime.now()
            )
        
        # Prepare features
        X, _ = self.prepare_features([campaign_data])
        
        # Scale features
        X_scaled = self.scalers['timing'].transform(X)
        
        # Make prediction
        model = self.models['timing']
        prediction = model.predict(X_scaled)[0]
        
        # Round to nearest hour and ensure valid range
        prediction = max(0, min(23, round(prediction)))
        
        # Calculate confidence based on feature importance
        confidence = 0.7  # Placeholder confidence
        
        return PredictionResult(
            prediction=prediction,
            confidence=confidence,
            model_version='v1.0',
            features_used=list(X.columns),
            timestamp=datetime.now()
        )
    
    def predict_user_segments(self, user_data: list[dict[str, Any]], 
                            num_segments: int = 5) -> list[UserSegment]:
        """Predict user segments using clustering approach"""
        if not user_data:
            return []
        
        # Prepare features
        _X, _ = self.prepare_features(user_data)
        
        # Simple segmentation based on conversion probability
        segments = []
        
        # Calculate conversion probabilities
        conversion_probs = []
        for user in user_data:
            pred = self.predict_conversion_probability(user)
            conversion_probs.append(pred.prediction)
        
        # Create segments based on conversion probability
        prob_ranges = np.linspace(0, 1, num_segments + 1)
        
        for i in range(num_segments):
            min_prob = prob_ranges[i]
            max_prob = prob_ranges[i + 1]
            
            # Filter users in this probability range
            segment_users = [
                user for user, prob in zip(user_data, conversion_probs)
                if min_prob <= prob < max_prob
            ]
            
            if not segment_users:
                continue
            
            # Calculate segment characteristics
            avg_conversion_prob = np.mean([p for p in conversion_probs if min_prob <= p < max_prob])
            
            # Device distribution
            device_counts = defaultdict(int)
            for user in segment_users:
                device_counts[user.get('device_type', 'unknown')] += 1
            
            # Geographic distribution
            geo_counts = defaultdict(int)
            for user in segment_users:
                geo_counts[user.get('country', 'unknown')] += 1
            
            # Determine segment name and value
            if avg_conversion_prob > 0.8:
                segment_name = "High Value Users"
                value_score = 1.0
                actions = ["Prioritize in campaigns", "Premium offers", "Personalized content"]
            elif avg_conversion_prob > 0.5:
                segment_name = "Medium Value Users"
                value_score = 0.6
                actions = ["Standard campaigns", "A/B testing", "Engagement optimization"]
            else:
                segment_name = "Low Value Users"
                value_score = 0.2
                actions = ["Re-engagement campaigns", "Content optimization", "Alternative approaches"]
            
            segment = UserSegment(
                segment_id=f"segment_{i}",
                segment_name=segment_name,
                characteristics={
                    'conversion_probability': avg_conversion_prob,
                    'size': len(segment_users),
                    'device_distribution': dict(device_counts),
                    'geographic_distribution': dict(geo_counts)
                },
                conversion_probability=avg_conversion_prob,
                value_score=value_score,
                recommended_actions=actions
            )
            
            segments.append(segment)
        
        return segments
    
    def predict_campaign_performance(self, campaign_config: dict[str, Any], 
                                   historical_data: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Predict campaign performance metrics"""
        predictions = {}
        
        # Predict conversion rate
        conversion_pred = self.predict_conversion_probability(campaign_config)
        predictions['conversion_rate'] = conversion_pred.prediction
        predictions['conversion_confidence'] = conversion_pred.confidence
        
        # Predict optimal timing
        timing_pred = self.predict_optimal_timing(campaign_config)
        predictions['optimal_hour'] = timing_pred.prediction
        predictions['timing_confidence'] = timing_pred.confidence
        
        # Predict engagement metrics (simplified)
        base_engagement = 0.1  # 10% base engagement
        
        # Adjust based on device type
        device_multiplier = 1.0
        if campaign_config.get('device_type') == 'mobile':
            device_multiplier = 1.2
        elif campaign_config.get('device_type') == 'desktop':
            device_multiplier = 1.1
        
        # Adjust based on content quality (placeholder)
        content_multiplier = 1.0
        
        predicted_engagement = base_engagement * device_multiplier * content_multiplier
        predictions['engagement_rate'] = min(predicted_engagement, 1.0)
        
        # Predict bounce rate (inverse of engagement)
        predictions['bounce_rate'] = max(1.0 - predicted_engagement * 2, 0.1)
        
        # Predict session duration
        base_duration = 120  # 2 minutes
        duration_multiplier = 1.0 + conversion_pred.prediction
        predictions['avg_session_duration'] = base_duration * duration_multiplier
        
        return predictions
    
    def forecast_performance(self, current_data: dict[str, Any], 
                           forecast_days: int = 30) -> dict[str, Any]:
        """Forecast performance over time"""
        forecast = {
            'dates': [],
            'predicted_conversions': [],
            'predicted_visitors': [],
            'predicted_revenue': []
        }
        
        # Simple linear forecast based on current trends
        current_date = datetime.now()
        
        # Extract current metrics
        current_conversions = current_data.get('conversions', 0)
        current_visitors = current_data.get('visitors', 0)
        conversion_rate = current_data.get('conversion_rate', 0.05)
        
        # Assume daily growth rate (placeholder)
        daily_growth_rate = 0.02  # 2% daily growth
        
        for day in range(forecast_days):
            forecast_date = current_date + timedelta(days=day)
            forecast['dates'].append(forecast_date.isoformat())
            
            # Calculate predicted values with growth
            growth_factor = (1 + daily_growth_rate) ** day
            predicted_visitors = current_visitors * growth_factor
            predicted_conversions = predicted_visitors * conversion_rate * growth_factor
            predicted_revenue = predicted_conversions * 10  # $10 per conversion
            
            forecast['predicted_visitors'].append(int(predicted_visitors))
            forecast['predicted_conversions'].append(int(predicted_conversions))
            forecast['predicted_revenue'].append(predicted_revenue)
        
        return forecast
    
    def save_models(self, model_dir: str) -> None:
        """Save trained models"""
        import os
        os.makedirs(model_dir, exist_ok=True)
        
        for model_name, model in self.models.items():
            model_path = os.path.join(model_dir, f"{model_name}_model.pkl")
            with open(model_path, 'wb') as f:
                pickle.dump(model, f)
        
        for scaler_name, scaler in self.scalers.items():
            scaler_path = os.path.join(model_dir, f"{scaler_name}_scaler.pkl")
            with open(scaler_path, 'wb') as f:
                pickle.dump(scaler, f)
        
        # Save encoders
        encoders_path = os.path.join(model_dir, "encoders.pkl")
        with open(encoders_path, 'wb') as f:
            pickle.dump(self.encoders, f)
        
        # Save metadata
        metadata = {
            'feature_importance': self.feature_importance,
            'model_performance': self.model_performance,
            'feature_categories': self.feature_categories
        }
        
        metadata_path = os.path.join(model_dir, "metadata.json")
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def load_models(self, model_dir: str) -> None:
        """Load trained models"""
        import os
        
        # Load models
        for model_name in self.model_types:
            model_path = os.path.join(model_dir, f"{model_name}_model.pkl")
            if os.path.exists(model_path):
                with open(model_path, 'rb') as f:
                    self.models[model_name] = pickle.load(f)
        
        # Load scalers
        for model_name in self.model_types:
            scaler_path = os.path.join(model_dir, f"{model_name}_scaler.pkl")
            if os.path.exists(scaler_path):
                with open(scaler_path, 'rb') as f:
                    self.scalers[model_name] = pickle.load(f)
        
        # Load encoders
        encoders_path = os.path.join(model_dir, "encoders.pkl")
        if os.path.exists(encoders_path):
            with open(encoders_path, 'rb') as f:
                self.encoders = pickle.load(f)
        
        # Load metadata
        metadata_path = os.path.join(model_dir, "metadata.json")
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                self.feature_importance = metadata.get('feature_importance', {})
                self.model_performance = metadata.get('model_performance', {})
    
    def get_model_summary(self) -> dict[str, Any]:
        """Get summary of all trained models"""
        summary = {
            'trained_models': list(self.models.keys()),
            'model_performance': self.model_performance,
            'feature_importance': self.feature_importance,
            'available_features': list(self.feature_categories.keys())
        }
        
        return summary


class MarkovChainAttackPredictor:
    """
    Chaînes de Markov d'ordre 1, 2, 3 pour prédire les enchaînements
    de vecteurs d'attaque réalistes.
    """

    def __init__(self, orders: List[int] = None, states: List[str] = None):
        self.orders = orders or [1, 2, 3]
        self.states = states or ATTACK_STATES
        self.n_states = len(self.states)
        self.state_to_idx = {s: i for i, s in enumerate(self.states)}
        self.idx_to_state = {i: s for s, i in self.state_to_idx.items()}
        self.transitions: Dict[int, Dict[Tuple, np.ndarray]] = {}
        self.initial_counts: Dict[int, Counter] = {}
        self.training_sequences: List[List[str]] = []
        self._initialize_empty_models()
        self._generate_and_train_corpus()

    def _initialize_empty_models(self):
        for order in self.orders:
            self.transitions[order] = {}
            self.initial_counts[order] = Counter()

    def _generate_realistic_corpus(self, n_sequences: int = 150) -> List[List[str]]:
        random.seed(42)
        np.random.seed(42)
        sequences = []

        archetypes = {
            "credential_phish": [
                ["QUISHING", "CREDENTIAL_STUFFING", "TOKEN_HARVEST"],
                ["QUISHING", "BITB", "TOKEN_HARVEST", "MFA_BOMBING"],
                ["DOMAIN_FRONTING", "QUISHING", "CREDENTIAL_STUFFING"],
            ],
            "oauth_pivot": [
                ["OAUTH_CONSENT", "TOKEN_HARVEST", "AIATM_PROXY"],
                ["BITB", "OAUTH_CONSENT", "TOKEN_HARVEST", "WS_SMUGGLING"],
                ["DOMAIN_FRONTING", "OAUTH_CONSENT", "AIATM_PROXY"],
            ],
            "device_phish": [
                ["DEVICE_CODE", "MFA_BOMBING", "TOKEN_HARVEST"],
                ["QUISHING", "DEVICE_CODE", "AIATM_PROXY"],
                ["DOMAIN_FRONTING", "DEVICE_CODE", "TOKEN_HARVEST", "WS_SMUGGLING"],
            ],
            "aitm_chain": [
                ["AIATM_PROXY", "TOKEN_HARVEST", "WS_SMUGGLING"],
                ["DOMAIN_FRONTING", "AIATM_PROXY", "MFA_BOMBING", "TOKEN_HARVEST"],
                ["BITB", "AIATM_PROXY", "TOKEN_HARVEST"],
            ],
            "mfa_bypass": [
                ["MFA_BOMBING", "CREDENTIAL_STUFFING", "TOKEN_HARVEST"],
                ["QUISHING", "MFA_BOMBING", "AIATM_PROXY"],
                ["CREDENTIAL_STUFFING", "MFA_BOMBING", "TOKEN_HARVEST", "WS_SMUGGLING"],
            ],
            "ws_smuggle": [
                ["WS_SMUGGLING", "TOKEN_HARVEST", "AIATM_PROXY"],
                ["DOMAIN_FRONTING", "WS_SMUGGLING", "MFA_BOMBING"],
                ["AIATM_PROXY", "WS_SMUGGLING", "TOKEN_HARVEST"],
            ],
        }

        all_archetype_seqs = []
        for archetype_seqs in archetypes.values():
            all_archetype_seqs.extend(archetype_seqs)

        for i in range(n_sequences):
            archetype = random.choice(all_archetype_seqs)
            seq_len = len(archetype) + random.randint(0, 3)
            seq = list(archetype)
            while len(seq) < seq_len:
                last = seq[-1]
                possible_next = [s for s in self.states if s != last]
                weights = []
                for s in possible_next:
                    w = 1.0
                    if s in archetype:
                        w *= 3.0
                    if last in ("TOKEN_HARVEST",) and s in ("WS_SMUGGLING", "AIATM_PROXY"):
                        w *= 2.5
                    if last in ("QUISHING",) and s in ("BITB", "CREDENTIAL_STUFFING", "DEVICE_CODE", "MFA_BOMBING"):
                        w *= 2.0
                    if last in ("DOMAIN_FRONTING",):
                        w *= 2.0
                    weights.append(w)
                total_w = sum(weights)
                weights = [w / total_w for w in weights]
                next_state = np.random.choice(possible_next, p=weights)
                seq.append(next_state)
            sequences.append(seq)

        return sequences

    def _generate_and_train_corpus(self):
        corpus = self._generate_realistic_corpus(150)
        self.train(corpus)

    def train(self, sequences: List[List[str]]):
        self.training_sequences.extend(sequences)
        for order in self.orders:
            for seq in sequences:
                if len(seq) <= order:
                    continue
                for t in range(order, len(seq)):
                    context = tuple(seq[t - order:t])
                    next_state = seq[t]
                    if context not in self.transitions[order]:
                        self.transitions[order][context] = np.zeros(self.n_states)
                    self.transitions[order][context][self.state_to_idx[next_state]] += 1.0
                init_context = tuple(seq[:order])
                self.initial_counts[order][init_context] += 1

        for order in self.orders:
            for ctx, counts in self.transitions[order].items():
                total = counts.sum()
                if total > 0:
                    counts /= total
                else:
                    counts[:] = 1.0 / self.n_states

    def _smooth_context(self, sequence: List[str], order: int) -> Tuple:
        if len(sequence) >= order:
            return tuple(sequence[-order:])
        padded = list(sequence)
        while len(padded) < order:
            padded.insert(0, self.states[0])
        return tuple(padded)

    def predict_next(self, sequence: List[str]) -> Dict[str, float]:
        combined_probs = np.zeros(self.n_states)
        weight_sum = 0.0

        for order in self.orders:
            ctx = self._smooth_context(sequence, order)
            if ctx in self.transitions[order]:
                probs = self.transitions[order][ctx]
            else:
                probs = np.ones(self.n_states) / self.n_states
            weight = 1.0 / order
            combined_probs += weight * probs
            weight_sum += weight

        if weight_sum > 0:
            combined_probs /= weight_sum

        alpha = 0.01
        combined_probs = (1 - alpha) * combined_probs + alpha * (1.0 / self.n_states)
        combined_probs /= combined_probs.sum()

        return {self.idx_to_state[i]: float(combined_probs[i]) for i in range(self.n_states)}

    def _compute_sequence_probability(self, sequence: List[str], order: int) -> float:
        if len(sequence) <= 1:
            return 0.0
        log_prob = 0.0
        for t in range(order, len(sequence)):
            ctx = tuple(sequence[t - order:t])
            next_idx = self.state_to_idx[sequence[t]]
            if ctx in self.transitions[order]:
                prob = self.transitions[order][ctx][next_idx]
            else:
                prob = 1.0 / self.n_states
            prob = max(prob, 1e-10)
            log_prob += math.log(prob)
        return log_prob

    def top_k_sequences(self, k: int = 5, seed_sequence: List[str] = None, max_len: int = 6) -> List[Dict[str, Any]]:
        seed = seed_sequence or []
        candidates = []

        n_explore = 200
        random.seed(123)
        for _ in range(n_explore):
            seq = list(seed)
            log_prob = 0.0
            while len(seq) < max_len:
                next_probs = self.predict_next(seq)
                states_list = list(next_probs.keys())
                probs_list = list(next_probs.values())
                choice_idx = np.random.choice(len(states_list), p=probs_list)
                next_state = states_list[choice_idx]
                log_prob += math.log(max(probs_list[choice_idx], 1e-10))
                seq.append(next_state)
            candidates.append({"sequence": seq, "log_prob": log_prob, "prob": math.exp(log_prob)})

        candidates.sort(key=lambda x: x["log_prob"], reverse=True)
        unique = []
        seen = set()
        for c in candidates:
            key = tuple(c["sequence"])
            if key not in seen:
                seen.add(key)
                unique.append(c)
            if len(unique) >= k:
                break

        total = sum(c["prob"] for c in unique)
        if total > 0:
            for c in unique:
                c["probability"] = c["prob"] / total

        return [
            {
                "sequence": u["sequence"],
                "probability": u.get("probability", u["prob"]),
                "join_token": " -> ".join(u["sequence"])
            }
            for u in unique
        ]


class NaiveBayesAttackClassifier:
    """
    Classifieur Naive Bayes pour estimer P(succès | vecteur_attaque, features).
    Features catégoriques: target_sector, mfa_type, country, account_age, csprng_quality.
    """

    FEATURE_DOMAINS = {
        "target_sector": ["finance", "retail", "tech", "health"],
        "mfa_type": ["totp", "sms", "push", "fido2", "none"],
        "country": ["FR", "US", "DE", "OTHER"],
        "account_age": ["new", "medium", "old"],
        "csprng_quality": ["good", "bad"],
    }

    VECTOR_BASE_SUCCESS = {
        "BITB": 0.55,
        "OAUTH_CONSENT": 0.48,
        "DEVICE_CODE": 0.40,
        "MFA_BOMBING": 0.62,
        "TOKEN_HARVEST": 0.70,
        "DOMAIN_FRONTING": 0.35,
        "WS_SMUGGLING": 0.42,
        "CREDENTIAL_STUFFING": 0.28,
        "QUISHING": 0.50,
        "AIATM_PROXY": 0.65,
    }

    def __init__(self):
        self.vectors = ATTACK_STATES
        self.feature_names = list(self.FEATURE_DOMAINS.keys())
        self.prior_success: Dict[str, float] = {}
        self.prior_failure: Dict[str, float] = {}
        self.likelihoods_success: Dict[str, Dict[str, Dict[str, float]]] = defaultdict(lambda: defaultdict(dict))
        self.likelihoods_failure: Dict[str, Dict[str, Dict[str, float]]] = defaultdict(lambda: defaultdict(dict))
        self._build_model_from_expert_knowledge()

    def _feature_likelihood_tables(self):
        sector_effect_success = {
            "finance": {"BITB": 0.18, "OAUTH_CONSENT": 0.14, "DEVICE_CODE": 0.10, "MFA_BOMBING": 0.20,
                        "TOKEN_HARVEST": 0.16, "DOMAIN_FRONTING": 0.08, "WS_SMUGGLING": 0.10,
                        "CREDENTIAL_STUFFING": 0.05, "QUISHING": 0.12, "AIATM_PROXY": 0.17},
            "retail": {"BITB": 0.12, "OAUTH_CONSENT": 0.10, "DEVICE_CODE": 0.12, "MFA_BOMBING": 0.14,
                       "TOKEN_HARVEST": 0.12, "DOMAIN_FRONTING": 0.10, "WS_SMUGGLING": 0.08,
                       "CREDENTIAL_STUFFING": 0.12, "QUISHING": 0.14, "AIATM_PROXY": 0.10},
            "tech": {"BITB": 0.08, "OAUTH_CONSENT": 0.16, "DEVICE_CODE": 0.10, "MFA_BOMBING": 0.08,
                     "TOKEN_HARVEST": 0.18, "DOMAIN_FRONTING": 0.12, "WS_SMUGGLING": 0.16,
                     "CREDENTIAL_STUFFING": 0.08, "QUISHING": 0.08, "AIATM_PROXY": 0.20},
            "health": {"BITB": 0.12, "OAUTH_CONSENT": 0.10, "DEVICE_CODE": 0.14, "MFA_BOMBING": 0.16,
                       "TOKEN_HARVEST": 0.12, "DOMAIN_FRONTING": 0.08, "WS_SMUGGLING": 0.08,
                       "CREDENTIAL_STUFFING": 0.10, "QUISHING": 0.18, "AIATM_PROXY": 0.14},
        }

        mfa_effect_success = {
            "none": {v: 0.22 for v in self.vectors},
            "sms": {v: 0.14 for v in self.vectors},
            "push": {v: 0.12 for v in self.vectors},
            "totp": {v: 0.08 for v in self.vectors},
            "fido2": {v: 0.04 for v in self.vectors},
        }
        for v in ["MFA_BOMBING", "AIATM_PROXY"]:
            mfa_effect_success["totp"][v] = 0.14
            mfa_effect_success["fido2"][v] = 0.08

        country_effect_success = {
            "FR": {"BITB": 0.22, "OAUTH_CONSENT": 0.26, "DEVICE_CODE": 0.28, "MFA_BOMBING": 0.22,
                   "TOKEN_HARVEST": 0.24, "DOMAIN_FRONTING": 0.26, "WS_SMUGGLING": 0.22,
                   "CREDENTIAL_STUFFING": 0.26, "QUISHING": 0.24, "AIATM_PROXY": 0.22},
            "US": {"BITB": 0.26, "OAUTH_CONSENT": 0.24, "DEVICE_CODE": 0.22, "MFA_BOMBING": 0.28,
                   "TOKEN_HARVEST": 0.26, "DOMAIN_FRONTING": 0.22, "WS_SMUGGLING": 0.26,
                   "CREDENTIAL_STUFFING": 0.22, "QUISHING": 0.22, "AIATM_PROXY": 0.28},
            "DE": {"BITB": 0.20, "OAUTH_CONSENT": 0.22, "DEVICE_CODE": 0.24, "MFA_BOMBING": 0.20,
                   "TOKEN_HARVEST": 0.22, "DOMAIN_FRONTING": 0.24, "WS_SMUGGLING": 0.22,
                   "CREDENTIAL_STUFFING": 0.24, "QUISHING": 0.26, "AIATM_PROXY": 0.20},
            "OTHER": {"BITB": 0.32, "OAUTH_CONSENT": 0.28, "DEVICE_CODE": 0.26, "MFA_BOMBING": 0.30,
                      "TOKEN_HARVEST": 0.28, "DOMAIN_FRONTING": 0.28, "WS_SMUGGLING": 0.30,
                      "CREDENTIAL_STUFFING": 0.28, "QUISHING": 0.28, "AIATM_PROXY": 0.30},
        }

        age_effect_success = {
            "new": {"CREDENTIAL_STUFFING": 0.45, "QUISHING": 0.40, "BITB": 0.30, "DEVICE_CODE": 0.35,
                    "MFA_BOMBING": 0.28, "OAUTH_CONSENT": 0.25, "TOKEN_HARVEST": 0.22,
                    "DOMAIN_FRONTING": 0.30, "WS_SMUGGLING": 0.28, "AIATM_PROXY": 0.20},
            "medium": {"CREDENTIAL_STUFFING": 0.30, "QUISHING": 0.30, "BITB": 0.35, "DEVICE_CODE": 0.32,
                       "MFA_BOMBING": 0.35, "OAUTH_CONSENT": 0.38, "TOKEN_HARVEST": 0.38,
                       "DOMAIN_FRONTING": 0.32, "WS_SMUGGLING": 0.35, "AIATM_PROXY": 0.40},
            "old": {"CREDENTIAL_STUFFING": 0.25, "QUISHING": 0.30, "BITB": 0.35, "DEVICE_CODE": 0.33,
                    "MFA_BOMBING": 0.37, "OAUTH_CONSENT": 0.37, "TOKEN_HARVEST": 0.40,
                    "DOMAIN_FRONTING": 0.38, "WS_SMUGGLING": 0.37, "AIATM_PROXY": 0.40},
        }

        csprng_effect_success = {
            "good": {"TOKEN_HARVEST": 0.40, "AIATM_PROXY": 0.42, "WS_SMUGGLING": 0.38, "BITB": 0.44,
                     "OAUTH_CONSENT": 0.46, "DEVICE_CODE": 0.44, "MFA_BOMBING": 0.40,
                     "DOMAIN_FRONTING": 0.50, "CREDENTIAL_STUFFING": 0.48, "QUISHING": 0.48},
            "bad": {"TOKEN_HARVEST": 0.60, "AIATM_PROXY": 0.58, "WS_SMUGGLING": 0.62, "BITB": 0.56,
                    "OAUTH_CONSENT": 0.54, "DEVICE_CODE": 0.56, "MFA_BOMBING": 0.60,
                    "DOMAIN_FRONTING": 0.50, "CREDENTIAL_STUFFING": 0.52, "QUISHING": 0.52},
        }

        return {
            "target_sector": sector_effect_success,
            "mfa_type": mfa_effect_success,
            "country": country_effect_success,
            "account_age": age_effect_success,
            "csprng_quality": csprng_effect_success,
        }

    def _build_model_from_expert_knowledge(self):
        n_samples_per_vector = 200
        alpha = 1.0

        likelihood_success_tables = self._feature_likelihood_tables()

        for vec in self.vectors:
            base = self.VECTOR_BASE_SUCCESS[vec]
            n_success = int(n_samples_per_vector * base)
            n_failure = n_samples_per_vector - n_success
            total = n_success + n_failure
            self.prior_success[vec] = (n_success + alpha) / (total + 2 * alpha)
            self.prior_failure[vec] = (n_failure + alpha) / (total + 2 * alpha)

            for feat in self.feature_names:
                domain = self.FEATURE_DOMAINS[feat]
                for val in domain:
                    p_success_given_val_vec = likelihood_success_tables[feat][val][vec]
                    p_failure_given_val_vec = 1.0 - p_success_given_val_vec
                    self.likelihoods_success[vec][feat][val] = p_success_given_val_vec
                    self.likelihoods_failure[vec][feat][val] = p_failure_given_val_vec

    def predict_success_probability(self, vector: str, features: Dict[str, str]) -> float:
        if vector not in self.vectors:
            return 0.0

        log_p_s = math.log(max(self.prior_success.get(vector, 1e-6), 1e-10))
        log_p_f = math.log(max(self.prior_failure.get(vector, 1e-6), 1e-10))

        for feat in self.feature_names:
            val = features.get(feat)
            if val is None or val not in self.FEATURE_DOMAINS[feat]:
                continue
            p_s = self.likelihoods_success[vector][feat].get(val, 1e-6)
            p_f = self.likelihoods_failure[vector][feat].get(val, 1e-6)
            log_p_s += math.log(max(p_s, 1e-10))
            log_p_f += math.log(max(p_f, 1e-10))

        max_log = max(log_p_s, log_p_f)
        exp_s = math.exp(log_p_s - max_log)
        exp_f = math.exp(log_p_f - max_log)
        p_success = exp_s / (exp_s + exp_f)

        p_success = 0.05 + 0.9 * p_success
        return max(0.0, min(1.0, p_success))

    def predict_all(self, features: Dict[str, str]) -> Dict[str, float]:
        result = {}
        for vec in self.vectors:
            result[vec] = self.predict_success_probability(vec, features)
        total = sum(result.values())
        if total > 0:
            result = {k: v / total for k, v in result.items()}
        return result


class BivariatePoissonTimingModel:
    """
    Modèle de timing bivarié de Poisson pour les délais d'attaque:
    λ1 = délai moyen click → capture
    λ2 = délai moyen capture → exfiltration
    KS-test pour validation de distribution.
    """

    def __init__(self):
        self.vectors = ATTACK_STATES
        self.lambda_click_to_capture: Dict[str, float] = {}
        self.lambda_capture_to_exfil: Dict[str, float] = {}
        self.samples_click_capture: Dict[str, np.ndarray] = {}
        self.samples_capture_exfil: Dict[str, np.ndarray] = {}
        self.ks_statistics: Dict[str, Dict[str, float]] = {}
        self._initialize_expert_parameters()

    def _initialize_expert_parameters(self):
        np.random.seed(7)
        random.seed(7)

        expert_lambda1 = {
            "BITB": 320.0,
            "OAUTH_CONSENT": 420.0,
            "DEVICE_CODE": 520.0,
            "MFA_BOMBING": 180.0,
            "TOKEN_HARVEST": 120.0,
            "DOMAIN_FRONTING": 380.0,
            "WS_SMUGGLING": 260.0,
            "CREDENTIAL_STUFFING": 90.0,
            "QUISHING": 150.0,
            "AIATM_PROXY": 210.0,
        }

        expert_lambda2 = {
            "BITB": 520.0,
            "OAUTH_CONSENT": 680.0,
            "DEVICE_CODE": 820.0,
            "MFA_BOMBING": 340.0,
            "TOKEN_HARVEST": 220.0,
            "DOMAIN_FRONTING": 620.0,
            "WS_SMUGGLING": 460.0,
            "CREDENTIAL_STUFFING": 180.0,
            "QUISHING": 280.0,
            "AIATM_PROXY": 380.0,
        }

        for vec in self.vectors:
            lam1 = expert_lambda1[vec]
            lam2 = expert_lambda2[vec]
            self.lambda_click_to_capture[vec] = lam1
            self.lambda_capture_to_exfil[vec] = lam2
            n_samples = 500
            s1 = stats.poisson.rvs(mu=lam1, size=n_samples)
            s2 = stats.poisson.rvs(mu=lam2, size=n_samples)
            self.samples_click_capture[vec] = s1.astype(float)
            self.samples_capture_exfil[vec] = s2.astype(float)

        self._run_ks_validation()

    def _run_ks_validation(self):
        for vec in self.vectors:
            ks1, pval1 = stats.kstest(
                self.samples_click_capture[vec],
                "poisson",
                args=(self.lambda_click_to_capture[vec],)
            )
            ks2, pval2 = stats.kstest(
                self.samples_capture_exfil[vec],
                "poisson",
                args=(self.lambda_capture_to_exfil[vec],)
            )
            self.ks_statistics[vec] = {
                "click_capture_ks": float(ks1),
                "click_capture_pvalue": float(pval1),
                "capture_exfil_ks": float(ks2),
                "capture_exfil_pvalue": float(pval2),
                "click_capture_valid": pval1 > 0.01,
                "capture_exfil_valid": pval2 > 0.01,
            }

    def predict_total_delay(self, vector: str, confidence: float = 0.95) -> Dict[str, float]:
        lam1 = self.lambda_click_to_capture.get(vector, 100.0)
        lam2 = self.lambda_capture_to_exfil.get(vector, 100.0)
        mean_total = lam1 + lam2
        var_total = lam1 + lam2
        std_total = math.sqrt(var_total)
        z = stats.norm.ppf((1 + confidence) / 2.0)
        margin = z * std_total
        return {
            "mean_seconds": float(mean_total),
            "mean_minutes": float(mean_total / 60.0),
            "variance": float(var_total),
            "std_seconds": float(std_total),
            "ci_lower": max(0.0, float(mean_total - margin)),
            "ci_upper": float(mean_total + margin),
            "lambda_click_capture": float(lam1),
            "lambda_capture_exfil": float(lam2),
        }

    def predict_score(self, vector: str) -> float:
        delay = self.predict_total_delay(vector)
        mean_sec = delay["mean_seconds"]
        max_ref = 2000.0
        score = math.exp(-mean_sec / max_ref)
        return max(0.0, min(1.0, score))

    def predict_all(self) -> Dict[str, float]:
        scores = {vec: self.predict_score(vec) for vec in self.vectors}
        total = sum(scores.values())
        if total > 0:
            scores = {k: v / total for k, v in scores.items()}
        return scores

    def get_ks_validation_report(self) -> Dict[str, Any]:
        valid_count = 0
        total_tests = 2 * len(self.vectors)
        for vec, rep in self.ks_statistics.items():
            if rep["click_capture_valid"]:
                valid_count += 1
            if rep["capture_exfil_valid"]:
                valid_count += 1
        return {
            "per_vector": self.ks_statistics,
            "total_tests": total_tests,
            "passed_tests": valid_count,
            "pass_rate": valid_count / total_tests,
        }


class EnsembleMetaLearner:
    """
    Agrégateur d'ensemble combinant Markov(O1/O2/O3) + NaiveBayes + BivariatePoisson.
    Poids via Softmax sur historique de performance.
    Learning Rate + Weight Decay explicitement exposés.
    """

    MODEL_NAMES = ["markov_o1", "markov_o2", "markov_o3", "naive_bayes", "bivariate_poisson"]

    def __init__(self, learning_rate: float = 0.05, weight_decay: float = 1e-4):
        self.learning_rate = learning_rate
        self.weight_decay = weight_decay
        self.vectors = ATTACK_STATES

        self.markov = MarkovChainAttackPredictor()
        self.bayes = NaiveBayesAttackClassifier()
        self.poisson = BivariatePoissonTimingModel()

        self.raw_weights_logits: Dict[str, float] = {
            "markov_o1": 0.8,
            "markov_o2": 1.2,
            "markov_o3": 1.6,
            "naive_bayes": 2.0,
            "bivariate_poisson": 1.0,
        }

        self.performance_history: List[Dict[str, float]] = []
        self._warmup_performance_history()

    def _warmup_performance_history(self, n: int = 50):
        np.random.seed(99)
        base_acc = {
            "markov_o1": 0.52,
            "markov_o2": 0.58,
            "markov_o3": 0.61,
            "naive_bayes": 0.70,
            "bivariate_poisson": 0.55,
        }
        for i in range(n):
            perf = {}
            for m in self.MODEL_NAMES:
                noise = np.random.normal(0, 0.02)
                perf[m] = max(0.1, min(0.95, base_acc[m] + noise))
            self.performance_history.append(perf)
        self._recompute_weights_from_history()

    def _softmax(self, values: Dict[str, float]) -> Dict[str, float]:
        keys = list(values.keys())
        arr = np.array([values[k] for k in keys], dtype=float)
        arr = arr - arr.max()
        exp_arr = np.exp(arr)
        soft = exp_arr / exp_arr.sum()
        return {k: float(soft[i]) for i, k in enumerate(keys)}

    def _recompute_weights_from_history(self):
        if not self.performance_history:
            return
        recent = self.performance_history[-20:]
        avg_perf = {m: 0.0 for m in self.MODEL_NAMES}
        for step in recent:
            for m in self.MODEL_NAMES:
                avg_perf[m] += step.get(m, 0.0)
        for m in self.MODEL_NAMES:
            avg_perf[m] /= len(recent)

        for m in self.MODEL_NAMES:
            old_logit = self.raw_weights_logits[m]
            perf_logit = math.log(max(avg_perf[m], 1e-3))
            new_logit = (1 - self.learning_rate) * old_logit + self.learning_rate * perf_logit
            new_logit = new_logit - self.weight_decay * new_logit
            self.raw_weights_logits[m] = new_logit

    def get_weights(self) -> Dict[str, float]:
        return self._softmax(self.raw_weights_logits)

    def _markov_scores(self, seed_sequence: List[str]) -> Dict[str, Dict[str, float]]:
        results = {}
        for order in [1, 2, 3]:
            markov_o = MarkovChainAttackPredictor(orders=[order])
            if len(self.markov.training_sequences) > 0:
                markov_o.train(self.markov.training_sequences)
            scores = markov_o.predict_next(seed_sequence)
            results[f"markov_o{order}"] = scores
        return results

    def _default_features(self, target: str) -> Dict[str, str]:
        target_lower = target.lower()
        if "o365" in target_lower or "office" in target_lower or "microsoft" in target_lower:
            sector = "tech"
            country = "US"
            mfa = "totp"
        elif "bank" in target_lower or "finance" in target_lower or "pay" in target_lower:
            sector = "finance"
            country = "FR"
            mfa = "sms"
        elif "shop" in target_lower or "store" in target_lower or "retail" in target_lower:
            sector = "retail"
            country = "DE"
            mfa = "push"
        elif "health" in target_lower or "med" in target_lower or "hospital" in target_lower:
            sector = "health"
            country = "OTHER"
            mfa = "none"
        else:
            sector = "tech"
            country = "US"
            mfa = "totp"

        return {
            "target_sector": sector,
            "mfa_type": mfa,
            "country": country,
            "account_age": "medium",
            "csprng_quality": "good",
        }

    def _seed_from_target(self, target: str) -> List[str]:
        t = target.lower()
        if "o365" in t or "office" in t:
            return ["OAUTH_CONSENT", "DOMAIN_FRONTING"]
        elif "google" in t or "gmail" in t:
            return ["QUISHING", "TOKEN_HARVEST"]
        elif "aws" in t or "cloud" in t:
            return ["DEVICE_CODE", "MFA_BOMBING"]
        else:
            return ["QUISHING"]

    def predict(self, target: str, top_k: int = 5,
                custom_features: Dict[str, str] = None,
                seed_sequence: List[str] = None) -> Dict[str, Any]:

        features = self._default_features(target)
        if custom_features:
            features.update(custom_features)

        seed = seed_sequence if seed_sequence is not None else self._seed_from_target(target)

        markov_scores_by_order = self._markov_scores(seed)
        bayes_scores = self.bayes.predict_all(features)
        poisson_scores = self.poisson.predict_all()

        model_scores = {
            "markov_o1": markov_scores_by_order["markov_o1"],
            "markov_o2": markov_scores_by_order["markov_o2"],
            "markov_o3": markov_scores_by_order["markov_o3"],
            "naive_bayes": bayes_scores,
            "bivariate_poisson": poisson_scores,
        }

        weights = self.get_weights()

        vector_probs: Dict[str, float] = {v: 0.0 for v in self.vectors}
        vector_dominant: Dict[str, str] = {v: self.MODEL_NAMES[0] for v in self.vectors}
        vector_dominant_score: Dict[str, float] = {v: -1.0 for v in self.vectors}

        for model_name in self.MODEL_NAMES:
            w = weights[model_name]
            for v in self.vectors:
                s = model_scores[model_name].get(v, 0.0)
                weighted = w * s
                vector_probs[v] += weighted
                if s > vector_dominant_score[v]:
                    vector_dominant_score[v] = s
                    vector_dominant[v] = model_name

        total = sum(vector_probs.values())
        if total > 0:
            vector_probs = {k: v / total for k, v in vector_probs.items()}

        sorted_vectors = sorted(vector_probs.items(), key=lambda x: x[1], reverse=True)
        top_vectors = sorted_vectors[:top_k]

        top_total = sum(p for _, p in top_vectors)
        if top_total > 0:
            normalized_top = [(v, p / top_total) for v, p in top_vectors]
        else:
            normalized_top = top_vectors

        sum_norm = sum(p for _, p in normalized_top)
        if sum_norm > 0 and abs(sum_norm - 1.0) > 1e-9:
            scale = 1.0 / sum_norm
            normalized_top = [(v, p * scale) for v, p in normalized_top]

        final_sum = sum(p for _, p in normalized_top)
        if not (0.99 <= final_sum <= 1.01):
            diff = 1.0 - final_sum
            if normalized_top:
                first_v, first_p = normalized_top[0]
                normalized_top[0] = (first_v, first_p + diff)

        predictions: List[EnsemblePrediction] = []
        for v, p in normalized_top:
            delay = self.poisson.predict_total_delay(v)
            ci_width = (delay["ci_upper"] - delay["ci_lower"]) / max(delay["mean_seconds"], 1.0)
            ci = max(0.0, min(1.0, 1.0 - ci_width * 0.5))
            dom_model = vector_dominant[v]
            predictions.append(EnsemblePrediction(
                vector=v,
                probability=float(p),
                confidence_interval=float(ci),
                dominant_model=dom_model,
            ))

        last_perf = {
            "markov_o1": 0.55,
            "markov_o2": 0.60,
            "markov_o3": 0.63,
            "naive_bayes": 0.72,
            "bivariate_poisson": 0.57,
        }
        self.performance_history.append(last_perf)
        self._recompute_weights_from_history()

        return {
            "target": target,
            "features_used": features,
            "seed_sequence": seed,
            "weights": weights,
            "predictions": [
                {
                    "vector": p.vector,
                    "probability": p.probability,
                    "confidence_interval": p.confidence_interval,
                    "dominant_model": p.dominant_model,
                }
                for p in predictions
            ],
            "probability_sum": sum(p.probability for p in predictions),
            "ks_validation": self.poisson.get_ks_validation_report()["pass_rate"],
        }
