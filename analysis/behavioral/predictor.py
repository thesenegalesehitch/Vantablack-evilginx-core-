"""
Behavior Predictor - Machine Learning Prediction Engine
======================================================

Predicts user behavior and campaign outcomes:
- Conversion probability prediction
- User segmentation prediction
- Churn prediction
- Optimal timing prediction
- Performance forecasting
"""

import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, mean_squared_error
import pickle


@dataclass
class PredictionResult:
    """Prediction result with confidence"""
    prediction: Any
    confidence: float
    model_version: str
    features_used: List[str]
    timestamp: datetime


@dataclass
class UserSegment:
    """User segment prediction"""
    segment_id: str
    segment_name: str
    characteristics: Dict[str, Any]
    conversion_probability: float
    value_score: float
    recommended_actions: List[str]


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
    
    def prepare_features(self, data: List[Dict[str, Any]], 
                        target_column: str = None) -> Tuple[pd.DataFrame, Optional[pd.Series]]:
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
    
    def train_conversion_model(self, training_data: List[Dict[str, Any]]) -> Dict[str, Any]:
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
    
    def train_timing_model(self, training_data: List[Dict[str, Any]]) -> Dict[str, Any]:
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
    
    def predict_conversion_probability(self, user_data: Dict[str, Any]) -> PredictionResult:
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
    
    def predict_optimal_timing(self, campaign_data: Dict[str, Any]) -> PredictionResult:
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
    
    def predict_user_segments(self, user_data: List[Dict[str, Any]], 
                            num_segments: int = 5) -> List[UserSegment]:
        """Predict user segments using clustering approach"""
        if not user_data:
            return []
        
        # Prepare features
        X, _ = self.prepare_features(user_data)
        
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
    
    def predict_campaign_performance(self, campaign_config: Dict[str, Any], 
                                   historical_data: List[Dict[str, Any]] = None) -> Dict[str, Any]:
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
    
    def forecast_performance(self, current_data: Dict[str, Any], 
                           forecast_days: int = 30) -> Dict[str, Any]:
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
        for model_name in self.model_types.keys():
            model_path = os.path.join(model_dir, f"{model_name}_model.pkl")
            if os.path.exists(model_path):
                with open(model_path, 'rb') as f:
                    self.models[model_name] = pickle.load(f)
        
        # Load scalers
        for model_name in self.model_types.keys():
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
    
    def get_model_summary(self) -> Dict[str, Any]:
        """Get summary of all trained models"""
        summary = {
            'trained_models': list(self.models.keys()),
            'model_performance': self.model_performance,
            'feature_importance': self.feature_importance,
            'available_features': list(self.feature_categories.keys())
        }
        
        return summary
