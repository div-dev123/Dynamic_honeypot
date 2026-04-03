# ml/ml_pipeline.py

import numpy as np
import pickle
from tensorflow import keras

class MLPipeline:
    def __init__(self, models_dir='ml/models'):
        print('🧠 Loading ML pipeline...')

        # Supervised classifier
        self.main_model = keras.models.load_model(
            f'{models_dir}/model_FINAL_v3.keras')

        # R2L vs U2R specialist
        with open(f'{models_dir}/model_specialist_r2l_u2r.pkl', 'rb') as f:
            self.specialist = pickle.load(f)

        # Anomaly detectors
        self.autoencoder = keras.models.load_model(
            f'{models_dir}/model_autoencoder.keras')
        with open(f'{models_dir}/model_isolation_forest.pkl', 'rb') as f:
            self.iso_forest = pickle.load(f)

        # Config + artifacts
        with open(f'{models_dir}/final_pipeline.pkl', 'rb') as f:
            self.pipeline_cfg = pickle.load(f)
        with open(f'{models_dir}/anomaly_artifacts.pkl', 'rb') as f:
            self.anomaly_cfg = pickle.load(f)
        with open(f'{models_dir}/artifacts.pkl', 'rb') as f:
            artifacts = pickle.load(f)

        self.label_encoder = artifacts['label_encoder']
        self.class_names   = list(self.label_encoder.classes_)
        self.r2l_idx       = self.class_names.index('R2L')
        self.u2r_idx       = self.class_names.index('U2R')
        self.conf_threshold = self.pipeline_cfg['confidence_threshold']
        self.ae_threshold   = self.anomaly_cfg['ae_threshold']

        print('✅ ML pipeline loaded')

    def predict(self, feature_vector):
        """
        Returns full prediction result dict for one connection.
        feature_vector: numpy array shape (1, n_features)
        """
        # ── Layer 1: Anomaly Detection ────────────────────────
        ae_recon     = self.autoencoder.predict(feature_vector, verbose=0)
        ae_error     = float(np.mean((feature_vector - ae_recon) ** 2))
        iso_score    = float(-self.iso_forest.decision_function(
                             feature_vector)[0])

        is_anomaly   = ae_error > self.ae_threshold
        zero_day     = False

        # ── Layer 2: Classification ───────────────────────────
        probs        = self.main_model.predict(feature_vector, verbose=0)[0]
        pred_idx     = int(np.argmax(probs))
        confidence   = float(np.max(probs))

        # ── Layer 3: Specialist for R2L/U2R ───────────────────
        if pred_idx in [self.r2l_idx, self.u2r_idx] \
                and confidence < self.conf_threshold:
            specialist_pred = self.specialist.predict(feature_vector)[0]
            pred_idx = self.r2l_idx if specialist_pred == 0 \
                       else self.u2r_idx

        # Variety-first labeling: keep the classifier label for dashboards.
        # Zero-day becomes a *flag* (still surfaced via ml_zero_day), instead of
        # overriding the main attack_type label.
        attack_label = self.class_names[pred_idx]

        # Zero-Day: anomaly + very low confidence + strong reconstruction error.
        # This makes Zero-Day rarer and prevents "everything" from collapsing to it.
        if is_anomaly and confidence < (self.conf_threshold * 0.75) and ae_error > (self.ae_threshold * 1.5):
            zero_day = True

        return {
            'attack_type'   : attack_label,
            'confidence'    : round(confidence * 100, 2),
            'is_anomaly'    : is_anomaly,
            'zero_day'      : zero_day,
            'ae_error'      : round(ae_error, 4),
            'iso_score'     : round(iso_score, 4),
            'probabilities' : {
                cls: round(float(p) * 100, 2)
                for cls, p in zip(self.class_names, probs)
            }
        }