# ML Pipeline Context — Adaptive Honeypot Integration

## Overview
A 4-layer ML pipeline has been fully built and trained in Google Colab.
All model files are saved and ready for integration.
The pipeline takes raw network connection data as input and returns
attack classification + adaptive deception response as output.

The integration work (connecting honeypot services to ML) has NOT been
done yet. That is what needs to be built now.

---

## What Was Built (Training — DONE)

### Datasets Used
Three datasets were downloaded, preprocessed, and merged:
1. NSL-KDD      — baseline IDS dataset, 41 features, 5 attack classes
2. UNSW-NB15    — modern dataset, merged into NSL-KDD feature space
3. CICIDS2017   — realistic traffic dataset, merged into same feature space

All three were unified into the same 38-feature space using:
- Label encoding for categorical features (protocol_type, service, flag)
- StandardScaler for normalization (fitted on NSL-KDD train set only)
- VarianceThreshold for feature selection
- SMOTE (targeted, minority classes only) for class balancing

The scaler, encoders, label encoder, and variance selector are all saved
in artifacts.pkl. EVERY input to the ML models must be transformed using
these exact artifacts before inference — raw values will not work.

### Unified Label Space
All datasets were mapped to 5 attack categories:
- Normal  → legitimate traffic
- DoS     → denial of service attacks
- Probe   → port scans, reconnaissance
- R2L     → remote to local, brute force, unauthorized access
- U2R     → privilege escalation, SQL injection, web attacks
A 6th label "ZeroDay" is assigned at runtime (not a trained class).

---

## Layer 1 — Anomaly Detection (TRAINED)

Three models trained on NORMAL traffic only.
They learn what normal looks like, then flag deviations.

Models:
- Isolation Forest   AUC = 0.940, Detection Rate = 88.8%
- One-Class SVM      AUC = 0.904, Detection Rate = 86.0%
- Autoencoder        AUC = 0.952, Detection Rate = 97.0% ← primary

The Autoencoder is the most important one.
It compresses and reconstructs input. High reconstruction
error (MSE) means the pattern was never seen in normal traffic.

Thresholds for each model are stored in anomaly_artifacts.pkl:
- iso_threshold        ← Isolation Forest decision threshold
- ocsvm_threshold      ← One-Class SVM threshold
- ae_threshold         ← Autoencoder MSE threshold ← most important
- ensemble_threshold   ← combined score threshold
- confidence_threshold ← 0.70 for Zero-Day labeling

Zero-Day Logic:
If autoencoder reconstruction error > ae_threshold
AND classifier confidence < confidence_threshold (0.70)
→ label the connection as "ZeroDay Suspicious"
This is the novel part of the project — semi-autonomous
detection of unknown attack patterns.

Files:
- model_autoencoder.keras
- model_isolation_forest.pkl
- model_ocsvm.pkl
- anomaly_artifacts.pkl

---

## Layer 2 — Attack Classifier (TRAINED)

Architecture: Neural Network
Layers: Input → Dense(512) → BN → Dropout(0.3)
               → Dense(256) → BN → Dropout(0.3)
               → Dense(128) → BN → Dropout(0.2)
               → Dense(64)  → BN → Dropout(0.2)
               → Dense(32)
               → Dense(5, softmax)

Trained on all three merged datasets with class balancing.
Each class was resampled to 20,000 samples before training.

Performance on combined test set:
- DoS    F1 = 0.696  ✅ acceptable
- Normal F1 = 0.799  ✅ good
- Probe  F1 = 0.675  ✅ acceptable
- R2L    F1 = 0.071  ⚠️ weak (compensated by Layer 1)
- U2R    F1 = 0.100  ⚠️ weak (compensated by Layer 1)
- Overall Accuracy = 68.42%
- Weighted F1 = 0.834

Why R2L and U2R are weak:
The main model over-predicts these classes after balancing.
Precision is very low (0.03-0.05) even though recall is high.
This is a known limitation. The anomaly detection layer (97%
detection rate) compensates by catching these attacks regardless
of classification label.

Files:
- model_FINAL_v3.keras      ← primary classifier (use this)
- model_nn_balanced.keras   ← secondary, used in ensemble experiments

---

## Layer 3 — R2L vs U2R Specialist (TRAINED)

A dedicated Random Forest binary classifier.
Trained ONLY on R2L and U2R samples to resolve confusion
between these two classes specifically.

The t-SNE analysis confirmed R2L and U2R form completely
separate clusters in feature space — they ARE distinguishable.
The main model confuses them with each other, not with Normal.

Specialist performance:
- R2L precision=0.97, recall=0.95, F1=0.96
- U2R precision=0.95, recall=0.97, F1=0.96
- Overall accuracy = 96.03%

Trigger condition (confidence gate):
Only activate specialist when:
  main model predicts R2L or U2R
  AND confidence < 0.60

This prevents the specialist from being overwhelmed by
false positives from the main model.

Files:
- model_specialist_r2l_u2r.pkl
- final_pipeline.pkl  ← stores confidence_threshold=0.60,
                         r2l_idx, u2r_idx, class_names

---

## Layer 4 — Reinforcement Learning Agent (TRAINED)

Algorithm: Q-Learning (tabular, not deep RL)
Training: 10,000 episodes in a simulated honeypot environment
Q-table size: 54 states × 6 actions

State Space (54 total):
  attack_type    × aggressiveness × time_bucket
  [6 types]        [3 levels]       [3 buckets]

  attack_type  : Normal, DoS, Probe, R2L, U2R, ZeroDay
  aggressiveness: low, medium, high
    (computed from: confidence score + request count
     + anomaly error + zero_day flag)
  time_bucket  : just_arrived, exploring, deep_in
    (computed from: number of requests in current session)

Action Space (6 actions):
  0: slow_response      → adds artificial delay, frustrates bots
  1: expose_fake_db     → shows fake database, lures human attackers
  2: redirect_sandbox   → moves to isolated env, safe observation
  3: deep_packet_log    → logs everything in detail, intel gathering
  4: fake_error         → returns fake errors, confuses script kiddies
  5: expose_fake_dirs   → reveals fake directory tree, keeps them busy

Reward Structure:
  +2.0 if attacker reveals more payload
  +1.5 if attacker goes deeper into system
  +1.0 if attacker stays longer
  -1.0 if attacker disconnects early
  -2.0 if attacker detects it is a honeypot
  +0.5 bonus if optimal action chosen for that attack type

Learned optimal actions (examples):
  U2R  + high aggression  → expose_fake_db
  Probe + medium          → expose_fake_dirs
  DoS  + high             → redirect_sandbox
  R2L  + low              → expose_fake_db
  ZeroDay + any           → redirect_sandbox + deep_packet_log

Deception Effectiveness Score (DES) — Novel Metric:
  DES = (time_stayed × 0.4)
      + (payload_revealed × 0.4)
      + (depth_reached × 0.2)
  Range: 0.0 (failed deception) → 1.0 (perfect deception)
  Computed per session, per attacker IP.
  This is an original metric created for this project.

Files:
- rl_agent.pkl  ← contains Q-table, state/action mappings,
                   STATES dict, ACTIONS dict, hyperparameters

---

## All Model Files Summary

Place all of these in ml/models/ folder:

| File                          | Purpose                        |
|-------------------------------|--------------------------------|
| model_FINAL_v3.keras          | Main attack classifier         |
| model_nn_balanced.keras       | Secondary classifier           |
| model_specialist_r2l_u2r.pkl  | R2L vs U2R resolver            |
| model_autoencoder.keras       | Anomaly detection (primary)    |
| model_isolation_forest.pkl    | Anomaly detection              |
| model_ocsvm.pkl               | Anomaly detection              |
| artifacts.pkl                 | Scaler + encoders + features   |
| anomaly_artifacts.pkl         | Anomaly thresholds             |
| final_pipeline.pkl            | Classifier config + thresholds |
| rl_agent.pkl                  | Q-table + state/action maps    |

---

## Integration Code Files (Ready to Use)

Four Python files have been written and are ready for use.
Place them in the project as shown:

ml/feature_extractor.py
  - Class: FeatureExtractor
  - Method: extractor.extract(connection_event) → numpy array
  - Converts raw connection dict into scaled feature vector
  - Handles categorical encoding, scaling, variance selection
  - Tracks per-IP behavioral features (request count,
    failed logins, connection history) across sessions
  - Must use the same artifacts.pkl used during training

ml/ml_pipeline.py
  - Class: MLPipeline
  - Method: pipeline.predict(feature_vector) → result dict
  - Runs all 3 classification layers in sequence
  - Returns attack_type, confidence, is_anomaly,
    zero_day flag, ae_error, per-class probabilities

ml/rl_agent.py
  - Class: HoneypotRLAgent
  - Method: agent.get_action(src_ip, ml_result) → action dict
  - Loads Q-table from rl_agent.pkl
  - Computes aggressiveness from ml_result + session history
  - Tracks per-IP sessions (time_spent, payload_count)
  - Returns action name, q_value, aggressiveness, DES score
  - Additional methods: agent.record_payload(src_ip),
    agent.end_session(src_ip)

core/event_bus.py
  - Class: EventBus
  - Ties everything together
  - Method: bus.emit(connection_event) → called by each service
  - Method: bus.subscribe(callback) → called by dashboard
  - Internally runs FeatureExtractor → MLPipeline → RLAgent
  - Pushes enriched result to all subscribers via callback
  - Runs in background thread with a queue


---

## Input Format (connection_event dict)

Every honeypot service must call bus.emit() with this structure:
{
    'src_ip'        : str,    # attacker IP e.g. '192.168.1.100'
    'dst_port'      : int,    # port attacked e.g. 22
    'protocol'      : str,    # 'tcp' or 'udp'
    'service'       : str,    # 'ssh','http','ftp','smtp','telnet','mysql'
    'duration'      : float,  # connection duration in seconds
    'src_bytes'     : int,    # bytes sent by attacker
    'dst_bytes'     : int,    # bytes sent by honeypot
    'flag'          : str,    # TCP flag: 'SF','S0','REJ','RSTO','SH'
    'logged_in'     : bool,   # did attacker successfully authenticate
    'failed_logins' : int,    # number of failed login attempts
    'payload'       : bytes,  # raw payload bytes (can be b'' if none)
    'timestamp'     : float,  # time.time()
}

---

## Output Format (enriched event)

After bus processes the event, subscribers receive:
{
    # original connection fields preserved
    'src_ip', 'service', 'timestamp', ... 

    'ml': {
        'attack_type'   : str,   # DoS/Normal/Probe/R2L/U2R/ZeroDay
        'confidence'    : float, # 0.0 to 100.0
        'is_anomaly'    : bool,
        'zero_day'      : bool,
        'ae_error'      : float, # autoencoder reconstruction error
        'iso_score'     : float, # isolation forest anomaly score
        'probabilities' : {      # per-class confidence
            'DoS': float, 'Normal': float, 'Probe': float,
            'R2L': float, 'U2R': float
        }
    },
    'rl': {
        'action'         : str,  # chosen deception action name
        'action_idx'     : int,  # 0-5
        'q_value'        : float,
        'attack_type'    : str,
        'aggressiveness' : str,  # low/medium/high
        'time_bucket'    : str,  # just_arrived/exploring/deep_in
        'des'            : float,# 0.0 to 1.0
        'session'        : dict, # full session info for this IP
    }
}

---

## What Still Needs to Be Done (Integration Tasks)

1. Each honeypot service (HTTP, SSH, MySQL, FTP, Telnet, SMTP)
   needs to call bus.emit(connection_event) on every connection.
   The connection_event dict fields must be populated from
   whatever data each service already captures.

2. The dashboard needs to subscribe to EventBus and display:
   - Live attack classification with confidence
   - RL action being taken in real time
   - DES score per session updating live
   - Attack type distribution chart
   - Anomaly flag indicator

3. A main.py entry point that starts all services + dashboard
   together in separate threads.

4. Install required packages:
   tensorflow, scikit-learn, numpy, flask,
   flask-socketio, pickle (built-in)

---

## Important Notes for Integration

- artifacts.pkl MUST be loaded to preprocess inputs correctly.
  Never pass raw values directly to ML models.

- The FeatureExtractor maintains state per IP address.
  It tracks request counts and connection history in memory.
  This is required for behavioral features like serror_rate.

- All model files must be in ml/models/ relative to project root
  or update the paths in ml_pipeline.py and ml/rl_agent.py.

- The ML pipeline runs synchronously inside EventBus worker thread.
  On a modern CPU each prediction takes ~50-100ms.
  If latency is a concern, the pipeline can be made async.

- R2L and U2R classification is weak by design limitation.
  The anomaly detection layer compensates.
  Do not expect high precision on these two classes.
  The system is still effective because Layer 1 catches them.