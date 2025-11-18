import json
import numpy as np
from features_config import FEATURE_KEYS

def json_to_vector(json_obj):
    vec = []
    for key in FEATURE_KEYS:
        val = json_obj.get(key, 0)

        if key == "sha256":
            continue

        # strictly int or float
        if isinstance(val, bool):
            val = int(val)
        elif isinstance(val, str):
            try:
                val = float(val)
            except:
                val = 0

        vec.append(val)
    
    # replace any inf/nan with 0
    arr = np.array(vec, dtype=float)
    arr = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)
    return arr

def load_jsonl_to_matrix(path):
    X = []
    with open(path, "r") as f:
        for line in f:
            obj = json.loads(line)
            X.append(json_to_vector(obj))
    return np.vstack(X)
