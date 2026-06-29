"""
explain.py — per-prediction explainability for Auto-SOC

Answers the SOC question "WHY did the model flag this connection?" by attributing
the decision to individual features using SHAP (SHapley Additive exPlanations) on
the Random Forest. A positive SHAP value means the feature pushed the prediction
TOWARD the detected class.

Falls back to a global-importance-based explanation if SHAP is unavailable, so the
dashboard never breaks.
"""

import numpy as np

FEATURE_COLS = [
    "duration", "protocol_type", "service", "src_bytes", "dst_bytes",
    "flag", "count", "srv_count", "dst_host_count", "dst_host_srv_count",
]

# Short, human-readable signature note per attack class (for the explanation text).
_CLASS_HINT = {
    "DoS":   "flood signature — many half-open connections, little/no data returned",
    "Probe": "reconnaissance — short connections probing many ports/services",
    "R2L":   "remote-to-local — login/service traffic from a remote host",
    "U2R":   "privilege-escalation — large payload over an interactive session",
    "Normal": "benign traffic profile",
}

_explainer = None


def _get_explainer(model):
    global _explainer
    if _explainer is None:
        import shap
        _explainer = shap.TreeExplainer(model)
    return _explainer


def explain_prediction(model, X_row, orig_feat, pred, top_n=4):
    """
    Explain one prediction.
      model     : trained RandomForest
      X_row     : 1-row DataFrame of ENCODED features (FEATURE_COLS order)
      orig_feat : dict of ORIGINAL human-readable feature values (for display)
      pred      : predicted class label
    Returns dict: {method, drivers:[{feature,value,impact,direction}], text}
    """
    try:
        expl = _get_explainer(model)
        sv = np.array(expl.shap_values(X_row))      # shape (1, n_features, n_classes)
        classes = list(model.classes_)
        ci = classes.index(pred)
        contrib = sv[0, :, ci]                       # contribution of each feature toward `pred`
        order = np.argsort(np.abs(contrib))[::-1][:top_n]
        drivers = []
        for i in order:
            f = FEATURE_COLS[i]
            drivers.append({
                "feature": f,
                "value": orig_feat.get(f),
                "impact": round(float(contrib[i]), 4),
                "direction": "raises" if contrib[i] > 0 else "lowers",
            })
        return {"method": "SHAP", "drivers": drivers,
                "text": _format(pred, drivers, "SHAP")}
    except Exception:
        return _rule_based(orig_feat, pred, top_n)


def _format(pred, drivers, method):
    hint = _CLASS_HINT.get(pred, "")
    bits = [f"{d['feature']}={d['value']} ({d['direction']} P({pred}))" for d in drivers]
    tail = f" — {hint}" if hint else ""
    return f"Flagged as {pred} via {method}. Top drivers: " + "; ".join(bits) + f".{tail}"


def _rule_based(orig_feat, pred, top_n=4):
    """Fallback explanation ordered by the model's known global feature importance."""
    GLOBAL = ["dst_bytes", "src_bytes", "duration", "dst_host_srv_count",
              "srv_count", "count", "dst_host_count", "flag", "protocol_type", "service"]
    drivers = [{"feature": f, "value": orig_feat.get(f), "impact": None,
                "direction": "key"} for f in GLOBAL[:top_n]]
    bits = "; ".join(f"{d['feature']}={d['value']}" for d in drivers)
    hint = _CLASS_HINT.get(pred, "")
    tail = f" — {hint}" if hint else ""
    return {"method": "rule-based", "drivers": drivers,
            "text": f"Flagged as {pred}. Key features: {bits}.{tail}"}
