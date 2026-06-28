from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime
from typing import Optional
import uuid

app = FastAPI(
    title="AccessGuard — CyberPulse Audit API",
    description="Plateforme de gestion et reporting d'audit cybersécurité",
    version="1.0.0"
)

# Base de données en mémoire (pas besoin de SQL pour ce soir)
audit_results = []
access_requests = []
audit_logs = []

# ─── MODÈLES ───────────────────────────────────────────────
class AuditResult(BaseModel):
    target: str
    tool: str  # nmap, zap, gophish...
    pilier: str  # Pilier 1, 2, 3, 4
    severity: str  # Critique, Élevé, Moyen, Faible
    description: str
    recommendation: str

class AccessRequest(BaseModel):
    user: str
    resource: str
    reason: str

class AccessDecision(BaseModel):
    decision: str  # approved / rejected
    manager: str

# ─── ROUTES AUDIT ──────────────────────────────────────────
@app.get("/", tags=["Info"])
def root():
    return {
        "projet": "CyberPulse — AccessGuard",
        "version": "1.0.0",
        "status": "opérationnel"
    }

@app.post("/audit/result", tags=["Audit"])
def add_audit_result(result: AuditResult):
    entry = result.dict()
    entry["id"] = str(uuid.uuid4())[:8]
    entry["timestamp"] = datetime.now().isoformat()
    audit_results.append(entry)
    audit_logs.append({
        "action": "audit_result_added",
        "target": result.target,
        "tool": result.tool,
        "timestamp": entry["timestamp"]
    })
    return {"message": "Résultat d'audit enregistré", "id": entry["id"]}

@app.get("/audit/results", tags=["Audit"])
def get_audit_results(pilier: Optional[str] = None, severity: Optional[str] = None):
    results = audit_results
    if pilier:
        results = [r for r in results if r["pilier"] == pilier]
    if severity:
        results = [r for r in results if r["severity"] == severity]
    return {"total": len(results), "results": results}

@app.get("/audit/summary", tags=["Audit"])
def get_audit_summary():
    summary = {"Critique": 0, "Élevé": 0, "Moyen": 0, "Faible": 0}
    for r in audit_results:
        if r["severity"] in summary:
            summary[r["severity"]] += 1
    return {
        "total_vulnerabilites": len(audit_results),
        "par_severite": summary,
        "outils_utilises": list(set(r["tool"] for r in audit_results))
    }

# ─── ROUTES ACCÈS ──────────────────────────────────────────
@app.post("/access/request", tags=["Gestion des accès"])
def create_access_request(req: AccessRequest):
    entry = req.dict()
    entry["id"] = str(uuid.uuid4())[:8]
    entry["status"] = "pending"
    entry["timestamp"] = datetime.now().isoformat()
    access_requests.append(entry)
    audit_logs.append({
        "action": "access_requested",
        "user": req.user,
        "resource": req.resource,
        "timestamp": entry["timestamp"]
    })
    return {"message": "Demande d'accès créée", "id": entry["id"], "status": "pending"}

@app.put("/access/request/{request_id}", tags=["Gestion des accès"])
def decide_access_request(request_id: str, decision: AccessDecision):
    for req in access_requests:
        if req["id"] == request_id:
            req["status"] = decision.decision
            req["manager"] = decision.manager
            req["decided_at"] = datetime.now().isoformat()
            audit_logs.append({
                "action": f"access_{decision.decision}",
                "request_id": request_id,
                "manager": decision.manager,
                "timestamp": req["decided_at"]
            })
            return {"message": f"Accès {decision.decision}", "request": req}
    raise HTTPException(status_code=404, detail="Demande introuvable")

@app.get("/access/requests", tags=["Gestion des accès"])
def get_access_requests():
    return {"total": len(access_requests), "requests": access_requests}

# ─── LOGS ──────────────────────────────────────────────────
@app.get("/audit/logs", tags=["Logs"])
def get_audit_logs():
    return {"total": len(audit_logs), "logs": audit_logs}
