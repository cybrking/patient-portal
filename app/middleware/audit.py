from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
import json
import time
import logging

logger = logging.getLogger("audit")

# Routes that access PHI — always logged
PHI_ROUTES = ["/patients", "/records", "/prescriptions", "/appointments"]

class AuditLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()

        # Extract user from JWT if present
        user_id = None
        user_role = None
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            try:
                import jwt, os
                token = auth_header.split(" ")[1]
                payload = jwt.decode(token, os.getenv("JWT_SECRET_KEY"), algorithms=["HS256"])
                user_id = payload.get("sub")
                user_role = payload.get("role")
            except Exception:
                pass

        response = await call_next(request)
        duration = time.time() - start_time

        # Log all PHI-touching routes
        if any(request.url.path.startswith(route) for route in PHI_ROUTES):
            audit_entry = {
                "timestamp": time.time(),
                "user_id": user_id,
                "user_role": user_role,
                "method": request.method,
                "path": request.url.path,
                "query": str(request.query_params),
                "ip": request.client.host,
                "user_agent": request.headers.get("User-Agent"),
                "status_code": response.status_code,
                "duration_ms": round(duration * 1000, 2),
                "success": response.status_code < 400
            }
            # Write to immutable audit store (CloudWatch / SIEM)
            logger.info(json.dumps(audit_entry))

        return response
