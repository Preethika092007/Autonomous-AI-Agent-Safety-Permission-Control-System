import logging
import json
from datetime import datetime, timezone
import contextvars

# Context variable to hold the request ID across async calls
request_id_ctx_var = contextvars.ContextVar("request_id", default="-")

class StructuredJsonFormatter(logging.Formatter):
    """
    Formatter that outputs JSON strings for structured logging.
    Ensures secrets are not logged by explicit omission of sensitive fields.
    """
    def format(self, record: logging.LogRecord) -> str:
        # Avoid logging sensitive fields if they ever make it into the record
        message = record.getMessage()
        
        # Mask obvious secrets in the message string just in case
        if "bearer " in message.lower() or "aura-" in message.lower():
            message = "*** MASKED SENSITIVE DATA ***"
            
        log_obj = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "name": record.name,
            "message": message,
            "request_id": request_id_ctx_var.get()
        }
        
        # Add exception traceback if present
        if record.exc_info:
            log_obj["exc_info"] = self.formatException(record.exc_info)
            
        return json.dumps(log_obj)

def configure_logging():
    """
    Configure the root logger and specific app loggers to use the structured JSON formatter.
    """
    root_logger = logging.getLogger()
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredJsonFormatter())
    
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)
    
    # Set uvicorn loggers to use this formatter too
    for logger_name in ("uvicorn.access", "uvicorn", "aura.endpoints", "aura.auth"):
        l = logging.getLogger(logger_name)
        l.handlers = [handler]
        l.propagate = False
