import sys
import os
import yaml

# Add backend directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app

# Generate the OpenAPI schema dictionary from the FastAPI app
openapi_schema = app.openapi()

# Resolve path for openapi.yaml at the workspace root
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
openapi_path = os.path.join(root_dir, "openapi.yaml")

with open(openapi_path, "w") as f:
    yaml.dump(openapi_schema, f, sort_keys=False)

print(f"Exported OpenAPI spec successfully to {openapi_path}")
