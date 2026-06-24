#!/usr/bin/env bash
#MISE description="Generate typed Go models from Keycloak OpenAPI spec"
#MISE alias="gom"
set -euo pipefail

SPEC_FILE="keycloak-oapi/26.6.2.spec.json"
CONFIG_FILE="mise-tasks/generate/oapi-codegen-models.yaml"
OUTPUT_FILE="pkg/models/models.gen.go"

if [ ! -f "$SPEC_FILE" ]; then
    echo "Spec file not found: $SPEC_FILE. Run 'mise run generate:oapi' first." >&2
    exit 1
fi

oapi-codegen -config "$CONFIG_FILE" -o "$OUTPUT_FILE" "$SPEC_FILE"
echo "Generated $OUTPUT_FILE"
