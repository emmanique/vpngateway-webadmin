#!/bin/sh
# FAIL-CLOSED GUARD - NOT ENABLED. Install only as part of a tested migration.
set -eu
# Replace existing DIRECT default atomically; a higher metric would NOT block fallback.
ip -4 route replace unreachable default table 211
# Keep the source-specific policy rule, and never change table 249 or main.
