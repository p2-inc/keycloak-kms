#!/usr/bin/env bash
# Regenerate sigv4-vectors.json from botocore, which ships inside the AWS CLI.
#
# The point of these vectors is that they come from an implementation nobody here wrote. If you
# regenerate them because a test failed, you have deleted the test. Regenerate only when adding a
# new request shape.
set -euo pipefail

CLI_ROOT="${AWS_CLI_ROOT:-$(dirname "$(dirname "$(readlink -f "$(command -v aws)")")")}"
PY="$CLI_ROOT/bin/python"
SP="$(dirname "$("$PY" -c 'import awscli, os; print(os.path.dirname(awscli.__file__))')")"

PYTHONPATH="$SP/awscli:$SP" "$PY" "$(dirname "$0")/regenerate-sigv4-vectors.py"
