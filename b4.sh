#!/bin/bash

set -eou pipefail

make test
rm -f .b4.lock
