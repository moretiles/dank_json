#!/bin/bash

set -eou pipefail

make TAGS=y format
make TAGS=y test
rm -f .b4.lock
