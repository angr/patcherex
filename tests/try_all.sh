#!/bin/bash

find . -name "test*" | xargs -n1 -P1 -I{} bash -c "echo '========================= testing {}';./{}"

