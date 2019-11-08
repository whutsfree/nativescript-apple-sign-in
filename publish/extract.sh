#!/bin/bash

PACK_DIR=package;

extract() {
    # extract the package
    cd "$PACK_DIR"
    tar -xzf *

    cd ..
}

extract
