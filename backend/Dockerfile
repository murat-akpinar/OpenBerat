# Multi-stage build: the compiler image is ~1.5GB, the runtime image ~80MB.
# Filled in during Phase 2.
#   stage 1: rust:alpine -> cargo build --release
#   stage 2: alpine      -> the binary and CA certificates only
