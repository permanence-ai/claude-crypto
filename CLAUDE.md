# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

An experimental C++26 project for exploring cryptography and modern C++ with Claude Code. Currently a greenfield — no crypto functionality implemented yet.

## Build

```bash
# Configure
cmake -B cmake-build-debug -S .

# Build
cmake --build cmake-build-debug

# Run
./cmake-build-debug/claude_crypto
```

For a release build, substitute `cmake-build-release` for `cmake-build-debug` and add `-DCMAKE_BUILD_TYPE=Release` to the configure step.

## Lint

```bash
clang-tidy main.cpp -- -std=c++26
```

## Crypto Implementation Rules
- All crypto implementation must be constant time.
- All secrets used in crypto must be scrubbed.

## Stack

- **Language:** C++26
- **Build system:** CMake 3.31
- **IDE:** CLion (`.idea/` present but git-ignored)

Test framework: GoogleTest (via FetchContent). Crypto library: mbedtls 4.1.0 (via FetchContent, PSA Crypto API).
