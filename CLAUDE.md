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

## Stack

- **Language:** C++26
- **Build system:** CMake 3.31
- **IDE:** CLion (`.idea/` present but git-ignored)

No test framework, linting, or external libraries are configured yet.
