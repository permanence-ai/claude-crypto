# IA-ASM provider plan

# Requirements
- Implements the same interface as the one defined in safe-crypto-lib.
- Only implements functions in ASM that benefit from ASM implementations.
  - This should include functions that benefit from the use of SIMD instructions.
  - This should include functions that benefit from IA crypto instructions. (e.g., AES-NI).
  - Functionality that is not implemented in ASM should be implemented in C++ 26.
- Note that building and testing this will require a CPU that supports AMD64 architecture.
- ASM functions should be instruction ordering aware.
- ASM functions must be side-channel resistant, including being constant time.
- ASM functions should be optimized for performance, taking advantage of available CPU resources.
- ASM functions should be implemented in a way that is easy to understand and maintain.
