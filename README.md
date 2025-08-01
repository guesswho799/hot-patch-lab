# Hot Patch Lab
*A Web UI for `dynamic` remote code injection. Select a target process and function, and inject custom or pre-made code blocks—all without restarting the application.*

<img width="1608" height="753" alt="image" src="https://github.com/user-attachments/assets/b8587b4b-847e-4b4b-a201-b105ff89eff1" />

## Features

- Inject from a library of pre-built code blocks:
  - Failure detection (specific return value), for logging
  - Function timing, for benchmarching production environment
  - Early returns on argument checks, for bugfixing
- Full custom function replacement (JIT compiled)
  - For cyber reasons

## Why use Hot Patch Lab
Designed to reduce logging overhead in production:
- Avoids always-on logging runtime cost
- Accelerates debugging without slowing down dev cycles
- Captures actionable insights only when you need them

## How to build
```console
gcc test/main.c -o test/program
cmake -Bbuild
cmake --build build -j 8
./build/HotPatchLab
```

## Dependencies
* Capstone for disassembling
* Crow for web server
