# tests/common - C and C++ symbol visibility test program

## Overview

This directory contains the source for the symbol visibility test program:

- `symbol_test.py` - test driver for C and C++ (supports parallel compilation)
- `test_parse_env_cfg.py` - unit test for environment config parser
- `test_parse_sym_cfg.py` - unit test for symbols config parser
- `test_gen_probe.py` - unit test for test/probe program generation

The `symbol_test.py` program:
- reads an `environment config` file
- reads a `symbols config` file
- runs short compiler jobs for each combination of environement and symbol,
  verifying that it exists or does not exist as indicated by the data from
  the `symbols config` file.

The config file format is documented in `../cfg/README`,
`../cfg/c-symbols/README`, and `../cfg/cxx-symbols/README`.

## Program Operation

- Compiler discovery: tries `g++` then `clang++`, or accepts `-c compiler`.
- C++ include path setup: queries the compiler for its internal include
  directory and constructs the `-isystem` paths needed to find C++ standard
  headers without picking up GCC's fixincludes copies of system headers.

## Probe program generation

For each test entry, the program generates a minimal C or C++ program.
For notes on "probe" program generation, see `test_gen_probe.py`

#### `func` - function call test

Config line:
```
func | log | double | double | math.h | C99+
```
Generated program (C):
```c
#include <math.h>
double
test_func(double a0)
{
	return log(a0);
}
```

In the C++ program, the return value uses a `RESULT()` macro that selects
brace-initialisation (C++11 and later) or plain assignment (C++98):
```cpp
#if __cplusplus >= 201103L
#define RESULT(v) result{v}
#else
#define RESULT(v) result = (v)
#endif
double
test_func(double a0)
{
	double RESULT(log(a0));
	return result;
}
```
Brace-initialisation prohibits narrowing conversions, so a missing `float`
or `long double` overload that would silently promote through `double` is
caught as a compile error rather than a silent pass.  C++98 uses plain
assignment since brace-init is a C++11 extension.
Function pointer return types use plain `return` in the program since
brace-init does not compose with declarator syntax.

#### `type` - type existence test

Config line:
```
type | size_t | stddef.h | C11+
```
Generated program:
```c
#include <stddef.h>
size_t test_type;
```

#### `value` - constant/variable access test

Config line:
```
value | M_PI | double | math.h | C99+
```
Generated program:
```c
#include <math.h>
double test_value;
void
test_func(void)
{
	test_value = M_PI;
}
```

#### `define` - preprocessor macro test

Config line:
```
define | INFINITY | | math.h | C99+
```
Generated program:
```c
#include <math.h>
#if !defined(INFINITY)
#error INFINITY is not defined or has the wrong value
#endif
```
An optional value field checks strict equality:
```
define | FLT_RADIX | 2 | float.h | C99+
```
```c
#include <float.h>
#if !defined(FLT_RADIX) || FLT_RADIX != 2
#error FLT_RADIX is not defined or has the wrong value
#endif
```

## Command-line options

### Usage

    python3 symbol_test.py --lang c|c++ -m64|-m32 [options] env_cfg sym_cfg...

Required arguments:

    --lang c|c++   Language to test
    -m64 | -m32    Target ABI

Options:

    -C          Check compiler only, do not run tests
    -f          Force: continue after failures
    -d          Debug: print probe and compiler output on failures
    -D          Extra debug: also print the compiler command (implies -d)
    -c compiler Use the specified compiler instead of auto-detecting
    -s sym      Run only the test for the named symbol
    -e ENV      Run only tests for the named environment
    -j N        Number of parallel compile jobs (default: 4 or
                the environment variable SYMBOL_TEST_JOBS)

When running tests by hand (not via the `setup` script), you may
pass `-f` to see all failures instead of stopping on errors.

## Extending the tests

To add tests for a new header:

1. Add a new `.cfg` file in `../cfg/c-symbols/` or `../cfg/cxx-symbols/`.
2. Add a wrapper script (hardlink or copy of `setup`) in the corresponding
   `../c-symbols/` or `../cxx-symbols/` subdirectory, named after the cfg file
   without `.cfg`.
3. Add the new files to the `../cfg/Makefile` and the IPS manifest.

To add a new compilation environment or group, edit
`../cfg/c-symbols-env.cfg` or `../cfg/cxx-symbols-env.cfg`.

## Developer Notes

Unit tests for the Python components (`symbol_test.py`) live alongside the
source in this directory.  They use canned string input and require no
external files or build products.

Run individual test modules from `tests/common/`:

```
python3 test_parse_env_cfg.py -v
python3 test_parse_sym_cfg.py -v
python3 test_gen_probe.py -v
```

Or run all unit tests at once from the repository root:

```
python3 -m unittest discover -s usr/src/test/header-tests/tests/common -p 'test_*.py' -v
```
