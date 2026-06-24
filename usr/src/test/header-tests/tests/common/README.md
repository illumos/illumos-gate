# tests/common - C and C++ symbol visibility test programs

## Overview

This directory contains the source for the symbol visibility test programs:

- `c_symbols_test.c` - tests C symbol visibility in system headers
- `cxx_symbols_test.c` - tests C++ symbol visibility in system headers

Each is built in 32-bit and 64-bit variants (`_32`/`_64` suffixes) and
invoked by the `setup` scripts in `../c-symbols/` and `../cxx-symbols/`
respectively.

Both programs follow the same pattern:

1. Read a **compilation environment config** (`../cfg/c-symbols-env.cfg` or
   `../cfg/cxx-symbols-env.cfg`) that defines named environments (compiler
   flags + preprocessor definitions) and environment groups.
2. Read one or more **test config files** (e.g. `../cfg/c-symbols/math_h.cfg`)
   that describe symbols to test, which header to include, and which
   environments should compile successfully or fail.
3. For each (symbol, environment) pair, **generate a small probe program**,
   compile it with the environment's flags, and check the result against
   the expectation.

The config file format is documented in `../cfg/README`,
`../cfg/c-symbols/README`, and `../cfg/cxx-symbols/README`.

## Source files

`c_symbols_test.c` and `cxx_symbols_test.c` share the same overall
structure and options.  The C++ version adds:

- Compiler discovery (`find_compiler()`): tries `g++` then `clang++`, or
  accepts an explicit `-c compiler` argument.
- C++ include path setup (`find_cxx_includes()`): queries the compiler
  for its internal include directory and constructs the `-isystem` paths
  needed to find C++ standard headers without picking up GCC's
  fixincludes copies of system headers.  See the function comment for
  details.
- A `RESULT()` macro in `func` probe programs that uses brace-initialisation
  in C++11 and later, and plain assignment in C++98 (see below).

## Probe program generation

For each test entry, both programs generate a minimal C or C++ program.
The directive types and generated forms are the same in both, except
where noted below.

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
	double RESULT(std::log(a0));
	return result;
}
```
Brace-initialisation prohibits narrowing conversions, so a missing `float`
or `long double` overload that would silently promote through `double` is
caught as a compile error rather than a silent pass.  C++98 uses plain
assignment since brace-init is a C++11 extension.
Function pointer return types use plain `return` in both programs since
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

Both programs accept:

    -f          Force: continue after failures (important - without this,
                the program exits on the first failure, which makes
                interactive test runs misleading)
    -d          Debug: print compiler output on failures
    -D          Extra debug: also print the compiler command line
    -c compiler Use the specified compiler instead of auto-detecting
    -s sym      Run only the test entry for the named symbol

When running tests by hand (not via the `setup` script), always pass `-f`
to see all failures rather than stopping at the first one.

## Extending the tests

To add tests for a new header:

1. Add a new `.cfg` file in `../cfg/c-symbols/` or `../cfg/cxx-symbols/`.
2. Add a wrapper script (hardlink or copy of `setup`) in the corresponding
   `../c-symbols/` or `../cxx-symbols/` subdirectory, named after the cfg file
   without `.cfg`.
3. Add the new files to the `../cfg/Makefile` and the IPS manifest.

To add a new compilation environment or group, edit
`../cfg/c-symbols-env.cfg` or `../cfg/cxx-symbols-env.cfg`.  Note that the
total number of environments is limited to 64 (a bitmask of type
`uint64_t`).  Currently 10 C++ environments are defined, so there is
ample room.
