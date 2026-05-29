
<details>
<summary>License and copyright</summary>

CDDL HEADER START

The contents of this file are subject to the terms of the
Common Development and Distribution License (the "License").
You may not use this file except in compliance with the License.

You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
or http://www.opensolaris.org/os/licensing.
See the License for the specific language governing permissions
and limitations under the License.

When distributing Covered Code, include this CDDL HEADER in each
file and include the License file at usr/src/OPENSOLARIS.LICENSE.
If applicable, add the following below this CDDL HEADER, with the
fields enclosed by brackets "[]" replaced with your own identifying
information: Portions Copyright [yyyy] [name of copyright owner]

CDDL HEADER END

Copyright 2026 Gordon W. Ross

</details>

# Guidance for headers used in C++

## Background

Two models exist for how C system headers expose library names to C++:

**std-primary**: ISO C library functions are declared inside `namespace std {}`.
The global namespace (`::`) is then populated via `using std::func` declarations.

**global-primary**: ISO C library functions are declared directly in `::` via
`extern "C" {}`.  The `std::` namespace is then populated via `using ::func`
declarations.

For future illumos header work, use the **global-primary** model.  It matches
what modern C++ toolchains expect, keeps the C declarations in their natural
namespace, and gives a clear rule for what may be exposed in `namespace std`.

The most important cautionary example is IL-15209.  In `<math.h>`, a
std-primary layout let `using std::log` pull the float, double, and long double
overloads into `::`, which made `log(int)` ambiguous.  The guidance below is
intended to prevent that class of problem when updating existing headers or
adding C++ support to new ones.

---

## Standards Basis: What Belongs in `::` vs. `namespace std`

For a C header such as `<math.h>`, the practical guidance is:

- put the C declarations in `::`
- populate `namespace std` only with names the C++ standard requires
- keep extension names in `::`, not in `namespace std`
- use Pattern B for math functions and other functions commonly called with
  integer arguments

Those rules follow from the C and C++ standards, summarized here.

### The C standard

The C standard defines only the `double` forms of math functions in `<math.h>`
(for example, `double log(double)`).  The `float` and `long double` variants
(`logf`, `logl`) are separate C function names, not overloads.  Therefore, the
C standard places only the `double` form in `::`.

### C++11 §D.5 `[depr.c.headers]`

C++11 Annex D §5 says:

> Each C header `<name.h>` behaves as if each name placed in the standard
> library namespace by the corresponding `<cname>` header is placed within the
> global namespace scope.

Read literally, this suggests that `<math.h>` should also expose in `::` the
names that `<cmath>` places in `namespace std`.  But the same paragraph makes
the mechanism **implementation-defined**:

> It is unspecified whether these names are first declared or defined within
> namespace scope of the namespace `std` and are then injected into the global
> namespace scope by explicit using-declarations.

In illumos headers, that flexibility should be used in a way that keeps the
rules simple for future maintenance:

- C declarations stay in `::`
- `namespace std` is populated explicitly, by `using ::func` and by C++-only
  inlines where needed
- the system header does not try to pre-populate `::` with every C++ overload

### Pattern A: type variant overloads in `::`

Pattern A puts C++-only type variant overloads in `::` alongside the
C-standard form.  `using ::func` in `namespace std` then brings all overloads
at once.

Use Pattern A only for functions not commonly called with integer arguments.
For such functions, the layout is simple and there is no practical ambiguity
problem.

### Pattern B: type variant overloads in `namespace std` only

For math functions, Pattern B is required:

- `::` gets only what the C standard defines: for example, `double log(double)`.
- `namespace std` gets that form via `using ::log`, plus the float and long
  double overloads as C++-only inlines defined directly in `namespace std`.

This avoids the IL-15209 failure mode.  C++11 `[c.math]` requires `<cmath>` to
provide enough overloads for calls such as `log(1)` to work without ambiguity.
On GCC, the integer-covering support lives inside `namespace std`, not in `::`.
If the float and long double overloads are also placed in `::`, `log(1)` becomes
ambiguous.  Pattern B keeps those overloads where the C++ library expects them.

GCC signals this expectation with `__CORRECT_ISO_CPP_MATH_H_PROTO`
(via `os_defines.h`).  When that macro is defined, libstdc++ expects the system
header to have already provided the type variant overloads in `namespace std`
and skips adding its own.

### Compatibility with other systems

The illumos guidance here is intended to make header behavior more predictable
for code written against other Unix-like systems and modern C++ libraries.

**glibc (Linux) and FreeBSD** place no C++ overloads in `<math.h>` at all.
Their system headers declare the C functions in `::`, and their C++ libraries
handle the overload sets in `<cmath>`.
([glibc math/math.h](https://github.com/bminor/glibc/blob/glibc-2.42/math/math.h),
[FreeBSD lib/msun/src/math.h](https://github.com/freebsd/freebsd-src/blob/stable/14/lib/msun/src/math.h))

**LLVM libc++** uses a self-contained arrangement based on an internal
`std::__math` namespace.  It does not rely on illumos-style system header
coordination, but it still follows the general expectation that the C library
declarations live in `::` and the C++ library manages the overload model.
([libcxx/include/math.h](https://github.com/llvm/llvm-project/blob/release/20.x/libcxx/include/math.h),
[libcxx/include/cmath](https://github.com/llvm/llvm-project/blob/release/20.x/libcxx/include/cmath),
[libcxx/include/__math/trigonometric_functions.h](https://github.com/llvm/llvm-project/blob/release/20.x/libcxx/include/__math/trigonometric_functions.h))

**libstdc++** uses Pattern B by default.  Its `<cmath>` puts the type variant
overloads in `namespace std`, and on Solaris or illumos it uses
`__CORRECT_ISO_CPP_MATH_H_PROTO` to decide whether the system header already
did that work.
([libstdc++-v3/include/c_global/cmath](https://github.com/gcc-mirror/gcc/blob/releases/gcc-14/libstdc++-v3/include/c_global/cmath),
[libstdc++-v3/include/bits/std_abs.h](https://github.com/gcc-mirror/gcc/blob/releases/gcc-14/libstdc++-v3/include/bits/std_abs.h))

For illumos, the key compatibility point is with **libstdc++**.  If the system
header uses global-primary structure and Pattern B for math, the system header
and the C++ library cooperate cleanly.
([libstdc++-v3/config/os/solaris/os_defines.h](https://github.com/gcc-mirror/gcc/blob/releases/gcc-14/libstdc++-v3/config/os/solaris/os_defines.h))

### In what namespace are extensions?

Extension symbols (those gated on `__EXTENSIONS__`, `_XOPEN_SOURCE`, or
similar macros) are declared in the C++ global namespace (`::`) only.
`namespace std` is populated exclusively with names the C++ standard requires.
This keeps the rule simple: if a name is an extension, it belongs in `::`.

---

## Why Change from std-primary to global-primary?

The older illumos headers were developed when the C and C++ standards were
still evolving and when SunPro was the primary compiler.  Today the important
goal is to make future header work predictable and compatible with modern C++
toolchains.  Adopting the global-primary model gives several advantages:

1. **Standards conformance.**  C declarations belong in `::` by definition; that
   is what `extern "C"` means.  The std-primary model placed them in
   `namespace std` as a primary residence, which is non-standard.  Global-primary
   aligns with both the C standard (declarations in `::`) and the C++ standard
   (`namespace std` contains what `<cname>` is required to provide).

2. **Mismatch with other platforms.**  glibc, FreeBSD, macOS, and other major
   Unix systems use global-primary: C declarations in `::`, with the C++ library
   responsible for populating `namespace std`.  illumos being different causes
   portability friction for application code.

3. **Extension pollution of `namespace std`.**  In the std-primary model it is
   easy to accidentally declare extension symbols (those gated on `__EXTENSIONS__`
   or `_XOPEN_SOURCE`) inside `namespace std`.  The global-primary model makes
   the boundary explicit: extensions go in `::` only, and `namespace std` is
   populated exclusively via deliberate `using ::func` aliases.

4. **Bugs from over-population of `::`.**  The outer headers use `using std::func`
   to pull names from `namespace std` into `::`.  When `namespace std` contains
   type variant overloads (float, long double), all of them land in `::` at once,
   with no integer-covering template to resolve ambiguous calls.  IL-15209
   (`log(int)` ambiguous) is one instance of this class of bug.

---

## Header Structure

See the [`header-template.h`](#Header-template) below for the canonical
annotated example.  Each ISO header is structured into six sections:

### Core principle

The **global namespace is primary**.  `std::` is secondary, populated only
with what the C++ standard requires.

illumos headers are currently in transition.  Many still follow the old
std-primary model.  See [Status by header](#status-by-header) for the current
state of each header.

### Section 1: Unconditional C declarations (C++ global namespace)
Standard C library functions are declared with C linkage, visible to both C
and C++ translation units:

```cpp
#ifdef __cplusplus
extern "C" {
#endif

extern double log(double);
extern double acos(double);
/* ... */

#ifdef __cplusplus
}  /* extern "C" */
#endif
```

The outer header (`<math.h>`) needs no `using std::log` lines; `::log` is
already there from the declaration.

### Section 2: Conditional C declarations (C++ global namespace)
Functions gated on environment macros (`_C99_SOURCE`, `_XOPEN_SOURCE`,
`__EXTENSIONS__`, etc.) declared in `::` under the appropriate guards.
Extension symbols (`__EXTENSIONS__`) are **not** aliased into `namespace std`.

### Section 3: C-linkage helpers for C++ only (C++ global namespace)
Type-variant C functions needed solely by C++ overloaded inlines in Section 4,
with no purpose in C translation units.  For `<math.h>` this means the `*f`
and `*l` variants, declared inside the `extern "C"` block but guarded by
`#ifdef __cplusplus`:

```cpp
#ifdef __cplusplus
extern float  acosf(float);
extern long double acosl(long double);
#endif
```

### Sections 4–6: C++ block (always a separate top-level `extern "C++"`)

The `extern "C++"` block is **never nested inside `extern "C"`**.  It opens
after the `extern "C"` block closes.

**Section 4: C++ overloaded inlines (C++ global namespace or `namespace std`).**
Where the inlines live depends on which pattern applies
(see [Standards Basis](#standards-basis-what-belongs-in--vs-namespace-std)):

- **Pattern A**: inlines go in the C++ global namespace (`extern "C++"` at
  file scope, outside any `namespace` block).  A subsequent `using ::func`
  in Section 6 brings all overloads into `namespace std` at once.  Safe only
  for functions not commonly called with integer arguments.
- **Pattern B**: no inlines here.  Inlines are defined directly inside
  `namespace std` in Section 6.  Required for math functions (`log`, `sin`,
  etc.) to prevent `log(1)` ambiguity.

```cpp
#if __cplusplus >= 199711L
extern "C++" {

    /* Pattern A: global namespace; acos(1) is unambiguous */
    inline float       acos(float __x)       { return acosf(__x); }
    inline long double acos(long double __x) { return acosl(__x); }

    /* Pattern B functions have no inlines here; see Section 6 */
```

**Section 5: C++ overloads for conditionally-exposed functions (C++ global
namespace).**  Same `extern "C++"` block.  Type variant inlines for functions
declared in Section 2, placed in the C++ global namespace and guarded by the
same environment macro conditions (`_C99_SOURCE`, `_XOPEN_SOURCE`,
`__EXTENSIONS__`, etc.) as their Section 2 declarations:

```cpp
#if defined(__EXTENSIONS__)
    inline float       acospi(float __x)       { return acospif(__x); }
    inline long double acospi(long double __x) { return acospil(__x); }
#endif
```

**Section 6: `namespace std`** (same `extern "C++"` block).  Populated with
only the names the C++ standard requires.  No extensions.  Pattern B inlines
are defined here inside `namespace std`:

```cpp
    namespace std {
        using ::acos;            /* Pattern A: brings double+float+ldbl */

        using ::log;             /* Pattern B: double form only */
        inline float       log(float __x)       { return logf(__x); }
        inline long double log(long double __x) { return logl(__x); }
    }

}  /* extern "C++" */
#endif  /* __cplusplus >= 199711L */
```

## Header template

```
/*
 *  top matter (CDDL, copyrights)
 */

/*
 * Global-primary namespace model
 * --------------------------------
 * All C library function declarations go in the global namespace (::)
 * inside extern "C" {}.  The C++ standard namespace (std::) is then
 * populated exclusively via "using ::" aliases, never by redeclaring
 * symbols inside "namespace std {}".
 *
 * C++ requires additional type variant overloads (e.g., math.h's float
 * and long double forms of acos).  These are:
 *   - Forward-declared with C linkage inside extern "C" (Section 3)
 *   - Provided as overloaded inlines via extern "C++" (Sections 4 or 6)
 *   - Brought into std:: in Section 6
 *
 * There are two patterns for where the inlines live:
 *
 *   Pattern A: inlines in :: (global namespace).
 *     "using ::func" in namespace std then brings all type variant
 *     overloads into std:: in one declaration.  Use this when the
 *     function is unlikely to be called with integer arguments.
 *
 *   Pattern B: inlines in namespace std only.
 *     "using ::func" brings only the C-standard (e.g., double) form
 *     into std::.  Type variant inlines are defined directly in
 *     namespace std.  Use this for functions that may be called with
 *     integer arguments: if type variant overloads were in ::, a call
 *     like log(1) would be ambiguous.  Math functions use Pattern B.
 *
 * The extern "C++" block is always separate from (never nested inside)
 * extern "C" {}.
 */

#ifndef _INCLUDE_GUARD_
#define _INCLUDE_GUARD_

/* prerequisite includes etc. */
#include <sys/feature_tests.h>

/*
 * Section 1: Unconditional C linkage declarations (global namespace ::)
 *
 * Visible to both C and C++.  For example, math.h declares
 * `double acos(double)` here.
 */
#ifdef	__cplusplus
extern "C" {
#endif

extern double acos(double);

/*
 * Section 2: Conditionally exposed declarations (global namespace ::)
 *
 * Functions exposed based on the compilation environment: C standard
 * version (_C99_SOURCE, _C11_SOURCE), feature-test macros
 * (_XOPEN_SOURCE, _POSIX_SOURCE, __EXTENSIONS__), and similar.
 * Some of these may be aliased into std:: in Section 6.
 */
#if defined(_C99_SOURCE) || defined(_XOPEN_SOURCE)

/* extern double foo(double); */

#endif	/* _C99_SOURCE || _XOPEN_SOURCE (and others) */

#if defined(__EXTENSIONS__)

extern double acospi(double);

#endif	/* __EXTENSIONS__ */

/*
 * Section 3: C-linkage functions needed only by the C++ overloaded
 * inlines or templates in Section 4; they have no use in C
 * translation units.  Functions from Section 2 that also need
 * type variant helpers belong here too, guarded by the same
 * feature-test conditions as their Section 2 declarations.
 * For example, math.h adds `float acosf(float)` and
 * `long double acosl(long double)` here for use in the argument
 * overloads in Section 4.
 */
#ifdef	__cplusplus
extern float acosf(float);
extern long double acosl(long double);
#endif	/* __cplusplus */

#ifdef	__cplusplus
}  /* extern "C" */
#endif

/*
 * Section 4: C++ overloaded inlines (Pattern A: inlines in ::).
 *
 * This block is entirely separate from extern "C" above.
 * Use Pattern A when the function is not commonly called with
 * integer arguments.  For example, acos(1) compiles fine even
 * with type variant overloads in :: because there is no ambiguity
 * in practice.
 *
 * For functions that ARE commonly called with integer arguments
 * (most math functions), use Pattern B: omit the inlines here
 * and define them directly inside namespace std in Section 6.
 */
#if __cplusplus >= 199711L
extern "C++" {
#undef	__X
#undef	__Y

	inline float acos(float __X) { return acosf(__X); }
	inline long double acos(long double __X) { return acosl(__X); }

/*
 * Section 5: C++ overloads for conditionally-exposed functions
 * (C++ global namespace).
 *
 * Type variant inlines for functions declared in Section 2, guarded
 * by the same environment macro conditions as their Section 2
 * declarations.
 */
#if defined(__EXTENSIONS__)
#undef	__X

	inline float acospi(float __X) { return acospif(__X); }
	inline long double acospi(long double __X) { return acospil(__X); }

#endif	/* __EXTENSIONS__ */

/*
 * Section 6: namespace std population.
 *
 * Only declarations codified by C++ standards are aliased into std::.
 * Aliases for Section 2 (conditionally exposed, standards-codified)
 * functions may also appear here, guarded by the same conditions as
 * Section 2.
 *
 * Pattern A: "using ::" brings all type variant overloads into std::
 * in one declaration; used when inlines are in :: (Section 4).
 *
 * Pattern B (math functions): "using ::" brings only the C-standard
 * form; type variant inlines are defined directly here in namespace
 * std to avoid ambiguity when called with integer args.
 */
namespace std {
	/* Pattern A example: */
	using ::acos;

	/* Pattern B example (math.h style): */
	using ::log;	/* double form only in :: */
	inline float log(float __X) { return logf(__X); }
	inline long double log(long double __X) { return logl(__X); }

}  /* namespace std */

}  /* extern "C++" */
#endif	/* __cplusplus >= 199711L */

#endif	/* _INCLUDE_GUARD_ */
```
