#include <stdio.h>

#include "symbol.h"
#include "target.h"
#include "machine.h"

struct symbol *size_t_ctype = &ulong_ctype;
struct symbol *ssize_t_ctype = &long_ctype;
struct symbol *intmax_ctype = &llong_ctype;
struct symbol *uintmax_ctype = &ullong_ctype;
struct symbol *int64_ctype = &long_ctype;
struct symbol *uint64_ctype = &ulong_ctype;
struct symbol *int32_ctype = &int_ctype;
struct symbol *uint32_ctype = &uint_ctype;
struct symbol *wchar_ctype = &int_ctype;
struct symbol *wint_ctype = &uint_ctype;

/*
 * For "__attribute__((aligned))"
 */
int max_alignment = 16;

/*
 * Integer data types
 */
int bits_in_bool = 1;
int bits_in_char = 8;
int bits_in_short = 16;
int bits_in_int = 32;
int bits_in_long = 32;
int bits_in_longlong = 64;
int bits_in_longlonglong = 128;

int max_int_alignment = 4;

/*
 * Floating point data types
 */
int bits_in_float = 32;
int bits_in_double = 64;
int bits_in_longdouble = 128;

int max_fp_alignment = 16;

/*
 * Pointer data type
 */
int bits_in_pointer = 32;
int pointer_alignment = 4;

/*
 * Enum data types
 */
int bits_in_enum = 32;
int enum_alignment = 4;


void init_target(void)
{
	switch (arch_mach) {
	case MACH_X86_64:
		if (arch_m64 == ARCH_LP64)
			break;
		/* fall through */
	case MACH_I386:
	case MACH_M68K:
	case MACH_SPARC32:
	case MACH_PPC32:
		wchar_ctype = &long_ctype;
		break;
	case MACH_ARM:
	case MACH_ARM64:
		wchar_ctype = &uint_ctype;
		break;
	default:
		break;
	}

	switch (arch_mach) {
	case MACH_MIPS64:
		if (arch_m64 == ARCH_LP64)
			break;
		/* fall through */
	case MACH_M68K:
	case MACH_SPARC32:
	case MACH_PPC32:
	case MACH_MIPS32:
	case MACH_RISCV32:
		arch_m64 = ARCH_LP32;
		int32_ctype = &long_ctype;
		uint32_ctype = &ulong_ctype;
		break;
	default:
		break;
	}

	switch (arch_mach) {
	case MACH_ARM:
	case MACH_MIPS32:
	case MACH_S390X:
	case MACH_SPARC32:
		bits_in_longdouble = 64;
		max_fp_alignment = 8;
		break;
	case MACH_X86_64:
		if (arch_m64 == ARCH_LP64 || arch_m64 == ARCH_X32)
			break;
		/* fall through */
	case MACH_I386:
	case MACH_M68K:
		bits_in_longdouble = 96;
		max_fp_alignment = 4;
		break;
	default:
		break;
	}

	switch (arch_m64) {
	case ARCH_X32:
		max_int_alignment = 8;
		int64_ctype = &llong_ctype;
		uint64_ctype = &ullong_ctype;
		break;
	case ARCH_LP32:
		/* default values */
		int64_ctype = &llong_ctype;
		uint64_ctype = &ullong_ctype;
		intmax_ctype = &llong_ctype;
		uintmax_ctype = &ullong_ctype;
		break;
	case ARCH_LP64:
		bits_in_long = 64;
		max_int_alignment = 8;
		size_t_ctype = &ulong_ctype;
		ssize_t_ctype = &long_ctype;
		intmax_ctype = &long_ctype;
		uintmax_ctype = &ulong_ctype;
		goto case_64bit_common;
	case ARCH_LLP64:
		bits_in_long = 32;
		max_int_alignment = 8;
		size_t_ctype = &ullong_ctype;
		ssize_t_ctype = &llong_ctype;
		int64_ctype = &llong_ctype;
		uint64_ctype = &ullong_ctype;
		goto case_64bit_common;
	case_64bit_common:
		bits_in_pointer = 64;
		pointer_alignment = 8;
		break;
	}

#if defined(__CYGWIN__)
	wchar_ctype = &ushort_ctype;
#endif
#if defined(__FreeBSD__) || defined(__APPLE__)
	wint_ctype = &int_ctype;
#endif
#if defined(__APPLE__)
	int64_ctype = &llong_ctype;
	uint64_ctype = &ullong_ctype;
#endif
}
