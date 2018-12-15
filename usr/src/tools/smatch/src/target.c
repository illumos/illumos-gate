#include <stdio.h>

#include "symbol.h"
#include "target.h"

struct symbol *size_t_ctype = &ulong_ctype;
struct symbol *ssize_t_ctype = &long_ctype;

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

int bits_in_wchar = 32;

int max_int_alignment = 4;

/*
 * Floating point data types
 */
int bits_in_float = 32;
int bits_in_double = 64;
int bits_in_longdouble = 80;

int max_fp_alignment = 8;

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
