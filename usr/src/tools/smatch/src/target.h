#ifndef TARGET_H
#define TARGET_H

extern struct symbol *size_t_ctype;
extern struct symbol *ssize_t_ctype;
extern struct symbol *intmax_ctype;
extern struct symbol *uintmax_ctype;
extern struct symbol *int64_ctype;
extern struct symbol *uint64_ctype;
extern struct symbol *int32_ctype;
extern struct symbol *uint32_ctype;
extern struct symbol *wchar_ctype;
extern struct symbol *wint_ctype;

/*
 * For "__attribute__((aligned))"
 */
extern int max_alignment;

/*
 * Integer data types
 */
extern int bits_in_bool;
extern int bits_in_char;
extern int bits_in_short;
extern int bits_in_int;
extern int bits_in_long;
extern int bits_in_longlong;
extern int bits_in_longlonglong;

extern int max_int_alignment;

/*
 * Floating point data types
 */
extern int bits_in_float;
extern int bits_in_double;
extern int bits_in_longdouble;

extern int max_fp_alignment;

/*
 * Pointer data type
 */
extern int bits_in_pointer;
extern int pointer_alignment;

/*
 * Enum data types
 */
extern int bits_in_enum;
extern int enum_alignment;

/*
 * Helper functions for converting bits to bytes and vice versa.
 */

static inline int bits_to_bytes(int bits)
{
	return bits >= 0 ? (bits + bits_in_char - 1) / bits_in_char : -1;
}

static inline int bytes_to_bits(int bytes)
{
	return bytes * bits_in_char;
}

static inline unsigned long array_element_offset(unsigned long base_bits, int idx)
{
	int fragment = base_bits % bits_in_char;
	if (fragment)
		base_bits += bits_in_char - fragment;
	return base_bits * idx;
}

#endif
