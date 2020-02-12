/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

#ifndef _CHECK_COMMON_H
#define	_CHECK_COMMON_H

/*
 * Common definitions for the CTF tests
 */

#include <stdlib.h>
#include <unistd.h>
#include <libctf.h>
#include <err.h>
#include <strings.h>
#include <sys/param.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct check_number {
	const char *cn_tname;
	uint_t cn_kind;
	uint_t cn_flags;
	uint_t cn_offset;
	uint_t cn_size;
} check_number_t;

typedef struct check_symbol {
	const char *cs_symbol;
	const char *cs_type;
} check_symbol_t;

typedef struct check_descent {
	const char *cd_tname;
	uint_t cd_kind;
	const char *cd_contents;
	uint_t cd_nents;
} check_descent_t;

typedef struct check_descent_test {
	const char *cdt_sym;
	const check_descent_t *cdt_tests;
} check_descent_test_t;

typedef struct check_enum {
	const char *ce_name;
	int64_t ce_value;
} check_enum_t;

typedef struct check_enum_test {
	const char *cet_type;
	const check_enum_t *cet_tests;
} check_enum_test_t;

typedef struct check_member {
	const char *cm_name;
	const char *cm_type;
	ulong_t cm_offset;
} check_member_t;

typedef struct check_member_test {
	const char *cmt_type;
	int cmt_kind;
	size_t cmt_size;
	const check_member_t *cmt_members;
} check_member_test_t;

typedef struct check_function_test {
	const char *cft_name;
	const char *cft_rtype;
	uint_t cft_nargs;
	uint_t cft_flags;
	const char **cft_args;
} check_function_test_t;

typedef struct check_size_test {
	const char *cst_name;
	size_t cst_size;
} check_size_test_t;

/*
 * Looks up each type and verifies that it matches the expected type.
 */
extern boolean_t ctftest_check_numbers(ctf_file_t *, const check_number_t *);

/*
 * Looks at each symbol specified and verifies that it matches the expected
 * type.
 */
extern boolean_t ctftest_check_symbols(ctf_file_t *, const check_symbol_t *);

/*
 * Given a symbol name which refers to a type, walks all the references of that
 * type and checks against it with each subsequent entry.
 */
extern boolean_t ctftest_check_descent(const char *, ctf_file_t *,
    const check_descent_t *, boolean_t);

/*
 * Checks that all of the listed members of an enum are present and have the
 * right values.
 */
extern boolean_t ctftest_check_enum(const char *, ctf_file_t *,
    const check_enum_t *);

/*
 * Checks that all of the members of a structure or union are present and have
 * the right types and byte offsets. This can be used for either structures or
 * unions.
 */
extern boolean_t ctftest_check_members(const char *, ctf_file_t *, int, size_t,
    const check_member_t *);

/*
 * Check that the named function or function pointer has the correct return
 * type, arguments, and function flags.
 */
extern boolean_t ctftest_check_function(const char *, ctf_file_t *,
    const char *, uint_t, uint_t, const char **);
extern boolean_t ctftest_check_fptr(const char *, ctf_file_t *,
    const char *, uint_t, uint_t, const char **);

/*
 * Check size of types.
 */
extern boolean_t ctftest_check_size(const char *, ctf_file_t *, size_t);

/*
 * Determine whether or not we have a duplicate type or not based on its name.
 */
extern boolean_t ctftest_duplicates(ctf_file_t *);

#ifdef __cplusplus
}
#endif

#endif /* _CHECK_COMMON_H */
