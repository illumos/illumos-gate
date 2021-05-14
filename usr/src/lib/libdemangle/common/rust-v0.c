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
 * Copyright 2019 Joyent, Inc.
 * Copyright 2021 Jason King
 */

/* BEGIN CSTYLED */

/*
 * This implements the 'symbol_name_mangling_v2' demangling for rust as
 * described in Rust RFC 2603 as opposed to the original (now called
 * legacy) mangling older versions of rust used (implemented in rust.c).
 *
 * The specification can be viewed at:
 *     https://github.com/rust-lang/rfcs/blob/master/text/2603-rust-symbol-name-mangling-v0.md
 */

/* END CSTYLED */

#include <errno.h>
#include <libcustr.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rust.h"

/*
 * Help track amount of additional output added to rs_demangled across
 * a function call (to allow that portion to be output for debugging)
 */
#define	SAVE_LEN(_st, _len) _len = custr_len((_st)->rs_demangled)
#define	CSTR_END(_st, _len)					\
	((int)(custr_len((_st)->rs_demangled) - (_len))),	\
	custr_cstr((_st)->rs_demangled) + (_len)

typedef enum const_type_class {
	CTC_INVALID = -1,
	CTC_UNSIGNED,
	CTC_SIGNED,
	CTC_CHAR,
	CTC_BOOL,
} const_type_class_t;

/*
 * Sometimes, parsing something is optional.  In this case a failure to
 * parse is fine, however we still want to consider a fatal error as
 * failure.
 */
#define	OPTIONAL(_st, _f) ((_f) || !HAS_ERROR(_st))

static boolean_t rustv0_valid_sym(const strview_t *);
static const_type_class_t rustv0_classify_const_type(char);
static boolean_t rustv0_parse_hex_num(rust_state_t *restrict,
    strview_t *restrict, uint64_t *restrict);
static boolean_t rustv0_parse_base62(rust_state_t *restrict,
    strview_t *restrict, uint64_t *restrict);

static boolean_t rustv0_parse_undisambiguated_identifier(
    rust_state_t *restrict, strview_t *restrict, boolean_t);
static boolean_t rustv0_parse_disambiguator(rust_state_t *restrict,
    strview_t *restrict, uint64_t *restrict);

static boolean_t rustv0_parse_path(rust_state_t *restrict, strview_t *restrict,
    boolean_t);
static boolean_t rustv0_parse_impl_path(rust_state_t *restrict,
    strview_t *restrict, boolean_t);
static boolean_t rustv0_parse_nested_path(rust_state_t *restrict,
    strview_t *restrict, boolean_t);
static boolean_t rustv0_parse_basic_type(rust_state_t *restrict,
    strview_t *restrict);
static boolean_t rustv0_parse_backref(rust_state_t *restrict,
    strview_t *restrict,
    boolean_t (*)(rust_state_t *restrict, strview_t *restrict, boolean_t),
    boolean_t);
static boolean_t rustv0_parse_lifetime(rust_state_t *restrict,
    strview_t *restrict);
static boolean_t rustv0_parse_const(rust_state_t *restrict,
    strview_t *restrict, boolean_t);
static boolean_t rustv0_parse_fnsig(rust_state_t *restrict,
    strview_t *restrict);
static boolean_t rustv0_parse_dynbounds(rust_state_t *restrict,
    strview_t *restrict);
static boolean_t rustv0_parse_generic_arg(rust_state_t *restrict,
    strview_t *restrict, boolean_t);

boolean_t
rust_demangle_v0(rust_state_t *restrict st, strview_t *restrict sv)
{
	boolean_t save_skip;
	boolean_t ret;

	/* Make sure all the characters are valid */
	if (!rustv0_valid_sym(sv)) {
		st->rs_error = EINVAL;
		return (B_FALSE);
	}

	/*
	 * <symbol-name> = "_R" [<decimal-number>] <path>
	 *	[<instantiating-crate>]
	 *
	 * We've already parsed the prefix in rust_demangle(), as well
	 * as made sure there's no [<decimal-number>] present, so
	 * start with <path>.
	 */
	if (!rustv0_parse_path(st, sv, B_TRUE))
		return (B_FALSE);

	/* [<instantiating crate>] -- parse but don't save */
	SKIP_BEGIN(st, save_skip);
	ret = OPTIONAL(st, rustv0_parse_path(st, sv, B_FALSE));
	SKIP_END(st, save_skip);
	if (!ret)
		return (B_FALSE);

	/* If nothing's left, we know we're done */
	if (sv_remaining(sv) == 0)
		return (!HAS_ERROR(st));

	/*
	 * LLVM sometimes will suffix symbols starting with a '.'
	 * followed by extra data. For things that start with
	 * ".llvm.", we discard the rest of the string.  For
	 * other things that start with '.', we copy the
	 * results to the final string. This matches
	 * what the rust native demangler crate does, and
	 * we don't see a reason to deviate from their
	 * behavior.
	 */
	if (sv_consume_if(sv, ".llvm."))
		return (!HAS_ERROR(st));

	if (sv_peek(sv, 0) != '.') {
		DEMDEBUG("%s: Unexpected trailing data at the end of the "
		    "name: '%.*s'", __func__, SV_PRINT(sv));
		st->rs_error = EINVAL;
		return (B_FALSE);
	}

	return (rust_append_sv(st, sv_remaining(sv), sv));
}

/*
 * Parse an optional list terminated by 'E'. Each result of 'fn' is
 * separated by 'sep' in the output.
 */
static boolean_t
rustv0_parse_opt_list(rust_state_t *restrict st, strview_t *restrict sv,
    boolean_t (*fn)(rust_state_t *restrict, strview_t *restrict, boolean_t),
    const char *restrict sep, boolean_t bval, size_t *restrict countp)
{
	size_t count = 0;

	DEMDEBUG("%s: str = '%.*s'", __func__, SV_PRINT(sv));

	while (sv_remaining(sv) > 0) {
		if (sv_consume_if_c(sv, 'E')) {
			if (countp != NULL)
				*countp += count;
			return (B_TRUE);
		}

		if (count > 0 && !rust_append(st, sep))
			return (B_FALSE);

		if (!fn(st, sv, bval))
			return (B_FALSE);

		count++;
	}

	/*
	 * An optional list should terminate with an 'E'.  If we get here,
	 * we ran out of charaters and didn't terminate as we should.
	 */
	return (B_FALSE);
}

static boolean_t
rustv0_parse_uint_type(rust_state_t *restrict st, strview_t *sv)
{
	const char *str = NULL;
	strview_t save;
	char c;

	if (HAS_ERROR(st) || sv_remaining(sv) == 0)
		return (B_FALSE);

	sv_init_sv(&save, sv);

	switch (c = sv_consume_c(sv)) {
	case 'h':
		str = "u8";
		break;
	case 't':
		str = "u16";
		break;
	case 'm':
		str = "u32";
		break;
	case 'y':
		str = "u64";
		break;
	case 'o':
		str = "u128";
		break;
	case 'j':	/* usize */
		str = "usize";
		break;
	default:
		sv_init_sv(sv, &save);
		return (B_FALSE);
	}

	DEMDEBUG("%s: %c -> %s", __func__, c, str);
	return (rust_append(st, str));
}

static boolean_t
rustv0_parse_basic_type(rust_state_t *restrict st, strview_t *restrict sv)
{
	const char *str = NULL;
	strview_t save;
	char c;

	if (HAS_ERROR(st) || sv_remaining(sv) == 0)
		return (B_FALSE);

	if (rustv0_parse_uint_type(st, sv))
		return (B_TRUE);

	sv_init_sv(&save, sv);

	switch (c = sv_consume_c(sv)) {
	case 'a':
		str = "i8";
		break;
	case 'b':
		str = "bool";
		break;
	case 'c':
		str = "char";
		break;
	case 'd':
		str = "f64";
		break;
	case 'e':
		str = "str";
		break;
	case 'f':
		str = "f32";
		break;
	case 'i':
		str = "isize";
		break;
	case 'l':
		str = "i32";
		break;
	case 'n':
		str = "i128";
		break;
	case 'p':
		str = "_";
		break;
	case 's':
		str = "i16";
		break;
	case 'u':
		str = "()";
		break;
	case 'v':
		str = "...";
		break;
	case 'x':
		str = "i64";
		break;
	case 'z':
		str = "!";
		break;
	default:
		sv_init_sv(sv, &save);
		return (B_FALSE);
	}

	DEMDEBUG("%s: %c -> %s", __func__, c, str);
	return (rust_append(st, str));
}

static boolean_t
rustv0_parse_type(rust_state_t *restrict st, strview_t *restrict sv,
    boolean_t dummy __unused)
{
	strview_t save;
	size_t len, tuple_elem_count;
	boolean_t ret;
	char c;

	if (HAS_ERROR(st))
		return (B_FALSE);

	DEMDEBUG("%s: str='%.*s'", __func__, SV_PRINT(sv));

	if (sv_remaining(sv) == 0)
		return (B_FALSE);

	SAVE_LEN(st, len);
	sv_init_sv(&save, sv);

	switch (c = sv_consume_c(sv)) {
	case 'A':
		ret = rust_appendc(st, '[') &&
		    rustv0_parse_type(st, sv, B_FALSE) &&
		    rust_append(st, "; ") &&
		    rustv0_parse_const(st, sv, B_FALSE) &&
		    rust_appendc(st, ']');
		break;
	case 'S':
		ret = rust_appendc(st, '[') &&
		    rustv0_parse_type(st, sv, B_FALSE) &&
		    rust_appendc(st, ']');
		break;
	case 'T':
		tuple_elem_count = 0;
		ret = rust_appendc(st, '(') &&
		    rustv0_parse_opt_list(st, sv, rustv0_parse_type, ", ",
		    B_FALSE, &tuple_elem_count) &&
		    rust_append(st, (tuple_elem_count == 1) ? ",)" : ")");
		break;
	case 'R':
	case 'Q':
		/* `&mut T` or `&'... mut T` */
		if (!(ret = rust_appendc(st, '&')))
			break;

		/*
		 * lifetime is optional, but we need to add a trailing
		 * space if present (so we cannot use the OPTIONAL macro).
		 */
		if (rustv0_parse_lifetime(st, sv)) {
			if (!(ret = rust_appendc(st, ' ')))
				break;
		} else if (HAS_ERROR(st)) {
			break;
		}

		ret = rust_append(st, (c == 'Q') ? "mut " : "") &&
		    rustv0_parse_type(st, sv, B_FALSE);
		break;
	case 'P':
		ret = rust_append(st, "*const ") &&
		    rustv0_parse_type(st, sv, B_FALSE);
		break;
	case 'O':
		ret = rust_append(st, "*mut ") &&
		    rustv0_parse_type(st, sv, B_FALSE);
		break;
	case 'F':
		ret = rustv0_parse_fnsig(st, sv);
		break;
	case 'D':
		ret = rust_append(st, "dyn ") &&
		    rustv0_parse_dynbounds(st, sv);
		if (!ret)
			break;

		/*
		 * Rust RFC2603 shows the lifetime as required, however
		 * it appears this is optional.
		 */
		DEMDEBUG("%s: pre-lifetime: '%*s'", __func__, SV_PRINT(sv));

		/*
		 * We only want to print a non-zero (non "'_")
		 * lifetime.
		 */
		if (sv_consume_if(sv, "L_"))
			break;

		/*
		 * But if there is a lifetime we want to print,
		 * we want to prepend " + " before it.
		 */
		if (sv_peek(sv, 0) == 'L' &&
		    !(ret = rust_append(st, " + ")))
			break;

		ret = rustv0_parse_lifetime(st, sv);
		break;
	default:
		sv_init_sv(sv, &save);

		ret = rustv0_parse_backref(st, sv, rustv0_parse_type,
		    B_FALSE) ||
		    rustv0_parse_basic_type(st, sv);
		if (ret)
			break;

		ret = rustv0_parse_path(st, sv, B_FALSE);
		break;
	}

	DEMDEBUG("%s: type='%.*s' (%s)", __func__, CSTR_END(st, len),
	    ret ? "success" : "fail");

	return (ret);
}

/*
 * <path> = "C" <identifier>		crate root
 *	| "M" <impl-path> <type>	<T>
 *	| "X" <impl-path> <type> <path>	<T as Trait> (trait impl)
 *	| "Y" <type> <path>		<T as Trait> (trait definition)
 *	| "N" <ns> <path> <identifier>	...::ident (nested path)
 *	| "I" <path> {<generic-arg>} "E" ...<T, U>
 *	| <backref>
 */
static boolean_t
rustv0_parse_path(rust_state_t *restrict st, strview_t *restrict sv,
    boolean_t in_value)
{
	strview_t save;
	uint64_t disamb = 0;
	size_t len;
	boolean_t ret = B_FALSE;
	boolean_t save_skip;
	boolean_t args_stay_save = st->rs_args_stay_open;
	boolean_t args_open_save = st->rs_args_is_open;

	if (HAS_ERROR(st))
		return (B_FALSE);

	DEMDEBUG("%s: str='%.*s'", __func__, SV_PRINT(sv));

	if (sv_remaining(sv) == 0)
		return (B_FALSE);

	SAVE_LEN(st, len);
	sv_init_sv(&save, sv);

	switch (sv_consume_c(sv)) {
	case 'C':
		if (!OPTIONAL(st, rustv0_parse_disambiguator(st, sv, &disamb)))
			goto done;

		if (!rustv0_parse_undisambiguated_identifier(st, sv, B_FALSE))
			goto done;

		if (st->rs_verbose &&
		    !rust_append_printf(st, "[%" PRIx64 "]", disamb))
			goto done;
		break;
	case 'M':
		SKIP_BEGIN(st, save_skip);
		if (!rustv0_parse_impl_path(st, sv, in_value)) {
			SKIP_END(st, save_skip);
			goto done;
		}
		SKIP_END(st, save_skip);

		if (!rust_appendc(st, '<') ||
		    !rustv0_parse_type(st, sv, B_FALSE) ||
		    !rust_appendc(st, '>'))
			goto done;
		break;
	case 'X':
		SKIP_BEGIN(st, save_skip);
		if (!rustv0_parse_impl_path(st, sv, in_value)) {
			SKIP_END(st, save_skip);
			goto done;
		}
		SKIP_END(st, save_skip);
		/*FALLTHRU*/
	case 'Y':
		if (!rust_appendc(st, '<') ||
		    !rustv0_parse_type(st, sv, B_FALSE) ||
		    !rust_append(st, " as ") ||
		    !rustv0_parse_path(st, sv, B_FALSE) ||
		    !rust_appendc(st, '>'))
			goto done;
		break;
	case 'N':
		if (!rustv0_parse_nested_path(st, sv, in_value))
			goto done;
		break;
	case 'I':
		st->rs_args_stay_open = B_FALSE;
		st->rs_args_is_open = B_FALSE;

		if (!rustv0_parse_path(st, sv, in_value))
			goto done;

		if (in_value && !rust_append(st, "::"))
			goto done;

		if (!rust_appendc(st, '<') ||
		    !rustv0_parse_opt_list(st, sv, rustv0_parse_generic_arg,
		    ", ", B_FALSE, NULL))
			goto done;

		st->rs_args_stay_open = args_stay_save;
		st->rs_args_is_open = args_open_save;

		/*
		 * If we were asked to not close our list, then don't and
		 * indicate that the list is open.
		 */
		if (st->rs_args_stay_open) {
			st->rs_args_stay_open = B_FALSE;
			st->rs_args_is_open = B_TRUE;
		} else if (!rust_appendc(st, '>')) {
			goto done;
		}
		break;
	default:
		/*
		 * Didn't recognize the letter, so it has to be a path. Restore
		 * sv to state prior to switch and continue.
		 */
		sv_init_sv(sv, &save);
		if (!rustv0_parse_backref(st, sv, rustv0_parse_path, in_value))
			goto done;
	}

	ret = B_TRUE;

done:
	DEMDEBUG("%s: path='%.*s' (%s)", __func__, CSTR_END(st, len),
	    ret ? "success" : "fail");

	return (ret);
}

static boolean_t
rustv0_parse_impl_path(rust_state_t *restrict st, strview_t *restrict sv,
    boolean_t in_value)
{
	uint64_t val = 0;

	return (OPTIONAL(st, rustv0_parse_disambiguator(st, sv, &val)) &&
	    rustv0_parse_path(st, sv, in_value));
}

/*
 * A bit of a hack -- when printing a nested path, we need to know
 * if the identifier is there or not in order to correctly format
 * the output preceeding it (when present). This peeks ahead and
 * determines this.
 */
static boolean_t
rustv0_has_name(rust_state_t *restrict st, strview_t *restrict sv,
    boolean_t *has_namep)
{
	strview_t save;

	if (HAS_ERROR(st))
		return (B_FALSE);

	DEMDEBUG("%s: str='%.*s'", __func__, SV_PRINT(sv));

	if (sv_remaining(sv) == 0)
		return (B_FALSE);

	sv_init_sv(&save, sv);

	/* For checking the length, we don't care if it's punycode or not */
	(void) sv_consume_if_c(&save, 'u');

	if (sv_remaining(sv) == 0) {
		st->rs_error = EINVAL;
		return (B_FALSE);
	}

	if (sv_consume_if_c(&save, '0')) {
		*has_namep = B_FALSE;
		return (B_TRUE);
	}

	*has_namep = B_TRUE;
	return (B_TRUE);
}

static boolean_t
rustv0_parse_nested_path(rust_state_t *restrict st, strview_t *restrict sv,
    boolean_t in_value)
{
	uint64_t disambiguator = 0;
	size_t len = 0;
	char ns;
	boolean_t ret = B_FALSE;
	boolean_t has_name;

	if (HAS_ERROR(st))
		return (B_FALSE);

	DEMDEBUG("%s: str='%.*s'", __func__, SV_PRINT(sv));

	if (sv_remaining(sv) == 0)
		return (B_FALSE);

	SAVE_LEN(st, len);

	ns = sv_consume_c(sv);

	if (!rustv0_parse_path(st, sv, in_value))
		goto done;

	if (!OPTIONAL(st, rustv0_parse_disambiguator(st, sv, &disambiguator)))
		goto done;

	if (!rustv0_has_name(st, sv, &has_name))
		goto done;

	if (ISUPPER(ns)) {
		if (!rust_append(st, "::{"))
			goto done;

		switch (ns) {
		case 'C':
			if (!rust_append(st, "closure"))
				goto done;
			break;
		case 'S':
			if (!rust_append(st, "shim"))
				goto done;
			break;
		default:
			if (!rust_appendc(st, ns))
				goto done;
			break;
		}

		if (has_name && !rust_appendc(st, ':'))
			goto done;

		if (!rustv0_parse_undisambiguated_identifier(st, sv, B_FALSE))
			goto done;

		ret = rust_append_printf(st, "#%" PRIu64 "}", disambiguator);
	} else {
		if (has_name) {
			if (!(ret = rust_append(st, "::")))
				goto done;
		}
		ret = rustv0_parse_undisambiguated_identifier(st, sv, B_FALSE);
	}

done:
	DEMDEBUG("%s: nested path = '%.*s' (%s)", __func__, CSTR_END(st, len),
	    ret ? "success" : "fail");

	return (ret);
}

/*
 * <disambiguator> = "s" <base-64-number>
 *
 */
static boolean_t
rustv0_parse_disambiguator(rust_state_t *restrict st, strview_t *restrict sv,
    uint64_t *valp)
{
	if (HAS_ERROR(st) || sv_remaining(sv) < 2)
		return (B_FALSE);

	DEMDEBUG("%s: str='%.*s'", __func__, SV_PRINT(sv));

	*valp = 0;

	if (!sv_consume_if_c(sv, 's'))
		return (B_FALSE);

	if (!rustv0_parse_base62(st, sv, valp)) {
		st->rs_error = EINVAL;
		return (B_FALSE);
	}

	/*
	 * Rust RFC 2603 details this in Appendix A, but not the main
	 * portion of the RFC. If no disambiguator is present, the value
	 * is 0, if the decoded value is 0, the index is 1, ...
	 * rustv0_parse_base62() already adjusts _ -> 0, 0 -> 1, so we
	 * only need to add one here to complete the adjustment.
	 */
	*valp = *valp + 1;

	DEMDEBUG("%s: disambiguator=%" PRIu64, __func__, *valp);
	return (B_TRUE);
}

/* <undisambiguated-identifier> = ["u"] <decimal-number> ["_"] <bytes> */
static boolean_t
rustv0_parse_undisambiguated_identifier(rust_state_t *restrict st,
    strview_t *restrict sv, boolean_t repl_underscore)
{
	uint64_t len = 0;
	boolean_t puny = B_FALSE;

	if (HAS_ERROR(st))
		return (B_FALSE);

	DEMDEBUG("%s: str='%.*s'", __func__, SV_PRINT(sv));

	if (sv_remaining(sv) == 0)
		return (B_FALSE);

	if (sv_consume_if_c(sv, 'u'))
		puny = B_TRUE;

	if (!rust_parse_base10(st, sv, &len))
		return (B_FALSE);

	/* skip optional separator '_' */
	(void) sv_consume_if_c(sv, '_');

	if (sv_remaining(sv) < len) {
		DEMDEBUG("%s: ERROR: identifier length (%" PRIu64 ") "
		    "> remaining bytes (%zu)", __func__, len,
		    sv_remaining(sv));
		return (B_FALSE);
	}

	/* 0 length identifiers are acceptable */
	if (len == 0)
		return (B_TRUE);

	if (puny) {
		strview_t ident;

		sv_init_sv_range(&ident, sv, len);
		if (!rustv0_puny_decode(st, &ident, repl_underscore))
			return (B_FALSE);

		sv_consume_n(sv, len);
		return (B_TRUE);
	}

	/*
	 * rust identifiers do not contain '-'. However ABI identifiers
	 * are allowed to contain them (e.g. extern "foo-bar" fn ...).
	 * They are substituted with '_' in the mangled output. If we
	 * do not need to reverse this, we can just append 'len' bytes
	 * of sv.  Otherwise we need to go through and reverse this
	 * substitution.
	 */
	if (!repl_underscore)
		return (rust_append_sv(st, len, sv));

	/*
	 * We checked earlier that len < sv_remaining(sv); so this loop
	 * cannot overrun.
	 */
	for (size_t i = 0; i < len; i++) {
		char c = sv_consume_c(sv);

		if (c == '_')
			c = '-';

		if (!rust_appendc(st, c))
			return (B_FALSE);
	}

	return (B_TRUE);
}

/* <backref> = "B" <base-62-number> */
static boolean_t
rustv0_parse_backref(rust_state_t *restrict st, strview_t *restrict sv,
    boolean_t (*fn)(rust_state_t *restrict, strview_t *restrict, boolean_t b),
    boolean_t bval)
{
	strview_t backref;
	strview_t target;
	uint64_t idx = 0;
	size_t save_len;
	size_t len;

	if (HAS_ERROR(st))
		return (B_FALSE);

	sv_init_sv(&backref, sv);

	if (!sv_consume_if_c(sv, 'B'))
		return (B_FALSE);

	DEMDEBUG("%s: str='B%.*s'", __func__, SV_PRINT(sv));

	if (!rustv0_parse_base62(st, sv, &idx)) {
		st->rs_error = EINVAL;
		return (B_FALSE);
	}

	/*
	 * Determine how many bytes we've consumed (up to the start of
	 * the current backref token).
	 */
	VERIFY3P(backref.sv_first, >=, st->rs_orig.sv_first);
	len = (size_t)(uintptr_t)(backref.sv_first - st->rs_orig.sv_first);

	/*
	 * The backref can only refer to an index prior to the start of
	 * the current backref token -- that is must always refer back in
	 * the string, never to the current position or beyond.
	 */
	if (idx >= len) {
		DEMDEBUG("%s: ERROR: backref index (%" PRIu64 ") "
		    "is out of range [0, %zu)", __func__, idx, len);
		st->rs_error = ERANGE;
		return (B_FALSE);
	}

	/*
	 * Create a strview_t of the original string (sans prefix) by
	 * copying from st->rs_orig. The length of the target strview_t is
	 * capped to end immediately prior to this backref token. Since we
	 * enforce that backrefs must always refer to already processed
	 * portions of the string (i.e. must always refer backwards), and the
	 * length of the strview_t is set to end prior to the start of this
	 * backref token, we guarantee processing of a backref will always
	 * terminate before it can possibly encounter this backref token
	 * and cause a loop -- either the processing terminates normally or
	 * it reaches the end of the capped strview_t.
	 */
	sv_init_sv_range(&target, &st->rs_orig, len);

	/*
	 * Consume all the input in the target strview_t up to the index
	 */
	sv_consume_n(&target, idx);

	DEMDEBUG("%s: backref starting at %" PRIu64 " str='%.*s'%s", __func__,
	    idx, SV_PRINT(&target), st->rs_skip ? " (skipping)" : "");

	/*
	 * If we're skipping the output, there's no reason to bother reparsing
	 * the output -- we're not going to save it. We still setup everything
	 * so that the debug output is still emitted.
	 */
	if (st->rs_skip)
		return (B_TRUE);

	SAVE_LEN(st, save_len);
	if (!fn(st, &target, bval))
		return (B_FALSE);

	DEMDEBUG("%s: backref is '%.*s'", __func__, CSTR_END(st, save_len));
	return (B_TRUE);
}

static boolean_t
rustv0_append_lifetime(rust_state_t *restrict st, uint64_t lifetime)
{
	uint64_t bound_lt;

	if (HAS_ERROR(st))
		return (B_FALSE);

	if (!rust_appendc(st, '\''))
		return (B_FALSE);

	if (lifetime == 0)
		return (rust_appendc(st, '_'));

	if (sub_overflow(st->rs_lt_depth, lifetime, &bound_lt)) {
		DEMDEBUG("%s: ERROR: lifetime value %" PRIu64
		    " > current depth %" PRIu64, __func__, lifetime,
		    st->rs_lt_depth);
		st->rs_lt_depth = ERANGE;
		return (B_FALSE);
	}

	/*
	 * Use 'a, 'b, ...
	 */
	if (bound_lt < 26) {
		char c = (char)bound_lt + 'a';
		return (rust_append_printf(st, "%c", c));
	}

	/*
	 * Otherwise, use '_123, '_456, ...
	 */
	return (rust_append_printf(st, "_%" PRIu64, bound_lt));
}

static boolean_t
rustv0_parse_lifetime(rust_state_t *restrict st, strview_t *restrict sv)
{
	uint64_t lifetime;

	if (!sv_consume_if_c(sv, 'L'))
		return (B_FALSE);

	if (!rustv0_parse_base62(st, sv, &lifetime))
		return (B_FALSE);

	return (rustv0_append_lifetime(st, lifetime));
}

static boolean_t
rustv0_parse_const_data(rust_state_t *restrict st,
    const_type_class_t type_class, strview_t *restrict sv)
{
	uint64_t val = 0;
	size_t save_len;
	boolean_t neg = B_FALSE;
	boolean_t ret = B_FALSE;

	VERIFY3S(type_class, !=, CTC_INVALID);

	if (HAS_ERROR(st))
		return (B_FALSE);

	DEMDEBUG("%s: str='%.*s'", __func__, SV_PRINT(sv));
	SAVE_LEN(st, save_len);

	if (sv_remaining(sv) == 0)
		return (B_FALSE);

	if (type_class == CTC_SIGNED && sv_consume_if_c(sv, 'n'))
		neg = B_TRUE;

	ret = OPTIONAL(st, rustv0_parse_hex_num(st, sv, &val)) &&
	    sv_consume_if_c(sv, '_');
	if (!ret)
		goto done;

	switch (type_class) {
	case CTC_SIGNED:
	case CTC_UNSIGNED:
		ret = rust_append_printf(st, "%s%" PRIu64, neg ? "-" : "", val);
		break;
	case CTC_BOOL:
		if (val > 1) {
			DEMDEBUG("%s: invalid bool val %" PRIu64, __func__,
			    val);
			ret = B_FALSE;
			break;
		}
		ret = rust_append_printf(st, "%s",
		    (val == 0) ? "false" : "true");
		break;
	case CTC_CHAR:
		if (val > UINT32_MAX) {
			DEMDEBUG("%s: char value %" PRIu64 " out of range",
			    __func__, val);
			ret = B_FALSE;
			break;
		}

		ret = rust_appendc(st, '\'') && rust_append_utf8_c(st, val) &&
		    rust_appendc(st, '\'');
		break;
	default:
		ret = B_FALSE;
	}

done:
	DEMDEBUG("%s: const='%.*s' (%s)", __func__, CSTR_END(st, save_len),
	    ret ? "success" : "fail");

	return (ret);
}

static boolean_t
rustv0_parse_const(rust_state_t *restrict st, strview_t *restrict sv,
    boolean_t dummy __unused)
{
	strview_t type;
	size_t start_len;
	const_type_class_t ctype_class;
	char ctype;
	boolean_t save_skip;
	boolean_t ret;

	if (HAS_ERROR(st))
		return (B_FALSE);

	DEMDEBUG("%s: str='%.*s'", __func__, SV_PRINT(sv));
	SAVE_LEN(st, start_len);

	if (sv_remaining(sv) == 0)
		return (B_FALSE);

	if (rustv0_parse_backref(st, sv, rustv0_parse_const, B_FALSE))
		return (B_TRUE);

	if (sv_consume_if_c(sv, 'p')) {
		ret = rust_appendc(st, '_');
		goto done;
	}

	ctype = sv_peek(sv, 0);
	ctype_class = rustv0_classify_const_type(ctype);
	if (ctype_class == CTC_INVALID) {
		DEMDEBUG("%s: const type isn't a valid const generic type",
		    __func__);
		return (B_FALSE);
	}

	/*
	 * This isn't spelled out clearly in Rust RFC 2603, but currently
	 * only unsigned int types are allowed at this point. However, we
	 * have a bit of a potential tricky situation. Unlike formatting
	 * the other tokens, if we want to display the type, we do so
	 * _after_ the value, even though the type appears first.
	 *
	 * This is bit of a hack, but we save off the input position from
	 * sv before the parse the type. We then parse it without saving
	 * the resulting value, then parse and output the constant. If
	 * we wish to then display the type, we can go back and parse
	 * the type again, this time saving the result.
	 */
	sv_init_sv(&type, sv);

	SKIP_BEGIN(st, save_skip);
	ret = rustv0_parse_type(st, sv, B_FALSE);
	SKIP_END(st, save_skip);

	if (!ret) {
		DEMDEBUG("%s: const type isn't valid", __func__);
		return (B_FALSE);
	}

	if (sv_consume_if_c(sv, 'p')) {
		ret = rust_appendc(st, '_');
	} else {
		ret = rustv0_parse_const_data(st, ctype_class, sv);
	}
	if (!ret)
		goto done;

	if (st->rs_show_const_type) {
		ret = rust_append(st, ": ") &&
		    rustv0_parse_uint_type(st, &type);
	}

done:
	DEMDEBUG("%s: const='%.*s' (%s)", __func__, CSTR_END(st, start_len),
	    ret ? "success" : "fail");
	return (ret);
}

static boolean_t
rustv0_parse_abi(rust_state_t *restrict st, strview_t *restrict sv)
{
	DEMDEBUG("%s: str = '%.*s'", __func__, SV_PRINT(sv));

	if (sv_consume_if_c(sv, 'C'))
		return (rust_appendc(st, 'C'));

	return (rustv0_parse_undisambiguated_identifier(st, sv, B_TRUE));
}

static boolean_t
rustv0_parse_binder(rust_state_t *restrict st, strview_t *restrict sv)
{
	uint64_t n, i;

	if (!sv_consume_if_c(sv, 'G'))
		return (B_FALSE);

	if (!rustv0_parse_base62(st, sv, &n))
		return (B_FALSE);
	n += 1;

	if (!rust_append(st, "for<"))
		return (B_FALSE);

	for (i = 0; i < n; i++) {
		if (i > 0 && !rust_append(st, ", "))
			return (B_FALSE);

		st->rs_lt_depth++;
		if (!rustv0_append_lifetime(st, 1))
			return (B_FALSE);
	}

	if (!rust_append(st, "> "))
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * <fn-sig> := [<binder>] ["U"] ["K" <abi>] {type} "E" <type>
 *
 * Note that while the Rust RFC states the binder is manditory, based on
 * actual examples, and comparing with the rust-based demangler, it is in
 * fact optional.
 */
static boolean_t
rustv0_parse_fnsig(rust_state_t *restrict st, strview_t *restrict sv)
{
	uint64_t save_lt = st->rs_lt_depth;

	DEMDEBUG("%s: str = '%.*s'", __func__, SV_PRINT(sv));

	if (!OPTIONAL(st, rustv0_parse_binder(st, sv)))
		return (B_FALSE);

	if (sv_consume_if_c(sv, 'U') && !rust_append(st, "unsafe "))
		return (B_FALSE);

	if (sv_consume_if_c(sv, 'K') &&
	    (!rust_append(st, "extern \"") || !rustv0_parse_abi(st, sv) ||
	    !rust_append(st, "\" ")))
		return (B_FALSE);

	if (!rust_append(st, "fn("))
		return (B_FALSE);

	if (!rustv0_parse_opt_list(st, sv, rustv0_parse_type, ", ", B_FALSE,
	    NULL)) {
		return (B_FALSE);
	}

	if (!rust_appendc(st, ')'))
		return (B_FALSE);

	/* If the return type is (), don't print it */
	if (!sv_consume_if_c(sv, 'u')) {
		if (!rust_append(st, " -> "))
			return (B_FALSE);

		if (!rustv0_parse_type(st, sv, B_FALSE))
			return (B_FALSE);
	}

	st->rs_lt_depth = save_lt;

	return (B_TRUE);
}

/*
 * <dyn-trait-assoc-binding> = "p" <undisambiguated-identifier> <type>
 */
static boolean_t
rustv0_parse_dyn_trait_assoc_binding(rust_state_t *restrict st,
    strview_t *restrict sv, boolean_t open)
{
	size_t save_len;

	if (HAS_ERROR(st))
		return (B_FALSE);

	if (sv_remaining(sv) == 0)
		return (B_FALSE);

	if (!sv_consume_if_c(sv, 'p'))
		return (B_FALSE);

	DEMDEBUG("%s: str='%.*s'", __func__, SV_PRINT(sv));
	SAVE_LEN(st, save_len);

	if (!rust_append(st, open ? ", " : "<"))
		return (B_FALSE);

	if (!rustv0_parse_undisambiguated_identifier(st, sv, B_FALSE)) {
		st->rs_error = EINVAL;
		return (B_FALSE);
	}

	if (!rust_append(st, " = "))
		return (B_FALSE);

	if (!rustv0_parse_type(st, sv, B_FALSE)) {
		st->rs_error = EINVAL;
		return (B_FALSE);
	}

	DEMDEBUG("%s: binding='%.*s'", __func__, CSTR_END(st, save_len));

	return (B_TRUE);
}

static boolean_t
rustv0_parse_dyn_trait(rust_state_t *restrict st, strview_t *restrict sv,
    boolean_t dummy __unused)
{
	boolean_t stay_save = st->rs_args_stay_open;
	boolean_t open_save = st->rs_args_is_open;
	boolean_t open = B_FALSE;

	if (HAS_ERROR(st))
		return (B_FALSE);

	DEMDEBUG("%s: str='%.*s'", __func__, SV_PRINT(sv));

	/*
	 * This is a bit subtle, but when formatting a trait in trait,
	 * we want something like this:
	 *
	 *	dyn Trait<T, U, Assoc=X>
	 *
	 * instead of
	 *
	 *	dyn Trait<T, U, <Assoc=X>>
	 *
	 * So when parsing the path, if we encounter generic arguments, we want
	 * the arg list to remain open at the end of processing the path so
	 * we can append the bindings to it. We set rs_args_stay_open to B_TRUE
	 * to indidcate to rustv0_parse_path() that a generic argument list
	 * should not be closed (i.e. don't append a '>' at the end of the
	 * list). If rustv0_parse_path() encounters a list of generic arguments,
	 * it will also set rs->args_is_open to indiciate it opened the list.
	 * We save this in 'open' so that when we process the associated
	 * bindings, we know if we need to open the list on the first binding
	 * or not -- we don't want 'dyn Trait<>' if there are no bindings,
	 * just 'dyn Trait'.
	 */
	st->rs_args_stay_open = B_TRUE;
	st->rs_args_is_open = B_FALSE;

	if (!rustv0_parse_path(st, sv, B_FALSE)) {
		st->rs_args_stay_open = stay_save;
		st->rs_args_is_open = open_save;
		return (B_FALSE);
	}

	open = st->rs_args_is_open;

	st->rs_args_stay_open = stay_save;
	st->rs_args_is_open = open_save;

	while (rustv0_parse_dyn_trait_assoc_binding(st, sv, open)) {
		open = B_TRUE;
	}

	if (HAS_ERROR(st))
		return (B_FALSE);

	if (open && !rust_appendc(st, '>'))
		return (B_FALSE);

	return (!HAS_ERROR(st));
}

static boolean_t
rustv0_parse_dynbounds(rust_state_t *restrict st, strview_t *restrict sv)
{
	uint64_t save_lt = st->rs_lt_depth;

	if (HAS_ERROR(st))
		return (B_FALSE);

	DEMDEBUG("%s: str='%.*s'", __func__, SV_PRINT(sv));

	/*
	 * This is another case where Rust RFC2603 seems to disagree with
	 * the implementation. The RFC implies this is mandatory, while
	 * the implementations treat it as optional.
	 */
	if (!OPTIONAL(st, rustv0_parse_binder(st, sv)))
		return (B_FALSE);

	if (!rustv0_parse_opt_list(st, sv, rustv0_parse_dyn_trait, " + ",
	    B_FALSE, NULL))
		return (B_FALSE);

	st->rs_lt_depth = save_lt;

	return (B_TRUE);
}

static boolean_t
rustv0_parse_generic_arg(rust_state_t *restrict st, strview_t *restrict sv,
    boolean_t dummy __unused)
{
	DEMDEBUG("%s: str='%.*s'", __func__, SV_PRINT(sv));

	if (sv_consume_if_c(sv, 'K'))
		return (rustv0_parse_const(st, sv, B_FALSE));

	if (rustv0_parse_lifetime(st, sv))
		return (B_TRUE);

	return (rustv0_parse_type(st, sv, B_FALSE));
}

/*
 * Parse a hex value into *valp. Note that rust only uses lower case
 * hex values.
 */
static boolean_t
rustv0_parse_hex_num(rust_state_t *restrict st, strview_t *restrict sv,
    uint64_t *restrict valp)
{
	uint64_t val = 0;
	size_t ndigits = 0;

	if (HAS_ERROR(st))
		return (B_FALSE);

	DEMDEBUG("%s: str='%.*s'", __func__, SV_PRINT(sv));

	if (sv_remaining(sv) == 0)
		return (B_FALSE);

	/*
	 * Unfortunately, Rust RFC 2603 also doesn't not explicty define
	 * {hex-digits}. We follow what decimal digits does, and treat a
	 * leading 0 as a terminator.
	 */
	while (sv_remaining(sv) > 0) {
		char c = sv_peek(sv, 0);

		if (ISDIGIT(c)) {
			val *= 16;
			val += c - '0';
		} else if (c >= 'a' && c <= 'f') {
			val *= 16;
			val += c - 'a' + 10;
		} else {
			break;
		}

		sv_consume_n(sv, 1);

		if (++ndigits == 1 && val == 0)
			break;
	}

	if (ndigits > 0)
		*valp = val;

	return ((ndigits > 0) ? B_TRUE : B_FALSE);
}

/*
 * Parse a base62 number into *valp.  The number is explicitly terminated
 * by a '_'.  The values are also offset by 0 -- that is '_' == 0,
 * '0_' == 1, ...
 */
static boolean_t
rustv0_parse_base62(rust_state_t *restrict st, strview_t *restrict sv,
    uint64_t *restrict valp)
{
	uint64_t val = 0;
	char c;

	if (HAS_ERROR(st))
		return (B_FALSE);

	DEMDEBUG("%s: str='%.*s'", __func__, SV_PRINT(sv));

	if (sv_remaining(sv) == 0)
		return (B_FALSE);

	/* A terminating '_' without any digits is 0 */
	if (sv_consume_if_c(sv, '_')) {
		*valp = 0;
		return (B_TRUE);
	}

	/* Need at least one valid digit if > 0 */
	if (!ISALNUM(sv_peek(sv, 0)))
		return (B_FALSE);

	while (sv_remaining(sv) > 0) {
		c = sv_consume_c(sv);

		if (c == '_') {
			/*
			 * Because a lone '_' was already handled earlier,
			 * we know we've had at least one other digit and
			 * can increment the value and return.
			 */
			*valp = val + 1;
			return (B_TRUE);
		} else if (ISDIGIT(c)) {
			val *= 62;
			val += c - '0';
		} else if (ISLOWER(c)) {
			val *= 62;
			val += c - 'a' + 10;
		} else if (ISUPPER(c)) {
			val *= 62;
			val += c - 'A' + 36;
		} else {
			return (B_FALSE);
		}
	}

	/* We reached the end of the string without a terminating _ */
	return (B_FALSE);
}

static const_type_class_t
rustv0_classify_const_type(char type)
{
	switch (type) {
	case 'h': case 't': case 'm': case 'y': case 'o': case 'j':
		return (CTC_UNSIGNED);
	case 'a': case 'i': case 'l': case 'n': case 's': case 'x':
		return (CTC_SIGNED);
	case 'b':
		return (CTC_BOOL);
	case 'c':
		return (CTC_CHAR);
	default:
		return (CTC_INVALID);
	}
}

/*
 * Make sure the name is a plausible mangled rust symbol.
 * Non-ASCII are never allowed.  Rust itself uses [_0-9A-Za-z], however
 * some things will add a suffix starting with a '.' (e.g. LLVM thin LTO).
 * As such we proceed in two phases. We first only allow [_0-9A-Z-az] until
 * we encounter a '.'. At that point, any ASCII character is allowed.
 */
static boolean_t
rustv0_valid_sym(const strview_t *sv)
{
	size_t i;
	boolean_t check_rust = B_TRUE;

	for (i = 0; i < sv->sv_rem; i++) {
		char c = sv->sv_first[i];

		if (ISALNUM(c) || c == '_')
			continue;

		if (c == '.') {
			check_rust = B_FALSE;
			continue;
		}

		if (check_rust || (c & 0x80) != 0) {
			DEMDEBUG("%s: ERROR found invalid character '%c' "
			    "in '%.*s' at index %zu",
			    __func__, c, SV_PRINT(sv), i);
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}
