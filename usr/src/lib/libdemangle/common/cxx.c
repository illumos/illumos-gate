/*
 * Ported from LLVM's libcxxabi trunk/src/cxa_demangle.cpp
 * LICENSE.TXT contents is available as ../THIRDPARTYLICENSE
 *
 *                     The LLVM Compiler Infrastructure
 *
 * This file is dual licensed under the MIT and the University of Illinois Open
 * Source Licenses. See LICENSE.TXT for details.
 *
 */

/*
 * Copyright 2018 Jason King.
 */
#include <ctype.h>
#include <errno.h>
#include <locale.h>
#include <note.h>
#include <string.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/isa_defs.h>
#include <sys/debug.h>
#include "demangle-sys.h"
#include "demangle_int.h"
#include "cxx.h"

#ifndef	ARRAY_SIZE
#define	ARRAY_SIZE(x) (sizeof (x) / sizeof (x[0]))
#endif

#define	CPP_QUAL_CONST		(1U)
#define	CPP_QUAL_VOLATILE	(2U)
#define	CPP_QUAL_RESTRICT	(4U)

typedef struct cpp_db_s {
	sysdem_ops_t	*cpp_ops;
	jmp_buf		cpp_jmp;
	name_t		cpp_name;
	sub_t		cpp_subs;
	templ_t		cpp_templ;
	unsigned	cpp_cv;
	unsigned	cpp_ref;
	unsigned	cpp_depth;
	boolean_t	cpp_parsed_ctor_dtor_cv;
	boolean_t	cpp_tag_templates;
	boolean_t	cpp_fix_forward_references;
	boolean_t	cpp_try_to_parse_template_args;
	locale_t	cpp_loc;
} cpp_db_t;

#define	CK(x)						\
	do {						\
		if (!(x)) {				\
			longjmp(db->cpp_jmp, 1);	\
		}					\
	NOTE(CONSTCOND)					\
	} while (0)

#define	TOP_L(db) (&(name_top(&(db)->cpp_name)->strp_l))
#define	RLEN(f, l) ((size_t)((l) - (f)))
#define	NAMT(db, n) (nlen(db) - n)

static inline boolean_t is_xdigit(int);

static boolean_t nempty(cpp_db_t *);
static size_t nlen(cpp_db_t *);
static void nadd_l(cpp_db_t *, const char *, size_t);
static void njoin(cpp_db_t *, size_t, const char *);
static void nfmt(cpp_db_t *, const char *, const char *);

static void save_top(cpp_db_t *, size_t);
static void sub(cpp_db_t *, size_t);

static boolean_t tempty(const cpp_db_t *);
static size_t ttlen(const cpp_db_t *);

static void tsub(cpp_db_t *, size_t);
static void tpush(cpp_db_t *);
static void tpop(cpp_db_t *);
static void tsave(cpp_db_t *, size_t);

static boolean_t db_init(cpp_db_t *, sysdem_ops_t *);
static void db_fini(cpp_db_t *);
static void dump(cpp_db_t *, FILE *);

static void demangle(const char *, const char *, cpp_db_t *);

static const char *parse_type(const char *, const char *, cpp_db_t *);
static const char *parse_builtin_type(const char *, const char *, cpp_db_t *);
static const char *parse_qual_type(const char *, const char *, cpp_db_t *);
static const char *parse_encoding(const char *, const char *, cpp_db_t *);
static const char *parse_dot_suffix(const char *, const char *, cpp_db_t *);
static const char *parse_block_invoke(const char *, const char *, cpp_db_t *);
static const char *parse_special_name(const char *, const char *, cpp_db_t *);
static const char *parse_name(const char *, const char *, boolean_t *,
    cpp_db_t *);
static const char *parse_call_offset(const char *, const char *, locale_t);
static const char *parse_number(const char *, const char *, locale_t);
static const char *parse_nested_name(const char *, const char *, boolean_t *,
    cpp_db_t *);
static const char *parse_local_name(const char *, const char *, boolean_t *,
    cpp_db_t *);
static const char *parse_unscoped_name(const char *, const char *, cpp_db_t *);
static const char *parse_template_args(const char *, const char *, cpp_db_t *);
static const char *parse_substitution(const char *, const char *, cpp_db_t *);
static const char *parse_discriminator(const char *, const char *, locale_t);
static const char *parse_cv_qualifiers(const char *, const char *, unsigned *);
static const char *parse_template_param(const char *, const char *, cpp_db_t *);
static const char *parse_decltype(const char *, const char *, cpp_db_t *);
static const char *parse_template_args(const char *, const char *, cpp_db_t *);
static const char *parse_unqualified_name(const char *, const char *,
    cpp_db_t *);
static const char *parse_template_arg(const char *, const char *, cpp_db_t *);
static const char *parse_expression(const char *, const char *, cpp_db_t *);
static const char *parse_expr_primary(const char *, const char *, cpp_db_t *);
static const char *parse_binary_expr(const char *, const char *,
    const char *, cpp_db_t *);
static const char *parse_prefix_expr(const char *, const char *,
    const char *, cpp_db_t *);
static const char *parse_gs(const char *, const char *, cpp_db_t *);
static const char *parse_idx_expr(const char *, const char *, cpp_db_t *);
static const char *parse_mm_expr(const char *, const char *, cpp_db_t *);
static const char *parse_pp_expr(const char *, const char *, cpp_db_t *);
static const char *parse_trinary_expr(const char *, const char *, cpp_db_t *);
static const char *parse_new_expr(const char *, const char *, cpp_db_t *);
static const char *parse_del_expr(const char *, const char *, cpp_db_t *);
static const char *parse_cast_expr(const char *, const char *, cpp_db_t *);
static const char *parse_sizeof_param_pack_expr(const char *, const char *,
    cpp_db_t *);
static const char *parse_typeid_expr(const char *, const char *, cpp_db_t *);
static const char *parse_throw_expr(const char *, const char *, cpp_db_t *);
static const char *parse_dot_star_expr(const char *, const char *, cpp_db_t *);
static const char *parse_dot_expr(const char *, const char *, cpp_db_t *);
static const char *parse_call_expr(const char *, const char *, cpp_db_t *);
static const char *parse_arrow_expr(const char *, const char *, cpp_db_t *);
static const char *parse_conv_expr(const char *, const char *, cpp_db_t *);
static const char *parse_function_param(const char *, const char *, cpp_db_t *);
static const char *parse_base_unresolved_name(const char *, const char *,
    cpp_db_t *);
static const char *parse_unresolved_name(const char *, const char *,
    cpp_db_t *);
static const char *parse_noexcept_expr(const char *, const char *, cpp_db_t *);
static const char *parse_alignof(const char *, const char *, cpp_db_t *);
static const char *parse_sizeof(const char *, const char *, cpp_db_t *);
static const char *parse_unnamed_type_name(const char *, const char *,
    cpp_db_t *);
static const char *parse_ctor_dtor_name(const char *, const char *, cpp_db_t *);
static const char *parse_source_name(const char *, const char *, cpp_db_t *);
static const char *parse_operator_name(const char *, const char *, cpp_db_t *);
static const char *parse_pack_expansion(const char *, const char *, cpp_db_t *);
static const char *parse_unresolved_type(const char *, const char *,
    cpp_db_t *);
static const char *parse_unresolved_qualifier_level(const char *, const char *,
    cpp_db_t *);
static const char *parse_destructor_name(const char *, const char *,
    cpp_db_t *);
static const char *parse_function_type(const char *, const char *, cpp_db_t *);
static const char *parse_array_type(const char *, const char *, cpp_db_t *);
static const char *parse_pointer_to_member_type(const char *, const char *,
    cpp_db_t *);
static const char *parse_vector_type(const char *, const char *, cpp_db_t *);

size_t cpp_name_max_depth = 1024;	/* max depth of name stack */

char *
cpp_demangle(const char *src, size_t srclen, sysdem_ops_t *ops)
{
	char *result = NULL;
	cpp_db_t db;

	if (!db_init(&db, ops))
		goto done;
	if (setjmp(db.cpp_jmp) != 0)
		goto done;

	errno = 0;
	demangle(src, src + srclen, &db);

	if (errno == 0 && db.cpp_fix_forward_references &&
	    !templ_empty(&db.cpp_templ) &&
	    !sub_empty(&db.cpp_templ.tpl_items[0])) {
		db.cpp_fix_forward_references = B_FALSE;
		db.cpp_tag_templates = B_FALSE;
		name_clear(&db.cpp_name);
		sub_clear(&db.cpp_subs);

		if (setjmp(db.cpp_jmp) != 0)
			goto done;

		demangle(src, src + srclen, &db);

		if (db.cpp_fix_forward_references) {
			errno = EINVAL;
			goto done;
		}
	}

	if (errno != 0)
		goto done;

	if (nempty(&db)) {
		errno = EINVAL;
		goto done;
	}

	njoin(&db, 1, "");

	if (nlen(&db) > 0) {
		str_t *s = TOP_L(&db);
		char *res = zalloc(ops, s->str_len + 1);
		if (res == NULL)
			goto done;

		(void) memcpy(res, s->str_s, s->str_len);
		result = res;
	}

done:
	if (demangle_debug)
		dump(&db, stdout);

	db_fini(&db);
	return (result);
}

static void
demangle(const char *first, const char *last, cpp_db_t *db)
{
	const char *t = NULL;

	if (first >= last) {
		errno = EINVAL;
		return;
	}

	if (first[0] != '_') {
		t = parse_type(first, last, db);
		if (t == first) {
			errno = EINVAL;
			return;
		}
		goto done;
	}

	if (last - first < 4) {
		errno = EINVAL;
		return;
	}

	if (first[1] == 'Z') {
		t = parse_encoding(first + 2, last, db);

		if (t != first + 2 && t != last && t[0] == '.') {
			t = parse_dot_suffix(t, last, db);
			if (nlen(db) > 1)
				njoin(db, 2, "");
		}

		goto done;
	}

	if (first[1] != '_' || first[2] != '_' || first[3] != 'Z')
		goto done;

	t = parse_encoding(first + 4, last, db);
	if (t != first + 4 && t != last)
		t = parse_block_invoke(t, last, db);

done:
	if (t != last)
		errno = EINVAL;
}

static const char *
parse_dot_suffix(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (first == last || first[0] != '.')
		return (first);

	if (nempty(db))
		return (first);

	nadd_l(db, first, RLEN(first, last));
	nfmt(db, " ({0})", NULL);

	return (last);
}

/*
 * _block_invoke
 * _block_invoke<digit>*
 * _block_invoke_<digit>+
 */
static const char *
parse_block_invoke(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 13)
		return (first);

	const char test[] = "_block_invoke";
	const char *t = first;

	if (strncmp(first, test, sizeof (test) - 1) != 0)
		return (first);

	t += sizeof (test);
	if (t == last)
		goto done;

	if (t[0] == '_') {
		/* need at least one digit */
		if (t + 1 == last || !isdigit_l(t[1], db->cpp_loc))
			return (first);
		t += 2;
	}

	while (t < last && isdigit_l(t[0], db->cpp_loc))
		t++;

done:
	if (nempty(db))
		return (first);

	nfmt(db, "invocation function for block in {0}", NULL);
	return (t);
}

/*
 * <encoding> ::= <function name><bare-function-type>
 *            ::= <data name>
 *            ::= <special name>
 */
static const char *
parse_encoding(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (first == last)
		return (first);

	const char *t = NULL;
	const char *t2 = NULL;
	unsigned cv = 0;
	unsigned ref = 0;
	boolean_t tag_templ_save = db->cpp_tag_templates;

	if (++db->cpp_depth > 1)
		db->cpp_tag_templates = B_TRUE;

	if (first[0] == 'G' || first[0] == 'T') {
		t = parse_special_name(first, last, db);
		goto done;
	}

	boolean_t ends_with_template_args = B_FALSE;
	t = parse_name(first, last, &ends_with_template_args, db);
	if (t == first)
		goto fail;

	cv = db->cpp_cv;
	ref = db->cpp_ref;

	if (t == last || t[0] == 'E' || t[0] == '.')
		goto done;

	db->cpp_tag_templates = B_FALSE;
	if (nempty(db) || str_length(TOP_L(db)) == 0)
		goto fail;

	if (!db->cpp_parsed_ctor_dtor_cv && ends_with_template_args) {
		t2 = parse_type(t, last, db);
		if (t2 == t || nlen(db) < 2)
			goto fail;

		str_pair_t *sp = name_top(&db->cpp_name);

		if (str_length(&sp->strp_r) == 0)
			(void) str_append(&sp->strp_l, " ", 1);

		nfmt(db, "{0:L}{1:L}", "{1:R}{0:R}");
		t = t2;
	}

	if (t == last || nempty(db))
		goto fail;

	size_t n = nlen(db);

	if (t[0] == 'v') {
		t++;
	} else {
		for (;;) {
			t2 = parse_type(t, last, db);
			if (t2 == t || t == last)
				break;

			t = t2;
		}
	}

	/*
	 * a bit of a hack, but a template substitution can apparently be
	 * an empty string at the end of an argument list, so avoid
	 * <...., >
	 */
	if (NAMT(db, n) > 1 && str_pair_len(name_top(&db->cpp_name)) == 0)
		name_pop(&db->cpp_name, NULL);

	njoin(db, NAMT(db, n), ", ");
	nfmt(db, "({0})", NULL);

	str_t *s = TOP_L(db);

	if (cv & CPP_QUAL_CONST) {
		CK(str_append(s, " const", 0));
	}
	if (cv & CPP_QUAL_VOLATILE) {
		CK(str_append(s, " volatile", 0));
	}
	if (cv & CPP_QUAL_RESTRICT) {
		CK(str_append(s, " restrict", 0));
	}
	if (ref == 1) {
		CK(str_append(s, " &", 0));
	}
	if (ref == 2) {
		CK(str_append(s, " &&", 0));
	}

	nfmt(db, "{1:L}{0}{1:R}", NULL);

done:
	db->cpp_tag_templates = tag_templ_save;
	db->cpp_depth--;
	return (t);

fail:
	db->cpp_tag_templates = tag_templ_save;
	db->cpp_depth--;
	return (first);
}

/*
 * <special-name> ::= TV <type>    # virtual table
 *                ::= TT <type>    # VTT structure (construction vtable index)
 *                ::= TI <type>    # typeinfo structure
 *                ::= TS <type>    # typeinfo name (null-terminated byte string)
 *                ::= Tc <call-offset> <call-offset> <base encoding>
 *                    # base is the nominal target function of thunk
 *                    # first call-offset is 'this' adjustment
 *                    # second call-offset is result adjustment
 *                ::= T <call-offset> <base encoding>
 *                    # base is the nominal target function of thunk
 *                ::= GV <object name> # Guard variable for one-time init
 *                                     # No <type>
 *                ::= TW <object name> # Thread-local wrapper
 *                ::= TH <object name> # Thread-local initialization
 *      extension ::= TC <first type> <number> _ <second type>
 *                                     # construction vtable for second-in-first
 *      extension ::= GR <object name> # reference temporary for object
 */
static const char *
parse_special_name(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	const char *t = first;
	const char *t1 = NULL;
	size_t n = nlen(db);

	if (last - first < 2)
		return (first);

	switch (t[0]) {
	case 'T':
		switch (t[1]) {
		case 'V':
			nadd_l(db, "vtable for", 0);
			t = parse_type(first + 2, last, db);
			break;
		case 'T':
			nadd_l(db, "VTT for", 0);
			t = parse_type(first + 2, last, db);
			break;
		case 'I':
			nadd_l(db, "typeinfo for", 0);
			t = parse_type(first + 2, last, db);
			break;
		case 'S':
			nadd_l(db, "typeinfo name for", 0);
			t = parse_type(first + 2, last, db);
			break;
		case 'c':
			nadd_l(db, "covariant return thunk to", 0);
			t1 = parse_call_offset(first + 2, last, db->cpp_loc);
			if (t1 == t)
				return (first);
			t = parse_call_offset(t1, last, db->cpp_loc);
			if (t == t1)
				return (first);
			t1 = parse_encoding(t, last, db);
			if (t1 == t)
				return (first);
			break;
		case 'C':
			t = parse_type(first + 2, last, db);
			if (t == first + 2)
				return (first);
			t1 = parse_number(t, last, db->cpp_loc);
			if (*t1 != '_')
				return (first);
			t = parse_type(t1 + 1, last, db);
			if (t == t1 + 1 || nlen(db) < 2)
				return (first);
			nfmt(db, "construction vtable for {0}-in-{1}", NULL);
			return (t);
		case 'W':
			nadd_l(db, "thread-local wrapper routine for", 0);
			t = parse_name(first + 2, last, NULL, db);
			break;
		case 'H':
			nadd_l(db, "thread-local initialization routine for",
			    0);
			t = parse_name(first + 2, last, NULL, db);
			break;
		default:
			if (first[1] == 'v') {
				nadd_l(db, "virtual thunk to", 0);
			} else {
				nadd_l(db, "non-virtual thunk to", 0);
			}

			t = parse_call_offset(first + 1, last, db->cpp_loc);
			if (t == first + 1)
				return (first);
			t1 = parse_encoding(t, last, db);
			if (t == t1)
				return (first);
			t = t1;
			break;
		}
		break;
	case 'G':
		switch (first[1]) {
		case 'V':
			nadd_l(db, "guard variable for", 0);
			t = parse_name(first + 2, last, NULL, db);
			break;
		case 'R':
			nadd_l(db, "reference temporary for", 0);
			t = parse_name(first + 2, last, NULL, db);
			break;
		default:
			return (first);
		}
		break;
	default:
		return (first);
	}

	size_t amt = NAMT(db, n);
	if (t == first + 2 || amt < 2)
		return (first);

	njoin(db, amt, " ");
	return (t);
}

/*
 * <call-offset> ::= h <nv-offset> _
 *               ::= v <v-offset> _
 *
 * <nv-offset> ::= <offset number>
 *               # non-virtual base override
 *
 * <v-offset>  ::= <offset number> _ <virtual offset number>
 *               # virtual base override, with vcall offset
 */
static const char *
parse_call_offset(const char *first, const char *last, locale_t loc)
{
	VERIFY3P(first, <=, last);

	const char *t = NULL;
	const char *t1 = NULL;

	if (first == last)
		return (first);

	if (first[0] != 'h' && first[0] != 'v')
		return (first);

	t = parse_number(first + 1, last, loc);
	if (t == first + 1 || t == last || t[0] != '_')
		return (first);

	/* skip _ */
	t++;

	if (first[0] == 'h')
		return (t);

	t1 = parse_number(t, last, loc);
	if (t == t1 || t1 == last || t1[0] != '_')
		return (first);

	/* skip _ */
	t1++;

	return (t1);
}

/*
 * <name> ::= <nested-name> // N
 *        ::= <local-name> # See Scope Encoding below  // Z
 *        ::= <unscoped-template-name> <template-args>
 *        ::= <unscoped-name>
 *
 * <unscoped-template-name> ::= <unscoped-name>
 *                          ::= <substitution>
 */
static const char *
parse_name(const char *first, const char *last,
    boolean_t *ends_with_template_args, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	const char *t = first;
	const char *t1 = NULL;

	if (last - first < 2)
		return (first);

	/* extension: ignore L here */
	if (t[0] == 'L')
		t++;

	switch (t[0]) {
	case 'N':
		t1 = parse_nested_name(t, last, ends_with_template_args, db);
		return ((t == t1) ? first : t1);
	case 'Z':
		t1 = parse_local_name(t, last, ends_with_template_args, db);
		return ((t == t1) ? first : t1);
	}

	/*
	 * <unscoped-name>
	 * <unscoped-name> <template-args>
	 * <substitution> <template-args>
	 */
	t1 = parse_unscoped_name(t, last, db);

	/* <unscoped-name> */
	if (t != t1 && t1[0] != 'I')
		return (t1);

	if (t == t1) {
		t1 = parse_substitution(t, last, db);
		if (t == t1 || t1 == last || t1[0] != 'I')
			return (first);
	} else {
		save_top(db, 1);
	}

	t = parse_template_args(t1, last, db);
	if (t1 == t || nlen(db) < 2)
		return (first);

	nfmt(db, "{1:L}{0}", "{1:R}");

	if (ends_with_template_args != NULL)
		*ends_with_template_args = B_TRUE;

	return (t);
}

/* BEGIN CSTYLED */
/*
 * <local-name> := Z <function encoding> E <entity name> [<discriminator>]
 *              := Z <function encoding> E s [<discriminator>]
 *              := Z <function encoding> Ed [ <parameter number> ] _ <entity name>
 */
/* END CSTYLED */
const char *
parse_local_name(const char *first, const char *last,
    boolean_t *ends_with_template_args, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	const char *t = NULL;
	const char *t1 = NULL;
	const char *t2 = NULL;

	if (first == last || first[0] != 'Z')
		return (first);

	t = parse_encoding(first + 1, last, db);
	if (t == first + 1 || t == last || t[0] != 'E')
		return (first);

	VERIFY(!nempty(db));

	/* skip E */
	t++;

	if (t[0] == 's') {
		nfmt(db, "{0:L}::string literal", "{0:R}");
		return (parse_discriminator(t, last, db->cpp_loc));
	}

	if (t[0] == 'd') {
		t1 = parse_number(t + 1, last, db->cpp_loc);
		if (t1[0] != '_')
			return (first);
		t1++;
	} else {
		t1 = t;
	}

	t2 = parse_name(t1, last, ends_with_template_args, db);
	if (t2 == t1)
		return (first);

	nfmt(db, "{1:L}::{0}", "{1:R}");

	/* parsed, but ignored */
	if (t[0] != 'd')
		t2 = parse_discriminator(t2, last, db->cpp_loc);

	return (t2);
}

/* BEGIN CSTYLED */
/*
 * <nested-name> ::= N [<CV-qualifiers>] [<ref-qualifier>] <prefix> <unqualified-name> E
 *               ::= N [<CV-qualifiers>] [<ref-qualifier>] <template-prefix> <template-args> E
 *
 * <prefix> ::= <prefix> <unqualified-name>
 *          ::= <template-prefix> <template-args>
 *          ::= <template-param>
 *          ::= <decltype>
 *          ::= # empty
 *          ::= <substitution>
 *          ::= <prefix> <data-member-prefix>
 *  extension ::= L
 *
 * <template-prefix> ::= <prefix> <template unqualified-name>
 *                   ::= <template-param>
 *                   ::= <substitution>
 */
/* END CSTYLED */
static const char *
parse_nested_name(const char *first, const char *last,
    boolean_t *ends_with_template_args, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (first == last || first[0] != 'N')
		return (first);

	unsigned cv = 0;
	const char *t = parse_cv_qualifiers(first + 1, last, &cv);

	if (t == last)
		return (first);

	boolean_t more = B_FALSE;

	switch (t[0]) {
	case 'R':
		db->cpp_ref = 1;
		t++;
		break;
	case 'O':
		db->cpp_ref = 2;
		t++;
		break;
	case 'S':
		if (last - first < 2 || t[1] != 't')
			break;
		if (last - first == 2)
			return (first);
		nadd_l(db, "std", 3);
		more = B_TRUE;
		t += 2;
		break;
	}

	boolean_t pop_subs = B_FALSE;
	boolean_t component_ends_with_template_args = B_FALSE;

	while (t[0] != 'E' && t != last) {
		const char *t1 = NULL;
		size_t n = nlen(db);
		component_ends_with_template_args = B_FALSE;

		switch (t[0]) {
		case 'S':
			if (t + 1 != last && t[1] == 't')
				break;

			t1 = parse_substitution(t, last, db);
			if (t1 == t || t1 == last || NAMT(db, n) != 1)
				return (first);

			if (!more) {
				nfmt(db, "{0}", NULL);
			} else {
				VERIFY3U(nlen(db), >, 1);
				nfmt(db, "{1:L}::{0}", "{1:R}");
				save_top(db, 1);
			}

			more = B_TRUE;
			pop_subs = B_TRUE;
			t = t1;
			continue;

		case 'T':
			t1 = parse_template_param(t, last, db);
			if (t1 == t || t1 == last || NAMT(db, n) != 1)
				return (first);

			if (!more) {
				nfmt(db, "{0}", NULL);
			} else {
				VERIFY3U(nlen(db), >, 1);
				nfmt(db, "{1:L}::{0}", "{1:R}");
			}

			save_top(db, 1);
			more = B_TRUE;
			pop_subs = B_TRUE;
			t = t1;
			continue;

		case 'D':
			if (t + 1 != last && t[1] != 't' && t[1] != 'T')
				break;
			t1 = parse_decltype(t, last, db);
			if (t1 == t || t1 == last || NAMT(db, n) != 1)
				return (first);

			if (!more) {
				nfmt(db, "{0}", NULL);
			} else {
				VERIFY3U(nlen(db), >, 1);
				nfmt(db, "{1:L}::{0}", "{1:R}");
			}

			save_top(db, 1);
			more = B_TRUE;
			pop_subs = B_TRUE;
			t = t1;
			continue;

		case 'I':
			/*
			 * Must have at least one component before
			 * <template-args>
			 */
			if (!more)
				return (first);

			t1 = parse_template_args(t, last, db);
			if (t1 == t || t1 == last)
				return (first);

			VERIFY3U(nlen(db), >, 1);
			nfmt(db, "{1:L}{0}", "{1:R}");
			save_top(db, 1);
			t = t1;
			component_ends_with_template_args = B_TRUE;
			continue;

		case 'L':
			if (t + 1 == last)
				return (first);
			t++;
			continue;

		default:
			break;
		}

		t1 = parse_unqualified_name(t, last, db);
		if (t1 == t || t1 == last || NAMT(db, n) != 1)
			return (first);

		if (!more) {
			nfmt(db, "{0}", NULL);
		} else {
			VERIFY3U(nlen(db), >, 1);
			nfmt(db, "{1:L}::{0}", "{1:R}");
		}

		save_top(db, 1);
		more = B_TRUE;
		pop_subs = B_TRUE;
		t = t1;
	}

	/* need to parse at least one thing */
	if (!more)
		return (first);

	db->cpp_cv = cv;
	if (pop_subs && !sub_empty(&db->cpp_subs))
		sub_pop(&db->cpp_subs);

	if (ends_with_template_args != NULL)
		*ends_with_template_args = component_ends_with_template_args;

	if (t[0] != 'E')
		return (first);

	return (t + 1);
}

/*
 * <template-arg> ::= <type>                   # type or template
 *                ::= X <expression> E         # expression
 *                ::= <expr-primary>           # simple expressions
 *                ::= J <template-arg>* E      # argument pack
 *                ::= LZ <encoding> E          # extension
 */
static const char *
parse_template_arg(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	const char *t = NULL;
	const char *t1 = NULL;

	if (first == last)
		return (first);

	switch (first[0]) {
	case 'X':
		t = parse_expression(first + 1, last, db);
		if (t == first + 1 || t[0] != 'E')
			return (first);

		/* E */
		t++;
		break;

	case 'J':
		t = first + 1;
		if (t == last)
			return (first);

		while (t[0] != 'E') {
			t1 = parse_template_arg(t, last, db);
			if (t == t1)
				return (first);
			t = t1;
		}

		/* E */
		t++;
		break;

	case 'L':
		if (first + 1 == last || first[1] != 'Z') {
			t = parse_expr_primary(first, last, db);
		} else {
			t = parse_encoding(first + 2, last, db);
			if (t == first + 2 || t == last || t[0] != 'E')
				return (first);

			/* E */
			t++;
		}
		break;

	default:
		t = parse_type(first, last, db);
	}

	return (t);
}

/* BEGIN CSTYLED */
/*
 * <expression> ::= <unary operator-name> <expression>
 *              ::= <binary operator-name> <expression> <expression>
 *              ::= <ternary operator-name> <expression> <expression> <expression>
 *              ::= cl <expression>+ E                                   # call
 *              ::= cv <type> <expression>                               # conversion with one argument
 *              ::= cv <type> _ <expression>* E                          # conversion with a different number of arguments
 *              ::= [gs] nw <expression>* _ <type> E                     # new (expr-list) type
 *              ::= [gs] nw <expression>* _ <type> <initializer>         # new (expr-list) type (init)
 *              ::= [gs] na <expression>* _ <type> E                     # new[] (expr-list) type
 *              ::= [gs] na <expression>* _ <type> <initializer>         # new[] (expr-list) type (init)
 *              ::= [gs] dl <expression>                                 # delete expression
 *              ::= [gs] da <expression>                                 # delete[] expression
 *              ::= pp_ <expression>                                     # prefix ++
 *              ::= mm_ <expression>                                     # prefix --
 *              ::= ti <type>                                            # typeid (type)
 *              ::= te <expression>                                      # typeid (expression)
 *              ::= dc <type> <expression>                               # dynamic_cast<type> (expression)
 *              ::= sc <type> <expression>                               # static_cast<type> (expression)
 *              ::= cc <type> <expression>                               # const_cast<type> (expression)
 *              ::= rc <type> <expression>                               # reinterpret_cast<type> (expression)
 *              ::= st <type>                                            # sizeof (a type)
 *              ::= sz <expression>                                      # sizeof (an expression)
 *              ::= at <type>                                            # alignof (a type)
 *              ::= az <expression>                                      # alignof (an expression)
 *              ::= nx <expression>                                      # noexcept (expression)
 *              ::= <template-param>
 *              ::= <function-param>
 *              ::= dt <expression> <unresolved-name>                    # expr.name
 *              ::= pt <expression> <unresolved-name>                    # expr->name
 *              ::= ds <expression> <expression>                         # expr.*expr
 *              ::= sZ <template-param>                                  # size of a parameter pack
 *              ::= sZ <function-param>                                  # size of a function parameter pack
 *              ::= sp <expression>                                      # pack expansion
 *              ::= tw <expression>                                      # throw expression
 *              ::= tr                                                   # throw with no operand (rethrow)
 *              ::= <unresolved-name>                                    # f(p), N::f(p), ::f(p),
 *                                                                       # freestanding dependent name (e.g., T::x),
 *                                                                       # objectless nonstatic member reference
 *              ::= <expr-primary>
 */
/* END CSTYLED */

#define	PA(cd, arg, fn) {	\
	.code = cd,		\
	.p.parse_expr_arg = fn,	\
	.fntype = EXPR_ARG,	\
	.val = arg		\
}

#define	PN(cd, fn) {			\
	.code = cd,			\
	.p.parse_expr_noarg = fn,	\
	.fntype = EXPR_NOARG		\
}

static struct {
	const char code[3];
	union {
		const char *(*parse_expr_arg)(const char *, const char *,
		    const char *, cpp_db_t *);
		const char *(*parse_expr_noarg)(const char *, const char *,
		    cpp_db_t *);
	} p;
	enum {
		EXPR_ARG,
		EXPR_NOARG
	} fntype;
	const char val[4];
} expr_tbl[] = {
	PA("aN", "&=", parse_binary_expr),
	PA("aS", "=", parse_binary_expr),
	PA("aa", "&&", parse_binary_expr),
	PA("ad", "&", parse_prefix_expr),
	PA("an", "&", parse_binary_expr),
	PN("at", parse_alignof),
	PN("az", parse_alignof),
	PN("cc", parse_cast_expr),
	PN("cl", parse_call_expr),
	PA("cm", ",", parse_binary_expr),
	PA("co", "~", parse_prefix_expr),
	PN("cv", parse_conv_expr),
	PN("da", parse_del_expr),
	PA("dV", "/=", parse_binary_expr),
	PN("dc", parse_cast_expr),
	PA("de", "*", parse_prefix_expr),
	PN("dl", parse_del_expr),
	PN("dn", parse_unresolved_name),
	PN("ds", parse_dot_star_expr),
	PN("dt", parse_dot_expr),
	PA("dv", "/", parse_binary_expr),
	PA("eO", "^=", parse_binary_expr),
	PA("eo", "^", parse_binary_expr),
	PA("eq", "==", parse_binary_expr),
	PA("ge", ">=", parse_binary_expr),
	PN("gs", parse_gs),
	PA("gt", ">", parse_binary_expr),
	PN("ix", parse_idx_expr),
	PA("lS", "<<=", parse_binary_expr),
	PA("le", "<=", parse_binary_expr),
	PA("ls", "<<", parse_binary_expr),
	PA("lt", "<", parse_binary_expr),
	PA("mI", "-=", parse_binary_expr),
	PA("mL", "*=", parse_binary_expr),
	PN("mm", parse_mm_expr),
	PA("mi", "-", parse_binary_expr),
	PA("ml", "*", parse_binary_expr),
	PN("na", parse_new_expr),
	PA("ne", "!=", parse_binary_expr),
	PA("ng", "-", parse_prefix_expr),
	PA("nt", "!", parse_prefix_expr),
	PN("nw", parse_new_expr),
	PN("nx", parse_noexcept_expr),
	PA("oR", "|=", parse_binary_expr),
	PN("on", parse_unresolved_name),
	PA("oo", "||", parse_binary_expr),
	PA("or", "|", parse_binary_expr),
	PA("pL", "+=", parse_binary_expr),
	PA("pl", "+", parse_binary_expr),
	PA("pm", "->*", parse_binary_expr),
	PN("pp", parse_pp_expr),
	PA("ps", "+", parse_prefix_expr),
	PN("pt", parse_arrow_expr),
	PN("qu", parse_trinary_expr),
	PA("rM", "%=", parse_binary_expr),
	PA("rS", ">>=", parse_binary_expr),
	PN("rc", parse_cast_expr),
	PA("rm", "%", parse_binary_expr),
	PA("rs", ">>", parse_binary_expr),
	PN("sc", parse_cast_expr),
	PN("sp", parse_pack_expansion),
	PN("sr", parse_unresolved_name),
	PN("st", parse_sizeof),
	PN("sz", parse_sizeof),
	PN("sZ", parse_sizeof_param_pack_expr),
	PN("te", parse_typeid_expr),
	PN("tr", parse_throw_expr),
	PN("tw", parse_throw_expr)
};
#undef PA
#undef PN

static const char *
parse_expression(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 2)
		return (first);

	for (size_t i = 0; i < ARRAY_SIZE(expr_tbl); i++) {
		if (strncmp(expr_tbl[i].code, first, 2) != 0)
			continue;
		switch (expr_tbl[i].fntype) {
		case EXPR_ARG:
			return (expr_tbl[i].p.parse_expr_arg(first, last,
			    expr_tbl[i].val, db));
		case EXPR_NOARG:
			return (expr_tbl[i].p.parse_expr_noarg(first, last,
			    db));
		}
	}

	switch (first[0]) {
	case 'L':
		return (parse_expr_primary(first, last, db));
	case 'T':
		return (parse_template_param(first, last, db));
	case 'f':
		return (parse_function_param(first, last, db));
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		return (parse_unresolved_name(first, last, db));
	}

	return (first);
}

static const char *
parse_binary_expr(const char *first, const char *last, const char *op,
    cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 2)
		return (first);

	size_t n = nlen(db);

	const char *t1 = parse_expression(first + 2, last, db);
	if (t1 == first + 2)
		return (first);

	nadd_l(db, op, 0);

	const char *t2 = parse_expression(t1, last, db);
	if (t2 == t1)
		return (first);

	if (NAMT(db, n) != 3)
		return (first);

	VERIFY3U(nlen(db), >, 2);

	nfmt(db, "({2}) {1} ({0})", NULL);
	if (strcmp(op, ">") == 0)
		nfmt(db, "({0})", NULL);

	return (t2);
}

static const char *
parse_prefix_expr(const char *first, const char *last, const char *op,
    cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 2)
		return (first);

	nadd_l(db, op, 0);

	const char *t = parse_expression(first + 2, last, db);
	if (t == first + 2) {
		return (first);
	}

	VERIFY3U(nlen(db), >, 1);

	nfmt(db, "{1}({0})", NULL);
	return (t);
}

static const char *
parse_gs(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	const char *t = NULL;

	if (last - first < 4)
		return (first);

	if (first[2] == 'n' && (first[3] == 'a' || first[3] == 'w'))
		t = parse_new_expr(first + 2, last, db);
	else if (first[2] == 'd' && (first[3] == 'l' || first[3] == 'a'))
		t = parse_del_expr(first + 2, last, db);
	else
		return (first);

	if (t == first + 2)
		return (first);

	VERIFY3U(nlen(db), >, 0);

	nfmt(db, "::{0}", NULL);
	return (t);
}

/*
 * [gs] nw <expression>* _ <type> E		# new (expr-list) type
 * [gs] nw <expression>* _ <type> <initializer>	# new (expr-list) type (init)
 * [gs] na <expression>* _ <type> E		# new[] (expr-list) type
 * [gs] na <expression>* _ <type> <initializer>	# new[] (expr-list) type (init)
 * <initializer> ::= pi <expression>* E		# parenthesized initialization
 */
static const char *
parse_new_expr(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	/* note [gs] is already handled by parse_gs() */
	if (last - first < 3)
		return (first);

	VERIFY3U(first[0], ==, 'n');
	VERIFY(first[1] == 'a' || first[1] == 'w');

	const char *t1 = first + 2;
	const char *t2 = NULL;
	size_t n = nlen(db);

	nadd_l(db, (first[1] == 'w') ? "new" : "new[]", 0);

	while (t1 != last && t1[0] != '_') {
		t2 = parse_expression(t1, last, db);
		VERIFY3P(t2, !=, NULL);
		if (t2 == t1)
			return (first);
		t1 = t2;
	}
	if (t1 == last)
		return (first);

	if (NAMT(db, n) > 1) {
		njoin(db, NAMT(db, n) - 1, ", ");
		nfmt(db, "({0})", NULL);
	}

	t2 = parse_type(t1 + 1, last, db);
	if (t1 + 1 == t2)
		return (first);

	if (t2[0] != 'E') {
		if (last - t2 < 3)
			return (first);
		if (t2[0] != 'p' && t2[1] != 'i')
			return (first);

		t2 += 2;
		const char *t3 = t2;
		size_t n1 = nlen(db);

		while (t2[0] != 'E' && t2 != last) {
			t3 = parse_expression(t2, last, db);

			if (t2 == t3)
				return (first);
			t2 = t3;
		}
		if (t3 == last || t3[0] != 'E')
			return (first);

		if (NAMT(db, n1) > 0) {
			njoin(db, NAMT(db, n1), ", ");
			nfmt(db, "({0})", NULL);
		}
	}

	njoin(db, NAMT(db, n), " ");
	return (t2 + 1);
}

static const char *
parse_del_expr(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 3)
		return (first);

	VERIFY3U(first[0], ==, 'd');
	VERIFY(first[1] == 'l' || first[1] == 'a');

	size_t n = nlen(db);
	const char *t = parse_expression(first + 2, last, db);
	if (t == first + 2 || NAMT(db, n) != 1)
		return (first);

	nfmt(db, (first[1] == 'a') ? "delete[] {0}" : "delete {0}", NULL);
	return (t);
}

static const char *
parse_idx_expr(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);
	VERIFY3U(first[0], ==, 'i');
	VERIFY3U(first[1], ==, 'x');

	size_t n = nlen(db);
	const char *t1 = parse_expression(first + 2, last, db);
	if (t1 == first + 2)
		return (first);

	const char *t2 = parse_expression(t1, last, db);
	if (t2 == t1 || NAMT(db, n) != 2)
		return (first);

	nfmt(db, "({0})[{1}]", NULL);
	return (t2);
}

static const char *
parse_ppmm_expr(const char *first, const char *last, const char *fmt,
    cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 3)
		return (first);

	const char *t = NULL;
	size_t n = nlen(db);

	if (first[2] == '_') {
		t = parse_binary_expr(first + 3, last, "--", db);
		if (t == first + 3)
			return (first);
		return (t);
	}

	t = parse_expression(first + 2, last, db);
	if (t == first + 2 || NAMT(db, n) < 1)
		return (first);

	nfmt(db, fmt, NULL);
	return (t);
}

static const char *
parse_mm_expr(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);
	VERIFY3U(first[0], ==, 'm');
	VERIFY3U(first[1], ==, 'm');

	return (parse_ppmm_expr(first, last, "({0})--", db));
}

static const char *
parse_pp_expr(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	VERIFY3U(first[0], ==, 'p');
	VERIFY3U(first[0], ==, 'p');

	return (parse_ppmm_expr(first, last, "({0})++", db));
}

static const char *
parse_trinary_expr(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	const char *t1, *t2, *t3;
	size_t n = nlen(db);

	if (last - first < 2)
		return (first);

	t1 = parse_expression(first + 2, last, db);
	if (t1 == first + 2)
		return (first);
	t2 = parse_expression(t1, last, db);
	if (t1 == t2)
		return (first);
	t3 = parse_expression(t2, last, db);
	if (t3 == t2)
		return (first);

	if (NAMT(db, n) != 3)
		return (first);

	nfmt(db, "({2}) ? ({1}) : ({0})", NULL);
	return (t3);
}

static const char *
parse_noexcept_expr(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 2)
		return (first);

	size_t n = nlen(db);
	const char *t = parse_expression(first + 2, last, db);
	if (t == first + 2 || NAMT(db, n) != 1)
		return (first);

	nfmt(db, "noexcept ({0})", NULL);
	return (t);
}

/*
 * cc <type> <expression>	# const_cast<type> (expression)
 * dc <type> <expression>	# dynamic_cast<type> (expression)
 * rc <type> <expression>	# reinterpret_cast<type> (expression)
 * sc <type> <expression>	# static_cast<type> (expression)
 */
static const char *
parse_cast_expr(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 2)
		return (first);

	const char *fmt = NULL;
	switch (first[0]) {
	case 'c':
		fmt = "const_cast<{1}> ({0})";
		break;
	case 'd':
		fmt = "dynamic_cast<{1}> ({0})";
		break;
	case 'r':
		fmt = "reinterpret_cast<{1}> ({0})";
		break;
	case 's':
		fmt = "static_cast<{1}> ({0})";
		break;
	default:
		return (first);
	}

	VERIFY3U(first[1], ==, 'c');

	const char *t1 = parse_type(first + 2, last, db);
	if (t1 == first + 2)
		return (first);

	const char *t2 = parse_expression(t1, last, db);
	if (t2 == t1)
		return (first);

	VERIFY3U(nlen(db), >, 1);

	nfmt(db, fmt, NULL);
	return (t2);
}

/* pt <expression> <expression>		# expr->name */
static const char *
parse_arrow_expr(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 4)
		return (first);

	size_t n = nlen(db);

	const char *t1 = parse_expression(first + 2, last, db);
	if (t1 == first + 2)
		return (first);

	const char *t2 = parse_expression(t1, last, db);
	if (t2 == t1 || NAMT(db, n) != 2)
		return (first);

	nfmt(db, "{1}->{0}", NULL);
	return (t2);
}

/* wrap value in () when necessary */
static void
paren(str_pair_t *sp)
{
	str_t *l = &sp->strp_l;
	str_t *r = &sp->strp_r;

	if (str_length(r) > 1 &&
	    r->str_s[0] == ' ' && r->str_s[1] == '[') {
		(void) str_append(l, " (", 2);
		(void) str_insert(r, 0, ")", 1);
	} else if (str_length(r) > 0 && r->str_s[0] == '(') {
		(void) str_append(l, "(", 1);
		(void) str_insert(r, 0, ")", 1);
	}
}

/* BEGIN CSTYLED */
/*
 * <type> ::= <builtin-type>
 *        ::= <function-type>
 *        ::= <class-enum-type>
 *        ::= <array-type>
 *        ::= <pointer-to-member-type>
 *        ::= <template-param>
 *        ::= <template-template-param> <template-args>
 *        ::= <decltype>
 *        ::= <substitution>
 *        ::= <CV-qualifiers> <type>
 *        ::= P <type>        # pointer-to
 *        ::= R <type>        # reference-to
 *        ::= O <type>        # rvalue reference-to (C++0x)
 *        ::= C <type>        # complex pair (C 2000)
 *        ::= G <type>        # imaginary (C 2000)
 *        ::= Dp <type>       # pack expansion (C++0x)
 *        ::= U <source-name> <type>  # vendor extended type qualifier
 * extension := U <objc-name> <objc-type>  # objc-type<identifier>
 * extension := <vector-type> # <vector-type> starts with Dv
 *
 * <objc-name> ::= <k0 number> objcproto <k1 number> <identifier>  # k0 = 9 + <number of digits in k1> + k1
 * <objc-type> := <source-name>  # PU<11+>objcproto 11objc_object<source-name> 11objc_object -> id<source-name>
 */
/* END CSTYLED */
static const char *
parse_type(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (first == last)
		return (first);

	switch (first[0]) {
	case 'r':
	case 'V':
	case 'K':
		return (parse_qual_type(first, last, db));
	}

	const char *t = first;
	const char *t1 = NULL;
	str_pair_t *sp = NULL;
	size_t n = nlen(db);
	size_t amt = 0;

	t = parse_builtin_type(first, last, db);
	if (t != first)
		return (t);

	switch (first[0]) {
	case 'A':
		t = parse_array_type(first, last, db);
		if (t == first || NAMT(db, n) == 0)
			return (first);
		save_top(db, 1);
		return (t);

	case 'C':
		t = parse_type(first + 1, last, db);
		if (t == first + 1 || NAMT(db, n) == 0)
			return (first);

		(void) str_append(TOP_L(db), " complex", 8);
		save_top(db, 1);
		return (t);

	case 'F':
		t = parse_function_type(first, last, db);
		if (t == first || NAMT(db, n) == 0)
			return (first);
		save_top(db, 1);
		return (t);

	case 'G':
		t = parse_type(first + 1, last, db);
		if (t == first + 1 || NAMT(db, n) == 0)
			return (first);

		(void) str_append(TOP_L(db), " imaginary", 10);
		save_top(db, 1);
		return (t);

	case 'M':
		t = parse_pointer_to_member_type(first, last, db);
		if (t == first || NAMT(db, n) == 0)
			return (first);
		save_top(db, 1);
		return (t);

	case 'O':
		t = parse_type(first + 1, last, db);
		amt = NAMT(db, n);
		if (t == first + 1 || amt == 0)
			return (first);

		sp = name_at(&db->cpp_name, amt - 1);
		for (size_t i = 0; i < amt; i++, sp++) {
			paren(sp);
			if (str_pair_len(sp) > 0)
				(void) str_append(&sp->strp_l, "&&", 2);
		}

		save_top(db, amt);
		return (t);

	case 'P':
		t = parse_type(first + 1, last, db);
		amt = NAMT(db, n);
		if (t == first + 1 || amt == 0)
			return (first);

		sp = name_at(&db->cpp_name, amt - 1);
		for (size_t i = 0; i < amt; i++, sp++) {
			str_t *l = &sp->strp_l;

			if (str_pair_len(sp) == 0)
				continue;

			paren(sp);
			if (first[1] != 'U' ||
			    strncmp(l->str_s, "objc_object<", 12) != 0) {
				(void) str_append(l, "*", 1);
			} else {
				(void) str_erase(l, 0, 11);
				(void) str_insert(l, 0, "id", 2);
			}
		}
		save_top(db, amt);
		return (t);

	case 'R':
		t = parse_type(first + 1, last, db);
		amt = NAMT(db, n);
		if (t == first + 1 || amt == 0)
			return (first);

		sp = name_at(&db->cpp_name, amt - 1);
		for (size_t i = 0; i < amt; i++, sp++) {
			if (str_length(&sp->strp_l) == 0 &&
			    str_length(&sp->strp_r) == 0)
				continue;

			paren(sp);
			(void) str_append(&sp->strp_l, "&", 1);
		}

		save_top(db, amt);
		return (t);

	case 'T':
		t = parse_template_param(first, last, db);
		if (t == first)
			return (first);

		amt = NAMT(db, n);
		save_top(db, amt);
		if (!db->cpp_try_to_parse_template_args || amt != 1)
			return (t);

		t1 = parse_template_args(t, last, db);
		if (t1 == t)
			return (t);

		nfmt(db, "{1:L}{0}", "{1:R}");
		save_top(db, 1);
		return (t1);

	case 'U':
		if (first + 1 == last)
			return (first);

		t = parse_source_name(first + 1, last, db);
		if (t == first + 1)
			return (first);

		nfmt(db, "{0}", NULL);

		t1 = parse_type(t, last, db);
		if (t1 == t || NAMT(db, n) < 2)
			return (first);

		const str_t *name = &name_at(&db->cpp_name, 1)->strp_l;

		if (str_length(name) > 0 &&
		    strncmp(name->str_s, "objcproto", 9) != 0) {
			nfmt(db, "{0} {1}", NULL);
		} else {
			t = parse_source_name(name->str_s + 9,
			    name->str_s + name->str_len, db);
			if (t != name->str_s + 9) {
				nfmt(db, "{1}<{0}>", NULL);

				str_pair_t save = {0};

				name_pop(&db->cpp_name, &save);

				/* get rid of 'objcproto' */
				name_pop(&db->cpp_name, NULL);
				CK(name_add_str(&db->cpp_name, &save.strp_l,
				    &save.strp_r));
			} else {
				nfmt(db, "{1} {0}", NULL);
			}
		}

		save_top(db, 1);
		return (t1);

	case 'S':
		if (first + 1 != last && first[1] == 't') {
			t = parse_name(first, last, NULL, db);
			if (t == first || NAMT(db, n) == 0)
				return (first);

			save_top(db, 1);
			return (t);
		}

		t = parse_substitution(first, last, db);
		if (t == first)
			return (first);

		/*
		 * If the substitution is a <template-param>, it might
		 * be followed by <template-args>
		 */
		t1 = parse_template_args(t, last, db);
		if (t1 == t)
			return (t);

		if (NAMT(db, n) < 2)
			return (t);

		nfmt(db, "{1:L}{0}", "{1:R}");
		save_top(db, 1);
		return (t1);

	case 'D':
		if (first + 1 == last)
			return (first);

		switch (first[1]) {
		case 'p':
			t = parse_type(first + 2, last, db);
			if (t == first + 2)
				break;

			save_top(db, NAMT(db, n));
			return (t);

		case 't':
		case 'T':
			t = parse_decltype(first, last, db);
			if (first == t)
				break;

			save_top(db, 1);
			return (t);

		case 'v':
			t = parse_vector_type(first, last, db);
			if (first == t)
				break;

			if (NAMT(db, n) == 0)
				return (first);

			save_top(db, 1);
			return (t);
		}
		break;
	}

	/*
	 * must check for builtin-types before class-enum-types to avoid
	 * ambiguities with operator-names
	 */
	t = parse_builtin_type(first, last, db);
	if (t != first)
		return (t);

	t = parse_name(first, last, NULL, db);
	if (t == first || NAMT(db, n) == 0)
		return (first);

	save_top(db, 1);
	return (t);
}

static const char *
parse_qual_type(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	const char *t = NULL;
	const char *t1 = NULL;
	unsigned cv = 0;

	t = parse_cv_qualifiers(first, last, &cv);
	if (t == first)
		return (first);

	size_t n = nlen(db);
	boolean_t is_func = !!(t[0] == 'F');

	t1 = parse_type(t, last, db);
	size_t amt = NAMT(db, n);
	if (t == t1 || amt == 0)
		return (first);

	if (is_func)
		sub_pop(&db->cpp_subs);

	str_pair_t *sp = name_at(&db->cpp_name, amt - 1);

	for (size_t i = 0; i < amt; i++, sp++) {
		str_t *s = NULL;

		if (!is_func) {
			s = &sp->strp_l;

			if (str_length(s) == 0)
				continue;

			if (cv & 1)
				(void) str_append(s, " const", 6);
			if (cv & 2)
				(void) str_append(s, " volatile", 9);
			if (cv & 4)
				(void) str_append(s, " restrict", 9);

			continue;
		}

		s = &sp->strp_r;
		size_t pos = str_length(s);

		if (pos > 0 && s->str_s[pos - 1] == '&') {
			pos--;
			if (s->str_s[pos - 1] == '&')
				pos--;
		}

		if (cv & 1) {
			(void) str_insert(s, pos, " const", 6);
			pos += 6;
		}
		if (cv & 2) {
			(void) str_insert(s, pos, " volatile", 9);
			pos += 9;
		}
		if (cv & 4) {
			(void) str_insert(s, pos, " restrict", 9);
		}
	}

	save_top(db, amt);
	return (t1);
}

/*
 * at <type>		# alignof (a type)
 * az <expression>	# alignof (a expression)
 */
static const char *
parse_alignof(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 2)
		return (first);

	const char *(*fn)(const char *, const char *, cpp_db_t *);

	fn = (first[1] == 't') ? parse_type : parse_expression;

	size_t n = nlen(db);
	const char *t = fn(first + 2, last, db);
	if (t == first + 2 || NAMT(db, n) != 1)
		return (first);

	nfmt(db, "alignof ({0})", NULL);
	return (t);
}

/*
 * st <type>	# sizeof (a type)
 * sz <expr>	# sizeof (a expression)
 */
static const char *
parse_sizeof(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 2)
		return (first);

	VERIFY3U(first[0], ==, 's');

	const char *t = NULL;
	size_t n = nlen(db);

	switch (first[1]) {
	case 't':
		t = parse_type(first + 2, last, db);
		break;
	case 'z':
		t = parse_expression(first + 2, last, db);
		break;
	default:
		return (first);
	}
	if (t == first + 2 || NAMT(db, n) != 1)
		return (first);

	nfmt(db, "sizeof ({0})", NULL);
	return (t);
}

/* BEGIN CSTYLED */
/*
 * <function-param> ::= fp <top-level CV-qualifiers> _                                     # L == 0, first parameter
 *                  ::= fp <top-level CV-qualifiers> <parameter-2 non-negative number> _   # L == 0, second and later parameters
 *                  ::= fL <L-1 non-negative number> p <top-level CV-qualifiers> _         # L > 0, first parameter
 *                  ::= fL <L-1 non-negative number> p <top-level CV-qualifiers> <parameter-2 non-negative number> _   # L > 0, second and later parameters
 */
/* END CSTYLED */
static const char *
parse_function_param(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 3 || first[0] != 'f')
		return (first);

	const char *t1 = first + 2;
	const char *t2 = NULL;
	unsigned cv = 0;

	if (first[1] == 'L') {
		t2 = parse_number(t1, last, db->cpp_loc);
		if (t2 == last || t2[0] != 'p')
			return (first);
		t1 = t2;
	}

	if (first[1] != 'p')
		return (first);

	t1 = parse_cv_qualifiers(t1, last, &cv);
	t2 = parse_number(t1, last, db->cpp_loc);
	if (t2 == last || t2[0] != '_')
		return (first);

	if (t2 - t1 > 0)
		nadd_l(db, t1, (size_t)(t2 - t1));
	else
		nadd_l(db, "", 0);

	nfmt(db, "fp{0}", NULL);
	return (t2 + 1);
}

/*
 * sZ <template-param>		# size of a parameter pack
 * sZ <function-param>		# size of a function parameter pack
 */
static const char *
parse_sizeof_param_pack_expr(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 3)
		return (first);

	VERIFY3U(first[0], ==, 's');
	VERIFY3U(first[1], ==, 'Z');

	if (first[2] != 'T' && first[2] != 'f')
		return (first);

	const char *t = NULL;
	size_t n = nlen(db);

	if (first[2] == 'T')
		t = parse_template_param(first + 2, last, db);
	else
		t = parse_function_param(first + 2, last, db);

	if (t == first + 2)
		return (first);

	njoin(db, NAMT(db, n), ", ");
	nfmt(db, "sizeof...({0})", NULL);
	return (t);
}

/*
 * te <expression>                                      # typeid (expression)
 * ti <type>                                            # typeid (type)
 */
static const char *
parse_typeid_expr(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 3)
		return (first);

	VERIFY3U(first[0], ==, 't');
	VERIFY(first[1] == 'e' || first[1] == 'i');

	const char *t = NULL;
	size_t n = nlen(db);

	if (first[1] == 'e')
		t = parse_expression(first + 2, last, db);
	else
		t = parse_type(first + 2, last, db);

	if (t == first + 2 || NAMT(db, n) != 1)
		return (first);

	nfmt(db, "typeid ({0})", NULL);
	return (t);
}

/*
 * tr							# throw
 * tw <expression>					# throw expression
 */
static const char *
parse_throw_expr(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 3)
		return (first);

	VERIFY3U(first[0], ==, 't');
	VERIFY(first[1] == 'w' || first[1] == 'r');

	if (first[1] == 'r') {
		nadd_l(db, "throw", 0);
		return (first + 2);
	}

	size_t n = nlen(db);
	const char *t = parse_expression(first + 2, last, db);
	if (t == first + 2 || NAMT(db, n) != 1)
		return (first);

	nfmt(db, "throw {0}", NULL);
	return (t);
}

/* ds <expression> <expression>		# expr.*expr */
static const char *
parse_dot_star_expr(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 3)
		return (first);

	VERIFY3U(first[0], ==, 'd');
	VERIFY3U(first[1], ==, 's');

	size_t n = nlen(db);
	const char *t = parse_expression(first + 2, last, db);
	if (t == first + 2)
		return (first);

	const char *t2 = parse_expression(t, last, db);
	if (t == t2 || NAMT(db, n) != 2)
		return (first);

	nfmt(db, "{1}.*{0}", NULL);
	return (t2);
}

/* dt <expression> <unresolved-name>		# expr.name */
static const char *
parse_dot_expr(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 3)
		return (first);

	VERIFY3U(first[0], ==, 'd');
	VERIFY3U(first[1], ==, 't');

	const char *t = parse_expression(first + 2, last, db);
	if (t == first + 2)
		return (first);

	const char *t1 = parse_unresolved_name(t, last, db);
	if (t1 == t)
		return (first);

	nfmt(db, "{1}.{0}", NULL);
	return (t1);
}

/* cl <expression>+ E		# call */
static const char *
parse_call_expr(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 4)
		return (first);

	VERIFY3U(first[0], ==, 'c');
	VERIFY3U(first[1], ==, 'l');

	const char *t = first + 2;
	const char *t1 = NULL;
	size_t n = nlen(db);

	for (t = first + 2; t != last && t[0] != 'E'; t = t1) {
		t1 = parse_expression(t, last, db);
		if (t1 == t)
			return (first);
	}

	size_t amt = NAMT(db, n);

	if (t == last || amt == 0)
		return (first);

	njoin(db, amt - 1, ", ");
	nfmt(db, "{1}({0})", NULL);

	VERIFY3U(t[0], ==, 'E');
	return (t + 1);
}

/* BEGIN CSTYLED */
/*
 * cv <type> <expression>	# conversion with one argument
 * cv <type> _ <expression>* E	# conversion with a different number of arguments
 */
/* END CSTYLED */
static const char *
parse_conv_expr(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 3)
		return (first);

	VERIFY3U(first[0], ==, 'c');
	VERIFY3U(first[1], ==, 'v');

	const char *t = NULL;
	const char *t1 = NULL;
	size_t n = nlen(db);

	boolean_t try_to_parse_template_args =
	    db->cpp_try_to_parse_template_args;

	db->cpp_try_to_parse_template_args = B_FALSE;
	t = parse_type(first + 2, last, db);
	db->cpp_try_to_parse_template_args = try_to_parse_template_args;

	if (t == first + 2)
		return (first);

	if (t[0] != '_') {
		t1 = parse_expression(t, last, db);
		if (t1 == t)
			return (first);

		t = t1;
	} else {
		size_t n1 = nlen(db);

		/* skip _ */
		t++;
		while (t[0] != 'E' && t != last) {
			t1 = parse_expression(t, last, db);
			if (t1 == t)
				return (first);
			t1 = t;
		}

		/* E */
		t++;

		njoin(db, NAMT(db, n1), ", ");
	}

	if (NAMT(db, n) < 2)
		return (first);

	nfmt(db, "({1})({0})", NULL);
	return (t);
}

/* <simple-id> ::= <source-name> [ <template-args> ] */
static const char *
parse_simple_id(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	const char *t = parse_source_name(first, last, db);
	if (t == first)
		return (t);

	const char *t1 = parse_template_args(t, last, db);
	if (t == t1)
		return (t);

	nfmt(db, "{1}{0}", NULL);
	return (t1);
}

/*
 * <unresolved-type> ::= <template-param>
 *                   ::= <decltype>
 *                   ::= <substitution>
 */
static const char *
parse_unresolved_type(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (first == last)
		return (first);

	const char *t = first;
	size_t n = nlen(db);

	switch (first[0]) {
	case 'T':
		t = parse_template_param(first, last, db);
		if (t == first || NAMT(db, n) != 1) {
			for (size_t i = 0; i < NAMT(db, n); i++)
				name_pop(&db->cpp_name, NULL);
			return (first);
		}
		save_top(db, 1);
		return (t);

	case 'D':
		t = parse_decltype(first, last, db);
		if (t == first || NAMT(db, n) == 0)
			return (first);
		save_top(db, 1);
		return (t);

	case 'S':
		t = parse_substitution(first, last, db);
		if (t != first)
			return (t);

		if (last - first < 2 || first[1] != 't')
			return (first);

		t = parse_unqualified_name(first + 2, last, db);
		if (t == first + 2 || NAMT(db, n) == 0)
			return (first);

		nfmt(db, "std::{0:L}", "{0:R}");
		save_top(db, 1);
		return (t);
	}

	return (first);
}

/* sp <expression>		# pack expansion */
static const char *
parse_pack_expansion(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 3)
		return (first);

	VERIFY3U(first[0], ==, 's');
	VERIFY3U(first[1], ==, 'p');

	const char *t = parse_expression(first + 2, last, db);
	if (t == first +2)
		return (first);

	return (t);
}

/*
 * <unscoped-name> ::= <unqualified-name>
 *                 ::= St <unqualified-name>   # ::std::
 * extension       ::= StL<unqualified-name>
 */
static const char *
parse_unscoped_name(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 2)
		return (first);

	const char *t = first;
	const char *t1 = NULL;
	boolean_t st = B_FALSE;

	if (first[0] == 'S' && first[1] == 't') {
		st = B_TRUE;
		t = first + 2;

		if (first + 3 != last && first[2] == 'L')
			t++;
	}

	t1 = parse_unqualified_name(t, last, db);
	if (t == t1)
		return (first);

	if (st)
		nfmt(db, "std::{0}", NULL);

	return (t1);
}

/*
 * <unqualified-name> ::= <operator-name>
 *                    ::= <ctor-dtor-name>
 *                    ::= <source-name>
 *                    ::= <unnamed-type-name>
 */
const char *
parse_unqualified_name(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (first == last)
		return (first);

	switch (*first) {
	case 'C':
	case 'D':
		return (parse_ctor_dtor_name(first, last, db));
	case 'U':
		return (parse_unnamed_type_name(first, last, db));

	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		return (parse_source_name(first, last, db));
	default:
		return (parse_operator_name(first, last, db));
	}
}

/*
 * <unnamed-type-name> ::= Ut [ <nonnegative number> ] _
 *                     ::= <closure-type-name>
 *
 * <closure-type-name> ::= Ul <lambda-sig> E [ <nonnegative number> ] _
 *
 * <lambda-sig> ::= <parameter type>+
 *			# Parameter types or "v" if the lambda has no parameters
 */
static const char *
parse_unnamed_type_name(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 2 || first[0] != 'U')
		return (first);

	if (first[1] != 't' && first[1] != 'l')
		return (first);

	const char *t1 = first + 2;
	const char *t2 = NULL;

	if (first[1] == 't') {
		while (t1 != last && t1[0] != '_' &&
		    isdigit_l(t1[0], db->cpp_loc))
			t1++;

		if (t1[0] != '_')
			return (first);

		if (t1 == first + 2)
			nadd_l(db, "", 0);
		else
			nadd_l(db, first + 2, (size_t)(t1 - first - 2));

		nfmt(db, "'unnamed{0}'", NULL);
		return (t1 + 1);
	}

	size_t n = nlen(db);

	if (first[2] != 'v') {
		do {
			t2 = parse_type(t1, last, db);
			if (t1 == t2)
				return (first);
			t1 = t2;
		} while (t1 != last && t1[0] != 'E');

		if (t1 == last || NAMT(db, n) < 1)
			return (first);

		if (NAMT(db, n) < 1)
			return (first);
	} else {
		t1++;
		if (t1[0] != 'E')
			return (first);
	}

	njoin(db, NAMT(db, n), ", ");

	/* E */
	t1++;

	t2 = t1;
	while (t2 != last && t2[0] != '_') {
		if (!isdigit_l(*t2++, db->cpp_loc))
			return (first);
	}

	if (t2[0] != '_')
		return (first);

	if (t2 - t1 > 0)
		nadd_l(db, t1, (size_t)(t2 - t1));
	else
		nadd_l(db, "", 0);

	nfmt(db, "'lambda{0}'({1})", NULL);

	/* _ */
	return (t2 + 1);
}

static struct {
	const char *alias;
	const char *fullname;
	const char *basename;
} aliases[] = {
	{
		"std::string",
		"std::basic_string<char, std::char_traits<char>, "
		    "std::allocator<char> >",
		"basic_string"
	},
	{
		"std::istream",
		"std::basic_istream<char, std::char_traits<char> >",
		"basic_istream"
	},
	{
		"std::ostream",
		"std::basic_ostream<char, std::char_traits<char> >",
		"basic_ostream"
	},
	{
		"std::iostream",
		"std::basic_iostream<char, std::char_traits<char> >",
		"basic_iostream"
	}
};

static void
basename(cpp_db_t *db)
{
	str_t *s = TOP_L(db);

	for (size_t i = 0; i < ARRAY_SIZE(aliases); i++) {
		if (str_length(s) != strlen(aliases[i].alias))
			continue;
		if (strncmp(aliases[i].alias, s->str_s, str_length(s)) != 0)
			continue;

		/* swap out alias for full name */
		sysdem_ops_t *ops = s->str_ops;
		str_fini(s);
		str_init(s, ops);
		str_set(s, aliases[i].fullname, 0);

		nadd_l(db, aliases[i].basename, 0);
		return;
	}

	const char *start = s->str_s;
	const char *end = s->str_s + s->str_len;

	/*
	 * if name ends with a template i.e. <.....> back up to start
	 * of outermost template
	 */
	unsigned c = 0;

	if (end[-1] == '>') {
		for (; end > start; end--) {
			switch (end[-1]) {
			case '<':
				if (--c == 0) {
					end--;
					goto out;
				}
				break;
			case '>':
				c++;
				break;
			}
		}
	}

out:
	VERIFY3P(end, >=, start);

	if (end - start < 2) {
		nadd_l(db, "", 0);
		return;
	}

	for (start = end - 1; start > s->str_s; start--) {
		if (start[0] == ':') {
			start++;
			break;
		}
	}

	VERIFY3P(end, >=, start);

	nadd_l(db, start, (size_t)(end - start));
}

/*
 * <ctor-dtor-name> ::= C1    # complete object constructor
 *                  ::= C2    # base object constructor
 *                  ::= C3    # complete object allocating constructor
 *   extension      ::= C5    # ?
 *                  ::= D0    # deleting destructor
 *                  ::= D1    # complete object destructor
 *                  ::= D2    # base object destructor
 *   extension      ::= D5    # ?
 */
static const char *
parse_ctor_dtor_name(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 2 || nempty(db) || str_length(TOP_L(db)) == 0)
		return (first);

	switch (first[0]) {
	case 'C':
		switch (first[1]) {
		case '1':
		case '2':
		case '3':
		case '5':
			basename(db);
			break;
		default:
			return (first);
		}
		break;
	case 'D':
		switch (first[1]) {
		case '0':
		case '1':
		case '2':
		case '5':
			basename(db);
			(void) str_insert(TOP_L(db), 0, "~", 1);
			break;
		default:
			return (first);
		}
		break;
	default:
		return (first);
	}

	db->cpp_parsed_ctor_dtor_cv = B_TRUE;
	return (first + 2);
}

static const char *
parse_integer_literal(const char *first, const char *last, const char *fmt,
    cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	const char *t = parse_number(first, last, db->cpp_loc);
	const char *start = first;

	if (t == first || t == last || t[0] != 'E')
		return (first);

	if (first[0] == 'n')
		start++;

	nadd_l(db, start, (size_t)(t - start));
	if (start != first)
		nfmt(db, "-{0}", NULL);

	nfmt(db, fmt, NULL);
	return (t + 1);
}

static struct float_data_s {
	const char *spec;
	size_t mangled_size;
	size_t max_demangled_size;
	char type;
} float_info[] = {
	{ "%af", 8, 24, 'f' },		/* float */
	{ "%a", 16, 32, 'd' },		/* double */
	{ "%LaL", 20, 40, 'e' }		/* long double */
};

static const char *
parse_floating_literal(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);
	VERIFY(first[0] == 'f' || first[0] == 'd' || first[0] == 'e');

	const struct float_data_s *fd = NULL;

	for (size_t i = 0; i < ARRAY_SIZE(float_info); i++) {
		if (float_info[i].type != first[0])
			continue;

		fd = &float_info[i];
		break;
	}

	if (fd == NULL || (size_t)(last - first) < fd->mangled_size)
		return (first);

	union {
		union {
			float v;
			char buf[sizeof (float)];
		} f;
		union {
			double v;
			char buf[sizeof (double)];
		} d;
		union {
			long double v;
			char buf[sizeof (long double)];
		} ld;
	} conv;

	const char *t = NULL;
	char *e = NULL;

	switch (first[0]) {
	case 'f':
		e = conv.f.buf;
		break;
	case 'd':
		e = conv.d.buf;
		break;
	case 'e':
		e = conv.ld.buf;
		break;
	}
	last = first + fd->mangled_size + 1;

#if defined(_BIG_ENDIAN)
	for (t = first + 1; t != last; t++, e++) {
		if (!is_xdigit(t[0]))
			return (first);

		unsigned d1 = isdigit_l(t[0], db->cpp_loc) ?
		    t[0] - '0' : t[0] - 'a' + 10;
		t++;
		unsigned d0 = isdigit_l(t[0], db->cpp_loc) ?
		    t[0] - '0' : t[0] - 'a' + 10;

		*e = (d1 << 4) + d0;
	}
#elif defined(_LITTLE_ENDIAN)
	for (t = last - 1; t > first; t--, e++) {
		if (!is_xdigit(t[0]))
			return (first);

		unsigned d0 = isdigit_l(t[0], db->cpp_loc) ?
		    t[0] - '0' : t[0] - 'a' + 10;
		t--;
		unsigned d1 = isdigit_l(t[0], db->cpp_loc) ?
		    t[0] - '0' : t[0] - 'a' + 10;

		*e = (d1 << 4) + d0;
	}
	t = last;
#else
#error One of _BIG_ENDIAN or _LITTLE_ENDIAN must be defined
#endif

	if (t[0] != 'E')
		return (first);

	str_t num = { 0 };
	str_init(&num, db->cpp_ops);

	num.str_size = fd->max_demangled_size + 1;
	num.str_s = zalloc(db->cpp_ops, num.str_size);
	CK(num.str_s != NULL);

	int n = 0;

	switch (first[0]) {
	case 'f':
		n = snprintf(num.str_s, fd->max_demangled_size, fd->spec,
		    conv.f.v);
		break;
	case 'd':
		n = snprintf(num.str_s, fd->max_demangled_size, fd->spec,
		    conv.d.v);
		break;
	case 'e':
		n = snprintf(num.str_s, fd->max_demangled_size, fd->spec,
		    conv.ld.v);
	}

	if (n >= fd->max_demangled_size || n <= 0) {
		str_fini(&num);
		return (first);
	}

	num.str_len = n;
	(void) name_add_str(&db->cpp_name, &num, NULL);

	return (t + 1);
}

/*
 * <expr-primary> ::= L <type> <value number> E	# integer literal
 *                ::= L <type> <value float> E	# floating literal
 *                ::= L <string type> E		# string literal
 *                ::= L <nullptr type> E	# nullptr literal (i.e., "LDnE")
 *
 *                ::= L <type> <real-part float> _ <imag-part float> E
 *						# complex floating point
 *						# literal (C 2000)
 *
 *                ::= L <mangled-name> E	# external name
 */
static struct {
	int		c;
	const char	*fmt;
} int_lits[] = {
	{ 'a', "(signed char){0}" },
	{ 'c', "(char){0}" },
	{ 'h', "(unsigned char){0}" },
	{ 'i', "{0}" },
	{ 'j', "{0}u" },
	{ 'l', "{0}l" },
	{ 'm', "{0}ul" },
	{ 'n', "(__int128){0}" },
	{ 'o', "(unsigned __int128){0}" },
	{ 's', "(short){0}" },
	{ 't', "(unsigned short){0}" },
	{ 'w', "(wchar_t){0}" },
	{ 'x', "{0}ll" },
	{ 'y', "{0}ull" }
};

static const char *
parse_expr_primary(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 4 || first[0] != 'L')
		return (first);

	const char *t = NULL;

	for (size_t i = 0; i < ARRAY_SIZE(int_lits); i++) {
		if (first[1] == int_lits[i].c) {
			t = parse_integer_literal(first + 2, last,
			    int_lits[i].fmt, db);
			return ((t == first + 2) ? first : t);
		}
	}

	switch (first[1]) {
	case 'b':
		if (first[3] != 'E')
			return (first);

		switch (first[2]) {
		case '0':
			nadd_l(db, "false", 5);
			break;
		case '1':
			nadd_l(db, "true", 4);
			break;
		default:
			return (first);
		}
		return (first + 4);
	case 'd':	/* double */
	case 'e':	/* long double */
	case 'f':	/* float */
		t = parse_floating_literal(first + 1, last, db);
		return ((t == first + 1) ? first : t);
	case 'T':
/* BEGIN CSTYLED */
		/*
		 * Invalid mangled name per
		 *   http://sourcerytools.com/pipermail/cxx-abi-dev/2011-August/002422.html
		 *
		 */
/* END CSTYLED */
		return (first);
	case '_':
		if (first[2] != 'Z')
			return (first);

		t = parse_encoding(first + 3, last, db);
		if (t == first + 3 || t == last || t[0] != 'E')
			return (first);

		/* skip E */
		return (t + 1);
	default:
		t = parse_type(first + 1, last, db);
		if (t == first + 1 || t == last)
			return (first);

		if (t[0] == 'E')
			return (t + 1);

		const char *n;
		for (n = t; n != last && isdigit_l(n[0], db->cpp_loc); n++)
			;
		if (n == last || nempty(db) || n[0] != 'E')
			return (first);
		if (n == t)
			return (t);

		nadd_l(db, t, (size_t)(n - t));
		nfmt(db, "({1}){0}", NULL);

		return (n + 1);
	}
}

/*
 *   <operator-name>
 *                   ::= aa    # &&
 *                   ::= ad    # & (unary)
 *                   ::= an    # &
 *                   ::= aN    # &=
 *                   ::= aS    # =
 *                   ::= cl    # ()
 *                   ::= cm    # ,
 *                   ::= co    # ~
 *                   ::= cv <type>    # (cast)
 *                   ::= da    # delete[]
 *                   ::= de    # * (unary)
 *                   ::= dl    # delete
 *                   ::= dv    # /
 *                   ::= dV    # /=
 *                   ::= eo    # ^
 *                   ::= eO    # ^=
 *                   ::= eq    # ==
 *                   ::= ge    # >=
 *                   ::= gt    # >
 *                   ::= ix    # []
 *                   ::= le    # <=
 *                   ::= li <source-name>	# operator ""
 *                   ::= ls    # <<
 *                   ::= lS    # <<=
 *                   ::= lt    # <
 *                   ::= mi    # -
 *                   ::= mI    # -=
 *                   ::= ml    # *
 *                   ::= mL    # *=
 *                   ::= mm    # -- (postfix in <expression> context)
 *                   ::= na    # new[]
 *                   ::= ne    # !=
 *                   ::= ng    # - (unary)
 *                   ::= nt    # !
 *                   ::= nw    # new
 *                   ::= oo    # ||
 *                   ::= or    # |
 *                   ::= oR    # |=
 *                   ::= pm    # ->*
 *                   ::= pl    # +
 *                   ::= pL    # +=
 *                   ::= pp    # ++ (postfix in <expression> context)
 *                   ::= ps    # + (unary)
 *                   ::= pt    # ->
 *                   ::= qu    # ?
 *                   ::= rm    # %
 *                   ::= rM    # %=
 *                   ::= rs    # >>
 *                   ::= rS    # >>=
 *                   ::= v <digit> <source-name> # vendor extended operator
 */
static struct {
	const char code[3];
	const char *op;
} op_tbl[] = {
	{ "aa", "operator&&" },
	{ "ad", "operator&" },
	{ "an", "operator&" },
	{ "aN", "operator&=" },
	{ "aS", "operator=" },
	{ "cl", "operator()" },
	{ "cm", "operator," },
	{ "co", "operator~" },
	{ "da", "operator delete[]" },
	{ "de", "operator*" },
	{ "dl", "operator delete" },
	{ "dv", "operator/" },
	{ "dV", "operator/=" },
	{ "eo", "operator^" },
	{ "eO", "operator^=" },
	{ "eq", "operator==" },
	{ "ge", "operator>=" },
	{ "gt", "operator>" },
	{ "ix", "operator[]" },
	{ "le", "operator<=" },
	{ "ls", "operator<<" },
	{ "lS", "operator<<=" },
	{ "lt", "operator<" },
	{ "mi", "operator-" },
	{ "mI", "operator-=" },
	{ "ml", "operator*" },
	{ "mL", "operator*=" },
	{ "mm", "operator--" },
	{ "na", "operator new[]" },
	{ "ne", "operator!=" },
	{ "ng", "operator-" },
	{ "nt", "operator!" },
	{ "nw", "operator new" },
	{ "oo", "operator||" },
	{ "or", "operator|" },
	{ "oR", "operator|=" },
	{ "pm", "operator->*" },
	{ "pl", "operator+" },
	{ "pL", "operator+=" },
	{ "pp", "operator++" },
	{ "ps", "operator+" },
	{ "pt", "operator->" },
	{ "qu", "operator?" },
	{ "rm", "operator%" },
	{ "rM", "operator%=" },
	{ "rs", "operator>>" },
	{ "rS", "operator>>=" }
};

static const char *
parse_operator_name(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 2)
		return (first);

	for (size_t i = 0; i < ARRAY_SIZE(op_tbl); i++) {
		if (strncmp(first, op_tbl[i].code, 2) != 0)
			continue;

		nadd_l(db, op_tbl[i].op, 0);
		return (first + 2);
	}

	const char *t = NULL;

	if (first[0] == 'l' && first[1] == 'i') {
		t = parse_source_name(first + 2, last, db);
		if (t == first + 2 || nempty(db))
			return (first);

		nfmt(db, "operator\"\" {0}", NULL);
		return (t);
	}

	if (first[0] == 'v') {
		if (!isdigit_l(first[1], db->cpp_loc))
			return (first);

		t = parse_source_name(first + 2, last, db);
		if (t == first + 2)
			return (first);

		nfmt(db, "operator {0}", NULL);
		return (t);
	}

	if (first[0] != 'c' && first[1] != 'v')
		return (first);

	boolean_t try_to_parse_template_args =
	    db->cpp_try_to_parse_template_args;

	db->cpp_try_to_parse_template_args = B_FALSE;
	t = parse_type(first + 2, last, db);
	db->cpp_try_to_parse_template_args = try_to_parse_template_args;

	if (t == first + 2 || nempty(db))
		return (first);

	nfmt(db, "operator {0}", NULL);
	db->cpp_parsed_ctor_dtor_cv = B_TRUE;
	return (t);
}

struct type_tbl_s {
	int code;
	const char *name;
};

static struct type_tbl_s type_tbl1[] = {
	{ 'a', "signed char" },
	{ 'b', "bool" },
	{ 'c', "char" },
	{ 'd', "double" },
	{ 'e', "long double" },
	{ 'f', "float" },
	{ 'g', "__float128" },
	{ 'h', "unsigned char" },
	{ 'i', "int" },
	{ 'j', "unsigned int" },
	{ 'l', "long" },
	{ 'm', "unsigned long" },
	{ 'n', "__int128" },
	{ 'o', "unsigned __int128" },
	{ 's', "short" },
	{ 't', "unsigned short" },
	{ 'v', "void" },
	{ 'w', "wchar_t" },
	{ 'x', "long long" },
	{ 'y', "unsigned long long" },
	{ 'z', "..." }
};

static struct type_tbl_s type_tbl2[] = {
	{ 'a', "auto" },
	{ 'c', "decltype(auto)" },
	{ 'd', "decimal64" },
	{ 'e', "decimal128" },
	{ 'f', "decimal32" },
	{ 'h', "decimal16" },
	{ 'i', "char32_t" },
	{ 'n', "std::nullptr_t" },
	{ 's', "char16_t" }
};

static const char *
parse_builtin_type(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (first == last)
		return (first);

	size_t i;

	for (i = 0; i < ARRAY_SIZE(type_tbl1); i++) {
		if (first[0] == type_tbl1[i].code) {
			nadd_l(db, type_tbl1[i].name, 0);
			return (first + 1);
		}
	}

	if (first[0] == 'D') {
		if (first + 1 == last)
			return (first);
		for (i = 0; i < ARRAY_SIZE(type_tbl2); i++) {
			if (first[1] == type_tbl2[i].code) {
				nadd_l(db, type_tbl2[i].name, 0);
				return (first + 2);
			}
		}
	}

	if (first[0] == 'u') {
		const char *t = parse_source_name(first + 1, last, db);
		if (t == first + 1)
			return (first);
		return (t);
	}

	return (first);
}

static const char *
parse_base36(const char *first, const char *last, size_t *val, locale_t loc)
{
	VERIFY3P(first, <=, last);

	const char *t;

	for (t = first, *val = 0; t != last; t++) {
		if (!isdigit_l(t[0], loc) && !isupper_l(t[0], loc))
			return (t);

		*val *= 36;

		if (isdigit_l(t[0], loc))
			*val += t[0] - '0';
		else
			*val += t[0] - 'A' + 10;
	}
	return (t);
}

static struct type_tbl_s sub_tbl[] = {
	{ 'a', "std::allocator" },
	{ 'b', "std::basic_string" },
	{ 's', "std::string" },
	{ 'i', "std::istream" },
	{ 'o', "std::ostream" },
	{ 'd', "std::iostream" }
};

static const char *
parse_substitution(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (first == last || last - first < 2)
		return (first);

	if (first[0] != 'S')
		return (first);

	for (size_t i = 0; i < ARRAY_SIZE(sub_tbl); i++) {
		if (first[1] == sub_tbl[i].code) {
			nadd_l(db, sub_tbl[i].name, 0);
			return (first + 2);
		}
	}

	const char *t = first + 1;
	size_t n = 0;

	if (t[0] != '_') {
		t = parse_base36(first + 1, last, &n, db->cpp_loc);
		if (t == first + 1 || t[0] != '_')
			return (first);

		/*
		 * S_ == substitution 0,
		 * S0_ == substituion 1,
		 * ...
		 */
		n++;
	}

	if (n >= sub_len(&db->cpp_subs))
		return (first);

	sub(db, n);

	/* skip _ */
	VERIFY3U(t[0], ==, '_');

	return (t + 1);
}

static const char *
parse_source_name(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (first == last)
		return (first);

	const char *t = NULL;
	size_t n = 0;

	for (t = first; t != last && isdigit_l(t[0], db->cpp_loc); t++) {
		/* make sure we don't overflow */
		size_t nn = n * 10;
		if (nn < n)
			return (first);

		nn += t[0] - '0';
		if (nn < n)
			return (first);

		n = nn;
	}

	if (n == 0 || t == last || t + n > last ||
	    (uintptr_t)t + n < (uintptr_t)t)
		return (first);

	if (strncmp(t, "_GLOBAL__N", 10) == 0)
		nadd_l(db, "(anonymous namespace)", 0);
	else
		nadd_l(db, t, n);

	return (t + n);
}

/*
 * extension:
 * <vector-type>           ::= Dv <positive dimension number> _
 *                                    <extended element type>
 *                         ::= Dv [<dimension expression>] _ <element type>
 * <extended element type> ::= <element type>
 *                         ::= p # AltiVec vector pixel
 */
static const char *
parse_vector_type(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 3)
		return (first);

	VERIFY3U(first[0], ==, 'D');
	VERIFY3U(first[1], ==, 'v');

	const char *t = first + 2;
	const char *t1 = NULL;

	if (isdigit_l(first[2], db->cpp_loc) && first[2] != '0') {
		t1 = parse_number(t, last, db->cpp_loc);
		if (t1 == last || t1 + 1 == last || t1[0] != '_')
			return (first);

		nadd_l(db, t, (size_t)(t1 - t));

		/* skip _ */
		t = t1 + 1;

		if (t[0] != 'p') {
			t1 = parse_type(t, last, db);
			if (t1 == t)
				return (first);

			nfmt(db, "{0} vector[{1}]", NULL);
			return (t1);
		}
		nfmt(db, "{0} pixel vector[{1}]", NULL);
		return (t1);
	}

	if (first[2] != '_') {
		t1 = parse_expression(first + 2, last, db);
		if (first == last || t1 == first + 2 || t1[0] != '_')
			return (first);

		/* skip _ */
		t = t1 + 1;
	} else {
		nadd_l(db, "", 0);
	}

	t1 = parse_type(t, last, db);
	if (t == t1)
		return (first);

	nfmt(db, "{1:L} vector[{0}]", "{1:R}");
	return (t1);
}

/* BEGIN CSTYLED */
/*
 * <decltype>  ::= Dt <expression> E  # decltype of an id-expression or class member access (C++0x)
 *             ::= DT <expression> E  # decltype of an expression (C++0x)
 */
/* END CSTYLED */
static const char *
parse_decltype(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 4)
		return (first);

	VERIFY3U(first[0], ==, 'D');

	if (first[1] != 't' && first[1] != 'T')
		return (first);

	size_t n = nlen(db);
	const char *t = parse_expression(first + 2, last, db);
	if (NAMT(db, n) != 1 || t == first + 2 || t == last || t[0] != 'E')
		return (first);

	nfmt(db, "decltype({0})", NULL);

	/* skip E */
	return (t + 1);
}

/*
 * <array-type> ::= A <positive dimension number> _ <element type>
 *              ::= A [<dimension expression>] _ <element type>
 */
static const char *
parse_array_type(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);
	VERIFY3U(first[0], ==, 'A');

	if (last - first < 3)
		return (first);

	const char *t = first + 1;
	const char *t1 = NULL;
	size_t n = nlen(db);

	if (t[0] != '_') {
		if (isdigit_l(t[0], db->cpp_loc) && t[0] != '0') {
			t1 = parse_number(t, last, db->cpp_loc);
			if (t1 == last)
				return (first);

			nadd_l(db, t, (size_t)(t1 - t));
		} else {
			t1 = parse_expression(t, last, db);
			if (t1 == last || t == t1)
				return (first);
		}

		if (t1[0] != '_')
			return (first);

		t = t1;
	} else {
		nadd_l(db, "", 0);
	}

	VERIFY3U(t[0], ==, '_');

	t1 = parse_type(t + 1, last, db);
	if (t1 == t + 1 || NAMT(db, n) != 2)
		return (first);

	/*
	 * if we have  " [xxx]" already, want new result to be
	 * " [yyy][xxx]"
	 */
	str_t *r = &name_top(&db->cpp_name)->strp_r;
	if (r->str_len > 1 && r->str_s[0] == ' ' && r->str_s[1] == '[')
		(void) str_erase(r, 0, 1);

	nfmt(db, "{0:L}", " [{1}]{0:R}");
	return (t1);
}

/* <pointer-to-member-type> ::= M <class type> <member type> */
static const char *
parse_pointer_to_member_type(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 3)
		return (first);

	VERIFY3U(first[0], ==, 'M');

	const char *t1 = first + 1;
	const char *t2 = NULL;
	size_t n = nlen(db);

	t2 = parse_type(t1, last, db);
	if (t1 == t2)
		return (first);

	t1 = t2;
	t2 = parse_type(t1, last, db);
	if (t1 == t2)
		return (first);

	if (NAMT(db, n) != 2)
		return (first);

	str_pair_t *func = name_top(&db->cpp_name);

	if (str_length(&func->strp_r) > 0 && func->strp_r.str_s[0] == '(')
		nfmt(db, "{0:L}({1}::*", "){0:R}");
	else
		nfmt(db, "{0:L} {1}::*", "{0:R}");

	return (t2);
}

/* BEGIN CSTYLED */
/*
 * <unresolved-name>
 *  extension        ::= srN <unresolved-type> [<template-args>] <unresolved-qualifier-level>* E <base-unresolved-name>
 *                   ::= [gs] <base-unresolved-name>                     # x or (with "gs") ::x
 *                   ::= [gs] sr <unresolved-qualifier-level>+ E <base-unresolved-name>
 *                                                                       # A::x, N::y, A<T>::z; "gs" means leading "::"
 *                   ::= sr <unresolved-type> <base-unresolved-name>     # T::x / decltype(p)::x
 *  extension        ::= sr <unresolved-type> <template-args> <base-unresolved-name>
 *                                                                       # T::N::x /decltype(p)::N::x
 *  (ignored)        ::= srN <unresolved-type>  <unresolved-qualifier-level>+ E <base-unresolved-name>
 */
/* END CSTYLED */
static const char *
parse_unresolved_name(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 2)
		return (first);

	const char *t = first;
	const char *t2 = NULL;
	boolean_t global = B_FALSE;
	size_t n;

	if (t[0] == 'g' && t[1] == 's') {
		global = B_TRUE;
		t += 2;
	}
	if (t == last)
		return (first);

	t2 = parse_base_unresolved_name(t, last, db);
	if (t != t2) {
		if (global) {
			if (nempty(db))
				return (first);

			(void) str_insert(TOP_L(db), 0, "::", 2);
		}
		return (t2);
	}

	if (t[0] != 's' || t[1] != 'r' || last - t < 2)
		return (first);

	n = nlen(db);
	if (t[2] == 'N') {
		t += 3;
		t2 = parse_unresolved_type(t, last, db);
		if (t2 == t || t2 == last)
			return (first);
		t = t2;

		t2 = parse_template_args(t, last, db);
		if (t2 != t) {
			if (NAMT(db, n) < 2 || t2 == last)
				return (first);

			nfmt(db, "{1:L}{0}", "{1:R}");
			t = t2;
		}

		VERIFY3U(NAMT(db, n), ==, 1);

		while (t[0] != 'E') {
			size_t nn = nlen(db);
			t2 = parse_unresolved_qualifier_level(t, last, db);
			if (t == t2 || t == last || NAMT(db, nn) != 1)
				return (first);

			t = t2;
		}

		/* skip E */
		t++;

		t2 = parse_base_unresolved_name(t, last, db);
		if (t == t2 || NAMT(db, n) < 2)
			return (first);

		njoin(db, NAMT(db, n), "::");
		return (t2);
	}

	t += 2;

	t2 = parse_unresolved_type(t, last, db);
	if (t != t2) {
		t = t2;
		t2 = parse_template_args(t, last, db);
		if (t2 != t)
			nfmt(db, "{1:L}{0}", "{1:R}");
		t = t2;

		t2 = parse_base_unresolved_name(t, last, db);
		if (t == t2 || nlen(db) < 2)
			return (first);

		nfmt(db, "{1:L}::{0}", "{1:R}");
		return (t2);
	}

	t2 = parse_unresolved_qualifier_level(t, last, db);
	if (t2 == t || t2 == last)
		return (first);

	t = t2;
	if (global && nlen(db) > 0)
		nfmt(db, "::{0:L}", "{0:R}");

	while (t[0] != 'E') {
		t2 = parse_unresolved_qualifier_level(t, last, db);
		if (t == t2 || t == last || nlen(db) < 2)
			return (first);

		t = t2;
	}

	/* skip E */
	t++;

	t2 = parse_base_unresolved_name(t, last, db);
	if (t == t2 || nlen(db) < 2)
		return (first);

	njoin(db, NAMT(db, n), "::");
	return (t2);
}

/* <unresolved-qualifier-level> ::= <simple-id> */
static const char *
parse_unresolved_qualifier_level(const char *first, const char *last,
    cpp_db_t *db)
{
	VERIFY3P(first, <=, last);
	return (parse_simple_id(first, last, db));
}

/* BEGIN CSTYLED */
/*
 * <base-unresolved-name> ::= <simple-id>                                # unresolved name
 *          extension     ::= <operator-name>                            # unresolved operator-function-id
 *          extension     ::= <operator-name> <template-args>            # unresolved operator template-id
 *                        ::= on <operator-name>                         # unresolved operator-function-id
 *                        ::= on <operator-name> <template-args>         # unresolved operator template-id
 *                        ::= dn <destructor-name>                       # destructor or pseudo-destructor;
 *                                                                       # e.g. ~X or ~X<N-1>
 */
/* END CSTYLED */
static const char *
parse_base_unresolved_name(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 2)
		return (first);

	const char *t = NULL;
	const char *t1 = NULL;

	if ((first[0] != 'o' && first[0] != 'd') || first[1] != 'n') {
		t = parse_simple_id(first, last, db);
		if (t != first)
			return (t);

		t = parse_operator_name(first, last, db);
		if (t == first)
			return (first);

		t1 = parse_template_args(t, last, db);
		if (t1 != t) {
			if (nlen(db) < 2)
				return (first);
			nfmt(db, "{1:L}{0}", "{1:R}");
		}

		return (t1);
	}

	if (first[0] == 'd') {
		t = parse_destructor_name(first + 2, last, db);
		return ((t != first + 2) ? t : first);
	}

	t = parse_operator_name(first + 2, last, db);
	if (t == first + 2)
		return (first);

	t1 = parse_template_args(t, last, db);
	if (t1 != t)
		nfmt(db, "{1:L}{0}", "{1:R}");
	return (t1);
}

/*
 * <destructor-name> ::= <unresolved-type>	# e.g., ~T or ~decltype(f())
 *                   ::= <simple-id>		# e.g., ~A<2*N>
 */
static const char *
parse_destructor_name(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (first == last)
		return (first);

	const char *t = parse_unresolved_type(first, last, db);

	if (t == first)
		t = parse_simple_id(first, last, db);

	if (t == first)
		return (first);

	nfmt(db, "~{0:L}", "{0:R}");
	return (t);
}

/*
 *  <ref-qualifier> ::= R                   # & ref-qualifier
 *  <ref-qualifier> ::= O                   # && ref-qualifier
 *
 * <function-type> ::= F [Y] <bare-function-type> [<ref-qualifier>] E
 */
static const char *
parse_function_type(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 2)
		return (first);

	VERIFY3U(first[0], ==, 'F');

	const char *t = first + 1;

	/* extern "C" */
	if (t[0] == 'Y')
		t++;

	const char *t1 = parse_type(t, last, db);
	if (t1 == t)
		return (first);

	size_t n = nlen(db);
	int ref_qual = 0;

	t = t1;

	while (t != last && t[0] != 'E') {
		if (t[0] == 'v') {
			t++;
			continue;
		}

		if (t[0] == 'R' && t + 1 != last && t[1] == 'E') {
			ref_qual = 1;
			t++;
			continue;
		}

		if (t[0] == 'O' && t + 1 != last && t[1] == 'E') {
			ref_qual = 2;
			t++;
			continue;
		}


		t1 = parse_type(t, last, db);
		if (t1 == t || t == last)
			return (first);

		t = t1;
	}

	if (t == last)
		return (first);

	njoin(db, NAMT(db, n), ", ");
	nfmt(db, "({0})", NULL);

	switch (ref_qual) {
	case 1:
		nfmt(db, "{0} &", NULL);
		break;
	case 2:
		nfmt(db, "{0} &&", NULL);
		break;
	}

	nfmt(db, "{1:L} ", "{0}{1:R}");

	/* skip E */
	return (t + 1);
}

/*
 * <template-param> ::= T_    # first template parameter
 *                  ::= T <parameter-2 non-negative number> _
 */
static const char *
parse_template_param(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 2 || first[0] != 'T')
		return (first);

	const char *t = first + 1;
	size_t idx = 0;

	while (t != last && t[0] != '_') {
		if (!isdigit_l(t[0], db->cpp_loc))
			return (first);

		idx *= 10;
		idx += t[0] - '0';
		t++;
	}

	if (t == last)
		return (first);

	VERIFY3U(t[0], ==, '_');

	/*
	 * T_ -> idx 0
	 * T0 -> idx 1
	 * T1 -> idx 2
	 * ...
	 */
	if (first[1] != '_')
		idx++;

	/* skip _ */
	t++;

	if (tempty(db))
		return (first);

	if (idx >= ttlen(db)) {
		nadd_l(db, first, (size_t)(t - first));
		db->cpp_fix_forward_references = B_TRUE;
		return (t);
	}

	tsub(db, idx);
	return (t);
}

/*
 * <template-args> ::= I <template-arg>* E
 *     extension, the abi says <template-arg>+
 */
static const char *
parse_template_args(const char *first, const char *last, cpp_db_t *db)
{
	VERIFY3P(first, <=, last);

	if (last - first < 2 || first[0] != 'I')
		return (first);

	if (db->cpp_tag_templates)
		sub_clear(templ_top(&db->cpp_templ));

	const char *t = first + 1;
	size_t n = nlen(db);

	while (t[0] != 'E') {
		if (db->cpp_tag_templates)
			tpush(db);

		size_t n1 = nlen(db);
		const char *t1 = parse_template_arg(t, last, db);

		if (db->cpp_tag_templates)
			tpop(db);

		if (t1 == t || t == last)
			return (first);

		if (db->cpp_tag_templates)
			tsave(db, NAMT(db, n1));

		t = t1;
	}

	/*
	 * ugly, but if the last thing pushed was an empty string,
	 * get rid of it so we dont get "<..., >"
	 */
	if (NAMT(db, n) > 1 &&
	    str_pair_len(name_top(&db->cpp_name)) == 0)
		name_pop(&db->cpp_name, NULL);

	njoin(db, NAMT(db, n), ", ");

	VERIFY3U(nlen(db), >, 0);

	/* make sure we don't bitshift ourselves into oblivion */
	str_t *top = TOP_L(db);
	if (str_length(top) > 0 &&
	    top->str_s[top->str_len - 1] == '>')
		nfmt(db, "<{0} >", NULL);
	else
		nfmt(db, "<{0}>", NULL);

	/* skip E */
	return (t + 1);
}

/*
 * <discriminator> := _ <non-negative number>      # when number < 10
 *                 := __ <non-negative number> _   # when number >= 10
 *  extension      := decimal-digit+               # at the end of string
 */
static const char *
parse_discriminator(const char *first, const char *last, locale_t loc)
{
	VERIFY3P(first, <=, last);

	const char *t = NULL;

	if (first == last)
		return (first);

	if (isdigit_l(first[0], loc)) {
		for (t = first; t != last && isdigit_l(t[0], loc); t++)
			;

		/* not at the end of the string */
		if (t != last)
			return (first);

		return (t);
	} else if (first[0] != '_' || first + 1 == last) {
		return (first);
	}

	t = first + 1;
	if (isdigit_l(t[0], loc))
		return (t + 1);

	if (t[0] != '_' || t + 1 == last)
		return (first);

	for (t++; t != last && isdigit_l(t[0], loc); t++)
		;
	if (t == last || t[0] != '_')
		return (first);

	return (t);
}

/* <CV-qualifiers> ::= [r] [V] [K] */
const char *
parse_cv_qualifiers(const char *first, const char *last, unsigned *cv)
{
	VERIFY3P(first, <=, last);

	if (first == last)
		return (first);

	*cv = 0;
	if (first[0] == 'r') {
		*cv |= CPP_QUAL_RESTRICT;
		first++;
	}
	if (first != last && first[0] == 'V') {
		*cv |= CPP_QUAL_VOLATILE;
		first++;
	}
	if (first != last && first[0] == 'K') {
		*cv |= CPP_QUAL_CONST;
		first++;
	}

	return (first);
}

/*
 * <number> ::= [n] <non-negative decimal integer>
 */
static const char *
parse_number(const char *first, const char *last, locale_t loc)
{
	VERIFY3P(first, <=, last);

	const char *t = first;

	if (first == last || (first[0] != 'n' && !isdigit_l(first[0], loc)))
		return (first);

	if (t[0] == 'n')
		t++;

	if (t[0] == '0')
		return (t + 1);

	while (isdigit_l(t[0], loc))
		t++;

	return (t);
}

/*
 * Like isxdigit(3C), except we can only accept lower case letters as
 * that's only what is allowed when [de]mangling floating point constants into
 * their hex representation.
 */
static inline boolean_t
is_xdigit(int c)
{
	if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
		return (B_TRUE);
	return (B_FALSE);
}

static boolean_t
nempty(cpp_db_t *db)
{
	return (name_empty(&db->cpp_name));
}

static size_t
nlen(cpp_db_t *db)
{
	return (name_len(&db->cpp_name));
}

static void
nadd_l(cpp_db_t *db, const char *s, size_t len)
{
	CK(name_add(&db->cpp_name, s, len, NULL, 0));
}

static void
njoin(cpp_db_t *db, size_t amt, const char *sep)
{
	name_t *nm = &db->cpp_name;

	CK(name_join(nm, amt, sep));
}

static void
nfmt(cpp_db_t *db, const char *fmt_l, const char *fmt_r)
{
	CK(name_fmt(&db->cpp_name, fmt_l, fmt_r));
}

static void
save_top(cpp_db_t *db, size_t amt)
{
	CK(sub_save(&db->cpp_subs, &db->cpp_name, amt));
}

static void
sub(cpp_db_t *db, size_t n)
{
	CK(sub_substitute(&db->cpp_subs, n, &db->cpp_name));
}

static boolean_t
tempty(const cpp_db_t *db)
{
	return (templ_empty(&db->cpp_templ) ? B_TRUE : B_FALSE);
}

static size_t
ttlen(const cpp_db_t *db)
{
	return (templ_top_len(&db->cpp_templ));
}

static void
tsub(cpp_db_t *db, size_t n)
{
	CK(templ_sub(&db->cpp_templ, n, &db->cpp_name));
}

static void
tpush(cpp_db_t *db)
{
	CK(templ_push(&db->cpp_templ));
}

static void
tpop(cpp_db_t *db)
{
	templ_pop(&db->cpp_templ);
}

static void
tsave(cpp_db_t *db, size_t amt)
{
	CK(templ_save(&db->cpp_name, amt, &db->cpp_templ));
}

static boolean_t
db_init(cpp_db_t *db, sysdem_ops_t *ops)
{
	(void) memset(db, 0, sizeof (*db));
	db->cpp_ops = ops;
	name_init(&db->cpp_name, ops);
	sub_init(&db->cpp_subs, ops);
	templ_init(&db->cpp_templ, ops);
	db->cpp_tag_templates = B_TRUE;
	db->cpp_try_to_parse_template_args = B_TRUE;
	tpush(db);
	db->cpp_loc = newlocale(LC_CTYPE_MASK, "C", 0);
	return ((db->cpp_loc != NULL) ? B_TRUE : B_FALSE);
}

static void
db_fini(cpp_db_t *db)
{
	name_fini(&db->cpp_name);
	sub_fini(&db->cpp_subs);
	templ_fini(&db->cpp_templ);
	freelocale(db->cpp_loc);
	(void) memset(db, 0, sizeof (*db));
}

static void
print_sp(const str_pair_t *sp, FILE *out)
{
	(void) fprintf(out, "{%.*s#%.*s}",
	    (int)sp->strp_l.str_len, sp->strp_l.str_s,
	    (int)sp->strp_r.str_len, sp->strp_r.str_s);
}

static void
print_name(const name_t *n, FILE *out)
{
	const str_pair_t *sp = name_top((name_t *)n);
	size_t i;

	(void) fprintf(out, "Name:\n");

	if (name_len(n) == 0)
		return;

	for (i = 0; i < n->nm_len; i++, sp--) {
		(void) fprintf(out, "  [%02zu] ", i);
		print_sp(sp, out);
		(void) fputc('\n', out);
	}

	(void) fputc('\n', out);
}

/* Print a base-36 number (for substitutions) */
static char *
base36(char *buf, size_t val)
{
	char tmp[16] = { 0 };
	char *p = tmp;

	if (val == 0) {
		buf[0] = '0';
		buf[1] = '\0';
		return (buf);
	}

	while (val > 0) {
		size_t r = val % 36;

		if (r < 10)
			*p++ = r + '0';
		else
			*p++ = r - 10 + 'A';

		val /= 36;
	}

	char *q = buf;
	while (--p >= tmp)
		*q++ = *p;

	return (buf);
}

static void
print_sub(const sub_t *sub, FILE *out)
{
	const name_t *n = sub->sub_items;

	(void) fprintf(out, "Substitutions:\n");

	if (sub->sub_len == 0)
		return;

	for (size_t i = 0; i < sub->sub_len; i++, n++) {
		(void) printf("  ");
		if (i == 0) {
			(void) fprintf(out, "%-4s", "S_");
		} else {
			char buf[16] = { 0 };
			char buf2[16] = { 0 };

			(void) snprintf(buf, sizeof (buf), "S%s_",
			    base36(buf2, i));
			(void) fprintf(out, "%-4s", buf);
		}
		(void) fprintf(out, " = ");

		(void) fputc('{', out);
		for (size_t j = 0; j < n->nm_len; j++) {
			if (j > 0)
				(void) fputc(' ', out);
			print_sp(&n->nm_items[j], out);
		}
		(void) fputc('}', out);

		(void) fputc('\n', out);
	}
	(void) fputc('\n', out);
}

static void
print_templ(const templ_t *tpl, FILE *out)
{

	(void) fprintf(out, "Template\n");

	const sub_t *s = templ_top((templ_t *)tpl);

	for (size_t i = 0; i < s->sub_len; i++) {
		char buf[16] = { 0 };

		if (i == 0)
			(void) snprintf(buf, sizeof (buf), "%s", "T_");
		else
			(void) snprintf(buf, sizeof (buf), "T%zu_", i - 1);

		(void) fprintf(out, "  %-4s = ", buf);

		(void) fputc('{', out);

		const name_t *n = &s->sub_items[i];
		for (size_t j = 0; j < n->nm_len; j++) {
			const str_pair_t *sp = &n->nm_items[j];

			if (j > 0)
				(void) fputc(' ', out);

			(void) fprintf(out, "{%.*s#%.*s}",
			    (int)sp->strp_l.str_len, sp->strp_l.str_s,
			    (int)sp->strp_r.str_len, sp->strp_r.str_s);
		}
		(void) fprintf(out, "}\n");
	}
	(void) fprintf(out, "\n");
}

static void
dump(cpp_db_t *db, FILE *out)
{
	print_name(&db->cpp_name, out);
	print_sub(&db->cpp_subs, out);
	print_templ(&db->cpp_templ, out);
}
