/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include "fields.h"

/*
 * fields
 *
 * Overview
 *   By a field, we mean the various delimited character sequences within each
 *   line of the input files.  The sort key consists of an ordered sequence of
 *   fields, which need not include all possible fields for the given line.
 *   (Furthermore, not every line need contain sufficient fields for the fields
 *   given within the sort key.  In fact, none of the lines in the input stream
 *   need contain sufficient fields.)
 *
 *   There are two methods for specifying fields for sort(1); these are
 *   discussed in options.c.  Here we discuss only the internal representation
 *   of fields, as used for constructing the collation vector for each line as
 *   defined by the sort key.
 *
 * Representation
 *   The sort key is a singly-linked list of field specifiers.  At present,
 *   fields may belong to one of three species:  alphabetical, numerical, or
 *   monthly; the species (f_species) then indicates the conversion function
 *   (f_convert) used to transform the raw characters of the character sequence
 *   to a collatable form.  (In principle, this allows us to consider future
 *   field species such as hexadecimal.)
 *
 *   Fields and offsets are numbered such that zero refers to the first field or
 *   character, respectively.  Thus, the interpretation of a key specifier, m.n,
 *   is that the field begins at the nth character beyond the mth occurence of
 *   the key separator.  If the blanks flag has been specified, then the field
 *   begins at the nth non-blank character past the mth key separator.  If the
 *   key separator is unspecified, then the key separator is defined as one or
 *   more blank characters.
 *
 *   In general, the various options afforded by sort may be broken into two
 *   categories:  field species and field modifiers.  For each field species,
 *   there is one or more conversion routines that take a delimited character
 *   sequence and convert it to a character sequence collatable by strcmp() or
 *   memcmp().  For field species that may be further modified, such as the
 *   fold-to-uppercase option for alphabetic fields, the conversion routine may
 *   be aware of how the modifier affects collation.  Finally, the no-modifiers
 *   case may present an opportunity for a simplified, faster version.
 *
 * Code Structure
 *   The code paths for single-byte and multi-byte locales diverge significantly
 *   in fields.c.  Most routines have an *_wide() version, which produces an
 *   equivalent effect for line records whose data field is composed of wide
 *   characters (wchar_t).  However, the l_collated field of a line record is
 *   always composed of characters, so that the radix sorts provided in
 *   internal.c can work in both single- and multi-byte locales.  Thus, in the
 *   various convert_*_wide() routines, the output is placed in l_collated, with
 *   a length multiplier of 4.
 */

#define	BEFORE_NUMBER	0x0
#define	IN_NUMBER	0x1

static char	numerical_separator;
static char	numerical_decimal;
static char	monetary_separator;
static char	monetary_decimal;

static wchar_t	w_numerical_separator;
static wchar_t	w_numerical_decimal;
static wchar_t	w_monetary_separator;
static wchar_t	w_monetary_decimal;

#define	MONTHS_IN_YEAR	12
#define	MAX_MON_LEN	20

enum { MO_NONE = 1, MO_OFFSET = 2 };

static char	*months[MONTHS_IN_YEAR];
static size_t	month_lengths[MONTHS_IN_YEAR];
static wchar_t	*w_months[MONTHS_IN_YEAR];
static size_t	w_month_lengths[MONTHS_IN_YEAR];

#define	DECIMAL_CHAR		(numerical_decimal)
#define	IS_BLANK(x)		(isspace((uchar_t)(x)) && (x) != '\n')
#define	IS_SEPARATOR(x)		\
	((numerical_separator != '\0' && (x) == numerical_separator) || \
	(monetary_separator != '\0' && (x) == monetary_separator))
#define	IS_DECIMAL(x)		\
	((x) == numerical_decimal || \
	(monetary_decimal != '\0' && (x) == monetary_decimal))
#define	W_DECIMAL_CHAR		(w_numerical_decimal)
#define	W_IS_BLANK(x)		(iswspace(x) && (x) != L'\n')
#define	W_IS_SEPARATOR(x)	\
	((numerical_separator != '\0' && (x) == w_numerical_separator) || \
	(monetary_separator != '\0' && (x) == w_monetary_separator))
#define	W_IS_DECIMAL(x)		\
	(((x) == w_numerical_decimal) || \
	(monetary_decimal != '\0' && (x) == w_monetary_decimal))

#define	INTERFIELD_SEPARATOR '\0'
#define	W_INTERFIELD_SEPARATOR L'\0'

#define	INT_SIGN_FLIP_MASK 0x80000000
#define	INT_SIGN_PASS_MASK 0x00000000

/*
 * strx_ops_t, xfrm_len, and xfrm_cpy:  In the case where we are sorting in the
 * C locale, we want to avoid the expense of transforming strings to collatable
 * forms since, by definition, an arbitrary string in the C locale is already in
 * its collatable form.  Therefore, we construct a small ops vector (the
 * strx_ops) and two wrappers: xfrm_len() to massage the strxfrm(NULL, ...) into
 * strlen()-like behaviour, and xfrm_cpy() to make strncpy() appear
 * strxfrm()-like.
 */
/*ARGSUSED*/
static size_t
xfrm_len(const char *s2, size_t len)
{
	return (strxfrm(NULL, s2, 0) + 1);
}

/*
 * The length represented by n includes a null character, so to return the
 * correct length we subtract 1.  Note that this function is only used by
 * field_convert_alpha, and isn't for general use, as it assumes that n is the
 * length of s2 plus a null character.
 */
static size_t
C_ncpy(char *s1, const char *s2, size_t n)
{
	(void) strncpy(s1, s2, n);
	return (n - 1);
}

/*ARGSUSED*/
static size_t
C_len(const char *s, size_t len)
{
	ASSERT(s != NULL);
	return (len);
}

typedef struct _strx_ops {
	size_t	(*sx_len)(const char *, size_t);
	size_t	(*sx_xfrm)(char *, const char *, size_t);
} strx_ops_t;

static const strx_ops_t C_ops = { C_len, C_ncpy };
static const strx_ops_t SB_ops = { xfrm_len, strxfrm };

static const strx_ops_t *xfrm_ops;

static void
field_initialize_separator(void)
{
	/*
	 * A locale need not define all of the cases below:  only decimal_point
	 * must be defined.  Furthermore, sort(1) has traditionally not used the
	 * positive_sign and negative_sign, grouping, or currency_symbols (or
	 * their numeric counterparts, if any).
	 */
	struct lconv *conv = localeconv();

	if (!xstreql(conv->thousands_sep, "")) {
		numerical_separator = *conv->thousands_sep;
		(void) mbtowc(&w_numerical_separator, conv->thousands_sep,
		    MB_CUR_MAX);
	} else
		numerical_separator = '\0';

	if (!xstreql(conv->mon_thousands_sep, "")) {
		monetary_separator = *conv->mon_thousands_sep;
		(void) mbtowc(&w_monetary_separator, conv->mon_thousands_sep,
		    MB_CUR_MAX);
	} else
		monetary_separator = '\0';

	if (!xstreql(conv->mon_decimal_point, "")) {
		monetary_decimal = *conv->mon_decimal_point;
		(void) mbtowc(&w_monetary_decimal, conv->mon_decimal_point,
		    MB_CUR_MAX);
	} else
		monetary_decimal = '\0';

	numerical_decimal = *conv->decimal_point;
	(void) mbtowc(&w_numerical_decimal, conv->decimal_point, MB_CUR_MAX);
}

static void
field_initialize_month(int is_c_locale)
{
	int i;
	int j;
	struct tm this_month;
	const char *c_months[MONTHS_IN_YEAR] = {
		"JAN", "FEB", "MAR", "APR", "MAY", "JUN",
		"JUL", "AUG", "SEP", "OCT", "NOV", "DEC"
	};

	char month_name[MAX_MON_LEN * MB_LEN_MAX];
	wchar_t	w_month_name[MAX_MON_LEN];

	if (is_c_locale) {
		for (i = 0; i < MONTHS_IN_YEAR; i++) {
			months[i] = (char *)c_months[i];
			month_lengths[i] = strlen(c_months[i]);
		}
		/*
		 * We don't need to initialize the wide version of the month
		 * names.
		 */
		return;
	}

	(void) memset(&this_month, 0, sizeof (this_month));

	for (i = 0; i < MONTHS_IN_YEAR; i++) {
		this_month.tm_mon = i;

		(void) strftime(month_name, sizeof (month_name),
		    "%b", &this_month);

		for (j = 0; j < strlen(month_name); j++)
			month_name[j] = toupper(month_name[j]);
		(void) mbstowcs(w_month_name, month_name, MAX_MON_LEN);

		months[i] = strdup(month_name);
		month_lengths[i] = strlen(month_name);
		w_months[i] = wsdup(w_month_name);
		w_month_lengths[i] = wslen(w_month_name);
	}
}

void
field_initialize(sort_t *S)
{
	field_initialize_month(S->m_c_locale);
	field_initialize_separator();

	if (S->m_c_locale)
		xfrm_ops = &C_ops;
	else
		xfrm_ops = &SB_ops;
}

field_t *
field_new(sort_t *S)
{
	field_t	*F = safe_realloc(NULL, sizeof (field_t));

	F->f_start_field = -1;
	F->f_start_offset = -1;
	F->f_end_field = -1;
	F->f_end_offset = -1;
	F->f_next = NULL;

	if (S == NULL) {
		F->f_species = ALPHA;
		F->f_options = 0;
	} else {
		F->f_species = S->m_default_species;
		F->f_options = S->m_field_options;
	}

	return (F);
}

void
field_delete(field_t *F)
{
	free(F);
}

/*
 * The recursive implementation of field_add_to_chain() given below is
 * inappropriate if function calls are expensive, or a truly large number of
 * fields are anticipated.
 */
void
field_add_to_chain(field_t **F, field_t *A)
{
	if (*F == NULL)
		*F = A;
	else
		field_add_to_chain(&((*F)->f_next), A);
}

#ifdef DEBUG
#ifndef _LP64
#define	FIELD_FMT \
"\nStart field: %d\tStart offset: %d\nEnd field: %d\tEnd offset: %d\n"
#else /* !_LP64 */
#define	FIELD_FMT \
"\nStart field: %ld\tStart offset: %ld\nEnd field: %ld\tEnd offset: %ld\n"
#endif /* !_LP64 */

/*
 * field_print is used only for debugging purposes.
 */
void
field_print(field_t *F)
{
	char *field_names[] = {"ALPHA", "MONTH", "NUMERIC"};
	int status = 0;

	(void) fprintf(stderr, "Type: %s", field_names[F->f_species]);
	(void) fprintf(stderr, "\tOptions: ");

	if (F->f_options & FIELD_REVERSE_COMPARISONS) {
		(void) fprintf(stderr, "REVERSE");
		status++;
	}
	if (F->f_options & FIELD_DICTIONARY_ORDER) {
		(void) fprintf(stderr, "DICTIONARY ");
		status++;
	}
	if (F->f_options & FIELD_FOLD_UPPERCASE) {
		(void) fprintf(stderr, "UPPERCASE ");
		status++;
	}
	if (F->f_options & FIELD_IGNORE_NONPRINTABLES) {
		(void) fprintf(stderr, "PRINTABLES ");
		status++;
	}
	if (F->f_options & FIELD_IGNORE_BLANKS_START) {
		(void) fprintf(stderr, "BLANKS_START ");
		status++;
	}
	if (F->f_options & FIELD_IGNORE_BLANKS_END) {
		(void) fprintf(stderr, "BLANKS_END ");
		status++;
	}

	if (status == 0)
		(void) fprintf(stderr, "NO_MODIFIERS");

	(void) fprintf(stderr, FIELD_FMT, F->f_start_field, F->f_start_offset,
	    F->f_end_field, F->f_end_offset);
}
#endif /* DEBUG */

static ssize_t
field_boundary(field_t *F, line_rec_t *L, int is_end, int is_blanks)
{
	char *S = L->l_data.sp;
	char *T = S;
	char *eol = S + L->l_data_length;
	ssize_t field = is_end ? F->f_end_field : F->f_start_field;
	ssize_t offset = is_end ? F->f_end_offset : F->f_start_offset;
	ssize_t ret;

	ASSERT(is_end || field > -1);

	if (is_end && field == -1)
		return (L->l_data_length);

	while (field-- > 0) {
		while (T < eol && IS_BLANK(*T))
			T++;

		while (T < eol && !IS_BLANK(*T))
			T++;
	}

	if ((!is_end || offset > 0) && is_blanks) {
		while (IS_BLANK(*T))
			T++;
	}

	if ((ret = MAX(T - S, 0) + offset) >= L->l_data_length)
		return (L->l_data_length);

	return (ret);
}

static void
field_delimit(field_t *F, line_rec_t *L, ssize_t *start, ssize_t *end)
{
	ASSERT(F->f_start_field > -1);

	*start = field_boundary(F, L, 0,
	    F->f_options & FIELD_IGNORE_BLANKS_START);
	*end = field_boundary(F, L, 1,
	    F->f_options & FIELD_IGNORE_BLANKS_END);
}

static ssize_t
field_boundary_wide(field_t *F, line_rec_t *L, int is_end, int is_blanks)
{
	wchar_t *S = L->l_data.wp;
	wchar_t *T = S;
	wchar_t *eol = S + L->l_data_length;
	ssize_t field = is_end ? F->f_end_field : F->f_start_field;
	ssize_t offset = is_end ? F->f_end_offset : F->f_start_offset;
	ssize_t ret;

	ASSERT(is_end || field > -1);

	if (is_end && field == -1)
		return (L->l_data_length);

	while (field-- > 0) {
		while (T < eol && W_IS_BLANK(*T))
			T++;

		while (T < eol && !W_IS_BLANK(*T))
			T++;
	}

	if ((!is_end || offset > 0) && is_blanks) {
		while (W_IS_BLANK(*T))
			T++;
	}

	if ((ret = MAX(T - S, 0) + offset) >= L->l_data_length)
		return (L->l_data_length);

	return (ret);
}

static void
field_delimit_wide(field_t *F, line_rec_t *L, ssize_t *start, ssize_t *end)
{
	ASSERT(F->f_start_field > -1);

	*start = field_boundary_wide(F, L, 0,
	    F->f_options & FIELD_IGNORE_BLANKS_START);
	*end = field_boundary_wide(F, L, 1,
	    F->f_options & FIELD_IGNORE_BLANKS_END);
}

static ssize_t
field_boundary_tabbed(field_t *F, line_rec_t *L, int is_end, int is_blanks,
    vchar_t delimiter)
{
	char *S = L->l_data.sp;
	char *T = S;
	char *eol = S + L->l_data_length;
	ssize_t field = is_end ? F->f_end_field : F->f_start_field;
	ssize_t offset = is_end ? F->f_end_offset : F->f_start_offset;
	ssize_t ret;

	ASSERT(is_end || field > -1);

	if (is_end && field == -1)
		return (L->l_data_length);

	while (field-- > 0) {
		T = xstrnchr(T, delimiter.sc, eol - T);
		if (T == NULL || T > eol)
			return (L->l_data_length);

		T++;
	}

	if ((!is_end || offset != 0) && is_blanks) {
		while (IS_BLANK(*T))
			T++;
	}

	if ((ret = MAX(T - S, 0) + offset) >= L->l_data_length) {
		if (L->l_data_length <= 0)
			return (0);
		if (S[L->l_data_length - 1] == delimiter.sc) {
			return (L->l_data_length - 1);
		} else {
			return (L->l_data_length);
		}
	}

	if (is_end && offset == 0)
		ret--;

	return (ret);
}

/*
 * field_delimit_tabbed() is called when a field separator has been defined
 * using the -t option.  The character at the offset, start, is either one or
 * more character positions past the delimiter marking the start of the
 * field, or at the end of the line.
 */
static void
field_delimit_tabbed(field_t *F, line_rec_t *L, ssize_t *start, ssize_t *end,
    vchar_t delimiter)
{
	ASSERT(F->f_start_field > -1);

	*start = field_boundary_tabbed(F, L, 0, F->f_options &
	    FIELD_IGNORE_BLANKS_START, delimiter);
	*end = field_boundary_tabbed(F, L, 1, F->f_options &
	    FIELD_IGNORE_BLANKS_END, delimiter);
}

static ssize_t
field_boundary_tabbed_wide(field_t *F, line_rec_t *L, int is_end, int is_blanks,
    vchar_t delimiter)
{
	wchar_t *S = L->l_data.wp;
	wchar_t *T = S;
	wchar_t *eol = S + L->l_data_length;
	ssize_t field = is_end ? F->f_end_field : F->f_start_field;
	ssize_t offset = is_end ? F->f_end_offset : F->f_start_offset;
	ssize_t ret;

	ASSERT(is_end || field > -1);

	if (is_end && field == -1)
		return (L->l_data_length);

	while (field-- > 0) {
		T = xwsnchr(T, delimiter.wc, eol - T);
		if (T == NULL || T > eol)
			return (L->l_data_length);

		T++;
	}

	if ((!is_end || offset != 0) && is_blanks) {
		while (W_IS_BLANK(*T))
			T++;
	}

	if ((ret = MAX(T - S, 0) + offset) >= L->l_data_length) {
		if (L->l_data_length <= 0)
			return (0);
		if (S[L->l_data_length - 1] == delimiter.wc) {
			return (L->l_data_length - 1);
		} else {
			return (L->l_data_length);
		}
	}

	if (is_end && offset == 0)
		ret--;

	return (ret);
}

static void
field_delimit_tabbed_wide(field_t *F, line_rec_t *L, ssize_t *start,
    ssize_t *end, vchar_t delimiter)
{
	ASSERT(F->f_start_field > -1);

	*start = field_boundary_tabbed_wide(F, L, 0, F->f_options &
	    FIELD_IGNORE_BLANKS_START, delimiter);
	*end = field_boundary_tabbed_wide(F, L, 1, F->f_options &
	    FIELD_IGNORE_BLANKS_END, delimiter);
}

/*ARGSUSED*/
ssize_t
field_convert_month(field_t *F, line_rec_t *L, vchar_t delimiter,
    ssize_t data_offset, ssize_t data_length, ssize_t coll_offset)
{
	int j;
	ssize_t	val;
	char month_candidate[MAX_MON_LEN * MB_LEN_MAX];
	ssize_t month_length = data_length;
	ssize_t month_offset = data_offset;

	if (sizeof (char) > L->l_collate_bufsize - coll_offset)
		return (-1);

	(void) memset(month_candidate, 0, MAX_MON_LEN * MB_LEN_MAX);


	/*
	 * The month field formally begins with the first non-blank character.
	 */
	while (IS_BLANK(*(L->l_data.sp + month_offset))) {
		month_offset++;
		month_length--;
	}

	for (j = 0; j < MAX_MON_LEN && j < month_length; j++)
		month_candidate[j] = toupper((L->l_data.sp + month_offset)[j]);

	for (j = 0; j < MONTHS_IN_YEAR; j++) {
		if (xstrneql(month_candidate, months[j], month_lengths[j])) {
			*(L->l_collate.sp + coll_offset) = '\0' + j + MO_OFFSET;
			return (1);
		}
	}

	/*
	 * no matching month; copy string into field.  required behaviour is
	 * that "month-free" keys sort before month-sortable keys, so insert
	 * a "will sort first" token.
	 */
	*(L->l_collate.sp + coll_offset) = '\0' + MO_NONE;

	val = field_convert_alpha_simple(F, L, delimiter, data_offset,
	    data_length, coll_offset + 1);

	if (val < 0)
		return (-1);
	else
		return (val + 1);
}

/*ARGSUSED*/
ssize_t
field_convert_month_wide(field_t *F, line_rec_t *L, vchar_t delimiter,
    ssize_t data_offset, ssize_t data_length, ssize_t coll_offset)
{
	ssize_t j;
	ssize_t val;
	wchar_t month_candidate[MAX_MON_LEN];
	wchar_t *month;
	wchar_t *buffer = L->l_collate.wp + coll_offset;
	ssize_t month_length = data_length;
	ssize_t month_offset = data_offset;

	if (L->l_collate_bufsize - coll_offset * sizeof (wchar_t) <
	    sizeof (wchar_t))
		return (-1);

	(void) memset(month_candidate, 0, MAX_MON_LEN * sizeof (wchar_t));


	while (W_IS_BLANK(*(L->l_data.wp + month_offset))) {
		month_offset++;
		month_length--;
	}

	month = L->l_data.wp + month_offset;

	for (j = 0; j < MAX_MON_LEN && j < month_length; j++)
		month_candidate[j] = towupper(month[j]);

	for (j = 0; j < MONTHS_IN_YEAR; j++)
		if (xwcsneql(month_candidate, w_months[j],
		    w_month_lengths[j])) {
			*buffer = L'\0' + j + MO_OFFSET;
			return (1);
		}

	*buffer = L'\0' + MO_NONE;

	val = field_convert_alpha_wide(F, L, delimiter, data_offset,
	    data_length, coll_offset + sizeof (wchar_t));

	if (val < 0)
		return (-1);
	else
		return (val + 1);
}

/*
 * field_convert_alpha() always fails with return value -1 if the converted
 * string would cause l_collate_length to exceed l_collate_bufsize
 */
/*ARGSUSED*/
ssize_t
field_convert_alpha(field_t *F, line_rec_t *L, vchar_t delimiter,
    ssize_t data_offset, ssize_t data_length, ssize_t coll_offset)
{
	static char *compose;
	static ssize_t compose_length;

	ssize_t	clength = 0;
	ssize_t	dlength;
	ssize_t	i;

	if (compose_length < (data_length + 1)) {
		compose_length = data_length + 1;
		compose = safe_realloc(compose, compose_length * sizeof (char));
	}

	for (i = data_offset; i < data_offset + data_length; i++) {
		char t = (L->l_data.sp)[i];

		if ((F->f_options & FIELD_IGNORE_NONPRINTABLES) &&
		    !isprint((uchar_t)t))
			continue;

		if ((F->f_options & FIELD_DICTIONARY_ORDER) &&
		    !isalnum((uchar_t)t) && !isspace((uchar_t)t))
			continue;

		if (F->f_options & FIELD_FOLD_UPPERCASE)
			t = toupper(t);

		compose[clength++] = t;
	}
	compose[clength] = '\0';

	if ((dlength = xfrm_ops->sx_len(compose, clength)) <
	    L->l_collate_bufsize - coll_offset)
		return (xfrm_ops->sx_xfrm(L->l_collate.sp + coll_offset,
		    compose, dlength + 1));
	else
		return ((ssize_t)-1);
}

/*ARGSUSED*/
ssize_t
field_convert_alpha_simple(field_t *F, line_rec_t *L, vchar_t delimiter,
    ssize_t data_offset, ssize_t data_length, ssize_t coll_offset)
{
	static char *compose;
	static ssize_t compose_length;

	ssize_t	clength;
	ssize_t	dlength;

	if (compose_length < (data_length + 1)) {
		compose_length = data_length + 1;
		compose = safe_realloc(compose, compose_length * sizeof (char));
	}

	(void) memcpy(compose, L->l_data.sp + data_offset, data_length);
	clength = data_length;
	compose[clength] = '\0';

	if ((dlength = xfrm_ops->sx_len(compose, clength)) <
	    L->l_collate_bufsize - coll_offset)
		return (xfrm_ops->sx_xfrm(L->l_collate.sp + coll_offset,
		    compose, dlength + 1));
	else
		return ((ssize_t)-1);
}

/*ARGSUSED*/
ssize_t
field_convert_alpha_wide(field_t *F, line_rec_t *L, vchar_t delimiter,
    ssize_t data_offset, ssize_t data_length, ssize_t coll_offset)
{
	wchar_t	*compose = safe_realloc(NULL, (data_length + 1) *
	    sizeof (wchar_t));
	ssize_t	clength = 0;
	ssize_t	dlength;
	ssize_t	i;
	ssize_t ret;

	for (i = data_offset; i < data_offset + data_length; i++) {
		wchar_t	t = (L->l_data.wp)[i];

		if ((F->f_options & FIELD_IGNORE_NONPRINTABLES) && !iswprint(t))
			continue;

		if ((F->f_options & FIELD_DICTIONARY_ORDER) && !iswalnum(t) &&
		    !iswspace(t))
			continue;

		if (F->f_options & FIELD_FOLD_UPPERCASE)
			t = towupper(t);

		compose[clength++] = t;
	}
	compose[clength] = L'\0';

	dlength = wcsxfrm(NULL, compose, (size_t)0);
	if ((dlength * sizeof (wchar_t)) < L->l_collate_bufsize -
	    coll_offset * sizeof (wchar_t)) {
		ret = (ssize_t)wcsxfrm(L->l_collate.wp + coll_offset, compose,
		    (size_t)dlength + 1);
	} else {
		ret = (ssize_t)-1;
	}

	safe_free(compose);

	return (ret);
}

/*
 * field_convert_numeric() converts the given field into a collatable numerical
 * sequence.  The sequence is ordered as { log, integer, separator, fraction },
 * with an optional sentinel component at the sequence end.
 */
/*ARGSUSED*/
ssize_t
field_convert_numeric(field_t *F, line_rec_t *L, vchar_t delimiter,
    ssize_t data_offset, ssize_t data_length, ssize_t coll_offset)
{
	char *number;
	char *buffer = L->l_collate.sp + coll_offset;
	ssize_t length;

	char sign = '2';
	int log_ten;
	char *digits = buffer + 1 + sizeof (int) / sizeof (char);
	size_t j = 0;
	size_t i;

	int state = BEFORE_NUMBER;

	number = L->l_data.sp + data_offset;
	length = data_length;

	/*
	 * Eat leading blanks, if any.
	 */
	for (i = 0; i < length; i++)
		if (!IS_BLANK(number[i]))
			break;

	/*
	 * Test that there is sufficient size in the collation buffer for our
	 * number.  In addition to the possible remaining characters in the
	 * field, we also require space for the sign (char), logarithm (int),
	 * separator (char), and as many as two string terminators (for reverse
	 * sorts).
	 */
	if (((length - i) + 4 * sizeof (char) + sizeof (int)) >
	    (L->l_collate_bufsize - coll_offset))
		return ((ssize_t)-1);

	/*
	 * If negative, set sign.
	 */
	if (number[i] == '-') {
		i++;
		sign = '0';
	}

	/*
	 * Scan integer part; eat leading zeros.
	 */
	for (; i < length; i++) {
		if (IS_SEPARATOR(number[i]))
			continue;

		if (number[i] == '0' && !(state & IN_NUMBER))
			continue;

		if (!isdigit((uchar_t)number[i]))
			break;

		state |= IN_NUMBER;
		if (sign == '0')
			digits[j++] = '0' + '9' - number[i];
		else
			digits[j++] = number[i];
	}

	if (i < length && IS_DECIMAL(number[i])) {
		/*
		 * Integer part terminated by decimal.
		 */
		digits[j] = DECIMAL_CHAR;
		log_ten = j++;

		/*
		 * Scan fractional part.
		 */
		for (++i; i < length; i++) {
			if (IS_SEPARATOR(number[i]))
				continue;

			if (!isdigit((uchar_t)number[i]))
				break;

			if (number[i] != '0')
				state |= IN_NUMBER;

			if (sign == '0')
				digits[j++] = '0' + '9' - number[i];
			else
				digits[j++] = number[i];
		}

		if (sign == '0')
			digits[j++] = (char)(UCHAR_MAX - INTERFIELD_SEPARATOR);
	} else {
		/*
		 * Nondigit or end of string seen.
		 */
		log_ten = (int)j;
		if (sign == '0')
			digits[j++] = (char)(UCHAR_MAX - INTERFIELD_SEPARATOR);
		else
			digits[j] = INTERFIELD_SEPARATOR;
	}

	if ((state & IN_NUMBER) == 0) {
		/*
		 * A non-zero number was not detected; treat as defined zero.
		 */
		sign = '1';
		log_ten = 0;
		digits[0] = '0';
		j = 1;
	}

	/*
	 * We subtract a constant from the log of negative values so that
	 * they will correctly precede positive values with a zero logarithm.
	 */
	if (sign == '0') {
		if (j != 0)
			log_ten = -log_ten - 2;
		else
			/*
			 * Special case for -0.
			 */
			log_ten = -1;
	}

	buffer[0] = sign;

	/*
	 * Place logarithm in big-endian form.
	 */
	for (i = 0; i < sizeof (int); i++)
		buffer[i + 1] = (log_ten << (i * NBBY))
		    >> ((sizeof (int) - 1) * NBBY);

	if (j + sizeof (char) + sizeof (int) <
	    L->l_collate_bufsize - coll_offset)
		return (j + 1 + sizeof (int));
	else
		return ((ssize_t)-1);
}

/*ARGSUSED*/
ssize_t
field_convert_numeric_wide(field_t *F, line_rec_t *L, vchar_t delimiter,
    ssize_t data_offset, ssize_t data_length, ssize_t coll_offset)
{
	wchar_t *number;
	wchar_t *buffer = L->l_collate.wp + coll_offset;
	char *lbuffer;
	ssize_t length;

	wchar_t	sign = L'2';
	int log_ten;
	wchar_t	*digits = buffer + 1 + sizeof (int)/sizeof (wchar_t);
	size_t j = 0;
	size_t i;

	int state = BEFORE_NUMBER;

	number = L->l_data.wp + data_offset;
	length = data_length;

	for (i = 0; i < length; i++)
		if (!W_IS_BLANK(number[i]))
			break;

	if (((length - i) * sizeof (wchar_t) + 4 * sizeof (wchar_t) +
	    sizeof (int)) > (L->l_collate_bufsize - coll_offset))
		return ((ssize_t)-1);

	if (number[i] == L'-') {
		i++;
		sign = L'0';
	}

	for (; i < length; i++) {
		if (W_IS_SEPARATOR(number[i]))
			continue;

		if (number[i] == L'0' && !(state & IN_NUMBER))
			continue;

		if (!iswdigit(number[i]))
			break;

		state |= IN_NUMBER;
		if (sign == L'0')
			digits[j++] = L'0' + L'9' - number[i];
		else
			digits[j++] = number[i];
	}

	if (i < length && W_IS_DECIMAL(number[i])) {
		digits[j] = W_DECIMAL_CHAR;
		log_ten = j++;

		for (++i; i < length; i++) {
			if (W_IS_SEPARATOR(number[i]))
				continue;

			if (!iswdigit(number[i]))
				break;

			if (number[i] != L'0')
				state |= IN_NUMBER;

			if (sign == L'0')
				digits[j++] = L'0' + L'9' - number[i];
			else
				digits[j++] = number[i];
		}

		if (sign == L'0')
			digits[j++] = (wchar_t)(WCHAR_MAX -
			    W_INTERFIELD_SEPARATOR);
	} else {
		log_ten = (int)j;
		if (sign == L'0')
			digits[j++] = (wchar_t)(WCHAR_MAX -
			    W_INTERFIELD_SEPARATOR);
		else
			digits[j] = W_INTERFIELD_SEPARATOR;
	}

	if ((state & IN_NUMBER) == 0) {
		sign = L'1';
		log_ten = 0;
		digits[0] = L'0';
		j = 1;
	}

	if (sign == L'0') {
		if (j != 0)
			log_ten = -log_ten - 2;
		else
			log_ten = -1;
	}

	buffer[0] = sign;
	/*
	 * Place logarithm in big-endian form.
	 */
	lbuffer = (char *)(buffer + 1);
	for (i = 0; i < sizeof (int); i++)
		lbuffer[i] = (log_ten << (i * NBBY))
		    >> ((sizeof (int) - 1) * NBBY);

	if ((j + 1 + sizeof (int)/sizeof (wchar_t)) * sizeof (wchar_t) <
	    L->l_collate_bufsize - coll_offset * sizeof (wchar_t))
		return (j + 1 + sizeof (int) / sizeof (wchar_t));
	else
		return ((ssize_t)-1);
}

/*
 * flags contains one of CV_REALLOC, CV_FAIL, specifying the preferred behaviour
 * when coll_offset exceeds l_collate_bufsize.
 */
ssize_t
field_convert(field_t *F, line_rec_t *L, int flags, vchar_t field_separator)
{
	ssize_t coll_offset = 0;
	ssize_t	start, end, distance;
	field_t *cur_fieldp = F;

	while (cur_fieldp != NULL) {
		/*
		 * delimit field
		 */
		if (!field_separator.sc)
			field_delimit(cur_fieldp, L, &start, &end);
		else
			field_delimit_tabbed(cur_fieldp, L, &start, &end,
			    field_separator);

		distance = 0;
		if (end - start > 0 ||
		    (end - start == 0 && F->f_species == NUMERIC)) {
			/*
			 * Convert field, appending to collated field of line
			 * record.
			 */
			distance = cur_fieldp->f_convert(cur_fieldp, L,
			    field_separator, start, end - start, coll_offset);

			/*
			 * branch should execute comparatively rarely
			 */
			if (distance == -1) {
				if (flags & FCV_REALLOC) {
					ASSERT(L->l_collate_bufsize > 0);
					L->l_collate_bufsize *= 2;
					L->l_collate.sp =
					    safe_realloc(L->l_collate.sp,
					    L->l_collate_bufsize);

					__S(stats_incr_convert_reallocs());
					continue;
				} else {
					/*
					 * FCV_FAIL has been set.
					 */
					return (-1);
				}
			}
		}

		if (cur_fieldp->f_options & FIELD_REVERSE_COMPARISONS) {
			xstrninv(L->l_collate.sp, coll_offset, distance);
			*(L->l_collate.sp + coll_offset + distance) =
			    (char)(UCHAR_MAX - INTERFIELD_SEPARATOR);
			distance++;
		}

		ASSERT(distance >= 0);
		coll_offset += distance;
		if (coll_offset >= L->l_collate_bufsize) {
			if (flags & FCV_REALLOC) {
				ASSERT(L->l_collate_bufsize > 0);
				L->l_collate_bufsize *= 2;
				L->l_collate.sp = safe_realloc(L->l_collate.sp,
				    L->l_collate_bufsize);

				__S(stats_incr_convert_reallocs());
			} else {
				return (-1);
			}
		}
		*(L->l_collate.sp + coll_offset) = INTERFIELD_SEPARATOR;
		coll_offset++;

		cur_fieldp = cur_fieldp->f_next;
	}

	L->l_collate_length = coll_offset;

	return (L->l_collate_length);
}

ssize_t
field_convert_wide(field_t *F, line_rec_t *L, int flags,
    vchar_t field_separator)
{
	ssize_t coll_offset = 0;
	ssize_t	start, end, distance;
	field_t *cur_fieldp = F;

	while (cur_fieldp != NULL) {
		if (!field_separator.wc)
			field_delimit_wide(cur_fieldp, L, &start, &end);
		else
			field_delimit_tabbed_wide(cur_fieldp, L, &start, &end,
			    field_separator);

		distance = 0;
		if (end - start > 0 ||
		    end - start == 0 && F->f_species == NUMERIC) {
			distance = cur_fieldp->f_convert(cur_fieldp, L,
			    field_separator, start, end - start, coll_offset);

			if (distance == -1) {
				if (flags & FCV_REALLOC) {
					ASSERT(L->l_collate_bufsize > 0);
					L->l_collate_bufsize *= 2;
					L->l_collate.wp = safe_realloc(
					    L->l_collate.wp,
					    L->l_collate_bufsize);

					__S(stats_incr_convert_reallocs());
					continue;
				} else {
					return (-1);
				}
			}
		}

		if (cur_fieldp->f_options & FIELD_REVERSE_COMPARISONS) {
			xwcsninv(L->l_collate.wp, coll_offset, distance);
			*(L->l_collate.wp + coll_offset + distance) =
			    WCHAR_MAX - INTERFIELD_SEPARATOR;
			distance++;
		}

		ASSERT(distance >= 0);
		coll_offset += distance;
		if (coll_offset * sizeof (wchar_t) >= L->l_collate_bufsize) {
			if (flags & FCV_REALLOC) {
				ASSERT(L->l_collate_bufsize > 0);
				L->l_collate_bufsize *= 2;
				L->l_collate.wp = safe_realloc(L->l_collate.wp,
				    L->l_collate_bufsize);

				__S(stats_incr_convert_reallocs());
			} else {
				return (-1);
			}
		}
		*(L->l_collate.wp + coll_offset) = W_INTERFIELD_SEPARATOR;
		coll_offset++;

		cur_fieldp = cur_fieldp->f_next;
	}

	L->l_collate_length = coll_offset * sizeof (wchar_t);
#ifdef _LITTLE_ENDIAN
	xwcsntomsb(L->l_collate.wp, coll_offset);
#endif /* _LITTLE_ENDIAN */

	return (L->l_collate_length);
}

/*
 * line_convert() and line_convert_wide() are called when the collation vector
 * of a given line has been exhausted, and we are performing the final,
 * full-line comparison required by the sort specification.  Because we do not
 * have a guarantee that l_data is null-terminated, we create an explicitly
 * null-terminated copy suitable for transformation to a collatable form for the
 * current locale.
 */
static void
line_convert(line_rec_t *L)
{
	static ssize_t bufsize;
	static char *buffer;

	if (L->l_raw_collate.sp != NULL)
		return;

	if (L->l_data_length + 1 > bufsize) {
		buffer = safe_realloc(buffer, L->l_data_length + 1);
		bufsize = L->l_data_length + 1;
	}

	(void) strncpy(buffer, L->l_data.sp, L->l_data_length);
	buffer[L->l_data_length] = '\0';

	L->l_raw_collate.sp = safe_realloc(L->l_raw_collate.sp,
	    xfrm_ops->sx_len(buffer, L->l_data_length) + 1);
	xfrm_ops->sx_xfrm(L->l_raw_collate.sp, buffer,
	    xfrm_ops->sx_len(buffer, L->l_data_length) + 1);

	__S(stats_incr_line_conversions());
}

static void
line_convert_wide(line_rec_t *L)
{
	static wchar_t *buffer;
	static ssize_t bufsize;

	ssize_t dlength;

	if (L->l_raw_collate.wp != NULL)
		return;

	if (L->l_data_length + 1 > bufsize) {
		buffer = safe_realloc(buffer, (L->l_data_length + 1) *
		    sizeof (wchar_t));
		bufsize = L->l_data_length + 1;
	}

	(void) wcsncpy(buffer, L->l_data.wp, L->l_data_length);
	buffer[L->l_data_length] = L'\0';

	dlength = wcsxfrm(NULL, buffer, 0) + 1;
	L->l_raw_collate.wp = safe_realloc(L->l_raw_collate.wp, dlength *
	    sizeof (wchar_t));
	(void) wcsxfrm(L->l_raw_collate.wp, buffer, dlength);

	__S(stats_incr_line_conversions());
}

/*
 * Our convention for collation is
 *
 *	A > B  => r > 0,
 *	A == B => r = 0,
 *	A < B  => r < 0
 *
 * This convention is consistent with the definition of memcmp(), strcmp(), and
 * strncmp() in the C locale.  collated() and collated_wide() have two optional
 * behaviours, which can be activated by setting the appropriate values in
 * coll_flag:  COLL_UNIQUE, which returns 0 if the l_collate fields of the line
 * records being compared are identical; COLL_DATA_ONLY, which ignores the
 * l_collate field for the current comparison; and COLL_REVERSE, which flips the
 * result for comparisons that fall through to an actual data comparison (since
 * the collated vector should already reflect reverse ordering from field
 * conversion).
 */
int
collated(line_rec_t *A, line_rec_t *B, ssize_t depth, flag_t coll_flag)
{
	ssize_t ml = MIN(A->l_collate_length, B->l_collate_length) - depth;
	int r;
	int mask = (coll_flag & COLL_REVERSE) ? INT_SIGN_FLIP_MASK :
	    INT_SIGN_PASS_MASK;
	ssize_t la, lb;

	if (!(coll_flag & COLL_DATA_ONLY)) {
		if (ml > 0) {
			r = memcmp(A->l_collate.sp + depth,
			    B->l_collate.sp + depth, ml);

			if (r)
				return (r);
		}

		if (A->l_collate_length < B->l_collate_length)
			return (-1);

		if (A->l_collate_length > B->l_collate_length)
			return (1);
	}

	/*
	 * This is where we cut out, if we know that the current sort is over
	 * the entire line.
	 */
	if (coll_flag & COLL_UNIQUE)
		return (0);

	line_convert(A);
	line_convert(B);

	la = strlen(A->l_raw_collate.sp);
	lb = strlen(B->l_raw_collate.sp);

	r = memcmp(A->l_raw_collate.sp, B->l_raw_collate.sp, MIN(la, lb));

	if (r)
		return (r ^ mask);

	if (la < lb)
		return (-1 ^ mask);

	if (la > lb)
		return (1 ^ mask);

	return (0);
}

int
collated_wide(line_rec_t *A, line_rec_t *B, ssize_t depth, flag_t coll_flag)
{
	ssize_t ml = MIN(A->l_collate_length, B->l_collate_length) - depth;
	int r;
	int mask = (coll_flag & COLL_REVERSE) ? INT_SIGN_FLIP_MASK :
	    INT_SIGN_PASS_MASK;
	ssize_t la, lb;

	if (!(coll_flag & COLL_DATA_ONLY)) {
		if (ml > 0) {
			r = memcmp(A->l_collate.sp + depth,
			    B->l_collate.sp + depth, ml);

			if (r)
				return (r);
		}
		if (A->l_collate_length < B->l_collate_length)
			return (-1);

		if (A->l_collate_length > B->l_collate_length)
			return (1);
	}

	if (coll_flag & COLL_UNIQUE)
		return (0);

	line_convert_wide(A);
	line_convert_wide(B);

	la = wcslen(A->l_raw_collate.wp);
	lb = wcslen(B->l_raw_collate.wp);

	r = wmemcmp(A->l_raw_collate.wp, B->l_raw_collate.wp,
	    (size_t)MIN(la, lb));

	if (r)
		return (r ^ mask);

	if (la < lb)
		return (-1 ^ mask);

	if (la > lb)
		return (1 ^ mask);

	return (0);
}
