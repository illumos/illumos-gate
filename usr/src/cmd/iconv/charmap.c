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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * CHARMAP file handling for iconv.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <alloca.h>
#include <sys/avl.h>
#include <stddef.h>
#include <unistd.h>
#include "charmap.h"
#include "parser.tab.h"
#include <assert.h>

enum cmap_pass cmap_pass;
static avl_tree_t	cmap_sym;
static avl_tree_t	cmap_mbs;

typedef struct charmap {
	const char *cm_name;
	struct charmap *cm_alias_of;
	avl_node_t cm_avl_sym;
	avl_node_t cm_avl_mbs;
	int cm_warned;
	int cm_frmbs_len;
	int cm_tombs_len;
	char cm_frmbs[MB_LEN_MAX + 1]; /* input */
	char cm_tombs[MB_LEN_MAX + 1]; /* output */
} charmap_t;

static void add_charmap_impl_fr(char *sym, char *mbs, int mbs_len, int nodups);
static void add_charmap_impl_to(char *sym, char *mbs, int mbs_len, int nodups);

/*
 * Array of POSIX specific portable characters.
 */
static const struct {
	char	*name;
	int	ch;
} portable_chars[] = {
	{ "NUL",		 '\0' },
	{ "alert",		'\a' },
	{ "backspace",		'\b' },
	{ "tab",		'\t' },
	{ "carriage-return",	'\r' },
	{ "newline",		'\n' },
	{ "vertical-tab",	'\v' },
	{ "form-feed",		'\f' },
	{ "space",		' ' },
	{ "exclamation-mark",	'!' },
	{ "quotation-mark",	'"' },
	{ "number-sign",	'#' },
	{ "dollar-sign",	'$' },
	{ "percent-sign",	'%' },
	{ "ampersand",		'&' },
	{ "apostrophe",		'\'' },
	{ "left-parenthesis",	'(' },
	{ "right-parenthesis",	'(' },
	{ "asterisk",		'*' },
	{ "plus-sign",		'+' },
	{ "comma",		 ','},
	{ "hyphen-minus",	'-' },
	{ "hyphen",		'-' },
	{ "full-stop",		'.' },
	{ "period",		'.' },
	{ "slash",		'/' },
	{ "solidus",		'/' },
	{ "zero",		'0' },
	{ "one",		'1' },
	{ "two",		'2' },
	{ "three",		'3' },
	{ "four",		'4' },
	{ "five",		'5' },
	{ "six",		'6' },
	{ "seven",		'7' },
	{ "eight",		'8' },
	{ "nine",		'9' },
	{ "colon",		':' },
	{ "semicolon",		';' },
	{ "less-than-sign",	'<' },
	{ "equals-sign",	'=' },
	{ "greater-than-sign",	'>' },
	{ "question-mark",	'?' },
	{ "commercial-at",	'@' },
	{ "left-square-bracket", '[' },
	{ "backslash",		'\\' },
	{ "reverse-solidus",	'\\' },
	{ "right-square-bracket", ']' },
	{ "circumflex",		'^' },
	{ "circumflex-accent",	'^' },
	{ "low-line",		'_' },
	{ "underscore",		'_' },
	{ "grave-accent",	'`' },
	{ "left-brace",		'{' },
	{ "left-curly-bracket",	'{' },
	{ "vertical-line",	'|' },
	{ "right-brace",	'}' },
	{ "right-curly-bracket", '}' },
	{ "tilde",		'~' },
	{ "A", 'A' },
	{ "B", 'B' },
	{ "C", 'C' },
	{ "D", 'D' },
	{ "E", 'E' },
	{ "F", 'F' },
	{ "G", 'G' },
	{ "H", 'H' },
	{ "I", 'I' },
	{ "J", 'J' },
	{ "K", 'K' },
	{ "L", 'L' },
	{ "M", 'M' },
	{ "N", 'N' },
	{ "O", 'O' },
	{ "P", 'P' },
	{ "Q", 'Q' },
	{ "R", 'R' },
	{ "S", 'S' },
	{ "T", 'T' },
	{ "U", 'U' },
	{ "V", 'V' },
	{ "W", 'W' },
	{ "X", 'X' },
	{ "Y", 'Y' },
	{ "Z", 'Z' },
	{ "a", 'a' },
	{ "b", 'b' },
	{ "c", 'c' },
	{ "d", 'd' },
	{ "e", 'e' },
	{ "f", 'f' },
	{ "g", 'g' },
	{ "h", 'h' },
	{ "i", 'i' },
	{ "j", 'j' },
	{ "k", 'k' },
	{ "l", 'l' },
	{ "m", 'm' },
	{ "n", 'n' },
	{ "o", 'o' },
	{ "p", 'p' },
	{ "q", 'q' },
	{ "r", 'r' },
	{ "s", 's' },
	{ "t", 't' },
	{ "u", 'u' },
	{ "v", 'v' },
	{ "w", 'w' },
	{ "x", 'x' },
	{ "y", 'y' },
	{ "z", 'z' },
	{ NULL, 0 }
};

static int
cmap_compare_sym(const void *n1, const void *n2)
{
	const charmap_t *c1 = n1;
	const charmap_t *c2 = n2;
	int rv;

	rv = strcmp(c1->cm_name, c2->cm_name);
	return ((rv < 0) ? -1 : (rv > 0) ? 1 : 0);
}

/*
 * In order for partial match searches to work,
 * we need these sorted by mbs contents.
 */
static int
cmap_compare_mbs(const void *n1, const void *n2)
{
	const charmap_t *c1 = n1;
	const charmap_t *c2 = n2;
	int len, rv;

	len = c1->cm_frmbs_len;
	if (len < c2->cm_frmbs_len)
		len = c2->cm_frmbs_len;
	rv = memcmp(c1->cm_frmbs, c2->cm_frmbs, len);
	if (rv < 0)
		return (-1);
	if (rv > 0)
		return (1);
	/* they match through length */
	if (c1->cm_frmbs_len < c2->cm_frmbs_len)
		return (-1);
	if (c2->cm_frmbs_len < c1->cm_frmbs_len)
		return (1);
	return (0);
}

void
charmap_init(char *to_map, char *from_map)
{
	avl_create(&cmap_sym, cmap_compare_sym, sizeof (charmap_t),
	    offsetof(charmap_t, cm_avl_sym));

	avl_create(&cmap_mbs, cmap_compare_mbs, sizeof (charmap_t),
	    offsetof(charmap_t, cm_avl_mbs));

	cmap_pass = CMAP_PASS_FROM;
	reset_scanner(from_map);
	(void) yyparse();
	add_charmap_posix();

	cmap_pass = CMAP_PASS_TO;
	reset_scanner(to_map);
	(void) yyparse();
}

void
charmap_dump()
{
	charmap_t *cm;
	int i;

	cm = avl_first(&cmap_mbs);
	while (cm != NULL) {
		(void) printf("name=\"%s\"\n", cm->cm_name);

		(void) printf("\timbs=\"");
		for (i = 0; i < cm->cm_frmbs_len; i++)
			(void) printf("\\x%02x", cm->cm_frmbs[i] & 0xFF);
		(void) printf("\"\n");

		(void) printf("\tombs=\"");
		for (i = 0; i < cm->cm_tombs_len; i++)
			(void) printf("\\x%02x", cm->cm_tombs[i] & 0xFF);
		(void) printf("\"\n");

		cm = AVL_NEXT(&cmap_mbs, cm);
	}
}

/*
 * We parse two charmap files:  First the "from" map, where we build
 * cmap_mbs and cmap_sym which we'll later use to translate the input
 * stream (mbs encodings) to symbols.  Second, we parse the "to" map,
 * where we fill in the tombs members of entries in cmap_sym, (which
 * must alread exist) used later to write the output encoding.
 */
static void
add_charmap_impl(char *sym, char *mbs, int mbs_len, int nodups)
{

	/*
	 * While parsing both the "from" and "to" cmaps,
	 * require both the symbol and encoding.
	 */
	if (sym == NULL || mbs == NULL) {
		errf(_("invalid charmap entry"));
		return;
	}

	switch (cmap_pass) {
	case CMAP_PASS_FROM:
		add_charmap_impl_fr(sym, mbs, mbs_len, nodups);
		break;
	case CMAP_PASS_TO:
		add_charmap_impl_to(sym, mbs, mbs_len, nodups);
		break;
	default:
		abort();
		break;
	}
}

static void
add_charmap_impl_fr(char *sym, char *mbs, int mbs_len, int nodups)
{
	charmap_t	*m, *n, *s;
	avl_index_t	where_sym, where_mbs;

	if ((n = calloc(1, sizeof (*n))) == NULL) {
		errf(_("out of memory"));
		return;
	}
	n->cm_name = sym;

	assert(0 < mbs_len && mbs_len <= MB_LEN_MAX);
	(void) memcpy(n->cm_frmbs, mbs, mbs_len);
	n->cm_frmbs_len = mbs_len;

	m = avl_find(&cmap_mbs, n, &where_mbs);
	s = avl_find(&cmap_sym, n, &where_sym);

	/*
	 * If we found the symbol, this is a dup.
	 */
	if (s != NULL) {
		if (nodups) {
			warn(_("%s: duplicate character symbol"), sym);
		}
		free(n);
		return;
	}

	/*
	 * If we found the mbs, the new one is an alias,
	 * which we'll add _only_ to the symbol AVL.
	 */
	if (m != NULL) {
		/* The new one is an alias of the original. */
		n->cm_alias_of = m;
		avl_insert(&cmap_sym, n, where_sym);
		return;
	}

	avl_insert(&cmap_sym, n, where_sym);
	avl_insert(&cmap_mbs, n, where_mbs);
}

static void
add_charmap_impl_to(char *sym, char *mbs, int mbs_len, int nodups)
{
	charmap_t	srch = {0};
	charmap_t	*m;

	assert(0 < mbs_len && mbs_len <= MB_LEN_MAX);

	srch.cm_name = sym;

	m = avl_find(&cmap_sym, &srch, NULL);
	if (m == NULL) {
		if (sflag == 0)
			warn(_("%s: symbol not found"), sym);
		return;
	}
	if (m->cm_alias_of != NULL) {
		m = m->cm_alias_of;

		/* don't warn for dups with aliases */
		if (m->cm_tombs_len != 0)
			return;
	}

	if (m->cm_tombs_len != 0) {
		if (nodups) {
			warn(_("%s: duplicate encoding for"), sym);
		}
		return;
	}

	(void) memcpy(m->cm_tombs, mbs, mbs_len);
	m->cm_tombs_len = mbs_len;
}

void
add_charmap(char *sym, char *mbs)
{
	/* mbs[0] is the length */
	int mbs_len = *mbs++;
	assert(0 < mbs_len && mbs_len <= MB_LEN_MAX);
	add_charmap_impl(sym, mbs, mbs_len, 1);
}


/*
 * This is called by the parser with start/end symbol strings (ssym, esym),
 * which are allocated in the scanner (T_SYMBOL) and free'd here.
 */
void
add_charmap_range(char *ssym, char *esym, char *mbs)
{
	int	ls, le;
	int	si;
	int	sn, en;
	int	i;
	int	mbs_len;
	char	tmbs[MB_LEN_MAX+1];
	char	*mb_last;

	static const char *digits = "0123456789";

	/* mbs[0] is the length */
	mbs_len = *mbs++;
	assert(0 < mbs_len && mbs_len <= MB_LEN_MAX);
	(void) memcpy(tmbs, mbs, mbs_len);
	mb_last = tmbs + mbs_len - 1;

	ls = strlen(ssym);
	le = strlen(esym);

	if (((si = strcspn(ssym, digits)) == 0) || (si == ls) ||
	    (strncmp(ssym, esym, si) != 0) ||
	    (strspn(ssym + si, digits) != (ls - si)) ||
	    (strspn(esym + si, digits) != (le - si)) ||
	    ((sn = atoi(ssym + si)) > ((en = atoi(esym + si))))) {
		errf(_("malformed charmap range"));
		return;
	}

	ssym[si] = 0;
	for (i = sn; i <= en; i++) {
		char *nn;
		(void) asprintf(&nn, "%s%0*u", ssym, ls - si, i);
		if (nn == NULL) {
			errf(_("out of memory"));
			return;
		}

		add_charmap_impl(nn, tmbs, mbs_len, 1);
		(*mb_last)++;
	}
	free(ssym);
	free(esym);
}

void
add_charmap_char(char *name, int c)
{
	char mbs[MB_LEN_MAX+1];

	mbs[0] = c;
	mbs[1] = '\0';
	add_charmap_impl(name, mbs, 1, 0);
}

/*
 * POSIX insists that certain entries be present, even when not in the
 * orginal charmap file.
 */
void
add_charmap_posix(void)
{
	int	i;

	for (i = 0; portable_chars[i].name; i++) {
		add_charmap_char(portable_chars[i].name, portable_chars[i].ch);
	}
}

/*
 * This is called with a buffer of (typically) MB_LEN_MAX bytes,
 * which is potentially a multi-byte symbol, but often contains
 * extra bytes. Find and return the longest match in the charmap.
 */
static charmap_t *
find_mbs(const char *mbs, int len)
{
	charmap_t srch = {0};
	charmap_t *cm = NULL;

	while (len > 0) {
		(void) memcpy(srch.cm_frmbs, mbs, len);
		srch.cm_frmbs_len = len;
		cm = avl_find(&cmap_mbs, &srch, NULL);
		if (cm != NULL)
			break;
		len--;
	}

	return (cm);
}

/*
 * Return true if this sequence matches the initial part
 * of any sequence known in this charmap.
 */
static boolean_t
find_mbs_partial(const char *mbs, int len)
{
	charmap_t srch = {0};
	charmap_t *cm;
	avl_index_t where;

	(void) memcpy(srch.cm_frmbs, mbs, len);
	srch.cm_frmbs_len = len;
	cm = avl_find(&cmap_mbs, &srch, &where);
	if (cm != NULL) {
		/* full match - not expected, but OK */
		return (B_TRUE);
	}
	cm = avl_nearest(&cmap_mbs, where, AVL_AFTER);
	if (cm != NULL && 0 == memcmp(cm->cm_frmbs, mbs, len))
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * Do like iconv(3), but with charmaps.
 */
size_t
cm_iconv(const char **iptr, size_t *ileft, char **optr, size_t *oleft)
{
	charmap_t *cm;
	int mbs_len;

	/* Ignore state reset requests. */
	if (iptr == NULL || *iptr == NULL)
		return (0);

	if (*oleft < MB_LEN_MAX) {
		errno = E2BIG;
		return ((size_t)-1);
	}

	while (*ileft > 0 && *oleft >= MB_LEN_MAX) {
		mbs_len = MB_LEN_MAX;
		if (mbs_len > *ileft)
			mbs_len = *ileft;
		cm = find_mbs(*iptr, mbs_len);
		if (cm == NULL) {
			if (mbs_len < MB_LEN_MAX &&
			    find_mbs_partial(*iptr, mbs_len)) {
				/* incomplete sequence */
				errno = EINVAL;
			} else {
				errno = EILSEQ;
			}
			return ((size_t)-1);
		}
		assert(cm->cm_frmbs_len > 0);
		if (cm->cm_tombs_len == 0) {
			if (sflag == 0 && cm->cm_warned == 0) {
				cm->cm_warned = 1;
				warn(_("To-map does not encode <%s>\n"),
				    cm->cm_name);
			}
			if (cflag == 0) {
				errno = EILSEQ;
				return ((size_t)-1);
			}
			/* just skip this input seq. */
			*iptr  += cm->cm_frmbs_len;
			*ileft -= cm->cm_frmbs_len;
			continue;
		}

		*iptr  += cm->cm_frmbs_len;
		*ileft -= cm->cm_frmbs_len;
		(void) memcpy(*optr, cm->cm_tombs, cm->cm_tombs_len);
		*optr  += cm->cm_tombs_len;
		*oleft -= cm->cm_tombs_len;
	}

	return (0);
}
