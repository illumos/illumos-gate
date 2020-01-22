/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1996-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>

#include "stabs.h"

static struct tdesc *hash_table[BUCKETS];
static struct tdesc *name_table[BUCKETS];

static void reset(void);
static jmp_buf	resetbuf;

static char *get_line(void);
static void parseline(char *cp);
static char *soudef(char *cp, enum type type, struct tdesc **rtdp);
static void enumdef(char *cp, struct tdesc **rtdp);
static int compute_sum(char *w);
static struct tdesc *lookup(int h);

static char *number(char *cp, int *n);
static char *name(char *cp, char **w);
static char *id(char *cp, int *h);
static char *offsize(char *cp, struct mlist *mlp);
static char *whitesp(char *cp);
static void addhash(struct tdesc *tdp, int num);
static void tagadd(char *w, int h, struct tdesc *tdp);
static void tagdecl(char *cp, struct tdesc **rtdp, int h, char *w);
static char *tdefdecl(char *cp, int h, struct tdesc **rtdp);
static char *intrinsic(char *cp, struct tdesc **rtdp);
static char *arraydef(char *cp, struct tdesc **rtdp);

static int line_number = 0;
static int debug_line  = 0;
static char linebuf[MAXLINE];

extern int debug_level;

static void
debug(int level, char *cp, char *fmt, ...)
{
	va_list ap;
	char buf[1024];
	char tmp[32];
	int i;

	if (level > debug_level)
		return;

	if (cp != NULL) {
		for (i = 0; i < 30; i++) {
			if (cp[i] == '\0')
				break;
			if (!iscntrl(cp[i]))
				tmp[i] = cp[i];
		}
		tmp[i] = '\0';
		(void) snprintf(buf, sizeof (buf), "%s [cp='%s']\n", fmt, tmp);
	} else {
		(void) snprintf(buf, sizeof (buf), "%s\n", fmt);
	}

	va_start(ap, fmt);
	(void) vfprintf(stderr, buf, ap);
	va_end(ap);
}


/* Report unexpected syntax in stabs. */
static void
expected(
	char *who,	/* what function, or part thereof, is reporting */
	char *what,	/* what was expected */
	char *where)	/* where we were in the line of input */
{
	fprintf(stderr, "%s, input line %d: expecting \"%s\" at \"%s\"\n",
	    who, line_number, what, where);
	exit(1);
}

/* Read a line from stdin into linebuf and increment line_number. */
static char *
get_line(void)
{
	char *cp = fgets(linebuf, MAXLINE, stdin);
	line_number++;

	/* For debugging, you can set debug_line to a line to stop on. */
	if (line_number == debug_line) {
		fprintf(stderr, "Hit debug line number %d\n", line_number);
		for (;;)
			(void) sleep(1);
	}
	return (cp);
}

/* Get the continuation of the current input line. */
static char *
get_continuation(void)
{
	char *cp = get_line();
	if (!cp) {
		fprintf(stderr, "expecting continuation line, "
		    "got end of input\n");
		exit(1);
	}

	/* Skip to the quoted stuff. */
	while (*cp++ != '"')
		;
	return (cp);
}

void
parse_input(void)
{
	char *cp;
	int i = 0;

	for (i = 0; i < BUCKETS; i++) {
		hash_table[i] = NULL;
		name_table[i] = NULL;
	}

	/*
	 * get a line at a time from the .s stabs file and parse.
	 */
	while ((cp = get_line()) != NULL)
		parseline(cp);
}

/*
 * Parse each line of the .s file (stabs entry) gather meaningful information
 * like name of type, size, offsets of fields etc.
 */
static void
parseline(char *cp)
{
	struct tdesc *tdp;
	char c, *w;
	int h, tagdef;

	/*
	 * setup for reset()
	 */
	if (setjmp(resetbuf))
		return;

	/*
	 * Look for lines of the form
	 *	.stabs	"str",n,n,n,n
	 * The part in '"' is then parsed.
	 */
	cp = whitesp(cp);
#define	STLEN	6
	debug(2, cp, "parseline");
	if (strncmp(cp, ".stabs", STLEN) != 0)
		reset();
	cp += STLEN;
#undef STLEN
	cp = whitesp(cp);
	if (*cp++ != '"')
		reset();

	/*
	 * name:type		variable (ignored)
	 * name:ttype		typedef
	 * name:Ttype		struct tag define
	 */
	cp = whitesp(cp);
	cp = name(cp, &w);

	tagdef = 0;
	switch (c = *cp++) {
	case 't': /* type */
		break;
	case 'T': /* struct, union, enum */
		tagdef = 1;
		break;
	default:
		reset();
	}

	/*
	 * The type id and definition follow.
	 */
	cp = id(cp, &h);
	if (*cp == '"') {
		struct tdesc *ntdp;

		cp++;
		ntdp = lookup(h);
		if (ntdp == NULL) {  /* if that type isn't defined yet */
			if (*cp++ != '=')  /* better be defining it now */
				expected("parseline/'0-9'", "=", cp - 1);
			cp = tdefdecl(cp, h, &tdp);
			addhash(tdp, h); /* for *(x,y) types */
		} else { /* that type is already defined */
			tdp = malloc(sizeof (*tdp));
			tdp->type = TYPEOF;
			tdp->name = (w != NULL) ? strdup(w) : NULL;
			tdp->data.tdesc = ntdp;
			addhash(tdp, h); /* for *(x,y) types */
			debug(3, NULL, "    %s defined as %s(%d)", w,
			    (ntdp->name != NULL) ? ntdp->name : "anon", h);
		}
		return;
	} else if (*cp++ != '=') {
		expected("parseline", "=", cp - 1);
	}
	if (tagdef) {
		tagdecl(cp, &tdp, h, w);
	} else {
		(void) tdefdecl(cp, h, &tdp);
		tagadd(w, h, tdp);
	}
}

/*
 * Check if we have this node in the hash table already
 */
static struct tdesc *
lookup(int h)
{
	int hash = HASH(h);
	struct tdesc *tdp = hash_table[hash];

	while (tdp != NULL) {
		if (tdp->id == h)
			return (tdp);
		tdp = tdp->hash;
	}
	return (NULL);
}

static char *
whitesp(char *cp)
{
	char *orig, c;

	orig = cp;
	for (c = *cp++; isspace(c); c = *cp++)
		;
	--cp;
	return (cp);
}

static char *
name(char *cp, char **w)
{
	char *new, *orig, c;
	int len;

	orig = cp;
	c = *cp++;
	if (c == ':')
		*w = NULL;
	else if (isalpha(c) || c == '_') {
		for (c = *cp++; isalnum(c) || c == ' ' || c == '_'; c = *cp++)
			;
		if (c != ':')
			reset();
		len = cp - orig;
		new = malloc(len);
		while (orig < cp - 1)
			*new++ = *orig++;
		*new = '\0';
		*w = new - (len - 1);
	} else
		reset();

	return (cp);
}

static char *
number(char *cp, int *n)
{
	char *next;

	*n = (int)strtol(cp, &next, 10);
	if (next == cp)
		expected("number", "<number>", cp);
	return (next);
}

static char *
id(char *cp, int *h)
{
	int n1, n2;

	if (*cp == '(') {	/* SunPro style */
		cp++;
		cp = number(cp, &n1);
		if (*cp++ != ',')
			expected("id", ",", cp - 1);
		cp = number(cp, &n2);
		if (*cp++ != ')')
			expected("id", ")", cp - 1);
		*h = n1 * 1000 + n2;
	} else if (isdigit(*cp)) { /* gcc style */
		cp = number(cp, &n1);
		*h = n1;
	} else {
		expected("id", "(/0-9", cp);
	}
	return (cp);
}

static void
tagadd(char *w, int h, struct tdesc *tdp)
{
	struct tdesc *otdp;

	tdp->name = w;
	if (!(otdp = lookup(h)))
		addhash(tdp, h);
	else if (otdp != tdp) {
		fprintf(stderr, "duplicate entry\n");
		fprintf(stderr, "old: %s %d %d %d\n",
		    otdp->name ? otdp->name : "NULL",
		    otdp->type, otdp->id / 1000, otdp->id % 1000);
		fprintf(stderr, "new: %s %d %d %d\n",
		    tdp->name ? tdp->name : "NULL",
		    tdp->type, tdp->id / 1000, tdp->id % 1000);
	}
}

static void
tagdecl(char *cp, struct tdesc **rtdp, int h, char *w)
{
	debug(1, NULL, "tagdecl: declaring '%s'", w ? w : "(anon)");
	if ((*rtdp = lookup(h)) != NULL) {
		if (w != NULL) {
			if ((*rtdp)->name != NULL &&
			    strcmp((*rtdp)->name, w) != 0) {
				struct tdesc *tdp;

				tdp = malloc(sizeof (*tdp));
				tdp->name = strdup(w);
				tdp->type = TYPEOF;
				tdp->data.tdesc = *rtdp;
				addhash(tdp, h); /* for *(x,y) types */
				debug(3, NULL, "    %s defined as %s(%d)", w,
				    ((*rtdp)->name != NULL) ?
				    (*rtdp)->name : "anon", h);
			} else if ((*rtdp)->name == NULL) {
				(*rtdp)->name = w;
				addhash(*rtdp, h);
			}
		}
	} else {
		*rtdp = malloc(sizeof (**rtdp));
		(*rtdp)->name = w;
		addhash(*rtdp, h);
	}

	switch (*cp++) {
	case 's':
		(void) soudef(cp, STRUCT, rtdp);
		break;
	case 'u':
		(void) soudef(cp, UNION, rtdp);
		break;
	case 'e':
		enumdef(cp, rtdp);
		break;
	default:
		expected("tagdecl", "<tag type s/u/e>", cp - 1);
		break;
	}
}

static char *
tdefdecl(char *cp, int h, struct tdesc **rtdp)
{
	struct tdesc *ntdp;
	char *w;
	int c, h2;
	char type;

	debug(3, cp, "tdefdecl h=%d", h);

	/* Type codes */
	switch (type = *cp) {
	case 'b': /* integer */
		c = *++cp;
		if (c != 's' && c != 'u')
			expected("tdefdecl/b", "[su]", cp - 1);
		c = *++cp;
		if (c == 'c')
			cp++;
		cp = intrinsic(cp, rtdp);
		break;
	case 'R': /* fp */
		/* skip up to and past ';' */
		while (*cp++ != ';')
			/* NULL */;
		cp = intrinsic(cp, rtdp);
		break;
	case '(': /* equiv to another type */
		cp = id(cp, &h2);
		ntdp = lookup(h2);
		if (ntdp == NULL) {  /* if that type isn't defined yet */
			if (*cp++ != '=')  /* better be defining it now */
				expected("tdefdecl/'('", "=", cp - 1);
			cp = tdefdecl(cp, h2, rtdp);
			ntdp = malloc(sizeof (*ntdp));
			ntdp->type = TYPEOF;
			ntdp->data.tdesc = *rtdp;
			addhash(ntdp, h2);
		} else { /* that type is already defined */
			*rtdp = malloc(sizeof (**rtdp));
			(*rtdp)->type = TYPEOF;
			(*rtdp)->data.tdesc = ntdp;
		}
		break;
	case '*':
		ntdp = NULL;
		cp = tdefdecl(cp + 1, h, &ntdp);
		if (ntdp == NULL)
			expected("tdefdecl/*", "id", cp);

		*rtdp = malloc(sizeof (**rtdp));
		(*rtdp)->type = POINTER;
		(*rtdp)->size = model->pointersize;
		(*rtdp)->name = "pointer";
		(*rtdp)->data.tdesc = ntdp;
		break;
	case 'f':
		cp = tdefdecl(cp + 1, h, &ntdp);
		*rtdp = malloc(sizeof (**rtdp));
		(*rtdp)->type = FUNCTION;
		(*rtdp)->size = model->pointersize;
		(*rtdp)->name = "function";
		(*rtdp)->data.tdesc = ntdp;
		break;
	case 'a':
		cp++;
		if (*cp++ != 'r')
			expected("tdefdecl/a", "r", cp - 1);
		*rtdp = malloc(sizeof (**rtdp));
		(*rtdp)->type = ARRAY;
		(*rtdp)->name = "array";
		cp = arraydef(cp, rtdp);
		break;
	case 'x':
		c = *++cp;
		if (c != 's' && c != 'u' && c != 'e')
			expected("tdefdecl/x", "[sue]", cp - 1);
		cp = name(cp + 1, &w);
		*rtdp = malloc(sizeof (**rtdp));
		(*rtdp)->type = FORWARD;
		(*rtdp)->name = w;
		break;
	case 'B': /* volatile */
		cp = tdefdecl(cp + 1, h, &ntdp);
		*rtdp = malloc(sizeof (**rtdp));
		(*rtdp)->type = VOLATILE;
		(*rtdp)->size = 0;
		(*rtdp)->name = "volatile";
		(*rtdp)->data.tdesc = ntdp;
		break;
	case 'k': /* const */
		cp = tdefdecl(cp + 1, h, &ntdp);
		*rtdp = malloc(sizeof (**rtdp));
		(*rtdp)->type = CONST;
		(*rtdp)->size = 0;
		(*rtdp)->name = "const";
		(*rtdp)->data.tdesc = ntdp;
		break;
	case '0': case '1': case '2': case '3':	case '4':
	case '5': case '6': case '7': case '8': case '9':
		/* gcc equiv to another type */
		cp = id(cp, &h2);
		ntdp = lookup(h2);
		if (ntdp == NULL) {  /* if that type isn't defined yet */
			/* better be defining it now */
			if (*cp++ != '=') {
				if (h != h2)
					expected("tdefdecl/'0-9'", "=", cp - 1);
				/* defined in terms of itself */
				*rtdp = malloc(sizeof (**rtdp));
				(*rtdp)->type = INTRINSIC;
				(*rtdp)->name = "void";
				(*rtdp)->size = 0;
			} else {
				cp = tdefdecl(cp, h2, rtdp);
				ntdp = malloc(sizeof (*ntdp));
				ntdp->type = TYPEOF;
				ntdp->data.tdesc = *rtdp;
				addhash(ntdp, h2);
			}
		} else { /* that type is already defined */
			*rtdp = malloc(sizeof (**rtdp));
			(*rtdp)->type = TYPEOF;
			(*rtdp)->data.tdesc = ntdp;
		}
		break;
	case 'u':
	case 's':
		cp++;

		*rtdp = malloc(sizeof (**rtdp));
		(*rtdp)->name = NULL;
		cp = soudef(cp, (type == 'u') ? UNION : STRUCT, rtdp);
		break;
	default:
		expected("tdefdecl", "<type code>", cp);
	}
	return (cp);
}

static char *
intrinsic(char *cp, struct tdesc **rtdp)
{
	struct tdesc *tdp;
	int size;

	cp = number(cp, &size);
	tdp = malloc(sizeof (*tdp));
	tdp->type = INTRINSIC;
	tdp->size = size;
	tdp->name = NULL;
	debug(3, NULL, "intrinsic: size=%ld", size);
	*rtdp = tdp;
	return (cp);
}

static char *
soudef(char *cp, enum type type, struct tdesc **rtdp)
{
	struct mlist **next_pp, *prev_p = NULL;
	char *w;
	int size;
	struct tdesc *tdp;

	cp = number(cp, &size);
	(*rtdp)->size = size;
	(*rtdp)->type = type; /* s or u */

	/*
	 * An '@' here indicates a bitmask follows.   This is so the
	 * compiler can pass information to debuggers about how structures
	 * are passed in the v9 world.  We don't need this information
	 * so we skip over it.
	 */
	if (cp[0] == '@')
		cp += 3;

	debug(3, cp, "soudef: %s size=%d",
	    (*rtdp)->name ? (*rtdp)->name : "(anonsou)",
	    (*rtdp)->size);

	next_pp = &((*rtdp)->data.members.forw); /* head for forward linklist */
	/* fill up the fields */
	while ((*cp != '"') && (*cp != ';')) { /* signifies end of fields */
		int h;
		struct mlist *mlp = malloc(sizeof (*mlp));

		mlp->prev = prev_p;	/* links for the backward list */
		prev_p = mlp;
		*next_pp = mlp;		/* links for the forward list */
		next_pp = &mlp->next;

		cp = name(cp, &w);
		mlp->name = w;
		cp = id(cp, &h);
		/*
		 * find the tdesc struct in the hash table for this type
		 * and stick a ptr in here
		 */
		tdp = lookup(h);
		if (tdp == NULL) { /* not in hash list */
			debug(3, NULL, "      defines %s (%d)", w, h);
			if (*cp++ != '=')
				expected("soudef", "=", cp - 1);
			cp = tdefdecl(cp, h, &tdp);
			addhash(tdp, h);
			debug(4, cp, "     soudef now looking at    ");
			cp++;

		} else {
			debug(3, NULL, "      refers to %s (%d, %s)",
			    w ? w : "anon", h, tdp->name ? tdp->name : "anon");
		}

		mlp->fdesc = tdp;
		cp = offsize(cp, mlp);	/* cp is now pointing to next field */
		if (*cp == '\\')	/* could be a continuation */
			cp = get_continuation();
	}
	(*rtdp)->data.members.back = prev_p;	/* head for backward linklist */
	return (cp);
}

static char *
offsize(char *cp, struct mlist *mlp)
{
	int offset, size;

	if (*cp == ',')
		cp++;
	cp = number(cp, &offset);
	if (*cp++ != ',')
		expected("offsize/2", ",", cp - 1);
	cp = number(cp, &size);
	if (*cp++ != ';')
		expected("offsize/3", ";", cp - 1);
	mlp->offset = offset;
	mlp->size = size;
	return (cp);
}

static char *
arraydef(char *cp, struct tdesc **rtdp)
{
	int h;
	int start, end;

	cp = id(cp, &h);
	if (*cp++ != ';')
		expected("arraydef/1", ";", cp - 1);

	(*rtdp)->data.ardef = malloc(sizeof (struct ardef));
	(*rtdp)->data.ardef->indices = malloc(sizeof (struct element));
	(*rtdp)->data.ardef->indices->index_type = lookup(h);

	cp = number(cp, &start); /* lower */
	if (*cp++ != ';')
		expected("arraydef/2", ";", cp - 1);
	cp = number(cp, &end);	/* upper */
	if (*cp++ != ';')
		expected("arraydef/3", ";", cp - 1);
	(*rtdp)->data.ardef->indices->range_start = start;
	(*rtdp)->data.ardef->indices->range_end = end;
#if 0
	if (isdigit(*cp)) {
		cp = number(cp, &contents_type); /* lower */
		tdp = lookup(contents_type);
		if (tdp != NULL) {
			(*rtdp)->data.ardef->contents = tdp;
		} else {
			if (*cp != '=')
				expected("arraydef/4", "=", cp);
			cp = tdefdecl(cp + 1, h, &tdp);
			addhash(tdp, h); /* for *(x,y) types */
			(*rtdp)->data.ardef->contents = tdp;
		}
	} /* else  */
#endif
	cp = tdefdecl(cp, h, &((*rtdp)->data.ardef->contents));
	return (cp);
}

static void
enumdef(char *cp, struct tdesc **rtdp)
{
	struct elist *elp, **prev;
	char *w;

	(*rtdp)->type = ENUM;
	(*rtdp)->data.emem = NULL;

	prev = &((*rtdp)->data.emem);
	while (*cp != ';') {
		elp = malloc(sizeof (*elp));
		elp->next = NULL;
		*prev = elp;
		cp = name(cp, &w);
		elp->name = w;
		cp = number(cp, &elp->number);
		debug(3, NULL, "enum %s: %s=%ld",
		    (*rtdp)->name ? (*rtdp)->name : "(anon enum)",
		    elp->name, elp->number);
		prev = &elp->next;
		if (*cp++ != ',')
			expected("enumdef", ",", cp - 1);
		if (*cp == '\\')
			cp = get_continuation();
	}
}

/*
 * Add a node to the hash queues.
 */
static void
addhash(struct tdesc *tdp, int num)
{
	int hash = HASH(num);
	struct tdesc *ttdp;
	char added_num = 0, added_name = 0;

	/*
	 * If it already exists in the hash table don't add it again
	 * (but still check to see if the name should be hashed).
	 */
	ttdp = lookup(num);
	if (ttdp == NULL) {
		tdp->id = num;
		tdp->hash = hash_table[hash];
		hash_table[hash] = tdp;
		added_num = 1;
	}

	if (tdp->name != NULL) {
		ttdp = lookupname(tdp->name);
		if (ttdp == NULL) {
			hash = compute_sum(tdp->name);
			tdp->next = name_table[hash];
			name_table[hash] = tdp;
			added_name = 1;
		}
	}
	if (!added_num && !added_name) {
		fprintf(stderr, "stabs: broken hash\n");
		exit(1);
	}
}

struct tdesc *
lookupname(char *name)
{
	int hash = compute_sum(name);
	struct tdesc *tdp, *ttdp = NULL;

	for (tdp = name_table[hash]; tdp != NULL; tdp = tdp->next) {
		if (tdp->name != NULL && strcmp(tdp->name, name) == 0) {
			if (tdp->type == STRUCT || tdp->type == UNION ||
			    tdp->type == ENUM || tdp->type == INTRINSIC)
				return (tdp);
			if (tdp->type == TYPEOF)
				ttdp = tdp;
		}
	}
	return (ttdp);
}

static int
compute_sum(char *w)
{
	char c;
	int sum;

	for (sum = 0; (c = *w) != '\0'; sum += c, w++)
		;
	return (HASH(sum));
}

static void
reset(void)
{
	longjmp(resetbuf, 1);
	/* NOTREACHED */
}
