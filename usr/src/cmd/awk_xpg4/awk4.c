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
 * awk -- functions
 *
 * Copyright (c) 1995, 1996 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Copyright 1986, 1994 by Mortice Kern Systems Inc.  All rights reserved.
 *
 * Based on MKS awk(1) ported to be /usr/xpg4/bin/awk with POSIX/XCU4 changes
 */

#include "awk.h"
#include "y.tab.h"
#include <time.h>
#include <sys/wait.h>

static uint	nargs(NODE *np);
static NODE	*dosub(NODE *np, int glob);
static NODE	*docasetr(NODE *np, int upper);
static int	asortcmp(const void *npp1, const void *npp2);

static char	nargerr[] = "wrong number of arguments to function \"%s\"";
static NODE	*asortfunc;		/* Function call for asort() */
static NODE	*asnp1, *asnp2;		/* index1, index2 nodes */
static int	asarraylen;		/* strlen(array)+1 for asort */

/*
 * Return the value of exp(x).
 * Usage:	y = exp(x)
 *		y = exp()
 */
NODE *
f_exp(NODE *np)
{
	register uint na;

	if ((na = nargs(np)) > 1)
		awkerr(nargerr, s_exp);
	return (realnode(exp(exprreal(na==0 ? field0 : getlist(&np)))));
}

/*
 * Return the integer part of the argument.
 * Usage:	i = int(r)
 *		i = int()
 */
NODE *
f_int(NODE *np)
{
	register uint na;

	if ((na = nargs(np)) > 1)
		awkerr(nargerr, s_int);
	return (intnode(exprint(na==0 ? field0 : getlist(&np))));
}

/*
 * Logarithm function.
 * Usage:	y = log(x)
 *		y = log()
 */
NODE *
f_log(NODE *np)
{
	register uint na;

	if ((na = nargs(np)) > 1)
		awkerr(nargerr, s_log);
	return (realnode(log(exprreal(na==0 ? field0 : getlist(&np)))));
}

/*
 * Square root function.
 * Usage:	y = sqrt(x)
 *		y = sqrt()
 */
NODE *
f_sqrt(NODE *np)
{
	register uint na;

	if ((na = nargs(np)) > 1)
		awkerr(nargerr, s_sqrt);
	return (realnode(sqrt(exprreal(na==0 ? field0 : getlist(&np)))));
}

/*
 * Trigonometric sine function.
 * Usage:	y = sin(x)
 */
NODE *
f_sin(NODE *np)
{
	if (nargs(np) != 1)
		awkerr(nargerr, s_sin);
	return (realnode(sin(exprreal(getlist(&np)))));
}

/*
 * Trigonometric cosine function.
 * Usage:	y = cos(x)
 */
NODE *
f_cos(NODE *np)
{
	if (nargs(np) != 1)
		awkerr(nargerr, s_cos);
	return (realnode(cos(exprreal(getlist(&np)))));
}

/*
 * Arctangent of y/x.
 * Usage:	z = atan2(y, x)
 */
NODE *
f_atan2(NODE *np)
{
	double y, x;

	if (nargs(np) != 2)
		awkerr(nargerr, s_atan2);
	y = (double)exprreal(getlist(&np));
	x = (double)exprreal(getlist(&np));
	return (realnode(atan2(y, x)));
}

/*
 * Set the seed for the random number generator function -- rand.
 * Usage:	srand(x)
 *		srand()
 */
NODE *
f_srand(NODE *np)
{
	register uint na;
	register uint seed;
	static uint oldseed = 0;

	if ((na = nargs(np)) > 1)
		awkerr(nargerr, s_srand);
	if (na == 0)
		seed = (uint)time((time_t *)0); else
		seed = (uint)exprint(getlist(&np));
	srand(seed);
	na = oldseed;
	oldseed = seed;
	return (intnode((INT)na));
}

/*
 * Generate a random number.
 * Usage:	x = rand()
 */
NODE *
f_rand(NODE *np)
{
	double result;
	int expon;
	ushort rint;

	if (nargs(np) != 0)
		awkerr(nargerr, s_rand);
	rint = rand() & SHRT_MAX;
	result = frexp((double)rint, &expon);
	return (realnode((REAL)ldexp(result, expon-15)));
}

/*
 * Substitute function.
 * Usage:	n = sub(regex, replace, target)
 *		n = sub(regex, replace)
 */
NODE *
f_sub(NODE *np)
{
	return (dosub(np, 1));
}

/*
 * Global substitution function.
 * Usage:	n = gsub(regex, replace, target)
 *		n = gsub(regex, replace)
 */
NODE *
f_gsub(NODE *np)
{
	return (dosub(np, 0));
}

/*
 * Do actual substitutions.
 * `glob' is the number to substitute, 0 for all.
 */
static NODE *
dosub(NODE *np, int glob)
{
	wchar_t *text;
	register wchar_t *sub;
	register uint n;
	register uint na;
	register REGEXP rp;
	NODE *left;
	static wchar_t *buf;

	if ((na = nargs(np)) != 2 && na != 3)
		awkerr(nargerr, glob==0 ? s_gsub : s_sub);
	rp = getregexp(getlist(&np));
	sub = exprstring(getlist(&np));
	if (na == 3) {
		left = getlist(&np);
		text = exprstring(left);
	} else {
		left = field0;
		text = linebuf;
	}
	switch (REGWDOSUBA(rp, sub, text, &buf, 256, &glob)) {
	case REG_OK:
	case REG_NOMATCH:
		n = glob;
		break;
	case REG_ESPACE:
		if (buf != NULL)
			free(buf);
		awkerr(nomem);
	default:
		awkerr(gettext("regular expression error"));
	}
	(void)assign(left, stringnode(buf, FNOALLOC, wcslen(buf)));
	return (intnode((INT)n));
}

/*
 * Match function.  Return position (origin 1) or 0 for regular
 * expression match in string.  Set new variables RSTART and RLENGTH
 * as well.
 * Usage:	pos = match(string, re)
 */
NODE *
f_match(NODE *np)
{
	register wchar_t *text;
	register REGEXP rp;
	register int pos, length;
	REGWMATCH_T match[10];

	if (nargs(np) != 2)
		awkerr(nargerr, s_match);
	text = exprstring(getlist(&np));
	rp = getregexp(getlist(&np));
	if (REGWEXEC(rp, text, 10, match, 0) == REG_OK) {
		pos = match[0].rm_sp-text+1;
		length = match[0].rm_ep - match[0].rm_sp;
	} else {
		pos = 0;
		length = -1;
	}
	constant->n_int = length;
	(void)assign(vlook(M_MB_L("RLENGTH")), constant);
	return (assign(vlook(M_MB_L("RSTART")), intnode((INT)pos)));
}

/*
 * Call shell or command interpreter.
 * Usage:	status = system(command)
 */
NODE *
f_system(NODE *np)
{
	int retcode;

	if (nargs(np) != 1)
		awkerr(nargerr, s_system);
	(void) fflush(stdout);
	retcode = system(mbunconvert(exprstring(getlist(&np))));
	return (intnode((INT)WEXITSTATUS(retcode)));
}

/*
 * Search for string within string.
 * Usage:	pos = index(string1, string2)
 */
NODE *
f_index(NODE *np)
{
	register wchar_t *s1, *s2;
	register int l1, l2;
	register int result;

	if (nargs(np) != 2)
		awkerr(nargerr, s_index);
	s1 = (wchar_t *)exprstring(getlist(&np));
	s2 = (wchar_t *)exprstring(getlist(&np));
	l1 = wcslen(s1);
	l2 = wcslen(s2);
	result = 1;
	while (l2 <= l1) {
		if (memcmp(s1, s2, l2 * sizeof(wchar_t)) == 0)
			break;
		result++;
		s1++;
		l1--;
	}
	if (l2 > l1)
		result = 0;
	return (intnode((INT)result));
}

/*
 * Return length of argument or $0
 * Usage:	n = length(string)
 *		n = length()
 *		n = length
 */
NODE *
f_length(NODE *np)
{
	register uint na;

	if ((na = nargs(np)) > 1)
		awkerr(nargerr, s_length);
	if (na == 0)
		na = lbuflen; else
		na = wcslen((wchar_t *)exprstring(getlist(&np)));
	return (intnode((INT)na));
}

/*
 * Split string into fields.
 * Usage: nfields = split(string, array [, separator]);
 */
NODE *
f_split(NODE *np)
{
	register wchar_t *cp;
	wchar_t *ep, *saved = 0;
	register NODE *tnp, *snp, *otnp;
	register NODE *sep;
	REGEXP old_resep = 0;
	size_t seplen;
	uint n;
	wint_t c;
	wchar_t savesep[20];
	wchar_t  *(*old_awkfield)(wchar_t **) = 0;

	if ((n = nargs(np))<2 || n>3)
		awkerr(nargerr, s_split);
	ep = exprstring(snp = getlist(&np));
	tnp = getlist(&np);
	if (snp->n_type == INDEX && snp->n_left == tnp)
		ep = saved = wsdup(ep);
	if (n == 3) {
		sep = getlist(&np);
	} else
		sep = NNULL;
	switch (tnp->n_type) {
	case ARRAY:
		delarray(tnp);
		break;

	case PARM:
		break;

	case VAR:
		if (isstring(tnp->n_flags) && tnp->n_string==_null)
			break;
		/* FALLTHROUGH */

	default:
		awkerr(gettext(
			"second parameter to \"split\" must be an array"));
	}
	/*
	 * If an argument has been passed in to be used as the
	 * field separator check to see if it is a constant regular
	 * expression. If so, use it directly otherwise reduce the
	 * expression, convert the result into a string and assign it
	 * to "FS" (after saving the old value for FS.)
	 */
	if (sep != NNULL) {
		if (sep->n_type == PARM)
			sep = sep->n_next;
		if (sep->n_type == RE) {
			old_resep = resep;
			resep = sep->n_regexp;
			old_awkfield = awkfield;
			awkfield = refield;
		} else {
			sep = exprreduce(sep);
			seplen = wcslen(cp = (wchar_t *)exprstring(varFS));
			(void) memcpy(savesep, cp, 
				(seplen+1) * sizeof(wchar_t));
			(void) assign(varFS, sep);
		}
	}
	/*
	 * Iterate over the record, extracting each field and assigning it to
	 * the corresponding element in the array.
	 */
	otnp = tnp;	/* save tnp for possible promotion */
	tnp = node(INDEX, tnp, constant);
	fcount = 0;
	for (;;) {
		if ((cp = (*awkfield)(&ep)) == NULL) {
			if (fcount == 0) {
				if (otnp->n_type == PARM)
					otnp = otnp->n_next;
				promote(otnp);
			}
			break;
		}
		c = *ep;
		*ep = '\0';
		constant->n_int = ++fcount;
		(void)assign(tnp, stringnode(cp,FALLOC|FSENSE,(size_t)(ep-cp)));
		*ep = c;
	}
	/*
	 * Restore the old record separator/and or regular expression.
	 */
	if (sep != NNULL) {
		if (old_awkfield != 0) {
			resep = old_resep;
			awkfield = old_awkfield;
		} else {
			(void)assign(varFS,
				stringnode(savesep, FSTATIC, seplen));
		}
	}
	if (saved)
		free(saved);
	return (intnode((INT)fcount));
}

/*
 * Sprintf function.
 * Usage:	string = sprintf(format, arg, ...)
 */
NODE *
f_sprintf(NODE *np)
{
        wchar_t *cp;
        size_t length;

        if (nargs(np) == 0)
                awkerr(nargerr, s_sprintf);
        length = xprintf(np, (FILE *)NULL, &cp);
        np = stringnode(cp, FNOALLOC, length);
        return (np);
}

/*
 * Substring.
 * newstring = substr(string, start, [length])
 */
NODE *
f_substr(NODE *np)
{
	register STRING str;
	register size_t n;
	register int start;
	register size_t len;

	if ((n = nargs(np))<2 || n>3)
		awkerr(nargerr, s_substr);
	str = exprstring(getlist(&np));
	if ((start = (int)exprint(getlist(&np))-1) < 0)
		start = 0;
	if (n == 3) {
		int x;
		x = (int)exprint(getlist(&np));
		if (x < 0)
			len = 0;
		else
			len = (size_t)x;
	} else
		len = LARGE;
	n = wcslen((wchar_t *)str);
	if (start > n)
		start = n;
	n -= start;
	if (len > n)
		len = n;
	str += start;
	n = str[len];
	str[len] = '\0';
	np = stringnode(str, FALLOC, len);
	str[len] = n;
	return (np);
}

/*
 * Close an output or input file stream.
 */
NODE *
f_close(NODE *np)
{
	register OFILE *op;
	register char *name;

	if (nargs(np) != 1)
		awkerr(nargerr, s_close);
	name = mbunconvert(exprstring(getlist(&np)));
	for (op = &ofiles[0]; op < &ofiles[NIOSTREAM]; op++)
		if (op->f_fp!=FNULL && strcmp(name, op->f_name)==0) {
			awkclose(op);
			break;
		}
	if (op >= &ofiles[NIOSTREAM])
		return (const1);
	return (const0);
}

/*
 * Return the integer value of the first character of a string.
 * Usage:	char = ord(string)
 */
NODE *
f_ord(NODE *np)
{
	if (nargs(np) != 1)
		awkerr(nargerr, s_ord);
	return (intnode((INT)*exprstring(getlist(&np))));
}

/*
 * Return the argument string in lower case:
 * Usage:
 *	lower = tolower(upper)
 */
NODE *
f_tolower(NODE *np)
{
	return (docasetr(np, 0));
}

/*
 * Return the argument string in upper case:
 * Usage:
 *	upper = toupper(lower)
 */
NODE *
f_toupper(NODE *np)
{
	return (docasetr(np, 1));
}

/*
 * Sort the array into traversal order by the next "for (i in array)" loop.
 * Usage:
 *	asort(array, "cmpfunc")
 * 	cmpfunc(array, index1, index2)
 *		returns:
 *		<0		if 	array[index1] <  array[index2]
 *		 0		if	array[index1] == array[index2]
 *		>0		if	array[index1] >  array[index2]
 */
NODE *
f_asort(NODE *np)
{
	NODE *array;
	STRING funcname;
	register size_t nel;
	register NODE *tnp;
	register NODE *funcnp;
	register NODE **alist, **npp;

	if (nargs(np) != 2)
		awkerr(nargerr, s_asort);
	array = getlist(&np);
	if (array->n_type == PARM)
		array = array->n_next;
	if (array->n_type != ARRAY)
		awkerr(gettext("%s function requires an array"),
			s_asort);
	funcname = exprstring(getlist(&np));
	if ((funcnp = vlookup(funcname, 1)) == NNULL
	 || funcnp->n_type != UFUNC)
		awkerr(gettext("%s: %s is not a function\n"),
		    s_asort, funcname);
	/*
	 * Count size of array, allowing one extra for NULL at end
	 */
	nel = 1;
	for (tnp = array->n_alink; tnp != NNULL; tnp = tnp->n_alink)
		++nel;
	/*
	 * Create UFUNC node that points at the funcnp on left and the
	 * list of three variables on right (array, index1, index2)
	 *				UFUNC
	 *				/    \
	 *			   funcnp    COMMA
	 *				      /   \
	 *				array	  COMMA
	 *					  /    \
	 *					index1 index2
	 */
	if (asortfunc == NNULL) {
		running = 0;
		asortfunc = node(CALLUFUNC, NNULL,
				    node(COMMA, NNULL,
				    node(COMMA,
					asnp1=stringnode(_null, FSTATIC, 0),
					asnp2=stringnode(_null, FSTATIC, 0))));
		running = 1;
	}
	asortfunc->n_left = funcnp;
	asortfunc->n_right->n_left = array;
	asarraylen = wcslen(array->n_name)+1;
	alist = (NODE **) emalloc(nel*sizeof(NODE *));
	/*
	 * Copy array into alist.
	 */
	npp = alist;
	for (tnp = array->n_alink; tnp != NNULL; tnp = tnp->n_alink)
		*npp++ = tnp;
	*npp = NNULL;
	/*
	 * Re-order array to this list
	 */
	qsort((wchar_t *)alist, nel-1, sizeof (NODE *), asortcmp);
	tnp = array;
	npp = alist;
	do {
		tnp = tnp->n_alink = *npp;
	} while (*npp++ != NNULL);
	free((wchar_t *)alist);
	return (constundef);
}

/*
 * Return the number of arguments of a function.
 */
static uint
nargs(NODE *np)
{
	register int n;

	if (np == NNULL)
		return (0);
	n = 1;
	while (np!=NNULL && np->n_type==COMMA) {
		np = np->n_right;
		n++;
	}
	return (n);
}

/*
 * Do case translation.
 */
static NODE *
docasetr(NODE *np, int upper)
{
	register int c;
	register wchar_t *cp;
	register wchar_t *str;
	register uint na;

	if ((na = nargs(np)) > 1)
		awkerr(nargerr, upper ? s_toupper : s_tolower);
	str = strsave(na==0 ? linebuf : exprstring(getlist(&np)));
	cp = str;
	if (upper) {
		while ((c = *cp++) != '\0')
			cp[-1] = towupper(c);
	} else {
		while ((c = *cp++) != '\0')
			cp[-1] = towlower(c);
	}
	return (stringnode((STRING)str, FNOALLOC, (size_t)(cp-str-1)));
}

/*
 * The comparison routine used by qsort inside f_asort()
 */
static int
asortcmp(const void *npp1, const void *npp2)
{
	asnp1->n_strlen =
	    wcslen(asnp1->n_string = (*(NODE **)npp1)->n_name+asarraylen);
	asnp2->n_strlen =
	    wcslen(asnp2->n_string = (*(NODE **)npp2)->n_name+asarraylen);
	return ((int)exprint(asortfunc));
}

#if M_MATHERR
#if !defined(__BORLANDC__)&&defined(__TURBOC__)&&__COMPACT__&&__EMULATE__
/* So it won't optimize registers our FP is using */
#define	flushesbx()	(_BX = 0, _ES = _BX)
#else
#define	flushesbx()	(0)
#endif

/*
 * Math error for awk.
 */
int
matherr(struct exception *ep)
{
	register uint type;
	static char msgs[7][256];
	static int first_time = 1;

	if (first_time) {
		msgs[0] = gettext("Unknown FP error"),
		msgs[1] = gettext("Domain"),
		msgs[2] = gettext("Singularity"),
		msgs[3] = gettext("Overflow"),
		msgs[4] = gettext("Underflow"),
		msgs[5] = gettext("Total loss of precision"),
		msgs[6] = gettext("Partial loss of precision")
		first_time = 0;
	}

	if ((type = ep->type) > (uint)PLOSS)
		type = 0;
	(void)fprintf(stderr, "awk: %s", strmsg(msgs[type]));
	(void)fprintf(stderr, gettext(
		" error in function %s(%g) at NR=%lld\n"),
		((void) flushesbx(), ep->name), ep->arg1, (INT)exprint(varNR));
	return (1);
}
#endif	/*M_MATHERR*/
