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
 * awk -- executor
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 1985, 1994 by Mortice Kern Systems Inc.  All rights reserved.
 *
 * Based on MKS awk(1) ported to be /usr/xpg4/bin/awk with POSIX/XCU4 changes
 */

#include "awk.h"
#include "y.tab.h"

static int	dohash(wchar_t *name);
static NODE	*arithmetic(NODE *np);
static NODE	*comparison(NODE *np);
static int	type_of(NODE *np);
static NODE	*lfield(INT fieldno, NODE *value);
static NODE	*rfield(INT fieldno);
static NODE	*userfunc(NODE *np);
static wchar_t	*lltoa(long long l);
static NODE	*exprconcat(NODE *np, int len);
static int	s_if(NODE *np);
static int	s_while(NODE *np);
static int	s_for(NODE *np);
static int	s_forin(NODE *np);
static void	setrefield(NODE *value);
static void	freetemps(void);
static int	action(NODE *np);
static wchar_t	*makeindex(NODE *np, wchar_t *array, int tag);
static int	exprtest(NODE *np);

#define	regmatch(rp, s) REGWEXEC(rp, s, 0, (REGWMATCH_T*)NULL, 0)

/*
 * This code allows for integers to be stored in longs (type INT) and
 * only promoted to double precision floating point numbers (type REAL)
 * when overflow occurs during +, -, or * operations.  This is very
 * non-portable if you desire such a speed optimisation.  You may wish
 * to put something here for your system.  This "something" would likely
 * include either an assembler "jump on overflow" instruction or a
 * method to get traps on overflows from the hardware.
 *
 * This portable method works for ones and twos complement integer
 * representations (which is, realistically) almost all machines.
 */
#if	__TURBOC__
#define	addoverflow()	asm	jo	overflow
#define	suboverflow()	asm	jo	overflow
#else
/*
 * These are portable to two's complement integer machines
 */
#define	addoverflow()	if ((i1^i2) >= 0 && (iresult^i1) < 0) goto overflow
#define	suboverflow()	if ((i1^i2) < 0 && (iresult^i2) >= 0) goto overflow
#endif
#define	muloverflow()	if (((short)i1 != i1 || (short)i2 != i2) &&	\
			    ((i2 != 0 && iresult/i2 != i1) ||		\
			    (i1 == LONG_MIN && i2 == -1)))	  goto overflow

static char	notarray[] = "scalar \"%s\" cannot be used as array";
static char	badarray[] = "array \"%s\" cannot be used as a scalar";
static char	varnotfunc[] = "variable \"%s\" cannot be used as a function";
static char	tmfld[] = "Too many fields (LIMIT: %d)";
static char	toolong[] = "Record too long (LIMIT: %d bytes)";
static char	divzero[] =  "division (/ or %%) by zero";
static char	toodeep[] = "too deeply nested for in loop (LIMIT: %d)";

static wchar_t	numbuf[NUMSIZE];	/* Used to convert INTs to strings */
static wchar_t	*fields[NFIELD];	/* Cache of pointers into fieldbuf */
static wchar_t	*fieldbuf;		/* '\0' separated copy of linebuf */
static NODE	nodes[NSNODE];		/* Cache of quick access nodes */
static NODE	*fnodep = &nodes[0];
#define	NINDEXBUF	50
static wchar_t	indexbuf[NINDEXBUF];	/* Used for simple array indices */
static int	concflag;		/* In CONCAT operation (no frees) */
static NODE	*retval;		/* Last return value of a function */

/*
 * The following stack is used to store the next pointers for all nested
 * for-in loops. This needs to be global so that delete can check to see
 * if it is deleting the next node to be used by a loop.
 */
#define	NFORINLOOP	10
static NODE*	forindex[NFORINLOOP];
static NODE**	next_forin = forindex;

/*
 * Assign a string directly to a NODE without creating an intermediate
 * NODE.  This can handle either FALLOC, FSTATIC, FNOALLOC or FSENSE for
 * "flags" argument.  Also the NODE "np" must be reduced to an lvalue
 * (PARM nodes are not acceptable).
 */
void
strassign(NODE *np, STRING string, int flags, size_t length)
{
	if (np->n_type == FUNC)
		awkerr(gettext("attempt to redefine builtin function"));
	else if (np->n_type == GETLINE || np->n_type == KEYWORD)
		awkerr(gettext("inadmissible use of reserved keyword"));
	if (np->n_flags & FSPECIAL) {
		(void) nassign(np, stringnode(string, flags, length));
		return;
	}
	if (isastring(np->n_flags))
		free((wchar_t *)np->n_string);
	np->n_strlen = length++;
	if (flags & FALLOC) {
		length *= sizeof (wchar_t);
		np->n_string = (STRING) emalloc(length);
		(void) memcpy((void *)np->n_string, string, length);
	} else {
		np->n_string = string;
		if (flags & FNOALLOC) {
			flags &= ~FNOALLOC;
			flags |= FALLOC;
		}
	}
	np->n_flags &= FSAVE;
	if (flags & FSENSE) {
		flags &= ~FSENSE;
		flags |= type_of(np);
	} else
		flags |= FSTRING;
	np->n_flags |= flags;
}

/*
 * Assign to a variable node.
 * LHS must be a VAR type and RHS must be reduced by now.
 * To speed certain operations up, check for
 * certain things here and do special assignments.
 */
NODE *
nassign(NODE *np, NODE *value)
{
	register wchar_t *cp;
	register int len;

	/* short circuit assignment of a node to itself */
	if (np == value)
		return (np);
	if (np->n_flags & FSPECIAL) {
		if (np == varRS || np == varFS) {
			if (isastring(np->n_flags))
				free((void *)np->n_string);
			len = sizeof (wchar_t) * ((np->n_strlen =
				wcslen(cp = exprstring(value)))+1);
			np->n_string = emalloc(len);
			(void) memcpy((wchar_t *)np->n_string, cp, len);
			np->n_flags = FALLOC|FSTRING|FSPECIAL;
			if (np == varRS) {
				if (np->n_string[0] == '\n')
					awkrecord = defrecord;
				else if (np->n_string[0] == '\0')
					awkrecord = multirecord;
				else
					awkrecord = charrecord;
			} else if (np == varFS) {
				if (resep != (REGEXP)NULL) {
					REGWFREE(resep);
					resep = (REGEXP)NULL;
				}
				if (wcslen((wchar_t *)np->n_string) > 1)
					setrefield(np);
				else if (np->n_string[0] == ' ')
					awkfield = whitefield;
				else
					awkfield = blackfield;
			}
			return (np);
		}
	}
	if (isastring(np->n_flags))
		free((wchar_t *)np->n_string);
	if (isstring(value->n_flags)) {
		np->n_strlen = value->n_strlen;
		if (value->n_flags&FALLOC || value->n_string != _null) {
			len = (np->n_strlen+1) * sizeof (wchar_t);
			np->n_string = emalloc(len);
			(void) memcpy(np->n_string, value->n_string, len);
			np->n_flags &= FSAVE;
			np->n_flags |= value->n_flags & ~FSAVE;
			np->n_flags |= FALLOC;
			return (np);
		} else
			np->n_string = value->n_string;
	} else if (value->n_flags & FINT)
		np->n_int = value->n_int;
	else
		np->n_real = value->n_real;
	np->n_flags &= FSAVE;
	np->n_flags |= value->n_flags & ~FSAVE;
	return (np);
}

/*
 * Set regular expression FS value.
 */
static void
setrefield(NODE *np)
{
	static REGEXP re;
	int n;

	if ((n = REGWCOMP(&re, np->n_string)) != REG_OK) {
		REGWERROR(n, &re, (char *)linebuf, sizeof (linebuf));
		awkerr(gettext("syntax error \"%s\" in /%s/\n"),
			(char *)linebuf, np->n_string);
	}
	resep = re;
	awkfield = refield;
}

/*
 * Assign to an l-value node.
 */
NODE *
assign(NODE *left, NODE *right)
{
	if (isleaf(right->n_flags)) {
		if (right->n_type == PARM)
			right = right->n_next;
	} else
		right = exprreduce(right);
top:
	switch (left->n_type) {
	case INDEX:
		left = exprreduce(left);
		/* FALLTHROUGH */
	case VAR:
		return (nassign(left, right));

	case PARM:
		/*
		 * If it's a parameter then link to the actual value node and
		 * do the checks again.
		 */
		left = left->n_next;
		goto top;

	case FIELD:
		return (lfield(exprint(left->n_left), right));

	case CALLUFUNC:
	case UFUNC:
		awkerr(gettext("cannot assign to function \"%s\""),
		    left->n_name);

	default:
		awkerr(gettext("lvalue required in assignment"));
	}
	/* NOTREACHED */
	return (0);
}

/*
 * Compiled tree non-terminal node.
 */
NODE *
node(int type, NODE *left, NODE *right)
{
	register NODE *np;

	np = emptynode(type, 0);
	np->n_left = left;
	np->n_right = right;
	np->n_lineno = lineno;
	return (np);
}

/*
 * Create an integer node.
 */
NODE *
intnode(INT i)
{
	register NODE *np;

	np = emptynode(CONSTANT, 0);
	np->n_flags = FINT|FVINT;
	np->n_int = i;
	return (np);
}

/*
 * Create a real number node.
 */
NODE *
realnode(REAL real)
{
	register NODE *np;

	np = emptynode(CONSTANT, 0);
	np->n_flags = FREAL|FVREAL;
	np->n_real = real;
	return (np);
}

/*
 * Make a node for a string.
 */
NODE *
stringnode(STRING s, int how, size_t length)
{
	register NODE *np;

	np = emptynode(CONSTANT, 0);
	np->n_strlen = length;
	if (how & FALLOC) {
		np->n_string = emalloc(length = (length+1) * sizeof (wchar_t));
		(void) memcpy(np->n_string, s, length);
	} else {
		np->n_string = s;
		if (how & FNOALLOC) {
			how &= ~FNOALLOC;
			how |= FALLOC;
		}
	}
	if (how & FSENSE) {
		np->n_flags = type_of(np);
		how &= ~FSENSE;
	} else
		np->n_flags = FSTRING;
	np->n_flags |= how;
	return (np);
}

/*
 * Save a copy of a string.
 */
STRING
strsave(wchar_t *old)
{
	STRING new;
	register size_t len;

	new = (STRING)emalloc(len = (wcslen(old)+1) * sizeof (wchar_t));
	(void) memcpy(new, old, len);
	return (new);
}

/*
 * Allocate an empty node of given type.
 * String space for the node is given by `length'.
 */
NODE *
emptynode(int type, size_t length)
{
	register NODE *np;

	if (length == 0 && running && fnodep < &nodes[NSNODE]) {
		np = fnodep++;
	} else {
		np = (NODE *)emalloc(sizeof (NODE) +
		    (length * sizeof (wchar_t)));
		if (running && type != VAR && type != ARRAY) {
			np->n_next = freelist;
			freelist = np;
		}
	}
	np->n_flags = FNONTOK;
	np->n_type = type;
	np->n_alink = NNULL;

	return (np);
}

/*
 * Free a node.
 */
void
freenode(NODE *np)
{
	if (isastring(np->n_flags))
		free((wchar_t *)np->n_string);
	else if (np->n_type == RE) {
		REGWFREE(np->n_regexp);
	}
	free((wchar_t *)np);
}

/*
 * Install a keyword of given `type'.
 */
void
kinstall(LOCCHARP name, int type)
{
	register NODE *np;
	register size_t l;

	l = wcslen(name);
	np = emptynode(KEYWORD, l);
	np->n_keywtype = type;
	(void) memcpy(np->n_name, name, (l+1) * sizeof (wchar_t));
	addsymtab(np);
}

/*
 * Install built-in function.
 */
NODE *
finstall(LOCCHARP name, FUNCTION func, int type)
{
	register NODE *np;
	register size_t l;

	l = wcslen(name);
	np = emptynode(type, l);
	np->n_function = func;
	(void) memcpy(np->n_name, name, (l+1) * sizeof (wchar_t));
	addsymtab(np);
	return (np);
}

/*
 * Lookup an identifier.
 * nocreate contains the following flag values:
 *	1 if no creation of a new NODE,
 *	0 if ok to create new NODE
 */
NODE *
vlookup(wchar_t *name, int nocreate)
{
	register ushort_t hash;
	register NODE *np;

	np = symtab[hashbuck(hash = dohash((wchar_t *)name))];
	while (np != NNULL) {
		if (np->n_hash == hash && wcscmp(name, np->n_name) == 0)
			return (np);
		np = np->n_next;
	}
	if (nocreate) {
		np = NNULL;
	} else {
		np = emptynode(VAR, hash = wcslen(name));
		np->n_flags = FSTRING|FVINT;
		np->n_strlen = 0;
		np->n_string = _null;
		(void) memcpy(np->n_name, name,
			(hash+1) * sizeof (wchar_t));
		addsymtab(np);
	}
	return (np);
}

/*
 * Add a symbol to the table.
 */
void
addsymtab(NODE *np)
{
	register NODE **spp;

	np->n_hash = dohash((wchar_t *)np->n_name);
	spp = &symtab[hashbuck(np->n_hash)];
	np->n_next = *spp;
	*spp = np;
}

/*
 * Delete the given node from the symbol table.
 * If fflag is non-zero, also free the node space.
 * This routine must also check the stack of forin loop pointers. If
 * we are deleting the next item to be used, then the pointer must be
 * advanced.
 */
void
delsymtab(NODE *np, int fflag)
{
	register NODE *rnp;
	register NODE *prevp;
	register NODE **sptr;
	register ushort_t h;





	h = hashbuck(np->n_hash);
	prevp = NNULL;
	for (rnp = symtab[h]; rnp != NNULL; rnp = rnp->n_next) {
		if (rnp == np) {
			/*
			 * check all of the for-in loop pointers
			 * to see if any need to be advanced because
			 * this element is being deleted.
			 */
			if (next_forin != forindex) {
				sptr = next_forin;
				do {
					if (*--sptr == rnp) {
						*sptr = rnp->n_next;
						break;
					}
				} while (sptr != forindex);
			}
			if (prevp == NNULL)
				symtab[h] = rnp->n_next; else
				prevp->n_next = rnp->n_next;
			if (fflag)
				freenode(rnp);
			break;
		}
		prevp = rnp;
	}
}

/*
 * Hashing function.
 */
static int
dohash(wchar_t *name)
{
	register int hash = 0;

	while (*name != '\0')
		hash += *name++;
	return (hash);
}

/*
 * Top level executor for an awk programme.
 * This will be passed: pattern, action or a list of these.
 * The former function to evaluate a pattern has been
 * subsumed into this function for speed.
 * Patterns are:
 *	BEGIN,
 *	END,
 *	other expressions (including regular expressions)
 */
void
execute(NODE *wp)
{
	register NODE *np;
	register int type;
	register NODE *tnp;

	curnode = wp;
	if (phase != 0) {
		linebuf[0] = '\0';
		lbuflen = 0;
	}
	while (wp != NNULL) {
		if (wp->n_type == COMMA) {
			np = wp->n_left;
			wp = wp->n_right;
		} else {
			np = wp;
			wp = NNULL;
		}
		if (np->n_type != PACT)
			awkerr(interr, "PACT");
		/*
		 * Save the parent node and evaluate the pattern.
		 * If it evaluates to false (0) just continue
		 * to the next pattern/action (PACT) pair.
		 */
		tnp = np;
		np = np->n_left;
		if (np == NNULL) {
			if (phase != 0)
				continue;
		} else if (phase != 0) {
			if (np->n_type != phase)
				continue;
		} else if ((type = np->n_type) == BEGIN || type == END) {
			continue;
		} else if (type == COMMA) {
			/*
			 * The grammar only allows expressions
			 * to be separated by the ',' operator
			 * for range patterns.
			 */
			if (np->n_flags & FMATCH) {
				if (exprint(np->n_right) != 0)
					np->n_flags &= ~FMATCH;
			} else if (exprint(np->n_left) != 0) {
				if (exprint(np->n_right) == 0)
					np->n_flags |= FMATCH;
			} else
				continue;
		} else if (exprint(np) == 0)
			continue;
		np = tnp;
		if (action(np->n_right)) {
			loopexit = 0;
			break;
		}
	}
	if (freelist != NNULL)
		freetemps();
}

/*
 * Free all temporary nodes.
 */
static void
freetemps()
{
	register NODE *np, *nnp;

	if (concflag)
		return;
	for (np = &nodes[0]; np < fnodep; np++) {
		if (isastring(np->n_flags)) {
			free((wchar_t *)np->n_string);
		} else if (np->n_type == RE) {
			REGWFREE(np->n_regexp);
		}
	}
	fnodep = &nodes[0];
	for (np = freelist; np != NNULL; np = nnp) {
		nnp = np->n_next;
		freenode(np);
	}
	freelist = NNULL;
}

/*
 * Do the given action.
 * Actions are statements or expressions.
 */
static int
action(NODE *wp)
{
	register NODE *np;
	register int act = 0;
	register NODE *l;

	while (wp != NNULL) {
		if (wp->n_type == COMMA) {
			np = wp->n_left;
			wp = wp->n_right;
		} else {
			np = wp;
			wp = NNULL;
		}
		if (freelist != NNULL)
			freetemps();
		curnode = np;
		/*
		 * Don't change order of these cases without
		 * changing order in awk.y declarations.
		 * The order is optimised.
		 */
		switch (np->n_type) {
		case ASG:
			(void) assign(np->n_left, np->n_right);
			continue;

		case PRINT:
			s_print(np);
			continue;

		case PRINTF:
			s_prf(np);
			continue;

		case EXIT:
			if (np->n_left != NNULL)
				act = (int)exprint(np->n_left); else
				act = 0;
			doend(act);
			/* NOTREACHED */

		case RETURN:
			if (slevel == 0)
				awkerr(gettext("return outside of a function"));
			np = np->n_left != NNULL
			    ? exprreduce(np->n_left)
			    : const0;
			retval = emptynode(CONSTANT, 0);
			retval->n_flags = FINT;
			(void) nassign(retval, np);
			return (RETURN);

		case NEXT:
			loopexit = NEXT;
		/* FALLTHROUGH */
		case BREAK:
		case CONTINUE:
			return (np->n_type);

		case DELETE:
			if ((l = np->n_left)->n_type == PARM) {
				l = l->n_next;
				if (!(l->n_flags & FLARRAY))
					l = l->n_alink;
			}
			switch (l->n_type) {
			case ARRAY:
				delarray(l);
				break;

			case INDEX:
				if ((np = l->n_left)->n_type == PARM) {
					np = np->n_next;
					if (!(np->n_flags & FLARRAY))
						np = np->n_alink;
				}
				/*
				 * get pointer to the node for this array
				 * element using the hash key.
				 */
				l = exprreduce(l);
				/*
				 * now search linearly from the beginning of
				 * the list to find the element before the
				 * one being deleted. This must be done
				 * because arrays are singley-linked.
				 */
				while (np != NNULL) {
					if (np->n_alink == l) {
						np->n_alink = l->n_alink;
						break;
					}
					np = np->n_alink;
				}
				delsymtab(l, 1);
				break;

			case VAR:
				if (isstring(l->n_flags) &&
				    l->n_string == _null)
					break;
				/* FALLTHROUGH */
			default:
				awkerr(gettext(
				    "may delete only array element or array"));
				break;
			}
			continue;

		case WHILE:
		case DO:
			if ((act = s_while(np)) != 0)
				break;
			continue;

		case FOR:
			if ((act = s_for(np)) != 0)
				break;
			continue;

		case FORIN:
			if ((act = s_forin(np)) != 0)
				break;
			continue;

		case IF:
			if ((act = s_if(np)) != 0)
				break;
			continue;

		default:
			(void) exprreduce(np);
			if (loopexit != 0) {
				act = loopexit;
				break;
			}
			continue;
		}
		return (act);
	}
	return (0);
}

/*
 * Delete an entire array
 */
void
delarray(NODE *np)
{
	register NODE *nnp;

	nnp = np->n_alink;
	np->n_alink = NNULL;
	while (nnp != NNULL) {
		np = nnp->n_alink;
		delsymtab(nnp, 1);
		nnp = np;
	}
}

/*
 * Return the INT value of an expression.
 */
INT
exprint(NODE *np)
{
	if (isleaf(np->n_flags)) {
		if (np->n_type == PARM)
			np = np->n_next;
		goto leaf;
	}
	np = exprreduce(np);
	switch (np->n_type) {
	case CONSTANT:
	case VAR:
	leaf:
		if (np->n_flags & FINT)
			return (np->n_int);
		if (np->n_flags & FREAL)
			return ((INT)np->n_real);
		return ((INT)wcstoll(np->n_string, NULL, 10));

	default:
		awkerr(interr, "exprint");
	}
	/* NOTREACHED */
	return (0);
}

/*
 * Return a real number from an expression tree.
 */
REAL
exprreal(NODE *np)
{
	if (loopexit)
		return ((REAL)loopexit);
	if (isleaf(np->n_flags)) {
		if (np->n_type == PARM)
			np = np->n_next;
		goto leaf;
	}
	np = exprreduce(np);
	switch (np->n_type) {
	case CONSTANT:
	case VAR:
	leaf:
		if (np->n_flags & FREAL)
			return (np->n_real);
		if (np->n_flags & FINT)
			return ((REAL)np->n_int);
		return ((REAL)wcstod((wchar_t *)np->n_string, (wchar_t **)0));

	default:
		awkerr(interr, "exprreal");
	}
	/* NOTREACHED */
	return ((REAL)0);
}

/*
 * Return a string from an expression tree.
 */
STRING
exprstring(NODE *np)
{
	if (isleaf(np->n_flags)) {
		if (np->n_type == PARM)
			np = np->n_next;
		goto leaf;
	}
	np = exprreduce(np);
	switch (np->n_type) {
	case CONSTANT:
	case VAR:
	leaf:
		if (isstring(np->n_flags))
			return (np->n_string);
		if (np->n_flags & FINT)
			return (STRING)lltoa((long long)np->n_int);
		{
			char *tmp;
			(void) wsprintf(numbuf,
		(const char *) (tmp = wcstombsdup(exprstring(varCONVFMT))),
				(double)np->n_real);
			if (tmp != NULL)
				free(tmp);
		}
		return ((STRING)numbuf);

	default:
		awkerr(interr, "exprstring");
	}
	/* NOTREACHED */
	return (0);
}

/*
 * Convert number to string.
 */
static wchar_t *
lltoa(long long l)
{
	register wchar_t *p = &numbuf[NUMSIZE];
	register int s;
	register int neg;
	static wchar_t zero[] = M_MB_L("0");

	if (l == 0)
		return (zero);
	*--p = '\0';
	if (l < 0)
		neg = 1, l = -l; else
		neg = 0;
	if ((s = (short)l) == l) {
		while (s != 0) {
			*--p = s%10 + '0';
			s /= 10;
		}
	} else {
		while (l != 0) {
			*--p = l%10 + '0';
			l /= 10;
		}
	}
	if (neg)
		*--p = '-';
	return (wcscpy(numbuf, p));
}

/*
 * Return pointer to node with concatenation of operands of CONCAT node.
 * In the interest of speed, a left recursive tree of CONCAT nodes
 * is handled with a single malloc.  The accumulated lengths of the
 * right operands are passed down recursive invocations of this
 * routine, which allocates a large enough string when the left
 * operand is not a CONCAT node.
 */
static NODE *
exprconcat(NODE *np, int len)
{
	/* we KNOW (np->n_type==CONCAT) */
	register NODE *lnp = np->n_left;
	register NODE *rnp = np->n_right;
	register STRING	rsp;
	int rlen;
	size_t llen;
	wchar_t *cp;
	wchar_t rnumbuf[NUMSIZE];

	if (isleaf(rnp->n_flags) && rnp->n_type == PARM)
		rnp = rnp->n_next;
	if (isstring(rnp->n_flags)) {
		rsp = rnp->n_string;
		rlen = rnp->n_strlen;
	} else
		rlen = wcslen((wchar_t *)(rsp = exprstring(rnp)));
	if (rsp == numbuf) {	/* static, so save a copy */
		(void) memcpy(rnumbuf, (wchar_t *)rsp,
			(rlen+1) * sizeof (wchar_t));
		rsp = rnumbuf;
	}
	len += rlen;
	if (lnp->n_type == CONCAT) {
		lnp = exprconcat(lnp, len);
		cp = lnp->n_string;
		llen = lnp->n_strlen;
	} else {
		register STRING	lsp;

		if (isleaf(lnp->n_flags) && lnp->n_type == PARM)
			lnp = lnp->n_next;
		if (isstring(lnp->n_flags)) {
			lsp = lnp->n_string;
			llen = lnp->n_strlen;
		} else
			llen = wcslen((wchar_t *)(lsp = exprstring(lnp)));
		cp = emalloc((llen+len+1) * sizeof (wchar_t));
		(void) memcpy(cp, (wchar_t *)lsp, llen * sizeof (wchar_t));
		lnp = stringnode(cp, FNOALLOC, llen);
	}
	(void) memcpy(cp+llen, (wchar_t *)rsp, (rlen+1) * sizeof (wchar_t));
	lnp->n_strlen += rlen;
	return (lnp);
}

/*
 * Reduce an expression to a terminal node.
 */
NODE *
exprreduce(NODE *np)
{
	register wchar_t *cp;
	NODE *tnp;
	register int temp;
	register int t;
	register int  tag;
	register wchar_t *fname;
	register wchar_t *aname;

	/*
	 * a var or constant is a leaf-node (no further reduction required)
	 * so return immediately.
	 */
	if ((t = np->n_type) == VAR || t == CONSTANT)
		return (np);
	/*
	 * If it's a parameter then it is probably a leaf node but it
	 * might be an array so we check.. If it is an array, then signal
	 * an error as an array by itself cannot be used in this context.
	 */
	if (t == PARM)
		if ((np = np->n_next)->n_type == ARRAY)
			awkerr(badarray, np->n_name);
		else
			return (np);
	/*
	 * All the rest are non-leaf nodes.
	 */
	curnode = np;
	switch (t) {
	case CALLUFUNC:
		return (userfunc(np));

	case FIELD:
		return (rfield(exprint(np->n_left)));

	case IN:
	case INDEX:
		tag = 0;
		temp = np->n_type;
		tnp = np->n_left;
		np = np->n_right;
		/* initially formal var name and array key name are the same */
		fname = aname = tnp->n_name;
		if (tnp->n_type == PARM) {
			tnp = tnp->n_next;
			tag = tnp->n_scope;
			if (!(tnp->n_flags & FLARRAY)) {
				tnp = tnp->n_alink;
			}
			aname = tnp->n_name;
		}
		if (tnp->n_type != ARRAY) {
			if (!isstring(tnp->n_flags) || tnp->n_string != _null)
				awkerr(notarray, fname);
			else {
				/* promotion to array */
				promote(tnp);
				if (tnp->n_alink != NNULL) {
					tag = tnp->n_scope;
					if (!(tnp->n_flags & FLARRAY))
						tnp = tnp->n_alink;
					aname = tnp->n_name;
				} else {
					tag = 0;
					if (tnp->n_flags & FLARRAY)
						tag = tnp->n_scope;
				}
			}
		}
		if (tnp == varSYMTAB) {
			if (np == NNULL || np->n_type == COMMA)
				awkerr(gettext(
				    "SYMTAB must have exactly one index"));
			np = vlook(exprstring(np));
			return (np);
		}
		cp = makeindex(np, aname, tag);
		if (temp == INDEX) {
			np = vlook(cp);
			if (!(np->n_flags & FINARRAY)) {
				np->n_alink = tnp->n_alink;
				tnp->n_alink = np;
				np->n_flags |= FINARRAY;
			}
		} else
			np = vlookup(cp, 1) == NNULL ? const0 : const1;
		if (cp != indexbuf)
			free(cp);
		return (np);

	case CONCAT:
		++concflag;
		np = exprconcat(np, 0);
		--concflag;
		return (np);

	case NOT:
		return (intnode(exprtest(np->n_left) == 0 ? (INT)1 : (INT)0));

	case AND:
		return ((exprtest(np->n_left) != 0 &&
		    exprtest(np->n_right) != 0) ? const1 : const0);

	case OR:
		return ((exprtest(np->n_left) != 0 ||
		    exprtest(np->n_right) != 0) ? const1 : const0);

	case EXP:
		{
			double f1, f2;

			/*
			 * evaluate expressions in proper order before
			 * calling pow().
			 * Can't guarantee that compiler will do this
			 * correctly for us if we put them inline.
			 */
			f1 = (double)exprreal(np->n_left);
			f2 = (double)exprreal(np->n_right);
			return (realnode((REAL)pow(f1, f2)));
		}

	case QUEST:
		if (np->n_right->n_type != COLON)
			awkerr(interr, "?:");
		if (exprtest(np->n_left))
			np = np->n_right->n_left; else
			np = np->n_right->n_right;
		return (exprreduce(np));

	case EQ:
	case NE:
	case GE:
	case LE:
	case GT:
	case LT:
		return (comparison(np));

	case ADD:
	case SUB:
	case MUL:
	case DIV:
	case REM:
		return (arithmetic(np));

	case DEC:
		inc_oper->n_type = SUB;
		goto do_inc_op;
	case INC:
		inc_oper->n_type = ADD;
do_inc_op:
		if ((np = np->n_left)->n_type == INDEX)
			np = exprreduce(np);
		if (np->n_flags & FREAL)
			tnp = realnode(np->n_real);
		else
			tnp = intnode(exprint(np));
		inc_oper->n_left = np;
		(void) assign(np, inc_oper);
		return (tnp);

	case PRE_DEC:
		inc_oper->n_type = SUB;
		goto do_pinc_op;
	case PRE_INC:
		inc_oper->n_type = ADD;
do_pinc_op:
		if ((np = np->n_left)->n_type == INDEX)
			np = exprreduce(np);
		inc_oper->n_left = np;
		return (assign(np, inc_oper));

	case AADD:
		asn_oper->n_type = ADD;
		goto do_asn_op;
	case ASUB:
		asn_oper->n_type = SUB;
		goto do_asn_op;
	case AMUL:
		asn_oper->n_type = MUL;
		goto do_asn_op;
	case ADIV:
		asn_oper->n_type = DIV;
		goto do_asn_op;
	case AREM:
		asn_oper->n_type = REM;
		goto do_asn_op;
	case AEXP:
		asn_oper->n_type = EXP;
do_asn_op:
		asn_oper->n_right = np->n_right;
		if ((np = np->n_left)->n_type == INDEX)
			np = exprreduce(np);
		asn_oper->n_left = np;
		return (assign(np, asn_oper));


	case GETLINE:
		return (f_getline(np));

	case CALLFUNC:
		return ((*np->n_left->n_function)(np->n_right));

	case RE:
		if (regmatch(np->n_regexp, linebuf) == REG_OK)
			return (const1);
		return (const0);

	case TILDE:
		cp = exprstring(np->n_left);
		if (regmatch(getregexp(np->n_right), cp) == REG_OK)
			return (const1);
		return (const0);

	case NRE:
		cp = exprstring(np->n_left);
		if (regmatch(getregexp(np->n_right), cp) != REG_OK)
			return (const1);
		return (const0);

	case ASG:
		return (assign(np->n_left, np->n_right));

	case ARRAY:
		awkerr(badarray, np->n_name);

	case UFUNC:
		awkerr(varnotfunc, np->n_name);

	default:
		awkerr(gettext("panic: exprreduce(%d)"), t);
		/* NOTREACHED */
	}
	return (0);
}

/*
 * Do arithmetic operators.
 */
static NODE *
arithmetic(NODE *np)
{
	register NODE *left, *right;
	int type;
	register INT i1, i2;
	register INT iresult;
	register REAL r1, r2;

	left = exprreduce(np->n_left);
	if (isreal(left->n_flags) ||
	    (isstring(left->n_flags) && (type_of(left)&FVREAL))) {
		type = FREAL;
		r1 = exprreal(left);
		r2 = exprreal(np->n_right);
	} else {
		i1 = exprint(left);
		right = exprreduce(np->n_right);
		if (isreal(right->n_flags) ||
		    (isstring(right->n_flags) && (type_of(right)&FVREAL))) {

			type = FREAL;
			r1 = i1;
			r2 = exprreal(right);
		} else {
			type = FINT;
			i2 = exprint(right);
		}
	}
reswitch:
	switch (np->n_type) {
	case ADD:
		if (type == FINT) {
			iresult = i1 + i2;
			addoverflow();
		} else
			r1 += r2;
		break;

	/*
	 * Strategically placed between ADD and SUB
	 * so "jo" branches will reach on 80*86
	 */
	overflow:
		r1 = i1;
		r2 = i2;
		type = FREAL;
		goto reswitch;

	case SUB:
		if (type == FINT) {
			iresult = i1 - i2;
			suboverflow();
		} else
			r1 -= r2;
		break;

	case MUL:
		if (type == FINT) {
			iresult = i1 * i2;
			muloverflow();
		} else
			r1 *= r2;
		break;

	case DIV:
		if (type == FINT) {
			r1 = i1;
			r2 = i2;
			type = FREAL;
		}
		if (r2 == 0.0)
			awkerr(divzero);
		r1 /= r2;
		break;

	case REM:
		if (type == FINT) {
			if (i2 == 0)
				awkerr(divzero);
			iresult = i1 % i2;
		} else {
			double fmod(double x, double y);

			errno = 0;
			r1 = fmod(r1, r2);
			if (errno == EDOM)
				awkerr(divzero);
		}
		break;
	}
	return (type == FINT ? intnode(iresult) : realnode(r1));
}

/*
 * Do comparison operators.
 */
static NODE *
comparison(NODE *np)
{
	register NODE *left, *right;
	register int cmp;
	int tl, tr;
	register REAL r1, r2;
	register INT i1, i2;

	left = np->n_left;
	if (isleaf(left->n_flags)) {
		if (left->n_type == PARM)
			left = left->n_next;
	} else
		left = exprreduce(left);
	tl = left->n_flags;
	right = np->n_right;
	if (isleaf(right->n_flags)) {
		if (right->n_type == PARM)
			right = right->n_next;
	} else {
		++concflag;
		right = exprreduce(right);
		--concflag;
	}
	tr = right->n_flags;
	/*
	 * Posix mandates semantics for the comparison operators that
	 * are incompatible with traditional AWK behaviour. If the following
	 * define is true then awk will use the traditional behaviour.
	 * if it's false, then AWK will use the POSIX-mandated behaviour.
	 */
#define	TRADITIONAL 0
#if TRADITIONAL
	if (!isnumber(tl) || !isnumber(tr)) {
		cmp = wcscoll((wchar_t *)exprstring(left),
		    (wchar_t *)exprstring(right));
	} else if (isreal(tl) || isreal(tr)) {
		r1 = exprreal(left);
		r2 = exprreal(right);
		if (r1 < r2)
			cmp = -1;
		else if (r1 > r2)
			cmp = 1;
		else
			cmp = 0;
	} else {
		i1 = exprint(left);
		i2 = exprint(right);
		if (i1 < i2)
			cmp = -1;
		else if (i1 > i2)
			cmp = 1;
		else
			cmp = 0;
	}
#else
	if (!isnumber(tl) && !isnumber(tr)) {
do_strcmp:
		cmp = wcscoll((wchar_t *)exprstring(left),
		    (wchar_t *)exprstring(right));
	} else {
		if (isstring(tl))
			tl = type_of(left);
		if (isstring(tr))
			tr = type_of(right);
		if (!isnumber(tl) || !isnumber(tr))
			goto do_strcmp;
		if (isreal(tl) || isreal(tr)) {
			r1 = exprreal(left);
			r2 = exprreal(right);
			if (r1 < r2)
				cmp = -1;
			else if (r1 > r2)
				cmp = 1;
			else
				cmp = 0;
		} else {
			i1 = exprint(left);
			i2 = exprint(right);
			if (i1 < i2)
				cmp = -1;
			else if (i1 > i2)
				cmp = 1;
			else
				cmp = 0;
		}
	}
#endif
	switch (np->n_type) {
	case EQ:
		return (cmp == 0 ? const1 : const0);

	case  NE:
		return (cmp != 0 ? const1 : const0);

	case GE:
		return (cmp >= 0 ? const1 : const0);

	case LE:
		return (cmp <= 0 ? const1 : const0);

	case GT:
		return (cmp > 0 ? const1 : const0);

	case LT:
		return (cmp < 0 ? const1 : const0);

	default:
		awkerr(interr, "comparison");
	}
	/* NOTREACHED */
	return (0);
}

/*
 * Return the type of a constant that is a string.
 * The node must be a FSTRING type and the return value
 * will possibly have FVINT or FVREAL or'ed in.
 */
static int
type_of(NODE *np)
{
	wchar_t *cp;
	int somedigits = 0;
	int seene = 0;
	int seenradix = 0;
	int seensign = 0;
	int digitsaftere = 0;

	cp = (wchar_t *)np->n_string;
	if (*cp == '\0')
		return (FSTRING|FVINT);
	while (iswspace(*cp))
		cp++;
	if (*cp == '-' || *cp == '+')
		cp++;
	while (*cp != '\0') {
		switch (*cp) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			if (seene)
				digitsaftere = 1;
			somedigits++;
			break;

		case 'E':
		case 'e':
			if (seene || !somedigits)
				return (FSTRING);
			seene = 1;
			break;

		case '+':
		case '-':
			if (seensign || !seene || digitsaftere)
				return (FSTRING);
			seensign = 1;
			break;

		default:
			if (*cp == radixpoint) {
				if (seenradix || seene || (!somedigits &&
				    !iswdigit(*++cp)))
					return (FSTRING);
			} else
				return (FSTRING);
			seenradix = 1;
		}
		cp++;
	}
	if (somedigits == 0)
		return (FSTRING);
	if (somedigits >= MAXDIGINT || seenradix || seene) {
		if (seensign && !digitsaftere)
			return (FSTRING);
		else
			return (FSTRING|FVREAL);
	} else
		return (FSTRING|FVINT);
}

/*
 * Return a field rvalue.
 */
static NODE *
rfield(INT fieldno)
{
	register wchar_t *cp;

	if (fieldno == 0)
		return (stringnode(linebuf, FSTATIC|FSENSE, lbuflen));
	if (!splitdone)
		fieldsplit();
	if (fieldno > nfield || fieldno < 0)
		return (stringnode(_null, FSTATIC, 0));
	cp = fields[fieldno-1];
	return (stringnode(cp, FSTATIC|FSENSE, wcslen(cp)));
}

/*
 * Split linebuf into fields.  Done only once
 * per input record (maximum).
 */
void
fieldsplit()
{
	register wchar_t *ip, *op;
	register int n;
	wchar_t *ep;

	if (fieldbuf == NULL)
		fieldbuf = emalloc(NLINE * sizeof (wchar_t));
	fcount = 0;
	ep = linebuf;
	op = fieldbuf;
	while ((ip = (*awkfield)(&ep)) != NULL) {
		fields[fcount++] = op;
		if (fcount > NFIELD)
			awkerr(tmfld, NFIELD);
		n = ep-ip;
		(void) memcpy(op, ip, n * sizeof (wchar_t));
		op += n;
		*op++ = '\0';
	}
	if (varNF->n_flags & FINT)
		varNF->n_int = fcount;
	else {
		constant->n_int = fcount;
		(void) nassign(varNF, constant);
	}
	nfield = fcount;
	splitdone++;
}

/*
 * Assign to a field as an lvalue.
 * Return the unevaluated node as one doesn't always need it
 * evaluated in an assignment.
 */
static NODE *
lfield(INT fieldno, NODE *np)
{
	register wchar_t *cp;
	register wchar_t *op;
	register wchar_t *sep;
	register int i;
	register wchar_t *newval;
	register int seplen;
	register int newlen;

	newlen = wcslen(newval = (wchar_t *)exprstring(np));
	if (fieldno == 0) {
		splitdone = 0;
		(void) memcpy(linebuf, newval, (newlen+1) * sizeof (wchar_t));
		lbuflen = newlen;
		fieldsplit();
	} else {
		seplen = wcslen(sep = (wchar_t *)exprstring(varOFS));
		if (!splitdone)
			fieldsplit();
		if (--fieldno < nfield &&
		    (newlen <= wcslen(fields[fieldno]))) {
			(void) memcpy(fields[fieldno], newval,
				(newlen+1) * sizeof (wchar_t));
		} else {
			register wchar_t *buf;

			buf = fieldbuf;
			fieldbuf = emalloc(NLINE * sizeof (wchar_t));
			if (fieldno >= nfield) {
				if (fieldno >= NFIELD)
					awkerr(tmfld, NFIELD);
				while (nfield < fieldno)
					fields[nfield++] = _null;
				++nfield;
			}
			fields[fieldno] = newval;
			op = fieldbuf;
			for (i = 0; i < nfield; i++) {
				newlen = wcslen(cp = fields[i])+1;
				fields[i] = op;
				if (op+newlen >= fieldbuf+NLINE)
					awkerr(toolong, NLINE);
				(void) memcpy(op, cp,
				    newlen * sizeof (wchar_t));
				op += newlen;
			}
			free(buf);
		}
		/*
		 * Reconstruct $0
		 */
		op = linebuf;
		i = 0;
		while (i < nfield) {
			newlen = wcslen(cp = fields[i++]);
			(void) memcpy(op, cp, newlen * sizeof (wchar_t));
			op += newlen;
			if (i < nfield) {
				(void) memcpy(op, sep,
					seplen * sizeof (wchar_t));
				op += seplen;
			}
			if (op >= &linebuf[NLINE])
				awkerr(toolong, NLINE);
		}
		*op = '\0';
		lbuflen = op-linebuf;
		if (varNF->n_flags & FINT)
			varNF->n_int = nfield;
		else {
			constant->n_int = nfield;
			(void) nassign(varNF, constant);
		}
	}
	return (np);
}

/*
 * Do a user function.
 * Each formal parameter must:
 *	have the actual parameter assigned to it (call by value),
 *	have a pointer to an array put into it (call by reference),
 *	and be made undefined (extra formal parameters)
 */
static NODE *
userfunc(NODE *np)
{
	register NODE *temp;
	NODE *fnp;

	if ((fnp = np->n_left) == NNULL)
		awkerr(gettext("impossible function call"));
	if (fnp->n_type != UFUNC)
		awkerr(varnotfunc, fnp->n_name);

#ifndef M_STKCHK
	if (slevel >= NRECUR)
		awkerr(gettext("function \"%S\" nesting level > %u"),
		    fnp->n_name, NRECUR);
#else
	if (!M_STKCHK)
		awkerr(gettext("function \"%s\" nesting level too deep"),
		    fnp->n_name);
#endif

	fnp = fnp->n_ufunc;
	{
		register NODE *formal;
		register NODE *actual;
		NODE *formlist, *actlist, *templist, *temptail;

		templist = temptail = NNULL;
		actlist = np->n_right;
		formlist = fnp->n_left;
		/*
		 * pass through formal list, setting up a list
		 * (on templist) containing temps for the values
		 * of the actuals.
		 * If the actual list runs out before the formal
		 * list, assign 'constundef' as the value
		 */
		while ((formal = getlist(&formlist)) != NNULL) {
			register NODE *array;
			register int t;
			register size_t len;
			register int scope_tag;

			actual = getlist(&actlist);
			if (actual == NNULL) {
				actual = constundef;
				scope_tag = slevel+1;
			} else
				scope_tag = 0;
			array = actual;
			switch (actual->n_type) {
			case ARRAY:
				t = ARRAY;
				scope_tag = 0;
				break;

			case PARM:
				array = actual = actual->n_next;
				t = actual->n_type;
				scope_tag = actual->n_scope;
				if (!(actual->n_flags & FLARRAY))
					array = actual->n_alink;
				break;

			default:
				t = VAR;
				break;
			}
			temp = emptynode(t, len = wcslen(formal->n_name));
			(void) memcpy(temp->n_name, formal->n_name,
			    (len+1) * sizeof (wchar_t));
			temp->n_flags = FSTRING|FVINT;
			temp->n_string = _null;
			temp->n_strlen = 0;
			if (t == VAR)
				(void) assign(temp, actual);
			if (t != ARRAY)
				temp->n_flags |= FLARRAY;
			temp->n_scope = scope_tag;
			/*
			 * link to actual parameter in case of promotion to
			 * array
			 */
			if (actual != constundef)
				temp->n_alink = actual;
			/*
			 * Build the templist
			 */
			if (templist != NNULL) {
				temptail->n_next = temp;
				temptail = temp;
			} else
				templist = temptail = temp;
			temp->n_next = NNULL;
			if (actual->n_type == CONSTANT)
				temp->n_alink = temp;
			else
				temp->n_alink = array;
		}
		/*
		 * Bind results of the evaluation of actuals to formals.
		 */
		formlist = fnp->n_left;
		while (templist != NNULL) {
			temp = templist;
			templist = temp->n_next;
			formal = getlist(&formlist);
			temp->n_next = formal->n_next;
			formal->n_next = temp;








		}
	}
	{
		register NODE *savenode = curnode;

		++slevel;
		if (action(fnp->n_right) == RETURN)
			np = retval; else
			np = const0;
		curnode = savenode;
	}
	{
		register NODE *formal;
		NODE *formlist;

		formlist = fnp->n_left;
		while ((formal = getlist(&formlist)) != NNULL) {
			temp = formal->n_next;
			formal->n_next = temp->n_next;
			/* if node is a local array, free the elements */
			if (temp->n_type == ARRAY && (temp->n_scope == slevel))
				delarray(temp);
			freenode(temp);
		}
	}
	--slevel;
	return (np);
}

/*
 * Get the regular expression from an expression tree.
 */
REGEXP
getregexp(NODE *np)
{
	if (np->n_type == RE)
		return (np->n_regexp);
	np = renode((wchar_t *)exprstring(np));
	return (np->n_regexp);
}

/*
 * Get the next element from a list.
 */
NODE *
getlist(NODE **npp)
{
	register NODE *np;

	if ((np = *npp) == NNULL)
		return (np);
	if (np->n_type == COMMA) {
		*npp = np->n_right;
		return (np->n_left);
	} else {
		*npp = NNULL;
		return (np);
	}
}

/*
 * if statement.
 */
static int
s_if(NODE *np)
{
	register NODE *xp;
	register int test;

	test = exprtest(np->n_left);
	xp = np->n_right;
	if (xp->n_type != ELSE)
		awkerr(interr, "if/else");
	if (test)
		xp = xp->n_left;
	else
		xp = xp->n_right;
	return (action(xp));
}

/*
 * while and do{}while statements.
 */
static int
s_while(NODE *np)
{
	register int act = 0;

	if (np->n_type == DO)
		goto dowhile;
	for (;;) {
		if (exprtest(np->n_left) == 0)
			break;
	dowhile:
		if ((act = action(np->n_right)) != 0) {
			switch (act) {
			case BREAK:
				act = 0;
				break;

			case CONTINUE:
				act = 0;
				continue;
			}
			break;
		}
	}
	return (act);
}

/*
 * for statement.
 */
static int
s_for(NODE *np)
{
	register NODE *testnp, *incnp, *initnp;
	register int act = 0;
	NODE *listp;

	listp = np->n_left;
	initnp = getlist(&listp);
	testnp = getlist(&listp);
	incnp = getlist(&listp);
	if (initnp != NNULL)
		(void) exprreduce(initnp);
	for (;;) {
		if (exprtest(testnp) == 0)
			break;
		if ((act = action(np->n_right)) != 0) {
			switch (act) {
			case BREAK:
				act = 0;
				break;

			case CONTINUE:
				act = 0;
				goto clabel;
			}
			break;
		}
	clabel:
		if (incnp != NNULL)
			(void) exprreduce(incnp);
	}
	return (act);
}

/*
 * for variable in array statement.
 */
static int
s_forin(NODE *np)
{
	register NODE *left;
	register int act = 0;
	register NODE *var;
	register NODE **nnp;
	register NODE *statement;
	register int issymtab = 0;
	wchar_t *index;
	register int alen;
	int nbuck;

	left = np->n_left;
	statement = np->n_right;
	if (left->n_type != IN)
		awkerr(interr, "for (var in array)");
	if ((var = left->n_left)->n_type == PARM)
		var = var->n_next;
	np = left->n_right;
	if (np->n_type == PARM) {
		np = np->n_next;
		if (!(np->n_flags & FLARRAY))
			np = np->n_alink;
	}
	if (np == varSYMTAB) {
		issymtab++;
		np = NNULL;
		nbuck = 0;
	} else {
		/*
		 * At this point if the node is not actually an array
		 * check to see if it has already been established as
		 * a scalar. If it is a scalar then flag an error. If
		 * not then promote the object to an array type.
		 */
		if (np->n_type != ARRAY) {
			if (!isstring(np->n_flags) || np->n_string != _null)
				awkerr(notarray, np->n_name);
			else {
				/* promotion to array */
				promote(np);
				if (np->n_alink != NNULL)
					if (!(np->n_flags & FLARRAY))
						np = np->n_alink;
			}
		}
		/*
		 * Set up a pointer to the first node in the array list.
		 * Save this pointer on the delete stack. This information
		 * is used by the delete function to advance any pointers
		 * that might be pointing at a node which has been deleted.
		 * See the delsymtab() function for more information. Note
		 * that if the a_link field is nil, then just return 0 since
		 * this array has no elements yet.
		 */
		if ((*(nnp = next_forin) = np->n_alink) == 0)
			return (0);
		if (++next_forin > &forindex[NFORINLOOP])
			awkerr(toodeep, NFORINLOOP);
		/*
		 * array elements have names of the form
		 *	<name>]<index> (global arrays)
		 * or
		 *	<name>[<scope>]<index> (local arrays)
		 * We need to know the offset of the index portion of the
		 * name string in order to place it in the index variable so
		 * we look for the ']'. This is calculated here and then
		 * used below.
		 */
		for (alen = 0; (*nnp)->n_name[alen++] != ']'; )
			if ((*nnp)->n_name[alen] == '\0')
				awkerr(interr, "for: invalid array");
	}
	for (;;) {
		if (issymtab) {
			if ((left = symwalk(&nbuck, &np)) == NNULL)
				break;
			index = left->n_name;
		} else {
			if ((np = *nnp) == NNULL)
				break;
			index = np->n_name+alen;
			*nnp = np->n_alink;
		}
		strassign(var, index, FSTATIC, wcslen(index));
		if ((act = action(statement)) != 0) {
			switch (act) {
			case BREAK:
				act = 0;
				break;

			case CONTINUE:
				act = 0;
				continue;
			}
			break;
		}
	}
	next_forin--;
	return (act);
}

/*
 * Walk the symbol table using the same algorithm as arraynode.
 */
NODE *
symwalk(int *buckp, NODE **npp)
{
	register NODE *np;

	np = *npp;
	for (;;) {
		while (np == NNULL) {
			if (*buckp >= NBUCKET)
				return (*npp = NNULL);
			np = symtab[(*buckp)++];
		}
		if (np->n_type == VAR &&
		    (!isstring(np->n_flags) || np->n_string != _null)) {
			*npp = np->n_next;
			return (np);
		}
		np = np->n_next;
	}
	/* NOTREACHED */
}

/*
 * Test the result of an expression.
 */
static int
exprtest(NODE *np)
{
	register int t;

	if (np == NNULL)
		return (1);
	if (freelist != NNULL)
		freetemps();
	np = exprreduce(np);
	if (isint(t = np->n_flags)) {
		if (isstring(t))
			return (exprint(np) != 0);
		return (np->n_int != 0);
	}
	if (isreal(t)) {
		REAL rval;

		rval = isstring(t) ? exprreal(np) : np->n_real;
		return (rval != 0.0);
	}
	return (*(wchar_t *)exprstring(np) != '\0');
}

/*
 * Return malloc'ed space that holds the given name "[" scope "]" index ...
 * concatenated string.
 * The node (np) is the list of indices and 'array' is the array name.
 */
static wchar_t *
makeindex(NODE *np, wchar_t *array, int tag)
{
	static wchar_t tags[sizeof (int)];
	static wchar_t tag_chars[] = M_MB_L("0123456789ABCDEF");
	register wchar_t *cp;
	register NODE *index;
	register uint_t n;
	register int len;
	register wchar_t *indstr;
	register wchar_t *sep;
	register int seplen;
	register int taglen;


	/*
	 * calculate and create the tag string
	 */
	for (taglen = 0; tag; tag >>= 4)
		tags[taglen++] = tag_chars[tag & 0xf];
	/*
	 * Special (normal) case: only one index.
	 */
	if (np->n_type != COMMA) {
		wchar_t *ocp;
		size_t i;

		if (isleaf(np->n_flags) && np->n_type == PARM)
			np = np->n_next;
		if (isstring(np->n_flags)) {
			indstr = np->n_string;
			len = np->n_strlen;
		} else {
			indstr = exprstring(np);
			len = wcslen(indstr);
		}
		i = (n = wcslen(array)) + len + 3 + taglen;
		if (i < NINDEXBUF)
			ocp = indexbuf;
		else
			ocp = emalloc(i * sizeof (wchar_t));
		(void) memcpy(ocp, array, n * sizeof (wchar_t));
		cp = ocp+n;
		if (taglen) {
			*cp++ = '[';
			while (taglen)
				*cp++ = tags[--taglen];
		}
		*cp++ = ']';
		(void) memcpy(cp, indstr, (len+1) * sizeof (wchar_t));

		return (ocp);
	}
	n = 0;
	seplen = wcslen(sep = (wchar_t *)exprstring(varSUBSEP));
	while ((index = getlist(&np)) != NNULL) {
		indstr = exprstring(index);
		len = wcslen(indstr);
		if (n == 0) {
			cp = emalloc(sizeof (wchar_t) * ((n = wcslen(array)) +
				len + 3 + taglen));
			(void) memcpy(cp, array, n * sizeof (wchar_t));
			if (taglen) {
				cp[n++] = '[';
				while (taglen)
					cp[n++] = tags[--taglen];
			}
			cp[n++] = ']';
		} else {
			cp = erealloc(cp, (n+len+seplen+1) * sizeof (wchar_t));
			(void) memcpy(cp+n, sep, seplen * sizeof (wchar_t));
			n += seplen;
		}
		(void) memcpy(cp+n, indstr, (len+1) * sizeof (wchar_t));
		n += len;
	}
	return (cp);
}


/*
 * Promote a node to an array. In the simplest case, just set the
 * node type field to ARRAY. The more complicated case involves walking
 * a list of variables that haven't been determined yet as scalar or array.
 * This routine plays with the pointers to avoid recursion.
 */
void
promote(NODE *n)
{
	register NODE *prev = NNULL;
	register NODE *next;

	/*
	 * walk down the variable chain, reversing the pointers and
	 * setting each node to type array.
	 */
	while ((n->n_flags & FLARRAY) && (n->n_alink != n)) {
		n->n_type = ARRAY;
		next = n->n_alink;
		n->n_alink = prev;
		prev = n;
		n = next;
	}

	/*
	 * If the final entity on the chain is a local variable, then
	 * reset it's alink field to NNULL - normally it points back
	 * to itself - this is used in other parts of the code to
	 * reduce the number of conditionals when handling locals.
	 */
	n->n_type = ARRAY;
	if (n->n_flags & FLARRAY)
		n->n_alink = NNULL;

	/*
	 * Now walk back up the list setting the alink to point to
	 * the last entry in the chain and clear the 'local array'
	 * flag.
	 */
	while (prev != NNULL) {
		prev->n_flags &= ~FLARRAY;
		next = prev->n_alink;
		prev->n_alink = n;
		prev = next;
	}
}
