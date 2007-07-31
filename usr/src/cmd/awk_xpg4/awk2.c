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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 1986, 1994 by Mortice Kern Systems Inc.  All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * awk -- process input files, field extraction, output
 *
 * Based on MKS awk(1) ported to be /usr/xpg4/bin/awk with POSIX/XCU4 changes
 */

#include "awk.h"
#include "y.tab.h"

static FILE	*awkinfp;		/* Input file pointer */
static int	reclen;			/* Length of last record */
static int	exstat;			/* Exit status */

static FILE	*openfile(NODE *np, int flag, int fatal);
static FILE	*newfile(void);
static NODE	*nextarg(NODE **npp);
static void	adjust_buf(wchar_t **, int *, wchar_t **, char *, size_t);
static void	awk_putwc(wchar_t, FILE *);

/*
 * mainline for awk execution
 */
void
awk()
{
	running = 1;
	dobegin();
	while (nextrecord(linebuf, awkinfp) > 0)
		execute(yytree);
	doend(exstat);
}

/*
 * "cp" is the buffer to fill.  There is a special case if this buffer is
 * "linebuf" ($0)
 * Return 1 if OK, zero on EOF, -1 on error.
 */
int
nextrecord(wchar_t *cp, FILE *fp)
{
	wchar_t *ep = cp;

nextfile:
	if (fp == FNULL && (fp = newfile()) == FNULL)
		return (0);
	if ((*awkrecord)(ep, NLINE, fp) == NULL) {
		if (fp == awkinfp) {
			if (fp != stdin)
				(void) fclose(awkinfp);
			awkinfp = fp = FNULL;
			goto nextfile;
		}
		if (ferror(fp))
			return (-1);
		return (0);
	}
	if (fp == awkinfp) {
		if (varNR->n_flags & FINT)
			++varNR->n_int;
		else
			(void) exprreduce(incNR);
		if (varFNR->n_flags & FINT)
			++varFNR->n_int;
		else
			(void) exprreduce(incFNR);
	}
	if (cp == linebuf) {
		lbuflen = reclen;
		splitdone = 0;
		if (needsplit)
			fieldsplit();
	}
	/* if record length is too long then bail out */
	if (reclen > NLINE - 2) {
		awkerr(gettext("Record too long (LIMIT: %d bytes)"),
		    NLINE - 1);
		/* Not Reached */
	}
	return (1);
}

/*
 * isclvar()
 *
 * Returns 1 if the input string, arg, is a variable assignment,
 * otherwise returns 0.
 *
 * An argument to awk can be either a pathname of a file, or a variable
 * assignment.  An operand that begins with an undersore or alphabetic
 * character from the portable character set, followed by a sequence of
 * underscores, digits, and alphabetics from the portable character set,
 * followed by the '=' character, shall specify a variable assignment
 * rather than a pathname.
 */
int
isclvar(wchar_t *arg)
{
	wchar_t	*tmpptr = arg;

	if (tmpptr != NULL) {

		/* Begins with an underscore or alphabetic character */
		if (iswalpha(*tmpptr) || *tmpptr == '_') {

			/*
			 * followed by a sequence of underscores, digits,
			 * and alphabetics
			 */
			for (tmpptr++; *tmpptr; tmpptr++) {
				if (!(iswalnum(*tmpptr) || (*tmpptr == '_'))) {
					break;
				}
			}
			return (*tmpptr == '=');
		}
	}

	return (0);
}

/*
 * Return the next file from the command line.
 * Return FNULL when no more files.
 * Sets awkinfp variable to the new current input file.
 */
static FILE *
newfile()
{
	static int argindex = 1;
	static int filedone;
	wchar_t *ap;
	int argc;
	wchar_t *arg;
	extern void strescape(wchar_t *);

	argc = (int)exprint(varARGC);
	for (;;) {
		if (argindex >= argc) {
			if (filedone)
				return (FNULL);
			++filedone;
			awkinfp = stdin;
			arg = M_MB_L("-");
			break;
		}
		constant->n_int = argindex++;
		arg = (wchar_t *)exprstring(ARGVsubi);
		/*
		 * If the argument contains a '=', determine if the
		 * argument needs to be treated as a variable assignment
		 * or as the pathname of a file.
		 */
		if (((ap = wcschr(arg, '=')) != NULL) && isclvar(arg)) {
			*ap = '\0';
			strescape(ap+1);
			strassign(vlook(arg), linebuf, FALLOC|FSENSE,
			    wcslen(linebuf));
			*ap = '=';
			continue;
		}
		if (arg[0] == '\0')
			continue;
		++filedone;
		if (arg[0] == '-' && arg[1] == '\0') {
			awkinfp = stdin;
			break;
		}
		if ((awkinfp = fopen(mbunconvert(arg), r)) == FNULL) {
			(void) fprintf(stderr, gettext("input file \"%s\""),
			    mbunconvert(arg));
			exstat = 1;
			continue;
		}
		break;
	}
	strassign(varFILENAME, arg, FALLOC, wcslen(arg));
	if (varFNR->n_flags & FINT)
		varFNR->n_int = 0;
	else
		(void) exprreduce(clrFNR);
	return (awkinfp);
}

/*
 * Default record reading code
 * Uses fgets for potential speedups found in some (e.g. MKS)
 * stdio packages.
 */
wchar_t *
defrecord(wchar_t *bp, int lim, FILE *fp)
{
	wchar_t *endp;

	if (fgetws(bp, lim, fp) == NULL) {
		*bp = '\0';
		return (NULL);
	}
/*
 * XXXX
 *	switch (fgetws(bp, lim, fp)) {
 *	case M_FGETS_EOF:
 *		*bp = '\0';
 *		return (NULL);
 *	case M_FGETS_BINARY:
 *		awkerr(gettext("file is binary"));
 *	case M_FGETS_LONG:
 *		awkerr(gettext("line too long: limit %d"),
 *			lim);
 *	case M_FGETS_ERROR:
 *		awkperr(gettext("error reading file"));
 *	}
 */

	if (*(endp = (bp + (reclen = wcslen(bp))-1)) == '\n') {
		*endp = '\0';
		reclen--;
	}
	return (bp);
}

/*
 * Read a record separated by one character in the RS.
 * Compatible calling sequence with fgets, but don't include
 * record separator character in string.
 */
wchar_t *
charrecord(wchar_t *abp, int alim, FILE *fp)
{
	wchar_t *bp;
	wint_t c;
	int limit = alim;
	wint_t endc;

	bp = abp;
	endc = *(wchar_t *)varRS->n_string;
	while (--limit > 0 && (c = getwc(fp)) != endc && c != WEOF)
		*bp++ = c;
	*bp = '\0';
	reclen = bp-abp;
	return (c == WEOF && bp == abp ? NULL : abp);
}

/*
 * Special routine for multiple line records.
 */
wchar_t *
multirecord(wchar_t *abp, int limit, FILE *fp)
{
	wchar_t *bp;
	int c;

	while ((c = getwc(fp)) == '\n')
		;
	bp = abp;
	if (c != WEOF) do {
		if (--limit == 0)
			break;
		if (c == '\n' && bp[-1] == '\n')
			break;

		*bp++ = c;
	} while ((c = getwc(fp)) != WEOF);
	*bp = '\0';
	if (bp > abp)
		*--bp = '\0';
	reclen = bp-abp;
	return (c == WEOF && bp == abp ? NULL : abp);
}

/*
 * Look for fields separated by spaces, tabs or newlines.
 * Extract the next field, given pointer to start address.
 * Return pointer to beginning of field or NULL.
 * Reset end of field reference, which is the beginning of the
 * next field.
 */
wchar_t *
whitefield(wchar_t **endp)
{
	wchar_t *sp;
	wchar_t *ep;

	sp = *endp;
	while (*sp == ' ' || *sp == '\t' || *sp == '\n')
		++sp;
	if (*sp == '\0')
		return (NULL);
	for (ep = sp; *ep != ' ' && *ep != '\0' && *ep != '\t' &&
	    *ep != '\n'; ++ep)
		;
	*endp = ep;
	return (sp);
}

/*
 * Look for fields separated by non-whitespace characters.
 * Same calling sequence as whitefield().
 */
wchar_t *
blackfield(wchar_t **endp)
{
	wchar_t *cp;
	int endc;

	endc = *(wchar_t *)varFS->n_string;
	cp = *endp;
	if (*cp == '\0')
		return (NULL);
	if (*cp == endc && fcount != 0)
		cp++;
	if ((*endp = wcschr(cp, endc)) == NULL)
		*endp = wcschr(cp, '\0');
	return (cp);
}

/*
 * This field separation routine uses the same logic as
 * blackfield but uses a regular expression to separate
 * the fields.
 */
wchar_t *
refield(wchar_t **endpp)
{
	wchar_t *cp, *start;
	int flags;
	static	REGWMATCH_T match[10];
	int result;

	cp = *endpp;
	if (*cp == '\0') {
		match[0].rm_ep = NULL;
		return (NULL);
	}
	if (match[0].rm_ep != NULL) {
		flags = REG_NOTBOL;
		cp = (wchar_t *)match[0].rm_ep;
	} else
		flags = 0;
	start = cp;
again:
	switch ((result = REGWEXEC(resep, cp, 10, match, flags))) {
	case REG_OK:
		/*
		 * Check to see if a null string was matched. If this is the
		 * case, then move the current pointer beyond this position.
		 */
		if (match[0].rm_sp == match[0].rm_ep) {
			cp = (wchar_t *)match[0].rm_sp;
			if (*cp++ != '\0') {
				goto again;
			}
		}
		*endpp = (wchar_t *)match[0].rm_sp;
		break;
	case REG_NOMATCH:
		match[0].rm_ep = NULL;
		*endpp = wcschr(cp, '\0');
		break;
	default:
		(void) REGWERROR(result, resep, (char *)linebuf,
		    sizeof (linebuf));
		awkerr(gettext("error splitting record: %s"),
		    (char *)linebuf);
	}
	return (start);
}

/*
 * do begin processing
 */
void
dobegin()
{
	/*
	 * Free all keyword nodes to save space.
	 */
	{
		NODE *np;
		int nbuck;
		NODE *knp;

		np = NNULL;
		nbuck = 0;
		while ((knp = symwalk(&nbuck, &np)) != NNULL)
			if (knp->n_type == KEYWORD)
				delsymtab(knp, 1);
	}
	/*
	 * Copy ENVIRON array only if needed.
	 * Note the convoluted work to assign to an array
	 * and that the temporary nodes will be freed by
	 * freetemps() because we are "running".
	 */
	if (needenviron) {
		char **app;
		wchar_t *name, *value;
		NODE *namep = stringnode(_null, FSTATIC, 0);
		NODE *valuep = stringnode(_null, FSTATIC, 0);
		NODE *ENVsubname = node(INDEX, varENVIRON, namep);
		extern char **environ;

		/* (void) m_setenv(); XXX what's this do? */
		for (app = environ; *app != NULL; /* empty */) {
			name = mbstowcsdup(*app++);

			if ((value = wcschr(name, '=')) != NULL) {
				*value++ = '\0';
				valuep->n_strlen = wcslen(value);
				valuep->n_string = value;
			} else {
				valuep->n_strlen = 0;
				valuep->n_string = _null;
			}
			namep->n_strlen = wcslen(namep->n_string = name);
			(void) assign(ENVsubname, valuep);
			if (value != NULL)
				value[-1] = '=';
		}
	}
	phase = BEGIN;
	execute(yytree);
	phase = 0;
	if (npattern == 0)
		doend(0);
	/*
	 * Delete all pattern/action rules that are BEGIN at this
	 * point to save space.
	 * NOTE: this is not yet implemented.
	 */
}

/*
 * Do end processing.
 * Exit with a status
 */
void
doend(int s)
{
	OFILE *op;

	if (phase != END) {
		phase = END;
		awkinfp = stdin;
		execute(yytree);
	}
	for (op = &ofiles[0]; op < &ofiles[NIOSTREAM]; op++)
		if (op->f_fp != FNULL)
			awkclose(op);
	if (awkinfp == stdin)
		(void) fflush(awkinfp);
	exit(s);
}

/*
 * Print statement.
 */
void
s_print(NODE *np)
{
	FILE *fp;
	NODE *listp;
	char *ofs;
	int notfirst = 0;

	fp = openfile(np->n_right, 1, 1);
	if (np->n_left == NNULL)
		(void) fputs(mbunconvert(linebuf), fp);
	else {
		ofs = wcstombsdup((isstring(varOFS->n_flags)) ?
		    (wchar_t *)varOFS->n_string :
		    (wchar_t *)exprstring(varOFS));
		listp = np->n_left;
		while ((np = getlist(&listp)) != NNULL) {
			if (notfirst++)
				(void) fputs(ofs, fp);
			np = exprreduce(np);
			if (np->n_flags & FINT)
				(void) fprintf(fp, "%lld", (INT)np->n_int);
			else if (isstring(np->n_flags))
				(void) fprintf(fp, "%S", np->n_string);
			else
				(void) fprintf(fp,
				    mbunconvert((wchar_t *)exprstring(varOFMT)),
				    (double)np->n_real);
		}
		free(ofs);
	}
	(void) fputs(mbunconvert(isstring(varORS->n_flags) ?
	    (wchar_t *)varORS->n_string : (wchar_t *)exprstring(varORS)),
	    fp);
	if (ferror(fp))
		awkperr("error on print");
}

/*
 * printf statement.
 */
void
s_prf(NODE *np)
{
	FILE *fp;

	fp = openfile(np->n_right, 1, 1);
	(void) xprintf(np->n_left, fp, (wchar_t **)NULL);
	if (ferror(fp))
		awkperr("error on printf");
}

/*
 * Get next input line.
 * Read into variable on left of node (or $0 if NULL).
 * Read from pipe or file on right of node (or from regular
 * input if NULL).
 * This is an oddball inasmuch as it is a function
 * but parses more like the keywords print, etc.
 */
NODE *
f_getline(NODE *np)
{
	wchar_t *cp;
	INT ret;
	FILE *fp;
	size_t len;

	if (np->n_right == NULL && phase == END) {
		/* Pretend we've reached end of (the non-existant) file. */
		return (intnode(0));
	}

	if ((fp = openfile(np->n_right, 0, 0)) != FNULL) {
		if (np->n_left == NNULL) {
			ret = nextrecord(linebuf, fp);
		} else {
			cp = emalloc(NLINE * sizeof (wchar_t));
			ret = nextrecord(cp, fp);
			np = np->n_left;
			len = wcslen(cp);
			cp = erealloc(cp, (len+1)*sizeof (wchar_t));
			if (isleaf(np->n_flags)) {
				if (np->n_type == PARM)
					np = np->n_next;
				strassign(np, cp, FNOALLOC, len);
			} else
				(void) assign(np, stringnode(cp,
				    FNOALLOC, len));
		}
	} else
		ret = -1;
	return (intnode(ret));
}

/*
 * Open a file.  Flag is non-zero for output.
 */
static FILE *
openfile(NODE *np, int flag, int fatal)
{
	OFILE *op;
	char *cp;
	FILE *fp;
	int type;
	OFILE *fop;

	if (np == NNULL) {
		if (flag)
			return (stdout);
		if (awkinfp == FNULL)
			awkinfp = newfile();
		return (awkinfp);
	}
	if ((type = np->n_type) == APPEND)
		type = WRITE;
	cp = mbunconvert(exprstring(np->n_left));
	fop = (OFILE *)NULL;
	for (op = &ofiles[0]; op < &ofiles[NIOSTREAM]; op++) {
		if (op->f_fp == FNULL) {
			if (fop == (OFILE *)NULL)
				fop = op;
			continue;
		}
		if (op->f_mode == type && strcmp(op->f_name, cp) == 0)
			return (op->f_fp);
	}
	if (fop == (OFILE *)NULL)
		awkerr(gettext("too many open streams to %s onto \"%s\""),
		    flag ? "print/printf" : "getline", cp);
	(void) fflush(stdout);
	op = fop;
	if (cp[0] == '-' && cp[1] == '\0') {
		fp = flag ? stdout : stdin;
	} else {
		switch (np->n_type) {
		case WRITE:
			if ((fp = fopen(cp, w)) != FNULL) {
				if (isatty(fileno(fp)))
					(void) setvbuf(fp, 0, _IONBF, 0);
			}
			break;

		case APPEND:
			fp = fopen(cp, "a");
			break;

		case PIPE:
			fp = popen(cp, w);
			(void) setvbuf(fp, (char *)0, _IOLBF, 0);
			break;

		case PIPESYM:
			fp = popen(cp, r);
			break;

		case LT:
			fp = fopen(cp, r);
			break;

		default:
			awkerr(interr, "openfile");
		}
	}
	if (fp != FNULL) {
		op->f_name = strdup(cp);
		op->f_fp = fp;
		op->f_mode = type;
	} else if (fatal) {
		awkperr(flag ? gettext("output file \"%s\"") :
		    gettext("input file \"%s\""), cp);
	}
	return (fp);
}

/*
 * Close a stream.
 */
void
awkclose(OFILE *op)
{
	if (op->f_mode == PIPE || op->f_mode == PIPESYM)
		(void) pclose(op->f_fp);
	else if (fclose(op->f_fp) == EOF)
		awkperr("error on stream \"%s\"", op->f_name);
	op->f_fp = FNULL;
	free(op->f_name);
	op->f_name = NULL;
}

/*
 * Internal routine common to printf, sprintf.
 * The node is that describing the arguments.
 * Returns the number of characters written to file
 * pointer `fp' or the length of the string return
 * in cp. If cp is NULL then the file pointer is used. If
 * cp points to a string pointer, a pointer to an allocated
 * buffer will be returned in it.
 */
size_t
xprintf(NODE *np, FILE *fp, wchar_t **cp)
{
	wchar_t *fmt;
	int c;
	wchar_t *bptr = (wchar_t *)NULL;
	char fmtbuf[40];
	size_t length = 0;
	char *ofmtp;
	NODE *fnp;
	wchar_t *fmtsave;
	int slen;
	int cplen;

	fnp = getlist(&np);
	if (isleaf(fnp->n_flags) && fnp->n_type == PARM)
		fnp = fnp->n_next;
	if (isstring(fnp->n_flags)) {
		fmt = fnp->n_string;
		fmtsave = NULL;
	} else
		fmtsave = fmt = (wchar_t *)strsave(exprstring(fnp));

	/*
	 * if a char * pointer has been passed in then allocate an initial
	 * buffer for the string. Make it LINE_MAX plus the length of
	 * the format string but do reallocs only based LINE_MAX.
	 */
	if (cp != (wchar_t **)NULL) {
		cplen = LINE_MAX;
		bptr = *cp = emalloc(sizeof (wchar_t) * (cplen + wcslen(fmt)));
	}

	while ((c = *fmt++) != '\0') {
		if (c != '%') {
			if (bptr == (wchar_t *)NULL)
				awk_putwc(c, fp);
			else
				*bptr++ = c;
			++length;
			continue;
		}
		ofmtp = fmtbuf;
		*ofmtp++ = (char)c;
	nextc:
		switch (c = *fmt++) {
		case '%':
			if (bptr == (wchar_t *)NULL)
				awk_putwc(c, fp);
			else
				*bptr++ = c;
			++length;
			continue;

		case 'c':
			*ofmtp++ = 'w';
			*ofmtp++ = 'c';
			*ofmtp = '\0';
			fnp = exprreduce(nextarg(&np));
			if (isnumber(fnp->n_flags))
				c = exprint(fnp);
			else
				c = *(wchar_t *)exprstring(fnp);
			if (bptr == (wchar_t *)NULL)
				length += fprintf(fp, fmtbuf, c);
			else {
				/*
				 * Make sure that the buffer is long
				 * enough to hold the formatted string.
				 */
				adjust_buf(cp, &cplen, &bptr, fmtbuf, 0);
				/*
				 * Since the call to adjust_buf() has already
				 * guaranteed that the buffer will be long
				 * enough, just pass in INT_MAX as
				 * the length.
				 */
				(void) wsprintf(bptr, (const char *) fmtbuf, c);
				bptr += (slen = wcslen(bptr));
				length += slen;
			}
			continue;
/* XXXX Is this bogus? Figure out what s & S mean - look at original code */
		case 's':
		case 'S':
			*ofmtp++ = 'w';
			*ofmtp++ = 's';
			*ofmtp = '\0';
			if (bptr == (wchar_t *)NULL)
				length += fprintf(fp, fmtbuf,
				    (wchar_t *)exprstring(nextarg(&np)));
			else {
				wchar_t *ts = exprstring(nextarg(&np));

				adjust_buf(cp, &cplen, &bptr, fmtbuf,
				    wcslen(ts));
				(void) wsprintf(bptr, (const char *) fmtbuf,
				    ts);
				bptr += (slen = wcslen(bptr));
				length += slen;
			}
			continue;

		case 'o':
		case 'O':
		case 'X':
		case 'x':
		case 'd':
		case 'i':
		case 'D':
		case 'U':
		case 'u':
			*ofmtp++ = 'l';
			*ofmtp++ = 'l'; /* now dealing with long longs */
			*ofmtp++ = c;
			*ofmtp = '\0';
			if (bptr == (wchar_t *)NULL)
				length += fprintf(fp, fmtbuf,
				    exprint(nextarg(&np)));
			else {
				adjust_buf(cp, &cplen, &bptr, fmtbuf, 0);
				(void) wsprintf(bptr, (const char *) fmtbuf,
				    exprint(nextarg(&np)));
				bptr += (slen = wcslen(bptr));
				length += slen;
			}
			continue;

		case 'e':
		case 'E':
		case 'f':
		case 'F':
		case 'g':
		case 'G':
			*ofmtp++ = c;
			*ofmtp = '\0';
			if (bptr == (wchar_t *)NULL)
				length += fprintf(fp, fmtbuf,
				    exprreal(nextarg(&np)));
			else {
				adjust_buf(cp, &cplen, &bptr, fmtbuf, 0);
				(void) wsprintf(bptr, (const char *) fmtbuf,
				    exprreal(nextarg(&np)));
				bptr += (slen = wcslen(bptr));
				length += slen;
			}
			continue;

		case 'l':
		case 'L':
			break;

		case '*':
#ifdef M_BSD_SPRINTF
			sprintf(ofmtp, "%lld", (INT)exprint(nextarg(&np)));
			ofmtp += strlen(ofmtp);
#else
			ofmtp += sprintf(ofmtp, "%lld",
			    (INT)exprint(nextarg(&np)));
#endif
			break;

		default:
			if (c == '\0') {
				*ofmtp = (wchar_t)NULL;
				(void) fprintf(fp, "%s", fmtbuf);
				continue;
			} else {
				*ofmtp++ = (wchar_t)c;
				break;
			}
		}
		goto nextc;
	}
	if (fmtsave != NULL)
		free(fmtsave);
	/*
	 * If printing to a character buffer then make sure it is
	 * null-terminated and only uses as much space as required.
	 */
	if (bptr != (wchar_t *)NULL) {
		*bptr = '\0';
		*cp = erealloc(*cp, (length+1) * sizeof (wchar_t));
	}
	return (length);
}

/*
 * Return the next argument from the list.
 */
static NODE *
nextarg(NODE **npp)
{
	NODE *np;

	if ((np = getlist(npp)) == NNULL)
		awkerr(gettext("insufficient arguments to printf or sprintf"));
	if (isleaf(np->n_flags) && np->n_type == PARM)
		return (np->n_next);
	return (np);
}


/*
 * Check and adjust the length of the buffer that has been passed in
 * to make sure that it has space to accomodate the sequence string
 * described in fmtstr. This routine is used by xprintf() to allow
 * for arbitrarily long sprintf() strings.
 *
 * bp		= start of current buffer
 * len		= length of current buffer
 * offset	= offset in current buffer
 * fmtstr	= format string to check
 * slen		= size of string for %s formats
 */
static void
adjust_buf(wchar_t **bp, int *len, wchar_t **offset, char *fmtstr, size_t slen)
{
	int ioff;
	int width = 0;
	int prec = 0;

	do {
		fmtstr++;
	} while (strchr("-+ 0", *fmtstr) != (char *)0 || *fmtstr == ('#'));
	if (*fmtstr != '*') {
		if (isdigit(*fmtstr)) {
			width = *fmtstr-'0';
			while (isdigit(*++fmtstr))
				width = width * 10 + *fmtstr - '0';
		}
	} else
		fmtstr++;
	if (*fmtstr == '.') {
		if (*++fmtstr != '*') {
			prec = *fmtstr-'0';
			while (isdigit(*++fmtstr))
				prec = prec * 10 + *fmtstr - '0';
		} else
			fmtstr++;
	}
	if (strchr("Llh", *fmtstr) != (char *)0)
		fmtstr++;
	if (*fmtstr == 'S') {
		if (width && slen < width)
			slen = width;
		if (prec && slen > prec)
			slen = prec;
		width = slen+1;
	} else
		if (width == 0)
			width = NUMSIZE;

	if (*offset+ width > *bp+ *len) {
		ioff = *offset-*bp;
		*len += width+1;
		*bp = erealloc(*bp, *len * sizeof (wchar_t));
		*offset = *bp+ioff;
	}
}

static void
awk_putwc(wchar_t c, FILE *fp)
{
	char mb[MB_LEN_MAX];
	size_t mbl;

	if ((mbl = wctomb(mb, c)) > 0) {
		mb[mbl] = '\0';
		(void) fputs(mb, fp);
	} else
		awkerr(gettext("invalid wide character %x"), c);
}
