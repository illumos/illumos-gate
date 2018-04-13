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

/*
 * awk -- mainline, yylex, etc.
 *
 * Based on MKS awk(1) ported to be /usr/xpg4/bin/awk with POSIX/XCU4 changes
 */

#include "awk.h"
#include "y.tab.h"
#include <stdarg.h>
#include <unistd.h>
#include <locale.h>
#include <search.h>

static char	*progfiles[NPFILE];	/* Programmes files for yylex */
static char	**progfilep = &progfiles[0]; /* Pointer to last file */
static wchar_t	*progptr;		/* In-memory programme */
static int	proglen;		/* Length of progptr */
static wchar_t	context[NCONTEXT];	/* Circular buffer of context */
static wchar_t	*conptr = &context[0];	/* context ptr */
static FILE	*progfp;		/* Stdio stream for programme */
static char	*filename;
#ifdef	DEBUG
static int	dflag;
#endif

#define	AWK_EXEC_MAGIC	"<MKS AWKC>"
#define	LEN_EXEC_MAGIC	10

static char	unbal[] = "unbalanced E char";

static void	awkarginit(int c, char **av);
static int	lexid(wint_t c);
static int	lexnumber(wint_t c);
static int	lexstring(wint_t endc);
static int	lexregexp(wint_t endc);

static void	awkvarinit(void);
static wint_t	lexgetc(void);
static void	lexungetc(wint_t c);
static size_t	lexescape(wint_t endc, int regx, int cmd_line_operand);
static void	awkierr(int perr, char *fmt, va_list ap) __NORETURN;
static int	usage(void);
void		strescape(wchar_t *str);
static const char	*toprint(wint_t);
char *_cmdname;
static wchar_t *mbconvert(char *str);

extern int	isclvar(wchar_t *arg);

/*
 * mainline for awk
 */
int
main(int argc, char *argv[])
{
	wchar_t *ap;
	char *cmd;

	cmd = argv[0];
	_cmdname = cmd;

	linebuf = emalloc(NLINE * sizeof (wchar_t));

	/*
	 * At this point only messaging should be internationalized.
	 * numbers are still scanned as in the Posix locale.
	 */
	(void) setlocale(LC_ALL, "");
	(void) setlocale(LC_NUMERIC, "C");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	awkvarinit();
	/* running = 1; */
	while (argc > 1 && *argv[1] == '-') {
		void *save_ptr = NULL;
		ap = mbstowcsdup(&argv[1][1]);
		if (ap == NULL)
			break;
		if (*ap == '\0') {
			free(ap);
			break;
		}
		save_ptr = (void *) ap;
		++argv;
		--argc;
		if (*ap == '-' && ap[1] == '\0')
			break;
		for (; *ap != '\0'; ++ap) {
			switch (*ap) {
#ifdef DEBUG
			case 'd':
				dflag = 1;
				continue;

#endif
			case 'f':
				if (argc < 2) {
					(void) fprintf(stderr,
				gettext("Missing script file\n"));
					return (1);
				}
				*progfilep++ = argv[1];
				--argc;
				++argv;
				continue;

			case 'F':
				if (ap[1] == '\0') {
					if (argc < 2) {
						(void) fprintf(stderr,
				gettext("Missing field separator\n"));
						return (1);
					}
					ap = mbstowcsdup(argv[1]);
					--argc;
					++argv;
				} else
					++ap;
				strescape(ap);
				strassign(varFS, linebuf, FALLOC,
				    wcslen(linebuf));
				break;

			case 'v': {
				wchar_t *vp;
				wchar_t *arg;

				if (argc < 2) {
					(void) fprintf(stderr,
		gettext("Missing variable assignment\n"));
					return (1);
				}
				arg = mbconvert(argv[1]);
				/*
				 * Ensure the variable expression
				 * is valid (correct form).
				 */
				if (((vp = wcschr(arg, '=')) != NULL) &&
				    isclvar(arg)) {
					*vp = '\0';
					strescape(vp+1);
					strassign(vlook(arg), linebuf,
					    FALLOC|FSENSE,
					    wcslen(linebuf));
					*vp = '=';
				} else {
					(void) fprintf(stderr, gettext(
					    "Invalid form for variable "
					    "assignment: %S\n"), arg);
					return (1);
				}
				--argc;
				++argv;
				continue;
			}

			default:
				(void) fprintf(stderr,
				gettext("Unknown option \"-%S\"\n"), ap);
				return (usage());
			}
			break;
		}
		if (save_ptr)
			free(save_ptr);
	}
	if (progfilep == &progfiles[0]) {
		if (argc < 2)
			return (usage());
		filename = "[command line]";	/* BUG: NEEDS TRANSLATION */
		progptr = mbstowcsdup(argv[1]);
		proglen = wcslen(progptr);
		--argc;
		++argv;
	}

	argv[0] = cmd;

	awkarginit(argc, argv);

	/* running = 0; */
	(void) yyparse();

	lineno = 0;
	/*
	 * Ok, done parsing, so now activate the rest of the nls stuff, set
	 * the radix character.
	 */
	(void) setlocale(LC_ALL, "");
	radixpoint = *localeconv()->decimal_point;
	awk();
	/* NOTREACHED */
	return (0);
}

/*
 * Do initial setup of buffers, etc.
 * This must be called before most processing
 * and especially before lexical analysis.
 * Variables initialised here will be overruled by command
 * line parameter initialisation.
 */
static void
awkvarinit()
{
	NODE *np;

	(void) setvbuf(stderr, NULL, _IONBF, 0);

	if ((NIOSTREAM = sysconf(_SC_OPEN_MAX) - 4) <= 0) {
		(void) fprintf(stderr,
	gettext("not enough available file descriptors"));
		exit(1);
	}
	ofiles = (OFILE *)emalloc(sizeof (OFILE)*NIOSTREAM);
#ifdef A_ZERO_POINTERS
	(void) memset((wchar_t *)ofiles, 0, sizeof (OFILE) * NIOSTREAM);
#else
	{
		/* initialize file descriptor table */
		OFILE *fp;
		for (fp = ofiles; fp < &ofiles[NIOSTREAM]; fp += 1) {
			fp->f_fp = FNULL;
					fp->f_mode = 0;
					fp->f_name = (char *)0;
		}
	}
#endif
	constant = intnode((INT)0);

	const0 = intnode((INT)0);
	const1 = intnode((INT)1);
	constundef = emptynode(CONSTANT, 0);
	constundef->n_flags = FSTRING|FVINT;
	constundef->n_string = _null;
	constundef->n_strlen = 0;
	inc_oper = emptynode(ADD, 0);
	inc_oper->n_right = const1;
	asn_oper = emptynode(ADD, 0);
	field0 = node(FIELD, const0, NNULL);

	{
		RESFUNC near*rp;

		for (rp = &resfuncs[0]; rp->rf_name != (LOCCHARP)NULL; ++rp) {
			np = finstall(rp->rf_name, rp->rf_func, rp->rf_type);
		}
	}
	{
		RESERVED near*rp;

		for (rp = &reserved[0]; rp->r_name != (LOCCHARP)NULL; ++rp) {
			switch (rp->r_type) {
			case SVAR:
			case VAR:
				running = 1;
				np = vlook(rp->r_name);
				if (rp->r_type == SVAR)
					np->n_flags |= FSPECIAL;
				if (rp->r_svalue != NULL)
					strassign(np, rp->r_svalue, FSTATIC,
					    (size_t)rp->r_ivalue);
				else {
					constant->n_int = rp->r_ivalue;
					(void) assign(np, constant);
				}
				running = 0;
				break;

			case KEYWORD:
				kinstall(rp->r_name, (int)rp->r_ivalue);
				break;
			}
		}
	}

	varNR = vlook(s_NR);
	varFNR = vlook(s_FNR);
	varNF = vlook(s_NF);
	varOFMT = vlook(s_OFMT);
	varCONVFMT = vlook(s_CONVFMT);
	varOFS = vlook(s_OFS);
	varORS = vlook(s_ORS);
	varRS = vlook(s_RS);
	varFS = vlook(s_FS);
	varARGC = vlook(s_ARGC);
	varSUBSEP = vlook(s_SUBSEP);
	varENVIRON = vlook(s_ENVIRON);
	varFILENAME = vlook(s_FILENAME);
	varSYMTAB = vlook(s_SYMTAB);
	incNR = node(ASG, varNR, node(ADD, varNR, const1));
	incFNR = node(ASG, varFNR, node(ADD, varFNR, const1));
	clrFNR = node(ASG, varFNR, const0);
}

/*
 * Initialise awk ARGC, ARGV variables.
 */
static void
awkarginit(int ac, char **av)
{
	int i;
	wchar_t *cp;

	ARGVsubi = node(INDEX, vlook(s_ARGV), constant);
	running = 1;
	constant->n_int = ac;
	(void) assign(varARGC, constant);
	for (i = 0; i < ac; ++i) {
		cp = mbstowcsdup(av[i]);
		constant->n_int = i;
		strassign(exprreduce(ARGVsubi), cp,
		    FSTATIC|FSENSE, wcslen(cp));
	}
	running = 0;
}

/*
 * Clean up when done parsing a function.
 * All formal parameters, because of a deal (funparm) in
 * yylex, get put into the symbol table in front of any
 * global variable of the same name.  When the entire
 * function is parsed, remove these formal dummy nodes
 * from the symbol table but retain the nodes because
 * the generated tree points at them.
 */
void
uexit(NODE *np)
{
	NODE *formal;

	while ((formal = getlist(&np)) != NNULL)
		delsymtab(formal, 0);
}

/*
 * The lexical analyzer.
 */
int
yylex()
{
	wint_t c, c1;
	int i;
	static int savetoken = 0;
	static int wasfield;
	static int isfuncdef;
	static int nbrace, nparen, nbracket;
	static struct ctosymstruct {
		wint_t c, sym;
	} ctosym[] = {
		{ '|', BAR },		{ '^', CARAT },
		{ '~', TILDE },		{ '<', LANGLE },
		{ '>', RANGLE },	{ '+', PLUSC },
		{ '-', HYPHEN },	{ '*', STAR },
		{ '/', SLASH },		{ '%', PERCENT },
		{ '!', EXCLAMATION },	{ '$', DOLLAR },
		{ '[', LSQUARE },	{ ']', RSQUARE },
		{ '(', LPAREN },	{ ')', RPAREN },
		{ ';', SEMI },		{ '{', LBRACE },
		{ '}', RBRACE },	{   0, 0 }
	};

	if (savetoken) {
		c = savetoken;
		savetoken = 0;
	} else if (redelim != '\0') {
		c = redelim;
		redelim = 0;
		catterm = 0;
		savetoken = c;
		c = lexlast = lexregexp(c);
		goto out;
	} else while ((c = lexgetc()) != WEOF) {
		if (iswalpha(c) || c == '_') {
			c = lexid(c);
		} else if (iswdigit(c) || c == '.') {
			c = lexnumber(c);
		} else if (isWblank(c)) {
			continue;
		} else switch (c) {
#if DOS || OS2
		case 032:		/* ^Z */
			continue;
#endif

		case '"':
			c = lexstring(c);
			break;

		case '#':
			while ((c = lexgetc()) != '\n' && c != WEOF)
				;
			lexungetc(c);
			continue;

		case '+':
			if ((c1 = lexgetc()) == '+')
				c = INC;
			else if (c1 == '=')
				c = AADD;
			else
				lexungetc(c1);
			break;

		case '-':
			if ((c1 = lexgetc()) == '-')
				c = DEC;
			else if (c1 == '=')
				c = ASUB;
			else
				lexungetc(c1);
			break;

		case '*':
			if ((c1 = lexgetc()) == '=')
				c = AMUL;
			else if (c1 == '*') {
				if ((c1 = lexgetc()) == '=')
					c = AEXP;
				else {
					c = EXP;
					lexungetc(c1);
				}
			} else
				lexungetc(c1);
			break;

		case '^':
			if ((c1 = lexgetc()) == '=') {
				c = AEXP;
			} else {
				c = EXP;
				lexungetc(c1);
			}
			break;

		case '/':
			if ((c1 = lexgetc()) == '=' &&
			    lexlast != RE && lexlast != NRE &&
			    lexlast != ';' && lexlast != '\n' &&
			    lexlast != ',' && lexlast != '(')
				c = ADIV;
			else
				lexungetc(c1);
			break;

		case '%':
			if ((c1 = lexgetc()) == '=')
				c = AREM;
			else
				lexungetc(c1);
			break;

		case '&':
			if ((c1 = lexgetc()) == '&')
				c = AND;
			else
				lexungetc(c1);
			break;

		case '|':
			if ((c1 = lexgetc()) == '|')
				c = OR;
			else {
				lexungetc(c1);
				if (inprint)
					c = PIPE;
			}
			break;

		case '>':
			if ((c1 = lexgetc()) == '=')
				c = GE;
			else if (c1 == '>')
				c = APPEND;
			else {
				lexungetc(c1);
				if (nparen == 0 && inprint)
					c = WRITE;
			}
			break;

		case '<':
			if ((c1 = lexgetc()) == '=')
				c = LE;
			else
				lexungetc(c1);
			break;

		case '!':
			if ((c1 = lexgetc()) == '=')
				c = NE;
			else if (c1 == '~')
				c = NRE;
			else
				lexungetc(c1);
			break;

		case '=':
			if ((c1 = lexgetc()) == '=')
				c = EQ;
			else {
				lexungetc(c1);
				c = ASG;
			}
			break;

		case '\n':
			switch (lexlast) {
			case ')':
				if (catterm || inprint) {
					c = ';';
					break;
				}
			/* FALLTHROUGH */
			case AND:
			case OR:
			case COMMA:
			case '{':
			case ELSE:
			case ';':
			case DO:
				continue;

			case '}':
				if (nbrace != 0)
					continue;
				/* FALLTHROUGH */

			default:
				c = ';';
				break;
			}
			break;

		case ELSE:
			if (lexlast != ';') {
				savetoken = ELSE;
				c = ';';
			}
			break;

		case '(':
			++nparen;
			break;

		case ')':
			if (--nparen < 0)
				awkerr(unbal, "()");
			break;

		case '{':
			nbrace++;
			break;

		case '}':
			if (--nbrace < 0) {
				char brk[3];

				brk[0] = '{';
				brk[1] = '}';
				brk[2] = '\0';
				awkerr(unbal, brk);
			}
			if (lexlast != ';') {
				savetoken = c;
				c = ';';
			}
			break;

		case '[':
			++nbracket;
			break;

		case ']':
			if (--nbracket < 0) {
				char brk[3];

				brk[0] = '[';
				brk[1] = ']';
				brk[2] = '\0';
				awkerr(unbal, brk);
			}
			break;

		case '\\':
			if ((c1 = lexgetc()) == '\n')
				continue;
			lexungetc(c1);
			break;

		case ',':
			c = COMMA;
			break;

		case '?':
			c = QUEST;
			break;

		case ':':
			c = COLON;
			break;

		default:
			if (!iswprint(c))
				awkerr(
				    gettext("invalid character \"%s\""),
				    toprint(c));
			break;
		}
		break;
	}

	switch (c) {
	case ']':
		++catterm;
		break;

	case VAR:
		if (catterm) {
			savetoken = c;
			c = CONCAT;
			catterm = 0;
		} else if (!isfuncdef) {
			if ((c1 = lexgetc()) != '(')
				++catterm;
			lexungetc(c1);
		}
		isfuncdef = 0;
		break;

	case PARM:
	case CONSTANT:
		if (catterm) {
			savetoken = c;
			c = CONCAT;
			catterm = 0;
		} else {
			if (lexlast == '$')
				wasfield = 2;
			++catterm;
		}
		break;

	case INC:
	case DEC:
		if (!catterm || lexlast != CONSTANT || wasfield)
			break;

	/* FALLTHROUGH */
	case UFUNC:
	case FUNC:
	case GETLINE:
	case '!':
	case '$':
	case '(':
		if (catterm) {
			savetoken = c;
			c = CONCAT;
			catterm = 0;
		}
		break;

	case '}':
		if (nbrace == 0)
			savetoken = ';';
	/* FALLTHROUGH */
	case ';':
		inprint = 0;
	/* FALLTHROUGH */
	default:
		if (c == DEFFUNC)
			isfuncdef = 1;
		catterm = 0;
	}
	lexlast = c;
	if (wasfield)
		wasfield--;
	/*
	 * Map character constants to symbolic names.
	 */
	for (i = 0; ctosym[i].c != 0; i++)
		if (c == ctosym[i].c) {
			c = ctosym[i].sym;
			break;
		}
out:
#ifdef DEBUG
	if (dflag)
		(void) printf("%d\n", (int)c);
#endif
	return ((int)c);
}

/*
 * Read a number for the lexical analyzer.
 * Input is the first character of the number.
 * Return value is the lexical type.
 */
static int
lexnumber(wint_t c)
{
	wchar_t *cp;
	int dotfound = 0;
	int efound = 0;
	INT number;

	cp = linebuf;
	do {
		if (iswdigit(c))
			;
		else if (c == '.') {
			if (dotfound++)
				break;
		} else if (c == 'e' || c == 'E') {
			if ((c = lexgetc()) != '-' && c != '+') {
				lexungetc(c);
				c = 'e';
			} else
				*cp++ = 'e';
			if (efound++)
				break;
		} else
			break;
		*cp++ = c;
	} while ((c = lexgetc()) != WEOF);
	*cp = '\0';
	if (dotfound && cp == linebuf+1)
		return (DOT);
	lexungetc(c);
	errno = 0;
	if (!dotfound && !efound &&
	    ((number = wcstol(linebuf, (wchar_t **)0, 10)), errno != ERANGE))
		yylval.node = intnode(number);
	else
		yylval.node = realnode((REAL)wcstod(linebuf, (wchar_t **)0));
	return (CONSTANT);
}

/*
 * Read an identifier.
 * Input is first character of identifier.
 * Return VAR.
 */
static int
lexid(wint_t c)
{
	wchar_t *cp;
	size_t i;
	NODE *np;

	cp = linebuf;
	do {
		*cp++ = c;
		c = lexgetc();
	} while (iswalpha(c) || iswdigit(c) || c == '_');
	*cp = '\0';
	lexungetc(c);
	yylval.node = np = vlook(linebuf);

	switch (np->n_type) {
	case KEYWORD:
		switch (np->n_keywtype) {
		case PRINT:
		case PRINTF:
			++inprint;
			/* FALLTHROUGH */
		default:
			return ((int)np->n_keywtype);
		}
		/* NOTREACHED */

	case ARRAY:
	case VAR:
		/*
		 * If reading the argument list, create a dummy node
		 * for the duration of that function. These variables
		 * can be removed from the symbol table at function end
		 * but they must still exist because the execution tree
		 * knows about them.
		 */
		if (funparm) {
do_funparm:
			np = emptynode(PARM, i = (cp-linebuf));
			np->n_flags = FSTRING;
			np->n_string = _null;
			np->n_strlen = 0;
			(void) memcpy(np->n_name, linebuf,
			    (i+1) * sizeof (wchar_t));
			addsymtab(np);
			yylval.node = np;
		} else if (np == varNF || (np == varFS &&
		    (!doing_begin || begin_getline))) {
			/*
			 * If the user program references NF or sets
			 * FS either outside of a begin block or
			 * in a begin block after a getline then the
			 * input line will be split immediately upon read
			 * rather than when a field is first referenced.
			 */
			needsplit = 1;
		} else if (np == varENVIRON)
			needenviron = 1;
	/* FALLTHROUGH */
	case PARM:
		return (VAR);

	case UFUNC:
		/*
		 * It is ok to redefine functions as parameters
		 */
		if (funparm) goto do_funparm;
	/* FALLTHROUGH */
	case FUNC:
	case GETLINE:
		/*
		 * When a getline is encountered, clear the 'doing_begin' flag.
		 * This will force the 'needsplit' flag to be set, even inside
		 * a begin block, if FS is altered. (See VAR case above)
		 */
		if (doing_begin)
			begin_getline = 1;
		return (np->n_type);
	}
	/* NOTREACHED */
	return (0);
}

/*
 * Read a string for the lexical analyzer.
 * `endc' terminates the string.
 */
static int
lexstring(wint_t endc)
{
	size_t length = lexescape(endc, 0, 0);

	yylval.node = stringnode(linebuf, FALLOC, length);
	return (CONSTANT);
}

/*
 * Read a regular expression.
 */
static int
lexregexp(wint_t endc)
{
	(void) lexescape(endc, 1, 0);
	yylval.node = renode(linebuf);
	return (URE);
}

/*
 * Process a string, converting the escape characters as required by
 * 1003.2. The processed string ends up in the global linebuf[]. This
 * routine also changes the value of 'progfd' - the program file
 * descriptor, so it should be used with some care. It is presently used to
 * process -v (awk1.c) and var=str type arguments (awk2.c, nextrecord()).
 */
void
strescape(wchar_t *str)
{
	progptr = str;
	proglen = wcslen(str) + 1;	/* Include \0 */
	(void) lexescape('\0', 0, 1);
	progptr = NULL;
}

/*
 * Read a string or regular expression, terminated by ``endc'',
 * for lexical analyzer, processing escape sequences.
 * Return string length.
 */
static size_t
lexescape(wint_t endc, int regx, int cmd_line_operand)
{
	static char nlre[256];
	static char nlstr[256];
	static char eofre[256];
	static char eofstr[256];
	int first_time = 1;
	wint_t c;
	wchar_t *cp;
	int n, max;

	if (first_time == 1) {
		(void) strcpy(nlre, gettext("Newline in regular expression\n"));
		(void) strcpy(nlstr, gettext("Newline in string\n"));
		(void) strcpy(eofre, gettext("EOF in regular expression\n"));
		(void) strcpy(eofstr, gettext("EOF in string\n"));
		first_time = 0;
	}

	cp = linebuf;
	while ((c = lexgetc()) != endc) {
		if (c == '\n')
			awkerr(regx ? nlre : nlstr);
		if (c == '\\') {
			switch (c = lexgetc(), c) {
			case '\\':
				if (regx)
					*cp++ = '\\';
				break;

			case '/':
				c = '/';
				break;

			case 'n':
				c = '\n';
				break;

			case 'b':
				c = '\b';
				break;

			case 't':
				c = '\t';
				break;

			case 'r':
				c = '\r';
				break;

			case 'f':
				c = '\f';
				break;

			case 'v':
				c = '\v';
				break;

			case 'a':
				c = (char)0x07;
				break;

			case 'x':
				n = 0;
				while (iswxdigit(c = lexgetc())) {
					if (iswdigit(c))
						c -= '0';
					else if (iswupper(c))
						c -= 'A'-10;
					else
						c -= 'a'-10;
					n = (n<<4) + c;
				}
				lexungetc(c);
				c = n;
				break;

			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
#if 0
/*
 * Posix.2 draft 10 disallows the use of back-referencing - it explicitly
 * requires processing of the octal escapes both in strings and
 * regular expressions. The following code is disabled instead of
 * removed as back-referencing may be reintroduced in a future draft
 * of the standard.
 */
				/*
				 * For regular expressions, we disallow
				 * \ooo to mean octal character, in favour
				 * of back referencing.
				 */
				if (regx) {
					*cp++ = '\\';
					break;
				}
#endif
				max = 3;
				n = 0;
				do {
					n = (n<<3) + c-'0';
					if ((c = lexgetc()) > '7' || c < '0')
						break;
				} while (--max);
				lexungetc(c);
				/*
				 * an octal escape sequence must have at least
				 * 2 digits after the backslash, otherwise
				 * it gets passed straight thru for possible
				 * use in backreferencing.
				 */
				if (max == 3) {
					*cp++ = '\\';
					n += '0';
				}
				c = n;
				break;

			case '\n':
				continue;

			default:
				if (c != endc || cmd_line_operand) {
					*cp++ = '\\';
					if (c == endc)
						lexungetc(c);
				}
			}
		}
		if (c == WEOF)
			awkerr(regx ? eofre : eofstr);
		*cp++ = c;
	}
	*cp = '\0';
	return (cp - linebuf);
}

/*
 * Build a regular expression NODE.
 * Argument is the string holding the expression.
 */
NODE *
renode(wchar_t *s)
{
	NODE *np;
	int n;

	np = emptynode(RE, 0);
	np->n_left = np->n_right = NNULL;
	if ((n = REGWCOMP(&np->n_regexp, s)) != REG_OK) {
		int m;
		char *p;

		m = REGWERROR(n, np->n_regexp, NULL, 0);
		p = (char *)emalloc(m);
		REGWERROR(n, np->n_regexp, p, m);
		awkerr("/%S/: %s", s, p);
	}
	return (np);
}
/*
 * Get a character for the lexical analyser routine.
 */
static wint_t
lexgetc()
{
	wint_t c;
	static char **files = &progfiles[0];

	if (progfp != FNULL && (c = fgetwc(progfp)) != WEOF)
		;
	else {
		if (progptr != NULL) {
			if (proglen-- <= 0)
				c = WEOF;
			else
				c = *progptr++;
		} else {
			if (progfp != FNULL) {
				if (progfp != stdin)
					(void) fclose(progfp);
				else
					clearerr(progfp);
				progfp = FNULL;
			}
			if (files < progfilep) {
				filename = *files++;
				lineno = 1;
				if (filename[0] == '-' && filename[1] == '\0')
					progfp = stdin;
				else if ((progfp = fopen(filename, r))
				    == FNULL) {
					(void) fprintf(stderr,
				gettext("script file \"%s\""), filename);
					exit(1);
				}
				c = fgetwc(progfp);
			}
		}
	}
	if (c == '\n')
		++lineno;
	if (conptr >= &context[NCONTEXT])
		conptr = &context[0];
	if (c != WEOF)
		*conptr++ = c;
	return (c);
}

/*
 * Return a character for lexical analyser.
 * Only one returned character is (not enforced) legitimite.
 */
static void
lexungetc(wint_t c)
{
	if (c == '\n')
		--lineno;
	if (c != WEOF) {
		if (conptr == &context[0])
			conptr = &context[NCONTEXT];
		*--conptr = '\0';
	}
	if (progfp != FNULL) {
		(void) ungetwc(c, progfp);
		return;
	}
	if (c == WEOF)
		return;
	*--progptr = c;
	proglen++;
}

/*
 * Syntax errors during parsing.
 */
void
yyerror(char *s, ...)
{
	if (lexlast == FUNC || lexlast == GETLINE || lexlast == KEYWORD)
		if (lexlast == KEYWORD)
			awkerr(gettext("inadmissible use of reserved keyword"));
		else
			awkerr(gettext("attempt to redefine builtin function"));
	awkerr(s);
}

/*
 * Error routine for all awk errors.
 */
/* ARGSUSED */
void
awkerr(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	awkierr(0, fmt, args);
	va_end(args);
}

/*
 * Error routine like "awkerr" except that it prints out
 * a message that includes an errno-specific indication.
 */
/* ARGSUSED */
void
awkperr(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	awkierr(1, fmt, args);
	va_end(args);
}

/*
 * Common internal routine for awkerr, awkperr
 */
static void
awkierr(int perr, char *fmt, va_list ap)
{
	static char sep1[] = "\n>>>\t";
	static char sep2[] = "\t<<<";
	int saveerr = errno;

	(void) fprintf(stderr, "%s: ", _cmdname);
	if (running) {
		(void) fprintf(stderr, gettext("line %u ("),
		    curnode == NNULL ? 0 : curnode->n_lineno);
		if (phase == 0)
			(void) fprintf(stderr, "NR=%lld): ",
			    (INT)exprint(varNR));
		else
			(void) fprintf(stderr, "%s): ",
			    phase == BEGIN ? s_BEGIN : s_END);
	} else if (lineno != 0) {
		(void) fprintf(stderr, gettext("file \"%s\": "), filename);
		(void) fprintf(stderr, gettext("line %u: "), lineno);
	}
	(void) vfprintf(stderr, gettext(fmt), ap);
	if (perr == 1)
		(void) fprintf(stderr, ": %s", strerror(saveerr));
	if (perr != 2 && !running) {
		wchar_t *cp;
		int n;
		int c;

		(void) fprintf(stderr, gettext("  Context is:%s"), sep1);
		cp = conptr;
		n = NCONTEXT;
		do {
			if (cp >= &context[NCONTEXT])
				cp = &context[0];
			if ((c = *cp++) != '\0')
				(void) fputs(c == '\n' ? sep1 : toprint(c),
				    stderr);
		} while (--n != 0);
		(void) fputs(sep2, stderr);
	}
	(void) fprintf(stderr, "\n");
	exit(1);
}

wchar_t *
emalloc(unsigned n)
{
	wchar_t *cp;

	if ((cp = malloc(n)) == NULL)
		awkerr(nomem);
	return (cp);
}

wchar_t *
erealloc(wchar_t *p, unsigned n)
{
	wchar_t *cp;

	if ((cp = realloc(p, n)) == NULL)
		awkerr(nomem);
	return (cp);
}


/*
 * usage message for awk
 */
static int
usage()
{
	(void) fprintf(stderr, gettext(
"Usage:	awk [-F ERE] [-v var=val] 'program' [var=val ...] [file ...]\n"
"	awk [-F ERE] -f progfile ... [-v var=val] [var=val ...] [file ...]\n"));
	return (2);
}


static wchar_t *
mbconvert(char *str)
{
	static wchar_t *op = 0;

	if (op != 0)
		free(op);
	return (op = mbstowcsdup(str));
}

char *
mbunconvert(wchar_t *str)
{
	static char *op = 0;

	if (op != 0)
		free(op);
	return (op = wcstombsdup(str));
}

/*
 * Solaris port - following functions are typical MKS functions written
 * to work for Solaris.
 */

wchar_t *
mbstowcsdup(char *s)
{
	int n;
	wchar_t *w;

	n = strlen(s) + 1;
	if ((w = (wchar_t *)malloc(n * sizeof (wchar_t))) == NULL)
		return (NULL);

	if (mbstowcs(w, s, n) == (size_t)-1)
		return (NULL);
	return (w);

}

char *
wcstombsdup(wchar_t *w)
{
	int n;
	char *mb;

	/* Fetch memory for worst case string length */
	n = wslen(w) + 1;
	n *= MB_CUR_MAX;
	if ((mb = (char *)malloc(n)) == NULL) {
		return (NULL);
	}

	/* Convert the string */
	if ((n = wcstombs(mb, w, n)) == -1) {
		int saverr = errno;

		free(mb);
		errno = saverr;
		return (0);
	}

	/* Shrink the string down */
	if ((mb = (char *)realloc(mb, strlen(mb)+1)) == NULL)  {
		return (NULL);
	}
	return (mb);
}

/*
 * The upe_ctrls[] table contains the printable 'control-sequences' for the
 * character values 0..31 and 127.  The first entry is for value 127, thus the
 * entries for the remaining character values are from 1..32.
 */
static const char *const upe_ctrls[] =
{
	"^?",
	"^@",  "^A",  "^B",  "^C",  "^D",  "^E",  "^F",  "^G",
	"^H",  "^I",  "^J",  "^K",  "^L",  "^M",  "^N",  "^O",
	"^P",  "^Q",  "^R",  "^S",  "^T",  "^U",  "^V",  "^W",
	"^X",  "^Y",  "^Z",  "^[",  "^\\", "^]",  "^^",  "^_"
};


/*
 * Return a printable string corresponding to the given character value.  If
 * the character is printable, simply return it as the string.  If it is in
 * the range specified by table 5-101 in the UPE, return the corresponding
 * string.  Otherwise, return an octal escape sequence.
 */
static const char *
toprint(wchar_t c)
{
	int n, len;
	unsigned char *ptr;
	static char mbch[MB_LEN_MAX+1];
	static char buf[5 * MB_LEN_MAX + 1];

	if ((n = wctomb(mbch, c)) == -1) {
		/* Should never happen */
		(void) sprintf(buf, "\\%x", c);
		return (buf);
	}
	mbch[n] = '\0';
	if (iswprint(c)) {
		return (mbch);
	} else if (c == 127) {
		return (upe_ctrls[0]);
	} else if (c < 32) {
		/* Print as in Table 5-101 in the UPE */
		return (upe_ctrls[c+1]);
	} else {
		/* Print as an octal escape sequence */
		for (len = 0, ptr = (unsigned char *) mbch; 0 < n; --n, ++ptr)
			len += sprintf(buf+len, "\\%03o", *ptr);
	}
	return (buf);
}

static int
wcoff(const wchar_t *astring, const int off)
{
	const wchar_t *s = astring;
	int c = 0;
	char mb[MB_LEN_MAX];

	while (c < off) {
		int n;
		if ((n = wctomb(mb, *s)) == 0)
			break;
		if (n == -1)
			n = 1;
		c += n;
		s++;
	}

	return (s - astring);
}

#define	NREGHASH	64
#define	NREGHOLD	1024	/* max number unused entries */

static int	nregunref;

struct reghashq {
	struct qelem hq;
	struct regcache *regcachep;
};

struct regcache {
	struct qelem	lq;
	wchar_t	*pattern;
	regex_t	re;
	int	refcnt;
	struct reghashq	hash;
};

static struct qelem reghash[NREGHASH], reglink;

/*
 * Generate a hash value of the given wchar string.
 * The hashing method is similar to what Java does for strings.
 */
static uint_t
regtxthash(const wchar_t *str)
{
	int k = 0;

	while (*str != L'\0')
		k = (31 * k) + *str++;

	k += ~(k << 9);
	k ^=  (k >> 14);
	k +=  (k << 4);
	k ^=  (k >> 10);

	return (k % NREGHASH);
}

int
int_regwcomp(REGEXP *r, const wchar_t *pattern)
{
	regex_t re;
	char *mbpattern;
	int ret;
	uint_t key;
	struct qelem *qp;
	struct regcache *rcp;

	key = regtxthash(pattern);
	for (qp = reghash[key].q_forw; qp != NULL; qp = qp->q_forw) {
		rcp = ((struct reghashq *)qp)->regcachep;
		if (*rcp->pattern == *pattern &&
		    wcscmp(rcp->pattern, pattern) == 0)
			break;
	}
	if (qp != NULL) {
		/* update link. put this one at the beginning */
		if (rcp != (struct regcache *)reglink.q_forw) {
			remque(&rcp->lq);
			insque(&rcp->lq, &reglink);
		}
		if (rcp->refcnt == 0)
			nregunref--;	/* no longer unref'ed */
		rcp->refcnt++;
		*(struct regcache **)r = rcp;
		return (REG_OK);
	}

	if ((mbpattern = wcstombsdup((wchar_t *)pattern)) == NULL)
		return (REG_ESPACE);

	ret = regcomp(&re, mbpattern, REG_EXTENDED);

	free(mbpattern);

	if (ret != REG_OK)
		return (ret);

	if ((rcp = malloc(sizeof (struct regcache))) == NULL)
		return (REG_ESPACE);
	rcp->re = re;
	if ((rcp->pattern = wsdup(pattern)) == NULL) {
		regfree(&re);
		free(rcp);
		return (REG_ESPACE);
	}
	rcp->refcnt = 1;
	insque(&rcp->lq, &reglink);
	insque(&rcp->hash.hq, &reghash[key]);
	rcp->hash.regcachep = rcp;

	*(struct regcache **)r = rcp;
	return (ret);
}

void
int_regwfree(REGEXP r)
{
	int	cnt;
	struct qelem *qp, *nqp;
	struct regcache *rcp;

	rcp = (struct regcache *)r;

	if (--rcp->refcnt != 0)
		return;

	/* this cache has no reference */
	if (++nregunref < NREGHOLD)
		return;

	/*
	 * We've got too much unref'ed regex. Free half of least
	 * used regex.
	 */
	cnt = 0;
	for (qp = reglink.q_forw; qp != NULL; qp = nqp) {
		nqp = qp->q_forw;
		rcp = (struct regcache *)qp;
		if (rcp->refcnt != 0)
			continue;

		/* free half of them */
		if (++cnt < (NREGHOLD / 2))
			continue;

		/* detach and free */
		remque(&rcp->lq);
		remque(&rcp->hash.hq);

		/* free up */
		free(rcp->pattern);
		regfree(&rcp->re);
		free(rcp);

		nregunref--;
	}
}

size_t
int_regwerror(int errcode, REGEXP r, char *errbuf, size_t bufsiz)
{
	struct regcache *rcp;

	rcp = (struct regcache *)r;
	return (regerror(errcode, &rcp->re, errbuf, bufsiz));
}

int
int_regwexec(REGEXP r,		/* compiled RE */
    const wchar_t *astring,	/* subject string */
    size_t nsub,		/* number of subexpressions */
    int_regwmatch_t *sub,	/* subexpression pointers */
    int flags)
{
	char *mbs;
	regmatch_t *mbsub = NULL;
	int i;
	struct regcache *rcp;

	if ((mbs = wcstombsdup((wchar_t *)astring)) == NULL)
		return (REG_ESPACE);

	if (nsub > 0 && sub) {
		if ((mbsub = malloc(nsub * sizeof (regmatch_t))) == NULL)
			return (REG_ESPACE);
	}

	rcp = (struct regcache *)r;

	i = regexec(&rcp->re, mbs, nsub, mbsub, flags);

	/* Now, adjust the pointers/counts in sub */
	if (i == REG_OK && nsub > 0 && mbsub) {
		int j, k;

		for (j = 0; j < nsub; j++) {
			regmatch_t *ms = &mbsub[j];
			int_regwmatch_t *ws = &sub[j];

			if ((k = ms->rm_so) >= 0) {
				ws->rm_so = wcoff(astring, k);
				ws->rm_sp = astring + ws->rm_so;
			}
			if ((k = ms->rm_eo) >= 0) {
				ws->rm_eo = wcoff(astring, k);
				ws->rm_ep = astring + ws->rm_eo;
			}
		}
	}

	free(mbs);
	if (mbsub)
		free(mbsub);
	return (i);
}

int
int_regwdosuba(REGEXP rp,	/* compiled RE: Pattern */
    const wchar_t *rpl,		/* replacement string: /rpl/ */
    const wchar_t *src,		/* source string */
    wchar_t **dstp,		/* destination string */
    int len,			/* destination length */
    int *globp)		/* IN: occurence, 0 for all; OUT: substitutions */
{
	wchar_t *dst, *odst;
	const wchar_t *ip, *xp;
	wchar_t *op;
	int i;
	wchar_t c;
	int glob, iglob = *globp, oglob = 0;
#define	NSUB	10
	int_regwmatch_t rm[NSUB], *rmp;
	int flags;
	wchar_t *end;
	int regerr;

/* handle overflow of dst. we need "i" more bytes */
#ifdef OVERFLOW
#undef OVERFLOW
#define	OVERFLOW(i) { \
		int pos = op - dst; \
		dst = (wchar_t *)realloc(odst = dst, \
			(len += len + i) * sizeof (wchar_t)); \
		if (dst == NULL) \
			goto nospace; \
		op = dst + pos; \
		end = dst + len; \
	}
#endif

	*dstp = dst = (wchar_t *)malloc(len * sizeof (wchar_t));
	if (dst == NULL)
		return (REG_ESPACE);

	if (rp == NULL || rpl == NULL || src == NULL || dst ==  NULL)
		return (REG_EFATAL);

	glob = 0;	/* match count */
	ip = src;	/* source position */
	op = dst;	/* destination position */
	end = dst + len;

	flags = 0;
	while ((regerr = int_regwexec(rp, ip, NSUB, rm, flags)) == REG_OK) {
		/* Copy text preceding match */
		if (op + (i = rm[0].rm_sp - ip) >= end)
			OVERFLOW(i)
		while (i--)
			*op++ = *ip++;

		if (iglob == 0 || ++glob == iglob) {
			oglob++;
			xp = rpl;		/* do substitute */
		} else
			xp = L"&";		/* preserve text */

		/* Perform replacement of matched substing */
		while ((c = *xp++) != '\0') {
			rmp = NULL;
			if (c == '&')
				rmp = &rm[0];
			else if (c == '\\') {
				if ('0' <= *xp && *xp <= '9')
					rmp = &rm[*xp++ - '0'];
				else if (*xp != '\0')
					c = *xp++;
			}

			if (rmp ==  NULL) {	/* Ordinary character. */
				*op++ = c;
				if (op >= end)
					OVERFLOW(1)
			} else if (rmp->rm_sp != NULL && rmp->rm_ep != NULL) {
				ip = rmp->rm_sp;
				if (op + (i = rmp->rm_ep - rmp->rm_sp) >= end)
					OVERFLOW(i)
				while (i--)
					*op++ = *ip++;
			}
		}

		ip = rm[0].rm_ep;
		if (*ip == '\0')	/* If at end break */
			break;
		else if (rm[0].rm_sp == rm[0].rm_ep) {
			/* If empty match copy next char */
			*op++ = *ip++;
			if (op >= end)
				OVERFLOW(1)
		}
		flags = REG_NOTBOL;
	}

	if (regerr != REG_OK && regerr != REG_NOMATCH)
		return (regerr);

	/* Copy rest of text */
	if (op + (i =  wcslen(ip)) >= end)
		OVERFLOW(i)
	while (i--)
		*op++ = *ip++;
	*op++ = '\0';

	if ((*dstp = dst = (wchar_t *)realloc(odst = dst,
	    sizeof (wchar_t) * (size_t)(op - dst))) == NULL) {
nospace:
		free(odst);
		return (REG_ESPACE);
	}

	*globp = oglob;

	return ((oglob == 0) ? REG_NOMATCH : REG_OK);
}
