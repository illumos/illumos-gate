/*
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	All Rights Reserved	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 *   Modify ctags to handle C++ in C_entries(), etc:
 *	-  Handles C++ comment token "//"
 *	-  Handles C++ scope operator "::".
 *		This helps to distinguish between xyz()
 *	   definition and X::xyz() definition.
 *	-  Recognizes C++ reserved word "class" in typedef processing
 *		(for "-t" option)
 *	-  Handles Sun C++ special file name extensions: .c, .C, .cc, and .cxx.
 *	-  Handles overloaded unary/binary operator names
 *   Doesn't handle yet:
 *	-  inline functions in class definition (currently they get
 *		swallowed within a class definition)
 *	-  Tags with scope operator :: with spaces in between,
 *		e.g. classz ::afunc
 *
 *   Enhance operator functions support:
 *	-  Control flow involving operator tokens scanning are
 *	   consistent with that of other function tokens - original
 *	   hacking method for 2.0 is removed.  This will accurately
 *	   identify tags for declarations of the form 'operator+()'
 *	   (bugid 1027806) as well as allowing spaces in between
 *	   'operator' and 'oprtk', e.g. 'operator + ()'.
 *
 */

#ifndef lint
char copyright[] = "@(#) Copyright (c) 1980 Regents of the University of "
			"California.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <ctype.h>
#include <locale.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>

/*
 * ctags: create a tags file
 */

#define	bool	char

#define	TRUE	(1)
#define	FALSE	(0)

#define	CPFLAG	3			/* # of bytes in a flag		*/

#define	iswhite(arg)	(_wht[arg])	/* T if char is white		*/
#define	begtoken(arg)	(_btk[arg])	/* T if char can start token	*/
#define	intoken(arg)	(_itk[arg])	/* T if char can be in token	*/
#define	endtoken(arg)	(_etk[arg])	/* T if char ends tokens	*/
#define	isgood(arg)	(_gd[arg])	/* T if char can be after ')'	*/

#define	optoken(arg)	(_opr[arg])	/* T if char can be		*/
					/* an overloaded operator token	*/

#define	max(I1, I2)	(I1 > I2 ? I1 : I2)

struct	nd_st {			/* sorting structure			*/
	char	*entry;			/* function or type name	*/
	char	*file;			/* file name			*/
	bool	f;			/* use pattern or line no	*/
	int	lno;			/* for -x option		*/
	char	*pat;			/* search pattern		*/
	bool	been_warned;		/* set if noticed dup		*/
	struct	nd_st	*left, *right;	/* left and right sons		*/
};

long	ftell();
typedef	struct	nd_st	NODE;

static bool
	number,				/* T if on line starting with #	*/
	gotone,				/* found a func already on line	*/
					/* boolean "func" (see init)	*/
	_wht[0177], _etk[0177], _itk[0177], _btk[0177], _gd[0177];

/* boolean array for overloadable operator symbols			*/
static bool	_opr[0177];

	/*
	 * typedefs are recognized using a simple finite automata,
	 * tydef is its state variable.
	 */
typedef enum {none, begin, begin_rec, begin_tag, middle, end } TYST;

static TYST tydef = none;

static char	searchar = '/';		/* use /.../ searches		*/

static int	lineno;			/* line number of current line */
static char
	line[4*BUFSIZ],		/* current input line			*/
	*curfile,		/* current input file name		*/
	*outfile = "tags",	/* output file				*/
	*white	= " \f\t\n",	/* white chars				*/
	*endtk	= " \t\n\"'#()[]{}=-+%*/&|^~!<>;,.:?",
				/* token ending chars			*/
	*begtk	= "ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz",
				/* token starting chars			*/
	*intk	= "ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"
		    "0123456789",
				/* valid in-token chars			*/
	*notgd	= ",;";		/* non-valid after-function chars	*/

static char	*oprtk	= " =-+%*/&|^~!<>[]()";	/* overloadable operators */

static int	file_num;	/* current file number			*/
static int	aflag;		/* -a: append to tags */

#ifndef XPG4			/* XPG4: handle typedefs by default	*/
static int	tflag;		/* -t: create tags for typedefs		*/
#endif /*  !XPG4 */

static int	uflag;		/* -u: update tags			*/
static int	wflag;		/* -w: suppress warnings		*/
static int	vflag;		/* -v: create vgrind style index output */
static int	xflag;		/* -x: create cxref style output	*/

static char	lbuf[LINE_MAX];

static FILE
	*inf,			/* ioptr for current input file		*/
	*outf;			/* ioptr for tags file			*/

static long	lineftell;	/* ftell after getc( inf ) == '\n'	*/

static NODE	*head;		/* the head of the sorted binary tree	*/

#ifdef __STDC__
char	*strrchr(), *strchr();
#else
char	*rindex(), *index();
#endif

static int	infile_fail;	/* Count of bad opens. Fix bug ID #1082298 */

static char	*dbp = lbuf;
static int	pfcnt;

static int	mac;		/* our modified argc, after parseargs() */
static char	**mav;		/* our modified argv, after parseargs() */


/* our local functions:							*/
static void	init();
static void	find_entries(char *file);
static void	pfnote();
static void	C_entries();
static int	start_entry(char **lp, char *token, int *f);
static void	Y_entries();
static char	*toss_comment(char *start);
static void	getaline(long int where);
static void	free_tree(NODE *node);
static void	add_node(NODE *node, NODE *cur_node);
static void	put_entries(NODE *node);
static int	PF_funcs(FILE *fi);
static int	tail(char *cp);
static void	takeprec();
static void	getit();
static char	*savestr(char *cp);
static void	L_funcs(FILE *fi);
static void	L_getit(int special);
static int	striccmp(char *str, char *pat);
static int	first_char();
static void	toss_yysec();
static void	Usage();
static void	parseargs(int ac, char **av);

int
main(int ac, char *av[])
{
	int i;
	char cmd[100];

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	parseargs(ac, av);

	while ((i = getopt(mac, mav, "aBFtuvwxf:")) != EOF) {
		switch (i) {
		case 'a':	/* -a: Append output to existing tags file */
			aflag++;
			break;

		case 'B':	/* -B: Use backward search patterns (?...?) */
			searchar = '?';
			break;

		case 'F':	/* -F: Use forward search patterns (/.../) */
			searchar = '/';
			break;

		case 't':	/* -t: Create tags for typedefs.	*/
				/* for XPG4 , we silently ignore "-t".	*/
#ifndef XPG4
			tflag++;
#endif /*  !XPG4 */
			break;

		case 'u':	/* -u: Update the specified tags file	*/
			uflag++;
			break;

		case 'v':	/* -v: Index listing on stdout		*/
			vflag++;
			xflag++;
			break;

		case 'w':	/* -w: Suppress warnings		*/
			wflag++;
			break;

		case 'x':	/* -x: Produce a simple index		*/
			xflag++;
			break;

		case 'f':	/* -f tagsfile: output to tagsfile	*/
			outfile = strdup(optarg);
			break;

		default:
			Usage();	/* never returns		*/
			break;
		}
	}

	/* if we didn't specify any source code to parse, complain and die. */
	if (optind == mac) {
		Usage();	/* never returns		*/
	}


	init();			/* set up boolean "functions"		*/
	/*
	 * loop through files finding functions
	 */
	for (file_num = optind; file_num < mac; file_num++)
		find_entries(mav[file_num]);

	if (xflag) {
		put_entries(head);
		exit(infile_fail > 0 ? 2 : 0); /* Fix for 1082298 */
	}
	if (uflag) {
		for (i = 1; i < mac; i++) {
			(void) sprintf(cmd,
			"mv %s OTAGS;fgrep -v '\t%s\t' OTAGS >%s;rm OTAGS",
				outfile, mav[i], outfile);
			(void) system(cmd);
		}
		aflag++;
	}
	outf = fopen(outfile, aflag ? "a" : "w");
	if (outf == NULL) {
		perror(outfile);
		exit(1);
	}
	put_entries(head);
	(void) fclose(outf);
	if (uflag) {
		(void) sprintf(cmd, "sort %s -o %s", outfile, outfile);
		(void) system(cmd);
	}
	return (infile_fail > 0 ? 2 : 0); /* Fix for #1082298 */
}

/*
 * This routine sets up the boolean psuedo-functions which work
 * by seting boolean flags dependent upon the corresponding character
 * Every char which is NOT in that string is not a white char.  Therefore,
 * all of the array "_wht" is set to FALSE, and then the elements
 * subscripted by the chars in "white" are set to TRUE.  Thus "_wht"
 * of a char is TRUE if it is the string "white", else FALSE.
 */
static void
init()
{
	char	*sp;
	int	i;

	for (i = 0; i < 0177; i++) {
		_wht[i] = _etk[i] = _itk[i] = _btk[i] = FALSE;
		_opr[i] = FALSE;	/* initialize boolean		*/
					/* array of operator symbols	*/
		_gd[i] = TRUE;
	}
	for (sp = white; *sp; sp++)
		_wht[*sp] = TRUE;
	for (sp = endtk; *sp; sp++)
		_etk[*sp] = TRUE;
	for (sp = intk; *sp; sp++)
		_itk[*sp] = TRUE;
	for (sp = begtk; *sp; sp++)
		_btk[*sp] = TRUE;

	/* mark overloadable operator symbols				*/
	for (sp = oprtk; *sp; sp++)
		_opr[*sp] = TRUE;

	for (sp = notgd; *sp; sp++)
		_gd[*sp] = FALSE;
}

/*
 * This routine opens the specified file and calls the function
 * which finds the function and type definitions.
 */
static void
find_entries(file)
char	*file;
{
	char *cp;
	struct stat st;

	/* skip anything that isn't a regular file */
	if (stat(file, &st) == 0 && !S_ISREG(st.st_mode))
		return;

	if ((inf = fopen(file, "r")) == NULL) {
		perror(file);
		infile_fail++;		/* Count bad opens. ID #1082298 */
		return;
	}
	curfile = savestr(file);
	lineno = 0;
#ifdef __STDC__
	cp = strrchr(file, '.');
#else
	cp = rindex(file, '.');
#endif
	/* .l implies lisp or lex source code */
	if (cp && cp[1] == 'l' && cp[2] == '\0') {
#ifdef __STDC__
		if (strchr(";([", first_char()) != NULL)	/* lisp */
#else
		if (index(";([", first_char()) != NULL)		/* lisp */
#endif
		{
			L_funcs(inf);
			(void) fclose(inf);
			return;
		} else {					/* lex */
			/*
			 * throw away all the code before the second "%%"
			 */
			toss_yysec();
			getaline(lineftell);
			pfnote("yylex", lineno, TRUE);
			toss_yysec();
			C_entries();
			(void) fclose(inf);
			return;
		}
	}
	/* .y implies a yacc file */
	if (cp && cp[1] == 'y' && cp[2] == '\0') {
		toss_yysec();
		Y_entries();
		C_entries();
		(void) fclose(inf);
		return;
	}

	/*
	 * Add in file name extension support for Sun C++ which
	 * permits .C/.c (AT&T), .cc (G++) and .cxx (Gloksp.)
	 */

	/* if not a .c, .C, .cc, .cxx or .h file, try fortran */
	if (cp && (cp[1] != 'C' && cp[1] != 'c' && cp[1] != 'h') &&
	    cp[2] == '\0' && (strcmp(cp, ".cc") == 0) &&
	    (strcmp(cp, ".cxx") == 0)) {
		if (PF_funcs(inf) != 0) {
			(void) fclose(inf);
			return;
		}
		rewind(inf);	/* no fortran tags found, try C */
	}
	C_entries();
	(void) fclose(inf);
}

static void
pfnote(name, ln, f)
char	*name;
int	ln;
bool	f;		/* f == TRUE when function */
{
	char *fp;
	NODE *np;
	char *nametk;	/* hold temporary tokens from name */
	char nbuf[BUFSIZ];

	if ((np = malloc(sizeof (NODE))) == NULL) {
		(void) fprintf(stderr,
				gettext("ctags: too many entries to sort\n"));
		put_entries(head);
		free_tree(head);
		head = np = (NODE *) malloc(sizeof (NODE));
	}
	if (xflag == 0 && (strcmp(name, "main") == 0)) {
#ifdef __STDC__
		fp = strrchr(curfile, '/');
#else
		fp = rindex(curfile, '/');
#endif
		if (fp == 0)
			fp = curfile;
		else
			fp++;
		(void) sprintf(nbuf, "M%s", fp);
#ifdef __STDC__
		fp = strrchr(nbuf, '.');
#else
		fp = rindex(nbuf, '.');
#endif
		/* Chop off .cc and .cxx as well as .c, .h, etc		*/
		if (fp && ((fp[2] == 0) || (fp[2] == 'c' && fp[3] == 0) ||
			    (fp[3] == 'x' && fp[4] == 0)))
			*fp = 0;
		name = nbuf;
	}

	/* remove in-between blanks operator function tags */
#ifdef __STDC__
	if (strchr(name, ' ') != NULL)
#else
	if (index(name, ' ') != NULL)
#endif
	{
		(void) strcpy(name, strtok(name, " "));
		while (nametk = strtok(0, " "))
			(void) strcat(name, nametk);
	}
	np->entry = savestr(name);
	np->file = curfile;
	np->f = f;
	np->lno = ln;
	np->left = np->right = 0;
	if (xflag == 0) {
		lbuf[50] = 0;
		(void) strcat(lbuf, "$");
		lbuf[50] = 0;
	}
	np->pat = savestr(lbuf);
	if (head == NULL)
		head = np;
	else
		add_node(np, head);
}

/*
 * This routine finds functions and typedefs in C syntax and adds them
 * to the list.
 */
static void
C_entries()
{
	int c;
	char *token, *tp;
	bool incomm, inquote, inchar, midtoken, isoperator, optfound;
	int level;
	char *sp;
	char tok[BUFSIZ];
	long int tokftell;

	number = gotone = midtoken = inquote = inchar =
	incomm = isoperator = optfound = FALSE;

	level = 0;
	sp = tp = token = line;
	lineno++;
	lineftell = tokftell = ftell(inf);
	for (;;) {
		*sp = c = getc(inf);
		if (feof(inf))
			break;
		if (c == '\n') {
			lineftell = ftell(inf);
			lineno++;
		} else if (c == '\\') {
			c = *++sp = getc(inf);
			if ((c == '\n') || (c == EOF)) { /* c == EOF, 1091005 */
				lineftell = ftell(inf);
				lineno++;
				c = ' ';
			}
		} else if (incomm) {
			if (c == '*') {
				while ((*++sp = c = getc(inf)) == '*')
					continue;

				/* c == EOF 1091005			*/
				if ((c == '\n') || (c == EOF)) {
					lineftell = ftell(inf);
					lineno++;
				}

				if (c == '/')
					incomm = FALSE;
			}
		} else if (inquote) {
			/*
			 * Too dumb to know about \" not being magic, but
			 * they usually occur in pairs anyway.
			 */
			if (c == '"')
				inquote = FALSE;
			continue;
		} else if (inchar) {
			if (c == '\'')
				inchar = FALSE;
			continue;
		} else if (midtoken == TRUE) {	/* if white space omitted */
			goto dotoken;
		} else switch (c) {
		    case '"':
			inquote = TRUE;
			continue;
		    case '\'':
			inchar = TRUE;
			continue;
		    case '/':
			*++sp = c = getc(inf);
			/* Handles the C++ comment token "//"		*/
			if (c == '*')
				incomm = TRUE;
			else if (c == '/') {
				/*
				 * Skip over all the characters after
				 * "//" until a newline character. Now also
				 * includes fix for 1091005, check for EOF.
				 */
				do  {
					c = getc(inf);
				/* 1091005:				*/
				} while ((c != '\n') && (c != EOF));


				/*
				 * Fixed bugid 1030014
				 * Return the current position of the
				 * file after the newline.
				 */
				lineftell = ftell(inf);
				lineno++;
				*--sp = c;
			}
			else
				(void) ungetc(*sp, inf);
			continue;
		    case '#':
			if (sp == line)
				number = TRUE;
			continue;
		    case '{':
			if ((tydef == begin_rec) || (tydef == begin_tag)) {
				tydef = middle;
			}
			level++;
			continue;
		    case '}':
			/*
			 * Heuristic for function or structure end;
			 * common for #ifdef/#else blocks to add extra "{"
			 */
			if (sp == line)
				level = 0;	/* reset */
			else
				level--;
			if (!level && tydef == middle) {
				tydef = end;
			}
			if (!level && tydef == none) /* Fix for #1034126 */
				goto dotoken;
			continue;
		}

dotoken:


		if (!level && !inquote && !incomm && gotone == FALSE) {
			if (midtoken) {
				if (endtoken(c)) {

				/*
				 *
				 *    ':'  +---> ':' -> midtok
				 *
				 *    +---> operator{+,-, etc} -> midtok
				 *		(continue)
				 *    +---> endtok
				 */
		/*
		 * Enhance operator function support and
		 *	fix bugid 1027806
		 *
		 *  For operator token, scanning will continue until
		 *  '(' is found.  Spaces between 'operater' and
		 *  'oprtk' are allowed (e.g. 'operator + ()'), but
		 *  will be removed when the actual entry for the tag
		 *  is made.
		 *  Note that functions of the form 'operator ()(int)'
		 *  will be recognized, but 'operator ()' will not,
		 *  even though this is legitimate in C.
		 */

					if (optoken(c)) {
					    if (isoperator) {
					    if (optfound) {
						    if (c != '(') {
						    tp++;
						    goto next_char;
						    }
					    } else {
						    if (c != ' ') {
						    optfound = TRUE;
						    }
						    tp++;
						    goto next_char;
					    }
					    } else {
				/* start: this code shifted left for cstyle */
				char *backptr = tp - 7;
				if (strncmp(backptr, "operator", 8) == 0) {
					/* This is an overloaded operator */
					isoperator = TRUE;
					if (c != ' ') {
						optfound = TRUE;
					}

					tp++;
					goto next_char;
				} else if (c == '~') {
					/* This is a destructor		*/
					tp++;
					goto next_char;
				}
				/* end: above code shifted left for cstyle */
					}
					} else if (c == ':') {
					    if ((*++sp = getc(inf)) == ':') {
						tp += 2;
						c = *sp;
						goto next_char;
					    } else {
						(void) ungetc (*sp, inf);
						--sp;
					    }
					}

				/* start: this code shifted left for cstyle */
				{
				int f;
				int pfline = lineno;

				if (start_entry(&sp, token, &f)) {
					(void) strncpy(tok, token, tp-token+1);
					tok[tp-token+1] = 0;
					getaline(tokftell);
					pfnote(tok, pfline, f);
					gotone = f;	/* function */
				}

				isoperator = optfound = midtoken = FALSE;
				token = sp;
				}
				/* end: above code shifted left for cstyle */
				} else if (intoken(c))
					tp++;
			} else if (begtoken(c)) {
				token = tp = sp;
				midtoken = TRUE;
				tokftell = lineftell;
			}
		}
	next_char:
		if (c == ';' && tydef == end)	/* clean with typedefs */
			tydef = none;
		sp++;
			/* The "c == }" was added to fix #1034126 */
		if (c == '\n' ||c == '}'|| sp > &line[sizeof (line) - BUFSIZ]) {
			tp = token = sp = line;
			number = gotone = midtoken = inquote =
			inchar = isoperator = optfound = FALSE;
		}
	}
}

/*
 * This routine  checks to see if the current token is
 * at the start of a function, or corresponds to a typedef
 * It updates the input line * so that the '(' will be
 * in it when it returns.
 */
static int
start_entry(lp, token, f)
char	**lp, *token;
int	*f;
{
	char	*sp;
	int	c;
	static	bool	found;
	bool	firsttok;	/* T if have seen first token in ()'s	*/
	int	bad;

	*f = 1;			/* a function */
	sp = *lp;
	c = *sp;
	bad = FALSE;
	if (!number) {		/* space is not allowed in macro defs	*/
		while (iswhite(c)) {
			*++sp = c = getc(inf);
			if ((c == '\n') || (c == EOF)) { /* c==EOF, #1091005 */
				lineno++;
				lineftell = ftell(inf);
				if (sp > &line[sizeof (line) - BUFSIZ])
					goto ret;
			}
		}
	/* the following tries to make it so that a #define	a b(c)	*/
	/* doesn't count as a define of b.				*/
	} else {
		if (strncmp(token, "define", 6) == 0)
			found = 0;
		else
			found++;
		if (found >= 2) {
			gotone = TRUE;
badone:			bad = TRUE;
			goto ret;
		}
	}
	/* check for the typedef cases		*/
#ifdef XPG4
	if (strncmp(token, "typedef", 7) == 0) {
#else /*  !XPG4 */
	if (tflag && (strncmp(token, "typedef", 7) == 0)) {
#endif /*  XPG4 */
		tydef = begin;
		goto badone;
	}
	/* Handles 'class' besides 'struct' etc.			*/
	if (tydef == begin && ((strncmp(token, "struct", 6) == 0) ||
			    (strncmp(token, "class", 5) == 0) ||
			    (strncmp(token, "union", 5) == 0)||
			    (strncmp(token, "enum", 4) == 0))) {
		tydef = begin_rec;
		goto badone;
	}
	if (tydef == begin) {
		tydef = end;
		goto badone;
	}
	if (tydef == begin_rec) {
		tydef = begin_tag;
		goto badone;
	}
	if (tydef == begin_tag) {
		tydef = end;
		goto gottydef;	/* Fall through to "tydef==end" */
	}

gottydef:
	if (tydef == end) {
		*f = 0;
		goto ret;
	}
	if (c != '(')
		goto badone;
	firsttok = FALSE;
	while ((*++sp = c = getc(inf)) != ')') {
		if ((c == '\n') || (c == EOF)) { /* c == EOF Fix for #1091005 */
			lineftell = ftell(inf);
			lineno++;
			if (sp > &line[sizeof (line) - BUFSIZ])
				goto ret;
		}
		/*
		 * This line used to confuse ctags:
		 *	int	(*oldhup)();
		 * This fixes it. A nonwhite char before the first
		 * token, other than a / (in case of a comment in there)
		 * makes this not a declaration.
		 */
		if (begtoken(c) || c == '/')
			firsttok = TRUE;
		else if (!iswhite(c) && !firsttok)
			goto badone;
	}
	while (iswhite(*++sp = c = getc(inf)))
		if ((c == '\n') || (c == EOF)) { /* c == EOF fix for #1091005 */
			lineno++;
			lineftell = ftell(inf);
			if (sp > &line[sizeof (line) - BUFSIZ])
				break;
		}
ret:
	*lp = --sp;
	if (c == '\n')
		lineno--;
	(void) ungetc(c, inf);
	return (!bad && (!*f || isgood(c)));
					/* hack for typedefs */
}

/*
 * Y_entries:
 *	Find the yacc tags and put them in.
 */
static void
Y_entries()
{
	char	*sp, *orig_sp;
	int	brace;
	bool	in_rule, toklen;
	char		tok[BUFSIZ];

	brace = 0;
	getaline(lineftell);
	pfnote("yyparse", lineno, TRUE);
	while (fgets(line, sizeof (line), inf) != NULL)
		for (sp = line; *sp; sp++)
			switch (*sp) {
			    case '\n':
				lineno++;
				/* FALLTHROUGH */
			    case ' ':
			    case '\t':
			    case '\f':
			    case '\r':
				break;
			    case '"':
				do {
					while (*++sp != '"')
						continue;
				} while (sp[-1] == '\\');
				break;
			    case '\'':
				do {
					while (*++sp != '\'')
						continue;
				} while (sp[-1] == '\\');
				break;
			    case '/':
				if (*++sp == '*')
					sp = toss_comment(sp);
				else
					--sp;
				break;
			    case '{':
				brace++;
				break;
			    case '}':
				brace--;
				break;
			    case '%':
				if (sp[1] == '%' && sp == line)
					return;
				break;
			    case '|':
			    case ';':
				in_rule = FALSE;
				break;
			    default:
				if (brace == 0 && !in_rule && (isalpha(*sp) ||
								*sp == '.' ||
								*sp == '_')) {
					orig_sp = sp;
					++sp;
					while (isalnum(*sp) || *sp == '_' ||
						*sp == '.')
						sp++;
					toklen = sp - orig_sp;
					while (isspace(*sp))
						sp++;
					if (*sp == ':' || (*sp == '\0' &&
						    first_char() == ':')) {
						(void) strncpy(tok,
							orig_sp, toklen);
						tok[toklen] = '\0';
						(void) strcpy(lbuf, line);
						lbuf[strlen(lbuf) - 1] = '\0';
						pfnote(tok, lineno, TRUE);
						in_rule = TRUE;
					}
					else
						sp--;
				}
				break;
			}
}

static char *
toss_comment(start)
char	*start;
{
	char	*sp;

	/*
	 * first, see if the end-of-comment is on the same line
	 */
	do {
#ifdef __STDC__
		while ((sp = strchr(start, '*')) != NULL)
#else
		while ((sp = index(start, '*')) != NULL)
#endif
			if (sp[1] == '/')
				return (++sp);
			else
				start = (++sp);
		start = line;
		lineno++;
	} while (fgets(line, sizeof (line), inf) != NULL);

	/*
	 * running this through lint revealed that the original version
	 * of this routine didn't explicitly return something; while
	 * the return value was always used!. so i've added this
	 * next line.
	 */
	return (sp);
}

static void
getaline(where)
long int where;
{
	long saveftell = ftell(inf);
	char *cp;

	(void) fseek(inf, where, 0);
	(void) fgets(lbuf, sizeof (lbuf), inf);
#ifdef __STDC__
	cp = strrchr(lbuf, '\n');
#else
	cp = rindex(lbuf, '\n');
#endif
	if (cp)
		*cp = 0;
	(void) fseek(inf, saveftell, 0);
}

static void
free_tree(node)
NODE	*node;
{
	while (node) {
		free_tree(node->right);
		free(node);
		node = node->left;
	}
}

static void
add_node(node, cur_node)
NODE *node, *cur_node;
{
	int dif;

	dif = strcmp(node->entry, cur_node->entry);
	if (dif == 0) {
		if (node->file == cur_node->file) {
			if (!wflag) {
			(void) fprintf(stderr,
			gettext("Duplicate entry in file %s, line %d: %s\n"),
			node->file, lineno, node->entry);
			(void) fprintf(stderr,
					gettext("Second entry ignored\n"));
			}
			return;
		}
		if (!cur_node->been_warned)
			if (!wflag) {
				(void) fprintf(stderr, gettext("Duplicate "
					    "entry in files %s and %s: %s "
					    "(Warning only)\n"),
					    node->file, cur_node->file,
					    node->entry);
			}
		cur_node->been_warned = TRUE;
		return;
	}

	if (dif < 0) {
		if (cur_node->left != NULL)
			add_node(node, cur_node->left);
		else
			cur_node->left = node;
		return;
	}
	if (cur_node->right != NULL)
		add_node(node, cur_node->right);
	else
		cur_node->right = node;
}

static void
put_entries(node)
NODE	*node;
{
	char	*sp;

	if (node == NULL)
		return;
	put_entries(node->left);

	/*
	 * while the code in the following #ifdef section could be combined,
	 * it's explicitly separated here to make maintainance easier.
	 */
#ifdef XPG4
	/*
	 * POSIX 2003: we no longer have a "-t" flag; the logic is
	 * automatically assumed to be "turned on" here.
	 */
	if (xflag == 0) {
			(void) fprintf(outf, "%s\t%s\t%c^",
				node->entry, node->file, searchar);
			for (sp = node->pat; *sp; sp++)
				if (*sp == '\\')
					(void) fprintf(outf, "\\\\");
				else if (*sp == searchar)
					(void) fprintf(outf, "\\%c", searchar);
				else
					(void) putc(*sp, outf);
			(void) fprintf(outf, "%c\n", searchar);
	} else if (vflag)
		(void) fprintf(stdout, "%s %s %d\n",
				node->entry, node->file, (node->lno+63)/64);
	else
		(void) fprintf(stdout, "%-16s %4d %-16s %s\n",
			node->entry, node->lno, node->file, node->pat);
#else /* XPG4 */
	/*
	 * original way of doing things. "-t" logic is only turned on
	 * when the user has specified it via a command-line argument.
	 */
	if (xflag == 0)
		if (node->f) {		/* a function */
			(void) fprintf(outf, "%s\t%s\t%c^",
				node->entry, node->file, searchar);
			for (sp = node->pat; *sp; sp++)
				if (*sp == '\\')
					(void) fprintf(outf, "\\\\");
				else if (*sp == searchar)
					(void) fprintf(outf, "\\%c", searchar);
				else
					(void) putc(*sp, outf);
			(void) fprintf(outf, "%c\n", searchar);
		} else {		/* a typedef; text pattern inadequate */
			(void) fprintf(outf, "%s\t%s\t%d\n",
				node->entry, node->file, node->lno);
		} else if (vflag)
		(void) fprintf(stdout, "%s %s %d\n",
				node->entry, node->file, (node->lno+63)/64);
	else
		(void) fprintf(stdout, "%-16s %4d %-16s %s\n",
			node->entry, node->lno, node->file, node->pat);
#endif /* XPG4 */
	put_entries(node->right);
}


static int
PF_funcs(fi)
FILE *fi;
{

	pfcnt = 0;
	while (fgets(lbuf, sizeof (lbuf), fi)) {
		lineno++;
		dbp = lbuf;
		if (*dbp == '%') dbp++;	/* Ratfor escape to fortran */
		while (isspace(*dbp))
			dbp++;
		if (*dbp == 0)
			continue;
		switch (*dbp |' ') {

		    case 'i':
			if (tail("integer"))
				takeprec();
			break;
		    case 'r':
			if (tail("real"))
				takeprec();
			break;
		    case 'l':
			if (tail("logical"))
				takeprec();
			break;
		    case 'c':
			if (tail("complex") || tail("character"))
				takeprec();
			break;
		    case 'd':
			if (tail("double")) {
				while (isspace(*dbp))
					dbp++;
				if (*dbp == 0)
					continue;
				if (tail("precision"))
					break;
				continue;
			}
			break;
		}
		while (isspace(*dbp))
			dbp++;
		if (*dbp == 0)
			continue;
		switch (*dbp|' ') {

		    case 'f':
			if (tail("function"))
				getit();
			continue;
		    case 's':
			if (tail("subroutine"))
				getit();
			continue;
		    case 'p':
			if (tail("program")) {
				getit();
				continue;
			}
			if (tail("procedure"))
				getit();
			continue;
		}
	}
	return (pfcnt);
}

static int
tail(cp)
char *cp;
{
	int len = 0;

	while (*cp && (*cp&~' ') == ((*(dbp+len))&~' '))
		cp++, len++;
	if (*cp == 0) {
		dbp += len;
		return (1);
	}
	return (0);
}

static void
takeprec()
{

	while (isspace(*dbp))
		dbp++;
	if (*dbp != '*')
		return;
	dbp++;
	while (isspace(*dbp))
		dbp++;
	if (!isdigit(*dbp)) {
		--dbp;		/* force failure */
		return;
	}
	do
		dbp++;
	while (isdigit(*dbp));
}

static void
getit()
{
	char *cp;
	char c;
	char nambuf[BUFSIZ];

	for (cp = lbuf; *cp; cp++)
		;
	*--cp = 0;	/* zap newline */
	while (isspace(*dbp))
		dbp++;
	if (*dbp == 0 || !isalpha(*dbp) || !isascii(*dbp))
		return;
	for (cp = dbp+1; *cp && (isalpha(*cp) || isdigit(*cp)); cp++)
		continue;
	c = cp[0];
	cp[0] = 0;
	(void) strcpy(nambuf, dbp);
	cp[0] = c;
	pfnote(nambuf, lineno, TRUE);
	pfcnt++;
}

static char *
savestr(cp)
char *cp;
{
	int len;
	char *dp;

	len = strlen(cp);
	dp = (char *)malloc(len+1);
	(void) strcpy(dp, cp);

	return (dp);
}

#ifndef __STDC__
/*
 * Return the ptr in sp at which the character c last
 * appears; NULL if not found
 *
 * Identical to v7 rindex, included for portability.
 */

static char *
rindex(sp, c)
char *sp, c;
{
	char *r;

	r = NULL;
	do {
		if (*sp == c)
			r = sp;
	} while (*sp++);
	return (r);
}
#endif

/*
 * lisp tag functions
 * just look for (def or (DEF
 */

static void
L_funcs(fi)
FILE *fi;
{
	int	special;

	pfcnt = 0;
	while (fgets(lbuf, sizeof (lbuf), fi)) {
		lineno++;
		dbp = lbuf;
		if (dbp[0] == '(' &&
		    (dbp[1] == 'D' || dbp[1] == 'd') &&
		    (dbp[2] == 'E' || dbp[2] == 'e') &&
		    (dbp[3] == 'F' || dbp[3] == 'f')) {
			dbp += 4;
			if (striccmp(dbp, "method") == 0 ||
			    striccmp(dbp, "wrapper") == 0 ||
			    striccmp(dbp, "whopper") == 0)
				special = TRUE;
			else
				special = FALSE;
			while (!isspace(*dbp))
				dbp++;
			while (isspace(*dbp))
				dbp++;
			L_getit(special);
		}
	}
}

static void
L_getit(special)
int	special;
{
	char	*cp;
	char	c;
	char		nambuf[BUFSIZ];

	for (cp = lbuf; *cp; cp++)
		continue;
	*--cp = 0;		/* zap newline */
	if (*dbp == 0)
		return;
	if (special) {
#ifdef __STDC__
		if ((cp = strchr(dbp, ')')) == NULL)
#else
		if ((cp = index(dbp, ')')) == NULL)
#endif
			return;
		while (cp >= dbp && *cp != ':')
			cp--;
		if (cp < dbp)
			return;
		dbp = cp;
		while (*cp && *cp != ')' && *cp != ' ')
			cp++;
	}
	else
		for (cp = dbp + 1; *cp && *cp != '(' && *cp != ' '; cp++)
			continue;
	c = cp[0];
	cp[0] = 0;
	(void) strcpy(nambuf, dbp);
	cp[0] = c;
	pfnote(nambuf, lineno, TRUE);
	pfcnt++;
}

/*
 * striccmp:
 *	Compare two strings over the length of the second, ignoring
 *	case distinctions.  If they are the same, return 0.  If they
 *	are different, return the difference of the first two different
 *	characters.  It is assumed that the pattern (second string) is
 *	completely lower case.
 */
static int
striccmp(str, pat)
char	*str, *pat;
{
	int	c1;

	while (*pat) {
		if (isupper(*str))
			c1 = tolower(*str);
		else
			c1 = *str;
		if (c1 != *pat)
			return (c1 - *pat);
		pat++;
		str++;
	}
	return (0);
}

/*
 * first_char:
 *	Return the first non-blank character in the file.  After
 *	finding it, rewind the input file so we start at the beginning
 *	again.
 */
static int
first_char()
{
	int	c;
	long	off;

	off = ftell(inf);
	while ((c = getc(inf)) != EOF)
		if (!isspace(c) && c != '\r') {
			(void) fseek(inf, off, 0);
			return (c);
		}
	(void) fseek(inf, off, 0);
	return (EOF);
}

/*
 * toss_yysec:
 *	Toss away code until the next "%%" line.
 */
static void
toss_yysec()
{
	char		buf[BUFSIZ];

	for (;;) {
		lineftell = ftell(inf);
		if (fgets(buf, BUFSIZ, inf) == NULL)
			return;
		lineno++;
		if (strncmp(buf, "%%", 2) == 0)
			return;
	}
}

static void
Usage()
{
#ifdef XPG4
	(void) fprintf(stderr, gettext("Usage:\tctags [-aBFuvw] "
#else /*  !XPG4 */
	(void) fprintf(stderr, gettext("Usage:\tctags [-aBFtuvw] "
#endif /*  XPG4 */
		    "[-f tagsfile] file ...\n"));
	(void) fprintf(stderr, gettext("OR:\tctags [-x] file ...\n"));
	exit(1);
}


/*
 * parseargs():		modify the args
 *	the purpose of this routine is to transform any ancient argument
 *	usage into a format which is acceptable to getopt(3C), so that we
 *	retain backwards Solaris 2.[0-4] compatibility.
 *
 *	This routine allows us to make full use of getopts, without any
 *	funny argument processing in main().
 *
 *	The other alternative would be to hand-craft the processed arguments
 *	during and after getopt(3C) - which usually leads to uglier code
 *	in main(). I've opted to keep the ugliness isolated down here,
 *	instead of in main().
 *
 *	In a nutshell, if the user has used the old Solaris syntax of:
 *		ctags [-aBFtuvwx] [-f tagsfile] filename ...
 *	We simply change this into:
 *		ctags [-a] [-B] [-F] [-t] [-u] [-v] [-w] [-x] [-f tags] file...
 *
 *	If the user has specified the new getopt(3C) syntax, we merely
 *	copy that into our modified argument space.
 */
static void
parseargs(ac, av)
int ac;				/* argument count			*/
char **av;			/* ptr to original argument space	*/
{
	int i;			/* current argument			*/
	int a;			/* used to parse combined arguments	*/
	int fflag;		/* 1 = we're only parsing filenames	*/
	size_t sz;		/* size of the argument			*/
	size_t mav_sz;		/* size of our psuedo argument space	*/

	i = mac = fflag = 0;	/* proper initializations */

	mav_sz = ((ac + 1) * sizeof (char *));
	if ((mav = malloc(mav_sz)) == (char **)NULL) {
		perror("Can't malloc argument space");
		exit(1);
	}

	/* for each argument, see if we need to change things:		*/
	for (; (av[i] != NULL) && (av[i][0] != '\0'); i++) {

		if (strcmp(av[i], "--") == 0) {
			fflag = 1;	/* just handle filenames now	*/
		}

		sz = strlen(&av[i][0]);	/* get this arg's size		*/

		/*
		 * if the argument starts with a "-", and has more than
		 * 1 flag, then we have to search through each character,
		 * and separate any flags which have been combined.
		 *
		 * so, if we've found a "-" string which needs separating:
		 */
		if (fflag == 0 &&	/* not handling filename args	*/
		    av[i][0] == '-' &&	/* and this is a flag		*/
		    sz > 2) {		/* and there's more than 1 flag	*/
			/* then for each flag after the "-" sign:	*/
			for (a = 1; av[i][a]; a++) {
				/* copy the flag into mav space.	*/
				if (a > 1) {
					/*
					 * we need to call realloc() after the
					 * 1st combined flag, because "ac"
					 * doesn't include combined args.
					 */
					mav_sz += sizeof (char *);
					if ((mav = realloc(mav, mav_sz)) ==
					    (char **)NULL) {
						perror("Can't realloc "
							"argument space");
						exit(1);
					}
				}

				if ((mav[mac] = malloc((size_t)CPFLAG)) ==
				    (char *)NULL) {
					perror("Can't malloc argument space");
					exit(1);
				}
				(void) sprintf(mav[mac], "-%c", av[i][a]);
				++mac;
			}
		} else {
			/* otherwise, just copy the argument:		*/
			if ((mav[mac] = malloc(sz + 1)) == (char *)NULL) {
				perror("Can't malloc argument space");
				exit(1);
			}
			(void) strcpy(mav[mac], av[i]);
			++mac;
		}
	}

	mav[mac] = (char *)NULL;
}
