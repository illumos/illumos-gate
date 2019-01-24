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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * csplit - Context or line file splitter
 * Compile: cc -O -s -o csplit csplit.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <regexpr.h>
#include <signal.h>
#include <locale.h>
#include <libintl.h>

#define	LAST	0LL
#define	ERR	-1
#define	FALSE	0
#define	TRUE	1
#define	EXPMODE	2
#define	LINMODE	3
#define	LINSIZ	LINE_MAX	/* POSIX.2 - read lines LINE_MAX long */

	/* Globals */

char linbuf[LINSIZ];		/* Input line buffer */
char *expbuf;
char tmpbuf[BUFSIZ];		/* Temporary buffer for stdin */
char file[8192] = "xx";		/* File name buffer */
char *targ;			/* Arg ptr for error messages */
char *sptr;
FILE *infile, *outfile;		/* I/O file streams */
int silent, keep, create;	/* Flags: -s(ilent), -k(eep), (create) */
int errflg;
int fiwidth = 2;		/* file index width (output file names) */
extern int optind;
extern char *optarg;
offset_t offset;		/* Regular expression offset value */
offset_t curline;		/* Current line in input file */

/*
 * These defines are needed for regexp handling(see regexp(7))
 */
#define	PERROR(x)	fatal("%s: Illegal Regular Expression\n", targ);

static int asc_to_ll(char *, long long *);
static void closefile(void);
static void fatal(char *, char *);
static offset_t findline(char *, offset_t);
static void flush(void);
static FILE *getfile(void);
static char *getaline(int);
static void line_arg(char *);
static void num_arg(char *, int);
static void re_arg(char *);
static void sig(int);
static void to_line(offset_t);
static void usage(void);

int
main(int argc, char **argv)
{
	int ch, mode;
	char *ptr;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((ch = getopt(argc, argv, "skf:n:")) != EOF) {
		switch (ch) {
			case 'f':
				(void) strcpy(file, optarg);
				if ((ptr = strrchr(optarg, '/')) == NULL)
					ptr = optarg;
				else
					ptr++;

				break;
			case 'n':		/* POSIX.2 */
				for (ptr = optarg; *ptr != '\0'; ptr++)
					if (!isdigit((int)*ptr))
						fatal("-n num\n", NULL);
				fiwidth = atoi(optarg);
				break;
			case 'k':
				keep++;
				break;
			case 's':
				silent++;
				break;
			case '?':
				errflg++;
		}
	}

	argv = &argv[optind];
	argc -= optind;
	if (argc <= 1 || errflg)
		usage();

	if (strcmp(*argv, "-") == 0) {
		infile = tmpfile();

		while (fread(tmpbuf, 1, BUFSIZ, stdin) != 0) {
			if (fwrite(tmpbuf, 1, BUFSIZ, infile) == 0)
				if (errno == ENOSPC) {
					(void) fprintf(stderr, "csplit: ");
					(void) fprintf(stderr, gettext(
					    "No space left on device\n"));
					exit(1);
				} else {
					(void) fprintf(stderr, "csplit: ");
					(void) fprintf(stderr, gettext(
					    "Bad write to temporary "
					    "file\n"));
					exit(1);
				}

	/* clear the buffer to get correct size when writing buffer */

			(void) memset(tmpbuf, '\0', sizeof (tmpbuf));
		}
		rewind(infile);
	} else if ((infile = fopen(*argv, "r")) == NULL)
		fatal("Cannot open %s\n", *argv);
	++argv;
	curline = (offset_t)1;
	(void) signal(SIGINT, sig);

	/*
	 * The following for loop handles the different argument types.
	 * A switch is performed on the first character of the argument
	 * and each case calls the appropriate argument handling routine.
	 */

	for (; *argv; ++argv) {
		targ = *argv;
		switch (**argv) {
		case '/':
			mode = EXPMODE;
			create = TRUE;
			re_arg(*argv);
			break;
		case '%':
			mode = EXPMODE;
			create = FALSE;
			re_arg(*argv);
			break;
		case '{':
			num_arg(*argv, mode);
			mode = FALSE;
			break;
		default:
			mode = LINMODE;
			create = TRUE;
			line_arg(*argv);
			break;
		}
	}
	create = TRUE;
	to_line(LAST);
	return (0);
}

/*
 * asc_to_ll takes an ascii argument(str) and converts it to a long long(plc)
 * It returns ERR if an illegal character.  The reason that asc_to_ll
 * does not return an answer(long long) is that any value for the long
 * long is legal, and this version of asc_to_ll detects error strings.
 */

static int
asc_to_ll(char *str, long long *plc)
{
	int f;
	*plc = 0;
	f = 0;
	for (; ; str++) {
		switch (*str) {
		case ' ':
		case '\t':
			continue;
		case '-':
			f++;
			/* FALLTHROUGH */
		case '+':
			str++;
		}
		break;
	}
	for (; *str != '\0'; str++)
		if (*str >= '0' && *str <= '9')
			*plc = *plc * 10 + *str - '0';
		else
			return (ERR);
	if (f)
		*plc = -(*plc);
	return (TRUE);	/* not error */
}

/*
 * Closefile prints the byte count of the file created,(via fseeko
 * and ftello), if the create flag is on and the silent flag is not on.
 * If the create flag is on closefile then closes the file(fclose).
 */

static void
closefile()
{
	if (!silent && create) {
		(void) fseeko(outfile, (offset_t)0, SEEK_END);
		(void) fprintf(stdout, "%lld\n", (offset_t)ftello(outfile));
	}
	if (create)
		(void) fclose(outfile);
}

/*
 * Fatal handles error messages and cleanup.
 * Because "arg" can be the global file, and the cleanup processing
 * uses the global file, the error message is printed first.  If the
 * "keep" flag is not set, fatal unlinks all created files.  If the
 * "keep" flag is set, fatal closes the current file(if there is one).
 * Fatal exits with a value of 1.
 */

static void
fatal(char *string, char *arg)
{
	char *fls;
	int num;

	(void) fprintf(stderr, "csplit: ");

	/* gettext dynamically replaces string */

	(void) fprintf(stderr, gettext(string), arg);
	if (!keep) {
		if (outfile) {
			(void) fclose(outfile);
			for (fls = file; *fls != '\0'; fls++)
				continue;
			fls -= fiwidth;
			for (num = atoi(fls); num >= 0; num--) {
				(void) sprintf(fls, "%.*d", fiwidth, num);
				(void) unlink(file);
			}
		}
	} else
		if (outfile)
			closefile();
	exit(1);
}

/*
 * Findline returns the line number referenced by the current argument.
 * Its arguments are a pointer to the compiled regular expression(expr),
 * and an offset(oset).  The variable lncnt is used to count the number
 * of lines searched.  First the current stream location is saved via
 * ftello(), and getaline is called so that R.E. searching starts at the
 * line after the previously referenced line.  The while loop checks
 * that there are more lines(error if none), bumps the line count, and
 * checks for the R.E. on each line.  If the R.E. matches on one of the
 * lines the old stream location is restored, and the line number
 * referenced by the R.E. and the offset is returned.
 */

static offset_t
findline(char *expr, offset_t oset)
{
	static int benhere = 0;
	offset_t lncnt = 0, saveloc;

	saveloc = ftello(infile);
	if (curline != (offset_t)1 || benhere)	/* If first line, first time, */
		(void) getaline(FALSE);		/* then don't skip */
	else
		lncnt--;
	benhere = 1;
	while (getaline(FALSE) != NULL) {
		lncnt++;
		if ((sptr = strrchr(linbuf, '\n')) != NULL)
			*sptr = '\0';
		if (step(linbuf, expr)) {
			(void) fseeko(infile, (offset_t)saveloc, SEEK_SET);
			return (curline+lncnt+oset);
		}
	}
	(void) fseeko(infile, (offset_t)saveloc, SEEK_SET);
	return (curline+lncnt+oset+2);
}

/*
 * Flush uses fputs to put lines on the output file stream(outfile)
 * Since fputs does its own buffering, flush doesn't need to.
 * Flush does nothing if the create flag is not set.
 */

static void
flush()
{
	if (create)
		(void) fputs(linbuf, outfile);
}

/*
 * Getfile does nothing if the create flag is not set.  If the create
 * flag is set, getfile positions the file pointer(fptr) at the end of
 * the file name prefix on the first call(fptr=0).  The file counter is
 * stored in the file name and incremented.  If the subsequent fopen
 * fails, the file name is copied to tfile for the error message, the
 * previous file name is restored for cleanup, and fatal is called.  If
 * the fopen succeeds, the stream(opfil) is returned.
 */

FILE *
getfile()
{
	static char *fptr;
	static int ctr;
	FILE *opfil;
	char tfile[15];
	char *delim;
	char savedelim;

	if (create) {
		if (fptr == 0)
			for (fptr = file; *fptr != '\0'; fptr++)
				continue;
		(void) sprintf(fptr, "%.*d", fiwidth, ctr++);

		/* check for suffix length overflow */
		if (strlen(fptr) > fiwidth) {
			fatal("Suffix longer than %ld chars; increase -n\n",
			    (char *)fiwidth);
		}

		/* check for filename length overflow */

		delim = strrchr(file, '/');
		if (delim == (char *)NULL) {
			if (strlen(file) > pathconf(".", _PC_NAME_MAX)) {
				fatal("Name too long: %s\n", file);
			}
		} else {
			/* truncate file at pathname delim to do pathconf */
			savedelim = *delim;
			*delim = '\0';
			/*
			 * file: pppppppp\0fffff\0
			 * ..... ^ file
			 * ............. ^ delim
			 */
			if (strlen(delim + 1) > pathconf(file, _PC_NAME_MAX)) {
				fatal("Name too long: %s\n", delim + 1);
			}
			*delim = savedelim;
		}

		if ((opfil = fopen(file, "w")) == NULL) {
			(void) strlcpy(tfile, file, sizeof (tfile));
			(void) sprintf(fptr, "%.*d", fiwidth, (ctr-2));
			fatal("Cannot create %s\n", tfile);
		}
		return (opfil);
	}
	return (NULL);
}

/*
 * Getline gets a line via fgets from the input stream "infile".
 * The line is put into linbuf and may not be larger than LINSIZ.
 * If getaline is called with a non-zero value, the current line
 * is bumped, otherwise it is not(for R.E. searching).
 */

static char *
getaline(int bumpcur)
{
	char *ret;
	if (bumpcur)
		curline++;
	ret = fgets(linbuf, LINSIZ, infile);
	return (ret);
}

/*
 * Line_arg handles line number arguments.
 * line_arg takes as its argument a pointer to a character string
 * (assumed to be a line number).  If that character string can be
 * converted to a number(long long), to_line is called with that number,
 * otherwise error.
 */

static void
line_arg(char *line)
{
	long long to;

	if (asc_to_ll(line, &to) == ERR)
		fatal("%s: bad line number\n", line);
	to_line(to);
}

/*
 * Num_arg handles repeat arguments.
 * Num_arg copies the numeric argument to "rep" (error if number is
 * larger than 20 characters or } is left off).  Num_arg then converts
 * the number and checks for validity.  Next num_arg checks the mode
 * of the previous argument, and applys the argument the correct number
 * of times. If the mode is not set properly its an error.
 */

static void
num_arg(char *arg, int md)
{
	offset_t repeat, toline;
	char rep[21];
	char *ptr;
	int		len;

	ptr = rep;
	for (++arg; *arg != '}'; arg += len) {
		if (*arg == '\0')
			fatal("%s: missing '}'\n", targ);
		if ((len = mblen(arg, MB_LEN_MAX)) <= 0)
			len = 1;
		if ((ptr + len) >= &rep[20])
			fatal("%s: Repeat count too large\n", targ);
		(void) memcpy(ptr, arg, len);
		ptr += len;
	}
	*ptr = '\0';
	if ((asc_to_ll(rep, &repeat) == ERR) || repeat < 0L)
		fatal("Illegal repeat count: %s\n", targ);
	if (md == LINMODE) {
		toline = offset = curline;
		for (; repeat > 0LL; repeat--) {
			toline += offset;
			to_line(toline);
		}
	} else	if (md == EXPMODE)
			for (; repeat > 0LL; repeat--)
				to_line(findline(expbuf, offset));
		else
			fatal("No operation for %s\n", targ);
}

/*
 * Re_arg handles regular expression arguments.
 * Re_arg takes a csplit regular expression argument.  It checks for
 * delimiter balance, computes any offset, and compiles the regular
 * expression.  Findline is called with the compiled expression and
 * offset, and returns the corresponding line number, which is used
 * as input to the to_line function.
 */

static void
re_arg(char *string)
{
	char *ptr;
	char ch;
	int		len;

	ch = *string;
	ptr = string;
	ptr++;
	while (*ptr != ch) {
		if (*ptr == '\\')
			++ptr;

		if (*ptr == '\0')
			fatal("%s: missing delimiter\n", targ);

		if ((len = mblen(ptr, MB_LEN_MAX)) <= 0)
			len = 1;
		ptr += len;
	}

	/*
	 * The line below was added because compile no longer supports
	 * the fourth argument being passed.  The fourth argument used
	 * to be '/' or '%'.
	 */

	*ptr = '\0';
	if (asc_to_ll(++ptr, &offset) == ERR)
		fatal("%s: illegal offset\n", string);

	/*
	 * The line below was added because INIT which did this for us
	 * was removed from compile in regexp.h
	 */

	string++;
	expbuf = compile(string, (char *)0, (char *)0);
	if (regerrno)
		PERROR(regerrno);
	to_line(findline(expbuf, offset));
}

/*
 * Sig handles breaks.  When a break occurs the signal is reset,
 * and fatal is called to clean up and print the argument which
 * was being processed at the time the interrupt occured.
 */

/* ARGSUSED */
static void
sig(int s)
{
	(void) signal(SIGINT, sig);
	fatal("Interrupt - program aborted at arg '%s'\n", targ);
}

/*
 * To_line creates split files.
 * To_line gets as its argument the line which the current argument
 * referenced.  To_line calls getfile for a new output stream, which
 * does nothing if create is False.  If to_line's argument is not LAST
 * it checks that the current line is not greater than its argument.
 * While the current line is less than the desired line to_line gets
 * lines and flushes(error if EOF is reached).
 * If to_line's argument is LAST, it checks for more lines, and gets
 * and flushes lines till the end of file.
 * Finally, to_line calls closefile to close the output stream.
 */

static void
to_line(offset_t ln)
{
	outfile = getfile();
	if (ln != LAST) {
		if (curline > ln)
			fatal("%s - out of range\n", targ);
		while (curline < ln) {
			if (getaline(TRUE) == NULL)
				fatal("%s - out of range\n", targ);
			flush();
		}
	} else		/* last file */
		if (getaline(TRUE) != NULL) {
			flush();
			for (;;) {
				if (getaline(TRUE) == NULL)
					break;
				flush();
			}
		} else
			fatal("%s - out of range\n", targ);
	closefile();
}

static void
usage()
{
	(void) fprintf(stderr, gettext(
	    "usage: csplit [-ks] [-f prefix] [-n number] "
	    "file arg1 ...argn\n"));
	exit(1);
}
