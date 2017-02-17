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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <signal.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdio.h>
#include <wchar.h>
#include <curses.h>
#include <term.h>
#include <errno.h>
#include <stdlib.h>
#include <regexpr.h>
#include <limits.h>
#include <locale.h>
#include <wctype.h> /* iswprint() */
#include <string.h>
#include <unistd.h>
#include <wait.h>
#include <libw.h>
#include <regexpr.h>


/*
 *	pg -- paginator for crt terminals
 *
 *	Includes the ability to display pages that have
 *	already passed by. Also gives the user the ability
 *	to search forward and backwards for regular expressions.
 *	This works for piped input by copying to a temporary file,
 *	and resolving backreferences from there.
 *
 *	Note:	The reason that there are so many commands to do
 *		the same types of things is to try to accommodate
 *		users of other paginators.
 */

#define	LINSIZ	1024
#define	QUIT	'\034'
#define	BOF	(EOF - 1)	/* Begining of File */
#define	STOP    (EOF - 2)
#define	PROMPTSIZE	256

/*
 * Function definitions
 */
static	void	lineset(int);
static	char	*setprompt();
static	int	set_state(int *, wchar_t, char *);
static	void	help();
static	void	copy_file(FILE *, FILE *);
static	void	re_error(int);
static	void	save_input(FILE *);
static	void	save_pipe();
static	void	newdol(FILE *);
static	void	erase_line(int);
static	void	kill_line();
static	void	doclear();
static	void	sopr(char *, int);
static	void	prompt(char *);
static	void	error(char *);
static	void	terminit();
static	void	compact();
static	off_t	getaline(FILE *);
static	int	mrdchar();
static	off_t	find(int, off_t);
static	int	search(char *, off_t);
static	FILE	*checkf(char *);
static	int	skipf(int);
static	int	readch();
static	int	ttyin();
static	int	number();
static	int	command(char *);
static	int	screen(char *);
static	int	fgetputc();
static 	char	*pg_strchr();


struct line {			/* how line addresses are stored */
	off_t	l_addr;		/* file offset */
	off_t	l_no;		/* line number in file */
};

typedef	struct line	LINE;

static	LINE	*zero = NULL,	/* first line */
		*dot,		/* current line */
		*dol,		/* last line */
		*contig;	/* where contiguous (non-aged) lines start */
static	long	nlall;		/* room for how many LINEs in memory */

static	FILE	*in_file,	/* current input stream */
		*tmp_fin,	/* pipe temporary file in */
		*tmp_fou;	/* pipe temporary file out */
static	char	tmp_name[] = "/tmp/pgXXXXXX";

static	short	sign;		/* sign of command input */

static	int	fnum,		/* which file argument we're in */
		pipe_in,	/* set when stdin is a pipe */
		out_is_tty;	/* set if stdout is a tty */
static	pid_t	my_pgid;

static	void	on_brk(),
		end_it();
static	short	brk_hit;	/* interrupt handling is pending flag */

static	int	window = 0;	/* window size in lines */
static	short	eof_pause = 1;	/* pause w/ prompt at end of files */
static	short	rmode = 0;	/* deny shell escape in restricted mode */
static	short	soflag = 0;	/* output all messages in standout mode */
static	short	promptlen;	/* length of the current prompt */
static	short	firstf = 1;	/* set before first file has been processed */
static	short	inwait,		/* set while waiting for user input */
		errors;		/* set if error message has been printed. */
				/* if so, need to erase it and prompt */

static	char	**fnames;
static	short	status = 0;	/* set > 0 if error detected */
static	short	fflag = 0;	/* set if the f option is used */
static	short	nflag = 0;	/* set for "no newline" input option */
static	short	clropt = 0;	/* set if the clear option is used */
static	int	initopt = 0;	/* set if the line option is used */
static	int	srchopt = 0;	/* set if the search option is used */
static	int	initline;
static	char	initbuf[BUFSIZ];
static	wchar_t	leave_search = L't';
				/* where on the page to leave a found string */
static	short	nfiles;
static	char	*shell;
static	char	*promptstr = ":";
static  off_t	nchars;			/* return from getaline in find() */
static	jmp_buf	restore;
static	char	Line[LINSIZ+2];

static	int	catch_susp;

static	void	onsusp();

struct screen_stat {
	off_t	first_line;
	off_t	last_line;
	short	is_eof;
	};

static	struct screen_stat old_ss = { 0, 0, 0 };
static	struct screen_stat new_ss;
static	struct termio otty;	/* to save old terminal settings */

static	short	termflg = 0;	/* set once terminal is initialized */
static	short	eoflag;		/* set whenever at end of current file */
static	short	doliseof;	/* set when last line of file is known */
static	off_t	eofl_no;	/* what the last line of the file is */
static	void	usage(void);
static FILE	*pg_stdin;

int
main(int argc, char **argv)
{
	char	*s;
	char	*p;
	int		prnames = 0;
	int		opt;
	int		i;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* check for non-standard "-#" option */
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0)
			break;

		if ((argv[i][0] == '-') && isdigit(argv[i][1])) {
			if (strlen(&argv[i][1]) !=
			    strspn(&argv[i][1], "0123456789")) {
				(void) fprintf(stderr, gettext(
				    "pg: Badly formed number\n"));
				usage();
			}

			window = (int)strtol(&argv[i][1], (char **)NULL, 10);

			while (i < argc) {
				argv[i] = argv[i + 1];
				i++;
			}
			i--;
			argc--;
		}
	}

	/* check for non-standard + option */
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0)
		break;

		if (argv[i][0] == '+') {
			if (argv[i][1] == '/') {
				srchopt++;
				initopt = 0;
				for (s = &argv[i][2], p = initbuf; *s != '\0'; )
					if (p < initbuf + sizeof (initbuf))
						*p++ = *s++;
					else {
						(void) fprintf(stderr, gettext(
						    "pg: pattern too long\n"));
						return (1);
					}
				*p = '\0';
			} else {
				initopt++;
				srchopt = 0;
				s = &argv[i][2];
				for (; isdigit(*s); s++)
					initline = initline*10 + *s -'0';
				if (*s != '\0')
					usage();
			}

			while (i < argc) {
				argv[i] = argv[i + 1];
				i++;
			}
			i--;
			argc--;
		}
	}

	while ((opt = getopt(argc, argv, "cefnrsp:")) != EOF) {
		switch (opt) {
		case 'c':
			clropt = 1;
			break;

		case 'e':
			eof_pause = 0;
			break;

		case 'f':
			fflag = 1;
			break;

		case 'n':
			nflag = 1;
			break;

		case 'r':
			rmode = 1;	/* restricted mode */
			break;

		case 's':
			soflag = 1;	/* standout mode */
			break;

		case 'p':
			promptstr = setprompt(optarg);
			break;

		default:
			usage();
		}
	}

	nfiles = argc - optind;
	fnames = &argv[optind];

	(void) signal(SIGQUIT, end_it);
	(void) signal(SIGINT, end_it);
	out_is_tty = isatty(1);
	my_pgid = getpgrp();
	if (out_is_tty) {
		terminit();
		(void) signal(SIGQUIT, on_brk);
		(void) signal(SIGINT, on_brk);
		if (signal(SIGTSTP, SIG_IGN) == SIG_DFL) {
			(void) signal(SIGTSTP, onsusp);
			catch_susp++;
		}
	}
	if (window == 0)
		window = lines - 1;
	if (window <= 1)
		window = 2;
	if (initline <= 0)
		initline = 1;
	if (nfiles > 1)
		prnames++;

	if (nfiles == 0) {
		fnames[0] = "-";
		nfiles++;
	}
	while (fnum < nfiles) {
		if (strcmp(fnames[fnum], "") == 0)
			fnames[fnum] = "-";
		if ((in_file = checkf(fnames[fnum])) == NULL) {
			status = 2;
			fnum++;
		} else {
			status = 0;
			if (out_is_tty)
				fnum += screen(fnames[fnum]);
			else {
				if (prnames) {
					(void) fputs("::::::::::::::\n",
					    stdout);
					(void) fputs(fnames[fnum], stdout);
					(void) fputs("\n::::::::::::::\n",
					    stdout);
				}
				copy_file(in_file, stdout);
				fnum++;
			}
			(void) fflush(stdout);
			if (pipe_in)
				save_pipe();
			else
			if (in_file != tmp_fin)
				(void) fclose(in_file);
		}
	}
	end_it();

	/*NOTREACHED*/
	return (0);
}

static	char *
setprompt(s)
char *s;
{
	int i = 0;
	int pct_d = 0;
	static char pstr[PROMPTSIZE];

	while (i < PROMPTSIZE - 2)
		switch (pstr[i++] = *s++) {
		case '\0':
			return (pstr);
		case '%':
			if (*s == 'd' && !pct_d) {
				pct_d++;
			} else if (*s != '%')
				pstr[i++] = '%';
			if ((pstr[i++] = *s++) == '\0')
				return (pstr);
			break;
		default:
			break;
		}
	(void) fprintf(stderr, gettext("pg: prompt too long\n"));
	exit(1);
	/*NOTREACHED*/
}


/*
 * Print out the contents of the file f, one screenful at a time.
 */

static int
screen(file_name)
char *file_name;
{
	int cmd_ret = 0;
	off_t start;
	short hadchance = 0;

	old_ss.is_eof = 0;
	old_ss.first_line = 0;
	old_ss.last_line = 0;
	new_ss = old_ss;
	if (!firstf)
		cmd_ret = command(file_name);
	else {
		firstf = 0;
		if (initopt) {
			initopt = 0;
			new_ss.first_line = initline;
			new_ss.last_line = initline + (off_t)window - 1;
		} else if (srchopt) {
			srchopt = 0;
			if (!search(initbuf, (off_t)1))
				cmd_ret = command(file_name);
		} else {
			new_ss.first_line = 1;
			new_ss.last_line = (off_t)window;
		}
	}

	for (;;) {
		if (cmd_ret)
			return (cmd_ret);
		if (hadchance && new_ss.last_line >= eofl_no)
			return (1);
		hadchance = 0;

		if (new_ss.last_line < (off_t)window)
			new_ss.last_line = (off_t)window;
		if (find(0, new_ss.last_line + 1) != EOF)
			new_ss.is_eof = 0;
		else {
			new_ss.is_eof = 1;
			new_ss.last_line = eofl_no - 1;
			new_ss.first_line = new_ss.last_line -
			    (off_t)window + 1;
		}

		if (new_ss.first_line < 1)
			new_ss.first_line = 1;
		if (clropt) {
			doclear();
			start = new_ss.first_line;
		} else {
			if (new_ss.first_line == old_ss.last_line)
				start = new_ss.first_line + 1;
			else
			if (new_ss.first_line > old_ss.last_line)
				start = new_ss.first_line;
			else
			if (old_ss.first_line < new_ss.first_line)
				start = old_ss.last_line + 1;
			else
				start = new_ss.first_line;

			if (start < old_ss.first_line)
				sopr(gettext("...skipping backward\n"), 0);
			else
			if (start > old_ss.last_line + 1)
				sopr(gettext("...skipping forward\n"), 0);
		}

		for (; start <= new_ss.last_line; start++) {
			(void) find(0, start);
			(void) fputs(Line, stdout);
			if (brk_hit) {
				new_ss.last_line = find(1, 0);
				new_ss.is_eof = 0;
				break;
			}
		}

		brk_hit = 0;
		(void) fflush(stdout);
		if (new_ss.is_eof) {
			if (!eof_pause || eofl_no == 1)
				return (1);
			hadchance++;
			error("(EOF)");
		}
		old_ss = new_ss;
		cmd_ret = command((char *)NULL);
	}
}

static	char	cmdbuf[LINSIZ], *cmdptr;
#define	BEEP()		if (bell) { (void) putp(bell); (void) fflush(stdout); }
#define	BLANKS(p)	while (*p == ' ' || *p == '\t') p++
#define	CHECKEND()	BLANKS(cmdptr); if (*cmdptr) { BEEP(); break; }

/*
 * Read a command and do it. A command consists of an optional integer
 * argument followed by the command character.  Return the number of files
 * to skip, 0 if we're still talking about the same file.
 */

static int
command(filename)
char *filename;
{
	off_t nlines;
	FILE *sf;
	char *cmdend;
	pid_t id;
	int skip;
	int	len;
	wchar_t	wc;
	wchar_t	wc_e;
	wchar_t	wc_e1;
	char	*p;

	for (;;) {
		/*
		 * Wait for output to drain before going on.
		 * This is done so that the user will not hit
		 * break and quit before they have seen the prompt.
		 */
		(void) ioctl(1, TCSBRK, 1);
		if (setjmp(restore) > 0)
			end_it();
		inwait = 1;
		brk_hit = 0;
		if (errors)
			errors = 0;
		else {
			kill_line();
			prompt(filename);
		}
		(void) fflush(stdout);
		if (ttyin())
			continue;
		cmdptr = cmdbuf;
		nlines = number();
		BLANKS(cmdptr);

		if ((len = mbtowc(&wc, cmdptr, MB_CUR_MAX)) <= 0) {
			wc = *cmdptr;
			len = 1;
		}
		cmdptr += len;
		switch (wc) {
		case 'h':
			CHECKEND();
			help();
			break;
		case '\014': /* ^L */
		case '.':	/* redisplay current window */
			CHECKEND();
			new_ss.first_line = old_ss.first_line;
			new_ss.last_line = old_ss.last_line;
			inwait = 0;
			return (0);
		case 'w':	/* set window size */
		case 'z':
			if (sign == -1) {
				BEEP();
				break;
			}
			CHECKEND();
			if (nlines == 0)
				nlines = (off_t)window;
			else
			if (nlines > 1)
				window = (int)nlines;
			else {
				BEEP();
				break;
			}
			new_ss.first_line = old_ss.last_line;
			new_ss.last_line = new_ss.first_line +
			    (off_t)window - 1;
			inwait = 0;
			return (0);
		case '\004': /* ^D */
		case 'd':
			CHECKEND();
			if (sign == 0)
				sign = 1;
			new_ss.last_line = old_ss.last_line +
			    (off_t)sign*window/2;
			new_ss.first_line = new_ss.last_line -
			    (off_t)window + 1;
			inwait = 0;
			return (0);
		case 's':
			/*
			 * save input in filename.
			 * Check for filename, access, etc.
			 */
			BLANKS(cmdptr);
			if (!*cmdptr) {
				BEEP();
				break;
			}
			if (setjmp(restore) > 0) {
				BEEP();
			} else {
				char outstr[PROMPTSIZE];
				if ((sf = fopen(cmdptr, "w")) == NULL) {
					error("cannot open save file");
					break;
				}
				kill_line();
				(void) sprintf(outstr, gettext(
				    "saving file %s"), cmdptr);
				sopr(outstr, 1);
				(void) fflush(stdout);
				save_input(sf);
				error("saved");
			}
			(void) fclose(sf);
			break;
		case 'q':
		case 'Q':
			CHECKEND();
			inwait = 0;
			end_it();
			/*FALLTHROUGH*/

		case 'f':	/* skip forward screenfuls */
			CHECKEND();
			if (sign == 0)
				sign++;	/* skips are always relative */
			if (nlines == 0)
				nlines++;
			nlines = nlines * (window - 1);
			if (sign == 1)
				new_ss.first_line = old_ss.last_line + nlines;
			else
				new_ss.first_line = old_ss.first_line - nlines;
			new_ss.last_line = new_ss.first_line +
			    (off_t)window - 1;
			inwait = 0;
			return (0);
		case 'l':	/* get a line */
			CHECKEND();
			if (nlines == 0) {
				nlines++;
				if (sign == 0)
					sign = 1;
			}
			switch (sign) {
			case 1:
				new_ss.last_line = old_ss.last_line + nlines;
				new_ss.first_line =
				    new_ss.last_line - (off_t)window + 1;
				break;
			case 0:  /* leave addressed line at top */
				new_ss.first_line = nlines;
				new_ss.last_line = nlines + (off_t)window - 1;
				break;
			case -1:
				new_ss.first_line = old_ss.first_line - nlines;
				new_ss.last_line =
				    new_ss.first_line + (off_t)window - 1;
				break;
			}
			inwait = 0;
			return (0);
		case '\0': /* \n or blank */
			if (nlines == 0) {
				nlines++;
				if (sign == 0)
					sign = 1;
			}
			nlines = (nlines - 1) * (window - 1);
			switch (sign) {
			case 1:
				new_ss.first_line = old_ss.last_line + nlines;
				new_ss.last_line =
				    new_ss.first_line + (off_t)window - 1;
				break;
			case 0:
				new_ss.first_line = nlines + 1;
				new_ss.last_line = nlines + (off_t)window;
				/*
				 * This if statement is to fix the obscure bug
				 * where you have a file that has less lines
				 * than a screen holds, and the user types '1',
				 * expecting to have the 1st page (re)displayed.
				 * If we didn't set the new last_line to
				 * eofl_no-1, the screen() routine
				 * would cause pg to exit.
				 */
				if (new_ss.first_line == 1 &&
				    new_ss.last_line >= eofl_no)
					new_ss.last_line = eofl_no - 1;
				break;
			case -1:
				new_ss.last_line = old_ss.first_line - nlines;
				new_ss.first_line =
				    new_ss.last_line - (off_t)window + 1;
				break;
			}
			inwait = 0;
			return (0);
		case 'n':	/* switch to next file in arglist */
			CHECKEND();
			if (sign == 0)
				sign = 1;
			if (nlines == 0)
				nlines++;
			if ((skip = skipf(sign *nlines)) == 0) {
				BEEP();
				break;
			}
			inwait = 0;
			return (skip);
		case 'p':	/* switch to previous file in arglist */
			CHECKEND();
			if (sign == 0)
				sign = 1;
			if (nlines == 0)
				nlines++;
			if ((skip = skipf(-sign * nlines)) == 0) {
				BEEP();
				break;
			}
			inwait = 0;
			return (skip);
		case '$':	/* go to end of file */
			CHECKEND();
			sign = 1;
			while (find(1, (off_t)10000) != EOF)
				/* any large number will do */;
			new_ss.last_line = eofl_no - 1;
			new_ss.first_line = eofl_no - (off_t)window;
			inwait = 0;
			return (0);
		case '/':	/* search forward for r.e. */
		case '?':	/*   "  backwards */
		case '^':	/* this ones a ? for regent100s */
			if (sign < 0) {
				BEEP();
				break;
			}
			if (nlines == 0)
				nlines++;
			cmdptr--;
			cmdend = cmdptr + (strlen(cmdptr) - 1);
			wc_e1 = -1;
			wc_e = -1;
			for (p = cmdptr; p <= cmdend; p += len) {
				wc_e1 = wc_e;
				if ((len = mbtowc(&wc_e, p, MB_CUR_MAX)) <= 0) {
					wc_e = *p;
					len = 1;
				}
			}

			if (cmdend > cmdptr + 1) {
				if ((wc_e1 == *cmdptr) &&
				    ((wc_e == L't') ||
					(wc_e == L'm') || (wc_e == L'b'))) {
					leave_search = wc_e;
					wc_e = wc_e1;
					cmdend--;
				}
			}
			if ((cmdptr < cmdend) && (wc_e == *cmdptr))
				*cmdend = '\0';
			if (*cmdptr != '/')  /* signify back search by - */
				nlines = -nlines;
			if (!search(++cmdptr, (off_t)nlines))
				break;
			else {
				inwait = 0;
				return (0);
			}
		case '!':	/* shell escape */
			if (rmode) {	/* restricted mode */
				(void) fprintf(stderr, gettext(
				"!command not allowed in restricted mode.\n"));
				break;
			}
			if (!hard_copy) { /* redisplay the command */
				(void) fputs(cmdbuf, stdout);
				(void) fputs("\n", stdout);
			}
			if ((id = fork()) < 0) {
				error("cannot fork, try again later");
				break;
			}
			if (id == (pid_t)0) {
				/*
				 * if stdin is a pipe, need to close it so
				 * that the terminal is really stdin for
				 * the command
				 */
				(void) fclose(stdin);
				(void) fclose(pg_stdin);
				(void) dup(fileno(stdout));
				(void) execl(shell, shell, "-c", cmdptr, 0);
				(void) perror("exec");
				exit(1);
			}
			(void) signal(SIGINT, SIG_IGN);
			(void) signal(SIGQUIT, SIG_IGN);
			if (catch_susp)
				(void) signal(SIGTSTP, SIG_DFL);
			while (wait((int *)0) != id);
			{
				if (errno == ECHILD)
					break;
				else
					errno = 0;
			}
			(void) fputs("!\n", stdout);
			(void) fflush(stdout);
			(void) signal(SIGINT, on_brk);
			(void) signal(SIGQUIT, on_brk);
			if (catch_susp)
				(void) signal(SIGTSTP, onsusp);
			break;
		default:
			BEEP();
			break;
		}
	}
}

static int
number()
{
	int i;
	char *p;

	i = 0;
	sign = 0;
	p = cmdptr;
	BLANKS(p);
	if (*p == '+') {
		p++;
		sign = 1;
	}
	else
	if (*p == '-') {
		p++;
		sign = -1;
	}
	while (isdigit(*p))
		i = i * 10 + *p++ - '0';
	cmdptr = p;
	return (i);
}

static int
ttyin()
{
	char *sptr, *p;
	wchar_t ch;
	int slash = 0;
	int state = 0;
	int width, length;
	char multic[MB_LEN_MAX];
	int 	len;

	(void) fixterm();
	/* initialize state processing */
	(void) set_state(&state, ' ', (char *)0);
	sptr = cmdbuf;
	while (state != 10) {
		if ((ch = readch()) < 0 || !iswascii(ch) && !iswprint(ch)) {
			BEEP();
			continue;
		}

		if ((length = wctomb(multic, ch)) < 0)
			length = 0;
		multic[length] = 0;

		if (ch == '\n' && !slash)
			break;
		if (ch == erasechar() && !slash) {
			if (sptr > cmdbuf) {
				char *oldp = cmdbuf;
				wchar_t wchar;
				p = cmdbuf;
				while (p  < sptr) {
					oldp = p;
					len = mbtowc(&wchar, p, MB_CUR_MAX);
					if (len <= 0) {
						wchar = (unsigned char)*p;
						len = 1;
					}
					p += len;
				}
				if ((width = wcwidth(wchar)) <= 0)
					/* ascii control character */
					width = 2;
				promptlen -= width;
				while (width--)
					(void) fputs("\b \b", stdout);
				sptr = oldp;
			}
			(void) set_state(&state, ch, sptr);
			(void) fflush(stdout);
			continue;
		}
		else
		if (ch == killchar() && !slash) {
			if (hard_copy)
				(void) putwchar(ch);
			(void) resetterm();
			return (1);
		}
		if (ch < ' ')
			width = 2;
		else
			if ((width = wcwidth(ch)) <= 0)
				width = 0;
		if (slash) {
			slash = 0;
			(void) fputs("\b \b", stdout);
			sptr--;
			promptlen--;
		} else /* is there room to keep this character? */
		if (sptr >= cmdbuf + sizeof (cmdbuf) ||
		    promptlen + width >= columns) {
			BEEP();
			continue;
		}
		else
		if (ch == '\\')
			slash++;
		if (set_state(&state, ch, sptr) == 0) {
			BEEP();
			continue;
		}
		(void) strncpy(sptr, multic, (size_t)length);
		sptr += length;
		if (ch < ' ') {
			ch += 0100;
			multic[0] = '^';
			multic[1] = ch;
			length = 2;
		}
		p = multic;
		while (length--)
			(void) putchar(*p++);
		promptlen += width;
		(void) fflush(stdout);
	}

	*sptr = '\0';
	kill_line();
	(void) fflush(stdout);
	(void) resetterm();
	return (0);
}

static	int
set_state(pstate, c, pc)
int *pstate;
wchar_t c;
char *pc;
{
	static char *psign;
	static char *pnumber;
	static char *pcommand;
	static int slash;

	if (*pstate == 0) {
		psign = (char *)NULL;
		pnumber = (char *)NULL;
		pcommand = (char *)NULL;
		*pstate = 1;
		slash = 0;
		return (1);
	}
	if (c == '\\' && !slash) {
		slash++;
		return (1);
	}
	if (c == erasechar() && !slash)
		switch (*pstate) {
		case 4:
			if (pc > pcommand)
				return (1);
			pcommand = (char *)NULL;
			/*FALLTHROUGH*/

		case 3:
			if (pnumber && pc > pnumber) {
				*pstate = 3;
				return (1);
			}
			pnumber = (char *)NULL;
			/*FALLTHROUGH*/

		case 2:
			if (psign && pc > psign) {
				*pstate = 2;
				return (1);
			}
			psign = (char *)NULL;
			/*FALLTHROUGH*/

		case 1:
			*pstate = 1;
			return (1);
		}

	slash = 0;
	switch (*pstate) {
	case 1: /* before recieving anything interesting */
		if (c == '\t' || (!nflag && c == ' '))
			return (1);
		if (c == '+' || c == '-') {
			psign = pc;
			*pstate = 2;
			return (1);
		}
		/*FALLTHROUGH*/

	case 2: /* recieved sign, waiting for digit */
		if (iswascii(c) && isdigit(c)) {
			pnumber = pc;
			*pstate = 3;
			return (1);
		}
		/*FALLTHROUGH*/

	case 3: /* recieved digit, waiting for the rest of the number */
		if (iswascii(c) && isdigit(c))
			return (1);
		if (iswascii(c) && pg_strchr("h\014.wz\004dqQfl np$", c)) {
			pcommand = pc;
			if (nflag)
				*pstate = 10;
			else
				*pstate = 4;
			return (1);
		}
		if (iswascii(c) && pg_strchr("s/^?!", c)) {
			pcommand = pc;
			*pstate = 4;
			return (1);
		}
		return (0);
	case 4:
		return (1);
	}
	return (0);
}

static	int
readch()
{
	return (fgetwc(pg_stdin));
}

static void
help()
{
	if (clropt)
		doclear();

	(void) fputs(gettext(
"-------------------------------------------------------\n"
"  h                     help\n"
"  q or Q                quit\n"
"  <blank> or <newline>  next page\n"
"  l                     next line\n"
"  d or <^D>             display half a page more\n"
"  . or <^L>             redisplay current page\n"
"  f                     skip the next page forward\n"
"  n                     next file\n"
"  p                     previous file\n"
"  $                     last page\n"
"  w or z                set window size and display next page\n"
"  s savefile            save current file in savefile\n"
"  /pattern/             search forward for pattern\n"
"  ?pattern? or\n"
"  ^pattern^             search backward for pattern\n"
"  !command              execute command\n"
"\n"
"Most commands can be preceeded by a number, as in:\n"
"+1<newline> (next page); -1<newline> (previous page); 1<newline> (page 1).\n"
"\n"
"See the manual page for more detail.\n"
"-------------------------------------------------------\n"),
	    stdout);
}

/*
 * Skip nskip files in the file list (from the command line). Nskip may be
 * negative.
 */

static int
skipf(nskip)
int nskip;
{
	if (fnum + nskip < 0) {
		nskip = -fnum;
		if (nskip == 0)
			error("No previous file");
	}
	else
	if (fnum + nskip > nfiles - 1) {
		nskip = (nfiles - 1) - fnum;
		if (nskip == 0)
			error("No next file");
	}
	return (nskip);
}

/*
 * Check whether the file named by fs is a file which the user may
 * access.  If it is, return the opened file. Otherwise return NULL.
 */

static FILE *
checkf(fs)
char *fs;
{
	struct stat stbuf;
	FILE *f;
	int fd;
	int f_was_opened;

	pipe_in = 0;
	if (strcmp(fs, "-") == 0) {
		if (tmp_fin == NULL)
			f = stdin;
		else {
			rewind(tmp_fin);
			f = tmp_fin;
		}
		f_was_opened = 0;
	} else {
		if ((f = fopen(fs, "r")) == (FILE *)NULL) {
			(void) fflush(stdout);
			perror(fs);
			return ((FILE *)NULL);
		}
		f_was_opened = 1;
	}
	if (fstat(fileno(f), &stbuf) == -1) {
		if (f_was_opened)
			(void) fclose(f);
		(void) fflush(stdout);
		perror(fs);
		return ((FILE *)NULL);
	}
	if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
		if (f_was_opened)
			(void) fclose(f);
		(void) fprintf(stderr, "pg: ");
		(void) fprintf(stderr, gettext("%s is a directory\n"), fs);
		return ((FILE *)NULL);
	}
	if ((stbuf.st_mode & S_IFMT) == S_IFREG) {
		if (f == stdin)		/* It may have been read from */
			rewind(f);	/* already, and not reopened  */
	} else {
		if (f != stdin) {
			if (f_was_opened)
				(void) fclose(f);
			(void) fprintf(stderr, "pg: ");
			(void) fprintf(stderr, gettext(
			"special files only handled as standard input\n"));
			return ((FILE *)NULL);
		} else {
			if ((fd = mkstemp(tmp_name)) < 0) {
			    (void) perror(tmp_name);
			    return ((FILE *)NULL);
			}
			(void) close(fd);
			if ((tmp_fou = fopen(tmp_name, "w")) == NULL) {
				(void) perror(tmp_name);
				return ((FILE *)NULL);
			}
			if ((tmp_fin = fopen(tmp_name, "r")) == NULL) {
				(void) perror(tmp_name);
				return ((FILE *)NULL);
			}
			pipe_in = 1;
		}
	}
	lineset(BOF);
	return (f);
}

static void
copy_file(f, out)
FILE *f, *out;
{
	int c;

	while ((c = getc(f)) != EOF)
		(void) putc(c, out);

}

static void
re_error(i)
int i;
{
	int j;
	static struct messages {
		char *message;
		int number;
		} re_errmsg[] = {
		"Pattern not found",				1,
		"Range endpoint too large",			11,
		"Bad number",					16,
		"`\\digit' out of range",			25,
		"No remembered search string",  		41,
		"\\( \\) imbalance",				42,
		"Too many \\(",					43,
		"More than two numbers given in \\{ \\}",  	44,
		"} expected after \\",				45,
		"First number exceeds second in \\{ \\}",  	46,
		"[] imbalance",					49,
		"Regular expression overflow",			50,
		"Illegal byte sequence",			67,
		"Bad regular expression",			0
		};

	for (j = 0; re_errmsg[j].number != 0; j++)
		if (re_errmsg[j].number == i)
			break;
	error(re_errmsg[j].message);
	longjmp(restore, 1);  /* restore to search() */
}

/*
 * Search for nth ocurrence of regular expression contained in buf in the file
 *	negative n implies backward search
 *	n 'guaranteed' non-zero
 */


static int
search(buf, n)
char buf[];
off_t n;
{
	int direction;
	static char *expbuf;
	char *nexpbuf;
	int END_COND;

	if (setjmp(restore) <= 0) {
		nexpbuf = compile(buf, (char *)0, (char *)0);
		if (regerrno) {
			if (regerrno != 41 || expbuf == NULL)
				re_error(regerrno);
		} else {
			if (expbuf)
				free(expbuf);
			expbuf = nexpbuf;
		}

		if (n < 0) {	/* search back */
			direction = -1;
			(void) find(0, old_ss.first_line);
			END_COND = BOF;
		} else {
			direction = 1;
			(void) find(0, old_ss.last_line);
			END_COND = EOF;
		}

		while (find(1, direction) != END_COND) {
			if (brk_hit)
				break;
			if (step(Line, expbuf))
				if ((n -= direction) == 0) {
					switch (leave_search) {
					case 't':
						new_ss.first_line =
						    find(1, (off_t)0);
						new_ss.last_line =
						    new_ss.first_line +
						    (off_t)window
						    - 1;
						break;
					case 'b':
						new_ss.last_line =
						    find(1, (off_t)0);
						new_ss.first_line =
						    new_ss.last_line -
						    (off_t)window
						    + 1;
						break;
					case 'm':
						new_ss.first_line =
						    find(1, (off_t)0) -
						    ((off_t)window - 1)/2;
						new_ss.last_line =
						    new_ss.first_line +
						    (off_t)window
						    - 1;
						break;
					}
					return (1);
				}
		}
		re_error(1); /* Pattern not found */
	}
	BEEP();
	return (0);
}

/*
 *	find -- find line in file f, subject to certain constraints.
 *
 *	This is the reason for all the funny stuff with sign and nlines.
 *	We need to be able to differentiate between relative and abosolute
 *	address specifications.
 *
 *	So...there are basically three cases that this routine
 *	handles. Either line is zero, which  means there is to be
 *	no motion (because line numbers start at one), or
 *	how and line specify a number, or line itself is negative,
 *	which is the same as having how == -1 and line == abs(line).
 *
 *	Then, figure where exactly it is that we are going (an absolute
 *	line number). Find out if it is within what we have read,
 *	if so, go there without further ado. Otherwise, do some
 *	magic to get there, saving all the intervening lines,
 *	in case the user wants to see them some time later.
 *
 *	In any case, return the line number that we end up at.
 *	(This is used by search() and screen()). If we go past EOF,
 *	return EOF.
 *	This EOF will go away eventually, as pg is expanded to
 *	handle multiple files as one huge one. Then EOF will
 *	mean we have run off the file list.
 *	If the requested line number is too far back, return BOF.
 */

static off_t
find(how, line)	/* find the line and seek there */
int how;
off_t line;
{
	/* no compacted memory yet */
	FILE *f = in_file;
	off_t where;

	if (how == 0)
		where = line;
	else
		if (dot == zero - 1)
			where = how * line;
		else
			where = how * line + dot->l_no;

	/* now, where is either at, before, or after dol */
	/* most likely case is after, so do it first */

	eoflag = 0;
	if (where >= dol->l_no) {
		if (doliseof) {
			dot = dol;
			eoflag++;
			return (EOF);
		}
		if (pipe_in)
			in_file = f = stdin;
		else
			(void) fseeko(f, (off_t)dol->l_addr, SEEK_SET);
		dot = dol - 1;
		while ((nchars = getaline(f)) != EOF) {
			dot++;
			newdol(f);
			if (where == dot->l_no || brk_hit)
				break;
		}
		if (nchars != EOF)
			return (dot->l_no);
		else { /* EOF */
			dot = dol;
			eoflag++;
			doliseof++;
			eofl_no = dol->l_no;
			return (EOF);
		}
	} else { /* where < dol->l_no */
		if (pipe_in) {
			(void) fflush(tmp_fou);
			in_file = f = tmp_fin;
		}
		if (where < zero->l_no) {
			(void) fseeko(f, (off_t)zero->l_addr, SEEK_SET);
			dot = zero - 1;
			return (BOF);
		} else {
			dot = zero + where - 1;
			(void) fseeko(f, (off_t)dot->l_addr, SEEK_SET);
			nchars = getaline(f);
			return (dot->l_no);
		}
	}
}

static FILE *fileptr;
static int (*rdchar)();

static int
mrdchar()
{
	return (rdchar(fileptr));
}

/*
 * Get a logical line
 */

static off_t
getaline(f)
FILE *f;
{
	char	*p;
	int	column;
	static char multic[MB_LEN_MAX];
	static int savlength;
	wchar_t c;
	int length, width;

	if (pipe_in && f == stdin)
		rdchar = fgetputc;
	else
		rdchar = (int (*)())fgetwc;

	fileptr = f;
	/* copy overlap from previous call to getaline */
	if (savlength)
		(void) strncpy(Line, multic, (size_t)savlength);
	for (column = 0, p = Line + savlength; ; ) {
		if ((c = mrdchar()) <= 0) {
			clearerr(f);
			if (p > Line) {	/* last line doesn't have '\n', */
				*p++ = '\n';
				*p = '\0';	/* print it any way */
				return (column);
			}
			return (EOF);
		}
		length = wctomb(multic, c);
		if (length < 0) {
			length = -length;
			c = 0;
		}
		if ((width = wcwidth(c)) < 0)
			width = 0;
		if (column + width > columns && !fflag)
			break;

		if (p + length > &Line[LINSIZ - 2] && c != '\n')
			break;
		(void) strncpy(p, multic, (size_t)length);
		p += length;
		column += width;
		/* don't have any overlap here */
		length = 0;
		switch (c) {
		case '\t': /* just a guess */
			column = 1 + (column | 7);
			break;
		case '\b':
			if (column > 0)
				column--;
			break;
		case '\r':
			column = 0;
			break;
		}
		if (c == '\n')
			break;
		if (column >= columns && !fflag)
			break;
	}
	if (c != '\n') { /* We're stopping in the middle of the line */
		if (column != columns || !auto_right_margin)
			*p++ = '\n';	/* for the display */
		/* save overlap for next call to getaline */
		savlength = length;
		if (savlength == 0) {
			/*
			 * check if following byte is newline and get
			 * it if it is
			 */
			c = fgetwc(f);
			if (c == '\n') {
				/* gobble and copy (if necessary) newline */
				(void) ungetwc(c, f);
				(void) (*rdchar)(f);
			} else if (c == EOF)
				clearerr(f);
			else
				(void) ungetwc(c, f);
		}
	} else
		savlength = 0;
	*p = 0;
	return (column);
}

static void
save_input(f)
FILE *f;
{
	if (pipe_in) {
		save_pipe();
		in_file = tmp_fin;
		pipe_in = 0;
	}
	(void) fseeko(in_file, (off_t)0, SEEK_SET);
	copy_file(in_file, f);
}

static void
save_pipe()
{
	if (!doliseof)
		while (fgetputc(stdin) != EOF)
			if (brk_hit) {
				brk_hit = 0;
				error("Piped input only partially saved");
				break;
			}
	(void) fclose(tmp_fou);
}

static int
fgetputc(f)	/* copy anything read from a pipe to tmp_fou */
FILE *f;
{
	int c;

	if ((c = fgetwc(f)) != EOF)
		(void) fputwc(c, tmp_fou);
	return (c);
}

static	void
lineset(how)	/* initialize line memory */
int how;
{
	if (zero == NULL) {
		nlall = 128;
		zero = (LINE *) malloc(nlall * sizeof (LINE));
	}
	dol = contig = zero;
	zero->l_no = 1;
	zero->l_addr = 0l;
	if (how == BOF) {
		dot = zero - 1;
		eoflag = 0;
		doliseof = 0;
		eofl_no = -1;
	} else {
		dot = dol;
		eoflag = 1;
		doliseof = 1;
		eofl_no = 1;
	}
}

static void
newdol(f)	/* add address of new 'dol' */
		/* assumes that f is currently at beginning of said line */
		/* updates dol */
FILE *f;
{
	int diff;

	if ((dol - zero) + 1 >= nlall) {
		LINE *ozero = zero;

		nlall += 512;
		if ((zero = (LINE *)realloc((char *)zero,
		    (unsigned)(nlall * sizeof (LINE)))) == NULL) {
			zero = ozero;
			compact();
		}
		diff = (int)((int)zero - (int)ozero);
		dot = (LINE *)((int)dot + diff);
		dol = (LINE *)((int)dol + diff);
		contig = (LINE *)((int)contig + diff);
	}
	dol++;
	if (!pipe_in)
		dol->l_addr = (off_t)ftello(f);
	else {
		(void) fflush(tmp_fou);
		dol->l_addr = (off_t)ftello(tmp_fou);
	}
	dol->l_no = (dol-1)->l_no + 1;
}

static void
compact()
{
	(void) perror("realloc");
	end_it();

}

static void
terminit()	/* set up terminal dependencies from termlib */
{
	int err_ret;
	struct termio ntty;

	for (;;) {
		pid_t my_tgid;
		my_tgid = tcgetpgrp(1);
		if (my_tgid == -1 || my_tgid == my_pgid)
			break;
		(void) kill(-my_pgid, SIGTTOU);
	}

	if ((freopen("/dev/tty", "r+", stdout)) == NULL) {
		(void) perror("open");
		exit(1);
	}
	(void) ioctl(fileno(stdout), TCGETA, &otty);
	termflg = 1;

	(void) setupterm(0, fileno(stdout), &err_ret);
	(void) ioctl(fileno(stdout), TCGETA, &ntty);
	ntty.c_lflag &= ~(ECHONL | ECHO | ICANON);
	ntty.c_cc[VMIN] = 1;
	ntty.c_cc[VTIME] = 1;
	(void) ioctl(fileno(stdout), TCSETAW, &ntty);
	pg_stdin = fdopen(dup(fileno(stdout)), "r");
	(void) saveterm();
	(void) resetterm();
	if (lines <= 0 || hard_copy) {
		hard_copy = 1;
		lines = 24;
	}
	if (columns <= 0)
		columns = 80;
	if (clropt && !clear_screen)
		clropt = 0;
	if ((shell = getenv("SHELL")) == (char *)NULL)
			shell = "/usr/bin/sh";
}

static void
error(mess)
char *mess;
{
	kill_line();
	sopr(gettext(mess), 1);
	prompt((char *)NULL);
	errors++;
}

static void
prompt(filename)
char *filename;
{
	char outstr[PROMPTSIZE+6];
	int pagenum;
	if (filename != NULL) {
		/*
		 * TRANSLATION_NOTE
		 * 	%s is a filename.
		 */
		(void) sprintf(outstr, gettext("(Next file: %s)"), filename);
	} else {
		if ((pagenum = (int)((new_ss.last_line-2)/(window-1)+1))
						> 999999)
			pagenum = 999999;
		(void) sprintf(outstr, promptstr, pagenum);
	}
	sopr(outstr, 1);
	(void) fflush(stdout);
}

/*
 *  sopr puts out the message (please no \n's) surrounded by standout
 *  begins and ends
 */

static void
sopr(m, count)
	char *m;
	int count;
{
	wchar_t	wc;
	int	len, n;
	char	*p;

	if (count) {
		p = m;
		for (; *p; p += len) {
			if ((len = mbtowc(&wc, p, MB_CUR_MAX)) <= 0) {
				len = 1;
				continue;
			}
			if ((n = wcwidth(wc)) > 0)
				promptlen += n;
		}
	}
	if (soflag && enter_standout_mode && exit_standout_mode) {
		(void) putp(enter_standout_mode);
		(void) fputs(m, stdout);
		(void) putp(exit_standout_mode);
	}
	else
		(void) fputs(m, stdout);
}

static void
doclear()
{
	if (clear_screen)
		(void) putp(clear_screen);
	(void) putchar('\r');  /* this resets the terminal drivers character */
			/* count in case it is trying to expand tabs  */

}

static void
kill_line()
{
	erase_line(0);
	if (!clr_eol) (void) putchar('\r');

}

/* erase from after col to end of prompt */
static void
erase_line(col)
int col;
{

	if (promptlen == 0)
		return;
	if (hard_copy)
		(void) putchar('\n');
	else {
		if (col == 0)
			(void) putchar('\r');
		if (clr_eol) {
			(void) putp(clr_eol);
			/* for the terminal driver again */
			(void) putchar('\r');
		}
		else
			for (col = promptlen - col; col > 0; col--)
				(void) putchar(' ');
	}
	promptlen = 0;
}

/*
 * Come here if a quit or interrupt signal is received
 */

static void
on_brk(sno)
	int sno;	/* signal number generated */
{
	(void) signal(sno, on_brk);
	if (!inwait) {
		BEEP();
		brk_hit = 1;
	} else {
		brk_hit = 0;
		longjmp(restore, 1);
	}
}

/*
 * Clean up terminal state and exit.
 */

void
end_it()
{

	if (out_is_tty) {
		kill_line();
		(void) resetterm();
		if (termflg)
			(void) ioctl(fileno(stdout), TCSETAW, &otty);
	}
	if (tmp_fin)
		(void) fclose(tmp_fin);
	if (tmp_fou)
		(void) fclose(tmp_fou);
	if (tmp_fou || tmp_fin)
		(void) unlink(tmp_name);
	exit(status);
}

void
onsusp()
{
	int ttou_is_dfl;

	/* ignore SIGTTOU so following resetterm and flush works */
	ttou_is_dfl = (signal(SIGTTOU, SIG_IGN) == SIG_DFL);
	(void) resetterm();
	(void) fflush(stdout);
	if (ttou_is_dfl)
		(void) signal(SIGTTOU, SIG_DFL);

	/* send SIGTSTP to stop this process group */
	(void) signal(SIGTSTP, SIG_DFL);
	(void) kill(-my_pgid, SIGTSTP);

	/* continued - reset the terminal */
#ifdef __STDC__
	(void) signal(SIGTSTP, (void (*)(int))onsusp);
#else
	(void) signal(SIGTSTP, (void (*))onsusp);
#endif
	(void) resetterm();
	if (inwait)
		longjmp(restore, -1);

}

static char *
pg_strchr(str, c)
char	*str;
wchar_t	c;
{
	while (*str) {
		if (c == *str)
			return (str);
		str++;
	}
	return (0);
}

void
usage()
{
	(void) fprintf(stderr, gettext(
"Usage: pg [-number] [-p string] [-cefnrs] [+line] [+/pattern/] files\n"));
	exit(1);
}
