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
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 *
 * Portions of this file developed by DEY Storage Systems, Inc. are licensed
 * under the terms of the Common Development and Distribution License (CDDL)
 * version 1.0 only.  The use of subsequent versions of the License are
 * is specifically prohibited unless those terms are not in conflict with
 * version 1.0 of the License.  You can find this license on-line at
 * http://www.illumos.org/license/CDDL
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <limits.h>
#include <wchar.h>
#include <locale.h>
#include <langinfo.h>
#include <stropts.h>
#include <poll.h>
#include <errno.h>
#include <stdarg.h>
#include "getresponse.h"

#define	HEAD	0
#define	TAIL	1
#define	FALSE 0
#define	TRUE 1
#define	MAXSBUF 255
#define	MAXIBUF 512
#define	MAXINSERTS 5
#define	BUFSIZE LINE_MAX
#define	MAXARGS 255
#define	INSPAT_STR	"{}"	/* default replstr string for -[Ii]	*/
#define	FORK_RETRY	5

#define	QBUF_STARTLEN 255  /* start size of growable string buffer */
#define	QBUF_INC 100	   /* how much to grow a growable string by */

/* We use these macros to help make formatting look "consistent" */
#define	EMSG(s)		ermsg(gettext(s "\n"))
#define	EMSG2(s, a)	ermsg(gettext(s "\n"), a)
#define	PERR(s)		perror(gettext("xargs: " s))

/* Some common error messages */

#define	LIST2LONG	"Argument list too long"
#define	ARG2LONG	"A single argument was greater than %d bytes"
#define	MALLOCFAIL	"Memory allocation failure"
#define	CORRUPTFILE	"Corrupt input file"
#define	WAITFAIL	"Wait failure"
#define	CHILDSIG	"Child killed with signal %d"
#define	CHILDFAIL	"Command could not continue processing data"
#define	FORKFAIL	"Could not fork child"
#define	EXECFAIL	"Could not exec command"
#define	MISSQUOTE	"Missing quote"
#define	BADESCAPE	"Incomplete escape"
#define	IBUFOVERFLOW	"Insert buffer overflow"

#define	_(x)	gettext(x)

static wctype_t	blank;
static char	*arglist[MAXARGS+1];
static char	argbuf[BUFSIZE * 2 + 1];
static char	lastarg[BUFSIZE + 1];
static char	**ARGV = arglist;
static char	*LEOF = "_";
static char	*INSPAT = INSPAT_STR;
static char	ins_buf[MAXIBUF];
static char	*p_ibuf;

static struct inserts {
	char	**p_ARGV;	/* where to put newarg ptr in arg list */
	char	*p_skel;	/* ptr to arg template */
} saveargv[MAXINSERTS];

static int	PROMPT = -1;
static int	BUFLIM = BUFSIZE;
static int	N_ARGS = 0;
static int	N_args = 0;
static int	N_lines = 0;
static int	DASHX = FALSE;
static int	MORE = TRUE;
static int	PER_LINE = FALSE;
static int	ERR = FALSE;
static int	OK = TRUE;
static int	LEGAL = FALSE;
static int	TRACE = FALSE;
static int	INSERT = FALSE;
static int	ZERO = FALSE;
static int	linesize = 0;
static int	ibufsize = 0;
static int	exitstat = 0;	/* our exit status			*/
static int	mac;		/* modified argc, after parsing		*/
static char	**mav;		/* modified argv, after parsing		*/
static int	n_inserts;	/* # of insertions.			*/

/* our usage message:							*/
#define	USAGEMSG "Usage: xargs: [-t] [-p] [-0] [-e[eofstr]] [-E eofstr] "\
	"[-I replstr] [-i[replstr]] [-L #] [-l[#]] [-n # [-x]] [-s size] "\
	"[cmd [args ...]]\n"

static int	echoargs();
static wint_t	getwchr(char *, size_t *);
static int	lcall(char *sub, char **subargs);
static void	addibuf(struct inserts *p);
static void	ermsg(char *messages, ...);
static char	*addarg(char *arg);
static void	store_str(char **, char *, size_t);
static char	*getarg(char *);
static char	*insert(char *pattern, char *subst);
static void	usage();
static void	parseargs();

int
main(int argc, char **argv)
{
	int	j;
	struct inserts *psave;
	int c;
	int	initsize;
	char	*cmdname, **initlist;
	char	*arg;
	char	*next;

	/* initialization */
	blank = wctype("blank");
	n_inserts = 0;
	psave = saveargv;
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D 		*/
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't 		*/
#endif
	(void) textdomain(TEXT_DOMAIN);
	if (init_yes() < 0) {
		ermsg(_(ERR_MSG_INIT_YES), strerror(errno));
		exit(1);
	}

	parseargs(argc, argv);

	/* handling all of xargs arguments:				*/
	while ((c = getopt(mac, mav, "0tpe:E:I:i:L:l:n:s:x")) != EOF) {
		switch (c) {
		case '0':
			ZERO = TRUE;
			break;

		case 't':	/* -t: turn trace mode on		*/
			TRACE = TRUE;
			break;

		case 'p':	/* -p: turn on prompt mode.		*/
			if ((PROMPT = open("/dev/tty", O_RDONLY)) == -1) {
				PERR("can't read from tty for -p");
			} else {
				TRACE = TRUE;
			}
			break;

		case 'e':
			/*
			 * -e[eofstr]: set/disable end-of-file.
			 * N.B. that an argument *isn't* required here; but
			 * parseargs forced an argument if not was given.  The
			 * forced argument is the default...
			 */
			LEOF = optarg; /* can be empty */
			break;

		case 'E':
			/*
			 * -E eofstr: change end-of-file string.
			 * eofstr *is* required here, but can be empty:
			 */
			LEOF = optarg;
			break;

		case 'I':
			/* -I replstr: Insert mode. replstr *is* required. */
			INSERT = PER_LINE = LEGAL = TRUE;
			N_ARGS = 0;
			INSPAT = optarg;
			if (*optarg == '\0') {
				ermsg(_("Option requires an argument: -%c\n"),
				    c);
			}
			break;

		case 'i':
			/*
			 * -i [replstr]: insert mode, with *optional* replstr.
			 * N.B. that an argument *isn't* required here; if
			 * it's not given, then the string INSPAT_STR will
			 * be assumed.
			 *
			 * Since getopts(3C) doesn't handle the case of an
			 * optional variable argument at all, we have to
			 * parse this by hand:
			 */

			INSERT = PER_LINE = LEGAL = TRUE;
			N_ARGS = 0;
			if ((optarg != NULL) && (*optarg != '\0')) {
				INSPAT = optarg;
			} else {
				/*
				 * here, there is no next argument. so
				 * we reset INSPAT to the INSPAT_STR.
				 * we *have* to do this, as -i/I may have
				 * been given previously, and XCU4 requires
				 * that only "the last one specified takes
				 * effect".
				 */
				INSPAT = INSPAT_STR;
			}
			break;

		case 'L':
			/*
			 * -L number: # of times cmd is executed
			 * number *is* required here:
			 */
			PER_LINE = TRUE;
			N_ARGS = 0;
			INSERT = FALSE;
			if ((PER_LINE = atoi(optarg)) <= 0) {
				ermsg(_("#lines must be positive int: %s\n"),
				    optarg);
			}
			break;

		case 'l':
			/*
			 * -l [number]: # of times cmd is executed
			 * N.B. that an argument *isn't* required here; if
			 * it's not given, then 1 is assumed.
			 *
			 * parseargs handles the optional arg processing.
			 */

			PER_LINE = LEGAL = TRUE;  /* initialization	*/
			N_ARGS = 0;
			INSERT = FALSE;

			if ((optarg != NULL) && (*optarg != '\0')) {
				if ((PER_LINE = atoi(optarg)) <= 0)
					PER_LINE = 1;
			}
			break;

		case 'n':	/* -n number: # stdin args		*/
			/*
			 * -n number: # stdin args.
			 * number *is* required here:
			 */
			if ((N_ARGS = atoi(optarg)) <= 0) {
				ermsg(_("#args must be positive int: %s\n"),
				    optarg);
			} else {
				LEGAL = DASHX || N_ARGS == 1;
				INSERT = PER_LINE = FALSE;
			}
			break;

		case 's':	/* -s size: set max size of each arg list */
			BUFLIM = atoi(optarg);
			if (BUFLIM > BUFSIZE || BUFLIM <= 0) {
				ermsg(_("0 < max-cmd-line-size <= %d: %s\n"),
				    BUFSIZE, optarg);
			}
			break;

		case 'x':	/* -x: terminate if args > size limit	*/
			DASHX = LEGAL = TRUE;
			break;

		default:
			/*
			 * bad argument. complain and get ready to die.
			 */
			usage();
			exit(2);
			break;
		}
	}

	/*
	 * if anything called ermsg(), something screwed up, so
	 * we exit early.
	 */
	if (OK == FALSE) {
		usage();
		exit(2);
	}

	/*
	 * we're finished handling xargs's options, so now pick up
	 * the command name (if any), and it's options.
	 */


	mac -= optind;	/* dec arg count by what we've processed 	*/
	mav += optind;	/* inc to current mav				*/

	if (mac <= 0) {	/* if there're no more args to process,	*/
		cmdname = "/usr/bin/echo";	/* our default command	*/
		*ARGV++ = addarg(cmdname);	/* use the default cmd.	*/
	} else {	/* otherwise keep parsing rest of the string.	*/
		/*
		 * note that we can't use getopts(3C), and *must* parse
		 * this by hand, as we don't know apriori what options the
		 * command will take.
		 */
		cmdname = *mav;	/* get the command name	*/


		/* pick up the remaining args from the command line:	*/
		while ((OK == TRUE) && (mac-- > 0)) {
			/*
			 * while we haven't crapped out, and there's
			 * work to do:
			 */
			if (INSERT && ! ERR) {
				if (strstr(*mav, INSPAT) != NULL) {
					if (++n_inserts > MAXINSERTS) {
						ermsg(_("too many args "
						    "with %s\n"), INSPAT);
						ERR = TRUE;
					}
					psave->p_ARGV = ARGV;
					(psave++)->p_skel = *mav;
				}
			}
			*ARGV++ = addarg(*mav++);
		}
	}

	/* pick up args from standard input */

	initlist = ARGV;
	initsize = linesize;
	lastarg[0] = '\0';

	while (OK) {
		N_args = 0;
		N_lines = 0;
		ARGV = initlist;
		linesize = initsize;
		next = argbuf;

		while (MORE || (lastarg[0] != '\0')) {
			int l;

			if (*lastarg != '\0') {
				arg = strcpy(next, lastarg);
				*lastarg = '\0';
			} else if ((arg = getarg(next)) == NULL) {
				break;
			}

			l = strlen(arg) + 1;
			linesize += l;
			next += l;

			/* Inserts are handled specially later. */
			if ((n_inserts == 0) && (linesize >= BUFLIM)) {
				/*
				 * Legal indicates hard fail if the list is
				 * truncated due to size.  So fail, or if we
				 * cannot create any list because it would be
				 * too big.
				 */
				if (LEGAL || N_args == 0) {
					EMSG(LIST2LONG);
					exit(2);
					/* NOTREACHED */
				}

				/*
				 * Otherwise just save argument for later.
				 */
				(void) strcpy(lastarg, arg);
				break;
			}

			*ARGV++ = arg;

			N_args++;

			if ((PER_LINE && N_lines >= PER_LINE) ||
			    (N_ARGS && (N_args) >= N_ARGS)) {
				break;
			}


			if ((ARGV - arglist) == MAXARGS) {
				break;
			}
		}

		*ARGV = NULL;
		if (N_args == 0) {
			/* Reached the end with no more work. */
			exit(exitstat);
		}

		/* insert arg if requested */

		if (!ERR && INSERT) {

			p_ibuf = ins_buf;
			ARGV--;
			j = ibufsize = 0;
			for (psave = saveargv; ++j <= n_inserts; ++psave) {
				addibuf(psave);
				if (ERR)
					break;
			}
		}
		*ARGV = NULL;

		if (n_inserts > 0) {
			/*
			 * if we've done any insertions, re-calculate the
			 * linesize. bomb out if we've exceeded our length.
			 */
			linesize = 0;
			for (ARGV = arglist; *ARGV != NULL; ARGV++) {
				linesize += strlen(*ARGV) + 1;
			}
			if (linesize >= BUFLIM) {
				EMSG(LIST2LONG);
				exit(2);
				/* NOTREACHED */
			}
		}

		/* exec command */

		if (!ERR) {
			if (!MORE &&
			    (PER_LINE && N_lines == 0 || N_ARGS && N_args == 0))
				exit(exitstat);
			OK = TRUE;
			j = TRACE ? echoargs() : TRUE;
			if (j) {
				/*
				 * for xcu4, all invocations of cmdname must
				 * return 0, in order for us to return 0.
				 * so if we have a non-zero status here,
				 * quit immediately.
				 */
				exitstat |= lcall(cmdname, arglist);
			}
		}
	}

	if (OK)
		return (exitstat);

	/*
	 * if exitstat was set, to match XCU4 complience,
	 * return that value, otherwise, return 1.
	 */
	return (exitstat ? exitstat : 1);
}

static char *
addarg(char *arg)
{
	linesize += (strlen(arg) + 1);
	return (arg);
}


static void
store_str(char **buffer, char *str, size_t len)
{
	(void) memcpy(*buffer, str, len);
	(*buffer)[len] = '\0';
	*buffer += len;
}


static char *
getarg(char *arg)
{
	char	*xarg = arg;
	wchar_t	c;
	char	mbc[MB_LEN_MAX];
	size_t	len;
	int	escape = 0;
	int	inquote = 0;

	arg[0] = '\0';

	while (MORE) {

		len = 0;
		c = getwchr(mbc, &len);

		if (((arg - xarg) + len) > BUFLIM) {
			EMSG2(ARG2LONG, BUFLIM);
			exit(2);
			ERR = TRUE;
			return (NULL);
		}

		switch (c) {
		case '\n':
			if (ZERO) {
				store_str(&arg, mbc, len);
				continue;
			}
			/* FALLTHRU */

		case '\0':
		case WEOF:	/* Note WEOF == EOF */

			if (escape) {
				EMSG(BADESCAPE);
				ERR = TRUE;
				return (NULL);
			}
			if (inquote) {
				EMSG(MISSQUOTE);
				ERR = TRUE;
				return (NULL);
			}

			N_lines++;
			break;

		case '"':
			if (ZERO || escape || (inquote == 1)) {
				/* treat it literally */
				escape = 0;
				store_str(&arg, mbc, len);

			} else if (inquote == 2) {
				/* terminating double quote */
				inquote = 0;

			} else {
				/* starting quoted string */
				inquote = 2;
			}
			continue;

		case '\'':
			if (ZERO || escape || (inquote == 2)) {
				/* treat it literally */
				escape = 0;
				store_str(&arg, mbc, len);

			} else if (inquote == 1) {
				/* terminating single quote */
				inquote = 0;

			} else {
				/* starting quoted string */
				inquote = 1;
			}
			continue;

		case '\\':
			/*
			 * Any unquoted character can be escaped by
			 * preceding it with a backslash.
			 */
			if (ZERO || inquote || escape) {
				escape = 0;
				store_str(&arg, mbc, len);
			} else {
				escape = 1;
			}
			continue;

		default:
			/* most times we will just want to store it */
			if (inquote || escape || ZERO || !iswctype(c, blank)) {
				escape = 0;
				store_str(&arg, mbc, len);
				continue;
			}
			/* unquoted blank */
			break;
		}

		/*
		 * At this point we are processing a complete argument.
		 */
		if (strcmp(xarg, LEOF) == 0 && *LEOF != '\0') {
			MORE = FALSE;
			return (NULL);
		}
		if (c == WEOF) {
			MORE = FALSE;
		}
		if (xarg[0] == '\0')
			continue;
		break;
	}

	return (xarg[0] == '\0' ? NULL : xarg);
}

/*
 * ermsg():	print out an error message, and indicate failure globally.
 *
 *	Assumes that message has already been gettext()'d. It would be
 *	nice if we could just do the gettext() here, but we can't, since
 *	since xgettext(1M) wouldn't be able to pick up our error message.
 */
/* PRINTFLIKE1 */
static void
ermsg(char *messages, ...)
{
	va_list	ap;

	va_start(ap, messages);

	(void) fprintf(stderr, "xargs: ");
	(void) vfprintf(stderr, messages, ap);

	va_end(ap);
	OK = FALSE;
}

static int
echoargs()
{
	char	**anarg;
	char	**tanarg;	/* tmp ptr			*/
	int		i;
	char		reply[LINE_MAX];

	tanarg = anarg = arglist-1;

	/*
	 * write out each argument, separated by a space. the tanarg
	 * nonsense is for xcu4 testsuite compliance - so that an
	 * extra space isn't echoed after the last argument.
	 */
	while (*++anarg) {		/* while there's an argument	*/
		++tanarg;		/* follow anarg			*/
		(void) write(2, *anarg, strlen(*anarg));

		if (*++tanarg) {	/* if there's another argument:	*/
			(void) write(2, " ", 1); /* add a space		*/
			--tanarg;	/* reset back to anarg		*/
		}
	}
	if (PROMPT == -1) {
		(void) write(2, "\n", 1);
		return (TRUE);
	}

	(void) write(2, "?...", 4);	/* ask the user for input	*/

	for (i = 0; i < LINE_MAX && read(PROMPT, &reply[i], 1) > 0; i++) {
		if (reply[i] == '\n') {
			if (i == 0)
				return (FALSE);
			break;
		}
	}
	reply[i] = 0;

	/* flush remainder of line if necessary */
	if (i == LINE_MAX) {
		char	bitbucket;

		while ((read(PROMPT, &bitbucket, 1) > 0) && (bitbucket != '\n'))
			;
	}

	return (yes_check(reply));
}


static char *
insert(char *pattern, char *subst)
{
	static char	buffer[MAXSBUF+1];
	int		len, ipatlen;
	char	*pat;
	char	*bufend;
	char	*pbuf;

	len = strlen(subst);
	ipatlen = strlen(INSPAT) - 1;
	pat = pattern - 1;
	pbuf = buffer;
	bufend = &buffer[MAXSBUF];

	while (*++pat) {
		if (strncmp(pat, INSPAT, ipatlen) == 0) {
			if (pbuf + len >= bufend) {
				break;
			} else {
				(void) strcpy(pbuf, subst);
				pat += ipatlen;
				pbuf += len;
			}
		} else {
			*pbuf++ = *pat;
			if (pbuf >= bufend)
				break;
		}
	}

	if (!*pat) {
		*pbuf = '\0';
		return (buffer);
	} else {
		ermsg(gettext("Maximum argument size with insertion via %s's "
		    "exceeded\n"), INSPAT);
		ERR = TRUE;
		return (NULL);
	}
}


static void
addibuf(struct inserts	*p)
{
	char	*newarg, *skel, *sub;
	int		l;

	skel = p->p_skel;
	sub = *ARGV;
	newarg = insert(skel, sub);
	if (ERR)
		return;

	l = strlen(newarg) + 1;
	if ((ibufsize += l) > MAXIBUF) {
		EMSG(IBUFOVERFLOW);
		ERR = TRUE;
	}
	(void) strcpy(p_ibuf, newarg);
	*(p->p_ARGV) = p_ibuf;
	p_ibuf += l;
}


/*
 * getwchr():	get the next wide character.
 * description:
 *	we get the next character from stdin.  This returns WEOF if no
 *	character is present.  If ZERO is set, it gets a single byte instead
 *	a wide character.
 */
static wint_t
getwchr(char *mbc, size_t *sz)
{
	size_t		i;
	int		c;
	wchar_t		wch;

	i = 0;
	while (i < MB_CUR_MAX) {

		if ((c = fgetc(stdin)) == EOF) {

			if (i == 0) {
				/* TRUE EOF has been reached */
				return (WEOF);
			}

			/*
			 * We have some characters in our buffer still so it
			 * must be an invalid character right before EOF.
			 */
			break;
		}
		mbc[i++] = (char)c;

		/* If this succeeds then we are done */
		if (ZERO) {
			*sz = i;
			return ((char)c);
		}
		if (mbtowc(&wch, mbc, i) != -1) {
			*sz = i;
			return ((wint_t)wch);
		}
	}

	/*
	 * We have now encountered an illegal character sequence.
	 * There is nothing much we can do at this point but
	 * return an error.  If we attempt to recover we may in fact
	 * return garbage as arguments, from the customer's point
	 * of view.  After all what if they are feeding us a file
	 * generated in another locale?
	 */
	errno = EILSEQ;
	PERR(CORRUPTFILE);
	exit(1);
	/* NOTREACHED */
}


static int
lcall(char *sub, char **subargs)
{
	int retcode, retry = 0;
	pid_t iwait, child;

	for (;;) {
		switch (child = fork()) {
		default:
			while ((iwait = wait(&retcode)) != child &&
			    iwait != (pid_t)-1)
				;
			if (iwait == (pid_t)-1) {
				PERR(WAITFAIL);
				exit(122);
				/* NOTREACHED */
			}
			if (WIFSIGNALED(retcode)) {
				EMSG2(CHILDSIG, WTERMSIG(retcode));
				exit(125);
				/* NOTREACHED */
			}
			if ((WEXITSTATUS(retcode) & 0377) == 0377) {
				EMSG(CHILDFAIL);
				exit(124);
				/* NOTREACHED */
			}
			return (WEXITSTATUS(retcode));
		case 0:
			(void) execvp(sub, subargs);
			PERR(EXECFAIL);
			if (errno == EACCES)
				exit(126);
			exit(127);
			/* NOTREACHED */
		case -1:
			if (errno != EAGAIN && retry++ < FORK_RETRY) {
				PERR(FORKFAIL);
				exit(123);
			}
			(void) sleep(1);
		}
	}
}


static void
usage()
{
	ermsg(_(USAGEMSG));
	OK = FALSE;
}



/*
 * parseargs():		modify the args
 *	since the -e, -i and -l flags all take optional subarguments,
 *	and getopts(3C) is clueless about this nonsense, we change the
 *	our local argument count and strings to separate this out,
 *	and make it easier to handle via getopts(3c).
 *
 *	-e	-> "-e ""
 *	-e3	-> "-e "3"
 *	-Estr	-> "-E "str"
 *	-i	-> "-i "{}"
 *	-irep	-> "-i "rep"
 *	-l	-> "-i "1"
 *	-l10	-> "-i "10"
 *
 *	since the -e, -i and -l flags all take optional subarguments,
 */
static void
parseargs(int ac, char **av)
{
	int i;			/* current argument			*/
	int cflag;		/* 0 = not processing cmd arg		*/

	if ((mav = malloc((ac * 2 + 1) * sizeof (char *))) == NULL) {
		PERR(MALLOCFAIL);
		exit(1);
	}

	/* for each argument, see if we need to change things:		*/
	for (i = mac = cflag = 0; (av[i] != NULL) && i < ac; i++, mac++) {
		if ((mav[mac] = strdup(av[i])) == NULL) {
			PERR(MALLOCFAIL);
			exit(1);
		}

		/* -- has been found or argument list is fully processes */
		if (cflag)
			continue;

		/*
		 * if we're doing special processing, and we've got a flag
		 */
		else if ((av[i][0] == '-') && (av[i][1] != NULL)) {
			char	*def;

			switch (av[i][1]) {
			case	'e':
				def = ""; /* -e with no arg turns off eof */
				goto process_special;
			case	'i':
				def = INSPAT_STR;
				goto process_special;
			case	'l':
				def = "1";
process_special:
				/*
				 * if there's no sub-option, we *must* add
				 * a default one. this is because xargs must
				 * be able to distinguish between a valid
				 * suboption, and a command name.
				 */
				if (av[i][2] == NULL) {
					mav[++mac] = strdup(def);
				} else {
					/* clear out our version: */
					mav[mac][2] = NULL;
					mav[++mac] = strdup(&av[i][2]);
				}
				if (mav[mac] == NULL) {
					PERR(MALLOCFAIL);
					exit(1);
				}
				break;

			/* flags with required subarguments:		*/

			/*
			 * there are two separate cases here. either the
			 * flag can have the normal XCU4 handling
			 * (of the form: -X subargument); or it can have
			 * the old solaris 2.[0-4] handling (of the
			 * form: -Xsubargument). in order to maintain
			 * backwards compatibility, we must support the
			 * latter case. we handle the latter possibility
			 * first so both the old solaris way of handling
			 * and the new XCU4 way of handling things are allowed.
			 */
			case	'n':	/* FALLTHROUGH			*/
			case	's':	/* FALLTHROUGH			*/
			case	'E':	/* FALLTHROUGH			*/
			case	'I':	/* FALLTHROUGH			*/
			case	'L':
				/*
				 * if the second character isn't null, then
				 * the user has specified the old syntax.
				 * we move the subargument into our
				 * mod'd argument list.
				 */
				if (av[i][2] != NULL) {
					/* first clean things up:	*/
					mav[mac][2] = NULL;

					/* now add the separation:	*/
					++mac;	/* inc to next mod'd arg */
					if ((mav[mac] = strdup(&av[i][2])) ==
					    NULL) {
						PERR(MALLOCFAIL);
						exit(1);
					}
					break;
				}
				i++;
				mac++;

				if (av[i] == NULL) {
					mav[mac] = NULL;
					return;
				}
				if ((mav[mac] = strdup(av[i])) == NULL) {
					PERR(MALLOCFAIL);
					exit(1);
				}
				break;

			/* flags */
			case 'p' :
			case 't' :
			case 'x' :
			case '0' :
				break;

			case '-' :
			default:
				/*
				 * here we've hit the cmd argument. so
				 * we'll stop special processing, as the
				 * cmd may have a "-i" etc., argument,
				 * and we don't want to add a "" to it.
				 */
				cflag = 1;
				break;
			}
		} else if (i > 0) {	/* if we're not the 1st arg	*/
			/*
			 * if it's not a flag, then it *must* be the cmd.
			 * set cflag, so we don't mishandle the -[eil] flags.
			 */
			cflag = 1;
		}
	}

	mav[mac] = NULL;
}
