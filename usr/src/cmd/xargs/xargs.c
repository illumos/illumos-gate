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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

static wctype_t	blank;
static char	*arglist[MAXARGS+1];
static char	argbuf[BUFSIZE+1];
static char	*next = argbuf;
static char	*lastarg = "";
static char	**ARGV = arglist;
static char	*LEOF = "_";
static char	*INSPAT = INSPAT_STR;
static char	ins_buf[MAXIBUF];
static char	*p_ibuf;

static struct inserts {
	char	**p_ARGV;	/* where to put newarg ptr in arg list */
	char	*p_skel;	/* ptr to arg template */
} saveargv[MAXINSERTS];

static off_t	file_offset = 0;
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
static int	linesize = 0;
static int	ibufsize = 0;
static int	exitstat = 0;	/* our exit status			*/
static int	mac;		/* modified argc, after parsing		*/
static char	**mav;		/* modified argv, after parsing		*/
static int	n_inserts;	/* # of insertions.			*/
static int	inquote = 0;	/* processing a quoted string		*/
static int	save_index = 0;

/*
 * the pio structure is used to save any pending input before the
 * user replies to a prompt. the pending input is saved here,
 * for the appropriate processing later.
 */
typedef struct pio {
	struct pio *next;	/* next in stack			*/
	char *start;		/* starting addr of the buffer		*/
	char *cur;		/* ptr to current char in buf		*/
	size_t length;		/* number of bytes remaining		*/
} pio;

static pio *queued_data = NULL;

/* our usage message:							*/
#define	USAGEMSG "Usage: xargs: [-t] [-p] [-e[eofstr]] [-E eofstr] "\
	"[-I replstr] [-i[replstr]] [-L #] [-l[#]] [-n # [-x]] [-s size] "\
	"[cmd [args ...]]\n"

static int	echoargs();
static int	getchr(void);
static wchar_t	getwchr(void);
static void	ungetwchr(wchar_t);
static int	lcall(char *sub, char **subargs);
static int	xindex(char *as1, char *as2);
static void	addibuf(struct inserts *p);
static void	ermsg(char *messages, ...);
static char	*addarg(char *arg);
static char	*checklen(char *arg);
static size_t   store_wchr(char **, size_t *, size_t, wchar_t);
static char	*getarg();
static char	*insert(char *pattern, char *subst);
static void	usage();
static void	parseargs();
static void	saveinput();

int
main(int argc, char **argv)
{
	int	j;
	struct inserts *psave;
	int c;
	int	initsize;
	char	*cmdname, *initbuf, **initlist;


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
		ermsg(gettext(ERR_MSG_INIT_YES), strerror(errno));
		exit(1);
	}

	parseargs(argc, argv);

	/* handling all of xargs arguments:				*/
	while ((c = getopt(mac, mav, "tpe:E:I:i:L:l:n:s:x")) != EOF) {
		switch (c) {
		case 't':	/* -t: turn trace mode on		*/
			TRACE = TRUE;
			break;

		case 'p':	/* -p: turn on prompt mode.		*/
			if ((PROMPT = open("/dev/tty", O_RDONLY)) == -1) {
				perror(gettext("can't read from tty for -p"));
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
				ermsg(gettext(
				    "Option requires an argument: -%c\n"), c);
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
				ermsg(gettext("#lines must be positive "
				    "int: %s\n"), optarg);
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
				ermsg(gettext("#args must be positive "
				    "int: %s\n"), optarg);
			} else {
				LEGAL = DASHX || N_ARGS == 1;
				INSERT = PER_LINE = FALSE;
			}
			break;

		case 's':	/* -s size: set max size of each arg list */
			BUFLIM = atoi(optarg);
			if (BUFLIM > BUFSIZE || BUFLIM <= 0) {
				ermsg(gettext(
				    "0 < max-cmd-line-size <= %d: "
				    "%s\n"), BUFSIZE, optarg);
			}
			break;

		case 'x':	/* -x: terminate if args > size limit	*/
			DASHX = LEGAL = TRUE;
			break;

		default:
			/*
			 * bad argument. complain and get ready to die.
			 */
			ERR = TRUE;
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
		ERR = TRUE;
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
				if (xindex(*mav, INSPAT) != -1) {
					if (++n_inserts > MAXINSERTS) {
						ermsg(gettext("too many args "
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

	initbuf = next;
	initlist = ARGV;
	initsize = linesize;

	while (OK && MORE) {
		N_args = 0;
		N_lines = 0;
		next = initbuf;
		ARGV = initlist;
		linesize = initsize;
		if (*lastarg) {
			*ARGV++ = addarg(lastarg);
			lastarg = "";
		}

		while (((*ARGV++ = getarg()) != NULL) && OK) {
			if ((ARGV - arglist) == MAXARGS) {
				save_index = ARGV - arglist;
				break;
			}
		}
		if ((save_index == MAXARGS) && !MORE && (N_args == 0)) {
			/* there were no more args after filling arglist */
			exit(exitstat);
		}

		/* insert arg if requested */

		if (!ERR && INSERT) {
			if ((!MORE) && (N_lines == 0)) {
				exit(exitstat);
			}
					/* no more input lines */
			p_ibuf = ins_buf;
			ARGV--;
			j = ibufsize = 0;
			for (psave = saveargv; ++j <= n_inserts; ++psave) {
				addibuf(psave);
				if (ERR)
					break;
			}
		}
		*ARGV = 0;

		if (n_inserts > 0) {
			int t_ninserts;

			/*
			 * if we've done any insertions, re-calculate the
			 * linesize. bomb out if we've exceeded our length.
			 */
			t_ninserts = n_inserts;
			n_inserts = 0;	/* inserts have been done 	*/
			linesize = 0;	/* recalculate this		*/

			/* for each current argument in the list:	*/
			for (ARGV = arglist; *ARGV != NULL; ARGV++) {
				/* recalculate everything.		*/
				if (checklen(*ARGV) != 0) {
					if (N_ARGS && (N_args >= N_ARGS)) {
						N_lines = N_args = 0;
						OK = FALSE;
						ERR = TRUE;
					}
				}
			}
			n_inserts = t_ninserts;
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
				if ((exitstat |= lcall(cmdname, arglist)) == 0)
					continue;
			}
		}
	}

	(void) lseek(0, file_offset, SEEK_SET);
	if (OK) {
		return (exitstat);
	} else {
		/*
		 * if exitstat was set, to match XCU4 complience,
		 * return that value, otherwise, return 1.
		 */
		return (exitstat ? exitstat : 1);
	}
}

static void
queue(char *buffer, int len, int where)
{
	pio *new, *element;

	if ((new = malloc(sizeof (pio))) == NULL) {
		perror(gettext("xargs: Memory allocation failure"));
		exit(1);
	}
	new->cur = new->start = buffer;
	new->length = len;

	if (where == TAIL) {
		new->next = NULL;
		if (queued_data == NULL) {
			queued_data = new;
		} else {
			element = queued_data;
			while (element->next != NULL) {
				element = element->next;
			}
			element->next = new;
		}
	} else {
		file_offset -= len;
		new->next = queued_data;
		queued_data = new;
	}
}

static char *
checklen(char *arg)
{
	int	oklen;

	oklen = TRUE;
	linesize += strlen(arg) + 1;
	if (linesize >= BUFLIM) {
		/*
		 * we skip this if there're inserts. we'll handle the
		 * argument counting after all the insertions have
		 * been done.
		 */
		if (n_inserts == 0) {
			lastarg = arg;
			oklen = OK = FALSE;

			if (LEGAL) {
				ERR = TRUE;
				ermsg(gettext("arg list too long\n"));
			} else if (N_args > 1) {
				N_args = 1;
			} else {
				ermsg(gettext("a single arg was greater than "
				    "the max arglist size of %d characters\n"),
				    BUFLIM);
				ERR = TRUE;
			}
		}
	}
	return (oklen ? arg : 0);
}

static char *
addarg(char *arg)
{
	if (checklen(arg) != 0) {
		(void) strcpy(next, arg);
		arg = next;
		next += strlen(arg) + 1;
		return (arg);
	}
	return ((char *)0);
}

/*
 * store_wchr() : append a wchar_t to a char buffer, resize buffer if required.
 *
 *     Given a pointer to the beginning of a string buffer, the length of the
 *     buffer and an offset indicating the next place to write within that
 *     buffer, the passed wchar_t will be appended to the buffer if there is
 *     enough space. If there is not enough space, an attempt to reallocate the
 *     buffer will be made and if successful the passed pointer and size will be
 *     updated to describe the reallocated block. Returns the new value for
 *     'offset' (it will be incremented by the number of bytes written).
 */
static size_t
store_wchr(char **buffer, size_t *buflen, size_t offset, wchar_t c)
{
	int bytes;

	/*
	 * Make sure that there is enough room in the buffer to store the
	 * maximum length of c.
	 */
	if ((offset + MB_CUR_MAX) > *buflen) {
		/*
		 * Not enough room so attempt to reallocate. Add 'MB_CUR_MAX' to
		 * buffer length to ensure that there is always enough room to
		 * store 'c' if realloc succeeds, no matter what QBUF_INC is
		 * defined as.
		 */
		*buflen += (QBUF_INC + MB_CUR_MAX);
		if ((*buffer = realloc(*buffer, *buflen)) == NULL) {
			perror(gettext("xargs: Memory allocation failure"));
			exit(1);
		}
	}
	/* store bytes from wchar into buffer */
	bytes = wctomb(*buffer + offset, c);
	if (bytes == -1) {
		/* char was invalid */
		bytes = 1;
		*(*buffer + offset) = (char)c;
	}

	/* return new value for offset */
	return (offset + bytes);
}

static char *
getarg()
{
	int	bytes;
	wchar_t	c;
	char	*arg;
	char	*retarg, *requeue_buf;
	size_t  requeue_offset = 0, requeue_len;
	char	mbc[MB_LEN_MAX];

	while (iswspace(c = getwchr()) || c == '\n')
		;

	if (c == '\0') {
		MORE = FALSE;
		return (0);
	}

	/*
	 * While we are reading in an argument, it is possible that we will
	 * reach the maximum length of the overflow buffer and we'll have to
	 * requeue what we have read so far. To handle this we allocate an
	 * initial buffer here which will keep an unprocessed copy of the data
	 * that we read in (this buffer will grow as required).
	 */
	requeue_len = (size_t)QBUF_STARTLEN;
	if ((requeue_buf = (char *)malloc(requeue_len)) == NULL) {
		perror(gettext("xargs: Memory allocation failure"));
		exit(1);
	}

	for (arg = next; ; c = getwchr()) {
		bytes = wctomb(mbc, c);

		/*
		 * Store the char that we have read before processing it in case
		 * the current argument needs to be requeued.
		 */
		requeue_offset = store_wchr(&requeue_buf, &requeue_len,
		    requeue_offset, c);

		/* Check for overflow the input buffer */
		if ((next + ((bytes == -1) ? 1 : bytes)) >= &argbuf[BUFLIM]) {
			/*
			 * It's only an error if there are no Args in buffer
			 * already.
			 */
			if ((N_ARGS || PER_LINE) && LEGAL) {
				ERR = TRUE;
				ermsg(gettext("Argument list too long\n"));
				free(requeue_buf);
				return (0);
			} else if (N_args == 0) {
				lastarg = "";
				ERR = TRUE;
				ermsg(gettext("A single arg was greater than "
				    "the max arglist size of %d characters\n"),
				    BUFSIZE);
				free(requeue_buf);
				return (0);
			}
			/*
			 * Otherwise we put back the current argument
			 * and use what we have collected so far...
			 */
			queue(requeue_buf, requeue_offset, HEAD);
			/* reset inquote because we have requeued the quotes */
			inquote = 0;
			return (NULL);
		}


		if (iswctype(c, blank) && inquote == 0) {
			if (INSERT) {
				if (bytes == -1) {
					*next++ = (char)c;
				} else {
					(void) wctomb(next, c);
					next += bytes;
				}
				continue;
			}

			/* skip over trailing whitespace till next arg */
			while (iswctype((c = getwchr()), blank) &&
			    (c != '\n') && (c != '\0'))
				;

			/*
			 * if there was space till end of line then the last
			 * character was really a newline...
			 */
			if (c == L'\n' || c == L'\0') {
				ungetwchr(L'\n');
			} else {
				/* later code needs to know this was a space */
				ungetwchr(c);
				c = L' ';
			}
			goto end_arg;
		}
		switch (c) {
		case L'\0':
		case L'\n':
			if (inquote) {
				*next++ = '\0';
				ermsg(gettext("Missing quote: %s\n"), arg);
				ERR = TRUE;
				free(requeue_buf);
				return (0);
			}

			N_lines++;
end_arg:		*next++ = '\0';
			/* we finished without requeuing so free requeue_buf */
			free(requeue_buf);
			if ((strcmp(arg, LEOF) == 0 && *LEOF != '\0') ||
			    (c == '\0' && strlen(arg) == 0)) {
				MORE = FALSE;
				/* absorb the rest of the line */
				if ((c != '\n') && (c != '\0'))
					while (c = getwchr())
						if ((c == '\n') || (c == '\0'))
							break;
				if (strcmp(arg, LEOF) == 0 && *LEOF != '\0') {
					/*
					 * Encountered EOF string.
					 * Don't read any more lines.
					 */
					N_lines = 0;
				}
				return (0);
			} else {
				++N_args;
				if (retarg = checklen(arg)) {
					if ((PER_LINE &&
					    N_lines >= PER_LINE &&
					    (c == '\0' || c == '\n')) ||
					    (N_ARGS && N_args >= N_ARGS)) {
						N_lines = N_args = 0;
						lastarg = "";
						OK = FALSE;
					}
				}
				return (retarg);
			}

		case '"':
			if (inquote == 1)	/* in single quoted string */
				goto is_default;
			if (inquote == 2)	/* terminating double quote */
				inquote = 0;
			else			/* starting quoted string */
				inquote = 2;
			break;

		case '\'':
			if (inquote == 2)	/* in double quoted string */
				goto is_default;
			if (inquote == 1)	/* terminating single quote */
				inquote = 0;
			else			/* starting quoted string */
				inquote = 1;
			break;

		case L'\\':
			/*
			 * Any unquoted character can be escaped by
			 * preceding it with a backslash.
			 */
			if (inquote == 0) {
				c = getwchr();
				/* store quoted char for potential requeueing */
				requeue_offset = store_wchr(&requeue_buf,
				    &requeue_len, requeue_offset, c);
			}

		default:
is_default:		if (bytes == -1) {
				*next++ = (char)c;
			} else {
				(void) wctomb(next, c);
				next += bytes;
			}
			break;
		}
	}
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

	/*
	 * at this point, there may be unexpected input pending on stdin,
	 * if one has used the -n flag. this presents a problem, because
	 * if we simply do a read(), we'll get the extra input, instead
	 * of our desired y/n input. so, we see if there's any extra
	 * input, and if there is, then we will store it.
	 */
	saveinput();

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
		if (xindex(pat, INSPAT) == 0) {
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
		return (0);
	}
}


static void
addibuf(struct inserts	*p)
{
	char	*newarg, *skel, *sub;
	int		l;

	skel = p->p_skel;
	sub = *ARGV;
	linesize -= strlen(skel) + 1;
	newarg = insert(skel, sub);
	if (ERR)
		return;

	if (checklen(newarg)) {
		if ((ibufsize += (l = strlen(newarg) + 1)) > MAXIBUF) {
			ermsg(gettext("Insert buffer overflow\n"));
			ERR = TRUE;
		}
		(void) strcpy(p_ibuf, newarg);
		*(p->p_ARGV) = p_ibuf;
		p_ibuf += l;
	}
}


/*
 * getchr():	get the next character.
 * description:
 *	we get the next character from pio.structure, if there's a character
 *	to get. this may happen when we've had to flush stdin=/dev/tty,
 *	but still wanted to preserve the characters for later processing.
 *
 *	otherwise we just get the character from stdin.
 */
static int
getchr(void)
{
	char	c;

	do {
		if (queued_data == NULL) {
			char	*buffer;
			int	len;

			if ((buffer = malloc(BUFSIZE)) == NULL) {
				perror(gettext(
				    "xargs: Memory allocation failure"));
				exit(1);
			}

			if ((len = read(0, buffer, BUFSIZE)) == 0)
				return (0);
			if (len == -1) {
				perror(gettext("xargs: Read failure"));
				exit(1);
			}

			queue(buffer, len, TAIL);
		}

		file_offset++;
		c = *queued_data->cur++;	 /* get the next character */
		if (--queued_data->length == 0) { /* at the end of buffer? */
			pio	*nxt = queued_data->next;

			free(queued_data->start);
			free(queued_data);
			queued_data = nxt;
		}
	} while (c == '\0');
	return (c);
}


static wchar_t
getwchr(void)
{
	int		i;
	wchar_t		wch;
	unsigned char	buffer[MB_LEN_MAX + 1];

	for (i = 0; i < (int)MB_CUR_MAX; ) {
		if ((buffer[i++] = getchr()) == NULL) {
			/* We have reached  EOF */
			if (i == 1) {
				/* TRUE EOF has been reached */
				return (NULL);
			}
			/*
			 * We have some characters in our buffer still so it
			 * must be an invalid character right before EOF.
			 */
			break;
		}

		/* If this succeeds then we are done */
		if (mbtowc(&wch, (char *)buffer, i) != -1)
			return (wch);
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
	perror(gettext("xargs: Corrupt input file"));
	exit(1);
	/* NOTREACHED */
}


static void
ungetwchr(wchar_t wch)
{
	char	*buffer;
	int	bytes;

	if ((buffer = malloc(MB_LEN_MAX)) == NULL) {
		perror(gettext("xargs: Memory allocation failure"));
		exit(1);
	}
	bytes = wctomb(buffer, wch);
	queue(buffer, bytes, HEAD);
}


static int
lcall(char *sub, char **subargs)
{
	int retcode, retry = 0;
	pid_t iwait, child;

	for (; ; ) {
		switch (child = fork()) {
		default:
			while ((iwait = wait(&retcode)) != child &&
			    iwait != (pid_t)-1)
				;
			if (iwait == (pid_t)-1) {
				perror(gettext("xargs: Wait failure"));
				exit(122);
				/* NOTREACHED */
			}
			if (WIFSIGNALED(retcode)) {
				ermsg(gettext("Child killed with signal %d\n"),
				    WTERMSIG(retcode));
				exit(125);
				/* NOTREACHED */
			}
			if ((WEXITSTATUS(retcode) & 0377) == 0377) {
				ermsg(gettext("Command could not continue "
				    "processing data\n"));
				exit(124);
				/* NOTREACHED */
			}
			return (WEXITSTATUS(retcode));
		case 0:
			(void) execvp(sub, subargs);
			perror(gettext("xargs: Could not exec command"));
			if (errno == EACCES)
				exit(126);
			exit(127);
			/* NOTREACHED */
		case -1:
			if (errno != EAGAIN && retry++ < FORK_RETRY) {
				perror(gettext("xargs: Could not fork child"));
				exit(123);
			}
			(void) sleep(1);
		}
	}
}


/*
 * If `s2' is a substring of `s1' return the offset of the first
 * occurrence of `s2' in `s1', else return -1.
 */
static int
xindex(char *as1, char *as2)
{
	char	*s1, *s2, c;
	int		offset;

	s1 = as1;
	s2 = as2;
	c = *s2;

	while (*s1) {
		if (*s1++ == c) {
			offset = s1 - as1 - 1;
			s2++;
			while ((c = *s2++) == *s1++ && c)
				;
			if (c == 0)
				return (offset);
			s1 = offset + as1 + 1;
			s2 = as2;
			c = *s2;
		}
	}
	return (-1);
}


static void
usage()
{
	ermsg(gettext(USAGEMSG));
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
		perror(gettext("xargs: Memory allocation failure"));
		exit(1);
	}

	/* for each argument, see if we need to change things:		*/
	for (i = mac = cflag = 0; (av[i] != NULL) && i < ac; i++, mac++) {
		if ((mav[mac] = strdup(av[i])) == NULL) {
			perror(gettext("xargs: Memory allocation failure"));
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
					perror(gettext("xargs: Memory"
					    " allocation failure"));
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
						perror(gettext("xargs: Memory"
						    " allocation failure"));
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
					perror(gettext("xargs: Memory"
					    " allocation failure"));
					exit(1);
				}
				break;

			/* flags */
			case 'p' :
			case 't' :
			case 'x' :
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


/*
 * saveinput(): pick up any pending input, so it can be processed later.
 *
 * description:
 *	the purpose of this routine is to allow us to handle the user
 *	typing in a 'y' or 'n', when there's existing characters already
 *	in stdin. this happens when one gives the "-n" option along with
 *	"-p". the problem occurs when the user first types in more arguments
 *	than specified by the -n number. echoargs() wants to read stdin
 *	in order to get the user's response, but if there's already stuff
 *	there, echoargs() won't read the proper character.
 *
 *	the solution provided by this routine is to pick up all characters
 *	(if any), and store them for later processing.
 */

void
saveinput()
{
	char *buffer;		/* ptr to the floating data buffer	*/
	struct strpeek speek;	/* to see what's on the queue		*/
	struct strpeek *ps;

	/* if we're not in -p mode, skip				*/
	if (PROMPT == -1) {
		return;
	}


	/* now see if there's any activity pending:			*/
	ps = &speek;
	ps->ctlbuf.maxlen = 0;
	ps->ctlbuf.len = 0;
	ps->ctlbuf.buf = NULL;
	ps->flags = 0;
	ps->databuf.maxlen = MAX_INPUT;
	ps->databuf.len = 0;
	if ((buffer = malloc((size_t)MAX_INPUT)) == NULL) {
		perror(gettext("xargs: Memory allocation failure"));
		exit(1);
	}
	ps->databuf.buf = (char *)buffer;

	if (ioctl(PROMPT, I_PEEK, ps) == -1) {
		perror(gettext("xargs: I_PEEK failure"));
		exit(1);
	}

	if (ps->databuf.len > 0) {
		int	len;

		if ((len = read(PROMPT, buffer, ps->databuf.len)) == -1) {
			perror(gettext("xargs: read failure"));
			exit(1);
		}
		queue(buffer, len, TAIL);
	}
}
