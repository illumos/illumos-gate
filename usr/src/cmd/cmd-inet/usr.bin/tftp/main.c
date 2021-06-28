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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * TFTP User Program -- Command Interface.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>

#include <arpa/inet.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <ctype.h>
#include <netdb.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <libtecla.h>

#include "tftpcommon.h"
#include "tftpprivate.h"

#define	TIMEOUT		5		/* secs between rexmt's */

struct sockaddr_in6	sin6;
int			f;
int			maxtimeout = 5 * TIMEOUT;
int			verbose;
int			trace;
int			srexmtval;
int			blksize;
int			rexmtval = TIMEOUT;
int			tsize_opt;
jmp_buf			toplevel;

static int			default_port, port;
static int			connected;
static char			mode[32];
static char			line[200];
static char			*prompt = "tftp> ";
static char			hostname[MAXHOSTNAMELEN];
static GetLine			*gl;

static void		intr(int);
static void		quit(int, char **);
static void		help(int, char **);
static void		setverbose(int, char **);
static void		settrace(int, char **);
static void		status(int, char **);
static void		get(int, char **);
static void		put(int, char **);
static void		setpeer(int, char **);
static void		modecmd(int, char **);
static void		setrexmt(int, char **);
static void		settimeout(int, char **);
static void		setbinary(int, char **);
static void		setascii(int, char **);
static void		setblksize(int, char **);
static void		setsrexmt(int, char **);
static void		settsize(int, char **);
static void		setmode(char *);
static void		putusage(char *);
static void		getusage(char *);
static char		*finddelimiter(char *);
static char		*removebrackets(char *);
static int		prompt_for_arg(char *, int, char *);
static struct cmd	*getcmd(char *);
static char		*tail(char *);
static void		command(int);
static void		makeargv(char *, int *, char ***);

#define	HELPINDENT (sizeof ("connect"))

struct cmd {
	char	*name;
	char	*help;
	void	(*handler)(int, char **);
};

static char	vhelp[] =	"toggle verbose mode";
static char	thelp[] =	"toggle packet tracing";
static char	chelp[] =	"connect to remote tftp";
static char	qhelp[] =	"exit tftp";
static char	hhelp[] =	"print help information";
static char	shelp[] =	"send file";
static char	rhelp[] =	"receive file";
static char	mhelp[] =	"set file transfer mode";
static char	sthelp[] =	"show current status";
static char	xhelp[] =	"set per-packet retransmission timeout";
static char	ihelp[] =	"set total retransmission timeout";
static char	ashelp[] =	"set mode to netascii";
static char	bnhelp[] =	"set mode to octet";
static char	bshelp[] =	"set transfer blocksize to negotiate with the "
				"server";
static char	srhelp[] =	"set preferred per-packet retransmission "
				"timeout for server";
static char	tshelp[] =	"toggle sending the transfer size option to "
				"the server";

static struct cmd	cmdtab[] = {
	{ "connect",	chelp,		setpeer },
	{ "mode",	mhelp,		modecmd },
	{ "put",	shelp,		put },
	{ "get",	rhelp,		get },
	{ "quit",	qhelp,		quit },
	{ "verbose",	vhelp,		setverbose },
	{ "trace",	thelp,		settrace },
	{ "status",	sthelp,		status },
	{ "binary",	bnhelp,		setbinary },
	{ "ascii",	ashelp,		setascii },
	{ "rexmt",	xhelp,		setrexmt },
	{ "timeout",	ihelp,		settimeout },
	{ "blksize",	bshelp,		setblksize },
	{ "srexmt",	srhelp,		setsrexmt },
	{ "tsize",	tshelp,		settsize },
	{ "help",	hhelp,		help },
	{ "?",		hhelp,		help },
	{ NULL }
};

#define	AMBIGCMD	(&cmdtab[ARRAY_SIZE(cmdtab)])

static struct modes {
	char *m_name;
	char *m_mode;
} modes[] = {
	{ "ascii",	"netascii" },
	{ "netascii",	"netascii" },
	{ "binary",	"octet" },
	{ "image",	"octet" },
	{ "octet",	"octet" },
/*      { "mail",       "mail" },       */
	{ NULL,		NULL }
};

static int
cmdmatch(WordCompletion *cpl, void *data, const char *line, int word_end)
{
	struct cmd *cmds = data;
	const char *word;
	int i, rc = 0;

	for (word = line + word_end; word > line && *(word - 1) != ' '; word--)
		;

	/* This word is command */
	if (word == line) {
		for (i = 0; cmds[i].name != NULL; i++) {
			const char *cmd = strstr(cmds[i].name, word);

			if (cmd == cmds[i].name) {
				rc = cpl_add_completion(cpl, line, 0,
				    word_end, cmds[i].name + strlen(word),
				    NULL, NULL);
			}
		}
	} else {
		/* We only complete arguments for mode command */
		if (strncmp(line, "mode", 4) == 0) {
			for (i = 0; modes[i].m_name != NULL; i++) {
				const char *mode;

				mode = strstr(modes[i].m_name, word);
				if (mode == modes[i].m_name) {
					rc = cpl_add_completion(cpl, line, 0,
					    word_end,
					    modes[i].m_name + strlen(word),
					    NULL, NULL);
				}
			}
		}
	}

	return (rc);
}

#define	LINELEN		1024
#define	HISTORY		2048

int
main(int argc, char **argv)
{
	struct servent *sp;
	struct sockaddr_in6 sin6;
	int top;

	sp = getservbyname("tftp", "udp");
	default_port = (sp != NULL) ? sp->s_port : htons(IPPORT_TFTP);
	port = default_port;

	f = socket(AF_INET6, SOCK_DGRAM, 0);
	if (f < 0) {
		perror("tftp: socket");
		exit(3);
	}

	(void) memset(&sin6, 0, sizeof (sin6));
	sin6.sin6_family = AF_INET6;
	if (bind(f, (struct sockaddr *)&sin6, sizeof (sin6)) < 0) {
		perror("tftp: bind");
		exit(1);
	}

	(void) strlcpy(mode, "netascii", sizeof (mode));

	gl = new_GetLine(LINELEN, HISTORY);
	if (gl == NULL) {
		perror("tftp: cli setup");
		exit(1);
	}

	/* SIGALRM is used by tftp */
	if (gl_ignore_signal(gl, SIGALRM) == 0) {
		if (gl_customize_completion(gl, cmdtab, cmdmatch) != 0)
			perror("gl_customize_completion");
	} else {
		perror("gl_ignore_signal");
	}

	(void) signal(SIGINT, intr);
	if (argc > 1) {
		if (setjmp(toplevel) != 0)
			exit(0);
		setpeer(argc, argv);
	}

	top = (setjmp(toplevel) == 0);
	for (;;)
		command(top);

	/*NOTREACHED*/
	return (0);
}

/* Prompt for command argument, add to buffer with space separator */
static int
prompt_for_arg(char *buffer, int buffer_size, char *prompt)
{
	char *buf;
	char *p;

	if (strlcat(buffer, " ", buffer_size) >= buffer_size) {
		(void) fputs("?Line too long\n", stderr);
		return (-1);
	}

	if (asprintf(&p, "(%s) ", prompt) < 0)
		perror("prompt_for_arg");
	buf = gl_get_line(gl, p, NULL, -1);
	free(p);
	if (buf == NULL)
		return (-1);

	if (strlcat(buffer, buf, buffer_size) >= buffer_size) {
		(void) fputs("?Line too long\n", stderr);
		return (-1);
	}
	return (0);
}

static void
unknown_host(int error, char *hostname)
{
	if (error == TRY_AGAIN)
		(void) fprintf(stderr, "%s: Unknown host (try again later).\n",
		    hostname);
	else
		(void) fprintf(stderr, "%s: Unknown host.\n", hostname);
}

static void
setpeer(int argc, char **argv)
{
	struct hostent *host;
	int error_num;
	struct in6_addr ipv6addr;
	struct in_addr ipv4addr;
	char *hostnameinput;
	const char *errstr;

	if (argc < 2) {
		if (strlcat(line, argv[0], sizeof (line)) >= sizeof (line)) {
			(void) fprintf(stderr, "%s is too big\n", argv[0]);
			return;
		}
		if (prompt_for_arg(line, sizeof (line), "to") == -1)
			return;
		makeargv(line, &argc, &argv);
	}
	if (argc > 3 || argc < 2) {
		(void) fprintf(stderr, "usage: %s host-name [port]\n",
		    argv[0]);
		return;
	}
	hostnameinput = removebrackets(argv[1]);

	(void) memset(&sin6, 0, sizeof (sin6));
	sin6.sin6_family = AF_INET6;
	host = getipnodebyname(hostnameinput, AF_INET6,
	    AI_ALL | AI_ADDRCONFIG | AI_V4MAPPED, &error_num);
	if (host != NULL) {
		(void) memcpy(&sin6.sin6_addr, host->h_addr_list[0],
		    host->h_length);
		/*
		 * If host->h_name is a IPv4-mapped IPv6 literal, we'll convert
		 * it to IPv4 literal address.
		 */
		if ((inet_pton(AF_INET6, host->h_name, &ipv6addr) > 0) &&
		    IN6_IS_ADDR_V4MAPPED(&ipv6addr)) {
			IN6_V4MAPPED_TO_INADDR(&ipv6addr, &ipv4addr);
			(void) inet_ntop(AF_INET, &ipv4addr, hostname,
			    sizeof (hostname));
		} else {
			(void) strlcpy(hostname, host->h_name,
			    sizeof (hostname));
		}
		freehostent(host);
	} else {
		/* Keeping with previous semantics */
		connected = 0;
		unknown_host(error_num, hostnameinput);
		return;
	}

	port = default_port;
	if (argc == 3) {
		port = strtonum(argv[2], 1, 65535, &errstr);
		if (errstr != NULL) {
			(void) fprintf(stderr, "%s: bad port number: %s\n",
			    argv[2], errstr);
			connected = 0;
			return;
		}
		port = htons(port);
	}
	connected = 1;
}

static void
modecmd(int argc, char **argv)
{
	struct modes *p;

	if (argc < 2) {
		(void) fprintf(stderr, "Using %s mode to transfer files.\n",
		    mode);
		return;
	}
	if (argc == 2) {
		for (p = modes; p->m_name != NULL; p++)
			if (strcmp(argv[1], p->m_name) == 0) {
				setmode(p->m_mode);
				return;
			}
		(void) fprintf(stderr, "%s: unknown mode\n", argv[1]);
		/* drop through and print usage message */
	}

	p = modes;
	(void) fprintf(stderr, "usage: %s [ %s", argv[0], p->m_name);
	for (p++; p->m_name != NULL; p++)
		(void) fprintf(stderr, " | %s", p->m_name);
	(void) puts(" ]");
}

/*ARGSUSED*/
static void
setbinary(int argc, char **argv)
{
	setmode("octet");
}

/*ARGSUSED*/
static void
setascii(int argc, char **argv)
{
	setmode("netascii");
}

static void
setmode(char *newmode)
{
	(void) strlcpy(mode, newmode, sizeof (mode));
	if (verbose)
		(void) printf("mode set to %s\n", mode);
}

/*
 * Send file(s).
 */
static void
put(int argc, char **argv)
{
	int fd;
	int n;
	char *cp, *targ;
	struct in6_addr	ipv6addr;
	struct in_addr ipv4addr;
	char buf[PATH_MAX + 1], *argtail;

	if (argc < 2) {
		if (strlcat(line, argv[0], sizeof (line)) >= sizeof (line)) {
			(void) fprintf(stderr, "%s is too big\n", argv[0]);
			return;
		}
		if (prompt_for_arg(line, sizeof (line), "file") == -1)
			return;
		makeargv(line, &argc, &argv);
	}
	if (argc < 2) {
		putusage(argv[0]);
		return;
	}
	targ = argv[argc - 1];
	if (finddelimiter(argv[argc - 1])) {
		char *cp;
		struct hostent *hp;
		int error_num;

		for (n = 1; n < argc - 1; n++)
			if (finddelimiter(argv[n])) {
				putusage(argv[0]);
				return;
			}
		cp = argv[argc - 1];
		targ = finddelimiter(cp);
		*targ++ = 0;
		cp = removebrackets(cp);

		if ((hp = getipnodebyname(cp,
		    AF_INET6, AI_ALL | AI_ADDRCONFIG | AI_V4MAPPED,
		    &error_num)) == NULL) {
			unknown_host(error_num, cp);
			return;
		}
		(void) memcpy(&sin6.sin6_addr, hp->h_addr_list[0],
		    hp->h_length);

		sin6.sin6_family = AF_INET6;
		connected = 1;
		/*
		 * If hp->h_name is a IPv4-mapped IPv6 literal, we'll convert
		 * it to IPv4 literal address.
		 */
		if ((inet_pton(AF_INET6, hp->h_name, &ipv6addr) > 0) &&
		    IN6_IS_ADDR_V4MAPPED(&ipv6addr)) {
			IN6_V4MAPPED_TO_INADDR(&ipv6addr, &ipv4addr);
			(void) inet_ntop(AF_INET, &ipv4addr, hostname,
			    sizeof (hostname));
		} else {
			(void) strlcpy(hostname, hp->h_name,
			    sizeof (hostname));
		}
	}
	if (!connected) {
		(void) fputs("No target machine specified.\n", stderr);
		return;
	}
	if (argc < 4) {
		cp = argc == 2 ? tail(targ) : argv[1];
		fd = open(cp, O_RDONLY);
		if (fd < 0) {
			(void) fprintf(stderr, "tftp: %s: %s\n", cp,
			    strerror(errno));
			return;
		}
		if (verbose)
			(void) printf("putting %s to %s:%s [%s]\n",
			    cp, hostname, targ, mode);
		sin6.sin6_port = port;
		tftp_sendfile(fd, targ, mode);
		return;
	}
	/* this assumes the target is a directory */
	/* on a remote unix system.  hmmmm.  */
	if (strlen(targ) + 1 >= sizeof (buf)) {
		(void) fprintf(stderr, "tftp: filename too long: %s\n", targ);
		return;
	}
	for (n = 1; n < argc - 1; n++) {
		argtail = tail(argv[n]);
		if (snprintf(buf, sizeof (buf), "%s/%s", targ, argtail) >=
		    sizeof (buf)) {
			(void) fprintf(stderr,
			    "tftp: filename too long: %s/%s\n", targ, argtail);
			continue;
		}
		fd = open(argv[n], O_RDONLY);
		if (fd < 0) {
			(void) fprintf(stderr, "tftp: %s: %s\n", argv[n],
			    strerror(errno));
			continue;
		}
		if (verbose)
			(void) printf("putting %s to %s:%s [%s]\n",
			    argv[n], hostname, buf, mode);
		sin6.sin6_port = port;
		tftp_sendfile(fd, buf, mode);
	}
}

static void
putusage(char *s)
{
	(void) fprintf(stderr, "usage: %s file ... host:target, or\n"
	    "       %s file ... target (when already connected)\n", s, s);
}

/*
 * Receive file(s).
 */
static void
get(int argc, char **argv)
{
	int fd;
	int n;
	char *cp;
	char *src;
	struct in6_addr ipv6addr;
	struct in_addr ipv4addr;
	int error_num;

	if (argc < 2) {
		if (strlcat(line, argv[0], sizeof (line)) >= sizeof (line)) {
			(void) fprintf(stderr, "%s is too big\n", argv[0]);
			return;
		}
		if (prompt_for_arg(line, sizeof (line), "files") == -1)
			return;
		makeargv(line, &argc, &argv);
	}
	if (argc < 2) {
		getusage(argv[0]);
		return;
	}
	if (!connected) {
		for (n = 1; n < argc; n++)
			if (finddelimiter(argv[n]) == 0) {
				getusage(argv[0]);
				return;
			}
	}
	for (n = 1; n < argc; n++) {
		src = finddelimiter(argv[n]);
		if (src == NULL)
			src = argv[n];
		else {
			struct hostent *hp;
			char *hostnameinput;

			*src++ = 0;
			hostnameinput = removebrackets(argv[n]);

			if ((hp = getipnodebyname(hostnameinput, AF_INET6,
			    AI_ALL | AI_ADDRCONFIG | AI_V4MAPPED,
			    &error_num)) == NULL) {
				unknown_host(error_num, hostnameinput);
				continue;
			}
			(void) memcpy((caddr_t)&sin6.sin6_addr,
			    hp->h_addr_list[0], hp->h_length);

			sin6.sin6_family = AF_INET6;
			connected = 1;
			/*
			 * If hp->h_name is a IPv4-mapped IPv6 literal, we'll
			 * convert it to IPv4 literal address.
			 */
			if ((inet_pton(AF_INET6, hp->h_name, &ipv6addr) > 0) &&
			    IN6_IS_ADDR_V4MAPPED(&ipv6addr)) {
				IN6_V4MAPPED_TO_INADDR(&ipv6addr, &ipv4addr);
				(void) inet_ntop(AF_INET, &ipv4addr, hostname,
				    sizeof (hostname));
			} else {
				(void) strlcpy(hostname, hp->h_name,
				    sizeof (hostname));
			}
		}
		if (argc < 4) {
			cp = argc == 3 ? argv[2] : tail(src);
			fd = creat(cp, 0644);
			if (fd < 0) {
				(void) fprintf(stderr, "tftp: %s: %s\n", cp,
				    strerror(errno));
				return;
			}
			if (verbose)
				(void) printf("getting from %s:%s to %s [%s]\n",
				    hostname, src, cp, mode);
			sin6.sin6_port = port;
			tftp_recvfile(fd, src, mode);
			break;
		}
		cp = tail(src);	/* new .. jdg */
		fd = creat(cp, 0644);
		if (fd < 0) {
			(void) fprintf(stderr, "tftp: %s: %s\n", cp,
			    strerror(errno));
			continue;
		}
		if (verbose)
			(void) printf("getting from %s:%s to %s [%s]\n",
			    hostname, src, cp, mode);
		sin6.sin6_port = port;
		tftp_recvfile(fd, src, mode);
	}
}

static void
getusage(char *s)
{
	(void) fprintf(stderr, "usage: %s host:file host:file ... file, or\n"
	    "       %s file file ... file if connected\n", s, s);
}

static void
setrexmt(int argc, char **argv)
{
	int t;
	const char *errstr;

	if (argc < 2) {
		if (strlcat(line, argv[0], sizeof (line)) >= sizeof (line)) {
			(void) fprintf(stderr, "%s is too big\n", argv[0]);
			return;
		}
		if (prompt_for_arg(line, sizeof (line), "value") == -1)
			return;
		makeargv(line, &argc, &argv);
	}
	if (argc != 2) {
		(void) fprintf(stderr, "usage: %s value\n", argv[0]);
		return;
	}

	t = strtonum(argv[1], 0, INT_MAX, &errstr);
	if (errstr != NULL)
		(void) fprintf(stderr, "%s: bad value: %s\n", argv[1], errstr);
	else
		rexmtval = t;
}

static void
settimeout(int argc, char **argv)
{
	int t;
	const char *errstr;

	if (argc < 2) {
		if (strlcat(line, argv[0], sizeof (line)) >= sizeof (line)) {
			(void) fprintf(stderr, "%s is too big\n", argv[0]);
			return;
		}
		if (prompt_for_arg(line, sizeof (line), "value") == -1)
			return;
		makeargv(line, &argc, &argv);
	}
	if (argc != 2) {
		(void) fprintf(stderr, "usage: %s value\n", argv[0]);
		return;
	}
	t = strtonum(argv[1], 0, INT_MAX, &errstr);
	if (errstr != NULL)
		(void) fprintf(stderr, "%s: bad value: %s\n", argv[1], errstr);
	else
		maxtimeout = t;
}

/*ARGSUSED*/
static void
status(int argc, char **argv)
{
	if (connected)
		(void) printf("Connected to %s.\n", hostname);
	else
		(void) puts("Not connected.");
	(void) printf("Mode: %s Verbose: %s Tracing: %s\n", mode,
	    verbose ? "on" : "off", trace ? "on" : "off");
	(void) printf("Rexmt-interval: %d seconds, Max-timeout: %d seconds\n",
	    rexmtval, maxtimeout);
	(void) printf("Transfer blocksize option: ");
	if (blksize == 0)
		(void) puts("off");
	else
		(void) printf("%d bytes\n", blksize);
	(void) printf("Server rexmt-interval option: ");
	if (srexmtval == 0)
		(void) puts("off");
	else
		(void) printf("%d seconds\n", srexmtval);
	(void) printf("Transfer size option: %s\n", tsize_opt ? "on" : "off");
}

/*ARGSUSED*/
static void
intr(int signum)
{
	(void) cancel_alarm();
	longjmp(toplevel, -1);
}

static char *
tail(char *filename)
{
	char *s;

	while (*filename != '\0') {
		s = strrchr(filename, '/');
		if (s == NULL)
			break;
		if (s[1] != '\0')
			return (&s[1]);
		*s = '\0';
	}
	return (filename);
}

/*
 * Command parser.
 */
static void
command(int top)
{
	struct cmd *c;
	char *buf, **argv;
	int argc;

	if (!top)
		(void) putchar('\n');
	for (;;) {
		buf = gl_get_line(gl, prompt, NULL, -1);
		if (buf == NULL) {
			quit(0, NULL);
		}

		makeargv(buf, &argc, &argv);
		c = getcmd(argv[0]);
		if (c == AMBIGCMD)
			(void) fputs("?Ambiguous command\n", stderr);
		else if (c == NULL)
			(void) fputs("?Invalid command\n", stderr);
		else
			(*c->handler)(argc, argv);
	}
}

static struct cmd *
getcmd(char *name)
{
	char *p, *q;
	struct cmd *c, *found;

	if (name == NULL)
		return (NULL);

	found = NULL;
	for (c = cmdtab; (p = c->name) != NULL; c++) {
		for (q = name; *q == *p++; q++)
			if (*q == '\0')		/* exact match? */
				return (c);
		if (*q == '\0')		/* the name was a prefix */
			found = (found == NULL) ? c : AMBIGCMD;
	}
	return (found);
}

/*
 * Given a string, this function returns the pointer to the delimiting ':'.
 * The string can contain an IPv6 literal address, which should be inside a
 * pair of brackets, e.g. [1::2]. Any colons inside a pair of brackets are not
 * accepted as delimiters. Returns NULL if delimiting ':' is not found.
 */
static char *
finddelimiter(char *str)
{
	bool is_bracket_open = false;
	char *cp;

	for (cp = str; *cp != '\0'; cp++) {
		if (*cp == '[')
			is_bracket_open = true;
		else if (*cp == ']')
			is_bracket_open = false;
		else if (*cp == ':' && !is_bracket_open)
			return (cp);
	}
	return (NULL);
}

/*
 * Given a string which is possibly surrounded by brackets, e.g. [1::2], this
 * function returns a string after removing those brackets. If the brackets
 * don't match, it does nothing.
 */
static char *
removebrackets(char *str)
{
	char *newstr = str;

	if ((str[0] == '[') && (str[strlen(str) - 1] == ']')) {
		newstr = str + 1;
		str[strlen(str) - 1] = '\0';
	}
	return (newstr);
}

#define	MARGV_INC	20

/*
 * Slice a string up into argc/argv.
 */
static void
makeargv(char *buf, int *argcp, char ***argvp)
{
	char *cp;
	char **argp;
	int argc;
	static char **argv;
	static int argv_size;

	if (argv == NULL) {
		argv_size = MARGV_INC;
		if ((argv = malloc(argv_size * sizeof (char *))) == NULL) {
			perror("tftp: malloc");
			exit(1);
		}
	}
	argc = 0;
	argp = argv;
	for (cp = buf; *cp != '\0'; ) {
		while (isspace(*cp))
			cp++;
		if (*cp == '\0')
			break;
		*argp++ = cp;
		argc++;
		if (argc == argv_size) {
			argv_size += MARGV_INC;
			if ((argv = realloc(argv,
			    argv_size * sizeof (char *))) == NULL) {
				perror("tftp: realloc");
				exit(1);
			}
			argp = argv + argc;
		}
		while (*cp != '\0' && !isspace(*cp))
			cp++;
		if (*cp == '\0')
			break;
		*cp++ = '\0';
	}
	*argp = NULL;

	*argcp = argc;
	*argvp = argv;
}

/*ARGSUSED*/
static void
quit(int argc, char **argv)
{
	exit(0);
}

/*
 * Help command.
 */
static void
help(int argc, char **argv)
{
	struct cmd *c;

	if (argc == 1) {
		(void) puts("Commands may be abbreviated.  Commands are:\n");
		for (c = cmdtab; c->name != NULL; c++)
			(void) printf("%-*s\t%s\n", HELPINDENT, c->name,
			    c->help);
		return;
	}
	while (--argc > 0) {
		char *arg;
		arg = *++argv;
		c = getcmd(arg);
		if (c == AMBIGCMD)
			(void) fprintf(stderr, "?Ambiguous help command %s\n",
			    arg);
		else if (c == NULL)
			(void) fprintf(stderr, "?Invalid help command %s\n",
			    arg);
		else
			(void) fprintf(stderr, "%s\n", c->help);
	}
}

/*ARGSUSED*/
static void
settrace(int argc, char **argv)
{
	trace = !trace;
	(void) printf("Packet tracing %s.\n", trace ? "on" : "off");
}

/*ARGSUSED*/
static void
setverbose(int argc, char **argv)
{
	verbose = !verbose;
	(void) printf("Verbose mode %s.\n", verbose ? "on" : "off");
}

static void
setblksize(int argc, char **argv)
{
	int b;
	const char *errstr;

	if (argc < 2) {
		if (strlcat(line, argv[0], sizeof (line)) >= sizeof (line)) {
			(void) fprintf(stderr, "%s is too big\n", argv[0]);
			return;
		}
		if (prompt_for_arg(line, sizeof (line), "value") == -1)
			return;
		makeargv(line, &argc, &argv);
	}
	if (argc != 2) {
		(void) fprintf(stderr, "usage: %s value\n", argv[0]);
		return;
	}

	/* RFC 2348 specifies valid blksize range, allow 0 to turn option off */
	errno = 0;
	b = strtonum(argv[1], 0, MAX_BLKSIZE, &errstr);
	if (errstr != NULL || (b > 0 && b < MIN_BLKSIZE))
		(void) fprintf(stderr, "%s: bad value: %s\n", argv[1], errstr);
	else
		blksize = b;
}

static void
setsrexmt(int argc, char **argv)
{
	int t;
	const char *errstr;

	if (argc < 2) {
		if (strlcat(line, argv[0], sizeof (line)) >= sizeof (line)) {
			(void) fprintf(stderr, "%s is too big\n", argv[0]);
			return;
		}
		if (prompt_for_arg(line, sizeof (line), "value") == -1)
			return;
		makeargv(line, &argc, &argv);
	}
	if (argc != 2) {
		(void) fprintf(stderr, "usage: %s value\n", argv[0]);
		return;
	}

	/* RFC 2349 specifies valid timeout range, allow 0 to turn option off */
	t = strtonum(argv[1], 0, MAX_TIMEOUT, &errstr);
	if (errstr != NULL || (t > 0 && t < MIN_TIMEOUT))
		(void) fprintf(stderr, "%s: bad value: %s\n", argv[1], errstr);
	else
		srexmtval = t;
}

static void
settsize(int argc, char **argv)
{
	if (argc != 1) {
		(void) fprintf(stderr, "usage: %s\n", argv[0]);
		return;
	}
	tsize_opt = !tsize_opt;
	(void) printf("Transfer size option %s.\n", tsize_opt ? "on" : "off");
}
