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
 *	Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved  	*/

/*
 *	University Copyright- Copyright (c) 1982, 1986, 1988
 *	The Regents of the University of California
 *	All Rights Reserved
 *
 *	University Acknowledgment- Portions of this document are derived from
 *	software developed by the University of California, Berkeley, and its
 *	contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * FTP User Program -- Command Interface.
 */
#define	EXTERN
#include	"ftp_var.h"
#include	<deflt.h>	/* macros that make using libcmd easier */

static void usage(void);
static void timeout_sig(int sig);
static void cmdscanner(int top);
static void intr(int sig);
static char *slurpstring(void);
extern	int use_eprt;

boolean_t ls_invokes_NLST = B_TRUE;

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#define	GETOPT_STR	"dginpstvET:axfm:"
#define	USAGE_STR	"[-adfginpstvx] [-m mech] [-T timeout] " \
			"[hostname [port]]"

int
main(int argc, char *argv[])
{
	char *cp;
	int c, top;
	struct passwd *pw = NULL;
	char homedir[MAXPATHLEN];
	char *temp_string = NULL;

	(void) setlocale(LC_ALL, "");

	buf = (char *)memalign(getpagesize(), FTPBUFSIZ);
	if (buf == NULL) {
		(void) fprintf(stderr, "ftp: memory allocation failed\n");
		return (1);
	}

	timeoutms = timeout = 0;
	doglob = 1;
	interactive = 1;
	autologin = 1;

	autoauth = 0;
	/* by default SYST command will be sent to determine system type */
	skipsyst = 0;
	fflag = 0;
	autoencrypt = 0;
	goteof = 0;
	mechstr[0] = '\0';

	sendport = -1;	/* tri-state variable. start out in "automatic" mode. */
	passivemode = 0;

	while ((c = getopt(argc, argv, GETOPT_STR)) != EOF) {
		switch (c) {
		case 'd':
			options |= SO_DEBUG;
			debug++;
			break;

		case 'g':
			doglob = 0;
			break;

		case 'i':
			interactive = 0;
			break;

		case 'n':
			autologin = 0;
			break;

		case 'p':
			passivemode = 1;
			break;

		case 't':
			trace++;
			break;

		case 'v':
			verbose++;
			break;

		/* undocumented option: allows testing of EPRT */
		case 'E':
			use_eprt = 1;
			break;

		case 'T':
			if (!isdigit(*optarg)) {
				(void) fprintf(stderr,
					"ftp: bad timeout: \"%s\"\n", optarg);
				break;
			}
			timeout = atoi(optarg);
			timeoutms = timeout * MILLISEC;
			break;

		case 'a':
			autoauth = 1;
			break;

		case 'f':
			autoauth = 1;
			fflag = 1;
			break;

		case 'm':
			autoauth = 1;
			call(setmech, "ftp", optarg, 0);
			if (code != 0)
				exit(1);
			break;

		case 'x':
			autoauth = 1;
			autoencrypt = 1;
			break;

		case 's':
			skipsyst = 1;
			break;

		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 2)
		usage();

	fromatty = isatty(fileno(stdin));
	/*
	 * Scan env, then DEFAULTFTPFILE
	 * for FTP_LS_SENDS_NLST
	 */
	temp_string = getenv("FTP_LS_SENDS_NLST");
	if (temp_string == NULL) {	/* env var not set */
		if (defopen(DEFAULTFTPFILE) == 0) {
			/*
			 * turn off case sensitivity
			 */
			int flags = defcntl(DC_GETFLAGS, 0);

			TURNOFF(flags, DC_CASE);
			(void) defcntl(DC_SETFLAGS, flags);

			temp_string = defread("FTP_LS_SENDS_NLST=");
			(void) defopen(NULL);	/* close default file */
		}
	}
	if (temp_string != NULL &&
	    strncasecmp(temp_string, "n", 1) == 0)
		ls_invokes_NLST = B_FALSE;

	/*
	 * Set up defaults for FTP.
	 */
	(void) strcpy(typename, "ascii"), type = TYPE_A;
	(void) strcpy(formname, "non-print"), form = FORM_N;
	(void) strcpy(modename, "stream"), mode = MODE_S;
	(void) strcpy(structname, "file"), stru = STRU_F;
	(void) strcpy(bytename, "8"), bytesize = 8;
	if (fromatty)
		verbose++;
	cpend = 0;	/* no pending replies */
	proxy = 0;	/* proxy not active */
	crflag = 1;	/* strip c.r. on ascii gets */

	if (mechstr[0] == '\0') {
		strlcpy(mechstr, FTP_DEF_MECH, MECH_SZ);
	}

	/*
	 * Set up the home directory in case we're globbing.
	 */
	cp = getlogin();
	if (cp != NULL) {
		pw = getpwnam(cp);
	}
	if (pw == NULL)
		pw = getpwuid(getuid());
	if (pw != NULL) {
		home = homedir;
		(void) strcpy(home, pw->pw_dir);
	}
	if (setjmp(timeralarm)) {
		(void) fflush(stdout);
		(void) printf("Connection timeout\n");
		exit(1);
	}
	(void) signal(SIGALRM, timeout_sig);
	reset_timer();
	if (argc > 0) {
		int nargc = 0;
		char *nargv[4];

		if (setjmp(toplevel))
			return (0);
		(void) signal(SIGINT, intr);
		(void) signal(SIGPIPE, lostpeer);
		nargv[nargc++] = "ftp";
		nargv[nargc++] = argv[0];		/* hostname */
		if (argc > 1)
			nargv[nargc++] = argv[1];	/* port */
		nargv[nargc] = NULL;
		setpeer(nargc, nargv);
	}
	top = setjmp(toplevel) == 0;
	if (top) {
		(void) signal(SIGINT, intr);
		(void) signal(SIGPIPE, lostpeer);
	}

	for (;;) {
		cmdscanner(top);
		top = 1;
	}
}

static void
usage(void)
{
	(void) fprintf(stderr, "usage: ftp %s\n", USAGE_STR);
	exit(1);
}

void
reset_timer()
{
	/* The test is just to reduce syscalls if timeouts aren't used */
	if (timeout)
		alarm(timeout);
}

void
stop_timer()
{
	if (timeout)
		alarm(0);
}

/*ARGSUSED*/
static void
timeout_sig(int sig)
{
	longjmp(timeralarm, 1);
}

/*ARGSUSED*/
static void
intr(int sig)
{
	longjmp(toplevel, 1);
}

/*ARGSUSED*/
void
lostpeer(int sig)
{
	extern FILE *ctrl_out;
	extern int data;

	if (connected) {
		if (ctrl_out != NULL) {
			(void) shutdown(fileno(ctrl_out), 1+1);
			(void) fclose(ctrl_out);
			ctrl_out = NULL;
		}
		if (data >= 0) {
			(void) shutdown(data, 1+1);
			(void) close(data);
			data = -1;
		}
		connected = 0;

		auth_type = AUTHTYPE_NONE;
		clevel = dlevel = PROT_C;
		goteof = 0;
	}
	pswitch(1);
	if (connected) {
		if (ctrl_out != NULL) {
			(void) shutdown(fileno(ctrl_out), 1+1);
			(void) fclose(ctrl_out);
			ctrl_out = NULL;
		}
		connected = 0;

		auth_type = AUTHTYPE_NONE;
		clevel = dlevel = PROT_C;
		goteof = 0;
	}
	proxflag = 0;
	pswitch(0);
}

/*
 * Command parser.
 */
static void
cmdscanner(int top)
{
	struct cmd *c;

	if (!top)
		(void) putchar('\n');
	for (;;) {
		stop_timer();
		if (fromatty) {
			(void) printf("ftp> ");
			(void) fflush(stdout);
		}
		if (fgets(line, sizeof (line), stdin) == 0) {
			if (feof(stdin) || ferror(stdin))
				quit(0, NULL);
			break;
		}
		if (line[0] == 0)
			break;
		/* If not all, just discard rest of line */
		if (line[strlen(line)-1] != '\n') {
			while (fgetc(stdin) != '\n' && !feof(stdin) &&
			    !ferror(stdin))
				;
			(void) printf("Line too long\n");
			continue;
		} else
			line[strlen(line)-1] = 0;

		makeargv();
		if (margc == 0) {
			continue;
		}
		c = getcmd(margv[0]);
		if (c == (struct cmd *)-1) {
			(void) printf("?Ambiguous command\n");
			continue;
		}
		if (c == 0) {
			(void) printf("?Invalid command\n");
			continue;
		}
		if (c->c_conn && !connected) {
			(void) printf("Not connected.\n");
			continue;
		}
		reset_timer();
		(*c->c_handler)(margc, margv);
#ifndef CTRL
#define	CTRL(c) ((c)&037)
#endif
		stop_timer();
		if (bell && c->c_bell)
			(void) putchar(CTRL('g'));
		if (c->c_handler != help)
			break;
	}
	(void) signal(SIGINT, intr);
	(void) signal(SIGPIPE, lostpeer);
}

struct cmd *
getcmd(char *name)
{
	char *p, *q;
	struct cmd *c, *found;
	int nmatches, longest;
	extern struct cmd cmdtab[];

	if (name == NULL)
		return (0);

	longest = 0;
	nmatches = 0;
	found = 0;
	for (c = cmdtab; (p = c->c_name) != NULL; c++) {
		for (q = name; *q == *p++; q++)
			if (*q == 0)		/* exact match? */
				return (c);
		if (!*q) {			/* the name was a prefix */
			if (q - name > longest) {
				longest = q - name;
				nmatches = 1;
				found = c;
			} else if (q - name == longest)
				nmatches++;
		}
	}
	if (nmatches > 1)
		return ((struct cmd *)-1);
	return (found);
}

/*
 * Slice a string up into argc/argv.
 */

static int slrflag;
#define	MARGV_INC	20

void
makeargv(void)
{
	char **argp;
	static int margv_size;

	margc = 0;
	stringbase = line;		/* scan from first of buffer */
	argbase = argbuf;		/* store from first of buffer */
	slrflag = 0;

	if (!margv) {
		margv_size = MARGV_INC;
		if ((margv = malloc(margv_size * sizeof (char *))) == NULL)
			fatal("Out of memory");
	}
	argp = margv;
	while (*argp++ = slurpstring()) {
		margc++;
		if (margc == margv_size) {
			margv_size += MARGV_INC;
			if ((margv = realloc(margv,
			    margv_size * sizeof (char *))) == NULL)
				fatal("Out of memory");
			argp = margv + margc;
		}
	}
}

/*
 * Parse string into argbuf;
 * implemented with FSM to
 * handle quoting and strings
 */
static char *
slurpstring(void)
{
	int got_one = 0;
	char *sb = stringbase;
	char *ap = argbase;
	char *tmp = argbase;		/* will return this if token found */
	int	len;

	if (*sb == '!' || *sb == '$') {	/* recognize ! as a token for shell */
		switch (slrflag) {	/* and $ as token for macro invoke */
			case 0:
				slrflag++;
				stringbase++;
				return ((*sb == '!') ? "!" : "$");
			case 1:
				slrflag++;
				altarg = stringbase;
				break;
			default:
				break;
		}
	}

S0:
	switch (*sb) {

	case '\0':
		goto OUT;

	case ' ':
	case '\t':
		sb++; goto S0;

	default:
		switch (slrflag) {
			case 0:
				slrflag++;
				break;
			case 1:
				slrflag++;
				altarg = sb;
				break;
			default:
				break;
		}
		goto S1;
	}

S1:
	switch (*sb) {

	case ' ':
	case '\t':
	case '\0':
		goto OUT;	/* end of token */

	case '\\':
		sb++; goto S2;	/* slurp next character */

	case '"':
		sb++; goto S3;	/* slurp quoted string */

	default:
		if ((len = mblen(sb, MB_CUR_MAX)) <= 0)
			len = 1;
		memcpy(ap, sb, len);
		ap += len;
		sb += len;
		got_one = 1;
		goto S1;
	}

S2:
	switch (*sb) {

	case '\0':
		goto OUT;

	default:
		if ((len = mblen(sb, MB_CUR_MAX)) <= 0)
			len = 1;
		memcpy(ap, sb, len);
		ap += len;
		sb += len;
		got_one = 1;
		goto S1;
	}

S3:
	switch (*sb) {

	case '\0':
		goto OUT;

	case '"':
		sb++; goto S1;

	default:
		if ((len = mblen(sb, MB_CUR_MAX)) <= 0)
			len = 1;
		memcpy(ap, sb, len);
		ap += len;
		sb += len;
		got_one = 1;
		goto S3;
	}

OUT:
	if (got_one)
		*ap++ = '\0';
	argbase = ap;			/* update storage pointer */
	stringbase = sb;		/* update scan pointer */
	if (got_one) {
		return (tmp);
	}
	switch (slrflag) {
		case 0:
			slrflag++;
			break;
		case 1:
			slrflag++;
			altarg = (char *)0;
			break;
		default:
			break;
	}
	return ((char *)0);
}

#define	HELPINDENT (sizeof ("directory"))

/*
 * Help command.
 * Call each command handler with argc == 0 and argv[0] == name.
 */
void
help(int argc, char *argv[])
{
	struct cmd *c;
	extern struct cmd cmdtab[];

	if (argc == 1) {
		int i, j, w, k;
		int columns, width = 0, lines;
		extern int NCMDS;

		(void) printf(
			"Commands may be abbreviated.  Commands are:\n\n");
		for (c = cmdtab; c < &cmdtab[NCMDS]; c++) {
			int len = strlen(c->c_name);

			if (len > width)
				width = len;
		}
		width = (width + 8) &~ 7;
		columns = 80 / width;
		if (columns == 0)
			columns = 1;
		lines = (NCMDS + columns - 1) / columns;
		for (i = 0; i < lines; i++) {
			for (j = 0; j < columns; j++) {
				c = cmdtab + j * lines + i;
				if (c->c_name && (!proxy || c->c_proxy)) {
					(void) printf("%s", c->c_name);
				} else if (c->c_name) {
					for (k = 0; k < strlen(c->c_name);
					    k++) {
						(void) putchar(' ');
					}
				}
				if (c + lines >= &cmdtab[NCMDS]) {
					(void) printf("\n");
					break;
				}
				w = strlen(c->c_name);
				while (w < width) {
					w = (w + 8) &~ 7;
					(void) putchar('\t');
				}
			}
		}
		return;
	}
	while (--argc > 0) {
		char *arg;
		arg = *++argv;
		c = getcmd(arg);
		if (c == (struct cmd *)-1)
			(void) printf("?Ambiguous help command %s\n", arg);
		else if (c == (struct cmd *)0)
			(void) printf("?Invalid help command %s\n", arg);
		else
			(void) printf("%-*s\t%s\n", HELPINDENT,
				c->c_name, c->c_help);
	}
}

/*
 * Call routine with argc, argv set from args (terminated by 0).
 */
void
call(void (*routine)(int argc, char *argv[]), ...)
{
	va_list ap;
	char *argv[10];
	int argc = 0;

	va_start(ap, routine);
	while ((argv[argc] = va_arg(ap, char *)) != (char *)0)
		argc++;
	va_end(ap);
	(*routine)(argc, argv);
}
