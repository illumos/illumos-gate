/*
 * Copyright (c) 1998 Sendmail, Inc.  All rights reserved.
 * Copyright (c) 1990, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * By using this file, you agree to the terms and conditions set
 * forth in the LICENSE file which can be found at the top level
 * of the sendmail distribution.
 */

/*
 * Copyright 1994-2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef lint
static char copyright[] =
"@(#) Copyright (c) 1990, 1993, 1994\n\
	The Regents of the University of California.  All rights reserved.\n";
#endif /* not lint */

#pragma ident  "%Z%%M% %I%     %E% SMI"

#ifndef lint
static char sccsid[] = "@(#)mail.local.c	8.83 (Berkeley) 12/17/98";
static char sccsi2[] = "%W% (Sun) %G%";
#endif /* not lint */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/file.h>

#include <netinet/in.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>
#include <maillock.h>
#include <grp.h>

#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include <syslog.h>

#include <sysexits.h>
#include <ctype.h>

#include <sm/conf.h>
#include <sendmail/pathnames.h>

/*
**  If you don't have flock, you could try using lockf instead.
*/

#ifdef LDA_USE_LOCKF
# define flock(a, b)	lockf(a, b, 0)
# ifdef LOCK_EX
#  undef LOCK_EX
# endif /* LOCK_EX */
# define LOCK_EX        F_LOCK
#endif /* LDA_USE_LOCKF */

#ifndef LOCK_EX
# include <sys/file.h>
#endif /* ! LOCK_EX */

#ifndef MAILER_DAEMON
# define MAILER_DAEMON	"MAILER-DAEMON"
#endif

typedef int bool;

#define	FALSE	0
#define	TRUE	1

bool	EightBitMime = TRUE;		/* advertise 8BITMIME in LMTP */
static int eval = EX_OK;			/* sysexits.h error value. */
static int lmtpmode = 0;
bool	bouncequota = FALSE;		/* permanent error when over quota */

#define	_PATH_MAILDIR	"/var/mail"
#define	_PATH_LOCTMP	"/tmp/local.XXXXXX"
#define	_PATH_LOCHTMP	"/tmp/lochd.XXXXXX"
#define	FALSE 0
#define	TRUE  1
#define	MAXLINE 2048

static void	deliver(int, int, char *, bool);
static void	e_to_sys(int);
static void	err(const char *fmt, ...);
static void	notifybiff(char *);
static void	store(char *, int);
static void	usage(void);
static void	vwarn();
static void	warn(const char *fmt, ...);
static void	mailerr(const char *, const char *, ...);
static void	sigterm_handler();

static char	unix_from_line[MAXLINE];
static int	ulen;
static int	content_length;
static int	bfd, hfd; /* temp file */
static uid_t	src_uid, targ_uid, saved_uid;
static int	sigterm_caught;

int
main(argc, argv)
	int argc;
	char *argv[];
{
	struct passwd *pw;
	int ch;
	uid_t uid;
	char *from;
	struct  group *grpptr;
	void dolmtp();

	openlog("mail.local", 0, LOG_MAIL);

	from = NULL;
	pw = NULL;
	sigterm_caught = FALSE;

	(void) sigset(SIGTERM, sigterm_handler);

	while ((ch = getopt(argc, argv, "7bdf:r:l")) != EOF)
		switch (ch) {
		case '7':		/* Do not advertise 8BITMIME */
			EightBitMime = FALSE;
			break;

		case 'b':		/* bounce mail when over quota. */
			bouncequota = TRUE;
			break;

		case 'd':		/* Backward compatible. */
			break;
		case 'f':
		case 'r':		/* Backward compatible. */
			if (from != NULL) {
				warn("multiple -f options");
				usage();
			}
			from = optarg;
			break;
		case 'l':
			lmtpmode++;
			break;
		case '?':
		default:
			usage();
		}
	argc -= optind;
	argv += optind;

	notifybiff(NULL); /* initialize biff structures */

	/*
	 * We expect sendmail will invoke us with saved id 0
	 * We then do setgid and setuid defore delivery
	 * setgid to mail group
	 */
	if ((grpptr = getgrnam("mail")) != NULL)
		(void) setgid(grpptr->gr_gid);
	saved_uid = geteuid();

	if (lmtpmode) {
		if (saved_uid != 0) {
			warn("only super-user can use -l option");
			exit(EX_CANTCREAT);
		}
		dolmtp(bouncequota);
	}

	if (!*argv)
		usage();

	/*
	 * If from not specified, use the name from getlogin() if the
	 * uid matches, otherwise, use the name from the password file
	 * corresponding to the uid.
	 */
	uid = getuid();
	if (!from && (!(from = getlogin()) ||
	    !(pw = getpwnam(from)) || pw->pw_uid != uid))
		from = (pw = getpwuid(uid)) ? pw->pw_name : "???";
	src_uid = pw ? pw->pw_uid : uid;

	/*
	 * There is no way to distinguish the error status of one delivery
	 * from the rest of the deliveries.  So, if we failed hard on one
	 * or more deliveries, but had no failures on any of the others, we
	 * return a hard failure.  If we failed temporarily on one or more
	 * deliveries, we return a temporary failure regardless of the other
	 * failures.  This results in the delivery being reattempted later
	 * at the expense of repeated failures and multiple deliveries.
	 */

	for (store(from, 0); *argv; ++argv)
		deliver(hfd, bfd, *argv, bouncequota);
	return (eval);
}

void
sigterm_handler()
{
	sigterm_caught = TRUE;
	(void) sigignore(SIGTERM);
}

char *
parseaddr(s)
	char *s;
{
	char *p;
	int len;

	if (*s++ != '<')
		return NULL;

	p = s;

	/* at-domain-list */
	while (*p == '@') {
		p++;
		if (*p == '[') {
			p++;
			while (isascii(*p) &&
			       (isalnum(*p) || *p == '.' ||
				*p == '-' || *p == ':'))
				p++;
			if (*p++ != ']')
				return NULL;
		} else {
			while ((isascii(*p) && isalnum(*p)) ||
			       strchr(".-_", *p))
				p++;
		}
		if (*p == ',' && p[1] == '@')
			p++;
		else if (*p == ':' && p[1] != '@')
			p++;
		else
			return NULL;
	}

	s = p;

	/* local-part */
	if (*p == '\"') {
		p++;
		while (*p && *p != '\"') {
			if (*p == '\\') {
				if (!*++p)
					return NULL;
			}
			p++;
		}
		if (!*p++)
			return NULL;
	} else {
		while (*p && *p != '@' && *p != '>') {
			if (*p == '\\') {
				if (!*++p)
					return NULL;
			} else {
			if (*p <= ' ' || (*p & 128) ||
			    strchr("<>()[]\\,;:\"", *p))
				return NULL;
			}
			p++;
		}
	}

	/* @domain */
	if (*p == '@') {
		p++;
		if (*p == '[') {
			p++;
			while (isascii(*p) &&
			       (isalnum(*p) || *p == '.' ||
				*p == '-' || *p == ':'))
				p++;
			if (*p++ != ']')
				return NULL;
		} else {
			while ((isascii(*p) && isalnum(*p)) ||
			       strchr(".-_", *p))
				p++;
		}
	}

	if (*p++ != '>')
		return NULL;
	if (*p && *p != ' ')
		return NULL;
	len = p - s - 1;

	if (*s == '\0' || len <= 0)
	{
		s = MAILER_DAEMON;
		len = strlen(s);
	}

	p = malloc(len + 1);
	if (p == NULL) {
		printf("421 4.3.0 memory exhausted\r\n");
		exit(EX_TEMPFAIL);
	}

	strncpy(p, s, len);
	p[len] = '\0';
	return p;
}

char *
process_recipient(addr)
	char *addr;
{
	if (getpwnam(addr) == NULL) {
		return "550 5.1.1 user unknown";
	}

	return NULL;
}

#define RCPT_GROW	30

void
dolmtp(bouncequota)
	bool bouncequota;
{
	char *return_path = NULL;
	char **rcpt_addr = NULL;
	int rcpt_num = 0;
	int rcpt_alloc = 0;
	bool gotlhlo = FALSE;
	char myhostname[MAXHOSTNAMELEN];
	char buf[4096];
	char *err;
	char *p;
	int i;

	gethostname(myhostname, sizeof myhostname - 1);

	printf("220 %s LMTP ready\r\n", myhostname);
	for (;;) {
		if (sigterm_caught) {
			for (; rcpt_num > 0; rcpt_num--)
				printf("451 4.3.0 shutting down\r\n");
			exit(EX_OK);
		}
		fflush(stdout);
		if (fgets(buf, sizeof(buf)-1, stdin) == NULL) {
			exit(EX_OK);
		}
		p = buf + strlen(buf) - 1;
		if (p >= buf && *p == '\n')
			*p-- = '\0';
		if (p >= buf && *p == '\r')
			*p-- = '\0';

		switch (buf[0]) {

		case 'd':
		case 'D':
			if (strcasecmp(buf, "data") == 0) {
				if (rcpt_num == 0) {
					printf("503 5.5.1 No recipients\r\n");
					continue;
				}
				store(return_path, rcpt_num);
				if (bfd == -1 || hfd == -1)
					continue;

				for (i = 0; i < rcpt_num; i++) {
					p = strchr(rcpt_addr[i], '+');
					if (p != NULL)
						*p++ = '\0';
					deliver(hfd, bfd, rcpt_addr[i], 
						bouncequota);
				}
				close(bfd);
				close(hfd);
				goto rset;
			}
			goto syntaxerr;
			/* NOTREACHED */
			break;

		case 'l':
		case 'L':
			if (strncasecmp(buf, "lhlo ", 5) == 0)
			{
				/* check for duplicate per RFC 1651 4.2 */
				if (gotlhlo)
				{
					printf("503 %s Duplicate LHLO\r\n",
					       myhostname);
					continue;
				}
				gotlhlo = TRUE;
				printf("250-%s\r\n", myhostname);
				if (EightBitMime)
					printf("250-8BITMIME\r\n");
				printf("250-ENHANCEDSTATUSCODES\r\n");
				printf("250 PIPELINING\r\n");
				continue;
			}
			goto syntaxerr;
			/* NOTREACHED */
			break;

		case 'm':
		case 'M':
			if (strncasecmp(buf, "mail ", 5) == 0) {
				if (return_path != NULL) {
					printf("503 5.5.1 Nested MAIL command\r\n");
					continue;
				}
				if (strncasecmp(buf+5, "from:", 5) != 0 ||
				    ((return_path = parseaddr(buf+10)) == NULL)) {
					printf("501 5.5.4 Syntax error in parameters\r\n");
					continue;
				}
				printf("250 2.5.0 ok\r\n");
				continue;
			}
			goto syntaxerr;

		case 'n':
		case 'N':
			if (strcasecmp(buf, "noop") == 0) {
				printf("250 2.0.0 ok\r\n");
				continue;
			}
			goto syntaxerr;

		case 'q':
		case 'Q':
			if (strcasecmp(buf, "quit") == 0) {
				printf("221 2.0.0 bye\r\n");
				exit(EX_OK);
			}
			goto syntaxerr;

		case 'r':
		case 'R':
			if (strncasecmp(buf, "rcpt ", 5) == 0) {
				if (return_path == NULL) {
					printf("503 5.5.1 Need MAIL command\r\n");
					continue;
				}
				if (rcpt_num >= rcpt_alloc) {
					rcpt_alloc += RCPT_GROW;
					rcpt_addr = (char **)
						realloc((char *)rcpt_addr,
							rcpt_alloc * sizeof(char **));
					if (rcpt_addr == NULL) {
						printf("421 4.3.0 memory exhausted\r\n");
						exit(EX_TEMPFAIL);
					}
				}
				if (strncasecmp(buf+5, "to:", 3) != 0 ||
				    ((rcpt_addr[rcpt_num] = parseaddr(buf+8)) == NULL)) {
					printf("501 5.5.4 Syntax error in parameters\r\n");
					continue;
				}
				if ((err = process_recipient(rcpt_addr[rcpt_num])) != NULL) {
					printf("%s\r\n", err);
					continue;
				}
				rcpt_num++;
				printf("250 2.1.5 ok\r\n");
				continue;
			}
			else if (strcasecmp(buf, "rset") == 0) {
				printf("250 2.0.0 ok\r\n");

  rset:
				while (rcpt_num > 0) {
					free(rcpt_addr[--rcpt_num]);
				}
				if (return_path != NULL)
					free(return_path);
				return_path = NULL;
				continue;
			}
			goto syntaxerr;

		case 'v':
		case 'V':
			if (strncasecmp(buf, "vrfy ", 5) == 0) {
				printf("252 2.3.3 try RCPT to attempt delivery\r\n");
				continue;
			}
			goto syntaxerr;

		default:
  syntaxerr:
			printf("500 5.5.2 Syntax error\r\n");
			continue;
		}
	}
}

static void
store(from, lmtprcpts)
	char *from;
	int lmtprcpts;
{
	FILE *fp = NULL;
	time_t tval;
	bool fullline = TRUE;	/* current line is terminated */
	bool prevfl;		/* previous line was terminated */
	char line[MAXLINE];
	FILE *bfp, *hfp;
	char *btn, *htn;
	int in_header_section;
	int newfd;

	bfd = -1;
	hfd = -1;
	btn = strdup(_PATH_LOCTMP);
	if ((bfd = mkstemp(btn)) == -1 || (bfp = fdopen(bfd, "w+")) == NULL) {
		if (bfd != -1)
			(void) close(bfd);
		if (lmtprcpts) {
			printf("451 4.3.0 unable to open temporary file\r\n");
			return;
		} else {
			mailerr("451 4.3.0", "unable to open temporary file");
			exit(eval);
		}
	}
	(void) unlink(btn);
	free(btn);

	if (lmtpmode) {
		printf("354 go ahead\r\n");
		fflush(stdout);
	}

	htn = strdup(_PATH_LOCHTMP);
	if ((hfd = mkstemp(htn)) == -1 || (hfp = fdopen(hfd, "w+")) == NULL) {
		if (hfd != -1)
			(void) close(hfd);
		e_to_sys(errno);
		err("unable to open temporary file");
	}
	(void) unlink(htn);
	free(htn);

	in_header_section = TRUE;
	content_length = 0;
	fp = hfp;

	line[0] = '\0';
	while (fgets(line, sizeof(line), stdin) != (char *)NULL)
	{
		size_t line_len = 0;
		int peek;

		prevfl = fullline;	/* preserve state of previous line */
		while (line[line_len] != '\n' && line_len < sizeof(line) - 2)
			line_len++;
		line_len++;

		/* Check for dot-stuffing */
		if (prevfl && lmtprcpts && line[0] == '.')
		{
			if (line[1] == '\n' ||
			    (line[1] == '\r' && line[2] == '\n'))
				goto lmtpdot;
			memcpy(line, line + 1, line_len);
			line_len--;
		}

		/* Check to see if we have the full line from fgets() */
		fullline = FALSE;
		if (line_len > 0)
		{
			if (line[line_len - 1] == '\n')
			{
				if (line_len >= 2 &&
				    line[line_len - 2] == '\r')
				{
					line[line_len - 2] = '\n';
					line[line_len - 1] = '\0';
					line_len--;
				}
				fullline = TRUE;
			}
			else if (line[line_len - 1] == '\r')
			{
				/* Did we just miss the CRLF? */
				peek = fgetc(stdin);
				if (peek == '\n')
				{
					line[line_len - 1] = '\n';
					fullline = TRUE;
				}
				else
					(void) ungetc(peek, stdin);
			}
		}
		else
			fullline = TRUE;

		if (prevfl && line[0] == '\n' && in_header_section) {
			in_header_section = FALSE;
			if (fflush(fp) == EOF || ferror(fp)) {
				if (lmtprcpts) {
					while (lmtprcpts--)
						printf("451 4.3.0 temporary file write error\r\n");
					fclose(fp);
					return;
				} else {
					mailerr("451 4.3.0",
						"temporary file write error");
					fclose(fp);
					exit(eval);
				}
			}
			fp = bfp;
			continue;
		}

		if (in_header_section) {
			if (strncasecmp("Content-Length:", line, 15) == 0) {
				continue; /* skip this header */
			}
		} else
			content_length += strlen(line);
		(void) fwrite(line, sizeof(char), line_len, fp);
		if (ferror(fp)) {
			if (lmtprcpts) {
				while (lmtprcpts--)
					printf("451 4.3.0 temporary file write error\r\n");
				fclose(fp);
				return;
			} else {
				mailerr("451 4.3.0",
					"temporary file write error");
				fclose(fp);
				exit(eval);
			}
		}
	}
	if (sigterm_caught) {
		if (lmtprcpts)
			while (lmtprcpts--)
				printf("451 4.3.0 shutting down\r\n");
		else
			mailerr("451 4.3.0", "shutting down");
		fclose(fp);
		exit(eval);
	}

	if (lmtprcpts) {
		/* Got a premature EOF -- toss message and exit */
		exit(EX_OK);
	}

	/* If message not newline terminated, need an extra. */
	if (!strchr(line, '\n')) {
		(void) putc('\n', fp);
		content_length++;
	}

  lmtpdot:

	/* Output a newline; note, empty messages are allowed. */
	(void) putc('\n', fp);

	if (fflush(fp) == EOF || ferror(fp)) {
		if (lmtprcpts) {
			while (lmtprcpts--) {
				printf("451 4.3.0 temporary file write error\r\n");
			}
			fclose(fp);
			return;
		} else {
			mailerr("451 4.3.0", "temporary file write error");
			fclose(fp);
			exit(eval);
		}
	}

	if ((newfd = dup(bfd)) >= 0) {
		fclose(bfp);
		bfd = newfd;
	}
	if ((newfd = dup(hfd)) >= 0) {
		fclose(hfp);
		hfd = newfd;
	}
	(void) time(&tval);
	(void) snprintf(unix_from_line, sizeof (unix_from_line), "From %s %s",
	    from, ctime(&tval));
	ulen = strlen(unix_from_line);
}

static void
handle_error(err_num, bouncequota, path)
	int err_num;
	bool bouncequota;
	char *path;
{
#ifdef EDQUOT
	if (err_num == EDQUOT && bouncequota) {
		mailerr("552 5.2.2", "%s: %s", path, sm_errstring(err_num));
	} else
#endif /* EDQUOT */
		mailerr("450 4.2.0", "%s: %s", path, sm_errstring(err_num));
}

static void
deliver(hfd, bfd, name, bouncequota)
	int hfd;
	int bfd;
	char *name;
	bool bouncequota;
{
	struct stat fsb, sb;
	int mbfd = -1, nr, nw = 0, off;
	char biffmsg[100], buf[8*1024], path[MAXPATHLEN];
	off_t curoff, cursize;
	int len;
	struct passwd *pw = NULL;

	/*
 	* Disallow delivery to unknown names -- special mailboxes
 	* can be handled in the sendmail aliases file.
 	*/
	if ((pw = getpwnam(name)) == NULL) {
		eval = EX_TEMPFAIL;
		mailerr("451 4.3.0", "cannot lookup name: %s", name);
		return;
	}
	endpwent();

	if (sigterm_caught) {
		mailerr("451 4.3.0", "shutting down");
		return;
	}

	/* mailbox may be NFS mounted, seteuid to user */
	targ_uid = pw->pw_uid;
	(void) seteuid(targ_uid);

	if ((saved_uid != 0) && (src_uid != targ_uid)) {
		/*
		 * If saved_uid == 0 (root), anything is OK; this is
		 * as it should be.  But to prevent a random user from
		 * calling "mail.local foo" in an attempt to hijack
		 * foo's mail-box, make sure src_uid == targ_uid o/w.
		 */
		warn("%s: wrong owner (is %d, should be %d)",
			name, src_uid, targ_uid);
		eval = EX_CANTCREAT;
		return;
	}

	path[0] = '\0';
	(void) snprintf(path, sizeof (path), "%s/%s", _PATH_MAILDIR, name);

	/*
	 * If the mailbox is linked or a symlink, fail.  There's an obvious
	 * race here, that the file was replaced with a symbolic link after
	 * the lstat returned, but before the open.  We attempt to detect
	 * this by comparing the original stat information and information
	 * returned by an fstat of the file descriptor returned by the open.
	 *
	 * NB: this is a symptom of a larger problem, that the mail spooling
	 * directory is writeable by the wrong users.  If that directory is
	 * writeable, system security is compromised for other reasons, and
	 * it cannot be fixed here.
	 *
	 * If we created the mailbox, set the owner/group.  If that fails,
	 * just return.  Another process may have already opened it, so we
	 * can't unlink it.  Historically, binmail set the owner/group at
	 * each mail delivery.  We no longer do this, assuming that if the
	 * ownership or permissions were changed there was a reason.
	 *
	 * XXX
	 * open(2) should support flock'ing the file.
	 */
tryagain:
	/* should check lock status, but... maillock return no value */
	maillock(name, 10);

	if (sigterm_caught) {
		mailerr("451 4.3.0", "shutting down");
		goto err0;
	}

	if (lstat(path, &sb)) {
		mbfd = open(path, O_APPEND|O_CREAT|O_EXCL|O_WRONLY,
				S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
		if (mbfd != -1)
			(void) fchmod(mbfd, 0660);


		if (mbfd == -1) {
			if (errno == EEXIST) {
				mailunlock();
				goto tryagain;
			}
		}
	} else if (sb.st_nlink != 1) {
		mailerr("550 5.2.0", "%s: too many links", path);
		goto err0;
	} else if (!S_ISREG(sb.st_mode)) {
		mailerr("550 5.2.0", "%s: irregular file", path);
		goto err0;
	} else {
		mbfd = open(path, O_APPEND|O_WRONLY, 0);
		if (mbfd != -1 &&
		    (fstat(mbfd, &fsb) || fsb.st_nlink != 1 ||
		    S_ISLNK(fsb.st_mode) || sb.st_dev != fsb.st_dev ||
		    sb.st_ino != fsb.st_ino)) {
			eval = EX_TEMPFAIL;
			mailerr("550 5.2.0",
				"%s: fstat: file changed after open", path);
			goto err1;
		}
	}

	if (mbfd == -1) {
		mailerr("450 4.2.0", "%s: %s", path, strerror(errno));
		goto err0;
	}

	if (sigterm_caught) {
		mailerr("451 4.3.0", "shutting down");
		goto err0;
	}

	/* Get the starting offset of the new message for biff. */
	curoff = lseek(mbfd, (off_t)0, SEEK_END);
	(void) snprintf(biffmsg, sizeof (biffmsg), "%s@%ld\n", name, curoff);

	/* Copy the message into the file. */
	if (lseek(hfd, (off_t)0, SEEK_SET) == (off_t)-1) {
		mailerr("450 4.2.0", "temporary file: %s", strerror(errno));
		goto err1;
	}
	/* Copy the message into the file. */
	if (lseek(bfd, (off_t)0, SEEK_SET) == (off_t)-1) {
		mailerr("450 4.2.0", "temporary file: %s", strerror(errno));
		goto err1;
	}
	if ((write(mbfd, unix_from_line, ulen)) != ulen) {
		handle_error(errno, bouncequota, path);
		goto err2;
	}

	if (sigterm_caught) {
		mailerr("451 4.3.0", "shutting down");
		goto err2;
	}

	while ((nr = read(hfd, buf, sizeof (buf))) > 0)
		for (off = 0; off < nr; nr -= nw, off += nw)
			if ((nw = write(mbfd, buf + off, nr)) < 0)
			{
				handle_error(errno, bouncequota, path);
				goto err2;
			}
	if (nr < 0) {
		handle_error(errno, bouncequota, path);
		goto err2;
	}

	if (sigterm_caught) {
		mailerr("451 4.3.0", "shutting down");
		goto err2;
	}

	(void) snprintf(buf, sizeof (buf), "Content-Length: %d\n\n",
	    content_length);
	len = strlen(buf);
	if (write(mbfd, buf, len) != len) {
		handle_error(errno, bouncequota, path);
		goto err2;
	}

	if (sigterm_caught) {
		mailerr("451 4.3.0", "shutting down");
		goto err2;
	}

	while ((nr = read(bfd, buf, sizeof (buf))) > 0) {
		for (off = 0; off < nr; nr -= nw, off += nw)
			if ((nw = write(mbfd, buf + off, nr)) < 0) {
				handle_error(errno, bouncequota, path);
				goto err2;
			}
		if (sigterm_caught) {
			mailerr("451 4.3.0", "shutting down");
			goto err2;
		}
	}
	if (nr < 0) {
		handle_error(errno, bouncequota, path);
		goto err2;
	}

	/* Flush to disk, don't wait for update. */
	if (fsync(mbfd)) {
		handle_error(errno, bouncequota, path);
err2:		if (mbfd >= 0)
			(void)ftruncate(mbfd, curoff);
err1:		(void)close(mbfd);
err0:		mailunlock();
		(void)seteuid(saved_uid);
		return;
	}

	/*
	**  Save the current size so if the close() fails below
	**  we can make sure no other process has changed the mailbox
	**  between the failed close and the re-open()/re-lock().
	**  If something else has changed the size, we shouldn't
	**  try to truncate it as we may do more harm then good
	**  (e.g., truncate a later message delivery).
	*/

	if (fstat(mbfd, &sb) < 0)
		cursize = 0;
	else
		cursize = sb.st_size;

	/* Close and check -- NFS doesn't write until the close. */
	if (close(mbfd))
	{
		handle_error(errno, bouncequota, path);
		mbfd = open(path, O_WRONLY, 0);
		if (mbfd < 0 ||
		    cursize == 0
		    || flock(mbfd, LOCK_EX) < 0 ||
		    fstat(mbfd, &sb) < 0 ||
		    sb.st_size != cursize ||
		    sb.st_nlink != 1 ||
		    !S_ISREG(sb.st_mode) ||
		    sb.st_dev != fsb.st_dev ||
		    sb.st_ino != fsb.st_ino ||
		    sb.st_uid != fsb.st_uid)
		{
			/* Don't use a bogus file */
			if (mbfd >= 0)
			{
				(void) close(mbfd);
				mbfd = -1;
			}
		}

		/* Attempt to truncate back to pre-write size */
		goto err2;
	} else
		notifybiff(biffmsg);

	mailunlock();

	(void)seteuid(saved_uid);

	if (lmtpmode) {
		printf("250 2.1.5 %s OK\r\n", name);
	}
}

static void
notifybiff(msg)
	char *msg;
{
	static struct sockaddr_in addr;
	static int f = -1;
	struct hostent *hp;
	struct servent *sp;
	int len;

	if (msg == NULL) {
		/* Be silent if biff service not available. */
		if ((sp = getservbyname("biff", "udp")) == NULL)
			return;
		if ((hp = gethostbyname("localhost")) == NULL) {
			warn("localhost: %s", strerror(errno));
			return;
		}
		addr.sin_family = hp->h_addrtype;
		(void) memmove(&addr.sin_addr, hp->h_addr, hp->h_length);
		addr.sin_port = sp->s_port;
		return;
	}

	if (addr.sin_family == 0)
		return; /* did not initialize */

	if (f < 0 && (f = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		warn("socket: %s", strerror(errno));
		return;
	}
	len = strlen(msg) + 1;
	if (sendto(f, msg, len, 0, (struct sockaddr *)&addr, sizeof (addr))
	    != len)
		warn("sendto biff: %s", strerror(errno));
}

static void
usage()
{
	eval = EX_USAGE;
	err("usage: mail.local [-l] [-f from] user ...");
}

static void
/*VARARGS2*/
#ifdef __STDC__
mailerr(const char *hdr, const char *fmt, ...)
#else
mailerr(hdr, fmt, va_alist)
	const char *hdr;
	const char *fmt;
	va_dcl
#endif
{
	va_list ap;

#ifdef __STDC__
	va_start(ap, fmt);
#else
	va_start(ap);
#endif
	if (lmtpmode)
	{
		if (hdr != NULL)
			printf("%s ", hdr);
		vprintf(fmt, ap);
		printf("\r\n");
	}
	else
	{
		e_to_sys(errno);
		vwarn(fmt, ap);
	}
}

static void
/*VARARGS1*/
#ifdef __STDC__
err(const char *fmt, ...)
#else
err(fmt, va_alist)
	const char *fmt;
	va_dcl
#endif
{
	va_list ap;

#ifdef __STDC__
	va_start(ap, fmt);
#else
	va_start(ap);
#endif
	vwarn(fmt, ap);
	va_end(ap);

	exit(eval);
}

static void
/*VARARGS1*/
#ifdef __STDC__
warn(const char *fmt, ...)
#else
warn(fmt, va_alist)
	const char *fmt;
	va_dcl
#endif
{
	va_list ap;

#ifdef __STDC__
	va_start(ap, fmt);
#else
	va_start(ap);
#endif
	vwarn(fmt, ap);
	va_end(ap);
}

static void
vwarn(fmt, ap)
	const char *fmt;
	va_list ap;
{
	/*
	 * Log the message to stderr.
	 *
	 * Don't use LOG_PERROR as an openlog() flag to do this,
	 * it's not portable enough.
	 */
	if (eval != EX_USAGE)
		(void) fprintf(stderr, "mail.local: ");
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, "\n");

	/* Log the message to syslog. */
	vsyslog(LOG_ERR, fmt, ap);
}

/*
 * e_to_sys --
 *	Guess which errno's are temporary.  Gag me.
 */
static void
e_to_sys(num)
	int num;
{
	/* Temporary failures override hard errors. */
	if (eval == EX_TEMPFAIL)
		return;

	switch (num)		/* Hopefully temporary errors. */
	{
#ifdef EDQUOT
	case EDQUOT:		/* Disc quota exceeded */
		if (bouncequota)
		{
			eval = EX_UNAVAILABLE;
			break;
		}
#endif /* EDQUOT */
#ifdef EAGAIN
		/* FALLTHROUGH */
	case EAGAIN:		/* Resource temporarily unavailable */
#endif
#ifdef EBUSY
	case EBUSY:		/* Device busy */
#endif
#ifdef EPROCLIM
	case EPROCLIM:		/* Too many processes */
#endif
#ifdef EUSERS
	case EUSERS:		/* Too many users */
#endif
#ifdef ECONNABORTED
	case ECONNABORTED:	/* Software caused connection abort */
#endif
#ifdef ECONNREFUSED
	case ECONNREFUSED:	/* Connection refused */
#endif
#ifdef ECONNRESET
	case ECONNRESET:	/* Connection reset by peer */
#endif
#ifdef EDEADLK
	case EDEADLK:		/* Resource deadlock avoided */
#endif
#ifdef EFBIG
	case EFBIG:		/* File too large */
#endif
#ifdef EHOSTDOWN
	case EHOSTDOWN:		/* Host is down */
#endif
#ifdef EHOSTUNREACH
	case EHOSTUNREACH:	/* No route to host */
#endif
#ifdef EMFILE
	case EMFILE:		/* Too many open files */
#endif
#ifdef ENETDOWN
	case ENETDOWN:		/* Network is down */
#endif
#ifdef ENETRESET
	case ENETRESET:		/* Network dropped connection on reset */
#endif
#ifdef ENETUNREACH
	case ENETUNREACH:	/* Network is unreachable */
#endif
#ifdef ENFILE
	case ENFILE:		/* Too many open files in system */
#endif
#ifdef ENOBUFS
	case ENOBUFS:		/* No buffer space available */
#endif
#ifdef ENOMEM
	case ENOMEM:		/* Cannot allocate memory */
#endif
#ifdef ENOSPC
	case ENOSPC:		/* No space left on device */
#endif
#ifdef EROFS
	case EROFS:		/* Read-only file system */
#endif
#ifdef ESTALE
	case ESTALE:		/* Stale NFS file handle */
#endif
#ifdef ETIMEDOUT
	case ETIMEDOUT:		/* Connection timed out */
#endif
#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
	case EWOULDBLOCK:	/* Operation would block. */
#endif
		eval = EX_TEMPFAIL;
		break;
	default:
		eval = EX_UNAVAILABLE;
		break;
	}
}
