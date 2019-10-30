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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <pwd.h>
#include <unistd.h>
#include <locale.h>
#include <nl_types.h>
#include <langinfo.h>
#include <libintl.h>
#include <security/pam_appl.h>
#include <limits.h>
#include <libzoneinfo.h>
#include "cron.h"
#include "getresponse.h"

#if defined(XPG4)
#define	VIPATH	"/usr/xpg4/bin/vi"
#elif defined(XPG6)
#define	VIPATH	"/usr/xpg6/bin/vi"
#else
#define	_XPG_NOTDEFINED
#define	VIPATH	"vi"
#endif

#define	TMPFILE		"_cron"		/* prefix for tmp file */
#define	CRMODE		0600	/* mode for creating crontabs */

#define	BADCREATE	\
	"can't create your crontab file in the crontab directory."
#define	BADOPEN		"can't open your crontab file."
#define	BADSHELL	\
	"because your login shell isn't /usr/bin/sh, you can't use cron."
#define	WARNSHELL	"warning: commands will be executed using /usr/bin/sh\n"
#define	BADUSAGE	\
	"usage:\n"			\
	"\tcrontab [file]\n"		\
	"\tcrontab -e [username]\n"	\
	"\tcrontab -l [-g] [username]\n"	\
	"\tcrontab -r [username]"
#define	INVALIDUSER	"you are not a valid user (no entry in /etc/passwd)."
#define	NOTALLOWED	"you are not authorized to use cron.  Sorry."
#define	NOTROOT		\
	"you must be super-user to access another user's crontab file"
#define	AUDITREJECT	"The audit context for your shell has not been set."
#define	EOLN		"unexpected end of line."
#define	UNEXPECT	"unexpected character found in line."
#define	OUTOFBOUND	"number out of bounds."
#define	OVERFLOW	"too many elements."
#define	ERRSFND		"errors detected in input, no crontab file generated."
#define	ED_ERROR	\
	"     The editor indicates that an error occurred while you were\n"\
	"     editing the crontab data - usually a minor typing error.\n\n"
#define	BADREAD		"error reading your crontab file"
#define	ED_PROMPT	\
	"     Edit again, to ensure crontab information is intact (%s/%s)?\n"\
	"     ('%s' will discard edits.)"
#define	NAMETOOLONG	"login name too long"
#define	BAD_TZ	"Timezone unrecognized in: %s"
#define	BAD_SHELL	"Invalid shell specified: %s"
#define	BAD_HOME	"Unable to access directory: %s\t%s\n"

extern int	per_errno;

extern int	audit_crontab_modify(char *, char *, int);
extern int	audit_crontab_delete(char *, int);
extern int	audit_crontab_not_allowed(uid_t, char *);

int		err;
int		cursor;
char		*cf;
char		*tnam;
char		edtemp[5+13+1];
char		line[CTLINESIZE];
static		char	login[UNAMESIZE];

static void	catch(int);
static void	crabort(char *);
static void	cerror(char *);
static void	copycron(FILE *);

int
main(int argc, char **argv)
{
	int	c, r;
	int	rflag	= 0;
	int	lflag	= 0;
	int	gflag	= 0;
	int	eflag	= 0;
	int	errflg	= 0;
	char *pp;
	FILE *fp, *tmpfp;
	struct stat stbuf;
	struct passwd *pwp;
	time_t omodtime;
	char *editor;
	uid_t ruid;
	pid_t pid;
	int stat_loc;
	int ret;
	char real_login[UNAMESIZE];
	int tmpfd = -1;
	pam_handle_t *pamh;
	int pam_error;
	char *buf;
	size_t buflen;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (init_yes() < 0) {
		(void) fprintf(stderr, gettext(ERR_MSG_INIT_YES),
		    strerror(errno));
		exit(1);
	}

	while ((c = getopt(argc, argv, "eglr")) != EOF)
		switch (c) {
			case 'e':
				eflag++;
				break;
			case 'g':
				gflag++;
				break;
			case 'l':
				lflag++;
				break;
			case 'r':
				rflag++;
				break;
			case '?':
				errflg++;
				break;
		}

	if (eflag + lflag + rflag > 1)
		errflg++;

	if (gflag && !lflag)
		errflg++;

	argc -= optind;
	argv += optind;
	if (errflg || argc > 1)
		crabort(BADUSAGE);

	ruid = getuid();
	if ((pwp = getpwuid(ruid)) == NULL)
		crabort(INVALIDUSER);

	if (strlcpy(real_login, pwp->pw_name, sizeof (real_login))
	    >= sizeof (real_login))
		crabort(NAMETOOLONG);

	if ((eflag || lflag || rflag) && argc == 1) {
		if ((pwp = getpwnam(*argv)) == NULL)
			crabort(INVALIDUSER);

		if (!cron_admin(real_login)) {
			if (pwp->pw_uid != ruid)
				crabort(NOTROOT);
			else
				pp = getuser(ruid);
		} else
			pp = *argv++;
	} else {
		pp = getuser(ruid);
	}

	if (pp == NULL) {
		if (per_errno == 2)
			crabort(BADSHELL);
		else
			crabort(INVALIDUSER);
	}
	if (strlcpy(login, pp, sizeof (login)) >= sizeof (login))
		crabort(NAMETOOLONG);
	if (!allowed(login, CRONALLOW, CRONDENY))
		crabort(NOTALLOWED);

	/* Do account validation check */
	pam_error = pam_start("cron", pp, NULL, &pamh);
	if (pam_error != PAM_SUCCESS) {
		crabort((char *)pam_strerror(pamh, pam_error));
	}
	pam_error = pam_acct_mgmt(pamh, PAM_SILENT);
	if (pam_error != PAM_SUCCESS) {
		(void) fprintf(stderr, gettext("Warning - Invalid account: "
		    "'%s' not allowed to execute cronjobs\n"), pp);
	}
	(void) pam_end(pamh, PAM_SUCCESS);


	/* check for unaudited shell */
	if (audit_crontab_not_allowed(ruid, pp))
		crabort(AUDITREJECT);

	cf = xmalloc(strlen(CRONDIR)+strlen(login)+2);
	strcat(strcat(strcpy(cf, CRONDIR), "/"), login);

	if (rflag) {
		r = unlink(cf);
		cron_sendmsg(DELETE, login, login, CRON);
		audit_crontab_delete(cf, r);
		exit(0);
	}
	if (lflag) {
		char sysconf[PATH_MAX];

		if (gflag) {
			if (snprintf(sysconf, sizeof (sysconf), "%s/%s",
			    SYSCRONDIR, login) < sizeof (sysconf) &&
			    (fp = fopen(sysconf, "r")) != NULL) {
				while (fgets(line, CTLINESIZE, fp) != NULL)
					fputs(line, stdout);
				fclose(fp);
				exit(0);
			} else {
				crabort(BADOPEN);
			}
		} else {
			if ((fp = fopen(cf, "r")) == NULL)
				crabort(BADOPEN);
			while (fgets(line, CTLINESIZE, fp) != NULL)
				fputs(line, stdout);
			fclose(fp);
			exit(0);
		}
	}
	if (eflag) {
		if ((fp = fopen(cf, "r")) == NULL) {
			if (errno != ENOENT)
				crabort(BADOPEN);
		}
		(void) strcpy(edtemp, "/tmp/crontabXXXXXX");
		tmpfd = mkstemp(edtemp);
		if (fchown(tmpfd, ruid, -1) == -1) {
			(void) close(tmpfd);
			crabort("fchown of temporary file failed");
		}
		(void) close(tmpfd);
		/*
		 * Fork off a child with user's permissions,
		 * to edit the crontab file
		 */
		if ((pid = fork()) == (pid_t)-1)
			crabort("fork failed");
		if (pid == 0) {		/* child process */
			/* give up super-user privileges. */
			setuid(ruid);
			if ((tmpfp = fopen(edtemp, "w")) == NULL)
				crabort("can't create temporary file");
			if (fp != NULL) {
				/*
				 * Copy user's crontab file to temporary file.
				 */
				while (fgets(line, CTLINESIZE, fp) != NULL) {
					fputs(line, tmpfp);
					if (ferror(tmpfp)) {
						fclose(fp);
						fclose(tmpfp);
						crabort("write error on"
						    "temporary file");
					}
				}
				if (ferror(fp)) {
					fclose(fp);
					fclose(tmpfp);
					crabort(BADREAD);
				}
				fclose(fp);
			}
			if (fclose(tmpfp) == EOF)
				crabort("write error on temporary file");
			if (stat(edtemp, &stbuf) < 0)
				crabort("can't stat temporary file");
			omodtime = stbuf.st_mtime;
#ifdef _XPG_NOTDEFINED
			editor = getenv("VISUAL");
			if (editor == NULL) {
#endif
				editor = getenv("EDITOR");
				if (editor == NULL)
					editor = VIPATH;
#ifdef _XPG_NOTDEFINED
			}
#endif
			buflen = strlen(editor) + strlen(edtemp) + 2;
			buf = xmalloc(buflen);
			(void) snprintf(buf, buflen, "%s %s", editor, edtemp);

			sleep(1);

			while (1) {
				ret = system(buf);

				/* sanity checks */
				if ((tmpfp = fopen(edtemp, "r")) == NULL)
					crabort("can't open temporary file");
				if (fstat(fileno(tmpfp), &stbuf) < 0)
					crabort("can't stat temporary file");
				if (stbuf.st_size == 0)
					crabort("temporary file empty");
				if (omodtime == stbuf.st_mtime) {
					(void) unlink(edtemp);
					fprintf(stderr, gettext(
					    "The crontab file was not"
					    " changed.\n"));
					exit(1);
				}
				if ((ret) && (errno != EINTR)) {
					/*
					 * Some editors (like 'vi') can return
					 * a non-zero exit status even though
					 * everything is okay. Need to check.
					 */
					fprintf(stderr, gettext(ED_ERROR));
					fflush(stderr);
					if (isatty(fileno(stdin))) {
						/* Interactive */
						fprintf(stdout,
						    gettext(ED_PROMPT),
						    yesstr, nostr, nostr);
						fflush(stdout);

						if (yes()) {
							/* Edit again */
							continue;
						} else {
							/* Dump changes */
							(void) unlink(edtemp);
							exit(1);
						}
					} else {
						/*
						 * Non-interactive, dump changes
						 */
						(void) unlink(edtemp);
						exit(1);
					}
				}
				exit(0);
			} /* while (1) */
		}

		/* fix for 1125555 - ignore common signals while waiting */
		(void) signal(SIGINT, SIG_IGN);
		(void) signal(SIGHUP, SIG_IGN);
		(void) signal(SIGQUIT, SIG_IGN);
		(void) signal(SIGTERM, SIG_IGN);
		wait(&stat_loc);
		if ((stat_loc & 0xFF00) != 0)
			exit(1);

		/*
		 * unlink edtemp as 'ruid'. The file contents will be held
		 * since we open the file descriptor 'tmpfp' before calling
		 * unlink.
		 */
		if (((ret = seteuid(ruid)) < 0) ||
		    ((tmpfp = fopen(edtemp, "r")) == NULL) ||
		    (unlink(edtemp) == -1)) {
			fprintf(stderr, "crontab: %s: %s\n",
			    edtemp, errmsg(errno));
			if ((ret < 0) || (tmpfp == NULL))
				(void) unlink(edtemp);
			exit(1);
		} else
			seteuid(0);

		copycron(tmpfp);
	} else {
		if (argc == 0)
			copycron(stdin);
		else if (seteuid(getuid()) != 0 || (fp = fopen(argv[0], "r"))
		    == NULL)
			crabort(BADOPEN);
		else {
			seteuid(0);
			copycron(fp);
		}
	}
	cron_sendmsg(ADD, login, login, CRON);
/*
 *	if (per_errno == 2)
 *		fprintf(stderr, gettext(WARNSHELL));
 */
	return (0);
}

static void
copycron(FILE *fp)
{
	FILE *tfp;
	char pid[6], *tnam_end;
	int t;
	char buf[LINE_MAX];
	cferror_t cferr;

	sprintf(pid, "%-5d", getpid());
	tnam = xmalloc(strlen(CRONDIR)+strlen(TMPFILE)+7);
	strcat(strcat(strcat(strcpy(tnam, CRONDIR), "/"), TMPFILE), pid);
	/* cut trailing blanks */
	tnam_end = strchr(tnam, ' ');
	if (tnam_end != NULL)
		*tnam_end = 0;
	/* catch SIGINT, SIGHUP, SIGQUIT signals */
	if (signal(SIGINT, catch) == SIG_IGN)
		signal(SIGINT, SIG_IGN);
	if (signal(SIGHUP, catch) == SIG_IGN) signal(SIGHUP, SIG_IGN);
	if (signal(SIGQUIT, catch) == SIG_IGN) signal(SIGQUIT, SIG_IGN);
	if (signal(SIGTERM, catch) == SIG_IGN) signal(SIGTERM, SIG_IGN);
	if ((t = creat(tnam, CRMODE)) == -1) crabort(BADCREATE);
	if ((tfp = fdopen(t, "w")) == NULL) {
		unlink(tnam);
		crabort(BADCREATE);
	}
	err = 0;	/* if errors found, err set to 1 */
	while (fgets(line, CTLINESIZE, fp) != NULL) {
		cursor = 0;
		while (line[cursor] == ' ' || line[cursor] == '\t')
			cursor++;
		/* fix for 1039689 - treat blank line like a comment */
		if (line[cursor] == '#' || line[cursor] == '\n')
			goto cont;

		if (strncmp(&line[cursor], ENV_TZ, strlen(ENV_TZ)) == 0) {
			char *x;

			strncpy(buf, &line[cursor + strlen(ENV_TZ)],
			    sizeof (buf));
			if ((x = strchr(buf, '\n')) != NULL)
				*x = '\0';

			if (isvalid_tz(buf, NULL, _VTZ_ALL)) {
				goto cont;
			} else {
				err = 1;
				fprintf(stderr, BAD_TZ, &line[cursor]);
				continue;
			}
		} else if (strncmp(&line[cursor], ENV_SHELL,
		    strlen(ENV_SHELL)) == 0) {
			char *x;

			strncpy(buf, &line[cursor + strlen(ENV_SHELL)],
			    sizeof (buf));
			if ((x = strchr(buf, '\n')) != NULL)
				*x = '\0';

			if (isvalid_shell(buf)) {
				goto cont;
			} else {
				err = 1;
				fprintf(stderr, BAD_SHELL, &line[cursor]);
				continue;
			}
		} else if (strncmp(&line[cursor], ENV_HOME,
		    strlen(ENV_HOME)) == 0) {
			char *x;

			strncpy(buf, &line[cursor + strlen(ENV_HOME)],
			    sizeof (buf));
			if ((x = strchr(buf, '\n')) != NULL)
				*x = '\0';
			if (chdir(buf) == 0) {
				goto cont;
			} else {
				err = 1;
				fprintf(stderr, BAD_HOME, &line[cursor],
				    strerror(errno));
				continue;
			}
		}

		if ((cferr = next_field(0, 59, line, &cursor, NULL)) != CFOK ||
		    (cferr = next_field(0, 23, line, &cursor, NULL)) != CFOK ||
		    (cferr = next_field(1, 31, line, &cursor, NULL)) != CFOK ||
		    (cferr = next_field(1, 12, line, &cursor, NULL)) != CFOK ||
		    (cferr = next_field(0, 6, line, &cursor, NULL)) != CFOK) {
			switch (cferr) {
			case CFEOLN:
				cerror(EOLN);
				break;
			case CFUNEXPECT:
				cerror(UNEXPECT);
				break;
			case CFOUTOFBOUND:
				cerror(OUTOFBOUND);
				break;
			case CFEOVERFLOW:
				cerror(OVERFLOW);
				break;
			case CFENOMEM:
				(void) fprintf(stderr, "Out of memory\n");
				exit(55);
				break;
			default:
				break;
			}
			continue;
		}

		if (line[++cursor] == '\0') {
			cerror(EOLN);
			continue;
		}
cont:
		if (fputs(line, tfp) == EOF) {
			unlink(tnam);
			crabort(BADCREATE);
		}
	}
	fclose(fp);
	fclose(tfp);

	/* audit differences between old and new crontabs */
	audit_crontab_modify(cf, tnam, err);

	if (!err) {
		/* make file tfp the new crontab */
		unlink(cf);
		if (link(tnam, cf) == -1) {
			unlink(tnam);
			crabort(BADCREATE);
		}
	} else {
		crabort(ERRSFND);
	}
	unlink(tnam);
}

static void
cerror(char *msg)
{
	fprintf(stderr, gettext("%scrontab: error on previous line; %s\n"),
	    line, msg);
	err = 1;
}


static void
catch(int x)
{
	unlink(tnam);
	exit(1);
}

static void
crabort(char *msg)
{
	int sverrno;

	if (strcmp(edtemp, "") != 0) {
		sverrno = errno;
		(void) unlink(edtemp);
		errno = sverrno;
	}
	if (tnam != NULL) {
		sverrno = errno;
		(void) unlink(tnam);
		errno = sverrno;
	}
	fprintf(stderr, "crontab: %s\n", gettext(msg));
	exit(1);
}
