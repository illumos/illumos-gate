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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <sac.h>
#include <spawn.h>
#include "misc.h"
#include "structs.h"
#include "adm.h"
#include "extern.h"


/*
 * functions
 */

char	*pflags();
char	*getfield();
void	add_pm();
void	cleandirs();
void	rem_pm();
void	start_pm();
void	kill_pm();
void	enable_pm();
void	disable_pm();
void	list_pms();
void	read_db();
void	sendcmd();
void	checkresp();
void	single_print();
void	catch();
void	usage();
static	int invoke_rm(char *);

# define START		0x1	/* -s seen */
# define KILL		0x2	/* -k seen */
# define ENABLE		0x4	/* -e seen */
# define DISABLE	0x8	/* -d seen */
# define PLIST		0x10	/* -l seen */
# define LIST		0x20	/* -L seen */
# define DBREAD		0x40	/* -x seen */
# define CONFIG		0x80	/* -G seen */
# define PCONFIG	0x100	/* -g seen */
# define ADD		0x200	/* -a or other required options seen */
# define REMOVE		0x400	/* -r seen */

/*
 * common error messages
 */

# define NOTPRIV	"User not privileged for operation"
# define SACERR		"Can not contact SAC"
# define BADINP		"Embedded newlines not allowed"


int	Saferrno;	/* internal `errno' for exit */


/*
 * main - scan args for sacadm and call appropriate handling code
 */

int
main(int argc, char *argv[])
{
	int c;			/* option letter */
	uid_t uid;		/* invoker's real uid */
	int ret;		/* return code from check_version */
	int flag = 0;		/* flag to record requested operations */
	int errflg = 0;		/* error indicator */
	int version = -1;	/* argument to -v */
	int count = 0;		/* argument to -n */
	int badcnt = 0;		/* count of bad args to -f */
	int sawaflag = 0;	/* true if actually saw -a */
	int conflag = 0;	/* true if output should be in condensed form */
	long flags = 0;		/* arguments to -f */
	FILE *fp;		/* scratch file pointer */
	char *pmtag = NULL;	/* argument to -p */
	char *type = NULL;	/* argument to -t */
	char *script = NULL;	/* argument to -z */
	char *command = NULL;	/* argument to -c */
	char *comment = " ";	/* argument to -y */
	char badargs[BADFARGSIZE];	/* place to hold bad args to -f */
	char buf[SIZE];		/* scratch buffer */
	register char *p;	/* scratch pointer */

	if (argc == 1)
		usage(argv[0]);
	while ((c = getopt(argc, argv, "ac:def:GgkLln:p:rst:v:xy:z:")) != -1) {
		switch (c) {
		case 'a':
			flag |= ADD;
			sawaflag = 1;
			break;
		case 'c':
			flag |= ADD;
			if (strchr(optarg, '\n')) {
				Saferrno = E_BADARGS;
				error(BADINP);
			}
			command = optarg;
			if (*command != '/') {
				Saferrno = E_BADARGS;
				error("command must be a full pathname");
			}
			break;
		case 'd':
			flag |= DISABLE;
			break;
		case 'e':
			flag |= ENABLE;
			break;
		case 'f':
			flag |= ADD;
			while (*optarg) {
				switch (*optarg++) {
				case 'd':
					flags |= D_FLAG;
					break;
				case 'x':
					flags |= X_FLAG;
					break;
				default:
					if (badcnt < (BADFARGSIZE -1))
					    badargs[badcnt++] = *(optarg - 1);
					break;
				}
			}
			/* null terminate just in case anything is there */
			badargs[badcnt] = '\0';
			break;
		case 'G':
			flag |= CONFIG;
			break;
		case 'g':
			flag |= PCONFIG;
			break;
		case 'k':
			flag |= KILL;
			break;
		case 'L':
			flag |= LIST;
			break;
		case 'l':
			flag |= PLIST;
			break;
		case 'n':
			flag |= ADD;
			count = atoi(optarg);
			if (count < 0) {
				Saferrno = E_BADARGS;
				error("restart count can not be negative");
			}
			break;
		case 'p':
			pmtag = optarg;
			if (strchr(optarg, '\n')) {
				Saferrno = E_BADARGS;
				error(BADINP);
			}
			if (strlen(pmtag) > PMTAGSIZE) {
				pmtag[PMTAGSIZE] = '\0';
				(void) fprintf(stderr, "tag too long, truncated to <%s>\n", pmtag);
			}
			for (p = pmtag; *p; p++) {
				if (!isalnum(*p)) {
					Saferrno = E_BADARGS;
					error("port monitor tag must be alphanumeric");
				}
			}
			break;
		case 'r':
			flag |= REMOVE;
			break;
		case 's':
			flag |= START;
			break;
		case 't':
			type = optarg;
			if (strchr(optarg, '\n')) {
				Saferrno = E_BADARGS;
				error(BADINP);
			}
			if (strlen(type) > PMTYPESIZE) {
				type[PMTYPESIZE] = '\0';
				(void) fprintf(stderr, "type too long, truncated to <%s>\n", type);
			}
			for (p = type; *p; p++) {
				if (!isalnum(*p)) {
					Saferrno = E_BADARGS;
					error("port monitor type must be alphanumeric");
				}
			}
			break;
		case 'v':
			flag |= ADD;
			version = atoi(optarg);
			if (version < 0) {
				Saferrno = E_BADARGS;
				error("version number can not be negative");
			}
			break;
		case 'x':
			flag |= DBREAD;
			break;
		case 'y':
			flag |= ADD;
			if (strchr(optarg, '\n')) {
				Saferrno = E_BADARGS;
				error(BADINP);
			}
			comment = optarg;
			break;
		case 'z':
			if (strchr(optarg, '\n')) {
				Saferrno = E_BADARGS;
				error(BADINP);
			}
			script = optarg;
			break;
		case '?':
			errflg++;
		}
	}
	if (errflg || (optind < argc))
		usage(argv[0]);

	if (badcnt) {
		/* bad flags were given to -f */
		Saferrno = E_BADARGS;
		(void) sprintf(buf,
		    "Invalid request, %s are not valid arguments for \"-f\"",
			badargs);
		error(buf);
	}

	if ((ret = check_version(VERSION, SACTAB)) == 1) {
		Saferrno = E_SAFERR;
		error("_sactab version number is incorrect");
	}
	else if (ret == 2) {
		(void) sprintf(buf, "could not open %s", SACTAB);
		Saferrno = E_SYSERR;
		error(buf);
	}
	else if (ret == 3) {
		(void) sprintf(buf, "%s file is corrupt", SACTAB);
		Saferrno = E_SAFERR;
		error(buf);
	}
	uid = getuid();
	switch (flag) {
	case ADD:
		if (uid) {
			Saferrno = E_NOPRIV;
			error(NOTPRIV);
		}
		if (!sawaflag || !pmtag || !type || !command || (version < 0))
			usage(argv[0]);
		add_pm(pmtag, type, command, version, flags, count, script, comment);
		break;
	case REMOVE:
		if (uid) {
			Saferrno = E_NOPRIV;
			error(NOTPRIV);
		}
		if (!pmtag || type || script)
			usage(argv[0]);
		rem_pm(pmtag);
		break;
	case START:
		if (uid) {
			Saferrno = E_NOPRIV;
			error(NOTPRIV);
		}
		if (!pmtag || type || script)
			usage(argv[0]);
		start_pm(pmtag);
		break;
	case KILL:
		if (uid) {
			Saferrno = E_NOPRIV;
			error(NOTPRIV);
		}
		if (!pmtag || type || script)
			usage(argv[0]);
		kill_pm(pmtag);
		break;
	case ENABLE:
		if (uid) {
			Saferrno = E_NOPRIV;
			error(NOTPRIV);
		}
		if (!pmtag || type || script)
			usage(argv[0]);
		enable_pm(pmtag);
		break;
	case DISABLE:
		if (uid) {
			Saferrno = E_NOPRIV;
			error(NOTPRIV);
		}
		if (!pmtag || type || script)
			usage(argv[0]);
		disable_pm(pmtag);
		break;
	case LIST:
		conflag = 1;
		/* fall through */
	case PLIST:
		if ((pmtag && type) || script)
			usage(argv[0]);
		list_pms(pmtag, type, conflag);
		break;
	case DBREAD:
		if (uid) {
			Saferrno = E_NOPRIV;
			error(NOTPRIV);
		}
		if (type || script)
			usage(argv[0]);
		read_db(pmtag);
		break;
	case CONFIG:
		if (script && uid) {
			Saferrno = E_NOPRIV;
			error(NOTPRIV);
		}
		if (type || pmtag)
			usage(argv[0]);
		(void) do_config(script, "_sysconfig");
		break;
	case PCONFIG:
		if (script && uid) {
			Saferrno = E_NOPRIV;
			error(NOTPRIV);
		}
		if (!pmtag || type)
			usage(argv[0]);
		fp = fopen(SACTAB, "r");
		if (fp == NULL) {
			Saferrno = E_SYSERR;
			error("Could not open _sactab");
		}
		if (!find_pm(fp, pmtag)) {
			Saferrno = E_NOEXIST;
			(void) sprintf(buf, "Invalid request, %s does not exist", pmtag);
			error(buf);
		}
		(void) fclose(fp);
		(void) sprintf(buf, "%s/_config", pmtag);
		(void) do_config(script, buf);
		break;
	default:
		/* we only get here if more than one flag bit was set */
		usage(argv[0]);
		/* NOTREACHED */
	}
	quit();
	/* NOTREACHED */
	return (0);
}


/*
 * usage - print out a usage message
 *
 *	args:	cmdname - the name command was invoked with
 */

void
usage(cmdname)
char *cmdname;
{
	(void) fprintf(stderr, "Usage:\t%s -a -p pmtag -t type -c cmd -v ver [ -f dx ] [ -n count ]\n", cmdname);
	(void) fprintf(stderr, "\t\t[ -y comment ] [ -z script]\n");
	(void) fprintf(stderr, "\t%s -r -p pmtag\n", cmdname);
	(void) fprintf(stderr, "\t%s -s -p pmtag\n", cmdname);
	(void) fprintf(stderr, "\t%s -k -p pmtag\n", cmdname);
	(void) fprintf(stderr, "\t%s -e -p pmtag\n", cmdname);
	(void) fprintf(stderr, "\t%s -d -p pmtag\n", cmdname);
	(void) fprintf(stderr, "\t%s -l [ -p pmtag | -t type ]\n", cmdname);
	(void) fprintf(stderr, "\t%s -L [ -p pmtag | -t type ]\n", cmdname);
	(void) fprintf(stderr, "\t%s -g -p pmtag [ -z script ]\n", cmdname);
	(void) fprintf(stderr, "\t%s -G [ -z script ]\n", cmdname);
	(void) fprintf(stderr, "\t%s -x [ -p pmtag ]\n", cmdname);
	Saferrno = E_BADARGS;
	quit();
}


/*
 * add_pm - add a port monitor entry
 *
 *	args:	tag - port monitor's tag
 *		type - port monitor's type
 *		command - command string to invoke port monitor
 *		version - version number of port monitor's pmtab
 *		flags - port monitor flags
 *		count - restart count
 *		script - port monitor's configuration script
 *		comment - comment describing port monitor
 */

void
add_pm(tag, type, command, version, flags, count, script, comment)
char *tag;
char *type;
char *command;
int version;
long flags;
int count;
char *script;
char *comment;
{
	FILE *fp;		/* file pointer for _sactab */
	int fd;			/* scratch file descriptor */
	struct stat statbuf;	/* file status info */
	char buf[SIZE];		/* scratch buffer */
	char fname[SIZE];	/* scratch buffer for building names */
	register int i;		/* scratch variable */
	int retval = 0;		/* return value from invoke_rm() function */

	fp = fopen(SACTAB, "r");
	if (fp == NULL) {
		Saferrno = E_SYSERR;
		error("Could not open _sactab");
	}
	if (find_pm(fp, tag)) {
		Saferrno = E_DUP;
		(void) sprintf(buf, "Invalid request, %s already exists", tag);
		error(buf);
	}
	(void) fclose(fp);

/*
 * create the directories for it if needed and put in initial files
 * (/etc/saf and /var/saf)
 */

	for (i = 0; i < 2; i++) {
		/* i == 0 do /etc/saf i == 1 do /var/saf */
		(void) sprintf(fname, "%s/%s", (i == 0 ) ? HOME : ALTHOME, tag);
		if (access(fname, 0) == 0) {
			/* something is there, find out what it is */
			if (stat(fname, &statbuf) < 0) {
				Saferrno = E_SYSERR;
				(void) sprintf(buf, "could not stat <%s>", fname);
				error(buf);
			}
			if ((statbuf.st_mode & S_IFMT) != S_IFDIR) {
				Saferrno = E_SYSERR;
				(void) sprintf(buf, "<%s> exists and is not a directory", fname);
				error(buf);
			}
			/* note: this removes the directory too */
			if ((retval = invoke_rm(fname)) != 0) {
				Saferrno = E_SYSERR;
				if (snprintf(buf, sizeof (buf),
				    "could not remove files under <%s>",
				    fname) >= sizeof (buf)) {
					snprintf(buf, sizeof (buf),
					    "tag too long");
				}
				error(buf);
			}
		}

/*
 * create the directory
 */

		if (mkdir(fname, 0755) < 0) {
			Saferrno = E_SYSERR;
			(void) sprintf(buf, "could not create directory <%s>", fname);
			cleandirs(tag);
			error(buf);
		}
	}

/*
 * put in the config script, if specified
 */

	if (script) {
		(void) sprintf(fname, "%s/_config", tag);
		if (do_config(script, fname)) {
			cleandirs(tag);
			/* do_config put out any messages */
			quit();
		}
	}

/*
 * create the communications pipe, but first make sure that the
 * permissions we specify are what we get
 */

	(void) umask(0);
	(void) sprintf(fname, "%s/%s/_pmpipe", HOME, tag);
	if (mknod(fname, S_IFIFO | 0600, 0) < 0) {
		Saferrno = E_SYSERR;
		cleandirs(tag);
		error("could not create communications pipe");
	}

/*
 * create the _pid file
 */

	(void) sprintf(fname, "%s/%s/_pid", HOME, tag);
	if ((fd = creat(fname, 0644)) < 0) {
		Saferrno = E_SYSERR;
		cleandirs(tag);
		error("could not create _pid file");
	}
	(void) close(fd);

/*
 * create the _pmtab file
 */

	(void) sprintf(fname, "%s/%s/_pmtab", HOME, tag);
	if ((fd = creat(fname, 0644)) < 0) {
		Saferrno = E_SYSERR;
		cleandirs(tag);
		error("could not create _pmtab file");
	}
	(void) sprintf(buf, "%s%d\n", VSTR, version);
	if (write(fd, buf, (unsigned) strlen(buf)) != strlen(buf)) {
		(void) close(fd);
		(void) unlink(fname);
		Saferrno = E_SYSERR;
		cleandirs(tag);
		error("error initializing _pmtab");
	}
	(void) close(fd);

/*
 * isolate the command name, but remember it since strtok() trashes it
 */

	if (strlcpy(buf, command, sizeof (buf)) >= sizeof (buf)) {
		Saferrno = E_SYSERR;
		cleandirs(tag);
		error("command string too long");
	}

	(void) strtok(command, " \t");

/*
 * check out the command - let addition succeed if it doesn't exist (assume
 * it will be added later); fail anything else
 */

	if (access(command, 0) == 0) {
		if (stat(command, &statbuf) < 0) {
			Saferrno = E_SYSERR;
			(void) fprintf(stderr, "Could not stat <%s>\n", command);
			cleandirs(tag);
			quit();
		}
		if (!(statbuf.st_mode & 0111)) {
			Saferrno = E_BADARGS;
			(void) fprintf(stderr, "%s not executable\n", command);
			cleandirs(tag);
			quit();
		}
		if ((statbuf.st_mode & S_IFMT) != S_IFREG) {
			Saferrno = E_BADARGS;
			(void) fprintf(stderr, "%s not a regular file\n", command);
			cleandirs(tag);
			quit();
		}
	}
	else {
		(void) fprintf(stderr, "warning - %s does not exist\n", command);
	}

/*
 * add the line
 */

	fp = fopen(SACTAB, "a");
	if (fp == NULL) {
		Saferrno = E_SYSERR;
		cleandirs(tag);
		error("Could not open _sactab");
	}
	(void) fprintf(fp, "%s:%s:%s:%d:%s\t#%s\n", tag, type,
		(flags ? pflags(flags, FALSE) : ""), count, buf,
		(comment ? comment : ""));
	(void) fclose(fp);


/*
 * tell the SAC to read _sactab if its there (i.e. single user)
 */

	if (sac_home())
		read_db(NULL);
	return;
}


/*
 * cleandirs - remove anything that might have been created (i.e. failed
 *	addition.  Saferrno is set elsewhere; this is strictly an attempt
 *	to clean up what mess we've left, so don't check to see if the
 *	cleanup worked.
 *
 *	args:	tag - tag of port monitor whose trees should be removed
 */

void
cleandirs(tag)
char *tag;
{
	char buf[SIZE];		/* scratch buffer */

	/* note: this removes the directory too, first zap /etc/saf/<tag> */
	if (snprintf(buf, sizeof (buf), "%s/%s", HOME, tag) >= sizeof (buf))
		(void) fprintf(stderr, "tag too long\n");
	else
		(void) invoke_rm(buf);

	/* now remove /var/saf/<tag> */
	if (snprintf(buf, sizeof (buf), "%s/%s", ALTHOME, tag) >= sizeof (buf))
		(void) fprintf(stderr, "tag too long\n");
	else
		(void) rmdir(buf);
}


/*
 * rem_pm - remove a port monitor
 *
 *	args:	tag - tag of port monitor to be removed
 */

void
rem_pm(tag)
char *tag;
{
	FILE *fp;		/* file pointer for _sactab */
	FILE *tfp;		/* file pointer for temp file */
	int line;		/* line number entry is on */
	char *tname;		/* temp file name */
	char buf[SIZE];		/* scratch buffer */

	fp = fopen(SACTAB, "r");
	if (fp == NULL) {
		Saferrno = E_SYSERR;
		error("Could not open _sactab");
	}
	if ((line = find_pm(fp, tag)) == 0) {
		Saferrno = E_NOEXIST;
		(void) sprintf(buf, "Invalid request, %s does not exist", tag);
		error(buf);
	}
	tname = make_tempname("_sactab");
	tfp = open_temp(tname);
	if (line != 1) {
		if (copy_file(fp, tfp, 1, line - 1)) {
			(void) unlink(tname);
			Saferrno = E_SYSERR;
			error("error accessing temp file");
		}
	}
	if (copy_file(fp, tfp, line + 1, -1)) {
		(void) unlink(tname);
		Saferrno = E_SYSERR;
		error("error accessing temp file");
	}
	(void) fclose(fp);
	if (fclose(tfp) == EOF) {
		(void) unlink(tname);
		Saferrno = E_SYSERR;
		error("error closing tempfile");
	}
	/* note - replace only returns if successful */
	replace("_sactab", tname);

/*
 * tell the SAC to read _sactab if its there (i.e. single user)
 */

	if (sac_home())
		read_db(NULL);
	return;
}


/*
 * start_pm - start a particular port monitor
 *
 *	args:	tag - tag of port monitor to be started
 */

void
start_pm(tag)
char *tag;
{
	struct admcmd cmd;			/* command structure */
	register struct admcmd *ap = &cmd;	/* and a pointer to it */

	ap->ac_mtype = AC_START;
	(void) strcpy(ap->ac_tag, tag);
	ap->ac_pid = getpid();
	sendcmd(ap, NULL, tag);
	return;
}


/*
 * kill_pm - stop a particular port monitor
 *
 *	args:	tag - tag of port monitor to be stopped
 */

void
kill_pm(tag)
char *tag;
{
	struct admcmd cmd;			/* command structure */
	register struct admcmd *ap = &cmd;	/* and a pointer to it */

	ap->ac_mtype = AC_KILL;
	(void) strcpy(ap->ac_tag, tag);
	ap->ac_pid = getpid();
	sendcmd(ap, NULL, tag);
	return;
}


/*
 * enable_pm - enable a particular port monitor
 *
 *	args:	tag - tag of port monitor to be enabled
 */

void
enable_pm(tag)
char *tag;
{
	struct admcmd cmd;			/* command structure */
	register struct admcmd *ap = &cmd;	/* and a pointer to it */

	ap->ac_mtype = AC_ENABLE;
	(void) strcpy(ap->ac_tag, tag);
	ap->ac_pid = getpid();
	sendcmd(ap, NULL, tag);
	return;
}


/*
 * disable_pm - disable a particular port monitor
 *
 *	args:	tag - tag of port monitor to be disabled
 */

void
disable_pm(tag)
char *tag;
{
	struct admcmd cmd;			/* command structure */
	register struct admcmd *ap = &cmd;	/* and a pointer to it */

	ap->ac_mtype = AC_DISABLE;
	(void) strcpy(ap->ac_tag, tag);
	ap->ac_pid = getpid();
	sendcmd(ap, NULL, tag);
	return;
}


/*
 * read_db - tell SAC or a port monitor to read its administrative file.
 *
 *	args:	tag - tag of port monitor that should read its administrative
 *		      file.  If NULL, it means SAC should.
 */

void
read_db(tag)
char *tag;
{
	struct admcmd cmd;			/* command structure */
	register struct admcmd *ap = &cmd;	/* and a pointer to it */

	ap->ac_mtype = (tag) ? AC_PMREAD : AC_SACREAD;
	if (tag)
		(void) strcpy(ap->ac_tag, tag);
	ap->ac_pid = getpid();
	sendcmd(ap, NULL, tag);
	return;
}


/*
 * list_pms - request information about port monitors from SAC and output
 *		requested info
 *
 *	args:	pmtag - tag of port monitor to be listed (may be null)
 *		pmtype - type of port monitors to be listed (may be null)
 *		oflag - true if output should be easily parseable
 */

void
list_pms(pmtag, pmtype, oflag)
char *pmtag;
char *pmtype;
int oflag;
{
	struct admcmd acmd;			/* command structure */
	register struct admcmd *ap = &acmd;	/* and a pointer to it */
	int nprint = 0;				/* count # of PMs printed */
	char *p;				/* scratch pointer */
	char *tag;				/* returned tag */
	char *type;				/* returned type */
	char *flags;				/* returned flags */
	char *rsmax;				/* returned restart count */
	char *state;				/* returned state */
	char *cmd;				/* returned command string */
	char *comment;				/* returned comment string */

/*
 * if sac isn't there (single user), provide info direct from _sactab
 * note: when this routine returns, the process exits, so there is no
 * need to free up any memory
 */

	p = NULL;
	if (sac_home()) {
		ap->ac_mtype = AC_STATUS;
		ap->ac_tag[0] = '\0';
		ap->ac_pid = getpid();
		sendcmd(ap, &p, NULL);
	}
	else {
		single_print(&p);
	}

/*
 * SAC sends back info in condensed form, we have to separate it out
 * fields come in ':' separated, records are separated by newlines
 */

	while (p && *p) {
		tag = getfield(&p, ':');	/* PM tag */
		type = getfield(&p, ':');	/* PM type */
		flags = getfield(&p, ':');	/* flags */
		rsmax = getfield(&p, ':');	/* restart count */
		state = pstate((unchar) atoi(getfield(&p, ':')));	/* state in nice output format */
		cmd = getfield(&p, ':');	/* command */
		comment = getfield(&p, '\n');	/* comment */


/*
 * print out if no selectors specified, else check to see if
 * a selector matched
 */

		if ((!pmtag && !pmtype) || (pmtag && !strcmp(pmtag, tag)) || (pmtype && !strcmp(pmtype, type))) {
			if (oflag) {
				(void) printf("%s:%s:%s:%s:%s:%s#%s\n", tag, type, pflags(atol(flags), FALSE),
						rsmax, state, cmd, comment);
			}
			else {
				if (nprint == 0) {
					(void) printf("PMTAG          PMTYPE         FLGS RCNT STATUS     COMMAND\n");
				}
				(void) printf("%-14s %-14s %-4s %-4s %-10s %s #%s\n", tag, type, pflags(atol(flags), TRUE),
						rsmax, state, cmd, comment);
			}
			nprint++;
		}
	}
	/*
	 * if we didn't find any valid ones, indicate an error (note: 1 and
	 * only 1 of the if statements should be true)
	 */
	if (nprint == 0) {
		if (pmtype)
			(void) fprintf(stderr, "Invalid request, %s does not exist\n", pmtype);
		else if (pmtag)
			(void) fprintf(stderr, "Invalid request, %s does not exist\n", pmtag);
		else if (!pmtag && !pmtype)
			(void) fprintf(stderr, "No port monitors defined\n");
		Saferrno = E_NOEXIST;
	}
	return;
}


/*
 * getfield - retrieve and return a field from the sac "status" string (input
 *	argument is modified to point to next field as a side-effect)
 *
 *	args:	p - address of remaining portion of string
 *		sepchar - field terminator character
 */

char *
getfield(p, sepchar)
char **p;
char sepchar;
{
	char *savep;	/* for saving argument */

	savep = *p;
	*p = strchr(*p, sepchar);
	if (*p == NULL) {
		Saferrno = E_SAFERR;
		(void) fprintf(stderr, "Improper message from SAC\n");
		return(NULL);
	}
	**p = '\0';
	(*p)++;
	return(savep);
}


/*
 * single_print - print out _sactab if sac not at home (should only happen
 *	in single user mode
 *
 *	args:	p - address of pointer where formatted data should be
 *		    placed (space allocated here)
 */

void
single_print(p)
char **p;
{
	FILE *fp;				/* file pointer for _sactab */
	struct stat statbuf;			/* file status info */
	register char *tp1;			/* scratch pointer */
	register char *tp2;			/* scratch pointer */
	struct sactab stab;			/* place to hold parsed info */
	register struct sactab *sp = &stab;	/* and a pointer to it */
	char buf[SIZE];				/* scratch buffer */

	fp = fopen(SACTAB, "r");
	if (fp == NULL) {
		Saferrno = E_SYSERR;
		error("Could not open _sactab");
	}
	if (fstat(fileno(fp), &statbuf) < 0) {
		Saferrno = E_SYSERR;
		error("could not stat _sactab");
	}

/*
 * allocate space to build return string, twice file size should be more
 * than enough (and make sure it's zero'ed out)
 */

	tp1 = calloc(2 * statbuf.st_size, sizeof(char));
	if (tp1 == NULL) {
		Saferrno = E_SYSERR;
		error("could not allocate storage");
	}

/*
 * read the file and build the string
 */

	while (fgets(buf, SIZE, fp)) {
		tp2 = trim(buf);
		if (*tp2 == '\0')
			continue;
		parse(tp2, &stab);
		(void) sprintf(buf, "%s:%s:%d:%d:%d:%s:%s\n", sp->sc_tag, sp->sc_type,
			sp->sc_flags, sp->sc_rsmax, SSTATE, sp->sc_cmd, sp->sc_comment);
		(void) strcat(tp1, buf);
		free(sp->sc_cmd);
		free(sp->sc_comment);
	}
	if (!feof(fp)) {
		Saferrno = E_SYSERR;
		error("error reading _sactab");
	}
	(void) fclose(fp);

/*
 * point at the just-built string
 */

	*p = tp1;
	return;
}


/*
 * openpipe - open up command pipe to SAC
 */

int
openpipe()
{
	int fd;		/* file descriptor associated with command pipe */

	fd = open(CMDPIPE, O_RDWR);
	if (fd < 0) {
		Saferrno = E_SYSERR;
		error(SACERR);
	}

/*
 * lock pipe to insure serial access, lock will disappear if process dies
 */

	if (lockf(fd, F_LOCK, 0) < 0) {
		Saferrno = E_SYSERR;
		error("unable to lock command pipe");
	}
	return(fd);
}


/*
 * sendcmd - send a command to the SAC
 *
 *	args:	ap - pointer to command to send
 *		info - pointer to return information from the SAC
 *		tag - tag of port monitor to which the command applies (may
 *		      be NULL)
 */

void
sendcmd(ap, info, tag)
struct admcmd *ap;
char **info;
char *tag;
{
	int fd;		/* file descriptor of command pipe */

	fd = openpipe();
	if (write(fd, ap, sizeof(struct admcmd)) < 0) {
		Saferrno = E_SYSERR;
		error(SACERR);
	}
	checkresp(fd, info, tag);

/*
 * unlock the command pipe - not really necessary since we're about to close
 */

	(void) lockf(fd, F_ULOCK, 0);
	(void) close(fd);
	return;
}


/*
 * checkresp - check the SAC's response to our command
 *
 *	args:	fd - file descriptor of command pipe
 *		info - pointer to return and info send along by SAC
 *		tag - tag of port monitor that the command had been
 *		      for, only used for error reporting
 */

void
checkresp(fd, info, tag)
int fd;
char **info;
char *tag;
{
	struct admack ack;			/* acknowledgment struct */
	register struct admack *ak = &ack;	/* and a pointer to it */
	pid_t pid;				/* my pid */
	struct sigaction sigact;		/* signal handler setup */

/*
 * make sure this ack is meant for me, put an alarm around the read
 * so we don't hang out forever.
 */

	pid = getpid();
	sigact.sa_flags = 0;
	sigact.sa_handler = catch;
	(void) sigemptyset(&sigact.sa_mask);
	(void) sigaddset(&sigact.sa_mask, SIGALRM);
	(void) sigaction(SIGALRM, &sigact, NULL);
	(void) alarm(10);
	do {
		if (read(fd, ak, sizeof(ack)) != sizeof(ack)) {
			Saferrno = E_SACNOTRUN;
			error(SACERR);
		}
	} while (pid != ak->ak_pid);
	(void) alarm(0);

/*
 * check out what happened
 */

	switch (ak->ak_resp) {
	case AK_ACK:
		/* everything was A-OK */
		if (info && ak->ak_size) {
			/* there is return info and a place to put it */
			if ((*info = malloc((unsigned) (ak->ak_size + 1))) == NULL) {
				Saferrno = E_SYSERR;
				error("could not allocate storage");
			}
			if (read(fd, *info, (unsigned) ak->ak_size) != ak->ak_size) {
				Saferrno = E_SYSERR;
				error(SACERR);
			}
			/* make sure "string" is null-terminated */
			(*info)[ak->ak_size] = '\0';
		}
		return;
	/* something went wrong - see what */
	case AK_PMRUN:
		Saferrno = E_PMRUN;
		(void) fprintf(stderr, "Port monitor, %s, is already running\n", tag);
		break;
	case AK_PMNOTRUN:
		Saferrno = E_PMNOTRUN;
		(void) fprintf(stderr, "Port monitor, %s, is not running\n", tag);
		break;
	case AK_NOPM:
		Saferrno = E_NOEXIST;
		(void) fprintf(stderr, "Invalid request, %s does not exist\n", tag);
		break;
	case AK_UNKNOWN:
		Saferrno = E_SAFERR;
		(void) fprintf(stderr, "Internal error - sent invalid command\n");
		break;
	case AK_NOCONTACT:
		Saferrno = E_SAFERR;
		(void) fprintf(stderr, "Could not contact %s\n", tag);
		break;
	case AK_PMLOCK:
		Saferrno = E_SAFERR;
		(void) fprintf(stderr, "Could not start %s - _pid file locked\n", tag);
		break;
	case AK_RECOVER:
		Saferrno = E_RECOVER;
		(void) fprintf(stderr, "Port monitor, %s, is in recovery\n", tag);
		break;
	case AK_REQFAIL:
		Saferrno = E_SAFERR;
		(void) fprintf(stderr, "This request could not be completed - see sac log file for details\n");
		break;
	default:
		Saferrno = E_SAFERR;
		(void) fprintf(stderr, "unknown response\n");
		break;
	}
}


/*
 * catch - catcher for SIGALRM, don't need to do anything
 */

void
catch()
{
}


/*
 * pflags - put port monitor flags into intelligible form for output
 *
 *	args:	flags - binary representation of flags
 *		dflag - true if a "-" should be returned if no flags
 */

char *
pflags(flags, dflag)
long flags;
int dflag;
{
	register int i;			/* scratch counter */
	static char buf[SIZE];		/* formatted flags */

	if (flags == 0) {
		if (dflag)
			return("-");
		else
			return("");
	}
	i = 0;
	if (flags & D_FLAG) {
		buf[i++] = 'd';
		flags &= ~D_FLAG;
	}
	if (flags & X_FLAG) {
		buf[i++] = 'x';
		flags &= ~X_FLAG;
	}
	if (flags) {
		(void) fprintf(stderr, "Bad information from SAC\n");
		exit(1);
	}
	buf[i] = '\0';
	return(buf);
}


/*
 * sac_home - returns true is sac has a lock on its logfile, false
 *	otherwise (useful to avoid errors for administrative actions in
 *	single user mode)
 */

int
sac_home()
{
	int fd;		/* fd to sac logfile */

	fd = open(LOGFILE, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "warning - could not ascertain sac status\n");
		return(FALSE);
	}
	if (lockf(fd, F_TEST, 0) < 0) {
		/* everything is ok */
		(void) close(fd);
		return(TRUE);
	}
	else {
		/* no one home */
		(void) close(fd);
		return(FALSE);
	}
}

/*
 * invoke_rm - deletes the argument directory and all its files/subdirectories
 */
static int
invoke_rm(char *fname)
{
	pid_t cpid;		/* process ID of the child process */
	int cstatus;		/* status of child process */
	char *argvec[4];

	argvec[0] = "rm";
	argvec[1] = "-rf";
	argvec[2] = fname;
	argvec[3] = NULL;

	if (posix_spawn(&cpid, "/usr/bin/rm", NULL, NULL,
	    (char *const *)argvec, NULL))
		return (-1);
	if (waitpid(cpid, &cstatus, 0) == -1)
		return (-1);

	return ((WIFEXITED(cstatus) == 0) ? 99 : WEXITSTATUS(cstatus));
}
