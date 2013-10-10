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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/



/*
 * Copyright 1988-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2012 Joyent, Inc. All rights reserved.
 *
 * Copyright (c) 2013 Gary Mills
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <grp.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <utmpx.h>
#include <sys/utsname.h>
#include <dirent.h>
#include <pwd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <locale.h>
#include <syslog.h>
#include <sys/wait.h>
#include <limits.h>
#include <libzonecfg.h>
#include <zone.h>
#include <sys/contract/process.h>
#include <libcontract.h>
#include <sys/ctfs.h>

/*
 * Use the full lengths from utmpx for user and line.
 */
#define	NMAX	(sizeof (((struct utmpx *)0)->ut_user))
#define	LMAX	(sizeof (((struct utmpx *)0)->ut_line))

static char	mesg[3000];
static char	*infile;
static int	gflag;
static struct	group *pgrp;
static char	*grpname;
static char	line[MAXNAMLEN+1] = "???";
static char	systm[MAXNAMLEN+1];
static time_t	tloc;
static struct	utsname utsn;
static char	who[NMAX+1]	= "???";
static char	time_buf[50];
#define	DATE_FMT	"%a %b %e %H:%M:%S"

static void sendmes(struct utmpx *, zoneid_t);
static void sendmes_tozone(zoneid_t, int);
static int chkgrp(char *);
static char *copy_str_till(char *, char *, char, int);

static int init_template(void);
int contract_abandon_id(ctid_t);

int
main(int argc, char *argv[])
{
	FILE	*f;
	char	*ptr, *start;
	struct	passwd *pwd;
	char	*term_name;
	int	c;
	int	aflag = 0;
	int	errflg = 0;
	int zflg = 0;
	int Zflg = 0;

	char *zonename = NULL;
	zoneid_t *zoneidlist = NULL;
	uint_t nzids_saved, nzids = 0;

	(void) setlocale(LC_ALL, "");

	while ((c = getopt(argc, argv, "g:az:Z")) != EOF)
		switch (c) {
		case 'a':
			aflag++;
			break;
		case 'g':
			if (gflag) {
				(void) fprintf(stderr,
				    "Only one group allowed\n");
				return (1);
			}
			if ((pgrp = getgrnam(grpname = optarg)) == NULL) {
				(void) fprintf(stderr, "Unknown group %s\n",
				    grpname);
				return (1);
			}
			gflag++;
			break;
		case 'z':
			zflg++;
			zonename = optarg;
			if (getzoneidbyname(zonename) == -1) {
				(void) fprintf(stderr, "Specified zone %s "
				    "is invalid", zonename);
				return (1);
			}
			break;
		case 'Z':
			Zflg++;
			break;
		case '?':
			errflg++;
			break;
		}

	if (errflg) {
		(void) fprintf(stderr,
		    "Usage: wall [-a] [-g group] [-z zone] [-Z] [files...]\n");
		return (1);
	}

	if (zflg && Zflg) {
		(void) fprintf(stderr, "Cannot use -z with -Z\n");
		return (1);
	}

	if (optind < argc)
		infile = argv[optind];

	if (uname(&utsn) == -1) {
		(void) fprintf(stderr, "wall: uname() failed, %s\n",
		    strerror(errno));
		return (2);
	}
	(void) strcpy(systm, utsn.nodename);

	/*
	 * Get the name of the terminal wall is running from.
	 */

	if ((term_name = ttyname(fileno(stderr))) != NULL) {
		/*
		 * skip the leading "/dev/" in term_name
		 */
		(void) strncpy(line, &term_name[5], sizeof (line) - 1);
	}

	if (who[0] == '?') {
		if (pwd = getpwuid(getuid()))
			(void) strncpy(&who[0], pwd->pw_name, sizeof (who));
	}

	f = stdin;
	if (infile) {
		f = fopen(infile, "r");
		if (f == NULL) {
			(void) fprintf(stderr, "Cannot open %s\n", infile);
			return (1);
		}
	}

	start = &mesg[0];
	ptr = start;
	while ((ptr - start) < 3000) {
		size_t n;

		if (fgets(ptr, &mesg[sizeof (mesg)] - ptr, f) == NULL)
			break;
		if ((n = strlen(ptr)) == 0)
			break;
		ptr += n;
	}
	(void) fclose(f);

	/*
	 * If the request is from the rwall daemon then use the caller's
	 * name and host.  We determine this if all of the following is true:
	 *	1) First 5 characters are "From "
	 *	2) Next non-white characters are of the form "name@host:"
	 */
	if (strcmp(line, "???") == 0) {
		char rwho[MAXNAMLEN+1];
		char rsystm[MAXNAMLEN+1];
		char *cp;

		if (strncmp(mesg, "From ", 5) == 0) {
			cp = &mesg[5];
			cp = copy_str_till(rwho, cp, '@', MAXNAMLEN + 1);
			if (rwho[0] != '\0') {
				cp = copy_str_till(rsystm, ++cp, ':',
				    MAXNAMLEN + 1);
				if (rsystm[0] != '\0') {
					(void) strcpy(systm, rsystm);
					(void) strncpy(rwho, who,
					    sizeof (who));
					(void) strcpy(line, "rpc.rwalld");
				}
			}
		}
	}
	(void) time(&tloc);
	(void) strftime(time_buf, sizeof (time_buf),
	    DATE_FMT, localtime(&tloc));

	if (zflg != 0) {
		if ((zoneidlist =
		    malloc(sizeof (zoneid_t))) == NULL ||
		    (*zoneidlist = getzoneidbyname(zonename)) == -1)
			return (errno);
		nzids = 1;
	} else if (Zflg != 0) {
		if (zone_list(NULL, &nzids) != 0)
			return (errno);
again:
		nzids *= 2;
		if ((zoneidlist = malloc(nzids * sizeof (zoneid_t))) == NULL)
			exit(errno);
		nzids_saved = nzids;
		if (zone_list(zoneidlist, &nzids) != 0) {
			(void) free(zoneidlist);
			return (errno);
		}
		if (nzids > nzids_saved) {
			free(zoneidlist);
			goto again;
		}
	}
	if (zflg || Zflg) {
		for (; nzids > 0; --nzids)
			sendmes_tozone(zoneidlist[nzids-1], aflag);
		free(zoneidlist);
	} else
		sendmes_tozone(getzoneid(), aflag);

	return (0);
}

/*
 * Copy src to destination upto but not including the delim.
 * Leave dst empty if delim not found or whitespace encountered.
 * Return pointer to next character (delim, whitespace, or '\0')
 */
static char *
copy_str_till(char *dst, char *src, char delim, int len)
{
	int i = 0;

	while (*src != '\0' && i < len) {
		if (isspace(*src)) {
			dst[0] = '\0';
			return (src);
		}
		if (*src == delim) {
			dst[i] = '\0';
			return (src);
		}
		dst[i++] = *src++;
	}
	dst[0] = '\0';
	return (src);
}

static void
sendmes_tozone(zoneid_t zid, int aflag) {
	int i = 0;
	char zonename[ZONENAME_MAX], root[MAXPATHLEN];
	struct utmpx *p;

	if (zid != getzoneid()) {
		root[0] = '\0';
		(void) getzonenamebyid(zid, zonename, ZONENAME_MAX);
		(void) zone_get_rootpath(zonename, root, sizeof (root));
		(void) strlcat(root, UTMPX_FILE, sizeof (root));
		if (!utmpxname(root)) {
			(void) fprintf(stderr, "Cannot open %s\n", root);
			return;
		}
	} else {
		(void) utmpxname(UTMPX_FILE);
	}
	setutxent();
	while ((p = getutxent()) != NULL) {
		if (p->ut_type != USER_PROCESS)
			continue;
		/*
		 * if (-a option OR NOT pty window login), send the message
		 */
		if (aflag || !nonuser(*p))
			sendmes(p, zid);
	}
	endutxent();

	(void) alarm(60);
	do {
		i = (int)wait((int *)0);
	} while (i != -1 || errno != ECHILD);

}

/*
 * Note to future maintainers: with the change of wall to use the
 * getutxent() API, the forked children (created by this function)
 * must call _exit as opposed to exit. This is necessary to avoid
 * unwanted fflushing of getutxent's stdio stream (caused by atexit
 * processing).
 */
static void
sendmes(struct utmpx *p, zoneid_t zid)
{
	int i;
	char *s;
	static char device[LMAX + 6];
	char *bp;
	int ibp;
	FILE *f;
	int fd, tmpl_fd;
	boolean_t zoneenter = B_FALSE;

	if (zid != getzoneid()) {
		zoneenter = B_TRUE;
		tmpl_fd = init_template();
		if (tmpl_fd == -1) {
			(void) fprintf(stderr, "Could not initialize "
			    "process contract");
			return;
		}
	}

	while ((i = (int)fork()) == -1) {
		(void) alarm(60);
		(void) wait((int *)0);
		(void) alarm(0);
	}

	if (i)
		return;

	if (zoneenter && zone_enter(zid) == -1) {
		char zonename[ZONENAME_MAX];
		(void) getzonenamebyid(zid, zonename, ZONENAME_MAX);
		(void) fprintf(stderr, "Could not enter zone "
		    "%s\n", zonename);
	}
	if (zoneenter)
		(void) ct_tmpl_clear(tmpl_fd);

	if (gflag)
		if (!chkgrp(p->ut_user))
			_exit(0);

	(void) signal(SIGHUP, SIG_IGN);
	(void) alarm(60);
	s = &device[0];
	(void) snprintf(s, sizeof (device), "/dev/%.*s", LMAX, p->ut_line);

	/* check if the device is really a tty */
	if ((fd = open(s, O_WRONLY|O_NOCTTY|O_NONBLOCK)) == -1) {
		(void) fprintf(stderr, "Cannot send to %.*s on %s\n",
		    NMAX, p->ut_user, s);
		perror("open");
		(void) fflush(stderr);
		_exit(1);
	} else {
		if (!isatty(fd)) {
			(void) fprintf(stderr,
			    "Cannot send to device %.*s %s\n",
			    LMAX, p->ut_line,
			    "because it's not a tty");
			openlog("wall", 0, LOG_AUTH);
			syslog(LOG_CRIT, "%.*s in utmpx is not a tty\n",
			    LMAX, p->ut_line);
			closelog();
			(void) fflush(stderr);
			_exit(1);
		}
	}
#ifdef DEBUG
	(void) close(fd);
	f = fopen("wall.debug", "a");
#else
	f = fdopen(fd, "w");
#endif
	if (f == NULL) {
		(void) fprintf(stderr, "Cannot send to %-.*s on %s\n",
		    NMAX, &p->ut_user[0], s);
		perror("open");
		(void) fflush(stderr);
		_exit(1);
	}
	(void) fprintf(f,
	    "\07\07\07Broadcast Message from %s (%s) on %s %19.19s",
	    who, line, systm, time_buf);
	if (gflag)
		(void) fprintf(f, " to group %s", grpname);
	(void) fprintf(f, "...\n");
#ifdef DEBUG
	(void) fprintf(f, "DEBUG: To %.*s on %s\n", NMAX, p->ut_user, s);
#endif
	i = strlen(mesg);
	for (bp = mesg; --i >= 0; bp++) {
		ibp = (unsigned int)((unsigned char) *bp);
		if (*bp == '\n')
			(void) putc('\r', f);
		if (isprint(ibp) || *bp == '\r' || *bp == '\013' ||
		    *bp == ' ' || *bp == '\t' || *bp == '\n' || *bp == '\007') {
			(void) putc(*bp, f);
		} else {
			if (!isascii(*bp)) {
				(void) fputs("M-", f);
				*bp = toascii(*bp);
			}
			if (iscntrl(*bp)) {
				(void) putc('^', f);
				(void) putc(*bp + 0100, f);
			}
			else
				(void) putc(*bp, f);
		}

		if (*bp == '\n')
			(void) fflush(f);

		if (ferror(f) || feof(f)) {
			(void) printf("\n\007Write failed\n");
			(void) fflush(stdout);
			_exit(1);
		}
	}
	(void) fclose(f);
	(void) close(fd);
	_exit(0);
}


static int
chkgrp(char *name)
{
	int i;
	char user[NMAX + 1];

	(void) strlcpy(user, name, sizeof (user));
	for (i = 0; pgrp->gr_mem[i] && pgrp->gr_mem[i][0]; i++) {
		if (strcmp(user, pgrp->gr_mem[i]) == 0)
			return (1);
	}

	return (0);
}

static int
init_template(void) {
	int fd = 0;
	int err = 0;

	fd = open64(CTFS_ROOT "/process/template", O_RDWR);
	if (fd == -1)
		return (-1);

	err |= ct_tmpl_set_critical(fd, 0);
	err |= ct_tmpl_set_informative(fd, 0);
	err |= ct_pr_tmpl_set_fatal(fd, CT_PR_EV_HWERR);
	err |= ct_pr_tmpl_set_param(fd, CT_PR_PGRPONLY | CT_PR_REGENT);
	if (err || ct_tmpl_activate(fd)) {
		(void) close(fd);
		return (-1);
	}

	return (fd);
}
