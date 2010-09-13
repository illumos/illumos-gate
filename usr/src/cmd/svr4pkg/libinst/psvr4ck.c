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

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/utsname.h>
#include <locale.h>
#include <libintl.h>
#include <pkglib.h>
#include <libinst.h>
#include <libadm.h>

#ifdef	MAILCMD
#undef  MAILCMD
#define	MAILCMD		"/bin/mail"
#endif	/* MAILCMD */
#define	ERR_MAIL	"unable to send electronic mail notification"
#define	ERR_OVERWRITE	"unable to determine overwrite list"
#define	ERR_PIPE	"unable to open pipe to process <%s>"
#define	ASK_CONT	"Do you want to continue processing this package"
#define	MSG_CONFLICT	"The following files are currently being used by " \
			"other packages on the system, and may be " \
			"overwritten by the installation of this pre-SVR4 " \
			"package:"
#define	HLP_CONFLICT	"If you choose to continue installation, it is " \
			"possible that you will overwrite files which are " \
			"part of another package that is already installed " \
			"on the system.  If you want to assure that the " \
			"files are not overwritten, answer 'n' to stop the " \
			"installation process."
#define	MSG_NOTVER	"The media being processed is in an old (pre-SVR4) " \
			"format and it is not possible to verify that the " \
			"inserted media belongs to the <%s> package."
#define	HLP_NOTVER	"If you choose to continue installation, it is " \
			"possible that you will install the wrong package.  " \
			"If you are sure the media being installed contains " \
			"the package you wish to install, answer 'y' to " \
			"continue the installation process."
#define	MSG_CONFIRM	"The media being processed is in an old (pre-SVR4) " \
			"format and appears to be part of the <%s> package."
#define	HLP_CONFIRM	"The installation of older-style (pre-SVR4) packages " \
			"is, in general, not as robust as installing " \
			"standard packages.  Older packages may attempt " \
			"things during installation which overwrite existing " \
			"files or otherwise modify the system without your " \
			"approval.  If you wish to allow installation of " \
			"identified pre-SVR4 package, answer 'y' to continue " \
			"the installation process."

static char	*Rlist[] = {
	"/install/install/Rlist",
	"/install/install/RLIST",
	"/install/install/rlist",
	NULL
};

static char	ckcmd[] = "/usr/sbin/pkgchk -L -i %s";

/*
 * Remove the list & both #defines below for on1095 -- JST
 * Further, please note :
 * This is NOT a database (Oh, yeah it looks like it, but it isn't). For that
 * reason these are in alphabetical order. Any additions must maintain this
 * order and must not increase the list length beyond 120.
 */
#define	TREEHEIGHT	7
#define	TREEFILL	4	/* number of fill entries per side */

#ifdef	ALLOW_EXCEPTION_PKG_LIST
static char *x_pkg[] =
{
	"AAAA1",	/* fill to avoid constraint tests in loop */
	"AAAA2",
	"AAAA3",
	"AAAA4",
	/* '+' means packages known to be non-compliant */
	"SPROcpl",	/* + bugID 1133962 */
	"SPROlklnt",	/* + SW Lock_Lint */
	"SPROltool",	/* + SW Loop Profiling Tools */
	"SPROssbd",	/* + SW ssbd component for SC 3.0 */
	"SPROtha",	/* + Performance Analzyer */
	"SUNW3270c",	/* + SunLink Client 3270 */
	"SUNW3270g",	/* SunLink CG3270 8.0 */
	"SUNW3270t",	/* + SunLink TN3270*Server */
	"SUNW86nma",	/* SunNet Manager Core Tools for x86 */
	"SUNW86nmc",	/* SunNet Manager Agents & Libraries for x86 */
	"SUNW86nmp",	/* SunNet Manager SNMP daemon for x86 */
	"SUNWabcg",	/* SunLink CG320 8.0 User's Guide */
	"SUNWbf",	/* + 2.0 FDDI/S Beta */
	"SUNWbsccu",	/* SunLink BSC Core Util */
	"SUNWbscdr",	/* SunLink BSC Drivers */
	"SUNWcosiA",	/* OSI Core Stack Kernel Files 1 */
	"SUNWcosiC",	/* Stack Mgmnt Utilities 2 */
	"SUNWcosia",	/* + OSI Core Stack Kernel Files */
	"SUNWcosib",	/* OSI Core Stack Configuration Files */
	"SUNWcosic",	/* OSI Core Stack Utilities */
	"SUNWcosid",	/* OSI Core Stack Development Kit (new pakage) */
	"SUNWcosij",	/* OSI Core Stack User Space Utilities */
	"SUNWdniCU",	/* + SunLink DNI Core Utilities 8.0 */
	"SUNWdniKR",	/* + SunLink DNI Kernel 8.0 */
	"SUNWdniMA",	/* SunLink DNI Mail Agent 8.0 */
	"SUNWflex",	/* + FLEX LM DEVEL PKG */
	"SUNWftama",	/* OSI FTAM Configuration Files */
	"SUNWftamb",	/* OSI FTAM Executable, Libraries and Man Pages */
	"SUNWhsis",	/* SunConnect HSI/S */
	"SUNWjaCL",	/* + Frances Ho confirms for SUNpics */
	"SUNWjncmt",	/* SunNet Manager Core Tools(Japan) */
	"SUNWjnmag",	/* SunNet Manager Agents & Libraries (Japan) */
	"SUNWjnmpd",	/* SunNet Manager SNMP daemon(Japan) */
	"SUNWlicsw",	/* + FLEXlm */
	"SUNWlit",	/* STE LIC INSTALL TOOL */
	"SUNWllc2a",	/* X.25 LLC2 KRNL MOD, INCLDS FL */
	"SUNWllc2b",	/* X.25 USR PROG, MAN PAGES */
	"SUNWmd",	/* + Suhas Patil request 1994-07-12 */
	"SUNWmhs1a",	/* MHS Message Transfer Agent Configuration Files */
	"SUNWmhs1b",	/* MHS Message Transfer Agent Executable and Man Pgs */
	"SUNWomgta",	/* OSI Mgmnt Configuration Files */
	"SUNWomgtb",	/* OSI Mgmnt Configuration Files */
	"SUNWomgtc",	/* OSI Mgmnt SunNet Mgr Proxy Agent Executable Files */
	"SUNWomgtd",	/* OSI Mgmnt SunNet Mgr Proxy Agent Config Files */
	"SUNWp2pnm",	/* SunLink SNA Peer-to-Peer Network Management */
	"SUNWprsto",	/* + Varun Mehta request 1994-07-11 */
	"SUNWrup2p",	/* Sunlink SNA Peer-to-Peer Run Time Environment */
	"SUNWs3270",	/* + SunLink SNA3270/RJE */
	"SUNWscmmd",	/* SunLink Comm Daemon */
	"SUNWsdlc",	/* SunLink IBM SDLC */
	"SUNWsm-ml",	/* ShowMe Motif Libs */
	"SUNWsm-ol",	/* ShowMe Online help */
	"SUNWsmCmg",
	"SUNWsmap",	/* SunLink Mapper */
	"SUNWsmaud",	/* ShowMe Audio */
	"SUNWsmsha",	/* ShowMe SharedApp */
	"SUNWsmvid",	/* ShowMe Video */
	"SUNWsmwtb",	/* ShowMe Whiteboard */
	"SUNWsnmag",	/* + Steve Wong request 1994-02-15 */
	"SUNWsnmct",	/* + Steve Wong request 1994-02-15 */
	"SUNWsnmja",	/* SunNet Manager 2.2 Japanese feature */
	"SUNWsnmpd",	/* SunNet Manager SNMP daemon */
	"SUNWsnp2p",	/* + SunLink SNA P-to-P */
	"SUNWspii",	/* 1.0 SPARCprinterII */
	"SUNWsrjec",	/* + SunLink Client SNA RJE */
	"SUNWsteCL",	/* + Frances Ho confirms for SUNPics */
	"SUNWsteNP",	/* 2.5 NeWSprint */
	"SUNWte320",	/* + TE320 8.0 */
	"SUNWtris",	/* SunConnect TRI/S */
	"SUNWvtcfg",	/* OSI Virtual Terminal Configuration Files */
	"SUNWvtexe",	/* OSI Virtual Terminal User Program and Man Pages */
	"SUNWx25a",	/* + X.25 KRNL MOD, INCLDS FLS */
	"SUNWx25b",	/* + X.25 USR PROG AND LIB */
	"zzzz1",	/* fill to avoid constraint tests in loop */
	"zzzz2",
	"zzzz3",
	"zzzz4"
};
#endif

/*
 * Structure to hold the list of pkg names that are known to not behave
 * properly when sym link destinations are not followed.
 */

#ifdef	ALLOW_EXCEPTION_PKG_LIST
static char *x_pkg_link[] =
{
	"AAAA1",	/* fill to avoid constraint tests in loop */
	"AAAA2",
	"AAAA3",
	"AAAA4",
	/* '+' means packages known to be non-compliant */
	"SUNWixfta",
	"SUNWixsna",
	"zzzz1",	/* fill to avoid constraint tests in loop */
	"zzzz2",
	"zzzz3",
	"zzzz4"
};
#endif

/*
 * This function determines if the package being added is a known old-style
 * package which requires user interaction during procedure scripts. It is
 * to be removed for on1095. -- JST
 * It also is used for the determining if a pkg is known to have symlinks
 * that need to be processed the old way.
 */

#ifdef	ALLOW_EXCEPTION_PKG_LIST
int
exception_pkg(char *pkginst, int pkg_list)
{
	int	retvalue = 0;
	int	list_sz;
	int	list_cntr;	/* starting point for binary search */
	register int	pos;		/* current position */
	register int	level;		/* current height in the tree */
	register int 	incr;		/* increment for step */
	int	result;		/* result of strcmp */
	register char **x_ptr = x_pkg;
	register char **x_ptr_link = x_pkg_link;
	char	*pkgend;
	char	*pkgname = strdup(pkginst);

	/*
	 * NOTE : If more structures need to be defined the following if
	 * statement needs to be revised to handle multiple flags
	 */

	if (pkg_list)
		list_sz = (sizeof (x_pkg_link) / sizeof (char *));
	else
		list_sz = (sizeof (x_pkg) / sizeof (char *));

	/*
	 * NOTE : shifts are used instead of integer division to save
	 * time. Numerous other checks are omitted also. This tree
	 * contains double nodes but is entirely connected and closed.
	 */

	list_cntr = list_sz >> 1;
	incr = list_cntr - TREEFILL;

	pkgend = strchr(pkgname, '.');

	if (pkgend)
		*pkgend = '\0';	/* terminate the instance to a name */

	for (level = TREEHEIGHT, 	/* start at the top level */
	    pos = list_cntr;		/*   ... in the middle */
	    level;		/* for as long as we're in the tree */
	    level--, pos += (result > 0) ? incr : -incr) {

		if (pkg_list)
			result = strcmp(pkgname, *(x_ptr_link + pos));
		else
			result = strcmp(pkgname, *(x_ptr + pos));

		if (result == 0) {
			retvalue = 1;
			break;
		}

		incr = (incr & 0x0001) | (incr >> 1);	/* halve it & rnd up */
	}

	free(pkgname);

	return (retvalue);
}

#endif

void
psvr4pkg(char	**ppkg)
{
	struct dirent *drp;
	DIR	*dirfp;
	char	*pt;
	int	n;
	char	ans[MAX_INPUT], path[PATH_MAX];

	if (*ppkg) {
		(void) snprintf(path, sizeof (path),
				"/install/new/usr/options/%s.name",
				*ppkg);
		if (access(path, 0)) {
			ptext(stderr, gettext(MSG_NOTVER), *ppkg);
			if (n = ckyorn(ans, NULL, NULL, gettext(HLP_NOTVER),
			    gettext(ASK_CONT)))
				quit(n);
			if (strchr("yY", *ans) == NULL)
				quit(3);
		}
		return;
	}

	if (dirfp = opendir("/install/new/usr/options")) {
		while (drp = readdir(dirfp)) {
			if (drp->d_name[0] == '.')
				continue;
			if (pt = strchr(drp->d_name, '.')) {
				if (strcmp(pt, ".name") == 0) {
					*pt = '\0';
					*ppkg = qstrdup(drp->d_name);
					break;
				}
			}
		}
		(void) closedir(dirfp);
	}

	if (*ppkg) {
		ptext(stderr, gettext(MSG_CONFIRM), *ppkg);
		if (n = ckyorn(ans, NULL, NULL, gettext(HLP_CONFIRM),
		    gettext(ASK_CONT)))
			quit(n);
	} else {
		ptext(stderr, gettext(MSG_NOTVER), *ppkg);
		if (n = ckyorn(ans, NULL, NULL, gettext(HLP_NOTVER),
		    gettext(ASK_CONT)))
			quit(n);
	}
	if (strchr("yY", *ans) == NULL)
		quit(3);
}

void
psvr4cnflct(void)
{
	FILE	*pp;
	int	n, found;
	char	*pt,
		ans[MAX_INPUT],
		cmd[PATH_MAX+sizeof (ckcmd)],
		path[PATH_MAX];

	for (n = 0; Rlist[n] != NULL; n++) {
		if (access(Rlist[n], 0) == 0)
			break;
	}
	if (Rlist[n] == NULL)
		return; /* Rlist file not found on device */

	(void) sprintf(cmd, ckcmd, Rlist[n]);
	echo(gettext("## Checking for conflicts with installed packages"));
	echo(gettext("   (using %s provided by pre-SVR4 package)"), Rlist[n]);
	if ((pp = popen(cmd, "r")) == NULL) {
		progerr(gettext(ERR_PIPE), cmd);
		progerr(gettext(ERR_OVERWRITE));
		quit(99);
	}

	found = 0;
	while (fgets(path, PATH_MAX, pp)) {
		if (!found++)
			ptext(stderr, gettext(MSG_CONFLICT));
		if (pt = strpbrk(path, " \t\n"))
			*pt = '\0';
		echo("\t%s", path);
	}
	if (pclose(pp)) {
		progerr(gettext(ERR_OVERWRITE));
		quit(99);
	}

	if (found) {
		if (n = ckyorn(ans, NULL, NULL, gettext(HLP_CONFLICT),
		    gettext(ASK_CONT)))
			quit(n);
		if (strchr("yY", *ans) == NULL)
			quit(3);
	}
}

void
psvr4mail(char *list, char *msg, int retcode, char *pkg)
{
	struct utsname utsbuf;
	FILE	*pp;
	char	cmd[BUFSIZ];

	if (list == NULL)
		return;

	while (isspace(*list))
		list++;
	if (*list == '\0')
		return;

	/* send e-mail notifications */
	(void) snprintf(cmd, sizeof (cmd), "%s %s", MAILCMD, list);
	if ((pp = popen(cmd, "w")) == NULL) {
		progerr(gettext(ERR_PIPE), MAILCMD);
		progerr(gettext(ERR_MAIL));
		quit(99);
	}

	(void) strcpy(utsbuf.nodename, gettext("(unknown)"));
	(void) uname(&utsbuf);
	ptext(pp, msg, pkg, utsbuf.nodename, retcode);

	if (pclose(pp)) {
		progerr(gettext(ERR_MAIL));
		quit(99);
	}
}
