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


#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <utmpx.h>
#include <dirent.h>
#include <sys/types.h>
#include <locale.h>
#include <libintl.h>
#include <pkgstrct.h>
#include <pkglocs.h>
#include <assert.h>
#include <pkglib.h>
#include <install.h>
#include <libinst.h>
#include <libadm.h>
#include <messages.h>
#include <instzones_api.h>

extern int	npkgs;	/* the number of packages yet to be installed */

/*
 * ckquit is a global that controls 'ckyorn' (defined in libadm)
 * If ckquit is non-zero, then "quit" is allowed as an answer when
 * ckyorn is called. If is it zero, then "quit" is not an allowed answer.
 */
extern int	ckquit;

extern struct admin adm;

/*
 * each one of these represents a single kind of dependency check
 */

static depckError_t er_depsonme = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_prenci = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_prereq = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_rckdepend = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_rckpriv = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_rckrunlevel = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_runlevel = {0, (depckErrorRecord_t *)NULL};

/*
 * each one of these represents a localized message for a single kind
 * of dependency check
 */

static char *IMSG_PKGRMCHK_CKRUNLVL = (char *)NULL;
static char *IMSG_PKGRMCHK_DEPEND = (char *)NULL;
static char *IMSG_PKGRMCHK_DEPSONME = (char *)NULL;
static char *IMSG_PKGRMCHK_PRENCI = (char *)NULL;
static char *IMSG_PKGRMCHK_PREREQ = (char *)NULL;
static char *IMSG_PKGRMCHK_PRIV = (char *)NULL;
static char *IMSG_PKGRMCHK_RUNLEVEL = (char *)NULL;

/*
 * each one of these represents a function to handle a single kind of
 * dependency check
 */

static int rckdepend(char *a_msg, char *a_pkg);
static int rckdepsonme(char *a_msg, char *a_pkg);
static int rckprenci(char *a_msg, char *a_pkg);
static int rckprereq(char *a_msg, char *a_pkg);
static int rckpriv(char *a_msg, char *a_pkg);
static int rckrunlevel(char *a_msg, char *a_pkg);

static depckl_t DEPCKL[] = {
	/*
	 * Message hierarchy:
	 * -- runlevel=%s
	 * --- rckrunlevel=%d
	 * --- rckpriv=%d  ****
	 * -- incompat=%s
	 * -- prerequisite-incomplete=%s
	 * -- dependonme=%s
	 * -- dependsonme=%s:%s
	 * -- prerequisite-installed=%s
	 * ---rckdepend=%d ****
	 */

	/* name,	ignore_values,	err_msg,	depcklFunc,	recrd */
	/*
	 * package and zone information is collected in the "record" object for
	 * each occurance - then a message is constructed for each zone that
	 * reported the condition - the message includes that portion of the
	 * check past the "=" - then the specified "depcklFunc" is called to
	 * process each message.
	 * Message format:
	 * 	%s %s <%s> %s <%s>
	 * Message arguments:
	 *	value, "package", package-name, "zone/zones", zone-name
	 */

	{ "dependsonme=",		NULL, 	&IMSG_PKGRMCHK_DEPSONME,
					&rckdepsonme,	&er_depsonme
	},
	{ "dependonme=",		NULL, 	&IMSG_PKGRMCHK_DEPSONME,
					&rckdepsonme,	&er_depsonme
	},
	{ "prerequisite-incomplete=",	NULL,	&IMSG_PKGRMCHK_PRENCI,
					&rckprenci,	&er_prenci
	},
	{ "prerequisite-installed=",	NULL,	&IMSG_PKGRMCHK_PREREQ,
					&rckprereq,	&er_prereq
	},
	{ "runlevel=",			NULL,	&IMSG_PKGRMCHK_RUNLEVEL,
					NULL,		&er_runlevel
	},

	/*
	 * these checks are ignored if they return one of the listed values
	 * if they do NOT return one of the listed values, then the package
	 * and zone information is collected in the "record" object for each
	 * occurance - then a single unified message is constructed for all
	 * zones that report the same condition; then the specified "depcklFunc"
	 * is called to process the resulting combined message.
	 * Message format:
	 * 	%s <%s> %s <%s>
	 * Message arguments:
	 *	"package", package-name, "zone/zones", zone-name(s)
	 */

	{ "rckdepend=",			"0",	&IMSG_PKGRMCHK_DEPEND,
					&rckdepend,	&er_rckdepend
	},
	{ "rckpriv=",			"0",	&IMSG_PKGRMCHK_PRIV,
					&rckpriv,	&er_rckpriv
	},
	{ "rckrunlevel=",		"0",	&IMSG_PKGRMCHK_CKRUNLVL,
					&rckrunlevel,	&er_rckrunlevel
	},

	/*
	 * same as above BUT no check to ignore is done; message always reported
	 */

	{ NULL,				NULL,	NULL,
						NULL,		NULL
	}
};

/*
 * Name:	preremove_verify
 * Description:	verify results of preremoval dependency checking
 * Arguments:	a_pkglist - pointer to array of strings representing the names
 *			of all the packages that have been checked
 *		a_zlst - list of zones that dependencies were checked on
 *		a_zoneTempDir - pointer to string representing the path where
 *			the files containing the preremoval dependency
 *			check data are located
 * Returns:	int
 *		== 0 - continue processing
 *		!= 0 - do not continue processing
 */

int
preremove_verify(char **a_pkglist, zoneList_t a_zlst, char *a_zoneTempDir)
{
	char		*pkginst;
	int		i;
	int		savenpkgs = npkgs;

	/*
	 * entry assertions
	 */

	assert(a_pkglist != (char **)NULL);
	assert(a_zlst != (zoneList_t)NULL);
	assert(a_zoneTempDir != (char *)NULL);

	/*
	 * entry debugging info
	 */

	echoDebug(DBG_PRERVFY_ENTRY);

	/*
	 * localize messages
	 */

	IMSG_PKGRMCHK_DEPSONME = MSG_PKGRMCHK_DEPSONME;
	IMSG_PKGRMCHK_PRENCI = MSG_PKGRMCHK_PRENCI;
	IMSG_PKGRMCHK_PREREQ = MSG_PKGRMCHK_PREREQ;
	IMSG_PKGRMCHK_RUNLEVEL = MSG_PKGRMCHK_RUNLEVEL;
	IMSG_PKGRMCHK_DEPEND = MSG_PKGRMCHK_DEPEND;
	IMSG_PKGRMCHK_PRIV = MSG_PKGRMCHK_PRIV;
	IMSG_PKGRMCHK_CKRUNLVL = MSG_PKGRMCHK_CKRUNLVL;

	/*
	 * outer loop - process each package first
	 */

	for (i = 0; (pkginst = a_pkglist[i]) != NULL; i++) {

		char	*zoneName;
		int	zoneIndex;

		/*
		 * inner loop - for each package process each zone second
		 */

		if (pkgIsPkgInGzOnly(get_inst_root(), pkginst) == B_TRUE) {
			continue;
		}

		for (zoneIndex = 0;
			(zoneName = z_zlist_get_zonename(a_zlst, zoneIndex)) !=
				(char *)NULL; zoneIndex++) {

			FILE	*fp;
			char	line[PATH_MAX+1];
			char	preremovecheckPath[PATH_MAX+1];
			int	len;

			/* skip the zone if it is NOT bootable */

			if (z_zlist_is_zone_runnable(a_zlst,
			    zoneIndex) == B_FALSE) {
				continue;
			}

			/* create path to this packages preremove check data */

			len = snprintf(preremovecheckPath,
			    sizeof (preremovecheckPath),
			    "%s/%s.%s.preremovecheck.txt",
			    a_zoneTempDir, pkginst,
			    z_zlist_get_scratch(a_zlst, zoneIndex));

			if (len > sizeof (preremovecheckPath)) {
				progerr(ERR_CREATE_PATH_3, a_zoneTempDir,
					pkginst, zoneName);
				continue;
			}

			/* error if preremove check data path is not a file */

			if (isfile((char *)NULL, preremovecheckPath) != 0) {
				echoDebug(DBG_PRERVFY_NOFILE, pkginst, zoneName,
					preremovecheckPath, strerror(errno));
				progerr(ERR_PRERVFY_NOFILE, pkginst, zoneName);
				continue;
			}

			/* open the preremove check data file */

			fp = fopen(preremovecheckPath, "r");
			if (fp == (FILE *)NULL) {
				progerr(ERR_PRERVFY_OPEN_FILE,
					preremovecheckPath, pkginst, zoneName,
					strerror(errno));
				continue;
			}

			/* read and process each preremove check data line */

			while (fgets(line, sizeof (line), fp) != (char *)NULL) {
				int	len;
				int	j;

				/* remove all new-lines from end of line */

				len = strlen(line);
				while ((len > 0) && (line[len-1] == '\n')) {
					line[--len] = '\0';
				}

				/* ignore comment lines */

				if (line[0] == '#') {
					continue;
				}

				/* ignore empty lines */

				if (line[0] == '\0') {
					continue;
				}

				/* scan dependency list for this item */

				for (j = 0;
					DEPCKL[j].name != (char *)NULL; j++) {
					len = strlen(DEPCKL[j].name);

					if (strncmp(line, DEPCKL[j].name,
								len) == 0) {
						break;
					}
				}

				echoDebug(DBG_PRERVFY_SCAN, line, pkginst,
						zoneName);

				/* ignore line if not found */

				if (DEPCKL[j].name == (char *)NULL) {
					progerr(ERR_PRERVFY_UNKNOWN_LINE, line,
							pkginst, zoneName);
					continue;
				}

				if ((DEPCKL[j].ignore_values != (char *)NULL) &&
					(*(DEPCKL[j].ignore_values) != '\0') &&
					(strchr(DEPCKL[j].ignore_values,
						line[len]) != (char *)NULL)) {
						continue;
				}
				/* found match - record this dependency issue */

				depchkRecordError(DEPCKL[j].record, pkginst,
					zoneName, &line[len]);
			}

			/* close preremove check data file */

			(void) fclose(fp);
		}
	}

	/*
	 * all dependency issues have been recorded; report results
	 */

	i = depchkReportErrors(DEPCKL);

	/* restore "npkgs" */

	npkgs = savenpkgs;

	/* return continue/dont dontinue results */

	return (i);
}

/*
 * Name:	getyorn
 * Description:	Deliver dependency check reason; ask question; return response
 * Arguments:	a_msg - pointer to string representing the message to output
 *			such as 'The package <..> contains <...>'
 *		a_pkg - pointer to string representing the package for which
 *			the question is being asked
 *		a_nocheck - should the message be output?
 *			== 0 - do not output the message
 *			!= 0 - output the message
 *		a_quit - should the question NOT be asked?
 *			== 0 - ask the question
 *			!= 0 - do not ask the question - return "no"
 *		a_helpMsg - pointer to string representing help message to be
 *			made available if the question is asked
 *			== NULL - no help message is available
 *		a_adminMsg - pointer to string representing the dependency check
 *			failure 'reason' - such as "Privilege checking failed."
 *			== NULL - no failure reason is available
 * Returns:	int - results of question/response actions
 *			0 - success
 *			1 - end of file
 *			2 - undefined error
 *			3 - answer was not "y"/was "q"
 *			4 - quit action taken
 *			5 - interactive mode required
 */

static int
getyorn(char *a_msg, char *a_pkg, int a_nocheck, int a_quit,
	char *a_helpMsg, char *a_adminMsg)
{
	char	ans[MAX_INPUT];
	char	ask_cont[MSG_MAX];
	int	n;
	int	saveCkquit;

	/*
	 * entry assertions
	 */

	assert(a_pkg != (char *)NULL);
	assert(*a_pkg != '\0');

	/*
	 * entry debugging info
	 */

	echoDebug(DBG_PRERVFY_GETYORN_ARGS, a_pkg, a_nocheck, a_quit, a_msg,
			a_adminMsg ? a_adminMsg : "");

	/* return success (0) if "nocheck" is non-zero */

	if (a_nocheck != 0) {
		echoDebug(DBG_PRERVFY_GETYORN_NOCHECK, a_pkg);
		return (0);
	}

	/* output reason for this particular failure */

	if ((a_msg != (char *)NULL) && (*a_msg != '\0')) {
		ptext(stderr, "%s", a_msg);
	}

	/* return "4 (administration)" if "quit" is non-zero */

	if (a_quit != 0) {
		/* output failure "admin reason" if available */
		if ((a_adminMsg != (char *)NULL) && (*a_adminMsg != '\0')) {
			ptext(stderr, a_adminMsg);
		}
		echoDebug(DBG_PRERVFY_GETYORN_QUIT, a_pkg);
		return (4);
	}

	/* return "5 (administration interaction required)" if -n */

	if (echoGetFlag() == B_FALSE) {
		ptext(stderr, MSG_PRERVFY_GETYORN_SUSP, a_pkg);
		echoDebug(DBG_PRERVFY_GETYORN_QUIT_USER, a_pkg);
		return (5);
	}

	/* prepare question to ask "continue with removal of pkg <xxx>?" */

	(void) snprintf(ask_cont, sizeof (ask_cont), gettext(ASK_PKGRMCHK_CONT),
		a_pkg);

	/* ask question */

	saveCkquit = ckquit;
	ckquit = 0;

	n = ckyorn(ans, NULL, NULL, a_helpMsg, ask_cont);

	ckquit = saveCkquit;

	if (n != 0) {
		ptext(stderr, MSG_PRERVFY_GETYORN_TERM, a_pkg);
		echoDebug(DBG_PRERVFY_GETYORN_CKYORN, a_pkg, n);
		return (n);
	}

	/* return "3 (interruption) if not "y" or "Y" */

	if (strchr("yY", *ans) == NULL) {
		ptext(stderr, MSG_PRERVFY_GETYORN_TERM_USER, a_pkg);
		echoDebug(DBG_PRERVFY_GETYORN_NOT_Y, a_pkg, ans);
		return (3);
	}

	/* return "0 - success" */

	echoDebug(DBG_PRERVFY_GETYORN_SUCCESS, a_pkg);

	return (0);
}

/*
 * Trigger:	dependsonme=<<package>>
 * Sequence:	- one or more: dependsonme=<<package>>
 *		- one: rckdepend=<<n>>
 * Actions:	Output message if "rdepend!=nocheck"
 *		Return 0
 *		Terminate when 'rckdepend' processed
 */

static int
rckdepsonme(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PRERVFY_RCKDEPSONME, a_pkg, a_msg);

	if (!(ADM(rdepend, "nocheck"))) {
		ptext(stderr, "%s", a_msg);
	}

	return (0);
}

/*
 * Trigger:	prerequisite-incomplete=<<package>>
 * Sequence:	- one or more: prerequisite-incomplete=<<package>>
 *		- one: rckdepend=<<n>>
 * Actions:	Output message if "rdepend!=nocheck"
 *		Return 0
 *		Terminate when 'rckdepend' processed
 */

static int
rckprenci(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PRERVFY_RCKPRENCI, a_pkg, a_msg);

	if (!(ADM(rdepend, "nocheck"))) {
		ptext(stderr, "%s", a_msg);
	}

	return (0);
}

/*
 * Trigger:	prerequisite-installed=<<package>>
 * Sequence:	- one or more: prerequisite-installed=<<package>>
 *		- one: rckdepend=<<n>>
 * Actions:	Output message if "rdepend!=nocheck"
 *		Return 0
 *		Terminate when 'rckdepend' processed
 */

static int
rckprereq(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PRERVFY_RCKPREREQ, a_pkg, a_msg);

	if (!(ADM(rdepend, "nocheck"))) {
		ptext(stderr, "%s", a_msg);
	}

	return (0);
}

/*
 * Return value:	int
 *			0 - success
 *			1 - end of file
 *			2 - undefined error
 *			3 - answer was not "y"/was "q"
 *			4 - quit action taken
 *			5 - interactive mode required
 *			99 - fatal error
 */

static int
rckrunlevel(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PRERVFY_RCKRUNLEVEL, a_pkg, a_msg);
	/*
	 * For now, we are ignoring runlevel removal issues within
	 * non-global zones.  This is questionable, but the RSTATES
	 * feature is rarely used and known uses within Solaris are
	 * effectively no-ops as of this time
	 */
	return (0);
}

/*
 * Trigger:	rckdepend=<<n>>
 * Sequence:	- one or more of:
 *		-- incompat=<<package>>
 *		-- prerequisite-incomplete=<<package>>
 *		-- prerequisite-installed=<<package>>
 *		-- dependson=<<package>>
 *		-- dependsonme=<<package>>
 *		- one: ckpdepend=<<n>>
 * Actions:	process according to settings
 * Return value:	int
 *			0 - success
 *			1 - end of file
 *			2 - undefined error
 *			3 - answer was not "y"/was "q"
 *			4 - quit action taken
 *			5 - interactive mode required
 */

static int
rckdepend(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PRERVFY_RCKDEPEND, a_pkg, a_msg);

	return (getyorn(a_msg, a_pkg, ADM(rdepend, "nocheck"),
		ADM(rdepend, "quit"), HLP_PKGRMCHK_DEPEND,
		ERR_PKGRMCHK_DEPFAILED));
}

/*
 * Trigger:	rckpriv=<<n>>
 * Sequence:	- one: rckpriv=<<n>>
 * Actions:	process according to settings
 * Return value:	int
 *			0 - success
 *			1 - end of file
 *			2 - undefined error
 *			3 - answer was not "y"/was "q"
 *			4 - quit action taken
 *			5 - interactive mode required
 */

static int
rckpriv(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PRERVFY_RCKPRIV, a_pkg, a_msg);

	return (getyorn(a_msg, a_pkg, ADM(action, "nocheck"),
		ADM(action, "quit"), HLP_PKGRMCHK_PRIV,
		ERR_PKGRMCHK_PRIVFAILED));
}
