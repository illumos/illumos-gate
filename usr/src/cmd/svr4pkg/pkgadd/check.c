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
#include <dirent.h>
#include <sys/types.h>
#include <locale.h>
#include <libintl.h>
#include <pkgstrct.h>
#include <pkglocs.h>
#include <assert.h>

#include <instzones_api.h>
#include <pkglib.h>
#include <messages.h>

#include <install.h>
#include <libinst.h>
#include <libadm.h>

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

static depckError_t er_ckconflict = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_ckdepend = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_ckcfcontent = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_ckinstance = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_ckdirs = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_ckpartinst = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_ckpartrem = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_ckpkgdirs = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_ckpkgfilebad = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_ckpkgfiles = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_ckpriv = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_ckrunlevel = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_cksetuid = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_ckspace = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_newonly = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_prereqinc = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_prereqinst = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_runlevel = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_same = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_overwrite = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_uniq1 = {0, (depckErrorRecord_t *)NULL};
static depckError_t er_attrib = {0, NULL};
static depckError_t er_setuidf = {0, NULL};
static depckError_t er_setgidf = {0, NULL};
static depckError_t er_overwr = {0, NULL};

/*
 * each one of these represents a localized message for a single kind
 * of dependency check
 */

static char *IMSG_ABADFILE = (char *)NULL;
static char *IMSG_BADFILE = (char *)NULL;
static char *IMSG_CKRUNLVL = (char *)NULL;
static char *IMSG_CNFFAILED = (char *)NULL;
static char *IMSG_DEPEND = (char *)NULL;
static char *IMSG_CFCONTENT = (char *)NULL;
static char *IMSG_INSTANCE = "INSTANCE %s <%s> on %s <%s>";
static char *IMSG_DIRS  = (char *)NULL;
static char *IMSG_NEWONLY = (char *)NULL;
static char *IMSG_PARTINST = (char *)NULL;
static char *IMSG_PARTREM = (char *)NULL;
static char *IMSG_PKGDIRS = (char *)NULL;
static char *IMSG_PRENCI  = (char *)NULL;
static char *IMSG_PREREQ  = (char *)NULL;
static char *IMSG_PRIV = (char *)NULL;
static char *IMSG_RUNLEVEL = (char *)NULL;
static char *IMSG_SAME = (char *)NULL;
static char *IMSG_OVERWRITE = (char *)NULL;
static char *IMSG_UNIQ1 = (char *)NULL;
static char *IMSG_SETUID = (char *)NULL;
static char *IMSG_SPCFAILED = (char *)NULL;
static char *IMSG_ATTRIB;
static char *IMSG_SETUIDF;
static char *IMSG_SETGIDF;
static char *IMSG_OVERWR;

/*
 * each one of these represents a function to handle a single kind of
 * dependency check
 */

static int ckconflict(char *a_msg, char *a_pkg);
static int ckdepend(char *a_msg, char *a_pkg);
static int ckcfcontent(char *a_msg, char *a_pkg);
static int ckinstance(char *a_msg, char *a_pkg);
static int ckdirs(char *a_msg, char *a_pkg);
static int ckpartinst(char *a_msg, char *a_pkg);
static int ckpartrem(char *a_msg, char *a_pkg);
static int ckpkgfilebad(char *a_msg, char *a_pkg);
static int ckpkgdirs(char *a_msg, char *a_pkg);
static int ckpkgfiles(char *a_msg, char *a_pkg);
static int ckprereqinc(char *a_msg, char *a_pkg);
static int ckprereqinst(char *a_msg, char *a_pkg);
static int ckpriv(char *a_msg, char *a_pkg);
static int ckrunlevel(char *a_msg, char *a_pkg);
static int cksetuid(char *a_msg, char *a_pkg);
static int ckspace(char *a_msg, char *a_pkg);
static int attrib(char *a_msg, char *a_pkg);
static int setuidf(char *a_msg, char *a_pkg);
static int setgidf(char *a_msg, char *a_pkg);
static int overwr(char *a_msg, char *a_pkg);

static depckl_t DEPCKL[] = {
	/*
	 * name,	ignore_values,	err_msg,	depcklFunc,	recrd
	 * ---
	 * ignore_values == NULL:
	 * package and zone information is collected in the "record" object for
	 * each occurance - then a message is constructed for each zone that
	 * reported the condition - the message includes that portion of the
	 * check past the "=" - then the specified "depcklFunc" is called to
	 * process each message.
	 * Message format:
	 * 	%s %s <%s> %s <%s>
	 * Message arguments:
	 *	value, "package", package-name, "zone/zones", zone-name
	 * ---
	 * ignore-values == "???":
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
	 * ---
	 * ignore-values="":
	 * same as above BUT no check to ignore is done; message always reported
	 */

	{ "install-same-instance=true",	"",		&IMSG_SAME,
					NULL,		&er_same
	},
	{ "ckpkgfilebad=",		NULL,		&IMSG_ABADFILE,
					&ckpkgfilebad,	&er_ckpkgfilebad
	},
	{ "ckdirs=",			NULL,		&IMSG_DIRS,
					&ckdirs,	&er_ckdirs
	},
	{ "prerequisite-incomplete=",	NULL,		&IMSG_PRENCI,
					&ckprereqinc,	&er_prereqinc
	},
	{ "prerequisite-installed=",	NULL,		&IMSG_PREREQ,
					&ckprereqinst,	&er_prereqinst
	},
	{ "runlevel=",			NULL,		&IMSG_RUNLEVEL,
					NULL,		&er_runlevel
	},
	{ "conflict-contents=",		NULL,		&IMSG_CFCONTENT,
					&ckcfcontent,	&er_ckcfcontent
	},
	{ "ckconflict=",		"0",		&IMSG_CNFFAILED,
					&ckconflict,	&er_ckconflict
	},
	{ "ckdepend=",			"0",		&IMSG_DEPEND,
					&ckdepend,	&er_ckdepend
	},
	{ "ckpartialinstall=",		"0",		&IMSG_PARTINST,
					&ckpartinst,	&er_ckpartinst
	},
	{ "ckpartialremove=",		"0",		&IMSG_PARTREM,
					&ckpartrem,	&er_ckpartrem
	},
	{ "ckpkgdirs=",			"0",		&IMSG_PKGDIRS,
					&ckpkgdirs,	&er_ckpkgdirs
	},
	{ "ckpkgfiles=",		"0",		&IMSG_BADFILE,
					&ckpkgfiles,	&er_ckpkgfiles
	},
	{ "ckpriv=",			"0",		&IMSG_PRIV,
					&ckpriv,	&er_ckpriv
	},
	{ "ckrunlevel=",		"0",		&IMSG_CKRUNLVL,
					&ckrunlevel,	&er_ckrunlevel
	},
	{ "cksetuid=",			"0",		&IMSG_SETUID,
					&cksetuid,	&er_cksetuid
	},
	{ "ckspace=",			"0",		&IMSG_SPCFAILED,
					&ckspace,	&er_ckspace
	},
	{ "install-new-only=true",	"",		&IMSG_NEWONLY,
					NULL,		&er_newonly
	},
	{ "install-ovewrite=true",	"",		&IMSG_OVERWRITE,
					NULL,		&er_overwrite
	},
	{ "install-too-many-instances=true",	"",	&IMSG_UNIQ1,
					NULL,		&er_uniq1
	},
	{ "ckinstance=",		"0",		&IMSG_INSTANCE,
					&ckinstance,	&er_ckinstance
	},
	{ "conflict-attributes=",	NULL,		&IMSG_ATTRIB,
					&attrib,	&er_attrib
	},
	{ "setuid=",			NULL,		&IMSG_SETUIDF,
					&setuidf,	&er_setuidf
	},
	{ "setgid=",			NULL,		&IMSG_SETGIDF,
					&setgidf,	&er_setgidf
	},
	{ "setuid-overwrite=true",	"",		&IMSG_OVERWR,
					&overwr,	&er_overwr
	},

	{ NULL,				NULL,	NULL,
				NULL,		NULL }
};

/*
 * Name:	preinstall_verify
 * Description:	verify results of preinstallation dependency checking
 * Arguments:	a_pkglist - pointer to array of strings representing the names
 *			of all the packages that have been checked
 *		a_zlst - list of zones that dependencies were checked on
 *		a_zoneTempDir - pointer to string representing the path where
 *			the files containing the preinstallation dependency
 *			check data are located
 * Returns:	int
 *		== 0 - continue processing
 *		!= 0 - do not continue processing
 */

int
preinstall_verify(char **a_pkglist, zoneList_t a_zlst, char *a_zoneTempDir)
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

	echoDebug(DBG_PREIVFY_ENTRY);

	/*
	 * localize messages
	 */

	IMSG_ABADFILE = MSG_PKGADDCHK_ABADFILE;
	IMSG_BADFILE = MSG_PKGADDCHK_BADFILE;
	IMSG_CFCONTENT = MSG_PKGADDCHK_CFCONTENT;
	IMSG_CKRUNLVL = MSG_PKGADDCHK_CKRUNLVL;
	IMSG_CNFFAILED = MSG_PKGADDCHK_CNFFAILED;
	IMSG_DEPEND = MSG_PKGADDCHK_DEPEND;
	IMSG_DIRS  = MSG_PKGADDCHK_DIRS;
	IMSG_NEWONLY = MSG_PKGADDCHK_NEWONLY;
	IMSG_OVERWRITE = MSG_PKGADDCHK_OVERWRITE;
	IMSG_PARTINST = MSG_PKGADDCHK_PARTINST;
	IMSG_PARTREM = MSG_PKGADDCHK_PARTREM;
	IMSG_PKGDIRS = MSG_PKGADDCHK_PKGDIRS;
	IMSG_PRENCI  = MSG_PKGADDCHK_PRENCI;
	IMSG_PREREQ  = MSG_PKGADDCHK_PREREQ;
	IMSG_PRIV = MSG_PKGADDCHK_PRIV;
	IMSG_RUNLEVEL = MSG_PKGADDCHK_RUNLEVEL;
	IMSG_SAME = MSG_PKGADDCHK_SAME;
	IMSG_SETUID = MSG_PKGADDCHK_SETUID;
	IMSG_SPCFAILED = MSG_PKGADDCHK_SPCFAILED;
	IMSG_UNIQ1 = MSG_PKGADDCHK_UNIQ1;
	IMSG_ATTRIB = gettext("\\nattribute change for %s <%s> on %s <%s>\n");
	IMSG_SETUIDF = gettext("\\nsetuid %s in %s <%s> on %s <%s>\n");
	IMSG_SETGIDF = gettext("\\nsetgid %s in %s <%s> on %s <%s>\n");
	IMSG_OVERWR = gettext("\\nFiles that are setuid will be overwritten "
	    "by installation of %s\n<%s> on %s <%s>.\n");

	/*
	 * outer loop - process each package first
	 */

	for (i = 0; (pkginst = a_pkglist[i]) != NULL; i++) {

		char	*zoneName;
		int	zoneIndex;

		/*
		 * if this package is marked "install in this zone only", then
		 * do not check dependencies in any zone
		 */

		if (pkgPackageIsThisZone(pkginst) == B_TRUE) {
			echoDebug(DBG_PREIVFY_SKIP_THISZONE, pkginst);
			continue;
		}

		/*
		 * inner loop - for each package process each zone second
		 */

		for (zoneIndex = 0;
			(zoneName = z_zlist_get_zonename(a_zlst, zoneIndex)) !=
				(char *)NULL; zoneIndex++) {

			FILE	*fp;
			char	line[PATH_MAX+1];
			char	preinstallcheckPath[PATH_MAX+1];
			int	len;

			/* skip the zone if it is NOT bootable */

			if (z_zlist_is_zone_runnable(a_zlst,
							zoneIndex) == B_FALSE) {
				continue;
			}

			/* create path to this packages preinstall check data */

			len = snprintf(preinstallcheckPath,
				sizeof (preinstallcheckPath),
				"%s/%s.%s.preinstallcheck.txt", a_zoneTempDir,
				pkginst, zoneName);

			if (len > sizeof (preinstallcheckPath)) {
				progerr(ERR_CREATE_PATH_3, a_zoneTempDir,
					pkginst, zoneName);
				continue;
			}

			/* error if preinstall check data path is not a file */

			if (isfile((char *)NULL, preinstallcheckPath) != 0) {
				echoDebug(DBG_PREIVFY_NOFILE,
					pkginst, zoneName, preinstallcheckPath,
					strerror(errno));
				progerr(ERR_PREIVFY_NOFILE,
					pkginst, zoneName);
				continue;
			}

			/* open the preinstall check data file */

			fp = fopen(preinstallcheckPath, "r");
			if (fp == (FILE *)NULL) {
				progerr(ERR_PREIVFY_OPEN_FILE,
					preinstallcheckPath, pkginst, zoneName,
					strerror(errno));
				continue;
			}

			/* read and process each preinstall check data line */

			while (fgets(line, sizeof (line), fp) != (char *)NULL) {
				int	j;
				int	len;

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

				echoDebug(DBG_PREIVFY_SCAN, line, pkginst,
						zoneName);

				/* ignore line if not found */

				if (DEPCKL[j].name == (char *)NULL) {
					progerr(ERR_PREIVFY_UNKNOWN_LINE, line,
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

			/* close preinstall check data file */

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

	echoDebug(DBG_PREIVFY_GETYORN_ARGS, a_pkg, a_nocheck, a_quit, a_msg,
			a_adminMsg ? a_adminMsg : "");

	/* return success (0) if "nocheck" is non-zero */

	if (a_nocheck != 0) {
		echoDebug(DBG_PREIVFY_GETYORN_NOCHECK, a_pkg);
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
		echoDebug(DBG_PREIVFY_GETYORN_QUIT, a_pkg);
		return (4);
	}

	/* return "5 (administration interaction required)" if -n */

	if (echoGetFlag() == B_FALSE) {
		ptext(stderr, MSG_PREIVFY_GETYORN_SUSP, a_pkg);
		echoDebug(DBG_PREIVFY_GETYORN_QUIT_USER, a_pkg);
		return (5);
	}

	/* prepare question to ask "continue with pkg <xxx>?" */

	(void) snprintf(ask_cont, sizeof (ask_cont), gettext(ASK_CONT), a_pkg);

	/* ask question */

	saveCkquit = ckquit;
	ckquit = 0;

	n = ckyorn(ans, NULL, NULL, a_helpMsg, ask_cont);

	ckquit = saveCkquit;

	if (n != 0) {
		ptext(stderr, MSG_PREIVFY_GETYORN_TERM, a_pkg);
		echoDebug(DBG_PREIVFY_GETYORN_CKYORN, a_pkg, n);
		return (n);
	}

	/* return "3 (interruption) if not "y" or "Y" */

	if (strchr("yY", *ans) == NULL) {
		ptext(stderr, MSG_PREIVFY_GETYORN_TERM_USER, a_pkg);
		echoDebug(DBG_PREIVFY_GETYORN_NOT_Y, a_pkg, ans);
		return (3);
	}

	/* return "0 - success" */

	echoDebug(DBG_PREIVFY_GETYORN_SUCCESS, a_pkg);

	return (0);
}

/*
 * Trigger:	prerequisite-incomplete=<<package>>
 * Sequence:	- one or more: prerequisite-incomplete=<<package>>
 *		- one: ckdepend=<<n>>
 * Actions:	Output message if "idepend!=nocheck"
 *		Return 0
 *		Terminate when 'ckdepend' processed
 */

static int
ckprereqinc(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PREIVFY_CKPRENCI, a_pkg, a_msg);

	if (!(ADM(idepend, "nocheck"))) {
		ptext(stderr, "%s", a_msg);
	}

	return (0);
}

/*
 * Trigger:	prerequisite-installed=<<package>>
 * Sequence:	- one or more: prerequisite-installed=<<package>>
 *		- one: ckdepend=<<n>>
 * Actions:	Output message if "idepend!=nocheck"
 *		Return 0
 *		Terminate when 'ckdepend' processed
 */

static int
ckprereqinst(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PREIVFY_CKPREREQ, a_pkg, a_msg);

	if (!(ADM(idepend, "nocheck"))) {
		ptext(stderr, "%s", a_msg);
	}

	return (0);
}

/*
 * Trigger:	ckpartialinstall=<<n>>
 * Sequence:	- one: ckpartialinstall=<<n>>
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
ckpartinst(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PREIVFY_CKPARTIALINSTALL, a_pkg, a_msg);

	return (getyorn(a_msg, a_pkg, ADM(partial, "nocheck"),
			ADM(partial, "quit"), HLP_PKGADDCHK_PARTIAL, NULL));
}

/*
 * Trigger:	ckpartialremove=<<n>>
 * Sequence:	- one: ckpartialremove=<<n>>
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
ckpartrem(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PREIVFY_CKPARTIALREMOVE, a_pkg, a_msg);

	return (getyorn(a_msg, a_pkg, ADM(partial, "nocheck"),
		ADM(partial, "quit"), HLP_PKGADDCHK_PARTIAL, NULL));
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
ckrunlevel(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PREIVFY_CKRUNLEVEL, a_pkg, a_msg);
	return (0);
}

/*
 * Trigger:	conflict-contents=<<n>>
 * Sequence:	- one or more of:
 *		-- conflict-contents=<<path>>
 *		-- conflict-attributes=<<path>>
 *		- one: ckconflict=<<n>>
 * Actions:	output message
 * Return value:	int
 *			0 - success
 */

static int
ckcfcontent(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PREIVFY_CKCFCONTENT, a_pkg, a_msg);

	ptext(stderr, "%s", a_msg);

	return (0);
}

/*
 * Trigger:	ckinstance=<<n>>
 * Sequence:	- one or more of:
 *		-- install-instance=true
 *		-- install-new-only=true\n
 *		-- install-same-instance=true\n
 *		-- install-ovewrite=true\n
 *		-- install-too-many-instances=true\n
 *		-- install-new-instance=true\n
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
ckinstance(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PREIVFY_CKINSTANCE, a_pkg, a_msg);

	return (getyorn(a_msg, a_pkg, ADM(instance, "nocheck"),
		ADM(instance, "quit"), HLP_PKGADDCHK_DEPEND,
		ERR_PKGADDCHK_DEPFAILED));
}

/*
 * Trigger:	ckdepend=<<n>>
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
ckdepend(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PREIVFY_CKDEPEND, a_pkg, a_msg);

	return (getyorn(a_msg, a_pkg, ADM(idepend, "nocheck"),
		ADM(idepend, "quit"), HLP_PKGADDCHK_DEPEND,
		ERR_PKGADDCHK_DEPFAILED));
}

/*
 * Trigger:	ckspace=<<n>>
 * Sequence:	- one: ckspace=<<n>>
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
ckspace(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PREIVFY_CKSPACE, a_pkg, a_msg);

	return (getyorn(a_msg, a_pkg, ADM(space, "nocheck"),
		ADM(space, "quit"), HLP_PKGADDCHK_SPACE,
		ERR_PKGADDCHK_SPCFAILED));
}

/*
 * Trigger:	ckpkgdirs=<<n>>
 * Sequence:	- one: ckpkgdirs=<<n>>
 * Actions:	output message
 *		Return 4
 */

static int
ckpkgdirs(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PREIVFY_CKPKGDIRS, a_pkg, a_msg);

	ptext(stderr, "%s", a_msg);

	return (4);
}

/*
 * Trigger:	ckdirs=<<path>>
 * Sequence:	- one: ckdirs=<<path>>
 * Actions:	output message
 *		Return 4
 */

static int
ckdirs(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PREIVFY_CKDIRS, a_pkg, a_msg);

	ptext(stderr, "%s", a_msg);

	ptext(stderr, ERR_PKGADDCHK_MKPKGDIR);

	return (4);
}

/*
 * Trigger:	ckpkgfilebad=<<path>>
 * Sequence:	- one or more:
 *		-- ckpkgfilebad=<<path>>
 *		- one ckpkgfiles=<n>
 * Actions:	output message
 *		Return 0
 */

static int
ckpkgfilebad(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PREIVFY_CKPKGFILEBAD, a_pkg, a_msg);

	ptext(stderr, "%s", a_msg);

	return (0);
}

/*
 * Trigger:	ckconflict=<<n>>
 * Sequence:	- one or more:
 *		-- conflict-contents=<<path>>
 *		-- conflict-attributes=<<path>>
 *		- one: ckconflict=<<n>>
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
ckconflict(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PREIVFY_CKCONFLICT, a_pkg, a_msg);

	return (getyorn(a_msg, a_pkg, ADM(conflict, "nocheck"),
		ADM(conflict, "quit"), HLP_PKGADDCHK_CONFLICT,
		ERR_PKGADDCHK_CNFFAILED));
}

/*
 * Trigger:	cksetuid=<<n>>
 * Sequence:	- one or more:
 *		-- setuid=<path>:<owner>
 *		-- setgid=<path>:<group>
 *		-- setuid-overwrite=true
 *		- one: cksetuid=<<n>>
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
cksetuid(char *a_msg, char *a_pkg)
{
	char	ans[MAX_INPUT];
	char	ask_cont[MSG_MAX];
	int	n;
	int	saveCkquit;

	echoDebug(DBG_PREIVFY_CKSETUID, a_pkg, a_msg);

	n = getyorn(a_msg, a_pkg, ADM(setuid, "nocheck"),
		ADM(setuid, "quit"), HLP_PKGADDCHK_SETUID, NULL);

	/* if user did not answer "n" return answer given */

	if (n != 3) {
		return (n);
	}

	(void) snprintf(ask_cont, sizeof (ask_cont), gettext(ASK_CONT), a_pkg);

	saveCkquit = ckquit;
	ckquit = 0;

	n = ckyorn(ans, NULL, NULL, gettext(HLP_PKGADDCHK_CONT), ask_cont);

	ckquit = saveCkquit;

	if (n != 0) {
		ptext(stderr, MSG_PREIVFY_GETYORN_TERM, a_pkg);
		echoDebug(DBG_PREIVFY_GETYORN_CKYORN, a_pkg, n);
		return (n);
	}

	/* return "3 (interruption) if not "y" or "Y" */

	if (strchr("yY", *ans) == NULL) {
		ptext(stderr, MSG_PREIVFY_GETYORN_TERM_USER, a_pkg);
		echoDebug(DBG_PREIVFY_GETYORN_NOT_Y, a_pkg, ans);
		return (3);
	}

	/* return "0 - success" */

	echoDebug(DBG_PREIVFY_GETYORN_SUCCESS, a_pkg);

	return (0);
}

/*
 * Trigger:	ckpriv=<<n>>
 * Sequence:	- one: ckpriv=<<n>>
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
ckpriv(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PREIVFY_CKPRIV, a_pkg, a_msg);

	return (getyorn(a_msg, a_pkg, ADM(action, "nocheck"),
		ADM(action, "quit"), HLP_PKGADDCHK_PRIV,
		ERR_PKGADDCHK_PRIVFAILED));
}

/*
 * Trigger:	ckpkgfiles=<<n>>
 * Sequence:	- one or more:
 *		-- ckpkgfilebad=<path>
 *		- one: ckpkgfiles=<<n>>
 * Return value:	int
 *			0 - success
 *			4 - failure
 */

static int
ckpkgfiles(char *a_msg, char *a_pkg)
{
	echoDebug(DBG_PREIVFY_CKPKGFILES, a_pkg, a_msg);

	ptext(stderr, "%s", a_msg);

	return (4);
}

static int
attrib(char *a_msg, char *a_pkg)
{
	return (getyorn(a_msg, a_pkg, ADM(instance, "nocheck"),
		ADM(instance, "quit"), HLP_PKGADDCHK_CONT,
		ERR_PKGADDCHK_DEPFAILED));
}

/* ARGSUSED1 */
static int
setuidf(char *a_msg, char *a_pkg)
{
	char *cp;

	if ((cp = strchr(a_msg, ':')) != NULL)
		*cp = ' ';
	return (0);
}

/* ARGSUSED1 */
static int
setgidf(char *a_msg, char *a_pkg)
{
	char *cp;

	if ((cp = strchr(a_msg, ':')) != NULL)
		*cp = ' ';
	return (0);
}

static int
overwr(char *a_msg, char *a_pkg)
{
	return (getyorn(a_msg, a_pkg, ADM(instance, "nocheck"),
		ADM(instance, "quit"), HLP_PKGADDCHK_SETUID,
		ERR_PKGADDCHK_DEPFAILED));
}
