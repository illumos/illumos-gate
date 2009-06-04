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

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>
#include <pkgdev.h>
#include <pkginfo.h>
#include <pkglocs.h>
#include <locale.h>
#include <libintl.h>
#include <instzones_api.h>
#include <pkglib.h>
#include <install.h>
#include <libinst.h>
#include <libadm.h>
#include <messages.h>

static char *localeNames[] = {
	"LC_CTYPE",
	"LC_NUMERIC",
	"LC_TIME",
	"LC_COLLATE",
	"LC_MESSAGES",
	"LC_MONETARY",
	"LC_ALL",
	"LANG",
	"TZ",
	NULL
};

#define	NUM_LOCALE_TYPES	100

static char	*envPtr[NUM_LOCALE_TYPES];

/*
 * extern declarations
 */

extern char	**environ;

/*
 * this is the initial and incremental allocation used to
 * populate the environment "environ"
 */

#define	MALSIZ	64

void
putparam(char *param, char *value)
{
	char	*pt;
	int	ptlen;
	int	i, n;

	/*
	 * If the environment is NULL, allocate space for the
	 * character pointers.
	 */
	if (environ == NULL) {
		environ = (char **)calloc(MALSIZ, sizeof (char *));
		if (environ == NULL) {
			progerr(gettext(ERR_MEMORY), errno);
			quit(99);
		}
	}

	/*
	 * If this parameter is already in place and it has a different
	 * value, clear the old value by freeing the memory previously
	 * allocated. Otherwise, we leave well-enough alone.
	 */
	n = strlen(param);
	for (i = 0; environ[i]; i++) {
		if (strncmp(environ[i], param, n) == 0 &&
		    (environ[i][n] == '=')) {
			if (strcmp((environ[i]) + n + 1, value) == 0)
				return;
			else {
				free(environ[i]);
				break;
			}
		}
	}

	/* Allocate space for the new environment entry. */
	ptlen = (strlen(param)+strlen(value)+2)*(sizeof (char));
	pt = (char *)calloc(strlen(param)+strlen(value)+2, sizeof (char));
	if (pt == NULL) {
		progerr(gettext(ERR_MEMORY), errno);
		quit(99);
	}

	/*
	 * Put the statement into the allocated space and point the
	 * environment entry at it.
	 */
	(void) snprintf(pt, ptlen, "%s=%s", param, value);
	if (environ[i]) {
		environ[i] = pt;
		return;
	}

	/*
	 * With this parameter in place, if we're at the end of the
	 * allocated environment then allocate more space.
	 */
	environ[i++] = pt;
	if ((i % MALSIZ) == 0) {
		environ = (char **)realloc((void *)environ,
			(i+MALSIZ)*sizeof (char *));
		if (environ == NULL) {
			progerr(gettext(ERR_MEMORY), errno);
			quit(1);
		}
	}

	/* Terminate the environment properly. */
	environ[i] = (char *)NULL;
}

/* bugid 4279039 */
void
getuserlocale(void)
{
	int i;

	for (i = 0; (localeNames[i] != NULL) && (i < NUM_LOCALE_TYPES); i++) {
		envPtr[i] = getenv(localeNames[i]);
		if (envPtr[i]) {
			putparam(localeNames[i], envPtr[i]);
		}
	}
}

/* bugid 4279039 */
void
putuserlocale(void)
{
	int i;

	for (i = 0; (localeNames[i] != NULL) && (i < NUM_LOCALE_TYPES); i++) {
		if (envPtr[i]) {
			putparam(localeNames[i], envPtr[i]);
		}
	}
}

/*
 * Name:	putConditionInfo
 * Description:	put parent "condition" information to environment
 * Arguments:	a_parentZoneName - name of the parent zone
 *			== NULL - no name
 *		a_parentZoneType - parent zone "type"
 *			== NULL - no type
 * Returns:	void
 */

void
putConditionInfo(char *a_parentZoneName, char *a_parentZoneType)
{
	char	**pp;
	char	*p;
	char	*pa;
	SML_TAG	*tag = SML_TAG__NULL;
	SML_TAG	*ntag;

	/* entry debugging info */

	echoDebug(DBG_PUTPARAM_PUTCONDINFO_ENTRY);

	/*
	 * create tag to hold condition information:
	 * <environmentConditionInformation>
	 * <parentZone zoneName=<?> zoneType=<?>/>
	 * <currentZone zoneName=<?> zoneType=<?>/>
	 * <inheritedFileSystem fileSystemName=<?>/>
	 * </environmentConditionInformation>
	 */

	tag = smlNewTag(TAG_COND_TOPLEVEL);

	/*
	 * information about pkgadd or pkgrm environment
	 * <parentZone zoneName=<?> zoneType=<?>/>
	 */

	/* allocate tag for parent info */

	ntag = smlNewTag(TAG_COND_PARENT_ZONE);

	/* parent zone name */

	smlSetParam(ntag, TAG_COND_ZONE_NAME,
		a_parentZoneName ? a_parentZoneName : "");

	/* parent zone info */

	smlSetParam(ntag, TAG_COND_ZONE_TYPE,
		a_parentZoneType ? a_parentZoneType : "");

	/* add to top level tag */

	(void) smlAddTag(&tag, -1, ntag);
	free(ntag);

	/*
	 * information about pkginstall or pkgremove environment
	 * <currentZone zoneName=<?> zoneType=<?>/>
	 */

	/* allocate tag for parent info */

	ntag = smlNewTag(TAG_COND_CURRENT_ZONE);

	/* current zone name */

	p = z_get_zonename();
	if ((p != NULL) && (*p != '\0')) {
		smlSetParam(ntag, TAG_COND_ZONE_NAME, p);
		free(p);
	}

	/* current zone type */

	smlSetParam(ntag, TAG_COND_ZONE_TYPE,
		z_running_in_global_zone() == B_TRUE ?
			TAG_VALUE_GLOBAL_ZONE : TAG_VALUE_NONGLOBAL_ZONE);

	/* add to top level tag */

	(void) smlAddTag(&tag, -1, ntag);
	free(ntag);

	/*
	 * describe any inherited file systems:
	 * <inheritedFileSystem fileSystemName=<?>/>
	 */

	pp = z_get_inherited_file_systems();
	if (pp != (char **)NULL) {
		int n;
		for (n = 0; pp[n] != (char *)NULL; n++) {
			/* allocate tag for inherited file system info */

			ntag = smlNewTag(TAG_COND_INHERITED_FS);

			/* inherited file system */

			smlSetParam(ntag, TAG_COND_FS_NAME, pp[n]);

			/* add to top level tag */

			(void) smlAddTag(&tag, -1, ntag);
			free(ntag);
		}
	}

	/*
	 * done filling in tag - convert to string and place in environment
	 */

	p = smlConvertTagToString(tag);

	/* convert all new-line characters to space */

	for (pa = p; *pa != '\0'; pa++) {
		if (*pa == '\n') {
			*pa = ' ';
		}
	}

	echoDebug(DBG_PUTPARAM_PUTCONDINFO_EXIT, p);

	putparam(PKGCOND_GLOBAL_VARIABLE, p);
}
