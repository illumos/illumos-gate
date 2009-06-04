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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * System includes
 */

#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <locale.h>
#include <libintl.h>
#include <assert.h>

/*
 * local pkg command library includes
 */

#include "libinst.h"
#include "messages.h"

/*
 * forward declarations
 */

static int
collectError(int *r_numZones, char **r_zoneNames, char *a_packageName,
	depckl_t *a_dck, int a_depIndex, depckErrorRecord_t *a_eir,
	int a_errIndex);

/*
 * *****************************************************************************
 * global external (public) functions
 * *****************************************************************************
 */

int
depchkReportErrors(depckl_t *a_dck)
{
	char	*packageName;
	char	*zonenames;
	char	msgbuf[4096];
	int	err;
	int	i;
	int	numzones = 0;

	/* entry assertions */

	assert(a_dck != (depckl_t *)NULL);

	/* entry debugging info */

	echoDebug(DBG_DEPCHK_ENTRY);

	zonenames = (char *)NULL;

	/* go through dependency table, collect, collapse, report errors */

	for (i = 0; a_dck[i].name != (char *)NULL; i++) {
		int	j;
		depckError_t	*erc;

		if (zonenames != (char *)NULL) {
			free(zonenames);
			zonenames = (char *)NULL;
		}

		erc = a_dck[i].record;
		if (erc->er_numEntries == 0) {
			continue;
		}

		for (j = 0; j < erc->er_numEntries; j++) {
			int	k;
			depckErrorRecord_t *eir;

			if (zonenames != (char *)NULL) {
				free(zonenames);
				zonenames = (char *)NULL;
			}

			eir = &erc->er_theEntries[j];
			packageName = eir->ier_packageName;
			for (k = 0; k < eir->ier_numZones; k++) {
				int err;

				err = collectError(&numzones, &zonenames,
					packageName, a_dck, i, eir, k);
				if (err != 0) {
					if (zonenames != (char *)NULL) {
						free(zonenames);
						zonenames = (char *)NULL;
					}
					return (err);
				}
			}

			if (a_dck[i].ignore_values == (char *)NULL) {
				continue;
			}

			if (a_dck[i].err_msg == (char **)NULL) {
				(void) snprintf(msgbuf, sizeof (msgbuf),
					ERR_DEPENDENCY_IGNORED, a_dck[i].name,
					packageName,
					numzones == 1 ? "zone" : "zones",
					zonenames ? zonenames : "?");
			} else {
				/* LINTED variable format specifier to ... */
				(void) snprintf(msgbuf, sizeof (msgbuf),
					*a_dck[i].err_msg, "package",
					packageName,
					numzones == 1 ? "zone" : "zones",
					zonenames ? zonenames : "??");
			}

			if (a_dck[i].depcklFunc != NULL) {
				/* call check function */
				err = (a_dck[i].depcklFunc)(msgbuf,
					packageName);
				echoDebug(DBG_DEPCHK_REPORT_ERROR,
					a_dck[i].ignore_values, err,
					packageName, msgbuf);
				if (err != 0) {
					if (zonenames != (char *)NULL) {
						free(zonenames);
						zonenames = (char *)NULL;
					}
					return (err);
				}
			} else {
				/* no check function - just report message */
				echoDebug(DBG_DEPCHK_IGNORE_ERROR,
					a_dck[i].ignore_values, packageName,
					msgbuf);
				ptext(stderr, "\\n%s", msgbuf);
			}
		}
	}

	if (zonenames != (char *)NULL) {
		free(zonenames);
		zonenames = (char *)NULL;
	}

	return (0);
}

void
depchkRecordError(depckError_t *a_erc, char *a_pkginst,
	char *a_zoneName, char *a_value)
{
	depckErrorRecord_t *erc;
	int		i;

	/*
	 * create new error record and entry if first entry
	 * record will look like this:
	 * err->er_#entry=1
	 * err->entry[0]->record->ier_numZones=1
	 * err->entry[0]->record->ier_packageName=a_pkginst
	 * err->entry[0]->record->ier_zones[0]=a_zoneName
	 * err->entry[0]->record->ier_values[0]=a_value
	 */

	if (a_erc->er_numEntries == 0) {
		depckErrorRecord_t	*eir;

		eir = (depckErrorRecord_t *)calloc(1,
					sizeof (depckErrorRecord_t));
		eir->ier_packageName = strdup(a_pkginst);
		eir->ier_numZones = 1;
		eir->ier_zones = (char **)calloc(1, sizeof (char **));
		(eir->ier_zones)[eir->ier_numZones-1] = strdup(a_zoneName);
		eir->ier_values = (char **)calloc(1, sizeof (char *));
		(eir->ier_values)[eir->ier_numZones-1] = strdup(a_value);

		a_erc->er_numEntries = 1;
		a_erc->er_theEntries = eir;

		echoDebug(DBG_DEPCHK_RECORD_ERROR, (long)a_erc, a_pkginst,
					a_zoneName, a_value);

		return;
	}

	/* see if this package already has an entry if so add zone to list */

	for (i = 0; i < a_erc->er_numEntries; i++) {
		erc = &a_erc->er_theEntries[i];

		if (strcmp(erc->ier_packageName, a_pkginst) != 0) {
			continue;
		}

		echoDebug(DBG_DEPCHK_RECORD_ZERROR, (long)a_erc, a_zoneName,
			a_value, erc->ier_packageName, erc->ier_numZones,
			erc->ier_zones[0]);

		/*
		 * this package already has an entry - add zone to
		 * existing package entry the modified records will
		 * look like this:
		 * err->er_#entry++;
		 * err->entry[0]->...
		 * err->entry[i]->
		 * -------------->record->
		 * ---------------------->ier_numZones++;
		 * ---------------------->ier_packageName=a_pkginst
		 * ---------------------->ier_zones[0]=...
		 * ---------------------->ier_zones[...]=...
		 * ---------------------->ier_zones[ier_numZones-1]=a_zoneName
		 * ---------------------->ier_values[0]=...
		 * ---------------------->ier_values[...]=...
		 * ---------------------->ier_values[ier_numZones-1]=a_value
		 * err->entry[i+1]->...
		 */
		erc->ier_numZones++;
		erc->ier_zones = (char **)realloc(erc->ier_zones,
					sizeof (char **)*erc->ier_numZones);
		(erc->ier_zones)[erc->ier_numZones-1] = strdup(a_zoneName);
		erc->ier_values = (char **)realloc(erc->ier_values,
					sizeof (char **)*erc->ier_numZones);
		(erc->ier_values)[erc->ier_numZones-1] = strdup(a_value);
		return;
	}

	/*
	 * this packages does not have an entry - add new package
	 * entry for this zone the modified records will look like this:
	 * err->er_#entry++;
	 * err->entry[0]->record->ier_numZones=...
	 * err->entry[0]->record->ier_packageName=...
	 * err->entry[0]->record->ier_zones[0]=...
	 * err->entry[0]->record->ier_values[0]=...
	 * err->entry[er_#entry-1]->record->ier_numZones=1
	 * err->entry[er_#entry-1]->record->ier_packageName=a_pkginst
	 * err->entry[er_#entry-1]->record->ier_zones[0]=a_zoneName
	 * err->entry[er_#entry-1]->record->ier_values[0]=a_value
	 */

	echoDebug(DBG_DEPCHK_RECORD_PERROR, (long)a_erc,
			a_erc->er_numEntries, a_pkginst, a_zoneName, a_value);

	a_erc->er_numEntries++;

	a_erc->er_theEntries = realloc(a_erc->er_theEntries,
			sizeof (depckErrorRecord_t)*a_erc->er_numEntries);

	erc = &a_erc->er_theEntries[a_erc->er_numEntries-1];

	erc->ier_packageName = strdup(a_pkginst);
	erc->ier_numZones = 1;
	erc->ier_zones = (char **)calloc(1, sizeof (char *));
	(erc->ier_zones)[erc->ier_numZones-1] = strdup(a_zoneName);
	erc->ier_values = (char **)calloc(1, sizeof (char *));
	(erc->ier_values)[erc->ier_numZones-1] = strdup(a_value);
}

/*
 * *****************************************************************************
 * static internal (private) functions
 * *****************************************************************************
 */

static int
collectError(int *r_numZones, char **r_zoneNames, char *a_packageName,
	depckl_t *a_dck, int a_depIndex, depckErrorRecord_t *a_eir,
	int a_errIndex)
{
	char	msgbuf[4096];
	char	*zn = *r_zoneNames;

	if (a_dck[a_depIndex].ignore_values == (char *)NULL) {
		if (a_dck[a_depIndex].err_msg == (char **)NULL) {
			(void) snprintf(msgbuf, sizeof (msgbuf),
			ERR_DEPENDENCY_REPORT, a_eir->ier_values[a_errIndex],
			"package", a_packageName,
			"zone", a_eir->ier_zones[a_errIndex]);
		} else {
			/* LINTED variable format specifier to snprintf(); */
			(void) snprintf(msgbuf, sizeof (msgbuf),
			*a_dck[a_depIndex].err_msg,
			a_eir->ier_values[a_errIndex],
			"package", a_packageName,
			"zone", a_eir->ier_zones[a_errIndex]);
		}
		if (a_dck[a_depIndex].depcklFunc != NULL) {
			int	err;

			err = (a_dck[a_depIndex].depcklFunc)(msgbuf,
							a_packageName);
			echoDebug(DBG_DEPCHK_COLLECT_ERROR, err, a_packageName,
					msgbuf);
			if (err != 0) {
				return (err);
			}
		} else {
			echoDebug(DBG_DEPCHK_COLLECT_IGNORE, a_packageName,
					msgbuf);
			ptext(stderr, "\\n%s", msgbuf);
		}
		return (0);
	}

	*r_numZones = (*r_numZones)+1;
	if (zn == (char *)NULL) {
		zn = strdup(a_eir->ier_zones[a_errIndex]);
	} else {
		char *p;
		int len = strlen(zn)+strlen(a_eir->ier_zones[a_errIndex])+3;
		p = calloc(1, len);
		(void) snprintf(p, len, "%s, %s", zn,
			a_eir->ier_zones[a_errIndex]);
		free(zn);
		zn = p;

	}
	*r_zoneNames = zn;
	return (0);
}
