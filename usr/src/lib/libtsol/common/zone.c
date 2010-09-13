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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdlib.h>
#include	<strings.h>
#include	<zone.h>
#include	<errno.h>
#include	<sys/types.h>
#include 	<sys/tsol/label_macro.h>

/*
 * Get label from zone name
 */
m_label_t *
getzonelabelbyname(const char *zone)
{
	zoneid_t	zoneid;

	if ((zoneid = getzoneidbyname(zone)) == -1) {
		errno = EINVAL;
		return (NULL);
	}
	return (getzonelabelbyid(zoneid));
}

/*
 * Get label from zone id
 */
m_label_t *
getzonelabelbyid(zoneid_t zoneid)
{
	m_label_t 	*slabel;

	if ((slabel = m_label_alloc(MAC_LABEL)) == NULL)
		return (NULL);

	if (zone_getattr(zoneid, ZONE_ATTR_SLBL, slabel,
	    sizeof (m_label_t)) < 0) {
		m_label_free(slabel);
		errno = EINVAL;
		return (NULL);
	}

	return (slabel);
}

/*
 * Get zone id from label
 */

zoneid_t
getzoneidbylabel(const m_label_t *label)
{
	m_label_t	admin_low;
	m_label_t	admin_high;
	zoneid_t	zoneid;
	zoneid_t 	*zids;
	uint_t		nzents;
	uint_t		nzents_saved;
	int		i;

	bsllow(&admin_low);
	bslhigh(&admin_high);

	/* Check for admin_low or admin_high; both are global zone */
	if (blequal(label, &admin_low) || blequal(label, &admin_high))
		return (GLOBAL_ZONEID);

	nzents = 0;
	if (zone_list(NULL, &nzents) != 0)
		return (-1);

again:
	if (nzents == 0) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Add a small amount of padding here to avoid spinning in a tight loop
	 * if there's a process running somewhere that's creating lots of zones
	 * all at once.
	 */
	nzents += 8;
	if ((zids = malloc(nzents * sizeof (zoneid_t))) == NULL)
		return (-1);
	nzents_saved = nzents;

	if (zone_list(zids, &nzents) != 0) {
		free(zids);
		return (-1);
	}
	if (nzents > nzents_saved) {
		/* list changed, try again */
		free(zids);
		goto again;
	}

	for (i = 0; i < nzents; i++) {
		m_label_t	test_sl;

		if (zids[i] == GLOBAL_ZONEID)
			continue;

		if (zone_getattr(zids[i], ZONE_ATTR_SLBL, &test_sl,
		    sizeof (m_label_t)) < 0)
			continue;	/* Badly configured zone info */

		if (blequal(label, &test_sl) != 0) {
			zoneid = zids[i];
			free(zids);
			return (zoneid);
		}
	}
	free(zids);
	errno = EINVAL;
	return (-1);
}

/*
 * Get zoneroot for a zoneid
 */

char *
getzonerootbyid(zoneid_t zoneid)
{
	char zoneroot[MAXPATHLEN];

	if (zone_getattr(zoneid, ZONE_ATTR_ROOT, zoneroot,
	    sizeof (zoneroot)) == -1) {
		return (NULL);
	}

	return (strdup(zoneroot));
}

/*
 * Get zoneroot for a zonename
 */

char *
getzonerootbyname(const char *zone)
{
	zoneid_t	zoneid;

	if ((zoneid = getzoneidbyname(zone)) == -1)
		return (NULL);
	return (getzonerootbyid(zoneid));
}

/*
 * Get zoneroot for a label
 */

char *
getzonerootbylabel(const m_label_t *label)
{
	zoneid_t	zoneid;

	if ((zoneid = getzoneidbylabel(label)) == -1)
		return (NULL);
	return (getzonerootbyid(zoneid));
}

/*
 * Get label of path relative to global zone
 *
 * This function must be called from the global zone
 */

m_label_t *
getlabelbypath(const char *path)
{
	m_label_t	*slabel;
	zoneid_t 	*zids;
	uint_t		nzents;
	uint_t		nzents_saved;
	int		i;

	if (getzoneid() != GLOBAL_ZONEID) {
		errno = EINVAL;
		return (NULL);
	}

	nzents = 0;
	if (zone_list(NULL, &nzents) != 0)
		return (NULL);

again:
	/* Add a small amount of padding to avoid loops */
	nzents += 8;
	zids = malloc(nzents * sizeof (zoneid_t));
	if (zids == NULL)
		return (NULL);

	nzents_saved = nzents;

	if (zone_list(zids, &nzents) != 0) {
		free(zids);
		return (NULL);
	}
	if (nzents > nzents_saved) {
		/* list changed, try again */
		free(zids);
		goto again;
	}

	slabel = m_label_alloc(MAC_LABEL);
	if (slabel == NULL) {
		free(zids);
		return (NULL);
	}

	for (i = 0; i < nzents; i++) {
		char	zoneroot[MAXPATHLEN];
		int	zonerootlen;

		if (zids[i] == GLOBAL_ZONEID)
			continue;

		if (zone_getattr(zids[i], ZONE_ATTR_ROOT, zoneroot,
		    sizeof (zoneroot)) == -1)
			continue;	/* Badly configured zone info */

		/*
		 * Need to handle the case for the /dev directory which is
		 * parallel to the zone's root directory.  So we back up
		 * 4 bytes - the strlen of "root".
		 */
		if ((zonerootlen = strlen(zoneroot)) <= 4)
			continue;	/* Badly configured zone info */
		if (strncmp(path, zoneroot, zonerootlen - 4) == 0) {
			/*
			 * If we get a match, the file is in a labeled zone.
			 * Return the label of that zone.
			 */
			if (zone_getattr(zids[i], ZONE_ATTR_SLBL, slabel,
			    sizeof (m_label_t)) < 0)
				continue;	/* Badly configured zone info */

			free(zids);
			return (slabel);
		}
	}
	free(zids);
	bsllow(slabel);
	return (slabel);
}
