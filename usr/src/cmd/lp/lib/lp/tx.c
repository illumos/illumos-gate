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

#include <sys/types.h>
#include <sys/zone.h>
#include <syslog.h>
#include <strings.h>

#include <ucred.h>
#include "tsol/label.h"
/* lpsched include files */
#if defined PS_FAULTED
#undef  PS_FAULTED
#endif /* PS_FAULTED */
#include "lp.h"

/*
 * get_labeled_zonename - gets the the zonename with the same label.
 *
 *	Input:
 *		slabel - USER_CLEAR label to match
 *
 *	Output:
 *		-1 - zonename with that label could not be found
 *			or no memory for zonename
 *		 0 - label was GLOBAL_ZONENAME
 *		 addr - zonename of zone matching USER_CLEAR label
 *			must be retuened by calling Free(addr)
 *
 */

char *
get_labeled_zonename(char *slabel)
{
	m_label_t	*bsl = NULL;
	int	err = 0;
	ssize_t	zonename_size = -1;
	zoneid_t	zid = -1;
	char *zname = NULL;

	syslog(LOG_DEBUG, "lpsched: get_labeled_zonename %s", slabel);
	/*
	 * convert the label to binary.
	 */
	if (str_to_label(slabel, &bsl, USER_CLEAR,
	    L_NO_CORRECTION, &err) == -1) {
		/* label could not be converted, error */
		syslog(LOG_WARNING,
		    "lpsched: %s: label not recognized (error==%d)",
		    slabel, err);
		return ((char *)-1);
	}
	if ((zid = getzoneidbylabel(bsl)) < 0) {
		/* no zone with that label, cannot send mail */
		syslog(LOG_WARNING,
		    "lpsched: cannot send mail, no zone with %s label",
		    slabel);
		m_label_free(bsl);
		return ((char *)-1);
	}
	zname = Malloc(ZONENAME_MAX + 1);
	if ((zonename_size = getzonenamebyid(zid, zname, ZONENAME_MAX + 1))
	    == -1) {
		/* cannot get zone name, cannot send mail */
		syslog(LOG_WARNING,
		    "lpsched: cannot send mail, no zone name for %s",
		    slabel);
		m_label_free(bsl);
		Free(zname);
		return ((char *)-1);
	} else {
		m_label_free(bsl);
		if (strcmp(zname, GLOBAL_ZONENAME) == 0) {
			Free(zname);
			zname = NULL;
		}
	}
	return (zname);
}

int
get_peer_label(int fd, char **slabel)
{
	if (is_system_labeled()) {
		ucred_t *uc = NULL;
		m_label_t *sl;
		char *pslabel = NULL; /* peer's slabel */

		if ((fd < 0) || (slabel == NULL)) {
			errno = EINVAL;
			return (-1);
		}

		if (getpeerucred(fd, &uc) == -1)
			return (-1);

		sl = ucred_getlabel(uc);
		if (label_to_str(sl, &pslabel, M_INTERNAL, DEF_NAMES) != 0)
			syslog(LOG_WARNING, "label_to_str(): %m");
		ucred_free(uc);

		if (pslabel != NULL) {
			syslog(LOG_DEBUG, "get_peer_label(%d, %s): becomes %s",
				fd, (*slabel ? *slabel : "NULL"), pslabel);
			if (*slabel != NULL)
				free(*slabel);
			*slabel = strdup(pslabel);
		}
	}

	return (0);
}
