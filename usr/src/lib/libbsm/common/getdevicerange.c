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

#include <stdlib.h>
#include <errno.h>
#include <tsol/label.h>
#include <bsm/devices.h>


/*
 * getdevicerange
 *	Gets the minimum and maximum labels within which the device can
 *	be used. If label range is not specified for the device in
 *	device_allocate, defaults to admin_low and admin_high.
 *	Returns malloc'ed blrange pointer, or NULL on any error.
 */
blrange_t *
getdevicerange(const char *dev)
{
	int		err;
	char		*lstr;
	devalloc_t	*da;
	devmap_t	*dm;
	blrange_t	*range;

	errno = 0;
	if ((range = malloc(sizeof (blrange_t))) == NULL)
		return (NULL);
	if ((range->lower_bound = blabel_alloc()) == NULL) {
		free(range);
		return (NULL);
	}
	if ((range->upper_bound = blabel_alloc()) == NULL) {
		blabel_free(range->lower_bound);
		free(range);
		return (NULL);
	}

	/*
	 * If an entry is found for the named device,
	 * return its label range.
	 */
	setdaent();
	if ((da = getdanam((char *)dev)) == NULL) {
		setdmapent();
		/* check for an actual device file */
		if ((dm = getdmapdev((char *)dev)) != NULL) {
			da = getdanam(dm->dmap_devname);
			freedmapent(dm);
		}
		enddmapent();
	}
	enddaent();
	if (da == NULL) {
		bsllow(range->lower_bound);
		bslhigh(range->upper_bound);
	} else {
		lstr = kva_match(da->da_devopts, DAOPT_MINLABEL);
		if (lstr == NULL) {
			bsllow(range->lower_bound);
		} else if (stobsl(lstr, range->lower_bound, NO_CORRECTION,
		    &err) == 0) {
			blabel_free(range->lower_bound);
			blabel_free(range->upper_bound);
			free(range);
			errno = ENOTSUP;
			return (NULL);
		}
		lstr = kva_match(da->da_devopts, DAOPT_MAXLABEL);
		if (lstr == NULL) {
			bslhigh(range->upper_bound);
		} else if (stobsl(lstr, range->upper_bound, NO_CORRECTION,
		    &err) == 0) {
			blabel_free(range->lower_bound);
			blabel_free(range->upper_bound);
			free(range);
			errno = ENOTSUP;
			return (NULL);
		}
		freedaent(da);
	}

	return (range);
}
