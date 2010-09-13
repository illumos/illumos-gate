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
/*
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _DHCPTAB_H
#define	_DHCPTAB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Implementation-specific data structures and constants for the binary
 * dhcptab container.  These structures are subject to change at any time.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <dhcp_svc_public.h>

#define	DT_NOREC	0		/* "no record" id value */
#define	DT_MAGIC	0x0d6c94ab	/* "dhcptab" in a hexadecimal world */

/*
 * Constants for use with find_dt
 */
#define	FIND_PARTIAL	0x0001		/* allow partial success */
#define	FIND_POSITION	0x0002 		/* return dt_recpos_t's */

/*
 * Header atop the dhcptab container -- contains some basic information
 * about the container for sanity-checking purposes.
 */
typedef struct dt_header {
	unsigned char	dth_version;	/* container version */
	unsigned char	dth_align[3]; 	/* ensure binary compatibility */
	uint32_t	dth_magic;	/* magic for sanity check */
	uint32_t	dth_pad[4];	/* for future use */
} dt_header_t;

/*
 * What each dt_rec_t looks like on-disk -- note that we cannot just write
 * dt_rec_t's because the `dt_value' field can be arbitrarily large.
 * Instead, write out the dt_rec_t structure followed by the variable-size
 * `rec_dtval' array which will contain the current value of `dt_value'.
 * Since `rec_dtval' is of variable size, we must explicitly keep track of
 * its length via `rec_dtvalsize'.
 */
typedef struct dt_filerec {
	dt_rec_t	rec_dt;		/* actual dt_rec_t */
	uint32_t	rec_dtvalsize;	/* total size of rec_dtval */
	char		rec_dtval[1];	/* dt_value field from dt_rec_t */
} dt_filerec_t;

/*
 * Per-record state describing the underlying record, including its
 * position on-disk; these are returned instead of dt_rec_t's when find_dt
 * is called with FIND_POSITION set.  Note that for this to work, the
 * dt_rec_t must be the first member.
 */
typedef struct dt_recpos {
	dt_rec_t	dtp_rec;	/* traditional dt_rec_t */
	size_t		dtp_size;	/* its size in the file */
	off_t		dtp_off;	/* its starting offset in the file */
} dt_recpos_t;

/*
 * Per-instance state for each handle returned from open_dt
 */
typedef struct dt_handle {
	unsigned int	dh_oflags;		 /* flags passed into open_dt */
	char		dh_location[MAXPATHLEN]; /* location of container */
} dt_handle_t;

#ifdef __cplusplus
}
#endif

#endif /* _DHCPTAB_H */
