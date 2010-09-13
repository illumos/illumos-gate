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

#include <sys/types.h>
#include <stdio.h>
#include <dhcp_svc_public.h>

/*
 * Implementation-specific data structures for the files dhcptab container.
 * These structures are subject to change at any time.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Per-record state describing the underlying record, including its
 * position on-disk.
 */
typedef struct dt_recpos {
	dt_rec_t	dtp_rec;	/* traditional record */
	size_t		dtp_size;	/* its size in the file */
	off_t		dtp_off;	/* its starting offset in the file */
} dt_recpos_t;

/*
 * Per-instance state for each instance of an open_dt()
 */
typedef struct dt_handle {
	unsigned int	dh_oflags;	/* flags passed into open_dt() */
	char		dh_location[MAXPATHLEN];
} dt_handle_t;

/*
 * Order of the fields in the on-disk record.
 */
enum { DTF_KEY, DTF_TYPE, DTF_SIG, DTF_VALUE };

#define	DTF_FIELDS		4	/* number of fields */
#define	DTF_COMMENT_CHAR	'#'

/*
 * Constants for use with find_dt()
 */
#define	FIND_PARTIAL	0x0001		/* allow partial success */
#define	FIND_POSITION	0x0002 		/* return dt_recpos_t's */

#ifdef	__cplusplus
}
#endif

#endif	/* _DHCPTAB_H */
