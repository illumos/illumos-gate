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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _DHCP_NETWORK_H
#define	_DHCP_NETWORK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>

/*
 * Implementation-specific data structures and constants for the files0
 * dhcp_network container.  These are subject to change at any time.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Per-record state describing the underlying record, including its
 * position on-disk.
 */
typedef struct dn_recpos {
	dn_rec_t	dnp_rec;	/* traditional record */
	size_t		dnp_size;	/* its size in the file */
	off_t		dnp_off;	/* its starting offset in the file */
} dn_recpos_t;

/*
 * Per-instance state for each instance of an open_dn().
 */
typedef struct dn_handle {
	unsigned int	dh_oflags;	/* flags passed into open_dn() */
	char		dh_location[MAXPATHLEN];
	ipaddr_t	dh_net;
} dn_handle_t;

/*
 * Order of the fields in the on-disk record.
 */
enum { DNF_CID, DNF_FLAGS, DNF_CIP, DNF_SIP, DNF_LEASE, DNF_MACRO,
    DNF_COMMENT };

#define	DNF_MAX_FIELDS		7	/* maximum number of fields */
#define	DNF_REQ_FIELDS		5	/* number of required fields */
#define	DNF_COMMENT_CHAR	'#'

/*
 * Constants for use with find_dn().
 */
#define	FIND_PARTIAL	0x0001		/* allow partial success */
#define	FIND_POSITION	0x0002 		/* return dn_recpos_t's */

#ifdef	__cplusplus
}
#endif

#endif	/* _DHCP_NETWORK_H */
