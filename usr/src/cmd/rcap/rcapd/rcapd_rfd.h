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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _RCAPD_RFD_H
#define	_RCAPD_RFD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include "rcapd.h"

/*
 * Classes of cached, revocable file descriptors
 */
typedef enum {
	RFD_PAGEDATA = 1,	/* pagedata is always preferred over psinfo */
	RFD_PSINFO,		/* psinfo, at least one of which is */
				/* cached at any time */
	RFD_XMAP,		/* xmap */
	RFD_RESERVED		/* opened for use by external consumers */
} rfd_class_t;

/*
 * Revocable file descriptor
 */
typedef struct rfd {
	int rfd_fd;				/* cached descriptor */
	rfd_class_t rfd_class;			/* class of descriptor */
	void(*rfd_revoke)(struct rfd *);	/* revocation function */
	void *rfd_data;				/* supplied data */

	struct rfd *rfd_next;			/* list */
	struct rfd *rfd_prev;

	struct rfd *rfd_prev_class;		/* link to previous of same */
						/* class */
} rfd_t;

int rfd_close(int);
int rfd_open(char *, int, rfd_class_t, void(*)(struct rfd *), void *, int,
    mode_t);
int rfd_reserve(int);

#ifdef	__cplusplus
}
#endif

#endif /* _RCAPD_RFD_H */
