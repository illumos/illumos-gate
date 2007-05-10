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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBDISKSTATUS_H
#define	_LIBDISKSTATUS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libnvpair.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct disk_status disk_status_t;

/*
 * Error definitions
 */
#define	EDS_BASE	2000

enum {
	EDS_NOMEM = EDS_BASE,		/* memory allocation failure */
	EDS_CANT_OPEN,			/* failed to open device */
	EDS_NO_TRANSPORT,		/* no supported transport */
	EDS_NOT_SUPPORTED,		/* status information not supported */
	EDS_NOT_SIMULATOR,		/* not a valid simulator file */
	EDS_IO				/* I/O error */
};

/*
 * Basic library functions
 */
extern disk_status_t *disk_status_open(const char *, int *);
extern void disk_status_close(disk_status_t *);
extern const char *disk_status_errmsg(int);
extern void disk_status_set_debug(boolean_t);
extern int disk_status_errno(disk_status_t *);

/*
 * Miscellaneous functions.
 */
extern const char *disk_status_path(disk_status_t *);

/*
 * Main entry point.
 */
extern nvlist_t *disk_status_get(disk_status_t *);

/*
 * Utility function to simulate predictive failure (device-specific).
 */
extern int disk_status_test_predfail(disk_status_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDISKSTATUS_H */
