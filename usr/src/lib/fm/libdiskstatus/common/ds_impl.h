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
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_DS_IMPL_H
#define	_DS_IMPL_H

#include <dlfcn.h>
#include <libnvpair.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct disk_status;

typedef struct ds_transport {
	void		*(*dt_open)(struct disk_status *);
	void		(*dt_close)(void *);
	int		(*dt_scan)(void *);
} ds_transport_t;

struct disk_status {
	char			*ds_path;	/* path to device */
	int			ds_fd;		/* device file descriptor */
	ds_transport_t		*ds_transport;	/* associated transport */
	void			*ds_data;	/* transport-specific data */
	int			ds_faults;	/* mask of current faults */
	nvlist_t		*ds_overtemp;	/* overtemp */
	nvlist_t		*ds_predfail;	/* predict fail */
	nvlist_t		*ds_testfail;	/* self test fail */
	nvlist_t		*ds_ssmwearout;	/* SSM wearout fail */
	int			ds_error;	/* last error */
	nvlist_t		*ds_state;	/* protocol state */
};

#define	DS_FAULT_OVERTEMP	0x1
#define	DS_FAULT_PREDFAIL	0x2
#define	DS_FAULT_TESTFAIL	0x4
#define	DS_FAULT_SSMWEAROUT	0x8

extern void dprintf(const char *, ...);
extern void ddump(const char *, const void *, size_t);
extern boolean_t ds_debug;

extern int ds_set_errno(struct disk_status *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _DS_IMPL_H */
