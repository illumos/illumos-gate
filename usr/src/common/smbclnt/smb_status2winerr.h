/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SMB_STATUS2WINERR_H_
#define	_SMB_STATUS2WINERR_H_

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct status2winerr {
	uint_t status;
	uint_t winerr;
};

/* This is a zero-terminated table. */
extern const struct status2winerr smb_status2winerr_map[];

#ifdef	__cplusplus
}
#endif

#endif /* _SMB_STATUS2WINERR_H_ */
