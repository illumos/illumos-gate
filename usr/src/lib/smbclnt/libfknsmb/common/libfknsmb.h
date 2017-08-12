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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_LIBFKNSMB_H_
#define	_LIBFKNSMB_H_

#include <sys/types.h>
#include <sys/types32.h>
#include <sys/cred.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct smb_share;

extern const uint32_t nsmb_version;
extern void streams_msg_init(void);

int nsmb_drv_init(void);
int nsmb_drv_fini(void);
/* These are dev32_t because they're cast to int in user code. */
int nsmb_drv_ioctl(dev32_t dev, int cmd, intptr_t arg, int flags);
int nsmb_drv_open(dev32_t *dev, int flags, int otyp);
int nsmb_drv_close(dev32_t dev, int flags, int otyp);
int smb_dev2share(int fd, struct smb_share **sspp);
void nsmb_drv_load(void);

#ifdef __cplusplus
}
#endif

#endif	/* _LIBFKNSMB_H_ */
