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
 * Copyright 2024 Racktop Systems, Inc.
 */
#ifndef _LMRC_IOCTL_H
#define	_LMRC_IOCTL_H

#include <sys/cred.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/scsi/adapters/mfi/mfi_ioctl.h>

int lmrc_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

#endif /* _LMRC_IOCTL_H */
