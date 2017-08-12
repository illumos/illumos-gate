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

/*
 * pkey stubs
 */

#include <sys/types.h>
#include <sys/cred.h>
#include <sys/errno.h>

#include <netsmb/smb_dev.h>
#include <netsmb/smb_pass.h>

void
smb_pkey_init()
{
}

void
smb_pkey_fini()
{
}

int
smb_pkey_idle()
{
	return (0);
}

/* ARGSUSED */
int
smb_pkey_ioctl(int cmd, intptr_t arg, int flags, cred_t *cr)
{
	return (ENOTTY);
}
