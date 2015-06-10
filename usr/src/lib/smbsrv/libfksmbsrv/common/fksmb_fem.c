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

#include <sys/fcntl.h>

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>


/*
 * smb_fem_init
 */
int
smb_fem_init(void)
{
	return (0);
}

/*
 * smb_fem_fini
 */
void
smb_fem_fini(void)
{
}

/* ARGSUSED */
int
smb_fem_fcn_install(smb_node_t *node)
{
	return (0);
}

/* ARGSUSED */
void
smb_fem_fcn_uninstall(smb_node_t *node)
{
}

/* ARGSUSED */
int
smb_fem_oplock_install(smb_node_t *node)
{
	return (0);
}

/* ARGSUSED */
void
smb_fem_oplock_uninstall(smb_node_t *node)
{
}
