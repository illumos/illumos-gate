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
 * Example using the "smb2" dtrace provider.
 * Traces all SMB commands.
 *
 * All these probes provide:
 *	args[0]  conninfo_t
 *	args[1]  smb2opinfo_t
 * Some also provide one of: (not used here)
 *	args[2]  smb_open_args_t
 *	args[2]  smb_rw_args_t
 */

smb2:::op-*-start
{
	printf("clnt=%s mid=0x%x uid=0x%x tid=0x%x\n",
	       args[0]->ci_remote,
	       args[1]->soi_mid,
	       args[1]->soi_uid,
	       args[1]->soi_tid);
}

smb2:::op-*-done
{
	printf("clnt=%s mid=0x%x status=0x%x\n",
	       args[0]->ci_remote,
	       args[1]->soi_mid,
	       args[1]->soi_status);
}
