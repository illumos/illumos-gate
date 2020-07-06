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
 * Copyright 2020 RackTop Systems, Inc.
 */

#include <smbsrv/smb_ktypes.h>
#include <smbsrv/mbuf.h>

/*
 * not implemented yet
 */
void
smb31_preauth_init_mech(smb_session_t *s)
{
}

void
smb31_preauth_fini(smb_session_t *s)
{
}

int
smb31_preauth_sha512_calc(smb_request_t *sr, struct mbuf_chain *mbc,
    uint8_t *in_hashval, uint8_t *out_hashval)
{
	return (0);
}
