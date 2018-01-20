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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Find existing an VC given a list of addresses.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <libintl.h>
#include <xti.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/byteorder.h>
#include <sys/socket.h>
#include <sys/fcntl.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <netsmb/smb.h>
#include <netsmb/smb_lib.h>
#include <netsmb/netbios.h>
#include <netsmb/nb_lib.h>
#include <netsmb/smb_dev.h>

#include "charsets.h"
#include "private.h"

/*
 * Ask the driver if it has a VC with this IP address.
 */
static int
findvc(struct smb_ctx *ctx, struct addrinfo *ai)
{
	smbioc_ossn_t *ssn = &ctx->ct_ssn;

	/*
	 * Copy the passed address into ssn_srvaddr,
	 * but first sanity-check lengths.  Also,
	 * zero it first to avoid trailing junk.
	 */
	if (ai->ai_addrlen > sizeof (ssn->ssn_srvaddr))
		return (EINVAL);
	bzero(&ssn->ssn_srvaddr, sizeof (ssn->ssn_srvaddr));
	bcopy(ai->ai_addr, &ssn->ssn_srvaddr, ai->ai_addrlen);

	if (nsmb_ioctl(ctx->ct_dev_fd, SMBIOC_SSN_FIND, ssn) == -1)
		return (errno);

	return (0);
}

/*
 * Find (and reuse) an existing VC.
 * See also: newvc.c
 */
int
smb_ctx_findvc(struct smb_ctx *ctx)
{
	struct addrinfo *ai;
	int err;

	/* Should already have the address list. */
	if ((ctx->ct_flags & SMBCF_RESOLVED) == 0)
		return (EINVAL);

	if (ctx->ct_dev_fd < 0) {
		if ((err = smb_ctx_gethandle(ctx)))
			return (err);
	}

	for (ai = ctx->ct_addrinfo; ai; ai = ai->ai_next) {

		switch (ai->ai_family) {

		case AF_INET:
		case AF_INET6:
		case AF_NETBIOS:
			err = findvc(ctx, ai);
			break;

		default:
			DPRINT("skipped family %d", ai->ai_family);
			err = EPROTONOSUPPORT;
			break;
		}

		if (err == 0) {
			/* re-use an existing VC */
			return (0);
		}
	}

	return (ENOENT);
}

/*
 * Forcibly disconnect the current session, even if
 * there are others using it!  This is used by the
 * SMB server netlogon when it wants to setup a new
 * logon session and does not want any re-use.
 */
int
smb_ctx_kill(struct smb_ctx *ctx)
{

	if (nsmb_ioctl(ctx->ct_dev_fd, SMBIOC_SSN_KILL, NULL) == -1)
		return (errno);

	return (0);
}
