/*
 * Copyright (c) 2000-2001 Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Selected code from smb_conn.c
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * Helper functions for smb_trantcp.c
 * (and maybe future transports)
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

/* Like smb_dev.h, this knows about all our sockaddr formats. */
#include <netsmb/netbios.h>

#ifdef APPLE
#include <sys/smb_apple.h>
#else
#include <netsmb/smb_osdep.h>
#endif

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_tran.h>

/*
 * Return the length of a sockaddr structure.
 * Only needs to handle the address formats
 * used by smb_dup_sockaddr.
 */
static size_t
SA_LEN(struct sockaddr *sa)
{
	size_t len;

	switch (sa->sa_family) {
	case AF_INET:
		len = sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		len = sizeof (struct sockaddr_in6);
		break;
	case AF_NETBIOS:
		len = sizeof (struct sockaddr_nb);
		break;
	default:
		SMBSDEBUG("invalid address family %d\n", sa->sa_family);
		len = sizeof (struct sockaddr);
		break;
	}

	return (len);
}

/*
 * Compare two sockaddr contents
 * Return zero if identical.
 */
int
smb_cmp_sockaddr(struct sockaddr *a1, struct sockaddr *a2)
{
	size_t l1, l2;

	l1 = SA_LEN(a1);
	l2 = SA_LEN(a2);

	if (l1 != l2)
		return (-1);

	return (bcmp(a1, a2, l1));
}

/*
 * Copy a socket address of varying size.
 */
struct sockaddr *
smb_dup_sockaddr(struct sockaddr *sa)
{
	struct sockaddr *sa2;
	size_t len;

	/* Get the length (varies per family) */
	len = SA_LEN(sa);

	sa2 = kmem_alloc(len, KM_SLEEP);
	if (sa2)
		bcopy(sa, sa2, len);

	return (sa2);
}

void
smb_free_sockaddr(struct sockaddr *sa)
{
	size_t len;

	/* Get the length (varies per family) */
	len = SA_LEN(sa);

	kmem_free(sa, len);
}
