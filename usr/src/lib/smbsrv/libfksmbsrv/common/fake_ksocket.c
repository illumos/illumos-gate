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
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * Shim to implement ksocket_sendmblk on top of ksocket_sendmsg
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/ksocket.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <umem.h>

int
ksocket_sendmblk(ksocket_t ks, struct nmsghdr *msg, int flags,
    mblk_t **mpp, cred_t *cr)
{
	struct msghdr	tmsg;
	mblk_t		*m;
	iovec_t		*iov = NULL;
	size_t		iov_sz = 0;
	size_t		tlen, sent;
	int		i, nseg;
	int		rc;

	/*
	 * Setup the IOV.  First, count the number of IOV segments
	 * and get the total length.
	 */
	nseg = 0;
	tlen = 0;
	m = *mpp;
	while (m != NULL) {
		nseg++;
		tlen += MBLKL(m);
		m = m->b_cont;
	}
	ASSERT(tlen > 0);
	if (tlen == 0) {
		rc = 0;
		goto out;
	}

	iov_sz = nseg * sizeof (iovec_t);
	iov = kmem_alloc(iov_sz, KM_SLEEP);

	/*
	 * Build the iov list
	 */
	i = 0;
	m = *mpp;
	while (m != NULL) {
		iov[i].iov_base = (void *) m->b_rptr;
		iov[i++].iov_len = MBLKL(m);
		m = m->b_cont;
	}
	ASSERT3S(i, ==, nseg);

	bzero(&tmsg, sizeof (tmsg));
	tmsg.msg_iov = iov;
	tmsg.msg_iovlen = nseg;
	while (tlen > 0) {
		sent = 0;
		rc = ksocket_sendmsg(ks, &tmsg, 0, &sent, CRED());
		if (rc != 0)
			break;
		tlen -= sent;
	}

out:
	if (iov != NULL)
		kmem_free(iov, iov_sz);
	if (*mpp != NULL) {
		freemsg(*mpp);
		*mpp = NULL;
	}

	return (rc);
}
