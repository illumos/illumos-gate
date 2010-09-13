/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	_XPG4_2
#define	__EXTENSIONS__

#include <assert.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stropts.h>
#include <stdio.h>
#include <strings.h>
#include <netinet/in.h>
#include <netinet/sctp.h>

/* This will hold either a v4 or a v6 sockaddr */
union sockaddr_storage_v6 {
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
};

/*
 * This file implements all the libsctp calls.
 */

/*
 * To bind a list of addresses to a socket.  If the socket is
 * v4, the type of the list of addresses is (struct in_addr).
 * If the socket is v6, the type is (struct in6_addr).
 */
int
sctp_bindx(int sock, void *addrs, int addrcnt, int flags)
{
	socklen_t sz;

	if (addrs == NULL || addrcnt == 0) {
		errno = EINVAL;
		return (-1);
	}

	/* Assume the caller uses the correct family type. */
	switch (((struct sockaddr *)addrs)->sa_family) {
	case AF_INET:
		sz = sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		sz = sizeof (struct sockaddr_in6);
		break;
	default:
		errno = EAFNOSUPPORT;
		return (-1);
	}

	switch (flags) {
	case SCTP_BINDX_ADD_ADDR:
		return (setsockopt(sock, IPPROTO_SCTP, SCTP_ADD_ADDR, addrs,
		    sz * addrcnt));
	case SCTP_BINDX_REM_ADDR:
		return (setsockopt(sock, IPPROTO_SCTP, SCTP_REM_ADDR, addrs,
		    sz * addrcnt));
	default:
		errno = EINVAL;
		return (-1);
	}
}

/*
 * XXX currently not atomic -- need a better way to do this.
 */
int
sctp_getpaddrs(int sock, sctp_assoc_t id, void **addrs)
{
	uint32_t naddrs;
	socklen_t bufsz;
	struct sctpopt opt;

	if (addrs == NULL) {
		errno = EINVAL;
		return (-1);
	}

	/* First, find out how many peer addresses there are. */
	*addrs = NULL;

	opt.sopt_aid = id;
	opt.sopt_name = SCTP_GET_NPADDRS;
	opt.sopt_val = (caddr_t)&naddrs;
	opt.sopt_len = sizeof (naddrs);
	if (ioctl(sock, SIOCSCTPGOPT, &opt) == -1) {
		return (-1);
	}
	if (naddrs == 0)
		return (0);

	/*
	 * Now we can get all the peer addresses.  This will over allocate
	 * space for v4 socket.  But it should be OK and save us
	 * the job to find out if it is a v4 or v6 socket.
	 */
	bufsz = sizeof (union sockaddr_storage_v6) * naddrs;
	if ((*addrs = malloc(bufsz)) == NULL) {
		return (-1);
	}
	opt.sopt_name = SCTP_GET_PADDRS;
	opt.sopt_val = *addrs;
	opt.sopt_len = bufsz;
	if (ioctl(sock, SIOCSCTPGOPT, &opt) == -1) {
		free(*addrs);
		*addrs = NULL;
		return (-1);
	}

	/* Calculate the number of addresses returned. */
	switch (((struct sockaddr *)*addrs)->sa_family) {
	case AF_INET:
		naddrs = opt.sopt_len / sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		naddrs = opt.sopt_len / sizeof (struct sockaddr_in6);
		break;
	}
	return (naddrs);
}

void
sctp_freepaddrs(void *addrs)
{
	free(addrs);
}

int
sctp_getladdrs(int sock, sctp_assoc_t id, void **addrs)
{
	uint32_t naddrs;
	socklen_t bufsz;
	struct sctpopt opt;

	if (addrs == NULL) {
		errno = EINVAL;
		return (-1);
	}

	/* First, try to find out how many bound addresses there are. */
	*addrs = NULL;

	opt.sopt_aid = id;
	opt.sopt_name = SCTP_GET_NLADDRS;
	opt.sopt_val = (caddr_t)&naddrs;
	opt.sopt_len = sizeof (naddrs);
	if (ioctl(sock, SIOCSCTPGOPT, &opt) == -1) {
		return (-1);
	}
	if (naddrs == 0)
		return (0);

	/*
	 * Now we can get all the bound addresses.  This will over allocate
	 * space for v4 socket.  But it should be OK and save us
	 * the job to find out if it is a v4 or v6 socket.
	 */
	bufsz = sizeof (union sockaddr_storage_v6) * naddrs;
	if ((*addrs = malloc(bufsz)) == NULL) {
		return (-1);
	}
	opt.sopt_name = SCTP_GET_LADDRS;
	opt.sopt_val = *addrs;
	opt.sopt_len = bufsz;
	if (ioctl(sock, SIOCSCTPGOPT, &opt) == -1) {
		free(*addrs);
		*addrs = NULL;
		return (-1);
	}

	/* Calculate the number of addresses returned. */
	switch (((struct sockaddr *)*addrs)->sa_family) {
	case AF_INET:
		naddrs = opt.sopt_len / sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		naddrs = opt.sopt_len / sizeof (struct sockaddr_in6);
		break;
	}
	return (naddrs);
}

void
sctp_freeladdrs(void *addrs)
{
	free(addrs);
}

int
sctp_opt_info(int sock, sctp_assoc_t id, int opt, void *arg, socklen_t *len)
{
	struct sctpopt sopt;

	sopt.sopt_aid = id;
	sopt.sopt_name = opt;
	sopt.sopt_val = arg;
	sopt.sopt_len = *len;

	if (ioctl(sock, SIOCSCTPGOPT, &sopt) == -1) {
		return (-1);
	}
	*len = sopt.sopt_len;
	return (0);
}

/*
 * Branch off an association to its own socket. ioctl() allocates and
 * returns new fd.
 */
int
sctp_peeloff(int sock, sctp_assoc_t id)
{
	int fd;

	fd = id;
	if (ioctl(sock, SIOCSCTPPEELOFF, &fd) == -1) {
		return (-1);
	}
	return (fd);
}


ssize_t
sctp_recvmsg(int s, void *msg, size_t len, struct sockaddr *from,
    socklen_t *fromlen, struct sctp_sndrcvinfo *sinfo, int *msg_flags)
{
	struct msghdr hdr;
	struct iovec iov;
	struct cmsghdr *cmsg;
	char cinmsg[sizeof (*sinfo) + sizeof (*cmsg) + _CMSG_HDR_ALIGNMENT];
	int err;

	hdr.msg_name = from;
	hdr.msg_namelen = (fromlen != NULL) ? *fromlen : 0;
	hdr.msg_iov = &iov;
	hdr.msg_iovlen = 1;
	if (sinfo != NULL) {
		hdr.msg_control = (void *)_CMSG_HDR_ALIGN(cinmsg);
		hdr.msg_controllen = sizeof (cinmsg) -
		    (_CMSG_HDR_ALIGN(cinmsg) - (uintptr_t)cinmsg);
	} else {
		hdr.msg_control = NULL;
		hdr.msg_controllen = 0;
	}

	iov.iov_base = msg;
	iov.iov_len = len;
	err = recvmsg(s, &hdr, msg_flags == NULL ? 0 : *msg_flags);
	if (err == -1) {
		return (-1);
	}
	if (fromlen != NULL) {
		*fromlen = hdr.msg_namelen;
	}
	if (msg_flags != NULL) {
		*msg_flags = hdr.msg_flags;
	}
	if (sinfo != NULL) {
		for (cmsg = CMSG_FIRSTHDR(&hdr); cmsg != NULL;
			cmsg = CMSG_NXTHDR(&hdr, cmsg)) {
			if (cmsg->cmsg_level == IPPROTO_SCTP &&
			    cmsg->cmsg_type == SCTP_SNDRCV) {
				bcopy(CMSG_DATA(cmsg), sinfo, sizeof (*sinfo));
				break;
			}
		}
	}
	return (err);
}

static ssize_t
sctp_send_common(int s, const void *msg, size_t len, const struct sockaddr *to,
    socklen_t tolen, uint32_t ppid, uint32_t sinfo_flags, uint16_t stream_no,
    uint32_t timetolive, uint32_t context, sctp_assoc_t aid, int flags)
{
	struct msghdr hdr;
	struct iovec iov;
	struct sctp_sndrcvinfo *sinfo;
	struct cmsghdr *cmsg;
	char coutmsg[sizeof (*sinfo) + sizeof (*cmsg) + _CMSG_HDR_ALIGNMENT];

	hdr.msg_name = (caddr_t)to;
	hdr.msg_namelen = tolen;
	hdr.msg_iov = &iov;
	hdr.msg_iovlen = 1;
	hdr.msg_control = (void *)_CMSG_HDR_ALIGN(coutmsg);
	hdr.msg_controllen = sizeof (*cmsg) + sizeof (*sinfo);

	iov.iov_len = len;
	iov.iov_base = (caddr_t)msg;

	cmsg = CMSG_FIRSTHDR(&hdr);
	cmsg->cmsg_level = IPPROTO_SCTP;
	cmsg->cmsg_type = SCTP_SNDRCV;
	cmsg->cmsg_len = sizeof (*cmsg) + sizeof (*sinfo);

	sinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
	sinfo->sinfo_stream = stream_no;
	sinfo->sinfo_ssn = 0;
	sinfo->sinfo_flags = sinfo_flags;
	sinfo->sinfo_ppid = ppid;
	sinfo->sinfo_context = context;
	sinfo->sinfo_timetolive = timetolive;
	sinfo->sinfo_tsn = 0;
	sinfo->sinfo_cumtsn = 0;
	sinfo->sinfo_assoc_id = aid;

	return (sendmsg(s, &hdr, flags));
}

ssize_t
sctp_send(int s, const void *msg, size_t len,
    const struct sctp_sndrcvinfo *sinfo, int flags)
{
	/* Note that msg can be NULL for pure control message. */
	if (sinfo == NULL) {
		errno = EINVAL;
		return (-1);
	}
	return (sctp_send_common(s, msg, len, NULL, 0, sinfo->sinfo_ppid,
	    sinfo->sinfo_flags, sinfo->sinfo_stream, sinfo->sinfo_timetolive,
	    sinfo->sinfo_context, sinfo->sinfo_assoc_id, flags));
}

ssize_t
sctp_sendmsg(int s, const void *msg, size_t len, const struct sockaddr *to,
    socklen_t tolen, uint32_t ppid, uint32_t flags, uint16_t stream_no,
    uint32_t timetolive, uint32_t context)
{
	return (sctp_send_common(s, msg, len, to, tolen, ppid, flags,
	    stream_no, timetolive, context, 0, 0));
}
