/*
 * Copyright 1992-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1988, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)rtsock.c	8.6 (Berkeley) 2/11/95
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains routines that processes routing socket requests.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strlog.h>
#include <sys/dlpi.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>

#include <sys/systm.h>
#include <sys/param.h>
#include <sys/socket.h>
#define	_SUN_TPI_VERSION	2
#include <sys/tihdr.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <netinet/ip6.h>

#include <inet/common.h>
#include <inet/mi.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ip_rts.h>
#include <inet/ip_multi.h>

/*
 * Fills the message with the given info.
 */
void
rts_fill_msg_v6(int type, int rtm_addrs, const in6_addr_t *dst,
    const in6_addr_t *mask, const in6_addr_t *gateway,
    const in6_addr_t *src_addr, const in6_addr_t *brd_addr,
    const in6_addr_t *author, ipif_t *ipif, mblk_t *mp)
{
	rt_msghdr_t	*rtm;
	sin6_t		*sin6;
	size_t		data_size, header_size;
	uchar_t		*cp;
	int		i;

	ASSERT(mp != NULL);
	/*
	 * First find the type of the message
	 * and its length.
	 */
	header_size = rts_header_msg_size(type);
	/*
	 * Now find the size of the data
	 * that follows the message header.
	 */
	data_size = rts_data_msg_size(rtm_addrs, AF_INET6);

	rtm = (rt_msghdr_t *)mp->b_rptr;
	mp->b_wptr = &mp->b_rptr[header_size];
	cp = mp->b_wptr;
	bzero(cp, data_size);
	for (i = 0; i < RTA_NUMBITS; i++) {
		sin6 = (sin6_t *)cp;
		switch (rtm_addrs & (1 << i)) {
		case RTA_DST:
			sin6->sin6_addr = *dst;
			sin6->sin6_family = AF_INET6;
			cp += sizeof (sin6_t);
			break;
		case RTA_GATEWAY:
			sin6->sin6_addr = *gateway;
			sin6->sin6_family = AF_INET6;
			cp += sizeof (sin6_t);
			break;
		case RTA_NETMASK:
			sin6->sin6_addr = *mask;
			sin6->sin6_family = AF_INET6;
			cp += sizeof (sin6_t);
			break;
		case RTA_IFA:
		case RTA_SRC:
			sin6->sin6_addr = *src_addr;
			sin6->sin6_family = AF_INET6;
			cp += sizeof (sin6_t);
			break;
		case RTA_IFP:
			cp += ill_dls_info((struct sockaddr_dl *)cp, ipif);
			break;
		case RTA_AUTHOR:
			sin6->sin6_addr = *author;
			sin6->sin6_family = AF_INET6;
			cp += sizeof (sin6_t);
			break;
		case RTA_BRD:
			/*
			 * RTA_BRD is used typically to specify a point-to-point
			 * destination address.
			 */
			sin6->sin6_addr = *brd_addr;
			sin6->sin6_family = AF_INET6;
			cp += sizeof (sin6_t);
			break;
		}
	}
	mp->b_wptr = cp;
	mp->b_cont = NULL;
	/*
	 * set the fields that are common to
	 * to different messages.
	 */
	rtm->rtm_msglen = (short)(header_size + data_size);
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_type = (uchar_t)type;
}

/*
 * This routine is called to generate a message to the routing
 * socket indicating that a redirect has occured, a routing lookup
 * has failed, or that a protocol has detected timeouts to a particular
 * destination. This routine is called for message types RTM_LOSING,
 * RTM_REDIRECT, and RTM_MISS.
 */
void
ip_rts_change_v6(int type, const in6_addr_t *dst_addr,
    const in6_addr_t *gw_addr, const in6_addr_t *net_mask,
    const in6_addr_t *source, const in6_addr_t *author,
    int flags, int error, int rtm_addrs)
{
	rt_msghdr_t	*rtm;
	mblk_t		*mp;

	if (rtm_addrs == 0)
		return;
	mp = rts_alloc_msg(type, rtm_addrs, AF_INET6);
	if (mp == NULL)
		return;
	rts_fill_msg_v6(type, rtm_addrs, dst_addr, net_mask, gw_addr, source,
	    &ipv6_all_zeros, author, NULL, mp);
	rtm = (rt_msghdr_t *)mp->b_rptr;
	rtm->rtm_flags = flags;
	rtm->rtm_errno = error;
	rtm->rtm_flags |= RTF_DONE;
	rtm->rtm_addrs = rtm_addrs;
	rts_queue_input(mp, NULL, AF_INET6);
}
