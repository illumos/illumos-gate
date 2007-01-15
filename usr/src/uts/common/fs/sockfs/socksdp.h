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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SOCKSDP_H_
#define	_SOCKSDP_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SDP socket structure.
 *
 * The opaque pointer passed in upcalls is a pointer to sdp_sonode.
 */
struct sdp_sonode {
	int			ss_type;	/* sonode or soassoc */
	struct sonode		ss_so;
	struct sockaddr_in6	ss_laddr;	/* can fit both v4 & v6 */
	struct sockaddr_in6	ss_faddr;
	int			ss_rxqueued;	/* queued # of conn */
	struct pollhead		ss_poll_list;
};

extern sdp_upcalls_t sosdp_sock_upcalls;
extern struct vnodeops *socksdp_vnodeops;
extern const fs_operation_def_t socksdp_vnodeops_template[];

extern void sosdp_free(struct sonode *so);
extern int sosdp_chgpgrp(struct sdp_sonode *ss, pid_t pid);
extern void sosdp_sendsig(struct sdp_sonode *ss, int event);

extern int sosdp_bind(struct sonode *so, struct sockaddr *name,
    socklen_t namelen, int flags);
extern int sosdp_recvmsg(struct sonode *, struct nmsghdr *, struct uio *);

extern int sosdp_waitconnected(struct sonode *so, int fmode);

extern void sosdp_so_inherit(struct sdp_sonode *lss, struct sdp_sonode *nss);

/*
 * Data structure types.
 */
#define	SOSDP_SOCKET	0x1

#define	SOTOSDO(so) ((struct sdp_sonode *)(((char *)so) -	\
			offsetof(struct sdp_sonode, ss_so)))

/*
 * Event flags to sosdp_sendsig().
 */
#define	SDPSIG_WRITE	0x1
#define	SDPSIG_READ	0x2
#define	SDPSIG_URG	0x4

#ifdef	__cplusplus
}
#endif

#endif /* _SOCKSDP_H_ */
