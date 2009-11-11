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
 */

#ifndef	_INET_PROTO_SET_H
#define	_INET_PROTO_SET_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/socket_proto.h>
#include <inet/optcom.h>
#include <inet/ipclassifier.h>

extern boolean_t	proto_set_rx_hiwat(queue_t *, struct conn_s *, size_t);
extern boolean_t	proto_set_rx_lowat(queue_t *, struct conn_s *, size_t);
extern boolean_t	proto_set_maxpsz(queue_t *, struct conn_s *, size_t);
extern boolean_t	proto_set_tx_maxblk(queue_t *, struct conn_s *,
    ssize_t);
extern boolean_t	proto_set_tx_copyopt(queue_t *, struct conn_s *, int);
extern boolean_t	proto_set_tx_wroff(queue_t *, struct conn_s *, size_t);
extern void		proto_set_rx_oob_opt(struct conn_s *, boolean_t);

extern int	proto_tlitosyserr(int);
extern int	proto_verify_ip_addr(int, const struct sockaddr *, socklen_t);

extern int	proto_opt_check(int, int, int, t_uscalar_t *, opdes_t *,
    uint_t, boolean_t, boolean_t, cred_t *);
extern opdes_t *proto_opt_lookup(t_uscalar_t, t_uscalar_t, opdes_t *, uint_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_PROTO_SET_H */
