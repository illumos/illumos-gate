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
 * from "tnet.h	7.44	02/10/09 SMI; TSOL 2.x"
 */

#ifndef	_SYS_TSOL_TNET_H
#define	_SYS_TSOL_TNET_H

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/tsol/label.h>
#include <sys/tsol/tndb.h>
#include <netinet/in.h>
#include <inet/ip.h>
#include <net/route.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL
/* Maximum label returned by tsol_compute_label_v6 */
#define	TSOL_MAX_IPV6_OPTION	(8 + IP_MAX_OPT_LENGTH)

extern int tsol_tnrh_chk(tsol_tpent_t *, bslabel_t *, int);
extern tsol_tnrhc_t *find_rhc(const void *, uchar_t, boolean_t);
extern int tsol_check_dest(const ts_label_t *, const void *, uchar_t,
    uint_t, boolean_t, ts_label_t **);
extern int tsol_compute_label_v4(const ts_label_t *, zoneid_t, ipaddr_t,
    uchar_t *, ip_stack_t *);
extern int tsol_compute_label_v6(const ts_label_t *, zoneid_t,
    const in6_addr_t *, uchar_t *, ip_stack_t *);
extern int tsol_check_label_v4(const ts_label_t *, zoneid_t, mblk_t **,
    uint_t, boolean_t, ip_stack_t *, ts_label_t **);
extern int tsol_check_label_v6(const ts_label_t *, zoneid_t, mblk_t **,
    uint_t, boolean_t, ip_stack_t *, ts_label_t **);
extern int tsol_prepend_option(uchar_t *, ipha_t *, int);
extern int tsol_prepend_option_v6(uchar_t *, ip6_t *, int);
extern int tsol_remove_secopt(ipha_t *, int);
extern int tsol_remove_secopt_v6(ip6_t *, int);

extern tsol_ire_gw_secattr_t *ire_gw_secattr_alloc(int);
extern void ire_gw_secattr_free(tsol_ire_gw_secattr_t *);

extern boolean_t tsol_can_reply_error(const mblk_t *, ip_recv_attr_t *);
extern boolean_t tsol_receive_local(const mblk_t *, const void *, uchar_t,
    ip_recv_attr_t *, const conn_t *);
extern boolean_t tsol_can_accept_raw(mblk_t *, ip_recv_attr_t *, boolean_t);
extern boolean_t tsol_get_pkt_label(mblk_t *, int, ip_recv_attr_t *);
extern zoneid_t tsol_attr_to_zoneid(const ip_recv_attr_t *);

extern boolean_t tsol_get_option_v4(mblk_t *, tsol_ip_label_t *, uint8_t **);
extern boolean_t tsol_get_option_v6(mblk_t *, tsol_ip_label_t *, uint8_t **);
extern boolean_t tsol_find_secopt_v6(const uchar_t *, uint_t, uchar_t **,
    uchar_t **, boolean_t *);

extern int tsol_ire_match_gwattr(ire_t *, const ts_label_t *);
extern int tsol_rtsa_init(rt_msghdr_t *, tsol_rtsecattr_t *, caddr_t);
extern int tsol_ire_init_gwattr(ire_t *, uchar_t, tsol_gc_t *);
extern mblk_t *tsol_ip_forward(ire_t *, mblk_t *, const ip_recv_attr_t *);
extern uint32_t tsol_pmtu_adjust(mblk_t *, uint32_t, int, int);

extern mlp_type_t tsol_mlp_addr_type(zoneid_t, uchar_t, const void *,
    ip_stack_t *);
extern boolean_t tsol_check_interface_address(const ipif_t *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TSOL_TNET_H */
