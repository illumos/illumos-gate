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

#ifndef _LIBDLIPTUN_H
#define	_LIBDLIPTUN_H

#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inet/iptun.h>
#include <libdladm.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct iptun_params {
	datalink_id_t	iptun_param_linkid;
	uint_t		iptun_param_flags;
	iptun_type_t	iptun_param_type;
	char		iptun_param_laddr[NI_MAXHOST];	/* local address */
	char		iptun_param_raddr[NI_MAXHOST];	/* remote address */
	ipsec_req_t	iptun_param_secinfo;
} iptun_params_t;

/* iptun_param_flags */
#define	IPTUN_PARAM_TYPE	0x00000001 /* itp_type is set */
#define	IPTUN_PARAM_LADDR	0x00000002 /* itp_laddr is set */
#define	IPTUN_PARAM_RADDR	0x00000004 /* itp_raddr is set */
#define	IPTUN_PARAM_SECINFO	0x00000008 /* itp_secinfo is set */
#define	IPTUN_PARAM_IMPLICIT	0x00000010 /* implicitly created IP tunnel */
#define	IPTUN_PARAM_IPSECPOL	0x00000020 /* IPsec policy exists */

extern dladm_status_t	dladm_iptun_create(dladm_handle_t, const char *,
    iptun_params_t *, uint_t);
extern dladm_status_t	dladm_iptun_delete(dladm_handle_t, datalink_id_t,
    uint_t);
extern dladm_status_t	dladm_iptun_modify(dladm_handle_t,
    const iptun_params_t *, uint_t);
extern dladm_status_t	dladm_iptun_getparams(dladm_handle_t, iptun_params_t *,
    uint_t);
extern dladm_status_t	dladm_iptun_up(dladm_handle_t, datalink_id_t);
extern dladm_status_t	dladm_iptun_down(dladm_handle_t, datalink_id_t);
extern dladm_status_t	dladm_iptun_set6to4relay(dladm_handle_t,
    struct in_addr *);
extern dladm_status_t	dladm_iptun_get6to4relay(dladm_handle_t,
    struct in_addr *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLIPTUN_H */
