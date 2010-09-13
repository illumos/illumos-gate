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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_RDS_TRANSPORT_H
#define	_RDS_TRANSPORT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct rds_transport_ops_s {
	int (*rds_transport_open_ib)(void);
	void (*rds_transport_close_ib)(void);
	int (*rds_transport_sendmsg)(uio_t *uiop, ipaddr_t srcip,
	    ipaddr_t destip, in_port_t sport, in_port_t dport,
	    zoneid_t zoneid);
	void (*rds_transport_resume_port)(in_port_t port);
	boolean_t (*rds_transport_if_lookup_by_name)(char *if_name);
} rds_transport_ops_t;

extern	rds_transport_ops_t *rds_transport_ops;
extern	uint_t	UserBufferSize;
extern	uint_t	rds_rx_pkts_pending_hwm;

#ifdef	__cplusplus
}
#endif

#endif	/* _RDS_TRANSPORT_H */
