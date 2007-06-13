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

#ifndef _RDSIB_SC_H
#define	_RDSIB_SC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <net/if.h>

typedef struct rds_path_endpoint_s {
	uint32_t	iftype;
	ipaddr_t	ipaddr;
	ipaddr_t	node_ipaddr;
	char		*ifname;
} rds_path_endpoint_t;

typedef struct rds_path_s {
	rds_path_endpoint_t	local;
	rds_path_endpoint_t	remote;
} rds_path_t;

extern void rds_clif_name(char *name);
extern void rds_path_up(struct rds_path_s *path);
extern void rds_path_down(struct rds_path_s *path);

#ifdef __cplusplus
}
#endif

#endif	/* _RDSIB_SC_H */
