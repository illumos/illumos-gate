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

#ifndef	_NET_H
#define	_NET_H

#ifdef	__cplusplus
extern "C" {
#endif

extern struct mi_payload_walk_arg_s mi_ar_arg;
extern struct mi_payload_walk_arg_s mi_icmp_arg;
extern struct mi_payload_walk_arg_s mi_ill_arg;

extern int sonode_walk_init(mdb_walk_state_t *);
extern int sonode_walk_step(mdb_walk_state_t *);
extern void sonode_walk_fini(mdb_walk_state_t *);
extern int mi_walk_init(mdb_walk_state_t *);
extern int mi_walk_step(mdb_walk_state_t *);
extern void mi_walk_fini(mdb_walk_state_t *);
extern int mi_payload_walk_init(mdb_walk_state_t *);
extern int mi_payload_walk_step(mdb_walk_state_t *);
extern int ar_stacks_walk_init(mdb_walk_state_t *);
extern int ar_stacks_walk_step(mdb_walk_state_t *);
extern int icmp_stacks_walk_init(mdb_walk_state_t *);
extern int icmp_stacks_walk_step(mdb_walk_state_t *);
extern int tcp_stacks_walk_init(mdb_walk_state_t *);
extern int tcp_stacks_walk_step(mdb_walk_state_t *);
extern int udp_stacks_walk_init(mdb_walk_state_t *);
extern int udp_stacks_walk_step(mdb_walk_state_t *);

extern int sonode(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int mi(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int netstat(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int dladm(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void dladm_help(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _NET_H */
