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

#ifndef	_CRYPTO_CMDS_H
#define	_CRYPTO_CMDS_H

#ifdef	__cplusplus
extern "C" {
#endif

extern int crypto_provider_ext_info(uintptr_t addr, uint_t flags, int argc, \
	const mdb_arg_t *argv);
extern int crypto_mech_info(uintptr_t addr, uint_t flags, int argc, \
	const mdb_arg_t *argv);

extern int crypto_mechanism(uintptr_t addr, uint_t flags, int argc, \
	const mdb_arg_t *argv);
extern int crypto_data(uintptr_t addr, uint_t flags, int argc, \
	const mdb_arg_t *argv);
extern int crypto_dual_data(uintptr_t addr, uint_t flags, int argc, \
	const mdb_arg_t *argv);
extern int crypto_key(uintptr_t addr, uint_t flags, int argc, \
	const mdb_arg_t *argv);

extern int kcf_provider_desc(uintptr_t addr, uint_t flags, int argc, \
	const mdb_arg_t *argv);

extern int prov_tab(uintptr_t addr, uint_t flags, int argc, \
	const mdb_arg_t *argv);

extern int policy_tab(uintptr_t addr, uint_t flags, int argc, \
	const mdb_arg_t *argv);

extern int kcf_areq_node(uintptr_t addr, uint_t flags, int argc, \
	const mdb_arg_t *argv);

extern int kcf_global_swq(uintptr_t addr, uint_t flags, int argc, \
	const mdb_arg_t *argv);

extern int kcf_reqid_table_dcmd(uintptr_t addr, uint_t flags, int argc, \
	const mdb_arg_t *argv);

extern int crypto_find_reqid(uintptr_t addr, uint_t flags, int argc, \
	const mdb_arg_t *argv);

extern int areq_first_walk_init(mdb_walk_state_t *);
extern int an_idnext_walk_init(mdb_walk_state_t *);
extern int an_idprev_walk_init(mdb_walk_state_t *);
extern int an_ctxchain_walk_init(mdb_walk_state_t *);
extern int areq_last_walk_init(mdb_walk_state_t *);
extern int an_next_walk_step(mdb_walk_state_t *);
extern int an_idnext_walk_step(mdb_walk_state_t *);
extern int an_idprev_walk_step(mdb_walk_state_t *);
extern int an_ctxchain_walk_step(mdb_walk_state_t *);
extern void areq_walk_fini(mdb_walk_state_t *);
extern int an_prev_walk_step(mdb_walk_state_t *);
extern int reqid_table_walk_init(mdb_walk_state_t *);
extern int reqid_table_walk_step(mdb_walk_state_t *);
extern void reqid_table_walk_fini(mdb_walk_state_t *);

extern int soft_conf_walk_init(mdb_walk_state_t *);
extern int soft_conf_walk_step(mdb_walk_state_t *);
extern void soft_conf_walk_fini(mdb_walk_state_t *);

extern int kcf_soft_conf_entry(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv);

extern int kcf_policy_desc(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv);


#ifdef	__cplusplus
}
#endif

#endif	/* _CRYPTO_CMDS_H */
