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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DID_H
#define	_DID_H

#include <sys/pci.h>
#include <fm/topo_mod.h>
#include <libdevinfo.h>
#include <libnvpair.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct did did_t;

extern did_t *did_create(topo_mod_t *, di_node_t, int, int, int,
    int);
extern did_t *did_find(topo_mod_t *, di_node_t);
extern did_t *did_hash_lookup(topo_mod_t *, di_node_t);
extern void did_hash_insert(topo_mod_t *, di_node_t, did_t *);
extern void did_hash_fini(topo_mod_t *);
extern int did_hash_init(topo_mod_t *);
extern void did_link_set(topo_mod_t *, tnode_t *, did_t *);
extern void did_setspecific(topo_mod_t *, void *);

extern topo_mod_t *did_mod(did_t *);
extern di_node_t did_dinode(did_t *);
extern void did_BDF(did_t *, int *, int *, int *);
extern void did_markrc(did_t *);
extern const char *did_label(did_t *, int);
extern int did_board(did_t *);
extern int did_bridge(did_t *);
extern int did_rc(did_t *);
extern int did_physslot(did_t *);
extern int did_inherit(did_t *, did_t *);
extern int did_excap(did_t *);
extern void did_excap_set(did_t *, int);
extern int did_bdf(did_t *);
extern did_t *did_link_get(did_t *);
extern did_t *did_chain_get(did_t *);
extern void did_destroy(did_t *);
extern void did_hold(did_t *);
extern void did_did_link_set(did_t *, did_t *);
extern void did_did_chain_set(did_t *, did_t *);
extern void did_rele(did_t *);
extern void did_settnode(did_t *, tnode_t *);
extern tnode_t *did_gettnode(did_t *);

#ifdef __cplusplus
}
#endif

#endif /* _DID_H */
