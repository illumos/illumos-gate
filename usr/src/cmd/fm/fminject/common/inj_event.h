/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _INJ_EVENT_H
#define	_INJ_EVENT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <inj.h>
#include <inj_string.h>

#ifdef __cplusplus
extern "C" {
#endif

extern inj_decl_t *inj_decl_create(inj_declmem_t *);
extern void inj_decl_addmem(inj_decl_t *, inj_declmem_t *);
extern void inj_decl_finish(inj_decl_t *, const char *, inj_itemtype_t);
extern void inj_decl_destroy(inj_decl_t *);
extern inj_decl_t *inj_decl_lookup(const char *, inj_itemtype_t);

extern inj_declmem_t *inj_decl_mem_create(const char *, inj_memtype_t);
extern inj_declmem_t *inj_decl_mem_create_defined(const char *, const char *,
    inj_itemtype_t);
extern inj_declmem_t *inj_decl_mem_create_enum(const char *, inj_hash_t *);
extern void inj_decl_mem_destroy(inj_declmem_t *);
extern void inj_decl_mem_make_array(inj_declmem_t *, uint_t);

extern inj_defn_t *inj_defn_create(inj_defnmem_t *);
extern void inj_defn_addmem(inj_defn_t *, inj_defnmem_t *);
extern void inj_defn_finish(inj_defn_t *, const char *, const char *,
    inj_itemtype_t);
extern inj_defn_t *inj_defn_lookup(const char *, inj_memtype_t);

extern inj_defnmem_t *inj_defn_mem_create(const char *, inj_defnmemtype_t);
extern inj_defnmem_t *inj_defn_mem_create_list(inj_defn_t *,
    inj_defnmemtype_t);

extern const char *inj_item2str(inj_itemtype_t);
extern inj_memtype_t inj_item2mem(inj_itemtype_t);
extern const char *inj_mem2str(inj_memtype_t);
extern inj_itemtype_t inj_mem2item(inj_memtype_t);

extern inj_randelem_t *inj_rand_create(inj_defn_t *, uint_t);
extern inj_randelem_t *inj_rand_add(inj_randelem_t *, inj_randelem_t *);

extern void inj_cmds_add(inj_cmd_t *);
extern inj_list_t *inj_cmds_get(void);

extern inj_cmd_t *inj_cmd_rand(inj_randelem_t *);
extern inj_cmd_t *inj_cmd_repeat(inj_cmd_t *, uint_t);
extern inj_cmd_t *inj_cmd_send(inj_defn_t *);
extern inj_cmd_t *inj_cmd_sleep(uint_t);
extern inj_cmd_t *inj_cmd_addhrt(hrtime_t);
extern inj_cmd_t *inj_cmd_endhrt(void);

#ifdef __cplusplus
}
#endif

#endif /* _INJ_EVENT_H */
