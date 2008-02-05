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

#ifndef	_SYS_PROMIF_IMPL_H
#define	_SYS_PROMIF_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#ifdef _KERNEL
#include <sys/promimpl.h>
#endif
#include <sys/obpdefs.h>
#include <sys/cmn_err.h>
#include <sys/note.h>

/*
 * CIF handler functions
 */
typedef int (*cif_func_t) (void *);
extern int promif_getprop(void *p);
extern int promif_getproplen(void *p);
extern int promif_nextprop(void *p);
extern int promif_nextnode(void *p);
extern int promif_childnode(void *p);
extern int promif_parentnode(void *p);
extern int promif_enter_mon(void *p);
extern int promif_exit_to_mon(void *p);
extern int promif_reboot(void *p);
extern int promif_write(void *p);
extern int promif_read(void *p);
extern int promif_interpret(void *p);
extern int promif_finddevice(void *p);
extern int promif_instance_to_package(void *p);
#ifndef _KMDB
extern int promif_setprop(void *p);
extern int promif_test(void *p);
extern int promif_instance_to_path(void *p);
extern int promif_power_off(void *p);
extern int promif_asr_list_keys_len(void *p);
extern int promif_asr_list_keys(void *p);
extern int promif_asr_export_len(void *p);
extern int promif_asr_export(void *p);
extern int promif_set_security_key(void *p);
extern int promif_get_security_key(void *p);
extern int promif_start_cpu(void *p);
extern int promif_set_mmfsa_traptable(void *p);
extern int promif_set_sun4v_api_version(void *p);
extern int promif_get_sun4v_api_version(void *p);
#endif

/*
 * Shadow device tree access functions
 */
extern pnode_t promif_stree_nextnode(pnode_t nodeid);
extern pnode_t promif_stree_childnode(pnode_t nodeid);
extern pnode_t promif_stree_parentnode(pnode_t nodeid);
extern int promif_stree_getproplen(pnode_t, char *name);
extern int promif_stree_getprop(pnode_t, char *name, void *value);
extern int promif_stree_setprop(pnode_t, char *name, void *value, int len);
extern char *promif_stree_nextprop(pnode_t nodeid, char *name, char *next);

/*
 * Hooks for kmdb to get and set a pointer to the PROM shadow tree
 */
#ifdef _KMDB
extern void promif_stree_setroot(void *root);
extern caddr_t promif_stree_getroot(void);
#endif

/*
 * Miscellaneous functions
 */
extern cif_func_t promif_find_cif_callback(char *opname);
extern int promif_ldom_setprop(char *name, void *value, int valuelen);
extern char promif_getchar(void);

/*
 * Initialization functions
 */
#ifdef _KMDB
extern void cif_init(char *, caddr_t, ihandle_t, ihandle_t,
    phandle_t, phandle_t, pnode_t, pnode_t);
extern void promif_io_init(ihandle_t, ihandle_t, phandle_t, phandle_t);
extern void promif_set_nodes(pnode_t, pnode_t);
#else
extern void promif_io_init(void);
extern void promif_stree_init(void);
extern void promif_prop_init(void);
#endif

/*
 * Debugging support
 */
#ifdef DEBUG

extern uint_t cif_debug;

#define	CIF_DBG_FLAG_NODE		0x01
#define	CIF_DBG_FLAG_REBOOT		0x02

#define	CIF_DBG_ALL	if (cif_debug)				prom_printf
#define	CIF_DBG_NODE	if (cif_debug & CIF_DBG_FLAG_NODE)	prom_printf
#define	CIF_DBG_REBOOT	if (cif_debug & CIF_DBG_FLAG_REBOOT)	prom_printf

#else /* DEBUG */

#define	CIF_DBG_ALL	_NOTE(CONSTCOND) if (0)	prom_printf
#define	CIF_DBG_NODE	CIF_DBG_ALL
#define	CIF_DBG_REBOOT	CIF_DBG_ALL

#endif /* DEBUG */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_PROMIF_IMPL_H */
