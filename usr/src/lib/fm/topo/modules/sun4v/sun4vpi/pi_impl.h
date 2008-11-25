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

#ifndef _PI_IMPL_H
#define	_PI_IMPL_H

/*
 * SUN4V Platform Independent Enumerator private interfaces
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <pthread.h>
#include <libuutil.h>
#include <sys/mdesc.h>
#include <sys/fm/ldom.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>

/* Definitions used when registering the enumerator with libtopo */
#define	SUN4VPI_DESC		"SUN4V Platform independent topology enumerator"
#define	SUN4VPI_SCHEME		"hc"
#define	SUN4VPI_VERSION		TOPO_VERSION

/* Flags used by pi_enum_generic_impl */
#define	SUN4VPI_ENUM_ADD_SERIAL	1	/* Add serial to resource */

/* Definitions used when working with PRI machine description nodes */
#define	MD_STR_BACK		"back"
#define	MD_STR_CFG_HANDLE	"cfg-handle"		/* FWARC/2008/300 */
#define	MD_STR_CHIP		"chip"
#define	MD_STR_COMPONENT	"component"		/* FWARC/2006/700 */
#define	MD_STR_CHASSIS		"chassis"
#define	MD_STR_COMPONENTS	"components"		/* FWARC/2006/700 */
#define	MD_STR_DASH_NUMBER	"dash_number"		/* FWARC/2006/700 */
#define	MD_STR_FRU		"fru"			/* FWARC/2006/700 */
#define	MD_STR_FWD		"fwd"
#define	MD_STR_ID		"id"			/* FWARC/2008/300 */
#define	MD_STR_NAC		"nac"			/* FWARC/2008/300 */
#define	MD_STR_NAME		"name"
#define	MD_STR_PART_NUMBER	"part_number"		/* FWARC/2008/300 */
#define	MD_STR_PLATFORM		"platform"
#define	MD_STR_REVISION_NUMBER	"rev_number"		/* FWARC/2008/300 */
#define	MD_STR_SERIAL_NUMBER	"serial_number"		/* FWARC/2008/300 */
#define	MD_STR_TOPO_HC_NAME	"topo-hc-name"		/* FWARC/2008/300 */
#define	MD_STR_TOPO_SKIP	"topo-skip"		/* FWARC/2008/300 */
#define	MD_STR_TYPE		"type"


/*
 * The enumerator needs to pass some state in to the function that walks
 * the PRI graph.  This structure contains the necessary information.
 */
struct pi_enum_s {
	topo_mod_t	*mod;		/* Topo module handle		*/

	ldom_hdl_t	*ldomp;		/* LDOM connection handle	*/
	uint64_t	*ldom_bufp;	/* LDOM connection data		*/
	ssize_t		ldom_bufsize;	/* LDOM connection data size	*/

	md_t		*mdp;		/* Machine Description handle	*/
	int		md_nodes;	/* Number of md nodes		*/

	void		*wp;		/* Walker private data		*/
};
typedef struct pi_enum_s pi_enum_t;


/*
 * Some node types require custom functions to create their topology nodes.
 * This function prototype defines the interface to these functions.
 */
typedef int pi_enum_fn_t(topo_mod_t *, md_t *, mde_cookie_t, topo_instance_t,
    tnode_t *, const char *, tnode_t **);

pi_enum_fn_t	pi_enum_cpu;		/* Enumerate a CHIP/CORE/CPU node */
pi_enum_fn_t	pi_enum_mem;		/* Enumerate a DIMM node */
pi_enum_fn_t	pi_enum_generic;	/* Enumerate a generic PRI node */
pi_enum_fn_t	pi_enum_niu;		/* Enumerate an NIU node */
pi_enum_fn_t	pi_enum_pciexrc;	/* Enumerate a PCIEX root complex */
pi_enum_fn_t	pi_enum_top;		/* Enumerate a top-level PRI node */

int pi_enum_generic_impl(topo_mod_t *, md_t *, mde_cookie_t, topo_instance_t,
    tnode_t *, tnode_t *, const char *, const char *, tnode_t **, int flag);


/*
 * Some enumeration functions may need to defer execution until after the
 * entire PRI graph has been walked for some nodes.  This interface is
 * provided to allow for the registration of routines to execute after the
 * entire graph has been walked (for example, to execute sub-enumerators).
 */
typedef int pi_deferenum_fn_t(topo_mod_t *, md_t *, mde_cookie_t,
    topo_instance_t, tnode_t *, const char *, tnode_t *, void *);

int pi_defer_add(topo_mod_t *, mde_cookie_t, tnode_t *, tnode_t *,
    pi_deferenum_fn_t, void *);
int pi_defer_exec(topo_mod_t *, md_t *);


/* Functions to handle LDOM PRI sessions */
int  pi_ldompri_open(topo_mod_t *, pi_enum_t *);
void pi_ldompri_close(topo_mod_t *, pi_enum_t *);


/* Walk the PRI and create a topology starting at a particular PRI node */
int  pi_walker(pi_enum_t *, tnode_t *, const char *, mde_cookie_t,
    mde_str_cookie_t, mde_str_cookie_t);
int  pi_walker_init(topo_mod_t *);
void pi_walker_fini(topo_mod_t *);

/* PRI machine description node data access routines */
int	pi_find_mdenodes(topo_mod_t *, md_t *, mde_cookie_t, char *, char *,
    mde_cookie_t **, size_t *);
int	pi_skip_node(topo_mod_t *, md_t *, mde_cookie_t);
int	pi_get_cfg_handle(topo_mod_t *, md_t *, mde_cookie_t, uint64_t *);
char   *pi_get_chassisid(topo_mod_t *, md_t *, mde_cookie_t);
char   *pi_get_topo_hc_name(topo_mod_t *, md_t *, mde_cookie_t);
int	pi_get_instance(topo_mod_t *, md_t *, mde_cookie_t, topo_instance_t *);
char   *pi_get_part(topo_mod_t *, md_t *, mde_cookie_t);
char   *pi_get_productid(topo_mod_t *, md_t *);
char   *pi_get_revision(topo_mod_t *, md_t *, mde_cookie_t);
char   *pi_get_serial(topo_mod_t *, md_t *, mde_cookie_t);
char   *pi_get_serverid(topo_mod_t *);
int	pi_get_fru(topo_mod_t *, md_t *, mde_cookie_t, int *);
char   *pi_get_label(topo_mod_t *, md_t *, mde_cookie_t);

int	pi_set_auth(topo_mod_t *, md_t *, mde_cookie_t, tnode_t *, tnode_t *);
int	pi_set_frufmri(topo_mod_t *, md_t *, mde_cookie_t, const char *,
    topo_instance_t, tnode_t *, tnode_t *);
int	pi_set_label(topo_mod_t *, md_t *, mde_cookie_t, tnode_t *);
int	pi_set_system(topo_mod_t *, tnode_t *);

tnode_t *pi_node_bind(topo_mod_t *, md_t *, mde_cookie_t, tnode_t *,
    const char *, topo_instance_t, nvlist_t *);

#ifdef __cplusplus
}
#endif

#endif /* _PI_IMPL_H */
