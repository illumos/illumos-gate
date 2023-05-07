/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

#ifndef _TOPO_UFM_H
#define	_TOPO_UFM_H

/*
 * The ufm module provides the ability for callers to enumerate ufm subtrees
 * beneath them. The module will create all required ranges. To invoke this, one
 * should use the topo_hc.h UFM definition as the name. The enumerator requires
 * an argument that describes how the UFM should be found. There are different
 * structures for each type, the first argument is always a topo_ufm_method_t.
 *
 * Currently the only supported method is to use a devinfo path (i.e.
 * di_devfs_path()). This has been designed so that way as we have more complex
 * cases where we need to create the UFMs manually and through the kernel UFM
 * subsystem they can leverage the same topo logic and just use an additional
 * method.
 *
 * For simple cases, it is ok to still use topo_mod_create_ufm() for the time
 * being.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	TOPO_MOD_UFM	"ufm"
#define	TOPO_MOD_UFM_VERS	1

typedef enum {
	/*
	 * Enumerate a series of UFM nodes
	 */
	TOPO_UFM_M_DEVINFO
} topo_ufm_method_t;

typedef struct {
	topo_ufm_method_t tud_method;
	const char *tud_path;
} topo_ufm_devinfo_t;

#ifdef __cplusplus
}
#endif

#endif /* _TOPO_UFM_H */
