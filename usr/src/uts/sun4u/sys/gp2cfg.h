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
 * Copyright 2000-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_GP2CFG_H
#define	_SYS_GP2CFG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Header file for the Safari Configurator (gptwocfg).
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/safari_pcd.h>
#include <sys/fcode.h>
#include <sys/fcgp2.h>

/*
 * Interfaces exported by Safari Configurator module, kernel/misc/gp2cfg.
 */

typedef void *gptwocfg_cookie_t;
typedef void *gptwocfg_ops_cookie_t;
typedef uint32_t gptwo_aid_t;

gptwocfg_cookie_t gptwocfg_configure(dev_info_t *, spcd_t *, uint_t);
gptwocfg_cookie_t gptwocfg_unconfigure(dev_info_t *, gptwo_aid_t);
int gptwocfg_next_node(gptwocfg_cookie_t, dev_info_t *, dev_info_t **);
void gptwocfg_save_handle(dev_info_t *, fco_handle_t);
fco_handle_t gptwocfg_get_handle(dev_info_t *);


/*
 * Prototypes for the platform specific functions.
 */

#define	GP2CFG_SUCCESS	0x00
#define	GP2CFG_FAILURE	0x01

struct gptwo_phys_spec {
	uint_t gptwo_phys_hi;	/* child's address, hi word */
	uint_t gptwo_phys_low;	/* child's address, low word */
	uint_t gptwo_size_hi;	/* high word of size field */
	uint_t gptwo_size_low;	/* low word of size field */
};

typedef struct gptwo_phys_spec gptwo_regspec_t;


#define	GP2_VERSION		0

struct gptwo_new_nodes {
	uint_t		gptwo_version;
	uint_t		gptwo_number_of_nodes;
	dev_info_t	*gptwo_nodes[1];
		/* actual size is gptwo_number_of_nodes */
};

typedef struct gptwo_new_nodes gptwo_new_nodes_t;

typedef struct gptwocfg_config {
	uint_t			gptwo_version;
	dev_info_t		*gptwo_ap;
	struct gptwocfg_ops	*gptwo_ops;
	gptwo_aid_t		gptwo_portid;
	gptwo_new_nodes_t	*gptwo_nodes;
	struct gptwocfg_config	*gptwo_next;
} gptwocfg_config_t;

typedef struct gptwocfg_handle_list {
	dev_info_t			*dip;
	fco_handle_t			fco_handle;
	struct gptwocfg_handle_list	*next;
} gptwocfg_handle_list_t;

#define	GPTWOCFG_OPS_VERSION	0

typedef struct gptwocfg_ops {
	int	gptwocfg_version;	/* GPTWOCFG_OPS_VERSION */
	int	gptwocfg_type;		/* SAFPTYPE_xxx */
	gptwo_new_nodes_t *(*gptwocfg_configure)
	    (dev_info_t *ap, spcd_t *pcd, gptwo_aid_t id);
	dev_info_t *(*gptwocfg_unconfigure)
	    (dev_info_t *dip);
} gptwocfg_ops_t;

typedef gptwo_new_nodes_t *gptwo_cfgfunc_t(dev_info_t *, spcd_t *, gptwo_aid_t);
typedef dev_info_t *gptwo_uncfgfunc_t(dev_info_t *);
void gptwocfg_register_ops(uint_t, gptwo_cfgfunc_t *, gptwo_uncfgfunc_t *);
void gptwocfg_unregister_ops(uint_t);
gptwo_new_nodes_t *gptwocfg_allocate_node_list(int);
void gptwocfg_free_node_list(gptwo_new_nodes_t *);
void gptwocfg_devi_attach_to_parent(dev_info_t *);

struct gfc_ops_v {
	char *svc_name;
	fc_ops_t *f;
};

extern struct gfc_ops_v gptwo_pov[];

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_GP2CFG_H */
