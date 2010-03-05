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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _X86PI_IMPL_H
#define	_X86PI_IMPL_H

/*
 * i86pc Generic Enumerator private interfaces
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <smbios.h>
#include <ctype.h>


/*
 * Table showing the relationship between hc-canonical names and the
 * SMBIOS tables/values.
 *
 * **************************************************************************
 * | hc-name             | SMB Table | Offset - Name            | Value     |
 * --------------------------------------------------------------------------
 * --------------------------------------------------------------------------
 * | "motherboard"       | Type 2    | 0x0D - Board Type        | 0x0A      |
 * --------------------------------------------------------------------------
 * | "cpuboard"          | Type 2    | 0x0D - Board Type        | 0x06      |
 * --------------------------------------------------------------------------
 * | "memboard"          | Type 2    | 0x0D - Board Type        | 0x08      |
 * --------------------------------------------------------------------------
 * | "ioboard"           | Type 2    | 0x0D - Board Type        | 0x07      |
 * --------------------------------------------------------------------------
 * | "systemboard"       | Type 2    | 0x0D - Board Type        | 0x03,0x09,|
 * |                     |           |                          | 0x0B,0x0C |
 * --------------------------------------------------------------------------
 * | "bay"               | Type 136  |                                      |
 * --------------------------------------------------------------------------
 * | "hostbridge"        | Type 138  |                                      |
 * --------------------------------------------------------------------------
 * | "pciexrc"           | Type 138  |                                      |
 * **************************************************************************
 */


/* Definitions used when registering the enumerator with libtopo */
#define	X86PI_DESC	"i86pc Generic Topology Enumerator"
#define	X86PI_SCHEME	"hc"
#define	X86PI_VERSION	TOPO_VERSION

/*
 * Solaris FMA Compliance level for SMBIOS.
 * The same X86PI_* definitions are used in chip.h
 * please keep them in sync
 */
#define	X86PI_FULL	1
#define	X86PI_NONE	2

/* used in traversing contained bboards */
#define	X86PI_VISITED	1

#define	LABEL		1

/* Flags used by x86pi_enum_generic */
#define	X86PI_ENUM_FRU	0x0001	/* Indicates a FRU */

/* max allowed contained count */
#define	SMB_MAX_ID	0x40

/* indication of successful fac node creation */
int fac_done;

/*
 * Count and smbios struct id(s) for each smbios struct type.
 */
typedef struct smbs_con_ids {
	id_t id;			/* smbios struct id */
	id_t con_cnt;			/* containee count */
	id_t con_ids[SMB_MAX_ID];	/* containee ids */
	id_t con_by_id;			/* container id */
	int visited;			/* visit flag */
	tnode_t *node;
} smbs_con_ids_t;

typedef struct smbs_cnt {
	int type;		/* SMBIOS stucture type */
	int count;		/* number of table entries */
	smbs_con_ids_t ids[SMB_MAX_ID]; /* SMBIOS table entry id(s) */
} smbs_cnt_t;

smbs_cnt_t stypes[SMB_TYPE_OEM_HI]; /* one for each struct */

/*
 * The enumerator needs to pass some state in to the function that walks
 * the PRI graph.  This structure contains the necessary information.
 */
struct x86pi_enum_s {
	topo_mod_t	*mod;		/* Topo module handle */
	tnode_t		*t_parent;	/* "Chassis" parent */
	uint32_t	force;		/* force legacy */
	void		*priv;		/* Private data */
};
typedef struct x86pi_enum_s x86pi_enum_t;

/*
 * x86gentopo hcfmri info structure.
 *
 * Available unformed SMBIOS strings:
 *  smbi_manufacturer
 *  smbi_product
 *  smbi_version
 *  smbi_serial
 *  smbi_asset
 *  smbi_location
 *  smbi_part
 *
 */
struct x86pi_hcfmri_info_s {
	int		instance;
	int		rev;

	const char	*hc_name;
	const char	*manufacturer;
	const char	*product;
	const char	*version;
	const char	*serial_number;
	const char	*asset_tag;
	const char	*location;
	const char	*part_number;
};
typedef struct x86pi_hcfmri_info_s x86pi_hcfmri_t;

/*
 * Prototypes
 */

/* SMBIOS */
smbios_hdl_t *x86pi_smb_open(topo_mod_t *);
void x86pi_smb_strcnt(smbios_hdl_t *, smbs_cnt_t *);
int x86pi_check_comp(topo_mod_t *, smbios_hdl_t *);

/* Node generation */
tnode_t *x86pi_gen_chassis(topo_mod_t *, tnode_t *, smbios_hdl_t *, int, int);
tnode_t *x86pi_gen_bboard(topo_mod_t *, tnode_t *, smbios_hdl_t *, int, int,
    int);
int x86pi_gen_cmp(topo_mod_t *, tnode_t *, smbios_hdl_t *, int, int, int);
int x86pi_gen_core(topo_mod_t *, tnode_t *, int, int, int);
int x86pi_gen_strand(topo_mod_t *, tnode_t *, int, int, int);
int x86pi_gen_memarray(topo_mod_t *, tnode_t *, smbios_hdl_t *, int, int);
void x86pi_gen_memdev(topo_mod_t *, tnode_t *, smbios_hdl_t *, int, int, int);
int x86pi_gen_hbr(topo_mod_t *, tnode_t *, smbios_hdl_t *, int,
    topo_instance_t, topo_instance_t *);
int x86pi_gen_bay(topo_mod_t *, tnode_t *, smbios_hdl_t *, smbios_port_ext_t *,
    int);

/* support routines */
int x86pi_enum_generic(topo_mod_t *, x86pi_hcfmri_t *, tnode_t *, tnode_t *,
    tnode_t **, int);
tnode_t *x86pi_node_bind(topo_mod_t *, tnode_t *, x86pi_hcfmri_t *, nvlist_t *,
    int);
void x86pi_hcfmri_info_fini(topo_mod_t *, x86pi_hcfmri_t *);
uint16_t x86pi_bdf(topo_mod_t *, di_node_t);
int x86pi_phy(topo_mod_t *, di_node_t);

/* get/set info */
char *x86pi_get_serverid(topo_mod_t *);
int x86pi_set_frufmri(topo_mod_t *, x86pi_hcfmri_t *, tnode_t *, tnode_t *,
    int);
int x86pi_set_label(topo_mod_t *, const char *, const char *, tnode_t *);
int x86pi_set_auth(topo_mod_t *, x86pi_hcfmri_t *, tnode_t *, tnode_t *);
int x86pi_set_system(topo_mod_t *, tnode_t *);

/* hostbridge */
int x86pi_hbr_enum_init(topo_mod_t *);
void x86pi_hbr_enum_fini(topo_mod_t *);

/* base board */
id_t x86pi_bb_topparent(smbios_hdl_t *, int, tnode_t **, id_t *);
int x86pi_bb_contains(topo_mod_t *, smbios_hdl_t *);
int x86pi_bb_getchips(topo_mod_t *, smbios_hdl_t *, int, int);

const char *x86pi_cleanup_smbios_str(topo_mod_t *, const char *, int);

#ifdef __cplusplus
}
#endif

#endif /* _X86PI_IMPL_H */
