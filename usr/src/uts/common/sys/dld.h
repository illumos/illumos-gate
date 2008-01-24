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

#ifndef	_SYS_DLD_H
#define	_SYS_DLD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Data-Link Driver (public header).
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/mac.h>
#include <sys/dls.h>
#include <sys/conf.h>
#include <sys/sad.h>
#include <net/if.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Data-Link Driver Information (text emitted by modinfo(1m))
 */
#define	DLD_INFO	"Data-Link Driver v%I%"

/*
 * Options: To enable an option set the property name to a non-zero value
 *	    in kernel/drv/dld.conf.
 */

/*
 * Prevent use of the IP fast-path (direct M_DATA transmit).
 */
#define	DLD_PROP_NO_FASTPATH	"no-fastpath"

/*
 * Prevent advertising of the DL_CAPAB_POLL capability.
 */
#define	DLD_PROP_NO_POLL	"no-poll"

/*
 * Prevent advertising of the DL_CAPAB_ZEROCOPY capability.
 */
#define	DLD_PROP_NO_ZEROCOPY	"no-zerocopy"

/*
 * Prevent advertising of the DL_CAPAB_SOFTRING capability.
 */
#define	DLD_PROP_NO_SOFTRING	"no-softring"

/*
 * The name of the driver.
 */
#define	DLD_DRIVER_NAME		"dld"

/*
 * The name of the control minor node of dld.
 */
#define	DLD_CONTROL_MINOR_NAME	"ctl"
#define	DLD_CONTROL_MINOR	0
#define	DLD_CONTROL_DEV		"/devices/pseudo/" DLD_DRIVER_NAME "@0:" \
				DLD_CONTROL_MINOR_NAME

/*
 * IOCTL codes and data structures.
 */
#define	DLDIOC		('D' << 24 | 'L' << 16 | 'D' << 8)

#define	DLDIOC_ATTR	(DLDIOC | 0x03)

typedef struct dld_ioc_attr {
	datalink_id_t	dia_linkid;
	uint_t		dia_max_sdu;
} dld_ioc_attr_t;

#define	DLDIOC_VLAN_ATTR	(DLDIOC | 0x04)
typedef struct dld_ioc_vlan_attr {
	datalink_id_t	div_vlanid;
	uint16_t	div_vid;
	datalink_id_t	div_linkid;
	boolean_t	div_force;
	boolean_t	div_implicit;
} dld_ioc_vlan_attr_t;

#define	DLDIOC_PHYS_ATTR	(DLDIOC | 0x05)
typedef struct dld_ioc_phys_attr {
	datalink_id_t	dip_linkid;
	/*
	 * Whether this physical link supports vanity naming. Note that
	 * physical links whose media type is not supported by GLDv3
	 * can not support vanity naming.
	 */
	boolean_t	dip_novanity;
	char		dip_dev[MAXLINKNAMELEN];
} dld_ioc_phys_attr_t;

/*
 * Secure objects ioctls
 */
typedef enum {
	DLD_SECOBJ_CLASS_WEP = 1,
	DLD_SECOBJ_CLASS_WPA
} dld_secobj_class_t;

#define	DLD_SECOBJ_OPT_CREATE	0x00000001
#define	DLD_SECOBJ_NAME_MAX	32
#define	DLD_SECOBJ_VAL_MAX	256
typedef struct dld_secobj {
	char			so_name[DLD_SECOBJ_NAME_MAX];
	dld_secobj_class_t	so_class;
	uint8_t			so_val[DLD_SECOBJ_VAL_MAX];
	uint_t			so_len;
} dld_secobj_t;

#define	DLDIOC_SECOBJ_SET	(DLDIOC | 0x06)
typedef struct dld_ioc_secobj_set {
	dld_secobj_t		ss_obj;
	uint_t			ss_flags;
} dld_ioc_secobj_set_t;

#define	DLDIOC_SECOBJ_GET	(DLDIOC | 0x07)
typedef struct dld_ioc_secobj_get {
	dld_secobj_t		sg_obj;
	uint_t			sg_count;
} dld_ioc_secobj_get_t;

/*
 * The following two slots were used outside of ON, so don't reuse them.
 *
 * #define DLDIOCHOLDVLAN (DLDIOC | 0x08)
 * #define DLDIOCRELEVLAN (DLDIOC | 0x09)
 */

#define	DLDIOC_SECOBJ_UNSET	(DLDIOC | 0x0a)
typedef struct dld_ioc_secobj_unset {
	char			su_name[DLD_SECOBJ_NAME_MAX];
} dld_ioc_secobj_unset_t;

#define	DLDIOC_CREATE_VLAN	(DLDIOC | 0x0b)
typedef struct dld_ioc_create_vlan {
	datalink_id_t	dic_vlanid;
	datalink_id_t	dic_linkid;
	uint16_t	dic_vid;
	boolean_t	dic_force;
} dld_ioc_create_vlan_t;

#define	DLDIOC_DELETE_VLAN	(DLDIOC | 0x0c)
typedef struct dld_ioc_delete_vlan {
	datalink_id_t	did_linkid;
} dld_ioc_delete_vlan_t;

#define	DLDIOC_SETAUTOPUSH	(DLDIOC | 0x0d)
#define	DLDIOC_GETAUTOPUSH	(DLDIOC | 0x0e)
#define	DLDIOC_CLRAUTOPUSH	(DLDIOC | 0x0f)
typedef struct dld_ioc_ap {
	datalink_id_t	dia_linkid;
	uint_t  	dia_anchor;
	uint_t		dia_npush;
	char		dia_aplist[MAXAPUSH][FMNAMESZ+1];
} dld_ioc_ap_t;

#define	DLDIOC_DOORSERVER	(DLDIOC | 0x10)
typedef struct dld_ioc_door {
	boolean_t	did_start_door;
} dld_ioc_door_t;

#define	DLDIOC_RENAME		(DLDIOC | 0x11)
typedef struct dld_ioc_rename {
	datalink_id_t	dir_linkid1;
	datalink_id_t	dir_linkid2;
	char		dir_link[MAXLINKNAMELEN];
} dld_ioc_rename_t;

/*
 * DLDIOC_SETZID sets the zoneid of a given link. It could cause a VLAN to be
 * implicitly created.  Note that we will hold a reference for the given link
 * whenever it has a zoneid other than the global zone.
 */
#define	DLDIOC_SETZID		(DLDIOC | 0x12)
typedef struct dld_ioc_setzid {
	char		dis_link[MAXLINKNAMELEN];
	zoneid_t	dis_zid;
} dld_ioc_setzid_t;

#define	DLDIOC_GETZID  		(DLDIOC | 0x13)
typedef struct dld_ioc_getzid {
	datalink_id_t	dig_linkid;
	zoneid_t	dig_zid;
} dld_ioc_getzid_t;

/*
 * data-link autopush configuration.
 */
struct dlautopush {
	uint_t	dap_anchor;
	uint_t	dap_npush;
	char	dap_aplist[MAXAPUSH][FMNAMESZ+1];
};

#ifdef _KERNEL
int	dld_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
int	dld_open(queue_t *, dev_t *, int, int, cred_t *);
int	dld_close(queue_t *);
void	dld_wput(queue_t *, mblk_t *);
void	dld_wsrv(queue_t *);
void	dld_init_ops(struct dev_ops *, const char *);
void	dld_fini_ops(struct dev_ops *);
int	dld_autopush(dev_t *, struct dlautopush *);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DLD_H */
