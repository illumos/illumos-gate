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

#ifndef	_SYS_DLS_H
#define	_SYS_DLS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stream.h>
#include <net/if.h>
#include <sys/mac.h>

/*
 * Data-Link Services Module
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Module name.
 */
#define	DLS_MODULE_NAME	"dls"

/*
 * Data-Link Services Information (text emitted by modinfo(1m))
 */
#define	DLS_INFO	"Data-Link Services v%I%"

/*
 * Macros for converting ppas to instance #s, Vlan ID, or minor.
 */
#define	DLS_PPA2INST(ppa)	((int)((ppa) % 1000))
#define	DLS_PPA2VID(ppa)	((ppa) / 1000)

/*
 * Converts a minor to an instance#; makes sense only when minor <= 1000.
 */
#define	DLS_MINOR2INST(minor)	((int)((minor) - 1))

typedef enum {
	DATALINK_CLASS_PHYS		= 0x01,
	DATALINK_CLASS_VLAN		= 0x02,
	DATALINK_CLASS_AGGR		= 0x04,
	DATALINK_CLASS_VNIC		= 0x08
} datalink_class_t;

#define	DATALINK_CLASS_ALL	(DATALINK_CLASS_PHYS |	\
	DATALINK_CLASS_VLAN | DATALINK_CLASS_AGGR | DATALINK_CLASS_VNIC)

/*
 * A combination of flags and media.
 *   flags is the higher 32 bits, and if it is 0x01, it indicates all media
 *   types can be accepted; otherwise, only the given media type (specified
 *   in the lower 32 bits) is accepted.
 */
typedef uint64_t	datalink_media_t;

#define	DATALINK_ANY_MEDIATYPE		\
	((datalink_media_t)(((datalink_media_t)0x01) << 32))

#define	DATALINK_MEDIA_ACCEPTED(dmedia, media)				\
	(((uint32_t)(((dmedia) >> 32) & 0xfffffffful) & 0x01) ?		\
	B_TRUE : ((uint32_t)((dmedia) & 0xfffffffful) == (media)))

#define	MAXLINKATTRLEN		32
#define	MAXLINKATTRVALLEN	1024

/*
 * Link attributes used by the kernel.
 */
/*
 * The major number and instance number of the underlying physical device
 * are kept as FPHYMAJ and FPHYINST (major, instance + 1).
 *
 * Set for physical links only.
 */
#define	FPHYMAJ		"phymaj"	/* uint64_t */
#define	FPHYINST	"phyinst"	/* uint64_t */

/*
 * The devname of the physical link. For example, bge0, ce1. Set for physical
 * links only.
 */
#define	FDEVNAME	"devname"	/* string */

/*
 * The door file for the dlmgmtd (data-link management) daemon.
 */
#define	DLMGMT_DOOR	"/etc/svc/volatile/dladm/dlmgmt_door"

/*
 * Door upcall commands.
 */
#define	DLMGMT_CMD_DLS_CREATE		1
#define	DLMGMT_CMD_DLS_GETATTR		2
#define	DLMGMT_CMD_DLS_DESTROY		3
#define	DLMGMT_CMD_GETNAME		4
#define	DLMGMT_CMD_GETLINKID		5
#define	DLMGMT_CMD_GETNEXT		6
#define	DLMGMT_CMD_DLS_UPDATE		7
#define	DLMGMT_CMD_LINKPROP_INIT	8
#define	DLMGMT_CMD_BASE			128

/*
 * Indicate the link mapping is active or persistent
 */
#define	DLMGMT_ACTIVE		0x01
#define	DLMGMT_PERSIST		0x02

/* upcall argument */
typedef struct dlmgmt_door_arg {
	uint_t			ld_cmd;
} dlmgmt_door_arg_t;

typedef struct dlmgmt_upcall_arg_create {
	int			ld_cmd;
	datalink_class_t	ld_class;
	uint32_t		ld_media;
	boolean_t		ld_persist;
	uint64_t		ld_phymaj;
	uint64_t		ld_phyinst;
	char			ld_devname[MAXNAMELEN];
} dlmgmt_upcall_arg_create_t;

/*
 * Note: ld_padding is necessary to keep the size of the structure the
 * same on amd64 and i386.  The same note applies to other ld_padding
 * and lr_paddding fields in structures throughout this file.
 */
typedef struct dlmgmt_upcall_arg_destroy {
	int			ld_cmd;
	datalink_id_t		ld_linkid;
	boolean_t		ld_persist;
	int			ld_padding;
} dlmgmt_upcall_arg_destroy_t;

typedef struct dlmgmt_upcall_arg_update {
	int			ld_cmd;
	boolean_t		ld_novanity;
	uint32_t		ld_media;
	uint32_t		ld_padding;
	char			ld_devname[MAXNAMELEN];
} dlmgmt_upcall_arg_update_t;

typedef struct dlmgmt_upcall_arg_getattr {
	int			ld_cmd;
	datalink_id_t		ld_linkid;
	char			ld_attr[MAXLINKATTRLEN];
} dlmgmt_upcall_arg_getattr_t;

typedef struct dlmgmt_door_getname {
	int			ld_cmd;
	datalink_id_t		ld_linkid;
} dlmgmt_door_getname_t;

typedef struct dlmgmt_door_getlinkid {
	int			ld_cmd;
	char			ld_link[MAXLINKNAMELEN];
} dlmgmt_door_getlinkid_t;

typedef struct dlmgmt_door_getnext_s {
	int			ld_cmd;
	datalink_id_t		ld_linkid;
	datalink_class_t	ld_class;
	uint32_t		ld_flags;
	datalink_media_t	ld_dmedia;
} dlmgmt_door_getnext_t;

typedef struct dlmgmt_door_linkprop_init {
	int			ld_cmd;
	datalink_id_t		ld_linkid;
} dlmgmt_door_linkprop_init_t;

/* upcall return value */
typedef struct dlmgmt_retval_s {
	uint_t			lr_err; /* return error code */
} dlmgmt_retval_t;

typedef dlmgmt_retval_t	dlmgmt_destroy_retval_t,
			dlmgmt_linkprop_init_retval_t;

struct dlmgmt_linkid_retval_s {
	uint_t			lr_err;
	datalink_id_t		lr_linkid;
	uint32_t		lr_flags;
	datalink_class_t	lr_class;
	uint32_t		lr_media;
	uint32_t		lr_padding;
};

typedef struct dlmgmt_linkid_retval_s	dlmgmt_create_retval_t,
					dlmgmt_update_retval_t,
					dlmgmt_getlinkid_retval_t,
					dlmgmt_getnext_retval_t;

typedef struct dlmgmt_getname_retval_s {
	uint_t			lr_err;
	char			lr_link[MAXLINKNAMELEN];
	datalink_class_t	lr_class;
	uint32_t		lr_media;
	uint32_t		lr_flags;
} dlmgmt_getname_retval_t;

typedef struct dlmgmt_getattr_retval_s {
	uint_t			lr_err;
	uint_t			lr_type;
	uint_t			lr_attrsz;
	uint_t			lr_padding;
	char			lr_attrval[MAXLINKATTRVALLEN];
} dlmgmt_getattr_retval_t;

#ifdef	_KERNEL

#define	DLS_MAX_PPA	999
#define	DLS_MAX_MINOR	(DLS_MAX_PPA + 1)

typedef	struct dls_t		*dls_channel_t;

extern int		dls_open_style2_vlan(major_t, uint_t, dls_channel_t *);
extern int		dls_open_by_dev(dev_t, dls_channel_t *);
extern void		dls_close(dls_channel_t);

extern mac_handle_t	dls_mac(dls_channel_t);
extern uint16_t		dls_vid(dls_channel_t);

#define	DLS_SAP_LLC	0
#define	DLS_SAP_PROMISC	(1 << 16)

extern int		dls_bind(dls_channel_t, uint32_t);
extern void		dls_unbind(dls_channel_t);

#define	DLS_PROMISC_SAP		0x00000001
#define	DLS_PROMISC_MULTI	0x00000002
#define	DLS_PROMISC_PHYS	0x00000004

extern int		dls_promisc(dls_channel_t, uint32_t);

extern int		dls_multicst_add(dls_channel_t, const uint8_t *);
extern int		dls_multicst_remove(dls_channel_t, const uint8_t *);

extern mblk_t		*dls_header(dls_channel_t, const uint8_t *,
			    uint16_t, uint_t, mblk_t **);
extern int		dls_header_info(dls_channel_t, mblk_t *,
			    mac_header_info_t *);

typedef	void		(*dls_rx_t)(void *, mac_resource_handle_t, mblk_t *,
			    mac_header_info_t *);

extern void		dls_rx_set(dls_channel_t, dls_rx_t, void *);

extern mblk_t		*dls_tx(dls_channel_t, mblk_t *);

extern boolean_t	dls_active_set(dls_channel_t);
extern void		dls_active_clear(dls_channel_t);

extern dev_info_t	*dls_finddevinfo(dev_t);

typedef struct dls_devnet_s	*dls_dl_handle_t;
typedef struct dls_dev_t	*dls_dev_handle_t;

extern int		dls_devnet_open(const char *,
			    dls_dl_handle_t *, dev_t *);
extern void		dls_devnet_close(dls_dl_handle_t);
extern boolean_t	dls_devnet_rebuild();

extern int		dls_devnet_rename(datalink_id_t, datalink_id_t,
			    const char *);
extern int		dls_devnet_create(mac_handle_t, datalink_id_t);
extern int		dls_devnet_destroy(mac_handle_t, datalink_id_t *);
extern int		dls_devnet_recreate(mac_handle_t, datalink_id_t);
extern int		dls_devnet_create_vlan(datalink_id_t,
			    datalink_id_t, uint16_t, boolean_t);
extern int		dls_devnet_destroy_vlan(datalink_id_t);
extern int		dls_devnet_hold_tmp(datalink_id_t, dls_dl_handle_t *);
extern void		dls_devnet_rele_tmp(dls_dl_handle_t);
extern void		dls_devnet_prop_task_wait(dls_dl_handle_t);

extern const char	*dls_devnet_mac(dls_dl_handle_t);
extern uint16_t		dls_devnet_vid(dls_dl_handle_t);
extern datalink_id_t	dls_devnet_linkid(dls_dl_handle_t);
extern boolean_t	dls_devnet_is_explicit(dls_dl_handle_t);
extern int		dls_devnet_dev2linkid(dev_t, datalink_id_t *);
extern int		dls_devnet_phydev(datalink_id_t, dev_t *);
extern int		dls_devnet_setzid(const char *, zoneid_t);
extern int		dls_devnet_getzid(datalink_id_t, zoneid_t *);

extern int		dls_mgmt_door_set(boolean_t);
extern int		dls_mgmt_create(const char *, dev_t, datalink_class_t,
			    uint32_t, boolean_t, datalink_id_t *);
extern int		dls_mgmt_destroy(datalink_id_t, boolean_t);
extern int		dls_mgmt_update(const char *, uint32_t, boolean_t,
			    uint32_t *, datalink_id_t *);
extern int		dls_mgmt_get_linkinfo(datalink_id_t, char *,
			    datalink_class_t *, uint32_t *, uint32_t *);
extern int		dls_mgmt_get_linkid(const char *, datalink_id_t *);
extern datalink_id_t	dls_mgmt_get_next(datalink_id_t, datalink_class_t,
			    datalink_media_t, uint32_t);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DLS_H */
