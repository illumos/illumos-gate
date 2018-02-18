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
 * Copyright (c) 2017, Joyent, Inc.
 */

#ifndef	_SYS_DLD_H
#define	_SYS_DLD_H

/*
 * Data-Link Driver ioctl interfaces.
 *
 * Note that the data structures defined here define an ioctl interface
 * that is shared betwen user and kernel space.  The dld driver thus
 * assumes that the structures have identical layout and size when
 * compiled in either IPL32 or LP64.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/mac_flow.h>
#include <sys/conf.h>
#include <sys/sad.h>
#include <sys/mac.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Data-Link Driver Information (text emitted by modinfo(1m))
 */
#define	DLD_INFO	"Data-Link Driver"

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

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

/*
 * IOCTL codes and data structures.
 */
#define	DLDIOC_ATTR	DLDIOC(0x03)

typedef struct dld_ioc_attr {
	datalink_id_t		dia_linkid;
	uint_t			dia_max_sdu;
} dld_ioc_attr_t;

#define	DLDIOC_VLAN_ATTR	DLDIOC(0x04)
typedef struct dld_ioc_vlan_attr {
	datalink_id_t	div_vlanid;
	uint16_t	div_vid;
	datalink_id_t	div_linkid;
	boolean_t	div_force;
} dld_ioc_vlan_attr_t;

#define	DLDIOC_PHYS_ATTR	DLDIOC(0x05)
#define	DLPI_LINKNAME_MAX	32

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

#define	DLDIOC_SECOBJ_SET	DLDIOC(0x06)
typedef struct dld_ioc_secobj_set {
	dld_secobj_t		ss_obj;
	uint_t			ss_flags;
} dld_ioc_secobj_set_t;

#define	DLDIOC_SECOBJ_GET	DLDIOC(0x07)
typedef struct dld_ioc_secobj_get {
	dld_secobj_t		sg_obj;
	uint_t			sg_count;
	uint_t			sg_size;
} dld_ioc_secobj_get_t;

/*
 * The following two slots were used outside of ON, so don't reuse them.
 *
 * #define DLDIOCHOLDVLAN DLDIOC(0x08)
 * #define DLDIOCRELEVLAN DLDIOC(0x09)
 */

#define	DLDIOC_SECOBJ_UNSET	DLDIOC(0x0a)
typedef struct dld_ioc_secobj_unset {
	char			su_name[DLD_SECOBJ_NAME_MAX];
} dld_ioc_secobj_unset_t;

#define	DLDIOC_CREATE_VLAN	DLDIOC(0x0b)
typedef struct dld_ioc_create_vlan {
	datalink_id_t	dic_vlanid;
	datalink_id_t	dic_linkid;
	uint16_t	dic_vid;
	boolean_t	dic_force;
} dld_ioc_create_vlan_t;

#define	DLDIOC_DELETE_VLAN	DLDIOC(0x0c)
typedef struct dld_ioc_delete_vlan {
	datalink_id_t	did_linkid;
} dld_ioc_delete_vlan_t;

/*
 * The following constants have been removed, and the slots are open:
 *
 * #define DLDIOC_SETAUTOPUSH	DLDIOC(0x0d)
 * #define DLDIOC_GETAUTOPUSH	DLDIOC(0x0e)
 * #define DLDIOC_CLRAUTOPUSH	DLDIOC(0x0f)
 */

#define	DLDIOC_DOORSERVER	DLDIOC(0x10)
typedef struct dld_ioc_door {
	boolean_t	did_start_door;
} dld_ioc_door_t;

#define	DLDIOC_RENAME		DLDIOC(0x11)
typedef struct dld_ioc_rename {
	datalink_id_t	dir_linkid1;
	datalink_id_t	dir_linkid2;
	char		dir_link[MAXLINKNAMELEN];
} dld_ioc_rename_t;

/*
 * The following constants have been removed, and the slots are open:
 *
 * #define DLDIOC_SETZID	DLDIOC(0x12)
 * #define DLDIOC_GETZID	DLDIOC(0x13)
 */

typedef struct dld_ioc_zid {
	zoneid_t	diz_zid;
	datalink_id_t	diz_linkid;
} dld_ioc_zid_t;

/*
 * data-link autopush configuration.
 */
struct dlautopush {
	uint_t	dap_anchor;
	uint_t	dap_npush;
	char	dap_aplist[MAXAPUSH][FMNAMESZ+1];
};

#define	DLDIOC_MACADDRGET	DLDIOC(0x15)
typedef struct dld_ioc_macaddrget {
	datalink_id_t	dig_linkid;
	uint_t		dig_count;
	uint_t		dig_size;
} dld_ioc_macaddrget_t;

/* possible flags for dmi_flags below */
#define	DLDIOCMACADDR_USED	0x1	/* address slot used */

typedef struct dld_macaddrinfo {
	uint_t		dmi_slot;
	uint_t		dmi_flags;
	uint_t		dmi_addrlen;
	uchar_t		dmi_addr[MAXMACADDRLEN];
	char		dmi_client_name[MAXNAMELEN];
	datalink_id_t	dma_client_linkid;
} dld_macaddrinfo_t;

/*
 * IOCTL codes and data structures for flowadm.
 */
#define	DLDIOC_ADDFLOW		DLDIOC(0x16)
typedef struct dld_ioc_addflow {
	datalink_id_t		af_linkid;
	flow_desc_t		af_flow_desc;
	mac_resource_props_t	af_resource_props;
	char			af_name[MAXFLOWNAMELEN];
} dld_ioc_addflow_t;

#define	DLDIOC_REMOVEFLOW	DLDIOC(0x17)
typedef struct dld_ioc_removeflow {
	char			rf_name[MAXFLOWNAMELEN];
} dld_ioc_removeflow_t;

#define	DLDIOC_MODIFYFLOW	DLDIOC(0x18)
typedef struct dld_ioc_modifyflow {
	char			mf_name[MAXFLOWNAMELEN];
	mac_resource_props_t	mf_resource_props;
} dld_ioc_modifyflow_t;

#define	DLDIOC_WALKFLOW		DLDIOC(0x19)
typedef struct dld_ioc_walkflow {
	datalink_id_t		wf_linkid;
	char			wf_name[MAXFLOWNAMELEN];
	uint32_t		wf_nflows;
	uint_t			wf_len;
} dld_ioc_walkflow_t;

typedef struct dld_flowinfo {
	datalink_id_t		fi_linkid;
	flow_desc_t		fi_flow_desc;
	mac_resource_props_t	fi_resource_props;
	char			fi_flowname[MAXFLOWNAMELEN];
	uint32_t		fi_pad;
} dld_flowinfo_t;

#define	DLDIOC_USAGELOG		DLDIOC(0x1a)
typedef struct dld_ioc_usagelog {
	mac_logtype_t	ul_type;
	boolean_t	ul_onoff;
	uint_t		ul_interval;
} dld_ioc_usagelog_t;

#define	DLDIOC_SETMACPROP	DLDIOC(0x1b)
#define	DLDIOC_GETMACPROP	DLDIOC(0x1c)

/* pr_flags can be set to a combination of the following flags */
#define	DLD_PROP_DEFAULT	0x0001
#define	DLD_PROP_POSSIBLE	0x0002

typedef struct dld_ioc_macprop_s {
	uint_t		pr_flags;
	datalink_id_t	pr_linkid;
	mac_prop_id_t	pr_num;
	uint_t		pr_perm_flags;
	char    	pr_name[MAXLINKPROPNAME];
	uint_t		pr_valsize;		/* sizeof pr_val */
	char		pr_val[1];
} dld_ioc_macprop_t;

#define	DLDIOC_GETHWGRP		DLDIOC(0x1d)

typedef struct dld_ioc_hwgrpget {
	datalink_id_t	dih_linkid;
	uint_t		dih_n_groups;	/* number of groups included in ioc */
	uint_t		dih_size;
} dld_ioc_hwgrpget_t;

#define	MAXCLIENTNAMELEN	1024
typedef struct dld_hwgrpinfo {
	char	dhi_link_name[MAXLINKNAMELEN];
	uint_t	dhi_grp_num;
	uint_t	dhi_grp_type;
	uint_t	dhi_n_rings;
	uint_t	dhi_n_clnts;
	uint_t	dhi_rings[MAX_RINGS_PER_GROUP];
	char	dhi_clnts[MAXCLIENTNAMELEN];
} dld_hwgrpinfo_t;

#define	DLDIOC_GETTRAN		DLDIOC(0x1e)

#define	DLDIOC_GETTRAN_GETNTRAN	UINT32_MAX

typedef struct dld_ioc_gettran {
	datalink_id_t		dgt_linkid;
	uint_t			dgt_tran_id;
	boolean_t		dgt_present;
	boolean_t		dgt_usable;
} dld_ioc_gettran_t;

#define	DLDIOC_READTRAN		DLDIOC(0x1f)
typedef struct dld_ioc_tranio {
	datalink_id_t	dti_linkid;
	uint_t		dti_tran_id;
	uint_t		dti_page;
	uint_t		dti_nbytes;
	uint_t		dti_off;
	uint64_t	dti_buf;
} dld_ioc_tranio_t;

#define	DLDIOC_GETLED		DLDIOC(0x20)
#define	DLDIOC_SETLED		DLDIOC(0x21)

typedef struct dld_ioc_led {
	datalink_id_t	dil_linkid;
	mac_led_mode_t	dil_supported;
	mac_led_mode_t	dil_active;
	uint_t		dil_pad;
} dld_ioc_led_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#ifdef _KERNEL

#define	DLD_CAPAB_DIRECT	0x00000001
#define	DLD_CAPAB_POLL		0x00000002
#define	DLD_CAPAB_PERIM		0x00000003
#define	DLD_CAPAB_LSO		0x00000004

#define	DLD_ENABLE		0x00000001
#define	DLD_DISABLE		0x00000002
#define	DLD_QUERY		0x00000003

/*
 * GLDv3 entry point for negotiating capabilities.
 * This is exposed to IP after negotiation of DL_CAPAB_DLD.
 *
 * This function takes the following arguments:
 * handle: used for identifying the interface to operate on (provided by dld).
 * type: capability type.
 * arg: points to a capability-specific structure.
 * flags: used for indicating whether to enable or disable a capability.
 *
 * With this function, capability negotiation is reduced from a multi-step
 * process to just one single function call.
 * e.g. the following code would pass 'x' from IP to dld and obtain
 * arg.output_arg from dld:
 *
 * arg.input_arg = x;
 * rc = (*dld_capab)(handle, DLD_CAPAB_XXX, &arg, DLD_ENABLE);
 * ill->info1 = arg.output_arg;
 */
typedef	int	(*dld_capab_func_t)(void *, uint_t, void *, uint_t);

/*
 * Direct Tx/Rx capability.
 */
typedef struct dld_capab_direct_s {
	/*
	 * Rx entry point and handle, owned by IP.
	 */
	uintptr_t	di_rx_cf;
	void		*di_rx_ch;

	/*
	 * Tx entry points and handle, owned by DLD.
	 */
	/* Entry point for transmitting packets */
	uintptr_t	di_tx_df;
	void		*di_tx_dh;

	/* flow control notification callback */
	uintptr_t	di_tx_cb_df; /* callback registration/de-registration */
	void		*di_tx_cb_dh;

	/* flow control "can I put on a ring" callback */
	uintptr_t	di_tx_fctl_df; /* canput-like callback */
	void		*di_tx_fctl_dh;
} dld_capab_direct_t;

/*
 * Polling/softring capability.
 */
#define	POLL_SOFTRING		0x00000001
typedef struct dld_capab_poll_s {
	uintptr_t	poll_ring_add_cf;
	uintptr_t	poll_ring_remove_cf;
	uintptr_t	poll_ring_quiesce_cf;
	uintptr_t	poll_ring_restart_cf;
	uintptr_t	poll_ring_bind_cf;
	void		*poll_ring_ch;
	uintptr_t	poll_mac_accept_df;
	void		*poll_mac_dh;
} dld_capab_poll_t;

/*
 * LSO capability
 */
/*
 * Currently supported flags for LSO.
 */
#define	DLD_LSO_BASIC_TCP_IPV4	0x01	/* TCP LSO over IPv4 capability */
#define	DLD_LSO_BASIC_TCP_IPV6	0x02	/* TCP LSO over IPv6 capability */

typedef struct dld_capab_lso_s {
	uint_t  lso_flags;	/* capability flags */
	uint_t  lso_max;	/* maximum payload */
} dld_capab_lso_t;

int	dld_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
int	dld_devt_to_instance(dev_t);
int	dld_open(queue_t *, dev_t *, int, int, cred_t *);
int	dld_close(queue_t *);
void	dld_wput(queue_t *, mblk_t *);
void	dld_wsrv(queue_t *);
int	dld_str_open(queue_t *, dev_t *, void *);
int	dld_str_close(queue_t *);
void	*dld_str_private(queue_t *);
void	dld_init_ops(struct dev_ops *, const char *);
void	dld_fini_ops(struct dev_ops *);
int	dld_autopush(dev_t *, struct dlautopush *);

int	dld_add_flow(datalink_id_t, char *, flow_desc_t *,
    mac_resource_props_t *);
int	dld_remove_flow(char *);
int	dld_modify_flow(char *, mac_resource_props_t *);
int	dld_walk_flow(dld_ioc_walkflow_t *, intptr_t, cred_t *);

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DLD_H */
