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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 * Copyright (c) 2015 Garrett D'Amore <garrett@damore.org>
 */

#ifndef	_SYS_MAC_H
#define	_SYS_MAC_H

#include <sys/types.h>
#ifdef	_KERNEL
#include <sys/sunddi.h>
#endif

/*
 * MAC Services Module
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * MAC Information (text emitted by modinfo(1m))
 */
#define	MAC_INFO	"MAC Services"

/*
 * MAC-Type version identifier.  This is used by mactype_alloc() and
 * mactype_register() to verify that incompatible MAC-Type plugins don't
 * register.
 */
#define	MACTYPE_VERSION	0x1

/*
 * Opaque handle types
 */
typedef struct __mac_handle		*mac_handle_t;
typedef struct __mac_resource_handle	*mac_resource_handle_t;
typedef struct __mac_notify_handle	*mac_notify_handle_t;
typedef struct __mac_tx_notify_handle	*mac_tx_notify_handle_t;
typedef	struct __mac_intr_handle	*mac_intr_handle_t;
typedef	struct __mac_ring_handle	*mac_ring_handle_t;
typedef	struct __mac_group_handle	*mac_group_handle_t;

#define	DATALINK_INVALID_LINKID	0
#define	DATALINK_ALL_LINKID	0
#define	DATALINK_MAX_LINKID	0xffffffff

typedef enum {
	LINK_STATE_UNKNOWN = -1,
	LINK_STATE_DOWN,
	LINK_STATE_UP
} link_state_t;

typedef enum {
	LINK_DUPLEX_UNKNOWN = 0,
	LINK_DUPLEX_HALF,
	LINK_DUPLEX_FULL
} link_duplex_t;

typedef enum {
	LINK_FLOWCTRL_NONE = 0,
	LINK_FLOWCTRL_RX,
	LINK_FLOWCTRL_TX,
	LINK_FLOWCTRL_BI
} link_flowctrl_t;

typedef enum {
	LINK_TAGMODE_VLANONLY = 0,
	LINK_TAGMODE_NORMAL
} link_tagmode_t;

/*
 * Defines range of uint32_t values
 */
typedef struct mac_propval_uint32_range_s {
	uint32_t mpur_min;
	uint32_t mpur_max;
} mac_propval_uint32_range_t;

/*
 * Data type of property values.
 */
typedef enum {
	MAC_PROPVAL_UINT8,
	MAC_PROPVAL_UINT32,
	MAC_PROPVAL_STR
} mac_propval_type_t;

/*
 * Captures possible values for a given property. A property can have
 * range of values (int32, int64, uint32, uint64, et al) or collection/
 * enumeration of values (strings).
 * Can be used as a value-result parameter.
 */
typedef struct mac_propval_range_s {
	uint_t mpr_count;			/* count of ranges */
	mac_propval_type_t mpr_type;		/* type of value */
	union {
		mac_propval_uint32_range_t mpr_uint32[1];
	} u;
} mac_propval_range_t;

#define	mpr_range_uint32	u.mpr_uint32

/*
 * Maximum MAC address length
 */
#define	MAXMACADDRLEN		20

#define	MPT_MAXMACADDR		32

typedef struct mac_secondary_addr_s {
	uint32_t	ms_addrcnt;
	uint8_t		ms_addrs[MPT_MAXMACADDR][MAXMACADDRLEN];
} mac_secondary_addr_t;

typedef enum {
	MAC_LOGTYPE_LINK = 1,
	MAC_LOGTYPE_FLOW
} mac_logtype_t;

#define	MAXLINKPROPNAME		256		/* max property name len */

/*
 * Public properties.
 *
 * Note that there are 2 sets of parameters: the *_EN_* values are
 * those that the Administrator configures for autonegotiation. The
 * _ADV_* values are those that are currently exposed over the wire.
 */
typedef enum {
	MAC_PROP_DUPLEX = 0x00000001,
	MAC_PROP_SPEED,
	MAC_PROP_STATUS,
	MAC_PROP_AUTONEG,
	MAC_PROP_EN_AUTONEG,
	MAC_PROP_MTU,
	MAC_PROP_ZONE,
	MAC_PROP_AUTOPUSH,
	MAC_PROP_FLOWCTRL,
	MAC_PROP_ADV_1000FDX_CAP,
	MAC_PROP_EN_1000FDX_CAP,
	MAC_PROP_ADV_1000HDX_CAP,
	MAC_PROP_EN_1000HDX_CAP,
	MAC_PROP_ADV_100FDX_CAP,
	MAC_PROP_EN_100FDX_CAP,
	MAC_PROP_ADV_100HDX_CAP,
	MAC_PROP_EN_100HDX_CAP,
	MAC_PROP_ADV_10FDX_CAP,
	MAC_PROP_EN_10FDX_CAP,
	MAC_PROP_ADV_10HDX_CAP,
	MAC_PROP_EN_10HDX_CAP,
	MAC_PROP_ADV_100T4_CAP,
	MAC_PROP_EN_100T4_CAP,
	MAC_PROP_IPTUN_HOPLIMIT,
	MAC_PROP_IPTUN_ENCAPLIMIT,
	MAC_PROP_WL_ESSID,
	MAC_PROP_WL_BSSID,
	MAC_PROP_WL_BSSTYPE,
	MAC_PROP_WL_LINKSTATUS,
	MAC_PROP_WL_DESIRED_RATES,
	MAC_PROP_WL_SUPPORTED_RATES,
	MAC_PROP_WL_AUTH_MODE,
	MAC_PROP_WL_ENCRYPTION,
	MAC_PROP_WL_RSSI,
	MAC_PROP_WL_PHY_CONFIG,
	MAC_PROP_WL_CAPABILITY,
	MAC_PROP_WL_WPA,
	MAC_PROP_WL_SCANRESULTS,
	MAC_PROP_WL_POWER_MODE,
	MAC_PROP_WL_RADIO,
	MAC_PROP_WL_ESS_LIST,
	MAC_PROP_WL_KEY_TAB,
	MAC_PROP_WL_CREATE_IBSS,
	MAC_PROP_WL_SETOPTIE,
	MAC_PROP_WL_DELKEY,
	MAC_PROP_WL_KEY,
	MAC_PROP_WL_MLME,
	MAC_PROP_TAGMODE,
	MAC_PROP_ADV_10GFDX_CAP,
	MAC_PROP_EN_10GFDX_CAP,
	MAC_PROP_PVID,
	MAC_PROP_LLIMIT,
	MAC_PROP_LDECAY,
	MAC_PROP_RESOURCE,
	MAC_PROP_RESOURCE_EFF,
	MAC_PROP_RXRINGSRANGE,
	MAC_PROP_TXRINGSRANGE,
	MAC_PROP_MAX_TX_RINGS_AVAIL,
	MAC_PROP_MAX_RX_RINGS_AVAIL,
	MAC_PROP_MAX_RXHWCLNT_AVAIL,
	MAC_PROP_MAX_TXHWCLNT_AVAIL,
	MAC_PROP_IB_LINKMODE,
	MAC_PROP_VN_PROMISC_FILTERED,
	MAC_PROP_SECONDARY_ADDRS,
	MAC_PROP_ADV_40GFDX_CAP,
	MAC_PROP_EN_40GFDX_CAP,
	MAC_PROP_ADV_100GFDX_CAP,
	MAC_PROP_EN_100GFDX_CAP,
	MAC_PROP_ADV_2500FDX_CAP,
	MAC_PROP_EN_2500FDX_CAP,
	MAC_PROP_ADV_5000FDX_CAP,
	MAC_PROP_EN_5000FDX_CAP,
	MAC_PROP_PRIVATE = -1
} mac_prop_id_t;

/*
 * Flags to figure out r/w status of legacy ndd props.
 */
#define	MAC_PROP_PERM_READ		0x0001
#define	MAC_PROP_PERM_WRITE		0x0010
#define	MAC_PROP_MAP_KSTAT		0x0100
#define	MAC_PROP_PERM_RW		(MAC_PROP_PERM_READ|MAC_PROP_PERM_WRITE)
#define	MAC_PROP_FLAGS_RK		(MAC_PROP_PERM_READ|MAC_PROP_MAP_KSTAT)

#ifdef	_KERNEL

/*
 * There are three ranges of statistics values.  0 to 1 - MAC_STAT_MIN are
 * interface statistics maintained by the mac module.  MAC_STAT_MIN to 1 -
 * MACTYPE_STAT_MIN are common MAC statistics defined by the mac module and
 * maintained by each driver.  MACTYPE_STAT_MIN and above are statistics
 * defined by MAC-Type plugins and maintained by each driver.
 */
#define	MAC_STAT_MIN		1000
#define	MACTYPE_STAT_MIN	2000

#define	IS_MAC_STAT(stat)	\
	(stat >= MAC_STAT_MIN && stat < MACTYPE_STAT_MIN)
#define	IS_MACTYPE_STAT(stat)	(stat >= MACTYPE_STAT_MIN)

/*
 * Statistics maintained by the mac module, and possibly populated as link
 * statistics.
 */
enum mac_mod_stat {
	MAC_STAT_LINK_STATE,
	MAC_STAT_LINK_UP,
	MAC_STAT_PROMISC,
	MAC_STAT_LOWLINK_STATE,
	MAC_STAT_HDROPS
};

/*
 * Do not reorder, and add only to the end of this list.
 */
enum mac_driver_stat {
	/* MIB-II stats (RFC 1213 and RFC 1573) */
	MAC_STAT_IFSPEED = MAC_STAT_MIN,
	MAC_STAT_MULTIRCV,
	MAC_STAT_BRDCSTRCV,
	MAC_STAT_MULTIXMT,
	MAC_STAT_BRDCSTXMT,
	MAC_STAT_NORCVBUF,
	MAC_STAT_IERRORS,
	MAC_STAT_UNKNOWNS,
	MAC_STAT_NOXMTBUF,
	MAC_STAT_OERRORS,
	MAC_STAT_COLLISIONS,
	MAC_STAT_RBYTES,
	MAC_STAT_IPACKETS,
	MAC_STAT_OBYTES,
	MAC_STAT_OPACKETS,
	MAC_STAT_UNDERFLOWS,
	MAC_STAT_OVERFLOWS
};

#define	MAC_NSTAT	(MAC_STAT_OVERFLOWS - MAC_STAT_IFSPEED + 1)

#define	MAC_STAT_ISACOUNTER(_stat) (		\
	    (_stat) == MAC_STAT_MULTIRCV ||	\
	    (_stat) == MAC_STAT_BRDCSTRCV ||	\
	    (_stat) == MAC_STAT_MULTIXMT ||	\
	    (_stat) == MAC_STAT_BRDCSTXMT ||	\
	    (_stat) == MAC_STAT_NORCVBUF ||	\
	    (_stat) == MAC_STAT_IERRORS ||	\
	    (_stat) == MAC_STAT_UNKNOWNS ||	\
	    (_stat) == MAC_STAT_NOXMTBUF ||	\
	    (_stat) == MAC_STAT_OERRORS ||	\
	    (_stat) == MAC_STAT_COLLISIONS ||	\
	    (_stat) == MAC_STAT_RBYTES ||	\
	    (_stat) == MAC_STAT_IPACKETS ||	\
	    (_stat) == MAC_STAT_OBYTES ||	\
	    (_stat) == MAC_STAT_OPACKETS ||	\
	    (_stat) == MAC_STAT_UNDERFLOWS ||	\
	    (_stat) == MAC_STAT_OVERFLOWS)

/*
 * Immutable information. (This may not be modified after registration).
 */
typedef struct mac_info_s {
	uint_t		mi_media;
	uint_t		mi_nativemedia;
	uint_t		mi_addr_length;
	uint8_t		*mi_unicst_addr;
	uint8_t		*mi_brdcst_addr;
} mac_info_t;

/*
 * When VNICs are created on top of the NIC, there are two levels
 * of MAC layer, a lower MAC, which is the MAC layer at the level of the
 * physical NIC, and an upper MAC, which is the MAC layer at the level
 * of the VNIC. Each VNIC maps to a MAC client at the lower MAC, and
 * the SRS and classification is done at the lower MAC level. The upper
 * MAC is therefore for the most part pass-through, and therefore
 * special processing needs to be done at the upper MAC layer when
 * dealing with a VNIC.
 *
 * This capability allows the MAC layer to detect when a VNIC is being
 * access, and implement the required shortcuts.
 *
 * In addition, this capability is used to keep the VNIC's secondary
 * mac_clients in sync when the primary MAC is updated.
 */

typedef void *(*mac_client_handle_fn_t)(void *);
typedef void (*mac_client_update_fn_t)(void *);

typedef struct mac_capab_vnic_s {
	void			*mcv_arg;
	mac_client_handle_fn_t	mcv_mac_client_handle;
	mac_client_update_fn_t	mcv_mac_secondary_update;
} mac_capab_vnic_t;

typedef void (*mac_rename_fn_t)(const char *, void *);
typedef mblk_t *(*mac_tx_ring_fn_t)(void *, mblk_t *, uintptr_t,
    mac_ring_handle_t *);
typedef struct mac_capab_aggr_s {
	mac_rename_fn_t mca_rename_fn;
	int (*mca_unicst)(void *, const uint8_t *);
	mac_tx_ring_fn_t mca_find_tx_ring_fn;
	void *mca_arg;
} mac_capab_aggr_t;

/* Bridge transmit and receive function signatures */
typedef mblk_t *(*mac_bridge_tx_t)(mac_handle_t, mac_ring_handle_t, mblk_t *);
typedef void (*mac_bridge_rx_t)(mac_handle_t, mac_resource_handle_t, mblk_t *);
typedef void (*mac_bridge_ref_t)(mac_handle_t, boolean_t);
typedef link_state_t (*mac_bridge_ls_t)(mac_handle_t, link_state_t);

/* must change mac_notify_cb_list[] in mac_provider.c if this is changed */
typedef enum {
	MAC_NOTE_LINK,
	MAC_NOTE_UNICST,
	MAC_NOTE_TX,
	MAC_NOTE_DEVPROMISC,
	MAC_NOTE_FASTPATH_FLUSH,
	MAC_NOTE_SDU_SIZE,
	MAC_NOTE_DEST,
	MAC_NOTE_MARGIN,
	MAC_NOTE_CAPAB_CHG,
	MAC_NOTE_LOWLINK,
	MAC_NOTE_ALLOWED_IPS,
	MAC_NNOTE	/* must be the last entry */
} mac_notify_type_t;

typedef void		(*mac_notify_t)(void *, mac_notify_type_t);
typedef void		(*mac_rx_t)(void *, mac_resource_handle_t, mblk_t *,
			    boolean_t);
typedef	mblk_t		*(*mac_receive_t)(void *, int);

/*
 * MAC resource types
 */
typedef enum {
	MAC_RX_FIFO = 1
} mac_resource_type_t;

typedef	int	(*mac_intr_enable_t)(mac_intr_handle_t);
typedef	int	(*mac_intr_disable_t)(mac_intr_handle_t);

typedef	struct mac_intr_s {
	mac_intr_handle_t	mi_handle;
	mac_intr_enable_t	mi_enable;
	mac_intr_disable_t	mi_disable;
	ddi_intr_handle_t	mi_ddi_handle;
	boolean_t		mi_ddi_shared;
} mac_intr_t;

typedef struct mac_rx_fifo_s {
	mac_resource_type_t	mrf_type;	/* MAC_RX_FIFO */
	mac_intr_t		mrf_intr;
	mac_receive_t		mrf_receive;
	void			*mrf_rx_arg;
	uint32_t		mrf_flow_priority;
	/*
	 * The CPU this flow is to be processed on. With intrd and future
	 * things, we should know which CPU the flow needs to be processed
	 * and get a squeue assigned on that CPU.
	 */
	uint_t			mrf_cpu_id;
} mac_rx_fifo_t;

#define	mrf_intr_handle		mrf_intr.mi_handle
#define	mrf_intr_enable		mrf_intr.mi_enable
#define	mrf_intr_disable	mrf_intr.mi_disable

typedef union mac_resource_u {
	mac_resource_type_t	mr_type;
	mac_rx_fifo_t		mr_fifo;
} mac_resource_t;

typedef enum {
	MAC_ADDRTYPE_UNICAST,
	MAC_ADDRTYPE_MULTICAST,
	MAC_ADDRTYPE_BROADCAST
} mac_addrtype_t;

typedef struct mac_header_info_s {
	size_t		mhi_hdrsize;
	size_t		mhi_pktsize;
	const uint8_t	*mhi_daddr;
	const uint8_t	*mhi_saddr;
	uint32_t	mhi_origsap;
	uint32_t	mhi_bindsap;
	mac_addrtype_t	mhi_dsttype;
	uint16_t	mhi_tci;
	boolean_t	mhi_istagged;
	boolean_t	mhi_ispvid;
} mac_header_info_t;

/*
 * Function pointer to match dls client signature. Should be same as
 * dls_rx_t to allow a soft ring to bypass DLS layer and call a DLS
 * client directly.
 */
typedef	void		(*mac_direct_rx_t)(void *, mac_resource_handle_t,
				mblk_t *, mac_header_info_t *);

typedef mac_resource_handle_t	(*mac_resource_add_t)(void *, mac_resource_t *);
typedef int			(*mac_resource_bind_t)(void *,
    mac_resource_handle_t, processorid_t);
typedef void			(*mac_resource_remove_t)(void *, void *);
typedef void			(*mac_resource_quiesce_t)(void *, void *);
typedef void			(*mac_resource_restart_t)(void *, void *);
typedef int			(*mac_resource_modify_t)(void *, void *,
				    mac_resource_t *);
typedef	void			(*mac_change_upcall_t)(void *, mac_direct_rx_t,
    void *);

/*
 * MAC-Type plugin interfaces
 */

typedef int		(*mtops_addr_verify_t)(const void *, void *);
typedef boolean_t	(*mtops_sap_verify_t)(uint32_t, uint32_t *, void *);
typedef mblk_t		*(*mtops_header_t)(const void *, const void *,
    uint32_t, void *, mblk_t *, size_t);
typedef int		(*mtops_header_info_t)(mblk_t *, void *,
    mac_header_info_t *);
typedef boolean_t	(*mtops_pdata_verify_t)(void *, size_t);
typedef	mblk_t		*(*mtops_header_modify_t)(mblk_t *, void *);
typedef void		(*mtops_link_details_t)(char *, size_t, mac_handle_t,
    void *);

typedef struct mactype_ops_s {
	uint_t			mtops_ops;
	/*
	 * mtops_unicst_verify() returns 0 if the given address is a valid
	 * unicast address, or a non-zero errno otherwise.
	 */
	mtops_addr_verify_t	mtops_unicst_verify;
	/*
	 * mtops_multicst_verify() returns 0 if the given address is a
	 * valid multicast address, or a non-zero errno otherwise.  If the
	 * media doesn't support multicast, ENOTSUP should be returned (for
	 * example).
	 */
	mtops_addr_verify_t	mtops_multicst_verify;
	/*
	 * mtops_sap_verify() returns B_TRUE if the given SAP is a valid
	 * SAP value, or B_FALSE otherwise.
	 */
	mtops_sap_verify_t	mtops_sap_verify;
	/*
	 * mtops_header() is used to allocate and construct a MAC header.
	 */
	mtops_header_t		mtops_header;
	/*
	 * mtops_header_info() is used to gather information on a given MAC
	 * header.
	 */
	mtops_header_info_t	mtops_header_info;
	/*
	 * mtops_pdata_verify() is used to verify the validity of MAC
	 * plugin data.  It is called by mac_register() if the driver has
	 * supplied MAC plugin data, and also by mac_pdata_update() when
	 * drivers update the data.
	 */
	mtops_pdata_verify_t	mtops_pdata_verify;
	/*
	 * mtops_header_cook() is an optional callback that converts (or
	 * "cooks") the given raw header (as sent by a raw DLPI consumer)
	 * into one that is appropriate to send down to the MAC driver.
	 * Following the example above, an Ethernet header sent down by a
	 * DLPI consumer would be converted to whatever header the MAC
	 * driver expects.
	 */
	mtops_header_modify_t	mtops_header_cook;
	/*
	 * mtops_header_uncook() is an optional callback that does the
	 * opposite of mtops_header_cook().  It "uncooks" a given MAC
	 * header (as received from the driver) for consumption by raw DLPI
	 * consumers.  For example, for a non-Ethernet plugin that wants
	 * raw DLPI consumers to be fooled into thinking that the device
	 * provides Ethernet access, this callback would modify the given
	 * mblk_t such that the MAC header is converted to an Ethernet
	 * header.
	 */
	mtops_header_modify_t	mtops_header_uncook;
	/*
	 * mtops_link_details() is an optional callback that provides
	 * extended information about the link state.  Its primary purpose
	 * is to provide type-specific support for syslog contents on
	 * link up events.  If no implementation is provided, then a default
	 * implementation will be used.
	 */
	mtops_link_details_t	mtops_link_details;
} mactype_ops_t;

/*
 * mtops_ops exists for the plugin to enumerate the optional callback
 * entrypoints it has defined.  This allows the mac module to define
 * additional plugin entrypoints in mactype_ops_t without breaking backward
 * compatibility with old plugins.
 */
#define	MTOPS_PDATA_VERIFY	0x001
#define	MTOPS_HEADER_COOK	0x002
#define	MTOPS_HEADER_UNCOOK	0x004
#define	MTOPS_LINK_DETAILS	0x008

/*
 * Provide mapping for legacy ndd ioctls relevant to that mactype.
 * Note that the ndd ioctls are obsolete, and may be removed in a future
 * release of Solaris. The ndd ioctls are not typically used in legacy
 * ethernet drivers. New datalink drivers of all link-types should use
 * dladm(1m) interfaces for administering tunables and not have to provide
 * a mapping.
 */
typedef struct mac_ndd_mapping_s {
	char		*mp_name;
	union {
		mac_prop_id_t   u_id;
		uint_t		u_kstat;
	} u_mp_id;
	long		mp_minval;
	long		mp_maxval;
	size_t		mp_valsize;
	int		mp_flags;
} mac_ndd_mapping_t;

#define	mp_prop_id	u_mp_id.u_id
#define	mp_kstat	u_mp_id.u_kstat

typedef struct mac_stat_info_s {
	uint_t		msi_stat;
	char		*msi_name;
	uint_t		msi_type;	/* as defined in kstat_named_init(9F) */
	uint64_t	msi_default;
} mac_stat_info_t;

typedef struct mactype_register_s {
	uint_t		mtr_version;	/* set by mactype_alloc() */
	const char	*mtr_ident;
	mactype_ops_t	*mtr_ops;
	uint_t		mtr_mactype;
	uint_t		mtr_nativetype;
	uint_t		mtr_addrlen;
	uint8_t		*mtr_brdcst_addr;
	mac_stat_info_t	*mtr_stats;
	size_t		mtr_statcount;
	mac_ndd_mapping_t *mtr_mapping;
	size_t		mtr_mappingcount;
} mactype_register_t;

/*
 * Driver interface functions.
 */
extern int			mac_open_by_linkid(datalink_id_t,
				    mac_handle_t *);
extern int			mac_open_by_linkname(const char *,
				    mac_handle_t *);
extern const char		*mac_name(mac_handle_t);
extern minor_t			mac_minor(mac_handle_t);
extern minor_t			mac_minor_hold(boolean_t);
extern void			mac_minor_rele(minor_t);
extern void			mac_sdu_get(mac_handle_t, uint_t *, uint_t *);
extern void			mac_sdu_get2(mac_handle_t, uint_t *, uint_t *,
				    uint_t *);
extern int			mac_maxsdu_update(mac_handle_t, uint_t);
extern int			mac_maxsdu_update2(mac_handle_t, uint_t,
				    uint_t);
extern uint_t			mac_addr_len(mac_handle_t);
extern int			mac_type(mac_handle_t);
extern int			mac_nativetype(mac_handle_t);

extern void 			mac_unicst_update(mac_handle_t,
				    const uint8_t *);
extern void			mac_capab_update(mac_handle_t);
extern int			mac_pdata_update(mac_handle_t, void *,
				    size_t);
extern boolean_t		mac_margin_update(mac_handle_t, uint32_t);
extern void			mac_margin_get(mac_handle_t, uint32_t *);
extern int			mac_margin_remove(mac_handle_t, uint32_t);
extern int			mac_margin_add(mac_handle_t, uint32_t *,
				    boolean_t);
extern int			mac_mtu_add(mac_handle_t, uint32_t *,
				    boolean_t);
extern int			mac_mtu_remove(mac_handle_t, uint32_t);
extern int			mac_fastpath_disable(mac_handle_t);
extern void			mac_fastpath_enable(mac_handle_t);
extern void			mac_no_active(mac_handle_t);

extern mactype_register_t	*mactype_alloc(uint_t);
extern void			mactype_free(mactype_register_t *);
extern int			mactype_register(mactype_register_t *);
extern int			mactype_unregister(const char *);

extern int			mac_start_logusage(mac_logtype_t, uint_t);
extern void			mac_stop_logusage(mac_logtype_t);

extern mac_handle_t		mac_get_lower_mac_handle(mac_handle_t);
extern boolean_t		mac_is_vnic_primary(mac_handle_t);

/*
 * Packet hashing for distribution to multiple ports and rings.
 */

#define	MAC_PKT_HASH_L2		0x01
#define	MAC_PKT_HASH_L3		0x02
#define	MAC_PKT_HASH_L4		0x04

extern uint64_t			mac_pkt_hash(uint_t, mblk_t *, uint8_t,
				    boolean_t);

/*
 * Bridging linkage
 */
extern void			mac_rx_common(mac_handle_t,
				    mac_resource_handle_t, mblk_t *);
extern int			mac_bridge_set(mac_handle_t, mac_handle_t);
extern void			mac_bridge_clear(mac_handle_t, mac_handle_t);
extern void			mac_bridge_vectors(mac_bridge_tx_t,
				    mac_bridge_rx_t, mac_bridge_ref_t,
				    mac_bridge_ls_t);

/* special case function for TRILL observability */
extern void			mac_trill_snoop(mac_handle_t, mblk_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_MAC_H */
