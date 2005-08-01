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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_MAC_H
#define	_SYS_MAC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stream.h>

/*
 * MAC Services Module
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Module name.
 */
#define	MAC_MODULE_NAME	"mac"

/*
 * MAC Information (text emitted by modinfo(1m))
 */
#define	MAC_INFO	"MAC Services v%I%"

/*
 * Statistics
 */

#define	XCVR_UNDEFINED		0
#define	XCVR_NONE		1
#define	XCVR_10			2
#define	XCVR_100T4		3
#define	XCVR_100X		4
#define	XCVR_100T2		5
#define	XCVR_1000X		6
#define	XCVR_1000T		7

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

#ifdef	_KERNEL

enum mac_stat {
	/*
	 * PSARC 1997/198 (MIB-II kstats)
	 */
	MAC_STAT_IFSPEED,
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

	/*
	 * PSARC 1997/247 (RFC 1643 kstats)
	 */
	MAC_STAT_ALIGN_ERRORS,
	MAC_STAT_FCS_ERRORS,
	MAC_STAT_FIRST_COLLISIONS,
	MAC_STAT_MULTI_COLLISIONS,
	MAC_STAT_SQE_ERRORS,
	MAC_STAT_DEFER_XMTS,
	MAC_STAT_TX_LATE_COLLISIONS,
	MAC_STAT_EX_COLLISIONS,
	MAC_STAT_MACXMT_ERRORS,
	MAC_STAT_CARRIER_ERRORS,
	MAC_STAT_TOOLONG_ERRORS,
	MAC_STAT_MACRCV_ERRORS,

	/*
	 * PSARC 2003/581 (MII/GMII kstats)
	 */
	MAC_STAT_XCVR_ADDR,
	MAC_STAT_XCVR_ID,
	MAC_STAT_XCVR_INUSE,
	MAC_STAT_CAP_1000FDX,
	MAC_STAT_CAP_1000HDX,
	MAC_STAT_CAP_100FDX,
	MAC_STAT_CAP_100HDX,
	MAC_STAT_CAP_10FDX,
	MAC_STAT_CAP_10HDX,
	MAC_STAT_CAP_ASMPAUSE,
	MAC_STAT_CAP_PAUSE,
	MAC_STAT_CAP_AUTONEG,
	MAC_STAT_ADV_CAP_1000FDX,
	MAC_STAT_ADV_CAP_1000HDX,
	MAC_STAT_ADV_CAP_100FDX,
	MAC_STAT_ADV_CAP_100HDX,
	MAC_STAT_ADV_CAP_10FDX,
	MAC_STAT_ADV_CAP_10HDX,
	MAC_STAT_ADV_CAP_ASMPAUSE,
	MAC_STAT_ADV_CAP_PAUSE,
	MAC_STAT_ADV_CAP_AUTONEG,
	MAC_STAT_LP_CAP_1000FDX,
	MAC_STAT_LP_CAP_1000HDX,
	MAC_STAT_LP_CAP_100FDX,
	MAC_STAT_LP_CAP_100HDX,
	MAC_STAT_LP_CAP_10FDX,
	MAC_STAT_LP_CAP_10HDX,
	MAC_STAT_LP_CAP_ASMPAUSE,
	MAC_STAT_LP_CAP_PAUSE,
	MAC_STAT_LP_CAP_AUTONEG,
	MAC_STAT_LINK_ASMPAUSE,
	MAC_STAT_LINK_PAUSE,
	MAC_STAT_LINK_AUTONEG,
	MAC_STAT_LINK_DUPLEX,
	MAC_NSTAT	/* must be the last entry */
};

/*
 * Maximum MAC address length
 */
#define	MAXADDRLEN	20

/*
 * Immutable information. (This may not be modified after registration).
 */
typedef struct mac_info_s {
	uint_t		mi_media;
	uint_t		mi_sdu_min;
	uint_t		mi_sdu_max;
	uint32_t	mi_cksum;
	uint32_t	mi_poll;
	uint_t		mi_addr_length;
	uint8_t		mi_unicst_addr[MAXADDRLEN];
	uint8_t		mi_brdcst_addr[MAXADDRLEN];
	boolean_t	mi_stat[MAC_NSTAT];
} mac_info_t;

#define	MAC_STAT_MIB(_mi_stat) \
{ \
	(_mi_stat)[MAC_STAT_IFSPEED] = B_TRUE; \
	(_mi_stat)[MAC_STAT_MULTIRCV] = B_TRUE; \
	(_mi_stat)[MAC_STAT_BRDCSTRCV] = B_TRUE; \
	(_mi_stat)[MAC_STAT_MULTIXMT] = B_TRUE; \
	(_mi_stat)[MAC_STAT_BRDCSTXMT] = B_TRUE; \
	(_mi_stat)[MAC_STAT_NORCVBUF] = B_TRUE; \
	(_mi_stat)[MAC_STAT_IERRORS] = B_TRUE; \
	(_mi_stat)[MAC_STAT_UNKNOWNS] = B_TRUE; \
	(_mi_stat)[MAC_STAT_NOXMTBUF] = B_TRUE; \
	(_mi_stat)[MAC_STAT_OERRORS] = B_TRUE; \
	(_mi_stat)[MAC_STAT_COLLISIONS] = B_TRUE; \
	(_mi_stat)[MAC_STAT_RBYTES] = B_TRUE; \
	(_mi_stat)[MAC_STAT_IPACKETS] = B_TRUE; \
	(_mi_stat)[MAC_STAT_OBYTES] = B_TRUE; \
	(_mi_stat)[MAC_STAT_OPACKETS] = B_TRUE; \
}

#define	MAC_STAT_ETHER(_mi_stat) \
{ \
	(_mi_stat)[MAC_STAT_ALIGN_ERRORS] = B_TRUE; \
	(_mi_stat)[MAC_STAT_FCS_ERRORS] = B_TRUE; \
	(_mi_stat)[MAC_STAT_FIRST_COLLISIONS] = B_TRUE; \
	(_mi_stat)[MAC_STAT_MULTI_COLLISIONS] = B_TRUE; \
	(_mi_stat)[MAC_STAT_SQE_ERRORS] = B_TRUE; \
	(_mi_stat)[MAC_STAT_DEFER_XMTS] = B_TRUE; \
	(_mi_stat)[MAC_STAT_TX_LATE_COLLISIONS] = B_TRUE; \
	(_mi_stat)[MAC_STAT_EX_COLLISIONS] = B_TRUE; \
	(_mi_stat)[MAC_STAT_MACXMT_ERRORS] = B_TRUE; \
	(_mi_stat)[MAC_STAT_CARRIER_ERRORS] = B_TRUE; \
	(_mi_stat)[MAC_STAT_TOOLONG_ERRORS] = B_TRUE; \
	(_mi_stat)[MAC_STAT_MACRCV_ERRORS] = B_TRUE; \
}

#define	MAC_STAT_MII(_mi_stat) \
{ \
	(_mi_stat)[MAC_STAT_XCVR_ADDR] = B_TRUE; \
	(_mi_stat)[MAC_STAT_XCVR_ID] = B_TRUE; \
	(_mi_stat)[MAC_STAT_XCVR_INUSE] = B_TRUE; \
	(_mi_stat)[MAC_STAT_CAP_1000FDX] = B_TRUE; \
	(_mi_stat)[MAC_STAT_CAP_1000HDX] = B_TRUE; \
	(_mi_stat)[MAC_STAT_CAP_100FDX] = B_TRUE; \
	(_mi_stat)[MAC_STAT_CAP_100HDX] = B_TRUE; \
	(_mi_stat)[MAC_STAT_CAP_10FDX] = B_TRUE; \
	(_mi_stat)[MAC_STAT_CAP_10HDX] = B_TRUE; \
	(_mi_stat)[MAC_STAT_CAP_ASMPAUSE] = B_TRUE; \
	(_mi_stat)[MAC_STAT_CAP_PAUSE] = B_TRUE; \
	(_mi_stat)[MAC_STAT_CAP_AUTONEG] = B_TRUE; \
	(_mi_stat)[MAC_STAT_ADV_CAP_1000FDX] = B_TRUE; \
	(_mi_stat)[MAC_STAT_ADV_CAP_1000HDX] = B_TRUE; \
	(_mi_stat)[MAC_STAT_ADV_CAP_100FDX] = B_TRUE; \
	(_mi_stat)[MAC_STAT_ADV_CAP_100HDX] = B_TRUE; \
	(_mi_stat)[MAC_STAT_ADV_CAP_10FDX] = B_TRUE; \
	(_mi_stat)[MAC_STAT_ADV_CAP_10HDX] = B_TRUE; \
	(_mi_stat)[MAC_STAT_ADV_CAP_ASMPAUSE] = B_TRUE; \
	(_mi_stat)[MAC_STAT_ADV_CAP_PAUSE] = B_TRUE; \
	(_mi_stat)[MAC_STAT_ADV_CAP_AUTONEG] = B_TRUE; \
	(_mi_stat)[MAC_STAT_LP_CAP_1000FDX] = B_TRUE; \
	(_mi_stat)[MAC_STAT_LP_CAP_1000HDX] = B_TRUE; \
	(_mi_stat)[MAC_STAT_LP_CAP_100FDX] = B_TRUE; \
	(_mi_stat)[MAC_STAT_LP_CAP_100HDX] = B_TRUE; \
	(_mi_stat)[MAC_STAT_LP_CAP_10FDX] = B_TRUE; \
	(_mi_stat)[MAC_STAT_LP_CAP_10HDX] = B_TRUE; \
	(_mi_stat)[MAC_STAT_LP_CAP_ASMPAUSE] = B_TRUE; \
	(_mi_stat)[MAC_STAT_LP_CAP_PAUSE] = B_TRUE; \
	(_mi_stat)[MAC_STAT_LP_CAP_AUTONEG] = B_TRUE; \
	(_mi_stat)[MAC_STAT_LINK_ASMPAUSE] = B_TRUE; \
	(_mi_stat)[MAC_STAT_LINK_PAUSE] = B_TRUE; \
	(_mi_stat)[MAC_STAT_LINK_AUTONEG] = B_TRUE; \
	(_mi_stat)[MAC_STAT_LINK_DUPLEX] = B_TRUE; \
}

/*
 * MAC version identifer (for debugging)
 */
#define	MAC_IDENT	"%I%"

/*
 * MAC driver entry point types.
 */
typedef uint64_t	(*mac_stat_t)(void *, enum mac_stat);
typedef	int		(*mac_start_t)(void *);
typedef void		(*mac_stop_t)(void *);
typedef int		(*mac_promisc_t)(void *, boolean_t);
typedef int		(*mac_multicst_t)(void *, boolean_t, const uint8_t *);
typedef int		(*mac_unicst_t)(void *, const uint8_t *);
typedef void		(*mac_resources_t)(void *);
typedef void		(*mac_ioctl_t)(void *, queue_t *, mblk_t *);
typedef mblk_t		*(*mac_tx_t)(void *, mblk_t *);

/*
 * MAC extensions. (Currently there are non defined).
 */
typedef struct mac_ext_s	mac_ext_t;

/*
 * MAC implementation private data.
 */
typedef struct mac_impl_s	mac_impl_t;

/*
 * MAC structure: supplied by the driver.
 */
typedef struct mac {
	const char	*m_ident;	/* MAC_IDENT */
	mac_ext_t	*m_extp;
	mac_impl_t	*m_impl;	/* MAC private data */
	void		*m_driver;	/* Driver private data */

	dev_info_t	*m_dip;
	uint_t		m_port;

	mac_info_t	m_info;

	mac_stat_t	m_stat;
	mac_start_t	m_start;
	mac_stop_t	m_stop;
	mac_promisc_t	m_promisc;
	mac_multicst_t	m_multicst;
	mac_unicst_t	m_unicst;
	mac_resources_t	m_resources;
	mac_ioctl_t	m_ioctl;
	mac_tx_t	m_tx;
} mac_t;

/*
 * Construct the name of a MAC interface.
 */
#define	MAC_NAME(_name, _dev, _port) \
	(void) snprintf((_name), MAXNAMELEN - 1, "%s/%u", (_dev), (_port))

/*
 * Opaque handle types.
 */
typedef	struct __mac_handle		*mac_handle_t;
typedef struct __mac_notify_handle	*mac_notify_handle_t;
typedef struct __mac_rx_handle		*mac_rx_handle_t;
typedef struct __mac_txloop_handle	*mac_txloop_handle_t;
typedef struct __mac_resource_handle	*mac_resource_handle_t;

/*
 * MAC interface callback types.
 */
typedef enum {
	MAC_NOTE_LINK,
	MAC_NOTE_PROMISC,
	MAC_NOTE_UNICST,
	MAC_NOTE_TX,
	MAC_NOTE_RESOURCE,
	MAC_NOTE_DEVPROMISC,
	MAC_NNOTE	/* must be the last entry */
} mac_notify_type_t;

typedef void		(*mac_notify_t)(void *, mac_notify_type_t);
typedef void		(*mac_rx_t)(void *, mac_resource_handle_t, mblk_t *);
typedef void		(*mac_txloop_t)(void *, mblk_t *);
typedef void		(*mac_blank_t)(void *, time_t, uint_t);

/*
 * MAC promiscuous types
 */
typedef enum {
	MAC_PROMISC = 0x01,		/* MAC instance is promiscuous */
	MAC_DEVPROMISC = 0x02		/* Device is promiscuous */
} mac_promisc_type_t;

/*
 * MAC resource types
 */
typedef enum {
	MAC_RX_FIFO = 1
} mac_resource_type_t;

typedef struct mac_rx_fifo_s {
	mac_resource_type_t	mrf_type;	/* MAC_RX_FIFO */
	mac_blank_t		mrf_blank;
	void			*mrf_arg;
	time_t			mrf_normal_blank_time;
	uint_t			mrf_normal_pkt_count;
} mac_rx_fifo_t;

typedef struct mac_txinfo_s {
	mac_tx_t		mt_fn;
	void			*mt_arg;
} mac_txinfo_t;

typedef union mac_resource_u {
	mac_resource_type_t	mr_type;
	mac_rx_fifo_t		mr_fifo;
} mac_resource_t;

typedef mac_resource_handle_t	(*mac_resource_add_t)(void *, mac_resource_t *);

/*
 * Client interface functions.
 */
extern int			mac_open(const char *, uint_t, mac_handle_t *);
extern void			mac_close(mac_handle_t);
extern const mac_info_t		*mac_info(mac_handle_t);
extern boolean_t		mac_info_get(const char *, mac_info_t *);
extern uint64_t			mac_stat_get(mac_handle_t, enum mac_stat);
extern int			mac_start(mac_handle_t);
extern void			mac_stop(mac_handle_t);
extern int			mac_promisc_set(mac_handle_t, boolean_t,
    mac_promisc_type_t);
extern boolean_t		mac_promisc_get(mac_handle_t,
    mac_promisc_type_t);
extern int 			mac_multicst_add(mac_handle_t, const uint8_t *);
extern int 			mac_multicst_remove(mac_handle_t,
    const uint8_t *);
extern int			mac_unicst_set(mac_handle_t, const uint8_t *);
extern void			mac_unicst_get(mac_handle_t, uint8_t *);
extern void			mac_resources(mac_handle_t);
extern void			mac_ioctl(mac_handle_t, queue_t *, mblk_t *);
extern const mac_txinfo_t	*mac_tx_get(mac_handle_t);
extern link_state_t		mac_link_get(mac_handle_t);
extern mac_notify_handle_t	mac_notify_add(mac_handle_t, mac_notify_t,
    void *);
extern void			mac_notify_remove(mac_handle_t,
    mac_notify_handle_t);
extern void			mac_notify(mac_handle_t);
extern mac_rx_handle_t		mac_rx_add(mac_handle_t, mac_rx_t, void *);
extern void			mac_rx_remove(mac_handle_t, mac_rx_handle_t);
extern mblk_t			*mac_txloop(void *, mblk_t *);
extern mac_txloop_handle_t	mac_txloop_add(mac_handle_t, mac_txloop_t,
    void *);
extern void			mac_txloop_remove(mac_handle_t,
    mac_txloop_handle_t);
extern boolean_t		mac_active_set(mac_handle_t);
extern void			mac_active_clear(mac_handle_t);
extern void			mac_resource_set(mac_handle_t,
    mac_resource_add_t, void *);
extern dev_info_t		*mac_devinfo_get(mac_handle_t);

/*
 * Driver interface functions.
 */
extern int  			mac_register(mac_t *);
extern int  			mac_unregister(mac_t *);
extern void 			mac_rx(mac_t *, mac_resource_handle_t,
    mblk_t *);
extern void 			mac_link_update(mac_t *, link_state_t);
extern void 			mac_unicst_update(mac_t *, const uint8_t *);
extern void			mac_tx_update(mac_t *);
extern void			mac_resource_update(mac_t *);
extern mac_resource_handle_t	mac_resource_add(mac_t *, mac_resource_t *);
extern void			mac_multicst_refresh(mac_t *, mac_multicst_t,
    void *, boolean_t);
extern void			mac_unicst_refresh(mac_t *, mac_unicst_t,
    void *);
extern void			mac_promisc_refresh(mac_t *, mac_promisc_t,
    void *);
extern void			mac_init_ops(struct dev_ops *, const char *);
extern void			mac_fini_ops(struct dev_ops *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_MAC_H */
