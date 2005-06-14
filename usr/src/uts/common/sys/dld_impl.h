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

#ifndef	_SYS_DLD_IMPL_H
#define	_SYS_DLD_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/ethernet.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/mac.h>
#include <sys/dls.h>
#include <sys/dld.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * dld_ppa_t object definition.
 */
typedef	struct dld_node	dld_node_t;

typedef struct dld_ppa {
	/*
	 * Name of the data-link.
	 */
	char		dp_name[IFNAMSIZ];

	/*
	 * The device and port of the MAC interface.
	 */
	char		dp_dev[MAXNAMELEN];
	uint_t		dp_port;

	/*
	 * The VLAN identifier of the data-link interface.
	 */
	uint_t		dp_vid;

	/*
	 * Style 1 and style 2 provider nodes that reference the object.
	 */
	dld_node_t	*dp_style1;
	dld_node_t	*dp_style2;

	/*
	 * Style 2 PPA index number of the object.
	 */
	t_scalar_t	dp_index;
} dld_ppa_t;

/*
 * dld_node_t object definition.
 */
struct dld_node {
	/*
	 * Name of the node, this will be the name of the dev_t in the
	 * file system.
	 */
	char		dn_name[IFNAMSIZ];

	/*
	 * DL_STYLE1 or DL_STYLE2.
	 */
	t_uscalar_t	dn_style;

	/*
	 * Minor number of the dev_t.
	 */
	minor_t		dn_minor;

	/*
	 * Global hash table entries that reference the object.
	 */
	ghte_t		dn_byminor_hte;
	ghte_t		dn_byname_hte;

	/*
	 * Number of dld_ppa_t objects referencing the object.
	 */
	uint32_t	dn_ref;

	/*
	 * For style 1 nodes there is only a single dld_ppa_t object reference.
	 * This field is used for that purpose.
	 */
	dld_ppa_t	*dn_dpp;

	/*
	 * For style 2 nodes there may be many dld_ppa_t references, keyed
	 * by a PPA index number. The following hash table stores the
	 * references and the subsequent methods are used to manage the table.
	 */
	ght_t		dn_hash;
};

#define	DLD_CONTROL	0x00000001
#define	DLD_DLPI	0x00000002

typedef enum {
	DLD_UNITDATA,
	DLD_FASTPATH,
	DLD_RAW
} dld_str_mode_t;

typedef enum {
	DLD_UNINITIALIZED,
	DLD_PASSIVE,
	DLD_ACTIVE
} dld_passivestate_t;

typedef struct dld_str	dld_str_t;

/*
 * dld_str_t object definition.
 */
struct dld_str {
	/*
	 * Ephemeral minor number for the object.
	 */
	minor_t			ds_minor;

	/*
	 * Read/write queues for the stream which the object represents.
	 */
	queue_t			*ds_rq;
	queue_t			*ds_wq;

	/*
	 * Stream is open to DLD_CONTROL (control node) or
	 * DLD_DLPI (DLS provider) node.
	 */
	uint_t			ds_type;

	/*
	 * The following fields are only used for DLD_DLPI type objects.
	 */

	/*
	 * dld_node_t of the node that was opened.
	 */
	dld_node_t		*ds_dnp;

	/*
	 * Current DLPI state.
	 */
	t_uscalar_t		ds_dlstate;

	/*
	 * Currently bound DLSAP.
	 */
	uint16_t		ds_sap;

	/*
	 * Handle of the data-link channel that is used by this object.
	 */
	dls_channel_t		ds_dc;

	/*
	 * Handle of the MAC that is used by the data-link interface.
	 */
	mac_handle_t		ds_mh;

	/*
	 * VLAN identifier of the data-link interface.
	 */
	uint16_t		ds_vid;

	/*
	 * Promiscuity level information.
	 */
	uint32_t		ds_promisc;

	/*
	 * Immutable information of the MAC which the channel is using.
	 */
	const mac_info_t	*ds_mip;

	/*
	 * Current packet priority.
	 */
	uint_t			ds_pri;

	/*
	 * Handle of our MAC notification callback.
	 */
	mac_notify_handle_t	ds_mnh;

	/*
	 * Set of enabled DL_NOTE... notifications. (See dlpi.h).
	 */
	uint32_t		ds_notifications;

	/*
	 * Cached MAC unicast addresses.
	 */
	uint8_t			ds_fact_addr[MAXADDRLEN];
	uint8_t			ds_curr_addr[MAXADDRLEN];

	/*
	 * Mode: unitdata, fast-path or raw.
	 */
	dld_str_mode_t		ds_mode;

	/*
	 * IP polling is operational if this flag is set.
	 */
	boolean_t		ds_polling;

	/*
	 * State of DLPI user: may be active (regular network layer),
	 * passive (snoop-like monitoring), or unknown (not yet
	 * determined).
	 */
	dld_passivestate_t	ds_passivestate;

	/*
	 * Message handler jump tables.
	 */
	struct str_msg_info	*ds_mi;
	struct str_msg_info	*ds_pmi;
} dld_str;

/*
 * dld_str.c module.
 */

extern void		dld_str_init(void);
extern int		dld_str_fini(void);
extern dld_str_t	*dld_str_create(queue_t *);
extern void		dld_str_destroy(dld_str_t *);
extern int		dld_str_attach(dld_str_t *, dld_ppa_t *);
extern void		dld_str_detach(dld_str_t *);
extern void		dld_str_tx_raw(dld_str_t *);
extern void		dld_str_tx_fastpath(dld_str_t *);
extern void		dld_str_tx_drop(dld_str_t *);
extern void		dld_str_rx_raw(void *, mac_resource_handle_t,
    mblk_t *, size_t);
extern void		dld_str_rx_fastpath(void *, mac_resource_handle_t,
    mblk_t *, size_t);
extern void		dld_str_rx_unitdata(void *, mac_resource_handle_t,
    mblk_t *, size_t);
extern void		dld_str_put(dld_str_t *, mblk_t *);
extern void		dld_str_srv(dld_str_t *, mblk_t *);
extern void		dld_str_notify_ind(dld_str_t *);

/*
 * dld_proto.c
 */
extern void		dld_proto(dld_str_t *, mblk_t *);

/*
 * dld_ppa.c module.
 */
extern void		dld_ppa_init(void);
extern int		dld_ppa_fini(void);
extern int		dld_ppa_create(const char *, const char *, uint_t,
    uint16_t);
extern int		dld_ppa_destroy(const char *);
extern int		dld_ppa_attr(const char *, char *, uint_t *,
    uint16_t *);

/*
 * dld_node.c module.
 */
extern void		dld_node_init(void);
extern int		dld_node_fini(void);
extern dld_node_t	*dld_node_hold(const char *, t_uscalar_t);
extern void		dld_node_rele(dld_node_t *);
extern dld_node_t	*dld_node_find(minor_t);
extern int		dld_node_ppa_add(dld_node_t *, t_scalar_t,
    dld_ppa_t *);
extern int		dld_node_ppa_remove(dld_node_t *, t_scalar_t);
extern dld_ppa_t	*dld_node_ppa_find(dld_node_t *, t_scalar_t);

/*
 * dld_minor.c module.
 */
extern void		dld_minor_init(void);
extern int		dld_minor_fini(void);
extern minor_t		dld_minor_hold(boolean_t);
extern void		dld_minor_rele(minor_t);

/*
 * dld_ioc.c module.
 */
extern void		dld_ioc(dld_str_t *, mblk_t *);

/*
 * dld_drv.c module.
 */
extern dev_info_t	*dld_dip;

/*
 * Options: there should be a separate bit defined here for each
 *          DLD_PROP... defined in dld.h.
 */
#define	DLD_OPT_NO_STYLE1	0x00000001
#define	DLD_OPT_NO_FASTPATH	0x00000002
#define	DLD_OPT_NO_POLL		0x00000004
#define	DLD_OPT_NO_ZEROCOPY	0x00000008

extern uint32_t		dld_opt;

/*
 * Useful macros.
 */

#define	IMPLY(p, c)	(!(p) || (c))
#define	AGGR_DEV	"aggr0"

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DLD_IMPL_H */
