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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_DLS_H
#define	_SYS_DLS_H

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/mac_client.h>
#include <sys/dls_mgmt.h>

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
#define	DLS_INFO	"Data-Link Services"

/*
 * Macros for converting ppas to instance #s, Vlan ID, or minor.
 */
#define	DLS_PPA2INST(ppa)	((int)((ppa) % 1000))
#define	DLS_PPA2VID(ppa)	((uint16_t)((ppa) / 1000))
#define	DLS_PPA2MINOR(ppa)	((minor_t)((DLS_PPA2INST(ppa)) + 1))

/*
 * Maps a (VID, INST) pair to ppa
 */
#define	DLS_VIDINST2PPA(vid, inst)	((minor_t)((vid) * 1000 + (inst)))

/*
 * Converts a minor to an instance#; makes sense only when minor <= 1000.
 */
#define	DLS_MINOR2INST(minor)	((int)((minor) - 1))

#ifdef	_KERNEL

#define	DLS_MAX_PPA	999
#define	DLS_MAX_MINOR	(DLS_MAX_PPA + 1)

typedef void    (*dls_rx_t)(void *, mac_resource_handle_t, mblk_t *,
		    mac_header_info_t *);

typedef struct dld_str_s	dld_str_t;
typedef struct dls_devnet_s	*dls_dl_handle_t;
typedef struct dls_dev_t	*dls_dev_handle_t;
typedef struct dls_link_s	dls_link_t;

#define	DLS_SAP_LLC	0
#define	DLS_SAP_PROMISC	(1 << 16)

#define	DLS_PROMISC_SAP		0x00000001
#define	DLS_PROMISC_MULTI	0x00000002
#define	DLS_PROMISC_PHYS	0x00000004

extern int	dls_open(dls_link_t *, dls_dl_handle_t, dld_str_t *);
extern void	dls_close(dld_str_t *);
extern int	dls_bind(dld_str_t *, uint32_t);
extern void	dls_unbind(dld_str_t *);

extern int	dls_promisc(dld_str_t *, uint32_t);

extern int	dls_multicst_add(dld_str_t *, const uint8_t *);
extern int	dls_multicst_remove(dld_str_t *, const uint8_t *);

extern mblk_t	*dls_header(dld_str_t *, const uint8_t *,
		    uint16_t, uint_t, mblk_t **);

extern void	dls_rx_set(dld_str_t *, dls_rx_t, void *);
extern dld_str_t *dls_rx_get(char *, flow_desc_t *, size_t *);

extern void	str_notify(void *, mac_notify_type_t);

extern int		dls_devnet_open(const char *,
			    dls_dl_handle_t *, dev_t *);
extern void		dls_devnet_close(dls_dl_handle_t);
extern boolean_t	dls_devnet_rebuild();

extern int		dls_devnet_rename(datalink_id_t, datalink_id_t,
			    const char *);
extern int		dls_devnet_create(mac_handle_t, datalink_id_t,
			    zoneid_t);
extern int		dls_devnet_destroy(mac_handle_t, datalink_id_t *,
			    boolean_t);
extern int		dls_devnet_recreate(mac_handle_t, datalink_id_t);
extern int		dls_devnet_hold_tmp(datalink_id_t, dls_dl_handle_t *);
extern void		dls_devnet_rele_tmp(dls_dl_handle_t);
extern int		dls_devnet_hold_by_dev(dev_t, dls_dl_handle_t *);
extern void		dls_devnet_rele(dls_dl_handle_t);
extern void		dls_devnet_prop_task_wait(dls_dl_handle_t);

extern const char	*dls_devnet_mac(dls_dl_handle_t);
extern uint16_t		dls_devnet_vid(dls_dl_handle_t);
extern datalink_id_t	dls_devnet_linkid(dls_dl_handle_t);
extern int		dls_devnet_dev2linkid(dev_t, datalink_id_t *);
extern int		dls_devnet_phydev(datalink_id_t, dev_t *);
extern int		dls_devnet_setzid(dls_dl_handle_t, zoneid_t);
extern zoneid_t		dls_devnet_getzid(dls_dl_handle_t);
extern zoneid_t		dls_devnet_getownerzid(dls_dl_handle_t);
extern boolean_t	dls_devnet_islinkvisible(datalink_id_t, zoneid_t);

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
extern int		dls_devnet_macname2linkid(const char *,
			    datalink_id_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DLS_H */
