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

#ifndef	_SYS_SOFTMAC_IMPL_H
#define	_SYS_SOFTMAC_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/ethernet.h>
#include <sys/taskq.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/strsun.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/mac.h>
#include <sys/mac_ether.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct softmac_lower_s {
	struct softmac		*sl_softmac;
	queue_t			*sl_wq;

	/*
	 * sl_ctl_inprogress is used to serialize the control path.  It will
	 * be set when either an ioctl or an M_{PC,}PROTO message is received
	 * from the upper layer, and will be cleared when processing done.
	 */
	kmutex_t		sl_ctl_mutex;
	kcondvar_t		sl_ctl_cv;
	boolean_t		sl_ctl_inprogress;

	/*
	 * When a control message is processed, either sl_pending_prim or
	 * sl_pending_ioctl will be set.  They will be cleared when the
	 * acknowledgement of the specific control message is received
	 * from the underlying legacy driver.
	 */
	kmutex_t		sl_mutex;
	kcondvar_t		sl_cv;
	t_uscalar_t		sl_pending_prim;
	boolean_t		sl_pending_ioctl;
	mblk_t			*sl_ack_mp;

	mac_resource_handle_t	sl_handle;
	ldi_handle_t		sl_lh;
} softmac_lower_t;

enum softmac_state {
	SOFTMAC_INITIALIZED,
	SOFTMAC_READY
};

typedef struct softmac_dev_s {
	dev_t	sd_dev;
} softmac_dev_t;

/*
 * smac_flag values.
 */
#define	SOFTMAC_GLDV3		0x01
#define	SOFTMAC_NOSUPP		0x02
#define	SOFTMAC_ATTACH_DONE	0x04
#define	SOFTMAC_NEED_RECREATE	0x08

/*
 * The softmac structure allows all minor nodes (at most two, style-1 and
 * style-2) for the same device to be processed.  A softmac_dev_t will be
 * created for each minor node.
 *
 * We try to "register" the mac after all the softmac_dev_t's are processed so
 * that even if DLPI operations fail (because of driver bugs) for one minor
 * node, the other minor node can still be used to register the mac.
 * (Specifically, an incorrect xxx_getinfo() implementation will cause style-2
 * minor node mac registration to fail.)
 */
typedef struct softmac {
	/*
	 * The following fields will be set when the softmac is created and
	 * will not change.  No lock is required.
	 */
	char		smac_devname[MAXNAMELEN];
	major_t		smac_umajor;
	int		smac_uppa;
	uint32_t	smac_cnt;	/* # of minor nodes for this device */

	/*
	 * The following fields are protected by softmac_hash_lock.
	 */
	/*
	 * The smac_hold_cnt field increases when softmac_hold_device() is
	 * called to force the dls_vlan_t of the device to be created.  The
	 * device pre-detach fails if this counter is not 0.
	 */
	uint32_t	smac_hold_cnt;

	/*
	 * The following fields are protected by smac_lock.
	 */
	kmutex_t	smac_mutex;
	kcondvar_t	smac_cv;
	uint32_t	smac_flags;
	int		smac_attacherr;
	mac_handle_t	smac_mh;
	softmac_dev_t	*smac_softmac[2];
	taskqid_t	smac_taskq;
	/*
	 * Number of minor nodes whose post-attach routine has succeeded.
	 * This should be the same as the numbers of softmac_dev_t.
	 * Note that it does not imply SOFTMAC_ATTACH_DONE as the taskq might
	 * be still ongoing.
	 */
	uint32_t	smac_attachok_cnt;
	/*
	 * Number of softmac_dev_t left when pre-detach fails. This is used
	 * to indicate whether postattach is called because of a failed
	 * pre-detach.
	 */
	uint32_t	smac_attached_left;

	/*
	 * This field is set and cleared by users of softmac (who calls
	 * softmac_hold/rele_device()). It is protected by smac_mutex.
	 */
	dev_info_t	*smac_udip;

	/*
	 * The remaining fields are used to register the MAC for a legacy
	 * device.  They are set in softmac_mac_register() and do not change.
	 * One can access them when mac_register() is done without locks.
	 */

	/*
	 * media type is needed for create <link name, linkid> mapping, so
	 * it is set for GLDv3 device as well
	 */
	uint_t		smac_media;
	/* DLPI style of the underlying device */
	int		smac_style;
	dev_t		smac_dev;
	size_t		smac_saplen;
	size_t		smac_addrlen;
	uchar_t		smac_unicst_addr[MAXMACADDRLEN];
	uint_t		smac_min_sdu;
	uint_t		smac_max_sdu;
	uint32_t	smac_margin;

	/* Notifications the underlying driver can support. */
	uint32_t	smac_notifications;

	/*
	 * Capabilities of the underlying driver.
	 */
	uint32_t	smac_capab_flags;
	uint32_t	smac_hcksum_txflags;
	boolean_t	smac_no_capability_req;
	dl_capab_mdt_t	smac_mdt_capab;
	boolean_t	smac_mdt;

	/*
	 * The following fields are protected by smac_lock
	 */
	krwlock_t	smac_lock;
	enum softmac_state	smac_state;
	/* Lower stream structure */
	softmac_lower_t	*smac_lower;
} softmac_t;

typedef struct smac_ioc_start_s {
	softmac_lower_t	*si_slp;
} smac_ioc_start_t;

#define	SMAC_IOC	('S' << 24 | 'M' << 16 | 'C' << 8)
#define	SMAC_IOC_START	(SMAC_IOC | 0x01)

#define	SOFTMAC_BLANK_TICKS	128
#define	SOFTMAC_BLANK_PKT_COUNT	8

extern dev_info_t		*softmac_dip;
#define	SOFTMAC_DEV_NAME	"softmac"

extern int	softmac_send_bind_req(softmac_lower_t *, uint_t);
extern int	softmac_send_notify_req(softmac_lower_t *, uint32_t);
extern int	softmac_send_promisc_req(softmac_lower_t *, t_uscalar_t,
    boolean_t);
extern void	softmac_init(void);
extern void	softmac_fini(void);
extern boolean_t softmac_busy(void);
extern int	softmac_fill_capab(ldi_handle_t, softmac_t *);
extern int	softmac_capab_enable(softmac_lower_t *);
extern void	softmac_rput_process_notdata(queue_t *, mblk_t *);
extern void	softmac_rput_process_data(softmac_lower_t *, mblk_t *);

extern int	softmac_m_promisc(void *, boolean_t);
extern int	softmac_m_multicst(void *, boolean_t, const uint8_t *);
extern int	softmac_m_unicst(void *, const uint8_t *);
extern void	softmac_m_ioctl(void *, queue_t *, mblk_t *);
extern int	softmac_m_stat(void *, uint_t, uint64_t *);
extern mblk_t	*softmac_m_tx(void *, mblk_t *);
extern void	softmac_m_resources(void *);
extern int	softmac_proto_tx(softmac_lower_t *, mblk_t *, mblk_t **);
extern void	softmac_ioctl_tx(softmac_lower_t *, mblk_t *, mblk_t **);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SOFTMAC_IMPL_H */
