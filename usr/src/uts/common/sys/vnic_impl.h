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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_VNIC_IMPL_H
#define	_SYS_VNIC_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/vnic.h>
#include <sys/ksynch.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef void (*vnic_rx_fn_t)(void *, void *, mblk_t *);

typedef struct vnic_flow_fn_info_s {
	vnic_rx_fn_t	ff_fn;
	void		*ff_arg1;
	void		*ff_arg2;
} vnic_flow_fn_info_t;

typedef struct vnic_flow_s {
	uchar_t			vf_addr[MAXMACADDRLEN];
	uint_t			vf_addr_len;
	vnic_flow_fn_info_t	vf_fn_info;
	void			*vf_cookie;
	struct vnic_flow_s	*vf_next;
	kmutex_t		vf_lock;
	kcondvar_t		vf_cv;
	uint32_t		vf_refs;
	boolean_t		vf_clearing;
	boolean_t		vf_is_active;
} vnic_flow_t;

typedef struct vnic_flow_tab_s {
	vnic_flow_t		*vt_flow_list;
	krwlock_t		vt_lock;
	uint_t			vt_addr_len;
} vnic_flow_tab_t;

typedef struct vnic_mac_s {
	mac_handle_t		va_mh;
	uint_t			va_refs;
	char			va_dev_name[MAXNAMELEN];
	const mac_txinfo_t	*va_txinfo;
	struct vnic_bcast_grp_s	*va_bcast_grp;
	krwlock_t		va_bcast_grp_lock;
	size_t			va_addr_len;
	mac_notify_handle_t	va_notify_hdl;
	mac_rx_handle_t		va_rx_hdl;
	vnic_flow_t		*va_active_flow;
	vnic_flow_tab_t		*va_flow_tab;
	boolean_t		va_mac_set;
	struct vnic_s		*va_promisc;
	krwlock_t		va_promisc_lock;
	uint64_t		va_promisc_gen;
} vnic_mac_t;

typedef struct vnic_s {
	uint_t		vn_id;
	uint32_t
		vn_started : 1,
		vn_promisc : 1,
		vn_bcast_grp : 1,
		vn_multi_mac : 1,
		vn_promisc_mac : 1,
		vn_pad_to_bit_31 : 27;

	int		vn_slot_id;
	multiaddress_capab_t	vn_mma_capab;
	uint8_t		vn_addr[ETHERADDRL];
	vnic_mac_addr_type_t vn_addr_type;

	mac_handle_t	vn_mh;
	vnic_mac_t	*vn_vnic_mac;
	vnic_flow_t	*vn_flow_ent;
	uint32_t	vn_hcksum_txflags;
	struct vnic_s	*vn_promisc_next;

	uint64_t	vn_stat_multircv;
	uint64_t	vn_stat_brdcstrcv;
	uint64_t	vn_stat_multixmt;
	uint64_t	vn_stat_brdcstxmt;
	uint64_t	vn_stat_ierrors;
	uint64_t	vn_stat_oerrors;
	uint64_t	vn_stat_rbytes;
	uint64_t	vn_stat_ipackets;
	uint64_t	vn_stat_obytes;
	uint64_t	vn_stat_opackets;
} vnic_t;

#define	vn_txinfo	vn_vnic_mac->va_txinfo

#define	vn_madd_naddr		vn_mma_capab.maddr_naddr
#define	vn_maddr_naddrfree	vn_mma_capab.maddr_naddrfree
#define	vn_maddr_flag		vn_mma_capab.maddr_flag
#define	vn_maddr_handle		vn_mma_capab.maddr_handle
#define	vn_maddr_reserve	vn_mma_capab.maddr_reserve
#define	vn_maddr_add		vn_mma_capab.maddr_add
#define	vn_maddr_remove		vn_mma_capab.maddr_remove
#define	vn_maddr_modify		vn_mma_capab.maddr_modify
#define	vn_maddr_get		vn_mma_capab.maddr_get

#define	VNIC_FLOW_REFHOLD(flow) {				\
	mutex_enter(&(flow)->vf_lock);				\
	(flow)->vf_refs++;					\
	mutex_exit(&(flow)->vf_lock);				\
}

#define	VNIC_FLOW_REFRELE(flow) {				\
	mutex_enter(&(flow)->vf_lock);				\
	if (--(flow)->vf_refs == 0 && (flow)->vf_clearing) {	\
	    (flow)->vf_clearing = B_FALSE;			\
	    cv_signal(&(flow)->vf_cv);				\
	}							\
	mutex_exit(&(flow)->vf_lock);				\
}

extern int vnic_dev_create(uint_t, char *, int, uchar_t *);
extern int vnic_dev_modify(uint_t, uint_t, vnic_mac_addr_type_t,
    uint_t, uchar_t *);
extern int vnic_dev_delete(uint_t);

typedef int (*vnic_info_new_vnic_fn_t)(void *, uint32_t, vnic_mac_addr_type_t,
    uint_t, uint8_t *, char *);

extern void vnic_dev_init(void);
extern void vnic_dev_fini(void);
extern uint_t vnic_dev_count(void);
extern dev_info_t *vnic_get_dip(void);

extern int vnic_info(uint_t *, uint32_t, char *, void *,
    vnic_info_new_vnic_fn_t);

extern void vnic_rx(void *, void *, mblk_t *);
extern mblk_t *vnic_fix_cksum(mblk_t *);
extern mblk_t *vnic_copymsgchain_cksum(mblk_t *);
extern mblk_t *vnic_copymsg_cksum(mblk_t *);

extern void vnic_promisc_rx(vnic_mac_t *, vnic_t *, mblk_t *);

extern void vnic_bcast_init(void);
extern void vnic_bcast_fini(void);
extern int vnic_bcast_add(vnic_t *, const uint8_t *, mac_addrtype_t);
extern void vnic_bcast_delete(vnic_t *, const uint8_t *);
extern void vnic_bcast_send(void *, void *, mblk_t *);

extern void vnic_classifier_init(void);
extern void vnic_classifier_fini(void);
extern vnic_flow_t *vnic_classifier_flow_create(uint_t, uchar_t *, void *,
    boolean_t, int);
extern void vnic_classifier_flow_destroy(vnic_flow_t *);
extern void vnic_classifier_flow_add(vnic_mac_t *, vnic_flow_t *, vnic_rx_fn_t,
    void *, void *);
extern void vnic_classifier_flow_remove(vnic_mac_t *, vnic_flow_t *);
extern void vnic_classifier_flow_update_addr(vnic_flow_t *, uchar_t *);
extern void vnic_classifier_flow_update_fn(vnic_flow_t *, vnic_rx_fn_t,
    void *, void *);
extern int vnic_classifier_flow_tab_init(vnic_mac_t *, uint_t, int);
extern void vnic_classifier_flow_tab_fini(vnic_mac_t *);
extern vnic_flow_t *vnic_classifier_get_flow(vnic_mac_t *, mblk_t *);
extern void *vnic_classifier_get_client_cookie(vnic_flow_t *);
extern vnic_flow_fn_info_t *vnic_classifier_get_fn_info(vnic_flow_t *);
extern boolean_t vnic_classifier_is_active(vnic_flow_t *);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VNIC_IMPL_H */
