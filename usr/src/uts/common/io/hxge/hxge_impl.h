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

#ifndef	_SYS_HXGE_HXGE_IMPL_H
#define	_SYS_HXGE_HXGE_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM
#include <sys/types.h>
#include <sys/byteorder.h>
#include <sys/debug.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strlog.h>
#include <sys/strsubr.h>
#include <sys/cmn_err.h>
#include <sys/vtrace.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>
#include <sys/stat.h>
#include <sys/cpu.h>
#include <sys/kstat.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <sys/dlpi.h>
#include <inet/nd.h>
#include <netinet/in.h>
#include <sys/ethernet.h>
#include <sys/vlan.h>
#include <sys/pci.h>
#include <sys/taskq.h>
#include <sys/atomic.h>

#include <hxge_defs.h>
#include <hxge_peu.h>
#include <hxge_pfc.h>
#include <hxge_pfc_hw.h>
#include <hxge_vmac.h>
#include <hxge_fm.h>
#include <sys/netlb.h>
#include <sys/ddi_intr.h>

#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/note.h>

/*
 * Handy macros (taken from bge driver)
 */
#define	RBR_SIZE			4
#define	DMA_COMMON_VPTR(area)		((area.kaddrp))
#define	DMA_COMMON_HANDLE(area)		((area.dma_handle))
#define	DMA_COMMON_ACC_HANDLE(area)	((area.acc_handle))
#define	DMA_COMMON_IOADDR(area)		((area.dma_cookie.dmac_laddress))
#define	DMA_COMMON_SYNC(area, flag)	((void) ddi_dma_sync((area).dma_handle,\
						(area).offset, (area).alength, \
						(flag)))
#define	DMA_COMMON_SYNC_OFFSET(area, bufoffset, len, flag)	\
					((void) ddi_dma_sync((area).dma_handle,\
					(area.offset + bufoffset), len, \
					(flag)))

#define	NEXT_ENTRY(index, wrap)		((index + 1) & wrap)
#define	NEXT_ENTRY_PTR(ptr, first, last)	\
					((ptr == last) ? first : (ptr + 1))

/*
 * HPI related macros
 */
#define	HXGE_DEV_HPI_HANDLE(hxgep)	(hxgep->hpi_handle)

#define	HPI_PCI_ACC_HANDLE_SET(hxgep, ah) (hxgep->hpi_pci_handle.regh = ah)
#define	HPI_PCI_ADD_HANDLE_SET(hxgep, ap) (hxgep->hpi_pci_handle.regp = ap)

#define	HPI_ACC_HANDLE_SET(hxgep, ah)	(hxgep->hpi_handle.regh = ah)
#define	HPI_ADD_HANDLE_SET(hxgep, ap)	\
		hxgep->hpi_handle.is_vraddr = B_FALSE;	\
		hxgep->hpi_handle.function.instance = hxgep->instance;   \
		hxgep->hpi_handle.function.function = 0;   \
		hxgep->hpi_handle.hxgep = (void *) hxgep;   \
		hxgep->hpi_handle.regp = ap;

#define	HPI_REG_ACC_HANDLE_SET(hxgep, ah) (hxgep->hpi_reg_handle.regh = ah)
#define	HPI_REG_ADD_HANDLE_SET(hxgep, ap)	\
		hxgep->hpi_reg_handle.is_vraddr = B_FALSE;	\
		hxgep->hpi_handle.function.instance = hxgep->instance;   \
		hxgep->hpi_handle.function.function = 0;   \
		hxgep->hpi_reg_handle.hxgep = (void *) hxgep;   \
		hxgep->hpi_reg_handle.regp = ap;

#define	HPI_MSI_ACC_HANDLE_SET(hxgep, ah) (hxgep->hpi_msi_handle.regh = ah)
#define	HPI_MSI_ADD_HANDLE_SET(hxgep, ap)	\
		hxgep->hpi_msi_handle.is_vraddr = B_FALSE;	\
		hxgep->hpi_msi_handle.function.instance = hxgep->instance;   \
		hxgep->hpi_msi_handle.function.function = 0;   \
		hxgep->hpi_msi_handle.hxgep = (void *) hxgep;   \
		hxgep->hpi_msi_handle.regp = ap;

#define	HPI_DMA_ACC_HANDLE_SET(dmap, ah) (dmap->hpi_handle.regh = ah)
#define	HPI_DMA_ACC_HANDLE_GET(dmap) 	(dmap->hpi_handle.regh)

#define	LDV_ON(ldv, vector)	((vector >> ldv) & 0x1)

typedef uint32_t		hxge_status_t;

typedef enum  {
	DVMA,
	DMA,
	SDMA
} dma_method_t;

typedef enum  {
	BKSIZE_4K,
	BKSIZE_8K,
	BKSIZE_16K,
	BKSIZE_32K
} hxge_rx_block_size_t;

#ifdef TX_ONE_BUF
#define	TX_BCOPY_MAX 512
#else
#define	TX_BCOPY_MAX	512
#define	TX_BCOPY_SIZE	512
#endif

#define	TX_STREAM_MIN 512
#define	TX_FASTDVMA_MIN 1024

#define	HXGE_RDC_RCR_THRESHOLD_MAX	256
#define	HXGE_RDC_RCR_TIMEOUT_MAX	64
#define	HXGE_RDC_RCR_THRESHOLD_MIN	1
#define	HXGE_RDC_RCR_TIMEOUT_MIN	1

#define	HXGE_IS_VLAN_PACKET(ptr)				\
	((((struct ether_vlan_header *)ptr)->ether_tpid) ==	\
	htons(VLAN_ETHERTYPE))

typedef enum {
	USE_NONE,
	USE_BCOPY,
	USE_DVMA,
	USE_DMA,
	USE_SDMA
} dma_type_t;

struct _hxge_block_mv_t {
	uint32_t msg_type;
	dma_type_t dma_type;
};

typedef struct _hxge_block_mv_t hxge_block_mv_t, *p_hxge_block_mv_t;

typedef struct ether_addr ether_addr_st, *p_ether_addr_t;
typedef struct ether_header ether_header_t, *p_ether_header_t;
typedef queue_t *p_queue_t;
typedef mblk_t *p_mblk_t;

/*
 * Common DMA data elements.
 */
struct _hxge_dma_common_t {
	uint16_t		dma_channel;
	void			*kaddrp;
	void			*ioaddr_pp;
	ddi_dma_cookie_t 	dma_cookie;
	uint32_t		ncookies;

	ddi_dma_handle_t	dma_handle;
	hxge_os_acc_handle_t	acc_handle;
	hpi_handle_t		hpi_handle;

	size_t			block_size;
	uint32_t		nblocks;
	size_t			alength;
	uint_t			offset;
	uint_t			dma_chunk_index;
	void			*orig_ioaddr_pp;
	uint64_t		orig_vatopa;
	void			*orig_kaddrp;
	size_t			orig_alength;
	boolean_t		contig_alloc_type;
};

typedef struct _hxge_t hxge_t, *p_hxge_t;
typedef struct _hxge_dma_common_t hxge_dma_common_t, *p_hxge_dma_common_t;

typedef struct _hxge_dma_pool_t {
	p_hxge_dma_common_t	*dma_buf_pool_p;
	uint32_t		ndmas;
	uint32_t		*num_chunks;
	boolean_t		buf_allocated;
} hxge_dma_pool_t, *p_hxge_dma_pool_t;

/*
 * Each logical device (69):
 *	- LDG #
 *	- flag bits
 *	- masks.
 *	- interrupt handler function.
 *
 * Generic system interrupt handler with two arguments:
 *	(hxge_sys_intr_t)
 *	Per device instance data structure
 *	Logical group data structure.
 *
 * Logical device interrupt handler with two arguments:
 *	(hxge_ldv_intr_t)
 *	Per device instance data structure
 *	Logical device number
 */
typedef struct	_hxge_ldg_t hxge_ldg_t, *p_hxge_ldg_t;
typedef struct	_hxge_ldv_t hxge_ldv_t, *p_hxge_ldv_t;
typedef uint_t	(*hxge_sys_intr_t)(caddr_t arg1, caddr_t arg2);
typedef uint_t	(*hxge_ldv_intr_t)(caddr_t arg1, caddr_t arg2);

/*
 * Each logical device Group (64) needs to have the following
 * configurations:
 *	- timer counter (6 bits)
 *	- timer resolution (20 bits, number of system clocks)
 *	- system data (7 bits)
 */
struct _hxge_ldg_t {
	uint8_t			ldg;		/* logical group number */
	uint8_t			vldg_index;
	boolean_t		arm;
	boolean_t		interrupted;
	uint16_t		ldg_timer;	/* counter */
	uint8_t			vector;
	uint8_t			nldvs;
	p_hxge_ldv_t		ldvp;
	hxge_sys_intr_t		sys_intr_handler;
	p_hxge_t		hxgep;
	uint32_t		htable_idx;
};

struct _hxge_ldv_t {
	uint8_t			ldg_assigned;
	uint8_t			ldv;
	boolean_t		is_rxdma;
	boolean_t		is_txdma;
	boolean_t		is_vmac;
	boolean_t		is_syserr;
	boolean_t		is_pfc;
	boolean_t		use_timer;
	uint8_t			channel;
	uint8_t			vdma_index;
	p_hxge_ldg_t		ldgp;
	uint8_t			ldv_ldf_masks;
	hxge_ldv_intr_t		ldv_intr_handler;
	p_hxge_t		hxgep;
};

typedef struct _pci_cfg_t {
	uint16_t vendorid;
	uint16_t devid;
	uint16_t command;
	uint16_t status;
	uint8_t  revid;
	uint8_t  res0;
	uint16_t junk1;
	uint8_t  cache_line;
	uint8_t  latency;
	uint8_t  header;
	uint8_t  bist;
	uint32_t base;
	uint32_t base14;
	uint32_t base18;
	uint32_t base1c;
	uint32_t base20;
	uint32_t base24;
	uint32_t base28;
	uint32_t base2c;
	uint32_t base30;
	uint32_t res1[2];
	uint8_t int_line;
	uint8_t int_pin;
	uint8_t	min_gnt;
	uint8_t max_lat;
} pci_cfg_t, *p_pci_cfg_t;

typedef struct _dev_regs_t {
	hxge_os_acc_handle_t	hxge_pciregh;	/* PCI config DDI IO handle */
	p_pci_cfg_t		hxge_pciregp;	/* mapped PCI registers */

	hxge_os_acc_handle_t	hxge_regh;	/* device DDI IO (BAR 0) */
	void			*hxge_regp;	/* mapped device registers */

	hxge_os_acc_handle_t	hxge_msix_regh;	/* MSI/X DDI handle (BAR 2) */
	void 			*hxge_msix_regp; /* MSI/X register */

	hxge_os_acc_handle_t	hxge_romh;	/* fcode rom handle */
	unsigned char		*hxge_romp;	/* fcode pointer */
} dev_regs_t, *p_dev_regs_t;

#include <hxge_common_impl.h>
#include <hxge_common.h>
#include <hxge_rxdma.h>
#include <hxge_txdma.h>
#include <hxge_fzc.h>
#include <hxge_flow.h>
#include <hxge_virtual.h>
#include <hxge.h>
#include <sys/modctl.h>
#include <sys/pattr.h>
#include <hpi_vir.h>

/*
 * Reconfiguring the network devices requires the net_config privilege
 * in Solaris 10+.  Prior to this, root privilege is required.  In order
 * that the driver binary can run on both S10+ and earlier versions, we
 * make the decisiion as to which to use at runtime.  These declarations
 * allow for either (or both) to exist ...
 */
extern int secpolicy_net_config(const cred_t *, boolean_t);
extern void hxge_fm_report_error(p_hxge_t hxgep,
	uint8_t err_chan, hxge_fm_ereport_id_t fm_ereport_id);
extern int fm_check_acc_handle(ddi_acc_handle_t);
extern int fm_check_dma_handle(ddi_dma_handle_t);

#pragma weak    secpolicy_net_config

hxge_status_t hxge_classify_init(p_hxge_t hxgep);
hxge_status_t hxge_classify_uninit(p_hxge_t hxgep);
void hxge_put_tcam(p_hxge_t hxgep, p_mblk_t mp);
void hxge_get_tcam(p_hxge_t hxgep, p_mblk_t mp);

hxge_status_t hxge_classify_init_hw(p_hxge_t hxgep);
hxge_status_t hxge_classify_init_sw(p_hxge_t hxgep);
hxge_status_t hxge_classify_exit_sw(p_hxge_t hxgep);
hxge_status_t hxge_pfc_ip_class_config_all(p_hxge_t hxgep);
hxge_status_t hxge_pfc_ip_class_config(p_hxge_t hxgep, tcam_class_t l3_class,
	uint32_t class_config);
hxge_status_t hxge_pfc_ip_class_config_get(p_hxge_t hxgep,
	tcam_class_t l3_class, uint32_t *class_config);

hxge_status_t hxge_pfc_set_hash(p_hxge_t, uint32_t);
hxge_status_t hxge_pfc_config_tcam_enable(p_hxge_t);
hxge_status_t hxge_pfc_config_tcam_disable(p_hxge_t);
hxge_status_t hxge_pfc_ip_class_config(p_hxge_t, tcam_class_t, uint32_t);
hxge_status_t hxge_pfc_ip_class_config_get(p_hxge_t, tcam_class_t, uint32_t *);
hxge_status_t hxge_pfc_mac_addrs_get(p_hxge_t hxgep);


hxge_status_t hxge_pfc_hw_reset(p_hxge_t hxgep);
hxge_status_t hxge_pfc_handle_sys_errors(p_hxge_t hxgep);

/* hxge_kstats.c */
void hxge_init_statsp(p_hxge_t);
void hxge_setup_kstats(p_hxge_t);
void hxge_destroy_kstats(p_hxge_t);
int hxge_port_kstat_update(kstat_t *, int);

int hxge_m_stat(void *arg, uint_t stat, uint64_t *val);
int hxge_rx_ring_stat(mac_ring_driver_t, uint_t, uint64_t *);
int hxge_tx_ring_stat(mac_ring_driver_t, uint_t, uint64_t *);

/* hxge_hw.c */
void
hxge_hw_ioctl(p_hxge_t, queue_t *, mblk_t *, struct iocblk *);
void hxge_loopback_ioctl(p_hxge_t, queue_t *, mblk_t *, struct iocblk *);
void hxge_global_reset(p_hxge_t);
uint_t hxge_intr(caddr_t arg1, caddr_t arg2);
void hxge_intr_enable(p_hxge_t hxgep);
void hxge_intr_disable(p_hxge_t hxgep);
void hxge_hw_id_init(p_hxge_t hxgep);
void hxge_hw_init_niu_common(p_hxge_t hxgep);
void hxge_intr_hw_enable(p_hxge_t hxgep);
void hxge_intr_hw_disable(p_hxge_t hxgep);
void hxge_hw_stop(p_hxge_t hxgep);
void hxge_global_reset(p_hxge_t hxgep);
void hxge_check_hw_state(p_hxge_t hxgep);

/* hxge_send.c. */
uint_t hxge_reschedule(caddr_t arg);

/* hxge_ndd.c */
void hxge_get_param_soft_properties(p_hxge_t);
void hxge_setup_param(p_hxge_t);
void hxge_init_param(p_hxge_t);
void hxge_destroy_param(p_hxge_t);
boolean_t hxge_check_rxdma_port_member(p_hxge_t, uint8_t);
boolean_t hxge_check_txdma_port_member(p_hxge_t, uint8_t);
int hxge_param_get_generic(p_hxge_t, queue_t *, mblk_t *, caddr_t);
int hxge_param_set_generic(p_hxge_t, queue_t *, mblk_t *, char *, caddr_t);
int hxge_get_default(p_hxge_t, queue_t *, p_mblk_t, caddr_t);
int hxge_set_default(p_hxge_t, queue_t *, p_mblk_t, char *, caddr_t);
int hxge_nd_get_names(p_hxge_t, queue_t *, p_mblk_t, caddr_t);
int hxge_mk_mblk_tail_space(p_mblk_t mp, p_mblk_t *nmp, size_t size);
void hxge_param_ioctl(p_hxge_t hxgep, queue_t *, mblk_t *, struct iocblk *);
boolean_t hxge_nd_load(caddr_t *, char *, pfi_t, pfi_t, caddr_t);
void hxge_nd_free(caddr_t *);
int hxge_nd_getset(p_hxge_t, queue_t *, caddr_t, p_mblk_t);
boolean_t hxge_set_lb(p_hxge_t, queue_t *wq, p_mblk_t mp);
int hxge_param_rx_intr_pkts(p_hxge_t hxgep, queue_t *, mblk_t *, char *,
    caddr_t);
int hxge_param_rx_intr_time(p_hxge_t hxgep, queue_t *, mblk_t *, char *,
    caddr_t);
int hxge_param_set_ip_opt(p_hxge_t hxgep, queue_t *, mblk_t *, char *, caddr_t);
int hxge_param_get_ip_opt(p_hxge_t hxgep, queue_t *, mblk_t *, caddr_t);

/* hxge_virtual.c */
hxge_status_t hxge_get_config_properties(p_hxge_t);
hxge_status_t hxge_init_fzc_txdma_channel(p_hxge_t hxgep, uint16_t channel,
	p_tx_ring_t tx_ring_p, p_tx_mbox_t mbox_p);
hxge_status_t hxge_init_fzc_rxdma_channel(p_hxge_t hxgep, uint16_t channel,
	p_rx_rbr_ring_t rbr_p, p_rx_rcr_ring_t rcr_p, p_rx_mbox_t mbox_p);
hxge_status_t hxge_init_fzc_rx_common(p_hxge_t hxgep);
hxge_status_t hxge_init_fzc_rxdma_channel_pages(p_hxge_t hxgep,
	uint16_t channel, p_rx_rbr_ring_t rbr_p);
hxge_status_t hxge_init_fzc_txdma_channel_pages(p_hxge_t hxgep,
	uint16_t channel, p_tx_ring_t tx_ring_p);
hxge_status_t hxge_intr_mask_mgmt_set(p_hxge_t hxgep, boolean_t on);

/* MAC functions */
hxge_status_t hxge_vmac_init(p_hxge_t hxgep);
hxge_status_t hxge_link_init(p_hxge_t hxgep);
hxge_status_t hxge_tx_vmac_init(p_hxge_t hxgep);
hxge_status_t hxge_rx_vmac_init(p_hxge_t hxgep);
hxge_status_t hxge_tx_vmac_enable(p_hxge_t hxgep);
hxge_status_t hxge_tx_vmac_disable(p_hxge_t hxgep);
hxge_status_t hxge_rx_vmac_enable(p_hxge_t hxgep);
hxge_status_t hxge_rx_vmac_disable(p_hxge_t hxgep);
hxge_status_t hxge_tx_vmac_reset(p_hxge_t hxgep);
hxge_status_t hxge_rx_vmac_reset(p_hxge_t hxgep);
hxge_status_t hxge_add_mcast_addr(p_hxge_t, struct ether_addr *);
hxge_status_t hxge_del_mcast_addr(p_hxge_t, struct ether_addr *);
hxge_status_t hxge_pfc_set_mac_address(p_hxge_t hxgep, uint32_t slot,
    struct ether_addr *addrp);
hxge_status_t hxge_pfc_num_macs_get(p_hxge_t hxgep, uint8_t *nmacs);
hxge_status_t hxge_pfc_clear_mac_address(p_hxge_t, uint32_t slot);
hxge_status_t hxge_set_promisc(p_hxge_t hxgep, boolean_t on);
void hxge_save_cntrs(p_hxge_t hxgep);
int hxge_vmac_set_framesize(p_hxge_t hxgep);

void hxge_debug_msg(p_hxge_t, uint64_t, char *, ...);

#ifdef HXGE_DEBUG
char *hxge_dump_packet(char *addr, int size);
#endif

#endif	/* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HXGE_HXGE_IMPL_H */
