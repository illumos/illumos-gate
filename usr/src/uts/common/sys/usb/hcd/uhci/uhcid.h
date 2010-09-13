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

#ifndef _SYS_USB_UHCID_H
#define	_SYS_USB_UHCID_H


#ifdef __cplusplus
extern "C" {
#endif

/*
 * Universal Host Controller Driver (UHCI)
 *
 * The UHCI driver is a driver which interfaces to the Universal
 * Serial Bus Driver (USBA) and the Host Controller (HC). The interface to
 * the Host Controller is defined by the Universal Host Controller Interface.
 *
 * This file contains the data structures for the UHCI driver.
 */
#include <sys/types.h>
#include <sys/pci.h>
#include <sys/kstat.h>

#include <sys/usb/usba/usbai_version.h>
#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_types.h>

#include <sys/usb/usba/genconsole.h>
#include <sys/usb/usba/hcdi.h>

#include <sys/usb/hubd/hub.h>
#include <sys/usb/usba/hubdi.h>
#include <sys/usb/hubd/hubdvar.h>

#include <sys/usb/hcd/uhci/uhci.h>

/* limit the xfer size for bulk */
#define	UHCI_BULK_MAX_XFER_SIZE	(124*1024) /* Max bulk xfer size */

/* Maximum allowable data transfer size per transaction */
#define	UHCI_MAX_TD_XFER_SIZE	0x500 /* Maximum data per transaction */

/*
 * Generic UHCI Macro definitions
 */
#define	UHCI_UNDERRUN_OCCURRED	0x1234
#define	UHCI_OVERRUN_OCCURRED	0x5678
#define	UHCI_PROP_MASK		0x01000020
#define	UHCI_RESET_DELAY	15000
#define	UHCI_TIMEWAIT		10000

#define	MAX_SOF_WAIT_COUNT	2
#define	MAX_RH_PORTS		2
#define	DISCONNECTED		2
#define	POLLING_FREQ_7MS	7
#define	PCI_CONF_IOBASE		0x20
#define	PCI_CONF_IOBASE_MASK	0xffe0

#define	UHCI_ONE_SECOND		drv_usectohz(1000000)
#define	UHCI_ONE_MS		drv_usectohz(1000)
#define	UHCI_32_MS		drv_usectohz(32*1000)
#define	UHCI_256_MS		drv_usectohz(256*1000)
#define	UHCI_MAX_INSTS		4

#define	POLLED_RAW_BUF_SIZE	8

/* Default time out values for bulk and ctrl commands */
#define	UHCI_CTRL_TIMEOUT	5
#define	UHCI_BULK_TIMEOUT	60

/* UHCI root hub structure */
typedef struct uhci_root_hub_info {
	uint_t			rh_status;		/* Last RH status */
	uint_t			rh_num_ports;		/* #ports on the root */

	/* Last status of ports */
	uint_t			rh_port_status[MAX_RH_PORTS];
	uint_t			rh_port_changes[MAX_RH_PORTS];
	uint_t			rh_port_state[MAX_RH_PORTS]; /* See below */

	usba_pipe_handle_data_t	*rh_intr_pipe_handle;	/* RH intr pipe hndle */
	usb_hub_descr_t		rh_descr;		/* RH descr's copy */
	uint_t			rh_pipe_state;		/* RH intr pipe state */

	usb_intr_req_t		*rh_curr_intr_reqp;	/* Current intr req */
	usb_intr_req_t		*rh_client_intr_req;	/* save IN request */
} uhci_root_hub_info_t;

/*
 * UHCI Host Controller per instance data structure
 *
 * The Host Controller Driver (HCD) maintains the state of Host Controller
 * (HC). There is an uhci_state structure per instance	of the UHCI
 * host controller.
 */
typedef struct uhci_state {
	dev_info_t		*uhci_dip;		/* dip of HC */
	uint_t			uhci_instance;
	usba_hcdi_ops_t		*uhci_hcdi_ops;		/* HCDI structure */

	uint_t			uhci_dma_addr_bind_flag;

	/* UHCI Host Controller Software State information */
	uint_t			uhci_hc_soft_state;

	hc_regs_t		*uhci_regsp;		/* Host ctlr regs */
	ddi_acc_handle_t	uhci_regs_handle;	/* Reg handle */

	ddi_acc_handle_t	uhci_config_handle;	/* Config space hndle */

	/* Frame interval reg */
	uint_t			uhci_frame_interval;
	ddi_dma_attr_t		uhci_dma_attr;		/* DMA attributes */

	ddi_intr_handle_t	*uhci_htable;		/* intr handle */
	int			uhci_intr_type;		/* intr type used */
	int			uhci_intr_cnt;		/* # of intrs inuse */
	uint_t			uhci_intr_pri;		/* intr priority */
	int			uhci_intr_cap;		/* intr capabilities */
	kmutex_t		uhci_int_mutex;		/* Mutex for struct */

	frame_lst_table_t	*uhci_frame_lst_tablep;	/* Virtual HCCA ptr */
	uhci_td_t		*uhci_isoc_q_tailp[NUM_FRAME_LST_ENTRIES];

	ddi_dma_cookie_t	uhci_flt_cookie;	/* DMA cookie */
	ddi_dma_handle_t	uhci_flt_dma_handle;	/* DMA handle */
	ddi_acc_handle_t	uhci_flt_mem_handle;	/* Memory handle */

	/*
	 * There are two pools of memory. One pool contains the memory for
	 * the transfer descriptors and other pool contains the memory for
	 * the Queue Head pointers. The advantage of the pools is that it's
	 * easy to go back and forth between the iommu and the cpu addresses.
	 *
	 * The pools are protected by the int_mutex because the memory
	 * in the pools may be accessed by either the host controller or the
	 * host controller driver.
	 */

	/* General transfer descriptor pool */
	uhci_td_t		*uhci_td_pool_addr;	/* Start of the pool */
	ddi_dma_cookie_t	uhci_td_pool_cookie;	/* DMA cookie */
	ddi_dma_handle_t	uhci_td_pool_dma_handle; /* DMA hndle */
	ddi_acc_handle_t	uhci_td_pool_mem_handle; /* Mem hndle */

	/* Endpoint descriptor pool */
	queue_head_t		*uhci_qh_pool_addr;	/* Start of the pool */
	ddi_dma_cookie_t	uhci_qh_pool_cookie;	/* DMA cookie */
	ddi_dma_handle_t	uhci_qh_pool_dma_handle; /* DMA handle */
	ddi_acc_handle_t	uhci_qh_pool_mem_handle; /* Mem handle */

	/* Semaphore to serialize opens and closes */
	ksema_t			uhci_ocsem;

	/* Timeout id of the root hub status change pipe handler */
	timeout_id_t		uhci_timeout_id;

	/* Timeout id of the ctrl/bulk/intr xfers timeout */
	timeout_id_t		uhci_cmd_timeout_id;

	/*
	 * Bandwidth fields
	 *
	 * The uhci_bandwidth array keeps track of the allocated bandwidth
	 * for this host controller. The uhci_bandwidth_isoch_sum field
	 * represents the sum of the allocated isochronous bandwidth. The
	 * total bandwidth allocated for least allocated list out of the 32
	 * interrupt lists is represented by the uhci_bandwdith_intr_min
	 * field.
	 */
	uint_t			uhci_bandwidth[NUM_FRAME_LST_ENTRIES];
	uint_t			uhci_bandwidth_isoch_sum;
	uint_t			uhci_bandwidth_intr_min;

	uhci_root_hub_info_t	uhci_root_hub;	/* Root hub info */

	uhci_td_t		*uhci_outst_tds_head;
	uhci_td_t		*uhci_outst_tds_tail;

	queue_head_t		*uhci_ctrl_xfers_q_head;
	queue_head_t		*uhci_ctrl_xfers_q_tail;
	queue_head_t		*uhci_bulk_xfers_q_head;
	queue_head_t		*uhci_bulk_xfers_q_tail;

	kcondvar_t		uhci_cv_SOF;
	uchar_t			uhci_cv_signal;

	/* Polled I/O support */
	frame_lst_table_t	uhci_polled_save_IntTble[1024];
	uint_t			uhci_polled_count;
	uint32_t		uhci_polled_flag;

	/* Software frame number */
	usb_frame_number_t	uhci_sw_frnum;

	/* Number of pending bulk commands */
	uint32_t		uhci_pending_bulk_cmds;

	/* logging support */
	usb_log_handle_t	uhci_log_hdl;

	/*
	 * TD's used for the generation of interrupt
	 */
	queue_head_t		*uhci_isoc_qh;
	uhci_td_t		*uhci_sof_td;
	uhci_td_t		*uhci_isoc_td;

	/*
	 * Keep io base address, for debugging purpose
	 */
	uint_t			uhci_iobase;

	/*
	 * kstat structures
	 */
	kstat_t			*uhci_intrs_stats;
	kstat_t			*uhci_total_stats;
	kstat_t			*uhci_count_stats[USB_N_COUNT_KSTATS];
} uhci_state_t;


/*
 * uhci_dma_addr_bind_flag values
 *
 * This flag indicates if the various DMA addresses allocated by the UHCI
 * have been bound to their respective handles. This is needed to recover
 * without errors from uhci_cleanup when it calls ddi_dma_unbind_handle()
 */
#define	UHCI_TD_POOL_BOUND	0x01	/* for TD pools */
#define	UHCI_QH_POOL_BOUND	0x02	/* for QH pools */
#define	UHCI_FLA_POOL_BOUND	0x04	/* for Host Ctrlr Framelist Area */

/*
 * Definitions for uhci_polled_flag
 * The flag is set to UHCI_POLLED_FLAG_FALSE by default. The flags is
 * set to UHCI_POLLED_FLAG_TD_COMPL when shifting from normal mode to
 * polled mode and if the normal TD is completed at that time. And the
 * flag is set to UHCI_POLLED_FLAG_TRUE while exiting from the polled
 * mode. In the timeout handler for root hub status change, this flag
 * is checked. If set to UHCI_POLLED_FLAG_TRUE, the routine
 * uhci_process_submitted_td_queue() to process the completed TD.
 */
#define	UHCI_POLLED_FLAG_FALSE		0
#define	UHCI_POLLED_FLAG_TRUE		1
#define	UHCI_POLLED_FLAG_TD_COMPL	2

/*
 * Pipe private structure
 *
 * There is an instance of this structure per pipe.  This structure holds
 * HCD specific pipe information.  A pointer to this structure is kept in
 * the USBA pipe handle (usba_pipe_handle_data_t).
 */
typedef struct uhci_pipe_private {
	usba_pipe_handle_data_t	*pp_pipe_handle; /* Back ptr to pipe handle */
	queue_head_t		*pp_qh;		/* Pipe's ept */
	uint_t			pp_state;	/* See below */
	usb_pipe_policy_t	pp_policy;	/* Copy of the pipe policy */
	uint_t			pp_node;	/* Node in lattice */
	uchar_t			pp_data_toggle;	/* save data toggle bit */

	/*
	 * Each pipe may have multiple transfer wrappers. Each transfer
	 * wrapper represents a USB transfer on the bus.  A transfer is
	 * made up of one or more transactions.
	 */
	struct uhci_trans_wrapper *pp_tw_head;	/* Head of the list */
	struct uhci_trans_wrapper *pp_tw_tail;	/* Tail of the list */

	/*
	 * Starting frame number at which next isoc TD will be inserted
	 * for this pipe
	 */
	uint64_t		pp_frame_num;

	/*
	 * HCD gets Interrupt/Isochronous IN polling request only once and
	 * it has to insert next polling requests after completion of first
	 * request until either stop polling/pipe close is called. So  HCD
	 * has to take copy of the original Interrupt/Isochronous IN request.
	 */
	usb_opaque_t		pp_client_periodic_in_reqp;
} uhci_pipe_private_t;

/* warlock directives, stable data */
_NOTE(MUTEX_PROTECTS_DATA(uhci_state_t::uhci_int_mutex, uhci_pipe_private_t))
_NOTE(LOCK_ORDER(uhci_state::uhci_int_mutex \
		usba_pipe_handle_data::p_mutex \
		usba_device::usb_mutex \
		usba_ph_impl::usba_ph_mutex))
_NOTE(SCHEME_PROTECTS_DATA("private mutex", kstat_io))
_NOTE(SCHEME_PROTECTS_DATA("unshared", usb_isoc_pkt_descr))

/*
 * Pipe states
 *
 * uhci pipe states will be similar to usba. Refer usbai.h.
 */
#define	UHCI_PIPE_STATE_IDLE	1	/* Pipe has opened,ready state */
#define	UHCI_PIPE_STATE_ACTIVE	2	/* Polling the endpoint,busy state */

/*
 * to indicate if we are in close/reset so that we can issue callbacks to
 * IN packets that are pending
 */
#define	UHCI_IN_CLOSE	4
#define	UHCI_IN_RESET	5
#define	UHCI_IN_ERROR	6

/* Function prototype */
typedef void (*uhci_handler_function_t) (uhci_state_t *uhcip, uhci_td_t  *td);

/*
 * Transfer wrapper
 *
 * The transfer wrapper represents a USB transfer on the bus and there
 * is one instance per USB transfer.  A transfer is made up of one or
 * more transactions. UHCI uses one TD for one transaction. So one
 * transfer wrapper may have one or more TDs associated.
 *
 * Control and bulk pipes will have one transfer wrapper per transfer
 * and where as Isochronous and Interrupt pipes will only have one
 * transfer wrapper. The transfers wrapper are continually reused for
 * the Interrupt and Isochronous pipes as those pipes are polled.
 *
 * Control, bulk and interrupt transfers will have one DMA buffer per
 * transfer. The data to be transferred are contained in the DMA buffer
 * which is virtually contiguous but physically discontiguous. When
 * preparing the TDs for a USB transfer, the DMA cookies contained in
 * the buffer need to be walked through to retrieve the DMA addresses.
 *
 * Isochronous transfers will have multiple DMA buffers per transfer
 * with each isoc packet having a DMA buffer. And the DMA buffers should
 * only contain one cookie each, so no cookie walking is necessary.
 */
typedef struct uhci_trans_wrapper {
	struct uhci_trans_wrapper	*tw_next;	/* Next wrapper */
	uhci_pipe_private_t		*tw_pipe_private;
	size_t				tw_length;	/* Txfer length */
	uint_t				tw_tmp;		/* Temp variable */
	ddi_dma_handle_t		tw_dmahandle;	/* DMA handle */
	ddi_acc_handle_t		tw_accesshandle; /* Acc hndle */
	char				*tw_buf;	/* Buffer for txfer */
	ddi_dma_cookie_t		tw_cookie;	/* DMA cookie */
	uint_t				tw_ncookies;	/* DMA cookie count */
	uint_t				tw_cookie_idx;	/* DMA cookie index */
	size_t				tw_dma_offs;	/* DMA buffer offset */
	int				tw_ctrl_state;	/* See below */
	uhci_td_t			*tw_hctd_head;	/* Head TD */
	uhci_td_t			*tw_hctd_tail;	/* Tail TD */
	uint_t				tw_direction;	/* Direction of TD */
	usb_flags_t			tw_flags;	/* Flags */

	/*
	 * This is the function to call when this td is done. This way
	 * we don't have to look in the td to figure out what kind it is.
	 */
	uhci_handler_function_t		tw_handle_td;

	/*
	 * This is the callback value used when processing a done td.
	 */
	usb_opaque_t			tw_handle_callback_value;

	uint_t				tw_bytes_xfered;
	uint_t				tw_bytes_pending;

	/* Maximum amount of time for this command */
	uint_t				tw_timeout_cnt;

	usb_isoc_req_t			*tw_isoc_req;
	uhci_bulk_isoc_xfer_t		tw_xfer_info;
	uhci_isoc_buf_t			*tw_isoc_bufs;	/* Isoc DMA buffers */
	size_t				tw_isoc_strtlen;

	/* This is used to avoid multiple tw deallocation */
	uint_t				tw_claim;

	/*
	 * Pointer to the data in case of send command
	 */
	mblk_t				*tw_data;

	/* save a copy of current request */
	usb_opaque_t			tw_curr_xfer_reqp;
} uhci_trans_wrapper_t;

/* Macros for uhci DMA buffer */
#define	UHCI_DMA_ATTR_ALIGN	0x800
#define	UHCI_DMA_ATTR_SGLLEN	0x7fffffff
#define	UHCI_CTRL_EPT_MAX_SIZE	64

/*
 * Macro for allocation of Bulk and Isoc TD pools
 *
 * When a Bulk or Isoc transfer needs to allocate too many TDs,
 * the allocation for one physical contiguous TD pool may fail
 * due to the fragmentation of physical memory. The number of
 * TDs in one pool should be limited so that a TD pool is within
 * page size under this situation.
 */
#if defined(__sparc)
#define	UHCI_MAX_TD_NUM_PER_POOL	88
#else
#define	UHCI_MAX_TD_NUM_PER_POOL	44
#endif

/* set timeout flag so as to decrement timeout_cnt only once */
#define	TW_TIMEOUT_FLAG		0x1000

/* Macro for changing the data toggle */
#define	ADJ_DATA_TOGGLE(pp) \
		(pp)->pp_data_toggle = ((pp)->pp_data_toggle == 0) ? 1 : 0;

/*
 * Macros for setting/getting information
 */
#define	Get_OpReg32(addr)	ddi_get32(uhcip->uhci_regs_handle, \
				    (uint32_t *)&uhcip->uhci_regsp->addr)
#define	Get_OpReg16(addr)	ddi_get16(uhcip->uhci_regs_handle, \
				    (uint16_t *)&uhcip->uhci_regsp->addr)
#define	Get_OpReg8(addr)	ddi_get8(uhcip->uhci_regs_handle, \
				    (uchar_t *)&uhcip->uhci_regsp->addr)

#define	Set_OpReg32(addr, val)	 ddi_put32(uhcip->uhci_regs_handle, \
				    ((uint32_t *)&uhcip->uhci_regsp->addr), \
				    ((int32_t)(val)))
#define	Set_OpReg16(addr, val)	 ddi_put16(uhcip->uhci_regs_handle, \
				    ((uint16_t *)&uhcip->uhci_regsp->addr), \
				    ((int16_t)(val)))

#define	QH_PADDR(addr) \
		((uint32_t)(uhcip->uhci_qh_pool_cookie.dmac_address + \
		(uint32_t)((uintptr_t)(addr) - \
		(uintptr_t)uhcip->uhci_qh_pool_addr)))


#define	QH_VADDR(addr) \
		((void *)(((uint32_t)(addr) - \
		(uint32_t)uhcip->uhci_qh_pool_cookie.dmac_address) + \
		(char *)uhcip->uhci_qh_pool_addr))

#define	TD_PADDR(addr)	\
		((uint32_t)uhcip->uhci_td_pool_cookie.dmac_address + \
		(uint32_t)((uintptr_t)(addr) - \
		(uintptr_t)(uhcip->uhci_td_pool_addr)))

#define	BULKTD_PADDR(x, addr)\
		((uint32_t)((uintptr_t)(addr) - (uintptr_t)x->pool_addr) + \
		(uint32_t)(x)->cookie.dmac_address)

#define	BULKTD_VADDR(x, addr)\
		((void *)(((uint32_t)(addr) - \
		(uint32_t)(x)->cookie.dmac_address) + \
		(char *)(x)->pool_addr))

#define	ISOCTD_PADDR(x, addr)\
		((uint32_t)((uintptr_t)(addr) - (uintptr_t)(x)->pool_addr) + \
		(uint32_t)(x)->cookie.dmac_address)

#define	TD_VADDR(addr) \
		((void *)(((uint32_t)(addr) - \
		(uint32_t)uhcip->uhci_td_pool_cookie.dmac_address) + \
		(char *)uhcip->uhci_td_pool_addr))

/*
 * If the terminate bit is cleared, there shouldn't be any
 * race condition problems. If the host controller reads the
 * bit before the driver has a chance to set the bit, the bit
 * will be reread on the next frame.
 */
#define	UHCI_SET_TERMINATE_BIT(addr)	\
	SetQH32(uhcip, addr, GetQH32(uhcip, (addr)) | HC_END_OF_LIST)
#define	UHCI_CLEAR_TERMINATE_BIT(addr)	\
	SetQH32(uhcip, addr, GetQH32(uhcip, (addr)) & ~HC_END_OF_LIST)

#define	UHCI_XFER_TYPE(ept)		((ept)->bmAttributes & USB_EP_ATTR_MASK)
#define	UHCI_XFER_DIR(ept)		((ept)->bEndpointAddress & \
						USB_EP_DIR_MASK)

/*
 * for HCD based kstats:
 * uhci_intrs_stats_t structure
 */
typedef struct uhci_intrs_stats {
	struct kstat_named	uhci_intrs_hc_halted;
	struct kstat_named	uhci_intrs_hc_process_err;
	struct kstat_named	uhci_intrs_host_sys_err;
	struct kstat_named	uhci_intrs_resume_detected;
	struct kstat_named	uhci_intrs_usb_err_intr;
	struct kstat_named	uhci_intrs_usb_intr;
	struct kstat_named	uhci_intrs_total;
	struct kstat_named	uhci_intrs_not_claimed;
} uhci_intrs_stats_t;

/*
 * uhci defines for kstats
 */
#define	UHCI_INTRS_STATS(uhci)	((uhci)->uhci_intrs_stats)
#define	UHCI_INTRS_STATS_DATA(uhci)	\
	((uhci_intrs_stats_t *)UHCI_INTRS_STATS((uhci))->ks_data)

#define	UHCI_TOTAL_STATS(uhci)		((uhci)->uhci_total_stats)
#define	UHCI_TOTAL_STATS_DATA(uhci)	(KSTAT_IO_PTR((uhci)->uhci_total_stats))
#define	UHCI_CTRL_STATS(uhci)	\
		(KSTAT_IO_PTR((uhci)->uhci_count_stats[USB_EP_ATTR_CONTROL]))
#define	UHCI_BULK_STATS(uhci)	\
		(KSTAT_IO_PTR((uhci)->uhci_count_stats[USB_EP_ATTR_BULK]))
#define	UHCI_INTR_STATS(uhci)	\
		(KSTAT_IO_PTR((uhci)->uhci_count_stats[USB_EP_ATTR_INTR]))
#define	UHCI_ISOC_STATS(uhci)	\
		(KSTAT_IO_PTR((uhci)->uhci_count_stats[USB_EP_ATTR_ISOCH]))

#define	UHCI_UNIT(dev)	(getminor((dev)) & ~HUBD_IS_ROOT_HUB)

#define	UHCI_PERIODIC_ENDPOINT(ept) \
	(((((ept)->bmAttributes) & USB_EP_ATTR_MASK) == USB_EP_ATTR_INTR) || \
	((((ept)->bmAttributes) & USB_EP_ATTR_MASK) == USB_EP_ATTR_ISOCH))

/*
 * Host Contoller Software States
 *
 * UHCI_CTLR_INIT_STATE:
 *      The host controller soft state will be set to this during the
 *      uhci_attach.
 *
 * UHCI_CTLR_SUSPEND_STATE:
 *      The host controller soft state will be set to this during the
 *      uhci_cpr_suspend.
 *
 * UHCI_CTLR_OPERATIONAL_STATE:
 *      The host controller soft state will be set to this after moving
 *      host controller to operational state and host controller start
 *      generating SOF successfully.
 *
 * UHCI_CTLR_ERROR_STATE:
 *      The host controller soft state will be set to this during the
 *      hardware error or no SOF conditions.
 *
 *      Under non-operational state, only pipe stop polling, pipe reset
 *      and pipe close are allowed. But all other entry points like pipe
 *      open, get/set pipe policy, cotrol send/receive, bulk send/receive
 *      isoch send/receive, start polling etc. will fail.
 */
#define	UHCI_CTLR_INIT_STATE		0	/* Initilization state */
#define	UHCI_CTLR_SUSPEND_STATE		1	/* Suspend state */
#define	UHCI_CTLR_OPERATIONAL_STATE	2	/* Operational state */
#define	UHCI_CTLR_ERROR_STATE		3	/* Hardware error */

/*
 * Debug printing Masks
 */
#define	PRINT_MASK_ATTA		0x00000001	/* Attach time */
#define	PRINT_MASK_LISTS	0x00000002	/* List management */
#define	PRINT_MASK_ROOT_HUB	0x00000004	/* Root hub stuff */
#define	PRINT_MASK_ALLOC	0x00000008	/* Alloc/dealloc descr */
#define	PRINT_MASK_INTR		0x00000010	/* Interrupt handling */
#define	PRINT_MASK_BW		0x00000020	/* Bandwidth */
#define	PRINT_MASK_CBOPS	0x00000040	/* CB-OPS */
#define	PRINT_MASK_HCDI		0x00000080	/* HCDI entry points */
#define	PRINT_MASK_DUMPING	0x00000100	/* Dump HCD state info */
#define	PRINT_MASK_ISOC		0x00000200	/* For ISOC xfers */

#define	PRINT_MASK_ALL		0xFFFFFFFF

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_UHCID_H */
