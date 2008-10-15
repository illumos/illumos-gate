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

#ifndef _SYS_USB_OHCID_H
#define	_SYS_USB_OHCID_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Open Host Controller Driver (OHCI)
 *
 * The USB Open Host Controller driver is a software driver which interfaces
 * to the Universal Serial Bus layer (USBA) and the USB Open Host Controller.
 * The interface to USB Open Host Controller is defined by the OpenHCI  Host
 * Controller Interface.
 *
 * This header file describes the data structures required for the USB Open
 * Host Controller Driver to maintain state of USB Open Host Controller, to
 * perform different USB transfers and for the bandwidth allocations.
 */

#include <sys/usb/hcd/openhci/ohci.h>
#include <sys/usb/hcd/openhci/ohci_hub.h>

/*
 * OpenHCI interrupt status information structure
 *
 * The Host Controller Driver (HCD) has to maintain two different sets of
 * Host Controller (HC) state information that includes HC registers, the
 * interrupt tables etc.. for the normal and polled modes.  In	addition,
 * suppose if we switched to polled mode while ohci  interrupt handler is
 * executing in the normal mode then we need to save the interrupt status
 * information that includes interrupts for which ohci interrupt  handler
 * is called and HCCA done head list in the polled mode. This infromation
 * will be used later in normal mode to  service those missed interrupts.
 * This will avoid race conditions like missing of normal mode's ohci SOF
 * and WriteDoneHead interrupts because of this polled switch.
 */
typedef struct ohci_save_intr_sts {
	/*
	 * The following field has set of flags & these flags will be set
	 * in the ohci interrupt handler to indicate that currently  ohci
	 * interrupt handler is in execution and also while critical code
	 * execution within the ohci interrupt handler.  These flags will
	 * be verified in polled mode while saving the normal mode's ohci
	 * interrupt status information.
	 */
	uint_t		ohci_intr_flag;		/* Intr handler flags */

	/*
	 * The following fields will be used to save the interrupt status
	 * and the HCCA done head list that the ohci interrupt handler is
	 * currently handling.
	 */
	uint_t		ohci_curr_intr_sts;	/* Current interrupts */
	ohci_td_t	*ohci_curr_done_lst;	/* Current done head  */

	/*
	 * The following fields will be used to save the interrupt status
	 * and the HCCA done list currently being handled by the critical
	 * section of the ohci interrupt handler..
	 */
	uint_t		ohci_critical_intr_sts;	/* Critical interrupts */
	ohci_td_t	*ohci_critical_done_lst; /* Critical done head */

	/*
	 * The following fields will be used to save the interrupt status
	 * and HCCA done head list by the polled code if an  interrupt is
	 * pending when polled code is entered. These missed interrupts &
	 * done list will be serviced either in current  normal mode ohci
	 * interrupt handler execution or during the next  ohci interrupt
	 * handler execution.
	 */
	uint_t		ohci_missed_intr_sts;	/* Missed interrupts */
	ohci_td_t	*ohci_missed_done_lst;	/* Missed done head  */
} ohci_save_intr_sts_t;

/*
 * These flags will be set in the the normal mode ohci	interrupt handler
 * to indicate that currently ohci interrupt handler is in  execution and
 * also while critical code  execution within the ohci interrupt handler.
 * These flags will be verified in the polled mode while saving the normal
 * mode's ohci interrupt status infromation.
 */
#define		OHCI_INTR_HANDLING	0x01	/* Handling ohci intrs */
#define		OHCI_INTR_CRITICAL	0x02	/* Critical intr code  */


/*
 * OpenHCI Host Controller state structure
 *
 * The Host Controller Driver (HCD) maintains the state of Host Controller
 * (HC). There is an ohci_state structure per instance	of the OpenHCI
 * host controller.
 */

typedef struct ohci_state {
	dev_info_t		*ohci_dip;		/* Dip of HC */
	uint_t			ohci_instance;
	usba_hcdi_ops_t		*ohci_hcdi_ops;		/* HCDI structure */
	uint_t			ohci_flags;		/* Used for cleanup */
	uint16_t		ohci_vendor_id;		/* chip vendor */
	uint16_t		ohci_device_id;		/* chip device */
	uint8_t			ohci_rev_id;		/* chip revison */

	ohci_regs_t		*ohci_regsp;		/* Host ctlr regs */
	ddi_acc_handle_t	ohci_regs_handle;	/* Reg handle */

	ddi_acc_handle_t	ohci_config_handle;	/* Config space hndle */
	uint_t			ohci_frame_interval;	/* Frme inter reg */
	ddi_dma_attr_t		ohci_dma_attr;		/* DMA attributes */

	ddi_intr_handle_t	*ohci_htable;		/* intr handle */
	int			ohci_intr_type;		/* intr type used */
	int			ohci_intr_cnt;		/* # of intrs inuse */
	uint_t			ohci_intr_pri;		/* intr priority */
	int			ohci_intr_cap;		/* intr capabilities */
	boolean_t		ohci_msi_enabled;	/* default to true */
	kmutex_t		ohci_int_mutex;		/* Mutex for struct */

	/* HCCA area */
	ohci_hcca_t		*ohci_hccap;		/* Virtual HCCA ptr */
	ddi_dma_cookie_t	ohci_hcca_cookie;	/* DMA cookie */
	ddi_dma_handle_t	ohci_hcca_dma_handle;	/* DMA handle */
	ddi_acc_handle_t	ohci_hcca_mem_handle;	/* Memory handle */

	/*
	 * There are two pools of memory. One pool contains the memory for
	 * the transfer descriptors and other pool contains the memory for
	 * the endpoint descriptors. The advantage of the pools is that it's
	 * easy to go back and forth between the iommu and the cpu addresses.
	 *
	 * The pools are protected by the ohci_int_mutex because the memory
	 * in the pools may be accessed by either the host controller or the
	 * host controller driver.
	 */

	/* General transfer descriptor pool */
	ohci_td_t		*ohci_td_pool_addr;	/* Start of the pool */
	ddi_dma_cookie_t	ohci_td_pool_cookie;	/* DMA cookie */
	ddi_dma_handle_t	ohci_td_pool_dma_handle;	/* DMA hndle */
	ddi_acc_handle_t	ohci_td_pool_mem_handle;	/* Mem hndle */

	/* Endpoint descriptor pool */
	ohci_ed_t		*ohci_ed_pool_addr;	/* Start of the pool */
	ddi_dma_cookie_t	ohci_ed_pool_cookie;	/* DMA cookie */
	ddi_dma_handle_t	ohci_ed_pool_dma_handle;	/* DMA handle */
	ddi_acc_handle_t	ohci_ed_pool_mem_handle;	/* Mem handle */
	uint_t			ohci_dma_addr_bind_flag;	/* DMA flag */

	/* Condition variables */
	kcondvar_t		ohci_SOF_cv;		/* SOF variable */

	/* Semaphore to serialize opens and closes */
	ksema_t			ohci_ocsem;

	/*
	 * Bandwidth fields
	 *
	 * The ohci_bandwidth array keeps track of the allocated bandwidth
	 * for this host controller. The total bandwidth allocated for least
	 * allocated list out of the 32 periodic lists is represented by the
	 * ohci_periodic_minimum_bandwidth field.
	 */
	uint_t			ohci_periodic_minimum_bandwidth;
	uint_t			ohci_periodic_bandwidth[NUM_INTR_ED_LISTS];

	/* Different transfer open pipe counts */
	uint_t			ohci_open_pipe_count;
	uint_t			ohci_open_ctrl_pipe_count;
	uint_t			ohci_open_bulk_pipe_count;
	uint_t			ohci_open_periodic_pipe_count;
	uint_t			ohci_open_isoch_pipe_count;
	/*
	 * Endpoint Reclamation List
	 *
	 * The interrupt or isochronous list processing cannot be stopped
	 * when a periodic endpoint is removed from the list. The endpoints
	 * are detached from the interrupt lattice tree and put on to the
	 * reclaimation list. On next SOF interrupt all those endpoints,
	 * which are on the reclaimation list will be deallocated.
	 */
	ohci_ed_t		*ohci_reclaim_list;	/* Reclaimation list */

	ohci_root_hub_t		ohci_root_hub;		/* Root hub info */

	/*
	 * Global transfer timeout handling & this transfer timeout handling
	 * will be per USB Host Controller.
	 */
	struct ohci_trans_wrapper *ohci_timeout_list;	/* Timeout List */
	timeout_id_t		ohci_timer_id;		/* Timer id  */

	/* Frame number overflow information */
	usb_frame_number_t	ohci_fno;

	/* For Schedule Overrun error counter */
	uint_t			ohci_so_error;

	/* For host controller error counter */
	uint_t			ohci_hc_error;

	/* For SOF interrupt event */
	boolean_t		ohci_sof_flag;

	/* Openhci Host Controller Software State information */
	uint_t			ohci_hc_soft_state;

	/*
	 * ohci_save_intr_stats is used to save the normal mode interrupt
	 * status information while executing interrupt handler & also by
	 * the polled code if an interrupt is pending for the normal mode
	 * when polled code is entered.
	 */
	ohci_save_intr_sts_t	ohci_save_intr_sts;

	/*
	 * Saved copy of the ohci registers of the normal mode & change
	 * required ohci registers values for the polled mode operation.
	 * Before returning from the polled mode to normal mode replace
	 * the required current registers with this saved ohci registers
	 * copy.
	 */
	ohci_regs_t	ohci_polled_save_regs;

	/*
	 * Saved copy of the interrupt table used in normal ohci mode and
	 * replace this table by another interrupt table that used in the
	 * POLLED mode.
	 */
	ohci_ed_t	*ohci_polled_save_IntTble[NUM_INTR_ED_LISTS];

	/* ohci polled mode enter counter for the input devices */
	uint_t			ohci_polled_enter_count;

	/*
	 * Counter for polled mode and used in suspend mode to see if
	 * there is a input device connected.
	 */
	uint_t			ohci_polled_kbd_count;

	/* Done list for the Polled mode */
	ohci_td_t		*ohci_polled_done_list;

	/* Log handle for debug, console, log messages */
	usb_log_handle_t	ohci_log_hdl;

	/* Kstat structures */
	kstat_t			*ohci_intrs_stats;
	kstat_t			*ohci_total_stats;
	kstat_t			*ohci_count_stats[USB_N_COUNT_KSTATS];
} ohci_state_t;

typedef struct ohci_intrs_stats {
	struct kstat_named	ohci_hcr_intr_so;
	struct kstat_named	ohci_hcr_intr_wdh;
	struct kstat_named	ohci_hcr_intr_sof;
	struct kstat_named	ohci_hcr_intr_rd;
	struct kstat_named	ohci_hcr_intr_ue;
	struct kstat_named	ohci_hcr_intr_fno;
	struct kstat_named	ohci_hcr_intr_rhsc;
	struct kstat_named	ohci_hcr_intr_oc;
	struct kstat_named	ohci_hcr_intr_not_claimed;
	struct kstat_named	ohci_hcr_intr_total;
} ohci_intrs_stats_t;

/*
 * ohci kstat defines
 */
#define	OHCI_INTRS_STATS(ohci)	((ohci)->ohci_intrs_stats)
#define	OHCI_INTRS_STATS_DATA(ohci)	\
	((ohci_intrs_stats_t *)OHCI_INTRS_STATS((ohci))->ks_data)

#define	OHCI_TOTAL_STATS(ohci)	((ohci)->ohci_total_stats)
#define	OHCI_TOTAL_STATS_DATA(ohci)	(KSTAT_IO_PTR((ohci)->ohci_total_stats))
#define	OHCI_CTRL_STATS(ohci)	\
	(KSTAT_IO_PTR((ohci)->ohci_count_stats[USB_EP_ATTR_CONTROL]))
#define	OHCI_BULK_STATS(ohci)	\
	(KSTAT_IO_PTR((ohci)->ohci_count_stats[USB_EP_ATTR_BULK]))
#define	OHCI_INTR_STATS(ohci)	\
	(KSTAT_IO_PTR((ohci)->ohci_count_stats[USB_EP_ATTR_INTR]))
#define	OHCI_ISOC_STATS(ohci)	\
	(KSTAT_IO_PTR((ohci)->ohci_count_stats[USB_EP_ATTR_ISOCH]))

/* warlock directives, stable data */
_NOTE(MUTEX_PROTECTS_DATA(ohci_state_t::ohci_int_mutex, ohci_state_t))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ohci_state_t::ohci_intr_pri))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ohci_state_t::ohci_dip))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ohci_state_t::ohci_regsp))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ohci_state_t::ohci_instance))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ohci_state_t::ohci_vendor_id))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ohci_state_t::ohci_device_id))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ohci_state_t::ohci_rev_id))

/* this may not be stable data in the future */
_NOTE(DATA_READABLE_WITHOUT_LOCK(ohci_state_t::ohci_td_pool_addr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ohci_state_t::ohci_td_pool_mem_handle))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ohci_state_t::ohci_ed_pool_addr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ohci_state_t::ohci_ed_pool_mem_handle))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ohci_state_t::ohci_td_pool_cookie))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ohci_state_t::ohci_ed_pool_cookie))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ohci_state_t::ohci_hcca_mem_handle))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ohci_state_t::ohci_hccap))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ohci_state_t::ohci_dma_addr_bind_flag))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ohci_state_t::ohci_log_hdl))

_NOTE(LOCK_ORDER(ohci_state::ohci_int_mutex \
		usba_pipe_handle_data::p_mutex \
		usba_device::usb_mutex \
		usba_ph_impl::usba_ph_mutex))

/*
 * Host Contoller Software States
 *
 * OHCI_CTLR_INIT_STATE:
 *	The host controller soft state will be set to this during the
 *	ohci_attach.
 *
 * OHCI_CTLR_SUSPEND_STATE:
 *	The host controller soft state will be set to this during the
 *	ohci_cpr_suspend.
 *
 * OHCI_CTLR_OPERATIONAL_STATE:
 *	The host controller soft state will be set to this after moving
 *	host controller to operational state and host controller start
 *	generating SOF successfully.
 *
 * OHCI_CTLR_ERROR_STATE:
 *	The host controller soft state will be set to this during the
 *	no SOF or UE error conditions.
 *
 *	Under this state or condition, only pipe stop polling, pipe reset
 *	and pipe close are allowed. But all other entry points like  pipe
 *	open, get/set pipe policy, cotrol send/receive, bulk send/receive
 *	isoch send/receive, start polling etc. will fail.
 *
 * State Diagram for the host controller software state
 *
 *
 * ohci_attach->[INIT_STATE]
 *	|
 *	|	-------->----[ERROR_STATE]--<-----------<---
 *	|      |      Failure (UE/no SOF condition)	    |
 *	|      ^					    ^
 *	V      |      Success				    |
 * ohci_init_ctlr--->--------[OPERATIONAL_STATE]------>-ohci_send/recv/polling
 *	^					    |
 *	|					    |
 *	|					    V
 *	-<-ohci_cpr_resume--[SUSPEND_STATE]-<-ohci_cpr_suspend
 */
#define	OHCI_CTLR_INIT_STATE		0	/* Initilization state */
#define	OHCI_CTLR_SUSPEND_STATE		1	/* Suspend state */
#define	OHCI_CTLR_OPERATIONAL_STATE	2	/* Operational state */
#define	OHCI_CTLR_ERROR_STATE		3	/* Ue error or no sof state */

/*
 * Define all ohci's Vendor-id and Device-id Here
 */
#define	RIO_VENDOR	0x108e
#define	RIO_DEVICE	0x1103
#define	OHCI_IS_RIO(ohcip)	(ohcip->ohci_vendor_id == RIO_VENDOR)

/*
 * Periodic and non-periodic macros
 */
#define	OHCI_PERIODIC_ENDPOINT(endpoint) (((endpoint->bmAttributes &\
				USB_EP_ATTR_MASK) == USB_EP_ATTR_INTR) ||\
				((endpoint->bmAttributes &\
				USB_EP_ATTR_MASK) == USB_EP_ATTR_ISOCH))

#define	OHCI_NON_PERIODIC_ENDPOINT(endpoint) (((endpoint->bmAttributes &\
				USB_EP_ATTR_MASK) == USB_EP_ATTR_CONTROL) ||\
				((endpoint->bmAttributes &\
				USB_EP_ATTR_MASK) == USB_EP_ATTR_BULK))

/*
 * OHCI ED and TD Pool sizes.
 */
#define	OHCI_ED_POOL_SIZE	100
#define	OHCI_TD_POOL_SIZE	200

/*
 * ohci_dma_addr_bind_flag values
 *
 * This flag indicates if the various DMA addresses allocated by the OHCI
 * have been bound to their respective handles. This is needed to recover
 * without errors from ohci_cleanup when it calls ddi_dma_unbind_handle()
 */
#define	OHCI_TD_POOL_BOUND	0x01	/* For TD pools  */
#define	OHCI_ED_POOL_BOUND	0x02	/* For ED pools  */
#define	OHCI_HCCA_DMA_BOUND	0x04	/* For HCCA area */

/*
 * Maximum SOF wait count
 */
#define	MAX_SOF_WAIT_COUNT	2	/* Wait for maximum SOF frames */


/*
 * Pipe private structure
 *
 * There is an instance of this structure per pipe.  This structure holds
 * HCD specific pipe information.  A pointer to this structure is kept in
 * the USBA pipe handle (usba_pipe_handle_data_t).
 */
typedef struct ohci_pipe_private {
	usba_pipe_handle_data_t	*pp_pipe_handle;	/* Back ptr to handle */
	ohci_ed_t		*pp_ept;		/* Pipe's ept */

	/* State of the pipe */
	uint_t			pp_state;		/* See below */

	/* Local copy of the pipe policy */
	usb_pipe_policy_t	pp_policy;

	/* For Periodic Pipes Only */
	uint_t			pp_node;		/* Node in lattice */
	uint_t			pp_cur_periodic_req_cnt; /* Curr req count */
	uint_t			pp_max_periodic_req_cnt; /* Max req count */

	/* For isochronous pipe only */
	usb_frame_number_t	pp_next_frame_number;	/* Next frame no */

	/*
	 * Each pipe may have multiple transfer wrappers. Each transfer
	 * wrapper represents a USB transfer on the bus.  A transfer is
	 * made up of one or more transactions.
	 */
	struct ohci_trans_wrapper *pp_tw_head;	/* Head of the list */
	struct ohci_trans_wrapper *pp_tw_tail;	/* Tail of the list */

	/* Done td count */
	uint_t			pp_count_done_tds;	/* Done td count */

	/* Errors */
	usb_cr_t		pp_error;		/* Pipe error */

	/* Flags */
	uint_t			pp_flag;		/* Flags */

	/* Condition variable for transfers completion event */
	kcondvar_t		pp_xfer_cmpl_cv;	/* Xfer completion */

	/*
	 * HCD gets Interrupt/Isochronous IN polling request only once and
	 * it has to insert next polling requests after completion of first
	 * request until either stop polling/pipe close is called. So  HCD
	 * has to take copy of the original Interrupt/Isochronous IN request.
	 */
	usb_opaque_t		pp_client_periodic_in_reqp;
} ohci_pipe_private_t;

/* warlock directives, stable data */
_NOTE(MUTEX_PROTECTS_DATA(ohci_state_t::ohci_int_mutex, ohci_pipe_private_t))

/*
 * Pipe states
 *
 * ohci pipe states will be similar to usba. Refer usbai.h.
 */
#define	OHCI_PIPE_STATE_IDLE		1	/* Pipe is in ready state */
#define	OHCI_PIPE_STATE_ACTIVE		2	/* Pipe is in busy state */
#define	OHCI_PIPE_STATE_ERROR		3	/* Pipe is in error state */

/* Additional ohci pipe states for the ohci_pipe_cleanup */
#define	OHCI_PIPE_STATE_CLOSE		4	/* Pipe close */
#define	OHCI_PIPE_STATE_RESET		5	/* Pipe reset */
#define	OHCI_PIPE_STATE_STOP_POLLING	6	/* Pipe stop polling */

/*
 * Pipe specific Flags
 */
#define	OHCI_ISOC_XFER_CONTINUE	1	/* For isoc transfers */

/*
 * The maximum allowable usb isochronous data transfer size or maximum
 * number of isochronous data packets.
 *
 * Each usb isochronous request must not exceed multiples of isochronous
 * endpoint packet size and OHCI_MAX_ISOC_PKTS_PER_XFER.
 *
 * Ex: usb isochronous endpoint maximum packet size is 64 bytes
 *     maximum usb isochronous request will be OHCI_MAX_ISOC_PKTS_PER_XFER
 *     * 64 bytes
 */
#define		OHCI_MAX_ISOC_PKTS_PER_XFER	256	/* Max pkts per req */

/*
 * The ohci supports maximum of eight isochronous data packets per transfer
 * descriptor.
 */
#define		OHCI_ISOC_PKTS_PER_TD		8	/* Packets per TD */

/*
 * USB frame offset
 *
 * Add appropriate frame offset to the current usb frame number and use it
 * as a starting frame number for a given usb isochronous request.
 */
#define		OHCI_FRAME_OFFSET		2	/* Frame offset */

/*
 * Default usb isochronous receive packets per request before ohci will do
 * callback.
 */
#define		OHCI_DEFAULT_ISOC_RCV_PKTS	1	/* isoc pkts per req */

/*
 * Different interrupt polling intervals supported
 */
#define		INTR_1MS_POLL	1
#define		INTR_2MS_POLL	2
#define		INTR_4MS_POLL	4
#define		INTR_8MS_POLL	8
#define		INTR_16MS_POLL	16
#define		INTR_32MS_POLL	32

/*
 * Number of interrupt/isochronous transfer requests that should
 * be maintained on the interrupt/isochronous endpoint corresponding
 * to different polling intervals supported.
 */
#define		INTR_1MS_REQS	4	/* 1ms polling interval */
#define		INTR_2MS_REQS	2	/* 2ms polling interval */
#define		INTR_XMS_REQS	1	/* Between 4ms and 32ms */

/* Function prototype */
typedef void (*ohci_handler_function_t)(
	ohci_state_t			*ohcip,
	ohci_pipe_private_t		*pp,
	struct ohci_trans_wrapper	*tw,
	ohci_td_t			*td,
	void				*ohci_handle_callback_value);


/*
 * Transfer wrapper
 *
 * The transfer wrapper represents a USB transfer on the bus and there
 * is one instance per USB transfer.  A transfer is made up of one or
 * more transactions. OHCI uses one TD for one transaction. So one
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
 * Isochronous transfers may have multiple DMA buffers per transfer
 * with each isoc TD having a DMA buffer. And one isoc TD may hold up to
 * eight isoc packets, but two cookies at most.
 */
typedef struct ohci_trans_wrapper {
	struct ohci_trans_wrapper	*tw_next;	/* Next wrapper */
	ohci_pipe_private_t		*tw_pipe_private; /* Back ptr */
	ddi_dma_handle_t		tw_dmahandle;	/* DMA handle */
	ddi_acc_handle_t		tw_accesshandle; /* Acc hndle */
	ddi_dma_cookie_t		tw_cookie;	/* DMA cookie */
	uint32_t			tw_id;		/* 32bit ID */
	size_t				tw_length;	/* Txfer length */
	char				*tw_buf;	/* Buffer for Xfer */
	uint_t				tw_ncookies;	/* DMA cookie count */
	uint_t				tw_cookie_idx;	/* DMA cookie index */
	size_t				tw_dma_offs;	/* DMA buffer offset */
	usb_flags_t			tw_flags;	/* Flags */
	uint_t				tw_num_tds;	/* Number of TDs */
	ohci_td_t			*tw_hctd_head;	/* Head TD */
	ohci_td_t			*tw_hctd_tail;	/* Tail TD */
	uint_t				tw_direction;	/* Direction of TD */
	uint_t				tw_pkt_idx;	/* packet index */

	/* We preallocate all the td's for each tw and place them here */
	ohci_td_t			*tw_hctd_free_list;

	/* Current transfer request pointer */
	usb_opaque_t			tw_curr_xfer_reqp;

	/* Current isochronous packet descriptor pointer */
	usb_isoc_pkt_descr_t		*tw_curr_isoc_pktp;

	/* Isochronous DMA handlers and buffer pointers are stored here */
	ohci_isoc_buf_t			*tw_isoc_bufs;
	size_t				tw_isoc_strtlen;

	/* Transfer timeout information */
	uint_t				tw_timeout;	/* Timeout value */
	struct ohci_trans_wrapper	*tw_timeout_next; /* Xfer Timeout Q */

	/*
	 * This is the function to call when this td is done. This way
	 * we don't have to look in the td to figure out what kind it is.
	 */
	ohci_handler_function_t		tw_handle_td;

	/*
	 * This is the callback value used when processing a done td.
	 */
	usb_opaque_t			tw_handle_callback_value;
} ohci_trans_wrapper_t;

_NOTE(MUTEX_PROTECTS_DATA(ohci_state_t::ohci_int_mutex, ohci_trans_wrapper))


/*
 * Time waits for the different OHCI specific operations.
 * These timeout values are specified in terms of microseconds.
 */
#define	OHCI_RESET_TIMEWAIT	10000	/* HC reset waiting time */
#define	OHCI_RESUME_TIMEWAIT	40000	/* HC resume waiting time */
#define	OHCI_TIMEWAIT		10000	/* HC any other waiting time */

/* These timeout values are specified in seconds */
#define	OHCI_DEFAULT_XFER_TIMEOUT	5 /* Default transfer timeout */
#define	OHCI_MAX_SOF_TIMEWAIT		3 /* Maximum SOF waiting time */
#define	OHCI_XFER_CMPL_TIMEWAIT		3 /* Xfers completion timewait */

/* OHCI flags for general use */
#define	OHCI_FLAGS_NOSLEEP	0x000	/* Don't wait for SOF */
#define	OHCI_FLAGS_SLEEP	0x100	/* Wait for SOF */
#define	OHCI_FLAGS_DMA_SYNC	0x200	/* Call ddi_dma_sync */

/*
 * Maximum allowable data transfer  size per transaction as supported
 * by OHCI is 8k. (See Open Host Controller Interface Spec rev 1.0a)
 */
#define	OHCI_MAX_TD_XFER_SIZE	0x2000	/* Maxmum data per transaction */

/*
 * One OHCI TD allows two physically discontiguous pages. The page size
 * is 4k.
 */
#define	OHCI_MAX_TD_BUF_SIZE	0x1000

/*
 * The maximum allowable bulk data transfer size. It can be different
 * from OHCI_MAX_TD_XFER_SIZE and if it is more then ohci driver will
 * take care of  breaking a bulk data request into  multiples of ohci
 * OHCI_MAX_TD_XFER_SIZE  until request is satisfied.  Currently this
 * value is set to 256k bytes.
 */
#define	OHCI_MAX_BULK_XFER_SIZE	0x40000	/* Maximum bulk transfer size */

/*
 * Timeout flags
 *
 * These flags will be used to stop the timer before timeout handler
 * gets executed.
 */
#define	OHCI_REMOVE_XFER_IFLAST	1	/* Stop the timer if  it is last TD */
#define	OHCI_REMOVE_XFER_ALWAYS	2	/* Stop the timer without condition */


/*
 * Bandwidth allocation
 *
 * The following definitions are  used during  bandwidth calculations
 * for a given endpoint maximum packet size.
 */
#define	MAX_USB_BUS_BANDWIDTH	1500	/* Up to 1500 bytes per frame */
#define	MAX_POLL_INTERVAL	255	/* Maximum polling interval */
#define	MIN_POLL_INTERVAL	1	/* Minimum polling interval */
#define	SOF			6	/* Length in bytes of SOF */
#define	EOF			4	/* Length in bytes of EOF */
#define	TREE_HEIGHT		5	/* Log base 2 of 32 */

/*
 * Minimum polling interval for low speed endpoint
 *
 * According USB Specifications, a full-speed endpoint can specify
 * a desired polling interval 1ms to 255ms and a low speed endpoints
 * are limited to specifying only 10ms to 255ms. But some old keyboards
 * and mice uses polling interval of 8ms. For compatibility purpose,
 * we are using polling interval between 8ms and 255ms for low speed
 * endpoints. But ohci driver will reject any low speed endpoints which
 * request polling interval less than 8ms.
 */
#define	MIN_LOW_SPEED_POLL_INTERVAL	8

/*
 * For non-periodic transfers, reserve atleast for one low-speed device
 * transaction. According to USB Bandwidth Analysis white paper and also
 * as per OHCI Specification 1.0a, section 7.3.5, page 123, one low-speed
 * transaction takes 0x628h full speed bits (197 bytes), which comes to
 * around 13% of USB frame time.
 *
 * The periodic transfers will  get around 87% of USB frame time.
 */
#define	MAX_NON_PERIODIC_BANDWIDTH	197
#define	MAX_PERIODIC_BANDWIDTH		(MAX_USB_BUS_BANDWIDTH - SOF - \
					EOF - MAX_NON_PERIODIC_BANDWIDTH)

/*
 * The USB periodic transfers like interrupt and isochronous transfers
 * after completion of SOF and USB non-periodic transfers.
 */
#define	PERIODIC_XFER_STARTS		(MAX_USB_BUS_BANDWIDTH - \
					SOF - MAX_NON_PERIODIC_BANDWIDTH)

/* Number of Bits Per Byte */
#define	BITS_PER_BYTE			8

/*
 * The following are the protocol overheads in terms of Bytes for the
 * different transfer types.  All these protocol overhead  values are
 * derived from the 5.9.3 section of USB Specification	and  with the
 * help of Bandwidth Analysis white paper which is posted on the  USB
 * developer forum.
 */
#define	FS_NON_ISOC_PROTO_OVERHEAD	14
#define	FS_ISOC_INPUT_PROTO_OVERHEAD	11
#define	FS_ISOC_OUTPUT_PROTO_OVERHEAD	10
#define	LOW_SPEED_PROTO_OVERHEAD	97
#define	HUB_LOW_SPEED_PROTO_OVERHEAD	01

/*
 * The Host Controller (HC) delays are the USB host controller specific
 * delays. The value shown below is the host  controller delay for  the
 * RIO USB host controller.  This value was calculated and  given by the
 * Sun USB hardware people.
 */
#define	HOST_CONTROLLER_DELAY		18

/*
 * The low speed clock below represents that to transmit one low-speed
 * bit takes eight times more than one full speed bit time.
 */
#define	LOW_SPEED_CLOCK			8


/*
 * Macros for setting/getting information
 */
#define	Get_ED(addr)		ddi_get32(ohcip->ohci_ed_pool_mem_handle, \
					(uint32_t *)&addr)

#define	Set_ED(addr, val)	ddi_put32(ohcip->ohci_ed_pool_mem_handle,  \
					((uint32_t *)&addr), \
					((int32_t)(val)))

#define	Get_TD(addr)		ddi_get32(ohcip->ohci_td_pool_mem_handle, \
					(uint32_t *)&addr)

#define	Set_TD(addr, val)	ddi_put32(ohcip->ohci_td_pool_mem_handle, \
					((uint32_t *)&addr), \
					((uint32_t)(uintptr_t)(val)))

#define	Get_HCCA(addr)		ddi_get32(ohcip->ohci_hcca_mem_handle, \
					(uint32_t *)&addr)

#define	Set_HCCA(addr, val)	ddi_put32(ohcip->ohci_hcca_mem_handle, \
					((uint32_t *)&addr), \
					((int32_t)(val)))

#define	Get_OpReg(addr)		ddi_get32(ohcip->ohci_regs_handle, \
					(uint32_t *)&ohcip->ohci_regsp->addr)

#define	Set_OpReg(addr, val)	ddi_put32(ohcip->ohci_regs_handle, \
				((uint32_t *)&ohcip->ohci_regsp->addr), \
					((int32_t)(val)))

#define	Sync_HCCA(ohcip)	(void) ddi_dma_sync( \
				ohcip->ohci_hcca_dma_handle, \
				0, sizeof (ohci_hcca_t), \
				DDI_DMA_SYNC_FORCPU);

#define	Sync_ED_TD_Pool(ohcip)	(void) ddi_dma_sync( \
				ohcip->ohci_ed_pool_dma_handle, \
				0, OHCI_ED_POOL_SIZE * sizeof (ohci_ed_t), \
				DDI_DMA_SYNC_FORCPU); \
				(void) ddi_dma_sync( \
				ohcip->ohci_td_pool_dma_handle, \
				0, OHCI_TD_POOL_SIZE * sizeof (ohci_td_t), \
				DDI_DMA_SYNC_FORCPU);

#define	Sync_IO_Buffer(dma_handle, length) \
				(void) ddi_dma_sync(dma_handle, \
				0, length, DDI_DMA_SYNC_FORCPU);

/*
 * Macros to speed handling of 32bit IDs
 */
#define	OHCI_GET_ID(x)		id32_alloc((void *)(x), KM_SLEEP)
#define	OHCI_LOOKUP_ID(x)	id32_lookup((x))
#define	OHCI_FREE_ID(x)		id32_free((x))


/*
 * Miscellaneous definitions.
 */

/* Data toggle bits */
#define	DATA0		0
#define	DATA1		1

/* sKip bit actions */
#define	CLEAR_sKip	0
#define	SET_sKip	1

typedef uint_t		skip_bit_t;

/*
 * Setup Packet
 */
typedef struct setup_pkt {
	uchar_t	bmRequestType;
	uchar_t	bRequest;
	ushort_t wValue;
	ushort_t wIndex;
	ushort_t wLength;
}setup_pkt_t;

#define	SETUP_SIZE		8	/* Setup packet is always 8 bytes */

#define	REQUEST_TYPE_OFFSET	0
#define	REQUEST_OFFSET		1
#define	VALUE_OFFSET		2
#define	INDEX_OFFSET		4
#define	LENGTH_OFFSET		6

#define	TYPE_DEV_TO_HOST	0x80000000
#define	DEVICE			0x00000001
#define	CONFIGURATION		0x00000002

/*
 * The following are used in attach to	 indicate
 * what has been succesfully allocated, so detach
 * can remove them.
 */
#define	OHCI_ATTACH		0x01	/* ohci driver initilization */
#define	OHCI_ZALLOC		0x02	/* Memory for ohci state structure */
#define	OHCI_INTR		0x04	/* Interrupt handler registered */
#define	OHCI_USBAREG		0x08	/* USBA registered */
#define	OHCI_RHREG		0x10	/* Root hub driver loaded */

#define	OHCI_UNIT(dev)	(getminor((dev)) & ~HUBD_IS_ROOT_HUB)

/*
 * Debug printing
 * Masks
 */
#define	PRINT_MASK_ATTA		0x00000001	/* Attach time */
#define	PRINT_MASK_LISTS	0x00000002	/* List management */
#define	PRINT_MASK_ROOT_HUB	0x00000004	/* Root hub stuff */
#define	PRINT_MASK_ALLOC	0x00000008	/* Alloc/dealloc descr */
#define	PRINT_MASK_INTR		0x00000010	/* Interrupt handling */
#define	PRINT_MASK_BW		0x00000020	/* Bandwidth */
#define	PRINT_MASK_CBOPS	0x00000040	/* CB-OPS */
#define	PRINT_MASK_HCDI		0x00000080	/* HCDI entry points */
#define	PRINT_MASK_DUMPING	0x00000100	/* Dump ohci info */
#define	PRINT_MASK_ALL		0xFFFFFFFF


/* Polling support */
int		ohci_hcdi_polled_input_init(
				usba_pipe_handle_data_t	*ph,
				uchar_t			**polled_buf,
				usb_console_info_impl_t	*info);
int		ohci_hcdi_polled_input_enter(
				usb_console_info_impl_t	*info);
int		ohci_hcdi_polled_read(
				usb_console_info_impl_t	*info,
				uint_t			*num_characters);
int		ohci_hcdi_polled_input_exit(
				usb_console_info_impl_t	*info);
int		ohci_hcdi_polled_input_fini(
				usb_console_info_impl_t	*info);

/* Root hub related functions */
int		ohci_init_root_hub(
				ohci_state_t		*ohcip);
int		ohci_load_root_hub_driver(
				ohci_state_t		*ohcip);
int		ohci_unload_root_hub_driver(
				ohci_state_t		*ohcip);
int		ohci_handle_root_hub_pipe_open(
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		flags);
int		ohci_handle_root_hub_pipe_close(
				usba_pipe_handle_data_t	*ph);
int		ohci_handle_root_hub_pipe_reset(
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		flags);
int		ohci_handle_root_hub_request(
				ohci_state_t		*ohcip,
				usba_pipe_handle_data_t	*ph,
				usb_ctrl_req_t		*ctrl_reqp);
int		ohci_handle_root_hub_pipe_start_intr_polling(
				usba_pipe_handle_data_t	*ph,
				usb_intr_req_t		*intr_reqp,
				usb_flags_t		flags);
void		ohci_handle_root_hub_pipe_stop_intr_polling(
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		flags);
void		ohci_handle_root_hub_status_change(void *arg);

/* Endpoint Descriptor (ED) related functions */
ohci_ed_t	*ohci_alloc_hc_ed(
				ohci_state_t		*ohcip,
				usba_pipe_handle_data_t	*ph);
void		ohci_deallocate_ed(
				ohci_state_t		*ohcip,
				ohci_ed_t		*old_ed);
uint32_t	ohci_ed_cpu_to_iommu(
				ohci_state_t		*ohcip,
				ohci_ed_t		*addr);

/* Transfer Descriptor (TD) related functions */
int		ohci_start_periodic_pipe_polling(
				ohci_state_t		*ohcip,
				usba_pipe_handle_data_t	*ph,
				usb_opaque_t		periodic_in_reqp,
				usb_flags_t		flags);
void		ohci_traverse_tds(
				ohci_state_t		*ohcip,
				usba_pipe_handle_data_t	*ph);
void		ohci_deallocate_td(
				ohci_state_t		*ohcip,
				ohci_td_t		*old_td);
uint32_t	ohci_td_cpu_to_iommu(
				ohci_state_t		*ohcip,
				ohci_td_t		*addr);
ohci_td_t	*ohci_td_iommu_to_cpu(
				ohci_state_t		*ohcip,
				uintptr_t		addr);
size_t		ohci_get_td_residue(
				ohci_state_t		*ohcip,
				ohci_td_t		*td);
void		ohci_init_td(
				ohci_state_t		*ohcip,
				ohci_trans_wrapper_t	*tw,
				uint32_t		hctd_dma_offs,
				size_t			hctd_length,
				ohci_td_t		*td);

/* Transfer Wrapper (TW) functions */
void		ohci_deallocate_tw_resources(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp,
				ohci_trans_wrapper_t	*tw);

/* Interrupt Handling functions */
void		ohci_handle_frame_number_overflow(
				ohci_state_t		*ohcip);

/* Miscillaneous functions */
ohci_state_t	*ohci_obtain_state(
				dev_info_t		*dip);
int		ohci_state_is_operational(
				ohci_state_t		*ohcip);
int		ohci_do_soft_reset(
				ohci_state_t		*ohcip);
usb_frame_number_t ohci_get_current_frame_number(
				ohci_state_t		*ohcip);
void		ohci_handle_outstanding_requests(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_OHCID_H */
