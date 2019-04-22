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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_USB_EHCID_H
#define	_SYS_USB_EHCID_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Enchanced Host Controller Driver (EHCI)
 *
 * The EHCI driver is a software driver which interfaces to the Universal
 * Serial Bus layer (USBA) and the Host Controller (HC). The interface to
 * the Host Controller is defined by the EHCI Host Controller Interface.
 *
 * This header file describes the data structures and function prototypes
 * required for the EHCI Driver to maintain state of Host Controller (HC),
 * to perform different USB transfers and for the bandwidth allocations.
 */

#include <sys/usb/hcd/ehci/ehci.h>
#include <sys/usb/hcd/ehci/ehci_hub.h>


/*
 * EHCI Bandwidth Maintainence Structure.
 *
 * The ehci_bandwidth array keeps track of allocated bandwidth for ehci
 * host controller. There are 32 bandwidth lists corresponding to 32 ms
 * periodic frame lists.  Each bandwidth list inturn will contain eight
 * micro frame bandwidth lists.
 */
#define	EHCI_MAX_UFRAMES	8	/* Max uframes 125us per frame */

typedef struct ehci_frame_bandwidth {
	uint_t			ehci_allocated_frame_bandwidth;
	uint_t			ehci_micro_frame_bandwidth[EHCI_MAX_UFRAMES];
} ehci_frame_bandwidth_t;


/*
 * EHCI Host Controller state structure
 *
 * The Host Controller Driver (HCD) maintains the state of Host Controller
 * (HC). There is an ehci_state structure per instance	of the EHCI
 * host controller.
 */
typedef struct ehci_state {
	dev_info_t		*ehci_dip;		/* Dip of HC */
	uint_t			ehci_instance;
	usba_hcdi_ops_t		*ehci_hcdi_ops;		/* HCDI structure */
	uint_t			ehci_flags;		/* Used for cleanup */
	uint16_t		ehci_vendor_id;		/* chip vendor */
	uint16_t		ehci_device_id;		/* chip device */
	uint8_t			ehci_rev_id;		/* chip revison */

	ddi_acc_handle_t	ehci_caps_handle;	/* Caps Reg Handle */
	ehci_caps_t		*ehci_capsp;		/* Capability Regs */
	ehci_regs_t		*ehci_regsp;		/* Operational Regs */

	ddi_acc_handle_t	ehci_config_handle;	/* Config space hndle */
	uint_t			ehci_frame_interval;	/* Frme inter reg */
	ddi_dma_attr_t		ehci_dma_attr;		/* DMA attributes */

	ddi_intr_handle_t	*ehci_htable;		/* intr handle */
	int			ehci_intr_type;		/* intr type used */
	int			ehci_intr_cnt;		/* # of intrs inuse */
	uint_t			ehci_intr_pri;		/* intr priority */
	int			ehci_intr_cap;		/* intr capabilities */
	boolean_t		ehci_msi_enabled;	/* default to true */
	kmutex_t		ehci_int_mutex;		/* Global EHCI mutex */

	/* Periodic Frame List area */
	ehci_periodic_frame_list_t	*ehci_periodic_frame_list_tablep;
				/* Virtual Periodic Frame List ptr */
	ddi_dma_cookie_t	ehci_pflt_cookie;	/* DMA cookie */
	ddi_dma_handle_t	ehci_pflt_dma_handle;	/* DMA handle */
	ddi_acc_handle_t	ehci_pflt_mem_handle;	/* Memory handle */

	/*
	 * There are two pools of memory. One pool contains the memory for
	 * the transfer descriptors and other pool contains the memory for
	 * the endpoint descriptors. The advantage of the pools is that it's
	 * easy to go back and forth between the iommu and the cpu addresses.
	 *
	 * The pools are protected by the ehci_int_mutex because the memory
	 * in the pools may be accessed by either the host controller or the
	 * host controller driver.
	 */

	/* Endpoint descriptor pool */
	ehci_qh_t		*ehci_qh_pool_addr;	/* Start of the pool */
	ddi_dma_cookie_t	ehci_qh_pool_cookie;	/* DMA cookie */
	ddi_dma_handle_t	ehci_qh_pool_dma_handle;	/* DMA handle */
	ddi_acc_handle_t	ehci_qh_pool_mem_handle;	/* Mem handle */
	uint_t			ehci_dma_addr_bind_flag;	/* DMA flag */

	/* General transfer descriptor pool */
	ehci_qtd_t		*ehci_qtd_pool_addr;	/* Start of the pool */
	ddi_dma_cookie_t	ehci_qtd_pool_cookie;	/* DMA cookie */
	ddi_dma_handle_t	ehci_qtd_pool_dma_handle;	/* DMA hndle */
	ddi_acc_handle_t	ehci_qtd_pool_mem_handle;	/* Mem hndle */

	/* Isochronous transfer descriptor pool */
	ehci_itd_t		*ehci_itd_pool_addr;	/* Start of the pool */
	ddi_dma_cookie_t	ehci_itd_pool_cookie;	/* DMA cookie */
	ddi_dma_handle_t	ehci_itd_pool_dma_handle;	/* DMA hndle */
	ddi_acc_handle_t	ehci_itd_pool_mem_handle;	/* Mem hndle */

	/* Condition variable for advance on Asynchronous Schedule */
	kcondvar_t		ehci_async_schedule_advance_cv;

	/* Head of Asynchronous Schedule List */
	ehci_qh_t		*ehci_head_of_async_sched_list;

	/*
	 * List of QTD inserted either into Asynchronous or Periodic
	 * Schedule lists.
	 */
	ehci_qtd_t		*ehci_active_qtd_list;
	/*
	 * List of ITD active itd list.
	 */
	ehci_itd_t		*ehci_active_itd_list;

	/*
	 * Bandwidth fields
	 *
	 * The ehci_bandwidth array keeps track of allocated bandwidth for
	 * ehci host controller. There are 32 bandwidth lists corresponding
	 * to 32 ms periodic frame lists. Each bandwidth list in turn will
	 * contain eight micro frame bandwidth lists.
	 *
	 * ehci_min_frame_bandwidth field indicates least allocated milli
	 * second bandwidth list.
	 */
	ehci_frame_bandwidth_t	ehci_frame_bandwidth[EHCI_NUM_INTR_QH_LISTS];

	/* No. of open pipes, async qh, and periodic qh */
	uint_t			ehci_open_pipe_count;
	uint_t			ehci_open_async_count;
	uint_t			ehci_open_periodic_count;

	/* No. of async and periodic requests */
	uint_t			ehci_async_req_count;
	uint_t			ehci_periodic_req_count;

	/*
	 * Endpoint Reclamation List
	 *
	 * The interrupt list processing cannot be stopped when a periodic
	 * endpoint is removed from the list.  The endpoints are detached
	 * from the interrupt lattice tree and put on to the reclaimation
	 * list. On next SOF interrupt all those endpoints,  which are on
	 * the reclaimation list will be deallocated.
	 */
	ehci_qh_t		*ehci_reclaim_list;	/* Reclaimation list */

	ehci_root_hub_t		ehci_root_hub;		/* Root hub info */

	/* Frame number overflow information */
	usb_frame_number_t	ehci_fno;

	/* For host controller error counter */
	uint_t			ehci_hc_error;

	/*
	 * ehci_missed_intr_sts is used to save the normal mode interrupt
	 * status information  if an interrupt is pending for normal mode
	 * when polled code is entered.
	 */
	uint_t			ehci_missed_intr_sts;

	/*
	 * Saved copy of the ehci registers of the normal mode & change
	 * required ehci registers values for the polled mode operation.
	 * Before returning from the polled mode to normal mode replace
	 * the required current registers with this saved ehci registers
	 * copy.
	 */
	ehci_regs_t	ehci_polled_save_regs;

	/*
	 * Saved copy of the interrupt table used in normal ehci mode and
	 * replace this table by another interrupt table that used in the
	 * POLLED mode.
	 */
	ehci_qh_t *ehci_polled_frame_list_table[EHCI_NUM_PERIODIC_FRAME_LISTS];

	/* ehci polled mode enter counter */
	uint_t			ehci_polled_enter_count;

	/*
	 * counter for polled mode and used in suspend mode to see if
	 * there is a keyboard connected.
	 */
	uint_t			ehci_polled_kbd_count;

	/* counter for polled read and use it to clean the interrupt status */
	uint_t			ehci_polled_read_count;

#if defined(__x86)
	/* counter for polled root hub status */
	uint_t			ehci_polled_root_hub_count;
#endif	/* __x86 */

	/* EHCI Host Controller Software State information */
	uint_t			ehci_hc_soft_state;

	/* Log handle for debug, console, log messages */
	usb_log_handle_t	ehci_log_hdl;

	/* Kstat structures */
	kstat_t			*ehci_intrs_stats;
	kstat_t			*ehci_total_stats;
	kstat_t			*ehci_count_stats[USB_N_COUNT_KSTATS];
} ehci_state_t;

typedef struct ehci_intrs_stats {
	struct kstat_named	ehci_sts_async_sched_status;
	struct kstat_named	ehci_sts_periodic_sched_status;
	struct kstat_named	ehci_sts_empty_async_schedule;
	struct kstat_named	ehci_sts_host_ctrl_halted;
	struct kstat_named	ehci_sts_async_advance_intr;
	struct kstat_named	ehci_sts_host_system_error_intr;
	struct kstat_named	ehci_sts_frm_list_rollover_intr;
	struct kstat_named	ehci_sts_rh_port_change_intr;
	struct kstat_named	ehci_sts_usb_error_intr;
	struct kstat_named	ehci_sts_usb_intr;
	struct kstat_named	ehci_sts_not_claimed;
	struct kstat_named	ehci_sts_total;
} ehci_intrs_stats_t;

/*
 * ehci kstat defines
 */
#define	EHCI_INTRS_STATS(ehci)	((ehci)->ehci_intrs_stats)
#define	EHCI_INTRS_STATS_DATA(ehci)	\
	((ehci_intrs_stats_t *)EHCI_INTRS_STATS((ehci))->ks_data)

#define	EHCI_TOTAL_STATS(ehci)	((ehci)->ehci_total_stats)
#define	EHCI_TOTAL_STATS_DATA(ehci)	(KSTAT_IO_PTR((ehci)->ehci_total_stats))
#define	EHCI_CTRL_STATS(ehci)	\
	(KSTAT_IO_PTR((ehci)->ehci_count_stats[USB_EP_ATTR_CONTROL]))
#define	EHCI_BULK_STATS(ehci)	\
	(KSTAT_IO_PTR((ehci)->ehci_count_stats[USB_EP_ATTR_BULK]))
#define	EHCI_INTR_STATS(ehci)	\
	(KSTAT_IO_PTR((ehci)->ehci_count_stats[USB_EP_ATTR_INTR]))
#define	EHCI_ISOC_STATS(ehci)	\
	(KSTAT_IO_PTR((ehci)->ehci_count_stats[USB_EP_ATTR_ISOCH]))

/* warlock directives, stable data */
_NOTE(MUTEX_PROTECTS_DATA(ehci_state_t::ehci_int_mutex, ehci_state_t))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ehci_state_t::ehci_intr_pri))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ehci_state_t::ehci_dip))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ehci_state_t::ehci_regsp))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ehci_state_t::ehci_instance))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ehci_state_t::ehci_vendor_id))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ehci_state_t::ehci_device_id))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ehci_state_t::ehci_rev_id))

/* this may not be stable data in the future */
_NOTE(DATA_READABLE_WITHOUT_LOCK(ehci_state_t::ehci_qtd_pool_addr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ehci_state_t::ehci_qtd_pool_mem_handle))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ehci_state_t::ehci_qtd_pool_cookie))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ehci_state_t::ehci_qh_pool_addr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ehci_state_t::ehci_qh_pool_mem_handle))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ehci_state_t::ehci_qh_pool_cookie))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ehci_state_t::ehci_itd_pool_addr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ehci_state_t::ehci_itd_pool_mem_handle))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ehci_state_t::ehci_itd_pool_cookie))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ehci_state_t::ehci_dma_addr_bind_flag))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ehci_state_t::ehci_log_hdl))

_NOTE(LOCK_ORDER(ehci_state::ehci_int_mutex \
		usba_pipe_handle_data::p_mutex \
		usba_device::usb_mutex \
		usba_ph_impl::usba_ph_mutex))

/*
 * Host Contoller Software States
 *
 * EHCI_CTLR_INIT_STATE:
 *	The host controller soft state will be set to this during the
 *	ehci_attach.
 *
 * EHCI_CTLR_SUSPEND_STATE:
 *	The host controller soft state will be set to this during the
 *	ehci_cpr_suspend.
 *
 * EHCI_CTLR_OPERATIONAL_STATE:
 *	The host controller soft state will be set to this after moving
 *	host controller to operational state and host controller start
 *	generating SOF successfully.
 *
 * EHCI_CTLR_ERROR_STATE:
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
 * ehci_attach->[INIT_STATE]
 *	|
 *	|	-------->----[ERROR_STATE]--<-----------<---
 *	|      |      Failure (UE/no SOF condition)	    |
 *	|      ^					    ^
 *	V      |      Success				    |
 * ehci_init_ctlr--->--------[OPERATIONAL_STATE]------>-ehci_send/recv/polling
 *	^					    |
 *	|					    |
 *	|					    V
 *	-<-ehci_cpr_resume--[SUSPEND_STATE]-<-ehci_cpr_suspend
 */
#define	EHCI_CTLR_INIT_STATE		0	/* Initilization state */
#define	EHCI_CTLR_SUSPEND_STATE		1	/* Suspend state */
#define	EHCI_CTLR_OPERATIONAL_STATE	2	/* Operational state */
#define	EHCI_CTLR_ERROR_STATE		3	/* Ue error or no sof state */

/*
 * Flags for initializatoin of host controller
 */
#define	EHCI_NORMAL_INITIALIZATION	0	/* Normal initialization */
#define	EHCI_REINITIALIZATION		1	/* Re-initialization */

/*
 * Periodic and non-periodic macros
 */
#define	EHCI_PERIODIC_ENDPOINT(endpoint) (((endpoint->bmAttributes &\
				USB_EP_ATTR_MASK) == USB_EP_ATTR_INTR) ||\
				((endpoint->bmAttributes &\
				USB_EP_ATTR_MASK) == USB_EP_ATTR_ISOCH))

#define	EHCI_NON_PERIODIC_ENDPOINT(endpoint) (((endpoint->bmAttributes &\
				USB_EP_ATTR_MASK) == USB_EP_ATTR_CONTROL) ||\
				((endpoint->bmAttributes &\
				USB_EP_ATTR_MASK) == USB_EP_ATTR_BULK))

#define	EHCI_ISOC_ENDPOINT(endpoint) (((endpoint->bmAttributes &\
				USB_EP_ATTR_MASK) == USB_EP_ATTR_ISOCH))

#define	EHCI_INTR_ENDPOINT(endpoint) (((endpoint->bmAttributes &\
				USB_EP_ATTR_MASK) == USB_EP_ATTR_INTR))


/*
 * EHCI QH and QTD Pool sizes.
 */
#define	EHCI_QH_POOL_SIZE	100
#define	EHCI_QTD_POOL_SIZE	200
#define	EHCI_ITD_POOL_SIZE	200

/*
 * ehci_dma_addr_bind_flag values
 *
 * This flag indicates if the various DMA addresses allocated by the EHCI
 * have been bound to their respective handles. This is needed to recover
 * without errors from ehci_cleanup when it calls ddi_dma_unbind_handle()
 */
#define	EHCI_QTD_POOL_BOUND	0x01	/* For QTD pools  */
#define	EHCI_QH_POOL_BOUND	0x02	/* For QH pools  */
#define	EHCI_PFLT_DMA_BOUND	0x04	/* For Periodic Frame List area */
#define	EHCI_ITD_POOL_BOUND	0x08	/* For QTD pools  */

/*
 * Maximum SOF wait count
 */
#define	MAX_SOF_WAIT_COUNT	2	/* Wait for maximum SOF frames */

/*
 * One uFrame	125 micro seconds
 * One Frame	1 milli second or 8 uFrames
 */
#define	EHCI_uFRAMES_PER_USB_FRAME		8
#define	EHCI_uFRAMES_PER_USB_FRAME_SHIFT	3


/*
 * Pipe private structure
 *
 * There is an instance of this structure per pipe.  This structure holds
 * HCD specific pipe information.  A pointer to this structure is kept in
 * the USBA pipe handle (usba_pipe_handle_data_t).
 */
typedef struct ehci_pipe_private {
	usba_pipe_handle_data_t	*pp_pipe_handle;	/* Back ptr to handle */
	ehci_qh_t		*pp_qh;			/* Pipe's qh */

	/* State of the pipe */
	uint_t			pp_state;		/* See below */

	/* Local copy of the pipe policy */
	usb_pipe_policy_t	pp_policy;

	/* For Periodic Pipes Only */
	uint_t			pp_pnode;		/* periodic node */
	uchar_t			pp_smask;		/* Start split mask */
	uchar_t			pp_cmask;		/* Comp split mask */
	uint_t			pp_cur_periodic_req_cnt; /* Curr req count */
	uint_t			pp_max_periodic_req_cnt; /* Max req count */

	/* For Isochronous pipes only */
	usb_frame_number_t	pp_next_frame_number;	/* Next frame no */

	/*
	 * Each pipe may have multiple transfer wrappers. Each transfer
	 * wrapper represents a USB transfer on the bus.  A transfer is
	 * made up of one or more transactions.
	 */
	struct ehci_trans_wrapper *pp_tw_head;	/* Head of the list */
	struct ehci_trans_wrapper *pp_tw_tail;	/* Tail of the list */

	struct ehci_isoc_xwrapper *pp_itw_head;	/* Head of the list */
	struct ehci_isoc_xwrapper *pp_itw_tail;	/* Tail of the list */

	/*
	 * Pipe's transfer timeout handling & this transfer timeout handling
	 * will be per pipe.
	 */
	struct ehci_trans_wrapper *pp_timeout_list;	/* Timeout list */
	timeout_id_t		pp_timer_id;		/* Timer id  */

	/* Done td count */
	uint_t			pp_count_done_qtds;	/* Done td count */

	/* Errors */
	usb_cr_t		pp_error;		/* Pipe error */

	/* Condition variable for transfers completion event */
	kcondvar_t		pp_xfer_cmpl_cv;	/* Xfer completion */

	/* Pipe flag */
	uint_t			pp_flag;		/* For polled mode */

	/* Halting States */
	uint_t			pp_halt_state;		/* Is it halting */

	/* Condition variable for halt completion event */
	kcondvar_t		pp_halt_cmpl_cv;	/* Xfer completion */

	/*
	 * HCD gets Interrupt/Isochronous IN polling request only once and
	 * it has to insert next polling requests after completion of first
	 * request until either stop polling/pipe close is called. So  HCD
	 * has to take copy of the original Interrupt/Isochronous IN request.
	 */
	usb_opaque_t		pp_client_periodic_in_reqp;
} ehci_pipe_private_t;

_NOTE(MUTEX_PROTECTS_DATA(ehci_state_t::ehci_int_mutex, ehci_pipe_private_t))

/*
 * Pipe states
 *
 * ehci pipe states will be similar to usba. Refer usbai.h.
 */
#define	EHCI_PIPE_STATE_IDLE		1	/* Pipe is in ready state */
#define	EHCI_PIPE_STATE_ACTIVE		2	/* Pipe is in busy state */
#define	EHCI_PIPE_STATE_ERROR		3	/* Pipe is in error state */

/* Additional ehci pipe states for the ehci_pipe_cleanup */
#define	EHCI_PIPE_STATE_CLOSE		4	/* Pipe close */
#define	EHCI_PIPE_STATE_RESET		5	/* Pipe reset */
#define	EHCI_PIPE_STATE_STOP_POLLING	6	/* Pipe stop polling */

/*
 * Pipe flag
 *
 * Interrupt or polled mode.
 */
#define	EHCI_INTERRUPT_MODE_FLAG	0	/* Interrupt mode flag */
#define	EHCI_POLLED_MODE_FLAG		1	/* Polled mode flag */

/* Pipe specific flags */
#define	EHCI_ISOC_XFER_CONTINUE		1	/* For isoc transfers */

/*
 * Halting States
 *  prevent halting from interleaving.
 */
#define	EHCI_HALT_STATE_FREE		0	/* Pipe free to accept reqs */
#define	EHCI_HALT_STATE_HALTING		1	/* Currently Halting */

/*
 * Request values for Clear_TT_Buffer
 */
#define	EHCI_CLEAR_TT_BUFFER_REQTYPE	(USB_DEV_REQ_TYPE_CLASS | \
					USB_DEV_REQ_RCPT_OTHER)
#define	EHCI_CLEAR_TT_BUFFER_BREQ	8

/*
 * USB frame offset
 *
 * Add appropriate frame offset to the current usb frame number and use it
 * as a starting frame number for a given usb isochronous request.
 */
#define	EHCI_FRAME_OFFSET		2	/* Frame offset */

/*
 * Different interrupt polling intervals supported for high speed
 * devices and its range must be from 1 to 16 units. This value is
 * used as th exponent for a 2 ^ (bInterval - 1). Ex: a Binterval
 * of 4 means a period of 8us (2 ^ (4-1)).
 *
 * The following values are defined after above convertion in terms
 * 125us units.
 */
#define	EHCI_INTR_1US_POLL		1	/* 1us poll interval */
#define	EHCI_INTR_2US_POLL		2	/* 2us poll interval */
#define	EHCI_INTR_4US_POLL		4	/* 4us poll interval */
#define	EHCI_INTR_XUS_POLL		8	/* 8us and above */

/*
 * The following indecies are are used to calculate Start and complete
 * masks as per the polling interval.
 */
#define	EHCI_1US_MASK_INDEX		14	/* 1us mask index */
#define	EHCI_2US_MASK_INDEX		12	/* 2us mask index */
#define	EHCI_4US_MASK_INDEX		8	/* 4us mask index */
#define	EHCI_XUS_MASK_INDEX		0	/* 8us and above */

/*
 * Different interrupt polling intervals supported for low/full/high
 * speed devices. For high speed devices, the following values are
 * applicable after convertion.
 */
#define	EHCI_INTR_1MS_POLL		1	/* 1ms poll interval */
#define	EHCI_INTR_2MS_POLL		2	/* 2ms poll interval */
#define	EHCI_INTR_4MS_POLL		4	/* 4ms poll interval */
#define	EHCI_INTR_8MS_POLL		8	/* 8ms poll interval */
#define	EHCI_INTR_16MS_POLL		16	/* 16ms poll interval */
#define	EHCI_INTR_32MS_POLL		32	/* 32ms poll interval */

/*
 * Number of interrupt transfer requests that should be maintained on
 * the interrupt endpoint corresponding to different polling intervals
 * supported.
 */
#define	EHCI_INTR_1MS_REQS		4	/* 1ms polling interval */
#define	EHCI_INTR_2MS_REQS		2	/* 2ms polling interval */
#define	EHCI_INTR_XMS_REQS		1	/* Between 4ms and 32ms */

/* Function prototype */
typedef void (*ehci_handler_function_t)(
	ehci_state_t			*ehcip,
	ehci_pipe_private_t		*pp,
	struct ehci_trans_wrapper	*tw,
	ehci_qtd_t			*qtd,
	void				*ehci_handle_callback_value);


/*
 * Transfer wrapper
 *
 * The transfer wrapper represents a USB transfer on the bus and there
 * is one instance per USB transfer.  A transfer is made up of one or
 * more transactions. EHCI uses one QTD for one transaction. So one
 * transfer wrapper may have one or more QTDs associated.
 *
 * The data to be transferred are contained in the TW buffer which is
 * virtually contiguous but physically discontiguous. When preparing
 * the QTDs for a USB transfer, the DMA cookies corresponding to the
 * TW buffer need to be walked through to retrieve the DMA addresses.
 *
 * Control and bulk pipes will have one transfer wrapper per transfer
 * and where as Isochronous and Interrupt pipes will only have one
 * transfer wrapper. The transfers wrapper are continually reused for
 * the Interrupt and Isochronous pipes as those pipes are polled.
 */
typedef struct ehci_trans_wrapper {
	struct ehci_trans_wrapper	*tw_next;	/* Next wrapper */
	ehci_pipe_private_t		*tw_pipe_private; /* Back ptr */
	ddi_dma_handle_t		tw_dmahandle;	/* DMA handle */
	ddi_acc_handle_t		tw_accesshandle; /* Acc hndle */
	ddi_dma_cookie_t		tw_cookie;	/* DMA cookie */
	uint_t				tw_ncookies;	/* DMA cookie count */
	uint_t				tw_cookie_idx;	/* DMA cookie index */
	size_t				tw_dma_offs;	/* DMA buffer offset */
	uint32_t			tw_id;		/* 32bit ID */
	size_t				tw_length;	/* Txfer length */
	char				*tw_buf;	/* Buffer for Xfer */
	usb_flags_t			tw_flags;	/* Flags */
	uint_t				tw_num_qtds;	/* Number of QTDs */
	ehci_qtd_t			*tw_qtd_head;	/* Head QTD */
	ehci_qtd_t			*tw_qtd_tail;	/* Tail QTD */
	uint_t				tw_direction;	/* Direction of QTD */

	/* Current transfer request pointer */
	usb_opaque_t			tw_curr_xfer_reqp;

	/* Transfer timeout information */
	int				tw_timeout;	/* Timeout value */
	struct ehci_trans_wrapper	*tw_timeout_next; /* Xfer Timeout Q */

	/*
	 * This is the function to call when this td is done. This way
	 * we don't have to look in the td to figure out what kind it is.
	 */
	ehci_handler_function_t		tw_handle_qtd;

	/*
	 * This is the callback value used when processing a done td.
	 */
	usb_opaque_t			tw_handle_callback_value;

	/* We preallocate all the td's for each tw and place them here */
	ehci_qtd_t			*tw_qtd_free_list;
	ehci_qtd_t			*tw_alt_qtd;
} ehci_trans_wrapper_t;

_NOTE(MUTEX_PROTECTS_DATA(ehci_state_t::ehci_int_mutex, ehci_trans_wrapper))

/*
 * Isochronous Transfer Wrapper
 *
 * This transfer wrapper is built specifically for the LOW/FULL/HIGH speed
 * isochronous transfers.  A transfer wrapper consists of one or more
 * transactionsl, but there is one one instance per USB transfer request.
 *
 * The isochrnous transfer wrapper are continiously reused because these
 * pipes are polled.
 */
typedef struct ehci_isoc_xwrapper {
	struct ehci_isoc_xwrapper	*itw_next;	/* Next wrapper in pp */
	ehci_pipe_private_t		*itw_pipe_private;

	/* DMA and memory pointers */
	ddi_dma_handle_t		itw_dmahandle;	/* DMA handle ETT */
	ddi_acc_handle_t		itw_accesshandle; /* Acc hndle */
	ddi_dma_cookie_t		itw_cookie;	/* DMA cookie */

	/* Transfer information */
	char				*itw_buf;	/* Buffer for Xfer */
	size_t				itw_length;	/* Txfer length */
	usb_flags_t			itw_flags;	/* Flags */
	usb_port_status_t		itw_port_status; /* Port Speed */
	uint_t				itw_direction;	/* Direction of ITD */

	/* ITD information */
	uint_t				itw_num_itds;	/* Number of ITDs */
	ehci_itd_t			*itw_itd_head;	/* Head ITD */
	ehci_itd_t			*itw_itd_tail;	/* Tail ITD */
	usb_isoc_req_t			*itw_curr_xfer_reqp;
	usb_isoc_pkt_descr_t		*itw_curr_isoc_pktp;

	/* We preallocate all the td's for each tw and place them here */
	ehci_itd_t			*itw_itd_free_list;

	/* Device and hub information needed by every iTD */
	uint_t				itw_hub_addr;
	uint_t				itw_hub_port;
	uint_t				itw_endpoint_num;
	uint_t				itw_device_addr;

	/*
	 * Callback handling function and arguement.  Called when an iTD is
	 * is done.
	 */
	usb_opaque_t			itw_handle_callback_value;

	/* 32bit ID */
	uint32_t			itw_id;
} ehci_isoc_xwrapper_t;

_NOTE(MUTEX_PROTECTS_DATA(ehci_state_t::ehci_int_mutex, ehci_isoc_xwrapper_t))

/*
 * Time waits for the different EHCI specific operations.
 * These timeout values are specified in terms of microseconds.
 */
#define	EHCI_RESET_TIMEWAIT	10000	/* HC reset waiting time */
#define	EHCI_TIMEWAIT		10000	/* HC any other waiting time */
#define	EHCI_SOF_TIMEWAIT	20000	/* SOF Wait time */
#define	EHCI_TAKEOVER_DELAY	10000	/* HC take over waiting time */
#define	EHCI_TAKEOVER_WAIT_COUNT	25	/* HC take over waiting count */

/* These timeout values are specified in seconds */
#define	EHCI_DEFAULT_XFER_TIMEOUT	5 /* Default transfer timeout */
#define	EHCI_XFER_CMPL_TIMEWAIT		3 /* Xfers completion timewait */

/* EHCI flags for general use */
#define	EHCI_FLAGS_NOSLEEP	0x000	/* Don't wait for SOF */
#define	EHCI_FLAGS_SLEEP	0x100	/* Wait for SOF */
#define	EHCI_FLAGS_DMA_SYNC	0x200	/* Call ddi_dma_sync */

/*
 * Maximum allowable data transfer  size per transaction as supported
 * by EHCI is 20k. (See EHCI Host Controller Interface Spec Rev 0.96)
 *
 * Also within QTD, there will be five buffer pointers abd each buffer
 * pointer can transfer upto 4k bytes of data.
 */
#define	EHCI_MAX_QTD_XFER_SIZE	0x5000	/* Maxmum data per transaction */
#define	EHCI_MAX_QTD_BUF_SIZE	0x1000	/* Maxmum data per buffer */

/*
 * The maximum allowable bulk data transfer size. It can be different
 * from EHCI_MAX_QTD_XFER_SIZE and if it is more then ehci driver will
 * take care of  breaking a bulk data request into  multiples of ehci
 * EHCI_MAX_QTD_XFER_SIZE  until request is satisfied.	Currently this
 * value is set to 640k bytes.
 */
#define	EHCI_MAX_BULK_XFER_SIZE	0xA0000	/* Maximum bulk transfer size */

/*
 * Timeout flags
 *
 * These flags will be used to stop the timer before timeout handler
 * gets executed.
 */
#define	EHCI_REMOVE_XFER_IFLAST	1	/* Stop the timer if it is last QTD */
#define	EHCI_REMOVE_XFER_ALWAYS	2	/* Stop the timer without condition */


/*
 * High speed bandwidth allocation
 *
 * The following definitions are used during bandwidth calculations
 * for a given high speed endpoint or high speed split transactions.
 */
#define	HS_BUS_BANDWIDTH	7500	/* Up to 7500 bytes per 125us */
#define	HS_MAX_POLL_INTERVAL	16	/* Max high speed polling interval */
#define	HS_MIN_POLL_INTERVAL	1	/* Min high speed polling interval */
#define	HS_SOF			12	/* Length in bytes of High speed SOF */
#define	HS_EOF			70	/* Length in bytes of High speed EOF */
#define	TREE_HEIGHT		5	/* Log base 2 of 32 */

/*
 * As per USB 2.0 specification section 5.5.4, 20% of bus time is reserved
 * for the non-periodic high-speed transfers. Where as peridoic high-speed
 * transfers will get 80% of the bus time. In one micro-frame or 125us, we
 * can transfer 7500 bytes or 60,000 bits.
 */
#define	HS_NON_PERIODIC_BANDWIDTH	1500
#define	HS_PERIODIC_BANDWIDTH		(HS_BUS_BANDWIDTH - HS_SOF - \
					HS_EOF - HS_NON_PERIODIC_BANDWIDTH)

/*
 * High speed periodic frame bandwidth will be eight times the micro frame
 * high speed periodic bandwidth.
 */
#define	HS_PERIODIC_FRAME_BANDWIDTH	HS_PERIODIC_BANDWIDTH * EHCI_MAX_UFRAMES

/*
 * The following are the protocol overheads in terms of Bytes for the
 * different transfer types.  All these protocol overhead  values are
 * derived from the 5.11.3 section of USB 2.0 Specification.
 */
#define	HS_NON_ISOC_PROTO_OVERHEAD	55
#define	HS_ISOC_PROTO_OVERHEAD		38

/*
 * The following are THE protocol overheads in terms of Bytes for the
 * start and complete split transactions tokens overheads.  All these
 * protocol overhead values are derived from the 8.4.2.2 and 8.4.2.3
 * of USB2.0 Specification.
 */
#define	START_SPLIT_OVERHEAD		04
#define	COMPLETE_SPLIT_OVERHEAD		04

/*
 * The Host Controller (HC) delays are the USB host controller specific
 * delays. The value shown below is the host  controller delay for  the
 * given EHCI host controller.
 */
#define	EHCI_HOST_CONTROLLER_DELAY	18

/*
 * Low/Full speed bandwidth allocation
 *
 * The following definitions are used during bandwidth calculations for
 * a given high speed hub or  a transaction translator	(TT) and  for a
 * given low/full speed device connected to high speed hub or TT  using
 * split transactions
 */
#define	FS_BUS_BANDWIDTH	1500	/* Up to 1500 bytes per 1ms */
#define	FS_MAX_POLL_INTERVAL	255	/* Max full speed poll interval */
#define	FS_MIN_POLL_INTERVAL	1	/* Min full speed polling interval */
#define	FS_SOF			6	/* Length in bytes of Full speed SOF */
#define	FS_EOF			4	/* Length in bytes of Full speed EOF */

/*
 * Minimum polling interval for low speed endpoint
 *
 * According USB 2.0 Specification, a full-speed endpoint can specify
 * a desired polling interval 1ms to 255ms and a low speed endpoints
 * are limited to specifying only 10ms to 255ms. But some old keyboards
 * and mice uses polling interval of 8ms. For compatibility purpose,
 * we are using polling interval between 8ms and 255ms for low speed
 * endpoints. The ehci driver will use 8ms polling interval if a low
 * speed device reports a polling interval that is less than 8ms.
 */
#define	LS_MAX_POLL_INTERVAL	255	/* Max low speed poll interval */
#define	LS_MIN_POLL_INTERVAL	8	/* Min low speed polling interval */

/*
 * For non-periodic transfers, reserve atleast for one low-speed device
 * transaction. According to USB Bandwidth Analysis white paper and also
 * as per OHCI Specification 1.0a, section 7.3.5, page 123, one low-speed
 * transaction takes 0x628h full speed bits (197 bytes), which comes to
 * around 13% of USB frame time.
 *
 * The periodic transfers will	get around 87% of USB frame time.
 */
#define	FS_NON_PERIODIC_BANDWIDTH	197
#define	FS_PERIODIC_BANDWIDTH		(FS_BUS_BANDWIDTH - FS_SOF - \
					FS_EOF - FS_NON_PERIODIC_BANDWIDTH)

/*
 * The following are the protocol overheads in terms of Bytes for the
 * different transfer types.  All these protocol overhead  values are
 * derived from the 5.11.3 section of USB Specification	and  with the
 * help of Bandwidth Analysis white paper which is posted on the  USB
 * developer forum.
 */
#define	FS_NON_ISOC_PROTO_OVERHEAD	14
#define	FS_ISOC_INPUT_PROTO_OVERHEAD	11
#define	FS_ISOC_OUTPUT_PROTO_OVERHEAD	10
#define	LOW_SPEED_PROTO_OVERHEAD	97
#define	HUB_LOW_SPEED_PROTO_OVERHEAD	01

/* The maximum amount of isoch data that can be transferred in one uFrame */
#define	MAX_UFRAME_SITD_XFER		188

/*
 * The low speed clock below represents that to transmit one low-speed
 * bit takes eight times more than one full speed bit time.
 */
#define	LOW_SPEED_CLOCK			8

/*
 * The Transaction Translator (TT) delay is the additional time needed
 * to execute low/full speed transaction from high speed split transaction
 * for the low/full device connected to the high speed extrenal hub.
 */
#define	TT_DELAY			18


/*
 * Macros for setting/getting information
 */
#define	Get_QH(addr)		ddi_get32(ehcip->ehci_qh_pool_mem_handle, \
					(uint32_t *)&addr)

#define	Set_QH(addr, val)	ddi_put32(ehcip->ehci_qh_pool_mem_handle,  \
					((uint32_t *)&addr), \
					((int32_t)(val)))

#define	Get_QTD(addr)		ddi_get32(ehcip->ehci_qtd_pool_mem_handle, \
					(uint32_t *)&addr)

#define	Set_QTD(addr, val)	ddi_put32(ehcip->ehci_qtd_pool_mem_handle, \
					((uint32_t *)&addr), \
					((int32_t)(val)))

#define	Get_ITD(addr)		ddi_get32(ehcip->ehci_itd_pool_mem_handle, \
					(uint32_t *)&addr)

#define	Set_ITD(addr, val)	ddi_put32(ehcip->ehci_itd_pool_mem_handle, \
					((uint32_t *)&addr), \
					((int32_t)(val)))

#define	Get_ITD_BODY(ptr, addr)		ddi_get32( \
					    ehcip->ehci_itd_pool_mem_handle, \
					    (uint32_t *)&ptr->itd_body[addr])

#define	Set_ITD_BODY(ptr, addr, val)	ddi_put32( \
					    ehcip->ehci_itd_pool_mem_handle, \
					    ((uint32_t *)&ptr->itd_body[addr]),\
					    ((int32_t)(val)))

#define	Get_ITD_INDEX(ptr, pos)		ddi_get32( \
					    ehcip->ehci_itd_pool_mem_handle, \
					    (uint32_t *)&ptr->itd_index[pos])

#define	Set_ITD_INDEX(ptr, pos, val)	ddi_put32( \
					    ehcip->ehci_itd_pool_mem_handle, \
					    ((uint32_t *)&ptr->itd_index[pos]),\
					    ((uint32_t)(val)))

#define	Get_ITD_FRAME(addr)		ddi_get64( \
					    ehcip->ehci_itd_pool_mem_handle, \
					    (uint64_t *)&addr)

#define	Set_ITD_FRAME(addr, val)	ddi_put64( \
					    ehcip->ehci_itd_pool_mem_handle, \
					    ((uint64_t *)&addr), \
					    (val))

#define	Get_PFLT(addr)		ddi_get32(ehcip->ehci_pflt_mem_handle, \
					(uint32_t *)&addr)

#define	Set_PFLT(addr, val)	ddi_put32(ehcip->ehci_pflt_mem_handle, \
					((uint32_t *)&addr), \
					((int32_t)(uintptr_t)(val)))

#define	Get_8Cap(addr)		ddi_get8(ehcip->ehci_caps_handle, \
					(uint8_t *)&ehcip->ehci_capsp->addr)

#define	Get_16Cap(addr)		ddi_get16(ehcip->ehci_caps_handle, \
					(uint16_t *)&ehcip->ehci_capsp->addr)

#define	Get_Cap(addr)		ddi_get32(ehcip->ehci_caps_handle, \
					(uint32_t *)&ehcip->ehci_capsp->addr)

#define	Get_OpReg(addr)		ddi_get32(ehcip->ehci_caps_handle, \
					(uint32_t *)&ehcip->ehci_regsp->addr)

#define	Set_OpReg(addr, val)	ddi_put32(ehcip->ehci_caps_handle, \
				((uint32_t *)&ehcip->ehci_regsp->addr), \
					((int32_t)(val)))

#define	CalculateITDMultiField(pkgSize)		(1 + (((pkgSize)>>11) & 0x03))

#define	EHCI_MAX_RETRY		10

#define	Set_OpRegRetry(addr, val, r) \
				while (Get_OpReg(addr) != val) { \
					if (r >= EHCI_MAX_RETRY) \
						break; \
					r++; \
					Set_OpReg(addr, val); \
				}

#define	Sync_QH_QTD_Pool(ehcip) (void) ddi_dma_sync( \
				ehcip->ehci_qh_pool_dma_handle, \
				0, EHCI_QH_POOL_SIZE * sizeof (ehci_qh_t), \
				DDI_DMA_SYNC_FORCPU); \
				(void) ddi_dma_sync( \
				ehcip->ehci_qtd_pool_dma_handle, \
				0, EHCI_QTD_POOL_SIZE * sizeof (ehci_qtd_t), \
				DDI_DMA_SYNC_FORCPU);

#define	Sync_ITD_Pool(ehcip) (void) ddi_dma_sync( \
				ehcip->ehci_itd_pool_dma_handle, \
				0, EHCI_ITD_POOL_SIZE * sizeof (ehci_itd_t), \
				DDI_DMA_SYNC_FORCPU);

#define	Sync_IO_Buffer(dma_handle, length) \
				(void) ddi_dma_sync(dma_handle, \
				0, length, DDI_DMA_SYNC_FORCPU);

#define	Sync_IO_Buffer_for_device(dma_handle, length) \
				(void) ddi_dma_sync(dma_handle, \
				0, length, DDI_DMA_SYNC_FORDEV);

/*
 * Macros to speed handling of 32bit IDs
 */
#define	EHCI_GET_ID(x)		id32_alloc((void *)(x), KM_SLEEP)
#define	EHCI_LOOKUP_ID(x)	id32_lookup((x))
#define	EHCI_FREE_ID(x)		id32_free((x))


/*
 * Miscellaneous definitions.
 */

/* Data toggle bits */
#define	DATA0		0
#define	DATA1		1

/* Halt bit actions */
#define	CLEAR_HALT	0
#define	SET_HALT	1

typedef uint_t		halt_bit_t;

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
#define	EHCI_ATTACH		0x01	/* ehci driver initilization */
#define	EHCI_ZALLOC		0x02	/* Memory for ehci state structure */
#define	EHCI_INTR		0x04	/* Interrupt handler registered */
#define	EHCI_USBAREG		0x08	/* USBA registered */
#define	EHCI_RHREG		0x10	/* Root hub driver loaded */

/*
 * This variable is used in the EHCI_FLAGS to tell the ISR to broadcase
 * the ehci_async_schedule_advance_cv when an intr occurs.  It is used to
 * make sure that EHCI is receiving interrupts.
 */
#define	EHCI_CV_INTR		0x20	/* Ask INTR to broadcast cv */

#define	EHCI_UNIT(dev)	(getminor((dev)) & ~HUBD_IS_ROOT_HUB)

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
#define	PRINT_MASK_DUMPING	0x00000100	/* Dump ehci info */
#define	PRINT_MASK_ALL		0xFFFFFFFF

#define	PCI_VENDOR_NVIDIA	0x10de		/* PCI Vendor-id NVIDIA */
#define	PCI_DEVICE_NVIDIA_CK804	0x5b
#define	PCI_DEVICE_NVIDIA_MCP04	0x3c
/*
 * workaround for ALI chips
 */
#define	PCI_VENDOR_ALI		0x10b9		/* PCI Vendor-id Acer */

/*
 * NEC on COMBO and Uli M1575 can support PM
 */
#define	PCI_VENDOR_NEC_COMBO	0x1033
#define	PCI_DEVICE_NEC_COMBO	0xe0
#define	PCI_VENDOR_ULi_M1575	0x10b9
#define	PCI_DEVICE_ULi_M1575	0x5239

/*
 * VIA chips have some problems, the workaround can ensure those chips
 * work reliably. Revisions >= 0x80 are part of a southbridge and appear
 * to be reliable.
 */
#define	PCI_VENDOR_VIA		0x1106		/* PCI Vendor-id VIA */
#define	PCI_VIA_REVISION_6212	0x80		/* VIA 6212 revision ID */

#define	EHCI_VIA_LOST_INTERRUPTS	0x01
#define	EHCI_VIA_ASYNC_SCHEDULE		0x02
#define	EHCI_VIA_REDUCED_MAX_BULK_XFER_SIZE	0x04

#define	EHCI_VIA_WORKAROUNDS \
	(EHCI_VIA_LOST_INTERRUPTS | \
	EHCI_VIA_ASYNC_SCHEDULE | \
	EHCI_VIA_REDUCED_MAX_BULK_XFER_SIZE)

#define	EHCI_VIA_MAX_BULK_XFER_SIZE 0x8000 /* Maximum bulk transfer size */


/*
 * EHCI HCDI entry points
 *
 * The Host Controller Driver Interfaces (HCDI) are the software interfaces
 * between the Universal Serial Bus Driver (USBA) and the Host	Controller
 * Driver (HCD). The HCDI interfaces or entry points are subject to change.
 */
int		ehci_hcdi_pipe_open(
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		usb_flags);
int		ehci_hcdi_pipe_close(
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		usb_flags);
int		ehci_hcdi_pipe_reset(
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		usb_flags);
void		ehci_hcdi_pipe_reset_data_toggle(
				usba_pipe_handle_data_t	*ph);
int		ehci_hcdi_pipe_ctrl_xfer(
				usba_pipe_handle_data_t	*ph,
				usb_ctrl_req_t		*ctrl_reqp,
				usb_flags_t		usb_flags);
int		ehci_hcdi_bulk_transfer_size(
				usba_device_t		*usba_device,
				size_t			*size);
int		ehci_hcdi_pipe_bulk_xfer(
				usba_pipe_handle_data_t	*ph,
				usb_bulk_req_t		*bulk_reqp,
				usb_flags_t		usb_flags);
int		ehci_hcdi_pipe_intr_xfer(
				usba_pipe_handle_data_t	*ph,
				usb_intr_req_t		*intr_req,
				usb_flags_t		usb_flags);
int		ehci_hcdi_pipe_stop_intr_polling(
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		usb_flags);
int		ehci_hcdi_get_current_frame_number(
				usba_device_t		*usba_device,
				usb_frame_number_t	*frame_number);
int		ehci_hcdi_get_max_isoc_pkts(
				usba_device_t		*usba_device,
				uint_t		*max_isoc_pkts_per_request);
int		ehci_hcdi_pipe_isoc_xfer(
				usba_pipe_handle_data_t	*ph,
				usb_isoc_req_t		*isoc_reqp,
				usb_flags_t		usb_flags);
int		ehci_hcdi_pipe_stop_isoc_polling(
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		usb_flags);

/*
 * EHCI Polled entry points function prototypes.
 */
int		ehci_hcdi_polled_input_init(
				usba_pipe_handle_data_t	*ph,
				uchar_t			**polled_buf,
				usb_console_info_impl_t	*info);
int		ehci_hcdi_polled_input_enter(
				usb_console_info_impl_t	*info);
int		ehci_hcdi_polled_read(
				usb_console_info_impl_t	*info,
				uint_t			*num_characters);
int		ehci_hcdi_polled_input_exit(
				usb_console_info_impl_t	*info);
int		ehci_hcdi_polled_input_fini(
				usb_console_info_impl_t	*info);
int		ehci_hcdi_polled_output_init(
				usba_pipe_handle_data_t	*ph,
				usb_console_info_impl_t	*console_output_info);
int		ehci_hcdi_polled_output_enter(
				usb_console_info_impl_t	*info);
int		ehci_hcdi_polled_write(
				usb_console_info_impl_t *info,
				uchar_t *buf,
				uint_t num_characters,
				uint_t *num_characters_written);
int		ehci_hcdi_polled_output_exit(
				usb_console_info_impl_t	*info);
int		ehci_hcdi_polled_output_fini(
				usb_console_info_impl_t *info);
/*
 * EHCI Root Hub entry points function prototypes.
 */
int		ehci_init_root_hub(
				ehci_state_t		*ehcip);
int		ehci_load_root_hub_driver(
				ehci_state_t		*ehcip);
int		ehci_unload_root_hub_driver(
				ehci_state_t		*ehcip);
int		ehci_handle_root_hub_pipe_open(
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		flags);
int		ehci_handle_root_hub_pipe_close(
				usba_pipe_handle_data_t	*ph);
int		ehci_handle_root_hub_pipe_reset(
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		flags);
int		ehci_handle_root_hub_request(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				usb_ctrl_req_t		*ctrl_reqp);
int		ehci_handle_root_hub_pipe_start_intr_polling(
				usba_pipe_handle_data_t	*ph,
				usb_intr_req_t		*intr_reqp,
				usb_flags_t		flags);
void		ehci_handle_root_hub_pipe_stop_intr_polling(
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		flags);

/*
 * EHCI Interrupt Handler entry point.
 */
uint_t		ehci_intr(caddr_t			arg1,
				caddr_t			arg2);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_EHCID_H */
