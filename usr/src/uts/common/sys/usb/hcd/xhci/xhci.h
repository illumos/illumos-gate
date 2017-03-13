/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

#ifndef _SYS_USB_XHCI_XHCI_H
#define	_SYS_USB_XHCI_XHCI_H

/*
 * Extensible Host Controller Interface (xHCI) USB Driver
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/taskq_impl.h>
#include <sys/sysmacros.h>
#include <sys/usb/hcd/xhci/xhcireg.h>

#include <sys/usb/usba.h>
#include <sys/usb/usba/hcdi.h>
#include <sys/usb/hubd/hub.h>
#include <sys/usb/usba/hubdi.h>
#include <sys/usb/hubd/hubdvar.h>


#ifdef __cplusplus
extern "C" {
#endif

/*
 * The base segment for DMA attributes was determined to be 4k based on xHCI 1.1
 * / table 54: Data Structure Max Size, Boundary, and Alignment Requirement
 * Summary.  This indicates that the required alignment for most things is
 * PAGESIZE, which in our current implementation is required to be 4K. We
 * provide the ring segment value below for the things which need 64K alignment
 *
 * Similarly, in the same table, the maximum required alignment is 64 bytes,
 * hence we use that for everything.
 *
 * Next is the scatter/gather lengths. For most of the data structures, we only
 * want to have a single SGL entry, e.g. just a simple flat mapping. For many of
 * our transfers, we use the same logic to simplify the implementation of the
 * driver. However, for bulk transfers, which are the largest by far, we want to
 * be able to leverage SGLs to give us more DMA flexibility.
 *
 * We can transfer up to 64K in one transfer request block (TRB) which
 * corresponds to a single SGL entry. Each ring we create is a single page in
 * size and will support at most 256 TRBs. We've selected to use up to 8 SGLs
 * for these transfer cases. This allows us to put up to 512 KiB in a given
 * transfer request and in the worst case, we can have about 30 of them
 * outstanding. Experimentally, this has proven to be sufficient for most of the
 * drivers that we support today.
 */
#define	XHCI_TRB_MAX_TRANSFER	65536
#define	XHCI_DMA_ALIGN		64
#define	XHCI_DEF_DMA_SGL	1
#define	XHCI_TRANSFER_DMA_SGL	8
#define	XHCI_MAX_TRANSFER	(XHCI_TRB_MAX_TRANSFER * XHCI_TRANSFER_DMA_SGL)
#define	XHCI_DMA_STRUCT_SIZE	4096

/*
 * Properties and values for rerouting ehci ports to xhci.
 */
#define	XHCI_PROP_REROUTE_DISABLE	0
#define	XHCI_PROP_REROUTE_DEFAULT	1

/*
 * This number is a bit made up. Truthfully, the API here isn't the most useful
 * for what we need to define as it should really be based on the endpoint that
 * we're interested in rather than the device as a whole.
 *
 * We're basically being asked how many TRBs we're willing to schedule in one
 * go. There's no great way to come up with this number, so we basically are
 * making up something such that we use up a good portion of a ring, but not too
 * much of it.
 */
#define	XHCI_ISOC_MAX_TRB	64

#ifdef	DEBUG
#define	XHCI_DMA_SYNC(dma, flag)	VERIFY0(ddi_dma_sync( \
					    (dma).xdb_dma_handle, 0, 0, \
					    (flag)))
#else
#define	XHCI_DMA_SYNC(dma, flag)	((void) ddi_dma_sync( \
					    (dma).xdb_dma_handle, 0, 0, \
					    (flag)))
#endif

/*
 * This defines a time in 2-ms ticks that is required to wait for the controller
 * to be ready to go. Section 5.4.8 of the XHCI specification in the description
 * of the PORTSC register indicates that the upper bound is 20 ms. Therefore the
 * number of ticks is 10.
 */
#define	XHCI_POWER_GOOD	10

/*
 * Definitions to determine the default number of interrupts. Note that we only
 * bother with a single interrupt at this time, though we've arranged the driver
 * to make it possible to request more if, for some unlikely reason, it becomes
 * necessary.
 */
#define	XHCI_NINTR	1

/*
 * Default interrupt modulation value. This enables us to have 4000 interrupts /
 * second. This is supposed to be the default value of the controller. See xHCI
 * 1.1 / 4.17.2 for more information.
 */
#define	XHCI_IMOD_DEFAULT 	0x000003F8U

/*
 * Definitions that surround the default values used in various contexts. These
 * come from various parts of the xHCI specification. In general, see xHCI 1.1 /
 * 4.8.2. Note that the MPS_MASK is used for ISOCH and INTR endpoints which have
 * different sizes.
 *
 * The burst member is a bit more complicated. By default for USB 2 devices, it
 * only matters for ISOCH and INTR endpoints and so we use the macros below to
 * pull it out of the endpoint description's max packet field. For USB 3, it
 * matters for non-control endpoints. However, it comes out of a companion
 * description.
 *
 * By default the mult member is zero for all cases except for super speed
 * ISOCH endpoints, where it comes from the companion descriptor.
 */
#define	XHCI_CONTEXT_DEF_CERR		3
#define	XHCI_CONTEXT_ISOCH_CERR		0
#define	XHCI_CONTEXT_MPS_MASK		0x07ff
#define	XHCI_CONTEXT_BURST_MASK		0x1800
#define	XHCI_CONTEXT_BURST_SHIFT	11
#define	XHCI_CONTEXT_DEF_MULT		0
#define	XHCI_CONTEXT_DEF_MAX_ESIT	0
#define	XHCI_CONTEXT_DEF_CTRL_ATL	8

/*
 * This number represents the number of transfers that we'll set up for a given
 * interrupt transfer. Note that the idea here is that we'll want to allocate a
 * certain number of transfers to basically ensure that we'll always be able to
 * have a transfer available, even if the system is a bit caught up in trying to
 * process it and for some reason we can't fire the interrupt. As such, we
 * basically want to have enough available that at the fastest interval (125 us)
 * that we have enough. So in this case we choose 8, with the assumption that we
 * should be able to process at least one in a given millisecond. Note that this
 * is not based in fact and is really just as much a guess and a hope.
 *
 * While we could then use less resources for other interrupt transfers that are
 * slower, starting with uniform resource usage will make things a bit easier.
 */
#define	XHCI_INTR_IN_NTRANSFERS	8

/*
 * This number represents the number of xhci_transfer_t structures that we'll
 * set up for a given isochronous transfer polling request. A given isochronous
 * transfer may actually have multiple units of time associated with it. As
 * such, we basically want to treat this like a case of classic double
 * buffering. We have one ready to go while the other is being filled up. This
 * will compensate for additional latency in the system. This is smaller than
 * the Interrupt IN transfer case above as many callers may ask for multiple
 * intervals in a single request.
 */
#define	XHCI_ISOC_IN_NTRANSFERS	2

#define	XHCI_PERIODIC_IN_NTRANSFERS					\
	MAX(XHCI_ISOC_IN_NTRANSFERS, XHCI_INTR_IN_NTRANSFERS)

/*
 * Mask for a route string which is a 20-bit value.
 */
#define	XHCI_ROUTE_MASK(x)	((x) & 0xfffff)

/*
 * This is the default tick that we use for timeouts while endpoints have
 * outstanding, active, non-periodic transfers. We choose one second as the USBA
 * specifies timeouts in units of seconds. Note that this is in microseconds, so
 * it can be fed into drv_usectohz().
 */
#define	XHCI_TICK_TIMEOUT_US	(MICROSEC)

/*
 * Set of bits that we need one of to indicate that this port has something
 * interesting on it.
 */
#define	XHCI_HUB_INTR_CHANGE_MASK	(XHCI_PS_CSC | XHCI_PS_PEC | \
    XHCI_PS_WRC | XHCI_PS_OCC | XHCI_PS_PRC | XHCI_PS_PLC | XHCI_PS_CEC)

/*
 * These represent known issues with various xHCI controllers.
 *
 * 	XHCI_QUIRK_NO_MSI	MSI support on this controller is known to be
 * 				broken.
 *
 * 	XHCI_QUIRK_32_ONLY	Only use 32-bit DMA addreses with this
 * 				controller.
 *
 * 	XHCI_QUIRK_INTC_EHCI	This is an Intel platform which supports
 * 				rerouting ports between EHCI and xHCI
 * 				controllers on the platform.
 */
typedef enum xhci_quirk {
	XHCI_QUIRK_NO_MSI	= 0x01,
	XHCI_QUIRK_32_ONLY	= 0x02,
	XHCI_QUIRK_INTC_EHCI	= 0x04
} xhci_quirk_t;

/*
 * xHCI capability parameter flags. These are documented in xHCI 1.1 / 5.3.6.
 */
typedef enum xhci_cap_flags {
	XCAP_AC64 	= 0x001,
	XCAP_BNC	= 0x002,
	XCAP_CSZ	= 0x004,
	XCAP_PPC	= 0x008,
	XCAP_PIND	= 0x010,
	XCAP_LHRC	= 0x020,
	XCAP_LTC	= 0x040,
	XCAP_NSS	= 0x080,
	XCAP_PAE	= 0x100,
	XCAP_SPC	= 0x200,
	XCAP_SEC	= 0x400,
	XCAP_CFC	= 0x800
} xchi_cap_flags_t;

/*
 * Second set of capabilities, these are documented in xHCI 1.1 / 5.3.9.
 */
typedef enum xhci_cap2_flags {
	XCAP2_U3C	= 0x01,
	XCAP2_CMC	= 0x02,
	XCAP2_FMC	= 0x04,
	XCAP2_CTC	= 0x08,
	XCAP2_LEC	= 0x10,
	XCAP2_CIC	= 0x20
} xhci_cap2_flags_t;

/*
 * These represent and store the various capability registers that we'll need to
 * use. In addition, we stash a few other versioning related bits here. Note
 * that we cache more information than we might need so that we have it for
 * debugging purposes.
 */
typedef struct xhci_capability {
	uint8_t			xcap_usb_vers;
	uint16_t		xcap_hci_vers;
	uint32_t		xcap_pagesize;
	uint8_t			xcap_max_slots;
	uint16_t		xcap_max_intrs;
	uint8_t			xcap_max_ports;
	boolean_t		xcap_ist_micro;
	uint8_t			xcap_ist;
	uint16_t		xcap_max_esrt;
	boolean_t		xcap_scratch_restore;
	uint16_t		xcap_max_scratch;
	uint8_t			xcap_u1_lat;
	uint16_t		xcap_u2_lat;
	xchi_cap_flags_t	xcap_flags;
	uint8_t			xcap_max_psa;
	uint16_t		xcap_xecp_off;
	xhci_cap2_flags_t	xcap_flags2;
	int			xcap_intr_types;
} xhci_capability_t;

/*
 * This represents a single logical DMA allocation. For the vast majority of
 * non-transfer cases, it only represents a single DMA buffer and not a
 * scatter-gather list.
 */
typedef struct xhci_dma_buffer {
	caddr_t			xdb_va;		/* Buffer VA */
	size_t			xdb_len;	/* Buffer logical len */
	ddi_acc_handle_t	xdb_acc_handle;	/* Access handle */
	ddi_dma_handle_t	xdb_dma_handle;	/* DMA handle */
	int			xdb_ncookies;	/* Number of actual cookies */
	ddi_dma_cookie_t	xdb_cookies[XHCI_TRANSFER_DMA_SGL];
} xhci_dma_buffer_t;

/*
 * This is a single transfer descriptor. It's packed to match the hardware
 * layout.
 */
#pragma pack(1)
typedef struct xhci_trb {
	uint64_t	trb_addr;
	uint32_t	trb_status;
	uint32_t	trb_flags;
} xhci_trb_t;
#pragma pack()

/*
 * This represents a single transfer that we want to allocate and perform.
 */
typedef struct xhci_transfer {
	list_node_t		xt_link;
	hrtime_t		xt_sched_time;
	xhci_dma_buffer_t	xt_buffer;
	uint_t			xt_ntrbs;
	uint_t			xt_short;
	uint_t			xt_timeout;
	usb_cr_t		xt_cr;
	boolean_t		xt_data_tohost;
	xhci_trb_t		*xt_trbs;
	usb_isoc_pkt_descr_t	*xt_isoc;
	usb_opaque_t		xt_usba_req;
} xhci_transfer_t;

/*
 * This represents a ring in xHCI, upon which event, transfer, and command TRBs
 * are scheduled.
 */
typedef struct xhci_ring {
	xhci_dma_buffer_t	xr_dma;
	uint_t			xr_ntrb;
	xhci_trb_t		*xr_trb;
	uint_t			xr_head;
	uint_t			xr_tail;
	uint8_t			xr_cycle;
} xhci_ring_t;

/*
 * This structure is used to represent the xHCI Device Context Base Address
 * Array. It's defined in section 6.1 of the specification and is required for
 * the controller to start.
 *
 * The maximum number of slots supported is always 256, therefore we size this
 * structure at its maximum.
 */
#define	XHCI_MAX_SLOTS	256
#define	XHCI_DCBAA_SCRATCHPAD_INDEX	0

typedef struct xhci_dcbaa {
	uint64_t		*xdc_base_addrs;
	xhci_dma_buffer_t	xdc_dma;
} xhci_dcbaa_t;

typedef struct xhci_scratchpad {
	uint64_t		*xsp_addrs;
	xhci_dma_buffer_t	xsp_addr_dma;
	xhci_dma_buffer_t	*xsp_scratch_dma;
} xhci_scratchpad_t;

/*
 * Contexts. These structures are inserted into the DCBAA above and are used for
 * describing the state of the system. Note, that while many of these are
 * 32-bytes in size, the xHCI specification defines that they'll be extended to
 * 64-bytes with all the extra bytes as zeros if the CSZ flag is set in the
 * HCCPARAMS1 register, e.g. we have the flag XCAP_CSZ set.
 *
 * The device context covers the slot context and 31 endpoints.
 */
#define	XHCI_DEVICE_CONTEXT_32	1024
#define	XHCI_DEVICE_CONTEXT_64	2048
#define	XHCI_NUM_ENDPOINTS	31
#define	XHCI_DEFAULT_ENDPOINT	0

#pragma pack(1)
typedef struct xhci_slot_context {
	uint32_t	xsc_info;
	uint32_t	xsc_info2;
	uint32_t	xsc_tt;
	uint32_t	xsc_state;
	uint32_t	xsc_reserved[4];
} xhci_slot_context_t;

typedef struct xhci_endpoint_context {
	uint32_t	xec_info;
	uint32_t	xec_info2;
	uint64_t	xec_dequeue;
	uint32_t	xec_txinfo;
	uint32_t	xec_reserved[3];
} xhci_endpoint_context_t;

typedef struct xhci_input_context {
	uint32_t	xic_drop_flags;
	uint32_t	xic_add_flags;
	uint32_t	xic_reserved[6];
} xhci_input_context_t;
#pragma pack()

/*
 * Definitions and structures for maintaining the event ring.
 */
#define	XHCI_EVENT_NSEGS	1

#pragma pack(1)
typedef struct xhci_event_segment {
	uint64_t	xes_addr;
	uint16_t	xes_size;
	uint16_t	xes_rsvd0;
	uint32_t	xes_rsvd1;
} xhci_event_segment_t;
#pragma pack()

typedef struct xhci_event_ring {
	xhci_event_segment_t	*xev_segs;
	xhci_dma_buffer_t	xev_dma;
	xhci_ring_t		xev_ring;
} xhci_event_ring_t;

typedef enum xhci_command_ring_state {
	XHCI_COMMAND_RING_IDLE		= 0x00,
	XHCI_COMMAND_RING_RUNNING	= 0x01,
	XHCI_COMMAND_RING_ABORTING	= 0x02,
	XHCI_COMMAND_RING_ABORT_DONE	= 0x03
} xhci_command_ring_state_t;

typedef struct xhci_command_ring {
	xhci_ring_t			xcr_ring;
	kmutex_t			xcr_lock;
	kcondvar_t			xcr_cv;
	list_t				xcr_commands;
	timeout_id_t			xcr_timeout;
	xhci_command_ring_state_t	xcr_state;
} xhci_command_ring_t;

/*
 * Individual command states.
 *
 * XHCI_COMMAND_S_INIT		The command has yet to be inserted into the
 * 				command ring.
 *
 * XHCI_COMMAND_S_QUEUED	The command is queued in the command ring.
 *
 * XHCI_COMMAND_S_RECEIVED	A command completion for this was received.
 *
 * XHCI_COMMAND_S_DONE		The command has been executed. Note that it may
 * 				have been aborted.
 *
 * XHCI_COMMAND_S_RESET		The ring is being reset due to a fatal error and
 * 				this command has been removed from the ring.
 * 				This means it has been aborted, but it was not
 * 				the cause of the abort.
 *
 * Note, when adding states, anything after XHCI_COMMAND_S_DONE implies that
 * upon reaching this state, it is no longer in the ring.
 */
typedef enum xhci_command_state {
	XHCI_COMMAND_S_INIT	= 0x00,
	XHCI_COMMAND_S_QUEUED	= 0x01,
	XHCI_COMMAND_S_RECEIVED = 0x02,
	XHCI_COMMAND_S_DONE	= 0x03,
	XHCI_COMMAND_S_RESET	= 0x04
} xhci_command_state_t;

/*
 * The TRB contents here are always kept in host byte order and are transformed
 * to little endian when actually scheduled on the ring.
 */
typedef struct xhci_command {
	list_node_t		xco_link;
	kcondvar_t		xco_cv;
	xhci_trb_t		xco_req;
	xhci_trb_t		xco_res;
	xhci_command_state_t	xco_state;
} xhci_command_t;

typedef enum xhci_endpoint_state {
	XHCI_ENDPOINT_PERIODIC		= 0x01,
	XHCI_ENDPOINT_HALTED		= 0x02,
	XHCI_ENDPOINT_QUIESCE		= 0x04,
	XHCI_ENDPOINT_TIMED_OUT		= 0x08,
	/*
	 * This is a composite of states that we need to watch for. We don't
	 * want to allow ourselves to set one of these flags while one of them
	 * is currently active.
	 */
	XHCI_ENDPOINT_SERIALIZE		= 0x0c,
	/*
	 * This is a composite of states that we need to make sure that if set,
	 * we do not schedule activity on the ring.
	 */
	XHCI_ENDPOINT_DONT_SCHEDULE	= 0x0e,
	/*
	 * This enpdoint is being torn down and should make sure it de-schedules
	 * itself.
	 */
	XHCI_ENDPOINT_TEARDOWN		= 0x10
} xhci_endpoint_state_t;

/*
 * Forwards required for the endpoint
 */
struct xhci_device;
struct xhci;

typedef struct xhci_endpoint {
	struct xhci		*xep_xhci;
	struct xhci_device	*xep_xd;
	uint_t			xep_num;
	uint_t			xep_type;
	xhci_endpoint_state_t	xep_state;
	kcondvar_t		xep_state_cv;
	timeout_id_t		xep_timeout;
	list_t			xep_transfers;
	usba_pipe_handle_data_t	*xep_pipe;
	xhci_ring_t		xep_ring;
} xhci_endpoint_t;

typedef struct xhci_device {
	list_node_t		xd_link;
	usb_port_t		xd_port;
	uint8_t			xd_slot;
	boolean_t		xd_addressed;
	usba_device_t		*xd_usbdev;
	xhci_dma_buffer_t	xd_ictx;
	kmutex_t		xd_imtx;	/* Protects input contexts */
	xhci_input_context_t	*xd_input;
	xhci_slot_context_t	*xd_slotin;
	xhci_endpoint_context_t	*xd_endin[XHCI_NUM_ENDPOINTS];
	xhci_dma_buffer_t	xd_octx;
	xhci_slot_context_t	*xd_slotout;
	xhci_endpoint_context_t	*xd_endout[XHCI_NUM_ENDPOINTS];
	xhci_endpoint_t		*xd_endpoints[XHCI_NUM_ENDPOINTS];
} xhci_device_t;

typedef enum xhci_periodic_state {
	XHCI_PERIODIC_POLL_IDLE	= 0x0,
	XHCI_PERIODIC_POLL_ACTIVE,
	XHCI_PERIODIC_POLL_NOMEM,
	XHCI_PERIODIC_POLL_STOPPING
} xhci_periodic_state_t;

typedef struct xhci_periodic_pipe {
	xhci_periodic_state_t	xpp_poll_state;
	usb_opaque_t		xpp_usb_req;
	size_t			xpp_tsize;
	uint_t			xpp_ntransfers;
	xhci_transfer_t		*xpp_transfers[XHCI_PERIODIC_IN_NTRANSFERS];
} xhci_periodic_pipe_t;

typedef struct xhci_pipe {
	list_node_t		xp_link;
	hrtime_t		xp_opentime;
	usba_pipe_handle_data_t	*xp_pipe;
	xhci_endpoint_t		*xp_ep;
	xhci_periodic_pipe_t	xp_periodic;
} xhci_pipe_t;

typedef struct xhci_usba {
	usba_hcdi_ops_t		*xa_ops;
	ddi_dma_attr_t		xa_dma_attr;
	usb_dev_descr_t		xa_dev_descr;
	usb_ss_hub_descr_t	xa_hub_descr;
	usba_pipe_handle_data_t	*xa_intr_cb_ph;
	usb_intr_req_t		*xa_intr_cb_req;
	list_t			xa_devices;
	list_t			xa_pipes;
} xhci_usba_t;

typedef enum xhci_attach_seq {
	XHCI_ATTACH_FM		= 0x1 << 0,
	XHCI_ATTACH_PCI_CONFIG	= 0x1 << 1,
	XHCI_ATTACH_REGS_MAP	= 0x1 << 2,
	XHCI_ATTACH_INTR_ALLOC	= 0x1 << 3,
	XHCI_ATTACH_INTR_ADD	= 0x1 << 4,
	XHCI_ATTACH_SYNCH	= 0x1 << 5,
	XHCI_ATTACH_INTR_ENABLE	= 0x1 << 6,
	XHCI_ATTACH_STARTED	= 0x1 << 7,
	XHCI_ATTACH_USBA	= 0x1 << 8,
	XHCI_ATTACH_ROOT_HUB	= 0x1 << 9
} xhci_attach_seq_t;

typedef enum xhci_state_flags {
	XHCI_S_ERROR		= 0x1 << 0
} xhci_state_flags_t;

typedef struct xhci {
	dev_info_t		*xhci_dip;
	xhci_attach_seq_t	xhci_seq;
	int			xhci_fm_caps;
	ddi_acc_handle_t	xhci_cfg_handle;
	uint16_t		xhci_vendor_id;
	uint16_t		xhci_device_id;
	caddr_t			xhci_regs_base;
	ddi_acc_handle_t	xhci_regs_handle;
	uint_t			xhci_regs_capoff;
	uint_t			xhci_regs_operoff;
	uint_t			xhci_regs_runoff;
	uint_t			xhci_regs_dooroff;
	xhci_capability_t	xhci_caps;
	xhci_quirk_t		xhci_quirks;
	ddi_intr_handle_t	xhci_intr_hdl;
	int			xhci_intr_num;
	int			xhci_intr_type;
	uint_t			xhci_intr_pri;
	int			xhci_intr_caps;
	xhci_dcbaa_t		xhci_dcbaa;
	xhci_scratchpad_t	xhci_scratchpad;
	xhci_command_ring_t	xhci_command;
	xhci_event_ring_t	xhci_event;
	taskq_ent_t		xhci_tqe;
	kmutex_t		xhci_lock;
	kcondvar_t		xhci_statecv;
	xhci_state_flags_t	xhci_state;
	xhci_usba_t		xhci_usba;
} xhci_t;

/*
 * The xHCI memory mapped registers come in four different categories. The
 * offset to them is variable. These represent the given register set that we're
 * after.
 */
typedef enum xhci_reg_type {
	XHCI_R_CAP,
	XHCI_R_OPER,
	XHCI_R_RUN,
	XHCI_R_DOOR
} xhci_reg_type_t;

/*
 * Quirks related functions
 */
extern void xhci_quirks_populate(xhci_t *);
extern void xhci_reroute_intel(xhci_t *);

/*
 * Interrupt related functions
 */
extern uint_t xhci_intr(caddr_t, caddr_t);
extern boolean_t xhci_ddi_intr_disable(xhci_t *);
extern boolean_t xhci_ddi_intr_enable(xhci_t *);
extern int xhci_intr_conf(xhci_t *);

/*
 * DMA related functions
 */
extern int xhci_check_dma_handle(xhci_t *, xhci_dma_buffer_t *);
extern void xhci_dma_acc_attr(xhci_t *, ddi_device_acc_attr_t *);
extern void xhci_dma_dma_attr(xhci_t *, ddi_dma_attr_t *);
extern void xhci_dma_scratchpad_attr(xhci_t *, ddi_dma_attr_t *);
extern void xhci_dma_transfer_attr(xhci_t *, ddi_dma_attr_t *, uint_t);
extern void xhci_dma_free(xhci_dma_buffer_t *);
extern boolean_t xhci_dma_alloc(xhci_t *, xhci_dma_buffer_t *, ddi_dma_attr_t *,
    ddi_device_acc_attr_t *, boolean_t, size_t, boolean_t);
extern uint64_t xhci_dma_pa(xhci_dma_buffer_t *);

/*
 * DMA Transfer Ring functions
 */
extern xhci_transfer_t *xhci_transfer_alloc(xhci_t *, xhci_endpoint_t *, size_t,
    int, int);
extern void xhci_transfer_free(xhci_t *, xhci_transfer_t *);
extern void xhci_transfer_copy(xhci_transfer_t *, void *, size_t, boolean_t);
extern int xhci_transfer_sync(xhci_t *, xhci_transfer_t *, uint_t);
extern void xhci_transfer_trb_fill_data(xhci_endpoint_t *, xhci_transfer_t *,
    int, boolean_t);
extern void xhci_transfer_calculate_isoc(xhci_device_t *, xhci_endpoint_t *,
    uint_t, uint_t *, uint_t *);

/*
 * Context (DCBAA, Scratchpad, Slot) functions
 */
extern int xhci_context_init(xhci_t *);
extern void xhci_context_fini(xhci_t *);
extern boolean_t xhci_context_slot_output_init(xhci_t *, xhci_device_t *);
extern void xhci_context_slot_output_fini(xhci_t *, xhci_device_t *);

/*
 * Command Ring Functions
 */
extern int xhci_command_ring_init(xhci_t *);
extern void xhci_command_ring_fini(xhci_t *);
extern boolean_t xhci_command_event_callback(xhci_t *, xhci_trb_t *trb);

extern void xhci_command_init(xhci_command_t *);
extern void xhci_command_fini(xhci_command_t *);

extern int xhci_command_enable_slot(xhci_t *, uint8_t *);
extern int xhci_command_disable_slot(xhci_t *, uint8_t);
extern int xhci_command_set_address(xhci_t *, xhci_device_t *, boolean_t);
extern int xhci_command_configure_endpoint(xhci_t *, xhci_device_t *);
extern int xhci_command_evaluate_context(xhci_t *, xhci_device_t *);
extern int xhci_command_reset_endpoint(xhci_t *, xhci_device_t *,
    xhci_endpoint_t *);
extern int xhci_command_set_tr_dequeue(xhci_t *, xhci_device_t *,
    xhci_endpoint_t *);
extern int xhci_command_stop_endpoint(xhci_t *, xhci_device_t *,
    xhci_endpoint_t *);

/*
 * Event Ring Functions
 */
extern int xhci_event_init(xhci_t *);
extern void xhci_event_fini(xhci_t *);
extern boolean_t xhci_event_process(xhci_t *);

/*
 * General Ring functions
 */
extern void xhci_ring_free(xhci_ring_t *);
extern int xhci_ring_reset(xhci_t *, xhci_ring_t *);
extern int xhci_ring_alloc(xhci_t *, xhci_ring_t *);

/*
 * Event Ring (Consumer) oriented functions.
 */
extern xhci_trb_t *xhci_ring_event_advance(xhci_ring_t *);


/*
 * Command and Transfer Ring (Producer) oriented functions.
 */
extern boolean_t xhci_ring_trb_tail_valid(xhci_ring_t *, uint64_t);
extern int xhci_ring_trb_valid_range(xhci_ring_t *, uint64_t, uint_t);

extern boolean_t xhci_ring_trb_space(xhci_ring_t *, uint_t);
extern void xhci_ring_trb_fill(xhci_ring_t *, uint_t, xhci_trb_t *, boolean_t);
extern void xhci_ring_trb_produce(xhci_ring_t *, uint_t);
extern boolean_t xhci_ring_trb_consumed(xhci_ring_t *, uint64_t);
extern void xhci_ring_trb_put(xhci_ring_t *, xhci_trb_t *);
extern void xhci_ring_skip(xhci_ring_t *);
extern void xhci_ring_skip_transfer(xhci_ring_t *, xhci_transfer_t *);

/*
 * MMIO related functions. Note callers are responsible for checking with FM
 * after accessing registers.
 */
extern int xhci_check_regs_acc(xhci_t *);

extern uint8_t xhci_get8(xhci_t *, xhci_reg_type_t, uintptr_t);
extern uint16_t xhci_get16(xhci_t *, xhci_reg_type_t, uintptr_t);
extern uint32_t xhci_get32(xhci_t *, xhci_reg_type_t, uintptr_t);
extern uint64_t xhci_get64(xhci_t *, xhci_reg_type_t, uintptr_t);

extern void xhci_put8(xhci_t *, xhci_reg_type_t, uintptr_t, uint8_t);
extern void xhci_put16(xhci_t *, xhci_reg_type_t, uintptr_t, uint16_t);
extern void xhci_put32(xhci_t *, xhci_reg_type_t, uintptr_t, uint32_t);
extern void xhci_put64(xhci_t *, xhci_reg_type_t, uintptr_t, uint64_t);

/*
 * Runtime FM related functions
 */
extern void xhci_fm_runtime_reset(xhci_t *);

/*
 * Endpoint related functions
 */
extern int xhci_endpoint_init(xhci_t *, xhci_device_t *,
    usba_pipe_handle_data_t *);
extern void xhci_endpoint_fini(xhci_device_t *, int);
extern int xhci_endpoint_update_default(xhci_t *, xhci_device_t *,
    xhci_endpoint_t *);

extern int xhci_endpoint_setup_default_context(xhci_t *, xhci_device_t *,
    xhci_endpoint_t *);

extern uint_t xhci_endpoint_pipe_to_epid(usba_pipe_handle_data_t *);
extern boolean_t xhci_endpoint_is_periodic_in(xhci_endpoint_t *);

extern int xhci_endpoint_quiesce(xhci_t *, xhci_device_t *, xhci_endpoint_t *);
extern int xhci_endpoint_schedule(xhci_t *, xhci_device_t *, xhci_endpoint_t *,
    xhci_transfer_t *, boolean_t);
extern int xhci_endpoint_ring(xhci_t *, xhci_device_t *, xhci_endpoint_t *);
extern boolean_t xhci_endpoint_transfer_callback(xhci_t *, xhci_trb_t *);

/*
 * USB Framework related functions
 */
extern int xhci_hcd_init(xhci_t *);
extern void xhci_hcd_fini(xhci_t *);

/*
 * Root hub related functions
 */
extern int xhci_root_hub_init(xhci_t *);
extern int xhci_root_hub_fini(xhci_t *);
extern int xhci_root_hub_ctrl_req(xhci_t *, usba_pipe_handle_data_t *,
    usb_ctrl_req_t *);
extern void xhci_root_hub_psc_callback(xhci_t *);
extern int xhci_root_hub_intr_root_enable(xhci_t *, usba_pipe_handle_data_t *,
    usb_intr_req_t *);
extern void xhci_root_hub_intr_root_disable(xhci_t *);

/*
 * Logging functions
 */
extern void xhci_log(xhci_t *xhcip, const char *fmt, ...) __KPRINTFLIKE(2);
extern void xhci_error(xhci_t *xhcip, const char *fmt, ...) __KPRINTFLIKE(2);

/*
 * Misc. data
 */
extern void *xhci_soft_state;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_XHCI_XHCI_H */
