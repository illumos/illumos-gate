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

#ifndef	_SSERVICE_H
#define	_SSERVICE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef int(f_tt)(int, ...);	/* for lint - cc -v quieting */

/*
 * identifiers for all SS functions implemented
 */
#define	SS_GetAdapter		0
#define	SS_GetPage		1
#define	SS_GetSocket		2
#define	SS_GetStatus		3
#define	SS_GetWindow		4
#define	SS_InquireAdapter	5
#define	SS_InquireSocket	6
#define	SS_InquireWindow	7
#define	SS_ResetSocket		8
#define	SS_SetPage		9
#define	SS_SetAdapter		10
#define	SS_SetSocket		11
#define	SS_SetWindow		12
#define	SS_SetIRQHandler	13
#define	SS_ClearIRQHandler	14
#define	CSGetActiveDip		98
#define	CSInitDev		99
#define	CSRegister		100
#define	CSCISInit		101
#define	CSUnregister		102

/*
 * XXX
 */
#define	CISGetAddress		103
#define	CISSetAddress		104
#define	CSCardRemoved		105
#define	CSGetCookiesAndDip	106

/*
 * returns a la Socket Services
 */

#define	SUCCESS		0x00
#define	BAD_ADAPTER		0x01
#define	BAD_ATTRIBUTE	0x02
#define	BAD_BASE		0x03
#define	BAD_EDC		0x04
#define	BAD_IRQ		0x06
#define	BAD_OFFSET		0x07
#define	BAD_PAGE		0x08
#define	READ_FAILURE		0x09
#define	BAD_SIZE		0x0a
#define	BAD_SOCKET		0x0b
#define	BAD_TYPE		0x0d
#define	BAD_VCC		0x0e
#define	BAD_VPP		0x0f
#define	BAD_WINDOW		0x11
#define	WRITE_FAILURE	0x12
#define	NO_CARD		0x14
#define	BAD_FUNCTION		0x15
#define	BAD_MODE		0x16
#define	BAD_SPEED		0x17
#define	BUSY			0x18
#define	NO_RESOURCE		0x20

/* events for callback */
				/* card related events */
#define	PCE_CARD_REMOVAL	0 /* card removed */
#define	PCE_CARD_INSERT		1 /* card inserted */
#define	PCE_CARD_READY		2 /* ready state changed */
#define	PCE_CARD_BATTERY_WARN	3 /* battery is getting low */
#define	PCE_CARD_BATTERY_DEAD	4 /* battery is dead */
#define	PCE_CARD_STATUS_CHANGE	5 /* card status change for I/O card */
#define	PCE_CARD_WRITE_PROTECT	6 /* card write protect status change */
#define	PCE_CARD_RESET		7 /* client requested reset complete */
#define	PCE_CARD_UNLOCK		8 /* lock has been unlocked (opt) */
#define	PCE_CLIENT_INFO		9 /* someone wants client information */
#define	PCE_EJECTION_COMPLETE	10 /* Motor has finished ejecting card */
#define	PCE_EJECTION_REQUEST	11 /* request to eject card */
#define	PCE_ERASE_COMPLETE	12 /* a Flash Erase request completed */
#define	PCE_EXCLUSIVE_COMPLETE	13
#define	PCE_EXCLUSIVE_REQUEST	14
#define	PCE_INSERTION_COMPLETE	15
#define	PCE_INSERTION_REQUEST	16
#define	PCE_REGISTRATION_COMPLETE	17
#define	PCE_RESET_COMPLETE	18
#define	PCE_RESET_PHYSICAL	19
#define	PCE_RESET_REQUEST	20
#define	PCE_TIMER_EXPIRED	21

/* added for SPARC CPR support */
#define	PCE_PM_RESUME		22
#define	PCE_PM_SUSPEND		23

/* added for dynamic nexus registration */
#define	PCE_SS_INIT_STATE	24 /* SS init state */
#define	PCE_ADD_SOCKET		25 /* add a new socket */
#define	PCE_DROP_SOCKET		26 /* drop an existing socket */

#define	PCE_DEV_IDENT		30 /* The nexus has identified the device */
#define	PCE_INIT_DEV		31 /* asking for a device */

#define	PCE_E2M(event)		(1 << (event))

/* event callback uses an indirect call -- make it look like a function */
#define	CS_EVENT(event, socket, arg)	(*pcmcia_cs_event) (event, socket, arg)

/* values for "socket number" field for PCE_SS_INIT_STATE event */
#define	PCE_SS_STATE_INIT	0x0001  /* SS ready for callbacks */
#define	PCE_SS_STATE_DEINIT	0x0002  /* SS not ready for callbacks */

/*
 * The following structure is to support CSRegister
 */
typedef struct csregister {
	uint32_t	cs_magic;		/* magic number */
	uint32_t		cs_version;		/* CS version number */
						/* CS entry point */
	int		(*cs_card_services)(int, ...);
						/* CS event entry point */
	f_tt		*cs_event;
} csregister_t;

/* GetAdapter(get_adapter_t) */

typedef struct get_adapter {
	unsigned	state;		/* adapter hardware state */
	irq_t		SCRouting;	/* status change IRQ routing */
} get_adapter_t;

/* IRQ definitions */
#define	IRQ_ENABLE	0x8000

/* GetPage(get_page_t) */

typedef struct get_page {
	unsigned	window;		/* window number */
	unsigned	page;		/* page number within window */
	unsigned	state;		/* page state: */
					/*
					 * PS_ATTRIBUTE
					 * PS_COMMON
					 * PS_IO (for DoRight?)
					 * PS_ENABLED
					 * PS_WP
					 */
	off_t		offset;		/* PC card's memory offset */
} get_page_t;

/*
 * PS flags
 */

#define	PS_ATTRIBUTE	0x01
#define	PS_ENABLED	0x02
#define	PS_WP		0x04
#define	PS_IO		0x08	/* needed? for DoRight */

/* GetSocket(get_socket_t) */

typedef struct get_socket {
	unsigned	socket;		/* socket number */
	unsigned	SCIntMask;	/* status change interrupt mask */
	unsigned	VccLevel;	/* VCC voltage in 1/10 volt */
	unsigned	Vpp1Level;	/* VPP1 voltage in 1/10 volt */
	unsigned	Vpp2Level;	/* VPP2 voltage in 1/10 volt */
	unsigned	state;		/* latched status change signals */
	unsigned	CtlInd;		/* controls and indicators */
	irq_t		IRQRouting;	/* I/O IRQ routing */
	unsigned	IFType;		/* memory-only or memory & I/O */
} get_socket_t;

/* GetStatus(get_ss_status_t) */

typedef struct get_ss_status {
	unsigned	socket;		/* socket number */
	unsigned	CardState;	/* real-time card state */
	unsigned	SocketState;	/* latched status change signals */
	unsigned	CtlInd;		/* controls and indicators */
	irq_t		IRQRouting;	/* I/O IRQ routing */
	unsigned	IFType;		/* memory-only or memory & I/O */
} get_ss_status_t;

/*
 * Socket specific flags and capabilities
 */

#define	SBM_WP		0x01
#define	SBM_LOCKED	0x02
#define	SBM_EJECT	0x04
#define	SBM_INSERT	0x08
#define	SBM_BVD1	0x10
#define	SBM_BVD2	0x20
#define	SBM_RDYBSY	0x40
#define	SBM_CD		0x80

				/* capabilities only */
#define	SBM_LOCK	0x10
#define	SBM_BATT	0x20
#define	SBM_BUSY	0x40
#define	SBM_XID		0x80

/* GetWindow(get_window_t) */
typedef uint32_t speed_t;	/* memory speed in nanoseconds */

typedef struct get_window {
	unsigned		window;	/* window number */
	unsigned		socket;	/* socket this window is assigned to */
	unsigned		size;	/* size in bytes */
	unsigned		state;	/* current state of window hardware */
	uint_t			speed;	/* speed in nanoseconds */
	uint_t			base;
	ddi_acc_handle_t	handle;		/* base addr in host space */
} get_window_t;

/*
 * window flags (state and capabilities)
 */
#define	WS_IO		0x01
#define	WS_ENABLED	0x02
#define	WS_16BIT	0x04
#define	WS_PAGED	0x80
#define	WS_EISA		0x10
#define	WS_CENABLE	0x20
#define	WS_EXACT_MAPIN	0x40	/* map exactly what's asked for */

/* Inquire Adapter(inquire_adapter_t) */

typedef struct inquire_adapter {
	unsigned	NumSockets;	/* number of sockets */
	unsigned	NumWindows;	/* number of windows */
	unsigned	NumEDCs;	/* number of EDCs */

	unsigned	AdpCaps;	/* adapter power capabilities */
	irq_t		ActiveHigh;	/* active high status change IRQ */
	irq_t		ActiveLow;	/* active low status change IRQ */
	int		NumPower;	/* number of power entries */
	struct power_entry {
		unsigned	PowerLevel;	/* voltage in 1/10 volt */
		unsigned	ValidSignals;	/* voltage is valid for: */
						/*
						 * VCC
						 * VPP1
						 * VPP2
						 * if none are set, this is end
						 * of list
						 */
	} *power_entry;
	int		NumInterrupts; /* number of interrupts supportable */
	struct intr_entry {
		int	pri;
		int	intr;
	}		*AvailInterrupts; /* array of intrs, one per intr */
	uint_t		ResourceFlags; /* resource allocation requirements */
} inquire_adapter_t;

#define	VCC	0x80
#define	VPP1	0x40
#define	VPP2	0x20
#define	V_MASK	(VCC|VPP1|VPP2)

#define	RES_OWN_IRQ	0x0001	/* adapter owns own IRQ resources */
#define	RES_OWN_IO	0x0002	/* adapter owns own I/O resources */
#define	RES_OWN_MEM	0x0004	/* adapter owns own memory resources */
#define	RES_IRQ_NEXUS	0x0008	/* adapter/nexus must multiplex IRQs */
#define	RES_IRQ_SHAREABLE	0x0010 /* IRQ can be shared */

/* InquireSocket(inquire_socket_t) */

typedef struct inquire_socket {
	unsigned	socket;		/* socket number */
	unsigned	SCIntCaps;	/* status change interrupt events */
	unsigned	SCRptCaps;	/* reportable status change events */
	unsigned	CtlIndCaps;	/* controls and indicators */
	unsigned	SocketCaps;	/* socket capabilities */
	irq_t		ActiveHigh;	/* active high status change IRQ */
	irq_t		ActiveLow;	/* active low status change IRQ */
} inquire_socket_t;

/* InquireWindow(inquire_window_t) */

typedef struct memwin_char {
	unsigned	MemWndCaps;	/* memory window characteristcs */
	baseaddr_t	FirstByte;	/* first byte in host space */
	baseaddr_t	LastByte;	/* last byte in host space */
	unsigned	MinSize;	/* minimum window size */
	unsigned	MaxSize;	/* maximum window size */
	unsigned	ReqGran;	/* window size constraints */
	unsigned	ReqBase;	/* base address alignment boundry */
	unsigned	ReqOffset;	/* offset alignment boundry */
	unsigned	Slowest;	/* slowest speed in nanoseconds */
	unsigned	Fastest;	/* fastest speed in nanoseconds */
} mem_win_char_t;

typedef struct iowin_char {
	unsigned	IOWndCaps;	/* I/O window characteristcs */
	baseaddr_t	FirstByte;	/* first byte in host space */
	baseaddr_t	LastByte;	/* last byte in host space */
	unsigned	MinSize;	/* minimum window size */
	unsigned	MaxSize;	/* maximum window size */
	unsigned	ReqGran;	/* window size constraints */
	unsigned	AddrLines;	/* number of address lines decoded */
	unsigned	EISASlot;	/* EISA I/O address decoding */
} iowin_char_t;

typedef struct inquire_window {
	unsigned	window;		/* window number */
	unsigned	WndCaps;	/* window capabilities */
	socket_enum_t	Sockets;	/* window<->socket assignment mask */
	/* note that we always declare both forms */
	mem_win_char_t	mem_win_char;
	iowin_char_t	iowin_char;
} inquire_window_t;


/* interface definitions */
#define	IF_CARDBUS	0x00	/* CardBus interface */
#define	IF_IO		0x01	/* IO + memory */
#define	IF_MEMORY	0x02	/* memory only */
#define	IF_TYPE_MASK	0x03

#define	DREQ_MASK	0x0c
#define	DREQ_NONE	0x00
#define	DREQ_SPKR	0x04
#define	DREQ_IOIS16	0x08
#define	DREQ_INPACK	0x0c

#define	DMA_CHAN_MASK	0xf0
#define	DMA_GET_CHAN(x) (((x) >> 4) & 0xF)
#define	DMA_SET_CHAN(x, y) (((x) & 0xF) | ((y) & ~DMA_CHAN_MASK))

#define	IF_CB		0x04
#define	IF_DMA		0x08
#define	IF_VSKEY	0x10
#define	IF_33VC		0x20
#define	IF_XXVCC	0x40


#define	PC_PAGESIZE	0x4000	/* 16K page size */

/* window capabilities */
				/* generic */
#define	WC_IO		0x0004
#define	WC_WAIT		0x0080
#define	WC_COMMON	0x0001
#define	WC_ATTRIBUTE	0x0002
				/* I/O and memory */
#define	WC_BASE		0x0001
#define	WC_SIZE		0x0002
#define	WC_WENABLE	0x0004
#define	WC_8BIT		0x0008
#define	WC_16BIT	0x0010
#define	WC_BALIGN	0x0020
#define	WC_POW2		0x0040
				/* memory only */
#define	WC_CALIGN	0x0080
#define	WC_PAVAIL	0x0100
#define	WC_PSHARED	0x0200
#define	WC_PENABLE	0x0400
#define	WC_WP		0x0800
				/* I/O only */
#define	WC_INPACK	0x0080
#define	WC_EISA		0x0100
#define	WC_CENABLE	0x0200
				/* Solaris/SPARC */
#define	WC_IO_RANGE_PER_WINDOW	0x8000 /* I/O range unique for each window */

/* SetPage(set_page_t *) */
typedef struct set_page {
	unsigned	window;	/* window number */
	unsigned	page;	/* page number */
	unsigned	state;	/* page state */
	off_t		offset;	/* offset in PC card space */
} set_page_t;

/* SetSocket(set_socket_t) */

typedef struct set_socket {
	unsigned	socket;	/* socket number */
	unsigned	SCIntMask; /* status change enables */
	unsigned	Vcontrol; /* power control flags */
	unsigned	VccLevel; /* Vcc power index level */
	unsigned	Vpp1Level; /* Vpp1 power index level */
	unsigned	Vpp2Level; /* Vpp2 power index level */
	unsigned	State;
	unsigned	CtlInd;	/* control and indicator bits */
	irq_t		IREQRouting; /* I/O IRQ routing */
	unsigned	IFType;	/* interface type (mem/IO) */
} set_socket_t;

#define	VCTL_CISREAD	0x01	/* controlled by Vcc/Vpp sense pins */
#define	VCTL_OVERRIDE	0x02	/* 16-bit cards, ignore the sense pins */

/* SetIRQHandler(set_irq_handler_t) */

typedef struct set_irq_handler {
	unsigned	socket;	/* associate with a socket for now */
	unsigned	irq;
	unsigned	handler_id;	/* ID of this client's handler */
	f_tt		*handler;	/* client IO IRQ handler entry point */
	void		*arg1;		/* arg to call client handler with */
	void		*arg2;		/* arg to call client handler with */
	ddi_iblock_cookie_t	*iblk_cookie;	/* iblk cookie pointer */
	ddi_idevice_cookie_t	*idev_cookie;	/* idev cookie pointer */
} set_irq_handler_t;

#define	IRQ_ANY		0x0

/* interrupt priority levels */
#define	PRIORITY_LOW	0x00
#define	PRIORITY_HIGH	0x10

/* ClearIRQHandler(clear_irq_handler_t) */

typedef struct clear_irq_handler {
	unsigned	socket;
	unsigned	handler_id;	/* client handler ID to remove */
	f_tt		*handler;	/* client IO IRQ handler entry point */
} clear_irq_handler_t;

/* SetWindow(set_window_t) */

typedef struct set_window {
	unsigned		window;		/* window number */
	unsigned		socket;		/* socket number */
	unsigned		WindowSize;	/* window size in bytes */
	unsigned		state;		/* window state */
	unsigned		speed;		/* window speed, nanoseconds */
	uint_t			base;
	ddi_acc_handle_t	handle;		/* base addr in host space */
	dev_info_t		*child;		/* child's dip */
	ddi_device_acc_attr_t	attr;
} set_window_t;

/* CSInitDev */
typedef
struct ss_make_device_node {
	uint32_t		flags;		/* operation flags */
	dev_info_t	*dip;		/* dip for this client */
	char		*name;		/* device node path and name */
	char		*slot;		/* slot name string */
	char		*busaddr;	/* bus addr name string */
	int		spec_type;	/* dev special type (block/char) */
	int		minor_num;	/* device node minor number */
	char		*node_type;	/* device node type */
} ss_make_device_node_t;

#define	SS_CSINITDEV_CREATE_DEVICE	0x01	/* create device node */
#define	SS_CSINITDEV_REMOVE_DEVICE	0x02	/* remove device node */
#define	SS_CSINITDEV_USE_SLOT		0x04	/* use slot name from caller */
#define	SS_CSINITDEV_USE_BUSADDR	0x08	/* use bus addr from caller */
#define	SS_CSINITDEV_MORE_DEVICES	0x10	/* send PCE_INIT_DEV */
#define	SS_CSINITDEV_SEND_DEV_EVENT	0x10	/* send PCE_INIT_DEV */

/*
 * csss_adapter_info_t - provides additional per-socket adapter info
 */
typedef struct csss_adapter_info_t {
	char	name[MODMAXNAMELEN];	/* adapter name */
	int	major;			/* adapter major number */
	int	minor;			/* adapter minor number */
	int	number;			/* canonical adapter number */
	int	num_sockets;		/* # sockets on this adapter */
	int	first_socket;		/* first socket # on this adapter */
} csss_adapter_info_t;

/* CSGetCookiesAndDip */
typedef struct get_cookies_and_dip_t {
	unsigned		socket;		/* socket number */
	dev_info_t		*dip;		/* adapter instance dip */
	ddi_iblock_cookie_t	*iblock;	/* for event handler */
	ddi_idevice_cookie_t	*idevice;	/* for event handler */
	csss_adapter_info_t	adapter_info;	/* adapter info for socket */
} get_cookies_and_dip_t;

/* ResetSocket */
#define	RESET_MODE_FULL		0 /* Reset to SocketServices Specification */
#define	RESET_MODE_CARD_ONLY	1 /* only reset the card itself */

/* union of all exported functions functions */
typedef
union sservice {
	get_adapter_t	get_adapter;
	get_page_t	get_page;
	get_socket_t	get_socket;
	get_window_t	get_window;
	get_ss_status_t	get_ss_status;
	inquire_adapter_t	inquire_adapter;
	inquire_socket_t	inquire_socket;
	inquire_window_t	inquire_window;
	set_page_t	set_page;
	set_socket_t	set_socket;
	set_irq_handler_t	set_irq_handler;
	set_window_t	set_window;
	get_cookies_and_dip_t get_cookies;
	ss_make_device_node_t make_device;
} sservice_t;

/* event manager structures */
struct pcm_make_dev {
	int	socket;
	int	flags;
	int	op;
	dev_t	dev;
	int	type;
	char	driver[MODMAXNAMELEN];
	char	path[MAXPATHLEN];
};

#define	PCM_EVENT_MORE		0x0001	/* more events of this type coming */

#ifdef	_KERNEL

#include <sys/sunndi.h>

/*
 * prototypes for nexi
 */

int pcmcia_attach(dev_info_t *, struct pcmcia_adapter_nexus_private *);
int pcmcia_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *, void *);
int pcmcia_prop_op(dev_t, dev_info_t *, dev_info_t *, ddi_prop_op_t,
			int, char *, caddr_t, int *);
int pcmcia_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result);

int pcmcia_open(dev_t *, int, int, cred_t *);
int pcmcia_close(dev_t, int, int, cred_t *);
int pcmcia_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
int pcmcia_power(dev_info_t *, int, int);
void pcmcia_begin_resume(dev_info_t *);
void pcmcia_wait_insert(dev_info_t *);


/* resource allocation functions and structure */
typedef struct ra_return {
	uint_t	ra_addr_hi;
	uint_t	ra_addr_lo;
	uint_t	ra_len;
} ra_return_t;

int pcmcia_alloc_mem(dev_info_t *, ndi_ra_request_t *, ra_return_t *,
		dev_info_t **);
int pcmcia_alloc_io(dev_info_t *, ndi_ra_request_t *, ra_return_t *,
		dev_info_t **);
int pcmcia_free_mem(dev_info_t *, ra_return_t *);
int pcmcia_free_io(dev_info_t *, ra_return_t *);
int pcmcia_map_reg(dev_info_t *, dev_info_t *, ra_return_t *,
			uint32_t, caddr_t *, ddi_acc_handle_t *,
			ddi_device_acc_attr_t *, uint32_t);
int pcmcia_bus_map(dev_info_t *, dev_info_t *, ddi_map_req_t *,
	off_t, off_t, caddr_t *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SSERVICE_H */
