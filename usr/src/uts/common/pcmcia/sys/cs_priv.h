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

#ifndef _CS_PRIV_H
#define	_CS_PRIV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * PCMCIA Card Services private header file
 */

/*
 * typedef for function pointers to quiet lint and cc -v
 */
typedef	int32_t (f_t)(int32_t, ...);	/* for lint - cc -v quieting */

/*
 * Magic number we use when talking with Socket Services
 */
#define	CS_MAGIC	PCCS_MAGIC

/*
 * Make the calls to SocketServices and the CIS Parser look like
 *	function calls.
 */
#define	SocketServices	(*cs_socket_services)
#define	CIS_PARSER	(*cis_parser)

/*
 * CIS_DEFAULT_SPEED is the default speed to use to read the CIS
 *	in AM space.  It is expressed in nS.
 */
#define	CIS_DEFAULT_SPEED	250

/*
 * This is the IO window speed.
 */
#define	IO_WIN_SPEED		250

/*
 * Flags to support various internal first/next functions. All of
 *	these must be within CIS_GET_LTUPLE_OPMASK which is defined
 *	in the cis.h file. Values outside this mask range are used
 *	internally by the CIS parser.
 */
#define	CS_GET_FIRST_FLAG	0x0001
#define	CS_GET_NEXT_FLAG	0x0002

/*
 * Macros to manipulate bits - only does up to uint32_t size
 */
#define	CS_BIT_WORDSIZE		(sizeof (uint32_t))

#define	CS_BIT_GET(val, bit)	\
			((uint32_t)(val) & (uint32_t)(1<<(uint32_t)(bit)))

#define	CS_BIT_CLEAR(val, bit)	((val) &= (uint32_t)~(1<<(uint32_t)(bit)))

#define	CS_BIT_SET(val, bit)	\
			((uint32_t)(val) |= (uint32_t)(1<<(uint32_t)(bit)))

/*
 * Minimum time to wait after socket reset before we are allowed to
 *	access the card.  The PCMCIA specification says at least 20mS
 *	must elapse from the time that the card is reset until the
 *	first access of any kind can be made to the card. This time
 *	value is expressed in mS.
 */
#define	RESET_TIMEOUT_TIME	180

/*
 * Maximum time to wait for card ready after resetting the socket.
 *	We wait for card ready a maximum of 20 seconds after card
 *	reset before considering that we have an error condition.
 * XXX - what does PCMCIA specify as the max time here??
 */
#define	READY_TIMEOUT_TIME	(drv_usectohz(20000000))

/*
 * Time between periodically kicking the soft interrupt handler.
 */
#define	SOFTINT_TIMEOUT_TIME	(drv_usectohz(2000000))

/*
 * Various delays are necessary when switching the card and socket
 *	between IO and memory modes. All delays are in mS.
 *
 *  cs_request_configuration parameters:
 *    CS_RC1_DELAY - delay between writing COR and switching socket
 *			to IO mode
 *    CS_RC2_DELAY - delay after switching socket to IO mode
 *
 *  cs_release_configuration parameters:
 *	CS_RQ_DELAY - amount of time that the RESET bit in the COR is
 *			held asserted
 */
#define	CS_RC1_DELAY		20	/* COR->IO delay in mS */
#define	CS_RC2_DELAY		300	/* post-COR delay in mS */
#define	CS_RQ_DELAY		100	/* COR(RESET) delay in mS */

/*
 * Handy macro to do untimeout.
 */
#define	UNTIMEOUT(id)		\
	if ((id)) {		\
	    (void) untimeout((id));	\
	    (id) = 0;		\
	}

/*
 * Macros to enter/exit event thread mutex
 */
#define	EVENT_THREAD_MUTEX_ENTER(acq, sp)		\
	acq = !MUTEX_HELD(&sp->client_lock);		\
	if (acq)					\
	    mutex_enter(&sp->client_lock);
#define	EVENT_THREAD_MUTEX_EXIT(acq, sp)		\
	if (acq)					\
	    mutex_exit(&sp->client_lock);

/*
 * cisregister_t structure is used to support the CISRegister
 *	and the CISUnregister function calls
 */
typedef struct cisregister_t {
	uint32_t		cis_magic;
	uint32_t		cis_version;
	void *			(*cis_parser)(int32_t function, ...);
	cistpl_callout_t	*cistpl_std_callout; /* standard callout list */
} cisregister_t;

/*
 * These two defines are to support CISRegister and CISUnregister
 */
#define	CIS_MAGIC	0x20434953
#define	CIS_VERSION	_VERSION(0, 1)

/*
 * CS_MAX_CIS defines the number of CIS chains that we hang off the per-socket
 *	structure.
 *
 * CS_GLOBAL_CIS defines the index where the CIS parser puts the first CIS list
 *	for a single-function card or the global CIS list for a multi-function
 *	card.
 *
 * CS_MAX_CIS is one greater than CIS_MAX_FUNCTIONS since the CIS parser
 *	puts the global CIS chain on the CS_GLOBAL_CIS function index as
 * 	follows:
 *
 *	For single-function cards:
 *	    sp->cis[0] - CIS chain
 *	    sp->cis[1..(CIS_MAX_FUNCTIONS - 1)] - not used
 *	    sp->cis[CS_GLOBAL_CIS] - not used
 *
 *	For multi-function cards:
 *	    sp->cis[0..(CIS_MAX_FUNCTIONS - 1)] - global CIS chain followed
 *					by per-function CIS chain
 *	    sp->cis[CS_GLOBAL_CIS] - global CIS chain
 */
#define	CS_MAX_CIS	(CIS_MAX_FUNCTIONS + 1)
#define	CS_GLOBAL_CIS	CIS_MAX_FUNCTIONS

/*
 * CS_SS_CLIENT_HANDLE is a special client handle that Socket Services gets
 *	when it registers with RegisterClient.
 */
#define	CS_SS_CLIENT_HANDLE	0x00000000

/*
 * Client handle, socket number, function number and socket pointer
 *	macros. The client handle encoding is private to Card Services,
 *	and external modules should not use these macros to manipulate
 *	client handles.
 *
 *	The encoding of the client handle is:
 *
 *		xxxxxfff | xsssssss | cccccccc | cccccccc
 *
 *	f - function number bit
 *	s - socket number bit
 *	c - client number bit
 *	x - don't care bits
 */
#define	CLIENT_HANDLE_IS_SS(ch)		(!GET_CLIENT_MINOR((ch)))
#define	CS_MAX_SOCKETS_MASK		(PCMCIA_MAX_SOCKETS - 1)
#define	CS_MAX_FUNCTIONS_MASK		(CIS_MAX_FUNCTIONS - 1)
#define	CS_MAX_CLIENTS_MASK		0x0ffff
#define	CS_MAX_CLIENTS			(CS_MAX_CLIENTS_MASK - 2)
#define	MAKE_CLIENT_HANDLE(s, f, c)	((((f)&CS_MAX_FUNCTIONS_MASK)<<24) | \
					    (((s)&CS_MAX_SOCKETS_MASK)<<16) | \
					    ((c)&CS_MAX_CLIENTS_MASK))
#define	GET_CLIENT_SOCKET(ch)		(((ch)>>16)&CS_MAX_SOCKETS_MASK)
#define	GET_CLIENT_FUNCTION(ch)		(((ch)>>24)&CS_MAX_FUNCTIONS_MASK)
#define	GET_CLIENT_MINOR(ch)		((ch)&CS_MAX_CLIENTS_MASK)

/*
 * Socket number macros. These are used by Socket Services, CSI
 *	drivers and the "super-client" driver to specify which
 *	socket and function number on that socket they wish to
 *	manipulate. This socket number encoding is typically passed
 *	to various Card Services functions by these drivers.
 *
 *	The encoding of the socket number is:
 *
 *		xxxxxxxx | xxxxgfff | xxxxxxxx | xsssssss
 *
 *	g - global CIS bit
 *	f - function number bit
 *	s - socket number bit
 *	x - don't care bits
 */
#define	CS_GET_SOCKET_NUMBER(s)		((s)&CS_MAX_SOCKETS_MASK)
#define	CS_GET_FUNCTION_NUMBER(s)	(((s)>>16)&(CS_MAX_FUNCTIONS_MASK | \
							CIS_MAX_FUNCTIONS))
#define	CS_SET_SOCKET_NUMBER(s)		((s)&CS_MAX_SOCKETS_MASK)
#define	CS_SET_FUNCTION_NUMBER(f)	(((f)&(CS_MAX_FUNCTIONS_MASK | \
						CIS_MAX_FUNCTIONS))<<16)
#define	CS_MAKE_SOCKET_NUMBER(s, f)	(CS_SET_SOCKET_NUMBER(s) | \
						CS_SET_FUNCTION_NUMBER(f))

/*
 * DIP2SOCKET_NUM(dip) - this macro gets the PCM_DEV_SOCKET property from
 *	the passed dip.  If the property can't be found, then the default
 *	value of cs_globals.max_socket_num is returned.
 */
#define	DIP2SOCKET_NUM(dip)		ddi_getprop(DDI_DEV_T_NONE, dip,\
						(DDI_PROP_CANSLEEP |	\
							DDI_PROP_NOTPROM), \
						PCM_DEV_SOCKET,		\
						cs_globals.max_socket_num)

/*
 * Range checking macros
 *
 * CHECK_SOCKET_NUM(socket_number, max_sockets) returns 1 if
 *	socket_number is in range
 */
#define	CHECK_SOCKET_NUM(sn, ms)	(((sn) >= (ms))?0:1)

/*
 * window macros
 *
 * These all expect that the window has been validated as a valid
 *	window (i.e. CW_WINDOW_VALID is set in window state)
 *
 * Note that WINDOW_FOR_SOCKET expects a socket mask for the wsm
 *	parameter (this is a socket_enum_t type, and NOT just a
 *	plain old uint32_t)
 */
#define	WINDOW_FOR_SOCKET(wsm, sn)	((wsm)[sn/PR_WORDSIZE] & \
						(1 << ((sn) & PR_MASK)))
#define	WINDOW_AVAILABLE_FOR_MEM(cwp)	(!(cwp->state & CW_WIN_IN_USE))
#define	WINDOW_AVAILABLE_FOR_IO(cwp)	\
		(!(cwp->state & (CW_CIS | CW_MEM | CW_ALLOCATED)))

/*
 * IO Base and NumPorts address frobnitz macros
 */
#define	IOADDR_FROBNITZ(Base, IOAddrLines)	(Base&((1<<IOAddrLines)-1))
#define	IONUMPORTS_FROBNITZ(np)			(((np)&1)?((np)+1):(np))

/*
 * Structure that contains offsets to the card's configuration registers
 *	as well as copies of the data written to them in RequestConfiguration.
 *	We use an offset per register approach since not all cards have
 *	all registers implemented, and by specifying a NULL register offset,
 *	we know not to try to access that register.
 */
typedef struct config_regs_t {
	cfg_regs_t	cor;		/* Configuration Option Register */
	uint32_t	cor_p;
	cfg_regs_t	ccsr;		/* Configuration and Status Register */
	uint32_t	ccsr_p;
	cfg_regs_t	prr;		/* Pin Replacement Register */
	uint32_t	prr_p;
	cfg_regs_t	scr;		/* Socket and Copy Register */
	uint32_t	scr_p;
	cfg_regs_t	exstat;		/* Extended Status Register */
	uint32_t	exstat_p;
	cfg_regs_t	iobase0;	/* IO Base 0 Register */
	uint32_t	iobase0_p;
	cfg_regs_t	iobase1;	/* IO Base 1 Register */
	uint32_t	iobase1_p;
	cfg_regs_t	iobase2;	/* IO Base 2 Register */
	uint32_t	iobase2_p;
	cfg_regs_t	iobase3;	/* IO Base 3 Register */
	uint32_t	iobase3_p;
	cfg_regs_t	iolimit;	/* IO Limit Register */
	uint32_t	iolimit_p;
} config_regs_t;

/*
 * Macro to make calling the client's event handler look like a function.
 */
#define	CLIENT_EVENT_CALLBACK(cp, event, pri)		\
	    (cp)->event_callback_handler(event, pri,	\
			&(cp)->event_callback_args)

/*
 * Macro to return event in PRR - this also clears the changed bit if
 *	the event occured.
 */
#define	PRR_EVENT(prrx, pe, ps, ce, re)	\
	if (prrx & pe) {		\
	    if (prrx & ps)		\
		(re) |= ce;		\
	    prrx &= ~pe;		\
	    prrx |= ps;			\
	}

/*
 * io_alloc_t struct used to keep track of a client's IO window allocation
 */
typedef struct io_alloc_t {
	uint32_t	Window1;	/* allocated IO window no. for set #1 */
	baseaddru_t	BasePort1;	/* 1st IO range base address or port */
	uint32_t	NumPorts1;	/* 1st IO range no. contiguous ports */
	uint32_t	Attributes1;	/* 1st IO range attributes */
	uint32_t	Window2;	/* allocated IO window no. for set #2 */
	baseaddru_t	BasePort2;	/* s2nd IO range base address or port */
	uint32_t	NumPorts2;	/* 2nd IO range no. contiguous ports */
	uint32_t	Attributes2;	/* second IO range attributes */
	uint32_t	IOAddrLines;	/* number of IO address lines decoded */
} io_alloc_t;

/*
 * irq_alloc_t structure used to keep track of a client's IRQ allocation
 */
typedef struct irq_alloc_t {
	uint32_t	Attributes;	/* IRQ attribute flags */
	uint32_t	irq;		/* assigned IRQ number */
	uint32_t	handler_id;	/* IRQ handler ID for this IRQ */
	f_t		*irq_handler;
	void		*irq_handler_arg1;
	void		*irq_handler_arg2;
} irq_alloc_t;

/*
 * The client data structure
 */
typedef struct client_t {
	client_handle_t	client_handle;	/* this client's client handle */
	unsigned	flags;		/* client flags */
	/* resource control */
	uint32_t	memwin_count;	/* number of mem windows allocated */
	io_alloc_t	io_alloc;	/* IO resource allocations */
	irq_alloc_t	irq_alloc;	/* IRQ resource allocations */
	/* event support */
	uint32_t	event_mask;	/* client event mask */
	uint32_t	global_mask;	/* client global event mask */
	uint32_t	events;		/* current events pending */
	uint32_t	pending_events;	/* events pending in RegisterClient */
	csfunction_t	*event_callback_handler;
	event_callback_args_t	event_callback_args;
	/* config registers support */
	config_regs_t	config_regs;	/* pointers to config registers */
	uint32_t	config_regs_offset; /* offset from start of AM */
	unsigned	pin;		/* valid bits in PRR */
	uint32_t	present;	/* which config registers present */
	/* DDI support */
	dev_info_t	*dip;		/* this client's dip */
	char		*driver_name;	/* client's driver name */
	int32_t		instance;	/* client's driver instance */
	/* list control */
	struct client_t	*next;		/* next client pointer */
	struct client_t	*prev;		/* previous client pointer */
} client_t;

/*
 * Flags for client structure - note that we share the client_t->flags
 *	member with the definitions in cs.h that are used by the
 *	RegisterClient function.
 *
 * We can start our flags from 0x00001000 and on up.
 */
#define	REQ_CONFIGURATION_DONE	0x00001000	/* RequestConfiguration done */
#define	REQ_SOCKET_MASK_DONE	0x00002000	/* RequestSocketMask done */
#define	REQ_IO_DONE		0x00004000	/* RequestIO done */
#define	REQ_IRQ_DONE		0x00008000	/* RequestIRQ done */
#define	CLIENT_SUPER_CLIENT	0x00010000	/* "super-client" client */
#define	CLIENT_CSI_CLIENT	0x00020000	/* CSI client */
#define	CLIENT_CARD_INSERTED	0x00100000	/* current card for client */
#define	CLIENT_SENT_INSERTION	0x00200000	/* send CARD_INSERTION */
#define	CLIENT_MTD_IN_PROGRESS	0x01000000	/* MTD op in progress */
#define	CLIENT_IO_ALLOCATED	0x02000000	/* IO resources allocated */
#define	CLIENT_IRQ_ALLOCATED	0x04000000	/* IRQ resources allocated */
#define	CLIENT_WIN_ALLOCATED	0x08000000	/* window resources allocated */

#ifdef	USE_IOMMAP_WINDOW
/*
 * io_mmap_window_t structure that describes the memory-mapped IO
 *	window on this socket
 */
typedef struct io_mmap_window_t {
	uint32_t		flags;	/* window flags */
	uint32_t		number;	/* IO window number */
	uint32_t		size;	/* size of mapped IO window */
	ddi_acc_handle_t	handle;	/* window mapped base address */
	uint32_t		count;	/* referance count */
} io_mmap_window_t;
#endif	/* USE_IOMMAP_WINDOW */

/*
 * cis_info_t structure used to hold per-socket CIS information
 */
typedef struct cis_info_t {
	uint32_t	flags;		/* CIS-specific flags */
	cistpl_t	*cis;		/* CIS linked lists */
	uint32_t	nchains;	/* number of tuple chains in CIS */
	uint32_t	ntuples;	/* number of tuples in CIS */
} cis_info_t;

/*
 * cs_adapter_t structure used to hold per-socket
 *	adapter-specific info
 */
typedef struct cs_adapter_t {
	uint32_t	flags;		/* adapter flags */
	char		name[MODMAXNAMELEN]; /* adapter module name */
	uint32_t	major;		/* adapter major number */
	uint32_t	minor;		/* adapter minor number */
	uint32_t	instance;	/* instance number of this adapter */
	uint32_t	number;		/* canonical adapter number */
	uint32_t	num_sockets;	/* # sockets on this adapter */
	uint32_t	first_socket;	/* first socket # on this adapter */
} cs_adapter_t;

/*
 * The per-socket structure.
 */
typedef struct cs_socket_t {
	unsigned	socket_num;	/* socket number */
	uint32_t	flags;		/* socket flags */
	uint32_t	init_state;	/* cs_init state */
	cs_adapter_t	adapter;	/* adapter info */
	/* socket thread control and status */
	kthread_t	*event_thread;	/* per-socket work thread */
	uint32_t	thread_state;	/* socket thread state flags */
	kmutex_t	lock;		/* protects events and clients */
	kcondvar_t	thread_cv;	/* event handling synchronization */
	kcondvar_t	caller_cv;	/* event handling synchronization */
	kcondvar_t	reset_cv;	/* for use after card RESET */
	uint32_t	events;		/* socket events */
	uint32_t	event_mask;	/* socket event mask */
	ddi_softintr_t	softint_id;	/* soft interrupt handler ID */
	timeout_id_t	rdybsy_tmo_id;	/* timer ID for READY/BUSY timer */
	ddi_iblock_cookie_t	*iblk;	/* event iblk cookie */
	ddi_idevice_cookie_t	*idev;	/* event idev cookie */
	callb_cpr_t	cprinfo_cs;	/* CPR cookie for cs_event_thread */
	callb_cpr_t	cprinfo_ss;	/* CPR cookie for cs_ss_thread */
	/* client management */
	client_t	*client_list;	/* clients on this socket */
	unsigned	next_cl_minor;	/* next available client minor num */
	kmutex_t	client_lock;	/* protects client list */
	uint32_t	num_clients;	/* number of clients on this socket */
	/* CIS support */
	uint32_t	cis_win_num;	/* CIS window number */
	unsigned	cis_win_size;	/* CIS window size */
	uint32_t	cis_flags;
	uint32_t	nfuncs;		/* number of functions */
	cis_info_t	cis[CS_MAX_CIS]; /* CIS information */
	kmutex_t	cis_lock;	/* protects CIS */
#ifdef	USE_IOMMAP_WINDOW
	/* memory mapped IO window support */
	io_mmap_window_t *io_mmap_window;
#endif	/* USE_IOMMAP_WINDOW */
	/* Socket Services work thread control and status */
	kthread_t	*ss_thread;	/* SS work thread */
	uint32_t	ss_thread_state; /* SS work thread state */
	kcondvar_t	ss_thread_cv;	/* SS work thread synchronization */
	kcondvar_t	ss_caller_cv;	/* SS work thread synchronization */
	kmutex_t	ss_thread_lock;	/* protects SS work thread state */
	struct cs_socket_t	*next;	/* next socket in list */
} cs_socket_t;

/*
 * cs_socket_t->flags flags
 */
#define	SOCKET_CARD_INSERTED		0x00000001	/* card is inserted */
#define	SOCKET_IS_IO			0x00000002	/* socket in IO mode */
#define	SOCKET_UNLOAD_MODULE		0x00000004	/* want to unload CS */
#define	SOCKET_NEEDS_THREAD		0x00000008	/* wake event thread */
#define	SOCKET_IS_VALID			0x00000020	/* socket OK to use */

/*
 * cs_socket_t->thread_state and cs_socket_t->ss_thread_state flags
 */

/* generic for all threads */
#define	SOCKET_THREAD_EXIT		0x00000001	/* exit event thread */

/* only used for per-socket event thread */
#define	SOCKET_WAIT_FOR_READY		0x00001000	/* waiting for READY */
#define	SOCKET_RESET_TIMER		0x00002000	/* RESET timer */
#define	SOCKET_WAIT_SYNC		0x00004000	/* SYNC */

/* only used for Socket Services work thread */
#define	SOCKET_THREAD_CSCISInit		0x00100000	/* call CSCISInit */

/*
 * cs_socket_t->cis_flags and cs_socket_t->cis_info_t->flags flags
 */
#define	CW_VALID_CIS			0x00000001	/* valid CIS */
#define	CW_MULTI_FUNCTION_CIS		0x00000002	/* multifunction card */
#define	CW_LONGLINK_A_FOUND		0x00000004	/* CISTPL_LONGLINK_A */
#define	CW_LONGLINK_C_FOUND		0x00000008	/* CISTP_LONGLINK_C */
#define	CW_LONGLINK_MFC_FOUND		0x00000010	/* LONGLINK_MFC */
#define	CW_CHECK_LINKTARGET		0x00000020	/* check linktarget */
#define	CW_RET_ON_LINKTARGET_ERROR	0x00000040	/* linktarget invalid */
#define	CW_CHECK_PRIMARY_CHAIN		0x00000080	/* check for primary */
							/* chain tuples */

/*
 * CW_LONGLINK_FOUND - a combination of the various CW_LONGLINK_XXX_FOUND
 *			flags used to make the code less dense.
 */
#define	CW_LONGLINK_FOUND		(CW_LONGLINK_A_FOUND |	\
					CW_LONGLINK_C_FOUND |	\
					CW_LONGLINK_MFC_FOUND)

/*
 * macro to test for a valid CIS window on a socket
 */
#define	SOCKET_HAS_CIS_WINDOW(sp)	(sp->cis_win_num != PCMCIA_MAX_WINDOWS)

/*
 * cs_socket_t->init_state flags - these flags are used to keep track of what
 *	was allocated in cs_init so that things can be deallocated properly
 *	in cs_deinit.
 */
#define	SOCKET_INIT_STATE_MUTEX		0x00000001	/* mutexii are OK */
#define	SOCKET_INIT_STATE_CV		0x00000002	/* cvii are OK */
#define	SOCKET_INIT_STATE_THREAD	0x00000004	/* thread OK */
#define	SOCKET_INIT_STATE_READY		0x00000008	/* socket OK */
#define	SOCKET_INIT_STATE_SS_THREAD	0x00000010	/* SS thread OK */
/*
 * While this next flag doesn't really describe a per-socket resource,
 *	we still set it for each socket.  When the soft interrupt handler
 *	finally gets removed in cs_deinit, this flag will get cleared.
 *	The value of this flag should follow the previous SOCKET_INIT
 *	flag values.
 */
#define	SOCKET_INIT_STATE_SOFTINTR	0x00000020	/* softintr handler */

/*
 * Macro to create a socket event thread.
 */
#define	CS_THREAD_PRIORITY		(v.v_maxsyspri - 4)
#define	CREATE_SOCKET_EVENT_THREAD(eh, csp)			\
	thread_create(NULL, 0, eh, (void *)csp,			\
	0, &p0, TS_RUN, CS_THREAD_PRIORITY)

/*
 * The per-window structure.
 */
typedef struct cs_window_t {
	uint32_t	window_num;	/* window number */
	window_handle_t	window_handle;	/* unique window handle */
	client_handle_t	client_handle;	/* owner of this window */
	unsigned	socket_num;	/* socket number */
	unsigned	state;		/* window state flags */
	struct cs_window_t	*next;	/* next window in list */
} cs_window_t;

/*
 * Window structure state flags - if none of the bits in the
 *	CW_WIN_IN_USE mask are set AND if CW_WINDOW_VALID is set,
 *	it means that this window is available and not being used
 *	by anyone.
 * Setting the CW_ALLOCATED will prevent the window from being found
 *	as an available window for memory or IO; since memory windows
 *	are not shared between clients, RequestWindow will always set
 *	the CW_ALLOCATED flag when it has assigned a memory window to
 *	a client.  Since we can sometimes share IO windows, RequestIO
 *	will only set the CW_ALLOCATED flag if it doesn't want the IO
 *	window to be used by other calls to RequestIO.
 * When CW_WINDOW_VALID is set, it means that this is a valid window
 *	that has been added by the framework and can be used. If this
 *	bit is not set, this window can not be used at all.
 */
#define	CW_ALLOCATED	0x00000001	/* window is allocated  */
#define	CW_CIS		0x00000002	/* window being used as CIS window */
#define	CW_MEM		0x00000004	/* window being used as mem window */
#define	CW_IO		0x00000008	/* window being used as IO window */
#define	CW_WIN_IN_USE	0x0000ffff	/* window in use mask */
#define	CW_WINDOW_VALID	0x00010000	/* window is valid */

/*
 * window handle defines - the WINDOW_HANDLE_MASK implies the maximum number
 *	of windows allowed
 */
#define	WINDOW_HANDLE_MAGIC	0x574d0000
#define	WINDOW_HANDLE_MASK	0x0000ffff
#define	GET_WINDOW_NUMBER(wh)	((wh) & WINDOW_HANDLE_MASK)
#define	GET_WINDOW_MAGIC(wh)	((wh) & ~WINDOW_HANDLE_MASK)

/*
 * The client type structures, used to sequence events to clients on a
 *	socket. The "type" flags are the same as are used for the
 *	RegisterClient function.
 */
typedef struct client_types_t {
	uint32_t		type;
	uint32_t		order;
	struct client_types_t	*next;
} client_types_t;

/*
 * Flags that specify the order of client event notifications for the
 *	client_types_t structure.
 */
#define	CLIENT_EVENTS_LIFO	0x00000001
#define	CLIENT_EVENTS_FIFO	0x00000002

/*
 * This is a structure that CS uses to keep track of items that are global
 *	to all functions in the module.
 */
typedef struct cs_globals_t {
	cs_socket_t	*sp;		/* head of socket list */
	cs_window_t	*cw;		/* head of window list */
	kmutex_t	global_lock;	/* protects this struct */
	kmutex_t	window_lock;	/* protects cs_windows */
	ddi_softintr_t	softint_id;	/* soft interrupt handler id */
	timeout_id_t	sotfint_tmo;	/* soft interrupt handler timeout id */
	uint32_t	init_state;	/* flags set in cs_init */
	uint32_t	flags;		/* general global flags */
	uint32_t	max_socket_num;	/* highest socket number plus one */
	uint32_t	num_sockets;	/* total number of sockets */
	uint32_t	num_windows;	/* total number of windows */
	struct sclient_list_t	*sclient_list;
} cs_globals_t;

/*
 * Flags for cs_globals_t->init_state
 */
#define	GLOBAL_INIT_STATE_SOFTINTR	0x00010000	/* softintr handler */
#define	GLOBAL_INIT_STATE_MUTEX		0x00020000	/* global mutex init */
#define	GLOBAL_INIT_STATE_NO_CLIENTS	0x00040000	/* no new clients */
#define	GLOBAL_INIT_STATE_UNLOADING	0x00080000	/* cs_deinit running */
#define	GLOBAL_INIT_STATE_SS_READY	0x00100000	/* SS ready for */
							/* callbacks */
/*
 * Flags for cs_globals_t->flags
 */
#define	GLOBAL_SUPER_CLIENT_REGISTERED	0x00000001	/* "super-client" reg */
#define	GLOBAL_IN_SOFTINTR		0x00000002	/* in soft int code */

/*
 * sclient_reg_t struct for RegisterClient when a "super-client" is
 *	registering.
 * This structure is actually hung off of the client_reg_t.private
 *	structure member.  Since we don't make public how to write
 *	a "super-client", the actual structure that the client uses
 *	is defined in this private header file.
 */
typedef struct sclient_reg_t {
	uint32_t		max_socket_num;
	uint32_t		num_sockets;
	uint32_t		num_windows;
	uint32_t		num_clients;
	struct sclient_list_t {
		client_handle_t	client_handle;
		uint32_t	error;
	} **sclient_list;
} sclient_reg_t;

/*
 * structure for event text used for cs_ss_event_text
 */
typedef struct cs_ss_event_text_t {
	event_t		ss_event;	/* SS event code */
	event_t		cs_event;	/* CS event code */
	char		*text;
} cs_ss_event_text_t;

/*
 * Flags for cs_read_event_status
 */
#define	CS_RES_IGNORE_NO_CARD		0x0001	/* don't check for card */

/*
 * cs_csfunc2text_strings_t structure used internally in Error2Text
 */
typedef struct cs_csfunc2text_strings_t {
	uint32_t	item;
	char		*text;
} cs_csfunc2text_strings_t;

/*
 * Flags for Error2Text - not used by clients; the struct is defined
 *	in the cs.h header file.
 */
#define	CSFUN2TEXT_FUNCTION	0x0001	/* return text of CS function code */
#define	CSFUN2TEXT_RETURN	0x0002	/* return text of CS return code */

/*
 * Macros to walk the local linked CIS list.
 *
 * These macros can take any valid local list tuple pointer.  They return
 *	another tuple pointer or NULL if they fail.
 */
#define	GET_NEXT_TUPLE(tp, f)		CIS_PARSER(CISP_CIS_GET_LTUPLE, tp,  \
						NULL, GET_NEXT_LTUPLEF |     \
						(f & ~CIS_GET_LTUPLE_OPMASK))
#define	GET_PREV_TUPLE(tp, f)		CIS_PARSER(CISP_CIS_GET_LTUPLE, tp,  \
						NULL, GET_PREV_LTUPLEF |     \
						(f & ~CIS_GET_LTUPLE_OPMASK))
#define	GET_FIRST_LTUPLE(tp, f)		CIS_PARSER(CISP_CIS_GET_LTUPLE, tp,   \
						NULL, GET_FIRST_LTUPLEF |     \
						(f & ~CIS_GET_LTUPLE_OPMASK))
#define	GET_LAST_LTUPLE(tp, f)		CIS_PARSER(CISP_CIS_GET_LTUPLE, tp,   \
						NULL, GET_LAST_LTUPLEF |      \
						(f & ~CIS_GET_LTUPLE_OPMASK))
#define	FIND_LTUPLE_FWD(tp, tu, f)	CIS_PARSER(CISP_CIS_GET_LTUPLE, tp,   \
						tu, FIND_LTUPLE_FWDF |        \
						(f & ~CIS_GET_LTUPLE_OPMASK))
#define	FIND_LTUPLE_BACK(tp, tu, f)	CIS_PARSER(CISP_CIS_GET_LTUPLE, tp,   \
						tu, FIND_LTUPLE_BACKF |       \
						(f & ~CIS_GET_LTUPLE_OPMASK))
#define	FIND_NEXT_LTUPLE(tp, tu, f)	CIS_PARSER(CISP_CIS_GET_LTUPLE, tp,   \
						tu, FIND_NEXT_LTUPLEF |       \
						(f & ~CIS_GET_LTUPLE_OPMASK))
#define	FIND_PREV_LTUPLE(tp, tu, f)	CIS_PARSER(CISP_CIS_GET_LTUPLE, tp,   \
						tu, FIND_PREV_LTUPLEF |       \
						(f & ~CIS_GET_LTUPLE_OPMASK))
#define	FIND_FIRST_LTUPLE(tp, tu, f)	FIND_LTUPLE_FWD(GET_FIRST_LTUPLE(tp,  \
								f), tu, f)


/*
 * Card Services hooks and general nexus prototypes
 */
int	 cs_init(void);
uint32_t cs_event(event_t, uint32_t, uint32_t);
int	 pcmcia_set_em_handler(int (*handler)(), caddr_t events,
	    int elen, uint32_t id, void **cs, void **ss);

extern csfunction_t	*cs_socket_services;


#ifdef	__cplusplus
}
#endif

#endif	/* _CS_PRIV_H */
