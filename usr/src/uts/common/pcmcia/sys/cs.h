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

#ifndef _CS_H
#define	_CS_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * PCMCIA Card Services header file
 */

/*
 * XXX - This define really should be in a global header file
 *	somewhere; we do this stunt here since a lot of
 *	people include this header file but not necessarily
 *	the header file in which this is defined.
 */
#ifndef	_VERSION
#define	_VERSION(major, minor)	((major)<<16|(minor))
#endif

/*
 * Define this version of CS - this should correspond to the PCMCIA
 *	version number specified in the PCMCIA standard.
 */
#define	CS_VERSION	_VERSION(5, 2)

/*
 * CS_INTERNAL_REVISION_LEVEL is our internal revision level value returned
 *	via GetCardServicesInfo in get_cardservices_info_t->Revision
 */
#define	CS_INTERNAL_REVISION_LEVEL	_VERSION(2, 0)

#define	CS_GET_CARDSERVICES_INFO_VENDOR_STRING	"Solaris UNIX Card Services\n" \
	"Copyright 2008 Sun Microsystems, Inc.  All rights reserved.\n" \
	"Use is subject to license terms.\n" \
	"@(#)cs.h	1.69 08/10/17 SMI\n" \
	"Based on the PC Card Standard, February 1995\n"

/*
 * typedef for function pointers to quiet lint and cc -v
 */
typedef	int32_t (csfunction_t)(int32_t, ...);	/* for lint - cc -v quieting */

/*
 * CS_SUN_VENDOR_DESCRIPTION - can be returned by clients handling
 *				the CS_EVENT_CLIENT_INFO event in the
 *				client_info_t->VendorName member.
 */
#define	CS_SUN_VENDOR_DESCRIPTION	"Sun Microsystems, Inc. (c) 1996"

/*
 * Return codes from Card Services - these correspond to the PCMCIA
 *	standard and also include some implementation-specific return
 *	codes.
 */
#define	CS_SUCCESS		0x00	/* Request succeeded */
#define	CS_BAD_ADAPTER		0x01	/* Specified adapter is invalid */
#define	CS_BAD_ATTRIBUTE	0x02	/* Bad attribute value */
#define	CS_BAD_BASE		0x03	/* System base address invalid */
#define	CS_BAD_EDC		0x04	/* EDC generator is invalid */
	/* RESERVED - 0x05 */
#define	CS_BAD_IRQ		0x06	/* Invalid IRQ */
#define	CS_BAD_OFFSET		0x07	/* Card offset invalid */
#define	CS_BAD_PAGE		0x08	/* Card page invalid */
#define	CS_READ_FAILURE		0x09	/* Unable to complete read request */
#define	CS_BAD_SIZE		0x0a	/* Size is invalid */
#define	CS_BAD_SOCKET		0x0b	/* Specified socket is invalid */
	/* RESERVED - 0x0c */
#define	CS_BAD_TYPE		0x0d	/* Window/interface type invalid */
#define	CS_BAD_VCC		0x0e	/* Vcc value/index invalid */
#define	CS_BAD_VPP		0x0f	/* Vpp value/index invalid */
#define	CS_BAD_WINDOW		0x11	/* Specified window is invalid */
#define	CS_WRITE_FAILURE	0x12	/* Unable to complete write request */
	/* RESERVED - 0x13 */
#define	CS_NO_CARD		0x14	/* No PC card in socket */
#define	CS_UNSUPPORTED_FUNCTION	0x15	/* Unsupported function */
#define	CS_UNSUPPORTED_MODE	0x16	/* Unsupported processor mode */
#define	CS_BAD_SPEED		0x17	/* Specified speed is unavailable */
#define	CS_BUSY			0x18	/* CS is busy - try again later */
#define	CS_GENERAL_FAILURE	0x19	/* Undefined error */
#define	CS_WRITE_PROTECTED	0x1a	/* Media is write protected */
#define	CS_BAD_ARG_LENGTH	0x1b	/* Arg length invalid */
#define	CS_BAD_ARGS		0x1c	/* Arg values invalid */
#define	CS_CONFIGURATION_LOCKED	0x1d	/* This configuration is locked */
#define	CS_IN_USE		0x1e	/* Requested resource in use */
#define	CS_NO_MORE_ITEMS	0x1f	/* No more of requested item */
#define	CS_OUT_OF_RESOURCE	0x20	/* Internal CS resources exhausted */
#define	CS_BAD_HANDLE		0x21	/* client or window handle invalid */

/*
 * The following are Solaris-specific extended return codes
 */
#define	CS_NO_CIS		0x80	/* No CIS on card */
#define	CS_BAD_CIS		0x81	/* Bad CIS on card */
#define	CS_UNKNOWN_TUPLE	0x82	/* unknown tuple */
#define	CS_BAD_VERSION		0x83	/* bad CS version */
#define	CS_UNSUPPORTED_EVENT	0x84	/* Unsupported event in client */
#define	CS_CSI_ERROR		0x85	/* error in csi driver protocol */
#define	CS_CSI_NOT_INIT		0x86	/* csi library/driver not initialized */
#define	CS_NO_TUPLE_PARSER	0x87	/* no tuple parser for this tuple */
#define	CS_CARD_NOT_READY	0x88	/* card not ready */
#define	CS_ERRORLIST_END	0x8000	/* end of error list */

/*
 * Card Services event codes - these do NOT correspond to the PCMCIA
 *	standard event codes for CS since these events are encoded as
 *	bit flags, while the PCMCIA standard event codes are encoded
 *	as numerical values.  In practice, this shouldn't be a problem
 *	since no one should be looking at the absolute value of the
 *	event codes; these defines should be used.
 *
 * The numerical value of an event code determines in what order a client
 *	will receive the event if other events are also pending for that
 *	client. XXX - need to make event_t a 64-bit field.
 *
 * Card Services receives these events from Socket Services or by reading
 *	the card's Pin Replacement Register.  In either case, the client
 *	always gets the same type of notification.
 */
#define	CS_EVENT_REGISTRATION_COMPLETE	0x00000001 /* 0x82 */
#define	CS_EVENT_PM_RESUME		0x00000002 /* 0x05 */
#define	CS_EVENT_CARD_INSERTION		0x00000004 /* 0x0c */
#define	CS_EVENT_CARD_READY		0x00000008 /* 0x01 */
#define	CS_EVENT_BATTERY_LOW		0x00000010 /* 0x02 is also BVD2 */
#define	CS_EVENT_BATTERY_DEAD		0x00000020 /* 0x40 is also BVD1 */
#define	CS_EVENT_CARD_LOCK		0x00000040 /* 0x03 */
#define	CS_EVENT_PM_SUSPEND		0x00000080 /* 0x04 */
#define	CS_EVENT_CARD_RESET		0x00000100 /* 0x11 */
#define	CS_EVENT_CARD_UNLOCK		0x00000200 /* 0x06 */
#define	CS_EVENT_EJECTION_COMPLETE	0x00000400 /* 0x07 */
#define	CS_EVENT_EJECTION_REQUEST	0x00000800 /* 0x08 */
#define	CS_EVENT_ERASE_COMPLETE		0x00001000 /* 0x81 */
#define	CS_EVENT_EXCLUSIVE_COMPLETE	0x00002000 /* 0x0d */
#define	CS_EVENT_EXCLUSIVE_REQUEST	0x00004000 /* 0x0e */
#define	CS_EVENT_INSERTION_COMPLETE	0x00008000 /* 0x09 */
#define	CS_EVENT_INSERTION_REQUEST	0x00010000 /* 0x0a */
#define	CS_EVENT_RESET_COMPLETE		0x00020000 /* 0x80 */
#define	CS_EVENT_RESET_PHYSICAL		0x00040000 /* 0x0f */
#define	CS_EVENT_RESET_REQUEST		0x00080000 /* 0x10 */
#define	CS_EVENT_MTD_REQUEST		0x00100000 /* 0x12 */
#define	CS_EVENT_CLIENT_INFO		0x00200000 /* 0x14 */
#define	CS_EVENT_TIMER_EXPIRED		0x00400000 /* 0x15 */
#define	CS_EVENT_WRITE_PROTECT		0x01000000 /* 0x17 */

/*
 * The CS_EVENT_SS_UPDATED event is generated when Socket Services
 *	has completed parsing the CIS and has done any necessary
 *	work to get the client driver loaded and attached.
 */
#define	CS_EVENT_SS_UPDATED		0x00800000 /* 0x16 */

/*
 * The CS_EVENT_STATUS_CHANGE event is generated by a Socket Services
 *	PCE_CARD_STATUS_CHANGE event; this event gets converted to
 *	the appropriate Card Services events when Card Services
 *	reads the PRR.
 */
#define	CS_EVENT_STATUS_CHANGE		0x02000000 /* ?? */

/*
 * The CS_EVENT_CARD_REMOVAL is the last "real" CS event and must
 *	have the highest value of all "real" CS events so that this
 *	event is handed to the client after all other queued events
 *	have been processed.
 * If the client has set the CS_EVENT_CARD_REMOVAL_LOWP flag in
 *	either of their event masks, then they will also receive
 *	a CS_EVENT_CARD_REMOVAL at low (cs_event_thread) priority;
 *	in this low priority removal event, the client can call
 *	many CS functions that they can't call when they recieve
 *	the high priority removal event.
 */
#define	CS_EVENT_CARD_REMOVAL		0x10000000 /* 0x0b */
#define	CS_EVENT_CARD_REMOVAL_LOWP	0x20000000 /* ?? */
/*
 * The following are not events but they share the event flags field
 *	and are used internally by CS.  These bit patterns will never
 *	be seen by clients.
 * CS_EVENT_ALL_CLIENTS can only be set by the super-client and by
 *	the CSI clients; setting this bit causes the driver to
 *	receive any events specified in their event masks whenever
 *	any such events occur on the socket.
 * CS_EVENT_READY_TIMEOUT is a CS-private flag and should never be
 *	set by clients.
 */
#define	CS_EVENT_ALL_CLIENTS		0x40000000 /* ?? */
#define	CS_EVENT_READY_TIMEOUT		0x80000000 /* ?? */

/*
 * CS_EVENT_CLIENT_EVENTS_MASK is a msk of events that only the framework
 *	is allowed to manipulate.
 */
#define	CS_EVENT_CLIENT_EVENTS_MASK	~(CS_EVENT_SS_UPDATED |		\
						CS_EVENT_ALL_CLIENTS |	\
						CS_EVENT_CARD_REMOVAL_LOWP)

/*
 * client_info_t structure used by clients for a CS_EVENT_CLIENT_INFO
 *	event and for the GetClientInfo function.
 */
#define	CS_CLIENT_INFO_MAX_NAME_LEN	80
typedef struct client_info_t {
	uint32_t	Attributes;
	uint32_t	Revision;	/* BCD value of client revision */
	uint32_t	CSLevel;	/* BCD value of CS release */
	uint32_t	RevDate;	/* revision date */
	char		ClientName[CS_CLIENT_INFO_MAX_NAME_LEN];
	char		VendorName[CS_CLIENT_INFO_MAX_NAME_LEN];
	char		DriverName[MODMAXNAMELEN];
} client_info_t;

/*
 * Flags for client_info_t->Attributes
 *
 * The low order byte bit values are used to return the data passed
 *	in to RegisterClient in the client_reg_t->Attributes member.
 */
#define	CS_CLIENT_INFO_SOCKET_SERVICES	INFO_SOCKET_SERVICES
#define	CS_CLIENT_INFO_IO_CLIENT	INFO_IO_CLIENT
#define	CS_CLIENT_INFO_MTD_CLIENT	INFO_MTD_CLIENT
#define	CS_CLIENT_INFO_MEM_CLIENT	INFO_MEM_CLIENT
#define	CS_CLIENT_INFO_CSI_CLIENT	INFO_CSI_CLIENT
#define	CS_CLIENT_INFO_CARD_SHARE	INFO_CARD_SHARE
#define	CS_CLIENT_INFO_CARD_EXCL	INFO_CARD_EXCL
#define	CS_CLIENT_INFO_CLIENT_MASK	0x000000ff
/*
 * Control and status flags.
 */
#define	CS_CLIENT_INFO_VALID		0x00010000	/* client info valid */
#define	CS_CLIENT_INFO_CLIENT_ACTIVE	0x00020000	/* client is for card */
#define	CS_CLIENT_INFO_FLAGS_MASK	0xffff0000
/*
 * Client Info subservice flags and types.
 */
#define	CS_CLIENT_INFO_SUBSVC_CS	0x00000000	/* CS client data */
#define	CS_CLIENT_INFO_SUBSVC_MASK	0x0000ff00	/* sub-service mask */
#define	GET_CLIENT_INFO_SUBSVC(s)	(((s) & CS_CLIENT_INFO_SUBSVC_MASK)>>8)
#define	SET_CLIENT_INFO_SUBSVC(s)	(((s)<<8) & CS_CLIENT_INFO_SUBSVC_MASK)

/*
 * CS_CLIENT_INFO_MAKE_DATE - Macro to make constructing the
 *	client_info_t->RevDate member easier. Parameters are:
 *
 *	day - from 1 to 31
 *	month - from 1 to 12
 *	year - year relative to 1980
 *			00 - 1980
 *			06 - 1986
 *			12 = 1992
 *			16 - 1996, etc...
 */
#define	CS_CLIENT_INFO_MAKE_DATE(d, m, y)	(((d) & 0x01f) |	\
						(((m) & 0x0f) << 5) |	\
						(((y) & 0x7f) << 9))
#define	CS_CLIENT_INFO_GET_DAY(d)		((d) & 0x1f)
#define	CS_CLIENT_INFO_GET_MONTH(m)		(((m) >> 5) & 0x0f)
#define	CS_CLIENT_INFO_GET_YEAR(y)		((((y) >> 9) & 0x7f) + 1980)
#define	CS_CLIENT_INFO_GET_YEAR_OFFSET(y)	(((y) >> 9) & 0x7f)

/*
 * get_firstnext_client_t_t structure used for GetFirstClient and GetNextClient
 */
typedef struct get_firstnext_client_t {
	uint32_t	Socket;
	uint32_t	Attributes;
	client_handle_t	client_handle;		/* returned client handle */
	uint32_t	num_clients;
} get_firstnext_client_t;

/*
 * Flags for get_firstnext_client_t->Attributes
 */
#define	CS_GET_FIRSTNEXT_CLIENT_ALL_CLIENTS	0x00000001
#define	CS_GET_FIRSTNEXT_CLIENT_SOCKET_ONLY	0x00000002

/*
 * The client event callback argument structure - this is passed in to
 *	the client event handler.  Most of these arguments are identical
 *	to the PCMCIA-specified arguments.
 */
typedef struct event_callback_args_t {
	client_handle_t	client_handle;
	void		*info;
	void		*mtdrequest;
	void		*buffer;
	void		*misc;
	void		*client_data;
	client_info_t	client_info;
} event_callback_args_t;

/*
 * Event priority flag passed to the client's event handler; the client
 *	uses this priority to determine which mutex to use.
 */
#define	CS_EVENT_PRI_LOW	0x0001
#define	CS_EVENT_PRI_HIGH	0x0002
#define	CS_EVENT_PRI_NONE	0x0004

/*
 * Event-specific event_callback_args_t->info values
 *
 * CS_EVENT_WRITE_PROTECT
 *	CS_EVENT_WRITE_PROTECT_WPOFF - card is not write protected
 *	CS_EVENT_WRITE_PROTECT_WPON - card is write protected
 */
#define	CS_EVENT_WRITE_PROTECT_WPOFF	0x0000
#define	CS_EVENT_WRITE_PROTECT_WPON	0xffff

/*
 * Endinanness and data ordering Attribute bits common to both R2 and
 *	CardBus windows and common to RequestIO, RequestWindow and
 *	DupHandle.
 */
#define	WIN_ACC_ENDIAN_MASK	0x00300000	/* endian mask */
#define	WIN_ACC_NEVER_SWAP	0x00000000	/* i/o access: no swap */
#define	WIN_ACC_BIG_ENDIAN	0x00100000	/* big endian */
#define	WIN_ACC_LITTLE_ENDIAN	0x00200000	/* little endian */

#define	WIN_ACC_ORDER_MASK	0x00700000	/* order mask */
#define	WIN_ACC_STRICT_ORDER	0x00000000	/* strict order */
#define	WIN_ACC_UNORDERED_OK	0x00100000	/* may be re-ordered */
#define	WIN_ACC_MERGING_OK	0x00200000	/* may merge i/o */
#define	WIN_ACC_LOADCACHING_OK	0x00300000	/* may cache reads */
#define	WIN_ACC_STORECACHING_OK	0x00400000	/* may cache all i/o */

/*
 * io_req_t structure used for RequestIO and ReleaseIO
 */
typedef struct io_req_t {
	uint32_t	Socket;
	baseaddru_t	BasePort1;
	uint32_t	NumPorts1;	/* 1st IO range no. contiguous ports */
	uint32_t	Attributes1;	/* 1st IO range attributes */
	baseaddru_t	BasePort2;
	uint32_t	NumPorts2;	/* 2nd IO range no. contiguous ports */
	uint32_t	Attributes2;	/* 2nd IO range attributes */
	uint32_t	IOAddrLines;	/* number of IO address lines decoded */
} io_req_t;

/*
 * Flags for RequestIO and ReleaseIO
 */
#define	IO_DATA_WIDTH_MASK	0x00000001	/* data path width mask */
#define	IO_DATA_WIDTH_8		0x00000000	/* 8 bit data path */
#define	IO_DATA_WIDTH_16	0x00000001	/* 16 bit data path */

/*
 * The following flags are included for compatability with other versions of
 *	Card Services, but they are not implemented in this version.  They
 *	are assigned values as placeholders only.  If any of these flags
 *	are set on a call to RequestIO, CS_BAD_ATTRIBUTE is returned.
 */
#define	IO_SHARED		0x00010000	/* for compatability only */
#define	IO_FIRST_SHARED		0x00020000	/* for compatability only */
#define	IO_FORCE_ALIAS_ACCESS	0x00040000	/* for compatability only */

/*
 * The following flags are private to Card Services and should never be set
 *	by a client.  Doing so will cause the system to take a supervisor
 *	trap at level twenty-nine.
 */
#define	IO_DEALLOCATE_WINDOW	0x10000000	/* CS private */
#define	IO_DISABLE_WINDOW	0x20000000	/* CS private */

/*
 * win_req_t structure used for RequestWindow
 *
 * Note that the ReqOffset member is not defined in the current PCMCIA
 *	spec but is included here to aid clients in determining the
 *	optimum offset to give to MapMemPage.
 */
typedef struct win_req_t {
	uint32_t	Socket;
	uint32_t	Attributes;	/* window flags */
	union {
	    uint32_t		base;	/* requested window base address */
	    acc_handle_t	handle;	/* access handle for base of window */
	} Base;
	uint32_t	Size;		/* window size requested/granted */
	union {
	    uint32_t		AccessSpeed;	/* window access speed */
	    uint32_t		IOAddrLines;	/* for I/O windows only */
	} win_params;
	uint32_t	ReqOffset;	/* required window offest */
} win_req_t;

/*
 * modify_win_t structure used for ModifyWindow
 */
typedef struct modify_win_t {
	uint32_t	Attributes;	/* window flags */
	uint32_t	AccessSpeed;	/* window access speed */
} modify_win_t;

/*
 * Flags for RequestWindow and ModifyWindow
 */
#define	WIN_MEMORY_TYPE_MASK	0x00000021	/* window type mask */
#define	WIN_MEMORY_TYPE_CM	0x00000000	/* window points to CM */
#define	WIN_MEMORY_TYPE_AM	0x00000001	/* window points to AM */
#define	WIN_MEMORY_TYPE_IO	0x00000020	/* window points to IO */

#define	WIN_DATA_WIDTH_MASK	0x00000042	/* data path width mask */
#define	WIN_DATA_WIDTH_8	0x00000000	/* 8-bit data path */
#define	WIN_DATA_WIDTH_16	0x00000002	/* 16-bit data path */
#define	WIN_DATA_WIDTH_32	0x00000040	/* 32-bit data path */

#define	WIN_ENABLE		0x00000004	/* enable/disable window */
#define	WIN_OFFSET_SIZE		0x00000008	/* card offsets window sized */
#define	WIN_ACCESS_SPEED_VALID	0x00000010	/* speed valid (ModifyWindow) */

#define	WIN_PREFETCH_CACHE_MASK	0x00000300	/* prefetch/cache mask */
#define	WIN_PREFETCH		0x00000100	/* prefetchable not cacheable */
#define	WIN_PREFETCH_CACHE	0x00000200	/* prefetchable and cacheable */

#define	WIN_BAR_MASK		0x00007000	/* Base Address Register mask */
#define	WIN_BAR_1		0x00001000	/* Base Address Register 1 */
#define	WIN_BAR_2		0x00002000	/* Base Address Register 2 */
#define	WIN_BAR_3		0x00003000	/* Base Address Register 3 */
#define	WIN_BAR_4		0x00004000	/* Base Address Register 4 */
#define	WIN_BAR_5		0x00005000	/* Base Address Register 5 */
#define	WIN_BAR_6		0x00006000	/* Base Address Register 6 */
#define	WIN_BAR_7		0x00007000	/* Base Address Register 7 */

/*
 * The following flag is used internally by Card Services and should never
 *	be set by the caller.
 */
#define	WIN_DATA_WIDTH_VALID	0x00008000	/* CS internal */

/*
 * The following flags are included for compatability with other versions of
 *	Card Services, but they are not implemented in this version.  They
 *	are assigned values as placeholders only.  If any of these flags
 *	are set on a call to RequestWindow, CS_BAD_ATTRIBUTE is returned.
 */
#define	WIN_PAGED		0x00010000	/* for compatability only */
#define	WIN_SHARED		0x00020000	/* for compatability only */
#define	WIN_FIRST_SHARED	0x00040000	/* for compatability only */
#define	WIN_BINDING_SPECIFIC	0x00080000	/* for compatability only */

/*
 * The following flag is actually part of the AccessSpeed member
 */
#define	WIN_USE_WAIT		0x80	/* use window that supports WAIT */

/*
 * client_reg_t structure for RegisterClient
 */
typedef struct client_reg_t {
	uint32_t		Attributes;
	uint32_t		EventMask;
	event_callback_args_t	event_callback_args;
	uint32_t		Version;	/* CS version to expect */
	csfunction_t		*event_handler;
	/* DDI support */
	ddi_iblock_cookie_t	*iblk_cookie;	/* event iblk cookie */
	ddi_idevice_cookie_t	*idev_cookie;	/* event idev cookie */
	dev_info_t		*dip;		/* client's dip */
	char			driver_name[MODMAXNAMELEN];
	/* CS private */
	void			*priv;		/* CS private data */
} client_reg_t;

/*
 * Flags for RegisterClient - some of these flags are also used internally
 *	by CS to sequence the order of event callbacks and to allow Socket
 *	Services to register as a "super" client.
 *
 * The client_reg_t->Attributes structure member uses these flags.
 *
 * The client_info_t->Attributes, client_types_t->type and client_t->flags
 *	tructure members use these flags as well.
 *
 * Client types - mutually exclusive.
 */
#define	INFO_SOCKET_SERVICES	0x00000001
#define	INFO_IO_CLIENT		0x00000002
#define	INFO_MTD_CLIENT		0x00000004
#define	INFO_MEM_CLIENT		0x00000008
#define	INFO_CSI_CLIENT		0x00000010
#define	INFO_CLIENT_TYPE_MASK	(INFO_SOCKET_SERVICES |		\
					INFO_IO_CLIENT |	\
					INFO_MTD_CLIENT	|	\
					INFO_MEM_CLIENT |	\
					INFO_CSI_CLIENT)
#define	MAX_CLIENT_TYPES	3	/* doesn't include SS or CSI clients */

/*
 * The following two are for backwards-compatability with the PCMCIA spec.
 *	We will give the client CARD_INSERTION and REGISTRATION_COMPLETE
 *	if either of these two bits are set.  Normally, all IO and MEM
 *	clients should set both of these bits.
 */
#define	INFO_CARD_SHARE		0x00000020
#define	INFO_CARD_EXCL		0x00000040
#define	INFO_CARD_FLAGS_MASK	(INFO_CARD_SHARE | INFO_CARD_EXCL)

/*
 * tuple_t struct used for GetFirstTuple, GetNextTuple, GetTupleData
 *	and ParseTuple
 *
 * Note that the values for DesiredTuple are defined in the cis.h header
 *	file.
 */
typedef struct tuple_t {
	uint32_t	Socket;		/* socket number to get tuple from */
	uint32_t	Attributes;	/* tuple return attributes */
	cisdata_t	DesiredTuple;	/* tuple to search for or flags */
	cisdata_t	TupleOffset;	/* offset in tuple data body */
	uint32_t	Flags;		/* CS private */
	cistpl_t	*LinkOffset;	/* CS private */
	cistpl_t	*CISOffset;	/* CS private */
	cisdata_t	TupleDataMax;	/* max size of tuple data area */
	cisdata_t	TupleDataLen;	/* actual size of tuple data area */
					/* tuple body data buffer */
	cisdata_t	TupleData[CIS_MAX_TUPLE_DATA_LEN];
	cisdata_t	TupleCode;	/* tuple type code */
	cisdata_t	TupleLink;	/* tuple data body size */
} tuple_t;

/*
 * Attribute flags definitions for CS tuple functions.
 *
 */
#define	TUPLE_RETURN_LINK		0x00000002 /* return link tuples */
#define	TUPLE_RETURN_IGNORED_TUPLES	0x00010000 /* return ignored tuples */
#define	TUPLE_RETURN_NAME		0x00020000 /* return tuple name */

/*
 * cisinfo_t structure used for ValidateCIS
 */
typedef struct cisinfo_t {
	uint32_t	Socket;		/* socket number to validate CIS on */
	uint32_t	Chains;		/* number of tuple chains in CIS */
	uint32_t	Tuples;		/* total number of tuples in CIS */
} cisinfo_t;

/*
 * map_mem_page_t structure used for MapMemPage
 */
typedef struct map_mem_page_t {
	uint32_t	CardOffset;	/* card offset */
	uint32_t	Page;		/* page number */
} map_mem_page_t;

/*
 * sockevent_t structure used for GetEventMask and SetEventMask
 */
typedef struct sockevent_t {
	uint32_t	Attributes;	/* attribute flags for call */
	uint32_t	EventMask;	/* event mask to set or return */
	uint32_t	Socket;		/* socket number if necessary */
} sockevent_t;

/*
 * request_socket_mask_t structure used for RequestSocketMask
 */
typedef struct request_socket_mask_t {
	uint32_t	Socket;		/* socket number if necessary */
	uint32_t	EventMask;	/* event mask to set or return */
} request_socket_mask_t;

/*
 * release_socket_mask_t structure used for ReleaseSocketMask
 */
typedef struct release_socket_mask_t {
	uint32_t	Socket;
} release_socket_mask_t;

/*
 * Flags for GetEventMask and SetEventMask
 */
#define	CONF_EVENT_MASK_GLOBAL	0x00000000	/* global event mask */
#define	CONF_EVENT_MASK_CLIENT	0x00000001	/* client event mask */
#define	CONF_EVENT_MASK_VALID	0x00000001	/* client event mask */

/*
 * convert_speed_t structure used for ConvertSpeed
 */
typedef struct convert_speed_t {
	uint32_t	Attributes;
	uint32_t	nS;
	uint32_t	devspeed;
} convert_speed_t;

/*
 * Flags for ConvertSpeed
 */
#define	CONVERT_NS_TO_DEVSPEED	0x00000001
#define	CONVERT_DEVSPEED_TO_NS	0x00000002

/*
 * convert_size_t structure used for ConvertSize
 */
typedef struct convert_size_t {
	uint32_t	Attributes;
	uint32_t	bytes;
	uint32_t	devsize;
} convert_size_t;

/*
 * Flags for ConvertSize
 */
#define	CONVERT_BYTES_TO_DEVSIZE	0x00000001
#define	CONVERT_DEVSIZE_TO_BYTES	0x00000002

#define	MAX_CS_EVENT_BUFSIZE		64	/* single event */
#define	MAX_MULTI_EVENT_BUFSIZE		512	/* all events */

#define	CS_EVENT_MAX_BUFSIZE	MAX_MULTI_EVENT_BUFSIZE
#define	CS_ERROR_MAX_BUFSIZE	MAX_CS_EVENT_BUFSIZE

/*
 * event2text_t structure used for Event2Text
 */
typedef struct event2text_t {
	event_t		event;		/* events */
					/* buffer to return text strings */
	char		text[CS_EVENT_MAX_BUFSIZE];
} event2text_t;

/*
 * error2text_t structure used for Error2Text
 */
typedef struct error2text_t {
	uint32_t	item;
	char		text[CS_ERROR_MAX_BUFSIZE];
} error2text_t;

/*
 * get_status_t structure used for GetStatus
 *
 * The values in the status members are the same as the CS_EVENT_XXX values.
 */
typedef struct get_status_t {
	uint32_t	Socket;
	uint32_t	CardState;	/* "live" card status for this client */
	uint32_t	SocketState;	/* latched socket values */
	uint32_t	raw_CardState;	/* raw live card status */
} get_status_t;

/*
 * GetStatus returns card state using the same bit definitions
 *	as the CS_EVENT_XXX bits. Some of the CS_EVENT_XXX bits
 *	are not meaningful for GetStatus and are reused here for
 *	status definitions.
 *
 * get_status_t->CardState and get_status_t->raw_CardState bits
 */
#define	CS_STATUS_WRITE_PROTECTED	CS_EVENT_WRITE_PROTECT
#define	CS_STATUS_CARD_LOCKED		CS_EVENT_CARD_LOCK
#define	CS_STATUS_EJECTION_REQUEST	CS_EVENT_EJECTION_REQUEST
#define	CS_STATUS_INSERTION_REQUEST	CS_EVENT_INSERTION_REQUEST
#define	CS_STATUS_BATTERY_DEAD		CS_EVENT_BATTERY_DEAD
#define	CS_STATUS_BATTERY_LOW		CS_EVENT_BATTERY_LOW
#define	CS_STATUS_CARD_READY		CS_EVENT_CARD_READY
#define	CS_STATUS_CARD_INSERTED		CS_EVENT_CARD_INSERTION
#define	CS_STATUS_RES_EVT1		0x00100000
#define	CS_STATUS_RES_EVT2		0x00200000
#define	CS_STATUS_RES_EVT3		0x00400000
#define	CS_STATUS_VCC_50		0x10000000
#define	CS_STATUS_VCC_33		0x20000000
#define	CS_STATUS_VCC_XX		0x40000000
#define	CS_STATUS_REQ_ATTN		0x80000000
/*
 * get_status_t->SocketState bits
 */
#define	CS_SOCK_STATUS_WRITE_PROTECT_CHANGE	CS_EVENT_WRITE_PROTECT
#define	CS_SOCK_STATUS_CARD_LOCK_CHNAGE		CS_EVENT_CARD_LOCK
#define	CS_SOCK_STATUS_EJECTION_PENDING		CS_EVENT_EJECTION_REQUEST
#define	CS_SOCK_STATUS_INSERTION_PENDING	CS_EVENT_INSERTION_REQUEST
#define	CS_SOCK_STATUS_BATTERY_DEAD_CHNAGE	CS_EVENT_BATTERY_DEAD
#define	CS_SOCK_STATUS_BATTERY_LOW_CHNAGE	CS_EVENT_BATTERY_LOW
#define	CS_SOCK_STATUS_CARD_READY_CHANGE	CS_EVENT_CARD_READY
#define	CS_SOCK_STATUS_CARD_DETECT_CHNAGE	CS_EVENT_CARD_INSERTION

/*
 * map_log_socket_t structure used for MapLogSocket
 */
typedef struct map_log_socket_t {
	uint32_t	LogSocket;	/* logical socket */
	uint32_t	PhyAdapter;	/* physical adapter */
	uint32_t	PhySocket;	/* physical socket */
} map_log_socket_t;

/*
 * get_physical_adapter_info_t structure used for GetPhysicalAdapterInfo
 */
typedef struct get_physical_adapter_info_t {
	uint32_t	LogSocket;	/* logical socket */
	uint32_t	PhySocket;	/* physical socket */
	uint32_t	flags;		/* adapter flags */
	char		name[MODMAXNAMELEN]; /* adapter module name */
	uint32_t	major;		/* adapter major number */
	uint32_t	minor;		/* adapter minor number */
	uint32_t	instance;	/* instance number of this adapter */
	uint32_t	number;		/* canonical adapter number */
	uint32_t	num_sockets;	/* # sockets on this adapter */
	uint32_t	first_socket;	/* first socket # on this adapter */
} get_physical_adapter_info_t;

/*
 * irq_req_t structure used for RequestIRQ and ReleaseIRQ
 */
typedef struct irq_req_t {
	uint32_t		Socket;
	uint32_t		Attributes;	/* IRQ attribute flags */
	csfunction_t		*irq_handler;
	void			*irq_handler_arg;
	ddi_iblock_cookie_t	*iblk_cookie;	/* IRQ iblk cookie */
	ddi_idevice_cookie_t	*idev_cookie;	/* IRQ idev cookie */
} irq_req_t;

/*
 * Flags for RequestIRQ and ReleaseIRQ
 */
#define	IRQ_TYPE_EXCLUSIVE		0x00000002
/*
 * The following flags are included for compatability with other versions of
 *	Card Services, but they are not implemented in this version.  They
 *	are assigned values as placeholders only.  If any of these flags
 *	are set on a call to RequestIRQ, CS_BAD_ATTRIBUTE is returned.
 */
#define	IRQ_FORCED_PULSE		0x00010000
#define	IRQ_TYPE_TIME			0x00020000
#define	IRQ_TYPE_DYNAMIC_SHARING	0x00040000
#define	IRQ_FIRST_SHARED		0x00080000
#define	IRQ_PULSE_ALLOCATED		0x00100000

/*
 * release_config_t structure used for ReleaseConfiguration
 */
typedef struct release_config_t {
	uint32_t	Socket;
} release_config_t;

/*
 * config_req_t structure used for RequestConfiguration
 */
typedef struct config_req_t {
	uint32_t	Socket;
	uint32_t	Attributes;	/* configuration attributes */
	uint32_t	Vcc;		/* Vcc value */
	uint32_t	Vpp1;		/* Vpp1 value */
	uint32_t	Vpp2;		/* Vpp2 value */
	uint32_t	IntType;	/* socket interface type - mem or IO */
	uint32_t	ConfigBase;	/* offset from start of AM space */
	uint32_t	Status;		/* value to write to STATUS register */
	uint32_t	Pin;		/* value to write to PRR */
	uint32_t	Copy;		/* value to write to COPY register */
	uint32_t	ConfigIndex;	/* value to write to COR */
	uint32_t	Present;	/* which config registers present */
	uint32_t	ExtendedStatus;	/* value to write to EXSTAT register */
} config_req_t;

/*
 * Flags for RequestConfiguration - note that the CONF_ENABLE_IRQ_STEERING
 *	flag shares the same bit field as the Attributes flags for
 *	ModifyConfiguration.
 */
#define	CONF_ENABLE_IRQ_STEERING	0x00010000
/*
 * The following flags are used for the IntType member to specify which
 *	type of socket interface the client wants.
 */
#define	SOCKET_INTERFACE_MEMORY		0x00000001
#define	SOCKET_INTERFACE_MEMORY_AND_IO	0x00000002
/*
 * The following flags are used for the Present member to specify which
 *	configuration registers are present.  They may also be used by
 *	clients for their internal state.
 */
#define	CONFIG_OPTION_REG_PRESENT	0x00000001 /* COR present */
#define	CONFIG_STATUS_REG_PRESENT	0x00000002 /* STAT reg present */
#define	CONFIG_PINREPL_REG_PRESENT	0x00000004 /* PRR present */
#define	CONFIG_COPY_REG_PRESENT		0x00000008 /* COPY reg present */
#define	CONFIG_EXSTAT_REG_PRESENT	0x00000010 /* EXSTAT reg present */
#define	CONFIG_IOBASE0_REG_PRESENT	0x00000020 /* IOBASE0 reg present */
#define	CONFIG_IOBASE1_REG_PRESENT	0x00000040 /* IOBASE1 reg present */
#define	CONFIG_IOBASE2_REG_PRESENT	0x00000080 /* IOBASE2 reg present */
#define	CONFIG_IOBASE3_REG_PRESENT	0x00000100 /* IOBASE3 reg present */
#define	CONFIG_IOLIMIT_REG_PRESENT	0x00000200 /* IOLIMIT reg present */

/*
 * CONFIG_IOBASE_REG_MASK - mask of IO Base Port register present bits
 * CONFIG_IOBASE_REG_SHIFT - shifts IO Base Port register present bits
 */
#define	CONFIG_IOBASE_REG_MASK		0x000001e0 /* IOBASEn present mask */
#define	CONFIG_IOBASE_REG_SHIFT		5

/*
 * Bit definitions for configuration registers.
 *
 * Pin Replacement Register (PRR) bits - these are used for calls to
 *	RequestConfiguration, AccessConfigurationRegister and
 *	GetConfigurationInfo, as well as internally by clients
 *	and Card Services.
 * To inform Card Services that a particular bit in the PRR is valid on
 *	a call to RequestConfiguration, both the XXX_STATUS and the
 *	XXX_EVENT bits must be set.
 */
#define	PRR_WP_STATUS		0x01	/* R-WP state W-write WP Cbit */
#define	PRR_READY_STATUS	0x02	/* R-READY state W-write READY Cbit */
#define	PRR_BVD2_STATUS		0x04	/* R-BVD2 state W-write BVD2 Cbit */
#define	PRR_BVD1_STATUS		0x08	/* R-BVD1 state W-write BVD1 Cbit */
#define	PRR_WP_EVENT		0x10	/* WP changed */
#define	PRR_READY_EVENT		0x20	/* READY changed */
#define	PRR_BVD2_EVENT		0x40	/* BVD2 changed */
#define	PRR_BVD1_EVENT		0x80	/* BVD1 changed */
/*
 * Configuration Option Register (COR) bits
 */
#define	COR_ENABLE_FUNCTION	0x01	/* enable function */
#define	COR_ENABLE_BASE_LIMIT	0x02	/* enable base and limit registers */
#define	COR_ENABLE_IREQ_ROUTING	0x04	/* enable IREQ routing */
#define	COR_STATUS_CHANGE_MODE	0x08	/* status change mode */
#define	COR_LEVEL_IRQ		0x40	/* set to enable level interrupts */
#define	COR_SOFT_RESET		0x80	/* soft reset bit */
/*
 * Card Configuration Status Register (CCSR)
 */
#define	CCSR_INTR_ACK		0x01	/* interrupt acknowledge */
#define	CCSR_INTR		0x02	/* interrupt pending */
#define	CCSR_POWER_DOWN		0x04	/* power down card */
#define	CCSR_AUDIO		0x08	/* enable Audio signal */
#define	CCSR_IO_IS_8		0x20	/* only 8-bit IO data path */
#define	CCSR_SIG_CHG		0x40	/* enable status changes */
#define	CCSR_CHANGED		0x80	/* one of the PRR bits has changed */
/*
 * Macros to manipulate the Socket and Copy Register (SCR) values
 */
#define	SCR_GET_SOCKET(r)		((r)&0x0f)
#define	SCR_GET_COPY(r)			(((r)>>4)&7)
#define	SCR_SET_SOCKET(s)		((s)&0x0f)
#define	SCR_SET_COPY(c)			(((c)&7)<<4)
#define	SCR_SET_SOCKET_COPY(s, c)	(((s)&0x0f) | (((c)&7)<<4))

/*
 * modify_config_t structure used for ModifyConfiguration
 */
typedef struct modify_config_t {
	uint32_t	Socket;
	uint32_t	Attributes;	/* attributes to modify */
	uint32_t	Vpp1;		/* Vpp1 value */
	uint32_t	Vpp2;		/* Vpp2 value */
} modify_config_t;

/*
 * Flags for ModifyConfiguration - note that the CONF_ENABLE_IRQ_STEERING
 *	flag used with RequestConfiguration shares this bit field.
 */
#define	CONF_VPP1_CHANGE_VALID		0x00000002	/* Vpp1 is valid */
#define	CONF_VPP2_CHANGE_VALID		0x00000004	/* Vpp2 is valid */
#define	CONF_IRQ_CHANGE_VALID		0x00000008	/* IRQ is valid */

/*
 * access_config_reg_t structure used for AccessConfigurationRegister
 */
typedef struct access_config_reg_t {
	uint32_t	Socket;
	uint32_t	Action;		/* register access operation */
	uint32_t	Offset;		/* config register offset */
	uint32_t	Value;		/* value read or written */
} access_config_reg_t;
/*
 * Flags for AccessConfigurationRegister
 */
#define	CONFIG_REG_READ		0x00000001	/* read config register */
#define	CONFIG_REG_WRITE	0x00000002	/* write config register */
/*
 * The following offsets are used to specify the configuration register
 *	offset to AccessConfigurationRegister
 */
#define	CONFIG_OPTION_REG_OFFSET	0x00	/* COR offset */
#define	CONFIG_STATUS_REG_OFFSET	0x02	/* STAT reg offset */
#define	CONFIG_PINREPL_REG_OFFSET	0x04	/* PRR offset */
#define	CONFIG_COPY_REG_OFFSET		0x06	/* COPY reg offset */
#define	CONFIG_EXSTAT_REG_OFFSET	0x08	/* EXSTAT reg offset */
#define	CONFIG_IOBASE0_REG_OFFSET	0x0a	/* IOBASE0 reg offset */
#define	CONFIG_IOBASE1_REG_OFFSET	0x0c	/* IOBASE1 reg offset */
#define	CONFIG_IOBASE2_REG_OFFSET	0x0e	/* IOBASE2 reg offset */
#define	CONFIG_IOBASE3_REG_OFFSET	0x10	/* IOBASE3 reg offset */
#define	CONFIG_IOLIMIT_REG_OFFSET	0x12	/* IOLIMIT reg offset */

/*
 * reset_function_t structure used for ResetFunction
 */
typedef struct reset_function_t {
	uint32_t	Socket;
	uint32_t	Attributes;
} reset_function_t;

/*
 * get_cardservices_info_t structure used for GetCardServicesInfo
 */
#define	CS_GET_CARDSERVICES_INFO_MAX_VS_LEN	512
typedef struct get_cardservices_info_t {
	char		Signature[2];	/* CS signature bytes */
	uint32_t	NumSockets;	/* number of sockets */
	uint32_t	Revision;	/* BCD value of CS revision */
	uint32_t	CSLevel;	/* BCD value of CS release */
	uint32_t	FuncsPerSocket;	/* max number of functions per socket */
	char		VendorString[CS_GET_CARDSERVICES_INFO_MAX_VS_LEN];
} get_cardservices_info_t;

/*
 * get_configuration_info_t structure used by GetConfigurationInfo
 */
typedef struct get_configuration_info_t {
	uint32_t	Socket;		/* Socket/function to get info for */
	uint32_t	Attributes;	/* configuration attributes */
	uint32_t	Vcc;		/* Vcc value */
	uint32_t	Vpp1;		/* Vpp1 value */
	uint32_t	Vpp2;		/* Vpp2 value */
	uint32_t	IntType;	/* memory only or memory and IO ifc */
	uint32_t	ConfigBase;	/* offset from start of AM space */
	uint32_t	Status;		/* value written to STATUS register */
	uint32_t	Pin;		/* value written to PRR */
	uint32_t	Copy;		/* value to written COPY register */
	uint32_t	Option;		/* which written to COR */
	uint32_t	Present;	/* which config registers present */
	uint32_t	FirstDevType;	/* from CISTPL_DEVICE */
	uint32_t	FuncCode;	/* from CISTPL_FUNCID */
	uint32_t	SysInitMask;	/* from CISTPL_FUNCID */
	uint32_t	ManufCode;	/* from CISTPL_MANFID */
	uint32_t	ManufInfo;	/* from CISTPL_MANFID */
	uint32_t	CardValues;	/* which config registers written */
	uint32_t	AssignedIRQ;	/* IRQ assigned to card */
	uint32_t	IRQ_Attributes;	/* IRQ attributes */
	uint32_t	BasePort1;	/* address of 1st IO range */
	uint32_t	NumPorts1;	/* 1st IO range no. contiguous ports */
	uint32_t	Attributes1;	/* 1st IO range attributes */
	uint32_t	BasePort2;	/* address of 2nd IO range */
	uint32_t	NumPorts2;	/* 2nd IO range no. contiguous ports */
	uint32_t	Attributes2;	/* 2nd IO range attributes */
	uint32_t	IOAddrLines;	/* number of IO address lines decoded */
	uint32_t	ExStat;		/* value written to EXSTAT register */
	uint32_t	DMA_Attributes;	/* signals used for DMA */
	uint32_t	DMA_Assign_Chan;	/* assigned DMA channel */
	uint32_t	NumIOWindows;	/* number of IO windows in use */
	uint32_t	NumMemWindows;	/* number of memory windows in use */
} get_configuration_info_t;

/*
 * devnode_desc_t structure used in make_device_node_t and remove_device_node_t
 *	for MakeDeviceNode and RemoveDeviceNode
 */
typedef struct devnode_desc_t {
	char	*name;		/* device node path and name */
	int32_t	spec_type;	/* dev special type (block or char) */
	int32_t	minor_num;	/* device node minor number */
	char	*node_type;	/* device node type */
} devnode_desc_t;

/*
 * make_device_node_t structure used for MakeDeviceNode
 */
typedef struct make_device_node_t {
	uint32_t	Action;		/* device operation */
	uint32_t	NumDevNodes;	/* number of nodes to create */
	devnode_desc_t	*devnode_desc;	/* description of device nodes */
} make_device_node_t;
/*
 * Action values for MakeDeviceNode
 */
#define	CREATE_DEVICE_NODE		0x01	/* create device node */

/*
 * remove_device_node_t structure used for RemoveDeviceNode
 */
typedef struct remove_device_node_t {
	uint32_t	Action;		/* device operation */
	uint32_t	NumDevNodes;	/* number of nodes to remove */
	devnode_desc_t	*devnode_desc;	/* description of device nodes */
} remove_device_node_t;
/*
 * Action values for RemoveDeviceNode
 *
 * Note: The "Action" member for make_device_node_t and remove_device_node_t
 *		share the same set of values.
 */
#define	REMOVE_DEVICE_NODE		0x02	/* remove device node */
#define	REMOVE_ALL_DEVICE_NODES		0x03	/* remove all device nodes */

/*
 * cs_ddi_info_t for CS_DDI_Info
 */
typedef struct cs_ddi_info_t {
	uint32_t	Socket;		/* socket number */
	char		*driver_name;	/* unique driver name */
	dev_info_t	*dip;		/* dip */
	int32_t		instance;	/* instance */
} cs_ddi_info_t;

/*
 * cs_sys_ctl_t for CS_Sys_Ctl
 */
typedef struct cs_sys_ctl_t {
	uint32_t	Socket;
	uint32_t	Action;
	uint32_t	Flags;
	uint32_t	Events;
	client_handle_t	client_handle;
} cs_sys_ctl_t;
/*
 * cs_sys_ctl_t->Action defines
 *
 * CS_SYS_CTL_SEND_EVENT - send events in cs_sys_ctl_t->Events to clients
 */
#define	CS_SYS_CTL_SEND_EVENT	0x0001	/* simulate events */
/*
 * cs_sys_ctl_t->Flags defines
 *
 * CS_SYS_CTL_WAIT_SYNC - wait for operation to complete, otherwise
 *	return immediately
 * CS_SYS_CTL_EVENT_SOCKET - send events to all clients on specified
 *	socket
 * CS_SYS_CTL_EVENT_CLIENT - send events to client specified by
 *	cs_sys_ctl_t->client_handle
 */
#define	CS_SYS_CTL_WAIT_SYNC	0x00000001	/* synchornize with thread */
#define	CS_SYS_CTL_EVENT_SOCKET	0x00000002	/* to all clients on socket */
#define	CS_SYS_CTL_EVENT_CLIENT	0x00000004	/* to client specified */

/*
 * Autoincrement control flags for RepPut8, RepPut16, RepPut32, RepPut32,
 *	RepGet8, RepGet16, RepGet32, RepGet64
 */
#define	CS_DEV_AUTOINCR		DDI_DEV_AUTOINCR
#define	CS_DEV_NO_AUTOINCR	DDI_DEV_NO_AUTOINCR

/*
 * Card Services function prototypes
 */
int32_t csx_RegisterClient(client_handle_t *, client_reg_t *);
int32_t csx_DeregisterClient(client_handle_t);
int32_t csx_GetStatus(client_handle_t, get_status_t *);
int32_t csx_SetEventMask(client_handle_t, sockevent_t *);
int32_t csx_GetEventMask(client_handle_t, sockevent_t *);
int32_t csx_RequestIO(client_handle_t, io_req_t *);
int32_t csx_ReleaseIO(client_handle_t, io_req_t *);
int32_t csx_RequestIRQ(client_handle_t, irq_req_t *);
int32_t csx_ReleaseIRQ(client_handle_t, irq_req_t *);
int32_t csx_RequestWindow(client_handle_t, window_handle_t *, win_req_t *);
int32_t csx_ReleaseWindow(window_handle_t);
int32_t csx_ModifyWindow(window_handle_t, modify_win_t *);
int32_t csx_MapMemPage(window_handle_t, map_mem_page_t *);
int32_t csx_RequestSocketMask(client_handle_t, request_socket_mask_t *);
int32_t csx_ReleaseSocketMask(client_handle_t, release_socket_mask_t *);
int32_t csx_RequestConfiguration(client_handle_t, config_req_t *);
int32_t csx_ModifyConfiguration(client_handle_t, modify_config_t *);
int32_t csx_ReleaseConfiguration(client_handle_t, release_config_t *);
int32_t csx_AccessConfigurationRegister(client_handle_t, access_config_reg_t *);
int32_t csx_GetFirstTuple(client_handle_t, tuple_t *);
int32_t csx_GetNextTuple(client_handle_t, tuple_t *);
int32_t csx_GetTupleData(client_handle_t, tuple_t *);
int32_t csx_MapLogSocket(client_handle_t, map_log_socket_t *);
int32_t csx_ValidateCIS(client_handle_t, cisinfo_t *);
int32_t csx_MakeDeviceNode(client_handle_t, make_device_node_t *);
int32_t csx_RemoveDeviceNode(client_handle_t, remove_device_node_t *);
int32_t csx_ConvertSpeed(convert_speed_t *);
int32_t csx_ConvertSize(convert_size_t *);
int32_t csx_Event2Text(event2text_t *);
int32_t csx_Error2Text(error2text_t *);
int32_t csx_CS_DDI_Info(cs_ddi_info_t *);
int32_t csx_CS_Sys_Ctl(cs_sys_ctl_t *);
int32_t csx_ResetFunction(client_handle_t, reset_function_t *);
int32_t csx_GetFirstClient(get_firstnext_client_t *);
int32_t csx_GetNextClient(get_firstnext_client_t *);
int32_t csx_GetClientInfo(client_handle_t, client_info_t *);
int32_t csx_GetCardServicesInfo(client_handle_t, get_cardservices_info_t *);
int32_t csx_GetConfigurationInfo(client_handle_t *, get_configuration_info_t *);
int32_t csx_GetPhysicalAdapterInfo(client_handle_t,
					get_physical_adapter_info_t *);

/*
 * CIS tuple parsing functions
 */
int32_t csx_Parse_CISTPL_CONFIG(client_handle_t, tuple_t *, cistpl_config_t *);
int32_t csx_Parse_CISTPL_DEVICE(client_handle_t, tuple_t *, cistpl_device_t *);
int32_t csx_Parse_CISTPL_DEVICE_A(client_handle_t, tuple_t *,
					cistpl_device_t *);
int32_t csx_Parse_CISTPL_DEVICE_OA(client_handle_t, tuple_t *,
					cistpl_device_t *);
int32_t csx_Parse_CISTPL_DEVICE_OC(client_handle_t, tuple_t *,
					cistpl_device_t *);
int32_t csx_Parse_CISTPL_VERS_1(client_handle_t, tuple_t *, cistpl_vers_1_t *);
int32_t csx_Parse_CISTPL_VERS_2(client_handle_t, tuple_t *, cistpl_vers_2_t *);
int32_t csx_Parse_CISTPL_JEDEC_A(client_handle_t, tuple_t *, cistpl_jedec_t *);
int32_t csx_Parse_CISTPL_JEDEC_C(client_handle_t, tuple_t *, cistpl_jedec_t *);
int32_t csx_Parse_CISTPL_FORMAT(client_handle_t, tuple_t *, cistpl_format_t *);
int32_t csx_Parse_CISTPL_FORMAT_A(client_handle_t, tuple_t *,
					cistpl_format_t *);
int32_t csx_Parse_CISTPL_GEOMETRY(client_handle_t, tuple_t *,
					cistpl_geometry_t *);
int32_t csx_Parse_CISTPL_BYTEORDER(client_handle_t, tuple_t *,
					cistpl_byteorder_t *);
int32_t csx_Parse_CISTPL_DATE(client_handle_t, tuple_t *, cistpl_date_t *);
int32_t csx_Parse_CISTPL_BATTERY(client_handle_t, tuple_t *,
					cistpl_battery_t *);
int32_t csx_Parse_CISTPL_ORG(client_handle_t, tuple_t *, cistpl_org_t *);
int32_t csx_Parse_CISTPL_MANFID(client_handle_t, tuple_t *, cistpl_manfid_t *);
int32_t csx_Parse_CISTPL_FUNCID(client_handle_t, tuple_t *, cistpl_funcid_t *);
int32_t csx_Parse_CISTPL_FUNCE(client_handle_t, tuple_t *, cistpl_funce_t *,
					uint32_t);
int32_t csx_Parse_CISTPL_CFTABLE_ENTRY(client_handle_t, tuple_t *,
					cistpl_cftable_entry_t *);
int32_t csx_Parse_CISTPL_LINKTARGET(client_handle_t, tuple_t *,
					cistpl_linktarget_t *);
int32_t csx_Parse_CISTPL_LONGLINK_A(client_handle_t, tuple_t *,
					cistpl_longlink_ac_t *);
int32_t csx_Parse_CISTPL_LONGLINK_C(client_handle_t, tuple_t *,
					cistpl_longlink_ac_t *);
int32_t csx_Parse_CISTPL_LONGLINK_MFC(client_handle_t, tuple_t *,
					cistpl_longlink_mfc_t *);
int32_t csx_Parse_CISTPL_SPCL(client_handle_t, tuple_t *,
					cistpl_spcl_t *);
int32_t csx_Parse_CISTPL_SWIL(client_handle_t, tuple_t *,
					cistpl_swil_t *);
int32_t csx_Parse_CISTPL_BAR(client_handle_t, tuple_t *,
					cistpl_bar_t *);
int32_t csx_Parse_CISTPL_DEVICEGEO(client_handle_t, tuple_t *,
					cistpl_devicegeo_t *);
int32_t csx_Parse_CISTPL_DEVICEGEO_A(client_handle_t, tuple_t *,
					cistpl_devicegeo_t *);
int32_t csx_Parse_CISTPL_LONGLINK_CB(client_handle_t, tuple_t *,
					cistpl_longlink_cb_t *);
int32_t csx_ParseTuple(client_handle_t, tuple_t *, cisparse_t *, uint32_t);

/*
 * Data access functions
 */
void csx_Put8(acc_handle_t, uint32_t, uint8_t);
void csx_Put16(acc_handle_t, uint32_t, uint16_t);
void csx_Put32(acc_handle_t, uint32_t, uint32_t);
void csx_Put64(acc_handle_t, uint32_t, uint64_t);
uint8_t csx_Get8(acc_handle_t, uint32_t);
uint16_t csx_Get16(acc_handle_t, uint32_t);
uint32_t csx_Get32(acc_handle_t, uint32_t);
uint64_t csx_Get64(acc_handle_t, uint32_t);
void csx_RepPut8(acc_handle_t, uint8_t *, uint32_t, uint32_t, uint32_t);
void csx_RepPut16(acc_handle_t, uint16_t *, uint32_t, uint32_t, uint32_t);
void csx_RepPut32(acc_handle_t, uint32_t *, uint32_t, uint32_t, uint32_t);
void csx_RepPut64(acc_handle_t, uint64_t *, uint32_t, uint32_t, uint32_t);
void csx_RepGet8(acc_handle_t, uint8_t *, uint32_t, uint32_t, uint32_t);
void csx_RepGet16(acc_handle_t, uint16_t *, uint32_t, uint32_t, uint32_t);
void csx_RepGet32(acc_handle_t, uint32_t *, uint32_t, uint32_t, uint32_t);
void csx_RepGet64(acc_handle_t, uint64_t *, uint32_t, uint32_t, uint32_t);

/*
 * Data access handle manipulation functions
 */
int32_t csx_GetMappedAddr(acc_handle_t, void **);
int32_t csx_GetPhysAddr(acc_handle_t, void **);
int32_t csx_DupHandle(acc_handle_t, acc_handle_t *, uint32_t);
int32_t csx_FreeHandle(acc_handle_t *);
int32_t csx_GetHandleOffset(acc_handle_t, uint32_t *);
int32_t csx_SetHandleOffset(acc_handle_t, uint32_t);

/*
 * XXX - PCMCIA Shady Meadows Retirement Community
 *
 * The defines in this section should be retired once the PS drivers
 *	get updated.
 *
 * XXX This is an old version of WIN_DATA_WIDTH_MASK and should be
 *	retired soon. RETIRE
 */
#define	WIN_DATA_WIDTH		0x00000002	/* 16-bit data path */
/*
 * XXX The following are old versions of the IO_DATA_WIDTH_XXX names and
 *	should be retured soon. RETIRE
 */
#define	IO_DATA_PATH_WIDTH	0x00000001	/* 16 bit data path */
#define	IO_DATA_PATH_WIDTH_8	0x00000000	/* 8 bit data path */
#define	IO_DATA_PATH_WIDTH_16	0x00000001	/* 16 bit data path */
/*
 * XXX - REMOVAL_ALL_DEVICE_NODES typo, remove soon. RETIRE
 */
#define	REMOVAL_ALL_DEVICE_NODES	0x03	/* remove all device nodes */

/*
 * The old name of the csx_RequestSocketMask structure was
 *	sockmask_t for some bizzare reason. This typedef
 *	keeps that old name around until we can fix
 *	the drivers.
 */
typedef struct request_socket_mask_t sockmask_t;	/* RETIRE */

/* XXX - RETIRE and change to a typedef XXX */
struct devnode_desc {
    char	*name;		/* device node path and name */
    int32_t	spec_type;	/* dev special type (block or char) */
    int32_t	minor_num;	/* device node minor number */
    char	*node_type;	/* device node type */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _CS_H */
