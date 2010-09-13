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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_IB_MGT_IBMF_IBMF_H
#define	_SYS_IB_MGT_IBMF_IBMF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file defines the IBMF client interface.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/note.h>
#include <sys/ib/ib_types.h>
#include <sys/ib/ib_pkt_hdrs.h>
#include <sys/ib/mgt/ib_mad.h>
#include <sys/ib/mgt/ibmf/ibmf_msg.h>
#include <sys/ib/mgt/ibmf/ibmf_saa.h>
#include <sys/ib/mgt/ibmf/ibmf_utils.h>

/* IBMF API function return values */
#define	IBMF_SUCCESS			0	/* successful call */
#define	IBMF_FAILURE			-1	/* ibmf internal error */
#define	IBMF_PORT_IN_USE 		-2	/* class already registered */
#define	IBMF_BAD_CLASS			-3	/* bad class specified */
#define	IBMF_BAD_HANDLE			-4	/* bad ibmf handle */
#define	IBMF_BAD_QP_HANDLE		-5	/* bad QP handle */
#define	IBMF_BAD_NODE			-6	/* bad node specified to reg */
#define	IBMF_BAD_PORT			-7	/* bad port specified to reg */
#define	IBMF_BAD_PORT_STATE		-8	/* port in incorrect state */
#define	IBMF_BAD_VERSION		-9	/* bad IBMF version */
#define	IBMF_BAD_FLAGS			-10	/* bad IBMF flags */
#define	IBMF_BAD_SIZE			-11	/* bad data size in message */
#define	IBMF_BAD_RMPP_OPT		-12	/* more than one class used */
#define	IBMF_BUSY			-13	/* resources held by client */
#define	IBMF_NO_RESOURCES		-14	/* no resources */
#define	IBMF_NOT_SUPPORTED		-15	/* function not supported */
#define	IBMF_PARTIAL_TRANSFER		-16	/* excess response data */
#define	IBMF_UNEXP_TRANS_RECVD		-17	/* unexpected trans received */
#define	IBMF_TRANS_TIMEOUT		-18	/* transaction timed out */
#define	IBMF_TRANS_FAILURE		-19	/* transaction failure */
#define	IBMF_NO_MEMORY			-20	/* could not alloc memory */
#define	IBMF_REQ_INVALID		-21	/* request was invalid */
#define	IBMF_NO_RECORDS			-22	/* no records match query */
#define	IBMF_TOO_MANY_RECORDS		-23	/* too many recs match query */
#define	IBMF_INVALID_GID		-24	/* invalid gid in sa request */
#define	IBMF_INSUFF_COMPS		-25	/* insufficient components */
#define	IBMF_UNSUPP_METHOD		-26	/* unsupported method */
#define	IBMF_UNSUPP_METHOD_ATTR		-27	/* unsupp. method/attrbute */
#define	IBMF_INVALID_FIELD		-28	/* invalid field in MAD */
#define	IBMF_INVALID_ARG		-29	/* invalid function argument */
#define	IBMF_CB_REGISTERED		-30	/* callback already regd */
#define	IBMF_CB_NOT_REGISTERED		-31	/* callback not registered */
#define	IBMF_TRANSPORT_FAILURE		-32	/* a transport call failed */
#define	IBMF_TID_IN_USE			-33	/* client's TID in use */

/* flags to ibmf_alloc_msg() */
#define	IBMF_ALLOC_SLEEP		0
#define	IBMF_ALLOC_NOSLEEP		1

/*
 * IBMF version
 */
#define	IBMF_VERSION			1

typedef struct _ibmf_handle_dummy	*ibmf_handle_t;

typedef struct _ibmf_qp_dummy		*ibmf_qp_handle_t;

/*
 * IBMF default QP handles
 */
#define	IBMF_QP_HANDLE_DEFAULT		(ibmf_qp_handle_t)0

/*
 * ir_client_type
 */
typedef	enum _ibmf_client_type_t {
	SUBN_AGENT				= 0x00010001,
	SUBN_MANAGER				= 0x00020001,
	SUBN_ADM_AGENT				= 0x00010003,
	SUBN_ADM_MANAGER			= 0x00020003,
	PERF_AGENT				= 0x00010004,
	PERF_MANAGER				= 0x00020004,
	BM_AGENT				= 0x00010005,
	BM_MANAGER				= 0x00020005,
	DEV_MGT_AGENT				= 0x00010006,
	DEV_MGT_MANAGER				= 0x00020006,
	COMM_MGT_MANAGER_AGENT			= 0x00030007,
	SNMP_MANAGER_AGENT			= 0x00030008,
	VENDOR_09_MANAGER_AGENT			= 0x00030009,
	VENDOR_0A_MANAGER_AGENT			= 0x0003000A,
	VENDOR_0B_MANAGER_AGENT			= 0x0003000B,
	VENDOR_0C_MANAGER_AGENT			= 0x0003000C,
	VENDOR_0D_MANAGER_AGENT			= 0x0003000D,
	VENDOR_0E_MANAGER_AGENT			= 0x0003000E,
	VENDOR_0F_MANAGER_AGENT			= 0x0003000F,
	VENDOR_30_MANAGER_AGENT			= 0x00030030,
	VENDOR_31_MANAGER_AGENT			= 0x00030031,
	VENDOR_32_MANAGER_AGENT			= 0x00030032,
	VENDOR_33_MANAGER_AGENT			= 0x00030033,
	VENDOR_34_MANAGER_AGENT			= 0x00030034,
	VENDOR_35_MANAGER_AGENT			= 0x00030035,
	VENDOR_36_MANAGER_AGENT			= 0x00030036,
	VENDOR_37_MANAGER_AGENT			= 0x00030037,
	VENDOR_38_MANAGER_AGENT			= 0x00030038,
	VENDOR_39_MANAGER_AGENT			= 0x00030039,
	VENDOR_3A_MANAGER_AGENT			= 0x0003003A,
	VENDOR_3B_MANAGER_AGENT			= 0x0003003B,
	VENDOR_3C_MANAGER_AGENT			= 0x0003003C,
	VENDOR_3D_MANAGER_AGENT			= 0x0003003D,
	VENDOR_3E_MANAGER_AGENT			= 0x0003003E,
	VENDOR_3F_MANAGER_AGENT			= 0x0003003F,
	VENDOR_40_MANAGER_AGENT			= 0x00030040,
	VENDOR_41_MANAGER_AGENT			= 0x00030041,
	VENDOR_42_MANAGER_AGENT			= 0x00030042,
	VENDOR_43_MANAGER_AGENT			= 0x00030043,
	VENDOR_44_MANAGER_AGENT			= 0x00030044,
	VENDOR_45_MANAGER_AGENT			= 0x00030045,
	VENDOR_46_MANAGER_AGENT			= 0x00030046,
	VENDOR_47_MANAGER_AGENT			= 0x00030047,
	VENDOR_48_MANAGER_AGENT			= 0x00030048,
	VENDOR_49_MANAGER_AGENT			= 0x00030049,
	VENDOR_4A_MANAGER_AGENT			= 0x0003004A,
	VENDOR_4B_MANAGER_AGENT			= 0x0003004B,
	VENDOR_4C_MANAGER_AGENT			= 0x0003004C,
	VENDOR_4D_MANAGER_AGENT			= 0x0003004D,
	VENDOR_4E_MANAGER_AGENT			= 0x0003004E,
	VENDOR_4F_MANAGER_AGENT			= 0x0003004F,
	APPLICATION_10_MANAGER_AGENT		= 0x00030010,
	APPLICATION_11_MANAGER_AGENT		= 0x00030011,
	APPLICATION_12_MANAGER_AGENT		= 0x00030012,
	APPLICATION_13_MANAGER_AGENT		= 0x00030013,
	APPLICATION_14_MANAGER_AGENT		= 0x00030014,
	APPLICATION_15_MANAGER_AGENT		= 0x00030015,
	APPLICATION_16_MANAGER_AGENT		= 0x00030016,
	APPLICATION_17_MANAGER_AGENT		= 0x00030017,
	APPLICATION_18_MANAGER_AGENT		= 0x00030018,
	APPLICATION_19_MANAGER_AGENT		= 0x00030019,
	APPLICATION_1A_MANAGER_AGENT		= 0x0003001A,
	APPLICATION_1B_MANAGER_AGENT		= 0x0003001B,
	APPLICATION_1C_MANAGER_AGENT		= 0x0003001C,
	APPLICATION_1D_MANAGER_AGENT		= 0x0003001D,
	APPLICATION_1E_MANAGER_AGENT		= 0x0003001E,
	APPLICATION_1F_MANAGER_AGENT		= 0x0003001F,
	APPLICATION_20_MANAGER_AGENT		= 0x00030020,
	APPLICATION_21_MANAGER_AGENT		= 0x00030021,
	APPLICATION_22_MANAGER_AGENT		= 0x00030022,
	APPLICATION_23_MANAGER_AGENT		= 0x00030023,
	APPLICATION_24_MANAGER_AGENT		= 0x00030024,
	APPLICATION_25_MANAGER_AGENT		= 0x00030025,
	APPLICATION_26_MANAGER_AGENT		= 0x00030026,
	APPLICATION_27_MANAGER_AGENT		= 0x00030027,
	APPLICATION_28_MANAGER_AGENT		= 0x00030028,
	APPLICATION_29_MANAGER_AGENT		= 0x00030029,
	APPLICATION_2A_MANAGER_AGENT		= 0x0003002A,
	APPLICATION_2B_MANAGER_AGENT		= 0x0003002B,
	APPLICATION_2C_MANAGER_AGENT		= 0x0003002C,
	APPLICATION_2D_MANAGER_AGENT		= 0x0003002D,
	APPLICATION_2E_MANAGER_AGENT		= 0x0003002E,
	APPLICATION_2F_MANAGER_AGENT		= 0x0003002F,
	UNIVERSAL_CLASS				= 0x00040001
} ibmf_client_type_t;

/*
 * ibmf_retrans_t data type is used to specify the maximum values
 * of the retransmission parameters, number of retries,
 * response time value, round trip travel time, and transaction timeout.
 *
 * The retries value must be provided by the client
 * for all the transaction types enumerated by ibmf_trans_t.
 * The retries value will be used to retry any section of
 * the underlying transmission and reception protocol that
 * are time bound by timers.
 *
 * The response time value must be specified for all transaction types except an
 * unsequenced, non-RMPP send (see the table below).
 * The response time value is the length of processing time for the
 * responder to process the requested transaction, from the point of receiving
 * the last request packet, to the point of returning the first response packet.
 * This value is interpreted in microseconds.
 * If the response time value is zero, an implementation default is used.
 *
 * The round trip time must be specified for all transaction types except an
 * unsequenced, non-RMPP send (see the table below).
 * The round trip travel time is the maximum time it should take a packet
 * to travel from the requester to the responder and back to the requester.
 * This value does not include the processing time at the responder.
 * This value is interpreted in microseconds.
 * If the round trip time value is zero, an implementation default is used.
 *
 * The transaction timeout should be specified for all transactions
 * using RMPP to receive a message.
 * Since, it is not possible for the client to know the size of the
 * response, IBMF will calculate a reasonable transaction timeout after
 * receiving the first RMPP data packet of the response at which time the
 * size of the message will be known.  If this value is greater than the
 * client's transaction timeout parameter the client's value will be used.
 * If the client's transaction timeout parameter is 0 the calculated value will
 * be used.
 * This value is interpreted in microseconds.
 * If the transaction timeout value is zero, an implementation default is used.
 *
 * See Section 13.6.3.1, of the InfiniBand Architecture Specification,
 * Volume 1, Release 1.1 for details on how to deduce this value.
 *
 * The following table describes the retrans parameters needed for
 * the various ibmf_msg_transport() flag combinations.
 *
 * ibmf_msg_transport() flags   retries      rtv/rttv      trans_to
 * No Flags                     ignored      ignored       ignored
 * Sequenced Flag               required     required      required
 * RMPP Flag                    required     required      ignored
 * RMPP + Sequenced Flags       required     required      optional
 */
typedef struct _ibmf_retrans_t {
	uint32_t	retrans_retries;	/* number of retries */
	uint32_t	retrans_rtv;		/* response time value */
	uint32_t	retrans_rttv; 		/* round trip travel time */
	uint32_t	retrans_trans_to;	/* transaction timeout */
} ibmf_retrans_t;

typedef struct _ibmf_register_info {
	ib_guid_t		ir_ci_guid;
	uint_t			ir_port_num;
	ibmf_client_type_t	ir_client_class;
} ibmf_register_info_t;

typedef enum _ibmf_impl_caps {
	IBMF_DEF_QP_HDL_P_KEY_ANY		= 0x0001,
	IBMF_DEF_QP_HDL_Q_KEY_ANY		= 0x0002,
	IBMF_NON_DEF_QP_HDL_P_KEY_ANY		= 0x0004,
	IBMF_NON_DEF_QP_HDL_Q_KEY_ANY		= 0x0008
} ibmf_impl_caps_t;


/*
 * Defines for channel interface events.
 * IBMF_CI_OFFLINE :
 *      Indication to the client that it must cease all ibmf activity
 *      (after any current activity has terminated). The client must
 *      release all ibmf resources and unregister from ibmf prior to
 *      returning from the callback.
 *
 *      NOTE1: It is expected that there will exist some higher level
 *      management entity that will "wake up" the ibmf client once
 *      the CI is available. The ibmf client may then register with the
 *      available CI's nodeguid and portnumber.
 *
 *	NOTE2: callback implementors must handle the case where the
 *	callback is invoked AFTER the ibmf resources have been freed by
 *	another thread.
 */
typedef enum ibmf_async_event_e {
	IBMF_CI_OFFLINE		= 0x1
} ibmf_async_event_t;

/*
 * ibmf_async_event_cb_t():
 * IBMF's callback to clients to inform them of events such as
 * the ibmf services temporarily suspending or resuming.
 * This notification mechanism covers all asynchronous events
 * of interest that are not related to IB messages.
 *
 * NOTE:
 * It is possible for the callback function to be called before
 * ibmf_register() returns. When this happens, the entity doing the
 * ibmf_register() may see an ibmf_handle being passed to the
 * callback function that it does not recognize.
 *
 * Input arguments:
 *	ibmf_handle - Handle to the IBMF interface
 *      clnt_private - is an opaque handle to client specific data
 *      event_type - specifies the event type the client is being notified of
 *
 * Output arguments:
 *      None
 *
 * Return values:
 *      None
 */
typedef void (*ibmf_async_event_cb_t)(
	ibmf_handle_t		ibmf_handle,
	void			*clnt_private,
	ibmf_async_event_t	event_type);

/*
 * ibmf_msg_cb_t():
 *
 * This routine type is called by IBMF when an unsolicited message that
 * corresponds to one of the class registrants is received. An unsolicited
 * message is one that was not allocated by this client for the purpose
 * of executing a transaction using the ibmf_msg_transport() call.
 * Examples of unsolicited messages are traps, and requests from other
 * management entities.
 *
 * This routine type is also called by IBMF at the end of a transaction
 * specified in a call to ibmf_msg_transport().
 *
 * When it is called as result of an incoming message:
 *
 *	The recipient is expected to free the ibmf_msg_t passed in by
 *	calling ibmf_free_msg(); this freeing should be done before the
 *	client unregisters.
 *
 *	The recipient is expected to not call any routines in the callback
 *	that may block.
 *
 * 	Blocking within the callback is not allowed, but ibmf doesn't enforce
 *	this.
 *
 *	This routine may be called before ibmf_setup_async_cb() returns.
 *
 *
 * Input arguments:
 *	Handle to the IBMF interface
 *	Pointer to the Message sent or received
 *	Callback arguments, specified at registration time (for async callbacks)
 *		or specified to ibmf_msg_transport()
 *
 * Output arguments:
 *	None
 *
 * Return values:
 *	None
 */
typedef void (*ibmf_msg_cb_t)(
	ibmf_handle_t		ibmf_handle,
	ibmf_msg_t		*msgp,
	void			*args);

/* defines for im_msg_flags */
#define	IBMF_MSG_FLAGS_GLOBAL_ADDRESS	0x00000010	/* has global addr */

/*
 * ibmf_register():
 *
 * An agent needs to register before it can receive any management packets
 * and a manager needs to register before it can send/receive any management
 * packets. The registration is on a per port of the node basis.
 *
 * A client can register for one class per call to ibmf_register().
 * The client should set ir_client_class component of the client_info argument
 * to the class it wants to register for.
 * ibmf_register() will fail if the class is already registered for,
 * with the error code IBMF_PORT_IN_USE.
 *
 * Note that for some classes, the client can register as agent or manager only
 * and agent+manager only. An exception to this rule is the UNIVERSAL_CLASS
 * described below.
 *
 * Clients that require to send/receive general UD traffic,
 * not limited to MADs, over a UD QP may do so by registering
 * with the UNIVERSAL_CLASS client type.
 * Unlike the other IBMF client types, any number of clients may
 * be simultaneously registered for the UNIVERSAL_CLASS on a port.
 * When registered with the UNIVERSAL_CLASS, a client should only use the
 * alternate QPs, and never use the default QP handle.
 * However, a client registered for any other client type may also use
 * the alternate QPs in addition to using the default QP handle.
 * IBMF implementations that do not support registration for the UNIVERSAL class
 * will return IBMF_NOT_SUPPORTED.
 *
 * NOTE on usage of qp handles:
 *
 * Some implementations support specifying any Q_Key and P_Key
 * combination when ibmf_qp_handle_t arg is set to IBMF_QP_HANDLE_DEFAULT
 * in the call to ibmf_msg_transport() and some implementations allow only
 * the default values of Q_Key (0x8001_0000) and P_Key (0xFFFF/0x7FFFF)
 * when ibmf_qp_handle_t arg is IBMF_QP_HANDLE_DEFAULT. The client can know
 * the behavior supported via ibmf_impl_caps_t arg on successful return from
 * ibmf_register(). ibmf_impl_caps_t arg points to a bit mask of the
 * capabilities of the platform. If the implementation supports any
 * P_Key and/or Q_Key value with IBMF_QP_HANDLE_DEFAULT, then
 * IBMF_DEF_QP_HDL_P_KEY_ANY and/or IBMF_DEF_QP_HDL_Q_KEY_ANY will be set in
 * ibmf_impl_caps_t.
 *
 * Some implementations support specifying any P_Key and Q_Key combination on
 * a per-request basis when ibmf_qp_handle_t is set to an explicitly allocated
 * qp handle (the client specifies the P_Key/Q_Key value in ibmf_addr_info_t
 * argument). IBMA indicates this behavior by setting
 * IBMF_NON_DEF_QP_HDL_P_KEY_ANY and/or IBMF_NON_DEF_QP_HDL_Q_KEY_ANY in the
 * ibmf_impl_caps_t arg. In such an implementation, ibmf_modify_qp() does not
 * change anything in the transport and always returns IBMF_SUCCESS.
 *
 * When the implementation supports IBMF_DEF_QP_HDL_P_KEY_ANY and/or
 * IBMF_DEF_QP_HDL_Q_KEY_ANY, it may map IBMF_QP_HANDLE_DEFAULT to any qp
 * number(s) supported by the
 * underlying transport. The client can not not make any assumptions on this
 * mapping nor can it query ibmf for the qp num being used with
 * IBMF_QP_HANDLE_DEFAULT. There are cases where the client needs to have
 * explicit control over the qp number being used by ibmf (eg., agent
 * redirection). The client should explicitly allocate a qp using
 * ibmf_alloc_qp() in such cases.
 *
 * Also, IBMF_QP_HANDLE_DEFAULT can only be used when the class of the MAD
 * being sent using ibmf_msg_transport() is the same as the class the client
 * registered for. If a client wishes to send a MAD class other than the
 * one it registered for, it should explicitly allocate a qp and use that
 * qp while sending MADs.
 *
 * If the implementation supports
 * IBMF_DEF_QP_HDL_P_KEY_ANY/IBMF_DEF_QP_HDL_Q_KEY_ANY and/or
 * IBMF_NON_DEF_QP_HDL_P_KEY_ANY/IBMF_NON_DEF_QP_HDL_Q_KEY_ANY, it is the
 * implementation's responsibility to ensure that the
 * requested P_Key and Q_Key can be used by, with in resource limitations,
 * concurrent sends.
 *
 * Clients registering for classes that include an RMPP header in their
 * MADs must set the IBMF_REG_FLAG_RMPP flag when registering with IBMF.
 * This must be done regardless of whether the client intends to use
 * the RMPP protocol or not. The flag is an indicator to IBMF of the
 * presence of the RMPP header in the MAD.
 *
 * IBMF will always insure that receive buffer pointers are offsets into a
 * single contiguous buffer of memory. The im_msgbufs_recv.im_bufs_mad_hdr,
 * points to the start of the buffer. The other two pointers,
 * im_msgbufs_recv.im_bufs_cl_hdr, and im_msgbufs_recv.im_bufs_cl_data,
 * will point to class specific offsets within the buffer.
 *
 * Clients may provide a pointer to a callback function in the client_cb
 * argument. Implementations of ibmf that require the client_cb to
 * be specified should return IBMF_INVALID_ARG if the client_cb argument
 * is NULL.
 *
 * This interface may block
 *
 * Input arguments:
 *	Pointer to client registration information
 *	Version of the interface (IBMF_VERSION)
 *	flags - set IBMF_REG_FLAG_RMPP if client supports RMPP MAD
 *		set IBMF_REG_FLAG_NO_OFFLOAD for requiring that processing
 *			not be offloaded onto a non-interrupt context thread
 *			on send completions and receive completions.
 *			(Processsing will be done in the interrupt context)
 *			The default is to offload the processing to a
 *			non-interrupt context thread(s).
 *		set IBMF_REG_FLAG_SINGLE_OFFLOAD for requiring single
 *			threaded processing if IBMF_REG_FLAG_NO_OFFLOAD
 *			is not specified. The default is multi-threaded
 *			processing. It is an error to set this flag if
 *			IBMF_REG_FLAG_NO_OFFLOAD is set.
 *      client_cb - callback to be called for asynchronous events that
 *                  are not related to IB messages
 *      client_cb_args - opaque pointer to client private data area
 *
 * Output arguments:
 *	Handle to the IBMF interface; used in subsequent interactions
 *	Pointer to ibmf_impl_caps_t; gives capabilities of the platform
 *
 * Return values:
 *	IBMF_SUCCESS		- registration successful
 *	IBMF_BAD_VERSION	- registration failed due to invalid version
 *	IBMF_PORT_IN_USE	- registration failed - some entity already
 *				  registered for the class on the node/port
 *				  specified.
 *	IBMF_BAD_CLASS		- registration failed - invalid class
 *	IBMF_BAD_PORT		- registration failed - non existent port
 *	IBMF_BAD_NODE		- registration failed - non existent node
 *	IBMF_BAD_FLAGS		- IBMF_REG_FLAG_NO_OFFLOAD is specified with
 *					IBMF_REG_FLAG_SINGLE_OFFLOAD
 *	IBMF_INVALID_ARG	- registration failed - invalid argument
 *	IBMF_FAILURE		- registration failed - ibmf internal error
 *	IBMF_NO_RESOURCES	- registration failed - not enough resources
 *	IBMF_TRANSPORT_FAILURE	- registration failed - transport call failed
 *
 */
int	ibmf_register(
		ibmf_register_info_t	*client_info,
		uint_t			ibmf_version,
		uint_t			flags,
		ibmf_async_event_cb_t   client_cb,
		void			*client_cb_args,
		ibmf_handle_t		*ibmf_handle,
		ibmf_impl_caps_t	*ibmf_impl_features);

#define	IBMF_REG_FLAG_RMPP		0x1
#define	IBMF_REG_FLAG_NO_OFFLOAD	0x2
#define	IBMF_REG_FLAG_SINGLE_OFFLOAD	0x4

/*
 * ibmf_unregister():
 *
 * Unregister a previously established registration.
 *
 * This interface may block.
 *
 * The client should free any and all ibmf_msg_t's passed in all
 * "receive msg callbacks" before unregistering. Also, the client should
 * ensure that it is not trying to send any messages before calling this
 * routine.
 *
 * After successfully returning from this call, ibmf_handle should not be used
 * for any further interactions with the IBMF.
 *
 * Input arguments:
 *	Handle to the IBMF interface
 *	flags - unused (should be 0)
 *
 * Output arguments:
 *	Handle to the IBMF interface; will be invalidated following
 *		this call.
 *
 * Return values:
 *	IBMF_SUCCESS		- unregistration successful
 *	IBMF_BAD_HANDLE		- unregistration failed - invalid handle
 *				  passed in.
 *	IBMF_BUSY		- unregistration failed - client has not
 *				  freed all the resources (ibmf_msg_t's etc)
 *				  allocated by the IBMF, the client
 *				  has not removed all recv callbacks.
 *	IBMF_INVALID_ARG	- invalid argument
 *	IBMF_FAILURE		- ibmf internal error
 *	IBMF_NO_RESOURCES	- not enough resources
 *	IBMF_TRANSPORT_FAILURE	- transport call failed
 */
int	ibmf_unregister(
		ibmf_handle_t		*ibmf_handle,
		uint_t			flags);

/*
 * ibmf_setup_async_cb():
 *
 * This routine establishes a callback that the IBMF invokes when a message
 * corresponding to the class corresponding to ibmf_handle is received.
 * It is an error to call this routine twice without an intervening
 * call to ibmf_tear_down_async_cb() for the same ibmf_qp_handle/ibmf_handle
 * combination. Only unsolicited message reception will result in this
 * callback being invoked.
 *
 * This interface may block.
 *
 * The callback routine could be invoked before this function returns.
 *
 * Input arguments:
 *	Handle to the IBMF interface
 *	IBMF QP handle (either allocated via ibmf_alloc_qp() or
 *	    IBMF_QP_HANDLE_DEFAULT)
 *	Callback routine
 *	Argument to be passed when the callback is invoked
 *	flags - unused (should be 0)
 *
 * Output arguments:
 *	None
 *
 * Return values:
 *	IBMF_SUCCESS		- Callback established successfully
 *	IBMF_BAD_HANDLE		- failure - invalid handle
 *	IBMF_BAD_QP_HANDLE	- failure - invalid qp handle
 *	IBMF_CB_REGISTERED	- failure - callback is already established
 *	IBMF_INVALID_ARG	- failure - invalid argument
 */
int	ibmf_setup_async_cb(
		ibmf_handle_t		ibmf_handle,
		ibmf_qp_handle_t	ibmf_qp_handle,
		ibmf_msg_cb_t		async_msg_cb,
		void			*async_msg_cb_args,
		uint_t			flags);

/*
 * ibmf_tear_down_async_cb():
 *
 * This routine removes the callback set up using ibmf_setup_async_cb.
 * There will not be any callbacks if messages are received after successful
 * return from this routine. There could be message received callbacks during
 * the execution of this routine.
 *
 * This interface may block.
 *
 * Input arguments:
 *	Handle to the IBMF interface
 *	IBMF QP handle (either allocated via ibmf_alloc_qp() or
 *	    IBMF_QP_HANDLE_DEFAULT)
 *	flags - unused (should be 0)
 *
 * Output arguments:
 *	None
 *
 * Return values:
 *	IBMF_SUCCESS		- call successful
 *	IBMF_BAD_HANDLE		- failure - invalid ibmf handle or qp handle
 *	IBMF_BAD_QP_HANDLE	- failure - invalid qp handle
 *	IBMF_CB_NOT_REGISTERED	- No callback currently registered
 *	IBMF_INVALID_ARG	- failure - invalid argument
 */
int	ibmf_tear_down_async_cb(
		ibmf_handle_t		ibmf_handle,
		ibmf_qp_handle_t	ibmf_qp_handle,
		uint_t			flags);

/*
 * ibmf_msg_transport():
 *
 * This interface does not block if a callback is specified.
 *
 * IBMF makes some preliminary checks and returns failure if the
 * checks fail. The callback, if any, is not called in this case. If the
 * checks pass, the message specified in msgp->im_msgbufs_send is relayed
 * down into the transport layer over as many MAD packets as necessary
 * to accommodate the entire message. The IBMF_MSG_TRANS_FLAG_RMPP flag is set
 * when the RMPP protocol should be used when sending out the message.
 * The IBMF_MSG_TRANS_FLAG_SEQ is set when the the transaction is a
 * sequenced transaction (send and receive) where the client expects a reply.
 * The transaction completion callback will be invoked when IBMF
 * is done processing the send operation and after having received the
 * complete response if one is due, with or without errors.
 * If no callback is specified, the routine blocks till the underlying
 * transport is done processing the send request and received the complete
 * response, with or without errors
 *
 * When sending non-MAD traffic over the alternate QPs,
 * if the message data exceeds the maximum MTU supported, the call will fail
 * with the status IBMF_BAD_SIZE.
 *
 * NOTE: If the call is asynchronous, the callback may be invoked before
 * the call returns. The client should be prepared to handle this possibility.
 *
 * The message is sent to the address specified by msgp->im_local_addr and
 * msgp->im_global_addr (global address invalid for SMPs and is ignored).
 * Note that the desired Q_Key and P_Key can be specified via
 * msgp->im_local_addr. If the ibmf implementation does not support any
 * value of Q_Key/P_Key with IBMF_QP_HANDLE_DEFAULT, it is an error to specify
 * a Q_Key other than 0x8001_0000 and a P_Key other than 0xFFFF/0x7FFF when
 * ibmf_qp_handle_t arg is set IBMF_QP_HANDLE_DEFAULT. (See the NOTE in
 * ibmf_register() on what the platform supports.) In this case, when a q_key
 * value other than 0x8001_0000 and/or P_Key value other than
 * 0xFFFF/0x7FFF is desired, the client should allocate its own qp handle
 * with the desired values and use that in the ibmf_msg_transport() call.
 * ibmf_msg_transport() returns IBMF_BAD_HANDLE to flag the error.
 *
 * NOTE: If the qp handle is not the default handle (ie., not
 * IBMF_QP_HANDLE_DEFAULT), it is possible for some other thread to modify
 * P_Key and Q_Key value associated with the qp_handle while this function
 * is executing; this routine may return IBMF_BAD_HANDLE if that
 * happens. It is possible that the modification happens after this routine
 * validates the values, in which case no error may be flagged.
 *
 * NOTE: if the class of the MAD being sent is not the same as what the
 * ibmf_handle (obtained via ibmf_register()) corresponds to, ibmf_qp_handle
 * can not be set to IBMF_QP_HANDLE_DEFAULT.
 *
 * NOTE on notation: A message structure allocated by an ibmf_alloc_msg()
 * call or one returned in an unsolicted callback will be referred to as
 * "Message". When referring to a message in the general sense of the word,
 * it will be referred to as "message".
 * NOTE: Rules for reusing an IBMF Message:
 * Clients may reuse a Message, either provided by IBMF in an unsolicited
 * request, or one obtained through the ibmf_alloc_msg() call, for a
 * subsequent request from the client itself. The client may reuse a Message
 * to avoid the overhead of allocating a new Message and new send buffers.
 * To safely reuse Messages, the client must follow the rules listed below.
 * 1) Using the receive buffers to send the message header and data:
 * If the Message has been provided by IBMF in an unsolicited request,
 * it will have its receive buffers already allocated and pointed to by
 * im_msgbufs_recv pointers by IBMF. In such a case, a client may set
 * the im_msgbufs_send pointers to the values in the im_msgbufs_recv
 * thus reusing the buffer allocated by IBMF for the incoming Message.
 * However, this may be done only when the request from the client is
 * a non-sequenced operation i.e. IBMF_MSG_TRANS_FLAG_SEQ flag is not set.
 * An attempt to reuse the receive buffer for any other operation will
 * result in the failure of the ibmf_msg_transport() call with the error
 * status IBMF_REQ_INVALID.
 * 2) Providing send buffers to send the message header and data:
 * If the client provides its own send buffers for the message header and data,
 * the IBMF Message may be reused for both sequenced and non-sequenced
 * transactions. Any receive buffers that were allocated by IBMF from a
 * previous transaction, will be freed up once the Message is reused in an
 * ibmf_msg_transport() call. New receive buffers will be provided by IBMF
 * if the new transaction is a sequenced transaction.
 *
 * Input arguments:
 *	Handle to the IBMF interface
 *	IBMF QP handle (either allocated via ibmf_alloc_qp() or
 *	    IBMF_QP_HANDLE_DEFAULT [see the NOTE above regarding MAD class])
 *	Pointer to ibmf_msg_t to be sent
 *	A pointer to ibmf_retrans_t to specify retries and timeout
 *	values to use during the transaction.
 *	Function to be called when the operation is done.
 *		(the routine is blocking if this function is NULL).
 *	Argument to be passed when the callback is invoked
 *	flags - set IBMF_MSG_TRANS_FLAG_RMPP if send should use RMPP
 *		set IBMF_MSG_TRANS_FLAG_SEQ if transaction is sequenced
 *
 * Output arguments:
 *	None
 *
 * Return values:
 *	IBMF_SUCCESS		- If blocking call, the operation was
 *				  completed by the transport. For
 *				  non blocking call, the request passed basic
 *				  checks and the callback should be expected.
 *	IBMF_BAD_HANDLE		- operation failure - invalid ibmf handle
 *	IBMF_BAD_QP_HANDLE	- operation failure - invalid qp handle or
 *				  q_key/p_key in msgp->ip_local_addr is
 *				  inconsistent with ibmf_qp_handle (for eg.,
 *				  handle is IBMF_QP_HANDLE_DEFAULT and
 *				  Q_Key/P_Key is non-default and platform
 *				  doesn't support non-default keys on this
 *				  qp_handle or handle is IBMF_QP_HANDLE_DEFAULT
 *				  but MAD class is not the one specified to
 *				  ibmf_register())
 *	IBMF_BAD_PORT_STATE	- operation failure - port in incorrect state
 *				  for packet transmission
 *	IBMF_NO_RESOURCES	- operation failure - temporarily out of
 *				  resources and call may succeed on a retry
 *	IBMF_FAILURE		- operation failure - unspecified error
 *	IBMF_BAD_SIZE		- data size in message to long for single UD pkt
 *	IBMF_BAD_RMPP_OPT	- the class or QP does not support RMPP
 *	IBMF_PARTIAL_TRANSFER	- only part of the received data was returned
 *				  to the client up to the message size limit.
 *	IBMF_TRANS_TIMEOUT	- transaction timed out
 *	IBMF_TRANS_FAILURE	- transaction failure
 *	IBMF_REQ_INVALID	- tried to reuse receive buffer for sending
 *				  message data in a sequenced operation.
 *	IBMF_BUSY		- message already being processed
 *	IBMF_INVALID_ARG	- invalid argument
 *	IBMF_FAILURE		- ibmf internal error
 *	IBMF_NO_RESOURCES	- not enough resources
 *	IBMF_TRANSPORT_FAILURE	- transport call failed
 *	IBMF_BAD_SIZE		- if msgp->im_msgbufs_send.im_bufs_mad_hdr
 *				  is NULL when ibmf_qp_handle is the default
 *				  QP handle, OR, if
 *				  msgp->im_msgbufs_send.im_bufs_mad_hdr
 *				  is NULL when ibmf_qp_handle is not the default
 *				  QP handle and the alternate QP is not being
 *				  used for RAW data traffic.
 */
int	ibmf_msg_transport(
		ibmf_handle_t		ibmf_handle,
		ibmf_qp_handle_t	ibmf_qp_handle,
		ibmf_msg_t		*msgp,
		ibmf_retrans_t		*retrans,
		ibmf_msg_cb_t		msg_cb,
		void			*msg_cb_args,
		uint_t			flags);

#define	IBMF_MSG_TRANS_FLAG_RMPP	0x1
#define	IBMF_MSG_TRANS_FLAG_SEQ		0x2

/*
 * ibmf_alloc_msg():
 *
 * Alloc memory to hold the message being sent out or being received.
 * The IBMF client must provide the buffers in im_msgbufs_send before
 * calling ibmf_msg_transport(). If this message is used in a sequenced
 * transaction response or an unsolicited transaction, IBMF will provide
 * the buffers in im_msgbufs_recv with the response, once the
 * transaction is complete.
 * The client is responsible for freeing the buffers pointed to in
 * im_msgbufs_send when they are no longer needed. IBMF will free the buffers
 * in im_msgbufs_send once ibmf_free_msg() is called by the client.
 *
 * This interface may block if IBMF_ALLOC_SLEEP is specified.
 *
 * Input arguments:
 *	Handle to the IBMF interface
 *	sleep flag - IBMF_ALLOC_SLEEP/IBMF_ALLOC_NOSLEEP
 *
 * Output arguments:
 *	Pointer to the buffer allocated; may be NULL if system runs out
 *		of memory and IBMF_ALLOC_NOSLEEP is specified.
 *
 * Return values:
 *	IBMF_SUCCESS		- allocation successful
 *	IBMF_BAD_HANDLE		- alloc failed - Invalid IBMF handle passed in
 *	IBMF_BAD_FLAGS		- allocation failed - invalid flags
 *	IBMF_INVALID_ARG	- allocation failed - invalid argument
 *	IBMF_FAILURE		- ibmf internal error
 *	IBMF_NO_RESOURCES	- not enough resources
 *	IBMF_TRANSPORT_FAILURE	- transport call failed
 */
int	ibmf_alloc_msg(
		ibmf_handle_t		ibmf_handle,
		int			flag,
		ibmf_msg_t		**ibmf_msgpp);


/*
 * ibmf_free_msg():
 *
 * Free message context. This message context is either allocated when
 * the client calls ibmf_alloc_msg() or is allocated by IBMF automatically in
 * response to incoming unsolicited messages. For all incoming messages,
 * solicited or unsolicited, IBMF will provide the buffers pointed to
 * in im_msgbufs_recv. In addition to freeing the message context,
 * IBMF is responsible for freeing any buffers allocated by itself,
 * and pointed to in im_msgbufs_recv when the client calls ibmf_free_msg().
 *
 * This interface does not block
 *
 * Input arguments:
 *	Handle to the IBMF interface
 *	Pointer to the buffer to be freed
 *
 * Output arguments:
 *	None
 *
 * Return values:
 *	IBMF_SUCCESS		- free successful
 *	IBMF_BAD_HANDLE		- free failed - Invalid IBMF handle passed in
 *	IBMF_BUSY		- free failed - message in use
 *	IBMF_INVALID_ARG	- free failed - invalid argument
 *	IBMF_FAILURE		- ibmf internal error
 *	IBMF_NO_RESOURCES	- not enough resources
 *	IBMF_TRANSPORT_FAILURE	- transport call failed
 */
int	ibmf_free_msg(
		ibmf_handle_t		ibmf_handle,
		ibmf_msg_t		**ibmf_msgpp);


/*
 * ibmf_alloc_qp():
 *
 * Alloc a qp with the specified P_key and Q_key values. A pointer to
 * ibmf_qp_handle_t is returned if the call is successful. The qp is
 * associated with the port that ibmf_handle corresponds to.
 *
 * Non-special QPs may be tagged to send and receive
 * one of the three types of traffic, either non-MAD UD, or MADs with
 * RMPP or MADs without RMPP.
 * The tagging should be done when calling ibmf_alloc_qp()
 * by setting the flags argument in the ibmf_alloc_qp() interface
 * function call to specifically defined values.
 * Only one, and at least one, of these flags must be specified.
 *
 * A client may specify the IBMF_ALT_QP_RAW_ONLY flag to limit
 * the QP to non-MAD UD traffic. If this flag is specified, and the
 * IBMF implementation supports this flag, the client may send
 * and receive MADs up to the maximum MTU supported on the link
 * connected to the chosen port.
 *
 * If any of the flag options are not supported by the IBMF implementation,
 * IBMF will return IBMF_NOT_SUPPORTED.
 *
 * This interface may block
 *
 * Input arguments:
 *	Handle to the IBMF interface
 *	P_Key
 *	Q_Key
 *	flags - IBMF_ALT_QP_MAD_NO_RMPP = MAD traffic only,
 *		IBMF_ALT_QP_MAD_RMPP = RMPP MADs only,
 *		IBMF_ALT_QP_RAW_ONLY = Non-MAD UD traffic only
 *
 * Output arguments:
 *	Pointer to the qp handle
 *
 * Return values:
 *	IBMF_SUCCESS		- allocation successful
 *	IBMF_BAD_HANDLE		- alloc failed - Invalid IBMF handle passed in
 *	IBMF_NO_RESOURCES	- alloc failed - no resources for qp allocation
 *	IBMF_BAD_FLAGS		- allocation failed - bad flag combination
 *	IBMF_NOT_SUPPORTED	- allocation failed - unsupported traffic
 *	IBMF_INVALID_ARG	- allocation failed - invalid argument
 *	IBMF_NO_RESOURCES	- not enough resources
 *	IBMF_TRANSPORT_FAILURE	- transport call failed
 *
 */
int	ibmf_alloc_qp(
		ibmf_handle_t		ibmf_handle,
		ib_pkey_t		p_key,
		ib_qkey_t		q_key,
		uint_t			flags,
		ibmf_qp_handle_t	*ibmf_qp_handlep);

/* Flags values for ibmf_alloc_qp() flags argument */
#define	IBMF_ALT_QP_MAD_NO_RMPP		0x1
#define	IBMF_ALT_QP_MAD_RMPP		0x2
#define	IBMF_ALT_QP_RAW_ONLY		0x4

/*
 * ibmf_query_qp():
 *
 * This function returns the P_Key, Q_Key, qp num and the port num that the
 * qp_handle corresponds to. It is possible that some other thread is
 * modifying the p_key and q_key for the qp_handle while this function is
 * executing or some other thread modifies the p_key/q_key values after the
 * function returns.
 * It is the callers responsibility to deal with these cases.
 *
 * This interface does not block.
 *
 * Input arguments:
 *	Handle to the IBMF interface
 *	IBMF qp handle (this can not be IBMF_QP_HANDLE_DEFAULT)
 *	flags - unused (should be 0)
 *
 * Output arguments:
 *	Pointer to QP num
 *	Pointer to P_key
 *	Pointer to Q_key
 *	Pointer to the port num
 *
 * Return values:
 *	IBMF_SUCCESS		- call successful
 *	IBMF_BAD_HANDLE		- failure - Invalid IBMF handle
 *	IBMF_BAD_QP_HANDLE	- failure - Invalid qp handle
 *	IBMF_INVALID_ARG	- failure - invalid argument
 *	IBMF_TRANSPORT_FAILURE	- transport call failed
 */
int	ibmf_query_qp(
		ibmf_handle_t		ibmf_handle,
		ibmf_qp_handle_t	ibmf_qp_handle,
		uint_t			*qp_num,
		ib_pkey_t		*p_key,
		ib_qkey_t		*q_key,
		uint8_t			*portnum,
		uint_t			flags);

/*
 * ibmf_modify_qp():
 *
 * This function sets the p_key and q_key associated with the qp handle to the
 * values specified.
 *
 * This interface may block.
 *
 * Input arguments:
 *	Handle to the IBMF interface
 *	IBMF qp handle (this can not be IBMF_QP_HANDLE_DEFAULT)
 *	P_key
 *	Q_key
 *	flags - unused (should be 0)
 *
 * Output arguments:
 *	None
 *
 * Return values:
 *	IBMF_SUCCESS		- call successful
 *	IBMF_BAD_HANDLE		- failure - Invalid IBMF handle or qp handle
 *	IBMF_BAD_QP_HANDLE	- failure - Invalid qp handle
 *	IBMF_INVALID_ARG	- failure - invalid argument
 *	IBMF_TRANSPORT_FAILURE	- transport call failed
 */
int	ibmf_modify_qp(
		ibmf_handle_t		ibmf_handle,
		ibmf_qp_handle_t	ibmf_qp_handle,
		ib_pkey_t		p_key,
		ib_qkey_t		q_key,
		uint_t			flags);

/*
 * ibmf_free_qp():
 *
 * This function frees a qp allocated by ibmf_alloc_qp().
 * The ibmf handle argument must be the same ibmf handle used in the
 * corresponding ibmf_alloc_qp() call. ibmf_unregister() for the ibmf
 * handle will not be allowed until all associated qps are freed.
 * The client must have already invoked ibmf_tear_down_recv_cb()
 * for this qp handle prior to calling ibmf_free_qp(), else IBMF_BUSY
 * will be returned.
 *
 * This interface may block.
 *
 * Input arguments:
 *	Handle to the IBMF interface
 *	IBMF qp handle pointer (this can not be IBMF_QP_HANDLE_DEFAULT)
 *	flags - unused (should be 0)
 *
 * Output arguments:
 *	IBMF qp handle; will be invalidated following successful return from
 *	this call
 *
 * Return values:
 *	IBMF_SUCCESS		- call successful
 *	IBMF_BAD_HANDLE		- failure - Invalid IBMF handle or qp handle
 *	IBMF_BAD_QP_HANDLE	- failure - Invalid qp handle
 *	IBMF_BUSY		- failure - callback is active
 *	IBMF_INVALID_ARG	- failure - invalid argument
 *	IBMF_TRANSPORT_FAILURE	- transport call failed
 */
int	ibmf_free_qp(
		ibmf_handle_t		ibmf_handle,
		ibmf_qp_handle_t	*ibmf_qp_handle,
		uint_t			flags);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_MGT_IBMF_IBMF_H */
