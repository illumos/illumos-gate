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

#ifndef	_SYS_AGGR_LACP_H
#define	_SYS_AGGR_LACP_H

#include <sys/aggr.h>
#include <sys/ethernet.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * 802.3ad LACP version number
 */
#define	LACP_VERSION	0x01	/* LACP version from 802.3ad */
#define	LACP_SUBTYPE	0x1

/*
 * TLV type (type/length/value carried in the LACPDU structure.
 */
#define	ACTOR_TLV	0x01	/* actor TLV type */
#define	PARTNER_TLV	0x02	/* partner TLV type */
#define	COLLECTOR_TLV	0x03	/* collector TLV type */
#define	TERMINATOR_TLV	0x00	/* end of message */

/*
 * Length fields as per 802.3ad.
 */
#define	LACP_COLLECTOR_INFO_LEN		0x10
#define	LACP_TERMINATOR_INFO_LEN	0x00

/* LACP Receive State Machine states */
typedef	enum {
	LACP_INITIALIZE		= 0,
	LACP_PORT_DISABLED	= 1,
	LACP_EXPIRED		= 2,
	LACP_DISABLED		= 3,
	LACP_DEFAULTED		= 4,
	LACP_CURRENT		= 5
} lacp_receive_state_t;

#define	LACP_RECEIVE_STATE_STRINGS {	\
	"LACP_INITIALIZE",		\
	"LACP_PORT_DISABLED",		\
	"LACP_EXPIRED",			\
	"LACP_DISABLED",		\
	"LACP_DEFAULTED",		\
	"LACP_CURRENT"			\
}

/* LACP Periodic State Machine states */
typedef	enum {
	LACP_NO_PERIODIC		= 0,
	LACP_FAST_PERIODIC		= 1,
	LACP_SLOW_PERIODIC		= 2,
	LACP_PERIODIC_TX		= 3
} lacp_periodic_state_t;

#define	LACP_PERIODIC_STRINGS {		\
	"LACP_NO_PERIODIC",		\
	"LACP_FAST_PERIODIC",		\
	"LACP_SLOW_PERIODIC",		\
	"LACP_PERIODIC_TX"		\
}


/* LACP Mux State Machine states */
typedef	enum {
	LACP_DETACHED			= 0,
	LACP_WAITING			= 1,
	LACP_ATTACHED			= 2,
	LACP_COLLECTING_DISTRIBUTING	= 3
} lacp_mux_state_t;

#define	LACP_MUX_STRINGS {		\
	"LACP_DETACHED",		\
	"LACP_WAITING",			\
	"LACP_ATTACHED",		\
	"LACP_COLLECTING_DISTRIBUTING"	\
}

/* LACP Churn State Machine states */
typedef	enum {
	LACP_NO_ACTOR_CHURN		= 0,
	LACP_ACTOR_CHURN_MONITOR	= 1,
	LACP_ACTOR_CHURN		= 2
} lacp_churn_state_t;

/*
 * 802.3ad timer constants.  (IEEE 802.3ad: section 43.4.4)
 *
 * All timers specified have a implementation tolerance of +- 250 ms.
 */
#define	FAST_PERIODIC_TIME		1	/* using short timeouts (tx) */
#define	SLOW_PERIODIC_TIME		30	/* using long timeouts (tx) */
#define	SHORT_TIMEOUT_TIME		3	/* before invalidate LACPDU */
#define	LONG_TIMEOUT_TIME		90	/* before invalidate LACPDU */
#define	CHURN_DETECTION_TIME		60	/* sync between actor/partner */
#define	AGGREGATE_WAIT_TIME		2  /* Delay wait to aggregate links */

/*
 * 802.3ad Variables associated with the system (section 43.4.5)
 */
typedef struct system_info {
	struct ether_addr system_id;	/* MAC address assigned by admin */
	uint16_t system_priority; 	/* system priority assigned by admin */
} system_info_t;

typedef struct lacp_timer {
	uint32_t	val;
	timeout_id_t	id;
} lacp_timer_t;

/*
 * 802.3ad Variables associated with each aggregation (section 43.4.6)
 *	Note: These are on a per aggregation basis.
 */
typedef struct Agg {
	uint32_t	AggregatorIdentifier;	/* not used */
	boolean_t	IndividualAggr;		/* individual aggregator */
	uint32_t	ActorAdminKey;		/* assigned by admin. */
	uint32_t	ActorOperKey;		/* assigned by admin. */
	struct ether_addr PartnerSystem;	/* partner system ID */
	uint32_t	PartnerSystemPriority;	/* partner system priority */
	uint32_t	PartnerOperAggrKey;	/* parter oper aggr. key */
	boolean_t	ReceiveState;		/* Enabled/Disabled */
	boolean_t	TransmitState;		/* Enabled/Disabled */

	uint16_t	ActorSystemPriority;	/* System Priority */
	uint16_t	CollectorMaxDelay;	/* tens of Usecs */
	aggr_lacp_timer_t PeriodicTimer;	/* AGGR_LACP_{LONG,SHORT} */
	uint64_t	TimeOfLastOperChange;	/* Time in state */
	boolean_t	ready;			/* Ready_N for all ports TRUE */
} Agg_t;

/*
 * 802.3ad Variables used for managing the operation of
 * the state machines (section 43.4.8)
 * Note: These are on a per port basis.
 */
typedef	enum {
	AGGR_UNSELECTED,	/* aggregator not selected */
	AGGR_SELECTED,		/* aggregator selected */
	AGGR_STANDBY		/* port in standby */
} lacp_selected_t;

typedef struct state_machine {
	uint32_t	lacp_on : 1,		/* LACP on or off */
			begin : 1,		/* LACP init(or reinit.) */
			lacp_enabled : 1,	/* Full/Half Duplex */
			port_enabled : 1,	/* Link Up/Down */
			actor_churn : 1,	/* failed to converge */
			partner_churn : 1,
			ready_n : 1,		/* waiting */
			port_moved : 1,		/* any port is not waiting */
			pad_bits : 24;
	/* "Ready" is accessed from the aggregator structure */
	lacp_selected_t	selected;	/* SELECTED/UNSELECTED/STANDBY */
	uint32_t	current_while_timer_exp; /* # of times timer expired */
	lacp_periodic_state_t	periodic_state;	/* State of periodic machine */
	lacp_receive_state_t	receive_state;	/* State of receive machine */
	lacp_mux_state_t	mux_state;	/* State of mux machine */
	lacp_churn_state_t	churn_state;	/* State of churn machine */
} state_machine_t;

/*
 * The following three flags are set when specific timer is timed out; used
 * by the LACP timer handler thread.
 */
#define	LACP_PERIODIC_TIMEOUT		0x01
#define	LACP_WAIT_WHILE_TIMEOUT		0x02
#define	LACP_CURRENT_WHILE_TIMEOUT	0x04
/*
 * Set when the port is being deleted; used to inform the LACP timer handler
 * thread to exit.
 */
#define	LACP_THREAD_EXIT		0x08

/*
 * 802.3ad Variables associated with each port (section 43.4.7)
 */
typedef struct aggr_lacp_port {
	uint16_t	ActorPortNumber;	/* actor port number */
	uint16_t	ActorPortPriority;	/* actor port priority */
	uint32_t	ActorPortAggrId;	/* aggregator id */
	boolean_t	NTT;			/* need to transmit */
	uint16_t	ActorAdminPortKey;	/* admin. port key */
	uint16_t	ActorOperPortKey;	/* oper port key */
	aggr_lacp_state_t ActorAdminPortState;	/* actor admin. port state */
	aggr_lacp_state_t ActorOperPortState;	/* actor oper. port state */

	/*
	 * partner information
	 */
	struct ether_addr PartnerAdminSystem;	/* partner admin. system */
	struct ether_addr PartnerOperSystem;	/* partner oper.system */
	uint16_t PartnerAdminSysPriority;	/* partner admin. sys. pri. */
	uint16_t PartnerOperSysPriority;	/* partner oper. sys. pri. */
	uint16_t PartnerAdminKey;		/* partner admin. key */
	uint16_t PartnerOperKey;		/* partner oper. key */
	uint16_t PartnerAdminPortNum;		/* partner admin. port # */
	uint16_t PartnerOperPortNum;		/* partner oper. port # */
	uint16_t PartnerAdminPortPriority;	/* partner admin. port pri. */
	uint16_t PartnerOperPortPriority;	/* partner oper. port pri. */
	aggr_lacp_state_t PartnerAdminPortState; /* partner admin port state */
	aggr_lacp_state_t PartnerOperPortState; /* partner oper port state */
	uint16_t PartnerCollectorMaxDelay;	/* tens of microseconds */

	/*
	 * State machine and Timer information.
	 */
	state_machine_t	sm;		/* state machine variables per port */
	lacp_timer_t	current_while_timer;
	lacp_timer_t	periodic_timer;
	lacp_timer_t	wait_while_timer;
	uint32_t	lacp_timer_bits;
	kthread_t	*lacp_timer_thread;
	kmutex_t	lacp_timer_lock;
	kcondvar_t	lacp_timer_cv;
	hrtime_t	time;
} aggr_lacp_port_t;

typedef struct lacp_stats_s {
	uint64_t	LACPDUsRx;
	uint64_t	MarkerPDUsRx;
	uint64_t	MarkerResponsePDUsRx;
	uint64_t	UnknownRx;
	uint64_t	IllegalRx;
	uint64_t	LACPDUsTx;
	uint64_t	MarkerPDUsTx;
	uint64_t	MarkerResponsePDUsTx;
} lacp_stats_t;

/*
 * 802.3ad protocol information
 */
/*
 * Actor/Partner information
 */
typedef struct link_info {
	uint8_t			tlv_type;	/* type/length/value */
	uint8_t			information_len; /* information length */
	uint16_t		system_priority; /* system priority */
	struct ether_addr	system_id;	/* encoded as MAC address */
	uint16_t		key;		/* operational key */
	uint16_t		port_priority;	/* port priority */
	uint16_t		port;		/* port */
	aggr_lacp_state_t	state;		/* state info */
	uint8_t			reserved[3];	/* reserved */
} link_info_t;

/*
 * Link Aggregation Control Protocol (LACPDU) structure
 */
typedef struct lacp {
	uint8_t			subtype;	/* = LACP */
	uint8_t			version;	/* LACP version */
	link_info_t		actor_info;	/* actor information */
	link_info_t		partner_info;	/* partner information */
	uint8_t			tlv_collector;	/* collector tlv */
	uint8_t			collector_len;	/* collector len */
	uint16_t		collector_max_delay; /* tens of miscrosecond */
	uint8_t			reserved[12];	/* reserved */
	uint8_t			tlv_terminator;	/* terminator tlv */
	uint8_t			terminator_len;	/* terminator len */
	uint8_t			lacp_reserved[50];	/* reserved */
} lacp_t;

/*
 * Marker protocol
 */

#define	MARKER_VERSION	0x1		/* 802.3ad Marker version number */
#define	MARKER_SUBTYPE	0x2
#define	MARKER_INFO_RESPONSE_LENGTH	16

/*
 * marker TLV_type
 */
#define	MARKER_INFO_TLV		0x01	/* marker information */
#define	MARKER_RESPONSE_TLV	0x02	/* marker response information */

typedef struct marker_pdu {
	struct ether_addr	dest_addr;	/* Slow protocol multicast */
	struct ether_addr	src_addr;	/* Source address */
	uint16_t		type;		/* Slow protocol type */
	uint8_t			subtype;	/* = Marker 0x2 */
	uint8_t			version;	/* Marker version 0x01 */
	uint8_t			tlv_marker;	/* marker tlv */
	uint8_t			marker_len;	/* marker len */
	uint16_t		requestor_port; /* requestor port */
	struct ether_addr	system_id;	/* requestor system */
	uint8_t			transaction_id[4];	/* transaction id */
	uint8_t			pad[2];		/* zeros to align */
	uint8_t			reserved[90];	/* reserved */
	uint32_t		fcs;		/* generated by MAC */
} marker_pdu_t;

/*
 * 802.3ad Link Aggregation Group Identifier (IEEE 802.3ad 43.3.6)
 * port identifire = port priority and port number.
 */
typedef struct lag_id {
	uint16_t		system_priority;	/* system priority */
	struct ether_addr	system_id;		/* system identifier */
	uint16_t		oper_key;		/* operational key */
	uint16_t		port_priority;		/* port priority */
	uint16_t		port_number;		/* 0: aggregatable */
} lag_id_t;

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AGGR_LACP_H */
