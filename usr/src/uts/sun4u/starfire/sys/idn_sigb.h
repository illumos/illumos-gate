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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Inter-Domain Network Sigblock Interface.
 *
 * ******************************************************
 * ******************************************************
 * IMPORTANT:	THE DEFINITIONS HERE ARE DUPLICATES OF
 *		THE cbe_idn_sigb.h FILE IN cbe/cbutils.
 *		ANY CHANGES THERE MUST BE RELECTED
 *		HERE AND VICE VERSA.  WE CANNOT INCLUDE
 *		THIS HEADER IN THE BUILD OF CBE.
 * ******************************************************
 * ******************************************************
 */

#ifndef _SYS_IDN_SIGB_H
#define	_SYS_IDN_SIGB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _SSP
#include <domain_config.h>
#include <sigblock.h>
#define	_MAX_DOMAINS	MAX_DOMAINS_PER_MACH
#else /* _SSP */
#include <sys/starfire.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/cpu_sgn.h>
#define	MAX_BOARDS	STARFIRE_MAX_BOARDS
#define	MAX_DOMAINS	MAX_BOARDS
#define	_MAX_DOMAINS	MAX_DOMAINS
#endif /* _SSP */

#define	SSI_LINK	(('I' << 8) | 0x01)
#define	SSI_UNLINK	(('I' << 8) | 0x02)
#define	SSI_INFO	(('I' << 8) | 0x03)
#define	SSI_ACK		0x10

#define	VALID_IDNSIGBCMD(c)	((((c) & ~SSI_ACK) == SSI_LINK) || \
				(((c) & ~SSI_ACK) == SSI_UNLINK) || \
				(((c) & ~SSI_ACK) == SSI_INFO))

/*
 * SSI_LINK
 * timeout field must be first.
 */
typedef struct {
	int32_t		timeout;	/* seconds */
	int32_t		cpuid;
	int32_t		domid;
	int32_t		master_pri;
} idnsb_link_t;


/*
 * SSI_UNLINK
 * timeout field must be first.
 *
 * If both cpuid and domid are specified then they must match the
 * correct domain from the local domain's perspective.  The cpuid
 * and/or domid have precedence over the boardset parameter.
 * The boardset parameter is provided if the caller is unable to
 * determine the cpuid/domid of the target domain.  This may happen
 * if the target domain is currently down.
 *
 * idnsb_unlink_t.force values.
 */
#define	SSIFORCE_OFF	0
#define	SSIFORCE_SOFT	1
#define	SSIFORCE_HARD	2

typedef struct {
	int32_t		timeout;	/* seconds */
	int32_t		cpuid;
	int32_t		domid;
	ushort_t	boardset;
	short		force;
	ushort_t	idnset;
} idnsb_unlink_t;


/*
 * SSI_INFO
 *	Assumes max of 16 boards/domain.
 *
 * idnsb_info_t.idn_active values.
 */
#define	SSISTATE_INACTIVE	0
#define	SSISTATE_BUSY		1
#define	SSISTATE_ACTIVE		2

typedef struct {
	ushort_t	domain_boardset[_MAX_DOMAINS];
	uchar_t		idn_active;
	uchar_t		idn_state;	/* same as GSTATE */
	uchar_t		local_index;
	uchar_t		local_cpuid;
	uchar_t		master_index;
	uchar_t		master_cpuid;
	ushort_t	awol_domset;
	ushort_t	conn_domset;
	ushort_t	_filler;
} idnsb_info_t;

#define	INIT_IDNKERR(ep) \
		(bzero((caddr_t)(ep), sizeof (idnsb_error_t)))
#define	SET_IDNKERR_ERRNO(ep, err)	((ep)->k_errno = (int)(err))
#define	SET_IDNKERR_IDNERR(ep, err)	((ep)->k_idnerr = (int)(err))
#define	SET_IDNKERR_PARAM0(ep, p0)	((ep)->k_param[0] = (uint_t)(p0))
#define	SET_IDNKERR_PARAM1(ep, p1)	((ep)->k_param[1] = (uint_t)(p1))
#define	SET_IDNKERR_PARAM2(ep, p2)	((ep)->k_param[2] = (uint_t)(p2))
#define	GET_IDNKERR_ERRNO(ep)		((ep)->k_errno)
#define	GET_IDNKERR_IDNERR(ep)		((ep)->k_idnerr)
#define	GET_IDNKERR_PARAM0(ep)		((ep)->k_param[0])
#define	GET_IDNKERR_PARAM1(ep)		((ep)->k_param[1])
#define	GET_IDNKERR_PARAM2(ep)		((ep)->k_param[2])

#define	IDNKERR_DRV_DISABLED	0x100	/* IDN driver disabled */
					/* param=none */
#define	IDNKERR_DATA_LEN	0x101	/* invalid length of idnsb_data_t */
					/* p0=length */
#define	IDNKERR_INFO_FAILED	0x102	/* SSI_INFO failed */
					/* param=none */
#define	IDNKERR_INVALID_DOMAIN	0x103	/* invalid domain specified */
					/* p0=domid, p1=cpuid */
#define	IDNKERR_INVALID_FORCE	0x104	/* invalid force option specified */
					/* p0=force */
#define	IDNKERR_INVALID_CMD	0x105	/* invalid IDN/SSI command req */
					/* p0=cmd */
#define	IDNKERR_INVALID_WTIME	0x106	/* invalid waittime specified */
					/* p0=waittime */
#define	IDNKERR_SMR_CORRUPTED	0x107	/* SMR memory is corrupted */
					/* p0=domid (against who detected) */
#define	IDNKERR_CPU_CONFIG	0x108	/* missing a cpu per board */
					/* p0=domid */
#define	IDNKERR_HW_ERROR	0x109	/* error programming hardware */
					/* p0=domid */
#define	IDNKERR_SIGBINTR_LOCKED	0x10a	/* sigbintr is locked */
#define	IDNKERR_SIGBINTR_BUSY	0x10b	/* sigbintr is busy working */
#define	IDNKERR_SIGBINTR_NOTRDY	0x10c	/* sigbintr thread not ready */
#define	IDNKERR_CONFIG_FATAL	0x10d	/* fatal error during config */
#define	IDNKERR_CONFIG_MULTIPLE	0x10e	/* multiple config conflicts */
					/* p0=domid, p1=count */
	/*
	 * For all CONFIG errors:
	 *	p0=domid, p1=expected, p2=actual.
	 */
#define	IDNKERR_CONFIG_MTU	0x10f	/* MTU configs conflict */
#define	IDNKERR_CONFIG_BUF	0x110	/* SMR_BUF_SIZE conflicts */
#define	IDNKERR_CONFIG_SLAB	0x111	/* slab-size conflicts */
#define	IDNKERR_CONFIG_NWR	0x112	/* NWR sizes conflict */
#define	IDNKERR_CONFIG_NETS	0x113	/* MAX_NETS conflict */
#define	IDNKERR_CONFIG_MBOX	0x114	/* MBOX_PER_NETS conflict */
#define	IDNKERR_CONFIG_NMCADR	0x115	/* Number of MCADRS conflicts */
#define	IDNKERR_CONFIG_MCADR	0x116	/* Missing MCADR */
#define	IDNKERR_CONFIG_CKSUM	0x117	/* checksum setting conflicts */
#define	IDNKERR_CONFIG_SMR	0x118	/* master's SMR too large */

typedef struct {
	int		k_errno;
	int		k_idnerr;
	uint_t		k_param[3];
} idnsb_error_t;

typedef struct {
	union {
		int		_ssb_timeout;	/* link & unlink only (secs) */
		idnsb_link_t	_ssb_link;
		idnsb_unlink_t	_ssb_unlink;
		idnsb_info_t	_ssb_info;
	} _u;
	idnsb_error_t	ssb_error;
} idnsb_data_t;

#define	ssb_timeout	_u._ssb_timeout
#define	ssb_link	_u._ssb_link
#define	ssb_unlink	_u._ssb_unlink
#define	ssb_info	_u._ssb_info


/*
 * Boot information set by IDN driver when loaded.
 * SSIEVENT_BOOT Indicates IDN driver is ready for linking.
 *		 If this nibble is cleared (0) it
 *		 indicates domain has halted.
 * SSIEVENT_AWOL Indicates local IDN has reported
 *		 some domains (boards) have gone AWOL.
 * (event_handled) is primarily used by SSP/CB applications for
 * synchronization with respect to handling event triggered in (event).
 * The respective bits from (event) are set in (event_handled)
 * when the event has been successfully processed by IDNevent(SSP).
 * It is cleared by CBE based TCL scripts (mon_signatures.tcl, idn.tcl)
 * when event is detected and needs processing.
 * SSIEVENT_VERSION represents the version of the SSP side of
 * the IDN software.  While idnsb_event_t.version represents the
 * version of the OS side of the IDN software.
 *
 * Protocol:	Host				SSP
 *		----				---
 *		event
 *		- 1 -> evt[].e_handled
 *		- X -> evt[].e_event
 *		- Y -> evt[].e_event_data
 *		- 0 -> evt[].e_handled
 *					(!evt[].e_handled)
 *					...process(evt[].e_event)
 *					- evt[].e_handled_data =
 *							evt[].e_event_data
 *					- evt[].e_handled = 1
 */
#define	SSIEVENT_COOKIE		"IDN"
#define	SSIEVENT_COOKIE_LEN	3
#define	SSIEVENT_VERSION	1

#define	SSIEVENT_BOOT		0	/* index to evt[] */
#define	_SSIEVENT_BOOT_VAL	0xb
#define	_SSIEVENT_BOOT_SHIFT	(SSIEVENT_BOOT << 2)
#define	_SSIEVENT_BOOT_MASK	(_SSIEVENT_BOOT_VAL << _SSIEVENT_BOOT_SHIFT)

#define	SSIEVENT_AWOL		1
#define	_SSIEVENT_AWOL_VAL	0xa
#define	_SSIEVENT_AWOL_SHIFT	(SSIEVENT_AWOL << 2)
#define	_SSIEVENT_AWOL_MASK	(_SSIEVENT_AWOL_VAL << _SSIEVENT_AWOL_SHIFT)

#define	SSIEVENT_NUM		2	/* actual max simultaneous events */
#define	SSIEVENT_MAXNUM		3	/* last one in reserve */

#define	_SSIEVENT_VALUE(i) \
	((i == 0) ? _SSIEVENT_BOOT_VAL : ((i == 1) ? _SSIEVENT_AWOL_VAL : 0))

#define	_SSIEVENT_MASKS(i) \
	((i == 0) ? _SSIEVENT_BOOT_MASK : ((i == 1) ? _SSIEVENT_AWOL_MASK : 0))
/*
 * Get a bitmask of the current "state".
 */
#define	SSIEVENT_GET_STATE_MASK(s) \
	(((s).idn_evt[SSIEVENT_BOOT].e_event ? _SSIEVENT_BOOT_MASK : 0) \
	| ((s).idn_evt[SSIEVENT_AWOL].e_event ? _SSIEVENT_AWOL_MASK : 0))

#define	SSIEVENT_GET_STATE(s, e) \
			((s).idn_evt[e].e_event ? _SSIEVENT_VALUE(e) : 0)
#define	SSIEVENT_CLR_STATE(s, e) \
			((s).idn_evt[e].e_event = 0)
#define	SSIEVENT_SET_STATE(s, e) \
			((s).idn_evt[e].e_event = _SSIEVENT_VALUE(e))

/*
 * Get a bitmask of the currently handled states.
 */
#define	SSIEVENT_GET_HANDLED_MASK(s) \
	(((s).idn_evt[SSIEVENT_BOOT].e_handled ? _SSIEVENT_BOOT_MASK : 0) \
	| ((s).idn_evt[SSIEVENT_AWOL].e_handled ? _SSIEVENT_AWOL_MASK : 0))

#define	SSIEVENT_GET_HANDLED(s, e) \
			((s).idn_evt[e].e_handled ? _SSIEVENT_VALUE(e) : 0)
#define	SSIEVENT_CLR_HANDLED(s, e) \
			((s).idn_evt[e].e_handled = 0)
#define	SSIEVENT_SET_HANDLED(s, e) \
			((s).idn_evt[e].e_handled = _SSIEVENT_VALUE(e))
#define	SSIEVENT_SET_HANDLED_DATA(s, e, d) \
			((s).idn_evt[e].e_handled_data = (ushort_t)(d))
#define	SSIEVENT_GET_HANDLED_EVT(i, e) \
				((i).e_handled ? _SSIEVENT_VALUE(e) : 0)
#define	SSIEVENT_CLR_HANDLED_EVT(i)	((i).e_handled = 0)
#define	SSIEVENT_SET_HANDLED_EVT(i, e)	((i).e_handled = _SSIEVENT_VALUE(e))

/*
 * Check for the state of a particular event within a state bitmask.
 */
#define	SSIEVENT_CHK_STATE_MASK(m, e) \
	((((m) & (0xf << ((e) << 2))) == _SSIEVENT_MASKS(e)) ? 1 : 0)
#define	SSIEVENT_CHK_HANDLED_MASK(m, e)	SSIEVENT_CHK_STATE_MASK((m), (e))

/*
 * Build the state mask managed in the cbe to represent the state
 * of the respective events above.
 */
#define	SSIEVENT_DEL_STATE_MASK(m, e)	((m) &= ~(0xf << ((e) << 2)))
#define	SSIEVENT_ADD_STATE_MASK(m, e) \
		(SSIEVENT_DEL_STATE_MASK((m), (e)), \
		((m) |= _SSIEVENT_MASKS(e)))
#define	SSIEVENT_STATE_MASK	(_SSIEVENT_BOOT_MASK | _SSIEVENT_AWOL_MASK)
#define	SSIEVENT_STATE_NIL	0

#ifdef _KERNEL
#define	SSIEVENT_SET(s, e, d) { \
		SSIEVENT_SET_HANDLED(*(s), (e)); \
		membar_stst_stld(); \
		SSIEVENT_SET_STATE(*(s), (e)); \
		(s)->idn_evt[e].e_event_data = (ushort_t)(d); \
		membar_stst_stld(); \
		SSIEVENT_CLR_HANDLED(*(s), (e)); \
}
#define	SSIEVENT_CLEAR(s, e, d) { \
		SSIEVENT_SET_HANDLED(*(s), (e)); \
		membar_stst_stld(); \
		SSIEVENT_CLR_STATE(*(s), (e)); \
		(s)->idn_evt[e].e_event_data &= (ushort_t)~(d); \
		membar_stst_stld(); \
		SSIEVENT_CLR_HANDLED(*(s), (e)); \
}
#define	SSIEVENT_ADD(s, e, d) { \
		SSIEVENT_SET_HANDLED(*(s), (e)); \
		membar_stst_stld(); \
		SSIEVENT_SET_STATE(*(s), (e)); \
		(s)->idn_evt[e].e_event_data |= (ushort_t)(d); \
		membar_stst_stld(); \
		SSIEVENT_CLR_HANDLED(*(s), (e)); \
}
#define	SSIEVENT_DEL(s, e, d) { \
		SSIEVENT_SET_HANDLED(*(s), (e)); \
		membar_stst_stld(); \
		(s)->idn_evt[e].e_event_data &= (ushort_t)~(d); \
		if ((s)->idn_evt[e].e_event_data != 0) { \
			SSIEVENT_SET_STATE(*(s), (e)); \
			membar_stst_stld(); \
			SSIEVENT_CLR_HANDLED(*(s), (e)); \
		} else { \
			membar_stst_stld(); \
			SSIEVENT_CLR_STATE(*(s), (e)); \
		} \
}
#endif /* _KERNEL */

typedef struct idnevent {
	uchar_t		e_event;
	uchar_t		e_handled;
	ushort_t	e_event_data;
	ushort_t	e_handled_data;
	ushort_t	reserved;
} idnevent_t;

/*
 * IMPORTANT: This data structure must be the size of a sigbmbox_t
 *	      so that it fits in the space it steals in the sigblock.
 *            Also, any changes to this structure must be cross-checked
 *	      with (struct idnsb) in <sun4u1/sys/idn.h> with respect
 *	      the area from reserved1 on down.
 */
#define	IDNSB_EVENT_SIZE	(sizeof (sigbmbox_t))
typedef struct {
	struct _idnsb_event {
		union {
			struct {
				char	_cookie[SSIEVENT_COOKIE_LEN];
				uchar_t	_version;
			} _ss;
			struct {
				uint_t	_cookie : 24;
				uint_t	_version : 8;
			} _sn;
		} _u;
		uint_t		_reserved1;	/* reserved for IDN driver */
		idnevent_t	_evt[SSIEVENT_MAXNUM];
	} _s;

		/* reserved for IDN driver */
	char	reserved2[IDNSB_EVENT_SIZE - sizeof (struct _idnsb_event)];
} idnsb_event_t;

#define	idn_evt			_s._evt
#define	idn_reserved1		_s._reserved1
#define	idn_cookie_str		_s._u._ss._cookie
#define	idn_version_byte	_s._u._ss._version
#define	idn_cookie		_s._u._sn._cookie
#define	idn_version		_s._u._sn._version

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_IDN_SIGB_H */
