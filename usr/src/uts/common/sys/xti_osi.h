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
/*	Copyright (c) 1996-1998 Sun Microsystems, Inc.	*/
/*	  All Rights Reserved	*/


#ifndef _SYS_XTI_OSI_H
#define	_SYS_XTI_OSI_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_XPG5)

/*
 * SPECIFIC ISO OPTION AND MANAGEMENT PARAMETERS
 *
 * Note:
 * Unfortunately, XTI specification test assertions require exposing in
 * headers options that are not implemented. They also require exposing
 * Internet and OSI related options as part of inclusion of <xti.h>
 *
 */


/*
 * Definitions of ISO transport classes
 */

#define	T_CLASS0	0
#define	T_CLASS1	1
#define	T_CLASS2	2
#define	T_CLASS3	3
#define	T_CLASS4	4


/*
 * Definition of the priorities
 */

#define	T_PRITOP	0
#define	T_PRIHIGH	1
#define	T_PRIMID	2
#define	T_PRILOW	3
#define	T_PRIDFLT	4

/*
 * Definitions of the protection levels
 */

#define	T_NOPROTECT		1
#define	T_PASSIVEPROTECT	2
#define	T_ACTIVEPROTECT		4

/*
 * Default values for the length of TPDUs
 * Note: Sigh ! This obsolete constant required according to XTI test
 *	 assertions.
 */

#define	T_LTPDUDFLT	128	/* define obsolete in XPG4 */

/*
 * rate structure
 */

struct rate {
	t_scalar_t	targetvalue;	/* target value */
	t_scalar_t	minacceptvalue;	/* value of minimum */
					/* acceptable quality */
};

/*
 * reqvalue structure
 */

struct reqvalue {
	struct rate called;	/* called rate */
	struct rate calling;	/* calling rate */
};

/*
 * thrpt structure
 */

struct thrpt {
	struct reqvalue maxthrpt; /* maximum throughput */
	struct reqvalue avgthrpt; /* average throughput */
};

/*
 * transdel structure
 */

struct transdel {
	struct reqvalue maxdel;	/* maximum transit delay */
	struct reqvalue avgdel;	/* average throughput */
};

/*
 * Protocol Levels
 */

#define	ISO_TP	0x0100

/*
 * Options for Quality of Service and Expedited Data (ISO 8072:1986)
 */

#define	TCO_THROUGHPUT		0x0001
#define	TCO_TRANSDEL		0x0002
#define	TCO_RESERRORRATE	0x0003
#define	TCO_TRANSFFAILPROB	0x0004
#define	TCO_ESTFAILPROB		0x0005
#define	TCO_RELFAILPROB		0x0006
#define	TCO_ESTDELAY		0x0007
#define	TCO_RELDELAY		0x0008
#define	TCO_CONNRESIL		0x0009
#define	TCO_PROTECTION		0x000a
#define	TCO_PRIORITY		0x000b
#define	TCO_EXPD		0x000c

#define	TCL_TRANSDEL		0x000d
#define	TCL_RESERRORRATE	TCO_RESERRORRATE
#define	TCL_PROTECTION		TCO_PROTECTION
#define	TCL_PRIORITY		TCO_PRIORITY


/*
 * Management Options
 */

#define	TCO_LTPDU		0x0100
#define	TCO_ACKTIME		0x0200
#define	TCO_REASTIME		0x0300
#define	TCO_EXTFORM		0x0400
#define	TCO_FLOWCTRL		0x0500
#define	TCO_CHECKSUM		0x0600
#define	TCO_NETEXP		0x0700
#define	TCO_NETRECPTCF		0x0800
#define	TCO_PREFCLASS		0x0900
#define	TCO_ALTCLASS1		0x0a00
#define	TCO_ALTCLASS2		0x0b00
#define	TCO_ALTCLASS3		0x0c00
#define	TCO_ALTCLASS4		0x0d00

#define	TCL_CHECKSUM		TCO_CHECKSUM

#endif /* !defined(_XPG5) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_XTI_OSI_H */
