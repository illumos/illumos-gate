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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 *  Copyright (c) 1996-1999 by the University of Southern California.
 *  All rights reserved.
 *
 *  Permission to use, copy, modify, and distribute this software and
 *  its documentation in source and binary forms for lawful
 *  purposes and without fee is hereby granted, provided
 *  that the above copyright notice appear in all copies and that both
 *  the copyright notice and this permission notice appear in supporting
 *  documentation, and that any documentation, advertising materials,
 *  and other materials related to such distribution and use acknowledge
 *  that the software was developed by the University of Southern
 *  California and/or Information Sciences Institute.
 *  The name of the University of Southern California may not
 *  be used to endorse or promote products derived from this software
 *  without specific prior written permission.
 *
 *  THE UNIVERSITY OF SOUTHERN CALIFORNIA DOES NOT MAKE ANY REPRESENTATIONS
 *  ABOUT THE SUITABILITY OF THIS SOFTWARE FOR ANY PURPOSE.  THIS SOFTWARE IS
 *  PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES,
 *  INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND
 *  NON-INFRINGEMENT.
 *
 *  IN NO EVENT SHALL USC, OR ANY OTHER CONTRIBUTOR BE LIABLE FOR ANY
 *  SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES, WHETHER IN CONTRACT,
 *  TORT, OR OTHER FORM OF ACTION, ARISING OUT OF OR IN CONNECTION WITH,
 *  THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  Other copyrights might apply to parts of this software and are so
 *  noted when applicable.
 */

#ifndef _NETINET_PIM_H
#define	_NETINET_PIM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Protocol Independent Multicast (PIM) definitions
 *
 * Written by Ahmed Helmy, USC/SGI, July 1996
 * Modified by George Edmond Eddy (Rusty), ISI, February 1998
 * Modified by Pavlin Ivanov Radoslavov, USC/ISI, May 1998
 *
 * $Id: pim.h,v 1.3 1999/08/31 03:03:08 pavlin Exp $
 */

/*
 * PIM packet format.
 */
typedef struct pim {
#ifdef _BIT_FIELDS_LTOH
	uint8_t		pim_type:4,	/* type of PIM message */
			pim_vers:4;	/* PIM version */
#else
	uint8_t		pim_vers:4,	/* PIM version */
			pim_type:4;	/* type of PIM message */
#endif
	uint8_t		pim_reserved;	/* Reserved */
	uint16_t	pim_cksum;	/* IP-style checksum */
} pim_t;

#define	PIM_VERSION	2
#define	PIM_MINLEN	8		/* The header min. length is 8 */

/* Register message + inner IPheader */
#define	PIM_REG_MINLEN 	(PIM_MINLEN + IP_SIMPLE_HDR_LENGTH)

/*
 * From the PIM protocol spec (RFC 2362), the following PIM message types
 * are defined.  All of these, except PIM_REGISTER, are currently not defined
 * in the USC/ISI distributed <netinet/pim.h> include file.  So they are listed
 * here commented out.
 *
 * #define	PIM_HELLO		0x0
 * #define	PIM_REGISTER		0x1
 * #define	PIM_REGISTER_STOP	0x2
 * #define	PIM_JOIN_PRUNE		0x3
 * #define	PIM_BOOTSTRAP		0x4
 * #define	PIM_ASSERT		0x5
 * #define	PIM_GRAFT		0x6
 * #define	PIM_GRAFT_ACK		0x7
 * #define	PIM_CAND_RP_ADV		0x8
 *
 */
#define	PIM_REGISTER	0x1		/* PIM Register type is 1 */

/*
 * First bit in reg_head (right after PIM header) is the Border bit.
 */
#define	PIM_BORDER_REGISTER	0x80000000

/*
 * Second bit in reg_head (right after PIM header) is the Null-Register bit
 */
#define	PIM_NULL_REGISTER	0x40000000

#ifdef __cplusplus
}
#endif

#endif /* _NETINET_PIM_H */
