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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4.1.1	*/

/*
 * The Network Listener Process Service (NLPS)
 * protocol message sent by client machines to
 * a listener process to request a service on the listener's
 * machine. The message is sent to "netnodename(r_nodename)"
 * where r_nodename is the nodename (see uname(2)) of the
 * remote host. Note that client's need not know (or care)
 * about the details of this message.  They use the "att_service(3)"
 * library routine which uses this message.
 *
 * Message is in ASCII and has the following format:
 *
 * iiii:lll:hhh:ssssssssssssss
 *
 * where:
 *	iiii = 4 character ID == "NLPS"
 *	lll = 3 character low version number (ASCII decimal digits)
 *	hhh = 3 character hi  version number (ASCII decimal digits)
 *	ssssssssssssss = 14 character service_code (ASCII letters, digits or '_')
 *	: = field separator char == ':'
 */

#define NLPSIDSZ	4
#define NLPSIDSTR	"NLPS"
#define NLPSSEPCHAR	':'		/* field separator character */

