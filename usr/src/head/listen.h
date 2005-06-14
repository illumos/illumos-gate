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


#ifndef	_LISTEN_H
#define	_LISTEN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4.3.1 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * listen.h:	Include file for network listener related user programs
 *
 */

/*
 * The NLPS (Network Listener Process Service)
 * protocol message sent by client machines to
 * a listener process to request a service on the listener's
 * machine. The message is sent to "netnodename(r_nodename)"
 * where r_nodename is the nodename (see uname(2)) of the
 * remote host. Note that client's need not know (or care)
 * about the details of this message.  They use the "nls_connect(3)"
 * library routine which uses this message.
 *
 * msg format:
 *
 *		"id:low:high:service_code"
 *
 *		id = "NLPS"
 *		low:high = version number of listener (see prot msg)
 *		service_code is ASCII/decimal
 *
 * the following prot string can be run through sprintf with a service code
 * to generate the message:
 *
 *	len = sprintf(buf,nls_prot_msg,svc_code);
 *	t_snd(fd, buf, len, ...);
 *
 * See also:  listen(1), nlsrequest(3)
 *
 * and on the UNIX PC STARLAN NETWORK:
 * See also:  nlsname(3), nlsconnect(3), nlsestablish(3)
 */

/*
 * defines for compatability purposes
 */

#define	nls_prot_msg	nls_v0_d
#define	nls_v2_msg	nls_v2_s

static char *nls_v0_d = "NLPS:000:001:%d";
static char *nls_v0_s = "NLPS:000:001:%s";
static char *nls_v2_d = "NLPS:002:002:%d";
static char *nls_v2_s = "NLPS:002:002:%s";

#define	NLSSTART	0
#define	NLSFORMAT	2
#define	NLSUNKNOWN	3
#define	NLSDISABLED	4

#define	SVC_CODE_SZ	14

/*
 * Structure for handling multiple connection requests on the same stream.
 */

struct callsave {
	struct t_call *c_cp;
	struct callsave *c_np;
};

struct call_list {
	struct callsave *cl_head;
	struct callsave *cl_tail;
};


#define	EMPTYLIST(p)	(p->cl_head == (struct callsave *) NULL)

/*
 * Ridiculously high value for maximum number of connects per stream.
 * Transport Provider will determine actual maximum to be used.
 */

#define	MAXCON		100

/*
 * these are names of environment variables that the listener
 * adds to the servers environment before the exec(2).
 *
 * the variables should be accessed via library routines.
 *
 * see nlsgetcall(3X) and nlsprovider(3X).
 */

#define	NLSADDR		"NLSADDR"
#define	NLSOPT		"NLSOPT"
#define	NLSUDATA	"NLSUDATA"
#define	NLSPROVIDER	"NLSPROVIDER"

/*
 * the following variables can be accessed "normally"
 */

#define	HOME		"HOME"
#define	PATH		"PATH"

#ifdef	__cplusplus
}
#endif

#endif	/* _LISTEN_H */
