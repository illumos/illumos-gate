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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_TPICOMMON_H
#define	_SYS_TPICOMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/feature_tests.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * WARNING: This header should not ever be included directly by application
 * programs. It exists so that common definitions can be included by other
 * system header files which define a documented interface. The interfaces
 * that share and expose the definitions in this file are:
 *
 *	(1) TLI interface <tiuser.h>  (which includes <sys/tiuser.h> which
 *				   includes this file)
 *	(2) XTI interface <xti.h>
 *	(3) Kernel Streams TPI message based inteface <sys/tihdr.h>
 */


/*
 * The following are "t_errno" error codes needed by both the kernel
 * level transport providers and the user level interfaces.
 */

#define	TBADADDR	1	/* Incorrect address format */
#define	TBADOPT		2	/* Incorrect options format */
#define	TACCES		3	/* Illegal permissions */
#define	TBADF		4	/* Illegal file descriptor */
#define	TNOADDR		5	/* Couldn't allocate address */
#define	TOUTSTATE	6	/* Routine will place interface out of state */
#define	TBADSEQ		7	/* Illegal called/calling sequence number */
#define	TSYSERR		8	/* System error */
#define	TLOOK		9	/* An event requires attention */
#define	TBADDATA	10	/* Illegal amount of data */
#define	TBUFOVFLW	11	/* Buffer not large enough */
#define	TFLOW		12	/* Can't send message - (blocked) */
#define	TNODATA		13	/* No message currently available */
#define	TNODIS		14	/* Disconnect message not found */
#define	TNOUDERR	15	/* Unitdata error message not found */
#define	TBADFLAG	16	/* Incorrect flags specified */
#define	TNOREL		17	/* Orderly release message not found */
#define	TNOTSUPPORT	18	/* Primitive not supported by provider */
#define	TSTATECHNG	19	/* State is in process of changing */
/*
 * Following new error codes added to namespace with introduction of XTI
 */
#define	TNOSTRUCTYPE	20	/* Unsupported structure type requested */
#define	TBADNAME	21	/* Invalid transport provider name */
#define	TBADQLEN	22	/* Listener queue length limit is zero */
#define	TADDRBUSY	23	/* Transport address is in use */
#define	TINDOUT		24	/* Outstanding connection indications */
#define	TPROVMISMATCH	25
			/* Listener-acceptor transport provider mismatch */

#define	TRESQLEN	26
/* Connection acceptor has listen queue length limit greater than zero */

#define	TRESADDR	27
/* Connection acceptor-listener addresses not same but required by transport */

#define	TQFULL		28	/* Incoming connection queue is full */
#define	TPROTO		29	/* Protocol error on transport primitive */

/*
 * Service type defines - used with T_info_ack
 */
#define	T_COTS	   1	/* connection oriented transport service	*/
#define	T_COTS_ORD 2	/* connection oriented w/ orderly release	*/
#define	T_CLTS	   3	/* connectionless transport service		*/
/*
 * NOT FOR PUBLIC USE, Solaris internal only.
 * This value of nc_semantics is strictly for use of Remote Direct
 * Memory Access provider interfaces in Solaris only and not for
 * general use. Do not use this value for general purpose user or
 * kernel programming. If used the behavior is undefined.
 * This is a PRIVATE interface to be used by Solaris kRPC only.
 */
#define	T_RDMA	   4	/* rdma transport service			*/


/*
 * The following are the flag definitions needed by the
 * user level library routines.
 */

/*
 * flags for option management request primitives
 * Note:
 * - This namespace is distinct from the namespace for data
 *   primitives.
 * - Flags T_NEGOTIATE, T_CHECK, T_DEFAULT, T_CURRENT
 *   are associated with an option request
 * - Flags T_SUCCESS, T_FAILURE, T_PARTSUCCESS, T_READONLY,
 *   T_NOTSUPPORT are associated with results of option request.
 */
#define	T_NEGOTIATE	0x004	/* set opts request	*/
#define	T_CHECK		0x008	/* check opts request	*/
#define	T_DEFAULT	0x010	/* get default opts request */
#define	T_SUCCESS	0x020	/* successful result */
#define	T_FAILURE	0x040	/* failure result */
#define	T_CURRENT	0x080	/* get current options request */
#define	T_PARTSUCCESS	0x100	/* partial success result */
#define	T_READONLY	0x200	/* read-only result */
#define	T_NOTSUPPORT	0x400	/* not supported result */


/*
 * General purpose defines - used in multiple options context.
 * They (T_YES and T_NO) need to be bitwise distinct from T_GARBAGE
 * used with TCP level options by XTI for historical XTI specification
 * reasons.
 * (T_GARBAGE declared in <sys/xti_inet.h> included by <xti.h>).
 */
#define	T_YES			1
#define	T_NO			0

/*
 * Values used with struct T_info_ack fields
 */
#define	T_INFINITE		-1
#define	T_INVALID		-2

/*
 * Constants used with option management "name" or "value" fields.
 */

/*
 * XTI defined value reserved for stating 'unspecified' value used
 * in some option namespaces.
 */
#define	T_UNSPEC	(~0-2)	/* applicable to ulong_t, long, char */

/*
 * XTI inspired option management defined an option name T_ALLOPT
 * to imply all options of a certain level.
 * No option name (for any level) should be defined with constant value of
 * T_ALLOPT (0).
 */
#define	T_ALLOPT	0	/* all options at any level */

/*
 * An option specification consists of an opthdr, followed by the value of
 * the option.  An options buffer contains one or more options.  The len
 * field of opthdr specifies the length of the option value in bytes.  This
 * length must be a multiple of sizeof (t_scalar_t) (use OPTLEN macro).
 * This is an antique definition which is used (unofficially) by TLI but
 * superceded in XTI.
 */
/*
 * The opthdr types are now t_uscalar_t - inspired by XTI
 */
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
struct opthdr {
	t_uscalar_t	level;	/* protocol level affected */
	t_uscalar_t	name;	/* option to modify */
	t_uscalar_t	len;	/* length of option value */
};

#define	OPTLEN(x) ((((x) + sizeof (t_uscalar_t) - 1) / \
		    sizeof (t_uscalar_t)) * sizeof (t_uscalar_t))
#define	OPTVAL(opt) ((char *)(opt + 1))
#endif	/* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TPICOMMON_H */
