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
/*	  All Rights Reserved  	*/

/*
 * This is a private header file. Applications should not directly include
 * this file. Instead they should include <xti_inet.h>
 */

#ifndef _SYS_XTI_INET_H
#define	_SYS_XTI_INET_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This is a private header file. Applications should not directly include
 * this file. Instead they should include <xti_inet.h>
 */

#if !defined(_XPG5)

/*
 * INTERNET SPECIFIC ENVIRONMENT
 *
 * Note:
 * Unfortunately, XTI specification test assertions require exposing in
 * headers options that are not implemented. They also require exposing
 * Internet and OSI related options as part of inclusion of <xti.h>
 *
 * Also XTI specification intrudes on <netinet/in.h> TCP_ and IP_ namespaces
 * and sometimes redefines the semantics or types of some options with a
 * different history in that namespace. The name and binary value are exposed
 * but option semantics may be different from what is in XTI spec and we defer
 * to the <netinet/in.h> precedent.
 *
 * New applications should not use these constants. These are meant
 * for compatibility with older applications.
 */

/*
 * TCP level
 */
#define	INET_TCP	6 /* must be same as IPPROTO_TCP in <netinet/in.h> */

/*
 * TCP level options
 */
#ifndef TCP_NODELAY
#define	TCP_NODELAY	0x1	/* must be same as <netinet/tcp.h> */
#endif

#ifndef TCP_MAXSEG
#define	TCP_MAXSEG	0x2	/* must be same as <netinet/tcp.h> */
#endif

#ifndef TCP_KEEPALIVE
#define	TCP_KEEPALIVE	0x8	/* must be same as <netinet/tcp.h> */
#endif

#endif /* !defined(_XPG5) */

/*
 * New applications must not use the constants defined above. Instead
 * they must use the constants with the T_ prefix defined below. The
 * constants without the T_ prefix are meant for compatibility with
 * older applications.
 */

/*
 * TCP level
 */
#define	T_INET_TCP	6

#define	T_TCP_NODELAY	0x1	/* Don't delay packets to coalesce */
#define	T_TCP_MAXSEG	0x2	/* Get maximum segment size */
#define	T_TCP_KEEPALIVE	0x8	/* check, if connections are alive */

/*
 * Structure used with TCP_KEEPALIVE option.
 */
struct t_kpalive {
	t_scalar_t	kp_onoff;	/* option on/off */
	t_scalar_t	kp_timeout;	/* timeout in minutes */
};


#if !defined(_XPG5)

/*
 * New applications must not use the constants defined below. Instead they
 * must use the corresponding T_prefix constants. The constants without the
 * T_ prefix are supported for legacy applications.
 */

#define	T_GARBAGE		0x02 /* send garbage byte */

/*
 * UDP level
 */
#define	INET_UDP	17 /* must be same as IPPROTO_UDP in <netinet/in.h> */


/*
 * UDP level Options
 */

#ifndef UDP_CHECKSUM
#define	UDP_CHECKSUM	0x0600	/* must be same as in <netinet/udp.h> */
#endif

/*
 * IP level
 */
#define	INET_IP	0	/* must be same as IPPROTO_IP in <netinet/in.h> */

/*
 * IP level Options
 */

#ifndef IP_OPTIONS
#define	IP_OPTIONS	0x1	/* must be same as <netinet/in.h> */
#endif

#ifndef IP_TOS
#define	IP_TOS		0x3	/* must be same as <netinet/in.h> */
#endif

#ifndef IP_TTL
#define	IP_TTL		0x4	/* must be same as <netinet/in.h> */
#endif

/*
 * following also added to <netinet/in.h> and be in sync to keep namespace
 * sane
 */

#ifndef IP_REUSEADDR
#define	IP_REUSEADDR	0x104	/* allow local address reuse */
#endif

#ifndef IP_DONTROUTE
#define	IP_DONTROUTE	0x105	/* just use interface addresses */
#endif

#ifndef IP_BROADCAST
#define	IP_BROADCAST	0x106	/* permit sending of broadcast msgs */
#endif

#endif /* !defined(_XPG5) */

/*
 * New applications should use the T_ prefix constants below
 */

/*
 * UDP level
 */
#define	T_INET_UDP	17

/*
 * UDP level Options
 */
#define	T_UDP_CHECKSUM	0x0600	/* Checksum computation */

/*
 * IP level
 */
#define	T_INET_IP	0

/*
 * IP level Options
 */
#define	T_IP_TTL	0x4	/* IP per packet time to live */
#define	T_IP_REUSEADDR	0x104	/* allow local address reuse */
#define	T_IP_DONTROUTE	0x105	/* just use interface addresses */
#define	T_IP_BROADCAST	0x106	/* permit sending of broadcast msgs */
#define	T_IP_OPTIONS	0x107	/* IP per-packet options */
#define	T_IP_TOS	0x108	/* IP per packet type of service */

/*
 * IP_TOS precedence level
 */
#define	T_ROUTINE			0
#define	T_PRIORITY			1
#define	T_IMMEDIATE			2
#define	T_FLASH				3
#define	T_OVERRIDEFLASH			4
#define	T_CRITIC_ECP			5
#define	T_INETCONTROL			6
#define	T_NETCONTROL			7


/*
 * IP_TOS type of service
 */
#define	T_NOTOS		0
#define	T_LDELAY	(1<<4)
#define	T_HITHRPT	(1<<3)
#define	T_HIREL		(1<<2)
#define	T_LOCOST	(1<<1)

#define	SET_TOS(prec, tos)	((0x7 & (prec)) << 5 | (0x1e & (tos)))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_XTI_INET_H */
