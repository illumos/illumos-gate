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
 * Copyright (c) 2002-2004, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DAT_PLATFORM_SPECIFIC_H_
#define	_DAT_PLATFORM_SPECIFIC_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 * HEADER: dat_platform_specific.h
 *
 * PURPOSE: defines Platform specific types.
 *
 * Description: Header file for "uDAPL: User Direct Access Programming
 *		Library, Version: 1.2"
 *
 * Mapping rules:
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

/* OS, processor, compiler type definitions. Add OS's as needed. */

/*
 * This captures the alignment for the bus transfer from the HCA/IB chip
 * to the main memory.
 */
#ifndef DAT_OPTIMAL_ALIGNMENT
#define	DAT_OPTIMAL_ALIGNMENT   256	/* Performance optimal alignment */
#endif /* DAT_OPTIMAL_ALIGNMENT */

/*
 * Assume all O/Ss use sockaddr, for address family: IPv4 == AF_INET,
 * IPv6 == AF_INET6. Use of "namelen" field indicated.
 *
 * The Interface Adaptor Address names an Interface Adaptor local or
 * remote, that is used for connection management and Name
 * Service. The format of the dat_ia_address_ptr follows the normal
 * socket programming practice of struct sockaddr *. DAT supports both
 * IPv4 and IPv6 address families.  Allocation and initialization of
 * DAT IA address structures must follow normal Sockets programming
 * procedures. The underlying type of the DAT IA address is the native
 * struct sockaddr for each target operating system. In all cases,
 * storage appropriate for the address family in use by the target
 * Provider must be allocated.  For instance, when IPv6 addressing is
 * in use, this should be allocated as struct sockaddr_net6. The
 * sockaddr sa_family and, if present, sa_len fields must be
 * initialized appropriately, as well as the address information.
 * When passed across the DAPL API this storage is cast to the
 * DAT_IA_ADDRESS_PTR type. It is the responsibility of the callee to
 * verify that the sockaddr contains valid data for the requested
 * operation. It is always the responsibility of the caller to manage
 * the storage.
 *
 * Code example for Linux:
 *
 * #include <stdio.h>
 * #include <sys/socket.h>
 * #include <netinet/in.h>
 * #include <dat/udat.h>
 *
 *  struct sockaddr_in6 addr;
 *  DAT_IA_ADDRESS_PTR ia_addr;
 *
 *	// Note: linux pton requires explicit encoding of IPv4 in IPv6
 *
 *	addr.sin6_family = AF_INET6;
 *	if (inet_pton(AF_INET6, "0:0:0:0:0:FFFF:192.168.0.1",
 *		      &addr.sin6_addr) <= 0)
 *	  return(-1); // Bad address or no address family support
 *
 *	// initialize other necessary fields such as port, flow, etc
 *
 *	ia_addr = (DAT_IA_ADDRESS_PTR) &addr;
 *	dat_ep_connect(ep_handle, ia_addr, conn_qual, timeout, 0, NULL,
 *		       qos, DAT_CONNECT_DEFAULT_FLAG);
 *
 */

#if defined(sun) || defined(__sun) || defined(_sun_) || defined(__solaris__)
/* Solaris begins */

#include <sys/types.h>
#include <inttypes.h>		/* needed for UINT64_C() macro */

typedef uint32_t		DAT_UINT32; /* Unsigned host order, 32 bits */
typedef uint64_t		DAT_UINT64; /* Unsigned host order, 64 bits */
typedef unsigned long long	DAT_UVERYLONG;  /* Unsigned longest native  */
						/* to compiler		    */

typedef void			*DAT_PVOID;
typedef int			DAT_COUNT;

#include <sys/socket.h>
#include <netinet/in.h>
typedef struct sockaddr		DAT_SOCK_ADDR;	/* Socket address header */
						/* native to OS */
typedef struct sockaddr_in6	DAT_SOCK_ADDR6; /* Socket address header */
						/* native to OS */

#define	DAT_AF_INET		AF_INET
#define	DAT_AF_INET6		AF_INET6

typedef	DAT_UINT64		DAT_PADDR;

/* Solaris ends */

#elif defined(__linux__) /* Linux */
/* Linux begins */

#include <sys/types.h>

typedef u_int32_t	DAT_UINT32;	/* unsigned host order, 32 bits */
typedef u_int64_t	DAT_UINT64;	/* unsigned host order, 64 bits */
typedef unsigned long long	DAT_UVERYLONG;  /* unsigned longest native */
						/* to compiler		   */

typedef void			*DAT_PVOID;
typedef int			DAT_COUNT;
typedef	DAT_UINT64		DAT_PADDR;

#ifndef	UINT64_C
#define	UINT64_C(c)		c ## ULL
#endif	/* UINT64_C */

#include <sys/socket.h>
typedef struct sockaddr		DAT_SOCK_ADDR;  /* Socket address header */
						/* native to OS		 */
typedef struct sockaddr_in6	DAT_SOCK_ADDR6; /* Socket address header */
						/* native to OS		 */

#define	DAT_AF_INET		AF_INET
#define	DAT_AF_INET6		AF_INET6

/* Linux ends */

#elif defined(_MSC_VER) || defined(_WIN32)
/* NT. MSC compiler, Win32 platform */
/* Win32 begins */

typedef unsigned __int32	DAT_UINT32; /* Unsigned host order, 32 bits */
typedef unsigned __int64	DAT_UINT64; /* Unsigned host order, 64 bits */
typedef unsigned  long		DAT_UVERYLONG;	/* Unsigned longest native to */
						/* compiler	*/

typedef void			*DAT_PVOID;
typedef long			DAT_COUNT;

typedef struct sockaddr		DAT_SOCK_ADDR;  /* Socket address header */
						/* native to OS */
typedef struct sockaddr_in6	DAT_SOCK_ADDR6; /* Socket address header */
						/* native to OS */
#ifndef	UINT64_C
#define	UINT64_C(c)		c ## i64
#endif	/* UINT64_C */

#define	DAT_AF_INET		AF_INET
#define	DAT_AF_INET6		AF_INET6

/* Win32 ends */

#else
#error	dat_platform_specific.h : OS type not defined
#endif

#ifndef IN
#define	IN
#endif
#ifndef OUT
#define	OUT
#endif
#ifndef INOUT
#define	INOUT
#endif

#ifdef __cplusplus
}
#endif

#endif /* _DAT_PLATFORM_SPECIFIC_H_ */
