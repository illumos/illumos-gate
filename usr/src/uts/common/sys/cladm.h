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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_CLADM_H
#define	_SYS_CLADM_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/clconf.h>
#include <netinet/in.h>


/*
 * This file defines interfaces which are private to Sun Clustering.
 * Others should not depend on this in any way as it may change or be
 * removed completely.
 */

/*
 * cladm() facilities; see below for definitions pertinent to each of these
 * facilities.
 */
#define	CL_INITIALIZE		0	/* bootstrapping information */
#define	CL_CONFIG		1	/* configuration information */


/*
 * Command definitions for each of the facilities.
 * The type of the data pointer and the direction of the data transfer
 * is listed for each command.
 */

/*
 * CL_INITIALIZE facility commands.
 */
#define	CL_GET_BOOTFLAG		0	/* Return cluster config/boot status */

/*
 * Definitions for the flag bits returned by CL_GET_BOOTFLAG.
 */
#define	CLUSTER_CONFIGURED	0x0001	/* system is configured as a cluster */
#define	CLUSTER_BOOTED		0x0002	/* system is booted as a cluster */

#ifdef _KERNEL
#define	CLUSTER_INSTALLING	0x0004	/* cluster is being installed */
#define	CLUSTER_DCS_ENABLED	0x0008	/* cluster device framework enabled */
#endif	/* _KERNEL */

/*
 * CL_CONFIG facility commands.
 * The CL_GET_NETADDRS and CL_GET_NUM_NETADDRS are contract private interfaces
 * per PSARC/2001/579-01.
 */
#define	CL_NODEID		0	/* Return nodeid of this node. */
#define	CL_HIGHEST_NODEID	1	/* Return highest configured nodeid. */
#define	CL_GDEV_PREFIX		2	/* Return path to global namespace.  */
#define	CL_GET_NETADDRS		3	/* Get array of network addresses    */
					/* controlled by Sun Cluster. */
#define	CL_GET_NUM_NETADDRS	4	/* Get the number of data structure  */
					/* entries in the array that will be */
					/* returned  using CL_GET_NETADDRS.  */

/*
 * The cladm system call can provide an array of cluster controlled
 * network addresses and associated netmasks.  The cladm arguments
 * must be as follows:  the argument fac is specified as CL_CONFIG,
 * the argument cmd is specified as CL_GET_NETADDRS, and argument arg
 * is the location of a structure of type cladm_netaddrs_t. The
 * cladm_num_netaddrs is used as input for the requested number
 * of array entries, and is used as ouput for the number of valid array
 * entries available.
 *
 * The caller must allocate sufficient memory for the array of
 * structures of type cladm_netaddr_entry_t and specify the starting
 * location as cladm_netaddrs_array.  The number of entries included
 * in the array is determined using cladm with argument fac specified
 * as CL_CONFIG, argument cmd specified as CL_GET_NUM_NETADDRS, and
 * argument arg is the location of a structure of type cladm_netaddrs_t.
 * The determined number of array entries is returned in
 * cladm_num_netaddrs.
 *
 * These commands support the yielding of DR operation control (by the
 * RCM Framework) to Sun Cluster for cluster controlled adapters.
 *
 * These data structures are contract private per PSARC/2001/579-01.
 */
typedef struct {
	int32_t		cl_ipversion;	/* IPV4_VERSION or IPV6_VERSION */
	union {
		struct {
			ipaddr_t	ipv4_netaddr;
			ipaddr_t	ipv4_netmask;
			} cl_ipv4;
		struct {
			uint32_t	ipv6_netaddr[4];
			uint32_t	ipv6_netmask[4];
			} cl_ipv6;
	} cl_ipv_un;
} cladm_netaddr_entry_t;

typedef struct {
	uint32_t		cladm_num_netaddrs;
	cladm_netaddr_entry_t	*cladm_netaddrs_array;
} cladm_netaddrs_t;

#if defined(_SYSCALL32)
typedef struct {
	uint32_t	cladm_num_netaddrs;
	caddr32_t	cladm_netaddrs_array;
} cladm_netaddrs32_t;
#endif /* defined(_SYSCALL32) */


#ifdef _KERNEL
extern int cladmin(int fac, int cmd, void *data);
extern int cluster_bootflags;
#else
extern int _cladm(int fac, int cmd, void *data);
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif


#endif	/* _SYS_CLADM_H */
