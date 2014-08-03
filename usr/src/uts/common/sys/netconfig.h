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


/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_NETCONFIG_H
#define	_SYS_NETCONFIG_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	NETCONFIG "/etc/netconfig"
#define	NETPATH   "NETPATH"

struct  netconfig {
	char		*nc_netid;	/* network identifier		*/
	unsigned int	nc_semantics;	/* defined below		*/
	unsigned int	nc_flag;	/* defined below		*/
	char		*nc_protofmly;	/* protocol family name		*/
	char		*nc_proto;	/* protocol name		*/
	char		*nc_device;	/* device name for network id	*/
	unsigned int	nc_nlookups;	/* # of entries in nc_lookups	*/
	char		**nc_lookups;	/* list of lookup directories	*/
	unsigned int	nc_unused[8];	/* borrowed for lockd etc.	*/
};

typedef struct {
	struct netconfig **nc_head;
	struct netconfig **nc_curr;
} NCONF_HANDLE;

/*
 *	Values of nc_semantics
 */

#define	NC_TPI_CLTS	1
#define	NC_TPI_COTS	2
#define	NC_TPI_COTS_ORD	3
#define	NC_TPI_RAW	4
/*
 * NOT FOR PUBLIC USE, Solaris internal only.
 * This value of nc_semantics is strictly for use of Remote Direct
 * Memory Access provider interfaces in Solaris only and not for
 * general use. Do not use this value for general purpose user or
 * kernel programming. If used the behavior is undefined.
 * This is a PRIVATE interface to be used by Solaris kRPC only.
 */
#define	NC_TPI_RDMA	5

/*
 *	Values of nc_flag
 */

#define	NC_NOFLAG	00
#define	NC_VISIBLE	01
#define	NC_BROADCAST	02

/*
 *	Values of nc_protofmly
 */

#define	NC_NOPROTOFMLY	"-"
#define	NC_LOOPBACK	"loopback"
#define	NC_INET		"inet"
#define	NC_INET6	"inet6"
#define	NC_IMPLINK	"implink"
#define	NC_PUP		"pup"
#define	NC_CHAOS	"chaos"
#define	NC_NS		"ns"
#define	NC_NBS		"nbs"
#define	NC_ECMA		"ecma"
#define	NC_DATAKIT	"datakit"
#define	NC_CCITT	"ccitt"
#define	NC_SNA		"sna"
#define	NC_DECNET	"decnet"
#define	NC_DLI		"dli"
#define	NC_LAT		"lat"
#define	NC_HYLINK	"hylink"
#define	NC_APPLETALK	"appletalk"
#define	NC_NIT		"nit"
#define	NC_IEEE802	"ieee802"
#define	NC_OSI		"osi"
#define	NC_X25		"x25"
#define	NC_OSINET	"osinet"
#define	NC_GOSIP	"gosip"
/*
 * NOT FOR PUBLIC USE, Solaris internal only.
 * This value of nc_semantics is strictly for use of Remote Direct
 * Memory Access provider interfaces in Solaris only and not for
 * general use. Do not use this value for general purpose user or
 * kernel programming. If used the behavior is undefined.
 * This is a PRIVATE interface to be used by Solaris kRPC only.
 */
#define	NC_RDMA		"rdma"

/*
 *	Values for nc_proto
 */

#define	NC_NOPROTO	"-"
#define	NC_TCP		"tcp"
#define	NC_UDP		"udp"
#define	NC_ICMP		"icmp"

/*
 * 	Values for nc_proto for "rdma" protofmly
 */
#define	NC_KVIPL	"kvipl"
#define	NC_IBTF		"ibtf"
#define	NC_KDAPL	"kdapl"

extern void		*setnetconfig(void);
extern int		endnetconfig(void *);
extern struct netconfig	*getnetconfig(void *);
extern struct netconfig	*getnetconfigent(const char *);
extern void		freenetconfigent(struct netconfig *);
extern void		*setnetpath(void);
extern int		endnetpath(void *);
extern struct netconfig *getnetpath(void *);
extern void		nc_perror(const char *);
extern char		*nc_sperror(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NETCONFIG_H */
