/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2014, OmniTI Computer Consulting, Inc. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef	_SYS_SOCKIO_H
#define	_SYS_SOCKIO_H

/*
 * General socket ioctl definitions.
 */

#include <sys/ioccom.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* socket i/o controls */
#define	SIOCSHIWAT	_IOW('s',  0, int)		/* set high watermark */
#define	SIOCGHIWAT	_IOR('s',  1, int)		/* get high watermark */
#define	SIOCSLOWAT	_IOW('s',  2, int)		/* set low watermark */
#define	SIOCGLOWAT	_IOR('s',  3, int)		/* get low watermark */
#define	SIOCATMARK	_IOR('s',  7, int)		/* at oob mark? */
#define	SIOCSPGRP	_IOW('s',  8, int)		/* set process group */
#define	SIOCGPGRP	_IOR('s',  9, int)		/* get process group */

/*
 * SIOCADDRT and SIOCDELRT ioctls need to be defined using _IOWN macro to
 * make them datamodel independent.
 */
#define	SIOCADDRT	_IOWN('r', 10, 48)		/* add route */
#define	SIOCDELRT	_IOWN('r', 11, 48)		/* delete route */

/* For multicast routing. These might change in future release */
#define	SIOCGETVIFCNT	_IOWR('r', 20, struct sioc_vif_req)
							/* get vif pkt count */
#define	SIOCGETSGCNT	_IOWR('r', 21, struct sioc_sg_req)
							/* get s,g pkt count */
#define	SIOCGETLSGCNT	_IOWR('r', 21, struct sioc_lsg_req)
							/* get s,g pkt count */

/*
 * Obsolete interface ioctls using struct ifreq that are supported
 * for compatibility. New interface ioctls use struct lifreq.
 */
#define	SIOCSIFADDR	_IOW('i',  12, struct ifreq)	/* set if address */
#define	SIOCGIFADDR	_IOWR('i', 13, struct ifreq)	/* get if address */
#define	SIOCSIFDSTADDR	_IOW('i',  14, struct ifreq)	/* set p-p address */
#define	SIOCGIFDSTADDR	_IOWR('i', 15, struct ifreq)	/* get p-p address */
#define	SIOCSIFFLAGS	_IOW('i',  16, struct ifreq)	/* set if flags */
#define	SIOCGIFFLAGS	_IOWR('i', 17, struct ifreq)	/* get if flags */
#define	SIOCSIFMEM	_IOW('i',  18, struct ifreq)	/* set interface mem */
#define	SIOCGIFMEM	_IOWR('i', 19, struct ifreq)	/* get interface mem */

/*
 * Needs to be defined using _IOWRN macro to make it datamodel independent.
 * Argument is a struct ifconf.
 */
#define	O_SIOCGIFCONF	_IOWRN('i', 20, 8)		/* old get if list */

#define	SIOCSIFMTU	_IOW('i',  21, struct ifreq)	/* set if mtu */
#define	SIOCGIFMTU	_IOWR('i', 22, struct ifreq)	/* get if mtu */

	/* from 4.3BSD */
#define	SIOCGIFBRDADDR	_IOWR('i', 23, struct ifreq)	/* get broadcast addr */
#define	SIOCSIFBRDADDR	_IOW('i',  24, struct ifreq)	/* set broadcast addr */
#define	SIOCGIFNETMASK	_IOWR('i', 25, struct ifreq)	/* get subnetmask */
#define	SIOCSIFNETMASK	_IOW('i',  26, struct ifreq)	/* set subnetmask */
#define	SIOCGIFMETRIC	_IOWR('i', 27, struct ifreq)	/* get if metric */
#define	SIOCSIFMETRIC	_IOW('i',  28, struct ifreq)	/* set if metric */

#define	SIOCSARP	_IOW('i',  30, struct arpreq)	/* set arp entry */
#define	SIOCGARP	_IOWR('i', 31, struct arpreq)	/* get arp entry */
#define	SIOCDARP	_IOW('i',  32, struct arpreq)	/* delete arp entry */
#define	SIOCUPPER	_IOW('i',  40, struct ifreq)	/* attach upper layer */
#define	SIOCLOWER	_IOW('i',  41, struct ifreq)	/* attach lower layer */
#define	SIOCSETSYNC	_IOW('i',  44, struct ifreq)	/* set syncmode */
#define	SIOCGETSYNC	_IOWR('i', 45, struct ifreq)	/* get syncmode */
#define	SIOCSSDSTATS	_IOWR('i', 46, struct ifreq)	/* sync data stats */
#define	SIOCSSESTATS	_IOWR('i', 47, struct ifreq)	/* sync error stats */

#define	SIOCSPROMISC	_IOW('i',  48, int)		/* request promisc */
							/* mode on/off */
#define	SIOCADDMULTI	_IOW('i',  49, struct ifreq)	/* set m/c address */
#define	SIOCDELMULTI	_IOW('i',  50, struct ifreq)	/* clr m/c address */

/* STREAMS based socket emulation */

#define	SIOCGETNAME	_IOR('s',  52, struct sockaddr)	/* getsockname */
#define	SIOCGETPEER	_IOR('s',  53, struct sockaddr)	/* getpeername */
#define	IF_UNITSEL	_IOW('s',  54, int)		/* set unit number */
#define	SIOCXPROTO	_IO('s',   55)			/* empty proto table */

#define	SIOCIFDETACH	_IOW('i',  56, struct ifreq)	/* detach interface */
#define	SIOCGENPSTATS	_IOWR('i', 57, struct ifreq)	/* get ENP stats */
#define	SIOCX25XMT	_IOWR('i', 59, struct ifreq)	/* start a slp proc */
							/* in x25if */
#define	SIOCX25RCV	_IOWR('i', 60, struct ifreq)	/* start a slp proc */
							/* in x25if */
#define	SIOCX25TBL	_IOWR('i', 61, struct ifreq)	/* xfer lun table to */
							/* kernel */
#define	SIOCSLGETREQ	_IOWR('i', 71, struct ifreq)	/* wait for switched */
							/* SLIP request */
#define	SIOCSLSTAT	_IOW('i',  72, struct ifreq)	/* pass SLIP info to */
							/* kernel */
#define	SIOCSIFNAME	_IOW('i',  73, struct ifreq)	/* set interface name */
#define	SIOCGENADDR	_IOWR('i', 85, struct ifreq)	/* Get ethernet addr */
#define	SIOCGIFNUM	_IOR('i',  87, int)		/* get number of ifs */

#define	SIOCGIFMUXID	_IOWR('i', 88, struct ifreq)	/* get if muxid */
#define	SIOCSIFMUXID	_IOW('i',  89, struct ifreq)	/* set if muxid */

#define	SIOCGIFINDEX	_IOWR('i', 90, struct ifreq)	/* get if index */
#define	SIOCSIFINDEX	_IOW('i',  91, struct ifreq)	/* set if index */
#define	SIOCGIFCONF	_IOWRN('i', 92, 8)		/* get if list */

/*
 * New interface ioctls that use the struct lifreq. Can be used for
 * both IPv4 and IPv6.
 */
#define	SIOCLIFREMOVEIF	_IOW('i',  110, struct lifreq)	/* delete logical */
#define	SIOCLIFADDIF	_IOWR('i', 111, struct lifreq)	/* create logical */

#define	SIOCSLIFADDR	_IOW('i',  112, struct lifreq)	/* set if address */
#define	SIOCGLIFADDR	_IOWR('i', 113, struct lifreq)	/* get if address */
#define	SIOCSLIFDSTADDR	_IOW('i',  114, struct lifreq)	/* set p-p address */
#define	SIOCGLIFDSTADDR	_IOWR('i', 115, struct lifreq)	/* get p-p address */
#define	SIOCSLIFFLAGS	_IOW('i',  116, struct lifreq)	/* set if flags */
#define	SIOCGLIFFLAGS	_IOWR('i', 117, struct lifreq)	/* get if flags */

/*
 * Needs to be defined using _IOWRN macro to make it datamodel independent.
 * Argument is a struct lifconf.
 */
#define	O_SIOCGLIFCONF	_IOWRN('i', 120, 16)		/* old get if list */
#define	SIOCSLIFMTU	_IOW('i',  121, struct lifreq)	/* set if mtu */
#define	SIOCGLIFMTU	_IOWR('i', 122, struct lifreq)	/* get if mtu */
#define	SIOCGLIFBRDADDR	_IOWR('i', 123, struct lifreq)	/* get broadcast addr */
#define	SIOCSLIFBRDADDR	_IOW('i',  124, struct lifreq)	/* set broadcast addr */
#define	SIOCGLIFNETMASK	_IOWR('i', 125, struct lifreq)	/* get subnetmask */
#define	SIOCSLIFNETMASK	_IOW('i',  126, struct lifreq)	/* set subnetmask */
#define	SIOCGLIFMETRIC	_IOWR('i', 127, struct lifreq)	/* get if metric */
#define	SIOCSLIFMETRIC	_IOW('i',  128, struct lifreq)	/* set if metric */
#define	SIOCSLIFNAME	_IOWR('i', 129, struct lifreq)	/* set interface name */
#define	SIOCGLIFNUM	_IOWR('i', 130, struct lifnum)	/* get number of ifs */
#define	SIOCGLIFMUXID	_IOWR('i', 131, struct lifreq)	/* get if muxid */
#define	SIOCSLIFMUXID	_IOW('i',  132, struct lifreq)	/* set if muxid */

#define	SIOCGLIFINDEX	_IOWR('i', 133, struct lifreq)	/* get if index */
#define	SIOCSLIFINDEX	_IOW('i',  134, struct lifreq)	/* set if index */

#define	SIOCSLIFTOKEN	_IOW('i',  135, struct lifreq)	/* Set token for link */
							/* local address and */
							/* autoconf */
#define	SIOCGLIFTOKEN	_IOWR('i', 136, struct lifreq)	/* Get token for link */
							/* local address and */
							/* autoconf */

#define	SIOCSLIFSUBNET	_IOW('i',  137, struct lifreq)	/* set subnet prefix */
#define	SIOCGLIFSUBNET	_IOWR('i', 138, struct lifreq)	/* get subnet prefix */

#define	SIOCSLIFLNKINFO _IOW('i',  139, struct lifreq)	/* set link info */
#define	SIOCGLIFLNKINFO _IOWR('i', 140, struct lifreq)	/* get link info */

#define	SIOCLIFDELND	_IOW('i',  141, struct lifreq)	/* Delete ND entry */
#define	SIOCLIFGETND	_IOWR('i', 142, struct lifreq)	/* Get ND entry */
#define	SIOCLIFSETND	_IOW('i',  143, struct lifreq)	/* Set ND entry */

/*
 * Address querying ioctls.
 */
#define	SIOCTMYADDR	_IOWR('i', 144, struct sioc_addrreq)
							/* My address? */
#define	SIOCTONLINK	_IOWR('i', 145, struct sioc_addrreq)
							/* Address on-link? */
#define	SIOCTMYSITE	_IOWR('i', 146, struct sioc_addrreq)
							/* In this site? */

/* 147-152 were SIOC*{TUNPARAM,IPSECONFIG} ioctls.  Feel free to re-use. */

/*
 * 153 can be reused (was consolidation-private SIOCLIFFAILOVER).
 */

/*
 * IP Multipathing ioctls.
 */
#define	SIOCGLIFBINDING		_IOWR('i', 154, struct lifreq)
#define	SIOCSLIFGROUPNAME	_IOW('i',  155, struct lifreq)
#define	SIOCGLIFGROUPNAME	_IOWR('i', 156, struct lifreq)
#define	SIOCGLIFGROUPINFO	_IOWR('i', 157, struct lifgroupinfo)

/*
 * Leave 158 - 160 unused; used to be SIOC*IFARP ioctls.
 * However, 161 can be reused (was consolidation-private SIOCSLIFOINDEX).
 */

/*
 * IOCTLS which provide an interface to the IPv6 address selection policy.
 */
#define	SIOCGIP6ADDRPOLICY	_IOWRN('i', 162, 0)
#define	SIOCSIP6ADDRPOLICY	_IOWN('i', 163, 0)

/*
 * IOCTL for retrieving sorting info for a list of destination addrs.
 * Use the _IOWRN macro to make it datamodel independent.  Argument
 * is a struct dstinfo.
 */
#define	SIOCGDSTINFO	_IOWRN('i', 164, 0)
#define	SIOCGLIFCONF	_IOWRN('i', 165, 16)	/* get if list */

/*
 * Extended IOCTLS for manipulating ARP cache entries.
 */
#define	SIOCSXARP	_IOW('i', 166, struct xarpreq)	/* set an ARP entry */
#define	SIOCGXARP	_IOWR('i', 167, struct xarpreq)	/* get an ARP entry */
#define	SIOCDXARP	_IOW('i', 168, struct xarpreq)	/* delete ARP entry */

/*
 * IOCTL private to sockfs.
 */
#define	_SIOCSOCKFALLBACK _IOW('i', 169, 0)

/*
 * IOCTLs for getting and setting zone associated with an interface, and
 * unplumbing interfaces associated with a given zone.
 */
#define	SIOCGLIFZONE	_IOWR('i', 170, struct lifreq)	/* get zone id */
#define	SIOCSLIFZONE	_IOW('i', 171, struct lifreq)	/* set zone id */

/*
 * IOCTLS for handling SCTP options.
 */
#define	SIOCSCTPSOPT	_IOWN('i', 172, 16)	/* Set SCTP option */
#define	SIOCSCTPGOPT	_IOWRN('i', 173, 16)	/* Get SCTP option */
#define	SIOCSCTPPEELOFF	_IOWR('i', 174, int)	/* SCTP peeloff */

/*
 * IOCTLs for getting and setting the source address that is used for packets
 * going out on the given interface.
 */
#define	SIOCGLIFUSESRC	_IOWR('i', 175, struct lifreq)	/* get src addr */
#define	SIOCSLIFUSESRC	_IOW('i', 176, struct lifreq)	/* set src addr */

/*
 * IOCTL used to get all the interfaces that use the the specified interfaces'
 * source address
 */
#define	SIOCGLIFSRCOF	_IOWRN('i', 177, 16)		/* source of */

/*
 * IOCTLs for source specific multicast; get or set a socket's
 * source filter for a particular multicast group.  Argument is
 * a struct group_filter.  Defined in RFC 3678.
 */
#define	SIOCGMSFILTER	_IOWR('i', 178, 0)
#define	SIOCSMSFILTER	_IOW('i', 179, 0)
/*
 * IPv4-specific versions of the above; get or set a socket's source
 * filter for a particular multicast group, for PF_INET sockets only.
 * Argument is a struct ip_msfilter.
 */
#define	SIOCGIPMSFILTER	_IOWR('i', 180, 0)
#define	SIOCSIPMSFILTER	_IOW('i', 181, 0)

/*
 * 182 can be reused (was consolidation-private SIOCSIPMPFAILBACK).
 */

#define	SIOCSENABLESDP	_IOWR('i', 183, int)    /*  Enable SDP */

#define	SIOCSQPTR	_IOWR('i', 184, int)    /* set q_ptr of stream */

/*
 * SIOCGIFHWADDR and SIOCGLIFHWADDR (below) are available for PF_PACKET,
 * PF_INET and PF_INET6 sockets.
 */
#define	SIOCGIFHWADDR	_IOWR('i', 185, struct ifreq)

#define	SIOCGSTAMP	_IOWR('i', 186, struct timeval)	/* PF_PACKET */

/*
 * Private ioctl for Integrated Load Balancer.  The ioctl length varies.
 */
#define	SIOCILB		_IOWR('i', 187, 0)

/*
 * IOCTL's to get/set module specific or interface specific properties.
 * Argument is a struct mod_ioc_prop_s. These ioctls are Consolidation Private.
 */
#define	SIOCGETPROP	_IOWRN('p', 188, 0)
#define	SIOCSETPROP	_IOW('p', 189, 0)

/*
 * IOCTL used to check for the given ipif, whether DAD is in progress or
 * DAD has completed. This ioctl is Consolidation Private.
 */
#define	SIOCGLIFDADSTATE	_IOWR('i', 190, struct lifreq)

/*
 * IOCTL used to generate an IPv6 address using the given prefix and the
 * default token for the interface.
 */
#define	SIOCSLIFPREFIX		_IOWR('i', 191, struct lifreq)

#define	SIOCGLIFHWADDR	_IOWR('i', 192, struct lifreq)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SOCKIO_H */
