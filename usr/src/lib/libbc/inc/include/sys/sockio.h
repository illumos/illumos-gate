/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef _sys_sockio_h
#define	_sys_sockio_h

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * General socket ioctl definitions.
 */

#include <sys/ioccom.h>

/* socket i/o controls */
#define	SIOCSHIWAT	_IOW('s',  0, int)		/* set high watermark */
#define	SIOCGHIWAT	_IOR('s',  1, int)		/* get high watermark */
#define	SIOCSLOWAT	_IOW('s',  2, int)		/* set low watermark */
#define	SIOCGLOWAT	_IOR('s',  3, int)		/* get low watermark */
#define	SIOCATMARK	_IOR('s',  7, int)		/* at oob mark? */
#define	SIOCSPGRP	_IOW('s',  8, int)		/* set process group */
#define	SIOCGPGRP	_IOR('s',  9, int)		/* get process group */

#define	SIOCADDRT	_IOW('r', 10, struct rtentry)	/* add route */
#define	SIOCDELRT	_IOW('r', 11, struct rtentry)	/* delete route */

#define	SIOCSIFADDR	_IOW('i', 12, struct ifreq)	/* set ifnet address */
#define	SIOCGIFADDR	_IOWR('i',13, struct ifreq)	/* get ifnet address */
#define	SIOCSIFDSTADDR	_IOW('i', 14, struct ifreq)	/* set p-p address */
#define	SIOCGIFDSTADDR	_IOWR('i',15, struct ifreq)	/* get p-p address */
#define	SIOCSIFFLAGS	_IOW('i', 16, struct ifreq)	/* set ifnet flags */
#define	SIOCGIFFLAGS	_IOWR('i',17, struct ifreq)	/* get ifnet flags */
#define	SIOCSIFMEM	_IOW('i', 18, struct ifreq)	/* set interface mem */
#define	SIOCGIFMEM	_IOWR('i',19, struct ifreq)	/* get interface mem */
#define	SIOCGIFCONF	_IOWR('i',20, struct ifconf)	/* get ifnet list */
#define	SIOCSIFMTU	_IOW('i', 21, struct ifreq)	/* set if_mtu */
#define	SIOCGIFMTU	_IOWR('i',22, struct ifreq)	/* get if_mtu */

	/* from 4.3BSD */
#define	SIOCGIFBRDADDR	_IOWR('i',23, struct ifreq)	/* get broadcast addr */
#define	SIOCSIFBRDADDR	_IOW('i',24, struct ifreq)	/* set broadcast addr */
#define	SIOCGIFNETMASK	_IOWR('i',25, struct ifreq)	/* get net addr mask */
#define	SIOCSIFNETMASK	_IOW('i',26, struct ifreq)	/* set net addr mask */
#define	SIOCGIFMETRIC	_IOWR('i',27, struct ifreq)	/* get IF metric */
#define	SIOCSIFMETRIC	_IOW('i',28, struct ifreq)	/* set IF metric */

#define	SIOCSARP	_IOW('i', 30, struct arpreq)	/* set arp entry */
#define	SIOCGARP	_IOWR('i',31, struct arpreq)	/* get arp entry */
#define	SIOCDARP	_IOW('i', 32, struct arpreq)	/* delete arp entry */
#define	SIOCUPPER       _IOW('i', 40, struct ifreq)       /* attach upper layer */
#define	SIOCLOWER       _IOW('i', 41, struct ifreq)       /* attach lower layer */
#define	SIOCSETSYNC	_IOW('i',  44, struct ifreq)	/* set syncmode */
#define	SIOCGETSYNC	_IOWR('i', 45, struct ifreq)	/* get syncmode */
#define	SIOCSSDSTATS	_IOWR('i', 46, struct ifreq)	/* sync data stats */
#define	SIOCSSESTATS	_IOWR('i', 47, struct ifreq)	/* sync error stats */

#define	SIOCSPROMISC	_IOW('i', 48, int)		/* request promisc mode
							   on/off */
#define	SIOCADDMULTI	_IOW('i', 49, struct ifreq)	/* set m/c address */
#define	SIOCDELMULTI	_IOW('i', 50, struct ifreq)	/* clr m/c address */

/* FDDI controls */
#define SIOCFDRESET	_IOW('i', 51, struct ifreq)	/* Reset FDDI */
#define SIOCFDSLEEP	_IOW('i', 52, struct ifreq)	/* Sleep until next dnld req */
#define SIOCSTRTFMWAR	_IOW('i', 53, struct ifreq)	/* Start FW at an addr */
#define SIOCLDNSTRTFW	_IOW('i', 54, struct ifreq)	/* Load the shared memory */
#define SIOCGETFDSTAT	_IOW('i', 55, struct ifreq)	/* Get FDDI stats */
#define SIOCFDNMIINT	_IOW('i', 56, struct ifreq)        /* NMI to fddi */
#define SIOCFDEXUSER	_IOW('i', 57, struct ifreq)        /* Exec in user mode */
#define SIOCFDGNETMAP	_IOW('i', 58, struct ifreq)        /* Get a netmap entry */
#define SIOCFDGIOCTL    _IOW('i', 59, struct ifreq)	 /* Generic ioctl for fddi */

/* protocol i/o controls */
#define	SIOCSNIT	_IOW('p',  0, struct nit_ioc)	/* set nit modes */
#define	SIOCGNIT	_IOWR('p', 1, struct nit_ioc)	/* get nit modes */

#endif /* !_sys_sockio_h */
