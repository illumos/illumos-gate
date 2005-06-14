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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * rarpd.c  Reverse-ARP server.
 * Refer to RFC 903 "A Reverse Address Resolution Protocol".
 */

#define	_REENTRANT

#include	<thread.h>
#include	<synch.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<sys/resource.h>
#include	<stdio.h>
#include	<stdarg.h>
#include	<string.h>
#include	<ctype.h>
#include	<fcntl.h>
#include	<sys/types.h>
#include	<dirent.h>
#include	<syslog.h>
#include	<signal.h>
#include	<netdb.h>
#include	<errno.h>
#include	<sys/socket.h>
#include	<sys/sockio.h>
#include	<net/if.h>
#include	<netinet/if_ether.h>
#include	<netinet/in.h>
#include	<arpa/inet.h>
#include	<stropts.h>
#include	<sys/dlpi.h>
#include	<libinetutil.h>
#include	<net/if_types.h>
#include	<net/if_dl.h>

#define	BOOTDIR		"/tftpboot"	/* boot files directory */
#define	DEVDIR		"/dev"		/* devices directory */
#define	DEVIP		"/dev/ip"	/* path to ip driver */
#define	DEVARP		"/dev/arp"	/* path to arp driver */

#define	BUFSIZE		2048		/* max receive frame length */
#define	MAXPATHL	128		/* max path length */
#define	MAXHOSTL	128		/* max host name length */
#define	MAXIFS		256

/*
 * Logical network devices
 */
struct	ifdev {
	char		ldevice[IFNAMSIZ];
	int		lunit;
	ipaddr_t	ipaddr;			/* network order */
	ipaddr_t	if_netmask;		/* host order */
	ipaddr_t	if_ipaddr;		/* host order */
	ipaddr_t	if_netnum;		/* host order, with subnet */
	struct ifdev *next;
};

/*
 * Physical network device
 */
struct	rarpdev {
	char		device[IFNAMSIZ];
	int		unit;
	int		fd;
	uchar_t		*lladdr;		/* mac address of interface */
	int		ifaddrlen;		/* mac address length */
	int		ifsaplen;		/* indicates dlsap format */
	int		ifrarplen;		/* size of rarp data packet */
	struct ifdev	*ifdev;			/* private interface info */
	struct rarpdev	*next;			/* list of managed devices */
};

struct	rarpreply {
	struct rarpdev		*rdev;		/* which device reply for */
	struct timeval		tv;		/* send RARP reply by when */
	uchar_t			*lldest;	/* target mac to send reply */
	uchar_t			*arprep;	/* [R]ARP response */
	struct rarpreply	*next;
};

static struct rarpreply	*delay_list;
static sema_t		delay_sema;
static mutex_t		delay_mutex;
static mutex_t		debug_mutex;

static struct rarpdev	*rarpdev_head;

/*
 * Globals initialized before multi-threading
 */
static char	*cmdname;		/* command name from argv[0] */
static int	dflag = 0;		/* enable diagnostics */
static int	aflag = 0;		/* start rarpd on all interfaces */
static char	*alarmmsg;		/* alarm() error message */
static long	pc_name_max;		/* pathconf maximum path name */

static void	getintf(void);
static struct rarpdev *find_device(ifspec_t *);
static void	init_rarpdev(struct rarpdev *);
static void	do_rarp(void *);
static void	rarp_request(struct rarpdev *, struct arphdr *,
		    uchar_t *);
static void	add_arp(struct rarpdev *, uchar_t *, uchar_t *);
static void	arp_request(struct rarpdev *, struct arphdr *, uchar_t *);
static int	rarp_open(struct rarpdev *, ushort_t);
static void	do_delay_write(void *);
static void	delay_write(struct rarpdev *, struct rarpreply *);
static int	rarp_write(int, struct rarpreply *);
static int	mightboot(ipaddr_t);
static void	get_ifdata(char *, int, ipaddr_t *, ipaddr_t *);
static int	get_ipaddr(struct rarpdev *, uchar_t *, uchar_t *, ipaddr_t *);
static void	sigalarm(int);
static int	strioctl(int, int, int, int, char *);
static void	usage();
static void	syserr(char *);
static void	error(char *, ...);
static void	debug(char *, ...);

extern	int	optind;
extern	char	*optarg;

int
main(int argc, char *argv[])
{
	int		c;
	struct rlimit rl;
	struct rarpdev	*rdev;
	int		i;

	cmdname = argv[0];

	while ((c = getopt(argc, argv, "ad")) != -1) {
		switch (c) {
		case 'a':
			aflag = 1;
			break;

		case 'd':
			dflag = 1;
			break;

		default:
			usage();
		}
	}

	if ((!aflag && (argc - optind) != 2) ||
					(aflag && (argc - optind) != 0)) {
		usage();
		/* NOTREACHED */
	}

	if (!dflag) {
		/*
		 * Background
		 */
		switch (fork()) {
			case -1:	/* error */
				syserr("fork");
				/*NOTREACHED*/

			case 0:		/* child */
				break;

			default:	/* parent */
				return (0);
		}
		for (i = 0; i < 3; i++) {
			(void) close(i);
		}
		(void) open("/", O_RDONLY, 0);
		(void) dup2(0, 1);
		(void) dup2(0, 2);
		/*
		 * Detach terminal
		 */
		if (setsid() < 0)
			syserr("setsid");
	}

	rl.rlim_cur = RLIM_INFINITY;
	rl.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
		syserr("setrlimit");

	/*
	 * Look up the maximum name length of the BOOTDIR, it may not
	 * exist so use /, if that fails use a reasonable sized buffer.
	 */
	if ((pc_name_max = pathconf(BOOTDIR, _PC_NAME_MAX)) == -1) {
		if ((pc_name_max = pathconf("/", _PC_NAME_MAX)) == -1) {
			pc_name_max = 255;
		}
	}

	(void) openlog(cmdname, LOG_PID, LOG_DAEMON);

	if (aflag) {
		/*
		 * Get each interface name and load rarpdev list
		 */
		getintf();
	} else {
		ifspec_t	ifsp;
		struct ifdev	*ifdev;
		char		buf[IFNAMSIZ + 1];

		/*
		 * Load specified device as only element of the list
		 */
		rarpdev_head = (struct rarpdev *)calloc(1,
						sizeof (struct rarpdev));
		if (rarpdev_head == NULL) {
			error("out of memory");
		}
		(void) strncpy(buf, argv[optind], IFNAMSIZ);
		(void) strncat(buf, argv[optind + 1], IFNAMSIZ - strlen(buf));

		if ((ifdev = calloc(1, sizeof (struct ifdev))) == NULL) {
			error("out of memory");
		}

		if (!ifparse_ifspec(buf, &ifsp) || ifsp.ifsp_modcnt != 0) {
			error("invalid interface specification");
		}

		if (ifsp.ifsp_lunvalid) {
			(void) snprintf(ifdev->ldevice,
			    sizeof (ifdev->ldevice), "%s%d:",
			    ifsp.ifsp_devnm, ifsp.ifsp_ppa);
			ifdev->lunit = ifsp.ifsp_lun;
		} else
			ifdev->lunit = -1; /* no logical unit */
		(void) strlcpy(rarpdev_head->device, ifsp.ifsp_devnm,
		    sizeof (rarpdev_head->device));
		rarpdev_head->unit = ifsp.ifsp_ppa;

		ifdev->next = rarpdev_head->ifdev;
		rarpdev_head->ifdev = ifdev;
	}

	/*
	 * Initialize each rarpdev
	 */
	for (rdev = rarpdev_head; rdev != NULL; rdev = rdev->next) {
		init_rarpdev(rdev);
	}

	(void) sema_init(&delay_sema, 0, USYNC_THREAD, NULL);
	(void) mutex_init(&delay_mutex, USYNC_THREAD, NULL);
	(void) mutex_init(&debug_mutex, USYNC_THREAD, NULL);

	/*
	 * Start delayed processing thread
	 */
	(void) thr_create(NULL, NULL, (void *(*)(void *))do_delay_write, NULL,
	    THR_NEW_LWP, NULL);

	/*
	 * Start RARP processing for each device
	 */
	for (rdev = rarpdev_head; rdev != NULL; rdev = rdev->next) {
		if (rdev->fd != -1) {
			(void) thr_create(NULL, NULL,
			    (void *(*)(void *))do_rarp, (void *)rdev,
			    THR_NEW_LWP, NULL);
		}
	}

	/*
	 * Exit main() thread
	 */
	thr_exit(NULL);

	return (0);
}

static void
getintf(void)
{
	int		fd;
	int		numifs;
	unsigned	bufsize;
	struct ifreq	*reqbuf;
	struct ifconf	ifconf;
	struct ifreq	*ifr;
	struct rarpdev	*rdev;
	struct ifdev	*ifdev;

	/*
	 * Open the IP provider.
	 */
	if ((fd = open(DEVIP, 0)) < 0)
		syserr(DEVIP);

	/*
	 * Ask IP for the list of configured interfaces.
	 */
	if (ioctl(fd, SIOCGIFNUM, (char *)&numifs) < 0) {
		numifs = MAXIFS;
	}
	bufsize = numifs * sizeof (struct ifreq);
	reqbuf = (struct ifreq *)malloc(bufsize);
	if (reqbuf == NULL) {
		error("out of memory");
	}

	ifconf.ifc_len = bufsize;
	ifconf.ifc_buf = (caddr_t)reqbuf;
	if (ioctl(fd, SIOCGIFCONF, (char *)&ifconf) < 0)
		syserr("SIOCGIFCONF");

	/*
	 * Initialize a rarpdev for each interface
	 */
	for (ifr = ifconf.ifc_req; ifconf.ifc_len > 0;
	    ifr++, ifconf.ifc_len -= sizeof (struct ifreq)) {
		ifspec_t	ifsp;

		if (ioctl(fd, SIOCGIFFLAGS, (char *)ifr) < 0) {
			syserr("ioctl SIOCGIFFLAGS");
			exit(1);
		}
		if ((ifr->ifr_flags & IFF_LOOPBACK) ||
		    !(ifr->ifr_flags & IFF_UP) ||
		    !(ifr->ifr_flags & IFF_BROADCAST) ||
		    (ifr->ifr_flags & IFF_NOARP) ||
		    (ifr->ifr_flags & IFF_POINTOPOINT))
			continue;

		if (!ifparse_ifspec(ifr->ifr_name, &ifsp))
			error("ifparse_ifspec failed");

		/*
		 * Look for an existing device for logical interfaces
		 */
		if ((rdev = find_device(&ifsp)) == NULL) {
			rdev = calloc(1, sizeof (struct rarpdev));
			if (rdev == NULL)
				error("out of memory");

			(void) strlcpy(rdev->device, ifsp.ifsp_devnm,
			    sizeof (rdev->device));
			rdev->unit = ifsp.ifsp_ppa;

			rdev->next = rarpdev_head;
			rarpdev_head = rdev;
		}

		if ((ifdev = calloc(1, sizeof (struct ifdev))) == NULL)
			error("out of memory");

		if (ifsp.ifsp_lunvalid) {
			(void) snprintf(ifdev->ldevice,
			    sizeof (ifdev->ldevice), "%s%d:",
			    ifsp.ifsp_devnm, ifsp.ifsp_ppa);
			ifdev->lunit = ifsp.ifsp_lun;
		} else
			ifdev->lunit = -1; /* no logical unit */

		ifdev->next = rdev->ifdev;
		rdev->ifdev = ifdev;
	}
	(void) free((char *)reqbuf);
}

static struct rarpdev *
find_device(ifspec_t *specp)
{
	struct rarpdev	*rdev;

	for (rdev = rarpdev_head; rdev != NULL; rdev = rdev->next) {
		if (specp->ifsp_ppa == rdev->unit &&
		    strcmp(specp->ifsp_devnm, rdev->device) == 0)
			return (rdev);
	}
	return (NULL);
}

static void
init_rarpdev(struct rarpdev *rdev)
{
	char *dev;
	int unit;
	struct ifdev *ifdev;

	/*
	 * Open datalink provider and get our mac address.
	 */
	rdev->fd = rarp_open(rdev, ETHERTYPE_REVARP);

	/*
	 * rarp_open may fail on certain types of interfaces
	 */
	if (rdev->fd < 0) {
		rdev->fd = -1;
		return;
	}

	/*
	 * Get the IP address and netmask from directory service for
	 * each logical interface.
	 */
	for (ifdev = rdev->ifdev; ifdev != NULL; ifdev = ifdev->next) {
		/*
		 * If lunit == -1 then this is the primary interface name
		 */
		if (ifdev->lunit == -1) {
			dev = rdev->device;
			unit = rdev->unit;
		} else {
			dev = ifdev->ldevice;
			unit = ifdev->lunit;
		}
		get_ifdata(dev, unit, &ifdev->if_ipaddr, &ifdev->if_netmask);

		/*
		 * Use IP address of the interface.
		 */
		ifdev->if_netnum = ifdev->if_ipaddr & ifdev->if_netmask;
		ifdev->ipaddr = (ipaddr_t)htonl(ifdev->if_ipaddr);
	}
}

static void
do_rarp(void *buf)
{
	struct rarpdev *rdev = (struct rarpdev *)buf;
	struct strbuf ctl;
	char	ctlbuf[BUFSIZE];
	struct strbuf data;
	char	databuf[BUFSIZE];
	char	*cause;
	struct arphdr *ans;
	uchar_t	*shost;
	int	flags, ret;
	union	DL_primitives	*dlp;
	uchar_t	*laddrp;
	char	*str = NULL;

	/*
	 * Sanity check; if we hit this limit, ctlbuf/databuf needs
	 * to be malloc'ed.
	 */
	if ((sizeof (ctlbuf) < (DL_UNITDATA_IND_SIZE + rdev->ifaddrlen)) ||
	    (sizeof (databuf) < rdev->ifrarplen))
		error("unsupported media");

	if (((shost = (uchar_t *)malloc(rdev->ifaddrlen)) == NULL) ||
	    ((ans = (struct arphdr *)malloc(rdev->ifrarplen)) == NULL))
		syserr("malloc");

	if (dflag) {
		str = _link_ntoa(rdev->lladdr, str, rdev->ifaddrlen, IFT_OTHER);
		if (str != NULL) {
			debug("starting rarp service on device %s%d address %s",
			    rdev->device, rdev->unit, str);
			free(str);
		}
	}

	/*
	 * read RARP packets and respond to them.
	 */
	for (;;) {
		ctl.len = 0;
		ctl.maxlen = BUFSIZE;
		ctl.buf = ctlbuf;
		data.len = 0;
		data.maxlen = BUFSIZE;
		data.buf = databuf;
		flags = 0;

		if ((ret = getmsg(rdev->fd, &ctl, &data, &flags)) < 0)
			syserr("getmsg");

		/*
		 * Validate DL_UNITDATA_IND.
		 */
		/* LINTED pointer */
		dlp = (union DL_primitives *)ctlbuf;

		(void) memcpy(ans, databuf, rdev->ifrarplen);

		cause = NULL;
		if (ctl.len == 0)
			cause = "missing control part of message";
		else if (ctl.len < 0)
			cause = "short control part of message";
		else if (dlp->dl_primitive != DL_UNITDATA_IND)
			cause = "not unitdata_ind";
		else if (ret & MORECTL)
			cause = "MORECTL flag";
		else if (ret & MOREDATA)
			cause = "MOREDATA flag";
		else if (ctl.len < DL_UNITDATA_IND_SIZE)
			cause = "short unitdata_ind";
		else if (data.len < rdev->ifrarplen)
			cause = "short arp";
		else if (ans->ar_hrd != htons(ARPHRD_ETHER))
			cause = "hrd";
		else if (ans->ar_pro != htons(ETHERTYPE_IP))
			cause = "pro";
		else if (ans->ar_hln != rdev->ifaddrlen)
			cause = "hln";
		else if (ans->ar_pln != sizeof (ipaddr_t))
			cause = "pln";
		if (cause) {
			if (dflag)
				debug("receive check failed: cause: %s",
					cause);
			continue;
		}

		/*
		 * Good request.
		 * Pick out the mac source address of this RARP request.
		 */
		laddrp = (uchar_t *)ctlbuf +
		    dlp->unitdata_ind.dl_src_addr_offset;
		(void) memcpy(shost, laddrp, ans->ar_hln);

		/*
		 * Handle the request.
		 */
		switch (ntohs(ans->ar_op)) {
		case REVARP_REQUEST:
			rarp_request(rdev, ans, shost);
			break;

		case ARPOP_REQUEST:
			arp_request(rdev, ans, shost);
			break;

		case REVARP_REPLY:
			if (dflag)
				debug("REVARP_REPLY ignored");
			break;

		case ARPOP_REPLY:
			if (dflag)
				debug("ARPOP_REPLY ignored");
			break;

		default:
			if (dflag)
				debug("unknown opcode 0x%x", ans->ar_op);
			break;
		}
	}
	/* NOTREACHED */
}

/*
 * Reverse address determination and allocation code.
 */
static void
rarp_request(struct rarpdev *rdev, struct arphdr *rp, uchar_t *shost)
{
	ipaddr_t		tpa,  spa;
	struct	rarpreply	*rrp;
	uchar_t			*shap, *thap, *spap, *tpap;
	char			*str = NULL;

	shap = (uchar_t *)rp + sizeof (struct arphdr);
	spap = shap + rp->ar_hln;
	thap = spap + rp->ar_pln;
	tpap = thap + rp->ar_hln;

	if (dflag) {
		str = _link_ntoa(thap, str, rdev->ifaddrlen, IFT_OTHER);
		if (str != NULL) {
			debug("RARP_REQUEST for %s", str);
			free(str);
		}
	}

	/*
	 * third party lookups are rare and wonderful
	 */
	if ((memcmp(shap, thap, rdev->ifaddrlen) != 0) ||
	    (memcmp(shap, shost, rdev->ifaddrlen) != 0)) {
		if (dflag)
			debug("weird (3rd party lookup)");
	}

	/*
	 * fill in given parts of reply packet
	 */
	(void) memcpy(shap, rdev->lladdr, rdev->ifaddrlen);

	/*
	 * If a good address is stored in our lookup tables, return it
	 * immediately or after a delay.  Store it our kernel's ARP cache.
	 */
	if (get_ipaddr(rdev, thap, tpap, &spa))
		return;
	(void) memcpy(spap, &spa, sizeof (spa));

	add_arp(rdev, tpap, thap);

	rp->ar_op = htons(REVARP_REPLY);

	if (dflag) {
		struct in_addr addr;

		(void) memcpy(&addr, tpap, sizeof (ipaddr_t));
		debug("good lookup, maps to %s", inet_ntoa(addr));
	}

	rrp = (struct rarpreply *)calloc(1, sizeof (struct rarpreply) +
	    rdev->ifaddrlen + rdev->ifrarplen);
	if (rrp == NULL)
		error("out of memory");
	rrp->lldest = (uchar_t *)rrp + sizeof (struct rarpreply);
	rrp->arprep = rrp->lldest + rdev->ifaddrlen;

	/*
	 * Create rarpreply structure.
	 */
	(void) gettimeofday(&rrp->tv, NULL);
	rrp->tv.tv_sec += 3;	/* delay */
	rrp->rdev = rdev;
	(void) memcpy(rrp->lldest, shost, rdev->ifaddrlen);
	(void) memcpy(rrp->arprep, rp, rdev->ifrarplen);

	/*
	 * If this is diskless and we're not its bootserver, let the
	 * bootserver reply first by delaying a while.
	 */
	(void) memcpy(&tpa, tpap, sizeof (ipaddr_t));
	if (mightboot(ntohl(tpa))) {
		if (rarp_write(rdev->fd, rrp) < 0)
			syslog(LOG_ERR, "Bad rarp_write:  %m");
		if (dflag)
			debug("immediate reply sent");
		(void) free(rrp);
	} else {
		delay_write(rdev, rrp);
	}
}

/*
 * Download an ARP entry into our kernel.
 */
static void
add_arp(struct rarpdev *rdev, uchar_t *ip, uchar_t *laddr)
{
	struct xarpreq ar;
	struct sockaddr_in	*sin;
	int	fd;

	/*
	 * Common part of query or set
	 */
	(void) memset(&ar, 0, sizeof (ar));
	ar.xarp_pa.ss_family = AF_INET;
	sin = (struct sockaddr_in *)&ar.xarp_pa;
	(void) memcpy(&sin->sin_addr, ip, sizeof (ipaddr_t));

	/*
	 * Open the IP provider.
	 */
	if ((fd = open(DEVARP, 0)) < 0)
		syserr(DEVARP);

	/*
	 * Set the entry
	 */
	(void) memcpy(LLADDR(&ar.xarp_ha), laddr, rdev->ifaddrlen);
	ar.xarp_ha.sdl_alen = rdev->ifaddrlen;
	ar.xarp_ha.sdl_family = AF_LINK;
	(void) strioctl(fd, SIOCDXARP, -1, sizeof (struct xarpreq),
	    (char *)&ar);
	if (strioctl(fd, SIOCSXARP, -1, sizeof (struct xarpreq),
	    (char *)&ar) < 0)
		syserr("SIOCSXARP");

	(void) close(fd);
}

/*
 * The RARP spec says we must be able to process ARP requests,
 * even through the packet type is RARP.  Let's hope this feature
 * is not heavily used.
 */
static void
arp_request(struct rarpdev *rdev, struct arphdr *rp, uchar_t *shost)
{
	struct	rarpreply	*rrp;
	struct ifdev		*ifdev;
	uchar_t			*shap, *thap, *spap, *tpap;
	int			ret;

	shap = (uchar_t *)rp + sizeof (struct arphdr);
	spap = shap + rp->ar_hln;
	thap = spap + rp->ar_pln;
	tpap = thap + rp->ar_hln;

	if (dflag)
		debug("ARPOP_REQUEST");

	for (ifdev = rdev->ifdev; ifdev != NULL; ifdev = ifdev->next) {
		if (memcmp(&ifdev->ipaddr, tpap, sizeof (ipaddr_t)) == 0)
			break;
	}
	if (ifdev == NULL)
		return;

	rp->ar_op = ARPOP_REPLY;
	(void) memcpy(shap, rdev->lladdr, rdev->ifaddrlen);
	(void) memcpy(spap, &ifdev->ipaddr, sizeof (ipaddr_t));
	(void) memcpy(thap, rdev->lladdr, rdev->ifaddrlen);

	add_arp(rdev, tpap, thap);

	/*
	 * Create rarp reply structure.
	 */
	rrp = (struct rarpreply *)calloc(1, sizeof (struct rarpreply) +
	    rdev->ifaddrlen + rdev->ifrarplen);
	if (rrp == NULL)
		error("out of memory");
	rrp->lldest = (uchar_t *)rrp + sizeof (struct rarpreply);
	rrp->arprep = rrp->lldest + rdev->ifaddrlen;
	rrp->rdev = rdev;

	(void) memcpy(rrp->lldest, shost, rdev->ifaddrlen);
	(void) memcpy(rrp->arprep, rp, rdev->ifrarplen);

	ret = rarp_write(rdev->fd, rrp);
	free(rrp);
	if (ret < 0)
		error("rarp_write error");
}

/*
 * OPEN the datalink provider device, ATTACH to the unit,
 * and BIND to the revarp type.
 * Return the resulting descriptor.
 *
 * MT-UNSAFE
 */
static int
rarp_open(struct rarpdev *rarpdev, ushort_t type)
{
	register int fd;
	char	path[MAXPATHL];
	union DL_primitives *dlp;
	char	buf[BUFSIZE];
	struct	strbuf	ctl;
	int	flags;
	uchar_t	*eap;
	char	*device = rarpdev->device;
	int	unit = rarpdev->unit;
	char	*str = NULL;

	/*
	 * Prefix the device name with "/dev/" if it doesn't
	 * start with a "/" .
	 */
	if (*device == '/')
		(void) snprintf(path, sizeof (path), "%s", device);
	else
		(void) snprintf(path, sizeof (path), "%s/%s", DEVDIR, device);

	/*
	 * Open the datalink provider.
	 */
	if ((fd = open(path, O_RDWR)) < 0)
		syserr(path);

	/*
	 * Issue DL_INFO_REQ and check DL_INFO_ACK for sanity.
	 */
	/* LINTED pointer */
	dlp = (union DL_primitives *)buf;
	dlp->info_req.dl_primitive = DL_INFO_REQ;

	ctl.buf = (char *)dlp;
	ctl.len = DL_INFO_REQ_SIZE;

	if (putmsg(fd, &ctl, NULL, 0) < 0)
		syserr("putmsg");

	(void) signal(SIGALRM, sigalarm);

	alarmmsg = "DL_INFO_REQ failed: timeout waiting for DL_INFO_ACK";
	(void) alarm(10);

	ctl.buf = (char *)dlp;
	ctl.len = 0;
	ctl.maxlen = BUFSIZE;
	flags = 0;
	if (getmsg(fd, &ctl, NULL, &flags) < 0)
		syserr("getmsg");

	(void) alarm(0);
	(void) signal(SIGALRM, SIG_DFL);

	/*
	 * Validate DL_INFO_ACK reply.
	 */
	if (ctl.len < sizeof (ulong_t))
		error("DL_INFO_REQ failed:  short reply to DL_INFO_REQ");

	if (dlp->dl_primitive != DL_INFO_ACK)
		error("DL_INFO_REQ failed:  dl_primitive 0x%lx received",
			dlp->dl_primitive);

	if (ctl.len < DL_INFO_ACK_SIZE)
		error("DL_INFO_REQ failed:  short info_ack:  %d bytes",
			ctl.len);

	if (dlp->info_ack.dl_version != DL_VERSION_2)
		error("DL_INFO_ACK:  incompatible version:  %lu",
			dlp->info_ack.dl_version);

	if (dlp->info_ack.dl_sap_length != -2) {
		if (dflag)
			debug(
"%s%d DL_INFO_ACK:  incompatible dl_sap_length:  %ld",
				device, unit, dlp->info_ack.dl_sap_length);
		(void) close(fd);
		return (-1);
	}

	if ((dlp->info_ack.dl_service_mode & DL_CLDLS) == 0) {
		if (dflag)
			debug(
"%s%d DL_INFO_ACK:  incompatible dl_service_mode:  0x%lx",
				device, unit, dlp->info_ack.dl_service_mode);
		(void) close(fd);
		return (-1);
	}

	rarpdev->ifsaplen = dlp->info_ack.dl_sap_length;
	rarpdev->ifaddrlen = dlp->info_ack.dl_addr_length -
	    abs(rarpdev->ifsaplen);
	rarpdev->ifrarplen = sizeof (struct arphdr) +
	    (2 * sizeof (ipaddr_t)) + (2 * rarpdev->ifaddrlen);

	/*
	 * Issue DL_ATTACH_REQ.
	 */
	/* LINTED pointer */
	dlp = (union DL_primitives *)buf;
	dlp->attach_req.dl_primitive = DL_ATTACH_REQ;
	dlp->attach_req.dl_ppa = unit;

	ctl.buf = (char *)dlp;
	ctl.len = DL_ATTACH_REQ_SIZE;

	if (putmsg(fd, &ctl, NULL, 0) < 0)
		syserr("putmsg");

	(void) signal(SIGALRM, sigalarm);
	alarmmsg = "DL_ATTACH_REQ failed: timeout waiting for DL_OK_ACK";

	(void) alarm(10);

	ctl.buf = (char *)dlp;
	ctl.len = 0;
	ctl.maxlen = BUFSIZE;
	flags = 0;
	if (getmsg(fd, &ctl, NULL, &flags) < 0)
		syserr("getmsg");

	(void) alarm(0);
	(void) signal(SIGALRM, SIG_DFL);

	/*
	 * Validate DL_OK_ACK reply.
	 */
	if (ctl.len < sizeof (ulong_t))
		error("DL_ATTACH_REQ failed:  short reply to attach request");

	if (dlp->dl_primitive == DL_ERROR_ACK)
		error("DL_ATTACH_REQ failed:  dl_errno %lu unix_errno %lu",
			dlp->error_ack.dl_errno, dlp->error_ack.dl_unix_errno);

	if (dlp->dl_primitive != DL_OK_ACK)
		error("DL_ATTACH_REQ failed:  dl_primitive 0x%lx received",
			dlp->dl_primitive);

	if (ctl.len < DL_OK_ACK_SIZE)
		error("attach failed:  short ok_ack:  %d bytes",
			ctl.len);

	/*
	 * Issue DL_BIND_REQ.
	 */
	/* LINTED pointer */
	dlp = (union DL_primitives *)buf;
	dlp->bind_req.dl_primitive = DL_BIND_REQ;
	dlp->bind_req.dl_sap = type;
	dlp->bind_req.dl_max_conind = 0;
	dlp->bind_req.dl_service_mode = DL_CLDLS;
	dlp->bind_req.dl_conn_mgmt = 0;
	dlp->bind_req.dl_xidtest_flg = 0;

	ctl.buf = (char *)dlp;
	ctl.len = DL_BIND_REQ_SIZE;

	if (putmsg(fd, &ctl, NULL, 0) < 0)
		syserr("putmsg");

	(void) signal(SIGALRM, sigalarm);

	alarmmsg = "DL_BIND_REQ failed:  timeout waiting for DL_BIND_ACK";
	(void) alarm(10);

	ctl.buf = (char *)dlp;
	ctl.len = 0;
	ctl.maxlen = BUFSIZE;
	flags = 0;
	if (getmsg(fd, &ctl, NULL, &flags) < 0)
		syserr("getmsg");

	(void) alarm(0);
	(void) signal(SIGALRM, SIG_DFL);

	/*
	 * Validate DL_BIND_ACK reply.
	 */
	if (ctl.len < sizeof (ulong_t))
		error("DL_BIND_REQ failed:  short reply");

	if (dlp->dl_primitive == DL_ERROR_ACK)
		error("DL_BIND_REQ failed:  dl_errno %lu unix_errno %lu",
			dlp->error_ack.dl_errno, dlp->error_ack.dl_unix_errno);

	if (dlp->dl_primitive != DL_BIND_ACK)
		error("DL_BIND_REQ failed:  dl_primitive 0x%lx received",
			dlp->dl_primitive);

	if (ctl.len < DL_BIND_ACK_SIZE)
		error(
"DL_BIND_REQ failed:  short bind acknowledgement received");

	if (dlp->bind_ack.dl_sap != type)
		error(
"DL_BIND_REQ failed:  returned dl_sap %lu != requested sap %d",
			dlp->bind_ack.dl_sap, type);

	/*
	 * Issue DL_PHYS_ADDR_REQ to get our local mac address.
	 */
	/* LINTED pointer */
	dlp = (union DL_primitives *)buf;
	dlp->physaddr_req.dl_primitive = DL_PHYS_ADDR_REQ;
	dlp->physaddr_req.dl_addr_type = DL_CURR_PHYS_ADDR;

	ctl.buf = (char *)dlp;
	ctl.len = DL_PHYS_ADDR_REQ_SIZE;

	if (putmsg(fd, &ctl, NULL, 0) < 0)
		syserr("putmsg");

	(void) signal(SIGALRM, sigalarm);

	alarmmsg =
	    "DL_PHYS_ADDR_REQ failed:  timeout waiting for DL_PHYS_ADDR_ACK";
	(void) alarm(10);

	ctl.buf = (char *)dlp;
	ctl.len = 0;
	ctl.maxlen = BUFSIZE;
	flags = 0;
	if (getmsg(fd, &ctl, NULL, &flags) < 0)
		syserr("getmsg");

	(void) alarm(0);
	(void) signal(SIGALRM, SIG_DFL);

	/*
	 * Validate DL_PHYS_ADDR_ACK reply.
	 */
	if (ctl.len < sizeof (ulong_t))
		error("DL_PHYS_ADDR_REQ failed:  short reply");

	if (dlp->dl_primitive == DL_ERROR_ACK)
		error("DL_PHYS_ADDR_REQ failed:  dl_errno %lu unix_errno %lu",
			dlp->error_ack.dl_errno, dlp->error_ack.dl_unix_errno);

	if (dlp->dl_primitive != DL_PHYS_ADDR_ACK)
		error("DL_PHYS_ADDR_REQ failed:  dl_primitive 0x%lx received",
			dlp->dl_primitive);

	if (ctl.len < DL_PHYS_ADDR_ACK_SIZE)
		error("DL_PHYS_ADDR_REQ failed:  short ack received");

	if (dlp->physaddr_ack.dl_addr_length != rarpdev->ifaddrlen) {
		if (dflag)
			debug(
"%s%d DL_PHYS_ADDR_ACK failed:  incompatible dl_addr_length:  %lu",
			device, unit, dlp->physaddr_ack.dl_addr_length);
		(void) close(fd);
		return (-1);
	}

	/*
	 * Save our mac address.
	 */
	if ((rarpdev->lladdr = (uchar_t *)malloc(rarpdev->ifaddrlen)) == NULL) {
		if (dflag)
			debug(" %s%d malloc failed: %d bytes", device,
			    unit, rarpdev->ifaddrlen);
		(void) close(fd);
		return (-1);
	}

	eap = (uchar_t *)dlp + dlp->physaddr_ack.dl_addr_offset;
	(void) memcpy(rarpdev->lladdr, eap, dlp->physaddr_ack.dl_addr_length);

	if (dflag) {
		str = _link_ntoa(rarpdev->lladdr, str, rarpdev->ifaddrlen,
		    IFT_OTHER);
		if (str != NULL) {
			debug("device %s%d lladdress %s", device, unit, str);
			free(str);
		}
	}

	return (fd);
}

/* ARGSUSED */
static void
do_delay_write(void *buf)
{
	struct	timeval		tv;
	struct	rarpreply	*rrp;
	int			err;

	for (;;) {
		if ((err = sema_wait(&delay_sema)) != 0) {
			if (err == EINTR)
				continue;
			error("do_delay_write: sema_wait failed");
		}

		(void) mutex_lock(&delay_mutex);
		rrp = delay_list;
		delay_list = delay_list->next;
		(void) mutex_unlock(&delay_mutex);

		(void) gettimeofday(&tv, NULL);
		if (tv.tv_sec < rrp->tv.tv_sec)
			(void) sleep(rrp->tv.tv_sec - tv.tv_sec);

		if (rarp_write(rrp->rdev->fd, rrp) < 0)
			error("rarp_write error");

		(void) free(rrp);
	}
	/* NOTREACHED */
}

/* ARGSUSED */
static void
delay_write(struct rarpdev *rdev, struct rarpreply *rrp)
{
	struct	rarpreply	*trp;

	(void) mutex_lock(&delay_mutex);
	if (delay_list == NULL) {
		delay_list = rrp;
	} else {
		trp = delay_list;
		while (trp->next != NULL)
			trp = trp->next;
		trp->next = rrp;
	}
	(void) mutex_unlock(&delay_mutex);

	(void) sema_post(&delay_sema);
}

static int
rarp_write(int fd, struct rarpreply *rrp)
{
	struct	strbuf	ctl, data;
	union	DL_primitives	*dlp;
	char	ctlbuf[BUFSIZE];
	ushort_t etype = ETHERTYPE_REVARP;
	int	ifaddrlen = rrp->rdev->ifaddrlen;

	/*
	 * Construct DL_UNITDATA_REQ.
	 */
	/* LINTED pointer */
	dlp = (union DL_primitives *)ctlbuf;
	ctl.len = DL_UNITDATA_REQ_SIZE + ifaddrlen + abs(rrp->rdev->ifsaplen);
	ctl.buf = ctlbuf;
	data.len = rrp->rdev->ifrarplen;
	data.buf = (char *)rrp->arprep;
	if (ctl.len > sizeof (ctlbuf))
		return (-1);

	dlp->unitdata_req.dl_primitive = DL_UNITDATA_REQ;
	dlp->unitdata_req.dl_dest_addr_length = ifaddrlen +
	    abs(rrp->rdev->ifsaplen);
	dlp->unitdata_req.dl_dest_addr_offset = DL_UNITDATA_REQ_SIZE;
	dlp->unitdata_req.dl_priority.dl_min = 0;
	dlp->unitdata_req.dl_priority.dl_max = 0;
	(void) memcpy(ctlbuf + DL_UNITDATA_REQ_SIZE, rrp->lldest, ifaddrlen);
	(void) memcpy(ctlbuf + DL_UNITDATA_REQ_SIZE + ifaddrlen, &etype,
	    sizeof (etype));

	/*
	 * Send DL_UNITDATA_REQ.
	 */
	return (putmsg(fd, &ctl, &data, 0));
}

/*
 * See if we have a TFTP boot file for this guy. Filenames in TFTP
 * boot requests are of the form <ipaddr> for Sun-3's and of the form
 * <ipaddr>.<arch> for all other architectures.  Since we don't know
 * the client's architecture, either format will do.
 */
static int
mightboot(ipaddr_t ipa)
{
	char path[MAXPATHL];
	DIR *dirp;
	struct dirent *dp;
	struct dirent *dentry;

	(void) snprintf(path, sizeof (path), "%s/%08X", BOOTDIR, ipa);

	/*
	 * Try a quick access() first.
	 */
	if (access(path, 0) == 0)
		return (1);

	/*
	 * Not there, do it the slow way by
	 * reading through the directory.
	 */
	(void) sprintf(path, "%08X", ipa);

	if (!(dirp = opendir(BOOTDIR)))
		return (0);

	dentry = (struct dirent *)malloc(sizeof (struct dirent) +
							pc_name_max + 1);
	if (dentry == NULL) {
		error("out of memory");
	}
#ifdef _POSIX_PTHREAD_SEMANTICS
	while ((readdir_r(dirp, dentry, &dp)) != 0) {
		if (dp == NULL)
			break;
#else
	while ((dp = readdir_r(dirp, dentry)) != NULL) {
#endif
		if (strncmp(dp->d_name, path, 8) != 0)
			continue;
		if ((strlen(dp->d_name) != 8) && (dp->d_name[8] != '.'))
			continue;
		break;
	}

	(void) closedir(dirp);
	(void) free(dentry);

	return (dp? 1: 0);
}

/*
 * Get our IP address and local netmask.
 */
static void
get_ifdata(char *dev, int unit, ipaddr_t *ipp, ipaddr_t *maskp)
{
	int	fd;
	struct	ifreq	ifr;
	struct	sockaddr_in	*sin;

	/* LINTED pointer */
	sin = (struct sockaddr_in *)&ifr.ifr_addr;

	/*
	 * Open the IP provider.
	 */
	if ((fd = open(DEVIP, 0)) < 0)
		syserr(DEVIP);

	/*
	 * Ask IP for our IP address.
	 */
	(void) snprintf(ifr.ifr_name, sizeof (ifr.ifr_name), "%s%d", dev, unit);
	if (strioctl(fd, SIOCGIFADDR, -1, sizeof (struct ifreq),
		(char *)&ifr) < 0)
		syserr("SIOCGIFADDR");
	*ipp = (ipaddr_t)ntohl(sin->sin_addr.s_addr);

	if (dflag)
		debug("device %s%d address %s",
			dev, unit, inet_ntoa(sin->sin_addr));

	/*
	 * Ask IP for our netmask.
	 */
	if (strioctl(fd, SIOCGIFNETMASK, -1, sizeof (struct ifreq),
		(char *)&ifr) < 0)
		syserr("SIOCGIFNETMASK");
	*maskp = (ipaddr_t)ntohl(sin->sin_addr.s_addr);

	if (dflag)
		debug("device %s%d subnet mask %s",
			dev, unit, inet_ntoa(sin->sin_addr));

	/*
	 * Thankyou ip.
	 */
	(void) close(fd);
}

/*
 * Translate mac address to IP address.
 * Return 0 on success, nonzero on failure.
 */
static int
get_ipaddr(struct rarpdev *rdev, uchar_t *laddr, uchar_t *ipp, ipaddr_t *ipaddr)
{
	char host[MAXHOSTL];
	char hbuffer[BUFSIZE];
	struct hostent *hp, res;
	int herror;
	struct in_addr addr;
	char	**p;
	struct ifdev *ifdev;

	if (rdev->ifaddrlen != ETHERADDRL) {
		if (dflag)
			debug("%s %s", " can not map non 6 byte hardware ",
			    "address to IP address");
		return (1);
	}

	/*
	 * Translate mac address to hostname
	 * and IP address.
	 */
	if (ether_ntohost(host, (struct ether_addr *)laddr) != 0 ||
	    !(hp = gethostbyname_r(host, &res, hbuffer, sizeof (hbuffer),
	    &herror)) ||
	    hp->h_addrtype != AF_INET || hp->h_length != sizeof (ipaddr_t)) {
		if (dflag)
			debug("could not map hardware address to IP address");
		return (1);
	}

	/*
	 * Find the IP address on the right net.
	 */
	for (p = hp->h_addr_list; *p; p++) {
		(void) memcpy(&addr, *p, sizeof (ipaddr_t));
		for (ifdev = rdev->ifdev; ifdev != NULL; ifdev = ifdev->next) {
			if (dflag) {
				struct in_addr daddr;
				ipaddr_t netnum;

				netnum = htonl(ifdev->if_netnum);
				(void) memcpy(&daddr, &netnum,
				    sizeof (ipaddr_t));
				if (ifdev->lunit == -1)
					debug(
"trying physical netnum %s mask %x",
					inet_ntoa(daddr),
					ifdev->if_netmask);
				else
					debug(
"trying logical %d netnum %s mask %x",
					ifdev->lunit,
					inet_ntoa(daddr),
					ifdev->if_netmask);
			}
			if ((ntohl(addr.s_addr) & ifdev->if_netmask) ==
							ifdev->if_netnum) {
				/*
				 * Return the correct IP address.
				 */
				(void) memcpy(ipp, &addr, sizeof (ipaddr_t));

				/*
				 * Return the interface's ipaddr
				 */
				(void) memcpy(ipaddr, &ifdev->ipaddr,
				    sizeof (ipaddr_t));

				return (0);
			}
		}
	}

	if (dflag)
		debug("got host entry but no IP address on this net");
	return (1);
}

/*ARGSUSED*/
void
sigalarm(int i)
{
	error(alarmmsg);
}

static int
strioctl(int fd, int cmd, int timout, int len, char *dp)
{
	struct	strioctl	si;

	si.ic_cmd = cmd;
	si.ic_timout = timout;
	si.ic_len = len;
	si.ic_dp = dp;
	return (ioctl(fd, I_STR, &si));
}

static void
usage()
{
	error("Usage:  %s [ -ad ] device unit", cmdname);
}

static void
syserr(s)
char	*s;
{
	char buf[256];
	int status = 1;

	(void) snprintf(buf, sizeof (buf), "%s: %s", s, strerror(errno));
	(void) fprintf(stderr, "%s:  %s\n", cmdname, buf);
	syslog(LOG_ERR, "%s", buf);
	thr_exit(&status);
}

/*PRINTFLIKE1*/
static void
error(char *fmt, ...)
{
	char buf[256];
	va_list ap;
	int status = 1;

	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);
	(void) fprintf(stderr, "%s:  %s\n", cmdname, buf);
	syslog(LOG_ERR, buf);
	thr_exit(&status);
}

/*PRINTFLIKE1*/
static void
debug(char *fmt, ...)
{
	va_list ap;

	(void) mutex_lock(&debug_mutex);
	va_start(ap, fmt);
	(void) fprintf(stderr, "%s:[%u]  ", cmdname, thr_self());
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, "\n");
	va_end(ap);
	(void) mutex_unlock(&debug_mutex);
}
