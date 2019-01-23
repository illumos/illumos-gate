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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

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
#include	<stdio_ext.h>
#include	<stdarg.h>
#include	<string.h>
#include	<fcntl.h>
#include	<sys/types.h>
#include	<dirent.h>
#include	<syslog.h>
#include	<netdb.h>
#include	<errno.h>
#include	<sys/socket.h>
#include	<sys/sockio.h>
#include	<net/if.h>
#include	<netinet/if_ether.h>
#include	<netinet/in.h>
#include	<arpa/inet.h>
#include	<stropts.h>
#include	<libinetutil.h>
#include	<libdlpi.h>
#include	<net/if_types.h>
#include	<net/if_dl.h>

#define	BOOTDIR		"/tftpboot"	/* boot files directory */
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
	char		device[DLPI_LINKNAME_MAX];
	uint_t		unit;
	dlpi_handle_t	dh_rarp;
	uchar_t		physaddr[DLPI_PHYSADDR_MAX];
						/* mac address of interface */
	uint_t		physaddrlen;		/* mac address length */
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

static void	getintf(void);
static struct rarpdev *find_device(ifspec_t *);
static void	init_rarpdev(struct rarpdev *);
static void	do_rarp(void *);
static void	rarp_request(struct rarpdev *, struct arphdr *,
		    uchar_t *);
static void	add_arp(struct rarpdev *, uchar_t *, uchar_t *);
static void	arp_request(struct rarpdev *, struct arphdr *, uchar_t *);
static void	do_delay_write(void *);
static void	delay_write(struct rarpdev *, struct rarpreply *);
static int	mightboot(ipaddr_t);
static void	get_ifdata(char *, int, ipaddr_t *, ipaddr_t *);
static int	get_ipaddr(struct rarpdev *, uchar_t *, uchar_t *, ipaddr_t *);
static int	strioctl(int, int, int, int, char *);
static void	usage();
static void	syserr(const char *);
/*PRINTFLIKE1*/
static void	error(const char *, ...);
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
	(void) enable_extended_FILE_stdio(-1, -1);

	(void) openlog(cmdname, LOG_PID, LOG_DAEMON);

	if (aflag) {
		/*
		 * Get each interface name and load rarpdev list.
		 */
		getintf();
	} else {
		ifspec_t	ifsp;
		struct ifdev	*ifdev;
		char		buf[IFNAMSIZ + 1];

		/*
		 * Load specified device as only element of the list.
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

		if (!ifparse_ifspec(buf, &ifsp))
			error("invalid interface specification");

		if (ifsp.ifsp_lunvalid) {
			(void) snprintf(ifdev->ldevice,
			    sizeof (ifdev->ldevice), "%s%d:",
			    ifsp.ifsp_devnm, ifsp.ifsp_ppa);
			ifdev->lunit = ifsp.ifsp_lun;
		} else {
			ifdev->lunit = -1; /* no logical unit */
		}
		(void) strlcpy(rarpdev_head->device, ifsp.ifsp_devnm,
		    sizeof (rarpdev_head->device));
		rarpdev_head->unit = ifsp.ifsp_ppa;

		ifdev->next = rarpdev_head->ifdev;
		rarpdev_head->ifdev = ifdev;
	}

	/*
	 * Initialize each rarpdev.
	 */
	for (rdev = rarpdev_head; rdev != NULL; rdev = rdev->next) {
		init_rarpdev(rdev);
	}

	(void) sema_init(&delay_sema, 0, USYNC_THREAD, NULL);
	(void) mutex_init(&delay_mutex, USYNC_THREAD, NULL);
	(void) mutex_init(&debug_mutex, USYNC_THREAD, NULL);

	/*
	 * Start delayed processing thread.
	 */
	(void) thr_create(NULL, 0, (void *(*)(void *))do_delay_write, NULL,
	    THR_NEW_LWP, NULL);

	/*
	 * Start RARP processing for each device.
	 */
	for (rdev = rarpdev_head; rdev != NULL; rdev = rdev->next) {
		if (rdev->dh_rarp != NULL) {
			(void) thr_create(NULL, 0,
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
	 * Initialize a rarpdev for each interface.
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
		 * Look for an existing device for logical interfaces.
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
	char 		*dev;
	int 		unit;
	struct ifdev 	*ifdev;
	int		retval;
	char		*str = NULL;
	uint_t		physaddrlen = DLPI_PHYSADDR_MAX;
	char		linkname[DLPI_LINKNAME_MAX];
	dlpi_handle_t	dh;

	(void) snprintf(linkname, DLPI_LINKNAME_MAX, "%s%d", rdev->device,
	    rdev->unit);
	/*
	 * Open datalink provider and get our mac address.
	 */
	if ((retval = dlpi_open(linkname, &dh, 0)) != DLPI_SUCCESS) {
		error("cannot open link %s: %s", linkname,
		    dlpi_strerror(retval));
	}

	if ((retval = dlpi_bind(dh, ETHERTYPE_REVARP, NULL)) != DLPI_SUCCESS) {
		dlpi_close(dh);
		error("dlpi_bind failed: %s", dlpi_strerror(retval));
	}

	/*
	 * Save our mac address.
	 */
	if ((retval = dlpi_get_physaddr(dh, DL_CURR_PHYS_ADDR, rdev->physaddr,
	    &physaddrlen)) != DLPI_SUCCESS) {
		dlpi_close(dh);
		error("dlpi_get_physaddr failed: %s", dlpi_strerror(retval));
	}

	rdev->physaddrlen = physaddrlen;
	rdev->ifrarplen = sizeof (struct arphdr) + (2 * sizeof (ipaddr_t)) +
	    (2 * physaddrlen);

	if (dflag) {
		str = _link_ntoa(rdev->physaddr, str,
		    rdev->physaddrlen, IFT_OTHER);
		if (str != NULL) {
			debug("device %s physical address %s", linkname, str);
			free(str);
		}
	}

	/*
	 * Assign dlpi handle to rdev.
	 */
	rdev->dh_rarp = dh;

	/*
	 * Get the IP address and netmask from directory service for
	 * each logical interface.
	 */
	for (ifdev = rdev->ifdev; ifdev != NULL; ifdev = ifdev->next) {
		/*
		 * If lunit == -1 then this is the primary interface name.
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
	struct rarpdev *rdev = buf;
	char	*cause;
	struct arphdr *ans;
	uchar_t *shost;
	uint_t	saddrlen;
	size_t	anslen = rdev->ifrarplen;
	char	*str = NULL;
	int	retval;

	if (((shost = malloc(rdev->physaddrlen)) == NULL) ||
	    ((ans = malloc(rdev->ifrarplen)) == NULL))
		syserr("malloc");

	if (dflag) {
		str = _link_ntoa(rdev->physaddr, str, rdev->physaddrlen,
		    IFT_OTHER);
		if (str != NULL) {
			debug("starting rarp service on device %s%d physical"
			    " address %s", rdev->device, rdev->unit, str);
			free(str);
		}
	}

	/*
	 * Read RARP packets and respond to them.
	 */
	for (;;) {
		saddrlen = DLPI_PHYSADDR_MAX;
		retval = dlpi_recv(rdev->dh_rarp, shost,
		    &saddrlen, ans, &anslen, -1, NULL);
		if (retval == DLPI_ETIMEDOUT) {
			continue;
		} else if (retval != DLPI_SUCCESS) {
			error("error in dlpi_recv %s: %s", rdev->dh_rarp,
			    dlpi_strerror(retval));
		}

		cause = NULL;

		if (anslen < rdev->ifrarplen)
			cause = "short packet";
		else if (ans->ar_hrd != htons(ARPHRD_ETHER))
			cause = "hardware type not Ethernet";
		else if (ans->ar_pro != htons(ETHERTYPE_IP))
			cause = "protocol type not IP";
		else if (ans->ar_hln != rdev->physaddrlen)
			cause = "unexpected hardware address length";
		else if (ans->ar_pln != sizeof (ipaddr_t))
			cause = "unexpected protocol address length";
		if (cause != NULL) {
			if (dflag)
				debug("RARP packet received but "
				    "discarded: %s", cause);
			continue;
		}

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
	int			retval;

	shap = (uchar_t *)rp + sizeof (struct arphdr);
	spap = shap + rp->ar_hln;
	thap = spap + rp->ar_pln;
	tpap = thap + rp->ar_hln;

	if (dflag) {
		str = _link_ntoa(thap, str, rdev->physaddrlen, IFT_OTHER);
		if (str != NULL) {
			debug("RARP_REQUEST for %s", str);
			free(str);
		}
	}

	/*
	 * Third party lookups are rare and wonderful.
	 */
	if ((memcmp(shap, thap, rdev->physaddrlen) != 0) ||
	    (memcmp(shap, shost, rdev->physaddrlen) != 0)) {
		if (dflag)
			debug("weird (3rd party lookup)");
	}

	/*
	 * Fill in given parts of reply packet.
	 */
	(void) memcpy(shap, rdev->physaddr, rdev->physaddrlen);

	/*
	 * If a good address is stored in our lookup tables, return it
	 * immediately or after a delay.  Store it in our kernel's ARP cache.
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

	rrp = calloc(1, sizeof (struct rarpreply) + rdev->physaddrlen +
	    rdev->ifrarplen);
	if (rrp == NULL)
		error("out of memory");
	rrp->lldest = (uchar_t *)rrp + sizeof (struct rarpreply);
	rrp->arprep = rrp->lldest + rdev->physaddrlen;

	/*
	 * Create rarpreply structure.
	 */
	(void) gettimeofday(&rrp->tv, NULL);
	rrp->tv.tv_sec += 3;	/* delay */
	rrp->rdev = rdev;
	(void) memcpy(rrp->lldest, shost, rdev->physaddrlen);
	(void) memcpy(rrp->arprep, rp, rdev->ifrarplen);

	/*
	 * If this is diskless and we're not its bootserver, let the
	 * bootserver reply first by delaying a while.
	 */
	(void) memcpy(&tpa, tpap, sizeof (ipaddr_t));
	if (mightboot(ntohl(tpa))) {
		retval = dlpi_send(rdev->dh_rarp, rrp->lldest,
		    rdev->physaddrlen, rrp->arprep, rdev->ifrarplen, NULL);
		if (retval != DLPI_SUCCESS) {
			error("dlpi_send failed: %s", dlpi_strerror(retval));
		} else if (dflag) {
			debug("immediate reply sent");
		}
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
	 * Common part of query or set.
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
	 * Set the entry.
	 */
	(void) memcpy(LLADDR(&ar.xarp_ha), laddr, rdev->physaddrlen);
	ar.xarp_ha.sdl_alen = rdev->physaddrlen;
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
	int			retval;

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
	(void) memcpy(shap, rdev->physaddr, rdev->physaddrlen);
	(void) memcpy(spap, &ifdev->ipaddr, sizeof (ipaddr_t));
	(void) memcpy(thap, rdev->physaddr, rdev->physaddrlen);

	add_arp(rdev, tpap, thap);

	/*
	 * Create rarp reply structure.
	 */
	rrp = calloc(1, sizeof (struct rarpreply) + rdev->physaddrlen +
	    rdev->ifrarplen);
	if (rrp == NULL)
		error("out of memory");
	rrp->lldest = (uchar_t *)rrp + sizeof (struct rarpreply);
	rrp->arprep = rrp->lldest + rdev->physaddrlen;
	rrp->rdev = rdev;

	(void) memcpy(rrp->lldest, shost, rdev->physaddrlen);
	(void) memcpy(rrp->arprep, rp, rdev->ifrarplen);

	retval = dlpi_send(rdev->dh_rarp, rrp->lldest, rdev->physaddrlen,
	    rrp->arprep, rdev->ifrarplen, NULL);
	free(rrp);
	if (retval != DLPI_SUCCESS)
		error("dlpi_send failed: %s", dlpi_strerror(retval));
}

/* ARGSUSED */
static void
do_delay_write(void *buf)
{
	struct	timeval		tv;
	struct	rarpreply	*rrp;
	struct	rarpdev		*rdev;
	int			err;

	for (;;) {
		if ((err = sema_wait(&delay_sema)) != 0) {
			if (err == EINTR)
				continue;
			error("do_delay_write: sema_wait failed");
		}

		(void) mutex_lock(&delay_mutex);
		rrp = delay_list;
		rdev = rrp->rdev;
		delay_list = delay_list->next;
		(void) mutex_unlock(&delay_mutex);

		(void) gettimeofday(&tv, NULL);
		if (tv.tv_sec < rrp->tv.tv_sec)
			(void) sleep(rrp->tv.tv_sec - tv.tv_sec);

		err = dlpi_send(rdev->dh_rarp, rrp->lldest, rdev->physaddrlen,
		    rrp->arprep, rdev->ifrarplen, NULL);
		if (err != DLPI_SUCCESS)
			error("dlpi_send failed: %s", dlpi_strerror(err));

		(void) free(rrp);
	}
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

	while ((dp = readdir(dirp)) != NULL) {
		if (strncmp(dp->d_name, path, 8) != 0)
			continue;
		if ((strlen(dp->d_name) != 8) && (dp->d_name[8] != '.'))
			continue;
		break;
	}

	(void) closedir(dirp);

	return ((dp != NULL) ? 1 : 0);
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
		debug("device %s%d address %s", dev, unit,
		    inet_ntoa(sin->sin_addr));

	/*
	 * Ask IP for our netmask.
	 */
	if (strioctl(fd, SIOCGIFNETMASK, -1, sizeof (struct ifreq),
	    (char *)&ifr) < 0)
		syserr("SIOCGIFNETMASK");
	*maskp = (ipaddr_t)ntohl(sin->sin_addr.s_addr);

	if (dflag)
		debug("device %s%d subnet mask %s", dev, unit,
		    inet_ntoa(sin->sin_addr));

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

	if (rdev->physaddrlen != ETHERADDRL) {
		if (dflag)
			debug("%s %s", " cannot map non 6 byte hardware ",
			    "address to IP address");
		return (1);
	}

	/*
	 * Translate mac address to hostname and IP address.
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
					debug("trying physical netnum %s"
					    " mask %x", inet_ntoa(daddr),
					    ifdev->if_netmask);
				else
					debug("trying logical %d netnum %s"
					    " mask %x", ifdev->lunit,
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
usage(void)
{
	error("Usage:  %s [ -ad ] device unit", cmdname);
}

static void
syserr(const char *s)
{
	char buf[256];
	int status = 1;

	(void) snprintf(buf, sizeof (buf), "%s: %s", s, strerror(errno));
	(void) fprintf(stderr, "%s:  %s\n", cmdname, buf);
	syslog(LOG_ERR, "%s", buf);
	thr_exit(&status);
}

static void
error(const char *fmt, ...)
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
