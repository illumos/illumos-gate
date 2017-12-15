/*
 * System-dependent procedures for pppd under Solaris 2.x (SunOS 5.x).
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.
 *
 * SUN MAKES NO REPRESENTATION OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT.  SUN SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES
 *
 * Copyright (c) 1994 The Australian National University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied. The Australian National University
 * makes no representations about the suitability of this software for
 * any purpose.
 *
 * IN NO EVENT SHALL THE AUSTRALIAN NATIONAL UNIVERSITY BE LIABLE TO ANY
 * PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAVE BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 */

#include <limits.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <termios.h>
#include <signal.h>
#include <string.h>
#include <stropts.h>
#include <utmpx.h>
#include <sys/types.h>
#include <sys/ioccom.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysmacros.h>
#include <sys/systeminfo.h>
#include <sys/stat.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <net/ppp_defs.h>
#include <net/pppio.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <sys/tihdr.h>
#include <inet/mib2.h>
#include <inet/ip.h>
#include <sys/ethernet.h>
#include <sys/ser_sync.h>
#include <libdlpi.h>
#include <arpa/inet.h>

#include "pppd.h"
#include "fsm.h"
#include "lcp.h"
#include "ipcp.h"
#ifdef INET6
#include "ipv6cp.h"
#endif /* INET6 */
#include "ccp.h"

#define	PPPSTRTIMOUT	1	/* Timeout in seconds for ioctl */
#define	MAX_POLLFDS	32
#define	NMODULES	32

#ifndef MAXIFS
#define	MAXIFS		256
#endif /* MAXIFS */

#ifdef INET6
#define	_IN6_LLX_FROM_EUI64(l, s, eui64, as, len)	\
	(s->sin6_addr.s6_addr32[0] = htonl(as),		\
	eui64_copy(eui64, s->sin6_addr.s6_addr32[2]),	\
	s->sin6_family = AF_INET6,			\
	l.lifr_addr.ss_family = AF_INET6,		\
	l.lifr_addrlen = len,				\
	l.lifr_addr = laddr)

/*
 * Generate a link-local address with an interface-id based on the given
 * EUI64 identifier.  Note that the len field is unused by SIOCSLIFADDR.
 */
#define	IN6_LLADDR_FROM_EUI64(l, s, eui64)		\
	_IN6_LLX_FROM_EUI64(l, s, eui64, 0xfe800000, 0)

/*
 * Generate an EUI64 based interface-id for use by stateless address
 * autoconfiguration.  These are required to be 64 bits long as defined in
 * the "Interface Identifiers" section of the IPv6 Addressing Architecture
 * (RFC3513).
 */
#define	IN6_LLTOKEN_FROM_EUI64(l, s, eui64) \
	_IN6_LLX_FROM_EUI64(l, s, eui64, 0, 64)
#endif /* INET6 */

#define	IPCP_ENABLED	ipcp_protent.enabled_flag
#ifdef INET6
#define	IPV6CP_ENABLED	ipv6cp_protent.enabled_flag
#endif /* INET6 */

/* For plug-in usage. */
int (*sys_read_packet_hook) __P((int retv, struct strbuf *ctrl,
    struct strbuf *data, int flags)) = NULL;
bool already_ppp = 0;			/* Already in PPP mode */

static int pppfd = -1;			/* ppp driver fd */
static int fdmuxid = -1;		/* driver mux fd */
static int ipfd = -1;			/* IPv4 fd */
static int ipmuxid = -1;		/* IPv4 mux fd */
static int ip6fd = -1;			/* IPv6 fd */
static int ip6muxid = -1;		/* IPv6 mux fd */
static bool if6_is_up = 0;		/* IPv6 if marked as up */
static bool if_is_up = 0;		/* IPv4 if marked as up */
static bool restore_term = 0;		/* Restore TTY after closing link */
static struct termios inittermios;	/* TTY settings */
static struct winsize wsinfo;		/* Initial window size info */
static pid_t tty_sid;			/* original sess ID for term */
static struct pollfd pollfds[MAX_POLLFDS]; /* array of polled fd */
static int n_pollfds = 0;		/* total count of polled fd */
static int link_mtu;			/* link Maximum Transmit Unit */
static int tty_nmodules;		/* total count of TTY modules used */
static char tty_modules[NMODULES][FMNAMESZ+1];
					/* array of TTY modules used */
static int tty_npushed;			/* total count of pushed PPP modules */
static u_int32_t remote_addr;		/* IP address of peer */
static u_int32_t default_route_gateway;	/* Gateway for default route */
static u_int32_t proxy_arp_addr;	/* Addr for proxy arp entry */
static u_int32_t lastlink_status;	/* Last link status info */

static bool use_plink = 0;		/* Use I_LINK by default */
static bool plumbed = 0;		/* Use existing interface */

/* Default is to use /dev/sppp as driver. */
static const char *drvnam = PPP_DEV_NAME;
static bool integrated_driver = 0;
static int extra_dev_fd = -1;		/* keep open until ready */

static option_t solaris_option_list[] = {
	{ "plink", o_bool, &use_plink, "Use I_PLINK instead of I_LINK",
	    OPT_PRIV|1 },
	{ "noplink", o_bool, &use_plink, "Use I_LINK instead of I_PLINK",
	    OPT_PRIV|0 },
	{ "plumbed", o_bool, &plumbed, "Use pre-plumbed interface",
	    OPT_PRIV|1 },
	{ NULL }
};

/*
 * Prototypes for procedures local to this file.
 */
static int translate_speed __P((int));
static int baud_rate_of __P((int));
static int get_ether_addr __P((u_int32_t, struct sockaddr_dl *, int));
static int strioctl __P((int, int, void *, int, int));
static int plumb_ipif __P((int));
static int unplumb_ipif __P((int));
#ifdef INET6
static int plumb_ip6if __P((int));
static int unplumb_ip6if __P((int));
static int open_ip6fd(void);
#endif /* INET6 */
static int open_ipfd(void);
static int sifroute __P((int, u_int32_t, u_int32_t, int, const char *));
static int giflags __P((u_int32_t, bool *));
static void handle_unbind __P((u_int32_t));
static void handle_bind __P((u_int32_t));

/*
 * Wrapper for regular ioctl; masks out EINTR.
 */
static int
myioctl(int fd, int cmd, void *arg)
{
	int retv;

	errno = 0;
	while ((retv = ioctl(fd, cmd, arg)) == -1) {
		if (errno != EINTR)
			break;
	}
	return (retv);
}

/*
 * sys_check_options()
 *
 * Check the options that the user specified.
 */
int
sys_check_options(void)
{
	if (plumbed) {
		if (req_unit == -1)
			req_unit = -2;
		ipmuxid = 0;
		ip6muxid = 0;
	}
	return (1);
}

/*
 * sys_options()
 *
 * Add or remove system-specific options.
 */
void
sys_options(void)
{
	(void) remove_option("ktune");
	(void) remove_option("noktune");
	add_options(solaris_option_list);
}

/*
 * sys_ifname()
 *
 * Set ifname[] to contain name of IP interface for this unit.
 */
void
sys_ifname(void)
{
	const char *cp;

	if ((cp = strrchr(drvnam, '/')) == NULL)
		cp = drvnam;
	else
		cp++;
	(void) slprintf(ifname, sizeof (ifname), "%s%d", cp, ifunit);
}

/*
 * ppp_available()
 *
 * Check whether the system has any ppp interfaces.
 */
int
ppp_available(void)
{
	struct stat buf;
	int fd;
	uint32_t typ;

	if (stat(PPP_DEV_NAME, &buf) >= 0)
		return (1);

	/*
	 * Simple check for system using Apollo POS without SUNWpppd
	 * (/dev/sppp) installed.  This is intentionally not kept open
	 * here, since the user may not have the same privileges (as
	 * determined later).  If Apollo were just shipped with the
	 * full complement of packages, this wouldn't be an issue.
	 */
	if (devnam[0] == '\0' &&
	    (fd = open(devnam, O_RDWR | O_NONBLOCK | O_NOCTTY)) >= 0) {
		if (strioctl(fd, PPPIO_GTYPE, &typ, 0, sizeof (typ)) >= 0 &&
		    typ == PPPTYP_MUX) {
			(void) close(fd);
			return (1);
		}
		(void) close(fd);
	}
	return (0);
}

static int
open_ipfd(void)
{
	ipfd = open(IP_DEV_NAME, O_RDWR | O_NONBLOCK, 0);
	if (ipfd < 0) {
		error("Couldn't open IP device (%s): %m", IP_DEV_NAME);
	}
	return (ipfd);
}

static int
read_ip_interface(int unit)
{
	struct ifreq ifr;
	struct sockaddr_in sin;

	if (ipfd == -1 && open_ipfd() == -1)
		return (0);

	BZERO(&ifr, sizeof (ifr));
	(void) strlcpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));

	/* Get the existing MTU */
	if (myioctl(ipfd, SIOCGIFMTU, &ifr) < 0) {
		warn("Couldn't get IP MTU on %s: %m", ifr.ifr_name);
		return (0);
	}
	dbglog("got MTU %d from interface", ifr.ifr_metric);
	if (ifr.ifr_metric != 0 &&
	    (lcp_allowoptions[unit].mru == 0 ||
	    lcp_allowoptions[unit].mru > ifr.ifr_metric))
		lcp_allowoptions[unit].mru = ifr.ifr_metric;

	/* Get the local IP address */
	if (ipcp_wantoptions[unit].ouraddr == 0 ||
	    ipcp_from_hostname) {
		if (myioctl(ipfd, SIOCGIFADDR, &ifr) < 0) {
			warn("Couldn't get local IP address (%s): %m",
			    ifr.ifr_name);
			return (0);
		}
		BCOPY(&ifr.ifr_addr, &sin, sizeof (struct sockaddr_in));
		ipcp_wantoptions[unit].ouraddr = sin.sin_addr.s_addr;
		dbglog("got local address %I from interface",
		    ipcp_wantoptions[unit].ouraddr);
	}

	/* Get the remote IP address */
	if (ipcp_wantoptions[unit].hisaddr == 0) {
		if (myioctl(ipfd, SIOCGIFDSTADDR, &ifr) < 0) {
			warn("Couldn't get remote IP address (%s): %m",
			    ifr.ifr_name);
			return (0);
		}
		BCOPY(&ifr.ifr_dstaddr, &sin, sizeof (struct sockaddr_in));
		ipcp_wantoptions[unit].hisaddr = sin.sin_addr.s_addr;
		dbglog("got remote address %I from interface",
		    ipcp_wantoptions[unit].hisaddr);
	}
	return (1);
}

#ifdef INET6
static int
open_ip6fd(void)
{
	ip6fd = open(IP6_DEV_NAME, O_RDWR | O_NONBLOCK, 0);
	if (ip6fd < 0) {
		error("Couldn't open IPv6 device (%s): %m", IP6_DEV_NAME);
	}
	return (ip6fd);
}

static int
read_ipv6_interface(int unit)
{
	struct lifreq lifr;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;

	if (ip6fd == -1 && open_ip6fd() == -1)
		return (0);

	BZERO(&lifr, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));

	/* Get the existing MTU */
	if (myioctl(ip6fd, SIOCGLIFMTU, &lifr) < 0) {
		warn("Couldn't get IPv6 MTU on %s: %m", lifr.lifr_name);
		return (0);
	}
	if (lifr.lifr_mtu != 0 &&
	    (lcp_allowoptions[unit].mru == 0 ||
	    lcp_allowoptions[unit].mru > lifr.lifr_mtu))
		lcp_allowoptions[unit].mru = lifr.lifr_mtu;

	/* Get the local IPv6 address */
	if (eui64_iszero(ipv6cp_wantoptions[unit].ourid) ||
	    (ipcp_from_hostname && ipv6cp_wantoptions[unit].use_ip)) {
		if (myioctl(ip6fd, SIOCGLIFADDR, &lifr) < 0) {
			warn("Couldn't get local IPv6 address (%s): %m",
			    lifr.lifr_name);
			return (0);
		}
		eui64_copy(sin6->sin6_addr.s6_addr32[2],
		    ipv6cp_wantoptions[unit].ourid);
	}

	/* Get the remote IP address */
	if (eui64_iszero(ipv6cp_wantoptions[unit].hisid)) {
		if (myioctl(ip6fd, SIOCGLIFDSTADDR, &lifr) < 0) {
			warn("Couldn't get remote IPv6 address (%s): %m",
			    lifr.lifr_name);
			return (0);
		}
		eui64_copy(sin6->sin6_addr.s6_addr32[2],
		    ipv6cp_wantoptions[unit].hisid);
	}
	return (1);
}
#endif /* INET6 */

/*
 * Read information on existing interface(s) and configure ourselves
 * to negotiate appropriately.
 */
static void
read_interface(int unit)
{
	dbglog("reading existing interface data; %sip %sipv6",
	    IPCP_ENABLED ? "" : "!",
#ifdef INET6
	    IPV6CP_ENABLED ? "" :
#endif
	    "!");
	if (IPCP_ENABLED && !read_ip_interface(unit))
		IPCP_ENABLED = 0;
#ifdef INET6
	if (IPV6CP_ENABLED && !read_ipv6_interface(unit))
		IPV6CP_ENABLED = 0;
#endif
}

/*
 * sys_init()
 *
 * System-dependent initialization.
 */
void
sys_init(bool open_as_user)
{
	uint32_t x;
	uint32_t typ;

	if (pppfd != -1) {
		return;
	}

	if (!direct_tty && devnam[0] != '\0') {
		/*
		 * Check for integrated driver-like devices (such as
		 * POS).  These identify themselves as "PPP
		 * multiplexor" drivers.
		 */
		if (open_as_user)
			(void) seteuid(getuid());
		pppfd = open(devnam, O_RDWR | O_NONBLOCK);
		if (open_as_user)
			(void) seteuid(0);
		if (pppfd >= 0 &&
		    strioctl(pppfd, PPPIO_GTYPE, &typ, 0, sizeof (typ)) >= 0 &&
		    typ == PPPTYP_MUX) {
			integrated_driver = 1;
			drvnam = devnam;
		} else if (demand) {
			(void) close(pppfd);
			pppfd = -1;
		} else {
			extra_dev_fd = pppfd;
			pppfd = -1;
		}
	}

	/*
	 * Open Solaris PPP device driver.
	 */
	if (pppfd < 0)
		pppfd = open(drvnam, O_RDWR | O_NONBLOCK);
	if (pppfd < 0) {
		fatal("Can't open %s: %m", drvnam);
	}
	if (kdebugflag & 1) {
		x = PPPDBG_LOG + PPPDBG_DRIVER;
		if (strioctl(pppfd, PPPIO_DEBUG, &x, sizeof (x), 0) < 0) {
			warn("PPPIO_DEBUG ioctl for mux failed: %m");
		}
	}
	/*
	 * Assign a new PPA and get its unit number.
	 */
	x = req_unit;
	if (strioctl(pppfd, PPPIO_NEWPPA, &x, sizeof (x), sizeof (x)) < 0) {
		if (errno == ENXIO && plumbed)
			fatal("No idle interfaces available for use");
		fatal("PPPIO_NEWPPA ioctl failed: %m");
	}
	ifunit = x;
	if (req_unit >= 0 && ifunit != req_unit) {
		if (plumbed)
			fatal("unable to get requested unit %d", req_unit);
		else
			warn("unable to get requested unit %d", req_unit);
	}
	/*
	 * Enable packet time-stamping when idle option is specified. Note
	 * that we need to only do this on the control stream. Subsequent
	 * streams attached to this control stream (ppa) will inherit
	 * the time-stamp bit.
	 */
	if (idle_time_limit > 0) {
		if (strioctl(pppfd, PPPIO_USETIMESTAMP, NULL, 0, 0) < 0) {
			warn("PPPIO_USETIMESTAMP ioctl failed: %m");
		}
	}
	if (plumbed) {
		sys_ifname();
		read_interface(0);
	}
}

int
sys_extra_fd(void)
{
	int fd;

	fd = extra_dev_fd;
	extra_dev_fd = -1;
	return (fd);
}

static int
open_udpfd(void)
{
	int udpfd;

	udpfd = open(UDP_DEV_NAME, O_RDWR | O_NONBLOCK, 0);
	if (udpfd < 0) {
		error("Couldn't open UDP device (%s): %m", UDP_DEV_NAME);
	}
	return (udpfd);
}

/*
 * plumb_ipif()
 *
 * Perform IP interface plumbing.
 */
/*ARGSUSED*/
static int
plumb_ipif(int unit)
{
	int udpfd = -1, tmpfd;
	uint32_t x;
	struct ifreq ifr;

	if (!IPCP_ENABLED || (ifunit == -1) || (pppfd == -1)) {
		return (0);
	}
	if (plumbed)
		return (1);
	if (ipfd == -1 && open_ipfd() == -1)
		return (0);
	if (use_plink && (udpfd = open_udpfd()) == -1)
		return (0);
	tmpfd = open(drvnam, O_RDWR | O_NONBLOCK, 0);
	if (tmpfd < 0) {
		error("Couldn't open PPP device (%s): %m", drvnam);
		if (udpfd != -1)
			(void) close(udpfd);
		return (0);
	}
	if (kdebugflag & 1) {
		x = PPPDBG_LOG + PPPDBG_DRIVER;
		if (strioctl(tmpfd, PPPIO_DEBUG, &x, sizeof (x), 0) < 0) {
			warn("PPPIO_DEBUG ioctl for mux failed: %m");
		}
	}
	if (myioctl(tmpfd, I_PUSH, IP_MOD_NAME) < 0) {
		error("Couldn't push IP module (%s): %m", IP_MOD_NAME);
		goto err_ret;
	}
	/*
	 * Assign ppa according to the unit number returned by ppp device
	 * after plumbing is completed above.  Without setting the ppa, ip
	 * module will return EINVAL upon setting the interface UP
	 * (SIOCSxIFFLAGS).  This is because ip module in 2.8 expects two
	 * DLPI_INFO_REQ to be sent down to the driver (below ip) before
	 * IFF_UP bit can be set. Plumbing the device causes one DLPI_INFO_REQ
	 * to be sent down, and the second DLPI_INFO_REQ is sent upon receiving
	 * IF_UNITSEL (old) or SIOCSLIFNAME (new) ioctls. Such setting of the
	 * ppa is required because the ppp DLPI provider advertises itself as
	 * a DLPI style 2 type, which requires a point of attachment to be
	 * specified. The only way the user can specify a point of attachment
	 * is via SIOCSLIFNAME or IF_UNITSEL.  Such changes in the behavior of
	 * ip module was made to meet new or evolving standards requirements.
	 */
	if (myioctl(tmpfd, IF_UNITSEL, &ifunit) < 0) {
		error("Couldn't set ppa for unit %d: %m", ifunit);
		goto err_ret;
	}
	if (use_plink) {
		ipmuxid = myioctl(udpfd, I_PLINK, (void *)tmpfd);
		if (ipmuxid < 0) {
			error("Can't I_PLINK PPP device to IP: %m");
			goto err_ret;
		}
	} else {
		ipmuxid = myioctl(ipfd, I_LINK, (void *)tmpfd);
		if (ipmuxid < 0) {
			error("Can't I_LINK PPP device to IP: %m");
			goto err_ret;
		}
	}
	BZERO(&ifr, sizeof (ifr));
	(void) strlcpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	ifr.ifr_ip_muxid = ipmuxid;
	ifr.ifr_arp_muxid = -1;
	if (myioctl(ipfd, SIOCSIFMUXID, (caddr_t)&ifr) < 0) {
		error("Can't set mux ID SIOCSIFMUXID on %s: %m", ifname);
		goto err_ret;
	}
	if (udpfd != -1)
		(void) close(udpfd);
	(void) close(tmpfd);
	return (1);
err_ret:
	if (udpfd != -1)
		(void) close(udpfd);
	(void) close(tmpfd);
	return (0);
}

/*
 * unplumb_ipif()
 *
 * Perform IP interface unplumbing.  Possibly called from die(), so there
 * shouldn't be any call to die() or fatal() here.
 */
static int
unplumb_ipif(int unit)
{
	int udpfd = -1, fd = -1;
	int id;
	struct lifreq lifr;

	if (!IPCP_ENABLED || (ifunit == -1)) {
		return (0);
	}
	if (!plumbed && (ipmuxid == -1 || (ipfd == -1 && !use_plink)))
		return (1);
	id = ipmuxid;
	if (!plumbed && use_plink) {
		if ((udpfd = open_udpfd()) == -1)
			return (0);
		/*
		 * Note: must re-get mux ID, since any intervening
		 * ifconfigs will change this.
		 */
		BZERO(&lifr, sizeof (lifr));
		(void) strlcpy(lifr.lifr_name, ifname,
		    sizeof (lifr.lifr_name));
		if (myioctl(ipfd, SIOCGLIFMUXID, (caddr_t)&lifr) < 0) {
			warn("Can't get mux fd: SIOCGLIFMUXID: %m");
		} else {
			id = lifr.lifr_ip_muxid;
			fd = myioctl(udpfd, _I_MUXID2FD, (void *)id);
			if (fd < 0) {
				warn("Can't get mux fd: _I_MUXID2FD: %m");
			}
		}
	}
	/*
	 * Mark down and unlink the ip interface.
	 */
	(void) sifdown(unit);
	if (default_route_gateway != 0) {
		(void) cifdefaultroute(0, default_route_gateway,
		    default_route_gateway);
	}
	if (proxy_arp_addr != 0) {
		(void) cifproxyarp(0, proxy_arp_addr);
	}
	ipmuxid = -1;
	if (plumbed)
		return (1);
	if (use_plink) {
		if (myioctl(udpfd, I_PUNLINK, (void *)id) < 0) {
			error("Can't I_PUNLINK PPP from IP: %m");
			if (fd != -1)
				(void) close(fd);
			(void) close(udpfd);
			return (0);
		}
		if (fd != -1)
			(void) close(fd);
		(void) close(udpfd);
	} else {
		if (myioctl(ipfd, I_UNLINK, (void *)id) < 0) {
			error("Can't I_UNLINK PPP from IP: %m");
			return (0);
		}
	}
	return (1);
}

/*
 * sys_cleanup()
 *
 * Restore any system state we modified before exiting: mark the
 * interface down, delete default route and/or proxy arp entry. This
 * should not call die() because it's called from die().
 */
void
sys_cleanup()
{
	(void) unplumb_ipif(0);
#ifdef INET6
	(void) unplumb_ip6if(0);
#endif /* INET6 */
}

/*
 * get_first_hwaddr()
 *
 * Stores the first hardware interface address found in the system
 * into addr and return 1 upon success, or 0 if none is found.  This
 * is also called from the multilink code.
 */
int
get_first_hwaddr(addr, msize)
	uchar_t *addr;
	int msize;
{
	struct ifconf ifc;
	register struct ifreq *pifreq;
	struct ifreq ifr;
	int fd, num_ifs, i;
	uint_t fl, req_size;
	char *req;
	boolean_t found;

	if (addr == NULL) {
		return (0);
	}
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		error("get_first_hwaddr: error opening IP socket: %m");
		return (0);
	}
	/*
	 * Find out how many interfaces are running
	 */
	if (myioctl(fd, SIOCGIFNUM, (caddr_t)&num_ifs) < 0) {
		num_ifs = MAXIFS;
	}
	req_size = num_ifs * sizeof (struct ifreq);
	req = malloc(req_size);
	if (req == NULL) {
		novm("interface request structure.");
	}
	/*
	 * Get interface configuration info for all interfaces
	 */
	ifc.ifc_len = req_size;
	ifc.ifc_buf = req;
	if (myioctl(fd, SIOCGIFCONF, &ifc) < 0) {
		error("SIOCGIFCONF: %m");
		(void) close(fd);
		free(req);
		return (0);
	}
	/*
	 * And traverse each interface to look specifically for the first
	 * occurence of an Ethernet interface which has been marked up
	 */
	pifreq = ifc.ifc_req;
	found = 0;
	for (i = ifc.ifc_len / sizeof (struct ifreq); i > 0; i--, pifreq++) {

		if (strchr(pifreq->ifr_name, ':') != NULL) {
			continue;
		}
		BZERO(&ifr, sizeof (ifr));
		(void) strncpy(ifr.ifr_name, pifreq->ifr_name,
		    sizeof (ifr.ifr_name));
		if (myioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
			continue;
		}
		fl = ifr.ifr_flags;
		if ((fl & (IFF_UP|IFF_BROADCAST|IFF_POINTOPOINT|IFF_LOOPBACK))
		    != (IFF_UP | IFF_BROADCAST)) {
			continue;
		}
		if (get_if_hwaddr(addr, msize, ifr.ifr_name) <= 0) {
			continue;
		}
		found = 1;
		break;
	}
	free(req);
	(void) close(fd);

	return (found);
}

/*
 * get_if_hwaddr()
 *
 * Get the hardware address for the specified network interface device.
 * Return the length of the MAC address (in bytes) or -1 if error.
 */
int
get_if_hwaddr(uchar_t *addrp, int msize, char *linkname)
{
	dlpi_handle_t dh;
	uchar_t physaddr[DLPI_PHYSADDR_MAX];
	size_t physaddrlen = sizeof (physaddr);
	int retv;

	if ((addrp == NULL) || (linkname == NULL))
		return (-1);

	/*
	 * Open the link and ask for hardware address.
	 */
	if ((retv = dlpi_open(linkname, &dh, 0)) != DLPI_SUCCESS) {
		error("Could not open %s: %s", linkname, dlpi_strerror(retv));
		return (-1);
	}

	retv = dlpi_get_physaddr(dh, DL_CURR_PHYS_ADDR,
	    physaddr, &physaddrlen);
	dlpi_close(dh);
	if (retv != DLPI_SUCCESS) {
		error("Could not get physical address on %s: %s", linkname,
		    dlpi_strerror(retv));
		return (-1);
	}

	/*
	 * Check if we have enough space to copy the address to.
	 */
	if (physaddrlen > msize)
		return (-1);
	(void) memcpy(addrp, physaddr, physaddrlen);
	return (physaddrlen);
}

/*
 * giflags()
 */
static int
giflags(u_int32_t flag, bool *retval)
{
	struct ifreq ifr;
	int fd;

	*retval = 0;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		error("giflags: error opening IP socket: %m");
		return (errno);
	}

	BZERO(&ifr, sizeof (ifr));
	(void) strncpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		(void) close(fd);
		return (errno);
	}

	*retval = ((ifr.ifr_flags & flag) != 0);
	(void) close(fd);
	return (errno);
}

/*
 * sys_close()
 *
 * Clean up in a child process before exec-ing.
 */
void
sys_close()
{
	if (ipfd != -1) {
		(void) close(ipfd);
		ipfd = -1;
	}
#ifdef INET6
	if (ip6fd != -1) {
		(void) close(ip6fd);
		ip6fd = -1;
	}
#endif /* INET6 */
	if (pppfd != -1) {
		(void) close(pppfd);
		pppfd = -1;
	}
}

/*
 * any_compressions()
 *
 * Check if compression is enabled or not.  In the STREAMS implementation of
 * kernel-portion pppd, the comp STREAMS module performs the ACFC, PFC, as
 * well CCP and VJ compressions. However, if the user has explicitly declare
 * to not enable them from the command line, there is no point of having the
 * comp module be pushed on the stream.
 */
static int
any_compressions(void)
{
	if ((!lcp_wantoptions[0].neg_accompression) &&
	    (!lcp_wantoptions[0].neg_pcompression) &&
	    (!ccp_protent.enabled_flag) &&
	    (!ipcp_wantoptions[0].neg_vj)) {
		return (0);
	}
	return (1);
}

/*
 * modpush()
 *
 * Push a module on the stream.
 */
static int
modpush(int fd, const char *modname, const char *text)
{
	if (myioctl(fd, I_PUSH, (void *)modname) < 0) {
		error("Couldn't push %s module: %m", text);
		return (-1);
	}
	if (++tty_npushed == 1 && !already_ppp) {
		if (strioctl(fd, PPPIO_LASTMOD, NULL, 0, 0) < 0) {
			warn("unable to set LASTMOD on %s: %m", text);
		}
	}
	return (0);
}

/*
 * establish_ppp()
 *
 * Turn the serial port into a ppp interface.
 */
int
establish_ppp(fd)
	int fd;
{
	int i;
	uint32_t x;

	if (default_device && !notty) {
		tty_sid = getsid((pid_t)0);
	}

	if (integrated_driver)
		return (pppfd);

	/*
	 * Pop any existing modules off the tty stream
	 */
	for (i = 0; ; ++i) {
		if ((myioctl(fd, I_LOOK, tty_modules[i]) < 0) ||
		    (strcmp(tty_modules[i], "ptem") == 0) ||
		    (myioctl(fd, I_POP, (void *)0) < 0)) {
			break;
		}
	}
	tty_nmodules = i;
	/*
	 * Push the async hdlc module and the compressor module
	 */
	tty_npushed = 0;
	if (!sync_serial && !already_ppp &&
	    modpush(fd, AHDLC_MOD_NAME, "PPP async HDLC") < 0) {
		return (-1);
	}
	/*
	 * There's no need to push comp module if we don't intend
	 * to compress anything
	 */
	if (any_compressions()) {
		(void) modpush(fd, COMP_MOD_NAME, "PPP compression");
	}

	/*
	 * Link the serial port under the PPP multiplexor
	 */
	if ((fdmuxid = myioctl(pppfd, I_LINK, (void *)fd)) < 0) {
		error("Can't link tty to PPP mux: %m");
		return (-1);
	}
	if (tty_npushed == 0 && !already_ppp) {
		if (strioctl(pppfd, PPPIO_LASTMOD, NULL, 0, 0) < 0) {
			warn("unable to set LASTMOD on PPP mux: %m");
		}
	}
	/*
	 * Debug configuration must occur *after* I_LINK.
	 */
	if (kdebugflag & 4) {
		x = PPPDBG_LOG + PPPDBG_AHDLC;
		if (strioctl(pppfd, PPPIO_DEBUG, &x, sizeof (x), 0) < 0) {
			warn("PPPIO_DEBUG ioctl for ahdlc module failed: %m");
		}
	}
	if (any_compressions() && (kdebugflag & 2)) {
		x = PPPDBG_LOG + PPPDBG_COMP;
		if (strioctl(pppfd, PPPIO_DEBUG, &x, sizeof (x), 0) < 0) {
			warn("PPPIO_DEBUG ioctl for comp module failed: %m");
		}
	}
	return (pppfd);
}

/*
 * restore_loop()
 *
 * Reattach the ppp unit to the loopback. This doesn't need to do anything
 * because disestablish_ppp does it
 */
void
restore_loop()
{
}

/*
 * disestablish_ppp()
 *
 * Restore the serial port to normal operation.  It attempts to reconstruct
 * the stream with the previously popped modules.  This shouldn't call die()
 * because it's called from die().  Stream reconstruction is needed in case
 * pppd is used for dial-in on /dev/tty and there's an option error.
 */
void
disestablish_ppp(fd)
	int fd;
{
	int i;

	if (fdmuxid == -1 || integrated_driver) {
		return;
	}
	if (myioctl(pppfd, I_UNLINK, (void *)fdmuxid) < 0) {
		if (!hungup) {
			error("Can't unlink tty from PPP mux: %m");
		}
	}
	fdmuxid = -1;
	if (!hungup) {
		while (tty_npushed > 0 && myioctl(fd, I_POP, (void *)0) >= 0) {
			--tty_npushed;
		}
		for (i = tty_nmodules - 1; i >= 0; --i) {
			if (myioctl(fd, I_PUSH, tty_modules[i]) < 0) {
				error("Couldn't restore tty module %s: %m",
				    tty_modules[i]);
			}
		}
	}
	if (hungup && default_device && tty_sid > 0) {
		/*
		 * If we have received a hangup, we need to send a
		 * SIGHUP to the terminal's controlling process.
		 * The reason is that the original stream head for
		 * the terminal hasn't seen the M_HANGUP message
		 * (it went up through the ppp driver to the stream
		 * head for our fd to /dev/ppp).
		 */
		(void) kill(tty_sid, SIGHUP);
	}
}

/*
 * clean_check()
 *
 * Check whether the link seems not to be 8-bit clean
 */
void
clean_check()
{
	uint32_t x;
	char *s = NULL;

	/*
	 * Skip this is synchronous link is used, since spppasyn won't
	 * be anywhere in the stream below to handle the ioctl.
	 */
	if (sync_serial) {
		return;
	}

	if (strioctl(pppfd, PPPIO_GCLEAN, &x, 0, sizeof (x)) < 0) {
		warn("unable to obtain serial link status: %m");
		return;
	}
	switch (~x) {
	case RCV_B7_0:
		s = "bit 7 set to 1";
		break;
	case RCV_B7_1:
		s = "bit 7 set to 0";
		break;
	case RCV_EVNP:
		s = "odd parity";
		break;
	case RCV_ODDP:
		s = "even parity";
		break;
	}
	if (s != NULL) {
		warn("Serial link is not 8-bit clean:");
		warn("All received characters had %s", s);
	}
}

/*
 * List of valid speeds.
 */
struct speed {
	int speed_int;
	int speed_val;
} speeds [] = {
#ifdef B50
	{ 50, B50 },
#endif
#ifdef B75
	{ 75, B75 },
#endif
#ifdef B110
	{ 110, B110 },
#endif
#ifdef B134
	{ 134, B134 },
#endif
#ifdef B150
	{ 150, B150 },
#endif
#ifdef B200
	{ 200, B200 },
#endif
#ifdef B300
	{ 300, B300 },
#endif
#ifdef B600
	{ 600, B600 },
#endif
#ifdef B1200
	{ 1200, B1200 },
#endif
#ifdef B1800
	{ 1800, B1800 },
#endif
#ifdef B2000
	{ 2000, B2000 },
#endif
#ifdef B2400
	{ 2400, B2400 },
#endif
#ifdef B3600
	{ 3600, B3600 },
#endif
#ifdef B4800
	{ 4800, B4800 },
#endif
#ifdef B7200
	{ 7200, B7200 },
#endif
#ifdef B9600
	{ 9600, B9600 },
#endif
#ifdef B19200
	{ 19200, B19200 },
#endif
#ifdef B38400
	{ 38400, B38400 },
#endif
#ifdef EXTA
	{ 19200, EXTA },
#endif
#ifdef EXTB
	{ 38400, EXTB },
#endif
#ifdef B57600
	{ 57600, B57600 },
#endif
#ifdef B76800
	{ 76800, B76800 },
#endif
#ifdef B115200
	{ 115200, B115200 },
#endif
#ifdef B153600
	{ 153600, B153600 },
#endif
#ifdef B230400
	{ 230400, B230400 },
#endif
#ifdef B307200
	{ 307200, B307200 },
#endif
#ifdef B460800
	{ 460800, B460800 },
#endif
#ifdef B921600
	{ 921600, B921600 },
#endif
	{ 0, 0 }
};

/*
 * translate_speed()
 *
 * Translate from bits/second to a speed_t
 */
static int
translate_speed(int bps)
{
	struct speed *speedp;

	if (bps == 0) {
		return (0);
	}
	for (speedp = speeds; speedp->speed_int; speedp++) {
		if (bps == speedp->speed_int) {
			return (speedp->speed_val);
		}
	}
	set_source(&speed_info);
	option_error("speed %d not supported", bps);
	return (0);
}

/*
 * baud_rate_of()
 *
 * Translate from a speed_t to bits/second
 */
static int
baud_rate_of(int speed)
{
	struct speed *speedp;

	if (speed == 0) {
		return (0);
	}
	for (speedp = speeds; speedp->speed_int; speedp++) {
		if (speed == speedp->speed_val) {
			return (speedp->speed_int);
		}
	}
	return (0);
}

/*
 * set_up_tty()
 *
 * Set up the serial port on `fd' for 8 bits, no parity, at the requested
 * speed, etc.  If `local' is true, set CLOCAL regardless of whether the
 * modem option was specified.
 */
void
set_up_tty(fd, local)
	int fd, local;
{
	int speed;
	struct termios tios;
	struct scc_mode sm;

	if (already_ppp)
		return;

	if (sync_serial) {
		restore_term = 0;
		speed = B0;
		baud_rate = 0;

		if (strioctl(fd, S_IOCGETMODE, &sm, sizeof (sm),
		    sizeof (sm)) < 0) {
			return;
		}

		baud_rate = sm.sm_baudrate;
		dbglog("synchronous speed appears to be %d bps", baud_rate);
	} else {
		if (tcgetattr(fd, &tios) < 0) {
			fatal("tcgetattr: %m");
		}
		if (!restore_term) {
			inittermios = tios;
			if (myioctl(fd, TIOCGWINSZ, &wsinfo) < 0) {
				if (errno == EINVAL) {
					/*
					 * ptem returns EINVAL if all zeroes.
					 * Strange and unfixable code.
					 */
					bzero(&wsinfo, sizeof (wsinfo));
				} else {
					warn("unable to get TTY window "
					    "size: %m");
				}
			}
		}
		tios.c_cflag &= ~(CSIZE | CSTOPB | PARENB | CLOCAL);
		if (crtscts > 0) {
			tios.c_cflag |= CRTSCTS | CRTSXOFF;
		} else if (crtscts < 0) {
			tios.c_cflag &= ~CRTSCTS & ~CRTSXOFF;
		}
		tios.c_cflag |= CS8 | CREAD | HUPCL;
		if (local || !modem) {
			tios.c_cflag |= CLOCAL;
		}
		tios.c_iflag = IGNBRK | IGNPAR;
		tios.c_oflag = 0;
		tios.c_lflag = 0;
		tios.c_cc[VMIN] = 1;
		tios.c_cc[VTIME] = 0;

		if (crtscts == -2) {
			tios.c_iflag |= IXON | IXOFF;
			tios.c_cc[VSTOP] = 0x13;	/* DC3 = XOFF = ^S */
			tios.c_cc[VSTART] = 0x11;	/* DC1 = XON  = ^Q */
		}
		speed = translate_speed(inspeed);
		if (speed) {
			(void) cfsetospeed(&tios, speed);
			(void) cfsetispeed(&tios, speed);
		} else {
			speed = cfgetospeed(&tios);
			/*
			 * We can't proceed if the serial port speed is 0,
			 * since that implies that the serial port is disabled.
			 */
			if (speed == B0) {
				fatal("Baud rate for %s is 0; need explicit "
				    "baud rate", devnam);
			}
		}
		if (tcsetattr(fd, TCSAFLUSH, &tios) < 0) {
			fatal("tcsetattr: %m");
		}
		baud_rate = baud_rate_of(speed);
		dbglog("%s speed set to %d bps",
		    fd == pty_slave ? "pty" : "serial", baud_rate);
		restore_term = 1;
	}
}

/*
 * restore_tty()
 *
 * Restore the terminal to the saved settings.
 */
void
restore_tty(fd)
	int fd;
{
	if (restore_term == 0) {
		return;
	}
	if (!default_device) {
		/*
		 * Turn off echoing, because otherwise we can get into
		 * a loop with the tty and the modem echoing to each
		 * other. We presume we are the sole user of this tty
		 * device, so when we close it, it will revert to its
		 * defaults anyway.
		 */
		inittermios.c_lflag &= ~(ECHO | ECHONL);
	}
	if (tcsetattr(fd, TCSAFLUSH, &inittermios) < 0) {
		if (!hungup && errno != ENXIO) {
			warn("tcsetattr: %m");
		}
	}
	if (wsinfo.ws_row != 0 || wsinfo.ws_col != 0 ||
	    wsinfo.ws_xpixel != 0 || wsinfo.ws_ypixel != 0) {
		if (myioctl(fd, TIOCSWINSZ, &wsinfo) < 0) {
			warn("unable to set TTY window size: %m");
		}
	}
	restore_term = 0;
}

/*
 * setdtr()
 *
 * Control the DTR line on the serial port. This is called from die(), so it
 * shouldn't call die()
 */
void
setdtr(fd, on)
	int fd, on;
{
	int modembits = TIOCM_DTR;
	if (!already_ppp &&
	    myioctl(fd, (on ? TIOCMBIS : TIOCMBIC), &modembits) < 0) {
		warn("unable to set DTR line %s: %m", (on ? "ON" : "OFF"));
	}
}

/*
 * open_loopback()
 *
 * Open the device we use for getting packets in demand mode. Under Solaris 2,
 * we use our existing fd to the ppp driver.
 */
int
open_ppp_loopback()
{
	/*
	 * Plumb the interface.
	 */
	if (IPCP_ENABLED && (plumb_ipif(0) == 0)) {
		fatal("Unable to initialize IP interface for demand dial.");
	}
#ifdef INET6
	if (IPV6CP_ENABLED && (plumb_ip6if(0) == 0)) {
		fatal("Unable to initialize IPv6 interface for demand dial.");
	}
#endif /* INET6 */

	return (pppfd);
}

/*
 * output()
 *
 * Output PPP packet downstream
 */
/*ARGSUSED*/
void
output(unit, p, len)
	int unit;
	uchar_t *p;
	int len;
{
	struct strbuf data;
	struct pollfd pfd;
	int retries, n;
	bool sent_ok = 1;

	data.len = len;
	data.buf = (caddr_t)p;
	retries = 4;

	while (putmsg(pppfd, NULL, &data, 0) < 0) {
		if (errno == EINTR)
			continue;
		if (--retries < 0 ||
		    (errno != EWOULDBLOCK && errno != EAGAIN)) {
			if (errno != ENXIO) {
				error("Couldn't send packet: %m");
				sent_ok = 0;
			}
			break;
		}
		pfd.fd = pppfd;
		pfd.events = POLLOUT;
		do {
			/* wait for up to 0.25 seconds */
			n = poll(&pfd, 1, 250);
		} while ((n == -1) && (errno == EINTR));
	}
	if (debug && sent_ok) {
		dbglog("sent %P", p, len);
	}
}

/*
 * wait_input()
 *
 * Wait until there is data available, for the length of time specified by
 * timo (indefinite if timo is NULL).
 */
void
wait_input(timo)
	struct timeval *timo;
{
	int t;

	t = (timo == NULL ? -1 : (timo->tv_sec * 1000 + timo->tv_usec / 1000));
	if ((poll(pollfds, n_pollfds, t) < 0) && (errno != EINTR)) {
		fatal("poll: %m");
	}
}

/*
 * add_fd()
 *
 * Add an fd to the set that wait_input waits for.
 */
void
add_fd(fd)
	int fd;
{
	int n;

	if (fd < 0) {
		return;
	}
	for (n = 0; n < n_pollfds; ++n) {
		if (pollfds[n].fd == fd) {
			return;
		}
	}
	if (n_pollfds < MAX_POLLFDS) {
		pollfds[n_pollfds].fd = fd;
		pollfds[n_pollfds].events = POLLIN | POLLPRI | POLLHUP;
		++n_pollfds;
	} else {
		fatal("add_fd: too many inputs!");
	}
}

/*
 * remove_fd()
 *
 * Remove an fd from the set that wait_input waits for.
 */
void
remove_fd(fd)
	int fd;
{
	int n;

	for (n = 0; n < n_pollfds; ++n) {
		if (pollfds[n].fd == fd) {
			while (++n < n_pollfds) {
				pollfds[n-1] = pollfds[n];
			}
			--n_pollfds;
			break;
		}
	}
}

static void
dump_packet(uchar_t *buf, int len)
{
	uchar_t *bp;
	int proto, offs;
	const char *cp;
	char sbuf[32];
	uint32_t src, dst;
	struct protoent *pep;
	struct in6_addr addr;
	char fromstr[INET6_ADDRSTRLEN];
	char tostr[INET6_ADDRSTRLEN];

	if (len < 4) {
		notice("strange link activity: %.*B", len, buf);
		return;
	}
	bp = buf;
	if (bp[0] == 0xFF && bp[1] == 0x03)
		bp += 2;
	proto = *bp++;
	if (!(proto & 1))
		proto = (proto << 8) + *bp++;
	len -= bp-buf;
	switch (proto) {
	case PPP_IP:
		if (len < IP_HDRLEN || get_ipv(bp) != 4 || get_iphl(bp) < 5) {
			notice("strange IP packet activity: %16.*B", len, buf);
			return;
		}
		src = get_ipsrc(bp);
		dst = get_ipdst(bp);
		proto = get_ipproto(bp);
		if ((pep = getprotobynumber(proto)) != NULL) {
			cp = pep->p_name;
		} else {
			(void) slprintf(sbuf, sizeof (sbuf), "IP proto %d",
			    proto);
			cp = sbuf;
		}
		if ((get_ipoff(bp) & IP_OFFMASK) != 0) {
			len -= get_iphl(bp) * 4;
			bp += get_iphl(bp) * 4;
			notice("%s fragment from %I->%I: %8.*B", cp, src, dst,
			    len, bp);
		} else {
			if (len > get_iplen(bp))
				len = get_iplen(bp);
			len -= get_iphl(bp) * 4;
			bp += get_iphl(bp) * 4;
			offs = proto == IPPROTO_TCP ? (get_tcpoff(bp)*4) : 8;
			if (proto == IPPROTO_TCP || proto == IPPROTO_UDP)
				notice("%s data:%d %s%I:%d->%I:%d: %8.*B", cp,
				    len-offs,
				    proto == IPPROTO_TCP ?
				    tcp_flag_decode(get_tcpflags(bp)) : "",
				    src, get_sport(bp), dst, get_dport(bp),
				    len-offs, bp+offs);
			else
				notice("%s %d bytes %I->%I: %8.*B", cp, len,
				    src, dst, len, bp);
		}
		return;

	case PPP_IPV6:
		if (len < IP6_HDRLEN) {
			notice("strange IPv6 activity: %16.*B", len, buf);
			return;
		}
		(void) BCOPY(get_ip6src(bp), &addr, sizeof (addr));
		(void) inet_ntop(AF_INET6, &addr, fromstr, sizeof (fromstr));
		(void) BCOPY(get_ip6dst(bp), &addr, sizeof (addr));
		(void) inet_ntop(AF_INET6, &addr, tostr, sizeof (tostr));
		proto = get_ip6nh(bp);
		if (proto == IPPROTO_FRAGMENT) {
			notice("IPv6 fragment from %s->%s", fromstr,
			    tostr);
			return;
		}
		if ((pep = getprotobynumber(proto)) != NULL) {
			cp = pep->p_name;
		} else {
			(void) slprintf(sbuf, sizeof (sbuf), "IPv6 proto %d",
			    proto);
			cp = sbuf;
		}
		len -= IP6_HDRLEN;
		bp += IP6_HDRLEN;
		offs = proto == IPPROTO_TCP ? (get_tcpoff(bp)*4) : 8;
		if (proto == IPPROTO_TCP || proto == IPPROTO_UDP)
			notice("%s data:%d %s[%s]%d->[%s]%d: %8.*B", cp,
			    len-offs,
			    proto == IPPROTO_TCP ?
			    tcp_flag_decode(get_tcpflags(bp)) : "",
			    fromstr, get_sport(bp), tostr, get_dport(bp),
			    len-offs, bp+offs);
		else
			notice("%s %d bytes %s->%s: %8.*B", cp, len,
			    fromstr, tostr, len, bp);
		return;
	}
	if ((cp = protocol_name(proto)) == NULL) {
		(void) slprintf(sbuf, sizeof (sbuf), "0x#X", proto);
		cp = (const char *)sbuf;
	}
	notice("link activity: %s %16.*B", cp, len, bp);
}

/*
 * handle_bind()
 */
static void
handle_bind(u_int32_t reason)
{
	/*
	 * Here we might, in the future, handle DL_BIND_REQ notifications
	 * in order to close and re-open a NCP when certain interface
	 * parameters (addresses, etc.) are changed via external mechanisms
	 * such as through the "ifconfig" program.
	 */
	switch (reason) {
	case PPP_LINKSTAT_IPV4_BOUND:
		break;
#ifdef INET6
	case PPP_LINKSTAT_IPV6_BOUND:
		break;
#endif
	default:
		error("handle_bind: unrecognized reason");
		break;
	}
}

/*
 * handle_unbind()
 */
static void
handle_unbind(u_int32_t reason)
{
	bool iff_up_isset;
	int rc;
	static const char *unplumb_str = "unplumbed";
	static const char *down_str = "downed";

	/*
	 * Since the kernel driver (sppp) notifies this daemon of the
	 * DLPI bind/unbind activities (for the purpose of bringing down
	 * a NCP), we need to explicitly test the "actual" status of
	 * the interface instance for which the notification is destined
	 * from.  This is because /dev/ip performs multiple DLPI attach-
	 * bind-unbind-detach during the early life of the interface,
	 * and when certain interface parameters change.  A DL_UNBIND_REQ
	 * coming down to the sppp driver from /dev/ip (which results in
	 * our receiving of the PPP_LINKSTAT_*_UNBOUND link status message)
	 * is not enough to conclude that the interface has been marked
	 * DOWN (its IFF_UP bit is cleared) or is going away.  Therefore,
	 * we should query /dev/ip directly, upon receiving such *_UNBOUND
	 * notification, to determine whether the interface is DOWN
	 * for real, and only take the necessary actions when IFF_UP
	 * bit for the interface instance is actually cleared.
	 */
	switch (reason) {
	case PPP_LINKSTAT_IPV4_UNBOUND:
		(void) sleep(1);
		rc = giflags(IFF_UP, &iff_up_isset);
		if (!iff_up_isset) {
			if_is_up = 0;
			ipmuxid = -1;
			info("IPv4 interface %s by administrator",
			    ((rc < 0 && rc == ENXIO) ? unplumb_str : down_str));
			fsm_close(&ipcp_fsm[0],
			    "administratively disconnected");
		}
		break;
#ifdef INET6
	case PPP_LINKSTAT_IPV6_UNBOUND:
		(void) sleep(1);
		rc = giflags(IFF_UP, &iff_up_isset);
		if (!iff_up_isset) {
			if6_is_up = 0;
			ip6muxid = -1;
			info("IPv6 interface %s by administrator",
			    ((rc < 0 && rc == ENXIO) ? unplumb_str : down_str));
			fsm_close(&ipv6cp_fsm[0],
			    "administratively disconnected");
		}
		break;
#endif
	default:
		error("handle_unbind: unrecognized reason");
		break;
	}
}

/*
 * read_packet()
 *
 * Get a PPP packet from the serial device.
 */
int
read_packet(buf)
	uchar_t *buf;
{
	struct strbuf ctrl;
	struct strbuf data;
	int flags;
	int len;
	int rc;
	struct ppp_ls *plp;
	uint32_t ctrlbuf[1536 / sizeof (uint32_t)];
	bool flushmode;

	flushmode = 0;
	for (;;) {

		data.maxlen = PPP_MRU + PPP_HDRLEN;
		data.buf = (caddr_t)buf;

		ctrl.maxlen = sizeof (ctrlbuf);
		ctrl.buf = (caddr_t)ctrlbuf;

		flags = 0;
		rc = len = getmsg(pppfd, &ctrl, &data, &flags);
		if (sys_read_packet_hook != NULL) {
			rc = len = (*sys_read_packet_hook)(len, &ctrl, &data,
			    flags);
		}
		if (len < 0) {
			if (errno == EAGAIN || errno == EINTR) {
				return (-1);
			}
			fatal("Error reading packet: %m");
		}
		if ((data.len > 0) && (ctrl.len < 0)) {
			/*
			 * If there's more data on stream head, keep reading
			 * but discard, since the stream is now corrupt.
			 */
			if (rc & MOREDATA) {
				dbglog("More data; input packet garbled");
				flushmode = 1;
				continue;
			}
			if (flushmode)
				return (-1);
			return (data.len);

		} else if (ctrl.len > 0) {
			/*
			 * If there's more ctl on stream head, keep reading,
			 * but start discarding.  We can't deal with fragmented
			 * messages at all.
			 */
			if (rc & MORECTL) {
				dbglog("More control; stream garbled");
				flushmode = 1;
				continue;
			}
			if (flushmode)
				return (-1);
			if (ctrl.len < sizeof (struct ppp_ls)) {
				warn("read_packet: ctl.len %d < "
				    "sizeof ppp_ls %d",
				    ctrl.len, sizeof (struct ppp_ls));
				return (-1);
			}
			plp = (struct ppp_ls *)ctrlbuf;
			if (plp->magic != PPPLSMAGIC) {
				/* Skip, as we don't understand it */
				dbglog("read_packet: unrecognized control %lX",
				    plp->magic);
				return (-1);
			}

			lastlink_status = plp->ppp_message;

			switch (plp->ppp_message) {
			case PPP_LINKSTAT_HANGUP:
				return (0);	/* Hangup */
			/* For use by integrated drivers. */
			case PPP_LINKSTAT_UP:
				lcp_lowerdown(0);
				lcp_lowerup(0);
				return (0);
			case PPP_LINKSTAT_NEEDUP:
				if (data.len > 0)
					dump_packet(buf, data.len);
				return (-1);	/* Demand dial */
			case PPP_LINKSTAT_IPV4_UNBOUND:
				(void) handle_unbind(plp->ppp_message);
				return (-1);
			case PPP_LINKSTAT_IPV4_BOUND:
				(void) handle_bind(plp->ppp_message);
				return (-1);
#ifdef INET6
			case PPP_LINKSTAT_IPV6_UNBOUND:
				(void) handle_unbind(plp->ppp_message);
				return (-1);
			case PPP_LINKSTAT_IPV6_BOUND:
				(void) handle_bind(plp->ppp_message);
				return (-1);
#endif
			default:
				warn("read_packet: unknown link status type!");
				return (-1);
			}
		} else {
			/*
			 * We get here on zero length data or control.
			 */
			return (-1);
		}
	}
}

/*
 * get_loop_output()
 *
 * Get outgoing packets from the ppp device, and detect when we want to bring
 * the real link up. Return value is 1 if we need to bring up the link, or 0
 * otherwise.
 */
int
get_loop_output()
{
	int loops;

	/*
	 * In the Solaris 2.x kernel-level portion implementation, packets
	 * which are received on a demand-dial interface are immediately
	 * discarded, and a notification message is sent up the control
	 * stream to the pppd process.  Therefore, the call to read_packet()
	 * below is merely there to wait for such message.
	 */
	lastlink_status = 0;
	loops = 0;
	while (read_packet(inpacket_buf) > 0) {
		if (++loops > 10)
			break;
	}
	return (lastlink_status == PPP_LINKSTAT_NEEDUP);
}

#ifdef MUX_FRAME
/*ARGSUSED*/
void
ppp_send_muxoption(unit, muxflag)
	int unit;
	u_int32_t muxflag;
{
	uint32_t	cf[2];

	/*
	 * Since muxed frame feature is implemented in the async module,
	 * don't send down the ioctl in the synchronous case.
	 */
	if (!sync_serial && fdmuxid >= 0 && pppfd != -1) {
		cf[0] = muxflag;
		cf[1] = X_MUXMASK;

		if (strioctl(pppfd, PPPIO_MUX, cf, sizeof (cf), 0) < 0) {
			error("Couldn't set mux option: %m");
		}
	}
}

/*ARGSUSED*/
void
ppp_recv_muxoption(unit, muxflag)
	int unit;
	u_int32_t muxflag;
{
	uint32_t	cf[2];

	/*
	 * Since muxed frame feature is implemented in the async module,
	 * don't send down the ioctl in the synchronous case.
	 */
	if (!sync_serial && fdmuxid >= 0 && pppfd != -1) {
		cf[0] = muxflag;
		cf[1] = R_MUXMASK;

		if (strioctl(pppfd, PPPIO_MUX, cf, sizeof (cf), 0) < 0) {
			error("Couldn't set receive mux option: %m");
		}
	}
}
#endif

/*
 * ppp_send_config()
 *
 * Configure the transmit characteristics of the ppp interface.
 */
/*ARGSUSED*/
void
ppp_send_config(unit, mtu, asyncmap, pcomp, accomp)
	int unit;
	int mtu;
	u_int32_t asyncmap;
	int pcomp;
	int accomp;
{
	uint32_t cf[2];

	if (pppfd == -1) {
		error("ppp_send_config called with invalid device handle");
		return;
	}
	cf[0] =	link_mtu = mtu;
	if (strioctl(pppfd, PPPIO_MTU, cf, sizeof (cf[0]), 0) < 0) {
		if (hungup && errno == ENXIO) {
			return;
		}
		error("Couldn't set MTU: %m");
	}
	if (fdmuxid != -1) {
		if (!sync_serial) {
			if (strioctl(pppfd, PPPIO_XACCM, &asyncmap,
			    sizeof (asyncmap), 0) < 0) {
				error("Couldn't set transmit ACCM: %m");
			}
		}
		cf[0] = (pcomp? COMP_PROT: 0) + (accomp? COMP_AC: 0);
		cf[1] = COMP_PROT | COMP_AC;

		if (any_compressions() && strioctl(pppfd, PPPIO_CFLAGS, cf,
		    sizeof (cf), sizeof (cf[0])) < 0) {
			error("Couldn't set prot/AC compression: %m");
		}
	}
}

/*
 * ppp_set_xaccm()
 *
 * Set the extended transmit ACCM for the interface.
 */
/*ARGSUSED*/
void
ppp_set_xaccm(unit, accm)
	int unit;
	ext_accm accm;
{
	if (sync_serial) {
		return;
	}
	if (fdmuxid != -1 && strioctl(pppfd, PPPIO_XACCM, accm,
	    sizeof (ext_accm), 0) < 0) {
		if (!hungup || errno != ENXIO) {
			warn("Couldn't set extended ACCM: %m");
		}
	}
}

/*
 * ppp_recv_config()
 *
 * Configure the receive-side characteristics of the ppp interface.
 */
/*ARGSUSED*/
void
ppp_recv_config(unit, mru, asyncmap, pcomp, accomp)
	int unit;
	int mru;
	u_int32_t asyncmap;
	int pcomp;
	int accomp;
{
	uint32_t cf[2];

	if (pppfd == -1) {
		error("ppp_recv_config called with invalid device handle");
		return;
	}
	cf[0] = mru;
	if (strioctl(pppfd, PPPIO_MRU, cf, sizeof (cf[0]), 0) < 0) {
		if (hungup && errno == ENXIO) {
			return;
		}
		error("Couldn't set MRU: %m");
	}
	if (fdmuxid != -1) {
		if (!sync_serial) {
			if (strioctl(pppfd, PPPIO_RACCM, &asyncmap,
			    sizeof (asyncmap), 0) < 0) {
				error("Couldn't set receive ACCM: %m");
			}
		}
		cf[0] = (pcomp ? DECOMP_PROT : 0) + (accomp ? DECOMP_AC : 0);
		cf[1] = DECOMP_PROT | DECOMP_AC;

		if (any_compressions() && strioctl(pppfd, PPPIO_CFLAGS, cf,
		    sizeof (cf), sizeof (cf[0])) < 0) {
			error("Couldn't set prot/AC decompression: %m");
		}
	}
}

#ifdef NEGOTIATE_FCS
/*
 * ppp_send_fcs()
 *
 * Configure the sender-side FCS.
 */
/*ARGSUSED*/
void
ppp_send_fcs(unit, fcstype)
	int unit, fcstype;
{
	uint32_t fcs;

	if (sync_serial) {
		return;
	}

	if (fcstype & FCSALT_32) {
		fcs = PPPFCS_32;
	} else if (fcstype & FCSALT_NULL) {
		fcs = PPPFCS_NONE;
	} else {
		fcs = PPPFCS_16;
	}
	if (strioctl(pppfd, PPPIO_XFCS, &fcs, sizeof (fcs), 0) < 0) {
		warn("Couldn't set transmit FCS: %m");
	}
}

/*
 * ppp_recv_fcs()
 *
 * Configure the receiver-side FCS.
 */
/*ARGSUSED*/
void
ppp_recv_fcs(unit, fcstype)
	int unit, fcstype;
{
	uint32_t fcs;

	if (sync_serial) {
		return;
	}

	if (fcstype & FCSALT_32) {
		fcs = PPPFCS_32;
	} else if (fcstype & FCSALT_NULL) {
		fcs = PPPFCS_NONE;
	} else {
		fcs = PPPFCS_16;
	}
	if (strioctl(pppfd, PPPIO_RFCS, &fcs, sizeof (fcs), 0) < 0) {
		warn("Couldn't set receive FCS: %m");
	}
}
#endif

/*
 * ccp_test()
 *
 * Ask kernel whether a given compression method is acceptable for use.
 */
/*ARGSUSED*/
int
ccp_test(unit, opt_ptr, opt_len, for_transmit)
	int unit;
	uchar_t *opt_ptr;
	int opt_len;
	int for_transmit;
{
	if (strioctl(pppfd, (for_transmit ? PPPIO_XCOMP : PPPIO_RCOMP),
	    opt_ptr, opt_len, 0) >= 0) {
		return (1);
	}
	warn("Error in %s ioctl: %m",
	    (for_transmit ? "PPPIO_XCOMP" : "PPPIO_RCOMP"));
	return ((errno == ENOSR) ? 0 : -1);
}

#ifdef COMP_TUNE
/*
 * ccp_tune()
 *
 * Tune compression effort level.
 */
/*ARGSUSED*/
void
ccp_tune(unit, effort)
	int unit, effort;
{
	uint32_t x;

	x = effort;
	if (strioctl(pppfd, PPPIO_COMPLEV, &x, sizeof (x), 0) < 0) {
		warn("unable to set compression effort level: %m");
	}
}
#endif

/*
 * ccp_flags_set()
 *
 * Inform kernel about the current state of CCP.
 */
/*ARGSUSED*/
void
ccp_flags_set(unit, isopen, isup)
	int unit, isopen, isup;
{
	uint32_t cf[2];

	cf[0] = (isopen ? CCP_ISOPEN : 0) + (isup ? CCP_ISUP : 0);
	cf[1] = CCP_ISOPEN | CCP_ISUP | CCP_ERROR | CCP_FATALERROR;

	if (strioctl(pppfd, PPPIO_CFLAGS, cf, sizeof (cf), sizeof (cf[0]))
	    < 0) {
		if (!hungup || errno != ENXIO) {
			error("Couldn't set kernel CCP state: %m");
		}
	}
}

/*
 * get_idle_time()
 *
 * Return how long the link has been idle.
 */
/*ARGSUSED*/
int
get_idle_time(u, pids)
	int u;
	struct ppp_idle *pids;
{
	int rc;

	rc = strioctl(pppfd, PPPIO_GIDLE, pids, 0, sizeof (struct ppp_idle));
	if (rc < 0) {
		warn("unable to obtain idle time: %m");
	}
	return ((rc == 0) ? 1 : 0);
}

/*
 * get_ppp_stats()
 *
 * Return statistics for the link.
 */
/*ARGSUSED*/
int
get_ppp_stats(u, stats)
	int u;
	struct pppd_stats *stats;
{
	struct ppp_stats64 s64;
	struct ppp_stats s;

	/* Try first to get these from the 64-bit interface */
	if (strioctl(pppfd, PPPIO_GETSTAT64, &s64, 0, sizeof (s64)) >= 0) {
		stats->bytes_in = s64.p.ppp_ibytes;
		stats->bytes_out = s64.p.ppp_obytes;
		stats->pkts_in = s64.p.ppp_ipackets;
		stats->pkts_out = s64.p.ppp_opackets;
		return (1);
	}

	if (strioctl(pppfd, PPPIO_GETSTAT, &s, 0, sizeof (s)) < 0) {
		error("Couldn't get link statistics: %m");
		return (0);
	}
	stats->bytes_in = s.p.ppp_ibytes;
	stats->bytes_out = s.p.ppp_obytes;
	stats->pkts_in = s.p.ppp_ipackets;
	stats->pkts_out = s.p.ppp_opackets;
	return (1);
}

#if defined(FILTER_PACKETS)
/*
 * set_filters()
 *
 * Transfer the pass and active filters to the kernel.
 */
int
set_filters(pass, active)
	struct bpf_program *pass;
	struct bpf_program *active;
{
	int ret = 1;

	if (pass->bf_len > 0) {
		if (strioctl(pppfd, PPPIO_PASSFILT, pass,
		    sizeof (struct bpf_program), 0) < 0) {
			error("Couldn't set pass-filter in kernel: %m");
			ret = 0;
		}
	}
	if (active->bf_len > 0) {
		if (strioctl(pppfd, PPPIO_ACTIVEFILT, active,
		    sizeof (struct bpf_program), 0) < 0) {
			error("Couldn't set active-filter in kernel: %m");
			ret = 0;
		}
	}
	return (ret);
}
#endif /* FILTER_PACKETS */

/*
 * ccp_fatal_error()
 *
 * Returns 1 if decompression was disabled as a result of an error detected
 * after decompression of a packet, 0 otherwise.  This is necessary because
 * of patent nonsense.
 */
/*ARGSUSED*/
int
ccp_fatal_error(unit)
	int unit;
{
	uint32_t cf[2];

	cf[0] = cf[1] = 0;
	if (strioctl(pppfd, PPPIO_CFLAGS, cf, sizeof (cf), sizeof (cf[0]))
	    < 0) {
		if (errno != ENXIO && errno != EINVAL) {
			error("Couldn't get compression flags: %m");
		}
		return (0);
	}
	return (cf[0] & CCP_FATALERROR);
}

/*
 * sifvjcomp()
 *
 * Config TCP header compression.
 */
/*ARGSUSED*/
int
sifvjcomp(u, vjcomp, xcidcomp, xmaxcid)
	int u, vjcomp, xcidcomp, xmaxcid;
{
	uint32_t cf[2];
	uchar_t maxcid[2];

	/*
	 * Since VJ compression code is in the comp module, there's no
	 * point of sending down any ioctls pertaining to VJ compression
	 * when the module isn't pushed on the stream.
	 */
	if (!any_compressions()) {
		return (1);
	}

	if (vjcomp) {
		maxcid[0] = xcidcomp;
		maxcid[1] = 15;		/* XXX should be rmaxcid */

		if (strioctl(pppfd, PPPIO_VJINIT, maxcid,
		    sizeof (maxcid), 0) < 0) {
			error("Couldn't initialize VJ compression: %m");
			return (0);
		}
	}

	cf[0] = (vjcomp ? COMP_VJC + DECOMP_VJC : 0)	/* XXX this is wrong */
		+ (xcidcomp? COMP_VJCCID + DECOMP_VJCCID: 0);

	cf[1] = COMP_VJC + DECOMP_VJC + COMP_VJCCID + DECOMP_VJCCID;

	if (strioctl(pppfd, PPPIO_CFLAGS, cf, sizeof (cf), sizeof (cf[0]))
	    < 0) {
		if (vjcomp) {
			error("Couldn't enable VJ compression: %m");
		} else {
			error("Couldn't disable VJ compression: %m");
		}
		return (0);
	}
	return (1);
}

/*
 * siflags()
 *
 * Set or clear the IP interface flags.
 */
int
siflags(f, set)
	u_int32_t f;
	int set;
{
	struct ifreq ifr;

	if (!IPCP_ENABLED || (ipmuxid == -1)) {
		return (0);
	}
	if (ipfd == -1 && open_ipfd() == -1)
		return (0);
	BZERO(&ifr, sizeof (ifr));
	(void) strlcpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	if (myioctl(ipfd, SIOCGIFFLAGS, &ifr) < 0) {
		error("Couldn't get IP interface flags: %m");
		return (0);
	}
	if (set) {
		ifr.ifr_flags |= f;
	} else {
		ifr.ifr_flags &= ~f;
	}
	if (myioctl(ipfd, SIOCSIFFLAGS, &ifr) < 0) {
		error("Couldn't set IP interface flags: %m");
		return (0);
	}
	return (1);
}

/*
 * sifup()
 *
 * Config the interface up and enable IP packets to pass.
 */
/*ARGSUSED*/
int
sifup(u)
	int u;
{
	if (if_is_up) {
		return (1);
	} else if (!IPCP_ENABLED) {
		warn("sifup called when IPCP is disabled");
		return (0);
	} else if (ipmuxid == -1) {
		warn("sifup called in wrong state");
		return (0);
	} else if (!siflags(IFF_UP, 1)) {
		error("Unable to mark the IP interface UP");
		return (0);
	}
	if_is_up = 1;
	return (1);
}

/*
 * sifdown()
 *
 * Config the interface down and disable IP.  Possibly called from die(),
 * so there shouldn't be any call to die() here.
 */
/*ARGSUSED*/
int
sifdown(u)
	int u;
{
	if (!IPCP_ENABLED) {
		warn("sifdown called when IPCP is disabled");
		return (0);
	} else if (!if_is_up || (ipmuxid == -1)) {
		return (1);
	} else if (!siflags(IFF_UP, 0)) {
		error("Unable to mark the IP interface DOWN");
		return (0);
	}
	if_is_up = 0;
	return (1);
}

/*
 * sifnpmode()
 *
 * Set the mode for handling packets for a given NP.  Not worried
 * about performance here since this is done only rarely.
 */
/*ARGSUSED*/
int
sifnpmode(u, proto, mode)
	int u;
	int proto;
	enum NPmode mode;
{
	uint32_t npi[2];
	const char *cp;
	static const struct npi_entry {
		enum NPmode ne_value;
		const char *ne_name;
	} npi_list[] = {
		{ NPMODE_PASS, "pass" },
		{ NPMODE_DROP, "drop" },
		{ NPMODE_ERROR, "error" },
		{ NPMODE_QUEUE, "queue" },
	};
	int i;
	char pname[32], mname[32];

	npi[0] = proto;
	npi[1] = (uint32_t)mode;

	cp = protocol_name(proto);
	if (cp == NULL)
		(void) slprintf(pname, sizeof (pname), "NP %04X", proto);
	else
		(void) strlcpy(pname, cp, sizeof (pname));
	for (i = 0; i < Dim(npi_list); i++)
		if (npi_list[i].ne_value == mode)
			break;
	if (i >= Dim(npi_list))
		(void) slprintf(mname, sizeof (mname), "mode %d", (int)mode);
	else
		(void) strlcpy(mname, npi_list[i].ne_name, sizeof (mname));

	if ((proto == PPP_IP && !if_is_up) ||
	    (proto == PPP_IPV6 && !if6_is_up)) {
		dbglog("ignoring request to set %s to %s", pname, mname);
		return (1);
	}
	if (strioctl(pppfd, PPPIO_NPMODE, npi, sizeof (npi), 0) < 0) {
		error("unable to set %s to %s: %m", pname, mname);
		return (0);
	}
	return (1);
}

/*
 * sifmtu()
 *
 * Config the interface IP MTU.
 */
int
sifmtu(mtu)
	int mtu;
{
	struct ifreq ifr;

	if (!IPCP_ENABLED || (ipmuxid == -1)) {
		return (0);
	}
	if (ipfd == -1 && open_ipfd() == -1)
		return (0);
	BZERO(&ifr, sizeof (ifr));
	(void) strlcpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	ifr.ifr_metric = mtu;
	if (myioctl(ipfd, SIOCSIFMTU, &ifr) < 0) {
		error("Couldn't set IP MTU on %s to %d: %m", ifr.ifr_name,
		    mtu);
		return (0);
	}
	return (1);
}

/*
 * sifaddr()
 *
 * Config the interface IP addresses and netmask.
 */
/*ARGSUSED*/
int
sifaddr(u, o, h, m)
	int u;
	u_int32_t o;
	u_int32_t h;
	u_int32_t m;
{
	struct ifreq ifr;
	struct sockaddr_in sin;

	if (!IPCP_ENABLED || (ipmuxid == -1 && plumb_ipif(u) == 0)) {
		return (0);
	}
	if (ipfd == -1 && open_ipfd() == -1)
		return (0);
	/*
	 * Set the IP interface MTU.
	 */
	if (!sifmtu(link_mtu)) {
		return (0);
	}
	/*
	 * Set the IP interface local point-to-point address.
	 */
	BZERO(&sin, sizeof (sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = o;

	BZERO(&ifr, sizeof (ifr));
	(void) strlcpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	ifr.ifr_addr = *(struct sockaddr *)&sin;
	if (myioctl(ipfd, SIOCSIFADDR, &ifr) < 0) {
		error("Couldn't set local IP address (%s): %m", ifr.ifr_name);
		return (0);
	}
	/*
	 * Set the IP interface remote point-to-point address.
	 */
	sin.sin_addr.s_addr = h;

	ifr.ifr_dstaddr = *(struct sockaddr *)&sin;
	if (myioctl(ipfd, SIOCSIFDSTADDR, &ifr) < 0) {
		error("Couldn't set remote IP address (%s): %m", ifr.ifr_name);
		return (0);
	}
	remote_addr = h;
	return (1);
}

/*
 * cifaddr()
 *
 * Clear the interface IP addresses.
 */
/*ARGSUSED*/
int
cifaddr(u, o, h)
	int u;
	u_int32_t o;
	u_int32_t h;
{
	if (!IPCP_ENABLED) {
		return (0);
	}
	/*
	 * Most of the work is done in sifdown().
	 */
	remote_addr = 0;
	return (1);
}

/*
 * sifroute()
 *
 * Add or delete a route.
 */
/*ARGSUSED*/
static int
sifroute(int u, u_int32_t l, u_int32_t g, int add, const char *str)
{
	struct sockaddr_in sin_dst, sin_gtw;
	struct rtentry rt;

	if (!IPCP_ENABLED || (ipmuxid == -1)) {
		error("Can't %s route: IP is not enabled", str);
		return (0);
	}
	if (ipfd == -1 && open_ipfd() == -1)
		return (0);

	BZERO(&sin_dst, sizeof (sin_dst));
	sin_dst.sin_family = AF_INET;
	sin_dst.sin_addr.s_addr = l;

	BZERO(&sin_gtw, sizeof (sin_gtw));
	sin_gtw.sin_family = AF_INET;
	sin_gtw.sin_addr.s_addr = g;

	BZERO(&rt, sizeof (rt));
	rt.rt_dst = *(struct sockaddr *)&sin_dst;
	rt.rt_gateway = *(struct sockaddr *)&sin_gtw;
	rt.rt_flags = (RTF_GATEWAY|RTF_STATIC);

	if (myioctl(ipfd, (add ? SIOCADDRT : SIOCDELRT), &rt) < 0) {
		error("Can't %s route: %m", str);
		return (0);
	}
	return (1);
}

/*
 * sifdefaultroute()
 *
 * Assign a default route through the address given.
 */
/*ARGSUSED*/
int
sifdefaultroute(u, l, g)
	int u;
	u_int32_t l;
	u_int32_t g;
{
	if (!sifroute(u, 0, g, 1, "add default")) {
		return (0);
	}
	default_route_gateway = g;
	return (1);
}

/*
 * cifdefaultroute()
 *
 * Delete a default route through the address given.
 */
/*ARGSUSED*/
int
cifdefaultroute(u, l, g)
	int u;
	u_int32_t l;
	u_int32_t g;
{
	if (!sifroute(u, 0, g, 0, "delete default")) {
		return (0);
	}
	default_route_gateway = 0;
	return (1);
}

/*
 * sifproxyarp()
 *
 * Make a proxy ARP entry for the peer.
 */
/*ARGSUSED*/
int
sifproxyarp(unit, hisaddr, quietflag)
	int unit;
	u_int32_t hisaddr;
	int quietflag;
{
	struct sockaddr_in sin;
	struct xarpreq arpreq;
	const uchar_t *cp;
	char *str = NULL;

	if (!IPCP_ENABLED || (ipmuxid == -1)) {
		return (0);
	}
	if (ipfd == -1 && open_ipfd() == -1)
		return (0);

	BZERO(&sin, sizeof (sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = hisaddr;

	BZERO(&arpreq, sizeof (arpreq));
	if (!get_ether_addr(hisaddr, &arpreq.xarp_ha, quietflag)) {
		return (0);
	}
	BCOPY(&sin, &arpreq.xarp_pa, sizeof (sin));
	arpreq.xarp_flags = ATF_PERM | ATF_PUBL;
	arpreq.xarp_ha.sdl_family = AF_LINK;

	if (myioctl(ipfd, SIOCSXARP, (caddr_t)&arpreq) < 0) {
		if (!quietflag)
			error("Couldn't set proxy ARP entry: %m");
		return (0);
	}
	cp = (const uchar_t *)LLADDR(&arpreq.xarp_ha);
	str = _link_ntoa(cp, str, arpreq.xarp_ha.sdl_alen, IFT_OTHER);
	if (str != NULL) {
		dbglog("established proxy ARP for %I using %s", hisaddr,
		    str);
		free(str);
	}
	proxy_arp_addr = hisaddr;
	return (1);
}

/*
 * cifproxyarp()
 *
 * Delete the proxy ARP entry for the peer.
 */
/*ARGSUSED*/
int
cifproxyarp(unit, hisaddr)
	int unit;
	u_int32_t hisaddr;
{
	struct sockaddr_in sin;
	struct xarpreq arpreq;

	if (!IPCP_ENABLED || (ipmuxid == -1)) {
		return (0);
	}
	if (ipfd == -1 && open_ipfd() == -1)
		return (0);

	BZERO(&sin, sizeof (sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = hisaddr;

	BZERO(&arpreq, sizeof (arpreq));
	BCOPY(&sin, &arpreq.xarp_pa, sizeof (sin));
	arpreq.xarp_ha.sdl_family = AF_LINK;

	if (myioctl(ipfd, SIOCDXARP, (caddr_t)&arpreq) < 0) {
		error("Couldn't delete proxy ARP entry: %m");
		return (0);
	}
	proxy_arp_addr = 0;
	return (1);
}

/*
 * get_ether_addr()
 *
 * Get the hardware address of an interface on the the same subnet as
 * ipaddr.  This routine uses old-style interfaces for intentional
 * backward compatibility -- SIOCGLIF* isn't in older Solaris
 * releases.
 */
static int
get_ether_addr(u_int32_t ipaddr, struct sockaddr_dl *hwaddr, int quietflag)
{
	struct ifreq *ifr, *ifend, ifreq;
	int nif, s, retv;
	struct ifconf ifc;
	u_int32_t ina, mask;
	struct xarpreq req;
	struct sockaddr_in sin;

	if (ipfd == -1 && open_ipfd() == -1)
		return (0);

	/*
	 * Scan through the system's network interfaces.
	 */
	if (myioctl(ipfd, SIOCGIFNUM, &nif) < 0) {
		nif = MAXIFS;
	}
	if (nif <= 0)
		return (0);
	ifc.ifc_len = nif * sizeof (struct ifreq);
	ifc.ifc_buf = (caddr_t)malloc(ifc.ifc_len);
	if (ifc.ifc_buf == NULL) {
		return (0);
	}
	if (myioctl(ipfd, SIOCGIFCONF, &ifc) < 0) {
		error("Couldn't get system interface list: %m");
		free(ifc.ifc_buf);
		return (0);
	}
	/* LINTED */
	ifend = (struct ifreq *)(ifc.ifc_buf + ifc.ifc_len);
	for (ifr = ifc.ifc_req; ifr < ifend; ++ifr) {
		if (ifr->ifr_addr.sa_family != AF_INET) {
			continue;
		}
		/*
		 * Check that the interface is up, and not
		 * point-to-point or loopback.
		 */
		(void) strlcpy(ifreq.ifr_name, ifr->ifr_name,
		    sizeof (ifreq.ifr_name));
		if (myioctl(ipfd, SIOCGIFFLAGS, &ifreq) < 0) {
			continue;
		}
		if ((ifreq.ifr_flags & (IFF_UP|IFF_BROADCAST|IFF_POINTOPOINT|
		    IFF_LOOPBACK|IFF_NOARP)) != (IFF_UP|IFF_BROADCAST)) {
			continue;
		}
		/*
		 * Get its netmask and check that it's on the right subnet.
		 */
		if (myioctl(ipfd, SIOCGIFNETMASK, &ifreq) < 0) {
			continue;
		}
		(void) memcpy(&sin, &ifr->ifr_addr, sizeof (sin));
		ina = sin.sin_addr.s_addr;
		(void) memcpy(&sin, &ifreq.ifr_addr, sizeof (sin));
		mask = sin.sin_addr.s_addr;
		if ((ipaddr & mask) == (ina & mask)) {
			break;
		}
	}
	if (ifr >= ifend) {
		if (!quietflag)
			warn("No suitable interface found for proxy ARP of %I",
			    ipaddr);
		free(ifc.ifc_buf);
		return (0);
	}
	info("found interface %s for proxy ARP of %I", ifr->ifr_name, ipaddr);

	/*
	 * New way - get the address by doing an arp request.
	 */
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		error("get_ether_addr: error opening IP socket: %m");
		free(ifc.ifc_buf);
		return (0);
	}
	BZERO(&sin, sizeof (sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ina;

	BZERO(&req, sizeof (req));
	BCOPY(&sin, &req.xarp_pa, sizeof (sin));
	req.xarp_ha.sdl_family = AF_LINK;

	if (myioctl(s, SIOCGXARP, &req) < 0) {
		error("Couldn't get ARP entry for %I: %m", ina);
		retv = 0;
	} else {
		(void) memcpy(hwaddr, &req.xarp_ha,
		    sizeof (struct sockaddr_dl));
		retv = 1;
	}
	(void) close(s);
	free(ifc.ifc_buf);
	return (retv);
}

/*
 * GetMask()
 *
 * Return mask (bogus, but needed for compatibility with other platforms).
 */
/*ARGSUSED*/
u_int32_t
GetMask(addr)
	u_int32_t addr;
{
	return (0xffffffffUL);
}

/*
 * logwtmp()
 *
 * Write an accounting record to the /var/adm/wtmp file.
 */
/*ARGSUSED*/
void
logwtmp(line, name, host)
	const char *line;
	const char *name;
	const char *host;
{
	static struct utmpx utmpx;

	if (name[0] != '\0') {
		/*
		 * logging in
		 */
		(void) strncpy(utmpx.ut_user, name, sizeof (utmpx.ut_user));
		(void) strncpy(utmpx.ut_id, ifname, sizeof (utmpx.ut_id));
		(void) strncpy(utmpx.ut_line, line, sizeof (utmpx.ut_line));

		utmpx.ut_pid = getpid();
		utmpx.ut_type = USER_PROCESS;
	} else {
		utmpx.ut_type = DEAD_PROCESS;
	}
	(void) gettimeofday(&utmpx.ut_tv, NULL);
	updwtmpx("/var/adm/wtmpx", &utmpx);
}

/*
 * get_host_seed()
 *
 * Return the serial number of this machine.
 */
int
get_host_seed()
{
	char buf[32];

	if (sysinfo(SI_HW_SERIAL, buf, sizeof (buf)) < 0) {
		error("sysinfo: %m");
		return (0);
	}
	return ((int)strtoul(buf, NULL, 16));
}

/*
 * strioctl()
 *
 * Wrapper for STREAMS I_STR ioctl.  Masks out EINTR from caller.
 */
static int
strioctl(int fd, int cmd, void *ptr, int ilen, int olen)
{
	struct strioctl	str;

	str.ic_cmd = cmd;
	str.ic_timout = PPPSTRTIMOUT;
	str.ic_len = ilen;
	str.ic_dp = ptr;

	if (myioctl(fd, I_STR, &str) == -1) {
		return (-1);
	}
	if (str.ic_len != olen) {
		dbglog("strioctl: expected %d bytes, got %d for cmd %x\n",
		    olen, str.ic_len, cmd);
	}
	return (0);
}

/*
 * have_route_to()
 *
 * Determine if the system has a route to the specified IP address.
 * Returns 0 if not, 1 if so, -1 if we can't tell. `addr' is in network
 * byte order. For demand mode to work properly, we have to ignore routes
 * through our own interface. XXX Would be nice to use routing socket.
 */
int
have_route_to(addr)
	u_int32_t addr;
{
	int r, flags, i;
	struct {
		struct T_optmgmt_req req;
		struct opthdr hdr;
	} req;
	union {
		struct T_optmgmt_ack ack;
		unsigned char space[64];
	} ack;
	struct opthdr *rh;
	struct strbuf cbuf, dbuf;
	int nroutes;
	mib2_ipRouteEntry_t routes[8];
	mib2_ipRouteEntry_t *rp;

	if (ipfd == -1 && open_ipfd() == -1)
		return (0);

	req.req.PRIM_type = T_OPTMGMT_REQ;
	req.req.OPT_offset = (caddr_t)&req.hdr - (caddr_t)&req;
	req.req.OPT_length = sizeof (req.hdr);
#ifdef T_CURRENT
	req.req.MGMT_flags = T_CURRENT;
#else
	/* Old-style */
	req.req.MGMT_flags = T_CHECK;
#endif

	req.hdr.level = MIB2_IP;
	req.hdr.name = 0;
	req.hdr.len = 0;

	cbuf.buf = (caddr_t)&req;
	cbuf.len = sizeof (req);

	if (putmsg(ipfd, &cbuf, NULL, 0) == -1) {
		warn("have_route_to: putmsg: %m");
		return (-1);
	}

	for (;;) {
		cbuf.buf = (caddr_t)&ack;
		cbuf.maxlen = sizeof (ack);
		dbuf.buf = (caddr_t)routes;
		dbuf.maxlen = sizeof (routes);
		flags = 0;
		r = getmsg(ipfd, &cbuf, &dbuf, &flags);
		if (r == -1) {
			warn("have_route_to: getmsg: %m");
			return (-1);
		}

		if (cbuf.len < sizeof (struct T_optmgmt_ack) ||
		    ack.ack.PRIM_type != T_OPTMGMT_ACK ||
		    ack.ack.MGMT_flags != T_SUCCESS ||
		    ack.ack.OPT_length < sizeof (struct opthdr)) {
			dbglog("have_route_to: bad message len=%d prim=%d",
			    cbuf.len, ack.ack.PRIM_type);
			return (-1);
		}
		/* LINTED */
		rh = (struct opthdr *)((caddr_t)&ack + ack.ack.OPT_offset);
		if (rh->level == 0 && rh->name == 0) {
			break;
		}
		if (rh->level != MIB2_IP || rh->name != MIB2_IP_21) {
			while (r == MOREDATA) {
				r = getmsg(ipfd, NULL, &dbuf, &flags);
			}
			continue;
		}

		/*
		 * Note that we have to skip routes to our own
		 * interface in order for demand dial to work.
		 *
		 * XXX awful hack here.  We don't know our own
		 * ifIndex, so we can't check ipRouteIfIndex here.
		 * Instead, we check the next hop address.
		 */
		for (;;) {
			nroutes = dbuf.len / sizeof (mib2_ipRouteEntry_t);
			for (rp = routes, i = 0; i < nroutes; ++i, ++rp) {
				if (rp->ipRouteNextHop != remote_addr &&
				    ((addr ^ rp->ipRouteDest) &
					rp->ipRouteMask) == 0) {
					dbglog("have route to %I/%I via %I",
					    rp->ipRouteDest,
					    rp->ipRouteMask,
					    rp->ipRouteNextHop);
					return (1);
				}
			}
			if (r == 0) {
				break;
			}
			r = getmsg(ipfd, NULL, &dbuf, &flags);
		}
	}
	return (0);
}

/*
 * get_pty()
 *
 * Get a pty master/slave pair and chown the slave side to the uid given.
 * Assumes slave_name points to MAXPATHLEN bytes of space.
 */
int
get_pty(master_fdp, slave_fdp, slave_name, uid)
	int *master_fdp;
	int *slave_fdp;
	char *slave_name;
	int uid;
{
	int mfd;
	int sfd;
	char *pty_name;

	mfd = open("/dev/ptmx", O_NOCTTY | O_RDWR);
	if (mfd < 0) {
		error("Couldn't open pty master: %m");
		return (0);
	}
	pty_name = ptsname(mfd);
	if (pty_name == NULL) {
		dbglog("Didn't get pty slave name on first try; sleeping.");
		/* In case "grow" operation is in progress; try again. */
		(void) sleep(1);
		pty_name = ptsname(mfd);
	}
	if (pty_name == NULL) {
		error("Couldn't get name of pty slave");
		(void) close(mfd);
		return (0);
	}
	if (chown(pty_name, uid, -1) < 0) {
		warn("Couldn't change owner of pty slave: %m");
	}
	if (chmod(pty_name, S_IRUSR | S_IWUSR) < 0) {
		warn("Couldn't change permissions on pty slave: %m");
	}
	if (unlockpt(mfd) < 0) {
		warn("Couldn't unlock pty slave: %m");
	}
	sfd = open(pty_name, O_RDWR);
	if (sfd < 0) {
		error("Couldn't open pty slave %s: %m", pty_name);
		(void) close(mfd);
		return (0);
	}
	if (myioctl(sfd, I_PUSH, "ptem") < 0) {
		warn("Couldn't push ptem module on pty slave: %m");
	}
	dbglog("Using %s; master fd %d, slave fd %d", pty_name, mfd, sfd);

	(void) strlcpy(slave_name, pty_name, MAXPATHLEN);

	*master_fdp = mfd;
	*slave_fdp = sfd;

	return (1);
}

#ifdef INET6
static int
open_udp6fd(void)
{
	int udp6fd;

	udp6fd = open(UDP6_DEV_NAME, O_RDWR | O_NONBLOCK, 0);
	if (udp6fd < 0) {
		error("Couldn't open UDPv6 device (%s): %m", UDP6_DEV_NAME);
	}
	return (udp6fd);
}

/*
 * plumb_ip6if()
 *
 * Perform IPv6 interface plumbing.
 */
/*ARGSUSED*/
static int
plumb_ip6if(int unit)
{
	int udp6fd = -1, tmpfd;
	uint32_t x;
	struct lifreq lifr;

	if (!IPV6CP_ENABLED || (ifunit == -1) || (pppfd == -1)) {
		return (0);
	}
	if (plumbed)
		return (1);
	if (ip6fd == -1 && open_ip6fd() == -1)
		return (0);
	if (use_plink && (udp6fd = open_udp6fd()) == -1)
		return (0);
	tmpfd = open(drvnam, O_RDWR | O_NONBLOCK, 0);
	if (tmpfd < 0) {
		error("Couldn't open PPP device (%s): %m", drvnam);
		if (udp6fd != -1)
			(void) close(udp6fd);
		return (0);
	}
	if (kdebugflag & 1) {
		x = PPPDBG_LOG + PPPDBG_DRIVER;
		if (strioctl(tmpfd, PPPIO_DEBUG, &x, sizeof (x), 0) < 0) {
			warn("PPPIO_DEBUG ioctl for mux failed: %m");
		}
	}
	if (myioctl(tmpfd, I_PUSH, IP_MOD_NAME) < 0) {
		error("Couldn't push IP module(%s): %m", IP_MOD_NAME);
		goto err_ret;
	}
	/*
	 * Sets interface ppa and flags (refer to comments in plumb_ipif for
	 * the IF_UNITSEL ioctl). In addition, the IFF_IPV6 bit must be set in
	 * order to declare this as an IPv6 interface.
	 */
	BZERO(&lifr, sizeof (lifr));
	if (myioctl(tmpfd, SIOCGLIFFLAGS, &lifr) < 0) {
		error("Couldn't get IPv6 interface flags: %m");
		goto err_ret;
	}
	lifr.lifr_flags |= IFF_IPV6;
	lifr.lifr_flags &= ~(IFF_BROADCAST | IFF_IPV4);
	lifr.lifr_ppa = ifunit;
	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	if (myioctl(tmpfd, SIOCSLIFNAME, &lifr) < 0) {
		error("Can't set ifname for unit %d: %m", ifunit);
		goto err_ret;
	}
	if (use_plink) {
		ip6muxid = myioctl(udp6fd, I_PLINK, (void *)tmpfd);
		if (ip6muxid < 0) {
			error("Can't I_PLINK PPP device to IPv6: %m");
			goto err_ret;
		}
	} else {
		ip6muxid = myioctl(ip6fd, I_LINK, (void *)tmpfd);
		if (ip6muxid < 0) {
			error("Can't I_LINK PPP device to IPv6: %m");
			goto err_ret;
		}
	}
	lifr.lifr_ip_muxid = ip6muxid;
	lifr.lifr_arp_muxid = -1;
	if (myioctl(ip6fd, SIOCSLIFMUXID, (caddr_t)&lifr) < 0) {
		error("Can't set mux ID:  SIOCSLIFMUXID: %m");
		goto err_ret;
	}
	(void) close(tmpfd);
	if (udp6fd != -1)
		(void) close(udp6fd);
	return (1);

err_ret:
	(void) close(tmpfd);
	if (udp6fd != -1)
		(void) close(udp6fd);
	return (0);
}

/*
 * unplumb_ip6if()
 *
 * Perform IPv6 interface unplumbing.  Possibly called from die(), so there
 * shouldn't be any call to die() here.
 */
static int
unplumb_ip6if(int unit)
{
	int udp6fd = -1, fd = -1;
	int id;
	struct lifreq lifr;

	if (!IPV6CP_ENABLED || ifunit == -1) {
		return (0);
	}
	if (!plumbed && (ip6muxid == -1 || (ip6fd == -1 && !use_plink))) {
		return (1);
	}
	id = ip6muxid;
	if (!plumbed && use_plink) {
		if ((udp6fd = open_udp6fd()) == -1)
			return (0);
		/*
		 * Note: must re-get mux ID, since any intervening
		 * ifconfigs will change this.
		 */
		BZERO(&lifr, sizeof (lifr));
		(void) strlcpy(lifr.lifr_name, ifname,
		    sizeof (lifr.lifr_name));
		if (myioctl(ip6fd, SIOCGLIFMUXID, (caddr_t)&lifr) < 0) {
			warn("Can't get mux fd: SIOCGLIFMUXID: %m");
		} else {
			id = lifr.lifr_ip_muxid;
			fd = myioctl(udp6fd, _I_MUXID2FD, (void *)id);
			if (fd < 0) {
				warn("Can't get mux fd: _I_MUXID2FD: %m");
			}
		}
	}
	/*
	 * Mark down and unlink the IPv6 interface.
	 */
	(void) sif6down(unit);
	if (plumbed)
		return (1);
	ip6muxid = -1;
	if (use_plink) {
		if ((fd = myioctl(udp6fd, _I_MUXID2FD, (void *)id)) < 0) {
			error("Can't recapture mux fd: _I_MUXID2FD: %m");
			(void) close(udp6fd);
			return (0);
		}
		if (myioctl(udp6fd, I_PUNLINK, (void *)id) < 0) {
			error("Can't I_PUNLINK PPP from IPv6: %m");
			(void) close(fd);
			(void) close(udp6fd);
			return (0);
		}
		(void) close(fd);
		(void) close(udp6fd);
	} else {
		if (myioctl(ip6fd, I_UNLINK, (void *)id) < 0) {
			error("Can't I_UNLINK PPP from IPv6: %m");
			return (0);
		}
	}
	return (1);
}

/*
 * sif6flags()
 *
 * Set or clear the IPv6 interface flags.
 */
int
sif6flags(f, set)
	u_int32_t f;
	int set;
{
	struct lifreq lifr;
	int fd;

	if (!IPV6CP_ENABLED || (ip6muxid == -1)) {
		return (0);
	}
	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0) {
		error("sif6flags: error opening IPv6 socket: %m");
		return (0);
	}
	BZERO(&lifr, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	if (myioctl(fd, SIOCGLIFFLAGS, &lifr) < 0) {
		error("Couldn't get IPv6 interface flags: %m");
		(void) close(fd);
		return (0);
	}
	if (set) {
		lifr.lifr_flags |= f;
	} else {
		lifr.lifr_flags &= ~f;
	}
	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	if (myioctl(fd, SIOCSLIFFLAGS, &lifr) < 0) {
		error("Couldn't set IPv6 interface flags: %m");
		(void) close(fd);
		return (0);
	}
	(void) close(fd);
	return (1);
}

/*
 * sif6up()
 *
 * Config the IPv6 interface up and enable IPv6 packets to pass.
 */
/*ARGSUSED*/
int
sif6up(unit)
	int unit;
{
	if (if6_is_up) {
		return (1);
	} else if (!IPV6CP_ENABLED) {
		warn("sif6up called when IPV6CP is disabled");
		return (0);
	} else if (ip6muxid == -1) {
		warn("sif6up called in wrong state");
		return (0);
	} else if (!sif6flags(IFF_UP, 1)) {
		error("Unable to mark the IPv6 interface UP");
		return (0);
	}
	if6_is_up = 1;
	return (1);
}

/*
 * sif6down()
 *
 * Config the IPv6 interface down and disable IPv6.  Possibly called from
 * die(), so there shouldn't be any call to die() here.
 */
/*ARGSUSED*/
int
sif6down(unit)
	int unit;
{
	if (!IPV6CP_ENABLED) {
		warn("sif6down called when IPV6CP is disabled");
		return (0);
	} else if (!if6_is_up || (ip6muxid == -1)) {
		return (1);
	} else if (!sif6flags(IFF_UP, 0)) {
		error("Unable to mark the IPv6 interface DOWN");
		return (0);
	}
	if6_is_up = 0;
	return (1);
}

/*
 * sif6mtu()
 *
 * Config the IPv6 interface MTU.
 */
int
sif6mtu(mtu)
	int mtu;
{
	struct lifreq lifr;
	int s;

	if (!IPV6CP_ENABLED || (ip6muxid == -1)) {
		return (0);
	}
	s = socket(AF_INET6, SOCK_DGRAM, 0);
	if (s < 0) {
		error("sif6mtu: error opening IPv6 socket: %m");
		return (0);
	}
	BZERO(&lifr, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	lifr.lifr_mtu = mtu;
	if (myioctl(s, SIOCSLIFMTU, &lifr) < 0) {
		error("Couldn't set IPv6 MTU (%s): %m", lifr.lifr_name);
		(void) close(s);
		return (0);
	}
	(void) close(s);
	return (1);
}

/*
 * sif6addr()
 *
 * Config the interface with an IPv6 link-local address.
 */
/*ARGSUSED*/
int
sif6addr(unit, ourid, hisid)
	int unit;
	eui64_t ourid;
	eui64_t hisid;
{
	struct lifreq lifr;
	struct sockaddr_storage	laddr;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&laddr;
	int fd;

	if (!IPV6CP_ENABLED || (ip6muxid == -1 && plumb_ip6if(unit) == 0)) {
		return (0);
	}
	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0) {
		error("sif6addr: error opening IPv6 socket: %m");
		return (0);
	}
	/*
	 * Set the IPv6 interface MTU.
	 */
	if (!sif6mtu(link_mtu)) {
		(void) close(fd);
		return (0);
	}
	/*
	 * Set the interface address token.  Do this because /dev/ppp responds
	 * to DL_PHYS_ADDR_REQ with zero values, hence the interface token
	 * came to be zero too, and without this, in.ndpd will complain.
	 */
	BZERO(&lifr, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	BZERO(sin6, sizeof (struct sockaddr_in6));
	IN6_LLTOKEN_FROM_EUI64(lifr, sin6, ourid);
	if (myioctl(fd, SIOCSLIFTOKEN, &lifr) < 0) {
		error("Couldn't set IPv6 token (%s): %m", lifr.lifr_name);
		(void) close(fd);
		return (0);
	}
	/*
	 * Set the IPv6 interface local point-to-point address.
	 */
	IN6_LLADDR_FROM_EUI64(lifr, sin6, ourid);
	if (myioctl(fd, SIOCSLIFADDR, &lifr) < 0) {
		error("Couldn't set local IPv6 address (%s): %m",
		    lifr.lifr_name);
		(void) close(fd);
		return (0);
	}
	/*
	 * Set the IPv6 interface local point-to-point address.
	 */
	BZERO(&lifr, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	IN6_LLADDR_FROM_EUI64(lifr, sin6, hisid);
	if (myioctl(fd, SIOCSLIFDSTADDR, &lifr) < 0) {
		error("Couldn't set remote IPv6 address (%s): %m",
		    lifr.lifr_name);
		(void) close(fd);
		return (0);
	}
	(void) close(fd);
	return (1);
}

/*
 * cif6addr()
 */
/*ARGSUSED*/
int
cif6addr(u, o, h)
	int u;
	eui64_t o;
	eui64_t h;
{
	if (!IPV6CP_ENABLED) {
		return (0);
	}
	/*
	 * Do nothing here, as everything has been done in sif6down().
	 */
	return (1);
}

/*
 * ether_to_eui64()
 *
 * Convert 48-bit Ethernet address into 64-bit EUI. Walks the list of valid
 * ethernet interfaces, and convert the first found 48-bit MAC address into
 * EUI 64. caller also assumes that the system has a properly configured
 * Ethernet interface for this function to return non-zero.
 */
int
ether_to_eui64(p_eui64)
	eui64_t *p_eui64;
{
	struct ether_addr eth_addr;

	if (p_eui64 == NULL) {
		return (0);
	}
	if (!get_first_hwaddr(eth_addr.ether_addr_octet,
	    sizeof (eth_addr.ether_addr_octet))) {
		return (0);
	}
	/*
	 * And convert the EUI-48 into EUI-64, per RFC 2472 [sec 4.1]
	 */
	p_eui64->e8[0] = (eth_addr.ether_addr_octet[0] & 0xFF) | 0x02;
	p_eui64->e8[1] = (eth_addr.ether_addr_octet[1] & 0xFF);
	p_eui64->e8[2] = (eth_addr.ether_addr_octet[2] & 0xFF);
	p_eui64->e8[3] = 0xFF;
	p_eui64->e8[4] = 0xFE;
	p_eui64->e8[5] = (eth_addr.ether_addr_octet[3] & 0xFF);
	p_eui64->e8[6] = (eth_addr.ether_addr_octet[4] & 0xFF);
	p_eui64->e8[7] = (eth_addr.ether_addr_octet[5] & 0xFF);
	return (1);
}
#endif /* INET6 */

struct bit_ent {
	int val;
	char *off, *on;
};

/* see sbuf[] below if you change this list */
static struct bit_ent bit_list[] = {
	{ TIOCM_DTR, "dtr", "DTR" },
	{ TIOCM_RTS, "rts", "RTS" },
	{ TIOCM_CTS, "cts", "CTS" },
	{ TIOCM_CD, "dcd", "DCD" },
	{ TIOCM_RI, "ri", "RI" },
	{ TIOCM_DSR, "dsr", "DSR" },
#if 0
	{ TIOCM_LE, "disabled", "ENABLED" },
	{ TIOCM_ST, NULL, "2nd-XMIT" },
	{ TIOCM_SR, NULL, "2nd-RECV" },
#endif
	{ 0, NULL, NULL }
};

static void
getbits(int fd, char *name, FILE *strptr)
{
	int nmods, i;
	struct str_list strlist;
	struct bit_ent *be;
	int mstate;
	char sbuf[50];		/* sum of string lengths in bit_list */
	char *str;

	nmods = ioctl(fd, I_LIST, NULL);
	if (nmods < 0) {
		error("unable to get module count: %m");
	} else {
		strlist.sl_nmods = nmods;
		strlist.sl_modlist = malloc(sizeof (struct str_mlist) * nmods);
		if (strlist.sl_modlist == NULL)
			novm("module list");
		if (ioctl(fd, I_LIST, (caddr_t)&strlist) < 0) {
			error("unable to get module names: %m");
		} else {
			for (i = 0; i < strlist.sl_nmods; i++)
				(void) flprintf(strptr, "%d: %s", i,
				    strlist.sl_modlist[i].l_name);
			free(strlist.sl_modlist);
		}
	}
	if (ioctl(fd, TIOCMGET, &mstate) < 0) {
		error("unable to get modem state: %m");
	} else {
		sbuf[0] = '\0';
		for (be = bit_list; be->val != 0; be++) {
			str = (be->val & mstate) ? be->on : be->off;
			if (str != NULL) {
				if (sbuf[0] != '\0')
					(void) strcat(sbuf, " ");
				(void) strcat(sbuf, str);
			}
		}
		(void) flprintf(strptr, "%s: %s\n", name, sbuf);
	}
}

/*
 * Print state of serial link.  The stream might be linked under the
 * /dev/sppp driver.  If it is, then it's necessary to unlink it first
 * and relink it when done.  Otherwise, it's not possible to use
 * ioctl() on the stream.
 */
void
sys_print_state(FILE *strptr)
{
	bool was_linked;

	if (pppfd == -1)
		return;
	if (ttyfd == -1) {
		(void) flprintf(strptr, "serial link is not active");
		return;
	}
	was_linked = fdmuxid != -1;
	if (was_linked && ioctl(pppfd, I_UNLINK, fdmuxid) == -1) {
		error("I_UNLINK: %m");
	} else {
		fdmuxid = -1;
		getbits(ttyfd, devnam, strptr);
		if (was_linked &&
		    (fdmuxid = ioctl(pppfd, I_LINK, (void *)ttyfd)) == -1)
			fatal("I_LINK: %m");
	}
}

/*
 * send ioctl to driver asking it to block packets with network protocol
 * proto in the control queue until the queue for proto is plumbed.
 */
void
sys_block_proto(uint16_t proto)
{
	if (proto > 0x7fff) {
		warn("cannot block: not a network proto 0x%lx\n", proto);
		return;
	}
	if (strioctl(pppfd, PPPIO_BLOCKNP, &proto, sizeof (proto), 0) < 0) {
		warn("PPPIO_BLOCKNP ioctl failed %m");
	}
}
/*
 * send ioctl to driver asking it to release packets with network protocol
 * proto from control queue to the protocol specific queue.
 */
void
sys_unblock_proto(uint16_t proto)
{
	if (proto > 0x7fff) {
		warn("cannot unblock: not a network proto 0x%lx\n", proto);
		return;
	}
	if (strioctl(pppfd, PPPIO_UNBLOCKNP, &proto, sizeof (proto), 0) < 0) {
		warn("PPPIO_UNBLOCKNP ioctl failed %m");
	}
}
