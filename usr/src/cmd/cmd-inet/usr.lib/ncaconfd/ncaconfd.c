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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/tihdr.h>
#include <stropts.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>
#include <locale.h>
#include <unistd.h>
#include <sys/varargs.h>

#include <netinet/in.h>
#include <sys/ethernet.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysmacros.h>
#include <net/if.h>
#include <inet/mib2.h>
#include <inet/ip.h>
#include <net/route.h>
#include <arpa/inet.h>
#include "ncaconf.h"

/* NCA does not support IPv6... */
#ifndef	NCA_MOD_NAME
#define	NCA_MOD_NAME	"nca"
#endif

#ifndef	ARP_MOD_NAME
#define	ARP_MOD_NAME	"arp"
#endif

#define	IF_SEPARATOR	':'

#define	ping_prog	"/usr/sbin/ping"

/* Structure to hold info about each network interface. */
typedef struct nif_s {
	char		name[LIFNAMSIZ+1];
	struct in_addr	local_addr;
	struct in_addr	router_addr;
	uchar_t		router_ether_addr[ETHERADDRL];
} nif_t;

typedef struct mib_item_s {
	struct mib_item_s	*next_item;
	int			group;
	int			mib_id;
	int			length;
	char			*valp;
} mib_item_t;

/* The network interface array. */
static nif_t *nif_list;
/* Number of network interface to process. */
static int num_nif;

/* Interface request to IP. */
static struct lifreq lifr;

/* True if syslog is to be used. */
static boolean_t logging;
/* True if additional debugging messages are printed. */
static boolean_t debug;

/* File descriptor to the routing socket. */
static int rt_fd;

static void logperror(char *);
static void logwarn(char *, ...);
static void logdebug(char *, ...);
static int ip_domux2fd(int *, int *);
static void ip_plink(int, int);
static int find_nca_pos(int);
static int nca_set_nif(int, struct in_addr, uchar_t *);
static void nca_setup(boolean_t *);
static int get_if_ip_addr(void);
static mib_item_t *mibget(int);
static int ire_process(mib2_ipRouteEntry_t *, size_t, boolean_t *);
static int arp_process(mib2_ipNetToMediaEntry_t *, size_t, boolean_t *);
static int get_router_ip_addr(mib_item_t *, boolean_t *);
static int get_router_ether_addr(mib_item_t *, boolean_t *);
static int get_if_info(boolean_t *);
static void daemon_init(void);
static void daemon_work(void);
static void ping_them(void);

/*
 * Print out system error messages, either to syslog or stderr.  Note that
 * syslog() should print out system error messages in the correct language
 * used.  There is no need to use gettext().
 */
static void
logperror(char *str)
{
	if (logging) {
		syslog(LOG_ERR, "%s: %m\n", str);
	} else {
		(void) fprintf(stderr, "ncaconfd: %s: %s\n", str,
		    strerror(errno));
	}
}

/*
 * Print out warning messages.  The caller should use gettext() to have
 * the message printed out in the correct language.
 */
/*PRINTFLIKE1*/
static void
logwarn(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (logging) {
		vsyslog(LOG_WARNING, fmt, ap);
	} else {
		(void) fprintf(stderr, "ncaconfd: ");
		(void) vfprintf(stderr, fmt, ap);
	}
	va_end(ap);
}

/*
 * Print out debugging info.  Note that syslogd(8) should be configured to
 * take ordinary debug info for it to get this kind of info.
 */
/*PRINTFLIKE1*/
static void
logdebug(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (logging) {
		vsyslog(LOG_WARNING, fmt, ap);
	} else {
		(void) fprintf(stderr, "ncaconfd: ");
		(void) vfprintf(stderr, fmt, ap);
	}
	va_end(ap);
}

/*
 * Helper function for nca_setup().  It gets a fd to the lower IP
 * stream and I_PUNLINK's the lower stream.  It also initializes the
 * global variable lifr.
 *
 * Param:
 *	int *udp_fd: (referenced) fd to /dev/udp (upper IP stream).
 *	int *fd: (referenced) fd to the lower IP stream.
 *
 * Return:
 *	-1 if operation fails, 0 otherwise.
 */
static int
ip_domux2fd(int *udp_fd, int *fd)
{
	int ip_fd;

	if ((ip_fd = open(IP_DEV_NAME, O_RDWR)) < 0) {
		logperror("Cannot open IP");
		return (-1);
	}
	if ((*udp_fd = open(UDP_DEV_NAME, O_RDWR)) < 0) {
		logperror("Cannot open UDP");
		(void) close(ip_fd);
		return (-1);
	}
	if (ioctl(ip_fd, SIOCGLIFMUXID, (caddr_t)&lifr) < 0) {
		logperror("ioctl(SIOCGLIFMUXID) failed");
		(void) close(ip_fd);
		return (-1);
	}
	if (debug) {
		logdebug("ARP_muxid %d IP_muxid %d\n", lifr.lifr_arp_muxid,
		    lifr.lifr_ip_muxid);
	}
	if ((*fd = ioctl(*udp_fd, _I_MUXID2FD, lifr.lifr_ip_muxid)) < 0) {
		logperror("ioctl(_I_MUXID2FD) failed");
		(void) close(ip_fd);
		(void) close(*udp_fd);
		return (-1);
	}
	(void) close(ip_fd);
	return (0);
}

/*
 * Helper function for nca_setup().  It I_PLINK's back the upper and
 * lower IP streams.  Note that this function must be called after
 * ip_domux2fd().  In ip_domux2fd(), the global variable lifr is initialized
 * and ip_plink() needs information in lifr.  So ip_domux2fd() and ip_plink()
 * must be called in pairs.
 *
 * Param:
 *	int udp_fd: fd to /dev/udp (upper IP stream).
 *	int fd: fd to the lower IP stream.
 */
static void
ip_plink(int udp_fd, int fd)
{
	int mux_id;

	if ((mux_id = ioctl(udp_fd, I_PLINK, fd)) < 0) {
		logperror("ioctl(I_PLINK) failed");
		return;
	}
	if (debug > 0) {
		logdebug("New IP_muxid %d\n", mux_id);
	}
	lifr.lifr_ip_muxid = mux_id;
	if (ioctl(udp_fd, SIOCSLIFMUXID, (caddr_t)&lifr) < 0) {
		logperror("ioctl(SIOCSLIFMUXID) failed");
	}
}

#define	FOUND_NCA	-1
#define	FOUND_NONE	-2
/*
 * Find the proper position to insert NCA, which is just below IP.
 *
 * Param:
 *	int fd: fd to the lower IP stream.
 *
 * Return:
 *	If positive, it is the position to insert NCA.
 *	FOUND_NCA: found NCA!  So skip this one for plumbing.  But we
 *		still keep it in the interface list.
 *	FOUND_NONE: could not find IP or encounter other errors.  Remove
 *		this interface from the	list.
 */
static int
find_nca_pos(int fd)
{
	int num_mods;
	int i, pos;
	struct str_list strlist;
	boolean_t found_ip = B_FALSE;
	boolean_t found_nca = B_FALSE;

	if ((num_mods = ioctl(fd, I_LIST, NULL)) < 0) {
		logperror("ioctl(I_LIST) failed");
		return (FOUND_NONE);
	} else {
		strlist.sl_nmods = num_mods;
		strlist.sl_modlist = calloc(num_mods,
		    sizeof (struct str_mlist));
		if (strlist.sl_modlist == NULL) {
			logperror("cannot malloc");
			return (FOUND_NONE);
		} else {
			if (ioctl(fd, I_LIST, (caddr_t)&strlist) < 0) {
				logperror("ioctl(I_LIST) failed");
			} else {
				for (i = 0; i < strlist.sl_nmods; i++) {
					if (strcmp(IP_MOD_NAME,
					    strlist.sl_modlist[i].l_name)
					    == 0) {
						found_ip = B_TRUE;
						/*
						 * NCA should be just below
						 * IP.
						 */
						pos = i + 1;
					} else if (strncmp(NCA_MOD_NAME,
					    strlist.sl_modlist[i].l_name,
					    strlen(NCA_MOD_NAME)) == 0) {
						found_nca = B_TRUE;
					}
				}
			}
			free(strlist.sl_modlist);
		}
	}
	if (found_nca) {
		return (FOUND_NCA);
	} else if (found_ip) {
		if (debug) {
			logdebug("NCA is at position %d in the stream.\n", pos);
		}
		return (pos);
	} else {
		if (debug) {
			logdebug("Cannot find IP??\n");
		}
		return (FOUND_NONE);
	}
}

/*
 * To set the local IP address and default router ethernet address.
 *
 * Param:
 *	int fd: the fd to the lower IP stream.
 *	struct in_addr local_addr: the IP address for this interface.
 *	uchar_t *ether_addr: the ethernet address of the default router for
 *		for this interface.
 *
 * Return:
 *	-1 if the system does not support this NCA ioctl(), 0 otherwise.
 */
static int
nca_set_nif(int fd, struct in_addr local_addr, uchar_t *ether_addr)
{
	struct nca_set_ioctl nca_ioctl;
	struct strioctl strioc;
	int len;
	uchar_t *dst;

	strioc.ic_cmd = NCA_SET_IF;
	strioc.ic_timout = INFTIM;
	strioc.ic_len = sizeof (nca_ioctl);
	strioc.ic_dp = (char *)&nca_ioctl;

	nca_ioctl.local_addr = local_addr.s_addr;
	dst = nca_ioctl.router_ether_addr;
	for (len = ETHERADDRL; len > 0; len--)
		*dst++ = *ether_addr++;
	nca_ioctl.action = ADD_DEF_ROUTE;

	if (ioctl(fd, I_STR, &strioc) < 0) {
		logperror("ioctl(NCA_SET_IF) failed");
		if (errno == EINVAL)
			return (-1);
	}
	return (0);
}

/*
 * To setup the NCA stream.  First insert NCA into the proper position.
 * Then tell NCA the local IP address and default router by using the
 * NCA_SET_IF ioctl.
 *
 * Param:
 *	boolean_t *active: (referenced) B_TRUE if NCA is setup to do active
 *		connection.  If NCA does not support active connection,
 *		in return, active will be set to B_FALSE.
 */
static void
nca_setup(boolean_t *active)
{
	int i;
	int udp_fd;
	int fd;
	struct strmodconf mod;
	/* 128 is enough because interface name can only be LIFNAMSIZ long. */
	char err_buf[128];

	mod.mod_name = NCA_MOD_NAME;
	lifr.lifr_addr.ss_family = AF_INET;
	for (i = 0; i < num_nif; i++) {
		if (debug) {
			logdebug("Plumbing NCA for %s\n", nif_list[i].name);
		}
		/* This interface does not exist according to IP. */
		if (nif_list[i].local_addr.s_addr == 0) {
			continue;
		}
		(void) strlcpy(lifr.lifr_name, nif_list[i].name,
		    sizeof (lifr.lifr_name));

		if (ip_domux2fd(&udp_fd, &fd) < 0) {
			continue;
		}
		if (ioctl(udp_fd, I_PUNLINK, lifr.lifr_ip_muxid) < 0) {
			(void) snprintf(err_buf, sizeof (err_buf),
			    "ioctl(I_PUNLINK) for %s failed", nif_list[i].name);
			logperror(err_buf);
			(void) close(udp_fd);
			(void) close(fd);
			continue;
		}
		if ((mod.pos = find_nca_pos(fd)) < 0) {
			if (mod.pos == FOUND_NCA) {
				if (debug) {
					logdebug("Find NCA in the %s"
					    " stream\n", nif_list[i].name);
				}
				/* Just skip plumbing NCA. */
				goto set_nif;
			}
			if (debug) {
				logdebug("Cannot find pos for %s\n",
				    nif_list[i].name);
			}
			goto clean_up;
		}
		if (ioctl(fd, _I_INSERT, (caddr_t)&mod) < 0) {
			(void) snprintf(err_buf, sizeof (err_buf),
			    "ioctl(_I_INSERT) for %s failed", nif_list[i].name);
			logperror(err_buf);
			goto clean_up;
		}

		/*
		 * Only do the following if NCA is also used to make
		 * outgoing connections, and all necessary info is
		 * there.
		 */
set_nif:
		if (*active && nif_list[i].router_addr.s_addr != 0) {
			if (nca_set_nif(fd, nif_list[i].local_addr,
			    nif_list[i].router_ether_addr) < 0) {
				/*
				 * The system does not support this ioctl()!
				 * Skip all active stack processing but
				 * continue to plumb NCA.
				 */
				logwarn("NCA does not support active stack!");
				*active = B_FALSE;
			}
		}
clean_up:
		ip_plink(udp_fd, fd);
		(void) close(udp_fd);
		(void) close(fd);
	}
}

/*
 * To get IP address of network interface from IP.
 */
static int
get_if_ip_addr(void)
{
	int sock;
	struct lifnum lifn;
	struct lifconf lifc;
	struct lifreq *lifr;
	struct sockaddr_in *sin;
	char *buf;
	int num_lifr;
	int i, j;

	/* NCA only supports IPv4... */
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		logperror(gettext("Cannot open socket"));
		return (-1);
	}
	lifn.lifn_family = AF_UNSPEC;
	lifn.lifn_flags = 0;
	if (ioctl(sock, SIOCGLIFNUM, (char *)&lifn) < 0) {
		logperror(gettext("ioctl(SIOCGLIFNUM) failed"));
		(void) close(sock);
		return (-1);
	}
	buf = (char *)calloc(lifn.lifn_count, sizeof (struct lifreq));
	if (buf == NULL) {
		logperror(gettext("calloc() failed"));
		(void) close(sock);
		return (-1);
	}

	lifc.lifc_family = AF_UNSPEC;
	lifc.lifc_flags = 0;
	lifc.lifc_len = lifn.lifn_count * sizeof (struct lifreq);
	lifc.lifc_buf = buf;

	if (ioctl(sock, SIOCGLIFCONF, (char *)&lifc) < 0) {
		/*
		 * NCA is set up after all the interfaces have been
		 * plumbed.  So normally we should not get any error.
		 * Just abort if we encounter an error.
		 */
		logperror(gettext("ioctl(SIOCGLIFCONF) failed"));
		free(buf);
		(void) close(sock);
		return (-1);
	}
	num_lifr = lifc.lifc_len / sizeof (struct lifreq);
	/* Find the interface and copy the local IP address. */
	for (i = 0; i < num_nif; i++) {
		lifr = (struct lifreq *)lifc.lifc_req;
		for (j = num_lifr; j > 0; j--, lifr++) {
			/* Again, NCA only supports IPv4. */
			if (lifr->lifr_addr.ss_family != AF_INET)
				continue;
			if (strncmp(nif_list[i].name, lifr->lifr_name,
			    strlen(nif_list[i].name)) == 0) {
				sin = (struct sockaddr_in *)&lifr->lifr_addr;
				nif_list[i].local_addr = sin->sin_addr;
				if (debug) {
					logdebug("IP address of %s: %s\n",
					    nif_list[i].name,
					    inet_ntoa(sin->sin_addr));
				}
				break;
			}
		}
		if (j == 0) {
			/*
			 * The interface does not exist according to IP!
			 * Log a warning and go on.
			 */
			logwarn(gettext("Network interface %s"
			    " does not exist!\n"), nif_list[i].name);
			/*
			 * Set local_addr to 0 so that nca_setup() will
			 * not do anything for this interface.
			 */
			nif_list[i].local_addr.s_addr = 0;
		}
	}
	free(buf);
	(void) close(sock);
	return (0);
}

/*
 * Get MIB2 info from IP.
 *
 * Param:
 *	int sd: descriptor to IP to send down mib request.
 */
static mib_item_t *
mibget(int sd)
{
	char			buf[1024];
	int			flags;
	int			i, j, getcode;
	struct strbuf		ctlbuf, databuf;
	/* LINTED */
	struct T_optmgmt_req	*tor = (struct T_optmgmt_req *)buf;
	/* LINTED */
	struct T_optmgmt_ack	*toa = (struct T_optmgmt_ack *)buf;
	/* LINTED */
	struct T_error_ack	*tea = (struct T_error_ack *)buf;
	struct opthdr		*req;
	mib_item_t		*first_item = (mib_item_t *)0;
	mib_item_t		*last_item  = (mib_item_t *)0;
	mib_item_t		*temp;

	tor->PRIM_type = T_SVR4_OPTMGMT_REQ;
	tor->OPT_offset = sizeof (struct T_optmgmt_req);
	tor->OPT_length = sizeof (struct opthdr);
	tor->MGMT_flags = T_CURRENT;
	req = (struct opthdr *)&tor[1];
	req->level = MIB2_IP;		/* any MIB2_xxx value ok here */
	req->name  = 0;
	req->len   = 0;

	ctlbuf.buf = buf;
	ctlbuf.len = tor->OPT_length + tor->OPT_offset;
	flags = 0;
	if (putmsg(sd, &ctlbuf, (struct strbuf *)0, flags) == -1) {
		logperror("mibget: putmsg(ctl) failed");
		goto error_exit;
	}

	/*
	 * Each reply consists of a ctl part for one fixed structure
	 * or table, as defined in mib2.h.  The format is a T_OPTMGMT_ACK,
	 * containing an opthdr structure.  level/name identify the entry,
	 * len is the size of the data part of the message.
	 */
	req = (struct opthdr *)&toa[1];
	ctlbuf.maxlen = sizeof (buf);
	j = 1;
	for (;;) {
		flags = 0;
		getcode = getmsg(sd, &ctlbuf, (struct strbuf *)0, &flags);
		if (getcode == -1) {
			logperror("mibget getmsg(ctl) failed");
			if (debug) {
				logdebug("#   level   name    len\n");
				i = 0;
				for (last_item = first_item; last_item;
					last_item = last_item->next_item)
					(void) printf("%d  %4d   %5d   %d\n",
					    ++i,
					    last_item->group,
					    last_item->mib_id,
					    last_item->length);
			}
			goto error_exit;
		}
		if (getcode == 0 &&
		    ctlbuf.len >= sizeof (struct T_optmgmt_ack) &&
		    toa->PRIM_type == T_OPTMGMT_ACK &&
		    toa->MGMT_flags == T_SUCCESS &&
		    req->len == 0) {
			if (debug) {
				logdebug("mibget getmsg() %d returned "
				    "EOD (level %ld, name %ld)\n",
				    j, req->level, req->name);
			}
			return (first_item);		/* this is EOD msg */
		}

		if (ctlbuf.len >= sizeof (struct T_error_ack) &&
		    tea->PRIM_type == T_ERROR_ACK) {
			logwarn("mibget %d gives T_ERROR_ACK: TLI_error ="
			    " 0x%lx, UNIX_error = 0x%lx\n",
			    j, tea->TLI_error, tea->UNIX_error);
			errno = (tea->TLI_error == TSYSERR) ?
			    tea->UNIX_error : EPROTO;
			goto error_exit;
		}

		if (getcode != MOREDATA ||
		    ctlbuf.len < sizeof (struct T_optmgmt_ack) ||
		    toa->PRIM_type != T_OPTMGMT_ACK ||
		    toa->MGMT_flags != T_SUCCESS) {
			logwarn("mibget getmsg(ctl) %d returned %d, "
			    "ctlbuf.len = %d, PRIM_type = %ld\n",
			    j, getcode, ctlbuf.len, toa->PRIM_type);
			if (toa->PRIM_type == T_OPTMGMT_ACK) {
				logwarn("T_OPTMGMT_ACK: "
				    "MGMT_flags = 0x%lx, req->len = %ld\n",
				    toa->MGMT_flags, req->len);
			}
			errno = ENOMSG;
			goto error_exit;
		}

		temp = (mib_item_t *)malloc(sizeof (mib_item_t));
		if (!temp) {
			logperror("mibget malloc failed");
			goto error_exit;
		}
		if (last_item)
			last_item->next_item = temp;
		else
			first_item = temp;
		last_item = temp;
		last_item->next_item = (mib_item_t *)0;
		last_item->group = req->level;
		last_item->mib_id = req->name;
		last_item->length = req->len;
		last_item->valp = malloc((int)req->len);

		databuf.maxlen = last_item->length;
		databuf.buf    = last_item->valp;
		databuf.len    = 0;
		flags = 0;
		getcode = getmsg(sd, (struct strbuf *)0, &databuf, &flags);
		if (getcode == -1) {
			logperror("mibget getmsg(data) failed");
			goto error_exit;
		} else if (getcode != 0) {
			logwarn("mibget getmsg(data) returned %d, "
			    "databuf.maxlen = %d, databuf.len = %d\n",
			    getcode, databuf.maxlen, databuf.len);
			goto error_exit;
		}
		j++;
	}

error_exit:;
	while (first_item) {
		last_item = first_item;
		first_item = first_item->next_item;
		free(last_item);
	}
	return (first_item);
}

/*
 * Examine the IPv4 routing table for default routers.  For each interface,
 * find its default router.
 *
 * Param:
 *	mib2_ipRouteEntry_t *buf: the mib info buffer.
 *	size_t len: length of buffer.
 *	boolean_t *changed (referenced): set to B_TRUE if there is a change
 *		in router info.
 *
 * Return:
 *	number of default router found.
 */
static int
ire_process(mib2_ipRouteEntry_t *buf, size_t len, boolean_t *changed)
{
	mib2_ipRouteEntry_t 	*rp;
	mib2_ipRouteEntry_t 	*rp1;
	mib2_ipRouteEntry_t 	*rp2;
	struct	in_addr		nexthop_v4;
	mib2_ipRouteEntry_t	*endp;
	char			ifname[LIFNAMSIZ + 1];
	char			*cp;
	int			i;
	int			ifname_len;
	boolean_t		found;
	int			num_found = 0;

	if (len == 0)
		return (0);
	endp = buf + (len / sizeof (mib2_ipRouteEntry_t));

	for (i = 0; i < num_nif; i++) {
		/*
		 * Loop thru the routing table entries. Process any
		 * IRE_DEFAULT ire.  Ignore the others.  For each such
		 * ire, get the nexthop gateway address.
		 */
		found = B_FALSE;
		for (rp = buf; rp < endp; rp++) {
			/*
			 * NCA is only interested in default routes associated
			 * with an interface.
			 */
			if (!(rp->ipRouteInfo.re_ire_type & IRE_DEFAULT)) {
				continue;
			}
			/*  Get the nexthop address. */
			nexthop_v4.s_addr = rp->ipRouteNextHop;

			/*
			 * Right now, not all IREs have the interface name
			 * it is associated with.
			 */
			if (rp->ipRouteIfIndex.o_length == 0) {
				/*
				 * We don't have the outgoing interface in
				 * this case.  Get the nexthop address. Then
				 * determine the outgoing interface, by
				 * examining all interface IREs, and
				 * picking the match.
				 */
				for (rp1 = buf; rp1 < endp; rp1++) {

				if (!(rp1->ipRouteInfo.re_ire_type &
				    IRE_INTERFACE)) {
					continue;
				}

				/*
				 * Determine the interface IRE that
				 * matches the nexthop. i.e.
				 * (IRE addr & IRE mask) ==
				 * (nexthop & IRE mask)
				 */
				if ((rp1->ipRouteDest & rp1->ipRouteMask) ==
				    (nexthop_v4.s_addr & rp1->ipRouteMask)) {
					/*
					 * We found the interface to go to
					 * the default router.  Check the
					 * interface name.
					 */
					/* Can this be possible?? */
					if (rp1->ipRouteIfIndex.o_length == 0)
						continue;
					rp2 = rp1;
					break;
				}

				} /* End inner for loop. */
			} else {
				rp2 = rp;
			}

			ifname_len = MIN(rp2->ipRouteIfIndex.o_length,
			    sizeof (ifname) - 1);
			(void) memcpy(ifname, rp2->ipRouteIfIndex.o_bytes,
			    ifname_len);
			ifname[ifname_len] = '\0';
			if (ifname[0] == '\0')
				continue;
			cp = strchr(ifname, IF_SEPARATOR);
			if (cp != NULL)
				*cp = '\0';

			/* We are sure both are NULL terminated. */
			if (strcmp(nif_list[i].name, ifname) == 0) {
				/* No change, do not do anything. */
				if (nexthop_v4.s_addr ==
				    nif_list[i].router_addr.s_addr) {
					found = B_TRUE;
					break;
				}
				nif_list[i].router_addr.s_addr =
				    nexthop_v4.s_addr;
				if (debug) {
					logdebug("Get default"
					    " router for %s: %s\n", ifname,
					    inet_ntoa(nexthop_v4));
				}
				found = B_TRUE;
				*changed = B_TRUE;
				break;
			}

		}
		if (!found) {
			/*
			 * The interface does not have a default router.
			 * Log a warning and go on.
			 */
			logwarn(gettext("Network interface %s"
			    " does not have a default router.\n"),
			    nif_list[i].name);
			/*
			 * Set router_addr to 0 so that we will
			 * not do anything for this interface.
			 */
			nif_list[i].router_addr.s_addr = 0;
		} else {
			num_found++;
		}
	}
	return (num_found);
}

/*
 * Examine the ARP table to find ethernet address for default routers.
 *
 * Param:
 *	mib2_ipNetToMdeiaEntry_t *buf: the mib info buffer.
 *	size_t len: length of buffer.
 *	boolean_t *changed (referenced): set to B_TRUE if there is any change
 *		in ethernet address for any default router.
 *
 * Return:
 *	number of ethernet address found.
 */
static int
arp_process(mib2_ipNetToMediaEntry_t *buf, size_t len, boolean_t *changed)
{
	mib2_ipNetToMediaEntry_t 	*rp;
	mib2_ipNetToMediaEntry_t	*endp;
	int				i;
	boolean_t			found;
	int				num_found = 0;
	uchar_t				*src, *dst;

	if (len == 0)
		return (0);
	endp = buf + (len / sizeof (mib2_ipNetToMediaEntry_t));

	for (i = 0; i < num_nif; i++) {
		/*
		 * Loop thru the arp table entries and find the ethernet
		 * address of those default routers.
		 */
		if (nif_list[i].router_addr.s_addr == 0)
			continue;
		found = B_FALSE;
		for (rp = buf; rp < endp; rp++) {
			if (rp->ipNetToMediaNetAddress ==
			    nif_list[i].router_addr.s_addr) {
				/*
				 * Sanity check.  Make sure that this
				 * default router is only reachable thru this
				 * interface.
				 */
				if (rp->ipNetToMediaIfIndex.o_length !=
				    strlen(nif_list[i].name) ||
				    strncmp(rp->ipNetToMediaIfIndex.o_bytes,
					nif_list[i].name,
					rp->ipNetToMediaIfIndex.o_length) !=
				    0) {
					break;
				}
				/* No change, do not do anything. */
				if (bcmp(nif_list[i].router_ether_addr,
				    rp->ipNetToMediaPhysAddress.o_bytes,
				    ETHERADDRL) == 0) {
					found = B_TRUE;
					continue;
				}
				dst = nif_list[i].router_ether_addr;
				src = (uchar_t *)
				    rp->ipNetToMediaPhysAddress.o_bytes;
				for (len = ETHERADDRL; len > 0; len--)
					*dst++ = *src++;
				if (debug) {
					int j;
					uchar_t *cp;
					char err_buf[128];

					(void) snprintf(err_buf,
					    sizeof (err_buf),
					    "Get address for %s: ",
					    inet_ntoa(nif_list[i].router_addr));
					cp = (uchar_t *)
					    nif_list[i].router_ether_addr;
					for (j = 0; j < ETHERADDRL; j++) {
						(void) sprintf(err_buf +
						    strlen(err_buf),
						    "%02x:", 0xff & cp[j]);
					}
					(void) sprintf(err_buf +
					    strlen(err_buf) - 1, "\n");
					logdebug(err_buf);
				}
				found = B_TRUE;
				*changed = B_TRUE;
			}
		}
		if (!found) {
			logwarn("Cannot reach %s using %s\n",
			    inet_ntoa(nif_list[i].router_addr),
			    nif_list[i].name);
			/* Clear this default router. */
			nif_list[i].router_addr.s_addr = 0;
		} else {
			num_found++;
		}
	}
	return (num_found);
}

/*
 * Get IP address of default routers for each interface.
 *
 * Param:
 *	mib_item_t *item: the mib info buffer.
 *	boolean_t *changed (referenced): set to B_TRUE if there is any change
 *		in router info.
 *
 * Return:
 *	-1 if there is no router found, 0 otherwise.
 */
static int
get_router_ip_addr(mib_item_t *item, boolean_t *changed)
{
	int found = 0;

	for (; item != NULL; item = item->next_item) {
		/* NCA does not support IPv6... */
		if (!(item->group == MIB2_IP && item->mib_id == MIB2_IP_ROUTE))
			continue;
		/* LINTED */
		found += ire_process((mib2_ipRouteEntry_t *)item->valp,
		    item->length, changed);
	}
	if (found == 0)
		return (-1);
	else
		return (0);
}

/*
 * Get Ethernet address for each default router from ARP.
 *
 * Param:
 *	mib_item_t *item: the mib info buffer.
 *	boolean_t *changed (referenced): set to B_TRUE if there is any change
 *		in ethernet address of router.
 *
 * Return:
 *	-1 if there is no ethernet address found, 0 otherwise.
 */
static int
get_router_ether_addr(mib_item_t *item, boolean_t *changed)
{
	int found = 0;

	for (; item != NULL; item = item->next_item) {
		/* NCA does not support IPv6... */
		if (!(item->group == MIB2_IP && item->mib_id == MIB2_IP_MEDIA))
			continue;
		/* LINTED */
		found += arp_process((mib2_ipNetToMediaEntry_t *)item->valp,
		    item->length, changed);
	}
	if (found == 0)
		return (-1);
	else
		return (0);
}

/*
 * Ping all default routers.  It just uses system(3F) to call
 * ping(8) to do the job...
 */
static void
ping_them(void)
{
	int i;
	char ping_cmd[128];

	for (i = 0; i < num_nif; i++) {
		if (nif_list[i].router_addr.s_addr != 0) {
			(void) snprintf(ping_cmd, sizeof (ping_cmd),
			    "%s %s > /dev/null 2>&1",
			    ping_prog,
			    inet_ntoa(nif_list[i].router_addr));
			(void) system(ping_cmd);
		}
	}
}

/*
 * To get default router info (both IP address and ethernet address) for
 * each configured interface from IP.
 *
 * Param:
 *	boolean_t *changed (referenced): set to B_TRUE if there is any change
 *		of info.
 *
 * Return:
 *	-1 if there is any error, 0 if everything is fine.
 */
static int
get_if_info(boolean_t *changed)
{
	int mib_fd;
	mib_item_t *item;
	boolean_t ip_changed = B_FALSE;
	boolean_t ether_changed = B_FALSE;

	if ((mib_fd = open(IP_DEV_NAME, O_RDWR)) < 0) {
		logperror("cannot open ip to get router info");
		return (-1);
	}
	if (ioctl(mib_fd, I_PUSH, ARP_MOD_NAME) == -1) {
		logperror("cannot push arp");
		goto err;
	}

	if ((item = mibget(mib_fd)) == NULL) {
		goto err;
	}

	if (get_router_ip_addr(item, &ip_changed) < 0) {
		goto err;
	}
	/*
	 * Ping every routers to make sure that ARP has all their ethernet
	 * addresses.
	 */
	ping_them();
	/*
	 * If the router IP address is not changed, its ethernet address
	 * should not be changed.  But just in case there is some IP
	 * failover going on...
	 */
	if (get_router_ether_addr(item, &ether_changed) < 0) {
		goto err;
	}
	(void) close(mib_fd);
	*changed = ip_changed || ether_changed;
	return (0);
err:
	(void) close(mib_fd);
	return (-1);
}

/*
 * To remove the default router from an interface.
 *
 * Param:
 *	struct in_addr gw_addr: the IP address of the default router to be
 *	removed.
 */
static void
nca_del_nif(struct in_addr gw_addr)
{
	struct nca_set_ioctl nca_ioctl;
	struct strioctl strioc;
	int i;
	int udp_fd, fd;

	/* Search for the interface for this router. */
	for (i = 0; i < num_nif; i++) {
		if (nif_list[i].router_addr.s_addr == gw_addr.s_addr)
			break;
	}
	if (i == num_nif)
		return;

	if (ip_domux2fd(&udp_fd, &fd) < 0) {
		logwarn(gettext("Removing interface %s from the"
		    " configuration list.\n"), nif_list[i].name);
		nif_list[i].name[0] = 0;
		return;
	}
	if (ioctl(udp_fd, I_PUNLINK, lifr.lifr_ip_muxid) < 0) {
		logwarn(gettext("Removing interface %s from the"
		    " configuration list.\n"), nif_list[i].name);
		nif_list[i].name[0] = 0;
		(void) close(udp_fd);
		(void) close(fd);
		return;
	}

	strioc.ic_cmd = NCA_SET_IF;
	strioc.ic_timout = INFTIM;
	strioc.ic_len = sizeof (nca_ioctl);
	strioc.ic_dp = (char *)&nca_ioctl;

	nca_ioctl.local_addr = 0;
	(void) memset(nca_ioctl.router_ether_addr, 0, ETHERADDRL);
	nca_ioctl.action = DEL_DEF_ROUTE;

	if (ioctl(fd, I_STR, &strioc) < 0) {
		logperror("ioctl(NCA_SET_IF) failed");
	}
	ip_plink(udp_fd, fd);
	(void) close(udp_fd);
	(void) close(fd);

	/* Clear the fields for this interface. */
	nif_list[i].router_addr.s_addr = 0;
	(void) memset(nif_list[i].router_ether_addr, 0, ETHERADDRL);
}

/*
 * Wait for any changes in the routing table.  If there are changes to
 * IP address or router ethernet address, send down the info to NCA.
 */
static void
daemon_work(void)
{
	int n;
	int i;
	int udp_fd;
	int fd;
	int64_t msg[2048/8];
	struct rt_msghdr *rtm;
	boolean_t changed;
	struct sockaddr_in *sin;
	struct in_addr gw_addr;
	uchar_t *cp;

	/* Loop forever waiting for any routing changes. */
	for (;;) {
		if (debug) {
			logdebug("Waiting to read routing info...\n");
		}
		n = read(rt_fd, msg, sizeof (msg));
		/* Don't die...  Reinitialize socket and listen again. */
		if (n <= 0) {
			if (debug) {
				logdebug("Routing socket read error.\n");
			}
			(void) close(rt_fd);
			rt_fd = socket(PF_ROUTE, SOCK_RAW, AF_INET);
			i = 0;
			while (rt_fd < 0) {
				if (i++ == 0) {
					logperror(gettext("cannot reinitialize"
					    " routing socket"));
				} else if (i > 5) {
					logwarn(gettext("Give up on trying to"
					    " reinitializing routing"
					    " socket\n"));
					exit(1);
				}
				/* May be a transient error... */
				(void) sleep(10);
				rt_fd = socket(PF_ROUTE, SOCK_RAW, AF_INET);
			}
		} else {
			rtm = (struct rt_msghdr *)msg;
			if (rtm->rtm_version != RTM_VERSION) {
				logwarn(gettext("Do non understand routing"
				    " socket info.\n"));
				continue;
			}
			if (debug) {
				logdebug("Get routing info.\n");
			}
			switch (rtm->rtm_type) {
			case RTM_DELETE:
			case RTM_OLDDEL:
				sin = (struct sockaddr_in *)(rtm + 1);
				cp = (uchar_t *)sin;
				/* Only handle default route deletion. */
				if ((rtm->rtm_addrs & RTA_DST) &&
				    (sin->sin_addr.s_addr == 0)) {
					if (!(rtm->rtm_addrs & RTA_GATEWAY)) {
						break;
					}
					cp += sizeof (struct sockaddr_in);
					/* LINTED */
					sin = (struct sockaddr_in *)cp;
					gw_addr = sin->sin_addr;
					if (debug) {
						logdebug("Get default route "
						    "removal notice: gw %s\n",
						    inet_ntoa(gw_addr));
					}
					nca_del_nif(gw_addr);
				}
				break;
			case RTM_ADD:
			case RTM_OLDADD:
			case RTM_CHANGE:
				changed = B_FALSE;
				if (get_if_info(&changed) < 0) {
					/* May be a transient error... */
					(void) sleep(10);
					break;
				}
				/* Nothing is changed, do nothing. */
				if (!changed) {
					if (debug) {
						logdebug("Get route change "
						    "notice, but nothing is "
						    "changed for us!");
					}
					break;
				}
				lifr.lifr_addr.ss_family = AF_INET;
				for (i = 0; i < num_nif; i++) {
					int ret;

					/*
					 * If name is NULL, it means that
					 * we have encontered some problems
					 * when configurating the interface.
					 * So we remove it from the list.
					 */
					if (nif_list[i].name[0] == 0 ||
					    nif_list[i].local_addr.s_addr == 0)
						continue;
					(void) strlcpy(lifr.lifr_name,
					    nif_list[i].name,
					    sizeof (lifr.lifr_name));
					if (ip_domux2fd(&udp_fd, &fd) < 0) {
						logwarn(gettext("Removing"
						    " interface %s from the"
						    " configuration list.\n"),
						    nif_list[i].name);
						nif_list[i].name[0] = 0;
						continue;
					}
					if (ioctl(udp_fd, I_PUNLINK,
					    lifr.lifr_ip_muxid) < 0) {
						logwarn(gettext("Removing"
						    " interface %s from the"
						    " configuration list.\n"),
						    nif_list[i].name);
						nif_list[i].name[0] = 0;
						(void) close(udp_fd);
						(void) close(fd);
						continue;
					}
					if (debug) {
						logdebug("Configuring"
						    " %s\n", nif_list[i].name);
					}
					ret = nca_set_nif(fd,
					    nif_list[i].local_addr,
					    nif_list[i].router_ether_addr);
					ip_plink(udp_fd, fd);
					if (ret < 0) {
						/*
						 * This should not be possible
						 * since if NCA does not
						 * support the ioctl, the
						 * active flag should be
						 * cleared already and this
						 * function should not have
						 * been called at all!
						 */
						logwarn("Daemon dies\n");
						exit(1);
					}
					(void) close(udp_fd);
					(void) close(fd);
				}
				break;
			default:
				continue;
			}
		}
	}
}

/*
 * Make us a daemon.
 */
static void
daemon_init(void)
{
	pid_t pid;

	if ((pid = fork()) == -1) {
		/* Write directly to terminal, instead of syslog. */
		(void) fprintf(stderr, gettext("ncaconfd: cannot fork: %s\n"),
		    strerror(errno));
		exit(1);
	}
	if (pid != 0)
		exit(0);
	(void) setsid();
	/* Fork again so that we will never get a controlling terminal. */
	if ((pid = fork()) == -1) {
		/* Write directly to terminal, instead of syslog. */
		(void) fprintf(stderr, gettext("ncaconfd: cannot fork: %s\n"),
		    strerror(errno));
		exit(1);
	}
	if (pid != 0)
		exit(0);
	(void) chdir("/");
	(void) umask(0);
	(void) fclose(stdin);
	(void) fclose(stdout);
	(void) fclose(stderr);
}

int
main(int argc, char **argv)
{
	int i, j;
	int c;
	boolean_t active = B_FALSE;
	boolean_t as_daemon = B_TRUE;

	if (argc == 1) {
		(void) fprintf(stderr, gettext("Usage: %s [-al]"
		    " [interface1 interface2 ...]\n"), argv[0]);
		return (1);
	}

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "adcl")) != EOF) {
		switch (c) {
		case 'a':
			active = B_TRUE;
			break;
		case 'd':
			debug = B_TRUE;
			break;
		case 'c':
			/* Don't run as daemon. */
			as_daemon = B_FALSE;
			break;
		case 'l':
			logging = B_TRUE;
			break;
		default:
			/* -d and -c are "undocumented" options. */
			(void) fprintf(stderr, gettext("Usage: %s [-al]"
			    " [interface1 interface2 ...]\n"), argv[0]);
			return (1);
		}
	}
	num_nif = argc - optind;
	if (num_nif == 0) {
		/* No network interface to proces... */
		(void) fprintf(stderr, gettext("Usage: %s [-al]"
		    " [interface1 interface2 ...]\n"), argv[0]);
		return (0);
	}
	nif_list = calloc(num_nif, sizeof (nif_t));
	if (nif_list == NULL) {
		(void) fprintf(stderr, gettext("ncaconfd: Cannot malloc: %s\n"),
		    strerror(errno));
		return (1);
	}
	for (i = 0, j = optind; i < num_nif; i++, j++) {
		(void) strlcpy(nif_list[i].name, argv[j], LIFNAMSIZ+1);
	}

	/* Get IP address info for all the intefaces. */
	if (get_if_ip_addr() < 0) {
		if (debug) {
			(void) fprintf(stderr, "ncaconfd: Cannot get IP"
			    " addresses for interfaces.\n");
		}
		return (1);
	}
	if (logging)
		openlog("ncaconfd", LOG_PID, LOG_DAEMON);
	/* No need to run as daemon if NCA is not making active connections. */
	if (active && as_daemon)
		daemon_init();
	if (active) {
		boolean_t changed;

		/* NCA does not support IPv6... */
		if ((rt_fd = socket(PF_ROUTE, SOCK_RAW, AF_INET)) < 0) {
			logperror("Cannot open routing socket");
			return (1);
		}
		/*
		 * At boot up time, the default router may not have been
		 * found.  So ignore the error and check later.
		 */
		if (get_if_info(&changed) < 0) {
			if (debug) {
				(void) logwarn("Cannot get"
				    " information from network interface.\n");
			}
		}
	}
	/* Do the set up as daemon (if we are) to save time at boot up... */
	nca_setup(&active);
	if (active)
		daemon_work();
	return (0);
}
