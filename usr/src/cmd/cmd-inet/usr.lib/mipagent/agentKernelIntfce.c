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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Routines in this program implement  OS-specific portions of
 * a Mobile-IP agent (RFC 2002).
 *
 */

#ifndef _REENTRANT
#error "Error!  Reentrant must be defined!"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <assert.h>
#include <synch.h>
#include <syslog.h>
#include <stropts.h>
#include <sys/dlpi.h>
#include <sys/types.h>
#include <sys/stream.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/stropts.h>
#include <sys/stropts.h>
#include <sys/types.h>

#include <inet/common.h>
#include <inet/ip.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <net/pfkeyv2.h>	/* ipsec alg values, etc. */

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <arpa/inet.h>

#include "agent.h"
#include "mip.h"
#include "agentKernelIntfce.h"
#include "conflib.h"

/* Check for bad os version, and compile anyway xxx WORK -- remove this */
#ifndef IFF_NORTEXCH
#define	IFF_NORTEXCH 0
#define	IFF_MIPRUNNING 1
#define	RTF_PRIVATE 2
#endif

/*
 * Routing socket message len for creating route for
 * reverse tunnel
 */

#define	MIP_RTUN_RTM_MSGLEN	sizeof (struct rt_msghdr)  +  \
				sizeof (struct sockaddr_in) + \
				sizeof (struct sockaddr_in) + \
				sizeof (struct sockaddr_in) + \
				sizeof (struct sockaddr_dl) + \
				sizeof (struct sockaddr_in) + \
				sizeof (struct sockaddr_dl)

/*
 * Routing socket message len for normal route
 * created to send reg reply to MN
 */
#define	MIP_RTM_MSGLEN	sizeof (struct rt_msghdr) + \
			sizeof (struct sockaddr_in) + \
			sizeof (struct sockaddr_in) + \
			sizeof (struct sockaddr_in)

/* Common to all mobility agents */
extern struct hash_table haMobileNodeHash;
extern struct hash_table maAdvConfigHash;
extern struct hash_table mipTunlHash;
extern int logVerbosity;

struct dynamicIfacetype *dynamicIfaceHead;

static int ioctl_sockid;
static int rtsock;
static rwlock_t gbl_tunnelLock;
static int first_tun_to_check = 0;
static struct staticIface *StaticIntfaceHead = NULL;

char *err2str(int);

#define	DEVICEDIR	"/dev/"
#ifndef ETH_ALEN
#define	ETH_ALEN	sizeof (struct ether_addr)
#endif

/* Definitions needed for refresh_mn_arp() module */
#define	BITSPERBYTE	8
#define	IPADDRL		sizeof (struct in_addr)
#define	DEVICEDIR	"/dev/"
#define	BCAST_HW_ADDR	"ff:ff:ff:ff:ff:ff"

#define	MAX_ERR			2048
#define	INVALID_PPA		(MAX_ERR + 1)
#define	INVALID_STRING		(MAX_ERR + 2)
#define	DLOKACK_SHORT_RESPONSE	(MAX_ERR + 3)
#define	DLOKACK_NOT_M_PCPROTO	(MAX_ERR + 4)
#define	ERR_MORECTL		(MAX_ERR + 5)
#define	ERR_MOREDATA		(MAX_ERR + 6)
#define	ERR_MORECTLDATA		(MAX_ERR + 7)
#define	DL_PRIMITIVE_ERROR	(MAX_ERR + 8)
#define	SHORT_CONTROL_PORTION	(MAX_ERR + 9)
#define	INVALID_ADDR		(MAX_ERR + 10)
#define	MN_ENTRY_ABSENT		(MAX_ERR + 11)
#define	NO_MAPPING		(MAX_ERR + 12)

/* Tunnel related definitions */
#define	MAX_TUNNEL_SUPPORTED	256
#define	NO_FREE_TUNNEL		(MAX_ERR + 1)
#define	TUNNEL_NOT_FOUND	(MAX_ERR + 2)
#define	DEV_NAME_NOT_FOUND	ENXIO
#define	INVALID_IP_ADDR		ENXIO
#define	MN_ENTRY_ABSENT		(MAX_ERR + 11)
#define	NO_MAPPING		(MAX_ERR + 12)


/* Table for mapping tunnelno with mobile-node address */
/*
 * WORK -- this will be removed once the tunneling interface returns us
 * a unique tunnel id.
 */
static struct {
	rwlock_t tunlLock;
	ipaddr_t mnaddr;
	ipaddr_t tunnelsrc;	/* only used on FA side */
	uint32_t refcnt;
} mnaddr_tunl[MAX_TUNNEL_SUPPORTED + 1];


#define	MAXWAIT		15
/* Maximum address buffer length */
#define	MAXDLADDR	1024
/* Handy macro. */
#define	OFFADDR(s, n)	(unsigned char *)((char *)(s) + (int)(n))


/* Internal Prototypes */
static int settaddr(int tnum, ipaddr_t ifaddr1, ipaddr_t ifaddr2,
    ipaddr_t saddr, ipaddr_t daddr, ipsec_req_t *);
static int garp(char *, uint32_t, unsigned char *);
static int plumb_one_tun(int tnum);
static int unplumb_one_tun(int muxfd);
static int setifflags(int tnum, int value);
static int strgetmsg(int fd, struct strbuf *ctlp, struct strbuf *datap,
    int *flagsp);
static int expecting(int prim, union DL_primitives *dlp);
static int arpgetHWaddr(ipaddr_t, unsigned char *);
int	gettunnelno(ipaddr_t, ipaddr_t);

int arpIfadd(ipaddr_t, char *, uint32_t);
int arpIfdel(ipaddr_t, char *, uint32_t);

/* External Prototypes */
extern MipTunlEntry *CreateTunlEntry(int tnum, ipaddr_t target, ipaddr_t tsrc,
    int muxfd);
extern char *ntoa(uint32_t addr_long, char *addr_string);
extern MobilityAgentEntry *findMaeFromIp(ipaddr_t, int);

/*
 * Function: InitTunnelModule
 *
 * Arguments: none
 *
 * Description: Initialize our globals.  Currently, initalize the global
 * 		tunnel lock.
 *
 * Returns: int (zero on success)
 */
static int
InitTunnelModule()
{
	int result;

	result = rwlock_init(&gbl_tunnelLock, USYNC_THREAD, NULL);

	return (result);
} /* InitTunnelModule */

/*
 * Function: newtunnel
 *
 * Arguments: ipaddr_t addr
 *	      ipaddr_t tsrc_addr
 *	      int *tunnels_scanned
 *
 * Description: This function returns the available tunnel number in the
 * 		range 0 through MAX_TUNNEL_SUPPORTED.  If none are available
 * 		it returns NO_FREE_TUNNEL. tunnels_scanned is used by the caller
 *		to figure out if all the tunnel numbers are scanned before
 *		concluding that	there's no free tunnel left.
 *
 * Returns: int (tunnel number, or -1 on error)
 */
static int
newtunnel(ipaddr_t addr, ipaddr_t tsrc_addr, int *tunnels_scanned)
{
	int i;
	boolean_t found = _B_FALSE;
	int tun_num;

	/* WARNING: check this xxx WORK */
	(void) rw_wrlock(&gbl_tunnelLock);
	*tunnels_scanned = 0;

	for (i = 0; i < MAX_TUNNEL_SUPPORTED; i++) {
		/* start scanning tunnel numbers where we were left last time */
		tun_num = (i + first_tun_to_check) % MAX_TUNNEL_SUPPORTED;

		/* is this an available tunnel? */
		if (mnaddr_tunl[tun_num].mnaddr == 0) {
			mnaddr_tunl[tun_num].mnaddr = addr;
			mnaddr_tunl[tun_num].tunnelsrc = tsrc_addr;
			found = _B_TRUE;
			break;
		}
	}

	/*
	 * Send back the number of tunnels scanned, so that caller can
	 * give up after scanning MAX_TUNNEL_SUPPORTED many tunnels.
	 * Also save where we were left, so that next time we start scanning
	 * from that point on.
	 */
	if (found) {
		*tunnels_scanned = i + 1;
		first_tun_to_check = (tun_num + 1) % MAX_TUNNEL_SUPPORTED;
	} else {
		*tunnels_scanned = MAX_TUNNEL_SUPPORTED;
		/*
		 * First_tun_to_check stays same. We did a one full round of
		 * scanning tunnel numbers and couldn't find any available.
		 * Next time we come here to find another available, we'll
		 * start from the same tunnel number.
		 */
	}

	(void) rw_unlock(&gbl_tunnelLock);


	if (found) {
	    return (tun_num);
	} else {
	    return (-1);
	}
} /* newtunnel */


/*
 * Function: freetunnel
 *
 * Arguments: int tnum
 *
 * Description: This function will free the current tunnel resource.  This
 * 		function will disappear with the new kernel tunnel interface.
 *
 * Returns: void
 */
static void
freetunnel(int tnum)
{

	(void) rw_wrlock(&gbl_tunnelLock);

	assert(mnaddr_tunl[tnum].refcnt == 0);

	mnaddr_tunl[tnum].mnaddr = 0;
	mipverbose(("Freeing tunnel module number %d\n", tnum));

	(void) rw_unlock(&gbl_tunnelLock);
} /* freetunnel */


/*
 * Gets the tunnel number corresponding to given
 * mobile node address .
 * If the corresponding tunnel number exist then it return s the tunnel no.
 * else return s -(TUNNEL_NOT_FOUND)
 */
/*
 * Function: gettunnelno
 *
 * Arguments: ipaddr_t mnaddr
 *	      ipaddr_t tsrc_addr
 *
 * Description: Returns the tunnel number corresponding to a given mobile
 * 		node address.  If the corresponding tunnel number exists, then
 * 		it returns the tunnel number.  Otherwise it returns (-1)
 *              When called from HA mnaddr=mnaddr.
 *		when called from FA mnaddr=haaddr
 *		Tunnel source end-point addr=tsrc_addr
 *
 * Returns: int (Tunnel Number, -1 on failure)
 */
int
gettunnelno(ipaddr_t mnaddr, ipaddr_t tsrc_addr)
{
	int i;
	int found = _B_FALSE;

	(void) rw_rdlock(&gbl_tunnelLock);

	for (i = 0; i < MAX_TUNNEL_SUPPORTED; i++) {
		if (mnaddr_tunl[i].mnaddr == mnaddr &&
		    mnaddr_tunl[i].tunnelsrc == tsrc_addr) {
			found = _B_TRUE;
			break;
		}
	}

	(void) rw_unlock(&gbl_tunnelLock);

	if (found == _B_TRUE) {
	    return (i);
	} else {
	    return (-1);
	}
} /* gettunnelno */

#if 0
/*
 * Function: printtunnels
 *
 * Arguments: none
 *
 * Description: This function prints out all the tunnels.  It is used for
 * 		debugging.
 *
 * Returns: void
 */
void
printtunnels()
{
	int i;
	char mnaddr[INET_ADDRSTRLEN];

	(void) rw_rdlock(&gbl_tunnelLock);

	for (i = 0; i < MAX_TUNNEL_SUPPORTED; i++) {
		if (mnaddr_tunl[i].mnaddr != 0) {
			mipverbose(("Tunnel %d is for %s with refcnt %d\n",
			    i, ntoa(mnaddr_tunl[i].mnaddr, mnaddr),
			    mnaddr_tunl[i].refcnt));
		}
	}

	(void) rw_unlock(&gbl_tunnelLock);
} /* printtunnels */
#endif


/* Convert a negative error value into a human readable error message */
/*
 * Function: err2str
 *
 * Arguments: int errval
 *
 * Description: This function tries to return an error message based on
 * 		an error code, or errno.  It first checks for special errors,
 * 		then checks the strerror string.
 * 		WARNING:  If the error is not found, then it returns a
 * 		pointer to a static string.  This function is NOT thread safe.
 *
 * Returns: char * (error string)
 */
char *
err2str(int errval)
{
	int err =  (-1 * errval);
	static char tmp[30];

	switch (err) {
		case INVALID_PPA:
			return ("Invalid PPA");

		case INVALID_STRING:
			return ("Invalid input string");

		case DLOKACK_SHORT_RESPONSE:
			return ("Short DLOKACK response");

		case DLOKACK_NOT_M_PCPROTO:
			return ("DLOKACK is not M_PCPROTO");

		case ERR_MORECTL:
			return ("MORECTL");

		case ERR_MOREDATA:
			return ("MOREDATA");

		case ERR_MORECTLDATA:
			return ("MORECTL or MOREDATA");

		case SHORT_CONTROL_PORTION:
			return ("Control portion is short");

		case DL_PRIMITIVE_ERROR:
			return ("DL primitive error");

		case INVALID_ADDR:
			return ("Invalid Address");

		case MN_ENTRY_ABSENT:
			return ("Missing Mobile node entry");

		case NO_MAPPING:
			return ("Bad ARP mapping for mobile node");

		default:
		{
			/* Check for errno error */
			char *reason;

			reason = strerror(err);

			if (reason != NULL) {
				return (reason);
			} else {
				(void) sprintf(tmp, "Reason unclear : %d",
				    err);
				return (tmp);
			}
		}
	} /* switch */
} /* err2str */


/*
 * Function: ifname2devppa
 *
 * Arguments: char *ifname, char *devname, int *ppa
 *
 * Description: Parse the interface name(e.g. "le0" or "hme1") and place the
 * 		corresponding device name(e.g. "/dev/le", "/dev/hme") in
 * 		devname and the ppa(e.g. 0 or 1 for the examples above) in ppa.
 *		It expects that the caller will pass adequate buffer in
 *		'devname' such that it can hold the full devicename.
 *
 * Returns: void
 */
void
ifname2devppa(char *ifname, char *devname, int *ppa)
{
	char *p;
	int  i, j, val;

	val = 0;
	j = strlen(DEVICEDIR);
	(void) strncpy(devname, DEVICEDIR, j);
	for (i = 0, p = ifname; i < strlen(ifname); i++, p++) {
		if (*p >= '0' && *p <= '9')
			val = 10*val + (*p - '0');
		else
			devname[j++] = *p;
	}
	devname[j] = '\0';
	*ppa = val;
} /* ifname2devppa */


/*
 * Function: mkpt2pt
 *
 * Arguments: char *ifname, ipaddr_t srcaddr, ipaddr_t dstaddr
 *
 * Description: Configure the point-to-point interface named ifname with the
 * 		given address. The source address being 'srcaddr' and
 *		destination address being 'dstaddr'
 *
 * Returns: int
 */
static int
mkpt2pt(char *ifname, ipaddr_t srcaddr, ipaddr_t dstaddr)
{
	struct lifreq lifr;
	struct sockaddr_in *sin;

	/* set the interface address */
	(void) memset((char *)&lifr, 0, sizeof (lifr));
	(void) strncpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	sin = (struct sockaddr_in *)&lifr.lifr_addr;
	(void) memset(sin, 0, sizeof (*sin));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = srcaddr;

	if (ioctl(ioctl_sockid, SIOCSLIFADDR, (caddr_t)&lifr) < 0) {
		syslog(LOG_ERR, "SIOCSLIFADDR failed");
		return (-1);
	}

	/* set the remote/peer address */
	(void) memset((char *)&lifr, 0, sizeof (lifr));
	(void) strncpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	sin = (struct sockaddr_in *)&lifr.lifr_addr;
	(void) memset(sin, 0, sizeof (*sin));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = dstaddr;

	if (dstaddr && (ioctl(ioctl_sockid, SIOCSLIFDSTADDR,
	    (caddr_t)&lifr) < 0)) {
		syslog(LOG_ERR, "SIOCSIFDSTADDR failed");
		return (-1);
	}

	return (0);
} /* mkpt2pt */

/*
 * Function: InitNet
 *
 * Arguments: none
 *
 * Description: Network-related initialization, e.g. loading tunneling module
 * 		etc.  Information about each mobility supporting interface is
 * 		available in maAdvConfigHash
 *
 * Returns: int (zero on success)
 */
int
InitNet()
{
	/*
	 * Enable forwarding, disable ICMP redirects in kernel, e.g. FA
	 * should not redirect visiting mobile nodes to another router).
	 */
	(void) system(
		"/usr/sbin/ndd -set /dev/ip "
		    "ip_forwarding 1 > /dev/null 2>&1\n");
	(void) system(
		"/usr/sbin/ndd -set /dev/ip "
		    "ip_send_redirects 0 > /dev/null 2>&1\n");

	mipverbose(("IP forwarding on, ICMP redirects off.\n"));

	/* Initialize the tunnel management module */
	if (InitTunnelModule() < 0) {
		syslog(LOG_ERR, "InitTunnelModule failed.");
		return (-1);
	}

	/* Make a socket for the various SIOCxxxx ioctl commands */
	if ((ioctl_sockid = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		syslog(LOG_ERR,
		    "Error: could not create socket for SIOCxxxx commands.");
		return (-1);
	}

	/* Open a routing socket for passing route commands */
	if ((rtsock = socket(AF_ROUTE, SOCK_RAW, AF_INET)) < 0) {
		syslog(LOG_ERR,
		    "Error: could not create socket for Route commands.");
		return (-1);
	}
	return (0);
} /* InitNet */

/*
 * Function: encapadd
 *
 * Arguments: ipaddr_t target, ipaddr_t tsrc, uint32_t tdst, uint8_t tflags
 *
 * Description: Enables encapsulation of pkts meant for target addr to the
 * 	tunnel's destination addr (tdst) with the source address
 * 	being that of the specified agent (tsrc). To configure an
 * 	IP-in-IP tunnel, first get an unused tunnel number and
 * 	then plumb it.  Next, invoke any ipsec policies to ensure outbound
 *      tunnel packets to, and incomming tunnel packets from the agent-peer are
 *      protected (or we, or they will discard)!  We do NOT set the peer-flag
 *	here as it's unnecessary, and should have been done anyway when we got
 *	the registration request (peer status isn't, after all, just about
 *	having a security association).  Next set up a point-to-point
 * 	interface between the target addr (target) - this is
 * 	usually the mobile node address and address of the specified
 * 	agent (tsrc) - this is usually the home agent address;
 * 	the routine also sets up the tunnel with the source address
 * 	of the tunnel being the specified agent address (tsrc)
 * 	and the destination address of the tunnel being the
 * 	address (tdst) - this usually is the foreign agent address.
 * 	Next a number of interface specific flags are set and
 * 	the tunnel is enabled. The tunnel specific entry data is
 * 	next added to the hash table, keying on target address.
 *
 * 	If a tunnel entry already exists for the target addr
 * 	increase the entry reference count.
 *
 *	For now, tflags only identify if we're to protect a reverse tunnel,
 *      but in the future it can be used to identify when a tunnel other than
 *      an IP in IP tunnel should be set up.
 *
 * Returns: int
 */
int
encapadd(ipaddr_t target, ipaddr_t tsrc, uint32_t tdst, uint8_t tflags)
{
	int  tnum, muxfd;
	MipTunlEntry *entry;
	int tunnels_scanned;		/* no. of tunnels scanned in a */
					/* single newtunnel() call. */
	int total_tunnels_scanned;	/* total no. of tunnels scanned */
					/* in this encapadd() call. */
	MobilityAgentEntry *mae;	/* for IPsec Tunnel SA */
	ipsec_req_t *ipsr_p = NULL;	/* for ipsec tunnel policy */

	/*
	 * We don't need a MipTunlEntryLookup here to match
	 * with destination endpoint address as we know that
	 * the target(mnaddr) is unique per HA
	 */
	if ((entry = (MipTunlEntry *)findHashTableEntryUint(
		&mipTunlHash, target, LOCK_WRITE, NULL, 0, 0,
		    0)) != NULL) {
		entry->refcnt++;
		(void) rw_unlock(&entry->TunlNodeLock);
		return (0);
	}

	total_tunnels_scanned = 0;
	muxfd = -1;

	while ((total_tunnels_scanned < MAX_TUNNEL_SUPPORTED) &&
	    (muxfd == -1)) {
		if ((tnum = newtunnel(target, tsrc, &tunnels_scanned)) < 0) {
			syslog(LOG_ERR, "encapadd: couldnot find free tnum");
			return (-1);
		}
		total_tunnels_scanned += tunnels_scanned;

		if ((muxfd = plumb_one_tun(tnum)) == -1)
			freetunnel(tnum);
	}
	if (muxfd == -1) {
		syslog(LOG_ERR, "encapadd: couldnot find free tnum");
		return (-1);
	}

	/*
	 * Before we can call settaddr, we need to see if we should pass down
	 * any IPSEC SAs so treqs can be set.
	 */
	if ((mae = findMaeFromIp(tdst, LOCK_READ)) != NULL) {
		/* for encapadd, we're an HA using "ipSecTunnel apply ..." */

		if (IPSEC_TUNNEL_ANY(mae->maIPsecSAFlags[IPSEC_APPLY])) {
			/* pass down what we've parsed */
			ipsr_p = &(mae->maIPsecTunnelIPSR[IPSEC_APPLY]);
			mae->maIPsecFlags |= IPSEC_TUNNEL_APPLY;

			/* Symetric tunnels: should we set the reverse bit? */
			if (tflags & REG_REVERSE_TUNNEL)
				mae->maIPsecFlags |=
				    IPSEC_REVERSE_TUNNEL_PERMIT;
		}

		/* unlock */
		(void) rw_unlock(&mae->maNodeLock);
	}


	if (settaddr(tnum, tsrc, target, tsrc, tdst, ipsr_p) == -1) {
		syslog(LOG_ERR, "encapadd: settaddr failed");
		(void) unplumb_one_tun(muxfd);
		mipverbose(("unplumb tunnel with number %d\n", tnum));
		freetunnel(tnum);
		return (-1);
	}

	if (setifflags(tnum, IFF_UP | IFF_NORTEXCH | IFF_MIPRUNNING |
		IFF_PRIVATE) == -1) {
		syslog(LOG_ERR, "encapadd: setifflags failed");
		mipverbose(("unplumb tunnel with number %d\n", tnum));
		(void) unplumb_one_tun(muxfd);
		freetunnel(tnum);
		return (-1);
	}

	if ((entry = CreateTunlEntry(tnum, target, tsrc, muxfd)) == NULL) {
		syslog(LOG_ERR, "encapadd: CreateTunlEntry failed");
		mipverbose(("unplumb tunnel with number %d\n", tnum));
		(void) unplumb_one_tun(muxfd);
		freetunnel(tnum);
		return (-1);
	}

	entry->refcnt++;

	(void) rw_unlock(&entry->TunlNodeLock);

	return (0);
} /* encapadd */

/*
 * Function: encaprem
 *
 * Arguments: ipaddr_t target
 *
 * Description: Terminates encapulation service for target addr.
 *		First find the tunnel entry in the hash table.
 *		If this is the last reference count to the tunnel entry
 *		then unplumb the tunnel and break the tunnel association
 *		between the foreign agent and home agent for
 *		encapsulation of packets destined for the target address.
 *		Next free the tunnel and the tunnel entry from hash table.
 *
 * Returns: int -1 on failure, the tunnel reference count on success.
 */
int
encaprem(ipaddr_t target)
{
	int  tnum, muxfd;
	MipTunlEntry *entry;

	/*
	 * NOTE: We do not need to call MipTunlEntryLookup here
	 * because we assume MN home address(target) is unique per HA.
	 */
	if ((entry = (MipTunlEntry *)findHashTableEntryUint(
	    &mipTunlHash, target, LOCK_WRITE, NULL, 0, 0, 0)) == NULL) {
		syslog(LOG_ERR, "encaprem: Target entry %x missing", target);
		return (-1);
	}

	tnum = entry->tunnelno;
	muxfd = entry->mux_fd;

	if (entry->refcnt == 1) {
		(void) setifflags(entry->tunnelno,
		    -IFF_UP | -IFF_NORTEXCH | -IFF_MIPRUNNING);
		mipverbose(("unplumb tunnel with number %d\n", tnum));
		if (unplumb_one_tun(muxfd) == -1) {
			(void) rw_unlock(&entry->TunlNodeLock);
			syslog(LOG_ERR,
			    "encaprem: unplumb of tunnel %d failed", tnum);
			return (-1);
		}
	}

	/* if refcnt is 0, this encapsulation point just went away */
	if (--entry->refcnt == 0) {
		/* WORK:Todo: This should call delHashTableEntry */
		int index = HASHIT(target);
		HashTable *htbl = &mipTunlHash;
		HashEntry *p, *q;

		freetunnel(tnum);

		(void) rw_wrlock(&htbl->bucketLock[index]);
		p = htbl->buckets[index];

		while (p) {
		    if (p->key == target)
			break;
		    q = p;
		    p = p->next;
		}

		if (p == htbl->buckets[index])
			htbl->buckets[index] = p->next;
		else
			q->next = p->next;

		(void) rw_unlock(&entry->TunlNodeLock);
		(void) rwlock_destroy(&entry->TunlNodeLock);

		free(entry);
		free(p);

		(void) rw_wrlock(&htbl->hashLock);
		htbl->size--;
		(void) rw_unlock(&htbl->hashLock);

		(void) rw_unlock(&htbl->bucketLock[index]);
	} else {
		/* Release the lock held in findHashTableEntryUint */
		(void) rw_unlock(&entry->TunlNodeLock);
	}

	return (entry->refcnt);
} /* encaprem */


/*
 * Function: decapadd
 *
 * Arguments: ipaddr_t ipipsrc, ipaddr_t ipipdst
 *
 * Description: Enable decapsulation service for target addr. To configure
 *		an IP-in-IP tunnel, first get an unused tunnel number and
 *		then plumb it. Next set up a point-to-point interface
 *		between the ipipdst addr - this is usually the foreign agent
 *		address and a dummy address ("0.0.0.0"); the routine
 *		also sets up the tunnel with the source address
 *		of the tunnel being ipipdst - usually foreign agent address
 *		and the destination address of the tunnel being the address
 *		ipipsrc - this usually is the home agent address. Next a
 *		number of interface specific flags are set and the tunnel is
 *		 enabled. The tunnel specific entry data is next added to
 *		the hash table, keying on ipipsrc address.
 *
 *		If a tunnel entry already exists for the ipipsrc addr
 *		increase the entry reference count.
 *		This function is called at the foreign agent end of tunnel.
 *
 * Returns: int (zero on success)
 */
int
decapadd(ipaddr_t ipipsrc, ipaddr_t ipipdst)
{
	int  tnum, muxfd;
	MipTunlEntry *entry;
	int tunnels_scanned;		/* no. of tunnels scanned in a  */
					/* single newtunnel() call. */
	int total_tunnels_scanned;	/* total no. of tunnels scanned */
					/* in this decapadd() call. */
	MobilityAgentEntry *mae;	/* to check for IPsec policy */
	ipsec_req_t *ipsr_p = NULL;	/* for ipsec tunnel policy */

	if ((entry = (MipTunlEntry *)findHashTableEntryUint(
		&mipTunlHash, ipipsrc, LOCK_WRITE, MipTunlEntryLookup,
		    (uint32_t)ipipdst, 0, 0)) != NULL) {
		entry->refcnt++;
		(void) rw_unlock(&entry->TunlNodeLock);
		return (0);
	}

	total_tunnels_scanned = 0;
	muxfd = -1;

	while ((total_tunnels_scanned < MAX_TUNNEL_SUPPORTED) &&
	    (muxfd == -1)) {
		if ((tnum = newtunnel(ipipsrc, ipipdst,
		    &tunnels_scanned)) < 0) {
			syslog(LOG_ERR, "decapadd: couldnot find free tnum");
			return (-1);
		}
		total_tunnels_scanned += tunnels_scanned;

		if ((muxfd = plumb_one_tun(tnum)) == -1)
			freetunnel(tnum);
	}
	if (muxfd == -1) {
		syslog(LOG_ERR, "decapadd: couldnot find free tnum");
		return (-1);
	}

	/*
	 * Before tunnel is plumbed, and the interface is created, see if we
	 * have an IPsecPolicy.  If so, point at it for settaddr().
	 */
	if ((mae = findMaeFromIp(ipipsrc, LOCK_READ)) != NULL) {
		/*
		 * for decapadd, we're an FA using "IPsecTunnel permit ..."
		 * Note that we set the IPSEC_REVERSE_TUNNEL_PERMIT flag when
		 * processing for a reverse-tunnel request.
		 * Note that we don't check to see if the IPSEC_TUNNEL_PERMIT
		 * flag is set because we always want to make sure the tunnel's
		 * protected correctly.
		 */
		if (IPSEC_TUNNEL_ANY(mae->maIPsecSAFlags[IPSEC_PERMIT])) {
			/* pass down what we've parsed */
			ipsr_p = &(mae->maIPsecTunnelIPSR[IPSEC_PERMIT]);

			/* set the invoked bit in case we have to restore */
			mae->maIPsecFlags |= IPSEC_TUNNEL_PERMIT;
		}

		/* unlock */
		(void) rw_unlock(&mae->maNodeLock);
	}

	/*
	 * Tunnels in Solaris are bi-directional, with the obvious caveat that
	 * the dst address must be set.  For security reasons, we only do this
	 * if the MN is requesting a reverse tunnel.  If so, ipipsrc should be
	 * the MN's home agent address.  ipsr contains our ipsec values.
	 * From FA end the parameters are : tsrc=COA, tdst=HAA, dstaddr=0.0.0.0
	 * srcaddr=COA
	 */
	if (settaddr(tnum, ipipdst, inet_addr("0.0.0.0"), ipipdst,
	    ipipsrc, ipsr_p) == -1) {
		syslog(LOG_ERR, "decapadd: settaddr failed");
		mipverbose(("unplumb tunnel with number %d\n", tnum));
		(void) unplumb_one_tun(muxfd);
		freetunnel(tnum);
		return (-1);
	}

	if (setifflags(tnum, IFF_UP | IFF_NORTEXCH | IFF_MIPRUNNING) == -1) {
		syslog(LOG_ERR, "decapadd: setifflags failed");
		mipverbose(("unplumb tunnel with number %d\n", tnum));
		(void)  unplumb_one_tun(muxfd);
		freetunnel(tnum);
		return (-1);
	}

	/* Entry will be locked after CreateTunlEntry */
	if ((entry = CreateTunlEntry(tnum, ipipsrc, ipipdst, muxfd)) == NULL) {
		syslog(LOG_ERR, "decapadd: CreateTunlEntry failed");
		mipverbose(("unplumb tunnel with number %d\n", tnum));
		(void) unplumb_one_tun(muxfd);
		freetunnel(tnum);
		return (-1);
	}

	entry->refcnt++;
	(void) rw_unlock(&entry->TunlNodeLock);

	return (0);
} /* decapadd */

/*
 * Function: decaprem
 *
 * Arguments: ipaddr_t target : Tunnel outer destination IP address at FA
 *	      ipaddr_t tsrc   : Tunnel outer source IP address at FA
 *
 * Description: Terminates decapulation service for target address.
 *		First find the tunnel entry in the hash table.
 *		If this is the last reference count to the tunnel entry
 *		then unplumb the tunnel and break the tunnel association
 *		between the foreign agent and home agent for
 *		decapsulation of packets. Next free the tunnel and the
 *		tunnel entry from hash table.
 *
 * Returns: int (zero on success)
 */
int
decaprem(ipaddr_t target, ipaddr_t tsrc)
{
	int tnum, muxfd;
	MipTunlEntry *entry;

	if ((entry = (MipTunlEntry *)findHashTableEntryUint(
	    &mipTunlHash, target, LOCK_WRITE, MipTunlEntryLookup,
	    (uint32_t)tsrc, 0, 0)) == NULL) {
		syslog(LOG_ERR, "encaprem: Target entry %x missing", target);
		return (-1);
	}

	tnum = entry->tunnelno;
	muxfd = entry->mux_fd;

	if (entry->refcnt == 1) {
		(void) setifflags(entry->tunnelno,
		    -IFF_UP | -IFF_NORTEXCH | -IFF_MIPRUNNING);
		mipverbose(("unplumb tunnel with number %d\n", tnum));
		if (unplumb_one_tun(muxfd) == -1) {
			(void) rw_unlock(&entry->TunlNodeLock);
			syslog(LOG_ERR,
			    "decaprem: unplumb of tunnel %d failed", tnum);
		    return (-1);
		}
	}


	if (--entry->refcnt == 0) {
		int index = HASHIT(target);
		HashTable *htbl = &mipTunlHash;
		HashEntry *p, *q;
		MipTunlEntry *Tunentry;

		freetunnel(tnum);

		(void) rw_wrlock(&htbl->bucketLock[index]);
		p = htbl->buckets[index];

		while (p) {
			Tunentry = (MipTunlEntry *)p->data;
			if (p->key == target && Tunentry->tunnelsrc == tsrc)
				break;
			q = p;
			p = p->next;
		}

		if (p == htbl->buckets[index])
			htbl->buckets[index] = p->next;
		else
			q->next = p->next;

		(void) rw_unlock(&entry->TunlNodeLock);
		(void) rwlock_destroy(&entry->TunlNodeLock);

		free(entry);
		free(p);

		(void) rw_wrlock(&htbl->hashLock);
		htbl->size--;
		(void) rw_unlock(&htbl->hashLock);

		(void) rw_unlock(&htbl->bucketLock[index]);
	} else {
		/*
		 * Release the lock. Other mobile node(s) may be
		 * using this tunnel.
		 */
		(void) rw_unlock(&entry->TunlNodeLock);
	}

	return (entry->refcnt);
}


/*
 * Function: MipTunlEntryLookup
 * Arguments: entry - Pointer to MipTunl entry
 *            p1- First parameter to match (Tunnel src-endpoint IPaddr)
 *            p2- Second Parameter to match (unused)
 *	      p3- Second Parameter to match (unused)
 * Description:
 *	This function is used to lookup a tunnel entry which is hashed
 *	by the tunnel destination endpoint address and matched with
 *	it's source end point address. This matching is necessary
 *	to support multihomed foreign agent with more than one COAs
 */
/* ARGSUSED */
boolean_t
MipTunlEntryLookup(void *entry, uint32_t p1, uint32_t p2, uint32_t p3)
{
	MipTunlEntry *Tunentry = entry;

	if (Tunentry->tunnelsrc == (ipaddr_t)p1)
		return (_B_TRUE);
	return (_B_FALSE);
}

/*
 * Function: arpadd
 *
 * Arguments: ipaddr_t host, unsigned char *eaddr, char *flag
 *
 * Description: Adds an arp entry with ip address set to host and hardware
 *		address set to eaddr with approriate flags specified by flag
 * 		argument, e.g. arpadd(inet_addr("129.146.122.121"),
 * 		"08:20:AB:FE:33:11", "pub") creates a proxy ARP entry for
 * 		129.146.122.121.
 *
 * Returns: int
 */
int
arpadd(ipaddr_t host, unsigned char *eaddr, unsigned int flags)
{
	struct arpreq ar;
	struct sockaddr_in *sin;

	bzero((caddr_t)&ar, sizeof (ar));
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	sin = (struct sockaddr_in *)&ar.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = (host);

	(void) memcpy(ar.arp_ha.sa_data, eaddr, ETH_ALEN);

	ar.arp_flags = ATF_PERM | flags;
#if 0
	if (strncmp(flag, "temp", 4) == 0)
	    ar.arp_flags &= ~ATF_PERM;
	if (strncmp(flag, "pub", 3) == 0)
	    ar.arp_flags |= ATF_PUBL;
	if (strncmp(flag, "trail", 5) == 0)
	    ar.arp_flags |= ATF_USETRAILERS;
#endif

	if (ioctl(ioctl_sockid, SIOCSARP, (caddr_t)&ar) < 0) {
	    if (errno != EEXIST)
		return ((-1) * errno);
	}

	return (0);
} /* arpadd */


/*
 * Function: arpdel
 *
 * Arguments: ipaddr_t host
 *
 * Description: Deletes an arp entry for ip address set to host
 *
 * Returns: int (zero on success)
 */
int
arpdel(ipaddr_t host)
{
	struct arpreq ar;
	struct sockaddr_in *sin;

	bzero((caddr_t)&ar, sizeof (ar));
	ar.arp_pa.sa_family = AF_INET;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	sin = (struct sockaddr_in *)&ar.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = (host);

	if (ioctl(ioctl_sockid, SIOCDARP, (caddr_t)&ar) < 0) {
	    if (errno != ENXIO)
		return ((-1) * errno);
	}
	return (0);
} /* arpdel */


/*
 * Function: arpgetHWaddr
 *
 * Arguments: ipaddr_t mnaddr, unsigned char *mnetheraddr
 *
 * Description: Get the hardware address corresponding to mnaddr from
 * 		the arp table.
 *
 * Returns: int (zero on success)
 */
static int
arpgetHWaddr(ipaddr_t mnaddr, unsigned char *mnetheraddr)
{
	struct arpreq ar;
	struct sockaddr_in *sin;

	bzero((caddr_t)&ar, sizeof (ar));
	ar.arp_pa.sa_family = AF_INET;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	sin = (struct sockaddr_in *)&ar.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = mnaddr;

	if (ioctl(ioctl_sockid, SIOCGARP, (caddr_t)&ar) < 0)
		return (-1 * (errno));
	else {
		(void) memcpy(mnetheraddr, ar.arp_ha.sa_data, ETH_ALEN);
		return (0);
	}
} /* arpgetHWaddr */


/*
 * Function: arprefresh
 *
 * Arguments: HaMobileNodeEntry *hentry, ipaddr_t mnaddr
 *
 * Description: Sends gratuitous arp for the mnaddr using the hardware address
 * 		found for mnaddr in its own ARP cache (making sure that the
 *		hardware address is not HA's own). The home agent calls
 *		arprefresh when a mobile node returns home and successfully
 *		deregisters itself.
 *
 * Returns: int (zero on success)
 */
int
arprefresh(HaMobileNodeEntry *hentry, ipaddr_t mnaddr)
{
	int ret;
	ipaddr_t ifaceaddr;
	char devname[LIFNAMSIZ + 1];
	unsigned char hainterfaceaddr[ETH_ALEN + 1];
	unsigned char mnetheraddr[ETH_ALEN + 1];
	unsigned char zero_addr[ETH_ALEN + 1] = {0x00, 0x00, 0x00,
						0x00, 0x00, 0x00};
	MaAdvConfigEntry *mentry;

	mipverbose(("Arp refresh called for %d.%d.%d.%d\n",
	    (unsigned char) ((ntohl(mnaddr) >> 24) & 0xff),
	    (unsigned char) ((ntohl(mnaddr) >> 16) & 0xff),
	    (unsigned char) ((ntohl(mnaddr) >> 8) & 0xff),
	    (unsigned char) (ntohl(mnaddr) & 0xff)));

	ifaceaddr = hentry->haBindingIfaceAddr;

	/* Get the matching maIfaceAddr from mnAdvConfigTable */
	if ((mentry = (MaAdvConfigEntry *)findHashTableEntryUint(
	    &maAdvConfigHash, ifaceaddr, LOCK_NONE, NULL, 0, 0, 0)) == NULL) {
		syslog(LOG_ERR, "Unable to find interface in hash table");
		return (-1 * MN_ENTRY_ABSENT); /* Unlikely to occur */
	}

	(void) strcpy(devname, mentry->maIfaceName);
	(void) memcpy(hainterfaceaddr, mentry->maIfaceHWaddr, ETH_ALEN);

	if ((ret = arpgetHWaddr(mnaddr, mnetheraddr)) < 0)
		return (ret);

	if ((memcmp(hainterfaceaddr, mnetheraddr, ETH_ALEN) == 0) ||
	    (memcmp(zero_addr, mnetheraddr, ETH_ALEN) == 0))
		return (-1 * NO_MAPPING);
	else
		return (garp(devname, mnaddr, mnetheraddr));
} /* arprefresh */

/*
 * Function: routemodify
 *
 * Arguments: ipaddr_t dst, ipaddr_t gw,
 *	      ipaddr_t insrc, int in_if, int out_if,
 *	      unsigned int cmd
 *
 * Description: Add or Delete route depending on 'cmd' argument.
 *		'cmd' argument can be either ADDRT or DELRT.
 * 		For adding/deleting route from registration
 *		process and reply functions, only dst,gw args
 *		are required. Thus that is defined as simple route.
 *		NOTE: simple route is not used by mipagent registration
 *		reply process as it uses IP_XMIT_IF socket option
 *		instead of simple route. Simple route can not distinguish
 *		between two different mobile nodes with same private
 *		addresses. But the code still contains simple route
 *		section, in case it's needed in future for any purpose.
 *		After the visitor is accepted at FA, the
 *		forward route created from FA to MN to relay the
 * 		packet from tunnel from home agent is defined
 *		as 'ftun_route'. This route must have in_if and out_if
 *		index arguments. For reverse tunnel route, this
 *		function expects a valid in_if and a valid out_if
 *		value and a non-zero source address(insrc). For ftun_route
 *		insrc must be zero.
 *
 *		To set up forward route  to reach MN:
 *		dst= MN's home addr, gw= COA, in_if=tun's if_index
 *		out_if = FA's interface index on which MN is attached.
 *		insrc = 0.0.0.0
 *
 *		To set up reverse tunnel route:
 *		dst = 0.0.0.0  gw = 0.0.0.0 in_if = FA's interface index on
 *		which MN is attached, out_if = tunnel's interface index.
 *		insrc = MN's homeaddr
 *
 * Returns: int (zero on success)
 */
int
routemodify(ipaddr_t dst, ipaddr_t gw, ipaddr_t insrc, int in_if,
    int out_if, unsigned int cmd)
{
	struct	rt_msghdr	*rt_msg;
	struct	sockaddr_in	*dstaddr;
	struct	sockaddr_in	*gwaddr;
	struct	sockaddr_in	*insrcaddr;
	struct	sockaddr_dl	*rta_ifp;
	struct	sockaddr_dl	*rta_srcifp;
	char	*cp;
	static	int		rtmseq;
	int	rlen;
	int	flags = RTF_STATIC | RTF_UP;
	boolean_t rtun_route = _B_FALSE; /* when insrc!=0, in_if, out_if !=0  */
	boolean_t ftun_route = _B_FALSE; /* when insrc==0, in_if!=0 */

	if (insrc == INADDR_ANY && in_if == 0 && out_if == 0) {
		/* Simple route case dst<->gw: not used by mipagent */
		flags = RTF_HOST | RTF_PRIVATE;
		rlen = MIP_RTM_MSGLEN;
	} else if (insrc == INADDR_ANY && in_if != 0 && out_if != 0) {
		/* Forward route to MN from tunnel */
		ftun_route = _B_TRUE;
		flags = RTF_HOST | RTF_PRIVATE;
		rlen = MIP_RTM_MSGLEN + 2 * (sizeof (struct sockaddr_dl));
	} else if (insrc != INADDR_ANY && in_if != 0 && out_if != 0) {
		/* Reverse tunnel route: insrc != 0 */
		rtun_route = _B_TRUE;
		flags = RTF_GATEWAY | RTF_PRIVATE;
		rlen = MIP_RTUN_RTM_MSGLEN;
	} else {
		/* Invalid Call */
		return (-1 * EINVAL);
	}

	rt_msg = (struct rt_msghdr *)malloc(rlen);
	if (rt_msg == NULL) {
		syslog(LOG_ERR, "route_modify: Cannot allocate memory");
		return (-1 * (errno));
	}

	bzero(rt_msg, rlen);
	rt_msg->rtm_msglen = rlen;
	rt_msg->rtm_version = RTM_VERSION;
	rt_msg->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
	rt_msg->rtm_pid = getpid();
	if (cmd == ADDRT)
		rt_msg->rtm_type = RTM_ADD;
	else
		rt_msg->rtm_type = RTM_DELETE;

	rt_msg->rtm_seq = ++rtmseq;
	rt_msg->rtm_flags = flags;

	cp = (char *)rt_msg + sizeof (struct rt_msghdr);

	/* DST */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	dstaddr = (struct sockaddr_in *)cp;
	dstaddr->sin_family = AF_INET;
	if (!rtun_route)
		dstaddr->sin_addr.s_addr = dst;
	else
		dstaddr->sin_addr.s_addr = INADDR_ANY;

	/* GATEWAY */
	cp += sizeof (struct sockaddr_in);
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	gwaddr = (struct sockaddr_in *)cp;
	gwaddr->sin_family = AF_INET;
	gwaddr->sin_addr.s_addr = gw;

	/* NETMASK */
	cp += sizeof (struct sockaddr_in);
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	dstaddr = (struct sockaddr_in *)cp;
	dstaddr->sin_family = AF_INET;

	if (!rtun_route) {
		dstaddr->sin_addr.s_addr = IP_HOST_MASK;
	} else {
		dstaddr->sin_addr.s_addr = INADDR_ANY;
	}

	/* Check if ftun_route or rtun_route is set, else it's simple_route */

	if (ftun_route) {
		/*
		 * We need to set both RTA_IFP and RTA_SRCIFP
		 * in order to support Lucent PPP interfaces to
		 * mobile nodes. Since there may not be an interface
		 * route for the dynamically plumbed PPP interfaces
		 * which are used in 3Gwireless technology to connect
		 * to the mobile node from the PDSN (Packet Data Service
		 * Network, IS-835, TIA document), thus the foreign agent
		 * (PDSN) end of PPP interface may have non-unique address
		 * (for example, all these special PPP interfaces may have
		 * same address, COA in the PDSN end). So it is not
		 * possible to derive interface index from the supplied
		 * gateway address. Hence the caller of this function
		 * must provide both outgoing and incoming interface
		 * index when creating the forward tunnel.
		 */
		rt_msg->rtm_addrs |= RTA_IFP | RTA_SRCIFP;

		/* IFP */
		cp += sizeof (struct sockaddr_in);
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		rta_ifp = (struct sockaddr_dl *)cp;
		rta_ifp->sdl_family = AF_LINK;
		rta_ifp->sdl_index = out_if;

		/* SRCIFP */
		cp += sizeof (struct sockaddr_dl);
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		rta_srcifp = (struct sockaddr_dl *)cp;
		rta_srcifp->sdl_family = AF_LINK;
		rta_srcifp->sdl_index = in_if;

	} else if (rtun_route) {

		/* it's a reverse tunnel route */

		rt_msg->rtm_addrs |= (RTA_IFP | RTA_SRC | RTA_SRCIFP);

		/* IFP */
		cp += sizeof (struct sockaddr_in);
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		rta_ifp = (struct sockaddr_dl *)cp;
		rta_ifp->sdl_family = AF_LINK;
		rta_ifp->sdl_index = out_if;

		/* SRC */
		cp += sizeof (struct sockaddr_dl);
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		insrcaddr = (struct sockaddr_in *)cp;
		insrcaddr->sin_family = AF_INET;
		insrcaddr->sin_addr.s_addr = insrc;

		/* SRCIFP */
		cp += sizeof (struct sockaddr_in);
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		rta_srcifp = (struct sockaddr_dl *)cp;
		rta_srcifp->sdl_family = AF_LINK;
		rta_srcifp->sdl_index = in_if;
	}

	/* Send the routing message */
	rlen = write(rtsock, rt_msg, rt_msg->rtm_msglen);
	if (rlen > 0) {
		if (cmd == ADDRT)
			mipverbose(("Added route\n"));
		else
			mipverbose(("Deleted route\n"));
	}
	/* Free rt_msg now */
	free((void *)rt_msg);

	if (rlen < 0)
		return ((-1) * (errno));

	return (0);
} /* routemodify */

/* Routines for refresh_mn_arp() */
/* -------- Start of dlcommon routines */
/*
 * Common (shared) DLPI test routines.
 * Mostly pretty boring boilerplate sorta stuff.
 * These can be split into individual library routines later
 * but it's just convenient to keep them in a single file
 * while they're being developed.
 *
 * Not supported:
 *   Connection Oriented stuff
 *   QOS stuff
 */


/*
 * Function: dlinforeq
 *
 * Arguments: fd
 *
 * Description:
 *
 * Returns: int
 */
static int
dlinforeq(int fd)
{
	dl_info_req_t	info_req;
	struct	strbuf	ctl;

	info_req.dl_primitive = DL_INFO_REQ;

	ctl.maxlen = 0;
	ctl.len = sizeof (info_req);
	ctl.buf = (char *)&info_req;

	if (putmsg(fd, &ctl, (struct strbuf *)NULL, RS_HIPRI) < 0) {
		return (-1 * errno);
	}
	return (0);
} /* dlinforeq */


/*
 * Function: dlinfoack
 *
 * Arguments: fd, bufp
 *
 * Description:
 *
 * Returns: int
 */
static int
dlinfoack(int fd, char *bufp)
{
	union DL_primitives	*dlp;
	struct strbuf ctl;
	int flags;
	int ret;

	ctl.maxlen = MAXDLBUF;
	ctl.len = 0;
	ctl.buf = bufp;

	(void)  strgetmsg(fd, &ctl, (struct strbuf *)NULL, &flags);

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	dlp = (union DL_primitives *)ctl.buf;

	if ((ret = expecting(DL_INFO_ACK, dlp)) < 0) {
		(void) close(fd);
		return (ret);
	}

	if (ctl.len < sizeof (dl_info_ack_t)) {
		return (-1 * DLOKACK_SHORT_RESPONSE);
	}

	if (flags != RS_HIPRI) {
		return (-1 * DLOKACK_NOT_M_PCPROTO);
	}

	if (ctl.len < sizeof (dl_info_ack_t)) {
		return (-1 * DLOKACK_SHORT_RESPONSE);
	}

	return (0);
} /* dlinfoack */


/*
 * Function: dlattachreq
 *
 * Arguments: fd, ppa
 *
 * Description:
 *
 * Returns: int
 */
int
dlattachreq(int fd, int ppa)
{
	dl_attach_req_t attach_req;
	struct strbuf ctl;

	attach_req.dl_primitive = DL_ATTACH_REQ;
	attach_req.dl_ppa = ppa;

	ctl.maxlen = 0;
	ctl.len = sizeof (attach_req);
	ctl.buf = (char *)&attach_req;

	if (putmsg(fd, &ctl, (struct strbuf *)NULL, 0) < 0)
		return (-1 * errno);

	return (0);
} /* dlattachreq */


/*
 * Function: dlbindreq
 *
 * Arguments: fd, sap, max_conind, service_mode, conn_mgmt, xidtest
 *
 * Description:
 *
 * Returns: int
 */
int
dlbindreq(int fd, uint32_t sap, uint32_t max_conind, uint32_t service_mode,
	uint32_t conn_mgmt, uint32_t xidtest)
{
	dl_bind_req_t bind_req;
	struct strbuf ctl;

	bind_req.dl_primitive = DL_BIND_REQ;
	bind_req.dl_sap = sap;
	bind_req.dl_max_conind = max_conind;
	bind_req.dl_service_mode = service_mode;
	bind_req.dl_conn_mgmt = conn_mgmt;
	bind_req.dl_xidtest_flg = xidtest;

	ctl.maxlen = 0;
	ctl.len = sizeof (bind_req);
	ctl.buf = (char *)&bind_req;

	if (putmsg(fd, &ctl, (struct strbuf *)NULL, 0) < 0)
		return (-1 * errno);

	return (0);
} /* dlbindreq */

/*
 * Function: dlunitdatareq
 *
 * Arguments: int fd, unsigned char *addrp, int addrlen, ulong_t minpri
 *		ulong_t maxpri, unsigned char *datap, int datalen)
 *
 * Description:
 *
 * Returns: int
 */
static int
dlunitdatareq(int fd, unsigned char *addrp, int addrlen, ulong_t minpri,
	ulong_t maxpri, unsigned char *datap, int datalen)
{
	long buf[MAXDLBUF];
	union DL_primitives	*dlp;
	struct strbuf data, ctl;

	dlp = (union DL_primitives *)buf;

	dlp->unitdata_req.dl_primitive = DL_UNITDATA_REQ;
	dlp->unitdata_req.dl_dest_addr_length = addrlen;
	dlp->unitdata_req.dl_dest_addr_offset = sizeof (dl_unitdata_req_t);
	dlp->unitdata_req.dl_priority.dl_min = minpri;
	dlp->unitdata_req.dl_priority.dl_max = maxpri;

	(void)  memcpy(OFFADDR(dlp, sizeof (dl_unitdata_req_t)), addrp,
	    addrlen);

	ctl.maxlen = 0;
	ctl.len = sizeof (dl_unitdata_req_t) + addrlen;
	ctl.buf = (char *)buf;

	data.maxlen = 0;
	data.len = datalen;
	data.buf = (char *)datap;

	if (putmsg(fd, &ctl, &data, 0) < 0)
		return (-1 * errno);

	return (0);
} /* dlunitdatareq */


/*
 * Function: dlokack
 *
 * Arguments: int fd, char *bufp
 *
 * Description:
 *
 * Returns: int
 */
int
dlokack(int fd, char *bufp)
{
	union DL_primitives	*dlp;
	struct	strbuf	ctl;
	int	flags;
	int ret;

	ctl.maxlen = MAXDLBUF;
	ctl.len = 0;
	ctl.buf = bufp;

	(void)  strgetmsg(fd, &ctl, (struct strbuf *)NULL, &flags);

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	dlp = (union DL_primitives *)ctl.buf;

	if ((ret = expecting(DL_OK_ACK, dlp)) < 0)
		return (ret);

	if (ctl.len < sizeof (dl_ok_ack_t))
		return (-1 * DLOKACK_SHORT_RESPONSE);

	if (flags != RS_HIPRI)
		return (-1 * DLOKACK_NOT_M_PCPROTO);

	if (ctl.len < sizeof (dl_ok_ack_t))
		return (-1 * DLOKACK_SHORT_RESPONSE);

	return (0);
} /* dlokack */


/*
 * Function: dlbindack
 *
 * Arguments: int fd, char *bufp
 *
 * Description:
 *
 * Returns: int
 */
int
dlbindack(int fd, char *bufp)
{
	union DL_primitives	*dlp;
	struct strbuf	ctl;
	int	flags;
	int ret;

	ctl.maxlen = MAXDLBUF;
	ctl.len = 0;
	ctl.buf = bufp;

	(void) strgetmsg(fd, &ctl, (struct strbuf *)NULL, &flags);

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	dlp = (union DL_primitives *)ctl.buf;

	if ((ret = expecting(DL_BIND_ACK, dlp)) < 0)
		return (ret);

	if (flags != RS_HIPRI)
		return (-1 * DLOKACK_NOT_M_PCPROTO);

	if (ctl.len < sizeof (dl_bind_ack_t))
		return (-1 * DLOKACK_SHORT_RESPONSE);

	return (0);
} /* dlbindack */


/*
 * Function: strgetmsg
 *
 * Arguments: int fd, struct strbuf *ctlp, struct strbuf *datap, int *flagsp,
 * 		char *caller
 *
 * Description:
 *
 * Returns: int
 */
static int
strgetmsg(int fd, struct strbuf *ctlp, struct strbuf *datap, int *flagsp)
{
	int	rc;

	/*
	 * Set flags argument and issue getmsg().
	 */
	*flagsp = 0;
	if ((rc = getmsg(fd, ctlp, datap, flagsp)) < 0) {
		return (-1 * errno);
	}

	/*
	 * Check for MOREDATA and/or MORECTL.
	 */
	if ((rc & (MORECTL | MOREDATA)) == (MORECTL | MOREDATA))
		return (-1 * ERR_MORECTLDATA);

	if (rc & MORECTL)
		return (-1 * ERR_MORECTL);

	if (rc & MOREDATA)
		return (-1 * ERR_MOREDATA);

	/*
	 * Check for at least sizeof (long) control data portion.
	 */
	if (ctlp->len < sizeof (long))
		return (-1 * SHORT_CONTROL_PORTION);

	return (0);
} /* strgetmsg */


/*
 * Function: expecting
 *
 * Arguments: int prim, union DL_primitives *dlp
 *
 * Description:
 *
 * Returns: int (zero on success)
 */
static int
expecting(int prim, union DL_primitives *dlp)
{
	if (dlp->dl_primitive != (ulong_t)prim)
		return (-1 * DL_PRIMITIVE_ERROR);

	return (0);
} /* expecting */


/*
 * Function: MAaddrtostring
 *
 * Arguments: unsigned char *addr, ulong_t length, unsigned char *s
 *
 * Description: return hardware address as string.
 *
 * Returns: void
 */
static void
MAaddrtostring(unsigned char *addr, ulong_t length, unsigned char *s)
{
	int	i;

	for (i = 0; i < length; i++) {
		(void)  sprintf((char *)s, "%x:", addr[i] & 0xff);
		s = s + strlen((char *)s);
	}
	if (length)
		*(--s) = '\0';
} /* MAaddrtostring */

#if 0
/*
 * Function: stringtoaddr
 *
 * Arguments: char *sp, char *addr
 *
 * Description: This function converts the string to an address.
 *
 * Returns: int (length of address)
 */
int
stringtoaddr(char *sp, char *addr)
{
	int n = 0;
	char *p;
	unsigned int val;

	p = sp;
	while (p = strtok(p, ":")) {
		if (sscanf(p, "%x", &val) != 1)
		return (-1 * INVALID_STRING);
		if (val > 0xff)
		return (-1 * INVALID_STRING);
		*addr++ = val;
		n++;
		p = NULL;
	}

	return (n);
} /* stringtoaddr */

#endif
/* -------- End of dlcommon routines */

/*
 * The parms are as follows:
 * device	String definition of the device (e.g. "/dev/le").
 * ppa		Int for the instance of the device (e.g. 3, for "le3").
 * phys		Byte String for the dst MAC address of this packet.
 * This is just the bcast address("ff:ff:ff:ff:ff:ff")
 * physlen	Length (int) of the mac address (not the string). E.g:
 *		6 for enet.
 * ipaddr	long for the ip address of the host we are advertising
 *		our mac address for.
 * ether_addr   Ether address we want to set for the ipaddress we are
 * impersonating
 * NOTE: The mac addr of this system is not passed in, it is obtained
 * 	directly from the dlpi info ack structure.
 * Steps executed :-
 * -----------------
 * Open datalink provider.
 * Attach to PPA.
 * Bind to sap
 * Send arp request as DL_UNITDATA_REQ msg
 *
 */
static int send_gratuitous_arp(char *device, int ppa, unsigned char *phys,
	int physlen, ipaddr_t ipaddr, unsigned char *ether_addr)
{
	int saplen;
	int	size = sizeof (struct ether_arp);
	int	sapval = ETHERTYPE_ARP;
	int	localsap = ETHERTYPE_ARP;
	int	fd;
	char buf[MAXDLBUF];
	unsigned char sap[MAXDLADDR];
	unsigned char addr[MAXDLADDR];
	int	addrlen;
	struct ether_arp req;
	union DL_primitives	*dlp;
	int	i, ret;
	ipaddr_t target_ipaddr = ipaddr;


	/* initialize buf[] */
	for (i = 0; i < MAXDLBUF; i++)
	buf[i] = (unsigned char) i & 0xff;

	/* Open the device. */
	if ((fd = open(device, 2)) < 0)
		return (-1 * errno);

	/* Attach. */
	if ((ret = dlattachreq(fd, ppa)) < 0) {
		(void) close(fd);
		return (ret);
	}

	if ((ret = dlokack(fd, buf)) < 0) {
		(void) close(fd);
		return (ret);
	}

	/* Bind. */
	if ((ret = dlbindreq(fd, localsap, 0, DL_CLDLS, 0, 0)) < 0) {
		(void) close(fd);
		return (ret);
	}

	if ((ret = dlbindack(fd, buf)) < 0) {
		(void) close(fd);
		return (ret);
	}

	/* Get info */
	if ((ret = dlinforeq(fd)) < 0) {
		(void) close(fd);
		return (ret);
	}

	if ((ret = dlinfoack(fd, buf)) < 0) {
		(void) close(fd);
		return (ret);
	}

	/*
	 * Verify sap and phys address lengths.
	 */

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	dlp = (union DL_primitives *)buf;

	MAaddrtostring(OFFADDR(dlp, dlp->info_ack.dl_addr_offset),
	dlp->info_ack.dl_addr_length, addr);

	saplen = ABS(dlp->info_ack.dl_sap_length);

	/*
	 * Convert destination address string to address.
	 */
	for (i = 0; i < saplen; ++i) {
		int rev_index = saplen - 1 -i;
		sap[i] = (sapval >> (rev_index * BITSPERBYTE)) & 0xff;
	}

	/*
	 * printdlprim(dlp);
	 */
	if (physlen != (dlp->info_ack.dl_addr_length - saplen)) {
		(void) close(fd);
		return (-1 * INVALID_ADDR);
	}

	addrlen = saplen + physlen;

	/*
	 * Construct destination address.
	 */
	if (dlp->info_ack.dl_sap_length > 0) {	/* order is sap+phys */
		(void) memcpy(addr, sap, saplen);
		(void) memcpy(addr + saplen, phys, physlen);

		/* obtain our MAC address */
		/*
		 * (void) memcpy((char *)my_etheraddr,
		 * (char *)OFFADDR(dlp,
		 *	dlp->info_ack.dl_addr_offset + saplen),
		 *	physlen);
		 */
	} else {	/* order is phys+sap */
		(void) memcpy(addr, phys, physlen);
		(void) memcpy(addr + physlen, sap, saplen);

		/* Obtain our MAC address */
		/*
		 * (void) memcpy((char *)my_etheraddr,
		 * (char *)OFFADDR(dlp, dlp->info_ack.dl_addr_offset), physlen);
		 */
	}

	/* create arp request */
	(void) memset(&req, 0, sizeof (req));
	req.arp_hrd = htons(ARPHRD_ETHER);
	req.arp_pro = htons(ETHERTYPE_IP);
	req.arp_hln = ETHERADDRL;
	req.arp_pln = IPADDRL;
	req.arp_op = htons(ARPOP_REQUEST);
	(void) memcpy(&req.arp_sha, ether_addr, ETHERADDRL);
	(void) memcpy(&req.arp_spa, &ipaddr, IPADDRL);
	(void) memcpy(&req.arp_tpa, &target_ipaddr, IPADDRL);

	/* Transmit it. */

	if ((ret =
	    dlunitdatareq(fd, addr, addrlen, 0, 0, (unsigned char *)&req,
		size)) < 0) {
	    (void) close(fd);
		return (ret);
	}

	(void) close(fd);
	return (0);
} /* send_gratuitous_arp() */


/*
 * SYNOPSIS:
 *	garp interface ipaddr ether_addr
 *
 * RETURN VALUE :
 * Returns 0 on success else -(error code)
 * "interface" is the interface to send the grarp out on.
 * "interface" is expressed in ifname convention(e.g. "le0", "bf2"),
 * and it will be converted by ifname2device_ppa() into the dlpi convention
 * (e.g. "/dev/le" + "0" and "/dev/bf" + "2").
 * "ipaddr" is the ipaddr of the system we're "impersonating"
 * ether_addr is the ethernet address to which we want to be impersonated.
 * Sends a gratuitous arp to hw addr ff:ff:ff:ff:ff:ff.
 *
 * The arp packet  fields are filled in as follows:
 * (To be in conformance gratuitous arp described in RFC2002)
 * In the gratuitous arp packet for Mobile - IP :
 * Ethernet header :
 * Source address	: Its own hardware address
 * Destination address : ff:ff:ff:ff:ff:ff(Broadcast address)
 * Frame Type		: 0x0806 Arp Request/Reply
 *
 * Arp Packet :
 * Format of hardware address : ARPHRD_ETHER	1
 * Format of protocol address : 0x0800
 * Length of hardware address : ETH_ALEN	6
 * Length of protocol address :			4
 * ARP opcode : ARPOP_REQUEST  1
 * Sender hardware address : Ethernet address to which to be updated.
 * Destination harware address : XXXX Don't Care
 * Sender IP address	: IP Address(Cache entry to be updated)
 * Target IP address	: Sender IP Address.
 * For an ARP Request Packet :
 *
 * Note : For ARP Reply packet target IP address should be set same
 * as source IP address
 *
 * Modified from gabriels's arp module which was
 * blatantly stolen from dlunitdatareq.c by Neal Nuckolls. Just added
 * stuff to compose an arp packet.
 */
int
garp(char *dev, ipaddr_t mnaddr, unsigned char *mnetheraddr)
{
	int ppa;
	unsigned char phys[MAXDLADDR];
	char device[MAX_INPUT];

	ifname2devppa(dev, device, &ppa);
	(void) memset(phys, 0xff, ETH_ALEN);

	/* Validate arguments. */
	if (ppa < 0)
		return (-1 * INVALID_PPA);

	return (send_gratuitous_arp(device, ppa, phys, ETH_ALEN,
		mnaddr, mnetheraddr));
} /* garp */


/*
 * Function: OScleanup
 *
 * Arguments: none
 *
 * Description: Close filedescriptors for shutdown.
 *	Also cleans up the dynamic interface and static
 *	interface list entries.
 *
 * Returns: void
 */
void
OScleanup()
{
	(void) close(ioctl_sockid);
	/* Cleanup static existing interface table */
	if (dynamicIfaceHead != NULL) {
		struct dynamicIfacetype *dp;
		struct dynamicIfacetype *savep;

		dp = dynamicIfaceHead;
		while (dp != NULL) {
			savep = dp->next;
			dp->next = NULL;
			free(dp);
			dp = savep;
		}
	}
	if (StaticIntfaceHead != NULL) {
		struct staticIface *sp;
		struct staticIface *save_sp;

		sp = StaticIntfaceHead;
		while (sp != NULL) {
			save_sp = sp->next;
			sp->next = NULL;
			free(sp);
			sp = save_sp;
		}
	}
	dynamicIfaceHead = NULL;
	StaticIntfaceHead = NULL;
	ioctl_sockid = -1;
} /* OScleanup */

/*
 * Function: plumb_one_tun
 *
 * Arguments: int tnum
 *
 * Description: Plumb the tunnel interface by opening the
 * 		associated devices and pushing the required modules eg.
 * 		'tunl' module and others and then create persistent links.
 *
 * Returns: -1 on error and mux_fd is returned upon success.
 *          mux_fd will be used by unplumb_one_tun to destroy
 *          the tunnel.
 */
static int
plumb_one_tun(int tnum)
{
	struct  lifreq lifr;
	int ip_fd, mux_fd, ip_muxid;
	char name[LIFNAMSIZ];

	mipverbose(("plumb_one_tun: tunnel number %d\n", tnum));

	if ((ip_fd = open("/dev/ip", O_RDWR)) < 0) {
		syslog(LOG_ERR, "open of /dev/ip failed");
		return (-1);
	}

	if (ioctl(ip_fd, I_PUSH, "tun") < 0) {
		syslog(LOG_ERR, "I_PUSH of tun failed");
		(void) close(ip_fd);
		return (-1);
	}

	if ((mux_fd = open("/dev/udp", O_RDWR)) < 0) {
		syslog(LOG_ERR, "open of /dev/ip failed");
		(void) close(ip_fd);
		return (-1);
	}

	if (ioctl(ip_fd, I_PUSH, "ip") == -1) {
		syslog(LOG_ERR, "I_PUSH of ip failed");
		(void) close(ip_fd);
		(void) close(mux_fd);
		return (-1);
	}

	/* Get the existing flags for this stream */
	(void) memset(&lifr, 0, sizeof (lifr));
	lifr.lifr_name[0] = '\0';
	if (ioctl(ip_fd, SIOCGLIFFLAGS, (char *)&lifr) == -1) {
		syslog(LOG_ERR, "plumb_one_tun: SIOCGLIFFLAGS");
		(void) close(ip_fd);
		(void) close(mux_fd);
		return (-1);
	}

	lifr.lifr_ppa = tnum;
	(void) sprintf(name, "ip.tun%d", tnum);
	(void)  strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(ip_fd, SIOCSLIFNAME, (char *)&lifr) == -1) {
		(void) close(ip_fd);
		(void) close(mux_fd);
		return (-1);
	}

	if ((ip_muxid = ioctl(mux_fd, I_LINK, ip_fd)) == -1) {
		syslog(LOG_ERR, "I_LINK for ip failed");
		(void) close(ip_fd);
		(void) close(mux_fd);
		return (-1);
	}

	lifr.lifr_ip_muxid = ip_muxid;

	/*
	 * Tell IP the muxids of the LINKed interface
	 * streams so that they can be closed down at a later
	 * time by an unplumb operation.
	 */
	if (ioctl(mux_fd, SIOCSLIFMUXID, (caddr_t)&lifr) < 0) {
		syslog(LOG_ERR, "plumb_one_tun: SIOCSLIFMUXID failed");
		(void) close(ip_fd);
		(void) close(mux_fd);
		return (-1);
	}

	(void)  close(ip_fd);

	return (mux_fd);
} /* plumb_one_tun */


/*
 * Function: unplumb_one_tun
 *
 * Arguments: int mux_fd
 *
 * Description: Unplumb the tunnel interface. Destroy all streams
 * 		associated with this tunnel and close it.
 *
 * Returns: int
 */
static int
unplumb_one_tun(int mux_fd)
{
	int retval;

	retval = close(mux_fd);
	return (retval);
}


/*
 * Function: setifflags
 *
 * Arguments: int tnum, int value
 *
 * Description: Set the interface specific flags indicated in
 * 		the argument 'value' for the given tunnel interface whose
 * 		tunnel number is the argument 'tnum'.
 *
 * Returns: int
 */
static int
setifflags(int tnum, int value)
{


	struct  lifreq lifr;
	char name[LIFNAMSIZ];

	(void) sprintf(name, "ip.tun%d", tnum);
	mipverbose(("setifflags %s\n", name));

	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(ioctl_sockid, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0) {
		syslog(LOG_ERR, "setifflags: SIOCGLIFFLAGS failed");
		return (-1);
	}
	if (value < 0) {
		value = -value;
		lifr.lifr_flags &= ~value;
	} else
		lifr.lifr_flags |= value;

	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(ioctl_sockid, SIOCSLIFFLAGS, (caddr_t)&lifr) < 0) {
		syslog(LOG_ERR, "setifflags: SIOCSLIFFLAGS failed");
		return (-1);
	}
	return (0);
}


/*
 * Function: settaddr
 *
 * Arguments: int tnum, ipaddr_t ifaddr1, ipaddr_t ifaddr2,
 * ipaddr_t saddr, ipaddr_t daddr, struct ipsec_req_t *ipsr
 *
 * Description: First forms a point-to-point interface between
 * 		ifaddr1 and ifaddr2 addresses. Next the source address of
 * 		the tunnel is set to address 'saddr'. This is the source
 * 		address of an outer encapsulating IP header and it must be
 * 		the address of an interface that has already been configured.
 * 		The destination address of the tunnel is set to 'daddr'.
 *
 * Returns: static int
 */
static int
settaddr(int tnum, ipaddr_t ifaddr1, ipaddr_t ifaddr2,
    ipaddr_t saddr, ipaddr_t daddr, ipsec_req_t *ipsr_p)
{

	struct sockaddr_storage laddr1, laddr2;
	struct iftun_req treq;
	char name[LIFNAMSIZ];
	struct sockaddr_in *sin;

	(void) sprintf(name, "ip.tun%d", tnum);
	mipverbose(("settaddr %s\n", name));


	if (mkpt2pt(name, ifaddr1, ifaddr2) < 0) {
		syslog(LOG_ERR, "settaddr: mkpt2pt failed");
		return (-1);
	}

	bzero(&treq, sizeof (struct iftun_req));
	treq.ifta_vers = IFTUN_VERSION;
	(void)  strncpy(treq.ifta_lifr_name, name,
	    sizeof (treq.ifta_lifr_name));
	if (ioctl(ioctl_sockid, SIOCGTUNPARAM, (caddr_t)&treq) < 0) {
		syslog(LOG_ERR, "Not a tunnel");
		return (-1);
	}

	if (treq.ifta_lower != IFTAP_IPV4) {
		syslog(LOG_ERR, "Unknown lower tunnel");
		return (-1);
	}

	sin = (struct sockaddr_in *)&laddr1;
	(void) memset(&laddr1, 0, sizeof (laddr1));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = saddr;

	sin = (struct sockaddr_in *)&laddr2;
	(void) memset(&laddr2, 0, sizeof (laddr2));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = daddr;

	treq.ifta_saddr = laddr1;
	treq.ifta_daddr = laddr2;
	treq.ifta_flags = IFTUN_SRC|IFTUN_DST;
	(void)  strncpy(treq.ifta_lifr_name, name,
				sizeof (treq.ifta_lifr_name));
	treq.ifta_vers = IFTUN_VERSION;

	/* non-null means there's tunnel protection to be added! */
	if (ipsr_p != NULL) {
		/* finally set the ipsec protection bits! */
		(void) memcpy(&treq.ifta_secinfo, ipsr_p, sizeof (ipsec_req_t));

		/* set the flag so the kernel sets up the security! */
		treq.ifta_flags |= IFTUN_SECURITY;
	}

	if (ioctl(ioctl_sockid, SIOCSTUNPARAM, (caddr_t)&treq) < 0) {
		syslog(LOG_ERR, "set tunnel addr failed");
		return (-1);
	}

	return (0);
} /* settaddr */

/*
 * Function: getEthernetAddr
 *
 * Arguments: char *ename, unsigned char *eaddr
 *
 * Description: Get the hardware address for specified interface name.
 *
 * Returns: int
 */
int
getEthernetAddr(char *ename, unsigned char *eaddr)
{
	int saplen;
	int	localsap = ETHERTYPE_ARP;
	int	fd;
	char buf[MAXDLBUF];
	unsigned char addr[MAXDLADDR];
	union DL_primitives	*dlp;
	int	i, ret;
	int physlen = ETHERADDRL;
	int ppa;
	char device[LIFNAMSIZ + 5];
	char *lasts;

	/*
	 * If this is a virtual interface, remove the ':' character (and
	 * everything following that character. We do not really care
	 * about it since the MAC address is the same as the physical
	 * interface.
	 */
	ename = strtok_r(ename, ":", &lasts);
	if (ename == NULL) {
		return (-1);
	}

	ifname2devppa(ename, device, &ppa);

	/* initialize buf[] */
	for (i = 0; i < MAXDLBUF; i++)
		buf[i] = (unsigned char) i & 0xff;

	/* Open the device. */
	if ((fd = open(device, (O_RDWR | O_NDELAY))) < 0)
	return (-1 * errno);

	/* Attach. */
	if ((ret = dlattachreq(fd, ppa)) < 0) {
		(void) close(fd);
		return (ret);
	}

	if ((ret = dlokack(fd, buf)) < 0) {
		(void) close(fd);
		return (ret);
	}

	/* Bind. */
	if ((ret = dlbindreq(fd, localsap, 0, DL_CLDLS, 0, 0)) < 0) {
		(void) close(fd);
		return (ret);
	}

	if ((ret = dlbindack(fd, buf)) < 0) {
		(void) close(fd);
		return (ret);
	}

	/* Get info */
	if ((ret = dlinforeq(fd)) < 0) {
		(void) close(fd);
		return (ret);
	}

	/* WORK -- check this error message, and send to mohanp@eng */
	(void) sleep(1);

	if ((ret = dlinfoack(fd, buf)) < 0) {
		(void) close(fd);
		return (ret);
	}

	/* Verify sap and phys address lengths */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	dlp = (union DL_primitives *)buf;

	MAaddrtostring(OFFADDR(dlp, dlp->info_ack.dl_addr_offset),
	dlp->info_ack.dl_addr_length, addr);

	saplen = ABS(dlp->info_ack.dl_sap_length);

	/* Construct destination address. */
	if (dlp->info_ack.dl_sap_length > 0) {	/* order is sap+phys */
		/* obtain our MAC address */
		(void) memcpy(eaddr, OFFADDR(dlp,
		    dlp->info_ack.dl_addr_offset + saplen),
		physlen);
	} else {	/* order is phys+sap */
		/* Obtain our MAC address */
		(void) memcpy(eaddr, OFFADDR(dlp,
		    dlp->info_ack.dl_addr_offset),
		physlen);
	}

	(void) close(fd);
	return (0);
} /* getEthernetAddr */


/*
 * Function: getIfaceInfo
 *
 * Arguments: char *ifaceName, ipaddr_t *addr, ipaddr_t *mask, uint64_t *flags
 *	      uint32_t *ifindex
 *
 * Description: Gets the interface information given the name.
 *
 * Returns: int
 */
int
getIfaceInfo(char *ifaceName, ipaddr_t *addr, ipaddr_t *mask,
    uint64_t *flags, uint32_t *ifindex)
{
	struct lifreq lifr;
	struct sockaddr_in *sin;
	int ioc_sockid;

	bzero((char *)&lifr, sizeof (lifr));
	(void) strncpy(lifr.lifr_name, ifaceName, sizeof (lifr.lifr_name));

	ioc_sockid = socket(AF_INET, SOCK_DGRAM, 0);
	if (ioc_sockid < 0) {
		syslog(LOG_ERR,
		    "Could not open socket for ioctls in getIfaceInfo()");
		return (-1);
	}

	if (ioctl(ioc_sockid, SIOCGLIFADDR, (caddr_t)&lifr) < 0) {
		syslog(LOG_ERR, "Could not read IP address for %s", ifaceName);
		(void) close(ioc_sockid);
		return (-1);
	}

	sin = (struct sockaddr_in *)&lifr.lifr_addr;
	*addr = sin->sin_addr.s_addr;

	if (ioctl(ioc_sockid, SIOCGLIFNETMASK, (caddr_t)&lifr) < 0) {
		syslog(LOG_ERR, "Could not read netmask for %s", ifaceName);
		(void) close(ioc_sockid);
		return (-1);
	}

	sin = (struct sockaddr_in *)&lifr.lifr_addr;
	*mask = sin->sin_addr.s_addr;

	(void) strncpy(lifr.lifr_name, ifaceName, sizeof (lifr.lifr_name));
	if (ioctl(ioc_sockid, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0) {
		syslog(LOG_ERR, "Could not read flags for %s", ifaceName);
		(void) close(ioc_sockid);
		return (-1);
	}

	*flags = lifr.lifr_flags;

	if (ioctl(ioc_sockid, SIOCGLIFINDEX, (char *)&lifr) < 0) {
		syslog(LOG_ERR, "Can't read IFINDEX %s", ifaceName);
		(void) close(ioc_sockid);
		return (-1);
	}
	*ifindex = lifr.lifr_index;

	(void) close(ioc_sockid);

	return (0);
} /* getIfaceInfo */


/*
 * Function:	arpIfadd
 *
 * Arguments:	vaddr  - visitor MN's IP address
 *		inIfindex - inbound interface index
 *		slla   - MN's source link layer addr
 *
 * Description:	Add an ARP entry given the interface index. Invokes
 *		SIOCSXARP with sdl_data array filled with interface
 *		name (without null terminator) followed by address.
 *		This code assumes it is being invoked on Ethernet.
 *
 * Returns:	0 - sucesss; errno - failure
 */
int
arpIfadd(ipaddr_t vaddr, char *slla, uint32_t inIfindex)
{
	struct xarpreq ar;
	char *etheraddr;
	int val;
	char addrstr1[INET_ADDRSTRLEN];
	struct ether_addr	ether;

	(void) memset(&ar, 0, sizeof (struct xarpreq));
	if (if_indextoname(inIfindex, ar.xarp_ha.sdl_data) == NULL) {
		syslog(LOG_ERR, "if_indextoname returned NULL\n");
		return ((-1) * errno);
	}

	/*
	 * Mark this entry permanent to prevent ARP from blowing this
	 * away.
	 */
	ar.xarp_flags = ATF_PERM;
	((struct sockaddr_in *)&ar.xarp_pa)->sin_addr.s_addr = vaddr;
	((struct sockaddr_in *)&ar.xarp_pa)->sin_family = AF_INET;

	(void) memcpy(ether.ether_addr_octet, slla, ETHERADDRL);
	etheraddr = ether_ntoa(&ether);
	mipverbose(("Adding temporary ARP entry for visitor %s,"
	    " hardware address %s on interface %s [index %d]\n",
	    ntoa(vaddr, addrstr1), etheraddr, ar.xarp_ha.sdl_data, inIfindex));
	ar.xarp_ha.sdl_nlen = strlen(ar.xarp_ha.sdl_data);
	ar.xarp_ha.sdl_alen = ETHERADDRL;
	ar.xarp_ha.sdl_family = AF_LINK;
	(void) memcpy(LLADDR(&ar.xarp_ha), slla, ar.xarp_ha.sdl_alen);

	val = ioctl(ioctl_sockid, SIOCSXARP, (caddr_t)&ar);

	if (val < 0)
		return ((-1) * errno);
	else
		return (val);
}

/*
 * Function:	arpIfdel
 *
 * Arguments:	vaddr  - visitor MN's IP address
 *		slla   - MN's source link layer addr (used here for mipverbose)
 *		inIfindex - inbound interface index
 *
 * Description:	Delete an ARP entry based on the interface index. Invokes
 *		SIOCDXARP with sdl_data array filled with interface
 *		name. This code assumes it is being invoked on Ethernet.
 *
 * Returns:	0 - sucesss; errno - failure
 */
int
arpIfdel(ipaddr_t vaddr, char *slla, uint32_t inIfindex)
{
	struct xarpreq ar;
	int val;
	char *etheraddr;
	char addrstr1[INET_ADDRSTRLEN];
	struct ether_addr	ether;

	(void) memset(&ar, 0, sizeof (struct xarpreq));
	if (if_indextoname(inIfindex, ar.xarp_ha.sdl_data) == NULL) {
		syslog(LOG_ERR, "if_indextoname returned NULL\n");
		return ((-1) * errno);
	}

	ar.xarp_flags = ATF_PERM;
	((struct sockaddr_in *)&ar.xarp_pa)->sin_addr.s_addr = vaddr;
	((struct sockaddr_in *)&ar.xarp_pa)->sin_family = AF_INET;

	(void) memcpy(ether.ether_addr_octet, slla, ETHERADDRL);
	etheraddr = ether_ntoa(&ether);
	mipverbose(("Deleting temporary ARP entry for visitor %s,"
	    " hardware address %s on interface %s [index %d]\n",
	    ntoa(vaddr, addrstr1), etheraddr, ar.xarp_ha.sdl_data, inIfindex));
	ar.xarp_ha.sdl_nlen = strlen(ar.xarp_ha.sdl_data);
	ar.xarp_ha.sdl_family = AF_LINK;

	/*
	 * Delete an ARP entry in the ARP cache
	 */
	val = ioctl(ioctl_sockid, SIOCDXARP, (caddr_t)&ar);

	if (val < 0)
		return ((-1) * errno);
	else
		return (0);
}

/*
 * Function: CreateListOfExistingIntfce
 * This function stores a list of existing interfaces into a
 * static interface entry table when the mipagent is started.
 * The existing interface list does not include any IPv6,
 * loopback  and logical interfaces.
 * Return value : 0 on success, -1 on failure
 */
int
CreateListOfExistingIntfce(void) {
	struct lifnum lifn;
	struct lifconf lifc;
	struct lifreq lifr;
	struct lifreq *lifrp;
	int numifs;
	int bufsize;
	int iocsock;
	int n;
	char *buf;
	StaticIfaceEntry *ifce_ptr;
	StaticIfaceEntry *saveptr = NULL;

	iocsock = socket(AF_INET, SOCK_DGRAM, 0);
	if (iocsock < 0) {
		syslog(LOG_ERR, "Can't open IOCTL socket: %m");
		return (-1);
	}

	lifn.lifn_family = AF_INET;
	lifn.lifn_flags = 0;
	if (ioctl(iocsock, SIOCGLIFNUM, (char *)&lifn) < 0) {
		syslog(LOG_ERR, "SIOCGLIFNUM failed: %m");
		return (-1);
	}
	numifs = lifn.lifn_count;
	bufsize = numifs * sizeof (struct lifreq);
	buf = malloc(bufsize);
	if (buf == NULL) {
		syslog(LOG_ERR,
		    "Can't create existing interface list: Out of memory: %m");
		return (-1);
	}

	lifc.lifc_family = AF_INET;
	lifc.lifc_flags = 0;
	lifc.lifc_len = bufsize;
	lifc.lifc_buf = buf;
	if (ioctl(iocsock, SIOCGLIFCONF, (char *)&lifc) < 0) {
		syslog(LOG_ERR,
		    "Can't get existing system interface configuration: %m");
		free(buf);
		return (-1);
	}


	StaticIntfaceHead = NULL;
	lifrp = lifc.lifc_req;
	for (n = lifc.lifc_len / sizeof (struct lifreq); n > 0; n--, lifrp++) {
		(void) strncpy(lifr.lifr_name, lifrp->lifr_name,
		    sizeof (lifr.lifr_name));
		if (strchr(lifr.lifr_name, ':') != NULL)
			continue;
		if (ioctl(iocsock, SIOCGLIFFLAGS, (char *)&lifr) < 0) {
			syslog(LOG_ERR,
			    "Can't get flag information for %s: %m",
			    lifr.lifr_name);
			continue;
		}
		if (lifr.lifr_flags & IFF_LOOPBACK)
			continue;
		/* Create or add interface list */
		ifce_ptr = (struct staticIface *)
		    malloc(sizeof (struct staticIface));
		if (ifce_ptr == NULL) {
			syslog(LOG_ERR,
			    "malloc: Can't create existing interface list: %m");
			free(buf);
			return (-1);
		}
		(void) strncpy(ifce_ptr->ifacename, lifr.lifr_name,
		    sizeof (lifr.lifr_name));
		if (StaticIntfaceHead == NULL)
			StaticIntfaceHead = ifce_ptr;
		if (saveptr != NULL) {
			saveptr->next = ifce_ptr;
		}
		ifce_ptr->next = NULL;
		saveptr = ifce_ptr;
	}
	(void) close(iocsock);
	free(buf);
	return (0);
}

/*
 * This function returns true or false based on matching entries
 * from StaticIfaceEntry list
 */
boolean_t
existingStaticInterface(const char *ifname) {
	struct staticIface *Sptr;

	Sptr = StaticIntfaceHead;
	while (Sptr != NULL) {
		if (strcmp(Sptr->ifacename, ifname) == 0) {
			mipverbose(("existingStaticInterface:"
			    "Found a static existing entry\n"));
			return (_B_TRUE);
		}
		Sptr = Sptr->next;
	}
	return (_B_FALSE);
}
