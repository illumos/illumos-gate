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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <libintl.h>
#include <strings.h>
#include <unistd.h>
#include <synch.h>
#include <stropts.h>
#include <errno.h>
#include <pthread.h>

#include <inet/ip.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netdb.h>
#include <net/route.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/systeminfo.h>

#include <smbsrv/libsmbns.h>

#define	MAXIFS	256

typedef struct smb_ifnames {
	char *if_names[MAXIFS];
	int if_num;
} smb_ifnames_t;

typedef struct {
	net_cfg_t	*nl_nics;
	int		nl_cnt;
} smb_niclist_t;

static int smb_nic_iflist_create(smb_ifnames_t *);
static void smb_nic_iflist_destroy(smb_ifnames_t *);

static int smb_niclist_create(void);
static void smb_niclist_destroy(void);
static void smb_niclist_lock(void);
static void smb_niclist_unlock(void);

/* This is the list we will monitor */
static smb_niclist_t smb_niclist = { NULL, 0 };
static pthread_mutex_t smb_niclist_mtx = PTHREAD_MUTEX_INITIALIZER;

int
smb_get_nameservers(struct in_addr *ips, int sz)
{
	union res_sockaddr_union set[MAXNS];
	int i, cnt;
	struct __res_state res_state;

	if (ips == NULL)
		return (0);

	bzero(&res_state, sizeof (struct __res_state));
	if (res_ninit(&res_state) < 0)
		return (0);

	cnt = res_getservers(&res_state, set, MAXNS);
	for (i = 0; i < cnt; i++) {
		if (i >= sz)
			break;
		ips[i] = set[i].sin.sin_addr;
		syslog(LOG_DEBUG, "NS Found %s name server\n",
		    inet_ntoa(ips[i]));
	}
	syslog(LOG_DEBUG, "NS Found %d name servers\n", i);
	res_ndestroy(&res_state);
	return (i);
}

/*
 * Initialize interface list.
 */
void
smb_nic_build_info(void)
{
	smb_niclist_lock();
	smb_niclist_destroy();

	if (smb_niclist_create() < 0)
		syslog(LOG_ERR, "smbd: failed getting network interfaces"
		    " information");
	else if (smb_niclist.nl_cnt == 0)
		syslog(LOG_ERR, "smbd: No network interfaces are configured "
		    "smb server may not function properly");

	smb_niclist_unlock();
}

/*
 * Get number of interfaces.
 */
int
smb_nic_get_num(void)
{
	int n;

	smb_niclist_lock();
	n = smb_niclist.nl_cnt;
	smb_niclist_unlock();

	return (n);
}

/*
 * Get if by index
 * Returns: NULL if not found.
 */
net_cfg_t *
smb_nic_get_byind(int ind, net_cfg_t *cfg)
{
	if (cfg == NULL)
		return (NULL);

	smb_niclist_lock();
	if (ind > smb_niclist.nl_cnt) {
		smb_niclist_unlock();
		return (NULL);
	}
	bcopy(&smb_niclist.nl_nics[ind], cfg, sizeof (net_cfg_t));
	smb_niclist_unlock();

	return (cfg);
}

/*
 * Get if by subnet
 * Returns: NULL if not found.
 */
net_cfg_t *
smb_nic_get_bysubnet(uint32_t ipaddr, net_cfg_t *cfg)
{
	net_cfg_t *tcfg;
	int i;

	if (cfg == NULL)
		return (NULL);

	bzero(cfg, sizeof (net_cfg_t));

	smb_niclist_lock();
	for (i = 0; i < smb_niclist.nl_cnt; i++) {
		tcfg = &smb_niclist.nl_nics[i];
		if ((ipaddr & tcfg->mask) ==
		    (tcfg->ip & tcfg->mask)) {
			bcopy(tcfg, cfg, sizeof (net_cfg_t));
			smb_niclist_unlock();
			return (cfg);
		}
	}
	smb_niclist_unlock();

	return (NULL);
}

/*
 * Get if by ip.
 * Returns: NULL if not found.
 */
net_cfg_t *
smb_nic_get_byip(uint32_t ipaddr, net_cfg_t *cfg)
{
	net_cfg_t *tcfg;
	int i;

	if (cfg == NULL)
		return (NULL);

	bzero(cfg, sizeof (net_cfg_t));

	smb_niclist_lock();
	for (i = 0; i < smb_niclist.nl_cnt; i++) {
		tcfg = &smb_niclist.nl_nics[i];
		if (ipaddr == tcfg->ip) {
			bcopy(tcfg, cfg, sizeof (net_cfg_t));
			smb_niclist_unlock();
			return (cfg);
		}
	}
	smb_niclist_unlock();

	return (NULL);
}

/*
 * The following list is taken from if.h. The function takes the
 * given interface name, and the passed flag(s), and returns true if
 * the flag is associated with the interface, and false if not.
 *
 * IFF_UP		interface is up
 * IFF_BROADCAST	broadcast address valid
 * IFF_LOOPBACK		is a loopback net
 * IFF_POINTOPOINT	interface is point-to-point link
 * IFF_RUNNING		resources allocated
 * IFF_MULTICAST	supports multicast
 * IFF_MULTI_BCAST	multicast using broadcast address
 * IFF_UNNUMBERED	non-unique address
 * IFF_DHCPRUNNING	DHCP controls this interface
 * IFF_PRIVATE		do not advertise
 * IFF_DEPRECATED	interface address deprecated
 * IFF_ANYCAST		Anycast address
 * IFF_IPV4		IPv4 interface
 * IFF_IPV6		IPv6 interface
 * IFF_NOFAILOVER	Don't failover on NIC failure
 * IFF_FAILED		NIC has failed
 * IFF_STANDBY		Standby NIC to be used on failures
 * IFF_OFFLINE		NIC has been offlined
 */
boolean_t
smb_nic_status(char *interface, uint64_t flag)
{
	struct lifreq lifrr;
	int rc;
	int s;

	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
		syslog(LOG_DEBUG, "smb_nic_status: %s", strerror(errno));
		return (B_FALSE);
	}

	(void) strlcpy(lifrr.lifr_name, interface, sizeof (lifrr.lifr_name));
	rc = ioctl(s, SIOCGLIFFLAGS, &lifrr);
	(void) close(s);

	if (rc < 0) {
		syslog(LOG_DEBUG, "smb_nic_status: %s", strerror(errno));
		return (B_FALSE);
	}

	if (lifrr.lifr_flags & flag)
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * Get IP info and more for the given interface
 */
static int
smb_nic_getinfo(char *interface, net_cfg_t *nc)
{
	struct lifreq lifrr;
	struct sockaddr_in *sa;
	int s;

	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
		return (-1);
	}

	(void) strlcpy(lifrr.lifr_name, interface, sizeof (lifrr.lifr_name));
	if (ioctl(s, SIOCGLIFADDR, &lifrr) < 0) {
		(void) close(s);
		return (-1);
	}
	sa = (struct sockaddr_in *)&lifrr.lifr_addr;
	nc->ip = (uint32_t)sa->sin_addr.s_addr;

	if (ioctl(s, SIOCGLIFBRDADDR, &lifrr) < 0) {
		(void) close(s);
		return (-1);
	}
	sa = (struct sockaddr_in *)&lifrr.lifr_broadaddr;
	nc->broadcast = (uint32_t)sa->sin_addr.s_addr;

	if (ioctl(s, SIOCGLIFNETMASK, &lifrr) < 0) {
		(void) close(s);
		return (-1);
	}
	sa = (struct sockaddr_in *)&lifrr.lifr_addr;
	nc->mask = (uint32_t)sa->sin_addr.s_addr;

	if (ioctl(s, SIOCGLIFFLAGS, &lifrr) < 0) {
		(void) close(s);
		return (-1);
	}
	nc->flags = lifrr.lifr_flags;

	(void) strlcpy(nc->ifname, interface, sizeof (nc->ifname));

	(void) close(s);
	return (0);
}

/*
 * Get the list of currently plumbed interface names. The loopback (lo0)
 * port is ignored
 */
static int
smb_nic_iflist_create(smb_ifnames_t *iflist)
{
	struct ifconf ifc;
	struct ifreq ifr;
	struct ifreq *ifrp;
	char *ifname;
	int ifnum;
	int i;
	int s;

	bzero(iflist, sizeof (smb_ifnames_t));

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return (-1);

	if (ioctl(s, SIOCGIFNUM, (char *)&ifnum) < 0) {
		(void) close(s);
		return (-1);
	}

	ifc.ifc_len = ifnum * sizeof (struct ifreq);
	ifc.ifc_buf = malloc(ifc.ifc_len);
	if (ifc.ifc_buf == NULL) {
		(void) close(s);
		return (-1);
	}
	bzero(ifc.ifc_buf, ifc.ifc_len);

	if (ioctl(s, SIOCGIFCONF, (char *)&ifc) < 0) {
		(void) close(s);
		free(ifc.ifc_buf);
		return (-1);
	}

	ifrp = ifc.ifc_req;
	ifnum = ifc.ifc_len / sizeof (struct ifreq);

	for (i = 0; i < ifnum; i++, ifrp++) {
		/*
		 * Get the flags so that we can skip the loopback interface
		 */
		(void) memset(&ifr, 0, sizeof (ifr));
		(void) strlcpy(ifr.ifr_name, ifrp->ifr_name,
		    sizeof (ifr.ifr_name));

		if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
			(void) close(s);
			free(ifc.ifc_buf);
			smb_nic_iflist_destroy(iflist);
			return (-1);
		}

		if (ifr.ifr_flags & IFF_LOOPBACK)
			continue;

		if ((ifr.ifr_flags & IFF_UP) == 0)
			continue;

		ifname = strdup(ifrp->ifr_name);
		if (ifname == NULL) {
			(void) close(s);
			free(ifc.ifc_buf);
			smb_nic_iflist_destroy(iflist);
			return (-1);
		}
		iflist->if_names[iflist->if_num++] = ifname;
	}

	(void) close(s);
	free(ifc.ifc_buf);
	return (0);
}

/*
 * Frees allocated memory for the given IF names lists.
 */
static void
smb_nic_iflist_destroy(smb_ifnames_t *iflist)
{
	int i;

	if (iflist == NULL)
		return;

	for (i = 0; i < iflist->if_num; i++)
		free(iflist->if_names[i]);
}

/*
 * This will mimick the workings of ifconfig -a command.
 *
 * Note that the caller of this function should grab the
 * list lock.
 */
static int
smb_niclist_create(void)
{
	smb_ifnames_t ifnames;
	net_cfg_t *nc;
	char *ifname;
	char excludestr[MAX_EXCLUDE_LIST_LEN];
	ipaddr_t exclude[SMB_PI_MAX_NETWORKS];
	int nexclude;
	int i;

	if (smb_nic_iflist_create(&ifnames) < 0)
		return (-1);

	smb_niclist.nl_nics = calloc(ifnames.if_num, sizeof (net_cfg_t));
	if (smb_niclist.nl_nics == NULL) {
		smb_nic_iflist_destroy(&ifnames);
		return (-1);
	}

	(void) smb_config_getstr(SMB_CI_WINS_EXCL, excludestr,
	    sizeof (excludestr));
	nexclude = smb_wins_iplist(excludestr, exclude, SMB_PI_MAX_NETWORKS);

	nc = smb_niclist.nl_nics;
	for (i = 0; i < ifnames.if_num; i++, nc++) {
		ifname = ifnames.if_names[i];
		if (strchr(ifname, ':'))
			/* Will not provide info on logical interfaces */
			continue;

		if (smb_nic_getinfo(ifname, nc) < 0) {
			smb_nic_iflist_destroy(&ifnames);
			smb_niclist_destroy();
			return (-1);
		}
		smb_niclist.nl_cnt++;

		if (smb_wins_is_excluded(nc->ip,
		    (ipaddr_t *)exclude, nexclude))
			nc->exclude = B_TRUE;
	}

	smb_nic_iflist_destroy(&ifnames);

	return (0);
}

static void
smb_niclist_destroy(void)
{
	free(smb_niclist.nl_nics);
	smb_niclist.nl_nics = NULL;
	smb_niclist.nl_cnt = 0;
}

/*
 * smb_niclist_lock
 *
 * Lock the nic table
 */
static void
smb_niclist_lock(void)
{
	(void) pthread_mutex_lock(&smb_niclist_mtx);
}

/*
 * smb_niclist_unlock
 *
 * Unlock the nic table.
 */
static void
smb_niclist_unlock(void)
{
	(void) pthread_mutex_unlock(&smb_niclist_mtx);
}
