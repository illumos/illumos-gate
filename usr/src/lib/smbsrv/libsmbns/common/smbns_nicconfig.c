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

static int smb_nic_get_list(struct if_list **);
static void smb_nic_clear_if_list(struct if_list *);

/* This is the list we will monitor */
static net_cfg_list_t smb_nic_list = { NULL, 0 };
static pthread_mutex_t smb_nic_mutex = PTHREAD_MUTEX_INITIALIZER;

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
	res_nclose(&res_state);
	return (i);
}

/*
 * The common NIC library will provide functions to obtain information
 * on all interfaces. Information will include IP addresses, netmasks
 * and broadcast address, as well as network statistic details.
 */

/*
 * Return IP string address associated with interface argument.
 * If an error occurs, -1 will be returned.
 * A return value of 1 indicates an unconfigured IP address
 */
static int
smb_nic_get_ip_addr(char *interface, char *IP, unsigned int IP_length)
{
	struct lifreq   lifrr;
	struct sockaddr_in  *sa;
	int sfd;

	sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

	if (sfd < 0) {
		syslog(LOG_ERR, "%s", "nic_get_IP:socket open failed\n");
		return (-1);
	}

	(void) strncpy(lifrr.lifr_name, interface, sizeof (lifrr.lifr_name));

	if (ioctl(sfd, SIOCGLIFADDR, &lifrr) < 0) {
		syslog(LOG_ERR, "%s", "nic_get_IP: get IP address failed\n");
		(void) close(sfd);
		return (-1);
	}
	/* Test length of allocated memory to avoid buffer overflow */
	if (IP_length < SIZE_IP) {
		syslog(LOG_ERR, "%s", "nic_get_IP: insufficient memory"
		    "allocation\n");
		(void) close(sfd);
		return (-1);
	}
	sa = (struct sockaddr_in  *) &lifrr.lifr_addr;
	(void) strncpy(IP, inet_ntoa(sa->sin_addr), SIZE_IP);
	/* Check for unconfigured interface */
	if (strncmp(IP, "0.0.0.0", sizeof (IP)) == 0) {
		syslog(LOG_ERR, "%s", "nic_get_IP: unconfigured interface\n");
		(void) close(sfd);
		return (1);
	}
	(void) close(sfd);
	return (0);
}

/*
 * Return IP address associated with interface argument. If an error occurs,
 * -1 will be returned. A return value of 1 indicates an unconfigured IP
 * address
 */
int
smb_nic_get_IP(char *interface, uint32_t *uip)
{
	struct lifreq   lifrr;
	struct sockaddr_in  *sa;
	int sfd;

	sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

	if (sfd < 0) {
		syslog(LOG_ERR, "%s", "nic_get_IP:socket open failed\n");
		return (-1);
	}

	(void) strncpy(lifrr.lifr_name, interface, sizeof (lifrr.lifr_name));

	if (ioctl(sfd, SIOCGLIFADDR, &lifrr) < 0) {
		syslog(LOG_ERR, "%s", "nic_get_IP: get IP address failed\n");
		(void) close(sfd);
		return (-1);
	}
	sa = (struct sockaddr_in  *) &lifrr.lifr_addr;
	if (uip != NULL)
		*uip = (uint32_t)sa->sin_addr.s_addr;
	(void) close(sfd);
	return (0);
}

/*
 * Return broadcast address associated with interface argument.If an error
 * occurs, -1 will be returned. A return value of 1 indicates an unconfigured
 * broadcast address
 */
int
smb_nic_get_broadcast(char *interface, uint32_t *uip)
{
	struct lifreq   lifrr;
	struct sockaddr_in  *sa;
	int sfd;

	sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sfd < 0) {
		syslog(LOG_ERR, "%s", "nic_get_broadcast:"
		    "socket open failed\n");
		return (-1);
	}

	(void) strncpy(lifrr.lifr_name, interface, sizeof (lifrr.lifr_name));

	if (ioctl(sfd, SIOCGLIFBRDADDR, &lifrr) < 0) {
		syslog(LOG_ERR, "%s", "nic_get_broadcast:"
		    "get broadcast address failed\n");
		(void) close(sfd);
		return (-1);
	}
	sa = (struct sockaddr_in *)&lifrr.lifr_broadaddr;
	if (uip != NULL)
		*uip = (uint32_t)sa->sin_addr.s_addr;
	(void) close(sfd);
	return (0);

}

/*
 * Return netmask address associated with interface argument. If error occurs,
 * -1 will be returned. A return value of 1 indicates an unconfigured netmask
 * address
 */
int
smb_nic_get_netmask(char *interface, uint32_t *uip)
{
	struct lifreq   lifrr;
	struct sockaddr_in  *sa;
	int sfd;

	sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sfd < 0) {
		syslog(LOG_ERR, "%s", "nic_get_netmask:"
		    "socket open failed\n");
		return (-1);
	}

	(void) strncpy(lifrr.lifr_name, interface, sizeof (lifrr.lifr_name));

	if (ioctl(sfd, SIOCGLIFNETMASK, &lifrr) < 0) {
		syslog(LOG_ERR, "%s", "nic_get_netmask:"
		    "get netmask address failed\n");
		(void) close(sfd);
		return (-1);
	}
	sa = (struct sockaddr_in *)&lifrr.lifr_addr;
	if (uip != NULL)
		*uip = (uint32_t)sa->sin_addr.s_addr;
	(void) close(sfd);
	return (0);

}

/*
 * Fill ip_alias with IP addresses if any
 * If it returns 0, there are no associated aliases with the interface.
 * If it returns -1, there was an error
 * If it returns 1, there are associated IP aliases with the interface.
 */
int
smb_nic_get_IP_aliases(char *interface, struct ip_alias **list)
{
	char ** names = NULL;
	int result = 0;
	int numnics, i, ret = 0;
	char IP[SIZE_IP];
	struct ip_alias *tmp;

	*list = NULL;

	/* If the interface is a logical interface, return immediately */
	if (strchr(interface, ':') != NULL) {
		syslog(LOG_ERR, "%s", "nic_get_IP_aliases:"
		    "invalid physical interface");
		return (ret);
	}

	numnics = smb_nic_build_if_name(&names);

	for (i = 0; i < numnics; i++) {
	/*
	 * Compare passed interface name to all other interface names.
	 * If it matches in the form of :1, it is an associated alias
	 * Example bge1:1's ip address is an ip alias of bge1
	 */
		if (strncasecmp(interface, names[i], strlen(names[0])) == 0 &&
		    strchr(names[i], ':') != 0) {

			result = smb_nic_get_ip_addr(names[i],
			    IP, sizeof (IP));
			if (result == -1)
				return (result);

			tmp = (struct ip_alias *)malloc(
			    sizeof (struct ip_alias));
				if (tmp == NULL) {
					syslog(LOG_ERR, "%s", "nic_get"
					    "_IP_aliases: out of memory");
					(void) smb_nic_clear_name_list(names,
					    numnics);
					return (-1);
				}

			(void) strncpy(tmp->name, IP, sizeof (tmp->name));
			tmp->next = *list;
			*list = tmp;
			ret = 1;
		}
	}
	(void) smb_nic_clear_name_list(names, numnics);
	return (ret);
}

/*
 * Return number of plumbed interfaces. Loopback interface is ignored
 */
int
smb_nic_get_number(void)
{
	struct lifnum lifn;
	int numifs = 0, sfd;

	sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sfd < 0) {
		syslog(LOG_ERR, "%s", "nic_get_number:"
		    "socket open failed");
		return (-1);
	}

	lifn.lifn_family = AF_INET;
	lifn.lifn_flags = 0;

	if (ioctl(sfd, SIOCGLIFNUM, &lifn) < 0) {
		syslog(LOG_ERR, "%s", "nic_get_number:"
		    "unable to determine number");
		(void) close(sfd);
		return (-1);
	}

	numifs = lifn.lifn_count - 1; /* loopback */
	(void) close(sfd);
	return (numifs);
}

/*
 * Given an interface name, return the name of the group it belongs to.
 */
int
smb_nic_get_group(char *lifname, char *grname)
{
	struct lifreq lifr;
	int sfd;
	int save_errno;

	sfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sfd < 0) {
		syslog(LOG_ERR, "%s", "nic_set_group:socket open failed");
		return (-1);
	}
	if (strchr(lifname, ':') == NULL) {
		(void) memset(lifr.lifr_groupname, 0,
		    sizeof (lifr.lifr_groupname));
		(void) strncpy(lifr.lifr_name, lifname,
		    sizeof (lifr.lifr_name));
		if (ioctl(sfd, SIOCGLIFGROUPNAME, (caddr_t)&lifr) >= 0) {
			if (strlen(lifr.lifr_groupname) > 0) {
				(void) strncpy(grname, lifr.lifr_groupname,
				    sizeof (lifr.lifr_groupname));
			}
		} else {
			save_errno = errno;
			syslog(LOG_ERR, "smb_nic_get_group:  ioctl failed");
			(void) close(sfd);
			errno = save_errno;
			return (-1);
		}
	}
	(void) close(sfd);
	return (0);
}

/*
 * Read the /etc/defaultrouter file for the gateway address. If an error occurs,
 * -1 will be returned.
 */
int
smb_nic_get_default_gateway(char *gw, unsigned int gw_length)
{
	FILE *fp;

	fp = fopen(GATEWAY_FILE, "r");

	if (fp == NULL) {
		(void) fclose(fp);
		return (-1);
	} else {
		/* Test length of allocated memory to avoid buffer overflow */
		if (gw_length < SIZE_IP) {
			syslog(LOG_ERR, "%s", "get_default_gateway: "
			    "insufficient memory allocation\n");
			(void) fclose(fp);
			return (-1);
		}
		(void) fgets(gw, SIZE_IP, fp);
		(void) fclose(fp);
	}

	return (0);
}

/*
 * Build the list of interface names, both physical and logical.
 * A pointer to a pointer to a char will be filled with the info
 */
int
smb_nic_build_if_name(char ***if_names)
{
	struct if_list *iflist;
	struct if_list *iflistptr;
	int num_ifs, i;

	/* Get the interfaces */
	num_ifs = smb_nic_get_list(&iflist);

	/* Build the list of names */
	*if_names = (char **)malloc(sizeof (char *) * num_ifs);

	if (if_names == NULL) {
		syslog(LOG_ERR, "%s", "Unable to build interface names");
		return (-1);
	}

	for (i = 0, iflistptr = iflist; i < num_ifs;
	    iflistptr = iflistptr->next, i++) {
		(*if_names)[i] = (char *)strdup(iflistptr->name);
	}
	(void) smb_nic_clear_if_list(iflist);
	return (num_ifs);
}

/*
 * Get number of physical interfaces
 */
int
smb_nic_get_num_physical(void)
{
	char **names = NULL;
	int phys_ifs = 0;
	int i, result = 0;
	/* Get list of interface names */
	result = smb_nic_build_if_name(&names);
	if (result == -1) {
		syslog(LOG_ERR, "%s", "Unable to determine num interfaces");
		return (-1);
	}
	for (i = 0; i < result; i++) {
		if (strchr(names[i], ':') == NULL) {
			/* It's a physical interface */
			phys_ifs++;
		}
	}
	(void) smb_nic_clear_name_list(names, result);
	return (phys_ifs);
}

/*
 * Get number of logical interfaces
 */
int
smb_nic_get_num_logical(void)
{
	char **names = NULL;
	int log_ifs = 0;
	int i, result = 0;
	/* Get list of interface names */
	result = smb_nic_build_if_name(&names);
	if (result == -1) {
		syslog(LOG_ERR, "%s", "Unable to determine num interfaces");
		return (-1);
	}
	for (i = 0; i < result; i++) {
		if (strchr(names[i], ':') != NULL) {
			/* It's a logical interface */
			log_ifs++;
		}
	}
	(void) smb_nic_clear_name_list(names, result);
	return (log_ifs);
}

/*
 * Get number of aliases associated with an interface
 */
int
smb_nic_get_num_aliases(char *interface)
{
	char **names = NULL;
	int aliases = 0;
	int i, result = 0;

	if (interface == NULL) {
		syslog(LOG_ERR, "%s", "Interface name not supplied");
		return (-1);
	}
	/* Get list of interface names */
	result = smb_nic_build_if_name(&names);
	if (result == -1) {
		syslog(LOG_ERR, "%s", "Unable to determine num interfaces");
		return (-1);
	}
	for (i = 0; i < result; i++) {
		if (strncasecmp(interface, names[i], strlen(names[0])) == 0 &&
		    strchr(names[i], ':') != 0) {
			/* It's an alias */
			aliases++;
		}
	}
	(void) smb_nic_clear_name_list(names, result);
	if (aliases == 0)
		return (1); /* Minimum of 1 for NULL assignment */
	else
		return (aliases);
}

/*
 * Get the list of currently plumbed interface names. The loopback(lo0)
 * port is ignored
 */
static int
smb_nic_get_list(struct if_list **list)
{
	int cnt = 0;
	struct if_list *tmp, *p;
	int n, s;
	char *buf;
	struct ifconf ifc;
	register struct ifreq *ifrp = NULL;
	struct ifreq ifr;
	int numifs = 0;
	unsigned int bufsize = 0;

	*list = NULL;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		syslog(LOG_ERR, "%s", "get_net_list: socket");
		return (-1);
	}

	if (ioctl(s, SIOCGIFNUM, (char *)&numifs) < 0) {
		syslog(LOG_ERR, "%s", "get number of interfaces");
		return (-1);
	}

	bufsize = numifs * sizeof (struct ifreq);
	buf = (char *)malloc(bufsize);
	if (buf == NULL) {
		syslog(LOG_ERR, "%s", "out of memory\n");
		(void) close(s);
		return (-1);
	}
	ifc.ifc_len = bufsize;
	ifc.ifc_buf = buf;

	if (ioctl(s, SIOCGIFCONF, (char *)&ifc) < 0) {
		syslog(LOG_ERR, "%s", "Unable to get interface list\n");
		(void) close(s);
		(void) free(buf);
		return (-1);
	}

	ifrp = ifc.ifc_req;
	for (n = ifc.ifc_len / sizeof (struct ifreq); n > 0; n--, ifrp++) {
		/* Get the flags so that we can skip the loopback interface */
		(void) memset((char *)&ifr, '\0', sizeof (ifr));
		(void) strncpy(ifr.ifr_name, ifrp->ifr_name,
		    sizeof (ifr.ifr_name));

		if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
			syslog(LOG_ERR, "%s", "unable to determine flags");
			(void) close(s);
			(void) free(buf);
			return (-1);
		}

		if (ifr.ifr_flags & IFF_LOOPBACK)
			continue;
		if ((ifr.ifr_flags & IFF_UP) == 0)
			continue;
		tmp = (struct if_list *)malloc(sizeof (struct if_list));
		if (tmp == NULL) {
			syslog(LOG_ERR, "%s", "out of memory\n");
			(void) close(s);
			(void) free(buf);
			return (-1);
		}

		tmp->next = NULL;
		(void) strncpy(tmp->name, ifrp->ifr_name, sizeof (tmp->name));
		if (*list == NULL) {
			*list = tmp;
		} else {
			for (p = *list; p->next; p = p->next)
				;
			p->next = tmp;
		}
		cnt++;
	}
	(void) close(s);
	(void) free(buf);
	return (cnt);
}

/*
 * This will mimick the workings of ifconfig -a command. A net_cfg
 * pointer will be passed, and all information will be assigned
 * within this function. Memory will be assigned in this function
 * also so the user doesn't have to worry about it. Freeing memory
 * will be handled in a different function - smb_nic_clear_memory
 */
int
smb_nic_build_network_structures(net_cfg_t **nc, int *number)
{
	char **names = NULL;
	int res, numnics = 0;
	int num_aliases = 0;
	uint32_t uip;
	uint64_t flags;
	int i = 0;
	int j = 1;
	int k = 0;
	struct ip_alias *list = NULL;
	net_cfg_t *nc_array;
	char excludestr[MAX_EXCLUDE_LIST_LEN];
	ipaddr_t exclude[SMB_PI_MAX_NETWORKS];
	int nexclude;

	*number = 0;
	numnics = smb_nic_build_if_name(&names);
	nc_array = *nc = malloc(sizeof (net_cfg_t) * numnics);
	if (nc_array == NULL) {
		(void) smb_nic_clear_name_list(names, numnics);
		return (-1);
	}
	bzero(nc_array, sizeof (net_cfg_t) * numnics);

	(void) smb_config_getstr(SMB_CI_WINS_EXCL, excludestr,
	    sizeof (excludestr));
	nexclude = smb_wins_iplist(excludestr, exclude, SMB_PI_MAX_NETWORKS);

	for (i = 0; i < numnics; i++) {

		if (strchr(names[i], ':') == NULL) {
			/* Will not provide info on logical interfaces */

			(void) memset ((*nc), 0, sizeof (net_cfg_t));
			num_aliases = smb_nic_get_num_aliases(names[i]);
			if (num_aliases == -1) {
				(void) smb_nic_clear_name_list(names, numnics);
				free (*nc);
				*nc = NULL;
				return (-1);
			}

			(*nc)->aliases = (char **)calloc(num_aliases,
			    (sizeof (char) * IP_ABITS));
			if ((*nc)->aliases == NULL) {
				(void) smb_nic_clear_name_list(names, numnics);
				free (*nc);
				*nc = NULL;
				return (-1);
			}
			(void) strncpy((*nc)->ifname, names[i],
			    sizeof ((*nc)->ifname));
			(*nc)->naliases = num_aliases;

			res = smb_nic_get_IP((*nc)->ifname, &uip);
			if (res == -1) { /* error retrieving IP address */
				(void) smb_nic_clear_name_list(names, numnics);
				free ((*nc)->aliases);
				free (*nc);
				*nc = NULL;
				return (-1);
			}
			(*nc)->ip = uip;
			if (smb_wins_is_excluded(uip,
			    (ipaddr_t *)exclude, nexclude))
				(*nc)->exclude = B_TRUE;
			res = smb_nic_get_netmask((*nc)->ifname, &uip);
			if (res == -1) { /* error retrieving netmask address */
				(void) smb_nic_clear_name_list(names, numnics);
				free ((*nc)->aliases);
				free (*nc);
				*nc = NULL;
				return (-1);
			}
			(*nc)->mask = uip;
			res = smb_nic_get_broadcast((*nc)->ifname, &uip);
			if (res == -1) { /* error retrieving broadcast add */
				(void) smb_nic_clear_name_list(names, numnics);
				free ((*nc)->aliases);
				free (*nc);
				*nc = NULL;
				return (-1);
			}
			(*nc)->broadcast = uip;
			res = smb_nic_get_group((*nc)->ifname,
			    (*nc)->groupname);
			if (res == -1) { /* error retrieving group name */
				(void) smb_nic_clear_name_list(names, numnics);
				free ((*nc)->aliases);
				free (*nc);
				*nc = NULL;
				return (-1);
			}
			res = smb_nic_flags((*nc)->ifname, &flags);
			if (res == -1) { /* error retrieving flags */
				(void) smb_nic_clear_name_list(names, numnics);
				free ((*nc)->aliases);
				free (*nc);
				*nc = NULL;
				return (-1);
			}
			(*nc)->flags = flags;
			/*
			 * If an interface has no associated alias, the alias
			 * field will be set to NULL
			 */
			res = smb_nic_get_IP_aliases((*nc)->ifname, &list);
			if (res == -1) {
				(*nc)->aliases[k] = NULL;
				(void) smb_nic_clear_name_list(names, numnics);
				free ((*nc)->aliases);
				free (*nc);
				*nc = NULL;
				return (-1);
			}

			if (res == 0) {
				(*nc)->aliases[k] = NULL;

			} else { /* There will be aliases */

				(*nc)->aliases[0] = (char *)list->name;
				while (list->next != NULL) {
					(*nc)->aliases[j] =
					    (char *)(list->next);
					j++;
					list = list->next;
				}
			}
			k++;
			*number = k; /* needed if we have to cleanup on fail */
			j = 1;
			(*nc)++; /* increment pointer */
		}
	} /* end for */

	*nc = nc_array;
	(void) smb_nic_clear_name_list(names, numnics);
	return (0);
}

/*
 * Return a space separated list of interface names depending on specified
 * flags. Either flags argument can be set to 0 if the caller chooses.
 * Returns NULL if no interfaces match the passed flags
 * flags_on: flags which must be on in each interface returned
 * flags_off : flags which must be off in each interface returned
 */
char *
smb_nic_get_ifnames(int flags_on, int flags_off)
{
	struct ifconf	ifc;
	int		numifs, i, sfd;
	char		*ifnames;


	sfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sfd == -1)
		return (NULL);

	if ((ioctl(sfd, SIOCGIFNUM, &numifs) == -1) || (numifs <= 0)) {
		(void) close(sfd);
		return (NULL);
	}

	ifnames = malloc(numifs * (LIFNAMSIZ + 1));
	if (ifnames == NULL) {
		return (NULL);
	}
	ifc.ifc_len = (numifs * sizeof (struct ifreq));
	ifc.ifc_req = malloc(numifs * sizeof (struct ifreq));
	if (ifc.ifc_req == NULL) {
		free(ifnames);
		return (NULL);
	}

	if (ioctl(sfd, SIOCGIFCONF, &ifc) == -1) {
		(void) close(sfd);
		free(ifnames);
		free(ifc.ifc_req);
		return (NULL);
	}

	for (i = 0; i < numifs; i++) {
		if (ioctl(sfd, SIOCGIFFLAGS, &ifc.ifc_req[i]) == 0) {
			if ((ifc.ifc_req[i].ifr_flags &
			    (flags_on | flags_off)) != flags_on) {
				continue;
			}
		}

		(void) strcat(ifnames, ifc.ifc_req[i].ifr_name);
		(void) strcat(ifnames, " ");
	}

	if (strlen(ifnames) > 1)
		ifnames[strlen(ifnames) - 1] = '\0';

	(void) close(sfd);
	free(ifc.ifc_req);

	return (ifnames);
}

/*
 * Function to determine if passed address is of form a.b.c.d.
 */
int
smb_nic_validate_ip_address(char *IP)
{
	in_addr_t addr;
	if ((int)(addr = inet_addr(IP)) == -1) {
		syslog(LOG_ERR, "%s", "IP-address must be"
		    " of the form a.b.c.d");
		return (addr);
	}
	else
		return (0);

}

/*
 * Get flags associated with if
 * -1 means there was an error retrieving the data
 * 0 success
 */
int
smb_nic_flags(char *interface, uint64_t *flag)
{
	struct lifreq   lifrr;
	int sfd;

	sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

	if (sfd < 0) {
		syslog(LOG_ERR, "%s", "smb_get_nic_flags: socket open failed");
		return (-1);
	}

	(void) strncpy(lifrr.lifr_name, interface, sizeof (lifrr.lifr_name));

	if (ioctl(sfd, SIOCGLIFFLAGS, &lifrr) < 0) {
		syslog(LOG_ERR, "%s", "smb_get_nic_flags: get flags failed");
		(void) close(sfd);
		return (-1);
	}

	(void) close(sfd);
	if (flag != NULL)
		*flag = lifrr.lifr_flags;
	return (0);
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
 * -1 means there was an error retrieving the data
 * 0 indicates false - the flag isn't associated
 * 1 indicates true - the flag is associated
 */
int
smb_nic_status(char *interface, uint64_t flag)
{
	struct lifreq   lifrr;
	int sfd;

	sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

	if (sfd < 0) {
		syslog(LOG_ERR, "%s", "nic_status: socket open failed");
		return (-1);
	}

	(void) strncpy(lifrr.lifr_name, interface, sizeof (lifrr.lifr_name));

	if (ioctl(sfd, SIOCGLIFFLAGS, &lifrr) < 0) {
		syslog(LOG_ERR, "%s", "nic_status: get flags failed");
		(void) close(sfd);
		return (-1);
	}

	if (lifrr.lifr_flags & flag) {
		(void) close(sfd);
		return (1); /* associated */
	} else {
		(void) close(sfd);
		return (0); /* not associated */
	}
}

/*
 * Free allocated memory for net_cfg structures. Takes number of allocated
 * structures as argument also
 */
int
smb_nic_clear_niclist(net_cfg_t *niclist, int amount)
{
	int i, j = 0;

	if (niclist == NULL)
		return (-1);
	for (i = 0; i < amount; i++) {
		while (niclist[i].aliases[j] != NULL) {
			free(niclist[i].aliases[j]);
			niclist[i].aliases[j] = NULL;
			j++;
		}
		free(niclist[i].aliases);
		niclist[i].aliases = NULL;
		j = 0;
	}
	free(niclist);

	return (0);
}

int
smb_nic_free_niclist(net_cfg_list_t *niclist)
{
	int ret;

	ret = smb_nic_clear_niclist(niclist->net_cfg_list,
	    niclist->net_cfg_cnt);
	niclist->net_cfg_list = NULL;
	niclist->net_cfg_cnt = 0;
	return (ret);
}

/*
 * Free allocated memory for names lists. Takes number of allocated
 * pointers as argument also
 */
int
smb_nic_clear_name_list(char **names, int amount)
{
	int i;

	for (i = 0; i < amount; i++) {
		free(names[i]);
	}

	free(names);
	return (0);
}

/* Free allocated memory for names lists. */

static void
smb_nic_clear_if_list(struct if_list *iflist)
{
	struct if_list *tmp;

	if (iflist == NULL)
		return;
	for (; iflist != NULL; iflist = tmp) {
		tmp = iflist->next;
		free(iflist);
	}
}

/* Free allocated memory for alias lists. */
int
smb_nic_clear_ip_alias(struct ip_alias *iplist)
{
	struct ip_alias *tmp;

	for (; iplist != NULL; iplist = tmp) {
		tmp = iplist->next;
		free(iplist);
	}

	return (0);
}

/*
 * smb_nic_lock
 *
 * Lock the nic table
 */
void
smb_nic_lock(void)
{
	(void) pthread_mutex_lock(&smb_nic_mutex);
}

/*
 * smb_nic_unlock
 *
 * Unlock the nic table.
 *
 * This function MUST be called after lock
 */
void
smb_nic_unlock(void)
{
	(void) pthread_mutex_unlock(&smb_nic_mutex);
}

int
smb_nic_init()
{
	int ret;

	smb_nic_lock();
	smb_nic_list.net_cfg_cnt = 0;
	smb_nic_list.net_cfg_list = NULL;
	ret = smb_nic_build_network_structures(&smb_nic_list.net_cfg_list,
	    &smb_nic_list.net_cfg_cnt);
	if (ret != 0)
		(void) smb_nic_free_niclist(&smb_nic_list);
	smb_nic_unlock();
	return (0);
}

/*
 * Initialize interface list.
 */
void
smb_nic_build_info(void)
{
	int ret;

	smb_nic_lock();
	if (smb_nic_list.net_cfg_list) {
		(void) smb_nic_free_niclist(&smb_nic_list);
	}
	smb_nic_list.net_cfg_cnt = 0;
	ret = smb_nic_build_network_structures(&smb_nic_list.net_cfg_list,
	    &smb_nic_list.net_cfg_cnt);
	if (ret != 0)
		(void) smb_nic_free_niclist(&smb_nic_list);
	if (smb_nic_list.net_cfg_cnt == 0)
		syslog(LOG_ERR, "smb: No network interfaces are configured "
		    "smb server may not function properly");

	smb_nic_unlock();
}

/*
 * Get number of interfaces.
 */
int
smb_nic_get_num(void)
{
	int sz;
	smb_nic_lock();
	sz = smb_nic_list.net_cfg_cnt;
	smb_nic_unlock();
	return (sz);
}

/*
 * Get if by index
 * Returns: NULL if not found.
 */
net_cfg_t *
smb_nic_get_byind(int ind, net_cfg_t *cfg)
{
	if (cfg == NULL)
		return (cfg);
	smb_nic_lock();
	if (ind > smb_nic_list.net_cfg_cnt) {
		smb_nic_unlock();
		return (NULL);
	}
	bcopy(&smb_nic_list.net_cfg_list[ind], cfg, sizeof (net_cfg_t));
	smb_nic_unlock();
	return (cfg);
}

/*
 * Get if by subnet
 * Returns: NULL if not found.
 */
net_cfg_t *
smb_nic_get_bysubnet(uint32_t ipaddr, net_cfg_t *cfg)
{
	int i;
	net_cfg_t *tcfg;

	if (cfg == NULL)
		return (cfg);
	smb_nic_lock();
	bzero(cfg, sizeof (net_cfg_t));
	for (i = 0; i < smb_nic_list.net_cfg_cnt; i++) {
		tcfg = &smb_nic_list.net_cfg_list[i];
		if ((ipaddr & tcfg->mask) ==
		    (tcfg->ip & tcfg->mask)) {
			bcopy(tcfg, cfg, sizeof (net_cfg_t));
			smb_nic_unlock();
			return (cfg);
		}
	}
	smb_nic_unlock();
	return (NULL);
}

/*
 * Get if by ip.
 * Returns: NULL if not found.
 */
net_cfg_t *
smb_nic_get_byip(uint32_t ipaddr, net_cfg_t *cfg)
{
	int i;
	net_cfg_t *tcfg;

	if (cfg == NULL)
		return (cfg);
	smb_nic_lock();
	bzero(cfg, sizeof (net_cfg_t));
	for (i = 0; i < smb_nic_list.net_cfg_cnt; i++) {
		tcfg = &smb_nic_list.net_cfg_list[i];
		if (ipaddr == tcfg->ip) {
			bcopy(tcfg, cfg, sizeof (net_cfg_t));
			smb_nic_unlock();
			return (cfg);
		}
	}
	smb_nic_unlock();
	return (NULL);
}
