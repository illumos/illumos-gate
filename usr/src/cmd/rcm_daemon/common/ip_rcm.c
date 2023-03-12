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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * This RCM module adds support to the RCM framework for IP managed
 * interfaces.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <synch.h>
#include <libintl.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stropts.h>
#include <strings.h>
#include <sys/sysmacros.h>
#include <inet/ip.h>
#include <libinetutil.h>
#include <libdllink.h>
#include <libgen.h>
#include <ipmp_admin.h>
#include <libipadm.h>

#include "rcm_module.h"

/*
 * Definitions
 */
#ifndef lint
#define	_(x)	gettext(x)
#else
#define	_(x)	x
#endif

/* Some generic well-knowns and defaults used in this module */
#define	ARP_MOD_NAME		"arp"		/* arp module */
#define	IP_MAX_MODS		9		/* max modules pushed on intr */
#define	MAX_RECONFIG_SIZE	1024		/* Max. reconfig string size */

#define	RCM_LINK_PREFIX		"SUNW_datalink"	/* RCM datalink name prefix */
#define	RCM_LINK_RESOURCE_MAX	(13 + LINKID_STR_WIDTH)

#define	RCM_STR_SUNW_IP		"SUNW_ip/"	/* IP address export prefix */

#define	SBIN_IFCONFIG		"/sbin/ifconfig" /* ifconfig command */
#define	SBIN_IFPARSE		"/sbin/ifparse"	/* ifparse command */
#define	DHCPFILE_FMT		"/etc/dhcp.%s"	/* DHCP config file */
#define	CFGFILE_FMT_IPV4	"/etc/hostname.%s"  /* IPV4 config file */
#define	CFGFILE_FMT_IPV6	"/etc/hostname6.%s" /* IPV6 config file */
#define	CFG_CMDS_STD	" netmask + broadcast + up" /* Normal config string */
#define	CFG_DHCP_CMD		"dhcp wait 0"	/* command to start DHCP */

/* Some useful macros */
#define	ISSPACE(c)	((c) == ' ' || (c) == '\t')
#define	ISEOL(c)	((c) == '\n' || (c) == '\r' || (c) == '\0')
#define	STREQ(a, b)	(*(a) == *(b) && strcmp((a), (b)) == 0)

/* Interface Cache state flags */
#define	CACHE_IF_STALE		0x1		/* stale cached data */
#define	CACHE_IF_NEW		0x2		/* new cached interface */
#define	CACHE_IF_OFFLINED	0x4		/* interface offlined */
#define	CACHE_IF_IGNORE		0x8		/* state held elsewhere */

/* Network Cache lookup options */
#define	CACHE_NO_REFRESH	0x1		/* cache refresh not needed */
#define	CACHE_REFRESH		0x2		/* refresh cache */

/* RCM IPMP Module specific property definitions */
#define	RCM_IPMP_MIN_REDUNDANCY	1		/* default min. redundancy */

/* Stream module operations */
#define	MOD_INSERT		0	/* Insert a mid-stream module */
#define	MOD_REMOVE		1	/* Remove a mid-stream module */
#define	MOD_CHECK		2	/* Check mid-stream module safety */

/*
 * IP module data types
 */

/* Physical interface representation */
typedef struct ip_pif {
	char		pi_ifname[LIFNAMSIZ];	/* interface name */
	char		pi_grname[LIFGRNAMSIZ]; /* IPMP group name */
	struct ip_lif	*pi_lifs;		/* ptr to logical interfaces */
} ip_pif_t;

/* Logical interface representation */
typedef struct ip_lif
{
	struct ip_lif		*li_next;	/* ptr to next lif */
	struct ip_lif		*li_prev;	/* previous next ptr */
	ip_pif_t		*li_pif;	/* back ptr to phy int */
	ushort_t		li_ifnum;	/* interface number */
	union {
		sa_family_t		family;
		struct sockaddr_storage storage;
		struct sockaddr_in	ip4;    /* IPv4 */
		struct sockaddr_in6	ip6;    /* IPv6 */
	} li_addr;
	uint64_t		li_ifflags;	/* current IFF_* flags */
	int			li_modcnt;	/* # of modules */
	char	*li_modules[IP_MAX_MODS];	/* module list pushed */
	char	*li_reconfig;			/* Reconfiguration string */
	int32_t			li_cachestate;	/* cache state flags */
} ip_lif_t;

/* Cache element */
typedef struct ip_cache
{
	struct ip_cache		*ip_next;	/* next cached resource */
	struct ip_cache		*ip_prev;	/* prev cached resource */
	char			*ip_resource;	/* resource name */
	ip_pif_t		*ip_pif;	/* ptr to phy int */
	int32_t			ip_ifred;	/* min. redundancy */
	int			ip_cachestate;	/* cache state flags */
} ip_cache_t;

/*
 * Global cache for network interfaces
 */
static ip_cache_t	cache_head;
static ip_cache_t	cache_tail;
static mutex_t		cache_lock;
static int		events_registered = 0;

static dladm_handle_t	dld_handle = NULL;
static ipadm_handle_t	ip_handle = NULL;

/*
 * RCM module interface prototypes
 */
static int ip_register(rcm_handle_t *);
static int ip_unregister(rcm_handle_t *);
static int ip_get_info(rcm_handle_t *, char *, id_t, uint_t,
			char **, char **, nvlist_t *, rcm_info_t **);
static int ip_suspend(rcm_handle_t *, char *, id_t,
			timespec_t *, uint_t, char **, rcm_info_t **);
static int ip_resume(rcm_handle_t *, char *, id_t, uint_t,
			char **, rcm_info_t **);
static int ip_offline(rcm_handle_t *, char *, id_t, uint_t,
			char **, rcm_info_t **);
static int ip_undo_offline(rcm_handle_t *, char *, id_t, uint_t,
			char **, rcm_info_t **);
static int ip_remove(rcm_handle_t *, char *, id_t, uint_t,
			char **, rcm_info_t **);
static int ip_notify_event(rcm_handle_t *, char *, id_t, uint_t,
			char **, nvlist_t *, rcm_info_t **);

/* Module private routines */
static void	free_cache();
static int	update_cache(rcm_handle_t *);
static void	cache_remove(ip_cache_t *);
static ip_cache_t *cache_lookup(rcm_handle_t *, char *, char);
static void	free_node(ip_cache_t *);
static void	cache_insert(ip_cache_t *);
static char	*ip_usage(ip_cache_t *);
static int	update_pif(rcm_handle_t *, int, int, struct ifaddrs *);
static int	ip_ipmp_offline(ip_cache_t *);
static int	ip_ipmp_undo_offline(ip_cache_t *);
static int	if_cfginfo(ip_cache_t *, uint_t);
static int	if_unplumb(ip_cache_t *);
static int	if_replumb(ip_cache_t *);
static void	ip_log_err(ip_cache_t *, char **, char *);
static char	*get_link_resource(const char *);
static void	clr_cfg_state(ip_pif_t *);
static int	modop(char *, char *, int, char);
static int	get_modlist(char *, ip_lif_t *);
static int	ip_domux2fd(int *, int *, int *, struct lifreq *);
static int	ip_plink(int, int, int, struct lifreq *);
static int	ip_onlinelist(rcm_handle_t *, ip_cache_t *, char **, uint_t,
			rcm_info_t **);
static int	ip_offlinelist(rcm_handle_t *, ip_cache_t *, char **, uint_t,
			rcm_info_t **);
static char	**ip_get_addrlist(ip_cache_t *);
static void	ip_free_addrlist(char **);
static void	ip_consumer_notify(rcm_handle_t *, datalink_id_t, char **,
			uint_t, rcm_info_t **);
static boolean_t ip_addrstr(ip_lif_t *, char *, size_t);

static int if_configure_hostname(datalink_id_t);
static int if_configure_ipadm(datalink_id_t);
static boolean_t if_hostname_exists(char *, sa_family_t);
static boolean_t isgrouped(const char *);
static int if_config_inst(const char *, FILE *, int, boolean_t);
static uint_t ntok(const char *cp);
static boolean_t ifconfig(const char *, const char *, const char *, boolean_t);

/* Module-Private data */
static struct rcm_mod_ops ip_ops =
{
	RCM_MOD_OPS_VERSION,
	ip_register,
	ip_unregister,
	ip_get_info,
	ip_suspend,
	ip_resume,
	ip_offline,
	ip_undo_offline,
	ip_remove,
	NULL,
	NULL,
	ip_notify_event
};

/*
 * rcm_mod_init() - Update registrations, and return the ops structure.
 */
struct rcm_mod_ops *
rcm_mod_init(void)
{
	char errmsg[DLADM_STRSIZE];
	dladm_status_t status;
	ipadm_status_t iph_status;

	rcm_log_message(RCM_TRACE1, "IP: mod_init\n");

	cache_head.ip_next = &cache_tail;
	cache_head.ip_prev = NULL;
	cache_tail.ip_prev = &cache_head;
	cache_tail.ip_next = NULL;
	(void) mutex_init(&cache_lock, USYNC_THREAD, NULL);

	if ((status = dladm_open(&dld_handle)) != DLADM_STATUS_OK) {
		rcm_log_message(RCM_WARNING,
		    "IP: mod_init failed: cannot get datalink handle: %s\n",
		    dladm_status2str(status, errmsg));
		return (NULL);
	}

	if ((iph_status = ipadm_open(&ip_handle, 0)) != IPADM_SUCCESS) {
		rcm_log_message(RCM_ERROR,
		    "IP: mod_init failed: cannot get IP handle: %s\n",
		    ipadm_status2str(iph_status));
		dladm_close(dld_handle);
		dld_handle = NULL;
		return (NULL);
	}

	/* Return the ops vectors */
	return (&ip_ops);
}

/*
 * rcm_mod_info() - Return a string describing this module.
 */
const char *
rcm_mod_info(void)
{
	rcm_log_message(RCM_TRACE1, "IP: mod_info\n");

	return ("IP Multipathing module version 1.23");
}

/*
 * rcm_mod_fini() - Destroy the network interfaces cache.
 */
int
rcm_mod_fini(void)
{
	rcm_log_message(RCM_TRACE1, "IP: mod_fini\n");

	free_cache();
	(void) mutex_destroy(&cache_lock);

	dladm_close(dld_handle);
	ipadm_close(ip_handle);
	return (RCM_SUCCESS);
}

/*
 * ip_register() - Make sure the cache is properly sync'ed, and its
 *		 registrations are in order.
 */
static int
ip_register(rcm_handle_t *hd)
{
	rcm_log_message(RCM_TRACE1, "IP: register\n");

	/* Guard against bad arguments */
	assert(hd != NULL);

	if (update_cache(hd) < 0)
		return (RCM_FAILURE);

	/*
	 * Need to register interest in all new resources
	 * getting attached, so we get attach event notifications
	 */
	if (!events_registered) {
		if (rcm_register_event(hd, RCM_RESOURCE_LINK_NEW, 0, NULL)
		    != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("IP: failed to register %s\n"),
			    RCM_RESOURCE_LINK_NEW);
			return (RCM_FAILURE);
		} else {
			rcm_log_message(RCM_DEBUG, "IP: registered %s\n",
			    RCM_RESOURCE_LINK_NEW);
			events_registered++;
		}
	}

	return (RCM_SUCCESS);
}

/*
 * ip_unregister() - Walk the cache, unregistering all the networks.
 */
static int
ip_unregister(rcm_handle_t *hd)
{
	ip_cache_t *probe;

	rcm_log_message(RCM_TRACE1, "IP: unregister\n");

	/* Guard against bad arguments */
	assert(hd != NULL);

	/* Walk the cache, unregistering everything */
	(void) mutex_lock(&cache_lock);
	probe = cache_head.ip_next;
	while (probe != &cache_tail) {
		if (rcm_unregister_interest(hd, probe->ip_resource, 0)
		    != RCM_SUCCESS) {
			/* unregister failed for whatever reason */
			(void) mutex_unlock(&cache_lock);
			return (RCM_FAILURE);
		}
		cache_remove(probe);
		free_node(probe);
		probe = cache_head.ip_next;
	}
	(void) mutex_unlock(&cache_lock);

	/*
	 * Need to unregister interest in all new resources
	 */
	if (events_registered) {
		if (rcm_unregister_event(hd, RCM_RESOURCE_LINK_NEW, 0)
		    != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("IP: failed to unregister %s\n"),
			    RCM_RESOURCE_LINK_NEW);
			return (RCM_FAILURE);
		} else {
			rcm_log_message(RCM_DEBUG, "IP: unregistered %s\n",
			    RCM_RESOURCE_LINK_NEW);
			events_registered--;
		}
	}

	return (RCM_SUCCESS);
}

/*
 * ip_offline() - Offline an interface.
 */
static int
ip_offline(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **depend_info)
{
	ip_cache_t *node;
	ip_pif_t *pif;
	boolean_t detachable = B_FALSE;
	boolean_t ipmp;
	int retval;

	rcm_log_message(RCM_TRACE1, "IP: offline(%s)\n", rsrc);

	/* Guard against bad arguments */
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(errorp != NULL);
	assert(depend_info != NULL);

	/* Lock the cache and lookup the resource */
	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_REFRESH);
	if (node == NULL) {
		ip_log_err(node, errorp, "Unrecognized resource");
		errno = ENOENT;
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	pif = node->ip_pif;

	/* Establish default detachability criteria */
	if (flags & RCM_FORCE)
		detachable = B_TRUE;

	/* Check if the interface is under IPMP */
	ipmp = (pif->pi_grname[0] != '\0');

	/*
	 * Even if the interface is not under IPMP, it's possible that it's
	 * still okay to offline it as long as there are higher-level failover
	 * mechanisms for the addresses it owns (e.g., clustering).  In this
	 * case, ip_offlinelist() will return RCM_SUCCESS, and we charge on.
	 */
	if (!ipmp && !detachable) {
		/* Inform consumers of IP addresses being offlined */
		if (ip_offlinelist(hd, node, errorp, flags, depend_info) ==
		    RCM_SUCCESS) {
			rcm_log_message(RCM_DEBUG,
			    "IP: consumers agree on detach");
		} else {
			ip_log_err(node, errorp,
			    "Device consumers prohibit offline");
			(void) mutex_unlock(&cache_lock);
			return (RCM_FAILURE);
		}
	}

	/* Check if it's a query */
	if (flags & RCM_QUERY) {
		rcm_log_message(RCM_TRACE1, "IP: offline query success(%s)\n",
		    rsrc);
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	/* Check detachability, save configuration if detachable */
	if (if_cfginfo(node, (flags & RCM_FORCE)) < 0) {
		node->ip_cachestate |= CACHE_IF_IGNORE;
		rcm_log_message(RCM_TRACE1, "IP: Ignoring node(%s)\n", rsrc);
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	/* standalone detachable device */
	if (!ipmp) {
		if (if_unplumb(node) < 0) {
			ip_log_err(node, errorp,
			    "Failed to unplumb the device");

			errno = EIO;
			(void) mutex_unlock(&cache_lock);
			return (RCM_FAILURE);
		}

		node->ip_cachestate |= CACHE_IF_OFFLINED;
		rcm_log_message(RCM_TRACE1, "IP: Offline success(%s)\n", rsrc);
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	/*
	 * This is an IPMP interface that can be offlined.
	 * Request in.mpathd(8) to offline the physical interface.
	 */
	if ((retval = ip_ipmp_offline(node)) != IPMP_SUCCESS)
		ip_log_err(node, errorp, "in.mpathd offline failed");

	if (retval == IPMP_EMINRED && !detachable) {
		/*
		 * in.mpathd(8) could not offline the device because it was
		 * the last interface in the group.  However, it's possible
		 * that it's still okay to offline it as long as there are
		 * higher-level failover mechanisms for the addresses it owns
		 * (e.g., clustering).  In this case, ip_offlinelist() will
		 * return RCM_SUCCESS, and we charge on.
		 */
		/* Inform consumers of IP addresses being offlined */
		if (ip_offlinelist(hd, node, errorp, flags,
		    depend_info) == RCM_SUCCESS) {
			rcm_log_message(RCM_DEBUG,
			    "IP: consumers agree on detach");
		} else {
			ip_log_err(node, errorp,
			    "Device consumers prohibit offline");
			(void) mutex_unlock(&cache_lock);
			errno = EBUSY;
			return (RCM_FAILURE);
		}
	}

	if (if_unplumb(node) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: Unplumb failed (%s)\n"),
		    pif->pi_ifname);

		/* Request in.mpathd to undo the offline */
		if (ip_ipmp_undo_offline(node) != IPMP_SUCCESS) {
			ip_log_err(node, errorp, "Undo offline failed");
			(void) mutex_unlock(&cache_lock);
			return (RCM_FAILURE);
		}
		(void) mutex_unlock(&cache_lock);
		return (RCM_FAILURE);
	}

	node->ip_cachestate |= CACHE_IF_OFFLINED;
	rcm_log_message(RCM_TRACE1, "IP: offline success(%s)\n", rsrc);
	(void) mutex_unlock(&cache_lock);
	return (RCM_SUCCESS);
}

/*
 * ip_undo_offline() - Undo offline of a previously offlined device.
 */
/*ARGSUSED*/
static int
ip_undo_offline(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **depend_info)
{
	ip_cache_t *node;

	rcm_log_message(RCM_TRACE1, "IP: online(%s)\n", rsrc);

	/* Guard against bad arguments */
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(errorp != NULL);
	assert(depend_info != NULL);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH);

	if (node == NULL) {
		ip_log_err(node, errorp, "No such device");
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	/* Check if no attempt should be made to online the device here */
	if (node->ip_cachestate & CACHE_IF_IGNORE) {
		node->ip_cachestate &= ~(CACHE_IF_IGNORE);
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}

	/* Check if the interface was previously offlined */
	if (!(node->ip_cachestate & CACHE_IF_OFFLINED)) {
		ip_log_err(node, errorp, "Device not offlined");
		(void) mutex_unlock(&cache_lock);
		errno = ENOTSUP;
		return (RCM_FAILURE);
	}

	if (if_replumb(node) == -1) {
		/* re-plumb failed */
		ip_log_err(node, errorp, "Replumb failed");
		(void) mutex_unlock(&cache_lock);
		errno = EIO;
		return (RCM_FAILURE);

	}

	/* Inform consumers about IP addresses being un-offlined */
	(void) ip_onlinelist(hd, node, errorp, flags, depend_info);

	node->ip_cachestate &= ~(CACHE_IF_OFFLINED);
	rcm_log_message(RCM_TRACE1, "IP: online success(%s)\n", rsrc);
	(void) mutex_unlock(&cache_lock);
	return (RCM_SUCCESS);
}

/*
 * ip_get_info() - Gather usage information for this resource.
 */
/*ARGSUSED*/
int
ip_get_info(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **usagep, char **errorp, nvlist_t *props, rcm_info_t **depend_info)
{
	ip_cache_t *node;
	char *infostr;

	/* Guard against bad arguments */
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(usagep != NULL);
	assert(errorp != NULL);
	assert(depend_info != NULL);

	rcm_log_message(RCM_TRACE1, "IP: get_info(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_REFRESH);
	if (!node) {
		rcm_log_message(RCM_INFO,
		    _("IP: get_info(%s) unrecognized resource\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	infostr = ip_usage(node);

	if (infostr == NULL) {
		/* most likely malloc failure */
		rcm_log_message(RCM_ERROR,
		    _("IP: get_info(%s) malloc failure\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOMEM;
		*errorp = NULL;
		return (RCM_FAILURE);
	}

	/* Set client/role properties */
	(void) nvlist_add_string(props, RCM_CLIENT_NAME, "IP");

	/* Set usage property, infostr will be freed by caller */
	*usagep = infostr;

	rcm_log_message(RCM_TRACE1, "IP: get_info(%s) info = %s \n",
	    rsrc, infostr);

	(void) mutex_unlock(&cache_lock);
	return (RCM_SUCCESS);
}

/*
 * ip_suspend() - Nothing to do, always okay
 */
/*ARGSUSED*/
static int
ip_suspend(rcm_handle_t *hd, char *rsrc, id_t id, timespec_t *interval,
    uint_t flags, char **errorp, rcm_info_t **depend_info)
{
	/* Guard against bad arguments */
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(interval != NULL);
	assert(errorp != NULL);
	assert(depend_info != NULL);

	rcm_log_message(RCM_TRACE1, "IP: suspend(%s)\n", rsrc);
	return (RCM_SUCCESS);
}

/*
 * ip_resume() - Nothing to do, always okay
 */
/*ARGSUSED*/
static int
ip_resume(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t ** depend_info)
{
	/* Guard against bad arguments */
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(errorp != NULL);
	assert(depend_info != NULL);

	rcm_log_message(RCM_TRACE1, "IP: resume(%s)\n", rsrc);

	return (RCM_SUCCESS);
}

/*
 * ip_remove() - remove a resource from cache
 */
/*ARGSUSED*/
static int
ip_remove(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, rcm_info_t **depend_info)
{
	ip_cache_t *node;

	/* Guard against bad arguments */
	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(errorp != NULL);
	assert(depend_info != NULL);

	rcm_log_message(RCM_TRACE1, "IP: remove(%s)\n", rsrc);

	(void) mutex_lock(&cache_lock);
	node = cache_lookup(hd, rsrc, CACHE_NO_REFRESH);
	if (!node) {
		rcm_log_message(RCM_INFO,
		    _("IP: remove(%s) unrecognized resource\n"), rsrc);
		(void) mutex_unlock(&cache_lock);
		errno = ENOENT;
		return (RCM_FAILURE);
	}

	/* remove the cached entry for the resource */
	cache_remove(node);
	free_node(node);

	(void) mutex_unlock(&cache_lock);
	return (RCM_SUCCESS);
}

/*
 * ip_notify_event - Project private implementation to receive new resource
 *		   events. It intercepts all new resource events. If the
 *		   new resource is a network resource, pass up a notify
 *		   for it too. The new resource need not be cached, since
 *		   it is done at register again.
 */
/*ARGSUSED*/
static int
ip_notify_event(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **errorp, nvlist_t *nvl, rcm_info_t **depend_info)
{
	datalink_id_t	linkid;
	nvpair_t *nvp = NULL;
	uint64_t id64;

	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(nvl != NULL);

	rcm_log_message(RCM_TRACE1, "IP: notify_event(%s)\n", rsrc);

	if (!STREQ(rsrc, RCM_RESOURCE_LINK_NEW)) {
		rcm_log_message(RCM_INFO,
		    _("IP: unrecognized event for %s\n"), rsrc);
		ip_log_err(NULL, errorp, "unrecognized event");
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	/* Update cache to reflect latest interfaces */
	if (update_cache(hd) < 0) {
		rcm_log_message(RCM_ERROR, _("IP: update_cache failed\n"));
		ip_log_err(NULL, errorp, "Private Cache update failed");
		return (RCM_FAILURE);
	}

	rcm_log_message(RCM_TRACE1, "IP: process_nvlist\n");
	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		if (STREQ(nvpair_name(nvp), RCM_NV_LINKID)) {
			if (nvpair_value_uint64(nvp, &id64) != 0) {
				rcm_log_message(RCM_WARNING,
				    _("IP: cannot get linkid\n"));
				return (RCM_FAILURE);
			}
			linkid = (datalink_id_t)id64;
			/*
			 * Grovel through /etc/hostname* files and configure
			 * interface in the same way that they would be handled
			 * by network/physical.
			 */
			if (if_configure_hostname(linkid) != 0) {
				rcm_log_message(RCM_ERROR,
				    _("IP: Configuration failed (%u)\n"),
				    linkid);
				ip_log_err(NULL, errorp,
				    "Failed configuring one or more IP "
				    "addresses");
			}

			/*
			 * Query libipadm for persistent configuration info
			 * and resurrect that persistent configuration.
			 */
			if (if_configure_ipadm(linkid) != 0) {
				rcm_log_message(RCM_ERROR,
				    _("IP: Configuration failed (%u)\n"),
				    linkid);
				ip_log_err(NULL, errorp,
				    "Failed configuring one or more IP "
				    "addresses");
			}

			/* Notify all IP address consumers */
			ip_consumer_notify(hd, linkid, errorp, flags,
			    depend_info);
		}
	}

	rcm_log_message(RCM_TRACE1,
	    "IP: notify_event: device configuration complete\n");

	return (RCM_SUCCESS);
}

/*
 * ip_usage - Determine the usage of a device.  Call with cache_lock held.
 *	    The returned buffer is owned by caller, and the caller
 *	    must free it up when done.
 */
static char *
ip_usage(ip_cache_t *node)
{
	ip_lif_t *lif;
	uint_t numup;
	char *sep, *buf, *linkidstr;
	datalink_id_t linkid;
	const char *msg;
	char link[MAXLINKNAMELEN];
	char addrstr[INET6_ADDRSTRLEN];
	char errmsg[DLADM_STRSIZE];
	dladm_status_t status;
	boolean_t offline, ipmp;
	size_t bufsz = 0;

	rcm_log_message(RCM_TRACE2, "IP: usage(%s)\n", node->ip_resource);

	/*
	 * Note that node->ip_resource is in the form of SUNW_datalink/<linkid>
	 */
	linkidstr = strchr(node->ip_resource, '/');
	assert(linkidstr != NULL);
	linkidstr = linkidstr ? linkidstr + 1 : node->ip_resource;

	errno = 0;
	linkid = strtol(linkidstr, &buf, 10);
	if (errno != 0 || *buf != '\0') {
		rcm_log_message(RCM_ERROR,
		    _("IP: usage(%s) parse linkid failure (%s)\n"),
		    node->ip_resource, strerror(errno));
		return (NULL);
	}

	if ((status = dladm_datalink_id2info(dld_handle, linkid, NULL, NULL,
	    NULL, link, sizeof (link))) != DLADM_STATUS_OK) {
		rcm_log_message(RCM_ERROR,
		    _("IP: usage(%s) get link name failure(%s)\n"),
		    node->ip_resource, dladm_status2str(status, errmsg));
		return (NULL);
	}

	/* TRANSLATION_NOTE: separator used between IP addresses */
	sep = _(", ");

	numup = 0;
	for (lif = node->ip_pif->pi_lifs; lif != NULL; lif = lif->li_next)
		if (lif->li_ifflags & IFF_UP)
			numup++;

	ipmp = (node->ip_pif->pi_grname[0] != '\0');
	offline = ((node->ip_cachestate & CACHE_IF_OFFLINED) != 0);

	if (offline) {
		msg = _("offlined");
	} else if (numup == 0) {
		msg = _("plumbed but down");
	} else {
		if (ipmp) {
			msg = _("providing connectivity for IPMP group ");
			bufsz += LIFGRNAMSIZ;
		} else {
			msg = _("hosts IP addresses: ");
			bufsz += (numup * (INET6_ADDRSTRLEN + strlen(sep)));
		}
	}

	bufsz += strlen(link) + strlen(msg) + 1;
	if ((buf = malloc(bufsz)) == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("IP: usage(%s) malloc failure(%s)\n"),
		    node->ip_resource, strerror(errno));
		return (NULL);
	}
	(void) snprintf(buf, bufsz, "%s: %s", link, msg);

	if (!offline && numup > 0) {
		if (ipmp) {
			(void) strlcat(buf, node->ip_pif->pi_grname, bufsz);
		} else {
			lif = node->ip_pif->pi_lifs;
			for (; lif != NULL; lif = lif->li_next) {
				if (!(lif->li_ifflags & IFF_UP))
					continue;

				if (!ip_addrstr(lif, addrstr, sizeof (addrstr)))
					continue;

				(void) strlcat(buf, addrstr, bufsz);
				if (--numup > 0)
					(void) strlcat(buf, sep, bufsz);
			}
		}
	}

	rcm_log_message(RCM_TRACE2, "IP: usage (%s) info = %s\n",
	    node->ip_resource, buf);

	return (buf);
}

static boolean_t
ip_addrstr(ip_lif_t *lif, char *addrstr, size_t addrsize)
{
	int af = lif->li_addr.family;
	void *addr;

	if (af == AF_INET6) {
		addr = &lif->li_addr.ip6.sin6_addr;
	} else if (af == AF_INET) {
		addr = &lif->li_addr.ip4.sin_addr;
	} else {
		rcm_log_message(RCM_DEBUG,
		    "IP: unknown addr family %d, assuming AF_INET\n", af);
		af = AF_INET;
		addr = &lif->li_addr.ip4.sin_addr;
	}
	if (inet_ntop(af, addr, addrstr, addrsize) == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("IP: inet_ntop: %s\n"), strerror(errno));
		return (B_FALSE);
	}

	rcm_log_message(RCM_DEBUG, "IP addr := %s\n", addrstr);
	return (B_TRUE);
}

/*
 * Cache management routines, all cache management functions should be
 * be called with cache_lock held.
 */

/*
 * cache_lookup() - Get a cache node for a resource.
 *		  Call with cache lock held.
 *
 * This ensures that the cache is consistent with the system state and
 * returns a pointer to the cache element corresponding to the resource.
 */
static ip_cache_t *
cache_lookup(rcm_handle_t *hd, char *rsrc, char options)
{
	ip_cache_t *probe;

	rcm_log_message(RCM_TRACE2, "IP: cache lookup(%s)\n", rsrc);

	if ((options & CACHE_REFRESH) && (hd != NULL)) {
		/* drop lock since update locks cache again */
		(void) mutex_unlock(&cache_lock);
		(void) update_cache(hd);
		(void) mutex_lock(&cache_lock);
	}

	probe = cache_head.ip_next;
	while (probe != &cache_tail) {
		if (probe->ip_resource &&
		    STREQ(rsrc, probe->ip_resource)) {
			rcm_log_message(RCM_TRACE2,
			    "IP: cache lookup success(%s)\n", rsrc);
			return (probe);
		}
		probe = probe->ip_next;
	}
	return (NULL);
}

/*
 * free_node - Free a node from the cache
 *	     Call with cache_lock held.
 */
static void
free_node(ip_cache_t *node)
{
	ip_pif_t *pif;
	ip_lif_t *lif, *tmplif;

	if (node) {
		if (node->ip_resource) {
			free(node->ip_resource);
		}

		/* free the pif */
		pif = node->ip_pif;
		if (pif) {
			/* free logical interfaces */
			lif = pif->pi_lifs;
			while (lif) {
				tmplif = lif->li_next;
				free(lif);
				lif = tmplif;
			}
			free(pif);
		}
		free(node);
	}
}

/*
 * cache_insert - Insert a resource node in cache
 *		Call with the cache_lock held.
 */
static void
cache_insert(ip_cache_t *node)
{
	rcm_log_message(RCM_TRACE2, "IP: cache insert(%s)\n",
	    node->ip_resource);

	/* insert at the head for best performance */
	node->ip_next = cache_head.ip_next;
	node->ip_prev = &cache_head;

	node->ip_next->ip_prev = node;
	node->ip_prev->ip_next = node;
}

/*
 * cache_remove() - Remove a resource node from cache.
 *		  Call with the cache_lock held.
 */
static void
cache_remove(ip_cache_t *node)
{
	rcm_log_message(RCM_TRACE2, "IP: cache remove(%s)\n",
	    node->ip_resource);

	node->ip_next->ip_prev = node->ip_prev;
	node->ip_prev->ip_next = node->ip_next;
	node->ip_next = NULL;
	node->ip_prev = NULL;
}

/*
 * update_pif() - Update physical interface properties
 *		Call with cache_lock held
 */
int
update_pif(rcm_handle_t *hd, int af, int sock, struct ifaddrs *ifa)
{
	char *rsrc;
	ifspec_t ifspec;
	ushort_t ifnumber = 0;
	ip_cache_t *probe;
	ip_pif_t pif;
	ip_pif_t *probepif;
	ip_lif_t *probelif;
	struct lifreq lifreq;
	struct sockaddr_storage ifaddr;
	uint64_t ifflags;
	int lif_listed = 0;

	rcm_log_message(RCM_TRACE1, "IP: update_pif(%s)\n", ifa->ifa_name);

	if (!ifparse_ifspec(ifa->ifa_name, &ifspec)) {
		rcm_log_message(RCM_ERROR, _("IP: bad network interface: %s\n"),
		    ifa->ifa_name);
		return (-1);
	}

	(void) snprintf(pif.pi_ifname, sizeof (pif.pi_ifname), "%s%d",
	    ifspec.ifsp_devnm, ifspec.ifsp_ppa);
	if (ifspec.ifsp_lunvalid)
		ifnumber = ifspec.ifsp_lun;

	/* Get the interface flags */
	ifflags = ifa->ifa_flags;

	/*
	 * Ignore interfaces that are always incapable of DR:
	 *   - IFF_VIRTUAL:	e.g., loopback and vni
	 *   - IFF_POINTOPOINT:	e.g., sppp and ip.tun
	 *   - !IFF_MULTICAST:	e.g., ip.6to4tun
	 *   - IFF_IPMP:	IPMP meta-interfaces
	 *
	 * Note: The !IFF_MULTICAST check can be removed once iptun is
	 * implemented as a datalink.
	 */
	if (!(ifflags & IFF_MULTICAST) ||
	    (ifflags & (IFF_POINTOPOINT | IFF_VIRTUAL | IFF_IPMP))) {
		rcm_log_message(RCM_TRACE3, "IP: if ignored (%s)\n",
		    pif.pi_ifname);
		return (0);
	}

	/* Get the interface group name for this interface */
	bzero(&lifreq, sizeof (lifreq));
	(void) strncpy(lifreq.lifr_name, ifa->ifa_name, LIFNAMSIZ);

	if (ioctl(sock, SIOCGLIFGROUPNAME, (char *)&lifreq) < 0) {
		if (errno != ENXIO) {
			rcm_log_message(RCM_ERROR,
			    _("IP: SIOCGLIFGROUPNAME(%s): %s\n"),
			    lifreq.lifr_name, strerror(errno));
		}
		return (-1);
	}

	/* copy the group name */
	(void) strlcpy(pif.pi_grname, lifreq.lifr_groupname,
	    sizeof (pif.pi_grname));

	/* Get the interface address for this interface */
	(void) memcpy(&ifaddr, ifa->ifa_addr, sizeof (ifaddr));

	rsrc = get_link_resource(pif.pi_ifname);
	if (rsrc == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("IP: get_link_resource(%s) failed\n"),
		    lifreq.lifr_name);
		return (-1);
	}

	probe = cache_lookup(hd, rsrc, CACHE_NO_REFRESH);
	if (probe != NULL) {
		free(rsrc);
		probe->ip_cachestate &= ~(CACHE_IF_STALE);
	} else {
		if ((probe = calloc(1, sizeof (ip_cache_t))) == NULL) {
			/* malloc errors are bad */
			free(rsrc);
			rcm_log_message(RCM_ERROR, _("IP: calloc: %s\n"),
			    strerror(errno));
			return (-1);
		}

		probe->ip_resource = rsrc;
		probe->ip_pif = NULL;
		probe->ip_ifred = RCM_IPMP_MIN_REDUNDANCY;
		probe->ip_cachestate |= CACHE_IF_NEW;

		cache_insert(probe);
	}

	probepif = probe->ip_pif;
	if (probepif != NULL) {
		/* Check if lifs need to be updated */
		probelif = probepif->pi_lifs;
		while (probelif != NULL) {
			if ((probelif->li_ifnum == ifnumber) &&
			    (probelif->li_addr.family == ifaddr.ss_family)) {

				rcm_log_message(RCM_TRACE2,
				    "IP: refreshing lifs for %s, ifnum=%d\n",
				    pif.pi_ifname, probelif->li_ifnum);

				/* refresh lif properties */
				(void) memcpy(&probelif->li_addr, &ifaddr,
				    sizeof (probelif->li_addr));

				probelif->li_ifflags = ifflags;

				lif_listed++;
				probelif->li_cachestate &= ~(CACHE_IF_STALE);
				break;
			}
			probelif = probelif->li_next;
		}
	}

	if (probepif == NULL) {
		if ((probepif = calloc(1, sizeof (ip_pif_t))) == NULL) {
			rcm_log_message(RCM_ERROR, _("IP: malloc: %s\n"),
			    strerror(errno));
			if (probe->ip_pif == NULL) {
				/* we created it, so clean it up */
				free(probe);
			}
			return (-1);
		}

		probe->ip_pif = probepif;

		/* Save interface name */
		(void) memcpy(&probepif->pi_ifname, &pif.pi_ifname,
		    sizeof (pif.pi_ifname));
	}

	/* save the group name */
	(void) strlcpy(probepif->pi_grname, pif.pi_grname,
	    sizeof (pif.pi_grname));

	/* add lif, if this is a lif and it is not in cache */
	if (!lif_listed) {
		rcm_log_message(RCM_TRACE2, "IP: adding lifs to %s\n",
		    pif.pi_ifname);

		if ((probelif = calloc(1, sizeof (ip_lif_t))) == NULL) {
			rcm_log_message(RCM_ERROR, _("IP: malloc: %s\n"),
			    strerror(errno));
			return (-1);
		}

		/* save lif properties */
		(void) memcpy(&probelif->li_addr, &ifaddr,
		    sizeof (probelif->li_addr));

		probelif->li_ifnum = ifnumber;
		probelif->li_ifflags = ifflags;

		/* insert us at the head of the lif list */
		probelif->li_next = probepif->pi_lifs;
		if (probelif->li_next != NULL) {
			probelif->li_next->li_prev = probelif;
		}
		probelif->li_prev = NULL;
		probelif->li_pif = probepif;

		probepif->pi_lifs = probelif;
	}

	rcm_log_message(RCM_TRACE3, "IP: update_pif: (%s) success\n",
	    probe->ip_resource);

	return (0);
}

/*
 * update_ipifs() - Determine all network interfaces in the system
 *		  Call with cache_lock held
 */
static int
update_ipifs(rcm_handle_t *hd, int af)
{

	struct ifaddrs *ifa;
	ipadm_addr_info_t *ainfo;
	ipadm_addr_info_t *ptr;
	ipadm_status_t status;
	int sock;

	if ((sock = socket(af, SOCK_DGRAM, 0)) == -1) {
		rcm_log_message(RCM_ERROR,
		    _("IP: failure opening %s socket: %s\n"),
		    af == AF_INET6 ? "IPv6" : "IPv4", strerror(errno));
		return (-1);
	}

	status = ipadm_addr_info(ip_handle, NULL, &ainfo, IPADM_OPT_ZEROADDR,
	    LIFC_UNDER_IPMP);
	if (status != IPADM_SUCCESS) {
		(void) close(sock);
		return (-1);
	}
	for (ptr = ainfo; ptr; ptr = IA_NEXT(ptr)) {
		ifa = &ptr->ia_ifa;
		if (ptr->ia_state != IFA_DISABLED &&
		    af == ifa->ifa_addr->sa_family)
			(void) update_pif(hd, af, sock, ifa);
	}
	(void) close(sock);
	ipadm_free_addr_info(ainfo);
	return (0);
}

/*
 * update_cache() - Update cache with latest interface info
 */
static int
update_cache(rcm_handle_t *hd)
{
	ip_cache_t *probe;
	struct ip_lif *lif;
	struct ip_lif *nextlif;
	int rv;
	int i;

	rcm_log_message(RCM_TRACE2, "IP: update_cache\n");

	(void) mutex_lock(&cache_lock);

	/* first we walk the entire cache, marking each entry stale */
	probe = cache_head.ip_next;
	while (probe != &cache_tail) {
		probe->ip_cachestate |= CACHE_IF_STALE;
		if ((probe->ip_pif != NULL) &&
		    ((lif = probe->ip_pif->pi_lifs) != NULL)) {
			while (lif != NULL) {
				lif->li_cachestate |= CACHE_IF_STALE;
				lif = lif->li_next;
			}
		}
		probe = probe->ip_next;
	}

	rcm_log_message(RCM_TRACE2, "IP: scanning IPv4 interfaces\n");
	if (update_ipifs(hd, AF_INET) < 0) {
		(void) mutex_unlock(&cache_lock);
		return (-1);
	}

	rcm_log_message(RCM_TRACE2, "IP: scanning IPv6 interfaces\n");
	if (update_ipifs(hd, AF_INET6) < 0) {
		(void) mutex_unlock(&cache_lock);
		return (-1);
	}

	probe = cache_head.ip_next;
	/* unregister devices that are not offlined and still in cache */
	while (probe != &cache_tail) {
		ip_cache_t *freeit;
		if ((probe->ip_pif != NULL) &&
		    ((lif = probe->ip_pif->pi_lifs) != NULL)) {
			/* clear stale lifs */
			while (lif != NULL) {
				if (lif->li_cachestate & CACHE_IF_STALE) {
					nextlif = lif->li_next;
					if (lif->li_prev != NULL)
						lif->li_prev->li_next = nextlif;
					if (nextlif != NULL)
						nextlif->li_prev = lif->li_prev;
					if (probe->ip_pif->pi_lifs == lif)
						probe->ip_pif->pi_lifs =
						    nextlif;
					for (i = 0; i < IP_MAX_MODS; i++) {
						free(lif->li_modules[i]);
					}
					free(lif->li_reconfig);
					free(lif);
					lif = nextlif;
				} else {
					lif = lif->li_next;
				}
			}
		}
		if ((probe->ip_cachestate & CACHE_IF_STALE) &&
		    !(probe->ip_cachestate & CACHE_IF_OFFLINED)) {
			(void) rcm_unregister_interest(hd, probe->ip_resource,
			    0);
			rcm_log_message(RCM_DEBUG, "IP: unregistered %s\n",
			    probe->ip_resource);
			freeit = probe;
			probe = probe->ip_next;
			cache_remove(freeit);
			free_node(freeit);
			continue;
		}

		if (!(probe->ip_cachestate & CACHE_IF_NEW)) {
			probe = probe->ip_next;
			continue;
		}

		rv = rcm_register_interest(hd, probe->ip_resource, 0, NULL);
		if (rv != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("IP: failed to register %s\n"),
			    probe->ip_resource);
			(void) mutex_unlock(&cache_lock);
			return (-1);
		} else {
			rcm_log_message(RCM_DEBUG, "IP: registered %s\n",
			    probe->ip_resource);
			probe->ip_cachestate &= ~(CACHE_IF_NEW);
		}
		probe = probe->ip_next;
	}

	(void) mutex_unlock(&cache_lock);
	return (0);
}

/*
 * free_cache() - Empty the cache
 */
static void
free_cache()
{
	ip_cache_t *probe;

	rcm_log_message(RCM_TRACE2, "IP: free_cache\n");

	(void) mutex_lock(&cache_lock);
	probe = cache_head.ip_next;
	while (probe != &cache_tail) {
		cache_remove(probe);
		free_node(probe);
		probe = cache_head.ip_next;
	}
	(void) mutex_unlock(&cache_lock);
}

/*
 * ip_log_err() - RCM error log wrapper
 */
static void
ip_log_err(ip_cache_t *node, char **errorp, char *errmsg)
{
	char *ifname = NULL;
	int size;
	const char *errfmt;
	char *error = NULL;

	if (node != NULL && node->ip_pif != NULL) {
		ifname = node->ip_pif->pi_ifname;
	}

	if (ifname == NULL) {
		rcm_log_message(RCM_ERROR, _("IP: %s\n"), errmsg);
		errfmt = _("IP: %s");
		size = strlen(errfmt) + strlen(errmsg) + 1;
		if (errorp != NULL && (error = malloc(size)) != NULL)
			(void) snprintf(error, size, errfmt, errmsg);
	} else {
		rcm_log_message(RCM_ERROR, _("IP: %s(%s)\n"), errmsg, ifname);
		errfmt = _("IP: %s(%s)");
		size = strlen(errfmt) + strlen(errmsg) + strlen(ifname) + 1;
		if (errorp != NULL && (error = malloc(size)) != NULL)
			(void) snprintf(error, size, errfmt, errmsg, ifname);
	}

	if (errorp != NULL)
		*errorp = error;
}

/*
 * if_cfginfo() - Save off the config info for all interfaces
 */
static int
if_cfginfo(ip_cache_t *node, uint_t force)
{
	ip_lif_t *lif;
	ip_pif_t *pif;
	int i;
	FILE *fp;
	char syscmd[MAX_RECONFIG_SIZE + LIFNAMSIZ];
	char buf[MAX_RECONFIG_SIZE];

	rcm_log_message(RCM_TRACE2, "IP: if_cfginfo(%s)\n", node->ip_resource);

	pif = node->ip_pif;
	lif = pif->pi_lifs;

	while (lif != NULL) {
		/* Make a list of modules pushed and save */
		if (lif->li_ifnum == 0) {	/* physical instance */
			if (get_modlist(pif->pi_ifname, lif) == -1) {
				rcm_log_message(RCM_ERROR,
				    _("IP: get modlist error (%s) %s\n"),
				    pif->pi_ifname, strerror(errno));
				clr_cfg_state(pif);
				return (-1);
			}

			if (!force) {
				/* Look if unknown modules have been inserted */
				for (i = (lif->li_modcnt - 2); i > 0; i--) {
					if (modop(pif->pi_ifname,
					    lif->li_modules[i],
					    i, MOD_CHECK) == -1) {
						rcm_log_message(RCM_ERROR,
						    _("IP: module %s@%d\n"),
						    lif->li_modules[i], i);
						clr_cfg_state(pif);
						return (-1);
					}
				}
			}

			/* Last module is the device driver, so ignore that */
			for (i = (lif->li_modcnt - 2); i > 0; i--) {
				rcm_log_message(RCM_TRACE2,
				    "IP: modremove Pos = %d, Module = %s \n",
				    i, lif->li_modules[i]);
				if (modop(pif->pi_ifname, lif->li_modules[i],
				    i, MOD_REMOVE) == -1) {
					while (i != (lif->li_modcnt - 2)) {
						if (modop(pif->pi_ifname,
						    lif->li_modules[i],
						    i, MOD_INSERT) == -1) {
							/* Gross error */
							rcm_log_message(
							    RCM_ERROR,
							    _("IP: if_cfginfo"
							    "(%s) %s\n"),
							    pif->pi_ifname,
							    strerror(errno));
							clr_cfg_state(pif);
							return (-1);
						}
						i++;
					}
					rcm_log_message(
					    RCM_ERROR,
					    _("IP: if_cfginfo(%s): modremove "
					    "%s failed: %s\n"), pif->pi_ifname,
					    lif->li_modules[i],
					    strerror(errno));
					clr_cfg_state(pif);
					return (-1);
				}
			}
		}

		/* Save reconfiguration information */
		if (lif->li_ifflags & IFF_IPV4) {
			(void) snprintf(syscmd, sizeof (syscmd),
			    "%s %s:%d configinfo\n", SBIN_IFCONFIG,
			    pif->pi_ifname, lif->li_ifnum);
		} else if (lif->li_ifflags & IFF_IPV6) {
			(void) snprintf(syscmd, sizeof (syscmd),
			    "%s %s:%d inet6 configinfo\n", SBIN_IFCONFIG,
			    pif->pi_ifname, lif->li_ifnum);
		}
		rcm_log_message(RCM_TRACE2, "IP: %s\n", syscmd);

		/* open a pipe to retrieve reconfiguration info */
		if ((fp = popen(syscmd, "r")) == NULL) {
			rcm_log_message(RCM_ERROR,
			    _("IP: ifconfig configinfo error (%s:%d) %s\n"),
			    pif->pi_ifname, lif->li_ifnum, strerror(errno));
			clr_cfg_state(pif);
			return (-1);
		}
		bzero(buf, MAX_RECONFIG_SIZE);

		if (fgets(buf, MAX_RECONFIG_SIZE, fp) == NULL) {
			rcm_log_message(RCM_ERROR,
			    _("IP: ifconfig configinfo error (%s:%d) %s\n"),
			    pif->pi_ifname, lif->li_ifnum, strerror(errno));
			(void) pclose(fp);
			clr_cfg_state(pif);
			return (-1);
		}
		(void) pclose(fp);

		if ((lif->li_reconfig = strdup(buf)) == NULL) {
			rcm_log_message(RCM_ERROR,
			    _("IP: malloc error (%s) %s\n"),
			    pif->pi_ifname, strerror(errno));
			clr_cfg_state(pif);
			return (-1);
		}
		rcm_log_message(RCM_DEBUG,
		    "IP: if_cfginfo: reconfig string(%s:%d) = %s\n",
		    pif->pi_ifname, lif->li_ifnum, lif->li_reconfig);

		lif = lif->li_next;
	}

	return (0);
}

/*
 * if_unplumb() - Unplumb the interface
 *		Save off the modlist, ifconfig options and unplumb.
 *		Fail, if an unknown module lives between IP and driver and
 *		force is not set
 *		Call with cache_lock held
 */
static int
if_unplumb(ip_cache_t *node)
{
	ip_lif_t *lif;
	ip_pif_t *pif = node->ip_pif;
	boolean_t ipv4 = B_FALSE;
	boolean_t ipv6 = B_FALSE;

	rcm_log_message(RCM_TRACE2, "IP: if_unplumb(%s)\n", node->ip_resource);

	for (lif = pif->pi_lifs; lif != NULL; lif = lif->li_next) {
		if (lif->li_ifflags & IFF_IPV4) {
			ipv4 = B_TRUE;
		} else if (lif->li_ifflags & IFF_IPV6) {
			ipv6 = B_TRUE;
		} else {
			/* Unlikely case */
			rcm_log_message(RCM_DEBUG,
			    "IP: Unplumb ignored (%s:%d)\n",
			    pif->pi_ifname, lif->li_ifnum);
		}
	}

	if (ipv4 && !ifconfig(pif->pi_ifname, "inet", "unplumb", B_FALSE)) {
		rcm_log_message(RCM_ERROR, _("IP: Cannot unplumb (%s) %s\n"),
		    pif->pi_ifname, strerror(errno));
		return (-1);
	}

	if (ipv6 && !ifconfig(pif->pi_ifname, "inet6", "unplumb", B_FALSE)) {
		rcm_log_message(RCM_ERROR, _("IP: Cannot unplumb (%s) %s\n"),
		    pif->pi_ifname, strerror(errno));
		return (-1);
	}

	rcm_log_message(RCM_TRACE2, "IP: if_unplumb(%s) success\n",
	    node->ip_resource);

	return (0);
}

/*
 * if_replumb() - Undo previous unplumb i.e. plumb back the physical interface
 *		instances and the logical interfaces in order, restoring
 *		all ifconfig options
 *		Call with cache_lock held
 */
static int
if_replumb(ip_cache_t *node)
{
	ip_lif_t *lif;
	ip_pif_t *pif;
	int i;
	boolean_t success, ipmp;
	const char *fstr;
	char lifname[LIFNAMSIZ];
	char buf[MAX_RECONFIG_SIZE];
	int max_lifnum = 0;

	rcm_log_message(RCM_TRACE2, "IP: if_replumb(%s)\n", node->ip_resource);

	/*
	 * Be extra careful about bringing up the interfaces in the
	 * correct order:
	 * - First plumb in the physical interface instances
	 * - modinsert the necessary modules@pos
	 * - Next, add the logical interfaces being careful about
	 *   the order, (follow the cached interface number li_ifnum order)
	 */

	pif = node->ip_pif;
	ipmp = (node->ip_pif->pi_grname[0] != '\0');

	/*
	 * Make a first pass to plumb in physical interfaces and get a count
	 * of the max logical interfaces
	 */
	for (lif = pif->pi_lifs; lif != NULL; lif = lif->li_next) {
		max_lifnum = MAX(lif->li_ifnum, max_lifnum);
		if (lif->li_ifflags & IFF_IPV4) {
			fstr = "inet";
		} else if (lif->li_ifflags & IFF_IPV6) {
			fstr = "inet6";
		} else {
			/* Unlikely case */
			rcm_log_message(RCM_DEBUG,
			    "IP: Re-plumb ignored (%s:%d)\n",
			    pif->pi_ifname, lif->li_ifnum);
			continue;
		}

		/* ignore logical interface instances */
		if (lif->li_ifnum != 0)
			continue;

		if ((lif->li_ifflags & IFF_NOFAILOVER) || !ipmp) {
			success = ifconfig("", "", lif->li_reconfig, B_FALSE);
		} else {
			(void) snprintf(buf, sizeof (buf), "plumb group %s",
			    pif->pi_grname);
			success = ifconfig(pif->pi_ifname, fstr, buf, B_FALSE);
		}

		if (!success) {
			rcm_log_message(RCM_ERROR,
			    _("IP: Cannot plumb (%s) %s\n"), pif->pi_ifname,
			    strerror(errno));
			return (-1);
		}

		/*
		 * Restart DHCP if necessary.
		 */
		if ((lif->li_ifflags & IFF_DHCPRUNNING) &&
		    !ifconfig(pif->pi_ifname, fstr, CFG_DHCP_CMD, B_FALSE)) {
			rcm_log_message(RCM_ERROR, _("IP: Cannot start DHCP "
			    "(%s) %s\n"), pif->pi_ifname, strerror(errno));
			return (-1);
		}

		rcm_log_message(RCM_TRACE2,
		    "IP: if_replumb: Modcnt = %d\n", lif->li_modcnt);
		/* modinsert modules in order, ignore driver(last) */
		for (i = 0; i < (lif->li_modcnt - 1); i++) {
			rcm_log_message(RCM_TRACE2,
			    "IP: modinsert: Pos = %d Mod = %s\n",
			    i, lif->li_modules[i]);
			if (modop(pif->pi_ifname, lif->li_modules[i], i,
			    MOD_INSERT) == -1) {
				rcm_log_message(RCM_ERROR,
				    _("IP: modinsert error(%s)\n"),
				    pif->pi_ifname);
				return (-1);
			}
		}
	}

	/* Now, add all the logical interfaces in the correct order */
	for (i = 1; i <= max_lifnum; i++) {
		(void) snprintf(lifname, LIFNAMSIZ, "%s:%d", pif->pi_ifname, i);

		/* reset lif through every iteration */
		for (lif = pif->pi_lifs; lif != NULL; lif = lif->li_next) {
			/*
			 * Process entries in order.  If the interface is
			 * using IPMP, only process test addresses.
			 */
			if (lif->li_ifnum != i ||
			    (ipmp && !(lif->li_ifflags & IFF_NOFAILOVER)))
				continue;

			if (!ifconfig("", "", lif->li_reconfig, B_FALSE)) {
				rcm_log_message(RCM_ERROR,
				    _("IP: Cannot addif (%s) %s\n"), lifname,
				    strerror(errno));
				return (-1);
			}

			/*
			 * Restart DHCP if necessary.
			 */
			if ((lif->li_ifflags & IFF_DHCPRUNNING) &&
			    !ifconfig(lifname, fstr, CFG_DHCP_CMD, B_FALSE)) {
				rcm_log_message(RCM_ERROR,
				    _("IP: Cannot start DHCP (%s) %s\n"),
				    lifname, strerror(errno));
				return (-1);
			}
		}
	}

	rcm_log_message(RCM_TRACE2, "IP: if_replumb(%s) success \n",
	    node->ip_resource);

	return (0);
}

/*
 * clr_cfg_state() - Cleanup after errors in unplumb
 */
static void
clr_cfg_state(ip_pif_t *pif)
{
	ip_lif_t *lif;
	int i;

	lif = pif->pi_lifs;

	while (lif != NULL) {
		lif->li_modcnt = 0;
		free(lif->li_reconfig);
		lif->li_reconfig = NULL;
		for (i = 0; i < IP_MAX_MODS; i++) {
			free(lif->li_modules[i]);
			lif->li_modules[i] = NULL;
		}
		lif = lif->li_next;
	}
}

/*
 * Attempt to offline ip_cache_t `node'; returns an IPMP error code.
 */
static int
ip_ipmp_offline(ip_cache_t *node)
{
	int retval;
	ipmp_handle_t handle;

	rcm_log_message(RCM_TRACE1, "IP: ip_ipmp_offline\n");

	if ((retval = ipmp_open(&handle)) != IPMP_SUCCESS) {
		rcm_log_message(RCM_ERROR,
		    _("IP: cannot create ipmp handle: %s\n"),
		    ipmp_errmsg(retval));
		return (retval);
	}

	retval = ipmp_offline(handle, node->ip_pif->pi_ifname, node->ip_ifred);
	if (retval != IPMP_SUCCESS) {
		rcm_log_message(RCM_ERROR, _("IP: ipmp_offline error: %s\n"),
		    ipmp_errmsg(retval));
	} else {
		rcm_log_message(RCM_TRACE1, "IP: ipmp_offline success\n");
	}

	ipmp_close(handle);
	return (retval);
}

/*
 * Attempt to undo the offline ip_cache_t `node'; returns an IPMP error code.
 */
static int
ip_ipmp_undo_offline(ip_cache_t *node)
{
	int retval;
	ipmp_handle_t handle;

	rcm_log_message(RCM_TRACE1, "IP: ip_ipmp_undo_offline\n");

	if ((retval = ipmp_open(&handle)) != IPMP_SUCCESS) {
		rcm_log_message(RCM_ERROR,
		    _("IP: cannot create ipmp handle: %s\n"),
		    ipmp_errmsg(retval));
		return (retval);
	}

	retval = ipmp_undo_offline(handle, node->ip_pif->pi_ifname);
	if (retval != IPMP_SUCCESS) {
		rcm_log_message(RCM_ERROR,
		    _("IP: ipmp_undo_offline error: %s\n"),
		    ipmp_errmsg(retval));
	} else {
		rcm_log_message(RCM_TRACE1, "IP: ipmp_undo_offline success\n");
	}

	ipmp_close(handle);
	return (retval);
}

/*
 * get_link_resource() - Convert a link name (e.g., net0, hme1000) into a
 * dynamically allocated string containing the associated link resource
 * name ("SUNW_datalink/<linkid>").
 */
static char *
get_link_resource(const char *link)
{
	char		errmsg[DLADM_STRSIZE];
	datalink_id_t	linkid;
	uint32_t	flags;
	char		*resource;
	dladm_status_t	status;

	status = dladm_name2info(dld_handle, link, &linkid, &flags, NULL, NULL);
	if (status != DLADM_STATUS_OK)
		goto fail;

	if (!(flags & DLADM_OPT_ACTIVE)) {
		status = DLADM_STATUS_FAILED;
		goto fail;
	}

	resource = malloc(RCM_LINK_RESOURCE_MAX);
	if (resource == NULL) {
		rcm_log_message(RCM_ERROR, _("IP: malloc error(%s): %s\n"),
		    strerror(errno), link);
		return (NULL);
	}

	(void) snprintf(resource, RCM_LINK_RESOURCE_MAX, "%s/%u",
	    RCM_LINK_PREFIX, linkid);

	return (resource);

fail:
	rcm_log_message(RCM_ERROR,
	    _("IP: get_link_resource for %s error(%s)\n"),
	    link, dladm_status2str(status, errmsg));
	return (NULL);
}

/*
 * modop() - Remove/insert a module
 */
static int
modop(char *name, char *arg, int pos, char op)
{
	char syscmd[LIFNAMSIZ+MAXPATHLEN];	/* must be big enough */

	rcm_log_message(RCM_TRACE1, "IP: modop(%s)\n", name);

	/* Nothing to do with "ip", "arp" */
	if ((arg == NULL) || (strcmp(arg, "") == 0) ||
	    STREQ(arg, IP_MOD_NAME) || STREQ(arg, ARP_MOD_NAME)) {
		rcm_log_message(RCM_TRACE1, "IP: modop success\n");
		return (0);
	}

	if (op == MOD_CHECK) {
		/*
		 * No known good modules (yet) apart from ip and arp
		 * which are handled above
		 */
		return (-1);
	}

	if (op == MOD_REMOVE) {
		(void) snprintf(syscmd, sizeof (syscmd),
		    "%s %s modremove %s@%d\n", SBIN_IFCONFIG, name, arg, pos);
	} else if (op == MOD_INSERT) {
		(void) snprintf(syscmd, sizeof (syscmd),
		    "%s %s modinsert %s@%d\n", SBIN_IFCONFIG, name, arg, pos);
	} else {
		rcm_log_message(RCM_ERROR,
		    _("IP: modop(%s): unknown operation\n"), name);
		return (-1);
	}

	rcm_log_message(RCM_TRACE1, "IP: modop(%s): %s\n", name, syscmd);
	if (rcm_exec_cmd(syscmd) == -1) {
		rcm_log_message(RCM_ERROR,
		    _("IP: modop(%s): %s\n"), name, strerror(errno));
		return (-1);
	}

	rcm_log_message(RCM_TRACE1, "IP: modop success\n");
	return (0);
}

/*
 * get_modlist() - return a list of pushed mid-stream modules
 *		 Required memory is malloced to construct the list,
 *		 Caller must free this memory list
 *		 Call with cache_lock held
 */
static int
get_modlist(char *name, ip_lif_t *lif)
{
	int mux_fd;
	int muxid_fd;
	int fd;
	int i;
	int num_mods;
	struct lifreq lifr;
	struct str_list strlist = { 0 };

	rcm_log_message(RCM_TRACE1, "IP: getmodlist(%s)\n", name);

	(void) strlcpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	lifr.lifr_flags = lif->li_ifflags;
	if (ip_domux2fd(&mux_fd, &muxid_fd, &fd, &lifr) < 0) {
		rcm_log_message(RCM_ERROR, _("IP: ip_domux2fd(%s)\n"), name);
		return (-1);
	}

	if ((num_mods = ioctl(fd, I_LIST, NULL)) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: get_modlist(%s): I_LIST(%s) \n"),
		    name, strerror(errno));
		goto fail;
	}

	strlist.sl_nmods = num_mods;
	strlist.sl_modlist = malloc(sizeof (struct str_mlist) * num_mods);
	if (strlist.sl_modlist == NULL) {
		rcm_log_message(RCM_ERROR, _("IP: get_modlist(%s): %s\n"),
		    name, strerror(errno));
		goto fail;
	}

	if (ioctl(fd, I_LIST, (caddr_t)&strlist) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: get_modlist(%s): I_LIST error: %s\n"),
		    name, strerror(errno));
		goto fail;
	}

	for (i = 0; i < strlist.sl_nmods; i++) {
		lif->li_modules[i] = strdup(strlist.sl_modlist[i].l_name);
		if (lif->li_modules[i] == NULL) {
			rcm_log_message(RCM_ERROR,
			    _("IP: get_modlist(%s): %s\n"),
			    name, strerror(errno));
			while (i > 0)
				free(lif->li_modules[--i]);
			goto fail;
		}
	}

	lif->li_modcnt = strlist.sl_nmods;
	free(strlist.sl_modlist);

	rcm_log_message(RCM_TRACE1, "IP: getmodlist(%s) success\n", name);
	return (ip_plink(mux_fd, muxid_fd, fd, &lifr));
fail:
	free(strlist.sl_modlist);
	(void) ip_plink(mux_fd, muxid_fd, fd, &lifr);
	return (-1);
}

/*
 * ip_domux2fd() - Helper function for mod*() functions
 *		 Stolen from ifconfig.c
 */
static int
ip_domux2fd(int *mux_fd, int *muxid_fdp, int *fd, struct lifreq *lifr)
{
	int muxid_fd;
	char	*udp_dev_name;

	if (lifr->lifr_flags & IFF_IPV6) {
		udp_dev_name  = UDP6_DEV_NAME;
	} else {
		udp_dev_name  = UDP_DEV_NAME;
	}

	if ((muxid_fd = open(udp_dev_name, O_RDWR)) < 0) {
		rcm_log_message(RCM_ERROR, _("IP: ip_domux2fd: open(%s) %s\n"),
		    udp_dev_name, strerror(errno));
		return (-1);
	}
	if ((*mux_fd = open(udp_dev_name, O_RDWR)) < 0) {
		rcm_log_message(RCM_ERROR, _("IP: ip_domux2fd: open(%s) %s\n"),
		    udp_dev_name, strerror(errno));
		(void) close(muxid_fd);
		return (-1);
	}
	if (ioctl(muxid_fd, SIOCGLIFMUXID, (caddr_t)lifr) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: ip_domux2fd: SIOCGLIFMUXID(%s): %s\n"),
		    udp_dev_name, strerror(errno));
		(void) close(*mux_fd);
		(void) close(muxid_fd);
		return (-1);
	}

	rcm_log_message(RCM_TRACE2,
	    "IP: ip_domux2fd: ARP_muxid %d IP_muxid %d\n",
	    lifr->lifr_arp_muxid, lifr->lifr_ip_muxid);

	if ((*fd = ioctl(*mux_fd, _I_MUXID2FD, lifr->lifr_ip_muxid)) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: ip_domux2fd: _I_MUXID2FD(%s): %s\n"),
		    udp_dev_name, strerror(errno));
		(void) close(*mux_fd);
		(void) close(muxid_fd);
		return (-1);
	}
	if (ioctl(*mux_fd, I_PUNLINK, lifr->lifr_ip_muxid) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: ip_domux2fd: I_PUNLINK(%s): %s\n"),
		    udp_dev_name, strerror(errno));
		(void) close(*mux_fd);
		(void) close(muxid_fd);
		return (-1);
	}

	/* Note: mux_fd and muxid_fd are closed in ip_plink below */
	*muxid_fdp = muxid_fd;
	return (0);
}

/*
 * ip_plink() - Helper function for mod*() functions.
 *	      Stolen from ifconfig.c
 */
static int
ip_plink(int mux_fd, int muxid_fd, int fd, struct lifreq *lifr)
{
	int mux_id;

	if ((mux_id = ioctl(mux_fd, I_PLINK, fd)) < 0) {
		rcm_log_message(RCM_ERROR, _("IP: ip_plink I_PLINK(%s): %s\n"),
		    UDP_DEV_NAME, strerror(errno));
		(void) close(mux_fd);
		(void) close(muxid_fd);
		(void) close(fd);
		return (-1);
	}

	lifr->lifr_ip_muxid = mux_id;
	if (ioctl(muxid_fd, SIOCSLIFMUXID, (caddr_t)lifr) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: ip_plink SIOCSLIFMUXID(%s): %s\n"),
		    UDP_DEV_NAME, strerror(errno));
		(void) close(mux_fd);
		(void) close(muxid_fd);
		(void) close(fd);
		return (-1);
	}

	(void) close(mux_fd);
	(void) close(muxid_fd);
	(void) close(fd);
	return (0);
}

/*
 * ip_onlinelist()
 *
 *	Notify online to IP address consumers.
 */
/*ARGSUSED*/
static int
ip_onlinelist(rcm_handle_t *hd, ip_cache_t *node, char **errorp, uint_t flags,
    rcm_info_t **depend_info)
{
	char **addrlist;
	int ret = RCM_SUCCESS;

	rcm_log_message(RCM_TRACE2, "IP: ip_onlinelist\n");

	addrlist = ip_get_addrlist(node);
	if (addrlist == NULL || addrlist[0] == NULL) {
		rcm_log_message(RCM_TRACE2, "IP: ip_onlinelist none\n");
		ip_free_addrlist(addrlist);
		return (ret);
	}

	ret = rcm_notify_online_list(hd, addrlist, 0, depend_info);

	ip_free_addrlist(addrlist);
	rcm_log_message(RCM_TRACE2, "IP: ip_onlinelist done\n");
	return (ret);
}

/*
 * ip_offlinelist()
 *
 *	Offline IP address consumers.
 */
/*ARGSUSED*/
static int
ip_offlinelist(rcm_handle_t *hd, ip_cache_t *node, char **errorp, uint_t flags,
    rcm_info_t **depend_info)
{
	char **addrlist;
	int ret = RCM_SUCCESS;

	rcm_log_message(RCM_TRACE2, "IP: ip_offlinelist\n");

	addrlist = ip_get_addrlist(node);
	if (addrlist == NULL || addrlist[0] == NULL) {
		rcm_log_message(RCM_TRACE2, "IP: ip_offlinelist none\n");
		ip_free_addrlist(addrlist);
		return (RCM_SUCCESS);
	}

	if ((ret = rcm_request_offline_list(hd, addrlist, flags, depend_info))
	    != RCM_SUCCESS) {
		if (ret == RCM_FAILURE)
			(void) rcm_notify_online_list(hd, addrlist, 0, NULL);

		ret = RCM_FAILURE;
	}

	ip_free_addrlist(addrlist);
	rcm_log_message(RCM_TRACE2, "IP: ip_offlinelist done\n");
	return (ret);
}

/*
 * ip_get_addrlist() -	Get the list of IP addresses on this interface (node);
 *			This routine malloc()s required memory for the list.
 *			Returns the list on success, NULL on failure.
 *			Call with cache_lock held.
 */
static char **
ip_get_addrlist(ip_cache_t *node)
{
	ip_lif_t *lif;
	char **addrlist = NULL;
	int i, numifs;
	size_t addrlistsize;
	char addrstr[INET6_ADDRSTRLEN];

	rcm_log_message(RCM_TRACE2, "IP: ip_get_addrlist(%s)\n",
	    node->ip_resource);

	numifs = 0;
	for (lif = node->ip_pif->pi_lifs; lif != NULL; lif = lif->li_next) {
		numifs++;
	}

	/*
	 * Allocate space for resource names list; add 1 and use calloc()
	 * so that the list is NULL-terminated.
	 */
	if ((addrlist = calloc(numifs + 1, sizeof (char *))) == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("IP: ip_get_addrlist(%s) malloc failure(%s)\n"),
		    node->ip_resource, strerror(errno));
		return (NULL);
	}

	for (lif = node->ip_pif->pi_lifs, i = 0; lif != NULL;
	    lif = lif->li_next, i++) {

		if (!ip_addrstr(lif, addrstr, sizeof (addrstr))) {
			ip_free_addrlist(addrlist);
			return (NULL);
		}

		addrlistsize = strlen(addrstr) + sizeof (RCM_STR_SUNW_IP);
		if ((addrlist[i] = malloc(addrlistsize)) == NULL) {
			rcm_log_message(RCM_ERROR,
			    _("IP: ip_get_addrlist(%s) malloc failure(%s)\n"),
			    node->ip_resource, strerror(errno));
			ip_free_addrlist(addrlist);
			return (NULL);
		}
		(void) snprintf(addrlist[i], addrlistsize, "%s%s",
		    RCM_STR_SUNW_IP, addrstr);

		rcm_log_message(RCM_DEBUG, "Anon Address: %s\n", addrlist[i]);
	}

	rcm_log_message(RCM_TRACE2, "IP: get_addrlist (%s) done\n",
	    node->ip_resource);

	return (addrlist);
}

static void
ip_free_addrlist(char **addrlist)
{
	int i;

	if (addrlist == NULL)
		return;

	for (i = 0; addrlist[i] != NULL; i++)
		free(addrlist[i]);
	free(addrlist);
}

/*
 * ip_consumer_notify() - Notify consumers of IP addresses coming back online.
 */

static void
ip_consumer_notify(rcm_handle_t *hd, datalink_id_t linkid, char **errorp,
    uint_t flags, rcm_info_t **depend_info)
{
	char cached_name[RCM_LINK_RESOURCE_MAX];
	ip_cache_t *node;

	assert(linkid != DATALINK_INVALID_LINKID);

	rcm_log_message(RCM_TRACE1, _("IP: ip_consumer_notify(%u)\n"), linkid);

	/* Check for the interface in the cache */
	(void) snprintf(cached_name, sizeof (cached_name), "%s/%u",
	    RCM_LINK_PREFIX, linkid);

	(void) mutex_lock(&cache_lock);
	if ((node = cache_lookup(hd, cached_name, CACHE_REFRESH)) == NULL) {
		rcm_log_message(RCM_TRACE1, _("IP: Skipping interface(%u)\n"),
		    linkid);
		(void) mutex_unlock(&cache_lock);
		return;
	}
	/*
	 * Inform anonymous consumers about IP addresses being onlined.
	 */
	(void) ip_onlinelist(hd, node, errorp, flags, depend_info);

	(void) mutex_unlock(&cache_lock);

	rcm_log_message(RCM_TRACE2, "IP: ip_consumer_notify success\n");
}

/*
 * Gets the interface name for the given linkid. Returns -1 if there is
 * any error. It fills in the interface name in `ifinst' if the interface
 * is not already configured. Otherwise, it puts a null string in `ifinst'.
 */
static int
if_configure_get_linkid(datalink_id_t linkid, char *ifinst, size_t len)
{
	char cached_name[RCM_LINK_RESOURCE_MAX];
	ip_cache_t *node;

	/* Check for the interface in the cache */
	(void) snprintf(cached_name, sizeof (cached_name), "%s/%u",
	    RCM_LINK_PREFIX, linkid);

	/* Check if the interface is new or was not previously offlined */
	(void) mutex_lock(&cache_lock);
	if (((node = cache_lookup(NULL, cached_name, CACHE_REFRESH)) != NULL) &&
	    (!(node->ip_cachestate & CACHE_IF_OFFLINED))) {
		rcm_log_message(RCM_TRACE1,
		    _("IP: Skipping configured interface(%u)\n"), linkid);
		(void) mutex_unlock(&cache_lock);
		*ifinst = '\0';
		return (0);
	}
	(void) mutex_unlock(&cache_lock);

	if (dladm_datalink_id2info(dld_handle, linkid, NULL, NULL, NULL, ifinst,
	    len) != DLADM_STATUS_OK) {
		rcm_log_message(RCM_ERROR,
		    _("IP: get %u link name failed\n"), linkid);
		return (-1);
	}
	return (0);
}

/*
 * if_configure_hostname() - Configure a physical interface after attach
 * based on the information in /etc/hostname.*
 */
static int
if_configure_hostname(datalink_id_t linkid)
{
	FILE *hostfp, *host6fp;
	boolean_t ipmp = B_FALSE;
	char ifinst[MAXLINKNAMELEN];
	char cfgfile[MAXPATHLEN];

	assert(linkid != DATALINK_INVALID_LINKID);
	rcm_log_message(RCM_TRACE1, _("IP: if_configure_hostname(%u)\n"),
	    linkid);

	if (if_configure_get_linkid(linkid, ifinst, sizeof (ifinst)) != 0)
		return (-1);

	/* Check if the interface is already configured. */
	if (ifinst[0] == '\0')
		return (0);

	/*
	 * Scan the IPv4 and IPv6 hostname files to see if (a) they exist
	 * and (b) if either one places the interface into an IPMP group.
	 */
	(void) snprintf(cfgfile, MAXPATHLEN, CFGFILE_FMT_IPV4, ifinst);
	rcm_log_message(RCM_TRACE1, "IP: Scanning %s\n", cfgfile);
	if ((hostfp = fopen(cfgfile, "r")) != NULL) {
		if (isgrouped(cfgfile))
			ipmp = B_TRUE;
	}

	(void) snprintf(cfgfile, MAXPATHLEN, CFGFILE_FMT_IPV6, ifinst);
	rcm_log_message(RCM_TRACE1, "IP: Scanning %s\n", cfgfile);
	if ((host6fp = fopen(cfgfile, "r")) != NULL) {
		if (!ipmp && isgrouped(cfgfile))
			ipmp = B_TRUE;
	}

	/*
	 * Configure the interface according to its hostname files.
	 */
	if (hostfp != NULL &&
	    if_config_inst(ifinst, hostfp, AF_INET, ipmp) == -1) {
		rcm_log_message(RCM_ERROR,
		    _("IP: IPv4 Post-attach failed (%s)\n"), ifinst);
		goto fail;
	}

	if (host6fp != NULL &&
	    if_config_inst(ifinst, host6fp, AF_INET6, ipmp) == -1) {
		rcm_log_message(RCM_ERROR,
		    _("IP: IPv6 Post-attach failed (%s)\n"), ifinst);
		goto fail;
	}

	(void) fclose(hostfp);
	(void) fclose(host6fp);
	rcm_log_message(RCM_TRACE1, "IP: if_configure_hostname(%s) success\n",
	    ifinst);
	return (0);
fail:
	(void) fclose(hostfp);
	(void) fclose(host6fp);
	return (-1);
}

/*
 * if_configure_ipadm() - Configure a physical interface after attach
 * Queries libipadm for persistent configuration information and then
 * resurrects that persistent configuration.
 */
static int
if_configure_ipadm(datalink_id_t linkid)
{
	char ifinst[MAXLINKNAMELEN];
	boolean_t found;
	ipadm_if_info_t *ifinfo, *ptr;
	ipadm_status_t status;

	assert(linkid != DATALINK_INVALID_LINKID);
	rcm_log_message(RCM_TRACE1, _("IP: if_configure_ipadm(%u)\n"),
	    linkid);

	if (if_configure_get_linkid(linkid, ifinst, sizeof (ifinst)) != 0)
		return (-1);

	/* Check if the interface is already configured. */
	if (ifinst[0] == '\0')
		return (0);

	status = ipadm_if_info(ip_handle, ifinst, &ifinfo, 0, LIFC_UNDER_IPMP);
	if (status == IPADM_ENXIO)
		goto done;
	if (status != IPADM_SUCCESS) {
		rcm_log_message(RCM_ERROR,
		    _("IP: IPv4 Post-attach failed (%s) Error %s\n"),
		    ifinst, ipadm_status2str(status));
		goto fail;
	}
	if (ifinfo != NULL) {
		found = B_FALSE;
		for (ptr = ifinfo; ptr != NULL; ptr = ptr->ifi_next) {
			if (strncmp(ptr->ifi_name, ifinst,
			    sizeof (ifinst)) == 0) {
				found = B_TRUE;
				break;
			}
		}
		ipadm_free_if_info(ifinfo);
		if (!found) {
			return (0);
		}
		if (if_hostname_exists(ifinst, AF_INET) ||
		    if_hostname_exists(ifinst, AF_INET6)) {
			rcm_log_message(RCM_WARNING,
			    _("IP: IPv4 Post-attach (%s) found both "
			    "/etc/hostname and ipadm persistent configuration. "
			    "Ignoring ipadm config\n"), ifinst);
			return (0);
		}
		status = ipadm_enable_if(ip_handle, ifinst, IPADM_OPT_ACTIVE);
		if (status != IPADM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("IP: Post-attach failed (%s) Error %s\n"),
			    ifinst, ipadm_status2str(status));
			goto fail;
		}
	}
done:
	rcm_log_message(RCM_TRACE1, "IP: if_configure_ipadm(%s) success\n",
	    ifinst);
	return (0);
fail:
	return (-1);
}

/*
 * isgrouped() - Scans the given config file to see if this interface is
 *	         using IPMP.  Returns B_TRUE or B_FALSE.
 */
static boolean_t
isgrouped(const char *cfgfile)
{
	FILE *fp;
	struct stat statb;
	char *nlp, *line, *token, *lasts, *buf;
	boolean_t grouped = B_FALSE;

	rcm_log_message(RCM_TRACE1, "IP: isgrouped(%s)\n", cfgfile);

	if (stat(cfgfile, &statb) != 0) {
		rcm_log_message(RCM_TRACE1,
		    _("IP: No config file(%s)\n"), cfgfile);
		return (B_FALSE);
	}

	/*
	 * We also ignore single-byte config files because the file should
	 * always be newline-terminated, so we know there's nothing of
	 * interest.  Further, a single-byte file would cause the fgets() loop
	 * below to spin forever.
	 */
	if (statb.st_size <= 1) {
		rcm_log_message(RCM_TRACE1,
		    _("IP: Empty config file(%s)\n"), cfgfile);
		return (B_FALSE);
	}

	if ((fp = fopen(cfgfile, "r")) == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("IP: Cannot open configuration file(%s): %s\n"), cfgfile,
		    strerror(errno));
		return (B_FALSE);
	}

	if ((buf = malloc(statb.st_size)) == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("IP: malloc failure(%s): %s\n"), cfgfile,
		    strerror(errno));
		goto out;
	}

	while (fgets(buf, statb.st_size, fp) != NULL) {
		if ((nlp = strrchr(buf, '\n')) != NULL)
			*nlp = '\0';

		line = buf;
		while ((token = strtok_r(line, " \t", &lasts)) != NULL) {
			line = NULL;
			if (STREQ("group", token) &&
			    strtok_r(NULL, " \t", &lasts) != NULL) {
				grouped = B_TRUE;
				goto out;
			}
		}
	}
out:
	free(buf);
	(void) fclose(fp);

	rcm_log_message(RCM_TRACE1, "IP: isgrouped(%s): %d\n", cfgfile,
	    grouped);

	return (grouped);
}

/*
 * if_config_inst() - Configure an interface instance as specified by the
 *		    address family af and if it is grouped (ipmp).
 */
static int
if_config_inst(const char *ifinst, FILE *hfp, int af, boolean_t ipmp)
{
	FILE *ifparsefp;
	struct stat statb;
	char *buf = NULL;
	char *ifparsebuf = NULL;
	uint_t ifparsebufsize;
	const char *fstr;		/* address family string */
	boolean_t stdif = B_FALSE;

	rcm_log_message(RCM_TRACE1, "IP: if_config_inst(%s) ipmp = %d\n",
	    ifinst, ipmp);

	if (fstat(fileno(hfp), &statb) != 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: Cannot fstat file(%s)\n"), ifinst);
		goto fail;
	}

	switch (af) {
	case AF_INET:
		fstr = "inet";
		break;
	case AF_INET6:
		fstr = "inet6";
		break;
	default:
		assert(0);
	}

	/*
	 * The hostname file exists; plumb the physical interface.
	 */
	if (!ifconfig(ifinst, fstr, "plumb", B_FALSE))
		goto fail;

	/* Skip static configuration if the hostname file is empty */
	if (statb.st_size <= 1) {
		rcm_log_message(RCM_TRACE1,
		    _("IP: Zero size hostname file(%s)\n"), ifinst);
		goto configured;
	}

	if (fseek(hfp, 0, SEEK_SET) == -1) {
		rcm_log_message(RCM_ERROR,
		    _("IP: Cannot rewind hostname file(%s): %s\n"), ifinst,
		    strerror(errno));
		goto fail;
	}

	/*
	 * Allocate the worst-case single-line buffer sizes.  A bit skanky,
	 * but since hostname files are small, this should suffice.
	 */
	if ((buf = calloc(1, statb.st_size)) == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("IP: calloc(%s): %s\n"), ifinst, strerror(errno));
		goto fail;
	}

	ifparsebufsize = statb.st_size + sizeof (SBIN_IFPARSE " -s inet6 ");
	if ((ifparsebuf = calloc(1, ifparsebufsize)) == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("IP: calloc(%s): %s\n"), ifinst, strerror(errno));
		goto fail;
	}

	/*
	 * For IPv4, determine whether the hostname file consists of a single
	 * line.  We need to handle these specially since they should
	 * automatically be suffixed with "netmask + broadcast + up".
	 */
	if (af == AF_INET &&
	    fgets(buf, statb.st_size, hfp) != NULL &&
	    fgets(buf, statb.st_size, hfp) == NULL) {
		rcm_log_message(RCM_TRACE1, "IP: one-line hostname file\n");
		stdif = B_TRUE;
	}

	if (fseek(hfp, 0L, SEEK_SET) == -1) {
		rcm_log_message(RCM_ERROR,
		    _("IP: Cannot rewind hostname file(%s): %s\n"), ifinst,
		    strerror(errno));
		goto fail;
	}

	/*
	 * Loop through the file one line at a time and feed it to ifconfig.
	 * If the interface is using IPMP, then we use /sbin/ifparse -s to
	 * weed out all of the data addresses, since those are already on the
	 * IPMP meta-interface.
	 */
	while (fgets(buf, statb.st_size, hfp) != NULL) {
		if (ntok(buf) == 0)
			continue;

		if (!ipmp) {
			(void) ifconfig(ifinst, fstr, buf, stdif);
			continue;
		}

		(void) snprintf(ifparsebuf, ifparsebufsize, SBIN_IFPARSE
		    " -s %s %s", fstr, buf);
		if ((ifparsefp = popen(ifparsebuf, "r")) == NULL) {
			rcm_log_message(RCM_ERROR,
			    _("IP: cannot configure %s: popen \"%s\" "
			    "failed: %s\n"), ifinst, buf, strerror(errno));
			goto fail;
		}

		while (fgets(buf, statb.st_size, ifparsefp) != NULL) {
			if (ntok(buf) > 0)
				(void) ifconfig(ifinst, fstr, buf, stdif);
		}

		if (pclose(ifparsefp) == -1) {
			rcm_log_message(RCM_ERROR,
			    _("IP: cannot configure %s: pclose \"%s\" "
			    "failed: %s\n"), ifinst, buf, strerror(errno));
			goto fail;
		}
	}

configured:
	/*
	 * Bring up the interface (it may already be up)
	 *
	 * Technically, since the boot scripts only unconditionally bring up
	 * IPv6 interfaces, we should only unconditionally bring up IPv6 here.
	 * However, if we don't bring up IPv4, and a legacy IPMP configuration
	 * without test addresses is being used, we will never bring the
	 * interface up even though we would've at boot.  One fix is to check
	 * if the IPv4 hostname file contains data addresses that we would've
	 * brought up, but there's no simple way to do that.  Given that it's
	 * rare to have persistent IP configuration for an interface that
	 * leaves it down, we cheap out and always bring it up for IPMP.
	 */
	if ((af == AF_INET6 || ipmp) && !ifconfig(ifinst, fstr, "up", B_FALSE))
		goto fail;

	/*
	 * For IPv4, if a DHCP configuration file exists, have DHCP configure
	 * the interface.  As with the boot scripts, this is done after the
	 * hostname files are processed so that configuration in those files
	 * (such as IPMP group names) will be applied first.
	 */
	if (af == AF_INET) {
		char dhcpfile[MAXPATHLEN];
		char *dhcpbuf;
		off_t i, dhcpsize;

		(void) snprintf(dhcpfile, MAXPATHLEN, DHCPFILE_FMT, ifinst);
		if (stat(dhcpfile, &statb) == -1)
			goto out;

		if ((dhcpbuf = copylist(dhcpfile, &dhcpsize)) == NULL) {
			rcm_log_message(RCM_ERROR, _("IP: cannot read "
			    "(%s): %s\n"), dhcpfile, strerror(errno));
			goto fail;
		}

		/*
		 * The copylist() API converts \n's to \0's, but we want them
		 * to be spaces.
		 */
		if (dhcpsize > 0) {
			for (i = 0; i < dhcpsize; i++)
				if (dhcpbuf[i] == '\0')
					dhcpbuf[i] = ' ';
			dhcpbuf[dhcpsize - 1] = '\0';
		}
		(void) ifconfig(ifinst, CFG_DHCP_CMD, dhcpbuf, B_FALSE);
		free(dhcpbuf);
	}
out:
	free(ifparsebuf);
	free(buf);
	rcm_log_message(RCM_TRACE1, "IP: if_config_inst(%s) success\n", ifinst);
	return (0);
fail:
	free(ifparsebuf);
	free(buf);
	rcm_log_message(RCM_ERROR, "IP: if_config_inst(%s) failure\n", ifinst);
	return (-1);
}

/*
 * ntok() - count the number of tokens in the provided buffer.
 */
static uint_t
ntok(const char *cp)
{
	uint_t ntok = 0;

	for (;;) {
		while (ISSPACE(*cp))
			cp++;

		if (ISEOL(*cp))
			break;

		do {
			cp++;
		} while (!ISSPACE(*cp) && !ISEOL(*cp));

		ntok++;
	}
	return (ntok);
}

static boolean_t
ifconfig(const char *ifinst, const char *fstr, const char *buf, boolean_t stdif)
{
	char syscmd[MAX_RECONFIG_SIZE + MAXPATHLEN + 1];
	int status;

	(void) snprintf(syscmd, sizeof (syscmd), SBIN_IFCONFIG " %s %s %s",
	    ifinst, fstr, buf);

	if (stdif)
		(void) strlcat(syscmd, CFG_CMDS_STD, sizeof (syscmd));

	rcm_log_message(RCM_TRACE1, "IP: Exec: %s\n", syscmd);
	if ((status = rcm_exec_cmd(syscmd)) != 0) {
		if (WIFEXITED(status)) {
			rcm_log_message(RCM_ERROR, _("IP: \"%s\" failed with "
			    "exit status %d\n"), syscmd, WEXITSTATUS(status));
		} else {
			rcm_log_message(RCM_ERROR, _("IP: Error: %s: %s\n"),
			    syscmd, strerror(errno));
		}
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Return TRUE if a writeable /etc/hostname[6].ifname file exists.
 */
static boolean_t
if_hostname_exists(char *ifname, sa_family_t af)
{
	char cfgfile[MAXPATHLEN];

	if (af == AF_INET) {
		(void) snprintf(cfgfile, MAXPATHLEN, CFGFILE_FMT_IPV4, ifname);
		if (access(cfgfile, W_OK|F_OK) == 0)
			return (B_TRUE);
	} else if (af == AF_INET6) {
		(void) snprintf(cfgfile, MAXPATHLEN, CFGFILE_FMT_IPV6, ifname);
		if (access(cfgfile, W_OK|F_OK) == 0)
			return (B_TRUE);
	}
	return (B_FALSE);
}
