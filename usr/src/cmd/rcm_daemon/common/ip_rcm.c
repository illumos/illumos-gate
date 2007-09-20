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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stropts.h>
#include <strings.h>
#include <libdevinfo.h>
#include <sys/systeminfo.h>
#include <netdb.h>
#include <inet/ip.h>
#include <libinetutil.h>

#include <ipmp_mpathd.h>
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

#define	RCM_NET_PREFIX		"SUNW_network"	/* RCM network name prefix */
#define	RCM_NET_RESOURCE_MAX	(13 + LIFNAMSIZ) /* RCM_NET_PREFIX+LIFNAMSIZ */

#define	RCM_STR_SUNW_IP		"SUNW_ip/"	/* IP address export prefix */
#define	RCM_SIZE_SUNW_IP	9		/* strlen("SUNW_ip/") + 1 */

/* ifconfig(1M) */
#define	USR_SBIN_IFCONFIG	"/usr/sbin/ifconfig" /* ifconfig command */
#define	CFGFILE_FMT_IPV4	"/etc/hostname."  /* IPV4 config file */
#define	CFGFILE_FMT_IPV6	"/etc/hostname6." /* IPV6 config file */
#define	CFG_CMDS_STD	" netmask + broadcast + up" /* Normal config string */
#define	CONFIG_AF_INET		0x1		/* Post-configure IPv4 */
#define	CONFIG_AF_INET6		0x2		/* Post-configure IPv6 */
#define	MAXLINE			1024		/* Max. line length */
#define	MAXARGS			512		/* Max. args in ifconfig cmd */

/* Physical interface flags mask */
#define	RCM_PIF_FLAGS		(IFF_OFFLINE | IFF_INACTIVE | IFF_FAILED | \
				    IFF_STANDBY)

/* Some useful macros */
#ifndef MAX
#define	MAX(a, b)	(((a) > (b))?(a):(b))
#endif /* MAX */

#ifndef ISSPACE
#define	ISSPACE(c)	((c) == ' ' || (c) == '\t')
#endif

#ifndef	ISEOL
#define	ISEOL(c)	((c) == '\n' || (c) == '\r' || (c) == '\0')
#endif

#ifndef	STREQ
#define	STREQ(a, b)	(*(a) == *(b) && strcmp((a), (b)) == 0)
#endif

#ifndef ADDSPACE
#define	ADDSPACE(a)	((void) strcat((a), " "))
#endif

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

/* in.mpathd(1M) specifics */
#define	MPATHD_MAX_RETRIES	5	/* Max. offline retries */

/* Stream module operations */
#define	MOD_INSERT		0	/* Insert a mid-stream module */
#define	MOD_REMOVE		1	/* Remove a mid-stream module */
#define	MOD_CHECK		2	/* Check mid-stream module safety */

/* VLAN format support */
#define	VLAN_MAX_PPA_ALLOWED	1000
#define	VLAN_GET_PPA(ppa)	(ppa % VLAN_MAX_PPA_ALLOWED)

/* devfsadm attach nvpair values */
#define	PROP_NV_DDI_NETWORK	"ddi_network"

/*
 * in.mpathd(1M) message passing formats
 */
typedef struct mpathd_cmd {
	uint32_t	cmd_command;		/* message command */
	char		cmd_ifname[LIFNAMSIZ];	/* this interface name */
	char		cmd_movetoif[LIFNAMSIZ]; /* move to interface */
	uint32_t	cmd_min_red;		/* min. redundancy */
/* Message passing values for MI_SETOINDEX */
#define	from_lifname	cmd_ifname		/* current logical interface */
#define	to_pifname	cmd_movetoif		/* new physical interface */
#define	addr_family	cmd_min_red		/* address family */
} mpathd_cmd_t;

/* This is needed since mpathd checks message size for offline */
typedef struct mpathd_unoffline {
	uint32_t	cmd_command;		/* offline / undo offline */
	char		cmd_ifname[LIFNAMSIZ];	/* this interface name */
} mpathd_unoffline_t;

typedef struct mpathd_response {
	uint32_t	resp_sys_errno;		/* system errno */
	uint32_t	resp_mpathd_err;	/* mpathd error information */
} mpathd_response_t;

/*
 * IP module data types
 */

/* Physical interface representation */
typedef struct ip_pif {
	char			pi_ifname[LIFNAMSIZ+1];	/* interface name */
	char			pi_grpname[LIFNAMSIZ+1]; /* IPMP group name */
	struct ip_lif		*pi_lifs;	/* ptr to logical interfaces */
} ip_pif_t;

/* Logical interface representation */
typedef struct ip_lif
{
	struct ip_lif		*li_next;	/* ptr to next lif */
	struct ip_lif		*li_prev;  	/* previous next ptr */
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

/*
 * Global NIC list to be configured after DR-attach
 */
#define	NIL_NULL	((struct ni_list *)0)

struct net_interface {
	char *type;	/* Name of type of interface  (le, ie, etc.)    */
	char *name;	/* Qualified name of interface (le0, ie0, etc.) */
};

struct ni_list {
	struct net_interface *nifp;
	struct ni_list *next;
};

static mutex_t nil_lock;	/* NIC list lock */
static int num_ni = 0;		/* Global new interface count */
static struct ni_list *nil_head = NIL_NULL;	/* Global new if list */

struct devfs_minor_data {
	int32_t minor_type;
	char *minor_name;
	char *minor_node_type;
};

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
static void 	free_cache();
static int 	update_cache(rcm_handle_t *);
static void 	cache_remove(ip_cache_t *);
static ip_cache_t *cache_lookup(rcm_handle_t *, char *, char);
static void 	free_node(ip_cache_t *);
static void 	cache_insert(ip_cache_t *);
static char 	*ip_usage(ip_cache_t *);
static int 	update_pif(rcm_handle_t *, int, int, struct lifreq *);
static int 	ip_ipmp_offline(ip_cache_t *, ip_cache_t *);
static int	ip_ipmp_undo_offline(ip_cache_t *);
static int	if_cfginfo(ip_cache_t *, uint_t);
static int	if_unplumb(ip_cache_t *);
static int	if_replumb(ip_cache_t *);
static void 	ip_log_err(ip_cache_t *, char **, char *);
static char	*get_physical_resource(const char *);
static void	clr_cfg_state(ip_pif_t *);
static uint64_t	if_get_flags(ip_pif_t *);
static int	mpathd_send_cmd(mpathd_cmd_t *);
static int	connect_to_mpathd(int);
static int	modop(char *, char *, int, char);
static int	get_modlist(char *, ip_lif_t *);
static int	ip_domux2fd(int *, int *, struct lifreq *);
static int	ip_plink(int, int, struct lifreq *);
static int	ip_onlinelist(rcm_handle_t *, ip_cache_t *, char **, uint_t,
			rcm_info_t **);
static int	ip_offlinelist(rcm_handle_t *, ip_cache_t *, char **, uint_t,
			rcm_info_t **);
static char 	**ip_get_addrlist(ip_cache_t *);
static void	ip_free_addrlist(char **);
static void	ip_consumer_notify(rcm_handle_t *, char *, char **, uint_t,
			rcm_info_t **);

static int process_nvlist(nvlist_t *);
static void process_minor(char *, char *, int32_t, struct devfs_minor_data *);
static int if_configure(char *);
static int isgrouped(char *);
static int if_ipmp_config(char *, int, int);
static int if_mpathd_configure(char *, char *, int, int);
static char *get_mpathd_dest(char *, int);
static int if_getcount(int);
static void tokenize(char *, char **, char *, int *);


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
	rcm_log_message(RCM_TRACE1, "IP: mod_init\n");

	cache_head.ip_next = &cache_tail;
	cache_head.ip_prev = NULL;
	cache_tail.ip_prev = &cache_head;
	cache_tail.ip_next = NULL;
	(void) mutex_init(&cache_lock, NULL, NULL);
	(void) mutex_init(&nil_lock, NULL, NULL);

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

	return ("IP Multipathing module version %I%");
}

/*
 * rcm_mod_fini() - Destroy the network interfaces cache.
 */
int
rcm_mod_fini(void)
{
	rcm_log_message(RCM_TRACE1, "IP: mod_fini\n");

	free_cache();
	(void) mutex_destroy(&nil_lock);
	(void) mutex_destroy(&cache_lock);
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
		if (rcm_register_event(hd, RCM_RESOURCE_NETWORK_NEW, 0, NULL)
		    != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("IP: failed to register %s\n"),
			    RCM_RESOURCE_NETWORK_NEW);
			return (RCM_FAILURE);
		} else {
			rcm_log_message(RCM_DEBUG, "IP: registered %s\n",
			    RCM_RESOURCE_NETWORK_NEW);
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
		if (rcm_unregister_event(hd, RCM_RESOURCE_NETWORK_NEW, 0)
		    != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    _("IP: failed to unregister %s\n"),
			    RCM_RESOURCE_NETWORK_NEW);
			return (RCM_FAILURE);
		} else {
			rcm_log_message(RCM_DEBUG, "IP: unregistered %s\n",
			    RCM_RESOURCE_NETWORK_NEW);
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
	int detachable = 0;
	int nofailover = 0;
	int ipmp = 0;

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
	if (flags & RCM_FORCE) {
		detachable++;
	}

	/* Check if the interface is an IPMP grouped interface */
	if (strcmp(pif->pi_grpname, "")) {
		ipmp++;
	}

	if (if_get_flags(pif) & IFF_NOFAILOVER) {
		nofailover++;
	}

	/*
	 * Even if the interface is not in an IPMP group, it's possible that
	 * it's still okay to offline it as long as there are higher-level
	 * failover mechanisms for the addresses it owns (e.g., clustering).
	 * In this case, ip_offlinelist() will return RCM_SUCCESS, and we
	 * charge on.
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

	/*
	 * Cannot remove an IPMP interface if IFF_NOFAILOVER is set.
	 */
	if (ipmp && nofailover) {
		/* Interface is part of an IPMP group, and cannot failover */
		ip_log_err(node, errorp, "Failover disabled");
		errno = EBUSY;
		(void) mutex_unlock(&cache_lock);
		return (RCM_FAILURE);
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
	 * This an IPMP interface that can be failed over.
	 * Request in.mpathd(1M) to failover the physical interface.
	 */

	/* Failover to "any", let mpathd determine best failover candidate */
	if (ip_ipmp_offline(node, NULL) < 0) {
		ip_log_err(node, errorp, "in.mpathd failover failed");
		/*
		 * Odds are that in.mpathd(1M) could not offline the device
		 * because it was the last interface in the group.  However,
		 * it's possible that it's still okay to offline it as long as
		 * there are higher-level failover mechanisms for the
		 * addresses it owns (e.g., clustering).  In this case,
		 * ip_offlinelist() will return RCM_SUCCESS, and we charge on.
		 *
		 * TODO: change ip_ipmp_offline() to return the actual failure
		 * from in.mpathd so that we can verify that it did indeed
		 * fail with IPMP_EMINRED.
		 */
		if (!detachable) {
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
	}

	if (if_unplumb(node) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: Unplumb failed (%s)\n"),
		    pif->pi_ifname);

		/* Request mpathd to undo the offline */
		if (ip_ipmp_undo_offline(node) < 0) {
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
	struct ni_list	*nilp, *onilp;
	struct net_interface *nip;
	int		n;

	assert(hd != NULL);
	assert(rsrc != NULL);
	assert(id == (id_t)0);
	assert(nvl != NULL);

	rcm_log_message(RCM_TRACE1, "IP: notify_event(%s)\n", rsrc);

	if (!STREQ(rsrc, RCM_RESOURCE_NETWORK_NEW)) {
		rcm_log_message(RCM_INFO,
		    _("IP: unrecognized event for %s\n"), rsrc);
		ip_log_err(NULL, errorp, "unrecognized event");
		errno = EINVAL;
		return (RCM_FAILURE);
	}

	/* Update cache to  reflect latest interfaces */
	if (update_cache(hd) < 0) {
		rcm_log_message(RCM_ERROR, _("IP: update_cache failed\n"));
		ip_log_err(NULL, errorp, "Private Cache update failed");
		return (RCM_FAILURE);
	}

	/* Process the nvlist for the event */
	if (process_nvlist(nvl) != 0) {
		rcm_log_message(RCM_WARNING,
		    _("IP: Error processing resource attributes(%s)\n"), rsrc);
		rcm_log_message(RCM_WARNING,
		    _("IP: One or more devices may not be configured.\n"));
		ip_log_err(NULL, errorp, "Error processing device properties");
		/* Continue processing interfaces that were valid */
	}

	(void) mutex_lock(&nil_lock);

	/* Configure all new interfaces found */
	for (nilp = nil_head, n = 0; n < num_ni; nilp = nilp->next, n++) {
		nip = nilp->nifp;
		if (if_configure(nip->name) != 0) {
			rcm_log_message(RCM_ERROR,
			    _("IP: Configuration failed (%s)\n"), nip->name);
			ip_log_err(NULL, errorp,
			    "Failed configuring one or more IP addresses");
			/* continue configuring rest of the interfaces */
		}
	}

	/* Notify all IP address consumers and clean up interface list */
	for (nilp = nil_head; nilp; ) {
		nip = nilp->nifp;
		if (nip != (struct net_interface *)0) {
			if (nip->name != 0) {
				ip_consumer_notify(hd, nip->name, errorp, flags,
				    depend_info);
				free(nip->name);
			}
			if (nip->type != 0)
				free(nip->type);
			free((char *)nip);
		}

		onilp = nilp;
		nilp = nilp->next;
		free((char *)onilp);
	}

	num_ni = 0;		/* reset new if count */
	nil_head = NIL_NULL;	/* reset list head */

	(void) mutex_unlock(&nil_lock);

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
	int numifs;
	char *buf;
	char *nic;
	const char *fmt;
	char *sep;
	char addrstr[INET6_ADDRSTRLEN];
	int offline = 0;
	size_t bufsz;

	rcm_log_message(RCM_TRACE2, "IP: usage(%s)\n", node->ip_resource);

	nic = strchr(node->ip_resource, '/');
	nic = nic ? nic + 1 : node->ip_resource;

	/* TRANSLATION_NOTE: separator used between IP addresses */
	sep = _(", ");

	numifs = 0;
	for (lif = node->ip_pif->pi_lifs; lif != NULL; lif = lif->li_next) {
		if (lif->li_ifflags & IFF_UP) {
			numifs++;
		}
	}

	if (node->ip_cachestate & CACHE_IF_OFFLINED) {
		offline++;
	}

	if (!offline && numifs) {
		fmt = _("%1$s hosts IP addresses: ");
	} else if (offline) {
		fmt = _("%1$s offlined");
	} else {
		fmt = _("%1$s plumbed but down");
	}

	/* space for addresses and separators, plus message */
	bufsz = ((numifs * (INET6_ADDRSTRLEN + strlen(sep))) +
	    strlen(fmt) + strlen(nic) + 1);
	if ((buf = malloc(bufsz)) == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("IP: usage(%s) malloc failure(%s)\n"),
		    node->ip_resource, strerror(errno));
		return (NULL);
	}
	bzero(buf, bufsz);
	(void) sprintf(buf, fmt, nic);

	if (offline || (numifs == 0)) {	/* Nothing else to do */
		rcm_log_message(RCM_TRACE2, "IP: usage (%s) info = %s\n",
		    node->ip_resource, buf);

		return (buf);
	}

	for (lif = node->ip_pif->pi_lifs; lif != NULL; lif = lif->li_next) {

		void *addr;
		int af;

		if (!(lif->li_ifflags & IFF_UP)) {
			/* ignore interfaces not up */
			continue;
		}
		af = lif->li_addr.family;
		if (af == AF_INET6) {
			addr = &lif->li_addr.ip6.sin6_addr;
		} else if (af == AF_INET) {
			addr = &lif->li_addr.ip4.sin_addr;
		} else {
			rcm_log_message(RCM_DEBUG,
			    "IP: unknown addr family %d, assuming AF_INET\n",
			    af);
			af = AF_INET;
			addr = &lif->li_addr.ip4.sin_addr;
		}
		if (inet_ntop(af, addr, addrstr, INET6_ADDRSTRLEN) == NULL) {
			rcm_log_message(RCM_ERROR,
			    _("IP: inet_ntop: %s\n"), strerror(errno));
			continue;
		}
		rcm_log_message(RCM_DEBUG, "IP addr := %s\n", addrstr);

		(void) strcat(buf, addrstr);
		numifs--;
		if (numifs > 0) {
			(void) strcat(buf, ", ");
		}
	}

	rcm_log_message(RCM_TRACE2, "IP: usage (%s) info = %s\n",
	    node->ip_resource, buf);

	return (buf);
}

/*
 * Cache management routines, all cache management functions should be
 * be called with cache_lock held.
 */

/*
 * cache_lookup() - Get a cache node for a resource. Supports VLAN interfaces.
 *		  Call with cache lock held.
 *
 * This ensures that the cache is consistent with the system state and
 * returns a pointer to the cache element corresponding to the resource.
 */
static ip_cache_t *
cache_lookup(rcm_handle_t *hd, char *rsrc, char options)
{
	ip_cache_t *probe;
	char *resource;		/* physical resource */

	rcm_log_message(RCM_TRACE2, "IP: cache lookup(%s)\n", rsrc);

	if ((options & CACHE_REFRESH) && (hd != NULL)) {
		/* drop lock since update locks cache again */
		(void) mutex_unlock(&cache_lock);
		(void) update_cache(hd);
		(void) mutex_lock(&cache_lock);
	}

	if ((resource = get_physical_resource(rsrc)) == NULL) {
		errno = ENOENT;
		return (NULL);
	}

	probe = cache_head.ip_next;
	while (probe != &cache_tail) {
		if (probe->ip_resource &&
		    STREQ(resource, probe->ip_resource)) {
			rcm_log_message(RCM_TRACE2,
			    "IP: cache lookup success(%s)\n", rsrc);
			free(resource);
			return (probe);
		}
		probe = probe->ip_next;
	}
	free(resource);
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
	node->ip_next->ip_prev = node->ip_prev;
	node->ip_prev->ip_next = node->ip_next;
	node->ip_next = NULL;
	node->ip_prev = NULL;
}

/*
 * update_pif() - Update physical interface properties
 *		Call with cache_lock held
 */
/*ARGSUSED*/
static int
update_pif(rcm_handle_t *hd, int af, int sock, struct lifreq *lifr)
{
	char	ifname[RCM_NET_RESOURCE_MAX];
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

	rcm_log_message(RCM_TRACE1, "IP: update_pif(%s)\n", lifr->lifr_name);

	if (!ifparse_ifspec(lifr->lifr_name, &ifspec)) {
		rcm_log_message(RCM_ERROR, _("IP: bad network interface: %s\n"),
		    lifr->lifr_name);
		return (-1);
	}

	(void) snprintf(pif.pi_ifname, sizeof (pif.pi_ifname), "%s%d",
	    ifspec.ifsp_devnm, ifspec.ifsp_ppa);
	if (ifspec.ifsp_lunvalid)
		ifnumber = ifspec.ifsp_lun;

	/* Get the interface flags */
	(void) strcpy(lifreq.lifr_name, lifr->lifr_name);
	if (ioctl(sock, SIOCGLIFFLAGS, (char *)&lifreq) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: SIOCGLIFFLAGS(%s): %s\n"),
		    pif.pi_ifname, strerror(errno));
		return (-1);
	}
	(void) memcpy(&ifflags, &lifreq.lifr_flags, sizeof (ifflags));

	/* Ignore loopback and multipoint interfaces */
	if (!(ifflags & IFF_MULTICAST) || (ifflags & IFF_LOOPBACK)) {
		rcm_log_message(RCM_TRACE3, "IP: if ignored (%s)\n",
		    pif.pi_ifname);
		return (0);
	}

	/* Get the interface group name for this interface */
	if (ioctl(sock, SIOCGLIFGROUPNAME, (char *)&lifreq) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: SIOCGLIFGROUPNAME(%s): %s\n"),
		    lifreq.lifr_name, strerror(errno));
		return (-1);
	}

	/* copy the group name */
	(void) memcpy(&pif.pi_grpname, &lifreq.lifr_groupname,
	    sizeof (pif.pi_grpname));
	pif.pi_grpname[sizeof (pif.pi_grpname) - 1] = '\0';

	/* Get the interface address for this interface */
	if (ioctl(sock, SIOCGLIFADDR, (char *)&lifreq) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: SIOCGLIFADDR(%s): %s\n"),
		    lifreq.lifr_name, strerror(errno));
		return (-1);
	}
	(void) memcpy(&ifaddr, &lifreq.lifr_addr, sizeof (ifaddr));

	/* Search for the interface in our cache */
	(void) snprintf(ifname, sizeof (ifname), "%s/%s", RCM_NET_PREFIX,
	    pif.pi_ifname);

	probe = cache_lookup(hd, ifname, CACHE_NO_REFRESH);
	if (probe != NULL) {
		probe->ip_cachestate &= ~(CACHE_IF_STALE);
	} else {
		if ((probe = calloc(1, sizeof (ip_cache_t))) == NULL) {
			/* malloc errors are bad */
			rcm_log_message(RCM_ERROR, _("IP: calloc: %s\n"),
			    strerror(errno));
			return (-1);
		}

		probe->ip_resource = get_physical_resource(ifname);
		if (!probe->ip_resource) {
			rcm_log_message(RCM_ERROR, _("IP: strdup: %s\n"),
			    strerror(errno));
			free(probe);
			return (-1);
		}

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

	/* save pif properties */
	(void) memcpy(&probepif->pi_grpname, &pif.pi_grpname,
	    sizeof (pif.pi_grpname));

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
	int sock;
	char *buf;
	struct lifnum lifn;
	struct lifconf lifc;
	struct lifreq *lifrp;
	int i;

	rcm_log_message(RCM_TRACE2, "IP: update_ipifs\n");

	if ((sock = socket(af, SOCK_DGRAM, 0)) == -1) {
		rcm_log_message(RCM_ERROR,
		    _("IP: failure opening %s socket: %s\n"),
		    af == AF_INET6 ? "IPv6" : "IPv4", strerror(errno));
		return (-1);
	}

	lifn.lifn_family = af;
	lifn.lifn_flags = 0;
	if (ioctl(sock, SIOCGLIFNUM, (char *)&lifn) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: SIOCLGIFNUM failed: %s\n"),
		    strerror(errno));
		(void) close(sock);
		return (-1);
	}

	if ((buf = calloc(lifn.lifn_count, sizeof (struct lifreq))) == NULL) {
		rcm_log_message(RCM_ERROR, _("IP: calloc: %s\n"),
		    strerror(errno));
		(void) close(sock);
		return (-1);
	}

	lifc.lifc_family = af;
	lifc.lifc_flags = 0;
	lifc.lifc_len = sizeof (struct lifreq) * lifn.lifn_count;
	lifc.lifc_buf = buf;

	if (ioctl(sock, SIOCGLIFCONF, (char *)&lifc) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: SIOCGLIFCONF failed: %s\n"),
		    strerror(errno));
		free(buf);
		(void) close(sock);
		return (-1);
	}

	/* now we need to search for active interfaces */
	lifrp = lifc.lifc_req;
	for (i = 0; i < lifn.lifn_count; i++) {
		(void) update_pif(hd, af, sock, lifrp);
		lifrp++;
	}

	free(buf);
	(void) close(sock);
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
	char *nic = NULL;
	int len;
	const char *errfmt;
	char *error;

	if ((node != NULL) && (node->ip_pif != NULL) &&
	    (node->ip_pif->pi_ifname != NULL)) {
		nic = strrchr(node->ip_pif->pi_ifname, '/');
		nic = nic ? nic + 1 : node->ip_pif->pi_ifname;
	}

	if (errorp != NULL)
		*errorp = NULL;

	if (nic == NULL) {
		rcm_log_message(RCM_ERROR, _("IP: %s\n"), errmsg);
		errfmt = _("IP: %s");
		len = strlen(errfmt) + strlen(errmsg) + 1;
		if (error = (char *)calloc(1, len)) {
			(void) sprintf(error, errfmt, errmsg);
		}
	} else {
		rcm_log_message(RCM_ERROR, _("IP: %s(%s)\n"), errmsg, nic);
		errfmt = _("IP: %s(%s)");
		len = strlen(errfmt) + strlen(errmsg) + strlen(nic) + 1;
		if (error = (char *)calloc(1, len)) {
			(void) sprintf(error, errfmt, errmsg, nic);
		}
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
				(void) clr_cfg_state(pif);
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
						(void) clr_cfg_state(pif);
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
			    "%s %s:%d configinfo\n", USR_SBIN_IFCONFIG,
			    pif->pi_ifname, lif->li_ifnum);
		} else if (lif->li_ifflags & IFF_IPV6) {
			(void) snprintf(syscmd, sizeof (syscmd),
			    "%s %s:%d inet6 configinfo\n", USR_SBIN_IFCONFIG,
			    pif->pi_ifname, lif->li_ifnum);
		}
		rcm_log_message(RCM_TRACE2, "IP: %s\n", syscmd);

		/* open a pipe to retrieve reconfiguration info */
		if ((fp = popen(syscmd, "r")) == NULL) {
			rcm_log_message(RCM_ERROR,
			    _("IP: ifconfig configinfo error (%s:%d) %s\n"),
			    pif->pi_ifname, lif->li_ifnum, strerror(errno));
			(void) clr_cfg_state(pif);
			return (-1);
		}
		bzero(buf, MAX_RECONFIG_SIZE);

		if (fgets(buf, MAX_RECONFIG_SIZE, fp) == NULL) {
			rcm_log_message(RCM_ERROR,
			    _("IP: ifconfig configinfo error (%s:%d) %s\n"),
			    pif->pi_ifname, lif->li_ifnum, strerror(errno));
			(void) pclose(fp);
			(void) clr_cfg_state(pif);
			return (-1);
		}
		(void) pclose(fp);

		lif->li_reconfig = malloc(strlen(buf)+1);
		if (lif->li_reconfig == NULL) {
			rcm_log_message(RCM_ERROR,
			    _("IP: malloc error (%s) %s\n"),
			    pif->pi_ifname, strerror(errno));
			(void) clr_cfg_state(pif);
			return (-1);
		}
		(void) strcpy(lif->li_reconfig, buf);
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
	ip_pif_t *pif;
	int ipv4 = 0, ipv6 = 0;
	char syscmd[MAX_RECONFIG_SIZE + LIFNAMSIZ];

	rcm_log_message(RCM_TRACE2, "IP: if_unplumb(%s)\n", node->ip_resource);

	pif = node->ip_pif;
	lif = pif->pi_lifs;

	while (lif != NULL) {
		if (lif->li_ifflags & IFF_IPV4) {
			ipv4++;
		} else if (lif->li_ifflags & IFF_IPV6) {
			ipv6++;
		} else {
			/* Unlikely case */
			rcm_log_message(RCM_DEBUG,
			    _("IP: Unplumb ignored (%s:%d)\n"),
			    pif->pi_ifname, lif->li_ifnum);
			lif = lif->li_next;
			continue;
		}
		lif = lif->li_next;
	}

	/* Unplumb the physical interface */
	if (ipv4) {
		rcm_log_message(RCM_TRACE2,
		    "IP: if_unplumb: ifconfig %s unplumb\n", pif->pi_ifname);
		(void) snprintf(syscmd, sizeof (syscmd), "%s %s unplumb\n",
		    USR_SBIN_IFCONFIG, pif->pi_ifname);
		if (rcm_exec_cmd(syscmd) != 0) {
			rcm_log_message(RCM_ERROR,
			    _("IP: Cannot unplumb (%s) %s\n"),
			    pif->pi_ifname, strerror(errno));
			return (-1);
		}
	}
	if (ipv6) {
		rcm_log_message(RCM_TRACE2,
		    "IP: if_unplumb: ifconfig %s inet6 unplumb\n",
		    pif->pi_ifname);
		(void) snprintf(syscmd, sizeof (syscmd),
		    "%s %s inet6 unplumb\n", USR_SBIN_IFCONFIG, pif->pi_ifname);
		if (rcm_exec_cmd(syscmd) != 0) {
			rcm_log_message(RCM_ERROR,
			    _("IP: Cannot unplumb (%s) %s\n"),
			    pif->pi_ifname, strerror(errno));
			return (-1);
		}
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
	char syscmd[LIFNAMSIZ+MAXPATHLEN];	/* must be big enough */
	int max_ipv4 = 0, max_ipv6 = 0;

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
	lif = pif->pi_lifs;

	/*
	 * Make a first pass to plumb in physical interfaces and get a count
	 * of the max logical interfaces
	 */
	while (lif != NULL) {
		if (lif->li_ifflags & IFF_IPV4) {
			if (lif->li_ifnum > max_ipv4) {
				max_ipv4 = lif->li_ifnum;
			}
		} else if (lif->li_ifflags & IFF_IPV6) {
			if (lif->li_ifnum > max_ipv6) {
				max_ipv6 = lif->li_ifnum;
			}
		} else {
			/* Unlikely case */
			rcm_log_message(RCM_DEBUG,
			    _("IP: Re-plumb ignored (%s:%d)\n"),
			    pif->pi_ifname, lif->li_ifnum);
			lif = lif->li_next;
			continue;
		}

		if (lif->li_ifnum == 0) { /* physical interface instance */
			if ((lif->li_ifflags & IFF_NOFAILOVER) ||
			    (strcmp(pif->pi_grpname, "") == 0)) {
				(void) snprintf(syscmd, sizeof (syscmd),
				    "%s %s\n", USR_SBIN_IFCONFIG,
				    lif->li_reconfig);
			} else if (lif->li_ifflags & IFF_IPV4) {
				(void) snprintf(syscmd, sizeof (syscmd),
				    "%s %s inet plumb group %s\n",
				    USR_SBIN_IFCONFIG,
				    pif->pi_ifname, pif->pi_grpname);
			} else if (lif->li_ifflags & IFF_IPV6) {
				(void) snprintf(syscmd, sizeof (syscmd),
				    "%s %s inet6 plumb group %s\n",
				    USR_SBIN_IFCONFIG,
				    pif->pi_ifname, pif->pi_grpname);
			}

			rcm_log_message(RCM_TRACE2,
			    "IP: if_replumb: %s\n", syscmd);
			if (rcm_exec_cmd(syscmd) != 0) {
				rcm_log_message(RCM_ERROR,
				    _("IP: Cannot plumb (%s) %s\n"),
				    pif->pi_ifname, strerror(errno));
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

		lif = lif->li_next;
	}

	/* Now, add all the logical interfaces in the correct order */
	for (i = 1; i <= MAX(max_ipv6, max_ipv4); i++) {
		/* reset lif through every iteration */
		lif = pif->pi_lifs;
		while (lif != NULL) {
			if (((lif->li_ifflags & IFF_NOFAILOVER) ||
			    (strcmp(pif->pi_grpname, "") == 0)) &&
			    (lif->li_ifnum == i)) {
				/* Plumb in the logical interface */
				(void) snprintf(syscmd, sizeof (syscmd),
				    "%s %s\n", USR_SBIN_IFCONFIG,
				    lif->li_reconfig);
				rcm_log_message(RCM_TRACE2,
				    "IP: if_replumb: %s\n", syscmd);
				if (rcm_exec_cmd(syscmd) != 0) {
					rcm_log_message(RCM_ERROR,
					    _("IP: Cannot addif (%s:%d) "
					    "%s\n"),
					    pif->pi_ifname, i, strerror(errno));
					return (-1);
				}
			}
			lif = lif->li_next;
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
 * ip_ipmp_offline() - Failover from if_from to if_to using a
 *		     minimum redudancy of min_red. This uses IPMPs
 *		     "offline" mechanism to achieve the failover.
 */
static int
ip_ipmp_offline(ip_cache_t *if_from, ip_cache_t *if_to)
{
	mpathd_cmd_t mpdcmd;

	if ((if_from == NULL) || (if_from->ip_pif == NULL) ||
	    (if_from->ip_pif->pi_ifname == NULL)) {
		return (-1);
	}

	rcm_log_message(RCM_TRACE1, "IP: ip_ipmp_offline\n");

	mpdcmd.cmd_command = MI_OFFLINE;
	(void) strcpy(mpdcmd.cmd_ifname, if_from->ip_pif->pi_ifname);

	if ((if_to != NULL) && (if_to->ip_pif != NULL) &&
	    (if_to->ip_pif->pi_ifname != NULL)) {
		rcm_log_message(RCM_TRACE1, "IP: ip_ipmp_offline (%s)->(%s)\n",
		    if_from->ip_pif->pi_ifname, if_to->ip_pif->pi_ifname);
		(void) strncpy(mpdcmd.cmd_movetoif, if_to->ip_pif->pi_ifname,
		    sizeof (mpdcmd.cmd_movetoif));
		mpdcmd.cmd_movetoif[sizeof (mpdcmd.cmd_movetoif) - 1] = '\0';
	} else {
		rcm_log_message(RCM_TRACE1, "IP: ip_ipmp_offline (%s)->(any)\n",
		    if_from->ip_pif->pi_ifname);
		(void) strcpy(mpdcmd.cmd_movetoif, "");	/* signifies any */
	}
	mpdcmd.cmd_min_red = if_from->ip_ifred;

	if (mpathd_send_cmd(&mpdcmd) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: mpathd offline error: %s\n"),
		    strerror(errno));
		return (-1);
	}

	rcm_log_message(RCM_TRACE1, "IP: ipmp offline success\n");
	return (0);
}

/*
 * ip_ipmp_undo_offline() - Undo prior offline of the interface.
 *			  This uses IPMPs "undo offline" feature.
 */
static int
ip_ipmp_undo_offline(ip_cache_t *node)
{
	mpathd_cmd_t mpdcmd;

	mpdcmd.cmd_command = MI_UNDO_OFFLINE;
	(void) strcpy(mpdcmd.cmd_ifname, node->ip_pif->pi_ifname);

	if (mpathd_send_cmd(&mpdcmd) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: mpathd error: %s\n"),
		    strerror(errno));
		return (-1);
	}

	rcm_log_message(RCM_TRACE1, "IP: ipmp undo offline success\n");
	return (0);
}

/*
 * get_physical_resource() - Convert a name (e.g., "SUNW_network/hme0:1" or
 * "SUNW_network/hme1000") into a dynamically allocated string containing the
 * associated physical device resource name ("SUNW_network/hme0").  Since we
 * assume that interface names map directly to device names, this is a
 * pass-through operation, with the exception that logical interface numbers
 * and VLANs encoded in the PPA are stripped.  This logic will need to be
 * revisited to support administratively-chosen interface names.
 */
static char *
get_physical_resource(const char *rsrc)
{
	char		*rsrc_ifname, *ifname;
	ifspec_t	ifspec;

	rsrc_ifname = strchr(rsrc, '/');
	if (rsrc_ifname == NULL || !ifparse_ifspec(rsrc_ifname + 1, &ifspec)) {
		rcm_log_message(RCM_ERROR, _("IP: bad resource: %s\n"), rsrc);
		return (NULL);
	}

	ifname = malloc(RCM_NET_RESOURCE_MAX);
	if (ifname == NULL) {
		rcm_log_message(RCM_ERROR, _("IP: malloc error(%s): %s\n"),
		    strerror(errno), rsrc);
		return (NULL);
	}

	(void) snprintf(ifname, RCM_NET_RESOURCE_MAX, "%s/%s%d", RCM_NET_PREFIX,
	    ifspec.ifsp_devnm, VLAN_GET_PPA(ifspec.ifsp_ppa));

	return (ifname);
}

/*
 * if_get_flags() - Return the cached physical interface flags
 *		  Call with cache_lock held
 */
static uint64_t
if_get_flags(ip_pif_t *pif)
{
	ip_lif_t *lif;

	for (lif = pif->pi_lifs; lif != NULL; lif = lif->li_next) {
		if (lif->li_ifnum == 0) {
			return (lif->li_ifflags & RCM_PIF_FLAGS);
		}
	}
	return (0);
}

/*
 * mpathd_send_cmd() - Sends the command to in.mpathd.
 */
static int
mpathd_send_cmd(mpathd_cmd_t *mpd)
{
	mpathd_unoffline_t mpc;
	struct mpathd_response mpr;
	int i;
	int s;

	rcm_log_message(RCM_TRACE1, "IP: mpathd_send_cmd \n");

	for (i = 0; i < MPATHD_MAX_RETRIES; i++) {
		s = connect_to_mpathd(AF_INET);
		if (s == -1) {
			s = connect_to_mpathd(AF_INET6);
			if (s == -1) {
				rcm_log_message(RCM_ERROR,
				    _("IP: Cannot talk to mpathd\n"));
				return (-1);
			}
		}
		switch (mpd->cmd_command) {
		case MI_OFFLINE :
			rcm_log_message(RCM_TRACE1, "IP: MI_OFFLINE: "
			    "(%s)->(%s) redundancy = %d\n", mpd->cmd_ifname,
			    mpd->cmd_movetoif, mpd->cmd_min_red);

			if (write(s, mpd, sizeof (mpathd_cmd_t)) !=
			    sizeof (mpathd_cmd_t)) {
				rcm_log_message(RCM_ERROR,
				    _("IP: mpathd write: %s\n"),
				    strerror(errno));
				(void) close(s);
				return (-1);
			}
			break;

		case MI_SETOINDEX :
			rcm_log_message(RCM_TRACE1, "IP: MI_SETOINDEX: "
			    "(%s)->(%s) family = %d\n", mpd->from_lifname,
			    mpd->to_pifname, mpd->addr_family);

			if (write(s, mpd, sizeof (mpathd_cmd_t)) !=
			    sizeof (mpathd_cmd_t)) {
				rcm_log_message(RCM_ERROR,
				    _("IP: mpathd write: %s\n"),
				    strerror(errno));
				(void) close(s);
				return (-1);
			}
			break;

		case MI_UNDO_OFFLINE:
			/* mpathd checks for exact size of the message */
			mpc.cmd_command = mpd->cmd_command;
			(void) strcpy(mpc.cmd_ifname, mpd->cmd_ifname);

			rcm_log_message(RCM_TRACE1, "IP: MI_UNDO_OFFLINE: "
			    "(%s)\n", mpd->cmd_ifname);

			if (write(s, &mpc, sizeof (mpathd_unoffline_t)) !=
			    sizeof (mpathd_unoffline_t)) {
				rcm_log_message(RCM_ERROR,
				    _("IP: mpathd write: %s\n"),
				    strerror(errno));
				(void) close(s);
				return (-1);
			}
			break;
		default :
			rcm_log_message(RCM_ERROR,
			    _("IP: unsupported mpathd command\n"));
			(void) close(s);
			return (-1);
		}

		bzero(&mpr, sizeof (struct mpathd_response));
		/* Read the result from mpathd */
		if (read(s, &mpr, sizeof (struct mpathd_response)) !=
		    sizeof (struct mpathd_response)) {
			rcm_log_message(RCM_ERROR,
			    _("IP: mpathd read : %s\n"), strerror(errno));
			(void) close(s);
			return (-1);
		}

		(void) close(s);
		if (mpr.resp_mpathd_err == 0) {
			rcm_log_message(RCM_TRACE1,
			    "IP: mpathd_send_cmd success\n");
			return (0);			/* Successful */
		}

		if (mpr.resp_mpathd_err == MPATHD_SYS_ERROR) {
			if (mpr.resp_sys_errno == EAGAIN) {
				(void) sleep(1);
				rcm_log_message(RCM_DEBUG,
				    _("IP: mpathd retrying\n"));
				continue;		/* Retry */
			}
			errno = mpr.resp_sys_errno;
			rcm_log_message(RCM_WARNING,
			    _("IP: mpathd_send_cmd error: %s\n"),
			    strerror(errno));
		} else if (mpr.resp_mpathd_err == MPATHD_MIN_RED_ERROR) {
			errno = EIO;
			rcm_log_message(RCM_ERROR, _("IP: in.mpathd(1M): "
			    "Minimum redundancy not met\n"));
		} else {
			rcm_log_message(RCM_ERROR,
			    _("IP: mpathd_send_cmd error\n"));
		}
		/* retry */
	}

	rcm_log_message(RCM_ERROR,
	    _("IP: mpathd_send_cmd failed %d retries\n"), MPATHD_MAX_RETRIES);
	return (-1);
}

/*
 * Returns -1 on failure. Returns the socket file descriptor on
 * success.
 */
static int
connect_to_mpathd(int family)
{
	int s;
	struct sockaddr_storage ss;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
	struct in6_addr loopback_addr = IN6ADDR_LOOPBACK_INIT;
	int addrlen;
	int ret;
	int on;

	rcm_log_message(RCM_TRACE1, "IP: connect_to_mpathd\n");

	s = socket(family, SOCK_STREAM, 0);
	if (s < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: mpathd socket: %s\n"), strerror(errno));
		return (-1);
	}
	bzero((char *)&ss, sizeof (ss));
	ss.ss_family = family;
	/*
	 * Need to bind to a privelged port. For non-root, this
	 * will fail. in.mpathd verifies that only commands coming
	 * from priveleged ports succeed so that the ordinary user
	 * can't issue offline commands.
	 */
	on = 1;
	if (setsockopt(s, IPPROTO_TCP, TCP_ANONPRIVBIND, &on,
	    sizeof (on)) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: mpathd setsockopt: TCP_ANONPRIVBIND: %s\n"),
		    strerror(errno));
		return (-1);
	}
	switch (family) {
	case AF_INET:
		sin->sin_port = 0;
		sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addrlen = sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		sin6->sin6_port = 0;
		sin6->sin6_addr = loopback_addr;
		addrlen = sizeof (struct sockaddr_in6);
		break;
	}
	ret = bind(s, (struct sockaddr *)&ss, addrlen);
	if (ret != 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: mpathd bind: %s\n"), strerror(errno));
		return (-1);
	}
	switch (family) {
	case AF_INET:
		sin->sin_port = htons(MPATHD_PORT);
		break;
	case AF_INET6:
		sin6->sin6_port = htons(MPATHD_PORT);
		break;
	}
	ret = connect(s, (struct sockaddr *)&ss, addrlen);
	if (ret != 0) {
		if (errno == ECONNREFUSED) {
			/* in.mpathd is not running, start it */
			if (rcm_exec_cmd(MPATHD_PATH) == -1) {
				rcm_log_message(RCM_ERROR,
				    _("IP: mpathd exec: %s\n"),
				    strerror(errno));
				return (-1);
			}
			ret = connect(s, (struct sockaddr *)&ss, addrlen);
		}
		if (ret != 0) {
			rcm_log_message(RCM_ERROR,
			    _("IP: mpathd connect: %s\n"), strerror(errno));
			return (-1);
		}
	}
	on = 0;
	if (setsockopt(s, IPPROTO_TCP, TCP_ANONPRIVBIND, &on,
	    sizeof (on)) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: mpathd setsockopt TCP_ANONPRIVBIND: %s\n"),
		    strerror(errno));
		return (-1);
	}

	rcm_log_message(RCM_TRACE1, "IP: connect_to_mpathd success\n");

	return (s);
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
		    "%s %s modremove %s@%d\n", USR_SBIN_IFCONFIG, name, arg,
		    pos);
	} else if (op == MOD_INSERT) {
		(void) snprintf(syscmd, sizeof (syscmd),
		    "%s %s modinsert %s@%d\n", USR_SBIN_IFCONFIG, name, arg,
		    pos);
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
	int udp_fd;
	int fd;
	int i;
	int num_mods;
	struct lifreq lifr;
	struct str_list strlist;

	rcm_log_message(RCM_TRACE1, "IP: getmodlist(%s)\n", name);

	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	lifr.lifr_flags = lif->li_ifflags;
	if (ip_domux2fd(&udp_fd, &fd, &lifr) < 0) {
		rcm_log_message(RCM_ERROR, _("IP: ip_domux2fd(%s)\n"), name);
		return (-1);
	}

	if ((num_mods = ioctl(fd, I_LIST, NULL)) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: get_modlist(%s): I_LIST(%s) \n"),
		    name, strerror(errno));
		(void) ip_plink(udp_fd, fd, &lifr);
		return (-1);
	}

	strlist.sl_nmods = num_mods;
	strlist.sl_modlist = malloc(sizeof (struct str_mlist) * num_mods);

	if (strlist.sl_modlist == NULL) {
		rcm_log_message(RCM_ERROR, _("IP: get_modlist(%s): %s\n"),
		    name, strerror(errno));
		(void) ip_plink(udp_fd, fd, &lifr);
		return (-1);
	}

	if (ioctl(fd, I_LIST, (caddr_t)&strlist) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: get_modlist(%s): I_LIST error: %s\n"),
		    name, strerror(errno));
		(void) ip_plink(udp_fd, fd, &lifr);
		return (-1);
	}

	for (i = 0; i < strlist.sl_nmods; i++) {
		lif->li_modules[i] =
		    malloc(strlen(strlist.sl_modlist[i].l_name)+1);
		if (lif->li_modules[i] == NULL) {
			rcm_log_message(RCM_ERROR,
			    _("IP: get_modlist(%s): %s\n"),
			    name, strerror(errno));
			(void) ip_plink(udp_fd, fd, &lifr);
			return (-1);
		}
		(void) strcpy(lif->li_modules[i], strlist.sl_modlist[i].l_name);
	}

	lif->li_modcnt = strlist.sl_nmods;
	free(strlist.sl_modlist);

	rcm_log_message(RCM_TRACE1, "IP: getmodlist(%s) success\n", name);
	return (ip_plink(udp_fd, fd, &lifr));
}

/*
 * ip_domux2fd() - Helper function for mod*() functions
 *		 Stolen from ifconfig.c
 */
static int
ip_domux2fd(int *udp_fd, int *fd, struct lifreq *lifr)
{
	int ip_fd;
	char	*udp_dev_name;
	char	*ip_dev_name;

	if (lifr->lifr_flags & IFF_IPV6) {
		udp_dev_name = UDP6_DEV_NAME;
		ip_dev_name  = IP6_DEV_NAME;
	} else {
		udp_dev_name = UDP_DEV_NAME;
		ip_dev_name  = IP_DEV_NAME;
	}

	if ((ip_fd = open(ip_dev_name, O_RDWR)) < 0) {
		rcm_log_message(RCM_ERROR, _("IP: ip_domux2fd: open(%s) %s\n"),
		    ip_dev_name, strerror(errno));
		return (-1);
	}
	if ((*udp_fd = open(udp_dev_name, O_RDWR)) < 0) {
		rcm_log_message(RCM_ERROR, _("IP: ip_domux2fd: open(%s) %s\n"),
		    udp_dev_name, strerror(errno));
		(void) close(ip_fd);
		return (-1);
	}
	if (ioctl(ip_fd, SIOCGLIFMUXID, (caddr_t)lifr) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: ip_domux2fd: SIOCGLIFMUXID(%s): %s\n"),
		    ip_dev_name, strerror(errno));
		(void) close(*udp_fd);
		(void) close(ip_fd);
		return (-1);
	}

	rcm_log_message(RCM_TRACE2,
	    "IP: ip_domux2fd: ARP_muxid %d IP_muxid %d\n",
	    lifr->lifr_arp_muxid, lifr->lifr_ip_muxid);

	if ((*fd = ioctl(*udp_fd, _I_MUXID2FD, lifr->lifr_ip_muxid)) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: ip_domux2fd: _I_MUXID2FD(%s): %s\n"),
		    udp_dev_name, strerror(errno));
		(void) close(*udp_fd);
		(void) close(ip_fd);
		return (-1);
	}
	if (ioctl(*udp_fd, I_PUNLINK, lifr->lifr_ip_muxid) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: ip_domux2fd: I_PUNLINK(%s): %s\n"),
		    udp_dev_name, strerror(errno));
		(void) close(*udp_fd);
		(void) close(ip_fd);
		return (-1);
	}

	/* Note: udp_fd is closed in ip_plink below */
	(void) close(ip_fd);
	return (0);
}

/*
 * ip_plink() - Helper function for mod*() functions.
 *	      Stolen from ifconfig.c
 */
static int
ip_plink(int udp_fd, int fd, struct lifreq *lifr)
{
	int mux_id;

	if ((mux_id = ioctl(udp_fd, I_PLINK, fd)) < 0) {
		rcm_log_message(RCM_ERROR, _("IP: ip_plink I_PLINK(%s): %s\n"),
		    UDP_DEV_NAME, strerror(errno));
		(void) close(udp_fd);
		(void) close(fd);
		return (-1);
	}

	lifr->lifr_ip_muxid = mux_id;
	if (ioctl(udp_fd, SIOCSLIFMUXID, (caddr_t)lifr) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: ip_plink SIOCSLIFMUXID(%s): %s\n"),
		    UDP_DEV_NAME, strerror(errno));
		(void) close(udp_fd);
		(void) close(fd);
		return (-1);
	}

	(void) close(udp_fd);
	(void) close(fd);
	return (0);
}

/*
 * ip_onlinelist()
 *
 *	Notify online to IP address consumers.
 */
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
 * ip_get_addrlist() -	Compile list of IP addresses hosted on this NIC (node)
 *			This routine malloc() required memeory for the list
 *			Returns list on success, NULL if failed
 *			Call with cache_lock held.
 */
static char **
ip_get_addrlist(ip_cache_t *node)
{
	ip_lif_t *lif;
	char **addrlist = NULL;
	int numifs;
	char addrstr[INET6_ADDRSTRLEN];
	void *addr;
	int af;
	int i;

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

		af = lif->li_addr.family;
		if (af == AF_INET6) {
			addr = &lif->li_addr.ip6.sin6_addr;
		} else if (af == AF_INET) {
			addr = &lif->li_addr.ip4.sin_addr;
		} else {
			rcm_log_message(RCM_DEBUG,
			    "IP: unknown addr family %d, assuming AF_INET\n",
			    af);
			af = AF_INET;
			addr = &lif->li_addr.ip4.sin_addr;
		}
		if (inet_ntop(af, addr, addrstr, INET6_ADDRSTRLEN) == NULL) {
			rcm_log_message(RCM_ERROR,
			    _("IP: inet_ntop: %s\n"), strerror(errno));
			ip_free_addrlist(addrlist);
			return (NULL);
		}

		if ((addrlist[i] = malloc(strlen(addrstr) + RCM_SIZE_SUNW_IP))
		    == NULL) {
			rcm_log_message(RCM_ERROR,
			    _("IP: ip_get_addrlist(%s) malloc failure(%s)\n"),
			    node->ip_resource, strerror(errno));
			ip_free_addrlist(addrlist);
			return (NULL);
		}
		(void) strcpy(addrlist[i], RCM_STR_SUNW_IP);	/* SUNW_ip/ */
		(void) strcat(addrlist[i], addrstr);	/* SUNW_ip/<address> */

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
ip_consumer_notify(rcm_handle_t *hd, char *ifinst, char **errorp, uint_t flags,
	rcm_info_t **depend_info)
{
	char ifname[LIFNAMSIZ + 1];
	char cached_name[RCM_NET_RESOURCE_MAX];
	ip_cache_t *node;
	char *cp;

	rcm_log_message(RCM_TRACE1, "IP: ip_consumer_notify(%s)\n", ifinst);

	if (ifinst == NULL)
		return;

	(void) memcpy(&ifname, ifinst, sizeof (ifname));
	ifname[sizeof (ifname) - 1] = '\0';

	/* remove LIF component */
	cp = strchr(ifname, ':');
	if (cp) {
		*cp = 0;
	}

	/* Check for the interface in the cache */
	(void) snprintf(cached_name, sizeof (cached_name), "%s/%s",
	    RCM_NET_PREFIX, ifname);

	(void) mutex_lock(&cache_lock);
	if ((node = cache_lookup(hd, cached_name, CACHE_REFRESH)) == NULL) {
		rcm_log_message(RCM_TRACE1, "IP: Skipping interface(%s) \n",
		    ifname);
		(void) mutex_unlock(&cache_lock);
		return;
	}
	/*
	 * Inform anonymous consumers about IP addresses being
	 * onlined
	 */
	(void) ip_onlinelist(hd, node, errorp, flags, depend_info);

	(void) mutex_unlock(&cache_lock);

	rcm_log_message(RCM_TRACE2, "IP: ip_consumer_notify success\n");
	return;

}
/*
 * process_nvlist() - Determine network interfaces on a new attach by
 *			processing the nvlist
 */
/*ARGSUSED*/
static int
process_nvlist(nvlist_t *nvl)
{
	nvpair_t	*nvp = NULL;
	char *driver_name;
	char *devfs_path;
	int32_t instance;
	char *minor_byte_array;	/* packed nvlist of minor_data */
	uint_t nminor;			/* # of minor nodes */
	struct devfs_minor_data *mdata;
	nvlist_t *mnvl;
	nvpair_t *mnvp = NULL;

	rcm_log_message(RCM_TRACE1, "IP: process_nvlist\n");

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		/* Get driver name */
		if (STREQ(nvpair_name(nvp), RCM_NV_DRIVER_NAME)) {
			if (nvpair_value_string(nvp, &driver_name) != 0) {
				rcm_log_message(RCM_WARNING,
				    _("IP: cannot get driver name\n"));
				return (-1);
			}
		}
		/* Get instance */
		if (STREQ(nvpair_name(nvp), RCM_NV_INSTANCE)) {
			if (nvpair_value_int32(nvp, &instance) != 0) {
				rcm_log_message(RCM_WARNING,
				    _("IP: cannot get device instance\n"));
				return (-1);
			}
		}
		/* Get devfs_path */
		if (STREQ(nvpair_name(nvp), RCM_NV_DEVFS_PATH)) {
			if (nvpair_value_string(nvp, &devfs_path) != 0) {
				rcm_log_message(RCM_WARNING,
				    _("IP: cannot get device path\n"));
				return (-1);
			}
		}
		/* Get minor data */
		if (STREQ(nvpair_name(nvp), RCM_NV_MINOR_DATA)) {
			if (nvpair_value_byte_array(nvp,
			    (uchar_t **)&minor_byte_array, &nminor) != 0) {
				rcm_log_message(RCM_WARNING,
				    _("IP: cannot get device minor data\n"));
				return (-1);
			}
			if (nvlist_unpack(minor_byte_array,
			    nminor, &mnvl, 0) != 0) {
				rcm_log_message(RCM_WARNING,
				    _("IP: cannot get minor node data\n"));
				return (-1);
			}
			mdata = (struct devfs_minor_data *)calloc(1,
			    sizeof (struct devfs_minor_data));
			if (mdata == NULL) {
				rcm_log_message(RCM_WARNING,
				    _("IP: calloc error(%s)\n"),
				    strerror(errno));
				nvlist_free(mnvl);
				return (-1);
			}
			/* Enumerate minor node data */
			while ((mnvp = nvlist_next_nvpair(mnvl, mnvp)) !=
			    NULL) {
				/* Get minor type */
				if (STREQ(nvpair_name(mnvp),
				    RCM_NV_MINOR_TYPE)) {
					if (nvpair_value_int32(mnvp,
					    &mdata->minor_type) != 0) {
						rcm_log_message(RCM_WARNING,
						    _("IP: cannot get minor "
						    "type \n"));
						nvlist_free(mnvl);
						return (-1);
					}
				}
				/* Get minor name */
				if (STREQ(nvpair_name(mnvp),
				    RCM_NV_MINOR_NAME)) {
					if (nvpair_value_string(mnvp,
					    &mdata->minor_name) != 0) {
						rcm_log_message(RCM_WARNING,
						    _("IP: cannot get minor "
						    "name \n"));
						nvlist_free(mnvl);
						return (-1);
					}
				}
				/* Get minor node type */
				if (STREQ(nvpair_name(mnvp),
				    RCM_NV_MINOR_NODE_TYPE)) {
					if (nvpair_value_string(mnvp,
					    &mdata->minor_node_type) != 0) {
						rcm_log_message(RCM_WARNING,
						    _("IP: cannot get minor "
						    "node type \n"));
						nvlist_free(mnvl);
						return (-1);
					}
				}
			}
			(void) process_minor(devfs_path, driver_name, instance,
			    mdata);
			nvlist_free(mnvl);
		}
	}

	rcm_log_message(RCM_TRACE1, "IP: process_nvlist success\n");
	return (0);
}

static void
process_minor(char *devfs_path, char *name, int instance,
    struct devfs_minor_data *mdata)
{
	struct net_interface *nip;
	struct ni_list *nilp;
	struct ni_list *p;
	struct ni_list **pp;
	char *cname;
	size_t cnamelen;

	rcm_log_message(RCM_TRACE1, "IP: process_minor\n");

	if ((mdata->minor_node_type != NULL) &&
	    !STREQ(mdata->minor_node_type, PROP_NV_DDI_NETWORK)) {
		/* Process network devices only */
		return;
	}

	rcm_log_message(RCM_TRACE1, "IP: Examining %s (%s)\n",
	    devfs_path, mdata->minor_name);

	/* Sanity check, instances > 999 are illegal */
	if (instance > 999) {
		errno = EINVAL;
		rcm_log_message(RCM_ERROR, _("IP: invalid instance %d(%s)\n"),
		    instance, strerror(errno));
		return;
	}

	/* Now, let's add the node to the interface list */
	if ((nip = malloc(sizeof (struct net_interface))) == NULL) {
		rcm_log_message(RCM_ERROR, _("IP: malloc failure(%s)\n"),
		    strerror(errno));
		return;
	}
	(void) memset(nip, 0, sizeof (struct net_interface));

	cnamelen = strlen(name) + 1;
	/* Set NIC type */
	if ((nip->type = (char *)malloc(cnamelen)) == NULL) {
		free(nip);
		rcm_log_message(RCM_ERROR, _("IP: malloc failure(%s)\n"),
		    strerror(errno));
		return;
	}
	(void) memcpy(nip->type, name, cnamelen);

	cnamelen += 3;
	if ((cname = (char *)malloc(cnamelen)) == NULL) {
		free(nip->type);
		free(nip);
		rcm_log_message(RCM_ERROR, _("IP: malloc failure(%s)\n"),
		    strerror(errno));
		return;
	}
	(void) snprintf(cname, cnamelen, "%s%d", name, instance);

	rcm_log_message(RCM_TRACE1, "IP: Found SUNW_network/%s%d\n", name,
	    instance);

	/* Set NIC name */
	if ((nip->name = strdup(cname)) == NULL) {
		free(nip->type);
		free(nip);
		free(cname);
		rcm_log_message(RCM_ERROR, _("IP: strdup failure(%s)\n"),
		    strerror(errno));
		return;
	}
	free(cname);

	/* Add new interface to the list */
	(void) mutex_lock(&nil_lock);
	for (pp = &nil_head; (p = *pp) != NULL; pp = &(p->next)) {
		cname = p->nifp->name;
		if (strcmp(cname, nip->name) == 0)
			break;
	}

	if (p != NULL) {
		(void) mutex_unlock(&nil_lock);
		free(nip->name);
		free(nip->type);
		free(nip);
		rcm_log_message(RCM_TRACE1, "IP: secondary node - ignoring\n");
		return;
	}

	if ((nilp = malloc(sizeof (struct ni_list))) == NULL) {
		(void) mutex_unlock(&nil_lock);
		free(nip->name);
		free(nip->type);
		free(nip);
		rcm_log_message(RCM_ERROR, _("IP: malloc failure(%s)\n"),
		    strerror(errno));
		return;
	}

	nilp->nifp = nip;
	nilp->next = NULL;
	*pp = nilp;

	num_ni++;	/* Increment interface count */

	(void) mutex_unlock(&nil_lock);
	rcm_log_message(RCM_TRACE1, "IP: added new node\n");
}

/*
 * if_configure() - Configure a physical interface after attach
 */
static int
if_configure(char *ifinst)
{
	char cfgfile[MAXPATHLEN];
	char ifname[LIFNAMSIZ + 1];
	char cached_name[RCM_NET_RESOURCE_MAX];
	struct stat statbuf;
	ip_cache_t *node;
	char *cp;
	int af = 0;
	int ipmp = 0;

	if (ifinst == NULL)
		return (0);

	rcm_log_message(RCM_TRACE1, "IP: if_configure(%s)\n", ifinst);

	/*
	 * Check if the interface is already configured
	 */

	(void) memcpy(&ifname, ifinst, sizeof (ifname));
	ifname[sizeof (ifname) - 1] = '\0';

	/* remove LIF component */
	cp = strchr(ifname, ':');
	if (cp) {
		*cp = 0;
	}

	/* Check for the interface in the cache */
	(void) snprintf(cached_name, sizeof (cached_name), "%s/%s",
	    RCM_NET_PREFIX, ifname);

	/* Check if the interface is new or was previously offlined */
	(void) mutex_lock(&cache_lock);
	if (((node = cache_lookup(NULL, cached_name, CACHE_REFRESH)) != NULL) &&
	    (!(node->ip_cachestate & CACHE_IF_OFFLINED))) {
		rcm_log_message(RCM_TRACE1,
		    "IP: Skipping configured interface(%s) \n", ifname);
		(void) mutex_unlock(&cache_lock);
		return (0);
	}
	(void) mutex_unlock(&cache_lock);

	/* Scan IPv4 configuration first */
	(void) snprintf(cfgfile, MAXPATHLEN, "%s%s", CFGFILE_FMT_IPV4, ifinst);
	cfgfile[MAXPATHLEN - 1] = '\0';

	rcm_log_message(RCM_TRACE1, "IP: Scanning %s\n", cfgfile);
	if (stat(cfgfile, &statbuf) == 0) {
		af |= CONFIG_AF_INET;
		if (isgrouped(cfgfile)) {
			ipmp++;
		}
	}

	/* Scan IPv6 configuration details */
	(void) snprintf(cfgfile, MAXPATHLEN, "%s%s", CFGFILE_FMT_IPV6, ifinst);
	cfgfile[MAXPATHLEN - 1] = '\0';
	rcm_log_message(RCM_TRACE1, "IP: Scanning %s\n", cfgfile);
	if (stat(cfgfile, &statbuf) == 0) {
		af |= CONFIG_AF_INET6;
		if ((ipmp == 0) && isgrouped(cfgfile)) {
			ipmp++;
		}
	}

	if (af & CONFIG_AF_INET) {
		if (if_ipmp_config(ifinst, CONFIG_AF_INET, ipmp) == -1) {
			rcm_log_message(RCM_ERROR,
			    _("IP: IPv4 Post-attach failed (%s)\n"), ifinst);
			return (-1);
		}
	}

	if (af & CONFIG_AF_INET6) {
		if (if_ipmp_config(ifinst, CONFIG_AF_INET6, ipmp) == -1) {
			rcm_log_message(RCM_ERROR,
			    _("IP: IPv6 Post-attach failed(%s)\n"), ifinst);
			return (-1);
		}
	}

	rcm_log_message(RCM_TRACE1, "IP: if_configure(%s) success\n", ifinst);

	return (0);

}

/*
 * isgrouped() - Scans the given config file to see if this is a grouped
 *	       interface
 *	       Returns non-zero if true; 0 if false
 */
static int
isgrouped(char *cfgfile)
{
	FILE *fp;
	struct stat statb;
	char *buf = NULL;
	char *tokens[MAXARGS];		/* token pointers */
	char tspace[MAXLINE];		/* token space */
	int ntok;
	int group = 0;

	if (cfgfile == NULL)
		return (0);

	rcm_log_message(RCM_TRACE1, "IP: isgrouped(%s)\n", cfgfile);

	if (stat(cfgfile, &statb) != 0) {
		rcm_log_message(RCM_TRACE1,
		    _("IP: No config file(%s)\n"), cfgfile);
		return (0);
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
		return (0);
	}

	if ((fp = fopen(cfgfile, "r")) == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("IP: Cannot open configuration file(%s): %s\n"), cfgfile,
		    strerror(errno));
		return (0);
	}

	if ((buf = calloc(1, statb.st_size)) == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("IP: calloc failure(%s): %s\n"), cfgfile,
		    strerror(errno));
		(void) fclose(fp);
		return (0);
	}

	while (fgets(buf, statb.st_size, fp) != NULL) {
		if (*buf == '\0')
			continue;

		tokenize(buf, tokens, tspace, &ntok);
		while (ntok) {
			if (STREQ("group", tokens[ntok - 1])) {
				if (tokens[ntok] != NULL) {
					group++;
				}
			}
			ntok--;
		}
	}

	free(buf);

	(void) fclose(fp);

	if (group <= 0) {
		rcm_log_message(RCM_TRACE1, "IP: isgrouped(%s) non-grouped\n",
		    cfgfile);
		return (0);
	} else {
		rcm_log_message(RCM_TRACE1, "IP: isgrouped(%s) grouped\n",
		    cfgfile);
		return (1);
	}
}


/*
 * if_ipmp_config() - Configure an interface instance as specified by the
 *		    address family af and if it is grouped (ipmp).
 */
static int
if_ipmp_config(char *ifinst, int af, int ipmp)
{
	char cfgfile[MAXPATHLEN];	/* configuration file */
	FILE *fp;
	struct stat statb;
	char *buf;
	char *tokens[MAXARGS];		/* list of config attributes */
	char tspace[MAXLINE];		/* token space */
	char syscmd[MAX_RECONFIG_SIZE + MAXPATHLEN + 1];
	char grpcmd[MAX_RECONFIG_SIZE + MAXPATHLEN + 1];
	char fstr[8];		/* address family string inet or inet6 */
	int nofailover = 0;
	int newattach = 0;
	int cmdvalid = 0;
	int ntok;
	int n;
	int stdif = 0;

	if (ifinst == NULL)
		return (0);

	rcm_log_message(RCM_TRACE1, "IP: if_ipmp_config(%s) ipmp = %d\n",
	    ifinst, ipmp);

	if (af & CONFIG_AF_INET) {
		(void) snprintf(cfgfile, MAXPATHLEN, "%s%s", CFGFILE_FMT_IPV4,
		    ifinst);
		(void) strcpy(fstr, "inet");
	} else if (af & CONFIG_AF_INET6) {
		(void) snprintf(cfgfile, MAXPATHLEN, "%s%s", CFGFILE_FMT_IPV6,
		    ifinst);
		(void) strcpy(fstr, "inet6");
	} else {
		return (0);		/* nothing to do */
	}

	cfgfile[MAXPATHLEN - 1] = '\0';
	grpcmd[0] = '\0';

	if (stat(cfgfile, &statb) != 0) {
		rcm_log_message(RCM_TRACE1,
		    _("IP: No config file(%s)\n"), ifinst);
		return (0);
	}

	/* Config file exists, plumb in the physical interface */
	if (af & CONFIG_AF_INET6) {
		if (if_getcount(AF_INET6) == 0) {
			/*
			 * Configure software loopback driver if this is the
			 * first IPv6 interface plumbed
			 */
			newattach++;
			(void) snprintf(syscmd, sizeof (syscmd),
			    "%s lo0 %s plumb ::1 up", USR_SBIN_IFCONFIG, fstr);
			if (rcm_exec_cmd(syscmd) != 0) {
				rcm_log_message(RCM_ERROR,
				    _("IP: Cannot plumb (%s) %s\n"),
				    ifinst, strerror(errno));
				return (-1);
			}
		}
		(void) snprintf(syscmd, sizeof (syscmd), "%s %s %s plumb up",
		    USR_SBIN_IFCONFIG, ifinst, fstr);
	} else {
		(void) snprintf(syscmd, sizeof (syscmd), "%s %s %s plumb ",
		    USR_SBIN_IFCONFIG, ifinst, fstr);
		if (if_getcount(AF_INET) == 0) {
			newattach++;
		}
	}
	rcm_log_message(RCM_TRACE1, "IP: Exec: %s\n", syscmd);

	if (rcm_exec_cmd(syscmd) != 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: Cannot plumb (%s) %s\n"), ifinst, strerror(errno));
		return (-1);
	}

	/* Check if config file is empty, if so, nothing else to do */
	if (statb.st_size == 0) {
		rcm_log_message(RCM_TRACE1,
		    _("IP: Zero size config file(%s)\n"), ifinst);
		return (0);
	}

	if ((fp = fopen(cfgfile, "r")) == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("IP: Open error(%s): %s\n"), cfgfile, strerror(errno));
		return (-1);
	}

	if ((buf = calloc(1, statb.st_size)) == NULL) {
		rcm_log_message(RCM_ERROR,
		    _("IP: calloc(%s): %s\n"), ifinst, strerror(errno));
		(void) fclose(fp);
		return (-1);
	}

	/* a single line with one token implies a classical if */
	if (fgets(buf, statb.st_size, fp) != NULL) {
		tokenize(buf, tokens, tspace, &ntok);
		if (ntok == 1) {
			rcm_log_message(RCM_TRACE1, "IP: Standard interface\n");
			stdif++;
		}
	}
	if (fseek(fp, 0L, SEEK_SET) == -1) {
		rcm_log_message(RCM_ERROR, _("IP: fseek: %s\n"),
		    strerror(errno));
		return (-1);
	}

	/*
	 * Process the config command
	 * This loop also handles multiple logical interfaces that may
	 * be configured on a single line
	 */
	while (fgets(buf, statb.st_size, fp) != NULL) {
		nofailover = 0;
		cmdvalid = 0;

		if (*buf == '\0')
			continue;

		tokenize(buf, tokens, tspace, &ntok);
		if (ntok <= 0)
			continue;

		/* Reset the config command */
		(void) snprintf(syscmd, sizeof (syscmd), "%s %s %s ",
		    USR_SBIN_IFCONFIG, ifinst, fstr);

		/* No parsing if this is first interface of its kind */
		if (newattach) {
			(void) strcat(syscmd, buf);
			/* Classic if */
			if ((af & CONFIG_AF_INET) && (stdif == 1)) {
				(void) strcat(syscmd, CFG_CMDS_STD);
			}
			rcm_log_message(RCM_TRACE1, "IP: New: %s\n", syscmd);
			if (rcm_exec_cmd(syscmd) != 0) {
				rcm_log_message(RCM_ERROR,
				    _("IP: Error: %s (%s): %s\n"),
				    syscmd, ifinst, strerror(errno));
			}
			continue;
		}

		/* Parse the tokens to determine nature of the interface */
		for (n = 0; n < ntok; n++) {
			/* Handle pathological failover cases */
			if (STREQ("-failover", tokens[n]))
				nofailover++;
			if (STREQ("failover", tokens[n]))
				nofailover--;

			/* group attribute requires special processing */
			if (STREQ("group", tokens[n])) {
				if (tokens[n + 1] != NULL) {
					(void) snprintf(grpcmd, sizeof (grpcmd),
					    "%s %s %s %s %s", USR_SBIN_IFCONFIG,
					    ifinst, fstr,
					    tokens[n], tokens[n + 1]);
					n++;		/* skip next token */
					continue;
				}
			}

			/* Execute buffered command ? */
			if (STREQ("set", tokens[n]) ||
			    STREQ("addif", tokens[n]) ||
			    STREQ("removeif", tokens[n]) ||
			    (n == (ntok -1))) {

				/* config command complete ? */
				if (n == (ntok -1)) {
					ADDSPACE(syscmd);
					(void) strcat(syscmd, tokens[n]);
					cmdvalid++;
				}

				if (!cmdvalid) {
					ADDSPACE(syscmd);
					(void) strcat(syscmd, tokens[n]);
					cmdvalid++;
					continue;
				}
				/* Classic if ? */
				if ((af & CONFIG_AF_INET) && (stdif == 1)) {
					(void) strcat(syscmd, CFG_CMDS_STD);
				}

				if (nofailover > 0) {
					rcm_log_message(RCM_TRACE1,
					    "IP: Interim exec: %s\n", syscmd);
					if (rcm_exec_cmd(syscmd) != 0) {
						rcm_log_message(RCM_ERROR,
						    _("IP: %s fail(%s): %s\n"),
						    syscmd, ifinst,
						    strerror(errno));
					}
				} else {
					/* Have mpathd configure the address */
					if (if_mpathd_configure(syscmd, ifinst,
					    af, ipmp) != 0) {
						rcm_log_message(RCM_ERROR,
						    _("IP: %s fail(%s): %s\n"),
						    syscmd, ifinst,
						    strerror(errno));
					}
				}

				/* Reset config command */
				(void) snprintf(syscmd, sizeof (syscmd),
				    "%s %s %s ", USR_SBIN_IFCONFIG, ifinst,
				    fstr);
				nofailover = 0;
				cmdvalid = 0;
			}
			/*
			 * Note: No explicit command validation is required
			 *	since ifconfig to does it for us
			 */
			ADDSPACE(syscmd);
			(void) strcat(syscmd, tokens[n]);
			cmdvalid++;
		}
	}

	free(buf);
	(void) fclose(fp);

	/*
	 * The group name needs to be set after all the test/nofailover
	 * addresses have been configured. Otherwise, if IPMP detects that the
	 * interface is failed, the addresses will be moved to a working
	 * interface before the '-failover' flag can be set.
	 */
	if (grpcmd[0] != '\0') {
		rcm_log_message(RCM_TRACE1, "IP: set group name: %s\n", grpcmd);
		if (rcm_exec_cmd(grpcmd) != 0) {
			rcm_log_message(RCM_ERROR, _("IP: %s fail(%s): %s\n"),
			    grpcmd, ifinst, strerror(errno));
		}
	}

	rcm_log_message(RCM_TRACE1, "IP: if_ipmp_config(%s) success\n", ifinst);

	return (0);
}

/*
 * if_mpathd_configure() - Determine configuration disposition of the interface
 */
static int
if_mpathd_configure(char *syscmd, char *ifinst, int af, int ipmp)
{
	char *tokens[MAXARGS];
	char tspace[MAXLINE];
	int ntok;
	char *addr;
	char *from_lifname;
	mpathd_cmd_t mpdcmd;
	int n;

	rcm_log_message(RCM_TRACE1, "IP: if_mpathd_configure(%s): %s\n",
	    ifinst, syscmd);

	tokenize(syscmd, tokens, tspace, &ntok);
	if (ntok <= 0)
		return (0);

	addr = tokens[3];	/* by default, third token is valid address */
	for (n = 0; n < ntok; n++) {
		if (STREQ("set", tokens[n]) ||
		    STREQ("addif", tokens[n])) {
			addr = tokens[n+1];
			if (addr == NULL) {	/* invalid format */
				return (-1);
			} else
				break;
		}
	}

	/* Check std. commands or no failed over address */
	if (STREQ("removeif", addr) || STREQ("group", addr) ||
	    ((from_lifname = get_mpathd_dest(addr, af)) == NULL)) {
		rcm_log_message(RCM_TRACE1,
		    "IP: No failed-over host, exec %s\n", syscmd);
		if (rcm_exec_cmd(syscmd) != 0) {
			rcm_log_message(RCM_ERROR,
			    _("IP: %s failed(%s): %s\n"),
			    syscmd, ifinst, strerror(errno));
			return (-1);
		}
		return (0);
	}

	/* Check for non-IPMP failover scenarios */
	if ((ipmp <= 0) && (from_lifname != NULL)) {
		/* Address already hosted on another NIC, return */
		rcm_log_message(RCM_TRACE1,
		    "IP: Non-IPMP failed-over host(%s): %s\n",
		    ifinst, addr);
		return (0);
	}

	/*
	 * Valid failed-over host; have mpathd set the original index
	 */
	mpdcmd.cmd_command = MI_SETOINDEX;
	(void) strcpy(mpdcmd.from_lifname, from_lifname);
	(void) strcpy(mpdcmd.to_pifname, ifinst);
	if (af & CONFIG_AF_INET6) {
		mpdcmd.addr_family = AF_INET6;
	} else {
		mpdcmd.addr_family = AF_INET;
	}

	/* Send command to in.mpathd(1M) */
	rcm_log_message(RCM_TRACE1,
	    "IP: Attempting setoindex from (%s) to (%s) ....\n",
	    from_lifname, ifinst);

	if (mpathd_send_cmd(&mpdcmd) < 0) {
		rcm_log_message(RCM_TRACE1,
		    _("IP: mpathd set original index unsuccessful: %s\n"),
		    strerror(errno));
		return (-1);
	}

	rcm_log_message(RCM_TRACE1,
	    "IP: setoindex success (%s) to (%s)\n",
	    from_lifname, ifinst);

	return (0);
}

/*
 * get_mpathd_addr() - Return current destination for lif; caller is
 *		     responsible to free memory allocated for address
 */
static char *
get_mpathd_dest(char *addr, int family)
{
	int sock;
	char *buf;
	struct lifnum lifn;
	struct lifconf lifc;
	struct lifreq *lifrp;
	sa_family_t af = AF_INET;	/* IPv4 by default */
	int i;
	struct lifreq lifreq;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct hostent *hp;
	char *ifname = NULL;
	char *prefix = NULL;
	char addrstr[INET6_ADDRSTRLEN];
	char ifaddr[INET6_ADDRSTRLEN];
	int err;

	if (addr == NULL) {
		return (NULL);
	}

	rcm_log_message(RCM_TRACE2, "IP: get_mpathd_dest(%s)\n", addr);

	if (family & CONFIG_AF_INET6) {
		af = AF_INET6;
	} else {
		af = AF_INET;
	}

	if ((sock = socket(af, SOCK_DGRAM, 0)) == -1) {
		rcm_log_message(RCM_ERROR,
		    _("IP: failure opening %s socket: %s\n"),
		    af == AF_INET6 ? "IPv6" : "IPv4", strerror(errno));
		return (NULL);
	}

	lifn.lifn_family = af;
	lifn.lifn_flags = 0;
	if (ioctl(sock, SIOCGLIFNUM, (char *)&lifn) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: SIOCLGIFNUM failed: %s\n"),
		    strerror(errno));
		(void) close(sock);
		return (NULL);
	}

	if ((buf = calloc(lifn.lifn_count, sizeof (struct lifreq))) == NULL) {
		rcm_log_message(RCM_ERROR, _("IP: calloc: %s\n"),
		    strerror(errno));
		(void) close(sock);
		return (NULL);
	}

	lifc.lifc_family = af;
	lifc.lifc_flags = 0;
	lifc.lifc_len = sizeof (struct lifreq) * lifn.lifn_count;
	lifc.lifc_buf = buf;

	if (ioctl(sock, SIOCGLIFCONF, (char *)&lifc) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: SIOCGLIFCONF failed: %s\n"),
		    strerror(errno));
		free(buf);
		(void) close(sock);
		return (NULL);
	}

	/* Filter out prefix address from netmask */
	(void) strcpy(ifaddr, addr);
	if ((prefix = strchr(ifaddr, '/')) != NULL) {
		*prefix = '\0';	/* We care about the address part only */
	}

	/* Check for aliases */
	hp = getipnodebyname(ifaddr, af, AI_DEFAULT, &err);
	if (hp) {
		if (inet_ntop(af, (void *)hp->h_addr_list[0],
		    ifaddr, sizeof (ifaddr)) == NULL) {
			/* Restore original address and use it */
			(void) strcpy(ifaddr, addr);
			if ((prefix = strchr(ifaddr, '/')) != NULL) {
				*prefix = '\0';
			}
		}
		freehostent(hp);
	}
	rcm_log_message(RCM_TRACE2, "IP: ifaddr(%s) = %s\n", addr, ifaddr);

	/* now search the interfaces */
	lifrp = lifc.lifc_req;
	for (i = 0; i < lifn.lifn_count; i++, lifrp++) {
		(void) strcpy(lifreq.lifr_name, lifrp->lifr_name);
		/* Get the interface address for this interface */
		if (ioctl(sock, SIOCGLIFADDR, (char *)&lifreq) < 0) {
			rcm_log_message(RCM_ERROR,
			    _("IP: SIOCGLIFADDR: %s\n"), strerror(errno));
			free(buf);
			(void) close(sock);
			return (NULL);
		}

		if (af == AF_INET6) {
			sin6 = (struct sockaddr_in6 *)&lifreq.lifr_addr;
			if (inet_ntop(AF_INET6, (void *)&sin6->sin6_addr,
			    addrstr, sizeof (addrstr)) == NULL) {
				continue;
			}
		} else {
			sin = (struct sockaddr_in *)&lifreq.lifr_addr;
			if (inet_ntop(AF_INET, (void *)&sin->sin_addr,
			    addrstr, sizeof (addrstr)) == NULL) {
				continue;
			}
		}

		if (STREQ(addrstr, ifaddr)) {
			/* Allocate memory to hold interface name */
			if ((ifname = (char *)malloc(LIFNAMSIZ)) == NULL) {
				rcm_log_message(RCM_ERROR,
				    _("IP: malloc: %s\n"), strerror(errno));
				free(buf);
				(void) close(sock);
				return (NULL);
			}

			/* Copy the interface name */
			/*
			 * (void) memcpy(ifname, lifrp->lifr_name,
			 *  sizeof (ifname));
			 * ifname[sizeof (ifname) - 1] = '\0';
			 */
			(void) strcpy(ifname, lifrp->lifr_name);
			break;
		}
	}

	(void) close(sock);
	free(buf);

	if (ifname == NULL)
		rcm_log_message(RCM_TRACE2, "IP: get_mpathd_dest(%s): none\n",
		    addr);
	else
		rcm_log_message(RCM_TRACE2, "IP: get_mpathd_dest(%s): %s\n",
		    addr, ifname);

	return (ifname);
}

static int
if_getcount(int af)
{
	int sock;
	struct lifnum lifn;

	rcm_log_message(RCM_TRACE1, "IP: if_getcount\n");

	if ((sock = socket(af, SOCK_DGRAM, 0)) == -1) {
		rcm_log_message(RCM_ERROR,
		    _("IP: failure opening %s socket: %s\n"),
		    af == AF_INET6 ? "IPv6" : "IPv4", strerror(errno));
		return (-1);
	}

	lifn.lifn_family = af;
	lifn.lifn_flags = 0;
	if (ioctl(sock, SIOCGLIFNUM, (char *)&lifn) < 0) {
		rcm_log_message(RCM_ERROR,
		    _("IP: SIOCLGIFNUM failed: %s\n"),
		    strerror(errno));
		(void) close(sock);
		return (-1);
	}
	(void) close(sock);

	rcm_log_message(RCM_TRACE1, "IP: if_getcount success: %d\n",
	    lifn.lifn_count);

	return (lifn.lifn_count);
}

/*
 * tokenize() - turn a command line into tokens; caller is responsible to
 *	      provide enough memory to hold all tokens
 */
static void
tokenize(char *line, char **tokens, char *tspace, int *ntok)
{
	char *cp;
	char *sp;

	sp = tspace;
	cp = line;
	for (*ntok = 0; *ntok < MAXARGS; (*ntok)++) {
		tokens[*ntok] = sp;
		while (ISSPACE(*cp))
			cp++;
		if (ISEOL(*cp))
			break;
		do {
			*sp++ = *cp++;
		} while (!ISSPACE(*cp) && !ISEOL(*cp));

		*sp++ = '\0';
	}
}
