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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysevent/vrrp.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/varargs.h>
#include <auth_attr.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <zone.h>
#include <libsysevent.h>
#include <limits.h>
#include <locale.h>
#include <arpa/inet.h>
#include <signal.h>
#include <assert.h>
#include <ucred.h>
#include <bsm/adt.h>
#include <bsm/adt_event.h>
#include <priv_utils.h>
#include <libdllink.h>
#include <libdlvnic.h>
#include <libipadm.h>
#include <pwd.h>
#include <libvrrpadm.h>
#include <net/route.h>
#include "vrrpd_impl.h"

/*
 * A VRRP router can be only start participating the VRRP protocol of a virtual
 * router when all the following conditions are met:
 *
 * - The VRRP router is enabled (vr->vvr_conf.vvc_enabled is _B_TRUE)
 * - The RX socket is successfully created over the physical interface to
 *   receive the VRRP multicast advertisement. Note that one RX socket can
 *   be shared by several VRRP routers configured over the same physical
 *   interface. (See vrrpd_init_rxsock())
 * - The TX socket is successfully created over the VNIC interface to send
 *   the VRRP advertisment. (See vrrpd_init_txsock())
 * - The primary IP address has been successfully selected over the physical
 *   interface. (See vrrpd_select_primary())
 *
 * If a VRRP router is enabled but the other conditions haven't be satisfied,
 * the router will be stay at the VRRP_STATE_INIT state. If all the above
 * conditions are met, the VRRP router will be transit to either
 * the VRRP_STATE_MASTER or the VRRP_STATE_BACKUP state, depends on the VRRP
 * protocol.
 */

#define	skip_whitespace(p)	while (isspace(*(p))) ++(p)

#define	BUFFSIZE	65536

#define	VRRPCONF	"/etc/inet/vrrp.conf"

typedef struct vrrpd_rtsock_s {
	int		vrt_af;		/* address family */
	int		vrt_fd;		/* socket for the PF_ROUTE msg */
	iu_event_id_t	vrt_eid;	/* event ID */
} vrrpd_rtsock_t;

static ipadm_handle_t	vrrp_ipadm_handle = NULL;	/* libipadm handle */
static int		vrrp_logflag = 0;
boolean_t		vrrp_debug_level = 0;
iu_eh_t			*vrrpd_eh = NULL;
iu_tq_t			*vrrpd_timerq = NULL;
static vrrp_handle_t	vrrpd_vh = NULL;
static int		vrrpd_cmdsock_fd = -1;	/* socket to communicate */
						/* between vrrpd/libvrrpadm */
static iu_event_id_t	vrrpd_cmdsock_eid = -1;
static int		vrrpd_ctlsock_fd = -1;	/* socket to bring up/down */
						/* the virtual IP addresses */
static int		vrrpd_ctlsock6_fd = -1;
static vrrpd_rtsock_t	vrrpd_rtsocks[2] = {
	{AF_INET, -1, -1},
	{AF_INET6, -1, -1}
};
static iu_timer_id_t	vrrp_scan_timer_id = -1;

TAILQ_HEAD(vrrp_vr_list_s, vrrp_vr_s);
TAILQ_HEAD(vrrp_intf_list_s, vrrp_intf_s);
static struct vrrp_vr_list_s	vrrp_vr_list;
static struct vrrp_intf_list_s	vrrp_intf_list;
static char		vrrpd_conffile[MAXPATHLEN];

/*
 * Multicast address of VRRP advertisement in network byte order
 */
static vrrp_addr_t	vrrp_muladdr4;
static vrrp_addr_t	vrrp_muladdr6;

static int		vrrpd_scan_interval = 20000;	/* ms */
static int		pfds[2];

/*
 * macros to calculate skew_time and master_down_timer
 *
 * Note that the input is in centisecs and output are in msecs
 */
#define	SKEW_TIME(pri, intv)	((intv) * (256 - (pri)) / 256)
#define	MASTER_DOWN_INTERVAL(pri, intv)	(3 * (intv) + SKEW_TIME((pri), (intv)))

#define	SKEW_TIME_VR(vr)	\
	SKEW_TIME((vr)->vvr_conf.vvc_pri, (vr)->vvr_master_adver_int)
#define	MASTER_DOWN_INTERVAL_VR(vr)	\
	MASTER_DOWN_INTERVAL((vr)->vvr_conf.vvc_pri, (vr)->vvr_master_adver_int)

#define	VRRP_CONF_UPDATE	0x01
#define	VRRP_CONF_DELETE	0x02

static char *af_str(int);

static iu_tq_callback_t vrrp_adv_timeout;
static iu_tq_callback_t vrrp_b2m_timeout;
static iu_eh_callback_t vrrpd_sock_handler;
static iu_eh_callback_t vrrpd_rtsock_handler;
static iu_eh_callback_t vrrpd_cmdsock_handler;

static int daemon_init();

static vrrp_err_t vrrpd_init();
static void vrrpd_fini();
static vrrp_err_t vrrpd_cmdsock_create();
static void vrrpd_cmdsock_destroy();
static vrrp_err_t vrrpd_rtsock_create();
static void vrrpd_rtsock_destroy();
static vrrp_err_t vrrpd_ctlsock_create();
static void vrrpd_ctlsock_destroy();

static void vrrpd_scan_timer(iu_tq_t *, void *);
static void vrrpd_scan(int);
static vrrp_err_t vrrpd_init_rxsock(vrrp_vr_t *);
static void vrrpd_fini_rxsock(vrrp_vr_t *);
static vrrp_err_t vrrpd_init_txsock(vrrp_vr_t *);
static vrrp_err_t vrrpd_init_txsock_v4(vrrp_vr_t *);
static vrrp_err_t vrrpd_init_txsock_v6(vrrp_vr_t *);
static void vrrpd_fini_txsock(vrrp_vr_t *);

static vrrp_err_t vrrpd_create_vr(vrrp_vr_conf_t *);
static vrrp_err_t vrrpd_enable_vr(vrrp_vr_t *);
static void vrrpd_disable_vr(vrrp_vr_t *, vrrp_intf_t *, boolean_t);
static void vrrpd_delete_vr(vrrp_vr_t *);

static vrrp_err_t vrrpd_create(vrrp_vr_conf_t *, boolean_t);
static vrrp_err_t vrrpd_delete(const char *);
static vrrp_err_t vrrpd_enable(const char *, boolean_t);
static vrrp_err_t vrrpd_disable(const char *);
static vrrp_err_t vrrpd_modify(vrrp_vr_conf_t *, uint32_t);
static void vrrpd_list(vrid_t, char *, int, vrrp_ret_list_t *, size_t *);
static void vrrpd_query(const char *, vrrp_ret_query_t *, size_t *);

static boolean_t vrrp_rd_prop_name(vrrp_vr_conf_t *, const char *);
static boolean_t vrrp_rd_prop_vrid(vrrp_vr_conf_t *, const char *);
static boolean_t vrrp_rd_prop_af(vrrp_vr_conf_t *, const char *);
static boolean_t vrrp_rd_prop_pri(vrrp_vr_conf_t *, const char *);
static boolean_t vrrp_rd_prop_adver_int(vrrp_vr_conf_t *, const char *);
static boolean_t vrrp_rd_prop_preempt(vrrp_vr_conf_t *, const char *);
static boolean_t vrrp_rd_prop_accept(vrrp_vr_conf_t *, const char *);
static boolean_t vrrp_rd_prop_ifname(vrrp_vr_conf_t *, const char *);
static boolean_t vrrp_rd_prop_enabled(vrrp_vr_conf_t *, const char *);
static int vrrp_wt_prop_name(vrrp_vr_conf_t *, char *, size_t);
static int vrrp_wt_prop_vrid(vrrp_vr_conf_t *, char *, size_t);
static int vrrp_wt_prop_af(vrrp_vr_conf_t *, char *, size_t);
static int vrrp_wt_prop_pri(vrrp_vr_conf_t *, char *, size_t);
static int vrrp_wt_prop_adver_int(vrrp_vr_conf_t *, char *, size_t);
static int vrrp_wt_prop_preempt(vrrp_vr_conf_t *, char *, size_t);
static int vrrp_wt_prop_accept(vrrp_vr_conf_t *, char *, size_t);
static int vrrp_wt_prop_ifname(vrrp_vr_conf_t *, char *, size_t);
static int vrrp_wt_prop_enabled(vrrp_vr_conf_t *, char *, size_t);

static void vrrpd_cmd_create(void *, void *, size_t *);
static void vrrpd_cmd_delete(void *, void *, size_t *);
static void vrrpd_cmd_enable(void *, void *, size_t *);
static void vrrpd_cmd_disable(void *, void *, size_t *);
static void vrrpd_cmd_modify(void *, void *, size_t *);
static void vrrpd_cmd_list(void *, void *, size_t *);
static void vrrpd_cmd_query(void *, void *, size_t *);

static vrrp_vr_t *vrrpd_lookup_vr_by_vrid(char *, vrid_t vrid_t, int);
static vrrp_vr_t *vrrpd_lookup_vr_by_name(const char *);
static vrrp_intf_t *vrrpd_lookup_if(const char *, int);
static vrrp_err_t vrrpd_create_if(const char *, int, uint32_t, vrrp_intf_t **);
static void vrrpd_delete_if(vrrp_intf_t *, boolean_t);
static vrrp_err_t vrrpd_create_ip(vrrp_intf_t *, const char *, vrrp_addr_t *,
    uint64_t flags);
static void vrrpd_delete_ip(vrrp_intf_t *, vrrp_ip_t *);

static void vrrpd_init_ipcache(int);
static void vrrpd_update_ipcache(int);
static ipadm_status_t vrrpd_walk_addr_info(int);
static vrrp_err_t vrrpd_add_ipaddr(char *, int, vrrp_addr_t *,
    int, uint64_t);
static vrrp_ip_t *vrrpd_select_primary(vrrp_intf_t *);
static void vrrpd_reselect_primary(vrrp_intf_t *);
static void vrrpd_reenable_all_vr();
static void vrrpd_remove_if(vrrp_intf_t *, boolean_t);

static uint16_t in_cksum(int, uint16_t, void *);
static uint16_t vrrp_cksum4(struct in_addr *, struct in_addr *,
    uint16_t, vrrp_pkt_t *);
static uint16_t vrrp_cksum6(struct in6_addr *, struct in6_addr *,
    uint16_t, vrrp_pkt_t *);
static size_t vrrpd_build_vrrp(vrrp_vr_t *, uchar_t *, int, boolean_t);

static void vrrpd_process_adv(vrrp_vr_t *, vrrp_addr_t *, vrrp_pkt_t *);
static vrrp_err_t vrrpd_send_adv(vrrp_vr_t *, boolean_t);

/* state transition functions */
static vrrp_err_t vrrpd_state_i2m(vrrp_vr_t *);
static vrrp_err_t vrrpd_state_i2b(vrrp_vr_t *);
static void vrrpd_state_m2i(vrrp_vr_t *);
static void vrrpd_state_b2i(vrrp_vr_t *);
static vrrp_err_t vrrpd_state_b2m(vrrp_vr_t *);
static vrrp_err_t vrrpd_state_m2b(vrrp_vr_t *);
static void vrrpd_state_trans(vrrp_state_t, vrrp_state_t, vrrp_vr_t *);

static vrrp_err_t vrrpd_set_noaccept(vrrp_vr_t *, boolean_t);
static vrrp_err_t vrrpd_virtualip_update(vrrp_vr_t *, boolean_t);
static vrrp_err_t vrrpd_virtualip_updateone(vrrp_intf_t *, vrrp_ip_t *,
    boolean_t);
static int vrrpd_post_event(const char *, vrrp_state_t, vrrp_state_t);

static void vrrpd_initconf();
static vrrp_err_t vrrpd_updateconf(vrrp_vr_conf_t *, uint_t);
static vrrp_err_t vrrpd_write_vrconf(char *, size_t, vrrp_vr_conf_t *);
static vrrp_err_t vrrpd_read_vrconf(char *, vrrp_vr_conf_t *);
static vrrp_err_t vrrpd_readprop(const char *, vrrp_vr_conf_t *);
static void vrrpd_cleanup();

static void vrrp_log(int, char *, ...);
static int timeval_to_milli(struct timeval);
static struct timeval timeval_delta(struct timeval, struct timeval);

typedef struct vrrpd_prop_s {
	char		*vs_propname;
	boolean_t	(*vs_propread)(vrrp_vr_conf_t *, const char *);
	int		(*vs_propwrite)(vrrp_vr_conf_t *, char *, size_t);
} vrrp_prop_t;

/*
 * persistent VRRP properties array
 */
static vrrp_prop_t vrrp_prop_info_tbl[] = {
	{"name", vrrp_rd_prop_name, vrrp_wt_prop_name},
	{"vrid", vrrp_rd_prop_vrid, vrrp_wt_prop_vrid},
	{"priority", vrrp_rd_prop_pri, vrrp_wt_prop_pri},
	{"adv_intval", vrrp_rd_prop_adver_int, vrrp_wt_prop_adver_int},
	{"preempt_mode", vrrp_rd_prop_preempt, vrrp_wt_prop_preempt},
	{"accept_mode", vrrp_rd_prop_accept, vrrp_wt_prop_accept},
	{"interface", vrrp_rd_prop_ifname, vrrp_wt_prop_ifname},
	{"af", vrrp_rd_prop_af, vrrp_wt_prop_af},
	{"enabled", vrrp_rd_prop_enabled, vrrp_wt_prop_enabled}
};

#define	VRRP_PROP_INFO_TABSIZE	\
	(sizeof (vrrp_prop_info_tbl) / sizeof (vrrp_prop_t))

typedef void vrrp_cmd_func_t(void *, void *, size_t *);

typedef struct vrrp_cmd_info_s {
	vrrp_cmd_type_t	vi_cmd;
	size_t		vi_reqsize;
	size_t		vi_acksize;	/* 0 if the size is variable */
	boolean_t	vi_setop;	/* Set operation? Check credentials */
	vrrp_cmd_func_t	*vi_cmdfunc;
} vrrp_cmd_info_t;

static vrrp_cmd_info_t vrrp_cmd_info_tbl[] = {
	{VRRP_CMD_CREATE, sizeof (vrrp_cmd_create_t),
	    sizeof (vrrp_ret_create_t), _B_TRUE, vrrpd_cmd_create},
	{VRRP_CMD_DELETE, sizeof (vrrp_cmd_delete_t),
	    sizeof (vrrp_ret_delete_t), _B_TRUE, vrrpd_cmd_delete},
	{VRRP_CMD_ENABLE, sizeof (vrrp_cmd_enable_t),
	    sizeof (vrrp_ret_enable_t), _B_TRUE, vrrpd_cmd_enable},
	{VRRP_CMD_DISABLE, sizeof (vrrp_cmd_disable_t),
	    sizeof (vrrp_ret_disable_t), _B_TRUE, vrrpd_cmd_disable},
	{VRRP_CMD_MODIFY, sizeof (vrrp_cmd_modify_t),
	    sizeof (vrrp_ret_modify_t), _B_TRUE, vrrpd_cmd_modify},
	{VRRP_CMD_QUERY, sizeof (vrrp_cmd_query_t), 0,
	    _B_FALSE, vrrpd_cmd_query},
	{VRRP_CMD_LIST, sizeof (vrrp_cmd_list_t), 0,
	    _B_FALSE, vrrpd_cmd_list}
};

#define	VRRP_DOOR_INFO_TABLE_SIZE	\
	(sizeof (vrrp_cmd_info_tbl) / sizeof (vrrp_cmd_info_t))

static int
ipaddr_cmp(int af, vrrp_addr_t *addr1, vrrp_addr_t *addr2)
{
	if (af == AF_INET) {
		return (memcmp(&addr1->in4.sin_addr,
		    &addr2->in4.sin_addr, sizeof (struct in_addr)));
	} else {
		return (memcmp(&addr1->in6.sin6_addr,
		    &addr2->in6.sin6_addr, sizeof (struct in6_addr)));
	}
}

static vrrp_vr_t *
vrrpd_lookup_vr_by_vrid(char *ifname, vrid_t vrid, int af)
{
	vrrp_vr_t *vr;

	TAILQ_FOREACH(vr, &vrrp_vr_list, vvr_next) {
		if (strcmp(vr->vvr_conf.vvc_link, ifname) == 0 &&
		    vr->vvr_conf.vvc_vrid == vrid &&
		    vr->vvr_conf.vvc_af == af) {
			break;
		}
	}
	return (vr);
}

static vrrp_vr_t *
vrrpd_lookup_vr_by_name(const char *name)
{
	vrrp_vr_t *vr;

	TAILQ_FOREACH(vr, &vrrp_vr_list, vvr_next) {
		if (strcmp(vr->vvr_conf.vvc_name, name) == 0)
			break;
	}
	return (vr);
}

static vrrp_intf_t *
vrrpd_lookup_if(const char *ifname, int af)
{
	vrrp_intf_t	*intf;

	TAILQ_FOREACH(intf, &vrrp_intf_list, vvi_next) {
		if (strcmp(ifname, intf->vvi_ifname) == 0 &&
		    af == intf->vvi_af) {
			break;
		}
	}
	return (intf);
}

static vrrp_err_t
vrrpd_create_if(const char *ifname, int af, uint32_t ifindex,
    vrrp_intf_t **intfp)
{
	vrrp_intf_t	*intf;

	vrrp_log(VRRP_DBG0, "vrrpd_create_if(%s, %s, %d)",
	    ifname, af_str(af), ifindex);

	if (((*intfp) = malloc(sizeof (vrrp_intf_t))) == NULL) {
		vrrp_log(VRRP_ERR, "vrrpd_create_if(): failed to "
		    "allocate %s/%s interface", ifname, af_str(af));
		return (VRRP_ENOMEM);
	}

	intf = *intfp;
	TAILQ_INIT(&intf->vvi_iplist);
	(void) strlcpy(intf->vvi_ifname, ifname, sizeof (intf->vvi_ifname));
	intf->vvi_af = af;
	intf->vvi_sockfd = -1;
	intf->vvi_nvr = 0;
	intf->vvi_eid = -1;
	intf->vvi_pip = NULL;
	intf->vvi_ifindex = ifindex;
	intf->vvi_state = NODE_STATE_NEW;
	intf->vvi_vr_state = VRRP_STATE_INIT;
	TAILQ_INSERT_TAIL(&vrrp_intf_list, intf, vvi_next);
	return (VRRP_SUCCESS);
}

/*
 * An interface is deleted. If update_vr is true, the deletion of the interface
 * may cause the state transition of assoicated VRRP router (if this interface
 * is either the primary or the VNIC interface of the VRRP router); otherwise,
 * simply delete the interface without updating the VRRP router.
 */
static void
vrrpd_delete_if(vrrp_intf_t *intf, boolean_t update_vr)
{
	vrrp_ip_t	*ip;

	vrrp_log(VRRP_DBG0, "vrrpd_delete_if(%s, %s, %supdate_vr)",
	    intf->vvi_ifname, af_str(intf->vvi_af), update_vr ? "" : "no_");

	if (update_vr) {
		/*
		 * If a this interface is the physical interface or the VNIC
		 * of a VRRP router, the deletion of the interface (no IP
		 * address exists on this interface) may cause the state
		 * transition of the VRRP router. call vrrpd_remove_if()
		 * to find all corresponding VRRP router and update their
		 * states.
		 */
		vrrpd_remove_if(intf, _B_FALSE);
	}

	/*
	 * First remove and delete all the IP addresses on the interface
	 */
	while (!TAILQ_EMPTY(&intf->vvi_iplist)) {
		ip = TAILQ_FIRST(&intf->vvi_iplist);
		vrrpd_delete_ip(intf, ip);
	}

	/*
	 * Then remove and delete the interface
	 */
	TAILQ_REMOVE(&vrrp_intf_list, intf, vvi_next);
	(void) free(intf);
}

static vrrp_err_t
vrrpd_create_ip(vrrp_intf_t *intf, const char *lifname, vrrp_addr_t *addr,
    uint64_t flags)
{
	vrrp_ip_t	*ip;
	char		abuf[INET6_ADDRSTRLEN];

	/* LINTED E_CONSTANT_CONDITION */
	VRRPADDR2STR(intf->vvi_af, addr, abuf, INET6_ADDRSTRLEN, _B_FALSE);
	vrrp_log(VRRP_DBG0, "vrrpd_create_ip(%s, %s, %s, 0x%x)",
	    intf->vvi_ifname, lifname, abuf, flags);

	if ((ip = malloc(sizeof (vrrp_ip_t))) == NULL) {
		vrrp_log(VRRP_ERR, "vrrpd_create_ip(%s, %s):"
		    "failed to allocate IP", lifname, abuf);
		return (VRRP_ENOMEM);
	}

	(void) strncpy(ip->vip_lifname, lifname, sizeof (ip->vip_lifname));
	ip->vip_state = NODE_STATE_NEW;
	ip->vip_flags = flags;
	(void) memcpy(&ip->vip_addr, addr, sizeof (ip->vip_addr));

	/*
	 * Make sure link-local IPv6 IP addresses are at the head of the list
	 */
	if (intf->vvi_af == AF_INET6 &&
	    IN6_IS_ADDR_LINKLOCAL(&addr->in6.sin6_addr)) {
		TAILQ_INSERT_HEAD(&intf->vvi_iplist, ip, vip_next);
	} else {
		TAILQ_INSERT_TAIL(&intf->vvi_iplist, ip, vip_next);
	}
	return (VRRP_SUCCESS);
}

static void
vrrpd_delete_ip(vrrp_intf_t *intf, vrrp_ip_t *ip)
{
	char	abuf[INET6_ADDRSTRLEN];
	int	af = intf->vvi_af;

	/* LINTED E_CONSTANT_CONDITION */
	VRRPADDR2STR(af, &ip->vip_addr, abuf, sizeof (abuf), _B_FALSE);
	vrrp_log(VRRP_DBG0, "vrrpd_delete_ip(%s, %s, %s) is %sprimary",
	    intf->vvi_ifname, ip->vip_lifname, abuf,
	    intf->vvi_pip == ip ? "" : "not ");

	if (intf->vvi_pip == ip)
		intf->vvi_pip = NULL;

	TAILQ_REMOVE(&intf->vvi_iplist, ip, vip_next);
	(void) free(ip);
}

static char *
rtm_event2str(uchar_t event)
{
	switch (event) {
	case RTM_NEWADDR:
		return ("RTM_NEWADDR");
	case RTM_DELADDR:
		return ("RTM_DELADDR");
	case RTM_IFINFO:
		return ("RTM_IFINFO");
	case RTM_ADD:
		return ("RTM_ADD");
	case RTM_DELETE:
		return ("RTM_DELETE");
	case RTM_CHANGE:
		return ("RTM_CHANGE");
	case RTM_OLDADD:
		return ("RTM_OLDADD");
	case RTM_OLDDEL:
		return ("RTM_OLDDEL");
	case RTM_CHGADDR:
		return ("RTM_CHGADDR");
	case RTM_FREEADDR:
		return ("RTM_FREEADDR");
	default:
		return ("RTM_OTHER");
	}
}

/*
 * This is called by the child process to inform the parent process to
 * exit with the given return value. Note that the child process
 * (the daemon process) informs the parent process to exit when anything
 * goes wrong or when all the intialization is done.
 */
static int
vrrpd_inform_parent_exit(int rv)
{
	int err = 0;

	/*
	 * If vrrp_debug_level is none-zero, vrrpd is not running as
	 * a daemon. Return directly.
	 */
	if (vrrp_debug_level != 0)
		return (0);

	if (write(pfds[1], &rv, sizeof (int)) != sizeof (int)) {
		err = errno;
		(void) close(pfds[1]);
		return (err);
	}
	(void) close(pfds[1]);
	return (0);
}

int
main(int argc, char *argv[])
{
	int c, err;
	struct sigaction sa;
	sigset_t mask;
	struct rlimit rl;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * We need PRIV_SYS_CONFIG to post VRRP sysevent, PRIV_NET_RAWACESS
	 * and PRIV_NET_ICMPACCESS to open  the raw socket, PRIV_SYS_IP_CONFIG
	 * to bring up/down the virtual IP addresses, and PRIV_SYS_RESOURCE to
	 * setrlimit().
	 *
	 * Note that sysevent is not supported in non-global zones.
	 */
	if (getzoneid() == GLOBAL_ZONEID) {
		err = __init_daemon_priv(PU_RESETGROUPS|PU_CLEARLIMITSET, 0, 0,
		    PRIV_SYS_CONFIG, PRIV_NET_RAWACCESS, PRIV_NET_ICMPACCESS,
		    PRIV_SYS_IP_CONFIG, PRIV_SYS_RESOURCE, NULL);
	} else {
		err = __init_daemon_priv(PU_RESETGROUPS|PU_CLEARLIMITSET, 0, 0,
		    PRIV_NET_RAWACCESS, PRIV_NET_ICMPACCESS,
		    PRIV_SYS_IP_CONFIG, PRIV_SYS_RESOURCE, NULL);
	}

	if (err == -1) {
		vrrp_log(VRRP_ERR, "main(): init_daemon_priv() failed");
		return (EXIT_FAILURE);
	}

	/*
	 * If vrrpd is started by other process, it will inherit the
	 * signal block mask. We unblock all signals to make sure the
	 * signal handling will work normally.
	 */
	(void) sigfillset(&mask);
	(void) thr_sigsetmask(SIG_UNBLOCK, &mask, NULL);
	sa.sa_handler = vrrpd_cleanup;
	sa.sa_flags = 0;
	(void) sigemptyset(&sa.sa_mask);
	(void) sigaction(SIGINT, &sa, NULL);
	(void) sigaction(SIGQUIT, &sa, NULL);
	(void) sigaction(SIGTERM, &sa, NULL);

	vrrp_debug_level = 0;
	(void) strlcpy(vrrpd_conffile, VRRPCONF, sizeof (vrrpd_conffile));
	while ((c = getopt(argc, argv, "d:f:")) != EOF) {
		switch (c) {
		case 'd':
			vrrp_debug_level = atoi(optarg);
			break;
		case 'f':
			(void) strlcpy(vrrpd_conffile, optarg,
			    sizeof (vrrpd_conffile));
			break;
		default:
			break;
		}
	}

	closefrom(3);
	if (vrrp_debug_level == 0 && (daemon_init() != 0)) {
		vrrp_log(VRRP_ERR, "main(): daemon_init() failed");
		return (EXIT_FAILURE);
	}

	rl.rlim_cur = RLIM_INFINITY;
	rl.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
		vrrp_log(VRRP_ERR, "main(): setrlimit() failed");
		goto child_out;
	}

	if (vrrpd_init() != VRRP_SUCCESS) {
		vrrp_log(VRRP_ERR, "main(): vrrpd_init() failed");
		goto child_out;
	}

	/*
	 * Get rid of unneeded privileges.
	 */
	__fini_daemon_priv(PRIV_PROC_FORK, PRIV_PROC_EXEC, PRIV_PROC_SESSION,
	    PRIV_FILE_LINK_ANY, PRIV_PROC_INFO, PRIV_SYS_RESOURCE, NULL);

	/*
	 * Read the configuration and initialize the existing VRRP
	 * configuration
	 */
	vrrpd_initconf();

	/*
	 * Inform the parent process that it can successfully exit.
	 */
	if ((err = vrrpd_inform_parent_exit(EXIT_SUCCESS)) != 0) {
		vrrpd_cleanup();
		vrrp_log(VRRP_WARNING, "vrrpd_inform_parent_exit() failed: %s",
		    strerror(err));
		return (EXIT_FAILURE);
	}

	/*
	 * Start the loop to handle the timer and the IO events.
	 */
	switch (iu_handle_events(vrrpd_eh, vrrpd_timerq)) {
	case -1:
		vrrp_log(VRRP_ERR, "main(): iu_handle_events() failed "
		    "abnormally");
		break;
	default:
		break;
	}

	vrrpd_cleanup();
	return (EXIT_SUCCESS);

child_out:
	(void) vrrpd_inform_parent_exit(EXIT_FAILURE);
	return (EXIT_FAILURE);
}

static int
daemon_init()
{
	pid_t	pid;
	int	rv;

	vrrp_log(VRRP_DBG0, "daemon_init()");

	if (getenv("SMF_FMRI") == NULL) {
		vrrp_log(VRRP_ERR, "daemon_init(): vrrpd is an smf(5) managed "
		    "service and should not be run from the command line.");
		return (-1);
	}

	/*
	 * Create the pipe used for the child process to inform the parent
	 * process to exit after all initialization is done.
	 */
	if (pipe(pfds) < 0) {
		vrrp_log(VRRP_ERR, "daemon_init(): pipe() failed: %s",
		    strerror(errno));
		return (-1);
	}

	if ((pid = fork()) < 0) {
		vrrp_log(VRRP_ERR, "daemon_init(): fork() failed: %s",
		    strerror(errno));
		(void) close(pfds[0]);
		(void) close(pfds[1]);
		return (-1);
	}

	if (pid != 0) { /* Parent */
		(void) close(pfds[1]);

		/*
		 * Read the child process's return value from the pfds.
		 * If the child process exits unexpectedly, read() returns -1.
		 */
		if (read(pfds[0], &rv, sizeof (int)) != sizeof (int)) {
			vrrp_log(VRRP_ERR, "daemon_init(): child process "
			    "exited unexpectedly %s", strerror(errno));
			(void) kill(pid, SIGTERM);
			rv = EXIT_FAILURE;
		}
		(void) close(pfds[0]);
		exit(rv);
	}

	/*
	 * in child process, became a daemon, and return to main() to continue.
	 */
	(void) close(pfds[0]);
	(void) chdir("/");
	(void) setsid();
	(void) close(0);
	(void) close(1);
	(void) close(2);
	(void) open("/dev/null", O_RDWR, 0);
	(void) dup2(0, 1);
	(void) dup2(0, 2);
	openlog("vrrpd", LOG_PID, LOG_DAEMON);
	vrrp_logflag = 1;
	return (0);
}

static vrrp_err_t
vrrpd_init()
{
	vrrp_err_t	err = VRRP_ESYS;

	vrrp_log(VRRP_DBG0, "vrrpd_init()");

	TAILQ_INIT(&vrrp_vr_list);
	TAILQ_INIT(&vrrp_intf_list);

	if (vrrp_open(&vrrpd_vh) != VRRP_SUCCESS) {
		vrrp_log(VRRP_ERR, "vrrpd_init(): vrrp_open() failed");
		goto fail;
	}

	if ((vrrpd_timerq = iu_tq_create()) == NULL) {
		vrrp_log(VRRP_ERR, "vrrpd_init(): iu_tq_create() failed");
		goto fail;
	}

	if ((vrrpd_eh = iu_eh_create()) == NULL) {
		vrrp_log(VRRP_ERR, "vrrpd_init(): iu_eh_create() failed");
		goto fail;
	}

	/*
	 * Create the AF_UNIX socket used to communicate with libvrrpadm.
	 *
	 * This socket is used to receive the administrative requests and
	 * send back the results.
	 */
	if (vrrpd_cmdsock_create() != VRRP_SUCCESS) {
		vrrp_log(VRRP_ERR, "vrrpd_init(): vrrpd_cmdsock_create() "
		    "failed");
		goto fail;
	}

	/*
	 * Create the VRRP control socket used to bring up/down the virtual
	 * IP addresses. It is also used to set the IFF_NOACCEPT flag of
	 * the virtual IP addresses.
	 */
	if (vrrpd_ctlsock_create() != VRRP_SUCCESS) {
		vrrp_log(VRRP_ERR, "vrrpd_init(): vrrpd_ctlsock_create() "
		    "failed");
		goto fail;
	}

	/*
	 * Create the PF_ROUTER socket used to listen to the routing socket
	 * messages and build the interface/IP address list.
	 */
	if (vrrpd_rtsock_create() != VRRP_SUCCESS) {
		vrrp_log(VRRP_ERR, "vrrpd_init(): vrrpd_rtsock_create() "
		    "failed");
		goto fail;
	}

	/* Open the libipadm handle */
	if (ipadm_open(&vrrp_ipadm_handle, 0) != IPADM_SUCCESS) {
		vrrp_log(VRRP_ERR, "vrrpd_init(): ipadm_open() failed");
		goto fail;
	}

	/*
	 * Build the list of interfaces and IP addresses. Also, start the time
	 * to scan the interfaces/IP addresses periodically.
	 */
	vrrpd_scan(AF_INET);
	vrrpd_scan(AF_INET6);
	if ((vrrp_scan_timer_id = iu_schedule_timer_ms(vrrpd_timerq,
	    vrrpd_scan_interval, vrrpd_scan_timer, NULL)) == -1) {
		vrrp_log(VRRP_ERR, "vrrpd_init(): start scan_timer failed");
		goto fail;
	}

	/*
	 * Initialize the VRRP multicast address.
	 */
	bzero(&vrrp_muladdr4, sizeof (vrrp_addr_t));
	vrrp_muladdr4.in4.sin_family = AF_INET;
	(void) inet_pton(AF_INET, "224.0.0.18", &vrrp_muladdr4.in4.sin_addr);

	bzero(&vrrp_muladdr6, sizeof (vrrp_addr_t));
	vrrp_muladdr6.in6.sin6_family = AF_INET6;
	(void) inet_pton(AF_INET6, "ff02::12", &vrrp_muladdr6.in6.sin6_addr);

	return (VRRP_SUCCESS);

fail:
	vrrpd_fini();
	return (err);
}

static void
vrrpd_fini()
{
	vrrp_log(VRRP_DBG0, "vrrpd_fini()");

	(void) iu_cancel_timer(vrrpd_timerq, vrrp_scan_timer_id, NULL);
	vrrp_scan_timer_id = -1;

	vrrpd_rtsock_destroy();
	vrrpd_ctlsock_destroy();
	vrrpd_cmdsock_destroy();

	if (vrrpd_eh != NULL) {
		iu_eh_destroy(vrrpd_eh);
		vrrpd_eh = NULL;
	}

	if (vrrpd_timerq != NULL) {
		iu_tq_destroy(vrrpd_timerq);
		vrrpd_timerq = NULL;
	}

	vrrp_close(vrrpd_vh);
	vrrpd_vh = NULL;
	assert(TAILQ_EMPTY(&vrrp_vr_list));
	assert(TAILQ_EMPTY(&vrrp_intf_list));

	ipadm_close(vrrp_ipadm_handle);
}

static void
vrrpd_cleanup(void)
{
	vrrp_vr_t	*vr;
	vrrp_intf_t	*intf;

	vrrp_log(VRRP_DBG0, "vrrpd_cleanup()");

	while (!TAILQ_EMPTY(&vrrp_vr_list)) {
		vr = TAILQ_FIRST(&vrrp_vr_list);
		vrrpd_delete_vr(vr);
	}

	while (!TAILQ_EMPTY(&vrrp_intf_list)) {
		intf = TAILQ_FIRST(&vrrp_intf_list);
		vrrpd_delete_if(intf, _B_FALSE);
	}

	vrrpd_fini();
	closelog();
	exit(1);
}

/*
 * Read the configuration file and initialize all the existing VRRP routers.
 */
static void
vrrpd_initconf()
{
	FILE *fp;
	char line[LINE_MAX];
	int linenum = 0;
	vrrp_vr_conf_t conf;
	vrrp_err_t err;

	vrrp_log(VRRP_DBG0, "vrrpd_initconf()");

	if ((fp = fopen(vrrpd_conffile, "rF")) == NULL) {
		vrrp_log(VRRP_ERR, "failed to open the configuration file %s",
		    vrrpd_conffile);
		return;
	}

	while (fgets(line, sizeof (line), fp) != NULL) {
		linenum++;
		conf.vvc_vrid = VRRP_VRID_NONE;
		if ((err = vrrpd_read_vrconf(line, &conf)) != VRRP_SUCCESS) {
			vrrp_log(VRRP_ERR, "failed to parse %d line %s",
			    linenum, line);
			continue;
		}

		/*
		 * Blank or comment line
		 */
		if (conf.vvc_vrid == VRRP_VRID_NONE)
			continue;

		/*
		 * No need to update the configuration since the VRRP router
		 * created/enabled based on the existing configuration.
		 */
		if ((err = vrrpd_create(&conf, _B_FALSE)) != VRRP_SUCCESS) {
			vrrp_log(VRRP_ERR, "VRRP router %s creation failed: "
			    "%s", conf.vvc_name, vrrp_err2str(err));
			continue;
		}

		if (conf.vvc_enabled &&
		    ((err = vrrpd_enable(conf.vvc_name, _B_FALSE)) !=
		    VRRP_SUCCESS)) {
			vrrp_log(VRRP_ERR, "VRRP router %s enable failed: %s",
			    conf.vvc_name, vrrp_err2str(err));
		}
	}

	(void) fclose(fp);
}

/*
 * Create the AF_UNIX socket used to communicate with libvrrpadm.
 *
 * This socket is used to receive the administrative request and
 * send back the results.
 */
static vrrp_err_t
vrrpd_cmdsock_create()
{
	iu_event_id_t		eid;
	struct sockaddr_un	laddr;
	int			sock, flags;

	vrrp_log(VRRP_DBG0, "vrrpd_cmdsock_create()");

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		vrrp_log(VRRP_ERR, "vrrpd_cmdsock_create(): socket(AF_UNIX) "
		    "failed: %s", strerror(errno));
		return (VRRP_ESYS);
	}

	/*
	 * Set it to be non-blocking.
	 */
	flags = fcntl(sock, F_GETFL, 0);
	(void) fcntl(sock, F_SETFL, (flags | O_NONBLOCK));

	/*
	 * Unlink first in case a previous daemon instance exited ungracefully.
	 */
	(void) unlink(VRRPD_SOCKET);

	bzero(&laddr, sizeof (laddr));
	laddr.sun_family = AF_UNIX;
	(void) strlcpy(laddr.sun_path, VRRPD_SOCKET, sizeof (laddr.sun_path));
	if (bind(sock, (struct sockaddr *)&laddr, sizeof (laddr)) < 0) {
		vrrp_log(VRRP_ERR, "vrrpd_cmdsock_create(): bind() failed: %s",
		    strerror(errno));
		(void) close(sock);
		return (VRRP_ESYS);
	}

	if (listen(sock, 30) < 0) {
		vrrp_log(VRRP_ERR, "vrrpd_cmdsock_create(): listen() "
		    "failed: %s", strerror(errno));
		(void) close(sock);
		return (VRRP_ESYS);
	}

	if ((eid = iu_register_event(vrrpd_eh, sock, POLLIN,
	    vrrpd_cmdsock_handler, NULL)) == -1) {
		vrrp_log(VRRP_ERR, "vrrpd_cmdsock_create(): iu_register_event()"
		    " failed");
		(void) close(sock);
		return (VRRP_ESYS);
	}

	vrrpd_cmdsock_fd = sock;
	vrrpd_cmdsock_eid = eid;
	return (VRRP_SUCCESS);
}

static void
vrrpd_cmdsock_destroy()
{
	vrrp_log(VRRP_DBG0, "vrrpd_cmdsock_destroy()");

	(void) iu_unregister_event(vrrpd_eh, vrrpd_cmdsock_eid, NULL);
	(void) close(vrrpd_cmdsock_fd);
	vrrpd_cmdsock_fd = -1;
	vrrpd_cmdsock_eid = -1;
}

/*
 * Create the PF_ROUTER sockets used to listen to the routing socket
 * messages and build the interface/IP address list. Create one for
 * each address family (IPv4 and IPv6).
 */
static vrrp_err_t
vrrpd_rtsock_create()
{
	int		i, flags, sock;
	iu_event_id_t	eid;

	vrrp_log(VRRP_DBG0, "vrrpd_rtsock_create()");

	for (i = 0; i < 2; i++) {
		sock = socket(PF_ROUTE, SOCK_RAW, vrrpd_rtsocks[i].vrt_af);
		if (sock == -1) {
			vrrp_log(VRRP_ERR, "vrrpd_rtsock_create(): socket() "
			    "failed: %s", strerror(errno));
			break;
		}

		/*
		 * Set it to be non-blocking.
		 */
		if ((flags = fcntl(sock, F_GETFL, 0)) < 0) {
			vrrp_log(VRRP_ERR, "vrrpd_rtsock_create(): "
			    "fcntl(F_GETFL) failed: %s", strerror(errno));
			break;
		}

		if ((fcntl(sock, F_SETFL, flags | O_NONBLOCK)) < 0) {
			vrrp_log(VRRP_ERR, "vrrpd_rtsock_create(): "
			    "fcntl(F_SETFL) failed: %s", strerror(errno));
			break;
		}

		if ((eid = iu_register_event(vrrpd_eh, sock, POLLIN,
		    vrrpd_rtsock_handler, &(vrrpd_rtsocks[i].vrt_af))) == -1) {
			vrrp_log(VRRP_ERR, "vrrpd_rtsock_create(): register "
			    "rtsock %d(%s) failed", sock,
			    af_str(vrrpd_rtsocks[i].vrt_af));
			break;
		}

		vrrpd_rtsocks[i].vrt_fd = sock;
		vrrpd_rtsocks[i].vrt_eid = eid;
	}

	if (i != 2) {
		(void) close(sock);
		vrrpd_rtsock_destroy();
		return (VRRP_ESYS);
	}

	return (VRRP_SUCCESS);
}

static void
vrrpd_rtsock_destroy()
{
	int		i;

	vrrp_log(VRRP_DBG0, "vrrpd_rtsock_destroy()");
	for (i = 0; i < 2; i++) {
		(void) iu_unregister_event(vrrpd_eh, vrrpd_rtsocks[i].vrt_eid,
		    NULL);
		(void) close(vrrpd_rtsocks[i].vrt_fd);
		vrrpd_rtsocks[i].vrt_eid = -1;
		vrrpd_rtsocks[i].vrt_fd = -1;
	}
}

/*
 * Create the VRRP control socket used to bring up/down the virtual
 * IP addresses. It is also used to set the IFF_NOACCEPT flag of
 * the virtual IP addresses.
 */
static vrrp_err_t
vrrpd_ctlsock_create()
{
	int	s, s6;
	int	on = _B_TRUE;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		vrrp_log(VRRP_ERR, "vrrpd_ctlsock_create(): socket(INET) "
		    "failed: %s", strerror(errno));
		return (VRRP_ESYS);
	}
	if (setsockopt(s, SOL_SOCKET, SO_VRRP, &on, sizeof (on)) < 0) {
		vrrp_log(VRRP_ERR, "vrrpd_ctlsock_create(): "
		    "setsockopt(INET, SO_VRRP) failed: %s", strerror(errno));
		(void) close(s);
		return (VRRP_ESYS);
	}

	if ((s6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		vrrp_log(VRRP_ERR, "vrrpd_ctlsock_create(): socket(INET6) "
		    "failed: %s", strerror(errno));
		(void) close(s);
		return (VRRP_ESYS);
	}
	if (setsockopt(s6, SOL_SOCKET, SO_VRRP, &on, sizeof (on)) < 0) {
		vrrp_log(VRRP_ERR, "vrrpd_ctlsock_create(): "
		    "setsockopt(INET6, SO_VRRP) failed: %s", strerror(errno));
		(void) close(s);
		(void) close(s6);
		return (VRRP_ESYS);
	}

	vrrpd_ctlsock_fd = s;
	vrrpd_ctlsock6_fd = s6;
	return (VRRP_SUCCESS);
}

static void
vrrpd_ctlsock_destroy()
{
	(void) close(vrrpd_ctlsock_fd);
	vrrpd_ctlsock_fd = -1;
	(void) close(vrrpd_ctlsock6_fd);
	vrrpd_ctlsock6_fd = -1;
}

/*ARGSUSED*/
static void
vrrpd_cmd_create(void *arg1, void *arg2, size_t *arg2_sz)
{
	vrrp_cmd_create_t	*cmd = (vrrp_cmd_create_t *)arg1;
	vrrp_ret_create_t	*ret = (vrrp_ret_create_t *)arg2;
	vrrp_err_t		err;

	err = vrrpd_create(&cmd->vcc_conf, _B_TRUE);
	if (err == VRRP_SUCCESS && cmd->vcc_conf.vvc_enabled) {
		/*
		 * No need to update the configuration since it is already
		 * done in the above vrrpd_create() call
		 */
		err = vrrpd_enable(cmd->vcc_conf.vvc_name, _B_FALSE);
		if (err != VRRP_SUCCESS)
			(void) vrrpd_delete(cmd->vcc_conf.vvc_name);
	}
	ret->vrc_err = err;
}

/*ARGSUSED*/
static void
vrrpd_cmd_delete(void *arg1, void *arg2, size_t *arg2_sz)
{
	vrrp_cmd_delete_t	*cmd = (vrrp_cmd_delete_t *)arg1;
	vrrp_ret_delete_t	*ret = (vrrp_ret_delete_t *)arg2;

	ret->vrd_err = vrrpd_delete(cmd->vcd_name);
}

/*ARGSUSED*/
static void
vrrpd_cmd_enable(void *arg1, void *arg2, size_t *arg2_sz)
{
	vrrp_cmd_enable_t	*cmd = (vrrp_cmd_enable_t *)arg1;
	vrrp_ret_enable_t	*ret = (vrrp_ret_enable_t *)arg2;

	ret->vrs_err = vrrpd_enable(cmd->vcs_name, _B_TRUE);
}

/*ARGSUSED*/
static void
vrrpd_cmd_disable(void *arg1, void *arg2, size_t *arg2_sz)
{
	vrrp_cmd_disable_t	*cmd = (vrrp_cmd_disable_t *)arg1;
	vrrp_ret_disable_t	*ret = (vrrp_ret_disable_t *)arg2;

	ret->vrx_err = vrrpd_disable(cmd->vcx_name);
}

/*ARGSUSED*/
static void
vrrpd_cmd_modify(void *arg1, void *arg2, size_t *arg2_sz)
{
	vrrp_cmd_modify_t	*cmd = (vrrp_cmd_modify_t *)arg1;
	vrrp_ret_modify_t	*ret = (vrrp_ret_modify_t *)arg2;

	ret->vrm_err = vrrpd_modify(&cmd->vcm_conf, cmd->vcm_mask);
}

static void
vrrpd_cmd_query(void *arg1, void *arg2, size_t *arg2_sz)
{
	vrrp_cmd_query_t	*cmd = (vrrp_cmd_query_t *)arg1;

	vrrpd_query(cmd->vcq_name, arg2, arg2_sz);
}

static void
vrrpd_cmd_list(void *arg1, void *arg2, size_t *arg2_sz)
{
	vrrp_cmd_list_t	*cmd = (vrrp_cmd_list_t *)arg1;

	vrrpd_list(cmd->vcl_vrid, cmd->vcl_ifname, cmd->vcl_af, arg2, arg2_sz);
}

/*
 * Write-type requeset must have the solaris.network.vrrp authorization.
 */
static boolean_t
vrrp_auth_check(int connfd, vrrp_cmd_info_t *cinfo)
{
	ucred_t		*cred = NULL;
	uid_t		uid;
	struct passwd	*pw;
	boolean_t	success = _B_FALSE;

	vrrp_log(VRRP_DBG0, "vrrp_auth_check()");

	if (!cinfo->vi_setop)
		return (_B_TRUE);

	/*
	 * Validate the credential
	 */
	if (getpeerucred(connfd, &cred) == (uid_t)-1) {
		vrrp_log(VRRP_ERR, "vrrp_auth_check(): getpeerucred() "
		    "failed: %s", strerror(errno));
		return (_B_FALSE);
	}

	if ((uid = ucred_getruid((const ucred_t *)cred)) == (uid_t)-1) {
		vrrp_log(VRRP_ERR, "vrrp_auth_check(): ucred_getruid() "
		    "failed: %s", strerror(errno));
		goto done;
	}

	if ((pw = getpwuid(uid)) == NULL) {
		vrrp_log(VRRP_ERR, "vrrp_auth_check(): getpwuid() failed");
		goto done;
	}

	success = (chkauthattr("solaris.network.vrrp", pw->pw_name) == 1);

done:
	ucred_free(cred);
	return (success);
}

/*
 * Process the administrative request from libvrrpadm
 */
/* ARGSUSED */
static void
vrrpd_cmdsock_handler(iu_eh_t *eh, int s, short events, iu_event_id_t id,
    void *arg)
{
	vrrp_cmd_info_t		*cinfo = NULL;
	vrrp_err_t		err = VRRP_SUCCESS;
	uchar_t			buf[BUFFSIZE], ackbuf[BUFFSIZE];
	size_t			cursize, acksize, len;
	uint32_t		cmd;
	int			connfd, i;
	struct sockaddr_in	from;
	socklen_t		fromlen;

	vrrp_log(VRRP_DBG0, "vrrpd_cmdsock_handler()");

	fromlen = (socklen_t)sizeof (from);
	if ((connfd = accept(s, (struct sockaddr *)&from, &fromlen)) < 0) {
		vrrp_log(VRRP_ERR, "vrrpd_cmdsock_handler() accept(): %s",
		    strerror(errno));
		return;
	}

	/*
	 * First get the type of the request
	 */
	cursize = 0;
	while (cursize < sizeof (uint32_t)) {
		len = read(connfd, buf + cursize,
		    sizeof (uint32_t) - cursize);
		if (len == (size_t)-1 && (errno == EAGAIN || errno == EINTR)) {
			continue;
		} else if (len > 0) {
			cursize += len;
			continue;
		}
		vrrp_log(VRRP_ERR, "vrrpd_cmdsock_handler(): invalid message "
		    "length");
		(void) close(connfd);
		return;
	}

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	cmd = ((vrrp_cmd_t *)buf)->vc_cmd;
	for (i = 0; i < VRRP_DOOR_INFO_TABLE_SIZE; i++) {
		if (vrrp_cmd_info_tbl[i].vi_cmd == cmd) {
			cinfo = vrrp_cmd_info_tbl + i;
			break;
		}
	}

	if (cinfo == NULL) {
		vrrp_log(VRRP_ERR, "vrrpd_cmdsock_handler(): invalid request "
		    "type %d", cmd);
		err = VRRP_EINVAL;
		goto done;
	}

	/*
	 * Get the rest of the request.
	 */
	assert(cursize == sizeof (uint32_t));
	while (cursize < cinfo->vi_reqsize) {
		len = read(connfd, buf + cursize,
		    cinfo->vi_reqsize - cursize);
		if (len == (size_t)-1 && (errno == EAGAIN || errno == EINTR)) {
			continue;
		} else if (len > 0) {
			cursize += len;
			continue;
		}
		vrrp_log(VRRP_ERR, "vrrpd_cmdsock_handler(): invalid message "
		    "length");
		err = VRRP_EINVAL;
		goto done;
	}

	/*
	 * Validate the authorization
	 */
	if (!vrrp_auth_check(connfd, cinfo)) {
		vrrp_log(VRRP_ERR, "vrrpd_cmdsock_handler(): "
		    "not sufficient authorization");
		err = VRRP_EPERM;
	}

done:
	/*
	 * Ack the request
	 */
	if (err != 0) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		((vrrp_ret_t *)ackbuf)->vr_err = err;
		acksize = sizeof (vrrp_ret_t);
	} else {
		/*
		 * If the size of ack is varied, the cmdfunc callback
		 * will set the right size.
		 */
		if ((acksize = cinfo->vi_acksize) == 0)
			acksize = sizeof (ackbuf);

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		cinfo->vi_cmdfunc((vrrp_cmd_t *)buf, ackbuf, &acksize);
	}

	/*
	 * Send the ack back.
	 */
	cursize = 0;
	while (cursize < acksize) {
		len = sendto(connfd, ackbuf + cursize, acksize - cursize,
		    0, (struct sockaddr *)&from, fromlen);
		if (len == (size_t)-1 && errno == EAGAIN) {
			continue;
		} else if (len > 0) {
			cursize += len;
			continue;
		} else {
			vrrp_log(VRRP_ERR, "vrrpd_cmdsock_handler() failed to "
			    "ack: %s", strerror(errno));
			break;
		}
	}

	(void) shutdown(connfd, SHUT_RDWR);
	(void) close(connfd);
}

/*
 * Process the routing socket messages and update the interfaces/IP addresses
 * list
 */
/* ARGSUSED */
static void
vrrpd_rtsock_handler(iu_eh_t *eh, int s, short events,
    iu_event_id_t id, void *arg)
{
	char			buf[BUFFSIZE];
	struct ifa_msghdr	*ifam;
	int			nbytes;
	int			af = *(int *)arg;
	boolean_t		scanif = _B_FALSE;

	for (;;) {
		nbytes = read(s, buf, sizeof (buf));
		if (nbytes <= 0) {
			/* No more messages */
			break;
		}

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		ifam = (struct ifa_msghdr *)buf;
		if (ifam->ifam_version != RTM_VERSION) {
			vrrp_log(VRRP_ERR, "vrrpd_rtsock_handler(): version %d "
			    "not understood", ifam->ifam_version);
			break;
		}

		vrrp_log(VRRP_DBG0, "vrrpd_rtsock_handler(): recv %s event",
		    rtm_event2str(ifam->ifam_type));

		switch (ifam->ifam_type) {
		case RTM_FREEADDR:
		case RTM_CHGADDR:
		case RTM_NEWADDR:
		case RTM_DELADDR:
			/*
			 * An IP address has been created/updated/deleted or
			 * brought up/down, re-initilialize the interface/IP
			 * address list.
			 */
			scanif = _B_TRUE;
			break;
		default:
			/* Not interesting */
			break;
		}
	}

	if (scanif)
		vrrpd_scan(af);
}

/*
 * Periodically scan the interface/IP addresses on the system.
 */
/* ARGSUSED */
static void
vrrpd_scan_timer(iu_tq_t *tq, void *arg)
{
	vrrp_log(VRRP_DBG0, "vrrpd_scan_timer()");
	vrrpd_scan(AF_INET);
	vrrpd_scan(AF_INET6);
}

/*
 * Get the list of the interface/IP addresses of the specified address
 * family.
 */
static void
vrrpd_scan(int af)
{
	vrrp_log(VRRP_DBG0, "vrrpd_scan(%s)", af_str(af));

again:
	vrrpd_init_ipcache(af);

	/* If interface index changes, walk again. */
	if (vrrpd_walk_addr_info(af) != IPADM_SUCCESS)
		goto again;

	vrrpd_update_ipcache(af);
}

/*
 * First mark all IP addresses of the specific address family to be removed.
 * This flag will then be cleared when we walk up all the IP addresses.
 */
static void
vrrpd_init_ipcache(int af)
{
	vrrp_intf_t	*intf, *next_intf;
	vrrp_ip_t	*ip, *nextip;
	char		abuf[INET6_ADDRSTRLEN];

	vrrp_log(VRRP_DBG0, "vrrpd_init_ipcache(%s)", af_str(af));

	next_intf = TAILQ_FIRST(&vrrp_intf_list);
	while ((intf = next_intf) != NULL) {
		next_intf = TAILQ_NEXT(intf, vvi_next);
		if (intf->vvi_af != af)
			continue;

		/*
		 * If the interface is still marked as new, it means that this
		 * vrrpd_init_ipcache() call is a result of ifindex change,
		 * which causes the re-walk of all the interfaces (see
		 * vrrpd_add_ipaddr()), and some interfaces are still marked
		 * as new during the last walk. In this case, delete this
		 * interface with the "update_vr" argument to be _B_FALSE,
		 * since no VRRP router has been assoicated with this
		 * interface yet (the association is done in
		 * vrrpd_update_ipcache()).
		 *
		 * This interface will be re-added later if it still exists.
		 */
		if (intf->vvi_state == NODE_STATE_NEW) {
			vrrp_log(VRRP_DBG0, "vrrpd_init_ipcache(): remove %s "
			    "(%d), may be added later", intf->vvi_ifname,
			    intf->vvi_ifindex);
			vrrpd_delete_if(intf, _B_FALSE);
			continue;
		}

		for (ip = TAILQ_FIRST(&intf->vvi_iplist); ip != NULL;
		    ip = nextip) {
			nextip = TAILQ_NEXT(ip, vip_next);
			/* LINTED E_CONSTANT_CONDITION */
			VRRPADDR2STR(af, &ip->vip_addr, abuf,
			    INET6_ADDRSTRLEN, _B_FALSE);

			if (ip->vip_state != NODE_STATE_NEW) {
				vrrp_log(VRRP_DBG0, "vrrpd_init_ipcache(%s/%d, "
				    "%s(%s/0x%x))", intf->vvi_ifname,
				    intf->vvi_ifindex, ip->vip_lifname,
				    abuf, ip->vip_flags);
				ip->vip_state = NODE_STATE_STALE;
				continue;
			}

			/*
			 * If the IP is still marked as new, it means that
			 * this vrrpd_init_ipcache() call is a result of
			 * ifindex change, which causes the re-walk of all
			 * the IP addresses (see vrrpd_add_ipaddr()).
			 * Delete this IP.
			 *
			 * This IP will be readded later if it still exists.
			 */
			vrrp_log(VRRP_DBG0, "vrrpd_init_ipcache(): remove "
			    "%s/%d , %s(%s)", intf->vvi_ifname,
			    intf->vvi_ifindex, ip->vip_lifname, abuf);
			vrrpd_delete_ip(intf, ip);
		}
	}
}

/*
 * Walk all the IP addresses of the given family and update its
 * addresses list. Return IPADM_FAILURE if it is required to walk
 * all the interfaces again (one of the interface index changes in between).
 */
static ipadm_status_t
vrrpd_walk_addr_info(int af)
{
	ipadm_addr_info_t	*ainfo, *ainfop;
	ipadm_status_t		ipstatus;
	char			*lifname;
	struct sockaddr_storage	stor;
	vrrp_addr_t		*addr;
	int			ifindex;
	uint64_t		flags;

	vrrp_log(VRRP_DBG0, "vrrpd_walk_addr_info(%s)", af_str(af));

	ipstatus = ipadm_addr_info(vrrp_ipadm_handle, NULL, &ainfo, 0, 0);
	if (ipstatus != IPADM_SUCCESS) {
		vrrp_log(VRRP_ERR, "vrrpd_walk_addr_info(%s): "
		    "ipadm_addr_info() failed: %s",
		    af_str(af), ipadm_status2str(ipstatus));
		return (IPADM_SUCCESS);
	}

	for (ainfop = ainfo; ainfop != NULL; ainfop = IA_NEXT(ainfop)) {
		if (ainfop->ia_ifa.ifa_addr->sa_family != af)
			continue;

		lifname = ainfop->ia_ifa.ifa_name;
		flags = ainfop->ia_ifa.ifa_flags;
		(void) memcpy(&stor, ainfop->ia_ifa.ifa_addr, sizeof (stor));
		addr = (vrrp_addr_t *)&stor;

		vrrp_log(VRRP_DBG0, "vrrpd_walk_addr_info(%s): %s",
		    af_str(af), lifname);

		/* Skip virtual/IPMP/P2P interfaces */
		if (flags & (IFF_VIRTUAL|IFF_IPMP|IFF_POINTOPOINT)) {
			vrrp_log(VRRP_DBG0, "vrrpd_walk_addr_info(%s): "
			    "skipped %s", af_str(af), lifname);
			continue;
		}

		/* Filter out the all-zero IP address */
		if (VRRPADDR_UNSPECIFIED(af, addr))
			continue;

		if ((ifindex = if_nametoindex(lifname)) == 0) {
			if (errno != ENXIO && errno != ENOENT) {
				vrrp_log(VRRP_ERR, "vrrpd_walk_addr_info(%s): "
				    "if_nametoindex() failed for %s: %s",
				    af_str(af), lifname, strerror(errno));
			}
			break;
		}

		/*
		 * The interface is unplumbed/replumbed during the walk.  Try
		 * to walk the IP addresses one more time.
		 */
		if (vrrpd_add_ipaddr(lifname, af, addr, ifindex, flags)
		    == VRRP_EAGAIN) {
			ipstatus = IPADM_FAILURE;
			break;
		}
	}

	ipadm_free_addr_info(ainfo);
	return (ipstatus);
}

/*
 * Given the information of each IP address, update the interface and
 * IP addresses list
 */
static vrrp_err_t
vrrpd_add_ipaddr(char *lifname, int af, vrrp_addr_t *addr, int ifindex,
    uint64_t flags)
{
	char		ifname[LIFNAMSIZ], *c;
	vrrp_intf_t	*intf;
	vrrp_ip_t	*ip;
	char		abuf[INET6_ADDRSTRLEN];
	vrrp_err_t	err;

	/* LINTED E_CONSTANT_CONDITION */
	VRRPADDR2STR(af, addr, abuf, INET6_ADDRSTRLEN, _B_FALSE);
	vrrp_log(VRRP_DBG0, "vrrpd_add_ipaddr(%s, %s, %d, 0x%x)", lifname,
	    abuf, ifindex, flags);

	/*
	 * Get the physical interface name from the logical interface name.
	 */
	(void) strlcpy(ifname, lifname, sizeof (ifname));
	if ((c = strchr(ifname, ':')) != NULL)
		*c = '\0';

	if ((intf = vrrpd_lookup_if(ifname, af)) == NULL) {
		vrrp_log(VRRP_DBG0, "vrrpd_add_ipaddr(): %s is new", ifname);
		err = vrrpd_create_if(ifname, af, ifindex, &intf);
		if (err != VRRP_SUCCESS)
			return (err);
	} else if (intf->vvi_ifindex != ifindex) {
		/*
		 * If index changes, it means that this interface is
		 * unplumbed/replumbed since we last checked. If this
		 * interface is not used by any VRRP router, just
		 * update its ifindex, and the IP addresses list will
		 * be updated later. Otherwise, return EAGAIN to rewalk
		 * all the IP addresses from the beginning.
		 */
		vrrp_log(VRRP_DBG0, "vrrpd_add_ipaddr(%s) ifindex changed ",
		    "from %d to %d", ifname, intf->vvi_ifindex, ifindex);
		if (!IS_PRIMARY_INTF(intf) && !IS_VIRTUAL_INTF(intf)) {
			intf->vvi_ifindex = ifindex;
		} else {
			/*
			 * delete this interface from the list if this
			 * interface has already been assoicated with
			 * any VRRP routers.
			 */
			vrrpd_delete_if(intf, _B_TRUE);
			return (VRRP_EAGAIN);
		}
	}

	/*
	 * Does this IP address already exist?
	 */
	TAILQ_FOREACH(ip, &intf->vvi_iplist, vip_next) {
		if (strcmp(ip->vip_lifname, lifname) == 0)
			break;
	}

	if (ip != NULL) {
		vrrp_log(VRRP_DBG0, "vrrpd_add_ipaddr(%s, %s) IP exists",
		    lifname, abuf);
		ip->vip_state = NODE_STATE_NONE;
		ip->vip_flags = flags;
		if (ipaddr_cmp(af, addr, &ip->vip_addr) != 0) {
			/*
			 * Address has been changed, mark it as new
			 * If this address is already selected as the
			 * primary IP address, the new IP will be checked
			 * to see whether it is still qualified as the
			 * primary IP address. If not, the primary IP
			 * address will be reselected.
			 */
			(void) memcpy(&ip->vip_addr, addr,
			    sizeof (vrrp_addr_t));

			ip->vip_state = NODE_STATE_NEW;
		}
	} else {
		vrrp_log(VRRP_DBG0, "vrrpd_add_ipaddr(%s, %s) IP is new",
		    lifname, abuf);

		err = vrrpd_create_ip(intf, lifname, addr, flags);
		if (err != VRRP_SUCCESS)
			return (err);
	}
	return (VRRP_SUCCESS);
}

/*
 * Update the interface and IP addresses list. Remove the ones that have been
 * staled since last time we walk the IP addresses and updated the ones that
 * have been changed.
 */
static void
vrrpd_update_ipcache(int af)
{
	vrrp_intf_t	*intf, *nextif;
	vrrp_ip_t	*ip, *nextip;
	char		abuf[INET6_ADDRSTRLEN];
	boolean_t	primary_selected;
	boolean_t	primary_now_selected;
	boolean_t	need_reenable = _B_FALSE;

	vrrp_log(VRRP_DBG0, "vrrpd_update_ipcache(%s)", af_str(af));

	nextif = TAILQ_FIRST(&vrrp_intf_list);
	while ((intf = nextif) != NULL) {
		nextif = TAILQ_NEXT(intf, vvi_next);
		if (intf->vvi_af != af)
			continue;

		/*
		 * Does the interface already select its primary IP address?
		 */
		primary_selected = (intf->vvi_pip != NULL);
		assert(!primary_selected || IS_PRIMARY_INTF(intf));

		/*
		 * Removed the IP addresses that have been unconfigured.
		 */
		for (ip = TAILQ_FIRST(&intf->vvi_iplist); ip != NULL;
		    ip = nextip) {
			nextip = TAILQ_NEXT(ip, vip_next);
			if (ip->vip_state != NODE_STATE_STALE)
				continue;

			/* LINTED E_CONSTANT_CONDITION */
			VRRPADDR2STR(af, &ip->vip_addr, abuf, INET6_ADDRSTRLEN,
			    _B_FALSE);
			vrrp_log(VRRP_DBG0, "vrrpd_update_ipcache(): IP %s "
			    "is removed over %s", abuf, intf->vvi_ifname);
			vrrpd_delete_ip(intf, ip);
		}

		/*
		 * No IP addresses left, delete this interface.
		 */
		if (TAILQ_EMPTY(&intf->vvi_iplist)) {
			vrrp_log(VRRP_DBG0, "vrrpd_update_ipcache(): "
			    "no IP left over %s", intf->vvi_ifname);
			vrrpd_delete_if(intf, _B_TRUE);
			continue;
		}

		/*
		 * If this is selected ss the physical interface for any
		 * VRRP router, reselect the primary address if needed.
		 */
		if (IS_PRIMARY_INTF(intf)) {
			vrrpd_reselect_primary(intf);
			primary_now_selected = (intf->vvi_pip != NULL);

			/*
			 * Cannot find the new primary IP address.
			 */
			if (primary_selected && !primary_now_selected) {
				vrrp_log(VRRP_DBG0, "vrrpd_update_ipcache() "
				    "reselect primary IP on %s failed",
				    intf->vvi_ifname);
				vrrpd_remove_if(intf, _B_TRUE);
			} else if (!primary_selected && primary_now_selected) {
				/*
				 * The primary IP address is successfully
				 * selected on the physical interfacew we
				 * need to walk through all the VRRP routers
				 * that is created on this physical interface
				 * and see whether they can now be enabled.
				 */
				need_reenable = _B_TRUE;
			}
		}

		/*
		 * For every new virtual IP address, bring up/down it based
		 * on the state of VRRP router.
		 *
		 * Note that it is fine to not update the IP's vip_flags field
		 * even if vrrpd_virtualip_updateone() changed the address's
		 * up/down state, since the vip_flags field is only used for
		 * select primary IP address over a physical interface, and
		 * vrrpd_virtualip_updateone() only affects the virtual IP
		 * address's status.
		 */
		for (ip = TAILQ_FIRST(&intf->vvi_iplist); ip != NULL;
		    ip = nextip) {
			nextip = TAILQ_NEXT(ip, vip_next);
			/* LINTED E_CONSTANT_CONDITION */
			VRRPADDR2STR(af, &ip->vip_addr, abuf, INET6_ADDRSTRLEN,
			    _B_FALSE);
			vrrp_log(VRRP_DBG0, "vrrpd_update_ipcache(): "
			    "IP %s over %s%s", abuf, intf->vvi_ifname,
			    ip->vip_state == NODE_STATE_NEW ? " is new" : "");

			if (IS_VIRTUAL_INTF(intf)) {
				/*
				 * If this IP is new, update its up/down state
				 * based on the virtual interface's state
				 * (which is determined by the VRRP router's
				 * state). Otherwise, check only and prompt
				 * warnings if its up/down state has been
				 * changed.
				 */
				if (vrrpd_virtualip_updateone(intf, ip,
				    ip->vip_state == NODE_STATE_NONE) !=
				    VRRP_SUCCESS) {
					vrrp_log(VRRP_DBG0,
					    "vrrpd_update_ipcache(): "
					    "IP %s over %s update failed", abuf,
					    intf->vvi_ifname);
					vrrpd_delete_ip(intf, ip);
					continue;
				}
			}
			ip->vip_state = NODE_STATE_NONE;
		}

		/*
		 * The IP address is deleted when it is failed to be brought
		 * up. If no IP addresses are left, delete this interface.
		 */
		if (TAILQ_EMPTY(&intf->vvi_iplist)) {
			vrrp_log(VRRP_DBG0, "vrrpd_update_ipcache(): "
			    "no IP left over %s", intf->vvi_ifname);
			vrrpd_delete_if(intf, _B_TRUE);
			continue;
		}

		if (intf->vvi_state == NODE_STATE_NEW) {
			/*
			 * A new interface is found. This interface can be
			 * the primary interface or the virtual VNIC
			 * interface.  Again, we need to walk throught all
			 * the VRRP routers to see whether some of them can
			 * now be enabled because of the new primary IP
			 * address or the new virtual IP addresses.
			 */
			intf->vvi_state = NODE_STATE_NONE;
			need_reenable = _B_TRUE;
		}
	}

	if (need_reenable)
		vrrpd_reenable_all_vr();
}

/*
 * Reselect primary IP if:
 * - The existing primary IP is no longer qualified (removed or it is down or
 *   not a link-local IP for IPv6 VRRP router);
 * - This is a physical interface but no primary IP is chosen;
 */
static void
vrrpd_reselect_primary(vrrp_intf_t *intf)
{
	vrrp_ip_t	*ip;
	char		abuf[INET6_ADDRSTRLEN];

	assert(IS_PRIMARY_INTF(intf));

	/*
	 * If the interface's old primary IP address is still valid, return
	 */
	if (((ip = intf->vvi_pip) != NULL) && (QUALIFY_PRIMARY_ADDR(intf, ip)))
		return;

	if (ip != NULL) {
		/* LINTED E_CONSTANT_CONDITION */
		VRRPADDR2STR(intf->vvi_af, &ip->vip_addr, abuf,
		    sizeof (abuf), _B_FALSE);
		vrrp_log(VRRP_DBG0, "vrrpd_reselect_primary(%s): primary IP %s "
		    "is no longer qualified", intf->vvi_ifname, abuf);
	}

	ip = vrrpd_select_primary(intf);
	intf->vvi_pip = ip;

	if (ip != NULL) {
		/* LINTED E_CONSTANT_CONDITION */
		VRRPADDR2STR(intf->vvi_af, &ip->vip_addr, abuf,
		    sizeof (abuf), _B_FALSE);
		vrrp_log(VRRP_DBG0, "vrrpd_reselect_primary(%s): primary IP %s "
		    "is selected", intf->vvi_ifname, abuf);
	}
}

/*
 * Select the primary IP address. Since the link-local IP address is always
 * at the head of the IP address list, try to find the first UP IP address
 * and see whether it qualify.
 */
static vrrp_ip_t *
vrrpd_select_primary(vrrp_intf_t *pif)
{
	vrrp_ip_t	*pip;
	char		abuf[INET6_ADDRSTRLEN];

	vrrp_log(VRRP_DBG1, "vrrpd_select_primary(%s)", pif->vvi_ifname);

	TAILQ_FOREACH(pip, &pif->vvi_iplist, vip_next) {
		assert(pip->vip_state != NODE_STATE_STALE);

		/* LINTED E_CONSTANT_CONDITION */
		VRRPADDR2STR(pif->vvi_af, &pip->vip_addr, abuf,
		    INET6_ADDRSTRLEN, _B_FALSE);
		vrrp_log(VRRP_DBG0, "vrrpd_select_primary(%s): %s is %s",
		    pif->vvi_ifname, abuf,
		    (pip->vip_flags & IFF_UP) ? "up" : "down");

		if (pip->vip_flags & IFF_UP)
			break;
	}

	/*
	 * Is this valid primary IP address?
	 */
	if (pip == NULL || !QUALIFY_PRIMARY_ADDR(pif, pip)) {
		vrrp_log(VRRP_DBG0, "vrrpd_select_primary(%s/%s) failed",
		    pif->vvi_ifname, af_str(pif->vvi_af));
		return (NULL);
	}
	return (pip);
}

/*
 * This is a new interface. Check whether any VRRP router is waiting for it
 */
static void
vrrpd_reenable_all_vr()
{
	vrrp_vr_t *vr;

	vrrp_log(VRRP_DBG0, "vrrpd_reenable_all_vr()");

	TAILQ_FOREACH(vr, &vrrp_vr_list, vvr_next) {
		if (vr->vvr_conf.vvc_enabled)
			(void) vrrpd_enable_vr(vr);
	}
}

/*
 * If primary_addr_gone is _B_TRUE, it means that we failed to select
 * the primary IP address on this (physical) interface; otherwise,
 * it means the interface is no longer available.
 */
static void
vrrpd_remove_if(vrrp_intf_t *intf, boolean_t primary_addr_gone)
{
	vrrp_vr_t *vr;

	vrrp_log(VRRP_DBG0, "vrrpd_remove_if(%s): %s", intf->vvi_ifname,
	    primary_addr_gone ? "primary address gone" : "interface deleted");

	TAILQ_FOREACH(vr, &vrrp_vr_list, vvr_next) {
		if (vr->vvr_conf.vvc_enabled)
			vrrpd_disable_vr(vr, intf, primary_addr_gone);
	}
}

/*
 * Update the VRRP configuration file based on the given configuration.
 * op is either VRRP_CONF_UPDATE or VRRP_CONF_DELETE
 */
static vrrp_err_t
vrrpd_updateconf(vrrp_vr_conf_t *newconf, uint_t op)
{
	vrrp_vr_conf_t	conf;
	FILE		*fp, *nfp;
	int		nfd;
	char		line[LINE_MAX];
	char		newfile[MAXPATHLEN];
	boolean_t	found = _B_FALSE;
	vrrp_err_t	err = VRRP_SUCCESS;

	vrrp_log(VRRP_DBG0, "vrrpd_updateconf(%s, %s)", newconf->vvc_name,
	    op == VRRP_CONF_UPDATE ? "update" : "delete");

	if ((fp = fopen(vrrpd_conffile, "r+F")) == NULL) {
		if (errno != ENOENT) {
			vrrp_log(VRRP_ERR, "vrrpd_updateconf(): open %s for "
			    "update failed: %s", vrrpd_conffile,
			    strerror(errno));
			return (VRRP_EDB);
		}

		if ((fp = fopen(vrrpd_conffile, "w+F")) == NULL) {
			vrrp_log(VRRP_ERR, "vrrpd_updateconf(): open %s for "
			    "write failed: %s", vrrpd_conffile,
			    strerror(errno));
			return (VRRP_EDB);
		}
	}

	(void) snprintf(newfile, MAXPATHLEN, "%s.new", vrrpd_conffile);
	if ((nfd = open(newfile, O_WRONLY | O_CREAT | O_TRUNC,
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) {
		vrrp_log(VRRP_ERR, "vrrpd_updateconf(): open %s failed: %s",
		    newfile, strerror(errno));
		(void) fclose(fp);
		return (VRRP_EDB);
	}

	if ((nfp = fdopen(nfd, "wF")) == NULL) {
		vrrp_log(VRRP_ERR, "vrrpd_updateconf(): fdopen(%s) failed: %s",
		    newfile, strerror(errno));
		goto done;
	}

	while (fgets(line, sizeof (line), fp) != NULL) {
		conf.vvc_vrid = VRRP_VRID_NONE;
		if (!found && (err = vrrpd_read_vrconf(line, &conf)) !=
		    VRRP_SUCCESS) {
			vrrp_log(VRRP_ERR, "vrrpd_updateconf(): invalid "
			    "configuration format: %s", line);
			goto done;
		}

		/*
		 * Write this line out if:
		 * - this is a comment line; or
		 * - we've done updating/deleting the the given VR; or
		 * - if the name of the VR read from this line does not match
		 *   the VR name that we are about to update/delete;
		 */
		if (found || conf.vvc_vrid == VRRP_VRID_NONE ||
		    strcmp(conf.vvc_name, newconf->vvc_name) != 0) {
			if (fputs(line, nfp) != EOF)
				continue;

			vrrp_log(VRRP_ERR, "vrrpd_updateconf(): failed to "
			    "write line %s", line);
			err = VRRP_EDB;
			goto done;
		}

		/*
		 * Otherwise, update/skip the line.
		 */
		found = _B_TRUE;
		if (op == VRRP_CONF_DELETE)
			continue;

		assert(op == VRRP_CONF_UPDATE);
		if ((err = vrrpd_write_vrconf(line, sizeof (line),
		    newconf)) != VRRP_SUCCESS) {
			vrrp_log(VRRP_ERR, "vrrpd_updateconf(): failed to "
			    "update configuration for %s", newconf->vvc_name);
			goto done;
		}
		if (fputs(line, nfp) == EOF) {
			vrrp_log(VRRP_ERR, "vrrpd_updateconf(): failed to "
			    "write line %s", line);
			err = VRRP_EDB;
			goto done;
		}
	}

	/*
	 * If we get to the end of the file and have not seen the router that
	 * we are about to update, write it out.
	 */
	if (!found && op == VRRP_CONF_UPDATE) {
		if ((err = vrrpd_write_vrconf(line, sizeof (line),
		    newconf)) == VRRP_SUCCESS && fputs(line, nfp) == EOF) {
			vrrp_log(VRRP_ERR, "vrrpd_updateconf(): failed to "
			    "write line %s", line);
			err = VRRP_EDB;
		}
	} else if (!found && op == VRRP_CONF_DELETE) {
		vrrp_log(VRRP_ERR, "vrrpd_updateconf(): failed to find "
		    "configuation for %s", newconf->vvc_name);
		err = VRRP_ENOTFOUND;
	}

	if (err != VRRP_SUCCESS)
		goto done;

	if (fflush(nfp) == EOF || rename(newfile, vrrpd_conffile) < 0) {
		vrrp_log(VRRP_ERR, "vrrpd_updateconf(): failed to "
		    "rename file %s", newfile);
		err = VRRP_EDB;
	}

done:
	(void) fclose(fp);
	(void) fclose(nfp);
	(void) unlink(newfile);
	return (err);
}

static vrrp_err_t
vrrpd_write_vrconf(char *line, size_t len, vrrp_vr_conf_t *conf)
{
	vrrp_prop_t	*prop;
	int		n, i;

	vrrp_log(VRRP_DBG0, "vrrpd_write_vrconf(%s)", conf->vvc_name);

	for (i = 0; i < VRRP_PROP_INFO_TABSIZE; i++) {
		prop = &vrrp_prop_info_tbl[i];
		n = snprintf(line, len, i == 0 ? "%s=" : " %s=",
		    prop->vs_propname);
		if (n < 0 || n >= len)
			break;
		len -= n;
		line += n;
		n = prop->vs_propwrite(conf, line, len);
		if (n < 0 || n >= len)
			break;
		len -= n;
		line += n;
	}
	if (i != VRRP_PROP_INFO_TABSIZE) {
		vrrp_log(VRRP_ERR, "vrrpd_write_vrconf(%s): buffer size too"
		    "small", conf->vvc_name);
		return (VRRP_EDB);
	}
	n = snprintf(line, len, "\n");
	if (n < 0 || n >= len) {
		vrrp_log(VRRP_ERR, "vrrpd_write_vrconf(%s): buffer size too"
		    "small", conf->vvc_name);
		return (VRRP_EDB);
	}
	return (VRRP_SUCCESS);
}

static vrrp_err_t
vrrpd_read_vrconf(char *line, vrrp_vr_conf_t *conf)
{
	char		*str, *token;
	char		*next;
	vrrp_err_t	err = VRRP_SUCCESS;
	char		tmpbuf[MAXLINELEN];

	str = tmpbuf;
	(void) strlcpy(tmpbuf, line, MAXLINELEN);

	/*
	 * Skip leading spaces, blank lines, and comments.
	 */
	skip_whitespace(str);
	if ((str - tmpbuf == strlen(tmpbuf)) || (*str == '#')) {
		conf->vvc_vrid = VRRP_VRID_NONE;
		return (VRRP_SUCCESS);
	}

	/*
	 * Read each VR properties.
	 */
	for (token = strtok_r(str, " \n\t", &next); token != NULL;
	    token = strtok_r(NULL, " \n\t", &next)) {
		if ((err = vrrpd_readprop(token, conf)) != VRRP_SUCCESS)
			break;
	}

	/* All properties read but no VRID defined */
	if (err == VRRP_SUCCESS && conf->vvc_vrid == VRRP_VRID_NONE)
		err = VRRP_EINVAL;

	return (err);
}

static vrrp_err_t
vrrpd_readprop(const char *str, vrrp_vr_conf_t *conf)
{
	vrrp_prop_t	*prop;
	char		*pstr;
	int		i;

	if ((pstr = strchr(str, '=')) == NULL) {
		vrrp_log(VRRP_ERR, "vrrpd_readprop(%s): invalid property", str);
		return (VRRP_EINVAL);
	}

	*pstr++ = '\0';
	for (i = 0; i < VRRP_PROP_INFO_TABSIZE; i++) {
		prop = &vrrp_prop_info_tbl[i];
		if (strcasecmp(str, prop->vs_propname) == 0) {
			if (prop->vs_propread(conf, pstr))
				break;
		}
	}

	if (i == VRRP_PROP_INFO_TABSIZE) {
		vrrp_log(VRRP_ERR, "vrrpd_readprop(%s): invalid property", str);
		return (VRRP_EINVAL);
	}

	return (VRRP_SUCCESS);
}

static boolean_t
vrrp_rd_prop_name(vrrp_vr_conf_t *conf, const char *str)
{
	size_t size = sizeof (conf->vvc_name);
	return (strlcpy(conf->vvc_name, str, size) < size);
}

static boolean_t
vrrp_rd_prop_vrid(vrrp_vr_conf_t *conf, const char *str)
{
	conf->vvc_vrid = strtol(str, NULL, 0);
	return (!(conf->vvc_vrid < VRRP_VRID_MIN ||
	    conf->vvc_vrid > VRRP_VRID_MAX ||
	    (conf->vvc_vrid == 0 && errno != 0)));
}

static boolean_t
vrrp_rd_prop_af(vrrp_vr_conf_t *conf, const char *str)
{
	if (strcasecmp(str, "AF_INET") == 0)
		conf->vvc_af = AF_INET;
	else if (strcasecmp(str, "AF_INET6") == 0)
		conf->vvc_af = AF_INET6;
	else
		return (_B_FALSE);
	return (_B_TRUE);
}

static boolean_t
vrrp_rd_prop_pri(vrrp_vr_conf_t *conf, const char *str)
{
	conf->vvc_pri = strtol(str, NULL, 0);
	return (!(conf->vvc_pri < VRRP_PRI_MIN ||
	    conf->vvc_pri > VRRP_PRI_OWNER ||
	    (conf->vvc_pri == 0 && errno != 0)));
}

static boolean_t
vrrp_rd_prop_adver_int(vrrp_vr_conf_t *conf, const char *str)
{
	conf->vvc_adver_int = strtol(str, NULL, 0);
	return (!(conf->vvc_adver_int < VRRP_MAX_ADVER_INT_MIN ||
	    conf->vvc_adver_int > VRRP_MAX_ADVER_INT_MAX ||
	    (conf->vvc_adver_int == 0 && errno != 0)));
}

static boolean_t
vrrp_rd_prop_preempt(vrrp_vr_conf_t *conf, const char *str)
{
	if (strcasecmp(str, "true") == 0)
		conf->vvc_preempt = _B_TRUE;
	else if (strcasecmp(str, "false") == 0)
		conf->vvc_preempt = _B_FALSE;
	else
		return (_B_FALSE);
	return (_B_TRUE);
}

static boolean_t
vrrp_rd_prop_accept(vrrp_vr_conf_t *conf, const char *str)
{
	if (strcasecmp(str, "true") == 0)
		conf->vvc_accept = _B_TRUE;
	else if (strcasecmp(str, "false") == 0)
		conf->vvc_accept = _B_FALSE;
	else
		return (_B_FALSE);
	return (_B_TRUE);
}

static boolean_t
vrrp_rd_prop_enabled(vrrp_vr_conf_t *conf, const char *str)
{
	if (strcasecmp(str, "enabled") == 0)
		conf->vvc_enabled = _B_TRUE;
	else if (strcasecmp(str, "disabled") == 0)
		conf->vvc_enabled = _B_FALSE;
	else
		return (_B_FALSE);
	return (_B_TRUE);
}

static boolean_t
vrrp_rd_prop_ifname(vrrp_vr_conf_t *conf, const char *str)
{
	size_t size = sizeof (conf->vvc_link);
	return (strlcpy(conf->vvc_link, str, size) < size);
}

static int
vrrp_wt_prop_name(vrrp_vr_conf_t *conf, char *str, size_t size)
{
	return (snprintf(str, size, "%s", conf->vvc_name));
}

static int
vrrp_wt_prop_pri(vrrp_vr_conf_t *conf, char *str, size_t size)
{
	return (snprintf(str, size, "%d", conf->vvc_pri));
}

static int
vrrp_wt_prop_adver_int(vrrp_vr_conf_t *conf, char *str, size_t size)
{
	return (snprintf(str, size, "%d", conf->vvc_adver_int));
}

static int
vrrp_wt_prop_preempt(vrrp_vr_conf_t *conf, char *str, size_t size)
{
	return (snprintf(str, size, "%s",
	    conf->vvc_preempt ? "true" : "false"));
}

static int
vrrp_wt_prop_accept(vrrp_vr_conf_t *conf, char *str, size_t size)
{
	return (snprintf(str, size, "%s",
	    conf->vvc_accept ? "true" : "false"));
}

static int
vrrp_wt_prop_enabled(vrrp_vr_conf_t *conf, char *str, size_t size)
{
	return (snprintf(str, size, "%s",
	    conf->vvc_enabled ? "enabled" : "disabled"));
}

static int
vrrp_wt_prop_vrid(vrrp_vr_conf_t *conf, char *str, size_t size)
{
	return (snprintf(str, size, "%d", conf->vvc_vrid));
}

static int
vrrp_wt_prop_af(vrrp_vr_conf_t *conf, char *str, size_t size)
{
	return (snprintf(str, size, "%s",
	    conf->vvc_af == AF_INET ? "AF_INET" : "AF_INET6"));
}

static int
vrrp_wt_prop_ifname(vrrp_vr_conf_t *conf, char *str, size_t size)
{
	return (snprintf(str, size, "%s", conf->vvc_link));
}

static char *
af_str(int af)
{
	if (af == 4 || af == AF_INET)
		return ("AF_INET");
	else if (af == 6 || af == AF_INET6)
		return ("AF_INET6");
	else if (af == AF_UNSPEC)
		return ("AF_UNSPEC");
	else
		return ("AF_error");
}

static vrrp_err_t
vrrpd_create_vr(vrrp_vr_conf_t *conf)
{
	vrrp_vr_t	*vr;

	vrrp_log(VRRP_DBG0, "vrrpd_create_vr(%s)", conf->vvc_name);

	if ((vr = malloc(sizeof (vrrp_vr_t))) == NULL) {
		vrrp_log(VRRP_ERR, "vrrpd_create_vr(): memory allocation for %s"
		    " failed", conf->vvc_name);
		return (VRRP_ENOMEM);
	}

	bzero(vr, sizeof (vrrp_vr_t));
	vr->vvr_state = VRRP_STATE_NONE;
	vr->vvr_timer_id = -1;
	vrrpd_state_trans(VRRP_STATE_NONE, VRRP_STATE_INIT, vr);
	(void) memcpy(&vr->vvr_conf, conf, sizeof (vrrp_vr_conf_t));
	vr->vvr_conf.vvc_enabled = _B_FALSE;
	TAILQ_INSERT_HEAD(&vrrp_vr_list, vr, vvr_next);
	return (VRRP_SUCCESS);
}

static void
vrrpd_delete_vr(vrrp_vr_t *vr)
{
	vrrp_log(VRRP_DBG0, "vrrpd_delete_vr(%s)", vr->vvr_conf.vvc_name);
	if (vr->vvr_conf.vvc_enabled)
		vrrpd_disable_vr(vr, NULL, _B_FALSE);
	assert(vr->vvr_state == VRRP_STATE_INIT);
	vrrpd_state_trans(VRRP_STATE_INIT, VRRP_STATE_NONE, vr);
	TAILQ_REMOVE(&vrrp_vr_list, vr, vvr_next);
	(void) free(vr);
}

static vrrp_err_t
vrrpd_enable_vr(vrrp_vr_t *vr)
{
	vrrp_err_t	rx_err, tx_err, err = VRRP_EINVAL;

	vrrp_log(VRRP_DBG0, "vrrpd_enable_vr(%s)", vr->vvr_conf.vvc_name);

	assert(vr->vvr_conf.vvc_enabled);

	/*
	 * This VRRP router has been successfully enabled and start
	 * participating.
	 */
	if (vr->vvr_state != VRRP_STATE_INIT)
		return (VRRP_SUCCESS);

	if ((rx_err = vrrpd_init_rxsock(vr)) == VRRP_SUCCESS) {
		/*
		 * Select the primary IP address. Even if this time
		 * primary IP selection failed, we will reselect the
		 * primary IP address when new IP address comes up.
		 */
		vrrpd_reselect_primary(vr->vvr_pif);
		if (vr->vvr_pif->vvi_pip == NULL) {
			vrrp_log(VRRP_DBG0, "vrrpd_enable_vr(%s): "
			    "select_primary over %s failed",
			    vr->vvr_conf.vvc_name, vr->vvr_pif->vvi_ifname);
			rx_err = VRRP_ENOPRIM;
		}
	}

	/*
	 * Initialize the TX socket used for this vrrp_vr_t to send the
	 * multicast packets.
	 */
	tx_err = vrrpd_init_txsock(vr);

	/*
	 * Only start the state transition if sockets for both RX and TX are
	 * initialized correctly.
	 */
	if (rx_err != VRRP_SUCCESS || tx_err != VRRP_SUCCESS) {
		/*
		 * Record the error information for diagnose purpose.
		 */
		vr->vvr_err = (rx_err == VRRP_SUCCESS) ? tx_err : rx_err;
		return (err);
	}

	if (vr->vvr_conf.vvc_pri == 255)
		err = vrrpd_state_i2m(vr);
	else
		err = vrrpd_state_i2b(vr);

	if (err != VRRP_SUCCESS) {
		vr->vvr_err = err;
		vr->vvr_pif->vvi_pip = NULL;
		vrrpd_fini_txsock(vr);
		vrrpd_fini_rxsock(vr);
	}
	return (err);
}

/*
 * Given the removed interface, see whether the given VRRP router would
 * be affected and stop participating the VRRP protocol.
 *
 * If intf is NULL, VR disabling request is coming from the admin.
 */
static void
vrrpd_disable_vr(vrrp_vr_t *vr, vrrp_intf_t *intf, boolean_t primary_addr_gone)
{
	vrrp_log(VRRP_DBG0, "vrrpd_disable_vr(%s): %s%s", vr->vvr_conf.vvc_name,
	    intf == NULL ? "requested by admin" : intf->vvi_ifname,
	    intf == NULL ? "" : (primary_addr_gone ? "primary address gone" :
	    "interface deleted"));

	/*
	 * An interface is deleted, see whether this interface is the
	 * physical interface or the VNIC of the given VRRP router.
	 * If so, continue to disable the VRRP router.
	 */
	if (!primary_addr_gone && (intf != NULL) && (intf != vr->vvr_pif) &&
	    (intf != vr->vvr_vif)) {
		return;
	}

	/*
	 * If this is the case that the primary IP address is gone,
	 * and we failed to reselect another primary IP address,
	 * continue to disable the VRRP router.
	 */
	if (primary_addr_gone && intf != vr->vvr_pif)
		return;

	vrrp_log(VRRP_DBG1, "vrrpd_disable_vr(%s): disabling",
	    vr->vvr_conf.vvc_name);

	if (vr->vvr_state == VRRP_STATE_MASTER) {
		/*
		 * If this router is disabled by the administrator, send
		 * the zero-priority advertisement to indicate the Master
		 * stops participating VRRP.
		 */
		if (intf == NULL)
			(void) vrrpd_send_adv(vr, _B_TRUE);

		vrrpd_state_m2i(vr);
	} else  if (vr->vvr_state == VRRP_STATE_BACKUP) {
		vrrpd_state_b2i(vr);
	}

	/*
	 * If no primary IP address can be selected, the VRRP router
	 * stays at the INIT state and will become BACKUP and MASTER when
	 * a primary IP address is reselected.
	 */
	if (primary_addr_gone) {
		vrrp_log(VRRP_DBG1, "vrrpd_disable_vr(%s): primary IP "
		    "is removed", vr->vvr_conf.vvc_name);
		vr->vvr_err = VRRP_ENOPRIM;
	} else if (intf == NULL) {
		/*
		 * The VRRP router is disable by the administrator
		 */
		vrrp_log(VRRP_DBG1, "vrrpd_disable_vr(%s): disabled by admin",
		    vr->vvr_conf.vvc_name);
		vr->vvr_err = VRRP_SUCCESS;
		vrrpd_fini_txsock(vr);
		vrrpd_fini_rxsock(vr);
	} else if (intf == vr->vvr_pif) {
		vrrp_log(VRRP_DBG1, "vrrpd_disable_vr(%s): physical interface "
		    "%s removed", vr->vvr_conf.vvc_name, intf->vvi_ifname);
		vr->vvr_err = VRRP_ENOPRIM;
		vrrpd_fini_rxsock(vr);
	} else if (intf == vr->vvr_vif) {
		vrrp_log(VRRP_DBG1, "vrrpd_disable_vr(%s): VNIC interface %s"
		    " removed", vr->vvr_conf.vvc_name, intf->vvi_ifname);
		vr->vvr_err = VRRP_ENOVIRT;
		vrrpd_fini_txsock(vr);
	}
}

vrrp_err_t
vrrpd_create(vrrp_vr_conf_t *conf, boolean_t updateconf)
{
	vrrp_err_t	err = VRRP_SUCCESS;

	vrrp_log(VRRP_DBG0, "vrrpd_create(%s, %s, %d)", conf->vvc_name,
	    conf->vvc_link, conf->vvc_vrid);

	assert(conf != NULL);

	/*
	 * Sanity check
	 */
	if ((strlen(conf->vvc_name) == 0) ||
	    (strlen(conf->vvc_link) == 0) ||
	    (conf->vvc_vrid < VRRP_VRID_MIN ||
	    conf->vvc_vrid > VRRP_VRID_MAX) ||
	    (conf->vvc_pri < VRRP_PRI_MIN ||
	    conf->vvc_pri > VRRP_PRI_OWNER) ||
	    (conf->vvc_adver_int < VRRP_MAX_ADVER_INT_MIN ||
	    conf->vvc_adver_int > VRRP_MAX_ADVER_INT_MAX) ||
	    (conf->vvc_af != AF_INET && conf->vvc_af != AF_INET6) ||
	    (conf->vvc_pri == VRRP_PRI_OWNER && !conf->vvc_accept)) {
		vrrp_log(VRRP_DBG1, "vrrpd_create(%s): invalid argument",
		    conf->vvc_name);
		return (VRRP_EINVAL);
	}

	if (!vrrp_valid_name(conf->vvc_name)) {
		vrrp_log(VRRP_DBG1, "vrrpd_create(): %s is not a valid router "
		    "name", conf->vvc_name);
		return (VRRP_EINVALVRNAME);
	}

	if (vrrpd_lookup_vr_by_name(conf->vvc_name) != NULL) {
		vrrp_log(VRRP_DBG1, "vrrpd_create(): %s already exists",
		    conf->vvc_name);
		return (VRRP_EINSTEXIST);
	}

	if (vrrpd_lookup_vr_by_vrid(conf->vvc_link, conf->vvc_vrid,
	    conf->vvc_af) != NULL) {
		vrrp_log(VRRP_DBG1, "vrrpd_create(): VRID %d/%s over %s "
		    "already exists", conf->vvc_vrid, af_str(conf->vvc_af),
		    conf->vvc_link);
		return (VRRP_EVREXIST);
	}

	if (updateconf && (err = vrrpd_updateconf(conf,
	    VRRP_CONF_UPDATE)) != VRRP_SUCCESS) {
		vrrp_log(VRRP_ERR, "vrrpd_create(): failed to update "
		    "configuration for %s", conf->vvc_name);
		return (err);
	}

	err = vrrpd_create_vr(conf);
	if (err != VRRP_SUCCESS && updateconf)
		(void) vrrpd_updateconf(conf, VRRP_CONF_DELETE);

	return (err);
}

static vrrp_err_t
vrrpd_delete(const char *vn)
{
	vrrp_vr_t	*vr;
	vrrp_err_t	err;

	vrrp_log(VRRP_DBG0, "vrrpd_delete(%s)", vn);

	if ((vr = vrrpd_lookup_vr_by_name(vn)) == NULL) {
		vrrp_log(VRRP_DBG1, "vrrpd_delete(): %s not exists", vn);
		return (VRRP_ENOTFOUND);
	}

	err = vrrpd_updateconf(&vr->vvr_conf, VRRP_CONF_DELETE);
	if (err != VRRP_SUCCESS) {
		vrrp_log(VRRP_ERR, "vrrpd_delete(): failed to delete "
		    "configuration for %s", vr->vvr_conf.vvc_name);
		return (err);
	}

	vrrpd_delete_vr(vr);
	return (VRRP_SUCCESS);
}

static vrrp_err_t
vrrpd_enable(const char *vn, boolean_t updateconf)
{
	vrrp_vr_t		*vr;
	vrrp_vr_conf_t		*conf;
	uint32_t		flags;
	datalink_class_t	class;
	vrrp_err_t		err = VRRP_SUCCESS;

	vrrp_log(VRRP_DBG0, "vrrpd_enable(%s)", vn);

	if ((vr = vrrpd_lookup_vr_by_name(vn)) == NULL) {
		vrrp_log(VRRP_DBG1, "vrrpd_enable(): %s does not exist", vn);
		return (VRRP_ENOTFOUND);
	}

	/*
	 * The VR is already enabled.
	 */
	conf = &vr->vvr_conf;
	if (conf->vvc_enabled) {
		vrrp_log(VRRP_DBG1, "vrrpd_enable(): %s is already "
		    "enabled", vn);
		return (VRRP_EALREADY);
	}

	/*
	 * Check whether the link exists.
	 */
	if ((strlen(conf->vvc_link) == 0) || dladm_name2info(vrrpd_vh->vh_dh,
	    conf->vvc_link, NULL, &flags, &class, NULL) != DLADM_STATUS_OK ||
	    !(flags & DLADM_OPT_ACTIVE) || ((class != DATALINK_CLASS_PHYS) &&
	    (class != DATALINK_CLASS_VLAN) && (class != DATALINK_CLASS_AGGR) &&
	    (class != DATALINK_CLASS_VNIC))) {
		vrrp_log(VRRP_DBG1, "vrrpd_enable(%s): invalid link %s",
		    vn, conf->vvc_link);
		return (VRRP_EINVALLINK);
	}

	/*
	 * Get the associated VNIC name by the given interface/vrid/
	 * address famitly.
	 */
	err = vrrp_get_vnicname(vrrpd_vh, conf->vvc_vrid,
	    conf->vvc_af, conf->vvc_link, NULL, NULL, vr->vvr_vnic,
	    sizeof (vr->vvr_vnic));
	if (err != VRRP_SUCCESS) {
		vrrp_log(VRRP_DBG1, "vrrpd_enable(%s): no VNIC for VRID %d/%s "
		    "over %s", vn, conf->vvc_vrid, af_str(conf->vvc_af),
		    conf->vvc_link);
		err = VRRP_ENOVNIC;
		goto fail;
	}

	/*
	 * Find the right VNIC, primary interface and get the list of the
	 * protected IP adressses and primary IP address. Note that if
	 * either interface is NULL (no IP addresses configured over the
	 * interface), we will still continue and mark this VRRP router
	 * as "enabled".
	 */
	vr->vvr_conf.vvc_enabled = _B_TRUE;
	if (updateconf && (err = vrrpd_updateconf(&vr->vvr_conf,
	    VRRP_CONF_UPDATE)) != VRRP_SUCCESS) {
		vrrp_log(VRRP_ERR, "vrrpd_enable(): failed to update "
		    "configuration for %s", vr->vvr_conf.vvc_name);
		goto fail;
	}

	/*
	 * If vrrpd_setup_vr() fails, it is possible that there is no IP
	 * addresses over ether the primary interface or the VNIC yet,
	 * return success in this case, the VRRP router will stay in
	 * the initialized state and start to work when the IP address is
	 * configured.
	 */
	(void) vrrpd_enable_vr(vr);
	return (VRRP_SUCCESS);

fail:
	vr->vvr_conf.vvc_enabled = _B_FALSE;
	vr->vvr_vnic[0] = '\0';
	return (err);
}

static vrrp_err_t
vrrpd_disable(const char *vn)
{
	vrrp_vr_t	*vr;
	vrrp_err_t	err;

	vrrp_log(VRRP_DBG0, "vrrpd_disable(%s)", vn);

	if ((vr = vrrpd_lookup_vr_by_name(vn)) == NULL) {
		vrrp_log(VRRP_DBG1, "vrrpd_disable(): %s does not exist", vn);
		return (VRRP_ENOTFOUND);
	}

	/*
	 * The VR is already disable.
	 */
	if (!vr->vvr_conf.vvc_enabled) {
		vrrp_log(VRRP_DBG1, "vrrpd_disable(): %s was not enabled", vn);
		return (VRRP_EALREADY);
	}

	vr->vvr_conf.vvc_enabled = _B_FALSE;
	err = vrrpd_updateconf(&vr->vvr_conf, VRRP_CONF_UPDATE);
	if (err != VRRP_SUCCESS) {
		vr->vvr_conf.vvc_enabled = _B_TRUE;
		vrrp_log(VRRP_ERR, "vrrpd_disable(): failed to update "
		    "configuration for %s", vr->vvr_conf.vvc_name);
		return (err);
	}

	vrrpd_disable_vr(vr, NULL, _B_FALSE);
	vr->vvr_vnic[0] = '\0';
	return (VRRP_SUCCESS);
}

static vrrp_err_t
vrrpd_modify(vrrp_vr_conf_t *conf, uint32_t mask)
{
	vrrp_vr_t	*vr;
	vrrp_vr_conf_t	savconf;
	int		pri;
	boolean_t	accept, set_accept = _B_FALSE;
	vrrp_err_t	err;

	vrrp_log(VRRP_DBG0, "vrrpd_modify(%s)", conf->vvc_name);

	if (mask == 0)
		return (VRRP_SUCCESS);

	if ((vr = vrrpd_lookup_vr_by_name(conf->vvc_name)) == NULL) {
		vrrp_log(VRRP_DBG1, "vrrpd_modify(): cannot find the given "
		    "VR instance: %s", conf->vvc_name);
		return (VRRP_ENOTFOUND);
	}

	if (mask & VRRP_CONF_INTERVAL) {
		if (conf->vvc_adver_int < VRRP_MAX_ADVER_INT_MIN ||
		    conf->vvc_adver_int > VRRP_MAX_ADVER_INT_MAX) {
			vrrp_log(VRRP_DBG1, "vrrpd_modify(%s): invalid "
			    "adver_interval %d", conf->vvc_name,
			    conf->vvc_adver_int);
			return (VRRP_EINVAL);
		}
	}

	pri = vr->vvr_conf.vvc_pri;
	if (mask & VRRP_CONF_PRIORITY) {
		if (conf->vvc_pri < VRRP_PRI_MIN ||
		    conf->vvc_pri > VRRP_PRI_OWNER) {
			vrrp_log(VRRP_DBG1, "vrrpd_modify(%s): invalid "
			    "priority %d", conf->vvc_name, conf->vvc_pri);
			return (VRRP_EINVAL);
		}
		pri = conf->vvc_pri;
	}

	accept = vr->vvr_conf.vvc_accept;
	if (mask & VRRP_CONF_ACCEPT)
		accept = conf->vvc_accept;

	if (pri == VRRP_PRI_OWNER && !accept) {
		vrrp_log(VRRP_DBG1, "vrrpd_modify(%s): accept mode must be "
		    "true for VRRP address owner", conf->vvc_name);
		return (VRRP_EINVAL);
	}

	if ((mask & VRRP_CONF_ACCEPT) && (vr->vvr_conf.vvc_accept != accept)) {
		err = vrrpd_set_noaccept(vr, !accept);
		if (err != VRRP_SUCCESS) {
			vrrp_log(VRRP_ERR, "vrrpd_modify(%s): access mode "
			    "updating failed: %s", conf->vvc_name,
			    vrrp_err2str(err));
			return (err);
		}
		set_accept = _B_TRUE;
	}

	/*
	 * Save the current configuration, so it can be restored if the
	 * following fails.
	 */
	(void) memcpy(&savconf, &vr->vvr_conf, sizeof (vrrp_vr_conf_t));
	if (mask & VRRP_CONF_PREEMPT)
		vr->vvr_conf.vvc_preempt = conf->vvc_preempt;

	if (mask & VRRP_CONF_ACCEPT)
		vr->vvr_conf.vvc_accept = accept;

	if (mask & VRRP_CONF_PRIORITY)
		vr->vvr_conf.vvc_pri = pri;

	if (mask & VRRP_CONF_INTERVAL)
		vr->vvr_conf.vvc_adver_int = conf->vvc_adver_int;

	err = vrrpd_updateconf(&vr->vvr_conf, VRRP_CONF_UPDATE);
	if (err != VRRP_SUCCESS) {
		vrrp_log(VRRP_ERR, "vrrpd_modify(%s): configuration update "
		    "failed: %s", conf->vvc_name, vrrp_err2str(err));
		if (set_accept)
			(void) vrrpd_set_noaccept(vr, accept);
		(void) memcpy(&vr->vvr_conf, &savconf, sizeof (vrrp_vr_conf_t));
		return (err);
	}

	if ((mask & VRRP_CONF_PRIORITY) && (vr->vvr_state == VRRP_STATE_BACKUP))
		vr->vvr_timeout = MASTER_DOWN_INTERVAL_VR(vr);

	if ((mask & VRRP_CONF_INTERVAL) && (vr->vvr_state == VRRP_STATE_MASTER))
		vr->vvr_timeout = conf->vvc_adver_int;

	return (VRRP_SUCCESS);
}

static void
vrrpd_list(vrid_t vrid, char *ifname, int af, vrrp_ret_list_t *ret,
    size_t *sizep)
{
	vrrp_vr_t	*vr;
	char		*p = (char *)ret + sizeof (vrrp_ret_list_t);
	size_t		size = (*sizep) - sizeof (vrrp_ret_list_t);

	vrrp_log(VRRP_DBG0, "vrrpd_list(%d_%s_%s)", vrid, ifname, af_str(af));

	ret->vrl_cnt = 0;
	TAILQ_FOREACH(vr, &vrrp_vr_list, vvr_next) {
		if (vrid !=  VRRP_VRID_NONE && vr->vvr_conf.vvc_vrid != vrid)
			continue;

		if (strlen(ifname) != 0 && strcmp(ifname,
		    vr->vvr_conf.vvc_link) == 0) {
			continue;
		}

		if ((af == AF_INET || af == AF_INET6) &&
		    vr->vvr_conf.vvc_af != af)
			continue;

		if (size < VRRP_NAME_MAX) {
			vrrp_log(VRRP_DBG1, "vrrpd_list(): buffer size too "
			    "small to hold %d router names", ret->vrl_cnt);
			*sizep = sizeof (vrrp_ret_list_t);
			ret->vrl_err = VRRP_ETOOSMALL;
			return;
		}
		(void) strlcpy(p, vr->vvr_conf.vvc_name, VRRP_NAME_MAX);
		p += (strlen(vr->vvr_conf.vvc_name) + 1);
		ret->vrl_cnt++;
		size -= VRRP_NAME_MAX;
	}

	*sizep = sizeof (vrrp_ret_list_t) + ret->vrl_cnt * VRRP_NAME_MAX;
	vrrp_log(VRRP_DBG1, "vrrpd_list() return %d", ret->vrl_cnt);
	ret->vrl_err = VRRP_SUCCESS;
}

static void
vrrpd_query(const char *vn, vrrp_ret_query_t *ret, size_t *sizep)
{
	vrrp_queryinfo_t	*infop;
	vrrp_vr_t		*vr;
	vrrp_intf_t		*vif;
	vrrp_ip_t		*ip;
	struct timeval		now;
	uint32_t		vipcnt = 0;
	size_t			size = *sizep;

	vrrp_log(VRRP_DBG1, "vrrpd_query(%s)", vn);

	if ((vr = vrrpd_lookup_vr_by_name(vn)) == NULL) {
		vrrp_log(VRRP_DBG1, "vrrpd_query(): %s does not exist", vn);
		*sizep = sizeof (vrrp_ret_query_t);
		ret->vrq_err = VRRP_ENOTFOUND;
		return;
	}

	/*
	 * Get the virtual IP list if the router is not in the INIT state.
	 */
	if (vr->vvr_state != VRRP_STATE_INIT) {
		vif = vr->vvr_vif;
		TAILQ_FOREACH(ip, &vif->vvi_iplist, vip_next) {
			vipcnt++;
		}
	}

	*sizep = sizeof (vrrp_ret_query_t);
	*sizep += (vipcnt == 0) ? 0 : (vipcnt - 1) * sizeof (vrrp_addr_t);
	if (*sizep > size) {
		vrrp_log(VRRP_ERR, "vrrpd_query(): not enough space to hold "
		    "%d virtual IPs", vipcnt);
		*sizep = sizeof (vrrp_ret_query_t);
		ret->vrq_err = VRRP_ETOOSMALL;
		return;
	}

	(void) gettimeofday(&now, NULL);

	bzero(ret, *sizep);
	infop = &ret->vrq_qinfo;
	(void) memcpy(&infop->show_vi,
	    &(vr->vvr_conf), sizeof (vrrp_vr_conf_t));
	(void) memcpy(&infop->show_vs,
	    &(vr->vvr_sinfo), sizeof (vrrp_stateinfo_t));
	(void) strlcpy(infop->show_va.va_vnic, vr->vvr_vnic, MAXLINKNAMELEN);
	infop->show_vt.vt_since_last_tran = timeval_to_milli(
	    timeval_delta(now, vr->vvr_sinfo.vs_st_time));

	if (vr->vvr_state == VRRP_STATE_INIT) {
		ret->vrq_err = VRRP_SUCCESS;
		return;
	}

	vipcnt = 0;
	TAILQ_FOREACH(ip, &vif->vvi_iplist, vip_next) {
		(void) memcpy(&infop->show_va.va_vips[vipcnt++],
		    &ip->vip_addr, sizeof (vrrp_addr_t));
	}
	infop->show_va.va_vipcnt = vipcnt;

	(void) memcpy(&infop->show_va.va_primary,
	    &vr->vvr_pif->vvi_pip->vip_addr, sizeof (vrrp_addr_t));

	(void) memcpy(&infop->show_vp, &(vr->vvr_peer), sizeof (vrrp_peer_t));

	/*
	 * Check whether there is a peer.
	 */
	if (!VRRPADDR_UNSPECIFIED(vr->vvr_conf.vvc_af,
	    &(vr->vvr_peer.vp_addr))) {
		infop->show_vt.vt_since_last_adv = timeval_to_milli(
		    timeval_delta(now, vr->vvr_peer.vp_time));
	}

	if (vr->vvr_state == VRRP_STATE_BACKUP) {
		infop->show_vt.vt_master_down_intv =
		    MASTER_DOWN_INTERVAL_VR(vr);
	}

	ret->vrq_err = VRRP_SUCCESS;
}

/*
 * Build the VRRP packet (not including the IP header). Return the
 * payload length.
 *
 * If zero_pri is set to be B_TRUE, then this is the specical zero-priority
 * advertisement which is sent by the Master to indicate that it has been
 * stopped participating in VRRP.
 */
static size_t
vrrpd_build_vrrp(vrrp_vr_t *vr, uchar_t *buf, int buflen, boolean_t zero_pri)
{
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	vrrp_pkt_t	*vp = (vrrp_pkt_t *)buf;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct in_addr	*a4 = (struct in_addr *)(vp + 1);
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct in6_addr *a6 = (struct in6_addr *)(vp + 1);
	vrrp_intf_t	*vif = vr->vvr_vif;
	vrrp_ip_t	*vip;
	int		af = vif->vvi_af;
	size_t		size = sizeof (vrrp_pkt_t);
	uint16_t	rsvd_adver_int;
	int		nip = 0;

	vrrp_log(VRRP_DBG1, "vrrpd_build_vrrp(%s, %s_priority): intv %d",
	    vr->vvr_conf.vvc_name, zero_pri ? "zero" : "non-zero",
	    vr->vvr_conf.vvc_adver_int);

	TAILQ_FOREACH(vip, &vif->vvi_iplist, vip_next) {
		if ((size += ((af == AF_INET) ? sizeof (struct in_addr) :
		    sizeof (struct in6_addr))) > buflen) {
			vrrp_log(VRRP_ERR, "vrrpd_build_vrrp(%s): buffer size "
			    "not big enough %d", vr->vvr_conf.vvc_name, size);
			return (0);
		}

		if (af == AF_INET)
			a4[nip++] = vip->vip_addr.in4.sin_addr;
		else
			a6[nip++] = vip->vip_addr.in6.sin6_addr;
	}

	if (nip == 0) {
		vrrp_log(VRRP_ERR, "vrrpd_build_vrrp(%s): no virtual IP "
		    "address", vr->vvr_conf.vvc_name);
		return (0);
	}

	vp->vp_vers_type = (VRRP_VERSION << 4) | VRRP_PKT_ADVERT;
	vp->vp_vrid = vr->vvr_conf.vvc_vrid;
	vp->vp_prio = zero_pri ? VRRP_PRIO_ZERO : vr->vvr_conf.vvc_pri;

	rsvd_adver_int = MSEC2CENTISEC(vr->vvr_conf.vvc_adver_int) & 0x0fff;
	vp->vp_rsvd_adver_int = htons(rsvd_adver_int);
	vp->vp_ipnum = nip;

	/*
	 * Set the checksum to 0 first, then caculate it.
	 */
	vp->vp_chksum = 0;
	if (af == AF_INET) {
		vp->vp_chksum = vrrp_cksum4(
		    &vr->vvr_pif->vvi_pip->vip_addr.in4.sin_addr,
		    &vrrp_muladdr4.in4.sin_addr, size, vp);
	} else {
		vp->vp_chksum = vrrp_cksum6(
		    &vr->vvr_pif->vvi_pip->vip_addr.in6.sin6_addr,
		    &vrrp_muladdr6.in6.sin6_addr, size, vp);
	}

	return (size);
}

/*
 * We need to build the IPv4 header on our own.
 */
static vrrp_err_t
vrrpd_send_adv_v4(vrrp_vr_t *vr, uchar_t *buf, size_t len, boolean_t zero_pri)
{
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct ip *ip = (struct ip *)buf;
	size_t plen;

	vrrp_log(VRRP_DBG1, "vrrpd_send_adv_v4(%s)", vr->vvr_conf.vvc_name);

	if ((plen = vrrpd_build_vrrp(vr, buf + sizeof (struct ip),
	    len - sizeof (struct ip), zero_pri)) == 0) {
		return (VRRP_ETOOSMALL);
	}

	ip->ip_hl = sizeof (struct ip) >> 2;
	ip->ip_v = IPV4_VERSION;
	ip->ip_tos = 0;
	plen += sizeof (struct ip);
	ip->ip_len = htons(plen);
	ip->ip_off = 0;
	ip->ip_ttl = VRRP_IP_TTL;
	ip->ip_p = IPPROTO_VRRP;
	ip->ip_src = vr->vvr_pif->vvi_pip->vip_addr.in4.sin_addr;
	ip->ip_dst = vrrp_muladdr4.in4.sin_addr;

	/*
	 * The kernel will set the IP cksum and the IPv4 identification.
	 */
	ip->ip_id = 0;
	ip->ip_sum = 0;

	if ((len = sendto(vr->vvr_vif->vvi_sockfd, buf, plen, 0,
	    (const struct sockaddr *)&vrrp_muladdr4,
	    sizeof (struct sockaddr_in))) != plen) {
		vrrp_log(VRRP_ERR, "vrrpd_send_adv_v4(): sendto() on "
		    "(vrid:%d, %s, %s) failed: %s sent:%d expect:%d",
		    vr->vvr_conf.vvc_vrid, vr->vvr_vif->vvi_ifname,
		    af_str(vr->vvr_conf.vvc_af), strerror(errno), len, plen);
		return (VRRP_ESYS);
	}

	vrrp_log(VRRP_DBG1, "vrrpd_send_adv_v4(%s) succeed",
	    vr->vvr_conf.vvc_name);
	return (VRRP_SUCCESS);
}

static vrrp_err_t
vrrpd_send_adv_v6(vrrp_vr_t *vr, uchar_t *buf, size_t len, boolean_t zero_pri)
{
	struct msghdr msg6;
	size_t hoplimit_space = 0;
	size_t pktinfo_space = 0;
	size_t bufspace = 0;
	struct in6_pktinfo *pktinfop;
	struct cmsghdr *cmsgp;
	uchar_t *cmsg_datap;
	struct iovec iov;
	size_t plen;

	vrrp_log(VRRP_DBG1, "vrrpd_send_adv_v6(%s)", vr->vvr_conf.vvc_name);

	if ((plen = vrrpd_build_vrrp(vr, buf, len, zero_pri)) == 0)
		return (VRRP_ETOOSMALL);

	msg6.msg_control = NULL;
	msg6.msg_controllen = 0;

	hoplimit_space = sizeof (int);
	bufspace += sizeof (struct cmsghdr) + _MAX_ALIGNMENT +
	    hoplimit_space + _MAX_ALIGNMENT;

	pktinfo_space = sizeof (struct in6_pktinfo);
	bufspace += sizeof (struct cmsghdr) + _MAX_ALIGNMENT +
	    pktinfo_space + _MAX_ALIGNMENT;

	/*
	 * We need to temporarily set the msg6.msg_controllen to bufspace
	 * (we will later trim it to actual length used). This is needed because
	 * CMSG_NXTHDR() uses it to check we have not exceeded the bounds.
	 */
	bufspace += sizeof (struct cmsghdr);
	msg6.msg_controllen = bufspace;

	msg6.msg_control = (struct cmsghdr *)malloc(bufspace);
	if (msg6.msg_control == NULL) {
		vrrp_log(VRRP_ERR, "vrrpd_send_adv_v6(%s): memory allocation "
		    "failed: %s", vr->vvr_conf.vvc_name, strerror(errno));
		return (VRRP_ENOMEM);
	}

	cmsgp = CMSG_FIRSTHDR(&msg6);

	cmsgp->cmsg_level = IPPROTO_IPV6;
	cmsgp->cmsg_type = IPV6_HOPLIMIT;
	cmsg_datap = CMSG_DATA(cmsgp);
	/* LINTED */
	*(int *)cmsg_datap = VRRP_IP_TTL;
	cmsgp->cmsg_len = cmsg_datap + hoplimit_space - (uchar_t *)cmsgp;
	cmsgp = CMSG_NXTHDR(&msg6, cmsgp);

	cmsgp->cmsg_level = IPPROTO_IPV6;
	cmsgp->cmsg_type = IPV6_PKTINFO;
	cmsg_datap = CMSG_DATA(cmsgp);

	/* LINTED */
	pktinfop = (struct in6_pktinfo *)cmsg_datap;
	/*
	 * We don't know if pktinfop->ipi6_addr is aligned properly,
	 * therefore let's use bcopy, instead of assignment.
	 */
	(void) bcopy(&vr->vvr_pif->vvi_pip->vip_addr.in6.sin6_addr,
	    &pktinfop->ipi6_addr, sizeof (struct in6_addr));

	/*
	 *  We can assume pktinfop->ipi6_ifindex is 32 bit aligned.
	 */
	pktinfop->ipi6_ifindex = vr->vvr_vif->vvi_ifindex;
	cmsgp->cmsg_len = cmsg_datap + pktinfo_space - (uchar_t *)cmsgp;
	cmsgp = CMSG_NXTHDR(&msg6, cmsgp);
	msg6.msg_controllen = (char *)cmsgp - (char *)msg6.msg_control;

	msg6.msg_name = &vrrp_muladdr6;
	msg6.msg_namelen = sizeof (struct sockaddr_in6);

	iov.iov_base = buf;
	iov.iov_len = plen;
	msg6.msg_iov = &iov;
	msg6.msg_iovlen = 1;

	if ((len = sendmsg(vr->vvr_vif->vvi_sockfd,
	    (const struct msghdr *)&msg6, 0)) != plen) {
		vrrp_log(VRRP_ERR, "vrrpd_send_adv_v6(%s): sendmsg() failed: "
		    "%s expect %d sent %d", vr->vvr_conf.vvc_name,
		    strerror(errno), plen, len);
		(void) free(msg6.msg_control);
		return (VRRP_ESYS);
	}

	vrrp_log(VRRP_DBG1, "vrrpd_send_adv_v6(%s) succeed",
	    vr->vvr_conf.vvc_name);
	(void) free(msg6.msg_control);
	return (VRRP_SUCCESS);
}

/*
 * Send the VRRP advertisement packets.
 */
static vrrp_err_t
vrrpd_send_adv(vrrp_vr_t *vr, boolean_t zero_pri)
{
	uint64_t buf[(IP_MAXPACKET + 1)/8];

	vrrp_log(VRRP_DBG1, "vrrpd_send_adv(%s, %s_priority)",
	    vr->vvr_conf.vvc_name, zero_pri ? "zero" : "non_zero");

	assert(vr->vvr_pif->vvi_pip != NULL);

	if (vr->vvr_pif->vvi_pip == NULL) {
		vrrp_log(VRRP_DBG0, "vrrpd_send_adv(%s): no primary IP "
		    "address", vr->vvr_conf.vvc_name);
		return (VRRP_EINVAL);
	}

	if (vr->vvr_conf.vvc_af == AF_INET) {
		return (vrrpd_send_adv_v4(vr, (uchar_t *)buf,
		    sizeof (buf), zero_pri));
	} else {
		return (vrrpd_send_adv_v6(vr, (uchar_t *)buf,
		    sizeof (buf), zero_pri));
	}
}

static void
vrrpd_process_adv(vrrp_vr_t *vr, vrrp_addr_t *from, vrrp_pkt_t *vp)
{
	vrrp_vr_conf_t *conf = &vr->vvr_conf;
	char		peer[INET6_ADDRSTRLEN];
	char		local[INET6_ADDRSTRLEN];
	int		addr_cmp;
	uint16_t	peer_adver_int;

	/* LINTED E_CONSTANT_CONDITION */
	VRRPADDR2STR(vr->vvr_conf.vvc_af, from, peer, INET6_ADDRSTRLEN,
	    _B_FALSE);
	vrrp_log(VRRP_DBG1, "vrrpd_process_adv(%s) from %s", conf->vvc_name,
	    peer);

	if (vr->vvr_state <= VRRP_STATE_INIT) {
		vrrp_log(VRRP_DBG1, "vrrpd_process_adv(%s): state: %s, not "
		    "ready", conf->vvc_name, vrrp_state2str(vr->vvr_state));
		return;
	}

	peer_adver_int = CENTISEC2MSEC(ntohs(vp->vp_rsvd_adver_int) & 0x0fff);

	/* LINTED E_CONSTANT_CONDITION */
	VRRPADDR2STR(vr->vvr_pif->vvi_af, &vr->vvr_pif->vvi_pip->vip_addr,
	    local, INET6_ADDRSTRLEN, _B_FALSE);
	vrrp_log(VRRP_DBG1, "vrrpd_process_adv(%s): local/state/pri"
	    "(%s/%s/%d) peer/pri/intv(%s/%d/%d)", conf->vvc_name, local,
	    vrrp_state2str(vr->vvr_state), conf->vvc_pri, peer,
	    vp->vp_prio, peer_adver_int);

	addr_cmp = ipaddr_cmp(vr->vvr_pif->vvi_af, from,
	    &vr->vvr_pif->vvi_pip->vip_addr);
	if (addr_cmp == 0) {
		vrrp_log(VRRP_DBG1, "vrrpd_process_adv(%s): local message",
		    conf->vvc_name);
		return;
	} else if (conf->vvc_pri == vp->vp_prio) {
		vrrp_log(VRRP_DBG1, "vrrpd_process_adv(%s): peer IP %s is %s"
		    " than the local IP %s", conf->vvc_name, peer,
		    addr_cmp > 0 ? "greater" : "less", local);
	}

	if (conf->vvc_pri == 255) {
		vrrp_log(VRRP_ERR, "vrrpd_process_adv(%s): virtual address "
		    "owner received advertisement from %s", conf->vvc_name,
		    peer);
		return;
	}

	(void) gettimeofday(&vr->vvr_peer_time, NULL);
	(void) memcpy(&vr->vvr_peer_addr, from, sizeof (vrrp_addr_t));
	vr->vvr_peer_prio = vp->vp_prio;
	vr->vvr_peer_adver_int = peer_adver_int;

	if (vr->vvr_state == VRRP_STATE_BACKUP) {
		vr->vvr_master_adver_int = vr->vvr_peer_adver_int;
		if ((vp->vp_prio == VRRP_PRIO_ZERO) ||
		    (conf->vvc_preempt == _B_FALSE ||
		    vp->vp_prio >= conf->vvc_pri)) {
			(void) iu_cancel_timer(vrrpd_timerq,
			    vr->vvr_timer_id, NULL);
			if (vp->vp_prio == VRRP_PRIO_ZERO) {
				/* the master stops participating in VRRP */
				vr->vvr_timeout = SKEW_TIME_VR(vr);
			} else {
				vr->vvr_timeout = MASTER_DOWN_INTERVAL_VR(vr);
			}
			if ((vr->vvr_timer_id = iu_schedule_timer_ms(
			    vrrpd_timerq, vr->vvr_timeout, vrrp_b2m_timeout,
			    vr)) == -1) {
				vrrp_log(VRRP_ERR, "vrrpd_process_adv(%s): "
				    "start vrrp_b2m_timeout(%d) failed",
				    conf->vvc_name, vr->vvr_timeout);
			} else {
				vrrp_log(VRRP_DBG1, "vrrpd_process_adv(%s): "
				    "start vrrp_b2m_timeout(%d)",
				    conf->vvc_name, vr->vvr_timeout);
			}
		}
	} else if (vr->vvr_state == VRRP_STATE_MASTER) {
		if (vp->vp_prio == VRRP_PRIO_ZERO) {
			(void) vrrpd_send_adv(vr, _B_FALSE);
			(void) iu_cancel_timer(vrrpd_timerq,
			    vr->vvr_timer_id, NULL);
			if ((vr->vvr_timer_id = iu_schedule_timer_ms(
			    vrrpd_timerq, vr->vvr_timeout, vrrp_adv_timeout,
			    vr)) == -1) {
				vrrp_log(VRRP_ERR, "vrrpd_process_adv(%s): "
				    "start vrrp_adv_timeout(%d) failed",
				    conf->vvc_name, vr->vvr_timeout);
			} else {
				vrrp_log(VRRP_DBG1, "vrrpd_process_adv(%s): "
				    "start vrrp_adv_timeout(%d)",
				    conf->vvc_name, vr->vvr_timeout);
			}
		} else if (vp->vp_prio > conf->vvc_pri ||
		    (vp->vp_prio == conf->vvc_pri && addr_cmp > 0)) {
			(void) vrrpd_state_m2b(vr);
		}
	} else {
		assert(_B_FALSE);
	}
}

static vrrp_err_t
vrrpd_process_vrrp(vrrp_intf_t *pif, vrrp_pkt_t *vp, size_t len,
    vrrp_addr_t *from)
{
	vrrp_vr_t	*vr;
	uint8_t		vers_type;
	uint16_t	saved_cksum, cksum;
	char		peer[INET6_ADDRSTRLEN];

	/* LINTED E_CONSTANT_CONDITION */
	VRRPADDR2STR(pif->vvi_af, from, peer, INET6_ADDRSTRLEN, _B_FALSE);
	vrrp_log(VRRP_DBG0, "vrrpd_process_vrrp(%s) from %s", pif->vvi_ifname,
	    peer);

	if (len < sizeof (vrrp_pkt_t)) {
		vrrp_log(VRRP_ERR, "vrrpd_process_vrrp(%s): invalid message "
		    "length %d", len);
		return (VRRP_EINVAL);
	}

	/*
	 * Verify: VRRP version number and packet type.
	 */
	vers_type = ((vp->vp_vers_type & VRRP_VER_MASK) >> 4);
	if (vers_type != VRRP_VERSION) {
		vrrp_log(VRRP_ERR, "vrrpd_process_vrrp(%s) unsupported "
		    "version %d", pif->vvi_ifname, vers_type);
		return (VRRP_EINVAL);
	}

	if (vp->vp_ipnum == 0) {
		vrrp_log(VRRP_ERR, "vrrpd_process_vrrp(%s): zero IPvX count",
		    pif->vvi_ifname);
		return (VRRP_EINVAL);
	}

	if (len - sizeof (vrrp_pkt_t) !=
	    vp->vp_ipnum * (pif->vvi_af == AF_INET ? sizeof (struct in_addr) :
	    sizeof (struct in6_addr))) {
		vrrp_log(VRRP_ERR, "vrrpd_process_vrrp(%s): invalid IPvX count"
		    " %d", pif->vvi_ifname, vp->vp_ipnum);
		return (VRRP_EINVAL);
	}

	vers_type = (vp->vp_vers_type & VRRP_TYPE_MASK);

	/*
	 * verify: VRRP checksum. Note that vrrp_cksum returns network byte
	 * order checksum value;
	 */
	saved_cksum = vp->vp_chksum;
	vp->vp_chksum = 0;
	if (pif->vvi_af == AF_INET) {
		cksum = vrrp_cksum4(&from->in4.sin_addr,
		    &vrrp_muladdr4.in4.sin_addr, len, vp);
	} else {
		cksum = vrrp_cksum6(&from->in6.sin6_addr,
		    &vrrp_muladdr6.in6.sin6_addr, len, vp);
	}

	if (cksum != saved_cksum) {
		vrrp_log(VRRP_ERR, "vrrpd_process_vrrp(%s) invalid "
		    "checksum: expected/real(0x%x/0x%x)", pif->vvi_ifname,
		    cksum, saved_cksum);
		return (VRRP_EINVAL);
	}

	if ((vr = vrrpd_lookup_vr_by_vrid(pif->vvi_ifname, vp->vp_vrid,
	    pif->vvi_af)) != NULL && vers_type == VRRP_PKT_ADVERT) {
		vrrpd_process_adv(vr, from, vp);
	} else {
		vrrp_log(VRRP_DBG1, "vrrpd_process_vrrp(%s) VRID(%d/%s) "
		    "not configured", pif->vvi_ifname, vp->vp_vrid,
		    af_str(pif->vvi_af));
	}
	return (VRRP_SUCCESS);
}

/*
 * IPv4 socket, the IPv4 header is included.
 */
static vrrp_err_t
vrrpd_process_adv_v4(vrrp_intf_t *pif, struct msghdr *msgp, size_t len)
{
	char		abuf[INET6_ADDRSTRLEN];
	struct ip	*ip;

	vrrp_log(VRRP_DBG0, "vrrpd_process_adv_v4(%s, %d)",
	    pif->vvi_ifname, len);

	ip = (struct ip *)msgp->msg_iov->iov_base;

	/* Sanity check */
	if (len < sizeof (struct ip) || len < ntohs(ip->ip_len)) {
		vrrp_log(VRRP_ERR, "vrrpd_process_adv_v4(%s): invalid length "
		    "%d", pif->vvi_ifname, len);
		return (VRRP_EINVAL);
	}

	assert(ip->ip_v == IPV4_VERSION);
	assert(ip->ip_p == IPPROTO_VRRP);
	assert(msgp->msg_namelen == sizeof (struct sockaddr_in));

	if (vrrp_muladdr4.in4.sin_addr.s_addr != ip->ip_dst.s_addr) {
		vrrp_log(VRRP_ERR, "vrrpd_process_adv_v4(%s): invalid "
		    "destination %s", pif->vvi_ifname,
		    inet_ntop(pif->vvi_af, &(ip->ip_dst), abuf, sizeof (abuf)));
		return (VRRP_EINVAL);
	}

	if (ip->ip_ttl != VRRP_IP_TTL) {
		vrrp_log(VRRP_ERR, "vrrpd_process_adv_v4(%s): invalid "
		    "ttl %d", pif->vvi_ifname, ip->ip_ttl);
		return (VRRP_EINVAL);
	}

	/*
	 * Note that the ip_len contains only the IP payload length.
	 */
	return (vrrpd_process_vrrp(pif,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (vrrp_pkt_t *)((char *)ip + ip->ip_hl * 4), ntohs(ip->ip_len),
	    (vrrp_addr_t *)msgp->msg_name));
}

/*
 * IPv6 socket, check the ancillary_data.
 */
static vrrp_err_t
vrrpd_process_adv_v6(vrrp_intf_t *pif, struct msghdr *msgp, size_t len)
{
	struct cmsghdr		*cmsgp;
	uchar_t			*cmsg_datap;
	struct in6_pktinfo	*pktinfop;
	char			abuf[INET6_ADDRSTRLEN];
	int			ttl;

	vrrp_log(VRRP_DBG1, "vrrpd_process_adv_v6(%s, %d)",
	    pif->vvi_ifname, len);

	/* Sanity check */
	if (len < sizeof (vrrp_pkt_t)) {
		vrrp_log(VRRP_ERR, "vrrpd_process_adv_v6(%s): invalid length "
		    "%d", pif->vvi_ifname, len);
		return (VRRP_EINVAL);
	}

	assert(msgp->msg_namelen == sizeof (struct sockaddr_in6));

	for (cmsgp = CMSG_FIRSTHDR(msgp); cmsgp != NULL;
	    cmsgp = CMSG_NXTHDR(msgp, cmsgp)) {
		assert(cmsgp->cmsg_level == IPPROTO_IPV6);
		cmsg_datap = CMSG_DATA(cmsgp);

		switch (cmsgp->cmsg_type) {
		case IPV6_HOPLIMIT:
			/* LINTED E_BAD_PTR_CAST_ALIGN */
			if ((ttl = *(int *)cmsg_datap) == VRRP_IP_TTL)
				break;

			vrrp_log(VRRP_ERR, "vrrpd_process_adv_v4(%s): invalid "
			    "ttl %d", pif->vvi_ifname, ttl);
			return (VRRP_EINVAL);
		case IPV6_PKTINFO:
			/* LINTED E_BAD_PTR_CAST_ALIGN */
			pktinfop = (struct in6_pktinfo *)cmsg_datap;
			if (IN6_ARE_ADDR_EQUAL(&pktinfop->ipi6_addr,
			    &vrrp_muladdr6.in6.sin6_addr)) {
				break;
			}

			vrrp_log(VRRP_ERR, "vrrpd_process_adv_v4(%s): invalid "
			    "destination %s", pif->vvi_ifname,
			    inet_ntop(pif->vvi_af, &pktinfop->ipi6_addr, abuf,
			    sizeof (abuf)));
			return (VRRP_EINVAL);
		}
	}

	return (vrrpd_process_vrrp(pif, msgp->msg_iov->iov_base, len,
	    msgp->msg_name));
}

/* ARGSUSED */
static void
vrrpd_sock_handler(iu_eh_t *eh, int s, short events, iu_event_id_t id,
    void *arg)
{
	struct msghdr		msg;
	vrrp_addr_t		from;
	uint64_t		buf[(IP_MAXPACKET + 1)/8];
	uint64_t		ancillary_data[(IP_MAXPACKET + 1)/8];
	vrrp_intf_t		*pif = arg;
	int			af = pif->vvi_af;
	int			len;
	struct iovec		iov;

	vrrp_log(VRRP_DBG1, "vrrpd_sock_handler(%s)", pif->vvi_ifname);

	msg.msg_name = (struct sockaddr *)&from;
	msg.msg_namelen = (af == AF_INET) ? sizeof (struct sockaddr_in) :
	    sizeof (struct sockaddr_in6);
	iov.iov_base = (char *)buf;
	iov.iov_len = sizeof (buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ancillary_data;
	msg.msg_controllen = sizeof (ancillary_data);

	if ((len = recvmsg(s, &msg, 0)) == -1) {
		vrrp_log(VRRP_ERR, "vrrpd_sock_handler() recvmsg(%s) "
		    "failed: %s", pif->vvi_ifname, strerror(errno));
		return;
	}

	/*
	 * Ignore packets whose control buffers that don't fit
	 */
	if (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) {
		vrrp_log(VRRP_ERR, "vrrpd_sock_handler() %s buffer not "
		    "big enough", pif->vvi_ifname);
		return;
	}

	if (af == AF_INET)
		(void) vrrpd_process_adv_v4(pif, &msg, len);
	else
		(void) vrrpd_process_adv_v6(pif, &msg, len);
}

/*
 * Create the socket which is used to receive VRRP packets. Virtual routers
 * that configured on the same physical interface share the same socket.
 */
static vrrp_err_t
vrrpd_init_rxsock(vrrp_vr_t *vr)
{
	vrrp_intf_t *pif;	/* Physical interface used to recv packets */
	struct group_req greq;
	struct sockaddr_storage *muladdr;
	int af, proto;
	int on = 1;
	vrrp_err_t err = VRRP_SUCCESS;

	vrrp_log(VRRP_DBG1, "vrrpd_init_rxsock(%s)", vr->vvr_conf.vvc_name);

	/*
	 * The RX sockets may already been initialized.
	 */
	if ((pif = vr->vvr_pif) != NULL) {
		vrrp_log(VRRP_DBG1, "vrrpd_init_rxsock(%s) already done on %s",
		    vr->vvr_conf.vvc_name, pif->vvi_ifname);
		assert(pif->vvi_sockfd != -1);
		return (VRRP_SUCCESS);
	}

	/*
	 * If no IP addresses configured on the primary interface,
	 * return failure.
	 */
	af = vr->vvr_conf.vvc_af;
	pif = vrrpd_lookup_if(vr->vvr_conf.vvc_link, af);
	if (pif == NULL) {
		vrrp_log(VRRP_DBG1, "vrrpd_init_rxsock(%s): no IP address "
		    "over %s/%s", vr->vvr_conf.vvc_name,
		    vr->vvr_conf.vvc_link, af_str(af));
		return (VRRP_ENOPRIM);
	}

	proto = (af == AF_INET ? IPPROTO_IP : IPPROTO_IPV6);
	if (pif->vvi_nvr++ == 0) {
		assert(pif->vvi_sockfd < 0);
		pif->vvi_sockfd = socket(af, SOCK_RAW, IPPROTO_VRRP);
		if (pif->vvi_sockfd < 0) {
			vrrp_log(VRRP_ERR, "vrrpd_init_rxsock(%s): socket() "
			    "failed %s", vr->vvr_conf.vvc_name,
			    strerror(errno));
			err = VRRP_ESYS;
			goto done;
		}

		/*
		 * Join the multicast group to receive VRRP packets.
		 */
		if (af == AF_INET) {
			muladdr = (struct sockaddr_storage *)
			    (void *)&vrrp_muladdr4;
		} else {
			muladdr = (struct sockaddr_storage *)
			    (void *)&vrrp_muladdr6;
		}

		greq.gr_interface = pif->vvi_ifindex;
		(void) memcpy(&greq.gr_group, muladdr,
		    sizeof (struct sockaddr_storage));
		if (setsockopt(pif->vvi_sockfd, proto, MCAST_JOIN_GROUP, &greq,
		    sizeof (struct group_req)) < 0) {
			vrrp_log(VRRP_ERR, "vrrpd_init_rxsock(%s): "
			    "join_group(%d) failed: %s", vr->vvr_conf.vvc_name,
			    pif->vvi_ifindex, strerror(errno));
			err = VRRP_ESYS;
			goto done;
		} else {
			vrrp_log(VRRP_DBG1, "vrrpd_init_rxsock(%s): "
			    "join_group(%d) succeeded", vr->vvr_conf.vvc_name,
			    pif->vvi_ifindex);
		}

		/*
		 * Unlike IPv4, the IPv6 raw socket does not pass the IP header
		 * when a packet is received. Call setsockopt() to receive such
		 * information.
		 */
		if (af == AF_INET6) {
			/*
			 * Enable receipt of destination address info
			 */
			if (setsockopt(pif->vvi_sockfd, proto, IPV6_RECVPKTINFO,
			    (char *)&on, sizeof (on)) < 0) {
				vrrp_log(VRRP_ERR, "vrrpd_init_rxsock(%s): "
				    "enable recvpktinfo failed: %s",
				    vr->vvr_conf.vvc_name, strerror(errno));
				err = VRRP_ESYS;
				goto done;
			}

			/*
			 * Enable receipt of hoplimit info
			 */
			if (setsockopt(pif->vvi_sockfd, proto,
			    IPV6_RECVHOPLIMIT, (char *)&on, sizeof (on)) < 0) {
				vrrp_log(VRRP_ERR, "vrrpd_init_rxsock(%s): "
				    "enable recvhoplimit failed: %s",
				    vr->vvr_conf.vvc_name, strerror(errno));
				err = VRRP_ESYS;
				goto done;
			}
		}

		if ((pif->vvi_eid = iu_register_event(vrrpd_eh,
		    pif->vvi_sockfd, POLLIN, vrrpd_sock_handler, pif)) == -1) {
			vrrp_log(VRRP_ERR, "vrrpd_init_rxsock(%s): "
			    "iu_register_event() failed",
			    vr->vvr_conf.vvc_name);
			err = VRRP_ESYS;
			goto done;
		}
	} else {
		vrrp_log(VRRP_DBG1, "vrrpd_init_rxsock(%s) over %s already "
		    "done %d", vr->vvr_conf.vvc_name, pif->vvi_ifname,
		    pif->vvi_nvr);
		assert(IS_PRIMARY_INTF(pif));
	}

done:
	vr->vvr_pif = pif;
	if (err != VRRP_SUCCESS)
		vrrpd_fini_rxsock(vr);

	return (err);
}

/*
 * Delete the socket which is used to receive VRRP packets for the given
 * VRRP router. Since all virtual routers that configured on the same
 * physical interface share the same socket, the socket is only closed
 * when the last VRRP router share this socket is deleted.
 */
static void
vrrpd_fini_rxsock(vrrp_vr_t *vr)
{
	vrrp_intf_t	*pif = vr->vvr_pif;

	vrrp_log(VRRP_DBG1, "vrrpd_fini_rxsock(%s)", vr->vvr_conf.vvc_name);

	if (pif == NULL)
		return;

	if (--pif->vvi_nvr == 0) {
		vrrp_log(VRRP_DBG1, "vrrpd_fini_rxsock(%s) over %s",
		    vr->vvr_conf.vvc_name, pif->vvi_ifname);
		(void) iu_unregister_event(vrrpd_eh, pif->vvi_eid, NULL);
		(void) close(pif->vvi_sockfd);
		pif->vvi_pip = NULL;
		pif->vvi_sockfd = -1;
		pif->vvi_eid = -1;
	} else {
		vrrp_log(VRRP_DBG1, "vrrpd_fini_rxsock(%s) over %s %d",
		    vr->vvr_conf.vvc_name, pif->vvi_ifname, pif->vvi_nvr);
	}
	vr->vvr_pif = NULL;
}

/*
 * Create the socket which is used to send VRRP packets. Further, set
 * the IFF_NOACCEPT flag based on the VRRP router's accept mode.
 */
static vrrp_err_t
vrrpd_init_txsock(vrrp_vr_t *vr)
{
	int		af;
	vrrp_intf_t	*vif;
	vrrp_err_t	err;

	vrrp_log(VRRP_DBG1, "vrrpd_init_txsock(%s)", vr->vvr_conf.vvc_name);

	if (vr->vvr_vif != NULL) {
		vrrp_log(VRRP_DBG1, "vrrpd_init_txsock(%s) already done on %s",
		    vr->vvr_conf.vvc_name, vr->vvr_vif->vvi_ifname);
		return (VRRP_SUCCESS);
	}

	af = vr->vvr_conf.vvc_af;
	if ((vif = vrrpd_lookup_if(vr->vvr_vnic, af)) == NULL) {
		vrrp_log(VRRP_DBG1, "vrrpd_init_txsock(%s) no IP address over "
		    "%s/%s", vr->vvr_conf.vvc_name, vr->vvr_vnic, af_str(af));
		return (VRRP_ENOVIRT);
	}

	vr->vvr_vif = vif;
	if (vr->vvr_conf.vvc_af == AF_INET)
		err = vrrpd_init_txsock_v4(vr);
	else
		err = vrrpd_init_txsock_v6(vr);

	if (err != VRRP_SUCCESS)
		goto done;

	/*
	 * The interface should start with IFF_NOACCEPT flag not set, only
	 * call this function when the VRRP router requires IFF_NOACCEPT.
	 */
	if (!vr->vvr_conf.vvc_accept)
		err = vrrpd_set_noaccept(vr, _B_TRUE);

done:
	if (err != VRRP_SUCCESS) {
		(void) close(vif->vvi_sockfd);
		vif->vvi_sockfd = -1;
		vr->vvr_vif = NULL;
	}

	return (err);
}

/*
 * Create the IPv4 socket which is used to send VRRP packets. Note that
 * the destination MAC address of VRRP advertisement must be the virtual
 * MAC address, so we specify the output interface to be the specific VNIC.
 */
static vrrp_err_t
vrrpd_init_txsock_v4(vrrp_vr_t *vr)
{
	vrrp_intf_t *vif;	/* VNIC interface used to send packets */
	vrrp_ip_t *vip;		/* The first IP over the VNIC */
	int on = 1;
	char off = 0;
	vrrp_err_t err = VRRP_SUCCESS;
	char abuf[INET6_ADDRSTRLEN];

	vif = vr->vvr_vif;
	assert(vr->vvr_conf.vvc_af == AF_INET);
	assert(vif != NULL);

	vrrp_log(VRRP_DBG1, "vrrpd_init_txsock_v4(%s) over %s",
	    vr->vvr_conf.vvc_name, vif->vvi_ifname);

	if (vif->vvi_sockfd != -1) {
		vrrp_log(VRRP_DBG1, "vrrpd_init_txsock_v4(%s) already done "
		    "over %s", vr->vvr_conf.vvc_name, vif->vvi_ifname);
		return (VRRP_SUCCESS);
	}

	vif->vvi_sockfd = socket(vif->vvi_af, SOCK_RAW, IPPROTO_VRRP);
	if (vif->vvi_sockfd < 0) {
		vrrp_log(VRRP_ERR, "vrrpd_init_txsock_v4(%s): socket() "
		    "failed: %s", vr->vvr_conf.vvc_name, strerror(errno));
		err = VRRP_ESYS;
		goto done;
	}

	/*
	 * Include the IP header, so that we can specify the IP address/ttl.
	 */
	if (setsockopt(vif->vvi_sockfd, IPPROTO_IP, IP_HDRINCL, (char *)&on,
	    sizeof (on)) < 0) {
		vrrp_log(VRRP_ERR, "vrrpd_init_txsock_v4(%s): ip_hdrincl "
		    "failed: %s", vr->vvr_conf.vvc_name, strerror(errno));
		err = VRRP_ESYS;
		goto done;
	}

	/*
	 * Disable multicast loopback.
	 */
	if (setsockopt(vif->vvi_sockfd, IPPROTO_IP, IP_MULTICAST_LOOP, &off,
	    sizeof (char)) == -1) {
		vrrp_log(VRRP_ERR, "vrrpd_init_txsock_v4(%s): disable "
		    "multicast_loop failed: %s", vr->vvr_conf.vvc_name,
		    strerror(errno));
		err = VRRP_ESYS;
		goto done;
	}

	vip = TAILQ_FIRST(&vif->vvi_iplist);
	/* LINTED E_CONSTANT_CONDITION */
	VRRPADDR2STR(vif->vvi_af, &vip->vip_addr, abuf, INET6_ADDRSTRLEN,
	    _B_FALSE);

	/*
	 * Set the output interface to send the VRRP packet.
	 */
	if (setsockopt(vif->vvi_sockfd, IPPROTO_IP, IP_MULTICAST_IF,
	    &vip->vip_addr.in4.sin_addr, sizeof (struct in_addr)) < 0) {
		vrrp_log(VRRP_ERR, "vrrpd_init_txsock_v4(%s): multcast_if(%s) "
		    "failed: %s", vr->vvr_conf.vvc_name, abuf, strerror(errno));
		err = VRRP_ESYS;
	} else {
		vrrp_log(VRRP_DBG0, "vrrpd_init_txsock_v4(%s): multcast_if(%s) "
		    "succeed", vr->vvr_conf.vvc_name, abuf);
	}

done:
	if (err != VRRP_SUCCESS) {
		(void) close(vif->vvi_sockfd);
		vif->vvi_sockfd = -1;
	}

	return (err);
}

/*
 * Create the IPv6 socket which is used to send VRRP packets. Note that
 * the destination must be the virtual MAC address, so we specify the output
 * interface to be the specific VNIC.
 */
static vrrp_err_t
vrrpd_init_txsock_v6(vrrp_vr_t *vr)
{
	vrrp_intf_t *vif;	/* VNIC interface used to send packets */
	int off = 0, ttl = VRRP_IP_TTL;
	vrrp_err_t err = VRRP_SUCCESS;

	vif = vr->vvr_vif;
	assert(vr->vvr_conf.vvc_af == AF_INET6);
	assert(vif != NULL);

	vrrp_log(VRRP_DBG1, "vrrpd_init_txsock_v6(%s) over %s",
	    vr->vvr_conf.vvc_name, vif->vvi_ifname);

	if (vif->vvi_sockfd != -1) {
		vrrp_log(VRRP_DBG1, "vrrpd_init_txsock_v6(%s) already done "
		    "over %s", vr->vvr_conf.vvc_name, vif->vvi_ifname);
		return (VRRP_SUCCESS);
	}

	vif->vvi_sockfd = socket(vif->vvi_af, SOCK_RAW, IPPROTO_VRRP);
	if (vif->vvi_sockfd < 0) {
		vrrp_log(VRRP_ERR, "vrrpd_init_txsock_v6(%s): socket() "
		    "failed: %s", vr->vvr_conf.vvc_name, strerror(errno));
		err = VRRP_ESYS;
		goto done;
	}

	/*
	 * Disable multicast loopback.
	 */
	if (setsockopt(vif->vvi_sockfd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
	    &off, sizeof (int)) == -1) {
		vrrp_log(VRRP_ERR, "vrrpd_init_txsock_v6(%s): disable "
		    "multicast_loop failed: %s", vr->vvr_conf.vvc_name,
		    strerror(errno));
		err = VRRP_ESYS;
		goto done;
	}

	/*
	 * Set the multicast TTL.
	 */
	if (setsockopt(vif->vvi_sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
	    &ttl, sizeof (int)) == -1) {
		vrrp_log(VRRP_ERR, "vrrpd_init_txsock_v6(%s): enable "
		    "multicast_hops %d failed: %s", vr->vvr_conf.vvc_name,
		    ttl, strerror(errno));
		err = VRRP_ESYS;
		goto done;
	}

	/*
	 * Set the output interface to send the VRRP packet.
	 */
	if (setsockopt(vif->vvi_sockfd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
	    &vif->vvi_ifindex, sizeof (uint32_t)) < 0) {
		vrrp_log(VRRP_ERR, "vrrpd_init_txsock_v6(%s): multicast_if(%d) "
		    "failed: %s", vr->vvr_conf.vvc_name, vif->vvi_ifindex,
		    strerror(errno));
		err = VRRP_ESYS;
	} else {
		vrrp_log(VRRP_DBG1, "vrrpd_init_txsock_v6(%s): multicast_if(%d)"
		    " succeed", vr->vvr_conf.vvc_name, vif->vvi_ifindex);
	}

done:
	if (err != VRRP_SUCCESS) {
		(void) close(vif->vvi_sockfd);
		vif->vvi_sockfd = -1;
	}

	return (err);
}

/*
 * Delete the socket which is used to send VRRP packets. Further, clear
 * the IFF_NOACCEPT flag based on the VRRP router's accept mode.
 */
static void
vrrpd_fini_txsock(vrrp_vr_t *vr)
{
	vrrp_intf_t *vif = vr->vvr_vif;

	vrrp_log(VRRP_DBG1, "vrrpd_fini_txsock(%s)", vr->vvr_conf.vvc_name);

	if (vif != NULL) {
		if (!vr->vvr_conf.vvc_accept)
			(void) vrrpd_set_noaccept(vr, _B_FALSE);
		(void) close(vif->vvi_sockfd);
		vif->vvi_sockfd = -1;
		vr->vvr_vif = NULL;
	}
}

/*
 * Given the the pseudo header cksum value (sum), caculate the cksum with
 * the rest of VRRP packet.
 */
static uint16_t
in_cksum(int sum, uint16_t plen, void *p)
{
	int nleft;
	uint16_t *w;
	uint16_t answer;
	uint16_t odd_byte = 0;

	nleft = plen;
	w = (uint16_t *)p;
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(uchar_t *)(&odd_byte) = *(uchar_t *)w;
		sum += odd_byte;
	}

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer == 0 ? ~0 : answer);
}

/* Pseudo header for v4 */
struct pshv4 {
	struct in_addr	ph4_src;
	struct in_addr	ph4_dst;
	uint8_t		ph4_zero;	/* always zero */
	uint8_t		ph4_protocol;	/* protocol used, IPPROTO_VRRP */
	uint16_t	ph4_len;	/* VRRP payload len */
};

/*
 * Checksum routine for VRRP checksum. Note that plen is the upper-layer
 * packet length (in the host byte order), and both IP source and destination
 * addresses are in the network byte order.
 */
static uint16_t
vrrp_cksum4(struct in_addr *src, struct in_addr *dst, uint16_t plen,
    vrrp_pkt_t *vp)
{
	struct pshv4 ph4;
	int nleft;
	uint16_t *w;
	int sum = 0;

	ph4.ph4_src = *src;
	ph4.ph4_dst = *dst;
	ph4.ph4_zero = 0;
	ph4.ph4_protocol = IPPROTO_VRRP;
	ph4.ph4_len = htons(plen);

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	nleft = sizeof (struct pshv4);
	w = (uint16_t *)&ph4;
	while (nleft > 0) {
		sum += *w++;
		nleft -= 2;
	}

	return (in_cksum(sum, plen, vp));
}

/* Pseudo header for v6 */
struct pshv6 {
	struct in6_addr	ph6_src;
	struct in6_addr	ph6_dst;
	uint32_t	ph6_len;	/* VRRP payload len */
	uint32_t	ph6_zero : 24,
			ph6_protocol : 8; /* protocol used, IPPROTO_VRRP */
};

/*
 * Checksum routine for VRRP checksum. Note that plen is the upper-layer
 * packet length (in the host byte order), and both IP source and destination
 * addresses are in the network byte order.
 */
static uint16_t
vrrp_cksum6(struct in6_addr *src, struct in6_addr *dst, uint16_t plen,
    vrrp_pkt_t *vp)
{
	struct pshv6 ph6;
	int nleft;
	uint16_t *w;
	int sum = 0;

	ph6.ph6_src = *src;
	ph6.ph6_dst = *dst;
	ph6.ph6_zero = 0;
	ph6.ph6_protocol = IPPROTO_VRRP;
	ph6.ph6_len = htonl((uint32_t)plen);

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	nleft = sizeof (struct pshv6);
	w = (uint16_t *)&ph6;
	while (nleft > 0) {
		sum += *w++;
		nleft -= 2;
	}

	return (in_cksum(sum, plen, vp));
}

vrrp_err_t
vrrpd_state_i2m(vrrp_vr_t *vr)
{
	vrrp_err_t	err;

	vrrp_log(VRRP_DBG1, "vrrpd_state_i2m(%s)", vr->vvr_conf.vvc_name);

	vrrpd_state_trans(VRRP_STATE_INIT, VRRP_STATE_MASTER, vr);
	if ((err = vrrpd_virtualip_update(vr, _B_FALSE)) != VRRP_SUCCESS)
		return (err);

	(void) vrrpd_send_adv(vr, _B_FALSE);

	vr->vvr_err = VRRP_SUCCESS;
	vr->vvr_timeout = vr->vvr_conf.vvc_adver_int;
	if ((vr->vvr_timer_id = iu_schedule_timer_ms(vrrpd_timerq,
	    vr->vvr_timeout, vrrp_adv_timeout, vr)) == -1) {
		vrrp_log(VRRP_ERR, "vrrpd_state_i2m(): unable to start timer");
		return (VRRP_ESYS);
	} else {
		vrrp_log(VRRP_DBG1, "vrrpd_state_i2m(%s): start "
		    "vrrp_adv_timeout(%d)", vr->vvr_conf.vvc_name,
		    vr->vvr_timeout);
	}
	return (VRRP_SUCCESS);
}

vrrp_err_t
vrrpd_state_i2b(vrrp_vr_t *vr)
{
	vrrp_err_t	err;

	vrrp_log(VRRP_DBG1, "vrrpd_state_i2b(%s)", vr->vvr_conf.vvc_name);

	vrrpd_state_trans(VRRP_STATE_INIT, VRRP_STATE_BACKUP, vr);
	if ((err = vrrpd_virtualip_update(vr, _B_FALSE)) != VRRP_SUCCESS)
		return (err);

	/*
	 * Reinitialize the Master advertisement interval to be the configured
	 * value.
	 */
	vr->vvr_err = VRRP_SUCCESS;
	vr->vvr_master_adver_int = vr->vvr_conf.vvc_adver_int;
	vr->vvr_timeout = MASTER_DOWN_INTERVAL_VR(vr);
	if ((vr->vvr_timer_id = iu_schedule_timer_ms(vrrpd_timerq,
	    vr->vvr_timeout, vrrp_b2m_timeout, vr)) == -1) {
		vrrp_log(VRRP_ERR, "vrrpd_state_i2b(): unable to set timer");
		return (VRRP_ESYS);
	} else {
		vrrp_log(VRRP_DBG1, "vrrpd_state_i2b(%s): start "
		    "vrrp_b2m_timeout(%d)", vr->vvr_conf.vvc_name,
		    vr->vvr_timeout);
	}
	return (VRRP_SUCCESS);
}

void
vrrpd_state_m2i(vrrp_vr_t *vr)
{
	vrrp_log(VRRP_DBG1, "vrrpd_state_m2i(%s)", vr->vvr_conf.vvc_name);

	vrrpd_state_trans(VRRP_STATE_MASTER, VRRP_STATE_INIT, vr);
	(void) vrrpd_virtualip_update(vr, _B_TRUE);
	bzero(&vr->vvr_peer, sizeof (vrrp_peer_t));
	(void) iu_cancel_timer(vrrpd_timerq, vr->vvr_timer_id, NULL);
}

void
vrrpd_state_b2i(vrrp_vr_t *vr)
{
	vrrp_log(VRRP_DBG1, "vrrpd_state_b2i(%s)", vr->vvr_conf.vvc_name);

	bzero(&vr->vvr_peer, sizeof (vrrp_peer_t));
	(void) iu_cancel_timer(vrrpd_timerq, vr->vvr_timer_id, NULL);
	vrrpd_state_trans(VRRP_STATE_BACKUP, VRRP_STATE_INIT, vr);
	(void) vrrpd_virtualip_update(vr, _B_TRUE);
}

/* ARGSUSED */
static void
vrrp_b2m_timeout(iu_tq_t *tq, void *arg)
{
	vrrp_vr_t *vr = (vrrp_vr_t *)arg;

	vrrp_log(VRRP_DBG1, "vrrp_b2m_timeout(%s)", vr->vvr_conf.vvc_name);
	(void) vrrpd_state_b2m(vr);
}

/* ARGSUSED */
static void
vrrp_adv_timeout(iu_tq_t *tq, void *arg)
{
	vrrp_vr_t *vr = (vrrp_vr_t *)arg;

	vrrp_log(VRRP_DBG1, "vrrp_adv_timeout(%s)", vr->vvr_conf.vvc_name);

	(void) vrrpd_send_adv(vr, _B_FALSE);
	if ((vr->vvr_timer_id = iu_schedule_timer_ms(vrrpd_timerq,
	    vr->vvr_timeout, vrrp_adv_timeout, vr)) == -1) {
		vrrp_log(VRRP_ERR, "vrrp_adv_timeout(%s): start timer failed",
		    vr->vvr_conf.vvc_name);
	} else {
		vrrp_log(VRRP_DBG1, "vrrp_adv_timeout(%s): start "
		    "vrrp_adv_timeout(%d)", vr->vvr_conf.vvc_name,
		    vr->vvr_timeout);
	}
}

vrrp_err_t
vrrpd_state_b2m(vrrp_vr_t *vr)
{
	vrrp_err_t	err;

	vrrp_log(VRRP_DBG1, "vrrpd_state_b2m(%s)", vr->vvr_conf.vvc_name);

	vrrpd_state_trans(VRRP_STATE_BACKUP, VRRP_STATE_MASTER, vr);
	if ((err = vrrpd_virtualip_update(vr, _B_FALSE)) != VRRP_SUCCESS)
		return (err);
	(void) vrrpd_send_adv(vr, _B_FALSE);

	vr->vvr_timeout = vr->vvr_conf.vvc_adver_int;
	if ((vr->vvr_timer_id = iu_schedule_timer_ms(vrrpd_timerq,
	    vr->vvr_timeout, vrrp_adv_timeout, vr)) == -1) {
		vrrp_log(VRRP_ERR, "vrrpd_state_b2m(%s): start timer failed",
		    vr->vvr_conf.vvc_name);
		return (VRRP_ESYS);
	} else {
		vrrp_log(VRRP_DBG1, "vrrpd_state_b2m(%s): start "
		    "vrrp_adv_timeout(%d)", vr->vvr_conf.vvc_name,
		    vr->vvr_timeout);
	}
	return (VRRP_SUCCESS);
}

vrrp_err_t
vrrpd_state_m2b(vrrp_vr_t *vr)
{
	vrrp_err_t	err;

	vrrp_log(VRRP_DBG1, "vrrpd_state_m2b(%s)", vr->vvr_conf.vvc_name);

	vrrpd_state_trans(VRRP_STATE_MASTER, VRRP_STATE_BACKUP, vr);
	if ((err = vrrpd_virtualip_update(vr, _B_FALSE)) != VRRP_SUCCESS)
		return (err);

	/*
	 * Cancel the adver_timer.
	 */
	vr->vvr_master_adver_int = vr->vvr_peer_adver_int;
	(void) iu_cancel_timer(vrrpd_timerq, vr->vvr_timer_id, NULL);
	vr->vvr_timeout = MASTER_DOWN_INTERVAL_VR(vr);
	if ((vr->vvr_timer_id = iu_schedule_timer_ms(vrrpd_timerq,
	    vr->vvr_timeout, vrrp_b2m_timeout, vr)) == -1) {
		vrrp_log(VRRP_ERR, "vrrpd_state_m2b(%s): start timer failed",
		    vr->vvr_conf.vvc_name);
	} else {
		vrrp_log(VRRP_DBG1, "vrrpd_state_m2b(%s) start "
		    "vrrp_b2m_timeout(%d)", vr->vvr_conf.vvc_name,
		    vr->vvr_timeout);
	}
	return (VRRP_SUCCESS);
}

/*
 * Set the IFF_NOACCESS flag on the VNIC interface of the VRRP router
 * based on its access mode.
 */
static vrrp_err_t
vrrpd_set_noaccept(vrrp_vr_t *vr, boolean_t on)
{
	vrrp_intf_t *vif = vr->vvr_vif;
	uint64_t curr_flags;
	struct lifreq lifr;
	int s;

	vrrp_log(VRRP_DBG1, "vrrpd_set_noaccept(%s, %s)",
	    vr->vvr_conf.vvc_name, on ? "on" : "off");

	/*
	 * Possibly no virtual address exists on this VRRP router yet.
	 */
	if (vif == NULL)
		return (VRRP_SUCCESS);

	vrrp_log(VRRP_DBG1, "vrrpd_set_noaccept(%s, %s)",
	    vif->vvi_ifname, vrrp_state2str(vr->vvr_state));

	s = (vif->vvi_af == AF_INET) ? vrrpd_ctlsock_fd : vrrpd_ctlsock6_fd;
	(void) strncpy(lifr.lifr_name, vif->vvi_ifname,
	    sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0) {
		if (errno != ENXIO && errno != ENOENT) {
			vrrp_log(VRRP_ERR, "vrrpd_set_noaccept(): "
			    "SIOCGLIFFLAGS on %s failed: %s",
			    vif->vvi_ifname, strerror(errno));
		}
		return (VRRP_ESYS);
	}

	curr_flags = lifr.lifr_flags;
	if (on)
		lifr.lifr_flags |= IFF_NOACCEPT;
	else
		lifr.lifr_flags &= ~IFF_NOACCEPT;

	if (lifr.lifr_flags != curr_flags) {
		if (ioctl(s, SIOCSLIFFLAGS, (caddr_t)&lifr) < 0) {
			if (errno != ENXIO && errno != ENOENT) {
				vrrp_log(VRRP_ERR, "vrrpd_set_noaccept(%s): "
				    "SIOCSLIFFLAGS 0x%llx on %s failed: %s",
				    on ? "no_accept" : "accept",
				    lifr.lifr_flags, vif->vvi_ifname,
				    strerror(errno));
			}
			return (VRRP_ESYS);
		}
	}
	return (VRRP_SUCCESS);
}

static vrrp_err_t
vrrpd_virtualip_updateone(vrrp_intf_t *vif, vrrp_ip_t *ip, boolean_t checkonly)
{
	vrrp_state_t	state = vif->vvi_vr_state;
	struct lifreq	lifr;
	char		abuf[INET6_ADDRSTRLEN];
	int		af = vif->vvi_af;
	uint64_t	curr_flags;
	int		s;

	assert(IS_VIRTUAL_INTF(vif));

	/* LINTED E_CONSTANT_CONDITION */
	VRRPADDR2STR(af, &ip->vip_addr, abuf, INET6_ADDRSTRLEN, _B_FALSE);
	vrrp_log(VRRP_DBG1, "vrrpd_virtualip_updateone(%s, %s%s)",
	    vif->vvi_ifname, abuf, checkonly ? ", checkonly" : "");

	s = (af == AF_INET) ? vrrpd_ctlsock_fd : vrrpd_ctlsock6_fd;
	(void) strncpy(lifr.lifr_name, ip->vip_lifname,
	    sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0) {
		if (errno != ENXIO && errno != ENOENT) {
			vrrp_log(VRRP_ERR, "vrrpd_virtualip_updateone(%s): "
			    "SIOCGLIFFLAGS on %s/%s failed: %s",
			    vif->vvi_ifname, lifr.lifr_name, abuf,
			    strerror(errno));
		}
		return (VRRP_ESYS);
	}

	curr_flags = lifr.lifr_flags;
	if (state == VRRP_STATE_MASTER)
		lifr.lifr_flags |= IFF_UP;
	else
		lifr.lifr_flags &= ~IFF_UP;

	if (lifr.lifr_flags == curr_flags)
		return (VRRP_SUCCESS);

	if (checkonly) {
		vrrp_log(VRRP_ERR, "VRRP virtual IP %s/%s was brought %s",
		    ip->vip_lifname, abuf,
		    state == VRRP_STATE_MASTER ? "down" : "up");
		return (VRRP_ESYS);
	} else if (ioctl(s, SIOCSLIFFLAGS, (caddr_t)&lifr) < 0) {
		if (errno != ENXIO && errno != ENOENT) {
			vrrp_log(VRRP_ERR, "vrrpd_virtualip_updateone(%s, %s): "
			    "bring %s %s/%s failed: %s",
			    vif->vvi_ifname, vrrp_state2str(state),
			    state == VRRP_STATE_MASTER ? "up" : "down",
			    ip->vip_lifname, abuf, strerror(errno));
		}
		return (VRRP_ESYS);
	}
	return (VRRP_SUCCESS);
}

static vrrp_err_t
vrrpd_virtualip_update(vrrp_vr_t *vr, boolean_t checkonly)
{
	vrrp_state_t		state;
	vrrp_intf_t		*vif = vr->vvr_vif;
	vrrp_ip_t		*ip, *nextip;
	char			abuf[INET6_ADDRSTRLEN];
	vrrp_err_t		err;

	vrrp_log(VRRP_DBG1, "vrrpd_virtualip_update(%s, %s, %s)%s",
	    vr->vvr_conf.vvc_name, vrrp_state2str(vr->vvr_state),
	    vif->vvi_ifname, checkonly ? " checkonly" : "");

	state = vr->vvr_state;
	assert(vif != NULL);
	assert(IS_VIRTUAL_INTF(vif));
	assert(vif->vvi_vr_state != state);
	vif->vvi_vr_state = state;
	for (ip = TAILQ_FIRST(&vif->vvi_iplist); ip != NULL; ip = nextip) {
		nextip = TAILQ_NEXT(ip, vip_next);
		err = vrrpd_virtualip_updateone(vif, ip, _B_FALSE);
		if (!checkonly && err != VRRP_SUCCESS) {
			/* LINTED E_CONSTANT_CONDITION */
			VRRPADDR2STR(vif->vvi_af, &ip->vip_addr, abuf,
			    INET6_ADDRSTRLEN, _B_FALSE);
			vrrp_log(VRRP_DBG1, "vrrpd_virtualip_update() update "
			    "%s over %s failed", abuf, vif->vvi_ifname);
			vrrpd_delete_ip(vif, ip);
		}
	}

	/*
	 * The IP address is deleted when it is failed to be brought
	 * up. If no IP addresses are left, delete this interface.
	 */
	if (!checkonly && TAILQ_EMPTY(&vif->vvi_iplist)) {
		vrrp_log(VRRP_DBG0, "vrrpd_virtualip_update(): "
		    "no IP left over %s", vif->vvi_ifname);
		vrrpd_delete_if(vif, _B_TRUE);
		return (VRRP_ENOVIRT);
	}
	return (VRRP_SUCCESS);
}

void
vrrpd_state_trans(vrrp_state_t prev_s, vrrp_state_t s, vrrp_vr_t *vr)
{
	vrrp_log(VRRP_DBG1, "vrrpd_state_trans(%s): %s --> %s",
	    vr->vvr_conf.vvc_name, vrrp_state2str(prev_s), vrrp_state2str(s));

	assert(vr->vvr_state == prev_s);
	vr->vvr_state = s;
	vr->vvr_prev_state = prev_s;
	(void) gettimeofday(&vr->vvr_st_time, NULL);
	(void) vrrpd_post_event(vr->vvr_conf.vvc_name, prev_s, s);
}

static int
vrrpd_post_event(const char *name, vrrp_state_t prev_st, vrrp_state_t st)
{
	sysevent_id_t	eid;
	nvlist_t	*nvl = NULL;

	/*
	 * sysevent is not supported in the non-global zone
	 */
	if (getzoneid() != GLOBAL_ZONEID)
		return (0);

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0)
		goto failed;

	if (nvlist_add_uint8(nvl, VRRP_EVENT_VERSION,
	    VRRP_EVENT_CUR_VERSION) != 0)
		goto failed;

	if (nvlist_add_string(nvl, VRRP_EVENT_ROUTER_NAME, name) != 0)
		goto failed;

	if (nvlist_add_uint8(nvl, VRRP_EVENT_STATE, st) != 0)
		goto failed;

	if (nvlist_add_uint8(nvl, VRRP_EVENT_PREV_STATE, prev_st) != 0)
		goto failed;

	if (sysevent_post_event(EC_VRRP, ESC_VRRP_STATE_CHANGE,
	    SUNW_VENDOR, VRRP_EVENT_PUBLISHER, nvl, &eid) == 0) {
		nvlist_free(nvl);
		return (0);
	}

failed:
	vrrp_log(VRRP_ERR, "vrrpd_post_event(): `state change (%s --> %s)' "
	    "sysevent posting failed: %s", vrrp_state2str(prev_st),
	    vrrp_state2str(st), strerror(errno));

	if (nvl != NULL)
		nvlist_free(nvl);
	return (-1);
}

/*
 * timeval processing functions
 */
static int
timeval_to_milli(struct timeval tv)
{
	return ((int)(tv.tv_sec * 1000 + tv.tv_usec / 1000 + 0.5));
}

static struct timeval
timeval_delta(struct timeval t1, struct timeval t2)
{
	struct timeval t;
	t.tv_sec = t1.tv_sec - t2.tv_sec;
	t.tv_usec = t1.tv_usec - t2.tv_usec;

	if (t.tv_usec < 0) {
		t.tv_usec += 1000000;
		t.tv_sec--;
	}
	return (t);
}

/*
 * print error messages to the terminal or to syslog
 */
static void
vrrp_log(int level, char *message, ...)
{
	va_list ap;
	int log_level = -1;

	va_start(ap, message);

	if (vrrp_logflag == 0) {
		if (level <= vrrp_debug_level) {
			/*
			 * VRRP_ERR goes to stderr, others go to stdout
			 */
			FILE *out = (level <= VRRP_ERR) ? stderr : stdout;
			(void) fprintf(out, "vrrpd: ");
			/* LINTED: E_SEC_PRINTF_VAR_FMT */
			(void) vfprintf(out, message, ap);
			(void) fprintf(out, "\n");
			(void) fflush(out);
		}
		va_end(ap);
		return;
	}

	/*
	 * translate VRRP_* to LOG_*
	 */
	switch (level) {
	case VRRP_ERR:
		log_level = LOG_ERR;
		break;
	case VRRP_WARNING:
		log_level = LOG_WARNING;
		break;
	case VRRP_NOTICE:
		log_level = LOG_NOTICE;
		break;
	case VRRP_DBG0:
		log_level = LOG_INFO;
		break;
	default:
		log_level = LOG_DEBUG;
		break;
	}

	/* LINTED: E_SEC_PRINTF_VAR_FMT */
	(void) vsyslog(log_level, message, ap);
	va_end(ap);
}
