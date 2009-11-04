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
#ifndef _ILBD_H
#define	_ILBD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <ucred.h>
#include <pwd.h>
#include <priv.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/list.h>
#include <libscf.h>
#include <libintl.h>
#include <locale.h>
#include <libinetutil.h>
#include <auth_list.h>
#include <bsm/adt.h>
#include <bsm/adt_event.h>

#define	SGNAME_SZ	80
#define	ILB_FMRI	"svc:/network/loadbalancer/ilb:default"

#define	HC_ACTION		ILB_SRV_DISABLED_HC
#define	ADMIN_ACTION		ILB_SRV_DISABLED_ADMIN

/* Max name and value length for scf properties */
#define	ILBD_MAX_NAME_LEN	ilbd_scf_limit(SCF_LIMIT_MAX_NAME_LENGTH)
#define	ILBD_MAX_VALUE_LEN	ilbd_scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH)

/* Different events ILBD is interested in. */
typedef enum {
	ILBD_EVENT_NEW_REQ,	/* New client request */
	ILBD_EVENT_REQ,		/* Client request comes in */
	ILBD_EVENT_REP_OK,	/* Reply channel to client is writeable */
	ILBD_EVENT_PROBE,	/* A HC returns some result */
	ILBD_EVENT_TIMER	/* ilbd_timer_q fired */
} ilbd_event_t;

typedef enum {
	ILBD_SCF_RULE,	/* prop group for rules */
	ILBD_SCF_SG,	/* prop group for servergroups */
	ILBD_SCF_HC	/* prop group for healthchecks */
} ilbd_scf_pg_type_t;

typedef enum {
	ILBD_SCF_CREATE,
	ILBD_SCF_DESTROY,
	ILBD_SCF_ENABLE_DISABLE
} ilbd_scf_cmd_t;

typedef enum {
	ILBD_STRING,	/* string */
	ILBD_INT,	/* int */
	ILBD_ADDR_V4,	/* ipv4 addr */
	ILBD_ADDR_V6	/* ipv6 addr */
} ilbd_scf_data_type_t;

typedef enum {
	stat_enable_server,
	stat_disable_server,
	stat_declare_srv_dead,
	stat_declare_srv_alive
} ilbd_srv_status_ind_t;

/*
 * All user struct pointer passed to port_associate() should have the first
 * field as ilbd_event_t.  The following struct can be used to find the
 * event.
 */
typedef struct {
	ilbd_event_t	ev;
} ilbd_event_obj_t;

typedef struct {
	ilbd_event_t	ev;
	timer_t		timerid;
} ilbd_timer_event_obj_t;

typedef struct ilbd_srv {
	list_node_t	isv_srv_link;
	ilb_sg_srv_t	isv_srv;
#define	isv_addr	isv_srv.sgs_addr
#define	isv_minport	isv_srv.sgs_minport
#define	isv_maxport	isv_srv.sgs_maxport
#define	isv_flags	isv_srv.sgs_flags
#define	isv_id		isv_srv.sgs_id
#define	isv_srvID	isv_srv.sgs_srvID
} ilbd_srv_t;

#define	MAX_SRVCOUNT	1000
#define	MAX_SRVID	(MAX_SRVCOUNT - 1)
#define	BAD_SRVID	(-1)

typedef struct ilbd_sg {
	list_t		isg_srvlist;	/* list of ilbd_srv_t */
	char		isg_name[ILB_SGNAME_SZ];
	int32_t		isg_srvcount;
	int32_t		isg_max_id;
	list_t		isg_rulelist;	/* list of ilbd_rule_t */
	char		isg_id_arr[MAX_SRVCOUNT]; /* for server ID allocation */

	list_node_t	isg_link;	/* linkage for sg list */
} ilbd_sg_t;

typedef struct ilbd_rule {
	list_node_t		irl_link;
	list_node_t		irl_sglink;
	ilbd_sg_t		*irl_sg;
	ilb_rule_info_t		irl_info;
#define	irl_flags	irl_info.rl_flags
#define	irl_name	irl_info.rl_name
#define	irl_vip		irl_info.rl_vip
#define	irl_proto	irl_info.rl_proto
#define	irl_ipversion	irl_info.rl_ipversion
#define	irl_minport	irl_info.rl_minport
#define	irl_maxport	irl_info.rl_maxport
#define	irl_algo	irl_info.rl_algo
#define	irl_topo	irl_info.rl_topo
#define	irl_nat_src_start	irl_info.rl_nat_src_start
#define	irl_nat_src_end	irl_info.rl_nat_src_end
#define	irl_stickymask	irl_info.rl_stickymask
#define	irl_conndrain	irl_info.rl_conndrain
#define	irl_nat_timeout	irl_info.rl_nat_timeout
#define	irl_sticky_timeout	irl_info.rl_sticky_timeout
#define	irl_hcport	irl_info.rl_hcport
#define	irl_hcpflag	irl_info.rl_hcpflag
#define	irl_sgname	irl_info.rl_sgname
#define	irl_hcname	irl_info.rl_hcname
} ilbd_rule_t;

/*
 * Health check related definitions
 */

/* Default health check probe program provided */
#define	ILB_PROBE_PROTO	"/usr/lib/inet/ilb/ilb_probe"

/* Command name (argv[0]) passed to ilb_probe to indicate a ping test */
#define	ILB_PROBE_PING	"ilb_ping"

/* Use the first character of the rule's hcname to decide if rule has HC. */
#define	RULE_HAS_HC(irl)	((irl)->irl_info.rl_hcname[0] != '\0')

/* Type of probe test */
typedef enum {
	ILBD_HC_PING = 1,	/* ICMP Echo probe */
	ILBD_HC_TCP,		/* TCP connect probe */
	ILBD_HC_UDP,		/* UDP packet probe */
	ILBD_HC_USER		/* User supplied probe */
} ilbd_hc_test_t;

/* Struct representing a hc object in ilbd */
typedef struct {
	list_node_t	ihc_link;	/* List linkage */

	ilb_hc_info_t	ihc_info;
/* Short hand for the fields inside ilb_hc_info_t */
#define	ihc_name	ihc_info.hci_name
#define	ihc_test	ihc_info.hci_test
#define	ihc_timeout	ihc_info.hci_timeout
#define	ihc_count	ihc_info.hci_count
#define	ihc_interval	ihc_info.hci_interval
#define	ihc_def_ping	ihc_info.hci_def_ping

	ilbd_hc_test_t	ihc_test_type;	/* Type of probe test */
	int		ihc_rule_cnt;	/* Num of rules associated with hc */
	list_t		ihc_rules;	/* Rules associated with this hc */
} ilbd_hc_t;

struct ilbd_hc_srv_s;

/*
 * Struct representing a hc rule object
 *
 * hcr_link: list linkage
 * hcr_rule: pointer to the ilbd rule object
 * hcr_servers: list of servers of this rule
 */
typedef struct {
	list_node_t		hcr_link;
	ilbd_rule_t const 	*hcr_rule;
	list_t			hcr_servers;
} ilbd_hc_rule_t;

struct ilbd_hc_srv_s;

/*
 * Struct representing a event of the probe process
 *
 * ihp_ev: the event type, which is ILBD_EVENT_PROBE
 * ihp_srv: pointer to the hc server object
 * ihp_pid: pid of the probe process
 * ihp_done: is ilbd done reading the output of the probe process
 */
typedef struct {
	ilbd_event_t		ihp_ev;
	struct ilbd_hc_srv_s	*ihp_srv;
	pid_t			ihp_pid;
	boolean_t		ihp_done;
} ilbd_hc_probe_event_t;

/*
 * ilbd_hc_srv_t state
 *
 * ihd_hc_def_pinging: the default ping should be run
 * ihd-hc_probing: the probe process should be started
 */
enum ilbd_hc_state {
	ilbd_hc_def_pinging,
	ilbd_hc_probing
};

/*
 * Struct representing a server associated with a hc object
 *
 * shc_srv_link: list linkage
 * shc_hc: pointer to the hc object
 * shc_hc_rule: pointer to the hc rule object
 * shc_sg_srv: pointer to the server group object
 * shc_tid: timeout ID
 * shc_cur_cnt: number of times the hc probe has been run
 * shc_fail_cnt: number of consecutive probe failure
 * shc_status: health status
 * shc_rtt: rtt (in micro sec) to the backend server
 * shc_lasttimer: last time a probe sequence is executed
 * shc_nexttime: next time a probe sequence is executed
 * shc_state: hc probe state
 * shc_child_pid: pid of the probe process
 * shc_child_fd: fd to the output of the probe process
 * shc_ev: event object of the probe process
 * shc_ev_port: event port of the event object
 */
typedef struct ilbd_hc_srv_s {
	list_node_t		shc_srv_link;
	ilbd_hc_t		*shc_hc;
	ilbd_hc_rule_t		*shc_hc_rule;
	ilb_sg_srv_t const	*shc_sg_srv;

	iu_timer_id_t		shc_tid;
	uint_t			shc_cur_cnt;
	uint_t			shc_fail_cnt;
	ilb_hc_srv_status_t	shc_status;
	uint32_t		shc_rtt;
	time_t			shc_lasttime;
	time_t			shc_nexttime;

	enum ilbd_hc_state	shc_state;
	pid_t			shc_child_pid;
	int			shc_child_fd;
	ilbd_hc_probe_event_t	*shc_ev;
	int			shc_ev_port;
} ilbd_hc_srv_t;

/*
 * Structure for holding audit server and servergroup event
 * data. Not all events use all members of the structure.
 */
typedef struct audit_sg_event_data {
	char	*ed_server_address;	/* server's IP address */
	char	*ed_serverid;   /* serverid. */
	uint16_t	ed_minport;	/* server's minport */
	uint16_t	ed_maxport;	/* server's maxport */
	char		*ed_sgroup;	/* servergroup */
} audit_sg_event_data_t;

/* Struct to store client info */
typedef struct {
	ilbd_event_t	cli_ev;
	int	cli_sd;
	struct passwd	cli_pw;
	size_t		cli_pw_bufsz;
	char		*cli_pw_buf;
	ilbd_cmd_t	cli_cmd;
	ilb_comm_t	*cli_saved_reply;
	size_t		cli_saved_size;
	ucred_t		*cli_peer_ucredp; /* needed for auditing */
} ilbd_client_t;

void		ilbd_reply_ok(uint32_t *, size_t *);
void		ilbd_reply_err(uint32_t *, size_t *, ilb_status_t);

ilb_status_t	ilbd_check_client_config_auth(const struct passwd *);
ilb_status_t	ilbd_check_client_enable_auth(const struct passwd *);
ilb_status_t	ilbd_retrieve_names(ilbd_cmd_t, uint32_t *, size_t *);
void		i_setup_sg_hlist(void);
void		i_setup_rule_hlist(void);
void		logperror(const char *);
ilb_status_t	ilbd_add_server_to_group(ilb_sg_info_t *, int,
	const struct passwd *, ucred_t *);
ilb_status_t	ilbd_rem_server_from_group(ilb_sg_info_t *, int,
	const struct passwd *, ucred_t *);
ilb_status_t	ilbd_create_sg(ilb_sg_info_t *, int,
	const struct passwd *, ucred_t *);

ilb_status_t	ilbd_destroy_sg(const char *, const struct passwd *,
		ucred_t *);
ilb_status_t	ilbd_retrieve_sg_hosts(const char *, uint32_t *, size_t *);

ilb_status_t	ilbd_enable_server(ilb_sg_info_t *, const struct passwd *,
		ucred_t *);
ilb_status_t	ilbd_disable_server(ilb_sg_info_t *, const struct passwd *,
		ucred_t *);
ilb_status_t	ilbd_k_Xable_server(const struct in6_addr *, const char *,
		    ilbd_srv_status_ind_t);

ilb_status_t	i_add_srv2krules(list_t *, ilb_sg_srv_t *, int);
ilb_status_t	i_rem_srv_frm_krules(list_t *, ilb_sg_srv_t *, int);
int		ilbd_get_num_krules(void);
ilb_status_t	ilbd_get_krule_names(ilbd_namelist_t **, int);
ilb_status_t	ilb_get_krule_servers(ilb_sg_info_t *);
ilbd_sg_t	*i_find_sg_byname(const char *);
ilb_status_t	i_check_srv2rules(list_t *, ilb_sg_srv_t *);

ilb_status_t	ilbd_address_to_srvID(ilb_sg_info_t *, uint32_t *, size_t *);
ilb_status_t	ilbd_srvID_to_address(ilb_sg_info_t *, uint32_t *, size_t *);

ilb_status_t	do_ioctl(void *, ssize_t);

ilb_status_t	ilbd_create_rule(ilb_rule_info_t *, int, const struct passwd *,
		ucred_t *);
ilb_status_t	ilbd_retrieve_rule(ilbd_name_t, uint32_t *, size_t *);

ilb_status_t	ilbd_destroy_rule(ilbd_name_t, const struct passwd *,
		ucred_t *);
ilb_status_t	ilbd_enable_rule(ilbd_name_t, const struct passwd *, ucred_t *);
ilb_status_t	ilbd_disable_rule(ilbd_name_t, const struct passwd *,
		ucred_t *);

boolean_t	is_debugging_on(void);
ilb_status_t	ilbd_sg_check_rule_port(ilbd_sg_t *, ilb_rule_info_t *);

void		ilbd_enable_debug(void);
ilb_status_t	ilb_map_errno2ilbstat(int);

ilb_status_t	i_attach_rule2sg(ilbd_sg_t *, ilbd_rule_t *);

/* Logging routine and macros */
void		ilbd_log(int, const char *, ...);
#define	logerr(...)	ilbd_log(LOG_ERR, __VA_ARGS__)
#define	logdebug(...)	ilbd_log(LOG_DEBUG, __VA_ARGS__)

/* Health check manipulation routines */
void		i_ilbd_setup_hc_list(void);
ilb_status_t	ilbd_create_hc(const ilb_hc_info_t *, int,
		    const struct passwd *, ucred_t *);
ilb_status_t	ilbd_destroy_hc(const char *, const struct passwd *, ucred_t *);
ilbd_hc_t	*ilbd_get_hc(const char *);
ilb_status_t	ilbd_get_hc_info(const char *, uint32_t *, size_t *);
ilb_status_t	ilbd_get_hc_srvs(const char *, uint32_t *, size_t *);
ilb_status_t	ilbd_hc_associate_rule(const ilbd_rule_t *, int);
ilb_status_t	ilbd_hc_dissociate_rule(const ilbd_rule_t *);
ilb_status_t	ilbd_hc_add_server(const ilbd_rule_t *, const ilb_sg_srv_t *,
		    int);
ilb_status_t	ilbd_hc_del_server(const ilbd_rule_t *, const ilb_sg_srv_t *);
ilb_status_t	ilbd_hc_enable_rule(const ilbd_rule_t *);
ilb_status_t	ilbd_hc_disable_rule(const ilbd_rule_t *);
ilb_status_t	ilbd_hc_enable_server(const ilbd_rule_t *,
		    const ilb_sg_srv_t *);
ilb_status_t	ilbd_hc_disable_server(const ilbd_rule_t *,
		    const ilb_sg_srv_t *);

/* Health check timer routines */
void		ilbd_hc_probe_return(int, int, int, ilbd_hc_probe_event_t *);
void		ilbd_hc_timer_init(int, ilbd_timer_event_obj_t *);
void		ilbd_hc_timeout(void);
void		ilbd_hc_timer_update(ilbd_timer_event_obj_t *);

/* Show NAT info routines */
ilb_status_t	ilbd_show_nat(void *, const ilb_comm_t *, uint32_t *,
		    size_t *);
void		ilbd_show_nat_cleanup(void);


/* Show sticky info routines */
ilb_status_t	ilbd_show_sticky(void *, const ilb_comm_t *, uint32_t *,
		    size_t *);
void		ilbd_show_sticky_cleanup(void);

ilb_status_t	ilbd_create_pg(ilbd_scf_pg_type_t, void *);
ilb_status_t	ilbd_destroy_pg(ilbd_scf_pg_type_t, const char *);
ilb_status_t	ilbd_change_prop(ilbd_scf_pg_type_t, const char *,
		    const char *, void *);
void		ilbd_scf_str_to_ip(int, char *, struct in6_addr *);
ilb_status_t	ilbd_scf_ip_to_str(uint16_t, struct in6_addr *, scf_type_t *,
		    char *);
ilb_status_t	ilbd_scf_add_srv(ilbd_sg_t *, ilbd_srv_t *);
ilb_status_t	ilbd_scf_del_srv(ilbd_sg_t *, ilbd_srv_t *);
int		ilbd_scf_limit(int);

ilb_status_t	ilbd_walk_rule_pgs(ilb_status_t (*)(ilb_rule_info_t *, int,
		    const struct passwd *, ucred_t *), void *, void *);
ilb_status_t	ilbd_walk_sg_pgs(ilb_status_t (*)(ilb_sg_info_t *, int,
		    const struct passwd *, ucred_t *), void *, void *);
ilb_status_t	ilbd_walk_hc_pgs(ilb_status_t (*)(const ilb_hc_info_t *, int,
		    const struct passwd *, ucred_t *), void *, void *);
void		ilbd_addr2str(struct in6_addr *, char *, size_t);
void		addr2str(ilb_ip_addr_t, char *, size_t);
void		ilbd_algo_to_str(ilb_algo_t, char *);
void		ilbd_topo_to_str(ilb_topo_t, char *);
void		ilbd_ip_to_str(uint16_t, struct in6_addr *, char *);
int		ilberror2auditerror(ilb_status_t);

#ifdef __cplusplus
}
#endif

#endif /* _ILBD_H */
