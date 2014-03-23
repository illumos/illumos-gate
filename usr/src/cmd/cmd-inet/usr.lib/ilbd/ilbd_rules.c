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

#include <stdlib.h>
#include <strings.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/list.h>
#include <net/if.h>
#include <assert.h>
#include <errno.h>
#include <libintl.h>
#include <libilb.h>
#include <inet/ilb.h>
#include "libilb_impl.h"
#include "ilbd.h"

/* until we all use AF_* macros ... */
#define	AF_2_IPPROTO(_af)	(_af == AF_INET)?IPPROTO_IP:IPPROTO_IPV6
#define	IPPROTO_2_AF(_i)	(_i == IPPROTO_IP)?AF_INET:AF_INET6

#define	PROTOCOL_LEN	16				/* protocol type */
#define	ADDR_LEN	(2 * INET6_ADDRSTRLEN + 1)	/* prxy src range */
#define	PORT_LEN	6			/* hcport:1-65535 or "ANY" */

static ilb_status_t ilbd_disable_one_rule(ilbd_rule_t *, boolean_t);
static uint32_t i_flags_d2k(int);

#define	ILB_SGSRV_2_KSRV(s, k)			\
	(k)->addr  = (s)->sgs_addr;		\
	(k)->min_port = (s)->sgs_minport;	\
	(k)->max_port = (s)->sgs_maxport;	\
	(k)->flags = i_flags_d2k((s)->sgs_flags);	\
	(k)->err = 0;				\
	(void) strlcpy((k)->name, (s)->sgs_srvID, sizeof ((k)->name))

list_t		ilbd_rule_hlist;

static ilb_algo_t
algo_impl2lib(ilb_algo_impl_t a)
{
	switch (a) {
	case ILB_ALG_IMPL_ROUNDROBIN:
		return (ILB_ALG_ROUNDROBIN);
	case ILB_ALG_IMPL_HASH_IP:
		return (ILB_ALG_HASH_IP);
	case ILB_ALG_IMPL_HASH_IP_SPORT:
		return (ILB_ALG_HASH_IP_SPORT);
	case ILB_ALG_IMPL_HASH_IP_VIP:
		return (ILB_ALG_HASH_IP_VIP);
	}
	return (0);
}

static ilb_topo_t
topo_impl2lib(ilb_topo_impl_t t)
{
	switch (t) {
	case ILB_TOPO_IMPL_DSR:
		return (ILB_TOPO_DSR);
	case ILB_TOPO_IMPL_NAT:
		return (ILB_TOPO_NAT);
	case ILB_TOPO_IMPL_HALF_NAT:
		return (ILB_TOPO_HALF_NAT);
	}
	return (0);
}

ilb_algo_impl_t
algo_lib2impl(ilb_algo_t a)
{
	switch (a) {
	case ILB_ALG_ROUNDROBIN:
		return (ILB_ALG_IMPL_ROUNDROBIN);
	case ILB_ALG_HASH_IP:
		return (ILB_ALG_IMPL_HASH_IP);
	case ILB_ALG_HASH_IP_SPORT:
		return (ILB_ALG_IMPL_HASH_IP_SPORT);
	case ILB_ALG_HASH_IP_VIP:
		return (ILB_ALG_IMPL_HASH_IP_VIP);
	}
	return (0);
}

ilb_topo_impl_t
topo_lib2impl(ilb_topo_t t)
{
	switch (t) {
	case ILB_TOPO_DSR:
		return (ILB_TOPO_IMPL_DSR);
	case ILB_TOPO_NAT:
		return (ILB_TOPO_IMPL_NAT);
	case ILB_TOPO_HALF_NAT:
		return (ILB_TOPO_IMPL_HALF_NAT);
	}
	return (0);
}

/*
 * Walk the list of rules and check if its safe to add the
 * the server to the rule (this is a list of rules hanging
 * off of a server group)
 */
ilb_status_t
i_check_srv2rules(list_t *rlist, ilb_sg_srv_t *srv)
{
	ilb_status_t	rc = ILB_STATUS_OK;
	ilbd_rule_t	*rl;
	int		server_portrange, rule_portrange;
	int		srv_minport, srv_maxport;
	int		r_minport, r_maxport;

	if (srv == NULL)
		return (ILB_STATUS_OK);

	srv_minport = ntohs(srv->sgs_minport);
	srv_maxport = ntohs(srv->sgs_maxport);

	for (rl = list_head(rlist); rl != NULL; rl = list_next(rlist, rl)) {
		r_minport = ntohs(rl->irl_minport);
		r_maxport = ntohs(rl->irl_maxport);

		if ((srv_minport != 0) && (srv_minport == srv_maxport)) {
			/* server has single port */
			if (rl->irl_topo == ILB_TOPO_DSR) {
				/*
				 * either we have a DSR rule with a port
				 * range, or both server and rule
				 * have single ports but their values
				 * don't match - this is incompatible
				 */
				if (r_maxport > r_minport) {
					rc = ILB_STATUS_INVAL_SRVR;
					break;
				} else if (srv_minport != r_minport) {
					rc = ILB_STATUS_BADPORT;
					break;
				}
			}
			if (rl->irl_hcpflag == ILB_HCI_PROBE_FIX &&
			    rl->irl_hcport != srv_minport) {
				rc = ILB_STATUS_BADPORT;
				break;
			}
		} else if (srv_maxport > srv_minport) {
			/* server has a port range */
			if ((rl->irl_topo == ILB_TOPO_DSR) &&
			    (r_maxport > r_minport)) {
				if ((r_minport != srv_minport) ||
				    (r_maxport != srv_maxport)) {
					/*
					 * we have a DSR rule with a port range
					 * and its min and max port values
					 * does not meet that of server's
					 * - this is incompatible
					 */
					rc = ILB_STATUS_BADPORT;
					break;
				}
			} else if ((rl->irl_topo == ILB_TOPO_DSR) &&
			    (r_maxport == r_minport)) {
					/*
					 * we have a DSR rule with a single
					 * port and a server with a port range
					 * - this is incompatible
					 */
					rc = ILB_STATUS_INVAL_SRVR;
					break;
			} else if (((rl->irl_topo == ILB_TOPO_NAT) ||
			    (rl->irl_topo == ILB_TOPO_HALF_NAT)) &&
			    (r_maxport > r_minport)) {
				server_portrange = srv_maxport - srv_minport;
				rule_portrange = r_maxport - r_minport;
				if (rule_portrange != server_portrange) {
					/*
					 * we have a NAT/Half-NAT rule with
					 * a port range and server with a port
					 * range and there is a mismatch in the
					 * sizes of the port ranges - this is
					 * incompatible
					 */
					rc = ILB_STATUS_INVAL_SRVR;
					break;
				}
			}
			if (rl->irl_hcpflag == ILB_HCI_PROBE_FIX &&
			    (rl->irl_hcport > srv_maxport ||
			    rl->irl_hcport < srv_minport)) {
				rc = ILB_STATUS_BADPORT;
				break;
			}
		}
	}

	return (rc);
}

void
i_setup_rule_hlist(void)
{
	list_create(&ilbd_rule_hlist, sizeof (ilbd_rule_t),
	    offsetof(ilbd_rule_t, irl_link));
}

ilb_status_t
i_ilbd_save_rule(ilbd_rule_t *irl, ilbd_scf_cmd_t scf_cmd)
{
	boolean_t enable = irl->irl_flags & ILB_FLAGS_RULE_ENABLED;

	switch (scf_cmd) {
	case ILBD_SCF_CREATE:
		return (ilbd_create_pg(ILBD_SCF_RULE, (void *)irl));
	case ILBD_SCF_DESTROY:
		return (ilbd_destroy_pg(ILBD_SCF_RULE, irl->irl_name));
	case ILBD_SCF_ENABLE_DISABLE:
		return (ilbd_change_prop(ILBD_SCF_RULE, irl->irl_name,
		    "status", &enable));
	default:
		logdebug("i_ilbd_save_rule: invalid scf cmd %d", scf_cmd);
		return (ILB_STATUS_INVAL_CMD);
	}
}

/*
 * allocate a new daemon-specific rule from the "template" passed
 * in in *r
 */
static ilbd_rule_t *
i_alloc_ilbd_rule(ilb_rule_info_t *r)
{
	ilbd_rule_t	*rl;

	rl = calloc(sizeof (*rl), 1);
	if (rl != NULL && r != NULL)
		bcopy(r, &rl->irl_info, sizeof (*r));

	return (rl);
}

static ilbd_rule_t *
i_find_rule_byname(const char *name)
{
	ilbd_rule_t	*rl;

	/* find position of rule in list */
	rl = list_head(&ilbd_rule_hlist);
	while (rl != NULL &&
	    strncmp(rl->irl_name, name, sizeof (rl->irl_name)) != 0) {
		rl = list_next(&ilbd_rule_hlist, rl);
	}

	return (rl);
}

/*
 * get exactly one rule (named in rl->irl_name) data from kernel
 */
static ilb_status_t
ilb_get_krule(ilb_rule_info_t *rl)
{
	ilb_status_t	rc;
	ilb_rule_cmd_t	kcmd;

	kcmd.cmd = ILB_LIST_RULE;
	(void) strlcpy(kcmd.name, rl->rl_name, sizeof (kcmd.name));
	kcmd.flags = 0;

	rc = do_ioctl(&kcmd, 0);
	if (rc != ILB_STATUS_OK)
		return (rc);

	rl->rl_flags = kcmd.flags;
	rl->rl_ipversion = IPPROTO_2_AF(kcmd.ip_ver);
	rl->rl_vip = kcmd.vip;
	rl->rl_proto = kcmd.proto;
	rl->rl_minport = kcmd.min_port;
	rl->rl_maxport = kcmd.max_port;
	rl->rl_algo = algo_impl2lib(kcmd.algo);
	rl->rl_topo = topo_impl2lib(kcmd.topo);
	rl->rl_stickymask = kcmd.sticky_mask;
	rl->rl_nat_src_start = kcmd.nat_src_start;
	rl->rl_nat_src_end = kcmd.nat_src_end;
	(void) strlcpy(rl->rl_name, kcmd.name, sizeof (rl->rl_name));
	rl->rl_conndrain = kcmd.conn_drain_timeout;
	rl->rl_nat_timeout = kcmd.nat_expiry;
	rl->rl_sticky_timeout = kcmd.sticky_expiry;

	return (ILB_STATUS_OK);
}

ilb_status_t
ilbd_retrieve_rule(ilbd_name_t rl_name, uint32_t *rbuf, size_t *rbufsz)
{
	ilbd_rule_t	*irl = NULL;
	ilb_status_t	rc;
	ilb_rule_info_t	*rinfo;

	irl = i_find_rule_byname(rl_name);
	if (irl == NULL)
		return (ILB_STATUS_ENOENT);

	ilbd_reply_ok(rbuf, rbufsz);
	rinfo = (ilb_rule_info_t *)&((ilb_comm_t *)rbuf)->ic_data;
	bcopy(&irl->irl_info, rinfo, sizeof (*rinfo));

	/*
	 * Check if the various timeout values are 0.  If one is, get the
	 * default values from kernel.
	 */
	if (rinfo->rl_conndrain == 0 || rinfo->rl_nat_timeout == 0 ||
	    rinfo->rl_sticky_timeout == 0) {
		ilb_rule_info_t tmp_info;

		(void) strcpy(tmp_info.rl_name, rinfo->rl_name);
		rc = ilb_get_krule(&tmp_info);
		if (rc != ILB_STATUS_OK)
			return (rc);
		if (rinfo->rl_conndrain == 0)
			rinfo->rl_conndrain = tmp_info.rl_conndrain;
		if ((rinfo->rl_topo == ILB_TOPO_NAT ||
		    rinfo->rl_topo == ILB_TOPO_HALF_NAT) &&
		    rinfo->rl_nat_timeout == 0) {
			rinfo->rl_nat_timeout = tmp_info.rl_nat_timeout;
		}
		if ((rinfo->rl_flags & ILB_FLAGS_RULE_STICKY) &&
		    rinfo->rl_sticky_timeout == 0) {
			rinfo->rl_sticky_timeout = tmp_info.rl_sticky_timeout;
		}
	}
	*rbufsz += sizeof (ilb_rule_info_t);

	return (ILB_STATUS_OK);
}

static ilb_status_t
ilbd_destroy_one_rule(ilbd_rule_t *irl)
{
	ilb_status_t	rc;
	ilb_name_cmd_t	kcmd;

	/*
	 * as far as talking to the kernel is concerned, "all rules"
	 * is handled in one go somewhere else, so we only
	 * tell the kernel about single rules here.
	 */
	if ((irl->irl_flags & ILB_FLAGS_RULE_ALLRULES) == 0) {
		kcmd.cmd = ILB_DESTROY_RULE;
		(void) strlcpy(kcmd.name, irl->irl_name, sizeof (kcmd.name));
		kcmd.flags = 0;

		rc = do_ioctl(&kcmd, 0);
		if (rc != ILB_STATUS_OK)
			return (rc);

	}
	list_remove(&irl->irl_sg->isg_rulelist, irl);
	list_remove(&ilbd_rule_hlist, irl);

	/*
	 * When dissociating a rule, only two errors can happen.  The hc
	 * name is incorrect or the rule is not associated with the hc
	 * object.  Both should not happen....  The check is for debugging
	 * purpose.
	 */
	if (RULE_HAS_HC(irl) && (rc = ilbd_hc_dissociate_rule(irl)) !=
	    ILB_STATUS_OK) {
		logerr("ilbd_destroy_one_rule: cannot "
		    "dissociate %s from hc object %s: %d",
		    irl->irl_name, irl->irl_hcname, rc);
	}

	rc = i_ilbd_save_rule(irl, ILBD_SCF_DESTROY);
	if (rc != ILB_STATUS_OK)
		logdebug("ilbd_destroy_rule: save rule failed");

	free(irl);
	return (rc);
}

/*
 * the following two functions are the other's opposite, and can
 * call into each other for roll back purposes in case of error.
 * To avoid endless recursion, the 'is_rollback' parameter must be
 * set to B_TRUE in the roll back case.
 */
static ilb_status_t
ilbd_enable_one_rule(ilbd_rule_t *irl, boolean_t is_rollback)
{
	ilb_status_t	rc = ILB_STATUS_OK;
	ilb_name_cmd_t	kcmd;

	/* no use sending a no-op to the kernel */
	if ((irl->irl_flags & ILB_FLAGS_RULE_ENABLED) != 0)
		return (ILB_STATUS_OK);

	irl->irl_flags |= ILB_FLAGS_RULE_ENABLED;

	/* "all rules" is handled in one go somewhere else, not here */
	if ((irl->irl_flags & ILB_FLAGS_RULE_ALLRULES) == 0) {
		kcmd.cmd = ILB_ENABLE_RULE;
		(void) strlcpy(kcmd.name, irl->irl_name, sizeof (kcmd.name));
		kcmd.flags = 0;

		rc = do_ioctl(&kcmd, 0);
		if (rc != ILB_STATUS_OK)
			return (rc);
	}
	if (RULE_HAS_HC(irl) && (rc = ilbd_hc_enable_rule(irl)) !=
	    ILB_STATUS_OK) {
		/* Undo the kernel work */
		kcmd.cmd = ILB_DISABLE_RULE;
		/* Cannot do much if ioctl fails... */
		(void) do_ioctl(&kcmd, 0);
		return (rc);
	}

	if (!is_rollback) {
		if (rc == ILB_STATUS_OK)
			rc = i_ilbd_save_rule(irl, ILBD_SCF_ENABLE_DISABLE);
		if (rc != ILB_STATUS_OK)
			/* ignore rollback return code */
			(void) ilbd_disable_one_rule(irl, B_TRUE);
	}

	return (rc);
}

static ilb_status_t
ilbd_disable_one_rule(ilbd_rule_t *irl, boolean_t is_rollback)
{
	ilb_status_t	rc = ILB_STATUS_OK;
	ilb_name_cmd_t	kcmd;

	/* no use sending a no-op to the kernel */
	if ((irl->irl_flags & ILB_FLAGS_RULE_ENABLED) == 0)
		return (ILB_STATUS_OK);

	irl->irl_flags &= ~ILB_FLAGS_RULE_ENABLED;

	/* "all rules" is handled in one go somewhere else, not here */
	if ((irl->irl_flags & ILB_FLAGS_RULE_ALLRULES) == 0) {
		kcmd.cmd = ILB_DISABLE_RULE;
		(void) strlcpy(kcmd.name, irl->irl_name, sizeof (kcmd.name));
		kcmd.flags = 0;

		rc = do_ioctl(&kcmd, 0);
		if (rc != ILB_STATUS_OK)
			return (rc);
	}

	if (RULE_HAS_HC(irl) && (rc = ilbd_hc_disable_rule(irl)) !=
	    ILB_STATUS_OK) {
		/* Undo the kernel work */
		kcmd.cmd = ILB_ENABLE_RULE;
		/* Cannot do much if ioctl fails... */
		(void) do_ioctl(&kcmd, 0);
		return (rc);
	}

	if (!is_rollback) {
		if (rc == ILB_STATUS_OK)
			rc = i_ilbd_save_rule(irl, ILBD_SCF_ENABLE_DISABLE);
		if (rc != ILB_STATUS_OK)
			/* ignore rollback return code */
			(void) ilbd_enable_one_rule(irl, B_TRUE);
	}

	return (rc);
}

/*
 * Generates an audit record for a supplied rule name
 * Used for enable_rule, disable_rule, delete_rule,
 * and create_rule subcommands
 */
static void
ilbd_audit_rule_event(const char *audit_rule_name,
    ilb_rule_info_t *rlinfo, ilbd_cmd_t cmd, ilb_status_t rc,
    ucred_t *ucredp)
{
	adt_session_data_t	*ah;
	adt_event_data_t	*event;
	au_event_t		flag;
	int			scf_val_len = ILBD_MAX_VALUE_LEN;
	char			*aobuf = NULL; /* algo:topo */
	char			*valstr1 = NULL;
	char			*valstr2 = NULL;
	char			pbuf[PROTOCOL_LEN]; /* protocol */
	char			hcpbuf[PORT_LEN]; /* hcport */
	int			audit_error;

	if ((ucredp == NULL) && (cmd == ILBD_CREATE_RULE))  {
		/*
		 * we came here from the path where ilbd incorporates
		 * the configuration that is listed in SCF :
		 * i_ilbd_read_config->ilbd_walk_rule_pgs->
		 *    ->ilbd_scf_instance_walk_pg->ilbd_create_rule
		 * We skip auditing in that case
		 */
		return;
	}
	if (adt_start_session(&ah, NULL, 0) != 0) {
		logerr("ilbd_audit_rule_event: adt_start_session failed");
		exit(EXIT_FAILURE);
	}
	if (adt_set_from_ucred(ah, ucredp, ADT_NEW) != 0) {
		(void) adt_end_session(ah);
		logerr("ilbd_audit_rule_event: adt_set_from_ucred failed");
		exit(EXIT_FAILURE);
	}
	if (cmd == ILBD_ENABLE_RULE)
		flag = ADT_ilb_enable_rule;
	else if (cmd == ILBD_DISABLE_RULE)
		flag = ADT_ilb_disable_rule;
	else if (cmd == ILBD_DESTROY_RULE)
		flag = ADT_ilb_delete_rule;
	else if (cmd == ILBD_CREATE_RULE)
		flag = ADT_ilb_create_rule;

	if ((event = adt_alloc_event(ah, flag)) == NULL) {
		logerr("ilbd_audit_rule_event: adt_alloc_event failed");
		exit(EXIT_FAILURE);
	}

	(void) memset((char *)event, 0, sizeof (adt_event_data_t));

	switch (cmd) {
	case ILBD_DESTROY_RULE:
		event->adt_ilb_delete_rule.auth_used = NET_ILB_CONFIG_AUTH;
		event->adt_ilb_delete_rule.rule_name = (char *)audit_rule_name;
		break;
	case ILBD_ENABLE_RULE:
		event->adt_ilb_enable_rule.auth_used = NET_ILB_ENABLE_AUTH;
		event->adt_ilb_enable_rule.rule_name = (char *)audit_rule_name;
		break;
	case ILBD_DISABLE_RULE:
		event->adt_ilb_disable_rule.auth_used = NET_ILB_ENABLE_AUTH;
		event->adt_ilb_disable_rule.rule_name = (char *)audit_rule_name;
		break;
	case ILBD_CREATE_RULE:
		if (((aobuf = malloc(scf_val_len)) == NULL) ||
		    ((valstr1 = malloc(scf_val_len)) == NULL) ||
		    ((valstr2 = malloc(scf_val_len)) == NULL)) {
			logerr("ilbd_audit_rule_event: could not"
			    " allocate buffer");
			exit(EXIT_FAILURE);
		}

		event->adt_ilb_create_rule.auth_used = NET_ILB_CONFIG_AUTH;

		/* Fill in virtual IP address type */
		if (IN6_IS_ADDR_V4MAPPED(&rlinfo->rl_vip)) {
			event->adt_ilb_create_rule.virtual_ipaddress_type =
			    ADT_IPv4;
			cvt_addr(event->adt_ilb_create_rule.virtual_ipaddress,
			    ADT_IPv4, rlinfo->rl_vip);
		} else {
			event->adt_ilb_create_rule.virtual_ipaddress_type =
			    ADT_IPv6;
			cvt_addr(event->adt_ilb_create_rule.virtual_ipaddress,
			    ADT_IPv6, rlinfo->rl_vip);
		}
		/* Fill in port - could be a single value or a range */
		event->adt_ilb_create_rule.min_port = ntohs(rlinfo->rl_minport);
		if (ntohs(rlinfo->rl_maxport) > ntohs(rlinfo->rl_minport)) {
			/* port range */
			event->adt_ilb_create_rule.max_port =
			    ntohs(rlinfo->rl_maxport);
		} else {
			/* in audit record, max=min when single port */
			event->adt_ilb_create_rule.max_port =
			    ntohs(rlinfo->rl_minport);
		}

		/*
		 * Fill in  protocol - if user does not specify it,
		 * its TCP by default
		 */
		if (rlinfo->rl_proto == IPPROTO_UDP)
			(void) snprintf(pbuf, PROTOCOL_LEN, "UDP");
		else
			(void) snprintf(pbuf, PROTOCOL_LEN, "TCP");
		event->adt_ilb_create_rule.protocol = pbuf;

		/* Fill in algorithm and operation type */
		ilbd_algo_to_str(rlinfo->rl_algo, valstr1);
		ilbd_topo_to_str(rlinfo->rl_topo, valstr2);
		(void) snprintf(aobuf, scf_val_len, "%s:%s",
		    valstr1, valstr2);
		event->adt_ilb_create_rule.algo_optype = aobuf;

		/* Fill in proxy-src for the NAT case */
		if (rlinfo->rl_topo == ILB_TOPO_NAT)  {
			/* copy starting proxy-src address */
			if (IN6_IS_ADDR_V4MAPPED(&rlinfo->rl_nat_src_start)) {
				/* V4 case */
				event->adt_ilb_create_rule.proxy_src_min_type =
				    ADT_IPv4;
				cvt_addr(
				    event->adt_ilb_create_rule.proxy_src_min,
				    ADT_IPv4, rlinfo->rl_nat_src_start);
			} else {
				/* V6 case */
				event->adt_ilb_create_rule.proxy_src_min_type =
				    ADT_IPv6;
				cvt_addr(
				    event->adt_ilb_create_rule.proxy_src_min,
				    ADT_IPv6, rlinfo->rl_nat_src_start);
			}

			/* copy ending proxy-src address */
			if (&rlinfo->rl_nat_src_end == 0) {
				/* proxy-src is a single address */
				event->adt_ilb_create_rule.proxy_src_max_type =
				    event->
				    adt_ilb_create_rule.proxy_src_min_type;
				(void) memcpy(
				    event->adt_ilb_create_rule.proxy_src_max,
				    event->adt_ilb_create_rule.proxy_src_min,
				    (4 * sizeof (uint32_t)));
			} else if (
			    IN6_IS_ADDR_V4MAPPED(&rlinfo->rl_nat_src_end)) {
				/*
				 * proxy-src is a address range - copy ending
				 * proxy-src address
				 * V4 case
				 */
				event->adt_ilb_create_rule.proxy_src_max_type =
				    ADT_IPv4;
				cvt_addr(
				    event->adt_ilb_create_rule.proxy_src_max,
				    ADT_IPv4, rlinfo->rl_nat_src_end);
			} else {
				/* V6 case */
				event->adt_ilb_create_rule.proxy_src_max_type =
				    ADT_IPv6;
				cvt_addr(
				    event->adt_ilb_create_rule.proxy_src_max,
				    ADT_IPv6, rlinfo->rl_nat_src_end);
			}
		}

		/*
		 * Fill in pmask if user has specified one - 0 means
		 * no persistence
		 */
		valstr1[0] = '\0';
		ilbd_ip_to_str(rlinfo->rl_ipversion, &rlinfo->rl_stickymask,
		    valstr1);
			event->adt_ilb_create_rule.persist_mask = valstr1;

		/* If there is a hcname */
		if (rlinfo->rl_hcname[0] != '\0')
			event->adt_ilb_create_rule.hcname = rlinfo->rl_hcname;

		/* Fill in hcport */
		if (rlinfo->rl_hcpflag == ILB_HCI_PROBE_FIX) {
			/* hcport is specified by user */
			(void) snprintf(hcpbuf, PORT_LEN, "%d",
			    rlinfo->rl_hcport);
			event->adt_ilb_create_rule.hcport = hcpbuf;
		} else if (rlinfo->rl_hcpflag == ILB_HCI_PROBE_ANY) {
			/* user has specified "ANY" */
			(void) snprintf(hcpbuf, PORT_LEN, "ANY");
			event->adt_ilb_create_rule.hcport = hcpbuf;
		}
		/*
		 * Fill out the conndrain, nat_timeout and persist_timeout
		 * If the user does not specify them, the default value
		 * is set in the kernel. Userland does not know what
		 * the values are. So if the user
		 * does not specify these values they will show up as
		 * 0 in the audit record.
		 */
		event->adt_ilb_create_rule.conndrain_timeout =
		    rlinfo->rl_conndrain;
		event->adt_ilb_create_rule.nat_timeout =
		    rlinfo->rl_nat_timeout;
		event->adt_ilb_create_rule.persist_timeout =
		    rlinfo->rl_sticky_timeout;

		/* Fill out servergroup and rule name */
		event->adt_ilb_create_rule.server_group = rlinfo->rl_sgname;
		event->adt_ilb_create_rule.rule_name = rlinfo->rl_name;
		break;
	}
	if (rc == ILB_STATUS_OK) {
		if (adt_put_event(event, ADT_SUCCESS, ADT_SUCCESS) != 0) {
			logerr("ilbd_audit_rule_event:adt_put_event failed");
			exit(EXIT_FAILURE);
		}
	} else {
		audit_error = ilberror2auditerror(rc);
		if (adt_put_event(event, ADT_FAILURE, audit_error) != 0) {
			logerr("ilbd_audit_rule_event: adt_put_event failed");
			exit(EXIT_FAILURE);
		}
	}
	adt_free_event(event);
	free(aobuf);
	free(valstr1);
	free(valstr2);
	(void) adt_end_session(ah);
}
/*
 * converts IP address from in6_addr format to uint32_t[4]
 * This conversion is needed for recording IP address in
 * audit records.
 */
void
cvt_addr(uint32_t *audit, int32_t type, struct in6_addr address)
{

	if (type == ADT_IPv4)  {
		/* address is IPv4 */
		audit[0] = address._S6_un._S6_u32[3];
	} else {
		/* address is IPv6 */
		(void) memcpy(audit, address._S6_un._S6_u32,
		    (4 * sizeof (uint32_t)));
	}
}

static ilb_status_t
i_ilbd_action_switch(ilbd_rule_t *irl, ilbd_cmd_t cmd,
    boolean_t is_rollback, ucred_t *ucredp)
{
	ilb_status_t    rc;

	switch (cmd) {
	case ILBD_DESTROY_RULE:
		rc = ilbd_destroy_one_rule(irl);
		if (!is_rollback) {
			ilbd_audit_rule_event(irl->irl_name, NULL,
			    cmd, rc, ucredp);
		}
		return (rc);
	case ILBD_ENABLE_RULE:
		rc = ilbd_enable_one_rule(irl, is_rollback);
		if (!is_rollback) {
			ilbd_audit_rule_event(irl->irl_name, NULL, cmd,
			    rc, ucredp);
		}
		return (rc);
	case ILBD_DISABLE_RULE:
		rc = ilbd_disable_one_rule(irl, is_rollback);
		if (!is_rollback) {
			ilbd_audit_rule_event(irl->irl_name, NULL, cmd,
			    rc, ucredp);
		}
		return (rc);
	}
	return (ILB_STATUS_INVAL_CMD);
}

static ilb_cmd_t
i_ilbd2ilb_cmd(ilbd_cmd_t c)
{
	ilb_cmd_t	r;

	switch (c) {
	case ILBD_CREATE_RULE:
		r = ILB_CREATE_RULE;
		break;
	case ILBD_DESTROY_RULE:
		r = ILB_DESTROY_RULE;
		break;
	case ILBD_ENABLE_RULE:
		r = ILB_ENABLE_RULE;
		break;
	case ILBD_DISABLE_RULE:
		r = ILB_DISABLE_RULE;
		break;
	}
	return (r);
}

static ilbd_cmd_t
get_undo_cmd(ilbd_cmd_t cmd)
{
	ilbd_cmd_t	u_cmd;

	switch (cmd) {
	case ILBD_DESTROY_RULE:
		u_cmd = ILBD_BAD_CMD;
		break;
	case ILBD_ENABLE_RULE:
		u_cmd = ILBD_DISABLE_RULE;
		break;
	case ILBD_DISABLE_RULE:
		u_cmd = ILBD_ENABLE_RULE;
		break;
	}

	return (u_cmd);
}

static ilb_status_t
i_ilbd_rule_action(const char *rule_name, const struct passwd *ps,
    ilbd_cmd_t cmd, ucred_t *ucredp)
{
	ilbd_rule_t	*irl, *irl_next;
	boolean_t	is_all_rules = B_FALSE;
	ilb_status_t	rc = ILB_STATUS_OK;
	ilb_name_cmd_t	kcmd;
	ilbd_cmd_t	u_cmd;
	char    rulename[ILB_NAMESZ];

	if (ps != NULL) {
		if ((cmd == ILBD_ENABLE_RULE) || (cmd == ILBD_DISABLE_RULE))
			rc = ilbd_check_client_enable_auth(ps);
		else
			rc = ilbd_check_client_config_auth(ps);
		/* generate the audit record before bailing out */
		if (rc != ILB_STATUS_OK) {
			if (rule_name != '\0') {
				ilbd_audit_rule_event(rule_name, NULL,
				    cmd, rc, ucredp);
			} else {
				(void) snprintf(rulename, sizeof (rulename),
				    "all");
				ilbd_audit_rule_event(rulename, NULL, cmd, rc,
				    ucredp);
			}
			goto out;
		}
	}
	is_all_rules = rule_name[0] == 0;

	/* just one rule */
	if (!is_all_rules) {
		irl = i_find_rule_byname(rule_name);
		if (irl == NULL) {
			rc = ILB_STATUS_ENORULE;
			ilbd_audit_rule_event(rule_name, NULL, cmd, rc, ucredp);
			goto out;
		}
		/* auditing will be done by i_ilbd_action_switch() */
		rc = i_ilbd_action_switch(irl, cmd, B_FALSE, ucredp);
		goto out;
	}

	/* all rules: first tell the kernel, then walk the daemon's list */
	kcmd.cmd = i_ilbd2ilb_cmd(cmd);
	kcmd.flags = ILB_RULE_ALLRULES;

	rc = do_ioctl(&kcmd, 0);
	if (rc != ILB_STATUS_OK) {
		(void) snprintf(rulename, sizeof (rulename), "all");
		ilbd_audit_rule_event(rulename, NULL, cmd, rc, ucredp);
		goto out;
	}

	irl = list_head(&ilbd_rule_hlist);
	while (irl != NULL) {
		irl_next = list_next(&ilbd_rule_hlist, irl);
		irl->irl_flags |= ILB_FLAGS_RULE_ALLRULES;
		/* auditing will be done by i_ilbd_action_switch() */
		rc = i_ilbd_action_switch(irl, cmd, B_FALSE, ucredp);
		irl->irl_flags &= ~ILB_FLAGS_RULE_ALLRULES;
		if (rc != ILB_STATUS_OK)
			goto rollback_list;
		irl = irl_next;
	}
	return (rc);

rollback_list:
	u_cmd = get_undo_cmd(cmd);
	if (u_cmd == ILBD_BAD_CMD)
		return (rc);

	if (is_all_rules) {
		kcmd.cmd = i_ilbd2ilb_cmd(u_cmd);
		(void) do_ioctl(&kcmd, 0);
	}
	/* current list element failed, so we start with previous one */
	irl = list_prev(&ilbd_rule_hlist, irl);
	while (irl != NULL) {
		if (is_all_rules)
			irl->irl_flags |= ILB_FLAGS_RULE_ALLRULES;

		/*
		 * When the processing of a command consists of
		 * multiple sequential steps, and one of them fails,
		 * ilbd performs rollback to undo the steps taken before the
		 * failing step. Since ilbd is initiating these steps
		 * there is not need to audit them.
		 */
		rc = i_ilbd_action_switch(irl, u_cmd, B_TRUE, NULL);
		irl->irl_flags &= ~ILB_FLAGS_RULE_ALLRULES;

		irl = list_prev(&ilbd_rule_hlist, irl);
	}
out:
	return (rc);
}

ilb_status_t
ilbd_destroy_rule(ilbd_name_t rule_name, const struct passwd *ps,
    ucred_t *ucredp)
{
	return (i_ilbd_rule_action(rule_name, ps, ILBD_DESTROY_RULE, ucredp));
}

ilb_status_t
ilbd_enable_rule(ilbd_name_t rule_name, const struct passwd *ps,
    ucred_t *ucredp)
{
	return (i_ilbd_rule_action(rule_name, ps, ILBD_ENABLE_RULE, ucredp));

}

ilb_status_t
ilbd_disable_rule(ilbd_name_t rule_name, const struct passwd *ps,
    ucred_t *ucredp)
{
	return (i_ilbd_rule_action(rule_name, ps, ILBD_DISABLE_RULE, ucredp));
}

/*
 * allocate storage for a kernel rule command and fill from
 * "template" irl, if non-NULL
 */
static ilb_rule_cmd_t *
i_alloc_kernel_rule_cmd(ilbd_rule_t *irl)
{
	ilb_rule_cmd_t *kcmd;

	kcmd = (ilb_rule_cmd_t *)malloc(sizeof (*kcmd));
	if (kcmd == NULL)
		return (kcmd);

	bzero(kcmd, sizeof (*kcmd));

	if (irl != NULL) {
		kcmd->flags = irl->irl_flags;
		kcmd->ip_ver = AF_2_IPPROTO(irl->irl_ipversion);
		kcmd->vip = irl->irl_vip;
		kcmd->proto = irl->irl_proto;
		kcmd->min_port = irl->irl_minport;
		kcmd->max_port = irl->irl_maxport;
		kcmd->algo = algo_lib2impl(irl->irl_algo);
		kcmd->topo = topo_lib2impl(irl->irl_topo);
		kcmd->sticky_mask = irl->irl_stickymask;
		kcmd->nat_src_start = irl->irl_nat_src_start;
		kcmd->nat_src_end = irl->irl_nat_src_end;
		kcmd->conn_drain_timeout = irl->irl_conndrain;
		kcmd->nat_expiry = irl->irl_nat_timeout;
		kcmd->sticky_expiry = irl->irl_sticky_timeout;
		(void) strlcpy(kcmd->name, irl->irl_name,
		    sizeof (kcmd->name));
	}
	return (kcmd);
}

/*
 * ncount is the next to be used index into (*kcmdp)->servers
 */
static ilb_status_t
adjust_srv_info_cmd(ilb_servers_info_cmd_t **kcmdp, int index)
{
	ilb_servers_info_cmd_t	*kcmd = *kcmdp;
	size_t			sz;

	if (kcmd != NULL && kcmd->num_servers > index + 1)
		return (ILB_STATUS_OK);

	/*
	 * the first ilb_server_info_t is part of *kcmd, so
	 * by using index (which is one less than the total needed) here,
	 * we allocate exactly the amount we need.
	 */
	sz = sizeof (*kcmd) + (index * sizeof (ilb_server_info_t));
	kcmd = (ilb_servers_info_cmd_t *)realloc(kcmd, sz);
	if (kcmd == NULL)
		return (ILB_STATUS_ENOMEM);

	/*
	 * we don't count the slot we newly allocated yet.
	 */
	kcmd->num_servers = index;
	*kcmdp = kcmd;

	return (ILB_STATUS_OK);
}

/*
 * this function adds all servers in srvlist to the kernel(!) rule
 * the name of which is passed as argument.
 */
static ilb_status_t
i_update_ksrv_rules(char *name, ilbd_sg_t *sg, ilbd_rule_t *rl)
{
	ilb_status_t		rc;
	ilbd_srv_t		*srvp;
	ilb_servers_info_cmd_t	*kcmd = NULL;
	int			i;

	/*
	 * If the servergroup doesn't have any servers associated with
	 * it yet, there's nothing more to do here.
	 */
	if (sg->isg_srvcount == 0)
		return (ILB_STATUS_OK);

	/*
	 * walk the list of servers attached to this SG
	 */
	srvp = list_head(&sg->isg_srvlist);
	for (i = 0; srvp != NULL; srvp = list_next(&sg->isg_srvlist, srvp)) {
		rc = adjust_srv_info_cmd(&kcmd, i);
		if (rc != ILB_STATUS_OK)
			goto rollback_kcmd;

		ILB_SGSRV_2_KSRV(&srvp->isv_srv, &kcmd->servers[i]);
		/*
		 * "no port" means "copy rule's port" (for kernel rule)
		 */
		if (kcmd->servers[i].min_port == 0) {
			kcmd->servers[i].min_port = rl->irl_minport;
			kcmd->servers[i].max_port = rl->irl_maxport;
		}
		i++;
	}
	assert(kcmd != NULL);

	kcmd->cmd = ILB_ADD_SERVERS;
	kcmd->num_servers = i;
	(void) strlcpy(kcmd->name, name, sizeof (kcmd->name));

	rc = do_ioctl(kcmd, 0);
	if (rc != ILB_STATUS_OK)
		goto rollback_kcmd;

	for (i = 0; i < kcmd->num_servers; i++) {
		int e;

		if ((e = kcmd->servers[i].err) != 0) {
			logerr("i_update_ksrv_rules "
			    "ioctl indicates failure: %s", strerror(e));
			rc = ilb_map_errno2ilbstat(e);
			/*
			 * if adding even a single server failed, we need to
			 * roll back the whole wad. We ignore any errors and
			 * return the one that was returned by the first ioctl.
			 */
			kcmd->cmd = ILB_DEL_SERVERS;
			(void) do_ioctl(kcmd, 0);
			goto rollback_kcmd;
		}
	}

rollback_kcmd:
	free(kcmd);
	return (rc);
}

/* convert a struct in6_addr to valstr */
void
ilbd_ip_to_str(uint16_t ipversion, struct in6_addr *addr, char *valstr)
{
	size_t	vallen;
	ilb_ip_addr_t	ipaddr;
	void	*addrptr;

	vallen = (ipversion == AF_INET) ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;

	IP_COPY_IMPL_2_CLI(addr, &ipaddr);
	addrptr = (ipversion == AF_INET) ?
	    (void *)&ipaddr.ia_v4 : (void *)&ipaddr.ia_v6;
	if (inet_ntop(ipversion, (void *)addrptr, valstr, vallen == NULL))
		logerr("ilbd_ip_to_str: inet_ntop failed");
	return;

}

ilb_status_t
ilbd_create_rule(ilb_rule_info_t *rl, int ev_port,
    const struct passwd *ps, ucred_t *ucredp)
{
	ilb_status_t	rc;
	ilbd_rule_t	*irl = NULL;
	ilbd_sg_t	*sg;
	ilb_rule_cmd_t	*kcmd = NULL;

	if (ps != NULL) {
		if ((rc = ilbd_check_client_config_auth(ps)) != ILB_STATUS_OK)
			goto out;
	}

	if (i_find_rule_byname(rl->rl_name) != NULL) {
		logdebug("ilbd_create_rule: rule %s"
		    " already exists", rl->rl_name);
		ilbd_audit_rule_event(NULL, rl, ILBD_CREATE_RULE,
		    ILB_STATUS_DUP_RULE, ucredp);
		return (ILB_STATUS_DUP_RULE);
	}

	sg = i_find_sg_byname(rl->rl_sgname);
	if (sg == NULL) {
		logdebug("ilbd_create_rule: rule %s uses non-existent"
		    " servergroup name %s", rl->rl_name, rl->rl_sgname);
		ilbd_audit_rule_event(NULL, rl, ILBD_CREATE_RULE,
		    ILB_STATUS_SGUNAVAIL, ucredp);
		return (ILB_STATUS_SGUNAVAIL);
	}

	if ((rc = ilbd_sg_check_rule_port(sg, rl)) != ILB_STATUS_OK) {
		ilbd_audit_rule_event(NULL, rl, ILBD_CREATE_RULE, rc, ucredp);
		return (rc);
	}

	/* allocs and copies contents of arg (if != NULL) into new rule */
	irl = i_alloc_ilbd_rule(rl);
	if (irl == NULL) {
		ilbd_audit_rule_event(NULL, rl, ILBD_CREATE_RULE,
		    ILB_STATUS_ENOMEM, ucredp);
		return (ILB_STATUS_ENOMEM);
	}

	/* make sure rule's IPversion (via vip) and SG's match */
	if (sg->isg_srvcount > 0) {
		ilbd_srv_t	*srv = list_head(&sg->isg_srvlist);
		int32_t		r_af = rl->rl_ipversion;
		int32_t		s_af = GET_AF(&srv->isv_addr);

		if (r_af != s_af) {
			logdebug("address family mismatch with servergroup");
			rc = ILB_STATUS_MISMATCHSG;
			goto out;
		}
	}
	irl->irl_sg = sg;

	/* Try associating the rule with the given hc oject. */
	if (RULE_HAS_HC(irl)) {
		if ((rc = ilbd_hc_associate_rule(irl, ev_port)) !=
		    ILB_STATUS_OK)
			goto out;
	}

	/*
	 * checks are done, now:
	 * 1. create rule in kernel
	 * 2. tell it about the backend server (which we maintain in SG)
	 * 3. attach the rule in memory
	 */
	/* 1. */
	/* allocs and copies contents of arg (if != NULL) into new rule */
	kcmd = i_alloc_kernel_rule_cmd(irl);
	if (kcmd == NULL) {
		rc = ILB_STATUS_ENOMEM;
		goto rollback_hc;
	}
	kcmd->cmd = ILB_CREATE_RULE;

	rc = do_ioctl(kcmd, 0);
	if (rc != ILB_STATUS_OK)
		goto rollback_kcmd;

	/* 2. */
	rc = i_update_ksrv_rules(kcmd->name, sg, irl);
	if (rc != ILB_STATUS_OK)
		goto rollback_kcmd;

	/* 3. */
	(void) i_attach_rule2sg(sg, irl);
	list_insert_tail(&ilbd_rule_hlist, irl);

	if (ps != NULL) {
		rc = i_ilbd_save_rule(irl, ILBD_SCF_CREATE);
		if (rc != ILB_STATUS_OK)
			goto rollback_rule;
	}

	free(kcmd);
	ilbd_audit_rule_event(NULL, rl, ILBD_CREATE_RULE,
	    ILB_STATUS_OK, ucredp);
	return (ILB_STATUS_OK);

rollback_rule:
	/*
	 * ilbd_destroy_one_rule() also frees irl, as well as dissociate
	 * rule and HC, so all we need to do afterwards is free the kcmd
	 * and return.
	 */
	(void) ilbd_destroy_one_rule(irl);
	ilbd_audit_rule_event(NULL, rl, ILBD_CREATE_RULE, rc, ucredp);
	free(kcmd);
	return (rc);

rollback_kcmd:
	free(kcmd);
rollback_hc:
	/* Cannot fail since the rule is just associated with the hc object. */
	if (RULE_HAS_HC(irl))
		(void) ilbd_hc_dissociate_rule(irl);
out:
	ilbd_audit_rule_event(NULL, rl, ILBD_CREATE_RULE, rc, ucredp);
	free(irl);
	return (rc);
}

static uint32_t
i_flags_d2k(int f)
{
	uint32_t	r = 0;

	if (ILB_IS_SRV_ENABLED(f))
		r |= ILB_SERVER_ENABLED;
	/* more as they are defined */

	return (r);
}

/*
 * walk the list of rules and add srv to the *kernel* rule
 * (this is a list of rules hanging off of a server group)
 */
ilb_status_t
i_add_srv2krules(list_t *rlist, ilb_sg_srv_t *srv, int ev_port)
{
	ilb_status_t		rc = ILB_STATUS_OK;
	ilbd_rule_t		*rl, *del_rl;
	ilb_servers_info_cmd_t	kcmd;
	ilb_servers_cmd_t	del_kcmd;

	kcmd.cmd = ILB_ADD_SERVERS;
	kcmd.num_servers = 1;
	kcmd.servers[0].err = 0;
	kcmd.servers[0].addr = srv->sgs_addr;
	kcmd.servers[0].flags = i_flags_d2k(srv->sgs_flags);
	(void) strlcpy(kcmd.servers[0].name, srv->sgs_srvID,
	    sizeof (kcmd.servers[0].name));

	/*
	 * a note about rollback: since we need to start rollback with the
	 * current list element in some case, and with the previous one
	 * in others, we must "go back" in this latter case before
	 * we jump to the rollback code.
	 */
	for (rl = list_head(rlist); rl != NULL; rl = list_next(rlist, rl)) {
		(void) strlcpy(kcmd.name, rl->irl_name, sizeof (kcmd.name));
		/*
		 * sgs_minport == 0 means "no port specified"; this
		 * indicates that the server matches anything the rule
		 * provides.
		 * NOTE: this can be different for different rules
		 * using the same server group, therefore we don't modify
		 * this information in the servergroup, but *only* in
		 * the kernel's rule.
		 */
		if (srv->sgs_minport == 0) {
			kcmd.servers[0].min_port = rl->irl_minport;
			kcmd.servers[0].max_port = rl->irl_maxport;
		} else {
			kcmd.servers[0].min_port = srv->sgs_minport;
			kcmd.servers[0].max_port = srv->sgs_maxport;
		}
		rc = do_ioctl((void *)&kcmd, 0);
		if (rc != ILB_STATUS_OK) {
			logdebug("i_add_srv2krules: do_ioctl call failed");
			del_rl = list_prev(rlist, rl);
			goto rollback;
		}

		/*
		 * if ioctl() returns != 0, it doesn't perform the copyout
		 * necessary to indicate *which* server failed (we could be
		 * adding more than one); therefore we must check this
		 * 'err' field even if ioctl() returns 0.
		 */
		if (kcmd.servers[0].err != 0) {
			logerr("i_add_srv2krules: SIOCILB ioctl returned"
			    " error %d", kcmd.servers[0].err);
			rc = ilb_map_errno2ilbstat(kcmd.servers[0].err);
			del_rl = list_prev(rlist, rl);
			goto rollback;
		}
		if (RULE_HAS_HC(rl)) {
			if ((rc = ilbd_hc_add_server(rl, srv, ev_port)) !=
			    ILB_STATUS_OK) {
				logerr("i_add_srv2krules: cannot start timer "
				    " for rules %s server %s", rl->irl_name,
				    srv->sgs_srvID);

				del_rl = rl;
				goto rollback;
			}
		}
	}

	return (rc);

rollback:
	/*
	 * this is almost, but not quite, the same as i_rem_srv_frm_krules()
	 * therefore we keep it seperate.
	 */
	del_kcmd.cmd = ILB_DEL_SERVERS;
	del_kcmd.num_servers = 1;
	del_kcmd.servers[0].addr = srv->sgs_addr;
	while (del_rl != NULL) {
		if (RULE_HAS_HC(del_rl))
			(void) ilbd_hc_del_server(del_rl, srv);
		(void) strlcpy(del_kcmd.name, del_rl->irl_name,
		    sizeof (del_kcmd.name));
		(void) do_ioctl((void *)&del_kcmd, 0);
		del_rl = list_prev(rlist, del_rl);
	}

	return (rc);
}

/*
 * ev_port is only used for rollback purposes in this function
 */
ilb_status_t
i_rem_srv_frm_krules(list_t *rlist, ilb_sg_srv_t *srv, int ev_port)
{
	ilb_status_t		rc = ILB_STATUS_OK;
	ilbd_rule_t		*rl, *add_rl;
	ilb_servers_cmd_t	kcmd;
	ilb_servers_info_cmd_t	add_kcmd;

	kcmd.cmd = ILB_DEL_SERVERS;
	kcmd.num_servers = 1;
	kcmd.servers[0].err = 0;
	kcmd.servers[0].addr = srv->sgs_addr;

	for (rl = list_head(rlist); rl != NULL; rl = list_next(rlist, rl)) {
		(void) strlcpy(kcmd.name, rl->irl_name, sizeof (kcmd.name));
		rc = do_ioctl((void *)&kcmd, 0);
		if (rc != ILB_STATUS_OK) {
			logdebug("i_rem_srv_frm_krules: do_ioctl"
			    "call failed");
			add_rl = list_prev(rlist, rl);
			goto rollback;
		}
		/*
		 * if ioctl() returns != 0, it doesn't perform the copyout
		 * necessary to indicate *which* server failed (we could be
		 * removing more than one); therefore we must check this
		 * 'err' field even if ioctl() returns 0.
		 */
		if (kcmd.servers[0].err != 0) {
			logerr("i_rem_srv_frm_krules: SIOCILB ioctl"
			    " returned error %s",
			    strerror(kcmd.servers[0].err));
			rc = ilb_map_errno2ilbstat(kcmd.servers[0].err);
			add_rl = list_prev(rlist, rl);
			goto rollback;
		}
		if (RULE_HAS_HC(rl) &&
		    (rc = ilbd_hc_del_server(rl, srv)) != ILB_STATUS_OK) {
			logerr("i_rem_srv_frm_krules: cannot delete "
			    "timer for rules %s server %s", rl->irl_name,
			    srv->sgs_srvID);
			add_rl = rl;
			goto rollback;
		}
	}

	return (rc);

rollback:
	/* Don't do roll back if ev_port == -1. */
	if (ev_port == -1)
		return (rc);

	add_kcmd.cmd = ILB_ADD_SERVERS;
	add_kcmd.num_servers = 1;
	add_kcmd.servers[0].err = 0;
	add_kcmd.servers[0].addr = srv->sgs_addr;
	add_kcmd.servers[0].flags = i_flags_d2k(srv->sgs_flags);
	(void) strlcpy(add_kcmd.servers[0].name, srv->sgs_srvID,
	    sizeof (add_kcmd.servers[0].name));
	while (add_rl != NULL) {
		if (srv->sgs_minport == 0) {
			add_kcmd.servers[0].min_port = add_rl->irl_minport;
			add_kcmd.servers[0].max_port = add_rl->irl_maxport;
		} else {
			add_kcmd.servers[0].min_port = srv->sgs_minport;
			add_kcmd.servers[0].max_port = srv->sgs_maxport;
		}
		if (RULE_HAS_HC(add_rl))
			(void) ilbd_hc_add_server(add_rl, srv, ev_port);
		(void) strlcpy(add_kcmd.name, add_rl->irl_name,
		    sizeof (add_kcmd.name));
		(void) do_ioctl((void *)&add_kcmd, 0);
		add_rl = list_prev(rlist, add_rl);
	}

	return (rc);
}
