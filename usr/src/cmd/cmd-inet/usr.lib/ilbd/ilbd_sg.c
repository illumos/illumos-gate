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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <stdlib.h>
#include <strings.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/list.h>
#include <assert.h>
#include <errno.h>
#include <libilb.h>
#include <net/if.h>
#include <inet/ilb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "libilb_impl.h"
#include "ilbd.h"

typedef enum {
	not_searched,
	stop_found,
	cont_search,
	fail_search
} srch_ind_t;

static list_t	ilbd_sg_hlist;

static ilb_status_t i_delete_srv(ilbd_sg_t *, ilbd_srv_t *, int);
static void i_ilbd_free_srvID(ilbd_sg_t *, int32_t);

/* Last parameter to pass to i_find_srv(), specifying the matching mode */
#define	MODE_ADDR	1
#define	MODE_SRVID	2

static ilbd_srv_t *i_find_srv(list_t *, ilb_sg_srv_t *, int);

void
i_setup_sg_hlist(void)
{
	list_create(&ilbd_sg_hlist, sizeof (ilbd_sg_t),
	    offsetof(ilbd_sg_t, isg_link));
}

/*
 * allocate storage for a daemon-internal server group, init counters
 */
static ilbd_sg_t *
i_ilbd_alloc_sg(char *name)
{
	ilbd_sg_t	*d_sg;

	d_sg = calloc(sizeof (*d_sg), 1);
	if (d_sg == NULL)
		goto out;

	(void) strlcpy(d_sg->isg_name, name, sizeof (d_sg->isg_name));

	list_create(&d_sg->isg_srvlist, sizeof (ilbd_srv_t),
	    offsetof(ilbd_srv_t, isv_srv_link));
	list_create(&d_sg->isg_rulelist, sizeof (ilbd_rule_t),
	    offsetof(ilbd_rule_t, irl_sglink));

	list_insert_tail(&ilbd_sg_hlist, d_sg);
out:
	return (d_sg);
}

static ilb_status_t
i_ilbd_save_sg(ilbd_sg_t *d_sg, ilbd_scf_cmd_t scf_cmd, const char *prop_name,
    char *valstr)
{
	switch (scf_cmd) {
	case ILBD_SCF_CREATE:
		return (ilbd_create_pg(ILBD_SCF_SG, (void *)d_sg));
	case ILBD_SCF_DESTROY:
		return (ilbd_destroy_pg(ILBD_SCF_SG, d_sg->isg_name));
	case ILBD_SCF_ENABLE_DISABLE:
		if (prop_name == NULL)
			return (ILB_STATUS_EINVAL);
		return (ilbd_change_prop(ILBD_SCF_SG, d_sg->isg_name,
		    prop_name, valstr));
	default:
		logdebug("i_ilbd_save_sg: invalid scf cmd %d", scf_cmd);
		return (ILB_STATUS_EINVAL);
	}
}

ilb_status_t
i_attach_rule2sg(ilbd_sg_t *sg, ilbd_rule_t *irl)
{
	/* assert: the same rule is attached to any sg only once */
	list_insert_tail(&sg->isg_rulelist, irl);
	return (ILB_STATUS_OK);
}

static void
i_ilbd_free_sg(ilbd_sg_t *sg)
{
	ilbd_srv_t *tmp_srv;

	if (sg == NULL)
		return;
	list_remove(&ilbd_sg_hlist, sg);
	while ((tmp_srv = list_remove_tail(&sg->isg_srvlist)) != NULL) {
		i_ilbd_free_srvID(sg, tmp_srv->isv_id);
		free(tmp_srv);
		sg->isg_srvcount--;
	}
	free(sg);
}

ilbd_sg_t *
i_find_sg_byname(const char *name)
{
	ilbd_sg_t *sg;

	/* find position of sg in list */
	for (sg = list_head(&ilbd_sg_hlist); sg != NULL;
	    sg = list_next(&ilbd_sg_hlist, sg)) {
		if (strncmp(sg->isg_name, name, sizeof (sg->isg_name)) == 0)
			return (sg);
	}
	return (sg);
}

/*
 * Generates an audit record for enable-server, disable-server, remove-server
 * delete-servergroup, create-servergroup and add-server subcommands.
 */
static void
ilbd_audit_server_event(audit_sg_event_data_t *data,
    ilbd_cmd_t cmd, ilb_status_t rc, ucred_t *ucredp)
{
	adt_session_data_t	*ah;
	adt_event_data_t	*event;
	au_event_t	flag;
	int	audit_error;

	if ((ucredp == NULL) && ((cmd == ILBD_ADD_SERVER_TO_GROUP) ||
	    (cmd == ILBD_CREATE_SERVERGROUP)))  {
		/*
		 * We came here from the path where ilbd is
		 * incorporating the ILB configuration from
		 * SCF. In that case, we skip auditing
		 */
		return;
	}

	if (adt_start_session(&ah, NULL, 0) != 0) {
		logerr("ilbd_audit_server_event: adt_start_session failed");
		exit(EXIT_FAILURE);
	}

	if (adt_set_from_ucred(ah, ucredp, ADT_NEW) != 0) {
		(void) adt_end_session(ah);
		logerr("ilbd_audit_server_event: adt_set_from_ucred failed");
		exit(EXIT_FAILURE);
	}

	if (cmd == ILBD_ENABLE_SERVER)
		flag = ADT_ilb_enable_server;
	else if (cmd == ILBD_DISABLE_SERVER)
		flag = ADT_ilb_disable_server;
	else if (cmd == ILBD_REM_SERVER_FROM_GROUP)
		flag = ADT_ilb_remove_server;
	else if (cmd == ILBD_ADD_SERVER_TO_GROUP)
		flag = ADT_ilb_add_server;
	else if (cmd == ILBD_CREATE_SERVERGROUP)
		flag = ADT_ilb_create_servergroup;
	else if (cmd == ILBD_DESTROY_SERVERGROUP)
		flag = ADT_ilb_delete_servergroup;

	if ((event = adt_alloc_event(ah, flag)) == NULL) {
		logerr("ilbd_audit_server_event: adt_alloc_event failed");
		exit(EXIT_FAILURE);
	}
	(void) memset((char *)event, 0, sizeof (adt_event_data_t));

	switch (cmd) {
	case ILBD_ENABLE_SERVER:
		event->adt_ilb_enable_server.auth_used =
		    NET_ILB_ENABLE_AUTH;
		event->adt_ilb_enable_server.server_id =
		    data->ed_serverid;
		event->adt_ilb_enable_server.server_ipaddress_type =
		    data->ed_ipaddr_type;
		(void) memcpy(event->adt_ilb_enable_server.server_ipaddress,
		    data->ed_server_address,
		    (sizeof (data->ed_server_address)));
		break;
	case ILBD_DISABLE_SERVER:
		event->adt_ilb_disable_server.auth_used =
		    NET_ILB_ENABLE_AUTH;
		event->adt_ilb_disable_server.server_id =
		    data->ed_serverid;
		event->adt_ilb_disable_server.server_ipaddress_type =
		    data->ed_ipaddr_type;
		(void) memcpy(event->adt_ilb_disable_server.server_ipaddress,
		    data->ed_server_address,
		    (sizeof (data->ed_server_address)));
		break;
	case ILBD_REM_SERVER_FROM_GROUP:
		event->adt_ilb_remove_server.auth_used =
		    NET_ILB_CONFIG_AUTH;
		event->adt_ilb_remove_server.server_id =
		    data->ed_serverid;
		event->adt_ilb_remove_server.server_group = data->ed_sgroup;
		event->adt_ilb_remove_server.server_ipaddress_type =
		    data->ed_ipaddr_type;
		(void) memcpy(event->adt_ilb_remove_server.server_ipaddress,
		    data->ed_server_address,
		    (sizeof (data->ed_server_address)));
		break;
	case ILBD_CREATE_SERVERGROUP:
		event->adt_ilb_create_servergroup.auth_used =
		    NET_ILB_CONFIG_AUTH;
		event->adt_ilb_create_servergroup.server_group =
		    data->ed_sgroup;
		break;
	case ILBD_ADD_SERVER_TO_GROUP:
		event->adt_ilb_add_server.auth_used =
		    NET_ILB_CONFIG_AUTH;
		event->adt_ilb_add_server.server_ipaddress_type =
		    data->ed_ipaddr_type;
		(void) memcpy(event->adt_ilb_add_server.server_ipaddress,
		    data->ed_server_address,
		    (sizeof (data->ed_server_address)));
		event->adt_ilb_add_server.server_id =
		    data->ed_serverid;
		event->adt_ilb_add_server.server_group =
		    data->ed_sgroup;
		event->adt_ilb_add_server.server_minport =
		    ntohs(data->ed_minport);
		event->adt_ilb_add_server.server_maxport =
		    ntohs(data->ed_maxport);
		break;
	case ILBD_DESTROY_SERVERGROUP:
		event->adt_ilb_delete_servergroup.auth_used =
		    NET_ILB_CONFIG_AUTH;
		event->adt_ilb_delete_servergroup.server_group =
		    data->ed_sgroup;
		break;
	}

	/* Fill in success/failure */
	if (rc == ILB_STATUS_OK) {
		if (adt_put_event(event, ADT_SUCCESS, ADT_SUCCESS) != 0) {
			logerr("ilbd_audit_server_event:"
			    " adt_put_event failed");
			exit(EXIT_FAILURE);
		}
	} else {
		audit_error = ilberror2auditerror(rc);
		if (adt_put_event(event, ADT_FAILURE, audit_error) != 0) {
			logerr("ilbd_audit_server_event:"
			    " adt_put_event failed");
			exit(EXIT_FAILURE);
		}
	}
	adt_free_event(event);
	(void) adt_end_session(ah);
}

ilb_status_t
ilbd_destroy_sg(const char *sg_name, const struct passwd *ps,
    ucred_t *ucredp)
{
	ilb_status_t	rc;
	ilbd_sg_t	*tmp_sg;
	audit_sg_event_data_t   audit_sg_data;

	(void) memset(&audit_sg_data, 0, sizeof (audit_sg_event_data_t));
	audit_sg_data.ed_sgroup = (char *)sg_name;

	rc = ilbd_check_client_config_auth(ps);
	if (rc != ILB_STATUS_OK) {
		ilbd_audit_server_event(&audit_sg_data,
		    ILBD_DESTROY_SERVERGROUP, rc, ucredp);
		return (rc);
	}

	tmp_sg = i_find_sg_byname(sg_name);
	if (tmp_sg == NULL) {
		logdebug("ilbd_destroy_sg: cannot find specified server"
		    " group %s", sg_name);
		ilbd_audit_server_event(&audit_sg_data,
		    ILBD_DESTROY_SERVERGROUP, ILB_STATUS_SGUNAVAIL, ucredp);
		return (ILB_STATUS_SGUNAVAIL);
	}

	/*
	 * we only destroy SGs that don't have any rules associated with
	 * them anymore.
	 */
	if (list_head(&tmp_sg->isg_rulelist) != NULL) {
		logdebug("ilbd_destroy_sg: server group %s has rules"
		" associated with it and thus cannot be"
		    " removed", tmp_sg->isg_name);
		ilbd_audit_server_event(&audit_sg_data,
		    ILBD_DESTROY_SERVERGROUP, ILB_STATUS_SGINUSE, ucredp);
		return (ILB_STATUS_SGINUSE);
	}

	if (ps != NULL) {
		rc = i_ilbd_save_sg(tmp_sg, ILBD_SCF_DESTROY, NULL, NULL);
		if (rc != ILB_STATUS_OK) {
		ilbd_audit_server_event(&audit_sg_data,
		    ILBD_DESTROY_SERVERGROUP, rc, ucredp);
			return (rc);
		}
	}
	i_ilbd_free_sg(tmp_sg);
	ilbd_audit_server_event(&audit_sg_data, ILBD_DESTROY_SERVERGROUP,
	    rc, ucredp);
	return (rc);
}

/* ARGSUSED */
/*
 * Parameter ev_port is not used but has to have for read persistent configure
 * ilbd_create_sg(), ilbd_create_hc() and ilbd_create_rule() are callbacks
 * for ilbd_scf_instance_walk_pg() which requires the same signature.
 */
ilb_status_t
ilbd_create_sg(ilb_sg_info_t *sg, int ev_port, const struct passwd *ps,
    ucred_t *ucredp)
{
	ilb_status_t	rc = ILB_STATUS_OK;
	ilbd_sg_t	*d_sg;
	audit_sg_event_data_t   audit_sg_data;

	(void) memset(&audit_sg_data, 0, sizeof (audit_sg_event_data_t));
	audit_sg_data.ed_sgroup = sg->sg_name;

	if (ps != NULL) {
		rc = ilbd_check_client_config_auth(ps);
		if (rc != ILB_STATUS_OK) {
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_CREATE_SERVERGROUP, rc, ucredp);
			return (rc);
		}
	}

	if (i_find_sg_byname(sg->sg_name) != NULL) {
		logdebug("ilbd_create_sg: server group %s already exists",
		    sg->sg_name);
		ilbd_audit_server_event(&audit_sg_data,
		    ILBD_CREATE_SERVERGROUP, ILB_STATUS_SGEXISTS, ucredp);
		return (ILB_STATUS_SGEXISTS);
	}

	d_sg = i_ilbd_alloc_sg(sg->sg_name);
	if (d_sg == NULL) {
		ilbd_audit_server_event(&audit_sg_data,
		    ILBD_CREATE_SERVERGROUP, ILB_STATUS_ENOMEM, ucredp);
		return (ILB_STATUS_ENOMEM);
	}

	/*
	 * we've successfully created the sg in memory. Before we can
	 * return "success", we need to reflect this in persistent
	 * storage
	 */
	if (ps != NULL) {
		rc = i_ilbd_save_sg(d_sg, ILBD_SCF_CREATE, NULL, NULL);
		if (rc != ILB_STATUS_OK) {
			i_ilbd_free_sg(d_sg);
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_CREATE_SERVERGROUP, rc, ucredp);
			return (rc);
		}
	}
	ilbd_audit_server_event(&audit_sg_data,
	    ILBD_CREATE_SERVERGROUP, rc, ucredp);
	return (rc);
}

/*
 * This function checks whether tsrv should/can be inserted before lsrv
 * and does so if possible.
 * We keep the list in sorted order so we don't have to search it
 * in its entirety for overlap every time we insert a new server.
 * Return code:
 *	stop_found: don't continue searching because we found a place
 *	cont_search: continue with next element in the list
 *	fail_search: search failed (caller translates to ILB_STATUS_EEXIST)
 */
static srch_ind_t
i_test_and_insert(ilbd_srv_t *tsrv, ilbd_srv_t *lsrv, list_t *srvlist)
{
	struct in6_addr	*t1, *l1;
	int		fnd;

	t1 = &tsrv->isv_addr;
	l1 = &lsrv->isv_addr;

	if ((fnd = ilb_cmp_in6_addr(t1, l1, NULL)) == 1)
		return (cont_search);	/* search can continue */

	if (fnd == 0) {
		logdebug("i_test_and_insert: specified server already exists");
		return (fail_search);
	}
	/* the list is kept in ascending order */
	list_insert_before(srvlist, lsrv, tsrv);
	return (stop_found);
}


/*
 * copy a server description [ip1,ip2,port1,port2,srvID,flags]
 */
#define	COPY_SERVER(src, dest)					\
	(dest)->sgs_addr = (src)->sgs_addr;			\
	(dest)->sgs_minport = (src)->sgs_minport;		\
	(dest)->sgs_maxport = (src)->sgs_maxport;		\
	(dest)->sgs_id = (src)->sgs_id;				\
	(void) strlcpy((dest)->sgs_srvID, (src)->sgs_srvID,	\
	    sizeof ((dest)->sgs_srvID));			\
	(dest)->sgs_flags = (src)->sgs_flags

static ilb_status_t
i_add_srv2sg(ilbd_sg_t *dsg, ilb_sg_srv_t *srv, ilbd_srv_t **ret_srv)
{
	ilb_sg_srv_t	*n_sg_srv;
	list_t		*srvlist;
	srch_ind_t	search = not_searched;
	ilb_status_t	rc = ILB_STATUS_OK;
	ilbd_srv_t	*nsrv, *lsrv;
	in_port_t	h_minport, h_maxport;

	nsrv = calloc(sizeof (*nsrv), 1);
	if (nsrv == NULL)
		return (ILB_STATUS_ENOMEM);
	n_sg_srv = &nsrv->isv_srv;
	COPY_SERVER(srv, n_sg_srv);

	/*
	 * port info is in network byte order - we need host byte order
	 * for comparisons purposes
	 */
	h_minport = ntohs(n_sg_srv->sgs_minport);
	h_maxport = ntohs(n_sg_srv->sgs_maxport);
	if (h_minport != 0 && h_minport > h_maxport)
		n_sg_srv->sgs_maxport = n_sg_srv->sgs_minport;

	srvlist = &dsg->isg_srvlist;

	lsrv = list_head(srvlist);
	if (lsrv == NULL) {
		list_insert_head(srvlist, nsrv);
	} else {
		while (lsrv != NULL) {
			search = i_test_and_insert(nsrv, lsrv,
			    srvlist);

			if (search != cont_search)
				break;
			lsrv = list_next(srvlist, lsrv);

			/* if reaches the end of list, insert to the tail */
			if (search == cont_search && lsrv == NULL)
				list_insert_tail(srvlist, nsrv);
		}
		if (search == fail_search)
			rc = ILB_STATUS_EEXIST;
	}

	if (rc == ILB_STATUS_OK) {
		dsg->isg_srvcount++;
		*ret_srv = nsrv;
	} else {
		free(nsrv);
	}

	return (rc);
}

/*
 * Allocate a server ID.  The algorithm is simple.  Just check the ID array
 * of the server group and find an unused ID.  If *set_id is given, it
 * means that the ID is already allocated and the ID array needs to be
 * updated.  This is the case when ilbd reads from the persistent
 * configuration.
 */
static int32_t
i_ilbd_alloc_srvID(ilbd_sg_t *sg, int32_t *set_id)
{
	int32_t		id;
	int32_t		i;

	/* The server ID is already allocated, just update the ID array. */
	if (set_id != NULL) {
		assert(sg->isg_id_arr[*set_id] == 0);
		sg->isg_id_arr[*set_id] = 1;
		return (*set_id);
	}

	/* if we're "full up", give back something invalid */
	if (sg->isg_srvcount == MAX_SRVCOUNT)
		return (BAD_SRVID);

	i = sg->isg_max_id;
	for (id = 0; id < MAX_SRVCOUNT; id++) {
		if (sg->isg_id_arr[(id + i) % MAX_SRVCOUNT] == 0)
			break;
	}

	sg->isg_max_id = (id + i) % MAX_SRVCOUNT;
	sg->isg_id_arr[sg->isg_max_id] = 1;
	return (sg->isg_max_id);
}

/*
 * Free a server ID by updating the server group's ID array.
 */
static void
i_ilbd_free_srvID(ilbd_sg_t *sg, int32_t id)
{
	assert(sg->isg_id_arr[id] == 1);
	sg->isg_id_arr[id] = 0;
}

/*
 * This function is called by ilbd_add_server_to_group() and
 * ilb_remove_server_group() to create a audit record for a
 * failed servicing of add-server/remove-server command
 */
static void
fill_audit_record(ilb_sg_info_t *sg, audit_sg_event_data_t *audit_sg_data,
    ilbd_cmd_t cmd, ilb_status_t rc, ucred_t *ucredp)
{
	ilb_sg_srv_t	*tsrv;
	int	i;

	for (i = 0; i < sg->sg_srvcount; i++) {
		tsrv = &sg->sg_servers[i];
		if (cmd == ILBD_ADD_SERVER_TO_GROUP)  {

			audit_sg_data->ed_serverid = NULL;
			if (IN6_IS_ADDR_V4MAPPED(&tsrv->sgs_addr)) {
				audit_sg_data->ed_ipaddr_type = ADT_IPv4;
				cvt_addr(audit_sg_data->ed_server_address,
				    ADT_IPv4, tsrv->sgs_addr);
			} else {
				audit_sg_data->ed_ipaddr_type = ADT_IPv6;
				cvt_addr(audit_sg_data->ed_server_address,
				    ADT_IPv6, tsrv->sgs_addr);
			}
			audit_sg_data->ed_minport = tsrv->sgs_minport;
			audit_sg_data->ed_maxport = tsrv->sgs_maxport;
			audit_sg_data->ed_sgroup = sg->sg_name;
		} else if (cmd == ILBD_REM_SERVER_FROM_GROUP) {
			audit_sg_data->ed_serverid = tsrv->sgs_srvID;
			audit_sg_data->ed_sgroup = sg->sg_name;

			audit_sg_data->ed_minport = 0;
			audit_sg_data->ed_maxport = 0;
		}
		ilbd_audit_server_event(audit_sg_data, cmd, rc, ucredp);
	}
}

/*
 * the name(s) of the server(s) are encoded in the sg.
 */
ilb_status_t
ilbd_add_server_to_group(ilb_sg_info_t *sg_info, int ev_port,
    const struct passwd *ps, ucred_t *ucredp)
{
	ilb_status_t	rc = ILB_STATUS_OK;
	ilbd_sg_t	*tmp_sg;
	int		i, j;
	int32_t		new_id = BAD_SRVID;
	int32_t		af = AF_UNSPEC;
	ilbd_srv_t	*nsrv;
	ilb_sg_srv_t	*srv;
	audit_sg_event_data_t   audit_sg_data;

	if (ps != NULL) {
		rc = ilbd_check_client_config_auth(ps);
		if (rc != ILB_STATUS_OK) {
			fill_audit_record(sg_info, &audit_sg_data,
			    ILBD_ADD_SERVER_TO_GROUP, rc, ucredp);
			return (rc);
		}
	}

	tmp_sg = i_find_sg_byname(sg_info->sg_name);
	if (tmp_sg == NULL) {
		logdebug("ilbd_add_server_to_group: server"
		    " group %s does not exist", sg_info->sg_name);
		fill_audit_record(sg_info, &audit_sg_data,
		    ILBD_ADD_SERVER_TO_GROUP, ILB_STATUS_ENOENT, ucredp);
		return (ILB_STATUS_ENOENT);
	}

	/*
	 * we do the dance with address family below to make sure only
	 * IP addresses in the same AF get into an SG; the first one to get
	 * in sets the "tone"
	 * if this is the first server to join a group, check whether
	 * there's no mismatch with any *rules* already attached
	 */
	if (tmp_sg->isg_srvcount > 0) {
		ilbd_srv_t *tsrv = list_head(&tmp_sg->isg_srvlist);

		af = GET_AF(&tsrv->isv_addr);
	} else {
		ilbd_rule_t	*irl = list_head(&tmp_sg->isg_rulelist);

		if (irl != NULL)
			af = GET_AF(&irl->irl_vip);
	}

	for (i = 0; i < sg_info->sg_srvcount; i++) {
		srv = &sg_info->sg_servers[i];

		(void) memset(&audit_sg_data, 0, sizeof (audit_sg_data));
		if (IN6_IS_ADDR_V4MAPPED(&srv->sgs_addr)) {
			audit_sg_data.ed_ipaddr_type = ADT_IPv4;
			cvt_addr(audit_sg_data.ed_server_address, ADT_IPv4,
			    srv->sgs_addr);
		} else {
			audit_sg_data.ed_ipaddr_type = ADT_IPv6;
			cvt_addr(audit_sg_data.ed_server_address, ADT_IPv6,
			    srv->sgs_addr);
		}
		audit_sg_data.ed_minport = srv->sgs_minport;
		audit_sg_data.ed_maxport = srv->sgs_maxport;
		audit_sg_data.ed_sgroup = sg_info->sg_name;

		/* only test if we have sth to test against */
		if (af != AF_UNSPEC) {
			int32_t	sgs_af = GET_AF(&srv->sgs_addr);

			if (af != sgs_af) {
				logdebug("address family mismatch with previous"
				    " hosts in servergroup or with rule");
				rc = ILB_STATUS_MISMATCHH;
				ilbd_audit_server_event(&audit_sg_data,
				    ILBD_ADD_SERVER_TO_GROUP, rc, ucredp);
				goto rollback;
			}
		}

		/*
		 * PS: NULL means daemon is loading configure from scf.
		 * ServerID is already assigned, just update the ID array.
		 */
		if (ps != NULL) {
			new_id = i_ilbd_alloc_srvID(tmp_sg, NULL);
			if (new_id == BAD_SRVID) {
				logdebug("ilbd_add_server_to_group: server"
				    "group %s is full, no more servers"
				    " can be added", sg_info->sg_name);
				rc = ILB_STATUS_SGFULL;
				ilbd_audit_server_event(&audit_sg_data,
				    ILBD_ADD_SERVER_TO_GROUP, rc, ucredp);
				goto rollback;
			}
			srv->sgs_id = new_id;
		} else {
			new_id = i_ilbd_alloc_srvID(tmp_sg, &srv->sgs_id);
		}

		/*
		 * here we implement the requirement that server IDs start
		 * with a character that is not legal in hostnames - in our
		 * case, a "_" (underscore).
		 */
		(void) snprintf(srv->sgs_srvID,
		    sizeof (srv->sgs_srvID), "%c%s.%d", ILB_SRVID_PREFIX,
		    tmp_sg->isg_name, srv->sgs_id);
		audit_sg_data.ed_serverid = srv->sgs_srvID;

		/*
		 * Before we update the kernel rules by adding the server,
		 * we need to make checks and fail if any of the
		 * following is true:
		 *
		 * o if the server has single port and the servergroup
		 *   is associated to a DSR rule with a port range
		 * o if the server has a port range and the servergroup
		 *   is associated to a DSR rule with a port range and
		 *   the rule's min and max port does not exactly
		 *   match that of the server's.
		 * o if the the server has a port range and the servergroup
		 *   is associated to a NAT/Half-NAT rule with a port range
		 *   and the rule's port range size does not match that
		 *   of the server's.
		 * o if the rule has a fixed hc port, check that this port
		 *   is valid in the server's port specification.
		 */
		rc = i_check_srv2rules(&tmp_sg->isg_rulelist, srv);
		if (rc != ILB_STATUS_OK) {
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_ADD_SERVER_TO_GROUP, rc, ucredp);
			goto rollback;
		}

		if ((rc = i_add_srv2sg(tmp_sg, srv, &nsrv)) != ILB_STATUS_OK) {
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_ADD_SERVER_TO_GROUP, rc, ucredp);
			goto rollback;
		}

		rc = i_add_srv2krules(&tmp_sg->isg_rulelist, &nsrv->isv_srv,
		    ev_port);
		if (rc != ILB_STATUS_OK) {
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_ADD_SERVER_TO_GROUP, rc, ucredp);
			/*
			 * The failure may be due to the serverid being on
			 * hold in kernel for connection draining. But ilbd
			 * has no way of knowing that. So we are freeing up
			 * the serverid, and may run into the risk of
			 * having this failure again, if we choose this
			 * serverid  when processing the next add-server
			 * command for this servergroup, while connection
			 * draining is underway. We assume that the user
			 * will read the man page after they encounter
			 * this failure, and learn to not add any server
			 * to the servergroup until connection draining of
			 * all servers in the  servergroup is complete.
			 * XXX Need to revisit this when connection draining
			 * is reworked
			 */
			list_remove(&tmp_sg->isg_srvlist, nsrv);
			i_ilbd_free_srvID(tmp_sg, nsrv->isv_id);
			free(nsrv);
			tmp_sg->isg_srvcount--;
			goto rollback;
		}
		if (ps != NULL) {
			rc = ilbd_scf_add_srv(tmp_sg, nsrv);
			if (rc != ILB_STATUS_OK) {
				/*
				 * The following should not fail since the
				 * server is just added.  Just in case, we
				 * pass in -1 as the event port to avoid
				 * roll back in i_rem_srv_frm_krules() called
				 * by i_delete_srv().
				 */
				ilbd_audit_server_event(&audit_sg_data,
				    ILBD_ADD_SERVER_TO_GROUP, rc, ucredp);
				(void) i_delete_srv(tmp_sg, nsrv, -1);
				break;
			}
		}
	}

	if (rc == ILB_STATUS_OK) {
		ilbd_audit_server_event(&audit_sg_data,
		    ILBD_ADD_SERVER_TO_GROUP, rc, ucredp);
		return (rc);
	}

rollback:
	/*
	 * If ilbd is initializing based on the SCF data and something fails,
	 * the only choice is to transition the service to maintanence mode...
	 */
	if (ps == NULL) {
		logerr("%s: failure during initialization -"
		    " entering maintenance mode", __func__);
		(void) smf_maintain_instance(ILB_FMRI, SMF_IMMEDIATE);
		return (rc);
	}

	/*
	 * we need to roll back all servers previous to the one
	 * that just caused the failure
	 */
	for (j = i-1; j >= 0; j--) {
		srv = &sg_info->sg_servers[j];

		/* We should be able to find those servers just added. */
		nsrv = i_find_srv(&tmp_sg->isg_srvlist, srv, MODE_SRVID);
		assert(nsrv != NULL);
		(void) i_delete_srv(tmp_sg, nsrv, -1);
	}
	return (rc);
}

static srch_ind_t
i_match_srvID(ilb_sg_srv_t *sg_srv, ilbd_srv_t *lsrv)
{
	if (strncmp(sg_srv->sgs_srvID, lsrv->isv_srvID,
	    sizeof (sg_srv->sgs_srvID)) == 0) {
		return (stop_found);
	}
	return (cont_search);
}

/*
 * Sanity check on a rule's port specification against all the servers'
 * specification in its associated server group.
 *
 * 1. If the health check's probe port (hcport) is specified.
 *    - if server port range is specified, check if hcport is inside
 *      the range
 *    - if no server port is specified (meaning the port range is the same as
 *      the rule's port range), check if hcport is inside the rule's range.
 *
 * 2. If a server has no port specification, there is no conflict.
 *
 * 3. If the rule's load balance mode is DSR, a server port specification must
 *    be exactly the same as the rule's.
 *
 * 4. In other modes (NAT and half-NAT), the server's port range must be
 *    the same as the rule's, unless it is doing port collapsing (the server's
 *    port range is only 1).
 */
ilb_status_t
ilbd_sg_check_rule_port(ilbd_sg_t *sg, ilb_rule_info_t *rl)
{
	ilbd_srv_t	*srv;
	in_port_t	r_minport, r_maxport;

	/* Don't allow adding a rule to a sg with no server, for now... */
	if (sg->isg_srvcount == 0)
		return (ILB_STATUS_SGEMPTY);

	r_minport = ntohs(rl->rl_minport);
	r_maxport = ntohs(rl->rl_maxport);

	for (srv = list_head(&sg->isg_srvlist); srv != NULL;
	    srv = list_next(&sg->isg_srvlist, srv)) {
		in_port_t srv_minport, srv_maxport;
		int range;

		srv_minport = ntohs(srv->isv_minport);
		srv_maxport = ntohs(srv->isv_maxport);
		range = srv_maxport - srv_minport;

		/*
		 * If the rule has a specific probe port, check if that port is
		 * valid in all the servers' port specification.
		 */
		if (rl->rl_hcpflag == ILB_HCI_PROBE_FIX) {
			in_port_t hcport = ntohs(rl->rl_hcport);

			/* No server port specified. */
			if (srv_minport == 0) {
				if (hcport > r_maxport || hcport < r_minport) {
					return (ILB_STATUS_BADSG);
				}
			} else {
				if (hcport > srv_maxport ||
				    hcport < srv_minport) {
					return (ILB_STATUS_BADSG);
				}
			}
		}

		/*
		 * There is no server port specification, so there cannot be
		 * any conflict.
		 */
		if (srv_minport == 0)
			continue;

		if (rl->rl_topo == ILB_TOPO_DSR) {
			if (r_minport != srv_minport ||
			    r_maxport != srv_maxport) {
				return (ILB_STATUS_BADSG);
			}
		} else {
			if ((range != r_maxport - r_minport) && range != 0)
				return (ILB_STATUS_BADSG);
		}
	}

	return (ILB_STATUS_OK);
}

static srch_ind_t
i_match_srvIP(ilb_sg_srv_t *sg_srv, ilbd_srv_t *lsrv)
{
	if (IN6_ARE_ADDR_EQUAL(&sg_srv->sgs_addr, &lsrv->isv_addr))
		return (stop_found);
	return (cont_search);
}

static ilbd_srv_t *
i_find_srv(list_t *srvlist, ilb_sg_srv_t *sg_srv, int cmpmode)
{
	ilbd_srv_t	*tmp_srv;
	srch_ind_t	srch_res = cont_search;

	for (tmp_srv = list_head(srvlist); tmp_srv != NULL;
	    tmp_srv = list_next(srvlist, tmp_srv)) {
		switch (cmpmode) {
		case MODE_ADDR:
			srch_res = i_match_srvIP(sg_srv, tmp_srv);
			break;
		case MODE_SRVID:
			srch_res = i_match_srvID(sg_srv, tmp_srv);
			break;
		}
		if (srch_res == stop_found)
			break;
	}

	if (srch_res == stop_found)
		return (tmp_srv);
	return (NULL);
}

static ilb_status_t
i_delete_srv(ilbd_sg_t *sg, ilbd_srv_t *srv, int ev_port)
{
	ilb_status_t	rc;

	rc = i_rem_srv_frm_krules(&sg->isg_rulelist, &srv->isv_srv, ev_port);
	if (rc != ILB_STATUS_OK)
		return (rc);
	list_remove(&sg->isg_srvlist, srv);
	i_ilbd_free_srvID(sg, srv->isv_id);
	free(srv);
	sg->isg_srvcount--;
	return (ILB_STATUS_OK);
}

/*
 * some people argue that returning anything here is
 * useless - what *do* you do if you can't remove/destroy
 * something anyway?
 */
ilb_status_t
ilbd_rem_server_from_group(ilb_sg_info_t *sg_info, int ev_port,
    const struct passwd *ps, ucred_t *ucredp)
{
	ilb_status_t	rc = ILB_STATUS_OK;
	ilbd_sg_t	*tmp_sg;
	ilbd_srv_t	*srv, tmp_srv;
	ilb_sg_srv_t    *tsrv;
	audit_sg_event_data_t   audit_sg_data;

	rc = ilbd_check_client_config_auth(ps);
	if (rc != ILB_STATUS_OK) {
		fill_audit_record(sg_info, &audit_sg_data,
		    ILBD_REM_SERVER_FROM_GROUP, rc, ucredp);
		return (rc);
	}

	tmp_sg = i_find_sg_byname(sg_info->sg_name);
	if (tmp_sg == NULL) {
		logdebug("%s: server group %s\n does not exist", __func__,
		    sg_info->sg_name);
		fill_audit_record(sg_info, &audit_sg_data,
		    ILBD_REM_SERVER_FROM_GROUP, ILB_STATUS_SGUNAVAIL, ucredp);
		return (ILB_STATUS_SGUNAVAIL);
	}
	tsrv = &sg_info->sg_servers[0];
	audit_sg_data.ed_serverid = tsrv->sgs_srvID;
	audit_sg_data.ed_sgroup = sg_info->sg_name;

	assert(sg_info->sg_srvcount == 1);
	srv = i_find_srv(&tmp_sg->isg_srvlist, &sg_info->sg_servers[0],
	    MODE_SRVID);
	if (srv == NULL) {
		logdebug("%s: cannot find server in server group %s", __func__,
		    sg_info->sg_name);
		ilbd_audit_server_event(&audit_sg_data,
		    ILBD_REM_SERVER_FROM_GROUP, ILB_STATUS_SRVUNAVAIL, ucredp);
		return (ILB_STATUS_SRVUNAVAIL);
	}
	tsrv = &srv->isv_srv;
	if (IN6_IS_ADDR_V4MAPPED(&tsrv->sgs_addr)) {
		audit_sg_data.ed_ipaddr_type = ADT_IPv4;
		cvt_addr(audit_sg_data.ed_server_address, ADT_IPv4,
		    tsrv->sgs_addr);
	} else {
		audit_sg_data.ed_ipaddr_type = ADT_IPv6;
		cvt_addr(audit_sg_data.ed_server_address, ADT_IPv6,
		    tsrv->sgs_addr);
	}
	/*
	 * i_delete_srv frees srv, therefore we need to save
	 * this information for ilbd_scf_del_srv
	 */
	(void) memcpy(&tmp_srv, srv, sizeof (tmp_srv));

	rc = i_delete_srv(tmp_sg, srv, ev_port);
	if (rc != ILB_STATUS_OK) {
		ilbd_audit_server_event(&audit_sg_data,
		    ILBD_REM_SERVER_FROM_GROUP, rc, ucredp);
		return (rc);
	}

	if (ps != NULL) {
		if ((rc = ilbd_scf_del_srv(tmp_sg, &tmp_srv)) !=
		    ILB_STATUS_OK) {
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_REM_SERVER_FROM_GROUP, rc, ucredp);
			logerr("%s: SCF update failed - entering maintenance"
			    " mode", __func__);
			(void) smf_maintain_instance(ILB_FMRI, SMF_IMMEDIATE);
		}
	}
	ilbd_audit_server_event(&audit_sg_data,
	    ILBD_REM_SERVER_FROM_GROUP, rc, ucredp);
	return (rc);
}

ilb_status_t
ilbd_retrieve_names(ilbd_cmd_t cmd, uint32_t *rbuf, size_t *rbufsz)
{
	ilb_status_t	rc = ILB_STATUS_OK;
	ilbd_namelist_t	*nlist;
	size_t		tmp_rbufsz;

	tmp_rbufsz = *rbufsz;
	/* Set up the reply buffer.  rbufsz will be set to the new size. */
	ilbd_reply_ok(rbuf, rbufsz);

	/* Calculate how much space is left for holding name info. */
	*rbufsz += sizeof (ilbd_namelist_t);
	tmp_rbufsz -= *rbufsz;

	nlist = (ilbd_namelist_t *)&((ilb_comm_t *)rbuf)->ic_data;
	nlist->ilbl_count = 0;

	switch (cmd) {
	case ILBD_RETRIEVE_SG_NAMES: {
		ilbd_sg_t	*sg;

		for (sg = list_head(&ilbd_sg_hlist);
		    sg != NULL && tmp_rbufsz >= sizeof (ilbd_name_t);
		    sg = list_next(&ilbd_sg_hlist, sg),
		    tmp_rbufsz -= sizeof (ilbd_name_t)) {
			(void) strlcpy(nlist->ilbl_name[nlist->ilbl_count++],
			    sg->isg_name, sizeof (ilbd_name_t));
		}
		break;
	}
	case ILBD_RETRIEVE_RULE_NAMES: {
		ilbd_rule_t	*irl;
		extern list_t	ilbd_rule_hlist;

		for (irl = list_head(&ilbd_rule_hlist);
		    irl != NULL && tmp_rbufsz >= sizeof (ilbd_name_t);
		    irl = list_next(&ilbd_rule_hlist, irl),
		    tmp_rbufsz -= sizeof (ilbd_name_t)) {
			(void) strlcpy(nlist->ilbl_name[nlist->ilbl_count++],
			    irl->irl_name, sizeof (ilbd_name_t));
		}
		break;
	}
	case ILBD_RETRIEVE_HC_NAMES: {
		extern list_t	ilbd_hc_list;
		ilbd_hc_t	*hc;

		for (hc = list_head(&ilbd_hc_list);
		    hc != NULL && tmp_rbufsz >= sizeof (ilbd_name_t);
		    hc = list_next(&ilbd_hc_list, hc)) {
			(void) strlcpy(nlist->ilbl_name[nlist->ilbl_count++],
			    hc->ihc_name, sizeof (ilbd_name_t));
		}
		break;
	}
	default:
		logdebug("ilbd_retrieve_names: unknown command");
		return (ILB_STATUS_INVAL_CMD);
	}

	*rbufsz += nlist->ilbl_count * sizeof (ilbd_name_t);
	return (rc);
}

ilb_status_t
ilbd_retrieve_sg_hosts(const char *sg_name, uint32_t *rbuf, size_t *rbufsz)
{
	ilbd_sg_t	*dsg;
	ilbd_srv_t	*dsrv;
	list_t		*srvlist;
	ilb_sg_info_t	*sg_info;
	size_t		tmp_rbufsz;

	dsg = i_find_sg_byname(sg_name);
	if (dsg == NULL) {
		logdebug("ilbd_retrieve_sg_hosts: server group"
		    " %s not found", sg_name);
		return (ILB_STATUS_SGUNAVAIL);
	}

	srvlist = &dsg->isg_srvlist;
	dsrv = list_head(srvlist);

	tmp_rbufsz = *rbufsz;
	ilbd_reply_ok(rbuf, rbufsz);

	/* Calculate the size to hold all the hosts info. */
	*rbufsz += sizeof (ilb_sg_info_t);
	tmp_rbufsz -= *rbufsz;

	sg_info = (ilb_sg_info_t *)&((ilb_comm_t *)rbuf)->ic_data;
	(void) strlcpy(sg_info->sg_name, sg_name, sizeof (sg_info->sg_name));
	sg_info->sg_srvcount = 0;

	while (dsrv != NULL && tmp_rbufsz >= sizeof (ilb_sg_srv_t)) {
		sg_info->sg_servers[sg_info->sg_srvcount++] = dsrv->isv_srv;
		dsrv = list_next(srvlist, dsrv);
		tmp_rbufsz -= sizeof (ilb_sg_srv_t);
	}
	*rbufsz += sg_info->sg_srvcount * sizeof (ilb_sg_srv_t);
	return (ILB_STATUS_OK);
}

/*
 * this mapping function works on the assumption that HC only is
 * active when a server is enabled.
 */
static ilb_cmd_t
i_srvcmd_d2k(ilbd_srv_status_ind_t dcmd)
{
	ilb_cmd_t	cmd;

	switch (dcmd) {
	case stat_enable_server:
	case stat_declare_srv_alive:
		cmd = ILB_ENABLE_SERVERS;
		break;
	case stat_disable_server:
	case stat_declare_srv_dead:
		cmd = ILB_DISABLE_SERVERS;
		break;
	}

	return (cmd);
}

ilb_status_t
ilbd_k_Xable_server(const struct in6_addr *addr, const char *rlname,
    ilbd_srv_status_ind_t cmd)
{
	ilb_status_t		rc;
	ilb_servers_cmd_t	kcmd;
	int			e;

	kcmd.cmd = i_srvcmd_d2k(cmd);
	(void) strlcpy(kcmd.name, rlname, sizeof (kcmd.name));
	kcmd.num_servers = 1;

	kcmd.servers[0].addr = *addr;
	kcmd.servers[0].err = 0;

	rc = do_ioctl(&kcmd, 0);
	if (rc != ILB_STATUS_OK)
		return (rc);

	if ((e = kcmd.servers[0].err) != 0) {
		logdebug("ilbd_k_Xable_server: error %s occurred",
		    strerror(e));
		return (ilb_map_errno2ilbstat(e));
	}

	return (rc);
}

#define	IS_SRV_ENABLED(s)	ILB_IS_SRV_ENABLED((s)->sgs_flags)
#define	IS_SRV_DISABLED(s)	(!(IS_SRV_ENABLED(s)))

#define	SET_SRV_ENABLED(s)	ILB_SET_ENABLED((s)->sgs_flags)
#define	SET_SRV_DISABLED(s)	ILB_SET_DISABLED((s)->sgs_flags)

static ilb_status_t
ilbd_Xable_server(ilb_sg_info_t *sg, const struct passwd *ps,
    ilbd_srv_status_ind_t cmd, ucred_t *ucredp)
{
	ilb_status_t	rc = ILB_STATUS_OK;
	ilbd_sg_t	*isg;
	ilbd_srv_t	*tmp_srv;
	ilb_sg_srv_t 	*srv;
	ilbd_rule_t	*irl;
	char		*dot;
	int		scf_name_len = ILBD_MAX_NAME_LEN;
	int		scf_val_len = ILBD_MAX_VALUE_LEN;
	char		*prop_name = NULL;
	ilb_ip_addr_t	ipaddr;
	void		*addrptr;
	char		ipstr[INET6_ADDRSTRLEN], *valstr = NULL;
	int		ipver, vallen;
	char		sgname[ILB_NAMESZ];
	uint32_t	nflags;
	ilbd_srv_status_ind_t u_cmd;
	audit_sg_event_data_t   audit_sg_data;

	(void) memset(&audit_sg_data, 0, sizeof (audit_sg_data));

	/* we currently only implement a "list" of one */
	assert(sg->sg_srvcount == 1);

	srv = &sg->sg_servers[0];
	audit_sg_data.ed_serverid = srv->sgs_srvID;

	rc = ilbd_check_client_enable_auth(ps);
	if (rc != ILB_STATUS_OK) {
		ilbd_audit_server_event(&audit_sg_data,
		    ILBD_ENABLE_SERVER, rc, ucredp);
		return (rc);
	}

	if (srv->sgs_srvID[0] != ILB_SRVID_PREFIX) {
		switch (cmd) {
		case stat_disable_server:
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_DISABLE_SERVER,
			    ILB_STATUS_EINVAL, ucredp);
			break;
		case stat_enable_server:
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_ENABLE_SERVER,
			    ILB_STATUS_EINVAL, ucredp);
			break;
		}
		return (ILB_STATUS_EINVAL);
	}

	/*
	 * the following asserts that serverIDs are constructed
	 * along the pattern "_"<SG name>"."<number>
	 * so we look for the final "." to recreate the SG name.
	 */
	(void) strlcpy(sgname, srv->sgs_srvID + 1, sizeof (sgname));
	dot = strrchr(sgname, (int)'.');
	if (dot == NULL) {
		switch (cmd) {
		case stat_disable_server:
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_DISABLE_SERVER,
			    ILB_STATUS_EINVAL, ucredp);
			break;
		case stat_enable_server:
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_ENABLE_SERVER,
			    ILB_STATUS_EINVAL, ucredp);
			break;
		}
		return (ILB_STATUS_EINVAL);
	}

	/* make the non-sg_name part "invisible" */
	*dot = '\0';
	isg = i_find_sg_byname(sgname);
	if (isg == NULL) {
		switch (cmd) {
		case stat_disable_server:
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_DISABLE_SERVER,
			    ILB_STATUS_ENOENT, ucredp);
			break;
		case stat_enable_server:
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_ENABLE_SERVER,
			    ILB_STATUS_ENOENT, ucredp);
			break;
		}
		return (ILB_STATUS_ENOENT);
	}

	tmp_srv = i_find_srv(&isg->isg_srvlist, srv, MODE_SRVID);
	if (tmp_srv == NULL) {
		switch (cmd) {
		case stat_disable_server:
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_DISABLE_SERVER,
			    ILB_STATUS_ENOENT, ucredp);
			break;
		case stat_enable_server:
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_ENABLE_SERVER,
			    ILB_STATUS_ENOENT, ucredp);
			break;
		}
		return (ILB_STATUS_ENOENT);
	}

	/*
	 * if server's servergroup is not associated with
	 * a rule, do not enable it.
	 */
	irl = list_head(&isg->isg_rulelist);
	if (irl == NULL) {
		switch (cmd) {
		case stat_disable_server:
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_DISABLE_SERVER,
			    ILB_STATUS_INVAL_ENBSRVR, ucredp);
			break;
		case stat_enable_server:
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_ENABLE_SERVER,
			    ILB_STATUS_INVAL_ENBSRVR, ucredp);
			break;
		}
		return (ILB_STATUS_INVAL_ENBSRVR);
	}
	/* Fill in the server IP address for audit record */
	if (IN6_IS_ADDR_V4MAPPED(&tmp_srv->isv_addr)) {
		audit_sg_data.ed_ipaddr_type = ADT_IPv4;
		cvt_addr(audit_sg_data.ed_server_address, ADT_IPv4,
		    tmp_srv->isv_addr);
	} else {
		audit_sg_data.ed_ipaddr_type = ADT_IPv6;
		cvt_addr(audit_sg_data.ed_server_address, ADT_IPv6,
		    tmp_srv->isv_addr);
	}

	/*
	 * We have found the server in memory, perform the following
	 * tasks.
	 *
	 * 1. For every rule associated with this SG,
	 *    - tell the kernel
	 *    - tell the hc
	 * 2. Update our internal state and persistent configuration
	 *    if the new state is not the same as the old one.
	 */
	/* 1. */
	for (; irl != NULL; irl = list_next(&isg->isg_rulelist, irl)) {
		rc = ilbd_k_Xable_server(&tmp_srv->isv_addr,
		    irl->irl_name, cmd);
		if (rc != ILB_STATUS_OK) {
			switch (cmd) {
			case stat_disable_server:
				ilbd_audit_server_event(&audit_sg_data,
				    ILBD_DISABLE_SERVER, rc, ucredp);
				break;
			case stat_enable_server:
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_ENABLE_SERVER, rc, ucredp);
			break;
			}
			goto rollback_rules;
		}
		if (!RULE_HAS_HC(irl))
			continue;

		if (cmd == stat_disable_server) {
			rc = ilbd_hc_disable_server(irl,
			    &tmp_srv->isv_srv);
		} else {
			assert(cmd == stat_enable_server);
			rc = ilbd_hc_enable_server(irl,
			    &tmp_srv->isv_srv);
		}
		if (rc != ILB_STATUS_OK) {
			logdebug("ilbd_Xable_server: cannot toggle srv "
			    "timer, rc =%d, srv =%s%d\n", rc,
			    tmp_srv->isv_srvID,
			    tmp_srv->isv_id);
		}
	}

	/* 2. */
	if ((cmd == stat_disable_server &&
	    IS_SRV_DISABLED(&tmp_srv->isv_srv)) ||
	    (cmd == stat_enable_server &&
	    IS_SRV_ENABLED(&tmp_srv->isv_srv))) {
		switch (cmd) {
		case stat_disable_server:
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_DISABLE_SERVER, ILB_STATUS_OK, ucredp);
			break;
		case stat_enable_server:
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_ENABLE_SERVER, ILB_STATUS_OK, ucredp);
			break;
		}
		return (ILB_STATUS_OK);
	}

	nflags = tmp_srv->isv_flags;
	if (cmd == stat_enable_server)
		ILB_SET_ENABLED(nflags);
	else
		ILB_SET_DISABLED(nflags);

	IP_COPY_IMPL_2_CLI(&tmp_srv->isv_addr, &ipaddr);
	ipver = GET_AF(&tmp_srv->isv_addr);
	vallen = (ipver == AF_INET) ? INET_ADDRSTRLEN :
	    INET6_ADDRSTRLEN;
	addrptr = (ipver == AF_INET) ? (void *)&ipaddr.ia_v4 :
	    (void *)&ipaddr.ia_v6;
	if (inet_ntop(ipver, addrptr, ipstr, vallen) == NULL) {
		logerr("ilbd_Xable_server: failed transfer ip addr to"
		    " str");
		if (errno == ENOSPC)
			rc = ILB_STATUS_ENOMEM;
		else
			rc = ILB_STATUS_GENERIC;
		switch (cmd) {
		case stat_disable_server:
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_DISABLE_SERVER, rc, ucredp);
			break;
		case stat_enable_server:
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_ENABLE_SERVER, rc, ucredp);
			break;
		}
		goto rollback_rules;
	}

	if ((prop_name = malloc(scf_name_len)) == NULL)
		return (ILB_STATUS_ENOMEM);
	if ((valstr = malloc(scf_val_len)) == NULL) {
		free(prop_name);
		return (ILB_STATUS_ENOMEM);
	}

	(void) snprintf(valstr, scf_val_len, "%s;%d;%d-%d;%d",
	    ipstr, ipver,
	    ntohs(tmp_srv->isv_minport),
	    ntohs(tmp_srv->isv_maxport), nflags);
	(void) snprintf(prop_name, scf_name_len, "server%d",
	    tmp_srv->isv_id);

	switch (cmd) {
	case stat_disable_server:
		rc = i_ilbd_save_sg(isg, ILBD_SCF_ENABLE_DISABLE,
		    prop_name, valstr);
		if (rc == ILB_STATUS_OK)
			SET_SRV_DISABLED(&tmp_srv->isv_srv);
		break;
	case stat_enable_server:
		rc = i_ilbd_save_sg(isg, ILBD_SCF_ENABLE_DISABLE,
		    prop_name, valstr);
		if (rc == ILB_STATUS_OK)
			SET_SRV_ENABLED(&tmp_srv->isv_srv);
		break;
	}
	free(prop_name);
	free(valstr);
	if (rc == ILB_STATUS_OK) {
		switch (cmd) {
		case stat_disable_server:
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_DISABLE_SERVER, ILB_STATUS_OK, ucredp);
			break;
		case stat_enable_server:
			ilbd_audit_server_event(&audit_sg_data,
			    ILBD_ENABLE_SERVER, ILB_STATUS_OK, ucredp);
			break;
		}
		return (ILB_STATUS_OK);
	}

rollback_rules:
	if (cmd == stat_disable_server)
		u_cmd = stat_enable_server;
	else
		u_cmd = stat_disable_server;

	if (irl == NULL)
		irl = list_tail(&isg->isg_rulelist);
	else
		irl = list_prev(&isg->isg_rulelist, irl);

	for (; irl != NULL; irl = list_prev(&isg->isg_rulelist, irl)) {
		(void) ilbd_k_Xable_server(&tmp_srv->isv_addr,
		    irl->irl_name, u_cmd);
		if (!RULE_HAS_HC(irl))
			continue;

		if (u_cmd == stat_disable_server)
			(void) ilbd_hc_disable_server(irl, &tmp_srv->isv_srv);
		else
			(void) ilbd_hc_enable_server(irl, &tmp_srv->isv_srv);
	}

	return (rc);
}

ilb_status_t
ilbd_disable_server(ilb_sg_info_t *sg, const struct passwd *ps,
    ucred_t *ucredp)
{
	return (ilbd_Xable_server(sg, ps, stat_disable_server, ucredp));
}

ilb_status_t
ilbd_enable_server(ilb_sg_info_t *sg, const struct passwd *ps,
    ucred_t *ucredp)
{
	return (ilbd_Xable_server(sg, ps, stat_enable_server, ucredp));
}

/*
 * fill in the srvID for the given IP address in the 0th server
 */
ilb_status_t
ilbd_address_to_srvID(ilb_sg_info_t *sg, uint32_t *rbuf, size_t *rbufsz)
{
	ilbd_srv_t 	*tmp_srv;
	ilb_sg_srv_t 	*tsrv;
	ilbd_sg_t	*tmp_sg;

	ilbd_reply_ok(rbuf, rbufsz);
	tsrv = (ilb_sg_srv_t *)&((ilb_comm_t *)rbuf)->ic_data;
	*rbufsz += sizeof (ilb_sg_srv_t);

	tmp_sg = i_find_sg_byname(sg->sg_name);
	if (tmp_sg == NULL)
		return (ILB_STATUS_SGUNAVAIL);
	tsrv->sgs_addr = sg->sg_servers[0].sgs_addr;

	tmp_srv = i_find_srv(&tmp_sg->isg_srvlist, tsrv, MODE_ADDR);
	if (tmp_srv == NULL)
		return (ILB_STATUS_ENOENT);

	(void) strlcpy(tsrv->sgs_srvID, tmp_srv->isv_srvID,
	    sizeof (tsrv->sgs_srvID));

	return (ILB_STATUS_OK);
}

/*
 * fill in the address for the given serverID in the 0th server
 */
ilb_status_t
ilbd_srvID_to_address(ilb_sg_info_t *sg, uint32_t *rbuf, size_t *rbufsz)
{
	ilbd_srv_t 	*tmp_srv;
	ilb_sg_srv_t 	*tsrv;
	ilbd_sg_t	*tmp_sg;

	ilbd_reply_ok(rbuf, rbufsz);
	tsrv = (ilb_sg_srv_t *)&((ilb_comm_t *)rbuf)->ic_data;

	tmp_sg = i_find_sg_byname(sg->sg_name);
	if (tmp_sg == NULL)
		return (ILB_STATUS_SGUNAVAIL);
	(void) strlcpy(tsrv->sgs_srvID, sg->sg_servers[0].sgs_srvID,
	    sizeof (tsrv->sgs_srvID));

	tmp_srv = i_find_srv(&tmp_sg->isg_srvlist, tsrv, MODE_SRVID);
	if (tmp_srv == NULL)
		return (ILB_STATUS_ENOENT);

	tsrv->sgs_addr = tmp_srv->isv_addr;
	*rbufsz += sizeof (ilb_sg_srv_t);

	return (ILB_STATUS_OK);
}

/*
 * Map ilb_status errors to similar errno values from errno.h or
 * adt_event.h to be used for audit record
 */
int
ilberror2auditerror(ilb_status_t rc)
{
	int audit_error;

	switch (rc) {
	case ILB_STATUS_CFGAUTH:
		audit_error = ADT_FAIL_VALUE_AUTH;
		break;
	case ILB_STATUS_ENOMEM:
		audit_error = ENOMEM;
		break;
	case ILB_STATUS_ENOENT:
	case ILB_STATUS_ENOHCINFO:
	case ILB_STATUS_INVAL_HCTESTTYPE:
	case ILB_STATUS_INVAL_CMD:
	case ILB_STATUS_DUP_RULE:
	case ILB_STATUS_ENORULE:
	case ILB_STATUS_SGUNAVAIL:
		audit_error = ENOENT;
		break;
	case ILB_STATUS_EINVAL:
	case ILB_STATUS_MISMATCHSG:
	case ILB_STATUS_MISMATCHH:
	case ILB_STATUS_BADSG:
	case ILB_STATUS_INVAL_SRVR:
	case ILB_STATUS_INVAL_ENBSRVR:
	case ILB_STATUS_BADPORT:
		audit_error = EINVAL;
		break;
	case ILB_STATUS_EEXIST:
	case ILB_STATUS_SGEXISTS:
		audit_error = EEXIST;
		break;
	case ILB_STATUS_EWOULDBLOCK:
		audit_error = EWOULDBLOCK;
		break;
	case ILB_STATUS_INPROGRESS:
		audit_error = EINPROGRESS;
		break;
	case ILB_STATUS_INTERNAL:
	case ILB_STATUS_CALLBACK:
	case ILB_STATUS_PERMIT:
	case ILB_STATUS_RULE_NO_HC:
		audit_error = ADT_FAIL_VALUE_PROGRAM;
		break;
	case ILB_STATUS_SOCKET:
		audit_error = ENOTSOCK;
		break;
	case ILB_STATUS_READ:
	case ILB_STATUS_WRITE:
		audit_error = ENOTCONN;
		break;
	case ILB_STATUS_SGINUSE:
		audit_error = EADDRINUSE;
		break;
	case ILB_STATUS_SEND:
		audit_error = ECOMM;
		break;
	case ILB_STATUS_SGFULL:
		audit_error = EOVERFLOW;
		break;
	case ILB_STATUS_NAMETOOLONG:
		audit_error = ENAMETOOLONG;
		break;
	case ILB_STATUS_SRVUNAVAIL:
		audit_error = EHOSTUNREACH;
		break;
	default:
		audit_error = ADT_FAIL_VALUE_UNKNOWN;
		break;
	}
	return (audit_error);
}
