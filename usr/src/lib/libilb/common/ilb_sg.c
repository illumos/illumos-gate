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

#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stddef.h>
#include <libilb_impl.h>
#include <libilb.h>

static ilb_status_t
i_ilb_addrem_sg(ilb_handle_t h, const char *sgname, ilbd_cmd_t cmd)
{
	ilb_status_t	rc;
	ilb_comm_t	*ic;
	size_t		ic_sz;

	if (h == ILB_INVALID_HANDLE || sgname == NULL || *sgname == '\0')
		return (ILB_STATUS_EINVAL);

	if (strlen(sgname) > ILB_SGNAME_SZ - 1)
		return (ILB_STATUS_NAMETOOLONG);

	if ((ic = i_ilb_alloc_req(cmd, &ic_sz)) == NULL)
		return (ILB_STATUS_ENOMEM);

	(void) strlcpy((char *)&ic->ic_data, sgname, sizeof (ilbd_name_t));

	rc = i_ilb_do_comm(h, ic, ic_sz, ic, &ic_sz);
	if (rc != ILB_STATUS_OK)
		goto out;

	if (ic->ic_cmd != ILBD_CMD_OK)
		rc = *(ilb_status_t *)&ic->ic_data;
out:
	free(ic);
	return (rc);
}

ilb_status_t
ilb_destroy_servergroup(ilb_handle_t h, const char *sgname)
{
	return (i_ilb_addrem_sg(h, sgname, ILBD_DESTROY_SERVERGROUP));
}

ilb_status_t
ilb_create_servergroup(ilb_handle_t h, const char *sgname)
{
	return (i_ilb_addrem_sg(h, sgname, ILBD_CREATE_SERVERGROUP));
}

static ilb_status_t
i_ilb_addrem_server_to_group(ilb_handle_t h, const char *sgname,
    ilb_server_data_t *srv, ilbd_cmd_t cmd)
{
	ilb_status_t		rc = ILB_STATUS_OK;
	ilb_sg_info_t		*sg;
	ilb_sg_srv_t		*sgs;
	in_port_t		h_maxport, h_minport;
	ilb_comm_t		*ic;
	size_t			ic_sz;

	if (h == ILB_INVALID_HANDLE || sgname == NULL ||
	    *sgname == '\0' || srv == NULL)
		return (ILB_STATUS_EINVAL);

	if (strlen(sgname) > ILB_SGNAME_SZ - 1)
		return (ILB_STATUS_NAMETOOLONG);

	/* now all the checks have passed, we can pass on the goods */
	if ((ic = i_ilb_alloc_req(cmd, &ic_sz)) == NULL)
		return (ILB_STATUS_ENOMEM);

	sg = (ilb_sg_info_t *)&ic->ic_data;
	sg->sg_srvcount = 1;
	(void) strlcpy(sg->sg_name, sgname, sizeof (sg->sg_name));

	sgs = &sg->sg_servers[0];

	IP_COPY_CLI_2_IMPL(&srv->sd_addr, &sgs->sgs_addr);
	h_minport = ntohs(srv->sd_minport);
	h_maxport = ntohs(srv->sd_maxport);
	sgs->sgs_minport = srv->sd_minport;
	if (h_minport != 0 && h_maxport < h_minport)
		sgs->sgs_maxport = srv->sd_minport;
	else
		sgs->sgs_maxport = srv->sd_maxport;

	sgs->sgs_flags = srv->sd_flags;
	if (srv->sd_srvID[0] == ILB_SRVID_PREFIX)
		(void) strlcpy(sgs->sgs_srvID, srv->sd_srvID,
		    sizeof (sgs->sgs_srvID));

	rc = i_ilb_do_comm(h, ic, ic_sz, ic, &ic_sz);
	if (rc != ILB_STATUS_OK)
		goto out;

	if (ic->ic_cmd != ILBD_CMD_OK)
		rc = *(ilb_status_t *)&ic->ic_data;

out:
	free(ic);
	return (rc);
}

ilb_status_t
ilb_add_server_to_group(ilb_handle_t h, const char *sgname,
    ilb_server_data_t *srv)
{
	return (i_ilb_addrem_server_to_group(h, sgname, srv,
	    ILBD_ADD_SERVER_TO_GROUP));
}

ilb_status_t
ilb_rem_server_from_group(ilb_handle_t h, const char *sgname,
    ilb_server_data_t *srv)
{
	return (i_ilb_addrem_server_to_group(h, sgname, srv,
	    ILBD_REM_SERVER_FROM_GROUP));
}

static ilb_status_t
i_ilb_retrieve_sg_names(ilb_handle_t h, ilb_comm_t **rbuf, size_t *rbufsz)
{
	ilb_status_t	rc;
	ilb_comm_t	ic, *tmp_rbuf;

	*rbufsz = ILBD_MSG_SIZE;
	if ((tmp_rbuf = malloc(*rbufsz)) == NULL)
		return (ILB_STATUS_ENOMEM);

	ic.ic_cmd = ILBD_RETRIEVE_SG_NAMES;
	rc = i_ilb_do_comm(h, &ic, sizeof (ic), tmp_rbuf, rbufsz);
	if (rc != ILB_STATUS_OK)
		goto out;

	if (tmp_rbuf->ic_cmd == ILBD_CMD_OK) {
		*rbuf = tmp_rbuf;
		return (rc);
	}
	rc = *(ilb_status_t *)&tmp_rbuf->ic_data;
out:
	free(tmp_rbuf);
	*rbuf = NULL;
	return (rc);
}

static ilb_status_t
i_ilb_retrieve_sg_hosts(ilb_handle_t h, const char *sgname, ilb_comm_t **rbuf,
    size_t *rbufsz)
{
	ilb_status_t	rc;
	ilb_comm_t	*ic, *tmp_rbuf;
	size_t		ic_sz;

	if ((ic = i_ilb_alloc_req(ILBD_RETRIEVE_SG_HOSTS, &ic_sz)) == NULL)
		return (ILB_STATUS_ENOMEM);
	*rbufsz = ILBD_MSG_SIZE;
	if ((tmp_rbuf = malloc(*rbufsz)) == NULL) {
		free(ic);
		*rbuf = NULL;
		return (ILB_STATUS_ENOMEM);
	}

	(void) strlcpy((char *)&ic->ic_data, sgname, sizeof (ilbd_name_t));
	rc = i_ilb_do_comm(h, ic, ic_sz, tmp_rbuf, rbufsz);
	if (rc != ILB_STATUS_OK)
		goto out;

	if (tmp_rbuf->ic_cmd == ILBD_CMD_OK) {
		*rbuf = tmp_rbuf;
		free(ic);
		return (rc);
	}
	rc = *(ilb_status_t *)&tmp_rbuf->ic_data;
out:
	free(ic);
	free(tmp_rbuf);
	*rbuf = NULL;
	return (rc);
}

typedef enum {
	walk_servers,
	walk_sg
} sgwalk_t;

/*
 * "walks" one sg (retrieves data) and depending on "walktype" argument
 * call servergroup function once per sg or server function once
 * for every server. in both cases, the argument "f" is cast to
 * be the proper function pointer type
 */
static ilb_status_t
i_ilb_walk_one_sg(ilb_handle_t h, void *f, const char *sgname, void *arg,
    sgwalk_t walktype)
{
	ilb_status_t	rc = ILB_STATUS_OK;
	ilb_sg_info_t	*sg_info;
	ilb_sg_srv_t	*srv;
	int		i;
	ilb_comm_t	*rbuf;
	size_t		rbufsz;

	rc = i_ilb_retrieve_sg_hosts(h, sgname, &rbuf, &rbufsz);
	if (rc != ILB_STATUS_OK)
		return (rc);
	sg_info = (ilb_sg_info_t *)&rbuf->ic_data;

	if (walktype == walk_sg) {
		sg_walkerfunc_t	sg_func = (sg_walkerfunc_t)f;
		ilb_sg_data_t	sgd;

		(void) strlcpy(sgd.sgd_name, sg_info->sg_name,
		    sizeof (sgd.sgd_name));
		sgd.sgd_srvcount = sg_info->sg_srvcount;
		sgd.sgd_flags = sg_info->sg_flags;
		rc = sg_func(h, &sgd, arg);
		goto out;
	}

	for (i = 0; i < sg_info->sg_srvcount; i++) {
		srv_walkerfunc_t srv_func = (srv_walkerfunc_t)f;
		ilb_server_data_t	 sd;

		srv = &sg_info->sg_servers[i];
		IP_COPY_IMPL_2_CLI(&srv->sgs_addr, &sd.sd_addr);
		sd.sd_minport = srv->sgs_minport;
		sd.sd_maxport = srv->sgs_maxport;
		sd.sd_flags = srv->sgs_flags;
		(void) strlcpy(sd.sd_srvID, srv->sgs_srvID,
		    sizeof (sd.sd_srvID));

		rc = srv_func(h, &sd, sg_info->sg_name, arg);
		if (rc != ILB_STATUS_OK)
			break;
	}

out:
	free(rbuf);
	return (rc);
}

/*
 * wrapper function for i_walk_one_sg; if necessary, gets list of
 * SG names and calles i_walk_one_sg with every name
 */
static ilb_status_t
i_walk_sgs(ilb_handle_t h, void *f, const char *sgname,
    void *arg, sgwalk_t walktype)
{
	ilb_status_t	rc;
	ilbd_namelist_t	*sgl;
	ilb_comm_t	*rbuf;
	size_t		rbufsz;
	int		i;

	if (sgname != NULL) {
		rc = i_ilb_walk_one_sg(h, f, sgname, arg, walktype);
		return (rc);
	}

	rc = i_ilb_retrieve_sg_names(h, &rbuf, &rbufsz);
	if (rc != ILB_STATUS_OK)
		return (rc);
	sgl = (ilbd_namelist_t *)&rbuf->ic_data;

	for (i = 0; i < sgl->ilbl_count; i++) {
		rc = i_ilb_walk_one_sg(h, f, sgl->ilbl_name[i], arg, walktype);
		/*
		 * The server group may have been removed by another
		 * process, just continue.
		 */
		if (rc == ILB_STATUS_SGUNAVAIL) {
			rc = ILB_STATUS_OK;
			continue;
		}
		if (rc != ILB_STATUS_OK)
			break;
	}
	free(rbuf);
	return (rc);
}

ilb_status_t
ilb_walk_servergroups(ilb_handle_t h, sg_walkerfunc_t f, const char *sgname,
    void *arg)
{
	return (i_walk_sgs(h, (void *)f, sgname, arg, walk_sg));
}

ilb_status_t
ilb_walk_servers(ilb_handle_t h, srv_walkerfunc_t f, const char *sgname,
    void *arg)
{
	return (i_walk_sgs(h, (void *)f, sgname, arg, walk_servers));
}

static ilb_status_t
ilb_Xable_server(ilb_handle_t h, ilb_server_data_t *srv, void *reserved,
    ilbd_cmd_t cmd)
{
	ilb_status_t	rc;
	ilb_sg_info_t	*sg_info;
	ilb_sg_srv_t	*sgs;
	in_port_t	h_maxport, h_minport;
	ilb_comm_t	*ic;
	size_t		ic_sz;

	if (h == NULL)
		return (ILB_STATUS_EINVAL);

	/*
	 * In this implementation, this needs to be NULL, so
	 * there's no ugly surprises with old apps once we attach
	 * meaning to this parameter.
	 */
	if (reserved != NULL)
		return (ILB_STATUS_EINVAL);

	/* now all the checks have passed, we can pass on the goods */
	if ((ic = i_ilb_alloc_req(cmd, &ic_sz)) == NULL)
		return (ILB_STATUS_ENOMEM);

	sg_info = (ilb_sg_info_t *)&ic->ic_data;
	sg_info->sg_srvcount = 1;

	sgs = &sg_info->sg_servers[0];

	/* make sure min_port <= max_port; comparison in host byte order! */
	h_maxport = ntohs(srv->sd_maxport);
	h_minport = ntohs(srv->sd_minport);
	if (h_maxport != 0 && h_maxport < h_minport)
		sgs->sgs_maxport = sgs->sgs_minport;
	else
		sgs->sgs_maxport = srv->sd_maxport;
	sgs->sgs_minport = srv->sd_minport;

	sgs->sgs_flags = srv->sd_flags;
	(void) strlcpy(sgs->sgs_srvID, srv->sd_srvID, sizeof (sgs->sgs_srvID));
	IP_COPY_CLI_2_IMPL(&srv->sd_addr, &sgs->sgs_addr);

	rc = i_ilb_do_comm(h, ic, ic_sz, ic, &ic_sz);
	if (rc != ILB_STATUS_OK)
		goto out;

	if (ic->ic_cmd != ILBD_CMD_OK)
		rc = *(ilb_status_t *)&ic->ic_data;
out:
	free(ic);
	return (rc);
}

ilb_status_t
ilb_enable_server(ilb_handle_t h, ilb_server_data_t *srv, void *reserved)
{
	return (ilb_Xable_server(h, srv, reserved, ILBD_ENABLE_SERVER));
}

ilb_status_t
ilb_disable_server(ilb_handle_t h, ilb_server_data_t *srv, void *reserved)
{
	return (ilb_Xable_server(h, srv, reserved, ILBD_DISABLE_SERVER));
}

static ilb_status_t
i_ilb_fillin_srvdata(ilb_handle_t h, ilb_server_data_t *srv, const char *sgname,
    ilbd_cmd_t cmd)
{
	ilb_status_t	rc;
	ilb_sg_info_t	*sg_info;
	ilb_sg_srv_t	*sgs;
	ilb_comm_t	*ic;
	size_t		ic_sz;
	ilb_comm_t	*rbuf;
	size_t		rbufsz;

	if (h == ILB_INVALID_HANDLE || sgname == NULL ||
	    *sgname == '\0' || srv == NULL)
		return (ILB_STATUS_EINVAL);

	if (cmd == ILBD_SRV_ID2ADDR && srv->sd_srvID[0] == '\0')
		return (ILB_STATUS_EINVAL);
	if (cmd == ILBD_SRV_ADDR2ID && !IS_AF_VALID(srv->sd_addr.ia_af))
		return (ILB_STATUS_EINVAL);

	if ((ic = i_ilb_alloc_req(cmd, &ic_sz)) == NULL)
		return (ILB_STATUS_ENOMEM);
	rbufsz = sizeof (ilb_comm_t) + sizeof (ilb_sg_srv_t);
	if ((rbuf = malloc(rbufsz)) == NULL) {
		free(ic);
		return (ILB_STATUS_ENOMEM);
	}

	sg_info = (ilb_sg_info_t *)&ic->ic_data;
	sg_info->sg_srvcount = 1;
	(void) strlcpy(sg_info->sg_name, sgname, sizeof (sg_info->sg_name));

	sgs = &sg_info->sg_servers[0];

	if (cmd == ILBD_SRV_ID2ADDR) {
		(void) strlcpy(sgs->sgs_srvID, srv->sd_srvID,
		    sizeof (sgs->sgs_srvID));
	} else {
		IP_COPY_CLI_2_IMPL(&srv->sd_addr, &sgs->sgs_addr);
	}

	rc = i_ilb_do_comm(h, ic, ic_sz, rbuf, &rbufsz);
	if (rc != ILB_STATUS_OK)
		goto out;

	if (rbuf->ic_cmd == ILBD_CMD_OK) {
		sgs = (ilb_sg_srv_t *)&rbuf->ic_data;
		if (cmd == ILBD_SRV_ID2ADDR) {
			IP_COPY_IMPL_2_CLI(&sgs->sgs_addr, &srv->sd_addr);
		} else {
			(void) strlcpy(srv->sd_srvID, sgs->sgs_srvID,
			    sizeof (sgs->sgs_srvID));
		}
		return (rc);
	}

	rc = *(ilb_status_t *)&rbuf->ic_data;
out:
	free(ic);
	return (rc);
}

ilb_status_t
ilb_srvID_to_address(ilb_handle_t h, ilb_server_data_t *srv, const char *sgname)
{
	return (i_ilb_fillin_srvdata(h, srv, sgname, ILBD_SRV_ID2ADDR));

}

ilb_status_t
ilb_address_to_srvID(ilb_handle_t h, ilb_server_data_t *srv, const char *sgname)
{
	return (i_ilb_fillin_srvdata(h, srv, sgname, ILBD_SRV_ADDR2ID));
}
