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
#include <sys/stropts.h>
#include <netinet/in.h>
#include <stddef.h>
#include "libilb.h"
#include "libilb_impl.h"

/* ARGSUSED */
static ilb_status_t
i_drop_hc(ilb_handle_t h, ilb_hc_info_t *hc, void *arg)
{
	return (ilb_destroy_hc(h, hc->hci_name));
}

/* ARGSUSED */
static ilb_status_t
i_drop_rule(ilb_handle_t h, ilb_rule_data_t *rd, void *arg)
{
	return (ilb_destroy_rule(h, rd->r_name));
}

/* ARGSUSED */
static ilb_status_t
i_drop_sg_srvs(ilb_handle_t h, ilb_server_data_t *srv, const char *sgname,
    void *arg)
{
	return (ilb_rem_server_from_group(h, sgname, srv));
}

/* ARGSUSED */
static ilb_status_t
i_drop_sg(ilb_handle_t h, ilb_sg_data_t *sg, void *arg)
{
	ilb_status_t	rc;

	rc = ilb_walk_servers(h, i_drop_sg_srvs, sg->sgd_name, (void *)sg);
	if (rc != ILB_STATUS_OK)
		return (rc);

	return (ilb_destroy_servergroup(h, sg->sgd_name));
}

ilb_status_t
ilb_reset_config(ilb_handle_t h)
{
	ilb_status_t	rc;

	if (h == NULL)
		return (ILB_STATUS_EINVAL);

	rc = ilb_walk_rules(h, i_drop_rule, NULL, NULL);
	if (rc != ILB_STATUS_OK)
		goto out;

	rc = ilb_walk_servergroups(h, i_drop_sg, NULL, NULL);
	if (rc != ILB_STATUS_OK)
		goto out;

	rc = ilb_walk_hc(h, i_drop_hc, NULL);
out:
	return (rc);
}

ilb_status_t
ilb_create_rule(ilb_handle_t h, const ilb_rule_data_t *rd)
{
	ilb_status_t	rc;
	ilb_comm_t	*ic;
	size_t		ic_sz;
	ilb_rule_info_t	*rl;

	if (h == ILB_INVALID_HANDLE || rd == NULL || *rd->r_name == '\0')
		return (ILB_STATUS_EINVAL);

	if ((ic = i_ilb_alloc_req(ILBD_CREATE_RULE, &ic_sz)) == NULL)
		return (ILB_STATUS_ENOMEM);
	rl = (ilb_rule_info_t *)&ic->ic_data;

	/*
	 * Since the IP address representation in ilb_rule_data_t and
	 * ilb_rule_info_t is different, we need to convert between
	 * them.
	 */
	(void) strlcpy(rl->rl_name, rd->r_name, sizeof (rl->rl_name));
	(void) strlcpy(rl->rl_sgname, rd->r_sgname, sizeof (rl->rl_sgname));
	(void) strlcpy(rl->rl_hcname, rd->r_hcname, sizeof (rl->rl_hcname));
	rl->rl_flags = rd->r_flags;
	rl->rl_proto = rd->r_proto;
	rl->rl_ipversion = rd->r_vip.ia_af;
	rl->rl_minport = rd->r_minport;
	if (ntohs(rd->r_maxport) < ntohs(rd->r_minport))
		rl->rl_maxport = rd->r_minport;
	else
		rl->rl_maxport = rd->r_maxport;
	rl->rl_algo = rd->r_algo;
	rl->rl_topo = rd->r_topo;
	rl->rl_conndrain = rd->r_conndrain;
	rl->rl_nat_timeout = rd->r_nat_timeout;
	rl->rl_sticky_timeout = rd->r_sticky_timeout;
	rl->rl_hcport = rd->r_hcport;
	rl->rl_hcpflag = rd->r_hcpflag;

	IP_COPY_CLI_2_IMPL(&rd->r_vip, &rl->rl_vip);
	IP_COPY_CLI_2_IMPL(&rd->r_stickymask, &rl->rl_stickymask);
	IP_COPY_CLI_2_IMPL(&rd->r_nat_src_start, &rl->rl_nat_src_start);
	IP_COPY_CLI_2_IMPL(&rd->r_nat_src_end, &rl->rl_nat_src_end);

	rc = i_ilb_do_comm(h, ic, ic_sz, ic, &ic_sz);
	if (rc != ILB_STATUS_OK)
		goto out;

	if (ic->ic_cmd != ILBD_CMD_OK)
		rc = *(ilb_status_t *)&ic->ic_data;

out:
	free(ic);
	return (rc);
}

static ilb_status_t
i_ilb_rule_action(ilb_handle_t h, const char *name, ilbd_cmd_t cmd)
{
	ilb_status_t	rc;
	ilb_comm_t	*ic;
	size_t		ic_sz;

	if (h == ILB_INVALID_HANDLE)
		return (ILB_STATUS_EINVAL);

	if ((ic = i_ilb_alloc_req(cmd, &ic_sz)) == NULL)
		return (ILB_STATUS_ENOMEM);

	if (name == NULL) {
		bzero(&ic->ic_data, sizeof (ilbd_name_t));
	} else {
		(void) strlcpy((char *)&ic->ic_data, name,
		    sizeof (ilbd_name_t));
	}

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
ilb_destroy_rule(ilb_handle_t h, const char *name)
{
	return (i_ilb_rule_action(h, name, ILBD_DESTROY_RULE));
}

ilb_status_t
ilb_enable_rule(ilb_handle_t h, const char *name)
{
	return (i_ilb_rule_action(h, name, ILBD_ENABLE_RULE));
}

ilb_status_t
ilb_disable_rule(ilb_handle_t h, const char *name)
{
	return (i_ilb_rule_action(h, name, ILBD_DISABLE_RULE));
}

ilb_status_t
i_ilb_retrieve_rule_names(ilb_handle_t h, ilb_comm_t **rbuf, size_t *rbufsz)
{
	ilb_status_t	rc;
	ilb_comm_t	ic, *tmp_rbuf;

	*rbufsz = ILBD_MSG_SIZE;
	if ((tmp_rbuf = malloc(*rbufsz)) == NULL)
		return (ILB_STATUS_ENOMEM);

	ic.ic_cmd = ILBD_RETRIEVE_RULE_NAMES;

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
i_ilb_walk_one_rule(ilb_handle_t h, rule_walkerfunc_t f, const char *name,
    void *arg)
{
	ilb_status_t		rc = ILB_STATUS_OK;
	ilb_rule_info_t		*rl = NULL;
	ilb_rule_data_t		rd;
	ilb_comm_t		*ic, *rbuf;
	size_t			ic_sz, rbufsz;


	if ((ic = i_ilb_alloc_req(ILBD_RETRIEVE_RULE, &ic_sz)) == NULL)
		return (ILB_STATUS_ENOMEM);
	rbufsz = sizeof (ilb_comm_t) + sizeof (ilb_rule_info_t);
	if ((rbuf = malloc(rbufsz)) == NULL) {
		free(ic);
		return (ILB_STATUS_ENOMEM);
	}

	(void) strlcpy((char *)&ic->ic_data,  name, sizeof (ilbd_name_t));
	rc = i_ilb_do_comm(h, ic, ic_sz, rbuf, &rbufsz);
	if (rc != ILB_STATUS_OK)
		goto out;
	if (rbuf->ic_cmd != ILBD_CMD_OK) {
		rc = *(ilb_status_t *)&rbuf->ic_data;
		goto out;
	}
	rl = (ilb_rule_info_t *)&rbuf->ic_data;

	/*
	 * Since the IP address representation in ilb_rule_data_t and
	 * ilb_rule_info_t is different, we need to convert between
	 * them.
	 */
	(void) strlcpy(rd.r_name, rl->rl_name, sizeof (rd.r_name));
	(void) strlcpy(rd.r_hcname, rl->rl_hcname, sizeof (rd.r_hcname));
	(void) strlcpy(rd.r_sgname, rl->rl_sgname, sizeof (rd.r_sgname));
	rd.r_flags = rl->rl_flags;
	rd.r_proto = rl->rl_proto;
	rd.r_minport = rl->rl_minport;
	rd.r_maxport = rl->rl_maxport;
	rd.r_algo = rl->rl_algo;
	rd.r_topo = rl->rl_topo;
	rd.r_conndrain = rl->rl_conndrain;
	rd.r_nat_timeout = rl->rl_nat_timeout;
	rd.r_sticky_timeout = rl->rl_sticky_timeout;
	rd.r_hcport = rl->rl_hcport;
	rd.r_hcpflag = rl->rl_hcpflag;

	IP_COPY_IMPL_2_CLI(&rl->rl_vip, &rd.r_vip);
	IP_COPY_IMPL_2_CLI(&rl->rl_nat_src_start, &rd.r_nat_src_start);
	IP_COPY_IMPL_2_CLI(&rl->rl_nat_src_end, &rd.r_nat_src_end);
	IP_COPY_IMPL_2_CLI(&rl->rl_stickymask, &rd.r_stickymask);

	rc = f(h, &rd, arg);

out:
	free(ic);
	free(rbuf);
	return (rc);
}

ilb_status_t
ilb_walk_rules(ilb_handle_t h, rule_walkerfunc_t f, const char *name,
    void *arg)
{
	ilb_status_t	rc;
	ilbd_namelist_t	*names;
	ilb_comm_t	*rbuf;
	size_t		rbufsz;
	int		i;

	if (h == NULL)
		return (ILB_STATUS_EINVAL);

	if (name != NULL)
		return (i_ilb_walk_one_rule(h, f, name, arg));

	rc = i_ilb_retrieve_rule_names(h, &rbuf, &rbufsz);
	if (rc != ILB_STATUS_OK)
		return (rc);

	names = (ilbd_namelist_t *)&rbuf->ic_data;
	for (i = 0; i < names->ilbl_count; i++) {
		rc = i_ilb_walk_one_rule(h, f, names->ilbl_name[i], arg);
		/*
		 * The rule may have been removed by another process since
		 * we retrieve all the rule names, just continue.
		 */
		if (rc == ILB_STATUS_ENOENT) {
			rc = ILB_STATUS_OK;
			continue;
		}
		if (rc != ILB_STATUS_OK)
			break;
	}

	free(rbuf);
	return (rc);
}
