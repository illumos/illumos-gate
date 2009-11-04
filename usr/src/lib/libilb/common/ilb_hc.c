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

/*
 * Create a health check, returning a health check handle upon success.
 * Health check created will be recorded in persistent datastore.
 */
ilb_status_t
ilb_create_hc(ilb_handle_t h, const ilb_hc_info_t *hc)
{
	ilb_status_t	rc;
	ilb_comm_t	*ic;
	size_t		ic_sz;

	if (h == ILB_INVALID_HANDLE || hc == NULL || *hc->hci_name == '\0' ||
	    hc->hci_timeout < 0 || hc->hci_count < 0 ||
	    hc->hci_interval <= hc->hci_timeout * hc->hci_count)
		return (ILB_STATUS_EINVAL);

	if ((ic = i_ilb_alloc_req(ILBD_CREATE_HC, &ic_sz)) == NULL)
		return (ILB_STATUS_ENOMEM);

	(void) memcpy(&ic->ic_data, hc, sizeof (ilb_hc_info_t));

	rc = i_ilb_do_comm(h, ic, ic_sz, ic, &ic_sz);
	if (rc != ILB_STATUS_OK)
		goto out;

	if (ic->ic_cmd != ILBD_CMD_OK)
		rc = *(ilb_status_t *)&ic->ic_data;

out:
	free(ic);
	return (rc);
}

/*
 * Given a health check handle, destroy the corresponding health check.
 * Persistent datastore will be updated as well.
 */
ilb_status_t
ilb_destroy_hc(ilb_handle_t h, const char *hcname)
{
	ilb_status_t	rc;
	ilb_comm_t	*ic;
	size_t		ic_sz;

	if (h == ILB_INVALID_HANDLE || hcname == NULL || *hcname == '\0')
		return (ILB_STATUS_EINVAL);

	if ((ic = i_ilb_alloc_req(ILBD_DESTROY_HC, &ic_sz)) == NULL)
		return (ILB_STATUS_ENOMEM);

	(void) strlcpy((char *)&ic->ic_data, hcname, sizeof (ilbd_name_t));

	rc = i_ilb_do_comm(h, ic, ic_sz, ic, &ic_sz);
	if (rc != ILB_STATUS_OK)
		goto out;

	if (ic->ic_cmd != ILBD_CMD_OK)
		rc = *(ilb_status_t *)&ic->ic_data;

out:
	free(ic);
	return (rc);
}

/*
 * Given a health check name, get hc info associated with this handle
 */
ilb_status_t
ilb_get_hc_info(ilb_handle_t h, const char *name, ilb_hc_info_t *hcp)
{
	ilb_status_t	rc;
	ilb_comm_t	*ic, *rbuf;
	size_t		ic_sz, rbufsz;

	if (h == ILB_INVALID_HANDLE || name == NULL || hcp == NULL)
		return (ILB_STATUS_EINVAL);

	if ((ic = i_ilb_alloc_req(ILBD_GET_HC_INFO, &ic_sz)) == NULL)
		return (ILB_STATUS_ENOMEM);
	rbufsz = sizeof (ilb_comm_t) + sizeof (ilb_hc_info_t);
	if ((rbuf = malloc(rbufsz)) == NULL) {
		free(ic);
		return (ILB_STATUS_ENOMEM);
	}

	(void) strlcpy((char *)&ic->ic_data, name, sizeof (ilbd_name_t));

	rc = i_ilb_do_comm(h, ic, ic_sz, rbuf, &rbufsz);
	if (rc != ILB_STATUS_OK)
		goto out;

	if (rbuf->ic_cmd != ILBD_CMD_OK) {
		rc = *(ilb_status_t *)&rbuf->ic_data;
		goto out;
	}
	(void) memcpy(hcp, &rbuf->ic_data, sizeof (*hcp));

out:
	free(ic);
	free(rbuf);
	return (rc);
}

/*
 * Walk through all health checks, will need if we implement list-hc
 */
ilb_status_t
ilb_walk_hc(ilb_handle_t h, hc_walkerfunc_t func, void *arg)
{
	ilb_status_t	rc;
	ilb_hc_info_t	hc_info;
	ilbd_namelist_t	*hc_names;
	ilb_comm_t	ic, *rbuf;
	size_t		rbufsz;
	int		i;

	rbufsz = ILBD_MSG_SIZE;
	if ((rbuf = malloc(rbufsz)) == NULL)
		return (ILB_STATUS_ENOMEM);
	ic.ic_cmd = ILBD_RETRIEVE_HC_NAMES;

	rc = i_ilb_do_comm(h, &ic, sizeof (ic), rbuf, &rbufsz);
	if (rc != ILB_STATUS_OK)
		goto out;
	if (rbuf->ic_cmd != ILBD_CMD_OK) {
		rc = *(ilb_status_t *)&rbuf->ic_data;
		goto out;
	}

	hc_names = (ilbd_namelist_t *)&rbuf->ic_data;
	for (i = 0; i < hc_names->ilbl_count; i++) {
		rc = ilb_get_hc_info(h, hc_names->ilbl_name[i], &hc_info);
		/*
		 * Since getting the list of hc names and getting the info
		 * of each of them are not atomic, some hc objects may have
		 * been deleted.  If this is the case, just skip them.
		 */
		if (rc == ILB_STATUS_ENOENT) {
			rc = ILB_STATUS_OK;
			continue;
		} else if (rc != ILB_STATUS_OK) {
			break;
		}
		rc = func(h, &hc_info, arg);
	}

out:
	free(rbuf);
	return (rc);
}

static ilb_status_t
ilb_get_hc_srvs(ilb_handle_t h, const char *rulename, ilb_comm_t **rbuf,
    size_t *rbufsz)
{
	ilb_status_t	rc;
	ilb_comm_t	*ic, *tmp_rbuf;
	size_t		ic_sz;

	if ((ic = i_ilb_alloc_req(ILBD_GET_HC_SRVS, &ic_sz)) == NULL)
		return (ILB_STATUS_ENOMEM);
	*rbufsz = ILBD_MSG_SIZE;
	if ((tmp_rbuf = malloc(*rbufsz)) == NULL) {
		free(ic);
		return (ILB_STATUS_ENOMEM);
	}

	(void) strlcpy((char *)&ic->ic_data, rulename,
	    sizeof (ilbd_name_t));

	rc = i_ilb_do_comm(h, ic, ic_sz, tmp_rbuf, rbufsz);
	if (rc != ILB_STATUS_OK)
		goto out;

	if (tmp_rbuf->ic_cmd == ILBD_CMD_OK) {
		*rbuf = tmp_rbuf;
		return (rc);
	}
	rc = *(ilb_status_t *)&tmp_rbuf->ic_data;
out:
	free(ic);
	free(tmp_rbuf);
	*rbuf = NULL;
	return (rc);
}

ilb_status_t
ilb_walk_hc_srvs(ilb_handle_t h, hc_srvwalkerfunc_t fn, const char *rulename,
    void *arg)
{
	ilb_status_t		rc;
	ilb_hc_rule_srv_t	*srvs;
	int			i, j;
	ilb_comm_t		*rbuf;
	size_t			rbufsz;

	if (rulename != NULL) {
		rc = ilb_get_hc_srvs(h, rulename, &rbuf, &rbufsz);
		if (rc != ILB_STATUS_OK)
			return (rc);
		srvs = (ilb_hc_rule_srv_t *)&rbuf->ic_data;
		for (i = 0; i < srvs->rs_num_srvs; i++) {
			rc = fn(h, &srvs->rs_srvs[i], arg);
			if (rc != ILB_STATUS_OK)
				break;
		}
		free(rbuf);
	} else {
		ilbd_namelist_t *names;
		ilb_comm_t	*srv_rbuf;
		size_t		srv_rbufsz;

		rc = i_ilb_retrieve_rule_names(h, &rbuf, &rbufsz);
		if (rc != ILB_STATUS_OK)
			return (rc);
		names = (ilbd_namelist_t *)&rbuf->ic_data;

		for (i = 0; i < names->ilbl_count; i++) {
			rc = ilb_get_hc_srvs(h, names->ilbl_name[i],
			    &srv_rbuf, &srv_rbufsz);

			/* Not all rules have HC, so reset the error to OK. */
			if (rc == ILB_STATUS_RULE_NO_HC) {
				rc = ILB_STATUS_OK;
				continue;
			} else if (rc != ILB_STATUS_OK) {
				break;
			}

			srvs = (ilb_hc_rule_srv_t *)&srv_rbuf->ic_data;
			for (j = 0; j < srvs->rs_num_srvs; j++) {
				rc = fn(h, &srvs->rs_srvs[j], arg);
				if (rc != ILB_STATUS_OK)
					break;
			}
			free(srv_rbuf);
		}
		free(rbuf);
	}
	return (rc);
}
