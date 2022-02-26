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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stropts.h>
#include <string.h>
#include <netdb.h>
#include <sys/conf.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <inet/iptun.h>
#include <sys/dls.h>
#include <libdlpi.h>
#include <libdladm_impl.h>
#include <libdllink.h>
#include <libdliptun.h>

/*
 * IP Tunneling Administration Library.
 * This library is used by dladm(8) and to configure IP tunnel links.
 */

#define	IPTUN_CONF_TYPE		"type"
#define	IPTUN_CONF_LADDR	"laddr"
#define	IPTUN_CONF_RADDR	"raddr"

/*
 * If IPTUN_CREATE and IPTUN_MODIFY include IPsec policy and IPsec hasn't
 * loaded yet, the ioctls may return EAGAIN.  We try the ioctl
 * IPTUN_IOCTL_ATTEMPT_LIMIT times and wait IPTUN_IOCTL_ATTEMPT_INTERVAL
 * microseconds between attempts.
 */
#define	IPTUN_IOCTL_ATTEMPT_LIMIT	3
#define	IPTUN_IOCTL_ATTEMPT_INTERVAL	10000

dladm_status_t
i_iptun_ioctl(dladm_handle_t handle, int cmd, void *dp)
{
	dladm_status_t	status = DLADM_STATUS_OK;
	uint_t		attempt;

	for (attempt = 0; attempt < IPTUN_IOCTL_ATTEMPT_LIMIT; attempt++) {
		if (attempt != 0)
			(void) usleep(IPTUN_IOCTL_ATTEMPT_INTERVAL);
		status = (ioctl(dladm_dld_fd(handle), cmd, dp) == 0) ?
		    DLADM_STATUS_OK : dladm_errno2status(errno);
		if (status != DLADM_STATUS_TRYAGAIN)
			break;
	}
	return (status);
}

/*
 * Given tunnel paramaters as supplied by a library consumer, fill in kernel
 * parameters to be passed down to the iptun control device.
 */
static dladm_status_t
i_iptun_kparams(dladm_handle_t handle, const iptun_params_t *params,
    iptun_kparams_t *ik)
{
	dladm_status_t	status;
	struct addrinfo	*ai, hints;
	iptun_kparams_t	tmpik;
	iptun_type_t	iptuntype = IPTUN_TYPE_UNKNOWN;

	(void) memset(ik, 0, sizeof (*ik));

	ik->iptun_kparam_linkid = params->iptun_param_linkid;

	if (params->iptun_param_flags & IPTUN_PARAM_TYPE) {
		ik->iptun_kparam_type = iptuntype = params->iptun_param_type;
		ik->iptun_kparam_flags |= IPTUN_KPARAM_TYPE;
	}

	if (params->iptun_param_flags & (IPTUN_PARAM_LADDR|IPTUN_PARAM_RADDR)) {
		if (iptuntype == IPTUN_TYPE_UNKNOWN) {
			/*
			 * We need to get the type of this existing tunnel in
			 * order to validate and/or look up the right kind of
			 * IP address.
			 */
			tmpik.iptun_kparam_linkid = params->iptun_param_linkid;
			status = i_iptun_ioctl(handle, IPTUN_INFO, &tmpik);
			if (status != DLADM_STATUS_OK)
				return (status);
			iptuntype = tmpik.iptun_kparam_type;
		}

		(void) memset(&hints, 0, sizeof (hints));
		switch (iptuntype) {
		case IPTUN_TYPE_IPV4:
		case IPTUN_TYPE_6TO4:
			hints.ai_family = AF_INET;
			break;
		case IPTUN_TYPE_IPV6:
			hints.ai_family = AF_INET6;
			break;
		}
	}

	if (params->iptun_param_flags & IPTUN_PARAM_LADDR) {
		if (getaddrinfo(params->iptun_param_laddr, NULL, &hints, &ai) !=
		    0)
			return (DLADM_STATUS_BADIPTUNLADDR);
		if (ai->ai_next != NULL) {
			freeaddrinfo(ai);
			return (DLADM_STATUS_BADIPTUNLADDR);
		}
		(void) memcpy(&ik->iptun_kparam_laddr, ai->ai_addr,
		    ai->ai_addrlen);
		ik->iptun_kparam_flags |= IPTUN_KPARAM_LADDR;
		freeaddrinfo(ai);
	}

	if (params->iptun_param_flags & IPTUN_PARAM_RADDR) {
		if (getaddrinfo(params->iptun_param_raddr, NULL, &hints, &ai) !=
		    0)
			return (DLADM_STATUS_BADIPTUNRADDR);
		if (ai->ai_next != NULL) {
			freeaddrinfo(ai);
			return (DLADM_STATUS_BADIPTUNRADDR);
		}
		(void) memcpy(&ik->iptun_kparam_raddr, ai->ai_addr,
		    ai->ai_addrlen);
		ik->iptun_kparam_flags |= IPTUN_KPARAM_RADDR;
		freeaddrinfo(ai);
	}

	if (params->iptun_param_flags & IPTUN_PARAM_SECINFO) {
		ik->iptun_kparam_secinfo = params->iptun_param_secinfo;
		ik->iptun_kparam_flags |= IPTUN_KPARAM_SECINFO;
	}

	return (DLADM_STATUS_OK);
}

/*
 * The inverse of i_iptun_kparams().  Given kernel tunnel paramaters as
 * returned from an IPTUN_INFO ioctl, fill in tunnel parameters.
 */
static dladm_status_t
i_iptun_params(const iptun_kparams_t *ik, iptun_params_t *params)
{
	socklen_t salen;

	(void) memset(params, 0, sizeof (*params));

	params->iptun_param_linkid = ik->iptun_kparam_linkid;

	if (ik->iptun_kparam_flags & IPTUN_KPARAM_TYPE) {
		params->iptun_param_type = ik->iptun_kparam_type;
		params->iptun_param_flags |= IPTUN_PARAM_TYPE;
	}

	if (ik->iptun_kparam_flags & IPTUN_KPARAM_LADDR) {
		salen = ik->iptun_kparam_laddr.ss_family == AF_INET ?
		    sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6);
		if (getnameinfo((const struct sockaddr *)
		    &ik->iptun_kparam_laddr, salen, params->iptun_param_laddr,
		    sizeof (params->iptun_param_laddr), NULL, 0,
		    NI_NUMERICHOST) != 0) {
			return (DLADM_STATUS_BADIPTUNLADDR);
		}
		params->iptun_param_flags |= IPTUN_PARAM_LADDR;
	}

	if (ik->iptun_kparam_flags & IPTUN_KPARAM_RADDR) {
		salen = ik->iptun_kparam_raddr.ss_family == AF_INET ?
		    sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6);
		if (getnameinfo((const struct sockaddr *)
		    &ik->iptun_kparam_raddr, salen, params->iptun_param_raddr,
		    sizeof (params->iptun_param_raddr), NULL, 0,
		    NI_NUMERICHOST) != 0) {
			return (DLADM_STATUS_BADIPTUNRADDR);
		}
		params->iptun_param_flags |= IPTUN_PARAM_RADDR;
	}

	if (ik->iptun_kparam_flags & IPTUN_KPARAM_SECINFO) {
		params->iptun_param_secinfo = ik->iptun_kparam_secinfo;
		params->iptun_param_flags |= IPTUN_PARAM_SECINFO;
	}

	if (ik->iptun_kparam_flags & IPTUN_KPARAM_IMPLICIT)
		params->iptun_param_flags |= IPTUN_PARAM_IMPLICIT;

	if (ik->iptun_kparam_flags & IPTUN_KPARAM_IPSECPOL)
		params->iptun_param_flags |= IPTUN_PARAM_IPSECPOL;

	return (DLADM_STATUS_OK);
}

dladm_status_t
i_iptun_get_sysparams(dladm_handle_t handle, iptun_params_t *params)
{
	dladm_status_t	status = DLADM_STATUS_OK;
	iptun_kparams_t	ik;

	ik.iptun_kparam_linkid = params->iptun_param_linkid;
	status = i_iptun_ioctl(handle, IPTUN_INFO, &ik);
	if (status == DLADM_STATUS_OK)
		status = i_iptun_params(&ik, params);
	return (status);
}

/*
 * Read tunnel parameters from persistent storage.  Note that the tunnel type
 * is the only thing which must always be in the configuratioh.  All other
 * parameters (currently the source and destination addresses) may or may not
 * have been configured, and therefore may not have been set.
 */
static dladm_status_t
i_iptun_get_dbparams(dladm_handle_t handle, iptun_params_t *params)
{
	dladm_status_t		status;
	dladm_conf_t		conf;
	datalink_class_t	class;
	uint64_t		temp;

	/* First, make sure that this is an IP tunnel. */
	if ((status = dladm_datalink_id2info(handle, params->iptun_param_linkid,
	    NULL, &class, NULL, NULL, 0)) != DLADM_STATUS_OK)
		return (status);
	if (class != DATALINK_CLASS_IPTUN)
		return (DLADM_STATUS_LINKINVAL);

	if ((status = dladm_getsnap_conf(handle, params->iptun_param_linkid,
	    &conf)) != DLADM_STATUS_OK) {
		return (status);
	}

	params->iptun_param_flags = 0;

	if ((status = dladm_get_conf_field(handle, conf, IPTUN_CONF_TYPE, &temp,
	    sizeof (temp))) != DLADM_STATUS_OK)
		goto done;
	params->iptun_param_type = (iptun_type_t)temp;
	params->iptun_param_flags |= IPTUN_PARAM_TYPE;

	if (dladm_get_conf_field(handle, conf, IPTUN_CONF_LADDR,
	    params->iptun_param_laddr, sizeof (params->iptun_param_laddr)) ==
	    DLADM_STATUS_OK)
		params->iptun_param_flags |= IPTUN_PARAM_LADDR;

	if (dladm_get_conf_field(handle, conf, IPTUN_CONF_RADDR,
	    params->iptun_param_raddr, sizeof (params->iptun_param_raddr)) ==
	    DLADM_STATUS_OK)
		params->iptun_param_flags |= IPTUN_PARAM_RADDR;

done:
	dladm_destroy_conf(handle, conf);
	return (status);
}

static dladm_status_t
i_iptun_create_sys(dladm_handle_t handle, iptun_params_t *params)
{
	iptun_kparams_t	ik;
	dladm_status_t	status = DLADM_STATUS_OK;

	/* The tunnel type is required for creation. */
	if (!(params->iptun_param_flags & IPTUN_PARAM_TYPE))
		return (DLADM_STATUS_IPTUNTYPEREQD);

	if ((status = i_iptun_kparams(handle, params, &ik)) == DLADM_STATUS_OK)
		status = i_iptun_ioctl(handle, IPTUN_CREATE, &ik);
	return (status);
}

static dladm_status_t
i_iptun_create_db(dladm_handle_t handle, const char *name,
    iptun_params_t *params, uint32_t media)
{
	dladm_conf_t	conf;
	dladm_status_t	status;
	uint64_t	storage;

	status = dladm_create_conf(handle, name, params->iptun_param_linkid,
	    DATALINK_CLASS_IPTUN, media, &conf);
	if (status != DLADM_STATUS_OK)
		return (status);

	assert(params->iptun_param_flags & IPTUN_PARAM_TYPE);
	storage = params->iptun_param_type;
	status = dladm_set_conf_field(handle, conf, IPTUN_CONF_TYPE,
	    DLADM_TYPE_UINT64, &storage);
	if (status != DLADM_STATUS_OK)
		goto done;

	if (params->iptun_param_flags & IPTUN_PARAM_LADDR) {
		status = dladm_set_conf_field(handle, conf, IPTUN_CONF_LADDR,
		    DLADM_TYPE_STR, params->iptun_param_laddr);
		if (status != DLADM_STATUS_OK)
			goto done;
	}

	if (params->iptun_param_flags & IPTUN_PARAM_RADDR) {
		status = dladm_set_conf_field(handle, conf, IPTUN_CONF_RADDR,
		    DLADM_TYPE_STR, params->iptun_param_raddr);
		if (status != DLADM_STATUS_OK)
			goto done;
	}

	status = dladm_write_conf(handle, conf);

done:
	dladm_destroy_conf(handle, conf);
	return (status);
}

static dladm_status_t
i_iptun_delete_sys(dladm_handle_t handle, datalink_id_t linkid)
{
	dladm_status_t status;

	status = i_iptun_ioctl(handle, IPTUN_DELETE, &linkid);
	if (status != DLADM_STATUS_OK)
		return (status);
	(void) dladm_destroy_datalink_id(handle, linkid, DLADM_OPT_ACTIVE);
	return (DLADM_STATUS_OK);
}

static dladm_status_t
i_iptun_modify_sys(dladm_handle_t handle, const iptun_params_t *params)
{
	iptun_kparams_t	ik;
	dladm_status_t	status;

	if ((status = i_iptun_kparams(handle, params, &ik)) == DLADM_STATUS_OK)
		status = i_iptun_ioctl(handle, IPTUN_MODIFY, &ik);
	return (status);
}

static dladm_status_t
i_iptun_modify_db(dladm_handle_t handle, const iptun_params_t *params)
{
	dladm_conf_t	conf;
	dladm_status_t	status;

	assert(params->iptun_param_flags &
	    (IPTUN_PARAM_LADDR|IPTUN_PARAM_RADDR));

	/*
	 * The only parameters that can be modified persistently are the local
	 * and remote addresses.
	 */
	if (params->iptun_param_flags & ~(IPTUN_PARAM_LADDR|IPTUN_PARAM_RADDR))
		return (DLADM_STATUS_BADARG);

	status = dladm_open_conf(handle, params->iptun_param_linkid, &conf);
	if (status != DLADM_STATUS_OK)
		return (status);

	if (params->iptun_param_flags & IPTUN_PARAM_LADDR) {
		status = dladm_set_conf_field(handle, conf, IPTUN_CONF_LADDR,
		    DLADM_TYPE_STR, (void *)params->iptun_param_laddr);
		if (status != DLADM_STATUS_OK)
			goto done;
	}

	if (params->iptun_param_flags & IPTUN_PARAM_RADDR) {
		status = dladm_set_conf_field(handle, conf, IPTUN_CONF_RADDR,
		    DLADM_TYPE_STR, (void *)params->iptun_param_raddr);
		if (status != DLADM_STATUS_OK)
			goto done;
	}

	status = dladm_write_conf(handle, conf);

done:
	dladm_destroy_conf(handle, conf);
	return (status);
}

dladm_status_t
dladm_iptun_create(dladm_handle_t handle, const char *name,
    iptun_params_t *params, uint32_t flags)
{
	dladm_status_t	status;
	uint32_t	linkmgmt_flags = flags;
	uint32_t	media;

	if (!(params->iptun_param_flags & IPTUN_PARAM_TYPE))
		return (DLADM_STATUS_IPTUNTYPEREQD);

	switch (params->iptun_param_type) {
	case IPTUN_TYPE_IPV4:
		media = DL_IPV4;
		break;
	case IPTUN_TYPE_IPV6:
		media = DL_IPV6;
		break;
	case IPTUN_TYPE_6TO4:
		media = DL_6TO4;
		break;
	default:
		return (DLADM_STATUS_IPTUNTYPE);
	}

	status = dladm_create_datalink_id(handle, name, DATALINK_CLASS_IPTUN,
	    media, linkmgmt_flags, &params->iptun_param_linkid);
	if (status != DLADM_STATUS_OK)
		return (status);

	if (flags & DLADM_OPT_PERSIST) {
		status = i_iptun_create_db(handle, name, params, media);
		if (status != DLADM_STATUS_OK)
			goto done;
	}

	if (flags & DLADM_OPT_ACTIVE) {
		status = i_iptun_create_sys(handle, params);
		if (status != DLADM_STATUS_OK && (flags & DLADM_OPT_PERSIST)) {
			(void) dladm_remove_conf(handle,
			    params->iptun_param_linkid);
		}
	}

done:
	if (status != DLADM_STATUS_OK) {
		(void) dladm_destroy_datalink_id(handle,
		    params->iptun_param_linkid, flags);
	}
	return (status);
}

dladm_status_t
dladm_iptun_delete(dladm_handle_t handle, datalink_id_t linkid, uint32_t flags)
{
	dladm_status_t		status;
	datalink_class_t	class;

	/* First, make sure that this is an IP tunnel. */
	if ((status = dladm_datalink_id2info(handle, linkid, NULL, &class, NULL,
	    NULL, 0)) != DLADM_STATUS_OK)
		return (status);
	if (class != DATALINK_CLASS_IPTUN)
		return (DLADM_STATUS_LINKINVAL);

	if (flags & DLADM_OPT_ACTIVE) {
		/*
		 * Note that if i_iptun_delete_sys() fails with
		 * DLADM_STATUS_NOTFOUND and the caller also wishes to delete
		 * the persistent configuration, we still fall through to the
		 * DLADM_OPT_PERSIST case in case the tunnel only exists
		 * persistently.
		 */
		status = i_iptun_delete_sys(handle, linkid);
		if (status != DLADM_STATUS_OK &&
		    (status != DLADM_STATUS_NOTFOUND ||
		    !(flags & DLADM_OPT_PERSIST)))
			return (status);
	}

	if (flags & DLADM_OPT_PERSIST) {
		(void) dladm_remove_conf(handle, linkid);
		(void) dladm_destroy_datalink_id(handle, linkid,
		    DLADM_OPT_PERSIST);
	}
	return (DLADM_STATUS_OK);
}

dladm_status_t
dladm_iptun_modify(dladm_handle_t handle, const iptun_params_t *params,
    uint32_t flags)
{
	dladm_status_t	status = DLADM_STATUS_OK;
	iptun_params_t	old_params;

	/*
	 * We can only modify the tunnel source, tunnel destination, or IPsec
	 * policy.
	 */
	if (!(params->iptun_param_flags &
	    (IPTUN_PARAM_LADDR|IPTUN_PARAM_RADDR|IPTUN_PARAM_SECINFO)))
		return (DLADM_STATUS_BADARG);

	if (flags & DLADM_OPT_PERSIST) {
		/*
		 * Before we change the database, save the old configuration
		 * so that we can revert back if an error occurs.
		 */
		old_params.iptun_param_linkid = params->iptun_param_linkid;
		status = i_iptun_get_dbparams(handle, &old_params);
		if (status != DLADM_STATUS_OK)
			return (status);
		/* we'll only need to revert the parameters being modified */
		old_params.iptun_param_flags = params->iptun_param_flags;

		status = i_iptun_modify_db(handle, params);
		if (status != DLADM_STATUS_OK)
			return (status);
	}

	if (flags & DLADM_OPT_ACTIVE) {
		status = i_iptun_modify_sys(handle, params);
		if (status != DLADM_STATUS_OK && (flags & DLADM_OPT_PERSIST)) {
			(void) i_iptun_modify_db(handle, &old_params);
		}
	}

	return (status);
}

dladm_status_t
dladm_iptun_getparams(dladm_handle_t handle, iptun_params_t *params,
    uint32_t flags)
{
	if (flags == DLADM_OPT_ACTIVE)
		return (i_iptun_get_sysparams(handle, params));
	else if (flags == DLADM_OPT_PERSIST)
		return (i_iptun_get_dbparams(handle, params));
	else
		return (DLADM_STATUS_BADARG);
}

static int
i_iptun_up(dladm_handle_t handle, datalink_id_t linkid, void *arg)
{
	dladm_status_t	*statusp = arg;
	dladm_status_t	status;
	iptun_params_t	params;
	boolean_t	id_up = B_FALSE;

	status = dladm_up_datalink_id(handle, linkid);
	if (status != DLADM_STATUS_OK)
		goto done;
	id_up = B_TRUE;

	(void) memset(&params, 0, sizeof (params));

	params.iptun_param_linkid = linkid;
	if ((status = i_iptun_get_dbparams(handle, &params)) == DLADM_STATUS_OK)
		status = i_iptun_create_sys(handle, &params);
done:
	if (statusp != NULL)
		*statusp = status;
	if (status != DLADM_STATUS_OK && id_up) {
		(void) dladm_destroy_datalink_id(handle, linkid,
		    DLADM_OPT_ACTIVE);
	}
	return (DLADM_WALK_CONTINUE);
}

static int
i_iptun_down(dladm_handle_t handle, datalink_id_t linkid, void *arg)
{
	dladm_status_t	*statusp = arg;
	dladm_status_t	status;

	status = i_iptun_delete_sys(handle, linkid);
	if (statusp != NULL)
		*statusp = status;
	return (DLADM_WALK_CONTINUE);
}

/* ARGSUSED */
dladm_status_t
dladm_iptun_up(dladm_handle_t handle, datalink_id_t linkid)
{
	dladm_status_t status = DLADM_STATUS_OK;

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(i_iptun_up, handle, NULL,
		    DATALINK_CLASS_IPTUN, DATALINK_ANY_MEDIATYPE,
		    DLADM_OPT_PERSIST);
	} else {
		(void) i_iptun_up(handle, linkid, &status);
	}
	return (status);
}

dladm_status_t
dladm_iptun_down(dladm_handle_t handle, datalink_id_t linkid)
{
	dladm_status_t status = DLADM_STATUS_OK;

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(i_iptun_down, handle, NULL,
		    DATALINK_CLASS_IPTUN, DATALINK_ANY_MEDIATYPE,
		    DLADM_OPT_ACTIVE);
	} else {
		(void) i_iptun_down(handle, linkid, &status);
	}
	return (status);
}

dladm_status_t
dladm_iptun_set6to4relay(dladm_handle_t handle, struct in_addr *relay)
{
	return (i_iptun_ioctl(handle, IPTUN_SET_6TO4RELAY, relay));
}

dladm_status_t
dladm_iptun_get6to4relay(dladm_handle_t handle, struct in_addr *relay)
{
	return (i_iptun_ioctl(handle, IPTUN_GET_6TO4RELAY, relay));
}
