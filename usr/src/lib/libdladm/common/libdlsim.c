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
 *
 * Copyright 2024 H. William Welliver <william@welliver.org>
 */

#include <sys/types.h>
#include <string.h>
#include <strings.h>
#include <sys/mac.h>
#include <sys/dls_mgmt.h>
#include <sys/dlpi.h>
#include <net/simnet.h>
#include <errno.h>
#include <unistd.h>

#include <libdladm_impl.h>
#include <libdllink.h>
#include <libdlaggr.h>
#include <libdlsim.h>

static dladm_status_t dladm_simnet_persist_conf(dladm_handle_t, const char *,
    dladm_simnet_attr_t *);

/* New simnet instance creation */
static dladm_status_t
i_dladm_create_simnet(dladm_handle_t handle, dladm_simnet_attr_t *attrp)
{
	int rc;
	dladm_status_t status = DLADM_STATUS_OK;
	simnet_ioc_create_t ioc;

	bzero(&ioc, sizeof (ioc));
	ioc.sic_link_id = attrp->sna_link_id;
	ioc.sic_type = attrp->sna_type;
	if (attrp->sna_mac_len > 0 && attrp->sna_mac_len <= MAXMACADDRLEN) {
		ioc.sic_mac_len = attrp->sna_mac_len;
		bcopy(attrp->sna_mac_addr, ioc.sic_mac_addr, ioc.sic_mac_len);
	}

	rc = ioctl(dladm_dld_fd(handle), SIMNET_IOC_CREATE, &ioc);
	if (rc < 0)
		status = dladm_errno2status(errno);

	if (status != DLADM_STATUS_OK)
		return (status);

	bcopy(ioc.sic_mac_addr, attrp->sna_mac_addr, MAXMACADDRLEN);
	attrp->sna_mac_len = ioc.sic_mac_len;
	return (status);
}

/* Modify existing simnet instance */
static dladm_status_t
i_dladm_modify_simnet(dladm_handle_t handle, dladm_simnet_attr_t *attrp)
{
	int rc;
	dladm_status_t status = DLADM_STATUS_OK;
	simnet_ioc_modify_t ioc;

	bzero(&ioc, sizeof (ioc));
	ioc.sim_link_id = attrp->sna_link_id;
	ioc.sim_peer_link_id = attrp->sna_peer_link_id;

	rc = ioctl(dladm_dld_fd(handle), SIMNET_IOC_MODIFY, &ioc);
	if (rc < 0)
		status = dladm_errno2status(errno);

	return (status);
}

/* Delete simnet instance */
static dladm_status_t
i_dladm_delete_simnet(dladm_handle_t handle, dladm_simnet_attr_t *attrp)
{
	int rc;
	dladm_status_t status = DLADM_STATUS_OK;
	simnet_ioc_delete_t ioc;

	bzero(&ioc, sizeof (ioc));
	ioc.sid_link_id = attrp->sna_link_id;

	rc = ioctl(dladm_dld_fd(handle), SIMNET_IOC_DELETE, &ioc);
	if (rc < 0)
		status = dladm_errno2status(errno);

	return (status);
}

/* Retrieve simnet instance information */
static dladm_status_t
i_dladm_get_simnet_info(dladm_handle_t handle, dladm_simnet_attr_t *attrp)
{
	int rc;
	dladm_status_t status = DLADM_STATUS_OK;
	simnet_ioc_info_t ioc;

	bzero(&ioc, sizeof (ioc));
	ioc.sii_link_id = attrp->sna_link_id;

	rc = ioctl(dladm_dld_fd(handle), SIMNET_IOC_INFO, &ioc);
	if (rc < 0) {
		status = dladm_errno2status(errno);
		return (status);
	}

	bcopy(ioc.sii_mac_addr, attrp->sna_mac_addr, MAXMACADDRLEN);
	attrp->sna_mac_len = ioc.sii_mac_len;
	attrp->sna_peer_link_id = ioc.sii_peer_link_id;
	attrp->sna_type = ioc.sii_type;
	return (status);
}

/* Retrieve simnet configuratin */
static dladm_status_t
i_dladm_get_simnet_info_persist(dladm_handle_t handle,
    dladm_simnet_attr_t *attrp)
{
	dladm_conf_t conf;
	dladm_status_t status;
	char macstr[ETHERADDRL * 3];
	char simnetpeer[MAXLINKNAMELEN];
	uint64_t u64;
	boolean_t mac_fixed;

	if ((status = dladm_getsnap_conf(handle, attrp->sna_link_id,
	    &conf)) != DLADM_STATUS_OK)
		return (status);

	status = dladm_get_conf_field(handle, conf, FSIMNETTYPE, &u64,
	    sizeof (u64));
	if (status != DLADM_STATUS_OK)
		goto done;
	attrp->sna_type = (uint_t)u64;

	status = dladm_get_conf_field(handle, conf, FMADDRLEN, &u64,
	    sizeof (u64));
	if (status != DLADM_STATUS_OK)
		goto done;
	attrp->sna_mac_len = (uint_t)u64;

	status = dladm_get_conf_field(handle, conf, FMACADDR, macstr,
	    sizeof (macstr));
	if (status != DLADM_STATUS_OK)
		goto done;
	(void) dladm_aggr_str2macaddr(macstr, &mac_fixed, attrp->sna_mac_addr);

	/* Peer field is optional and only set when peer is attached */
	if (dladm_get_conf_field(handle, conf, FSIMNETPEER, simnetpeer,
	    sizeof (simnetpeer)) == DLADM_STATUS_OK) {
		status = dladm_name2info(handle, simnetpeer,
		    &attrp->sna_peer_link_id, NULL, NULL, NULL);
	} else {
		attrp->sna_peer_link_id = DATALINK_INVALID_LINKID;
	}
done:
	dladm_destroy_conf(handle, conf);
	return (status);
}

dladm_status_t
dladm_simnet_create(dladm_handle_t handle, const char *simnetname,
    uint_t media, const char *maddr, uint32_t flags)
{
	datalink_id_t simnet_id;
	dladm_status_t status;
	dladm_simnet_attr_t attr;
	uchar_t *mac_addr;
	uint_t maclen;

	if (!(flags & DLADM_OPT_ACTIVE))
		return (DLADM_STATUS_NOTSUP);

	bzero(&attr, sizeof (attr));

	if (maddr != NULL) {
		mac_addr = _link_aton(maddr, (int *)&maclen);
		if (mac_addr == NULL) {
			if (maclen == (uint_t)-1)
				return (DLADM_STATUS_INVALIDMACADDR);
			else
				return (DLADM_STATUS_NOMEM);
		} else if (maclen != ETHERADDRL) {
			free(mac_addr);
			return (DLADM_STATUS_INVALIDMACADDRLEN);
		} else if ((mac_addr[0] & 1) || !(mac_addr[0] & 2)) {
			/* mac address must be unicast and local */
			free(mac_addr);
			return (DLADM_STATUS_INVALIDMACADDR);
		}

		attr.sna_mac_len = maclen;
		bcopy(mac_addr, attr.sna_mac_addr, maclen);
		free(mac_addr);
	}

	flags &= (DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST);
	if ((status = dladm_create_datalink_id(handle, simnetname,
	    DATALINK_CLASS_SIMNET, media, flags,
	    &simnet_id)) != DLADM_STATUS_OK)
		return (status);

	attr.sna_link_id = simnet_id;
	attr.sna_type = media;
	status = i_dladm_create_simnet(handle, &attr);
	if (status != DLADM_STATUS_OK)
		goto done;

	if (!(flags & DLADM_OPT_PERSIST))
		goto done;

	status = dladm_simnet_persist_conf(handle, simnetname, &attr);
	if (status != DLADM_STATUS_OK) {
		(void) i_dladm_delete_simnet(handle, &attr);
		goto done;
	}

	(void) dladm_set_linkprop(handle, simnet_id, NULL, NULL, 0, flags);

done:
	if (status != DLADM_STATUS_OK) {
		(void) dladm_destroy_datalink_id(handle, simnet_id, flags);
	}
	return (status);
}

/* Update existing simnet configuration */
static dladm_status_t
i_dladm_simnet_update_conf(dladm_handle_t handle, datalink_id_t simnet_id,
    datalink_id_t peer_simnet_id)
{
	dladm_status_t status;
	dladm_conf_t conf;
	char simnetpeer[MAXLINKNAMELEN];

	status = dladm_open_conf(handle, simnet_id, &conf);
	if (status != DLADM_STATUS_OK)
		return (status);

	/* First clear previous peer if any in configuration */
	(void) dladm_unset_conf_field(handle, conf, FSIMNETPEER);
	if (peer_simnet_id != DATALINK_INVALID_LINKID) {
		if ((status = dladm_datalink_id2info(handle,
		    peer_simnet_id, NULL, NULL, NULL, simnetpeer,
		    sizeof (simnetpeer))) == DLADM_STATUS_OK) {
			status = dladm_set_conf_field(handle, conf,
			    FSIMNETPEER, DLADM_TYPE_STR, simnetpeer);
		}
		if (status != DLADM_STATUS_OK)
			goto fail;
	}

	status = dladm_write_conf(handle, conf);
fail:
	dladm_destroy_conf(handle, conf);
	return (status);
}

/* Modify attached simnet peer */
dladm_status_t
dladm_simnet_modify(dladm_handle_t handle, datalink_id_t simnet_id,
    datalink_id_t peer_simnet_id, uint32_t flags)
{
	dladm_simnet_attr_t attr;
	dladm_simnet_attr_t prevattr;
	dladm_status_t status;
	datalink_class_t class;
	uint32_t linkflags;
	uint32_t peerlinkflags;

	if (!(flags & DLADM_OPT_ACTIVE))
		return (DLADM_STATUS_NOTSUP);

	if ((dladm_datalink_id2info(handle, simnet_id, &linkflags, &class,
	    NULL, NULL, 0) != DLADM_STATUS_OK))
		return (DLADM_STATUS_BADARG);
	if (class != DATALINK_CLASS_SIMNET)
		return (DLADM_STATUS_BADARG);

	if (peer_simnet_id != DATALINK_INVALID_LINKID) {
		if (dladm_datalink_id2info(handle, peer_simnet_id,
		    &peerlinkflags, &class, NULL, NULL, 0) != DLADM_STATUS_OK)
			return (DLADM_STATUS_BADARG);
		if (class != DATALINK_CLASS_SIMNET)
			return (DLADM_STATUS_BADARG);
		/* Check to ensure the peer link has identical flags */
		if (peerlinkflags != linkflags)
			return (DLADM_STATUS_BADARG);
	}

	/* Retrieve previous attrs before modification */
	bzero(&prevattr, sizeof (prevattr));
	if ((status = dladm_simnet_info(handle, simnet_id, &prevattr,
	    flags)) != DLADM_STATUS_OK)
		return (status);

	bzero(&attr, sizeof (attr));
	attr.sna_link_id = simnet_id;
	attr.sna_peer_link_id = peer_simnet_id;
	status = i_dladm_modify_simnet(handle, &attr);
	if ((status != DLADM_STATUS_OK) || !(flags & DLADM_OPT_PERSIST))
		return (status);

	/* First we clear link's existing peer field in config */
	status = i_dladm_simnet_update_conf(handle, simnet_id,
	    DATALINK_INVALID_LINKID);
	if (status != DLADM_STATUS_OK)
		return (status);

	/* Clear the previous peer link's existing peer field in config */
	if (prevattr.sna_peer_link_id != DATALINK_INVALID_LINKID) {
		status = i_dladm_simnet_update_conf(handle,
		    prevattr.sna_peer_link_id, DATALINK_INVALID_LINKID);
		if (status != DLADM_STATUS_OK)
			return (status);
	}

	/* Update the configuration in both simnets with any new peer link */
	if (peer_simnet_id != DATALINK_INVALID_LINKID) {
		status = i_dladm_simnet_update_conf(handle, simnet_id,
		    peer_simnet_id);
		if (status == DLADM_STATUS_OK)
			status = i_dladm_simnet_update_conf(handle,
			    peer_simnet_id, simnet_id);
	}

	return (status);
}

dladm_status_t
dladm_simnet_delete(dladm_handle_t handle, datalink_id_t simnet_id,
    uint32_t flags)
{
	dladm_simnet_attr_t attr;
	dladm_simnet_attr_t prevattr;
	dladm_status_t status;
	datalink_class_t class;

	if ((dladm_datalink_id2info(handle, simnet_id, NULL, &class,
	    NULL, NULL, 0) != DLADM_STATUS_OK))
		return (DLADM_STATUS_BADARG);

	if (class != DATALINK_CLASS_SIMNET)
		return (DLADM_STATUS_BADARG);

	/* Check current simnet attributes before deletion */
	flags &= (DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST);
	bzero(&prevattr, sizeof (prevattr));
	if ((status = dladm_simnet_info(handle, simnet_id, &prevattr,
	    flags)) != DLADM_STATUS_OK)
		return (status);

	bzero(&attr, sizeof (attr));
	attr.sna_link_id = simnet_id;
	if (flags & DLADM_OPT_ACTIVE) {
		status = i_dladm_delete_simnet(handle, &attr);
		if (status == DLADM_STATUS_OK) {
			(void) dladm_set_linkprop(handle, simnet_id, NULL,
			    NULL, 0, DLADM_OPT_ACTIVE);
			(void) dladm_destroy_datalink_id(handle, simnet_id,
			    DLADM_OPT_ACTIVE);
		} else if (status != DLADM_STATUS_NOTFOUND) {
			return (status);
		}
	}

	if (flags & DLADM_OPT_PERSIST) {
		(void) dladm_remove_conf(handle, simnet_id);
		(void) dladm_destroy_datalink_id(handle, simnet_id,
		    DLADM_OPT_PERSIST);

		/* Update any attached peer configuration */
		if (prevattr.sna_peer_link_id != DATALINK_INVALID_LINKID)
			status = i_dladm_simnet_update_conf(handle,
			    prevattr.sna_peer_link_id, DATALINK_INVALID_LINKID);
	}
	return (status);
}

/* Retrieve simnet information either active or from configuration */
dladm_status_t
dladm_simnet_info(dladm_handle_t handle, datalink_id_t simnet_id,
    dladm_simnet_attr_t *attrp, uint32_t flags)
{
	datalink_class_t class;
	dladm_status_t status;

	if ((dladm_datalink_id2info(handle, simnet_id, NULL, &class,
	    NULL, NULL, 0) != DLADM_STATUS_OK))
		return (DLADM_STATUS_BADARG);

	if (class != DATALINK_CLASS_SIMNET)
		return (DLADM_STATUS_BADARG);

	bzero(attrp, sizeof (*attrp));
	attrp->sna_link_id = simnet_id;

	if (flags & DLADM_OPT_ACTIVE) {
		status = i_dladm_get_simnet_info(handle, attrp);
		/*
		 * If no active simnet found then return any simnet
		 * from stored config if requested.
		 */
		if (status == DLADM_STATUS_NOTFOUND &&
		    (flags & DLADM_OPT_PERSIST))
			return (i_dladm_get_simnet_info_persist(handle, attrp));
		return (status);
	} else if (flags & DLADM_OPT_PERSIST) {
		return (i_dladm_get_simnet_info_persist(handle, attrp));
	} else {
		return (DLADM_STATUS_BADARG);
	}
}

/* Bring up simnet from stored configuration */
static int
i_dladm_simnet_up(dladm_handle_t handle, datalink_id_t simnet_id, void *arg)
{
	dladm_status_t *statusp = arg;
	dladm_status_t status;
	dladm_simnet_attr_t attr;
	dladm_simnet_attr_t peer_attr;

	bzero(&attr, sizeof (attr));
	attr.sna_link_id = simnet_id;
	status = dladm_simnet_info(handle, simnet_id, &attr,
	    DLADM_OPT_PERSIST);
	if (status != DLADM_STATUS_OK)
		goto done;

	status = i_dladm_create_simnet(handle, &attr);
	if (status != DLADM_STATUS_OK)
		goto done;

	/*
	 * When bringing up check if the peer link is available, if it
	 * is then modify the simnet and attach the peer link.
	 */
	if ((attr.sna_peer_link_id != DATALINK_INVALID_LINKID) &&
	    (dladm_simnet_info(handle, attr.sna_peer_link_id, &peer_attr,
	    DLADM_OPT_ACTIVE) == DLADM_STATUS_OK)) {
		status = i_dladm_modify_simnet(handle, &attr);
		if (status != DLADM_STATUS_OK)
			goto done;
	}

	if ((status = dladm_up_datalink_id(handle, simnet_id)) !=
	    DLADM_STATUS_OK) {
		(void) dladm_simnet_delete(handle, simnet_id,
		    DLADM_OPT_PERSIST);
		goto done;
	}
done:
	*statusp = status;
	return (DLADM_WALK_CONTINUE);
}

/* Bring up simnet instance(s) from configuration */
dladm_status_t
dladm_simnet_up(dladm_handle_t handle, datalink_id_t simnet_id,
    uint32_t flags __unused)
{
	dladm_status_t status;

	if (simnet_id == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(i_dladm_simnet_up, handle,
		    &status, DATALINK_CLASS_SIMNET, DATALINK_ANY_MEDIATYPE,
		    DLADM_OPT_PERSIST);
		return (DLADM_STATUS_OK);
	} else {
		(void) i_dladm_simnet_up(handle, simnet_id, &status);
		return (status);
	}
}

/* Store simnet configuration */
static dladm_status_t
dladm_simnet_persist_conf(dladm_handle_t handle, const char *name,
    dladm_simnet_attr_t *attrp)
{
	dladm_conf_t conf;
	dladm_status_t status;
	char mstr[ETHERADDRL * 3];
	uint64_t u64;

	if ((status = dladm_create_conf(handle, name, attrp->sna_link_id,
	    DATALINK_CLASS_SIMNET, attrp->sna_type, &conf)) != DLADM_STATUS_OK)
		return (status);

	status = dladm_set_conf_field(handle, conf, FMACADDR,
	    DLADM_TYPE_STR, dladm_aggr_macaddr2str(attrp->sna_mac_addr, mstr));
	if (status != DLADM_STATUS_OK)
		goto done;

	u64 = attrp->sna_type;
	status = dladm_set_conf_field(handle, conf, FSIMNETTYPE,
	    DLADM_TYPE_UINT64, &u64);
	if (status != DLADM_STATUS_OK)
		goto done;

	u64 = attrp->sna_mac_len;
	status = dladm_set_conf_field(handle, conf, FMADDRLEN,
	    DLADM_TYPE_UINT64, &u64);
	if (status != DLADM_STATUS_OK)
		goto done;

	status = dladm_write_conf(handle, conf);
done:
	dladm_destroy_conf(handle, conf);
	return (status);
}
