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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/dld.h>
#include <libdladm_impl.h>
#include <libdllink.h>
#include <libdlvlan.h>

/*
 * VLAN Administration Library.
 *
 * This library is used by administration tools such as dladm(1M) to
 * configure VLANs.
 */

/*
 * Returns the current attributes of the specified VLAN.
 */
static dladm_status_t
i_dladm_vlan_info_active(datalink_id_t vlanid, dladm_vlan_attr_t *dvap)
{
	int			fd;
	dld_ioc_vlan_attr_t	div;
	dladm_status_t		status = DLADM_STATUS_OK;

	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0)
		return (dladm_errno2status(errno));

	div.div_vlanid = vlanid;

	if (i_dladm_ioctl(fd, DLDIOC_VLAN_ATTR, &div, sizeof (div)) < 0)
		status = dladm_errno2status(errno);

	dvap->dv_vid = div.div_vid;
	dvap->dv_linkid = div.div_linkid;
	dvap->dv_force = div.div_force;
	dvap->dv_implicit = div.div_implicit;
done:
	(void) close(fd);
	return (status);
}

/*
 * Returns the persistent attributes of the specified VLAN.
 */
static dladm_status_t
i_dladm_vlan_info_persist(datalink_id_t vlanid, dladm_vlan_attr_t *dvap)
{
	dladm_conf_t	conf = DLADM_INVALID_CONF;
	dladm_status_t	status;
	uint64_t	u64;

	if ((status = dladm_read_conf(vlanid, &conf)) != DLADM_STATUS_OK)
		return (status);

	status = dladm_get_conf_field(conf, FLINKOVER, &u64, sizeof (u64));
	if (status != DLADM_STATUS_OK)
		goto done;
	dvap->dv_linkid = (datalink_id_t)u64;

	status = dladm_get_conf_field(conf, FFORCE, &dvap->dv_force,
	    sizeof (boolean_t));
	if (status != DLADM_STATUS_OK)
		goto done;

	dvap->dv_implicit = B_FALSE;

	status = dladm_get_conf_field(conf, FVLANID, &u64, sizeof (u64));
	if (status != DLADM_STATUS_OK)
		goto done;
	dvap->dv_vid = (uint16_t)u64;

done:
	dladm_destroy_conf(conf);
	return (status);
}

dladm_status_t
dladm_vlan_info(datalink_id_t vlanid, dladm_vlan_attr_t *dvap, uint32_t flags)
{
	assert(flags == DLADM_OPT_ACTIVE || flags == DLADM_OPT_PERSIST);
	if (flags == DLADM_OPT_ACTIVE)
		return (i_dladm_vlan_info_active(vlanid, dvap));
	else
		return (i_dladm_vlan_info_persist(vlanid, dvap));
}

static dladm_status_t
dladm_persist_vlan_conf(const char *vlan, datalink_id_t vlanid,
    boolean_t force, datalink_id_t linkid, uint16_t vid)
{
	dladm_conf_t	conf = DLADM_INVALID_CONF;
	dladm_status_t	status;
	uint64_t	u64;

	if ((status = dladm_create_conf(vlan, vlanid, DATALINK_CLASS_VLAN,
	    DL_ETHER, &conf)) != DLADM_STATUS_OK) {
		return (status);
	}

	u64 = linkid;
	status = dladm_set_conf_field(conf, FLINKOVER, DLADM_TYPE_UINT64, &u64);
	if (status != DLADM_STATUS_OK)
		goto done;

	status = dladm_set_conf_field(conf, FFORCE, DLADM_TYPE_BOOLEAN, &force);
	if (status != DLADM_STATUS_OK)
		goto done;

	u64 = vid;
	status = dladm_set_conf_field(conf, FVLANID, DLADM_TYPE_UINT64, &u64);
	if (status != DLADM_STATUS_OK)
		goto done;

	status = dladm_write_conf(conf);

done:
	dladm_destroy_conf(conf);
	return (status);
}

/*
 * Create a VLAN on given link.
 */
dladm_status_t
dladm_vlan_create(const char *vlan, datalink_id_t linkid, uint16_t vid,
    uint32_t flags)
{
	dld_ioc_create_vlan_t	dic;
	int			fd;
	datalink_id_t		vlanid = DATALINK_INVALID_LINKID;
	uint_t			media;
	datalink_class_t	class;
	dladm_status_t		status;

	if (vid < 1 || vid > 4094)
		return (DLADM_STATUS_VIDINVAL);

	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0)
		return (dladm_errno2status(errno));

	status = dladm_datalink_id2info(linkid, NULL, &class, &media, NULL, 0);
	if (status != DLADM_STATUS_OK || media != DL_ETHER ||
	    class == DATALINK_CLASS_VLAN) {
		return (DLADM_STATUS_BADARG);
	}

	status = dladm_create_datalink_id(vlan, DATALINK_CLASS_VLAN, DL_ETHER,
	    flags & (DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST), &vlanid);
	if (status != DLADM_STATUS_OK)
		goto fail;

	if (flags & DLADM_OPT_PERSIST) {
		status = dladm_persist_vlan_conf(vlan, vlanid,
		    (flags & DLADM_OPT_FORCE) != 0, linkid, vid);
		if (status != DLADM_STATUS_OK)
			goto fail;
	}

	if (flags & DLADM_OPT_ACTIVE) {
		dic.dic_vlanid = vlanid;
		dic.dic_linkid = linkid;
		dic.dic_vid = vid;
		dic.dic_force = (flags & DLADM_OPT_FORCE) != 0;

		if (i_dladm_ioctl(fd, DLDIOC_CREATE_VLAN, &dic,
		    sizeof (dic)) < 0) {
			status = dladm_errno2status(errno);
			if (flags & DLADM_OPT_PERSIST)
				(void) dladm_remove_conf(vlanid);
			goto fail;
		}
	}

	(void) close(fd);
	return (DLADM_STATUS_OK);

fail:
	if (vlanid != DATALINK_INVALID_LINKID) {
		(void) dladm_destroy_datalink_id(vlanid,
		    flags & (DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST));
	}
	(void) close(fd);
	return (status);
}

/*
 * Delete a given VLAN.
 */
dladm_status_t
dladm_vlan_delete(datalink_id_t vlanid, uint32_t flags)
{
	dld_ioc_delete_vlan_t	did;
	int			fd;
	datalink_class_t	class;
	dladm_status_t		status = DLADM_STATUS_OK;

	if ((dladm_datalink_id2info(vlanid, NULL, &class, NULL, NULL, 0) !=
	    DLADM_STATUS_OK) || (class != DATALINK_CLASS_VLAN)) {
		return (DLADM_STATUS_BADARG);
	}

	if (flags & DLADM_OPT_ACTIVE) {
		if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0)
			return (dladm_errno2status(errno));

		did.did_linkid = vlanid;
		if ((i_dladm_ioctl(fd, DLDIOC_DELETE_VLAN, &did,
		    sizeof (did)) < 0) &&
		    ((errno != ENOENT) || !(flags & DLADM_OPT_PERSIST))) {
			(void) close(fd);
			return (dladm_errno2status(errno));
		}
		(void) close(fd);

		/*
		 * Delete active linkprop before this active link is deleted.
		 */
		(void) dladm_set_linkprop(vlanid, NULL, NULL, 0,
		    DLADM_OPT_ACTIVE);
	}

	(void) dladm_destroy_datalink_id(vlanid,
	    flags & (DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST));

	if (flags & DLADM_OPT_PERSIST)
		(void) dladm_remove_conf(vlanid);

	return (status);
}

/*
 * Callback used by dladm_vlan_up()
 */
static int
i_dladm_vlan_up(datalink_id_t vlanid, void *arg)
{
	dladm_vlan_attr_t	dva;
	dld_ioc_create_vlan_t	dic;
	dladm_status_t		*statusp = arg;
	uint32_t		flags;
	int			fd;
	dladm_status_t		status;

	status = dladm_vlan_info(vlanid, &dva, DLADM_OPT_PERSIST);
	if (status != DLADM_STATUS_OK)
		goto done;

	/*
	 * Validate (and delete) the link associated with this VLAN, see if
	 * the specific hardware has been removed during system shutdown.
	 */
	if ((status = dladm_datalink_id2info(dva.dv_linkid, &flags, NULL,
	    NULL, NULL, 0)) != DLADM_STATUS_OK) {
		goto done;
	}

	if (!(flags & DLADM_OPT_ACTIVE)) {
		status = DLADM_STATUS_BADARG;
		goto done;
	}

	dic.dic_linkid = dva.dv_linkid;
	dic.dic_force = dva.dv_force;
	dic.dic_vid = dva.dv_vid;

	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0) {
		status = dladm_errno2status(errno);
		goto done;
	}

	dic.dic_vlanid = vlanid;
	if (i_dladm_ioctl(fd, DLDIOC_CREATE_VLAN, &dic, sizeof (dic)) < 0) {
		status = dladm_errno2status(errno);
		goto done;
	}

	if ((status = dladm_up_datalink_id(vlanid)) != DLADM_STATUS_OK) {
		dld_ioc_delete_vlan_t did;

		did.did_linkid = vlanid;
		(void) i_dladm_ioctl(fd, DLDIOC_DELETE_VLAN, &did,
		    sizeof (did));
	} else {
		/*
		 * Reset the active linkprop of this specific link.
		 */
		(void) dladm_init_linkprop(vlanid, B_FALSE);
	}

	(void) close(fd);
done:
	*statusp = status;
	return (DLADM_WALK_CONTINUE);
}

/*
 * Bring up one VLAN, or all persistent VLANs.  In the latter case, the
 * walk may terminate early if bringup of a VLAN fails.
 */
dladm_status_t
dladm_vlan_up(datalink_id_t linkid)
{
	dladm_status_t	status;

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(i_dladm_vlan_up, &status,
		    DATALINK_CLASS_VLAN, DATALINK_ANY_MEDIATYPE,
		    DLADM_OPT_PERSIST);
		return (DLADM_STATUS_OK);
	} else {
		(void) i_dladm_vlan_up(linkid, &status);
		return (status);
	}
}
