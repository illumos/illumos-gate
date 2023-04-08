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
 * Copyright 2016 Joyent, Inc.
 * Copyright 2023 Oxide Computer Company
 */

#include <door.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <zone.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/aggr.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <libdladm.h>
#include <libdladm_impl.h>
#include <libdllink.h>
#include <libdlmgmt.h>

/*
 * Table of data type sizes indexed by dladm_datatype_t.
 */
static size_t dladm_datatype_size[] = {
	0,				/* DLADM_TYPE_STR, use strnlen() */
	sizeof (boolean_t),		/* DLADM_TYPE_BOOLEAN */
	sizeof (uint64_t)		/* DLADM_TYPE_UINT64 */
};

static dladm_status_t
dladm_door_call(dladm_handle_t handle, void *arg, size_t asize, void *rbuf,
    size_t *rsizep)
{
	door_arg_t	darg;
	int		door_fd;
	dladm_status_t	status;
	boolean_t	reopen = B_FALSE;

	darg.data_ptr	= arg;
	darg.data_size	= asize;
	darg.desc_ptr	= NULL;
	darg.desc_num	= 0;
	darg.rbuf	= rbuf;
	darg.rsize	= *rsizep;

reopen:
	/* The door descriptor is opened if it isn't already */
	if ((status = dladm_door_fd(handle, &door_fd)) != DLADM_STATUS_OK)
		return (status);
	if (door_call(door_fd, &darg) == -1) {
		/*
		 * Stale door descriptor is possible if dlmgmtd was re-started
		 * since last door_fd open so try re-opening door file.
		 */
		if (!reopen && errno == EBADF) {
			(void) close(handle->door_fd);
			handle->door_fd = -1;
			reopen = B_TRUE;
			goto reopen;
		}
		status = dladm_errno2status(errno);
	}
	if (status != DLADM_STATUS_OK)
		return (status);

	if (darg.rbuf != rbuf) {
		/*
		 * The size of the input rbuf is not big enough so that
		 * the door allocate the rbuf itself. In this case, return
		 * the required size to the caller.
		 */
		(void) munmap(darg.rbuf, darg.rsize);
		*rsizep = darg.rsize;
		return (DLADM_STATUS_TOOSMALL);
	} else if (darg.rsize != *rsizep) {
		return (DLADM_STATUS_FAILED);
	}

	return (dladm_errno2status(((dlmgmt_retval_t *)rbuf)->lr_err));
}

/*
 * Allocate a new linkid with the given name. Return the new linkid.
 */
dladm_status_t
dladm_create_datalink_id(dladm_handle_t handle, const char *link,
    datalink_class_t class, uint32_t media, uint32_t flags,
    datalink_id_t *linkidp)
{
	dlmgmt_door_createid_t	createid;
	dlmgmt_createid_retval_t retval;
	uint32_t		dlmgmt_flags;
	dladm_status_t		status;
	size_t			sz = sizeof (retval);

	if (link == NULL || class == DATALINK_CLASS_ALL ||
	    !(flags & (DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST)) ||
	    linkidp == NULL) {
		return (DLADM_STATUS_BADARG);
	}

	if (getzoneid() != GLOBAL_ZONEID) {
		/*
		 * If we're creating this link in a non-global zone, then do
		 * not allow it to be persistent, and flag it as transient so
		 * that it will be automatically cleaned up on zone shutdown,
		 * rather than being moved to the GZ.
		 */
		if (flags & DLADM_OPT_PERSIST)
			return (DLADM_STATUS_TEMPONLY);
		flags |= DLADM_OPT_TRANSIENT;
	}

	dlmgmt_flags = (flags & DLADM_OPT_ACTIVE) ? DLMGMT_ACTIVE : 0;
	dlmgmt_flags |= (flags & DLADM_OPT_PERSIST) ? DLMGMT_PERSIST : 0;
	dlmgmt_flags |= (flags & DLADM_OPT_TRANSIENT) ? DLMGMT_TRANSIENT : 0;

	(void) strlcpy(createid.ld_link, link, MAXLINKNAMELEN);
	createid.ld_class = class;
	createid.ld_media = media;
	createid.ld_flags = dlmgmt_flags;
	createid.ld_cmd = DLMGMT_CMD_CREATE_LINKID;
	createid.ld_prefix = (flags & DLADM_OPT_PREFIX);

	if ((status = dladm_door_call(handle, &createid, sizeof (createid),
	    &retval, &sz)) == DLADM_STATUS_OK) {
		*linkidp = retval.lr_linkid;
	}
	return (status);
}

/*
 * Destroy the given link ID.
 */
dladm_status_t
dladm_destroy_datalink_id(dladm_handle_t handle, datalink_id_t linkid,
    uint32_t flags)
{
	dlmgmt_door_destroyid_t		destroyid;
	dlmgmt_destroyid_retval_t	retval;
	uint32_t			dlmgmt_flags;
	size_t				sz = sizeof (retval);

	dlmgmt_flags = (flags & DLADM_OPT_ACTIVE) ? DLMGMT_ACTIVE : 0;
	dlmgmt_flags |= ((flags & DLADM_OPT_PERSIST) ? DLMGMT_PERSIST : 0);

	destroyid.ld_cmd = DLMGMT_CMD_DESTROY_LINKID;
	destroyid.ld_linkid = linkid;
	destroyid.ld_flags = dlmgmt_flags;

	return (dladm_door_call(handle, &destroyid, sizeof (destroyid),
	    &retval, &sz));
}

/*
 * Remap a given link ID to a new name.
 */
dladm_status_t
dladm_remap_datalink_id(dladm_handle_t handle, datalink_id_t linkid,
    const char *link)
{
	dlmgmt_door_remapid_t	remapid;
	dlmgmt_remapid_retval_t	retval;
	size_t			sz = sizeof (retval);

	remapid.ld_cmd = DLMGMT_CMD_REMAP_LINKID;
	remapid.ld_linkid = linkid;
	(void) strlcpy(remapid.ld_link, link, MAXLINKNAMELEN);

	return (dladm_door_call(handle, &remapid, sizeof (remapid),
	    &retval, &sz));
}

/*
 * Make a given link ID active.
 */
dladm_status_t
dladm_up_datalink_id(dladm_handle_t handle, datalink_id_t linkid)
{
	dlmgmt_door_upid_t	upid;
	dlmgmt_upid_retval_t	retval;
	size_t			sz = sizeof (retval);

	upid.ld_cmd = DLMGMT_CMD_UP_LINKID;
	upid.ld_linkid = linkid;

	return (dladm_door_call(handle, &upid, sizeof (upid), &retval, &sz));
}

/*
 * Create a new link with the given name.  Return the new link's handle
 */
dladm_status_t
dladm_create_conf(dladm_handle_t handle, const char *link, datalink_id_t linkid,
    datalink_class_t class, uint32_t media, dladm_conf_t *confp)
{
	dlmgmt_door_createconf_t	createconf;
	dlmgmt_createconf_retval_t	retval;
	dladm_status_t			status;
	size_t				sz = sizeof (retval);

	if (link == NULL || confp == NULL)
		return (DLADM_STATUS_BADARG);

	(void) strlcpy(createconf.ld_link, link, MAXLINKNAMELEN);
	createconf.ld_class = class;
	createconf.ld_media = media;
	createconf.ld_linkid = linkid;
	createconf.ld_cmd = DLMGMT_CMD_CREATECONF;
	confp->ds_confid = DLADM_INVALID_CONF;

	if ((status = dladm_door_call(handle, &createconf, sizeof (createconf),
	    &retval, &sz)) == DLADM_STATUS_OK) {
		confp->ds_readonly = B_FALSE;
		confp->ds_confid = retval.lr_confid;
	}
	return (status);
}

/*
 * An active physical link reported by the dlmgmtd daemon might not be active
 * anymore as this link might be removed during system shutdown. Check its
 * real status by calling dladm_phys_info().
 */
dladm_status_t
i_dladm_phys_status(dladm_handle_t handle, datalink_id_t linkid,
    uint32_t *flagsp)
{
	dladm_phys_attr_t	dpa;
	dladm_status_t		status;

	assert((*flagsp) & DLMGMT_ACTIVE);

	status = dladm_phys_info(handle, linkid, &dpa, DLADM_OPT_ACTIVE);
	if (status == DLADM_STATUS_NOTFOUND) {
		/*
		 * No active status, this link was removed. Update its status
		 * in the daemon and delete all active linkprops.
		 *
		 * Note that the operation could fail. If it does, return
		 * failure now since otherwise dladm_set_linkprop() might
		 * call back to i_dladm_phys_status() recursively.
		 */
		if ((status = dladm_destroy_datalink_id(handle, linkid,
		    DLADM_OPT_ACTIVE)) != DLADM_STATUS_OK)
			return (status);

		(void) dladm_set_linkprop(handle, linkid, NULL, NULL, 0,
		    DLADM_OPT_ACTIVE);

		(*flagsp) &= ~DLMGMT_ACTIVE;
		status = DLADM_STATUS_OK;
	}
	return (status);
}

/*
 * Walk each entry in the data link configuration repository and
 * call fn on the linkid and arg.
 */
dladm_status_t
dladm_walk_datalink_id(int (*fn)(dladm_handle_t, datalink_id_t, void *),
    dladm_handle_t handle, void *argp, datalink_class_t class,
    datalink_media_t dmedia, uint32_t flags)
{
	dlmgmt_door_getnext_t	getnext;
	dlmgmt_getnext_retval_t	retval;
	uint32_t		dlmgmt_flags;
	datalink_id_t		linkid = DATALINK_INVALID_LINKID;
	dladm_status_t		status = DLADM_STATUS_OK;
	size_t			sz = sizeof (retval);

	if (fn == NULL)
		return (DLADM_STATUS_BADARG);

	dlmgmt_flags = (flags & DLADM_OPT_ACTIVE) ? DLMGMT_ACTIVE : 0;
	dlmgmt_flags |= ((flags & DLADM_OPT_PERSIST) ? DLMGMT_PERSIST : 0);
	dlmgmt_flags |= ((flags & DLADM_OPT_TRANSIENT) ? DLMGMT_TRANSIENT : 0);

	getnext.ld_cmd = DLMGMT_CMD_GETNEXT;
	getnext.ld_class = class;
	getnext.ld_dmedia = dmedia;
	getnext.ld_flags = dlmgmt_flags;

	do {
		getnext.ld_linkid = linkid;
		if ((status = dladm_door_call(handle, &getnext,
		    sizeof (getnext), &retval, &sz)) != DLADM_STATUS_OK) {
			/*
			 * Done with walking. If no next datalink is found,
			 * return success.
			 */
			if (status == DLADM_STATUS_NOTFOUND)
				status = DLADM_STATUS_OK;
			break;
		}

		linkid = retval.lr_linkid;
		if ((retval.lr_class == DATALINK_CLASS_PHYS) &&
		    (retval.lr_flags & DLMGMT_ACTIVE)) {
			/*
			 * An active physical link reported by the dlmgmtd
			 * daemon might not be active anymore. Check its
			 * real status.
			 */
			if (i_dladm_phys_status(handle, linkid,
			    &retval.lr_flags) != DLADM_STATUS_OK) {
				continue;
			}

			if (!(dlmgmt_flags & retval.lr_flags))
				continue;
		}

		if (fn(handle, linkid, argp) == DLADM_WALK_TERMINATE)
			break;
	} while (linkid != DATALINK_INVALID_LINKID);

	return (status);
}

/*
 * Get a handle of a copy of the link configuration (kept in the daemon)
 * for the given link so it can be updated later by dladm_write_conf().
 */
dladm_status_t
dladm_open_conf(dladm_handle_t handle, datalink_id_t linkid,
    dladm_conf_t *confp)
{
	dlmgmt_door_openconf_t		openconf;
	dlmgmt_openconf_retval_t	retval;
	dladm_status_t			status;
	size_t				sz;

	if (linkid == DATALINK_INVALID_LINKID || confp == NULL)
		return (DLADM_STATUS_BADARG);

	sz = sizeof (retval);
	openconf.ld_linkid = linkid;
	openconf.ld_cmd = DLMGMT_CMD_OPENCONF;
	confp->ds_confid = DLADM_INVALID_CONF;
	if ((status = dladm_door_call(handle, &openconf,
	    sizeof (openconf), &retval, &sz)) == DLADM_STATUS_OK) {
		confp->ds_readonly = B_FALSE;
		confp->ds_confid = retval.lr_confid;
	}

	return (status);
}

/*
 * Get the handle of a local snapshot of the link configuration. Note that
 * any operations with this handle are read-only, i.e., one can not update
 * the configuration with this handle.
 */
dladm_status_t
dladm_getsnap_conf(dladm_handle_t handle, datalink_id_t linkid,
    dladm_conf_t *confp)
{
	dlmgmt_door_getconfsnapshot_t	snapshot;
	dlmgmt_getconfsnapshot_retval_t	*retvalp;
	char				*nvlbuf;
	dladm_status_t			status;
	int				err;
	size_t				sz;

	if (linkid == DATALINK_INVALID_LINKID || confp == NULL)
		return (DLADM_STATUS_BADARG);

	sz = sizeof (dlmgmt_getconfsnapshot_retval_t);
	snapshot.ld_linkid = linkid;
	snapshot.ld_cmd = DLMGMT_CMD_GETCONFSNAPSHOT;
again:
	if ((retvalp = malloc(sz)) == NULL)
		return (DLADM_STATUS_NOMEM);

	if ((status = dladm_door_call(handle, &snapshot, sizeof (snapshot),
	    retvalp, &sz)) == DLADM_STATUS_TOOSMALL) {
		free(retvalp);
		goto again;
	}

	if (status != DLADM_STATUS_OK) {
		free(retvalp);
		return (status);
	}

	confp->ds_readonly = B_TRUE;
	nvlbuf = (char *)retvalp + sizeof (dlmgmt_getconfsnapshot_retval_t);
	if ((err = nvlist_unpack(nvlbuf, retvalp->lr_nvlsz,
	    &(confp->ds_nvl), 0)) != 0) {
		status = dladm_errno2status(err);
	}
	free(retvalp);
	return (status);
}

/*
 * Commit the given link to the data link configuration repository so
 * that it will persist across reboots.
 */
dladm_status_t
dladm_write_conf(dladm_handle_t handle, dladm_conf_t conf)
{
	dlmgmt_door_writeconf_t		writeconf;
	dlmgmt_writeconf_retval_t	retval;
	size_t				sz = sizeof (retval);

	if (conf.ds_confid == DLADM_INVALID_CONF)
		return (DLADM_STATUS_BADARG);

	if (conf.ds_readonly)
		return (DLADM_STATUS_DENIED);

	writeconf.ld_cmd = DLMGMT_CMD_WRITECONF;
	writeconf.ld_confid = conf.ds_confid;

	return (dladm_door_call(handle, &writeconf, sizeof (writeconf),
	    &retval, &sz));
}

/*
 * Given a dladm_conf_t, get the specific configuration field
 *
 * If the specified dladm_conf_t is a read-only snapshot of the configuration,
 * get a specific link propertie from that snapshot (nvl), otherwise, get
 * the link protperty from the dlmgmtd daemon using the given confid.
 */
dladm_status_t
dladm_get_conf_field(dladm_handle_t handle, dladm_conf_t conf, const char *attr,
    void *attrval, size_t attrsz)
{
	dladm_status_t		status = DLADM_STATUS_OK;

	if (attrval == NULL || attrsz == 0 || attr == NULL)
		return (DLADM_STATUS_BADARG);

	if (conf.ds_readonly) {
		uchar_t		*oattrval;
		uint32_t	oattrsz;
		int		err;

		if ((err = nvlist_lookup_byte_array(conf.ds_nvl, (char *)attr,
		    &oattrval, &oattrsz)) != 0) {
			return (dladm_errno2status(err));
		}
		if (oattrsz > attrsz)
			return (DLADM_STATUS_TOOSMALL);

		bcopy(oattrval, attrval, oattrsz);
	} else {
		dlmgmt_door_getattr_t	getattr;
		dlmgmt_getattr_retval_t	retval;
		size_t			sz = sizeof (retval);

		if (conf.ds_confid == DLADM_INVALID_CONF)
			return (DLADM_STATUS_BADARG);

		getattr.ld_cmd = DLMGMT_CMD_GETATTR;
		getattr.ld_confid = conf.ds_confid;
		(void) strlcpy(getattr.ld_attr, attr, MAXLINKATTRLEN);

		if ((status = dladm_door_call(handle, &getattr,
		    sizeof (getattr), &retval, &sz)) != DLADM_STATUS_OK) {
			return (status);
		}

		if (retval.lr_attrsz > attrsz)
			return (DLADM_STATUS_TOOSMALL);

		bcopy(retval.lr_attrval, attrval, retval.lr_attrsz);
	}
	return (status);
}

/*
 * Get next property attribute from data link configuration repository.
 * If last_attr is "", return the first property.
 */
dladm_status_t
dladm_getnext_conf_linkprop(dladm_handle_t handle __unused, dladm_conf_t conf,
    const char *last_attr, char *attr, void *attrval, size_t attrsz,
    size_t *attrszp)
{
	nvlist_t	*nvl = conf.ds_nvl;
	nvpair_t	*last = NULL, *nvp;
	uchar_t		*oattrval;
	uint32_t	oattrsz;
	int		err;

	if (nvl == NULL || attrval == NULL || attrsz == 0 || attr == NULL ||
	    !conf.ds_readonly)
		return (DLADM_STATUS_BADARG);

	while ((nvp = nvlist_next_nvpair(nvl, last)) != NULL) {
		if (last_attr[0] == '\0')
			break;
		if (last != NULL && strcmp(last_attr, nvpair_name(last)) == 0)
			break;
		last = nvp;
	}

	if (nvp == NULL)
		return (DLADM_STATUS_NOTFOUND);

	if ((err = nvpair_value_byte_array(nvp, (uchar_t **)&oattrval,
	    &oattrsz)) != 0) {
		return (dladm_errno2status(err));
	}

	*attrszp = oattrsz;
	if (oattrsz > attrsz)
		return (DLADM_STATUS_TOOSMALL);

	(void) strlcpy(attr, nvpair_name(nvp), MAXLINKATTRLEN);
	bcopy(oattrval, attrval, oattrsz);
	return (DLADM_STATUS_OK);
}

/*
 * Get the link ID that is associated with the given name in the current zone.
 */
dladm_status_t
dladm_name2info(dladm_handle_t handle, const char *link, datalink_id_t *linkidp,
    uint32_t *flagp, datalink_class_t *classp, uint32_t *mediap)
{
	return (dladm_zname2info(handle, NULL, link, linkidp, flagp, classp,
	   mediap));
}

/*
 * Get the link ID that is associated with the given zone/name pair.
 */
dladm_status_t
dladm_zname2info(dladm_handle_t handle, const char *zonename, const char *link,
    datalink_id_t *linkidp, uint32_t *flagp, datalink_class_t *classp,
    uint32_t *mediap)
{
	dlmgmt_door_getlinkid_t		getlinkid;
	dlmgmt_getlinkid_retval_t	retval;
	datalink_id_t			linkid;
	dladm_status_t			status;
	size_t				sz = sizeof (retval);

	getlinkid.ld_cmd = DLMGMT_CMD_GETLINKID;
	(void) strlcpy(getlinkid.ld_link, link, MAXLINKNAMELEN);
	if (zonename != NULL)
		getlinkid.ld_zoneid = getzoneidbyname(zonename);
	else
		getlinkid.ld_zoneid = -1;

	if ((status = dladm_door_call(handle, &getlinkid, sizeof (getlinkid),
	    &retval, &sz)) != DLADM_STATUS_OK) {
		return (status);
	}

	linkid = retval.lr_linkid;
	if (retval.lr_class == DATALINK_CLASS_PHYS &&
	    retval.lr_flags & DLMGMT_ACTIVE) {
		/*
		 * An active physical link reported by the dlmgmtd daemon
		 * might not be active anymore. Check and set its real status.
		 */
		status = i_dladm_phys_status(handle, linkid, &retval.lr_flags);
		if (status != DLADM_STATUS_OK)
			return (status);
	}

	if (linkidp != NULL)
		*linkidp = linkid;
	if (flagp != NULL) {
		*flagp = (retval.lr_flags & DLMGMT_ACTIVE) ?
		    DLADM_OPT_ACTIVE : 0;
		*flagp |= (retval.lr_flags & DLMGMT_PERSIST) ?
		    DLADM_OPT_PERSIST : 0;
		*flagp |= (retval.lr_flags & DLMGMT_TRANSIENT) ?
		    DLADM_OPT_TRANSIENT : 0;
	}
	if (classp != NULL)
		*classp = retval.lr_class;
	if (mediap != NULL)
		*mediap = retval.lr_media;

	return (DLADM_STATUS_OK);
}

/*
 * Get the link name that is associated with the given id.
 */
dladm_status_t
dladm_datalink_id2info(dladm_handle_t handle, datalink_id_t linkid,
    uint32_t *flagp, datalink_class_t *classp, uint32_t *mediap, char *link,
    size_t len)
{
	dlmgmt_door_getname_t	getname;
	dlmgmt_getname_retval_t	retval;
	dladm_status_t		status;
	size_t			sz = sizeof (retval);

	if ((linkid == DATALINK_INVALID_LINKID) || (link != NULL && len == 0) ||
	    (link == NULL && len != 0)) {
		return (DLADM_STATUS_BADARG);
	}

	getname.ld_cmd = DLMGMT_CMD_GETNAME;
	getname.ld_linkid = linkid;
	if ((status = dladm_door_call(handle, &getname, sizeof (getname),
	    &retval, &sz)) != DLADM_STATUS_OK) {
		return (status);
	}

	if (len != 0 && (strlen(retval.lr_link) + 1 > len))
		return (DLADM_STATUS_TOOSMALL);

	if (retval.lr_class == DATALINK_CLASS_PHYS &&
	    retval.lr_flags & DLMGMT_ACTIVE) {
		/*
		 * An active physical link reported by the dlmgmtd daemon
		 * might not be active anymore. Check and set its real status.
		 */
		status = i_dladm_phys_status(handle, linkid, &retval.lr_flags);
		if (status != DLADM_STATUS_OK)
			return (status);
	}

	if (link != NULL)
		(void) strlcpy(link, retval.lr_link, len);
	if (classp != NULL)
		*classp = retval.lr_class;
	if (mediap != NULL)
		*mediap = retval.lr_media;
	if (flagp != NULL) {
		*flagp = (retval.lr_flags & DLMGMT_ACTIVE) ?
		    DLADM_OPT_ACTIVE : 0;
		*flagp |= (retval.lr_flags & DLMGMT_PERSIST) ?
		    DLADM_OPT_PERSIST : 0;
		*flagp |= (retval.lr_flags & DLMGMT_TRANSIENT) ?
		    DLADM_OPT_TRANSIENT : 0;
	}
	return (DLADM_STATUS_OK);
}

/*
 * Set the given attr with the given attrval for the given link.
 */
dladm_status_t
dladm_set_conf_field(dladm_handle_t handle, dladm_conf_t conf, const char *attr,
    dladm_datatype_t type, const void *attrval)
{
	dlmgmt_door_setattr_t	setattr;
	dlmgmt_setattr_retval_t	retval;
	size_t			attrsz;
	size_t			sz = sizeof (retval);

	if (attr == NULL || attrval == NULL)
		return (DLADM_STATUS_BADARG);

	if (conf.ds_readonly)
		return (DLADM_STATUS_DENIED);

	if (type == DLADM_TYPE_STR)
		attrsz = strlen(attrval) + 1;
	else
		attrsz = dladm_datatype_size[type];

	if (attrsz > MAXLINKATTRVALLEN)
		return (DLADM_STATUS_TOOSMALL);

	setattr.ld_cmd = DLMGMT_CMD_SETATTR;
	setattr.ld_confid = conf.ds_confid;
	(void) strlcpy(setattr.ld_attr, attr, MAXLINKATTRLEN);
	setattr.ld_attrsz = (uint32_t)attrsz;
	setattr.ld_type = type;
	bcopy(attrval, &setattr.ld_attrval, attrsz);

	return (dladm_door_call(handle, &setattr, sizeof (setattr),
	    &retval, &sz));
}

/*
 * Unset the given attr the given link.
 */
dladm_status_t
dladm_unset_conf_field(dladm_handle_t handle, dladm_conf_t conf,
    const char *attr)
{
	dlmgmt_door_unsetattr_t		unsetattr;
	dlmgmt_unsetattr_retval_t	retval;
	size_t				sz = sizeof (retval);

	if (attr == NULL)
		return (DLADM_STATUS_BADARG);

	if (conf.ds_readonly)
		return (DLADM_STATUS_DENIED);

	unsetattr.ld_cmd = DLMGMT_CMD_UNSETATTR;
	unsetattr.ld_confid = conf.ds_confid;
	(void) strlcpy(unsetattr.ld_attr, attr, MAXLINKATTRLEN);

	return (dladm_door_call(handle, &unsetattr, sizeof (unsetattr),
	    &retval, &sz));
}

/*
 * Remove the given link ID and its entry from the data link configuration
 * repository.
 */
dladm_status_t
dladm_remove_conf(dladm_handle_t handle, datalink_id_t linkid)
{
	dlmgmt_door_removeconf_t	removeconf;
	dlmgmt_removeconf_retval_t	retval;
	size_t				sz = sizeof (retval);

	removeconf.ld_cmd = DLMGMT_CMD_REMOVECONF;
	removeconf.ld_linkid = linkid;

	return (dladm_door_call(handle, &removeconf, sizeof (removeconf),
	    &retval, &sz));
}

/*
 * Free the contents of the link structure.
 */
void
dladm_destroy_conf(dladm_handle_t handle, dladm_conf_t conf)
{
	dlmgmt_door_destroyconf_t	dconf;
	dlmgmt_destroyconf_retval_t	retval;
	size_t				sz = sizeof (retval);

	if (conf.ds_readonly) {
		nvlist_free(conf.ds_nvl);
	} else {
		if (conf.ds_confid == DLADM_INVALID_CONF)
			return;

		dconf.ld_cmd = DLMGMT_CMD_DESTROYCONF;
		dconf.ld_confid = conf.ds_confid;

		(void) dladm_door_call(handle, &dconf, sizeof (dconf),
		    &retval, &sz);
	}
}

dladm_status_t
dladm_zone_boot(dladm_handle_t handle, zoneid_t zoneid)
{
	dlmgmt_door_zoneboot_t		zoneboot;
	dlmgmt_zoneboot_retval_t	retval;
	size_t				sz = sizeof (retval);

	zoneboot.ld_cmd = DLMGMT_CMD_ZONEBOOT;
	zoneboot.ld_zoneid = zoneid;
	return (dladm_door_call(handle, &zoneboot, sizeof (zoneboot),
	    &retval, &sz));
}

dladm_status_t
dladm_zone_halt(dladm_handle_t handle, zoneid_t zoneid)
{
	dlmgmt_door_zonehalt_t		zonehalt;
	dlmgmt_zonehalt_retval_t	retval;
	size_t				sz = sizeof (retval);

	zonehalt.ld_cmd = DLMGMT_CMD_ZONEHALT;
	zonehalt.ld_zoneid = zoneid;
	return (dladm_door_call(handle, &zonehalt, sizeof (zonehalt),
	    &retval, &sz));
}
