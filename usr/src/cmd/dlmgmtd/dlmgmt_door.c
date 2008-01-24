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

/*
 * Main door handler functions used by dlmgmtd to process the different door
 * call requests. Door call requests can come from the user-land applications,
 * which will be handled by dlmgmt_call_handler(); or they can come from the
 * kernel, which will be handled by dlmgmt_upcall_handler().
 */

#include <assert.h>
#include <stdlib.h>
#include <alloca.h>
#include <strings.h>
#include <libdlmgmt.h>
#include "dlmgmt_impl.h"

static dlmgmt_link_t *
dlmgmt_getlink_by_dev(char *devname)
{
	dlmgmt_link_t *linkp = avl_first(&dlmgmt_id_avl);

	for (; linkp != NULL; linkp = AVL_NEXT(&dlmgmt_id_avl, linkp)) {
		if ((linkp->ll_class == DATALINK_CLASS_PHYS) &&
		    linkattr_equal(&(linkp->ll_head), FDEVNAME, devname,
		    strlen(devname) + 1)) {
			return (linkp);
		}
	}
	return (NULL);
}

static void
dlmgmt_upcall_create(dlmgmt_upcall_arg_create_t *create,
    dlmgmt_create_retval_t *retvalp)
{
	datalink_class_t	class;
	uint32_t		media;
	dlmgmt_link_t		*linkp;
	char			link[MAXLINKNAMELEN];
	uint32_t		flags;
	int			err;
	boolean_t		created = B_FALSE;

	/*
	 * Determine whether this link is persistent. Note that this request
	 * is coming from kernel so this link must be active.
	 */
	flags = DLMGMT_ACTIVE | (create->ld_persist ? DLMGMT_PERSIST : 0);

	class = create->ld_class;
	media = create->ld_media;

	/*
	 * Hold the writer lock to update the link table.
	 */
	dlmgmt_table_lock(B_TRUE);

	/*
	 * Check to see whether this is the reattachment of an existing
	 * physical link. If so, return its linkid.
	 */
	if ((class == DATALINK_CLASS_PHYS) &&
	    (linkp = dlmgmt_getlink_by_dev(create->ld_devname)) != NULL) {
		err = linkattr_set(&(linkp->ll_head), FPHYMAJ,
		    &create->ld_phymaj, sizeof (uint64_t), DLADM_TYPE_UINT64);
		if (err != 0)
			goto done;

		err = linkattr_set(&(linkp->ll_head), FPHYINST,
		    &create->ld_phyinst, sizeof (uint64_t), DLADM_TYPE_UINT64);
		if (err != 0)
			goto done;

		linkp->ll_flags |= flags;
		linkp->ll_gen++;
		goto done;
	}

	if ((err = dlmgmt_create_common(create->ld_devname, class, media,
	    flags, &linkp)) == EEXIST) {
		/*
		 * The link name already exists. Return error if this is a
		 * non-physical link (in that case, the link name must be
		 * the same as the given name).
		 */
		if (class != DATALINK_CLASS_PHYS)
			goto done;

		/*
		 * The physical link's name already exists, request
		 * a suggested link name: net<nextppa>
		 */
		err = dlmgmt_generate_name("net", link, MAXLINKNAMELEN);
		if (err != 0)
			goto done;

		err = dlmgmt_create_common(link, class, media, flags, &linkp);
	}

	if (err != 0)
		goto done;

	created = B_TRUE;

	/*
	 * This is a new link.  Only need to persist link attributes for
	 * physical links.
	 */
	if (class == DATALINK_CLASS_PHYS &&
	    (((err = linkattr_set(&linkp->ll_head, FDEVNAME, create->ld_devname,
	    strlen(create->ld_devname) + 1, DLADM_TYPE_STR)) != 0) ||
	    ((err = linkattr_set(&linkp->ll_head, FPHYMAJ, &create->ld_phymaj,
	    sizeof (uint64_t), DLADM_TYPE_UINT64)) != 0) ||
	    ((err = linkattr_set(&linkp->ll_head, FPHYINST, &create->ld_phyinst,
	    sizeof (uint64_t), DLADM_TYPE_UINT64)) != 0))) {
		(void) dlmgmt_destroy_common(linkp, flags);
		goto done;
	}

done:
	if ((err == 0) && ((err = dlmgmt_write_db_entry(linkp->ll_linkid,
	    linkp->ll_flags)) != 0) && created) {
		(void) dlmgmt_destroy_common(linkp, flags);
	}

	if (err == 0)
		retvalp->lr_linkid = linkp->ll_linkid;

	retvalp->lr_err = err;
	dlmgmt_table_unlock();
}

static void
dlmgmt_upcall_update(dlmgmt_upcall_arg_update_t *update,
    dlmgmt_update_retval_t *retvalp)
{
	uint32_t	media = update->ld_media;
	dlmgmt_link_t	*linkp;
	int		err = 0;

	/*
	 * Hold the writer lock to update the link table.
	 */
	dlmgmt_table_lock(B_TRUE);

	/*
	 * Check to see whether this is the reattachment of an existing
	 * physical link. If so, return its linkid.
	 */
	if ((linkp = dlmgmt_getlink_by_dev(update->ld_devname)) == NULL) {
		err = ENOENT;
		goto done;
	}

	retvalp->lr_linkid = linkp->ll_linkid;
	retvalp->lr_media = media;
	if (linkp->ll_media != media && linkp->ll_media != DL_OTHER) {
		/*
		 * Assume a DL_ETHER link ce0, a DL_WIFI link ath0
		 * 1. # dladm rename-link ce0 net0
		 * 2. DR out ce0. net0 is down.
		 * 3. use rename-link to have the ath0 device inherit
		 *    the configuration from net0
		 *    # dladm rename-link ath0 net0
		 * 4. DR in ath0.
		 * As ath0 and ce0 do not have the same media type, ath0
		 * cannot inherit the configuration of net0.
		 */
		err = EEXIST;

		/*
		 * Return the media type of the existing link to indicate the
		 * reason for the name conflict.
		 */
		retvalp->lr_media = linkp->ll_media;
		goto done;
	}

	if (update->ld_novanity &&
	    (strcmp(update->ld_devname, linkp->ll_link) != 0)) {
		/*
		 * Return an error if this is a physical link that does not
		 * support vanity naming, but the link name is not the same
		 * as the given device name.
		 */
		err = EEXIST;
		goto done;
	}

	linkp->ll_media = media;
	linkp->ll_gen++;

	(void) dlmgmt_write_db_entry(linkp->ll_linkid, linkp->ll_flags);

done:
	dlmgmt_table_unlock();
	retvalp->lr_err = err;
}

static void
dlmgmt_upcall_destroy(dlmgmt_upcall_arg_destroy_t *destroy,
    dlmgmt_destroy_retval_t *retvalp)
{
	datalink_id_t	linkid = destroy->ld_linkid;
	dlmgmt_link_t	*linkp = NULL;
	uint32_t	flags, dflags = 0;
	int		err = 0;

	flags = DLMGMT_ACTIVE | (destroy->ld_persist ? DLMGMT_PERSIST : 0);

	/*
	 * Hold the writer lock to update the link table.
	 */
	dlmgmt_table_lock(B_TRUE);

	if ((linkp = link_by_id(linkid)) == NULL) {
		err = ENOENT;
		goto done;
	}

	if (((linkp->ll_flags & flags) & DLMGMT_ACTIVE) &&
	    ((err = dlmgmt_delete_db_entry(linkid, DLMGMT_ACTIVE)) != 0)) {
		dflags = DLMGMT_ACTIVE;
		goto done;
	}

	if (((linkp->ll_flags & flags) & DLMGMT_PERSIST) &&
	    ((err = dlmgmt_delete_db_entry(linkid, DLMGMT_PERSIST)) != 0)) {
		if (dflags != 0)
			(void) dlmgmt_write_db_entry(linkp->ll_linkid, dflags);
		dflags |= DLMGMT_PERSIST;
		goto done;
	}

	if ((err = dlmgmt_destroy_common(linkp, flags)) != 0 && dflags != 0)
		(void) dlmgmt_write_db_entry(linkp->ll_linkid, dflags);

done:
	dlmgmt_table_unlock();
	retvalp->lr_err = err;
}

static void
dlmgmt_getname(dlmgmt_door_getname_t *getname, dlmgmt_getname_retval_t *retvalp)
{
	dlmgmt_link_t	*linkp;
	int		err = 0;

	/*
	 * Hold the reader lock to access the link
	 */
	dlmgmt_table_lock(B_FALSE);
	if ((linkp = link_by_id(getname->ld_linkid)) == NULL) {
		/*
		 * The link does not exists.
		 */
		err = ENOENT;
		goto done;
	}

	if (strlcpy(retvalp->lr_link, linkp->ll_link, MAXLINKNAMELEN) >=
	    MAXLINKNAMELEN) {
		err = ENOSPC;
		goto done;
	}
	retvalp->lr_flags = linkp->ll_flags;
	retvalp->lr_class = linkp->ll_class;
	retvalp->lr_media = linkp->ll_media;

done:
	dlmgmt_table_unlock();
	retvalp->lr_err = err;
}

static void
dlmgmt_getlinkid(dlmgmt_door_getlinkid_t *getlinkid,
    dlmgmt_getlinkid_retval_t *retvalp)
{
	dlmgmt_link_t	*linkp;
	int		err = 0;

	/*
	 * Hold the reader lock to access the link
	 */
	dlmgmt_table_lock(B_FALSE);
	if ((linkp = link_by_name(getlinkid->ld_link)) == NULL) {
		/*
		 * The link does not exists.
		 */
		err = ENOENT;
		goto done;
	}

	retvalp->lr_linkid = linkp->ll_linkid;
	retvalp->lr_flags = linkp->ll_flags;
	retvalp->lr_class = linkp->ll_class;
	retvalp->lr_media = linkp->ll_media;

done:
	dlmgmt_table_unlock();
	retvalp->lr_err = err;
}

static void
dlmgmt_getnext(dlmgmt_door_getnext_t *getnext, dlmgmt_getnext_retval_t *retvalp)
{
	dlmgmt_link_t	link, *linkp;
	datalink_id_t	linkid = getnext->ld_linkid;
	avl_index_t	where;
	int		err = 0;

	/*
	 * Hold the reader lock to access the link
	 */
	dlmgmt_table_lock(B_FALSE);

	link.ll_linkid = (linkid + 1);
	linkp = avl_find(&dlmgmt_id_avl, &link, &where);
	if (linkp == NULL)
		linkp = avl_nearest(&dlmgmt_id_avl, where, AVL_AFTER);

	for (; linkp != NULL; linkp = AVL_NEXT(&dlmgmt_id_avl, linkp)) {
		if ((linkp->ll_class & getnext->ld_class) &&
		    (linkp->ll_flags & getnext->ld_flags) &&
		    DATALINK_MEDIA_ACCEPTED(getnext->ld_dmedia,
		    linkp->ll_media))
			break;
	}

	if (linkp == NULL) {
		err = ENOENT;
	} else {
		retvalp->lr_linkid = linkp->ll_linkid;
		retvalp->lr_class = linkp->ll_class;
		retvalp->lr_media = linkp->ll_media;
		retvalp->lr_flags = linkp->ll_flags;
	}

	dlmgmt_table_unlock();
	retvalp->lr_err = err;
}

/*
 * Note that the caller needs to free the memory of *retvalp, when it returns
 * success.
 */
static int
dlmgmt_upcall_getattr(dlmgmt_upcall_arg_getattr_t *getattr,
    dlmgmt_getattr_retval_t **retvalpp, size_t *retszp)
{
	dlmgmt_link_t	*linkp;
	int		err = 0;

	/*
	 * Hold the reader lock to access the link
	 */
	dlmgmt_table_lock(B_FALSE);
	if ((linkp = link_by_id(getattr->ld_linkid)) == NULL) {
		/*
		 * The link does not exist.
		 */
		err = ENOENT;
		goto done;
	}

	err = dlmgmt_getattr_common(&linkp->ll_head, getattr->ld_attr,
	    retvalpp, retszp);

done:
	dlmgmt_table_unlock();
	return (err);
}

static void
dlmgmt_upcall_handler(void *arg, int cmd)
{
	switch (cmd) {
	case DLMGMT_CMD_DLS_CREATE: {
		dlmgmt_create_retval_t retval;

		dlmgmt_upcall_create(arg, &retval);
		(void) door_return((char *)&retval, sizeof (retval), NULL, 0);
		break;
	}
	case DLMGMT_CMD_DLS_UPDATE: {
		dlmgmt_update_retval_t retval;

		dlmgmt_upcall_update(arg, &retval);
		(void) door_return((char *)&retval, sizeof (retval), NULL, 0);
		break;
	}
	case DLMGMT_CMD_DLS_GETATTR: {
		dlmgmt_getattr_retval_t retval;
		dlmgmt_getattr_retval_t *retvalp = NULL;
		dlmgmt_getattr_retval_t *tmp;
		size_t retsz = 0;
		int err;

		if ((err = dlmgmt_upcall_getattr(arg, &retvalp, &retsz)) != 0) {
			retval.lr_err = err;
			retvalp = &retval;
			retsz = sizeof (retval);
		} else {
			/*
			 * For the successful case, retvalp points to
			 * memory that was allocated with malloc.  But, since
			 * door_return never returns, that memory gets leaked.
			 * Use alloca and free retvalp.
			 */
			tmp = alloca(retsz);
			bcopy(retvalp, tmp, retsz);
			free(retvalp);
			retvalp = tmp;
		}
		(void) door_return((char *)retvalp, retsz, NULL, 0);
		break;
	}
	case DLMGMT_CMD_DLS_DESTROY: {
		dlmgmt_destroy_retval_t retval;

		dlmgmt_upcall_destroy(arg, &retval);
		(void) door_return((char *)&retval, sizeof (retval), NULL, 0);
		break;
	}
	case DLMGMT_CMD_GETNAME: {
		dlmgmt_getname_retval_t retval;

		dlmgmt_getname(arg, &retval);
		(void) door_return((char *)&retval, sizeof (retval), NULL, 0);
		break;
	}
	case DLMGMT_CMD_GETLINKID: {
		dlmgmt_getlinkid_retval_t retval;

		dlmgmt_getlinkid(arg, &retval);
		(void) door_return((char *)&retval, sizeof (retval), NULL, 0);
		break;
	}
	case DLMGMT_CMD_GETNEXT: {
		dlmgmt_getnext_retval_t retval;

		dlmgmt_getnext(arg, &retval);
		(void) door_return((char *)&retval, sizeof (retval), NULL, 0);
		break;
	}
	default: {
		struct dlmgmt_null_retval_s retval;

		retval.lr_err = EINVAL;
		(void) door_return((char *)&retval, sizeof (retval), NULL, 0);
		break;
	}
	}
}

static void
dlmgmt_createid(dlmgmt_door_createid_t *createid,
    dlmgmt_createid_retval_t *retvalp)
{
	dlmgmt_link_t	*linkp;
	datalink_id_t	linkid = DATALINK_INVALID_LINKID;
	char		link[MAXLINKNAMELEN];
	int		err;

	/*
	 * Hold the writer lock to update the dlconf table.
	 */
	dlmgmt_table_lock(B_TRUE);

	if (createid->ld_prefix) {
		err = dlmgmt_generate_name(createid->ld_link, link,
		    MAXLINKNAMELEN);
		if (err != 0)
			goto done;

		err = dlmgmt_create_common(link, createid->ld_class,
		    createid->ld_media, createid->ld_flags, &linkp);
	} else {
		err = dlmgmt_create_common(createid->ld_link,
		    createid->ld_class, createid->ld_media, createid->ld_flags,
		    &linkp);
	}

	if (err == 0) {
		/*
		 * Keep the active mapping.
		 */
		linkid = linkp->ll_linkid;
		if (createid->ld_flags & DLMGMT_ACTIVE)
			(void) dlmgmt_write_db_entry(linkid, DLMGMT_ACTIVE);
	}

done:
	dlmgmt_table_unlock();
	retvalp->lr_linkid = linkid;
	retvalp->lr_err = err;
}

static void
dlmgmt_destroyid(dlmgmt_door_destroyid_t *destroyid,
    dlmgmt_destroyid_retval_t *retvalp)
{
	datalink_id_t	linkid = destroyid->ld_linkid;
	uint32_t	flags = destroyid->ld_flags;
	dlmgmt_link_t	*linkp = NULL;
	int		err = 0;

	/*
	 * Hold the writer lock to update the link table.
	 */
	dlmgmt_table_lock(B_TRUE);
	if ((linkp = link_by_id(linkid)) == NULL) {
		err = ENOENT;
		goto done;
	}

	if ((err = dlmgmt_destroy_common(linkp, flags)) != 0)
		goto done;

	/*
	 * Delete the active mapping.
	 */
	if (flags & DLMGMT_ACTIVE)
		(void) dlmgmt_delete_db_entry(linkid, DLMGMT_ACTIVE);

done:
	dlmgmt_table_unlock();
	retvalp->lr_err = err;
}

/*
 * Remap a linkid to a given link name, i.e., rename an existing link1
 * (ld_linkid) to a non-existent link2 (ld_link): rename link1's name to
 * the given link name.
 */
static void
dlmgmt_remapid(dlmgmt_door_remapid_t *remapid,
    dlmgmt_remapid_retval_t *retvalp)
{
	datalink_id_t	linkid1 = remapid->ld_linkid;
	dlmgmt_link_t	link, *linkp1, *tmp;
	avl_index_t	where;
	int		err = 0;

	if (!dladm_valid_linkname(remapid->ld_link)) {
		retvalp->lr_err = EINVAL;
		return;
	}

	/*
	 * Hold the writer lock to update the link table.
	 */
	dlmgmt_table_lock(B_TRUE);
	if ((linkp1 = link_by_id(linkid1)) == NULL) {
		err = ENOENT;
		goto done;
	}

	if (link_by_name(remapid->ld_link) != NULL) {
		err = EEXIST;
		goto done;
	}

	avl_remove(&dlmgmt_name_avl, linkp1);
	(void) strlcpy(link.ll_link, remapid->ld_link, MAXLINKNAMELEN);
	tmp = avl_find(&dlmgmt_name_avl, &link, &where);
	assert(tmp == NULL);
	(void) strlcpy(linkp1->ll_link, remapid->ld_link, MAXLINKNAMELEN);
	avl_insert(&dlmgmt_name_avl, linkp1, where);
	dlmgmt_advance(linkp1);

	/*
	 * If we renamed a temporary link, update the temporary repository.
	 */
	if (linkp1->ll_flags & DLMGMT_ACTIVE)
		(void) dlmgmt_write_db_entry(linkid1, DLMGMT_ACTIVE);
done:
	dlmgmt_table_unlock();
	retvalp->lr_err = err;
}

static void
dlmgmt_upid(dlmgmt_door_upid_t *upid, dlmgmt_upid_retval_t *retvalp)
{
	dlmgmt_link_t	*linkp;
	int		err = 0;

	/*
	 * Hold the writer lock to update the link table.
	 */
	dlmgmt_table_lock(B_TRUE);
	if ((linkp = link_by_id(upid->ld_linkid)) == NULL) {
		err = ENOENT;
		goto done;
	}

	if (linkp->ll_flags & DLMGMT_ACTIVE) {
		err = EINVAL;
		goto done;
	}

	linkp->ll_flags |= DLMGMT_ACTIVE;
	(void) dlmgmt_write_db_entry(linkp->ll_linkid, DLMGMT_ACTIVE);
done:
	dlmgmt_table_unlock();
	retvalp->lr_err = err;
}

static void
dlmgmt_createconf(dlmgmt_door_createconf_t *createconf,
    dlmgmt_createconf_retval_t *retvalp)
{
	dlmgmt_dlconf_t	dlconf, *dlconfp, *tmp;
	avl_index_t	where;
	int		err;

	/*
	 * Hold the writer lock to update the dlconf table.
	 */
	dlmgmt_dlconf_table_lock(B_TRUE);

	if ((err = dlconf_create(createconf->ld_link, createconf->ld_linkid,
	    createconf->ld_class, createconf->ld_media, &dlconfp)) != 0) {
		goto done;
	}

	dlconf.ld_id = dlconfp->ld_id;
	tmp = avl_find(&dlmgmt_dlconf_avl, &dlconf, &where);
	assert(tmp == NULL);
	avl_insert(&dlmgmt_dlconf_avl, dlconfp, where);
	dlmgmt_advance_dlconfid(dlconfp);

	retvalp->lr_conf = (dladm_conf_t)dlconfp->ld_id;
done:
	dlmgmt_dlconf_table_unlock();
	retvalp->lr_err = err;
}

static void
dlmgmt_setattr(dlmgmt_door_setattr_t *setattr, size_t argsz,
    dlmgmt_setattr_retval_t *retvalp)
{
	dlmgmt_dlconf_t	dlconf, *dlconfp;
	int		err = 0;

	if (argsz < sizeof (dlmgmt_door_setattr_t) ||
	    argsz != sizeof (dlmgmt_door_setattr_t) + setattr->ld_attrsz - 1) {
		retvalp->lr_err = EINVAL;
		return;
	}

	/*
	 * Hold the writer lock to update the dlconf table.
	 */
	dlmgmt_dlconf_table_lock(B_TRUE);

	dlconf.ld_id = (int)setattr->ld_conf;
	dlconfp = avl_find(&dlmgmt_dlconf_avl, &dlconf, NULL);
	if (dlconfp == NULL) {
		err = ENOENT;
		goto done;
	}

	err = linkattr_set(&(dlconfp->ld_head), setattr->ld_attr,
	    &setattr->ld_attrval, setattr->ld_attrsz, setattr->ld_type);

done:
	dlmgmt_dlconf_table_unlock();
	retvalp->lr_err = err;
}

static void
dlmgmt_unsetattr(dlmgmt_door_unsetattr_t *unsetattr,
    dlmgmt_unsetattr_retval_t *retvalp)
{
	dlmgmt_dlconf_t	dlconf, *dlconfp;
	int		err = 0;

	/*
	 * Hold the writer lock to update the dlconf table.
	 */
	dlmgmt_dlconf_table_lock(B_TRUE);

	dlconf.ld_id = (int)unsetattr->ld_conf;
	dlconfp = avl_find(&dlmgmt_dlconf_avl, &dlconf, NULL);
	if (dlconfp == NULL) {
		err = ENOENT;
		goto done;
	}

	err = linkattr_unset(&(dlconfp->ld_head), unsetattr->ld_attr);

done:
	dlmgmt_dlconf_table_unlock();
	retvalp->lr_err = err;
}

/*
 * Note that dlmgmt_readconf() returns a conf ID of a conf AVL tree entry,
 * which is managed by dlmgmtd.  The ID is used to find the conf entry when
 * dlmgmt_write_conf() is called.  The conf entry contains an ld_gen value
 * (which is the generation number - ll_gen) of the dlmgmt_link_t at the time
 * of dlmgmt_readconf(), and ll_gen changes every time the dlmgmt_link_t
 * changes its attributes.  Therefore, dlmgmt_write_conf() can compare ld_gen
 * in the conf entry against the latest dlmgmt_link_t ll_gen value to see if
 * anything has changed between the dlmgmt_read_conf() and dlmgmt_writeconf()
 * calls.  If so, EAGAIN is returned.  This mechanism can ensures atomicity
 * across the pair of dladm_read_conf() and dladm_write_conf() calls.
 */
static void
dlmgmt_writeconf(dlmgmt_door_writeconf_t *writeconf,
    dlmgmt_writeconf_retval_t *retvalp)
{
	dlmgmt_dlconf_t		dlconf, *dlconfp;
	dlmgmt_link_t		*linkp;
	dlmgmt_linkattr_t	*attrp, *next;
	int			err = 0;

	/*
	 * Hold the read lock to access the dlconf table.
	 */
	dlmgmt_dlconf_table_lock(B_TRUE);

	dlconf.ld_id = (int)writeconf->ld_conf;
	dlconfp = avl_find(&dlmgmt_dlconf_avl, &dlconf, NULL);
	if (dlconfp == NULL) {
		err = ENOENT;
		goto done;
	}

	/*
	 * Hold the writer lock to update the link table.
	 */
	dlmgmt_table_lock(B_TRUE);
	linkp = link_by_id(dlconfp->ld_linkid);
	if ((linkp == NULL) || (linkp->ll_class != dlconfp->ld_class) ||
	    (linkp->ll_media != dlconfp->ld_media) ||
	    (strcmp(linkp->ll_link, dlconfp->ld_link) != 0)) {
		/*
		 * The link does not exist.
		 */
		dlmgmt_table_unlock();
		err = ENOENT;
		goto done;
	}

	if (linkp->ll_gen != dlconfp->ld_gen) {
		/*
		 * Something has changed the link configuration; try again.
		 */
		dlmgmt_table_unlock();
		err = EAGAIN;
		goto done;
	}

	/*
	 * Delete the old attribute list.
	 */
	for (attrp = linkp->ll_head; attrp != NULL; attrp = next) {
		next = attrp->lp_next;
		free(attrp->lp_val);
		free(attrp);
	}
	linkp->ll_head = NULL;

	/*
	 * Set the new attribute.
	 */
	for (attrp = dlconfp->ld_head; attrp != NULL; attrp = attrp->lp_next) {
		if ((err = linkattr_set(&(linkp->ll_head), attrp->lp_name,
		    attrp->lp_val, attrp->lp_sz, attrp->lp_type)) != 0) {
			dlmgmt_table_unlock();
			goto done;
		}
	}

	linkp->ll_gen++;
	err = dlmgmt_write_db_entry(linkp->ll_linkid, DLMGMT_PERSIST);
	dlmgmt_table_unlock();
done:
	dlmgmt_dlconf_table_unlock();
	retvalp->lr_err = err;
}

static void
dlmgmt_removeconf(dlmgmt_door_removeconf_t *removeconf,
    dlmgmt_removeconf_retval_t *retvalp)
{
	int err;

	dlmgmt_table_lock(B_TRUE);
	err = dlmgmt_delete_db_entry(removeconf->ld_linkid, DLMGMT_PERSIST);
	dlmgmt_table_unlock();
	retvalp->lr_err = err;
}

static void
dlmgmt_destroyconf(dlmgmt_door_destroyconf_t *destroyconf,
    dlmgmt_destroyconf_retval_t *retvalp)
{
	dlmgmt_dlconf_t	dlconf, *dlconfp;
	int		err = 0;

	/*
	 * Hold the writer lock to update the dlconf table.
	 */
	dlmgmt_dlconf_table_lock(B_TRUE);

	dlconf.ld_id = (int)destroyconf->ld_conf;
	dlconfp = avl_find(&dlmgmt_dlconf_avl, &dlconf, NULL);
	if (dlconfp == NULL) {
		err = ENOENT;
		goto done;
	}

	avl_remove(&dlmgmt_dlconf_avl, dlconfp);
	dlconf_destroy(dlconfp);

done:
	dlmgmt_dlconf_table_unlock();
	retvalp->lr_err = err;
}

/*
 * See the comments above dladm_write_conf() to see how ld_gen is used to
 * ensure atomicity across the {dlmgmt_readconf(), dlmgmt_writeconf()} pair.
 */
static void
dlmgmt_readconf(dlmgmt_door_readconf_t *readconf,
    dlmgmt_readconf_retval_t *retvalp)
{
	dlmgmt_link_t 		*linkp;
	datalink_id_t		linkid = readconf->ld_linkid;
	dlmgmt_dlconf_t		*dlconfp, *tmp, dlconf;
	dlmgmt_linkattr_t	*attrp;
	avl_index_t		where;
	int			err = 0;

	/*
	 * Hold the writer lock to update the dlconf table.
	 */
	dlmgmt_dlconf_table_lock(B_TRUE);

	/*
	 * Hold the reader lock to access the link
	 */
	dlmgmt_table_lock(B_FALSE);
	linkp = link_by_id(linkid);
	if ((linkp == NULL) || !(linkp->ll_flags & DLMGMT_PERSIST)) {
		/*
		 * The persistent link configuration does not exists.
		 */
		err = ENOENT;
		goto done;
	}

	if ((err = dlconf_create(linkp->ll_link, linkp->ll_linkid,
	    linkp->ll_class, linkp->ll_media, &dlconfp)) != 0) {
		goto done;
	}

	for (attrp = linkp->ll_head; attrp != NULL; attrp = attrp->lp_next) {
		if ((err = linkattr_set(&(dlconfp->ld_head), attrp->lp_name,
		    attrp->lp_val, attrp->lp_sz, attrp->lp_type)) != 0) {
			dlconf_destroy(dlconfp);
			goto done;
		}
	}
	dlconfp->ld_gen = linkp->ll_gen;

	dlconf.ld_id = dlconfp->ld_id;
	tmp = avl_find(&dlmgmt_dlconf_avl, &dlconf, &where);
	assert(tmp == NULL);
	avl_insert(&dlmgmt_dlconf_avl, dlconfp, where);
	dlmgmt_advance_dlconfid(dlconfp);

	retvalp->lr_conf = (dladm_conf_t)dlconfp->ld_id;
done:
	dlmgmt_table_unlock();
	dlmgmt_dlconf_table_unlock();
	retvalp->lr_err = err;
}

/*
 * Note: the caller must free *retvalpp in case of success.
 */
static int
dlmgmt_getattr(dlmgmt_door_getattr_t *getattr,
    dlmgmt_getattr_retval_t **retvalpp, size_t *retszp)
{
	dlmgmt_dlconf_t		dlconf, *dlconfp;
	int			err = 0;

	/*
	 * Hold the writer lock to update the dlconf table.
	 */
	dlmgmt_dlconf_table_lock(B_FALSE);

	dlconf.ld_id = (int)getattr->ld_conf;
	dlconfp = avl_find(&dlmgmt_dlconf_avl, &dlconf, NULL);
	if (dlconfp == NULL) {
		err = ENOENT;
		goto done;
	}

	err = dlmgmt_getattr_common(&dlconfp->ld_head, getattr->ld_attr,
	    retvalpp, retszp);

done:
	dlmgmt_dlconf_table_unlock();
	return (err);
}

static void
dlmgmt_call_handler(void *arg, size_t argsz, int cmd)
{
	switch (cmd) {
	case DLMGMT_CMD_CREATE_LINKID: {
		dlmgmt_createid_retval_t retval;

		dlmgmt_createid(arg, &retval);
		(void) door_return((char *)&retval, sizeof (retval), NULL, 0);
		break;
	}
	case DLMGMT_CMD_DESTROY_LINKID: {
		dlmgmt_destroyid_retval_t retval;

		dlmgmt_destroyid(arg, &retval);
		(void) door_return((char *)&retval, sizeof (retval), NULL, 0);
		break;
	}
	case DLMGMT_CMD_REMAP_LINKID: {
		dlmgmt_remapid_retval_t retval;

		dlmgmt_remapid(arg, &retval);
		(void) door_return((char *)&retval, sizeof (retval), NULL, 0);
		break;
	}
	case DLMGMT_CMD_UP_LINKID: {
		dlmgmt_upid_retval_t retval;

		dlmgmt_upid(arg, &retval);
		(void) door_return((char *)&retval, sizeof (retval), NULL, 0);
		break;
	}
	case DLMGMT_CMD_CREATECONF: {
		dlmgmt_createconf_retval_t retval;

		dlmgmt_createconf(arg, &retval);
		(void) door_return((char *)&retval, sizeof (retval), NULL, 0);
		break;
	}
	case DLMGMT_CMD_SETATTR: {
		dlmgmt_setattr_retval_t retval;

		dlmgmt_setattr(arg, argsz, &retval);
		(void) door_return((char *)&retval, sizeof (retval), NULL, 0);
		break;
	}
	case DLMGMT_CMD_UNSETATTR: {
		dlmgmt_unsetattr_retval_t retval;

		dlmgmt_unsetattr(arg, &retval);
		(void) door_return((char *)&retval, sizeof (retval), NULL, 0);
		break;
	}
	case DLMGMT_CMD_WRITECONF: {
		dlmgmt_writeconf_retval_t retval;

		dlmgmt_writeconf(arg, &retval);
		(void) door_return((char *)&retval, sizeof (retval), NULL, 0);
		break;
	}
	case DLMGMT_CMD_REMOVECONF: {
		dlmgmt_removeconf_retval_t retval;

		dlmgmt_removeconf(arg, &retval);
		(void) door_return((char *)&retval, sizeof (retval), NULL, 0);
		break;
	}
	case DLMGMT_CMD_DESTROYCONF: {
		dlmgmt_destroyconf_retval_t retval;

		dlmgmt_destroyconf(arg, &retval);
		(void) door_return((char *)&retval, sizeof (retval), NULL, 0);
		break;
	}
	case DLMGMT_CMD_READCONF: {
		dlmgmt_readconf_retval_t retval;

		dlmgmt_readconf(arg, &retval);
		(void) door_return((char *)&retval, sizeof (retval), NULL, 0);
		break;
	}
	case DLMGMT_CMD_GETATTR: {
		dlmgmt_getattr_retval_t retval;
		dlmgmt_getattr_retval_t *retvalp = NULL;
		dlmgmt_getattr_retval_t *tmp;
		int err;
		size_t retsz = 0;

		if ((err = dlmgmt_getattr(arg, &retvalp, &retsz)) != 0) {
			retval.lr_err = err;
			retvalp = &retval;
			retsz = sizeof (retval);
		} else {
			/*
			 * For the successful case, retvalp points to memory
			 * that was allocated in dlmgmt_getattr().  Since
			 * door_return never returns, that memory would get
			 * leaked. So we use alloca instead, and free retvalp.
			 */
			tmp = alloca(retsz);
			bcopy(retvalp, tmp, retsz);
			free(retvalp);
			retvalp = tmp;
		}
		(void) door_return((char *)retvalp, retsz, NULL, 0);
		break;
	}
	default: {
		struct dlmgmt_null_retval_s retval;

		retval.lr_err = EINVAL;
		(void) door_return((char *)&retval, sizeof (retval), NULL, 0);
		break;
	}
	}
}

/* ARGSUSED */
void
dlmgmt_handler(void *cookie, char *argp, size_t argsz, door_desc_t *dp,
    uint_t n_desc)
{
	int cmd = ((dlmgmt_door_arg_t *)(void *)argp)->ld_cmd;

	if (cmd < DLMGMT_CMD_BASE) {
		/*
		 * Upcall request from the dls module.
		 */
		dlmgmt_upcall_handler(argp, cmd);
	} else {
		/*
		 * Door call request from libdladm.
		 */
		dlmgmt_call_handler(argp, argsz, cmd);
	}
}
