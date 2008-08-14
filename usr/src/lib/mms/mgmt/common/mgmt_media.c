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

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/nvpair.h>
#include <door.h>
#include <fcntl.h>

#include "mms_mgmt.h"
#include "mgmt_acsls.h"
#include "mmp_defs.h"
#include "mgmt_media.h"
#include "mgmt_sym.h"
#include "mgmt_util.h"

static char *_SrcFile = __FILE__;
#define	HERE _SrcFile, __LINE__

static char *mmsmntdoor = "/var/run/mmsmnt_door";

static int voltype_in_use(void *session, char *voltype);
static int
mgmt_show_mmvols(void *session, char *pcl, char *library, nvlist_t **vols);
static int
mgmt_show_partition(void *session, char *pcl, char *library, nvlist_t **parts);
static int call_mmsmnt(door_arg_t *arg);

static char *label_fname = "                 ";
static mms_mgmt_setopt_t cartridgegrpopts[] = {
	{O_NAME, "CartridgeGroupName", NULL, B_TRUE, NULL},
	{NULL, NULL, NULL, B_FALSE, NULL}
};
#define	CGOPT_COUNT	sizeof (cartridgegrpopts) / sizeof (mms_mgmt_setopt_t)

/*
 * Note that O_APPS (string array) is required for CartridgeGroupApplication.
 * Add a CGA for each application specified in the array.
 */
static mms_mgmt_setopt_t cgappopts[] = {
	{O_NAME, "CartridgeGroupName", NULL, B_TRUE, NULL},
	{O_APPS, "ApplicationName", NULL, B_TRUE, NULL},
	{NULL, NULL, NULL, B_FALSE, NULL}
};
#define	CGAOPT_COUNT	sizeof (cgappopts) / sizeof (mms_mgmt_setopt_t)

/*
 * mms_mgmt_discover_media()
 *
 *  Finds ACSLS media, optionally filtered by library acs & lsm.
 *  Those already configured for use with MMS are filtered out unless
 *  'showall' is TRUE.
 *
 *  Required opts are:
 *    acshost
 *    acsport (if not the default)
 *      -- or --
 *    library
 *  If library specified, get ACS information from LIBRARY object.
 */
int
mms_mgmt_discover_media(
    void *session, boolean_t showall, nvlist_t *opts, mms_list_t *vol_list,
    nvlist_t *errs)
{
	int		st;
	mms_acslib_t	*lsm = NULL;
	mms_acslib_t	*nlsm = NULL;
	mms_acscart_t	*vol = NULL;
	mms_acscart_t	*nvol = NULL;
	mms_list_t	lib_list;
	char		*acshost = NULL;
	char		*val = NULL;
	char		**in_libs = NULL;
	int		count = 0;
	void		*sess = NULL;
	void		*sessp = session;
	boolean_t	found;
	int		i;
	char		tid[64];
	char		cmd[8192];
	void		*response;
	nvlist_t	*volattrs = NULL;
	nvlist_t	*avl = NULL;
	int		ost;

	if (!opts || !vol_list) {
		return (MMS_MGMT_NOARG);
	}

	(void) memset(vol_list, 0, sizeof (mms_list_t));

	/*
	 * we need either the ACSLS host or one or more libraries to
	 * proceed.
	 */
	(void) nvlist_lookup_string(opts, O_ACSHOST, &acshost);
	in_libs = var_to_array(opts, O_MMSLIB, &count);

	if (!acshost && !in_libs) {
		st = ENOENT;
		MGMT_ADD_OPTERR(errs, O_ACSHOST, st);
		MGMT_ADD_OPTERR(errs, O_MMSLIB, st);

		return (st);
	}

	if (session == NULL) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st == 0) {
			sessp = sess;
		} else {
			return (st);
		}
	}

	/* get list of libs MMS knows about */
	st = mms_get_library(sessp, B_FALSE, &lib_list);
	if (st != 0) {
		goto done;
	}

	if (!acshost) {
		/* only supporting a single ACSLS server for V1 */
		lsm = mms_list_head(&lib_list);
		if (lsm == NULL) {
			st = ENOENT;
			MGMT_ADD_OPTERR(errs, O_ACSHOST, st);
			goto done;
		}
		acshost = lsm->acshost;
	}

	if (count > 0) {
		/* remove libraries not in our list */
		lsm = mms_list_head(&lib_list);
		while (lsm != NULL) {
			nlsm = mms_list_next(&lib_list, lsm);
			found = B_FALSE;

			for (i = 0; i < count; i++) {
				if (strcmp(in_libs[i], lsm->name) == 0) {
					found = B_TRUE;
					break;
				}
			}
			if (!found) {
				/* remove */
				mms_list_remove(&lib_list, lsm);
				free(lsm);
			}
			lsm = nlsm;
		}
	}

	/* all of the volumes from the ACSLS server */
	st = get_acs_volumes(acshost, NULL, vol_list);
	if (st != 0) {
		goto done;
	}

	/* weed out volumes for libraries we're not interested in */
	vol = mms_list_head(vol_list);
	while (vol != NULL) {
		nvol = mms_list_next(vol_list, vol);
		found = B_FALSE;

		mms_list_foreach(&lib_list, lsm) {
			if (strcmp(lsm->type, "DISK") == 0) {
				continue;
			}
			if ((lsm->acs == vol->libacs) &&
			    (lsm->lsm == vol->liblsm)) {
				found = B_TRUE;
				break;
			}
		}
		if (!found) {
			mms_list_remove(vol_list, vol);
			free(vol);
		} else {
			if (lsm->name[0] != '\0') {
				(void) strlcpy(vol->libname, lsm->name,
				    sizeof (vol->libname));
			}
		}
		vol = nvol;
	}

	/* fetch the list of cartridges MMS knows about */
	(void) mms_gen_taskid(tid);

	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] reportmode[namevalue] "
	    "report[CARTRIDGE.'CartridgePCL' CARTRIDGE.'CartridgeTypeName' "
	    "CARTRIDGE.'LibraryName' CARTRIDGE.'CartridgeGroupName'] ", tid);

	if (count > 0) {
		(void) strlcat(cmd, "match [or ", sizeof (cmd));
		for (i = 0; i < count; i++) {
			if (in_libs[i] == NULL) {
				continue;
			}
			(void) strlcat(cmd, "streq(LIBRARY.'LibraryName' ",
			    sizeof (cmd));
			(void) strlcat(cmd, "'", sizeof (cmd));
			(void) strlcat(cmd, in_libs[i], sizeof (cmd));
			(void) strlcat(cmd, "') ", sizeof (cmd));
		}
		(void) strlcat(cmd, "]", sizeof (cmd));
	}
	(void) strlcat(cmd, ";", sizeof (cmd));

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "list volumes", &response);
	if (st == 0) {
		st = mmp_get_nvattrs("volid", B_TRUE, response, &volattrs);
		mms_free_rsp(response);
	}

	if (st != 0) {
		goto done;
	}

	/*
	 * TODO:  this will break horribly if barcodes are not unique for
	 * all libs.  Fix this to be more library-aware.
	 */
	vol = mms_list_head(vol_list);
	while (vol != NULL) {
		nvol = mms_list_next(vol_list, vol);

		ost = nvlist_lookup_nvlist(volattrs, vol->label, &avl);
		if (ost == 0) {
			if (!showall) {
				mms_list_remove(vol_list, vol);
			} else {
				ost = nvlist_lookup_string(avl,
				    O_MPOOL, &val);
				if (ost == 0) {
					(void) strlcpy(vol->groupname, val,
					    sizeof (vol->groupname));
				}
			}
		}
		vol = nvol;
	}

done:
	mgmt_free_str_arr(in_libs, count);

	if (volattrs) {
		nvlist_free(volattrs);
	}

	free_acslib_list(&lib_list);

	if (st != 0) {
		mms_list_free_and_destroy(vol_list, free);
		vol_list = NULL;
	}

	return (st);
}

int
mms_mgmt_add_mpool(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	char		**varray = NULL;
	int		count = 0;
	int		i;

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.create")) {
		return (EACCES);
	}

	st = mms_add_object(session, "CARTRIDGEGROUP", cartridgegrpopts,
	    nvl, errs);

	if (st == 0) {
		/* save original values */
		varray = var_to_array(nvl, O_APPS, &count);

		for (i = 0; i < count; i++) {
			if (!varray[i] || (strlen(varray[i]) == 0) ||
			    (strcasecmp(varray[i], "none") == 0) ||
			    (strcasecmp(varray[i], "all") == 0)) {
				continue;
			}

			/* put back a single value */
			(void) nvlist_add_string(nvl, O_APPS, varray[i]);
			st = mms_add_object(session,
			    "CARTRIDGEGROUPAPPLICATION", cgappopts, nvl, errs);
			if (st != 0) {
				break;
			}
		}

		/* put back original values */
		if (varray) {
			(void) nvlist_add_string_array(nvl, O_APPS, varray,
			    count);
			mgmt_free_str_arr(varray, count);
		}
	}

	return (st);
}

int
mms_mgmt_modify_mpool(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	char		**varray = NULL;
	int		count = 0;
	int		i;
	char		cmd[8192];
	char		tid[64];
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	char		*mpool;
	nvlist_t	*cgattrs = NULL;
	nvlist_t	*new = NULL;
	nvpair_t	*nvp;
	char		*val;
	boolean_t	found;

	/* get list of apps, if new list != old list, update */

	if (!mgmt_chk_auth("solaris.mms.modify")) {
		return (EACCES);
	}

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &mpool);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	varray = var_to_array(nvl, O_APPS, &count);
	if (varray == NULL) {
		/* error or nothing to do? */
		return (0);
	}

	/* get list of already-established apps */
	(void) mms_gen_taskid(tid);

	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] reportmode[namevalue] "
	    "match[streq(CARTRIDGEGROUPAPPLICATION.'CartridgeGroupName' '%s')] "
	    "report[CARTRIDGEGROUPAPPLICATION.'ApplicationName'];",
	    tid, mpool);

	if (session == NULL) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			goto done;
		}
		sessp = sess;
	}

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "modify cartridgegroup",
	    &response);
	if (st == 0) {
		st = mmp_get_nvattrs("ApplicationName", B_FALSE, response,
		    &cgattrs);
		mms_free_rsp(response);
	}
	if (st != 0) {
		goto done;
	}

	/* see if we need to add any apps */
	for (i = 0; i < count; i++) {
		if (!varray[i] || (strlen(varray[i]) == 0) ||
		    (strcasecmp(varray[i], "none") == 0) ||
		    (strcasecmp(varray[i], "all") == 0)) {
			continue;
		}

		if (!nvlist_exists(cgattrs, varray[i])) {
			if (!new) {
				(void) nvlist_alloc(&new, NV_UNIQUE_NAME, 0);
				(void) nvlist_add_string(new, O_NAME, mpool);
			}

			(void) nvlist_add_string(new, O_APPS, varray[i]);
			st = mms_add_object(sessp, "CARTRIDGEGROUPAPPLICATION",
			    cgappopts, new, errs);
			if (st != 0) {
				break;
			}
		}
	}

	/* and if we need to remove any */
	nvp = NULL;
	while ((nvp = nvlist_next_nvpair(cgattrs, nvp)) != NULL) {
		val = nvpair_name(nvp);
		if (!val) {
			/* can't happen? */
			continue;
		}

		found = B_FALSE;

		for (i = 0; i < count; i++) {
			if (strcmp(val, varray[i]) == 0) {
				found = B_TRUE;
				break;
			}
		}

		if (found) {
			continue;
		}

		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "delete task['%s'] type[CARTRIDGEGROUPAPPLICATION] "
		    "match[and "
		    "(streq(CARTRIDGEGROUPAPPLICATION.'CartridgeGroupName' "
		    "'%s') "
		    "streq(CARTRIDGEGROUPAPPLICATION.'ApplicationName' "
		    "'%s'))];",
		    tid, mpool, val);

		st = mms_mgmt_send_cmd(sessp, tid, cmd, "modify cartridgegroup",
		    &response);
		if (st != 0) {
			break;
		}
	}

done:

	if (new) {
		nvlist_free(new);
	}

	if (cgattrs) {
		nvlist_free(cgattrs);
	}

	mgmt_free_str_arr(varray, count);

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

/*
 * verify no cartridges 'allocated'
 *   force?  remove cart anyway
 * remove all carts
 * remove cartridgegroupapplications
 * remove cartridgegroup
 */
int
mms_mgmt_remove_mpool(void *session, char *mpool, boolean_t force,
    nvlist_t *errs)
{
	int		st;
	nvlist_t	*nvl = NULL;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	char		tid[64];
	char		cmd[8192];

	if (!mpool) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.delete")) {
		return (EACCES);
	}

	st = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0);
	if (st != 0) {
		return (st);
	}

	(void) nvlist_add_string(nvl, O_NAME, mpool);
	(void) nvlist_add_boolean_value(nvl, O_FORCE, force);
	(void) nvlist_add_string(nvl, O_VOLUMES, "*");

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			nvlist_free(nvl);
			return (st);
		}
		sessp = sess;
	}

	st = mms_mgmt_remove_cartridges(sessp, nvl, errs);

	if (st != 0) {
		goto done;
	}

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "delete task['%s'] type[CARTRIDGEGROUPAPPLICATION] "
	    "match[streq"
	    "(CARTRIDGEGROUPAPPLICATION.'CartridgeGroupName' '%s')];",
	    tid, mpool);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "remove cartridgegroup",
	    &response);
	if (st != 0) {
		goto done;
	}

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "delete task['%s'] type[CARTRIDGEGROUP] "
	    "match[streq(CARTRIDGEGROUP.'CartridgeGroupName' '%s')];",
	    tid, mpool);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "remove cartridgegroup",
	    &response);
	if (st != 0) {
		goto done;
	}

done:
	if (nvl) {
		nvlist_free(nvl);
	}

	return (st);
}

int
mms_mgmt_add_cartridges(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	char		*mpool;
	char		**volarr = NULL;
	char		*libname;
	char		*mtype = NULL;
	int		count;
	int		i;
	char		tid[64];
	char		cmd[8192];
	void		*sess = NULL;
	void		*sessp = session;
	mms_list_t	lib_list;
	mms_acslib_t	*lsm;
	char		*volstr;
	mms_list_t	vol_list;
	mms_acscart_t	*vol;
	size_t		len = 0;
	void		*response;
	nvlist_t	*cart = NULL;
	char		*volxml = "</token><token>volume</token><token>";

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.media")) {
		return (EACCES);
	}

	(void) memset(&vol_list, 0, sizeof (mms_list_t));

	st = nvlist_lookup_string(nvl, O_NAME, &mpool);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	st = nvlist_lookup_string(nvl, O_MMSLIB, &libname);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_MMSLIB, st);
		return (st);
	}

	st = nvlist_lookup_string(nvl, O_VOLTYPE, &mtype);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_MTYPE, st);
		return (st);
	}

	volarr = var_to_array(nvl, O_VOLUMES, &count);
	if (volarr == NULL) {
		st = ENOENT;
		MGMT_ADD_OPTERR(errs, O_VOLUMES, st);
		return (st);
	}

	if (session == NULL) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			mgmt_free_str_arr(volarr, count);
			return (st);
		}
		sessp = sess;
	}

	/* get the library information */
	st = mms_get_library(sessp, B_FALSE, &lib_list);
	if (st != 0) {
		goto done;
	}

	mms_list_foreach(&lib_list, lsm) {
		if (strcmp(lsm->name, libname) == 0) {
			break;
		}
	}
	if (lsm == NULL) {
		st = EINVAL;
		MGMT_ADD_ERR(errs, O_MMSLIB, st);
		goto done;
	}

	/* get the volume info from the ACSLS server */
	for (i = 0; i < count; i++) {
		len += strlen(volarr[i]) + strlen(volxml);

	}
	len++;	/* include trailing nul */
	volstr = malloc(len);
	if (volstr == NULL) {
		st = ENOMEM;
		goto done;
	}
	volstr[0] = '\0';
	for (i = 0; i < count; i++) {
		if (i > 0) {
			(void) strlcat(volstr, volxml, len);
		}
		(void) strlcat(volstr, volarr[i], len);
	}

	st = get_acs_volumes(lsm->acshost, volstr, &vol_list);
	free(volstr);

	if (st != 0) {
		goto done;
	}

	/* requested volumes don't appear in the returned list */
	if (vol_list.list_size == 0) {
		st = ENOENT;
		for (i = 0; i < count; i++) {
			if (volarr[i]) {
				MGMT_ADD_ERR(errs, volarr[i], st);
			}
		}
		goto done;
	}

	/* list to be used when creating PARTITIONs */
	st = nvlist_alloc(&cart, NV_UNIQUE_NAME, 0);
	if (st != 0) {
		goto done;
	}
	/* pre-populate with constant values */
	(void) nvlist_add_string(cart, O_MMSLIB, libname);

	for (i = 0; i < count; i++) {
		mms_list_foreach(&vol_list, vol) {
			if (strcmp(vol->label, volarr[i]) == 0) {
				break;
			}
		}
		if (vol == NULL) {
			/* should never happen */
			continue;
		}

		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "create task['%s'] type[CARTRIDGE] "
		    "set[CARTRIDGE.'CartridgePCL' '%s'] "
		    "set[CARTRIDGE.'CartridgeTypeName' '%s'] "
		    "set[CARTRIDGE.'CartridgeGroupName' '%s'] "
		    "set[CARTRIDGE.'LibraryName' '%s']; ",
		    tid, vol->label, mtype, mpool, libname);

		st = mms_mgmt_send_cmd(sessp, tid, cmd, "add volume",
		    &response);
		if (st != 0) {
			break;
		}
		/* create the PARTITION */
		(void) nvlist_add_string(cart, O_NAME, vol->label);
		st = mms_mgmt_create_partition(sessp, cart, errs);
		if (st != 0) {
			break;
		}
	}

done:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	free_acslib_list(&lib_list);
	mms_list_free_and_destroy(&vol_list, free);
	mgmt_free_str_arr(volarr, count);

	if (cart) {
		nvlist_free(cart);
	}

	return (st);
}

int
mms_mgmt_create_voltype(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	void		*sessp = session;
	void		*sess = NULL;
	void		*response = NULL;
	char		tid[64];
	char		cmd[8192];
	nvlist_t	*stypes = NULL;
	nvlist_t	*ctypes = NULL;
	nvlist_t	*mnvl = NULL;
	char		*in_ty = NULL;
	char		*in_sz = NULL;
	char		*in_media = NULL;
	char		*val;

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.media")) {
		return (EACCES);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &in_ty);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	st = nvlist_lookup_string(nvl, O_SIZE, &in_sz);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_SIZE, st);
		return (st);
	}

	st = nvlist_lookup_string(nvl, O_MTYPE, &in_media);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_MTYPE, st);
		return (st);
	}

	if (!sessp) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	/* see if we've already got this type */
	st = mms_mgmt_show_cartridge_type(sessp, in_ty, &stypes);
	if (st != 0) {
		goto done;
	}

	/* we'll get an empty list if it isn't already defined */
	st = nvlist_lookup_nvlist(stypes, in_ty, &mnvl);
	if (st == 0) {
		/* make sure all attributes match */
		val = NULL;
		(void) nvlist_lookup_string(mnvl, "CartridgeTypeMediaLength",
		    &val);
		if ((!val) || (strcmp(val, in_sz) != 0)) {
			st = EINVAL;
			MGMT_ADD_OPTERR(errs, O_SIZE, st);
			goto done;
		}

		val = NULL;
		(void) nvlist_lookup_string(mnvl, "CartridgeShapeName", &val);
		if ((!val) || (strcmp(val, in_media) != 0)) {
			st = EINVAL;
			MGMT_ADD_OPTERR(errs, O_MTYPE, st);
			goto done;
		}

		/* all matched, nothing to do */
		goto done;
	}

	nvlist_free(stypes);
	stypes = NULL;

	st = mms_mgmt_list_supported_types(sessp, &stypes);
	if (st != 0) {
		MGMT_ADD_ERR(errs, "internal error", st);
		goto done;
	}

	st = nvlist_lookup_nvlist(stypes, "CARTRIDGE", &ctypes);
	if (st != 0) {
		MGMT_ADD_ERR(errs, "internal error", st);
		goto done;
	}

	/* make sure requested media type is supported */
	st = nvlist_lookup_nvlist(ctypes, in_media, &mnvl);
	if (st != 0) {
		if (st == ENOENT) {
			st = EOPNOTSUPP;
		}
		MGMT_ADD_ERR(errs, in_media, st);
		goto done;
	}

	/* create the new type */
	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "create task['%s'] type[CARTRIDGETYPE] "
	    "set[CARTRIDGETYPE.'CartridgeTypeName' '%s'] "
	    "set[CARTRIDGETYPE.'CartridgeTypeNumberSides' '1'] "
	    "set[CARTRIDGETYPE.'CartridgeTypeMediaType' 'data'] "
	    "set[CARTRIDGETYPE.'CartridgeTypeMediaLength' '%s'] "
	    "set[CARTRIDGETYPE.'CartridgeShapeName' '%s'];",
	    tid, in_ty, in_sz, in_media);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "create cartridge type",
	    &response);

done:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	if (stypes) {
		nvlist_free(stypes);
	}

	return (st);
}

static int
voltype_in_use(void *session, char *voltype)
{
	int		st;
	void		*sessp = session;
	void		*sess = NULL;
	void		*response = NULL;
	char		tid[64];
	char		cmd[8192];
	nvlist_t	*clist = NULL;

	if (!voltype) {
		return (MMS_MGMT_NOARG);
	}

	/* first, check to see if any cartridges are using this type */
	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] reportmode[namevalue unique] "
	    "report[CARTRIDGE.'CartridgeTypeName'] "
	    "match[streq(CARTRIDGETYPE.'CartridgeTypeName' '%s')];",
	    tid, voltype);

	if (!sessp) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "check voltype", &response);
	if (st == 0) {
		st = mmp_get_nvattrs("CartridgeTypeName", B_FALSE,
		    response, &clist);
		mms_free_rsp(response);
	}

	if (st == 0) {
		if (nvlist_exists(clist, voltype)) {
			st = EBUSY;
		}
	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	if (clist) {
		nvlist_free(clist);
	}

	return (st);
}

int
mms_mgmt_remove_voltype(void *session, char *voltype)
{
	int		st;
	void		*sessp = session;
	void		*sess = NULL;
	void		*response = NULL;
	char		tid[64];
	char		cmd[8192];

	if (!voltype) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.media")) {
		return (EACCES);
	}

	if (!sessp) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	/* first, check to see if any cartridges are using this type */
	st = voltype_in_use(sessp, voltype);

	if (st == 0) {
		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "delete task['%s'] type[CARTRIDGETYPE] "
		    "match[streq(CARTRIDGETYPE.'CartridgeTypeName' '%s')];",
		    tid, voltype);

		st = mms_mgmt_send_cmd(sessp, tid, cmd, "delete voltype",
		    &response);
	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

int
mms_mgmt_modify_voltype(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	void		*sessp = session;
	void		*sess = NULL;
	void		*response = NULL;
	char		tid[64];
	char		cmd[8192];
	char		buf[1024];
	char		*vtype = NULL;
	char		*sz = NULL;
	char		*mtype = NULL;

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.media")) {
		return (EACCES);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &vtype);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	if (!sessp) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	/* first, check to see if any cartridges are using this type */
	st = voltype_in_use(sessp, vtype);
	if (st != 0) {
		goto done;
	}

	(void) nvlist_lookup_string(nvl, O_MTYPE, &mtype);
	(void) nvlist_lookup_string(nvl, O_SIZE, &sz);

	if (!sz && !mtype) {
		goto done;
	}

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "attribute task['%s'] type[CARTRIDGETYPE] "
	    "match[streq(CARTRIDGETYPE.'CartridgeTypeName' '%s')]",
	    tid);

	if (sz) {
		(void) snprintf(buf, sizeof (buf),
		    " set[CARTRIDGETYPE.'CartridgeTypeMediaLength' '%s']",
		    sz);
		(void) strlcat(cmd, buf, sizeof (cmd));
	}

	if (mtype) {
		(void) snprintf(buf, sizeof (buf),
		    "set[CARTRIDGETYPE.'CartridgeShapeName' '%s'];",
		    mtype);
		(void) strlcat(cmd, buf, sizeof (cmd));
	}

	(void) strlcat(cmd, ";", sizeof (cmd));

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "delete voltype", &response);

done:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

int
mms_mgmt_show_cartridge_type(void *session, char *voltype, nvlist_t **nvl)
{
	int		st;
	void		*sessp = session;
	void		*sess = NULL;
	void		*response = NULL;
	char		tid[64];
	char		cmd[8192];
	char		buf[1024];

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	/* if voltype is NULL, return a list of all found */
	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] reportmode[namevalue] "
	    "report[CARTRIDGETYPE]", tid);

	if (voltype != NULL) {
		(void) snprintf(buf, sizeof (buf),
		    " match[streq (CARTRIDGETYPE.'CartridgeTypeName' '%s')]",
		    voltype);
		(void) strlcat(cmd, buf, sizeof (cmd));
	}

	(void) strlcat(cmd, ";", sizeof (cmd));

	if (!sessp) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "list cartridgetype",
	    &response);
	if (st == 0) {
		st = mmp_get_nvattrs("voltype", B_TRUE, response, nvl);
		mms_free_rsp(response);
	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}


int
mms_mgmt_remove_cartridges(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	char		*mpool;
	boolean_t	force = B_FALSE;
	nvlist_t	*vols = NULL;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	nvpair_t	*nvp;
	nvlist_t	*vlist;
	char		*val;
	char		*vname;
	boolean_t	skip = B_FALSE;
	char		tid[64];
	char		cmd[8192];
	int		skipped = 0;
	nvlist_t	*pclnv = NULL;
	char		*lib = NULL;

	if (!mgmt_chk_auth("solaris.mms.media")) {
		return (EACCES);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &mpool);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	if (!nvlist_exists(nvl, O_VOLUMES)) {
		/* nothing to remove */
		return (0);
	}

	(void) nvlist_lookup_string(nvl, O_MMSLIB, &lib);

	(void) nvlist_lookup_boolean_value(nvl, O_FORCE, &force);

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	/* tell the list function not to translate the var names */
	(void) nvlist_add_boolean_value(nvl, "cvt_mmp", B_FALSE);

	st = mms_mgmt_list_vols(sessp, nvl, &vols);
	if (st != 0) {
		goto done;
	}

	/* Create a temporary nvlist to store PCL & Library */
	st = nvlist_alloc(&pclnv, NV_UNIQUE_NAME, 0);
	if (st != 0) {
		goto done;
	}
	(void) nvlist_add_string(pclnv, O_MMSLIB, lib);

	/* vols is now a list of the volumes we're supposed to remove */
	nvp = NULL;

	while ((nvp = nvlist_next_nvpair(vols, nvp)) != NULL) {
		st = nvpair_value_nvlist(nvp, &vlist);
		if (st != 0) {
			continue;
		}
		st = nvlist_lookup_string(vlist, "CartridgePCL", &vname);
		if (st != 0) {
			continue;
		}

		skip = B_FALSE;

		if (!force) {
			st = nvlist_lookup_string(vlist, "CartridgeState",
			    &val);
			if (st != 0) {
				/* don't remove it if we can't tell state */
				continue;
			}
			if (strcmp(val, "allocated") == 0) {
				/* fail */
				MGMT_ADD_ERR(errs, vname, EBUSY);
				skipped++;
				skip = B_TRUE;
			}
		}

		if (skip) {
			continue;
		}

		(void) nvlist_add_string(pclnv, O_NAME, vname);

		/* remove partitions and vols if necessary */
		st = mms_mgmt_remove_partition(sessp, pclnv, errs);
		if (st != 0) {
			MGMT_ADD_ERR(errs, vname, st);
			continue;
		}

		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "delete task['%s'] type[CARTRIDGE] "
		    "match[and (streq(CARTRIDGE.'CartridgeGroupName' '%s') "
		    "streq(CARTRIDGE.'CartridgePCL' '%s'))];",
		    tid, mpool, vname);

		st = mms_mgmt_send_cmd(sessp, tid, cmd, "delete cartridge",
		    &response);
		if (st != 0) {
			MGMT_ADD_ERR(errs, vname, st);
			continue;
		}

		/* check for disk cartridges, remove the on-disk files if yes */
		st = nvlist_lookup_string(vlist, "CartridgeTypeName", &val);
		if (st == 0) {
			if (strcmp(val, "DISK") == 0) {
				char	*mntp = NULL;
				char	*rpath = NULL;

				(void) nvlist_lookup_string(vlist,
				    "CartridgeMountPoint", &mntp);
				(void) nvlist_lookup_string(vlist,
				    "CartridgePath", &rpath);
				if (!mntp || !rpath) {
					MGMT_ADD_ERR(errs, "bad cartridge path",
					    ENOENT);
					continue;
				}
				(void) snprintf(cmd, sizeof (cmd), "%s/%s",
				    mntp, rpath);
				st = mgmt_delete_dkvol(cmd, errs);
				if (st != 0) {
					MGMT_ADD_ERR(errs, cmd, st);
				}
			}
		}
	}

	if (pclnv) {
		nvlist_free(pclnv);
	}


done:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	if (vols) {
		nvlist_free(vols);
	}

	if ((st == 0) && skipped) {
		st = MMS_MGMT_CARTRIDGE_INUSE;
	}

	return (st);
}

/*
 *  list by mpool, by mpool&cartridge id or all
 */
int
mms_mgmt_list_vols(void *session, nvlist_t *nvl, nvlist_t **vol_list)
{
	int		st;
	char		*mpool = NULL;
	char		**volarr = NULL;
	int		count;
	char		tid[64];
	char		cmd[8192];
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	boolean_t	all = B_TRUE;
	int		i;
	boolean_t	cvt_mmp = B_TRUE;
	char		*key = "volid";

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	(void) nvlist_lookup_string(nvl, O_NAME, &mpool);

	st = nvlist_lookup_boolean_value(nvl, "cvt_mmp", &cvt_mmp);
	if (st == ENOENT) {
		cvt_mmp = B_TRUE;
	} else if (cvt_mmp == B_FALSE) {
		key = "CartridgePCL";
	}
	st = 0;

	volarr = var_to_array(nvl, O_VOLUMES, &count);
	if (volarr != NULL) {
		/* special case for all volumes */
		if (strcmp(volarr[0], "*") != 0) {
			all = B_FALSE;
		}
	}

	if (*vol_list == NULL) {
		st = nvlist_alloc(vol_list, NV_UNIQUE_NAME, 0);
		if (st != 0) {
			goto done;
		}

	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	/*
	 * get the cartridges from MMS.
	 */
	if (all) {
		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "show task['%s'] reportmode[namevalue] "
		    "report[CARTRIDGE] ", tid);

		if (!mpool) {
			(void) strlcat(cmd, ";", sizeof (cmd));
		} else {
			(void) strlcat(cmd,
			    "match[streq(CARTRIDGE.'CartridgeGroupName' '",
			    sizeof (cmd));
			(void) strlcat(cmd, mpool, sizeof (cmd));
			(void) strlcat(cmd, "')];", sizeof (cmd));
		}
		st = mms_mgmt_send_cmd(sessp, tid, cmd, "show cartridges",
		    &response);
		if (st == 0) {
			st = mmp_get_nvattrs(key, cvt_mmp, response,
			    vol_list);
			mms_free_rsp(response);
		}
	} else {
		for (i = 0; i < count; i++) {
			(void) mms_gen_taskid(tid);
			(void) snprintf(cmd, sizeof (cmd),
			    "show task['%s'] reportmode[namevalue] "
			    "report[CARTRIDGE] ", tid);

			if (mpool) {
				(void) strlcat(cmd, "match[and (streq(",
				    sizeof (cmd));
				(void) strlcat(cmd,
				    "CARTRIDGE.'CartridgeGroupName' '",
				    sizeof (cmd));
				(void) strlcat(cmd, mpool, sizeof (cmd));
				(void) strlcat(cmd, "') ", sizeof (cmd));
			}
			(void) strlcat(cmd, "streq(CARTRIDGE.'CartridgePCL' '",
			    sizeof (cmd));
			(void) strlcat(cmd, volarr[i], sizeof (cmd));
			(void) strlcat(cmd, "')", sizeof (cmd));
			if (mpool) {
				(void) strlcat(cmd, ")", sizeof (cmd));
			}
			(void) strlcat(cmd, "];", sizeof (cmd));

			st = mms_mgmt_send_cmd(sessp, tid, cmd,
			    "show cartridges", &response);
			if (st == 0) {
				st = mmp_get_nvattrs(key, cvt_mmp,
				    response, vol_list);
				mms_free_rsp(response);
			} else {
				break;
			}
		}
	}

	if (st == 0) {
		mgmt_filter_results(nvl, *vol_list);
	}

done:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	mgmt_free_str_arr(volarr, count);

	return (st);
}

int
mms_mgmt_show_mpool(void *session, nvlist_t *nvl, nvlist_t **pools)
{
	int		st;
	char		**names = NULL;
	int		count;
	char		tid[64];
	char		cmd[8192];
	char		buf[1024];
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	int		i;
	char		*key = O_MPOOL;
	int		vcount = 0;
	uint64_t	poolsz = 0;
	uint64_t	vsz = 0;
	nvlist_t	*vols = NULL;
	nvlist_t	*nva = NULL;
	nvpair_t	*nvp = NULL;
	nvlist_t	*nvav = NULL;
	nvpair_t	*nvpv = NULL;
	char		*val;

	if (!nvl || !pools) {
		return (MMS_MGMT_NOARG);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	names = var_to_array(nvl, O_NAME, &count);

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] reportmode[namevalue] "
	    "report[CARTRIDGEGROUP]",
	    tid);

	if (count > 1) {
		(void) strlcat(cmd, "match[or", sizeof (cmd));
	} else if (count == 1) {
		(void) strlcat(cmd, "match[", sizeof (cmd));
	}
	for (i = 0; i < count; i++) {
		(void) snprintf(buf, sizeof (buf),
		    " streq (CARTRIDGEGROUP.'%s' '%s')",
		    key, names[i]);
		(void) strlcat(cmd, buf, sizeof (cmd));
	}
	if (count > 0) {
		(void) strlcat(cmd, "];", sizeof (cmd));
	} else {
		(void) strlcat(cmd, ";", sizeof (cmd));
	}

	*pools = NULL;
	st = mms_mgmt_send_cmd(sessp, tid, cmd, "show mpool", &response);
	if (st == 0) {
		st = mmp_get_nvattrs(key, B_TRUE, response, pools);
		mms_free_rsp(response);
	}

	if (st != 0) {
		goto done;
	}

	while ((nvp = nvlist_next_nvpair(*pools, nvp)) != NULL) {
		st = nvpair_value_nvlist(nvp, &nva);
		if (st != 0) {
			continue;
		}
		val = nvpair_name(nvp);

		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "show task['%s'] reportmode[namevalue] "
		    "report[CARTRIDGE.'CartridgePCL' "
		    "CARTRIDGETYPE.'CartridgeShapeName' "
		    "CARTRIDGETYPE.'CartridgeTypeMediaLength' "
		    "PARTITION.'PartitionSize'] "
		    "match[streq(CARTRIDGEGROUP.'CartridgeGroupName' '%s')];",
		    tid, val);

		st = mms_mgmt_send_cmd(sessp, tid, cmd, "mpool vols",
		    &response);
		if (st == 0) {
			st = mmp_get_nvattrs("CartridgePCL", B_FALSE,
			    response, &vols);
			mms_free_rsp(response);
		}
		if (st != 0) {
			continue;
		}

		nvpv = NULL;
		cmd[0] = '\0';
		poolsz = 0;
		vcount = 0;

		while ((nvpv = nvlist_next_nvpair(vols, nvpv)) != NULL) {
			st = nvpair_value_nvlist(nvpv, &nvav);
			if (st != 0) {
				continue;
			}
			vcount++;

			st = nvlist_lookup_string(nvav, "CartridgeShapeName",
			    &val);
			if (st == 0) {
				(void) snprintf(buf, sizeof (buf), "%s,", val);
				if (strstr(cmd, buf) == NULL) {
					(void) strlcat(cmd, buf, sizeof (cmd));
				}
			}
			st = nvlist_lookup_string(nvav, "PartitionSize",
			    &val);
			if (st == 0) {
				(void) do_val_mms_size(val, &vsz);
				poolsz += vsz;
			} else {
				st = nvlist_lookup_string(nvav,
				    "CartridgeTypeMediaLength", &val);
				if (st == 0) {
					(void) do_val_mms_size(val, &vsz);
					poolsz += vsz;
				}
			}

		}
		nvlist_free(vols);
		vols = NULL;
		(void) snprintf(buf, sizeof (buf), "%lu", poolsz);
		(void) nvlist_add_string(nva, "total size", buf);
		(void) snprintf(buf, sizeof (buf), "%d", vcount);
		(void) nvlist_add_string(nva, "total volumes", buf);
		val = strrchr(cmd, ',');
		if (val != NULL) {
			*val = NULL;
		}
		(void) nvlist_add_string(nva, "voltype", cmd);
	}

	mgmt_filter_results(nvl, *pools);

	/* TODO:  list of cartridges + sum space used/free/avail */

done:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	if (names) {
		mgmt_free_str_arr(names, count);
	}

	return (st);
}

int
mms_mgmt_create_partition(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	char		tid[64];
	char		cmd[8192];
	char		*pcl = NULL;
	char		*lib = NULL;
	nvlist_t	*carts = NULL;
	nvlist_t	*this = NULL;

	if (!mgmt_chk_auth("solaris.mms.media")) {
		return (EACCES);
	}

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &pcl);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	st = nvlist_lookup_string(nvl, O_MMSLIB, &lib);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_MMSLIB, st);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] reportmode[namevalue] report[CARTRIDGE] "
	    "match[and (streq(CARTRIDGE.'LibraryName' '%s') "
	    "streq(CARTRIDGE.'CartridgePCL' '%s'))];",
	    tid, lib, pcl);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "show cartridge", &response);
	if (st == 0) {
		st = mmp_get_nvattrs("CartridgePCL", B_FALSE, response, &carts);
		mms_free_rsp(response);
	}

	st = nvlist_lookup_nvlist(carts, pcl, &this);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, pcl, st);
		goto done;
	}

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "create task['%s'] type[PARTITION] "
	    "set[PARTITION.'PartitionName' 'part1'] "
	    "set[PARTITION.'SideName' 'side 1'] "
	    "set[PARTITION.'CartridgePCL' '%s'] "
	    "set[PARTITION.'LibraryName' '%s'];",
	    tid, pcl, lib);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "create partition", &response);

done:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	if (carts) {
		nvlist_free(carts);
	}

	return (st);
}

int
mms_mgmt_remove_partition(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	char		tid[64];
	char		cmd[8192];
	char		*pcl = NULL;
	char		*lib = NULL;
	nvlist_t	*carts = NULL;
	nvlist_t	*vols = NULL;

	if (!mgmt_chk_auth("solaris.mms.media")) {
		return (EACCES);
	}

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &pcl);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	st = nvlist_lookup_string(nvl, O_MMSLIB, &lib);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_MMSLIB, st);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	/* check for existing volumes */
	st = mgmt_show_mmvols(sessp, pcl, lib, &vols);
	if (st != 0) {
		goto done;
	}

	if (vols) {
		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "delete task['%s'] type[VOLUME] "
		    "match[and (streq(PARTITION.'CartridgePCL' '%s') "
		    "streq(PARTITION.'LibraryName' '%s'))];",
		    tid, pcl, lib);

		st = mms_mgmt_send_cmd(sessp, tid, cmd, "delete volume",
		    &response);
		if (st != 0) {
			goto done;
		}
	}

	/* now the partitions */
	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "delete task['%s'] type[PARTITION] "
	    "match[and (streq (PARTITION.'LibraryName' '%s') "
	    "streq(PARTITION.'CartridgePCL' '%s'))];",
	    tid, lib, pcl);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "delete partition",
	    &response);

done:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	if (carts) {
		nvlist_free(carts);
	}

	if (vols) {
		nvlist_free(vols);
	}

	return (st);
}

int
mms_mgmt_label_multi(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	int		rst = 0;
	void		*sess = NULL;
	void		*sessp = session;
	char		*pass = NULL;
	char		*app = NULL;
	char		*inst = NULL;
	char		**varr = NULL;
	int		count = 0;
	int		i;

	if (!mgmt_chk_auth("solaris.mms.media")) {
		return (EACCES);
	}

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	varr = var_to_array(nvl, O_NAME, &count);
	if (!varr) {
		st = ENOENT;
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	if (!session) {
		(void) nvlist_lookup_string(nvl, O_APPS, &app);
		(void) nvlist_lookup_string(nvl, "instance", &inst);
		(void) nvlist_lookup_string(nvl, O_MMPASS, &pass);

		st = create_mm_clnt(app, inst, pass, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	for (i = 0; i < count; i++) {
		(void) nvlist_add_string(nvl, O_NAME, varr[i]);

		st = mms_mgmt_label_vol(sessp, nvl, errs);
		if (st != 0) {
			/* save return status */
			if (rst == 0) {
				rst = st;
			}
		}
	}

	/* set 'name' back to the way it started */
	(void) nvlist_add_string_array(nvl, O_NAME, varr, count);

	mgmt_free_str_arr(varr, count);

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (rst);
}

int
mms_mgmt_label_vol(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	char		tid[64];
	char		cmd[8192];
	char		buf[1024];
	char		*pcl;
	char		*lib;
	char		*app;
	char		*inst = NULL;
	char		*pass = NULL;
	nvlist_t	*attrs = NULL;
	nvpair_t	*nva;
	boolean_t	force = B_FALSE;

	if (!mgmt_chk_auth("solaris.mms.media")) {
		return (EACCES);
	}

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &pcl);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	st = nvlist_lookup_string(nvl, O_MMSLIB, &lib);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_MMSLIB, st);
		return (st);
	}

	st = nvlist_lookup_string(nvl, O_APPS, &app);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_APPS, st);
		return (st);
	}

	(void) nvlist_lookup_boolean_value(nvl, O_FORCE, &force);

	if (!session) {
		(void) nvlist_lookup_string(nvl, "instance", &inst);
		(void) nvlist_lookup_string(nvl, O_MMPASS, &pass);

		st = create_mm_clnt(app, inst, pass, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	/* check if partition for cartridge exists.  if no, create */
	st = mgmt_show_partition(sessp, pcl, lib, &attrs);

	if (st != 0) {
		goto done;
	}

	if (attrs == NULL) {
		st = mms_mgmt_create_partition(sessp, nvl, errs);
	} else {
		nva = nvlist_next_nvpair(attrs, NULL);
		if (nva) {
			if (nvlist_next_nvpair(attrs, nva)) {
				/* got more than 1, not supported */
				st = MMS_MGMT_ERR_PARTITION_NOT_UNIQUE;
				MGMT_ADD_ERR(errs, pcl, st);
				goto done;
			}
		}
	}

	nvlist_free(attrs);
	attrs = NULL;

	/* check for existing volumes */
	st = mgmt_show_mmvols(sessp, pcl, lib, &attrs);
	if (st != 0) {
		goto done;
	}

	if (!attrs) {
		/* create a volume */
		(void) snprintf(buf, sizeof (buf), "%s_%s", lib, pcl);
		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "allocate task['%s'] newvolname['%s'] "
		    "who['%s'] "
		    "match[and (streq(CARTRIDGE.'CartridgePCL' '%s') "
		    "streq(CARTRIDGE.'LibraryName' '%s'))];",
		    tid, buf, app, pcl, lib);

		st = mms_mgmt_send_cmd(sessp, tid, cmd, "create volume",
		    &response);
		if (st != 0) {
			MGMT_ADD_ERR(errs, pcl, st);
			goto done;
		}
	} else if (!force) {
		st = MMS_MGMT_CARTRIDGE_INUSE;
		MGMT_ADD_ERR(errs, pcl, st);
		goto done;
	}

	/* filename is 17 spaces - tells MM to re-init volume */
	(void) nvlist_add_string(nvl, "filename", label_fname);

	/* ok, mount with appropriate options */
	st = mms_mgmt_mount_vol(sessp, nvl, errs);

	if (st == 0) {
		/* label is a quick mount/unmount */
		st = mms_mgmt_unmount_vol(nvl, errs);
	}

done:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	if (attrs) {
		nvlist_free(attrs);
	}

	return (st);
}

static int
mgmt_show_partition(void *session, char *pcl, char *library, nvlist_t **parts)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	char		tid[64];
	char		cmd[8192];
	nvlist_t	*plist = NULL;
	nvpair_t	*nvp = NULL;

	if (!pcl || !library || !parts) {
		return (MMS_MGMT_NOARG);
	}

	st = nvlist_alloc(&plist, NV_UNIQUE_NAME, 0);
	if (st != 0) {
		return (st);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	*parts = NULL;

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] report[PARTITION] reportmode[namevalue] "
	    "match[and (streq(PARTITION.'CartridgePCL' '%s') "
	    "streq(PARTITION.'LibraryName' '%s'))];",
	    tid, pcl, library);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "show partition", &response);
	if (st == 0) {
		st = mmp_get_nvattrs("PartitionName", B_FALSE, response,
		    &plist);
		mms_free_rsp(response);
	}

	if (st == 0) {
		nvp = nvlist_next_nvpair(plist, NULL);
		if (nvp) {
			*parts = plist;
		} else {
			nvlist_free(plist);
		}
	}

	return (st);
}

static int
mgmt_show_mmvols(void *session, char *pcl, char *library, nvlist_t **vols)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	char		tid[64];
	char		cmd[8192];
	nvlist_t	*vlist = NULL;
	nvpair_t	*nvp = NULL;

	if (!pcl || !library || !vols) {
		return (MMS_MGMT_NOARG);
	}

	st = nvlist_alloc(&vlist, NV_UNIQUE_NAME, 0);
	if (st != 0) {
		return (st);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] report[VOLUME] reportmode[namevalue] "
	    "match[and (streq(PARTITION.'CartridgePCL' '%s') "
	    "streq(PARTITION.'LibraryName' '%s'))];",
	    tid, pcl, library);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "show volume", &response);
	if (st == 0) {
		st = mmp_get_nvattrs("VolumeName", B_FALSE, response, &vlist);
		mms_free_rsp(response);
	}

	if (st == 0) {
		nvp = nvlist_next_nvpair(vlist, NULL);
		if (!nvp) {
			/* nothing there */
			nvlist_free(vlist);
			*vols = NULL;
		} else {
			*vols = vlist;
		}
	}

	return (st);
}

static int
call_mmsmnt(door_arg_t *arg)
{
	int		st;
	int		doorfd = -1;
	int		count;
	/* LINTED [warning: pointer cast may result in improper alignment] */
	mmsmnt_arg_t	*mntarg = (mmsmnt_arg_t *)arg->rbuf;
	int		saverr;
	timespec_t	sleepfor = {5, 0};	/* 5 seconds */
	char		*cmd[2];

	if (arg == NULL) {
		return (MMS_MGMT_NOARG);
	}

	cmd[0] = MMSSBINDIR"/mmsmnt";
	cmd[1] = NULL;

	/* will get overwritten with correct status as appropriate */
	st = ENOTCONN;

	/* try 5 times to get connected, then give up */
	for (count = 0; count < 5; count++) {
		doorfd = open(mmsmntdoor, O_RDWR);
		if (doorfd == -1) {
			if (errno == ENOENT) {
			/* server is not running.  Try to start it */
				(void) exec_mgmt_cmd(NULL, NULL, 0, 0, B_TRUE,
				    cmd);
			} else {
				st = errno;
				return (st);
			}
		}

		/*
		 * try to contact the server - if door_call successful,
		 * status will be set by the server
		 */
		st = door_call(doorfd, arg);
		saverr = errno;

		if (st == 0) {
			/* connected ok, return error from daemon */
			st = mntarg->st;
			break;
		}

		(void) close(doorfd);
		doorfd = -1;

		if (saverr == EBADF) {
			/*
			 * server was not running when we opened
			 * the door file
			 */
			(void) exec_mgmt_cmd(NULL, NULL, 0, 0, B_TRUE, cmd);
			/* give the server a chance to start */
			(void) nanosleep(&sleepfor, NULL);
		} else if ((saverr != EAGAIN) && (saverr != EINTR)) {
			/* A non-recoverable error occurred */
			st = saverr;
			mms_trace(MMS_ERR,
			    "Could not contact the mmsmnt process, %d", st);
			return (st);
		}
	}

	if (doorfd != -1) {
		(void) close(doorfd);
	}

	return (st);
}

int
mms_mgmt_mount_vol(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response = NULL;
	char		tid[64];
	char		cmd[8192];
	char		mbuf[7168];
	char		buf[1024];
	char		*pcl;
	char		*lib;
	char		*mfile = NULL;
	char		*val;
	char		*app = NULL;
	char		*vname;
	nvlist_t	*attrs = NULL;
	nvpair_t	*nvp;
	nvlist_t	*nva;
	nvlist_t	*mntattrs = NULL;
	mmsmnt_arg_t	arg;
	door_arg_t	d_arg;
	int		others = 0;
	struct passwd	*pwd = NULL;
	char		*usernm = NULL;
	nvlist_t	*cattrs = NULL;
	boolean_t	isdsk = B_FALSE;
	char		**varray = NULL;
	int		count = 0;
	boolean_t	vbool = B_FALSE;
	int		i;
	char		*inst = NULL;
	char		*pass = NULL;

	if (!mgmt_chk_auth("solaris.mms.io.read")) {
		return (EACCES);
	}

	/* this function is unique, in that it returns the session */
	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &pcl);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	st = nvlist_lookup_string(nvl, O_MMSLIB, &lib);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_MMSLIB, st);
		return (st);
	}

	st = nvlist_lookup_string(nvl, O_APPS, &app);
	if (st != 0) {
		/* if not specified, see if we can mount as admin */
		if (st == ENOENT) {
			st = 0;
			app = "MMS";
			(void) nvlist_add_string(nvl, O_APPS, app);
		} else {
			MGMT_ADD_OPTERR(errs, O_APPS, st);
			return (st);
		}
	}

	(void) nvlist_lookup_string(nvl, "filename", &mfile);
	(void) nvlist_lookup_string(nvl, "instance", &inst);
	(void) nvlist_lookup_string(nvl, O_MMPASS, &pass);

	if (!sessp) {
		st = create_mm_clnt(app, inst, pass, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	/* check for volumes.  If one doesn't exist, fail */
	st = mgmt_show_mmvols(sessp, pcl, lib, &attrs);
	if (st == 0) {
		if (!attrs) {
			st = MMS_MGMT_VOL_NOT_INIT;
		}
	}
	if (st != 0) {
		MGMT_ADD_ERR(errs, pcl, st);
		goto done;
	}

	nvp = NULL;
	while ((nvp = nvlist_next_nvpair(attrs, nvp)) != NULL) {
		st = nvpair_value_nvlist(nvp, &nva);
		if (st != 0) {
			goto done;
		}
		st = nvlist_lookup_string(nva, "ApplicationName", &val);
		if (st != 0) {
			continue;
		}

		if (strcasecmp(val, app) != 0) {
			continue;
		}

		/* found a valid volume */
		break;
	}

	if ((st != 0) || (nvp == NULL)) {
		st = MMS_MGMT_NO_USABLE_VOL;
		MGMT_ADD_ERR(errs, pcl, st);
		goto done;
	}

	st = nvlist_lookup_string(nva, "VolumeName", &vname);
	if (st != 0) {
		goto done;
	}

	/* see what type of cartridge this is */
	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] report[CARTRIDGETYPE.'CartridgeShapeName'] "
	    "reportmode[namevalue] "
	    "match[and (streq(CARTRIDGE.'CartridgePCL' '%s') "
	    "streq(LIBRARY.'LibraryName' '%s'))];",
	    tid, pcl, lib);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "get cartridge type",
	    &response);
	if (st == 0) {
		st = mmp_get_nvattrs("CartridgeShapeName", B_FALSE, response,
		    &cattrs);
		mms_free_rsp(response);
	}
	if (st == 0) {
		if (nvlist_exists(cattrs, "DISK")) {
			isdsk = B_TRUE;
		}
	}
	/* reset */
	if (cattrs) {
		nvlist_free(cattrs);
	}
	st = 0;

	st = nvlist_lookup_string(nvl, "user", &usernm);
	if ((st != 0) || (usernm == NULL)) {
		pwd = getpwuid(getuid());
		if (pwd != NULL) {
			usernm = pwd->pw_name;
		}
		if (usernm == NULL) {
			usernm = "root";
		}
	}

	/* at last, create the mount command */
	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "mount task['%s'] user['%s'] type[VOLUME] "
	    "match[and (streq(LIBRARY.'LibraryName' '%s') "
	    "streq(CARTRIDGE.'CartridgePCL' '%s'))] "
	    "report[MOUNTLOGICAL] reportmode[namevalue] ",
	    tid, usernm, lib, pcl);

	if (mfile) {
		(void) snprintf(buf, sizeof (buf), "filename['%s'] ",
		    mfile);
		(void) strlcat(cmd, buf, sizeof (cmd));
	}

	st = nvlist_lookup_string(nvl, "blocksize", &val);
	if (st == 0) {
		(void) snprintf(buf, sizeof (buf), "blocksize['%s'] ", val);
		(void) strlcat(cmd, buf, sizeof (cmd));
	}

	st = nvlist_lookup_boolean_value(nvl, O_NOWAIT, &vbool);
	if ((st == 0) && (vbool)) {
		(void) strlcat(cmd, "when[immediate] ", sizeof (cmd));
	} else {
		(void) strlcat(cmd, "when[blocking] ", sizeof (cmd));
	}
	st = 0;

	/* get the firstmount and accessmodes */
	mbuf[0] = '\0';

	if (mfile && (strcmp(mfile, label_fname) == 0)) {
		/* The 17-space filename indicates we're labeling */
		(void) strlcat(cmd, "accessmode['creat'] ", sizeof (cmd));
		(void) strlcat(mbuf, "firstmount[", sizeof (mbuf));
	} else {
		/* all options go into accessmode otherwise */
		(void) strlcat(mbuf, "accessmode[", sizeof (mbuf));
	}

	/* get the rest of the options */
	if (isdsk) {
		others++;
		(void) strlcat(mbuf, "'st_bsd' ", sizeof (mbuf));
	}

	st = nvlist_lookup_string(nvl, O_MMSDRV, &val);
	if (st == 0) {
		others++;
		(void) snprintf(buf, sizeof (buf), "'%s' ", val);
		(void) strlcat(mbuf, buf, sizeof (mbuf));
	}

	st = nvlist_lookup_boolean_value(nvl, O_NOREWIND, &vbool);
	if ((st == 0) && (vbool)) {
		others++;
		(void) strlcat(mbuf, "'norewind' ", sizeof (mbuf));
	}

	st = nvlist_lookup_string(nvl, O_DENSITY, &val);
	if (st == 0) {
		others++;
		(void) snprintf(buf, sizeof (buf), "'%s' ", val);
		(void) strlcat(mbuf, buf, sizeof (mbuf));
	}

	varray = var_to_array(nvl, "mode", &count);
	for (i = 0; i < count; i++) {
		if (!varray[i]) {
			continue;
		}
		others++;
		(void) snprintf(buf, sizeof (buf), "'%s' ", varray[i]);
		(void) strlcat(mbuf, buf, sizeof (mbuf));
	}
	mgmt_free_str_arr(varray, count);
	varray = NULL;
	count = 0;

	st = nvlist_lookup_string(nvl, "readonly", &val);
	if (st == 0) {
		if (strcasecmp(val, "true") == 0) {
			(void) snprintf(buf, sizeof (buf), "'readonly' ");
		} else {
			(void) snprintf(buf, sizeof (buf), "'readwrite' ");
		}
		others++;
		(void) strlcat(mbuf, buf, sizeof (mbuf));
	}

	if (others > 0) {
		(void) strlcat(mbuf, "]", sizeof (mbuf));
		(void) strlcat(cmd, mbuf, sizeof (cmd));
	}

	(void) strlcat(cmd, ";", sizeof (cmd));

	/*
	 *  Call the mount daemon.  If successful, the handle will be
	 *  returned.
	 */

	(void) memset(&arg, 0, sizeof (mmsmnt_arg_t));
	(void) memset(&d_arg, 0, sizeof (door_arg_t));

	arg.op = 1;
	(void) strlcpy(arg.cartridge, pcl, sizeof (arg.cartridge));
	(void) strlcpy(arg.library, lib, sizeof (arg.library));
	(void) strlcpy(arg.volname, vname, sizeof (arg.volname));
	(void) strlcpy(arg.cmd, cmd, sizeof (arg.cmd));
	if (pass) {
		(void) strlcpy(arg.pass, pass, sizeof (arg.pass));
	}
	if (inst) {
		(void) strlcpy(arg.inst, inst, sizeof (arg.inst));
	}
	if (app) {
		(void) strlcpy(arg.app, app, sizeof (arg.app));
	}
	d_arg.data_ptr = (char *)&arg;
	d_arg.data_size = sizeof (mmsmnt_arg_t);
	d_arg.desc_ptr = NULL;
	d_arg.desc_num = 0;
	d_arg.rbuf = (char *)&arg;
	d_arg.rsize = d_arg.data_size;

	st = call_mmsmnt(&d_arg);

	if (st == 0) {
		(void) nvlist_add_string(nvl, "mountdev", arg.devname);
	}

done:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	if (attrs) {
		nvlist_free(attrs);
	}

	if (mntattrs) {
		nvlist_free(mntattrs);
	}

	return (st);
}

int
mms_mgmt_unmount_vol(nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	char		*lib = NULL;
	char		*pcl = NULL;
	char		*dev = NULL;
	char		*app = NULL;
	char		*inst = NULL;
	char		*pass = NULL;
	void		*sess = NULL;
	void		*resp = NULL;
	char		tid[64];
	char		cmd[8192];
	nvlist_t	*attrs = NULL;
	boolean_t	phys = B_FALSE;
	mmsmnt_arg_t	arg;
	door_arg_t	d_arg;

	if (!mgmt_chk_auth("solaris.mms.io.read")) {
		return (EACCES);
	}

	(void) memset(&arg, 0, sizeof (mmsmnt_arg_t));
	(void) memset(&d_arg, 0, sizeof (d_arg));

	/* requires either the pseudodevice name, *or* library/volume */
	st = nvlist_lookup_string(nvl, O_NAME, &pcl);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	if (pcl[0] == '/') {
		(void) strlcpy(arg.devname, pcl, sizeof (arg.devname));
	} else {
		(void) strlcpy(arg.cartridge, pcl, sizeof (arg.cartridge));
	}

	st = nvlist_lookup_string(nvl, O_MMSLIB, &lib);
	if ((st != 0) && (arg.cartridge[0] != '\0')) {
		MGMT_ADD_OPTERR(errs, O_MMSLIB, st);
		return (st);
	}

	if (lib) {
		(void) strlcpy(arg.library, lib, sizeof (arg.library));
	}

	/* could specify all the options, but unlikely */
	st = nvlist_lookup_string(nvl, "mountdev", &dev);
	if (st == 0) {
		(void) strlcpy(arg.devname, dev, sizeof (arg.devname));
	}

	(void) nvlist_lookup_string(nvl, O_APPS, &app);
	if (!app) {
		app = "MMS";
	}
	(void) nvlist_lookup_string(nvl, "instance", &inst);
	(void) nvlist_lookup_string(nvl, O_MMPASS, &pass);

	/* make sure user is permitted to unmount this volume */
	if (strcasecmp(app, "MMS") != 0) {
		st = create_mm_clnt(app, inst, pass, NULL, &sess);
		if (st != 0) {
			return (st);
		}

		(void) mms_gen_taskid(tid);

		if (pcl[0] == '/') {
			(void) snprintf(cmd, sizeof (cmd),
			    "show task['%s'] report[MOUNTPHYSICAL] "
			    "reportmode[namevalue] "
			    "match[and "
			    "(streq(MOUNTPHYSICAL.'ApplicationName' '%s') "
			    "streq(MOUNTLOGICAL.'MountLogicalHandle' '%s'))];",
			    tid, app, pcl);
		} else {
			(void) snprintf(cmd, sizeof (cmd),
			    "show task['%s'] report[MOUNTPHYSICAL] "
			    "reportmode[namevalue] "
			    "match[and "
			    "(streq(MOUNTPHYSICAL.'ApplicationName' '%s') "
			    "streq(MOUNTPHYSICAL.'CartridgePCL' '%s'))];",
			    tid, app, pcl);
		}

		st = mms_mgmt_send_cmd(sess, tid, cmd, "check mounted vol",
		    &resp);
		if (st == 0) {
			st = mmp_get_nvattrs("ApplicationName", B_FALSE,
			    resp, &attrs);
			mms_free_rsp(resp);
		}
		if (st == 0) {
			if (!nvlist_exists(attrs, app)) {
				st = MMS_MGMT_VOL_NOT_MOUNTED;
			}
			nvlist_free(attrs);
		}

		(void) mms_goodbye(sess, 0);

		if (st != 0) {
			return (st);
		}
	}

	arg.op = 2;

	/* see if they want the cartridge physically unloaded */
	st = nvlist_lookup_boolean_value(nvl, "unload", &phys);
	if (phys) {
		(void) strlcpy(arg.cmd, "physicalunmount", sizeof (arg.cmd));
	}

	d_arg.data_ptr = (char *)&arg;
	d_arg.data_size = sizeof (mmsmnt_arg_t);
	d_arg.desc_ptr = NULL;
	d_arg.desc_num = 0;
	d_arg.rbuf = (char *)&arg;
	d_arg.rsize = d_arg.data_size;

	st = call_mmsmnt(&d_arg);

	return (st);
}
