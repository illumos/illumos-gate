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
 * Datalink management routines.
 */

#include <sys/types.h>
#include <sys/door.h>
#include <sys/zone.h>
#include <sys/modctl.h>
#include <sys/file.h>
#include <sys/modhash.h>
#include <sys/kstat.h>
#include <sys/vnode.h>
#include <sys/cmn_err.h>
#include <sys/vlan.h>
#include <sys/softmac.h>
#include <sys/dls.h>
#include <sys/dls_impl.h>

static kmem_cache_t	*i_dls_devnet_cachep;
static kmutex_t		i_dls_mgmt_lock;
static krwlock_t	i_dls_devnet_lock;
static mod_hash_t	*i_dls_devnet_id_hash;
static mod_hash_t	*i_dls_devnet_hash;

boolean_t		devnet_need_rebuild;

#define	VLAN_HASHSZ	67	/* prime */

/* Upcall door handle */
static door_handle_t	dls_mgmt_dh = NULL;

/*
 * This structure is used to keep the <linkid, macname, vid> mapping.
 */
typedef struct dls_devnet_s {
	datalink_id_t	dd_vlanid;
	datalink_id_t	dd_linkid;
	char		dd_mac[MAXNAMELEN];
	uint16_t	dd_vid;
	char		dd_spa[MAXSPALEN];
	boolean_t	dd_explicit;
	kstat_t		*dd_ksp;

	uint32_t	dd_ref;

	kmutex_t	dd_mutex;
	kcondvar_t	dd_cv;
	uint32_t	dd_tref;

	kmutex_t	dd_zid_mutex;
	zoneid_t	dd_zid;
} dls_devnet_t;

/*ARGSUSED*/
static int
i_dls_devnet_constructor(void *buf, void *arg, int kmflag)
{
	dls_devnet_t	*ddp = buf;

	bzero(buf, sizeof (dls_devnet_t));
	mutex_init(&ddp->dd_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ddp->dd_zid_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ddp->dd_cv, NULL, CV_DEFAULT, NULL);
	return (0);
}

/*ARGSUSED*/
static void
i_dls_devnet_destructor(void *buf, void *arg)
{
	dls_devnet_t	*ddp = buf;

	ASSERT(ddp->dd_ksp == NULL);
	ASSERT(ddp->dd_ref == 0);
	ASSERT(ddp->dd_tref == 0);
	ASSERT(!ddp->dd_explicit);
	mutex_destroy(&ddp->dd_mutex);
	mutex_destroy(&ddp->dd_zid_mutex);
	cv_destroy(&ddp->dd_cv);
}

/*
 * Module initialization and finalization functions.
 */
void
dls_mgmt_init(void)
{
	mutex_init(&i_dls_mgmt_lock, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&i_dls_devnet_lock, NULL, RW_DEFAULT, NULL);

	/*
	 * Create a kmem_cache of dls_devnet_t structures.
	 */
	i_dls_devnet_cachep = kmem_cache_create("dls_devnet_cache",
	    sizeof (dls_devnet_t), 0, i_dls_devnet_constructor,
	    i_dls_devnet_destructor, NULL, NULL, NULL, 0);
	ASSERT(i_dls_devnet_cachep != NULL);

	/*
	 * Create a hash table, keyed by dd_vlanid, of dls_devnet_t.
	 */
	i_dls_devnet_id_hash = mod_hash_create_idhash("dls_devnet_id_hash",
	    VLAN_HASHSZ, mod_hash_null_valdtor);

	/*
	 * Create a hash table, keyed by dd_spa.
	 */
	i_dls_devnet_hash = mod_hash_create_extended("dls_devnet_hash",
	    VLAN_HASHSZ, mod_hash_null_keydtor, mod_hash_null_valdtor,
	    mod_hash_bystr, NULL, mod_hash_strkey_cmp, KM_SLEEP);

	devnet_need_rebuild = B_FALSE;
}

void
dls_mgmt_fini(void)
{
	mod_hash_destroy_hash(i_dls_devnet_hash);
	mod_hash_destroy_hash(i_dls_devnet_id_hash);
	kmem_cache_destroy(i_dls_devnet_cachep);
	rw_destroy(&i_dls_devnet_lock);
	mutex_destroy(&i_dls_mgmt_lock);
}

int
dls_mgmt_door_set(boolean_t start)
{
	int	err;

	/* handle daemon restart */
	mutex_enter(&i_dls_mgmt_lock);
	if (dls_mgmt_dh != NULL) {
		door_ki_rele(dls_mgmt_dh);
		dls_mgmt_dh = NULL;
	}

	if (start && ((err = door_ki_open(DLMGMT_DOOR, &dls_mgmt_dh)) != 0)) {
		mutex_exit(&i_dls_mgmt_lock);
		return (err);
	}

	mutex_exit(&i_dls_mgmt_lock);

	/*
	 * Create and associate <link name, linkid> mapping for network devices
	 * which are already attached before the daemon is started.
	 */
	if (start)
		softmac_recreate();
	return (0);
}

static boolean_t
i_dls_mgmt_door_revoked(door_handle_t dh)
{
	struct door_info info;
	extern int sys_shutdown;

	ASSERT(dh != NULL);

	if (sys_shutdown) {
		cmn_err(CE_NOTE, "dls_mgmt_door: shutdown observed\n");
		return (B_TRUE);
	}

	if (door_ki_info(dh, &info) != 0)
		return (B_TRUE);

	return ((info.di_attributes & DOOR_REVOKED) != 0);
}

/*
 * Upcall to the datalink management daemon (dlmgmtd).
 */
static int
i_dls_mgmt_upcall(void *arg, size_t asize, void *rbuf, size_t rsize)
{
	door_arg_t			darg, save_arg;
	door_handle_t			dh;
	int				err;
	int				retry = 0;

#define	MAXRETRYNUM	3

	ASSERT(arg);
	darg.data_ptr = arg;
	darg.data_size = asize;
	darg.desc_ptr = NULL;
	darg.desc_num = 0;
	darg.rbuf = rbuf;
	darg.rsize = rsize;
	save_arg = darg;

retry:
	mutex_enter(&i_dls_mgmt_lock);
	dh = dls_mgmt_dh;
	if ((dh == NULL) || i_dls_mgmt_door_revoked(dh)) {
		mutex_exit(&i_dls_mgmt_lock);
		return (EBADF);
	}
	door_ki_hold(dh);
	mutex_exit(&i_dls_mgmt_lock);

	for (;;) {
		retry++;
		if ((err = door_ki_upcall_cred(dh, &darg, kcred)) == 0)
			break;

		/*
		 * handle door call errors
		 */
		darg = save_arg;
		switch (err) {
		case EINTR:
			/*
			 * If the operation which caused this door upcall gets
			 * interrupted, return directly.
			 */
			goto done;
		case EAGAIN:
			/*
			 * Repeat upcall if the maximum attempt limit has not
			 * been reached.
			 */
			if (retry < MAXRETRYNUM) {
				delay(2 * hz);
				break;
			}
			cmn_err(CE_WARN, "dls: dlmgmtd fatal error %d\n", err);
			goto done;
		default:
			/* A fatal door error */
			if (i_dls_mgmt_door_revoked(dh)) {
				cmn_err(CE_NOTE,
				    "dls: dlmgmtd door service revoked\n");

				if (retry < MAXRETRYNUM) {
					door_ki_rele(dh);
					goto retry;
				}
			}
			cmn_err(CE_WARN, "dls: dlmgmtd fatal error %d\n", err);
			goto done;
		}
	}

	if (darg.rbuf != rbuf) {
		/*
		 * The size of the input rbuf was not big enough, so the
		 * upcall allocated the rbuf itself.  If this happens, assume
		 * that this was an invalid door call request.
		 */
		kmem_free(darg.rbuf, darg.rsize);
		err = ENOSPC;
		goto done;
	}

	if (darg.rsize != rsize) {
		err = EINVAL;
		goto done;
	}

	err = ((dlmgmt_retval_t *)rbuf)->lr_err;

done:
	door_ki_rele(dh);
	return (err);
}

/*
 * Request the datalink management daemon to create a link with the attributes
 * below.  Upon success, zero is returned and linkidp contains the linkid for
 * the new link; otherwise, an errno is returned.
 *
 *     - dev		physical dev_t.  required for all physical links,
 *		        including GLDv3 links.  It will be used to force the
 *		        attachment of a physical device, hence the
 *		        registration of its mac
 *     - class		datalink class
 *     - media type	media type; DL_OTHER means unknown
 *     - vid		VLAN ID (for VLANs)
 *     - persist	whether to persist the datalink
 */
int
dls_mgmt_create(const char *devname, dev_t dev, datalink_class_t class,
    uint32_t media, boolean_t persist, datalink_id_t *linkidp)
{
	dlmgmt_upcall_arg_create_t	create;
	dlmgmt_create_retval_t		retval;
	int				err;

	create.ld_cmd = DLMGMT_CMD_DLS_CREATE;
	create.ld_class = class;
	create.ld_media = media;
	create.ld_phymaj = getmajor(dev);
	create.ld_phyinst = getminor(dev);
	create.ld_persist = persist;
	if (strlcpy(create.ld_devname, devname, MAXNAMELEN) >= MAXNAMELEN)
		return (EINVAL);

	if ((err = i_dls_mgmt_upcall(&create, sizeof (create), &retval,
	    sizeof (retval))) == 0) {
		*linkidp = retval.lr_linkid;
	}
	return (err);
}

/*
 * Request the datalink management daemon to destroy the specified link.
 * Returns zero upon success, or an errno upon failure.
 */
int
dls_mgmt_destroy(datalink_id_t linkid, boolean_t persist)
{
	dlmgmt_upcall_arg_destroy_t	destroy;
	dlmgmt_destroy_retval_t		retval;

	destroy.ld_cmd = DLMGMT_CMD_DLS_DESTROY;
	destroy.ld_linkid = linkid;
	destroy.ld_persist = persist;

	return (i_dls_mgmt_upcall(&destroy, sizeof (destroy),
	    &retval, sizeof (retval)));
}

/*
 * Request the datalink management daemon to verify/update the information
 * for a physical link.  Upon success, get its linkid.
 *
 *     - media type	media type
 *     - novanity	whether this physical datalink supports vanity naming.
 *			physical links that do not use the GLDv3 MAC plugin
 *			cannot suport vanity naming
 *
 * This function could fail with ENOENT or EEXIST.  Two cases return EEXIST:
 *
 * 1. A link with devname already exists, but the media type does not match.
 *    In this case, mediap will bee set to the media type of the existing link.
 * 2. A link with devname already exists, but its link name does not match
 *    the device name, although this link does not support vanity naming.
 */
int
dls_mgmt_update(const char *devname, uint32_t media, boolean_t novanity,
    uint32_t *mediap, datalink_id_t *linkidp)
{
	dlmgmt_upcall_arg_update_t	update;
	dlmgmt_update_retval_t		retval;
	int				err;

	update.ld_cmd = DLMGMT_CMD_DLS_UPDATE;

	if (strlcpy(update.ld_devname, devname, MAXNAMELEN) >= MAXNAMELEN)
		return (EINVAL);

	update.ld_media = media;
	update.ld_novanity = novanity;

	if ((err = i_dls_mgmt_upcall(&update, sizeof (update), &retval,
	    sizeof (retval))) == EEXIST) {
		*linkidp = retval.lr_linkid;
		*mediap = retval.lr_media;
	} else if (err == 0) {
		*linkidp = retval.lr_linkid;
	}

	return (err);
}

/*
 * Request the datalink management daemon to get the information for a link.
 * Returns zero upon success, or an errno upon failure.
 *
 * Only fills in information for argument pointers that are non-NULL.
 * Note that the link argument is expected to be MAXLINKNAMELEN bytes.
 */
int
dls_mgmt_get_linkinfo(datalink_id_t linkid, char *link,
    datalink_class_t *classp, uint32_t *mediap, uint32_t *flagsp)
{
	dlmgmt_door_getname_t	getname;
	dlmgmt_getname_retval_t	retval;
	int			err, len;

	getname.ld_cmd = DLMGMT_CMD_GETNAME;
	getname.ld_linkid = linkid;

	if ((err = i_dls_mgmt_upcall(&getname, sizeof (getname), &retval,
	    sizeof (retval))) != 0) {
		return (err);
	}

	len = strlen(retval.lr_link);
	if (len <= 1 || len >= MAXLINKNAMELEN)
		return (EINVAL);

	if (link != NULL)
		(void) strlcpy(link, retval.lr_link, MAXLINKNAMELEN);
	if (classp != NULL)
		*classp = retval.lr_class;
	if (mediap != NULL)
		*mediap = retval.lr_media;
	if (flagsp != NULL)
		*flagsp = retval.lr_flags;
	return (0);
}

/*
 * Request the datalink management daemon to get the linkid for a link.
 * Returns a non-zero error code on failure.  The linkid argument is only
 * set on success (when zero is returned.)
 */
int
dls_mgmt_get_linkid(const char *link, datalink_id_t *linkid)
{
	dlmgmt_door_getlinkid_t		getlinkid;
	dlmgmt_getlinkid_retval_t	retval;
	int				err;

	getlinkid.ld_cmd = DLMGMT_CMD_GETLINKID;
	(void) strlcpy(getlinkid.ld_link, link, MAXLINKNAMELEN);

	if ((err = i_dls_mgmt_upcall(&getlinkid, sizeof (getlinkid), &retval,
	    sizeof (retval))) == 0) {
		*linkid = retval.lr_linkid;
	}
	return (err);
}

datalink_id_t
dls_mgmt_get_next(datalink_id_t linkid, datalink_class_t class,
    datalink_media_t dmedia, uint32_t flags)
{
	dlmgmt_door_getnext_t	getnext;
	dlmgmt_getnext_retval_t	retval;

	getnext.ld_cmd = DLMGMT_CMD_GETNEXT;
	getnext.ld_class = class;
	getnext.ld_dmedia = dmedia;
	getnext.ld_flags = flags;
	getnext.ld_linkid = linkid;

	if (i_dls_mgmt_upcall(&getnext, sizeof (getnext), &retval,
	    sizeof (retval)) != 0) {
		return (DATALINK_INVALID_LINKID);
	}

	return (retval.lr_linkid);
}

static int
i_dls_mgmt_get_linkattr(const datalink_id_t linkid, const char *attr,
    void *attrval, size_t *attrszp)
{
	dlmgmt_upcall_arg_getattr_t	getattr;
	dlmgmt_getattr_retval_t		retval;
	int				err;

	getattr.ld_cmd = DLMGMT_CMD_DLS_GETATTR;
	getattr.ld_linkid = linkid;
	(void) strlcpy(getattr.ld_attr, attr, MAXLINKATTRLEN);

	if ((err = i_dls_mgmt_upcall(&getattr, sizeof (getattr), &retval,
	    sizeof (retval))) == 0) {
		if (*attrszp < retval.lr_attrsz)
			return (EINVAL);
		*attrszp = retval.lr_attrsz;
		bcopy(retval.lr_attrval, attrval, retval.lr_attrsz);
	}

	return (err);
}

/*
 * Note that this function can only get devp successfully for non-VLAN link.
 */
int
dls_mgmt_get_phydev(datalink_id_t linkid, dev_t *devp)
{
	uint64_t	maj, inst;
	size_t		attrsz = sizeof (uint64_t);

	if (i_dls_mgmt_get_linkattr(linkid, FPHYMAJ, &maj, &attrsz) != 0 ||
	    attrsz != sizeof (uint64_t) ||
	    i_dls_mgmt_get_linkattr(linkid, FPHYINST, &inst, &attrsz) != 0 ||
	    attrsz != sizeof (uint64_t)) {
		return (EINVAL);
	}

	*devp = makedevice((major_t)maj, (minor_t)inst);
	return (0);
}

/*
 * Hold the vanity naming structure (dls_devnet_t) temporarily.  The request to
 * delete the dls_devnet_t will wait until the temporary reference is released.
 */
int
dls_devnet_hold_tmp(datalink_id_t linkid, dls_dl_handle_t *ddhp)
{
	dls_devnet_t		*ddp;
	dls_dev_handle_t	ddh = NULL;
	dev_t			phydev = 0;
	int			err;

	/*
	 * Hold this link to prevent it being detached (if physical link).
	 */
	if (dls_mgmt_get_phydev(linkid, &phydev) == 0)
		(void) softmac_hold_device(phydev, &ddh);

	rw_enter(&i_dls_devnet_lock, RW_READER);
	if ((err = mod_hash_find(i_dls_devnet_id_hash,
	    (mod_hash_key_t)(uintptr_t)linkid, (mod_hash_val_t *)&ddp)) != 0) {
		ASSERT(err == MH_ERR_NOTFOUND);
		rw_exit(&i_dls_devnet_lock);
		softmac_rele_device(ddh);
		return (ENOENT);
	}

	/*
	 * At least one reference was held when this datalink was created.
	 */
	ASSERT(ddp->dd_ref > 0);
	mutex_enter(&ddp->dd_mutex);
	ddp->dd_tref++;
	mutex_exit(&ddp->dd_mutex);
	rw_exit(&i_dls_devnet_lock);
	softmac_rele_device(ddh);

done:
	*ddhp = ddp;
	return (0);
}

void
dls_devnet_rele_tmp(dls_dl_handle_t dlh)
{
	dls_devnet_t		*ddp = dlh;

	mutex_enter(&ddp->dd_mutex);
	ASSERT(ddp->dd_tref != 0);
	if (--ddp->dd_tref == 0)
		cv_signal(&ddp->dd_cv);
	mutex_exit(&ddp->dd_mutex);
}

/*
 * "link" kstats related functions.
 */

/*
 * Query the "link" kstats.
 */
static int
dls_devnet_stat_update(kstat_t *ksp, int rw)
{
	dls_devnet_t	*ddp = ksp->ks_private;
	dls_vlan_t	*dvp;
	int		err;

	err = dls_vlan_hold(ddp->dd_mac, ddp->dd_vid, &dvp, B_FALSE, B_FALSE);
	if (err != 0)
		return (err);

	err = dls_stat_update(ksp, dvp, rw);
	dls_vlan_rele(dvp);
	return (err);
}

/*
 * Create the "link" kstats.
 */
static void
dls_devnet_stat_create(dls_devnet_t *ddp)
{
	char	link[MAXLINKNAMELEN];
	kstat_t	*ksp;

	if ((dls_mgmt_get_linkinfo(ddp->dd_vlanid, link,
	    NULL, NULL, NULL)) != 0) {
		return;
	}

	if (dls_stat_create("link", 0, link, dls_devnet_stat_update,
	    ddp, &ksp) != 0) {
		return;
	}

	ASSERT(ksp != NULL);
	ddp->dd_ksp = ksp;
}

/*
 * Destroy the "link" kstats.
 */
static void
dls_devnet_stat_destroy(dls_devnet_t *ddp)
{
	if (ddp->dd_ksp == NULL)
		return;

	kstat_delete(ddp->dd_ksp);
	ddp->dd_ksp = NULL;
}

/*
 * The link has been renamed. Destroy the old non-legacy kstats ("link kstats")
 * and create the new set using the new name.
 */
static void
dls_devnet_stat_rename(dls_devnet_t *ddp, const char *link)
{
	kstat_t	 *ksp;

	if (ddp->dd_ksp != NULL) {
		kstat_delete(ddp->dd_ksp);
		ddp->dd_ksp = NULL;
	}

	if (dls_stat_create("link", 0, link, dls_devnet_stat_update,
	    ddp, &ksp) != 0) {
		return;
	}

	ASSERT(ksp != NULL);
	ddp->dd_ksp = ksp;
}

/*
 * Associate a linkid with a given link (identified by <macname/vid>)
 *
 * Several cases:
 * a. implicit VLAN creation: (non-NULL "vlan")
 * b. explicit VLAN creation: (NULL "vlan")
 * c. explicit non-VLAN creation:
 *    (NULL "vlan" and linkid could be INVALID_LINKID if the physical device
 *    was created before the daemon was started)
 */
static int
dls_devnet_set(const char *macname, uint16_t vid,
    datalink_id_t vlan_linkid, datalink_id_t linkid, const char *vlan,
    dls_devnet_t **ddpp)
{
	dls_devnet_t		*ddp = NULL;
	char			spa[MAXSPALEN];
	boolean_t		explicit = (vlan == NULL);
	datalink_class_t	class;
	int			err;

	ASSERT(vid != VLAN_ID_NONE || explicit);
	ASSERT(vlan_linkid != DATALINK_INVALID_LINKID || !explicit ||
	    vid == VLAN_ID_NONE);

	(void) snprintf(spa, MAXSPALEN, "%s/%d", macname, vid);
	rw_enter(&i_dls_devnet_lock, RW_WRITER);
	if ((err = mod_hash_find(i_dls_devnet_hash,
	    (mod_hash_key_t)spa, (mod_hash_val_t *)&ddp)) == 0) {
		char	link[MAXLINKNAMELEN];

		if (explicit) {
			if ((vid != VLAN_ID_NONE) ||
			    (ddp->dd_vlanid != DATALINK_INVALID_LINKID)) {
				err = EEXIST;
				goto done;
			}

			/*
			 * This might be a physical link that has already
			 * been created, but which does not have a vlan_linkid
			 * because dlmgmtd was not running when it was created.
			 */
			if ((err = dls_mgmt_get_linkinfo(vlan_linkid, NULL,
			    &class, NULL, NULL)) != 0) {
				goto done;
			}

			if (class != DATALINK_CLASS_PHYS) {
				err = EINVAL;
				goto done;
			}

			goto newphys;
		}

		/*
		 * Implicit VLAN, but the same name has already
		 * been associated with another linkid.  Check if the name
		 * of that link matches the given VLAN name.
		 */
		ASSERT(vid != VLAN_ID_NONE);
		if ((err = dls_mgmt_get_linkinfo(ddp->dd_vlanid, link,
		    NULL, NULL, NULL)) != 0) {
			goto done;
		}

		if (strcmp(link, vlan) != 0) {
			err = EEXIST;
			goto done;
		}

		/*
		 * This is not an implicit created VLAN any more, return
		 * this existing datalink.
		 */
		ASSERT(ddp->dd_ref > 0);
		ddp->dd_ref++;
		goto done;
	}

	/*
	 * Request the daemon to create a new vlan_linkid for this implicitly
	 * created vlan.
	 */
	if (!explicit && ((err = dls_mgmt_create(vlan, 0,
	    DATALINK_CLASS_VLAN, DL_ETHER, B_FALSE, &vlan_linkid)) != 0)) {
		goto done;
	}

	ddp = kmem_cache_alloc(i_dls_devnet_cachep, KM_SLEEP);
	ddp->dd_vid = vid;
	ddp->dd_explicit = explicit;
	ddp->dd_tref = 0;
	ddp->dd_ref++;
	ddp->dd_zid = GLOBAL_ZONEID;
	(void) strncpy(ddp->dd_mac, macname, MAXNAMELEN);
	(void) snprintf(ddp->dd_spa, MAXSPALEN, "%s/%d", macname, vid);
	VERIFY(mod_hash_insert(i_dls_devnet_hash,
	    (mod_hash_key_t)ddp->dd_spa, (mod_hash_val_t)ddp) == 0);

newphys:

	ddp->dd_vlanid = vlan_linkid;
	if (ddp->dd_vlanid != DATALINK_INVALID_LINKID) {
		ddp->dd_linkid = linkid;

		VERIFY(mod_hash_insert(i_dls_devnet_id_hash,
		    (mod_hash_key_t)(uintptr_t)vlan_linkid,
		    (mod_hash_val_t)ddp) == 0);
		devnet_need_rebuild = B_TRUE;
		dls_devnet_stat_create(ddp);
	}
	err = 0;
done:
	rw_exit(&i_dls_devnet_lock);
	if (err == 0 && ddpp != NULL)
		*ddpp = ddp;
	return (err);
}

static void
dls_devnet_unset_common(dls_devnet_t *ddp)
{
	mod_hash_val_t	val;

	ASSERT(RW_WRITE_HELD(&i_dls_devnet_lock));

	ASSERT(ddp->dd_ref == 0);

	/*
	 * Remove this dls_devnet_t from the hash table.
	 */
	VERIFY(mod_hash_remove(i_dls_devnet_hash,
	    (mod_hash_key_t)ddp->dd_spa, &val) == 0);

	if (ddp->dd_vlanid != DATALINK_INVALID_LINKID) {
		VERIFY(mod_hash_remove(i_dls_devnet_id_hash,
		    (mod_hash_key_t)(uintptr_t)ddp->dd_vlanid, &val) == 0);

		dls_devnet_stat_destroy(ddp);
		devnet_need_rebuild = B_TRUE;
	}

	/*
	 * Wait until all temporary references are released.
	 */
	mutex_enter(&ddp->dd_mutex);
	while (ddp->dd_tref != 0)
		cv_wait(&ddp->dd_cv, &ddp->dd_mutex);
	mutex_exit(&ddp->dd_mutex);

	if (!ddp->dd_explicit) {
		ASSERT(ddp->dd_vid != VLAN_ID_NONE);
		ASSERT(ddp->dd_vlanid != DATALINK_INVALID_LINKID);
		(void) dls_mgmt_destroy(ddp->dd_vlanid, B_FALSE);
	}

	ddp->dd_vlanid = DATALINK_INVALID_LINKID;
	ddp->dd_zid = GLOBAL_ZONEID;
	ddp->dd_explicit = B_FALSE;
	kmem_cache_free(i_dls_devnet_cachep, ddp);
}

/*
 * Disassociate a linkid with a given link (identified by <macname/vid>)
 */
static int
dls_devnet_unset(const char *macname, uint16_t vid, datalink_id_t *id)
{
	dls_devnet_t	*ddp;
	char		spa[MAXSPALEN];
	int		err;

	(void) snprintf(spa, MAXSPALEN, "%s/%d", macname, vid);

	rw_enter(&i_dls_devnet_lock, RW_WRITER);
	if ((err = mod_hash_find(i_dls_devnet_hash,
	    (mod_hash_key_t)spa, (mod_hash_val_t *)&ddp)) != 0) {
		ASSERT(err == MH_ERR_NOTFOUND);
		rw_exit(&i_dls_devnet_lock);
		return (ENOENT);
	}

	ASSERT(ddp->dd_ref != 0);

	if (ddp->dd_ref != 1) {
		rw_exit(&i_dls_devnet_lock);
		return (EBUSY);
	}

	ddp->dd_ref--;

	if (id != NULL)
		*id = ddp->dd_vlanid;

	dls_devnet_unset_common(ddp);
	rw_exit(&i_dls_devnet_lock);
	return (0);
}

static int
dls_devnet_hold(datalink_id_t linkid, dls_devnet_t **ddpp)
{
	dls_devnet_t		*ddp;
	dev_t			phydev = 0;
	dls_dev_handle_t	ddh = NULL;
	int			err;

	/*
	 * Hold this link to prevent it being detached in case of a
	 * physical link.
	 */
	if (dls_mgmt_get_phydev(linkid, &phydev) == 0)
		(void) softmac_hold_device(phydev, &ddh);

	rw_enter(&i_dls_devnet_lock, RW_WRITER);
	if ((err = mod_hash_find(i_dls_devnet_id_hash,
	    (mod_hash_key_t)(uintptr_t)linkid, (mod_hash_val_t *)&ddp)) != 0) {
		ASSERT(err == MH_ERR_NOTFOUND);
		rw_exit(&i_dls_devnet_lock);
		softmac_rele_device(ddh);
		return (ENOENT);
	}

	ASSERT(ddp->dd_ref > 0);
	ddp->dd_ref++;
	rw_exit(&i_dls_devnet_lock);
	softmac_rele_device(ddh);

done:
	*ddpp = ddp;
	return (0);
}

/*
 * This funtion is called when a DLS client tries to open a device node.
 * This dev_t could a result of a /dev/net node access (returned by
 * devnet_create_rvp->dls_devnet_open()) or a direct /dev node access.
 * In both cases, this function returns 0. In the first case, bump the
 * reference count of the dls_devnet_t structure, so that it will not be
 * freed when devnet_inactive_callback->dls_devnet_close() is called
 * (Note that devnet_inactive_callback() is called right after dld_open,
 * not when the /dev/net access is done). In the second case, ddhp would
 * be NULL.
 *
 * To undo this function, call dls_devnet_close() in the first case, and call
 * dls_vlan_rele() in the second case.
 */
int
dls_devnet_open_by_dev(dev_t dev, dls_vlan_t **dvpp, dls_dl_handle_t *ddhp)
{
	dls_dev_handle_t	ddh = NULL;
	char			spa[MAXSPALEN];
	dls_devnet_t		*ddp;
	dls_vlan_t		*dvp;
	int			err;

	/*
	 * Hold this link to prevent it being detached in case of a
	 * GLDv3 physical link.
	 */
	if (getminor(dev) - 1 < MAC_MAX_MINOR)
		(void) softmac_hold_device(dev, &ddh);

	/*
	 * Found the dls_vlan_t with the given dev.
	 */
	err = dls_vlan_hold_by_dev(dev, &dvp);
	softmac_rele_device(ddh);

	if (err != 0)
		return (err);

	(void) snprintf(spa, MAXSPALEN, "%s/%d",
	    dvp->dv_dlp->dl_name, dvp->dv_id);

	rw_enter(&i_dls_devnet_lock, RW_WRITER);
	if ((err = mod_hash_find(i_dls_devnet_hash,
	    (mod_hash_key_t)spa, (mod_hash_val_t *)&ddp)) != 0) {
		ASSERT(err == MH_ERR_NOTFOUND);
		rw_exit(&i_dls_devnet_lock);
		*ddhp = NULL;
		*dvpp = dvp;
		return (0);
	}

	ASSERT(ddp->dd_ref > 0);
	ddp->dd_ref++;
	rw_exit(&i_dls_devnet_lock);
	*ddhp = ddp;
	*dvpp = dvp;
	return (0);
}

static void
dls_devnet_rele(dls_devnet_t *ddp)
{
	rw_enter(&i_dls_devnet_lock, RW_WRITER);
	ASSERT(ddp->dd_ref != 0);
	if (--ddp->dd_ref != 0) {
		rw_exit(&i_dls_devnet_lock);
		return;
	}
	/*
	 * This should only happen for implicitly-created VLAN.
	 */
	ASSERT(ddp->dd_vid != VLAN_ID_NONE);
	dls_devnet_unset_common(ddp);
	rw_exit(&i_dls_devnet_lock);
}

static int
dls_devnet_hold_by_name(const char *link, dls_devnet_t **ddpp, zoneid_t zid)
{
	char			link_under[MAXLINKNAMELEN];
	char			drv[MAXLINKNAMELEN];
	uint_t			ppa;
	major_t			major;
	dev_t			phy_dev, tmp_dev;
	uint_t			vid;
	datalink_id_t		linkid;
	dls_devnet_t		*ddp;
	dls_dev_handle_t	ddh;
	int			err;

	if ((err = dls_mgmt_get_linkid(link, &linkid)) == 0)
		return (dls_devnet_hold(linkid, ddpp));

	/*
	 * If we failed to get the link's linkid because the dlmgmtd daemon
	 * has not been started, return ENOENT so that the application can
	 * fallback to open the /dev node.
	 */
	if (err == EBADF)
		return (ENOENT);

	if (err != ENOENT)
		return (err);

	if (ddi_parse(link, drv, &ppa) != DDI_SUCCESS)
		return (ENOENT);

	if ((vid = DLS_PPA2VID(ppa)) > VLAN_ID_MAX)
		return (ENOENT);

	ppa = (uint_t)DLS_PPA2INST(ppa);
	(void) snprintf(link_under, sizeof (link_under), "%s%d", drv, ppa);

	if (vid != VLAN_ID_NONE) {
		/*
		 * Only global zone can implicitly create a VLAN.
		 */
		if (zid != GLOBAL_ZONEID)
			return (ENOENT);

		/*
		 * This is potentially an implicitly-created VLAN. Hold the
		 * link this VLAN is created on.
		 */
		if (dls_mgmt_get_linkid(link_under, &linkid) == 0 &&
		    dls_devnet_hold_tmp(linkid, &ddp) == 0) {
			if (ddp->dd_vid != VLAN_ID_NONE) {
				dls_devnet_rele_tmp(ddp);
				return (ENOENT);
			}
			goto implicit;
		}
	}

	/*
	 * If this link (or the link that an implicit vlan is created on)
	 * (a) is a physical device, (b) this is the first boot, (c) the MAC
	 * is not registered yet, and (d) we cannot find its linkid, then the
	 * linkname is the same as the devname.
	 *
	 * First filter out invalid names.
	 */
	if ((major = ddi_name_to_major(drv)) == (major_t)-1)
		return (ENOENT);

	phy_dev = makedevice(major, (minor_t)ppa + 1);
	if (softmac_hold_device(phy_dev, &ddh) != 0)
		return (ENOENT);

	/*
	 * At this time, the MAC should be registered, check its phy_dev using
	 * the given name.
	 */
	if ((err = dls_mgmt_get_linkid(link_under, &linkid)) != 0 ||
	    (err = dls_mgmt_get_phydev(linkid, &tmp_dev)) != 0) {
		softmac_rele_device(ddh);
		return (err);
	}
	if (tmp_dev != phy_dev) {
		softmac_rele_device(ddh);
		return (ENOENT);
	}

	if (vid == VLAN_ID_NONE) {
		/*
		 * For non-VLAN, we are done.
		 */
		err = dls_devnet_hold(linkid, ddpp);
		softmac_rele_device(ddh);
		return (err);
	}

	/*
	 * If this is an implicit VLAN, temporarily hold this non-VLAN.
	 */
	VERIFY(dls_devnet_hold_tmp(linkid, &ddp) == 0);
	softmac_rele_device(ddh);
	ASSERT(ddp->dd_vid == VLAN_ID_NONE);

	/*
	 * Again, this is potentially an implicitly-created VLAN.
	 */

implicit:
	ASSERT(vid != VLAN_ID_NONE);
	err = dls_devnet_set(ddp->dd_mac, vid, DATALINK_INVALID_LINKID,
	    linkid, link, ddpp);
	dls_devnet_rele_tmp(ddp);
	return (err);
}

/*
 * Get linkid for the given dev.
 */
int
dls_devnet_dev2linkid(dev_t dev, datalink_id_t *linkidp)
{
	dls_vlan_t	*dvp;
	dls_devnet_t	*ddp;
	char		spa[MAXSPALEN];
	int		err;

	if ((err = dls_vlan_hold_by_dev(dev, &dvp)) != 0)
		return (err);

	(void) snprintf(spa, MAXSPALEN, "%s/%d",
	    dvp->dv_dlp->dl_name, dvp->dv_id);

	rw_enter(&i_dls_devnet_lock, RW_READER);
	if (mod_hash_find(i_dls_devnet_hash, (mod_hash_key_t)spa,
	    (mod_hash_val_t *)&ddp) != 0) {
		rw_exit(&i_dls_devnet_lock);
		dls_vlan_rele(dvp);
		return (ENOENT);
	}

	*linkidp = ddp->dd_vlanid;
	rw_exit(&i_dls_devnet_lock);
	dls_vlan_rele(dvp);
	return (0);
}

/*
 * Get the link's physical dev_t. It this is a VLAN, get the dev_t of the
 * link this VLAN is created on.
 */
int
dls_devnet_phydev(datalink_id_t vlanid, dev_t *devp)
{
	dls_devnet_t	*ddp;
	int		err;

	if ((err = dls_devnet_hold_tmp(vlanid, &ddp)) != 0)
		return (err);

	err = dls_mgmt_get_phydev(ddp->dd_linkid, devp);
	dls_devnet_rele_tmp(ddp);
	return (err);
}

/*
 * Handle the renaming requests.  There are two rename cases:
 *
 * 1. Request to rename a valid link (id1) to an non-existent link name
 *    (id2). In this case id2 is DATALINK_INVALID_LINKID.  Just check whether
 *    id1 is held by any applications.
 *
 *    In this case, the link's kstats need to be updated using the given name.
 *
 * 2. Request to rename a valid link (id1) to the name of a REMOVED
 *    physical link (id2). In this case, check htat id1 and its associated
 *    mac is not held by any application, and update the link's linkid to id2.
 *
 *    This case does not change the <link name, linkid> mapping, so the link's
 *    kstats need to be updated with using name associated the given id2.
 */
int
dls_devnet_rename(datalink_id_t id1, datalink_id_t id2, const char *link)
{
	dls_dev_handle_t	ddh = NULL;
	char			linkname[MAXLINKNAMELEN];
	int			err = 0;
	dev_t			phydev = 0;
	dls_devnet_t		*ddp;
	mac_handle_t		mh;
	mod_hash_val_t		val;

	/*
	 * In the second case, id2 must be a REMOVED physical link.
	 */
	if ((id2 != DATALINK_INVALID_LINKID) &&
	    (dls_mgmt_get_phydev(id2, &phydev) == 0) &&
	    softmac_hold_device(phydev, &ddh) == 0) {
		softmac_rele_device(ddh);
		return (EEXIST);
	}

	/*
	 * Hold id1 to prevent it from being detached (if a physical link).
	 */
	if (dls_mgmt_get_phydev(id1, &phydev) == 0)
		(void) softmac_hold_device(phydev, &ddh);

	rw_enter(&i_dls_devnet_lock, RW_WRITER);
	if ((err = mod_hash_find(i_dls_devnet_id_hash,
	    (mod_hash_key_t)(uintptr_t)id1, (mod_hash_val_t *)&ddp)) != 0) {
		ASSERT(err == MH_ERR_NOTFOUND);
		err = ENOENT;
		goto done;
	}

	/*
	 * Return EBUSY if any applications have this link open.
	 */
	if ((ddp->dd_explicit && ddp->dd_ref > 1) ||
	    (!ddp->dd_explicit && ddp->dd_ref > 0)) {
		err = EBUSY;
		goto done;
	}

	if (id2 == DATALINK_INVALID_LINKID) {
		(void) strlcpy(linkname, link, sizeof (linkname));
		goto done;
	}

	/*
	 * The second case, check whether the MAC is used by any MAC
	 * user.  This must be a physical link so ddh must not be NULL.
	 */
	if (ddh == NULL) {
		err = EINVAL;
		goto done;
	}

	if ((err = mac_open(ddp->dd_mac, &mh)) != 0)
		goto done;

	/*
	 * We release the reference of the MAC which mac_open() is
	 * holding. Note that this mac will not be unregistered
	 * because the physical device is hold.
	 */
	mac_close(mh);

	/*
	 * Check if there is any other MAC clients, if not, hold this mac
	 * exclusively until we are done.
	 */
	if ((err = mac_hold_exclusive(mh)) != 0)
		goto done;

	/*
	 * Update the link's linkid.
	 */
	if ((err = mod_hash_find(i_dls_devnet_id_hash,
	    (mod_hash_key_t)(uintptr_t)id2, &val)) != MH_ERR_NOTFOUND) {
		mac_rele_exclusive(mh);
		err = EEXIST;
		goto done;
	}

	err = dls_mgmt_get_linkinfo(id2, linkname, NULL, NULL, NULL);
	if (err != 0) {
		mac_rele_exclusive(mh);
		goto done;
	}

	(void) mod_hash_remove(i_dls_devnet_id_hash,
	    (mod_hash_key_t)(uintptr_t)id1, &val);

	ddp->dd_vlanid = id2;
	(void) mod_hash_insert(i_dls_devnet_id_hash,
	    (mod_hash_key_t)(uintptr_t)ddp->dd_vlanid, (mod_hash_val_t)ddp);

	mac_rele_exclusive(mh);

done:
	/*
	 * Change the name of the kstat based on the new link name.
	 */
	if (err == 0)
		dls_devnet_stat_rename(ddp, linkname);

	rw_exit(&i_dls_devnet_lock);
	softmac_rele_device(ddh);
	return (err);
}

int
dls_devnet_setzid(const char *link, zoneid_t zid)
{
	dls_devnet_t	*ddp;
	int		err;
	zoneid_t	old_zid;

	if ((err = dls_devnet_hold_by_name(link, &ddp, GLOBAL_ZONEID)) != 0)
		return (err);

	mutex_enter(&ddp->dd_zid_mutex);
	if ((old_zid = ddp->dd_zid) == zid) {
		mutex_exit(&ddp->dd_zid_mutex);
		dls_devnet_rele(ddp);
		return (0);
	}

	if ((err = dls_vlan_setzid(ddp->dd_mac, ddp->dd_vid, zid)) != 0) {
		mutex_exit(&ddp->dd_zid_mutex);
		dls_devnet_rele(ddp);
		return (err);
	}

	ddp->dd_zid = zid;
	devnet_need_rebuild = B_TRUE;
	mutex_exit(&ddp->dd_zid_mutex);

	/*
	 * Keep this open reference only if it belonged to the global zone
	 * and is now assigned to a non-global zone.
	 */
	if (old_zid != GLOBAL_ZONEID || zid == GLOBAL_ZONEID)
		dls_devnet_rele(ddp);

	/*
	 * Then release this link if it belonged to an non-global zone
	 * but is now assigned back to the global zone.
	 */
	if (old_zid != GLOBAL_ZONEID && zid == GLOBAL_ZONEID)
		dls_devnet_rele(ddp);

	return (0);
}

int
dls_devnet_getzid(datalink_id_t linkid, zoneid_t *zidp)
{
	dls_devnet_t	*ddp;
	int		err;

	if ((err = dls_devnet_hold_tmp(linkid, &ddp)) != 0)
		return (err);

	mutex_enter(&ddp->dd_zid_mutex);
	*zidp = ddp->dd_zid;
	mutex_exit(&ddp->dd_zid_mutex);

	dls_devnet_rele_tmp(ddp);
	return (0);
}

/*
 * Access a vanity naming node.
 */
int
dls_devnet_open(const char *link, dls_dl_handle_t *dhp, dev_t *devp)
{
	dls_devnet_t	*ddp;
	dls_vlan_t	*dvp;
	zoneid_t	zid = getzoneid();
	int		err;

	if ((err = dls_devnet_hold_by_name(link, &ddp, zid)) != 0)
		return (err);

	/*
	 * Opening a link that does not belong to the current non-global zone
	 * is not allowed.
	 */
	if (zid != GLOBAL_ZONEID && ddp->dd_zid != zid) {
		dls_devnet_rele(ddp);
		return (ENOENT);
	}

	err = dls_vlan_hold(ddp->dd_mac, ddp->dd_vid, &dvp, B_FALSE, B_TRUE);
	if (err != 0) {
		dls_devnet_rele(ddp);
		return (err);
	}

	*dhp = ddp;
	*devp = dvp->dv_dev;
	return (0);
}

/*
 * Close access to a vanity naming node.
 */
void
dls_devnet_close(dls_dl_handle_t dlh)
{
	dls_devnet_t	*ddp = dlh;
	dls_vlan_t	*dvp;

	/*
	 * The VLAN is hold in dls_open_devnet_link().
	 */
	VERIFY((dls_vlan_hold(ddp->dd_mac, ddp->dd_vid, &dvp, B_FALSE,
	    B_FALSE)) == 0);
	dls_vlan_rele(dvp);
	dls_vlan_rele(dvp);
	dls_devnet_rele(ddp);
}

/*
 * This is used by /dev/net to rebuild the nodes for readdir().  It is not
 * critical and no protection is needed.
 */
boolean_t
dls_devnet_rebuild()
{
	boolean_t updated = devnet_need_rebuild;

	devnet_need_rebuild = B_FALSE;
	return (updated);
}

int
dls_devnet_create(mac_handle_t mh, datalink_id_t linkid)
{
	int		err;

	if ((err = dls_vlan_create(mac_name(mh), 0, B_FALSE)) != 0)
		return (err);

	err = dls_devnet_set(mac_name(mh), 0, linkid, linkid, NULL, NULL);
	if (err != 0)
		(void) dls_vlan_destroy(mac_name(mh), 0);

	return (err);
}

/*
 * Set the linkid of the dls_devnet_t and add it into the i_dls_devnet_id_hash.
 * This is called in the case that the dlmgmtd daemon is started later than
 * the physical devices get attached, and the linkid is only known after the
 * daemon starts.
 */
int
dls_devnet_recreate(mac_handle_t mh, datalink_id_t linkid)
{
	ASSERT(linkid != DATALINK_INVALID_LINKID);
	return (dls_devnet_set(mac_name(mh), 0, linkid, linkid, NULL, NULL));
}

int
dls_devnet_destroy(mac_handle_t mh, datalink_id_t *idp)
{
	int		err;

	*idp = DATALINK_INVALID_LINKID;
	err = dls_devnet_unset(mac_name(mh), 0, idp);
	if (err != 0 && err != ENOENT)
		return (err);

	if ((err = dls_vlan_destroy(mac_name(mh), 0)) == 0)
		return (0);

	(void) dls_devnet_set(mac_name(mh), 0, *idp, *idp, NULL, NULL);
	return (err);
}

int
dls_devnet_create_vlan(datalink_id_t vlanid, datalink_id_t linkid,
    uint16_t vid, boolean_t force)
{
	dls_devnet_t	*lnddp, *ddp;
	dls_vlan_t	*dvp;
	int		err;

	/*
	 * Hold the link the VLAN is being created on (which must not be a
	 * VLAN).
	 */
	ASSERT(vid != VLAN_ID_NONE);
	if ((err = dls_devnet_hold_tmp(linkid, &lnddp)) != 0)
		return (err);

	if (lnddp->dd_vid != VLAN_ID_NONE) {
		err = EINVAL;
		goto done;
	}

	/*
	 * A new link.
	 */
	err = dls_devnet_set(lnddp->dd_mac, vid, vlanid, linkid, NULL, &ddp);
	if (err != 0)
		goto done;

	/*
	 * Hold the dls_vlan_t (and create it if needed).
	 */
	err = dls_vlan_hold(ddp->dd_mac, ddp->dd_vid, &dvp, force, B_TRUE);
	if (err != 0)
		VERIFY(dls_devnet_unset(lnddp->dd_mac, vid, NULL) == 0);

done:
	dls_devnet_rele_tmp(lnddp);
	return (err);
}

int
dls_devnet_destroy_vlan(datalink_id_t vlanid)
{
	char		macname[MAXNAMELEN];
	uint16_t	vid;
	dls_devnet_t	*ddp;
	dls_vlan_t	*dvp;
	int		err;

	if ((err = dls_devnet_hold_tmp(vlanid, &ddp)) != 0)
		return (err);

	if (ddp->dd_vid == VLAN_ID_NONE) {
		dls_devnet_rele_tmp(ddp);
		return (EINVAL);
	}

	if (!ddp->dd_explicit) {
		dls_devnet_rele_tmp(ddp);
		return (EBUSY);
	}

	(void) strncpy(macname, ddp->dd_mac, MAXNAMELEN);
	vid = ddp->dd_vid;

	/*
	 * It is safe to release the temporary reference we just held, as the
	 * reference from VLAN creation is still held.
	 */
	dls_devnet_rele_tmp(ddp);

	if ((err = dls_devnet_unset(macname, vid, NULL)) != 0)
		return (err);

	/*
	 * This VLAN has already been held as the result of VLAN creation.
	 */
	VERIFY(dls_vlan_hold(macname, vid, &dvp, B_FALSE, B_FALSE) == 0);

	/*
	 * Release the reference which was held when this VLAN was created,
	 * and the reference which was just held.
	 */
	dls_vlan_rele(dvp);
	dls_vlan_rele(dvp);
	return (0);
}

const char *
dls_devnet_mac(dls_dl_handle_t ddh)
{
	return (ddh->dd_mac);
}

uint16_t
dls_devnet_vid(dls_dl_handle_t ddh)
{
	return (ddh->dd_vid);
}

datalink_id_t
dls_devnet_linkid(dls_dl_handle_t ddh)
{
	return (ddh->dd_linkid);
}

boolean_t
dls_devnet_is_explicit(dls_dl_handle_t ddh)
{
	return (ddh->dd_explicit);
}
