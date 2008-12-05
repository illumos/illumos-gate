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
#include <sys/softmac.h>
#include <sys/dls.h>
#include <sys/dls_impl.h>

/*
 * This vanity name management module is treated as part of the GLD framework
 * and we don't hold any GLD framework lock across a call to any mac
 * function that needs to acquire the mac perimeter. The hierarchy is
 * mac perimeter -> framework locks
 */

static kmem_cache_t	*i_dls_devnet_cachep;
static kmutex_t		i_dls_mgmt_lock;
static krwlock_t	i_dls_devnet_lock;
static mod_hash_t	*i_dls_devnet_id_hash;
static mod_hash_t	*i_dls_devnet_hash;

boolean_t		devnet_need_rebuild;

#define	VLAN_HASHSZ	67	/* prime */

/* Upcall door handle */
static door_handle_t	dls_mgmt_dh = NULL;

#define	DD_CONDEMNED	0x1

/*
 * This structure is used to keep the <linkid, macname> mapping.
 */
typedef struct dls_devnet_s {
	datalink_id_t	dd_linkid;
	char		dd_mac[MAXNAMELEN];
	kstat_t		*dd_ksp;
	uint32_t	dd_ref;

	kmutex_t	dd_mutex;
	kcondvar_t	dd_cv;
	uint32_t	dd_tref;
	uint_t		dd_flags;

	zoneid_t	dd_zid;

	boolean_t	dd_prop_loaded;
	taskqid_t	dd_prop_taskid;
} dls_devnet_t;


/*ARGSUSED*/
static int
i_dls_devnet_constructor(void *buf, void *arg, int kmflag)
{
	dls_devnet_t	*ddp = buf;

	bzero(buf, sizeof (dls_devnet_t));
	mutex_init(&ddp->dd_mutex, NULL, MUTEX_DEFAULT, NULL);
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
	mutex_destroy(&ddp->dd_mutex);
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
	 * Create a hash table, keyed by dd_linkid, of dls_devnet_t.
	 */
	i_dls_devnet_id_hash = mod_hash_create_idhash("dls_devnet_id_hash",
	    VLAN_HASHSZ, mod_hash_null_valdtor);

	/*
	 * Create a hash table, keyed by dd_mac
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
		if ((err = door_ki_upcall_limited(dh, &darg, kcred,
		    SIZE_MAX, 0)) == 0)
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
 * Request the datalink management daemon to push in
 * all properties associated with the link.
 * Returns a non-zero error code on failure.
 */
int
dls_mgmt_linkprop_init(datalink_id_t linkid)
{
	dlmgmt_door_linkprop_init_t	li;
	dlmgmt_linkprop_init_retval_t	retval;
	int				err;

	li.ld_cmd = DLMGMT_CMD_LINKPROP_INIT;
	li.ld_linkid = linkid;

	err = i_dls_mgmt_upcall(&li, sizeof (li), &retval, sizeof (retval));
	return (err);
}

static void
dls_devnet_prop_task(void *arg)
{
	dls_devnet_t		*ddp = arg;

	(void) dls_mgmt_linkprop_init(ddp->dd_linkid);

	mutex_enter(&ddp->dd_mutex);
	ddp->dd_prop_loaded = B_TRUE;
	ddp->dd_prop_taskid = NULL;
	cv_broadcast(&ddp->dd_cv);
	mutex_exit(&ddp->dd_mutex);
}

/*
 * Ensure property loading task is completed.
 */
void
dls_devnet_prop_task_wait(dls_dl_handle_t ddp)
{
	mutex_enter(&ddp->dd_mutex);
	while (ddp->dd_prop_taskid != NULL)
		cv_wait(&ddp->dd_cv, &ddp->dd_mutex);
	mutex_exit(&ddp->dd_mutex);
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

int
dls_devnet_hold_link(datalink_id_t linkid, dls_dl_handle_t *ddhp,
    dls_link_t **dlpp)
{
	dls_dl_handle_t	dlh;
	dls_link_t	*dlp;
	int		err;

	if ((err = dls_devnet_hold_tmp(linkid, &dlh)) != 0)
		return (err);

	if ((err = dls_link_hold(dls_devnet_mac(dlh), &dlp)) != 0) {
		dls_devnet_rele_tmp(dlh);
		return (err);
	}

	ASSERT(MAC_PERIM_HELD(dlp->dl_mh));

	*ddhp = dlh;
	*dlpp = dlp;
	return (0);
}

void
dls_devnet_rele_link(dls_dl_handle_t dlh, dls_link_t *dlp)
{
	ASSERT(MAC_PERIM_HELD(dlp->dl_mh));

	dls_link_rele(dlp);
	dls_devnet_rele_tmp(dlh);
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
	dls_link_t	*dlp;
	int		err;
	mac_perim_handle_t	mph;

	err = mac_perim_enter_by_macname(ddp->dd_mac, &mph);
	if (err != 0)
		return (err);

	err = dls_link_hold(ddp->dd_mac, &dlp);
	if (err != 0) {
		mac_perim_exit(mph);
		return (err);
	}

	err = dls_stat_update(ksp, dlp, rw);
	dls_link_rele(dlp);
	mac_perim_exit(mph);
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

	if ((dls_mgmt_get_linkinfo(ddp->dd_linkid, link,
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
 * Associate a linkid with a given link (identified by macname)
 */
static int
dls_devnet_set(const char *macname, datalink_id_t linkid, dls_devnet_t **ddpp)
{
	dls_devnet_t		*ddp = NULL;
	datalink_class_t	class;
	int			err;

	rw_enter(&i_dls_devnet_lock, RW_WRITER);
	if ((err = mod_hash_find(i_dls_devnet_hash,
	    (mod_hash_key_t)macname, (mod_hash_val_t *)&ddp)) == 0) {
		if (ddp->dd_linkid != DATALINK_INVALID_LINKID) {
			err = EEXIST;
			goto done;
		}

		/*
		 * This might be a physical link that has already
		 * been created, but which does not have a linkid
		 * because dlmgmtd was not running when it was created.
		 */
		if ((err = dls_mgmt_get_linkinfo(linkid, NULL,
		    &class, NULL, NULL)) != 0) {
			goto done;
		}

		if (class != DATALINK_CLASS_PHYS) {
			err = EINVAL;
			goto done;
		}

		goto newphys;
	}
	ddp = kmem_cache_alloc(i_dls_devnet_cachep, KM_SLEEP);
	ddp->dd_tref = 0;
	ddp->dd_ref++;
	ddp->dd_zid = GLOBAL_ZONEID;
	(void) strncpy(ddp->dd_mac, macname, MAXNAMELEN);
	VERIFY(mod_hash_insert(i_dls_devnet_hash,
	    (mod_hash_key_t)ddp->dd_mac, (mod_hash_val_t)ddp) == 0);

newphys:
	if (linkid != DATALINK_INVALID_LINKID) {
		ddp->dd_linkid = linkid;
		VERIFY(mod_hash_insert(i_dls_devnet_id_hash,
		    (mod_hash_key_t)(uintptr_t)linkid,
		    (mod_hash_val_t)ddp) == 0);
		devnet_need_rebuild = B_TRUE;
		dls_devnet_stat_create(ddp);

		mutex_enter(&ddp->dd_mutex);
		if (!ddp->dd_prop_loaded && (ddp->dd_prop_taskid == NULL)) {
			ddp->dd_prop_taskid = taskq_dispatch(system_taskq,
			    dls_devnet_prop_task, ddp, TQ_SLEEP);
		}
		mutex_exit(&ddp->dd_mutex);
	}

	err = 0;
done:
	rw_exit(&i_dls_devnet_lock);
	if (err == 0 && ddpp != NULL)
		*ddpp = ddp;
	return (err);
}

/*
 * Disassociate a linkid with a given link (identified by macname)
 * This waits until temporary references to the dls_devnet_t are gone.
 */
static int
dls_devnet_unset(const char *macname, datalink_id_t *id, boolean_t wait)
{
	dls_devnet_t	*ddp;
	int		err;
	mod_hash_val_t	val;

	rw_enter(&i_dls_devnet_lock, RW_WRITER);
	if ((err = mod_hash_find(i_dls_devnet_hash,
	    (mod_hash_key_t)macname, (mod_hash_val_t *)&ddp)) != 0) {
		ASSERT(err == MH_ERR_NOTFOUND);
		rw_exit(&i_dls_devnet_lock);
		return (ENOENT);
	}

	mutex_enter(&ddp->dd_mutex);

	/*
	 * Make sure downcalls into softmac_create or softmac_destroy from
	 * devfs don't cv_wait on any devfs related condition for fear of
	 * deadlock. Return EBUSY if the asynchronous thread started for
	 * property loading as part of the post attach hasn't yet completed.
	 */
	ASSERT(ddp->dd_ref != 0);
	if ((ddp->dd_ref != 1) || (!wait &&
	    (ddp->dd_tref != 0 || ddp->dd_prop_taskid != NULL))) {
		mutex_exit(&ddp->dd_mutex);
		rw_exit(&i_dls_devnet_lock);
		return (EBUSY);
	}

	ddp->dd_flags |= DD_CONDEMNED;
	ddp->dd_ref--;
	*id = ddp->dd_linkid;

	/*
	 * Remove this dls_devnet_t from the hash table.
	 */
	VERIFY(mod_hash_remove(i_dls_devnet_hash,
	    (mod_hash_key_t)ddp->dd_mac, &val) == 0);

	if (ddp->dd_linkid != DATALINK_INVALID_LINKID) {
		VERIFY(mod_hash_remove(i_dls_devnet_id_hash,
		    (mod_hash_key_t)(uintptr_t)ddp->dd_linkid, &val) == 0);

		dls_devnet_stat_destroy(ddp);
		devnet_need_rebuild = B_TRUE;
	}
	rw_exit(&i_dls_devnet_lock);

	if (wait) {
		/*
		 * Wait until all temporary references are released.
		 */
		while ((ddp->dd_tref != 0) || (ddp->dd_prop_taskid != NULL))
			cv_wait(&ddp->dd_cv, &ddp->dd_mutex);
	} else {
		ASSERT(ddp->dd_tref == 0 && ddp->dd_prop_taskid == NULL);
	}

	ddp->dd_prop_loaded = B_FALSE;
	ddp->dd_linkid = DATALINK_INVALID_LINKID;
	ddp->dd_zid = GLOBAL_ZONEID;
	ddp->dd_flags = 0;
	mutex_exit(&ddp->dd_mutex);
	kmem_cache_free(i_dls_devnet_cachep, ddp);

	return (0);
}

static int
dls_devnet_hold_common(datalink_id_t linkid, dls_devnet_t **ddpp,
    boolean_t tmp_hold)
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

	mutex_enter(&ddp->dd_mutex);
	ASSERT(ddp->dd_ref > 0);
	if (ddp->dd_flags & DD_CONDEMNED) {
		mutex_exit(&ddp->dd_mutex);
		rw_exit(&i_dls_devnet_lock);
		softmac_rele_device(ddh);
		return (ENOENT);
	}
	if (tmp_hold)
		ddp->dd_tref++;
	else
		ddp->dd_ref++;
	mutex_exit(&ddp->dd_mutex);
	rw_exit(&i_dls_devnet_lock);

	softmac_rele_device(ddh);

	*ddpp = ddp;
	return (0);
}

int
dls_devnet_hold(datalink_id_t linkid, dls_devnet_t **ddpp)
{
	return (dls_devnet_hold_common(linkid, ddpp, B_FALSE));
}

/*
 * Hold the vanity naming structure (dls_devnet_t) temporarily.  The request to
 * delete the dls_devnet_t will wait until the temporary reference is released.
 */
int
dls_devnet_hold_tmp(datalink_id_t linkid, dls_devnet_t **ddpp)
{
	return (dls_devnet_hold_common(linkid, ddpp, B_TRUE));
}

/*
 * This funtion is called when a DLS client tries to open a device node.
 * This dev_t could a result of a /dev/net node access (returned by
 * devnet_create_rvp->dls_devnet_open()) or a direct /dev node access.
 * In both cases, this function bumps up the reference count of the
 * dls_devnet_t structure. The reference is held as long as the device node
 * is open. In the case of /dev/net while it is true that the initial reference
 * is held when the devnet_create_rvp->dls_devnet_open call happens, this
 * initial reference is released immediately in devnet_inactive_callback ->
 * dls_devnet_close(). (Note that devnet_inactive_callback() is called right
 * after dld_open completes, not when the /dev/net node is being closed).
 * To undo this function, call dls_devnet_rele()
 */
int
dls_devnet_hold_by_dev(dev_t dev, dls_dl_handle_t *ddhp)
{
	char			name[MAXNAMELEN];
	char			*drv;
	dls_dev_handle_t	ddh = NULL;
	dls_devnet_t		*ddp;
	int			err;

	if ((drv = ddi_major_to_name(getmajor(dev))) == NULL)
		return (EINVAL);

	(void) snprintf(name, MAXNAMELEN, "%s%d", drv, getminor(dev) - 1);

	/*
	 * Hold this link to prevent it being detached in case of a
	 * GLDv3 physical link.
	 */
	if (getminor(dev) - 1 < MAC_MAX_MINOR)
		(void) softmac_hold_device(dev, &ddh);

	rw_enter(&i_dls_devnet_lock, RW_WRITER);
	if ((err = mod_hash_find(i_dls_devnet_hash,
	    (mod_hash_key_t)name, (mod_hash_val_t *)&ddp)) != 0) {
		ASSERT(err == MH_ERR_NOTFOUND);
		rw_exit(&i_dls_devnet_lock);
		softmac_rele_device(ddh);
		return (ENOENT);
	}
	mutex_enter(&ddp->dd_mutex);
	ASSERT(ddp->dd_ref > 0);
	if (ddp->dd_flags & DD_CONDEMNED) {
		mutex_exit(&ddp->dd_mutex);
		rw_exit(&i_dls_devnet_lock);
		softmac_rele_device(ddh);
		return (ENOENT);
	}
	ddp->dd_ref++;
	mutex_exit(&ddp->dd_mutex);
	rw_exit(&i_dls_devnet_lock);

	softmac_rele_device(ddh);

	*ddhp = ddp;
	return (0);
}

void
dls_devnet_rele(dls_devnet_t *ddp)
{
	mutex_enter(&ddp->dd_mutex);
	ASSERT(ddp->dd_ref > 1);
	ddp->dd_ref--;
	mutex_exit(&ddp->dd_mutex);
}

static int
dls_devnet_hold_by_name(const char *link, dls_devnet_t **ddpp)
{
	char			drv[MAXLINKNAMELEN];
	uint_t			ppa;
	major_t			major;
	dev_t			phy_dev, tmp_dev;
	datalink_id_t		linkid;
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

	/*
	 * If this link:
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
	if ((err = dls_mgmt_get_linkid(link, &linkid)) != 0 ||
	    (err = dls_mgmt_get_phydev(linkid, &tmp_dev)) != 0) {
		softmac_rele_device(ddh);
		return (err);
	}
	if (tmp_dev != phy_dev) {
		softmac_rele_device(ddh);
		return (ENOENT);
	}

	err = dls_devnet_hold(linkid, ddpp);
	softmac_rele_device(ddh);
	return (err);
}

int
dls_devnet_macname2linkid(const char *macname, datalink_id_t *linkidp)
{
	dls_devnet_t	*ddp;

	rw_enter(&i_dls_devnet_lock, RW_READER);
	if (mod_hash_find(i_dls_devnet_hash, (mod_hash_key_t)macname,
	    (mod_hash_val_t *)&ddp) != 0) {
		rw_exit(&i_dls_devnet_lock);
		return (ENOENT);
	}

	*linkidp = ddp->dd_linkid;
	rw_exit(&i_dls_devnet_lock);
	return (0);
}


/*
 * Get linkid for the given dev.
 */
int
dls_devnet_dev2linkid(dev_t dev, datalink_id_t *linkidp)
{
	char	macname[MAXNAMELEN];
	char	*drv;

	if ((drv = ddi_major_to_name(getmajor(dev))) == NULL)
		return (EINVAL);

	(void) snprintf(macname, MAXNAMELEN, "%s%d", drv, getminor(dev) - 1);
	return (dls_devnet_macname2linkid(macname, linkidp));
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
 *    physical link (id2). In this case, check that id1 and its associated
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
	mac_perim_handle_t	mph = NULL;
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

	/*
	 * The framework does not hold hold locks across calls to the
	 * mac perimeter, hence enter the perimeter first. This also waits
	 * for the property loading to finish.
	 */
	if ((err = mac_perim_enter_by_linkid(id1, &mph)) != 0)
		goto done;

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
	if (ddp->dd_ref > 1) {
		err = EBUSY;
		goto done;
	}

	if (id2 == DATALINK_INVALID_LINKID) {
		(void) strlcpy(linkname, link, sizeof (linkname));

		/* rename mac client name and its flow if exists */
		if ((err = mac_open(ddp->dd_mac, &mh)) != 0)
			goto done;
		(void) mac_rename_primary(mh, link);
		mac_close(mh);
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
	 * because the physical device is held.
	 */
	mac_close(mh);

	/*
	 * Check if there is any other MAC clients, if not, hold this mac
	 * exclusively until we are done.
	 */
	if ((err = mac_mark_exclusive(mh)) != 0)
		goto done;

	/*
	 * Update the link's linkid.
	 */
	if ((err = mod_hash_find(i_dls_devnet_id_hash,
	    (mod_hash_key_t)(uintptr_t)id2, &val)) != MH_ERR_NOTFOUND) {
		mac_unmark_exclusive(mh);
		err = EEXIST;
		goto done;
	}

	err = dls_mgmt_get_linkinfo(id2, linkname, NULL, NULL, NULL);
	if (err != 0) {
		mac_unmark_exclusive(mh);
		goto done;
	}

	(void) mod_hash_remove(i_dls_devnet_id_hash,
	    (mod_hash_key_t)(uintptr_t)id1, &val);

	ddp->dd_linkid = id2;
	(void) mod_hash_insert(i_dls_devnet_id_hash,
	    (mod_hash_key_t)(uintptr_t)ddp->dd_linkid, (mod_hash_val_t)ddp);

	mac_unmark_exclusive(mh);

	/* load properties for new id */
	mutex_enter(&ddp->dd_mutex);
	ddp->dd_prop_loaded = B_FALSE;
	ddp->dd_prop_taskid = taskq_dispatch(system_taskq,
	    dls_devnet_prop_task, ddp, TQ_SLEEP);
	mutex_exit(&ddp->dd_mutex);

done:
	/*
	 * Change the name of the kstat based on the new link name.
	 */
	if (err == 0)
		dls_devnet_stat_rename(ddp, linkname);

	rw_exit(&i_dls_devnet_lock);
	if (mph != NULL)
		mac_perim_exit(mph);
	softmac_rele_device(ddh);
	return (err);
}

int
dls_devnet_setzid(const char *link, zoneid_t zid)
{
	dls_devnet_t	*ddp;
	int		err;
	zoneid_t	old_zid;
	mac_perim_handle_t	mph;

	if ((err = dls_devnet_hold_by_name(link, &ddp)) != 0)
		return (err);

	err = mac_perim_enter_by_macname(ddp->dd_mac, &mph);
	if (err != 0)
		return (err);

	if ((old_zid = ddp->dd_zid) == zid) {
		mac_perim_exit(mph);
		dls_devnet_rele(ddp);
		return (0);
	}

	if ((err = dls_link_setzid(ddp->dd_mac, zid)) != 0) {
		mac_perim_exit(mph);
		dls_devnet_rele(ddp);
		return (err);
	}

	ddp->dd_zid = zid;
	devnet_need_rebuild = B_TRUE;
	mac_perim_exit(mph);

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

	*zidp = ddp->dd_zid;

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
	dls_link_t	*dlp;
	zoneid_t	zid = getzoneid();
	int		err;
	mac_perim_handle_t	mph;

	if ((err = dls_devnet_hold_by_name(link, &ddp)) != 0)
		return (err);

	dls_devnet_prop_task_wait(ddp);

	/*
	 * Opening a link that does not belong to the current non-global zone
	 * is not allowed.
	 */
	if (zid != GLOBAL_ZONEID && ddp->dd_zid != zid) {
		dls_devnet_rele(ddp);
		return (ENOENT);
	}

	err = mac_perim_enter_by_macname(ddp->dd_mac, &mph);
	if (err != 0) {
		dls_devnet_rele(ddp);
		return (err);
	}

	err = dls_link_hold_create(ddp->dd_mac, &dlp);
	mac_perim_exit(mph);

	if (err != 0) {
		dls_devnet_rele(ddp);
		return (err);
	}

	*dhp = ddp;
	*devp = dls_link_dev(dlp);
	return (0);
}

/*
 * Close access to a vanity naming node.
 */
void
dls_devnet_close(dls_dl_handle_t dlh)
{
	dls_devnet_t	*ddp = dlh;
	dls_link_t	*dlp;
	mac_perim_handle_t	mph;

	VERIFY(mac_perim_enter_by_macname(ddp->dd_mac, &mph) == 0);
	VERIFY(dls_link_hold(ddp->dd_mac, &dlp) == 0);

	/*
	 * One rele for the hold placed in dls_devnet_open, another for
	 * the hold done just above
	 */
	dls_link_rele(dlp);
	dls_link_rele(dlp);
	mac_perim_exit(mph);

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
	dls_link_t	*dlp;
	int		err;
	mac_perim_handle_t mph;

	mac_perim_enter_by_mh(mh, &mph);

	/*
	 * Make this association before we call dls_link_hold_create as
	 * we need to use the linkid to get the user name for the link
	 * when we create the MAC client.
	 */
	if ((err = dls_devnet_set(mac_name(mh), linkid, NULL)) != 0) {
		mac_perim_exit(mph);
		return (err);
	}
	if ((err = dls_link_hold_create(mac_name(mh), &dlp)) != 0) {
		(void) dls_devnet_unset(mac_name(mh), &linkid, B_TRUE);
		mac_perim_exit(mph);
		return (err);
	}
	mac_perim_exit(mph);
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
	return (dls_devnet_set(mac_name(mh), linkid, NULL));
}

int
dls_devnet_destroy(mac_handle_t mh, datalink_id_t *idp, boolean_t wait)
{
	int			err;
	mac_perim_handle_t	mph;

	*idp = DATALINK_INVALID_LINKID;
	err = dls_devnet_unset(mac_name(mh), idp, wait);
	if (err != 0 && err != ENOENT)
		return (err);

	mac_perim_enter_by_mh(mh, &mph);
	err = dls_link_rele_by_name(mac_name(mh));
	mac_perim_exit(mph);

	if (err == 0)
		return (0);

	(void) dls_devnet_set(mac_name(mh), *idp, NULL);
	return (err);
}

const char *
dls_devnet_mac(dls_dl_handle_t ddh)
{
	return (ddh->dd_mac);
}

datalink_id_t
dls_devnet_linkid(dls_dl_handle_t ddh)
{
	return (ddh->dd_linkid);
}
