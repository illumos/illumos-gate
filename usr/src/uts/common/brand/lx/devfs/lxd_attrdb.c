/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/cred.h>
#include <sys/pathname.h>
#include <sys/debug.h>
#include <sys/sdt.h>
#include <fs/fs_subr.h>

#include "lxd.h"

#define	LX_ATTR_FILE		"/etc/.lxd_dev_attr"

#define	RD_BUFSIZE	MAXPATHLEN
#define	ENTRY_BUFSIZE	(MAXPATHLEN + 32)

static int
lxd_db_open(int fmode, vnode_t **vpp)
{
	return (vn_open(LX_ATTR_FILE, UIO_SYSSPACE, fmode,
	    (int)(0644 & MODEMASK), vpp, CRCREAT, PTOU(curproc)->u_cmask));
}

static int
lxd_wr_entry(vnode_t *wvn, off_t offset, char *entry)
{
	int len, err;
	struct uio auio;
	struct iovec aiov;

	len = strlen(entry);
	aiov.iov_base = entry;
	aiov.iov_len = len;

	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = offset;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_resid = len;
	auio.uio_llimit = curproc->p_fsz_ctl;
	auio.uio_fmode = FWRITE;
	auio.uio_extflg = UIO_COPY_DEFAULT;

	(void) VOP_RWLOCK(wvn, V_WRITELOCK_TRUE, NULL);
	err = VOP_WRITE(wvn, &auio, FAPPEND, CRED(), NULL);
	VOP_RWUNLOCK(wvn, V_WRITELOCK_TRUE, NULL);

	if (err != 0)
		return (0);
	return (len);
}

/*
 * Given an entry, apply a uid, gid and mode change to the given device. There
 * is no strtok in the kernel but it's easy to tokenize the entry ourselves.
 *
 * entries have the form (newline removed by caller):
 * path uid gid mode\0
 */
static int
lxd_apply_entry(char *entry, char **dpath, uid_t *uidp, gid_t *gidp,
    mode_t *modep)
{
	char *dp, *up, *gp, *mp, *ep;
	long uid, gid, mode;
	int error, res = 0;
	vnode_t *vp;
	vattr_t va;

	dp = entry;

	/* find and delimit the first field (device name) */
	for (up = dp; *up != ' ' && *up != '\0'; up++)
		;
	if (*up != ' ')
		return (-1);
	*up++ = '\0';

	/* find and delimit the second field (uid) */
	for (gp = up; *gp != ' ' && *gp != '\0'; gp++)
		;
	if (*gp != ' ')
		return (-1);
	*gp++ = '\0';

	/* find and delimit the third field (gid) */
	for (mp = gp; *mp != ' ' && *mp != '\0'; mp++)
		;
	if (*mp != ' ')
		return (-1);
	*mp++ = '\0';

	/* validate the fourth field (mode) */
	ep = mp + strlen(mp);
	if (*ep != '\0')
		return (-1);

	if (*dp != '/')
		return (-1);

	error = ddi_strtol(up, &ep, 10, &uid);
	if (error != 0 || *ep != '\0' || uid > MAXUID || uid < 0)
		return (-1);

	error = ddi_strtol(gp, &ep, 10, &gid);
	if (error != 0 || *ep != '\0' || gid > MAXUID || gid < 0)
		return (-1);

	/* note that the mode is octal */
	error = ddi_strtol(mp, &ep, 8, &mode);
	if (error != 0 || *ep != '\0' || mode > 0777 || mode < 0)
		return (-1);

	if (lookupname(dp, UIO_SYSSPACE, FOLLOW, NULLVPP, &vp) != 0) {
		/*
		 * It's likely the device is no longer visible to the zone.
		 * No matter the reason, we indicate failure.
		 */
		return (-1);
	}

	va.va_mask =  AT_UID | AT_GID | AT_MODE;
	va.va_uid = (uid_t)uid;
	va.va_gid = (gid_t)gid;
	va.va_mode = (mode_t)mode;

	if (VOP_SETATTR(vp, &va, 0, CRED(), NULL) != 0)
		res = -1;

	VN_RELE(vp);

	*dpath = dp;
	*uidp = (uid_t)uid;
	*gidp = (gid_t)gid;
	*modep = (mode_t)mode;
	return (res);
}

/*
 * Return true if this is a pre-existing record.
 */
static boolean_t
lxd_save_devattr(lxd_mnt_t *lxdm, char *dpath, uid_t uid, gid_t gid,
    mode_t mode)
{
	lxd_dev_attr_t *da;

	da = list_head(&lxdm->lxdm_devattrs);
	while (da != NULL) {
		if (strcmp(dpath, da->lxda_name) == 0) {
			da->lxda_uid = uid;
			da->lxda_gid = gid;
			da->lxda_mode = mode;
			return (B_TRUE);
		}
		da = list_next(&lxdm->lxdm_devattrs, da);
	}

	da = kmem_zalloc(sizeof (lxd_dev_attr_t), KM_SLEEP);
	(void) strlcpy(da->lxda_name, dpath, sizeof (da->lxda_name));
	da->lxda_uid = uid;
	da->lxda_gid = gid;
	da->lxda_mode = mode;

	list_insert_tail(&lxdm->lxdm_devattrs, da);
	return (B_FALSE);
}

static void
lxd_save_db(lxd_mnt_t *lxdm)
{
	lxd_dev_attr_t *da;
	char *entry;
	vnode_t *wvn;
	off_t woff = 0;

	if (list_is_empty(&lxdm->lxdm_devattrs)) {
		/* The attribute file is no longer needed. */
		(void) vn_remove(LX_ATTR_FILE, UIO_SYSSPACE, RMFILE);
		return;
	}

	if (lxd_db_open(FWRITE | FCREAT | FTRUNC, &wvn) != 0)
		return;

	entry = kmem_alloc(ENTRY_BUFSIZE, KM_SLEEP);

	woff = lxd_wr_entry(wvn, woff, "# DO NOT EDIT: this file is "
	    "automatically maintained for lx container devices\n");

	da = list_head(&lxdm->lxdm_devattrs);
	while (da != NULL) {
		(void) snprintf(entry, ENTRY_BUFSIZE, "%s %d %d %o\n",
		    da->lxda_name, da->lxda_uid, da->lxda_gid,
		    da->lxda_mode & 0777);
		woff += lxd_wr_entry(wvn, woff, entry);
		da = list_next(&lxdm->lxdm_devattrs, da);
	}

	(void) VOP_CLOSE(wvn, FWRITE, 1, woff, CRED(), NULL);

	kmem_free(entry, ENTRY_BUFSIZE);
}

/*
 * This function records the uid, gid and mode information for an lx devfs
 * block device node after a chown/chmod setattr operation so that these
 * changes can be persistent across reboots. Since the actual setattr has
 * already suceeded, the tracking of these changes is done on a "best effort"
 * basis. That is, if we fail to record the change for some reason, the setattr
 * will still return success. The vp passed in is the "real vp" for the back
 * device node.
 */
void
lxd_save_attrs(lxd_mnt_t *lxdm, vnode_t *vp)
{
	vattr_t va;
	char devpath[MAXPATHLEN];

	/* the path returned is relative to the zone's root */
	if (vnodetopath(curproc->p_zone->zone_rootvp, vp, devpath,
	    sizeof (devpath), CRED()) != 0)
		return;

	va.va_mask = AT_MODE | AT_UID | AT_GID;

	/*
	 * We just set attrs, so the getattr shouldn't fail. If the device
	 * is not a block device we don't persist the change.
	 */
	if (VOP_GETATTR(vp, &va, 0, CRED(), NULL) != 0 ||
	    ((va.va_mode & S_IFBLK) != S_IFBLK))
		return;

	/*
	 * We serialize all updates to the attribute DB file. In practice this
	 * should not be a problem since there is rarely concurrent device
	 * file mode changes.
	 */
	mutex_enter(&lxdm->lxdm_attrlck);

	(void) lxd_save_devattr(lxdm, devpath, va.va_uid, va.va_gid,
	    va.va_mode & 0777);
	lxd_save_db(lxdm);

	mutex_exit(&lxdm->lxdm_attrlck);
}

/*
 * Re-apply the persistent attribute settings to the devices when this lx
 * devfs is mounted. As with lxd_save_attrs, this is done on a best effort and
 * we won't prevent the mount if there is a problem. No locking is needed
 * while reading the DB file since this action is performed during the
 * mount of the devfs.
 */
void
lxd_apply_db(lxd_mnt_t *lxdm)
{
	vnode_t *rvn;
	char *buf, *entry, *bp, *ep;
	struct uio auio;
	struct iovec aiov;
	size_t cnt, len, ecnt, roff;
	char *devpath;
	uid_t uid;
	gid_t gid;
	mode_t mode;
	boolean_t needs_update = B_FALSE;

	if (lxd_db_open(FREAD, &rvn) != 0)
		return;

	buf = kmem_alloc(RD_BUFSIZE, KM_SLEEP);
	entry = kmem_alloc(ENTRY_BUFSIZE, KM_SLEEP);

	roff = 0;
	ep = entry;
	ecnt = 0;
	(void) VOP_RWLOCK(rvn, V_WRITELOCK_FALSE, NULL);
loop:
	aiov.iov_base = buf;
	aiov.iov_len = RD_BUFSIZE;

	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = roff;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_resid = RD_BUFSIZE;
	auio.uio_fmode = 0;
	auio.uio_extflg = UIO_COPY_CACHED;

	(void) VOP_READ(rvn, &auio, 0, CRED(), NULL);

	len = RD_BUFSIZE - auio.uio_resid;
	roff += len;

	if (len > 0) {
		for (bp = buf, cnt = 0; cnt < len; bp++, cnt++) {

			/*
			 * We have an improperly formed entry in the file (too
			 * long). In an attempt to recover we reset the entry
			 * pointer so we can read the rest of the line and try
			 * to absorb the bad line. The code in lxd_apply_entry
			 * will handle any malformed or inapplicable entries.
			 */
			if (ecnt >= (ENTRY_BUFSIZE - 1)) {
				ep = entry;
				ecnt = 0;
				needs_update = B_TRUE;
			}

			if (*bp == '\n') {
				*ep = '\0';

				/* skip comments */
				if (entry[0] != '#') {
					if (lxd_apply_entry(entry, &devpath,
					    &uid, &gid, &mode) != 0 ||
					    lxd_save_devattr(lxdm, devpath,
					    uid, gid, mode)) {
						/*
						 * An invalid entry, a
						 * non-existent device node or
						 * a duplicate entry.
						 */
						needs_update = B_TRUE;
					}
				}
				ep = entry;
				ecnt = 0;
			} else {
				*ep++ = *bp;
				ecnt++;
			}
		}
		goto loop;
	}
	VOP_RWUNLOCK(rvn, V_WRITELOCK_FALSE, NULL);

	kmem_free(buf, RD_BUFSIZE);
	kmem_free(entry, ENTRY_BUFSIZE);

	(void) VOP_CLOSE(rvn, FREAD, 1, 0, CRED(), NULL);

	if (needs_update)
		lxd_save_db(lxdm);
}
