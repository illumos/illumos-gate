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
 * Driver for Virtual Disk.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/proc.h>
#include <sys/t_lock.h>
#include <sys/dkio.h>
#include <sys/kmem.h>
#include <sys/utsname.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/vtoc.h>
#include <sys/efi_partition.h>
#include <sys/open.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/lvm/mdmn_commd.h>

#include <sys/lvm/mdvar.h>
#include <sys/lvm/md_rename.h>
#include <sys/lvm/md_names.h>
#include <sys/lvm/md_hotspares.h>

extern md_ops_t		**md_ops;
extern unit_t		md_nunits;
extern set_t		md_nsets;
extern int		md_nmedh;
extern md_set_t		md_set[];
extern md_set_io_t	md_set_io[];
extern int		md_status;
extern int		md_ioctl_cnt;
extern int		md_in_upgrade;
extern major_t		md_major;

/* md.c */
extern kmutex_t		md_mx;
extern kcondvar_t	md_cv;

/* md_hotspares.c */
extern	hot_spare_pool_t *find_hot_spare_pool(set_t setno, int hsp_id);

/* md_med.c */
extern int		med_addr_tab_nents;
extern int		med_get_t_size_ioctl(mddb_med_t_parm_t *tpp, int mode);
extern int		med_get_t_ioctl(mddb_med_t_parm_t *tpp, int mode);
extern int		med_set_t_ioctl(mddb_med_t_parm_t *tpp, int mode);
extern unit_t		md_get_nextunit(set_t setno);

static int		md_mn_commd_present;

/* md_mddb.c */
extern mddb_set_t	*mddb_setenter(set_t setno, int flag, int *errorcodep);
extern void		mddb_setexit(mddb_set_t *s);
extern md_krwlock_t	nm_lock;

/*
 * md_mn_is_commd_present:
 * ----------------------
 * Determine if commd is running on this node.
 *
 * Returns:
 *	1	if commd has been started
 *	0	if commd has not been started or has exited
 */
int
md_mn_is_commd_present(void)
{
	return (md_mn_commd_present ? 1 : 0);
}

/*
 * md_mn_clear_commd_present:
 * -------------------------
 * Clear the commd_present flag. Called only from a CPR request to suspend /
 * terminate a resync thread. We clear the md_mn_commd_present flag so that
 * any RPC request that was in transit can complete with a failure and _not_
 * result in an unexpected system panic.
 */
void
md_mn_clear_commd_present()
{
	md_mn_commd_present = 0;
}

/*
 * It is possible to pass in a minor number via the ioctl interface
 * and this minor number is used to reference elements in arrays.
 * Therefore we need to make sure that the value passed in is
 * correct within the array sizes, and array dereference. Not
 * doing so allows for incorrect values which may result in panics.
 */
static int
verify_minor(minor_t mnum)
{
	set_t	setno = MD_MIN2SET(mnum);

	/*
	 * Check the bounds.
	 */
	if (setno >= md_nsets || (MD_MIN2UNIT(mnum) >= md_nunits)) {
		return (EINVAL);
	}

	/* has the set been initialised ? */
	if ((md_get_setstatus(setno) & MD_SET_SNARFED) == 0)
		return (ENODEV);

	return (0);
}

static int
get_lb_inittime_ioctl(
	mddb_config_t	*cp
)
{
	set_t		setno = cp->c_setno;
	int		err;
	mddb_set_t	*s;

	if (setno >= md_nsets)
		return (-1);

	if ((s = mddb_setenter(setno, MDDB_MUSTEXIST, &err)) == NULL)
		return (-1);

	if (s->s_lbp == NULL) {
		mddb_setexit(s);
		return (-1);
	}

	cp->c_timestamp = s->s_lbp->lb_inittime;

	mddb_setexit(s);
	return (0);
}

static int
setnm_ioctl(mdnm_params_t *nm, int mode)
{
	char 	*name, *minorname = NULL;
	side_t	side;
	int	err = 0;
	void	*devid = NULL;
	int	devid_sz;

	/*
	 * Don't allow addition of new names to namespace during upgrade.
	 */
	if (MD_UPGRADE)  {
		return (EAGAIN);
	}

	mdclrerror(&nm->mde);

	if ((mode & FWRITE) == 0)
		return (EACCES);

	if (md_snarf_db_set(MD_LOCAL_SET, &nm->mde) != 0)
		return (0);

	if ((md_get_setstatus(nm->setno) & MD_SET_SNARFED) == 0)
		return (ENODEV);

	if (md_get_setstatus(nm->setno) & MD_SET_STALE)
		return (mdmddberror(&nm->mde, MDE_DB_STALE, NODEV32,
		    nm->setno));

	name = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	err = ddi_copyin((caddr_t)(uintptr_t)nm->devname, name,
	    (size_t)nm->devname_len, mode);
	if (err) {
		err = EFAULT;
		goto out;
	}

	if (nm->imp_flag) {
		if ((nm->devid == NULL) || (nm->minorname == NULL)) {
			err = EINVAL;
			goto out;
		}
		if (nm->devid) {
			devid_sz = nm->devid_size;
			devid = kmem_zalloc(devid_sz, KM_SLEEP);
			err = ddi_copyin((caddr_t)(uintptr_t)nm->devid,
			    devid, devid_sz, mode);
			if (err) {
				err = EFAULT;
				goto out;
			}
		}
		if (nm->minorname) {
			if (nm->minorname_len > MAXPATHLEN) {
				err = EINVAL;
				goto out;
			}
			minorname = kmem_zalloc(nm->minorname_len, KM_SLEEP);
			err = ddi_copyin((caddr_t)(uintptr_t)nm->minorname,
			    minorname, (size_t)nm->minorname_len, mode);
			if (err) {
				err = EFAULT;
				goto out;
			}
		}
	}

	if (nm->side == -1)
		side = mddb_getsidenum(nm->setno);
	else
		side = nm->side;

	if (strcmp(nm->drvnm, "") == 0) {
		char *drvnm;
		drvnm = ddi_major_to_name(nm->major);
		(void) strncpy(nm->drvnm, drvnm, sizeof (nm->drvnm));
	}

	nm->key = md_setdevname(nm->setno, side, nm->key, nm->drvnm,
	    nm->mnum, name, nm->imp_flag, (ddi_devid_t)devid, minorname,
	    0, &nm->mde);
	/*
	 * If we got an error from md_setdevname & md_setdevname did not
	 * set the error code, we'll default to MDE_DB_NOSPACE.
	 */
	if ((((int)nm->key) < 0) && mdisok(&nm->mde)) {
		err = mdmddberror(&nm->mde, MDE_DB_NOSPACE, NODEV32, nm->setno);
		goto out;
	}

out:
	kmem_free(name, MAXPATHLEN);
	if (devid) {
		kmem_free(devid, devid_sz);
	}
	if (minorname)
		kmem_free(minorname, nm->minorname_len);
	return (err);
}

static int
getnm_ioctl(
	mdnm_params_t	*nm,
	int		mode
)
{
	char		*name;
	side_t		side;
	md_dev64_t	dev = NODEV64;
	mdc_unit_t	*un;
	uint_t		id;
	char		*setname;
	int		err = 0;

	mdclrerror(&nm->mde);

	if (md_snarf_db_set(MD_LOCAL_SET, &nm->mde) != 0)
		return (0);

	if ((md_get_setstatus(nm->setno) & MD_SET_SNARFED) == 0)
		return (ENODEV);


	name = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	if (nm->side == -1)
		side = mddb_getsidenum(nm->setno);
	else
		side = nm->side;

	if (nm->drvnm[0] == '\0') {
		char *drvnm;

		if (MD_UPGRADE)
			drvnm = md_targ_major_to_name(nm->major);
		else
			drvnm = ddi_major_to_name(nm->major);
		if (drvnm != NULL)
			(void) strncpy(nm->drvnm, drvnm, sizeof (nm->drvnm));
	}

	if (nm->drvnm[0] != '\0') {
		if (MD_UPGRADE)
			dev = md_makedevice(md_targ_name_to_major(nm->drvnm),
			    nm->mnum);
		else
			dev = md_makedevice(ddi_name_to_major(nm->drvnm),
			    nm->mnum);
	}

	/*
	 * With the introduction of friendly names, all friendly named
	 * metadevices will have an entry in the name space. However,
	 * systems upgraded from pre-friendly name to a friendly name
	 * release won't have name space entries for pre-friendly name
	 * top level metadevices.
	 *
	 * So we search the name space for the our entry with either the
	 * given dev_t or key. If we can't find the entry, we'll try the
	 * un array to get information for our target metadevice. Note
	 * we only use the un array when searching by dev_t since a
	 * key implies an existing device which should have been
	 * found in the name space with the call md_getdevname.
	 */
	if (md_getdevname(nm->setno, side, nm->key, dev, name,
	    MAXPATHLEN) == 0) {
		err = md_getnment(nm->setno, side, nm->key, dev, nm->drvnm,
		    sizeof (nm->drvnm), &nm->major, &nm->mnum, &nm->retkey);
		if (err) {
			if (err < 0)
				err = EINVAL;
			goto out;
		}
	} else {
		if ((nm->key != MD_KEYWILD) ||
		    (md_set[MD_MIN2SET(nm->mnum)].s_un == NULL) ||
		    (MD_UNIT(nm->mnum) == NULL)) {
			err = ENOENT;
			goto out;
		}

		/*
		 * We're here because the mnum is of a pre-friendly
		 * name device. Make sure the major value is for
		 * metadevices.
		 */
		if (nm->major != md_major) {
			err = ENOENT;
			goto out;
		}

		/*
		 * get the unit number and setname to construct the
		 * fully qualified name for the metadevice.
		 */
		un = MD_UNIT(nm->mnum);
		id =  MD_MIN2UNIT(un->un_self_id);
		if (nm->setno != MD_LOCAL_SET) {
			setname = mddb_getsetname(nm->setno);
			(void) snprintf(name, MAXPATHLEN,
			    "/dev/md/%s/dsk/d%u", setname, id);
		} else {
			(void) snprintf(name, MAXPATHLEN,
			    "/dev/md/dsk/d%u", id);
		}
	}

	err = ddi_copyout(name, (caddr_t)(uintptr_t)nm->devname,
	    strlen(name) + 1, mode);
	if (err) {
		err = EFAULT;
		goto out;
	}

out:
	kmem_free(name, MAXPATHLEN);
	return (err);
}

static int
gethspnm_ioctl(
	mdhspnm_params_t	*nm,
	int			mode
)
{
	char			*name;
	char			*tmpname;
	char			*setname = NULL;
	side_t			side;
	hot_spare_pool_t	*hsp = NULL;
	mdkey_t			key = MD_KEYWILD;
	int			err = 0;

	mdclrerror(&nm->mde);

	if (md_snarf_db_set(MD_LOCAL_SET, &nm->mde) != 0)
		return (0);

	if ((md_get_setstatus(nm->setno) & MD_SET_SNARFED) == 0)
		return (ENODEV);

	name = kmem_zalloc(MAXPATHLEN, KM_SLEEP);

	if (nm->side == -1)
		side = mddb_getsidenum(nm->setno);
	else
		side = nm->side;

	/*
	 * Get the key from input hspid, use different macros
	 * since the hspid could be either a FN or pre-FN hspid.
	 */
	if (nm->hspid != MD_HSPID_WILD) {
		if (HSP_ID_IS_FN(nm->hspid))
			key = HSP_ID_TO_KEY(nm->hspid);
		else
			key = HSP_ID(nm->hspid);
	}

	/*
	 * Get the input name if we're searching by hsp name. Check
	 * that the input name length is less than MAXPATHLEN.
	 */
	if ((nm->hspid == MD_HSPID_WILD) &&
	    (nm->hspname_len <= MAXPATHLEN)) {
		err = ddi_copyin((caddr_t)(uintptr_t)nm->hspname,
		    name, (sizeof (char)) * nm->hspname_len, mode);

		/* Stop if ddi_copyin failed. */
		if (err) {
			err = EFAULT;
			goto out;
		}
	}

	/* Must have either a valid hspid or a name to continue */
	if ((nm->hspid == MD_HSPID_WILD) && (name[0] == '\0')) {
		err = EINVAL;
		goto out;
	}

	/*
	 * Try to find the hsp namespace entry corresponds to either
	 * the given hspid or name. If we can't find it, the hsp maybe
	 * a pre-friendly name hsp so we'll try to find it in the
	 * s_hsp array.
	 */
	if ((nm->hspid == MD_HSPID_WILD) || (HSP_ID_IS_FN(nm->hspid))) {

		if (md_gethspinfo(nm->setno, side, key, nm->drvnm,
		    &nm->ret_hspid, name) != 0) {
			/*
			 * If we were given a key for a FN hsp and
			 * couldn't find its entry, simply errored
			 * out.
			 */
			if (HSP_ID_IS_FN(nm->hspid)) {
				err = ENOENT;
				goto out;
			}

			/*
			 * Since md_gethspinfo failed and the hspid is
			 * not a FN hspid,  we must have a name for a
			 * pre-FN hotspare pool
			 */
			if (name[0] == '\0') {
				err = EINVAL;
				goto out;
			}

			tmpname = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
			if (nm->setno != MD_LOCAL_SET)
				setname = mddb_getsetname(nm->setno);

			hsp = (hot_spare_pool_t *)md_set[nm->setno].s_hsp;
			while (hsp != NULL) {
				/* Only use the pre-friendly name hsp */
				if (!(hsp->hsp_revision & MD_FN_META_DEV)) {

					if (setname != NULL) {
						(void) snprintf(tmpname,
						    MAXPATHLEN,
						    "%s/hsp%03u", setname,
						    HSP_ID(hsp->hsp_self_id));
					} else {
						(void) snprintf(tmpname,
						    MAXPATHLEN, "hsp%03u",
						    HSP_ID(hsp->hsp_self_id));
					}

					if (strcmp(name, tmpname) == 0)
						break;
				}

				hsp = hsp->hsp_next;
			}
			kmem_free(tmpname, MAXPATHLEN);

			if (hsp == NULL) {
				err = ENOENT;
				goto out;
			}

			/* Return hsp_self_id */
			nm->ret_hspid = hsp->hsp_self_id;
		}

	} else {
		/*
		 * We have a hspid for a pre-FN hotspare pool. Let's
		 * try to find the matching hsp using the given
		 * hspid.
		 */
		if (nm->hspid == MD_HSPID_WILD) {
			err = ENOENT;
			goto out;
		}

		hsp = (hot_spare_pool_t *)md_set[nm->setno].s_hsp;
		while (hsp != NULL) {
			if (hsp->hsp_self_id == nm->hspid)
				break;
			hsp = hsp->hsp_next;
		}

		if (hsp == NULL) {
			err = ENOENT;
			goto out;
		}

		/* Prepare a name to return */
		if (nm->setno != MD_LOCAL_SET)
			setname = mddb_getsetname(nm->setno);

		if (setname != NULL) {
			(void) snprintf(name, MAXPATHLEN, "%s/hsp%03u",
			    setname, HSP_ID(hsp->hsp_self_id));
		} else {
			(void) snprintf(name, MAXPATHLEN, "hsp%03u",
			    HSP_ID(hsp->hsp_self_id));
		}

		nm->ret_hspid = hsp->hsp_self_id;
	}

	if (nm->hspid != MD_HSPID_WILD) {
		if ((strlen(name) + 1) > nm->hspname_len) {
			err = EINVAL;
			goto out;
		}
		err = ddi_copyout(name, (caddr_t)
		    (uintptr_t)nm->hspname, strlen(name)+1, mode);
	}

	if (err) {
		if (err < 0)
			err = EINVAL;
	}

out:
	kmem_free(name, MAXPATHLEN);
	return (err);
}


/*ARGSUSED*/
static int
update_loc_namespace_ioctl(
	mdnm_params_t	*nm,
	char		*dname,
	char		*pname,
	int		mode
)
{

	side_t		side;

	mdclrerror(&nm->mde);

	if (md_snarf_db_set(MD_LOCAL_SET, &nm->mde) != 0)
		return (0);

	if (MD_MNSET_SETNO(nm->setno))
		return (0);

	if ((md_get_setstatus(nm->setno) & MD_SET_STALE))
		return (0);

	if ((md_get_setstatus(nm->setno) & MD_SET_SNARFED) == 0)
		return (ENODEV);

	if (nm->side == -1)
		side = mddb_getsidenum(nm->setno);
	else
		side = nm->side;

	return (md_update_locator_namespace(nm->setno, side, dname,
	    pname, nm->devt));
}

/*ARGSUSED*/
static int
update_namespace_did_ioctl(
	mdnm_params_t	*nm,
	int		mode
)
{
	side_t		side;

	mdclrerror(&nm->mde);

	if (md_snarf_db_set(MD_LOCAL_SET, &nm->mde) != 0)
		return (0);

	if (MD_MNSET_SETNO(nm->setno))
		return (0);

	if ((md_get_setstatus(nm->setno) & MD_SET_STALE))
		return (0);

	if ((md_get_setstatus(nm->setno) & MD_SET_SNARFED) == 0)
		return (ENODEV);

	if (nm->side == -1)
		side = mddb_getsidenum(nm->setno);
	else
		side = nm->side;

	return (md_update_namespace_did(nm->setno, side, nm->key, &nm->mde));
}

/*ARGSUSED*/
static int
update_namespace_ioctl(
	mdnm_params_t	*nm,
	char		*dname,
	char		*pname,
	int		mode
)
{
	side_t		side;

	mdclrerror(&nm->mde);

	if (md_snarf_db_set(MD_LOCAL_SET, &nm->mde) != 0)
		return (0);

	if (MD_MNSET_SETNO(nm->setno))
		return (0);

	if ((md_get_setstatus(nm->setno) & MD_SET_STALE))
		return (0);

	if ((md_get_setstatus(nm->setno) & MD_SET_SNARFED) == 0)
		return (ENODEV);

	if (nm->side == -1)
		side = mddb_getsidenum(nm->setno);
	else
		side = nm->side;

	return (md_update_namespace(nm->setno, side, nm->key,
	    dname, pname, nm->mnum));

}

/*ARGSUSED*/
static int
getnextkey_ioctl(
	mdnm_params_t	*nm,
	int		mode
)
{
	side_t		side;

	mdclrerror(&nm->mde);

	if (md_snarf_db_set(MD_LOCAL_SET, &nm->mde) != 0)
		return (0);

	if (nm->setno >= md_nsets)
		return (EINVAL);

	if ((md_get_setstatus(nm->setno) & MD_SET_SNARFED) == 0)
		return (ENODEV);

	if (nm->side == -1)
		side = mddb_getsidenum(nm->setno);
	else
		side = nm->side;

	nm->key = md_getnextkey(nm->setno, side, nm->key, &nm->ref_count);
	return (0);
}

/*ARGSUSED*/
static int
remnm_ioctl(mdnm_params_t *nm, int mode)
{
	side_t	side;

	mdclrerror(&nm->mde);

	if (md_snarf_db_set(MD_LOCAL_SET, &nm->mde) != 0)
		return (0);

	if ((md_get_setstatus(nm->setno) & MD_SET_SNARFED) == 0)
		return (ENODEV);

	if (nm->side == -1)
		side = mddb_getsidenum(nm->setno);
	else
		side = nm->side;

	return (md_remdevname(nm->setno, side, nm->key));
}


/*ARGSUSED*/
static int
getdrvnm_ioctl(md_dev64_t dev, md_i_driverinfo_t *di, int mode)
{
	mdi_unit_t 	*ui;
	minor_t		mnum = di->mnum;
	set_t		setno = MD_MIN2SET(mnum);

	mdclrerror(&di->mde);

	if (md_snarf_db_set(MD_LOCAL_SET, &di->mde) != 0)
		return (0);

	ui = MDI_UNIT(mnum);
	if (ui == NULL) {
		return (mdmderror(&di->mde, MDE_UNIT_NOT_SETUP, mnum));
	}

	MD_SETDRIVERNAME(di, md_ops[ui->ui_opsindex]->md_driver.md_drivername,
	    setno);

	return (0);
}

/*ARGSUSED*/
static int
getnext_ioctl(md_i_getnext_t *gn, int mode)
{
	int		modindex;
	md_link_t	*next;
	uint_t		id;
	int		found = 0;
	set_t		setno = gn->md_driver.md_setno;

	mdclrerror(&gn->mde);

	if (md_snarf_db_set(MD_LOCAL_SET, &gn->mde) != 0)
		return (0);

	if ((md_get_setstatus(setno) & MD_SET_SNARFED) == 0) {
		if (md_get_setstatus(setno) & MD_SET_TAGDATA)
			return (mdmddberror(&gn->mde, MDE_DB_TAGDATA,
			    NODEV32, setno));
		else
			return (mderror(&gn->mde, MDE_UNIT_NOT_FOUND));
	}

	modindex = md_getmodindex((md_driver_t *)gn, 1, 0);
	if (modindex == -1) {
		return (mderror(&gn->mde, MDE_UNIT_NOT_FOUND));
	}

	rw_enter(&md_ops[modindex]->md_link_rw.lock, RW_READER);
	id = gn->id;
	next = md_ops[modindex]->md_head;
	while (next) {
		if ((next->ln_setno == setno) && (next->ln_id == id)) {
			gn->id = id;
			found = 1;
			break;
		}

		if ((next->ln_setno == setno) &&(next->ln_id > id) &&
		    (! found || (next->ln_id < gn->id))) {
			gn->id = next->ln_id;
			found = 1;
			/* continue looking for smallest */
		}
		next = next->ln_next;
	}
	rw_exit(&md_ops[modindex]->md_link_rw.lock);

	if (! found)
		return (mderror(&gn->mde, MDE_UNIT_NOT_FOUND));

	return (0);
}

/*ARGSUSED*/
static int
getnum_ioctl(void *d, int mode)
{
	int		modindex;
	md_link_t	*next;
	int		sz;
	minor_t		*minors;
	minor_t		*m_ptr;
	set_t		setno;
	int		err = 0;
	md_error_t	*mdep;
	int		minor_array_length;
	md_driver_t	*driver;
	int		count = 0;
	struct md_i_getnum	*gn = d;


	/* number of specified devices in specified set - if 0 return count */
	minor_array_length = gn->size;
	if (minor_array_length > md_nunits)
		return (EINVAL);

	mdep = &gn->mde;
	driver = &gn->md_driver;
	setno = driver->md_setno;

	mdclrerror(mdep);

	if (md_snarf_db_set(MD_LOCAL_SET, mdep) != 0)
		return (0);

	if ((md_get_setstatus(setno) & MD_SET_SNARFED) == 0) {
		if (md_get_setstatus(setno) & MD_SET_TAGDATA) {
			return (mdmddberror(mdep, MDE_DB_TAGDATA,
			    NODEV32, setno));
		} else {
			return (mderror(mdep, MDE_UNIT_NOT_FOUND));
		}
	}

	modindex = md_getmodindex(driver, 0, 0);
	if (modindex == -1) {

		return (mderror(mdep, MDE_UNIT_NOT_FOUND));
	}

	rw_enter(&md_ops[modindex]->md_link_rw.lock, RW_READER);
	/* if array length is not 0 then allocate the output buffers */
	if (minor_array_length != 0) {
		sz = minor_array_length * ((int)sizeof (minor_t));
		minors = kmem_zalloc(sz, KM_SLEEP);
		m_ptr = minors;
	}

	next = md_ops[modindex]->md_head;
	count = 0;
	while (next) {
		if (next->ln_setno == setno) {
			if ((minor_array_length > 0) &&
			    (count < minor_array_length)) {
				*m_ptr = next->ln_id;
				m_ptr++;
			}
			count++;
		}
		next = next->ln_next;
	}
	rw_exit(&md_ops[modindex]->md_link_rw.lock);

	gn->size = count;
	/* now copy the array back */
	if (minor_array_length > 0) {
		err = ddi_copyout(minors,
		    (caddr_t)(uintptr_t)gn->minors, sz, mode);
		kmem_free(minors, sz);
	}

	return (err);
}

/*ARGSUSED*/
static int
didstat_ioctl(
	md_i_didstat_t	*ds
)
{
	int		cnt = 0;
	int		err = 0;

	mdclrerror(&ds->mde);

	if (md_snarf_db_set(MD_LOCAL_SET, &ds->mde) != 0)
		return (0);

	if (ds->setno >= md_nsets) {
		return (EINVAL);
	}

	if ((md_get_setstatus(ds->setno) & MD_SET_SNARFED) == 0)
		return (ENODEV);

	if (ds->mode == MD_FIND_INVDID) {
		cnt = md_validate_devid(ds->setno, ds->side, &ds->maxsz);
		if (cnt == -1)
			err = -1;
		ds->cnt = cnt;
	} else if (ds->mode == MD_GET_INVDID) {
		if (md_get_invdid(ds->setno, ds->side, ds->cnt, ds->maxsz,
		    (caddr_t)(uintptr_t)ds->ctdp) == -1) {
			err = -1;
		}
	} else {
		/* invalid mode */
		err = EINVAL;
	}

	return (err);
}

/*ARGSUSED*/
static int
getdid_ioctl(
	mdnm_params_t	*nm,
	int		mode
)
{
	int		err = 0;
	ddi_devid_t	did = NULL;

	mdclrerror(&nm->mde);

	if (md_snarf_db_set(MD_LOCAL_SET, &nm->mde) != 0)
		return (0);

	if (nm->setno >= md_nsets) {
		return (EINVAL);
	}

	if ((md_get_setstatus(nm->setno) & MD_SET_SNARFED) == 0)
		return (ENODEV);

	/*
	 * Tell user that replica is not in devid mode
	 */
	if (!(((mddb_set_t *)md_set[nm->setno].s_db)->s_lbp->lb_flags
	    & MDDB_DEVID_STYLE) && md_keep_repl_state) {
		return (mdsyserror(&nm->mde, MDDB_F_NODEVID));
	}

	/*
	 * If user is prepared to receive the devid allocate a kernel buffer.
	 */
	if (nm->devid_size != 0) {
		/* check for bogus value of devid_size */
		if (nm->devid_size > MAXPATHLEN) {
			return (EINVAL);
		}
		did = kmem_alloc(nm->devid_size, KM_SLEEP);
	}

	err = md_getdevid(nm->setno, nm->side, nm->key, did, &nm->devid_size);

	if (err) {
		if (err < 0)
			err = EINVAL;
		goto out;
	}

	/*
	 * If devid size was already known to user then give them the devid.
	 */
	if (did != NULL)
		err = ddi_copyout(did,
		    (caddr_t)(uintptr_t)nm->devid, nm->devid_size, mode);

out:
	if (did != NULL)
		kmem_free(did, nm->devid_size);
	return (err);
}

int
mddb_setmaster_ioctl(mddb_setmaster_config_t *info)
{
	/* Verify that setno is in valid range */
	if (info->c_setno >= md_nsets)
		return (EINVAL);

	/*
	 * When adding the first disk to a MN diskset, the master
	 * needs to be set (in order to write out the mddb)
	 * before the set is snarfed or even before the set
	 * is marked as a MNset in the md_set structure.
	 * So, don't check for MNset or SNARFED and don't call
	 * mddb_setenter. In order to discourage bad ioctl calls,
	 * verify that magic field in structure is set correctly.
	 */
	if (info->c_magic != MDDB_SETMASTER_MAGIC)
		return (EINVAL);

	if (info->c_current_host_master)
		md_set[info->c_setno].s_am_i_master = 1;
	else
		md_set[info->c_setno].s_am_i_master = 0;

	return (0);
}

/*
 * Set the devid for the namespace record identified by the tuple
 * [setno, sideno, key]. The key is the namespace key. The md_getdevnum()
 * function is used to actually regenerate the devid.
 */
/*ARGSUSED*/
static int
setdid_ioctl(
	mdnm_params_t	*nm,
	int		mode
)
{
	dev_t		devt;

	/*
	 * If upgrading do not allow modification of the namespace.
	 */
	if (MD_UPGRADE)
		return (EAGAIN);

	mdclrerror(&nm->mde);

	if (md_snarf_db_set(MD_LOCAL_SET, &nm->mde) != 0)
		return (0);

	if (nm->setno >= md_nsets)
		return (EINVAL);

	if (MD_MNSET_SETNO(nm->setno))
		return (0);

	if ((md_get_setstatus(nm->setno) & MD_SET_SNARFED) == 0)
		return (ENODEV);

	devt = md_dev64_to_dev(
	    md_getdevnum(nm->setno, nm->side, nm->key, MD_TRUST_DEVT));

	if (devt == NODEV)
		return (ENODEV);

	return (0);
}

/*ARGSUSED*/
static int
getdidmin_ioctl(
	mdnm_params_t   *nm,
	int		mode
)
{
	int	err = 0;
	char	*minorname = NULL;

	mdclrerror(&nm->mde);

	if (md_snarf_db_set(MD_LOCAL_SET, &nm->mde) != 0)
		return (0);

	if (nm->setno >= md_nsets)
		return (EINVAL);

	if (MD_MNSET_SETNO(nm->setno))
		return (0);

	if ((md_get_setstatus(nm->setno) & MD_SET_SNARFED) == 0)
		return (ENODEV);

	minorname = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	if (nm->side == -1) {
		err = EINVAL;
		goto out;
	}

	err = md_getdevidminor(nm->setno, nm->side, nm->key, minorname,
	    MAXPATHLEN);

	if (err) {
		if (err < 0)
			err = EINVAL;
		goto out;
	}

	err = ddi_copyout(minorname, (caddr_t)(uintptr_t)nm->minorname,
	    strlen(minorname) + 1, mode);

out:

	kmem_free(minorname, MAXPATHLEN);
	return (err);
}

static int
mddb_userreq_ioctl(mddb_userreq_t *ur, int mode)
{
	void			*data;
	int			status;
	mddb_recid_t		*recids;
	int			flags;

	if (ur->ur_setno >= md_nsets)
		return (EINVAL);

	mdclrerror(&ur->ur_mde);

	if (md_snarf_db_set(MD_LOCAL_SET, &ur->ur_mde) != 0)
		return (0);

	if ((md_get_setstatus(ur->ur_setno) & MD_SET_SNARFED) == 0)
		return (ENODEV);

	switch (ur->ur_cmd) {
	case MD_DB_GETNEXTREC:
		if (ur->ur_recid == 0)
			ur->ur_recid = mddb_makerecid(ur->ur_setno, 0);
		/*
		 * Is ur_recid a valid one ?
		 */
		if (DBSET(ur->ur_recid) < 0 || DBSET(ur->ur_recid) >= md_nsets)
			return (EINVAL);

		ur->ur_recid = mddb_getnextrec(ur->ur_recid, ur->ur_type,
		    ur->ur_type2);
		if (ur->ur_recid > 0) {
			ur->ur_type = mddb_getrectype1(ur->ur_recid);
			ur->ur_type2 = mddb_getrectype2(ur->ur_recid);
			ur->ur_recstat = mddb_getrecstatus(ur->ur_recid);
		}
		break;

	case MD_DB_COMMIT_ONE:
		/*
		 * Is ur_recid a valid one?
		 */
		if (DBSET(ur->ur_recid) < 0 || DBSET(ur->ur_recid) >= md_nsets)
			return (EINVAL);

		ur->ur_recstat = mddb_getrecstatus(ur->ur_recid);
		if (ur->ur_recstat == MDDB_NORECORD)
			return (ENXIO);
		status = mddb_commitrec(ur->ur_recid);
		/*
		 * For MN sets we panic if there are too few database replicas
		 * and we're attempting to add entries to the log.
		 */
		if (status != 0) {
			if ((MD_MNSET_SETNO(ur->ur_setno) &&
			    (ur->ur_type2 == MDDB_UR_LR)) &&
			    (md_get_setstatus(ur->ur_setno) & MD_SET_TOOFEW)) {
				cmn_err(CE_PANIC,
				    "md: Panic due to lack of DiskSuite state\n"
				    " database replicas. Fewer than 50%% of "
				    "the total were available,\n so panic to "
				    "ensure data integrity.");
			}
			return (mddbstatus2error(&ur->ur_mde, status, NODEV32,
			    ur->ur_setno));
		}
		break;

	case MD_DB_COMMIT_MANY:
		if (ur->ur_size <= 0)
			return (EINVAL);

		data = kmem_alloc(ur->ur_size, KM_SLEEP);

		if (ddi_copyin((caddr_t)(uintptr_t)ur->ur_data, data,
		    (size_t)ur->ur_size, mode)) {
			kmem_free(data, ur->ur_size);
			return (EFAULT);
		}

		recids = (mddb_recid_t *)data;
		while (*recids != 0) {
			/*
			 * Is recid a valid ?
			 */
			if (DBSET(*recids) < 0 || DBSET(*recids) >= md_nsets) {
				kmem_free(data, ur->ur_size);
				return (EINVAL);
			}
			ur->ur_recstat = mddb_getrecstatus(*recids++);
			if (ur->ur_recstat == MDDB_NORECORD) {
				kmem_free(data, ur->ur_size);
				return (ENXIO);
			}
		}
		status = mddb_commitrecs(data);
		kmem_free(data, ur->ur_size);
		/*
		 * For MN sets we panic if there are too few database replicas
		 * and we're attempting to add entries to the log.
		 */
		if (status != 0) {
			if ((MD_MNSET_SETNO(ur->ur_setno) &&
			    (ur->ur_type2 == MDDB_UR_LR)) &&
			    (md_get_setstatus(ur->ur_setno) & MD_SET_TOOFEW)) {
				cmn_err(CE_PANIC,
				    "md: Panic due to lack of DiskSuite state\n"
				    " database replicas. Fewer than 50%% of "
				    "the total were available,\n so panic to "
				    "ensure data integrity.");
			}
			return (mddbstatus2error(&ur->ur_mde, status, NODEV32,
			    ur->ur_setno));
		}
		break;

	case MD_DB_GETDATA:
		/*
		 * Check ur_recid
		 */
		if (DBSET(ur->ur_recid) < 0 || DBSET(ur->ur_recid) >= md_nsets)
			return (EINVAL);

		ur->ur_recstat = mddb_getrecstatus(ur->ur_recid);
		if (ur->ur_recstat == MDDB_NORECORD ||
		    ur->ur_recstat == MDDB_NODATA)
			return (ENXIO);

		if (ur->ur_size > mddb_getrecsize(ur->ur_recid))
			return (EINVAL);

		data = mddb_getrecaddr(ur->ur_recid);
		if (ddi_copyout(data, (caddr_t)(uintptr_t)ur->ur_data,
		    (size_t)ur->ur_size, mode)) {
			return (EFAULT);
		}
		break;

	case MD_DB_SETDATA:
		if (DBSET(ur->ur_recid) < 0 || DBSET(ur->ur_recid) >= md_nsets)
			return (EINVAL);

		ur->ur_recstat = mddb_getrecstatus(ur->ur_recid);
		if (ur->ur_recstat == MDDB_NORECORD)
			return (ENXIO);

		if (ur->ur_size > mddb_getrecsize(ur->ur_recid))
			return (EINVAL);

		data = mddb_getrecaddr(ur->ur_recid);
		if (ddi_copyin((caddr_t)(uintptr_t)ur->ur_data, data,
		    (size_t)ur->ur_size, mode)) {
			return (EFAULT);
		}
		break;

	case MD_DB_DELETE:
		if (DBSET(ur->ur_recid) < 0 || DBSET(ur->ur_recid) >= md_nsets)
			return (EINVAL);

		ur->ur_recstat = mddb_getrecstatus(ur->ur_recid);
		if (ur->ur_recstat == MDDB_NORECORD)
			return (ENXIO);
		status = mddb_deleterec(ur->ur_recid);
		if (status < 0)
			return (mddbstatus2error(&ur->ur_mde, status, NODEV32,
			    ur->ur_setno));
		break;

	case MD_DB_CREATE:
	{
		int	mn_set = 0;

		if (md_get_setstatus(ur->ur_setno) & MD_SET_MNSET)
			mn_set = 1;

		if (ur->ur_setno >= md_nsets)
			return (EINVAL);
		if ((mn_set) && (ur->ur_type2 == MDDB_UR_LR))
			flags = MD_CRO_32BIT | MD_CRO_CHANGELOG;
		else
			flags = MD_CRO_32BIT;
		ur->ur_recid = mddb_createrec(ur->ur_size, ur->ur_type,
		    ur->ur_type2, flags, ur->ur_setno);
		if (ur->ur_recid < 0)
			return (mddbstatus2error(&ur->ur_mde, ur->ur_recid,
			    NODEV32, ur->ur_setno));
		break;
	}

	case MD_DB_GETSTATUS:
		if (DBSET(ur->ur_recid) < 0 || DBSET(ur->ur_recid) >= md_nsets)
			return (EINVAL);
		ur->ur_recstat = mddb_getrecstatus(ur->ur_recid);
		break;

	case MD_DB_GETSIZE:
		if (DBSET(ur->ur_recid) < 0 || DBSET(ur->ur_recid) >= md_nsets)
			return (EINVAL);
		ur->ur_size = mddb_getrecsize(ur->ur_recid);
		break;

	case MD_DB_MAKEID:
		if (ur->ur_setno >= md_nsets)
			return (EINVAL);
		ur->ur_recid = mddb_makerecid(ur->ur_setno, ur->ur_recid);
		break;

	default:
		return (EINVAL);
	}
	return (0);
}

static int
setuserflags(
	md_set_userflags_t	*msu,
	IOLOCK			*lock
)
{
	minor_t			mnum = msu->mnum;
	set_t			setno = MD_MIN2SET(mnum);
	md_unit_t		*un;
	mdi_unit_t		*ui;

	mdclrerror(&msu->mde);

	if (md_get_setstatus(setno) & MD_SET_STALE)
		return (mdmddberror(&msu->mde, MDE_DB_STALE, mnum, setno));

	if ((ui = MDI_UNIT(mnum)) == NULL) {
		return (mdmderror(&msu->mde, MDE_UNIT_NOT_SETUP, mnum));
	}

	un = (md_unit_t *)md_ioctl_writerlock(lock, ui);

	un->c.un_user_flags = msu->userflags;
	mddb_commitrec_wrapper(un->c.un_record_id);

	return (0);
}

/*
 * mddb_didstat_from_user -- called for DIDSTAT ioctl. 2 different calling
 * 	scenarios.
 * 	1) data->mode == MD_FIND_INVDID
 *	   when user is inquiring about the existence of invalid device id's.
 *	   Upon return to the user d->cnt may have a value in it.
 *	2) data->mode == MD_GET_INVDID
 *	   when the user wants a list of the invalid device id's.
 *	   In this case d->ctdp is non Null and cnt has	a value in it.
 *
 * Basically this routine along with mddb_didstat_to_user can be eliminated
 * by pushing ddi_copyout down to lower level interfaces.  To minimize impact
 * just keep the current implementation intact.
 */
static int
mddb_didstat_from_user(
	void		**d,
	caddr_t		data,
	int		mode,
	caddr_t		*ds_ctd_addr
)
{
	size_t		sz1 = 0, sz2 = 0;
	md_i_didstat_t	*d1;
	void		*d2;
	*ds_ctd_addr	= 0;

	sz1 = sizeof (md_i_didstat_t);
	d1 = (md_i_didstat_t *)kmem_zalloc(sz1, KM_SLEEP);

	if (ddi_copyin(data, (void *)d1, sz1, mode) != 0) {
		kmem_free((void *)d1, sz1);
		return (EFAULT);
	}

	/*
	 * ds_ctd_addr has actual user ctdp
	 */
	*ds_ctd_addr = (caddr_t)(uintptr_t)d1->ctdp;
	if (d1->mode == MD_GET_INVDID) {
		sz2 = (d1->cnt * d1->maxsz) + 1;
		if (sz2 <= 0) {
			kmem_free(d1, sz1);
			return (EINVAL);
		}
		d2 = kmem_zalloc(sz2, KM_SLEEP);
		d1->ctdp = (uint64_t)(uintptr_t)d2;
	} else if (d1->mode != MD_FIND_INVDID) {
		kmem_free(d1, sz1);
		return (EINVAL);
	}
	*d = (void *)d1;
	return (0);
}

/*
 * mddb_didstat_to_user -- see comment for mddb_didstat_from_user. In this
 * 		case d->cnt could have a value in it for either usage of
 *		the ioctl.
 */
/*ARGSUSED*/
static int
mddb_didstat_to_user(
	void 		*d,
	caddr_t		data,
	int		mode,
	caddr_t		ds_ctd_addr
)
{
	size_t		sz1 = 0, sz2 = 0;
	md_i_didstat_t		*d1;
	void			*d2;


	d1 = (md_i_didstat_t *)d;
	sz1 = sizeof (md_i_didstat_t);

	sz2 = (d1->cnt * d1->maxsz) + 1;
	d2 = (caddr_t)(uintptr_t)d1->ctdp;
	if (d2 && sz2) {
		/*
		 * Copy out from kernel ctdp to user ctdp area
		 */
		if (ddi_copyout(d2, (caddr_t)ds_ctd_addr, sz2, mode) != 0) {
			kmem_free(d1, sz1);
			kmem_free(d2, sz2);
			return (EFAULT);
		}
		d1->ctdp = (uint64_t)(uintptr_t)ds_ctd_addr;
	}
	if (ddi_copyout(d1, data, sz1, mode) != 0) {
		kmem_free(d1, sz1);
		if (sz2 && d2)
			kmem_free(d2, sz2);
		return (EFAULT);
	}
	kmem_free(d1, sz1);
	if (sz2 && d2)
		kmem_free(d2, sz2);
	return (0);
}


static int
mddb_config_from_user(
	void 		**d,
	caddr_t 	data,
	int 		mode,
	caddr_t 	*c_devid_addr,
	caddr_t		*c_old_devid_addr
)
{
	size_t		sz1 = 0, sz2 = 0, sz3 = 0;
	mddb_config_t	*d1;
	void		*d2;
	void 		*d3;

	*c_devid_addr = 0;

	sz1 = sizeof (mddb_config_t);
	d1 = (mddb_config_t *)kmem_zalloc(sz1, KM_SLEEP);

	if (ddi_copyin(data, (void *)d1, sz1, mode) != 0) {
		kmem_free((void *)d1, sz1);
		return (EFAULT);
	}
	*c_devid_addr = (caddr_t)(uintptr_t)d1->c_locator.l_devid;

	if (d1->c_locator.l_devid_flags & MDDB_DEVID_SPACE) {
		sz2 = d1->c_locator.l_devid_sz;
		if (d1->c_locator.l_devid_sz <= 0 ||
		    d1->c_locator.l_devid_sz > MAXPATHLEN) {
			kmem_free((void *)d1, sz1);
			return (EINVAL);
		}
		d2 = kmem_zalloc(sz2, KM_SLEEP);
		if (ddi_copyin((caddr_t)(uintptr_t)d1->c_locator.l_devid,
		    d2, sz2, mode) != 0) {
			kmem_free(d1, sz1);
			kmem_free(d2, sz2);
			return (EFAULT);
		}
		d1->c_locator.l_devid = (uint64_t)(uintptr_t)d2;

		if ((caddr_t)(uintptr_t)d1->c_locator.l_old_devid) {
			*c_old_devid_addr = (caddr_t)(uintptr_t)
			    d1->c_locator.l_old_devid;

			sz3 = d1->c_locator.l_old_devid_sz;
			if (d1->c_locator.l_old_devid_sz <= 0 ||
			    d1->c_locator.l_old_devid_sz > MAXPATHLEN) {
				kmem_free((void *)d1, sz1);
				kmem_free(d2, sz2);
				return (EINVAL);
			}
			d3 = kmem_zalloc(sz3, KM_SLEEP);
			if (ddi_copyin(
			    (caddr_t)(uintptr_t)d1->c_locator.l_old_devid,
			    d3, sz3, mode) != 0) {
				kmem_free((void *)d1, sz1);
				kmem_free(d2, sz2);
				kmem_free(d3, sz3);
				return (EFAULT);
			}
			d1->c_locator.l_old_devid = (uintptr_t)d3;
		}
	} else {
		d1->c_locator.l_devid = (uint64_t)0;
		d1->c_locator.l_old_devid = (uint64_t)0;
	}

	*d = (void *)d1;
	return (0);
}

/*ARGSUSED*/
static int
mddb_config_to_user(
	void 		*d,
	caddr_t 	data,
	int 		mode,
	caddr_t 	c_devid_addr,
	caddr_t		c_old_devid_addr
)
{
	size_t		sz1 = 0, sz2 = 0, sz3 = 0;
	mddb_config_t		*d1;
	void			*d2;
	void			*d3;

	d1 = (mddb_config_t *)d;
	sz1 = sizeof (mddb_config_t);

	if (d1->c_locator.l_devid_flags & MDDB_DEVID_SPACE) {
		sz2 = d1->c_locator.l_devid_sz;
		d2 = (caddr_t)(uintptr_t)d1->c_locator.l_devid;
		/* Only copyout devid if valid */
		if (d1->c_locator.l_devid_flags & MDDB_DEVID_VALID) {
			if (ddi_copyout(d2, (caddr_t)c_devid_addr,
			    sz2, mode) != 0) {
				kmem_free(d1, sz1);
				kmem_free(d2, sz2);
				return (EFAULT);
			}
		}
	}

	d1->c_locator.l_devid = (uint64_t)(uintptr_t)c_devid_addr;

	if (d1->c_locator.l_old_devid) {
		sz3 = d1->c_locator.l_old_devid_sz;
		d3 = (caddr_t)(uintptr_t)d1->c_locator.l_old_devid;
		if (ddi_copyout(d3, (caddr_t)c_old_devid_addr,
		    sz3, mode) != 0) {
			kmem_free(d1, sz1);
			kmem_free(d2, sz2);
			kmem_free(d3, sz3);
		}
	}
	d1->c_locator.l_old_devid = (uintptr_t)c_old_devid_addr;

	if (ddi_copyout(d1, data, sz1, mode) != 0) {
		kmem_free(d1, sz1);
		if (sz2)
			kmem_free(d2, sz2);
		if (sz3)
			kmem_free(d3, sz3);
		return (EFAULT);
	}

	if (d1)
		kmem_free(d1, sz1);
	if (sz2)
		kmem_free(d2, sz2);
	if (sz3)
		kmem_free(d3, sz3);

	return (0);
}

/*
 * NAME:	get_tstate
 * PURPOSE:	Return unit's transient error state to user.
 * INPUT:	device node (set + metadevice number)
 * OUTPUT:	gu->tstate
 * RETURNS:	0 on success
 *		EINVAL on failure
 */
static int
get_tstate(md_i_get_tstate_t *gu, IOLOCK *lock)
{
	mdi_unit_t	*ui;

	ui = MDI_UNIT(gu->id);
	if (ui == (mdi_unit_t *)NULL) {
		(void) mdmderror(&gu->mde, MDE_UNIT_NOT_SETUP, gu->id);
		return (EINVAL);
	}

	(void) md_ioctl_readerlock(lock, ui);
	gu->tstate = ui->ui_tstate;
	md_ioctl_readerexit(lock);

	return (0);
}

/*
 * NAME:	md_clu_ioctl
 * PURPOSE:	depending on clu_cmd:
 *		- Check open state,
 *		- lock opens and check open state
 *		- unlock opens again
 * INPUT:	metadevice and clu_cmd
 * OUTPUT:	open state (for MD_MN_LCU_UNLOCK always 0)
 * RETURNS:	0 on success
 *		EINVAL on failure
 */
int
md_clu_ioctl(md_clu_open_t *clu)
{
	mdi_unit_t	*ui;
	minor_t		mnum;

	if ((clu->clu_dev <= 0) ||
	    (md_getmajor(clu->clu_dev)) != md_major) {
		return (EINVAL);
	}

	mnum = md_getminor(clu->clu_dev);
	if ((ui = MDI_UNIT(mnum)) == NULL) {
		return (mdmderror(&clu->clu_mde, MDE_UNIT_NOT_SETUP, mnum));
	}

	switch (clu->clu_cmd) {
	case MD_MN_LCU_CHECK:
		/* No lock here, just checking */
		clu->clu_isopen = md_unit_isopen(ui);
		break;
	case MD_MN_LCU_LOCK:
		/* This inhibits later opens to succeed */
		ui->ui_tstate |= MD_OPENLOCKED;
		clu->clu_isopen = md_unit_isopen(ui);
		/* In case the md is opened, reset the lock immediately */
		if (clu->clu_isopen != 0) {
			ui->ui_tstate &= ~MD_OPENLOCKED;
		}
		break;
	case MD_MN_LCU_UNLOCK:
		ui->ui_tstate &= ~MD_OPENLOCKED;
		clu->clu_isopen = 0;	/* always sucess */
		break;
	}
	return (0);
}

/*
 * NAME:	mkdev_ioctl
 * PURPOSE:	Create device node for specified set / metadevice tuple
 * INPUT:	device tuple (set number + metadevice number)
 * OUTPUT:	None
 * RETURNS:	0 on success
 *		EINVAL on failure
 */
static int
mkdev_ioctl(md_mkdev_params_t *p)
{
	set_t	setno = p->md_driver.md_setno;
	unit_t	un;

	mdclrerror(&p->mde);

	/* Validate arguments passed in to ioctl */
	if (setno >= MD_MAXSETS) {
		(void) mderror(&p->mde, MDE_NO_SET);
		return (EINVAL);
	}

	/*
	 * Get the next available unit number in this set
	 */
	un = md_get_nextunit(setno);
	if (un == MD_UNITBAD) {
		(void) mdmderror(&p->mde, MDE_UNIT_NOT_SETUP, un);
		return (ENODEV);
	}

	/* Create the device node */
	if (md_create_minor_node(setno, un)) {
		(void) mdmderror(&p->mde, MDE_UNIT_NOT_SETUP, un);
		return (ENODEV);
	}

	/* Return the minor number */
	p->un = un;

	return (0);
}

/*
 * admin device ioctls
 */
static int
md_base_ioctl(md_dev64_t dev, int cmd, caddr_t data, int mode, IOLOCK *lockp)
{
	size_t		sz = 0;
	void		*d = NULL;
	mddb_config_t	*cp;
	set_t		setno;
	int		err = 0;
	int		err_to_user = 0;
	int		mddb_config_case = 0;
	int		mddb_didstat_case = 0;
	caddr_t		c_devid_addr = 0;
	caddr_t		c_old_devid_addr = 0;
	caddr_t		ds_ctd_addr = 0;
	mddb_set_node_params_t	*snp;

	/* For now we can only handle 32-bit clients for internal commands */
	if ((cmd != DKIOCINFO) &&
	    ((mode & DATAMODEL_MASK) != DATAMODEL_ILP32)) {
		return (EINVAL);
	}

	switch (cmd) {

	case DKIOCINFO:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (struct dk_cinfo);
		d = kmem_alloc(sz, KM_SLEEP);

		get_info((struct dk_cinfo *)d, md_getminor(dev));
		break;
	}

	case MD_DB_USEDEV:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		mddb_config_case = 1;

		err = mddb_config_from_user(&d, data, mode, &c_devid_addr,
		    &c_old_devid_addr);

		if (err)
			return (err);

		err = mddb_configure(MDDB_USEDEV, (mddb_config_t *)d);
		break;
	}

	case MD_DB_GETDEV:
	{
		if (! (mode & FREAD))
			return (EACCES);

		mddb_config_case = 1;

		err = mddb_config_from_user(&d, data, mode, &c_devid_addr,
		    &c_old_devid_addr);

		if (err)
			return (err);

		err = mddb_configure(MDDB_GETDEV, (mddb_config_t *)d);
		break;
	}

	case MD_DB_GETDRVNM:
	{
		if (! (mode & FREAD))
			return (EACCES);

		mddb_config_case = 1;

		err = mddb_config_from_user(&d, data, mode, &c_devid_addr,
		    &c_old_devid_addr);

		if (err)
			return (err);

		err = mddb_configure(MDDB_GETDRVRNAME, (mddb_config_t *)d);
		break;
	}

	case MD_DB_ENDDEV:
	{
		if (! (mode & FREAD))
			return (EACCES);

		mddb_config_case = 1;

		err = mddb_config_from_user(&d, data, mode, &c_devid_addr,
		    &c_old_devid_addr);

		if (err)
			return (err);

		err = mddb_configure(MDDB_ENDDEV, (mddb_config_t *)d);
		break;
	}

	case MD_DB_DELDEV:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		mddb_config_case = 1;

		err = mddb_config_from_user(&d, data, mode, &c_devid_addr,
		    &c_old_devid_addr);

		if (err)
			return (err);

		cp = (mddb_config_t *)d;
		setno = cp->c_setno;
		err = mddb_configure(MDDB_DELDEV, cp);
		if (! mdisok(&cp->c_mde))
			break;

		if (setno == MD_LOCAL_SET)
			break;

		if (cp->c_dbcnt != 0)
			break;

		/*
		 * if the last db replica of a diskset is deleted
		 * unload everything.
		 */

		/* Requesting a release, clean up everything */
		md_clr_setstatus(setno, MD_SET_KEEPTAG);

		err = release_set(cp, mode);

		break;
	}

	case MD_DB_NEWDEV:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		mddb_config_case = 1;

		err = mddb_config_from_user(&d, data, mode, &c_devid_addr,
		    &c_old_devid_addr);

		if (err)
			return (err);

		cp = (mddb_config_t *)d;
		setno = cp->c_setno;
		err = mddb_configure(MDDB_NEWDEV, cp);
		if (! err && mdisok(&cp->c_mde))
			(void) md_snarf_db_set(setno, &cp->c_mde);
		break;
	}

	case MD_DB_NEWSIDE:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		mddb_config_case = 1;

		err = mddb_config_from_user(&d, data, mode, &c_devid_addr,
		    &c_old_devid_addr);

		if (err)
			return (err);

		err = mddb_configure(MDDB_NEWSIDE, (mddb_config_t *)d);
		break;
	}

	case MD_DB_DELSIDE:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		mddb_config_case = 1;

		err = mddb_config_from_user(&d, data, mode, &c_devid_addr,
		    &c_old_devid_addr);

		if (err)
			return (err);

		err = mddb_configure(MDDB_DELSIDE, (mddb_config_t *)d);
		break;
	}

	case MD_DB_SETDID:
	{
		if (!(mode & FWRITE)) {
			return (EACCES);
		}

		mddb_config_case = 1;

		err = mddb_config_from_user(&d, data, mode, &c_devid_addr,
		    &c_old_devid_addr);

		if (err) {
			return (err);
		}

		err = mddb_configure(MDDB_SETDID, (mddb_config_t *)d);

		break;
	}

	case MD_GRAB_SET:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		mddb_config_case = 1;

		err = mddb_config_from_user(&d, data, mode, &c_devid_addr,
		    &c_old_devid_addr);

		if (err)
			return (err);

		cp = (mddb_config_t *)d;
		setno = cp->c_setno;

		err = take_set(cp, mode);

		if (err || ! mdisok(&cp->c_mde))
			break;

		if (md_get_setstatus(setno) & MD_SET_ACCOK)
			err = mdmddberror(&cp->c_mde, MDE_DB_ACCOK, NODEV32,
			    setno);

		md_unblock_setio(setno);
		break;
	}

	case MD_RELEASE_SET:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		mddb_config_case = 1;

		err = mddb_config_from_user(&d, data, mode, &c_devid_addr,
		    &c_old_devid_addr);

		if (err)
			return (err);

		/* shorthand */
		cp = (mddb_config_t *)d;
		setno = cp->c_setno;

		/* If the user requests a release, clean up everything */
		md_clr_setstatus(setno, MD_SET_KEEPTAG);

		/* Block incoming I/Os during release_set operation */
		if (MD_MNSET_SETNO(setno)) {
			/*
			 * md_tas_block_setio will block the set if
			 * there are no outstanding I/O requests,
			 * otherwise it returns -1.
			 */
			if (md_tas_block_setio(setno) != 1) {
				err = EBUSY;
				break;
			}
		} else {
			/*
			 * Should not return something other than 1
			 */
			if (md_block_setio(setno) != 1) {
				md_clearblock_setio(setno);
				err = EACCES;
				break;
			}
		}

		err = release_set(cp, mode);

		/* Always unblock I/O even if release_set fails */
		md_clearblock_setio(setno);

		break;
	}

	case MD_DB_GETOPTLOC:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (mddb_optloc_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = mddb_getoptloc((mddb_optloc_t *)d);
		break;
	}

	case MD_HALT:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		/* already have the ioctl lock */
		return (md_halt(MD_GBL_IOCTL_LOCK));
	}

	case MD_IOCSET_NM:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (mdnm_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		/* check data integrity */
		if (((mdnm_params_t *)d)->setno >= md_nsets) {
			err = EINVAL;
			break;
		}

		if ((((mdnm_params_t *)d)->devname_len == 0) ||
		    (((mdnm_params_t *)d)->devname_len > MAXPATHLEN)) {
			err = EINVAL;
			break;
		}

		if (((mdnm_params_t *)d)->devname == NULL) {
			err = EINVAL;
			break;
		}

		err = setnm_ioctl((mdnm_params_t *)d, mode);
		break;
	}

	case MD_IOCGET_NM:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (mdnm_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		/* check data integrity */
		if (((mdnm_params_t *)d)->setno >= md_nsets) {
			err = EINVAL;
			break;
		}
		if (((mdnm_params_t *)d)->devname == NULL) {
			err = EINVAL;
			break;
		}

		err = getnm_ioctl((mdnm_params_t *)d, mode);
		break;
	}

	case MD_IOCGET_HSP_NM:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (mdhspnm_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		/* check data integrity */
		if (((mdhspnm_params_t *)d)->setno >= md_nsets) {
			err = EINVAL;
			break;
		}
		if (((mdhspnm_params_t *)d)->hspname == NULL) {
			err = EINVAL;
			break;
		}

		err = gethspnm_ioctl((mdhspnm_params_t *)d, mode);
		break;
	}

	case MD_IOCNXTKEY_NM:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (mdnm_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = getnextkey_ioctl((mdnm_params_t *)d, mode);
		break;
	}

	case MD_IOCREM_NM:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (mdnm_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		/* check data integrity */
		if (((mdnm_params_t *)d)->setno >= md_nsets) {
			err = EINVAL;
			break;
		}

		err = remnm_ioctl((mdnm_params_t *)d, mode);
		break;
	}

	case MD_IOCGET_TSTATE:
	{
		md_i_get_tstate_t	*p;

		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (md_i_get_tstate_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		p = (md_i_get_tstate_t *)d;

		if ((err = verify_minor(p->id)) != 0) {
			if (err == EINVAL)
				(void) mdmderror(&p->mde, MDE_INVAL_UNIT,
				    p->id);
			break;
		}

		err = get_tstate(p, lockp);
		break;
	}

	case MD_IOCGET_DRVNM:
	{
		md_i_driverinfo_t	*p;

		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (md_i_driverinfo_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		p = (md_i_driverinfo_t *)d;

		/* check data integrity */
		if (p->md_driver.md_drivername == NULL) {
			err = EINVAL;
			break;
		}

		if ((err = verify_minor(p->mnum)) != 0) {
			if (err == EINVAL)
				(void) mdmderror(&p->mde, MDE_INVAL_UNIT,
				    p->mnum);
			break;
		}

		err = getdrvnm_ioctl(dev, p, mode);
		break;
	}

	case MD_IOCGET_NEXT:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (md_i_getnext_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		/* check data integrity */
		if (((md_i_getnext_t *)d)->md_driver.md_setno >= md_nsets) {
			err = EINVAL;
			break;
		}

		err = getnext_ioctl((md_i_getnext_t *)d, mode);
		break;
	}

	case MD_DB_USERREQ:
	case MD_MN_DB_USERREQ:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (mddb_userreq_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}
		err = mddb_userreq_ioctl((mddb_userreq_t *)d, mode);
		break;
	}

	case MD_IOCGET_NUM:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (md_i_getnum_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = getnum_ioctl(d, mode);
		break;
	}

	case MD_DB_OWNSET:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (mddb_ownset_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		if (((mddb_ownset_t *)d)->setno >= md_nsets) {
			err = EINVAL;
			break;
		}

		((mddb_ownset_t *)d)->owns_set =
		    mddb_ownset(((mddb_ownset_t *)d)->setno);

		break;
	}

	case MD_IOCGETNSET:
	{
		if (! (mode & FREAD))
			return (EACCES);

		if (ddi_copyout((caddr_t)&md_nsets, data,
		    sizeof (set_t), mode) != 0) {
			err = EFAULT;
			break;
		}
		break;
	}

	case MD_IOCGETNUNITS:
	{
		if (! (mode & FREAD))
			return (EACCES);

		if (ddi_copyout((caddr_t)&md_nunits, data,
		    sizeof (set_t), mode) != 0) {
			err = EFAULT;
			break;
		}
		break;
	}

	case MD_IOCGVERSION:
	{
		uint_t	dversion = MD_DVERSION;

		if (! (mode & FREAD))
			return (EACCES);

		if (ddi_copyout((caddr_t)&dversion, data,
		    sizeof (dversion), mode) != 0) {
			err = EFAULT;
			break;
		}
		break;
	}

	case MD_IOCSET_FLAGS:
	{
		md_set_userflags_t	*p;

		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_set_userflags_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		p = (md_set_userflags_t *)d;

		if ((err = verify_minor(p->mnum)) != 0) {
			if (err == EINVAL)
				(void) mdmderror(&p->mde, MDE_INVAL_UNIT,
				    p->mnum);
			break;
		}

		err = setuserflags(p, lockp);
		break;
	}

	case MD_IOCRENAME:
	{
		md_rename_t	*p;

		if (! (mode & FWRITE)) {
			return (EACCES);
		}

		sz = sizeof (md_rename_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		p = (md_rename_t *)d;

		if ((err = verify_minor(p->to.mnum)) != 0) {
			if (err == EINVAL)
				(void) mdmderror(&p->mde, MDE_INVAL_UNIT,
				    p->to.mnum);
			break;
		}

		if ((err = verify_minor(p->from.mnum)) != 0) {
			if (err == EINVAL)
				(void) mdmderror(&p->mde, MDE_INVAL_UNIT,
				    p->from.mnum);
			break;
		}

		err = md_rename(p, lockp);
		break;
	}

	case MD_IOCISOPEN:
	{
		md_isopen_t	*p;
		mdi_unit_t	*ui;
		minor_t		mnum;

		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (md_isopen_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		p = (md_isopen_t *)d;
		if ((p->dev <= 0) || (md_getmajor(p->dev)) != md_major) {
			err = EINVAL;
			break;
		}

		mnum = md_getminor(p->dev);

		if ((err = verify_minor(mnum)) != 0) {
			if (err == EINVAL)
				(void) mdmderror(&p->mde, MDE_INVAL_UNIT, mnum);
			break;
		}

		if ((ui = MDI_UNIT(mnum)) == NULL) {
			/*
			 * If the incore unit does not exist then rather
			 * than set err we need to set it to 0 because the
			 * multi-node code is expecting a return of
			 * 0 (from mdmderror() but with the mde structure
			 * filled with particular information
			 * (MDE_UNIT_NOT_SETUP).
			 */
			err = mdmderror(&p->mde, MDE_UNIT_NOT_SETUP, mnum);
			break;
		}

		p->isopen = md_unit_isopen(ui);
		break;
	}

	case MD_MED_GET_LST:
	{
		mddb_med_parm_t		*medpp;

		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (mddb_med_parm_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		medpp = (mddb_med_parm_t *)d;

		err = getmed_ioctl(medpp, mode);
		break;
	}

	case MD_MED_SET_LST:
	{
		mddb_med_parm_t		*medpp;

		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (mddb_med_parm_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		medpp = (mddb_med_parm_t *)d;

		err = setmed_ioctl(medpp, mode);

		break;
	}

	case MD_MED_UPD_MED:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (mddb_med_upd_parm_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = updmed_ioctl((mddb_med_upd_parm_t *)d, mode);

		break;
	}

	case MD_MED_GET_NMED:
	{
		if (! (mode & FREAD))
			return (EACCES);

		if (ddi_copyout((caddr_t)&md_nmedh, data,
		    sizeof (int), mode) != 0) {
			err = EFAULT;
			break;
		}
		break;
	}

	case MD_MED_GET_TAG:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (mddb_dtag_get_parm_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = gettag_ioctl((mddb_dtag_get_parm_t *)d, mode);

		break;
	}

	case MD_MED_USE_TAG:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (mddb_dtag_use_parm_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = usetag_ioctl((mddb_dtag_use_parm_t *)d, mode);

		break;
	}

	case MD_MED_ACCEPT:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (mddb_accept_parm_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = accept_ioctl((mddb_accept_parm_t *)d, mode);

		break;
	}

	case MD_MED_GET_TLEN:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (mddb_med_t_parm_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = med_get_t_size_ioctl((mddb_med_t_parm_t *)d, mode);

		break;
	}

	case MD_MED_GET_T:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = (sizeof (mddb_med_t_parm_t) - sizeof (mddb_med_t_ent_t)) +
		    (sizeof (mddb_med_t_ent_t) * med_addr_tab_nents);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = med_get_t_ioctl((mddb_med_t_parm_t *)d, mode);

		break;
	}

	case MD_MED_SET_T:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = (sizeof (mddb_med_t_parm_t) - sizeof (mddb_med_t_ent_t)) +
		    (sizeof (mddb_med_t_ent_t) * med_addr_tab_nents);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = med_set_t_ioctl((mddb_med_t_parm_t *)d, mode);

		break;
	}

	case  MD_GET_SETSTAT:
	{
		md_gs_stat_parm_t	*gsp;

		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (md_gs_stat_parm_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		gsp = (md_gs_stat_parm_t *)d;

		if (gsp->gs_setno > (md_nsets - 1)) {
			err = EINVAL;
			break;
		}

		gsp->gs_status = md_set[gsp->gs_setno].s_status;

		break;
	}

	case  MD_SETNMDID:
	{
		if (!(mode & FREAD))
			return (EACCES);

		sz = sizeof (mdnm_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = update_namespace_did_ioctl((mdnm_params_t *)d, mode);
		break;

	}
	case  MD_IOCUPD_NM:
	{
		char *dname;
		char *pname;
		uint_t	devnamelen, pathnamelen;

		if (!(mode & FREAD))
			return (EACCES);

		sz = sizeof (mdnm_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		devnamelen = ((mdnm_params_t *)d)->devname_len;
		pathnamelen = ((mdnm_params_t *)d)->pathname_len;

		if ((devnamelen > MAXPATHLEN) || (pathnamelen > MAXPATHLEN) ||
		    (devnamelen == 0) || (pathnamelen == 0)) {
			kmem_free(d, sz);
			return (EINVAL);
		}

		/* alloc memory for devname */
		dname = kmem_alloc(devnamelen + 1, KM_SLEEP);

		if (ddi_copyin(
		    (void *)(uintptr_t)((mdnm_params_t *)d)->devname,
		    (void *)dname, devnamelen + 1, mode) != 0) {
			err = EFAULT;
			kmem_free(dname, devnamelen + 1);
			break;
		}

		pname = kmem_alloc(pathnamelen + 1, KM_SLEEP);

		if (ddi_copyin(
		    (void *)(uintptr_t)((mdnm_params_t *)d)->pathname,
		    (void *)pname, pathnamelen + 1, mode) != 0) {
			err = EFAULT;
			kmem_free(dname, devnamelen + 1);
			kmem_free(pname, pathnamelen + 1);
			break;
		}

		err = update_namespace_ioctl((mdnm_params_t *)d, dname, pname,
		    mode);

		kmem_free(dname, devnamelen + 1);
		kmem_free(pname, pathnamelen + 1);
		break;
	}

	case	MD_IOCUPD_LOCNM:
	{
		char *dname;
		char *pname;
		uint_t	devnamelen, pathnamelen;

		if (!(mode & FREAD))
			return (EACCES);

		sz = sizeof (mdnm_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		devnamelen = ((mdnm_params_t *)d)->devname_len;
		pathnamelen = ((mdnm_params_t *)d)->pathname_len;

		if ((devnamelen > MAXPATHLEN) || (pathnamelen > MAXPATHLEN) ||
		    (devnamelen == 0) || (pathnamelen == 0)) {
			kmem_free(d, sz);
			return (EINVAL);
		}

		/* alloc memory for devname */
		dname = kmem_alloc(devnamelen + 1, KM_SLEEP);

		if (ddi_copyin(
		    (void *)(uintptr_t)((mdnm_params_t *)d)->devname,
		    (void *)dname, devnamelen + 1, mode) != 0) {
			err = EFAULT;
			kmem_free(dname, devnamelen + 1);
			break;
		}

		pname = kmem_alloc(pathnamelen + 1, KM_SLEEP);

		if (ddi_copyin(
		    (void *)(uintptr_t)((mdnm_params_t *)d)->pathname,
		    (void *)pname, pathnamelen + 1, mode) != 0) {
			err = EFAULT;
			kmem_free(dname, devnamelen + 1);
			kmem_free(pname, pathnamelen + 1);
			break;
		}

		err = update_loc_namespace_ioctl((mdnm_params_t *)d, dname,
		    pname, mode);

		kmem_free(dname, devnamelen + 1);
		kmem_free(pname, pathnamelen + 1);
		break;
	}

	case  MD_SET_SETSTAT:
	{
#ifdef DEBUG
		/* Can be used to set the s_status flags from user code */
		md_gs_stat_parm_t	*gsp;

		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_gs_stat_parm_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		gsp = (md_gs_stat_parm_t *)d;

		if (gsp->gs_setno > (md_nsets - 1)) {
			err = EINVAL;
			break;
		}

		md_set[gsp->gs_setno].s_status = gsp->gs_status;

#endif	/* DEBUG */
		break;
	}

	case MD_IOCGET_DID:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (mdnm_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = getdid_ioctl((mdnm_params_t *)d, mode);
		break;
	}

	case MD_IOCSET_DID:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (mdnm_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = setdid_ioctl((mdnm_params_t *)d, mode);
		break;
	}

	case MD_IOCGET_DIDMIN:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (mdnm_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		if (((mdnm_params_t *)d)->setno >= md_nsets) {
			err = EINVAL;
			break;
		}

		err = getdidmin_ioctl((mdnm_params_t *)d, mode);
		break;
	}

	case MD_IOCDID_STAT:
	{
		if (!(mode & FREAD))
			return (EACCES);

		mddb_didstat_case = 1;

		err = mddb_didstat_from_user(&d, data, mode, &ds_ctd_addr);

		if (err) {
			return (err);
		}

		err = didstat_ioctl((md_i_didstat_t *)d);
		break;
	}

	case MD_UPGRADE_STAT:
	{
		if (! (mode & FREAD))
			return (EACCES);

		if (ddi_copyout((caddr_t)&md_in_upgrade, data,
		    sizeof (int), mode) != 0) {
			err = EFAULT;
			break;
		}
		break;
	}

	case MD_SETMASTER:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (mddb_setmaster_config_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = mddb_setmaster_ioctl((mddb_setmaster_config_t *)d);
		break;
	}

	case MD_MN_SET_DOORH:
	{
	/* This ioctl sets the global kernel variable mdmn_door_handle */
		if (ddi_copyin(data, &mdmn_door_did, sizeof (int), mode) != 0) {
			err = EFAULT;
		} else {
			err = 0;
		}
		mdmn_door_handle = door_ki_lookup(mdmn_door_did);

		break;
	}

#ifdef DEBUG
	case MD_MN_CHECK_DOOR1:
	{
	/* This ioctl sends a message through a previously opened door */
		int		ret;
		int		msg_test = 11111111;
		int		nloops = 0;
		set_t		setno;
		md_mn_kresult_t	*result;
		uint_t		flags = MD_MSGF_NO_LOG | MD_MSGF_NO_BCAST;

		result = kmem_zalloc(sizeof (md_mn_kresult_t), KM_SLEEP);
		if (ddi_copyin(data, &nloops, sizeof (int), mode) != 0) {
			err = EFAULT;
		} else {
			err = 0;
		}

		/*
		 * This is a way to tell ksend_message() to use different sets.
		 * Odd numbers go to set 1 even numbers go to set 2
		 */
		if (nloops & 0x1) {
			setno = 1;
		} else {
			setno = 2;
		}
		while (nloops--)  {
			ret = mdmn_ksend_message(
			    setno,
			    MD_MN_MSG_TEST1,
			    flags,
			    (char *)&msg_test,
			    sizeof (msg_test),
			    result);

			if (ret != 0) {
				printf("mdmn_ksend_message failed (%d)\n", ret);
			}
		}
		kmem_free(result, sizeof (md_mn_kresult_t));

		break;
	}

	case MD_MN_CHECK_DOOR2:
	{
	/* This ioctl sends a message through a previously opened door */
		int		ret;
		int		msg_test = 22222222;
		int		nloops = 0;
		md_mn_kresult_t	*result;
		set_t		setno;
		uint_t		flags = MD_MSGF_NO_LOG;

		result = kmem_zalloc(sizeof (md_mn_kresult_t), KM_SLEEP);
		if (ddi_copyin(data, &nloops, sizeof (int), mode) != 0) {
			err = EFAULT;
		} else {
			err = 0;
		}
		/*
		 * This is a way to tell ksend_message() to use different sets.
		 * Odd numbers go to set 1 even numbers go to set 2
		 */
		if (nloops & 0x1) {
			setno = 1;
		} else {
			setno = 2;
		}
		while (nloops--)  {
			ret = mdmn_ksend_message(
			    setno,
			    MD_MN_MSG_TEST2,
			    flags,
			    (char *)&msg_test,
			    sizeof (msg_test),
			    result);

			if (ret != 0) {
				printf("mdmn_ksend_message failed (%d)\n", ret);
			}
		}
		kmem_free(result, sizeof (md_mn_kresult_t));

		break;
	}
#endif

	case MD_MN_OPEN_TEST:
	{
		md_clu_open_t	*p;
		minor_t		mnum;

		sz = sizeof (md_clu_open_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sizeof (md_clu_open_t), mode) != 0) {
			err = EFAULT;
			break;
		}

		p = (md_clu_open_t *)d;
		mnum = md_getminor(p->clu_dev);

		if ((err = verify_minor(mnum)) != 0) {
			if (err == EINVAL)
				(void) mdmderror(&p->clu_mde, MDE_INVAL_UNIT,
				    mnum);
			break;
		}
		err = md_clu_ioctl(p);
		break;
	}

	case MD_MN_SET_NODEID:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (mddb_set_node_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}
		snp = (mddb_set_node_params_t *)d;

		if (snp->sn_setno >= md_nsets) {
			err = EINVAL;
			break;
		}

		md_set[snp->sn_setno].s_nodeid = snp->sn_nodeid;

		if (md_mn_mynode_id == MD_MN_INVALID_NID)
			md_mn_mynode_id = snp->sn_nodeid;
#ifdef DEBUG
		else if (md_mn_mynode_id != snp->sn_nodeid)
			cmn_err(CE_WARN, "Previously set nodeid 0x%x for this"
			    "node doesn't match nodeid being set 0x%x\n",
			    md_mn_mynode_id, snp->sn_nodeid);
#endif /* DEBUG */
		err = 0;
		break;
	}
	case MD_IOCGUNIQMSGID:
	{
		md_mn_msgid_t msgid;
		struct timeval32 tv;

		if (! (mode & FREAD))
			return (EACCES);

		uniqtime32(&tv);

		/* high 32 bits are the seconds */
		msgid.mid_time = (u_longlong_t)tv.tv_sec << 32;
		/* low 32 bits are the micro secs */
		msgid.mid_time |= tv.tv_usec;

		msgid.mid_nid = md_mn_mynode_id;
		/*
		 * This is never called for submessages, so we better
		 * null out the submessage ID
		 */
		msgid.mid_smid = 0;

		if (ddi_copyout((caddr_t)&msgid, data, sizeof (msgid), mode)
		    != 0) {
			err = EFAULT;
			break;
		}
		break;
	}

	/*
	 * suspend the IO's for a given set number.
	 *
	 * If setno = 0 is specified, try operation on all snarfed MN disksets.
	 * If there are no snarfed MN disksets, then return success.
	 *
	 * If a specific set number is given, then return EINVAL if unable
	 * to perform operation.
	 */
	case MD_MN_SUSPEND_SET:
	{
		set_t	setno;
		int	rval = 0;
		int	i;

		if (! (mode & FWRITE))
			return (EACCES);

		if (ddi_copyin(data, &setno, sizeof (set_t), mode) != 0) {
			return (EFAULT);
		}
		if (setno >= MD_MAXSETS) {
			return (EINVAL);
		}

		mutex_enter(&md_mx);
		if (setno == 0) {
			/* if set number is 0, we walk all sets */
			for (i = 1; i <= (MD_MAXSETS - 1); i++) {
				if ((md_set[i].s_status &
				    (MD_SET_SNARFED|MD_SET_MNSET)) ==
				    (MD_SET_SNARFED|MD_SET_MNSET)) {
					md_set[i].s_status |= MD_SET_HALTED;
				}
			}
		} else {
			/* If unable to halt specified set, set EINVAL */
			if ((md_set[setno].s_status &
			    (MD_SET_SNARFED|MD_SET_MNSET)) ==
			    (MD_SET_SNARFED|MD_SET_MNSET)) {
				md_set[setno].s_status |= MD_SET_HALTED;
			} else {
				rval = EINVAL;
			}
		}
		mutex_exit(&md_mx);
		return (rval);
	}

	/*
	 * resume the IO's for a given set number.
	 *
	 * If setno = 0 is specified, try operation on all snarfed MN disksets.
	 * If there are no snarfed MN disksets, then return success.
	 *
	 * If a specific set number is given, then return EINVAL if unable
	 * to perform operation.
	 */
	case MD_MN_RESUME_SET:
	{
		set_t	setno;
		int	resumed_set = 0;
		int	rval = 0;
		int	i;

		if (! (mode & FWRITE))
			return (EACCES);

		if (ddi_copyin(data, &setno, sizeof (set_t), mode) != 0) {
			return (EFAULT);
		}
		if (setno >= MD_MAXSETS) {
			return (EINVAL);
		}

		/* if 0 is specified as the set number, we walk all sets */
		mutex_enter(&md_mx);
		if (setno == 0) {
			/* if set number is 0, we walk all sets */
			for (i = 1; i <= (MD_MAXSETS - 1); i++) {
				if ((md_set[i].s_status &
				    (MD_SET_SNARFED|MD_SET_MNSET)) ==
				    (MD_SET_SNARFED|MD_SET_MNSET)) {
					md_set[i].s_status &= ~MD_SET_HALTED;
					resumed_set = 1;
				}
			}
		} else {
			/* If unable to resume specified set, set EINVAL */
			if ((md_set[setno].s_status &
			    (MD_SET_SNARFED|MD_SET_MNSET)) ==
			    (MD_SET_SNARFED|MD_SET_MNSET)) {
				md_set[setno].s_status &= ~MD_SET_HALTED;
				resumed_set = 1;
			} else {
				rval = EINVAL;
			}
		}

		/*
		 * In case we actually resumed at least one set,
		 * Inform all threads waiting for this change
		 */
		if (resumed_set == 1) {
			cv_broadcast(&md_cv);
		}

		mutex_exit(&md_mx);
		return (rval);
	}

	case MD_MN_MDDB_PARSE:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (mddb_parse_parm_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}
		err = mddb_parse((mddb_parse_parm_t *)d);
		break;

	}

	case MD_MN_MDDB_BLOCK:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (mddb_block_parm_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}
		err = mddb_block((mddb_block_parm_t *)d);
		break;

	}

	case MD_MN_MDDB_OPTRECFIX:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (mddb_optrec_parm_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}
		err = mddb_optrecfix((mddb_optrec_parm_t *)d);
		break;

	}

	case MD_MN_CHK_WRT_MDDB:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (mddb_config_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = mddb_check_write_ioctl((mddb_config_t *)d);
		break;
	}

	case MD_MN_SET_SETFLAGS:
	case MD_MN_GET_SETFLAGS:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (mddb_setflags_config_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = mddb_setflags_ioctl((mddb_setflags_config_t *)d);
		break;
	}

	case MD_MN_COMMD_ERR:
	{
		md_mn_commd_err_t *cmp;
		char *msg;

		sz = sizeof (md_mn_commd_err_t);
		d = kmem_zalloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		cmp = (md_mn_commd_err_t *)d;
		if (cmp->size > MAXPATHLEN) {
			err = EINVAL;
			break;
		}

		msg = (char *)kmem_zalloc(cmp->size + 1, KM_SLEEP);
		if (ddi_copyin((caddr_t)(uintptr_t)cmp->md_message, msg,
		    cmp->size, mode) != 0) {
			kmem_free(msg, cmp->size + 1);
			err = EFAULT;
			break;
		}
		cmn_err(CE_WARN, "%s\n", msg);
		kmem_free(msg, cmp->size + 1);
		break;
	}

	case MD_IOCMAKE_DEV:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_mkdev_params_t);

		if ((d = kmem_alloc(sz, KM_NOSLEEP)) == NULL)
			return (ENOMEM);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = mkdev_ioctl((md_mkdev_params_t *)d);
		break;
	}

	case MD_IOCREM_DEV:
	{
		set_t	setno;

		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (minor_t);

		d = kmem_zalloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		/*
		 * This ioctl is called to cleanup the device name
		 * space when metainit fails or -n is invoked
		 * In this case, reclaim the dispatched un slot
		 */
		setno = MD_MIN2SET(*(minor_t *)d);
		if (setno >= md_nsets) {
			err = EINVAL;
			break;
		} else if (md_set[setno].s_un_next <= 0) {
			err = EFAULT;
			break;
		} else {
			md_set[setno].s_un_next--;
		}

		/*
		 * Attempt to remove the assocated device node
		 */
		md_remove_minor_node(*(minor_t *)d);
		break;
	}

	/*
	 * Update md_mn_commd_present global to reflect presence or absence of
	 * /usr/sbin/rpc.mdcommd. This allows us to determine if an RPC failure
	 * is expected during a mdmn_ksend_message() handshake. If the commd is
	 * not present then an RPC failure is acceptable. If the commd _is_
	 * present then an RPC failure means we have an inconsistent view across
	 * the cluster.
	 */
	case MD_MN_SET_COMMD_RUNNING:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		md_mn_commd_present = (int)(intptr_t)data;
		err = 0;
		break;
	}

	case MD_IOCIMP_LOAD:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		mddb_config_case = 1;

		err = mddb_config_from_user(&d, data, mode, &c_devid_addr,
		    &c_old_devid_addr);

		if (err) {
			return (err);
		}

		err = md_imp_snarf_set((mddb_config_t *)d);
		break;

	}

	case MD_DB_LBINITTIME:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		mddb_config_case = 1;

		err = mddb_config_from_user(&d, data, mode, &c_devid_addr,
		    &c_old_devid_addr);

		if (err)
			return (err);

		err = get_lb_inittime_ioctl((mddb_config_t *)d);
		break;
	}
	case MD_IOCUPDATE_NM_RR_DID:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		mddb_config_case = 1;

		err = mddb_config_from_user(&d, data, mode, &c_devid_addr,
		    &c_old_devid_addr);

		if (err)
			return (err);

		err = md_update_nm_rr_did_ioctl((mddb_config_t *)d);
		break;
	}
	default:
		return (ENOTTY);	/* used by next level up */
	}

	/*
	 * copyout and free any args
	 */
	if (mddb_config_case) {
		err_to_user = mddb_config_to_user(d, data, mode, c_devid_addr,
		    c_old_devid_addr);
	} else if (mddb_didstat_case) {
		err_to_user = mddb_didstat_to_user(d, data, mode, ds_ctd_addr);
	} else if (sz != 0) {
		if (ddi_copyout(d, data, sz, mode) != 0) {
			err = EFAULT;
		}
		kmem_free(d, sz);
	}

	if (err)
		return (err);
	return (err_to_user);
}

int
md_admin_ioctl(md_dev64_t dev, int cmd, caddr_t data, int mode, IOLOCK *lockp)
{
	md_driver_t	drv;
	int		modindex;
	int		err;

	/*
	 * see if we can do this without involving the subdriver
	 */
	if ((err = md_base_ioctl(dev, cmd, data, mode, lockp)) != ENOTTY)
		return (err);

	/*
	 * see what subdriver we need
	 */
	if (! ISMDIOC(cmd))
		return (ENOTTY);

	if ((!NODBNEEDED(cmd)) && md_snarf_db_set(MD_LOCAL_SET, NULL) != 0)
		return (ENODEV);

	if (ddi_copyin(data, (caddr_t)&drv, sizeof (drv), mode) != 0)
		return (EFAULT);

	/*
	 * load subdriver if not already loaded
	 */
	if (((modindex = md_getmodindex(&drv, 0, NODBNEEDED(cmd))) == -1) ||
	    (md_ops[modindex]->md_ioctl == NULL))
		return (ENOTTY);

	/*
	 * dispatch to subdriver
	 */
	return ((*md_ops[modindex]->md_ioctl)(md_dev64_to_dev(dev), cmd, data,
	    mode, lockp));
}

void
md_get_geom(
	md_unit_t	*un,
	struct dk_geom	*gp
)
{
	diskaddr_t		tb = un->c.un_total_blocks;
	uint_t			cylsize = un->c.un_nhead * un->c.un_nsect;

	bzero((caddr_t)gp, sizeof (*gp));
	gp->dkg_nhead = un->c.un_nhead;
	gp->dkg_nsect = un->c.un_nsect;
	gp->dkg_rpm = un->c.un_rpm;
	gp->dkg_write_reinstruct = un->c.un_wr_reinstruct;
	gp->dkg_read_reinstruct = un->c.un_rd_reinstruct;
	gp->dkg_ncyl = (ushort_t)(tb / cylsize);
	if (! (un->c.un_flag & MD_LABELED))	/* skip first cyl */
		gp->dkg_ncyl += 1;
	gp->dkg_pcyl = gp->dkg_ncyl;
}

void
md_get_vtoc(md_unit_t *un, struct vtoc *vtoc)
{
	caddr_t			v;
	mddb_recstatus_t	status;
	struct vtoc32		*vt32;

	/*
	 * Return vtoc structure fields in the provided VTOC area, addressed
	 * by *vtoc.
	 *
	 */

	if (un->c.un_vtoc_id) {
		status = mddb_getrecstatus(un->c.un_vtoc_id);
		if (status == MDDB_OK) {
			v = mddb_getrecaddr(un->c.un_vtoc_id);
			/* if this seems to be a sane vtoc, just copy it ... */
			if (((struct vtoc *)v)->v_sanity == VTOC_SANE) {
				bcopy(v, (caddr_t)vtoc, sizeof (struct vtoc));
			} else {
				/* ... else assume a vtoc32 was stored here */
				vt32 = (struct vtoc32 *)v;
				vtoc32tovtoc((*vt32), (*vtoc));
			}
			if (un->c.un_flag & MD_LABELED)
				vtoc->v_part[0].p_start = 0ULL;
			else
				vtoc->v_part[0].p_start = (diskaddr_t)
				    (un->c.un_nhead * un->c.un_nsect);
			vtoc->v_part[0].p_size = un->c.un_total_blocks;
			vtoc->v_version = V_VERSION;
			vtoc->v_sectorsz = DEV_BSIZE;
			return;
		}

		un->c.un_vtoc_id = 0;
		mddb_commitrec_wrapper(un->c.un_record_id);
	}

	bzero((caddr_t)vtoc, sizeof (struct vtoc));
	vtoc->v_sanity = VTOC_SANE;
	vtoc->v_nparts = 1;
	vtoc->v_version = V_VERSION;
	vtoc->v_sectorsz = DEV_BSIZE;
	if (un->c.un_flag & MD_LABELED)
		vtoc->v_part[0].p_start = 0ULL;
	else
		vtoc->v_part[0].p_start = (diskaddr_t)(un->c.un_nhead *
		    un->c.un_nsect);
	vtoc->v_part[0].p_size = un->c.un_total_blocks;
}

int
md_set_vtoc(md_unit_t *un, struct vtoc *vtoc)
{

	struct partition	*vpart;
	int			i;
	mddb_recid_t		recid;
	mddb_recid_t		recids[3];
	mddb_recstatus_t	status;
	caddr_t			v;
	diskaddr_t		sb;

	/*
	 * Sanity-check the vtoc
	 */
	if (vtoc->v_sanity != VTOC_SANE || vtoc->v_nparts != 1)
		return (EINVAL);

	/* don't allow to create a vtoc for a big metadevice */
	if (un->c.un_revision & MD_64BIT_META_DEV)
		return (ENOTSUP);
	/*
	 * Validate the partition table
	 */
	vpart = vtoc->v_part;
	for (i = 0; i < V_NUMPAR; i++, vpart++) {
		if (i == 0) {
			if (un->c.un_flag & MD_LABELED)
				sb = 0ULL;
			else
				sb = (diskaddr_t)(un->c.un_nhead *
				    un->c.un_nsect);
			if (vpart->p_start != sb)
				return (EINVAL);
			if (vpart->p_size != un->c.un_total_blocks)
				return (EINVAL);
			continue;
		}
		/* all other partitions must be zero */
		if (vpart->p_start != 0ULL)
			return (EINVAL);
		if (vpart->p_size != 0ULL)
			return (EINVAL);
	}

	if (un->c.un_vtoc_id) {
		recid = un->c.un_vtoc_id;
		status = mddb_getrecstatus(recid);
		if (status == MDDB_OK) {
			/*
			 * If there's enough space in the record, and the
			 * existing record is a vtoc record (not EFI),
			 * we just can use the existing space.
			 * Otherwise, we create a new MDDB_VTOC record for
			 * this unit.
			 */
			if ((mddb_getrecsize(recid) >= sizeof (struct vtoc)) &&
			    ((un->c.un_flag & MD_EFILABEL) == 0)) {
				v = mddb_getrecaddr(recid);
				bcopy((caddr_t)vtoc, v, sizeof (struct vtoc));
				mddb_commitrec_wrapper(recid);
				recids[0] = recid;
				recids[1] = un->c.un_record_id;
				recids[2] = 0;
				un->c.un_flag &= ~MD_EFILABEL;
				mddb_commitrecs_wrapper(recids);
				return (0);
			}

			un->c.un_vtoc_id = 0;
			mddb_commitrec_wrapper(un->c.un_record_id);
			mddb_deleterec_wrapper(recid);
		}
	}

	recid = mddb_createrec(sizeof (struct vtoc), MDDB_VTOC, 0,
	    MD_CRO_32BIT, MD_UN2SET(un));

	if (recid < 0) {
		return (ENOSPC);
	}

	recids[0] = recid;
	recids[1] = un->c.un_record_id;
	recids[2] = 0;
	v = mddb_getrecaddr(recid);
	bcopy((caddr_t)vtoc, v, sizeof (struct vtoc));

	un->c.un_vtoc_id = recid;
	un->c.un_flag &= ~MD_EFILABEL;
	mddb_commitrecs_wrapper(recids);
	return (0);
}

void
md_get_extvtoc(md_unit_t *un, struct extvtoc *extvtoc)
{
	caddr_t			v;
	mddb_recstatus_t	status;
	struct vtoc32		*vt32;
	struct vtoc		*vtoc;

	/*
	 * Return extvtoc structure fields in the provided VTOC area, addressed
	 * by *extvtoc.
	 *
	 */

	bzero((caddr_t)extvtoc, sizeof (struct extvtoc));
	if (un->c.un_vtoc_id) {
		status = mddb_getrecstatus(un->c.un_vtoc_id);
		if (status == MDDB_OK) {
			v = mddb_getrecaddr(un->c.un_vtoc_id);
			if (un->c.un_flag & MD_EFILABEL) {
				bcopy(v, (caddr_t)&(extvtoc->v_volume),
				    LEN_DKL_VVOL);
			} else {
				/*
				 * if this seems to be a sane vtoc,
				 * just copy it ...
				 */
				if (((struct vtoc *)v)->v_sanity == VTOC_SANE) {
					vtoc = (struct vtoc *)v;
					vtoctoextvtoc((*vtoc), (*extvtoc));
				} else {
					/* assume a vtoc32 was stored here */
					vt32 = (struct vtoc32 *)v;
					vtoc32toextvtoc((*vt32), (*extvtoc));
				}
			}
		} else {
			un->c.un_vtoc_id = 0;
			mddb_commitrec_wrapper(un->c.un_record_id);
		}
	}

	extvtoc->v_sanity = VTOC_SANE;
	extvtoc->v_nparts = 1;
	extvtoc->v_version = V_VERSION;
	extvtoc->v_sectorsz = DEV_BSIZE;
	if (un->c.un_flag & MD_LABELED)
		extvtoc->v_part[0].p_start = 0ULL;
	else
		extvtoc->v_part[0].p_start = (diskaddr_t)(un->c.un_nhead *
		    un->c.un_nsect);
	extvtoc->v_part[0].p_size = un->c.un_total_blocks;
}

int
md_set_extvtoc(md_unit_t *un, struct extvtoc *extvtoc)
{

	struct extpartition	*vpart;
	int			i;
	mddb_recid_t		recid;
	mddb_recid_t		recids[3];
	mddb_recstatus_t	status;
	caddr_t			v;
	diskaddr_t		sb;
	struct vtoc		vtoc;

	/*
	 * Sanity-check the vtoc
	 */
	if (extvtoc->v_sanity != VTOC_SANE || extvtoc->v_nparts != 1)
		return (EINVAL);

	/*
	 * Validate the partition table
	 */
	vpart = extvtoc->v_part;
	for (i = 0; i < V_NUMPAR; i++, vpart++) {
		if (i == 0) {
			if (un->c.un_flag & MD_LABELED)
				sb = 0ULL;
			else
				sb = (diskaddr_t)(un->c.un_nhead *
				    un->c.un_nsect);
			if (vpart->p_start != sb)
				return (EINVAL);
			if (vpart->p_size != un->c.un_total_blocks)
				return (EINVAL);
			continue;
		}
		/* all other partitions must be zero */
		if (vpart->p_start != 0ULL)
			return (EINVAL);
		if (vpart->p_size != 0)
			return (EINVAL);
	}

	if (!(un->c.un_revision & MD_64BIT_META_DEV)) {
		extvtoctovtoc((*extvtoc), (vtoc));
		return (md_set_vtoc(un, &vtoc));
	}

	/*
	 * Since the size is greater than 1 TB the information can either
	 * be stored as a VTOC or EFI.  Since EFI uses less space just use
	 * it.  md_get_extvtoc can reconstruct the label information from
	 * either format.
	 */
	if (un->c.un_vtoc_id) {
		recid = un->c.un_vtoc_id;
		status = mddb_getrecstatus(recid);
		if (status == MDDB_OK) {
			/*
			 * If there's enough space in the record, and the
			 * existing record is an EFI record (not vtoc),
			 * we just can use the existing space.
			 * Otherwise, we create a new MDDB_EFILABEL record for
			 * this unit.
			 */
			if ((mddb_getrecsize(recid) >= MD_EFI_PARTNAME_BYTES) &&
			    (un->c.un_flag & MD_EFILABEL))  {
				v = mddb_getrecaddr(recid);
				bzero((caddr_t)v, MD_EFI_PARTNAME_BYTES);
				bcopy((caddr_t)&(extvtoc->v_volume),
				    v, LEN_DKL_VVOL);
				mddb_commitrec_wrapper(recid);
				return (0);
			}

			un->c.un_vtoc_id = 0;
			mddb_commitrec_wrapper(un->c.un_record_id);
			mddb_deleterec_wrapper(recid);
		}
	}

	recid = mddb_createrec(MD_EFI_PARTNAME_BYTES, MDDB_EFILABEL, 0,
	    MD_CRO_32BIT, MD_UN2SET(un));

	if (recid < 0) {
		return (ENOSPC);
	}

	recids[0] = recid;
	recids[1] = un->c.un_record_id;
	recids[2] = 0;
	v = mddb_getrecaddr(recid);
	bzero((caddr_t)v, MD_EFI_PARTNAME_BYTES);
	bcopy((caddr_t)&(extvtoc->v_volume), v, LEN_DKL_VVOL);

	un->c.un_vtoc_id = recid;
	un->c.un_flag |= MD_EFILABEL;
	mddb_commitrecs_wrapper(recids);
	return (0);
}


void
md_get_cgapart(md_unit_t *un, struct dk_map *dkmapp)
{

	/* skip the first cyl */
	dkmapp->dkl_cylno = 1;

	dkmapp->dkl_nblk = (daddr_t)un->c.un_total_blocks;
}

static struct uuid md_efi_reserved = EFI_RESERVED;

/*
 * md_get_efi
 * INPUT:
 *	un; the md_unit
 *	buf; the buffer that is preallocated by the calling routine and
 *		capable of taking the EFI label for this unit
 * OUTPUT:
 *	A filled buffer, containing one struct efi_gpt followed by one
 *		struct efi_gpe, because a md efi only has one valid partition
 *		We fetch that date either from the mddb (like vtoc)
 *		or we a fake an EFI label.
 *
 * NOTES:
 *	We do not provide for any global unique identifiers,
 *	We also use the field c.un_vtoc_id, as the semantic is very similar
 *	When we are called, it's already checked, that this unit has an EFI
 *		label and not a vtoc
 */

void
md_get_efi(md_unit_t *un, char *buf)
{
	caddr_t		v;
	efi_gpt_t	*efi_header = (efi_gpt_t *)buf;
	efi_gpe_t	*efi_part = (efi_gpe_t *)(buf + sizeof (efi_gpt_t));
	mddb_recstatus_t	status;

	/* first comes the header */
	efi_header->efi_gpt_Signature = LE_64(EFI_SIGNATURE);
	efi_header->efi_gpt_HeaderSize = LE_32(sizeof (efi_gpt_t));
	efi_header->efi_gpt_NumberOfPartitionEntries = LE_32(1);
	efi_header->efi_gpt_SizeOfPartitionEntry = LE_32(sizeof (efi_gpe_t));
	efi_header->efi_gpt_LastUsableLBA = LE_64(un->c.un_total_blocks - 1);
	efi_header->efi_gpt_FirstUsableLBA = 0;
	efi_header->efi_gpt_Revision = LE_32(EFI_VERSION_CURRENT);

	/*
	 * We don't fill out any of these:
	 *
	 * efi_header->efi_gpt_HeaderCRC32;
	 * efi_header->efi_gpt_DiskGUID;
	 * efi_header->efi_gpt_PartitionEntryArrayCRC32;
	 * efi_header->efi_gpt_Reserved1;
	 * efi_header->efi_gpt_MyLBA;
	 * efi_header->efi_gpt_AlternateLBA;
	 * efi_header->efi_gpt_Reserved2[LEN_EFI_PAD];
	 * efi_header->efi_gpt_PartitionEntryLBA;
	 */

	/*
	 * We copy back one partition, of type reserved,
	 * which may contain the name of the metadevice
	 * (this is what was used to be v_volume for a vtoc device)
	 * if no name is stored in the vtoc record, we hand an empty name
	 * to the user
	 */

	UUID_LE_CONVERT(efi_part->efi_gpe_PartitionTypeGUID, md_efi_reserved);
	if (un->c.un_flag & MD_LABELED)
		efi_part->efi_gpe_StartingLBA = LE_64(1ULL);
	else
		efi_part->efi_gpe_StartingLBA = 0;

	efi_part->efi_gpe_EndingLBA = LE_64(un->c.un_total_blocks - 1);

	if (un->c.un_vtoc_id) {
		status = mddb_getrecstatus(un->c.un_vtoc_id);
		if (status == MDDB_OK) {
			v = mddb_getrecaddr(un->c.un_vtoc_id);
			bcopy(v, (caddr_t)&(efi_part->efi_gpe_PartitionName),
			    MD_EFI_PARTNAME_BYTES);
			return;
		}
		un->c.un_vtoc_id = 0;
		mddb_commitrec_wrapper(un->c.un_record_id);
	}

	/*
	 * We don't fill out any of these
	 * efi_part->efi_gpe_UniquePartitionGUID
	 * efi_part->efi_gpe_Attributes
	 */
}


/*
 * md_set_efi
 * INPUT:
 *	un; a md_unit
 *	buf; a buffer that is holding an EFI label for this unit
 *
 * PURPOSE:
 *	Perform some sanity checks on the EFI label provided,
 *	Then store efi_gpe_PartitionName in the mddb
 *	and link the unit's c.un_vtoc_id field to it.
 *
 * RETURN:
 *	EINVAL if any of the sanity checks fail
 *	0 on succes
 *
 * NOTES:
 *	We do not provide for any global unique identifiers,
 *	We also use the field c.un_vtoc_id, as the semantic is very similar
 *	When we are called, it's already checked, that this unit has an EFI
 *		label and not a vtoc
 */


int
md_set_efi(md_unit_t *un, char *buf)
{

	mddb_recid_t		recid;
	mddb_recid_t		recids[3];
	mddb_recstatus_t	status;
	caddr_t			v;
	efi_gpt_t	*efi_header = (efi_gpt_t *)buf;
	efi_gpe_t	*efi_part = (efi_gpe_t *)(buf + sizeof (efi_gpt_t));
	struct uuid	md_efi_reserved_le;

	/*
	 * Sanity-check the EFI label
	 */
	if ((efi_header->efi_gpt_Signature != LE_64(EFI_SIGNATURE)) ||
	    (efi_header->efi_gpt_NumberOfPartitionEntries != LE_32(1)))
		return (EINVAL);

	UUID_LE_CONVERT(md_efi_reserved_le, md_efi_reserved);

	/*
	 * Validate the partition
	 */
	if (efi_part->efi_gpe_StartingLBA != 0 ||
	    efi_part->efi_gpe_EndingLBA != LE_64(un->c.un_total_blocks - 1) ||
	    bcmp(&efi_part->efi_gpe_PartitionTypeGUID, &md_efi_reserved_le,
	    sizeof (struct uuid))) {
		return (EINVAL);
	}
	/*
	 * If no name is specified, we have nothing to do and return success.
	 * because efi_gpe_PartitionName is in unicode form, we have to
	 * check the first two bytes of efi_gpe_PartitionName.
	 */
	if (((char *)(uintptr_t)efi_part->efi_gpe_PartitionName[0] == NULL) &&
	    ((char *)(uintptr_t)efi_part->efi_gpe_PartitionName[1] == NULL)) {
		return (0);
	}

	if (un->c.un_vtoc_id) {
		recid = un->c.un_vtoc_id;
		status = mddb_getrecstatus(recid);
		if (status == MDDB_OK) {
			/*
			 * If there's enough space in the record, and the
			 * existing record is an EFI record (not vtoc),
			 * we just can use the existing space.
			 * Otherwise, we create a new MDDB_EFILABEL record for
			 * this unit.
			 */
			if ((mddb_getrecsize(recid) >= MD_EFI_PARTNAME_BYTES) &&
			    (un->c.un_flag & MD_EFILABEL))  {
				v = mddb_getrecaddr(recid);
				bcopy((caddr_t)&efi_part->efi_gpe_PartitionName,
				    v, MD_EFI_PARTNAME_BYTES);
				mddb_commitrec_wrapper(recid);
				return (0);
			}

			un->c.un_vtoc_id = 0;
			mddb_commitrec_wrapper(un->c.un_record_id);
			mddb_deleterec_wrapper(recid);
		}
	}

	recid = mddb_createrec(MD_EFI_PARTNAME_BYTES, MDDB_EFILABEL, 0,
	    MD_CRO_32BIT, MD_UN2SET(un));

	if (recid < 0) {
		return (ENOSPC);
	}

	recids[0] = recid;
	recids[1] = un->c.un_record_id;
	recids[2] = 0;
	v = mddb_getrecaddr(recid);
	bcopy((caddr_t)&efi_part->efi_gpe_PartitionName, v,
	    MD_EFI_PARTNAME_BYTES);

	un->c.un_vtoc_id = recid;
	un->c.un_flag |= MD_EFILABEL;
	mddb_commitrecs_wrapper(recids);
	return (0);
}

int
md_dkiocgetefi(minor_t mnum, void *data, int mode)
{
	dk_efi_t	efi;
	caddr_t		*buf;
	int		rval = 0;
	mdi_unit_t	*ui;
	md_unit_t	*mdun;

	if (!(mode & FREAD))
		return (EACCES);

	if (ddi_copyin(data, &efi, sizeof (dk_efi_t), mode))
		return (EFAULT);

	efi.dki_data = (void *)(uintptr_t)efi.dki_data_64;

	/*
	 * If the user specified a zero length or a null pointer, we give them
	 * the number of bytes to alloc in user land.
	 */
	if (efi.dki_length == 0 || efi.dki_data == NULL) {
		efi.dki_length = MD_EFI_LABEL_SIZE;
		if (ddi_copyout(&efi, data, sizeof (dk_efi_t), mode))
			return (EFAULT);
		return (0);
	}
	/* Bad size specified, better not answer to that query */
	if (efi.dki_length < MD_EFI_LABEL_SIZE)
		return (EINVAL);

	if ((ui = MDI_UNIT(mnum)) == NULL)
		return (ENXIO);

	/*
	 * We don't want to allocate as much bytes as we are told,
	 * because we know the good size is MD_EFI_LABEL_SIZE
	 */
	efi.dki_length = MD_EFI_LABEL_SIZE;
	buf = kmem_zalloc(MD_EFI_LABEL_SIZE, KM_SLEEP);

	mdun = (md_unit_t *)md_unit_readerlock(ui);
	md_get_efi(mdun, (char *)buf);
	md_unit_readerexit(ui);

	if (ddi_copyout(buf, efi.dki_data, efi.dki_length, mode))
		rval = EFAULT;

	kmem_free(buf, MD_EFI_LABEL_SIZE);
	return (rval);
}

int
md_dkiocsetefi(minor_t mnum, void *data, int mode)
{
	dk_efi_t	efi;
	caddr_t		*buf;
	int		rval = 0;
	mdi_unit_t	*ui;
	md_unit_t	*mdun;

	if (!(mode & FREAD))
		return (EACCES);

	if ((ui = MDI_UNIT(mnum)) == NULL)
		return (ENXIO);

	if (ddi_copyin(data, &efi, sizeof (dk_efi_t), mode))
		return (EFAULT);

	efi.dki_data = (void *)(uintptr_t)efi.dki_data_64;

	/* Sanity check of the skeleton */
	if ((efi.dki_length > sizeof (efi_gpt_t) + EFI_MIN_ARRAY_SIZE) ||
	    (efi.dki_length < sizeof (efi_gpt_t) + sizeof (efi_gpe_t)) ||
	    (efi.dki_data == NULL))
		return (EINVAL);

	/*
	 * It's only a real EFI label if the location is 1
	 * in all other cases, we do nothing but say we did.
	 */
	if (efi.dki_lba != 1)
		return (0);	/* success */

	buf = kmem_alloc(efi.dki_length, KM_SLEEP);
	/* And here we copy in the real data */
	if (ddi_copyin(efi.dki_data, buf, efi.dki_length, mode)) {
		rval = EFAULT;
	} else {
		mdun = (md_unit_t *)md_unit_readerlock(ui);
		rval = md_set_efi(mdun, (char *)buf);
		md_unit_readerexit(ui);
	}

	kmem_free(buf, efi.dki_length);
	return (rval);
}

/*
 * md_dkiocpartition()
 * Return the appropriate partition64 structure for a given metadevice.
 *
 * Actually the only real information being returned is the number of blocks
 * of the specified metadevice.
 * The starting block is always 0, and so is the partition number, because
 * metadevices don't have slices.
 *
 * This function is generic for all types of metadevices.
 */
int
md_dkiocpartition(minor_t mnum, void *data, int mode)
{
	struct partition64	p64;
	mdi_unit_t		*ui;
	md_unit_t		*un;
	int			rval = 0;

	if (!(mode & FREAD))
		return (EACCES);


	if ((ui = MDI_UNIT(mnum)) == NULL)
		return (ENXIO);

	if (ddi_copyin(data, &p64, sizeof (struct partition64), mode))
		return (EFAULT);

	if (p64.p_partno != 0)
		return (ESRCH);

	un = (md_unit_t *)md_unit_readerlock(ui);
	/* All metadevices share the same PartitionTypeGUID (see md_get_efi) */
	UUID_LE_CONVERT(p64.p_type, md_efi_reserved);

	p64.p_partno = 0;
	p64.p_start = 0;
	p64.p_size = un->c.un_total_blocks;
	md_unit_readerexit(ui);

	if (ddi_copyout(&p64, data, sizeof (struct partition64), mode)) {
		rval = EFAULT;
	}

	return (rval);
}


/*
 * Remove device node
 */
void
md_remove_minor_node(minor_t mnum)
{
	char			name[16];
	extern dev_info_t	*md_devinfo;

	/*
	 * Attempt release of its minor node
	 */
	(void) snprintf(name, sizeof (name), "%d,%d,blk", MD_MIN2SET(mnum),
	    MD_MIN2UNIT(mnum));
	ddi_remove_minor_node(md_devinfo, name);

	(void) snprintf(name, sizeof (name), "%d,%d,raw", MD_MIN2SET(mnum),
	    MD_MIN2UNIT(mnum));
	ddi_remove_minor_node(md_devinfo, name);
}
