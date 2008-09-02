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

#include <dlfcn.h>
#include <meta.h>
#include <metadyn.h>
#include <ctype.h>
#include <dirent.h>
#include <devid.h>
#include <sys/param.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/generic/inquiry.h>
#include <sys/efi_partition.h>

typedef struct ctlr_cache {
	char			*ctlr_nm;
	int			ctlr_ty;
	struct	ctlr_cache	*ctlr_nx;
} ctlr_cache_t;

static	ctlr_cache_t	*ctlr_cache = NULL;


/*
 * return set for a device
 */
mdsetname_t *
metagetset(
	mdname_t	*np,
	int		bypass_daemon,
	md_error_t	*ep
)
{
	mdsetname_t	*sp;

	/* metadevice */
	if (metaismeta(np))
		return (metasetnosetname(MD_MIN2SET(meta_getminor(np->dev)),
		    ep));

	/* regular device */
	if (meta_is_drive_in_anyset(np->drivenamep, &sp, bypass_daemon,
	    ep) != 0)
		return (NULL);

	if (sp != NULL)
		return (sp);

	return (metasetnosetname(MD_LOCAL_SET, ep));
}

/*
 * convert system to md types
 */
static void
meta_geom_to_md(
	struct dk_geom	*gp,
	mdgeom_t	*mdgp
)
{
	(void) memset(mdgp, '\0', sizeof (*mdgp));
	mdgp->ncyl = gp->dkg_ncyl;
	mdgp->nhead = gp->dkg_nhead;
	mdgp->nsect = gp->dkg_nsect;
	mdgp->rpm = gp->dkg_rpm;
	mdgp->write_reinstruct = gp->dkg_write_reinstruct;
	mdgp->read_reinstruct = gp->dkg_read_reinstruct;
	mdgp->blk_sz = DEV_BSIZE;
}

/*
 * convert efi to md types
 */
static void
meta_efi_to_mdgeom(struct dk_gpt *gpt, mdgeom_t	*mdgp)
{
	(void) memset(mdgp, '\0', sizeof (*mdgp));
	mdgp->ncyl = (gpt->efi_last_u_lba - gpt->efi_first_u_lba) /
	    (MD_EFI_FG_HEADS * MD_EFI_FG_SECTORS);
	mdgp->nhead = MD_EFI_FG_HEADS;
	mdgp->nsect = MD_EFI_FG_SECTORS;
	mdgp->rpm = MD_EFI_FG_RPM;
	mdgp->write_reinstruct = MD_EFI_FG_WRI;
	mdgp->read_reinstruct = MD_EFI_FG_RRI;
	mdgp->blk_sz = DEV_BSIZE;
}

static void
meta_efi_to_mdvtoc(struct dk_gpt *gpt, mdvtoc_t *mdvp)
{
	char		typename[EFI_PART_NAME_LEN];
	uint_t		i;

	(void) memset(mdvp, '\0', sizeof (*mdvp));
	mdvp->nparts = gpt->efi_nparts;
	if (mdvp->nparts > MD_MAX_PARTS)
		return;

	mdvp->first_lba = gpt->efi_first_u_lba;
	mdvp->last_lba = gpt->efi_last_u_lba;
	mdvp->lbasize = gpt->efi_lbasize;

	for (i = 0; (i < gpt->efi_nparts); ++i) {
		mdvp->parts[i].start = gpt->efi_parts[i].p_start;
		mdvp->parts[i].size = gpt->efi_parts[i].p_size;
		mdvp->parts[i].tag = gpt->efi_parts[i].p_tag;
		mdvp->parts[i].flag = gpt->efi_parts[i].p_flag;
		/*
		 * It is possible to present an efi label but be using vtoc
		 * disks to create a > 1 TB metadevice.  In case the first
		 * disk in the underlying metadevice is a vtoc disk and starts
		 * at the beginning of the disk it is necessary to convey this
		 * information to the user.
		 */
		if (mdvp->parts[i].size > 0 &&
		    mdvp->parts[i].start != 0 && mdvp->nparts == 1) {
			mdvp->parts[i].label = btodb(DK_LABEL_SIZE);
			mdvp->parts[i].start = 0;
		}

		/*
		 * Due to the lack of a label for the entire partition table,
		 * we use p_name of the reserved partition
		 */
		if ((gpt->efi_parts[i].p_tag == V_RESERVED) &&
		    (gpt->efi_parts[i].p_name != NULL)) {
			(void) strlcpy(typename, gpt->efi_parts[i].p_name,
			    EFI_PART_NAME_LEN);
			/* Stop at first (if any) space or tab */
			(void) strtok(typename, " \t");
			mdvp->typename = Strdup(typename);
		}
	}
}

static void
meta_mdvtoc_to_efi(mdvtoc_t *mdvp, struct dk_gpt **gpt)
{
	char		typename[EFI_PART_NAME_LEN];
	uint_t		i;
	uint_t		lastpart;
	size_t		size;

	/* first we count how many partitions we have to send */
	for (i = 0; i < MD_MAX_PARTS; i++) {
		if ((mdvp->parts[i].start == 0) &&
		    (mdvp->parts[i].size == 0) &&
		    (mdvp->parts[i].tag != V_RESERVED)) {
			continue;
		}
		/* if we are here, we know the partition is really used */
		lastpart = i;
	}
	size = sizeof (struct dk_gpt) + (sizeof (struct dk_part) * lastpart);
	*gpt = calloc(size, sizeof (char));

	(*gpt)->efi_nparts = lastpart + 1;
	(*gpt)->efi_first_u_lba = mdvp->first_lba;
	(*gpt)->efi_last_u_lba = mdvp->last_lba;
	(*gpt)->efi_lbasize = mdvp->lbasize;
	for (i = 0; (i < (*gpt)->efi_nparts); ++i) {
		(*gpt)->efi_parts[i].p_start = mdvp->parts[i].start;
		(*gpt)->efi_parts[i].p_size = mdvp->parts[i].size;
		(*gpt)->efi_parts[i].p_tag = mdvp->parts[i].tag;
		(*gpt)->efi_parts[i].p_flag = mdvp->parts[i].flag;
		/*
		 * Due to the lack of a label for the entire partition table,
		 * we use p_name of the reserved partition
		 */
		if (((*gpt)->efi_parts[i].p_tag == V_RESERVED) &&
		    (mdvp->typename != NULL)) {
			(void) strlcpy((*gpt)->efi_parts[i].p_name, typename,
			    EFI_PART_NAME_LEN);
		}
	}
}


void
ctlr_cache_add(char *nm, int ty)
{
	ctlr_cache_t	**ccpp;

	for (ccpp = &ctlr_cache; *ccpp != NULL; ccpp = &(*ccpp)->ctlr_nx)
		if (strcmp((*ccpp)->ctlr_nm, nm) == 0)
			return;

	*ccpp = Zalloc(sizeof (ctlr_cache_t));
	(*ccpp)->ctlr_nm = Strdup(nm);
	(*ccpp)->ctlr_ty = ty;
}

int
ctlr_cache_look(char *nm)
{
	ctlr_cache_t	*tcp;

	for (tcp = ctlr_cache; tcp != NULL; tcp = tcp->ctlr_nx)
		if (strcmp(tcp->ctlr_nm, nm) == 0)
			return (tcp->ctlr_ty);

	return (-1);
}


void
metaflushctlrcache(void)
{
	ctlr_cache_t	*cp, *np;

	for (cp = ctlr_cache, np = NULL; cp != NULL; cp = np) {
		np = cp->ctlr_nx;
		Free(cp->ctlr_nm);
		Free(cp);
	}
	ctlr_cache = NULL;
}

/*
 * getdrvnode -- return the driver name based on mdname_t->bname
 *	Need to free pointer when finished.
 */
char *
getdrvnode(mdname_t *np, md_error_t *ep)
{
	char	*devicespath,
	    *drvnode,
	    *cp;

	if ((devicespath = metagetdevicesname(np, ep)) == NULL)
		return (NULL);

	/*
	 * At this point devicespath should be like the following
	 * "/devices/<unknow_and_dont_care>/xxxx@vvvv"
	 *
	 * There's a couple of 'if' statements below which could
	 * return an error condition, but I've decide to allow
	 * a more open approach regarding the mapping so as to
	 * not restrict possible future projects.
	 */
	if (drvnode = strrchr(devicespath, '/'))
		/*
		 * drvnode now just "xxxx@vvvv"
		 */
		drvnode++;

	if (cp = strrchr(drvnode, '@'))
		/*
		 * Now drvnode is just the driver name "xxxx"
		 */
		*cp = '\0';

	cp = Strdup(drvnode);
	Free(devicespath);
	np->devicesname = NULL;

	return (cp);
}

/*
 * meta_load_dl -- open dynamic library using LDLIBRARYPATH, a debug
 *    environment variable METALDPATH, or the default location.
 */
static void *
meta_load_dl(mdname_t *np, md_error_t *ep)
{
	char	*drvnode,
	    newpath[MAXPATHLEN],
	    *p;
	void	*cookie;

	if ((drvnode = getdrvnode(np, ep)) != NULL) {

		/*
		 * Library seach algorithm:
		 * 1) Use LDLIBRARYPATH which is implied when a non-absolute
		 *    path name is passed to dlopen()
		 * 2) Use the value of METALDPATH as the directory. Mainly
		 *    used for debugging
		 * 3) Last search the default location of "/usr/lib"
		 */
		(void) snprintf(newpath, sizeof (newpath), "lib%s.so.1",
		    drvnode);
		if ((cookie = dlopen(newpath, RTLD_LAZY)) == NULL) {
			if ((p = getenv("METALDPATH")) == NULL)
				p = METALDPATH_DEFAULT;
			(void) snprintf(newpath, sizeof (newpath),
			    "%s/lib%s.so.1", p, drvnode);
			Free(drvnode);
			if ((cookie = dlopen(newpath, RTLD_LAZY)) != NULL) {
				/*
				 * Common failure here would be failing to
				 * find a libXX.so.1 such as libsd.so.1
				 * Some controllers will not have a library
				 * because there's no enclosure or name
				 * translation required.
				 */
				return (cookie);
			}
		} else {
			Free(drvnode);
			return (cookie);
		}
	}
	return (NULL);
}

/*
 * meta_match_names -- possibly convert the driver names returned by CINFO
 */
static void
meta_match_names(mdname_t *np, struct dk_cinfo *cp, mdcinfo_t *mdcp,
    md_error_t *ep)
{
	void		*cookie;
	meta_convert_e	((*fptr)(mdname_t *, struct dk_cinfo *, mdcinfo_t *,
	    md_error_t *));

	if ((cookie = meta_load_dl(np, ep)) != NULL) {
		fptr = (meta_convert_e (*)(mdname_t *, struct dk_cinfo *,
		    mdcinfo_t *, md_error_t *))dlsym(cookie, "convert_path");
		if (fptr != NULL)
			(void) (*fptr)(np, cp, mdcp, ep);
		(void) dlclose(cookie);
	}
}

/*
 * meta_match_enclosure -- return any enclosure info if found
 */
int
meta_match_enclosure(mdname_t *np, mdcinfo_t *mdcp, md_error_t *ep)
{
	meta_enclosure_e	e,
	    ((*fptr)(mdname_t *, mdcinfo_t *,
	    md_error_t *));
	void			*cookie;

	if ((cookie = meta_load_dl(np, ep)) != NULL) {
		fptr = (meta_enclosure_e (*)(mdname_t *, mdcinfo_t *,
		    md_error_t *))dlsym(cookie, "get_enclosure");
		if (fptr != NULL) {
			e = (*fptr)(np, mdcp, ep);
			switch (e) {
			case Enclosure_Error:
				/*
				 * Looks like this library wanted to handle
				 * our device and had an internal error.
				 */
				return (1);

			case Enclosure_Okay:
				/*
				 * Found a library to handle the request so
				 * just return with data provided.
				 */
				return (0);

			case Enclosure_Noop:
				/*
				 * Need to continue the search
				 */
				break;
			}
		}
		(void) dlclose(cookie);
	}
	return (0);
}

static int
meta_cinfo_to_md(mdname_t *np, struct dk_cinfo *cp, mdcinfo_t *mdcp,
    md_error_t *ep)
{
	/* default */
	(void) memset(mdcp, '\0', sizeof (*mdcp));
	(void) strncpy(mdcp->cname, cp->dki_cname,
	    min((sizeof (mdcp->cname) - 1), sizeof (cp->dki_cname)));
	mdcp->ctype = MHD_CTLR_GENERIC;
	mdcp->cnum = cp->dki_cnum;
	(void) strncpy(mdcp->dname, cp->dki_dname,
	    min((sizeof (mdcp->dname) - 1), sizeof (cp->dki_dname)));
	mdcp->unit = cp->dki_unit;
	mdcp->maxtransfer = cp->dki_maxtransfer;

	/*
	 * See if the driver name returned from DKIOCINFO
	 * is valid or not. In somecases, such as the ap_dmd
	 * driver, we need to modify the name that's return
	 * for everything to work.
	 */
	meta_match_names(np, cp, mdcp, ep);

	if (meta_match_enclosure(np, mdcp, ep))
		return (-1);

	/* return success */
	return (0);
}

static void
meta_vtoc_to_md(
	struct vtoc	*vp,
	mdvtoc_t	*mdvp
)
{
	char		typename[sizeof (vp->v_asciilabel) + 1];
	uint_t		i;

	(void) memset(mdvp, '\0', sizeof (*mdvp));
	(void) strncpy(typename, vp->v_asciilabel,
	    sizeof (vp->v_asciilabel));
	typename[sizeof (typename) - 1] = '\0';
	for (i = 0; ((i < sizeof (typename)) && (typename[i] != '\0')); ++i) {
		if ((typename[i] == ' ') || (typename[i] == '\t')) {
			typename[i] = '\0';
			break;
		}
	}
	mdvp->typename = Strdup(typename);
	mdvp->nparts = vp->v_nparts;
	for (i = 0; (i < vp->v_nparts); ++i) {
		mdvp->parts[i].start = vp->v_part[i].p_start;
		mdvp->parts[i].size = vp->v_part[i].p_size;
		mdvp->parts[i].tag = vp->v_part[i].p_tag;
		mdvp->parts[i].flag = vp->v_part[i].p_flag;
		if (vp->v_part[i].p_start == 0 && vp->v_part[i].p_size > 0)
			mdvp->parts[i].label = btodb(DK_LABEL_SIZE);
	}
}

/*
 * free allocations in vtoc
 */
void
metafreevtoc(
	mdvtoc_t	*vtocp
)
{
	if (vtocp->typename != NULL)
		Free(vtocp->typename);
	(void) memset(vtocp, 0, sizeof (*vtocp));
}

/*
 * return md types
 */
mdvtoc_t *
metagetvtoc(
	mdname_t	*np,	/* only rname, drivenamep, are setup */
	int		nocache,
	uint_t		*partnop,
	md_error_t	*ep
)
{
	mddrivename_t	*dnp = np->drivenamep;
	struct dk_geom	geom;
	char		*minor_name = NULL;
	char		*rname = np->rname;
	int		fd;
	int		partno;
	int		err = 0;	    /* saves errno from ioctl */
	ddi_devid_t	devid;
	char		*p;

	/* short circuit */
	if ((! nocache) && (dnp->vtoc.nparts != 0)) {
		if (partnop != NULL) {
			/*
			 * the following assigment works because the
			 * mdname_t structs are always created as part
			 * of the drivenamep struct.  When a user
			 * creates an mdname_t struct it either
			 * uses an existing drivenamep struct or creates
			 * a new one and then adds the mdname_t struct
			 * as part of its parts_val array.  So what is
			 * being computed below is the slice offset in
			 * the parts_val array.
			 */
			*partnop = np - np->drivenamep->parts.parts_val;
			assert(*partnop < dnp->parts.parts_len);
		}
		return (&dnp->vtoc);
	}

	/* can't get vtoc */
	if (! nocache) {
		switch (dnp->type) {
		case MDT_ACCES:
		case MDT_UNKNOWN:
			(void) mdsyserror(ep, dnp->errnum, rname);
			return (NULL);
		}
	}

	/* get all the info */
	if ((fd = open(rname, (O_RDONLY|O_NDELAY), 0)) < 0) {
		(void) mdsyserror(ep, errno, rname);
		return (NULL);
	}

	/*
	 * The disk is open so this is a good point to get the devid
	 * otherwise it will need to be done at another time which
	 * means reopening it.
	 */
	if (devid_get(fd, &devid) != 0) {
		/* there is no devid for the disk */
		if (((p = getenv("MD_DEBUG")) != NULL) &&
		    (strstr(p, "DEVID") != NULL)) {
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "%s has no device id\n"), np->rname);
		}
		np->minor_name = (char *)NULL;
		dnp->devid = NULL;
	} else {
		(void) devid_get_minor_name(fd, &minor_name);
		/*
		 * The minor name could be NULL if the underlying
		 * device driver does not support 'minor names'.
		 * This means we do not use devid's for this device.
		 * SunCluster did driver does not support minor names.
		 */
		if (minor_name != NULL) {
			np->minor_name = Strdup(minor_name);
			devid_str_free(minor_name);
			dnp->devid = devid_str_encode(devid, NULL);
		} else {
			np->minor_name = (char *)NULL;
			dnp->devid = NULL;

			if (((p = getenv("MD_DEBUG")) != NULL) &&
			    (strstr(p, "DEVID") != NULL)) {
				(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
				    "%s no minor name (no devid)\n"),
				    np->rname);
			}
		}
		devid_free(devid);
	}

	/*
	 * if our drivenamep points to a device not supporting DKIOCGGEOM,
	 * it's likely to have an EFI label.
	 */
	(void) memset(&geom, 0, sizeof (geom));
	if (ioctl(fd, DKIOCGGEOM, &geom) != 0) {
		err = errno;
		if (err == ENOTTY) {
			(void) mddeverror(ep, MDE_NOT_DISK, NODEV, rname);
			(void) close(fd);
			return (NULL);
		} else if (err != ENOTSUP) {
			(void) mdsyserror(ep, err, rname);
			(void) close(fd);
			return (NULL);
		}

	}
	/*
	 * If we are here, there was either no failure on DKIOCGGEOM or
	 * the failure was ENOTSUP
	 */
	if (err == ENOTSUP) {
		/* DKIOCGGEOM yielded ENOTSUP => try efi_alloc_and_read */
		struct dk_gpt	*gpt;
		int		save_errno;

		/* this also sets errno */
		partno = efi_alloc_and_read(fd, &gpt);
		save_errno = errno;
		(void) close(fd);
		if (partno < 0) {
			efi_free(gpt);
			(void) mdsyserror(ep, save_errno, rname);
			return (NULL);
		}
		if (partno >= gpt->efi_nparts) {
			efi_free(gpt);
			(void) mddeverror(ep, MDE_INVALID_PART, NODEV64,
			    rname);
			return (NULL);
		}

		/* convert to our format */
		metafreevtoc(&dnp->vtoc);
		meta_efi_to_mdvtoc(gpt, &dnp->vtoc);
		if (dnp->vtoc.nparts > MD_MAX_PARTS) {
			(void) mddeverror(ep, MDE_TOO_MANY_PARTS, NODEV64,
			    rname);
			return (NULL);
		}
		/*
		 * libmeta needs at least V_NUMPAR partitions.
		 * If we have an EFI partition with less than V_NUMPAR slices,
		 * we nevertheless reserve space for V_NUMPAR
		 */

		if (dnp->vtoc.nparts < V_NUMPAR) {
			dnp->vtoc.nparts = V_NUMPAR;
		}
		meta_efi_to_mdgeom(gpt, &dnp->geom);
		efi_free(gpt);
	} else {
		/* no error on DKIOCGGEOM, try meta_getvtoc */
		struct vtoc	vtoc;

		if (meta_getvtoc(fd, np->cname, &vtoc, &partno, ep) < 0) {
			(void) close(fd);
			return (NULL);
		}
		(void) close(fd);

		/* convert to our format */
		meta_geom_to_md(&geom, &dnp->geom);
		metafreevtoc(&dnp->vtoc);
		meta_vtoc_to_md(&vtoc, &dnp->vtoc);
	}

	/* fix up any drives which are now accessible */
	if ((nocache) && (dnp->type == MDT_ACCES) &&
	    (dnp->vtoc.nparts == dnp->parts.parts_len)) {
		dnp->type = MDT_COMP;
		dnp->errnum = 0;
	}

	/* save partno */
	assert(partno < dnp->vtoc.nparts);
	if (partnop != NULL)
		*partnop = partno;

	/* return info */
	return (&dnp->vtoc);
}

static void
meta_mdvtoc_to_vtoc(
	mdvtoc_t	*mdvp,
	struct vtoc	*vp
)
{
	uint_t		i;

	(void) memset(&vp->v_part, '\0', sizeof (vp->v_part));
	vp->v_nparts = (ushort_t)mdvp->nparts;
	for (i = 0; (i < mdvp->nparts); ++i) {
		vp->v_part[i].p_start = (daddr32_t)mdvp->parts[i].start;
		vp->v_part[i].p_size  = (daddr32_t)mdvp->parts[i].size;
		vp->v_part[i].p_tag   = mdvp->parts[i].tag;
		vp->v_part[i].p_flag  = mdvp->parts[i].flag;
	}
}

/*
 * Set the vtoc, but use the cached copy to get the info from.
 * We write np->drivenamep->vtoc to disk.
 * Before we can do this we read the vtoc in.
 * if we're dealing with a metadevice and this metadevice is a 64 bit device
 *	we can use meta_getmdvtoc/meta_setmdvtoc
 * else
 * 	we use meta_getvtoc/meta_setvtoc but than we first have to convert
 *	dnp->vtoc (actually being a mdvtoc_t) into a vtoc_t
 */
int
metasetvtoc(
	mdname_t	*np,
	md_error_t	*ep
)
{
	char		*rname = np->rname;
	mddrivename_t	*dnp = np->drivenamep;
	int		fd;
	int		err;
	int 		save_errno;
	struct dk_geom	geom;

	if ((fd = open(rname, (O_RDONLY | O_NDELAY), 0)) < 0)
		return (mdsyserror(ep, errno, rname));

	err = ioctl(fd, DKIOCGGEOM, &geom);
	save_errno = errno;
	if (err == 0) {
		struct vtoc	vtoc;

		if (meta_getvtoc(fd, np->cname, &vtoc, NULL, ep) < 0) {
			(void) close(fd);
			return (-1);
		}

		meta_mdvtoc_to_vtoc(&dnp->vtoc, &vtoc);

		if (meta_setvtoc(fd, np->cname, &vtoc, ep) < 0) {
			(void) close(fd);
			return (-1);
		}
	} else if (save_errno == ENOTSUP) {
		struct dk_gpt	*gpt;
		int		ret;

		/* allocation of gpt is done in meta_mdvtoc_to_efi */
		meta_mdvtoc_to_efi(&dnp->vtoc, &gpt);

		ret = efi_write(fd, gpt);
		save_errno = errno;
		free(gpt);
		if (ret != 0) {
			(void) close(fd);
			return (mdsyserror(ep, save_errno, rname));
		} else {
			(void) close(fd);
			return (0);
		}

	} else {
		(void) close(fd);
		return (mdsyserror(ep, save_errno, rname));
	}

	(void) close(fd);

	return (0);
}

mdgeom_t *
metagetgeom(
	mdname_t	*np,	/* only rname, drivenamep, are setup */
	md_error_t	*ep
)
{
	if (metagetvtoc(np, FALSE, NULL, ep) == NULL)
		return (NULL);
	return (&np->drivenamep->geom);
}

mdcinfo_t *
metagetcinfo(
	mdname_t	*np,	/* only rname, drivenamep, are setup */
	md_error_t	*ep
)
{
	char			*rname = np->rname;
	mddrivename_t		*dnp = np->drivenamep;
	int			fd;
	struct dk_cinfo		cinfo;

	/* short circuit */
	if (dnp->cinfo.cname[0] != '\0')
		return (&dnp->cinfo);

	/* get controller info */
	if ((fd = open(rname, (O_RDONLY|O_NDELAY), 0)) < 0) {
		(void) mdsyserror(ep, errno, rname);
		return (NULL);
	}
	if (ioctl(fd, DKIOCINFO, &cinfo) != 0) {
		int	save = errno;

		(void) close(fd);
		if (save == ENOTTY) {
			(void) mddeverror(ep, MDE_NOT_DISK, NODEV64, rname);
		} else {
			(void) mdsyserror(ep, save, rname);
		}
		return (NULL);
	}
	(void) close(fd);	/* sd/ssd bug */

	/* convert to our format */
	if (meta_cinfo_to_md(np, &cinfo, &dnp->cinfo, ep) != 0)
		return (NULL);

	/* return info */
	return (&dnp->cinfo);
}

/*
 * get partition number
 */
int
metagetpartno(
	mdname_t	*np,
	md_error_t	*ep
)
{
	mdvtoc_t	*vtocp;
	uint_t		partno;

	if ((vtocp = metagetvtoc(np, FALSE, &partno, ep)) == NULL)
		return (-1);
	assert(partno < vtocp->nparts);
	return (partno);
}

/*
 * get size of device
 */
diskaddr_t
metagetsize(
	mdname_t	*np,
	md_error_t	*ep
)
{
	mdvtoc_t	*vtocp;
	uint_t		partno;

	if ((vtocp = metagetvtoc(np, FALSE, &partno, ep)) == NULL)
		return (MD_DISKADDR_ERROR);
	assert(partno < vtocp->nparts);
	return (vtocp->parts[partno].size);
}

/*
 * get label of device
 */
diskaddr_t
metagetlabel(
	mdname_t	*np,
	md_error_t	*ep
)
{
	mdvtoc_t	*vtocp;
	uint_t		partno;

	if ((vtocp = metagetvtoc(np, FALSE, &partno, ep)) == NULL)
		return (MD_DISKADDR_ERROR);
	assert(partno < vtocp->nparts);
	return (vtocp->parts[partno].label);
}

/*
 * find out where database replicas end
 */
static int
mddb_getendblk(
	mdsetname_t		*sp,
	mdname_t		*np,
	diskaddr_t		*endblkp,
	md_error_t		*ep
)
{
	md_replicalist_t	*rlp = NULL;
	md_replicalist_t	*rl;

	/* make sure we have a component */
	*endblkp = 0;
	if (metaismeta(np))
		return (0);

	/* get replicas, quit if none */
	if (metareplicalist(sp, MD_BASICNAME_OK | PRINT_FAST, &rlp, ep) < 0) {
		if (! mdismddberror(ep, MDE_DB_NODB))
			return (-1);
		mdclrerror(ep);
		return (0);
	} else if (rlp == NULL)
		return (0);

	/* go through all the replicas */
	for (rl = rlp; (rl != NULL); rl = rl->rl_next) {
		md_replica_t	*rp = rl->rl_repp;
		mdname_t	*repnamep = rp->r_namep;
		diskaddr_t	dbend;

		if (np->dev != repnamep->dev)
			continue;
		dbend = rp->r_blkno + rp->r_nblk - 1;
		if (dbend > *endblkp)
			*endblkp = dbend;
	}

	/* cleanup, return success */
	metafreereplicalist(rlp);
	return (0);
}

/*
 * return cached start block
 */
static diskaddr_t
metagetend(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_error_t	*ep
)
{
	diskaddr_t	end_blk = MD_DISKADDR_ERROR;

	/* short circuit */
	if (np->end_blk != MD_DISKADDR_ERROR)
		return (np->end_blk);

	/* look for database locations */
	if (mddb_getendblk(sp, np, &end_blk, ep) != 0)
		return (MD_DISKADDR_ERROR);

	/* success */
	np->end_blk = end_blk;
	return (end_blk);
}

/*
 * does device have a metadb
 */
int
metahasmddb(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_error_t	*ep
)
{
	if (metagetend(sp, np, ep) == MD_DISKADDR_ERROR)
		return (-1);
	else if (np->end_blk > 0)
		return (1);
	else
		return (0);
}

/*
 * return cached start block
 */
diskaddr_t
metagetstart(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_error_t	*ep
)
{
	diskaddr_t	start_blk = MD_DISKADDR_ERROR;

	/* short circuit */
	if (np->start_blk != MD_DISKADDR_ERROR)
		return (np->start_blk);

	/* look for database locations */
	if ((start_blk = metagetend(sp, np, ep)) == MD_DISKADDR_ERROR)
		return (MD_DISKADDR_ERROR);

	/* check for label */
	if (start_blk == 0) {
		start_blk = metagetlabel(np, ep);
		if (start_blk == MD_DISKADDR_ERROR) {
			return (MD_DISKADDR_ERROR);
		}
	}

	/* roundup to next cylinder */
	if (start_blk != 0) {
		mdgeom_t	*geomp;

		if ((geomp = metagetgeom(np, ep)) == NULL)
			return (MD_DISKADDR_ERROR);
		start_blk = roundup(start_blk, (geomp->nhead * geomp->nsect));
	}

	/* success */
	np->start_blk = start_blk;
	return (start_blk);
}

/*
 * return cached devices name
 */
char *
metagetdevicesname(
	mdname_t	*np,
	md_error_t	*ep
)
{
	char		path[MAXPATHLEN + 1];
	int		len;

	/* short circuit */
	if (np->devicesname != NULL)
		return (np->devicesname);

	/* follow symlink */
	if ((len = readlink(np->bname, path, (sizeof (path) - 1))) < 0) {
		(void) mdsyserror(ep, errno, np->bname);
		return (NULL);
	} else if (len >= sizeof (path)) {
		(void) mdsyserror(ep, ENAMETOOLONG, np->bname);
		return (NULL);
	}
	path[len] = '\0';
	if ((len = strfind(path, "/devices/")) < 0) {
		(void) mddeverror(ep, MDE_DEVICES_NAME, np->dev, np->bname);
		return (NULL);
	}

	/* return name */
	np->devicesname = Strdup(path + len + strlen("/devices"));
	return (np->devicesname);
}

/*
 * get metadevice misc name
 */
char *
metagetmiscname(
	mdname_t		*np,
	md_error_t		*ep
)
{
	mddrivename_t		*dnp = np->drivenamep;
	md_i_driverinfo_t	mid;

	/* short circuit */
	if (dnp->miscname != NULL)
		return (dnp->miscname);
	if (metachkmeta(np, ep) != 0)
		return (NULL);

	/* get misc module from driver */
	(void) memset(&mid, 0, sizeof (mid));
	mid.mnum = meta_getminor(np->dev);
	if (metaioctl(MD_IOCGET_DRVNM, &mid, &mid.mde, np->cname) != 0) {
		(void) mdstealerror(ep, &mid.mde);
		return (NULL);
	}

	/* return miscname */
	dnp->miscname = Strdup(MD_PNTDRIVERNAME(&mid));
	return (dnp->miscname);
}

/*
 * get unit structure from driver
 */
md_unit_t *
meta_get_mdunit(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_error_t	*ep
)
{
	md_i_get_t	mig;
	char		*miscname = NULL;

	/* should have a set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(np->dev)));

	/* get size of unit structure */
	if (metachkmeta(np, ep) != 0)
		return (NULL);
	if ((miscname = metagetmiscname(np, ep)) == NULL)
		return (NULL);
	(void) memset(&mig, '\0', sizeof (mig));
	MD_SETDRIVERNAME(&mig, miscname, sp->setno);
	mig.id = meta_getminor(np->dev);
	if (metaioctl(MD_IOCGET, &mig, &mig.mde, np->cname) != 0) {
		(void) mdstealerror(ep, &mig.mde);
		return (NULL);
	}

	/* get actual unit structure */
	assert(mig.size > 0);
	mig.mdp = (uintptr_t)Zalloc(mig.size);
	if (metaioctl(MD_IOCGET, &mig, &mig.mde, np->cname) != 0) {
		(void) mdstealerror(ep, &mig.mde);
		Free((void *)(uintptr_t)mig.mdp);
		return (NULL);
	}

	return ((md_unit_t *)(uintptr_t)mig.mdp);
}

/*
 * free metadevice unit
 */
void
meta_free_unit(
	mddrivename_t	*dnp
)
{
	if (dnp->unitp != NULL) {
		switch (dnp->unitp->type) {
		case MD_DEVICE:
			meta_free_stripe((md_stripe_t *)dnp->unitp);
			break;
		case MD_METAMIRROR:
			meta_free_mirror((md_mirror_t *)dnp->unitp);
			break;
		case MD_METATRANS:
			meta_free_trans((md_trans_t *)dnp->unitp);
			break;
		case MD_METARAID:
			meta_free_raid((md_raid_t *)dnp->unitp);
			break;
		case MD_METASP:
			meta_free_sp((md_sp_t *)dnp->unitp);
			break;
		default:
			assert(0);
			break;
		}
		dnp->unitp = NULL;
	}
}

/*
 * free metadevice name info
 */
void
meta_invalidate_name(
	mdname_t	*namep
)
{
	mddrivename_t	*dnp = namep->drivenamep;

	/* get rid of cached name info */
	if (namep->devicesname != NULL) {
		Free(namep->devicesname);
		namep->devicesname = NULL;
	}
	namep->key = MD_KEYBAD;
	namep->start_blk = -1;
	namep->end_blk = -1;

	/* get rid of cached drivename info */
	(void) memset(&dnp->geom, 0, sizeof (dnp->geom));
	(void) memset(&dnp->cinfo, 0, sizeof (dnp->cinfo));
	metafreevtoc(&dnp->vtoc);
	metaflushsidenames(dnp);
	dnp->side_names_key = MD_KEYBAD;
	if (dnp->miscname != NULL) {
		Free(dnp->miscname);
		dnp->miscname = NULL;
	}
	meta_free_unit(dnp);
}

/*
 * get metadevice unit
 */
md_common_t *
meta_get_unit(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_error_t	*ep
)
{
	char		*miscname;

	/* short circuit */
	if (np->drivenamep->unitp != NULL)
		return (np->drivenamep->unitp);
	if (metachkmeta(np, ep) != 0)
		return (NULL);

	/* dispatch */
	if ((miscname = metagetmiscname(np, ep)) == NULL)
		return (NULL);
	else if (strcmp(miscname, MD_STRIPE) == 0)
		return ((md_common_t *)meta_get_stripe(sp, np, ep));
	else if (strcmp(miscname, MD_MIRROR) == 0)
		return ((md_common_t *)meta_get_mirror(sp, np, ep));
	else if (strcmp(miscname, MD_TRANS) == 0)
		return ((md_common_t *)meta_get_trans(sp, np, ep));
	else if (strcmp(miscname, MD_RAID) == 0)
		return ((md_common_t *)meta_get_raid(sp, np, ep));
	else if (strcmp(miscname, MD_SP) == 0)
		return ((md_common_t *)meta_get_sp(sp, np, ep));
	else {
		(void) mdmderror(ep, MDE_UNKNOWN_TYPE, meta_getminor(np->dev),
		    np->cname);
		return (NULL);
	}
}


int
meta_isopen(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_error_t	*ep,
	mdcmdopts_t	options
)
{
	md_isopen_t	d;

	if (metachkmeta(np, ep) != 0)
		return (-1);

	(void) memset(&d, '\0', sizeof (d));
	d.dev = np->dev;
	if (metaioctl(MD_IOCISOPEN, &d, &d.mde, np->cname) != 0)
		return (mdstealerror(ep, &d.mde));

	/*
	 * shortcut: if the device is open, no need to check on other nodes,
	 * even in case of a mn metadevice
	 * Also return in case we're told not to check on other nodes.
	 */
	if ((d.isopen != 0) || ((options & MDCMD_MN_OPEN_CHECK) == 0)) {
		return (d.isopen);
	}

	/*
	 * If the device is closed locally, but it's a mn device,
	 * check on all other nodes, too
	 */
	if (sp->setno != MD_LOCAL_SET) {
		(void) metaget_setdesc(sp, ep); /* not supposed to fail */
		if (sp->setdesc->sd_flags & MD_SR_MN) {
			int		err = 0;
			md_mn_result_t *resp;
			/*
			 * This message is never directly issued.
			 * So we launch it with a suspend override flag.
			 * If the commd is suspended, and this message comes
			 * along it must be sent due to replaying a metainit or
			 * similar. In that case we don't want this message to
			 * be blocked.
			 * If the commd is not suspended, the flag does no harm.
			 * Additionally we don't want the result of the message
			 * cached in the MCT, because we want uptodate results,
			 * and the message doesn't need being logged either.
			 * Hence NO_LOG and NO_MCT
			 */
			err = mdmn_send_message(
			    sp->setno,
			    MD_MN_MSG_CLU_CHECK,
			    MD_MSGF_NO_MCT | MD_MSGF_STOP_ON_ERROR |
			    MD_MSGF_NO_LOG | MD_MSGF_OVERRIDE_SUSPEND,
			    (char *)&d, sizeof (md_isopen_t),
			    &resp, ep);
			if (err == 0) {
				d.isopen = resp->mmr_exitval;
			} else {
				/*
				 * in case some error occurred,
				 * we better say the device is open
				 */
				d.isopen = 1;
			}
			if (resp != (md_mn_result_t *)NULL) {
				free_result(resp);
			}

		}
	}

	return (d.isopen);
}
