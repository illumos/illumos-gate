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
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * Metadevice database interfaces.
 */

#define	MDDB

#include <meta.h>
#include <sys/lvm/md_mddb.h>
#include <sys/lvm/md_crc.h>
#include <sys/lvm/mdio.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

struct svm_daemon {
	char *svmd_name;
	char *svmd_kill_val;
};

/*
 * This is a list of the daemons that are not stopped by the SVM smf(5)
 * services. The mdmonitord is started via svc:/system/mdmonitor:default
 * but no contract(4) is constructed and so it is not stopped by smf(5).
 */
struct svm_daemon svmd_kill_list[] = {
		{"mdmonitord", "HUP"},
		{"mddoors", "KILL"},
	};

#define	DAEMON_COUNT (sizeof (svmd_kill_list)/ sizeof (struct svm_daemon))

extern int procsigs(int block, sigset_t *oldsigs, md_error_t *ep);

/*
 * Are the locator blocks for the replicas using devids
 */
static int	devid_in_use = FALSE;

static char *
getlongname(
	struct mddb_config	*c,
	md_error_t		*ep
)
{
	char		*diskname = NULL;
	char		*devid_str;
	devid_nmlist_t	*disklist = NULL;

	c->c_locator.l_devid_flags = MDDB_DEVID_GETSZ;
	if (metaioctl(MD_DB_ENDDEV, c, &c->c_mde, NULL) != 0) {
		(void) mdstealerror(ep, &c->c_mde);
		return (NULL);
	}

	if (c->c_locator.l_devid_flags & MDDB_DEVID_SZ) {
		c->c_locator.l_devid = (uintptr_t)
		    Malloc(c->c_locator.l_devid_sz);
		c->c_locator.l_devid_flags =
		    MDDB_DEVID_SPACE | MDDB_DEVID_SZ;
	} else {
		(void) mderror(ep, MDE_NODEVID, "");
		goto out;
	}

	if (metaioctl(MD_DB_ENDDEV, c, &c->c_mde, NULL) != 0) {
		(void) mdstealerror(ep, &c->c_mde);
		goto out;
	}

	if (c->c_locator.l_devid_flags & MDDB_DEVID_NOSPACE) {
		(void) mderror(ep, MDE_NODEVID, "");
		goto out;
	}

	if (metaioctl(MD_DB_GETDEV, c, &c->c_mde, NULL) != 0) {
		(void) mdstealerror(ep, &c->c_mde);
		goto out;
	}

	if (c->c_locator.l_devid != NULL) {
		if (meta_deviceid_to_nmlist("/dev/dsk",
		    (ddi_devid_t)(uintptr_t)c->c_locator.l_devid,
		    c->c_locator.l_minor_name, &disklist) != 0) {
			devid_str = devid_str_encode(
			    (ddi_devid_t)(uintptr_t)c->c_locator.l_devid, NULL);
			(void) mderror(ep, MDE_MISSING_DEVID_DISK, "");
			mderrorextra(ep, devid_str);
			if (devid_str != NULL)
				devid_str_free(devid_str);
			goto out;
		}
		diskname = Strdup(disklist[0].devname);
	}

out:
	if (disklist != NULL)
		devid_free_nmlist(disklist);

	if (c->c_locator.l_devid != NULL)
		Free((void *)(uintptr_t)c->c_locator.l_devid);

	return (diskname);
}

/*
 * meta_get_lb_inittime sends a request for the lb_inittime to the kernel
 */
md_timeval32_t
meta_get_lb_inittime(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	mddb_config_t	c;

	(void) memset(&c, 0, sizeof (c));

	/* Fill in setno, setname, and sideno */
	c.c_setno = sp->setno;

	if (metaioctl(MD_DB_LBINITTIME, &c, &c.c_mde, NULL) != 0) {
		(void) mdstealerror(ep, &c.c_mde);
	}

	return (c.c_timestamp);
}

/*
 * mkmasterblks writes out the master blocks of the mddb to the replica.
 *
 * In a MN diskset, this is called by the node that is adding this replica
 * to the diskset.
 */

#define	MDDB_VERIFY_SIZE	8192

static int
mkmasterblks(
	mdsetname_t	*sp,
	mdname_t	*np,
	int		fd,
	daddr_t		firstblk,
	int		dbsize,
	md_timeval32_t	inittime,
	md_error_t	*ep
)
{
	int		consecutive;
	md_timeval32_t	tp;
	struct mddb_mb	*mb;
	char		*buffer;
	int		iosize;
	md_set_desc	*sd;
	int		mn_set = 0;
	daddr_t		startblk;
	int		cnt;
	ddi_devid_t	devid;

	if (! metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);

		if (MD_MNSET_DESC(sd)) {
			mn_set = 1;		/* Used later */
		}
	}

	/*
	 * Loop to verify the entire mddb region on disk is read/writable.
	 * buffer is used to write/read in at most MDDB_VERIFY_SIZE block
	 * chunks.
	 *
	 * A side-effect of this loop is to zero out the entire mddb region
	 */
	if ((buffer = Zalloc(MDDB_VERIFY_SIZE * DEV_BSIZE)) == NULL)
		return (mdsyserror(ep, ENOMEM, np->rname));

	startblk = firstblk;
	for (cnt = dbsize; cnt > 0; cnt -= consecutive) {

		if (cnt > MDDB_VERIFY_SIZE)
			consecutive = MDDB_VERIFY_SIZE;
		else
			consecutive = cnt;

		if (lseek(fd, (off_t)(startblk * DEV_BSIZE), SEEK_SET) < 0) {
			Free(buffer);
			return (mdsyserror(ep, errno, np->rname));
		}

		iosize = DEV_BSIZE * consecutive;
		if (write(fd, buffer, iosize) != iosize) {
			Free(buffer);
			return (mdsyserror(ep, errno, np->rname));
		}

		if (lseek(fd, (off_t)(startblk * DEV_BSIZE), SEEK_SET) < 0) {
			Free(buffer);
			return (mdsyserror(ep, errno, np->rname));
		}

		if (read(fd, buffer, iosize) != iosize) {
			Free(buffer);
			return (mdsyserror(ep, errno, np->rname));
		}

		startblk += consecutive;
	}

	Free(buffer);
	if ((mb = Zalloc(DEV_BSIZE)) == NULL)
		return (mdsyserror(ep, ENOMEM, np->rname));

	if (meta_gettimeofday(&tp) == -1) {
		Free(mb);
		return (mdsyserror(ep, errno, np->rname));
	}

	mb->mb_magic = MDDB_MAGIC_MB;
	/*
	 * If a MN diskset, set master block revision for a MN set.
	 * Even though the master block structure is no different
	 * for a MN set, setting the revision field to a different
	 * number keeps any pre-MN_diskset code from accessing
	 * this diskset.  It also allows for an early determination
	 * of a MN diskset when reading in from disk so that the
	 * proper size locator block and locator names structure
	 * can be read in thus saving time on diskset startup.
	 */
	if (mn_set)
		mb->mb_revision = MDDB_REV_MNMB;
	else
		mb->mb_revision = MDDB_REV_MB;
	mb->mb_timestamp = tp;
	mb->mb_setno = sp->setno;
	mb->mb_blkcnt = dbsize - 1;
	mb->mb_blkno = firstblk;
	mb->mb_nextblk = 0;

	mb->mb_blkmap.m_firstblk = firstblk + 1;
	mb->mb_blkmap.m_consecutive = dbsize - 1;
	if (! metaislocalset(sp)) {
		mb->mb_setcreatetime = inittime;
	}

	/*
	 * We try to save the disks device ID into the remaining bytes in
	 * the master block. The saved devid is used to provide a mapping
	 * between this disk's devid and the devid stored into the master
	 * block. This allows the disk image to be self-identifying
	 * if it gets copied (e.g. SNDR, True Copy, etc.).  This is used
	 * when we try to import these disks on the remote copied image.
	 * If we cannot save the disks device ID onto the master block that is
	 * ok.  The disk is just not self-identifying and won't be importable
	 * in the remote copy scenario.
	 */
	if (devid_get(fd, &devid) == 0) {
		size_t len;

		len = devid_sizeof(devid);
		if (len <= DEV_BSIZE - sizeof (*mb)) {
			/* there is enough space to store the devid */
			mb->mb_devid_magic = MDDB_MAGIC_DE;
			mb->mb_devid_len = len;
			(void) memcpy(mb->mb_devid, devid, len);
		}
		devid_free(devid);
	}

	crcgen((uchar_t *)mb, (uint_t *)&mb->mb_checksum, (uint_t)DEV_BSIZE,
	    (crc_skip_t *)NULL);

	if (lseek(fd, (off_t)(firstblk * DEV_BSIZE), SEEK_SET) < 0) {
		Free(mb);
		return (mdsyserror(ep, errno, np->rname));
	}

	if (write(fd, mb, DEV_BSIZE) != DEV_BSIZE) {
		Free(mb);
		return (mdsyserror(ep, errno, np->rname));
	}

	if (lseek(fd, (off_t)(firstblk * DEV_BSIZE), SEEK_SET) < 0) {
		Free(mb);
		return (mdsyserror(ep, errno, np->rname));
	}

	if (read(fd, mb, DEV_BSIZE) != DEV_BSIZE) {
		Free(mb);
		return (mdsyserror(ep, errno, np->rname));
	}

	if (crcchk((uchar_t *)mb, (uint_t *)&mb->mb_checksum,
	    (uint_t)DEV_BSIZE, (crc_skip_t *)NULL)) {
		Free(mb);
		return (mdmddberror(ep, MDE_NOTVERIFIED,
		    meta_getminor(np->dev), sp->setno, 0, np->rname));
	}

	Free(mb);
	return (0);
}

void
meta_mkdummymaster(
	mdsetname_t	*sp,
	int		fd,
	daddr_t		firstblk
)
{
	md_timeval32_t	tp;
	struct mddb_mb	*mb;
	ddi_devid_t	devid;
	md_set_desc	*sd;
	md_error_t	ep = mdnullerror;
	md_timeval32_t	inittime;

	/*
	 * No dummy master blocks are written for a MN diskset since devids
	 * are not supported in MN disksets.
	 */
	if (! metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, &ep)) == NULL)
			return;

		if (MD_MNSET_DESC(sd))
			return;
	}

	if ((mb = Zalloc(DEV_BSIZE)) == NULL)
		return;

	mb->mb_magic = MDDB_MAGIC_DU;
	mb->mb_revision = MDDB_REV_MB;
	mb->mb_setno = sp->setno;
	inittime = meta_get_lb_inittime(sp, &ep);
	mb->mb_setcreatetime = inittime;

	if (meta_gettimeofday(&tp) != -1)
		mb->mb_timestamp = tp;

	/*
	 * We try to save the disks device ID into the remaining bytes in
	 * the master block.  This allows the disk image to be self-identifying
	 * if it gets copied (e.g. SNDR, True Copy, etc.).  This is used
	 * when we try to import these disks on the remote copied image.
	 * If we cannot save the disks device ID onto the master block that is
	 * ok.  The disk is just not self-identifying and won't be importable
	 * in the remote copy scenario.
	 */
	if (devid_get(fd, &devid) == 0) {
		int len;

		len = devid_sizeof(devid);
		if (len <= DEV_BSIZE - sizeof (*mb)) {
			/* there is enough space to store the devid */
			mb->mb_devid_magic = MDDB_MAGIC_DE;
			mb->mb_devid_len = len;
			(void) memcpy(mb->mb_devid, (char *)devid, len);
		}
		devid_free(devid);
	}

	crcgen((uchar_t *)mb, (uint_t *)&mb->mb_checksum, (uint_t)DEV_BSIZE,
	    (crc_skip_t *)NULL);

	/*
	 * If any of these operations fail, we need to inform the
	 * user that the disk won't be self identifying. When support
	 * for importing remotely replicated disksets is added, we
	 * want to add the error messages here.
	 */
	if (lseek(fd, (off_t)(firstblk * DEV_BSIZE), SEEK_SET) < 0)
		goto out;

	if (write(fd, mb, DEV_BSIZE) != DEV_BSIZE)
		goto out;

	if (lseek(fd, (off_t)(firstblk * DEV_BSIZE), SEEK_SET) < 0)
		goto out;

	if (read(fd, mb, DEV_BSIZE) != DEV_BSIZE)
		goto out;

	if (crcchk((uchar_t *)mb, (uint_t *)&mb->mb_checksum,
	    (uint_t)DEV_BSIZE, (crc_skip_t *)NULL))
		goto out;

out:
	Free(mb);
}

static int
buildconf(mdsetname_t *sp, md_error_t *ep)
{
	md_replicalist_t	*rlp = NULL;
	md_replicalist_t	*rl;
	FILE			*cfp = NULL;
	FILE			*mfp = NULL;
	struct stat		sbuf;
	int			rval = 0;
	int			in_miniroot = 0;
	char			line[MDDB_BOOTLIST_MAX_LEN];
	char			*tname = NULL;

	/* get list of local replicas */
	if (! metaislocalset(sp))
		return (0);

	if (metareplicalist(sp, MD_BASICNAME_OK, &rlp, ep) < 0)
		return (-1);

	/* open tempfile, copy permissions of original file */
	if ((cfp = fopen(META_DBCONFTMP, "w+")) == NULL) {
		/*
		 * On the miniroot tmp files must be created in /var/tmp.
		 * If we get a EROFS error, we assume that we are in the
		 * miniroot.
		 */
		if (errno != EROFS)
			goto error;
		in_miniroot = 1;
		errno = 0;
		tname = tempnam("/var/tmp", "slvm_");
		if (tname == NULL && errno == EROFS) {
			/*
			 * If we are booted on a read-only root because
			 * of mddb quorum problems we don't want to emit
			 * any scary error messages.
			 */
			errno = 0;
			goto out;
		}

		/* open tempfile, copy permissions of original file */
		if ((cfp = fopen(tname, "w+")) == NULL)
			goto error;
	}
	if (stat(META_DBCONF, &sbuf) == 0) {
		if (fchmod(fileno(cfp), (sbuf.st_mode & 0666)) != 0)
			goto error;
		if (fchown(fileno(cfp), sbuf.st_uid, sbuf.st_gid) != 0)
			goto error;
	}

	/* print header */
	if (fprintf(cfp, "#metadevice database location file ") == EOF)
		goto error;
	if (fprintf(cfp, "do not hand edit\n") < 0)
		goto error;
	if (fprintf(cfp,
	    "#driver\tminor_t\tdaddr_t\tdevice id\tchecksum\n") < 0)
		goto error;

	/* dump replicas */
	for (rl = rlp; (rl != NULL); rl = rl->rl_next) {
		md_replica_t	*r = rl->rl_repp;
		int		checksum = 42;
		int		i;
		char		*devidp;
		minor_t		min;

		devidp = devid_str_encode(r->r_devid, r->r_minor_name);
		/* If devid code can't encode devidp - skip entry */
		if (devidp == NULL) {
			continue;
		}

		/* compute checksum */
		for (i = 0; ((r->r_driver_name[i] != '\0') &&
		    (i < sizeof (r->r_driver_name))); i++) {
			checksum -= r->r_driver_name[i];
		}
		min = meta_getminor(r->r_namep->dev);
		checksum -= min;
		checksum -= r->r_blkno;

		for (i = 0; i < strlen(devidp); i++) {
			checksum -= devidp[i];
		}
		/* print info */
		if (fprintf(cfp, "%s\t%lu\t%ld\t%s\t%d\n",
		    r->r_driver_name, min, r->r_blkno, devidp, checksum) < 0) {
			goto error;
		}

		devid_str_free(devidp);
	}

	/* close and rename to real file */
	if (fflush(cfp) != 0)
		goto error;
	if (fsync(fileno(cfp)) != 0)
		goto error;
	if (fclose(cfp) != 0) {
		cfp = NULL;
		goto error;
	}
	cfp = NULL;

	/*
	 * Renames don't work in the miniroot since tmpfiles are
	 * created in /var/tmp. Hence we copy the data out.
	 */

	if (! in_miniroot) {
		if (rename(META_DBCONFTMP, META_DBCONF) != 0)
			goto error;
	} else {
		if ((cfp = fopen(tname, "r")) == NULL)
			goto error;
		if ((mfp = fopen(META_DBCONF, "w+")) == NULL)
			goto error;
		while (fgets(line, MDDB_BOOTLIST_MAX_LEN, cfp) != NULL) {
			if (fputs(line, mfp) == NULL)
				goto error;
		}
		(void) fclose(cfp);
		cfp = NULL;
		if (fflush(mfp) != 0)
			goto error;
		if (fsync(fileno(mfp)) != 0)
			goto error;
		if (fclose(mfp) != 0) {
			mfp = NULL;
			goto error;
		}
		/* delete the tempfile */
		(void) unlink(tname);
	}
	/* success */
	rval = 0;
	goto out;

	/* tempfile error */
error:
	rval = (in_miniroot) ? mdsyserror(ep, errno, tname):
	    mdsyserror(ep, errno, META_DBCONFTMP);


	/* cleanup, return success */
out:
	if (rlp != NULL)
		metafreereplicalist(rlp);
	if ((cfp != NULL) && (fclose(cfp) != 0) && (rval == 0)) {
		rval = (in_miniroot) ? mdsyserror(ep, errno, tname):
		    mdsyserror(ep, errno, META_DBCONFTMP);
	}
	free(tname);
	return (rval);
}

/*
 * check replica for dev
 */
static int
in_replica(
	mdsetname_t	*sp,
	md_replica_t	*rp,
	mdname_t	*np,
	diskaddr_t	slblk,
	diskaddr_t	nblks,
	md_error_t	*ep
)
{
	mdname_t	*repnp = rp->r_namep;
	diskaddr_t	rep_sblk = rp->r_blkno;
	diskaddr_t	rep_nblks = rp->r_nblk;

	/* should be in the same set */
	assert(sp != NULL);

	/* if error in master block, assume whole partition */
	if ((rep_sblk == MD_DISKADDR_ERROR) ||
	    (rep_nblks == MD_DISKADDR_ERROR)) {
		rep_sblk = 0;
		rep_nblks = MD_DISKADDR_ERROR;
	}

	/* check overlap */
	if (meta_check_overlap(
	    MDB_STR, np, slblk, nblks, repnp, rep_sblk, rep_nblks, ep) != 0) {
		return (-1);
	}

	/* return success */
	return (0);
}

/*
 * check to see if we're in a replica
 */
int
meta_check_inreplica(
	mdsetname_t		*sp,
	mdname_t		*np,
	diskaddr_t		slblk,
	diskaddr_t		nblks,
	md_error_t		*ep
)
{
	md_replicalist_t	*rlp = NULL;
	md_replicalist_t	*rl;
	int			rval = 0;

	/* should have a set */
	assert(sp != NULL);

	/* for each replica */
	if (metareplicalist(sp, MD_BASICNAME_OK, &rlp, ep) < 0)
		return (-1);
	for (rl = rlp; (rl != NULL); rl = rl->rl_next) {
		md_replica_t	*rp = rl->rl_repp;

		/* check replica */
		if (in_replica(sp, rp, np, slblk, nblks, ep) != 0) {
			rval = -1;
			break;
		}
	}

	/* cleanup, return success */
	metafreereplicalist(rlp);
	return (rval);
}

/*
 * check replica
 */
int
meta_check_replica(
	mdsetname_t	*sp,		/* set to check against */
	mdname_t	*np,		/* component to check against */
	mdchkopts_t	options,	/* option flags */
	diskaddr_t	slblk,		/* start logical block */
	diskaddr_t	nblks,		/* number of blocks (-1,rest of them) */
	md_error_t	*ep		/* error packet */
)
{
	mdchkopts_t	chkoptions = MDCHK_ALLOW_REPSLICE;

	/* make sure we have a disk */
	if (metachkcomp(np, ep) != 0)
		return (-1);

	/* check to ensure that it is not already in use */
	if (meta_check_inuse(sp, np, MDCHK_INUSE, ep) != 0) {
		return (-1);
	}

	if (options & MDCHK_ALLOW_NODBS)
		return (0);

	if (options & MDCHK_DRVINSET)
		return (0);

	/* make sure it is in the set */
	if (meta_check_inset(sp, np, ep) != 0)
		return (-1);

	/* make sure its not in a metadevice */
	if (meta_check_inmeta(sp, np, chkoptions, slblk, nblks, ep) != 0)
		return (-1);

	/* return success */
	return (0);
}

static int
update_dbinfo_on_drives(
	mdsetname_t	*sp,
	md_drive_desc	*dd,
	int		set_locked,
	int		force,
	md_error_t	*ep
)
{
	md_set_desc		*sd;
	int			i;
	md_setkey_t		*cl_sk;
	int			rval = 0;
	md_mnnode_desc		*nd;

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	if (! set_locked) {
		if (MD_MNSET_DESC(sd)) {
			md_error_t xep = mdnullerror;
			sigset_t sigs;
			/* Make sure we are blocking all signals */
			if (procsigs(TRUE, &sigs, &xep) < 0)
				mdclrerror(&xep);

			nd = sd->sd_nodelist;
			while (nd) {
				if (force && strcmp(nd->nd_nodename,
				    mynode()) != 0) {
					nd = nd->nd_next;
					continue;
				}

				if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
					nd = nd->nd_next;
					continue;
				}

				if (clnt_lock_set(nd->nd_nodename, sp, ep))
					return (-1);
				nd = nd->nd_next;
			}
		} else {
			for (i = 0; i < MD_MAXSIDES; i++) {
				/* Skip empty slots */
				if (sd->sd_nodes[i][0] == '\0')
					continue;

				if (force && strcmp(sd->sd_nodes[i],
				    mynode()) != 0)
					continue;

				if (clnt_lock_set(sd->sd_nodes[i], sp, ep))
					return (-1);
			}
		}
	}

	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			if (force && strcmp(nd->nd_nodename, mynode()) != 0) {
				nd = nd->nd_next;
				continue;
			}

			if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
				nd = nd->nd_next;
				continue;
			}

			if (clnt_upd_dr_dbinfo(nd->nd_nodename, sp, dd, ep)
			    == -1) {
				rval = -1;
				break;
			}
			nd = nd->nd_next;
		}
	} else {
		for (i = 0; i < MD_MAXSIDES; i++) {
			/* Skip empty slots */
			if (sd->sd_nodes[i][0] == '\0')
				continue;

			if (force && strcmp(sd->sd_nodes[i], mynode()) != 0)
				continue;

			if (clnt_upd_dr_dbinfo(sd->sd_nodes[i], sp, dd, ep)
			    == -1) {
				rval = -1;
				break;
			}
		}
	}

	if (! set_locked) {
		cl_sk = cl_get_setkey(sp->setno, sp->setname);
		if (MD_MNSET_DESC(sd)) {
			nd = sd->sd_nodelist;
			while (nd) {
				if (force &&
				    strcmp(nd->nd_nodename, mynode()) != 0) {
					nd = nd->nd_next;
					continue;
				}

				if (!(nd->nd_flags & MD_MN_NODE_ALIVE)) {
					nd = nd->nd_next;
					continue;
				}

				if (clnt_unlock_set(nd->nd_nodename, cl_sk,
				    ep)) {
					rval = -1;
					break;
				}
				nd = nd->nd_next;
			}
		} else {
			for (i = 0; i < MD_MAXSIDES; i++) {
				/* Skip empty slots */
				if (sd->sd_nodes[i][0] == '\0')
					continue;

				if (force &&
				    strcmp(sd->sd_nodes[i], mynode()) != 0)
					continue;

				if (clnt_unlock_set(sd->sd_nodes[i], cl_sk,
				    ep)) {
					rval = -1;
					break;
				}
			}

		}
		cl_set_setkey(NULL);
	}

	return (rval);
}

int
meta_db_addsidenms(
	mdsetname_t	*sp,
	mdname_t	*np,
	daddr_t		blkno,
	int		bcast,
	md_error_t	*ep
)
{
	side_t		sideno;
	char		*bname = NULL;
	char		*dname = NULL;
	minor_t		mnum;
	mddb_config_t	c;
	int		done;
	int		rval = 0;
	md_set_desc	*sd;

	sideno = MD_SIDEWILD;
	/*CONSTCOND*/
	while (1) {
		if (bname != NULL) {
			Free(bname);
			bname = NULL;
		}
		if (dname != NULL) {
			Free(dname);
			dname = NULL;
		}
		if ((done = meta_getnextside_devinfo(sp, np->bname,
		    &sideno, &bname, &dname, &mnum, ep)) == -1) {
			rval = -1;
			break;
		}

		if (done == 0)
			break;

		if (! metaislocalset(sp)) {
			if ((sd = metaget_setdesc(sp, ep)) == NULL) {
				rval = -1;
				break;
			}
		}

		/*
		 * Send addsidenms to all nodes using rpc.mdcommd if
		 * sidename is being added to MN diskset.
		 *
		 *   It's ok to broadcast this call to other nodes.
		 *
		 *   Note: The broadcast to other nodes isn't needed during
		 *   the addition of the first mddbs to the set since the
		 *   other nodes haven't been joined to the set yet.  All
		 *   nodes in a MN diskset are (implicitly) joined to the set
		 *   on the addition of the first mddb.
		 */
		if ((! metaislocalset(sp)) && MD_MNSET_DESC(sd) &&
		    (bcast == DB_ADDSIDENMS_BCAST)) {
			md_mn_result_t			*resultp = NULL;
			md_mn_msg_meta_db_newside_t	db_ns;
			int				send_rval;

			db_ns.msg_l_dev = np->dev;
			db_ns.msg_sideno = sideno;
			db_ns.msg_blkno = blkno;
			(void) strncpy(db_ns.msg_dname, dname,
			    sizeof (db_ns.msg_dname));
			(void) splitname(np->bname, &db_ns.msg_splitname);
			db_ns.msg_mnum = mnum;

			/* Set devid to NULL until devids are supported */
			db_ns.msg_devid[0] = NULL;

			/*
			 * If reconfig cycle has been started, this node is
			 * stuck in in the return step until this command has
			 * completed.  If mdcommd is suspended, ask
			 * send_message to fail (instead of retrying)
			 * so that metaset can finish allowing the reconfig
			 * cycle to proceed.
			 */
			send_rval = mdmn_send_message(sp->setno,
			    MD_MN_MSG_META_DB_NEWSIDE, MD_MSGF_FAIL_ON_SUSPEND |
			    MD_MSGF_PANIC_WHEN_INCONSISTENT, (char *)&db_ns,
			    sizeof (md_mn_msg_meta_db_newside_t),
			    &resultp, ep);
			if (send_rval != 0) {
				rval = -1;
				if (resultp == NULL)
					(void) mddserror(ep,
					    MDE_DS_COMMD_SEND_FAIL,
					    sp->setno, NULL, NULL,
					    sp->setname);
				else {
					(void) mdstealerror(ep,
					    &(resultp->mmr_ep));
					if (mdisok(ep)) {
						(void) mddserror(ep,
						    MDE_DS_COMMD_SEND_FAIL,
						    sp->setno, NULL, NULL,
						    sp->setname);
					}
					free_result(resultp);
				}
				break;
			}
			if (resultp)
				free_result(resultp);
		} else {
			/*
			 * Let this side's  device name, minor # and driver name
			 * be known to the database replica.
			 */
			(void) memset(&c, 0, sizeof (c));

			/* Fill in device/replica info */
			c.c_locator.l_dev = meta_cmpldev(np->dev);
			c.c_locator.l_blkno = blkno;
			(void) strncpy(c.c_locator.l_driver, dname,
			    sizeof (c.c_locator.l_driver));
			if (splitname(np->bname, &c.c_devname) ==
			    METASPLIT_LONGDISKNAME && devid_in_use == FALSE) {
				rval = mddeverror(ep, MDE_DISKNAMETOOLONG,
				    NODEV64, np->rname);
				break;
			}

			c.c_locator.l_mnum = mnum;

			/* Fill in setno, setname, and sideno */
			c.c_setno = sp->setno;
			(void) strncpy(c.c_setname, sp->setname,
			    sizeof (c.c_setname));
			c.c_sideno = sideno;

			/*
			 * Don't need device id information from this ioctl
			 * Kernel determines device id from dev_t, which
			 * is just what this code would do.
			 */
			c.c_locator.l_devid = (uint64_t)0;
			c.c_locator.l_devid_flags = 0;

			if (metaioctl(MD_DB_NEWSIDE, &c, &c.c_mde, NULL) != 0) {
				rval = mdstealerror(ep, &c.c_mde);
				break;
			}
		}
	}

	/* cleanup, return success */
	if (bname != NULL) {
		Free(bname);
		bname = NULL;
	}
	if (dname != NULL) {
		Free(dname);
		dname = NULL;
	}
	return (rval);
}


int
meta_db_delsidenm(
	mdsetname_t	*sp,
	side_t		sideno,
	mdname_t	*np,
	daddr_t		blkno,
	md_error_t	*ep
)
{
	mddb_config_t	c;
	md_set_desc	*sd;

	if (! metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);
	}
	/* Use rpc.mdcommd to delete mddb side from all nodes */
	if ((! metaislocalset(sp)) && MD_MNSET_DESC(sd) &&
	    (sd->sd_mn_mynode->nd_flags & MD_MN_NODE_OWN)) {
		md_mn_result_t			*resultp = NULL;
		md_mn_msg_meta_db_delside_t	db_ds;
		int				send_rval;

		db_ds.msg_l_dev = np->dev;
		db_ds.msg_blkno = blkno;
		db_ds.msg_sideno = sideno;

		/* Set devid to NULL until devids are supported */
		db_ds.msg_devid[0] = NULL;

		/*
		 * If reconfig cycle has been started, this node is
		 * stuck in in the return step until this command has
		 * completed.  If mdcommd is suspended, ask
		 * send_message to fail (instead of retrying)
		 * so that metaset can finish allowing the reconfig
		 * cycle to proceed.
		 */
		send_rval = mdmn_send_message(sp->setno,
		    MD_MN_MSG_META_DB_DELSIDE, MD_MSGF_FAIL_ON_SUSPEND |
		    MD_MSGF_PANIC_WHEN_INCONSISTENT, (char *)&db_ds,
		    sizeof (md_mn_msg_meta_db_delside_t), &resultp, ep);
		if (send_rval != 0) {
			if (resultp == NULL)
				(void) mddserror(ep,
				    MDE_DS_COMMD_SEND_FAIL,
				    sp->setno, NULL, NULL,
				    sp->setname);
			else {
				(void) mdstealerror(ep, &(resultp->mmr_ep));
				if (mdisok(ep)) {
					(void) mddserror(ep,
					    MDE_DS_COMMD_SEND_FAIL,
					    sp->setno, NULL, NULL,
					    sp->setname);
				}
				free_result(resultp);
			}
			return (-1);
		}
		if (resultp)
			free_result(resultp);

	} else {
		/*
		 * Let this side's  device name, minor # and driver name
		 * be known to the database replica.
		 */
		(void) memset(&c, 0, sizeof (c));

		/* Fill in device/replica info */
		c.c_locator.l_dev = meta_cmpldev(np->dev);
		c.c_locator.l_blkno = blkno;

		/* Fill in setno, setname, and sideno */
		c.c_setno = sp->setno;
		(void) strcpy(c.c_setname, sp->setname);
		c.c_sideno = sideno;

		/*
		 * Don't need device id information from this ioctl
		 * Kernel determines device id from dev_t, which
		 * is just what this code would do.
		 */
		c.c_locator.l_devid = (uint64_t)0;
		c.c_locator.l_devid_flags = 0;

		if (metaioctl(MD_DB_DELSIDE, &c, &c.c_mde, NULL) != 0)
			return (mdstealerror(ep, &c.c_mde));
	}
	return (0);
}


static int
mdnamesareunique(mdnamelist_t *nlp, md_error_t *ep)
{
	mdnamelist_t		*dnp1, *dnp2;

	for (dnp1 = nlp; dnp1 != NULL; dnp1 = dnp1->next) {
		for (dnp2 = dnp1->next; dnp2 != NULL; dnp2 = dnp2->next) {
			if (strcmp(dnp1->namep->cname, dnp2->namep->cname) == 0)
				return (mderror(ep, MDE_DUPDRIVE,
				    dnp1->namep->cname));
		}
	}
	return (0);
}


/*
 * Return 1 if files are different, else return 0
 */
static int
filediff(char *tsname, char *sname)
{
	int ret = 1, fd;
	size_t tsz, sz;
	struct stat sbuf;
	char *tbuf, *buf;

	if (stat(tsname, &sbuf) != 0)
		return (1);
	tsz = sbuf.st_size;
	if (stat(sname, &sbuf) != 0)
		return (1);
	sz = sbuf.st_size;
	if (tsz != sz)
		return (1);

	/* allocate memory and read both files into buffer */
	tbuf = malloc(tsz);
	buf = malloc(sz);
	if (tbuf == NULL || buf == NULL)
		goto out;

	fd = open(tsname, O_RDONLY);
	if (fd == -1)
		goto out;
	sz = read(fd, tbuf, tsz);
	(void) close(fd);
	if (sz != tsz)
		goto out;

	fd = open(sname, O_RDONLY);
	if (fd == -1)
		goto out;
	sz = read(fd, buf, tsz);
	(void) close(fd);
	if (sz != tsz)
		goto out;

	/* compare content */
	ret = bcmp(tbuf, buf, tsz);
out:
	if (tbuf)
		free(tbuf);
	if (buf)
		free(buf);
	return (ret);
}

/*
 * patch md.conf file with mddb locations
 */
int
meta_db_patch(
	char		*sname,		/* system file name */
	char		*cname,		/* mddb.cf file name */
	int		patch,		/* patching locally */
	md_error_t	*ep
)
{
	char		*tsname = NULL;
	char		line[MDDB_BOOTLIST_MAX_LEN];
	FILE		*tsfp = NULL;
	FILE		*mfp = NULL;
	int		rval = -1;

	/* check names */
	if (sname == NULL) {
		if (patch)
			sname = "md.conf";
		else
			sname = "/kernel/drv/md.conf";
	}
	if (cname == NULL)
		cname = META_DBCONF;

	/*
	 * edit file
	 */
	if (meta_systemfile_copy(sname, 0, 1, 1, 0, &tsname, &tsfp, ep) != 0) {
		if (mdissyserror(ep, EROFS)) {
			/*
			 * If we are booted on a read-only root because
			 * of mddb quorum problems we don't want to emit
			 * any scary error messages.
			 */
			mdclrerror(ep);
			rval = 0;
		}
		goto out;
	}

	if (meta_systemfile_append_mddb(cname, sname, tsname, tsfp, 1, 0, 0,
	    ep) != 0)
		goto out;

	/* if file content is identical, skip rename */
	if (filediff(tsname, sname) == 0) {
		rval = 0;
		goto out;
	}

	if ((fflush(tsfp) != 0) || (fsync(fileno(tsfp)) != 0) ||
	    (fclose(tsfp) != 0)) {
		(void) mdsyserror(ep, errno, tsname);
		goto out;
	}

	tsfp = NULL;

	/*
	 * rename file. If we get a Cross Device error then it
	 * is because we are in the miniroot.
	 */
	if (rename(tsname, sname) != 0 && errno != EXDEV) {
		(void) mdsyserror(ep, errno, sname);
		goto out;
	}

	if (errno == EXDEV) {
		if ((tsfp = fopen(tsname, "r")) == NULL)
			goto out;
		if ((mfp = fopen(sname, "w+")) == NULL)
			goto out;
		while (fgets(line, sizeof (line), tsfp) != NULL) {
			if (fputs(line, mfp) == NULL)
				goto out;
		}
		(void) fclose(tsfp);
		tsfp = NULL;
		if (fflush(mfp) != 0)
			goto out;
		if (fsync(fileno(mfp)) != 0)
			goto out;
		if (fclose(mfp) != 0) {
			mfp = NULL;
			goto out;
		}
	}

	Free(tsname);
	tsname = NULL;
	rval = 0;

	/* cleanup, return error */
out:
	if (tsfp != NULL)
		(void) fclose(tsfp);
	if (tsname != NULL) {
		(void) unlink(tsname);
		Free(tsname);
	}
	return (rval);
}

/*
 * Add replicas to set.  This happens as a result of:
 *	- metadb [-s set_name] -a
 *	- metaset -s set_name -a disk
 *	- metaset -s set_name -d disk	 (causes a rebalance of mddbs)
 *	- metaset -s set_name -b
 *
 * For a local set, this routine is run on the local set host.
 *
 * For a traditional diskset, this routine is run on the node that
 * is running the metaset command.
 *
 * For a multinode diskset, this routine is run by the node that is
 * running the metaset command.  If this is the first mddb added to
 * the MN diskset, then no communication is made to other nodes via commd
 * since the other nodes will be in-sync with respect to the mddbs when
 * those other nodes join the set and snarf in the newly created mddb.
 * If this is not the first mddb added to the MN diskset, then this
 * attach command is sent to all of the nodes using commd.  This keeps
 * the nodes in-sync.
 */
int
meta_db_attach(
	mdsetname_t		*sp,
	mdnamelist_t		*db_nlp,
	mdchkopts_t		options,
	md_timeval32_t		*timeval,
	int			dbcnt,
	int			dbsize,
	char			*sysfilename,
	md_error_t		*ep
)
{
	struct mddb_config	c;
	mdnamelist_t		*nlp;
	mdname_t		*np;
	md_drive_desc		*dd = NULL;
	md_drive_desc		*p;
	int			i;
	int			fd;
	side_t			sideno;
	daddr_t			blkno;
	int			replicacount = 0;
	int			start_svmdaemons = 0;
	int			rval = 0;
	md_error_t		status = mdnullerror;
	md_set_desc		*sd;
	int			stale_bool = FALSE;
	int			flags;
	int			firstmddb = 1;
	md_timeval32_t		inittime = {0, 0};

	/*
	 * Error if we don't get some work to do.
	 */
	if (db_nlp == NULL)
		return (mdsyserror(ep, EINVAL, NULL));

	if (mdnamesareunique(db_nlp, ep) != 0)
		return (-1);
	(void) memset(&c, 0, sizeof (c));
	c.c_id = 0;
	c.c_setno = sp->setno;

	/* Don't need device id information from this ioctl */
	c.c_locator.l_devid = (uint64_t)0;
	c.c_locator.l_devid_flags = 0;
	if (metaioctl(MD_DB_GETDEV, &c, &c.c_mde, NULL) != 0) {
		if (metaislocalset(sp)) {
			if (mdismddberror(&c.c_mde, MDE_DB_INVALID))
				mdclrerror(&c.c_mde);
			else if (! mdismddberror(&c.c_mde, MDE_DB_NODB) ||
			    (! (options & MDCHK_ALLOW_NODBS)))
				return (mdstealerror(ep, &c.c_mde));
		} else {
			if (! mdismddberror(&c.c_mde, MDE_DB_NOTOWNER))
				return (mdstealerror(ep, &c.c_mde));
		}
		mdclrerror(&c.c_mde);
	}
	/*
	 * Is current set STALE?
	 */
	if (c.c_flags & MDDB_C_STALE) {
		stale_bool = TRUE;
	}

	assert(db_nlp != NULL);

	/* if these are the first replicas then the SVM daemons need to run */
	if (c.c_dbcnt == 0)
		start_svmdaemons = 1;

	/*
	 * check to see if we will go over the total possible number
	 * of data bases
	 */
	nlp = db_nlp;
	while (nlp) {
		replicacount += dbcnt;
		nlp = nlp->next;
	}

	if ((replicacount + c.c_dbcnt) > c.c_dbmax)
		return (mdmddberror(ep, MDE_TOOMANY_REPLICAS, NODEV32,
		    sp->setno, c.c_dbcnt + replicacount, NULL));

	/*
	 * go through and check to make sure all locations specified
	 * are legal also pick out driver name;
	 */
	for (nlp = db_nlp; nlp != NULL; nlp = nlp->next) {
		diskaddr_t devsize;

		np = nlp->namep;

		if (! metaislocalset(sp)) {
			uint_t	partno;
			uint_t	rep_partno;
			mddrivename_t	*dnp = np->drivenamep;

			/*
			 * make sure that non-local database replicas
			 * are always on the replica slice.
			 */
			if (meta_replicaslice(dnp,
			    &rep_partno, ep) != 0)
				return (-1);
			if (metagetvtoc(np, FALSE, &partno, ep) == NULL)
				return (-1);
			if (partno != rep_partno)
				return (mddeverror(ep, MDE_REPCOMP_ONLY,
				    np->dev, sp->setname));
		}

		if (meta_check_replica(sp, np, options, 0, (dbcnt * dbsize),
		    ep)) {
			return (-1);
		}

		if ((devsize = metagetsize(np, ep)) == -1)
			return (-1);

		if (devsize < (diskaddr_t)((dbcnt * dbsize) + 16))
			return (mdmddberror(ep, MDE_REPLICA_TOOSMALL,
			    meta_getminor(np->dev), sp->setno, devsize,
			    np->cname));
	}

	/*
	 * If first disk in set we don't have lb_inittime yet for use as
	 * mb_setcreatetime so don't go looking for it. WE'll come back
	 * later and update after the locator block has been created.
	 * If this isn't the first disk in the set, we have a locator
	 * block and thus we have lb_inittime. Set mb_setcreatetime to
	 * lb_inittime.
	 */
	if (! metaislocalset(sp)) {
		if (c.c_dbcnt != 0) {
			firstmddb = 0;
			inittime = meta_get_lb_inittime(sp, ep);
		}
	}

	/*
	 * go through and write all master blocks
	 */

	for (nlp = db_nlp; nlp != NULL; nlp = nlp->next) {
		np = nlp->namep;

		if ((fd = open(np->rname, O_RDWR)) < 0)
			return (mdsyserror(ep, errno, np->rname));

		for (i = 0; i < dbcnt; i++) {
			if (mkmasterblks(sp, np, fd, (i * dbsize + 16), dbsize,
			    inittime, ep)) {
				(void) close(fd);
				return (-1);
			}
		}
		(void) close(fd);
	}

	if ((sideno = getmyside(sp, ep)) == MD_SIDEWILD)
		return (-1);

	if (! metaislocalset(sp)) {
		dd = metaget_drivedesc_fromnamelist(sp, db_nlp, ep);
		if (! mdisok(ep))
			return (-1);
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);

	}

	/*
	 * go through and tell kernel to add them
	 */
	for (nlp = db_nlp; nlp != NULL; nlp = nlp->next) {
		mdcinfo_t	*cinfo;

		np = nlp->namep;

		if ((cinfo = metagetcinfo(np, ep)) == NULL) {
			rval = -1;
			goto out;
		}

		/*
		 * If mddb is being added to MN diskset and there already
		 * exists a valid mddb in the set (which equates to this
		 * node being an owner of the set) then use rpc.mdcommd
		 * mechanism to add mddb(s) so that all nodes stay in sync.
		 * If set is stale, don't log the message since rpc.mdcommd
		 * can't write the message to the mddb.
		 *
		 * Otherwise, just add mddb to this node.
		 */
		if ((! metaislocalset(sp)) && MD_MNSET_DESC(sd) &&
		    (sd->sd_mn_mynode->nd_flags & MD_MN_NODE_OWN)) {
			md_mn_result_t			*resultp = NULL;
			md_mn_msg_meta_db_attach_t	attach;
			int 				send_rval;

			/*
			 * In a scenario where new replicas had been added on
			 * the master, and then all of the old replicas failed
			 * before the slaves had knowledge of the new replicas,
			 * the slaves are unable to re-parse in the mddb
			 * from the new replicas since the slaves have no
			 * knowledge of the new replicas.  The following
			 * algorithm solves this problem:
			 * 	- META_DB_ATTACH message generates submsgs
			 * 		- BLOCK parse (master)
			 * 		- MDDB_ATTACH new replicas
			 * 		- UNBLOCK parse (master) causing parse
			 *		information to be sent from master
			 *		to slaves at a higher class than the
			 *		unblock so the parse message will
			 *		reach slaves before unblock message.
			 */
			attach.msg_l_dev = np->dev;
			attach.msg_cnt = dbcnt;
			attach.msg_dbsize = dbsize;
			(void) strncpy(attach.msg_dname, cinfo->dname,
			    sizeof (attach.msg_dname));
			(void) splitname(np->bname, &attach.msg_splitname);
			attach.msg_options = options;

			/* Set devid to NULL until devids are supported */
			attach.msg_devid[0] = NULL;

			/*
			 * If reconfig cycle has been started, this node is
			 * stuck in in the return step until this command has
			 * completed.  If mdcommd is suspended, ask
			 * send_message to fail (instead of retrying)
			 * so that metaset can finish allowing the reconfig
			 * cycle to proceed.
			 */
			flags = MD_MSGF_FAIL_ON_SUSPEND;
			if (stale_bool == TRUE)
				flags |= MD_MSGF_NO_LOG;
			send_rval = mdmn_send_message(sp->setno,
			    MD_MN_MSG_META_DB_ATTACH,
			    flags, (char *)&attach,
			    sizeof (md_mn_msg_meta_db_attach_t),
			    &resultp, ep);
			if (send_rval != 0) {
				rval = -1;
				if (resultp == NULL)
					(void) mddserror(ep,
					    MDE_DS_COMMD_SEND_FAIL,
					    sp->setno, NULL, NULL,
					    sp->setname);
				else {
					(void) mdstealerror(ep,
					    &(resultp->mmr_ep));
					if (mdisok(ep)) {
						(void) mddserror(ep,
						    MDE_DS_COMMD_SEND_FAIL,
						    sp->setno, NULL, NULL,
						    sp->setname);
					}
					free_result(resultp);
				}
				goto out;
			}
			if (resultp)
				free_result(resultp);
		} else {
			/* Adding mddb(s) to just this node */
			for (i = 0; i < dbcnt; i++) {
				(void) memset(&c, 0, sizeof (c));
				/* Fill in device/replica info */
				c.c_locator.l_dev = meta_cmpldev(np->dev);
				c.c_locator.l_blkno = i * dbsize + 16;
				blkno = c.c_locator.l_blkno;
				(void) strncpy(c.c_locator.l_driver,
				    cinfo->dname,
				    sizeof (c.c_locator.l_driver));

				if (splitname(np->bname, &c.c_devname) ==
				    METASPLIT_LONGDISKNAME && devid_in_use ==
				    FALSE) {
					rval = mddeverror(ep,
					    MDE_DISKNAMETOOLONG,
					    NODEV64, np->rname);
					goto out;
				}

				c.c_locator.l_mnum = meta_getminor(np->dev);

				/* Fill in setno, setname, and sideno */
				c.c_setno = sp->setno;
				if (! metaislocalset(sp)) {
					if (MD_MNSET_DESC(sd)) {
						c.c_multi_node = 1;
					}
				}
				(void) strcpy(c.c_setname, sp->setname);
				c.c_sideno = sideno;

				/*
				 * Don't need device id information from this
				 * ioctl Kernel determines device id from
				 * dev_t, which is just what this code would do.
				 */
				c.c_locator.l_devid = (uint64_t)0;
				c.c_locator.l_devid_flags = 0;

				if (timeval != NULL)
					c.c_timestamp = *timeval;

				if (setup_med_cfg(sp, &c,
				    (options & MDCHK_SET_FORCE), ep)) {
					rval = -1;
					goto out;
				}

				if (metaioctl(MD_DB_NEWDEV, &c, &c.c_mde,
				    NULL) != 0) {
					rval = mdstealerror(ep, &c.c_mde);
					goto out;
				}
				/*
				 * This is either a traditional diskset OR this
				 * is the first replica added to a MN diskset.
				 * In either case, set broadcast to NO_BCAST so
				 * that message won't go through rpc.mdcommd.
				 * If this is a traditional diskset, the bcast
				 * flag is ignored since traditional disksets
				 * don't use the rpc.mdcommd.
				 */
				if (meta_db_addsidenms(sp, np, blkno,
				    DB_ADDSIDENMS_NO_BCAST, ep))
					goto out;
			}
		}
		if (! metaislocalset(sp)) {
			/* update the dbcnt and size in dd */
			for (p = dd; p != NULL; p = p->dd_next)
				if (p->dd_dnp == np->drivenamep) {
					p->dd_dbcnt = dbcnt;
					p->dd_dbsize  = dbsize;
					break;
				}
		}

		/*
		 * If this was the first addition of disks to the
		 * diskset you now need to update the mb_setcreatetime
		 * which needed lb_inittime which wasn't there until now.
		 */
		if (firstmddb) {
			if (meta_update_mb(sp, dd, ep) != 0) {
				return (-1);
			}
		}
		(void) close(fd);
	}

out:
	if (metaislocalset(sp)) {

		/* everything looks fine. Start mdmonitord */
		if (rval == 0 && start_svmdaemons == 1) {
			if (meta_smf_enable(META_SMF_CORE, &status) == -1) {
				mde_perror(&status, "");
				mdclrerror(&status);
			}
		}

		if (buildconf(sp, &status)) {
			/* Don't mask any previous errors */
			if (rval == 0)
				rval = mdstealerror(ep, &status);
			return (rval);
		}

		if (meta_db_patch(sysfilename, NULL, 0, &status)) {
			/* Don't mask any previous errors */
			if (rval == 0)
				rval = mdstealerror(ep, &status);
		}
	} else {
		if (update_dbinfo_on_drives(sp, dd,
		    (options & MDCHK_SET_LOCKED),
		    (options & MDCHK_SET_FORCE),
		    &status)) {
			/* Don't mask any previous errors */
			if (rval == 0)
				rval = mdstealerror(ep, &status);
			else
				mdclrerror(&status);
		}
		metafreedrivedesc(&dd);
	}
	/*
	 * For MN disksets that already had already had nodes joined
	 * before the attach of this mddb(s), the name invalidation is
	 * done by the commd handler routine.  Otherwise, if this
	 * is the first attach of a MN diskset mddb, the invalidation
	 * must be done here since the first attach cannot be sent
	 * via the commd since there are no nodes joined to the set yet.
	 */
	if ((metaislocalset(sp)) || (!MD_MNSET_DESC(sd)) ||
	    (MD_MNSET_DESC(sd) &&
	    (!(sd->sd_mn_mynode->nd_flags & MD_MN_NODE_OWN)))) {
		for (nlp = db_nlp; (nlp != NULL); nlp = nlp->next) {
			meta_invalidate_name(nlp->namep);
		}
	}
	return (rval);
}

/*
 * deletelist_length
 *
 *	return the number of slices that have been specified for deletion
 *	on the metadb command line.  This does not calculate the number
 *	of replicas because there may be multiple replicas per slice.
 */
static int
deletelist_length(mdnamelist_t *db_nlp)
{

	mdnamelist_t		*nlp;
	int			list_length = 0;

	for (nlp = db_nlp; nlp != NULL; nlp = nlp->next) {
		list_length++;
	}

	return (list_length);
}

static int
in_deletelist(char *devname, mdnamelist_t *db_nlp)
{

	mdnamelist_t		*nlp;
	mdname_t		*np;
	int			index = 0;

	for (nlp = db_nlp; nlp != NULL; nlp = nlp->next) {
		np = nlp->namep;

		if (strcmp(devname, np->bname) == 0)
			return (index);
		index++;
	}

	return (-1);
}

/*
 * Delete replicas from set.  This happens as a result of:
 *	- metadb [-s set_name] -d
 *	- metaset -s set_name -a disk	(causes a rebalance of mddbs)
 *	- metaset -s set_name -d disk
 *	- metaset -s set_name -b
 *
 * For a local set, this routine is run on the local set host.
 *
 * For a traditional diskset, this routine is run on the node that
 * is running the metaset command.
 *
 * For a multinode diskset, this routine is run by the node that is
 * running the metaset command.  This detach routine is sent to all
 * of the joined nodes in the diskset using commd.  This keeps
 * the nodes in-sync.
 */
int
meta_db_detach(
	mdsetname_t		*sp,
	mdnamelist_t		*db_nlp,
	mdforceopts_t		force_option,
	char			*sysfilename,
	md_error_t		*ep
)
{
	struct mddb_config	c;
	mdnamelist_t		*nlp;
	mdname_t		*np;
	md_drive_desc		*dd = NULL;
	md_drive_desc		*p;
	int			replicacount;
	int			replica_delete_count;
	int			nr_replica_slices;
	int			i;
	int			stop_svmdaemons = 0;
	int			rval = 0;
	int			index;
	int			valid_replicas_nottodelete = 0;
	int			invalid_replicas_nottodelete = 0;
	int			invalid_replicas_todelete = 0;
	int			errored = 0;
	int			*tag_array;
	int			fd = -1;
	md_error_t		status = mdnullerror;
	md_set_desc		*sd;
	int			stale_bool = FALSE;
	int			flags;

	/*
	 * Error if we don't get some work to do.
	 */
	if (db_nlp == NULL)
		return (mdsyserror(ep, EINVAL, NULL));

	if (mdnamesareunique(db_nlp, ep) != 0)
		return (-1);

	(void) memset(&c, 0, sizeof (c));
	c.c_id = 0;
	c.c_setno = sp->setno;

	/* Don't need device id information from this ioctl */
	c.c_locator.l_devid = (uint64_t)0;
	c.c_locator.l_devid_flags = 0;

	if (metaioctl(MD_DB_GETDEV, &c, &c.c_mde, NULL) != 0)
		return (mdstealerror(ep, &c.c_mde));

	/*
	 * Is current set STALE?
	 */
	if (c.c_flags & MDDB_C_STALE) {
		stale_bool = TRUE;
	}

	replicacount = c.c_dbcnt;

	assert(db_nlp != NULL);

	/*
	 * go through and gather how many data bases are on each
	 * device specified.
	 */

	nr_replica_slices = deletelist_length(db_nlp);
	tag_array = (int *)calloc(nr_replica_slices, sizeof (int));

	replica_delete_count = 0;
	for (i = 0; i < replicacount; i++) {
		char	*devname;
		int	found = 0;

		c.c_id = i;

		/* Don't need device id information from this ioctl */
		c.c_locator.l_devid = (uint64_t)0;
		c.c_locator.l_devid_flags = 0;

		if (metaioctl(MD_DB_GETDEV, &c, &c.c_mde, NULL) != 0)
			return (mdstealerror(ep, &c.c_mde));

		devname = splicename(&c.c_devname);

		if (strstr(devname, META_LONGDISKNAME_STR) != NULL) {
			Free(devname);
			devname = getlongname(&c, ep);
			if (devname == NULL) {
				return (-1);
			}
		}

		if ((index = in_deletelist(devname, db_nlp)) != -1) {
			found = 1;
			tag_array[index] = 1;
			replica_delete_count++;
		}

		errored = c.c_locator.l_flags & (MDDB_F_EREAD |
		    MDDB_F_EWRITE | MDDB_F_TOOSMALL | MDDB_F_EFMT |
		    MDDB_F_EDATA | MDDB_F_EMASTER);

		/*
		 * There are four combinations of "errored" and "found"
		 * and they are used to find the number of
		 * (a) valid/invalid replicas that are not in the delete
		 * list and are available in the system.
		 * (b) valid/invalid replicas that are to be deleted.
		 */

		if (errored && !found)		/* errored and !found */
			invalid_replicas_nottodelete++;
		else if (!found)		/* !errored and !found */
			valid_replicas_nottodelete++;
		else if (errored)		/* errored and found */
			invalid_replicas_todelete++;
		/*
		 * else it is !errored and found. This means
		 * valid_replicas_todelete++; But this variable will not
		 * be used anywhere
		 */

		Free(devname);
	}

	index = 0;
	for (nlp = db_nlp; nlp != NULL; nlp = nlp->next) {
		np = nlp->namep;
		if (tag_array[index++] != 1) {
			Free(tag_array);
			return (mddeverror(ep, MDE_NO_DB, np->dev, np->cname));
		}
	}

	Free(tag_array);


	/* if all replicas are deleted stop mdmonitord */
	if ((replicacount - replica_delete_count) == 0)
		stop_svmdaemons = 1;

	if (((replicacount - replica_delete_count) < MD_MINREPLICAS)) {
		if (force_option & MDFORCE_NONE)
			return (mderror(ep, MDE_NOTENOUGH_DB, sp->setname));
		if (! metaislocalset(sp) && ! (force_option & MDFORCE_DS))
			return (mderror(ep, MDE_DELDB_NOTALLOWED, sp->setname));
	}

	/*
	 * The following algorithms are followed to check for deletion:
	 * (a) If the delete list(db_nlp) has all invalid replicas and no valid
	 * replicas, then deletion should be allowed.
	 * (b) Deletion should be allowed only if valid replicas that are "not"
	 * to be deleted is always greater than the invalid replicas that
	 * are "not" to be deleted.
	 * (c) If the user uses -f option, then deletion should be allowed.
	 */

	if ((invalid_replicas_todelete != replica_delete_count) &&
	    (invalid_replicas_nottodelete > valid_replicas_nottodelete) &&
	    (force_option != MDFORCE_LOCAL))
		return (mderror(ep, MDE_DEL_VALIDDB_NOTALLOWED, sp->setname));

	/*
	 * go through and tell kernel to delete them
	 */

	/* Don't need device id information from this ioctl */
	c.c_locator.l_devid = (uint64_t)0;
	c.c_locator.l_devid_flags = 0;

	if (metaioctl(MD_DB_GETDEV, &c, &c.c_mde, NULL) != 0)
		return (mdstealerror(ep, &c.c_mde));

	if (! metaislocalset(sp)) {
		dd = metaget_drivedesc_fromnamelist(sp, db_nlp, ep);
		if (! mdisok(ep))
			return (-1);
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);
	}

	for (nlp = db_nlp; nlp != NULL; nlp = nlp->next) {
		np = nlp->namep;

		/*
		 * If mddb is being deleted from MN diskset and node is
		 * an owner of the diskset then use rpc.mdcommd
		 * mechanism to add mddb(s) so that all nodes stay in sync.
		 * If set is stale, don't log the message since rpc.mdcommd
		 * can't write the message to the mddb.
		 *
		 * When mddbs are first being added to set, a detach can
		 * be called before any node has joined the diskset, so
		 * must check to see if node is an owner of the diskset.
		 *
		 * Otherwise, just delete mddb from this node.
		 */

		if ((! metaislocalset(sp)) && MD_MNSET_DESC(sd) &&
		    (sd->sd_mn_mynode->nd_flags & MD_MN_NODE_OWN)) {
			md_mn_result_t			*resultp;
			md_mn_msg_meta_db_detach_t	detach;
			int				send_rval;

			/*
			 * The following algorithm is used to detach replicas.
			 * 	- META_DB_DETACH message generates submsgs
			 * 		- BLOCK parse (master)
			 * 		- MDDB_DETACH replicas
			 * 		- UNBLOCK parse (master) causing parse
			 *		information to be sent from master
			 *		to slaves at a higher class than the
			 *		unblock so the parse message will
			 *		reach slaves before unblock message.
			 */
			(void) splitname(np->bname, &detach.msg_splitname);

			/* Set devid to NULL until devids are supported */
			detach.msg_devid[0] = NULL;

			/*
			 * If reconfig cycle has been started, this node is
			 * stuck in in the return step until this command has
			 * completed.  If mdcommd is suspended, ask
			 * send_message to fail (instead of retrying)
			 * so that metaset can finish allowing the reconfig
			 * cycle to proceed.
			 */
			flags = MD_MSGF_FAIL_ON_SUSPEND;
			if (stale_bool == TRUE)
				flags |= MD_MSGF_NO_LOG;
			send_rval = mdmn_send_message(sp->setno,
			    MD_MN_MSG_META_DB_DETACH,
			    flags, (char *)&detach,
			    sizeof (md_mn_msg_meta_db_detach_t),
			    &resultp, ep);
			if (send_rval != 0) {
				rval = -1;
				if (resultp == NULL)
					(void) mddserror(ep,
					    MDE_DS_COMMD_SEND_FAIL,
					    sp->setno, NULL, NULL,
					    sp->setname);
				else {
					(void) mdstealerror(ep,
					    &(resultp->mmr_ep));
					if (mdisok(ep)) {
						(void) mddserror(ep,
						    MDE_DS_COMMD_SEND_FAIL,
						    sp->setno, NULL, NULL,
						    sp->setname);
					}
					free_result(resultp);
				}
				goto out;
			}
			if (resultp)
				free_result(resultp);
		} else {
			i = 0;
			while (i < c.c_dbcnt) {
				char	*devname;

				c.c_id = i;

				/* Don't need devid info from this ioctl */
				c.c_locator.l_devid = (uint64_t)0;
				c.c_locator.l_devid_flags = 0;

				if (metaioctl(MD_DB_GETDEV, &c,
				    &c.c_mde, NULL)) {
					rval = mdstealerror(ep, &c.c_mde);
					goto out;
				}

				devname = splicename(&c.c_devname);

				if (strstr(devname, META_LONGDISKNAME_STR)
				    != NULL) {
					Free(devname);
					devname = getlongname(&c, ep);
					if (devname == NULL) {
						return (-1);
					}
				}

				if (strcmp(devname, np->bname) != 0) {
					Free(devname);
					i++;
					continue;
				}
				Free(devname);

				/* Don't need devid info from this ioctl */
				c.c_locator.l_devid = (uint64_t)0;
				c.c_locator.l_devid_flags = 0;

				if (metaioctl(MD_DB_DELDEV, &c,
				    &c.c_mde, NULL) != 0) {
					rval = mdstealerror(ep, &c.c_mde);
					goto out;
				}

				/* Not incrementing "i" intentionally */
			}
		}
		if (! metaislocalset(sp)) {
			/* update the dbcnt and size in dd */
			for (p = dd; p != NULL; p = p->dd_next) {
				if (p->dd_dnp == np->drivenamep) {
					p->dd_dbcnt = 0;
					p->dd_dbsize  = 0;
					break;
				}
			}

			/*
			 * Slam a dummy master block and make it self
			 * identifying
			 */
			if ((fd = open(np->rname, O_RDWR)) >= 0) {
				meta_mkdummymaster(sp, fd, 16);
				(void) close(fd);
			}
		}
	}
out:
	if (metaislocalset(sp)) {
		/*
		 * Stop all the daemons if there are
		 * no more replicas so that the module can be
		 * unloaded.
		 */
		if (rval == 0 && stop_svmdaemons == 1) {
			char buf[MAXPATHLEN];
			int i;

			for (i = 0; i < DAEMON_COUNT; i++) {
				(void) snprintf(buf, MAXPATHLEN,
				    "/usr/bin/pkill -%s -x %s",
				    svmd_kill_list[i].svmd_kill_val,
				    svmd_kill_list[i].svmd_name);
				if (pclose(popen(buf, "w")) == -1)
					md_perror(buf);
			}

			if (meta_smf_disable(META_SMF_ALL, &status) == -1) {
				mde_perror(&status, "");
				mdclrerror(&status);
			}
		}
		if (buildconf(sp, &status)) {
			/* Don't mask any previous errors */
			if (rval == 0)
				rval = mdstealerror(ep, &status);
			else
				mdclrerror(&status);
			return (rval);
		}

		if (meta_db_patch(sysfilename, NULL, 0, &status)) {
			/* Don't mask any previous errors */
			if (rval == 0)
				rval = mdstealerror(ep, &status);
			else
				mdclrerror(&status);
		}
	} else {
		if (update_dbinfo_on_drives(sp, dd,
		    (force_option & MDFORCE_SET_LOCKED),
		    ((force_option & MDFORCE_LOCAL) |
		    (force_option & MDFORCE_DS)), &status)) {
			/* Don't mask any previous errors */
			if (rval == 0)
				rval = mdstealerror(ep, &status);
			else
				mdclrerror(&status);
		}
		metafreedrivedesc(&dd);
	}
	if ((metaislocalset(sp)) || (!(MD_MNSET_DESC(sd)))) {
		for (nlp = db_nlp; (nlp != NULL); nlp = nlp->next) {
			meta_invalidate_name(nlp->namep);
		}
	}
	return (rval);
}

static md_replica_t *
metareplicaname(
	mdsetname_t		*sp,
	int			flags,
	struct mddb_config	*c,
	md_error_t		*ep
)
{
	md_replica_t	*rp;
	char		*devname;
	size_t		sz;
	devid_nmlist_t	*disklist = NULL;
	char		*devid_str;

	/* allocate replicaname */
	rp = Zalloc(sizeof (*rp));

	/* get device name */
	devname = splicename(&c->c_devname);

	/*
	 * Check if the device has a long name (>40 characters) and
	 * if so then we have to use devids to get the device name.
	 * If this cannot be done then we have to fail the request.
	 */
	if (strstr(devname, META_LONGDISKNAME_STR) != NULL) {
		if (c->c_locator.l_devid != NULL) {
			if (meta_deviceid_to_nmlist("/dev/dsk",
			    (ddi_devid_t)(uintptr_t)c->c_locator.l_devid,
			    c->c_locator.l_minor_name, &disklist) != 0) {
				devid_str = devid_str_encode(
				    (ddi_devid_t)(uintptr_t)
				    c->c_locator.l_devid, NULL);
				(void) mderror(ep, MDE_MISSING_DEVID_DISK, "");
				mderrorextra(ep, devid_str);
				if (devid_str != NULL)
					devid_str_free(devid_str);
				Free(rp);
				Free(devname);
				return (NULL);
			}
		} else {
			(void) mderror(ep, MDE_NODEVID, "");
			Free(rp);
			Free(devname);
			return (NULL);
		}
		Free(devname);
		devname = disklist[0].devname;
	}

	if (flags & PRINT_FAST) {
		if ((rp->r_namep = metaname_fast(&sp, devname,
		    LOGICAL_DEVICE, ep)) == NULL) {
			Free(devname);
			Free(rp);
			return (NULL);
		}
	} else {
		if ((rp->r_namep = metaname(&sp, devname,
		    LOGICAL_DEVICE, ep)) == NULL) {
			Free(devname);
			Free(rp);
			return (NULL);
		}
	}
	Free(devname);

	/* make sure it's OK */
	if ((! (flags & MD_BASICNAME_OK)) &&
	    (metachkcomp(rp->r_namep, ep) != 0)) {
		Free(rp);
		return (NULL);
	}

	rp->r_blkno = (daddr_t)MD_DISKADDR_ERROR;
	rp->r_nblk = (daddr_t)MD_DISKADDR_ERROR;
	rp->r_flags = c->c_locator.l_flags | MDDB_F_NODEVID;
	if (c->c_locator.l_devid_flags & MDDB_DEVID_VALID) {
		sz = devid_sizeof((ddi_devid_t)(uintptr_t)
		    (c->c_locator.l_devid));
		if ((rp->r_devid = (ddi_devid_t)malloc(sz)) ==
		    (ddi_devid_t)NULL) {
			Free(rp);
			return (NULL);
		}
		(void) memcpy((void *)rp->r_devid,
		    (void *)(uintptr_t)c->c_locator.l_devid, sz);
		(void) strcpy(rp->r_minor_name, c->c_locator.l_minor_name);
		rp->r_flags &= ~MDDB_F_NODEVID;
		/* Overwrite dev derived from name with dev from devid */
		rp->r_namep->dev = meta_expldev(c->c_locator.l_dev);
	}
	(void) strcpy(rp->r_driver_name, c->c_locator.l_driver);

	rp->r_blkno = c->c_locator.l_blkno;
	if (c->c_dbend != 0)
		rp->r_nblk = c->c_dbend - c->c_locator.l_blkno + 1;

	/* return replica */
	return (rp);
}

/*
 * free replica list
 */
void
metafreereplicalist(
	md_replicalist_t	*rlp
)
{
	md_replicalist_t	*rl = NULL;

	for (/* void */; (rlp != NULL); rlp = rl) {
		rl = rlp->rl_next;
		if (rlp->rl_repp->r_devid != (ddi_devid_t)0) {
			free(rlp->rl_repp->r_devid);
		}
		Free(rlp->rl_repp);
		Free(rlp);
	}
}

/*
 * return list of all replicas in set
 */
int
metareplicalist(
	mdsetname_t		*sp,
	int			flags,
	md_replicalist_t	**rlpp,
	md_error_t		*ep
)
{
	md_replicalist_t	**tail = rlpp;
	int			count = 0;
	struct mddb_config	c;
	int			i;
	char			*devid;

	/* for each replica */
	i = 0;
	do {
		md_replica_t	*rp;

		/* get next replica */
		(void) memset(&c, 0, sizeof (c));
		c.c_id = i;
		c.c_setno = sp->setno;

		c.c_locator.l_devid_flags = MDDB_DEVID_GETSZ;
		if (metaioctl(MD_DB_ENDDEV, &c, &c.c_mde, NULL) != 0) {
			if (mdismddberror(&c.c_mde, MDE_DB_INVALID)) {
				mdclrerror(&c.c_mde);
				break;	/* handle none at all */
			}
			(void) mdstealerror(ep, &c.c_mde);
			goto out;
		}

		if (c.c_locator.l_devid_flags & MDDB_DEVID_SZ) {
			if ((devid = malloc(c.c_locator.l_devid_sz)) == NULL) {
				(void) mdsyserror(ep, ENOMEM, META_DBCONF);
				goto out;
			}
			c.c_locator.l_devid = (uintptr_t)devid;
			/*
			 * Turn on space and sz flags since 'sz' amount of
			 * space has been alloc'd.
			 */
			c.c_locator.l_devid_flags =
			    MDDB_DEVID_SPACE | MDDB_DEVID_SZ;
		}

		if (metaioctl(MD_DB_ENDDEV, &c, &c.c_mde, NULL) != 0) {
			if (mdismddberror(&c.c_mde, MDE_DB_INVALID)) {
				mdclrerror(&c.c_mde);
				break;	/* handle none at all */
			}
			(void) mdstealerror(ep, &c.c_mde);
			goto out;
		}

		/*
		 * Paranoid check - shouldn't happen, but is left as
		 * a place holder for changes that will be needed after
		 * dynamic reconfiguration changes are added to SVM (to
		 * support movement of disks at any point in time).
		 */
		if (c.c_locator.l_devid_flags & MDDB_DEVID_NOSPACE) {
			(void) fprintf(stderr,
			    dgettext(TEXT_DOMAIN,
			    "Error: Relocation Information "
			    "(drvnm=%s, mnum=0x%lx) \n"
			    "relocation information size changed - \n"
			    "rerun command\n"),
			    c.c_locator.l_driver, c.c_locator.l_mnum);
			(void) mderror(ep, MDE_DEVID_TOOBIG, NULL);
			goto out;
		}

		if (c.c_dbcnt == 0)
			break;		/* handle none at all */

		/* get info */
		if ((rp = metareplicaname(sp, flags, &c, ep)) == NULL)
			goto out;

		/* append to list */
		*tail = Zalloc(sizeof (**tail));
		(*tail)->rl_repp = rp;
		tail = &(*tail)->rl_next;
		++count;

		if (c.c_locator.l_devid_flags & MDDB_DEVID_SPACE) {
			free(devid);
			c.c_locator.l_devid_flags = 0;
		}

	} while (++i < c.c_dbcnt);

	if (c.c_locator.l_devid_flags & MDDB_DEVID_SPACE) {
		free(devid);
	}

	/* return count */
	return (count);

	/* cleanup, return error */
out:
	if (c.c_locator.l_devid_flags & MDDB_DEVID_SPACE) {
		free(devid);
	}
	metafreereplicalist(*rlpp);
	*rlpp = NULL;
	return (-1);
}

/*
 * meta_sync_db_locations - get list of replicas from kernel and write
 * 	out to mddb.cf and md.conf.  'Syncs up' the replica list in
 * 	the kernel with the replica list in the conf files.
 *
 */
void
meta_sync_db_locations(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	char		*sname = 0;		/* system file name */
	char 		*cname = 0;		/* config file name */

	if (!metaislocalset(sp))
		return;

	/* Updates backup of configuration file (aka mddb.cf) */
	if (buildconf(sp, ep) != 0)
		return;

	/* Updates system configuration file (aka md.conf) */
	(void) meta_db_patch(sname, cname, 0, ep);
}

/*
 * setup_db_locations - parse the mddb.cf file and
 *			tells the driver which db locations to use.
 */
int
meta_setup_db_locations(
	md_error_t	*ep
)
{
	mddb_config_t	c;
	FILE		*fp;
	char		inbuff[1024];
	char		*buff;
	uint_t		i;
	size_t		sz;
	int		rval = 0;
	char		*devidp;
	uint_t		devid_size;
	char		*minor_name = NULL;
	ddi_devid_t	devid_decode;
	int		checksum;

	/* do mddb.cf file */
	(void) memset(&c, '\0', sizeof (c));
	if ((fp = fopen(META_DBCONF, "r")) == NULL) {
		if (errno != ENOENT)
			return (mdsyserror(ep, errno, META_DBCONF));
	}
	while ((fp != NULL) && ((buff = fgets(inbuff, (sizeof (inbuff) - 1),
	    fp)) != NULL)) {

		/* ignore comments */
		if (*buff == '#')
			continue;

		/* parse locator */
		(void) memset(&c, 0, sizeof (c));
		c.c_setno = MD_LOCAL_SET;
		i = strcspn(buff, " \t");
		if (i > sizeof (c.c_locator.l_driver))
			i = sizeof (c.c_locator.l_driver);
		(void) strncpy(c.c_locator.l_driver, buff, i);
		buff += i;
		c.c_locator.l_dev =
		    makedev((major_t)0, (minor_t)strtol(buff, &buff, 10));
		c.c_locator.l_blkno = (daddr_t)strtol(buff, &buff, 10);
		c.c_locator.l_mnum = minor(c.c_locator.l_dev);

		/* parse out devid */
		while (isspace((int)(*buff)))
			buff += 1;
		i = strcspn(buff, " \t");
		if ((devidp = (char *)malloc(i+1)) == NULL)
			return (mdsyserror(ep, ENOMEM, META_DBCONF));

		(void) strncpy(devidp, buff, i);
		devidp[i] = '\0';
		if (devid_str_decode(devidp, &devid_decode,
		    &minor_name) == -1) {
			free(devidp);
			continue;
		}

		/* Conf file must have minor name associated with devid */
		if (minor_name == NULL) {
			free(devidp);
			devid_free(devid_decode);
			continue;
		}

		sz = devid_sizeof(devid_decode);
		/* Copy to devid size buffer that ioctl expects */
		if ((c.c_locator.l_devid = (uintptr_t)malloc(sz)) == NULL) {
			devid_free(devid_decode);
			free(minor_name);
			free(devidp);
			return (mdsyserror(ep, ENOMEM, META_DBCONF));
		}

		(void) memcpy((void *)(uintptr_t)c.c_locator.l_devid,
		    (void *)devid_decode, sz);

		devid_free(devid_decode);

		if (strlen(minor_name) > MDDB_MINOR_NAME_MAX) {
			free(minor_name);
			free(devidp);
			free((void *)(uintptr_t)c.c_locator.l_devid);
			return (mdsyserror(ep, ENOMEM, META_DBCONF));
		}
		(void) strcpy(c.c_locator.l_minor_name, minor_name);
		free(minor_name);
		c.c_locator.l_devid_flags = MDDB_DEVID_VALID |
		    MDDB_DEVID_SPACE | MDDB_DEVID_SZ;
		c.c_locator.l_devid_sz = sz;

		devid_size = strlen(devidp);
		buff += devid_size;

		checksum = strtol(buff, &buff, 10);
		for (i = 0; c.c_locator.l_driver[i] != 0; i++)
			checksum += c.c_locator.l_driver[i];
		for (i = 0; i < devid_size; i++) {
			checksum += devidp[i];
		}
		free(devidp);

		checksum += minor(c.c_locator.l_dev);
		checksum += c.c_locator.l_blkno;
		if (checksum != 42) {
			/* overwritten later for more serious problems */
			rval = mderror(ep, MDE_MDDB_CKSUM, META_DBCONF);
			free((void *)(uintptr_t)c.c_locator.l_devid);
			continue;
		}
		c.c_locator.l_flags = 0;

		/* use db location */
		if (metaioctl(MD_DB_USEDEV, &c, &c.c_mde, NULL) != 0) {
			free((void *)(uintptr_t)c.c_locator.l_devid);
			return (mdstealerror(ep, &c.c_mde));
		}

		/* free up devid if in use */
		free((void *)(uintptr_t)c.c_locator.l_devid);
		c.c_locator.l_devid = (uint64_t)0;
		c.c_locator.l_devid_flags = 0;
	}
	if ((fp) && (fclose(fp) != 0))
		return (mdsyserror(ep, errno, META_DBCONF));

	/* check for stale database */
	(void) memset((char *)&c, 0, sizeof (struct mddb_config));
	c.c_id = 0;
	c.c_setno = MD_LOCAL_SET;

	/*
	 * While we do not need the devid here we may need to
	 * know if devid's are being used by the kernel for
	 * the replicas. This is because under some circumstances
	 * we can only manipulate the SVM configuration if the
	 * kernel is using devid's.
	 */
	c.c_locator.l_devid = (uint64_t)0;
	c.c_locator.l_devid_flags = MDDB_DEVID_GETSZ;
	c.c_locator.l_devid_sz = 0;

	if (metaioctl(MD_DB_GETDEV, &c, &c.c_mde, NULL) != 0) {
		if (! mdismddberror(&c.c_mde, MDE_DB_INVALID))
			return (mdstealerror(ep, &c.c_mde));
		mdclrerror(&c.c_mde);
	}

	if (c.c_flags & MDDB_C_STALE)
		return (mdmddberror(ep, MDE_DB_STALE, NODEV32, MD_LOCAL_SET,
		    0, NULL));

	if (c.c_locator.l_devid_sz != 0) {
		/*
		 * Devid's are being used to track the replicas because
		 * there is space for a devid.
		 */
		devid_in_use = TRUE;
	}

	/* success */
	return (rval);
}

/*
 * meta_db_minreplica - returns the minimum size replica currently in use.
 */
daddr_t
meta_db_minreplica(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	md_replica_t		*r;
	md_replicalist_t	*rl, *rlp = NULL;
	daddr_t			nblks = 0;

	if (metareplicalist(sp, (MD_BASICNAME_OK | PRINT_FAST), &rlp, ep) < 0)
		return (-1);

	if (rlp == NULL)
		return (-1);

	/* find the smallest existing replica */
	for (rl = rlp; rl != NULL; rl = rl->rl_next) {
		r = rl->rl_repp;
		nblks = ((nblks == 0) ? r->r_nblk : min(r->r_nblk, nblks));
	}

	metafreereplicalist(rlp);
	return (nblks);
}

/*
 * meta_get_replica_names
 *  returns an mdnamelist_t of replica slices
 */
/*ARGSUSED*/
int
meta_get_replica_names(
	mdsetname_t	*sp,
	mdnamelist_t	**nlpp,
	int		options,
	md_error_t	*ep
)
{
	md_replicalist_t	*rlp = NULL;
	md_replicalist_t	*rl;
	mdnamelist_t		**tailpp = nlpp;
	int			cnt = 0;

	assert(nlpp != NULL);

	if (!metaislocalset(sp))
		goto out;

	/* get replicas */
	if (metareplicalist(sp, MD_BASICNAME_OK, &rlp, ep) < 0) {
		cnt = -1;
		goto out;
	}

	/* build name list */
	for (rl = rlp; (rl != NULL); rl = rl->rl_next) {
		/*
		 * Add the name struct to the end of the
		 * namelist but keep a pointer to the last
		 * element so that we don't incur the overhead
		 * of traversing the list each time
		 */
		tailpp = meta_namelist_append_wrapper(
		    tailpp, rl->rl_repp->r_namep);
		++cnt;
	}

	/* cleanup, return count or error */
out:
	metafreereplicalist(rlp);
	return (cnt);
}
