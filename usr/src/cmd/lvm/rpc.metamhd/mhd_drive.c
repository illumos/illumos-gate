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

#include "mhd_local.h"

#include <ftw.h>
#include <libgen.h>
#include <sys/mhd.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/generic/inquiry.h>

/*
 * manipulate drives
 */

/*
 * null list constant
 */
const mhd_drive_list_t	mhd_null_list = MHD_NULL_LIST;

/*
 * add drive to list
 */
void
mhd_add_drive(
	mhd_drive_list_t	*dlp,
	mhd_drive_t		*dp
)
{
	/* add drive to list */
	if (dlp->dl_ndrive >= dlp->dl_alloc) {
		dlp->dl_alloc += 10;
		dlp->dl_drives = Realloc(dlp->dl_drives,
		    (dlp->dl_alloc * sizeof (*dlp->dl_drives)));
	}
	dlp->dl_drives[dlp->dl_ndrive++] = dp;
}

/*
 * delete drive from list
 */
void
mhd_del_drive(
	mhd_drive_list_t	*dlp,
	mhd_drive_t		*dp
)
{
	uint_t			i;

	/* delete drive from list */
	for (i = 0; (i < dlp->dl_ndrive); ++i) {
		if (dlp->dl_drives[i] == dp)
			break;
	}
	assert(dlp->dl_drives[i] == dp);
	for (/* void */; (i < dlp->dl_ndrive); ++i)
		dlp->dl_drives[i] = dlp->dl_drives[i + 1];
	dlp->dl_ndrive--;
}

/*
 * free drive list
 */
void
mhd_free_list(
	mhd_drive_list_t	*dlp
)
{
	if (dlp->dl_drives != NULL)
		Free(dlp->dl_drives);
	(void) memset(dlp, 0, sizeof (*dlp));
}

/*
 * manipulate drive state
 */
int
mhd_state(
	mhd_drive_t	*dp,
	mhd_state_t	new_state,
	mhd_error_t	*mhep
)
{
	mhd_drive_set_t	*sp = dp->dr_sp;
	mhd_state_t	old_state = dp->dr_state;

	/* check lock */
	assert(MUTEX_HELD(&sp->sr_mx));

	/* set state and kick thread */
	MHDPRINTF2(("%s: state 0x%x now 0x%x\n",
	    dp->dr_rname, dp->dr_state, new_state));
	dp->dr_state = new_state;
	mhd_cv_broadcast(&dp->dr_cv);

	/* if this is the last PROBING drive, disable any failfast */
	if ((old_state & DRIVE_PROBING) && (! (new_state & DRIVE_PROBING))) {
		mhd_drive_list_t	*dlp = &sp->sr_drives;
		uint_t			cnt, i;

		for (cnt = 0, i = 0; (i < dlp->dl_ndrive); ++i) {
			if (dlp->dl_drives[i]->dr_state & DRIVE_PROBING)
				++cnt;
		}
		if (cnt == 0) {
			mhd_error_t	status = mhd_null_error;

			if (mhep == NULL)
				mhep = &status;
			if (mhd_ff_disarm(sp, mhep) != 0) {
				if (mhep == &status) {
					mhde_perror(mhep, dp->dr_rname);
					mhd_clrerror(mhep);
				}
				return (-1);
			}
		}
	}

	/* return success */
	return (0);
}

int
mhd_state_set(
	mhd_drive_t	*dp,
	mhd_state_t	new_state,
	mhd_error_t	*mhep
)
{
	return (mhd_state(dp, (dp->dr_state | new_state), mhep));
}

static int
mhd_state_clr(
	mhd_drive_t	*dp,
	mhd_state_t	new_state,
	mhd_error_t	*mhep
)
{
	return (mhd_state(dp, (dp->dr_state & ~new_state), mhep));
}

/*
 * idle a drive
 */
int
mhd_idle(
	mhd_drive_t		*dp,
	mhd_error_t		*mhep
)
{
	mhd_drive_set_t		*sp = dp->dr_sp;

	/* check lock */
	assert(MUTEX_HELD(&sp->sr_mx));

	/* wait for thread to idle */
	for (;;) {
		if (DRIVE_IS_IDLE(dp))
			return (0);
		if (mhd_state(dp, DRIVE_IDLING, mhep) != 0)
			return (-1);
		(void) mhd_cv_wait(&sp->sr_cv, &sp->sr_mx);
	}
}

/*
 * reserve the drive
 */
static int
mhd_reserve(
	mhd_drive_t		*dp
)
{
	mhd_drive_set_t		*sp = dp->dr_sp;
	int			serial = (sp->sr_options & MHD_SERIAL);
	mhd_mhioctkown_t	*tkp = &sp->sr_timeouts.mh_tk;
	struct mhioctkown	tkown;
	int			err;

	/* check locks */
	assert(MUTEX_HELD(&sp->sr_mx));
	assert(dp->dr_fd >= 0);
	assert(dp->dr_state == DRIVE_RESERVING);

	/* setup timeouts */
	(void) memset(&tkown, 0, sizeof (tkown));
	tkown.reinstate_resv_delay = tkp->reinstate_resv_delay;
	tkown.min_ownership_delay = tkp->min_ownership_delay;
	tkown.max_ownership_delay = tkp->max_ownership_delay;

	/* reserve drive */
	if (! serial)
		mhd_mx_unlock(&sp->sr_mx);
	err = ioctl(dp->dr_fd, MHIOCTKOWN, &tkown);
	if (! serial)
		mhd_mx_lock(&sp->sr_mx);
	if (err != 0) {
		mhd_perror("%s: MHIOCTKOWN", dp->dr_rname);
		(void) mhd_state(dp, DRIVE_ERRORED, NULL);
		dp->dr_errnum = errno;
		return (-1);
	}

	/* return success */
	MHDPRINTF(("%s: MHIOCTKOWN: succeeded\n", dp->dr_rname));
	(void) mhd_state(dp, DRIVE_IDLE, NULL);
	return (0);
}

/*
 * failfast the drive
 */
static int
mhd_failfast(
	mhd_drive_t	*dp
)
{
	mhd_drive_set_t	*sp = dp->dr_sp;
	int		serial = (sp->sr_options & MHD_SERIAL);
	int		ff = sp->sr_timeouts.mh_ff;
	char		*release = ((ff == 0) ? " (release)" : "");
	int		err;

	/* check locks */
	assert(MUTEX_HELD(&sp->sr_mx));
	assert(dp->dr_fd >= 0);
	assert(dp->dr_state == DRIVE_FAILFASTING);

	/* failfast drive */
	if (! serial)
		mhd_mx_unlock(&sp->sr_mx);
	err = ioctl(dp->dr_fd, MHIOCENFAILFAST, &ff);
	if (! serial)
		mhd_mx_lock(&sp->sr_mx);
	if (err != 0) {
		mhd_perror("%s: MHIOCENFAILFAST%s", dp->dr_rname, release);
		(void) mhd_state(dp, DRIVE_ERRORED, NULL);
		dp->dr_errnum = errno;
		return (-1);
	}

	/* return success */
	MHDPRINTF(("%s: MHIOCENFAILFAST%s: succeeded\n",
	    dp->dr_rname, release));
	(void) mhd_state(dp, DRIVE_IDLE, NULL);
	return (0);
}

/*
 * release the drive
 */
static int
mhd_release(
	mhd_drive_t	*dp
)
{
	mhd_drive_set_t	*sp = dp->dr_sp;
	int		serial = (sp->sr_options & MHD_SERIAL);
	int		ff = 0;	/* disable failfast */
	int		err;

	/* check locks */
	assert(MUTEX_HELD(&sp->sr_mx));
	assert(dp->dr_fd >= 0);
	assert(dp->dr_state == DRIVE_RELEASING);

	/* disable failfast */
	if (! serial)
		mhd_mx_unlock(&sp->sr_mx);
	err = ioctl(dp->dr_fd, MHIOCENFAILFAST, &ff);
	if (! serial)
		mhd_mx_lock(&sp->sr_mx);
	if (err != 0) {
		mhd_perror("%s: MHIOCENFAILFAST (release)", dp->dr_rname);
		(void) mhd_state(dp, DRIVE_ERRORED, NULL);
		dp->dr_errnum = errno;
		return (-1);
	}
	MHDPRINTF(("%s: MHIOCENFAILFAST (release): succeeded\n",
	    dp->dr_rname));

	/* release drive */
	if (! serial)
		mhd_mx_unlock(&sp->sr_mx);
	err = ioctl(dp->dr_fd, MHIOCRELEASE, NULL);
	if (! serial)
		mhd_mx_lock(&sp->sr_mx);
	if (err != 0) {
		mhd_perror("%s: MHIOCRELEASE", dp->dr_rname);
		(void) mhd_state(dp, DRIVE_ERRORED, NULL);
		dp->dr_errnum = errno;
		return (-1);
	}

	/* return success */
	MHDPRINTF(("%s: MHIOCRELEASE: succeeded\n", dp->dr_rname));
	(void) mhd_state(dp, DRIVE_IDLE, NULL);
	return (0);
}

/*
 * probe the drive
 */
static int
mhd_probe(
	mhd_drive_t	*dp
)
{
	mhd_drive_set_t	*sp = dp->dr_sp;
	int		serial = (sp->sr_options & MHD_SERIAL);
	int		err;
	mhd_msec_t	now;

	/* check locks */
	assert(MUTEX_HELD(&sp->sr_mx));
	assert(dp->dr_fd >= 0);
	assert(dp->dr_state & (DRIVE_PROBING | DRIVE_STATUSING));

	/* get status (we may get dumped from PROBING here) */
	if (! serial)
		mhd_mx_unlock(&sp->sr_mx);
	err = ioctl(dp->dr_fd, MHIOCSTATUS, NULL);
	now = mhd_time();
	if (! serial)
		mhd_mx_lock(&sp->sr_mx);
	if (! (dp->dr_state & (DRIVE_PROBING | DRIVE_STATUSING)))
		return (0);

	/* update status */
	if (dp->dr_state & DRIVE_STATUSING) {
		if (err == 1) {
			MHDPRINTF(("%s: MHIOCSTATUS: reserved\n",
			    dp->dr_rname));
			dp->dr_errnum = MHD_E_RESERVED;
		} else if (err != 0) {
			mhd_perror("%s: MHIOCSTATUS", dp->dr_rname);
			dp->dr_errnum = errno;
		} else {
			MHDPRINTF(("%s: MHIOCSTATUS: available\n",
			    dp->dr_rname));
			dp->dr_errnum = 0;
		}
		(void) mhd_state_clr(dp, DRIVE_STATUSING, NULL);
	}

	/* update time or die */
	if (dp->dr_state & DRIVE_PROBING) {
		/* check our drive */
		if (err == 0) {
			dp->dr_time = now;
		} else if (err == 1) {
			mhd_eprintf("%s: %s: reservation conflict\n",
			    sp->sr_name, dp->dr_rname);
			mhd_ff_die(sp);
		}

		/* check other drives */
		mhd_ff_check(sp);
	}

	/* return success */
	return (0);
}

/*
 * cached controller map
 */
typedef struct {
	char	*regexpr1;
	uint_t	tray;
	uint_t	bus;
	char	*regexpr2;
	char	*scan;
} mhd_ctlrmap_t;

static	rwlock_t	ctlr_rw = DEFAULTRWLOCK;
static	time_t		ctlr_mtime = 0;
static	size_t		ctlr_num = 0;
static	mhd_ctlrmap_t	*ctlr_map = NULL;

/*
 * free up controller map
 */
static void
free_map()
{
	size_t		i;

	assert(RW_WRITE_HELD(&ctlr_rw));

	for (i = 0; (i < ctlr_num); ++i) {
		mhd_ctlrmap_t	*cmp  = &ctlr_map[i];

		if (cmp->regexpr1 != NULL)
			Free(cmp->regexpr1);
		if (cmp->regexpr2 != NULL)
			Free(cmp->regexpr2);
		if (cmp->scan != NULL)
			Free(cmp->scan);
	}
	if (ctlr_map != NULL)
		Free(ctlr_map);
	ctlr_num = 0;
	ctlr_map = NULL;
}

/*
 * unlock controller map
 */
static void
unlock_map()
{
	assert(RW_WRITE_HELD(&ctlr_rw) | RW_READ_HELD(&ctlr_rw));

	mhd_rw_unlock(&ctlr_rw);
}

/*
 * update controller map and lock it
 */
static int
update_map()
{
	struct stat	statbuf;
	FILE		*fp;
	char		line[256], expr1[256], expr2[256], scan[256];
	unsigned	tray, bus;
	int		rval = -1;

	/* see if map file has changed */
	mhd_rw_rdlock(&ctlr_rw);
	if (stat(METACTLRMAP, &statbuf) != 0) {
		mhd_perror(METACTLRMAP);
		goto out;
	}
	if (statbuf.st_mtime == ctlr_mtime) {
		rval = 0;
		goto out;
	}

	/* trade up to writer lock, check again */
	mhd_rw_unlock(&ctlr_rw);
	mhd_rw_wrlock(&ctlr_rw);
	if (statbuf.st_mtime == ctlr_mtime) {
		rval = 0;
		goto out;
	}
	if (ctlr_mtime != 0)
		mhd_eprintf("updating controller map\n");
	ctlr_mtime = statbuf.st_mtime;

	/* toss existing cache */
	free_map();

	/* parse md.ctlrmap */
	if ((fp = fopen(METACTLRMAP, "r")) == NULL) {
		mhd_perror(METACTLRMAP);
		goto out;
	}
	clearerr(fp);
	while (fgets(line, sizeof (line), fp) != NULL) {
		char		*regexpr1 = NULL;
		char		*regexpr2 = NULL;
		mhd_ctlrmap_t	*cmp;

		/* skip blank lines and comments */
		if ((line[0] == '\0') || (line[0] == '\n') || (line[0] == '#'))
			continue;

		/* parse line */
		if (((sscanf(line, "\"%[^\"]\" %u %u \"%[^\"]\" \"%[^\"]\"",
		    expr1, &tray, &bus, expr2, scan)) != 5) ||
		    ((regexpr1 = regcmp(expr1, 0)) == NULL) ||
		    ((regexpr2 = regcmp(expr2, 0)) == NULL)) {
			mhd_eprintf("%s: bad regex(es) '%s'\n",
			    METACTLRMAP, line);
			if (regexpr1 != NULL)
				Free(regexpr1);
			if (regexpr2 != NULL)
				Free(regexpr2);
			continue;
		}

		/* add to cache */
		ctlr_map = Realloc(ctlr_map,
		    ((ctlr_num + 1) * sizeof (*ctlr_map)));
		cmp = &ctlr_map[ctlr_num++];
		cmp->regexpr1 = regexpr1;
		cmp->tray = tray;
		cmp->bus = bus;
		cmp->regexpr2 = regexpr2;
		cmp->scan = Strdup(scan);
	}
	if (ferror(fp)) {
		mhd_perror(METACTLRMAP);
		(void) fclose(fp);
		goto out;
	}
	if (fclose(fp) != 0) {
		mhd_perror(METACTLRMAP);
		goto out;
	}

	/* success */
	rval = 0;

	/* return success */
out:
	if (rval != 0) {
		mhd_rw_unlock(&ctlr_rw);
		return (-1);
	}
	return (0);
}

static char *
get_pln_ctlr_name(
	char	*path
)
{
	char	*devicesname, *p;
	char	retval[MAXPATHLEN];

	devicesname = Strdup(path);
	if ((p = strrchr(devicesname, '/')) == NULL) {
		Free(devicesname);
		return (NULL);
	}

	/* strip off the "ssd@..." portion of the devices name */
	*p = '\0';

	/* strip off the "../../" in front of "devices" */
	if ((p = strstr(devicesname, "/devices/")) == NULL) {
		Free(devicesname);
		return (NULL);
	}

	(void) snprintf(retval, sizeof (retval), "%s:ctlr", p);
	Free(devicesname);
	return (Strdup(retval));
}

struct pln_cache {
	char			*pln_name;
	enum mhd_ctlrtype_t	ctype;
	struct pln_cache	*next;
};

static struct pln_cache	*pln_cache_anchor = NULL;
static mutex_t		mhd_pln_mx = DEFAULTMUTEX;

/* singled threaded by caller */
static void
add_pln_cache(
	char			*pln_name,
	enum mhd_ctlrtype_t	ctype

)
{
	struct pln_cache	*p;

	p = Malloc(sizeof (*p));

	p->pln_name = pln_name;
	p->ctype = ctype;
	p->next = pln_cache_anchor;
	pln_cache_anchor = p;
}

/* singled threaded by caller */
static int
find_pln_cache(
	char 			*pln_name,
	enum mhd_ctlrtype_t	*ctype_ret
)
{
	struct pln_cache	*p;

	for (p = pln_cache_anchor; p != NULL; p = p->next) {
		if (strcmp(pln_name, p->pln_name) == 0) {
			*ctype_ret = p->ctype;
			return (1);
		}
	}
	return (0);
}

static void
free_pln_cache(void)
{
	struct pln_cache	*p, *n = NULL;

	mutex_lock(&mhd_pln_mx);
	for (p = pln_cache_anchor; p != NULL; p = n) {
		n = p->next;
		Free(p->pln_name);
		Free(p);
	}

	pln_cache_anchor = NULL;
	mutex_unlock(&mhd_pln_mx);
}

/*
 * match on SSA Model 200.
 */
static void
match_SSA200(
	mhd_drive_t	*dp,
	char		*path
)
{
	mhd_cinfo_t		*cinfop = &dp->dr_drive_id.did_cinfo;
	struct uscsi_cmd	ucmd;
	union scsi_cdb		cdb;
	struct scsi_inquiry	inq;
	int			fd;
	char			*pln_ctlr_name;
	enum mhd_ctlrtype_t	ctype;
	char			*p;

	if ((pln_ctlr_name = get_pln_ctlr_name(path)) == NULL)
		return;

	mutex_lock(&mhd_pln_mx);
	if (find_pln_cache(pln_ctlr_name, &ctype) == 1) {
		mutex_unlock(&mhd_pln_mx);
		if (ctype != MHD_CTLR_SSA200)
			return;

		/* over-ride for SSA200 */
		cinfop->mhc_ctype = ctype;
		cinfop->mhc_tray = cinfop->mhc_bus;
		return;
	}

	if ((fd = open(pln_ctlr_name, (O_RDONLY|O_NDELAY), 0)) < 0) {
		mutex_unlock(&mhd_pln_mx);
		Free(pln_ctlr_name);
		return;
	}

	(void) memset(&ucmd, 0, sizeof (ucmd));
	(void) memset(&cdb, 0, sizeof (cdb));
	(void) memset(&inq, 0, sizeof (inq));
	cdb.scc_cmd = SCMD_INQUIRY;
	cdb.g0_count0 = sizeof (inq);
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = (caddr_t)&inq;
	ucmd.uscsi_buflen = sizeof (inq);
	ucmd.uscsi_flags = USCSI_READ | USCSI_ISOLATE | USCSI_DIAGNOSE;
	ucmd.uscsi_timeout = 30;
	if (ioctl(fd, USCSICMD, &ucmd)) {
		mutex_unlock(&mhd_pln_mx);
		(void) close(fd);
		MHDPRINTF(("%s: USCSICMD(SCMD_INQUIRY): failed errno %d\n",
		    pln_ctlr_name, errno));
		Free(pln_ctlr_name);
		return;
	}

	(void) close(fd);
	MHDPRINTF(("%s: USCSICMD(SCMD_INQUIRY): success\n", pln_ctlr_name));

	/* Make all trailing spaces be null char */
	for (p = inq.inq_pid + sizeof (inq.inq_pid) - 1; p != inq.inq_pid;
	    p--) {
		if (*p == '\0')
			continue;
		if (!isspace(*p))
			break;
		*p = '\0';
	}

	if (strncmp(inq.inq_pid, META_SSA200_PID, sizeof (inq.inq_pid)) != 0)
		goto out;

	/* over-ride the ctype, and tray */
	cinfop->mhc_ctype = MHD_CTLR_SSA200;
	cinfop->mhc_tray = cinfop->mhc_bus;

out:
	add_pln_cache(pln_ctlr_name, cinfop->mhc_ctype);
	mutex_unlock(&mhd_pln_mx);
}

/*
 * get controller info
 */
static void
match_SSA100(
	mhd_drive_t	*dp,
	char		*path
)
{
	mhd_cinfo_t	*cinfop = &dp->dr_drive_id.did_cinfo;
	uint_t		i;
	char		*p;
	lloff_t		wwn;
	const char	*fmt;

	/* update and lock controller map */
	if (update_map() != 0)
		return;		/* give up */
	assert(RW_WRITE_HELD(&ctlr_rw) || RW_READ_HELD(&ctlr_rw));

	/* look for match in cache */
	for (i = 0; (i < ctlr_num); ++i) {
		mhd_ctlrmap_t	*cmp  = &ctlr_map[i];

		fmt = cmp->scan;
		if ((regex(cmp->regexpr1, path) != NULL) &&
		    ((p = regex(cmp->regexpr2, path)) != NULL) &&
		    (sscanf(p, fmt,
		    (ulong_t *)&wwn._p._u, (ulong_t *)&wwn._p._l) == 2)) {
			cinfop->mhc_ctype = MHD_CTLR_SSA100;
			cinfop->mhc_tray = cmp->tray;
			cinfop->mhc_bus = cmp->bus;
			cinfop->mhc_wwn = wwn._f;
			match_SSA200(dp, path);
			break;
		}
	}

	/* unlock controller map */
	unlock_map();
}

/*
 * get unique drive ID
 */
static int
mhd_ident(
	mhd_drive_t		*dp
)
{
	mhd_drive_set_t		*sp = dp->dr_sp;
	int			serial = (sp->sr_options & MHD_SERIAL);
	struct uscsi_cmd	ucmd;
	union scsi_cdb		cdb;
	struct scsi_inquiry	inq;
	struct extvtoc		vtoc_buf;
	char			path[MAXPATHLEN + 1];
	int			len;
	int			err;

	/* check locks */
	assert(MUTEX_HELD(&sp->sr_mx));
	assert(dp->dr_fd >= 0);
	assert(dp->dr_state & DRIVE_IDENTING);

	/* reset ID */
	(void) memset(&dp->dr_drive_id, 0, sizeof (dp->dr_drive_id));

	/* get serial number */
	if (dp->dr_state & DRIVE_SERIALING) {
		if (! serial)
			mhd_mx_unlock(&sp->sr_mx);
		(void) memset(&ucmd, 0, sizeof (ucmd));
		(void) memset(&cdb, 0, sizeof (cdb));
		(void) memset(&inq, 0, sizeof (inq));
		cdb.scc_cmd = SCMD_INQUIRY;
		cdb.g0_count0 = sizeof (inq);
		ucmd.uscsi_cdb = (caddr_t)&cdb;
		ucmd.uscsi_cdblen = CDB_GROUP0;
		ucmd.uscsi_bufaddr = (caddr_t)&inq;
		ucmd.uscsi_buflen = sizeof (inq);
		ucmd.uscsi_flags = USCSI_READ | USCSI_ISOLATE | USCSI_DIAGNOSE;
		ucmd.uscsi_timeout = 30;
		err = ioctl(dp->dr_fd, USCSICMD, &ucmd);
		if (! serial)
			mhd_mx_lock(&sp->sr_mx);
		if (err != 0) {
			MHDPRINTF((
			    "%s: USCSICMD(SCMD_INQUIRY): failed errno %d\n",
			    dp->dr_rname, errno));
			dp->dr_drive_id.did_flags &= ~MHD_DID_SERIAL;
		} else {
			char	*p, *e;
			uint_t	i;

			MHDPRINTF(("%s: USCSICMD(SCMD_INQUIRY): success\n",
			    dp->dr_rname));
			dp->dr_drive_id.did_flags |= MHD_DID_SERIAL;
			p = dp->dr_drive_id.did_serial;
			e = p + sizeof (dp->dr_drive_id.did_serial);
			for (i = 0;
			    ((i < sizeof (inq.inq_vid)) && (p < e)); ++i)
				*p++ = inq.inq_vid[i];
			for (i = 0;
			    ((i < sizeof (inq.inq_pid)) && (p < e)); ++i)
				*p++ = inq.inq_pid[i];
			for (i = 0;
			    ((i < sizeof (inq.inq_revision)) && (p < e)); ++i)
				*p++ = inq.inq_revision[i];
			for (i = 0;
			    ((i < sizeof (inq.inq_serial)) && (p < e)); ++i)
				*p++ = inq.inq_serial[i];
			assert(p == e);
			for (p = dp->dr_drive_id.did_serial; (p < e); ++p) {
				if (*p == '\0')
					*p = ' ';
			}
		}
	} else {
		dp->dr_drive_id.did_flags &= ~MHD_DID_SERIAL;
	}

	/* get VTOC */
	if (dp->dr_state & DRIVE_VTOCING) {
		if (! serial)
			mhd_mx_unlock(&sp->sr_mx);
		(void) memset(&vtoc_buf, 0, sizeof (vtoc_buf));
		err = read_extvtoc(dp->dr_fd, &vtoc_buf);
		if (! serial)
			mhd_mx_lock(&sp->sr_mx);
		if (err < 0) {
			MHDPRINTF(("%s: read_extvtoc: failed errno %d\n",
			    dp->dr_rname, errno));
			dp->dr_drive_id.did_flags &= ~MHD_DID_TIME;
		} else {
			MHDPRINTF(("%s: read_extvtoc: success\n",
			    dp->dr_rname));
			dp->dr_drive_id.did_flags |= MHD_DID_TIME;
			dp->dr_drive_id.did_time = vtoc_buf.timestamp[0];
		}
	} else {
		dp->dr_drive_id.did_flags &= ~MHD_DID_TIME;
	}

	/* get controller info */
	if (dp->dr_state & DRIVE_CINFOING) {
		if (! serial)
			mhd_mx_unlock(&sp->sr_mx);
		len = readlink(dp->dr_rname0, path, (sizeof (path) - 1));
		if (! serial)
			mhd_mx_lock(&sp->sr_mx);
		if (len >= sizeof (path)) {
			len = -1;
			errno = ENAMETOOLONG;
		}
		if (len < 0) {
			MHDPRINTF(("%s: readlink: failed errno %d\n",
			    dp->dr_rname0, errno));
			dp->dr_drive_id.did_flags &= ~MHD_DID_CINFO;
		} else {
			MHDPRINTF(("%s: readlink: success\n",
			    dp->dr_rname0));
			dp->dr_drive_id.did_flags |= MHD_DID_CINFO;
			(void) memset(&dp->dr_drive_id.did_cinfo, 0,
			    sizeof (dp->dr_drive_id.did_cinfo));
			match_SSA100(dp, path);
		}
	} else {
		dp->dr_drive_id.did_flags &= ~MHD_DID_CINFO;
	}

	/* return success */
	(void) mhd_state_clr(dp, DRIVE_IDENTING, NULL);
	return (0);
}

/*
 * disk thread
 */
static void
mhd_drive_thread(
	mhd_drive_t	*dp
)
{
	mhd_drive_set_t	*sp = dp->dr_sp;

	/* wait for dp->dr_thread to be filled in */
	assert(sp != NULL);
	mhd_mx_lock(&sp->sr_mx);

	/* forever */
	for (;;) {
		/* check locks */
		assert(MUTEX_HELD(&sp->sr_mx));
		assert(dp->dr_thread == thr_self());

		/* check for changed set */
		if (sp != dp->dr_sp) {
			MHDPRINTF2(("%s: changed from set '%s' to '%s'\n",
			    dp->dr_rname, sp->sr_name, dp->dr_sp->sr_name));

			mhd_mx_unlock(&sp->sr_mx);
			sp = dp->dr_sp;
			mhd_mx_lock(&sp->sr_mx);
		}

		/* open drive, if necessary */
		if ((dp->dr_fd < 0) && (! (DRIVE_IS_IDLE(dp) ||
		    (dp->dr_state == DRIVE_IDLING)))) {
			int	serial = (sp->sr_options & MHD_SERIAL);

			if (! serial)
				mhd_mx_unlock(&sp->sr_mx);
			dp->dr_fd = open(dp->dr_rname0, (O_RDWR|O_NDELAY), 0);
			if (! serial)
				mhd_mx_lock(&sp->sr_mx);
			if (dp->dr_fd < 0) {
				mhd_perror("%s: open", dp->dr_rname);
				(void) mhd_state(dp, DRIVE_ERRORED, NULL);
				dp->dr_errnum = errno;
			}
			continue;
		}

		/* dispatch */
		switch (dp->dr_state) {
		case DRIVE_IDLE:
			MHDPRINTF1(("%s: IDLE\n", dp->dr_rname));
			break;

		case DRIVE_ERRORED:
			MHDPRINTF1(("%s: ERRORED %d\n",
			    dp->dr_rname, dp->dr_errnum));
			break;

		case DRIVE_IDLING:
			(void) mhd_state(dp, DRIVE_IDLE, NULL);
			continue;

		case DRIVE_RESERVING:
			MHDPRINTF1(("%s: RESERVING\n", dp->dr_rname));
			(void) mhd_reserve(dp);
			assert(DRIVE_IS_IDLE(dp));
			continue;

		case DRIVE_FAILFASTING:
			MHDPRINTF1(("%s: FAILFASTING\n", dp->dr_rname));
			(void) mhd_failfast(dp);
			assert(DRIVE_IS_IDLE(dp));
			continue;

		case DRIVE_RELEASING:
			MHDPRINTF1(("%s: RELEASING\n", dp->dr_rname));
			(void) mhd_release(dp);
			assert(DRIVE_IS_IDLE(dp));
			continue;

		/* non-exclusive states */
		default:
			assert(! (dp->dr_state &
			    (DRIVE_EXCLUSIVE_STATES & ~DRIVE_ERRORED)));
			if (dp->dr_state & (DRIVE_PROBING | DRIVE_STATUSING)) {
				MHDPRINTF1(("%s: PROBING\n", dp->dr_rname));
				(void) mhd_probe(dp);
				assert(! (dp->dr_state & DRIVE_STATUSING));
			}
			if (dp->dr_state & DRIVE_IDENTING) {
				MHDPRINTF1(("%s: IDENTING\n", dp->dr_rname));
				(void) mhd_ident(dp);
				assert(! (dp->dr_state & DRIVE_IDENTING));
				continue;	/* in case we're probing */
			}
			break;
		}

		/* close drive, if possible */
		if ((dp->dr_fd >= 0) && (DRIVE_IS_IDLE(dp))) {
			int	serial = (sp->sr_options & MHD_SERIAL);

			if (! serial)
				mhd_mx_unlock(&sp->sr_mx);
			(void) close(dp->dr_fd);	/* sd/ssd bug */
			if (! serial)
				mhd_mx_lock(&sp->sr_mx);
			dp->dr_fd = -1;
		}

		/* wake up anybody waiting */
		mhd_cv_broadcast(&sp->sr_cv);

		/* see if anything happened */
		if (! DRIVE_IS_IDLE(dp))
			continue;

		/* wait for something to happen */
		if (! (dp->dr_state & DRIVE_PROBING)) {
			mhd_cv_wait(&dp->dr_cv, &sp->sr_mx);
		} else {
			mhd_cv_timedwait(&dp->dr_cv, &sp->sr_mx,
			    (sp->sr_timeouts.mh_ff / 2));
		}
	}
}

/*
 * kick off drive thread
 */
static int
mhd_thread_create(
	mhd_drive_t	*dp,
	mhd_error_t	*mhep
)
{
	mhd_drive_set_t	*sp = dp->dr_sp;
	thread_t	thread = NULL;
	int		rval = 0;

	/* check lock and thread */
	assert(MUTEX_HELD(&sp->sr_mx));
	assert(dp->dr_thread == NULL);

	/* create thread */
	if (thr_create(NULL, 0, (void *(*)(void *))mhd_drive_thread,
	    (void *)dp, (THR_DETACHED | THR_BOUND), &thread) != 0) {
		rval = mhd_error(mhep, errno, "thr_create");
	} else {
		assert(thread != NULL);
		dp->dr_thread = thread;
	}

	/* return success */
	return (rval);
}

/*
 * peel off s%u from name
 */
static char *
diskname(
	const char	*sname
)
{
	char		*dname;
	char		*p, *e;

	/* duplicate name */
	if ((dname = Strdup(sname)) == NULL)
		return (NULL);

	/* gobble number and 's' */
	p = e = dname + strlen(dname) - 1;
	for (; (p > dname); --p) {
		if (!isdigit(*p))
			break;
	}
	if ((p == e) || (p <= dname)) {
		Free(dname);
		return (NULL);
	}
	if (*p-- != 's') {
		Free(dname);
		return (NULL);
	}
	if ((p <= dname) || (!isdigit(*p))) {
		Free(dname);
		return (NULL);
	}
	*(++p) = '\0';
	return (dname);
}

/*
 * create new drive
 */
mhd_drive_t *
mhd_create_drive(
	mhd_drive_set_t	*sp,		/* new set */
	char		*rname,		/* raw drive name */
	int		*fdp,		/* open device or -1 */
	mhd_error_t	*mhep		/* returned error */
)
{
	mhd_drive_t	*dp = NULL;
	char		*rname0 = NULL;

	/* check locks */
	assert(MUTEX_HELD(&sp->sr_mx));

	/* if drive already exists */
	if ((dp = mhd_find_drive(rname)) != NULL) {
		mhd_drive_set_t	*oldsp = dp->dr_sp;

		/* if set has changed, move drive */
		if (oldsp != sp) {
			mhd_mx_unlock(&sp->sr_mx);
			mhd_mx_lock(&oldsp->sr_mx);
			if (mhd_idle(dp, mhep) != 0) {
				mhd_mx_unlock(&oldsp->sr_mx);
				mhd_mx_lock(&sp->sr_mx);
				return (NULL);
			}
			mhd_del_drive_from_set(dp);
			mhd_mx_unlock(&oldsp->sr_mx);
			mhd_mx_lock(&sp->sr_mx);
			mhd_add_drive_to_set(sp, dp);
		}

		/* return drive */
		return (dp);
	}

	/* build slice0 */
	rname0 = Malloc(strlen(rname) + strlen("s0") + 1);
	(void) strcpy(rname0, rname);
	(void) strcat(rname0, "s0");

	/* allocate and initialize drive */
	dp = Zalloc(sizeof (*dp));
	dp->dr_sp = sp;
	dp->dr_rname = Strdup(rname);
	dp->dr_rname0 = rname0;
	mhd_cv_init(&dp->dr_cv);
	dp->dr_thread = NULL;
	dp->dr_fd = -1;
	dp->dr_state = DRIVE_IDLE;

	/* steal open drive */
	if ((fdp  != NULL) && (*fdp >= 0)) {
		dp->dr_fd = *fdp;
		*fdp = -1;
	}

	/* add to set */
	mhd_add_drive_to_set(sp, dp);

	/* kick off drive thread */
	if (mhd_thread_create(dp, mhep) != 0) {
		Free(dp->dr_rname0);
		Free(dp->dr_rname);
		Free(dp);
		return (NULL);
	}

	/* return drive */
	return (dp);
}

/*
 * find or create drive in any set
 */
static mhd_drive_t *
mhd_create_drive_anyset(
	char		*rname,
	int		*fdp,
	mhd_error_t	*mhep
)
{
	mhd_drive_set_t	*null_sp = mhd_create_set(NULL, 0, NULL, NULL);
	mhd_drive_t	*dp;

	/* check locks */
	assert(null_sp != NULL);

	/* drive already exists */
	if ((dp = mhd_find_drive(rname)) != NULL)
		return (dp);

	/* add to null set */
	mhd_mx_lock(&null_sp->sr_mx);
	dp = mhd_create_drive(null_sp, rname, fdp, mhep);
	mhd_mx_unlock(&null_sp->sr_mx);

	/* return drive */
	return (dp);
}

/*
 * process a file in the tree walk
 */
static int
do_disk(
	const char		*path,
	const struct stat	*statp,
	int			type
)
{
	char			*dname = NULL;
	int			fd = -1;
	struct dk_cinfo		cinfo;
	mhd_error_t		status = mhd_null_error;

	/* skip all but character devices */
	if ((type != FTW_F) || (! S_ISCHR(statp->st_mode)) ||
	    ((dname = diskname(path)) == NULL)) {
		return (0);
	}

	/* see if drive already exists */
	if (mhd_find_drive(dname) != NULL)
		return (0);

	/* see if device is a disk */
	if ((fd = open(path, (O_RDONLY|O_NDELAY), 0)) < 0)
		goto out;
	if (ioctl(fd, DKIOCINFO, &cinfo) != 0) {
		switch (errno) {
		case EINVAL:
		case ENOTTY:
			break;
		default:
			mhd_perror("DKIOCINFO: %s", path);
			break;
		}
		goto out;
	}

	/* skip CDROMs */
	if (cinfo.dki_ctype == DKC_CDROM) {
		(void) close(fd);
		Free(dname);
		return (0);
	}

	/* put disk on list */
	if (mhd_create_drive_anyset(dname, &fd, &status) == NULL) {
		mhde_perror(&status, "");
		goto out;
	}

	/* cleanup, return success (no matter what) */
out:
	if (dname != NULL)
		Free(dname);
	if (fd >= 0)
		(void) close(fd);
	mhd_clrerror(&status);
	return (0);
}

/*
 * find or create all the drives under a given directory
 */
int
mhd_create_drives(
	char		*path,
	mhd_error_t	*mhep
)
{
	/* default */
	if ((path == NULL) || (*path == '\0'))
		path = "/dev/rdsk";

	free_pln_cache();

	/* walk the directory, adding disks */
	if (ftw(path, do_disk, 5) != 0)
		return (mhd_error(mhep, errno, path));

	/* return success */
	return (0);
}
