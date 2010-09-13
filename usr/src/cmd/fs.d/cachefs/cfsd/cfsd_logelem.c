/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Methods of the cfsd_logelem* classes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <synch.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <libintl.h>
#include <errno.h>
#include <locale.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/cred.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_dlog.h>
#include <sys/fs/cachefs_ioctl.h>
#include <mdbug/mdbug.h>

#include "cfsd.h"
#include "cfsd_maptbl.h"
#include "cfsd_logfile.h"
#include "cfsd_kmod.h"
#include "cfsd_logelem.h"


#define	dl_ctime dl_times.tm_ctime
#define	dl_mtime dl_times.tm_mtime
#define	TIMECHANGE(A, B) (memcmp(&A, &B, sizeof (A)) != 0)
#define	X_OPTIMIZED -2
#define	X_CONFLICT -3


/*
 * -----------------------------------------------------------------
 *			cfsd_logelem_create
 *
 * Description:
 *	Constructor for the cfsd_logelem abstract base class.
 * Arguments:
 * Returns:
 * Preconditions:
 */

cfsd_logelem_object_t *
cfsd_logelem_create(cfsd_maptbl_object_t *maptbl_object_p,
	cfsd_logfile_object_t *logfile_object_p,
	cfsd_kmod_object_t *kmod_object_p)
{
	cfsd_logelem_object_t *logelem_object_p;

	dbug_enter("cfsd_logelem_create");

	logelem_object_p = cfsd_calloc(sizeof (cfsd_logelem_object_t));
	logelem_object_p->i_maptbl_object_p = maptbl_object_p;
	logelem_object_p->i_logfile_object_p = logfile_object_p;
	logelem_object_p->i_kmod_object_p = kmod_object_p;

	logelem_object_p->i_entp = logfile_object_p->i_cur_entry;
	logelem_object_p->i_offset = logfile_object_p->i_cur_offset;
	dbug_assert(logelem_object_p->i_entp);
	logelem_object_p->i_messagep[0] = '\0';
	logelem_object_p->i_type = NO_OBJECT_TYPE;

	dbug_leave("cfsd_logelem_create");
	return (logelem_object_p);
}

/*
 * -----------------------------------------------------------------
 *			cfsd_logelem_destroy
 *
 * Description:
 *	Destructor for the cfsd_logelem abstract base class.
 * Arguments:
 * Returns:
 * Preconditions:
 */


void
cfsd_logelem_destroy(cfsd_logelem_object_t *logelem_object_p)
{
	dbug_enter("cfsd_logelem_destroy");
	cfsd_free(logelem_object_p);
	dbug_leave("cfsd_logelem_destroy");
}
/*
 * -----------------------------------------------------------------
 *			logelem_print_cred
 *
 * Description:
 * Arguments:
 *	credp
 * Returns:
 * Preconditions:
 *	precond(credp)
 */

void
logelem_print_cred(dl_cred_t *credp)
{
	char buf[12 * NGROUPS_MAX_DEFAULT];
	char format[10];
	int xx;

	dbug_enter("logelem_print_cred");
	dbug_precond(credp);

	buf[0] = '\0';
	dbug_print(("dump", "credentials"));
	dbug_print(("dump", "  uid %d, gid %d",
	    credp->cr_uid, credp->cr_gid));
	dbug_print(("dump", "  ruid %d, rgid %d, suid %d, sgid %d",
	    credp->cr_ruid, credp->cr_rgid,
	    credp->cr_suid, credp->cr_sgid));

	for (xx = 0; xx < credp->cr_ngroups; xx++) {
		sprintf(format, " %d", credp->cr_groups[xx]);
		strlcat(buf, format, sizeof (buf));
	}
	dbug_print(("dump", "  ngroups %d,  %s", credp->cr_ngroups, buf));
	dbug_leave("logelem_print_cred");
}

/*
 * -----------------------------------------------------------------
 *			logelem_print_attr
 *
 * Description:
 * Arguments:
 *	vattrp
 * Returns:
 * Preconditions:
 *	precond(vattrp)
 */

void
logelem_print_attr(cfs_vattr_t *vp)
{
	dbug_enter("logelem_print_attr");
	dbug_precond(vp);

	dbug_print(("dump", "attributes"));
	dbug_print(("dump", "  mask 0x%x", vp->va_mask));
	if (vp->va_mask & AT_TYPE)
		dbug_print(("dump", "  type %d", vp->va_type));
	if (vp->va_mask & AT_MODE)
		dbug_print(("dump", "  mode 0%o", vp->va_mode));
	if (vp->va_mask & AT_UID)
		dbug_print(("dump", "  uid %d", vp->va_uid));
	if (vp->va_mask & AT_GID)
		dbug_print(("dump", "  gid %d", vp->va_gid));
	if (vp->va_mask & AT_FSID)
		dbug_print(("dump", "  fsid %08x", vp->va_fsid));
	if (vp->va_mask & AT_NODEID)
		dbug_print(("dump", "  nodeid %08x", vp->va_nodeid));
	if (vp->va_mask & AT_NLINK)
		dbug_print(("dump", "  nlink %d", vp->va_nlink));
	if (vp->va_mask & AT_SIZE)
		dbug_print(("dump", "  size %d", vp->va_size));
	if (vp->va_mask & AT_ATIME)
		dbug_print(("dump", "  atime %08x %08x",
		    vp->va_atime.tv_sec, vp->va_atime.tv_nsec));
	if (vp->va_mask & AT_MTIME)
		dbug_print(("dump", "  mtime %08x %08x",
		    vp->va_mtime.tv_sec, vp->va_mtime.tv_nsec));
	if (vp->va_mask & AT_CTIME)
		dbug_print(("dump", "  ctime %08x %08x",
		    vp->va_ctime.tv_sec, vp->va_ctime.tv_nsec));
	if (vp->va_mask & AT_RDEV)
		dbug_print(("dump", "  rdev %08x", vp->va_rdev));
	if (vp->va_mask & AT_BLKSIZE)
		dbug_print(("dump", "  blksize %08x", vp->va_blksize));
	if (vp->va_mask & AT_NBLOCKS)
		dbug_print(("dump", "  nblocks %d", vp->va_nblocks));
	if (vp->va_mask & AT_SEQ)
		dbug_print(("dump", "  seq %d", vp->va_seq));
	dbug_leave("logelem_print_attr");
}

/*
 * -----------------------------------------------------------------
 *			logelem_format_fid
 *
 * Description:
 * Arguments:
 *	fidp
 * Returns:
 * Preconditions:
 *	precond(fidp)
 */

void
logelem_format_fid(cfsd_logelem_object_t *logelem_object_p, cfs_fid_t *fidp)
{
	uint_t val;
	int index;
	char format[10];
	logelem_object_p->i_fidbuf[0] = '\0';

	for (index = 0; index < (int)fidp->fid_len; index += sizeof (uint_t)) {
		memcpy(&val, &fidp->fid_data[index], sizeof (uint_t));
		snprintf(format, sizeof (format), "%08x ", val);
		strlcat(logelem_object_p->i_fidbuf, format,
		    sizeof (logelem_object_p->i_fidbuf));
	}
}


/*
 * -----------------------------------------------------------------
 *			logelem_lostfound
 *
 * Description:
 *	Called when there is a conflict on a file.
 * Arguments:
 *	cidp	cid of file to move to lost+found
 *	pcidp	parent cid if known, else null
 *	namep	name of file if known, else null
 * Returns:
 *	Returns 0 for success, EIO if file could not be moved.
 * Preconditions:
 *	precond(cidp)
 */

int
logelem_lostfound(cfsd_logelem_object_t *logelem_object_p,
	cfs_cid_t *cidp,
	cfs_cid_t *pcidp,
	const char *namep,
	dl_cred_t *cred)
{
	struct cfs_dlog_mapping_space map;
	int xx;
	cfs_fid_t *fp, dirfid;
	cachefsio_getinfo_t ginfo;
	char namebuf[MAXNAMELEN];
	int gotdirfid = 0;
	int wrotefile = 0;
	char *np;
	char namebuf2[MAXNAMELEN * 3];
	int foundname = 0;
	int index;
	char *machnamep;
	struct utsname info;
	int len;
	cfs_fid_t filefid;
	struct cfs_vattr vattr;
	char newname[MAXNAMELEN];
	char mesgbuf[MAXNAMELEN * 3];
#define	MAXTRIES 10

	dbug_enter("logelem_lostfound");
	dbug_precond(cidp);
	dbug_precond(cred);

	/* make an alternate name for the file */
	if (namep == NULL)
		sprintf(namebuf, "fileno_%"PRIx64, cidp->cid_fileno);

	/* get info about the file from the cache */
	xx = kmod_getinfo(logelem_object_p->i_kmod_object_p, cidp, &ginfo);
	if (xx) {
		if (namep == NULL) {
			namep = namebuf;
		}
		logelem_log_opskipped(logelem_object_p, namep);
		dbug_leave("logelem_lostfound");
		return (0);
	}

	/* determine what we want to call this file */
	if (namep == NULL) {
		if (ginfo.gi_name[0] == '\0')
			namep = namebuf;
		else
			namep = ginfo.gi_name;
	}

	/* if not a regular file or not modified */
	if ((ginfo.gi_attr.va_type != VREG) || !ginfo.gi_modified) {
		logelem_log_opskipped(logelem_object_p, namep);
		dbug_leave("logelem_lostfound");
		return (0);
	}

	/* get the fid of the parent directory from the passed in cid */
	if (pcidp) {
		/* see if we have a valid mapping for the parent cid */
		xx = maptbl_get(logelem_object_p->i_maptbl_object_p,
		    *pcidp, &map);
		if (xx == -1) {
			logelem_log_opskipped(logelem_object_p, namep);
			dbug_leave("logelem_lostfound");
			return (EIO);
		}
		if ((xx == 0) && (0 < map.ms_fid)) {
			xx = logfile_offset(
			    logelem_object_p->i_logfile_object_p,
			    map.ms_fid, (caddr_t *)&fp);
			if (xx) {
				logelem_log_opskipped(logelem_object_p, namep);
				dbug_leave("logelem_lostfound");
				return (EIO);
			}
			if (fp->fid_len) {
				gotdirfid = 1;
				dirfid = *fp;
			}
		}

		/* otherwise try to get the fid from the cache */
		if (gotdirfid == 0) {
			xx = kmod_cidtofid(logelem_object_p->i_kmod_object_p,
			    pcidp, &dirfid);
			if (xx == 0)
				gotdirfid = 1;
		}
	}

	/* if not parent fid yet, try to get one from the dir in the cache */
	if ((gotdirfid == 0) && ginfo.gi_pcid.cid_fileno) {
		/* see if we have a valid mapping for the cache parent cid */
		xx = maptbl_get(logelem_object_p->i_maptbl_object_p,
		    ginfo.gi_pcid, &map);
		if (xx == -1) {
			logelem_log_opskipped(logelem_object_p, namep);
			dbug_leave("logelem_lostfound");
			return (EIO);
		}
		if ((xx == 0) && (0 < map.ms_fid)) {
			xx = logfile_offset(
			    logelem_object_p->i_logfile_object_p,
			    map.ms_fid, (caddr_t *)&fp);
			if (xx) {
				logelem_log_opskipped(logelem_object_p, namep);
				dbug_leave("logelem_lostfound");
				return (EIO);
			}
			if (fp->fid_len) {
				gotdirfid = 1;
				dirfid = *fp;
			}
		}

		/* otherwise try to get the fid from the cache */
		if (gotdirfid == 0) {
			xx = kmod_cidtofid(logelem_object_p->i_kmod_object_p,
			    &ginfo.gi_pcid, &dirfid);
			if (xx == 0)
				gotdirfid = 1;
		}
	}


	/* if we found a parent directory */
	if (gotdirfid) {
		/* get the host name */
		xx = uname(&info);
		if (xx == -1)
			machnamep = "client";
		else
			machnamep = info.nodename;

		/* find a name we can call this file */
		for (index = 0; index < MAXTRIES; index++) {
			/* construct the name */
			snprintf(namebuf2, sizeof (namebuf2),
			    "%s.conflict.%s.%x", machnamep, namep, index);
			len = strlen(namebuf2) + 1;
			if (len > MAXNAMELEN)
				np = &namebuf2[len - MAXNAMELEN];
			else
				np = namebuf2;

			/* see if it exists */
			xx = kmod_getattrname(
			    logelem_object_p->i_kmod_object_p,
			    &dirfid, np, cred, NULL, NULL);

			/* timeout error, pass the error back up */
			if ((xx == ETIMEDOUT) || (xx == EIO)) {
				dbug_leave("logelem_lostfound");
				return (ETIMEDOUT);
			}
			/* file does not exist, so try to use it */
			if (xx == ENOENT) {
				foundname = 1;
				break;
			}

			/* any other error on the directory, give up */
			if (xx)
				break;
		}

		/* if we found a name */
		if (foundname) {
			/* set up attributes for the file */
			vattr.va_type = VREG;
			vattr.va_mode = ginfo.gi_attr.va_mode;
			vattr.va_mask = AT_TYPE | AT_MODE | AT_SIZE;
			vattr.va_size = 0;

			/* create the file */
			xx = kmod_create(logelem_object_p->i_kmod_object_p,
			    &dirfid, np, NULL, &vattr, NONEXCL, VWRITE,
			    cred, &filefid, NULL, NULL);
			if (xx == 0) {
				/* write the file */
				xx = kmod_pushback(
				    logelem_object_p->i_kmod_object_p,
				    cidp, &filefid, cred, NULL, NULL, 0);
				if (xx == 0) {
					wrotefile = 1;
					snprintf(mesgbuf, sizeof (mesgbuf),
					    gettext("File %s renamed as %s on "
					    "server."),
					    namep, np);
					logelem_resolution(logelem_object_p,
					    mesgbuf);
				}
			}
		}

	}

	/* if we could not write the file to the server, move to lost+found */
	if (wrotefile == 0) {

		/* move the file to lost+found */
		xx = kmod_lostfound(logelem_object_p->i_kmod_object_p,
		    cidp, namep, newname);
		if (xx == EINVAL) {
			dbug_assert(0);
			logelem_log_opskipped(logelem_object_p, namep);
			dbug_leave("logelem_lostfound");
			return (0);
		} else if (xx) {
			snprintf(mesgbuf, sizeof (mesgbuf),
			    gettext("Cannot move %s to lost+found.  "),
			    namep);
			strlcat(mesgbuf,
			    gettext("Run cachefs fsck on the file system."),
			    sizeof (mesgbuf));
			logelem_resolution(logelem_object_p, mesgbuf);
			return (EIO);
		} else {
			snprintf(mesgbuf, sizeof (mesgbuf),
			    gettext("Moved %s to %s/%s/%s."), namep,
			    logelem_object_p->i_kmod_object_p->i_path,
			    CACHEFS_LOSTFOUND_NAME, newname);
			logelem_resolution(logelem_object_p, mesgbuf);
		}
	}

	/* set the mapping to indicate conflict */
	map.ms_cid = *cidp;
	map.ms_fid = X_CONFLICT;
	map.ms_times = 0;
	xx = maptbl_set(logelem_object_p->i_maptbl_object_p, &map, 1);
	if (xx) {
		dbug_leave("logelem_lostfound");
		return (EIO);
	}
	dbug_leave("logelem_lostfound");
	return (xx);
}

/*
 * -----------------------------------------------------------------
 *			logelem_problem
 *
 * Description:
 *	Specifies the problem string.
 *	Pass a variable number of strings.
 *	They are concatinated together to form the message.
 *	Terminate the argument list with NULL.
 * Arguments:
 *	strp
 * Returns:
 * Preconditions:
 *	precond(strp)
 */

void
logelem_problem(cfsd_logelem_object_t *logelem_object_p, char *strp)
{
	dbug_enter("logelem_problem");
	dbug_precond(strp);

	logelem_message(logelem_object_p, gettext("cachefsd: Problem: "), strp);
	dbug_leave("logelem_problem");
}

/*
 * -----------------------------------------------------------------
 *			logelem_resolution
 *
 * Description:
 *	Specifies the resolution string.
 *	Pass a variable number of strings.
 *	They are concatinated together to form the message.
 *	Terminate the argument list with NULL.
 * Arguments:
 *	strp
 * Returns:
 * Preconditions:
 *	precond(strp)
 */

void
logelem_resolution(cfsd_logelem_object_t *logelem_object_p, char *strp)
{
	dbug_enter("logelem_resolution");
	dbug_precond(strp);

	logelem_message(logelem_object_p, gettext("cachefsd: Resolution: "),
	    strp);
	dbug_leave("logelem_resolution");
}
/*
 * -----------------------------------------------------------------
 *			logelem_message_append
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 *	precond(strp1)
 *	precond(strp1)
 */

void
logelem_message_append(char *strp1, char *strp2)
{
	dbug_enter("logelem_message_append");
	if ((strlen(strp1) + strlen(strp2)) < (size_t)CFSDMesgMax)
		strcat(strp1, strp2);
	else {
		fprintf(stderr,
		    gettext("cachefsd: log element message truncated\n"));
		strncat(strp1, strp2, CFSDMesgMax - (strlen(strp1) + 1));
	}
	dbug_leave("logelem_message_append");
}
/*
 * -----------------------------------------------------------------
 *			logelem_message
 *
 * Description:
 * Arguments:
 *	prefix
 *	strp
 * Returns:
 * Preconditions:
 *	precond(prefix)
 *	precond(strp)
 */

void
logelem_message(cfsd_logelem_object_t *logelem_object_p,
	char *prefix,
	char *strp)
{
	dbug_enter("logelem_message");

	dbug_precond(prefix);
	dbug_precond(strp);

	logelem_message_append(logelem_object_p->i_messagep, prefix);
	logelem_message_append(logelem_object_p->i_messagep, strp);
	logelem_message_append(logelem_object_p->i_messagep, "\n");
	dbug_leave("logelem_message");
}
/*
 * -----------------------------------------------------------------
 *			logelem_log_opfailed
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

void
logelem_log_opfailed(cfsd_logelem_object_t *logelem_object_p,
	char *opp, char *info, const char *namep, int xx)
{
	char mesgbuf[CFSDStrMax];
	char errorbuf[CFSDStrMax];

	/*
	 * XXX need to change this so we don't assemble the message,
	 * this violates localization.
	 */
	snprintf(mesgbuf, sizeof (mesgbuf), gettext("%s failed"), opp);
	if (namep) {
		strlcat(mesgbuf, gettext(" on "), sizeof (mesgbuf));
		strlcat(mesgbuf, namep, sizeof (mesgbuf));
	}
	strlcat(mesgbuf, ".", sizeof (mesgbuf));
	if (info) {
		strlcat(mesgbuf, " ", sizeof (mesgbuf));
		strlcat(mesgbuf, info, sizeof (mesgbuf));
		strlcat(mesgbuf, ".", sizeof (mesgbuf));
	}
	if (xx) {
		snprintf(errorbuf, sizeof (errorbuf),
		    gettext(" Error: %s."), strerror(xx));
		strlcat(mesgbuf, errorbuf, sizeof (mesgbuf));
	}
	logelem_problem(logelem_object_p, mesgbuf);
}
/*
 * -----------------------------------------------------------------
 *			logelem_log_opskipped
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

void
logelem_log_opskipped(cfsd_logelem_object_t *logelem_object_p,
	const char *namep)
{
	char mesgbuf[CFSDStrMax];

	snprintf(mesgbuf, sizeof (mesgbuf),
	    gettext("Operation on %s skipped."), namep);
	logelem_resolution(logelem_object_p, mesgbuf);
}
/*
 * -----------------------------------------------------------------
 *			logelem_log_timelogmesg
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

void
logelem_log_timelogmesg(cfsd_logelem_object_t *logelem_object_p,
	char *opp, const char *namep, char *mesgp, int time_log)
{
	char mesgbuf[CFSDStrMax];

	/*
	 * XXX need to change this so we don't assemble the message,
	 * this violates localization.
	 */
	snprintf(mesgbuf, sizeof (mesgbuf), gettext("%s failed"), opp);
	if (namep) {
		strlcat(mesgbuf, gettext(" on "), sizeof (mesgbuf));
		strlcat(mesgbuf, namep, sizeof (mesgbuf));
	}
	strlcat(mesgbuf, ".", sizeof (mesgbuf));
	if (mesgp) {
		strlcat(mesgbuf, mesgp, sizeof (mesgbuf));
		strlcat(mesgbuf, ".", sizeof (mesgbuf));
	}
	strlcat(mesgbuf, " ", sizeof (mesgbuf));
	switch (time_log) {
	case 0:
		strlcat(mesgbuf, gettext("while rolling log."),
		    sizeof (mesgbuf));
		break;
	case 1:
		strlcat(mesgbuf, gettext("while disconnected."),
		    sizeof (mesgbuf));
		break;

	default:
		strlcat(mesgbuf, gettext("while unknown operation."),
		    sizeof (mesgbuf));
		break;
	}

	logelem_problem(logelem_object_p, mesgbuf);
}

/*
 *			cfsd_logelem_setattr_create
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */


cfsd_logelem_object_t *
cfsd_logelem_setattr_create(cfsd_maptbl_object_t *maptbl_object_p,
	cfsd_logfile_object_t *logfile_object_p,
	cfsd_kmod_object_t *kmod_object_p)
{
	cfsd_logelem_object_t *logelem_object_p;
	cfsd_logelem_setattr_object_t *setattr_object_p;

	dbug_enter("cfsd_logelem_setattr_create");

	logelem_object_p = cfsd_logelem_create(maptbl_object_p,
	    logfile_object_p, kmod_object_p);
	logelem_object_p->i_type = SETATTR_OBJECT_TYPE;

	setattr_object_p = SETATTR_OBJECT_PTR(logelem_object_p);
	setattr_object_p->i_up =
	    &logelem_object_p->i_entp->dl_u.dl_setattr;
	dbug_leave("cfsd_logelem_setattr_create");
	return (logelem_object_p);
}

/*
 *			cfsd_logelem_setsecattr_create
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */
cfsd_logelem_object_t *
cfsd_logelem_setsecattr_create(cfsd_maptbl_object_t *maptbl_object_p,
	cfsd_logfile_object_t *logfile_object_p,
	cfsd_kmod_object_t *kmod_object_p)
{
	cfsd_logelem_object_t *logelem_object_p;
	cfsd_logelem_setsecattr_object_t *setsecattr_object_p;

	dbug_enter("cfsd_logelem_setsecattr_create");

	logelem_object_p = cfsd_logelem_create(maptbl_object_p,
	    logfile_object_p, kmod_object_p);
	logelem_object_p->i_type = SETSECATTR_OBJECT_TYPE;

	setsecattr_object_p = SETSECATTR_OBJECT_PTR(logelem_object_p);
	setsecattr_object_p->i_up =
	    &logelem_object_p->i_entp->dl_u.dl_setsecattr;
	setsecattr_object_p->i_acl =
	    (const aclent_t *)
	    ((caddr_t)setsecattr_object_p->i_up->dl_buffer +
	    ((off_t)(setsecattr_object_p->i_up->dl_cred.cr_ngroups - 1)
	    * (off_t)sizeof (gid_t)));
	dbug_leave("cfsd_logelem_setsecattr_create");
	return (logelem_object_p);
}
/*
 *			cfsd_logelem_create_create
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

cfsd_logelem_object_t *
cfsd_logelem_create_create(cfsd_maptbl_object_t *maptbl_object_p,
	cfsd_logfile_object_t *logfile_object_p,
	cfsd_kmod_object_t *kmod_object_p)
{
	cfsd_logelem_object_t *logelem_object_p;
	cfsd_logelem_create_object_t *create_object_p;

	dbug_enter("cfsd_logelem_create_create");

	logelem_object_p = cfsd_logelem_create(maptbl_object_p,
	    logfile_object_p, kmod_object_p);
	logelem_object_p->i_type = CREATE_OBJECT_TYPE;

	create_object_p = CREATE_OBJECT_PTR(logelem_object_p);
	create_object_p->i_up =
	    &logelem_object_p->i_entp->dl_u.dl_create;
	create_object_p->i_namep =
	    create_object_p->i_up->dl_buffer +
	    ((create_object_p->i_up->dl_cred.cr_ngroups - 1) *
	    sizeof (gid_t));
	dbug_leave("cfsd_logelem_create_create");
	return (logelem_object_p);
}

/*
 *			cfsd_logelem_remove_create
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

cfsd_logelem_object_t *
cfsd_logelem_remove_create(cfsd_maptbl_object_t *maptbl_object_p,
	cfsd_logfile_object_t *logfile_object_p,
	cfsd_kmod_object_t *kmod_object_p)
{
	cfsd_logelem_object_t *logelem_object_p;
	cfsd_logelem_remove_object_t *remove_object_p;

	dbug_enter("cfsd_logelem_remove_create");

	logelem_object_p = cfsd_logelem_create(maptbl_object_p,
	    logfile_object_p, kmod_object_p);
	logelem_object_p->i_type = REMOVE_OBJECT_TYPE;

	remove_object_p = REMOVE_OBJECT_PTR(logelem_object_p);
	remove_object_p->i_up =
	    &logelem_object_p->i_entp->dl_u.dl_remove;
	remove_object_p->i_namep =
	    remove_object_p->i_up->dl_buffer +
	    ((remove_object_p->i_up->dl_cred.cr_ngroups - 1) *
	    sizeof (gid_t));
	dbug_leave("cfsd_logelem_remove_create");
	return (logelem_object_p);
}
/*
 * -----------------------------------------------------------------
 *			cfsd_logelem_rmdir_create
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

cfsd_logelem_object_t *
cfsd_logelem_rmdir_create(cfsd_maptbl_object_t *maptbl_object_p,
	cfsd_logfile_object_t *logfile_object_p,
	cfsd_kmod_object_t *kmod_object_p)
{
	cfsd_logelem_object_t *logelem_object_p;
	cfsd_logelem_rmdir_object_t *rmdir_object_p;

	dbug_enter("cfsd_logelem_rmdir_create");

	logelem_object_p = cfsd_logelem_create(maptbl_object_p,
	    logfile_object_p, kmod_object_p);
	logelem_object_p->i_type = RMDIR_OBJECT_TYPE;

	rmdir_object_p = RMDIR_OBJECT_PTR(logelem_object_p);
	rmdir_object_p->i_up =
	    &logelem_object_p->i_entp->dl_u.dl_rmdir;
	rmdir_object_p->i_namep =
	    rmdir_object_p->i_up->dl_buffer +
	    ((rmdir_object_p->i_up->dl_cred.cr_ngroups - 1)
	    * sizeof (gid_t));
	dbug_leave("cfsd_logelem_rmdir_create");
	return (logelem_object_p);
}
/*
 * -----------------------------------------------------------------
 *			cfsd_logelem_mkdir_create
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

cfsd_logelem_object_t *
cfsd_logelem_mkdir_create(cfsd_maptbl_object_t *maptbl_object_p,
	cfsd_logfile_object_t *logfile_object_p,
	cfsd_kmod_object_t *kmod_object_p)
{
	cfsd_logelem_object_t *logelem_object_p;
	cfsd_logelem_mkdir_object_t *mkdir_object_p;

	dbug_enter("cfsd_logelem_mkdir_create");

	logelem_object_p = cfsd_logelem_create(maptbl_object_p,
	    logfile_object_p, kmod_object_p);
	logelem_object_p->i_type = MKDIR_OBJECT_TYPE;

	mkdir_object_p = MKDIR_OBJECT_PTR(logelem_object_p);
	mkdir_object_p->i_up =
	    &logelem_object_p->i_entp->dl_u.dl_mkdir;
	mkdir_object_p->i_namep =
	    mkdir_object_p->i_up->dl_buffer +
	    ((mkdir_object_p->i_up->dl_cred.cr_ngroups - 1) *
	    sizeof (gid_t));
	dbug_leave("cfsd_logelem_mkdir_create");
	return (logelem_object_p);
}
/*
 * -----------------------------------------------------------------
 *			cfsd_logelem_link_create
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

cfsd_logelem_object_t *
cfsd_logelem_link_create(cfsd_maptbl_object_t *maptbl_object_p,
	cfsd_logfile_object_t *logfile_object_p,
	cfsd_kmod_object_t *kmod_object_p)
{
	cfsd_logelem_object_t *logelem_object_p;
	cfsd_logelem_link_object_t *link_object_p;

	dbug_enter("cfsd_logelem_link_create");

	logelem_object_p = cfsd_logelem_create(maptbl_object_p,
	    logfile_object_p, kmod_object_p);
	logelem_object_p->i_type = LINK_OBJECT_TYPE;

	link_object_p = LINK_OBJECT_PTR(logelem_object_p);
	link_object_p->i_up =
	    &logelem_object_p->i_entp->dl_u.dl_link;
	link_object_p->i_namep =
	    link_object_p->i_up->dl_buffer +
	    ((link_object_p->i_up->dl_cred.cr_ngroups - 1)
	    * sizeof (gid_t));
	dbug_leave("cfsd_logelem_link_create");
	return (logelem_object_p);
}
/*
 * -----------------------------------------------------------------
 *			cfsd_logelem_symlink_create
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

cfsd_logelem_object_t *
cfsd_logelem_symlink_create(cfsd_maptbl_object_t *maptbl_object_p,
	cfsd_logfile_object_t *logfile_object_p,
	cfsd_kmod_object_t *kmod_object_p)
{
	cfsd_logelem_object_t *logelem_object_p;
	cfsd_logelem_symlink_object_t *symlink_object_p;

	dbug_enter("cfsd_logelem_symlink_create");
	logelem_object_p = cfsd_logelem_create(maptbl_object_p,
	    logfile_object_p, kmod_object_p);
	logelem_object_p->i_type = SYMLINK_OBJECT_TYPE;

	symlink_object_p = SYMLINK_OBJECT_PTR(logelem_object_p);
	symlink_object_p->i_up =
	    &logelem_object_p->i_entp->dl_u.dl_symlink;
	symlink_object_p->i_namep =
	    symlink_object_p->i_up->dl_buffer +
	    ((symlink_object_p->i_up->dl_cred.cr_ngroups - 1) *
	    sizeof (gid_t));
	symlink_object_p->i_contentsp =
	    symlink_object_p->i_namep +
	    strlen(symlink_object_p->i_namep) + 1;
	dbug_leave("cfsd_logelem_symlink_create");
	return (logelem_object_p);
}
/*
 * -----------------------------------------------------------------
 *			cfsd_logelem_rename_create
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

cfsd_logelem_object_t *
cfsd_logelem_rename_create(cfsd_maptbl_object_t *maptbl_object_p,
	cfsd_logfile_object_t *logfile_object_p,
	cfsd_kmod_object_t *kmod_object_p)
{
	cfsd_logelem_object_t *logelem_object_p;
	cfsd_logelem_rename_object_t *rename_object_p;

	dbug_enter("cfsd_logelem_rename_create");
	logelem_object_p = cfsd_logelem_create(maptbl_object_p,
	    logfile_object_p, kmod_object_p);
	logelem_object_p->i_type = RENAME_OBJECT_TYPE;

	rename_object_p = RENAME_OBJECT_PTR(logelem_object_p);
	rename_object_p->i_up =
	    &logelem_object_p->i_entp->dl_u.dl_rename;
	rename_object_p->i_orignamep =
	    rename_object_p->i_up->dl_buffer +
	    ((rename_object_p->i_up->dl_cred.cr_ngroups - 1) *
	    sizeof (gid_t));
	rename_object_p->i_newnamep =
	    rename_object_p->i_orignamep +
	    strlen(rename_object_p->i_orignamep) + 1;
	dbug_leave("cfsd_logelem_rename_create");
	return (logelem_object_p);
}
/*
 *			cfsd_logelem_modified_create
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

cfsd_logelem_object_t *
cfsd_logelem_modified_create(cfsd_maptbl_object_t *maptbl_object_p,
	cfsd_logfile_object_t *logfile_object_p,
	cfsd_kmod_object_t *kmod_object_p)
{
	cfsd_logelem_object_t *logelem_object_p;
	cfsd_logelem_modified_object_t *modified_object_p;

	dbug_enter("cfsd_logelem_modified_create");
	logelem_object_p = cfsd_logelem_create(maptbl_object_p,
	    logfile_object_p, kmod_object_p);
	logelem_object_p->i_type = MODIFIED_OBJECT_TYPE;

	modified_object_p = MODIFIED_OBJECT_PTR(logelem_object_p);
	modified_object_p->i_up =
	    &logelem_object_p->i_entp->dl_u.dl_modify;
	dbug_leave("cfsd_logelem_modified_create");
	return (logelem_object_p);
}
/*
 *			cfsd_logelem_mapfid
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

cfsd_logelem_object_t *
cfsd_logelem_mapfid_create(cfsd_maptbl_object_t *maptbl_object_p,
	cfsd_logfile_object_t *logfile_object_p,
	cfsd_kmod_object_t *kmod_object_p)
{
	cfsd_logelem_object_t *logelem_object_p;
	cfsd_logelem_mapfid_object_t *mapfid_object_p;

	dbug_enter("cfsd_logelem_mapfid_create");
	logelem_object_p = cfsd_logelem_create(maptbl_object_p,
	    logfile_object_p, kmod_object_p);
	logelem_object_p->i_type = MAPFID_OBJECT_TYPE;

	mapfid_object_p = MAPFID_OBJECT_PTR(logelem_object_p);
	mapfid_object_p->i_up =
	    &logelem_object_p->i_entp->dl_u.dl_mapfid;
	dbug_leave("cfsd_logelem_mapfid_create");
	return (logelem_object_p);
}
/*
 *			logelem_roll
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

int
logelem_roll(cfsd_logelem_object_t *logelem_object_p, ulong_t *seqp)
{
	int retval = 0;

	dbug_enter("logelem_roll");

	switch (logelem_object_p->i_type) {

	case NO_OBJECT_TYPE:
		dbug_assert(0);
		retval = EIO;
		break;

	case SETATTR_OBJECT_TYPE:
		retval = logelem_roll_setattr(logelem_object_p, seqp);
		break;

	case SETSECATTR_OBJECT_TYPE:
		retval = logelem_roll_setsecattr(logelem_object_p, seqp);
		break;

	case CREATE_OBJECT_TYPE:
		retval = logelem_roll_create(logelem_object_p, seqp);
		break;

	case REMOVE_OBJECT_TYPE:
		retval = logelem_roll_remove(logelem_object_p, seqp);
		break;

	case RMDIR_OBJECT_TYPE:
		retval = logelem_roll_rmdir(logelem_object_p, seqp);
		break;

	case MKDIR_OBJECT_TYPE:
		retval = logelem_roll_mkdir(logelem_object_p, seqp);
		break;

	case LINK_OBJECT_TYPE:
		retval = logelem_roll_link(logelem_object_p, seqp);
		break;

	case SYMLINK_OBJECT_TYPE:
		retval = logelem_roll_symlink(logelem_object_p, seqp);
		break;

	case RENAME_OBJECT_TYPE:
		retval = logelem_roll_rename(logelem_object_p, seqp);
		break;

	case MODIFIED_OBJECT_TYPE:
		retval = logelem_roll_modified(logelem_object_p, seqp);
		break;

	case MAPFID_OBJECT_TYPE:
		retval = logelem_roll_mapfid(logelem_object_p);
		break;

	default:
		dbug_assert(0);
		retval = EIO;
	}
	dbug_leave("logelem_roll");
	return (retval);
}
/*
 *			logelem_roll_setattr
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

int
logelem_roll_setattr(cfsd_logelem_object_t *logelem_object_p, ulong_t *seqp)
{

	int xx;
	cfs_fid_t filefid, *fp;
	struct cfs_dlog_mapping_space map;
	cfs_dlog_tm_t *tmp;
	cfs_timestruc_t ctime, mtime;
	int time_log;
	cfs_vattr_t va;
	int conflict = 0;

	dbug_enter("logelem_roll_setattr");

	/* get the mapping for this cid if it exists */
	xx = maptbl_get(logelem_object_p->i_maptbl_object_p,
	    SETATTR_OBJECT(logelem_object_p).i_up->dl_cid, &map);
	if (xx == -1) {
		logelem_log_opfailed(logelem_object_p, "Setattr",
		    gettext("error mapping cid"), NULL, 0);
		dbug_leave("logelem_roll_setattr");
		return (EIO);
	}
	/* if a mapping was not found */
	if (xx) {
		/* dummy up mapping so we get values from the cache */
		map.ms_cid = SETATTR_OBJECT(logelem_object_p).i_up->dl_cid;
		map.ms_fid = 0;
		map.ms_times = 0;
	}

	/* done if there was a conflict on the file */
	if (map.ms_fid == X_CONFLICT) {
		logelem_log_opfailed(logelem_object_p, "Setattr",
		    gettext("file conflict"), NULL, 0);
		dbug_leave("logelem_roll_setattr");
		return (0);
	}
	/* done if the file is optimized out */
	if (map.ms_fid == X_OPTIMIZED) {
		dbug_leave("logelem_roll_setattr");
		return (0);
	}
	/* if we have a fid in the mapping */
	if (map.ms_fid) {
		/* get the fid */
		xx = logfile_offset(logelem_object_p->i_logfile_object_p,
		    map.ms_fid, (caddr_t *)&fp);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Setattr",
			    gettext("error getting logfile offset"), NULL, xx);
			dbug_leave("logelem_roll_setattr");
			return (EIO);
		}
		filefid = *fp;
		dbug_assert(filefid.fid_len);
	}

	/* else get the fid from the cache */
	else {
		xx = kmod_cidtofid(logelem_object_p->i_kmod_object_p,
		    &SETATTR_OBJECT(logelem_object_p).i_up->dl_cid, &filefid);
		if (xx == ENOENT) {
			dbug_leave("logelem_roll_setattr");
			return (0);
		}
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Setattr",
			    gettext("File is no longer in the cache"),
			    NULL, xx);
			xx = logelem_lostfound(logelem_object_p,
			    &SETATTR_OBJECT(logelem_object_p).i_up->dl_cid,
			    NULL, NULL,
			    &SETATTR_OBJECT(logelem_object_p).i_up->dl_cred);
			dbug_leave("logelem_roll_setattr");
			return (xx);
		}
	}

	/* if we have timestamps in the mapping */
	if (map.ms_times) {
		/* get the times */
		xx = logfile_offset(logelem_object_p->i_logfile_object_p,
		    map.ms_times, (caddr_t *)&tmp);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Setattr",
			    gettext("error getting logfile offset"), NULL, xx);
			dbug_leave("logelem_roll_setattr");
			return (EIO);
		}
		ctime = tmp->tm_ctime;
		mtime = tmp->tm_mtime;
		time_log = 0;
	}

	/* else get the timestamps from the log entry */
	else {
		ctime = SETATTR_OBJECT(logelem_object_p).i_up->dl_ctime;
		mtime = SETATTR_OBJECT(logelem_object_p).i_up->dl_mtime;
		time_log = 1;
	}

	/* get the attributes of the file from the back fs */
	xx = kmod_getattrfid(logelem_object_p->i_kmod_object_p, &filefid,
	    &SETATTR_OBJECT(logelem_object_p).i_up->dl_cred, &va);
	if ((xx == ETIMEDOUT) || (xx == EIO)) {
		dbug_leave("logelem_roll_setattr");
		return (ETIMEDOUT);
	}
	if (xx) {
		logelem_log_opfailed(logelem_object_p, "Setattr",
		    gettext("error getting attributes"), NULL, xx);
		xx = logelem_lostfound(logelem_object_p,
		    &SETATTR_OBJECT(logelem_object_p).i_up->dl_cid,
		    NULL, NULL,
		    &SETATTR_OBJECT(logelem_object_p).i_up->dl_cred);
		dbug_leave("logelem_roll_setattr");
		return (xx);
	}


	/* conflict if mtime changed */
	if (TIMECHANGE(mtime, va.va_mtime)) {
		logelem_log_timelogmesg(logelem_object_p, "Setattr",
		    NULL, gettext("File modified"), time_log);
		conflict = 1;
	}

	/* conflict if ctime changed */
	else if (TIMECHANGE(ctime, va.va_ctime)) {
		logelem_log_timelogmesg(logelem_object_p, "Setattr",
		    NULL, gettext("File changed"), time_log);
		conflict = 1;
	}

	/* if a conflict was detected */
	if (conflict) {
		logelem_log_opfailed(logelem_object_p, "Setattr",
		    gettext("file conflict"), NULL, 0);
		xx = logelem_lostfound(logelem_object_p,
		    &SETATTR_OBJECT(logelem_object_p).i_up->dl_cid,
		    NULL, NULL,
		    &SETATTR_OBJECT(logelem_object_p).i_up->dl_cred);
		dbug_leave("logelem_roll_setattr");
		return (xx);
	}

	/* now do the setattr, get the new times */
	xx = kmod_setattr(logelem_object_p->i_kmod_object_p,
	    &filefid, &SETATTR_OBJECT(logelem_object_p).i_up->dl_cid,
	    &SETATTR_OBJECT(logelem_object_p).i_up->dl_attrs,
	    SETATTR_OBJECT(logelem_object_p).i_up->dl_flags,
	    &SETATTR_OBJECT(logelem_object_p).i_up->dl_cred,
	    &SETATTR_OBJECT(logelem_object_p).i_up->dl_ctime,
	    &SETATTR_OBJECT(logelem_object_p).i_up->dl_mtime);
	if ((xx == ETIMEDOUT) || (xx == EIO)) {
		dbug_leave("logelem_roll_setattr");
		return (ETIMEDOUT);
	}
	if (xx) {
		logelem_log_opfailed(logelem_object_p, "Setattr", NULL,
		    NULL, xx);
		xx = logelem_lostfound(logelem_object_p,
		    &SETATTR_OBJECT(logelem_object_p).i_up->dl_cid,
		    NULL, NULL,
		    &SETATTR_OBJECT(logelem_object_p).i_up->dl_cred);
		dbug_leave("logelem_roll_setattr");
		return (xx);
	}

	/* update the mapping to point to the new times */
	map.ms_times = logelem_object_p->i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_setattr.dl_times);
	xx = maptbl_set(logelem_object_p->i_maptbl_object_p, &map, 1);
	if (xx) {
		dbug_leave("logelem_roll_setattr");
		return (EIO);
	}
	dbug_leave("logelem_roll_setattr");
	return (0);
}

/*
 *			logelem_roll_setsecattr
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

int
logelem_roll_setsecattr(cfsd_logelem_object_t *logelem_object_p, ulong_t *seqp)
{
	int xx;
	cfs_fid_t filefid, *fp;
	struct cfs_dlog_mapping_space map;
	cfs_dlog_tm_t *tmp;
	cfs_timestruc_t ctime, mtime;
	int time_log;
	cfs_vattr_t va;
	int conflict = 0;

	dbug_enter("logelem_roll_setsecattr");
	/* get the mapping for this cid if it exists */
	xx = maptbl_get(logelem_object_p->i_maptbl_object_p,
	    SETSECATTR_OBJECT(logelem_object_p).i_up->dl_cid, &map);
	if (xx == -1) {
		logelem_log_opfailed(logelem_object_p, "Setsecattr",
		    gettext("error mapping cid"), NULL, 0);
		dbug_leave("logelem_roll_setsecattr");
		return (EIO);
	}
	/* if a mapping was not found */
	if (xx) {
		/* dummy up mapping so we get values from the cache */
		map.ms_cid = SETSECATTR_OBJECT(logelem_object_p).i_up->dl_cid;
		map.ms_fid = 0;
		map.ms_times = 0;
	}

	/* done if there was a conflict on the file */
	if (map.ms_fid == X_CONFLICT) {
		logelem_log_opfailed(logelem_object_p, "Setsecattr",
		    gettext("file conflict"), NULL, 0);
		dbug_leave("logelem_roll_setsecattr");
		return (0);
	}
	/* done if the file is optimized out */
	if (map.ms_fid == X_OPTIMIZED) {
		dbug_leave("logelem_roll_setsecattr");
		return (0);
	}
	/* if we have a fid in the mapping */
	if (map.ms_fid) {
		/* get the fid */
		xx = logfile_offset(logelem_object_p->i_logfile_object_p,
		    map.ms_fid, (caddr_t *)&fp);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Setsecattr",
			    gettext("error getting logfile offset"), NULL, 0);
			dbug_leave("logelem_roll_setsecattr");
			return (EIO);
		}
		filefid = *fp;
		dbug_assert(filefid.fid_len);
	}

	/* else get the fid from the cache */
	else {
		xx = kmod_cidtofid(logelem_object_p->i_kmod_object_p,
		    &SETSECATTR_OBJECT(logelem_object_p).i_up->dl_cid,
		    &filefid);
		if (xx == ENOENT) {
			dbug_leave("logelem_roll_setsecattr");
			return (0);
		}
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Setsecattr",
			    gettext("File is no longer in the cache"),
			    NULL, xx);
			xx = logelem_lostfound(logelem_object_p,
			    &SETSECATTR_OBJECT(logelem_object_p).i_up->dl_cid,
			    NULL, NULL,
			    &SETSECATTR_OBJECT(logelem_object_p).i_up->dl_cred);
			dbug_leave("logelem_roll_setsecattr");
			return (xx);
		}
	}

	/* if we have timestamps in the mapping */
	if (map.ms_times) {
		/* get the times */
		xx = logfile_offset(logelem_object_p->i_logfile_object_p,
		    map.ms_times, (caddr_t *)&tmp);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Setsecattr",
			    gettext("error getting logfile offset"), NULL, 0);
			dbug_leave("logelem_roll_setsecattr");
			return (EIO);
		}
		ctime = tmp->tm_ctime;
		mtime = tmp->tm_mtime;
		time_log = 0;
	}

	/* else get the timestamps from the log entry */
	else {
		ctime = SETSECATTR_OBJECT(logelem_object_p).i_up->dl_ctime;
		mtime = SETSECATTR_OBJECT(logelem_object_p).i_up->dl_mtime;
		time_log = 1;
	}

	/* get the attributes of the file from the back fs */
	xx = kmod_getattrfid(logelem_object_p->i_kmod_object_p, &filefid,
	    &SETSECATTR_OBJECT(logelem_object_p).i_up->dl_cred, &va);
	if ((xx == ETIMEDOUT) || (xx == EIO)) {
		dbug_leave("logelem_roll_setsecattr");
		return (ETIMEDOUT);
	}
	if (xx) {
		logelem_log_opfailed(logelem_object_p, "Setsecattr",
		    gettext("error getting attributes"), NULL, 0);
		xx = logelem_lostfound(logelem_object_p,
		    &SETSECATTR_OBJECT(logelem_object_p).i_up->dl_cid,
		    NULL, NULL,
		    &SETSECATTR_OBJECT(logelem_object_p).i_up->dl_cred);
		dbug_leave("logelem_roll_setsecattr");
		return (xx);
	}

	/* conflict if mtime changed */
	if (TIMECHANGE(mtime, va.va_mtime)) {
		logelem_log_timelogmesg(logelem_object_p, "Setsecattr",
		    NULL, gettext("File modified"), time_log);
		conflict = 1;
	}

	/* conflict if ctime changed */
	else if (TIMECHANGE(ctime, va.va_ctime)) {
		logelem_log_timelogmesg(logelem_object_p, "Setsecattr",
		    NULL, gettext("File changed"), time_log);
		conflict = 1;
	}

	/* if a conflict was detected */
	if (conflict) {
		logelem_log_opfailed(logelem_object_p, "Setsecattr",
		    gettext("file conflict"), NULL, 0);
		xx = logelem_lostfound(logelem_object_p,
		    &SETSECATTR_OBJECT(logelem_object_p).i_up->dl_cid,
		    NULL, NULL,
		    &SETSECATTR_OBJECT(logelem_object_p).i_up->dl_cred);
		dbug_leave("logelem_roll_setsecattr");
		return (xx);
	}

	/* now do the setsecattr, get the new times */
	xx = kmod_setsecattr(logelem_object_p->i_kmod_object_p, &filefid,
	    &SETSECATTR_OBJECT(logelem_object_p).i_up->dl_cid,
	    SETSECATTR_OBJECT(logelem_object_p).i_up->dl_mask,
	    SETSECATTR_OBJECT(logelem_object_p).i_up->dl_aclcnt,
	    SETSECATTR_OBJECT(logelem_object_p).i_up->dl_dfaclcnt,
	    SETSECATTR_OBJECT(logelem_object_p).i_acl,
	    &SETSECATTR_OBJECT(logelem_object_p).i_up->dl_cred,
	    &SETSECATTR_OBJECT(logelem_object_p).i_up->dl_ctime,
	    &SETSECATTR_OBJECT(logelem_object_p).i_up->dl_mtime);
	if ((xx == ETIMEDOUT) || (xx == EIO)) {
		dbug_leave("logelem_roll_setsecattr");
		return (ETIMEDOUT);
	}
	if (xx) {
		logelem_log_opfailed(logelem_object_p, "Setsecattr", NULL,
		    NULL, xx);
		xx = logelem_lostfound(logelem_object_p,
		    &SETSECATTR_OBJECT(logelem_object_p).i_up->dl_cid,
		    NULL, NULL,
		    &SETSECATTR_OBJECT(logelem_object_p).i_up->dl_cred);
		dbug_leave("logelem_roll_setsecattr");
		return (xx);
	}

	/* update the mapping to point to the new times */
	map.ms_times = logelem_object_p->i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_setsecattr.dl_times);
	xx = maptbl_set(logelem_object_p->i_maptbl_object_p, &map, 1);
	if (xx) {
		dbug_leave("logelem_roll_setsecattr");
		return (EIO);
	}
	dbug_leave("logelem_roll_setsecattr");
	return (0);
}

/*
 *			logelem_roll_create
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

int
logelem_roll_create(cfsd_logelem_object_t *logelem_object_p, ulong_t *seqp)
{
	int xx;
	cfs_fid_t *fp;
	cfs_fid_t dirfid;
	struct cfs_dlog_mapping_space map;
	cfs_fid_t filefid2;
	cfs_vattr_t va;

	dbug_enter("logelem_roll_create");
	/* if the file existed at the time of this operation */
	dbug_assert(CREATE_OBJECT(logelem_object_p).i_up->dl_exists == 0);

	/* see if the file no longer exists in the cache */
#if 0
	xx = kmod_exists(logelem_object_p->i_kmod_object_p,
	    &CREATE_OBJECT(logelem_object_p).i_up->dl_new_cid);
	if (xx) {
		dbug_assert(xx == ENOENT);

		/* indicate ignore future operations on file */
		map.ms_cid = CREATE_OBJECT(logelem_object_p).i_up->dl_new_cid;
		map.ms_fid = X_OPTIMIZED;
		map.ms_times = 0;
		xx = maptbl_set(maptbl_object_p, &map, 1);
		dbug_leave("logelem_roll_create");
		if (xx) {
			dbug_leave("logelem_roll_create");
			return (EIO);
		}
		dbug_leave("logelem_roll_create");
		return (0);
	}
#endif

	/* get the fid of the parent directory */
	xx = maptbl_get(logelem_object_p->i_maptbl_object_p,
	    CREATE_OBJECT(logelem_object_p).i_up->dl_parent_cid, &map);
	if (xx == -1) {
		logelem_log_opfailed(logelem_object_p, "Create",
		    gettext("error mapping fid"), NULL, 0);
		dbug_leave("logelem_roll_create");
		return (EIO);
	}
	/* if error from getting map or no fid in map (ms_fid == 0) */
	if (xx || (map.ms_fid <= 0)) {
		xx = kmod_cidtofid(logelem_object_p->i_kmod_object_p,
		    &CREATE_OBJECT(logelem_object_p).i_up->dl_parent_cid,
		    &dirfid);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Create",
			    gettext("Parent directory no longer exists"),
			    CREATE_OBJECT(logelem_object_p).i_namep, xx);
			xx = logelem_lostfound(logelem_object_p,
			    &CREATE_OBJECT(logelem_object_p).i_up->dl_new_cid,
			    &
			    CREATE_OBJECT(logelem_object_p).i_up->dl_parent_cid,
			    CREATE_OBJECT(logelem_object_p).i_namep,
			    &CREATE_OBJECT(logelem_object_p).i_up->dl_cred);
			dbug_leave("logelem_roll_create");
			return (xx);
		}
	} else {
		xx = logfile_offset(logelem_object_p->i_logfile_object_p,
		    map.ms_fid, (caddr_t *)&fp);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Create",
			    gettext("error getting logfile offset"), NULL, 0);
			dbug_leave("logelem_roll_create");
			return (EIO);
		}
		dirfid = *fp;
		dbug_assert(dirfid.fid_len);
	}

	/* if the file exists on the back fs */
	xx = kmod_getattrname(logelem_object_p->i_kmod_object_p, &dirfid,
	    CREATE_OBJECT(logelem_object_p).i_namep,
	    &CREATE_OBJECT(logelem_object_p).i_up->dl_cred, &va, &filefid2);
	if ((xx == ETIMEDOUT) || (xx == EIO)) {
		dbug_leave("logelem_roll_create");
		return (ETIMEDOUT);
	}

	/* if the file exists on the back file system */
	if (xx == 0) {
		logelem_log_opfailed(logelem_object_p, "Create",
		    gettext("File created while disconnected"),
		    CREATE_OBJECT(logelem_object_p).i_namep, xx);
		xx = logelem_lostfound(logelem_object_p,
		    &CREATE_OBJECT(logelem_object_p).i_up->dl_new_cid,
		    &CREATE_OBJECT(logelem_object_p).i_up->dl_parent_cid,
		    CREATE_OBJECT(logelem_object_p).i_namep,
		    &CREATE_OBJECT(logelem_object_p).i_up->dl_cred);
		dbug_leave("logelem_roll_create");
		return (xx);
	}

	/* do the create */
	xx = kmod_create(logelem_object_p->i_kmod_object_p, &dirfid,
	    CREATE_OBJECT(logelem_object_p).i_namep,
	    &CREATE_OBJECT(logelem_object_p).i_up->dl_new_cid,
	    &CREATE_OBJECT(logelem_object_p).i_up->dl_attrs, NONEXCL,
	    CREATE_OBJECT(logelem_object_p).i_up->dl_mode,
	    &CREATE_OBJECT(logelem_object_p).i_up->dl_cred,
	    &CREATE_OBJECT(logelem_object_p).i_up->dl_fid,
	    &CREATE_OBJECT(logelem_object_p).i_up->dl_ctime,
	    &CREATE_OBJECT(logelem_object_p).i_up->dl_mtime);
	if (xx) {
		if ((xx == ETIMEDOUT) || (xx == EIO)) {
			dbug_leave("logelem_roll_create");
			return (ETIMEDOUT);
		}
		/* create failed move to lost and found */
		logelem_log_opfailed(logelem_object_p, "Create", NULL,
		    CREATE_OBJECT(logelem_object_p).i_namep, xx);
		xx = logelem_lostfound(logelem_object_p,
		    &CREATE_OBJECT(logelem_object_p).i_up->dl_new_cid,
		    &CREATE_OBJECT(logelem_object_p).i_up->dl_parent_cid,
		    CREATE_OBJECT(logelem_object_p).i_namep,
		    &CREATE_OBJECT(logelem_object_p).i_up->dl_cred);
		dbug_leave("logelem_roll_create");
		return (xx);
	}

	/* update the mapping to point to the new fid and times */
	map.ms_cid = CREATE_OBJECT(logelem_object_p).i_up->dl_new_cid;
	map.ms_fid = logelem_object_p->i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_create.dl_fid);
	map.ms_times = logelem_object_p->i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_create.dl_times);
	xx = maptbl_set(logelem_object_p->i_maptbl_object_p, &map, 1);
	if (xx) {
		dbug_leave("logelem_roll_create");
		return (EIO);
	}
	dbug_leave("logelem_roll_create");
	return (0);
}
/*
 * -----------------------------------------------------------------
 *			logelem_roll_remove
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */


int
logelem_roll_remove(cfsd_logelem_object_t *logelem_object_p, ulong_t *seqp)
{

	int xx;
	cfs_fid_t *fp;
	cfs_fid_t dirfid;
	struct cfs_dlog_mapping_space map, dirmap;
	cfs_timestruc_t ctime, mtime;
	int time_log;
	cfs_dlog_tm_t *tmp;
	cfs_fid_t filefid2;
	cfs_vattr_t va;
	cfs_timestruc_t *ctimep;

	dbug_enter("logelem_roll_remove");
	/* get the mapping for this cid if it exists */
	xx = maptbl_get(logelem_object_p->i_maptbl_object_p,
	    REMOVE_OBJECT(logelem_object_p).i_up->dl_child_cid, &map);
	if (xx == -1) {
		logelem_log_opfailed(logelem_object_p, "Remove",
		    gettext("error mapping cid"), NULL, 0);
		dbug_leave("logelem_roll_remove");
		return (EIO);
	}

	/* done if there was a conflict on the file */
	if (map.ms_fid == X_CONFLICT) {
		logelem_log_opfailed(logelem_object_p, "Remove",
		    gettext("file conflict"), NULL, 0);
		dbug_leave("logelem_roll_remove");
		return (0);
	}

	/* done if the file is optimized out */
	if (map.ms_fid == X_OPTIMIZED) {
		dbug_leave("logelem_roll_remove");
		return (0);
	}

	/* if a mapping was not found */
	if (xx) {
		/* dummy up mapping so we get values from the cache */
		map.ms_cid = REMOVE_OBJECT(logelem_object_p).i_up->dl_child_cid;
		map.ms_fid = 0;
		map.ms_times = 0;
	}

	/* if we have timestamps in the mapping */
	if (map.ms_times) {
		/* get the times */
		xx = logfile_offset(logelem_object_p->i_logfile_object_p,
		    map.ms_times, (caddr_t *)&tmp);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Remove",
			    gettext("error getting logfile offset"), NULL, 0);
			dbug_leave("logelem_roll_remove");
			return (EIO);
		}
		ctime = tmp->tm_ctime;
		mtime = tmp->tm_mtime;
		time_log = 0;
	}

	/* else get the timestamps from the log entry */
	else {
		ctime = REMOVE_OBJECT(logelem_object_p).i_up->dl_ctime;
		mtime = REMOVE_OBJECT(logelem_object_p).i_up->dl_mtime;
		time_log = 1;
	}

	/* get the fid of the parent directory */
	xx = maptbl_get(logelem_object_p->i_maptbl_object_p,
	    REMOVE_OBJECT(logelem_object_p).i_up->dl_parent_cid, &dirmap);
	if (xx == -1) {
		logelem_log_opfailed(logelem_object_p, "Remove",
		    gettext("error mapping fid"), NULL, 0);
		dbug_leave("logelem_roll_remove");
		return (EIO);
	}
	/* if error from getting map or no fid in map (ms_fid == 0) */
	if (xx || (dirmap.ms_fid <= 0)) {
		xx = kmod_cidtofid(logelem_object_p->i_kmod_object_p,
		    &REMOVE_OBJECT(logelem_object_p).i_up->dl_parent_cid,
		    &dirfid);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Remove",
			    gettext("Parent directory no longer exists"),
			    REMOVE_OBJECT(logelem_object_p).i_namep, xx);
			logelem_log_opskipped(logelem_object_p,
			    REMOVE_OBJECT(logelem_object_p).i_namep);
			dbug_leave("logelem_roll_remove");
			return (0);
		}
	} else {
		xx = logfile_offset(logelem_object_p->i_logfile_object_p,
		    dirmap.ms_fid, (caddr_t *)&fp);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Remove",
			    gettext("error getting logfile offset"), NULL, 0);
			dbug_leave("logelem_roll_remove");
			return (EIO);
		}
		dirfid = *fp;
		dbug_assert(dirfid.fid_len);
	}

	/* get file attributes */
	xx = kmod_getattrname(logelem_object_p->i_kmod_object_p, &dirfid,
	    REMOVE_OBJECT(logelem_object_p).i_namep,
	    &REMOVE_OBJECT(logelem_object_p).i_up->dl_cred,
	    &va, &filefid2);
	if ((xx == ETIMEDOUT) || (xx == EIO)) {
		dbug_leave("logelem_roll_remove");
		return (ETIMEDOUT);
	}

	/* if the file no longer exists on the back fs */
	if (xx == ENOENT) {
		logelem_log_opfailed(logelem_object_p, "Remove",
		    gettext("File no longer exists."),
		    REMOVE_OBJECT(logelem_object_p).i_namep, xx);
		logelem_log_opskipped(logelem_object_p,
		    REMOVE_OBJECT(logelem_object_p).i_namep);
		dbug_leave("logelem_roll_remove");
		return (0);
	} else if (xx) {
		logelem_log_opfailed(logelem_object_p, "Remove",
		    gettext("Cannot get file attributes from server"),
		    REMOVE_OBJECT(logelem_object_p).i_namep, xx);
		logelem_log_opskipped(logelem_object_p,
		    REMOVE_OBJECT(logelem_object_p).i_namep);
		dbug_leave("logelem_roll_remove");
		return (0);
	}

	/* conflict if mtime changed */
	if (TIMECHANGE(mtime, va.va_mtime)) {
		logelem_log_timelogmesg(logelem_object_p, "Remove",
		    REMOVE_OBJECT(logelem_object_p).i_namep,
		    gettext("File modified"), time_log);
		logelem_log_opskipped(logelem_object_p,
		    REMOVE_OBJECT(logelem_object_p).i_namep);
		dbug_leave("logelem_roll_remove");
		return (0);
	}

	/* conflict if ctime changed */
	else if (TIMECHANGE(ctime, va.va_ctime)) {
		logelem_log_timelogmesg(logelem_object_p, "Remove",
		    REMOVE_OBJECT(logelem_object_p).i_namep,
		    gettext("File changed"), time_log);
		logelem_log_opskipped(logelem_object_p,
		    REMOVE_OBJECT(logelem_object_p).i_namep);
		dbug_leave("logelem_roll_remove");
		return (0);
	}

	ctimep = (va.va_nlink > 1) ?
	    &REMOVE_OBJECT(logelem_object_p).i_up->dl_ctime : NULL;

	/* do the remove */
	xx = kmod_remove(logelem_object_p->i_kmod_object_p, &dirfid,
	    &REMOVE_OBJECT(logelem_object_p).i_up->dl_child_cid,
	    REMOVE_OBJECT(logelem_object_p).i_namep,
	    &REMOVE_OBJECT(logelem_object_p).i_up->dl_cred, ctimep);
	if (xx) {
		if ((xx == ETIMEDOUT) || (xx == EIO)) {
			dbug_leave("logelem_roll_remove");
			return (ETIMEDOUT);
		}

		/* remove failed */
		logelem_log_opfailed(logelem_object_p, "Remove", NULL,
		    REMOVE_OBJECT(logelem_object_p).i_namep, xx);
		logelem_log_opskipped(logelem_object_p,
		    REMOVE_OBJECT(logelem_object_p).i_namep);
		dbug_leave("logelem_roll_remove");
		return (0);
	}

	/* record new ctime if multiple links to file */
	if (ctimep) {
		REMOVE_OBJECT(logelem_object_p).i_up->dl_mtime = mtime;
		map.ms_times = logelem_object_p->i_offset +
		    offsetof(cfs_dlog_entry_t, dl_u.dl_remove.dl_times);
		xx = maptbl_set(logelem_object_p->i_maptbl_object_p, &map, 1);
		if (xx) {
			dbug_leave("logelem_roll_remove");
			return (EIO);
		}
	}

	dbug_leave("logelem_roll_remove");
	return (0);
}
/*
 * -----------------------------------------------------------------
 *			logelem_roll_rmdir
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

int
logelem_roll_rmdir(cfsd_logelem_object_t *logelem_object_p, ulong_t *seqp)
{
	int xx;
	cfs_fid_t *fp;
	cfs_fid_t dirfid;
	struct cfs_dlog_mapping_space map;

	dbug_enter("logelem_roll_rmdir");

	/* get the fid of the parent directory */
	xx = maptbl_get(logelem_object_p->i_maptbl_object_p,
	    RMDIR_OBJECT(logelem_object_p).i_up->dl_parent_cid, &map);
	if (xx == -1) {
		logelem_log_opfailed(logelem_object_p, "Remove Directory",
		    gettext("error mapping fid"), NULL, 0);
		dbug_leave("logelem_roll_rmdir");
		return (EIO);
	}
	/* if error from getting map or no fid in map (ms_fid == 0) */
	if (xx || (map.ms_fid <= 0)) {
		xx = kmod_cidtofid(logelem_object_p->i_kmod_object_p,
		    &RMDIR_OBJECT(logelem_object_p).i_up->dl_parent_cid,
		    &dirfid);
		if (xx) {
			logelem_log_opfailed(logelem_object_p,
			    gettext("Remove Directory"),
			    gettext("Parent directory no longer exists"),
			    RMDIR_OBJECT(logelem_object_p).i_namep, xx);
			logelem_log_opskipped(logelem_object_p,
			    RMDIR_OBJECT(logelem_object_p).i_namep);
			dbug_leave("logelem_roll_rmdir");
			return (0);
		}
	} else {
		xx = logfile_offset(logelem_object_p->i_logfile_object_p,
		    map.ms_fid, (caddr_t *)&fp);
		if (xx) {
			logelem_log_opfailed(logelem_object_p,
			    "Remove Directory",
			    gettext("error getting logfile offset"), NULL, 0);
			dbug_leave("logelem_roll_rmdir");
			return (EIO);
		}
		dirfid = *fp;
		dbug_assert(dirfid.fid_len);
	}

	/* perform the rmdir */
	xx = kmod_rmdir(logelem_object_p->i_kmod_object_p, &dirfid,
	    RMDIR_OBJECT(logelem_object_p).i_namep,
	    &RMDIR_OBJECT(logelem_object_p).i_up->dl_cred);
	if (xx) {
		if ((xx == ETIMEDOUT) || (xx == EIO)) {
			dbug_leave("logelem_roll_rmdir");
			return (ETIMEDOUT);
		}

		logelem_log_opfailed(logelem_object_p, "Remove Directory", NULL,
		    RMDIR_OBJECT(logelem_object_p).i_namep, xx);
		logelem_log_opskipped(logelem_object_p,
		    RMDIR_OBJECT(logelem_object_p).i_namep);
		dbug_leave("logelem_roll_rmdir");
		return (0);
	}
	dbug_leave("logelem_roll_rmdir");
	return (0);
}
/*
 * -----------------------------------------------------------------
 *			logelem_roll_mkdir
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

int
logelem_roll_mkdir(cfsd_logelem_object_t *logelem_object_p, ulong_t *seqp)
{
	int xx;
	cfs_fid_t *fp;
	cfs_fid_t dirfid;
	struct cfs_dlog_mapping_space map;

	dbug_enter("logelem_roll_mkdir");

	/* get the fid of the parent directory */
	xx = maptbl_get(logelem_object_p->i_maptbl_object_p,
	    MKDIR_OBJECT(logelem_object_p).i_up->dl_parent_cid, &map);
	if (xx == -1) {
		logelem_log_opfailed(logelem_object_p, "Create Directory",
		    gettext("error mapping fid"), NULL, 0);
		dbug_leave("logelem_roll_mkdir");
		return (EIO);
	}
	/* if error from getting map or no fid in map (ms_fid == 0) */
	if (xx || (map.ms_fid <= 0)) {
		xx = kmod_cidtofid(logelem_object_p->i_kmod_object_p,
		    &MKDIR_OBJECT(logelem_object_p).i_up->dl_parent_cid,
		    &dirfid);
		if (xx) {
			logelem_log_opfailed(logelem_object_p,
			    "Create Directory",
			    gettext("Parent directory no longer exists"),
			    MKDIR_OBJECT(logelem_object_p).i_namep, xx);
			logelem_log_opskipped(logelem_object_p,
			    MKDIR_OBJECT(logelem_object_p).i_namep);
			dbug_leave("logelem_roll_mkdir");
			return (0);
		}
	} else {
		xx = logfile_offset(logelem_object_p->i_logfile_object_p,
		    map.ms_fid, (caddr_t *)&fp);
		if (xx) {
			logelem_log_opfailed(logelem_object_p,
			    "Create Directory",
			    gettext("error getting logfile offset"), NULL, 0);
			dbug_leave("logelem_roll_mkdir");
			return (EIO);
		}
		dirfid = *fp;
		dbug_assert(dirfid.fid_len);
	}

	/* perform the mkdir */
	xx = kmod_mkdir(logelem_object_p->i_kmod_object_p, &dirfid,
	    MKDIR_OBJECT(logelem_object_p).i_namep,
	    &MKDIR_OBJECT(logelem_object_p).i_up->dl_child_cid,
	    &MKDIR_OBJECT(logelem_object_p).i_up->dl_attrs,
	    &MKDIR_OBJECT(logelem_object_p).i_up->dl_cred,
	    &MKDIR_OBJECT(logelem_object_p).i_up->dl_fid);
	if (xx) {
		if ((xx == ETIMEDOUT) || (xx == EIO)) {
			dbug_leave("logelem_roll_mkdir");
			return (ETIMEDOUT);
		}

		logelem_log_opfailed(logelem_object_p, "Create Directory", NULL,
		    MKDIR_OBJECT(logelem_object_p).i_namep, xx);
		logelem_log_opskipped(logelem_object_p,
		    MKDIR_OBJECT(logelem_object_p).i_namep);
		dbug_leave("logelem_roll_mkdir");
		return (0);
	}

	/* update the mapping to point to the new fid */
	map.ms_cid = MKDIR_OBJECT(logelem_object_p).i_up->dl_child_cid;
	map.ms_fid = logelem_object_p->i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_mkdir.dl_fid);
	map.ms_times = 0;
	xx = maptbl_set(logelem_object_p->i_maptbl_object_p, &map, 1);
	if (xx) {
		dbug_leave("logelem_roll_mkdir");
		return (EIO);
	}

	dbug_leave("logelem_roll_mkdir");
	return (0);
}

/*
 * -----------------------------------------------------------------
 *			logelem_roll_link
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

int
logelem_roll_link(cfsd_logelem_object_t *logelem_object_p, ulong_t *seqp)
{
	int xx;
	cfs_fid_t *fp;
	cfs_fid_t dirfid, linkfid;
	struct cfs_dlog_mapping_space map, dirmap;
	cfs_timestruc_t ctime, mtime;
	cfs_dlog_tm_t *tmp;
	int time_log;
	cfs_vattr_t va;

	dbug_enter("logelem_roll_link");

	/* get the mapping for the child cid if it exists */
	xx = maptbl_get(logelem_object_p->i_maptbl_object_p,
	    LINK_OBJECT(logelem_object_p).i_up->dl_child_cid, &map);
	if (xx == -1) {
		logelem_log_opfailed(logelem_object_p, "Link",
		    gettext("error mapping cid"), NULL, 0);
		dbug_leave("logelem_roll_link");
		return (EIO);
	}
	/* if a mapping was not found */
	if (xx) {
		/* dummy up mapping so we get values from the cache */
		map.ms_cid = LINK_OBJECT(logelem_object_p).i_up->dl_child_cid;
		map.ms_fid = 0;
		map.ms_times = 0;
	}

	/* done if there was a conflict on the file */
	if (map.ms_fid == X_CONFLICT) {
		logelem_log_opfailed(logelem_object_p, "Link",
		    gettext("file conflict"), NULL, 0);
		dbug_leave("logelem_roll_link");
		return (0);
	}
	/* done if the file is optimized out */
	if (map.ms_fid == X_OPTIMIZED) {
		dbug_leave("logelem_roll_link");
		return (0);
	}
	/* if we have a fid in the mapping */
	if (map.ms_fid) {
		/* get the fid */
		xx = logfile_offset(logelem_object_p->i_logfile_object_p,
		    map.ms_fid, (caddr_t *)&fp);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Link",
			    gettext("error getting logfile offset"), NULL, 0);
			dbug_leave("logelem_roll_link");
			return (EIO);
		}
		linkfid = *fp;
		dbug_assert(linkfid.fid_len);
	}

	/* else get the fid from the cache */
	else {
		xx = kmod_cidtofid(logelem_object_p->i_kmod_object_p,
		    &LINK_OBJECT(logelem_object_p).i_up->dl_child_cid,
		    &linkfid);
		if (xx == ENOENT) {
			dbug_leave("logelem_roll_link");
			return (0);
		}
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Link",
			    gettext("File is no longer in the cache"),
			    LINK_OBJECT(logelem_object_p).i_namep, xx);
			logelem_log_opskipped(logelem_object_p,
			    LINK_OBJECT(logelem_object_p).i_namep);
			dbug_leave("logelem_roll_link");
			return (0);
		}
	}

	/* if we have timestamps in the mapping */
	if (map.ms_times) {
		/* get the times */
		xx = logfile_offset(logelem_object_p->i_logfile_object_p,
		    map.ms_times, (caddr_t *)&tmp);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Link",
			    gettext("error getting logfile offset"), NULL, 0);
			dbug_leave("logelem_roll_link");
			return (EIO);
		}
		ctime = tmp->tm_ctime;
		mtime = tmp->tm_mtime;
		time_log = 0;
	}

	/* else get the timestamps from the log entry */
	else {
		ctime = LINK_OBJECT(logelem_object_p).i_up->dl_ctime;
		mtime = LINK_OBJECT(logelem_object_p).i_up->dl_mtime;
		time_log = 1;
	}

	/* get the attributes of the file from the back fs */
	xx = kmod_getattrfid(logelem_object_p->i_kmod_object_p, &linkfid,
	    &LINK_OBJECT(logelem_object_p).i_up->dl_cred, &va);
	if ((xx == ETIMEDOUT) || (xx == EIO)) {
		dbug_leave("logelem_roll_link");
		return (ETIMEDOUT);
	}
	if (xx) {
		logelem_log_opfailed(logelem_object_p, "Link",
		    gettext("error getting attributes"), NULL, xx);
		logelem_log_opskipped(logelem_object_p,
		    LINK_OBJECT(logelem_object_p).i_namep);
		dbug_leave("logelem_roll_link");
		return (0);
	}

	/* conflict if mtime changed */
	if (TIMECHANGE(mtime, va.va_mtime)) {
		logelem_log_timelogmesg(logelem_object_p, "Link",
		    LINK_OBJECT(logelem_object_p).i_namep,
		    gettext("File modified"), time_log);
		logelem_log_opskipped(logelem_object_p,
		    LINK_OBJECT(logelem_object_p).i_namep);
		dbug_leave("logelem_roll_link");
		return (0);
	}

	/* conflict if ctime changed */
	else if (TIMECHANGE(ctime, va.va_ctime)) {
		logelem_log_timelogmesg(logelem_object_p, "Link",
		    LINK_OBJECT(logelem_object_p).i_namep,
		    gettext("File changed"), time_log);
		logelem_log_opskipped(logelem_object_p,
		    LINK_OBJECT(logelem_object_p).i_namep);
		dbug_leave("logelem_roll_link");
		return (0);
	}

	/* get the fid of the parent directory */
	xx = maptbl_get(logelem_object_p->i_maptbl_object_p,
	    LINK_OBJECT(logelem_object_p).i_up->dl_parent_cid, &dirmap);
	if (xx == -1) {
		logelem_log_opfailed(logelem_object_p, "Link",
		    gettext("error mapping fid"), NULL, 0);
		dbug_leave("logelem_roll_link");
		return (EIO);
	}
	/* if error from getting map or no fid in map (ms_fid == 0) */
	if (xx || (dirmap.ms_fid <= 0)) {
		xx = kmod_cidtofid(logelem_object_p->i_kmod_object_p,
		    &LINK_OBJECT(logelem_object_p).i_up->dl_parent_cid,
		    &dirfid);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Link",
			    gettext("Parent directory no longer exists"),
			    LINK_OBJECT(logelem_object_p).i_namep, xx);
			logelem_log_opskipped(logelem_object_p,
			    LINK_OBJECT(logelem_object_p).i_namep);
			dbug_leave("logelem_roll_link");
			return (0);
		}
	} else {
		xx = logfile_offset(logelem_object_p->i_logfile_object_p,
		    dirmap.ms_fid, (caddr_t *)&fp);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Link",
			    gettext("error getting logfile offset"), NULL, 0);
			dbug_leave("logelem_roll_link");
			return (EIO);
		}
		dirfid = *fp;
		dbug_assert(dirfid.fid_len);
	}

	/* do the link */
	xx = kmod_link(logelem_object_p->i_kmod_object_p, &dirfid,
	    LINK_OBJECT(logelem_object_p).i_namep, &linkfid,
	    &LINK_OBJECT(logelem_object_p).i_up->dl_child_cid,
	    &LINK_OBJECT(logelem_object_p).i_up->dl_cred,
	    &LINK_OBJECT(logelem_object_p).i_up->dl_ctime);
	if (xx) {
		if ((xx == ETIMEDOUT) || (xx == EIO)) {
			dbug_leave("logelem_roll_link");
			return (ETIMEDOUT);
		}

		logelem_log_opfailed(logelem_object_p, "Link", NULL,
		    LINK_OBJECT(logelem_object_p).i_namep, xx);
		logelem_log_opskipped(logelem_object_p,
		    LINK_OBJECT(logelem_object_p).i_namep);
		dbug_leave("logelem_roll_link");
		return (0);
	}

	/* update the mapping with the new time */
	LINK_OBJECT(logelem_object_p).i_up->dl_mtime = mtime;
	map.ms_times = logelem_object_p->i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_link.dl_times);
	xx = maptbl_set(logelem_object_p->i_maptbl_object_p, &map, 1);
	if (xx) {
		dbug_leave("logelem_roll_link");
		return (EIO);
	}
	dbug_leave("logelem_roll_link");
	return (0);
}
/*
 * -----------------------------------------------------------------
 *			logelem_roll_symlink
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

int
logelem_roll_symlink(cfsd_logelem_object_t *logelem_object_p, ulong_t *seqp)
{
	int xx;
	cfs_fid_t *fp;
	cfs_fid_t dirfid;
	struct cfs_dlog_mapping_space map;

	dbug_enter("logelem_roll_symlink");

	/* see if the symlink no longer exists in the cache */
#if 0
	xx = kmod_exists(logelem_object_p->i_kmod_object_p,
	    &SYMLINK_OBJECT(logelem_object_p).i_up->dl_child_cid);
	if (xx) {
		dbug_assert(xx == ENOENT);

		/* indicate ignore future operations on symlink */
		map.ms_cid =
		    SYMLINK_OBJECT(logelem_object_p).i_up->dl_child_cid;
		map.ms_fid = X_OPTIMIZED;
		map.ms_times = 0;
		xx = maptbl_set(maptbl_object_p, &map, 1);
		if (xx) {
			dbug_leave("logelem_roll_symlink");
			return (EIO);
		}
		dbug_leave("logelem_roll_symlink");
		return (0);
	}
#endif

	/* get the fid of the parent directory */
	xx = maptbl_get(logelem_object_p->i_maptbl_object_p,
	    SYMLINK_OBJECT(logelem_object_p).i_up->dl_parent_cid, &map);
	if (xx == -1) {
		logelem_log_opfailed(logelem_object_p, "Symink",
		    gettext("error mapping fid"), NULL, 0);
		dbug_leave("logelem_roll_symlink");
		return (EIO);
	}
	/* if error from getting map or no fid in map (ms_fid == 0) */
	if (xx || (map.ms_fid <= 0)) {
		xx = kmod_cidtofid(logelem_object_p->i_kmod_object_p,
		    &SYMLINK_OBJECT(logelem_object_p).i_up->dl_parent_cid,
		    &dirfid);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Symlink",
			    gettext("Parent directory no longer exists"),
			    SYMLINK_OBJECT(logelem_object_p).i_namep, xx);
			logelem_log_opskipped(logelem_object_p,
			    SYMLINK_OBJECT(logelem_object_p).i_namep);
			dbug_leave("logelem_roll_symlink");
			return (0);
		}
	} else {
		xx = logfile_offset(logelem_object_p->i_logfile_object_p,
		    map.ms_fid, (caddr_t *)&fp);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Symlink",
			    gettext("error getting logfile offset"), NULL, 0);
			dbug_leave("logelem_roll_symlink");
			return (EIO);
		}
		dirfid = *fp;
		dbug_assert(dirfid.fid_len);
	}

	/* if the file exists on the back fs */
	xx = kmod_getattrname(logelem_object_p->i_kmod_object_p, &dirfid,
	    SYMLINK_OBJECT(logelem_object_p).i_namep,
	    &SYMLINK_OBJECT(logelem_object_p).i_up->dl_cred,
	    NULL, NULL);
	if ((xx == ETIMEDOUT) || (xx == EIO)) {
		dbug_leave("logelem_roll_symlink");
		return (ETIMEDOUT);
	}
	/* if the file exists on the back file system */
	if (xx == 0) {
		logelem_log_opfailed(logelem_object_p, "Symlink",
		    gettext("File created while disconnected"),
		    SYMLINK_OBJECT(logelem_object_p).i_namep, xx);
		logelem_log_opskipped(logelem_object_p,
		    SYMLINK_OBJECT(logelem_object_p).i_namep);
		dbug_leave("logelem_roll_symlink");
		return (0);
	}

	/* do the symlink */
	xx = kmod_symlink(logelem_object_p->i_kmod_object_p, &dirfid,
	    SYMLINK_OBJECT(logelem_object_p).i_namep,
	    &SYMLINK_OBJECT(logelem_object_p).i_up->dl_child_cid,
	    SYMLINK_OBJECT(logelem_object_p).i_contentsp,
	    &SYMLINK_OBJECT(logelem_object_p).i_up->dl_attrs,
	    &SYMLINK_OBJECT(logelem_object_p).i_up->dl_cred,
	    &SYMLINK_OBJECT(logelem_object_p).i_up->dl_fid,
	    &SYMLINK_OBJECT(logelem_object_p).i_up->dl_ctime,
	    &SYMLINK_OBJECT(logelem_object_p).i_up->dl_mtime);
	if (xx) {
		if ((xx == ETIMEDOUT) || (xx == EIO)) {
			dbug_leave("logelem_roll_symlink");
			return (ETIMEDOUT);
		}
		logelem_log_opfailed(logelem_object_p, "Symlink", NULL,
		    SYMLINK_OBJECT(logelem_object_p).i_namep, xx);
		logelem_log_opskipped(logelem_object_p,
		    SYMLINK_OBJECT(logelem_object_p).i_namep);
		dbug_leave("logelem_roll_symlink");
		return (0);
	}

	/* update the mapping to point to the new fid and times */
	map.ms_cid = SYMLINK_OBJECT(logelem_object_p).i_up->dl_child_cid;
	map.ms_fid = logelem_object_p->i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_symlink.dl_fid);
	map.ms_times = logelem_object_p->i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_symlink.dl_times);
	xx = maptbl_set(logelem_object_p->i_maptbl_object_p, &map, 1);
	if (xx) {
		dbug_leave("logelem_roll_symlink");
		return (EIO);
	}
	dbug_leave("logelem_roll_symlink");
	return (0);
}
/*
 * -----------------------------------------------------------------
 *			logelem_roll_rename
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

int
logelem_roll_rename(cfsd_logelem_object_t *logelem_object_p, ulong_t *seqp)
{
	int xx;
	cfs_fid_t *fp;
	cfs_fid_t odirfid, ndirfid;
	struct cfs_dlog_mapping_space map, dirmap, delmap;
	cfs_dlog_tm_t *tmp;
	cfs_vattr_t va;
	cfs_timestruc_t mtime, ctime;
	cfs_timestruc_t delmtime, delctime;
	cfs_timestruc_t *delctimep = NULL;
	int time_log;

	dbug_enter("logelem_roll_rename");

	/* get the mapping for the child cid if it exists */
	xx = maptbl_get(logelem_object_p->i_maptbl_object_p,
	    RENAME_OBJECT(logelem_object_p).i_up->dl_child_cid, &map);
	if (xx == -1) {
		logelem_log_opfailed(logelem_object_p, "Rename",
		    gettext("error mapping cid"), NULL, 0);
		dbug_leave("logelem_roll_rename");
		return (EIO);
	}
	/* if a mapping was not found */
	if (xx) {
		/* dummy up mapping so we get values from the cache */
		map.ms_cid = RENAME_OBJECT(logelem_object_p).i_up->dl_child_cid;
		map.ms_fid = 0;
		map.ms_times = 0;
	}

	/* done if there was a conflict on the file */
	if (map.ms_fid == X_CONFLICT) {
		logelem_log_opfailed(logelem_object_p, "Rename",
		    gettext("file conflict"), NULL, 0);
		dbug_leave("logelem_roll_rename");
		return (0);
	}
	/* done if the file is optimized out */
	if (map.ms_fid == X_OPTIMIZED) {
		dbug_leave("logelem_roll_rename");
		return (0);
	}
	/* if we have timestamps in the mapping */
	if (map.ms_times) {
		/* get the times */
		xx = logfile_offset(logelem_object_p->i_logfile_object_p,
		    map.ms_times, (caddr_t *)&tmp);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Rename",
			    gettext("error getting logfile offset"), NULL, 0);
			dbug_leave("logelem_roll_rename");
			return (EIO);
		}
		ctime = tmp->tm_ctime;
		mtime = tmp->tm_mtime;
		time_log = 0;
	}

	/* else get the timestamps from the log entry */
	else {
		ctime = RENAME_OBJECT(logelem_object_p).i_up->dl_ctime;
		mtime = RENAME_OBJECT(logelem_object_p).i_up->dl_mtime;
		time_log = 1;
	}

	/* get the fid of the old parent directory */
	xx = maptbl_get(logelem_object_p->i_maptbl_object_p,
	    RENAME_OBJECT(logelem_object_p).i_up->dl_oparent_cid, &dirmap);
	if (xx == -1) {
		logelem_log_opfailed(logelem_object_p, "Rename",
		    gettext("error mapping fid"), NULL, 0);
		dbug_leave("logelem_roll_rename");
		return (EIO);
	}
	/* if error from getting map or no fid in map (ms_fid == 0) */
	if (xx || (dirmap.ms_fid <= 0)) {
		xx = kmod_cidtofid(logelem_object_p->i_kmod_object_p,
		    &RENAME_OBJECT(logelem_object_p).i_up->dl_oparent_cid,
		    &odirfid);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Rename",
			    gettext("Original directory no longer exists"),
			    RENAME_OBJECT(logelem_object_p).i_orignamep, xx);
			logelem_log_opskipped(logelem_object_p,
			    RENAME_OBJECT(logelem_object_p).i_orignamep);
			dbug_leave("logelem_roll_rename");
			return (0);
		}
	} else {
		xx = logfile_offset(logelem_object_p->i_logfile_object_p,
		    dirmap.ms_fid, (caddr_t *)&fp);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Rename",
			    gettext("error getting logfile offset"), NULL, 0);
			dbug_leave("logelem_roll_rename");
			return (EIO);
		}
		odirfid = *fp;
		dbug_assert(odirfid.fid_len);
	}

	/* get the fid of the new parent directory */
	xx = maptbl_get(logelem_object_p->i_maptbl_object_p,
	    RENAME_OBJECT(logelem_object_p).i_up->dl_nparent_cid, &dirmap);
	if (xx == -1) {
		logelem_log_opfailed(logelem_object_p, "Rename",
		    gettext("error mapping fid"), NULL, 0);
		dbug_leave("logelem_roll_rename");
		return (EIO);
	}
	/* if error from getting map or no fid in map (ms_fid == 0) */
	if (xx || (dirmap.ms_fid <= 0)) {
		xx = kmod_cidtofid(logelem_object_p->i_kmod_object_p,
		    &RENAME_OBJECT(logelem_object_p).i_up->dl_nparent_cid,
		    &ndirfid);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Rename",
			    gettext("Target directory no longer exists"),
			    RENAME_OBJECT(logelem_object_p).i_orignamep, xx);
			logelem_log_opskipped(logelem_object_p,
			    RENAME_OBJECT(logelem_object_p).i_orignamep);
			dbug_leave("logelem_roll_rename");
			return (0);
		}
	} else {
		xx = logfile_offset(logelem_object_p->i_logfile_object_p,
		    dirmap.ms_fid, (caddr_t *)&fp);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Rename",
			    gettext("error getting logfile offset"), NULL, 0);
			dbug_leave("logelem_roll_rename");
			return (EIO);
		}
		ndirfid = *fp;
		dbug_assert(ndirfid.fid_len);
	}

	/* get the attributes of the file from the back fs */
	xx = kmod_getattrname(logelem_object_p->i_kmod_object_p, &odirfid,
	    RENAME_OBJECT(logelem_object_p).i_orignamep,
	    &RENAME_OBJECT(logelem_object_p).i_up->dl_cred,
	    &va, NULL);
	if ((xx == ETIMEDOUT) || (xx == EIO)) {
		dbug_leave("logelem_roll_rename");
		return (ETIMEDOUT);
	}
	if (xx) {
		logelem_log_opfailed(logelem_object_p, "Rename",
		    gettext("Cannot get attributes on file"),
		    RENAME_OBJECT(logelem_object_p).i_orignamep, xx);
		logelem_log_opskipped(logelem_object_p,
		    RENAME_OBJECT(logelem_object_p).i_orignamep);
		dbug_leave("logelem_roll_rename");
		return (0);
	}

	/* conflict if mtime changed */
	if (TIMECHANGE(mtime, va.va_mtime)) {
		logelem_log_timelogmesg(logelem_object_p, "Rename",
		    RENAME_OBJECT(logelem_object_p).i_orignamep,
		    gettext("File modified"), time_log);
		logelem_log_opskipped(logelem_object_p,
		    RENAME_OBJECT(logelem_object_p).i_orignamep);
		dbug_leave("logelem_roll_rename");
		return (0);
	}

	/* conflict if ctime changed */
	else if (TIMECHANGE(ctime, va.va_ctime)) {
		logelem_log_timelogmesg(logelem_object_p, "Rename",
		    RENAME_OBJECT(logelem_object_p).i_orignamep,
		    gettext("File changed"), time_log);
		logelem_log_opskipped(logelem_object_p,
		    RENAME_OBJECT(logelem_object_p).i_orignamep);
		dbug_leave("logelem_roll_rename");
		return (0);
	}

	/* if we are also deleting a file */
	if (RENAME_OBJECT(logelem_object_p).i_up->dl_del_cid.cid_fileno != 0) {
		/* get the mapping for the deleted cid if it exists */
		xx = maptbl_get(logelem_object_p->i_maptbl_object_p,
		    RENAME_OBJECT(logelem_object_p).i_up->dl_del_cid, &delmap);
		if (xx == -1) {
			logelem_log_opfailed(logelem_object_p, "Rename",
			    gettext("error mapping cid"), NULL, 0);
			dbug_leave("logelem_roll_rename");
			return (EIO);
		}
		/* if a mapping was not found */
		if (xx) {
			/* dummy up mapping so we get values from the cache */
			delmap.ms_cid =
			    RENAME_OBJECT(logelem_object_p).i_up->dl_del_cid;
			delmap.ms_fid = 0;
			delmap.ms_times = 0;
		}

		/* if we have timestamps in the mapping */
		if (delmap.ms_times) {
			/* get the times */
			xx = logfile_offset(
			    logelem_object_p->i_logfile_object_p,
			    delmap.ms_times, (caddr_t *)&tmp);
			if (xx) {
				logelem_log_opfailed(logelem_object_p, "Rename",
				    gettext("error getting logfile offset"),
				    NULL, 0);
				dbug_leave("logelem_roll_rename");
				return (EIO);
			}
			delctime = tmp->tm_ctime;
			delmtime = tmp->tm_mtime;
			time_log = 0;
		}

		/* else get the timestamps from the log entry */
		else {
			delctime = RENAME_OBJECT(logelem_object_p).
			    i_up->dl_del_times.tm_ctime;
			delmtime = RENAME_OBJECT(logelem_object_p).
			    i_up->dl_del_times.tm_mtime;
			time_log = 1;
		}

		/* get the attributes of the target file from the back fs */
		xx = kmod_getattrname(logelem_object_p->i_kmod_object_p,
		    &ndirfid,
		    RENAME_OBJECT(logelem_object_p).i_newnamep,
		    &RENAME_OBJECT(logelem_object_p).i_up->dl_cred,
		    &va, NULL);
		if ((xx == ETIMEDOUT) || (xx == EIO)) {
			dbug_leave("logelem_roll_rename");
			return (ETIMEDOUT);
		}
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Rename",
			    gettext("Cannot get attributes on file"),
			    RENAME_OBJECT(logelem_object_p).i_orignamep, xx);
			logelem_log_opskipped(logelem_object_p,
			    RENAME_OBJECT(logelem_object_p).i_orignamep);
			dbug_leave("logelem_roll_rename");
			return (0);
		}

		/* conflict if mtime changed */
		if (TIMECHANGE(delmtime, va.va_mtime)) {
			logelem_log_timelogmesg(logelem_object_p, "Rename",
			    RENAME_OBJECT(logelem_object_p).i_orignamep,
			    gettext("Target modified"), time_log);
			logelem_log_opskipped(logelem_object_p,
			    RENAME_OBJECT(logelem_object_p).i_orignamep);
			dbug_leave("logelem_roll_rename");
			return (0);

		}

		/* conflict if ctime changed */
		else if (TIMECHANGE(delctime, va.va_ctime)) {
			logelem_log_timelogmesg(logelem_object_p, "Rename",
			    RENAME_OBJECT(logelem_object_p).i_orignamep,
			    gettext("Target changed"), time_log);
			logelem_log_opskipped(logelem_object_p,
			    RENAME_OBJECT(logelem_object_p).i_orignamep);
			dbug_leave("logelem_roll_rename");
			return (0);
		}

		delctimep = (va.va_nlink > 1) ?
		    &RENAME_OBJECT(logelem_object_p).
		    i_up->dl_del_times.tm_ctime : NULL;
	}

	/* perform the rename */
	xx = kmod_rename(logelem_object_p->i_kmod_object_p, &odirfid,
	    RENAME_OBJECT(logelem_object_p).i_orignamep, &ndirfid,
	    RENAME_OBJECT(logelem_object_p).i_newnamep,
	    &RENAME_OBJECT(logelem_object_p).i_up->dl_child_cid,
	    &RENAME_OBJECT(logelem_object_p).i_up->dl_cred,
	    &RENAME_OBJECT(logelem_object_p).i_up->dl_ctime, delctimep,
	    &RENAME_OBJECT(logelem_object_p).i_up->dl_del_cid);
	if (xx) {
		if ((xx == ETIMEDOUT) || (xx == EIO)) {
			dbug_leave("logelem_roll_rename");
			return (ETIMEDOUT);
		}
		logelem_log_opfailed(logelem_object_p, "Rename", NULL,
		    RENAME_OBJECT(logelem_object_p).i_orignamep, xx);
		logelem_log_opskipped(logelem_object_p,
		    RENAME_OBJECT(logelem_object_p).i_orignamep);
		dbug_leave("logelem_roll_rename");
		return (0);
	}

	/* update the mapping to point to the new times for the file */
	RENAME_OBJECT(logelem_object_p).i_up->dl_mtime = mtime;
	map.ms_times = logelem_object_p->i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_rename.dl_times);
	xx = maptbl_set(logelem_object_p->i_maptbl_object_p, &map, 1);
	if (xx) {
		dbug_leave("logelem_roll_rename");
		return (EIO);
	}
	/* if we deleted a file with links left */
	if (delctimep) {
		/* update the mapping  to the new times for the deleted file */
		RENAME_OBJECT(logelem_object_p).i_up->dl_del_times.tm_mtime =
		    delmtime;
		delmap.ms_times = logelem_object_p->i_offset +
		    offsetof(cfs_dlog_entry_t, dl_u.dl_rename.dl_del_times);
		xx = maptbl_set(logelem_object_p->i_maptbl_object_p,
		    &delmap, 1);
		if (xx) {
			dbug_leave("logelem_roll_rename");
			return (EIO);
		}
	}

	dbug_leave("logelem_roll_rename");
	return (0);
}
/*
 *			logelem_roll_modified
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

int
logelem_roll_modified(cfsd_logelem_object_t *logelem_object_p, ulong_t *seqp)
{
	int xx;
	cfs_fid_t filefid, *fp;
	struct cfs_dlog_mapping_space map;
	cfs_dlog_tm_t *tmp;
	cfs_timestruc_t ctime, mtime;
	int time_log;
	cachefsio_getinfo_t ginfo;
	cfs_vattr_t va;
	int conflict = 0;

	dbug_enter("logelem_roll_modified");

	dbug_precond(seqp);

	/* get the mapping for this cid if it exists */
	xx = maptbl_get(logelem_object_p->i_maptbl_object_p,
	    MODIFIED_OBJECT(logelem_object_p).i_up->dl_cid, &map);
	if (xx == -1) {
		logelem_log_opfailed(logelem_object_p, "Modified",
		    gettext("error mapping cid"), NULL, 0);
		dbug_leave("logelem_roll_modified");
		return (EIO);
	}
	/* if a mapping was not found */
	if (xx) {
		/* dummy up mapping so we get values from the cache */
		map.ms_cid = MODIFIED_OBJECT(logelem_object_p).i_up->dl_cid;
		map.ms_fid = 0;
		map.ms_times = 0;
	}

	/* done if there was a conflict on the file */
	if (map.ms_fid == X_CONFLICT) {
		logelem_log_opfailed(logelem_object_p, "Modified",
		    gettext("file conflict"), NULL, 0);
		dbug_leave("logelem_roll_modified");
		return (0);
	}
	/* done if the file is optimized out */
	if (map.ms_fid == X_OPTIMIZED) {
		dbug_leave("logelem_roll_modified");
		return (0);
	}
	/* if we have a fid in the mapping */
	if (map.ms_fid) {
		/* get the fid */
		xx = logfile_offset(logelem_object_p->i_logfile_object_p,
		    map.ms_fid, (caddr_t *)&fp);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Modified",
			    gettext("error getting logfile offset"), NULL, 0);
			dbug_leave("logelem_roll_modified");
			return (EIO);
		}
		filefid = *fp;
		dbug_assert(filefid.fid_len);
	}

	/* else get the fid from the cache */
	else {
		xx = kmod_cidtofid(logelem_object_p->i_kmod_object_p,
		    &MODIFIED_OBJECT(logelem_object_p).i_up->dl_cid, &filefid);
		if (xx == ENOENT) {
			dbug_leave("logelem_roll_modified");
			return (0);
		}
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Write",
			    gettext("File is no longer in the cache"),
			    NULL, xx);
			xx = logelem_lostfound(logelem_object_p,
			    &MODIFIED_OBJECT(logelem_object_p).i_up->dl_cid,
			    NULL, NULL,
			    &MODIFIED_OBJECT(logelem_object_p).i_up->dl_cred);
			dbug_leave("logelem_roll_modified");
			return (xx);
		}
	}

	/* get info about the file from the cache */
	xx = kmod_getinfo(logelem_object_p->i_kmod_object_p,
	    &MODIFIED_OBJECT(logelem_object_p).i_up->dl_cid, &ginfo);
	if (xx) {
		logelem_log_opfailed(logelem_object_p, "Write",
		    gettext("File is no longer in the cache"), NULL, xx);
		xx = logelem_lostfound(logelem_object_p,
		    &MODIFIED_OBJECT(logelem_object_p).i_up->dl_cid,
		    NULL, NULL,
		    &MODIFIED_OBJECT(logelem_object_p).i_up->dl_cred);
		dbug_leave("logelem_roll_modified");
		return (xx);
	}

	/* if we are not ready to process this write yet */
	if (*seqp < ginfo.gi_seq) {
		dbug_print(("info", "Defering writing of file '%s' "
		    "current seq %d, metadata seq %d",
		    ginfo.gi_name, *seqp, ginfo.gi_seq));
		*seqp = ginfo.gi_seq;
		dbug_leave("logelem_roll_modified");
		return (EAGAIN);
	} else {
		dbug_print(("info", "Continue writing of file '%s' "
		    "current seq %d, metadata seq %d",
		    ginfo.gi_name, *seqp, ginfo.gi_seq));
	}

	/* if we have timestamps in the mapping */
	if (map.ms_times) {
		/* get the times */
		xx = logfile_offset(logelem_object_p->i_logfile_object_p,
		    map.ms_times, (caddr_t *)&tmp);
		if (xx) {
			logelem_log_opfailed(logelem_object_p, "Modified",
			    gettext("error getting logfile offset"), NULL, 0);
			dbug_leave("logelem_roll_modified");
			return (EIO);
		}
		ctime = tmp->tm_ctime;
		mtime = tmp->tm_mtime;
		time_log = 0;
	}

	/* else get the timestamps from the log entry */
	else {
		ctime = MODIFIED_OBJECT(logelem_object_p).i_up->dl_ctime;
		mtime = MODIFIED_OBJECT(logelem_object_p).i_up->dl_mtime;
		time_log = 1;
	}

	/* get the attributes of the file from the back fs */
	xx = kmod_getattrfid(logelem_object_p->i_kmod_object_p, &filefid,
	    &MODIFIED_OBJECT(logelem_object_p).i_up->dl_cred, &va);
	if ((xx == ETIMEDOUT) || (xx == EIO)) {
		dbug_leave("logelem_roll_modified");
		return (ETIMEDOUT);
	}
	if (xx) {
		logelem_log_opfailed(logelem_object_p, "Modified",
		    gettext("error getting attributes"), NULL, xx);
		xx = logelem_lostfound(logelem_object_p,
		    &MODIFIED_OBJECT(logelem_object_p).i_up->dl_cid,
		    NULL, NULL,
		    &MODIFIED_OBJECT(logelem_object_p).i_up->dl_cred);
		dbug_leave("logelem_roll_modified");
		return (xx);
	}


	/* conflict if mtime changed */
	if (TIMECHANGE(mtime, va.va_mtime)) {
		logelem_log_timelogmesg(logelem_object_p, "Write", NULL,
		    gettext("File modified"), time_log);
		conflict = 1;
	}

	/* conflict if ctime changed */
	else if (TIMECHANGE(ctime, va.va_ctime)) {
		logelem_log_timelogmesg(logelem_object_p, "Write", NULL,
		    gettext("File changed"), time_log);
		conflict = 1;
	}

	/* if a conflict was detected */
	if (conflict) {
		logelem_log_opfailed(logelem_object_p, "Modified",
		    gettext("file conflict"), NULL, 0);
		xx = logelem_lostfound(logelem_object_p,
		    &MODIFIED_OBJECT(logelem_object_p).i_up->dl_cid,
		    NULL, NULL,
		    &MODIFIED_OBJECT(logelem_object_p).i_up->dl_cred);
		dbug_leave("logelem_roll_modified");
		return (xx);
	}

	/* now do the write, get the new times */
	xx = kmod_pushback(logelem_object_p->i_kmod_object_p,
	    &MODIFIED_OBJECT(logelem_object_p).i_up->dl_cid, &filefid,
	    &MODIFIED_OBJECT(logelem_object_p).i_up->dl_cred,
	    &MODIFIED_OBJECT(logelem_object_p).i_up->dl_ctime,
	    &MODIFIED_OBJECT(logelem_object_p).i_up->dl_mtime, 1);
	if ((xx == ETIMEDOUT) || (xx == EIO)) {
		dbug_leave("logelem_roll_modified");
		return (ETIMEDOUT);
	}
	if (xx) {
		logelem_log_opfailed(logelem_object_p, "Write", NULL, NULL, xx);
		xx = logelem_lostfound(logelem_object_p,
		    &MODIFIED_OBJECT(logelem_object_p).i_up->dl_cid,
		    NULL, NULL,
		    &MODIFIED_OBJECT(logelem_object_p).i_up->dl_cred);
		dbug_leave("logelem_roll_modified");
		return (xx);
	}

	/* update the mapping to point to the new times */
	map.ms_times = logelem_object_p->i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_modify.dl_times);
	xx = maptbl_set(logelem_object_p->i_maptbl_object_p, &map, 1);
	if (xx) {
		dbug_leave("logelem_roll_modified");
		return (EIO);
	}
	dbug_leave("logelem_roll_modified");
	return (0);
}
/*
 *			logelem_roll_mapfid
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

int
logelem_roll_mapfid(cfsd_logelem_object_t *logelem_object_p)
{
	int xx;
	struct cfs_dlog_mapping_space map;

	dbug_enter("logelem_roll_mapfid");

	/* map the cid to the fid */
	dbug_assert(MAPFID_OBJECT(logelem_object_p).i_up->dl_fid.fid_len);
	map.ms_cid = MAPFID_OBJECT(logelem_object_p).i_up->dl_cid;
	map.ms_fid = logelem_object_p->i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_mapfid.dl_fid);
	map.ms_times = 0;

	xx = maptbl_set(logelem_object_p->i_maptbl_object_p, &map, 1);
	if (xx) {
		dbug_leave("logelem_roll_mapfid");
		return (EIO);
	}
	dbug_leave("logelem_roll_mapfid");
	return (0);
}
/*
 *			logelem_dump
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

void
logelem_dump(cfsd_logelem_object_t *logelem_object_p)
{
	dbug_enter("logelem_dump");

	switch (logelem_object_p->i_type) {

	case NO_OBJECT_TYPE:
		dbug_assert(0);
		break;

	case SETATTR_OBJECT_TYPE:
		logelem_dump_setattr(logelem_object_p);
		break;

	case SETSECATTR_OBJECT_TYPE:
		logelem_dump_setsecattr(logelem_object_p);
		break;

	case CREATE_OBJECT_TYPE:
		logelem_dump_create(logelem_object_p);
		break;

	case REMOVE_OBJECT_TYPE:
		logelem_dump_remove(logelem_object_p);
		break;

	case RMDIR_OBJECT_TYPE:
		logelem_dump_rmdir(logelem_object_p);
		break;

	case MKDIR_OBJECT_TYPE:
		logelem_dump_mkdir(logelem_object_p);
		break;

	case LINK_OBJECT_TYPE:
		logelem_dump_link(logelem_object_p);
		break;

	case SYMLINK_OBJECT_TYPE:
		logelem_dump_symlink(logelem_object_p);
		break;

	case RENAME_OBJECT_TYPE:
		logelem_dump_rename(logelem_object_p);
		break;

	case MODIFIED_OBJECT_TYPE:
		logelem_dump_modified(logelem_object_p);
		break;

	case MAPFID_OBJECT_TYPE:
		logelem_dump_mapfid(logelem_object_p);
		break;

	default:
		dbug_assert(0);
	}
	dbug_leave("logelem_dump");
}
/*
 *			logelem_dump_setattr
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

void
logelem_dump_setattr(cfsd_logelem_object_t *logelem_object_p)
{
	dbug_enter("logelem_dump_setattr");

	dbug_print(("dump", "SETATTR"));
	dbug_print(("dump", "len %d, valid %d, seq %d",
	    logelem_object_p->i_entp->dl_len,
	    logelem_object_p->i_entp->dl_valid,
	    logelem_object_p->i_entp->dl_seq));
	dbug_print(("dump", "file  cid %"PRIx64", flags 0x%x",
	    SETATTR_OBJECT(logelem_object_p).i_up->dl_cid.cid_fileno,
	    SETATTR_OBJECT(logelem_object_p).i_up->dl_flags));
	dbug_print(("dump", "ctime %x %x, mtime %x %x",
	    SETATTR_OBJECT(logelem_object_p).i_up->dl_ctime.tv_sec,
	    SETATTR_OBJECT(logelem_object_p).i_up->dl_ctime.tv_nsec,
	    SETATTR_OBJECT(logelem_object_p).i_up->dl_mtime.tv_sec,
	    SETATTR_OBJECT(logelem_object_p).i_up->dl_mtime.tv_nsec));
	logelem_print_attr(&SETATTR_OBJECT(logelem_object_p).i_up->dl_attrs);
	logelem_print_cred(&SETATTR_OBJECT(logelem_object_p).i_up->dl_cred);
	dbug_leave("logelem_dump_setattr");
}

/*
 *			logelem_dump_setsecattr
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

void
logelem_dump_setsecattr(cfsd_logelem_object_t *logelem_object_p)
{
	dbug_enter("logelem_dump_setsecattr");

	dbug_print(("dump", "SETSECATTR"));
	dbug_print(("dump", "len %d, valid %d, seq %d",
	    logelem_object_p->i_entp->dl_len,
	    logelem_object_p->i_entp->dl_valid,
	    logelem_object_p->i_entp->dl_seq));
	dbug_print(("dump", "file  cid %"PRIx64,
	    SETSECATTR_OBJECT(logelem_object_p).i_up->dl_cid.cid_fileno));
	dbug_print(("dump", "aclcnt %d dfaclcnt %d",
	    SETSECATTR_OBJECT(logelem_object_p).i_up->dl_aclcnt,
	    SETSECATTR_OBJECT(logelem_object_p).i_up->dl_dfaclcnt));
	dbug_print(("dump", "ctime %x %x, mtime %x %x",
	    SETSECATTR_OBJECT(logelem_object_p).i_up->dl_ctime.tv_sec,
	    SETSECATTR_OBJECT(logelem_object_p).i_up->dl_ctime.tv_nsec,
	    SETSECATTR_OBJECT(logelem_object_p).i_up->dl_mtime.tv_sec,
	    SETSECATTR_OBJECT(logelem_object_p).i_up->dl_mtime.tv_nsec));
	logelem_print_cred(&SETSECATTR_OBJECT(logelem_object_p).i_up->dl_cred);
	dbug_leave("logelem_dump_setsecattr");
}


/*
 *			logelem_dump_create
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

void
logelem_dump_create(cfsd_logelem_object_t *logelem_object_p)
{
	dbug_enter("logelem_dump_create");

	dbug_print(("dump", "CREATE"));
	dbug_print(("dump", "len %d, valid %d, seq %d",
	    logelem_object_p->i_entp->dl_len,
	    logelem_object_p->i_entp->dl_valid,
	    logelem_object_p->i_entp->dl_seq));
	dbug_print(("dump", "directory cid %"PRIx64,
	    CREATE_OBJECT(logelem_object_p).i_up->dl_parent_cid.cid_fileno));
	dbug_print(("dump", "file	  cid %"PRIx64,
	    CREATE_OBJECT(logelem_object_p).i_up->dl_new_cid.cid_fileno));
	dbug_print(("dump", "name \"%s\"",
	    CREATE_OBJECT(logelem_object_p).i_namep));
	dbug_print(("dump", "exclusive %d, mode 0%o, destexists %d",
	    CREATE_OBJECT(logelem_object_p).i_up->dl_excl,
	    CREATE_OBJECT(logelem_object_p).i_up->dl_mode,
	    CREATE_OBJECT(logelem_object_p).i_up->dl_exists));
	dbug_print(("dump", "ctime %x %x, mtime %x %x",
	    CREATE_OBJECT(logelem_object_p).i_up->dl_ctime.tv_sec,
	    CREATE_OBJECT(logelem_object_p).i_up->dl_ctime.tv_nsec,
	    CREATE_OBJECT(logelem_object_p).i_up->dl_mtime.tv_sec,
	    CREATE_OBJECT(logelem_object_p).i_up->dl_mtime.tv_nsec));
	logelem_print_attr(&CREATE_OBJECT(logelem_object_p).i_up->dl_attrs);
	logelem_print_cred(&CREATE_OBJECT(logelem_object_p).i_up->dl_cred);
	dbug_leave("logelem_dump_create");
}


/*
 * -----------------------------------------------------------------
 *			logelem_dump_remove
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

void
logelem_dump_remove(cfsd_logelem_object_t *logelem_object_p)
{
	dbug_enter("logelem_dump_remove");

	dbug_print(("dump", "REMOVE"));
	dbug_print(("dump", "len %d, valid %d, seq %d",
	    logelem_object_p->i_entp->dl_len,
	    logelem_object_p->i_entp->dl_valid,
	    logelem_object_p->i_entp->dl_seq));
	dbug_print(("dump", "file %s cid %"PRIx64", dir cid %"PRIx64,
	    REMOVE_OBJECT(logelem_object_p).i_namep,
	    REMOVE_OBJECT(logelem_object_p).i_up->dl_child_cid.cid_fileno,
	    REMOVE_OBJECT(logelem_object_p).i_up->dl_parent_cid.cid_fileno));
	dbug_print(("dump", "ctime %x %x, mtime %x %x",
	    REMOVE_OBJECT(logelem_object_p).i_up->dl_ctime.tv_sec,
	    REMOVE_OBJECT(logelem_object_p).i_up->dl_ctime.tv_nsec,
	    REMOVE_OBJECT(logelem_object_p).i_up->dl_mtime.tv_sec,
	    REMOVE_OBJECT(logelem_object_p).i_up->dl_mtime.tv_nsec));
	logelem_print_cred(&REMOVE_OBJECT(logelem_object_p).i_up->dl_cred);
	dbug_leave("logelem_dump_remove");
}

/*
 * -----------------------------------------------------------------
 *			logelem_dump_rmdir
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

void
logelem_dump_rmdir(cfsd_logelem_object_t *logelem_object_p)
{
	dbug_enter("logelem_dump_rmdir");

	dbug_print(("dump", "RMDIR"));
	dbug_print(("dump", "len %d, valid %d, seq %d",
	    logelem_object_p->i_entp->dl_len,
	    logelem_object_p->i_entp->dl_valid,
	    logelem_object_p->i_entp->dl_seq));
	dbug_print(("dump", "dir name %s, dir cid %"PRIx64,
	    RMDIR_OBJECT(logelem_object_p).i_namep,
	    RMDIR_OBJECT(logelem_object_p).i_up->dl_parent_cid.cid_fileno));
	logelem_print_cred(&RMDIR_OBJECT(logelem_object_p).i_up->dl_cred);
	dbug_leave("logelem_dump_rmdir");
}

/*
 * -----------------------------------------------------------------
 *			logelem_dump_mkdir
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

void
logelem_dump_mkdir(cfsd_logelem_object_t *logelem_object_p)
{
	dbug_enter("logelem_dump_mkdir");

	dbug_print(("dump", "MKDIR"));
	dbug_print(("dump", "len %d, valid %d, seq %d",
	    logelem_object_p->i_entp->dl_len,
	    logelem_object_p->i_entp->dl_valid,
	    logelem_object_p->i_entp->dl_seq));
	dbug_print(("dump", "file %s cid %"PRIx64", dir cid %"PRIx64,
	    MKDIR_OBJECT(logelem_object_p).i_namep,
	    MKDIR_OBJECT(logelem_object_p).i_up->dl_child_cid.cid_fileno,
	    MKDIR_OBJECT(logelem_object_p).i_up->dl_parent_cid.cid_fileno));
	logelem_print_attr(&MKDIR_OBJECT(logelem_object_p).i_up->dl_attrs);
	logelem_print_cred(&MKDIR_OBJECT(logelem_object_p).i_up->dl_cred);
	dbug_leave("logelem_dump_mkdir");
}

/*
 * -----------------------------------------------------------------
 *			logelem_dump_link
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

void
logelem_dump_link(cfsd_logelem_object_t *logelem_object_p)
{
	dbug_enter("logelem_dump_link");

	dbug_print(("dump", "LINK"));
	dbug_print(("dump", "len %d, valid %d, seq %d",
	    logelem_object_p->i_entp->dl_len,
	    logelem_object_p->i_entp->dl_valid,
	    logelem_object_p->i_entp->dl_seq));
	dbug_print(("dump", "name %s, cid to link %"PRIx64", dir cid %"PRIx64,
	    LINK_OBJECT(logelem_object_p).i_namep,
	    LINK_OBJECT(logelem_object_p).i_up->dl_child_cid.cid_fileno,
	    LINK_OBJECT(logelem_object_p).i_up->dl_parent_cid.cid_fileno));
	dbug_print(("dump", "ctime %x %x, mtime %x %x",
	    LINK_OBJECT(logelem_object_p).i_up->dl_ctime.tv_sec,
	    LINK_OBJECT(logelem_object_p).i_up->dl_ctime.tv_nsec,
	    LINK_OBJECT(logelem_object_p).i_up->dl_mtime.tv_sec,
	    LINK_OBJECT(logelem_object_p).i_up->dl_mtime.tv_nsec));
	logelem_print_cred(&LINK_OBJECT(logelem_object_p).i_up->dl_cred);
	dbug_leave("logelem_dump_link");
}
/*
 * -----------------------------------------------------------------
 *			logelem_dump_symlink
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

void
logelem_dump_symlink(cfsd_logelem_object_t *logelem_object_p)
{
	dbug_enter("logelem_dump_symlink");

	dbug_print(("dump", "SYMLINK"));
	dbug_print(("dump", "len %d, valid %d, seq %d",
	    logelem_object_p->i_entp->dl_len,
	    logelem_object_p->i_entp->dl_valid,
	    logelem_object_p->i_entp->dl_seq));
	dbug_print(("dump", "dir cid %"PRIx64,
	    SYMLINK_OBJECT(logelem_object_p).i_up->dl_parent_cid.cid_fileno));
	dbug_print(("dump", "name %s, contents %s, file cid %"PRIx64,
	    SYMLINK_OBJECT(logelem_object_p).i_namep,
	    SYMLINK_OBJECT(logelem_object_p).i_contentsp,
	    SYMLINK_OBJECT(logelem_object_p).i_up->dl_child_cid.cid_fileno));
	logelem_print_attr(&SYMLINK_OBJECT(logelem_object_p).i_up->dl_attrs);
	logelem_print_cred(&SYMLINK_OBJECT(logelem_object_p).i_up->dl_cred);
	dbug_leave("logelem_dump_symlink");
}
/*
 * -----------------------------------------------------------------
 *			logelem_dump_rename
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

void
logelem_dump_rename(cfsd_logelem_object_t *logelem_object_p)
{
	dbug_enter("logelem_dump_rename");

	dbug_print(("dump", "RENAME"));
	dbug_print(("dump", "len %d, valid %d, seq %d",
	    logelem_object_p->i_entp->dl_len,
	    logelem_object_p->i_entp->dl_valid,
	    logelem_object_p->i_entp->dl_seq));
	dbug_print(("dump", "orig dir cid %"PRIx64", new dir cid %"PRIx64,
	    RENAME_OBJECT(logelem_object_p).i_up->dl_oparent_cid.cid_fileno,
	    RENAME_OBJECT(logelem_object_p).i_up->dl_nparent_cid.cid_fileno));
	dbug_print(("dump", "file cid %"PRIx64,
	    RENAME_OBJECT(logelem_object_p).i_up->dl_child_cid.cid_fileno));
	dbug_print(("dump", "orig name '%s', new name '%s'",
	    RENAME_OBJECT(logelem_object_p).i_orignamep,
	    RENAME_OBJECT(logelem_object_p).i_newnamep));
	dbug_print(("dump", "file ctime %x %x, mtime %x %x",
	    RENAME_OBJECT(logelem_object_p).i_up->dl_ctime.tv_sec,
	    RENAME_OBJECT(logelem_object_p).i_up->dl_ctime.tv_nsec,
	    RENAME_OBJECT(logelem_object_p).i_up->dl_mtime.tv_sec,
	    RENAME_OBJECT(logelem_object_p).i_up->dl_mtime.tv_nsec));
	dbug_print(("dump", "deleted cid %"PRIx64,
	    RENAME_OBJECT(logelem_object_p).i_up->dl_del_cid.cid_fileno));
	dbug_print(("dump", "deleted ctime %x %x, mtime %x %x",
	    RENAME_OBJECT(logelem_object_p).i_up->dl_del_times.tm_ctime.tv_sec,
	    RENAME_OBJECT(logelem_object_p).i_up->dl_del_times.tm_ctime.tv_nsec,
	    RENAME_OBJECT(logelem_object_p).i_up->dl_del_times.tm_mtime.tv_sec,
	    RENAME_OBJECT(logelem_object_p).i_up->dl_del_times.tm_mtime.
	    tv_nsec));
	logelem_print_cred(&RENAME_OBJECT(logelem_object_p).i_up->dl_cred);
	dbug_leave("logelem_dump_rename");
}
/*
 *			logelem_dump_modified
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

void
logelem_dump_modified(cfsd_logelem_object_t *logelem_object_p)
{
	dbug_enter("logelem_dump_modified");

	dbug_print(("dump", "MODIFIED"));
	dbug_print(("dump", "len %d, valid %d, seq %d",
	    logelem_object_p->i_entp->dl_len,
	    logelem_object_p->i_entp->dl_valid,
	    logelem_object_p->i_entp->dl_seq));
	dbug_print(("dump", "file	  cid %"PRIx64,
	    MODIFIED_OBJECT(logelem_object_p).i_up->dl_cid.cid_fileno));
	dbug_print(("dump", "ctime %x %x, mtime %x %x",
	    MODIFIED_OBJECT(logelem_object_p).i_up->dl_ctime.tv_sec,
	    MODIFIED_OBJECT(logelem_object_p).i_up->dl_ctime.tv_nsec,
	    MODIFIED_OBJECT(logelem_object_p).i_up->dl_mtime.tv_sec,
	    MODIFIED_OBJECT(logelem_object_p).i_up->dl_mtime.tv_nsec));
	logelem_print_cred(&MODIFIED_OBJECT(logelem_object_p).i_up->dl_cred);
	dbug_leave("logelem_dump_modified");
}
/*
 *			logelem_dump_mapfid
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

void
logelem_dump_mapfid(cfsd_logelem_object_t *logelem_object_p)
{
	dbug_enter("logelem_dump_mapfid");
	dbug_print(("dump", "MAPFID"));
	dbug_print(("dump", "file	  cid %"PRIx64,
	    MAPFID_OBJECT(logelem_object_p).i_up->dl_cid.cid_fileno));
	logelem_format_fid(logelem_object_p,
	    &MAPFID_OBJECT(logelem_object_p).i_up->dl_fid);
	dbug_print(("dump", "fid '%s'", logelem_object_p->i_fidbuf));
	dbug_enter("logelem_dump_mapfid");
}
