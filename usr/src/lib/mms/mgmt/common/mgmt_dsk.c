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
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include "mms_mgmt.h"
#include "mmp_defs.h"
#include "mgmt_sym.h"
#include "mgmt_util.h"
#include "mms_cfg.h"
#include "dda.h"

static char *_SrcFile = __FILE__;
#define	HERE _SrcFile, __LINE__

static int
mgmt_get_dklibname(void *session, char *libname, nvlist_t **dklib);

static int
mgmt_create_dkvol(char *path, char *barcode, uint64_t volsz,
    char **mntpt, char **rpath, nvlist_t *errs);

#define	DEF_DK_LIBNAME	"MMS_Disk_Archive"

/*
 *  mms_mgmt_add_dklib()
 *
 *  Single library for _all_ disk volumes.  Added automatically
 *  the first time a disk virtual drive or disk volume is created.
 *
 */
int
mms_mgmt_add_dklib(void *session, char *libname, nvlist_t *errs)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	char		tid[64];
	char 		cmd[8192];
	char		buf[1024];
	nvlist_t	*dklib = NULL;
	nvlist_t	*nva = NULL;
	char		mmhost[NI_MAXHOST +  NI_MAXSERV + 2]; /* ':' + nul */

	if (!mgmt_chk_auth("solaris.mms.create")) {
		return (EACCES);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	st = mms_cfg_getvar(MMS_CFG_MGR_HOST, mmhost);
	if (st == 0) {
		if (mgmt_compare_hosts(mmhost, "localhost") == 0) {
			st = gethostname(mmhost, sizeof (mmhost));
		}
	}
	if (st != 0) {
		st = MMS_MGMT_NO_MMHOST;
		goto done;
	}

	if (!libname) {
		libname = DEF_DK_LIBNAME;
	}

	st = mgmt_get_dklibname(sessp, libname, &dklib);
	if (st != 0) {
		goto done;
	}

	if (nvlist_exists(dklib, libname)) {
		/* already there, nothing to do */
		goto done;
	}

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "create task['%s'] type[LIBRARY] "
	    "set[LIBRARY.'LibraryName' '%s'] "
	    "set[LIBRARY.'LibraryType' 'DISK'];",
	    tid, libname);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "add disk library",
	    &response);

	if (st != 0) {
		goto done;
	}

	(void) snprintf(buf, sizeof (buf), "LM_%s", libname);

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "create task['%s'] type[LM] "
	    "set[LM.'LMName' '%s'] "
	    "set[LM.'LibraryName' '%s'] "
	    "set[LM.'LMTargetHost' '%s'];",
	    tid, buf, libname, mmhost);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "add disk library",
	    &response);

	if (st == 0) {
		/* online this library */
		st = nvlist_alloc(&nva, NV_UNIQUE_NAME, 0);
		if (st != 0) {
			goto done;
		}
		(void) nvlist_add_string(nva, O_OBJSTATE, "online");
		(void) nvlist_add_string(nva, O_OBJTYPE, "library");
		(void) nvlist_add_string(nva, O_NAME, libname);

		st = mms_mgmt_set_state(sessp, nva, errs);

		nvlist_free(nva);
	}

done:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	if (dklib) {
		nvlist_free(dklib);
	}

	return (st);
}

static int
mgmt_get_dklibname(void *session, char *libname, nvlist_t **dklib)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	char		tid[64];
	char 		cmd[8192];
	char		buf[1024];

	if (!dklib) {
		return (MMS_MGMT_NOARG);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	*dklib = NULL;

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] report[LIBRARY.'LibraryName'] "
	    "reportmode[namevalue] ", tid);

	if (!libname) {
		(void) strlcat(cmd,
		    "match[streq(LIBRARY.'LibraryType' 'DISK')];",
		    sizeof (cmd));
	} else {
		(void) snprintf(buf, sizeof (buf),
		    "match[and "
		    "(streq(LIBRARY.'LibraryType' 'DISK') "
		    "streq(LIBRARY.'LibraryName' '%s'))];",
		    libname);
		(void) strlcat(cmd, buf, sizeof (cmd));
	}

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "mgmt_get_dklib",
	    &response);
	if (st == 0) {
		st = mmp_get_nvattrs("LibraryName", B_FALSE, response,
		    dklib);
		mms_free_rsp(response);
	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

int
mms_mgmt_create_dkvol(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	char		tid[64];
	char 		cmd[8192];
	char		*vdir = NULL;
	char		*barcode = NULL;
	char		*val = NULL;
	uint64_t	sz = 0;
	char		*libname = NULL;
	char		*mpool = NULL;
	char		*mntpt = NULL;
	char		*rpath = NULL;
	nvlist_t	*dklib = NULL;
	char		thishost[1024];

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	mms_trace(MMS_DEBUG, "add dkvol");

	if (!mgmt_chk_auth("solaris.mms.create")) {
		return (EACCES);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &barcode);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	st = nvlist_lookup_string(nvl, "dirname", &vdir);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, "dirname", st);
		return (st);
	}

	st = nvlist_lookup_string(nvl, O_SIZE, &val);
	if (st == 0) {
		st = do_val_mms_size(val, &sz);
		if ((st == 0) && (sz == 0)) {
			st = EINVAL;
		}
	}
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_SIZE, st);
		return (st);
	}

	st = nvlist_lookup_string(nvl, O_MPOOL, &mpool);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_MPOOL, st);
		return (st);
	}

	(void) nvlist_lookup_string(nvl, O_MMSLIB, &libname);

	st = gethostname(thishost, sizeof (thishost));
	if (st != 0) {
		st = errno;
		MGMT_ADD_ERR(errs, "hostname", st);
		return (st);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	/*
	 * We will always use the 'default' "DISK" library.
	 * If it wasn't returned in the list, create it.
	 */
	if (!libname) {
		libname = DEF_DK_LIBNAME;
		(void) nvlist_add_string(nvl, O_MMSLIB, libname);
	}

	st = mgmt_get_dklibname(sessp, libname, &dklib);
	if (st != 0) {
		goto done;
	}

	if (!nvlist_exists(dklib, libname)) {
		st = mms_mgmt_add_dklib(sessp, libname, errs);
	}

	if (st != 0) {
		goto done;
	}

	st = mgmt_create_dkvol(vdir, barcode, sz, &mntpt, &rpath, errs);
	if (st != 0) {
		goto done;
	}

	/* add the cartridge to MMS */
	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "create task['%s'] type[CARTRIDGE] "
	    "set[CARTRIDGE.'CartridgePCL' '%s'] "
	    "set[CARTRIDGE.'CartridgeTypeName' 'DISK'] "
	    "set[CARTRIDGE.'CartridgeGroupName' '%s'] "
	    "set[CARTRIDGE.'LibraryName' '%s'] "
	    "set[CARTRIDGE.'CartridgeMountPoint' '%s'] "
	    "set[CARTRIDGE.'CartridgePath' '%s'];",
	    tid, barcode, mpool, libname, mntpt, rpath);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "create dkvol",
	    &response);

	if (st == 0) {
		/* create the partition */
		st = mms_mgmt_create_partition(sessp, nvl, errs);
	}

done:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	if (dklib) {
		nvlist_free(dklib);
	}

	(void) mms_gen_taskid(tid);

	return (st);
}

static int
mgmt_create_dkvol(char *path, char *barcode, uint64_t volsz,
    char **mntpt, char **rpath, nvlist_t *errs)
{
	int		st;
	int		fd = -1;
	char		fname[MAXPATHLEN + 1];
	char		dname[MAXPATHLEN + 1];
	dda_metadata_t	metadata;
	dda_index_t	idx;
	char		*wpath = NULL;
	struct stat64	sbuf;
	struct statvfs64 vbuf;
	char		pbuf[MAXPATHLEN + 1];
	size_t		rlen;

	if (!path || (volsz == 0)) {
		return (MMS_MGMT_NOARG);
	}

	(void) memset(&metadata, 0, sizeof (dda_metadata_t));
	(void) memset(&idx, 0, sizeof (dda_index_t));
	(void) memset(pbuf, 0, sizeof (pbuf));

	(void) snprintf(fname, sizeof (fname), "%s/%s", path, barcode);

	st = stat64(fname, &sbuf);
	if (st == 0) {
		st = EEXIST;
		MGMT_ADD_ERR(errs, fname, st);
		return (st);
	}

	st = stat64(fname, &sbuf);
	if (st == 0) {
		if (!S_ISDIR(sbuf.st_mode)) {
			st = ENOTDIR;
		}
	} else if ((st = errno) == ENOENT) {
		st = mkdirp(fname, 0740);
		if (st == 0) {
			/* TODO:  set to root:bin for now */
			(void) realpath(fname, pbuf);
			if (pbuf[0] == NULL) {
				st = errno;
			} else {
				st = chown(fname, 0, 2);
			}
		}
	}
	if (st != 0) {
		MGMT_ADD_ERR(errs, fname, st);
		return (st);
	}

	st = statvfs64(fname, &vbuf);
	if (st == 0) {
		if (volsz > (vbuf.f_bsize * vbuf.f_bfree)) {
			st = ENOSPC;
		}
	} else {
		st = errno;
	}

	if (st != 0) {
		MGMT_ADD_ERR(errs, fname, st);
		return (st);
	}

	if (mntpt) {
		st = mgmt_get_mntpt(&vbuf, mntpt);
		if (st != 0) {
			MGMT_ADD_ERR(errs, fname, st);
		}
	}

	/*
	 *  Create the data file.  TODO:  reserve space??
	 */
	(void) snprintf(dname, sizeof (dname), "%s/%s", fname, DDA_DATA_FNAME);
	fd = open64(dname, O_CREAT|O_EXCL|O_RDWR|O_LARGEFILE, 0640);
	if (fd == -1) {
		st = errno;
		MGMT_ADD_ERR(errs, dname, st);
		return (st);
	}

	(void) directio(fd, DIRECTIO_ON);
	/* TODO:  Fix this ownership too */
	(void) fchown(fd, 0, 2);
	(void) close(fd);

	/*
	 * Create the metadata file
	 */
	metadata.dda_version.dda_major = DDA_MAJOR_VERSION;
	metadata.dda_version.dda_minor = DDA_MINOR_VERSION;
	metadata.dda_capacity = volsz;

	(void) snprintf(dname, sizeof (dname), "%s/%s", fname,
	    DDA_METADATA_FNAME);
	fd = open64(dname, O_CREAT|O_EXCL|O_RDWR, 0640);
	if (fd == -1) {
		st = errno;
		MGMT_ADD_ERR(errs, dname, st);
		return (st);
	}
	(void) fchown(fd, 0, 2);

	rlen = write_buf(fd, &metadata, sizeof (dda_metadata_t));
	if (rlen != sizeof (dda_metadata_t)) {
		st = EIO;
		MGMT_ADD_ERR(errs, dname, st);
		(void) close(fd);
		return (st);
	}
	(void) close(fd);

	/* Create the index file containing one empty record */
	(void) snprintf(dname, sizeof (dname), "%s/%s", fname, DDA_INDEX_FNAME);
	fd = open(dname, O_CREAT|O_EXCL|O_RDWR, 0640);
	if (fd == -1) {
		st = errno;
		MGMT_ADD_ERR(errs, dname, st);
		return (st);
	}
	(void) fchown(fd, 0, 2);

	rlen = write_buf(fd, &idx, sizeof (dda_index_t));
	if (rlen != sizeof (dda_index_t)) {
		st = EIO;
		MGMT_ADD_ERR(errs, dname, st);
		(void) close(fd);
		return (st);
	}

	/* TODO:  Cleanup dangling volume dir/files on error */

	wpath = strstr(pbuf, *mntpt);
	if (wpath == NULL) {
		/* can't happen?? */
		st = ENOTDIR;
		MGMT_ADD_ERR(errs, pbuf, st);
		return (st);
	}

	wpath = pbuf + strlen(*mntpt);
	if (*wpath == '/') {
		/* don't include the slash, it upsets DM */
		wpath++;
	}
	*rpath = strdup(wpath);
	return (0);
}

int
mms_mgmt_create_dkdrive(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	char		tid[64];
	char 		cmd[8192];
	char		buf[1024];
	DIR		*dirp = NULL;
	struct dirent	*ent;
	char		thishost[1024];
	char		*dname = NULL;
	char		ddadev[1024];
	nvlist_t	*drvs = NULL;
	char		*libname = NULL;
	char		*val = NULL;
	char		**apps = NULL;
	int		count = 0;
	int		i;

	if (!mgmt_chk_auth("solaris.mms.create")) {
		return (EACCES);
	}

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	/*
	 * find an available dda number.  if ! available, fail, error
	 * msg should tell user how to add new ones.
	 */

	st = nvlist_lookup_string(nvl, O_NAME, &dname);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	(void) nvlist_lookup_string(nvl, O_MMSLIB, &libname);
	if (!libname) {
		libname = DEF_DK_LIBNAME;
	}

	dirp = opendir("/dev/dda");
	if (dirp == NULL) {
		st = errno;
		return (st);
	}

	st = gethostname(thishost, sizeof (thishost));
	if (st != 0) {
		st = errno;
		MGMT_ADD_ERR(errs, "hostname", st);
		return (st);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			goto done;
		}
		sessp = sess;
	}

	/*  Create the library if it doesn't already exist */
	st = mms_mgmt_add_dklib(sessp, libname, errs);
	if (st != 0) {
		goto done;
	}

	/* fetch dkdrives already configured, if any */
	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] reportmode[namevalue] "
	    "report[DM.'DMTargetPath' DM.'DMTargetHost' "
	    "DRIVE.'DriveName'] "
	    "match[streq(DM.'DMTargetHost' '%s')];",
	    tid, thishost);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "lookup drive devs",
	    &response);
	if (st == 0) {
		st = mmp_get_nvattrs("DMTargetPath", B_FALSE, response,
		    &drvs);
		mms_free_rsp(response);
	}

	ddadev[0] = '\0';

	ent = NULL;
	while ((ent = readdir(dirp)) != NULL) {
		if (ent->d_name[0] == '.') {
			continue;
		}

		(void) snprintf(ddadev, sizeof (ddadev), "/dev/dda/%s",
		    ent->d_name);

		if (nvlist_exists(drvs, ddadev)) {
			/* already used */
			ddadev[0] = '\0';
			continue;
		}

		break;
	}
	(void) closedir(dirp);

	if (ddadev[0] == '\0') {
		st = ENODEV;
		goto done;
	}

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "create task['%s'] type[DRIVEGROUP] "
	    "set[DRIVEGROUP.'DriveGroupName' 'DG_%s'];",
	    tid, dname);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "create drivegroup",
	    &response);
	if (st != 0) {
		goto done;
	}

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "create task['%s'] type[DRIVE] "
	    "set[DRIVE.'DriveName' '%s'] "
	    "set[DRIVE.'DriveGroupName' 'DG_%s'] "
	    "set[DRIVE.'LibraryName' '%s'] "
	    "set[DRIVE.'ReserveDrive' 'no'] "
	    "set[DRIVE.'DriveGeometry' '%s']",
	    tid, dname, dname, libname, dname);

	st = nvlist_lookup_string(nvl, O_MSGLEVEL, &val);
	if (st == 0) {
		(void) snprintf(buf, sizeof (buf),
		    " set[DRIVE.'MessageLevel' '%s']",
		    val);
		(void) strlcat(cmd, buf, sizeof (cmd));
	}
	st = nvlist_lookup_string(nvl, O_TRACELEVEL, &val);
	if (st == 0) {
		(void) snprintf(buf, sizeof (buf),
		    " set[DRIVE.'TraceLevel' '%s']",
		    val);
		(void) strlcat(cmd, buf, sizeof (cmd));
	}
	st = nvlist_lookup_string(nvl, O_TRACESZ, &val);
	if (st == 0) {
		st = val_mms_size(val);
		if (st == 0) {
			(void) snprintf(buf, sizeof (buf),
			    " set[DRIVE.'TraceFileSize' '%s']",
			    val);
			(void) strlcat(cmd, buf, sizeof (cmd));
		} else {
			MGMT_ADD_OPTERR(errs, O_TRACESZ, st);
		}
	}
	st = nvlist_lookup_string(nvl, O_UNLOADTM, &val);
	if (st == 0) {
		(void) snprintf(buf, sizeof (buf),
		    " set[DRIVE.'UnloadTime' '%s']",
		    val);
		(void) strlcat(cmd, buf, sizeof (cmd));
	}
	(void) strlcat(cmd, ";", sizeof (cmd));

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "create drive",
	    &response);
	if (st != 0) {
		goto done;
	}

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "create task['%s'] type[DM] "
	    "set[DM.'DMName' 'DM_%s'] "
	    "set[DM.'DriveName' '%s'] "
	    "set[DM.'DMTargetHost' '%s'] "
	    "set[DM.'DMTargetPath' '%s'];",
	    tid, dname, dname, thishost, ddadev);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "create drive",
	    &response);
	if (st != 0) {
		goto done;
	}

	apps = var_to_array(nvl, O_APPS, &count);

	for (i = 0; i < count; i++) {
		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "create task['%s'] type[DRIVEGROUPAPPLICATION] "
		    "set[DRIVEGROUPAPPLICATION.'ApplicationName' '%s'] "
		    "set[DRIVEGROUPAPPLICATION.'DriveGroupName' 'DG_%s'];",
		    tid, apps[i], dname);

		st = mms_mgmt_send_cmd(sessp, tid, cmd, "create drive",
		    &response);
		if (st != 0) {
			goto done;
		}
	}

	if (st == 0) {
		if (!nvlist_exists(nvl, O_OBJSTATE)) {
			(void) nvlist_add_string(nvl, O_OBJSTATE, "online");
		}
		st = mms_mgmt_set_state(sessp, nvl, errs);
	}

done:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	if (apps) {
		mgmt_free_str_arr(apps, count);
	}

	if (drvs) {
		nvlist_free(drvs);
	}

	return (st);
}

int
mms_mgmt_set_dkvol_mode(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	char		tid[64];
	char 		cmd[8192];
	char		buf[1024];
	char		thishost[1024];
	char		*vol = NULL;
	nvlist_t	*nva = NULL;
	nvlist_t	*attrs = NULL;
	int		count = 0;
	nvpair_t	*nvp;
	char		*mntp;
	char		*rpath;
	int		fd = -1;
	dda_metadata_t	metadata;
	char		*readonly = "false";
	flock64_t	flk;

	if (!mgmt_chk_auth("solaris.mms.media")) {
		return (EACCES);
	}

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &vol);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	st = nvlist_lookup_string(nvl, "readonly", &readonly);
	if (st == 0) {
		st = val_truefalse(readonly);
	}
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, "readonly", st);
		return (st);
	}

	st = gethostname(thishost, sizeof (thishost));
	if (st != 0) {
		st = errno;
		MGMT_ADD_ERR(errs, "hostname", st);
		return (st);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	/* TODO:  Uniquely identify the cartridge.  No host name?! */
	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] report[CARTRIDGE] reportmode[namevalue] "
	    "match[streq(CARTRIDGE.'CartridgePCL' '%s')];",
	    tid, vol);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "get dkvol",
	    &response);
	if (st == 0) {
		st = mmp_get_nvattrs("CartridgePCL", B_FALSE, response,
		    &attrs);
		mms_free_rsp(response);
	}

	if (st != 0) {
		goto done;
	}

	/* make sure we only got one */
	nvp = NULL;
	count = 0;

	while ((nvp = nvlist_next_nvpair(attrs, nvp)) != NULL) {
		count++;
	}

	if (count > 1) {
		st = MMS_MGMT_ERR_CART_NOT_UNIQUE;
		MGMT_ADD_ERR(nvl, O_NAME, st);
		goto done;
	} else if (count == 0) {
		st = ENOENT;
		MGMT_ADD_OPTERR(nvl, O_NAME, st);
		goto done;
	}

	nvp = nvlist_next_nvpair(attrs, NULL);
	(void) nvpair_value_nvlist(nvp, &nva);

	st = nvlist_lookup_string(nva, "CartridgeMountPoint", &mntp);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, "cartridge mount point", st);
		goto done;
	}

	st = nvlist_lookup_string(nva, "CartridgePath", &rpath);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, "path to cartridge", st);
		goto done;
	}

	(void) snprintf(buf, sizeof (buf), "%s/%s/%s", mntp, rpath,
	    DDA_METADATA_FNAME);

	fd = open64(buf, O_RDWR);
	if (fd == -1) {
		st = errno;
		MGMT_ADD_ERR(errs, "open cartridge", st);
		goto done;
	}

	/*
	 *  Preclude acting on an in-use cartridge.  Try to
	 *  lock it -- if it's busy, DDA will hold the lock
	 *  so we should fail back to the user.
	 */
	(void) memset(&flk, 0, sizeof (flock64_t));
	flk.l_type = F_WRLCK;
	flk.l_whence = 1;
	flk.l_start = 0;
	flk.l_len = 0;
	if (fcntl(fd, F_SETLK64, &flk)) {
		st = MMS_MGMT_CARTRIDGE_INUSE;
		MGMT_ADD_ERR(errs, O_NAME, st);
		goto done;
	}

	if (read(fd, &metadata, sizeof (dda_metadata_t)) !=
	    sizeof (dda_metadata_t)) {
		st = errno;
		MGMT_ADD_ERR(errs, "read index", st);
		goto done;
	}

	if (strcasecmp(readonly, "true") == 0) {
		metadata.dda_flags |= DDA_FLAG_WPROTECT;
	} else {
		metadata.dda_flags &= ~DDA_FLAG_WPROTECT;
	}

	if (lseek(fd, SEEK_SET, 0) == -1) {
		st = errno;
		MGMT_ADD_ERR(errs, "write index", st);
		goto done;
	}

	if (write_buf(fd, &metadata, sizeof (dda_metadata_t)) !=
	    sizeof (dda_metadata_t)) {
		st = errno;
		MGMT_ADD_ERR(errs, "write index", st);
	}

done:

	if (fd > 0) {
		(void) close(fd);
	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	if (attrs) {
		nvlist_free(attrs);
	}

	return (st);
}

int
mgmt_delete_dkvol(char *volpath, nvlist_t *errs)
{
	int		st;
	struct stat64	sbuf;
	char		buf[1024];

	if (!volpath) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.media")) {
		return (EACCES);
	}

	if (*volpath != '/') {
		st = EINVAL;
		MGMT_ADD_ERR(errs, volpath, st);
		return (st);
	}

	st = stat64(volpath, &sbuf);
	if (st != 0) {
		st = errno;
		if (st == ENOENT) {
			/* not a failure, already removed */
			return (0);
		}
		MGMT_ADD_ERR(errs, volpath, st);
		return (st);
	}

	(void) snprintf(buf, sizeof (buf), "%s/%s", volpath, DDA_DATA_FNAME);
	if (stat64(buf, &sbuf) == 0) {
		(void) unlink(buf);
	}

	(void) snprintf(buf, sizeof (buf), "%s/%s", volpath,
	    DDA_METADATA_FNAME);
	if (stat64(buf, &sbuf) == 0) {
		(void) unlink(buf);
	}

	(void) snprintf(buf, sizeof (buf), "%s/%s", volpath, DDA_INDEX_FNAME);
	if (stat64(buf, &sbuf) == 0) {
		(void) unlink(buf);
	}

	st = rmdir(volpath);
	if (st != 0) {
		st = errno;
		if (st == ENOENT) {
			/* again, not a failure if already gone */
			st = 0;
		} else {
			MGMT_ADD_ERR(errs, volpath, st);
		}
	}

	return (st);
}
