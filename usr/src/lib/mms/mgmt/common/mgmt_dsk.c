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

extern	mms_mgmt_setopt_t dklibopts[];

static int
mgmt_create_dkvol(char *path, uint64_t volsz, nvlist_t *errs);

static int
mgmt_get_dklibname(void *session, char *libname, nvlist_t **lib)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	char		tid[64];
	char 		cmd[8192];

	if (!lib) {
		return (MMS_MGMT_NOARG);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	*lib = NULL;

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] "
	    "match[and( "
	    "streq(LIBRARY.'LibraryName' '%s') "
	    "streq(LIBRARY.'LibraryType' 'DISK'))] "
	    "report[LIBRARY.'LibraryName' LIBRARY.'DefaultLibraryPath'] "
	    "reportmode[namevalue]; ", tid, libname);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "mgmt_get_lib",
	    &response);
	if (st == 0) {
		st = mmp_get_nvattrs("LibraryName", B_FALSE, response,
		    lib);
		mms_free_rsp(response);
	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

/*
 *  mms_mgmt_add_dklib()
 *
 *  Single library for _all_ disk volumes.  Added automatically
 *  the first time a disk virtual drive or disk volume is created.
 *
 */
int
mms_mgmt_create_dklib(void *session, nvlist_t *lib, nvlist_t *errs)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	char		tid[64];
	char 		cmd[8192];
	int		len = sizeof (cmd);
	char		buf[1024];
	char		libpath[PATH_MAX];
	nvlist_t	*dklib = NULL;
	nvlist_t	*nva = NULL;
	char		mmhost[NI_MAXHOST +  NI_MAXSERV + 2]; /* ':' + nul */
	char		*libname = NULL;
	char		*dfltpath = NULL;
	char		**altpath = NULL;
	char		*pp = NULL;
	int		i;
	int		j;
	int		count = 0;
	char		*host = NULL;

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
		return (st);
	}

	/*
	 * Get dkpath of library
	 */
	st = nvlist_lookup_string(lib, "dkpath", &dfltpath);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, "dkpath", st);
		return (st);
	}
	if (dfltpath[0] != '/') {
		st = MMS_MGMT_INVALID_PATH;
		return (st);
	}
	for (j = strlen(dfltpath) - 1; j > 0 && dfltpath[j] == '/'; j--) {
		dfltpath[j] = '\0';
	}

	/*
	 * Get library name
	 */
	st = nvlist_lookup_string(lib, O_NAME, &libname);
	if (st != 0) {
		/* No libraryname */
		if (st == ENOENT) {
			st = MMS_MGMT_ERR_REQUIRED;
			MGMT_ADD_OPTERR(errs, "library", st);
		}
		return (st);
	}
	/*
	 * Find connection - where the LM is going to run
	 */
	st = nvlist_lookup_string(lib, O_HOST, &host);
	if (st != 0) {
		/* host not specified, default to mmhost */
		host = mmhost;
	}

	st = mgmt_get_dklibname(sessp, libname, &dklib);
	if (st != 0) {
		return (st);
	}

	if (nvlist_exists(dklib, libname)) {
		/* already there, tell caller */
		st = MMS_MGMT_LIB_EXISTS;
		return (st);
	}

	/*
	 * Build librarypath
	 */

	(void) snprintf(libpath, sizeof (libpath),
	    "%s/%s", dfltpath, libname);

	st = create_mmp_clause("LIBRARY", dklibopts, lib, errs, cmd, len);
	if (st != 0) {
		goto done;
	}

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "create task['%s'] type[LIBRARY] "
	    "set[LIBRARY.'LibraryName' '%s'] "
	    "set[LIBRARY.'DefaultLibraryPath' '%s'] "
	    "set[LIBRARY.'LibraryType' 'DISK'];",
	    tid, libname, libpath);
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
	    tid, buf, libname, host);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "add disk LM",
	    &response);
	if (st != 0) {
		goto done;
	}

	/*
	 * Add LIBRARYACCESS with altpaths
	 */

	/*
	 * altpath specifies a list of one or more host and path specs.
	 */
	altpath = mgmt_var_to_array(lib, "dkaltpath", &count);
	for (i = 0; i < count; i++) {
		/* Break each entry into hostname and path */
		if ((pp = strchr(altpath[i], '@')) == NULL) {
			/* Not hostname@path */
			st = MMS_MGMT_INV_HOSTPATH;
			goto done;
		}
		pp[0] = '\0';
		pp++;
		if (pp[0] != '/') {
			/* Not hostname@path */
			st = MMS_MGMT_INV_HOSTPATH;
			goto done;
		}
		for (j = strlen(pp) - 1; j > 0 && pp[j] == '/'; j--) {
			pp[j] = '\0';
		}

		/* append libname to path */
		(void) snprintf(libpath, sizeof (libpath),
		    "%s/%s", pp, libname);

		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "create task['%s'] "
		    "type[LIBRARYACCESS] "
		    "set[LIBRARYACCESS.'LibraryName' '%s'] "
		    "set[LIBRARYACCESS.'HostName' '%s'] "
		    "set[LIBRARYACCESS.'LibraryPath' '%s'] "
		    ";",
		    tid, libname, altpath[i], libpath);

		st = mms_mgmt_send_cmd(sessp, tid, cmd,
		    "add disk library",
		    &response);
		if (st != 0) {
			goto done;
		}
	}

	if (st == 0) {
		/* online this library */
		st = nvlist_alloc(&nva, NV_UNIQUE_NAME, 0);
		if (st != 0) {
			goto done1;
		}
		(void) nvlist_add_string(nva, O_OBJSTATE, "online");
		(void) nvlist_add_string(nva, O_OBJTYPE, "library");
		(void) nvlist_add_string(nva, O_NAME, libname);

		st = mms_mgmt_set_state(sessp, nva, errs);
		nvlist_free(nva);
		if (st != 0) {
			goto done1;
		}
	}

done:
	if (st != 0) {
		/* had an error */
		(void) mms_remove_library(sessp, lib, errs);
	}
done1:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}
	return (st);
}

int
mgmt_get_drvgrp(void *session, char *grpname, nvlist_t **drvgrp)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	char		tid[64];
	char 		cmd[8192];

	if (!drvgrp) {
		return (MMS_MGMT_NOARG);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	*drvgrp = NULL;

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] "
	    "match[streq(DRIVEGROUP.'DriveGroupName' '%s')] "
	    "report[DRIVEGROUP.'DriveGroupName'] "
	    "reportmode[namevalue]; ", tid, grpname);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "get drivegroup",
	    &response);
	if (st == 0) {
		st = mmp_get_nvattrs("DriveGroupName", B_FALSE, response,
		    drvgrp);
		mms_free_rsp(response);
	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

void
mms_mgmt_add_vol_cleanup(void *session, char *pcl, char *lib)
{
	void	*sess = NULL;
	void	*sessp = session;
	void	*response;
	char	cmd[8192];
	char	tid[64];
	int	st;

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return;
		}
		sessp = sess;
	}

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "delete task['%s'] "
	    "match[and (streq(CARTRIDGE.'CartridgePCL' '%s') "
	    "streq(CARTRIDGE.'LibraryName' '%s'))] "
	    "type[PARTITION];",
	    tid, pcl, lib);
	(void) mms_mgmt_send_cmd(sessp, tid, cmd,
	    "delete partition",
	    &response);
	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "delete task['%s'] "
	    "match[and (streq(CARTRIDGE.'CartridgePCL' '%s') "
	    "streq(CARTRIDGE.'LibraryName' '%s'))] "
	    "type[CARTRIDGE];",
	    tid, pcl, lib);
	(void) mms_mgmt_send_cmd(sessp, tid, cmd,
	    "delete cartridge",
	    &response);

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

}

int
mms_mgmt_add_dkvol(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	char		tid[64];
	char 		cmd[8192];
	char		*val = NULL;
	char		**pclarr = NULL;
	uint64_t	sz = 0;
	char		*libname = NULL;
	char		*mpool = NULL;
	char		volpath[MAXPATHLEN + 1];
	nvlist_t	*dklib = NULL;
	nvlist_t	*lib = NULL;
	nvlist_t	*cg = NULL;
	char		thishost[1024];
	char		*dfltpath = NULL;
	int		count = 0;
	int		i;
	int		st_save = 0;
	char		*rwmode = "readwrite";

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	mms_trace(MMS_DEBUG, "add dkvol");

	if (!mgmt_chk_auth("solaris.mms.create")) {
		return (EACCES);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &mpool);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	st = nvlist_lookup_string(nvl, O_SIZE, &val);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_SIZE, st);
		return (st);
	}

	st = do_val_mms_size(val, &sz);
	if ((st == 0) && (sz == 0)) {
		st = EINVAL;
	} else if (sz < 1024 * 1024) {
		sz = 1024 * 1024;
	}

	st = nvlist_lookup_string(nvl, "readonly", &rwmode);
	if (st == 0) {
		if (strcmp(rwmode, "true") == 0) {
			rwmode = "readonly";
		} else if (strcmp(rwmode, "false") == 0) {
			rwmode = "readwrite";
		} else {
			st = MMS_MGMT_INVALID_READONLY;
			MGMT_ADD_OPTERR(errs, "readonly", st);
			return (st);
		}
	}

	pclarr = mgmt_var_to_array(nvl, O_VOLUMES, &count);
	if (pclarr == NULL) {
		st = ENOENT;
		MGMT_ADD_OPTERR(errs, O_VOLUMES, st);
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

	st = mgmt_get_cgname(sessp, mpool, &cg);
	if (st != 0) {
		goto done;
	}

	if (!nvlist_exists(cg, mpool)) {
		st = MMS_MGMT_CG_NOT_EXIST;
		goto done;
	}

	(void) nvlist_lookup_string(nvl, O_MMSLIB, &libname);
	if (!libname) {
		goto done;
	}

	st = mgmt_get_dklibname(sessp, libname, &dklib);
	if (st != 0) {
		goto done;
	}

	if (!nvlist_exists(dklib, libname)) {
		st = MMS_MGMT_LIB_NOT_EXIST;
		goto done;
	}

	st = nvlist_lookup_nvlist(dklib, libname, &lib);
	if (st != 0) {
		st = MMS_MGMT_LIB_NOT_EXIST;
		goto done;
	}
	st = nvlist_lookup_string(lib, "DefaultLibraryPath", &dfltpath);
	if (st != 0) {
		st = MMS_MGMT_DFLTPATH_ERR;
		goto done;
	}

	for (i = 0; i < count; i++) {
		/* add the cartridge to MMS */
		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "create task['%s'] type[CARTRIDGE] "
		    "set[CARTRIDGE.'CartridgePCL' '%s'] "
		    "set[CARTRIDGE.'CartridgeTypeName' 'DISK'] "
		    "set[CARTRIDGE.'CartridgeGroupName' '%s'] "
		    "set[CARTRIDGE.'LibraryName' '%s'] "
		    ";",
		    tid, pclarr[i], mpool, libname);

		st = mms_mgmt_send_cmd(sessp, tid, cmd, "create dkvol",
		    &response);

		if (st != 0) {
			/* can't do this one */
			MGMT_ADD_ERR(errs, pclarr[i], st);
			st_save = MMS_MGMT_CREATE_CART_ERR;
			continue;
		}

		/* create the partition */
		st = mms_mgmt_create_partition(sessp,
		    pclarr[i], sz, libname, rwmode, errs);
		if (st != 0) {
			MGMT_ADD_ERR(errs, pclarr[i], st);
			st_save = MMS_MGMT_CREATE_PART_ERR;
			mms_mgmt_add_vol_cleanup(sessp, pclarr[i], libname);
			continue;
		}

		/* Create the disk files */
		(void) snprintf(volpath, sizeof (volpath), "%s/%s",
		    dfltpath, pclarr[i]);
		st = mgmt_create_dkvol(volpath, sz, errs);
		if (st != 0) {
			mms_mgmt_add_vol_cleanup(sessp, pclarr[i], libname);
			continue;
		}
	}

done:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	if (dklib) {
		nvlist_free(dklib);
	}

	return (st_save == 0 ? st : st_save);
}

static int
mgmt_create_dkvol(char *fname, uint64_t volsz, nvlist_t *errs)
{
	int		st;
	int		fd = -1;
	char		dname[MAXPATHLEN + 1];
	dda_metadata_t	metadata;
	dda_metadata_t	out_metadata;
	dda_index_t	idx;
	dda_index_t	out_idx;
	struct stat64	sbuf;
	struct statvfs64 vbuf;
	char		pbuf[MAXPATHLEN + 1];
	size_t		rlen;

	if (!fname || (volsz == 0)) {
		return (MMS_MGMT_NOARG);
	}

	(void) memset(&metadata, 0, sizeof (dda_metadata_t));
	(void) memset(&idx, 0, sizeof (dda_index_t));
	(void) memset(pbuf, 0, sizeof (pbuf));

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

	DDA_BE_METADATA(metadata, out_metadata);	/* to big endian */

	(void) snprintf(dname, sizeof (dname), "%s/%s", fname,
	    DDA_METADATA_FNAME);
	fd = open64(dname, O_CREAT|O_EXCL|O_RDWR, 0640);
	if (fd == -1) {
		st = errno;
		MGMT_ADD_ERR(errs, dname, st);
		return (st);
	}
	(void) fchown(fd, 0, 2);

	rlen = write_buf(fd, &out_metadata, sizeof (dda_metadata_t));
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

	DDA_BE_INDEX(idx, out_idx);		/* convert to big endian */
	rlen = write_buf(fd, &out_idx, sizeof (dda_index_t));
	if (rlen != sizeof (dda_index_t)) {
		st = EIO;
		MGMT_ADD_ERR(errs, dname, st);
		(void) close(fd);
		return (st);
	}

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
	nvlist_t	*dklib = NULL;
	nvlist_t	*dg = NULL;
	char		*libname = NULL;
	char		*dgname = NULL;
	char		*val = NULL;
	char		**apps = NULL;
	int		count = 0;

	if (!mgmt_chk_auth("solaris.mms.create")) {
		return (EACCES);
	}

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &dname);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	(void) nvlist_lookup_string(nvl, O_MMSLIB, &libname);
	if (!libname) {
		MGMT_ADD_OPTERR(errs, "library", st);
		goto done;
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			goto done;
		}
		sessp = sess;
	}

	st = mgmt_get_dklibname(sessp, libname, &dklib);
	if (st != 0) {
		goto done;
	}

	if (!nvlist_exists(dklib, libname)) {
		st = MMS_MGMT_LIB_NOT_EXIST;
		goto done;
	}

	(void) nvlist_lookup_string(nvl, O_DPOOL, &dgname);
	if (!dgname) {
		MGMT_ADD_OPTERR(errs, "dpool", st);
		goto done;
	}

	st = mgmt_get_dgname(sessp, dgname, &dg);
	if (st != 0) {
		goto done;
	}

	if (!nvlist_exists(dg, dgname)) {
		st = MMS_MGMT_DG_NOT_EXIST;
		goto done;
	}

	dirp = opendir("/dev/dda");
	if (dirp == NULL) {
		st = errno;
		goto done;
	}

	st = gethostname(thishost, sizeof (thishost));
	if (st != 0) {
		st = errno;
		MGMT_ADD_ERR(errs, "hostname", st);
		(void) closedir(dirp);
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
	    "create task['%s'] type[DRIVE] "
	    "set[DRIVE.'DriveName' '%s'] "
	    "set[DRIVE.'DriveGroupName' '%s'] "
	    "set[DRIVE.'LibraryName' '%s'] "
	    "set[DRIVE.'ReserveDrive' 'no'] "
	    "set[DRIVE.'DriveGeometry' '%s']",
	    tid, dname, dgname, libname, dname);

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

	if (dklib) {
		nvlist_free(dklib);
	}

	return (st);
}

int
mms_mgmt_set_vol_mode(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	char		tid[64];
	char 		cmd[8192];
	char		buf[1024];
	char		thishost[1024];
	char		*libname = NULL;
	char		*vol = NULL;
	nvlist_t	*nva = NULL;
	nvlist_t	*attrs = NULL;
	nvpair_t	*nvp;
	int		fd = -1;
	dda_metadata_t	metadata;
	dda_metadata_t	out_metadata;
	char		*readonly = "false";
	flock64_t	flk;
	char		*rwmode = NULL;
	char		*type = NULL;
	char		*libpath = NULL;

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

	st = nvlist_lookup_string(nvl, O_MMSLIB, &libname);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_MMSLIB, st);
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

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] "
	    "report[LIBRARY] "
	    "reportmode[namevalue] "
	    "match[and( streq(CARTRIDGE.'CartridgePCL' '%s') "
	    "streq(LIBRARY.'LibraryName' '%s'))];",
	    tid, vol, libname);

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
	if (attrs == NULL) {
		st = ENOENT;
		goto done;
	}

	/*
	 * If changing readonly mode
	 */
	st = nvlist_lookup_string(nvl, "readonly", &rwmode);
	if (st == 0) {
		if (strcmp(rwmode, "true") == 0) {
			rwmode = "readonly";
		} else if (strcmp(rwmode, "false") == 0) {
			rwmode = "readwrite";
		} else {
			st = MMS_MGMT_INVALID_READONLY;
			MGMT_ADD_OPTERR(errs, "readonly", st);
			return (st);
		}

		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "attribute task['%s'] "
		    "match[and( streq(CARTRIDGE.'CartridgePCL' '%s') "
		    "streq(LIBRARY.'LibraryName' '%s'))] "
		    "set[PARTITION.'PartitionRWMode' '%s'] "
		    ";",
		    tid, vol, libname, rwmode);
		st = mms_mgmt_send_cmd(sessp, tid, cmd, "get dkvol",
		    &response);
		if (st != 0) {
			goto done;
		}
		mms_free_rsp(response);
	}

	nvp = nvlist_next_nvpair(attrs, NULL);
	(void) nvpair_value_nvlist(nvp, &nva);

	st = nvlist_lookup_string(nva, "LibraryType", &type);
	if (st != 0) {
		goto done;
	}
	if (strcmp(type, "DISK")) {
		/* Not DISK library, then we are done */
		goto done;
	}

	/*
	 * DISK volume, set the DISK cartridge mode
	 */
	(void) nvlist_lookup_string(nva, "DefaultLibraryPath", &libpath);
	(void) snprintf(buf, sizeof (buf), "%s/%s/%s", libpath, vol,
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

	if (read(fd, &out_metadata, sizeof (dda_metadata_t)) !=
	    sizeof (dda_metadata_t)) {
		st = errno;
		MGMT_ADD_ERR(errs, "read index", st);
		goto done;
	}
	DDA_BE_METADATA(out_metadata, metadata);	/* to big endian */

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

	DDA_BE_METADATA(metadata, out_metadata);	/* to big endian */
	if (write_buf(fd, &out_metadata, sizeof (dda_metadata_t)) !=
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
