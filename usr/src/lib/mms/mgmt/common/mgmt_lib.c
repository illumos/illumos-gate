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

#include "mms_mgmt.h"
#include "mgmt_acsls.h"
#include "mmp_defs.h"
#include "mgmt_library.h"
#include "mgmt_sym.h"
#include "mgmt_util.h"

static char *_SrcFile = __FILE__;
#define	HERE _SrcFile, __LINE__

/*
 * Cannot set to online during create
 *	{O_ONLINE, "LibraryOnline", "true", B_FALSE, val_truefalse},
 */
static mms_mgmt_setopt_t libopts[] = {
	{O_NAME, "LibraryName", NULL, B_TRUE, NULL},
	{O_TYPE, "LibraryType", NULL, B_TRUE, NULL},
	{O_ACSHOST, "LibraryIP", NULL, B_TRUE, NULL},
	{O_ACSNUM, "LibraryACS", NULL, B_TRUE, val_numonly},
	{O_LSMNUM, "LibraryLSM", NULL, B_TRUE, val_numonly},
	{O_LIBCONN, "LibraryConnection", "network", B_TRUE, NULL},
	{O_SERIALNO, "LibrarySerialNumber", NULL, B_TRUE, NULL},
	{O_ACSPORT, NULL, NULL, B_FALSE, val_numonly},
	{NULL, NULL, NULL, B_FALSE, NULL}
};
#define	LIBOPT_COUNT	sizeof (libopts) / sizeof (mms_mgmt_setopt_t)

mms_mgmt_setopt_t dklibopts[] = {
	{O_NAME, "LibraryName", NULL, B_TRUE, NULL},
	{O_TYPE, "LibraryType", NULL, B_TRUE, NULL},
	{O_DFLTPATH, "DefaultLibraryPath", NULL, B_TRUE, NULL},
	{NULL, NULL, NULL, B_FALSE, NULL}
};
#define	DKLIBOPT_COUNT	sizeof (dklibopts) / sizeof (mms_mgmt_setopt_t)

static mms_mgmt_setopt_t lmopts[] = {
	{O_LMNAME, "LMName", NULL, B_TRUE, NULL},
	{O_NAME, "LibraryName", NULL, B_TRUE, NULL},
	{O_DEVCONN, "LMTargetHost", NULL, B_TRUE, NULL},
	{O_MSGLEVEL, "LMMessageLevel", "error", B_FALSE, val_level},
	{O_TRACELEVEL, "TraceLevel", "debug", B_FALSE, val_level},
	{O_TRACESZ, "TraceFileSize", "10M", B_FALSE, val_mms_size},
	{O_OBJSTATE, "LMDisabled", "false", B_FALSE, val_truefalse},
	{NULL, NULL, NULL, B_FALSE, NULL}
};
#define	LMOPT_COUNT	sizeof (lmopts) / sizeof (mms_mgmt_setopt_t)

/*
 * Cannot set to online during create
 *	{O_ONLINE, "DriveOnline", "true", B_FALSE, val_truefalse},
 */
static mms_mgmt_setopt_t driveopts[] = {
	{O_NAME, "DriveName", NULL, B_TRUE, NULL},
	{O_TYPE, "DriveType", NULL, B_TRUE, NULL},
	{O_SERIALNO, "DriveSerialNum", NULL, B_TRUE, NULL},
	{O_MMSLIB, "LibraryName", NULL, B_TRUE, NULL},
	{O_DPOOL, "DriveGroupName", NULL, B_TRUE, NULL},
	{O_RESERVE, "ReserveDrive", "yes", B_FALSE, val_yesno},
	{NULL, NULL, NULL, B_FALSE, NULL}
};
#define	DRVOPT_COUNT	sizeof (driveopts) / sizeof (mms_mgmt_setopt_t)

/*
 *  Note that O_DEVCONN (string array) is required for DM.  Add a DM
 *  for each host specified in the array.
 */
static mms_mgmt_setopt_t dmopts[] = {
	{O_DMNAME, "DMName", NULL, B_TRUE, NULL},
	{O_NAME, "DriveName", NULL, B_TRUE, NULL},
	{O_DEVCONN, "DMTargetHost", NULL, B_TRUE, NULL},
	{O_MSGLEVEL, "DMMessageLevel", "error", B_FALSE, val_level},
	{O_TRACELEVEL, "TraceLevel", "debug", B_FALSE, val_level},
	{O_TRACESZ, "TraceFileSize", "10M", B_FALSE, val_mms_size},
	{O_DISABLED, "DMDisabled", "false", B_FALSE, val_truefalse},
	{NULL, NULL, NULL, B_FALSE, NULL}
};
#define	DMOPT_COUNT	sizeof (dmopts) / sizeof (mms_mgmt_setopt_t)

static mms_mgmt_setopt_t drvgrpopts[] = {
	{O_NAME, "DriveGroupName", NULL, B_TRUE, NULL},
	{O_UNLOADTM, "DriveGroupUnloadTime", "60", B_FALSE, NULL},
	{NULL, NULL, NULL, B_FALSE, NULL}
};
#define	DGOPT_COUNT	sizeof (drvgrpopts) / sizeof (mms_mgmt_setopt_t)

/*
 * Note that O_APPS (string array) is required for DriveGroupApplication.
 * Add a DGA for each application specified in the array.
 *	{O_APPS, "ApplicationName", NULL, B_FALSE, NULL},
 */
static mms_mgmt_setopt_t drvgrpappopts[] = {
	{O_NAME, "DriveGroupName", NULL, B_TRUE, NULL},
	{O_APPS, "ApplicationName", NULL, B_TRUE, NULL},
	{NULL, NULL, NULL, B_FALSE, NULL}
};
#define	DGAOPT_COUNT	sizeof (drvgrpappopts) / sizeof (mms_mgmt_setopt_t)

static int
mms_remove_libaccess(void *session, char *libname);

static int
mms_remove_slotgroup(void *session, char *libname);

static int
mms_remove_lm(void *session, char *libname);

static int
mms_remove_dm(void *session, nvlist_t *nvl, nvlist_t *errs);

static int
mms_remove_dg(void *session, char *dgname);

static int
mms_create_drive(void *session, nvlist_t *nvl, nvlist_t *errs);

static int
update_DMs(void *session, char *drive, nvlist_t **olddms, int count,
    nvlist_t *nvl, nvlist_t *errs);

static int
update_DGAs(void *session, char *dgname, nvlist_t **old, int count,
    nvlist_t *nvl, nvlist_t *errs);

/*
 * mms_mgmt_discover_libraries()
 *
 *  Finds ACSLS libraries, and optionally associated drives.
 */
int
mms_mgmt_discover_libraries(
	char *acshost, boolean_t getdrives, mms_list_t *liblist)
{
	int		st;
	mms_acslib_t	*lsm = NULL;
	mms_acslib_t	*mlsm = NULL;
	mms_drive_t	*drv = NULL;
	mms_drive_t	*mdrv = NULL;
	mms_list_t	mlist;
	void		*session = NULL;

	if (!acshost || !liblist) {
		return (MMS_MGMT_NOARG);
	}

	(void) memset(&mlist, 0, sizeof (mms_list_t));

	mms_list_create(liblist, sizeof (mms_acslib_t),
	    offsetof(mms_acslib_t, lib_link));

	st = get_acs_library_cfg(acshost, getdrives, liblist);
	if (st != 0) {
		return (st);
	}

	st = create_mm_clnt(NULL, NULL, NULL, NULL, &session);
	if (st == 0) {
		st = mms_get_library(session, getdrives, &mlist);
		(void) mms_goodbye(session, 0);
	}

	if (st != 0) {
		free_acslib_list(liblist);
		liblist->list_size = 0;
		return (st);
	}

	mms_list_foreach(liblist, lsm) {
		if (mlist.list_size == 0) {
			continue;
		}

		mms_list_foreach(&mlist, mlsm) {
			if ((strcmp(lsm->serialnum, mlsm->serialnum) != 0) ||
			    (strcmp(lsm->type, mlsm->type) != 0)) {
				continue;
			}

			(void) strlcpy(lsm->name, mlsm->name,
			    sizeof (lsm->name));

			if (getdrives) {
				if (lsm->drive_list.list_size == 0) {
					break;
				}
				mms_list_foreach(&lsm->drive_list, drv) {
					if (mlsm->drive_list.list_size == 0) {
						break;
					}
					mms_list_foreach(&mlsm->drive_list,
					    mdrv) {
						if ((strcmp(drv->serialnum,
						    mdrv->serialnum) != 0) ||
						    (strcmp(drv->type,
						    mdrv->type) != 0)) {
							continue;
						}
						(void) strlcpy(drv->name,
						    mdrv->name,
						    sizeof (drv->name));

						break;
					}
				}
			}
			break;
		}
	}

	free_acslib_list(&mlist);

	return (0);
}

/*
 * The mms_get_library() function lists all the libraries that are controlled
 * by MM. The LM(s) and the drives in each library alongwith the the respective
 * DM(s) information for each drive are also obtained.
 *
 * The session argument should be provided if an existing connection to the
 * MM server is to be reused.  If this argument is NULL, a new connection to
 * MM will be created and destroyed before returning.
 *
 * PARAM
 *	session		- IN - MM session information
 *	get_drives	- IN - whether the drives should also be returned
 *	acslib_list	- OUT - list of mms_acslib_t
 *
 * RETURN
 * Upon successful completion, a value of 0 is returned. If errors are
 * encountered, an appropriate error number is returned
 *
 */
int
mms_get_library(
	void *session,
	boolean_t get_drives,
	mms_list_t *acslib_list)
{
	void		*response;
	mms_acslib_t	*acslib;
	int		st;
	char 		cmd[1024];
	char		tid[64];
	void		*sess = NULL;
	void**		sessp = session;

	mms_trace(MMS_DEBUG, "mms_get_library() start");

	if (session == NULL) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	(void) mms_gen_taskid(tid);

	/*
	 * generate command to query the MM for all the libraries and their
	 * associated LM(s)
	 */
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] report[LIBRARY] reportmode[namevalue];", tid);

	mms_trace(MMS_DEBUG, "mms_get_library() request command: %s", cmd);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "mms_get_library()", &response);
	if (st != 0) {
		goto done;
	}

	(void) mmp_parse_library_rsp(response, acslib_list);

	mms_free_rsp(response);

	for (acslib = mms_list_head(acslib_list); acslib;
	    acslib = mms_list_next(acslib_list, acslib)) {
		/* Get the LMs for each library */
		st = mms_get_lm(sessp, acslib->name, &(acslib->lm_list));
		if (st != 0) {
			break;
		}

		/* Get the drives in the each library */
		if (get_drives) {
			st = mms_get_drives_for_lib(
			    sessp, acslib->name, &acslib->drive_list);
			if (st != 0) {
				break;
			}
		}
	}

	mms_trace(MMS_DEBUG, "mms_get_library() completed, return[%d]", st);

done:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}
	return (st);
}


/*
 * The mms_get_lm() function gets information about all the LM(s) for a
 * particular library. The LM name and hostname are filled in the structure
 * mms_lm_t
 */
int
mms_get_lm(void *session, char *libname, mms_list_t *lm_list)
{
	void		*response;
	int		st;
	char		tid[64];
	char		cmd[8192];

	if ((session == NULL) || (libname == NULL) || (lm_list == NULL)) {
		return (MMS_MGMT_NOARG);
	}

	mms_trace(MMS_DEBUG, "mms_get_lm() for library[%s]", libname);

	(void) mms_gen_taskid(tid);

	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] match[ streq(LM.'LibraryName' '%s')]"
	    " report[LM] reportmode[namevalue];", tid, libname);

	mms_trace(MMS_DEBUG, "Send command[%s]", cmd);

	st = mms_mgmt_send_cmd(session, tid, cmd, "mms_get_lm()", &response);
	if (st == 0) {
		st = mmp_parse_lm_rsp(response, lm_list);
	}

	mms_trace(MMS_DEBUG, "mms_get_lm() completed, return[%d]", st);

	mms_free_rsp(response);
	return (st);

}


/*
 * The mms_get_dm() function gets information about all the dms for a
 * particular drive. The DM name, drive path, hostname and status are
 * filled in the structure mms_dm_t
 *
 */
int
mms_get_dm(void *session, char *drivename, mms_list_t *dm_list)
{
	void		*response;
	int		st;
	char		tid[64];
	char		cmd[8192];

	if ((session == NULL) || (drivename == NULL) || (dm_list == NULL)) {
		return (MMS_MGMT_NOARG);
	}

	mms_trace(MMS_DEBUG, "mms_get_dm() for drive[%s]", drivename);

	(void) mms_gen_taskid(tid);

	/* why not just a standard report? */
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] match[ streq(DM.'DriveName' '%s')] "
	    "report[DM] reportmode[namevalue];",
	    tid, drivename);

	mms_trace(MMS_DEBUG, "mms_get_dm() request command[%s]", cmd);

	st = mms_mgmt_send_cmd(session, tid, cmd, "mms_get_dm()", &response);
	if (st == 0) {
		st = mmp_parse_dm_rsp(response, dm_list);
	}

	mms_trace(MMS_DEBUG, "mms_get_dm() completed, return[%d]", st);

	mms_free_rsp(response);
	return (st);

}

/*
 * The mms_get_drives_for_lib()  function returns information about the
 * drives hosted by a particular library (in the MM configuration)
 *
 * PARAM
 * session	- IN - connection to MM
 * libname	- IN - name of library
 * drive_list	- OUT - A list of drives in the given library
 *
 * RETURN
 * upon successful completion, a value of 0 is returned to indicate success and
 * drives is updated with a list of drives
 * If the request cannot be completed, an appropriate error number is returned
 * to signify the error
 *
 * MMS_ERR
 * MMS Connection errors
 */
int
mms_get_drives_for_lib(void *session, char *libname, mms_list_t *drive_list)
{
	void		*response;
	int		st;
	char		tid[64];
	char 		cmd[8192];

	if ((session == NULL) || (libname == NULL) || (drive_list == NULL)) {
		return (MMS_MGMT_NOARG);
	}

	mms_trace(MMS_DEBUG, "mms_get_drives_for_lib(%s)", libname);

	(void) mms_gen_taskid(tid);

	/* this command is suspect too, if there's a drive but no DM */
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] match[ streq(DRIVE.'LibraryName' '%s')]"
	    " report[DRIVE DM] reportmode[namevalue];",
	    tid, libname);

	mms_trace(MMS_DEBUG, "mms_get_drives_for_lib() request command %s",
	    cmd);

	st = mms_mgmt_send_cmd(session, tid, cmd, "mms_get_drives_for_lib()",
	    &response);
	if (st == 0) {
		st = mmp_parse_drive_rsp(response, drive_list);
	}

	mms_free_rsp(response);

	mms_trace(MMS_DEBUG,
	    "mms_get_drives_for_lib() completed, return[%d]", st);

	return (st);
}

int
mms_get_drive(void *session, char *drivename, mms_drive_t **drive)
{
	void		*response;
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	char		tid[64];
	char 		cmd[8192];
	mms_list_t	drive_list;

	if (!drivename || !drive) {
		return (MMS_MGMT_NOARG);
	}

	*drive = NULL;

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	mms_trace(MMS_DEBUG, "mms_get_drives(%s)", drivename);

	(void) mms_gen_taskid(tid);

	/* this command is suspect too, if there's a drive but no DM */
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] match[ streq(DRIVE.'DriveName' '%s')]"
	    " report[DRIVE DM] reportmode[namevalue];",
	    tid, drivename);

	mms_trace(MMS_DEBUG, "mms_get_drive() request command %s", cmd);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "mms_get_drive()",
	    &response);
	if (st == 0) {
		st = mmp_parse_drive_rsp(response, &drive_list);
	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	if (st == 0) {
		*drive = mms_list_head(&drive_list);
	}

	mms_free_rsp(response);

	mms_list_destroy(&drive_list);

	mms_trace(MMS_DEBUG, "mms_get_drive() completed, return[%d]", st);

	return (st);
}

/*
 * The mms_add_library() function is used to add a library to the MM
 * configuration. The following steps are taken:
 *
 * 1. A Library object is created and associated with its network IP (ACSLS)
 * 2. the Library object is associated with a Library Manager
 * 3. Library is brought online
 *
 * ARGUMENTS:
 *	session		MM session information.  If this argument is
 *			NULL, a new session is created.
 *	lib		library attributes
 *
 * RETURN VALUES:
 *	0	Success
 *	>0	Failure
 *
 * ERRORS
 *	MMS_MGMT_NOARG	One or more required arguments is missing
 *	ENOENT		One or more required options is missing
 *	ENOMEM		Out of memory
 *	TBD		Could not communicate with MM
 *	TBD		Other MMP errors
 *
 * Notes:
 *	MMS defines a Library Manager(LM) to manage each Library object.
 *	While the MMS spec supports a library to be managed by multiple
 *	LMs (without any upper limit), multiple LMs are only required for
 *	switchover or failover purposes. As such, for the first release of
 *	the MMS api, the hostname of the LM is defaulted to the MM host.
 *
 *	If not specified, the library name is derived from library type and
 *	serial number.
 */
int
mms_add_library(void *session, nvlist_t *lib, nvlist_t *errs)
{
	int	st;
	char	*ltype;


	if (!lib) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.create")) {
		return (EACCES);
	}

	/* type is required */
	st = nvlist_lookup_string(lib, O_TYPE, &ltype);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_TYPE, st);
		return (st);
	}

	/*
	 * If adding DISK type library, then call add dklib function
	 */
	if (strcmp(ltype, "DISK") == 0) {
		/* Adding DISK library */
		st = mms_mgmt_create_dklib(session, lib, errs);
	} else {
		/* Adding a real library */
		st = mms_create_library(session, lib, errs);
	}
	return (st);
}

int
mms_create_library(void *session, nvlist_t *lib, nvlist_t *errs)
{
	void		*response;
	int		st;
	char		tid[64];
	char		cmd[8192];
	char		buf[1024];
	char		libname[1024];
	char		*namep = NULL;
	char		*val;
	size_t		len = sizeof (cmd);
	char		*cmdp;
	void		*sess;
	void		*sessp = session;
	char		*ltype = NULL;

	mms_trace(MMS_DEBUG, "mms_add_library");

	/* type is required */
	st = nvlist_lookup_string(lib, O_TYPE, &ltype);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_TYPE, st);
		return (st);
	}

	st = nvlist_lookup_string(lib, O_NAME, &namep);
	if (st != 0) {
		if (st != ENOENT) {
			MGMT_ADD_ERR(errs, O_NAME, st);
			return (st);
		}
	}

	if (namep == NULL) {
		/* Create library name */
		st = nvlist_lookup_string(lib, O_SERIALNO, &val);
		if (st != 0) {
			MGMT_ADD_OPTERR(errs, O_SERIALNO, st);
			return (st);
		}
		(void) snprintf(libname, sizeof (libname), "LIB_%s_%s",
		    ltype, val);
		(void) nvlist_add_string(lib, O_NAME, libname);
		namep = libname;
	}

	/* Create LM name */
	(void) snprintf(buf, sizeof (buf), "LM_%s", namep);
	(void) nvlist_add_string(lib, O_LMNAME, buf);

	/*
	 * MMS defines a Library Manager(LM) to manage each Library object.
	 * While the MMS spec supports a library to be managed by multiple LMs
	 * (without any upper limit), multiple LMs are only required for
	 * switchover or failover purposes. As such, for the first release of
	 * the MMS api, the hostname of the LM for ACSLS libraries defaults to
	 * the hostname running MM.
	 */
#ifdef	MGMT_VAR_CFG
	st = nvlist_lookup_string(lib, O_DEVCONN, &val);
	if (st != 0) {
		if (st != ENOENT) {
			MGMT_ADD_ERR(errs, O_DEVCONN, st);
			return (st);
		}

		st = mms_cfg_getvar(MMS_CFG_MGR_HOST, buf);
		if (st != 0) {
			return (MMS_MGMT_NO_MMHOST);
		}
		(void) nvlist_add_string(lib, O_DEVCONN, buf);
	}
#else
	/* always set to this host */
	st = gethostname(buf, sizeof (buf));
	if (st != 0) {
		MGMT_ADD_ERR(errs, "cannot determine hostname", st);
		return (st);
	}
	(void) nvlist_add_string(lib, O_DEVCONN, buf);
#endif	/* MGMT_VAR_CFG */

	/* create LIBRARY object */
	st = create_mmp_clause("LIBRARY", libopts, lib, errs, cmd, len);

	if (st != 0) {
		return (st);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "mms_add_library()", &response);
	if (st != 0) {
		MGMT_ADD_ERR(errs, namep, st);
		if (sess) {
			(void) mms_goodbye(sess, 0);
		}
		return (st);
	}

	/* move ahead in the cmdbuf */
	cmdp = cmd + strlen(cmd);
	len -= strlen(cmd);

	/* Build the LM object */
	st = create_mmp_clause("LM", lmopts, lib, errs, cmdp, len);

	if (st == 0) {
		st = mms_mgmt_send_cmd(sessp, tid, cmdp, "mms_add_library()",
		    &response);
	}

	/* online the library */
	if (st == 0) {
		if (!nvlist_exists(lib, O_OBJSTATE)) {
			(void) nvlist_add_string(lib, O_OBJSTATE, "online");
		}
		st = mms_mgmt_set_state(sessp, lib, errs);
	}

	if (st != 0) {
		MGMT_ADD_ERR(errs, namep, st);
		(void) mms_remove_library(sessp, lib, errs);
	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

int
mms_add_drive(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	char	*type;
	int	st = 0;

	st = nvlist_lookup_string(nvl, O_TYPE, &type);
	if (st != 0) {
		st = MMS_MGMT_NO_HWTYPE;
		MGMT_ADD_OPTERR(errs, "O_TYPE", st);
		return (st);
	}

	if (strcmp(type, "DISK") == 0) {
		st = mms_mgmt_create_dkdrive(session, nvl, errs);
	} else {
		st = mms_create_drive(session, nvl, errs);
	}
	return (st);
}

static int
mgmt_get_libname(void *session, char *libname, nvlist_t **lib)
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
	    "match[streq(LIBRARY.'LibraryName' '%s')] "
	    "report[LIBRARY.'LibraryName'] "
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

static int
mms_create_drive(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	char		buf[2048];
	void		*sess = NULL;
	void		*sessp = session;
	char		*val;
	char		drvnm[1024];
	char		*namep;
	char		**saved = NULL;
	char		*dgname = NULL;
	char		*libname = NULL;
	nvlist_t	*lib = NULL;
	nvlist_t	*dg = NULL;
	int		count = 0;
	char		hostbuf[1024];
	int		i;

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.create")) {
		return (EACCES);
	}

	st = gethostname(hostbuf, sizeof (hostbuf));
	if (st != 0) {
		st = errno;
		MGMT_ADD_ERR(errs, "could not determine hostname", st);
		return (st);
	}

	/* Library asssociation and connection are required */
	st = nvlist_lookup_string(nvl, O_MMSLIB, &libname);
	if (st != 0) {
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

	st = mgmt_get_libname(sessp, libname, &lib);
	if (st != 0) {
		goto done;
	}

	if (!nvlist_exists(lib, libname)) {
		st = MMS_MGMT_LIB_NOT_EXIST;
		goto done;
	}

#ifdef	MMS_VAR_CFG
	if (!nvlist_exists(nvl, O_DEVCONN)) {
		st = ENOENT;
		MGMT_ADD_OPTERR(errs, O_DEVCONN, st);
		return (st);
	}
#else
	/* must always be the same as MM server */
	st = nvlist_lookup_string(nvl, O_DEVCONN, &val);
	if (st == 0) {
		st = mgmt_compare_hosts(val, hostbuf);
		if (st != 0) {
			st = MMS_MGMT_REMOTE_NOT_SUPP;
			MGMT_ADD_OPTERR(errs, val, st);
			return (st);
		}
	} else {
		(void) nvlist_add_string(nvl, O_DEVCONN, hostbuf);
	}
#endif	/* MMS_VAR_CFG */

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

	st = nvlist_lookup_string(nvl, O_NAME, &val);
	if (st == 0) {
		/* name provided */
		namep = val;
	} else {
		if (st != ENOENT) {
			MGMT_ADD_ERR(errs, O_NAME, st);
			return (st);
		}

		st = nvlist_lookup_string(nvl, O_SERIALNO, &val);
		if (st != 0) {
			MGMT_ADD_OPTERR(errs, O_SERIALNO, st);
			return (st);
		}

		(void) snprintf(drvnm, sizeof (drvnm), "DRV_%s", val);
		(void) nvlist_add_string(nvl, O_NAME, drvnm);
		namep = drvnm;
	}

	/*
	 * Ready to create the objects.  On failure, unwind the list and
	 * remove what was added.  Order is DRIVE,
	 * foreach host add DM.
	 */

	st = mms_add_object(sessp, "DRIVE", driveopts, nvl, errs);
	if (st != 0) {
		MGMT_ADD_ERR(errs, namep, st);
		goto done;
	}

	/* For each host specified in O_DEVCONN, create a DM */
	saved = mgmt_var_to_array(nvl, O_DEVCONN, &count);
	if (saved == NULL) {
		/* should never happen since we checked earlier */
		goto done;
	}
	for (i = 0; i < count; i++) {
		/* create DM Name */
		(void) snprintf(buf, sizeof (buf), "DM_%s_%d", namep, i + 1);
		(void) nvlist_add_string(nvl, O_DMNAME, buf);
		(void) nvlist_add_string(nvl, O_DEVCONN, saved[i]);
		st = mms_add_object(sessp, "DM", dmopts, nvl, errs);
		if (st != 0) {
			(void) snprintf(buf, sizeof (buf),
			    "%s = %s", O_DEVCONN, saved[i]);
			MGMT_ADD_ERR(errs, buf, st);
			break;
		}
	}
	/* put back the original array */
	(void) nvlist_add_string_array(nvl, O_DEVCONN, saved, count);
	mgmt_free_str_arr(saved, count);

	if (st != 0) {
		goto done;
	}

	/* online the drive */
	if (st == 0) {
		if (!nvlist_exists(nvl, O_OBJSTATE)) {
			(void) nvlist_add_string(nvl, O_OBJSTATE, "online");
		}
		st = mms_mgmt_set_state(sessp, nvl, errs);
	}

done:
	if (lib) {
		nvlist_free(lib);
	}
	if (dg != NULL) {
		nvlist_free(dg);
	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	mms_trace(MMS_DEBUG, "mms_add_drive() completed, return[%d]", st);
	return (st);
}

void
free_acslib_list(void *arg)
{
	mms_list_t	*lst = arg;
	mms_acslib_t	*lsm;

	if (!lst || (lst->list_size == 0)) {
		return;
	}

	mms_list_foreach(lst, lsm) {
		free_drive_list(&lsm->drive_list);
		mms_list_free_and_destroy(&lsm->lm_list, free);
	}
	mms_list_free_and_destroy(lst, free);
}

void
free_drive_list(void *arg)
{
	mms_list_t	*lst = arg;
	mms_drive_t	*drv;

	if (!lst || (lst->list_size == 0)) {
		return;
	}

	mms_list_foreach(lst, drv) {
		mms_list_free_and_destroy(&drv->dm_list, free);
		mms_list_free_and_destroy(&drv->app_list, free);
	}

	mms_list_free_and_destroy(lst, free);
}

int
mms_remove_library(void *session, nvlist_t *lib, nvlist_t *errs)
{
	int		st;
	char		*val;
	void		*sessp = session;
	void		*sess = NULL;
	void		*response;
	char 		cmd[8192];
	char		tid[64];

	if (!lib) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.delete")) {
		return (EACCES);
	}

	st = nvlist_lookup_string(lib, O_NAME, &val);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	/* TODO:  Add checks for library dependencies in cartridgegroups */
	/* TODO:  Add checks for drives in this library */

	/* Attempt to delete LMs if they have been created */
	(void) mms_remove_lm(sessp, val);

	/* Attempt to delete LIBRARYACCESS if they have been created */
	(void) mms_remove_libaccess(sessp, val);

	if (st == 0) {
		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "delete task['%s'] type[LIBRARY] "
		    "match[streq (LIBRARY.'%s' '%s')];",
		    tid, "LibraryName", val);

		mms_trace(MMS_DEBUG, "mms_remove_library() request command: %s",
		    cmd);

		st = mms_mgmt_send_cmd(sessp, tid, cmd, "mms_remove_library()",
		    &response);

	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	if (st != 0) {
		MGMT_ADD_ERR(errs, val, st);
	}

	return (st);
}

static int
mms_remove_slotgroup(void *session, char *libname)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	char		cmd[2048];
	char		tid[64];
	void		*response;

	if (!libname) {
		return (MMS_MGMT_NOARG);
	}

	(void) mms_gen_taskid(tid);

	(void) snprintf(cmd, sizeof (cmd),
	    "delete task['%s'] type[SLOTGROUP] "
	    "match[streq (SLOTGROUP.'LibraryName' '%s')];",
	    tid, libname);

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "mms_remove_slotgroup()",
	    &response);

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

static int
mms_remove_lm(void *session, char *libname)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	char		cmd[2048];
	char		tid[64];
	void		*response;

	if (!libname) {
		return (MMS_MGMT_NOARG);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	(void) mms_remove_slotgroup(sessp, libname);

	(void) mms_gen_taskid(tid);

	(void) snprintf(cmd, sizeof (cmd),
	    "delete task['%s'] type[LM] match[streq (LM.'LibraryName' '%s')];",
	    tid, libname);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "mms_remove_lm()", &response);

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

int
mms_remove_libaccess(void *session, char *libname)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	char		cmd[2048];
	char		tid[64];
	void		*response;

	if (!libname) {
		return (MMS_MGMT_NOARG);
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
	    "delete task['%s'] type[LIBRARYACCESS] "
	    "match[streq (LIBRARYACCESS.'LibraryName' '%s')];",
	    tid, libname);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "mms_remove_libaccess()",
	    &response);

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

static int
mms_remove_dg(void *session, char *dgname)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response = NULL;
	char		tid[64];
	char		cmd[1024];

	if (!dgname) {
		return (MMS_MGMT_NOARG);
	}

	/*
	 * remove DRIVEGROUPAPPLICATIONs associated with this
	 * DRIVEGROUP too.
	 */

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "delete task['%s'] type[DRIVEGROUPAPPLICATION]"
	    " match[streq (DRIVEGROUP.'DriveGroupName' '%s')];",
	    tid, dgname);

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "mms_remove_dga", &response);

	if (st == 0) {
		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "delete task['%s'] type[DRIVEGROUP] "
		    "match[streq(DRIVEGROUP.'DriveGroupName' '%s')];",
		    tid, dgname);
		st = mms_mgmt_send_cmd(sessp, tid, cmd, "mms_remove_dg",
		    &response);
	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

static int
mms_remove_dm(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response = NULL;
	mms_list_t	dmlist;
	char		*drive;
	mms_dm_t	*dm;
	char		tid[64];
	char		cmd[1024];

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &drive);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	/* Find the list of DMs to be removed */
	st = mms_get_dm(sessp, drive, &dmlist);
	if (st != 0) {
		if (sess) {
			(void) mms_goodbye(sess, 0);
		}
		return (st);
	}

	mms_list_foreach(&dmlist, dm) {
		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "delete task['%s'] type[DM] "
		    "match[streq (DM.'%s' '%s')];",
		    tid, "DMName", dm->name);

		st = mms_mgmt_send_cmd(sessp, tid, cmd, "mms_remove_dm()",
		    &response);
		if (st != 0) {
			MGMT_ADD_ERR(errs, dm->name, st);
			mms_trace(MMS_ERR, "Error removing DM %s, status = %d",
			    dm->name, st);
			break;
		}
	}


	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	mms_list_free_and_destroy(&dmlist, free);

	return (st);
}

int
mms_remove_drive(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response = NULL;
	char		*drivename;
	char		tid[64];
	char		cmd[1024];

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.delete")) {
		return (EACCES);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &drivename);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	st = mms_remove_dm(sessp, nvl, errs);
	if (st == 0) {
		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "delete task['%s'] "
		    "type[DRIVE] match[streq (DRIVE.'%s' '%s')];",
		    tid, "DriveName", drivename);

		st = mms_mgmt_send_cmd(sessp, tid, cmd, "mms_remove_dm()",
		    &response);
	}

	if (st == 0) {
		(void) snprintf(cmd, sizeof (cmd), "DG_%s", drivename);
		st = mms_remove_dg(sessp, cmd);
	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

/*  MODIFY functions */
int
mms_modify_library(void *session, nvlist_t *nvl, nvlist_t *errs)
{
#define	CARRAY_COUNT	\
	(LIBOPT_COUNT > DKLIBOPT_COUNT ? LIBOPT_COUNT : DKLIBOPT_COUNT)

	int		st;
	char		*fnam = "mms_modify_library()";
	char		*libname;
	void		*sess = NULL;
	void		*sessp = session;
	char		tid[64];
	char		cmd[8192];
	char		lmcmd[8192];
	nvlist_t	*libattrs = NULL;
	void		*response = NULL;
	int		count = 0;
	int		lmcount = 0;
	char		*carray[CARRAY_COUNT];
	char		*lmarray[LMOPT_COUNT];
	nvpair_t	*nvp;
	nvlist_t	*nva;
	char		*type = NULL;
	mms_mgmt_setopt_t *libopts_p;
	char		*path = NULL;
	char		libpath[8192];
	int		i;

	if (!mgmt_chk_auth("solaris.mms.modify")) {
		return (EACCES);
	}

	(void) memset(&carray, 0, sizeof (carray));
	(void) memset(&lmarray, 0, sizeof (lmarray));

	/* get existing attrs for LIBRARY, LM */
	/* see what changed, if anything */
	/* update the objects */

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &libname);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
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
	 * Read LIBRARY and see what type it is
	 */
	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] match[streq (LIBRARY.'%s' '%s')] "
	    "reportmode[namevalue] report[LIBRARY];", tid,
	    "LibraryName", libname);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, fnam, &response);
	if (st == 0) {
		st = mmp_get_nvattrs("LibraryName", B_FALSE, response,
		    &libattrs);
		mms_free_rsp(response);
	}
	if (st != 0) {
		goto done;
	}

	st = nvlist_lookup_nvlist(libattrs, libname, &nva);
	if (st == 0) {
		st = nvlist_lookup_string(nva, "LibraryType", &type);
		if (st != 0) {
			goto done;
		}
	}

	/* see if there are LIBRARY attrs to be changed.  Skip over O_NAME. */
	if (strcmp(type, "DISK") == 0) {
		/*
		 * If dkpath is to be set, the library name must be appended
		 * to the path specified.
		 */
		if (nvlist_lookup_string(nvl, "dkpath", &path) == 0) {
			if (path[0] != '/') {
				st = MMS_MGMT_INVALID_PATH;
				goto done;
			}
			for (i = strlen(path) - 1;
			    i > 0 && path[i] == '/';
			    i--) {
				path[i] = '\0';
			}
			(void) snprintf(libpath, sizeof (libpath),
			    "%s/%s", path, libname);
			(void) nvlist_remove_all(nvl, "dkpath");
			(void) nvlist_add_string(nvl, "dkpath", libpath);
		}
		libopts_p = dklibopts;
	} else {
		libopts_p = libopts;
	}
	st = mgmt_find_changed_attrs("LIBRARY", libopts_p,
	    nvl, carray, &count, errs);

	/*
	 * see if there are LM attrs to be changed.
	 * Skip over O_NAME and O_LMNAME.
	 */
	st = mgmt_find_changed_attrs("LM", lmopts, nvl, lmarray, &lmcount,
	    errs);
	if (st != 0) {
		goto done;
	}

	(void) mms_gen_taskid(tid);

	(void) snprintf(lmcmd, sizeof (lmcmd),
	    "show task['%s'] match[streq (LM.'%s' '%s')] "
	    "reportmode[namevalue] report[LM];", tid, "LibraryName", libname);

	if ((count == 0) && (lmcount == 0)) {
		/* nothing to do */
		st = MMS_MGMT_NOARG;
		goto done;
	}

	if (count > 0) {
		st = nvlist_lookup_nvlist(libattrs, libname, &nva);
		if (st == 0) {
			cmp_mmp_opts(libopts_p, carray, nva, &count);
		}
	}


	if (lmcount > 0) {
		st = mms_mgmt_send_cmd(sessp, tid, lmcmd, fnam, &response);
		if (st == 0) {
			st = mmp_get_nvattrs("LMName", B_FALSE, response,
			    &libattrs);
			mms_free_rsp(response);
		}
		if (st != 0) {
			goto done;
		}

		nvp = nvlist_next_nvpair(libattrs, NULL);
		if (nvp) {
			cmp_mmp_opts(lmopts, lmarray, nva, &lmcount);
			nvlist_free(libattrs);
		} else {
			/* something is very wrong.  no LM returned */
			lmcount = 0;
		}
	}

	/* if we have any attrs left to set, do it */
	if (count > 0) {
		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "attribute task['%s'] "
		    "match[streq (LIBRARY.'LibraryName' '%s')] ",
		    tid, libname);

		mk_set_clause("LIBRARY", libopts_p, carray, cmd, sizeof (cmd));
		(void) strlcat(cmd, ";", sizeof (cmd));

		st = mms_mgmt_send_cmd(sessp, tid, cmd, fnam, &response);
		if (st != 0) {
			goto done;
		}
	}

	if (lmcount > 0) {
		(void) mms_gen_taskid(tid);
		(void) snprintf(lmcmd, sizeof (lmcmd),
		    "attribute task['%s'] "
		    "match[streq (LM.'LibraryName' '%s')] ",
		    tid, libname);

		mk_set_clause("LM", lmopts, lmarray, lmcmd, sizeof (lmcmd));
		(void) strlcat(lmcmd, ";", sizeof (lmcmd));

		st = mms_mgmt_send_cmd(sessp, tid, lmcmd, fnam, &response);
	}

done:
	if (libattrs) {
		nvlist_free(libattrs);
	}
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

int
mms_modify_drive(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	char		*fnam = "mms_modify_drive()";
	char		*drvname;
	void		*sess = NULL;
	void		*sessp = session;
	char		tid[64];
	char		cmd[8192];
	char		dmcmd[8192];
	char		dgcmd[8192];
	char		dgacmd[8192];
	nvlist_t	*drvattrs = NULL;
	nvlist_t	*dgattrs = NULL;
	nvlist_t	*dgaattrs = NULL;
	nvlist_t	*dmattrs = NULL;
	void		*response = NULL;
	int		count = 0;
	int		dgcount = 0;
	int		dmcount = 0;
	char		*carray[DRVOPT_COUNT];
	char		*dgarray[DGOPT_COUNT];
	char		*dmarray[DMOPT_COUNT];
	nvpair_t	*nvp;
	nvlist_t	*nva;
	boolean_t	dodg = B_FALSE;
	boolean_t	dodga = B_FALSE;
	char		*dgname = NULL;
	int		numdms = 0;
	nvlist_t	*olddm[10];	/* should never need more than 2 */
	int		numdga = 0;
	nvlist_t	*olddga[10];

	if (!mgmt_chk_auth("solaris.mms.modify")) {
		return (EACCES);
	}

	(void) memset(&carray, 0, sizeof (carray));

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &drvname);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
	}

	/* only get the DRIVEGROUP if we need it */
	if (nvlist_exists(nvl, O_APPS)) {
		dodg = B_TRUE;
		dodga = B_TRUE;
	} else if (nvlist_exists(nvl, O_UNLOADTM)) {
		dodg = B_TRUE;
	}

	/* see if there are DRIVE attrs to be changed. */
	(void) mms_gen_taskid(tid);

	/* figure out what things are changing */
	st = mgmt_find_changed_attrs("DRIVE", driveopts, nvl, carray, &count,
	    errs);

	if (st != 0) {
		return (st);
	}

	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] match[streq (DRIVE.'%s' '%s')] "
	    "reportmode[namevalue] report[DRIVE];", tid, "DriveName", drvname);

	/* DM */
	st = mgmt_find_changed_attrs("DM", dmopts, nvl, dmarray, &dmcount,
	    errs);

	if (st != 0) {
		return (st);
	}

	(void) mms_gen_taskid(tid);

	if (nvlist_exists(nvl, O_DEVCONN)) {
		/* need to make sure we've got info about all the DMs */
		(void) snprintf(dmcmd, sizeof (dmcmd),
		    "show task['%s'] "
		    "match[streq(DM.'DriveName' '%s')] "
		    "reportmode[namevalue] report[DM];", tid, drvname);
		dmcount++;
	}
	if (st != 0) {
		return (st);
	}

	/* connect to MM */
	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	/* fetch the drive attributes */
	st = mms_mgmt_send_cmd(sessp, tid, cmd, fnam, &response);
	if (st == 0) {
		st = mmp_get_nvattrs("DriveName", B_FALSE, response,
		    &drvattrs);
		mms_free_rsp(response);
	}
	if (st != 0) {
		goto done;
	}

	/* DRIVEGROUP */
	if (dodg) {
		st = nvlist_lookup_nvlist(drvattrs, drvname, &nva);
		if (nva == NULL) {
			/* uh oh */
			st = ENOENT;
		} else {
			if (st == 0) {
				st = nvlist_lookup_string(nva, "DriveGroupName",
				    &dgname);
			}
		}
		if (st != 0) {
			MGMT_ADD_OPTERR(errs, O_NAME, st);
			goto done;
		}

		(void) mms_gen_taskid(tid);
		(void) snprintf(dgcmd, sizeof (dgcmd),
		    "show task['%s'] "
		    "match[streq(DRIVEGROUP.'DriveGroupName' '%s')] "
		    "reportmode[namevalue] report[DRIVEGROUP];", tid, dgname);
	}

	if (dodga) {
		/*
		 * get all of them.  We need to make sure all apps
		 * in O_APPS are represented.
		 */

		(void) mms_gen_taskid(tid);
		(void) snprintf(dgacmd, sizeof (dgacmd),
		    "show task['%s'] report[DRIVEGROUPAPPLICATION] "
		    "match[streq(DRIVEGROUPAPPLICATION.'DriveGroupName' '%s')]"
		    " reportmode[namevalue];", tid, dgname);
	}

	if ((count == 0) && (dmcount == 0) && !dodg && !dodga) {
		/* nothing to do */
		goto done;
	}

	if (dodg) {
		st = mms_mgmt_send_cmd(sessp, tid, dgcmd, fnam, &response);
		if (st == 0) {
			st = mmp_get_nvattrs("DriveGroupName", B_FALSE,
			    response, &dgattrs);
			mms_free_rsp(response);
		}
		if (st != 0) {
			goto done;
		}
	}

	if (dmcount > 0) {
		st = mms_mgmt_send_cmd(sessp, tid, dmcmd, fnam, &response);
		if (st == 0) {
			st = mmp_get_nvattrs("DMName", B_FALSE, response,
			    &dmattrs);
			mms_free_rsp(response);
		}
		if (st != 0) {
			goto done;
		}
	}

	if (dodga) {
		st = mms_mgmt_send_cmd(sessp, tid, dgacmd, fnam, &response);
		if (st == 0) {
			st = mmp_get_nvattrs("ApplicationName", B_FALSE,
			    response, &dgaattrs);
		}
		if (st != 0) {
			goto done;
		}
	}

	st = nvlist_lookup_nvlist(drvattrs, drvname, &nva);
	if (st == 0) {
		cmp_mmp_opts(driveopts, carray, nva, &count);
		if (count > 0) {
			(void) mms_gen_taskid(tid);
			(void) snprintf(cmd, sizeof (cmd),
			    "attribute task['%s'] "
			    "match[streq (DRIVE.'DriveName' '%s')] ",
			    tid, drvname);

			mk_set_clause("DRIVE", driveopts, carray, cmd,
			    sizeof (cmd));
			(void) strlcat(cmd, ";", sizeof (cmd));

			st = mms_mgmt_send_cmd(sessp, tid, cmd, fnam,
			    &response);
			if (st != 0) {
				goto done;
			}
		}
	}

	st = nvlist_lookup_nvlist(dgattrs, dgname, &nva);
	if (st == 0) {
		cmp_mmp_opts(drvgrpopts, dgarray, nva, &dgcount);
		if (dgcount > 0) {
			(void) mms_gen_taskid(tid);
			(void) snprintf(dgcmd, sizeof (dgcmd),
			    "attribute task['%s'] "
			    "match[streq (DRIVEGROUP.'DriveGroupName' '%s')] ",
			    tid, dgname);

			mk_set_clause("DRIVEGROUP", drvgrpopts, dgarray, dgcmd,
			    sizeof (dgcmd));
			(void) strlcat(dgcmd, ";", sizeof (dgcmd));

			st = mms_mgmt_send_cmd(sessp, tid, dgcmd, fnam,
			    &response);
			if (st != 0) {
				goto done;
			}
		}
	}

	nvp = NULL;
	while ((nvp = nvlist_next_nvpair(dmattrs, nvp)) != NULL) {
		st = nvpair_value_nvlist(nvp, &nva);
		if (!nva) {
			continue;
		}

		/* be more robust here.  If it > 2, that's surprising */
		if (numdms < 10) {
			olddm[numdms++] = nva;
		}
	}

	/* Update the DMs */
	st = update_DMs(sessp, drvname, olddm, numdms, nvl, errs);
	if (st != 0) {
		goto done;
	}

	nvp = NULL;
	while ((nvp = nvlist_next_nvpair(dgaattrs, nvp)) != NULL) {
		if ((nvpair_value_nvlist(nvp, &nva)) != 0) {
			continue;
		}

		/*
		 * For DRIVEGROUPAPPLICATION, need to check
		 * current DGAs.  Remove any not reflected in
		 * app list, add new
		 */
		if (numdga < 10) {
			olddga[numdga++] = nva;
		}
	}

	/* Update the DriveGroupApplications */
	st = update_DGAs(sessp, dgname, olddga, numdga, nvl, errs);

done:
	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	if (drvattrs) {
		nvlist_free(drvattrs);
	}
	if (dmattrs) {
		nvlist_free(dmattrs);
	}
	if (dgattrs) {
		nvlist_free(dgattrs);
	}
	if (dgaattrs) {
		nvlist_free(dgaattrs);
	}

	return (st);
}

static int
update_DGAs(void *session, char *dgname, nvlist_t **old, int count,
    nvlist_t *nvl, nvlist_t *errs)
{
	int	st;
	int	vcount;
	char	**varray = NULL;
	int	i;
	int	j;
	char	*val;
	char	cmd[8192];
	char	tid[64];
	void	*response;
	int	rst = 0;

	if (!session || !dgname || !old || !nvl) {
		return (MMS_MGMT_NOARG);
	}

	vcount = 0;
	varray = mgmt_var_to_array(nvl, O_APPS, &vcount);

	for (i = 0; i < count; i++) {
		val = NULL;

		(void) nvlist_lookup_string(old[i], "ApplicationName", &val);
		if (!val) {
			continue;
		}

		for (j = 0; j < vcount; j++) {
			if (!varray[j]) {
				continue;
			}
			if (strcmp(val, varray[j]) == 0) {
				/* match, keep this one */
				free(varray[j]);
				varray[j] = NULL;
				break;
			}
		}

		if (j == vcount) {
			/* Remove this DGA */
			(void) mms_gen_taskid(tid);
			(void) snprintf(cmd, sizeof (cmd),
			    "delete task['%s'] type[DRIVEGROUPAPPLICATION] "
			    "match[ and ("
			    "streq(DRIVEGROUPAPPLICATION.'DriveGroupName' "
			    "'%s') "
			    "streq(DRIVEGROUPAPPLICATION.'ApplicationName' "
			    "'%s')"
			    ") ];", tid, dgname, val);

			st = mms_mgmt_send_cmd(session, tid, cmd, "removeDGA",
			    &response);
			if (st != 0) {
				if (rst == 0) {
					rst = st;
				}
				MGMT_ADD_ERR(errs, val, st);
			}
		}
	}

	/* add any remaining */
	for (i = 0; i < vcount; i++) {
		if (!varray[i] || (strlen(varray[i]) == 0) ||
		    (strcasecmp(varray[i], "none") == 0) ||
		    (strcasecmp(varray[i], "all") == 0)) {
			continue;
		}

		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "create task['%s'] type[DRIVEGROUPAPPLICATION] "
		    "set[DRIVEGROUPAPPLICATION.'DriveGroupName' '%s'] "
		    "set[DRIVEGROUPAPPLICATION.'ApplicationName' '%s'];",
		    tid, dgname, varray[i]);

		st = mms_mgmt_send_cmd(session, tid, cmd, "add DGA",
		    &response);
		if (st != 0) {
			if (rst == 0) {
				rst = st;
			}
			MGMT_ADD_ERR(errs, val, st);
		}
	}

	mgmt_free_str_arr(varray, vcount);

	return (rst);
}

static int
update_DMs(void *session, char *drive, nvlist_t **olddms, int count,
    nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	int		rst = 0;
	int		i;
	int		j;
	int		vcount;
	char		**varray = NULL;
	char		*val = NULL;
	char		*val2 = NULL;
	char		*msglevel = NULL;
	char		*trclevel = NULL;
	char		*trcsz = NULL;
	boolean_t	updated = B_FALSE;
	void		*sess = NULL;
	void		*sessp = session;
	char		cmd[8192];
	char		tid[64];
	void		*response = NULL;
	int		highid = 0;
	char		buf[1024];
	char		*bufp;

	if (!drive || !olddms || !nvl) {
		return (MMS_MGMT_NOARG);
	}

	(void) nvlist_lookup_string(nvl, O_MSGLEVEL, &msglevel);
	(void) nvlist_lookup_string(nvl, O_TRACELEVEL, &trclevel);
	(void) nvlist_lookup_string(nvl, O_TRACESZ, &trcsz);

	(void) snprintf(buf, sizeof (buf), "DM_%s_", drive);

	vcount = 0;
	varray = mgmt_var_to_array(nvl, O_DEVCONN, &vcount);

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	for (i = 0; i < count; i++) {
		/* save away existing values in case we need to add a DM */
		if (!msglevel) {
			(void) nvlist_lookup_string(olddms[i], "DMMessagelevel",
			    &msglevel);
		}
		if (!trclevel) {
			(void) nvlist_lookup_string(olddms[i], "TraceLevel",
			    &trclevel);
		}
		if (!trcsz) {
			(void) nvlist_lookup_string(olddms[i], "TraceFileSize",
			    &trcsz);
		}

		(void) nvlist_lookup_string(olddms[i], "DMTargetHost", &val);
		(void) nvlist_lookup_string(olddms[i], "DMName", &val2);

		for (j = 0; j < vcount; j++) {
			if (!varray[j]) {
				continue;
			}
			bufp = val2;

			if (mgmt_compare_hosts(varray[i], val) != 0) {
				continue;
			}
			/* this DM can stay.  */
			if (strncmp(buf, val2, strlen(buf)) == 0) {
				bufp += strlen(buf);
				st = atoi(bufp);
				if (st > highid) {
					highid = st;
				}
				st = 0;
			}
			free(varray[j]);
			varray[j] = NULL;
			break;
		}
		if ((vcount > 1) && (j == vcount)) {
			/* This DM needs to be removed */
			if (st != 0) {
				if (rst == 0) {
					rst = st;
				}
				(void) snprintf(cmd, sizeof (cmd),
				    "%s = %s", O_DEVCONN, val);
				MGMT_ADD_ERR(errs, cmd, EINVAL);
				continue;
			}
			(void) mms_gen_taskid(tid);
			(void) snprintf(cmd, sizeof (cmd),
			    "delete task['%s'] type[DM] "
			    "match[ streq(DM.'DMName' '%s')];",
			    tid, val2);

			st = mms_mgmt_send_cmd(sessp, tid, cmd, "removeDM",
			    &response);
			if (st != 0) {
				if (rst == 0) {
					rst = st;
				}
				MGMT_ADD_ERR(errs, val2, st);
				continue;
			}
		}
	}

	/*
	 * unused DMs are gone.  Add any new ones, and update all with
	 * new values if any
	 */
	for (i = 0; i < vcount; i++) {
		if (!varray[i]) {
			continue;
		}

		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "create task['%s'] type[DM] "
		    "set[DM.'DMName' 'DM_%s_%d'] "
		    "set[DM.'DriveName' '%s'] "
		    "set[DM.'DMTargetHost' '%s'] ",
		    tid, drive, ++highid, drive, varray[i]);

		st = mms_mgmt_send_cmd(sessp, tid, cmd, "addDM",
		    &response);
		if (st != 0) {
			if (rst == 0) {
				rst = st;
			}
			MGMT_ADD_ERR(errs, varray[i], st);
		}
		free(varray[i]);
	}
	/* done with the new DMs */
	free(varray);

	/* update any existing DMs with the new values, if any */
	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "attribute task['%s'] "
	    "match[ streq(DM.'DriveName' '%s')]", tid, drive);

	if (msglevel) {
		(void) snprintf(buf, sizeof (buf),
		    " set[DM.'DMMessageLevel' '%s']", msglevel);
		(void) strlcat(cmd, buf, sizeof (cmd));
		updated = B_TRUE;
	}
	if (trclevel) {
		(void) snprintf(buf, sizeof (buf),
		    " set[DM.'TraceLevel' '%s']", trclevel);
		(void) strlcat(cmd, buf, sizeof (cmd));
		updated = B_TRUE;
	}
	if (trcsz) {
		(void) snprintf(buf, sizeof (buf),
		    " set[DM.'TraceFileSize' '%s']", trcsz);
		(void) strlcat(cmd, buf, sizeof (cmd));
		updated = B_TRUE;
	}
	(void) strlcat(cmd, ";", sizeof (cmd));

	if (updated) {
		st = mms_mgmt_send_cmd(sessp, tid, cmd, "updateDM",
		    &response);
		if (st != 0) {
			if (rst == 0) {
				rst = st;
			}
		}
	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (rst);
}

/* Online/Offline functions */
int
mms_mgmt_set_state(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	char		*fnam = "mms_mgmt_set_state()";
	char		*otype;
	char		*name;
	char		cmd[8192];
	char		tid[64];
	void		*sess = NULL;
	void		*sessp = session;
	void		*response = NULL;
	char		*state = NULL;
	char		*val;
	char		buf[1024];
	nvlist_t	*attrs = NULL;
	nvpair_t	*nvp;
	nvlist_t	*nva;
	char		*key = NULL;

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.device.state")) {
		return (EACCES);
	}

	st = nvlist_lookup_string(nvl, O_OBJTYPE, &otype);
	if (st == 0) {
		if ((strcmp(otype, "drive") != 0) &&
		    (strcmp(otype, "library") != 0)) {
			st = EINVAL;
		}
	}
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_OBJTYPE, st);
		return (st);
	}

	st = nvlist_lookup_string(nvl, O_OBJSTATE, &state);
	if (st == 0) {
		if ((strcmp(state, "online") != 0) &&
		    (strcmp(state, "offline") != 0)) {
			st = EINVAL;
		}
	}
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_OBJSTATE, st);
		return (st);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &name);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	/* get LM or DM names */
	(void) mms_gen_taskid(tid);
	if (*otype == 'l') {
		key = "LMName";
		(void) snprintf(cmd, sizeof (cmd),
		    "show task['%s'] reportmode[namevalue] "
		    "match[streq(LM.'LibraryName' '%s')] "
		    "report[LM.'LMName'];",
		    tid, name);
	} else {
		key = "DMName";
		(void) snprintf(cmd, sizeof (cmd),
		    "show task['%s'] reportmode[namevalue] "
		    "match[streq(DM.'DriveName' '%s')] "
		    "report[DM.'DMName' DM.'DMTargetHost'];",
		    tid, name);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	st = mms_mgmt_send_cmd(sessp, tid, cmd, fnam, &response);
	if (st == 0) {
		st = mmp_get_nvattrs(key, B_FALSE, response, &attrs);
		mms_free_rsp(response);
	}
	if (st != 0) {
		if (sess) {
			(void) mms_goodbye(sess, 0);
		}
		return (st);
	}

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "%s task['%s'] %s['%s'", otype, tid, state, name);

	nvp = NULL;

	/* LM required for lib online, but must not be sent for offline */
	if ((strcmp(otype, "library") == 0) &&
	    (strcmp(state, "online") == 0)) {
		while ((nvp = nvlist_next_nvpair(attrs, nvp)) != NULL) {
			st = nvpair_value_nvlist(nvp, &nva);
			if (st != 0) {
				continue;
			}
			st = nvlist_lookup_string(nva, "LMName", &val);
			if (st == 0) {
				(void) snprintf(buf, sizeof (buf),
				    " '%s'", val);
				(void) strlcat(cmd, buf, sizeof (cmd));
			}
		}
		st = 0;
	}
	(void) strlcat(cmd, "];", sizeof (cmd));

	st = mms_mgmt_send_cmd(sessp, tid, cmd, fnam, &response);
	/* not a failure if already in requested state */
	if ((st == MMS_ELIBALREADYONLINE) ||
	    (st == MMS_EDRIVEALREADYONLINE) ||
	    (st == MMS_ELIBALREADYOFFLINE) ||
	    (st == MMS_EDRIVEALREADYOFFLINE)) {
		st = 0;
	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

int
mms_mgmt_list_drives(void *session, nvlist_t *nvl, nvlist_t *errs,
    nvlist_t **drvs)
{
	int		st;
	void		*sessp = session;
	void		*sess = NULL;
	void		*response = NULL;
	char		tid[64];
	char		cmd[8192];
	nvlist_t	*drvattrs = NULL;
	nvpair_t	*nvp = NULL;
	nvlist_t	*drv;
	char		*val;
	char		*conn[10];	/* should never be more than 2 */
	char		*apps[10];	/* fix this to be dynamic */
	nvlist_t	*oattrs = NULL;
	nvpair_t	*dvp;
	nvlist_t	*dva;
	char		*dval;
	int		i;
	boolean_t	first;
	int		count = 0;
	char		**varray = NULL;
	char		buf[2048];

	if (!drvs) {
		return (MMS_MGMT_NOARG);
	}

	if (*drvs == NULL) {
		st = nvlist_alloc(drvs, 0, 0);
		if (st != 0) {
			MGMT_ADD_ERR(errs, "internal error", st);
			return (st);
		}
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	/* primary filter on name */
	varray = mgmt_var_to_array(nvl, O_NAME, &count);

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] report[DRIVE] reportmode[namevalue]", tid);

	if (count == 1) {
		(void) snprintf(buf, sizeof (buf),
		    " match[streq(DRIVE.'DriveName' '%s')]",
		    varray[0]);
		(void) strlcat(cmd, buf, sizeof (cmd));
	} else if (count > 1) {
		(void) strlcat(cmd, " match[or (", sizeof (cmd));

		for (i = 0; i < count; i++) {
			if (!varray[i]) {
				continue;
			}
			(void) snprintf(buf, sizeof (buf),
			    "streq(DRIVE.'DriveName' '%s') ",
			    varray[i]);
			(void) strlcat(cmd, buf, sizeof (cmd));
		}
		(void) strlcat(cmd, ")]", sizeof (cmd));
	}
	(void) strlcat(cmd, ";", sizeof (cmd));

	mgmt_free_str_arr(varray, count);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "list_drives()", &response);
	if (st == 0) {
		st = mmp_get_nvattrs(O_NAME, B_TRUE, response, &drvattrs);
		mms_free_rsp(response);
	}
	if (st != 0) {
		goto done;
	}

	while ((nvp = nvlist_next_nvpair(drvattrs, nvp)) != NULL) {
		st = nvpair_value_nvlist(nvp, &drv);
		if (st != 0) {
			/* should never happen */
			continue;
		}
		st = nvlist_lookup_string(drv, O_NAME, &val);
		if (st != 0) {
			/* bad response from MM */
			continue;
		}

		(void) memset(&conn, 0, sizeof (conn));
		(void) memset(&apps, 0, sizeof (apps));

		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "show task['%s'] report[DM] reportmode[namevalue] "
		    "match[streq(DM.'DriveName' '%s')];", tid, val);

		st = mms_mgmt_send_cmd(sessp, tid, cmd, "list_dm()",
		    &response);

		if (st != 0) {
			continue;
		}

		oattrs = NULL;
		i = 0;

		st = mmp_get_nvattrs("DMName", B_FALSE, response, &oattrs);
		mms_free_rsp(response);

		dvp = NULL;

		while ((dvp = nvlist_next_nvpair(oattrs, dvp)) != NULL) {
			st = nvpair_value_nvlist(dvp, &dva);
			if (st != 0) {
				continue;
			}

			st = nvlist_lookup_string(dva, "DMTargetHost", &dval);
			if (st == 0) {
				conn[i++] = dval;
			}

			if (!nvlist_exists(dva, O_TRACESZ)) {
				st = nvlist_lookup_string(dva, "TraceFileSize",
				    &dval);
				if (st == 0) {
					(void) nvlist_add_string(drv, O_TRACESZ,
					    dval);
				}
			}
			if (!nvlist_exists(dva, O_TRACELEVEL)) {
				st = nvlist_lookup_string(dva, "TraceLevel",
				    &dval);
				if (st == 0) {
					(void) nvlist_add_string(drv,
					    O_TRACELEVEL, dval);
				}
			}
		}
		cmd[0] = '\0';
		first = B_TRUE;

		while (i > 0) {
			if (!first) {
				(void) strlcat(cmd, ",", sizeof (cmd));
			} else {
				first = B_FALSE;
			}
			(void) strlcat(cmd, conn[--i], sizeof (cmd));
		}
		(void) nvlist_add_string(drv, O_DEVCONN, cmd);

		nvlist_free(oattrs);
		oattrs = NULL;

		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "show task['%s'] reportmode[namevalue] "
		    "report[DRIVEGROUPAPPLICATION.'ApplicationName'] "
		    "match[streq(DRIVE.'DriveName' '%s')];", tid, val);

		st = mms_mgmt_send_cmd(sessp, tid, cmd, "list drive apps()",
		    &response);

		if (st == 0) {
			st = mmp_get_nvattrs("ApplicationName", B_FALSE,
			    response, &oattrs);
			mms_free_rsp(response);
		}

		if (st != 0) {
			continue;
		}

		i = 0;
		while ((dvp = nvlist_next_nvpair(oattrs, dvp)) != NULL) {
			dval = nvpair_name(dvp);
			if (dval == NULL) {
				continue;
			}

			apps[i++] = dval;
		}

		cmd[0] = '\0';
		first = B_TRUE;

		while (i > 0) {
			if (!first) {
				(void) strlcat(cmd, ",", sizeof (cmd));
			} else {
				first = B_FALSE;
			}
			(void) strlcat(cmd, apps[--i], sizeof (cmd));
		}
		(void) nvlist_add_string(drv, O_APPS, cmd);

		nvlist_free(oattrs);

		(void) nvlist_add_nvlist(*drvs, val, drv);
	}

	/* filter before returning */
	mgmt_filter_results(nvl, *drvs);

	/* reset status */
	st = 0;

done:
	nvlist_free(drvattrs);

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}


	return (st);
}

int
mms_mgmt_list_libraries(void *session, nvlist_t *nvl, nvlist_t *errs,
    nvlist_t **libs)
{
	int		st;
	void		*sessp = session;
	void		*sess = NULL;
	void		*response = NULL;
	char		tid[64];
	char		cmd[8192];
	nvlist_t	*libattrs = NULL;
	nvpair_t	*nvp = NULL;
	nvlist_t	*lib;
	char		*val;
	nvlist_t	*oattrs = NULL;
	nvpair_t	*lvp;
	nvlist_t	*lva;
	char		*lval;
	int		count = 0;
	int		i;
	char		**varray = NULL;
	char		buf[2048];

	if (!libs) {
		return (MMS_MGMT_NOARG);
	}

	if (*libs == NULL) {
		st = nvlist_alloc(libs, 0, 0);
		if (st != 0) {
			MGMT_ADD_ERR(errs, "internal error", st);
			return (st);
		}
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	/* primary filter on name */
	varray = mgmt_var_to_array(nvl, O_NAME, &count);

	(void) mms_gen_taskid(tid);

	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] report[LIBRARY] reportmode[namevalue]", tid);

	if (count == 1) {
		(void) snprintf(buf, sizeof (buf),
		    " match[streq(LIBRARY.'LibraryName' '%s')]",
		    varray[0]);
		(void) strlcat(cmd, buf, sizeof (cmd));
	} else if (count > 1) {
		(void) strlcat(cmd, " match[or (", sizeof (cmd));

		for (i = 0; i < count; i++) {
			if (!varray[i]) {
				continue;
			}
			(void) snprintf(buf, sizeof (buf),
			    "streq(LIBRARY.'LibraryName' '%s') ",
			    varray[i]);
			(void) strlcat(cmd, buf, sizeof (cmd));
		}
		(void) strlcat(cmd, ")]", sizeof (cmd));
	}
	(void) strlcat(cmd, ";", sizeof (cmd));

	mgmt_free_str_arr(varray, count);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "list_libraries()", &response);
	if (st == 0) {
		st = mmp_get_nvattrs(O_MMSLIB, B_TRUE, response, &libattrs);
		mms_free_rsp(response);
	}
	if (st != 0) {
		goto done;
	}

	while ((nvp = nvlist_next_nvpair(libattrs, nvp)) != NULL) {
		st = nvpair_value_nvlist(nvp, &lib);
		if (st != 0) {
			/* should never happen */
			continue;
		}
		st = nvlist_lookup_string(lib, O_MMSLIB, &val);
		if (st != 0) {
			/* bad response from MM */
			continue;
		}

		(void) mms_gen_taskid(tid);
		(void) snprintf(cmd, sizeof (cmd),
		    "show task['%s'] report[LM] reportmode[namevalue] "
		    "match[streq(LM.'LibraryName' '%s')];", tid, val);

		st = mms_mgmt_send_cmd(sessp, tid, cmd, "list_dm()",
		    &response);

		if (st != 0) {
			continue;
		}

		oattrs = NULL;

		st = mmp_get_nvattrs("LMName", B_FALSE, response, &oattrs);
		mms_free_rsp(response);

		lvp = NULL;

		while ((lvp = nvlist_next_nvpair(oattrs, lvp)) != NULL) {
			st = nvpair_value_nvlist(lvp, &lva);
			if (st != 0) {
				continue;
			}

			if (!nvlist_exists(lva, O_TRACESZ)) {
				st = nvlist_lookup_string(lva, "TraceFileSize",
				    &lval);
				if (st == 0) {
					(void) nvlist_add_string(lib, O_TRACESZ,
					    lval);
				}
			}
			if (!nvlist_exists(lva, O_TRACELEVEL)) {
				st = nvlist_lookup_string(lva, "TraceLevel",
				    &lval);
				if (st == 0) {
					(void) nvlist_add_string(lib,
					    O_TRACELEVEL, lval);
				}
			}
			if (!nvlist_exists(lva, O_MSGLEVEL)) {
				st = nvlist_lookup_string(lva, "MessageLevel",
				    &lval);
				if (st == 0) {
					(void) nvlist_add_string(lib,
					    O_MSGLEVEL, lval);
				}
			}
		}

		nvlist_free(oattrs);

		(void) nvlist_add_nvlist(*libs, val, lib);
	}

	/* filter before returning */
	mgmt_filter_results(nvl, *libs);

	/* reset status */
	st = 0;

done:
	nvlist_free(libattrs);

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}


	return (st);
}

int
mgmt_get_dgname(void *session, char *dgname, nvlist_t **dg)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	char		tid[64];
	char 		cmd[8192];

	if (!dg) {
		return (MMS_MGMT_NOARG);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	*dg = NULL;

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] "
	    "match[streq(DRIVEGROUP.'DriveGroupName' '%s')] "
	    "report[DRIVEGROUP.'DriveGroupName'] "
	    "reportmode[namevalue]; ", tid, dgname);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "mgmt_get_dgname",
	    &response);
	if (st == 0) {
		st = mmp_get_nvattrs("DriveGroupName", B_FALSE, response,
		    dg);
		mms_free_rsp(response);
	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

int
mgmt_get_cgname(void *session, char *cgname, nvlist_t **cg)
{
	int		st;
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	char		tid[64];
	char 		cmd[8192];

	if (!cg) {
		return (MMS_MGMT_NOARG);
	}

	if (!session) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	*cg = NULL;

	(void) mms_gen_taskid(tid);
	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] "
	    "match[streq(CARTRIDGEGROUP.'CartridgeGroupName' '%s')] "
	    "report[CARTRIDGEGROUP.'CartridgeGroupName'] "
	    "reportmode[namevalue]; ", tid, cgname);

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "mgmt_get_cgname",
	    &response);
	if (st == 0) {
		st = mmp_get_nvattrs("CartridgeGroupName", B_FALSE, response,
		    cg);
		mms_free_rsp(response);
	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

/*
 * mms_mgmt_modify_dpool()
 *	Add applications to existing dpool (DRIVEGROUP) by adding a
 *	DRIVEGROUPAPPLICATION for every app specified.
 */
int
mms_mgmt_modify_dpool(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	char		**varray = NULL;
	int		count = 0;
	int		i;
	char		cmd[8192];
	char		tid[64];
	void		*sess = NULL;
	void		*sessp = session;
	void		*response;
	char		*dpool;
	nvlist_t	*dgattrs = NULL;
	nvlist_t	*new = NULL;

	/* get list of apps, if new list != old list, update */

	if (!mgmt_chk_auth("solaris.mms.modify")) {
		return (EACCES);
	}

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &dpool);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	varray = mgmt_var_to_array(nvl, O_APPS, &count);
	if (varray == NULL) {
		/* error or nothing to do? */
		return (0);
	}

	/* get list of already-established apps */
	(void) mms_gen_taskid(tid);

	(void) snprintf(cmd, sizeof (cmd),
	    "show task['%s'] reportmode[namevalue] "
	    "match[streq(DRIVEGROUPAPPLICATION.'DriveGroupName' '%s')] "
	    "report[DRIVEGROUPAPPLICATION.'ApplicationName'];",
	    tid, dpool);

	if (session == NULL) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			goto done;
		}
		sessp = sess;
	}

	st = mms_mgmt_send_cmd(sessp, tid, cmd, "modify drivegroup",
	    &response);
	if (st == 0) {
		st = mmp_get_nvattrs("ApplicationName", B_FALSE, response,
		    &dgattrs);
		mms_free_rsp(response);
	}
	if (st != 0) {
		goto done;
	}

	/* see if we need to add any apps */
	for (i = 0; i < count; i++) {
		if (!varray[i] || (strlen(varray[i]) == 0) ||
		    (strcasecmp(varray[i], "none") == 0) ||
		    (strcasecmp(varray[i], "all") == 0)) {
			continue;
		}

		if (!nvlist_exists(dgattrs, varray[i])) {
			if (!new) {
				(void) nvlist_alloc(&new, NV_UNIQUE_NAME, 0);
				(void) nvlist_add_string(new, O_NAME, dpool);
			}

			(void) nvlist_add_string(new, O_APPS, varray[i]);
			st = mms_add_object(sessp, "DRIVEGROUPAPPLICATION",
			    drvgrpappopts, new, errs);
			if (st != 0) {
				break;
			}
		}
	}

done:

	if (new) {
		nvlist_free(new);
	}

	if (dgattrs) {
		nvlist_free(dgattrs);
	}

	mgmt_free_str_arr(varray, count);

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

int
mms_mgmt_add_dpool(void *session, nvlist_t *nvl, nvlist_t *errs)
{
	int		st;
	char		**varray = NULL;
	int		count = 0;
	char		*dpool = NULL;
	int		i;

	if (!nvl) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.create")) {
		return (EACCES);
	}

	st = nvlist_lookup_string(nvl, O_NAME, &dpool);
	if (st != 0) {
		MGMT_ADD_OPTERR(errs, O_NAME, st);
		return (st);
	}

	/* save original values */
	varray = mgmt_var_to_array(nvl, O_APPS, &count);
	if (count == 0) {
		st = MMS_MGMT_ERR_REQUIRED;
		MGMT_ADD_OPTERR(errs, O_APPS, st);
		return (st);
	}

	st = mms_add_object(session, "DRIVEGROUP", drvgrpopts,
	    nvl, errs);
	if (st == EEXIST) {
		MGMT_ADD_OPTERR(errs, dpool, st);
		return (st);
	}
	if (st == 0) {
		for (i = 0; i < count; i++) {
			if (!varray[i] || (strlen(varray[i]) == 0) ||
			    (strcasecmp(varray[i], "none") == 0) ||
			    (strcasecmp(varray[i], "all") == 0)) {
				continue;
			}

			/* put back a single value */
			(void) nvlist_add_string(nvl, O_APPS, varray[i]);
			st = mms_add_object(session,
			    "DRIVEGROUPAPPLICATION", drvgrpappopts, nvl, errs);
			if (st != 0) {
				MGMT_ADD_ERR(errs, varray[i], st);
				break;
			}
		}

		/* put back original values */
		if (varray) {
			(void) nvlist_add_string_array(nvl, O_APPS, varray,
			    count);
			mgmt_free_str_arr(varray, count);
		}
	}
	return (st);
}
