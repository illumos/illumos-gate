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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <assert.h>
#include <auth_attr.h>
#include <auth_list.h>
#include <bsm/adt.h>
#include <bsm/adt_event.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <pwd.h>
#include <secdb.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>

#include "libnwam_impl.h"
#include <libnwam_priv.h>
#include <libnwam.h>

/*
 * Communicate with and implement library backend (running in netcfgd) to
 * retrieve or change NWAM configuration.
 */

static int backend_door_client_fd = -1;

/*
 * Check if uid has proper auths.  flags is used to check auths for
 * enable/disable of profiles and manipulation of Known WLANs.
 */
static nwam_error_t
nwam_check_auths(uid_t uid, boolean_t write, uint64_t flags)
{
	struct passwd *pwd;
	nwam_error_t err = NWAM_SUCCESS;

	if ((pwd = getpwuid(uid)) == NULL) {
		endpwent();
		return (NWAM_PERMISSION_DENIED);
	}

	if (flags & NWAM_FLAG_ENTITY_ENABLE) {
		/* Enabling/disabling profile - need SELECT auth */
		if (chkauthattr(AUTOCONF_SELECT_AUTH, pwd->pw_name) == 0)
			err = NWAM_PERMISSION_DENIED;

	} else if (flags & NWAM_FLAG_ENTITY_KNOWN_WLAN) {
		/* Known WLAN activity - need WLAN auth */
		if (chkauthattr(AUTOCONF_WLAN_AUTH, pwd->pw_name) == 0)
			err = NWAM_PERMISSION_DENIED;

	} else {
		/*
		 * First, check for WRITE, since it implies READ.  If this
		 * auth is not present, and write is true, fail, otherwise
		 * check for READ.
		 */
		if (chkauthattr(AUTOCONF_WRITE_AUTH, pwd->pw_name) == 0) {
			if (write) {
				err = NWAM_PERMISSION_DENIED;
			} else {
				if (chkauthattr(AUTOCONF_READ_AUTH,
				    pwd->pw_name) == 0)
					err = NWAM_PERMISSION_DENIED;
			}
		}
	}

	endpwent();
	return (err);
}

static nwam_error_t
nwam_create_backend_door_arg(nwam_backend_door_cmd_t cmd,
    const char *dbname, const char *objname, uint64_t flags,
    void *obj, nwam_backend_door_arg_t *arg)
{
	nwam_error_t err;
	size_t datalen = 0;
	caddr_t dataptr;

	switch (cmd) {
	case NWAM_BACKEND_DOOR_CMD_READ_REQ:
		/*
		 * For a read request,  we want the full buffer to be
		 * available for the backend door to write to.
		 */
		datalen = NWAM_BACKEND_DOOR_ARG_SIZE;
		break;

	case NWAM_BACKEND_DOOR_CMD_UPDATE_REQ:
		/*
		 * An update request may either specify an object list
		 * (which we pack into the buffer immediately after the
		 * backend door request) or may not specify an object
		 * (signifying a request to create the container of the
		 * object).
		 */
		if (obj == NULL) {
			datalen = 0;
			break;
		}
		/* Data immediately follows the descriptor */
		dataptr = (caddr_t)arg + sizeof (nwam_backend_door_arg_t);
		datalen = NWAM_BACKEND_DOOR_ARG_SIZE;
		/* pack object list for update request,  adjusting datalen */
		if ((err = nwam_pack_object_list(obj, (char **)&dataptr,
		    &datalen)) != NWAM_SUCCESS)
			return (err);
		break;

	case NWAM_BACKEND_DOOR_CMD_REMOVE_REQ:
		/* A remove request has no associated object list. */
		datalen = 0;
		break;

	default:
		return (NWAM_INVALID_ARG);
	}

	arg->nwbda_cmd = cmd;
	arg->nwbda_flags = flags;
	arg->nwbda_datalen = datalen;
	arg->nwbda_result = NWAM_SUCCESS;

	if (dbname != NULL)
		(void) strlcpy(arg->nwbda_dbname, dbname, MAXPATHLEN);
	else
		arg->nwbda_dbname[0] = '\0';

	if (objname != NULL)
		(void) strlcpy(arg->nwbda_object, objname, NWAM_MAX_NAME_LEN);
	else
		arg->nwbda_object[0] = '\0';

	return (NWAM_SUCCESS);
}

/*
 * If the arg datalen is non-zero,  unpack the object list associated with
 * the backend door argument.
 */
static nwam_error_t
nwam_read_object_from_backend_door_arg(nwam_backend_door_arg_t *arg,
    char *dbname, char *name, void *objp)
{
	nwam_error_t err;
	caddr_t dataptr = (caddr_t)arg + sizeof (nwam_backend_door_arg_t);

	if (arg->nwbda_result != NWAM_SUCCESS)
		return (arg->nwbda_result);

	if (arg->nwbda_datalen > 0) {
		if ((err = nwam_unpack_object_list((char *)dataptr,
		    arg->nwbda_datalen, objp)) != NWAM_SUCCESS)
			return (err);
	} else {
		*((char **)objp) = NULL;
	}

	/*
	 * If "dbname" and "name" are non-NULL, copy in the actual dbname
	 * and name values from the door arg since both may have been changed
	 * from case-insensitive to case-sensitive matches.  They will be the
	 * same length as they only differ in case.
	 */
	if (dbname != NULL && strcmp(dbname, arg->nwbda_dbname) != 0)
		(void) strlcpy(dbname, arg->nwbda_dbname, strlen(dbname) + 1);
	if (name != NULL && strcmp(name, arg->nwbda_object) != 0)
		(void) strlcpy(name, arg->nwbda_object, strlen(name) + 1);

	return (NWAM_SUCCESS);
}

/* ARGSUSED */
void
nwam_backend_door_server(void *cookie, char *arg, size_t arg_size,
    door_desc_t *dp, uint_t ndesc)
{
	/* LINTED: alignment */
	nwam_backend_door_arg_t *req = (nwam_backend_door_arg_t *)arg;
	nwam_error_t err;
	void *obj, *newobj = NULL;
	ucred_t *ucr = NULL;
	uid_t uid;
	boolean_t write = B_TRUE;

	/* Check arg size */
	if (arg_size < sizeof (nwam_backend_door_arg_t)) {
		req->nwbda_result = NWAM_INVALID_ARG;
		(void) door_return((char *)req,
		    sizeof (nwam_backend_door_arg_t), NULL, 0);
	}

	if (door_ucred(&ucr) != 0) {
		req->nwbda_result = NWAM_ERROR_INTERNAL;
		(void) door_return((char *)req, arg_size, NULL, 0);
	}

	/* Check auths */
	uid = ucred_getruid(ucr);

	if (req->nwbda_cmd == NWAM_BACKEND_DOOR_CMD_READ_REQ)
		write = B_FALSE;
	if ((err = nwam_check_auths(uid, write, req->nwbda_flags))
	    != NWAM_SUCCESS) {
		if (write) {
			nwam_record_audit_event(ucr,
			    req->nwbda_cmd == NWAM_BACKEND_DOOR_CMD_UPDATE_REQ ?
			    ADT_netcfg_update : ADT_netcfg_remove,
			    (char *)req->nwbda_object,
			    (char *)req->nwbda_dbname, ADT_FAILURE,
			    ADT_FAIL_VALUE_AUTH);
		}
		req->nwbda_result = err;
		goto door_return;
	}

	switch (req->nwbda_cmd) {
	case NWAM_BACKEND_DOOR_CMD_READ_REQ:
		if ((req->nwbda_result = nwam_read_object_from_files_backend
		    (strlen(req->nwbda_dbname) > 0 ? req->nwbda_dbname : NULL,
		    strlen(req->nwbda_object) > 0 ? req->nwbda_object : NULL,
		    req->nwbda_flags, &newobj)) != NWAM_SUCCESS) {
			break;
		}
		if (newobj != NULL) {
			size_t datalen = arg_size -
			    sizeof (nwam_backend_door_arg_t);
			caddr_t dataptr = (caddr_t)req +
			    sizeof (nwam_backend_door_arg_t);

			if ((req->nwbda_result = nwam_pack_object_list(newobj,
			    (char **)&dataptr, &datalen)) != NWAM_SUCCESS)
				req->nwbda_datalen = 0;
			else
				req->nwbda_datalen = datalen;
			nwam_free_object_list(newobj);
		} else {
			req->nwbda_datalen = 0;
		}
		break;

	case NWAM_BACKEND_DOOR_CMD_UPDATE_REQ:
		if (req->nwbda_datalen == 0) {
			obj = NULL;
		} else {
			if ((req->nwbda_result =
			    nwam_read_object_from_backend_door_arg
			    (req, NULL, NULL, &obj)) != NWAM_SUCCESS)
				break;
		}
		req->nwbda_result = nwam_update_object_in_files_backend(
		    req->nwbda_dbname[0] == 0 ? NULL : req->nwbda_dbname,
		    req->nwbda_object[0] == 0 ? NULL : req->nwbda_object,
		    req->nwbda_flags, obj);
		nwam_free_object_list(obj);
		if (req->nwbda_result == NWAM_SUCCESS) {
			req->nwbda_datalen = 0;
			nwam_record_audit_event(ucr, ADT_netcfg_update,
			    (char *)req->nwbda_object,
			    (char *)req->nwbda_dbname, ADT_SUCCESS,
			    ADT_SUCCESS);
		}
		break;

	case NWAM_BACKEND_DOOR_CMD_REMOVE_REQ:
		req->nwbda_result = nwam_remove_object_from_files_backend
		    (strlen(req->nwbda_dbname) > 0 ? req->nwbda_dbname : NULL,
		    strlen(req->nwbda_object) > 0 ? req->nwbda_object : NULL,
		    req->nwbda_flags);
		if (req->nwbda_result == NWAM_SUCCESS) {
			nwam_record_audit_event(ucr, ADT_netcfg_update,
			    (char *)req->nwbda_object,
			    (char *)req->nwbda_dbname, ADT_SUCCESS,
			    ADT_SUCCESS);
		}
		break;

	default:
		req->nwbda_result = NWAM_INVALID_ARG;
		break;
	}

door_return:
	ucred_free(ucr);

	(void) door_return((char *)req, arg_size, NULL, 0);
}

static int backend_door_fd = -1;

void
nwam_backend_fini(void)
{
	if (backend_door_fd != -1) {
		(void) door_revoke(backend_door_fd);
		backend_door_fd = -1;
	}
	(void) unlink(NWAM_BACKEND_DOOR_FILE);
}

nwam_error_t
nwam_backend_init(void)
{
	int did;
	struct stat statbuf;

	/* Create the door directory if it doesn't already exist */
	if (stat(NWAM_DOOR_DIR, &statbuf) < 0) {
		if (mkdir(NWAM_DOOR_DIR, (mode_t)0755) < 0)
			return (NWAM_ERROR_BACKEND_INIT);
	} else {
		if ((statbuf.st_mode & S_IFMT) != S_IFDIR)
			return (NWAM_ERROR_BACKEND_INIT);
	}

	if (chmod(NWAM_DOOR_DIR, 0755) < 0 ||
	    chown(NWAM_DOOR_DIR, UID_NETADM, GID_NETADM) < 0)
		return (NWAM_ERROR_BACKEND_INIT);

	/* Do a low-overhead "touch" on the file that will be the door node. */
	did = open(NWAM_BACKEND_DOOR_FILE,
	    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK,
	    S_IRUSR | S_IRGRP | S_IROTH);

	if (did != -1)
		(void) close(did);
	else if (errno != EEXIST)
		return (NWAM_ERROR_BACKEND_INIT);

	/* Create the door. */
	backend_door_fd = door_create(nwam_backend_door_server, NULL,
	    DOOR_REFUSE_DESC);
	if (backend_door_fd == -1)
		return (NWAM_ERROR_BACKEND_INIT);

	/* Attach the door to the file. */
	(void) fdetach(NWAM_BACKEND_DOOR_FILE);
	if (fattach(backend_door_fd, NWAM_BACKEND_DOOR_FILE) == -1) {
		(void) door_revoke(backend_door_fd);
		return (NWAM_ERROR_BACKEND_INIT);
	}

	return (NWAM_SUCCESS);
}

static nwam_error_t
nwam_backend_door_call(nwam_backend_door_cmd_t cmd, char *dbname,
    char *objname, uint64_t flags, void *obj)
{
	uchar_t reqbuf[NWAM_BACKEND_DOOR_ARG_SIZE];
	/* LINTED: alignment */
	nwam_backend_door_arg_t *req = (nwam_backend_door_arg_t *)&reqbuf;
	nwam_error_t err, reserr;

	if ((err = nwam_create_backend_door_arg(cmd, dbname, objname, flags,
	    obj, req)) != NWAM_SUCCESS)
		return (err);

	if (nwam_make_door_call(NWAM_BACKEND_DOOR_FILE, &backend_door_client_fd,
	    req, sizeof (reqbuf)) != 0)
		return (NWAM_ERROR_BIND);

	reserr = req->nwbda_result;

	if (cmd == NWAM_BACKEND_DOOR_CMD_READ_REQ) {
		err = nwam_read_object_from_backend_door_arg(req, dbname,
		    objname, obj);
	}

	return (err == NWAM_SUCCESS ? reserr : err);
}

/*
 * Read object specified by objname from backend dbname, retrieving an object
 * list representation.
 *
 * If dbname is NULL, obj is a list of string arrays consisting of the list
 * of backend dbnames.
 *
 * If objname is NULL, read all objects in the specified dbname and create
 * an object list containing a string array which represents each object.
 *
 * Otherwise obj will point to a list of the properties for the object
 * specified by objname in the backend dbname.
 */
/* ARGSUSED2 */
nwam_error_t
nwam_read_object_from_backend(char *dbname, char *objname,
    uint64_t flags, void *obj)
{
	nwam_error_t err = nwam_check_auths(getuid(), B_FALSE, flags);

	if (err != NWAM_SUCCESS)
		return (err);

	return (nwam_backend_door_call(NWAM_BACKEND_DOOR_CMD_READ_REQ,
	    dbname, objname, flags, obj));
}

/*
 * Read in all objects from backend dbname and update object corresponding
 * to objname with properties recorded in proplist, writing the results to
 * the backend dbname.
 */
nwam_error_t
nwam_update_object_in_backend(char *dbname, char *objname,
    uint64_t flags, void *obj)
{
	nwam_error_t err = nwam_check_auths(getuid(), B_TRUE, flags);

	if (err != NWAM_SUCCESS)
		return (err);

	return (nwam_backend_door_call(NWAM_BACKEND_DOOR_CMD_UPDATE_REQ,
	    dbname, objname, flags, obj));
}

/*
 * Remove specified object from backend by reading in the list of objects,
 * removing objname and writing the remainder.
 *
 * If objname is NULL, remove the backend dbname.
 */
nwam_error_t
nwam_remove_object_from_backend(char *dbname, char *objname, uint64_t flags)
{
	nwam_error_t err = nwam_check_auths(getuid(), B_TRUE, flags);

	if (err != NWAM_SUCCESS)
		return (err);

	return (nwam_backend_door_call(NWAM_BACKEND_DOOR_CMD_REMOVE_REQ,
	    dbname, objname, flags, NULL));
}
