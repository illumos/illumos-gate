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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014, Joyent Inc. All rights reserved.
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <zone.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stropts.h>
#include <sys/conf.h>
#include <pthread.h>
#include <unistd.h>
#include <wait.h>
#include <libcontract.h>
#include <libcontract_priv.h>
#include <sys/contract/process.h>
#include <sys/vnic.h>
#include <zone.h>
#include "dlmgmt_impl.h"

typedef enum dlmgmt_db_op {
	DLMGMT_DB_OP_WRITE,
	DLMGMT_DB_OP_DELETE,
	DLMGMT_DB_OP_READ
} dlmgmt_db_op_t;

typedef struct dlmgmt_db_req_s {
	struct dlmgmt_db_req_s	*ls_next;
	dlmgmt_db_op_t		ls_op;
	char			ls_link[MAXLINKNAMELEN];
	datalink_id_t		ls_linkid;
	zoneid_t		ls_zoneid;
	uint32_t		ls_flags;	/* Either DLMGMT_ACTIVE or   */
						/* DLMGMT_PERSIST, not both. */
} dlmgmt_db_req_t;

/*
 * List of pending db updates (e.g., because of a read-only filesystem).
 */
static dlmgmt_db_req_t	*dlmgmt_db_req_head = NULL;
static dlmgmt_db_req_t	*dlmgmt_db_req_tail = NULL;

/*
 * rewrite_needed is set to B_TRUE by process_link_line() if it encounters a
 * line with an old format.  This will cause the file being read to be
 * re-written with the current format.
 */
static boolean_t	rewrite_needed;

static int		dlmgmt_db_update(dlmgmt_db_op_t, const char *,
			    dlmgmt_link_t *, uint32_t);
static int		dlmgmt_process_db_req(dlmgmt_db_req_t *);
static int		dlmgmt_process_db_onereq(dlmgmt_db_req_t *, boolean_t);
static void		*dlmgmt_db_update_thread(void *);
static boolean_t	process_link_line(char *, dlmgmt_link_t *);
static int		process_db_write(dlmgmt_db_req_t *, FILE *, FILE *);
static int		process_db_read(dlmgmt_db_req_t *, FILE *);
static void		generate_link_line(dlmgmt_link_t *, boolean_t, char *);

#define	BUFLEN(lim, ptr)	(((lim) > (ptr)) ? ((lim) - (ptr)) : 0)
#define	MAXLINELEN		1024

typedef void db_walk_func_t(dlmgmt_link_t *);

/*
 * Translator functions to go from dladm_datatype_t to character strings.
 * Each function takes a pointer to a buffer, the size of the buffer,
 * the name of the attribute, and the value to be written.  The functions
 * return the number of bytes written to the buffer.  If the buffer is not big
 * enough to hold the string representing the value, then nothing is written
 * and 0 is returned.
 */
typedef size_t write_func_t(char *, size_t, char *, void *);

/*
 * Translator functions to read from a NULL terminated string buffer into
 * something of the given DLADM_TYPE_*.  The functions each return the number
 * of bytes read from the string buffer.  If there is an error reading data
 * from the buffer, then 0 is returned.  It is the caller's responsibility
 * to free the data allocated by these functions.
 */
typedef size_t read_func_t(char *, void **);

typedef struct translator_s {
	const char	*type_name;
	write_func_t	*write_func;
	read_func_t	*read_func;
} translator_t;

/*
 * Translator functions, defined later but declared here so that
 * the translator table can be defined.
 */
static write_func_t	write_str, write_boolean, write_uint64;
static read_func_t	read_str, read_boolean, read_int64;

/*
 * Translator table, indexed by dladm_datatype_t.
 */
static translator_t translators[] = {
	{ "string",	write_str,	read_str	},
	{ "boolean",	write_boolean,	read_boolean	},
	{ "int",	write_uint64,	read_int64	}
};

static size_t ntranslators = sizeof (translators) / sizeof (translator_t);

#define	LINK_PROPERTY_DELIMINATOR	";"
#define	LINK_PROPERTY_TYPE_VALUE_SEP	","
#define	BASE_PROPERTY_LENGTH(t, n) (strlen(translators[(t)].type_name) +\
				    strlen(LINK_PROPERTY_TYPE_VALUE_SEP) +\
				    strlen(LINK_PROPERTY_DELIMINATOR) +\
				    strlen((n)))
#define	GENERATE_PROPERTY_STRING(buf, length, conv, name, type, val) \
	    (snprintf((buf), (length), "%s=%s%s" conv "%s", (name), \
	    translators[(type)].type_name, \
	    LINK_PROPERTY_TYPE_VALUE_SEP, (val), LINK_PROPERTY_DELIMINATOR))

/*
 * Name of the cache file to keep the active <link name, linkid> mapping
 */
char	cachefile[MAXPATHLEN];

#define	DLMGMT_PERSISTENT_DB_PATH	"/etc/dladm/datalink.conf"
#define	DLMGMT_MAKE_FILE_DB_PATH(buffer, persistent)	\
	(void) snprintf((buffer), MAXPATHLEN, "%s", \
	(persistent) ? DLMGMT_PERSISTENT_DB_PATH : cachefile);

typedef struct zopen_arg {
	const char	*zopen_modestr;
	int		*zopen_pipe;
	int		zopen_fd;
} zopen_arg_t;

typedef struct zrename_arg {
	const char	*zrename_newname;
} zrename_arg_t;

typedef union zfoparg {
	zopen_arg_t	zfop_openarg;
	zrename_arg_t	zfop_renamearg;
} zfoparg_t;

typedef struct zfcbarg {
	boolean_t	zfarg_inglobalzone; /* is callback in global zone? */
	zoneid_t	zfarg_finglobalzone; /* is file in global zone? */
	const char	*zfarg_filename;
	zfoparg_t	*zfarg_oparg;
} zfarg_t;
#define	zfarg_openarg	zfarg_oparg->zfop_openarg
#define	zfarg_renamearg	zfarg_oparg->zfop_renamearg

/* zone file callback */
typedef int zfcb_t(zfarg_t *);

/*
 * Execute an operation on filename relative to zoneid's zone root.  If the
 * file is in the global zone, then the zfcb() callback will simply be called
 * directly.  If the file is in a non-global zone, then zfcb() will be called
 * both from the global zone's context, and from the non-global zone's context
 * (from a fork()'ed child that has entered the non-global zone).  This is
 * done to allow the callback to communicate with itself if needed (e.g. to
 * pass back the file descriptor of an opened file).
 */
static int
dlmgmt_zfop(const char *filename, zoneid_t zoneid, zfcb_t *zfcb,
    zfoparg_t *zfoparg)
{
	int		ctfd;
	int		err;
	pid_t		childpid;
	siginfo_t	info;
	zfarg_t		zfarg;
	ctid_t		ct;

	if (zoneid != GLOBAL_ZONEID) {
		/*
		 * We need to access a file that isn't in the global zone.
		 * Accessing non-global zone files from the global zone is
		 * unsafe (due to symlink attacks), we'll need to fork a child
		 * that enters the zone in question and executes the callback
		 * that will operate on the file.
		 *
		 * Before we proceed with this zone tango, we need to create a
		 * new process contract for the child, as required by
		 * zone_enter().
		 */
		errno = 0;
		ctfd = open64("/system/contract/process/template", O_RDWR);
		if (ctfd == -1)
			return (errno);
		if ((err = ct_tmpl_set_critical(ctfd, 0)) != 0 ||
		    (err = ct_tmpl_set_informative(ctfd, 0)) != 0 ||
		    (err = ct_pr_tmpl_set_fatal(ctfd, CT_PR_EV_HWERR)) != 0 ||
		    (err = ct_pr_tmpl_set_param(ctfd, CT_PR_PGRPONLY)) != 0 ||
		    (err = ct_tmpl_activate(ctfd)) != 0) {
			(void) close(ctfd);
			return (err);
		}
		childpid = fork();
		switch (childpid) {
		case -1:
			(void) ct_tmpl_clear(ctfd);
			(void) close(ctfd);
			return (err);
		case 0:
			(void) ct_tmpl_clear(ctfd);
			(void) close(ctfd);
			/*
			 * Elevate our privileges as zone_enter() requires all
			 * privileges.
			 */
			if ((err = dlmgmt_elevate_privileges()) != 0)
				_exit(err);
			if (zone_enter(zoneid) == -1)
				_exit(errno);
			if ((err = dlmgmt_drop_privileges()) != 0)
				_exit(err);
			break;
		default:
			if (contract_latest(&ct) == -1)
				ct = -1;
			(void) ct_tmpl_clear(ctfd);
			(void) close(ctfd);
			if (waitid(P_PID, childpid, &info, WEXITED) == -1) {
				(void) contract_abandon_id(ct);
				return (errno);
			}
			(void) contract_abandon_id(ct);
			if (info.si_status != 0)
				return (info.si_status);
		}
	}

	zfarg.zfarg_inglobalzone = (zoneid == GLOBAL_ZONEID || childpid != 0);
	zfarg.zfarg_finglobalzone = (zoneid == GLOBAL_ZONEID);
	zfarg.zfarg_filename = filename;
	zfarg.zfarg_oparg = zfoparg;
	err = zfcb(&zfarg);
	if (!zfarg.zfarg_inglobalzone)
		_exit(err);
	return (err);
}

static int
dlmgmt_zopen_cb(zfarg_t *zfarg)
{
	struct strrecvfd recvfd;
	boolean_t	newfile = B_FALSE;
	boolean_t	inglobalzone = zfarg->zfarg_inglobalzone;
	zoneid_t	finglobalzone = zfarg->zfarg_finglobalzone;
	const char	*filename = zfarg->zfarg_filename;
	const char	*modestr = zfarg->zfarg_openarg.zopen_modestr;
	int		*p = zfarg->zfarg_openarg.zopen_pipe;
	struct stat	statbuf;
	int		oflags;
	mode_t		mode;
	int		fd = -1;
	int		err;

	/* We only ever open a file for reading or writing, not both. */
	oflags = (modestr[0] == 'r') ? O_RDONLY : O_WRONLY | O_CREAT | O_TRUNC;
	mode = (modestr[0] == 'r') ? 0 : S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

	/* Open the file if we're in the same zone as the file. */
	if (inglobalzone == finglobalzone) {
		/*
		 * First determine if we will be creating the file as part of
		 * opening it.  If so, then we'll need to ensure that it has
		 * the proper ownership after having opened it.
		 */
		if (oflags & O_CREAT) {
			if (stat(filename, &statbuf) == -1) {
				if (errno == ENOENT)
					newfile = B_TRUE;
				else
					return (errno);
			}
		}
		if ((fd = open(filename, oflags, mode)) == -1)
			return (errno);
		if (newfile) {
			if (chown(filename, UID_DLADM, GID_NETADM) == -1) {
				err = errno;
				(void) close(fd);
				return (err);
			}
		}
	}

	/*
	 * If we're not in the global zone, send the file-descriptor back to
	 * our parent in the global zone.
	 */
	if (!inglobalzone) {
		assert(!finglobalzone);
		assert(fd != -1);
		return (ioctl(p[1], I_SENDFD, fd) == -1 ? errno : 0);
	}

	/*
	 * At this point, we know we're in the global zone.  If the file was
	 * in a non-global zone, receive the file-descriptor from our child in
	 * the non-global zone.
	 */
	if (!finglobalzone) {
		if (ioctl(p[0], I_RECVFD, &recvfd) == -1)
			return (errno);
		fd = recvfd.fd;
	}

	zfarg->zfarg_openarg.zopen_fd = fd;
	return (0);
}

static int
dlmgmt_zunlink_cb(zfarg_t *zfarg)
{
	if (zfarg->zfarg_inglobalzone != zfarg->zfarg_finglobalzone)
		return (0);
	return (unlink(zfarg->zfarg_filename) == 0 ? 0 : errno);
}

static int
dlmgmt_zrename_cb(zfarg_t *zfarg)
{
	if (zfarg->zfarg_inglobalzone != zfarg->zfarg_finglobalzone)
		return (0);
	return (rename(zfarg->zfarg_filename,
	    zfarg->zfarg_renamearg.zrename_newname) == 0 ? 0 : errno);
}

/*
 * Same as fopen(3C), except that it opens the file relative to zoneid's zone
 * root.
 */
static FILE *
dlmgmt_zfopen(const char *filename, const char *modestr, zoneid_t zoneid,
    int *err)
{
	int		p[2];
	zfoparg_t	zfoparg;
	FILE		*fp = NULL;

	if (zoneid != GLOBAL_ZONEID && pipe(p) == -1) {
		*err = errno;
		return (NULL);
	}

	zfoparg.zfop_openarg.zopen_modestr = modestr;
	zfoparg.zfop_openarg.zopen_pipe = p;
	*err = dlmgmt_zfop(filename, zoneid, dlmgmt_zopen_cb, &zfoparg);
	if (zoneid != GLOBAL_ZONEID) {
		(void) close(p[0]);
		(void) close(p[1]);
	}
	if (*err == 0) {
		fp = fdopen(zfoparg.zfop_openarg.zopen_fd, modestr);
		if (fp == NULL) {
			*err = errno;
			(void) close(zfoparg.zfop_openarg.zopen_fd);
		}
	}
	return (fp);
}

/*
 * Same as rename(2), except that old and new are relative to zoneid's zone
 * root.
 */
static int
dlmgmt_zrename(const char *old, const char *new, zoneid_t zoneid)
{
	zfoparg_t zfoparg;

	zfoparg.zfop_renamearg.zrename_newname = new;
	return (dlmgmt_zfop(old, zoneid, dlmgmt_zrename_cb, &zfoparg));
}

/*
 * Same as unlink(2), except that filename is relative to zoneid's zone root.
 */
static int
dlmgmt_zunlink(const char *filename, zoneid_t zoneid)
{
	return (dlmgmt_zfop(filename, zoneid, dlmgmt_zunlink_cb, NULL));
}

static size_t
write_str(char *buffer, size_t buffer_length, char *name, void *value)
{
	char	*ptr = value;
	size_t	data_length = strnlen(ptr, buffer_length);

	/*
	 * Strings are assumed to be NULL terminated.  In order to fit in
	 * the buffer, the string's length must be less then buffer_length.
	 * If the value is empty, there's no point in writing it, in fact,
	 * we shouldn't even see that case.
	 */
	if (data_length + BASE_PROPERTY_LENGTH(DLADM_TYPE_STR, name) ==
	    buffer_length || data_length == 0)
		return (0);

	/*
	 * Since we know the string will fit in the buffer, snprintf will
	 * always return less than buffer_length, so we can just return
	 * whatever snprintf returns.
	 */
	return (GENERATE_PROPERTY_STRING(buffer, buffer_length, "%s",
	    name, DLADM_TYPE_STR, ptr));
}

static size_t
write_boolean(char *buffer, size_t buffer_length, char *name, void *value)
{
	boolean_t	*ptr = value;

	/*
	 * Booleans are either zero or one, so we only need room for two
	 * characters in the buffer.
	 */
	if (buffer_length <= 1 + BASE_PROPERTY_LENGTH(DLADM_TYPE_BOOLEAN, name))
		return (0);

	return (GENERATE_PROPERTY_STRING(buffer, buffer_length, "%d",
	    name, DLADM_TYPE_BOOLEAN, *ptr));
}

static size_t
write_uint64(char *buffer, size_t buffer_length, char *name, void *value)
{
	uint64_t	*ptr = value;

	/*
	 * Limit checking for uint64_t is a little trickier.
	 */
	if (snprintf(NULL, 0, "%lld", *ptr)  +
	    BASE_PROPERTY_LENGTH(DLADM_TYPE_UINT64, name) >= buffer_length)
		return (0);

	return (GENERATE_PROPERTY_STRING(buffer, buffer_length, "%lld",
	    name, DLADM_TYPE_UINT64, *ptr));
}

static size_t
read_str(char *buffer, void **value)
{
	char		*ptr = calloc(MAXLINKATTRVALLEN, sizeof (char));
	ssize_t		len;

	if (ptr == NULL || (len = strlcpy(ptr, buffer, MAXLINKATTRVALLEN))
	    >= MAXLINKATTRVALLEN) {
		free(ptr);
		return (0);
	}

	*(char **)value = ptr;

	/* Account for NULL terminator */
	return (len + 1);
}

static size_t
read_boolean(char *buffer, void **value)
{
	boolean_t	*ptr = calloc(1, sizeof (boolean_t));

	if (ptr == NULL)
		return (0);

	*ptr = atoi(buffer);
	*(boolean_t **)value = ptr;

	return (sizeof (boolean_t));
}

static size_t
read_int64(char *buffer, void **value)
{
	int64_t	*ptr = calloc(1, sizeof (int64_t));

	if (ptr == NULL)
		return (0);

	*ptr = (int64_t)atoll(buffer);
	*(int64_t **)value = ptr;

	return (sizeof (int64_t));
}

static dlmgmt_db_req_t *
dlmgmt_db_req_alloc(dlmgmt_db_op_t op, const char *linkname,
    datalink_id_t linkid, zoneid_t zoneid, uint32_t flags, int *err)
{
	dlmgmt_db_req_t *req;

	if ((req = calloc(1, sizeof (dlmgmt_db_req_t))) == NULL) {
		*err = errno;
	} else {
		req->ls_op = op;
		if (linkname != NULL)
			(void) strlcpy(req->ls_link, linkname, MAXLINKNAMELEN);
		req->ls_linkid = linkid;
		req->ls_zoneid = zoneid;
		req->ls_flags = flags;
	}
	return (req);
}

/*
 * Update the db entry with name "entryname" using information from "linkp".
 */
static int
dlmgmt_db_update(dlmgmt_db_op_t op, const char *entryname, dlmgmt_link_t *linkp,
    uint32_t flags)
{
	dlmgmt_db_req_t	*req;
	int		err;

	/* It is either a persistent request or an active request, not both. */
	assert((flags == DLMGMT_PERSIST) || (flags == DLMGMT_ACTIVE));

	if ((req = dlmgmt_db_req_alloc(op, entryname, linkp->ll_linkid,
	    linkp->ll_zoneid, flags, &err)) == NULL)
		return (err);

	/* If transient op and onloan, use the global zone cache file. */
	if (flags == DLMGMT_ACTIVE && linkp->ll_onloan)
		req->ls_zoneid = GLOBAL_ZONEID;

	/*
	 * If the return error is EINPROGRESS, this request is handled
	 * asynchronously; return success.
	 */
	err = dlmgmt_process_db_req(req);
	if (err != EINPROGRESS)
		free(req);
	else
		err = 0;
	return (err);
}

#define	DLMGMT_DB_OP_STR(op)					\
	(((op) == DLMGMT_DB_OP_READ) ? "read" :			\
	(((op) == DLMGMT_DB_OP_WRITE) ? "write" : "delete"))

#define	DLMGMT_DB_CONF_STR(flag)				\
	(((flag) == DLMGMT_ACTIVE) ? "active" :			\
	(((flag) == DLMGMT_PERSIST) ? "persistent" : ""))

static int
dlmgmt_process_db_req(dlmgmt_db_req_t *req)
{
	pthread_t	tid;
	boolean_t	writeop;
	int		err;

	/*
	 * If there are already pending "write" requests, queue this request in
	 * the pending list.  Note that this function is called while the
	 * dlmgmt_rw_lock is held, so it is safe to access the global variables.
	 */
	writeop = (req->ls_op != DLMGMT_DB_OP_READ);
	if (writeop && (req->ls_flags == DLMGMT_PERSIST) &&
	    (dlmgmt_db_req_head != NULL)) {
		dlmgmt_db_req_tail->ls_next = req;
		dlmgmt_db_req_tail = req;
		return (EINPROGRESS);
	}

	err = dlmgmt_process_db_onereq(req, writeop);
	if (err != EINPROGRESS && err != 0 && err != ENOENT) {
		/*
		 * Log the error unless the request processing is still in
		 * progress or if the configuration file hasn't been created
		 * yet (ENOENT).
		 */
		dlmgmt_log(LOG_WARNING, "dlmgmt_process_db_onereq() %s "
		    "operation on %s configuration failed: %s",
		    DLMGMT_DB_OP_STR(req->ls_op),
		    DLMGMT_DB_CONF_STR(req->ls_flags), strerror(err));
	}

	if (err == EINPROGRESS) {
		assert(req->ls_flags == DLMGMT_PERSIST);
		assert(writeop && dlmgmt_db_req_head == NULL);
		dlmgmt_db_req_tail = dlmgmt_db_req_head = req;
		err = pthread_create(&tid, NULL, dlmgmt_db_update_thread, NULL);
		if (err == 0)
			return (EINPROGRESS);
	}
	return (err);
}

static int
dlmgmt_process_db_onereq(dlmgmt_db_req_t *req, boolean_t writeop)
{
	int	err = 0;
	FILE	*fp, *nfp = NULL;
	char	file[MAXPATHLEN];
	char	newfile[MAXPATHLEN];

	DLMGMT_MAKE_FILE_DB_PATH(file, (req->ls_flags == DLMGMT_PERSIST));
	fp = dlmgmt_zfopen(file, "r", req->ls_zoneid, &err);
	/*
	 * Note that it is not an error if the file doesn't exist.  If we're
	 * reading, we treat this case the same way as an empty file.  If
	 * we're writing, the file will be created when we open the file for
	 * writing below.
	 */
	if (fp == NULL && !writeop)
		return (err);

	if (writeop) {
		(void) snprintf(newfile, MAXPATHLEN, "%s.new", file);
		nfp = dlmgmt_zfopen(newfile, "w", req->ls_zoneid, &err);
		if (nfp == NULL) {
			/*
			 * EROFS can happen at boot when the file system is
			 * read-only.  Return EINPROGRESS so that the caller
			 * can add this request to the pending request list
			 * and start a retry thread.
			 */
			err = (errno == EROFS ? EINPROGRESS : errno);
			goto done;
		}
	}
	if (writeop) {
		if ((err = process_db_write(req, fp, nfp)) == 0)
			err = dlmgmt_zrename(newfile, file, req->ls_zoneid);
	} else {
		err = process_db_read(req, fp);
	}

done:
	if (nfp != NULL) {
		(void) fclose(nfp);
		if (err != 0)
			(void) dlmgmt_zunlink(newfile, req->ls_zoneid);
	}
	(void) fclose(fp);
	return (err);
}

/*ARGSUSED*/
static void *
dlmgmt_db_update_thread(void *arg)
{
	dlmgmt_db_req_t	*req;

	dlmgmt_table_lock(B_TRUE);

	assert(dlmgmt_db_req_head != NULL);
	while ((req = dlmgmt_db_req_head) != NULL) {
		assert(req->ls_flags == DLMGMT_PERSIST);
		if (dlmgmt_process_db_onereq(req, B_TRUE) == EINPROGRESS) {
			/*
			 * The filesystem is still read only. Go to sleep and
			 * try again.
			 */
			dlmgmt_table_unlock();
			(void) sleep(5);
			dlmgmt_table_lock(B_TRUE);
			continue;
		}

		/*
		 * The filesystem is no longer read only. Continue processing
		 * and remove the request from the pending list.
		 */
		dlmgmt_db_req_head = req->ls_next;
		if (dlmgmt_db_req_tail == req) {
			assert(dlmgmt_db_req_head == NULL);
			dlmgmt_db_req_tail = NULL;
		}
		free(req);
	}

	dlmgmt_table_unlock();
	return (NULL);
}

static int
parse_linkprops(char *buf, dlmgmt_link_t *linkp)
{
	boolean_t		found_type = B_FALSE;
	dladm_datatype_t	type = DLADM_TYPE_STR;
	int			i, len;
	char			*curr;
	char			attr_name[MAXLINKATTRLEN];
	size_t			attr_buf_len = 0;
	void			*attr_buf = NULL;
	boolean_t		rename;

	curr = buf;
	len = strlen(buf);
	attr_name[0] = '\0';
	for (i = 0; i < len; i++) {
		rename = B_FALSE;
		char		c = buf[i];
		boolean_t	match = (c == '=' ||
		    (c == ',' && !found_type) || c == ';');

		/*
		 * Move to the next character if there is no match and
		 * if we have not reached the last character.
		 */
		if (!match && i != len - 1)
			continue;

		if (match) {
			/*
			 * NUL-terminate the string pointed to by 'curr'.
			 */
			buf[i] = '\0';
			if (*curr == '\0')
				goto parse_fail;
		}

		if (attr_name[0] != '\0' && found_type) {
			/*
			 * We get here after we have processed the "<prop>="
			 * pattern. The pattern we are now interested in is
			 * "<val>;".
			 */
			if (c == '=')
				goto parse_fail;

			if (strcmp(attr_name, "linkid") == 0) {
				if (read_int64(curr, &attr_buf) == 0)
					goto parse_fail;
				linkp->ll_linkid =
				    (datalink_class_t)*(int64_t *)attr_buf;
			} else if (strcmp(attr_name, "name") == 0) {
				if (read_str(curr, &attr_buf) == 0)
					goto parse_fail;
				(void) snprintf(linkp->ll_link,
				    MAXLINKNAMELEN, "%s", attr_buf);
			} else if (strcmp(attr_name, "class") == 0) {
				if (read_int64(curr, &attr_buf) == 0)
					goto parse_fail;
				linkp->ll_class =
				    (datalink_class_t)*(int64_t *)attr_buf;
			} else if (strcmp(attr_name, "media") == 0) {
				if (read_int64(curr, &attr_buf) == 0)
					goto parse_fail;
				linkp->ll_media =
				    (uint32_t)*(int64_t *)attr_buf;
			} else if (strcmp(attr_name, "zone") == 0) {
				if (read_str(curr, &attr_buf) == 0)
					goto parse_fail;
				linkp->ll_zoneid = getzoneidbyname(attr_buf);
				if (linkp->ll_zoneid == -1) {
					if (errno == EFAULT)
						abort();
					/*
					 * If we can't find the zone, assign the
					 * link to the GZ and mark it for being
					 * renamed.
					 */
					linkp->ll_zoneid = 0;
					rename = B_TRUE;
				}
			} else {
				attr_buf_len = translators[type].read_func(curr,
				    &attr_buf);
				if (attr_buf_len == 0)
					goto parse_fail;

				if (linkattr_set(&(linkp->ll_head), attr_name,
				    attr_buf, attr_buf_len, type) != 0) {
					free(attr_buf);
					goto parse_fail;
				}
			}

			free(attr_buf);
			attr_name[0] = '\0';
			found_type = B_FALSE;
		} else if (attr_name[0] != '\0') {
			/*
			 * Non-zero length attr_name and found_type of false
			 * indicates that we have not found the type for this
			 * attribute.  The pattern now is "<type>,<val>;", we
			 * want the <type> part of the pattern.
			 */
			for (type = 0; type < ntranslators; type++) {
				if (strcmp(curr,
				    translators[type].type_name) == 0) {
					found_type = B_TRUE;
					break;
				}
			}

			if (!found_type)
				goto parse_fail;
		} else {
			/*
			 * A zero length attr_name indicates we are looking
			 * at the beginning of a link attribute.
			 */
			if (c != '=')
				goto parse_fail;

			(void) snprintf(attr_name, MAXLINKATTRLEN, "%s", curr);
		}

		/*
		 * The zone that this link belongs to has died, we are
		 * reparenting it to the GZ and renaming it to avoid name
		 * collisions.
		 */
		if (rename == B_TRUE) {
			(void) snprintf(linkp->ll_link, MAXLINKNAMELEN,
			    "SUNWorphan%u", (uint16_t)(gethrtime() / 1000));
		}
		curr = buf + i + 1;
	}

	/* Correct any erroneous IPTUN datalink class constant in the file */
	if (linkp->ll_class == 0x60) {
		linkp->ll_class = DATALINK_CLASS_IPTUN;
		rewrite_needed = B_TRUE;
	}

	return (0);

parse_fail:
	/*
	 * Free linkp->ll_head (link attribute list)
	 */
	linkattr_destroy(linkp);
	return (-1);
}

static boolean_t
process_link_line(char *buf, dlmgmt_link_t *linkp)
{
	int	i, len, llen;
	char	*str, *lasts;
	char	tmpbuf[MAXLINELEN];

	bzero(linkp, sizeof (*linkp));
	linkp->ll_linkid = DATALINK_INVALID_LINKID;

	/*
	 * Use a copy of buf for parsing so that we can do whatever we want.
	 */
	(void) strlcpy(tmpbuf, buf, MAXLINELEN);

	/*
	 * Skip leading spaces, blank lines, and comments.
	 */
	len = strlen(tmpbuf);
	for (i = 0; i < len; i++) {
		if (!isspace(tmpbuf[i]))
			break;
	}
	if (i == len || tmpbuf[i] == '#')
		return (B_TRUE);

	str = tmpbuf + i;
	/*
	 * Find the link name and assign it to the link structure.
	 */
	if (strtok_r(str, " \n\t", &lasts) == NULL)
		goto fail;

	llen = strlen(str);
	/*
	 * Note that a previous version of the persistent datalink.conf file
	 * stored the linkid as the first field.  In that case, the name will
	 * be obtained through parse_linkprops from a property with the format
	 * "name=<linkname>".  If we encounter such a format, we set
	 * rewrite_needed so that dlmgmt_db_init() can rewrite the file with
	 * the new format after it's done reading in the data.
	 */
	if (isdigit(str[0])) {
		linkp->ll_linkid = atoi(str);
		rewrite_needed = B_TRUE;
	} else {
		if (strlcpy(linkp->ll_link, str, sizeof (linkp->ll_link)) >=
		    sizeof (linkp->ll_link))
			goto fail;
	}

	str += llen + 1;
	if (str >= tmpbuf + len)
		goto fail;

	/*
	 * Now find the list of link properties.
	 */
	if ((str = strtok_r(str, " \n\t", &lasts)) == NULL)
		goto fail;

	if (parse_linkprops(str, linkp) < 0)
		goto fail;

	return (B_TRUE);

fail:
	/*
	 * Delete corrupted line.
	 */
	buf[0] = '\0';
	return (B_FALSE);
}

/*
 * Find any properties in linkp that refer to "old", and rename to "new".
 * Return B_TRUE if any renaming occurred.
 */
static int
dlmgmt_attr_rename(dlmgmt_link_t *linkp, const char *old, const char *new,
    boolean_t *renamed)
{
	dlmgmt_linkattr_t	*attrp;
	char			*newval = NULL, *pname;
	char			valcp[MAXLINKATTRVALLEN];
	size_t			newsize;

	*renamed = B_FALSE;

	if ((attrp = linkattr_find(linkp->ll_head, "linkover")) != NULL ||
	    (attrp = linkattr_find(linkp->ll_head, "simnetpeer")) != NULL) {
		if (strcmp(old, (char *)attrp->lp_val) == 0) {
			newsize = strlen(new) + 1;
			if ((newval = malloc(newsize)) == NULL)
				return (errno);
			(void) strcpy(newval, new);
			free(attrp->lp_val);
			attrp->lp_val = newval;
			attrp->lp_sz = newsize;
			*renamed = B_TRUE;
		}
		return (0);
	}

	if ((attrp = linkattr_find(linkp->ll_head, "portnames")) == NULL)
		return (0);

	/* <linkname>:[<linkname>:]... */
	if ((newval = calloc(MAXLINKATTRVALLEN, sizeof (char))) == NULL)
		return (errno);

	bcopy(attrp->lp_val, valcp, sizeof (valcp));
	pname = strtok(valcp, ":");
	while (pname != NULL) {
		if (strcmp(pname, old) == 0) {
			(void) strcat(newval, new);
			*renamed = B_TRUE;
		} else {
			(void) strcat(newval, pname);
		}
		(void) strcat(newval, ":");
		pname = strtok(NULL, ":");
	}
	if (*renamed) {
		free(attrp->lp_val);
		attrp->lp_val = newval;
		attrp->lp_sz = strlen(newval) + 1;
	} else {
		free(newval);
	}
	return (0);
}

static int
process_db_write(dlmgmt_db_req_t *req, FILE *fp, FILE *nfp)
{
	boolean_t		done = B_FALSE;
	int			err = 0;
	dlmgmt_link_t		link_in_file, *linkp = NULL, *dblinkp;
	boolean_t		persist = (req->ls_flags == DLMGMT_PERSIST);
	boolean_t		writeall, rename, attr_renamed;
	char			buf[MAXLINELEN];

	writeall = (req->ls_linkid == DATALINK_ALL_LINKID);

	if (req->ls_op == DLMGMT_DB_OP_WRITE && !writeall) {
		/*
		 * find the link in the avl tree with the given linkid.
		 */
		linkp = link_by_id(req->ls_linkid, req->ls_zoneid);
		if (linkp == NULL || (linkp->ll_flags & req->ls_flags) == 0) {
			/*
			 * This link has already been changed. This could
			 * happen if the request is pending because of
			 * read-only file-system. If so, we are done.
			 */
			return (0);
		}
		/*
		 * In the case of a rename, linkp's name has been updated to
		 * the new name, and req->ls_link is the old link name.
		 */
		rename = (strcmp(req->ls_link, linkp->ll_link) != 0);
	}

	/*
	 * fp can be NULL if the file didn't initially exist and we're
	 * creating it as part of this write operation.
	 */
	if (fp == NULL)
		goto write;

	while (err == 0 && fgets(buf, sizeof (buf), fp) != NULL &&
	    process_link_line(buf, &link_in_file)) {
		/*
		 * Only the link name is needed. Free the memory allocated for
		 * the link attributes list of link_in_file.
		 */
		linkattr_destroy(&link_in_file);

		if (link_in_file.ll_link[0] == '\0' || done) {
			/*
			 * this is a comment line or we are done updating the
			 * line for the specified link, write the rest of
			 * lines out.
			 */
			if (fputs(buf, nfp) == EOF)
				err = errno;
			continue;
		}

		switch (req->ls_op) {
		case DLMGMT_DB_OP_WRITE:
			/*
			 * For write operations, we generate a new output line
			 * if we're either writing all links (writeall) or if
			 * the name of the link in the file matches the one
			 * we're looking for.  Otherwise, we write out the
			 * buffer as-is.
			 *
			 * If we're doing a rename operation, ensure that any
			 * references to the link being renamed in link
			 * properties are also updated before we write
			 * anything.
			 */
			if (writeall) {
				linkp = link_by_name(link_in_file.ll_link,
				    req->ls_zoneid);
			}
			if (writeall || strcmp(req->ls_link,
			    link_in_file.ll_link) == 0) {
				generate_link_line(linkp, persist, buf);
				if (!writeall && !rename)
					done = B_TRUE;
			} else if (rename && persist) {
				dblinkp = link_by_name(link_in_file.ll_link,
				    req->ls_zoneid);
				err = dlmgmt_attr_rename(dblinkp, req->ls_link,
				    linkp->ll_link, &attr_renamed);
				if (err != 0)
					break;
				if (attr_renamed) {
					generate_link_line(dblinkp, persist,
					    buf);
				}
			}
			if (fputs(buf, nfp) == EOF)
				err = errno;
			break;
		case DLMGMT_DB_OP_DELETE:
			/*
			 * Delete is simple.  If buf does not represent the
			 * link we're deleting, write it out.
			 */
			if (strcmp(req->ls_link, link_in_file.ll_link) != 0) {
				if (fputs(buf, nfp) == EOF)
					err = errno;
			} else {
				done = B_TRUE;
			}
			break;
		case DLMGMT_DB_OP_READ:
		default:
			err = EINVAL;
			break;
		}
	}

write:
	/*
	 * If we get to the end of the file and have not seen what linkid
	 * points to, write it out then.
	 */
	if (req->ls_op == DLMGMT_DB_OP_WRITE && !writeall && !rename && !done) {
		generate_link_line(linkp, persist, buf);
		done = B_TRUE;
		if (fputs(buf, nfp) == EOF)
			err = errno;
	}

	return (err);
}

static int
process_db_read(dlmgmt_db_req_t *req, FILE *fp)
{
	avl_index_t	name_where, id_where;
	dlmgmt_link_t	link_in_file, *newlink, *link_in_db;
	char		buf[MAXLINELEN];
	int		err = 0;

	/*
	 * This loop processes each line of the configuration file.
	 */
	while (fgets(buf, MAXLINELEN, fp) != NULL) {
		if (!process_link_line(buf, &link_in_file)) {
			err = EINVAL;
			break;
		}

		/*
		 * Skip the comment line.
		 */
		if (link_in_file.ll_link[0] == '\0') {
			linkattr_destroy(&link_in_file);
			continue;
		}

		if ((req->ls_flags & DLMGMT_ACTIVE) &&
		    link_in_file.ll_linkid == DATALINK_INVALID_LINKID) {
			linkattr_destroy(&link_in_file);
			continue;
		}

		link_in_file.ll_zoneid = req->ls_zoneid;
		link_in_db = link_by_name(link_in_file.ll_link,
		    link_in_file.ll_zoneid);
		if (link_in_db != NULL) {
			/*
			 * If the link in the database already has the flag
			 * for this request set, then the entry is a
			 * duplicate.  If it's not a duplicate, then simply
			 * turn on the appropriate flag on the existing link.
			 */
			if (link_in_db->ll_flags & req->ls_flags) {
				dlmgmt_log(LOG_WARNING, "Duplicate links "
				    "in the repository: %s",
				    link_in_file.ll_link);
				linkattr_destroy(&link_in_file);
			} else {
				if (req->ls_flags & DLMGMT_PERSIST) {
					/*
					 * Save the newly read properties into
					 * the existing link.
					 */
					assert(link_in_db->ll_head == NULL);
					link_in_db->ll_head =
					    link_in_file.ll_head;
				} else {
					linkattr_destroy(&link_in_file);
				}
				link_in_db->ll_flags |= req->ls_flags;
			}
		} else {
			/*
			 * This is a new link.  Allocate a new dlmgmt_link_t
			 * and add it to the trees.
			 */
			newlink = calloc(1, sizeof (*newlink));
			if (newlink == NULL) {
				dlmgmt_log(LOG_WARNING, "Unable to allocate "
				    "memory to create new link %s",
				    link_in_file.ll_link);
				linkattr_destroy(&link_in_file);
				continue;
			}
			bcopy(&link_in_file, newlink, sizeof (*newlink));

			if (newlink->ll_linkid == DATALINK_INVALID_LINKID)
				newlink->ll_linkid = dlmgmt_nextlinkid;
			if (avl_find(&dlmgmt_id_avl, newlink, &id_where) !=
			    NULL) {
				dlmgmt_log(LOG_WARNING, "Link ID %d is already"
				    " in use, destroying link %s",
				    newlink->ll_linkid, newlink->ll_link);
				link_destroy(newlink);
				continue;
			}

			if ((req->ls_flags & DLMGMT_ACTIVE) &&
			    link_activate(newlink) != 0) {
				dlmgmt_log(LOG_WARNING, "Unable to activate %s",
				    newlink->ll_link);
				link_destroy(newlink);
				continue;
			}

			avl_insert(&dlmgmt_id_avl, newlink, id_where);
			/*
			 * link_activate call above can insert newlink in
			 * dlmgmt_name_avl tree when activating a link that is
			 * assigned to a NGZ.
			 */
			if (avl_find(&dlmgmt_name_avl, newlink,
			    &name_where) == NULL)
				avl_insert(&dlmgmt_name_avl, newlink,
				    name_where);

			dlmgmt_advance(newlink);
			newlink->ll_flags |= req->ls_flags;
		}
	}

	return (err);
}

/*
 * Generate an entry in the link database.
 * Each entry has this format:
 * <link name>	<prop0>=<type>,<val>;...;<propn>=<type>,<val>;
 */
static void
generate_link_line(dlmgmt_link_t *linkp, boolean_t persist, char *buf)
{
	char			tmpbuf[MAXLINELEN];
	char			*ptr = tmpbuf;
	char			*lim = tmpbuf + MAXLINELEN;
	dlmgmt_linkattr_t	*cur_p = NULL;
	uint64_t		u64;

	ptr += snprintf(ptr, BUFLEN(lim, ptr), "%s\t", linkp->ll_link);
	if (!persist) {
		char zname[ZONENAME_MAX];
		/*
		 * We store the linkid and the zone name in the active database
		 * so that dlmgmtd can recover in the event that it is
		 * restarted.
		 */
		u64 = linkp->ll_linkid;
		ptr += write_uint64(ptr, BUFLEN(lim, ptr), "linkid", &u64);

		if (getzonenamebyid(linkp->ll_zoneid, zname,
		    sizeof (zname)) != -1) {
			ptr += write_str(ptr, BUFLEN(lim, ptr), "zone", zname);
		}
	}
	u64 = linkp->ll_class;
	ptr += write_uint64(ptr, BUFLEN(lim, ptr), "class", &u64);
	u64 = linkp->ll_media;
	ptr += write_uint64(ptr, BUFLEN(lim, ptr), "media", &u64);

	/*
	 * The daemon does not keep any active link attribute. Only store the
	 * attributes if this request is for persistent configuration,
	 */
	if (persist) {
		for (cur_p = linkp->ll_head; cur_p != NULL;
		    cur_p = cur_p->lp_next) {
			ptr += translators[cur_p->lp_type].write_func(ptr,
			    BUFLEN(lim, ptr), cur_p->lp_name, cur_p->lp_val);
		}
	}

	if (ptr <= lim)
		(void) snprintf(buf, MAXLINELEN, "%s\n", tmpbuf);
}

int
dlmgmt_delete_db_entry(dlmgmt_link_t *linkp, uint32_t flags)
{
	return (dlmgmt_db_update(DLMGMT_DB_OP_DELETE, linkp->ll_link, linkp,
	    flags));
}

int
dlmgmt_write_db_entry(const char *entryname, dlmgmt_link_t *linkp,
    uint32_t flags)
{
	int err;

	if (flags & DLMGMT_PERSIST) {
		if ((err = dlmgmt_db_update(DLMGMT_DB_OP_WRITE, entryname,
		    linkp, DLMGMT_PERSIST)) != 0) {
			return (err);
		}
	}

	if (flags & DLMGMT_ACTIVE) {
		if (((err = dlmgmt_db_update(DLMGMT_DB_OP_WRITE, entryname,
		    linkp, DLMGMT_ACTIVE)) != 0) && (flags & DLMGMT_PERSIST)) {
			(void) dlmgmt_db_update(DLMGMT_DB_OP_DELETE, entryname,
			    linkp, DLMGMT_PERSIST);
			return (err);
		}
	}

	return (0);
}

/*
 * Upgrade properties that have link IDs as values to link names.  Because '.'
 * is a valid linkname character, the port separater for link aggregations
 * must be changed to ':'.
 */
static void
linkattr_upgrade(dlmgmt_linkattr_t *attrp)
{
	datalink_id_t	linkid;
	char		*portidstr;
	char		portname[MAXLINKNAMELEN + 1];
	dlmgmt_link_t	*linkp;
	char		*new_attr_val;
	size_t		new_attr_sz;
	boolean_t	upgraded = B_FALSE;

	if (strcmp(attrp->lp_name, "linkover") == 0 ||
	    strcmp(attrp->lp_name, "simnetpeer") == 0) {
		if (attrp->lp_type == DLADM_TYPE_UINT64) {
			linkid = (datalink_id_t)*(uint64_t *)attrp->lp_val;
			if ((linkp = link_by_id(linkid, GLOBAL_ZONEID)) == NULL)
				return;
			new_attr_sz = strlen(linkp->ll_link) + 1;
			if ((new_attr_val = malloc(new_attr_sz)) == NULL)
				return;
			(void) strcpy(new_attr_val, linkp->ll_link);
			upgraded = B_TRUE;
		}
	} else if (strcmp(attrp->lp_name, "portnames") == 0) {
		/*
		 * The old format for "portnames" was
		 * "<linkid>.[<linkid>.]...".  The new format is
		 * "<linkname>:[<linkname>:]...".
		 */
		if (!isdigit(((char *)attrp->lp_val)[0]))
			return;
		new_attr_val = calloc(MAXLINKATTRVALLEN, sizeof (char));
		if (new_attr_val == NULL)
			return;
		portidstr = (char *)attrp->lp_val;
		while (*portidstr != '\0') {
			errno = 0;
			linkid = strtol(portidstr, &portidstr, 10);
			if (linkid == 0 || *portidstr != '.' ||
			    (linkp = link_by_id(linkid, GLOBAL_ZONEID)) ==
			    NULL) {
				free(new_attr_val);
				return;
			}
			(void) snprintf(portname, sizeof (portname), "%s:",
			    linkp->ll_link);
			if (strlcat(new_attr_val, portname,
			    MAXLINKATTRVALLEN) >= MAXLINKATTRVALLEN) {
				free(new_attr_val);
				return;
			}
			/* skip the '.' delimiter */
			portidstr++;
		}
		new_attr_sz = strlen(new_attr_val) + 1;
		upgraded = B_TRUE;
	}

	if (upgraded) {
		attrp->lp_type = DLADM_TYPE_STR;
		attrp->lp_sz = new_attr_sz;
		free(attrp->lp_val);
		attrp->lp_val = new_attr_val;
	}
}

static void
dlmgmt_db_upgrade(dlmgmt_link_t *linkp)
{
	dlmgmt_linkattr_t *attrp;

	for (attrp = linkp->ll_head; attrp != NULL; attrp = attrp->lp_next)
		linkattr_upgrade(attrp);
}

static void
dlmgmt_db_phys_activate(dlmgmt_link_t *linkp)
{
	linkp->ll_flags |= DLMGMT_ACTIVE;
	(void) dlmgmt_write_db_entry(linkp->ll_link, linkp, DLMGMT_ACTIVE);
}

static void
dlmgmt_db_walk(zoneid_t zoneid, datalink_class_t class, db_walk_func_t *func)
{
	dlmgmt_link_t *linkp;

	for (linkp = avl_first(&dlmgmt_id_avl); linkp != NULL;
	    linkp = AVL_NEXT(&dlmgmt_id_avl, linkp)) {
		if (linkp->ll_zoneid == zoneid && (linkp->ll_class & class))
			func(linkp);
	}
}

/*
 * Attempt to mitigate one of the deadlocks in the dlmgmtd architecture.
 *
 * dlmgmt_db_init() calls dlmgmt_process_db_req() which eventually gets to
 * dlmgmt_zfop() which tries to fork, enter the zone and read the file.
 * Because of the upcall architecture of dlmgmtd this can lead to deadlock
 * with the following scenario:
 *    a) the thread preparing to fork will have acquired the malloc locks
 *       then attempt to suspend every thread in preparation to fork.
 *    b) all of the upcalls will be blocked in door_ucred() trying to malloc()
 *       and get the credentials of their caller.
 *    c) we can't suspend the in-kernel thread making the upcall.
 *
 * Thus, we cannot serve door requests because we're blocked in malloc()
 * which fork() owns, but fork() is in turn blocked on the in-kernel thread
 * making the door upcall.  This is a fundamental architectural problem with
 * any server handling upcalls and also trying to fork().
 *
 * To minimize the chance of this deadlock occuring, we check ahead of time to
 * see if the file we want to read actually exists in the zone (which it almost
 * never does), so we don't need fork in that case (i.e. rarely to never).
 */
static boolean_t
zone_file_exists(char *zoneroot, char *filename)
{
	struct stat	sb;
	char		fname[MAXPATHLEN];

	(void) snprintf(fname, sizeof (fname), "%s/%s", zoneroot, filename);

	if (stat(fname, &sb) == -1)
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Initialize the datalink <link name, linkid> mapping and the link's
 * attributes list based on the configuration file /etc/dladm/datalink.conf
 * and the active configuration cache file
 * /etc/svc/volatile/dladm/datalink-management:default.cache.
 */
int
dlmgmt_db_init(zoneid_t zoneid, char *zoneroot)
{
	dlmgmt_db_req_t	*req;
	int		err;
	boolean_t	boot = B_FALSE;

	if ((req = dlmgmt_db_req_alloc(DLMGMT_DB_OP_READ, NULL,
	    DATALINK_INVALID_LINKID, zoneid, DLMGMT_ACTIVE, &err)) == NULL)
		return (err);

	/* Handle running in a non-native branded zone (i.e. has /native) */
	if (zone_file_exists(zoneroot, "/native" DLMGMT_TMPFS_DIR)) {
		char tdir[MAXPATHLEN];

		(void) snprintf(tdir, sizeof (tdir), "/native%s", cachefile);
		(void) strlcpy(cachefile, tdir, sizeof (cachefile));
	}

	if (zone_file_exists(zoneroot, cachefile)) {
		if ((err = dlmgmt_process_db_req(req)) != 0) {
			/*
			 * If we get back ENOENT, that means that the active
			 * configuration file doesn't exist yet, and is not an
			 * error.  We'll create it down below after we've
			 * loaded the persistent configuration.
			 */
			if (err != ENOENT)
				goto done;
			boot = B_TRUE;
		}
	} else {
		boot = B_TRUE;
	}

	if (zone_file_exists(zoneroot, DLMGMT_PERSISTENT_DB_PATH)) {
		req->ls_flags = DLMGMT_PERSIST;
		err = dlmgmt_process_db_req(req);
		if (err != 0 && err != ENOENT)
			goto done;
	}
	err = 0;
	if (rewrite_needed) {
		/*
		 * First update links in memory, then dump the entire db to
		 * disk.
		 */
		dlmgmt_db_walk(zoneid, DATALINK_CLASS_ALL, dlmgmt_db_upgrade);
		req->ls_op = DLMGMT_DB_OP_WRITE;
		req->ls_linkid = DATALINK_ALL_LINKID;
		if ((err = dlmgmt_process_db_req(req)) != 0 &&
		    err != EINPROGRESS)
			goto done;
	}
	if (boot) {
		dlmgmt_db_walk(zoneid, DATALINK_CLASS_PHYS,
		    dlmgmt_db_phys_activate);
	}

done:
	if (err == EINPROGRESS)
		err = 0;
	else
		free(req);
	return (err);
}

/*
 * Remove all links in the given zoneid.
 *
 * We do this work in two different passes. In the first pass, we remove any
 * entry that hasn't been loaned and mark every entry that has been loaned as
 * something that is going to be tombstomed. In the second pass, we drop the
 * table lock for every entry and remove the tombstombed entry for our zone.
 */
void
dlmgmt_db_fini(zoneid_t zoneid)
{
	dlmgmt_link_t *linkp = avl_first(&dlmgmt_name_avl), *next_linkp;

	while (linkp != NULL) {
		next_linkp = AVL_NEXT(&dlmgmt_name_avl, linkp);
		if (linkp->ll_zoneid == zoneid) {
			boolean_t onloan = linkp->ll_onloan;

			/*
			 * Cleanup any VNICs that were loaned to the zone
			 * before the zone goes away and we can no longer
			 * refer to the VNIC by the name/zoneid.
			 */
			if (onloan) {
				(void) dlmgmt_delete_db_entry(linkp,
				    DLMGMT_ACTIVE);
				linkp->ll_tomb = B_TRUE;
			} else {
				(void) dlmgmt_destroy_common(linkp,
				    DLMGMT_ACTIVE | DLMGMT_PERSIST);
			}

		}
		linkp = next_linkp;
	}

again:
	linkp = avl_first(&dlmgmt_name_avl);
	while (linkp != NULL) {
		vnic_ioc_delete_t ioc;

		next_linkp = AVL_NEXT(&dlmgmt_name_avl, linkp);

		if (linkp->ll_zoneid != zoneid) {
			linkp = next_linkp;
			continue;
		}
		ioc.vd_vnic_id = linkp->ll_linkid;
		if (linkp->ll_tomb != B_TRUE)
			abort();

		/*
		 * We have to drop the table lock while going up into the
		 * kernel. If we hold the table lock while deleting a vnic, we
		 * may get blocked on the mac perimeter and the holder of it may
		 * want something from dlmgmtd.
		 */
		dlmgmt_table_unlock();

		if (ioctl(dladm_dld_fd(dld_handle),
		    VNIC_IOC_DELETE, &ioc) < 0)
			dlmgmt_log(LOG_WARNING, "dlmgmt_db_fini "
			    "delete VNIC ioctl failed %d %d",
			    ioc.vd_vnic_id, errno);

		/*
		 * Even though we've dropped the lock, we know that nothing else
		 * could have removed us. Therefore, it should be safe to go
		 * through and delete ourselves, but do nothing else. We'll have
		 * to restart iteration from the beginning. This can be painful.
		 */
		dlmgmt_table_lock(B_TRUE);

		(void) dlmgmt_destroy_common(linkp,
		    DLMGMT_ACTIVE | DLMGMT_PERSIST);
		goto again;
	}

}
