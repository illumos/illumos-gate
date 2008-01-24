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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <syslog.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>
#include "dlmgmt_impl.h"

typedef enum dlmgmt_db_op {
	DLMGMT_DB_OP_WRITE,
	DLMGMT_DB_OP_DELETE,
	DLMGMT_DB_OP_READ
} dlmgmt_db_op_t;

typedef struct dlmgmt_db_req_s {
	struct dlmgmt_db_req_s	*ls_next;
	dlmgmt_db_op_t		ls_op;
	datalink_id_t		ls_linkid;
	uint32_t		ls_flags;	/* Either DLMGMT_ACTIVE or   */
						/* DLMGMT_PERSIST, not both. */
} dlmgmt_db_req_t;

/*
 * List of pending db updates (e.g., because of a read-only filesystem).
 */
static dlmgmt_db_req_t	*dlmgmt_db_req_head = NULL;
static dlmgmt_db_req_t	*dlmgmt_db_req_tail = NULL;

static int		dlmgmt_db_update(dlmgmt_db_op_t, datalink_id_t,
			    uint32_t);
static int		dlmgmt_process_db_req(dlmgmt_db_req_t *);
static int		dlmgmt_process_db_onereq(dlmgmt_db_req_t *, boolean_t);
static void		*dlmgmt_db_update_thread(void *);
static boolean_t	process_link_line(char *, dlmgmt_link_t **);
static int		process_db_write(dlmgmt_db_req_t *, FILE *, FILE *);
static int		process_db_read(dlmgmt_db_req_t *, FILE *, FILE *);
static void		generate_link_line(dlmgmt_link_t *, boolean_t, char *);

#define	BUFLEN(lim, ptr)	(((lim) > (ptr)) ? ((lim) - (ptr)) : 0)
#define	MAXLINELEN		1024

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

#define	DLMGMT_DB_OWNER	15
#define	DLMGMT_DB_GROUP	3

/*
 * Name of the cache file to keep the active <link name, linkid> mapping
 */
static char	cachefile[MAXPATHLEN];

#define	DLMGMT_TEMP_DB_DIR		"/etc/svc/volatile"
#define	DLMGMT_PERSISTENT_DB_PATH	"/etc/dladm/datalink.conf"
#define	DLMGMT_MAKE_FILE_DB_PATH(buffer, persistent)	\
	(void) snprintf((buffer), MAXPATHLEN, "%s", \
	(persistent) ? DLMGMT_PERSISTENT_DB_PATH : cachefile);

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
	char		*ptr = calloc(MAXLINKATTRLEN, sizeof (char));
	ssize_t		len;

	if (ptr == NULL || (len = snprintf(ptr, MAXLINKATTRLEN, "%s", buffer))
	    >= MAXLINKATTRLEN) {
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

static int
dlmgmt_db_update(dlmgmt_db_op_t op, datalink_id_t linkid, uint32_t flags)
{
	dlmgmt_db_req_t	*req;
	int		err;

	/*
	 * It is either a persistent request or an active request, not both.
	 */
	assert((flags == DLMGMT_PERSIST) || (flags == DLMGMT_ACTIVE));

	if ((req = malloc(sizeof (dlmgmt_db_req_t))) == NULL)
		return (ENOMEM);

	req->ls_next = NULL;
	req->ls_op = op;
	req->ls_linkid = linkid;
	req->ls_flags = flags;

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
	if (err != EINPROGRESS && err != 0 &&
	    (req->ls_flags != DLMGMT_ACTIVE || errno != ENOENT)) {

		/*
		 * Log the error unless the request processing:
		 * - is successful;
		 * - is still in progress;
		 * - has failed with ENOENT because the active configuration
		 *   file is not created yet;
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
	int	nfd;

	DLMGMT_MAKE_FILE_DB_PATH(file, (req->ls_flags == DLMGMT_PERSIST));
	if ((fp = fopen(file, (writeop ? "r+" : "r"))) == NULL) {
		if (writeop && errno == EROFS) {
			/*
			 * This can happen at boot when the file system is
			 * read-only.  So add this request to the pending
			 * request list and start a retry thread.
			 */
			return (EINPROGRESS);
		} else if (req->ls_flags == DLMGMT_ACTIVE && errno == ENOENT) {
			/*
			 * It is fine if the file keeping active configuration
			 * does not exist. This happens during a new reboot.
			 */
			if (!writeop)
				return (ENOENT);
			/*
			 * If this is an update request for the active
			 * configuration, create the file.
			 */
			if ((fp = fopen(file, "w")) == NULL)
				return (errno == EROFS ? EINPROGRESS : errno);
		} else {
			return (errno);
		}
	}

	if (writeop) {
		(void) snprintf(newfile, MAXPATHLEN, "%s.new", file);
		if ((nfd = open(newfile, O_WRONLY | O_CREAT | O_TRUNC,
		    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) {
			(void) fclose(fp);
			return (errno);
		}

		if ((nfp = fdopen(nfd, "w")) == NULL) {
			(void) close(nfd);
			(void) fclose(fp);
			(void) unlink(newfile);
			return (errno);
		}
	}
	if (writeop)
		err = process_db_write(req, fp, nfp);
	else
		err = process_db_read(req, fp, nfp);
	if (!writeop || err != 0)
		goto done;

	/*
	 * Configuration files need to be owned by the 'dladm' user.
	 * If we are invoked by root, the file ownership needs to be fixed.
	 */
	if (getuid() == 0 || geteuid() == 0) {
		if (fchown(nfd, DLMGMT_DB_OWNER, DLMGMT_DB_GROUP) < 0) {
			err = errno;
			goto done;
		}
	}

	if (fflush(nfp) == EOF) {
		err = errno;
		goto done;
	}
	(void) fclose(fp);
	(void) fclose(nfp);

	if (rename(newfile, file) < 0) {
		(void) unlink(newfile);
		return (errno);
	}

	return (0);

done:
	if (nfp != NULL) {
		(void) fclose(nfp);
		if (err != 0)
			(void) unlink(newfile);
	}
	(void) fclose(fp);
	return (err);
}

/*ARGSUSED*/
static void *
dlmgmt_db_update_thread(void *arg)
{
	dlmgmt_db_req_t	*req;
	int		err = 0;

	dlmgmt_table_lock(B_TRUE);

	assert(dlmgmt_db_req_head != NULL);
	while ((req = dlmgmt_db_req_head) != NULL) {
		assert(req->ls_flags == DLMGMT_PERSIST);
		err = dlmgmt_process_db_onereq(req, B_TRUE);
		if (err == EINPROGRESS) {
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
	int			err = 0;
	char			*curr;
	char			attr_name[MAXLINKATTRLEN];
	size_t			attr_buf_len = 0;
	void			*attr_buf = NULL;

	curr = buf;
	len = strlen(buf);
	attr_name[0] = '\0';
	for (i = 0; i < len && err == 0; i++) {
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

			if (strcmp(attr_name, "name") == 0) {
				(void) read_str(curr, &attr_buf);
				(void) snprintf(linkp->ll_link,
				    MAXLINKNAMELEN, "%s", attr_buf);
			} else if (strcmp(attr_name, "class") == 0) {
				(void) read_int64(curr, &attr_buf);
				linkp->ll_class =
				    (datalink_class_t)*(int64_t *)attr_buf;
			} else if (strcmp(attr_name, "media") == 0) {
				(void) read_int64(curr, &attr_buf);
				linkp->ll_media =
				    (uint32_t)*(int64_t *)attr_buf;
			} else {
				attr_buf_len = translators[type].read_func(curr,
				    &attr_buf);
				err = linkattr_set(&(linkp->ll_head), attr_name,
				    attr_buf, attr_buf_len, type);
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
		curr = buf + i + 1;
	}

	return (err);

parse_fail:
	return (-1);
}

static boolean_t
process_link_line(char *buf, dlmgmt_link_t **linkpp)
{
	dlmgmt_link_t		*linkp;
	int			i, len, llen;
	char			*str, *lasts;
	char			tmpbuf[MAXLINELEN];

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
	if (i == len || tmpbuf[i] == '#') {
		*linkpp = NULL;
		return (B_TRUE);
	}

	linkp = calloc(1, sizeof (dlmgmt_link_t));
	if (linkp == NULL)
		goto fail;

	str = tmpbuf + i;
	/*
	 * Find the link id and assign it to the link structure.
	 */
	if (strtok_r(str, " \n\t", &lasts) == NULL)
		goto fail;

	llen = strlen(str);
	linkp->ll_linkid = atoi(str);

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

	*linkpp = linkp;
	return (B_TRUE);

fail:
	link_destroy(linkp);

	/*
	 * Delete corrupted line.
	 */
	buf[0] = '\0';
	return (B_FALSE);
}

static int
process_db_write(dlmgmt_db_req_t *req, FILE *fp, FILE *nfp)
{
	boolean_t		done = B_FALSE;
	int			err = 0;
	dlmgmt_link_t		*linkp, *link_in_file, link;
	char			buf[MAXLINELEN];

	if (req->ls_op == DLMGMT_DB_OP_WRITE) {
		/*
		 * find the link in the avl tree with the given linkid.
		 */
		link.ll_linkid = req->ls_linkid;
		linkp = avl_find(&dlmgmt_id_avl, &link, NULL);
		if (linkp == NULL || (linkp->ll_flags & req->ls_flags) == 0) {
			/*
			 * This link has already been changed. This could
			 * happen if the request is pending because of
			 * read-only file-system. If so, we are done.
			 */
			return (0);
		}
	}

	while (err == 0 && fgets(buf, sizeof (buf), fp) != NULL &&
	    process_link_line(buf, &link_in_file)) {
		if (link_in_file == NULL || done) {
			/*
			 * this is a comment line, write it out.
			 */
			if (fputs(buf, nfp) == EOF)
				err = errno;
			continue;
		}

		switch (req->ls_op) {
		case DLMGMT_DB_OP_WRITE:
			/*
			 * For write operations, if the linkid of the link
			 * read from the file does not match the id of what
			 * req->ll_linkid points to, write out the buffer.
			 * Otherwise, generate a new line. If we get to the
			 * end and have not seen what req->ll_linkid points
			 * to, write it out then.
			 */
			if (linkp == NULL ||
			    linkp->ll_linkid != link_in_file->ll_linkid) {
				if (fputs(buf, nfp) == EOF)
					err = errno;
			} else {
				generate_link_line(linkp,
				    req->ls_flags == DLMGMT_PERSIST, buf);
				if (fputs(buf, nfp) == EOF)
					err = errno;
				done = B_TRUE;
			}
			break;
		case DLMGMT_DB_OP_DELETE:
			/*
			 * Delete is simple.  If buf does not represent the
			 * link we're deleting, write it out.
			 */
			if (req->ls_linkid != link_in_file->ll_linkid) {
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
		link_destroy(link_in_file);
	}

	/*
	 * If we get to the end of the file and have not seen what
	 * req->ll_linkid points to, write it out then.
	 */
	if (req->ls_op == DLMGMT_DB_OP_WRITE && !done) {
		generate_link_line(linkp, req->ls_flags == DLMGMT_PERSIST, buf);
		done = B_TRUE;
		if (fputs(buf, nfp) == EOF)
			err = errno;
	}

	if (!done)
		err = ENOENT;

	return (err);
}

/* ARGSUSED1 */
static int
process_db_read(dlmgmt_db_req_t *req, FILE *fp, FILE *nfp)
{
	avl_index_t	name_where, id_where;
	dlmgmt_link_t	*link_in_file;
	dlmgmt_link_t	*linkp1, *linkp2;
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
		if (link_in_file == NULL)
			continue;

		linkp1 = avl_find(&dlmgmt_name_avl, link_in_file, &name_where);
		linkp2 = avl_find(&dlmgmt_id_avl, link_in_file, &id_where);
		if ((linkp1 != NULL) || (linkp2 != NULL)) {
			/*
			 * If any of the following conditions are met, this is
			 * a duplicate entry:
			 *
			 * 1. link2 (with the given name) and link2 (with the
			 *    given id) are not the same link;
			 * 2. This is a persistent req and find the link with
			 *    the given name and id. Note that persistent db
			 *    is read before the active one.
			 * 3. Found the link with the given name and id but
			 *    the link is already active.
			 */
			if ((linkp1 != linkp2) ||
			    (req->ls_flags == DLMGMT_PERSIST) ||
			    ((linkp1->ll_flags & DLMGMT_ACTIVE) != 0)) {
				dlmgmt_log(LOG_WARNING, "Duplicate link "
				    "entries in repository:  link name %s "
				    "link id %i", link_in_file->ll_link,
				    link_in_file->ll_linkid);
			} else {
				linkp1->ll_flags |= DLMGMT_ACTIVE;
			}
			link_destroy(link_in_file);
		} else {
			avl_insert(&dlmgmt_name_avl, link_in_file, name_where);
			avl_insert(&dlmgmt_id_avl, link_in_file, id_where);
			dlmgmt_advance(link_in_file);
			link_in_file->ll_flags |= req->ls_flags;
		}
	}

	return (err);
}

/*
 * Generate an entry in the link database.
 * Each entry has this format:
 * <link id>	<prop0>=<type>,<val>;...;<propn>=<type>,<val>;
 */
static void
generate_link_line(dlmgmt_link_t *linkp, boolean_t persist, char *buf)
{
	char			tmpbuf[MAXLINELEN];
	char			*ptr;
	char			*lim = tmpbuf + MAXLINELEN;
	char			*name_to_write = NULL;
	datalink_id_t		id_to_write;
	dlmgmt_linkattr_t	*cur_p = NULL;
	uint64_t		u64;

	ptr = tmpbuf;
	id_to_write = linkp->ll_linkid;
	ptr += snprintf(ptr, BUFLEN(lim, ptr), "%d\t", id_to_write);
	name_to_write = linkp->ll_link;
	ptr += write_str(ptr, BUFLEN(lim, ptr), "name", name_to_write);
	u64 = linkp->ll_class;
	ptr += write_uint64(ptr, BUFLEN(lim, ptr), "class", &u64);
	u64 = linkp->ll_media;
	ptr += write_uint64(ptr, BUFLEN(lim, ptr), "media", &u64);

	/*
	 * The daemon does not keep any active link attribute. If this request
	 * is for active configuration, we are done.
	 */
	if (!persist)
		goto done;

	for (cur_p = linkp->ll_head; cur_p != NULL; cur_p = cur_p->lp_next) {
		ptr += translators[cur_p->lp_type].write_func(ptr,
		    BUFLEN(lim, ptr), cur_p->lp_name, cur_p->lp_val);
	}
done:
	if (ptr > lim)
		return;
	(void) snprintf(buf, MAXLINELEN, "%s\n", tmpbuf);
}

int
dlmgmt_delete_db_entry(datalink_id_t linkid, uint32_t flags)
{
	return (dlmgmt_db_update(DLMGMT_DB_OP_DELETE, linkid, flags));
}

int
dlmgmt_write_db_entry(datalink_id_t linkid, uint32_t flags)
{
	int		err;

	if (flags & DLMGMT_PERSIST) {
		if ((err = dlmgmt_db_update(DLMGMT_DB_OP_WRITE,
		    linkid, DLMGMT_PERSIST)) != 0) {
			return (err);
		}
	}

	if (flags & DLMGMT_ACTIVE) {
		if (((err = dlmgmt_db_update(DLMGMT_DB_OP_WRITE,
		    linkid, DLMGMT_ACTIVE)) != 0) &&
		    (flags & DLMGMT_PERSIST)) {
			(void) dlmgmt_db_update(DLMGMT_DB_OP_DELETE,
			    linkid, DLMGMT_PERSIST);
			return (err);
		}
	}

	return (0);
}

/*
 * Initialize the datalink <link name, linkid> mapping and the link's
 * attributes list based on the configuration file /etc/dladm/datalink.conf
 * and the active configuration cache file
 * /etc/svc/volatile/datalink-management:default.cache.
 *
 * This function is called when the datalink-management service is started
 * during reboot, and when the dlmgmtd daemon is restarted.
 */
int
dlmgmt_db_init()
{
	char		filename[MAXPATHLEN];
	dlmgmt_db_req_t	req;
	int		err;
	dlmgmt_link_t	*linkp;
	char		*fmri, *c;

	/*
	 * First derive the name of the cache file from the FMRI name. This
	 * cache name is used to keep active datalink configuration.
	 */
	if (debug) {
		(void) snprintf(cachefile, MAXPATHLEN, "%s/%s%s",
		    DLMGMT_TEMP_DB_DIR, progname, ".debug.cache");
	} else {
		if ((fmri = getenv("SMF_FMRI")) == NULL) {
			dlmgmt_log(LOG_WARNING, "dlmgmtd is an smf(5) managed "
			    "service and should not be run from the command "
			    "line.");
			return (EINVAL);
		}

		/*
		 * The FMRI name is in the form of
		 * svc:/service/service:instance.  We need to remove the
		 * prefix "svc:/" and replace '/' with '-'.  The cache file
		 * name is in the form of "service:instance.cache".
		 */
		if ((c = strchr(fmri, '/')) != NULL)
			c++;
		else
			c = fmri;
		(void) snprintf(filename, MAXPATHLEN, "%s.cache", c);
		for (c = filename; *c != '\0'; c++) {
			if (*c == '/')
				*c = '-';
		}

		(void) snprintf(cachefile, MAXPATHLEN, "%s/%s",
		    DLMGMT_TEMP_DB_DIR, filename);
	}

	dlmgmt_table_lock(B_TRUE);

	req.ls_next = NULL;
	req.ls_op = DLMGMT_DB_OP_READ;
	req.ls_linkid = DATALINK_INVALID_LINKID;
	req.ls_flags = DLMGMT_PERSIST;

	if ((err = dlmgmt_process_db_req(&req)) != 0)
		goto done;

	req.ls_flags = DLMGMT_ACTIVE;
	err = dlmgmt_process_db_req(&req);
	if (err == ENOENT) {
		/*
		 * The temporary datalink.conf does not exist. This is
		 * the first boot. Mark all the physical links active.
		 */
		for (linkp = avl_first(&dlmgmt_id_avl); linkp != NULL;
		    linkp = AVL_NEXT(&dlmgmt_id_avl, linkp)) {
			if (linkp->ll_class == DATALINK_CLASS_PHYS) {
				linkp->ll_flags |= DLMGMT_ACTIVE;
				(void) dlmgmt_write_db_entry(
				    linkp->ll_linkid, DLMGMT_ACTIVE);
			}
		}
		err = 0;
	}

done:
	dlmgmt_table_unlock();
	return (err);
}
