/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/* Copyright (c) 1996, 1997 PDC, Network Appliance. All Rights Reserved */
/* Copyright (c) 2007, The Storage Networking Industry Association. */

/*
 * File history callback functions called by backup modules. NDMP file history
 * supports 2 file history models: path based and inode/directory based.
 * Backup/recover modules similar to unix dump/restore utilize the
 * inode/directory based model. During the filesystem scan pass,
 * ndmpd_file_history_dir() is called. During the file backup pass,
 * ndmpd_file_history_node() is called. This model is appropriate for
 * modules whose code is structured such that file name and file attribute
 * data is not available at the same time. Backup/recover modules similar
 * to tar or cpio utilize the path based model. The simple dump/restore module
 * included with the SDK uses the path based model.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "ndmpd.h"
#include <dirent.h>
#include <bitmap.h>


#define	N_PATH_ENTRIES	1000
#define	N_FILE_ENTRIES	N_PATH_ENTRIES
#define	N_DIR_ENTRIES	1000
#define	N_NODE_ENTRIES	1000

/* Figure an average of 32 bytes per path name */
#define	PATH_NAMEBUF_SIZE	(N_PATH_ENTRIES * 32)

/* Figure an average of 16 bytes per file name */
#define	DIR_NAMEBUF_SIZE	(N_PATH_ENTRIES * 16)

static boolean_t fh_requested(void *cookie);
static void ndmpd_file_history_cleanup_v2(ndmpd_session_t *session,
    boolean_t send_flag);
static void ndmpd_file_history_cleanup_v3(ndmpd_session_t *session,
    boolean_t send_flag);
static ndmpd_module_params_t *get_params(void *cookie);


/*
 * Each file history as a separate message to the client.
 */
static int ndmp_syncfh = 0;


/*
 * ************************************************************************
 * NDMP V2 HANDLERS
 * ************************************************************************
 */

/*
 * ndmpd_api_file_history_path_v2
 *
 * Add a file history path entry to the buffer.
 * History data is buffered until the buffer is filled.
 * Full buffers are then sent to the client.
 *
 * Parameters:
 *   cookie   (input) - session pointer.
 *   name     (input) - file name.
 *		      NULL forces buffered data to be sent.
 *   file_stat (input) - file status pointer.
 *   fh_info  (input) - data stream position of file data used during
 *		      fast restore.
 *
 * Returns:
 *   0 - success
 *  -1 - error
 */
int
ndmpd_api_file_history_path_v2(void *cookie, char *name,
    struct stat64 *file_stat, u_longlong_t fh_info)
{
	ndmpd_session_t *session = (ndmpd_session_t *)cookie;
	ndmp_fh_unix_path *entry;

	if (name == NULL && session->ns_fh.fh_path_index == 0)
		return (0);

	/*
	 * If the buffer does not have space
	 * for the current entry, send the buffered data to the client.
	 * A NULL name indicates that any buffered data should be sent.
	 */
	if (name == NULL ||
	    (ndmp_syncfh && session->ns_fh.fh_path_index != 0) ||
	    session->ns_fh.fh_path_index == N_PATH_ENTRIES ||
	    session->ns_fh.fh_path_name_buf_index + strlen(name) + 1 >
	    PATH_NAMEBUF_SIZE) {
		ndmp_fh_add_unix_path_request request;

		NDMP_LOG(LOG_DEBUG,
		    "sending %ld entries", session->ns_fh.fh_path_index);

		request.paths.paths_val = session->ns_fh.fh_path_entries;
		request.paths.paths_len = session->ns_fh.fh_path_index;

		if (ndmp_send_request_lock(session->ns_connection,
		    NDMP_FH_ADD_UNIX_PATH, NDMP_NO_ERR, (void *) &request,
		    0) < 0) {
			NDMP_LOG(LOG_DEBUG, "Sending file history data");
			return (-1);
		}
		session->ns_fh.fh_path_index = 0;
		session->ns_fh.fh_path_name_buf_index = 0;
	}
	if (name == NULL)
		return (0);

	if (session->ns_fh.fh_path_entries == 0) {
		session->ns_fh.fh_path_entries = ndmp_malloc(N_PATH_ENTRIES *
		    sizeof (ndmp_fh_unix_path));
		if (session->ns_fh.fh_path_entries == 0)
			return (-1);
	}
	if (session->ns_fh.fh_path_name_buf == 0) {
		session->ns_fh.fh_path_name_buf =
		    ndmp_malloc(PATH_NAMEBUF_SIZE);
		if (session->ns_fh.fh_path_name_buf == 0)
			return (-1);
	}
	entry = &session->ns_fh.fh_path_entries[session->ns_fh.fh_path_index];
	ndmpd_get_file_entry_type(file_stat->st_mode, &entry->fstat.ftype);

	entry->name = &session->
	    ns_fh.fh_path_name_buf[session->ns_fh.fh_path_name_buf_index];
	(void) strlcpy(entry->name, name, PATH_NAMEBUF_SIZE);
	session->ns_fh.fh_path_name_buf_index += strlen(name) + 1;
	entry->fstat.mtime = (ulong_t)file_stat->st_mtime;
	entry->fstat.atime = (ulong_t)file_stat->st_atime;
	entry->fstat.ctime = (ulong_t)file_stat->st_ctime;
	entry->fstat.uid = file_stat->st_uid;
	entry->fstat.gid = file_stat->st_gid;
	entry->fstat.mode = (file_stat->st_mode) & 0x0fff;
	entry->fstat.size = long_long_to_quad((u_longlong_t)file_stat->st_size);
	entry->fstat.fh_info = long_long_to_quad((u_longlong_t)fh_info);
	session->ns_fh.fh_path_index++;
	return (0);
}


/*
 * ndmpd_api_file_history_dir_v2
 *
 * Add a file history dir entry to the buffer.
 * History data is buffered until the buffer is filled.
 * Full buffers are then sent to the client.
 *
 * Parameters:
 *   cookie (input) - session pointer.
 *   name   (input) - file name.
 *		    NULL forces buffered data to be sent.
 *   node   (input) - file inode.
 *   parent (input) - file parent inode.
 *		    Should equal node if the file is the root of
 *		    the filesystem and has no parent.
 *
 * Returns:
 *   0 - success
 *  -1 - error
 */
int
ndmpd_api_file_history_dir_v2(void *cookie, char *name, ulong_t node,
    ulong_t parent)
{
	ndmpd_session_t *session = (ndmpd_session_t *)cookie;
	ndmp_fh_unix_dir *entry;

	if (name == NULL && session->ns_fh.fh_dir_index == 0)
		return (0);

	/*
	 * If the buffer does not have space for the current entry,
	 * send the buffered data to the client. A NULL name indicates
	 * that any buffered data should be sent.
	 */
	if (name == NULL ||
	    (ndmp_syncfh && session->ns_fh.fh_dir_index != 0) ||
	    session->ns_fh.fh_dir_index == N_DIR_ENTRIES ||
	    session->ns_fh.fh_dir_name_buf_index + strlen(name) + 1 >
	    DIR_NAMEBUF_SIZE) {
		ndmp_fh_add_unix_dir_request request;

		NDMP_LOG(LOG_DEBUG,
		    "sending %ld entries", session->ns_fh.fh_dir_index);

		request.dirs.dirs_val = session->ns_fh.fh_dir_entries;
		request.dirs.dirs_len = session->ns_fh.fh_dir_index;
		if (ndmp_send_request_lock(session->ns_connection,
		    NDMP_FH_ADD_UNIX_DIR, NDMP_NO_ERR, (void *) &request,
		    0) < 0) {
			NDMP_LOG(LOG_DEBUG, "Sending file history data");
			return (-1);
		}
		session->ns_fh.fh_dir_index = 0;
		session->ns_fh.fh_dir_name_buf_index = 0;
	}
	if (name == NULL)
		return (0);

	if (session->ns_fh.fh_dir_entries == 0) {
		session->ns_fh.fh_dir_entries = ndmp_malloc(N_DIR_ENTRIES
		    * sizeof (ndmp_fh_unix_dir));
		if (session->ns_fh.fh_dir_entries == 0)
			return (-1);
	}
	if (session->ns_fh.fh_dir_name_buf == 0) {
		session->ns_fh.fh_dir_name_buf = ndmp_malloc(DIR_NAMEBUF_SIZE);
		if (session->ns_fh.fh_dir_name_buf == 0)
			return (-1);
	}
	entry = &session->ns_fh.fh_dir_entries[session->ns_fh.fh_dir_index];

	entry->name = &session->
	    ns_fh.fh_dir_name_buf[session->ns_fh.fh_dir_name_buf_index];
	(void) strlcpy(&session->
	    ns_fh.fh_dir_name_buf[session->ns_fh.fh_dir_name_buf_index],
	    name, PATH_NAMEBUF_SIZE);
	session->ns_fh.fh_dir_name_buf_index += strlen(name) + 1;

	entry->node = node;
	entry->parent = parent;

	session->ns_fh.fh_dir_index++;
	return (0);
}


/*
 * ndmpd_api_file_history_node_v2
 *
 * Add a file history node entry to the buffer.
 * History data is buffered until the buffer is filled.
 * Full buffers are then sent to the client.
 *
 * Parameters:
 *   cookie   (input) - session pointer.
 *   node     (input) - file inode.
 *	      must match a node from a prior ndmpd_api_file_history_dir()
 *		      call.
 *   file_stat (input) - file status pointer.
 *		      0 forces buffered data to be sent.
 *   fh_info  (input) - data stream position of file data used during
 *		      fast restore.
 *
 * Returns:
 *   0 - success
 *  -1 - error.
 */
int
ndmpd_api_file_history_node_v2(void *cookie, ulong_t node,
    struct stat64 *file_stat, u_longlong_t fh_info)
{
	ndmpd_session_t *session = (ndmpd_session_t *)cookie;
	ndmp_fh_unix_node *entry;

	if (file_stat == NULL && session->ns_fh.fh_node_index == 0)
		return (-1);

	/*
	 * If the buffer does not have space
	 * for the current entry, send the buffered data to the client.
	 * A 0 file_stat pointer indicates that any buffered data should
	 * be sent.
	 */
	if (file_stat == NULL ||
	    (ndmp_syncfh && session->ns_fh.fh_node_index != 0) ||
	    session->ns_fh.fh_node_index == N_NODE_ENTRIES) {
		ndmp_fh_add_unix_node_request request;

		NDMP_LOG(LOG_DEBUG,
		    "sending %ld entries", session->ns_fh.fh_node_index);

		request.nodes.nodes_val = session->ns_fh.fh_node_entries;
		request.nodes.nodes_len = session->ns_fh.fh_node_index;
		/*
		 * Need to send Dir entry as well. Since Dir entry is more than
		 * Node entry, we may send a Node entry that hasn't have
		 * its dir entry sent. Therefore, we need to flush Dir entry
		 * as well everytime the Dir entry is send.
		 */
		(void) ndmpd_api_file_history_dir_v2(session, 0, 0, 0);

		if (ndmp_send_request_lock(session->ns_connection,
		    NDMP_FH_ADD_UNIX_NODE, NDMP_NO_ERR, (void *) &request,
		    0) < 0) {
			NDMP_LOG(LOG_DEBUG, "Sending file history data");
			return (-1);
		}
		session->ns_fh.fh_node_index = 0;
	}
	if (file_stat == NULL)
		return (0);

	if (session->ns_fh.fh_node_entries == 0) {
		session->ns_fh.fh_node_entries = ndmp_malloc(N_NODE_ENTRIES
		    * sizeof (ndmp_fh_unix_node));
		if (session->ns_fh.fh_node_entries == 0)
			return (-1);
	}
	entry = &session->ns_fh.fh_node_entries[session->ns_fh.fh_node_index];
	ndmpd_get_file_entry_type(file_stat->st_mode, &entry->fstat.ftype);

	entry->node = node;
	entry->fstat.mtime = (ulong_t)file_stat->st_mtime;
	entry->fstat.atime = (ulong_t)file_stat->st_atime;
	entry->fstat.ctime = (ulong_t)file_stat->st_ctime;
	entry->fstat.uid = file_stat->st_uid;
	entry->fstat.gid = file_stat->st_gid;
	entry->fstat.mode = (file_stat->st_mode) & 0x0fff;
	entry->fstat.size = long_long_to_quad((u_longlong_t)file_stat->st_size);
	entry->fstat.fh_info = long_long_to_quad(fh_info);

	session->ns_fh.fh_node_index++;
	return (0);
}


/*
 * ************************************************************************
 * NDMP V3 HANDLERS
 * ************************************************************************
 */

/*
 * ndmpd_api_file_history_file_v3
 *
 * Add a file history file entry to the buffer.
 * History data is buffered until the buffer is filled.
 * Full buffers are then sent to the client.
 *
 * Parameters:
 *   cookie   (input) - session pointer.
 *   name     (input) - file name.
 *		      NULL forces buffered data to be sent.
 *   file_stat (input) - file status pointer.
 *   fh_info  (input) - data stream position of file data used during
 *		      fast restore.
 *
 * Returns:
 *   0 - success
 *  -1 - error
 */
int
ndmpd_api_file_history_file_v3(void *cookie, char *name,
    struct stat64 *file_stat, u_longlong_t fh_info)
{
	ndmpd_session_t *session = (ndmpd_session_t *)cookie;
	ndmp_file_v3 *file_entry;
	ndmp_file_name_v3 *file_name_entry;
	ndmp_file_stat_v3 *file_stat_entry;
	ndmp_fh_add_file_request_v3 request;

	if (name == NULL && session->ns_fh_v3.fh_file_index == 0)
		return (0);

	/*
	 * If the buffer does not have space
	 * for the current entry, send the buffered data to the client.
	 * A NULL name indicates that any buffered data should be sent.
	 */
	if (name == NULL ||
	    session->ns_fh_v3.fh_file_index == N_FILE_ENTRIES ||
	    session->ns_fh_v3.fh_file_name_buf_index + strlen(name) + 1 >
	    PATH_NAMEBUF_SIZE) {

		NDMP_LOG(LOG_DEBUG, "sending %ld entries",
		    session->ns_fh_v3.fh_file_index);

		request.files.files_len = session->ns_fh_v3.fh_file_index;
		request.files.files_val = session->ns_fh_v3.fh_files;

		if (ndmp_send_request_lock(session->ns_connection,
		    NDMP_FH_ADD_FILE, NDMP_NO_ERR, (void *) &request, 0) < 0) {
			NDMP_LOG(LOG_DEBUG,
			    "Sending ndmp_fh_add_file request");
			return (-1);
		}

		session->ns_fh_v3.fh_file_index = 0;
		session->ns_fh_v3.fh_file_name_buf_index = 0;
	}

	if (name == NULL)
		return (0);

	if (session->ns_fh_v3.fh_files == 0) {
		session->ns_fh_v3.fh_files = ndmp_malloc(sizeof (ndmp_file_v3) *
		    N_FILE_ENTRIES);
		if (session->ns_fh_v3.fh_files == 0)
			return (-1);
	}

	if (session->ns_fh_v3.fh_file_names == 0) {
		session->ns_fh_v3.fh_file_names =
		    ndmp_malloc(sizeof (ndmp_file_name_v3) * N_FILE_ENTRIES);
		if (session->ns_fh_v3.fh_file_names == 0)
			return (-1);
	}

	if (session->ns_fh_v3.fh_file_name_buf == 0) {
		session->ns_fh_v3.fh_file_name_buf =
		    ndmp_malloc(sizeof (char) * PATH_NAMEBUF_SIZE);
		if (session->ns_fh_v3.fh_file_name_buf == 0)
			return (-1);
	}

	if (session->ns_fh_v3.fh_file_stats == 0) {
		session->ns_fh_v3.fh_file_stats =
		    ndmp_malloc(sizeof (ndmp_file_stat_v3) * N_FILE_ENTRIES);
		if (session->ns_fh_v3.fh_file_stats == 0)
			return (-1);
	}

	file_entry =
	    &session->ns_fh_v3.fh_files[session->ns_fh_v3.fh_file_index];
	file_name_entry =
	    &session->ns_fh_v3.fh_file_names[session->ns_fh_v3.fh_file_index];
	file_stat_entry =
	    &session->ns_fh_v3.fh_file_stats[session->ns_fh_v3.fh_file_index];
	file_entry->names.names_len = 1;
	file_entry->names.names_val = file_name_entry;
	file_entry->stats.stats_len = 1;
	file_entry->stats.stats_val = file_stat_entry;
	file_entry->node = long_long_to_quad(file_stat->st_ino);
	file_entry->fh_info = long_long_to_quad(fh_info);

	file_name_entry->fs_type = NDMP_FS_UNIX;
	file_name_entry->ndmp_file_name_v3_u.unix_name =
	    &session->ns_fh_v3.fh_file_name_buf[session->
	    ns_fh_v3.fh_file_name_buf_index];
	(void) strlcpy(&session->ns_fh_v3.fh_file_name_buf[session->
	    ns_fh_v3.fh_file_name_buf_index], name, PATH_NAMEBUF_SIZE);
	session->ns_fh_v3.fh_file_name_buf_index += strlen(name) + 1;
	ndmpd_get_file_entry_type(file_stat->st_mode, &file_stat_entry->ftype);

	file_stat_entry->invalid = 0;
	file_stat_entry->fs_type = NDMP_FS_UNIX;
	file_stat_entry->mtime = file_stat->st_mtime;
	file_stat_entry->atime = file_stat->st_atime;
	file_stat_entry->ctime = file_stat->st_ctime;
	file_stat_entry->owner = file_stat->st_uid;
	file_stat_entry->group = file_stat->st_gid;
	file_stat_entry->fattr = file_stat->st_mode & 0x0fff;
	file_stat_entry->size =
	    long_long_to_quad((u_longlong_t)file_stat->st_size);
	file_stat_entry->links = file_stat->st_nlink;

	session->ns_fh_v3.fh_file_index++;

	return (0);
}


/*
 * ndmpd_api_file_history_dir_v3
 *
 * Add a file history dir entry to the buffer.
 * History data is buffered until the buffer is filled.
 * Full buffers are then sent to the client.
 *
 * Parameters:
 *   cookie (input) - session pointer.
 *   name   (input) - file name.
 *		    NULL forces buffered data to be sent.
 *   node   (input) - file inode.
 *   parent (input) - file parent inode.
 *		    Should equal node if the file is the root of
 *		    the filesystem and has no parent.
 *
 * Returns:
 *   0 - success
 *  -1 - error
 */
int
ndmpd_api_file_history_dir_v3(void *cookie, char *name, ulong_t node,
    ulong_t parent)
{
	ndmpd_session_t *session = (ndmpd_session_t *)cookie;
	ndmp_dir_v3 *dir_entry;
	ndmp_file_name_v3 *dir_name_entry;
	ndmp_fh_add_dir_request_v3 request;

	if (name == NULL && session->ns_fh_v3.fh_dir_index == 0)
		return (0);

	/*
	 * If the buffer does not have space
	 * for the current entry, send the buffered data to the client.
	 * A NULL name indicates that any buffered data should be sent.
	 */
	if (name == NULL ||
	    session->ns_fh_v3.fh_dir_index == N_DIR_ENTRIES ||
	    session->ns_fh_v3.fh_dir_name_buf_index + strlen(name) + 1 >
	    DIR_NAMEBUF_SIZE) {

		NDMP_LOG(LOG_DEBUG, "sending %ld entries",
		    session->ns_fh_v3.fh_dir_index);

		request.dirs.dirs_val = session->ns_fh_v3.fh_dirs;
		request.dirs.dirs_len = session->ns_fh_v3.fh_dir_index;

		if (ndmp_send_request_lock(session->ns_connection,
		    NDMP_FH_ADD_DIR, NDMP_NO_ERR, (void *) &request, 0) < 0) {
			NDMP_LOG(LOG_DEBUG,
			    "Sending ndmp_fh_add_dir request");
			return (-1);
		}

		session->ns_fh_v3.fh_dir_index = 0;
		session->ns_fh_v3.fh_dir_name_buf_index = 0;
	}

	if (name == NULL)
		return (0);

	if (session->ns_fh_v3.fh_dirs == 0) {
		session->ns_fh_v3.fh_dirs =
		    ndmp_malloc(sizeof (ndmp_dir_v3) * N_DIR_ENTRIES);
		if (session->ns_fh_v3.fh_dirs == 0)
			return (-1);
	}

	if (session->ns_fh_v3.fh_dir_names == 0) {
		session->ns_fh_v3.fh_dir_names =
		    ndmp_malloc(sizeof (ndmp_file_name_v3) * N_DIR_ENTRIES);
		if (session->ns_fh_v3.fh_dir_names == 0)
			return (-1);
	}

	if (session->ns_fh_v3.fh_dir_name_buf == 0) {
		session->ns_fh_v3.fh_dir_name_buf =
		    ndmp_malloc(sizeof (char) * DIR_NAMEBUF_SIZE);
		if (session->ns_fh_v3.fh_dir_name_buf == 0)
			return (-1);
	}

	dir_entry = &session->ns_fh_v3.fh_dirs[session->ns_fh_v3.fh_dir_index];
	dir_name_entry =
	    &session->ns_fh_v3.fh_dir_names[session->ns_fh_v3.fh_dir_index];

	dir_name_entry->fs_type = NDMP_FS_UNIX;
	dir_name_entry->ndmp_file_name_v3_u.unix_name =
	    &session->ns_fh_v3.fh_dir_name_buf[session->
	    ns_fh_v3.fh_dir_name_buf_index];

	(void) strlcpy(&session->ns_fh_v3.fh_dir_name_buf[session->
	    ns_fh_v3.fh_dir_name_buf_index], name, PATH_NAMEBUF_SIZE);
	session->ns_fh_v3.fh_dir_name_buf_index += strlen(name) + 1;

	dir_entry->names.names_len = 1;
	dir_entry->names.names_val = dir_name_entry;
	dir_entry->node = long_long_to_quad(node);
	dir_entry->parent = long_long_to_quad(parent);

	session->ns_fh_v3.fh_dir_index++;

	return (0);
}


/*
 * ndmpd_api_file_history_node_v3
 *
 * Add a file history node entry to the buffer.
 * History data is buffered until the buffer is filled.
 * Full buffers are then sent to the client.
 *
 * Parameters:
 *   cookie   (input) - session pointer.
 *   node     (input) - file inode.
 *		must match a node from a prior ndmpd_api_file_history_dir()
 *		      call.
 *   file_stat (input) - file status pointer.
 *		      0 forces buffered data to be sent.
 *   fh_info  (input) - data stream position of file data used during
 *		      fast restore.
 *
 * Returns:
 *   0 - success
 *  -1 - error.
 */
int
ndmpd_api_file_history_node_v3(void *cookie, ulong_t node,
    struct stat64 *file_stat, u_longlong_t fh_info)
{
	ndmpd_session_t *session = (ndmpd_session_t *)cookie;
	ndmp_node_v3 *node_entry;
	ndmp_file_stat_v3 *file_stat_entry;
	ndmp_fh_add_node_request_v3 request;

	if (file_stat == NULL && session->ns_fh_v3.fh_node_index == 0)
		return (0);

	/*
	 * If the buffer does not have space
	 * for the current entry, send the buffered data to the client.
	 * A 0 file_stat pointer indicates that any buffered data should
	 * be sent.
	 */
	if (file_stat == NULL ||
	    session->ns_fh_v3.fh_node_index == N_NODE_ENTRIES) {
		NDMP_LOG(LOG_DEBUG, "sending %ld entries",
		    session->ns_fh_v3.fh_node_index);

		/*
		 * Need to send Dir entry as well. Since Dir entry is more
		 * than a Node entry, we may send a Node entry that hasn't
		 * had its Dir entry sent. Therefore, we need to flush Dir
		 * entry as well every time the Dir entry is sent.
		 */
		(void) ndmpd_api_file_history_dir_v3(session, 0, 0, 0);

		request.nodes.nodes_len = session->ns_fh_v3.fh_node_index;
		request.nodes.nodes_val = session->ns_fh_v3.fh_nodes;

		if (ndmp_send_request_lock(session->ns_connection,
		    NDMP_FH_ADD_NODE,
		    NDMP_NO_ERR, (void *) &request, 0) < 0) {
			NDMP_LOG(LOG_DEBUG,
			    "Sending ndmp_fh_add_node request");
			return (-1);
		}

		session->ns_fh_v3.fh_node_index = 0;
	}

	if (file_stat == NULL)
		return (0);

	if (session->ns_fh_v3.fh_nodes == 0) {
		session->ns_fh_v3.fh_nodes =
		    ndmp_malloc(sizeof (ndmp_node_v3) * N_NODE_ENTRIES);
		if (session->ns_fh_v3.fh_nodes == 0)
			return (-1);
	}

	if (session->ns_fh_v3.fh_node_stats == 0) {
		session->ns_fh_v3.fh_node_stats =
		    ndmp_malloc(sizeof (ndmp_file_stat_v3) * N_NODE_ENTRIES);
		if (session->ns_fh_v3.fh_node_stats == 0)
			return (-1);
	}

	node_entry =
	    &session->ns_fh_v3.fh_nodes[session->ns_fh_v3.fh_node_index];

	file_stat_entry =
	    &session->ns_fh_v3.fh_node_stats[session->ns_fh_v3.fh_node_index];
	ndmpd_get_file_entry_type(file_stat->st_mode, &file_stat_entry->ftype);

	file_stat_entry->invalid = 0;
	file_stat_entry->fs_type = NDMP_FS_UNIX;
	file_stat_entry->mtime = file_stat->st_mtime;
	file_stat_entry->atime = file_stat->st_atime;
	file_stat_entry->ctime = file_stat->st_ctime;
	file_stat_entry->owner = file_stat->st_uid;
	file_stat_entry->group = file_stat->st_gid;
	file_stat_entry->fattr = file_stat->st_mode & 0x0fff;
	file_stat_entry->size =
	    long_long_to_quad((u_longlong_t)file_stat->st_size);
	file_stat_entry->links = file_stat->st_nlink;

	node_entry->stats.stats_len = 1;
	node_entry->stats.stats_val = file_stat_entry;
	node_entry->node = long_long_to_quad((u_longlong_t)node);
	node_entry->fh_info = long_long_to_quad(fh_info);

	session->ns_fh_v3.fh_node_index++;

	return (0);
}


/*
 * ************************************************************************
 * NDMP V4 HANDLERS
 * ************************************************************************
 */


/*
 * ndmpd_fhpath_v3_cb
 *
 * Callback function for file history path information
 */
int
ndmpd_fhpath_v3_cb(lbr_fhlog_call_backs_t *cbp, char *path, struct stat64 *stp,
    u_longlong_t off)
{
	int err;
	ndmp_lbr_params_t *nlp;
	ndmpd_module_params_t *params;

	if (!cbp) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "cbp is NULL");
	} else if (!cbp->fh_cookie) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "cookie is NULL");
	} else if (!path) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "path is NULL");
	} else if (!(nlp = ndmp_get_nlp(cbp->fh_cookie))) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "nlp is NULL");
	} else
		err = 0;

	if (err != 0)
		return (0);

	NDMP_LOG(LOG_DEBUG, "pname(%s)", path);

	err = 0;
	if (NLP_ISSET(nlp, NLPF_FH)) {
		if (!NLP_ISSET(nlp, NLPF_DIRECT)) {
			NDMP_LOG(LOG_DEBUG, "DAR NOT SET!");
			off = 0LL;
		}

		params = get_params(cbp->fh_cookie);
		if (!params || !params->mp_file_history_path_func) {
			err = -1;
		} else {
			char *p =
			    ndmp_get_relative_path(get_backup_path_v3(params),
			    path);
			if ((err = ndmpd_api_file_history_file_v3(cbp->
			    fh_cookie, p, stp, off)) < 0)
				NDMP_LOG(LOG_DEBUG, "\"%s\" %d", path, err);
		}
	}

	return (err);
}


/*
 * ndmpd_fhdir_v3_cb
 *
 * Callback function for file history dir information
 */
int
ndmpd_fhdir_v3_cb(lbr_fhlog_call_backs_t *cbp, char *dir, struct stat64 *stp)
{
	char nm[PATH_MAX+1];
	int nml;
	int err;
	ulong_t ino, pino;
	ulong_t pos;
	ndmp_lbr_params_t *nlp;
	ndmpd_module_params_t *params;
	DIR *dirp;
	char dirpath[PATH_MAX];

	if (!cbp) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "cbp is NULL");
	} else if (!cbp->fh_cookie) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "cookie is NULL");
	} else if (!dir) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "dir is NULL");
	} else if (!(nlp = ndmp_get_nlp(cbp->fh_cookie))) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "nlp is NULL");
	} else
		err = 0;

	if (err != 0)
		return (0);

	NDMP_LOG(LOG_DEBUG, "d(%s)", dir);

	if (!NLP_ISSET(nlp, NLPF_FH))
		return (0);

	/*
	 * Veritas net_backup accepts only 2 as the inode number of the backup
	 * root directory.  The other way compares the path against the
	 * backup path which is slower.
	 */
	if (stp->st_ino == nlp->nlp_bkdirino)
		pino = ROOT_INODE;
	else
		pino = stp->st_ino;

	/*
	 * There is nothing below this directory to be backed up.
	 * If there was, the bit for this directory would have
	 * been set.  Backup root directory is exception.  We
	 * always send the dir file history records of it.
	 */
	if (pino != ROOT_INODE &&
	    !dbm_getone(nlp->nlp_bkmap, (u_longlong_t)stp->st_ino)) {
		NDMP_LOG(LOG_DEBUG, "nothing below here");
		return (0);
	}

	params = nlp->nlp_params;
	if (!params || !params->mp_file_history_dir_func)
		return (-1);

	pos = 0;
	err = 0;

	dirp = opendir(dir);
	if (dirp == NULL)
		return (0);

	do {
		nml = PATH_MAX;
		err = dp_readdir(dirp, &pos, nm, &nml, &ino);
		if (err != 0) {
			NDMP_LOG(LOG_DEBUG,
			    "%d reading pos %u dir \"%s\"", err, pos, dir);
			break;
		}
		if (nml == 0)
			break;
		nm[nml] = '\0';

		if (pino == ROOT_INODE) {
			if (rootfs_dot_or_dotdot(nm))
				ino = ROOT_INODE;
		} else if (ino == nlp->nlp_bkdirino && IS_DOTDOT(nm)) {
			NDMP_LOG(LOG_DEBUG, "nm(%s): %lu", nm, ino);
			ino = ROOT_INODE;
		}

		if (!dbm_getone(nlp->nlp_bkmap, (u_longlong_t)ino))
			continue;

		/*
		 * If the entry is on exclusion list dont send the info
		 */
		if (tlm_is_excluded(dir, nm, ndmp_excl_list)) {
			NDMP_LOG(LOG_DEBUG,
			    "name \"%s\" skipped", nm == 0 ? "nil" : nm);
			continue;
		}

		err = (*params->mp_file_history_dir_func)(cbp->fh_cookie, nm,
		    ino, pino);
		if (err < 0) {
			NDMP_LOG(LOG_DEBUG, "\"%s\": %d", dir, err);
			break;
		}

		/*
		 * This is a requirement by some DMA's (net_vault) that during
		 * the incremental backup, the node info should also be sent
		 * along with the dir info for all directories leading to a
		 * backed up file.
		 */
		if (ndmp_fhinode) {
			struct stat64 ret_attr;

			(void) strlcpy(dirpath, dir, PATH_MAX);
			(void) strlcat(dirpath, "/", PATH_MAX);
			(void) strlcat(dirpath, nm, PATH_MAX);
			err = stat64(dirpath, &ret_attr);
			if (err != 0) {
				NDMP_LOG(LOG_DEBUG,
				    "Error looking up %s", nm);
				break;
			}

			if (S_ISDIR(ret_attr.st_mode)) {
				err = (*params->mp_file_history_node_func)(cbp->
				    fh_cookie, ino, &ret_attr, 0);
				if (err < 0) {
					NDMP_LOG(LOG_DEBUG, "\"%s/\": %d",
					    dir, err);
					break;
				}
			}
		}
	} while (err == 0);

	(void) closedir(dirp);
	return (err);
}


/*
 * ndmpd_fhnode_v3_cb
 *
 * Callback function for file history node information
 */
int
ndmpd_fhnode_v3_cb(lbr_fhlog_call_backs_t *cbp, char *dir, char *file,
    struct stat64 *stp, u_longlong_t off)
{
	int err;
	ulong_t ino;
	ndmp_lbr_params_t *nlp;
	ndmpd_module_params_t *params;

	if (!cbp) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "cbp is NULL");
	} else if (!cbp->fh_cookie) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "cookie is NULL");
	} else if (!dir) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "dir is NULL");
	} else if (!file) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "file is NULL");
	} else if (!stp) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "stp is NULL");
	} else if (!(nlp = ndmp_get_nlp(cbp->fh_cookie))) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "nlp is NULL");
	} else {
		err = 0;
	}

	if (err != 0)
		return (0);

	NDMP_LOG(LOG_DEBUG, "d(%s), f(%s)", dir, file);

	err = 0;
	if (NLP_ISSET(nlp, NLPF_FH)) {
		if (!NLP_ISSET(nlp, NLPF_DIRECT))
			off = 0LL;
		if (stp->st_ino == nlp->nlp_bkdirino) {
			ino = ROOT_INODE;
			NDMP_LOG(LOG_DEBUG,
			    "bkroot %d -> %d", stp->st_ino, ROOT_INODE);
		} else
			ino = stp->st_ino;

		params = nlp->nlp_params;
		if (!params || !params->mp_file_history_node_func)
			err = -1;
		else if ((err = (*params->mp_file_history_node_func)(cbp->
		    fh_cookie, ino, stp, off)) < 0)
			NDMP_LOG(LOG_DEBUG, "\"%s/%s\" %d", dir, file, err);
	}

	return (err);
}


/*
 * ndmp_send_recovery_stat_v3
 *
 * Send the recovery status to the DMA
 */
int
ndmp_send_recovery_stat_v3(ndmpd_module_params_t *params,
    ndmp_lbr_params_t *nlp, int idx, int stat)
{
	int rv;
	mem_ndmp_name_v3_t *ep;

	rv = -1;
	if (!params) {
		NDMP_LOG(LOG_DEBUG, "params == NULL");
	} else if (!params->mp_file_recovered_func) {
		NDMP_LOG(LOG_DEBUG, "paramsfile_recovered_func == NULL");
	} else if (!nlp) {
		NDMP_LOG(LOG_DEBUG, "nlp == NULL");
	} else if (idx < 0) {
		NDMP_LOG(LOG_DEBUG, "idx(%d) < 0", idx);
	} else if (!(ep = (mem_ndmp_name_v3_t *)MOD_GETNAME(params, idx))) {
		NDMP_LOG(LOG_DEBUG, "nlist[%d] == NULL", idx);
	} else if (!ep->nm3_opath) {
		NDMP_LOG(LOG_DEBUG, "nlist[%d].nm3_opath == NULL", idx);
	} else {
		NDMP_LOG(LOG_DEBUG,
		    "ep[%d].nm3_opath \"%s\"", idx, ep->nm3_opath);
		rv = MOD_FILERECOVERD(params, ep->nm3_opath, stat);
	}

	return (rv);
}


/*
 * ndmpd_path_restored_v3
 *
 * Send the recovery status and the information for the restored
 * path.
 */
/*ARGSUSED*/
int
ndmpd_path_restored_v3(lbr_fhlog_call_backs_t *cbp, char *name,
    struct stat64 *st, u_longlong_t ll_idx)
{
	int rv;
	ndmp_lbr_params_t *nlp;
	ndmpd_module_params_t *params;
	int idx = (int)ll_idx;

	if (!cbp) {
		NDMP_LOG(LOG_DEBUG, "cbp is NULL");
		return (-1);
	}
	if (!name) {
		NDMP_LOG(LOG_DEBUG, "name is NULL");
		return (-1);
	}

	NDMP_LOG(LOG_DEBUG, "name: \"%s\", idx: %d", name, idx);

	nlp = ndmp_get_nlp(cbp->fh_cookie);
	if (!nlp) {
		NDMP_LOG(LOG_DEBUG, "nlp is NULL");
		return (-1);
	}
	if (idx < 0 || idx >= nlp->nlp_nfiles) {
		NDMP_LOG(LOG_DEBUG, "Invalid idx: %d", idx);
		return (-1);
	}
	params = nlp->nlp_params;
	if (!params || !params->mp_file_recovered_func)
		return (-1);

	if (nlp->nlp_lastidx == -1)
		nlp->nlp_lastidx = idx;

	rv = 0;
	(void) bm_setone(nlp->nlp_rsbm, (u_longlong_t)idx);
	/*
	 * Note: We should set the nm3_err here.
	 */
	if (nlp->nlp_lastidx != idx) {
		rv = ndmp_send_recovery_stat_v3(params, nlp, nlp->nlp_lastidx,
		    0);
		nlp->nlp_lastidx = idx;
	}

	return (rv);
}



/*
 * ndmpd_file_history_init
 *
 * Initialize file history variables.
 * Note that the entry and name buffers are not allocated here.
 * Since it is not know if the backup module will be sending file history
 * data or what kind of data (path or dir/node), the entry and name
 * buffers are not allocated until the first call to one of the file history
 * entry functions is made. This way resources are only allocated as
 * needed.
 *
 * Parameters:
 *   session (input) - session pointer.
 *
 * Returns:
 *   void
 */
void
ndmpd_file_history_init(ndmpd_session_t *session)
{
	session->ns_fh.fh_path_entries = 0;
	session->ns_fh.fh_dir_entries = 0;
	session->ns_fh.fh_node_entries = 0;
	session->ns_fh.fh_path_name_buf = 0;
	session->ns_fh.fh_dir_name_buf = 0;
	session->ns_fh.fh_path_index = 0;
	session->ns_fh.fh_dir_index = 0;
	session->ns_fh.fh_node_index = 0;
	session->ns_fh.fh_path_name_buf_index = 0;
	session->ns_fh.fh_dir_name_buf_index = 0;

	/*
	 * V3.
	 */
	session->ns_fh_v3.fh_files = 0;
	session->ns_fh_v3.fh_dirs = 0;
	session->ns_fh_v3.fh_nodes = 0;
	session->ns_fh_v3.fh_file_names = 0;
	session->ns_fh_v3.fh_dir_names = 0;
	session->ns_fh_v3.fh_file_stats = 0;
	session->ns_fh_v3.fh_node_stats = 0;
	session->ns_fh_v3.fh_file_name_buf = 0;
	session->ns_fh_v3.fh_dir_name_buf = 0;
	session->ns_fh_v3.fh_file_index = 0;
	session->ns_fh_v3.fh_dir_index = 0;
	session->ns_fh_v3.fh_node_index = 0;
	session->ns_fh_v3.fh_file_name_buf_index = 0;
	session->ns_fh_v3.fh_dir_name_buf_index = 0;
}


/*
 * ndmpd_file_history_cleanup_v2
 *
 * Send (or discard) any buffered file history entries.
 *
 * Parameters:
 *   session  (input) - session pointer.
 *   send_flag (input) - if TRUE  buffered entries are sent.
 *		      if FALSE buffered entries are discarded.
 *
 * Returns:
 *   void
 */
static void
ndmpd_file_history_cleanup_v2(ndmpd_session_t *session, boolean_t send_flag)
{
	if (send_flag == TRUE) {
		(void) ndmpd_api_file_history_path_v2(session, 0, 0, 0);
		(void) ndmpd_api_file_history_dir_v2(session, 0, 0, 0);
		(void) ndmpd_api_file_history_node_v2(session, 0, 0, 0);
	}

	if (session->ns_fh.fh_path_entries != 0) {
		free(session->ns_fh.fh_path_entries);
		session->ns_fh.fh_path_entries = 0;
	}
	if (session->ns_fh.fh_dir_entries != 0) {
		free(session->ns_fh.fh_dir_entries);
		session->ns_fh.fh_dir_entries = 0;
	}
	if (session->ns_fh.fh_node_entries != 0) {
		free(session->ns_fh.fh_node_entries);
		session->ns_fh.fh_node_entries = 0;
	}
	if (session->ns_fh.fh_path_name_buf != 0) {
		free(session->ns_fh.fh_path_name_buf);
		session->ns_fh.fh_path_name_buf = 0;
	}
	if (session->ns_fh.fh_dir_name_buf != 0) {
		free(session->ns_fh.fh_dir_name_buf);
		session->ns_fh.fh_dir_name_buf = 0;
	}
	session->ns_fh.fh_path_index = 0;
	session->ns_fh.fh_dir_index = 0;
	session->ns_fh.fh_node_index = 0;
	session->ns_fh.fh_path_name_buf_index = 0;
	session->ns_fh.fh_dir_name_buf_index = 0;
}


/*
 * ndmpd_file_history_cleanup_v3
 *
 * Send (or discard) any buffered file history entries.
 *
 * Parameters:
 *   session  (input) - session pointer.
 *   send_flag (input) - if TRUE  buffered entries are sent.
 *		      if FALSE buffered entries are discarded.
 *
 * Returns:
 *   void
 */
static void
ndmpd_file_history_cleanup_v3(ndmpd_session_t *session, boolean_t send_flag)
{
	if (send_flag == TRUE) {
		(void) ndmpd_api_file_history_file_v3(session, 0, 0, 0);
		(void) ndmpd_api_file_history_dir_v3(session, 0, 0, 0);
		(void) ndmpd_api_file_history_node_v3(session, 0, 0, 0);
	}

	if (session->ns_fh_v3.fh_files != 0) {
		free(session->ns_fh_v3.fh_files);
		session->ns_fh_v3.fh_files = 0;
	}
	if (session->ns_fh_v3.fh_dirs != 0) {
		free(session->ns_fh_v3.fh_dirs);
		session->ns_fh_v3.fh_dirs = 0;
	}
	if (session->ns_fh_v3.fh_nodes != 0) {
		free(session->ns_fh_v3.fh_nodes);
		session->ns_fh_v3.fh_nodes = 0;
	}
	if (session->ns_fh_v3.fh_file_names != 0) {
		free(session->ns_fh_v3.fh_file_names);
		session->ns_fh_v3.fh_file_names = 0;
	}
	if (session->ns_fh_v3.fh_dir_names != 0) {
		free(session->ns_fh_v3.fh_dir_names);
		session->ns_fh_v3.fh_dir_names = 0;
	}
	if (session->ns_fh_v3.fh_file_stats != 0) {
		free(session->ns_fh_v3.fh_file_stats);
		session->ns_fh_v3.fh_file_stats = 0;
	}
	if (session->ns_fh_v3.fh_node_stats != 0) {
		free(session->ns_fh_v3.fh_node_stats);
		session->ns_fh_v3.fh_node_stats = 0;
	}
	if (session->ns_fh_v3.fh_file_name_buf != 0) {
		free(session->ns_fh_v3.fh_file_name_buf);
		session->ns_fh_v3.fh_file_name_buf = 0;
	}
	if (session->ns_fh_v3.fh_dir_name_buf != 0) {
		free(session->ns_fh_v3.fh_dir_name_buf);
		session->ns_fh_v3.fh_dir_name_buf = 0;
	}

	session->ns_fh_v3.fh_file_index = 0;
	session->ns_fh_v3.fh_dir_index = 0;
	session->ns_fh_v3.fh_node_index = 0;
	session->ns_fh_v3.fh_file_name_buf_index = 0;
	session->ns_fh_v3.fh_dir_name_buf_index = 0;
}


/*
 * ndmpd_file_history_cleanup
 *
 * Send any pending posts and clean up
 */
void
ndmpd_file_history_cleanup(ndmpd_session_t *session, boolean_t send_flag)
{
	switch (session->ns_protocol_version) {
	case 1:
	case 2:
		ndmpd_file_history_cleanup_v2(session, send_flag);
		break;
	case 3:
	case 4:
		ndmpd_file_history_cleanup_v3(session, send_flag);
		break;
	default:
		NDMP_LOG(LOG_DEBUG, "Unknown version %d",
		    session->ns_protocol_version);
	}
}

/*
 * get_params
 *
 * Callbacks from LBR.
 */
static ndmpd_module_params_t *
get_params(void *cookie)
{
	ndmp_lbr_params_t *nlp;

	if ((nlp = ndmp_get_nlp(cookie)) == NULL)
		return (NULL);

	return (nlp->nlp_params);
}


/*
 * fh_requested
 *
 * Check in LB parameters if file history is requested
 */
static boolean_t
fh_requested(void *cookie)
{
	ndmp_lbr_params_t *nlp;

	if ((nlp = ndmp_get_nlp(cookie)) == NULL) {
		NDMP_LOG(LOG_DEBUG, "nlp is NULL");
		return (FALSE);
	}

	NDMP_LOG(LOG_DEBUG, "nlp_fh %c", NDMP_YORN(NLP_ISSET(nlp, NLPF_FH)));

	return (NLP_ISSET(nlp, NLPF_FH));
}


/*
 * ndmpd_file_history_path
 *
 * Generates file history path information posts
 *
 * Note:
 *   Action must be determined when the 'dir' and/or 'file'
 *   arguments of ndmpd_file_history_path(), ndmpd_file_history_dir(), and
 *   ndmpd_file_history_node() are NULL.
 */
/*ARGSUSED*/
int
ndmpd_file_history_path(lbr_fhlog_call_backs_t *cbp, char *path,
    struct stat64 *stp, u_longlong_t off)
{
	int err;
	ndmpd_module_params_t *params;

	if (!cbp) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "cbp is NULL");
	} else if (!cbp->fh_cookie) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "cookie is NULL");
	} else if (!path) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "path is NULL");
	} else if (!stp) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "stp is NULL");
	} else
		err = 0;

	if (err != 0)
		return (0);

	NDMP_LOG(LOG_DEBUG, "path: \"%s\"", path);

	err = 0;
	if (fh_requested(cbp->fh_cookie)) {
		params = get_params(cbp->fh_cookie);
		if (params == NULL || params->mp_file_history_path_func == NULL)
			err = -1;
		else if ((err = (*params->mp_file_history_path_func)(cbp->
		    fh_cookie, path, stp, 0)) < 0)
			NDMP_LOG(LOG_DEBUG, "\"%s\": %d", path, err);
	}

	return (err);
}


/*
 * ndmpd_file_history_dir
 *
 * Generate file history directory information posts
 */
int
ndmpd_file_history_dir(lbr_fhlog_call_backs_t *cbp, char *dir,
    struct stat64 *stp)
{
	char nm[PATH_MAX+1];
	int nml;
	int err;
	ulong_t ino, pino;
	ulong_t pos;
	ndmp_lbr_params_t *nlp;
	ndmpd_module_params_t *params;
	DIR *dirp;
	char dirpath[PATH_MAX];

	if (!cbp) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "cbp is NULL");
	} else if (!cbp->fh_cookie) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "cookie is NULL");
	} else if (!dir) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "dir is NULL");
	} else if (!stp) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "stp is NULL");
	} if (!(nlp = ndmp_get_nlp(cbp->fh_cookie))) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "nlp is NULL");
	} else
		err = 0;

	if (err != 0)
		return (0);

	NDMP_LOG(LOG_DEBUG, "dir: \"%s\"", dir);

	if (!fh_requested(cbp->fh_cookie))
		return (0);

	/*
	 * Veritas net_backup accepts only 2 as the inode number of the backup
	 * root directory.  The other way compares the path against the
	 * backup path which is slower.
	 */
	if (stp->st_ino == nlp->nlp_bkdirino)
		pino = ROOT_INODE;
	else
		pino = stp->st_ino;

	/*
	 * There is nothing below this directory to be backed up.
	 * If there was, the bit for this directory would have
	 * been set.  Backup root directory is exception.  We
	 * always send the dir file history records of it.
	 */
	if (pino != ROOT_INODE &&
	    !dbm_getone(nlp->nlp_bkmap, (u_longlong_t)stp->st_ino)) {
		NDMP_LOG(LOG_DEBUG, "nothing below here");
		return (0);
	}

	params = get_params(cbp->fh_cookie);
	if (params == NULL || params->mp_file_history_dir_func == NULL) {
		return (0);
	}

	pos = 0;
	err = 0;

	dirp = opendir(dir);
	if (dirp == NULL)
		return (0);

	do {
		nml = PATH_MAX;
		err = dp_readdir(dirp, &pos, nm, &nml, &ino);
		if (err != 0) {
			NDMP_LOG(LOG_DEBUG,
			    "%d reading pos %u dir \"%s\"", err, pos, dir);
			break;
		}
		if (nml == 0)
			break;
		nm[nml] = '\0';

		if (pino == ROOT_INODE) {
			if (rootfs_dot_or_dotdot(nm))
				ino = ROOT_INODE;
		} else if (ino == nlp->nlp_bkdirino && IS_DOTDOT(nm)) {
			NDMP_LOG(LOG_DEBUG, "nm(%s): %lu", nm, ino);
			ino = ROOT_INODE;
		}

		if (!dbm_getone(nlp->nlp_bkmap, (u_longlong_t)ino))
			continue;

		err = (*params->mp_file_history_dir_func)(cbp->fh_cookie, nm,
		    ino, pino);
		if (err < 0) {
			NDMP_LOG(LOG_DEBUG, "\"%s/%s\": %d", dir, nm, err);
			break;
		}

		/*
		 * This is a requirement by some DMA's (net_vault) that during
		 * the incremental backup, the node info should also be sent
		 * along with the dir info for all directories leading to a
		 * backed up file.
		 */
		if (ndmp_fhinode) {
			struct stat64 ret_attr;

			(void) strlcpy(dirpath, dir, PATH_MAX);
			(void) strlcat(dirpath, "/", PATH_MAX);
			(void) strlcat(dirpath, nm, PATH_MAX);
			err = stat64(dirpath, &ret_attr);
			if (err != 0) {
				NDMP_LOG(LOG_DEBUG,
				    "Error looking up %s", nm);
				break;
			}

			if (S_ISDIR(ret_attr.st_mode)) {
				err = (*params->mp_file_history_node_func)(cbp->
				    fh_cookie, ino, &ret_attr, 0);
				if (err < 0) {
					NDMP_LOG(LOG_DEBUG, "\"%s/\": %d",
					    dir, err);
					break;
				}
			}
		}
	} while (err == 0);

	(void) closedir(dirp);
	return (err);
}


/*
 * ndmpd_file_history_node
 *
 * Generate file history node information posts
 */
/*ARGSUSED*/
int
ndmpd_file_history_node(lbr_fhlog_call_backs_t *cbp, char *dir, char *file,
    struct stat64 *stp, u_longlong_t off)
{
	int err;
	ulong_t ino;
	ndmp_lbr_params_t *nlp;
	ndmpd_module_params_t *params;

	if (!cbp) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "cbp is NULL");
	} else if (!cbp->fh_cookie) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "cookie is NULL");
	} else if (!dir) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "dir is NULL");
	} else if (!file) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "file is NULL");
	} else if (!stp) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "stp is NULL");
	} else if (!(nlp = ndmp_get_nlp(cbp->fh_cookie))) {
		err = -1;
		NDMP_LOG(LOG_DEBUG, "nlp is NULL");
	} else
		err = 0;

	if (err != 0)
		return (0);

	NDMP_LOG(LOG_DEBUG, "d(%s), f(%s)", dir, file);

	err = 0;
	if (fh_requested(cbp->fh_cookie) == TRUE) {
		if (stp->st_ino == nlp->nlp_bkdirino) {
			ino = ROOT_INODE;
			NDMP_LOG(LOG_DEBUG,
			    "bkroot %d -> %d", stp->st_ino, ROOT_INODE);
		} else {
			ino = stp->st_ino;
		}

		params = get_params(cbp->fh_cookie);
		if (params == NULL || params->mp_file_history_node_func == NULL)
			err = -1;
		else if ((err = (*params->mp_file_history_node_func)(cbp->
		    fh_cookie, ino, stp, 0)) < 0)
			NDMP_LOG(LOG_DEBUG, "\"%s/\": %d", dir, file, err);

	}

	return (err);
}


/*
 * ndmpd_path_restored
 *
 * Mark the specified path as a restored path
 */
/*ARGSUSED*/
int
ndmpd_path_restored(lbr_fhlog_call_backs_t *cbp, char *name, struct stat64 *stp,
    u_longlong_t ll_pos)
{
	int rv;
	ndmp_name *entp;
	ndmp_lbr_params_t *nlp;
	ndmpd_module_params_t *params;
	int pos =  (int)ll_pos;

	if (cbp == NULL) {
		NDMP_LOG(LOG_DEBUG, "cbp is NULL");
		return (-1);
	}
	if (name == NULL) {
		NDMP_LOG(LOG_DEBUG, "name is NULL");
		return (-1);
	}

	NDMP_LOG(LOG_DEBUG, "name: \"%s\", pos: %d",
	    name, pos);

	if ((nlp = ndmp_get_nlp(cbp->fh_cookie)) == NULL) {
		NDMP_LOG(LOG_DEBUG, "nlp is NULL");
		return (-1);
	}
	if (pos < 0 || pos >= nlp->nlp_nfiles) {
		NDMP_LOG(LOG_DEBUG, "Invalid pos: %d", pos);
		return (-1);
	}
	params = get_params(cbp->fh_cookie);
	if (params == NULL || params->mp_file_recovered_func == NULL)
		return (-1);

	rv = 0;
	if (!nlp->nlp_restored[pos]) {
		entp = (ndmp_name *)MOD_GETNAME(params, pos);
		if (entp && entp->name)
			name = entp->name;

		if ((rv = MOD_FILERECOVERD(params, name, 0)) >= 0)
			nlp->nlp_restored[pos] = TRUE;
	}

	return (rv);
}


/*
 * dp_readdir
 *
 * Reads the entry of the directory and provides other information
 * such as i-number, name, length and saves the dir entry position
 * in a cookie for future calls.
 */
int
dp_readdir(DIR *dirp, unsigned long *cookiep, char *name, int *n_namep,
    unsigned long *fileidp)
{
	struct dirent *entp;
	int err = errno;

	if ((entp = readdir(dirp)) == 0) {
		if (err == errno) {
			*n_namep = 0;
			return (0);
		}
		return (errno);
	}

	*fileidp = entp->d_ino;
	(void) strlcpy(name, entp->d_name, *n_namep);
	*n_namep = entp->d_reclen + 1;
	*cookiep = telldir(dirp);
	return (0);
}
