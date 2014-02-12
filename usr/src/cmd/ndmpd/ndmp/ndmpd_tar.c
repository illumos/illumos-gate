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
/* Copyright (c) 2007, The Storage Networking Industry Association. */
/* Copyright (c) 1996, 1997 PDC, Network Appliance. All Rights Reserved */
/* Copyright 2014 Nexenta Systems, Inc. All rights reserved. */

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <cstack.h>
#include <dirent.h>
#include <traverse.h>
#include "bitmap.h"
#include "ndmpd.h"
#include "tlm_buffers.h"


typedef struct ndmp_run_args {
	char *nr_chkp_nm;
	char *nr_unchkp_nm;
	char **nr_excls;
} ndmp_run_args_t;


/*
 * backup_create_structs
 *
 * Allocate the structures before performing backup
 *
 * Parameters:
 *   sesison (input) - session handle
 *   jname (input) - backup job name
 *
 * Returns:
 *   0: on success
 *  -1: otherwise
 */
static int
backup_create_structs(ndmpd_session_t *session, char *jname)
{
	int n;
	long xfer_size;
	ndmp_lbr_params_t *nlp;
	tlm_commands_t *cmds;

	if ((nlp = ndmp_get_nlp(session)) == NULL) {
		NDMP_LOG(LOG_DEBUG, "nlp == NULL");
		return (-1);
	}

	if ((nlp->nlp_jstat = tlm_new_job_stats(jname)) == NULL) {
		NDMP_LOG(LOG_DEBUG, "Creating job stats");
		return (-1);
	}

	cmds = &nlp->nlp_cmds;
	(void) memset(cmds, 0, sizeof (*cmds));

	xfer_size = ndmp_buffer_get_size(session);
	if (xfer_size < 512*KILOBYTE) {
		/*
		 * Read multiple of mover_record_size near to 512K.  This
		 * will prevent the data being copied in the mover buffer
		 * when we write the data.
		 */
		if ((n = (512 * KILOBYTE/xfer_size)) <= 0)
			n = 1;
		xfer_size *= n;
		NDMP_LOG(LOG_DEBUG, "Adjusted read size: %d", xfer_size);
	}

	cmds->tcs_command = tlm_create_reader_writer_ipc(TRUE, xfer_size);
	if (cmds->tcs_command == NULL) {
		NDMP_LOG(LOG_DEBUG, "Error creating ipc buffers");
		tlm_un_ref_job_stats(jname);
		return (-1);
	}

	nlp->nlp_logcallbacks = lbrlog_callbacks_init(session,
	    ndmpd_file_history_path,
	    ndmpd_file_history_dir,
	    ndmpd_file_history_node);
	if (nlp->nlp_logcallbacks == NULL) {
		tlm_release_reader_writer_ipc(cmds->tcs_command);
		tlm_un_ref_job_stats(jname);
		return (-1);
	}
	nlp->nlp_jstat->js_callbacks = (void *)(nlp->nlp_logcallbacks);

	return (0);
}


/*
 * restore_create_structs
 *
 * Allocate structures for performing a restore
 *
 * Parameters:
 *   sesison (input) - session handle
 *   jname (input) - backup job name
 *
 * Returns:
 *   0: on success
 *  -1: otherwise
 */
static int
restore_create_structs(ndmpd_session_t *session, char *jname)
{
	int i;
	long xfer_size;
	ndmp_lbr_params_t *nlp;
	tlm_commands_t *cmds;

	if ((nlp = ndmp_get_nlp(session)) == NULL) {
		NDMP_LOG(LOG_DEBUG, "nlp == NULL");
		return (-1);
	}
	if ((nlp->nlp_jstat = tlm_new_job_stats(jname)) == NULL) {
		NDMP_LOG(LOG_DEBUG, "Creating job stats");
		return (-1);
	}

	cmds = &nlp->nlp_cmds;
	(void) memset(cmds, 0, sizeof (*cmds));

	xfer_size = ndmp_buffer_get_size(session);
	cmds->tcs_command = tlm_create_reader_writer_ipc(FALSE, xfer_size);
	if (cmds->tcs_command == NULL) {
		NDMP_LOG(LOG_DEBUG, "Error creating ipc buffers");
		tlm_un_ref_job_stats(jname);
		return (-1);
	}

	nlp->nlp_logcallbacks = lbrlog_callbacks_init(session,
	    ndmpd_path_restored, NULL, NULL);
	if (nlp->nlp_logcallbacks == NULL) {
		tlm_release_reader_writer_ipc(cmds->tcs_command);
		tlm_un_ref_job_stats(jname);
		return (-1);
	}
	nlp->nlp_jstat->js_callbacks = (void *)(nlp->nlp_logcallbacks);

	nlp->nlp_restored = ndmp_malloc(sizeof (boolean_t) * nlp->nlp_nfiles);
	if (nlp->nlp_restored == NULL) {
		lbrlog_callbacks_done(nlp->nlp_logcallbacks);
		tlm_release_reader_writer_ipc(cmds->tcs_command);
		tlm_un_ref_job_stats(jname);
		return (-1);
	}
	for (i = 0; i < (int)nlp->nlp_nfiles; i++)
		nlp->nlp_restored[i] = FALSE;

	return (0);
}


/*
 * send_unrecovered_list
 *
 * Creates a list of restored files
 *
 * Parameters:
 *   params (input) - NDMP parameters
 *   nlp (input) - NDMP/LBR parameters
 *
 * Returns:
 *   0: on success
 *  -1: otherwise
 */
static int
send_unrecovered_list(ndmpd_module_params_t *params, ndmp_lbr_params_t *nlp)
{
	int i, rv;
	ndmp_name *ent;

	if (params == NULL) {
		NDMP_LOG(LOG_DEBUG, "params == NULL");
		return (-1);
	}
	if (nlp == NULL) {
		NDMP_LOG(LOG_DEBUG, "nlp == NULL");
		return (-1);
	}

	rv = 0;
	for (i = 0; i < (int)nlp->nlp_nfiles; i++) {
		NDMP_LOG(LOG_DEBUG, "nlp->nlp_restored[%d]: %s", i,
		    nlp->nlp_restored[i] ? "TRUE" : "FALSE");

		if (!nlp->nlp_restored[i]) {
			ent = (ndmp_name *)MOD_GETNAME(params, i);
			if (ent == NULL) {
				NDMP_LOG(LOG_DEBUG, "ent == NULL");
				rv = -1;
				break;
			}
			if (ent->name == NULL) {
				NDMP_LOG(LOG_DEBUG, "ent->name == NULL");
				rv = -1;
				break;
			}

			NDMP_LOG(LOG_DEBUG, "ent.name: \"%s\"", ent->name);

			rv = MOD_FILERECOVERD(params, ent->name, ENOENT);
			if (rv < 0)
				break;
		}
	}

	return (rv);
}


/*
 * backup_release_structs
 *
 * Deallocated the NDMP/LBR specific parameters
 *
 * Parameters:
 *   session (input) - session handle
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
static void
backup_release_structs(ndmpd_session_t *session)
{
	ndmp_lbr_params_t *nlp;
	tlm_commands_t *cmds;

	if ((nlp = ndmp_get_nlp(session)) == NULL) {
		NDMP_LOG(LOG_DEBUG, "nlp == NULL");
		return;
	}
	cmds = &nlp->nlp_cmds;
	if (cmds == NULL) {
		NDMP_LOG(LOG_DEBUG, "cmds == NULL");
		return;
	}

	if (nlp->nlp_logcallbacks != NULL) {
		lbrlog_callbacks_done(nlp->nlp_logcallbacks);
		nlp->nlp_logcallbacks = NULL;
	} else {
		NDMP_LOG(LOG_DEBUG, "FH CALLBACKS == NULL");
	}

	if (cmds->tcs_command != NULL) {
		if (cmds->tcs_command->tc_buffers != NULL)
			tlm_release_reader_writer_ipc(cmds->tcs_command);
		else
			NDMP_LOG(LOG_DEBUG, "BUFFERS == NULL");
		cmds->tcs_command = NULL;
	} else {
		NDMP_LOG(LOG_DEBUG, "COMMAND == NULL");
	}

	if (nlp->nlp_bkmap >= 0) {
		(void) dbm_free(nlp->nlp_bkmap);
		nlp->nlp_bkmap = -1;
	}

	if (session->ns_data.dd_operation == NDMP_DATA_OP_RECOVER &&
	    nlp->nlp_restored != NULL) {
		free(nlp->nlp_restored);
		nlp->nlp_restored = NULL;
	} else {
		NDMP_LOG(LOG_DEBUG, "nlp_restored == NULL");
	}
}

/*
 * ndmp_write_utf8magic
 *
 * Write a magic pattern to the tar header. This is used
 * as a crest to indicate that tape belongs to us.
 */
int
ndmp_write_utf8magic(tlm_cmd_t *cmd)
{
	char *cp;
	long actual_size;

	if (cmd->tc_buffers == NULL) {
		NDMP_LOG(LOG_DEBUG, "cmd->tc_buffers == NULL");
		return (-1);
	}

	cp = tlm_get_write_buffer(RECORDSIZE, &actual_size,
	    cmd->tc_buffers, TRUE);
	if (actual_size < RECORDSIZE) {
		NDMP_LOG(LOG_DEBUG, "Couldn't get enough buffer");
		return (-1);
	}

	(void) strlcpy(cp, NDMPUTF8MAGIC, RECORDSIZE);
	return (0);
}


/*
 * timecmp
 *
 * This callback function is used during backup.  It checks
 * if the object specified by the 'attr' should be backed
 * up or not.
 *
 * Directories are backed up anyways for dump format.
 * If this function is called, then the directory is
 * marked in the bitmap vector, it shows that either the
 * directory itself is modified or there is something below
 * it that will be backed up.
 *
 * Directories for tar format are backed up if and only if
 * they are modified.
 *
 * By setting ndmp_force_bk_dirs global variable to a non-zero
 * value, directories are backed up anyways.
 *
 * Backing up the directories unconditionally, helps
 * restoring the metadata of directories as well, when one
 * of the objects below them are being restored.
 *
 * For non-directory objects, if the modification or change
 * time of the object is after the date specified by the
 * bk_selector_t, the the object must be backed up.
 *
 */
static boolean_t
timecmp(bk_selector_t *bksp,
		struct stat64 *attr)
{
	ndmp_lbr_params_t *nlp;

	nlp = (ndmp_lbr_params_t *)bksp->bs_cookie;
	if (S_ISDIR(attr->st_mode) && ndmp_force_bk_dirs) {
		NDMP_LOG(LOG_DEBUG, "d(%lu)",
		    (uint_t)attr->st_ino);
		return (TRUE);
	}
	if (S_ISDIR(attr->st_mode) &&
	    dbm_getone(nlp->nlp_bkmap, (u_longlong_t)attr->st_ino) &&
	    ((NLP_ISDUMP(nlp) && ndmp_dump_path_node) ||
	    (NLP_ISTAR(nlp) && ndmp_tar_path_node))) {
		/*
		 * If the object is a directory and it leads to a modified
		 * object (that should be backed up) and for that type of
		 * backup the path nodes should be backed up, then return
		 * TRUE.
		 *
		 * This is required by some DMAs like Backup Express, which
		 * needs to receive ADD_NODE (for dump) or ADD_PATH (for tar)
		 * for the intermediate directories of a modified object.
		 * Other DMAs, like net_backup and net_worker, do not have such
		 * requirement.  This requirement makes sense for dump format
		 * but for 'tar' format, it does not.  In provision to the
		 * NDMP-v4 spec, for 'tar' format the intermediate directories
		 * need not to be reported.
		 */
		NDMP_LOG(LOG_DEBUG, "p(%lu)", (u_longlong_t)attr->st_ino);
		return (TRUE);
	}
	if (attr->st_mtime > bksp->bs_ldate) {
		NDMP_LOG(LOG_DEBUG, "m(%lu): %lu > %lu",
		    (uint_t)attr->st_ino, (uint_t)attr->st_mtime,
		    (uint_t)bksp->bs_ldate);
		return (TRUE);
	}
	if (attr->st_ctime > bksp->bs_ldate) {
		if (NLP_IGNCTIME(nlp)) {
			NDMP_LOG(LOG_DEBUG, "ign c(%lu): %lu > %lu",
			    (uint_t)attr->st_ino, (uint_t)attr->st_ctime,
			    (uint_t)bksp->bs_ldate);
			return (FALSE);
		}
		NDMP_LOG(LOG_DEBUG, "c(%lu): %lu > %lu",
		    (uint_t)attr->st_ino, (uint_t)attr->st_ctime,
		    (uint_t)bksp->bs_ldate);
		return (TRUE);
	}
	NDMP_LOG(LOG_DEBUG, "mc(%lu): (%lu,%lu) < %lu",
	    (uint_t)attr->st_ino, (uint_t)attr->st_mtime,
	    (uint_t)attr->st_ctime, (uint_t)bksp->bs_ldate);
	return (FALSE);
}


/*
 * get_acl_info
 *
 * load up all the access and attribute info
 */
static int
get_acl_info(char *name, tlm_acls_t *tlm_acls)
{
	int erc;
	acl_t *aclp = NULL;
	char *acltp;

	erc = lstat64(name, &tlm_acls->acl_attr);
	if (erc != 0) {
		NDMP_LOG(LOG_ERR, "Could not find file %s.", name);
		erc = TLM_NO_SOURCE_FILE;
		return (erc);
	}
	erc = acl_get(name, ACL_NO_TRIVIAL, &aclp);
	if (erc != 0) {
		NDMP_LOG(LOG_DEBUG,
		    "Could not read ACL for file [%s]", name);
		erc = TLM_NO_SOURCE_FILE;
		return (erc);
	}
	if (aclp && (acltp = acl_totext(aclp,
	    ACL_APPEND_ID | ACL_SID_FMT | ACL_COMPACT_FMT)) != NULL) {
		(void) strlcpy(tlm_acls->acl_info.attr_info, acltp,
		    TLM_MAX_ACL_TXT);
		acl_free(aclp);
		free(acltp);
	}
	return (erc);
}
/*
 * get_dir_acl_info
 *
 * load up all ACL and attr info about a directory
 */
static int
get_dir_acl_info(char *dir, tlm_acls_t *tlm_acls, tlm_job_stats_t *js)
{
	int	erc;
	char	*checkpointed_dir;
	char	root_dir[TLM_VOLNAME_MAX_LENGTH];
	char	*spot;
	char	*fil;
	acl_t	*aclp = NULL;
	char 	*acltp;

	checkpointed_dir = ndmp_malloc(TLM_MAX_PATH_NAME);
	if (checkpointed_dir == NULL)
		return (-1);

	if (tlm_acls->acl_checkpointed)
		fil = tlm_build_snapshot_name(dir, checkpointed_dir,
		    js->js_job_name);
	else
		fil = dir;
	erc = lstat64(fil, &tlm_acls->acl_attr);
	if (erc != 0) {
		NDMP_LOG(LOG_ERR, "Could not find directory %s.", dir);
		free(checkpointed_dir);
		return (-1);
	}

	spot = strchr(&fil[1], '/');
	if (spot == NULL) {
		(void) strlcpy(root_dir, fil, TLM_VOLNAME_MAX_LENGTH);
	} else {
		*spot = 0;
		(void) strlcpy(root_dir, fil, TLM_VOLNAME_MAX_LENGTH);
		*spot = '/';
	}
	if (strcmp(root_dir, tlm_acls->acl_root_dir) != 0) {
		struct stat64 attr;

		erc = lstat64(root_dir, &attr);
		if (erc != 0) {
			NDMP_LOG(LOG_ERR, "Cannot find root directory %s.",
			    root_dir);
			free(checkpointed_dir);
			return (-1);
		}
		(void) strlcpy(tlm_acls->acl_root_dir, root_dir,
		    TLM_VOLNAME_MAX_LENGTH);
	}
	erc = acl_get(fil, ACL_NO_TRIVIAL, &aclp);
	if (erc != 0) {
		NDMP_LOG(LOG_DEBUG,
		    "Could not read metadata for directory [%s]", dir);
		free(checkpointed_dir);
		return (-1);
	}
	if (aclp && (acltp = acl_totext(aclp,
	    ACL_APPEND_ID | ACL_SID_FMT | ACL_COMPACT_FMT)) != NULL) {
		(void) strlcpy(tlm_acls->acl_info.attr_info, acltp,
		    TLM_MAX_ACL_TXT);
		acl_free(aclp);
		free(acltp);
	}

	free(checkpointed_dir);
	return (0);
}

/*
 * backup_dir
 *
 * Create a TAR entry record for a directory
 */
static int
backup_dir(char *dir, tlm_acls_t *tlm_acls,
    tlm_cmd_t *local_commands, tlm_job_stats_t *job_stats,
    bk_selector_t *bksp)
{
	int erc;

	NDMP_LOG(LOG_DEBUG, "\"%s\"", dir);

	erc = get_dir_acl_info(dir, tlm_acls, job_stats);
	if (erc != 0) {
		NDMP_LOG(LOG_DEBUG,
		    "Could not read directory info for %s", dir);
		job_stats->js_errors++;
	} else {
		/*
		 * See if the directory must be backed up.
		 */
		if (bksp && !(*bksp->bs_fn)(bksp, &tlm_acls->acl_attr)) {
			NDMP_LOG(LOG_DEBUG, "[%s] dir skipped", dir);
			return (erc);
		}

		if (tm_tar_ops.tm_putdir != NULL)
			(void) (tm_tar_ops.tm_putdir)(dir, tlm_acls,
			    local_commands, job_stats);
	}

	return (erc);
}


/*
 * backup_file
 *
 * Create a TAR record entry for a file
 */
static longlong_t
backup_file(char *dir, char *name, tlm_acls_t *tlm_acls,
    tlm_commands_t *commands, tlm_cmd_t *local_commands,
    tlm_job_stats_t *job_stats, bk_selector_t *bksp)
{

	int erc;
	char buf[TLM_MAX_PATH_NAME];
	longlong_t rv;

	NDMP_LOG(LOG_DEBUG, "\"%s/%s\"", dir, name);

	(void) strlcpy(buf, dir, sizeof (buf));
	(void) strlcat(buf, "/", sizeof (buf));
	(void) strlcat(buf, name, sizeof (buf));

	/*
	 * get_acl_info extracts file handle, attributes and ACLs of the file.
	 * This is not efficient when the attributes and file handle of
	 * the file is already known.
	 */
	erc = get_acl_info(buf, tlm_acls);
	if (erc != TLM_NO_ERRORS) {
		NDMP_LOG(LOG_ERR, "Could not open file %s/%s.", dir, name);
		return (-ENOENT);
	}

	/* Should the file be backed up? */
	if (!bksp) {
		NDMP_LOG(LOG_DEBUG,
		    "[%s/%s] has no selection criteria", dir, name);

	} else if (!((*bksp->bs_fn)(bksp, &tlm_acls->acl_attr))) {
		NDMP_LOG(LOG_DEBUG, "[%s/%s] file skipped", dir, name);
		return (0);
	}

	/* Only the regular files and symbolic links can be backed up. */
	if (!S_ISLNK(tlm_acls->acl_attr.st_mode) &&
	    !S_ISREG(tlm_acls->acl_attr.st_mode)) {
		NDMP_LOG(LOG_DEBUG,
		    "Warning: skip backing up [%s][%s]", dir, name);
		return (-EINVAL);
	}


	if (tm_tar_ops.tm_putfile != NULL)
		rv = (tm_tar_ops.tm_putfile)(dir, name, tlm_acls, commands,
		    local_commands, job_stats);

	return (rv);
}



/*
 * backup_work
 *
 * Start the NDMP backup (V2 only).
 */
int
backup_work(char *bk_path, tlm_job_stats_t *job_stats,
    ndmp_run_args_t *np, tlm_commands_t *commands,
    ndmp_lbr_params_t *nlp)
{
	struct full_dir_info dir_info; /* the blob to push/pop with cstack_t */
	struct full_dir_info *t_dir_info, *p_dir_info;
	struct stat64 ret_attr; /* attributes of current file name */
	fs_fhandle_t ret_fh;
	char *first_name; /* where the first name is located */
	char *dname;
	int erc;
	int retval;
	cstack_t *stk;
	unsigned long fileid;
	tlm_acls_t tlm_acls;
	int dname_size;
	longlong_t fsize;
	bk_selector_t bks;
	tlm_cmd_t *local_commands;
	long 	dpos;

	NDMP_LOG(LOG_DEBUG, "nr_chkpnted %d nr_ldate: %u bk_path: \"%s\"",
	    NLP_ISCHKPNTED(nlp), nlp->nlp_ldate, bk_path);

	/* Get every name in this directory */
	dname = ndmp_malloc(TLM_MAX_PATH_NAME);
	if (dname == NULL)
		return (-ENOMEM);

	local_commands = commands->tcs_command;
	retval = 0;
	(void) memset(&bks, 0, sizeof (bks));
	bks.bs_cookie = (void *)nlp;
	bks.bs_level = nlp->nlp_clevel;
	bks.bs_ldate = nlp->nlp_ldate;
	bks.bs_fn = timecmp;

	/*
	 * should we skip the whole thing?
	 */
	if (tlm_is_excluded("", bk_path, np->nr_excls)) {
		NDMP_LOG(LOG_DEBUG, "%s excluded", bk_path);
		free(dname);
		return (0);
	}

	/*
	 * Search for the top-level file-directory
	 */
	if (NLP_ISCHKPNTED(nlp)) {
		first_name = np->nr_chkp_nm;
		(void) strlcpy(first_name, bk_path, TLM_MAX_PATH_NAME);
	} else {
		first_name = tlm_build_snapshot_name(bk_path, np->nr_chkp_nm,
		    nlp->nlp_jstat->js_job_name);
	}

	(void) memset(&ret_fh, 0, sizeof (ret_fh));
	erc = fs_getstat(first_name, &ret_fh, &ret_attr);
	if (erc != 0) {
		NDMP_LOG(LOG_ERR, "Path %s not found.", first_name);
		free(dname);
		return (-EINVAL);
	}

	if ((stk = cstack_new()) == NULL) {
		free(dname);
		NDMP_LOG(LOG_DEBUG, "cstack_new failed");
		return (-ENOMEM);
	}
	(void) strlcpy(dir_info.fd_dir_name, first_name, TLM_MAX_PATH_NAME);
	(void) memcpy(&dir_info.fd_dir_fh, &ret_fh, sizeof (fs_fhandle_t));
	p_dir_info = dup_dir_info(&dir_info);

	/*
	 * Push the first name onto the stack so that we can pop it back
	 * off as part of the normal cycle
	 */
	if (cstack_push(stk, p_dir_info, 0)) {
		free(dname);
		free(p_dir_info);
		cstack_delete(stk);
		NDMP_LOG(LOG_DEBUG, "cstack_push failed");
		return (-ENOMEM);
	}

	(void) memset(&tlm_acls, 0, sizeof (tlm_acls));
	/*
	 * Did NDMP create a checkpoint?
	 */
	if (NLP_ISCHKPNTED(nlp) || fs_is_rdonly(bk_path)) {
		tlm_acls.acl_checkpointed = FALSE;
	} else {
		/* Use the checkpoint created by NDMP */
		tlm_acls.acl_checkpointed = TRUE;
	}

	/*
	 * This is level-backup.  It never resets the archive bit.
	 */
	tlm_acls.acl_clear_archive = FALSE;

	NDMP_LOG(LOG_DEBUG, "acls.chkpnt: %c acls.clear_arcbit: %c",
	    NDMP_YORN(tlm_acls.acl_checkpointed),
	    NDMP_YORN(tlm_acls.acl_clear_archive));

	while (commands->tcs_reader == TLM_BACKUP_RUN &&
	    local_commands->tc_reader == TLM_BACKUP_RUN &&
	    cstack_pop(stk, (void **)&p_dir_info, 0) == 0) {

		if (NLP_ISCHKPNTED(nlp))
			(void) strlcpy(np->nr_unchkp_nm,
			    p_dir_info->fd_dir_name, TLM_MAX_PATH_NAME);
		else
			(void) tlm_remove_checkpoint(p_dir_info->fd_dir_name,
			    np->nr_unchkp_nm);

		(void) backup_dir(np->nr_unchkp_nm, &tlm_acls, local_commands,
		    job_stats, &bks);


		while (commands->tcs_reader == TLM_BACKUP_RUN &&
		    local_commands->tc_reader == TLM_BACKUP_RUN) {

			dname_size = TLM_MAX_PATH_NAME - 1;

			NDMP_LOG(LOG_DEBUG,
			    "dir_name: %s", p_dir_info->fd_dir_name);

			(void) memset(&ret_fh, 0, sizeof (ret_fh));
			erc = fs_readdir(&p_dir_info->fd_dir_fh,
			    p_dir_info->fd_dir_name, &dpos,
			    dname, &dname_size, &ret_fh, &ret_attr);
			if (erc == 0) {
				fileid = ret_fh.fh_fid;
			} else {
				NDMP_LOG(LOG_DEBUG,
				    "Filesystem readdir in [%s]",
				    p_dir_info->fd_dir_name);
				retval = -ENOENT;
				break;
			}

			/* an empty name size marks the end of the list */
			if (dname_size == 0)
				break;
			dname[dname_size] = '\0';

			NDMP_LOG(LOG_DEBUG, "dname: \"%s\"", dname);

			/*
			 * If name refers to a directory, push its file
			 *   handle onto the stack  (skip "." and "..").
			 */
			if (rootfs_dot_or_dotdot(dname)) {
				fileid = 0;
				continue;
			}

			/*
			 * Skip the:
			 * non-dir entries which should not be backed up
			 * Or
			 * dir-type entries which have have nothing under
			 * their hierarchy to be backed up.
			 */
			if (!dbm_getone(nlp->nlp_bkmap, (u_longlong_t)fileid)) {
				NDMP_LOG(LOG_DEBUG, "Skipping %s/%s",
				    p_dir_info->fd_dir_name, dname);
				fileid = 0;
				continue;
			}

			if (tlm_is_excluded(np->nr_unchkp_nm, dname,
			    np->nr_excls)) {
				fileid = 0;
				continue;
			}
			if (S_ISDIR(ret_attr.st_mode)) {
				/*
				 * only directories get pushed onto this stack,
				 * so we do not have to test for regular files.
				 */
				t_dir_info = tlm_new_dir_info(&ret_fh,
				    p_dir_info->fd_dir_name, dname);
				if (t_dir_info == NULL) {
					NDMP_LOG(LOG_DEBUG,
					    "While backing up [%s][%s]",
					    p_dir_info->fd_dir_name, dname);
				} else if (cstack_push(stk, t_dir_info,
				    0) != 0) {
					NDMP_LOG(LOG_DEBUG,
					    "No enough memory stack_push");
					retval = -ENOMEM;
					break;
				}
			} else if (S_ISREG(ret_attr.st_mode) ||
			    S_ISLNK(ret_attr.st_mode)) {

				fsize = backup_file(np->nr_unchkp_nm, dname,
				    &tlm_acls, commands, local_commands,
				    job_stats, &bks);

				if (fsize >= 0) {
					job_stats->js_files_so_far++;
					job_stats->js_bytes_total += fsize;
				} else
					job_stats->js_errors++;
				fileid = 0;
			}
		}
		fileid = 0;
		free(p_dir_info);
		if (retval != 0)
			break;
	}

	free(dname);

	while (cstack_pop(stk, (void **)&p_dir_info, 0) == 0) {
		free(p_dir_info);
	}

	cstack_delete(stk);
	return (retval);
}


/*
 * free_paths
 *
 * Free the path names
 */
static void
free_paths(ndmp_run_args_t *np)
{
	free(np->nr_chkp_nm);
	free(np->nr_unchkp_nm);
	free(np->nr_excls);
}


/*
 * malloc_paths
 *
 * Allocate the path names (direct and checkpointed paths)
 */
static boolean_t
malloc_paths(ndmp_run_args_t *np)
{
	boolean_t rv;

	rv = TRUE;
	np->nr_chkp_nm = ndmp_malloc(TLM_MAX_PATH_NAME);
	np->nr_unchkp_nm = ndmp_malloc(TLM_MAX_PATH_NAME);
	if (!np->nr_chkp_nm || !np->nr_unchkp_nm) {
		free_paths(np);
		rv = FALSE;
	} else if ((np->nr_excls = ndmpd_make_exc_list()) == NULL) {
		free_paths(np);
		rv = FALSE;
	}
	return (rv);
}


/*
 * ndmp_backup_reader
 *
 * Backup reader thread which uses backup_work to read and TAR
 * the files/dirs to be backed up (V2 only)
 */
static int
ndmp_backup_reader(tlm_commands_t *commands, ndmp_lbr_params_t *nlp,
    char *job_name)
{
	int retval;
	ndmp_run_args_t np;
	tlm_job_stats_t *job_stats;
	tlm_cmd_t *local_commands;

	NDMP_LOG(LOG_DEBUG, "bk_path: \"%s\"", nlp->nlp_backup_path);

	local_commands = commands->tcs_command;
	(void) memset(&np, 0, sizeof (np));
	if (!malloc_paths(&np))
		return (-1);
	local_commands->tc_ref++;
	commands->tcs_reader_count++;

	job_stats = tlm_ref_job_stats(job_name);

	retval = backup_work(nlp->nlp_backup_path, job_stats, &np,
	    commands, nlp);
	write_tar_eof(local_commands);

	commands->tcs_reader_count--;
	local_commands->tc_writer = TLM_STOP;
	tlm_release_reader_writer_ipc(local_commands);
	tlm_un_ref_job_stats(job_name);

	free_paths(&np);
	return (retval);

}


/*
 * ndmp_tar_writer
 *
 * The backup writer thread that writes the TAR records to the
 * tape media (V2 only)
 */
int
ndmp_tar_writer(ndmpd_session_t *session, ndmpd_module_params_t *mod_params,
    tlm_commands_t *cmds)
{
	int bidx, nw;
	int err;
	tlm_buffer_t *buf;
	tlm_buffers_t *bufs;
	tlm_cmd_t *lcmd;	/* Local command */

	err = 0;
	if (session == NULL) {
		NDMP_LOG(LOG_DEBUG, "session == NULL");
		err = -1;
	} else if (mod_params == NULL) {
		NDMP_LOG(LOG_DEBUG, "mod_params == NULL");
		err = -1;
	} else if (cmds == NULL) {
		NDMP_LOG(LOG_DEBUG, "cmds == NULL");
		err = -1;
	}

	if (err != 0)
		return (err);

	lcmd = cmds->tcs_command;
	bufs = lcmd->tc_buffers;

	lcmd->tc_ref++;
	cmds->tcs_writer_count++;

	nw = 0;
	buf = tlm_buffer_out_buf(bufs, &bidx);
	while (cmds->tcs_writer != (int)TLM_ABORT &&
	    lcmd->tc_writer != (int)TLM_ABORT) {
		if (buf->tb_full) {
			NDMP_LOG(LOG_DEBUG, "w%d", bidx);

			if (MOD_WRITE(mod_params, buf->tb_buffer_data,
			    buf->tb_buffer_size) != 0) {
				NDMP_LOG(LOG_DEBUG,
				    "Writing buffer %d, pos: %lld",
				    bidx, session->ns_mover.md_position);
				err = -1;
				break;
			}

			tlm_buffer_mark_empty(buf);
			(void) tlm_buffer_advance_out_idx(bufs);
			buf = tlm_buffer_out_buf(bufs, &bidx);
			tlm_buffer_release_out_buf(bufs);
			nw++;
		} else {
			if (lcmd->tc_writer != TLM_BACKUP_RUN) {
				/* No more data is comming; time to exit. */
				NDMP_LOG(LOG_DEBUG,
				    "tc_writer!=TLM_BACKUP_RUN; time to exit");
				break;
			} else {
				NDMP_LOG(LOG_DEBUG, "W%d", bidx);
				tlm_buffer_in_buf_timed_wait(bufs, 100);
			}
		}
	}

	NDMP_LOG(LOG_DEBUG, "nw: %d", nw);
	if (cmds->tcs_writer != (int)TLM_ABORT) {
		NDMP_LOG(LOG_DEBUG, "tcs_writer != TLM_ABORT");
	} else {
		NDMP_LOG(LOG_DEBUG, "tcs_writer == TLM_ABORT");
	}

	if (lcmd->tc_writer != (int)TLM_ABORT) {
		NDMP_LOG(LOG_DEBUG, "tc_writer != TLM_ABORT");
	} else {
		NDMP_LOG(LOG_DEBUG, "tc_writer == TLM_ABORT");
	}
	cmds->tcs_writer_count--;
	lcmd->tc_reader = TLM_STOP;
	lcmd->tc_ref--;

	return (err);
}


/*
 * read_one_buf
 *
 * Read one buffer from the tape
 */
static int
read_one_buf(ndmpd_module_params_t *mod_params, tlm_buffers_t *bufs,
    tlm_buffer_t *buf)
{
	int rv;

	if ((rv = MOD_READ(mod_params, buf->tb_buffer_data,
	    bufs->tbs_data_transfer_size)) == 0) {
		buf->tb_eof = buf->tb_eot = FALSE;
		buf->tb_errno = 0;
		buf->tb_buffer_size = bufs->tbs_data_transfer_size;
		buf->tb_buffer_spot = 0;
		buf->tb_full = TRUE;
		(void) tlm_buffer_advance_in_idx(bufs);
	}

	return (rv);
}


/*
 * ndmp_tar_reader
 *
 * NDMP Tar reader thread. This threads keep reading the tar
 * file from the tape and wakes up the consumer thread to extract
 * it on the disk
 */
int
ndmp_tar_reader(ndmp_tar_reader_arg_t *argp)
{
	int bidx;
	int err;
	tlm_buffer_t *buf;
	tlm_buffers_t *bufs;
	tlm_cmd_t *lcmd;	/* Local command */
	ndmpd_session_t *session;
	ndmpd_module_params_t *mod_params;
	tlm_commands_t *cmds;

	if (!argp)
		return (-1);

	session = argp->tr_session;
	mod_params = argp->tr_mod_params;
	cmds = argp->tr_cmds;

	err = 0;
	if (session == NULL) {
		NDMP_LOG(LOG_DEBUG, "session == NULL");
		err = -1;
	} else if (cmds == NULL) {
		NDMP_LOG(LOG_DEBUG, "cmds == NULL");
		err = -1;
	}

	if (err != 0) {
		tlm_cmd_signal(cmds->tcs_command, TLM_TAR_READER);
		return (err);
	}

	lcmd = cmds->tcs_command;
	bufs = lcmd->tc_buffers;

	lcmd->tc_ref++;
	cmds->tcs_reader_count++;

	/*
	 * Synchronize with our parent thread.
	 */
	tlm_cmd_signal(cmds->tcs_command, TLM_TAR_READER);

	buf = tlm_buffer_in_buf(bufs, &bidx);
	while (cmds->tcs_reader == TLM_RESTORE_RUN &&
	    lcmd->tc_reader == TLM_RESTORE_RUN) {

		if (buf->tb_full) {
			NDMP_LOG(LOG_DEBUG, "R%d", bidx);
			/*
			 * The buffer is still full, wait for the consumer
			 * thread to use it.
			 */
			tlm_buffer_out_buf_timed_wait(bufs, 100);
			buf = tlm_buffer_in_buf(bufs, NULL);
		} else {
			NDMP_LOG(LOG_DEBUG, "r%d", bidx);

			err = read_one_buf(mod_params, bufs, buf);
			if (err < 0) {
				NDMP_LOG(LOG_DEBUG,
				    "Reading buffer %d, pos: %lld",
				    bidx, session->ns_mover.md_position);

				/* Force the writer to stop. */
				buf->tb_eot = buf->tb_eof = TRUE;
				break;
			} else if (err == 1) {
				NDMP_LOG(LOG_DEBUG,
				    "operation aborted or session terminated");
				err = 0;
				break;
			}

			buf = tlm_buffer_in_buf(bufs, &bidx);
			tlm_buffer_release_in_buf(bufs);
		}
	}

	/*
	 * If the consumer is waiting for us, wake it up so that it detects
	 * we're quiting.
	 */
	lcmd->tc_writer = TLM_STOP;
	tlm_buffer_release_in_buf(bufs);
	(void) usleep(1000);

	/*
	 * Clean up.
	 */
	cmds->tcs_reader_count--;
	lcmd->tc_ref--;
	return (err);
}


/*
 * ndmpd_tar_backup
 *
 * Check must have been done that backup work directory exists, before
 * calling this function.
 */
static int
ndmpd_tar_backup(ndmpd_session_t *session, ndmpd_module_params_t *mod_params,
    ndmp_lbr_params_t *nlp)
{
	char jname[TLM_MAX_BACKUP_JOB_NAME];
	int err;
	tlm_commands_t *cmds;

	if (mod_params->mp_operation != NDMP_DATA_OP_BACKUP) {
		NDMP_LOG(LOG_DEBUG,
		    "mod_params->mp_operation != NDMP_DATA_OP_BACKUP");
		err = -1;
	} else {
		if (ndmpd_mark_inodes_v2(session, nlp) != 0)
			err = -1;
		else if (ndmp_get_bk_dir_ino(nlp))
			err = -1;
		else
			err = 0;
	}

	if (err != 0)
		return (err);

	(void) ndmp_new_job_name(jname);
	if (backup_create_structs(session, jname) < 0)
		return (-1);

	nlp->nlp_jstat->js_start_ltime = time(NULL);
	nlp->nlp_jstat->js_start_time = nlp->nlp_jstat->js_start_ltime;
	nlp->nlp_jstat->js_chkpnt_time = nlp->nlp_cdate;

	if (!session->ns_data.dd_abort) {

		cmds = &nlp->nlp_cmds;
		cmds->tcs_reader = cmds->tcs_writer = TLM_BACKUP_RUN;
		cmds->tcs_command->tc_reader = TLM_BACKUP_RUN;
		cmds->tcs_command->tc_writer = TLM_BACKUP_RUN;

		if (ndmp_write_utf8magic(cmds->tcs_command) < 0) {
			backup_release_structs(session);
			return (-1);
		}

		NDMP_LOG(LOG_DEBUG, "Backing up \"%s\" started.",
		    nlp->nlp_backup_path);

		err = ndmp_backup_reader(cmds, nlp, jname);
		if (err != 0) {
			backup_release_structs(session);
			NDMP_LOG(LOG_DEBUG, "Launch ndmp_backup_reader: %s",
			    strerror(err));
			return (-1);
		}

		/* Act as the writer thread. */
		err = ndmp_tar_writer(session, mod_params, cmds);

		nlp->nlp_jstat->js_stop_time = time(NULL);

		NDMP_LOG(LOG_DEBUG,
		    "Runtime [%s] %llu bytes (%llu): %d seconds",
		    nlp->nlp_backup_path, session->ns_mover.md_data_written,
		    session->ns_mover.md_data_written,
		    nlp->nlp_jstat->js_stop_time -
		    nlp->nlp_jstat->js_start_ltime);
		MOD_LOG(mod_params,
		    "Runtime [%s] %llu bytes (%llu): %d seconds",
		    nlp->nlp_backup_path, session->ns_mover.md_data_written,
		    session->ns_mover.md_data_written,
		    nlp->nlp_jstat->js_stop_time -
		    nlp->nlp_jstat->js_start_ltime);

		if (session->ns_data.dd_abort)
			err = -1;

		NDMP_LOG(LOG_DEBUG, "Backing up \"%s\" finished. (%d)",
		    nlp->nlp_backup_path, err);
	} else {
		nlp->nlp_jstat->js_stop_time = time(NULL);
		NDMP_LOG(LOG_DEBUG, "Backing up \"%s\" aborted.",
		    nlp->nlp_backup_path);
		err = 0;
	}

	backup_release_structs(session);
	return (err);
}


/*
 * ndmpd_tar_restore
 *
 * Restore function that launches TAR reader thread to read from the
 * tape and writes the extracted files/dirs to the filesystem
 */
static int
ndmpd_tar_restore(ndmpd_session_t *session, ndmpd_module_params_t *mod_params,
    ndmp_lbr_params_t *nlp)
{
	char jname[TLM_MAX_BACKUP_JOB_NAME];
	char *rspath;
	int err;
	tlm_commands_t *cmds;
	ndmp_tar_reader_arg_t arg;
	tlm_backup_restore_arg_t tlm_arg;
	ndmp_name *ent;
	pthread_t rdtp, wrtp;
	int i;

	if (mod_params->mp_operation != NDMP_DATA_OP_RECOVER) {
		NDMP_LOG(LOG_DEBUG,
		    "mod_params->mp_operation != NDMP_DATA_OP_RECOVER");
		return (-1);
	}

	if (nlp->nlp_restore_path[0] != '\0')
		rspath = nlp->nlp_restore_path;
	else if (nlp->nlp_restore_bk_path[0] != '\0')
		rspath = nlp->nlp_restore_bk_path;
	else
		rspath = "";

	(void) ndmp_new_job_name(jname);
	if (restore_create_structs(session, jname) < 0)
		return (-1);

	nlp->nlp_jstat->js_start_ltime = time(NULL);
	nlp->nlp_jstat->js_start_time = time(NULL);

	if (!session->ns_data.dd_abort) {
		cmds = &nlp->nlp_cmds;
		cmds->tcs_reader = cmds->tcs_writer = TLM_RESTORE_RUN;
		cmds->tcs_command->tc_reader = TLM_RESTORE_RUN;
		cmds->tcs_command->tc_writer = TLM_RESTORE_RUN;

		NDMP_LOG(LOG_DEBUG, "Restoring to \"%s\" started.", rspath);
		NDMP_LOG(LOG_DEBUG, "Restoring from %s tape(s).",
		    ndmp_data_get_mover_mode(session));

		arg.tr_session = session;
		arg.tr_mod_params = mod_params;
		arg.tr_cmds = cmds;

		err = pthread_create(&rdtp, NULL, (funct_t)ndmp_tar_reader,
		    (void *)&arg);
		if (err == 0) {
			tlm_cmd_wait(cmds->tcs_command, TLM_TAR_READER);
		} else {
			NDMP_LOG(LOG_DEBUG, "Launch ndmp_tar_reader: %m");
			return (-1);
		}

		if (!ndmp_check_utf8magic(cmds->tcs_command)) {
			NDMP_LOG(LOG_DEBUG, "UTF8Magic not found!");
		} else {
			NDMP_LOG(LOG_DEBUG, "UTF8Magic found");
		}

		(void) memset(&tlm_arg, 0, sizeof (tlm_backup_restore_arg_t));
		(void) pthread_barrier_init(&tlm_arg.ba_barrier, 0, 2);

		/*
		 * Set up restore parameters
		 */
		tlm_arg.ba_commands = cmds;
		tlm_arg.ba_cmd = cmds->tcs_command;
		tlm_arg.ba_job = nlp->nlp_jstat->js_job_name;
		tlm_arg.ba_dir = nlp->nlp_restore_path;
		for (i = 0; i < nlp->nlp_nfiles; i++) {
			ent = (ndmp_name *)MOD_GETNAME(mod_params, i);
			tlm_arg.ba_sels[i] = ent->name;
		}


		if (tm_tar_ops.tm_getfile != NULL) {
			err = pthread_create(&wrtp, NULL,
			    (funct_t)tm_tar_ops.tm_getfile, (void *)&tlm_arg);
		} else {
			(void) pthread_barrier_destroy(&tlm_arg.ba_barrier);
			NDMP_LOG(LOG_DEBUG,
			    "Thread create tm_getfile: ops NULL");
			return (-1);
		}
		if (err == 0) {
			(void) pthread_barrier_wait(&tlm_arg.ba_barrier);
		} else {
			(void) pthread_barrier_destroy(&tlm_arg.ba_barrier);
			NDMP_LOG(LOG_DEBUG, "thread create tm_getfile: %m");
			return (-1);
		}

		(void) pthread_join(rdtp, NULL);
		(void) pthread_join(wrtp, NULL);
		(void) pthread_barrier_destroy(&tlm_arg.ba_barrier);

		nlp->nlp_jstat->js_stop_time = time(NULL);

		/* Send the list of un-recovered files/dirs to the client.  */
		(void) send_unrecovered_list(mod_params, nlp);

		ndmp_stop_local_reader(session, cmds);
		ndmp_wait_for_reader(cmds);
		ndmp_stop_remote_reader(session);
		NDMP_LOG(LOG_DEBUG, "Restoring to \"%s\" finished. (%d)",
		    rspath, err);
	} else {
		nlp->nlp_jstat->js_stop_time = time(NULL);

		/* nothing restored. */
		(void) send_unrecovered_list(mod_params, nlp);
		NDMP_LOG(LOG_DEBUG, "Restoring to \"%s\" aborted.",
		    rspath);
		err = -1;
	}

	NDMP_FREE(nlp->nlp_restore_path);
	backup_release_structs(session);

	return (err);
}


/*
 * prefixdir
 *
 * Extract the path for a given full path entry
 */
static char *
prefixdir(char *dir, char *suffix)
{
	static char tmp[TLM_MAX_PATH_NAME];
	char *tend, *send; /* tmp and suffix end */

	if (dir == NULL || suffix == NULL)
		return (NULL);

	if (*suffix == '\0')
		return (dir);

	if (*dir == '\0')
		return (NULL);

	(void) strlcpy(tmp, dir, TLM_MAX_PATH_NAME);
	tend = &tmp[strlen(tmp)];
	send = &suffix[strlen(suffix)];

	/*
	 * Move backward as far as the last part of the dir and
	 * the suffix match.
	 */
	while (tend >= tmp && send >= suffix)
		if (*tend == *send)
			tend--, send--;
		else
			break;

	*++tend = '\0';
	return (tmp);
}


/*
 * get_nfiles
 *
 * Get the count of files to be restored
 */
static int
get_nfiles(ndmpd_session_t *session, ndmpd_module_params_t *params)
{
	if (session->ns_data.dd_nlist_len == 0) {
		MOD_LOG(params, "Error: nothing specified to be restored.\n");
		return (-1);
	}

	return (session->ns_data.dd_nlist_len);
}


/*
 * get_restore_dest
 *
 * Get the full pathname of where the entries should be restored to.
 */
static char *
get_restore_dest(ndmpd_module_params_t *params)
{
	ndmp_name *ent;
	char *cp;

	/*
	 * Destination of restore:
	 * NetBackup of Veritas(C) sends the entries like this:
	 *
	 *	ent[i].name: is the relative pathname of what is selected in
	 *	  the GUI.
	 *	ent[i].dest: is the full pathname of where the dir/file must
	 *	  be restored to.
	 *	ent[i].ssi: 0
	 *	ent[i].fh_info: 0
	 *
	 */
	ent = (ndmp_name *)MOD_GETNAME(params, 0);
	cp = prefixdir(ent->dest, ent->name);
	if (cp == NULL) {
		MOD_LOG(params, "Error: empty restore path.\n");
		return (NULL);
	}

	return (cp);
}


/*
 * correct_ents
 *
 * Correct the entries in the restore list by appending the appropriate
 * path to them
 */
static int
correct_ents(ndmpd_module_params_t *params, int n, char *bkpath)
{
	char *cp, *pathname;
	int i, len, rv;
	ndmp_name *ent;

	if ((pathname = ndmp_malloc(TLM_MAX_PATH_NAME)) == NULL) {
		MOD_LOG(params, "Error: insufficient memory.\n");
		return (-1);
	}

	rv = 0;
	/* Append the backup path to all the "ent[].name"s. */
	for (i = 0; i < n; i++) {
		ent = (ndmp_name *)MOD_GETNAME(params, i);

		NDMP_LOG(LOG_DEBUG,
		    "Old: ent[%d].name: \"%s\"", i, ent->name);
		NDMP_LOG(LOG_DEBUG,
		    "Old: ent[%d].dest: \"%s\"", i, ent->dest);

		/* remove trailing slash */
		len = strlen(ent->name);
		if (ent->name[len - 1] == '/')
			ent->name[len - 1] = '\0';

		if (!tlm_cat_path(pathname, bkpath, ent->name)) {
			MOD_LOG(params, "Error: path too long.\n");
			rv = -1;
			break;
		}

		/* Make a copy of the new string and save it in ent->name. */
		cp = strdup(pathname);
		if (cp == NULL) {
			MOD_LOG(params, "Error: insufficient memory.\n");
			rv = -1;
			break;
		}
		free(ent->name);
		ent->name = cp;

		NDMP_LOG(LOG_DEBUG,
		    "New: ent[%d].name: \"%s\"", i, ent->name);
	}

	free(pathname);
	return (rv);
}


/*
 * check_restore_paths
 *
 * Go through the restore list and check the validity of the
 * restore path.
 */
static int
check_restore_paths(ndmpd_module_params_t *params, int n, char *rspath)
{
	int i, rv;
	ndmp_name *ent;

	rv = 0;
	if (rspath != NULL && *rspath != '\0') {
		NDMP_LOG(LOG_DEBUG, "rspath: \"%s\"", rspath);
		if (!fs_volexist(rspath)) {
			MOD_LOG(params,
			    "Error: Invalid volume name for restore.");
			rv = -1;
		}
	} else {
		for (i = 0; i < n; i++) {
			ent = (ndmp_name *)MOD_GETNAME(params, i);
			NDMP_LOG(LOG_DEBUG,
			    "ent[%d].name: \"%s\"", i, ent->name);

			if (!fs_volexist(ent->name)) {
				MOD_LOG(params,
				    "Error: Invalid volume name for restore.",
				    ent->name);
				rv = -1;
				break;
			}
		}
	}

	return (rv);
}


/*
 * check_backup_dir_validity
 *
 * Check if the backup directory is valid. Make sure it exists and
 * is writable. Check for snapshot and readonly cases.
 */
static int
check_backup_dir_validity(ndmpd_module_params_t *params, char *bkpath)
{
	char *msg;
	int rv;
	struct stat64 st;

	rv = NDMP_NO_ERR;
	if (stat64(bkpath, &st) < 0) {
		msg = strerror(errno);
		MOD_LOG(params, "Error: stat(%s): %s.\n", bkpath, msg);
		rv = NDMP_ILLEGAL_ARGS_ERR;
	} else if (!S_ISDIR(st.st_mode)) {
		MOD_LOG(params, "Error: %s is not a directory.\n", bkpath);
		rv = NDMP_ILLEGAL_ARGS_ERR;
	} else if (fs_is_rdonly(bkpath) && !fs_is_chkpntvol(bkpath) &&
	    fs_is_chkpnt_enabled(bkpath)) {
		MOD_LOG(params, "Error: %s is not a checkpointed path.\n",
		    bkpath);
		rv = NDMP_BAD_FILE_ERR;
	}

	return (rv);
}


/*
 * ndmp_backup_extract_params
 *
 * Go through the backup parameters and check the validity
 * for each one. Then set the NLP flags according to the parameters.
 */
int
ndmp_backup_extract_params(ndmpd_session_t *session,
    ndmpd_module_params_t *params)
{
	char *cp;
	int rv;
	ndmp_lbr_params_t *nlp;

	/* Extract directory to be backed up from env variables */
	if ((nlp = ndmp_get_nlp(session)) == NULL) {
		MOD_LOG(params, "Error: Internal error: nlp == NULL.\n");
		return (NDMP_ILLEGAL_ARGS_ERR);
	}
	if ((nlp->nlp_backup_path = get_backup_path_v2(params)) == NULL)
		return (NDMP_FILE_NOT_FOUND_ERR);

	if ((rv = check_backup_dir_validity(params,
	    nlp->nlp_backup_path)) != NDMP_NO_ERR)
		return (rv);

	/* Should the st_ctime be ignored when backing up? */
	if (ndmp_ignore_ctime) {
		NDMP_LOG(LOG_DEBUG, "ignoring st_ctime");
		NLP_SET(nlp, NLPF_IGNCTIME);
	} else
		NLP_UNSET(nlp, NLPF_IGNCTIME);

	/* Should the st_lmtime be ignored when backing up? */
	if (ndmp_include_lmtime) {
		NDMP_LOG(LOG_DEBUG, "including st_lmtime");
		NLP_SET(nlp, NLPF_INCLMTIME);
	} else
		NLP_UNSET(nlp, NLPF_INCLMTIME);

	NDMP_LOG(LOG_DEBUG, "flags %x", nlp->nlp_flags);

	/* Is backup history requested? */
	cp = MOD_GETENV(params, "HIST");
	if (cp == NULL) {
		NDMP_LOG(LOG_DEBUG, "env(HIST) not specified");
		NLP_UNSET(nlp, NLPF_FH);
	} else {
		NDMP_LOG(LOG_DEBUG, "env(HIST): \"%s\"", cp);

		if (strchr("t_ty_y", *cp))
			NLP_SET(nlp, NLPF_FH);
		else
			NLP_UNSET(nlp, NLPF_FH);
	}

	nlp->nlp_clevel = 0;
	/* Is it an incremental backup? */
	cp = MOD_GETENV(params, "LEVEL");
	if (cp == NULL) {
		NDMP_LOG(LOG_DEBUG,
		    "env(LEVEL) not specified, default to 0");
	} else if (*cp < '0' || *cp > '9' || *(cp+1) != '\0') {
		NDMP_LOG(LOG_DEBUG, "Invalid backup level '%s'", cp);
		return (NDMP_ILLEGAL_ARGS_ERR);
	} else
		nlp->nlp_clevel = *cp - '0';

	/* Extract last backup time from the dumpdates file */
	nlp->nlp_llevel = nlp->nlp_clevel;
	nlp->nlp_ldate = 0;
	if (ndmpd_get_dumptime(nlp->nlp_backup_path, &nlp->nlp_llevel,
	    &nlp->nlp_ldate) < 0) {
		MOD_LOG(params, "Error: getting dumpdate for %s level %d\n",
		    nlp->nlp_backup_path, nlp->nlp_clevel);
		return (NDMP_NO_MEM_ERR);
	}

	NDMP_LOG(LOG_DEBUG,
	    "Date of this level %d on \"%s\": %s",
	    nlp->nlp_clevel, nlp->nlp_backup_path, cctime(&nlp->nlp_cdate));
	NDMP_LOG(LOG_DEBUG,
	    "Date of last level %d on \"%s\": %s",
	    nlp->nlp_llevel, nlp->nlp_backup_path, cctime(&nlp->nlp_ldate));

	/* Should the dumpdate file be updated? */
	cp = MOD_GETENV(params, "UPDATE");
	if (cp == NULL) {
		NDMP_LOG(LOG_DEBUG,
		    "env(UPDATE) not specified, default to TRUE");
		NLP_SET(nlp, NLPF_UPDATE);
	} else {
		NDMP_LOG(LOG_DEBUG, "env(UPDATE): \"%s\"", cp);
		if (strchr("t_ty_y", *cp) != NULL)
			NLP_SET(nlp, NLPF_UPDATE);
		else
			NLP_UNSET(nlp, NLPF_UPDATE);
	}

	return (NDMP_NO_ERR);
}



/*
 * log_bk_params_v2
 *
 * Dump the value of the parameters in the log file for debugging.
 */
void
log_bk_params_v2(ndmpd_session_t *session, ndmpd_module_params_t *params,
    ndmp_lbr_params_t *nlp)
{
	MOD_LOG(params, "Date of this level %d on \"%s\": %s\n",
	    nlp->nlp_clevel, nlp->nlp_backup_path, cctime(&nlp->nlp_cdate));
	MOD_LOG(params, "Date of last level %d on \"%s\": %s\n",
	    nlp->nlp_llevel, nlp->nlp_backup_path, cctime(&nlp->nlp_ldate));

	MOD_LOG(params, "Backing up: \"%s\".\n", nlp->nlp_backup_path);
	MOD_LOG(params, "Record size: %d\n", session->ns_mover.md_record_size);
	MOD_LOG(params, "File history: %c.\n",
	    NDMP_YORN(NLP_ISSET(nlp, NLPF_FH)));
	MOD_LOG(params, "Update: %s\n",
	    NLP_ISSET(nlp, NLPF_UPDATE) ? "TRUE" : "FALSE");

}


/*
 * same_path
 *
 * Find out if the paths are the same regardless of the ending slash
 *
 * Examples :
 *   /a/b/c == /a/b/c
 *   /a/b/c/ == /a/b/c
 *   /a/b/c == /a/b/c/
 */
static boolean_t
same_path(char *s, char *t)
{
	boolean_t rv;
	int slen, tlen;

	rv = FALSE;
	slen = strlen(s);
	tlen = strlen(t);
	if (slen == tlen && strcmp(s, t) == 0) {
		rv = TRUE;
	} else {
		if (slen == tlen - 1) {
			if (strncmp(s, t, slen) == 0 && t[tlen - 1] == '/')
				rv = TRUE;
		} else if (tlen == slen -1) {
			if (strncmp(s, t, tlen) == 0 && s[slen - 1] == '/')
				rv = TRUE;
		}
	}

	NDMP_LOG(LOG_DEBUG, "rv: %d", rv);
	return (rv);
}


/*
 * ndmp_restore_extract_params
 *
 * Go through the restore parameters and check them and extract them
 * by setting NLP flags and other values.
 *
 * Parameters:
 *
 * Returns:
 *   0: on success
 *  -1: otherwise
 */
int
ndmp_restore_extract_params(ndmpd_session_t *session,
    ndmpd_module_params_t *params)
{
	char *bkpath, *rspath;
	ndmp_lbr_params_t *nlp;

	if ((nlp = ndmp_get_nlp(session)) == NULL) {
		NDMP_LOG(LOG_DEBUG, "nlp == NULL");
		return (-1);
	}

	/* Extract directory from where the backup was made. */
	if ((bkpath = get_backup_path_v2(params)) == NULL)
		return (NDMP_ILLEGAL_ARGS_ERR);

	nlp->nlp_restore_bk_path = bkpath;

	/* The number of the selections. */
	if ((nlp->nlp_nfiles = get_nfiles(session, params)) == 0)
		return (NDMP_ILLEGAL_ARGS_ERR);

	NDMP_LOG(LOG_DEBUG, "nfiles: %d", nlp->nlp_nfiles);

	if ((rspath = get_restore_dest(params)) == NULL)
		return (NDMP_ILLEGAL_ARGS_ERR);

	if (fs_is_rdonly(rspath)) {
		MOD_LOG(params,
		    "Error: Can't restore to a read-only volume: \"%s\"\n",
		    rspath);
		return (NDMP_ILLEGAL_ARGS_ERR);
	}
	if (fs_is_chkpntvol(rspath)) {
		MOD_LOG(params,
		    "Error: Can't restore to a checkpoint: \"%s\"\n", rspath);
		return (NDMP_ILLEGAL_ARGS_ERR);
	}

	if (same_path(bkpath, rspath))
		rspath = "";

	if ((nlp->nlp_restore_path = strdup(rspath)) == NULL)
		return (NDMP_NO_MEM_ERR);

	bkpath = trim_name(bkpath);
	if (correct_ents(params, nlp->nlp_nfiles, bkpath) < 0) {
		free(nlp->nlp_restore_path);
		return (NDMP_ILLEGAL_ARGS_ERR);
	}

	if (check_restore_paths(params, nlp->nlp_nfiles, rspath) < 0) {
		free(nlp->nlp_restore_path);
		return (NDMP_ILLEGAL_ARGS_ERR);
	}

	MOD_LOG(params, "Restoring %d files.\n", nlp->nlp_nfiles);
	MOD_LOG(params, "Restoring to: \"%s\".\n", nlp->nlp_restore_path);
	MOD_LOG(params, "Record size: %d\n", session->ns_mover.md_record_size);

	return (NDMP_NO_ERR);
}

/*
 * ndmpd_tar_backup_starter (V2 only)
 *
 * The main backup starter function. It creates a snapshot if necessary
 * and calls ndmp_tar_backup to perform the actual backup. It does the cleanup
 * and release the snapshot at the end.
 */
int
ndmpd_tar_backup_starter(void *arg)
{
	ndmpd_module_params_t *mod_params = arg;
	int err;
	ndmpd_session_t *session;
	ndmp_lbr_params_t *nlp;

	session = (ndmpd_session_t *)(mod_params->mp_daemon_cookie);
	*(mod_params->mp_module_cookie) = nlp = ndmp_get_nlp(session);
	ndmp_session_ref(session);

	err = 0;
	if (fs_is_chkpntvol(nlp->nlp_backup_path) ||
	    fs_is_rdonly(nlp->nlp_backup_path) ||
	    !fs_is_chkpnt_enabled(nlp->nlp_backup_path))
		NLP_SET(nlp, NLPF_CHKPNTED_PATH);
	else {
		NLP_UNSET(nlp, NLPF_CHKPNTED_PATH);
		if (ndmp_create_snapshot(nlp->nlp_backup_path,
		    nlp->nlp_jstat->js_job_name) < 0) {
			MOD_LOG(mod_params,
			    "Error: creating checkpoint on %s\n",
			    nlp->nlp_backup_path);
			/* -1 causes halt reason to become internal error. */
			err = -1;
		}
	}

	NDMP_LOG(LOG_DEBUG, "NLPF_CHKPNTED_PATH: %c",
	    NDMP_YORN(NLP_ISCHKPNTED(nlp)));
	NDMP_LOG(LOG_DEBUG, "err: %d, update %c",
	    err, NDMP_YORN(NLP_SHOULD_UPDATE(nlp)));

	if (err == 0) {
		err = ndmp_get_cur_bk_time(nlp, &nlp->nlp_cdate,
		    nlp->nlp_jstat->js_job_name);
		if (err != 0) {
			NDMP_LOG(LOG_DEBUG, "err %d", err);
		} else {
			log_bk_params_v2(session, mod_params, nlp);
			err = ndmpd_tar_backup(session, mod_params, nlp);
		}
	}

	if (nlp->nlp_bkmap >= 0) {
		(void) dbm_free(nlp->nlp_bkmap);
		nlp->nlp_bkmap = -1;
	}

	if (!NLP_ISCHKPNTED(nlp))
		(void) ndmp_remove_snapshot(nlp->nlp_backup_path,
		    nlp->nlp_jstat->js_job_name);

	NDMP_LOG(LOG_DEBUG, "err %d, update %c",
	    err, NDMP_YORN(NLP_SHOULD_UPDATE(nlp)));

	if (err == 0 && NLP_SHOULD_UPDATE(nlp)) {
		if (ndmpd_put_dumptime(nlp->nlp_backup_path, nlp->nlp_clevel,
		    nlp->nlp_cdate) < 0) {
			err = EPERM;
			MOD_LOG(mod_params,
			    "Error: updating the dumpdates file on %s\n",
			    nlp->nlp_backup_path);
		}
	}

	MOD_DONE(mod_params, err);

	/* nlp_params is allocated in start_backup() */
	NDMP_FREE(nlp->nlp_params);

	NS_DEC(nbk);
	ndmp_session_unref(session);
	return (err);
}


/*
 * ndmpd_tar_backup_abort
 *
 * Abort the running backup by stopping the reader thread (V2 only)
 */
int
ndmpd_tar_backup_abort(void *module_cookie)
{
	ndmp_lbr_params_t *nlp;

	nlp = (ndmp_lbr_params_t *)module_cookie;
	if (nlp != NULL && nlp->nlp_session != NULL) {
		if (nlp->nlp_session->ns_data.dd_mover.addr_type ==
		    NDMP_ADDR_TCP && nlp->nlp_session->ns_data.dd_sock != -1) {
			(void) close(nlp->nlp_session->ns_data.dd_sock);
			nlp->nlp_session->ns_data.dd_sock = -1;
		}
		ndmp_stop_reader_thread(nlp->nlp_session);
	}

	return (0);
}

/*
 * ndmpd_tar_restore_starter
 *
 * Starts the restore by running ndmpd_tar_restore function (V2 only)
 */

int
ndmpd_tar_restore_starter(void *arg)
{
	ndmpd_module_params_t *mod_params = arg;
	int err;
	ndmpd_session_t *session;
	ndmp_lbr_params_t *nlp;

	session = (ndmpd_session_t *)(mod_params->mp_daemon_cookie);
	*(mod_params->mp_module_cookie) = nlp = ndmp_get_nlp(session);
	ndmp_session_ref(session);

	err = ndmpd_tar_restore(session, mod_params, nlp);
	MOD_DONE(mod_params, err);

	/* nlp_params is allocated in start_recover() */
	NDMP_FREE(nlp->nlp_params);

	NS_DEC(nrs);
	ndmp_session_unref(session);
	return (err);
}


/*
 * ndmpd_tar_restore_abort
 *
 * Aborts the restore operation by stopping the writer thread (V2 only)
 */
int
ndmpd_tar_restore_abort(void *module_cookie)
{
	ndmp_lbr_params_t *nlp;

	nlp = (ndmp_lbr_params_t *)module_cookie;
	if (nlp != NULL && nlp->nlp_session != NULL) {
		(void) mutex_lock(&nlp->nlp_mtx);
		if (nlp->nlp_session->ns_data.dd_mover.addr_type ==
		    NDMP_ADDR_TCP && nlp->nlp_session->ns_data.dd_sock != -1) {
			(void) close(nlp->nlp_session->ns_data.dd_sock);
			nlp->nlp_session->ns_data.dd_sock = -1;
		}
		(void) cond_broadcast(&nlp->nlp_cv);
		(void) mutex_unlock(&nlp->nlp_mtx);
		ndmp_stop_writer_thread(nlp->nlp_session);
	}

	return (0);
}
