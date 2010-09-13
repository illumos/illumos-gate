/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
#include <sys/stat.h>
#include <sys/types.h>
#include <cstack.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include "ndmpd.h"
#include <bitmap.h>
#include <traverse.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "tlm_buffers.h"


/*
 * Parameter passed to traverse for marking inodes
 * when traversing backup hierarchy in V2.  It
 * includes:
 *    mp_bmd: the bitmap describptor.
 *    mp_ddate: backup date.
 *    mp_session: pointer to the session structure.
 *    mp_nlp: pointer to the nlp.
 *    mp_tacl: pointer to the acl.
 */
typedef struct mark_param {
	int mp_bmd;
	time_t mp_ddate;
	ndmpd_session_t *mp_session;
	ndmp_lbr_params_t *mp_nlp;
	tlm_acls_t *mp_tacl;
} mark_param_t;


/*
 * Set this variable to non-zero to print the inodes
 * marked after traversing file system.
 */
static int ndmpd_print_inodes = 0;


/*
 * Flag passed to traverse_post.
 */
static int ndmpd_mark_flags = 0;


/*
 * Verbose traversing prints the file/dir path names
 * if they are being marked.
 */
static int ndmpd_verbose_traverse = 0;


/*
 * Set this flag to count the number of inodes marked
 * after traversing backup hierarchy.
 */
static int ndmpd_mark_count_flag = 0;


/*
 * Set this variable to non-zero value to force traversing
 * backup hierarchy for tar format.
 */
static int ndmp_tar_force_traverse = 0;


/*
 * Set this variable to non-zero value to skip processing
 * directories both for tar and dump.
 */
static int ndmp_skip_traverse = 0;


/*
 * count_bits_cb
 *
 * Call back for counting the set bits in the dbitmap.
 *
 * Parameters:
 *   bmd (input) - bitmap descriptor
 *   bn (input) - the bit number
 *   arg (input) - pointer to the argument
 *
 * Returns:
 *   0: always
 */
static int
count_bits_cb(int bmd, u_longlong_t bn, void *arg)
{
	if (dbm_getone(bmd, bn)) {
		(*(u_longlong_t *)arg)++;
		if (ndmpd_print_inodes)
			NDMP_LOG(LOG_DEBUG, "%llu", bn);
	}

	return (0);
}


/*
 * count_set_bits
 *
 * Count bits set in the bitmap.
 *
 * Parameters:
 *   path (input) - the backup path
 *   bmd (input) - bitmap descriptor
 *
 * Returns:
 *   void
 */
void
count_set_bits(char *path, int bmd)
{
	u_longlong_t cnt;

	if (!ndmpd_mark_count_flag)
		return;

	cnt = 0;
	(void) dbm_apply_ifset(bmd, count_bits_cb, &cnt);
	NDMP_LOG(LOG_DEBUG, "%s %llu inodes marked", path, cnt);
}


/*
 * traverse
 *
 * Starts the post-traverse the backup hierarchy.  Checks
 * for exceptional cases, like aborting operation and if
 * asked, report detailed information after traversing.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   nlp (input) - pointer to the nlp structure
 *   ftp (input) - pointer to the traverse parameters
 *
 * Returns:
 *   0: on success
 *   != 0: otherwise
 */
int
traverse(ndmpd_session_t *session, ndmp_lbr_params_t *nlp,
    fs_traverse_t *ftp)
{
	int rv;
	time_t s, e;

	if (!session || !nlp || !ftp) {
		NDMP_LOG(LOG_DEBUG, "Invalid argument");
		return (-1);
	}
	NDMP_LOG(LOG_DEBUG, "Processing directories of \"%s\"",
	    nlp->nlp_backup_path);

	(void) time(&s);
	if (traverse_post(ftp) != 0) {
		rv = -1;
		if (!session->ns_data.dd_abort && !NLP_ISSET(nlp,
		    NLPF_ABORTED)) {
			NDMP_LOG(LOG_DEBUG,
			    "Traversing backup path hierarchy \"%s\"",
			    nlp->nlp_backup_path);
		}
	} else {
		(void) dbm_setone(nlp->nlp_bkmap, (u_longlong_t)ROOT_INODE);
		rv = 0;
		(void) time(&e);
		NDMP_LOG(LOG_DEBUG,
		    "\"%s\" traversed in %u sec", nlp->nlp_backup_path,
		    (uint_t)(e-s));

		count_set_bits(nlp->nlp_backup_path, nlp->nlp_bkmap);
	}

	return (rv);
}


/*
 * mark_cb
 *
 * The callback function, called by traverse_post to mark bits
 * in the bitmap.
 *
 * Set the bit of the entry if it's been modified (obviously
 * should be backed up) plus its parent directory.
 *
 * If the entry is a directory and is not modified itself,
 * but it's marked, then there is something below it that
 * is being backed up.  It shows the the path, leads to
 * an object that will be backed up. So the path should
 * be marked too.
 *
 * The backup path itself is always marked.
 *
 * Parameters:
 *   arg (input) - pointer to the mark parameter
 *   pnp (input) - pointer to the path node
 *   enp (input) - pointer to the entry node
 *
 * Returns:
 *   0: as long as traversing should continue
 *   != 0: if traversing should stop
 */
int
mark_cb(void *arg, fst_node_t *pnp, fst_node_t *enp)
{
	int bmd;
	int rv;
	u_longlong_t bl;
	time_t ddate;
	fs_fhandle_t *pfhp, *efhp;
	struct stat64 *pstp, *estp;
	mark_param_t *mpp;
	ndmp_lbr_params_t *nlp;
	tlm_acls_t *tacl;

	rv = 0;
	mpp = (mark_param_t *)arg;
	tacl = mpp->mp_tacl;
	nlp = ndmp_get_nlp(mpp->mp_session);
	if (!mpp) {
		NDMP_LOG(LOG_DEBUG, "NULL argument passed");
		rv = -1;
	} else if (mpp->mp_session->ns_eof) {
		NDMP_LOG(LOG_INFO, "Connection to the client is closed");
		rv = -1;
	} else if (mpp->mp_session->ns_data.dd_abort ||
	    (nlp && NLP_ISSET(nlp, NLPF_ABORTED))) {
		NDMP_LOG(LOG_INFO, "Processing directories aborted.");
		rv = -1;
	}

	if (rv != 0)
		return (rv);

	ddate = mpp->mp_ddate;
	bmd = mpp->mp_bmd;
	bl = dbm_getlen(bmd);

	pfhp = pnp->tn_fh;
	pstp = pnp->tn_st;

	/* sanity check on fh and stat of the path passed */
	if (pstp->st_ino > bl) {
		NDMP_LOG(LOG_DEBUG, "Invalid path inode #%u",
		    (uint_t)pstp->st_ino);
		return (-1);
	}
	if (pstp->st_ino != pfhp->fh_fid) {
		NDMP_LOG(LOG_DEBUG, "Path ino mismatch %u %u",
		    (uint_t)pstp->st_ino, (uint_t)pfhp->fh_fid);
		return (-1);
	}

	/*
	 * Always mark the backup path inode number.
	 */
	if (!enp->tn_path) {
		(void) dbm_setone(bmd, pstp->st_ino);
		return (0);
	}

	efhp = enp->tn_fh;
	estp = enp->tn_st;

	/* sanity check on fh and stat of the entry passed */
	if (estp->st_ino > bl) {
		NDMP_LOG(LOG_DEBUG, "Invalid entry inode #%u",
		    (uint_t)estp->st_ino);
		return (-1);
	}
	if (estp->st_ino != efhp->fh_fid) {
		NDMP_LOG(LOG_DEBUG, "Entry ino mismatch %u %u", estp->st_ino,
		    (uint_t)pfhp->fh_fid);
		return (-1);
	}

	/* check the dates and mark the bitmap inode */
	if (ddate == 0) {
		/* base backup */
		(void) dbm_setone(bmd, (u_longlong_t)estp->st_ino);
		(void) dbm_setone(bmd, (u_longlong_t)pstp->st_ino);
		if (ndmpd_verbose_traverse) {
			NDMP_LOG(LOG_DEBUG, "Base Backup");
			NDMP_LOG(LOG_DEBUG, "\"%s/%s\"",
			    pnp->tn_path, enp->tn_path);
		}

	} else if (estp->st_mtime > ddate) {
		(void) dbm_setone(bmd, (u_longlong_t)estp->st_ino);
		(void) dbm_setone(bmd, (u_longlong_t)pstp->st_ino);
		if (ndmpd_verbose_traverse) {
			NDMP_LOG(LOG_DEBUG,
			    "m(%u,%u,%u,%u)", (uint_t)pstp->st_ino,
			    (uint_t)estp->st_ino, (uint_t)estp->st_mtime,
			    (uint_t)ddate);
			NDMP_LOG(LOG_DEBUG, "\"%s/%s\"",
			    pnp->tn_path, enp->tn_path);
		}
	} else if (iscreated(nlp, NULL, tacl, ddate)) {
		(void) dbm_setone(bmd, (u_longlong_t)estp->st_ino);
		(void) dbm_setone(bmd, (u_longlong_t)pstp->st_ino);
		if (ndmpd_verbose_traverse) {
			NDMP_LOG(LOG_DEBUG,
			    "cr(%u,%u,%u,%u)", (uint_t)pstp->st_ino,
			    (uint_t)estp->st_ino, (uint_t)estp->st_mtime,
			    (uint_t)ddate);
			NDMP_LOG(LOG_DEBUG, "\"%s/%s\"",
			    pnp->tn_path, enp->tn_path);
		}
	} else if (estp->st_ctime > ddate) {
		if (!NLP_IGNCTIME(nlp)) {
			(void) dbm_setone(bmd, (u_longlong_t)estp->st_ino);
			(void) dbm_setone(bmd, (u_longlong_t)pstp->st_ino);
		}
		if (ndmpd_verbose_traverse) {
			if (NLP_IGNCTIME(nlp)) {
				NDMP_LOG(LOG_DEBUG,
				    "ign c(%u,%u,%u,%u)", (uint_t)pstp->st_ino,
				    (uint_t)estp->st_ino,
				    (uint_t)estp->st_ctime, (uint_t)ddate);
			} else {
				NDMP_LOG(LOG_DEBUG,
				    "c(%u,%u,%u,%u)", (uint_t)pstp->st_ino,
				    (uint_t)estp->st_ino,
				    (uint_t)estp->st_ctime, (uint_t)ddate);
			}
			NDMP_LOG(LOG_DEBUG, "\"%s/%s\"",
			    pnp->tn_path, enp->tn_path);
		}
	} else if (S_ISDIR(estp->st_mode) &&
	    dbm_getone(bmd, (u_longlong_t)estp->st_ino)) {
		(void) dbm_setone(bmd, (u_longlong_t)pstp->st_ino);
		if (ndmpd_verbose_traverse) {
			NDMP_LOG(LOG_DEBUG, "d(%u,%u)",
			    (uint_t)pstp->st_ino, (uint_t)estp->st_ino);
			NDMP_LOG(LOG_DEBUG, "\"%s, %s\"",
			    pnp->tn_path, enp->tn_path);
		}
	}

	return (0);
}


/*
 * mark_inodes_v2
 *
 * Traverse the file system in post-order and mark
 * all the modified objects and also directories leading
 * to them.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   nlp (input) - pointer to the nlp structure
 *   path (input) - the physical path to traverse
 *
 * Returns:
 *   0: on success.
 *   != 0: on error.
 */
int
mark_inodes_v2(ndmpd_session_t *session, ndmp_lbr_params_t *nlp, char *path)
{
	fs_traverse_t ft;
	mark_param_t mp;

	if (!session || !nlp || !path || !*path) {
		NDMP_LOG(LOG_DEBUG, "Invalid argument");
		return (-1);
	}

	NDMP_LOG(LOG_DEBUG, "path \"%s\"", path);

	mp.mp_bmd = nlp->nlp_bkmap;
	mp.mp_ddate = nlp->nlp_ldate;
	mp.mp_session = session;
	mp.mp_nlp = nlp;

	ft.ft_path = path;
	ft.ft_lpath = nlp->nlp_backup_path;
	ft.ft_callbk = mark_cb;
	ft.ft_arg = &mp;
	ft.ft_logfp = (ft_log_t)ndmp_log;
	ft.ft_flags = ndmpd_mark_flags;

	return (traverse(session, nlp, &ft));
}


/*
 * create_bitmap
 *
 * Create a dbitmap and return its descriptor.
 *
 * Parameters:
 *   path (input) - path for which the bitmap should be created
 *   value (input) - the initial value for the bitmap
 *
 * Returns:
 *   the dbitmap descriptor
 */
static int
create_bitmap(char *path, int value)
{
	char bm_fname[PATH_MAX];
	char buf[TLM_MAX_PATH_NAME];
	char *livepath;
	ulong_t ninode;

	NDMP_LOG(LOG_DEBUG, "path \"%s\"", path);

	if (fs_is_chkpntvol(path))
		livepath = (char *)tlm_remove_checkpoint(path, buf);
	else
		livepath = path;
	ninode = 1024 * 1024 * 1024;
	if (ninode == 0)
		return (-1);
	(void) ndmpd_mk_temp(bm_fname);

	NDMP_LOG(LOG_DEBUG, "path \"%s\"ninode %u bm_fname \"%s\"",
	    livepath, ninode, bm_fname);

	return (dbm_alloc(bm_fname, (u_longlong_t)ninode, value));
}


/*
 * create_allset_bitmap
 *
 * A helper function to create a bitmap with all the
 * values set to 1.
 *
 * Parameters:
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   the dbitmap descriptor
 */
static int
create_allset_bitmap(ndmp_lbr_params_t *nlp)
{
	int rv;

	nlp->nlp_bkmap = create_bitmap(nlp->nlp_backup_path, 1);
	NDMP_LOG(LOG_DEBUG, "nlp_bkmap %d", nlp->nlp_bkmap);

	if (nlp->nlp_bkmap < 0) {
		NDMP_LOG(LOG_DEBUG, "Failed to allocate bitmap.");
		rv = -1;
	} else
		rv = 0;

	return (rv);
}


/*
 * mark_common_v2
 *
 * Create the inode bitmap.  If last date of the the
 * backup is epoch, then all the objects should be backed
 * up; there is no need to traverse the backup hierarchy
 * and mark the inodes.  All the bits should be marked.
 *
 * Otherwise, the backup hierarchy should be traversed and
 * the objects should be marked.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   0: on success.
 *   != 0: on error.
 */
static int
mark_common_v2(ndmpd_session_t *session, ndmp_lbr_params_t *nlp)
{
	char buf[TLM_MAX_PATH_NAME], *chkpath;
	int rv;

	/*
	 * Everything is needed for full backup.
	 */
	if (nlp->nlp_ldate == (time_t)0)
		return (create_allset_bitmap(nlp));

	rv = 0;
	nlp->nlp_bkmap = create_bitmap(nlp->nlp_backup_path, 0);
	NDMP_LOG(LOG_DEBUG, "nlp_bkmap %d", nlp->nlp_bkmap);

	if (nlp->nlp_bkmap < 0) {
		NDMP_LOG(LOG_DEBUG, "Failed to allocate bitmap.");
		rv = -1;
	} else {
		if (fs_is_chkpntvol(nlp->nlp_backup_path))
			chkpath = nlp->nlp_backup_path;
		else
			chkpath = tlm_build_snapshot_name(
			    nlp->nlp_backup_path, buf,
			    nlp->nlp_jstat->js_job_name);
		rv = mark_inodes_v2(session, nlp, chkpath);
		(void) dbm_setone(nlp->nlp_bkmap, (u_longlong_t)ROOT_INODE);
	}

	return (rv);
}


/*
 * mark_tar_inodes_v2
 *
 * Create the bitmap for tar backup format.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   0: on success.
 *   != 0: on error.
 */
static int
mark_tar_inodes_v2(ndmpd_session_t *session, ndmp_lbr_params_t *nlp)
{
	int rv;

	if (ndmp_tar_force_traverse)
		rv = mark_common_v2(session, nlp);
	else
		rv = create_allset_bitmap(nlp);

	return (rv);
}


/*
 * mark_dump_inodes_v2
 *
 * Create the bitmap for dump backup format.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   0: on success.
 *   != 0: on error.
 */
static int
mark_dump_inodes_v2(ndmpd_session_t *session, ndmp_lbr_params_t *nlp)
{
	return (mark_common_v2(session, nlp));
}


/*
 * ndmpd_mark_inodes_v2
 *
 * Mark the inodes of the backup hierarchy if necessary.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   0: on success.
 *   != 0: on error.
 */
int
ndmpd_mark_inodes_v2(ndmpd_session_t *session, ndmp_lbr_params_t *nlp)
{
	int rv;

	if (ndmp_skip_traverse) {
		NDMP_LOG(LOG_INFO, "Skip processing directories \"%s\"",
		    nlp->nlp_backup_path);
		rv = create_allset_bitmap(nlp);
	} else {
		if (NLP_ISTAR(nlp))
			rv = mark_tar_inodes_v2(session, nlp);
		else if (NLP_ISDUMP(nlp))
			rv = mark_dump_inodes_v2(session, nlp);
		else {
			NDMP_LOG(LOG_DEBUG, "Unknown backup type for \"%s\"",
			    nlp->nlp_backup_path);
			rv = -1;
		}
	}

	return (rv);
}


/*
 * ndmpd_abort_making_v2
 *
 * Abort the process of marking inodes.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *
 * Returns:
 *   void
 */
void
ndmpd_abort_marking_v2(ndmpd_session_t *session)
{
	ndmp_lbr_params_t *nlp;

	nlp = ndmp_get_nlp(session);
	if (nlp)
		NLP_SET(nlp, NLPF_ABORTED);
}


/*
 * mark_tokv3
 *
 * Traverse the backup hierarchy and mark the bits for the
 * modified objects of directories leading to a modified
 * object for the token-based backup.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   nlp (input) - pointer to the nlp structure
 *   path (input) - the physical path to traverse
 *
 * Returns:
 *   0: on success
 *   != 0: otherwise
 */
int
mark_tokv3(ndmpd_session_t *session, ndmp_lbr_params_t *nlp, char *path)
{
	fs_traverse_t ft;
	mark_param_t mp;

	if (!session || !nlp || !path || !*path) {
		NDMP_LOG(LOG_DEBUG, "Invalid argument");
		return (-1);
	}
	if (nlp->nlp_tokdate == (time_t)0)
		return (create_allset_bitmap(nlp));

	nlp->nlp_bkmap = create_bitmap(nlp->nlp_backup_path, 0);
	if (nlp->nlp_bkmap < 0) {
		NDMP_LOG(LOG_DEBUG, "Failed to allocate bitmap.");
		return (-1);
	}
	NDMP_LOG(LOG_DEBUG, "nlp_bkmap %d", nlp->nlp_bkmap);

	mp.mp_bmd = nlp->nlp_bkmap;
	mp.mp_ddate = nlp->nlp_tokdate;
	mp.mp_session = session;
	mp.mp_nlp = nlp;

	ft.ft_path = path;
	ft.ft_lpath = nlp->nlp_backup_path;
	ft.ft_callbk = mark_cb;
	ft.ft_arg = &mp;
	ft.ft_logfp = (ft_log_t)ndmp_log;
	ft.ft_flags = ndmpd_mark_flags;

	return (traverse(session, nlp, &ft));
}


/*
 * marklbrv3_cb
 *
 * The callback function, called by traverse_post to mark
 * bits in the bitmap.
 *
 * It's so much like mark_cb for time-based (token-based
 * and level-type) backup types, except that it looks at
 * the archive bit of the objects instead of their timestamp.
 *
 * Parameters:
 *   arg (input) - pointer to the mark parameter
 *   pnp (input) - pointer to the path node
 *   enp (input) - pointer to the entry node
 *
 * Returns:
 *   0: as long as traversing should continue
 *   != 0: if traversing should stop
 */
int
marklbrv3_cb(void *arg, fst_node_t *pnp, fst_node_t *enp)
{
	int bmd;
	u_longlong_t bl;
	fs_fhandle_t *pfhp, *efhp;
	struct stat64 *pstp, *estp;
	mark_param_t *mpp;
	ndmp_lbr_params_t *nlp;

	mpp = (mark_param_t *)arg;
	if (!mpp) {
		NDMP_LOG(LOG_DEBUG, "NULL argument passed");
		return (-1);
	}
	nlp = ndmp_get_nlp(mpp->mp_session);
	if (mpp->mp_session->ns_data.dd_abort ||
	    (nlp && NLP_ISSET(nlp, NLPF_ABORTED))) {
		NDMP_LOG(LOG_INFO, "Processing directories aborted.");
		return (-1);
	}

	bmd = mpp->mp_bmd;
	bl = dbm_getlen(bmd);

	pfhp = pnp->tn_fh;
	pstp = pnp->tn_st;

	/* sanity check on fh and stat of the path passed */
	if (pstp->st_ino > bl) {
		NDMP_LOG(LOG_DEBUG, "Invalid path inode #%u",
		    (uint_t)pstp->st_ino);
		return (-1);
	}
	if (pstp->st_ino != pfhp->fh_fid) {
		NDMP_LOG(LOG_DEBUG, "Path ino mismatch %u %u",
		    (uint_t)pstp->st_ino, (uint_t)pfhp->fh_fid);
		return (-1);
	}

	/*
	 * Always mark the backup path inode number.
	 */
	if (!enp->tn_path) {
		(void) dbm_setone(bmd, pstp->st_ino);
		if (ndmpd_verbose_traverse) {
			NDMP_LOG(LOG_DEBUG, "d(%u)", (uint_t)pstp->st_ino);
			NDMP_LOG(LOG_DEBUG, "\"%s\"", pnp->tn_path);
		}
		return (0);
	}

	efhp = enp->tn_fh;
	estp = enp->tn_st;

	/* sanity check on fh and stat of the entry passed */
	if (estp->st_ino > bl) {
		NDMP_LOG(LOG_DEBUG, "Invalid entry inode #%u",
		    (uint_t)estp->st_ino);
		return (-1);
	}
	if (estp->st_ino != efhp->fh_fid) {
		NDMP_LOG(LOG_DEBUG, "Entry ino mismatch %u %u", estp->st_ino,
		    (uint_t)pfhp->fh_fid);
		return (-1);
	}

	if (S_ISDIR(estp->st_mode) &&
	    dbm_getone(bmd, (u_longlong_t)estp->st_ino)) {
		(void) dbm_setone(bmd, (u_longlong_t)pstp->st_ino);
		if (ndmpd_verbose_traverse) {
			NDMP_LOG(LOG_DEBUG, "d(%u,%u)",
			    (uint_t)pstp->st_ino, (uint_t)estp->st_ino);
			NDMP_LOG(LOG_DEBUG, "\"%s, %s\"",
			    pnp->tn_path, enp->tn_path);
		}
	}

	return (0);
}


/*
 * mark_lbrv3
 *
 * Traverse the backup hierarchy and mark the bits for the
 * modified objects of directories leading to a modified
 * object for the LBR-type backup.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   nlp (input) - pointer to the nlp structure
 *   path (input) - the physical path to traverse
 *
 * Returns:
 *   0: on success
 *   != 0: otherwise
 */
int
mark_lbrv3(ndmpd_session_t *session, ndmp_lbr_params_t *nlp, char *path)
{
	char c;
	fs_traverse_t ft;
	mark_param_t mp;

	if (!session || !nlp || !path || !*path) {
		NDMP_LOG(LOG_DEBUG, "Invalid argument");
		return (-1);
	}
	/* full and archive backups backup everything */
	c = toupper(nlp->nlp_clevel);
	if (c == 'F' || c == 'A')
		return (create_allset_bitmap(nlp));

	nlp->nlp_bkmap = create_bitmap(nlp->nlp_backup_path, 0);
	if (nlp->nlp_bkmap < 0) {
		NDMP_LOG(LOG_DEBUG, "Failed to allocate bitmap.");
		return (-1);
	}
	NDMP_LOG(LOG_DEBUG, "nlp_bkmap %d", nlp->nlp_bkmap);

	mp.mp_bmd = nlp->nlp_bkmap;
	mp.mp_ddate = 0;
	mp.mp_session = session;
	mp.mp_nlp = nlp;

	ft.ft_path = path;
	ft.ft_lpath = nlp->nlp_backup_path;
	ft.ft_callbk = marklbrv3_cb;
	ft.ft_arg = &mp;
	ft.ft_logfp = (ft_log_t)ndmp_log;
	ft.ft_flags = ndmpd_mark_flags;

	return (traverse(session, nlp, &ft));
}


/*
 * mark_levelv3
 *
 * Traverse the backup hierarchy and mark the bits for the
 * modified objects of directories leading to a modified
 * object for the level-type backup.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   nlp (input) - pointer to the nlp structure
 *   path (input) - the physical path to traverse
 *
 * Returns:
 *   0: on success
 *   != 0: otherwise
 */
int
mark_levelv3(ndmpd_session_t *session, ndmp_lbr_params_t *nlp, char *path)
{
	fs_traverse_t ft;
	mark_param_t mp;
	tlm_acls_t traverse_acl;

	if (!session || !nlp || !path || !*path) {
		NDMP_LOG(LOG_DEBUG, "Invalid argument");
		return (-1);
	}
	if (nlp->nlp_ldate == (time_t)0)
		return (create_allset_bitmap(nlp));

	nlp->nlp_bkmap = create_bitmap(nlp->nlp_backup_path, 0);
	if (nlp->nlp_bkmap < 0) {
		NDMP_LOG(LOG_DEBUG, "Failed to allocate bitmap.");
		return (-1);
	}
	NDMP_LOG(LOG_DEBUG, "nlp_bkmap %d", nlp->nlp_bkmap);

	/*
	 * We do not want to allocate memory for acl every time we
	 * process a file.
	 */
	(void) memset(&traverse_acl, 0, sizeof (traverse_acl));
	mp.mp_tacl = &traverse_acl;

	mp.mp_bmd = nlp->nlp_bkmap;
	mp.mp_ddate = nlp->nlp_ldate;
	mp.mp_session = session;
	mp.mp_nlp = nlp;

	ft.ft_path = path;
	ft.ft_lpath = nlp->nlp_backup_path;
	ft.ft_callbk = mark_cb;
	ft.ft_arg = &mp;
	ft.ft_logfp = (ft_log_t)ndmp_log;
	ft.ft_flags = ndmpd_mark_flags;

	return (traverse(session, nlp, &ft));
}


/*
 * mark_commonv3
 *
 * Create the inode bitmap.  If last date of the the
 * backup is epoch, then all the objects should be backed
 * up; there is no need to traverse the backup hierarchy
 * and mark the inodes.  All the bits should be marked.
 *
 * Otherwise, the backup hierarchy should be traversed and
 * the objects should be marked.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   0: on success.
 *   != 0: on error.
 */
int
mark_commonv3(ndmpd_session_t *session, ndmp_lbr_params_t *nlp)
{
	char buf[TLM_MAX_PATH_NAME], *chkpath;
	int rv;

	if (NLP_ISCHKPNTED(nlp))
		chkpath = nlp->nlp_backup_path;
	else
		chkpath = tlm_build_snapshot_name(nlp->nlp_backup_path, buf,
		    nlp->nlp_jstat->js_job_name);

	if (NLP_ISSET(nlp, NLPF_TOKENBK))
		rv = mark_tokv3(session, nlp, chkpath);
	else if (NLP_ISSET(nlp, NLPF_LBRBK))
		rv = mark_lbrv3(session, nlp, chkpath);
	else if (NLP_ISSET(nlp, NLPF_LEVELBK)) {
		rv = mark_levelv3(session, nlp, chkpath);
	} else {
		rv = -1;
		NDMP_LOG(LOG_DEBUG, "Unknown backup type for \"%s\"",
		    nlp->nlp_backup_path);
	}

	return (rv);
}


/*
 * mark_tar_inodesv3
 *
 * Mark bits for tar backup format of V3.  Normally, the
 * backup hierarchy is not traversed for tar format
 * unless it's forced by setting the ndmp_tar_force_traverse
 * to a non-zero value.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   0: on success
 *   != 0: otherwise
 */
int
mark_tar_inodesv3(ndmpd_session_t *session, ndmp_lbr_params_t *nlp)
{
	int rv;

	if (ndmp_tar_force_traverse)
		rv = mark_commonv3(session, nlp);
	else
		rv = create_allset_bitmap(nlp);

	return (rv);
}


/*
 * ndmpd_mark_inodes_v3
 *
 * Mark the inodes of the backup hierarchy if necessary.
 *
 * Parameters:
 *   session (input) - pointer to the session
 *   nlp (input) - pointer to the nlp structure
 *
 * Returns:
 *   0: on success.
 *   != 0: on error.
 */
int
ndmpd_mark_inodes_v3(ndmpd_session_t *session, ndmp_lbr_params_t *nlp)
{
	int rv;

	if (ndmp_skip_traverse) {
		NDMP_LOG(LOG_INFO, "Skip processing directories \"%s\"",
		    nlp->nlp_backup_path);
		rv = create_allset_bitmap(nlp);
	} else {
		if (NLP_ISTAR(nlp))
			rv = mark_tar_inodesv3(session, nlp);
		else if (NLP_ISDUMP(nlp)) {
			rv = mark_commonv3(session, nlp);
		} else {
			NDMP_LOG(LOG_DEBUG, "Unknown backup type for \"%s\"",
			    nlp->nlp_backup_path);
			rv = -1;
		}
	}

	return (rv);
}
