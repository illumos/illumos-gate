/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc. All rights reserved.
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
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/acl.h>
#include <sys/mkdev.h>
#include <utime.h>
#include <unistd.h>
#include <pthread.h>
#include <archives.h>
#include <priv.h>
#include <tlm.h>
#include <libzfs.h>
#include <pwd.h>
#include <grp.h>
#include <ndmpd_prop.h>
#include "tlm_proto.h"


#define	PM_EXACT_OR_CHILD(m)	((m) == PM_EXACT || (m) == PM_CHILD)
#define	ERROR_IS_FATAL(err)	((err) == ENOSPC || (err) == EDQUOT)

typedef boolean_t name_match_fp_t(char *s, char *t);

static int set_acl(char *name, tlm_acls_t *acls);
static int restore_file(int *fp,
    char *real_name,
    long size,
    longlong_t huge_size,
    tlm_acls_t *,
    boolean_t want_this_file,
    tlm_cmd_t *,
    tlm_job_stats_t *,
    long *);
static long restore_xattr_hdr(int *fp,
    char *name,
    char *fname,
    long size,
    tlm_acls_t *acls,
    tlm_cmd_t *local_commands,
    tlm_job_stats_t *job_stats);
static int get_long_name(int lib,
    int drv,
    long recsize,
    char *name,
    long *buf_spot,
    tlm_cmd_t *local_commands);
static int get_humongus_file_header(int lib,
    int	drv,
    long recsize,
    longlong_t *size,
    char *name,
    tlm_cmd_t *);
static int create_directory(char *dir,
    tlm_job_stats_t *);
static int create_hard_link(char *name,
    char *link,
    tlm_acls_t *,
    tlm_job_stats_t *);
static int create_sym_link(char *dst,
    char *target,
    tlm_acls_t *,
    tlm_job_stats_t *);
static int create_special(char,
    char *name,
    tlm_acls_t *,
    int,
    int,
    tlm_job_stats_t *);
static long load_acl_info(int lib,
    int	drv,
    long size,
    tlm_acls_t *,
    long *acl_spot,
    tlm_cmd_t *);
static char *get_read_buffer(int want,
    int	*error,
    int	*actual_size,
    tlm_cmd_t *);
static boolean_t wildcard_enabled(void);
static boolean_t is_file_wanted(char *name,
    char **sels,
    char **exls,
    int	flags,
    int	*mchtype,
    int	*pos);
static char *catnames(struct rs_name_maker *rnp,
    char *buf,
    int	pos,
    char *path);

static char *rs_new_name(struct rs_name_maker *rnp,
    char *real_name,
    int pos,
    char *path);

static void rs_create_new_bkpath(char *bk_path,
    char *path,
    char *pbuf);

typedef struct stack_ent {
	char *se_name;
	tlm_acls_t se_acls;
} stack_ent_t;


/*
 * dtree_push
 */
int
dtree_push(cstack_t *stp, char *nmp, tlm_acls_t *acls)
{
	int len;
	stack_ent_t *sp;

	sp = ndmp_malloc(sizeof (stack_ent_t));
	if (!sp || !nmp || !acls) {
		free(sp);
		return (-1);
	}

	len = strlen(nmp) + 1;
	sp->se_name = ndmp_malloc(len);
	if (!sp->se_name) {
		free(sp);
		return (-1);
	}

	(void) strlcpy(sp->se_name, nmp, len);
	(void) memcpy(&sp->se_acls, acls, sizeof (*acls));
	(void) memset(acls, 0, sizeof (tlm_acls_t));

	return (cstack_push(stp, (void *)sp, sizeof (*sp)));
}

/*
 * dtree_pop
 */
int
dtree_pop(cstack_t *stp)
{
	int err;
	stack_ent_t *sp;

	err = cstack_pop(stp, (void **)&sp, (void *)NULL);
	if (err)
		return (-1);

	err = set_acl(sp->se_name, &sp->se_acls);

	free(sp->se_name);
	free(sp);
	return (err);
}


/*
 * dtree_peek
 */
char *
dtree_peek(cstack_t *stp)
{
	int err;
	stack_ent_t *sp;

	err = cstack_top(stp, (void **)&sp, (void *)NULL);
	if (err)
		return (NULL);

	return (sp->se_name);
}

/*
 * NBU and EBS may not send us the correct file list containing hardlinks
 * during a DAR restore, e.g. they appear always send the first name
 * associated with an inode, even if other link names were
 * selected for the restore.  As a workaround, we use the file name entry
 * in sels[] (ignore the name in the tar header) as restore target.
 */
static char *
rs_darhl_new_name(struct rs_name_maker *rnp, char *name, char **sels, int *pos,
    char *longname)
{
	int x;

	for (x = 0; sels[x] != NULL; x++) {
		if (strcmp(sels[x], " ")) {
			*pos = x;
			(void) strlcpy(longname, sels[x], TLM_MAX_PATH_NAME);
			NDMP_LOG(LOG_DEBUG,
			    "to replace hardlink name [%s], pos [%d]",
			    longname, *pos);

			return (rs_new_name(rnp, name, *pos, longname));
		}
	}

	return (NULL);
}


/*
 * Main dir restore function for tar
 *
 * If this function returns non-zero return value it means that fatal error
 * was encountered.
 */
int
tar_getdir(tlm_commands_t *commands,
    tlm_cmd_t *local_commands,
    tlm_job_stats_t *job_stats,
    struct rs_name_maker *rnp,
    int	lib,
    int	drv,
    char **sels, /* what to get off the tape */
    char **exls, /* what to leave behind */
    int	flags,
    int	DAR,
    char *bk_path,
    struct hardlink_q *hardlink_q)
{
	int	fp = 0;		/* file being restored ... */
				/*  ...need to preserve across volume changes */
	tlm_acls_t *acls;	/* file access info */
	char	*longname;
	boolean_t is_long_name = FALSE;
	char	*longlink;
	char	*hugename;
	longlong_t huge_size = 0;	/* size of a HUGE file */
	long	acl_spot;		/* any ACL info on the next volume */
	long	file_size;		/* size of file to restore */
	long	size_left = 0;		/* need this after volume change */
	int	last_action = 0;	/* what we are doing at EOT */
	boolean_t multi_volume = FALSE;	/* is this a multi-volume switch ? */
	int	chk_rv;			/* scratch area */

	int	mchtype, pos;
					/*
					 * if an exact match is found for
					 * restore and its position in the
					 * selections list
					 */
	int	nzerohdr;		/* the number of empty tar headers */
	int	rv;
	long nm_end, lnk_end;
	char	*name, *nmp;
	cstack_t *stp;
	char 	*bkpath;
	char 	*parentlnk;
	int dir_dar = 0;

	/*
	 * The directory where temporary files may be created during a partial
	 * non-DAR restore of hardlinks.  It is intended to be initialized by
	 * an environment variable that can be set by user.
	 *
	 * It is not initialized for now.   We keep it here for future use.
	 */
	char *tmplink_dir = NULL;
	int dar_recovered = 0;
	char *thname_buf;

	/*
	 * startup
	 */

	longname = ndmp_malloc(TLM_MAX_PATH_NAME);
	longlink = ndmp_malloc(TLM_MAX_PATH_NAME);
	hugename = ndmp_malloc(TLM_MAX_PATH_NAME);
	parentlnk = ndmp_malloc(TLM_MAX_PATH_NAME);
	thname_buf = ndmp_malloc(TLM_MAX_PATH_NAME);
	name = ndmp_malloc(TLM_MAX_PATH_NAME);
	acls = ndmp_malloc(sizeof (tlm_acls_t));
	stp = cstack_new();
	if (longname == NULL || longlink == NULL || hugename == NULL ||
	    name == NULL || acls == NULL || stp == NULL || parentlnk == NULL ||
	    thname_buf == NULL) {
		cstack_delete(stp);
		free(longname);
		free(longlink);
		free(hugename);
		free(parentlnk);
		free(name);
		free(acls);
		free(thname_buf);
		return (-TLM_NO_SCRATCH_SPACE);
	}

	acl_spot = 0;
	*hugename = '\0';
	*parentlnk = '\0';
	nm_end = 0;
	*longname = '\0';
	lnk_end = 0;
	*longlink = '\0';
	(void) memset(acls, 0, sizeof (tlm_acls_t));
	if (IS_SET(flags, RSFLG_OVR_ALWAYS)) {
		acls->acl_overwrite = TRUE;
		NDMP_LOG(LOG_DEBUG, "RSFLG_OVR_ALWAYS");
	} else if (IS_SET(flags, RSFLG_OVR_UPDATE)) {
		acls->acl_update = TRUE;
		NDMP_LOG(LOG_DEBUG, "RSFLG_OVR_UPDATE");
	}

	/*
	 * work
	 */
	rv = 0;
	nzerohdr = 0;
	while (commands->tcs_writer != TLM_ABORT &&
	    local_commands->tc_writer != TLM_STOP && rv == 0) {
		tlm_tar_hdr_t fake_tar_hdr;
		char	*file_name;
		char	*link_name;
		int	erc;
		int	actual_size;
		boolean_t want_this_file;
		int	want = sizeof (tlm_tar_hdr_t);
		tlm_tar_hdr_t *tar_hdr;

		/* The inode of an LF_LINK type. */
		unsigned long hardlink_inode = 0;

		/*
		 * Indicate whether a file with the same inode has been
		 * restored.
		 */
		int hardlink_done = 0;

		/* The path of the restored hardlink file */
		char *hardlink_target = NULL;
		int is_hardlink = 0;

		/*
		 * Whether a temporary file should be created for restoring
		 * hardlink.
		 */
		int hardlink_tmp_file = 0;
		char *hardlink_tmp_name = ".tmphlrsnondar";

		/* used to make up hardlink_tmp_name */
		static int hardlink_tmp_idx = 0;

		if (multi_volume) {
			NDMP_LOG(LOG_DEBUG, "multi_volume %c %d",
			    last_action, size_left);

			/*
			 * the previous volume is out of data
			 * and is back in the rack, a new tape
			 * is loaded and ready to read.
			 *
			 * We need to pick up where we left off.
			 */
			(void) memset(&fake_tar_hdr, 0, sizeof (fake_tar_hdr));
			file_size = size_left;
			tar_hdr = &fake_tar_hdr;
			tar_hdr->th_linkflag = last_action;

			multi_volume = FALSE;
			last_action = 0;
		} else {
			tar_hdr = (tlm_tar_hdr_t *)get_read_buffer(want,
			    &erc, &actual_size, local_commands);

			if (tar_hdr == NULL) {
				rv = -1;
				continue;
			}

			/*
			 * we can ignore read errors here because
			 *   1) they are logged by Restore Reader
			 *   2) we are not doing anything important here
			 *	just looking for the next work record.
			 */
			if (actual_size < want) {
				/*
				 * EOF hits here
				 *
				 * wait for another buffer to come along
				 * or until the Reader thread tells us
				 * that no more tapes will be loaded ...
				 * time to stop.
				 */
				continue;
			}

			/*
			 * check for "we are lost"
			 */
			chk_rv = tlm_vfy_tar_checksum(tar_hdr);
			if (chk_rv == 0) {
				/* one of the end of tar file marks */
				if (++nzerohdr >= 2) {
					NDMP_LOG(LOG_DEBUG,
					    "nzerohdr %d, breaking",
					    nzerohdr);
					/* end of tar file */
					break;
				}
				NDMP_LOG(LOG_DEBUG, "nzerohdr %d, continuing",
				    nzerohdr);
				continue;
			} else if (chk_rv < 0) {
				nzerohdr = 0;
				/* skip this record */
				continue;
			}
			nzerohdr = 0;

			/*
			 * When files are spanned to the next tape, the
			 * information of the acls must not be over-written
			 * by the information of the LF_MULTIVOL and LF_VOLHDR
			 * header, whose information is irrelevant to the file.
			 * The information of the original header must be
			 * kept in the 'acl'.
			 */
			if (tar_hdr->th_linkflag != LF_MULTIVOL &&
			    tar_hdr->th_linkflag != LF_VOLHDR) {
				if (tar_hdr->th_linkflag != LF_HUMONGUS) {
					acls->acl_attr.st_mode =
					    oct_atoi(tar_hdr->th_mode);
					acls->acl_attr.st_size =
					    oct_atoi(tar_hdr->th_size);
					acls->acl_attr.st_uid =
					    oct_atoi(tar_hdr->th_uid);
					acls->acl_attr.st_gid =
					    oct_atoi(tar_hdr->th_gid);
					acls->acl_attr.st_mtime =
					    oct_atoi(tar_hdr->th_mtime);
					(void) strlcpy(acls->uname,
					    tar_hdr->th_uname,
					    sizeof (acls->uname));
					(void) strlcpy(acls->gname,
					    tar_hdr->th_gname,
					    sizeof (acls->gname));
				}
				file_size = oct_atoi(tar_hdr->th_size);
				acl_spot = 0;
				last_action = tar_hdr->th_linkflag;
			}
		}

		NDMP_LOG(LOG_DEBUG, "n [%s] f [%c] s %lld m %o u %d g %d t %d",
		    tar_hdr->th_name, tar_hdr->th_linkflag,
		    acls->acl_attr.st_size, acls->acl_attr.st_mode,
		    acls->acl_attr.st_uid, acls->acl_attr.st_gid,
		    acls->acl_attr.st_mtime);

		/*
		 * If the restore is running using DAR we should check for
		 * extended attribute entries
		 */
		if (dar_recovered &&
		    tar_hdr->th_linkflag != LF_XATTR)
			break;

		rs_create_new_bkpath(bk_path, tar_hdr->th_name, thname_buf);

		switch (tar_hdr->th_linkflag) {
		case LF_MULTIVOL:
			multi_volume = TRUE;
			break;
		case LF_LINK:
			is_hardlink = 1;
			hardlink_inode =
			    oct_atoi(tar_hdr->th_shared.th_hlink_ino);

			/*
			 * Check if we have restored a link with the same inode
			 * If the inode is 0, we have to restore it as a
			 * regular file.
			 */
			if (hardlink_inode) {
				hardlink_done = !hardlink_q_get(hardlink_q,
				    hardlink_inode, 0, &hardlink_target);
			}

			if (hardlink_done) {
				NDMP_LOG(LOG_DEBUG,
				    "found hardlink, inode = %u, target = [%s]",
				    hardlink_inode,
				    hardlink_target? hardlink_target : "--");

				/* create a hardlink to hardlink_target */
				file_name = (*longname == 0) ?
				    thname_buf : longname;

				if (!is_file_wanted(file_name, sels, exls,
				    flags, &mchtype, &pos)) {
					nmp = NULL;
					/*
					 * This means that DMA did not send us
					 * the correct fh_info for the file
					 * in restore list.  We use the file
					 * name entry in sels[] (ignore the
					 * name in the tar header) as restore
					 * target.
					 */
					if (DAR) {
						nmp = rs_darhl_new_name(rnp,
						    name, sels, &pos,
						    file_name);
					}
				} else {
					nmp = rs_new_name(rnp, name, pos,
					    file_name);
					if (!nmp) {
						NDMP_LOG(LOG_DEBUG,
						    "can't make name for %s",
						    longname);
					}
				}

				if (nmp) {
					if (hardlink_target) {
						erc = create_hard_link(
						    hardlink_target, nmp,
						    acls, job_stats);
						if (ERROR_IS_FATAL(erc)) {
							rv = erc;
							continue;
						}
						if (erc == 0) {
							(void)
							    tlm_entry_restored(
							    job_stats,
							    file_name, pos);
							NDMP_LOG(LOG_DEBUG,
							    "restored %s -> %s",
							    nmp,
							    hardlink_target);
						}
					} else {
						NDMP_LOG(LOG_DEBUG,
						    "no target for hardlink %s",
						    nmp);
					}

					name[0] = 0;
					is_long_name = FALSE;
				}

				nm_end = 0;
				longname[0] = 0;
				lnk_end = 0;
				longlink[0] = 0;

				break;
			}
			/* otherwise fall through, restore like a normal file */
			/*FALLTHROUGH*/
		case LF_OLDNORMAL:
			/*
			 * check for TAR's end-of-tape method
			 * of zero filled records.
			 */
			if (tar_hdr->th_name[0] == 0) {
				break;
			}
			/*
			 * otherwise fall through,
			 * this is an old style normal file header
			 */
			/*FALLTHROUGH*/
		case LF_NORMAL:
		case LF_CONTIG:
			job_stats->js_files_so_far++;
			if (*hugename != 0) {
				(void) strlcpy(longname, hugename,
				    TLM_MAX_PATH_NAME);
			} else if (*longname == 0) {
				if (tar_hdr->th_name[0] != '/') {
					/*
					 * check for old tar format, it
					 * does not have a leading "/"
					 */
					longname[0] = '/';
					longname[1] = 0;
					(void) strlcat(longname,
					    tar_hdr->th_name,
					    TLM_MAX_PATH_NAME);
				} else {
					(void) strlcpy(longname,
					    thname_buf,
					    TLM_MAX_PATH_NAME);
				}
			}

			want_this_file = is_file_wanted(longname, sels, exls,
			    flags, &mchtype, &pos);
			if (!want_this_file) {
				nmp = NULL;
				/*
				 * This means that DMA did not send us valid
				 * fh_info for the file in restore list.  We
				 * use the file name entry in sels[] (ignore
				 * the name in the tar header) as restore
				 * target.
				 */
				if (DAR && (tar_hdr->th_linkflag == LF_LINK)) {
					nmp = rs_darhl_new_name(rnp, name,
					    sels, &pos, longname);
					if (nmp == NULL) {
						rv = ENOMEM;
						continue;
					}

					want_this_file = TRUE;
					mchtype = PM_EXACT;
				}
			} else {
				nmp = rs_new_name(rnp, name, pos, longname);
				if (!nmp)
					want_this_file = FALSE;
			}

			if (nmp)
				(void) strlcpy(parentlnk, nmp, strlen(nmp) + 1);

			/*
			 * For a hardlink, even if it's not asked to be
			 * restored, we restore it to a temporary location,
			 * in case other links to the same file need to be
			 * restored later.
			 *
			 * The temp files are created in tmplink_dir, with
			 * names like ".tmphlrsnondar*".  They are cleaned up
			 * at the completion of a restore.  However, if a
			 * restore were interrupted, e.g. by a system reboot,
			 * they would have to be cleaned up manually in order
			 * for the disk space to be freed.
			 *
			 * If tmplink_dir is NULL, no temperorary files are
			 * created during a restore.  This may result in some
			 * hardlinks not being restored during a partial
			 * restore.
			 */
			if (is_hardlink && !DAR && !want_this_file && !nmp) {
				if (tmplink_dir) {
					(void) snprintf(name, TLM_MAX_PATH_NAME,
					    "%s/%s_%d", tmplink_dir,
					    hardlink_tmp_name,
					    hardlink_tmp_idx);
					nmp = name;

					hardlink_tmp_idx++;
					hardlink_tmp_file = 1;
					want_this_file = TRUE;
					NDMP_LOG(LOG_DEBUG,
					    "To restore temp hardlink file %s.",
					    nmp);
				} else {
					NDMP_LOG(LOG_DEBUG,
					    "No tmplink_dir specified.");
				}
			}

			rv = restore_file(&fp, nmp, file_size,
			    huge_size, acls, want_this_file, local_commands,
			    job_stats, &size_left);
			if (rv != 0)
				continue;

			/*
			 * In the case of non-DAR, we have to record the first
			 * link for an inode that has multiple links. That's
			 * the only link with data records actually backed up.
			 * In this way, when we run into the other links, they
			 * will be treated as links, and we won't go to look
			 * for the data records to restore.  This is not a
			 * problem for DAR, where DMA tells the tape where
			 * to locate the data records.
			 */
			if (is_hardlink && !DAR) {
				if (hardlink_q_add(hardlink_q, hardlink_inode,
				    0, nmp, hardlink_tmp_file))
					NDMP_LOG(LOG_DEBUG,
					    "failed to add (%u, %s) to HL q",
					    hardlink_inode, nmp);
			}

			/* remove / reverse the temporary stuff */
			if (hardlink_tmp_file) {
				nmp = NULL;
				want_this_file = FALSE;
				hardlink_tmp_file = 0;
			}

			/*
			 * Check if it is time to set the attribute
			 * of the restored directory
			 */
			while (nmp && ((bkpath = dtree_peek(stp)) != NULL)) {
				int erc;

				if (strstr(nmp, bkpath))
					break;

				erc = dtree_pop(stp);
				if (ERROR_IS_FATAL(erc)) {
					rv = erc;
					break;
				}
			}
			if (rv != 0)
				continue;

			NDMP_LOG(LOG_DEBUG, "sizeleft %s %d, %lld", longname,
			    size_left, huge_size);

			if (want_this_file) {
				job_stats->js_bytes_total += file_size;
				job_stats->js_files_total++;
			}

			huge_size -= file_size;
			if (huge_size < 0) {
				huge_size = 0;
			}
			if (size_left == 0 && huge_size == 0) {
				if (PM_EXACT_OR_CHILD(mchtype)) {
					(void) tlm_entry_restored(job_stats,
					    longname, pos);

					/*
					 * Add an entry to hardlink_q to record
					 * this hardlink.
					 */
					if (is_hardlink) {
						NDMP_LOG(LOG_DEBUG,
						    "Restored hardlink file %s",
						    nmp);

						if (DAR) {
							(void) hardlink_q_add(
							    hardlink_q,
							    hardlink_inode, 0,
							    nmp, 0);
						}
					}
				}

				nm_end = 0;
				longname[0] = 0;
				lnk_end = 0;
				longlink[0] = 0;
				hugename[0] = 0;
				name[0] = 0;
				is_long_name = FALSE;
			}
			break;
		case LF_XATTR:
			file_name = (*longname == 0) ? thname_buf :
			    longname;

			size_left = restore_xattr_hdr(&fp, parentlnk,
			    file_name, file_size, acls, local_commands,
			    job_stats);

			break;
		case LF_SYMLINK:
			file_name = (*longname == 0) ? thname_buf :
			    longname;
			link_name = (*longlink == 0) ?
			    tar_hdr->th_linkname : longlink;
			NDMP_LOG(LOG_DEBUG, "file_name[%s]", file_name);
			NDMP_LOG(LOG_DEBUG, "link_name[%s]", link_name);
			if (is_file_wanted(file_name, sels, exls, flags,
			    &mchtype, &pos)) {
				nmp = rs_new_name(rnp, name, pos, file_name);
				if (nmp) {
					erc = create_sym_link(nmp, link_name,
					    acls, job_stats);
					if (ERROR_IS_FATAL(erc)) {
						rv = erc;
						continue;
					}
					if (erc == 0 &&
					    PM_EXACT_OR_CHILD(mchtype))
						(void) tlm_entry_restored(
						    job_stats, file_name, pos);
					name[0] = 0;
				}
			}
			nm_end = 0;
			longname[0] = 0;
			lnk_end = 0;
			longlink[0] = 0;
			break;
		case LF_DIR:
			file_name = *longname == 0 ? thname_buf :
			    longname;
			if (is_file_wanted(file_name, sels, exls, flags,
			    &mchtype, &pos)) {
				dir_dar = DAR;
				nmp = rs_new_name(rnp, name, pos, file_name);
				if (nmp && mchtype != PM_PARENT) {
					(void) strlcpy(parentlnk, nmp,
					    strlen(nmp));
					erc = create_directory(nmp, job_stats);
					if (ERROR_IS_FATAL(erc)) {
						rv = erc;
						continue;
					}
					if (erc == 0 &&
					    PM_EXACT_OR_CHILD(mchtype))
						(void) tlm_entry_restored(
						    job_stats, file_name, pos);
					/*
					 * Check if it is time to set
					 * the attribute of the restored
					 * directory
					 */
					while ((bkpath = dtree_peek(stp))
					    != NULL) {
						int rc;

						if (strstr(nmp, bkpath))
							break;
						rc = dtree_pop(stp);
						if (ERROR_IS_FATAL(rc)) {
							rv = rc;
							break;
						}
					}
					if (rv != 0)
						continue;

					(void) dtree_push(stp, nmp, acls);
					name[0] = 0;
				}
			} else {
				dir_dar = 0;
			}
			nm_end = 0;
			longname[0] = 0;
			lnk_end = 0;
			longlink[0] = 0;
			break;
		case LF_FIFO:
		case LF_BLK:
		case LF_CHR:
			file_name = *longname == 0 ? thname_buf :
			    longname;
			if (is_file_wanted(file_name, sels, exls, flags,
			    &mchtype, &pos)) {
				nmp = rs_new_name(rnp, name, pos, file_name);
				if (nmp) {
					erc = create_special(
					    tar_hdr->th_linkflag, nmp, acls,
					    oct_atoi(tar_hdr->th_shared.
					    th_dev.th_devmajor),
					    oct_atoi(tar_hdr->th_shared.
					    th_dev.th_devminor), job_stats);
					if (ERROR_IS_FATAL(erc)) {
						rv = erc;
						continue;
					}
					if (erc == 0 &&
					    PM_EXACT_OR_CHILD(mchtype))
						(void) tlm_entry_restored(
						    job_stats, file_name, pos);
					name[0] = 0;
				}
			}
			nm_end = 0;
			longname[0] = 0;
			lnk_end = 0;
			longlink[0] = 0;
			break;
		case LF_LONGLINK:
			file_size = min(file_size,
			    TLM_MAX_PATH_NAME - lnk_end - 1);
			file_size = max(0, file_size);
			size_left = get_long_name(lib, drv, file_size, longlink,
			    &lnk_end, local_commands);

			if (size_left != 0)
				NDMP_LOG(LOG_DEBUG,
				    "fsize %d sleft %d lnkend %d",
				    file_size, size_left, lnk_end);
			break;
		case LF_LONGNAME:
			file_size = min(file_size,
			    TLM_MAX_PATH_NAME - nm_end - 1);
			file_size = max(0, file_size);
			size_left = get_long_name(lib, drv, file_size, longname,
			    &nm_end, local_commands);

			if (size_left != 0)
				NDMP_LOG(LOG_DEBUG,
				    "fsize %d sleft %d nmend %d",
				    file_size, size_left, nm_end);
			is_long_name = TRUE;
			break;
		case LF_ACL:
			size_left = load_acl_info(lib, drv, file_size, acls,
			    &acl_spot, local_commands);
			break;
		case LF_VOLHDR:
			break;
		case LF_HUMONGUS:
			(void) memset(hugename, 0, TLM_MAX_PATH_NAME);
			(void) get_humongus_file_header(lib, drv, file_size,
			    &huge_size, hugename, local_commands);
			break;
		default:
			break;

		}

		/*
		 * If the restore is running using DAR we should check for
		 * long file names and HUGE file sizes.
		 */
		if (DAR && tar_hdr->th_linkflag != LF_ACL &&
		    tar_hdr->th_linkflag != LF_XATTR &&
		    !huge_size && !is_long_name && !dir_dar)
			dar_recovered = 1;
	}

	/*
	 * tear down
	 */
	if (rv != 0)
		commands->tcs_reader = TLM_ABORT;
	if (fp != 0) {
		(void) close(fp);
	}
	while (dtree_pop(stp) != -1)
		;
	cstack_delete(stp);
	free(acls);
	free(longname);
	free(parentlnk);
	free(longlink);
	free(hugename);
	free(name);
	free(thname_buf);
	return (rv);
}

/*
 * Main file restore function for tar (should run as a thread)
 */
int
tar_getfile(tlm_backup_restore_arg_t *argp)
{
	tlm_job_stats_t	*job_stats;
	char	**sels;		/* list of files desired */
	char	**exls;		/* list of files not wanted */
	char	*dir;		/* where to restore the files */
	char	job[TLM_MAX_BACKUP_JOB_NAME+1];
				/* the restore job name */
	int	erc;		/* error return codes */
	int	flags;
	struct	rs_name_maker rn;
	tlm_commands_t *commands;
	tlm_cmd_t *local_commands;
	char *list = NULL;

	commands = argp->ba_commands;
	local_commands = argp->ba_cmd;

	flags = 0;

	dir = ndmp_malloc(TLM_MAX_PATH_NAME);
	if (dir == NULL) {
		local_commands->tc_reader = TLM_STOP;
		(void) pthread_barrier_wait(&argp->ba_barrier);
		return (-1);
	}

	(void) strlcpy(job, argp->ba_job, TLM_MAX_BACKUP_JOB_NAME+1);
	(void) strlcpy(dir, argp->ba_dir, TLM_MAX_PATH_NAME);

	flags |= RSFLG_OVR_ALWAYS;
	flags |= RSFLG_IGNORE_CASE;

	/*
	 * do not test for "dir" having no string, since that
	 * is a legal condition.  Restore to origional location
	 * will not have a restore directory.
	 */
	if (*job == '\0') {
		NDMP_LOG(LOG_DEBUG, "No job defined");
		local_commands->tc_reader = TLM_STOP;
		free(dir);
		(void) pthread_barrier_wait(&argp->ba_barrier);
		return (-1);
	}

	sels = argp->ba_sels;
	if (sels == NULL) {
		local_commands->tc_reader = TLM_STOP;
		free(dir);
		(void) pthread_barrier_wait(&argp->ba_barrier);
		return (-1);
	}
	exls = &list;

	tlm_log_list("selections", sels);
	tlm_log_list("exclusions", exls);

	if (wildcard_enabled())
		flags |= RSFLG_MATCH_WCARD;

	local_commands->tc_ref++;
	commands->tcs_writer_count++;

	/*
	 * let the launcher continue
	 */
	(void) pthread_barrier_wait(&argp->ba_barrier);

	job_stats = tlm_ref_job_stats(job);

	rn.rn_fp = catnames;
	rn.rn_nlp = dir;

	/*
	 * work
	 */
	NDMP_LOG(LOG_DEBUG, "start restore job %s", job);
	erc = tar_getdir(commands, local_commands, job_stats, &rn, 1, 1,
	    sels, exls, flags, 0, NULL, NULL);

	/*
	 * teardown
	 */
	NDMP_LOG(LOG_DEBUG, "end restore job %s", job);
	tlm_un_ref_job_stats(job);
	tlm_release_list(sels);
	tlm_release_list(exls);

	commands->tcs_writer_count--;
	local_commands->tc_reader = TLM_STOP;
	tlm_release_reader_writer_ipc(local_commands);
	free(dir);
	return (erc);
}

/*
 * Creates the directories all the way down to the
 * end if they dont exist
 */
int
make_dirs(char *dir)
{
	char c;
	char *cp, *end;
	struct stat64 st;

	cp = dir;
	cp += strspn(cp, "/");
	end = dir + strlen(dir);
	do {
		if (*cp == '\0' || *cp == '/') {
			c = *cp;
			*cp = '\0';
			if (lstat64(dir, &st) < 0)
				if (mkdir(dir, 0777) < 0) {
					NDMP_LOG(LOG_DEBUG, "Error %d"
					    " creating directory %s",
					    errno, dir);
					*cp = c;
					return (errno);
				}

			*cp = c;
		}
	} while (++cp <= end);

	return (0);
}

/*
 * Creates the directories leading to the given path
 */
int
mkbasedir(char *path)
{
	int rv;
	char *cp;
	struct stat64 st;

	if (!path || !*path) {
		NDMP_LOG(LOG_DEBUG, "Invalid argument");
		return (-1);
	}

	cp = strrchr(path, '/');
	if (cp)
		*cp = '\0';
	rv = lstat64(path, &st);
	if (rv < 0)	/* need new directories */
		rv = make_dirs(path);
	if (cp)
		*cp = '/';

	return (rv);
}


/*
 * read the file off the tape back onto disk
 *
 * If the function returns a non-zero return code, it means that fatal error
 * was encountered and restore should terminate immediately.
 */
static int
restore_file(int *fp,
    char *real_name,
    long size,
    longlong_t huge_size,
    tlm_acls_t *acls,
    boolean_t want_this_file,
    tlm_cmd_t *local_commands,
    tlm_job_stats_t *job_stats,
    long *size_left)
{
	struct stat64	attr;
	int	ret, rv;

	*size_left = 0;
	if (!real_name) {
		if (want_this_file) {
			NDMP_LOG(LOG_DEBUG, "No file name but wanted!");
			want_this_file = FALSE;
		}
	} else
		NDMP_LOG(LOG_DEBUG, "new file[%s]", real_name);

	/*
	 * OK, some FM is creeping in here ...
	 * int *fp is used to keep the
	 * backup file channel open through
	 * the interruption of EOT and
	 * processing the headers of the
	 * next tape.  So, if *fp is zero
	 * then no file is open yet and all
	 * is normal.  If *fp has a number
	 * then we are returning after an
	 * EOT break.
	 *
	 * *fp is now also open for HUGE files
	 * that are put back in sections.
	 */

	if (*fp == 0 && want_this_file) {

		ret = mkbasedir(real_name);
		if (ret != 0) {
			job_stats->js_errors++;
			if (ERROR_IS_FATAL(ret))
				return (ret);
		}

		ret = stat64(real_name, (struct stat64 *)&attr);
		if (ret < 0) {
			/*EMPTY*/
			/* new file */
		} else if (acls->acl_overwrite) {
			/*EMPTY*/
			/* take this file no matter what */
		} else if (acls->acl_update) {
			if (attr.st_mtime < acls->acl_attr.st_mtime) {
				/*EMPTY*/
				/* tape is newer */
			} else {
				/* disk file is newer */
				want_this_file = FALSE;
			}
		} else {
			/*
			 * no overwrite, no update,
			 * do not ever replace old files.
			 */
			want_this_file = TRUE;
		}
		if (want_this_file) {

			*fp = open(real_name, O_CREAT | O_TRUNC | O_WRONLY,
			    S_IRUSR | S_IWUSR);
			if (*fp == -1) {
				NDMP_LOG(LOG_ERR,
				    "Could not open %s for restore: %d",
				    real_name, errno);
				job_stats->js_errors++;
				want_this_file = FALSE;
				/*
				 * In case of non-fatal error we cannot return
				 * here, because the file is still on the tape
				 * and must be skipped over.
				 */
				if (ERROR_IS_FATAL(errno))
					return (errno);
			}
		}
		(void) strlcpy(local_commands->tc_file_name, real_name,
		    TLM_MAX_PATH_NAME);
	}

	/*
	 * this is the size left in the next segment
	 */
	huge_size -= size;

	/*
	 * work
	 */
	rv = 0;
	while (size > 0 && local_commands->tc_writer == TLM_RESTORE_RUN) {
		int	actual_size;
		int	error;
		char	*rec;
		int	write_size;

		/*
		 * Use bytes_in_file field to tell reader the amount
		 * of data still need to be read for this file.
		 */
		job_stats->js_bytes_in_file = size;

		error = 0;
		rec = get_read_buffer(size, &error, &actual_size,
		    local_commands);
		if (actual_size <= 0) {
			NDMP_LOG(LOG_DEBUG,
			    "RESTORE WRITER> error %d, actual_size %d",
			    error, actual_size);

			/* no more data for this file for now */
			job_stats->js_bytes_in_file = 0;
			*size_left = size;
			return (0);
		} else if (error) {
			NDMP_LOG(LOG_DEBUG, "Error %d in file [%s]",
			    error, local_commands->tc_file_name);
			break;
		}

		write_size = min(size, actual_size);
		if (want_this_file) {
			ret = write(*fp, rec, write_size);
			if (ret < 0) {
				NDMP_LOG(LOG_ERR,
				    "Write error %d for file [%s]", errno,
				    local_commands->tc_file_name);
				job_stats->js_errors++;
				if (ERROR_IS_FATAL(errno)) {
					rv = errno;
					break;
				}
			} else {
				NS_ADD(wdisk, ret);
				NS_INC(wfile);
				if (ret < write_size) {
					NDMP_LOG(LOG_ERR,
					    "Partial write for file [%s]",
					    local_commands->tc_file_name);
				}
			}
		}
		size -= write_size;
	}

	/* no more data for this file for now */
	job_stats->js_bytes_in_file = 0;

	/*
	 * teardown
	 */
	if (*fp != 0 && huge_size <= 0) {
		(void) close(*fp);
		*fp = 0;
		if (rv == 0) {
			ret = set_acl(real_name, acls);
			if (ERROR_IS_FATAL(ret))
				return (ret);
		}
	}
	return (rv);
}

/*
 * Set the extended attributes file attribute
 */
static void
set_xattr(int fd, struct stat64 st)
{
	struct timeval times[2];

	times[0].tv_sec = st.st_atime;
	times[1].tv_sec = st.st_mtime;

	(void) fchmod(fd, st.st_mode);
	(void) fchown(fd, st.st_uid, st.st_gid);
	(void) futimesat(fd, ".", times);
}

/*
 * Read the system attribute file in a single buffer to write
 * it as a single write. A partial write to system attribute would
 * cause an EINVAL on write.
 */
static char *
get_read_one_buf(char *rec, int actual_size, int size, int *error,
    tlm_cmd_t *lc)
{
	char *buf, *p;
	int read_size;
	int len;

	if (actual_size > size)
		return (rec);

	buf = ndmp_malloc(size);
	if (buf == NULL) {
		*error = ENOMEM;
		return (NULL);
	}
	(void) memcpy(buf, rec, actual_size);
	rec = buf;
	buf += actual_size;
	while (actual_size < size) {
		p = get_read_buffer(size - actual_size, error, &read_size, lc);
		len = min(size - actual_size, read_size);
		(void) memcpy(buf, p, len);
		actual_size += len;
		buf += len;
	}
	return (rec);
}


/*
 * read the extended attribute header and write
 * it to the file
 */
static long
restore_xattr_hdr(int *fp,
    char *name,
    char *fname,
    long size,
    tlm_acls_t *acls,
    tlm_cmd_t *local_commands,
    tlm_job_stats_t *job_stats)
{
	tlm_tar_hdr_t *tar_hdr;
	struct xattr_hdr *xhdr;
	struct xattr_buf *xbuf;
	int namelen;
	char *xattrname;
	int actual_size;
	int error;

	if (!fname) {
		NDMP_LOG(LOG_DEBUG, "No file name but wanted!");
	} else {
		NDMP_LOG(LOG_DEBUG, "new xattr[%s]", fname);
	}

	error = 0;
	xhdr = (struct xattr_hdr *)get_read_buffer(size, &error,
	    &actual_size, local_commands);
	if (xhdr == NULL || error != 0) {
		NDMP_LOG(LOG_DEBUG,
		    "Could not read xattr [%s:%s] for restore. ",
		    name, fname);
		job_stats->js_errors++;
		return (0);
	}

	/* Check extended attribute header */
	if (strcmp(xhdr->h_version, XATTR_ARCH_VERS) != 0) {
		NDMP_LOG(LOG_DEBUG,
		    "Unrecognized header format [%s]", xhdr->h_version);
		return (0);
	}
	xbuf = (struct xattr_buf *)(((char *)xhdr) + sizeof (struct xattr_hdr));

	(void) sscanf(xbuf->h_namesz, "%7d", &namelen);
	xattrname = xbuf->h_names + strlen(xbuf->h_names) + 1;

	if (*fp == 0) {
		int fd;

		fd = attropen(name, xattrname, O_CREAT | O_RDWR, 0755);
		if (fd == -1) {
			NDMP_LOG(LOG_DEBUG,
			    "Could not open xattr [%s:%s] for restore err=%d.",
			    name, xattrname, errno);
			job_stats->js_errors++;
			return (0);
		}
		(void) strlcpy(local_commands->tc_file_name, xattrname,
		    TLM_MAX_PATH_NAME);
		*fp = fd;
	}

	/* Get the actual extended attribute file */
	tar_hdr = (tlm_tar_hdr_t *)get_read_buffer(sizeof (*tar_hdr),
	    &error, &actual_size, local_commands);
	if (tar_hdr == NULL || error != 0) {
		NDMP_LOG(LOG_DEBUG,
		    "Could not read xattr data [%s:%s] for restore. ",
		    fname, xattrname);
		job_stats->js_errors++;
		return (0);
	}
	acls->acl_attr.st_mode = oct_atoi(tar_hdr->th_mode);
	acls->acl_attr.st_size = oct_atoi(tar_hdr->th_size);
	acls->acl_attr.st_uid = oct_atoi(tar_hdr->th_uid);
	acls->acl_attr.st_gid = oct_atoi(tar_hdr->th_gid);
	acls->acl_attr.st_mtime = oct_atoi(tar_hdr->th_mtime);

	NDMP_LOG(LOG_DEBUG, "xattr_hdr: %s size %d mode %06o uid %d gid %d",
	    xattrname, acls->acl_attr.st_size, acls->acl_attr.st_mode,
	    acls->acl_attr.st_uid, acls->acl_attr.st_gid);

	size = acls->acl_attr.st_size;
	while (size > 0 && local_commands->tc_writer == TLM_RESTORE_RUN) {
		char	*rec;
		int	write_size;
		int	sysattr_write = 0;

		error = 0;
		rec = get_read_buffer(size, &error, &actual_size,
		    local_commands);

		if ((actual_size < size) && sysattr_rw(xattrname)) {
			rec = get_read_one_buf(rec, actual_size, size, &error,
			    local_commands);
			if (rec == NULL) {
				NDMP_LOG(LOG_DEBUG, "Error %d in file [%s]",
				    error, xattrname);
				return (size);
			}
			actual_size = size;
			sysattr_write = 1;
		}
		if (actual_size <= 0) {
			NDMP_LOG(LOG_DEBUG,
			    "RESTORE WRITER> error %d, actual_size %d",
			    error, actual_size);

			return (size);
		} else if (error) {
			NDMP_LOG(LOG_DEBUG, "Error %d in file [%s]",
			    error, local_commands->tc_file_name);
			break;
		} else {
			write_size = min(size, actual_size);
			if ((write_size = write(*fp, rec, write_size)) < 0) {
				if (sysattr_write)
					free(rec);

				break;
			}

			NS_ADD(wdisk, write_size);
			NS_INC(wfile);
			size -= write_size;
		}
		if (sysattr_write)
			free(rec);
	}

	if (*fp != 0) {
		set_xattr(*fp, acls->acl_attr);
		(void) close(*fp);
		*fp = 0;
	}
	return (0);
}

/*
 * Match the name with the list
 */
static int
exact_find(char *name, char **list)
{
	boolean_t found;
	int i;
	char *cp;

	found = FALSE;
	for (i = 0; *list != NULL; list++, i++) {
		cp = *list + strspn(*list, "/");
		if (match(cp, name)) {
			found = TRUE;
			NDMP_LOG(LOG_DEBUG, "exact_find> found[%s]", cp);
			break;
		}
	}

	return (found);
}

/*
 * On error, return FALSE and prevent restoring(probably) unwanted data.
 */
static int
is_parent(char *parent, char *child, int flags)
{
	char tmp[TLM_MAX_PATH_NAME];
	boolean_t rv;

	if (IS_SET(flags, RSFLG_MATCH_WCARD)) {
		if (!tlm_cat_path(tmp, parent, "*")) {
			NDMP_LOG(LOG_DEBUG,
			    "is_parent> path too long [%s]", parent);
			rv = FALSE;
		} else
			rv = (match(tmp, child) != 0) ? TRUE : FALSE;
	} else {
		if (!tlm_cat_path(tmp, parent, "/")) {
			NDMP_LOG(LOG_DEBUG,
			    "is_parent> path too long [%s]", parent);
			rv = FALSE;
		} else
			rv = (strncmp(tmp, child, strlen(tmp)) == 0) ?
			    TRUE : FALSE;
	}

	return (rv);
}

/*
 * Used to match the filename inside the list
 */
static boolean_t
strexactcmp(char *s, char *t)
{
	return ((strcmp(s, t) == 0) ? TRUE : FALSE);
}

/*
 * Check if the file is needed to be restored
 */
static boolean_t
is_file_wanted(char *name,
    char **sels,
    char **exls,
    int flags,
    int *mchtype,
    int *pos)
{
	char *p_sel;
	char *uc_name, *retry, *namep;
	boolean_t found;
	int i;
	name_match_fp_t *cmp_fp;

	if (name == NULL || sels == NULL || exls == NULL)
		return (FALSE);

	found = FALSE;
	if (mchtype != NULL)
		*mchtype = PM_NONE;
	if (pos != NULL)
		*pos = 0;

	/*
	 * For empty selection, restore everything
	 */
	if (*sels == NULL || **sels == '\0') {
		NDMP_LOG(LOG_DEBUG, "is_file_wanted: Restore all");
		return (TRUE);
	}

	retry = ndmp_malloc(TLM_MAX_PATH_NAME);
	if (retry == NULL)
		return (FALSE);

	if (IS_SET(flags, RSFLG_MATCH_WCARD))
		cmp_fp = match;
	else
		cmp_fp = strexactcmp;

	namep = name + strspn(name, "/");

	if (IS_SET(flags, RSFLG_IGNORE_CASE)) {
		uc_name = ndmp_malloc(TLM_MAX_PATH_NAME);
		if (uc_name == NULL) {
			free(retry);
			return (FALSE);
		}
		(void) strlcpy(uc_name, namep, TLM_MAX_PATH_NAME);
		(void) strupr(uc_name);
		namep = uc_name;
	}
	NDMP_LOG(LOG_DEBUG, "is_file_wanted> flg: 0x%x name: [%s]",
	    flags, name);

	for (i = 0; *sels != NULL; sels++, i++) {
		p_sel = *sels + strspn(*sels, "/");

		/*
		 * Try exact match.
		 */
		if ((*cmp_fp)(p_sel, namep)) {
			NDMP_LOG(LOG_DEBUG, "match1> pos: %d [%s][%s]",
			    i, p_sel, name);
			found = TRUE;
			if (mchtype != NULL)
				*mchtype = PM_EXACT;
			break;
		}
		/*
		 * Try "entry/" and the current selection.  The
		 * current selection may be something like "<something>/".
		 */
		(void) tlm_cat_path(retry, namep, "/");
		if ((*cmp_fp)(p_sel, retry)) {
			NDMP_LOG(LOG_DEBUG, "match2> pos %d [%s][%s]",
			    i, p_sel, name);
			found = TRUE;
			if (mchtype != NULL)
				*mchtype = PM_EXACT;
			break;
		}
		/*
		 * If the following check returns true it means that the
		 * 'name' is an entry below the 'p_sel' hierarchy.
		 */
		if (is_parent(p_sel, namep, flags)) {
			NDMP_LOG(LOG_DEBUG, "parent1> pos %d [%s][%s]",
			    i, p_sel, name);
			found = TRUE;
			if (mchtype != NULL)
				*mchtype = PM_CHILD;
			break;
		}
		/*
		 * There is a special case for parent directories of a
		 * selection.  If 'p_sel' is something like "*d1", the
		 * middle directories of the final entry can't be determined
		 * until the final entry matches with 'p_sel'.  At that
		 * time the middle directories of the entry have been passed
		 * and they can't be restored.
		 */
		if (is_parent(namep, p_sel, flags)) {
			NDMP_LOG(LOG_DEBUG, "parent2> pos %d [%s][%s]",
			    i, p_sel, name);
			found = TRUE;
			if (mchtype != NULL)
				*mchtype = PM_PARENT;
			break;
		}
	}

	/* Check for exclusions.  */
	if (found && exact_find(namep, exls)) {
		if (mchtype != NULL)
			*mchtype = PM_NONE;
		found = FALSE;
	}
	if (found && pos != NULL)
		*pos = i;

	if (IS_SET(flags, RSFLG_IGNORE_CASE))
		free(uc_name);
	free(retry);
	return (found);
}

/*
 * Read the specified amount data into the buffer.  Detects EOT or EOF
 * during read.
 *
 * Returns the number of bytes actually read.  On error returns -1.
 */
static int
input_mem(int l,
    int d,
    tlm_cmd_t *lcmds,
    char *mem,
    int len)
{
	int err;
	int toread, actual_size, rec_size;
	char *rec;

	if (l <= 0 || d <= 0 || !lcmds || !mem) {
		NDMP_LOG(LOG_DEBUG, "Invalid argument");
		return (-1);
	}

	toread = len;
	while (toread > 0) {
		rec = get_read_buffer(toread, &err, &actual_size, lcmds);
		if (actual_size <= 0) {
			NDMP_LOG(LOG_DEBUG, "err %d act_size %d detected",
			    err, actual_size);
			break;
		} else if (err) {
			NDMP_LOG(LOG_DEBUG, "error %d reading data", err);
			return (-1);
		}
		rec_size = min(actual_size, toread);
		(void) memcpy(mem, rec, rec_size);
		mem += rec_size;
		toread -= rec_size;
	}

	return (len - toread);
}

/*
 * pick up the name and size of a HUGE file
 */
static	int
get_humongus_file_header(int lib,
    int	drv,
    long recsize,
    longlong_t *size,
    char *name,
    tlm_cmd_t *local_commands)
{
	char *p_record, *value;
	int rv;

	NDMP_LOG(LOG_DEBUG, "HUGE Record found: %d", recsize);

	rv = 0;
	if (recsize == 0) {
		/*
		 * The humongus_file_header was written in a
		 * RECORDSIZE block and the header.size field of this
		 * record was 0 before this fix.  For backward compatiblity
		 * read only one RECORDSIZE-size block if the header.size
		 * field is 0.  Otherwise the header.size field should show
		 * the length of the data of this header.
		 */
		NDMP_LOG(LOG_DEBUG, "Old HUGE record found");
		recsize = RECORDSIZE;
	}

	if (input_mem(lib, drv, local_commands, name, recsize) != recsize) {
		rv = -1;
		*size = 0;
		*name = '\0';
		NDMP_LOG(LOG_DEBUG, "Error reading a HUGE file name");
	} else {
		NDMP_LOG(LOG_DEBUG, "HUGE [%s]", name);

		p_record = name;
		value = parse(&p_record, " ");
		*size = atoll(value);
		/*
		 * Note: Since the backed up names are not longer than
		 * NAME_MAX and the buffer passed to us is
		 * TLM_MAX_PATH_NAME, it should be safe to use strlcpy
		 * without check on the buffer size.
		 */
		(void) strlcpy(name, p_record, TLM_MAX_PATH_NAME);
	}

	NDMP_LOG(LOG_DEBUG, "HUGE Record %lld [%s]", *size, name);

	return (rv);
}

/*
 * pick up the long name from the special tape file
 */
static int
get_long_name(int lib,
    int drv,
    long recsize,
    char *name,
    long *buf_spot,
    tlm_cmd_t *local_commands)
{
	int nread;

	NDMP_LOG(LOG_DEBUG, "LONGNAME Record found rs %d bs %d", recsize,
	    *buf_spot);

	if (*buf_spot < 0)
		*buf_spot = 0;

	nread = input_mem(lib, drv, local_commands, name + *buf_spot,
	    recsize);
	if (nread < 0) {
		nread = recsize; /* return 0 as size left */
		name[*buf_spot] = '\0';
		NDMP_LOG(LOG_ERR, "Error %d reading a long file name %s.",
		    nread, name);
	} else {
		*buf_spot += nread;
		name[*buf_spot] = '\0';
		NDMP_LOG(LOG_DEBUG, "LONGNAME [%s]", name);
	}

	return (recsize - nread);
}

/*
 * create a new directory
 */
static int
create_directory(char *dir, tlm_job_stats_t *job_stats)
{
	struct stat64 attr;
	char	*p;
	char	temp;
	int	erc;

	/*
	 * Make sure all directories in this path exist, create them if
	 * needed.
	 */
	NDMP_LOG(LOG_DEBUG, "new dir[%s]", dir);

	erc = 0;
	p = &dir[1];
	do {
		temp = *p;
		if (temp == '/' || temp == 0) {
			*p = 0;
			if (stat64(dir, &attr) < 0) {
				if (mkdir(dir, 0777) != 0 && errno != EEXIST) {
					erc = errno;
					job_stats->js_errors++;
					NDMP_LOG(LOG_DEBUG,
					    "Could not create directory %s: %d",
					    dir, errno);
					break;
				}
			}
			*p = temp;
		}
		p++;
	} while (temp != 0);

	return (erc);
}

/*
 * create a new hardlink
 */
static int
create_hard_link(char *name_old, char *name_new,
    tlm_acls_t *acls, tlm_job_stats_t *job_stats)
{
	int erc;

	erc = mkbasedir(name_new);
	if (erc != 0)
		return (erc);

	if (link(name_old, name_new) != 0)
		erc = errno;

	if (erc) {
		/* Nothing to do if the destination already exists */
		if (erc == EEXIST)
			return (0);
		job_stats->js_errors++;
		NDMP_LOG(LOG_DEBUG, "error %d (errno %d) hardlink [%s] to [%s]",
		    erc, errno, name_new, name_old);
		return (erc);
	}
	return (set_acl(name_new, acls));
}

/*
 * create a new symlink
 */
/*ARGSUSED*/
static int
create_sym_link(char *dst, char *target, tlm_acls_t *acls,
    tlm_job_stats_t *job_stats)
{
	int erc;
	struct stat64 *st;

	erc = mkbasedir(dst);
	if (erc != 0)
		return (erc);

	st = &acls->acl_attr;
	if (symlink(target, dst) != 0) {
		erc = errno;
		job_stats->js_errors++;
		NDMP_LOG(LOG_DEBUG, "error %d softlink [%s] to [%s]",
		    errno, dst, target);
	} else {
		st->st_mode |= S_IFLNK;
		erc = set_acl(dst, acls);
	}

	return (erc);
}

/*
 * create a new FIFO, char/block device special files
 */
static int
create_special(char flag, char *name, tlm_acls_t *acls, int major, int minor,
    tlm_job_stats_t *job_stats)
{
	dev_t dev;
	mode_t mode;

	switch (flag) {
	case LF_CHR:
		mode = S_IFCHR;
		dev = makedev(major, minor);
		break;
	case LF_BLK:
		mode = S_IFBLK;
		dev = makedev(major, minor);
		break;
	case LF_FIFO:
		mode = S_IFIFO;
		dev = 0;
		break;
	default:
		NDMP_LOG(LOG_ERR, "unsupported flag %d", flag);
		return (-1);
	}

	/* Remove the old entry first */
	if (rmdir(name) < 0) {
		if (errno == ENOTDIR)
			(void) unlink(name);
	}
	if (mknod(name, 0777 | mode, dev) != 0) {
		job_stats->js_errors++;
		NDMP_LOG(LOG_DEBUG, "error %d mknod [%s] major"
		    " %d minor %d", errno, name, major, minor);
		return (errno);
	}
	return (set_acl(name, acls));
}

/*
 * read in the ACLs for the next file
 */
static long
load_acl_info(int lib,
    int drv,
    long file_size,
    tlm_acls_t *acls,
    long *acl_spot,
    tlm_cmd_t *local_commands)
{
	char *bp;
	int nread;

	/*
	 * If the ACL is spanned on tapes, then the acl_spot should NOT be
	 * 0 on next calls to this function to read the rest of the ACL
	 * on next tapes.
	 */
	if (*acl_spot == 0) {
		(void) memset(acls, 0, sizeof (tlm_acls_t));
	}

	bp = ((char *)&acls->acl_info) + *acl_spot;
	nread = input_mem(lib, drv, local_commands, (void *)bp, file_size);
	if (nread < 0) {
		*acl_spot = 0;
		(void) memset(acls, 0, sizeof (tlm_acls_t));
		NDMP_LOG(LOG_DEBUG, "Error reading ACL data");
		return (0);
	}
	*acl_spot += nread;
	acls->acl_non_trivial = TRUE;

	return (file_size - nread);
}

static int
ndmp_set_eprivs_least(void)
{
	priv_set_t *priv_set;

	if ((priv_set = priv_allocset()) == NULL) {
		NDMP_LOG(LOG_ERR, "Out of memory.");
		return (-1);
	}

	priv_basicset(priv_set);

	(void) priv_addset(priv_set, PRIV_PROC_AUDIT);
	(void) priv_addset(priv_set, PRIV_PROC_SETID);
	(void) priv_addset(priv_set, PRIV_PROC_OWNER);
	(void) priv_addset(priv_set, PRIV_FILE_CHOWN);
	(void) priv_addset(priv_set, PRIV_FILE_CHOWN_SELF);
	(void) priv_addset(priv_set, PRIV_FILE_DAC_READ);
	(void) priv_addset(priv_set, PRIV_FILE_DAC_SEARCH);
	(void) priv_addset(priv_set, PRIV_FILE_DAC_WRITE);
	(void) priv_addset(priv_set, PRIV_FILE_OWNER);
	(void) priv_addset(priv_set, PRIV_FILE_SETID);
	(void) priv_addset(priv_set, PRIV_SYS_LINKDIR);
	(void) priv_addset(priv_set, PRIV_SYS_DEVICES);
	(void) priv_addset(priv_set, PRIV_SYS_MOUNT);
	(void) priv_addset(priv_set, PRIV_SYS_CONFIG);

	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, priv_set) == -1) {
		NDMP_LOG(LOG_ERR, "Additional privileges required.");
		priv_freeset(priv_set);
		return (-1);
	}
	priv_freeset(priv_set);
	return (0);
}

static int
ndmp_set_eprivs_all(void)
{
	priv_set_t *priv_set;

	if ((priv_set = priv_allocset()) == NULL) {
		NDMP_LOG(LOG_ERR, "Out of memory.");
		return (-1);
	}

	priv_fillset(priv_set);

	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, priv_set) != 0) {
		NDMP_LOG(LOG_ERR, "Additional privileges required.");
		return (-1);
	}
	priv_freeset(priv_set);
	return (0);
}

/*
 * Set the standard attributes of the file
 */
static int
set_attr(char *name, tlm_acls_t *acls)
{
	struct utimbuf tbuf;
	boolean_t priv_all = FALSE;
	struct stat64 *st;
	uid_t uid;
	gid_t gid;
	struct passwd *pwd;
	struct group *grp;
	int erc = 0;


	if (!name || !acls)
		return (0);

	st = &acls->acl_attr;
	NDMP_LOG(LOG_DEBUG, "set_attr: %s uid %d gid %d uname %s gname %s "
	    "mode %o", name, st->st_uid, st->st_gid, acls->uname, acls->gname,
	    st->st_mode);

	uid = st->st_uid;
	if ((pwd = getpwnam(acls->uname)) != NULL) {
		NDMP_LOG(LOG_DEBUG, "set_attr: new uid %d old %d",
		    pwd->pw_uid, uid);
		uid = pwd->pw_uid;
	}

	gid = st->st_gid;
	if ((grp = getgrnam(acls->gname)) != NULL) {
		NDMP_LOG(LOG_DEBUG, "set_attr: new gid %d old %d",
		    grp->gr_gid, gid);
		gid = grp->gr_gid;
	}

	erc = lchown(name, uid, gid);
	if (erc != 0) {
		erc = errno;
		NDMP_LOG(LOG_ERR,
		    "Could not set uid or/and gid for file %s.", name);
	}

	if ((st->st_mode & (S_ISUID | S_ISGID)) != 0) {
		/*
		 * Change effective privileges to 'all' which is required to
		 * change setuid bit for 'root' owned files. If fails, just
		 * send error to log file and proceed.
		 */
		if (ndmp_set_eprivs_all()) {
			NDMP_LOG(LOG_ERR,
			    "Could not set effective privileges to 'all'.");
		} else {
			priv_all = TRUE;
		}
	}

	if (!S_ISLNK(st->st_mode)) {
		erc = chmod(name, st->st_mode);
		if (erc != 0) {
			erc = errno;
			NDMP_LOG(LOG_ERR, "Could not set correct file"
			    " permission for file %s: %d", name, errno);
		}

		tbuf.modtime = st->st_mtime;
		tbuf.actime = st->st_atime;
		(void) utime(name, &tbuf);
	}

	if (priv_all == TRUE) {
		/*
		 * Give up the 'all' privileges for effective sets and go back
		 * to least required privileges. If fails, just send error to
		 * log file and proceed.
		 */
		if (ndmp_set_eprivs_least())
			NDMP_LOG(LOG_ERR,
			    "Could not set least required privileges.");
	}

	return (erc);
}

/*
 * Set the ACL info for the file
 */
static int
set_acl(char *name, tlm_acls_t *acls)
{
	int erc;
	acl_t *aclp = NULL;

	if (name)
		NDMP_LOG(LOG_DEBUG, "set_acl: %s", name);
	if (acls == NULL)
		return (0);

	/* Need a place to save real modification time */

	erc = set_attr(name, acls);
	if (ERROR_IS_FATAL(erc))
		return (erc);

	if (!acls->acl_non_trivial) {
		(void) memset(acls, 0, sizeof (tlm_acls_t));
		NDMP_LOG(LOG_DEBUG, "set_acl: skipping trivial");
		return (erc);
	}

	erc = acl_fromtext(acls->acl_info.attr_info, &aclp);
	if (erc != 0) {
		NDMP_LOG(LOG_DEBUG,
		    "TAPE RESTORE> acl_fromtext errno %d", erc);
	}
	if (aclp) {
		erc = acl_set(name, aclp);
		if (erc < 0) {
			erc = errno;
			NDMP_LOG(LOG_DEBUG,
			    "TAPE RESTORE> acl_set errno %d", errno);
		}
		acl_free(aclp);
	}
	(void) memset(acls, 0, sizeof (tlm_acls_t));
	return (erc);
}

/*
 * a wrapper to tlm_get_read_buffer so that
 * we can cleanly detect ABORT commands
 * without involving the TLM library with
 * our problems.
 */
static char *
get_read_buffer(int want,
    int	*error,
    int	*actual_size,
    tlm_cmd_t *local_commands)
{
	while (local_commands->tc_writer == TLM_RESTORE_RUN) {
		char	*rec;
		rec = tlm_get_read_buffer(want, error,
		    local_commands->tc_buffers, actual_size);
		if (rec != 0) {
			return (rec);
		}
	}

	/*
	 * the job is ending, give Writer a buffer that will never be read ...
	 * it does not matter anyhow, we are aborting.
	 */
	*actual_size = RECORDSIZE;
	return (NULL);
}

/*
 * Enable wildcard for restore options
 */
static boolean_t
wildcard_enabled(void)
{
	char *cp;

	cp = ndmpd_get_prop_default(NDMP_RESTORE_WILDCARD_ENABLE, "n");
	return ((toupper(*cp) == 'Y') ? TRUE : FALSE);
}


/*
 * Concatenate two names
 */
/*ARGSUSED*/
static char *
catnames(struct rs_name_maker *rnp, char *buf, int pos, char *path)
{
	char *rv;

	rv = NULL;
	if (!buf) {
		NDMP_LOG(LOG_DEBUG, "buf is NULL");
	} else if (!path) {
		NDMP_LOG(LOG_DEBUG, "path is NULL");
	} else if (!rnp->rn_nlp) {
		NDMP_LOG(LOG_DEBUG, "rn_nlp is NULL [%s]", path);
	} else if (!tlm_cat_path(buf, rnp->rn_nlp, path)) {
		NDMP_LOG(LOG_DEBUG, "Path too long [%s][%s]",
		    rnp->rn_nlp, path);
	} else
		rv = buf;

	return (rv);
}


/*
 * Create a new name path for restore
 */
static char *
rs_new_name(struct rs_name_maker *rnp, char *buf, int pos, char *path)
{
	if (!rnp || !rnp->rn_fp)
		return (NULL);

	return (*rnp->rn_fp)(rnp, buf, pos, path);
}

/*
 * Clear the extra "/" in the tar header if exists
 */
static void
rs_create_new_bkpath(char *bk_path, char *path, char *pbuf)
{
	char *p, *slashp;

	if ((p = strstr(path, bk_path)) == NULL) {
		(void) strlcpy(pbuf, path, TLM_MAX_PATH_NAME);
		return;
	}
	if (*(p += strlen(bk_path)) == '/')
		p++;

	slashp = bk_path + strlen(bk_path) - 1;
	if (*slashp == '/')
		(void) snprintf(pbuf, TLM_MAX_PATH_NAME, "%s%s", bk_path, p);
	else
		(void) snprintf(pbuf, TLM_MAX_PATH_NAME, "%s/%s", bk_path, p);

	NDMP_LOG(LOG_DEBUG, "old path [%s] new path [%s]", path, pbuf);
}


/*
 * Iterate over ZFS metadata stored in the backup stream and use the callback
 * to restore it.
 */
int
ndmp_iter_zfs(ndmp_context_t *nctx, int (*np_restore_property)(nvlist_t *,
    void *), void *ptr)
{
	tlm_commands_t *cmds;
	ndmp_metadata_header_t *mhp;
	ndmp_metadata_header_ext_t *mhpx;
	ndmp_metadata_property_t *mpp;
	ndmp_metadata_property_ext_t *mppx;
	tlm_cmd_t *lcmd;
	int actual_size;
	nvlist_t *nvl;
	nvlist_t *valp;
	nvpair_t *nvp = NULL;
	char plname[100];
	char *mhbuf, *pp, *tp;
	int rv, i;
	int size, lsize, sz;
	int align = RECORDSIZE - 1;

	if (nctx == NULL || (cmds = (tlm_commands_t *)nctx->nc_cmds) == NULL)
		return (-1);

	nctx->nc_plname = plname;
	if ((lcmd = cmds->tcs_command) == NULL ||
	    lcmd->tc_buffers == NULL)
		return (-1);

	/* Default minimum bytes needed */
	size = sizeof (ndmp_metadata_header_t) +
	    ZFS_MAX_PROPS * sizeof (ndmp_metadata_property_t);
	size += align;
	size &= ~align;

	if ((mhbuf = malloc(size)) == NULL)
		return (-1);

	/* LINTED improper alignment */
	while ((mhp = (ndmp_metadata_header_t *)get_read_buffer(size, &rv,
	    &actual_size, lcmd)) != NULL) {
		pp = mhbuf;

		if (strncmp(mhp->nh_magic, ZFS_META_MAGIC,
		    sizeof (mhp->nh_magic)) != 0 &&
		    strncmp(mhp->nh_magic, ZFS_META_MAGIC_EXT,
		    sizeof (mhp->nh_magic)) != 0) {
			/* No more metadata */
			tlm_unget_read_buffer(lcmd->tc_buffers, actual_size);
			free(mhbuf);
			return (0);
		}

		if (strncmp(mhp->nh_magic, ZFS_META_MAGIC_EXT,
		    sizeof (mhp->nh_magic)) == 0) {
			mhpx = (ndmp_metadata_header_ext_t *)mhp;
			if (mhpx->nh_total_bytes > size) {
				if ((pp = realloc(mhbuf, mhpx->nh_total_bytes))
				    == NULL) {
					free(mhbuf);
					return (-1);
				}
				mhbuf = pp;
			}
			size = mhpx->nh_total_bytes;
		}

		(void) memcpy(pp, (char *)mhp, (actual_size < size) ?
		    actual_size : size);
		pp += (actual_size < size) ? actual_size : size;

		sz = actual_size;
		while (sz < size &&
		    ((tp = get_read_buffer(size - sz, &rv, &lsize,
		    lcmd))) != NULL) {
			(void) memcpy(pp, tp, lsize);
			sz += lsize;
			pp += lsize;
		}
		if (sz > size) {
			tlm_unget_read_buffer(lcmd->tc_buffers, sz - size);
		}

		/* LINTED improper alignment */
		mhp = (ndmp_metadata_header_t *)mhbuf;

		nvl = NULL;
		if (strncmp(mhp->nh_magic, ZFS_META_MAGIC_EXT,
		    sizeof (mhp->nh_magic)) == 0) {
			/* New metadata format */
			/* LINTED improper alignment */
			mhpx = (ndmp_metadata_header_ext_t *)mhbuf;

			if (mhpx->nh_major > META_HDR_MAJOR_VERSION) {
				/* Major header mismatch */
				NDMP_LOG(LOG_ERR, "metadata header mismatch",
				    "M%d != M%d", mhpx->nh_major,
				    META_HDR_MAJOR_VERSION);
				free(mhbuf);
				return (-1);
			}
			if (mhpx->nh_major == META_HDR_MAJOR_VERSION &&
			    mhpx->nh_minor > META_HDR_MINOR_VERSION) {
				/* Minor header mismatch */
				NDMP_LOG(LOG_ERR, "Warning:"
				    "metadata header mismatch m%d != m%d",
				    mhpx->nh_minor,
				    META_HDR_MINOR_VERSION);
				continue;
			}

			nctx->nc_plversion = mhpx->nh_plversion;
			(void) strlcpy(plname, mhpx->nh_plname,
			    sizeof (plname));

			if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0)
				goto nvlist_err;

			mppx = &mhpx->nh_property[0];
			for (i = 0; i < mhpx->nh_count && mppx; i++, mppx++) {
				if (!*mppx->mp_name)
					continue;
				valp = NULL;
				if (nvlist_alloc(&valp,
				    NV_UNIQUE_NAME, 0) != 0 ||
				    nvlist_add_string(valp, "value",
				    mppx->mp_value) != 0 ||
				    nvlist_add_string(valp, "source",
				    mppx->mp_source) != 0 ||
				    nvlist_add_nvlist(nvl, mppx->mp_name,
				    valp) != 0) {
					nvlist_free(valp);
					goto nvlist_err;
				}
				nvlist_free(valp);
			}
		} else {
			nctx->nc_plversion = mhp->nh_plversion;
			(void) strlcpy(plname, mhp->nh_plname,
			    sizeof (plname));

			if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0)
				goto nvlist_err;

			mpp = &mhp->nh_property[0];
			for (i = 0; i < mhp->nh_count && mpp; i++, mpp++) {
				if (!*mpp->mp_name)
					continue;
				valp = NULL;
				if (nvlist_alloc(&valp,
				    NV_UNIQUE_NAME, 0) != 0 ||
				    nvlist_add_string(valp, "value",
				    mpp->mp_value) != 0 ||
				    nvlist_add_string(valp, "source",
				    mpp->mp_source) != 0 ||
				    nvlist_add_nvlist(nvl, mpp->mp_name,
				    valp) != 0) {
					nvlist_free(valp);
					goto nvlist_err;
				}
				nvlist_free(valp);
			}
		}

		if (np_restore_property(nvl, ptr) != 0)
			goto nvlist_err;

		while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL &&
		    nvpair_value_nvlist(nvp, &valp) == 0) {
			nvlist_free(valp);
		}
		nvlist_free(nvl);
	}

	free(mhbuf);
	return (0);

nvlist_err:
	free(mhbuf);

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL &&
	    nvpair_value_nvlist(nvp, &valp) == 0) {
		nvlist_free(valp);
	}
	nvlist_free(nvl);
	return (-1);
}

/*
 * Returns the version number of the plugin which created the metadata
 */
uint_t
ndmp_context_get_version(ndmp_context_t *nctx)
{
	tlm_commands_t *cmds;
	ndmp_metadata_header_t *mhp;
	tlm_cmd_t *lcmd;
	int actual_size;
	int rv;
	int size;
	int align = RECORDSIZE - 1;

	if (nctx == NULL || (cmds = (tlm_commands_t *)nctx->nc_cmds) == NULL)
		return (0);

	if ((lcmd = cmds->tcs_command) == NULL ||
	    lcmd->tc_buffers == NULL)
		return (0);

	size = sizeof (ndmp_metadata_header_t);
	size += align;
	size &= ~align;

	/* LINTED improper alignment */
	if ((mhp = (ndmp_metadata_header_t *)get_read_buffer(size, &rv,
	    &actual_size, lcmd)) != NULL) {
		if (strncmp(mhp->nh_magic, ZFS_META_MAGIC,
		    sizeof (mhp->nh_magic)) != 0) {
			/* No more metadata */
			tlm_unget_read_buffer(lcmd->tc_buffers, actual_size);
			return (0);
		}

		nctx->nc_plversion = mhp->nh_plversion;
		tlm_unget_read_buffer(lcmd->tc_buffers, actual_size);
	}

	return (nctx->nc_plversion);
}
