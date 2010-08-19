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
#include <sys/errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <libzfs.h>
#include <pthread.h>
#include "tlm.h"
#include "tlm_proto.h"
#include <ndmpd_prop.h>
#include <sys/mtio.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>
#include <sys/statvfs.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/scsi/scsi.h>
#include <sys/mtio.h>
#include <thread.h>
#include <synch.h>
#include <sys/mutex.h>
#include <sys/sysmacros.h>
#include <sys/mkdev.h>

/*
 * Tar archiving ops vector
 */
tm_ops_t tm_tar_ops = {
	"tar",
	tar_putfile,
	tar_putdir,
	NULL,
	tar_getfile,
	tar_getdir,
	NULL
};

extern	libzfs_handle_t *zlibh;
extern	mutex_t zlib_mtx;

/*
 * get the next tape buffer from the drive's pool of buffers
 */
/*ARGSUSED*/
char *
tlm_get_write_buffer(long want, long *actual_size,
    tlm_buffers_t *buffers, int zero)
{
	int	buf = buffers->tbs_buffer_in;
	tlm_buffer_t *buffer = &buffers->tbs_buffer[buf];
	int	align_size = RECORDSIZE - 1;
	char	*rec;

	/*
	 * make sure the allocation is in chunks of 512 bytes
	 */
	want += align_size;
	want &= ~align_size;

	*actual_size = buffer->tb_buffer_size - buffer->tb_buffer_spot;
	if (*actual_size <= 0) {
		/*
		 * no room, send this one
		 * and wait for a free one
		 */
		if (!buffer->tb_full) {
			/*
			 * we are now ready to send a full buffer
			 * instead of trying to get a new buffer
			 *
			 * do not send if we failed to get a buffer
			 * on the previous call
			 */
			buffer->tb_full = TRUE;

			/*
			 * tell the writer that a buffer is available
			 */
			tlm_buffer_release_in_buf(buffers);

			buffer = tlm_buffer_advance_in_idx(buffers);
		}

		buffer = tlm_buffer_in_buf(buffers, NULL);

		if (buffer->tb_full) {
			/*
			 * wait for the writer to free up a buffer
			 */
			tlm_buffer_out_buf_timed_wait(buffers, 500);
		}

		buffer = tlm_buffer_in_buf(buffers, NULL);
		if (buffer->tb_full) {
			/*
			 * the next buffer is still full
			 * of data from previous activity
			 *
			 * nothing has changed.
			 */
			return (0);
		}

		buffer->tb_buffer_spot = 0;
		*actual_size = buffer->tb_buffer_size - buffer->tb_buffer_spot;
	}

	*actual_size = min(want, *actual_size);
	rec = &buffer->tb_buffer_data[buffer->tb_buffer_spot];
	buffer->tb_buffer_spot += *actual_size;
	buffers->tbs_offset += *actual_size;
	if (zero) {
		(void) memset(rec, 0, *actual_size);
	}
	return (rec);
}

/*
 * get a read record from the tape buffer,
 * and read a tape block if necessary
 */
/*ARGSUSED*/
char *
tlm_get_read_buffer(int want, int *error,
    tlm_buffers_t *buffers, int *actual_size)
{
	tlm_buffer_t *buffer;
	int	align_size = RECORDSIZE - 1;
	int	buf;
	int	current_size;
	char	*rec;

	buf = buffers->tbs_buffer_out;
	buffer = &buffers->tbs_buffer[buf];

	/*
	 * make sure the allocation is in chunks of 512 bytes
	 */
	want += align_size;
	want &= ~align_size;

	current_size = buffer->tb_buffer_size - buffer->tb_buffer_spot;
	if (buffer->tb_full && current_size <= 0) {
		/*
		 * no more data, release this
		 * one and go get another
		 */

		/*
		 * tell the reader that a buffer is available
		 */
		buffer->tb_full = FALSE;
		tlm_buffer_release_out_buf(buffers);

		buffer = tlm_buffer_advance_out_idx(buffers);
		current_size = buffer->tb_buffer_size - buffer->tb_buffer_spot;
	}

	if (!buffer->tb_full) {
		/*
		 * next buffer is not full yet.
		 * wait for the reader.
		 */
		tlm_buffer_in_buf_timed_wait(buffers, 500);

		buffer = tlm_buffer_out_buf(buffers, NULL);
		if (!buffer->tb_full) {
			/*
			 * we do not have anything from the tape yet
			 */
			return (0);
		}

		current_size = buffer->tb_buffer_size - buffer->tb_buffer_spot;
	}

	/* Make sure we got something */
	if (current_size <= 0)
		return (NULL);

	current_size = min(want, current_size);
	rec = &buffer->tb_buffer_data[buffer->tb_buffer_spot];
	buffer->tb_buffer_spot += current_size;
	*actual_size = current_size;

	/*
	 * the error flag is only sent back one time,
	 * since the flag refers to a previous read
	 * attempt, not the data in this buffer.
	 */
	*error = buffer->tb_errno;

	return (rec);
}


/*
 * unread a previously read buffer back to the tape buffer
 */
void
tlm_unget_read_buffer(tlm_buffers_t *buffers, int size)
{
	tlm_buffer_t *buffer;
	int	align_size = RECORDSIZE - 1;
	int	buf;
	int	current_size;

	buf = buffers->tbs_buffer_out;
	buffer = &buffers->tbs_buffer[buf];

	/*
	 * make sure the allocation is in chunks of 512 bytes
	 */
	size += align_size;
	size &= ~align_size;

	current_size = min(size, buffer->tb_buffer_spot);
	buffer->tb_buffer_spot -= current_size;
}


/*
 * unwrite a previously written buffer
 */
void
tlm_unget_write_buffer(tlm_buffers_t *buffers, int size)
{
	tlm_buffer_t *buffer;
	int	align_size = RECORDSIZE - 1;
	int	buf;
	int	current_size;

	buf = buffers->tbs_buffer_in;
	buffer = &buffers->tbs_buffer[buf];

	/*
	 * make sure the allocation is in chunks of 512 bytes
	 */
	size += align_size;
	size &= ~align_size;

	current_size = min(size, buffer->tb_buffer_spot);
	buffer->tb_buffer_spot -= current_size;
}


/*
 * build a checksum for a TAR header record
 */
void
tlm_build_header_checksum(tlm_tar_hdr_t *r)
{
	int	i;
	int	sum = 0;
	char *c = (char *)r;

	(void) memcpy(r->th_chksum, CHKBLANKS, strlen(CHKBLANKS));
	for (i = 0; i < RECORDSIZE; i++) {
		sum += c[i] & 0xFF;
	}
	(void) snprintf(r->th_chksum, sizeof (r->th_chksum), "%6o", sum);
}

/*
 * verify the tar header checksum
 */
int
tlm_vfy_tar_checksum(tlm_tar_hdr_t *tar_hdr)
{
	int	chksum = oct_atoi(tar_hdr->th_chksum);
	uchar_t	*p = (uchar_t *)tar_hdr;
	int	sum = 0;	/* initial value of checksum */
	int	i;		/* loop counter */

	/*
	 * compute the checksum
	 */
	for (i = 0; i < RECORDSIZE; i++) {
		sum += p[i] & 0xFF;
	}

	if (sum == 0) {
		NDMP_LOG(LOG_DEBUG,
		    "should be %d, is 0", chksum);
		/* a zero record ==> end of tar file */
		return (0);
	}

	/*
	 * subtract out the label's checksum values
	 * this lets us undo the old checksum "in-
	 * place", no need to swap blanks in and out
	 */
	for (i = 0; i < 8; i++) {
		sum -= 0xFF & tar_hdr->th_chksum[i];
	}

	/*
	 * replace the old checksum field with blanks
	 */
	sum += ' ' * 8;

	if (sum != chksum)
		NDMP_LOG(LOG_DEBUG,
		    "should be %d, is %d", chksum, sum);

	return ((sum == chksum) ? 1 : -1);
}

/*
 * get internal scsi_sasd entry for this tape drive
 */
int
tlm_get_scsi_sasd_entry(int lib, int drv)
{
	int entry;
	int i, n;
	scsi_link_t *sl;
	tlm_drive_t *dp;

	entry = -1;
	dp = tlm_drive(lib, drv);
	if (!dp) {
		NDMP_LOG(LOG_DEBUG, "NULL dp for (%d.%d)", lib, drv);
	} else if (!dp->td_slink) {
		NDMP_LOG(LOG_DEBUG, "NULL dp->td_slink for (%d.%d)", lib, drv);
	} else if (!dp->td_slink->sl_sa) {
		NDMP_LOG(LOG_DEBUG, "NULL dp->td_slink->sl_sa for (%d.%d)",
		    lib, drv);
	} else {
		/* search through the SASD table */
		n = sasd_dev_count();
		for (i = 0; i < n; i++) {
			sl = sasd_dev_slink(i);
			if (!sl)
				continue;

			if (dp->td_slink->sl_sa == sl->sl_sa &&
			    dp->td_scsi_id == sl->sl_sid &&
			    dp->td_lun == sl->sl_lun) {
				/* all 3 variables match */
				entry = i;
				break;
			}
		}
	}

	return (entry);
}

/*
 * get the OS device name for this tape
 */
char *
tlm_get_tape_name(int lib, int drv)
{
	int entry;

	entry = tlm_get_scsi_sasd_entry(lib, drv);
	if (entry >= 0) {
		sasd_drive_t *sd;

		if ((sd = sasd_drive(entry)) != 0)
			return (sd->sd_name);
	}

	return ("");
}

/*
 * create the IPC area between the reader and writer
 */
tlm_cmd_t *
tlm_create_reader_writer_ipc(boolean_t write, long data_transfer_size)
{
	tlm_cmd_t *cmd;

	cmd = ndmp_malloc(sizeof (tlm_cmd_t));
	if (cmd == NULL)
		return (NULL);

	cmd->tc_reader = TLM_BACKUP_RUN;
	cmd->tc_writer = TLM_BACKUP_RUN;
	cmd->tc_ref = 1;

	cmd->tc_buffers = tlm_allocate_buffers(write, data_transfer_size);
	if (cmd->tc_buffers == NULL) {
		free(cmd);
		return (NULL);
	}

	(void) mutex_init(&cmd->tc_mtx, 0, NULL);
	(void) cond_init(&cmd->tc_cv, 0, NULL);

	return (cmd);
}

/*
 * release(destroy) the IPC between the reader and writer
 */
void
tlm_release_reader_writer_ipc(tlm_cmd_t *cmd)
{
	if (--cmd->tc_ref <= 0) {
		(void) mutex_lock(&cmd->tc_mtx);
		tlm_release_buffers(cmd->tc_buffers);
		(void) cond_destroy(&cmd->tc_cv);
		(void) mutex_unlock(&cmd->tc_mtx);
		(void) mutex_destroy(&cmd->tc_mtx);
		free(cmd);
	}
}


/*
 * NDMP support begins here.
 */

/*
 * Initialize the file history callback functions
 */
lbr_fhlog_call_backs_t *
lbrlog_callbacks_init(void *cookie, path_hist_func_t log_pname_func,
    dir_hist_func_t log_dir_func, node_hist_func_t log_node_func)
{
	lbr_fhlog_call_backs_t *p;

	p = ndmp_malloc(sizeof (lbr_fhlog_call_backs_t));
	if (p == NULL)
		return (NULL);

	p->fh_cookie = cookie;
	p->fh_logpname = (func_t)log_pname_func;
	p->fh_log_dir = (func_t)log_dir_func;
	p->fh_log_node = (func_t)log_node_func;
	return (p);
}

/*
 * Cleanup the callbacks
 */
void
lbrlog_callbacks_done(lbr_fhlog_call_backs_t *p)
{
	if (p != NULL)
		(void) free((char *)p);
}

/*
 * Call back for file history directory info
 */
int
tlm_log_fhdir(tlm_job_stats_t *job_stats, char *dir, struct stat64 *stp,
    fs_fhandle_t *fhp)
{
	int rv;
	lbr_fhlog_call_backs_t *cbp; /* callbacks pointer */

	rv = 0;
	if (job_stats == NULL) {
		NDMP_LOG(LOG_DEBUG, "log_fhdir: jstat is NULL");
	} else if (dir == NULL) {
		NDMP_LOG(LOG_DEBUG, "log_fhdir: dir is NULL");
	} else if (stp == NULL) {
		NDMP_LOG(LOG_DEBUG, "log_fhdir: stp is NULL");
	} else if ((cbp = (lbr_fhlog_call_backs_t *)job_stats->js_callbacks)
	    == NULL) {
		NDMP_LOG(LOG_DEBUG, "log_fhdir: cbp is NULL");
	} else if (cbp->fh_log_dir == NULL) {
		NDMP_LOG(LOG_DEBUG, "log_fhdir: callback is NULL");
	} else
		rv = (*cbp->fh_log_dir)(cbp, dir, stp, fhp);

	return (rv);
}

/*
 * Call back for file history node info
 */
int
tlm_log_fhnode(tlm_job_stats_t *job_stats, char *dir, char *file,
    struct stat64 *stp, u_longlong_t off)
{
	int rv;
	lbr_fhlog_call_backs_t *cbp; /* callbacks pointer */

	rv = 0;
	if (job_stats == NULL) {
		NDMP_LOG(LOG_DEBUG, "log_fhnode: jstat is NULL");
	} else if (dir == NULL) {
		NDMP_LOG(LOG_DEBUG, "log_fhnode: dir is NULL");
	} else if (file == NULL) {
		NDMP_LOG(LOG_DEBUG, "log_fhnode: file is NULL");
	} else if (stp == NULL) {
		NDMP_LOG(LOG_DEBUG, "log_fhnode: stp is NULL");
	} else if ((cbp = (lbr_fhlog_call_backs_t *)job_stats->js_callbacks)
	    == NULL) {
		NDMP_LOG(LOG_DEBUG, "log_fhnode: cbp is NULL");
	} else if (cbp->fh_log_node == NULL) {
		NDMP_LOG(LOG_DEBUG, "log_fhnode: callback is NULL");
	} else
		rv = (*cbp->fh_log_node)(cbp, dir, file, stp, off);

	return (rv);
}

/*
 * Call back for file history path info
 */
int
tlm_log_fhpath_name(tlm_job_stats_t *job_stats, char *pathname,
    struct stat64 *stp, u_longlong_t off)
{
	int rv;
	lbr_fhlog_call_backs_t *cbp; /* callbacks pointer */

	rv = 0;
	if (!job_stats) {
		NDMP_LOG(LOG_DEBUG, "log_fhpath_name: jstat is NULL");
	} else if (!pathname) {
		NDMP_LOG(LOG_DEBUG, "log_fhpath_name: pathname is NULL");
	} else if (!stp) {
		NDMP_LOG(LOG_DEBUG, "log_fhpath_name: stp is NULL");
	} else if ((cbp = (lbr_fhlog_call_backs_t *)job_stats->js_callbacks)
	    == 0) {
		NDMP_LOG(LOG_DEBUG, "log_fhpath_name: cbp is NULL");
	} else if (!cbp->fh_logpname) {
		NDMP_LOG(LOG_DEBUG, "log_fhpath_name: callback is NULL");
	} else
		rv = (*cbp->fh_logpname)(cbp, pathname, stp, off);

	return (rv);
}


/*
 * Log call back to report the entry recovery
 */
int
tlm_entry_restored(tlm_job_stats_t *job_stats, char *name, int pos)
{
	lbr_fhlog_call_backs_t *cbp; /* callbacks pointer */

	NDMP_LOG(LOG_DEBUG, "name: \"%s\", pos: %d", name, pos);

	if (job_stats == NULL) {
		NDMP_LOG(LOG_DEBUG, "entry_restored: jstat is NULL");
		return (0);
	}
	cbp = (lbr_fhlog_call_backs_t *)job_stats->js_callbacks;
	if (cbp == NULL) {
		NDMP_LOG(LOG_DEBUG, "entry_restored is NULL");
		return (0);
	}
	return (*cbp->fh_logpname)(cbp, name, 0, (longlong_t)pos);
}
/*
 * NDMP support ends here.
 */

/*
 * Function: tlm_cat_path
 * Concatenates two path names
 * or directory name and file name
 * into a buffer passed by the caller. A slash
 * is inserted if required. Buffer is assumed
 * to hold PATH_MAX characters.
 *
 * Parameters:
 *	char *buf	- buffer to write new dir/name string
 *	char *dir	- directory name
 *	char *name	- file name
 *
 * Returns:
 *	TRUE		- No errors. buf contains the dir/name string
 *	FALSE		- Error. buf is not modified.
 */
boolean_t
tlm_cat_path(char *buf, char *dir, char *name)
{
	char *fmt;
	int dirlen = strlen(dir);
	int filelen = strlen(name);

	if ((dirlen + filelen + 1) >= PATH_MAX) {
		return (FALSE);
	}

	if (*dir == '\0' || *name == '\0' || dir[dirlen - 1] == '/' ||
	    *name == '/') {
		fmt = "%s%s";
	} else {
		fmt = "%s/%s";
	}

	/* check for ".../" and "/...." */
	if ((dirlen > 0) && (dir[dirlen - 1] == '/') && (*name == '/'))
		name += strspn(name, "/");

	/* LINTED variable format */
	(void) snprintf(buf, TLM_MAX_PATH_NAME, fmt, dir, name);

	return (TRUE);
}

/*
 * Get the checkpoint (snapshot) creation time.
 * This is necessary to check for checkpoints not being stale.
 */
int
tlm_get_chkpnt_time(char *path, int auto_checkpoint, time_t *tp, char *jname)
{
	char volname[TLM_VOLNAME_MAX_LENGTH];
	char chk_name[PATH_MAX];
	char *cp_nm;

	NDMP_LOG(LOG_DEBUG, "path [%s] auto_checkpoint: %d",
	    path, auto_checkpoint);

	if (path == NULL || *path == '\0' || tp == NULL)
		return (-1);

	if (get_zfsvolname(volname, TLM_VOLNAME_MAX_LENGTH,
	    path) == -1)
		return (-1);

	if (auto_checkpoint) {
		NDMP_LOG(LOG_DEBUG, "volname [%s]", volname);
		(void) snprintf(chk_name, PATH_MAX, "%s", jname);
		return (chkpnt_creationtime_bypattern(volname, chk_name, tp));
	}
	cp_nm = strchr(volname, '@');
	NDMP_LOG(LOG_DEBUG, "volname [%s] cp_nm [%s]", volname, cp_nm);

	return (chkpnt_creationtime_bypattern(volname, cp_nm, tp));
}

/*
 * Release an array of pointers and the pointers themselves.
 */
void
tlm_release_list(char **lpp)
{
	char **save;

	if ((save = lpp) == 0)
		return;

	while (*lpp)
		free(*lpp++);

	free(save);
}

/*
 * Print the list of array of strings in the backup log
 */
void
tlm_log_list(char *title, char **lpp)
{
	int i;

	if (!lpp)
		return;

	NDMP_LOG(LOG_DEBUG, "%s:", title);

	for (i = 0; *lpp; lpp++, i++)
		NDMP_LOG(LOG_DEBUG, "%d: [%s]", i, *lpp);
}

/*
 * Insert the backup snapshot name into the path.
 *
 * Input:
 * 	name: Original path name.
 *
 * Output:
 * 	name: Original name modified to include a snapshot.
 *
 * Returns:
 * 	Original name modified to include a snapshot.
 */
char *
tlm_build_snapshot_name(char *name, char *sname, char *jname)
{
	zfs_handle_t *zhp;
	char *rest;
	char volname[ZFS_MAXNAMELEN];
	char mountpoint[PATH_MAX];

	if (get_zfsvolname(volname, ZFS_MAXNAMELEN, name) == -1)
		goto notzfs;

	(void) mutex_lock(&zlib_mtx);
	if ((zlibh == NULL) ||
	    (zhp = zfs_open(zlibh, volname, ZFS_TYPE_DATASET)) == NULL) {
		(void) mutex_unlock(&zlib_mtx);
		goto notzfs;
	}

	if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, mountpoint, PATH_MAX, NULL,
	    NULL, 0, B_FALSE) != 0) {
		zfs_close(zhp);
		(void) mutex_unlock(&zlib_mtx);
		goto notzfs;
	}

	zfs_close(zhp);
	(void) mutex_unlock(&zlib_mtx);

	rest = name + strlen(mountpoint);
	(void) snprintf(sname, TLM_MAX_PATH_NAME, "%s/%s/%s%s", mountpoint,
	    TLM_SNAPSHOT_DIR, jname, rest);

	return (sname);

notzfs:
	(void) strlcpy(sname, name, TLM_MAX_PATH_NAME);
	return (sname);
}

/*
 * Remove the checkpoint from a path name.
 *
 * Input:
 * 	name: Full pathname with checkpoint embeded.
 *
 * Output:
 * 	unchkp_name: real pathname with no checkpoint.
 *
 * Returns:
 *	Pointer to the un-checkpointed path.
 */
char *
tlm_remove_checkpoint(char *name, char *unchkp_name)
{
	char *cp;
	int i;
	int plen;

	unchkp_name[0] = name[0];
	plen = strlen(TLM_SNAPSHOT_PREFIX);
	for (i = 1; i <= TLM_VOLNAME_MAX_LENGTH + 1; i++) {
		switch (name[i]) {
		case '.':
			if (strncmp(&name[i], TLM_SNAPSHOT_PREFIX,
			    plen) == 0) {
				unchkp_name[i] = '\0';
				i += plen;
				if (name[i] == '\0') {
					/*
					 * name == "/v1.chkpnt"
					 */
					return (unchkp_name);
				}
				if ((cp = strchr(&name[++i], '/')) != NULL) {
					(void) strlcat(unchkp_name, cp,
					    TLM_VOLNAME_MAX_LENGTH + 1);
				}
				return (unchkp_name);
			} else {
				unchkp_name[i] = name[i];
			}
			break;
		case '/':
			return (name);
		case 0:
			return (name);
		default:
			unchkp_name[i] = name[i];
			break;
		}
	}
	return (name);
}

/*
 * see if we should exclude this file.
 */
boolean_t
tlm_is_excluded(char *dir, char *name, char **excl_files)
{
	int	i;
	char	full_name[TLM_MAX_PATH_NAME];

	if (!dir || !name || !excl_files)
		return (FALSE);

	if (!tlm_cat_path(full_name, dir, name)) {
		NDMP_LOG(LOG_DEBUG, "Path too long [%s][%s]",
		    dir, name);
		return (FALSE);
	}
	for (i = 0; excl_files[i] != 0; i++) {
		if (match(excl_files[i], full_name)) {
			return (TRUE);
		}
	}
	return (FALSE);
}

/*
 * Check if the path is too long
 */
boolean_t
tlm_is_too_long(int checkpointed, char *dir, char *nm)
{
	int nlen, tot;

	tot = 0;
	if (dir)
		tot += strlen(dir);
	if (checkpointed)
		tot += strlen(TLM_SNAPSHOT_DIR) + 1;
	if (nm) {
		if ((nlen = strlen(nm)) > 0)
			tot += nlen + 1;
	}
	return ((tot >= PATH_MAX) ? TRUE : FALSE);
}

/*
 * Get the data offset of inside the buffer
 */
longlong_t
tlm_get_data_offset(tlm_cmd_t *lcmds)
{
	if (!lcmds)
		return (0LL);

	return (lcmds->tc_buffers->tbs_offset);
}

/*
 * Enable the barcode capability on the library
 */
void
tlm_enable_barcode(int l)
{
	tlm_library_t *lp;

	if ((lp = tlm_library(l))) {
		lp->tl_capability_barcodes = TRUE;
		NDMP_LOG(LOG_DEBUG,
		    "Barcode capability on library %d enabled.", l);
	}
}

/*
 * SASD SCSI support
 */
static scsi_adapter_t my_sa;
static int sasd_drive_count = 0;
static scsi_sasd_drive_t *scsi_sasd_drives[128];

/*
 * Count of SCSI devices
 */
int
sasd_dev_count(void)
{
	return (sasd_drive_count);
}

/*
 * Return the SCSI device name
 */
char *
sasd_slink_name(scsi_link_t *slink)
{
	int i;

	for (i = 0; i < sasd_drive_count; i++) {
		if (&scsi_sasd_drives[i]->ss_slink == slink)
			return (scsi_sasd_drives[i]->ss_sd.sd_name);
	}
	return (NULL);
}

/*
 * Return the SCSI drive structure
 */
sasd_drive_t *
sasd_slink_drive(scsi_link_t *slink)
{
	int i;

	for (i = 0; i < sasd_drive_count; i++) {
		if (&scsi_sasd_drives[i]->ss_slink == slink)
			return (&scsi_sasd_drives[i]->ss_sd);
	}
	return (NULL);
}

/*
 * Return the SCSI link pointer for the given index
 */
scsi_link_t *
sasd_dev_slink(int entry)
{
	scsi_link_t *rv;

	if (entry >= 0 && entry < sasd_drive_count)
		rv = &scsi_sasd_drives[entry]->ss_slink;
	else
		rv = NULL;

	return (rv);
}

/*
 * Return the SCSI drive for the given index
 */
sasd_drive_t *
sasd_drive(int entry)
{
	sasd_drive_t *rv;

	if (entry >= 0 && entry < sasd_drive_count)
		rv = &scsi_sasd_drives[entry]->ss_sd;
	else
		rv = NULL;

	return (rv);
}

/*
 * Attach the SCSI device by updating the structures
 */
void
scsi_sasd_attach(scsi_adapter_t *sa, int sid, int lun, char *name,
    int type)
{
	scsi_link_t *sl, *next;
	scsi_sasd_drive_t *ssd;

	ssd = ndmp_malloc(sizeof (scsi_sasd_drive_t));
	if (ssd == NULL)
		return;

	scsi_sasd_drives[sasd_drive_count++] = ssd;

	switch (type) {
	case DTYPE_CHANGER:
		(void) snprintf(ssd->ss_sd.sd_name,
		    sizeof (ssd->ss_sd.sd_name), "%s/%s", SCSI_CHANGER_DIR,
		    name);
		break;
	case DTYPE_SEQUENTIAL:
		(void) snprintf(ssd->ss_sd.sd_name,
		    sizeof (ssd->ss_sd.sd_name), "%s/%s", SCSI_TAPE_DIR, name);
		break;
	}

	sl = &ssd->ss_slink;
	sl->sl_type = type;
	sl->sl_sa = sa;
	sl->sl_lun = lun;
	sl->sl_sid = sid;
	sl->sl_requested_max_active = 1;

	/* Insert slink */
	next = sa->sa_link_head.sl_next;
	sa->sa_link_head.sl_next = sl;
	sl->sl_next = next;
}

/*
 * Go through the attached devices and detect the tape
 * and robot by checking the /dev entries
 */
int
probe_scsi(void)
{
	DIR *dirp;
	struct dirent *dp;
	scsi_adapter_t *sa = &my_sa;
	char *p;
	int lun = 0;
	int sid = 0;
	char *drive_type;

	/* Initialize the scsi adapter link */
	sa->sa_link_head.sl_next = &sa->sa_link_head;

	/* Scan for the changer */
	dirp = opendir(SCSI_CHANGER_DIR);
	if (dirp == NULL) {
		NDMP_LOG(LOG_DEBUG,
		    "Changer directory read error %s", SCSI_CHANGER_DIR);
	} else {
		while ((dp = readdir(dirp)) != NULL) {
			if ((strcmp(dp->d_name, ".") == 0) ||
			    (strcmp(dp->d_name, "..") == 0))
				continue;

			if ((p = strchr(dp->d_name, 'd')) != NULL) {
				lun = atoi(++p);
				p = strchr(dp->d_name, 't');
				sid = atoi(++p);
			}
			else
				sid = atoi(dp->d_name);

			scsi_sasd_attach(sa, 0, lun, dp->d_name,
			    DTYPE_CHANGER);
		}
		(void) closedir(dirp);
	}

	/* Scan for tape drives */
	dirp = opendir(SCSI_TAPE_DIR);
	if (dirp == NULL) {
		NDMP_LOG(LOG_DEBUG,
		    "Tape directory read error %s", SCSI_TAPE_DIR);
	} else {
		drive_type = ndmpd_get_prop(NDMP_DRIVE_TYPE);

		if ((strcasecmp(drive_type, "sysv") != 0) &&
		    (strcasecmp(drive_type, "bsd") != 0)) {
			NDMP_LOG(LOG_ERR, "Invalid ndmpd/drive-type value. "
			    "Valid values are 'sysv' and 'bsd'.");
			return (-1);
		}

		while ((dp = readdir(dirp)) != NULL) {
			if ((strcmp(dp->d_name, ".") == 0) ||
			    (strcmp(dp->d_name, "..") == 0))
				continue;

			/* Skip special modes */
			if (strpbrk(dp->d_name, "chlmu") != NULL)
				continue;

			/* Pick the non-rewind device */
			if (strchr(dp->d_name, 'n') == NULL)
				continue;

			if (strcasecmp(drive_type, "sysv") == 0) {
				if (strchr(dp->d_name, 'b') != NULL)
					continue;
			} else if (strcasecmp(drive_type, "bsd") == 0) {
				if (strchr(dp->d_name, 'b') == NULL)
					continue;
			}

			sid = atoi(dp->d_name);

			/*
			 * SCSI ID should match with the ID of the device
			 * (will be checked by SCSI get elements page later)
			 */
			scsi_sasd_attach(sa, sid, 0, dp->d_name,
			    DTYPE_SEQUENTIAL);
		}
		(void) closedir(dirp);
	}

	return (0);
}

/*
 * Get the SCSI device type (tape, robot)
 */
/*ARGSUSED*/
int
scsi_get_devtype(char *adapter, int sid, int lun)
{
	int rv;
	scsi_adapter_t *sa = &my_sa;
	scsi_link_t *sl, *sh;

	rv = -1;
	sh = &sa->sa_link_head;
	for (sl = sh->sl_next; sl != sh; sl = sl->sl_next)
		if (sl->sl_sid == sid && sl->sl_lun == lun)
			rv = sl->sl_type;

	return (rv);
}


/*
 * Check if the SCSI device exists
 */
/*ARGSUSED*/
int
scsi_dev_exists(char *adapter, int sid, int lun)
{
	scsi_adapter_t *sa = &my_sa;
	scsi_link_t *sl, *sh;

	sh = &sa->sa_link_head;
	for (sl = sh->sl_next; sl != sh; sl = sl->sl_next)
		if (sl->sl_sid == sid && sl->sl_lun == lun)
			return (1);
	return (0);
}


/*
 * Count of SCSI adapters
 */
int
scsi_get_adapter_count(void)
{
	/* Currently support one adapter only */
	return (1);
}

/*
 * Return the SCSI adapter structure
 */
/*ARGSUSED*/
scsi_adapter_t *
scsi_get_adapter(int adapter)
{
	return (&my_sa);
}

/*
 * IOCTL wrapper with retries
 */
int
tlm_ioctl(int fd, int cmd, void *data)
{
	int retries = 0;

	NDMP_LOG(LOG_DEBUG, "tlm_ioctl fd %d cmd %d", fd, cmd);
	if (fd == 0 || data == NULL)
		return (EINVAL);

	do {
		if (ioctl(fd, cmd, data) == 0)
			break;

		if (errno != EIO && errno != 0) {
			NDMP_LOG(LOG_ERR,
			    "Failed to send command to device: %m.");
			NDMP_LOG(LOG_DEBUG, "IOCTL error %d", errno);
			return (errno);
		}
		(void) sleep(1);
	} while (retries++ < MAXIORETRY);

	return (0);
}

/*
 * Checkpoint or snapshot calls
 */

/*
 * Get the snapshot creation time
 */
int
chkpnt_creationtime_bypattern(char *volname, char *pattern, time_t *tp)
{
	char chk_name[PATH_MAX];
	zfs_handle_t *zhp;
	char *p;

	if (!volname || !*volname)
		return (-1);

	/* Should also return -1 if checkpoint not enabled */

	/* Remove the leading slash */
	p = volname;
	while (*p == '/')
		p++;

	(void) strlcpy(chk_name, p, PATH_MAX);
	(void) strlcat(chk_name, "@", PATH_MAX);
	(void) strlcat(chk_name, pattern, PATH_MAX);

	(void) mutex_lock(&zlib_mtx);
	if ((zhp = zfs_open(zlibh, chk_name, ZFS_TYPE_DATASET)) == NULL) {
		NDMP_LOG(LOG_DEBUG, "chkpnt_creationtime: open %s failed",
		    chk_name);
		(void) mutex_unlock(&zlib_mtx);
		return (-1);
	}

	*tp = zfs_prop_get_int(zhp, ZFS_PROP_CREATION);
	zfs_close(zhp);
	(void) mutex_unlock(&zlib_mtx);

	return (0);
}


/*
 * Get the ZFS volume name out of the given path
 */
int
get_zfsvolname(char *volname, int len, char *path)
{
	struct stat64 stbuf;
	struct extmnttab ent;
	FILE *mntfp;
	int rv;

	*volname = '\0';
	if (stat64(path, &stbuf) != 0) {
		return (-1);
	}

	if ((mntfp = fopen(MNTTAB, "r")) == NULL) {
		return (-1);
	}
	while ((rv = getextmntent(mntfp, &ent, 0)) == 0) {
		if (makedevice(ent.mnt_major, ent.mnt_minor) ==
		    stbuf.st_dev)
			break;
	}

	if (rv == 0 &&
	    strcmp(ent.mnt_fstype, MNTTYPE_ZFS) == 0)
		(void) strlcpy(volname, ent.mnt_special, len);
	else
		rv = -1;

	(void) fclose(mntfp);
	return (rv);
}


/*
 * Check if the volume type is snapshot volume
 */
boolean_t
fs_is_chkpntvol(char *path)
{
	zfs_handle_t *zhp;
	char vol[ZFS_MAXNAMELEN];

	if (!path || !*path)
		return (FALSE);

	if (get_zfsvolname(vol, sizeof (vol), path) == -1)
		return (FALSE);

	(void) mutex_lock(&zlib_mtx);
	if ((zhp = zfs_open(zlibh, vol, ZFS_TYPE_DATASET)) == NULL) {
		(void) mutex_unlock(&zlib_mtx);
		return (FALSE);
	}

	if (zfs_get_type(zhp) != ZFS_TYPE_SNAPSHOT) {
		zfs_close(zhp);
		(void) mutex_unlock(&zlib_mtx);
		return (FALSE);
	}
	zfs_close(zhp);
	(void) mutex_unlock(&zlib_mtx);

	return (TRUE);
}

/*
 * Check if the volume is capable of checkpoints
 */
boolean_t
fs_is_chkpnt_enabled(char *path)
{
	zfs_handle_t *zhp;
	char vol[ZFS_MAXNAMELEN];

	if (!path || !*path)
		return (FALSE);

	(void) mutex_lock(&zlib_mtx);
	if (get_zfsvolname(vol, sizeof (vol), path) == -1) {
		(void) mutex_unlock(&zlib_mtx);
		return (FALSE);
	}

	if ((zhp = zfs_open(zlibh, vol, ZFS_TYPE_DATASET)) == NULL) {
		(void) mutex_unlock(&zlib_mtx);
		return (FALSE);
	}
	zfs_close(zhp);
	(void) mutex_unlock(&zlib_mtx);

	return (TRUE);
}

/*
 * Check if the volume is read-only
 */
boolean_t
fs_is_rdonly(char *path)
{
	return (fs_is_chkpntvol(path));
}

/*
 * Min/max functions
 */
unsigned
min(a, b)
	unsigned a, b;
{
	return (a < b ? a : b);
}

unsigned
max(a, b)
	unsigned a, b;
{
	return (a > b ? a : b);
}

longlong_t
llmin(longlong_t a, longlong_t b)
{
	return (a < b ? a : b);
}
