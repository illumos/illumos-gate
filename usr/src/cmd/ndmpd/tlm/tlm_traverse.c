/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
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
/*
 * This file implemets the post-order, pre-order and level-order
 * traversing of the file system.  The related macros and constants
 * are defined in traverse.h.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <assert.h>
#include <cstack.h>
#include <dirent.h>
#include <errno.h>
#include <traverse.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <tlm.h>
#include "tlm_proto.h"

/*
 * Check if it's "." or ".."
 */
boolean_t
rootfs_dot_or_dotdot(char *name)
{
	if (*name != '.')
		return (FALSE);

	if ((name[1] == 0) || (name[1] == '.' && name[2] == 0))
		return (TRUE);

	return (FALSE);
}

/*
 * Macros on fs_traverse flags.
 */
#define	STOP_ONERR(f)	((f)->ft_flags & FST_STOP_ONERR)
#define	STOP_ONLONG(f)	((f)->ft_flags & FST_STOP_ONLONG)
#define	VERBOSE(f)	((f)->ft_flags & FST_VERBOSE)

#define	CALLBACK(pp, ep)	\
	(*(ftp)->ft_callbk)((ftp)->ft_arg, pp, ep)

#define	NEGATE(rv)	((rv) =	-(rv))

/*
 * The traversing state that is pushed onto the stack.
 * This include:
 * 	- The end of the path of the current directory.
 *	- The position of the last component on it.
 *	- The read position in the directory.
 *	- The file handle of the directory.
 *	- The stat of the directory.
 */
typedef struct traverse_state {
	char *ts_end;
	char *ts_ent;
	long ts_dpos; /* position in the directory when reading its entries */
	fs_fhandle_t ts_fh;
	struct stat64 ts_st;
} traverse_state_t;

/*
 * Statistics gathering structure.
 */
typedef struct traverse_statistics {
	ulong_t fss_newdirs;
	ulong_t fss_readdir_err;
	ulong_t fss_longpath_err;
	ulong_t fss_lookup_err;
	ulong_t fss_nondir_calls;
	ulong_t fss_dir_calls;
	ulong_t fss_nondir_skipped;
	ulong_t fss_dir_skipped;
	ulong_t fss_pushes;
	ulong_t fss_pops;
	ulong_t fss_stack_residue;
} traverse_statistics_t;

/*
 * Global instance of statistics variable.
 */
traverse_statistics_t traverse_stats;

#define	MAX_DENT_BUF_SIZE	(8 * 1024)

typedef struct {
	struct stat64 fd_attr;
	fs_fhandle_t fd_fh;
	short fd_len;
	char fd_name[1];
} fs_dent_info_t;

typedef struct dent_arg {
	char *da_buf;
	int da_end;
	int da_size;
} dent_arg_t;

static int traverse_level_nondir(struct fs_traverse *ftp,
    traverse_state_t *tsp, struct fst_node *pnp,
    dent_arg_t *darg);

/*
 * Gather some directory entry information and return them
 */
static int
fs_populate_dents(void *arg, int namelen,
    char *name, long *countp, struct stat64 *attr,
    fs_fhandle_t *fh)
{
	dent_arg_t *darg = (dent_arg_t *)arg;
	int reclen = sizeof (fs_dent_info_t) + namelen;
	fs_dent_info_t *dent;

	if ((darg->da_end + reclen) > darg->da_size)
		return (-1);

	/* LINTED improper alignment */
	dent = (fs_dent_info_t *)(darg->da_buf + darg->da_end);

	dent->fd_attr = *attr;
	dent->fd_fh = *fh;
	(void) strcpy(dent->fd_name, name);

	dent->fd_len = reclen;
	darg->da_end += reclen;

	if (countp)
		(*countp)++;

	return (0);
}

/*
 * Creates a new traversing state based on the path passed to it.
 */
static traverse_state_t *
new_tsp(char *path)
{
	traverse_state_t *tsp;
	tsp = ndmp_malloc(sizeof (traverse_state_t));
	if (!tsp)
		return (NULL);

	tsp->ts_end = strchr(path, '\0');
	if (*(tsp->ts_end-1) == '/')
		*--tsp->ts_end = '\0';
	tsp->ts_ent = NULL;
	tsp->ts_dpos = 0;

	return (tsp);
}

/*
 * Create a file handle and get stats for the given path
 */
int
fs_getstat(char *path, fs_fhandle_t *fh, struct stat64 *st)
{
	if (lstat64(path, st) == -1)
		return (errno);

	fh->fh_fid = st->st_ino;

	if (!S_ISDIR(st->st_mode))
		fh->fh_fpath = NULL;
	else
		fh->fh_fpath = strdup(path);
	return (0);
}

/*
 * Get directory entries info and return in the buffer. Cookie
 * will keep the state of each call
 */
static int
fs_getdents(int fildes, struct dirent *buf, size_t *nbyte,
    char *pn_path, long *dpos, longlong_t *cookie,
    long *n_entries, dent_arg_t *darg)
{
	struct dirent *ptr;
	char file_path[PATH_MAX + 1];
	fs_fhandle_t fh;
	struct stat64 st;
	char *p;
	int len;
	int rv;

	if (*nbyte == 0) {
		(void) memset((char *)buf, 0, MAX_DENT_BUF_SIZE);
		*nbyte = rv = getdents(fildes, buf, darg->da_size);
		*cookie = 0LL;

		if (rv <= 0)
			return (rv);
	}

	p = (char *)buf + *cookie;
	len = *nbyte;
	do {
		/* LINTED improper alignment */
		ptr = (struct dirent *)p;
		*dpos =  ptr->d_off;

		if (rootfs_dot_or_dotdot(ptr->d_name))
			goto skip_entry;

		(void) snprintf(file_path, PATH_MAX, "%s/", pn_path);
		(void) strlcat(file_path, ptr->d_name, PATH_MAX + 1);
		(void) memset(&fh, 0, sizeof (fs_fhandle_t));

		if (lstat64(file_path, &st) != 0) {
			rv = -1;
			break;
		}

		fh.fh_fid = st.st_ino;

		if (S_ISDIR(st.st_mode))
			goto skip_entry;

		if (fs_populate_dents(darg, strlen(ptr->d_name),
		    (char *)ptr->d_name, n_entries, &st, &fh) != 0)
			break;

skip_entry:
		p = p + ptr->d_reclen;
		len -= ptr->d_reclen;
	} while (len);

	*cookie = (longlong_t)(p - (char *)buf);
	*nbyte = len;
	return (rv);
}

/*
 * Read the directory entries and return the information about
 * each entry
 */
int
fs_readdir(fs_fhandle_t *ts_fh, char *path, long *dpos,
    char *nm, int *el, fs_fhandle_t *efh, struct stat64 *est)
{
	struct dirent *dp;
	char  file_path[PATH_MAX + 1];
	DIR *dirp;
	int rv;

	if ((dirp = opendir(ts_fh->fh_fpath)) == NULL)
		return (errno);

	seekdir(dirp, *dpos);
	if ((dp = readdir(dirp)) == NULL) {
		rv = 0;  /* skip this dir */
		*el = 0;
	} else {
		(void) snprintf(file_path, PATH_MAX, "%s/", path);
		(void) strlcat(file_path, dp->d_name, PATH_MAX + 1);

		rv = fs_getstat(file_path, efh, est);
		if (rv == 0) {
			*dpos = telldir(dirp);
			(void) strlcpy(nm, dp->d_name, NAME_MAX + 1);
			*el = strlen(dp->d_name);
		} else {
			*el = 0;
		}
	}
	(void) closedir(dirp);
	return (rv);
}

/*
 * Traverse the file system in the post-order way.  The description
 * and example is in the header file.
 *
 * The callback function should return 0, on success and non-zero on
 * failure.  If the callback function returns non-zero return value,
 * the traversing stops.
 */
int
traverse_post(struct fs_traverse *ftp)
{
	char path[PATH_MAX + 1]; /* full path name of the current dir */
	char nm[NAME_MAX + 1]; /* directory entry name */
	char *lp; /* last position on the path */
	int next_dir, rv;
	int pl, el; /* path and directory entry length */
	cstack_t *sp;
	fs_fhandle_t pfh, efh;
	struct stat64 pst, est;
	traverse_state_t *tsp;
	struct fst_node pn, en; /* parent and entry nodes */

	if (!ftp || !ftp->ft_path || !*ftp->ft_path || !ftp->ft_callbk) {
		NDMP_LOG(LOG_DEBUG, "Invalid argument");
		errno = EINVAL;
		return (-1);
	}

	/* set the default log function if it's not already set */
	if (!ftp->ft_logfp) {
		ftp->ft_logfp = (ft_log_t)syslog;
		NDMP_LOG(LOG_DEBUG, "Log to system log \"%s\"", ftp->ft_path);
	}

	/* set the logical path to physical path if it's not already set */
	if (!ftp->ft_lpath) {
		NDMP_LOG(LOG_DEBUG,
		    "report the same paths: \"%s\"", ftp->ft_path);
		ftp->ft_lpath = ftp->ft_path;
	}

	pl = strlen(ftp->ft_lpath);
	if (pl + 1 > PATH_MAX) { /* +1 for the '/' */
		NDMP_LOG(LOG_DEBUG, "lpath too long \"%s\"", ftp->ft_path);
		errno = ENAMETOOLONG;
		return (-1);
	}
	(void) strcpy(path, ftp->ft_lpath);
	(void) memset(&pfh, 0, sizeof (pfh));
	rv = fs_getstat(ftp->ft_lpath, &pfh, &pst);

	if (rv != 0) {
		NDMP_LOG(LOG_DEBUG,
		    "Error %d on fs_getstat(%s)", rv, ftp->ft_path);
		return (rv);
	}

	if (!S_ISDIR(pst.st_mode)) {
		pn.tn_path = ftp->ft_lpath;
		pn.tn_fh = &pfh;
		pn.tn_st = &pst;
		en.tn_path = NULL;
		en.tn_fh = NULL;
		en.tn_st = NULL;
		rv = CALLBACK(&pn, &en);
		if (VERBOSE(ftp))
			NDMP_LOG(LOG_DEBUG, "CALLBACK(%s): %d", pn.tn_path, rv);
		free(pfh.fh_fpath);
		return (rv);
	}

	sp = cstack_new();
	if (!sp) {
		errno = ENOMEM;
		free(pfh.fh_fpath);
		return (-1);
	}
	tsp = new_tsp(path);
	if (!tsp) {
		cstack_delete(sp);
		errno = ENOMEM;
		free(pfh.fh_fpath);
		return (-1);
	}
	tsp->ts_ent = tsp->ts_end;
	tsp->ts_fh = pfh;
	tsp->ts_st = pst;
	pn.tn_path = path;
	pn.tn_fh = &tsp->ts_fh;
	pn.tn_st = &tsp->ts_st;

	rv = 0;
	next_dir = 1;
	do {
		if (next_dir) {
			traverse_stats.fss_newdirs++;

			*tsp->ts_end = '\0';
			if (VERBOSE(ftp))
				NDMP_LOG(LOG_DEBUG, "pl %d \"%s\"", pl, path);
		}

		next_dir = 0;
		do {
			el = NAME_MAX;
			rv = fs_readdir(&tsp->ts_fh, pn.tn_path,
			    &tsp->ts_dpos, nm, &el,
			    &efh, &est);

			if (rv != 0) {
				free(efh.fh_fpath);
				traverse_stats.fss_readdir_err++;

				NDMP_LOG(LOG_DEBUG,
				    "Error %d on readdir(%s) pos %d",
				    rv, path, tsp->ts_dpos);
				if (STOP_ONERR(ftp))
					break;
				rv = SKIP_ENTRY;

				continue;
			}

			/* done with this directory */
			if (el == 0) {
				if (VERBOSE(ftp))
					NDMP_LOG(LOG_DEBUG,
					    "Done(%s)", pn.tn_path);
				break;
			}
			nm[el] = '\0';

			if (rootfs_dot_or_dotdot(nm)) {
				free(efh.fh_fpath);
				continue;
			}

			if (VERBOSE(ftp))
				NDMP_LOG(LOG_DEBUG, "%u dname: \"%s\"",
				    tsp->ts_dpos, nm);

			if (pl + 1 + el > PATH_MAX) {
				traverse_stats.fss_longpath_err++;

				NDMP_LOG(LOG_ERR, "Path %s/%s is too long.",
				    path, nm);
				if (STOP_ONLONG(ftp))
					rv = ENAMETOOLONG;
				free(efh.fh_fpath);
				continue;
			}

			/*
			 * Push the current directory on to the stack and
			 * dive into the entry found.
			 */
			if (S_ISDIR(est.st_mode)) {

				assert(tsp != NULL);
				if (cstack_push(sp, tsp, 0)) {
					rv = ENOMEM;
					free(efh.fh_fpath);
					break;
				}
				traverse_stats.fss_pushes++;

				/*
				 * Concatenate the current entry with the
				 * current path.  This will be the path of
				 * the new directory to be scanned.
				 *
				 * Note:
				 * sprintf(tsp->ts_end, "/%s", de->d_name);
				 * could be used here, but concatenating
				 * strings like this might be faster.
				 * The length of the new path has been
				 * checked above.  So strcpy() can be
				 * safe and should not lead to a buffer
				 * over-run.
				 */
				lp = tsp->ts_end;
				*tsp->ts_end = '/';
				(void) strcpy(tsp->ts_end + 1, nm);

				tsp = new_tsp(path);
				if (!tsp) {
					free(efh.fh_fpath);
					rv = ENOMEM;
				} else {
					next_dir = 1;
					pl += el;
					tsp->ts_fh = efh;
					tsp->ts_st = est;
					tsp->ts_ent = lp;
					pn.tn_fh = &tsp->ts_fh;
					pn.tn_st = &tsp->ts_st;
				}
				break;
			} else {
				/*
				 * The entry is not a directory so the
				 * callback function must be called.
				 */
				traverse_stats.fss_nondir_calls++;

				en.tn_path = nm;
				en.tn_fh = &efh;
				en.tn_st = &est;
				rv = CALLBACK(&pn, &en);
				free(efh.fh_fpath);
				if (VERBOSE(ftp))
					NDMP_LOG(LOG_DEBUG,
					    "CALLBACK(%s/%s): %d",
					    pn.tn_path, en.tn_path, rv);

				if (rv != 0)
					break;
			}
		} while (rv == 0);

		/*
		 * A new directory must be processed, go to the start of
		 * the loop, open it and process it.
		 */
		if (next_dir)
			continue;

		if (rv == SKIP_ENTRY)
			rv = 0; /* We should skip the current directory */

		if (rv == 0) {
			/*
			 * Remove the ent from the end of path and send it
			 * as an entry of the path.
			 */
			lp = tsp->ts_ent;
			*lp = '\0';
			efh = tsp->ts_fh;
			est = tsp->ts_st;
			free(tsp);
			if (cstack_pop(sp, (void **)&tsp, (int *)NULL))
				break;

			assert(tsp != NULL);
			pl = tsp->ts_end - path;

			if (VERBOSE(ftp))
				NDMP_LOG(LOG_DEBUG, "poped pl %d 0x%p \"%s\"",
				    pl, tsp, path);

			traverse_stats.fss_pops++;
			traverse_stats.fss_dir_calls++;

			pn.tn_fh = &tsp->ts_fh;
			pn.tn_st = &tsp->ts_st;
			en.tn_path = lp + 1;
			en.tn_fh = &efh;
			en.tn_st = &est;

			rv = CALLBACK(&pn, &en);
			free(efh.fh_fpath);
			if (VERBOSE(ftp))
				NDMP_LOG(LOG_DEBUG, "CALLBACK(%s/%s): %d",
				    pn.tn_path, en.tn_path, rv);
			/*
			 * Does not need to free tsp here.  It will be released
			 * later.
			 */
		}

		if (rv != 0 && tsp) {
			free(tsp->ts_fh.fh_fpath);
			free(tsp);
		}

	} while (rv == 0);

	/*
	 * For the 'ftp->ft_path' directory itself.
	 */
	if (rv == 0) {
		traverse_stats.fss_dir_calls++;

		pn.tn_fh = &efh;
		pn.tn_st = &est;
		en.tn_path = NULL;
		en.tn_fh = NULL;
		en.tn_st = NULL;
		rv = CALLBACK(&pn, &en);
		if (VERBOSE(ftp))
			NDMP_LOG(LOG_DEBUG, "CALLBACK(%s): %d", pn.tn_path, rv);
	}

	/*
	 * Pop and free all the remaining entries on the stack.
	 */
	while (!cstack_pop(sp, (void **)&tsp, (int *)NULL)) {
		traverse_stats.fss_stack_residue++;

		free(tsp->ts_fh.fh_fpath);
		free(tsp);
	}

	cstack_delete(sp);
	return (rv);
}

/*
 * In one pass, read all the directory entries of the specified
 * directory and call the callback function for non-directory
 * entries.
 *
 * On return:
 *    0: Lets the directory to be scanned for directory entries.
 *    < 0: Completely stops traversing.
 *    FST_SKIP: stops further scanning of the directory.  Traversing
 *        will continue with the next directory in the hierarchy.
 *    SKIP_ENTRY: Failed to get the directory entries, so the caller
 *	  should skip this entry.
 */
static int
traverse_level_nondir(struct fs_traverse *ftp,
    traverse_state_t *tsp, struct fst_node *pnp, dent_arg_t *darg)
{
	int pl; /* path length */
	int rv;
	struct fst_node en; /* entry node */
	longlong_t cookie_verf;
	fs_dent_info_t *dent;
	struct dirent *buf;
	size_t len = 0;
	int fd;

	rv = 0;
	pl = strlen(pnp->tn_path);

	buf = ndmp_malloc(MAX_DENT_BUF_SIZE);
	if (buf == NULL)
		return (errno);

	fd = open(tsp->ts_fh.fh_fpath, O_RDONLY);
	if (fd == -1) {
		free(buf);
		return (errno);
	}

	while (rv == 0) {
		long i, n_entries;

		darg->da_end = 0;
		n_entries = 0;
		rv = fs_getdents(fd, buf, &len, pnp->tn_path, &tsp->ts_dpos,
		    &cookie_verf, &n_entries, darg);
		if (rv < 0) {
			traverse_stats.fss_readdir_err++;

			NDMP_LOG(LOG_DEBUG, "Error %d on readdir(%s) pos %d",
			    rv, pnp->tn_path, tsp->ts_dpos);
			if (STOP_ONERR(ftp))
				break;
			/*
			 * We cannot read the directory entry, we should
			 * skip to the next directory.
			 */
			rv = SKIP_ENTRY;
			continue;
		} else {
			/* Break at the end of directory */
			if (rv > 0)
				rv = 0;
			else
				break;
		}

		/* LINTED imporper alignment */
		dent = (fs_dent_info_t *)darg->da_buf;
		/* LINTED imporper alignment */
		for (i = 0; i < n_entries; i++, dent = (fs_dent_info_t *)
		    ((char *)dent + dent->fd_len)) {

			if (VERBOSE(ftp))
				NDMP_LOG(LOG_DEBUG, "i %u dname: \"%s\"",
				    dent->fd_fh.fh_fid, dent->fd_name);

			if ((pl + strlen(dent->fd_name)) > PATH_MAX) {
				traverse_stats.fss_longpath_err++;

				NDMP_LOG(LOG_ERR, "Path %s/%s is too long.",
				    pnp->tn_path, dent->fd_name);
				if (STOP_ONLONG(ftp))
					rv = -ENAMETOOLONG;
				free(dent->fd_fh.fh_fpath);
				continue;
			}

			/*
			 * The entry is not a directory so the callback
			 * function must be called.
			 */
			if (!S_ISDIR(dent->fd_attr.st_mode)) {
				traverse_stats.fss_nondir_calls++;

				en.tn_path = dent->fd_name;
				en.tn_fh = &dent->fd_fh;
				en.tn_st = &dent->fd_attr;
				rv = CALLBACK(pnp, &en);
				dent->fd_fh.fh_fpath = NULL;
				if (rv < 0)
					break;
				if (rv == FST_SKIP) {
					traverse_stats.fss_nondir_skipped++;
					break;
				}
			}
		}
	}

	free(buf);
	(void) close(fd);
	return (rv);
}

/*
 * Traverse the file system in the level-order way.  The description
 * and example is in the header file.
 */
int
traverse_level(struct fs_traverse *ftp)
{
	char path[PATH_MAX + 1];	/* full path name of the current dir */
	char nm[NAME_MAX + 1];	/* directory entry name */
	char *lp;		/* last position on the path */
	int next_dir, rv;
	int pl, el;		/* path and directory entry length */

	cstack_t *sp;
	fs_fhandle_t pfh, efh;
	struct stat64 pst, est;
	traverse_state_t *tsp;
	struct fst_node pn, en;  /* parent and entry nodes */
	dent_arg_t darg;

	if (!ftp || !ftp->ft_path || !*ftp->ft_path || !ftp->ft_callbk) {
		NDMP_LOG(LOG_DEBUG, "Invalid argument");
		errno = EINVAL;
		return (-1);
	}
	/* set the default log function if it's not already set */
	if (!ftp->ft_logfp) {
		ftp->ft_logfp = (ft_log_t)syslog;
		NDMP_LOG(LOG_DEBUG, "Log to system log \"%s\"", ftp->ft_path);
	}
	if (!ftp->ft_lpath) {
		NDMP_LOG(LOG_DEBUG,
		    "report the same paths \"%s\"", ftp->ft_path);
		ftp->ft_lpath = ftp->ft_path;
	}

	pl = strlen(ftp->ft_lpath);
	if (pl + 1 > PATH_MAX) { /* +1 for the '/' */
		NDMP_LOG(LOG_DEBUG, "lpath too long \"%s\"", ftp->ft_path);
		errno = ENAMETOOLONG;
		return (-1);
	}
	(void) strcpy(path, ftp->ft_lpath);
	(void) memset(&pfh, 0, sizeof (pfh));
	rv = fs_getstat(ftp->ft_lpath, &pfh, &pst);
	if (rv != 0) {
		NDMP_LOG(LOG_DEBUG,
		    "Error %d on fs_getstat(%s)", rv, ftp->ft_path);
		return (-1);
	}

	en.tn_path = NULL;
	en.tn_fh = NULL;
	en.tn_st = NULL;
	if (!S_ISDIR(pst.st_mode)) {
		pn.tn_path = ftp->ft_lpath;
		pn.tn_fh = &pfh;
		pn.tn_st = &pst;
		rv = CALLBACK(&pn, &en);
		if (VERBOSE(ftp))
			NDMP_LOG(LOG_DEBUG, "CALLBACK(%s): %d", pn.tn_path, rv);

		free(pfh.fh_fpath);
		return (rv);
	}

	sp = cstack_new();
	if (!sp) {
		free(pfh.fh_fpath);
		errno = ENOMEM;
		return (-1);
	}
	tsp = new_tsp(path);
	if (!tsp) {
		cstack_delete(sp);
		free(pfh.fh_fpath);
		errno = ENOMEM;
		return (-1);
	}

	darg.da_buf = ndmp_malloc(MAX_DENT_BUF_SIZE);
	if (!darg.da_buf) {
		cstack_delete(sp);
		free(pfh.fh_fpath);
		free(tsp);
		errno = ENOMEM;
		return (-1);
	}
	darg.da_size = MAX_DENT_BUF_SIZE;

	tsp->ts_ent = tsp->ts_end;
	tsp->ts_fh = pfh;
	tsp->ts_st = pst;
	pn.tn_path = path;
	pn.tn_fh = &tsp->ts_fh;
	pn.tn_st = &tsp->ts_st;

	/* call the callback function on the path itself */
	traverse_stats.fss_dir_calls++;
	rv = CALLBACK(&pn, &en);
	if (rv < 0) {
		free(tsp);
		goto end;
	}
	if (rv == FST_SKIP) {
		traverse_stats.fss_dir_skipped++;
		free(tsp);
		rv = 0;
		goto end;
	}

	rv = 0;
	next_dir = 1;
	do {
		if (next_dir) {
			traverse_stats.fss_newdirs++;

			*tsp->ts_end = '\0';
			if (VERBOSE(ftp))
				NDMP_LOG(LOG_DEBUG, "pl %d \"%s\"", pl, path);

			rv = traverse_level_nondir(ftp, tsp, &pn, &darg);
			if (rv < 0) {
				NEGATE(rv);
				free(tsp->ts_fh.fh_fpath);
				free(tsp);
				break;
			}
			/*
			 * If skipped by the callback function or
			 * error happened reading the information
			 */
			if (rv == FST_SKIP || rv == SKIP_ENTRY) {
				/*
				 * N.B. next_dir should be set to 0 as
				 * well. This prevents the infinite loop.
				 * If it's not set the same directory will
				 * be poped from the stack and will be
				 * scanned again.
				 */
				next_dir = 0;
				rv = 0;
				goto skip_dir;
			}

			/* re-start reading entries of the directory */
			tsp->ts_dpos = 0;
		}

		next_dir = 0;
		do {
			el = NAME_MAX;
			rv = fs_readdir(&tsp->ts_fh, pn.tn_path,
			    &tsp->ts_dpos, nm, &el, &efh,
			    &est);
			if (rv != 0) {
				traverse_stats.fss_readdir_err++;

				NDMP_LOG(LOG_DEBUG,
				    "Error %d on readdir(%s) pos %d",
				    rv, path, tsp->ts_dpos);
				if (STOP_ONERR(ftp))
					break;
				rv = SKIP_ENTRY;
				continue;
			}

			/* done with this directory */
			if (el == 0)
				break;

			nm[el] = '\0';

			if (rootfs_dot_or_dotdot(nm)) {
				free(efh.fh_fpath);
				continue;
			}

			if (VERBOSE(ftp))
				NDMP_LOG(LOG_DEBUG, "%u dname: \"%s\"",
				    tsp->ts_dpos, nm);

			if (pl + 1 + el > PATH_MAX) {
				/*
				 * The long paths were already encountered
				 * when processing non-dir entries in.
				 * traverse_level_nondir.
				 * We don't increase fss_longpath_err
				 * counter for them again here.
				 */
				NDMP_LOG(LOG_ERR, "Path %s/%s is too long.",
				    path, nm);
				if (STOP_ONLONG(ftp))
					rv = ENAMETOOLONG;
				free(efh.fh_fpath);
				continue;
			}

			if (!S_ISDIR(est.st_mode))
				continue;

			/*
			 * Call the callback function for the new
			 * directory found, then push the current
			 * directory on to the stack.  Then dive
			 * into the entry found.
			 */
			traverse_stats.fss_dir_calls++;
			en.tn_path = nm;
			en.tn_fh = &efh;
			en.tn_st = &est;
			rv = CALLBACK(&pn, &en);

			if (rv < 0) {
				NEGATE(rv);
				free(efh.fh_fpath);
				break;
			}
			if (rv == FST_SKIP) {
				traverse_stats.fss_dir_skipped++;
				free(efh.fh_fpath);
				rv = 0;
				continue;
			}

			/*
			 * Push the current directory on to the stack and
			 * dive into the entry found.
			 */
			if (cstack_push(sp, tsp, 0)) {
				rv = ENOMEM;
			} else {
				traverse_stats.fss_pushes++;

				lp = tsp->ts_end;
				*tsp->ts_end = '/';
				(void) strcpy(tsp->ts_end + 1, nm);

				tsp = new_tsp(path);
				if (!tsp)
					rv = ENOMEM;
				else {
					next_dir = 1;
					pl += el + 1;
					tsp->ts_fh = efh;
					tsp->ts_st = est;
					tsp->ts_ent = lp;
					pn.tn_fh = &tsp->ts_fh;
					pn.tn_st = &tsp->ts_st;
				}
			}
			break;

		} while (rv == 0);

		/*
		 * A new directory must be processed, go to the start of
		 * the loop, open it and process it.
		 */
		if (next_dir)
			continue;
skip_dir:
		if (tsp) {
			free(tsp->ts_fh.fh_fpath);
			free(tsp);
		}

		if (rv == SKIP_ENTRY)
			rv = 0;

		if (rv == 0) {
			if (cstack_pop(sp, (void **)&tsp, (int *)NULL))
				break;

			traverse_stats.fss_pops++;

			if (VERBOSE(ftp))
				NDMP_LOG(LOG_DEBUG,
				    "Poped pl %d \"%s\"", pl, path);

			*tsp->ts_end = '\0';
			pl = tsp->ts_end - path;
			pn.tn_fh = &tsp->ts_fh;
			pn.tn_st = &tsp->ts_st;
		}
	} while (rv == 0);

	/*
	 * Pop and free all the remaining entries on the stack.
	 */
	while (!cstack_pop(sp, (void **)&tsp, (int *)NULL)) {
		traverse_stats.fss_stack_residue++;

		free(tsp->ts_fh.fh_fpath);
		free(tsp);
	}
end:
	free(darg.da_buf);
	cstack_delete(sp);
	return (rv);
}

/*
 * filecopy - Copy a file
 *
 * Parameters:
 *  char *dest  - Destination path
 *  char *src   - Source path
 *
 * Returns:
 *  0    - No errors
 *  #0   - Error occured
 *		-4   - read/write error
 *		-5   - source modified during copy
 *
 * Simplified version for Solaris
 */
#define	BUFSIZE	32768
int
filecopy(char *dest, char *src)
{
	FILE *src_fh = 0;
	FILE *dst_fh = 0;
	struct stat64 src_attr;
	struct stat64 dst_attr;
	char *buf = 0;
	u_longlong_t bytes_to_copy;
	size_t nbytes;
	int file_copied = 0;

	buf = ndmp_malloc(BUFSIZE);
	if (!buf)
		return (-1);

	src_fh = fopen(src, "r");
	if (src_fh == 0) {
		free(buf);
		return (-2);
	}

	dst_fh = fopen(dest, "w");
	if (dst_fh == NULL) {
		free(buf);
		(void) fclose(src_fh);
		return (-3);
	}

	if (stat64(src, &src_attr) < 0) {
		free(buf);
		(void) fclose(src_fh);
		(void) fclose(dst_fh);
		return (-2);
	}

	bytes_to_copy = src_attr.st_size;
	while (bytes_to_copy) {
		if (bytes_to_copy > BUFSIZE)
			nbytes = BUFSIZE;
		else
			nbytes = bytes_to_copy;

		if ((fread(buf, nbytes, 1, src_fh) != 1) ||
		    (fwrite(buf, nbytes, 1, dst_fh) != 1))
			break;
		bytes_to_copy -= nbytes;
	}

	(void) fclose(src_fh);
	(void) fclose(dst_fh);

	if (bytes_to_copy > 0) {
		free(buf);
		/* short read/write, remove the partial file */
		return (-4);
	}

	if (stat64(src, &dst_attr) < 0) {
		free(buf);
		return (-2);
	}

	free(buf);

	if (!file_copied)
		return (-5);	/* source modified during copy */
	else
		return (0);
}
