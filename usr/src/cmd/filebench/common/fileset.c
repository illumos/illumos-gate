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
 *
 * Portions Copyright 2008 Denis Cheng
 */

#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <math.h>
#include <libgen.h>
#include <sys/mman.h>
#include <sys/shm.h>

#include "filebench.h"
#include "fileset.h"
#include "gamma_dist.h"
#include "utils.h"

/*
 * File sets, of type fileset_t, are entities which contain
 * information about collections of files and subdirectories in Filebench.
 * The fileset, once populated, consists of a tree of fileset entries of
 * type filesetentry_t which specify files and directories.  The fileset
 * is rooted in a directory specified by fileset_path, and once the populated
 * fileset has been created, has a tree of directories and files
 * corresponding to the fileset's filesetentry tree.
 *
 * Fileset entities are allocated by fileset_define() which is called from
 * parser_gram.y: parser_fileset_define(). The filesetentry tree corrseponding
 * to the eventual directory and file tree to be instantiated on the storage
 * medium is built by fileset_populate(), which is This routine is called
 * from fileset_createset(), which is in turn called by fileset_createset().
 * After calling fileset_populate(), fileset_createset() will call
 * fileset_create() to pre-allocate designated files and directories.
 *
 * Fileset_createset() is called from parser_gram.y: parser_create_fileset()
 * when a "create fileset" or "run" command is encountered. When the
 * "create fileset" command is used, it is generally paired with
 * a "create processes" command, and must appear first, in order to
 * instantiate all the files in the fileset before trying to use them.
 */

static int fileset_checkraw(fileset_t *fileset);

/* maximum parallel allocation control */
#define	MAX_PARALLOC_THREADS 32

/*
 * returns pointer to file or fileset
 * string, as appropriate
 */
static char *
fileset_entity_name(fileset_t *fileset)
{
	if (fileset->fs_attrs & FILESET_IS_FILE)
		return ("file");
	else
		return ("fileset");
}

/*
 * Removes the last file or directory name from a pathname.
 * Basically removes characters from the end of the path by
 * setting them to \0 until a forward slash '/' is
 * encountered. It also removes the forward slash.
 */
static char *
trunc_dirname(char *dir)
{
	char *s = dir + strlen(dir);

	while (s != dir) {
		int c = *s;

		*s = 0;
		if (c == '/')
			break;
		s--;
	}
	return (dir);
}

/*
 * Prints a list of allowed options and how to specify them.
 */
void
fileset_usage(void)
{
	(void) fprintf(stderr,
	    "define [file name=<name> | fileset name=<name>],path=<pathname>,"
	    ",entries=<number>\n");
	(void) fprintf(stderr,
	    "		        [,filesize=[size]]\n");
	(void) fprintf(stderr,
	    "		        [,dirwidth=[width]]\n");
	(void) fprintf(stderr,
	    "		        [,dirdepthrv=$random_variable_name]\n");
	(void) fprintf(stderr,
	    "		        [,dirgamma=[100-10000]] "
	    "(Gamma * 1000)\n");
	(void) fprintf(stderr,
	    "		        [,sizegamma=[100-10000]] (Gamma * 1000)\n");
	(void) fprintf(stderr,
	    "		        [,prealloc=[percent]]\n");
	(void) fprintf(stderr, "		        [,paralloc]\n");
	(void) fprintf(stderr, "		        [,reuse]\n");
	(void) fprintf(stderr, "\n");
}

/*
 * Frees up memory mapped file region of supplied size. The
 * file descriptor "fd" indicates which memory mapped file.
 * If successful, returns 0. Otherwise returns -1 if "size"
 * is zero, or -1 times the number of times msync() failed.
 */
static int
fileset_freemem(int fd, off64_t size)
{
	off64_t left;
	int ret = 0;

	for (left = size; left > 0; left -= MMAP_SIZE) {
		off64_t thismapsize;
		caddr_t addr;

		thismapsize = MIN(MMAP_SIZE, left);
		addr = mmap64(0, thismapsize, PROT_READ|PROT_WRITE,
		    MAP_SHARED, fd, size - left);
		ret += msync(addr, thismapsize, MS_INVALIDATE);
		(void) munmap(addr, thismapsize);
	}
	return (ret);
}

/*
 * Creates a path string from the filesetentry_t "*entry"
 * and all of its parent's path names. The resulting path
 * is a concatination of all the individual parent paths.
 * Allocates memory for the path string and returns a
 * pointer to it.
 */
char *
fileset_resolvepath(filesetentry_t *entry)
{
	filesetentry_t *fsep = entry;
	char path[MAXPATHLEN];
	char pathtmp[MAXPATHLEN];
	char *s;

	path[0] = '\0';
	while (fsep->fse_parent) {
		(void) strcpy(pathtmp, "/");
		(void) fb_strlcat(pathtmp, fsep->fse_path, MAXPATHLEN);
		(void) fb_strlcat(pathtmp, path, MAXPATHLEN);
		(void) fb_strlcpy(path, pathtmp, MAXPATHLEN);
		fsep = fsep->fse_parent;
	}

	s = malloc(strlen(path) + 1);
	(void) fb_strlcpy(s, path, MAXPATHLEN);
	return (s);
}

/*
 * Creates multiple nested directories as required by the
 * supplied path. Starts at the end of the path, creating
 * a list of directories to mkdir, up to the root of the
 * path, then mkdirs them one at a time from the root on down.
 */
static int
fileset_mkdir(char *path, int mode)
{
	char *p;
	char *dirs[65536];
	int i = 0;

	if ((p = strdup(path)) == NULL)
		goto null_str;

	/*
	 * Fill an array of subdirectory path names until either we
	 * reach the root or encounter an already existing subdirectory
	 */
	/* CONSTCOND */
	while (1) {
		struct stat64 sb;

		if (stat64(p, &sb) == 0)
			break;
		if (strlen(p) < 3)
			break;
		if ((dirs[i] = strdup(p)) == NULL) {
			free(p);
			goto null_str;
		}

		(void) trunc_dirname(p);
		i++;
	}

	/* Make the directories, from closest to root downwards. */
	for (--i; i >= 0; i--) {
		(void) mkdir(dirs[i], mode);
		free(dirs[i]);
	}

	free(p);
	return (FILEBENCH_OK);

null_str:
	/* clean up */
	for (--i; i >= 0; i--)
		free(dirs[i]);

	filebench_log(LOG_ERROR,
	    "Failed to create directory path %s: Out of memory", path);
	return (FILEBENCH_ERROR);
}

/*
 * creates the subdirectory tree for a fileset.
 */
static int
fileset_create_subdirs(fileset_t *fileset, char *filesetpath)
{
	filesetentry_t *direntry;
	char full_path[MAXPATHLEN];
	char *part_path;

	/* walk the subdirectory list, enstanciating subdirs */
	direntry = fileset->fs_dirlist;
	while (direntry) {
		(void) fb_strlcpy(full_path, filesetpath, MAXPATHLEN);
		part_path = fileset_resolvepath(direntry);
		(void) fb_strlcat(full_path, part_path, MAXPATHLEN);
		free(part_path);

		/* now create this portion of the subdirectory tree */
		if (fileset_mkdir(full_path, 0755) == FILEBENCH_ERROR)
			return (FILEBENCH_ERROR);

		direntry = direntry->fse_nextoftype;
	}
	return (FILEBENCH_OK);
}

/*
 * move filesetentry between exist tree and non-exist tree, source_tree
 * to destination tree.
 */
static void
fileset_move_entry(avl_tree_t *src_tree, avl_tree_t *dst_tree,
    filesetentry_t *entry)
{
	avl_remove(src_tree, entry);
	avl_add(dst_tree, entry);
}

/*
 * given a fileset entry, determines if the associated leaf directory
 * needs to be made or not, and if so does the mkdir.
 */
static int
fileset_alloc_leafdir(filesetentry_t *entry)
{
	fileset_t *fileset;
	char path[MAXPATHLEN];
	struct stat64 sb;
	char *pathtmp;

	fileset = entry->fse_fileset;
	(void) fb_strlcpy(path, avd_get_str(fileset->fs_path), MAXPATHLEN);
	(void) fb_strlcat(path, "/", MAXPATHLEN);
	(void) fb_strlcat(path, avd_get_str(fileset->fs_name), MAXPATHLEN);
	pathtmp = fileset_resolvepath(entry);
	(void) fb_strlcat(path, pathtmp, MAXPATHLEN);
	free(pathtmp);

	filebench_log(LOG_DEBUG_IMPL, "Populated %s", entry->fse_path);

	/* see if not reusing and this directory does not exist */
	if (!((entry->fse_flags & FSE_REUSING) && (stat64(path, &sb) == 0))) {

		/* No file or not reusing, so create */
		if (mkdir(path, 0755) < 0) {
			filebench_log(LOG_ERROR,
			    "Failed to pre-allocate leaf directory %s: %s",
			    path, strerror(errno));
			fileset_unbusy(entry, TRUE, FALSE, 0);
			return (FILEBENCH_ERROR);
		}
	}

	/* unbusy the allocated entry */
	fileset_unbusy(entry, TRUE, TRUE, 0);
	return (FILEBENCH_OK);
}

/*
 * given a fileset entry, determines if the associated file
 * needs to be allocated or not, and if so does the allocation.
 */
static int
fileset_alloc_file(filesetentry_t *entry)
{
	fileset_t *fileset;
	char path[MAXPATHLEN];
	char *buf;
	struct stat64 sb;
	char *pathtmp;
	off64_t seek;
	int fd;

	fileset = entry->fse_fileset;
	(void) fb_strlcpy(path, avd_get_str(fileset->fs_path), MAXPATHLEN);
	(void) fb_strlcat(path, "/", MAXPATHLEN);
	(void) fb_strlcat(path, avd_get_str(fileset->fs_name), MAXPATHLEN);
	pathtmp = fileset_resolvepath(entry);
	(void) fb_strlcat(path, pathtmp, MAXPATHLEN);
	free(pathtmp);

	filebench_log(LOG_DEBUG_IMPL, "Populated %s", entry->fse_path);

	/* see if reusing and this file exists */
	if ((entry->fse_flags & FSE_REUSING) && (stat64(path, &sb) == 0)) {
		if ((fd = open64(path, O_RDWR)) < 0) {
			filebench_log(LOG_INFO,
			    "Attempted but failed to Re-use file %s",
			    path);
			fileset_unbusy(entry, TRUE, FALSE, 0);
			return (FILEBENCH_ERROR);
		}

		if (sb.st_size == (off64_t)entry->fse_size) {
			filebench_log(LOG_DEBUG_IMPL,
			    "Re-using file %s", path);

			if (!avd_get_bool(fileset->fs_cached))
				(void) fileset_freemem(fd,
				    entry->fse_size);

			(void) close(fd);

			/* unbusy the allocated entry */
			fileset_unbusy(entry, TRUE, TRUE, 0);
			return (FILEBENCH_OK);

		} else if (sb.st_size > (off64_t)entry->fse_size) {
			/* reuse, but too large */
			filebench_log(LOG_DEBUG_IMPL,
			    "Truncating & re-using file %s", path);

#ifdef HAVE_FTRUNCATE64
			(void) ftruncate64(fd, (off64_t)entry->fse_size);
#else
			(void) ftruncate(fd, (off_t)entry->fse_size);
#endif

			if (!avd_get_bool(fileset->fs_cached))
				(void) fileset_freemem(fd,
				    entry->fse_size);

			(void) close(fd);

			/* unbusy the allocated entry */
			fileset_unbusy(entry, TRUE, TRUE, 0);
			return (FILEBENCH_OK);
		}
	} else {

		/* No file or not reusing, so create */
		if ((fd = open64(path, O_RDWR | O_CREAT, 0644)) < 0) {
			filebench_log(LOG_ERROR,
			    "Failed to pre-allocate file %s: %s",
			    path, strerror(errno));

			/* unbusy the unallocated entry */
			fileset_unbusy(entry, TRUE, FALSE, 0);
			return (FILEBENCH_ERROR);
		}
	}

	if ((buf = (char *)malloc(FILE_ALLOC_BLOCK)) == NULL) {
		/* unbusy the unallocated entry */
		fileset_unbusy(entry, TRUE, FALSE, 0);
		return (FILEBENCH_ERROR);
	}

	for (seek = 0; seek < entry->fse_size; ) {
		off64_t wsize;
		int ret = 0;

		/*
		 * Write FILE_ALLOC_BLOCK's worth,
		 * except on last write
		 */
		wsize = MIN(entry->fse_size - seek, FILE_ALLOC_BLOCK);

		ret = write(fd, buf, wsize);
		if (ret != wsize) {
			filebench_log(LOG_ERROR,
			    "Failed to pre-allocate file %s: %s",
			    path, strerror(errno));
			(void) close(fd);
			free(buf);
			fileset_unbusy(entry, TRUE, FALSE, 0);
			return (FILEBENCH_ERROR);
		}
		seek += wsize;
	}

	if (!avd_get_bool(fileset->fs_cached))
		(void) fileset_freemem(fd, entry->fse_size);

	(void) close(fd);

	free(buf);

	/* unbusy the allocated entry */
	fileset_unbusy(entry, TRUE, TRUE, 0);

	filebench_log(LOG_DEBUG_IMPL,
	    "Pre-allocated file %s size %llu",
	    path, (u_longlong_t)entry->fse_size);

	return (FILEBENCH_OK);
}

/*
 * given a fileset entry, determines if the associated file
 * needs to be allocated or not, and if so does the allocation.
 * Sets shm_fsparalloc_count to -1 on error.
 */
static void *
fileset_alloc_thread(filesetentry_t *entry)
{
	if (fileset_alloc_file(entry) == FILEBENCH_ERROR) {
		(void) pthread_mutex_lock(&filebench_shm->shm_fsparalloc_lock);
		filebench_shm->shm_fsparalloc_count = -1;
	} else {
		(void) pthread_mutex_lock(&filebench_shm->shm_fsparalloc_lock);
		filebench_shm->shm_fsparalloc_count--;
	}

	(void) pthread_cond_signal(&filebench_shm->shm_fsparalloc_cv);
	(void) pthread_mutex_unlock(&filebench_shm->shm_fsparalloc_lock);

	pthread_exit(NULL);
	return (NULL);
}


/*
 * First creates the parent directories of the file using
 * fileset_mkdir(). Then Optionally sets the O_DSYNC flag
 * and opens the file with open64(). It unlocks the fileset
 * entry lock, sets the DIRECTIO_ON or DIRECTIO_OFF flags
 * as requested, and returns the file descriptor integer
 * for the opened file.
 */
int
fileset_openfile(fileset_t *fileset,
    filesetentry_t *entry, int flag, int filemode, int attrs)
{
	char path[MAXPATHLEN];
	char dir[MAXPATHLEN];
	char *pathtmp;
	struct stat64 sb;
	int fd;
	int open_attrs = 0;

	(void) fb_strlcpy(path, avd_get_str(fileset->fs_path), MAXPATHLEN);
	(void) fb_strlcat(path, "/", MAXPATHLEN);
	(void) fb_strlcat(path, avd_get_str(fileset->fs_name), MAXPATHLEN);
	pathtmp = fileset_resolvepath(entry);
	(void) fb_strlcat(path, pathtmp, MAXPATHLEN);
	(void) fb_strlcpy(dir, path, MAXPATHLEN);
	free(pathtmp);
	(void) trunc_dirname(dir);

	/* If we are going to create a file, create the parent dirs */
	if ((flag & O_CREAT) && (stat64(dir, &sb) != 0)) {
		if (fileset_mkdir(dir, 0755) == FILEBENCH_ERROR)
			return (FILEBENCH_ERROR);
	}

	if (attrs & FLOW_ATTR_DSYNC) {
#ifdef sun
		open_attrs |= O_DSYNC;
#else
		open_attrs |= O_FSYNC;
#endif
	}

	if ((fd = open64(path, flag | open_attrs, filemode)) < 0) {
		filebench_log(LOG_ERROR,
		    "Failed to open file %d, %s, with status %x: %s",
		    entry->fse_index, path, entry->fse_flags, strerror(errno));

		fileset_unbusy(entry, FALSE, FALSE, 0);
		return (FILEBENCH_ERROR);
	}

	if (flag & O_CREAT)
		fileset_unbusy(entry, TRUE, TRUE, 1);
	else
		fileset_unbusy(entry, FALSE, FALSE, 1);

#ifdef sun
	if (attrs & FLOW_ATTR_DIRECTIO)
		(void) directio(fd, DIRECTIO_ON);
	else
		(void) directio(fd, DIRECTIO_OFF);
#endif

	return (fd);
}

/*
 * removes all filesetentries from their respective btrees, and puts them
 * on the free list. The supplied argument indicates which free list to
 * use.
 */
static void
fileset_pickreset(fileset_t *fileset, int entry_type)
{
	filesetentry_t	*entry;

	switch (entry_type & FILESET_PICKMASK) {
	case FILESET_PICKFILE:
		entry = (filesetentry_t *)avl_first(&fileset->fs_noex_files);

		/* make sure non-existing files are marked free */
		while (entry) {
			entry->fse_flags |= FSE_FREE;
			entry->fse_open_cnt = 0;
			fileset_move_entry(&fileset->fs_noex_files,
			    &fileset->fs_free_files, entry);
			entry =  AVL_NEXT(&fileset->fs_noex_files, entry);
		}

		/* free up any existing files */
		entry = (filesetentry_t *)avl_first(&fileset->fs_exist_files);

		while (entry) {
			entry->fse_flags |= FSE_FREE;
			entry->fse_open_cnt = 0;
			fileset_move_entry(&fileset->fs_exist_files,
			    &fileset->fs_free_files, entry);

			entry =  AVL_NEXT(&fileset->fs_exist_files, entry);
		}

		break;

	case FILESET_PICKDIR:
		/* nothing to reset, as all (sub)dirs always exist */
		break;

	case FILESET_PICKLEAFDIR:
		entry = (filesetentry_t *)
		    avl_first(&fileset->fs_noex_leaf_dirs);

		/* make sure non-existing leaf dirs are marked free */
		while (entry) {
			entry->fse_flags |= FSE_FREE;
			entry->fse_open_cnt = 0;
			fileset_move_entry(&fileset->fs_noex_leaf_dirs,
			    &fileset->fs_free_leaf_dirs, entry);
			entry =  AVL_NEXT(&fileset->fs_noex_leaf_dirs, entry);
		}

		/* free up any existing leaf dirs */
		entry = (filesetentry_t *)
		    avl_first(&fileset->fs_exist_leaf_dirs);

		while (entry) {
			entry->fse_flags |= FSE_FREE;
			entry->fse_open_cnt = 0;
			fileset_move_entry(&fileset->fs_exist_leaf_dirs,
			    &fileset->fs_free_leaf_dirs, entry);

			entry =  AVL_NEXT(&fileset->fs_exist_leaf_dirs, entry);
		}

		break;
	}
}

/*
 * find a filesetentry from the fileset using the supplied index
 */
static filesetentry_t *
fileset_find_entry(avl_tree_t *atp, uint_t index)
{
	avl_index_t	found_loc;
	filesetentry_t	desired_fse, *found_fse;

	/* find the file with the desired index, if it is in the tree */
	desired_fse.fse_index = index;
	found_fse = avl_find(atp, (void *)(&desired_fse), &found_loc);
	if (found_fse != NULL)
		return (found_fse);

	/* if requested node not found, find next higher node */
	found_fse = avl_nearest(atp, found_loc, AVL_AFTER);
	if (found_fse != NULL)
		return (found_fse);

	/* might have hit the end, return lowest available index node */
	found_fse = avl_first(atp);
	return (found_fse);
}

/*
 * Selects a fileset entry from a fileset. If the
 * FILESET_PICKLEAFDIR flag is set it will pick a leaf directory entry,
 * if the FILESET_PICKDIR flag is set it will pick a non leaf directory
 * entry, otherwise a file entry. The FILESET_PICKUNIQUE
 * flag will take an entry off of one of the free (unused)
 * lists (file or directory), otherwise the entry will be
 * picked off of one of the rotor lists (file or directory).
 * The FILESET_PICKEXISTS will insure that only extant
 * (FSE_EXISTS) state files are selected, while
 * FILESET_PICKNOEXIST insures that only non extant
 * (not FSE_EXISTS) state files are selected.
 * Note that the selected fileset entry (file) is returned
 * with its FSE_BUSY flag (in fse_flags) set.
 */
filesetentry_t *
fileset_pick(fileset_t *fileset, int flags, int tid, int index)
{
	filesetentry_t *entry = NULL;
	filesetentry_t *start_point;
	avl_tree_t *atp;
	fbint_t max_entries;

	(void) ipc_mutex_lock(&fileset->fs_pick_lock);

	/* see if we have to wait for available files or directories */
	switch (flags & FILESET_PICKMASK) {
	case FILESET_PICKFILE:
		if (fileset->fs_filelist == NULL)
			goto empty;

		while (fileset->fs_idle_files == 0) {
			(void) pthread_cond_wait(&fileset->fs_idle_files_cv,
			    &fileset->fs_pick_lock);
		}

		max_entries = fileset->fs_constentries;
		if (flags & FILESET_PICKUNIQUE) {
			atp = &fileset->fs_free_files;
		} else if (flags & FILESET_PICKNOEXIST) {
			atp = &fileset->fs_noex_files;
		} else {
			atp = &fileset->fs_exist_files;
		}
		break;

	case FILESET_PICKDIR:
		if (fileset->fs_dirlist == NULL)
			goto empty;

		while (fileset->fs_idle_dirs == 0) {
			(void) pthread_cond_wait(&fileset->fs_idle_dirs_cv,
			    &fileset->fs_pick_lock);
		}

		max_entries = 1;
		atp = &fileset->fs_dirs;
		break;

	case FILESET_PICKLEAFDIR:
		if (fileset->fs_leafdirlist == NULL)
			goto empty;

		while (fileset->fs_idle_leafdirs == 0) {
			(void) pthread_cond_wait(&fileset->fs_idle_leafdirs_cv,
			    &fileset->fs_pick_lock);
		}

		max_entries = fileset->fs_constleafdirs;
		if (flags & FILESET_PICKUNIQUE) {
			atp = &fileset->fs_free_leaf_dirs;
		} else if (flags & FILESET_PICKNOEXIST) {
			atp = &fileset->fs_noex_leaf_dirs;
		} else {
			atp = &fileset->fs_exist_leaf_dirs;
		}
		break;
	}

	/* see if asking for impossible */
	if (avl_is_empty(atp))
		goto empty;

	if (flags & FILESET_PICKUNIQUE) {
		uint64_t  index64;

		/*
		 * pick at random from free list in order to
		 * distribute initially allocated files more
		 * randomly on storage media. Use uniform
		 * random number generator to select index
		 * if it is not supplied with pick call.
		 */
		if (index) {
			index64 = index;
		} else {
			if (filebench_randomno64(&index64, max_entries, 1,
			    NULL) == FILEBENCH_ERROR)
				return (NULL);
		}

		entry = fileset_find_entry(atp, (int)index64);

		if (entry == NULL)
			goto empty;

	} else if (flags & FILESET_PICKBYINDEX) {
		/* pick by supplied index */
		entry = fileset_find_entry(atp, index);

	} else {
		/* pick in rotation */
		switch (flags & FILESET_PICKMASK) {
		case FILESET_PICKFILE:
			if (flags & FILESET_PICKNOEXIST) {
				entry = fileset_find_entry(atp,
				    fileset->fs_file_nerotor);
				fileset->fs_file_nerotor =
				    entry->fse_index + 1;
			} else {
				entry = fileset_find_entry(atp,
				    fileset->fs_file_exrotor[tid]);
				fileset->fs_file_exrotor[tid] =
				    entry->fse_index + 1;
			}
			break;

		case FILESET_PICKDIR:
			entry = fileset_find_entry(atp, fileset->fs_dirrotor);
			fileset->fs_dirrotor = entry->fse_index + 1;
			break;

		case FILESET_PICKLEAFDIR:
			if (flags & FILESET_PICKNOEXIST) {
				entry = fileset_find_entry(atp,
				    fileset->fs_leafdir_nerotor);
				fileset->fs_leafdir_nerotor =
				    entry->fse_index + 1;
			} else {
				entry = fileset_find_entry(atp,
				    fileset->fs_leafdir_exrotor);
				fileset->fs_leafdir_exrotor =
				    entry->fse_index + 1;
			}
			break;
		}
	}

	if (entry == NULL)
		goto empty;

	/* see if entry in use */
	start_point = entry;
	while (entry->fse_flags & FSE_BUSY) {

		/* it is, so try next */
		entry = AVL_NEXT(atp, entry);
		if (entry == NULL)
			entry = avl_first(atp);

		/* see if we have wrapped around */
		if ((entry == NULL) || (entry == start_point)) {
			filebench_log(LOG_DEBUG_SCRIPT,
			    "All %d files are busy", avl_numnodes(atp));
			goto empty;
		}

	}

	/* update file or directory idle counts */
	switch (flags & FILESET_PICKMASK) {
	case FILESET_PICKFILE:
		fileset->fs_idle_files--;
		break;
	case FILESET_PICKDIR:
		fileset->fs_idle_dirs--;
		break;
	case FILESET_PICKLEAFDIR:
		fileset->fs_idle_leafdirs--;
		break;
	}

	/* Indicate that file or directory is now busy */
	entry->fse_flags |= FSE_BUSY;

	(void) ipc_mutex_unlock(&fileset->fs_pick_lock);
	filebench_log(LOG_DEBUG_SCRIPT, "Picked file %s", entry->fse_path);
	return (entry);

empty:
	filebench_log(LOG_DEBUG_SCRIPT, "No file found");
	(void) ipc_mutex_unlock(&fileset->fs_pick_lock);
	return (NULL);
}

/*
 * Removes a filesetentry from the "FSE_BUSY" state, signaling any threads
 * that are waiting for a NOT BUSY filesetentry. Also sets whether it is
 * existant or not, or leaves that designation alone.
 */
void
fileset_unbusy(filesetentry_t *entry, int update_exist,
    int new_exist_val, int open_cnt_incr)
{
	fileset_t *fileset = NULL;

	if (entry)
		fileset = entry->fse_fileset;

	if (fileset == NULL) {
		filebench_log(LOG_ERROR, "fileset_unbusy: NO FILESET!");
		return;
	}

	(void) ipc_mutex_lock(&fileset->fs_pick_lock);

	/* modify FSE_EXIST flag and actual dirs/files count, if requested */
	if (update_exist) {
		if (new_exist_val == TRUE) {
			if (entry->fse_flags & FSE_FREE) {

				/* asked to set and it was free */
				entry->fse_flags |= FSE_EXISTS;
				entry->fse_flags &= (~FSE_FREE);
				switch (entry->fse_flags & FSE_TYPE_MASK) {
				case FSE_TYPE_FILE:
					fileset_move_entry(
					    &fileset->fs_free_files,
					    &fileset->fs_exist_files, entry);
					break;

				case FSE_TYPE_DIR:
					break;

				case FSE_TYPE_LEAFDIR:
					fileset_move_entry(
					    &fileset->fs_free_leaf_dirs,
					    &fileset->fs_exist_leaf_dirs,
					    entry);
					break;
				}

			} else if (!(entry->fse_flags & FSE_EXISTS)) {

				/* asked to set, and it was clear */
				entry->fse_flags |= FSE_EXISTS;
				switch (entry->fse_flags & FSE_TYPE_MASK) {
				case FSE_TYPE_FILE:
					fileset_move_entry(
					    &fileset->fs_noex_files,
					    &fileset->fs_exist_files, entry);
					break;
				case FSE_TYPE_DIR:
					break;
				case FSE_TYPE_LEAFDIR:
					fileset_move_entry(
					    &fileset->fs_noex_leaf_dirs,
					    &fileset->fs_exist_leaf_dirs,
					    entry);
					break;
				}
			}
		} else {
			if (entry->fse_flags & FSE_FREE) {
				/* asked to clear, and it was free */
				entry->fse_flags &= (~(FSE_FREE | FSE_EXISTS));
				switch (entry->fse_flags & FSE_TYPE_MASK) {
				case FSE_TYPE_FILE:
					fileset_move_entry(
					    &fileset->fs_free_files,
					    &fileset->fs_noex_files, entry);
					break;

				case FSE_TYPE_DIR:
					break;

				case FSE_TYPE_LEAFDIR:
					fileset_move_entry(
					    &fileset->fs_free_leaf_dirs,
					    &fileset->fs_noex_leaf_dirs,
					    entry);
					break;
				}
			} else if (entry->fse_flags & FSE_EXISTS) {

				/* asked to clear, and it was set */
				entry->fse_flags &= (~FSE_EXISTS);
				switch (entry->fse_flags & FSE_TYPE_MASK) {
				case FSE_TYPE_FILE:
					fileset_move_entry(
					    &fileset->fs_exist_files,
					    &fileset->fs_noex_files, entry);
					break;
				case FSE_TYPE_DIR:
					break;
				case FSE_TYPE_LEAFDIR:
					fileset_move_entry(
					    &fileset->fs_exist_leaf_dirs,
					    &fileset->fs_noex_leaf_dirs,
					    entry);
					break;
				}
			}
		}
	}

	/* update open count */
	entry->fse_open_cnt += open_cnt_incr;

	/* increment idle count, clear FSE_BUSY and signal IF it was busy */
	if (entry->fse_flags & FSE_BUSY) {

		/* unbusy it */
		entry->fse_flags &= (~FSE_BUSY);

		/* release any threads waiting for unbusy */
		if (entry->fse_flags & FSE_THRD_WAITNG) {
			entry->fse_flags &= (~FSE_THRD_WAITNG);
			(void) pthread_cond_broadcast(
			    &fileset->fs_thrd_wait_cv);
		}

		/* increment idle count and signal waiting threads */
		switch (entry->fse_flags & FSE_TYPE_MASK) {
		case FSE_TYPE_FILE:
			fileset->fs_idle_files++;
			if (fileset->fs_idle_files == 1) {
				(void) pthread_cond_signal(
				    &fileset->fs_idle_files_cv);
			}
			break;

		case FSE_TYPE_DIR:
			fileset->fs_idle_dirs++;
			if (fileset->fs_idle_dirs == 1) {
				(void) pthread_cond_signal(
				    &fileset->fs_idle_dirs_cv);
			}
			break;

		case FSE_TYPE_LEAFDIR:
			fileset->fs_idle_leafdirs++;
			if (fileset->fs_idle_leafdirs == 1) {
				(void) pthread_cond_signal(
				    &fileset->fs_idle_leafdirs_cv);
			}
			break;
		}
	}

	(void) ipc_mutex_unlock(&fileset->fs_pick_lock);
}

/*
 * Given a fileset "fileset", create the associated files as
 * specified in the attributes of the fileset. The fileset is
 * rooted in a directory whose pathname is in fileset_path. If the
 * directory exists, meaning that there is already a fileset,
 * and the fileset_reuse attribute is false, then remove it and all
 * its contained files and subdirectories. Next, the routine
 * creates a root directory for the fileset. All the file type
 * filesetentries are cycled through creating as needed
 * their containing subdirectory trees in the filesystem and
 * creating actual files for fileset_preallocpercent of them. The
 * created files are filled with fse_size bytes of unitialized
 * data. The routine returns FILEBENCH_ERROR on errors,
 * FILEBENCH_OK on success.
 */
static int
fileset_create(fileset_t *fileset)
{
	filesetentry_t *entry;
	char path[MAXPATHLEN];
	struct stat64 sb;
	hrtime_t start = gethrtime();
	char *fileset_path;
	char *fileset_name;
	int randno;
	int preallocated = 0;
	int reusing;

	if ((fileset_path = avd_get_str(fileset->fs_path)) == NULL) {
		filebench_log(LOG_ERROR, "%s path not set",
		    fileset_entity_name(fileset));
		return (FILEBENCH_ERROR);
	}

	if ((fileset_name = avd_get_str(fileset->fs_name)) == NULL) {
		filebench_log(LOG_ERROR, "%s name not set",
		    fileset_entity_name(fileset));
		return (FILEBENCH_ERROR);
	}

#ifdef HAVE_RAW_SUPPORT
	/* treat raw device as special case */
	if (fileset->fs_attrs & FILESET_IS_RAW_DEV)
		return (FILEBENCH_OK);
#endif /* HAVE_RAW_SUPPORT */

	/* XXX Add check to see if there is enough space */

	/* set up path to fileset */
	(void) fb_strlcpy(path, fileset_path, MAXPATHLEN);
	(void) fb_strlcat(path, "/", MAXPATHLEN);
	(void) fb_strlcat(path, fileset_name, MAXPATHLEN);

	/* if exists and resusing, then don't create new */
	if (((stat64(path, &sb) == 0)&& (strlen(path) > 3) &&
	    (strlen(avd_get_str(fileset->fs_path)) > 2)) &&
	    avd_get_bool(fileset->fs_reuse)) {
		reusing = 1;
	} else {
		reusing = 0;
	}

	if (!reusing) {
		char cmd[MAXPATHLEN];

		/* Remove existing */
		(void) snprintf(cmd, sizeof (cmd), "rm -rf %s", path);
		(void) system(cmd);
		filebench_log(LOG_VERBOSE,
		    "Removed any existing %s %s in %llu seconds",
		    fileset_entity_name(fileset), fileset_name,
		    (u_longlong_t)(((gethrtime() - start) /
		    1000000000) + 1));
	} else {
		/* we are re-using */
		filebench_log(LOG_VERBOSE, "Re-using %s %s.",
		    fileset_entity_name(fileset), fileset_name);
	}

	/* make the filesets directory tree unless in reuse mode */
	if (!reusing && (avd_get_bool(fileset->fs_prealloc))) {
		filebench_log(LOG_VERBOSE,
		    "making tree for filset %s", path);

		(void) mkdir(path, 0755);

		if (fileset_create_subdirs(fileset, path) == FILEBENCH_ERROR)
			return (FILEBENCH_ERROR);
	}

	start = gethrtime();

	filebench_log(LOG_VERBOSE, "Creating %s %s...",
	    fileset_entity_name(fileset), fileset_name);

	randno = ((RAND_MAX * (100
	    - avd_get_int(fileset->fs_preallocpercent))) / 100);

	/* alloc any files, as required */
	fileset_pickreset(fileset, FILESET_PICKFILE);
	while (entry = fileset_pick(fileset,
	    FILESET_PICKFREE | FILESET_PICKFILE, 0, 0)) {
		pthread_t tid;
		int newrand;

		newrand = rand();

		if (newrand < randno) {
			/* unbusy the unallocated entry */
			fileset_unbusy(entry, TRUE, FALSE, 0);
			continue;
		}

		preallocated++;

		if (reusing)
			entry->fse_flags |= FSE_REUSING;
		else
			entry->fse_flags &= (~FSE_REUSING);

		/* fire off allocation threads for each file if paralloc set */
		if (avd_get_bool(fileset->fs_paralloc)) {

			/* limit total number of simultaneous allocations */
			(void) pthread_mutex_lock(
			    &filebench_shm->shm_fsparalloc_lock);
			while (filebench_shm->shm_fsparalloc_count
			    >= MAX_PARALLOC_THREADS) {
				(void) pthread_cond_wait(
				    &filebench_shm->shm_fsparalloc_cv,
				    &filebench_shm->shm_fsparalloc_lock);
			}

			/* quit if any allocation thread reports and error */
			if (filebench_shm->shm_fsparalloc_count < 0) {
				(void) pthread_mutex_unlock(
				    &filebench_shm->shm_fsparalloc_lock);
				return (FILEBENCH_ERROR);
			}

			filebench_shm->shm_fsparalloc_count++;
			(void) pthread_mutex_unlock(
			    &filebench_shm->shm_fsparalloc_lock);

			/*
			 * Fire off a detached allocation thread per file.
			 * The thread will self destruct when it finishes
			 * writing pre-allocation data to the file.
			 */
			if (pthread_create(&tid, NULL,
			    (void *(*)(void*))fileset_alloc_thread,
			    entry) == 0) {
				/*
				 * A thread was created; detach it so it can
				 * fully quit when finished.
				 */
				(void) pthread_detach(tid);
			} else {
				filebench_log(LOG_ERROR,
				    "File prealloc thread create failed");
				filebench_shutdown(1);
			}

		} else {
			if (fileset_alloc_file(entry) == FILEBENCH_ERROR)
				return (FILEBENCH_ERROR);
		}
	}

	/* alloc any leaf directories, as required */
	fileset_pickreset(fileset, FILESET_PICKLEAFDIR);
	while (entry = fileset_pick(fileset,
	    FILESET_PICKFREE | FILESET_PICKLEAFDIR, 0, 0)) {

		if (rand() < randno) {
			/* unbusy the unallocated entry */
			fileset_unbusy(entry, TRUE, FALSE, 0);
			continue;
		}

		preallocated++;

		if (reusing)
			entry->fse_flags |= FSE_REUSING;
		else
			entry->fse_flags &= (~FSE_REUSING);

		if (fileset_alloc_leafdir(entry) == FILEBENCH_ERROR)
			return (FILEBENCH_ERROR);
	}

exit:
	filebench_log(LOG_VERBOSE,
	    "Preallocated %d of %llu of %s %s in %llu seconds",
	    preallocated,
	    (u_longlong_t)fileset->fs_constentries,
	    fileset_entity_name(fileset), fileset_name,
	    (u_longlong_t)(((gethrtime() - start) / 1000000000) + 1));

	return (FILEBENCH_OK);
}

/*
 * Adds an entry to the fileset's file list. Single threaded so
 * no locking needed.
 */
static void
fileset_insfilelist(fileset_t *fileset, filesetentry_t *entry)
{
	entry->fse_flags = FSE_TYPE_FILE | FSE_FREE;
	avl_add(&fileset->fs_free_files, entry);

	if (fileset->fs_filelist == NULL) {
		fileset->fs_filelist = entry;
		entry->fse_nextoftype = NULL;
	} else {
		entry->fse_nextoftype = fileset->fs_filelist;
		fileset->fs_filelist = entry;
	}
}

/*
 * Adds an entry to the fileset's directory list. Single
 * threaded so no locking needed.
 */
static void
fileset_insdirlist(fileset_t *fileset, filesetentry_t *entry)
{
	entry->fse_flags = FSE_TYPE_DIR | FSE_EXISTS;
	avl_add(&fileset->fs_dirs, entry);

	if (fileset->fs_dirlist == NULL) {
		fileset->fs_dirlist = entry;
		entry->fse_nextoftype = NULL;
	} else {
		entry->fse_nextoftype = fileset->fs_dirlist;
		fileset->fs_dirlist = entry;
	}
}

/*
 * Adds an entry to the fileset's leaf directory list. Single
 * threaded so no locking needed.
 */
static void
fileset_insleafdirlist(fileset_t *fileset, filesetentry_t *entry)
{
	entry->fse_flags = FSE_TYPE_LEAFDIR | FSE_FREE;
	avl_add(&fileset->fs_free_leaf_dirs, entry);

	if (fileset->fs_leafdirlist == NULL) {
		fileset->fs_leafdirlist = entry;
		entry->fse_nextoftype = NULL;
	} else {
		entry->fse_nextoftype = fileset->fs_leafdirlist;
		fileset->fs_leafdirlist = entry;
	}
}

/*
 * Compares two fileset entries to determine their relative order
 */
static int
fileset_entry_compare(const void *node_1, const void *node_2)
{
	if (((filesetentry_t *)node_1)->fse_index <
	    ((filesetentry_t *)node_2)->fse_index)
		return (-1);

	if (((filesetentry_t *)node_1)->fse_index ==
	    ((filesetentry_t *)node_2)->fse_index)
		return (0);

	return (1);
}

/*
 * Obtains a filesetentry entity for a file to be placed in a
 * (sub)directory of a fileset. The size of the file may be
 * specified by fileset_meansize, or calculated from a gamma
 * distribution of parameter fileset_sizegamma and of mean size
 * fileset_meansize. The filesetentry entity is placed on the file
 * list in the specified parent filesetentry entity, which may
 * be a directory filesetentry, or the root filesetentry in the
 * fileset. It is also placed on the fileset's list of all
 * contained files. Returns FILEBENCH_OK if successful or FILEBENCH_ERROR
 * if ipc memory for the path string cannot be allocated.
 */
static int
fileset_populate_file(fileset_t *fileset, filesetentry_t *parent, int serial)
{
	char tmpname[16];
	filesetentry_t *entry;
	double drand;
	uint_t index;

	if ((entry = (filesetentry_t *)ipc_malloc(FILEBENCH_FILESETENTRY))
	    == NULL) {
		filebench_log(LOG_ERROR,
		    "fileset_populate_file: Can't malloc filesetentry");
		return (FILEBENCH_ERROR);
	}

	/* Another currently idle file */
	(void) ipc_mutex_lock(&fileset->fs_pick_lock);
	index = fileset->fs_idle_files++;
	(void) ipc_mutex_unlock(&fileset->fs_pick_lock);

	entry->fse_index = index;
	entry->fse_parent = parent;
	entry->fse_fileset = fileset;
	fileset_insfilelist(fileset, entry);

	(void) snprintf(tmpname, sizeof (tmpname), "%08d", serial);
	if ((entry->fse_path = (char *)ipc_pathalloc(tmpname)) == NULL) {
		filebench_log(LOG_ERROR,
		    "fileset_populate_file: Can't alloc path string");
		return (FILEBENCH_ERROR);
	}

	/* see if random variable was supplied for file size */
	if (fileset->fs_meansize == -1) {
		entry->fse_size = (off64_t)avd_get_int(fileset->fs_size);
	} else {
		double gamma;

		gamma = avd_get_int(fileset->fs_sizegamma) / 1000.0;
		if (gamma > 0) {
			drand = gamma_dist_knuth(gamma,
			    fileset->fs_meansize / gamma);
			entry->fse_size = (off64_t)drand;
		} else {
			entry->fse_size = (off64_t)fileset->fs_meansize;
		}
	}

	fileset->fs_bytes += entry->fse_size;

	fileset->fs_realfiles++;
	return (FILEBENCH_OK);
}

/*
 * Obtaines a filesetentry entity for a leaf directory to be placed in a
 * (sub)directory of a fileset. The leaf directory will always be empty so
 * it can be created and deleted (mkdir, rmdir) at will. The filesetentry
 * entity is placed on the leaf directory list in the specified parent
 * filesetentry entity, which may be a (sub) directory filesetentry, or
 * the root filesetentry in the fileset. It is also placed on the fileset's
 * list of all contained leaf directories. Returns FILEBENCH_OK if successful
 * or FILEBENCH_ERROR if ipc memory cannot be allocated.
 */
static int
fileset_populate_leafdir(fileset_t *fileset, filesetentry_t *parent, int serial)
{
	char tmpname[16];
	filesetentry_t *entry;
	uint_t index;

	if ((entry = (filesetentry_t *)ipc_malloc(FILEBENCH_FILESETENTRY))
	    == NULL) {
		filebench_log(LOG_ERROR,
		    "fileset_populate_file: Can't malloc filesetentry");
		return (FILEBENCH_ERROR);
	}

	/* Another currently idle leaf directory */
	(void) ipc_mutex_lock(&fileset->fs_pick_lock);
	index = fileset->fs_idle_leafdirs++;
	(void) ipc_mutex_unlock(&fileset->fs_pick_lock);

	entry->fse_index = index;
	entry->fse_parent = parent;
	entry->fse_fileset = fileset;
	fileset_insleafdirlist(fileset, entry);

	(void) snprintf(tmpname, sizeof (tmpname), "%08d", serial);
	if ((entry->fse_path = (char *)ipc_pathalloc(tmpname)) == NULL) {
		filebench_log(LOG_ERROR,
		    "fileset_populate_file: Can't alloc path string");
		return (FILEBENCH_ERROR);
	}

	fileset->fs_realleafdirs++;
	return (FILEBENCH_OK);
}

/*
 * Creates a directory node in a fileset, by obtaining a
 * filesetentry entity for the node and initializing it
 * according to parameters of the fileset. It determines a
 * directory tree depth and directory width, optionally using
 * a gamma distribution. If its calculated depth is less then
 * its actual depth in the directory tree, it becomes a leaf
 * node and files itself with "width" number of file type
 * filesetentries, otherwise it files itself with "width"
 * number of directory type filesetentries, using recursive
 * calls to fileset_populate_subdir. The end result of the
 * initial call to this routine is a tree of directories of
 * random width and varying depth with sufficient leaf
 * directories to contain all required files.
 * Returns FILEBENCH_OK on success. Returns FILEBENCH_ERROR if ipc path
 * string memory cannot be allocated and returns the error code (currently
 * also FILEBENCH_ERROR) from calls to fileset_populate_file or recursive
 * calls to fileset_populate_subdir.
 */
static int
fileset_populate_subdir(fileset_t *fileset, filesetentry_t *parent,
    int serial, double depth)
{
	double randepth, drand, ranwidth;
	int isleaf = 0;
	char tmpname[16];
	filesetentry_t *entry;
	int i;
	uint_t index;

	depth += 1;

	/* Create dir node */
	if ((entry = (filesetentry_t *)ipc_malloc(FILEBENCH_FILESETENTRY))
	    == NULL) {
		filebench_log(LOG_ERROR,
		    "fileset_populate_subdir: Can't malloc filesetentry");
		return (FILEBENCH_ERROR);
	}

	/* another idle directory */
	(void) ipc_mutex_lock(&fileset->fs_pick_lock);
	index = fileset->fs_idle_dirs++;
	(void) ipc_mutex_unlock(&fileset->fs_pick_lock);

	(void) snprintf(tmpname, sizeof (tmpname), "%08d", serial);
	if ((entry->fse_path = (char *)ipc_pathalloc(tmpname)) == NULL) {
		filebench_log(LOG_ERROR,
		    "fileset_populate_subdir: Can't alloc path string");
		return (FILEBENCH_ERROR);
	}

	entry->fse_index = index;
	entry->fse_parent = parent;
	entry->fse_fileset = fileset;
	fileset_insdirlist(fileset, entry);

	if (fileset->fs_dirdepthrv) {
		randepth = (int)avd_get_int(fileset->fs_dirdepthrv);
	} else {
		double gamma;

		gamma = avd_get_int(fileset->fs_dirgamma) / 1000.0;
		if (gamma > 0) {
			drand = gamma_dist_knuth(gamma,
			    fileset->fs_meandepth / gamma);
			randepth = (int)drand;
		} else {
			randepth = (int)fileset->fs_meandepth;
		}
	}

	if (fileset->fs_meanwidth == -1) {
		ranwidth = avd_get_dbl(fileset->fs_dirwidth);
	} else {
		double gamma;

		gamma = avd_get_int(fileset->fs_sizegamma) / 1000.0;
		if (gamma > 0) {
			drand = gamma_dist_knuth(gamma,
			    fileset->fs_meanwidth / gamma);
			ranwidth = drand;
		} else {
			ranwidth = fileset->fs_meanwidth;
		}
	}

	if (randepth == 0)
		randepth = 1;
	if (ranwidth == 0)
		ranwidth = 1;
	if (depth >= randepth)
		isleaf = 1;

	/*
	 * Create directory of random width filled with files according
	 * to distribution, or if root directory, continue until #files required
	 */
	for (i = 1; ((parent == NULL) || (i < ranwidth + 1)) &&
	    (fileset->fs_realfiles < fileset->fs_constentries);
	    i++) {
		int ret = 0;

		if (parent && isleaf)
			ret = fileset_populate_file(fileset, entry, i);
		else
			ret = fileset_populate_subdir(fileset, entry, i, depth);

		if (ret != 0)
			return (ret);
	}

	/*
	 * Create directory of random width filled with leaf directories
	 * according to distribution, or if root directory, continue until
	 * the number of leaf directories required has been generated.
	 */
	for (i = 1; ((parent == NULL) || (i < ranwidth + 1)) &&
	    (fileset->fs_realleafdirs < fileset->fs_constleafdirs);
	    i++) {
		int ret = 0;

		if (parent && isleaf)
			ret = fileset_populate_leafdir(fileset, entry, i);
		else
			ret = fileset_populate_subdir(fileset, entry, i, depth);

		if (ret != 0)
			return (ret);
	}

	return (FILEBENCH_OK);
}

/*
 * Populates a fileset with files and subdirectory entries. Uses
 * the supplied fileset_dirwidth and fileset_entries (number of files) to
 * calculate the required fileset_meandepth (of subdirectories) and
 * initialize the fileset_meanwidth and fileset_meansize variables. Then
 * calls fileset_populate_subdir() to do the recursive
 * subdirectory entry creation and leaf file entry creation. All
 * of the above is skipped if the fileset has already been
 * populated. Returns 0 on success, or an error code from the
 * call to fileset_populate_subdir if that call fails.
 */
static int
fileset_populate(fileset_t *fileset)
{
	fbint_t entries = avd_get_int(fileset->fs_entries);
	fbint_t leafdirs = avd_get_int(fileset->fs_leafdirs);
	int meandirwidth;
	int ret;

	/* Skip if already populated */
	if (fileset->fs_bytes > 0)
		goto exists;

#ifdef HAVE_RAW_SUPPORT
	/* check for raw device */
	if (fileset->fs_attrs & FILESET_IS_RAW_DEV)
		return (FILEBENCH_OK);
#endif /* HAVE_RAW_SUPPORT */

	/*
	 * save value of entries and leaf dirs obtained for later
	 * in case it was random
	 */
	fileset->fs_constentries = entries;
	fileset->fs_constleafdirs = leafdirs;

	/* initialize idle files and directories condition variables */
	(void) pthread_cond_init(&fileset->fs_idle_files_cv, ipc_condattr());
	(void) pthread_cond_init(&fileset->fs_idle_dirs_cv, ipc_condattr());
	(void) pthread_cond_init(&fileset->fs_idle_leafdirs_cv, ipc_condattr());

	/* no files or dirs idle (or busy) yet */
	fileset->fs_idle_files = 0;
	fileset->fs_idle_dirs = 0;
	fileset->fs_idle_leafdirs = 0;

	/* initialize locks and other condition variables */
	(void) pthread_mutex_init(&fileset->fs_pick_lock,
	    ipc_mutexattr(IPC_MUTEX_NORMAL));
	(void) pthread_mutex_init(&fileset->fs_histo_lock,
	    ipc_mutexattr(IPC_MUTEX_NORMAL));
	(void) pthread_cond_init(&fileset->fs_thrd_wait_cv, ipc_condattr());

	/* Initialize avl btrees */
	avl_create(&(fileset->fs_free_files), fileset_entry_compare,
	    sizeof (filesetentry_t), FSE_OFFSETOF(fse_link));
	avl_create(&(fileset->fs_noex_files), fileset_entry_compare,
	    sizeof (filesetentry_t), FSE_OFFSETOF(fse_link));
	avl_create(&(fileset->fs_exist_files), fileset_entry_compare,
	    sizeof (filesetentry_t), FSE_OFFSETOF(fse_link));
	avl_create(&(fileset->fs_free_leaf_dirs), fileset_entry_compare,
	    sizeof (filesetentry_t), FSE_OFFSETOF(fse_link));
	avl_create(&(fileset->fs_noex_leaf_dirs), fileset_entry_compare,
	    sizeof (filesetentry_t), FSE_OFFSETOF(fse_link));
	avl_create(&(fileset->fs_exist_leaf_dirs), fileset_entry_compare,
	    sizeof (filesetentry_t), FSE_OFFSETOF(fse_link));
	avl_create(&(fileset->fs_dirs), fileset_entry_compare,
	    sizeof (filesetentry_t), FSE_OFFSETOF(fse_link));

	/* is dirwidth a random variable? */
	if (AVD_IS_RANDOM(fileset->fs_dirwidth)) {
		meandirwidth =
		    (int)fileset->fs_dirwidth->avd_val.randptr->rnd_dbl_mean;
		fileset->fs_meanwidth = -1;
	} else {
		meandirwidth = (int)avd_get_int(fileset->fs_dirwidth);
		fileset->fs_meanwidth = (double)meandirwidth;
	}

	/*
	 * Input params are:
	 *	# of files
	 *	ave # of files per dir
	 *	max size of dir
	 *	# ave size of file
	 *	max size of file
	 */
	fileset->fs_meandepth = log(entries+leafdirs) / log(meandirwidth);

	/* Has a random variable been supplied for dirdepth? */
	if (fileset->fs_dirdepthrv) {
		/* yes, so set the random variable's mean value to meandepth */
		fileset->fs_dirdepthrv->avd_val.randptr->rnd_dbl_mean =
		    fileset->fs_meandepth;
	}

	/* test for random size variable */
	if (AVD_IS_RANDOM(fileset->fs_size))
		fileset->fs_meansize = -1;
	else
		fileset->fs_meansize = avd_get_int(fileset->fs_size);

	if ((ret = fileset_populate_subdir(fileset, NULL, 1, 0)) != 0)
		return (ret);


exists:
	if (fileset->fs_attrs & FILESET_IS_FILE) {
		filebench_log(LOG_VERBOSE, "File %s: mbytes=%llu",
		    avd_get_str(fileset->fs_name),
		    (u_longlong_t)(fileset->fs_bytes / 1024UL / 1024UL));
	} else {
		filebench_log(LOG_VERBOSE, "Fileset %s: %d files, %d leafdirs "
		    "avg dir = %d, avg depth = %.1lf, mbytes=%llu",
		    avd_get_str(fileset->fs_name), entries, leafdirs,
		    meandirwidth,
		    fileset->fs_meandepth,
		    (u_longlong_t)(fileset->fs_bytes / 1024UL / 1024UL));
	}

	return (FILEBENCH_OK);
}

/*
 * Allocates a fileset instance, initializes fileset_dirgamma and
 * fileset_sizegamma default values, and sets the fileset name to the
 * supplied name string. Puts the allocated fileset on the
 * master fileset list and returns a pointer to it.
 *
 * This routine implements the 'define fileset' calls found in a .f
 * workload, such as in the following example:
 * define fileset name=drew4ever, entries=$nfiles
 */
fileset_t *
fileset_define(avd_t name)
{
	fileset_t *fileset;

	if (name == NULL)
		return (NULL);

	if ((fileset = (fileset_t *)ipc_malloc(FILEBENCH_FILESET)) == NULL) {
		filebench_log(LOG_ERROR,
		    "fileset_define: Can't malloc fileset");
		return (NULL);
	}

	filebench_log(LOG_DEBUG_IMPL,
	    "Defining file %s", avd_get_str(name));

	(void) ipc_mutex_lock(&filebench_shm->shm_fileset_lock);

	fileset->fs_dirgamma = avd_int_alloc(1500);
	fileset->fs_sizegamma = avd_int_alloc(1500);
	fileset->fs_histo_id = -1;

	/* Add fileset to global list */
	if (filebench_shm->shm_filesetlist == NULL) {
		filebench_shm->shm_filesetlist = fileset;
		fileset->fs_next = NULL;
	} else {
		fileset->fs_next = filebench_shm->shm_filesetlist;
		filebench_shm->shm_filesetlist = fileset;
	}

	(void) ipc_mutex_unlock(&filebench_shm->shm_fileset_lock);

	fileset->fs_name = name;

	return (fileset);
}

/*
 * If supplied with a pointer to a fileset and the fileset's
 * fileset_prealloc flag is set, calls fileset_populate() to populate
 * the fileset with filesetentries, then calls fileset_create()
 * to make actual directories and files for the filesetentries.
 * Otherwise, it applies fileset_populate() and fileset_create()
 * to all the filesets on the master fileset list. It always
 * returns zero (0) if one fileset is populated / created,
 * otherwise it returns the sum of returned values from
 * fileset_create() and fileset_populate(), which
 * will be a negative one (-1) times the number of
 * fileset_create() calls which failed.
 */
int
fileset_createset(fileset_t *fileset)
{
	fileset_t *list;
	int ret = 0;

	/* set up for possible parallel allocate */
	filebench_shm->shm_fsparalloc_count = 0;
	(void) pthread_cond_init(
	    &filebench_shm->shm_fsparalloc_cv,
	    ipc_condattr());

	if (fileset && avd_get_bool(fileset->fs_prealloc)) {

		/* check for raw files */
		if (fileset_checkraw(fileset)) {
			filebench_log(LOG_INFO,
			    "file %s/%s is a RAW device",
			    avd_get_str(fileset->fs_path),
			    avd_get_str(fileset->fs_name));
			return (FILEBENCH_OK);
		}

		filebench_log(LOG_INFO,
		    "creating/pre-allocating %s %s",
		    fileset_entity_name(fileset),
		    avd_get_str(fileset->fs_name));

		if ((ret = fileset_populate(fileset)) != FILEBENCH_OK)
			return (ret);

		if ((ret = fileset_create(fileset)) != FILEBENCH_OK)
			return (ret);
	} else {

		filebench_log(LOG_INFO,
		    "Creating/pre-allocating files and filesets");

		list = filebench_shm->shm_filesetlist;
		while (list) {
			/* check for raw files */
			if (fileset_checkraw(list)) {
				filebench_log(LOG_INFO,
				    "file %s/%s is a RAW device",
				    avd_get_str(list->fs_path),
				    avd_get_str(list->fs_name));
				list = list->fs_next;
				continue;
			}

			if ((ret = fileset_populate(list)) != FILEBENCH_OK)
				return (ret);

			if ((ret = fileset_create(list)) != FILEBENCH_OK)
				return (ret);

			list = list->fs_next;
		}
	}

	/* wait for allocation threads to finish */
	filebench_log(LOG_INFO,
	    "waiting for fileset pre-allocation to finish");

	(void) pthread_mutex_lock(&filebench_shm->shm_fsparalloc_lock);
	while (filebench_shm->shm_fsparalloc_count > 0)
		(void) pthread_cond_wait(
		    &filebench_shm->shm_fsparalloc_cv,
		    &filebench_shm->shm_fsparalloc_lock);
	(void) pthread_mutex_unlock(&filebench_shm->shm_fsparalloc_lock);

	if (filebench_shm->shm_fsparalloc_count < 0)
		return (FILEBENCH_ERROR);

	return (FILEBENCH_OK);
}

/*
 * Searches through the master fileset list for the named fileset.
 * If found, returns pointer to same, otherwise returns NULL.
 */
fileset_t *
fileset_find(char *name)
{
	fileset_t *fileset = filebench_shm->shm_filesetlist;

	(void) ipc_mutex_lock(&filebench_shm->shm_fileset_lock);

	while (fileset) {
		if (strcmp(name, avd_get_str(fileset->fs_name)) == 0) {
			(void) ipc_mutex_unlock(
			    &filebench_shm->shm_fileset_lock);
			return (fileset);
		}
		fileset = fileset->fs_next;
	}
	(void) ipc_mutex_unlock(&filebench_shm->shm_fileset_lock);

	return (NULL);
}

/*
 * Iterates over all the file sets in the filesetlist,
 * executing the supplied command "*cmd()" on them. Also
 * indicates to the executed command if it is the first
 * time the command has been executed since the current
 * call to fileset_iter.
 */
int
fileset_iter(int (*cmd)(fileset_t *fileset, int first))
{
	fileset_t *fileset = filebench_shm->shm_filesetlist;
	int count = 0;

	(void) ipc_mutex_lock(&filebench_shm->shm_fileset_lock);

	while (fileset) {
		if (cmd(fileset, count == 0) == FILEBENCH_ERROR) {
			(void) ipc_mutex_unlock(
			    &filebench_shm->shm_fileset_lock);
			return (FILEBENCH_ERROR);
		}
		fileset = fileset->fs_next;
		count++;
	}

	(void) ipc_mutex_unlock(&filebench_shm->shm_fileset_lock);
	return (FILEBENCH_OK);
}

/*
 * Prints information to the filebench log about the file
 * object. Also prints a header on the first call.
 */
int
fileset_print(fileset_t *fileset, int first)
{
	int pathlength;
	char *fileset_path;
	char *fileset_name;
	static char pad[] = "                              "; /* 30 spaces */

	if ((fileset_path = avd_get_str(fileset->fs_path)) == NULL) {
		filebench_log(LOG_ERROR, "%s path not set",
		    fileset_entity_name(fileset));
		return (FILEBENCH_ERROR);
	}

	if ((fileset_name = avd_get_str(fileset->fs_name)) == NULL) {
		filebench_log(LOG_ERROR, "%s name not set",
		    fileset_entity_name(fileset));
		return (FILEBENCH_ERROR);
	}

	pathlength = strlen(fileset_path) + strlen(fileset_name);

	if (pathlength > 29)
		pathlength = 29;

	if (first) {
		filebench_log(LOG_INFO, "File or Fileset name%20s%12s%10s",
		    "file size",
		    "dir width",
		    "entries");
	}

	if (fileset->fs_attrs & FILESET_IS_FILE) {
		if (fileset->fs_attrs & FILESET_IS_RAW_DEV) {
			filebench_log(LOG_INFO,
			    "%s/%s%s         (Raw Device)",
			    fileset_path, fileset_name, &pad[pathlength]);
		} else {
			filebench_log(LOG_INFO,
			    "%s/%s%s%9llu     (Single File)",
			    fileset_path, fileset_name, &pad[pathlength],
			    (u_longlong_t)avd_get_int(fileset->fs_size));
		}
	} else {
		filebench_log(LOG_INFO, "%s/%s%s%9llu%12llu%10llu",
		    fileset_path, fileset_name,
		    &pad[pathlength],
		    (u_longlong_t)avd_get_int(fileset->fs_size),
		    (u_longlong_t)avd_get_int(fileset->fs_dirwidth),
		    (u_longlong_t)fileset->fs_constentries);
	}
	return (FILEBENCH_OK);
}

/*
 * checks to see if the path/name pair points to a raw device. If
 * so it sets the raw device flag (FILESET_IS_RAW_DEV) and returns 1.
 * If RAW is not defined, or it is not a raw device, it clears the
 * raw device flag and returns 0.
 */
int
fileset_checkraw(fileset_t *fileset)
{
	char path[MAXPATHLEN];
	struct stat64 sb;
	char *pathname;
	char *setname;

	fileset->fs_attrs &= (~FILESET_IS_RAW_DEV);

#ifdef HAVE_RAW_SUPPORT
	/* check for raw device */
	if ((pathname = avd_get_str(fileset->fs_path)) == NULL)
		return (FILEBENCH_OK);

	if ((setname = avd_get_str(fileset->fs_name)) == NULL)
		return (FILEBENCH_OK);

	(void) fb_strlcpy(path, pathname, MAXPATHLEN);
	(void) fb_strlcat(path, "/", MAXPATHLEN);
	(void) fb_strlcat(path, setname, MAXPATHLEN);
	if ((stat64(path, &sb) == 0) &&
	    ((sb.st_mode & S_IFMT) == S_IFBLK) && sb.st_rdev) {
		fileset->fs_attrs |= FILESET_IS_RAW_DEV;
		if (!(fileset->fs_attrs & FILESET_IS_FILE)) {
			filebench_log(LOG_ERROR,
			    "WARNING Fileset %s/%s Cannot be RAW device",
			    avd_get_str(fileset->fs_path),
			    avd_get_str(fileset->fs_name));
			filebench_shutdown(1);
		}

		return (1);
	}
#endif /* HAVE_RAW_SUPPORT */

	return (FILEBENCH_OK);
}
