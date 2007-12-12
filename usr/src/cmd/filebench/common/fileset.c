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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <math.h>
#include <libgen.h>
#include <sys/mman.h>
#include "fileset.h"
#include "filebench.h"
#include "gamma_dist.h"

/*
 * File sets, of type fileset_t, are entities which contain
 * information about collections of files and subdirectories in Filebench.
 * The fileset, once populated, consists of a tree of fileset entries of
 * type filesetentry_t which specify files and directories.  The fileset
 * is rooted in a directory specified by fs_path, and once the populated
 * fileset has been created, has a tree of directories and files
 * corresponding to the fileset's filesetentry tree.
 */

/* parallel allocation control */
#define	MAX_PARALLOC_THREADS 32
static pthread_mutex_t	paralloc_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	paralloc_cv = PTHREAD_COND_INITIALIZER;
static int		paralloc_count;

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
	    "		        [,dirwidth=[width]]\n");
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

	*path = 0;
	while (fsep->fse_parent) {
		(void) strcpy(pathtmp, "/");
		(void) strcat(pathtmp, fsep->fse_path);
		(void) strcat(pathtmp, path);
		(void) strcpy(path, pathtmp);
		fsep = fsep->fse_parent;
	}

	s = malloc(strlen(path) + 1);
	(void) strcpy(s, path);
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
	return (0);

null_str:
	/* clean up */
	for (--i; i >= 0; i--)
		free(dirs[i]);

	filebench_log(LOG_ERROR,
	    "Failed to create directory path %s: Out of memory", path);

	return (-1);
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
		(void) strcpy(full_path, filesetpath);
		part_path = fileset_resolvepath(direntry);
		(void) strcat(full_path, part_path);
		free(part_path);

		/* now create this portion of the subdirectory tree */
		if (fileset_mkdir(full_path, 0755) == -1)
			return (-1);

		direntry = direntry->fse_dirnext;
	}
	return (0);
}

/*
 * given a fileset entry, determines if the associated file
 * needs to be allocated or not, and if so does the allocation.
 */
static int
fileset_alloc_file(filesetentry_t *entry)
{
	char path[MAXPATHLEN];
	char *buf;
	struct stat64 sb;
	char *pathtmp;
	off64_t seek;
	int fd;

	*path = 0;
	(void) strcpy(path, *entry->fse_fileset->fs_path);
	(void) strcat(path, "/");
	(void) strcat(path, entry->fse_fileset->fs_name);
	pathtmp = fileset_resolvepath(entry);
	(void) strcat(path, pathtmp);

	filebench_log(LOG_DEBUG_IMPL, "Populated %s", entry->fse_path);

	/* see if reusing and this file exists */
	if ((entry->fse_flags & FSE_REUSING) && (stat64(path, &sb) == 0)) {
		if ((fd = open64(path, O_RDWR)) < 0) {
			filebench_log(LOG_INFO,
			    "Attempted but failed to Re-use file %s",
			    path);
			return (-1);
		}

		if (sb.st_size == (off64_t)entry->fse_size) {
			filebench_log(LOG_INFO,
			    "Re-using file %s", path);

			if (!integer_isset(entry->fse_fileset->fs_cached))
				(void) fileset_freemem(fd,
				    entry->fse_size);

			entry->fse_flags |= FSE_EXISTS;
			(void) close(fd);
			return (0);

		} else if (sb.st_size > (off64_t)entry->fse_size) {
			/* reuse, but too large */
			filebench_log(LOG_INFO,
			    "Truncating & re-using file %s", path);

			(void) ftruncate64(fd,
			    (off64_t)entry->fse_size);

			if (!integer_isset(entry->fse_fileset->fs_cached))
				(void) fileset_freemem(fd,
				    entry->fse_size);

			entry->fse_flags |= FSE_EXISTS;
			(void) close(fd);
			return (0);
		}
	} else {

		/* No file or not reusing, so create */
		if ((fd = open64(path, O_RDWR | O_CREAT, 0644)) < 0) {
			filebench_log(LOG_ERROR,
			    "Failed to pre-allocate file %s: %s",
			    path, strerror(errno));

			return (-1);
		}
	}

	if ((buf = (char *)malloc(FILE_ALLOC_BLOCK)) == NULL)
		return (-1);

	entry->fse_flags |= FSE_EXISTS;

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
			return (-1);
		}
		seek += wsize;
	}

	if (!integer_isset(entry->fse_fileset->fs_cached))
		(void) fileset_freemem(fd, entry->fse_size);

	(void) close(fd);

	free(buf);

	filebench_log(LOG_DEBUG_IMPL,
	    "Pre-allocated file %s size %lld", path, entry->fse_size);

	return (0);
}

/*
 * given a fileset entry, determines if the associated file
 * needs to be allocated or not, and if so does the allocation.
 */
static void *
fileset_alloc_thread(filesetentry_t *entry)
{
	if (fileset_alloc_file(entry) == -1) {
		(void) pthread_mutex_lock(&paralloc_lock);
		paralloc_count = -1;
	} else {
		(void) pthread_mutex_lock(&paralloc_lock);
		paralloc_count--;
	}

	(void) pthread_cond_signal(&paralloc_cv);
	(void) pthread_mutex_unlock(&paralloc_lock);

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
    filesetentry_t *entry, int flag, int mode, int attrs)
{
	char path[MAXPATHLEN];
	char dir[MAXPATHLEN];
	char *pathtmp;
	struct stat64 sb;
	int fd;
	int open_attrs = 0;

	*path = 0;
	(void) strcpy(path, *fileset->fs_path);
	(void) strcat(path, "/");
	(void) strcat(path, fileset->fs_name);
	pathtmp = fileset_resolvepath(entry);
	(void) strcat(path, pathtmp);
	(void) strcpy(dir, path);
	free(pathtmp);
	(void) trunc_dirname(dir);

	/* If we are going to create a file, create the parent dirs */
	if ((flag & O_CREAT) && (stat64(dir, &sb) != 0)) {
		if (fileset_mkdir(dir, 0755) == -1)
			return (-1);
	}

	if (flag & O_CREAT)
		entry->fse_flags |= FSE_EXISTS;

	if (attrs & FLOW_ATTR_DSYNC) {
#ifdef sun
		open_attrs |= O_DSYNC;
#else
		open_attrs |= O_FSYNC;
#endif
	}

	if ((fd = open64(path, flag | open_attrs, mode)) < 0) {
		filebench_log(LOG_ERROR,
		    "Failed to open file %s: %s",
		    path, strerror(errno));
		(void) ipc_mutex_unlock(&entry->fse_lock);
		return (-1);
	}
	(void) ipc_mutex_unlock(&entry->fse_lock);

#ifdef sun
	if (attrs & FLOW_ATTR_DIRECTIO)
		(void) directio(fd, DIRECTIO_ON);
	else
		(void) directio(fd, DIRECTIO_OFF);
#endif

	return (fd);
}


/*
 * Selects a fileset entry from a fileset. If the
 * FILESET_PICKDIR flag is set it will pick a directory
 * entry, otherwise a file entry. The FILESET_PICKRESET
 * flag will cause it to reset the free list to the
 * overall list (file or directory). The FILESET_PICKUNIQUE
 * flag will take an entry off of one of the free (unused)
 * lists (file or directory), otherwise the entry will be
 * picked off of one of the rotor lists (file or directory).
 * The FILESET_PICKEXISTS will insure that only extant
 * (FSE_EXISTS) state files are selected, while
 * FILESET_PICKNOEXIST insures that only non extant
 * (not FSE_EXISTS) state files are selected.
 */
filesetentry_t *
fileset_pick(fileset_t *fileset, int flags, int tid)
{
	filesetentry_t *entry = NULL;
	filesetentry_t *first = NULL;

	(void) ipc_mutex_lock(&filebench_shm->fileset_lock);

	while (entry == NULL) {

		if ((flags & FILESET_PICKDIR) && (flags & FILESET_PICKRESET)) {
			entry = fileset->fs_dirlist;
			while (entry) {
				entry->fse_flags |= FSE_FREE;
				entry = entry->fse_dirnext;
			}
			fileset->fs_dirfree = fileset->fs_dirlist;
		}

		if (!(flags & FILESET_PICKDIR) && (flags & FILESET_PICKRESET)) {
			entry = fileset->fs_filelist;
			while (entry) {
				entry->fse_flags |= FSE_FREE;
				entry = entry->fse_filenext;
			}
			fileset->fs_filefree = fileset->fs_filelist;
		}

		if (flags & FILESET_PICKUNIQUE) {
			if (flags & FILESET_PICKDIR) {
				entry = fileset->fs_dirfree;
				if (entry == NULL)
					goto empty;
				fileset->fs_dirfree = entry->fse_dirnext;
			} else {
				entry = fileset->fs_filefree;
				if (entry == NULL)
					goto empty;
				fileset->fs_filefree = entry->fse_filenext;
			}
			entry->fse_flags &= ~FSE_FREE;
		} else {
			if (flags & FILESET_PICKDIR) {
				entry = fileset->fs_dirrotor;
				if (entry == NULL)
				fileset->fs_dirrotor =
				    entry = fileset->fs_dirlist;
				fileset->fs_dirrotor = entry->fse_dirnext;
			} else {
				entry = fileset->fs_filerotor[tid];
				if (entry == NULL)
					fileset->fs_filerotor[tid] =
					    entry = fileset->fs_filelist;
				fileset->fs_filerotor[tid] =
				    entry->fse_filenext;
			}
		}

		if (first == entry)
			goto empty;

		if (first == NULL)
			first = entry;

		/* Return locked entry */
		(void) ipc_mutex_lock(&entry->fse_lock);

		/* If we ask for an existing file, go round again */
		if ((flags & FILESET_PICKEXISTS) &&
		    !(entry->fse_flags & FSE_EXISTS)) {
			(void) ipc_mutex_unlock(&entry->fse_lock);
			entry = NULL;
		}

		/* If we ask for not an existing file, go round again */
		if ((flags & FILESET_PICKNOEXIST) &&
		    (entry->fse_flags & FSE_EXISTS)) {
			(void) ipc_mutex_unlock(&entry->fse_lock);
			entry = NULL;
		}
	}

	(void) ipc_mutex_unlock(&filebench_shm->fileset_lock);
	filebench_log(LOG_DEBUG_SCRIPT, "Picked file %s", entry->fse_path);
	return (entry);

empty:
	(void) ipc_mutex_unlock(&filebench_shm->fileset_lock);
	return (NULL);
}

/*
 * Given a fileset "fileset", create the associated files as
 * specified in the attributes of the fileset. The fileset is
 * rooted in a directory whose pathname is in fs_path. If the
 * directory exists, meaning that there is already a fileset,
 * and the fs_reuse attribute is false, then remove it and all
 * its contained files and subdirectories. Next, the routine
 * creates a root directory for the fileset. All the file type
 * filesetentries are cycled through creating as needed
 * their containing subdirectory trees in the filesystem and
 * creating actual files for fs_preallocpercent of them. The
 * created files are filled with fse_size bytes of unitialized
 * data. The routine returns -1 on errors, 0 on success.
 */
static int
fileset_create(fileset_t *fileset)
{
	filesetentry_t *entry;
	char path[MAXPATHLEN];
	struct stat64 sb;
	int pickflags = FILESET_PICKUNIQUE | FILESET_PICKRESET;
	hrtime_t start = gethrtime();
	int preallocated = 0;
	int reusing = 0;

	if (*fileset->fs_path == NULL) {
		filebench_log(LOG_ERROR, "%s path not set",
		    fileset_entity_name(fileset));
		return (-1);
	}

#ifdef HAVE_RAW_SUPPORT
	/* treat raw device as special case */
	if (fileset->fs_attrs & FILESET_IS_RAW_DEV)
		return (0);
#endif /* HAVE_RAW_SUPPORT */

	/* XXX Add check to see if there is enough space */

	/* Remove existing */
	(void) strcpy(path, *fileset->fs_path);
	(void) strcat(path, "/");
	(void) strcat(path, fileset->fs_name);
	if ((stat64(path, &sb) == 0) && (strlen(path) > 3) &&
	    (strlen(*fileset->fs_path) > 2)) {
		if (!integer_isset(fileset->fs_reuse)) {
			char cmd[MAXPATHLEN];

			(void) snprintf(cmd, sizeof (cmd), "rm -rf %s", path);
			(void) system(cmd);
			filebench_log(LOG_VERBOSE,
			    "Removed any existing %s %s in %lld seconds",
			    fileset_entity_name(fileset), fileset->fs_name,
			    ((gethrtime() - start) / 1000000000) + 1);
		} else {
			/* we are re-using */
			reusing = 1;
			filebench_log(LOG_VERBOSE,
			    "Re-using %s %s on %s file system.",
			    fileset_entity_name(fileset),
			    fileset->fs_name, sb.st_fstype);
		}
	}
	(void) mkdir(path, 0755);

	/* make the filesets directory tree */
	if (fileset_create_subdirs(fileset, path) == -1)
		return (-1);

	start = gethrtime();

	filebench_log(LOG_VERBOSE, "Creating %s %s...",
	    fileset_entity_name(fileset), fileset->fs_name);

	if (!integer_isset(fileset->fs_prealloc))
		goto exit;

	while (entry = fileset_pick(fileset, pickflags, 0)) {
		int randno;
		pthread_t tid;

		pickflags = FILESET_PICKUNIQUE;

		entry->fse_flags &= ~FSE_EXISTS;

		randno = ((RAND_MAX * (100 - *(fileset->fs_preallocpercent)))
		    / 100);

		/* entry doesn't need to be locked during initialization */
		(void) ipc_mutex_unlock(&entry->fse_lock);

		if (rand() < randno)
			continue;

		preallocated++;

		if (reusing)
			entry->fse_flags |= FSE_REUSING;
		else
			entry->fse_flags &= (~FSE_REUSING);

		if (integer_isset(fileset->fs_paralloc)) {

			/* fire off a separate allocation thread */
			(void) pthread_mutex_lock(&paralloc_lock);
			while (paralloc_count >= MAX_PARALLOC_THREADS) {
				(void) pthread_cond_wait(
				    &paralloc_cv, &paralloc_lock);
			}

			if (paralloc_count < 0) {
				(void) pthread_mutex_unlock(&paralloc_lock);
				return (-1);
			}

			paralloc_count++;
			(void) pthread_mutex_unlock(&paralloc_lock);

			if (pthread_create(&tid, NULL,
			    (void *(*)(void*))fileset_alloc_thread,
			    entry) != 0) {
				filebench_log(LOG_ERROR,
				    "File prealloc thread create failed");
				filebench_shutdown(1);
			}

		} else {
			if (fileset_alloc_file(entry) == -1)
				return (-1);
		}
	}

exit:
	filebench_log(LOG_VERBOSE,
	    "Preallocated %d of %lld of %s %s in %lld seconds",
	    preallocated,
	    *(fileset->fs_entries),
	    fileset_entity_name(fileset),
	    fileset->fs_name,
	    ((gethrtime() - start) / 1000000000) + 1);

	return (0);
}

/*
 * Adds an entry to the fileset's file list. Single threaded so
 * no locking needed.
 */
static void
fileset_insfilelist(fileset_t *fileset, filesetentry_t *entry)
{
	if (fileset->fs_filelist == NULL) {
		fileset->fs_filelist = entry;
		entry->fse_filenext = NULL;
	} else {
		entry->fse_filenext = fileset->fs_filelist;
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
	if (fileset->fs_dirlist == NULL) {
		fileset->fs_dirlist = entry;
		entry->fse_dirnext = NULL;
	} else {
		entry->fse_dirnext = fileset->fs_dirlist;
		fileset->fs_dirlist = entry;
	}
}

/*
 * Obtaines a filesetentry entity for a file to be placed in a
 * (sub)directory of a fileset. The size of the file may be
 * specified by fs_meansize, or calculated from a gamma
 * distribution of parameter fs_sizegamma and of mean size
 * fs_meansize. The filesetentry entity is placed on the file
 * list in the specified parent filesetentry entity, which may
 * be a directory filesetentry, or the root filesetentry in the
 * fileset. It is also placed on the fileset's list of all
 * contained files. Returns 0 if successful or -1 if ipc memory
 * for the path string cannot be allocated.
 */
static int
fileset_populate_file(fileset_t *fileset, filesetentry_t *parent, int serial)
{
	char tmpname[16];
	filesetentry_t *entry;
	double drand;
	double gamma;

	if ((entry = (filesetentry_t *)ipc_malloc(FILEBENCH_FILESETENTRY))
	    == NULL) {
		filebench_log(LOG_ERROR,
		    "fileset_populate_file: Can't malloc filesetentry");
		return (-1);
	}

	(void) pthread_mutex_init(&entry->fse_lock, ipc_mutexattr());
	entry->fse_parent = parent;
	entry->fse_fileset = fileset;
	entry->fse_flags |= FSE_FREE;
	fileset_insfilelist(fileset, entry);

	(void) snprintf(tmpname, sizeof (tmpname), "%08d", serial);
	if ((entry->fse_path = (char *)ipc_pathalloc(tmpname)) == NULL) {
		filebench_log(LOG_ERROR,
		    "fileset_populate_file: Can't alloc path string");
		return (-1);
	}

	gamma = *(fileset->fs_sizegamma) / 1000.0;

	if (gamma > 0) {
		drand = gamma_dist_knuth(gamma, fileset->fs_meansize / gamma);
		entry->fse_size = (off64_t)drand;
	} else {
		entry->fse_size = (off64_t)fileset->fs_meansize;
	}

	fileset->fs_bytes += entry->fse_size;

	fileset->fs_realfiles++;
	return (0);
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
 * Returns 0 on success. Returns -1 if ipc path string memory
 * cannot be allocated and returns an error code (currently
 * also -1) from calls to fileset_populate_file or recursive
 * calls to fileset_populate_subdir.
 */
static int
fileset_populate_subdir(fileset_t *fileset, filesetentry_t *parent,
    int serial, double depth)
{
	double randepth, drand, ranwidth, gamma;
	int isleaf = 0;
	char tmpname[16];
	filesetentry_t *entry;
	int i;

	depth += 1;

	/* Create dir node */
	if ((entry = (filesetentry_t *)ipc_malloc(FILEBENCH_FILESETENTRY))
	    == NULL) {
		filebench_log(LOG_ERROR,
		    "fileset_populate_subdir: Can't malloc filesetentry");
		return (-1);
	}

	(void) pthread_mutex_init(&entry->fse_lock, ipc_mutexattr());

	(void) snprintf(tmpname, sizeof (tmpname), "%08d", serial);
	if ((entry->fse_path = (char *)ipc_pathalloc(tmpname)) == NULL) {
		filebench_log(LOG_ERROR,
		    "fileset_populate_subdir: Can't alloc path string");
		return (-1);
	}

	entry->fse_parent = parent;
	entry->fse_flags |= FSE_DIR | FSE_FREE;
	fileset_insdirlist(fileset, entry);

	gamma = *(fileset->fs_dirgamma) / 1000.0;
	if (gamma > 0) {
		drand = gamma_dist_knuth(gamma, fileset->fs_meandepth / gamma);
		randepth = (int)drand;
	} else {
		randepth = (int)fileset->fs_meandepth;
	}

	gamma = *(fileset->fs_sizegamma) / 1000.0;

	if (gamma > 0) {
		drand = gamma_dist_knuth(gamma, fileset->fs_meanwidth / gamma);
		ranwidth = drand;
	} else {
		ranwidth = fileset->fs_meanwidth;
	}

	if (randepth == 0)
		randepth = 1;
	if (ranwidth == 0)
		ranwidth = 1;
	if (depth >= randepth)
		isleaf = 1;

	/*
	 * Create directory of random width according to distribution, or
	 * if root directory, continue until #files required
	 */
	for (i = 1;
	    ((parent == NULL) || (i < ranwidth + 1)) &&
	    (fileset->fs_realfiles < *(fileset->fs_entries)); i++) {
		int ret = 0;

		if (parent && isleaf)
			ret = fileset_populate_file(fileset, entry, i);
		else
			ret = fileset_populate_subdir(fileset, entry, i, depth);

		if (ret != 0)
			return (ret);
	}
	return (0);
}

/*
 * Populates a fileset with files and subdirectory entries. Uses
 * the supplied fs_dirwidth and fs_entries (number of files) to
 * calculate the required fs_meandepth (of subdirectories) and
 * initialize the fs_meanwidth and fs_meansize variables. Then
 * calls fileset_populate_subdir() to do the recursive
 * subdirectory entry creation and leaf file entry creation. All
 * of the above is skipped if the fileset has already been
 * populated. Returns 0 on success, or an error code from the
 * call to fileset_populate_subdir if that call fails.
 */
static int
fileset_populate(fileset_t *fileset)
{
	int nfiles;
	int meandirwidth = *(fileset->fs_dirwidth);
	int ret;

	/* Skip if already populated */
	if (fileset->fs_bytes > 0)
		goto exists;

#ifdef HAVE_RAW_SUPPORT
	/* check for raw device */
	if (fileset->fs_attrs & FILESET_IS_RAW_DEV)
		return (0);
#endif /* HAVE_RAW_SUPPORT */

	/*
	 * Input params are:
	 *	# of files
	 *	ave # of files per dir
	 *	max size of dir
	 *	# ave size of file
	 *	max size of file
	 */
	nfiles = *(fileset->fs_entries);
	fileset->fs_meandepth = log(nfiles) / log(meandirwidth);
	fileset->fs_meanwidth = meandirwidth;
	fileset->fs_meansize = *(fileset->fs_size);

	if ((ret = fileset_populate_subdir(fileset, NULL, 1, 0)) != 0)
		return (ret);


exists:
	if (fileset->fs_attrs & FILESET_IS_FILE) {
		filebench_log(LOG_VERBOSE, "File %s: mbytes=%lld",
		    fileset->fs_name,
		    fileset->fs_bytes / 1024UL / 1024UL);
	} else {
		filebench_log(LOG_VERBOSE, "Fileset %s: %lld files, "
		    "avg dir = %.1lf, avg depth = %.1lf, mbytes=%lld",
		    fileset->fs_name,
		    *(fileset->fs_entries),
		    fileset->fs_meanwidth,
		    fileset->fs_meandepth,
		    fileset->fs_bytes / 1024UL / 1024UL);
	}
	return (0);
}

/*
 * Allocates a fileset instance, initializes fs_dirgamma and
 * fs_sizegamma default values, and sets the fileset name to the
 * supplied name string. Puts the allocated fileset on the
 * master fileset list and returns a pointer to it.
 */
fileset_t *
fileset_define(char *name)
{
	fileset_t *fileset;

	if (name == NULL)
		return (NULL);

	if ((fileset = (fileset_t *)ipc_malloc(FILEBENCH_FILESET)) == NULL) {
		filebench_log(LOG_ERROR,
		    "fileset_define: Can't malloc fileset");
		return (NULL);
	}

	filebench_log(LOG_DEBUG_IMPL, "Defining file %s", name);

	(void) ipc_mutex_lock(&filebench_shm->fileset_lock);

	fileset->fs_dirgamma = integer_alloc(1500);
	fileset->fs_sizegamma = integer_alloc(1500);

	/* Add fileset to global list */
	if (filebench_shm->filesetlist == NULL) {
		filebench_shm->filesetlist = fileset;
		fileset->fs_next = NULL;
	} else {
		fileset->fs_next = filebench_shm->filesetlist;
		filebench_shm->filesetlist = fileset;
	}

	(void) ipc_mutex_unlock(&filebench_shm->fileset_lock);

	(void) strcpy(fileset->fs_name, name);

	return (fileset);
}

/*
 * If supplied with a pointer to a fileset and the fileset's
 * fs_prealloc flag is set, calls fileset_populate() to populate
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
	paralloc_count = 0;

	if (fileset && integer_isset(fileset->fs_prealloc)) {

		filebench_log(LOG_INFO,
		    "creating/pre-allocating %s %s",
		    fileset_entity_name(fileset), fileset->fs_name);

		if ((ret = fileset_populate(fileset)) != 0)
			return (ret);

		if ((ret = fileset_create(fileset)) != 0)
			return (ret);
	} else {

		filebench_log(LOG_INFO,
		    "Creating/pre-allocating files and filesets");

		list = filebench_shm->filesetlist;
		while (list) {
			if ((ret = fileset_populate(list)) != 0)
				return (ret);
			if ((ret = fileset_create(list)) != 0)
				return (ret);
			list = list->fs_next;
		}
	}

	/* wait for allocation threads to finish */
	filebench_log(LOG_INFO,
	    "waiting for fileset pre-allocation to finish");

	(void) pthread_mutex_lock(&paralloc_lock);
	while (paralloc_count > 0)
		(void) pthread_cond_wait(&paralloc_cv, &paralloc_lock);
	(void) pthread_mutex_unlock(&paralloc_lock);

	if (paralloc_count < 0)
		return (-1);

	return (0);
}

/*
 * Searches through the master fileset list for the named fileset.
 * If found, returns pointer to same, otherwise returns NULL.
 */
fileset_t *
fileset_find(char *name)
{
	fileset_t *fileset = filebench_shm->filesetlist;

	(void) ipc_mutex_lock(&filebench_shm->fileset_lock);

	while (fileset) {
		if (strcmp(name, fileset->fs_name) == 0) {
			(void) ipc_mutex_unlock(&filebench_shm->fileset_lock);
			return (fileset);
		}
		fileset = fileset->fs_next;
	}
	(void) ipc_mutex_unlock(&filebench_shm->fileset_lock);

	return (NULL);
}

/*
 * Iterates over all the file sets in the filesetlist,
 * executing the supplied command "*cmd()" on them. Also
 * indicates to the executed command if it is the first
 * time the command has been executed since the current
 * call to fileset_iter.
 */
void
fileset_iter(int (*cmd)(fileset_t *fileset, int first))
{
	fileset_t *fileset = filebench_shm->filesetlist;
	int count = 0;

	(void) ipc_mutex_lock(&filebench_shm->fileset_lock);

	while (fileset) {
		cmd(fileset, count == 0);
		fileset = fileset->fs_next;
		count++;
	}

	(void) ipc_mutex_unlock(&filebench_shm->fileset_lock);
}

/*
 * Prints information to the filebench log about the file
 * object. Also prints a header on the first call.
 */
int
fileset_print(fileset_t *fileset, int first)
{
	int pathlength = strlen(*fileset->fs_path) + strlen(fileset->fs_name);
	/* 30 spaces */
	char pad[] = "                              ";

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
			    *fileset->fs_path,
			    fileset->fs_name,
			    &pad[pathlength]);
		} else {
			filebench_log(LOG_INFO,
			    "%s/%s%s%9lld     (Single File)",
			    *fileset->fs_path,
			    fileset->fs_name,
			    &pad[pathlength],
			    *fileset->fs_size);
		}
	} else {
		filebench_log(LOG_INFO, "%s/%s%s%9lld%12lld%10lld",
		    *fileset->fs_path,
		    fileset->fs_name,
		    &pad[pathlength],
		    *fileset->fs_size,
		    *fileset->fs_dirwidth,
		    *fileset->fs_entries);
	}
	return (0);
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

	fileset->fs_attrs &= (~FILESET_IS_RAW_DEV);

#ifdef HAVE_RAW_SUPPORT
	/* check for raw device */
	(void) strcpy(path, *fileset->fs_path);
	(void) strcat(path, "/");
	(void) strcat(path, fileset->fs_name);
	if ((stat64(path, &sb) == 0) &&
	    ((sb.st_mode & S_IFMT) == S_IFBLK) && sb.st_rdev) {
		fileset->fs_attrs |= FILESET_IS_RAW_DEV;
		return (1);
	}
#endif /* HAVE_RAW_SUPPORT */

	return (0);
}
