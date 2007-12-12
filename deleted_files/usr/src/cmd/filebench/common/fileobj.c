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
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef HAVE_UTILITY_H
#include <utility.h>
#endif

#include "vars.h"
#include "filebench.h"
#include "fileobj.h"

/*
 * File objects, of type fileobj_t, are entities which contain
 * information about filebench files, one file per fileobj. The
 * information includes the file's name, its pathname, its size, and
 * a set of attributes indicating whether to create, preallocate,
 * allocate in parallel, reuse, and cache the file or not. All fileobj
 * are kept on a global linked list in shared memory.
 */

/*
 * Prints syntax for specifying file object parameters.
 */
void
fileobj_usage()
{
	(void) fprintf(stderr,
	    "define file name=<name>,path=<pathname>,size=<size>\n");
	(void) fprintf(stderr, "		        [,paralloc]\n");
	(void) fprintf(stderr, "		        [,prealloc]\n");
	(void) fprintf(stderr, "		        [,reuse]\n");
	(void) fprintf(stderr, "\n");
}

/*
 * Frees up memory mapped file region of supplied size.
 * The file descriptor "fd" indicates which memory mapped
 * file. If successful, returns 0. Otherwise returns -1 if
 * "size" is zero, or -1 times the number of times msync()
 * failed.
 */
static int
fileobj_freemem(int fd, off64_t size)
{
	off64_t left;
	int ret = -1;

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
 * Creates the file associated with a fileobj (file object)
 * and writes fo_size bytes to it. The bytes are written
 * FILE_ALLOC_BLOCK bytes at a time. However, if the file
 * already exists, is full size, and the fo_reuse flag is
 * set, then the file is just left alone.
 */
static int
fileobj_prealloc(fileobj_t *fileobj)
{
	off64_t seek;
	int fd;
	char *buf;
	int exists;
	struct stat64 sb;
	char name[MAXPATHLEN];

	if (*fileobj->fo_path == NULL) {
		filebench_log(LOG_ERROR, "File path not set");
		return (-1);
	}

	(void) strcpy(name, *fileobj->fo_path);
	(void) mkdir(name, 0777);
	(void) strcat(name, "/");
	(void) strcat(name, fileobj->fo_name);

	if ((fd = open64(name, O_RDWR)) < 0) {
		filebench_log(LOG_ERROR,
		    "Failed to find file %s for pre-allocation: %s",
		    name, strerror(errno));
		return (-1);
	}

	/* If it's a raw device */
	exists = (fstat64(fd, &sb) == 0);
#ifdef RAW
	if (exists && sb.st_rdev)
		return (0);
#endif

	if (integer_isset(fileobj->fo_reuse) && exists) {
		if (sb.st_size == (off64_t)*fileobj->fo_size) {
			filebench_log(LOG_INFO, "Re-using file %s", name);
			if (!integer_isset(fileobj->fo_cached))
				(void) fileobj_freemem(fd, *fileobj->fo_size);
			(void) close(fd);
			return (0);
		} else if (sb.st_size > (off64_t)*fileobj->fo_size) {
			/* reuse, but too large */
			filebench_log(LOG_INFO,
			    "Truncating & Re-using file %s", name);
			(void) ftruncate64(fd, (off64_t)*fileobj->fo_size);
			if (!integer_isset(fileobj->fo_cached))
				(void) fileobj_freemem(fd, *fileobj->fo_size);
			(void) close(fd);
			return (0);
		}
	}

	if ((buf = (char *)malloc(FILE_ALLOC_BLOCK)) == NULL) {
		(void) close(fd);
		return (-1);
	}

	for (seek = 0; seek < (off64_t)*fileobj->fo_size; ) {
		off64_t wsize;
		int ret = 0;

		/* Write FILE_ALLOC_BLOCK's worth except on last write */
		wsize = MIN((off64_t)*fileobj->fo_size - seek,
		    FILE_ALLOC_BLOCK);

		ret = write(fd, buf, wsize);
		if (ret != wsize) {
			filebench_log(LOG_ERROR,
			    "Failed to pre-allocate file %s: %s",
			    name, strerror(errno));
			(void) close(fd);
			return (-1);
		}
		seek += wsize;
	}

	filebench_log(LOG_INFO,
	    "Pre-allocated file %s", name);

	(void) fsync(fd);
	if (!integer_isset(fileobj->fo_cached))
		(void) fileobj_freemem(fd, *fileobj->fo_size);
	(void) close(fd);
	return (0);
}

/*
 * Creates the file portion of a fileobj (file object) and
 * leaves it empty. If the file already exists and the fo_reuse
 * flag is set, the file will be retained, otherwise any
 * existing file will first be deleted, and then a new
 * (empty) file will be created.
 */
static int
fileobj_createfile(fileobj_t *fileobj)
{
	int fd;
	struct stat64 sb;
	int exists;
	char name[MAXPATHLEN];

	if (*fileobj->fo_path == NULL) {
		filebench_log(LOG_ERROR, "File path not set");
		return (-1);
	}

	(void) strcpy(name, *fileobj->fo_path);
	(void) mkdir(name, 0777);
	(void) strcat(name, "/");
	(void) strcat(name, fileobj->fo_name);

	/* If it's a raw device */
	exists = (stat64(name, &sb) == 0);
#ifdef RAW
	if (exists && sb.st_rdev)
		return (0);
#endif

	/*
	 * If we are re-using the file, then just free up the cache and
	 * return
	 */
	if (integer_isset(fileobj->fo_reuse) && exists) {
		fd = open64(name, O_RDWR);
		(void) fsync(fd);
		(void) fileobj_freemem(fd, *fileobj->fo_size);
		(void) close(fd);
		return (fd < 0);
	}

	filebench_log(LOG_DEBUG_IMPL, "Creating file %s", name);
	(void) unlink(name);
	if ((fd = open64(name, O_RDWR | O_CREAT, 0666)) < 0) {
		filebench_log(LOG_ERROR,
		    "Failed to create file %s: %s",
		    name, strerror(errno));
		return (-1);
	}
	(void) fsync(fd);
	(void) close(fd);

	return (fd < 0);
}

/*
 * Creates and optionally preallocates the actual file
 * portions of all fileobjs found on the filelist maintained
 * in shared memory. If fo_paralloc is set, a thread will
 * be spawned to preallocate the fileobj in parallel with
 * that of other fileobjs. The routine waits for all such
 * threads to finish before exiting.
 */
int
fileobj_init()
{
	fileobj_t *fileobj = filebench_shm->filelist;
	int nthreads = 0;
	int ret = 0;

	(void) ipc_mutex_lock(&filebench_shm->fileobj_lock);

	filebench_log(LOG_INFO,
	    "Creating/pre-allocating files");

	while (fileobj) {

		/* Create files */
		if (*fileobj->fo_create)
			ret += fileobj_createfile(fileobj);

		/* Preallocate files */
		if (integer_isset(fileobj->fo_prealloc)) {

			if (!integer_isset(fileobj->fo_paralloc)) {
				ret += fileobj_prealloc(fileobj);
				fileobj = fileobj->fo_next;
				continue;
			}

			if (pthread_create(&fileobj->fo_tid, NULL,
			    (void *(*)(void*))fileobj_prealloc,
			    fileobj) != 0) {
				filebench_log(LOG_ERROR,
				    "File prealloc thread create failed");
				filebench_shutdown(1);
			} else {
				nthreads++;
			}
		}

		fileobj = fileobj->fo_next;
	}

	/* Wait for allocations to finish */
	if (nthreads) {
		filebench_log(LOG_INFO,
		    "Waiting for preallocation threads to complete...");
		fileobj = filebench_shm->filelist;
		while (fileobj) {
			ret += pthread_join(fileobj->fo_tid, NULL);
			fileobj = fileobj->fo_next;
		}
	}

	(void) ipc_mutex_unlock(&filebench_shm->fileobj_lock);

	return (ret);
}

/*
 * Allocates a fileobj (file object) in shared memory, sets
 * it's name to "name" and places it on the shared filelist.
 * It also returns a pointer to the fileobj.
 */
fileobj_t *
fileobj_define(char *name)
{
	fileobj_t *fileobj;

	if (name == NULL)
		return (NULL);

	/* allocate a fileobj from shared memory */
	if ((fileobj = (fileobj_t *)ipc_malloc(FILEBENCH_FILEOBJ)) == NULL) {
		filebench_log(LOG_ERROR,
		    "fileobj_define: Can't malloc fileobj");
		return (NULL);
	}

	filebench_log(LOG_DEBUG_IMPL, "Defining file %s", name);

	(void) ipc_mutex_lock(&filebench_shm->fileobj_lock);

	/* Add fileobj to global list */
	if (filebench_shm->filelist == NULL) {
		filebench_shm->filelist = fileobj;
		fileobj->fo_next = NULL;
	} else {
		fileobj->fo_next = filebench_shm->filelist;
		filebench_shm->filelist = fileobj;
	}

	(void) ipc_mutex_unlock(&filebench_shm->fileobj_lock);

	/* name the new fileobj */
	(void) strcpy(fileobj->fo_name, name);

	return (fileobj);
}

/*
 * Opens the file associated with a fileobj. The "attrs"
 * integer supplies optional attributes to the open64 call
 * used to actually open the file. The file is opened in
 * read/write mode, and may be opened in synchronous mode
 * if FLOW_ATTR_DSYNC is set in "attrs", and be set to
 * DIRECTIO_ON if FLOW_ATTR_DIRECTIO is set in "attrs".
 * The file descriptor integer returned by open64 is
 * returned to the caller.
 */
int
fileobj_open(fileobj_t *fileobj, int attrs)
{
	int open_attrs = 0;
	int fd;
	char name[MAXPATHLEN];

	if (*fileobj->fo_path == NULL) {
		filebench_log(LOG_ERROR, "File path not set");
		return (-1);
	}

	(void) strcpy(name, *fileobj->fo_path);
	(void) mkdir(name, 0777);
	(void) strcat(name, "/");
	(void) strcat(name, fileobj->fo_name);

	if (attrs & FLOW_ATTR_DSYNC) {
#ifdef sun
		open_attrs |= O_DSYNC;
#else
		open_attrs |= O_FSYNC;
#endif
	}

	fd = open64(name, O_RDWR | open_attrs, 0666);
	filebench_log(LOG_DEBUG_SCRIPT, "open file %s flags %d = %d",
	    *fileobj->fo_path, open_attrs, fd);

	if (fd < 0) {
		filebench_log(LOG_ERROR,
		    "Failed to open %s: %s",
		    name,
		    strerror(errno));
	}

	/* if running on Solaris, decide whether to use buffered io or not */
#ifdef sun
	if (attrs & FLOW_ATTR_DIRECTIO)
		(void) directio(fd, DIRECTIO_ON);
	else
		(void) directio(fd, DIRECTIO_OFF);
#endif

	return (fd);
}

/*
 * Searches the shared "filelist" for the named filobj.
 * Returns a pointer to the fileobj if found, otherwise NULL.
 */
fileobj_t *
fileobj_find(char *name)
{
	fileobj_t *fileobj = filebench_shm->filelist;

	(void) ipc_mutex_lock(&filebench_shm->fileobj_lock);

	while (fileobj) {

		if (strcmp(name, fileobj->fo_name) == 0) {
			(void) ipc_mutex_unlock(&filebench_shm->fileobj_lock);
			return (fileobj);
		}
		fileobj = fileobj->fo_next;
	}
	(void) ipc_mutex_unlock(&filebench_shm->fileobj_lock);

	return (NULL);
}

/*
 * Iterates over all the file objects in the filelist,
 * executing the supplied command "*cmd()" on them. Also
 * indicates to the executed command if it is the first
 * time the command has been executed since the current
 * call to fileobj_iter.
 */
void
fileobj_iter(int (*cmd)(fileobj_t *fileobj, int first))
{
	fileobj_t *fileobj = filebench_shm->filelist;
	int count = 0;

	(void) ipc_mutex_lock(&filebench_shm->fileobj_lock);

	while (fileobj) {
		cmd(fileobj, count == 0);
		fileobj = fileobj->fo_next;
		count++;
	}

	(void) ipc_mutex_unlock(&filebench_shm->fileobj_lock);
}

/*
 * Prints information to the filebench log about the file
 * object. Also prints a header on the first call.
 */
int
fileobj_print(fileobj_t *fileobj, int first)
{
	if (first) {
		filebench_log(LOG_INFO, "%10s %32s %8s",
		    "File Name",
		    "Path Name",
		    "Size");
	}

	filebench_log(LOG_INFO, "%10s %32s %8ld",
	    fileobj->fo_name,
	    *fileobj->fo_path,
	    *fileobj->fo_size);
	return (0);
}
