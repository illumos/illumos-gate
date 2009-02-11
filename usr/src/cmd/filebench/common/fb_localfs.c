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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Portions Copyright 2008 Denis Cheng
 */

#include "config.h"
#include "filebench.h"
#include "flowop.h"
#include "threadflow.h" /* For aiolist definition */

#ifndef HAVE_OFF64_T
/*
 * We are probably on linux.
 * According to http://www.suse.de/~aj/linux_lfs.html, defining the
 * above, automatically changes type of off_t to off64_t. so let
 * us use only off_t as off64_t is not defined
 */
#defineoff64_t off_t
#endif /* HAVE_OFF64_T */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/resource.h>

#include "filebench.h"
#include "fsplug.h"

#ifdef HAVE_AIO
#include <aio.h>
#endif /* HAVE_AIO */

#ifdef HAVE_LIBAIO_H
#include <libaio.h>
#endif /* HAVE_LIBAIO_H */

#ifndef HAVE_AIOCB64_T
#define	aiocb64 aiocb
#endif /* HAVE_AIOCB64_T */

/*
 * These routines implement local file access. They are placed into a
 * vector of functions that are called by all I/O operations in fileset.c
 * and flowop_library.c. This represents the default file system plug-in,
 * and may be replaced by vectors for other file system plug-ins.
 */

static int fb_lfs_freemem(fb_fdesc_t *fd, off64_t size);
static int fb_lfs_open(fb_fdesc_t *, char *, int, int);
static int fb_lfs_pread(fb_fdesc_t *, caddr_t, fbint_t, off64_t);
static int fb_lfs_read(fb_fdesc_t *, caddr_t, fbint_t);
static int fb_lfs_pwrite(fb_fdesc_t *, caddr_t, fbint_t, off64_t);
static int fb_lfs_write(fb_fdesc_t *, caddr_t, fbint_t);
static int fb_lfs_lseek(fb_fdesc_t *, off64_t, int);
static int fb_lfs_truncate(fb_fdesc_t *, off64_t);
static int fb_lfs_rename(const char *, const char *);
static int fb_lfs_close(fb_fdesc_t *);
static int fb_lfs_link(const char *, const char *);
static int fb_lfs_symlink(const char *, const char *);
static int fb_lfs_unlink(char *);
static ssize_t fb_lfs_readlink(const char *, char *, size_t);
static int fb_lfs_mkdir(char *, int);
static int fb_lfs_rmdir(char *);
static DIR *fb_lfs_opendir(char *);
static struct dirent *fb_lfs_readdir(DIR *);
static int fb_lfs_closedir(DIR *);
static int fb_lfs_fsync(fb_fdesc_t *);
static int fb_lfs_stat(char *, struct stat64 *);
static int fb_lfs_fstat(fb_fdesc_t *, struct stat64 *);
static int fb_lfs_access(const char *, int);

static fsplug_func_t fb_lfs_funcs =
{
	"locfs",
	fb_lfs_freemem,		/* flush page cache */
	fb_lfs_open,		/* open */
	fb_lfs_pread,		/* pread */
	fb_lfs_read,		/* read */
	fb_lfs_pwrite,		/* pwrite */
	fb_lfs_write,		/* write */
	fb_lfs_lseek,		/* lseek */
	fb_lfs_truncate,	/* ftruncate */
	fb_lfs_rename,		/* rename */
	fb_lfs_close,		/* close */
	fb_lfs_link,		/* link */
	fb_lfs_symlink,		/* symlink */
	fb_lfs_unlink,		/* unlink */
	fb_lfs_readlink,	/* readlink */
	fb_lfs_mkdir,		/* mkdir */
	fb_lfs_rmdir,		/* rmdir */
	fb_lfs_opendir,		/* opendir */
	fb_lfs_readdir,		/* readdir */
	fb_lfs_closedir,	/* closedir */
	fb_lfs_fsync,		/* fsync */
	fb_lfs_stat,		/* stat */
	fb_lfs_fstat,		/* fstat */
	fb_lfs_access		/* access */
};

#ifdef HAVE_AIO
/*
 * Local file system asynchronous IO flowops are in this module, as
 * they have a number of local file system specific features.
 */
static int fb_lfsflow_aiowrite(threadflow_t *threadflow, flowop_t *flowop);
static int fb_lfsflow_aiowait(threadflow_t *threadflow, flowop_t *flowop);

static flowop_proto_t fb_lfsflow_funcs[] = {
	FLOW_TYPE_AIO, FLOW_ATTR_WRITE, "aiowrite", flowop_init_generic,
	fb_lfsflow_aiowrite, flowop_destruct_generic,
	FLOW_TYPE_AIO, 0, "aiowait", flowop_init_generic,
	fb_lfsflow_aiowait, flowop_destruct_generic
};

#endif /* HAVE_AIO */

/*
 * Initialize this processes I/O functions vector to point to
 * the vector of local file system I/O functions
 */
void
fb_lfs_funcvecinit(void)
{
	fs_functions_vec = &fb_lfs_funcs;
}

/*
 * Initialize those flowops whose implementation is file system
 * specific.
 */
void
fb_lfs_flowinit(void)
{
	int nops;

	/*
	 * re-initialize the I/O functions vector while we are at
	 * it as it may have been redefined since the process was
	 * created, at least if this is the master processes
	 */
	fb_lfs_funcvecinit();

#ifdef HAVE_AIO
	nops = sizeof (fb_lfsflow_funcs) / sizeof (flowop_proto_t);
	flowop_flow_init(fb_lfsflow_funcs, nops);
#endif /* HAVE_AIO */
}

/*
 * Frees up memory mapped file region of supplied size. The
 * file descriptor "fd" indicates which memory mapped file.
 * If successful, returns 0. Otherwise returns -1 if "size"
 * is zero, or -1 times the number of times msync() failed.
 */
static int
fb_lfs_freemem(fb_fdesc_t *fd, off64_t size)
{
	off64_t left;
	int ret = 0;

	for (left = size; left > 0; left -= MMAP_SIZE) {
		off64_t thismapsize;
		caddr_t addr;

		thismapsize = MIN(MMAP_SIZE, left);
		addr = mmap64(0, thismapsize, PROT_READ|PROT_WRITE,
		    MAP_SHARED, fd->fd_num, size - left);
		ret += msync(addr, thismapsize, MS_INVALIDATE);
		(void) munmap(addr, thismapsize);
	}
	return (ret);
}

/*
 * Does a posix pread. Returns what the pread() returns.
 */
static int
fb_lfs_pread(fb_fdesc_t *fd, caddr_t iobuf, fbint_t iosize, off64_t fileoffset)
{
	return (pread64(fd->fd_num, iobuf, iosize, fileoffset));
}

/*
 * Does a posix read. Returns what the read() returns.
 */
static int
fb_lfs_read(fb_fdesc_t *fd, caddr_t iobuf, fbint_t iosize)
{
	return (read(fd->fd_num, iobuf, iosize));
}

#ifdef HAVE_AIO

/*
 * Asynchronous write section. An Asynchronous IO element
 * (aiolist_t) is used to associate the asynchronous write request with
 * its subsequent completion. This element includes a aiocb64 struct
 * that is used by posix aio_xxx calls to track the asynchronous writes.
 * The flowops aiowrite and aiowait result in calls to these posix
 * aio_xxx system routines to do the actual asynchronous write IO
 * operations.
 */


/*
 * Allocates an asynchronous I/O list (aio, of type
 * aiolist_t) element. Adds it to the flowop thread's
 * threadflow aio list. Returns a pointer to the element.
 */
static aiolist_t *
aio_allocate(flowop_t *flowop)
{
	aiolist_t *aiolist;

	if ((aiolist = malloc(sizeof (aiolist_t))) == NULL) {
		filebench_log(LOG_ERROR, "malloc aiolist failed");
		filebench_shutdown(1);
	}

	/* Add to list */
	if (flowop->fo_thread->tf_aiolist == NULL) {
		flowop->fo_thread->tf_aiolist = aiolist;
		aiolist->al_next = NULL;
	} else {
		aiolist->al_next = flowop->fo_thread->tf_aiolist;
		flowop->fo_thread->tf_aiolist = aiolist;
	}
	return (aiolist);
}

/*
 * Searches for the aiolist element that has a matching
 * completion block, aiocb. If none found returns FILEBENCH_ERROR. If
 * found, removes the aiolist element from flowop thread's
 * list and returns FILEBENCH_OK.
 */
static int
aio_deallocate(flowop_t *flowop, struct aiocb64 *aiocb)
{
	aiolist_t *aiolist = flowop->fo_thread->tf_aiolist;
	aiolist_t *previous = NULL;
	aiolist_t *match = NULL;

	if (aiocb == NULL) {
		filebench_log(LOG_ERROR, "null aiocb deallocate");
		return (FILEBENCH_OK);
	}

	while (aiolist) {
		if (aiocb == &(aiolist->al_aiocb)) {
			match = aiolist;
			break;
		}
		previous = aiolist;
		aiolist = aiolist->al_next;
	}

	if (match == NULL)
		return (FILEBENCH_ERROR);

	/* Remove from the list */
	if (previous)
		previous->al_next = match->al_next;
	else
		flowop->fo_thread->tf_aiolist = match->al_next;

	return (FILEBENCH_OK);
}

/*
 * Emulate posix aiowrite(). Determines which file to use,
 * either one file of a fileset, or the file associated
 * with a fileobj, allocates and fills an aiolist_t element
 * for the write, and issues the asynchronous write. This
 * operation is only valid for random IO, and returns an
 * error if the flowop is set for sequential IO. Returns
 * FILEBENCH_OK on success, FILEBENCH_NORSC if iosetup can't
 * obtain a file to open, and FILEBENCH_ERROR on any
 * encountered error.
 */
static int
fb_lfsflow_aiowrite(threadflow_t *threadflow, flowop_t *flowop)
{
	caddr_t iobuf;
	fbint_t wss;
	fbint_t iosize;
	fb_fdesc_t *fdesc;
	int ret;

	iosize = avd_get_int(flowop->fo_iosize);

	if ((ret = flowoplib_iosetup(threadflow, flowop, &wss, &iobuf,
	    &fdesc, iosize)) != FILEBENCH_OK)
		return (ret);

	if (avd_get_bool(flowop->fo_random)) {
		uint64_t fileoffset;
		struct aiocb64 *aiocb;
		aiolist_t *aiolist;

		if (filebench_randomno64(&fileoffset,
		    wss, iosize, NULL) == -1) {
			filebench_log(LOG_ERROR,
			    "file size smaller than IO size for thread %s",
			    flowop->fo_name);
			return (FILEBENCH_ERROR);
		}

		aiolist = aio_allocate(flowop);
		aiolist->al_type = AL_WRITE;
		aiocb = &aiolist->al_aiocb;

		aiocb->aio_fildes = fdesc->fd_num;
		aiocb->aio_buf = iobuf;
		aiocb->aio_nbytes = (size_t)iosize;
		aiocb->aio_offset = (off64_t)fileoffset;
		aiocb->aio_reqprio = 0;

		filebench_log(LOG_DEBUG_IMPL,
		    "aio fd=%d, bytes=%llu, offset=%llu",
		    fdesc->fd_num, (u_longlong_t)iosize,
		    (u_longlong_t)fileoffset);

		flowop_beginop(threadflow, flowop);
		if (aio_write64(aiocb) < 0) {
			filebench_log(LOG_ERROR, "aiowrite failed: %s",
			    strerror(errno));
			filebench_shutdown(1);
		}
		flowop_endop(threadflow, flowop, iosize);
	} else {
		return (FILEBENCH_ERROR);
	}

	return (FILEBENCH_OK);
}



#define	MAXREAP 4096

/*
 * Emulate posix aiowait(). Waits for the completion of half the
 * outstanding asynchronous IOs, or a single IO, which ever is
 * larger. The routine will return after a sufficient number of
 * completed calls issued by any thread in the procflow have
 * completed, or a 1 second timout elapses. All completed
 * IO operations are deleted from the thread's aiolist.
 */
static int
fb_lfsflow_aiowait(threadflow_t *threadflow, flowop_t *flowop)
{
	struct aiocb64 **worklist;
	aiolist_t *aio = flowop->fo_thread->tf_aiolist;
	int uncompleted = 0;

	worklist = calloc(MAXREAP, sizeof (struct aiocb64 *));

	/* Count the list of pending aios */
	while (aio) {
		uncompleted++;
		aio = aio->al_next;
	}

	do {
		uint_t ncompleted = 0;
		uint_t todo;
		struct timespec timeout;
		int inprogress;
		int i;

		/* Wait for half of the outstanding requests */
		timeout.tv_sec = 1;
		timeout.tv_nsec = 0;

		if (uncompleted > MAXREAP)
			todo = MAXREAP;
		else
			todo = uncompleted / 2;

		if (todo == 0)
			todo = 1;

		flowop_beginop(threadflow, flowop);

#if (defined(HAVE_AIOWAITN) && defined(USE_PROCESS_MODEL))
		if (((aio_waitn64((struct aiocb64 **)worklist,
		    MAXREAP, &todo, &timeout)) == -1) &&
		    errno && (errno != ETIME)) {
			filebench_log(LOG_ERROR,
			    "aiowait failed: %s, outstanding = %d, "
			    "ncompleted = %d ",
			    strerror(errno), uncompleted, todo);
		}

		ncompleted = todo;
		/* Take the  completed I/Os from the list */
		inprogress = 0;
		for (i = 0; i < ncompleted; i++) {
			if ((aio_return64(worklist[i]) == -1) &&
			    (errno == EINPROGRESS)) {
				inprogress++;
				continue;
			}
			if (aio_deallocate(flowop, worklist[i])
			    == FILEBENCH_ERROR) {
				filebench_log(LOG_ERROR, "Could not remove "
				    "aio from list ");
				flowop_endop(threadflow, flowop, 0);
				return (FILEBENCH_ERROR);
			}
		}

		uncompleted -= ncompleted;
		uncompleted += inprogress;

#else

		for (ncompleted = 0, inprogress = 0,
		    aio = flowop->fo_thread->tf_aiolist;
		    ncompleted < todo, aio != NULL; aio = aio->al_next) {
			int result = aio_error64(&aio->al_aiocb);

			if (result == EINPROGRESS) {
				inprogress++;
				continue;
			}

			if ((aio_return64(&aio->al_aiocb) == -1) || result) {
				filebench_log(LOG_ERROR, "aio failed: %s",
				    strerror(result));
				continue;
			}

			ncompleted++;

			if (aio_deallocate(flowop, &aio->al_aiocb) < 0) {
				filebench_log(LOG_ERROR, "Could not remove "
				    "aio from list ");
				flowop_endop(threadflow, flowop, 0);
				return (FILEBENCH_ERROR);
			}
		}

		uncompleted -= ncompleted;

#endif
		filebench_log(LOG_DEBUG_SCRIPT,
		    "aio2 completed %d ios, uncompleted = %d, inprogress = %d",
		    ncompleted, uncompleted, inprogress);

	} while (uncompleted > MAXREAP);

	flowop_endop(threadflow, flowop, 0);

	free(worklist);

	return (FILEBENCH_OK);
}

#endif /* HAVE_AIO */

/*
 * Does an open64 of a file. Inserts the file descriptor number returned
 * by open() into the supplied filebench fd. Returns FILEBENCH_OK on
 * successs, and FILEBENCH_ERROR on failure.
 */

static int
fb_lfs_open(fb_fdesc_t *fd, char *path, int flags, int perms)
{
	if ((fd->fd_num = open64(path, flags, perms)) < 0)
		return (FILEBENCH_ERROR);
	else
		return (FILEBENCH_OK);
}

/*
 * Does an unlink (delete) of a file.
 */
static int
fb_lfs_unlink(char *path)
{
	return (unlink(path));
}

/*
 * Does a readlink of a symbolic link.
 */
static ssize_t
fb_lfs_readlink(const char *path, char *buf, size_t buf_size)
{
	return (readlink(path, buf, buf_size));
}

/*
 * Does fsync of a file. Returns with fsync return info.
 */
static int
fb_lfs_fsync(fb_fdesc_t *fd)
{
	return (fsync(fd->fd_num));
}

/*
 * Do a posix lseek of a file. Return what lseek() returns.
 */
static int
fb_lfs_lseek(fb_fdesc_t *fd, off64_t offset, int whence)
{
	return (lseek64(fd->fd_num, offset, whence));
}

/*
 * Do a posix rename of a file. Return what rename() returns.
 */
static int
fb_lfs_rename(const char *old, const char *new)
{
	return (rename(old, new));
}


/*
 * Do a posix close of a file. Return what close() returns.
 */
static int
fb_lfs_close(fb_fdesc_t *fd)
{
	return (close(fd->fd_num));
}

/*
 * Use mkdir to create a directory.
 */
static int
fb_lfs_mkdir(char *path, int perm)
{
	return (mkdir(path, perm));
}

/*
 * Use rmdir to delete a directory. Returns what rmdir() returns.
 */
static int
fb_lfs_rmdir(char *path)
{
	return (rmdir(path));
}

/*
 * Does a posix opendir(), Returns a directory handle on success,
 * NULL on failure.
 */
static DIR *
fb_lfs_opendir(char *path)
{
	return (opendir(path));
}

/*
 * Does a readdir() call. Returns a pointer to a table of directory
 * information on success, NULL on failure.
 */
static struct dirent *
fb_lfs_readdir(DIR *dirp)
{
	return (readdir(dirp));
}

/*
 * Does a closedir() call.
 */
static int
fb_lfs_closedir(DIR *dirp)
{
	return (closedir(dirp));
}

/*
 * Does an fstat of a file.
 */
static int
fb_lfs_fstat(fb_fdesc_t *fd, struct stat64 *statbufp)
{
	return (fstat64(fd->fd_num, statbufp));
}

/*
 * Does a stat of a file.
 */
static int
fb_lfs_stat(char *path, struct stat64 *statbufp)
{
	return (stat64(path, statbufp));
}

/*
 * Do a pwrite64 to a file.
 */
static int
fb_lfs_pwrite(fb_fdesc_t *fd, caddr_t iobuf, fbint_t iosize, off64_t offset)
{
	return (pwrite64(fd->fd_num, iobuf, iosize, offset));
}

/*
 * Do a write to a file.
 */
static int
fb_lfs_write(fb_fdesc_t *fd, caddr_t iobuf, fbint_t iosize)
{
	return (write(fd->fd_num, iobuf, iosize));
}

/*
 * Does a truncate operation and returns the result
 */
static int
fb_lfs_truncate(fb_fdesc_t *fd, off64_t fse_size)
{
#ifdef HAVE_FTRUNCATE64
	return (ftruncate64(fd->fd_num, fse_size));
#else
	return (ftruncate(fd->fd_num, (off_t)fse_size));
#endif
}

/*
 * Does a link operation and returns the result
 */
static int
fb_lfs_link(const char *existing, const char *new)
{
	return (link(existing, new));
}

/*
 * Does a symlink operation and returns the result
 */
static int
fb_lfs_symlink(const char *existing, const char *new)
{
	return (symlink(existing, new));
}

/*
 * Does an access() check on a file.
 */
static int
fb_lfs_access(const char *path, int amode)
{
	return (access(path, amode));
}
