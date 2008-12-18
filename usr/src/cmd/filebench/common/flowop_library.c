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

#include "config.h"

#include <sys/types.h>
#ifdef HAVE_SYS_ASYNCH_H
#include <sys/asynch.h>
#endif
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <inttypes.h>
#include <fcntl.h>
#include <math.h>
#include <dirent.h>

#ifdef HAVE_UTILITY_H
#include <utility.h>
#endif /* HAVE_UTILITY_H */

#ifdef HAVE_AIO
#include <aio.h>
#endif /* HAVE_AIO */

#ifdef HAVE_LIBAIO_H
#include <libaio.h>
#endif /* HAVE_LIBAIO_H */

#ifdef HAVE_SYS_ASYNC_H
#include <sys/asynch.h>
#endif /* HAVE_SYS_ASYNC_H */

#ifdef HAVE_AIO_H
#include <aio.h>
#endif /* HAVE_AIO_H */

#ifndef HAVE_UINT_T
#define	uint_t unsigned int
#endif /* HAVE_UINT_T */

#ifndef HAVE_AIOCB64_T
#define	aiocb64 aiocb
#endif /* HAVE_AIOCB64_T */

#ifndef HAVE_SYSV_SEM
#include <semaphore.h>
#endif /* HAVE_SYSV_SEM */

#include "filebench.h"
#include "flowop.h"
#include "fileset.h"
#include "fb_random.h"
#include "utils.h"
/*
 * These routines implement the flowops from the f language. Each
 * flowop has has a name such as "read", and a set of function pointers
 * to call for initialization, execution and destruction of the flowop.
 * The table flowoplib_funcs[] contains a flowoplib struct for each
 * implemented flowop. Most flowops use a generic initialization function
 * and all currently use a generic destruction function. All flowop
 * functions referenced from the table are in this file, though, of
 * course, they often call functions from other files.
 *
 * The flowop_init() routine uses the flowoplib_funcs[] table to
 * create an initial set of "instance 0" flowops, one for each type of
 * flowop, from which all other flowops are derived. These "instance 0"
 * flowops are initialized with information from the table including
 * pointers for their fo_init, fo_func and fo_destroy functions. When
 * a flowop definition is encountered in an f language script, the
 * "type" of flowop, such as "read" is used to search for the
 * "instance 0" flowop named "read", then a new flowop is allocated
 * which inherits its function pointers and other initial properties
 * from the instance 0 flowop, and is given a new name as specified
 * by the "name=" attribute.
 */

static int flowoplib_init_generic(flowop_t *flowop);
static void flowoplib_destruct_generic(flowop_t *flowop);
static void flowoplib_destruct_noop(flowop_t *flowop);
static int flowoplib_fdnum(threadflow_t *threadflow, flowop_t *flowop);
static int flowoplib_print(threadflow_t *threadflow, flowop_t *flowop);
static int flowoplib_write(threadflow_t *threadflow, flowop_t *flowop);
#ifdef HAVE_AIO
static int flowoplib_aiowrite(threadflow_t *threadflow, flowop_t *flowop);
static int flowoplib_aiowait(threadflow_t *threadflow, flowop_t *flowop);
#endif
static int flowoplib_read(threadflow_t *threadflow, flowop_t *flowop);
static int flowoplib_block_init(flowop_t *flowop);
static int flowoplib_block(threadflow_t *threadflow, flowop_t *flowop);
static int flowoplib_wakeup(threadflow_t *threadflow, flowop_t *flowop);
static int flowoplib_hog(threadflow_t *threadflow, flowop_t *flowop);
static int flowoplib_delay(threadflow_t *threadflow, flowop_t *flowop);
static int flowoplib_sempost(threadflow_t *threadflow, flowop_t *flowop);
static int flowoplib_sempost_init(flowop_t *flowop);
static int flowoplib_semblock(threadflow_t *threadflow, flowop_t *flowop);
static int flowoplib_semblock_init(flowop_t *flowop);
static void flowoplib_semblock_destruct(flowop_t *flowop);
static int flowoplib_eventlimit(threadflow_t *, flowop_t *flowop);
static int flowoplib_bwlimit(threadflow_t *, flowop_t *flowop);
static int flowoplib_iopslimit(threadflow_t *, flowop_t *flowop);
static int flowoplib_opslimit(threadflow_t *, flowop_t *flowop);
static int flowoplib_openfile(threadflow_t *, flowop_t *flowop);
static int flowoplib_openfile_common(threadflow_t *, flowop_t *flowop, int fd);
static int flowoplib_createfile(threadflow_t *, flowop_t *flowop);
static int flowoplib_closefile(threadflow_t *, flowop_t *flowop);
static int flowoplib_makedir(threadflow_t *, flowop_t *flowop);
static int flowoplib_removedir(threadflow_t *, flowop_t *flowop);
static int flowoplib_listdir(threadflow_t *, flowop_t *flowop);
static int flowoplib_fsync(threadflow_t *, flowop_t *flowop);
static int flowoplib_readwholefile(threadflow_t *, flowop_t *flowop);
static int flowoplib_writewholefile(threadflow_t *, flowop_t *flowop);
static int flowoplib_appendfile(threadflow_t *threadflow, flowop_t *flowop);
static int flowoplib_appendfilerand(threadflow_t *threadflow, flowop_t *flowop);
static int flowoplib_deletefile(threadflow_t *threadflow, flowop_t *flowop);
static int flowoplib_statfile(threadflow_t *threadflow, flowop_t *flowop);
static int flowoplib_finishoncount(threadflow_t *threadflow, flowop_t *flowop);
static int flowoplib_finishonbytes(threadflow_t *threadflow, flowop_t *flowop);
static int flowoplib_fsyncset(threadflow_t *threadflow, flowop_t *flowop);
static int flowoplib_testrandvar(threadflow_t *threadflow, flowop_t *flowop);
static int flowoplib_testrandvar_init(flowop_t *flowop);
static void flowoplib_testrandvar_destruct(flowop_t *flowop);

typedef struct flowoplib {
	int	fl_type;
	int	fl_attrs;
	char	*fl_name;
	int	(*fl_init)();
	int	(*fl_func)();
	void	(*fl_destruct)();
} flowoplib_t;

static flowoplib_t flowoplib_funcs[] = {
	FLOW_TYPE_IO, FLOW_ATTR_WRITE, "write", flowoplib_init_generic,
	flowoplib_write, flowoplib_destruct_generic,
	FLOW_TYPE_IO, FLOW_ATTR_READ, "read", flowoplib_init_generic,
	flowoplib_read, flowoplib_destruct_generic,
#ifdef HAVE_AIO
	FLOW_TYPE_AIO, FLOW_ATTR_WRITE, "aiowrite", flowoplib_init_generic,
	flowoplib_aiowrite, flowoplib_destruct_generic,
	FLOW_TYPE_AIO, 0, "aiowait", flowoplib_init_generic,
	flowoplib_aiowait, flowoplib_destruct_generic,
#endif
	FLOW_TYPE_SYNC, 0, "block", flowoplib_block_init,
	flowoplib_block, flowoplib_destruct_generic,
	FLOW_TYPE_SYNC, 0, "wakeup", flowoplib_init_generic,
	flowoplib_wakeup, flowoplib_destruct_generic,
	FLOW_TYPE_SYNC, 0, "semblock", flowoplib_semblock_init,
	flowoplib_semblock, flowoplib_semblock_destruct,
	FLOW_TYPE_SYNC, 0, "sempost", flowoplib_sempost_init,
	flowoplib_sempost, flowoplib_destruct_noop,
	FLOW_TYPE_OTHER, 0, "hog", flowoplib_init_generic,
	flowoplib_hog, flowoplib_destruct_generic,
	FLOW_TYPE_OTHER, 0, "delay", flowoplib_init_generic,
	flowoplib_delay, flowoplib_destruct_generic,
	FLOW_TYPE_OTHER, 0, "eventlimit", flowoplib_init_generic,
	flowoplib_eventlimit, flowoplib_destruct_generic,
	FLOW_TYPE_OTHER, 0, "bwlimit", flowoplib_init_generic,
	flowoplib_bwlimit, flowoplib_destruct_generic,
	FLOW_TYPE_OTHER, 0, "iopslimit", flowoplib_init_generic,
	flowoplib_iopslimit, flowoplib_destruct_generic,
	FLOW_TYPE_OTHER, 0, "opslimit", flowoplib_init_generic,
	flowoplib_opslimit, flowoplib_destruct_generic,
	FLOW_TYPE_OTHER, 0, "finishoncount", flowoplib_init_generic,
	flowoplib_finishoncount, flowoplib_destruct_generic,
	FLOW_TYPE_OTHER, 0, "finishonbytes", flowoplib_init_generic,
	flowoplib_finishonbytes, flowoplib_destruct_generic,
	FLOW_TYPE_IO, 0, "openfile", flowoplib_init_generic,
	flowoplib_openfile, flowoplib_destruct_generic,
	FLOW_TYPE_IO, 0, "createfile", flowoplib_init_generic,
	flowoplib_createfile, flowoplib_destruct_generic,
	FLOW_TYPE_IO, 0, "closefile", flowoplib_init_generic,
	flowoplib_closefile, flowoplib_destruct_generic,
	FLOW_TYPE_IO, 0, "makedir", flowoplib_init_generic,
	flowoplib_makedir, flowoplib_destruct_generic,
	FLOW_TYPE_IO, 0, "removedir", flowoplib_init_generic,
	flowoplib_removedir, flowoplib_destruct_generic,
	FLOW_TYPE_IO, 0, "listdir", flowoplib_init_generic,
	flowoplib_listdir, flowoplib_destruct_generic,
	FLOW_TYPE_IO, 0, "fsync", flowoplib_init_generic,
	flowoplib_fsync, flowoplib_destruct_generic,
	FLOW_TYPE_IO, 0, "fsyncset", flowoplib_init_generic,
	flowoplib_fsyncset, flowoplib_destruct_generic,
	FLOW_TYPE_IO, 0, "statfile", flowoplib_init_generic,
	flowoplib_statfile, flowoplib_destruct_generic,
	FLOW_TYPE_IO, FLOW_ATTR_READ, "readwholefile", flowoplib_init_generic,
	flowoplib_readwholefile, flowoplib_destruct_generic,
	FLOW_TYPE_IO, FLOW_ATTR_WRITE, "appendfile", flowoplib_init_generic,
	flowoplib_appendfile, flowoplib_destruct_generic,
	FLOW_TYPE_IO, FLOW_ATTR_WRITE, "appendfilerand", flowoplib_init_generic,
	flowoplib_appendfilerand, flowoplib_destruct_generic,
	FLOW_TYPE_IO, 0, "deletefile", flowoplib_init_generic,
	flowoplib_deletefile, flowoplib_destruct_generic,
	FLOW_TYPE_IO, FLOW_ATTR_WRITE, "writewholefile", flowoplib_init_generic,
	flowoplib_writewholefile, flowoplib_destruct_generic,
	FLOW_TYPE_OTHER, 0, "print", flowoplib_init_generic,
	flowoplib_print, flowoplib_destruct_generic,
	/* routine to calculate mean and stddev for output from a randvar */
	FLOW_TYPE_OTHER, 0, "testrandvar", flowoplib_testrandvar_init,
	flowoplib_testrandvar, flowoplib_testrandvar_destruct
};

/*
 * Loops through the master list of flowops defined in this
 * module, and creates and initializes a flowop for each one
 * by calling flowop_define. As a side effect of calling
 * flowop define, the created flowops are placed on the
 * master flowop list. All created flowops are set to
 * instance "0".
 */
void
flowoplib_init()
{
	int nops = sizeof (flowoplib_funcs) / sizeof (flowoplib_t);
	int i;

	for (i = 0; i < nops; i++) {
		flowop_t *flowop;
		flowoplib_t *fl;

		fl = &flowoplib_funcs[i];

		if ((flowop = flowop_define(NULL,
		    fl->fl_name, NULL, NULL, 0, fl->fl_type)) == 0) {
			filebench_log(LOG_ERROR,
			    "failed to create flowop %s\n",
			    fl->fl_name);
			filebench_shutdown(1);
		}

		flowop->fo_func = fl->fl_func;
		flowop->fo_init = fl->fl_init;
		flowop->fo_destruct = fl->fl_destruct;
		flowop->fo_attrs = fl->fl_attrs;
	}
}

static int
flowoplib_init_generic(flowop_t *flowop)
{
	(void) ipc_mutex_unlock(&flowop->fo_lock);
	return (FILEBENCH_OK);
}

static void
flowoplib_destruct_generic(flowop_t *flowop)
{
	char *buf;

	/* release any local resources held by the flowop */
	(void) ipc_mutex_lock(&flowop->fo_lock);
	buf = flowop->fo_buf;
	flowop->fo_buf = NULL;
	(void) ipc_mutex_unlock(&flowop->fo_lock);

	if (buf)
		free(buf);
}

/*
 * Special total noop destruct
 */
/* ARGSUSED */
static void
flowoplib_destruct_noop(flowop_t *flowop)
{
}

/*
 * Generates a file attribute from flags in the supplied flowop.
 * Sets FLOW_ATTR_DIRECTIO and/or FLOW_ATTR_DSYNC as needed.
 */
static int
flowoplib_fileattrs(flowop_t *flowop)
{
	int attrs = 0;

	if (avd_get_bool(flowop->fo_directio))
		attrs |= FLOW_ATTR_DIRECTIO;

	if (avd_get_bool(flowop->fo_dsync))
		attrs |= FLOW_ATTR_DSYNC;

	return (attrs);
}

/*
 * Obtain a filesetentry for a file. Result placed where filep points.
 * Supply with a flowop and a flag to indicate whether an existent or
 * non-existent file is required. Returns FILEBENCH_NORSC if all out
 * of the appropriate type of directories, FILEBENCH_ERROR if the
 * flowop does not point to a fileset, and FILEBENCH_OK otherwise.
 */
static int
flowoplib_pickfile(filesetentry_t **filep, flowop_t *flowop, int flags, int tid)
{
	fileset_t	*fileset;
	int		fileindex;

	if ((fileset = flowop->fo_fileset) == NULL) {
		filebench_log(LOG_ERROR, "flowop NO fileset");
		return (FILEBENCH_ERROR);
	}

	if (flowop->fo_fileindex) {
		fileindex = (int)(avd_get_dbl(flowop->fo_fileindex) *
		    ((double)(fileset->fs_constentries / 2)));
		fileindex = fileindex % fileset->fs_constentries;
		flags |= FILESET_PICKBYINDEX;
	} else {
		fileindex = 0;
	}

	if ((*filep = fileset_pick(fileset, FILESET_PICKFILE | flags,
	    tid, fileindex)) == NULL) {
		filebench_log(LOG_DEBUG_SCRIPT,
		    "flowop %s failed to pick file from fileset %s",
		    flowop->fo_name,
		    avd_get_str(fileset->fs_name));
		return (FILEBENCH_NORSC);
	}

	return (FILEBENCH_OK);
}

/*
 * Obtain a filesetentry for a leaf directory. Result placed where dirp
 * points. Supply with flowop and a flag to indicate whether an existent
 * or non-existent leaf directory is required. Returns FILEBENCH_NORSC
 * if all out of the appropriate type of directories, FILEBENCH_ERROR
 * if the flowop does not point to a fileset, and FILEBENCH_OK otherwise.
 */
static int
flowoplib_pickleafdir(filesetentry_t **dirp, flowop_t *flowop, int flags)
{
	fileset_t	*fileset;
	int		dirindex;

	if ((fileset = flowop->fo_fileset) == NULL) {
		filebench_log(LOG_ERROR, "flowop NO fileset");
		return (FILEBENCH_ERROR);
	}

	if (flowop->fo_fileindex) {
		dirindex = (int)(avd_get_dbl(flowop->fo_fileindex) *
		    ((double)(fileset->fs_constleafdirs / 2)));
		dirindex = dirindex % fileset->fs_constleafdirs;
		flags |= FILESET_PICKBYINDEX;
	} else {
		dirindex = 0;
	}

	if ((*dirp = fileset_pick(fileset,
	    FILESET_PICKLEAFDIR | flags, 0, dirindex)) == NULL) {
		filebench_log(LOG_DEBUG_SCRIPT,
		    "flowop %s failed to pick directory from fileset %s",
		    flowop->fo_name,
		    avd_get_str(fileset->fs_name));
		return (FILEBENCH_NORSC);
	}

	return (FILEBENCH_OK);
}

/*
 * Searches for a file descriptor. Tries the flowop's
 * fo_fdnumber first and returns with it if it has been
 * explicitly set (greater than 0). It next checks to
 * see if a rotating file descriptor policy is in effect,
 * and if not returns the fdnumber regardless of what
 * it is. (note that if it is 0, it just selects to the
 * default file descriptor in the threadflow's tf_fd
 * array). If the rotating fd policy is in effect, it
 * cycles from the end of the tf_fd array to one location
 * beyond the maximum needed by the number of entries in
 * the associated fileset on each invocation, then starts
 * over from the end.
 *
 * The routine returns an index into the threadflow's
 * tf_fd table where the actual file descriptor will be
 * found. Note: the calling routine must not call this
 * routine if the flowop does not have a fileset, and the
 * flowop's fo_fdnumber is zero and fo_rotatefd is
 * asserted, or an addressing fault may occur.
 */
static int
flowoplib_fdnum(threadflow_t *threadflow, flowop_t *flowop)
{
	fbint_t	entries;
	int fdnumber = flowop->fo_fdnumber;

	/* If the script sets the fd explicitly */
	if (fdnumber > 0)
		return (fdnumber);

	/* If the flowop defaults to persistent fd */
	if (!avd_get_bool(flowop->fo_rotatefd))
		return (fdnumber);

	if (flowop->fo_fileset == NULL) {
		filebench_log(LOG_ERROR, "flowop NULL file");
		return (FILEBENCH_ERROR);
	}

	entries = flowop->fo_fileset->fs_constentries;

	/* Rotate the fd on each flowop invocation */
	if (entries > (THREADFLOW_MAXFD / 2)) {
		filebench_log(LOG_ERROR, "Out of file descriptors in flowop %s"
		    " (too many files : %llu",
		    flowop->fo_name, (u_longlong_t)entries);
		return (FILEBENCH_ERROR);
	}

	/* First time around */
	if (threadflow->tf_fdrotor == 0)
		threadflow->tf_fdrotor = THREADFLOW_MAXFD;

	/* One fd for every file in the set */
	if (entries == (THREADFLOW_MAXFD - threadflow->tf_fdrotor))
		threadflow->tf_fdrotor = THREADFLOW_MAXFD;


	threadflow->tf_fdrotor--;
	filebench_log(LOG_DEBUG_IMPL, "selected fd = %d",
	    threadflow->tf_fdrotor);
	return (threadflow->tf_fdrotor);
}

/*
 * Determines the file descriptor to use, and attempts to open
 * the file if it is not already open. Also determines the wss
 * value. Returns FILEBENCH_ERROR on errors, FILESET_NORSC if
 * if flowop_openfile_common couldn't obtain an appropriate file
 * from a the fileset, and FILEBENCH_OK otherwise.
 */
static int
flowoplib_filesetup(threadflow_t *threadflow, flowop_t *flowop,
    fbint_t *wssp, int *filedescp)
{
	int fd = flowoplib_fdnum(threadflow, flowop);

	if (fd == -1)
		return (FILEBENCH_ERROR);

	if (threadflow->tf_fd[fd] == 0) {
		int ret;

		if ((ret = flowoplib_openfile_common(
		    threadflow, flowop, fd)) != FILEBENCH_OK)
			return (ret);

		if (threadflow->tf_fse[fd]) {
			filebench_log(LOG_DEBUG_IMPL, "opened file %s",
			    threadflow->tf_fse[fd]->fse_path);
		} else {
			filebench_log(LOG_DEBUG_IMPL,
			    "opened device %s/%s",
			    avd_get_str(flowop->fo_fileset->fs_path),
			    avd_get_str(flowop->fo_fileset->fs_name));
		}
	}

	*filedescp = threadflow->tf_fd[fd];

	if ((*wssp = flowop->fo_constwss) == 0) {
		if (threadflow->tf_fse[fd])
			*wssp = threadflow->tf_fse[fd]->fse_size;
		else
			*wssp = avd_get_int(flowop->fo_fileset->fs_size);
	}

	return (FILEBENCH_OK);
}

/*
 * Determines the io buffer or random offset into tf_mem for
 * the IO operation. Returns FILEBENCH_ERROR on errors, FILEBENCH_OK otherwise.
 */
static int
flowoplib_iobufsetup(threadflow_t *threadflow, flowop_t *flowop,
    caddr_t *iobufp, fbint_t iosize)
{
	long memsize;
	size_t memoffset;

	if (iosize == 0) {
		filebench_log(LOG_ERROR, "zero iosize for thread %s",
		    flowop->fo_name);
		return (FILEBENCH_ERROR);
	}

	if ((memsize = threadflow->tf_constmemsize) != 0) {

		/* use tf_mem for I/O with random offset */
		if (filebench_randomno(&memoffset,
		    memsize, iosize, NULL) == -1) {
			filebench_log(LOG_ERROR,
			    "tf_memsize smaller than IO size for thread %s",
			    flowop->fo_name);
			return (FILEBENCH_ERROR);
		}
		*iobufp = threadflow->tf_mem + memoffset;

	} else {
		/* use private I/O buffer */
		if ((flowop->fo_buf != NULL) &&
		    (flowop->fo_buf_size < iosize)) {
			/* too small, so free up and re-allocate */
			free(flowop->fo_buf);
			flowop->fo_buf = NULL;
		}

		/*
		 * Allocate memory for the  buffer. The memory is freed
		 * by flowop_destruct_generic() or by this routine if more
		 * memory is needed for the buffer.
		 */
		if ((flowop->fo_buf == NULL) && ((flowop->fo_buf
		    = (char *)malloc(iosize)) == NULL))
			return (FILEBENCH_ERROR);

		flowop->fo_buf_size = iosize;
		*iobufp = flowop->fo_buf;
	}
	return (FILEBENCH_OK);
}

/*
 * Determines the file descriptor to use, opens it if necessary, the
 * io buffer or random offset into tf_mem for IO operation and the wss
 * value. Returns FILEBENCH_ERROR on errors, FILEBENCH_OK otherwise.
 */
static int
flowoplib_iosetup(threadflow_t *threadflow, flowop_t *flowop,
    fbint_t *wssp, caddr_t *iobufp, int *filedescp, fbint_t iosize)
{
	int ret;

	if ((ret = flowoplib_filesetup(threadflow, flowop, wssp, filedescp)) !=
	    FILEBENCH_OK)
		return (ret);

	if ((ret = flowoplib_iobufsetup(threadflow, flowop, iobufp, iosize)) !=
	    FILEBENCH_OK)
		return (ret);

	return (FILEBENCH_OK);
}

/*
 * Emulate posix read / pread. If the flowop has a fileset,
 * a file descriptor number index is fetched, otherwise a
 * supplied fileobj file is used. In either case the specified
 * file will be opened if not already open. If the flowop has
 * neither a fileset or fileobj, an error is logged and FILEBENCH_ERROR
 * returned.
 *
 * The actual read is done to a random offset in the
 * threadflow's thread memory (tf_mem), with a size set by
 * fo_iosize and at either a random disk offset within the
 * working set size, or at the next sequential location. If
 * any errors are encountered, FILEBENCH_ERROR is returned,
 * if no appropriate file can be obtained from the fileset then
 * FILEBENCH_NORSC is returned, otherise FILEBENCH_OK is returned.
 */
static int
flowoplib_read(threadflow_t *threadflow, flowop_t *flowop)
{
	caddr_t iobuf;
	fbint_t wss;
	fbint_t iosize;
	int filedesc;
	int ret;


	iosize = avd_get_int(flowop->fo_iosize);
	if ((ret = flowoplib_iosetup(threadflow, flowop, &wss, &iobuf,
	    &filedesc, iosize)) != FILEBENCH_OK)
		return (ret);

	if (avd_get_bool(flowop->fo_random)) {
		uint64_t fileoffset;

		if (filebench_randomno64(&fileoffset,
		    wss, iosize, NULL) == -1) {
			filebench_log(LOG_ERROR,
			    "file size smaller than IO size for thread %s",
			    flowop->fo_name);
			return (FILEBENCH_ERROR);
		}

		(void) flowop_beginop(threadflow, flowop);
		if ((ret = pread64(filedesc, iobuf,
		    iosize, (off64_t)fileoffset)) == -1) {
			(void) flowop_endop(threadflow, flowop, 0);
			filebench_log(LOG_ERROR,
			    "read file %s failed, offset %llu "
			    "io buffer %zd: %s",
			    avd_get_str(flowop->fo_fileset->fs_name),
			    (u_longlong_t)fileoffset, iobuf, strerror(errno));
			flowop_endop(threadflow, flowop, 0);
			return (FILEBENCH_ERROR);
		}
		(void) flowop_endop(threadflow, flowop, ret);

		if ((ret == 0))
			(void) lseek64(filedesc, 0, SEEK_SET);

	} else {
		(void) flowop_beginop(threadflow, flowop);
		if ((ret = read(filedesc, iobuf, iosize)) == -1) {
			(void) flowop_endop(threadflow, flowop, 0);
			filebench_log(LOG_ERROR,
			    "read file %s failed, io buffer %zd: %s",
			    avd_get_str(flowop->fo_fileset->fs_name),
			    iobuf, strerror(errno));
			(void) flowop_endop(threadflow, flowop, 0);
			return (FILEBENCH_ERROR);
		}
		(void) flowop_endop(threadflow, flowop, ret);

		if ((ret == 0))
			(void) lseek64(filedesc, 0, SEEK_SET);
	}

	return (FILEBENCH_OK);
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
flowoplib_aiowrite(threadflow_t *threadflow, flowop_t *flowop)
{
	caddr_t iobuf;
	fbint_t wss;
	fbint_t iosize;
	int filedesc;
	int ret;

	iosize = avd_get_int(flowop->fo_iosize);

	if ((ret = flowoplib_iosetup(threadflow, flowop, &wss, &iobuf,
	    &filedesc, iosize)) != FILEBENCH_OK)
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

		aiocb->aio_fildes = filedesc;
		aiocb->aio_buf = iobuf;
		aiocb->aio_nbytes = (size_t)iosize;
		aiocb->aio_offset = (off64_t)fileoffset;
		aiocb->aio_reqprio = 0;

		filebench_log(LOG_DEBUG_IMPL,
		    "aio fd=%d, bytes=%llu, offset=%llu",
		    filedesc, (u_longlong_t)iosize, (u_longlong_t)fileoffset);

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
flowoplib_aiowait(threadflow_t *threadflow, flowop_t *flowop)
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

#ifdef HAVE_AIOWAITN
		if ((aio_waitn64((struct aiocb64 **)worklist,
		    MAXREAP, &todo, &timeout) == -1) &&
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
			if (aio_deallocate(flowop, worklist[i]) < 0) {
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
				filebench_log(LOG_ERROR, "Could not remove aio "
				    "from list ");
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
 * Initializes a "flowop_block" flowop. Specifically, it
 * initializes the flowop's fo_cv and unlocks the fo_lock.
 */
static int
flowoplib_block_init(flowop_t *flowop)
{
	filebench_log(LOG_DEBUG_IMPL, "flow %s-%d block init address %zx",
	    flowop->fo_name, flowop->fo_instance, &flowop->fo_cv);
	(void) pthread_cond_init(&flowop->fo_cv, ipc_condattr());
	(void) ipc_mutex_unlock(&flowop->fo_lock);

	return (FILEBENCH_OK);
}

/*
 * Blocks the threadflow until woken up by flowoplib_wakeup.
 * The routine blocks on the flowop's fo_cv condition variable.
 */
static int
flowoplib_block(threadflow_t *threadflow, flowop_t *flowop)
{
	filebench_log(LOG_DEBUG_IMPL, "flow %s-%d blocking at address %zx",
	    flowop->fo_name, flowop->fo_instance, &flowop->fo_cv);
	(void) ipc_mutex_lock(&flowop->fo_lock);

	flowop_beginop(threadflow, flowop);
	(void) pthread_cond_wait(&flowop->fo_cv, &flowop->fo_lock);
	flowop_endop(threadflow, flowop, 0);

	filebench_log(LOG_DEBUG_IMPL, "flow %s-%d unblocking",
	    flowop->fo_name, flowop->fo_instance);

	(void) ipc_mutex_unlock(&flowop->fo_lock);

	return (FILEBENCH_OK);
}

/*
 * Wakes up one or more target blocking flowops.
 * Sends broadcasts on the fo_cv condition variables of all
 * flowops on the target list, except those that are
 * FLOW_MASTER flowops. The target list consists of all
 * flowops whose name matches this flowop's "fo_targetname"
 * attribute. The target list is generated on the first
 * invocation, and the run will be shutdown if no targets
 * are found. Otherwise the routine always returns FILEBENCH_OK.
 */
static int
flowoplib_wakeup(threadflow_t *threadflow, flowop_t *flowop)
{
	flowop_t *target;

	/* if this is the first wakeup, create the wakeup list */
	if (flowop->fo_targets == NULL) {
		flowop_t *result = flowop_find(flowop->fo_targetname);

		flowop->fo_targets = result;
		if (result == NULL) {
			filebench_log(LOG_ERROR,
			    "wakeup: could not find op %s for thread %s",
			    flowop->fo_targetname,
			    threadflow->tf_name);
			filebench_shutdown(1);
		}
		while (result) {
			result->fo_targetnext =
			    result->fo_resultnext;
			result = result->fo_resultnext;
		}
	}

	target = flowop->fo_targets;

	/* wakeup the targets */
	while (target) {
		if (target->fo_instance == FLOW_MASTER) {
			target = target->fo_targetnext;
			continue;
		}
		filebench_log(LOG_DEBUG_IMPL,
		    "wakeup flow %s-%d at address %zx",
		    target->fo_name,
		    target->fo_instance,
		    &target->fo_cv);

		flowop_beginop(threadflow, flowop);
		(void) ipc_mutex_lock(&target->fo_lock);
		(void) pthread_cond_broadcast(&target->fo_cv);
		(void) ipc_mutex_unlock(&target->fo_lock);
		flowop_endop(threadflow, flowop, 0);

		target = target->fo_targetnext;
	}

	return (FILEBENCH_OK);
}

/*
 * "think time" routines. the "hog" routine consumes cpu cycles as
 * it "thinks", while the "delay" flowop simply calls sleep() to delay
 * for a given number of seconds without consuming cpu cycles.
 */


/*
 * Consumes CPU cycles and memory bandwidth by looping for
 * flowop->fo_value times. With each loop sets memory location
 * threadflow->tf_mem to 1.
 */
static int
flowoplib_hog(threadflow_t *threadflow, flowop_t *flowop)
{
	uint64_t value = avd_get_int(flowop->fo_value);
	int i;

	filebench_log(LOG_DEBUG_IMPL, "hog enter");
	flowop_beginop(threadflow, flowop);
	if (threadflow->tf_mem != NULL) {
		for (i = 0; i < value; i++)
			*(threadflow->tf_mem) = 1;
	}
	flowop_endop(threadflow, flowop, 0);
	filebench_log(LOG_DEBUG_IMPL, "hog exit");
	return (FILEBENCH_OK);
}


/*
 * Delays for fo_value seconds.
 */
static int
flowoplib_delay(threadflow_t *threadflow, flowop_t *flowop)
{
	int value = avd_get_int(flowop->fo_value);

	flowop_beginop(threadflow, flowop);
	(void) sleep(value);
	flowop_endop(threadflow, flowop, 0);
	return (FILEBENCH_OK);
}

/*
 * Rate limiting routines. This is the event consuming half of the
 * event system. Each of the four following routines will limit the rate
 * to one unit of either calls, issued I/O operations, issued filebench
 * operations, or I/O bandwidth. Since there is only one event generator,
 * the events will be divided amoung multiple instances of an event
 * consumer, and further divided among different consumers if more than
 * one has been defined. There is no mechanism to enforce equal sharing
 * of events.
 */

/*
 * Completes one invocation per posted event. If eventgen_q
 * has an event count greater than zero, one will be removed
 * (count decremented), otherwise the calling thread will
 * block until another event has been posted. Always returns 0
 */
static int
flowoplib_eventlimit(threadflow_t *threadflow, flowop_t *flowop)
{
	/* Immediately bail if not set/enabled */
	if (filebench_shm->shm_eventgen_hz == NULL)
		return (FILEBENCH_OK);

	if (flowop->fo_initted == 0) {
		filebench_log(LOG_DEBUG_IMPL, "rate %zx %s-%d locking",
		    flowop, threadflow->tf_name, threadflow->tf_instance);
		flowop->fo_initted = 1;
	}

	flowop_beginop(threadflow, flowop);
	while (filebench_shm->shm_eventgen_hz != NULL) {
		(void) ipc_mutex_lock(&filebench_shm->shm_eventgen_lock);
		if (filebench_shm->shm_eventgen_q > 0) {
			filebench_shm->shm_eventgen_q--;
			(void) ipc_mutex_unlock(
			    &filebench_shm->shm_eventgen_lock);
			break;
		}
		(void) pthread_cond_wait(&filebench_shm->shm_eventgen_cv,
		    &filebench_shm->shm_eventgen_lock);
		(void) ipc_mutex_unlock(&filebench_shm->shm_eventgen_lock);
	}
	flowop_endop(threadflow, flowop, 0);
	return (FILEBENCH_OK);
}

static int
flowoplib_event_find_target(threadflow_t *threadflow, flowop_t *flowop)
{
	if (flowop->fo_targetname[0] != '\0') {

		/* Try to use statistics from specific flowop */
		flowop->fo_targets =
		    flowop_find_from_list(flowop->fo_targetname,
		    threadflow->tf_thrd_fops);
		if (flowop->fo_targets == NULL) {
			filebench_log(LOG_ERROR,
			    "limit target: could not find flowop %s",
			    flowop->fo_targetname);
			filebench_shutdown(1);
			return (FILEBENCH_ERROR);
		}
	} else {
		/* use total workload statistics */
		flowop->fo_targets = NULL;
	}
	return (FILEBENCH_OK);
}

/*
 * Blocks the calling thread if the number of issued I/O
 * operations exceeds the number of posted events, thus
 * limiting the average I/O operation rate to the rate
 * specified by eventgen_hz. Always returns FILEBENCH_OK.
 */
static int
flowoplib_iopslimit(threadflow_t *threadflow, flowop_t *flowop)
{
	uint64_t iops;
	uint64_t delta;
	uint64_t events;

	/* Immediately bail if not set/enabled */
	if (filebench_shm->shm_eventgen_hz == NULL)
		return (FILEBENCH_OK);

	if (flowop->fo_initted == 0) {
		filebench_log(LOG_DEBUG_IMPL, "rate %zx %s-%d locking",
		    flowop, threadflow->tf_name, threadflow->tf_instance);
		flowop->fo_initted = 1;

		if (flowoplib_event_find_target(threadflow, flowop)
		    == FILEBENCH_ERROR)
			return (FILEBENCH_ERROR);

		if (flowop->fo_targets && ((flowop->fo_targets->fo_attrs &
		    (FLOW_ATTR_READ | FLOW_ATTR_WRITE)) == 0)) {
			filebench_log(LOG_ERROR,
			    "WARNING: Flowop %s does no IO",
			    flowop->fo_targets->fo_name);
			filebench_shutdown(1);
			return (FILEBENCH_ERROR);
		}
	}

	if (flowop->fo_targets) {
		/*
		 * Note that fs_count is already the sum of fs_rcount
		 * and fs_wcount if looking at a single flowop.
		 */
		iops = flowop->fo_targets->fo_stats.fs_count;
	} else {
		(void) ipc_mutex_lock(&controlstats_lock);
		iops = (controlstats.fs_rcount +
		    controlstats.fs_wcount);
		(void) ipc_mutex_unlock(&controlstats_lock);
	}

	/* Is this the first time around */
	if (flowop->fo_tputlast == 0) {
		flowop->fo_tputlast = iops;
		return (FILEBENCH_OK);
	}

	delta = iops - flowop->fo_tputlast;
	flowop->fo_tputbucket -= delta;
	flowop->fo_tputlast = iops;

	/* No need to block if the q isn't empty */
	if (flowop->fo_tputbucket >= 0LL) {
		flowop_endop(threadflow, flowop, 0);
		return (FILEBENCH_OK);
	}

	iops = flowop->fo_tputbucket * -1;
	events = iops;

	flowop_beginop(threadflow, flowop);
	while (filebench_shm->shm_eventgen_hz != NULL) {

		(void) ipc_mutex_lock(&filebench_shm->shm_eventgen_lock);
		if (filebench_shm->shm_eventgen_q >= events) {
			filebench_shm->shm_eventgen_q -= events;
			(void) ipc_mutex_unlock(
			    &filebench_shm->shm_eventgen_lock);
			flowop->fo_tputbucket += events;
			break;
		}
		(void) pthread_cond_wait(&filebench_shm->shm_eventgen_cv,
		    &filebench_shm->shm_eventgen_lock);
		(void) ipc_mutex_unlock(&filebench_shm->shm_eventgen_lock);
	}
	flowop_endop(threadflow, flowop, 0);

	return (FILEBENCH_OK);
}

/*
 * Blocks the calling thread if the number of issued filebench
 * operations exceeds the number of posted events, thus limiting
 * the average filebench operation rate to the rate specified by
 * eventgen_hz. Always returns FILEBENCH_OK.
 */
static int
flowoplib_opslimit(threadflow_t *threadflow, flowop_t *flowop)
{
	uint64_t ops;
	uint64_t delta;
	uint64_t events;

	/* Immediately bail if not set/enabled */
	if (filebench_shm->shm_eventgen_hz == NULL)
		return (FILEBENCH_OK);

	if (flowop->fo_initted == 0) {
		filebench_log(LOG_DEBUG_IMPL, "rate %zx %s-%d locking",
		    flowop, threadflow->tf_name, threadflow->tf_instance);
		flowop->fo_initted = 1;

		if (flowoplib_event_find_target(threadflow, flowop)
		    == FILEBENCH_ERROR)
			return (FILEBENCH_ERROR);
	}

	if (flowop->fo_targets) {
		ops = flowop->fo_targets->fo_stats.fs_count;
	} else {
		(void) ipc_mutex_lock(&controlstats_lock);
		ops = controlstats.fs_count;
		(void) ipc_mutex_unlock(&controlstats_lock);
	}

	/* Is this the first time around */
	if (flowop->fo_tputlast == 0) {
		flowop->fo_tputlast = ops;
		return (FILEBENCH_OK);
	}

	delta = ops - flowop->fo_tputlast;
	flowop->fo_tputbucket -= delta;
	flowop->fo_tputlast = ops;

	/* No need to block if the q isn't empty */
	if (flowop->fo_tputbucket >= 0LL) {
		flowop_endop(threadflow, flowop, 0);
		return (FILEBENCH_OK);
	}

	ops = flowop->fo_tputbucket * -1;
	events = ops;

	flowop_beginop(threadflow, flowop);
	while (filebench_shm->shm_eventgen_hz != NULL) {
		(void) ipc_mutex_lock(&filebench_shm->shm_eventgen_lock);
		if (filebench_shm->shm_eventgen_q >= events) {
			filebench_shm->shm_eventgen_q -= events;
			(void) ipc_mutex_unlock(
			    &filebench_shm->shm_eventgen_lock);
			flowop->fo_tputbucket += events;
			break;
		}
		(void) pthread_cond_wait(&filebench_shm->shm_eventgen_cv,
		    &filebench_shm->shm_eventgen_lock);
		(void) ipc_mutex_unlock(&filebench_shm->shm_eventgen_lock);
	}
	flowop_endop(threadflow, flowop, 0);

	return (FILEBENCH_OK);
}


/*
 * Blocks the calling thread if the number of bytes of I/O
 * issued exceeds one megabyte times the number of posted
 * events, thus limiting the average I/O byte rate to one
 * megabyte times the event rate as set by eventgen_hz.
 * Always retuns FILEBENCH_OK.
 */
static int
flowoplib_bwlimit(threadflow_t *threadflow, flowop_t *flowop)
{
	uint64_t bytes;
	uint64_t delta;
	uint64_t events;

	/* Immediately bail if not set/enabled */
	if (filebench_shm->shm_eventgen_hz == NULL)
		return (FILEBENCH_OK);

	if (flowop->fo_initted == 0) {
		filebench_log(LOG_DEBUG_IMPL, "rate %zx %s-%d locking",
		    flowop, threadflow->tf_name, threadflow->tf_instance);
		flowop->fo_initted = 1;

		if (flowoplib_event_find_target(threadflow, flowop)
		    == FILEBENCH_ERROR)
			return (FILEBENCH_ERROR);

		if ((flowop->fo_targets) &&
		    ((flowop->fo_targets->fo_attrs &
		    (FLOW_ATTR_READ | FLOW_ATTR_WRITE)) == 0)) {
			filebench_log(LOG_ERROR,
			    "WARNING: Flowop %s does no Reads or Writes",
			    flowop->fo_targets->fo_name);
			filebench_shutdown(1);
			return (FILEBENCH_ERROR);
		}
	}

	if (flowop->fo_targets) {
		/*
		 * Note that fs_bytes is already the sum of fs_rbytes
		 * and fs_wbytes if looking at a single flowop.
		 */
		bytes = flowop->fo_targets->fo_stats.fs_bytes;
	} else {
		(void) ipc_mutex_lock(&controlstats_lock);
		bytes = (controlstats.fs_rbytes +
		    controlstats.fs_wbytes);
		(void) ipc_mutex_unlock(&controlstats_lock);
	}

	/* Is this the first time around? */
	if (flowop->fo_tputlast == 0) {
		flowop->fo_tputlast = bytes;
		return (FILEBENCH_OK);
	}

	delta = bytes - flowop->fo_tputlast;
	flowop->fo_tputbucket -= delta;
	flowop->fo_tputlast = bytes;

	/* No need to block if the q isn't empty */
	if (flowop->fo_tputbucket >= 0LL) {
		flowop_endop(threadflow, flowop, 0);
		return (FILEBENCH_OK);
	}

	bytes = flowop->fo_tputbucket * -1;
	events = (bytes / MB) + 1;

	filebench_log(LOG_DEBUG_IMPL, "%llu bytes, %llu events",
	    (u_longlong_t)bytes, (u_longlong_t)events);

	flowop_beginop(threadflow, flowop);
	while (filebench_shm->shm_eventgen_hz != NULL) {
		(void) ipc_mutex_lock(&filebench_shm->shm_eventgen_lock);
		if (filebench_shm->shm_eventgen_q >= events) {
			filebench_shm->shm_eventgen_q -= events;
			(void) ipc_mutex_unlock(
			    &filebench_shm->shm_eventgen_lock);
			flowop->fo_tputbucket += (events * MB);
			break;
		}
		(void) pthread_cond_wait(&filebench_shm->shm_eventgen_cv,
		    &filebench_shm->shm_eventgen_lock);
		(void) ipc_mutex_unlock(&filebench_shm->shm_eventgen_lock);
	}
	flowop_endop(threadflow, flowop, 0);

	return (FILEBENCH_OK);
}

/*
 * These flowops terminate a benchmark run when either the specified
 * number of bytes of I/O (flowoplib_finishonbytes) or the specified
 * number of I/O operations (flowoplib_finishoncount) have been generated.
 */


/*
 * Stop filebench run when specified number of I/O bytes have been
 * transferred. Compares controlstats.fs_bytes with flowop->value,
 * and if greater returns 1, stopping the run, if not, returns 0
 * to continue running.
 */
static int
flowoplib_finishonbytes(threadflow_t *threadflow, flowop_t *flowop)
{
	uint64_t bytes_io;		/* Bytes of I/O delivered so far */
	uint64_t byte_lim = flowop->fo_constvalue;  /* Total Bytes desired */
						    /* Uses constant value */

	if (flowop->fo_initted == 0) {
		filebench_log(LOG_DEBUG_IMPL, "rate %zx %s-%d locking",
		    flowop, threadflow->tf_name, threadflow->tf_instance);
		flowop->fo_initted = 1;

		if (flowoplib_event_find_target(threadflow, flowop)
		    == FILEBENCH_ERROR)
			return (FILEBENCH_ERROR);

		if ((flowop->fo_targets) &&
		    ((flowop->fo_targets->fo_attrs &
		    (FLOW_ATTR_READ | FLOW_ATTR_WRITE)) == 0)) {
			filebench_log(LOG_ERROR,
			    "WARNING: Flowop %s does no Reads or Writes",
			    flowop->fo_targets->fo_name);
			filebench_shutdown(1);
			return (FILEBENCH_ERROR);
		}
	}

	if (flowop->fo_targets) {
		bytes_io = flowop->fo_targets->fo_stats.fs_bytes;
	} else {
		(void) ipc_mutex_lock(&controlstats_lock);
		bytes_io = controlstats.fs_bytes;
		(void) ipc_mutex_unlock(&controlstats_lock);
	}

	flowop_beginop(threadflow, flowop);
	if (bytes_io > byte_lim) {
		flowop_endop(threadflow, flowop, 0);
		return (FILEBENCH_DONE);
	}
	flowop_endop(threadflow, flowop, 0);

	return (FILEBENCH_OK);
}

/*
 * Stop filebench run when specified number of I/O operations have
 * been performed. Compares controlstats.fs_count with *flowop->value,
 * and if greater returns 1, stopping the run, if not, returns FILEBENCH_OK
 * to continue running.
 */
static int
flowoplib_finishoncount(threadflow_t *threadflow, flowop_t *flowop)
{
	uint64_t ops;
	uint64_t count = flowop->fo_constvalue; /* use constant value */

	if (flowop->fo_initted == 0) {
		filebench_log(LOG_DEBUG_IMPL, "rate %zx %s-%d locking",
		    flowop, threadflow->tf_name, threadflow->tf_instance);
		flowop->fo_initted = 1;

		if (flowoplib_event_find_target(threadflow, flowop)
		    == FILEBENCH_ERROR)
			return (FILEBENCH_ERROR);
	}

	if (flowop->fo_targets) {
		ops = flowop->fo_targets->fo_stats.fs_count;
	} else {
		(void) ipc_mutex_lock(&controlstats_lock);
		ops = controlstats.fs_count;
		(void) ipc_mutex_unlock(&controlstats_lock);
	}

	flowop_beginop(threadflow, flowop);
	if (ops >= count) {
		flowop_endop(threadflow, flowop, 0);
		return (FILEBENCH_DONE);
	}
	flowop_endop(threadflow, flowop, 0);

	return (FILEBENCH_OK);
}

/*
 * Semaphore synchronization using either System V semaphores or
 * posix semaphores. If System V semaphores are available, they will be
 * used, otherwise posix semaphores will be used.
 */


/*
 * Initializes the filebench "block on semaphore" flowop.
 * If System V semaphores are implemented, the routine
 * initializes the System V semaphore subsystem if it hasn't
 * already been initialized, also allocates a pair of semids
 * and initializes the highwater System V semaphore.
 * If no System V semaphores, then does nothing special.
 * Returns FILEBENCH_ERROR if it cannot acquire a set of System V semphores
 * or if the initial post to the semaphore set fails. Returns FILEBENCH_OK
 * on success.
 */
static int
flowoplib_semblock_init(flowop_t *flowop)
{

#ifdef HAVE_SYSV_SEM
	int sys_semid;
	struct sembuf sbuf[2];
	int highwater;

	ipc_seminit();

	flowop->fo_semid_lw = ipc_semidalloc();
	flowop->fo_semid_hw = ipc_semidalloc();

	filebench_log(LOG_DEBUG_IMPL, "flow %s-%d semblock init semid=%x",
	    flowop->fo_name, flowop->fo_instance, flowop->fo_semid_lw);

	sys_semid = filebench_shm->shm_sys_semid;

	if ((highwater = flowop->fo_semid_hw) == 0)
		highwater = flowop->fo_constvalue; /* use constant value */

	filebench_log(LOG_DEBUG_IMPL, "setting highwater to : %d", highwater);

	sbuf[0].sem_num = (short)highwater;
	sbuf[0].sem_op = avd_get_int(flowop->fo_highwater);
	sbuf[0].sem_flg = 0;
	if ((semop(sys_semid, &sbuf[0], 1) == -1) && errno) {
		filebench_log(LOG_ERROR, "semblock init post failed: %s (%d,"
		    "%d)", strerror(errno), sbuf[0].sem_num, sbuf[0].sem_op);
		return (FILEBENCH_ERROR);
	}
#else
	filebench_log(LOG_DEBUG_IMPL,
	    "flow %s-%d semblock init with posix semaphore",
	    flowop->fo_name, flowop->fo_instance);

	sem_init(&flowop->fo_sem, 1, 0);
#endif	/* HAVE_SYSV_SEM */

	if (!(avd_get_bool(flowop->fo_blocking)))
		(void) ipc_mutex_unlock(&flowop->fo_lock);

	return (FILEBENCH_OK);
}

/*
 * Releases the semids for the System V semaphore allocated
 * to this flowop. If not using System V semaphores, then
 * it is effectively just a no-op.
 */
static void
flowoplib_semblock_destruct(flowop_t *flowop)
{
#ifdef HAVE_SYSV_SEM
	ipc_semidfree(flowop->fo_semid_lw);
	ipc_semidfree(flowop->fo_semid_hw);
#else
	sem_destroy(&flowop->fo_sem);
#endif /* HAVE_SYSV_SEM */
}

/*
 * Attempts to pass a System V or posix semaphore as appropriate,
 * and blocks if necessary. Returns FILEBENCH_ERROR if a set of System V
 * semphores is not available or cannot be acquired, or if the initial
 * post to the semaphore set fails. Returns FILEBENCH_OK on success.
 */
static int
flowoplib_semblock(threadflow_t *threadflow, flowop_t *flowop)
{

#ifdef HAVE_SYSV_SEM
	struct sembuf sbuf[2];
	int value = avd_get_int(flowop->fo_value);
	int sys_semid;
	struct timespec timeout;

	sys_semid = filebench_shm->shm_sys_semid;

	filebench_log(LOG_DEBUG_IMPL,
	    "flow %s-%d sem blocking on id %x num %x value %d",
	    flowop->fo_name, flowop->fo_instance, sys_semid,
	    flowop->fo_semid_hw, value);

	/* Post, decrement the increment the hw queue */
	sbuf[0].sem_num = flowop->fo_semid_hw;
	sbuf[0].sem_op = (short)value;
	sbuf[0].sem_flg = 0;
	sbuf[1].sem_num = flowop->fo_semid_lw;
	sbuf[1].sem_op = value * -1;
	sbuf[1].sem_flg = 0;
	timeout.tv_sec = 600;
	timeout.tv_nsec = 0;

	if (avd_get_bool(flowop->fo_blocking))
		(void) ipc_mutex_unlock(&flowop->fo_lock);

	flowop_beginop(threadflow, flowop);

#ifdef HAVE_SEMTIMEDOP
	(void) semtimedop(sys_semid, &sbuf[0], 1, &timeout);
	(void) semtimedop(sys_semid, &sbuf[1], 1, &timeout);
#else
	(void) semop(sys_semid, &sbuf[0], 1);
	(void) semop(sys_semid, &sbuf[1], 1);
#endif /* HAVE_SEMTIMEDOP */

	if (avd_get_bool(flowop->fo_blocking))
		(void) ipc_mutex_lock(&flowop->fo_lock);

	flowop_endop(threadflow, flowop, 0);

#else
	int value = avd_get_int(flowop->fo_value);
	int i;

	filebench_log(LOG_DEBUG_IMPL,
	    "flow %s-%d sem blocking on posix semaphore",
	    flowop->fo_name, flowop->fo_instance);

	/* Decrement sem by value */
	for (i = 0; i < value; i++) {
		if (sem_wait(&flowop->fo_sem) == -1) {
			filebench_log(LOG_ERROR, "semop wait failed");
			return (FILEBENCH_ERROR);
		}
	}

	filebench_log(LOG_DEBUG_IMPL, "flow %s-%d sem unblocking",
	    flowop->fo_name, flowop->fo_instance);
#endif /* HAVE_SYSV_SEM */

	return (FILEBENCH_OK);
}

/*
 * Calls ipc_seminit(). Always returns FILEBENCH_OK.
 */
/* ARGSUSED */
static int
flowoplib_sempost_init(flowop_t *flowop)
{
#ifdef HAVE_SYSV_SEM
	ipc_seminit();
#endif /* HAVE_SYSV_SEM */
	return (FILEBENCH_OK);
}

/*
 * Post to a System V or posix semaphore as appropriate.
 * On the first call for a given flowop instance, this routine
 * will use the fo_targetname attribute to locate all semblock
 * flowops that are expecting posts from this flowop. All
 * target flowops on this list will have a post operation done
 * to their semaphores on each call.
 */
static int
flowoplib_sempost(threadflow_t *threadflow, flowop_t *flowop)
{
	flowop_t *target;

	filebench_log(LOG_DEBUG_IMPL,
	    "sempost flow %s-%d",
	    flowop->fo_name,
	    flowop->fo_instance);

	/* if this is the first post, create the post list */
	if (flowop->fo_targets == NULL) {
		flowop_t *result = flowop_find(flowop->fo_targetname);

		flowop->fo_targets = result;

		if (result == NULL) {
			filebench_log(LOG_ERROR,
			    "sempost: could not find op %s for thread %s",
			    flowop->fo_targetname,
			    threadflow->tf_name);
			filebench_shutdown(1);
		}

		while (result) {
			result->fo_targetnext =
			    result->fo_resultnext;
			result = result->fo_resultnext;
		}
	}

	target = flowop->fo_targets;

	flowop_beginop(threadflow, flowop);
	/* post to the targets */
	while (target) {
#ifdef HAVE_SYSV_SEM
		struct sembuf sbuf[2];
		int sys_semid;
		int blocking;
#else
		int i;
#endif /* HAVE_SYSV_SEM */
		struct timespec timeout;
		int value = (int)avd_get_int(flowop->fo_value);

		if (target->fo_instance == FLOW_MASTER) {
			target = target->fo_targetnext;
			continue;
		}

#ifdef HAVE_SYSV_SEM

		filebench_log(LOG_DEBUG_IMPL,
		    "sempost flow %s-%d num %x",
		    target->fo_name,
		    target->fo_instance,
		    target->fo_semid_lw);

		sys_semid = filebench_shm->shm_sys_semid;
		sbuf[0].sem_num = target->fo_semid_lw;
		sbuf[0].sem_op = (short)value;
		sbuf[0].sem_flg = 0;
		sbuf[1].sem_num = target->fo_semid_hw;
		sbuf[1].sem_op = value * -1;
		sbuf[1].sem_flg = 0;
		timeout.tv_sec = 600;
		timeout.tv_nsec = 0;

		if (avd_get_bool(flowop->fo_blocking))
			blocking = 1;
		else
			blocking = 0;

#ifdef HAVE_SEMTIMEDOP
		if ((semtimedop(sys_semid, &sbuf[0], blocking + 1,
		    &timeout) == -1) && (errno && (errno != EAGAIN))) {
#else
		if ((semop(sys_semid, &sbuf[0], blocking + 1) == -1) &&
		    (errno && (errno != EAGAIN))) {
#endif /* HAVE_SEMTIMEDOP */
			filebench_log(LOG_ERROR, "semop post failed: %s",
			    strerror(errno));
			return (FILEBENCH_ERROR);
		}

		filebench_log(LOG_DEBUG_IMPL,
		    "flow %s-%d finished posting",
		    target->fo_name, target->fo_instance);
#else
		filebench_log(LOG_DEBUG_IMPL,
		    "sempost flow %s-%d to posix semaphore",
		    target->fo_name,
		    target->fo_instance);

		/* Increment sem by value */
		for (i = 0; i < value; i++) {
			if (sem_post(&target->fo_sem) == -1) {
				filebench_log(LOG_ERROR, "semop post failed");
				return (FILEBENCH_ERROR);
			}
		}

		filebench_log(LOG_DEBUG_IMPL, "flow %s-%d unblocking",
		    target->fo_name, target->fo_instance);
#endif /* HAVE_SYSV_SEM */

		target = target->fo_targetnext;
	}
	flowop_endop(threadflow, flowop, 0);

	return (FILEBENCH_OK);
}


/*
 * Section for exercising create / open / close / delete operations
 * on files within a fileset. For proper operation, the flowop attribute
 * "fd", which sets the fo_fdnumber field in the flowop, must be used
 * so that the same file is opened and later closed. "fd" is an index
 * into a pair of arrays maintained by threadflows, one of which
 * contains the operating system assigned file descriptors and the other
 * a pointer to the filesetentry whose file the file descriptor
 * references. An openfile flowop defined without fd being set will use
 * the default (0) fd or, if specified, rotate through fd indices, but
 * createfile and closefile must use the default or a specified fd.
 * Meanwhile deletefile picks and arbitrary file to delete, regardless
 * of fd attribute.
 */

/*
 * XXX Making file selection more consistent among the flowops might good
 */


/*
 * Emulates (and actually does) file open. Obtains a file descriptor
 * index, then calls flowoplib_openfile_common() to open. Returns
 * FILEBENCH_ERROR if no file descriptor is found, and returns the
 * status from flowoplib_openfile_common otherwise (FILEBENCH_ERROR,
 * FILEBENCH_NORSC, FILEBENCH_OK).
 */
static int
flowoplib_openfile(threadflow_t *threadflow, flowop_t *flowop)
{
	int fd = flowoplib_fdnum(threadflow, flowop);

	if (fd == -1)
		return (FILEBENCH_ERROR);

	return (flowoplib_openfile_common(threadflow, flowop, fd));
}

/*
 * Common file opening code for filesets. Uses the supplied
 * file descriptor index to determine the tf_fd entry to use.
 * If the entry is empty (0) and the fileset exists, fileset
 * pick is called to select a fileset entry to use. The file
 * specified in the filesetentry is opened, and the returned
 * operating system file descriptor and a pointer to the
 * filesetentry are stored in tf_fd[fd] and tf_fse[fd],
 * respectively. Returns FILEBENCH_ERROR on error,
 * FILEBENCH_NORSC if no suitable filesetentry can be found,
 * and FILEBENCH_OK on success.
 */
static int
flowoplib_openfile_common(threadflow_t *threadflow, flowop_t *flowop, int fd)
{
	filesetentry_t *file;
	char *fileset_name;
	int tid = 0;
	int err;

	if (flowop->fo_fileset == NULL) {
		filebench_log(LOG_ERROR, "flowop NULL file");
		return (FILEBENCH_ERROR);
	}

	if ((fileset_name =
	    avd_get_str(flowop->fo_fileset->fs_name)) == NULL) {
		filebench_log(LOG_ERROR,
		    "flowop %s: fileset has no name", flowop->fo_name);
		return (FILEBENCH_ERROR);
	}

	/*
	 * If the flowop doesn't default to persistent fd
	 * then get unique thread ID for use by fileset_pick
	 */
	if (avd_get_bool(flowop->fo_rotatefd))
		tid = threadflow->tf_utid;

	if (threadflow->tf_fd[fd] != 0) {
		filebench_log(LOG_ERROR,
		    "flowop %s attempted to open without closing on fd %d",
		    flowop->fo_name, fd);
		return (FILEBENCH_ERROR);
	}

#ifdef HAVE_RAW_SUPPORT
	if (flowop->fo_fileset->fs_attrs & FILESET_IS_RAW_DEV) {
		int open_attrs = 0;
		char name[MAXPATHLEN];

		(void) fb_strlcpy(name,
		    avd_get_str(flowop->fo_fileset->fs_path), MAXPATHLEN);
		(void) fb_strlcat(name, "/", MAXPATHLEN);
		(void) fb_strlcat(name, fileset_name, MAXPATHLEN);

		if (avd_get_bool(flowop->fo_dsync)) {
#ifdef sun
			open_attrs |= O_DSYNC;
#else
			open_attrs |= O_FSYNC;
#endif
		}

		filebench_log(LOG_DEBUG_SCRIPT,
		    "open raw device %s flags %d = %d", name, open_attrs, fd);

		threadflow->tf_fd[fd] = open64(name,
		    O_RDWR | open_attrs, 0666);

		if (threadflow->tf_fd[fd] < 0) {
			filebench_log(LOG_ERROR,
			    "Failed to open raw device %s: %s",
			    name, strerror(errno));
			return (FILEBENCH_ERROR);
		}

		/* if running on Solaris, use un-buffered io */
#ifdef sun
		(void) directio(threadflow->tf_fd[fd], DIRECTIO_ON);
#endif

		threadflow->tf_fse[fd] = NULL;

		return (FILEBENCH_OK);
	}
#endif /* HAVE_RAW_SUPPORT */

	if ((err = flowoplib_pickfile(&file, flowop,
	    FILESET_PICKEXISTS, tid)) != FILEBENCH_OK) {
		filebench_log(LOG_DEBUG_SCRIPT,
		    "flowop %s failed to pick file from %s on fd %d",
		    flowop->fo_name, fileset_name, fd);
		return (err);
	}

	threadflow->tf_fse[fd] = file;

	flowop_beginop(threadflow, flowop);
	threadflow->tf_fd[fd] = fileset_openfile(flowop->fo_fileset,
	    file, O_RDWR, 0666, flowoplib_fileattrs(flowop));
	flowop_endop(threadflow, flowop, 0);

	if (threadflow->tf_fd[fd] < 0) {
		filebench_log(LOG_ERROR, "flowop %s failed to open file %s",
		    flowop->fo_name, file->fse_path);
		return (FILEBENCH_ERROR);
	}

	filebench_log(LOG_DEBUG_SCRIPT,
	    "flowop %s: opened %s fd[%d] = %d",
	    flowop->fo_name, file->fse_path, fd, threadflow->tf_fd[fd]);

	return (FILEBENCH_OK);
}

/*
 * Emulate create of a file. Uses the flowop's fdnumber to select
 * tf_fd and tf_fse array locations to put the created file's file
 * descriptor and filesetentry respectively. Uses flowoplib_pickfile()
 * to select a specific filesetentry whose file does not currently
 * exist for the file create operation. Then calls
 * fileset_openfile() with the O_CREATE flag set to create the
 * file. Returns FILEBENCH_ERROR if the array index specified by fdnumber is
 * already in use, the flowop has no associated fileset, or
 * the create call fails. Returns 1 if a filesetentry with a
 * nonexistent file cannot be found. Returns FILEBENCH_OK on success.
 */
static int
flowoplib_createfile(threadflow_t *threadflow, flowop_t *flowop)
{
	filesetentry_t *file;
	int fd = flowop->fo_fdnumber;
	int err;

	if (threadflow->tf_fd[fd] != 0) {
		filebench_log(LOG_ERROR,
		    "flowop %s attempted to create without closing on fd %d",
		    flowop->fo_name, fd);
		return (FILEBENCH_ERROR);
	}

	if (flowop->fo_fileset == NULL) {
		filebench_log(LOG_ERROR, "flowop NULL file");
		return (FILEBENCH_ERROR);
	}

#ifdef HAVE_RAW_SUPPORT
	/* can't be used with raw devices */
	if (flowop->fo_fileset->fs_attrs & FILESET_IS_RAW_DEV) {
		filebench_log(LOG_ERROR,
		    "flowop %s attempted to a createfile on RAW device",
		    flowop->fo_name);
		return (FILEBENCH_ERROR);
	}
#endif /* HAVE_RAW_SUPPORT */

	if ((err = flowoplib_pickfile(&file, flowop,
	    FILESET_PICKNOEXIST, 0)) != FILEBENCH_OK) {
		filebench_log(LOG_DEBUG_SCRIPT,
		    "flowop %s failed to pick file from fileset %s",
		    flowop->fo_name,
		    avd_get_str(flowop->fo_fileset->fs_name));
		return (err);
	}

	threadflow->tf_fse[fd] = file;

	flowop_beginop(threadflow, flowop);
	threadflow->tf_fd[fd] = fileset_openfile(flowop->fo_fileset,
	    file, O_RDWR | O_CREAT, 0666, flowoplib_fileattrs(flowop));
	flowop_endop(threadflow, flowop, 0);

	if (threadflow->tf_fd[fd] < 0) {
		filebench_log(LOG_ERROR, "failed to create file %s",
		    flowop->fo_name);
		return (FILEBENCH_ERROR);
	}

	filebench_log(LOG_DEBUG_SCRIPT,
	    "flowop %s: created %s fd[%d] = %d",
	    flowop->fo_name, file->fse_path, fd, threadflow->tf_fd[fd]);

	return (FILEBENCH_OK);
}

/*
 * Emulates delete of a file. If a valid fd is provided, it uses the
 * filesetentry stored at that fd location to select the file to be
 * deleted, otherwise it picks an arbitrary filesetentry
 * whose file exists. It then uses unlink() to delete it and Clears
 * the FSE_EXISTS flag for the filesetentry. Returns FILEBENCH_ERROR if the
 * flowop has no associated fileset. Returns FILEBENCH_NORSC if an appropriate
 * filesetentry cannot be found, and FILEBENCH_OK on success.
 */
static int
flowoplib_deletefile(threadflow_t *threadflow, flowop_t *flowop)
{
	filesetentry_t *file;
	fileset_t *fileset;
	char path[MAXPATHLEN];
	char *pathtmp;
	int fd = flowop->fo_fdnumber;

	/* if fd specified, use it to access file */
	if ((fd > 0) && ((file = threadflow->tf_fse[fd]) != NULL)) {

		/* indicate that the file will be deleted */
		threadflow->tf_fse[fd] = NULL;

		/* if here, we still have a valid file pointer */
		fileset = file->fse_fileset;
	} else {

		/* Otherwise, pick arbitrary file */
		file = NULL;
		fileset = flowop->fo_fileset;
	}


	if (fileset == NULL) {
		filebench_log(LOG_ERROR, "flowop NULL file");
		return (FILEBENCH_ERROR);
	}

#ifdef HAVE_RAW_SUPPORT
	/* can't be used with raw devices */
	if (fileset->fs_attrs & FILESET_IS_RAW_DEV) {
		filebench_log(LOG_ERROR,
		    "flowop %s attempted a deletefile on RAW device",
		    flowop->fo_name);
		return (FILEBENCH_ERROR);
	}
#endif /* HAVE_RAW_SUPPORT */

	if (file == NULL) {
		int err;

		/* pick arbitrary, existing (allocated) file */
		if ((err = flowoplib_pickfile(&file, flowop,
		    FILESET_PICKEXISTS, 0)) != FILEBENCH_OK) {
			filebench_log(LOG_DEBUG_SCRIPT,
			    "flowop %s failed to pick file", flowop->fo_name);
			return (err);
		}
	} else {
		/* delete specific file. wait for it to be non-busy */
		(void) ipc_mutex_lock(&fileset->fs_pick_lock);
		while (file->fse_flags & FSE_BUSY) {
			file->fse_flags |= FSE_THRD_WAITNG;
			(void) pthread_cond_wait(&fileset->fs_thrd_wait_cv,
			    &fileset->fs_pick_lock);
		}

		/* File now available, grab it for deletion */
		file->fse_flags |= FSE_BUSY;
		fileset->fs_idle_files--;
		(void) ipc_mutex_unlock(&fileset->fs_pick_lock);
	}

	/* don't delete if anyone (other than me) has file open */
	if ((fd > 0) && (threadflow->tf_fd[fd] > 0)) {
		if (file->fse_open_cnt > 1) {
			filebench_log(LOG_DEBUG_SCRIPT,
			    "flowop %s can't delete file opened by other"
			    " threads at fd = %d", flowop->fo_name, fd);
			fileset_unbusy(file, FALSE, FALSE, 0);
			return (FILEBENCH_OK);
		} else {
			filebench_log(LOG_DEBUG_SCRIPT,
			    "flowop %s deleting still open file at fd = %d",
			    flowop->fo_name, fd);
		}
	} else if (file->fse_open_cnt > 0) {
		filebench_log(LOG_DEBUG_SCRIPT,
		    "flowop %s can't delete file opened by other"
		    " threads at fd = %d, open count = %d",
		    flowop->fo_name, fd, file->fse_open_cnt);
		fileset_unbusy(file, FALSE, FALSE, 0);
		return (FILEBENCH_OK);
	}

	(void) fb_strlcpy(path, avd_get_str(fileset->fs_path), MAXPATHLEN);
	(void) fb_strlcat(path, "/", MAXPATHLEN);
	(void) fb_strlcat(path, avd_get_str(fileset->fs_name), MAXPATHLEN);
	pathtmp = fileset_resolvepath(file);
	(void) fb_strlcat(path, pathtmp, MAXPATHLEN);
	free(pathtmp);

	/* delete the selected file */
	flowop_beginop(threadflow, flowop);
	(void) unlink(path);
	flowop_endop(threadflow, flowop, 0);

	/* indicate that it is no longer busy and no longer exists */
	fileset_unbusy(file, TRUE, FALSE, -file->fse_open_cnt);

	filebench_log(LOG_DEBUG_SCRIPT, "deleted file %s", file->fse_path);

	return (FILEBENCH_OK);
}

/*
 * Emulates fsync of a file. Obtains the file descriptor index
 * from the flowop, obtains the actual file descriptor from
 * the threadflow's table, checks to be sure it is still an
 * open file, then does an fsync operation on it. Returns FILEBENCH_ERROR
 * if the file no longer is open, FILEBENCH_OK otherwise.
 */
static int
flowoplib_fsync(threadflow_t *threadflow, flowop_t *flowop)
{
	filesetentry_t *file;
	int fd = flowop->fo_fdnumber;

	if (threadflow->tf_fd[fd] == 0) {
		filebench_log(LOG_ERROR,
		    "flowop %s attempted to fsync a closed fd %d",
		    flowop->fo_name, fd);
		return (FILEBENCH_ERROR);
	}

	file = threadflow->tf_fse[fd];

	if ((file == NULL) ||
	    (file->fse_fileset->fs_attrs & FILESET_IS_RAW_DEV)) {
		filebench_log(LOG_ERROR,
		    "flowop %s attempted to a fsync a RAW device",
		    flowop->fo_name);
		return (FILEBENCH_ERROR);
	}

	/* Measure time to fsync */
	flowop_beginop(threadflow, flowop);
	(void) fsync(threadflow->tf_fd[fd]);
	flowop_endop(threadflow, flowop, 0);

	filebench_log(LOG_DEBUG_SCRIPT, "fsync file %s", file->fse_path);

	return (FILEBENCH_OK);
}

/*
 * Emulate fsync of an entire fileset. Search through the
 * threadflow's file descriptor array, doing fsync() on each
 * open file that belongs to the flowop's fileset. Always
 * returns FILEBENCH_OK.
 */
static int
flowoplib_fsyncset(threadflow_t *threadflow, flowop_t *flowop)
{
	int fd;

	for (fd = 0; fd < THREADFLOW_MAXFD; fd++) {
		filesetentry_t *file;

		/* Match the file set to fsync */
		if ((threadflow->tf_fse[fd] == NULL) ||
		    (flowop->fo_fileset != threadflow->tf_fse[fd]->fse_fileset))
			continue;

		/* Measure time to fsync */
		flowop_beginop(threadflow, flowop);
		(void) fsync(threadflow->tf_fd[fd]);
		flowop_endop(threadflow, flowop, 0);

		file = threadflow->tf_fse[fd];

		filebench_log(LOG_DEBUG_SCRIPT, "fsync file %s",
		    file->fse_path);
	}

	return (FILEBENCH_OK);
}

/*
 * Emulate close of a file.  Obtains the file descriptor index
 * from the flowop, obtains the actual file descriptor from the
 * threadflow's table, checks to be sure it is still an open
 * file, then does a close operation on it. Then sets the
 * threadflow file descriptor table entry to 0, and the file set
 * entry pointer to NULL. Returns FILEBENCH_ERROR if the file was not open,
 * FILEBENCH_OK otherwise.
 */
static int
flowoplib_closefile(threadflow_t *threadflow, flowop_t *flowop)
{
	filesetentry_t *file;
	fileset_t *fileset;
	int fd = flowop->fo_fdnumber;

	if (threadflow->tf_fd[fd] == 0) {
		filebench_log(LOG_ERROR,
		    "flowop %s attempted to close an already closed fd %d",
		    flowop->fo_name, fd);
		return (FILEBENCH_ERROR);
	}

	file = threadflow->tf_fse[fd];
	fileset = file->fse_fileset;

	/* Wait for it to be non-busy */
	(void) ipc_mutex_lock(&fileset->fs_pick_lock);
	while (file->fse_flags & FSE_BUSY) {
		file->fse_flags |= FSE_THRD_WAITNG;
		(void) pthread_cond_wait(&fileset->fs_thrd_wait_cv,
		    &fileset->fs_pick_lock);
	}

	/* File now available, grab it for closing */
	file->fse_flags |= FSE_BUSY;

	/* if last open, set declare idle */
	if (file->fse_open_cnt == 1)
		fileset->fs_idle_files--;

	(void) ipc_mutex_unlock(&fileset->fs_pick_lock);

	/* Measure time to close */
	flowop_beginop(threadflow, flowop);
	(void) close(threadflow->tf_fd[fd]);
	flowop_endop(threadflow, flowop, 0);

	fileset_unbusy(file, FALSE, FALSE, -1);

	threadflow->tf_fd[fd] = 0;

	filebench_log(LOG_DEBUG_SCRIPT, "closed file %s", file->fse_path);

	return (FILEBENCH_OK);
}

/*
 * Obtain the full pathname of the directory described by the filesetentry
 * indicated by "dir", and copy it into the character array pointed to by
 * path. Returns FILEBENCH_ERROR on errors, FILEBENCH_OK otherwise.
 */
static int
flowoplib_getdirpath(filesetentry_t *dir, char *path)
{
	char		*fileset_path;
	char		*fileset_name;
	char		*part_path;

	if ((fileset_path = avd_get_str(dir->fse_fileset->fs_path)) == NULL) {
		filebench_log(LOG_ERROR, "Fileset path not set");
		return (FILEBENCH_ERROR);
	}

	if ((fileset_name = avd_get_str(dir->fse_fileset->fs_name)) == NULL) {
		filebench_log(LOG_ERROR, "Fileset name not set");
		return (FILEBENCH_ERROR);
	}

	(void) fb_strlcpy(path, fileset_path, MAXPATHLEN);
	(void) fb_strlcat(path, "/", MAXPATHLEN);
	(void) fb_strlcat(path, fileset_name, MAXPATHLEN);

	if ((part_path = fileset_resolvepath(dir)) == NULL)
		return (FILEBENCH_ERROR);

	(void) fb_strlcat(path, part_path, MAXPATHLEN);
	free(part_path);

	return (FILEBENCH_OK);
}

/*
 * Use mkdir to create a directory.  Obtains the fileset name from the
 * flowop, selects a non-existent leaf directory and obtains its full
 * path, then uses mkdir to create it on the storage subsystem (make it
 * existent). Returns FILEBENCH_NORSC is there are no more non-existent
 * directories in the fileset, FILEBENCH_ERROR on other errors, and
 * FILEBENCH_OK on success.
 */
static int
flowoplib_makedir(threadflow_t *threadflow, flowop_t *flowop)
{
	filesetentry_t	*dir;
	int		ret;
	char		full_path[MAXPATHLEN];

	if ((ret = flowoplib_pickleafdir(&dir, flowop,
	    FILESET_PICKNOEXIST)) != FILEBENCH_OK)
		return (ret);

	if ((ret = flowoplib_getdirpath(dir, full_path)) != FILEBENCH_OK)
		return (ret);

	flowop_beginop(threadflow, flowop);
	(void) mkdir(full_path, 0755);
	flowop_endop(threadflow, flowop, 0);

	/* indicate that it is no longer busy and now exists */
	fileset_unbusy(dir, TRUE, TRUE, 0);

	return (FILEBENCH_OK);
}

/*
 * Use rmdir to delete a directory.  Obtains the fileset name from the
 * flowop, selects an existent leaf directory and obtains its full path,
 * then uses rmdir to remove it from the storage subsystem (make it
 * non-existent). Returns FILEBENCH_NORSC is there are no more existent
 * directories in the fileset, FILEBENCH_ERROR on other errors, and
 * FILEBENCH_OK on success.
 */
static int
flowoplib_removedir(threadflow_t *threadflow, flowop_t *flowop)
{
	filesetentry_t *dir;
	int		ret;
	char		full_path[MAXPATHLEN];

	if ((ret = flowoplib_pickleafdir(&dir, flowop,
	    FILESET_PICKEXISTS)) != FILEBENCH_OK)
		return (ret);

	if ((ret = flowoplib_getdirpath(dir, full_path)) != FILEBENCH_OK)
		return (ret);

	flowop_beginop(threadflow, flowop);
	(void) rmdir(full_path);
	flowop_endop(threadflow, flowop, 0);

	/* indicate that it is no longer busy and no longer exists */
	fileset_unbusy(dir, TRUE, FALSE, 0);

	return (FILEBENCH_OK);
}

/*
 * Use opendir(), multiple readdir() calls, and closedir() to list the
 * contents of a directory.  Obtains the fileset name from the
 * flowop, selects a normal subdirectory (which always exist) and obtains
 * its full path, then uses opendir() to get a DIR handle to it from the
 * file system, a readdir() loop to access each directory entry, and
 * finally cleans up with a closedir(). The latency reported is the total
 * for all this activity, and it also reports the total number of bytes
 * in the entries as the amount "read". Returns FILEBENCH_ERROR on errors,
 * and FILEBENCH_OK on success.
 */
static int
flowoplib_listdir(threadflow_t *threadflow, flowop_t *flowop)
{
	fileset_t	*fileset;
	filesetentry_t	*dir;
	DIR		*dir_handlep;
	struct dirent	*direntp;
	int		dir_bytes = 0;
	int		ret;
	char		full_path[MAXPATHLEN];

	if ((fileset = flowop->fo_fileset) == NULL) {
		filebench_log(LOG_ERROR, "flowop NO fileset");
		return (FILEBENCH_ERROR);
	}

	if ((dir = fileset_pick(fileset, FILESET_PICKDIR, 0, 0)) == NULL) {
		filebench_log(LOG_DEBUG_SCRIPT,
		    "flowop %s failed to pick directory from fileset %s",
		    flowop->fo_name,
		    avd_get_str(fileset->fs_name));
		return (FILEBENCH_ERROR);
	}

	if ((ret = flowoplib_getdirpath(dir, full_path)) != FILEBENCH_OK)
		return (ret);

	flowop_beginop(threadflow, flowop);

	/* open the directory */
	if ((dir_handlep = opendir(full_path)) == NULL) {
		filebench_log(LOG_ERROR,
		    "flowop %s failed to open directory in fileset %s\n",
		    flowop->fo_name, avd_get_str(fileset->fs_name));
		return (FILEBENCH_ERROR);
	}

	/* read through the directory entries */
	while ((direntp = readdir(dir_handlep)) != NULL) {
		dir_bytes += (strlen(direntp->d_name) +
		    sizeof (struct dirent) - 1);
	}

	/* close the directory */
	(void) closedir(dir_handlep);

	flowop_endop(threadflow, flowop, dir_bytes);

	/* indicate that it is no longer busy */
	fileset_unbusy(dir, FALSE, FALSE, 0);

	return (FILEBENCH_OK);
}

/*
 * Emulate stat of a file. Picks an arbitrary filesetentry with
 * an existing file from the flowop's fileset, then performs a
 * stat() operation on it. Returns FILEBENCH_ERROR if the flowop has no
 * associated fileset. Returns FILEBENCH_NORSC if an appropriate filesetentry
 * cannot be found, and FILEBENCH_OK on success.
 */
static int
flowoplib_statfile(threadflow_t *threadflow, flowop_t *flowop)
{
	filesetentry_t *file;
	fileset_t *fileset;
	struct stat statbuf;
	int fd = flowop->fo_fdnumber;

	/* if fd specified and the file is open, use it to access file */
	if ((fd > 0) && ((threadflow->tf_fd[fd]) > 0)) {

		/* check whether file handle still valid */
		if ((file = threadflow->tf_fse[fd]) == NULL) {
			filebench_log(LOG_DEBUG_SCRIPT,
			    "flowop %s trying to stat NULL file at fd = %d",
			    flowop->fo_name, fd);
			return (FILEBENCH_ERROR);
		}

		/* if here, we still have a valid file pointer */
		fileset = file->fse_fileset;
	} else {
		/* Otherwise, pick arbitrary file */
		file = NULL;
		fileset = flowop->fo_fileset;
	}

	if (fileset == NULL) {
		filebench_log(LOG_ERROR,
		    "statfile with no fileset specified");
		return (FILEBENCH_ERROR);
	}

#ifdef HAVE_RAW_SUPPORT
	/* can't be used with raw devices */
	if (fileset->fs_attrs & FILESET_IS_RAW_DEV) {
		filebench_log(LOG_ERROR,
		    "flowop %s attempted do a statfile on a RAW device",
		    flowop->fo_name);
		return (FILEBENCH_ERROR);
	}
#endif /* HAVE_RAW_SUPPORT */

	if (file == NULL) {
		char path[MAXPATHLEN];
		char *pathtmp;
		int err;

		/* pick arbitrary, existing (allocated) file */
		if ((err = flowoplib_pickfile(&file, flowop,
		    FILESET_PICKEXISTS, 0)) != FILEBENCH_OK) {
			filebench_log(LOG_DEBUG_SCRIPT,
			    "Statfile flowop %s failed to pick file",
			    flowop->fo_name);
			return (err);
		}

		/* resolve path and do a stat on file */
		(void) fb_strlcpy(path, avd_get_str(fileset->fs_path),
		    MAXPATHLEN);
		(void) fb_strlcat(path, "/", MAXPATHLEN);
		(void) fb_strlcat(path, avd_get_str(fileset->fs_name),
		    MAXPATHLEN);
		pathtmp = fileset_resolvepath(file);
		(void) fb_strlcat(path, pathtmp, MAXPATHLEN);
		free(pathtmp);

		/* stat the file */
		flowop_beginop(threadflow, flowop);
		if (stat(path, &statbuf) == -1)
			filebench_log(LOG_ERROR,
			    "statfile flowop %s failed", flowop->fo_name);
		flowop_endop(threadflow, flowop, 0);

		fileset_unbusy(file, FALSE, FALSE, 0);
	} else {
		/* stat specific file */
		flowop_beginop(threadflow, flowop);
		if (fstat(threadflow->tf_fd[fd], &statbuf) == -1)
			filebench_log(LOG_ERROR,
			    "statfile flowop %s failed", flowop->fo_name);
		flowop_endop(threadflow, flowop, 0);

	}

	return (FILEBENCH_OK);
}


/*
 * Additional reads and writes. Read and write whole files, write
 * and append to files. Some of these work with both fileobjs and
 * filesets, others only with filesets. The flowoplib_write routine
 * writes from thread memory, while the others read or write using
 * fo_buf memory. Note that both flowoplib_read() and
 * flowoplib_aiowrite() use thread memory as well.
 */


/*
 * Emulate a read of a whole file. The file must be open with
 * file descriptor and filesetentry stored at the locations indexed
 * by the flowop's fdnumber. It then seeks to the beginning of the
 * associated file, and reads fs_iosize bytes at a time until the end
 * of the file. Returns FILEBENCH_ERROR on error, FILEBENCH_NORSC if
 * out of files, and FILEBENCH_OK on success.
 */
static int
flowoplib_readwholefile(threadflow_t *threadflow, flowop_t *flowop)
{
	caddr_t iobuf;
	off64_t bytes = 0;
	int filedesc;
	uint64_t wss;
	fbint_t iosize;
	int ret;
	char zerordbuf;

	/* get the file to use */
	if ((ret = flowoplib_filesetup(threadflow, flowop, &wss,
	    &filedesc)) != FILEBENCH_OK)
		return (ret);

	/* an I/O size of zero means read entire working set with one I/O */
	if ((iosize = avd_get_int(flowop->fo_iosize)) == 0)
		iosize = wss;

	/*
	 * The file may actually be 0 bytes long, in which case skip
	 * the buffer set up call (which would fail) and substitute
	 * a small buffer, which won't really be used.
	 */
	if (iosize == 0) {
		iobuf = (caddr_t)&zerordbuf;
		filebench_log(LOG_DEBUG_SCRIPT,
		    "flowop %s read zero length file", flowop->fo_name);
	} else {
		if (flowoplib_iobufsetup(threadflow, flowop, &iobuf,
		    iosize) != 0)
			return (FILEBENCH_ERROR);
	}

	/* Measure time to read bytes */
	flowop_beginop(threadflow, flowop);
	(void) lseek64(filedesc, 0, SEEK_SET);
	while ((ret = read(filedesc, iobuf, iosize)) > 0)
		bytes += ret;

	flowop_endop(threadflow, flowop, bytes);

	if (ret < 0) {
		filebench_log(LOG_ERROR,
		    "readwhole fail Failed to read whole file: %s",
		    strerror(errno));
		return (FILEBENCH_ERROR);
	}

	return (FILEBENCH_OK);
}

/*
 * Emulate a write to a file of size fo_iosize.  Will write
 * to a file from a fileset if the flowop's fo_fileset field
 * specifies one or its fdnumber is non zero. Otherwise it
 * will write to a fileobj file, if one exists. If the file
 * is not currently open, the routine will attempt to open
 * it. The flowop's fo_wss parameter will be used to set the
 * maximum file size if it is non-zero, otherwise the
 * filesetentry's  fse_size will be used. A random memory
 * buffer offset is calculated, and, if fo_random is TRUE,
 * a random file offset is used for the write. Otherwise the
 * write is to the next sequential location. Returns
 * FILEBENCH_ERROR on errors, FILEBENCH_NORSC if iosetup can't
 * obtain a file, or FILEBENCH_OK on success.
 */
static int
flowoplib_write(threadflow_t *threadflow, flowop_t *flowop)
{
	caddr_t iobuf;
	fbint_t wss;
	fbint_t iosize;
	int filedesc;
	int ret;

	iosize = avd_get_int(flowop->fo_iosize);
	if ((ret = flowoplib_iosetup(threadflow, flowop, &wss, &iobuf,
	    &filedesc, iosize)) != FILEBENCH_OK)
		return (ret);

	if (avd_get_bool(flowop->fo_random)) {
		uint64_t fileoffset;

		if (filebench_randomno64(&fileoffset,
		    wss, iosize, NULL) == -1) {
			filebench_log(LOG_ERROR,
			    "file size smaller than IO size for thread %s",
			    flowop->fo_name);
			return (FILEBENCH_ERROR);
		}
		flowop_beginop(threadflow, flowop);
		if (pwrite64(filedesc, iobuf,
		    iosize, (off64_t)fileoffset) == -1) {
			filebench_log(LOG_ERROR, "write failed, "
			    "offset %llu io buffer %zd: %s",
			    (u_longlong_t)fileoffset, iobuf, strerror(errno));
			flowop_endop(threadflow, flowop, 0);
			return (FILEBENCH_ERROR);
		}
		flowop_endop(threadflow, flowop, iosize);
	} else {
		flowop_beginop(threadflow, flowop);
		if (write(filedesc, iobuf, iosize) == -1) {
			filebench_log(LOG_ERROR,
			    "write failed, io buffer %zd: %s",
			    iobuf, strerror(errno));
			flowop_endop(threadflow, flowop, 0);
			return (FILEBENCH_ERROR);
		}
		flowop_endop(threadflow, flowop, iosize);
	}

	return (FILEBENCH_OK);
}

/*
 * Emulate a write of a whole file.  The size of the file
 * is taken from a filesetentry identified by fo_srcfdnumber or
 * from the working set size, while the file descriptor used is
 * identified by fo_fdnumber. Does multiple writes of fo_iosize
 * length length until full file has been written. Returns FILEBENCH_ERROR on
 * error, FILEBENCH_NORSC if out of files, FILEBENCH_OK on success.
 */
static int
flowoplib_writewholefile(threadflow_t *threadflow, flowop_t *flowop)
{
	caddr_t iobuf;
	filesetentry_t *file;
	int wsize;
	off64_t seek;
	off64_t bytes = 0;
	uint64_t wss;
	fbint_t iosize;
	int filedesc;
	int srcfd = flowop->fo_srcfdnumber;
	int ret;
	char zerowrtbuf;

	/* get the file to use */
	if ((ret = flowoplib_filesetup(threadflow, flowop, &wss,
	    &filedesc)) != FILEBENCH_OK)
		return (ret);

	/* an I/O size of zero means write entire working set with one I/O */
	if ((iosize = avd_get_int(flowop->fo_iosize)) == 0)
		iosize = wss;

	/*
	 * The file may actually be 0 bytes long, in which case skip
	 * the buffer set up call (which would fail) and substitute
	 * a small buffer, which won't really be used.
	 */
	if (iosize == 0) {
		iobuf = (caddr_t)&zerowrtbuf;
		filebench_log(LOG_DEBUG_SCRIPT,
		    "flowop %s wrote zero length file", flowop->fo_name);
	} else {
		if (flowoplib_iobufsetup(threadflow, flowop, &iobuf,
		    iosize) != 0)
			return (FILEBENCH_ERROR);
	}

	file = threadflow->tf_fse[srcfd];
	if ((srcfd != 0) && (file == NULL)) {
		filebench_log(LOG_ERROR, "flowop %s: NULL src file",
		    flowop->fo_name);
		return (FILEBENCH_ERROR);
	}

	if (file)
		wss = file->fse_size;

	wsize = (int)MIN(wss, iosize);

	/* Measure time to write bytes */
	flowop_beginop(threadflow, flowop);
	for (seek = 0; seek < wss; seek += wsize) {
		ret = write(filedesc, iobuf, wsize);
		if (ret != wsize) {
			filebench_log(LOG_ERROR,
			    "Failed to write %d bytes on fd %d: %s",
			    wsize, filedesc, strerror(errno));
			flowop_endop(threadflow, flowop, 0);
			return (FILEBENCH_ERROR);
		}
		wsize = (int)MIN(wss - seek, iosize);
		bytes += ret;
	}
	flowop_endop(threadflow, flowop, bytes);

	return (FILEBENCH_OK);
}


/*
 * Emulate a fixed size append to a file. Will append data to
 * a file chosen from a fileset if the flowop's fo_fileset
 * field specifies one or if its fdnumber is non zero.
 * Otherwise it will write to a fileobj file, if one exists.
 * The flowop's fo_wss parameter will be used to set the
 * maximum file size if it is non-zero, otherwise the
 * filesetentry's fse_size will be used. A random memory
 * buffer offset is calculated, then a logical seek to the
 * end of file is done followed by a write of fo_iosize
 * bytes. Writes are actually done from fo_buf, rather than
 * tf_mem as is done with flowoplib_write(), and no check
 * is made to see if fo_iosize exceeds the size of fo_buf.
 * Returns FILEBENCH_ERROR on error, FILEBENCH_NORSC if out of
 * files in the fileset, FILEBENCH_OK on success.
 */
static int
flowoplib_appendfile(threadflow_t *threadflow, flowop_t *flowop)
{
	caddr_t iobuf;
	int filedesc;
	fbint_t wss;
	fbint_t iosize;
	int ret;

	iosize = avd_get_int(flowop->fo_iosize);
	if ((ret = flowoplib_iosetup(threadflow, flowop, &wss, &iobuf,
	    &filedesc, iosize)) != FILEBENCH_OK)
		return (ret);

	/* XXX wss is not being used */

	/* Measure time to write bytes */
	flowop_beginop(threadflow, flowop);
	(void) lseek64(filedesc, 0, SEEK_END);
	ret = write(filedesc, iobuf, iosize);
	if (ret != iosize) {
		filebench_log(LOG_ERROR,
		    "Failed to write %llu bytes on fd %d: %s",
		    (u_longlong_t)iosize, filedesc, strerror(errno));
		flowop_endop(threadflow, flowop, ret);
		return (FILEBENCH_ERROR);
	}
	flowop_endop(threadflow, flowop, ret);

	return (FILEBENCH_OK);
}

/*
 * Emulate a random size append to a file. Will append data
 * to a file chosen from a fileset if the flowop's fo_fileset
 * field specifies one or if its fdnumber is non zero. Otherwise
 * it will write to a fileobj file, if one exists. The flowop's
 * fo_wss parameter will be used to set the maximum file size
 * if it is non-zero, otherwise the filesetentry's fse_size
 * will be used.  A random transfer size (but at most fo_iosize
 * bytes) and a random memory offset are calculated. A logical
 * seek to the end of file is done, then writes of up to
 * FILE_ALLOC_BLOCK in size are done until the full transfer
 * size has been written. Writes are actually done from fo_buf,
 * rather than tf_mem as is done with flowoplib_write().
 * Returns FILEBENCH_ERROR on error, FILEBENCH_NORSC if out of
 * files in the fileset, FILEBENCH_OK on success.
 */
static int
flowoplib_appendfilerand(threadflow_t *threadflow, flowop_t *flowop)
{
	caddr_t iobuf;
	uint64_t appendsize;
	int filedesc;
	fbint_t wss;
	fbint_t iosize;
	int ret = 0;

	if ((iosize = avd_get_int(flowop->fo_iosize)) == 0) {
		filebench_log(LOG_ERROR, "zero iosize for flowop %s",
		    flowop->fo_name);
		return (FILEBENCH_ERROR);
	}

	if (filebench_randomno64(&appendsize, iosize, 1LL, NULL) != 0)
		return (FILEBENCH_ERROR);

	/* skip if attempting zero length append */
	if (appendsize == 0) {
		flowop_beginop(threadflow, flowop);
		flowop_endop(threadflow, flowop, 0LL);
		return (FILEBENCH_OK);
	}

	if ((ret = flowoplib_iosetup(threadflow, flowop, &wss, &iobuf,
	    &filedesc, appendsize)) != FILEBENCH_OK)
		return (ret);

	/* XXX wss is not being used */

	/* Measure time to write bytes */
	flowop_beginop(threadflow, flowop);

	(void) lseek64(filedesc, 0, SEEK_END);
	ret = write(filedesc, iobuf, appendsize);
	if (ret != appendsize) {
		filebench_log(LOG_ERROR,
		    "Failed to write %llu bytes on fd %d: %s",
		    (u_longlong_t)appendsize, filedesc, strerror(errno));
		flowop_endop(threadflow, flowop, 0);
		return (FILEBENCH_ERROR);
	}

	flowop_endop(threadflow, flowop, appendsize);

	return (FILEBENCH_OK);
}

typedef struct testrandvar_priv {
	uint64_t sample_count;
	double val_sum;
	double sqr_sum;
} testrandvar_priv_t;

/*
 * flowop to calculate various statistics from the number stream
 * produced by a random variable. This allows verification that the
 * random distribution used to define the random variable is producing
 * the expected distribution of random numbers.
 */
/* ARGSUSED */
static int
flowoplib_testrandvar(threadflow_t *threadflow, flowop_t *flowop)
{
	testrandvar_priv_t	*mystats;
	double			value;

	if ((mystats = (testrandvar_priv_t *)flowop->fo_private) == NULL) {
		filebench_log(LOG_ERROR, "testrandvar not initialized\n");
		filebench_shutdown(1);
		return (-1);
	}

	value = avd_get_dbl(flowop->fo_value);

	mystats->sample_count++;
	mystats->val_sum += value;
	mystats->sqr_sum += (value * value);

	return (0);
}

/*
 * Initialize the private data area used to accumulate the statistics
 */
static int
flowoplib_testrandvar_init(flowop_t *flowop)
{
	testrandvar_priv_t	*mystats;

	if ((mystats = (testrandvar_priv_t *)
	    malloc(sizeof (testrandvar_priv_t))) == NULL) {
		filebench_log(LOG_ERROR, "could not initialize testrandvar");
		filebench_shutdown(1);
		return (-1);
	}

	mystats->sample_count = 0;
	mystats->val_sum = 0;
	mystats->sqr_sum = 0;
	flowop->fo_private = (void *)mystats;

	(void) ipc_mutex_unlock(&flowop->fo_lock);
	return (0);
}

/*
 * Print out the accumulated statistics, and free the private storage
 */
static void
flowoplib_testrandvar_destruct(flowop_t *flowop)
{
	testrandvar_priv_t	*mystats;
	double mean, std_dev, dbl_count;

	(void) ipc_mutex_lock(&flowop->fo_lock);
	if ((mystats = (testrandvar_priv_t *)
	    flowop->fo_private) == NULL) {
		(void) ipc_mutex_unlock(&flowop->fo_lock);
		return;
	}

	flowop->fo_private = NULL;
	(void) ipc_mutex_unlock(&flowop->fo_lock);

	dbl_count = (double)mystats->sample_count;
	mean = mystats->val_sum / dbl_count;
	std_dev = sqrt((mystats->sqr_sum / dbl_count) - (mean * mean)) / mean;

	filebench_log(LOG_VERBOSE,
	    "testrandvar: ops = %llu, mean = %8.2lf, stddev = %8.2lf",
	    (u_longlong_t)mystats->sample_count, mean, std_dev);
	free(mystats);
}

/*
 * prints message to the console from within a thread
 */
static int
flowoplib_print(threadflow_t *threadflow, flowop_t *flowop)
{
	procflow_t *procflow;

	procflow = threadflow->tf_process;
	filebench_log(LOG_INFO,
	    "Message from process (%s,%d), thread (%s,%d): %s",
	    procflow->pf_name, procflow->pf_instance,
	    threadflow->tf_name, threadflow->tf_instance,
	    avd_get_str(flowop->fo_value));

	return (FILEBENCH_OK);
}

/*
 * Prints usage information for flowop operations.
 */
void
flowoplib_usage()
{
	(void) fprintf(stderr,
	    "flowop [openfile|createfile] name=<name>,fileset=<fname>\n");
	(void) fprintf(stderr,
	    "                       [,fd=<file desc num>]\n");
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr,
	    "flowop closefile name=<name>,fd=<file desc num>]\n");
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr, "flowop deletefile name=<name>\n");
	(void) fprintf(stderr, "                       [,fileset=<fname>]\n");
	(void) fprintf(stderr,
	    "                       [,fd=<file desc num>]\n");
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr, "flowop statfile name=<name>\n");
	(void) fprintf(stderr, "                       [,fileset=<fname>]\n");
	(void) fprintf(stderr,
	    "                       [,fd=<file desc num>]\n");
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr,
	    "flowop fsync name=<name>,fd=<file desc num>]\n");
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr,
	    "flowop fsyncset name=<name>,fileset=<fname>]\n");
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr, "flowop [write|read|aiowrite] name=<name>, \n");
	(void) fprintf(stderr,
	    "                       filename|fileset=<fname>,\n");
	(void) fprintf(stderr, "                       iosize=<size>\n");
	(void) fprintf(stderr, "                       [,directio]\n");
	(void) fprintf(stderr, "                       [,dsync]\n");
	(void) fprintf(stderr, "                       [,iters=<count>]\n");
	(void) fprintf(stderr, "                       [,random]\n");
	(void) fprintf(stderr, "                       [,opennext]\n");
	(void) fprintf(stderr, "                       [,workingset=<size>]\n");
	(void) fprintf(stderr,
	    "flowop [appendfile|appendfilerand] name=<name>, \n");
	(void) fprintf(stderr,
	    "                       filename|fileset=<fname>,\n");
	(void) fprintf(stderr, "                       iosize=<size>\n");
	(void) fprintf(stderr, "                       [,dsync]\n");
	(void) fprintf(stderr, "                       [,iters=<count>]\n");
	(void) fprintf(stderr, "                       [,workingset=<size>]\n");
	(void) fprintf(stderr,
	    "flowop [readwholefile|writewholefile] name=<name>, \n");
	(void) fprintf(stderr,
	    "                       filename|fileset=<fname>,\n");
	(void) fprintf(stderr, "                       iosize=<size>\n");
	(void) fprintf(stderr, "                       [,dsync]\n");
	(void) fprintf(stderr, "                       [,iters=<count>]\n");
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr, "flowop aiowait name=<name>,target="
	    "<aiowrite-flowop>\n");
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr, "flowop sempost name=<name>,"
	    "target=<semblock-flowop>,\n");
	(void) fprintf(stderr,
	    "                       value=<increment-to-post>\n");
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr, "flowop semblock name=<name>,value="
	    "<decrement-to-receive>,\n");
	(void) fprintf(stderr, "                       highwater="
	    "<inbound-queue-max>\n");
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr, "flowop block name=<name>\n");
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr,
	    "flowop wakeup name=<name>,target=<block-flowop>,\n");
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr,
	    "flowop hog name=<name>,value=<number-of-mem-ops>\n");
	(void) fprintf(stderr,
	    "flowop delay name=<name>,value=<number-of-seconds>\n");
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr, "flowop eventlimit name=<name>\n");
	(void) fprintf(stderr, "flowop bwlimit name=<name>,value=<mb/s>\n");
	(void) fprintf(stderr, "flowop iopslimit name=<name>,value=<iop/s>\n");
	(void) fprintf(stderr,
	    "flowop finishoncount name=<name>,value=<ops/s>\n");
	(void) fprintf(stderr,
	    "flowop finishonbytes name=<name>,value=<bytes>\n");
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr, "\n");
}
