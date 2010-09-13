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
 *
 * Simple nfs ops - open, close, read, and lseek.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/types.h>
#include <rpc/auth.h>
#include <sys/t_lock.h>
#include "clnt.h"
#include <sys/fcntl.h>
#include <sys/vfs.h>
#include <errno.h>
#include <sys/promif.h>
#include <rpc/xdr.h>
#include "nfs_inet.h"
#include <sys/stat.h>
#include <sys/bootvfs.h>
#include <sys/bootdebug.h>
#include <sys/salib.h>
#include <sys/sacache.h>
#include <rpc/rpc.h>
#include "brpc.h"
#include <rpcsvc/nfs_prot.h>
#include "socket_inet.h"
#include "mac.h"
#include <sys/mode.h>

ushort_t vttoif_tab[] = {
	0, S_IFREG, S_IFDIR, S_IFBLK, S_IFCHR, S_IFLNK, S_IFIFO,
	S_IFDOOR, 0, S_IFSOCK, 0
};

static int file_desc = 1;
static struct nfs_files {
	struct nfs_file file;
	int	desc;
	struct nfs_files *next;
} nfs_files[1] = {
	{0, 0, 0},
};

#define	dprintf	if (boothowto & RB_DEBUG) printf

static int	boot_nfs_open(char *filename, int flags);
static int	boot_nfs_close(int fd);
static ssize_t	boot_nfs_read(int fd, caddr_t buf, size_t size);
static off_t	boot_nfs_lseek(int, off_t, int);
static int	boot_nfs_fstat(int fd, struct bootstat *stp);
static void	boot_nfs_closeall(int flag);
static int	boot_nfs_getdents(int fd, struct dirent *dep, unsigned size);

struct boot_fs_ops boot_nfs_ops = {
	"nfs",
	boot_nfs_mountroot,
	boot_nfs_unmountroot,
	boot_nfs_open,
	boot_nfs_close,
	boot_nfs_read,
	boot_nfs_lseek,
	boot_nfs_fstat,
	boot_nfs_closeall,
	boot_nfs_getdents
};

/*
 * bootops.c calls a closeall() function to close all open files. Since
 * we only permit one open file at a time (not counting the device), this
 * is simple to implement.
 */

/*ARGSUSED*/
static void
boot_nfs_closeall(int flag)
{
	struct nfs_files	*filep;

#ifdef NFS_OPS_DEBUG
	if ((boothowto & DBFLAGS) == DBFLAGS)
		printf("boot_nfs_closeall(%x)\n", flag);
#endif

	if (nfs_files->file.version == 0 &&
	    nfs_files->desc == 0 &&
	    nfs_files->next == NULL)
		return;

	/* delete any dynamically allocated entries */
	while ((filep = nfs_files->next) != NULL) {
		nfs_files->next = filep->next;
		bkmem_free((caddr_t)filep, sizeof (struct  nfs_files));
	}

	/* clear the first, static file */
	bzero((caddr_t)nfs_files, sizeof (struct nfs_files));

	/* Close device */
	release_cache(mac_get_dev());

	mac_fini();
}

/*
 * Get a file pointer given a file descriptor.  Return 0 on error
 */
static struct nfs_files *
get_filep(int fd)
{
	struct nfs_files *filep;

	for (filep = nfs_files; filep; filep = filep->next) {
		if (fd == filep->desc)
			return (filep);
	}
	return (NULL);
}

/*
 * Unmount the root fs -- not supported for this fstype.
 */

int
boot_nfs_unmountroot(void)
{
	return (-1);
}

/*
 * open a file for reading. Note: writing is NOT supported.
 */

static int
boot_nfs_open(char *path, int flags)
{
	struct nfs_files *filep, *newfilep;
	int got_filep;

#ifdef NFS_OPS_DEBUG
	if ((boothowto & DBFLAGS) == DBFLAGS)
		printf("boot_nfs_open(%s, %x)\n", path, flags);
#endif

	/* file can only be opened readonly. */
	if (flags & ~O_RDONLY) {
		dprintf("boot_nfs_open: files can only be opened O_RDONLY.\n");
		return (-1);
	}

	if (path == NULL || *path == '\0') {
		dprintf("boot_nfs_open: NULL or EMPTY pathname argument.\n");
		return (-1);
	}

	/* Try and find a vacant file pointer */
	filep = nfs_files;
	got_filep = FALSE;
	do {
		if (filep->desc == 0) {
			filep->desc = file_desc++;
			got_filep = TRUE;
			break;		/* We've got a file pointer */
		}
		/* Get next entry if not at end of list */
		if (filep->next)
			filep = filep->next;
	} while (filep->next);

	/* If a a vacant file pointer cannot be found, make one */
	if (!got_filep) {
		if ((newfilep = (struct nfs_files *)
		    bkmem_zalloc(sizeof (struct nfs_files))) == 0) {
			dprintf("open: Cannot allocate file pointer\n");
			return (-1);
		}
		filep->next = newfilep;
		filep = newfilep;
		filep->desc = file_desc++;
	}

	if (lookup(path, &filep->file, FALSE) != 0) {
#ifdef NFS_OPS_DEBUG
		if ((boothowto & DBFLAGS) == DBFLAGS)
			printf("boot_nfs_open(): Cannot open '%s'.\n", path);
#endif
		/* zero file pointer */
		bzero((caddr_t)filep, sizeof (struct nfs_file));
		filep->desc = 0;
		return (-1);
	}
	bzero(&filep->file.cookie, sizeof (filep->file.cookie));

#ifdef NFS_OPS_DEBUG
	if ((boothowto & DBFLAGS) == DBFLAGS)
		printf("boot_nfs_open(): '%s' successful, fd = 0x%x\n",
		    path, filep->desc);
#endif
	return (filep->desc);
}

/*
 * close a previously opened file.
 */
static int
boot_nfs_close(int fd)
{
	struct nfs_files *filep;

#ifdef NFS_OPS_DEBUG
	if ((boothowto & DBFLAGS) == DBFLAGS)
		printf("boot_nfs_close(%d)\n", fd);
#endif
	if ((filep = get_filep(fd)) == 0)
		return (0);

	/*
	 * zero file pointer
	 */
	bzero((caddr_t)&filep->file, sizeof (struct nfs_file));

	/*
	 * "close" the fd.
	 */
	filep->desc = 0;

	return (0);
}

/*
 * read from a file.
 */
static ssize_t
boot_nfs_read(int fd, char *buf, size_t size)
{
	struct nfs_files	*filep;
	int			count = 0;

	if (fd == 0) {
		dprintf("boot_nfs_read: Bad file number.\n");
		return (-1);
	}
	if (buf == NULL) {
		dprintf("boot_nfs_read: Bad address.\n");
		return (-1);
	}

#ifdef NFS_OPS_DEBUG
	if ((boothowto & DBFLAGS) == DBFLAGS)
		printf("boot_nfs_read(%d, %x, 0x%x)\n", fd, buf, size);
#endif

	/* initialize for read */
	if ((filep = get_filep(fd)) == 0)
		return (-1);

	switch (filep->file.version) {
	case NFS_VERSION:
		count = nfsread(&filep->file, buf, size);
		break;
	case NFS_V3:
		count = nfs3read(&filep->file, buf, size);
		break;
	case NFS_V4:
		count = nfs4read(&filep->file, buf, size);
		break;
	default:
		printf("boot_nfs_read: NFS Version %d not supported\n",
		    filep->file.version);
		count = -1;
		break;
	}

#ifdef NFS_OPS_DEBUG
	if ((boothowto & DBFLAGS) == DBFLAGS)
		printf("boot_nfs_read(): 0x%x bytes.\n", count);
#endif
	return (count);
}

/*
 * lseek - move read file pointer.
 */

static off_t
boot_nfs_lseek(int fd, off_t offset, int whence)
{
	struct nfs_files *filep;

#ifdef NFS_OPS_DEBUG
	if ((boothowto & DBFLAGS) == DBFLAGS)
		printf("boot_nfs_lseek(%d, 0x%x, %d)\n", fd, offset, whence);
#endif

	if (fd == 0) {
		dprintf("boot_nfs_lseek: Bad file number.\n");
		return (-1);
	}

	if ((filep = get_filep(fd)) == 0)
		return (-1);

	switch (whence) {

	case SEEK_SET:
		/*
		 * file ptr is set to offset from beginning of file
		 */
		filep->file.offset = offset;
		break;
	case SEEK_CUR:
		/*
		 * file ptr is set to offset from current position
		 */
		filep->file.offset += offset;
		break;
	case SEEK_END:
		/*
		 * file ptr is set to current size of file plus offset.
		 * But since we only support reading, this is illegal.
		 */
	default:
		/*
		 * invalid offset origin
		 */
		dprintf("boot_nfs_lseek: invalid whence value.\n");
		return (-1);
	}

#ifdef notyet
	return (filep->file.offset);
#else
	/*
	 * BROKE - lseek should return the offset seeked to on a
	 * successful seek, not zero - This must be fixed in the
	 * kernel before It can be fixed here.
	 */
	return (0);
#endif /* notyet */
}

/*
 * This version of fstat supports mode, size, inode #, and times only.
 * It can be enhanced if more is required,
 */

static int
boot_nfs_fstat(int fd, struct bootstat *stp)
{
	struct vattr va;
	struct nfs_files *filep;
	int status;

#ifdef NFS_OPS_DEBUG
	if ((boothowto & DBFLAGS) == DBFLAGS) {
		printf("boot_nfs_fstat(%d, 0x%x)\n", fd, stp);
	}
#endif
	if (fd == 0) {
		dprintf("boot_nfs_fstat(): Bad file number 0.\n");
		return (-1);
	}

	if ((filep = get_filep(fd)) == 0)
		return (-1);

	bzero((char *)&va, sizeof (va));
	va.va_mask = AT_TYPE | AT_SIZE | AT_MODE | AT_NODEID |
	    AT_ATIME | AT_CTIME | AT_MTIME;

	switch (filep->file.version) {
	case NFS_VERSION:
		status = nfsgetattr(&filep->file, &va);
		break;
	case NFS_V3:
		status = nfs3getattr(&filep->file, &va);
		break;
	case NFS_V4:
		status = nfs4getattr(&filep->file, &va);
		break;
	default:
		printf("boot_nfs_fstat: NFS Version %d not supported\n",
		    filep->file.version);
		status = -1;
		break;
	}

	if (status != 0)
		return (-1);

	if (va.va_size > (u_offset_t)MAXOFF_T) {
		dprintf("boot_nfs_fstat(): File too large.\n");
		return (-1);
	}
	stp->st_size = (off_t)va.va_size;
	stp->st_mode = VTTOIF(va.va_type) | va.va_mode;
	stp->st_atim.tv_sec = va.va_atime.tv_sec;
	stp->st_atim.tv_nsec = va.va_atime.tv_nsec;
	stp->st_ctim.tv_sec = va.va_ctime.tv_sec;
	stp->st_ctim.tv_nsec = va.va_ctime.tv_nsec;
	stp->st_mtim.tv_sec = va.va_mtime.tv_sec;
	stp->st_mtim.tv_nsec = va.va_mtime.tv_nsec;
	stp->st_ino = (ino_t)va.va_nodeid;

#ifdef NFS_OPS_DEBUG
	if ((boothowto & DBFLAGS) == DBFLAGS)
		printf("boot_nfs_fstat(): done.\n");
#endif
	return (0);
}

static int
boot_nfs_getdents(int fd, struct dirent *dep, unsigned size)
{
	struct nfs_files *filep;
	int status;

#ifdef NFS_OPS_DEBUG
	if ((boothowto & DBFLAGS) == DBFLAGS) {
		printf("boot_nfs_getdents(%d, 0x%x, 0x%x)\n", fd, dep, size);
	}
#endif

	if (fd == 0) {
		dprintf("boot_nfs_getdents(): Bad file number 0.\n");
		return (-1);
	}

	if ((filep = get_filep(fd)) == 0)
		return (-1);

	switch (filep->file.version) {
	case NFS_VERSION:
		status = nfsgetdents(&filep->file, dep, size);
		break;
	case NFS_V3:
		status = nfs3getdents(&filep->file, dep, size);
		break;
	default:
		printf("boot_nfs_getdents: NFS Version %d not supported\n",
		    filep->file.version);
		status = -1;
	}

#ifdef NFS_OPS_DEBUG
	if ((boothowto & DBFLAGS) == DBFLAGS)
		printf("boot_nfs_getdents(): done.\n");
#endif
	return (status);
}
