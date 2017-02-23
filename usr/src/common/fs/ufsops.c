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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_inode.h>
#include <sys/sysmacros.h>
#include <sys/bootvfs.h>
#include <sys/filep.h>

#ifdef	_BOOT
#include "../common/util.h"
#else
#include <sys/sunddi.h>
#endif

extern void *bkmem_alloc(size_t);
extern void bkmem_free(void *, size_t);
extern int cf_check_compressed(fileid_t *);
extern void cf_close(fileid_t *);
extern void cf_seek(fileid_t *, off_t, int);
extern int cf_read(fileid_t *, caddr_t, size_t);

int bootrd_debug;
#ifdef _BOOT
#define	dprintf	if (bootrd_debug) printf
#else
#define	printf	kobj_printf
#define	dprintf	if (bootrd_debug) kobj_printf

/* PRINTLIKE */
extern void kobj_printf(char *, ...);
#endif

/*
 * This fd is used when talking to the device file itself.
 */
static fileid_t *head;

/* Only got one of these...ergo, only 1 fs open at once */
/* static */
devid_t		*ufs_devp;

struct dirinfo {
	int 	loc;
	fileid_t *fi;
};

static	int	bufs_close(int);
static	void	bufs_closeall(int);
static 	ino_t	find(fileid_t *filep, char *path);
static	ino_t	dlook(fileid_t *filep, char *path);
static 	daddr32_t	sbmap(fileid_t *filep, daddr32_t bn);
static  struct direct *readdir(struct dirinfo *dstuff);
static	void set_cache(int, void *, uint_t);
static	void *get_cache(int);
static	void free_cache();


/*
 *	There is only 1 open (mounted) device at any given time.
 *	So we can keep a single, global devp file descriptor to
 *	use to index into the di[] array.  This is not true for the
 *	fi[] array.  We can have more than one file open at once,
 *	so there is no global fd for the fi[].
 *	The user program must save the fd passed back from open()
 *	and use it to do subsequent read()'s.
 */

static int
openi(fileid_t *filep, ino_t inode)
{
	struct dinode *dp;
	devid_t *devp = filep->fi_devp;

	filep->fi_inode = get_cache((int)inode);
	if (filep->fi_inode != 0)
		return (0);

	filep->fi_offset = 0;
	filep->fi_blocknum = fsbtodb(&devp->un_fs.di_fs,
	    itod(&devp->un_fs.di_fs, inode));

	/* never more than 1 disk block */
	filep->fi_count = devp->un_fs.di_fs.fs_bsize;
	filep->fi_memp = 0;		/* cached read */
	if (diskread(filep) != 0) {
		return (0);
	}

	dp = (struct dinode *)filep->fi_memp;
	filep->fi_inode = (struct inode *)
	    bkmem_alloc(sizeof (struct inode));
	bzero((char *)filep->fi_inode, sizeof (struct inode));
	filep->fi_inode->i_ic =
	    dp[itoo(&devp->un_fs.di_fs, inode)].di_un.di_icom;
	filep->fi_inode->i_number = inode;
	set_cache((int)inode, (void *)filep->fi_inode, sizeof (struct inode));
	return (0);
}

static fileid_t *
find_fp(int fd)
{
	fileid_t *filep = head;

	if (fd >= 0) {
		while ((filep = filep->fi_forw) != head)
			if (fd == filep->fi_filedes)
				return (filep->fi_taken ? filep : 0);
	}

	return (0);
}

static ino_t
find(fileid_t *filep, char *path)
{
	char *q;
	char c;
	ino_t inode;
	char lpath[MAXPATHLEN];
	char *lpathp = lpath;
	int len, r;
	devid_t	*devp;

	if (path == NULL || *path == '\0') {
		printf("null path\n");
		return ((ino_t)0);
	}

	dprintf("openi: %s\n", path);

	bzero(lpath, sizeof (lpath));
	bcopy(path, lpath, strlen(path));
	devp = filep->fi_devp;
	while (*lpathp) {
		/* if at the beginning of pathname get root inode */
		r = (lpathp == lpath);
		if (r && openi(filep, (ino_t)UFSROOTINO))
			return ((ino_t)0);
		while (*lpathp == '/')
			lpathp++;	/* skip leading slashes */
		q = lpathp;
		while (*q != '/' && *q != '\0')
			q++;		/* find end of component */
		c = *q;
		*q = '\0';		/* terminate component */

		/* Bail out early if opening root */
		if (r && (*lpathp == '\0'))
			return ((ino_t)UFSROOTINO);
		if ((inode = dlook(filep, lpathp)) != 0) {
			if (openi(filep, inode))
				return ((ino_t)0);
			if ((filep->fi_inode->i_smode & IFMT) == IFLNK) {
				filep->fi_blocknum =
				    fsbtodb(&devp->un_fs.di_fs,
				    filep->fi_inode->i_db[0]);
				filep->fi_count = DEV_BSIZE;
				filep->fi_memp = 0;
				if (diskread(filep) != 0)
					return ((ino_t)0);
				len = strlen(filep->fi_memp);
				if (filep->fi_memp[0] == '/')
					/* absolute link */
					lpathp = lpath;
				/* copy rest of unprocessed path up */
				bcopy(q, lpathp + len, strlen(q + 1) + 2);
				/* point to unprocessed path */
				*(lpathp + len) = c;
				/* prepend link in before unprocessed path */
				bcopy(filep->fi_memp, lpathp, len);
				lpathp = lpath;
				continue;
			} else
				*q = c;
			if (c == '\0')
				break;
			lpathp = q;
			continue;
		} else {
			return ((ino_t)0);
		}
	}
	return (inode);
}

static daddr32_t
sbmap(fileid_t *filep, daddr32_t bn)
{
	struct inode *inodep;
	int i, j, sh;
	daddr32_t nb, *bap;
	daddr32_t *db;
	devid_t	*devp;

	devp = filep->fi_devp;
	inodep = filep->fi_inode;
	db = inodep->i_db;

	/*
	 * blocks 0..NDADDR are direct blocks
	 */
	if (bn < NDADDR) {
		nb = db[bn];
		return (nb);
	}

	/*
	 * addresses NIADDR have single and double indirect blocks.
	 * the first step is to determine how many levels of indirection.
	 */
	sh = 1;
	bn -= NDADDR;
	for (j = NIADDR; j > 0; j--) {
		sh *= NINDIR(&devp->un_fs.di_fs);
		if (bn < sh)
			break;
		bn -= sh;
	}
	if (j == 0) {
		return ((daddr32_t)0);
	}

	/*
	 * fetch the first indirect block address from the inode
	 */
	nb = inodep->i_ib[NIADDR - j];
	if (nb == 0) {
		return ((daddr32_t)0);
	}

	/*
	 * fetch through the indirect blocks
	 */
	for (; j <= NIADDR; j++) {
		filep->fi_blocknum = fsbtodb(&devp->un_fs.di_fs, nb);
		filep->fi_count = devp->un_fs.di_fs.fs_bsize;
		filep->fi_memp = 0;
		if (diskread(filep) != 0)
			return (0);
		bap = (daddr32_t *)filep->fi_memp;
		sh /= NINDIR(&devp->un_fs.di_fs);
		i = (bn / sh) % NINDIR(&devp->un_fs.di_fs);
		nb = bap[i];
		if (nb == 0) {
			return ((daddr32_t)0);
		}
	}
	return (nb);
}

static ino_t
dlook(fileid_t *filep, char *path)
{
	struct direct *dp;
	struct inode *ip;
	struct dirinfo dirp;
	int len;

	ip = filep->fi_inode;
	if (path == NULL || *path == '\0')
		return (0);

	dprintf("dlook: %s\n", path);

	if ((ip->i_smode & IFMT) != IFDIR) {
		return (0);
	}
	if (ip->i_size == 0) {
		return (0);
	}
	len = strlen(path);
	dirp.loc = 0;
	dirp.fi = filep;
	for (dp = readdir(&dirp); dp != NULL; dp = readdir(&dirp)) {
		if (dp->d_ino == 0)
			continue;
		if (dp->d_namlen == len && strcmp(path, dp->d_name) == 0) {
			return (dp->d_ino);
		}
		/* Allow "*" to print all names at that level, w/out match */
		if (strcmp(path, "*") == 0)
			dprintf("%s\n", dp->d_name);
	}
	return (0);
}

/*
 * get next entry in a directory.
 */
struct direct *
readdir(struct dirinfo *dstuff)
{
	struct direct *dp;
	fileid_t *filep;
	daddr32_t lbn, d;
	int off;
	devid_t	*devp;

	filep = dstuff->fi;
	devp = filep->fi_devp;
	for (;;) {
		if (dstuff->loc >= filep->fi_inode->i_size) {
			return (NULL);
		}
		off = blkoff(&devp->un_fs.di_fs, dstuff->loc);
		dprintf("readdir: off = 0x%x\n", off);
		if (off == 0) {
			lbn = lblkno(&devp->un_fs.di_fs, dstuff->loc);
			d = sbmap(filep, lbn);

			if (d == 0)
				return (NULL);

			filep->fi_blocknum = fsbtodb(&devp->un_fs.di_fs, d);
			filep->fi_count =
			    blksize(&devp->un_fs.di_fs, filep->fi_inode, lbn);
			filep->fi_memp = 0;
			if (diskread(filep) != 0) {
				return (NULL);
			}
		}
		dp = (struct direct *)(filep->fi_memp + off);
		dstuff->loc += dp->d_reclen;
		if (dp->d_ino == 0)
			continue;
		dprintf("readdir: name = %s\n", dp->d_name);
		return (dp);
	}
}

/*
 * Get the next block of data from the file.  If possible, dma right into
 * user's buffer
 */
static int
getblock(fileid_t *filep, caddr_t buf, int count, int *rcount)
{
	struct fs *fs;
	caddr_t p;
	int off, size, diff;
	daddr32_t lbn;
	devid_t	*devp;

	dprintf("getblock: buf 0x%p, count 0x%x\n", (void *)buf, count);

	devp = filep->fi_devp;
	p = filep->fi_memp;
	if ((signed)filep->fi_count <= 0) {

		/* find the amt left to be read in the file */
		diff = filep->fi_inode->i_size - filep->fi_offset;
		if (diff <= 0) {
			printf("Short read\n");
			return (-1);
		}

		fs = &devp->un_fs.di_fs;
		/* which block (or frag) in the file do we read? */
		lbn = lblkno(fs, filep->fi_offset);

		/* which physical block on the device do we read? */
		filep->fi_blocknum = fsbtodb(fs, sbmap(filep, lbn));

		off = blkoff(fs, filep->fi_offset);

		/* either blksize or fragsize */
		size = blksize(fs, filep->fi_inode, lbn);
		filep->fi_count = size;
		filep->fi_memp = filep->fi_buf;

		/*
		 * optimization if we are reading large blocks of data then
		 * we can go directly to user's buffer
		 */
		*rcount = 0;
		if (off == 0 && count >= size) {
			filep->fi_memp = buf;
			if (diskread(filep)) {
				return (-1);
			}
			*rcount = size;
			filep->fi_count = 0;
			return (0);
		} else if (diskread(filep))
			return (-1);

		if (filep->fi_offset - off + size >= filep->fi_inode->i_size)
			filep->fi_count = diff + off;
		filep->fi_count -= off;
		p = &filep->fi_memp[off];
	}
	filep->fi_memp = p;
	return (0);
}

/*
 * Get the next block of data from the file.  Don't attempt to go directly
 * to user's buffer.
 */
static int
getblock_noopt(fileid_t *filep)
{
	struct fs *fs;
	caddr_t p;
	int off, size, diff;
	daddr32_t lbn;
	devid_t	*devp;

	dprintf("getblock_noopt: start\n");

	devp = filep->fi_devp;
	p = filep->fi_memp;
	if ((signed)filep->fi_count <= 0) {

		/* find the amt left to be read in the file */
		diff = filep->fi_inode->i_size - filep->fi_offset;
		if (diff <= 0) {
			printf("Short read\n");
			return (-1);
		}

		fs = &devp->un_fs.di_fs;
		/* which block (or frag) in the file do we read? */
		lbn = lblkno(fs, filep->fi_offset);

		/* which physical block on the device do we read? */
		filep->fi_blocknum = fsbtodb(fs, sbmap(filep, lbn));

		off = blkoff(fs, filep->fi_offset);

		/* either blksize or fragsize */
		size = blksize(fs, filep->fi_inode, lbn);
		filep->fi_count = size;
		/* reading on a ramdisk, just get a pointer to the data */
		filep->fi_memp = NULL;

		if (diskread(filep))
			return (-1);

		if (filep->fi_offset - off + size >= filep->fi_inode->i_size)
			filep->fi_count = diff + off;
		filep->fi_count -= off;
		p = &filep->fi_memp[off];
	}
	filep->fi_memp = p;
	return (0);
}


/*
 *  This is the high-level read function.  It works like this.
 *  We assume that our IO device buffers up some amount of
 *  data and that we can get a ptr to it.  Thus we need
 *  to actually call the device func about filesize/blocksize times
 *  and this greatly increases our IO speed.  When we already
 *  have data in the buffer, we just return that data (with bcopy() ).
 */

static ssize_t
bufs_read(int fd, caddr_t buf, size_t count)
{
	size_t i, j;
	caddr_t	n;
	int rcount;
	fileid_t *filep;

	if (!(filep = find_fp(fd))) {
		return (-1);
	}

	if ((filep->fi_flags & FI_COMPRESSED) == 0 &&
	    filep->fi_offset + count > filep->fi_inode->i_size)
		count = filep->fi_inode->i_size - filep->fi_offset;

	/* that was easy */
	if ((i = count) == 0)
		return (0);

	n = buf;
	while (i > 0) {
		if (filep->fi_flags & FI_COMPRESSED) {
			if ((j = cf_read(filep, buf, count)) < 0)
				return (0); /* encountered an error */
			if (j < i)
				i = j; /* short read, must have hit EOF */
		} else {
			/* If we need to reload the buffer, do so */
			if ((j = filep->fi_count) == 0) {
				(void) getblock(filep, buf, i, &rcount);
				i -= rcount;
				buf += rcount;
				filep->fi_offset += rcount;
				continue;
			} else {
				/* else just bcopy from our buffer */
				j = MIN(i, j);
				bcopy(filep->fi_memp, buf, (unsigned)j);
			}
		}
		buf += j;
		filep->fi_memp += j;
		filep->fi_offset += j;
		filep->fi_count -= j;
		i -= j;
	}
	return (buf - n);
}

/*
 *	This routine will open a device as it is known by the V2 OBP.
 *	Interface Defn:
 *	err = mountroot(string);
 *		err = 0 on success
 *		err = -1 on failure
 *	string:	char string describing the properties of the device.
 *	We must not dork with any fi[]'s here.  Save that for later.
 */

static int
bufs_mountroot(char *str)
{
	if (ufs_devp)		/* already mounted */
		return (0);

	ufs_devp = (devid_t *)bkmem_alloc(sizeof (devid_t));
	ufs_devp->di_taken = 1;
	ufs_devp->di_dcookie = 0;
	ufs_devp->di_desc = (char *)bkmem_alloc(strlen(str) + 1);
	(void) strcpy(ufs_devp->di_desc, str);
	bzero(ufs_devp->un_fs.dummy, SBSIZE);
	head = (fileid_t *)bkmem_alloc(sizeof (fileid_t));
	head->fi_back = head->fi_forw = head;
	head->fi_filedes = 0;
	head->fi_taken = 0;

	/* Setup read of the superblock */
	head->fi_devp = ufs_devp;
	head->fi_blocknum = SBLOCK;
	head->fi_count = (uint_t)SBSIZE;
	head->fi_memp = (caddr_t)&(ufs_devp->un_fs.di_fs);
	head->fi_offset = 0;

	if (diskread(head)) {
		printf("failed to read superblock\n");
		(void) bufs_closeall(1);
		return (-1);
	}

	if (ufs_devp->un_fs.di_fs.fs_magic != FS_MAGIC) {
		dprintf("fs magic = 0x%x\n", ufs_devp->un_fs.di_fs.fs_magic);
		(void) bufs_closeall(1);
		return (-1);
	}
	dprintf("mountroot succeeded\n");
	return (0);
}

/*
 * Unmount the currently mounted root fs.  In practice, this means
 * closing all open files and releasing resources.  All of this
 * is done by closeall().
 */

static int
bufs_unmountroot(void)
{
	if (ufs_devp == NULL)
		return (-1);

	(void) bufs_closeall(1);

	return (0);
}

/*
 *	We allocate an fd here for use when talking
 *	to the file itself.
 */

/*ARGSUSED*/
static int
bufs_open(char *filename, int flags)
{
	fileid_t	*filep;
	ino_t	inode;
	static int	filedes = 1;

	dprintf("open: %s\n", filename);

	/* build and link a new file descriptor */
	filep = (fileid_t *)bkmem_alloc(sizeof (fileid_t));
	filep->fi_back = head->fi_back;
	filep->fi_forw = head;
	head->fi_back->fi_forw = filep;
	head->fi_back = filep;
	filep->fi_filedes = filedes++;
	filep->fi_taken = 1;
	filep->fi_path = (char *)bkmem_alloc(strlen(filename) + 1);
	(void) strcpy(filep->fi_path, filename);
	filep->fi_devp = ufs_devp; /* dev is already "mounted" */
	filep->fi_inode = NULL;
	bzero(filep->fi_buf, MAXBSIZE);
	filep->fi_getblock = getblock_noopt;
	filep->fi_flags = 0;

	inode = find(filep, (char *)filename);
	if (inode == (ino_t)0) {
		dprintf("open: cannot find %s\n", filename);
		(void) bufs_close(filep->fi_filedes);
		return (-1);
	}
	if (openi(filep, inode)) {
		printf("open: cannot open %s\n", filename);
		(void) bufs_close(filep->fi_filedes);
		return (-1);
	}

	filep->fi_offset = filep->fi_count = 0;

	if (cf_check_compressed(filep) != 0)
		return (-1);
	return (filep->fi_filedes);
}

/*
 *  We don't do any IO here.
 *  We just play games with the device pointers.
 */

static off_t
bufs_lseek(int fd, off_t addr, int whence)
{
	fileid_t *filep;

	/* Make sure user knows what file they are talking to */
	if (!(filep = find_fp(fd)))
		return (-1);

	if (filep->fi_flags & FI_COMPRESSED) {
		cf_seek(filep, addr, whence);
	} else {
		switch (whence) {
		case SEEK_CUR:
			filep->fi_offset += addr;
			break;
		case SEEK_SET:
			filep->fi_offset = addr;
			break;
		default:
		case SEEK_END:
			printf("lseek(): invalid whence value %d\n", whence);
			break;
		}
		filep->fi_blocknum = addr / DEV_BSIZE;
	}

	filep->fi_count = 0;

	return (0);
}


int
bufs_fstat(int fd, struct bootstat *stp)
{
	fileid_t	*filep;
	struct inode	*ip;

	if (!(filep = find_fp(fd)))
		return (-1);

	ip = filep->fi_inode;

	stp->st_mode = 0;
	stp->st_size = 0;

	if (ip == NULL)
		return (0);

	switch (ip->i_smode & IFMT) {
	case IFLNK:
		stp->st_mode = S_IFLNK;
		break;
	case IFREG:
		stp->st_mode = S_IFREG;
		break;
	default:
		break;
	}
	/*
	 * NOTE: this size will be the compressed size for a compressed file
	 * This could confuse the caller since we decompress the file behind
	 * the scenes when the file is read.
	 */
	stp->st_size = ip->i_size;
	stp->st_atim.tv_sec = ip->i_atime.tv_sec;
	stp->st_atim.tv_nsec = ip->i_atime.tv_usec * 1000;
	stp->st_mtim.tv_sec = ip->i_mtime.tv_sec;
	stp->st_mtim.tv_nsec = ip->i_mtime.tv_usec * 1000;
	stp->st_ctim.tv_sec = ip->i_ctime.tv_sec;
	stp->st_ctim.tv_nsec = ip->i_ctime.tv_usec * 1000;

	return (0);
}


static int
bufs_close(int fd)
{
	fileid_t *filep;

	/* Make sure user knows what file they are talking to */
	if (!(filep = find_fp(fd)))
		return (-1);

	if (filep->fi_taken && (filep != head)) {
		/* Clear the ranks */
		bkmem_free(filep->fi_path, strlen(filep->fi_path)+1);
		filep->fi_blocknum = filep->fi_count = filep->fi_offset = 0;
		filep->fi_memp = (caddr_t)0;
		filep->fi_devp = 0;
		filep->fi_taken = 0;

		/* unlink and deallocate node */
		filep->fi_forw->fi_back = filep->fi_back;
		filep->fi_back->fi_forw = filep->fi_forw;
		cf_close(filep);
		bkmem_free((char *)filep, sizeof (fileid_t));

		return (0);
	} else {
		/* Big problem */
		printf("\nFile descrip %d not allocated!", fd);
		return (-1);
	}
}

/*ARGSUSED*/
static void
bufs_closeall(int flag)
{
	fileid_t *filep = head;

	while ((filep = filep->fi_forw) != head)
		if (filep->fi_taken)
			if (bufs_close(filep->fi_filedes))
				printf("Filesystem may be inconsistent.\n");

	ufs_devp->di_taken = 0;
	bkmem_free((char *)ufs_devp, sizeof (devid_t));
	bkmem_free((char *)head, sizeof (fileid_t));
	ufs_devp = (devid_t *)NULL;
	head = (fileid_t *)NULL;
	free_cache();
}

static struct cache {
	struct cache *next;
	void *data;
	int key;
	uint_t size;
} *icache;

void
set_cache(int key, void *data, uint_t size)
{
	struct cache *entry = bkmem_alloc(sizeof (*entry));
	entry->key = key;
	entry->data = data;
	entry->size = size;
	if (icache) {
		entry->next = icache;
		icache = entry;
	} else {
		icache = entry;
		entry->next = 0;
	}
}

void *
get_cache(int key)
{
	struct cache *entry = icache;
	while (entry) {
		if (entry->key == key)
			return (entry->data);
		entry = entry->next;
	}
	return (NULL);
}

void
free_cache()
{
	struct cache *next, *entry = icache;
	while (entry) {
		next = entry->next;
		bkmem_free(entry->data, entry->size);
		bkmem_free(entry, sizeof (*entry));
		entry = next;
	}
	icache = 0;
}

struct boot_fs_ops bufs_ops = {
	"boot_ufs",
	bufs_mountroot,
	bufs_unmountroot,
	bufs_open,
	bufs_close,
	bufs_read,
	bufs_lseek,
	bufs_fstat,
	NULL
};
