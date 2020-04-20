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

#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_inode.h>
#include <sys/sysmacros.h>
#include <sys/promif.h>
#include <sys/filep.h>
#include <sys/salib.h>
#include <sys/sacache.h>

#include <sys/fs/hsfs_spec.h>
#include <sys/fs/hsfs_isospec.h>
#include <sys/fs/hsfs_node.h>
#include <sys/fs/hsfs_susp.h>
#include <sys/fs/hsfs_rrip.h>

#include "hsfs_sig.h"

#include <sys/stat.h>
#include <sys/bootvfs.h>
#include <sys/bootconf.h>
#include <sys/bootdebug.h>

#define	hdbtodb(n)	((ISO_SECTOR_SIZE / DEV_BSIZE) * (n))

#define	THE_EPOCH	1970
#define	END_OF_TIME	2099

/* May not need this... */
static uint_t	sua_offset = 0;

/* The root inode on an HSFS filesystem can be anywhere! */
static uint_t	root_ino = 0;		/* This is both a flag and a value */

static fileid_t *head;

/* Only got one of these...ergo, only 1 fs open at once */
static devid_t *devp;

struct dirinfo {
	int 	loc;
	fileid_t *fi;
};

struct hs_direct {
    struct	direct	hs_ufs_dir;
    struct	hs_direntry hs_dir;
};

/*
 *  Function prototypes
 */

static int	boot_hsfs_mountroot(char *str);
static int	boot_hsfs_unmountroot(void);
static int	boot_hsfs_open(char *filename, int flags);
static int	boot_hsfs_close(int fd);
static ssize_t	boot_hsfs_read(int fd, caddr_t buf, size_t size);
static off_t	boot_hsfs_lseek(int, off_t, int);
static int	boot_hsfs_fstat(int fd, struct bootstat *stp);
static void	boot_hsfs_closeall(int flag);
static int	boot_hsfs_getdents(int fd, struct dirent *dep, unsigned size);

struct boot_fs_ops boot_hsfs_ops = {
	"hsfs",
	boot_hsfs_mountroot,
	boot_hsfs_unmountroot,
	boot_hsfs_open,
	boot_hsfs_close,
	boot_hsfs_read,
	boot_hsfs_lseek,
	boot_hsfs_fstat,
	boot_hsfs_closeall,
	boot_hsfs_getdents
};

static 	ino_t	find(fileid_t *, char *);
static	ino_t	dlook(fileid_t *, char *);
static	int	opendir(fileid_t *, ino_t);
static	struct	hs_direct *readdir(struct dirinfo *);
static	uint_t	parse_dir(fileid_t *, int, struct hs_direct *);
static	uint_t	parse_susp(char *, uint_t *, struct hs_direct *);
static	void	hs_seti(fileid_t *,  struct hs_direct *, ino_t);
static void	hs_dodates(enum hs_vol_type, struct hs_direntry *, char *);
static time_t	hs_date_to_gmtime(int, int, int, int);

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
opendir(fileid_t *filep, ino_t inode)
{
	struct hs_direct hsdep;
	int retval;

	/* Set up the saio request */
	filep->fi_offset = 0;
	filep->fi_blocknum = hdbtodb(inode);
	filep->fi_count = ISO_SECTOR_SIZE;

	/* Maybe the block is in the disk block cache */
	if ((filep->fi_memp = get_bcache(filep)) == NULL) {
		/* Not in the block cache so read it from disk */
		if (retval = set_bcache(filep)) {
			return (retval);
		}
	}

	filep->fi_offset = 0;
	filep->fi_blocknum = hdbtodb(inode);

	if (inode != root_ino)
		return (0);

	if ((int)(parse_dir(filep, 0, &hsdep)) > 0) {
		hs_seti(filep, &hsdep, inode);
		return (0);
	}
	return (1);
}

static ino_t
find(fileid_t *filep, char *path)
{
	register char *q;
	char c;
	ino_t inode;

	if (path == NULL || *path == '\0') {
		printf("null path\n");
		return (0);
	}

	if ((boothowto & RB_DEBUG) && (boothowto & RB_VERBOSE))
		printf("find(): path=<%s>\n", path);

	/* Read the ROOT directory */
	if (opendir(filep, inode = root_ino)) {
		printf("find(): root_ino opendir() failed!\n");
		return ((ino_t)-1);
	}

	while (*path) {
		while (*path == '/')
			path++;
		if (*(q = path) == '\0')
			break;
		while (*q != '/' && *q != '\0')
			q++;
		c = *q;
		*q = '\0';

		if ((inode = dlook(filep, path)) != 0) {
			if (c == '\0')
				break;
			if (opendir(filep, inode)) {
				printf("find(): opendir(%d) failed!\n", inode);
				*q = c;
				return ((ino_t)-1);
			}
			*q = c;
			path = q;
			continue;
		} else {
			*q = c;
			return (0);
		}
	}
	return (inode);
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
dlook(fileid_t *filep, char *path)
{
	int dv = filep->fi_devp->di_dcookie;
	register struct hs_direct *hsdep;
	register struct direct *udp;
	register struct inode *ip;
	struct dirinfo dirp;
	register int len;
	ino_t in;

	ip = filep->fi_inode;
	if (path == NULL || *path == '\0')
		return (0);
	if ((ip->i_smode & IFMT) != IFDIR) {
		return (0);
	}
	if (ip->i_size == 0) {
		return (0);
	}
	len = strlen(path);
	/* first look through the directory entry cache */
	if (in = get_dcache(dv, path, ip->i_number)) {
		if ((filep->fi_inode = get_icache(dv, in)) != NULL) {
			filep->fi_offset = 0;
			filep->fi_blocknum = hdbtodb(in);
			return (in);
		}
	}
	dirp.loc = 0;
	dirp.fi = filep;
	for (hsdep = readdir(&dirp); hsdep != NULL; hsdep = readdir(&dirp)) {
		udp = &hsdep->hs_ufs_dir;
		if (udp->d_namlen == 1 &&
		    udp->d_name[0] == '.' &&
		    udp->d_name[1] == '\0')
			continue;
		if (udp->d_namlen == 2 &&
		    udp->d_name[0] == '.' &&
		    udp->d_name[1] == '.' &&
		    udp->d_name[2] == '\0')
			continue;
		if (udp->d_namlen == len && (strcmp(path, udp->d_name) == 0)) {
			set_dcache(dv, path, ip->i_number, udp->d_ino);
			hs_seti(filep, hsdep, udp->d_ino);
			filep->fi_offset = 0;
			filep->fi_blocknum = hdbtodb(udp->d_ino);
			/* put this entry into the cache */
			return (udp->d_ino);
		}
		/* Allow "*" to print all names at that level, w/out match */
		if (strcmp(path, "*") == 0)
			printf("%s\n", udp->d_name);
	}
	return (0);
}

/*
 * get next entry in a directory.
 */
static struct hs_direct *
readdir(struct dirinfo *dirp)
{
	static struct hs_direct hsdep;
	register struct direct *udp = &hsdep.hs_ufs_dir;
	register struct inode *ip;
	register fileid_t *filep;
	register daddr_t lbn;
	register int off;

	filep = dirp->fi;
	ip = filep->fi_inode;
	for (;;) {
		if (dirp->loc >= ip->i_size) {
			return (NULL);
		}
		off = dirp->loc & ((1 << ISO_SECTOR_SHIFT) - 1);
		if (off == 0) {
			lbn = hdbtodb(dirp->loc >> ISO_SECTOR_SHIFT);
			filep->fi_blocknum = lbn + hdbtodb(ip->i_number);
			filep->fi_count = ISO_SECTOR_SIZE;
			/* check the block cache */
			if ((filep->fi_memp = get_bcache(filep)) == 0)
				if (set_bcache(filep))
					return ((struct hs_direct *)-1);
		}
		dirp->loc += parse_dir(filep, off, &hsdep);
		if (udp->d_reclen == 0 && dirp->loc <= ip->i_size) {
			dirp->loc = roundup(dirp->loc, ISO_SECTOR_SIZE);
			continue;
		}
		return (&hsdep);
	}
}

/*
 * Get the next block of data from the file.  If possible, dma right into
 * user's buffer
 */
static int
getblock(fileid_t *filep, caddr_t buf, int count, int *rcount)
{
	register struct inode *ip;
	register caddr_t p;
	register int off, size, diff;
	register daddr_t lbn;
	static int	pos;
	static char 	ind[] = "|/-\\";	/* that's entertainment? */
	static int	blks_read;

	ip = filep->fi_inode;
	p = filep->fi_memp;
	if ((signed)filep->fi_count <= 0) {

		/* find the amt left to be read in the file */
		diff = ip->i_size - filep->fi_offset;
		if (diff <= 0) {
			printf("Short read\n");
			return (-1);
		}

		/* which block (or frag) in the file do we read? */
		lbn = hdbtodb(filep->fi_offset >> ISO_SECTOR_SHIFT);

		/* which physical block on the device do we read? */
		filep->fi_blocknum = lbn + hdbtodb(ip->i_number);

		off = filep->fi_offset & ((1 << ISO_SECTOR_SHIFT) - 1);

		size = sizeof (filep->fi_buf);
		if (size > ISO_SECTOR_SIZE)
			size = ISO_SECTOR_SIZE;

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
			read_opt++;
			if ((blks_read++ & 0x3) == 0)
				printf("%c\b", ind[pos++ & 3]);
			return (0);
		} else
			if (diskread(filep))
				return (-1);

		/*
		 * round and round she goes (though not on every block..
		 * - OBP's take a fair bit of time to actually print stuff)
		 */
		if ((blks_read++ & 0x3) == 0)
			printf("%c\b", ind[pos++ & 3]);

		if (filep->fi_offset - off + size >= ip->i_size)
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
 *  data ant that we can get a ptr to it.  Thus we need
 *  to actually call the device func about filesize/blocksize times
 *  and this greatly increases our IO speed.  When we already
 *  have data in the buffer, we just return that data (with bcopy() ).
 */

static ssize_t
boot_hsfs_read(int fd, caddr_t buf, size_t count)
{
	size_t i, j;
	struct inode *ip;
	caddr_t	n;
	fileid_t *filep;
	int rcount;

	if (!(filep = find_fp(fd))) {
		return (-1);
	}

	ip = filep->fi_inode;

	if (filep->fi_offset + count > ip->i_size)
		count = ip->i_size - filep->fi_offset;

	/* that was easy */
	if ((i = count) == 0)
		return (0);

	n = buf;
	while (i > 0) {
		/* If we need to reload the buffer, do so */
		if ((j = filep->fi_count) == 0) {
			(void) getblock(filep, buf, i, &rcount);
			i -= rcount;
			buf += rcount;
			filep->fi_offset += rcount;
		} else {
			/* else just bcopy from our buffer */
			j = MIN(i, j);
			bcopy(filep->fi_memp, buf, (unsigned)j);
			buf += j;
			filep->fi_memp += j;
			filep->fi_offset += j;
			filep->fi_count -= j;
			i -= j;
		}
	}
	return (buf - n);
}

/*
 *	This routine will open a device as it is known by the
 *	V2 OBP.
 *	Interface Defn:
 *	err = mountroot(string);
 *	err:	0 on success
 *		-1 on failure
 *	string:	char string describing the properties of the device.
 *	We must not dork with any fi[]'s here.  Save that for later.
 */

static int
boot_hsfs_mountroot(char *str)
{
	ihandle_t	h;
	struct hs_volume *fsp;
	char 		*bufp;

	if ((boothowto & RB_DEBUG) && (boothowto & RB_VERBOSE))
		printf("mountroot()\n");

	/*
	 * If already mounted, just return success.
	 */
	if (root_ino != 0) {
		return (0);
	}

	h = prom_open(str);

	if (h == 0) {
		printf("Cannot open %s\n", str);
		return (-1);
	}

	devp = (devid_t *)bkmem_alloc(sizeof (devid_t));
	devp->di_taken = 1;
	devp->di_dcookie = h;
	devp->di_desc = (char *)bkmem_alloc(strlen(str) + 1);
	(void) strcpy(devp->di_desc, str);
	bzero(devp->un_fs.dummy, sizeof (devp->un_fs.dummy));
	head = (fileid_t *)bkmem_alloc(sizeof (fileid_t));
	head->fi_back = head->fi_forw = head;
	head->fi_filedes = 0;
	head->fi_taken = 0;

	/* Setup read of the "superblock" */
	bzero(head->fi_buf, sizeof (head->fi_buf));
	head->fi_devp = devp;
	head->fi_blocknum = hdbtodb(ISO_VOLDESC_SEC);
	head->fi_count = ISO_SECTOR_SIZE;
	head->fi_memp = head->fi_buf;
	head->fi_offset = 0;

	if (diskread(head)) {
		printf("mountroot(): read super block failed!\n");
		boot_hsfs_closeall(1);
		return (-1);
	}

	bufp = head->fi_memp;
	fsp = (struct hs_volume *)devp->un_fs.dummy;
	/* Since RRIP is based on ISO9660, that's where we start */

	if (ISO_DESC_TYPE(bufp) != ISO_VD_PVD ||
	    strncmp((char *)(ISO_std_id(bufp)), (char *)(ISO_ID_STRING),
	    ISO_ID_STRLEN) != 0 || ISO_STD_VER(bufp) != ISO_ID_VER) {
		boot_hsfs_closeall(1);
		return (-1);
	}

	/* Now we fill in the volume descriptor */
	fsp->vol_size = ISO_VOL_SIZE(bufp);
	fsp->lbn_size = ISO_BLK_SIZE(bufp);
	fsp->lbn_shift = ISO_SECTOR_SHIFT;
	fsp->lbn_secshift = ISO_SECTOR_SHIFT;
	fsp->vol_set_size = (ushort_t)ISO_SET_SIZE(bufp);
	fsp->vol_set_seq = (ushort_t)ISO_SET_SEQ(bufp);

	/* Make sure we have a valid logical block size */
	if (fsp->lbn_size & ~(1 << fsp->lbn_shift)) {
		printf("%d byte logical block size invalid.\n", fsp->lbn_size);
		boot_hsfs_closeall(1);
		return (-1);
	}

	/* Since an HSFS root could be located anywhere on the media! */
	root_ino = IDE_EXT_LBN(ISO_root_dir(bufp));

	if ((boothowto & RB_DEBUG) && (boothowto & RB_VERBOSE)) {
		int	i;

		printf("root_ino=%d\n", root_ino);
		printf("ID=");
		for (i = 0; i < ISO_ID_STRLEN; i++)
			printf("%c", *(ISO_std_id(bufp)+i));
		printf(" VS=%d\n", fsp->vol_size);
	}

	return (0);
}

/*
 * Unmount the currently mounted root fs.  In practice, this means
 * closing all open files and releasing resources.  All of this
 * is done by boot_hsfs_closeall().
 */

int
boot_hsfs_unmountroot(void)
{
	if (root_ino == 0)
		return (-1);

	boot_hsfs_closeall(1);

	return (0);
}

/*
 *	We allocate an fd here for use when talking
 *	to the file itself.
 */

/*ARGSUSED*/
static int
boot_hsfs_open(char *filename, int flags)
{
	fileid_t	*filep;
	ino_t		inode;
	static int	filedes = 1;

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
	filep->fi_devp = devp; /* dev is already "mounted" */

	filep->fi_inode = 0;

	inode = find(filep, filename);
	if (inode == (ino_t)0) {
		if ((boothowto & RB_DEBUG) && (boothowto & RB_VERBOSE))
			printf("open(%s) ENOENT\n", filename);
		(void) boot_hsfs_close(filep->fi_filedes);
		return (-1);
	}

	filep->fi_blocknum = hdbtodb(inode);
	filep->fi_offset = filep->fi_count = 0;

	if ((boothowto & RB_DEBUG) && (boothowto & RB_VERBOSE))
		printf("open(%s) fd=%d\n", filename, filep->fi_filedes);
	return (filep->fi_filedes);
}

/*
 * hsfs_fstat() only supports size, mode and times at present time.
 */

static int
boot_hsfs_fstat(int fd, struct bootstat *stp)
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
	case IFDIR:
		stp->st_mode = S_IFDIR;
		break;
	case IFREG:
		stp->st_mode = S_IFREG;
		break;
	default:
		break;
	}
	stp->st_size = ip->i_size;

	/* file times */
	stp->st_atim.tv_sec = ip->i_atime.tv_sec;
	stp->st_atim.tv_nsec = ip->i_atime.tv_usec * 1000;
	stp->st_mtim.tv_sec = ip->i_mtime.tv_sec;
	stp->st_mtim.tv_nsec = ip->i_mtime.tv_usec * 1000;
	stp->st_ctim.tv_sec = ip->i_ctime.tv_sec;
	stp->st_ctim.tv_nsec = ip->i_ctime.tv_usec * 1000;

	return (0);
}

/*
 *  We don't do any IO here.
 *  We just play games with the device pointers.
 */

/*ARGSUSED*/
static off_t
boot_hsfs_lseek(int fd, off_t addr, int whence)
{
	fileid_t *filep;

	if (!(filep = find_fp(fd)))
		return (-1);

	filep->fi_offset = addr;
	filep->fi_blocknum = addr / DEV_BSIZE;
	filep->fi_count = 0;

	return (0);
}

static int
boot_hsfs_close(int fd)
{
	fileid_t *filep;

	if ((boothowto & RB_DEBUG) && (boothowto & RB_VERBOSE))
		printf("close(%d)\n", fd);

	if (filep = find_fp(fd)) {
		/* Clear the ranks */
		bkmem_free(filep->fi_path, strlen(filep->fi_path)+1);
		filep->fi_blocknum = filep->fi_count = filep->fi_offset = 0;
		filep->fi_memp = (caddr_t)0;
		filep->fi_devp = 0;
		filep->fi_taken = 0;

		/* unlink and deallocate node */
		filep->fi_forw->fi_back = filep->fi_back;
		filep->fi_back->fi_forw = filep->fi_forw;
		bkmem_free((char *)filep, sizeof (fileid_t));

		return (0);
	} else {
		/* Big problem */
		printf("\nFile descrip %d not allocated!", fd);
		return (-1);
	}
}

/* closeall is now idempotent */
/*ARGSUSED*/
static void
boot_hsfs_closeall(int flag)
{
	fileid_t	*filep = head;
	extern int verbosemode;

	if (devp == NULL) {
		if (head)
			prom_panic("boot_hsfs_closeall: head != NULL.\n");
		return;
	}

	while ((filep = filep->fi_forw) != head)
		if (filep->fi_taken)
			if (boot_hsfs_close(filep->fi_filedes))
				prom_panic("Filesystem may be inconsistent.\n");


	release_cache(devp->di_dcookie);
	(void) prom_close(devp->di_dcookie);
	devp->di_taken = 0;
	if (verbosemode)
		print_cache_data();
	bkmem_free((char *)devp, sizeof (devid_t));
	bkmem_free((char *)head, sizeof (fileid_t));
	root_ino = 0;
	devp = NULL;
	head = NULL;
}

static uint_t
parse_dir(fileid_t *filep, int offset, struct hs_direct *hsdep)
{
	char *bufp = (char *)(filep->fi_memp + offset);
	struct direct *udp = &hsdep->hs_ufs_dir;
	struct hs_direntry *hdp = &hsdep->hs_dir;
	uint_t ce_lbn;
	uint_t ce_len;
	uint_t nmlen;
	uint_t i;
	uchar_t c;
	int ret_code = 0;

	if ((udp->d_reclen = IDE_DIR_LEN(bufp)) == 0)
		return (0);

	hdp->ext_lbn  = IDE_EXT_LBN(bufp);
	hdp->ext_size = IDE_EXT_SIZE(bufp);
	hs_dodates(HS_VOL_TYPE_ISO, hdp, bufp);
	hdp->xar_len  = IDE_XAR_LEN(bufp);
	hdp->intlf_sz = IDE_INTRLV_SIZE(bufp);
	hdp->intlf_sk = IDE_INTRLV_SKIP(bufp);
	hdp->sym_link = NULL;

	udp->d_ino = hdp->ext_lbn;

	c = IDE_FLAGS(bufp);
	if (IDE_REGULAR_FILE(c)) {
		hdp->type = VREG;
		hdp->mode = IFREG;
		hdp->nlink = 1;
	} else if (IDE_REGULAR_DIR(c)) {
		hdp->type = VDIR;
		hdp->mode = IFDIR;
		hdp->nlink = 2;
	} else {
		printf("parse_dir(): file type=0x%x unknown.\n", c);
		return ((uint_t)-1);
	}

	/* Some initial conditions */
	nmlen = IDE_NAME_LEN(bufp);
	c = *IDE_NAME(bufp);
	/* Special Case: Current Directory */
	if (nmlen == 1 && c == '\0') {
		udp->d_name[0] = '.';
		udp->d_name[1] = '\0';
		udp->d_namlen = 1;
	/* Special Case: Parent Directory */
	} else if (nmlen == 1 && c == '\001') {
		udp->d_name[0] = '.';
		udp->d_name[1] = '.';
		udp->d_name[2] = '\0';
		udp->d_namlen = 2;
	/* Other file name */
	} else {
		udp->d_namlen = 0;
		for (i = 0; i < nmlen; i++) {
			c = *(IDE_name(bufp)+i);
			if (c == ';')
				break;
			else if (c == ' ')
				continue;
			else
				udp->d_name[udp->d_namlen++] = c;
		}
		udp->d_name[udp->d_namlen] = '\0';
	}
	/* System Use Fields */
	ce_len = IDE_SUA_LEN(bufp);
	ce_lbn = 0;
	if ((int)(ce_len) > 0) {
		ce_lbn = parse_susp((char *)IDE_sys_use_area(bufp),
		    &ce_len, hsdep);
		while (ce_lbn) {
			daddr_t save_blocknum = filep->fi_blocknum;
			daddr_t save_offset = filep->fi_offset;
			caddr_t save_memp = filep->fi_memp;
			uint_t save_count = filep->fi_count;

#ifdef	noisy
			print_io_req(filep, "parse_dir(): [I]");
#endif	/* noisy */

			filep->fi_blocknum = hdbtodb(ce_lbn);
			filep->fi_offset = 0;
			filep->fi_count = ISO_SECTOR_SIZE;

#ifdef	noisy
			print_io_req(filep, "parse_dir(): [0]");
#endif	/* noisy */

			if ((filep->fi_memp = get_bcache(filep)) == 0)
				ret_code = set_bcache(filep);

#ifdef	noisy
			print_io_req(filep, "parse_dir(): [1]");
#endif	/* noisy */

			if (ret_code) {
				filep->fi_blocknum = save_blocknum;
				filep->fi_offset = save_offset;
				filep->fi_memp = save_memp;
				filep->fi_count = save_count;
				printf("parse_dir(): "
				    "set_bcache() failed (%d)\n", ret_code);
				break;
			}
			ce_lbn = parse_susp(filep->fi_memp, &ce_len, hsdep);

			filep->fi_blocknum = save_blocknum;
			filep->fi_offset = save_offset;
			filep->fi_memp = save_memp;
			filep->fi_count = save_count;

#ifdef	noisy
			print_io_req(filep, "parse_dir(): [2]");
#endif	/* noisy */
		}
	}

	return (udp->d_reclen);
}

static uint_t
parse_susp(char *bufp, uint_t *ce_len, struct hs_direct *hsdep)
{
	struct direct *udp = &hsdep->hs_ufs_dir;
	uchar_t *susp;
	uint_t cur_off = 0;
	uint_t blk_len = *ce_len;
	uint_t susp_len = 0;
	uint_t ce_lbn = 0;
	uint_t i;

	while (cur_off < blk_len) {
		susp = (uchar_t *)(bufp + cur_off);
		if (susp[0] == '\0' || susp[1] == '\0')
			break;
		susp_len = SUF_LEN(susp);
		if (susp_len == 0)
			break;
		for (i = 0; i < hsfs_num_sig; i++) {
			if (strncmp(hsfs_sig_tab[i],
			    (char *)susp, SUF_SIG_LEN) == 0) {
#ifdef	noisy
				if ((boothowto & RB_DEBUG) &&
				    (boothowto & RB_VERBOSE))
					printf("  SUSP_%c%c %d\n",
					    susp[0], susp[1], susp_len);
#endif	/* noisy */
				switch (i) {
				case SUSP_SP_IX:
					if (CHECK_BYTES_OK(susp)) {
						sua_offset =
						    SP_SUA_OFFSET(susp);
#ifdef	lint
						/* this may not be needed */
						i = (int)sua_offset;
#endif	/* lint */
					}
					break;

				case SUSP_CE_IX:
					ce_lbn = CE_BLK_LOC(susp);
					*ce_len = CE_CONT_LEN(susp);
#ifdef	noisy
					if ((boothowto & RB_DEBUG) &&
					    (boothowto & RB_VERBOSE))
						printf("parse_susp(): "
						    "CE: ce_lbn = %d "
						    "ce_len=%d\n",
						    ce_lbn, *ce_len);
#endif	/* noisy */
					break;

				case SUSP_ST_IX:
					printf("parse_susp(): ST: returning "
					    "%d\n", ce_lbn);
					return (ce_lbn);

				case RRIP_SL_IX:
#ifdef	noisy
					if ((boothowto & RB_DEBUG) &&
					    (boothowto & RB_VERBOSE))
						printf("parse_susp(): "
						    "******* SL *******\n");
#endif	/* noisy */
					break;

				case RRIP_RR_IX:
					break;

				case RRIP_NM_IX:
					if (!RRIP_NAME_FLAGS(susp)) {
						udp->d_namlen =
						    RRIP_NAME_LEN(susp);
						bcopy((char *)RRIP_name(susp),
						    (char *)udp->d_name,
						    udp->d_namlen);
						udp->d_name
						    [udp->d_namlen] = '\0';
					}
					break;
				}
				cur_off += susp_len;
				break;
			}
		}
		if (i > hsfs_num_sig) {
			printf("parse_susp(): Bad SUSP\n");
			cur_off = blk_len;
			break;
		}
	}
	return (ce_lbn);
}

static void
hs_seti(fileid_t *filep, struct hs_direct *hsdep, ino_t inode)
{
	register struct inode *ip;
	int dv = filep->fi_devp->di_dcookie;

	/* Try the inode cache first */
	if ((filep->fi_inode = get_icache(dv, inode)) != NULL)
		return;

	filep->fi_inode = (struct inode *)bkmem_alloc(sizeof (struct inode));
	ip = filep->fi_inode;
	bzero((char *)ip, sizeof (struct inode));
	ip->i_size = hsdep->hs_dir.ext_size;
	ip->i_smode = hsdep->hs_dir.mode;
	ip->i_number = inode;
	ip->i_atime.tv_sec = hsdep->hs_dir.adate.tv_sec;
	ip->i_atime.tv_usec = hsdep->hs_dir.adate.tv_usec;
	ip->i_ctime.tv_sec = hsdep->hs_dir.cdate.tv_sec;
	ip->i_ctime.tv_usec = hsdep->hs_dir.cdate.tv_usec;
	ip->i_mtime.tv_sec = hsdep->hs_dir.mdate.tv_sec;
	ip->i_mtime.tv_usec = hsdep->hs_dir.mdate.tv_usec;
	set_icache(dv, inode, ip, sizeof (struct inode));
}

#ifdef	noisy
static void
print_io_req(fileid_t *filep, char *str)
{
	printf("%s o=%d b=%d c=%d m=%x\n",
	    str,
	    filep->fi_offset,
	    filep->fi_blocknum,
	    filep->fi_count,
	    (uint_t)filep->fi_memp);
}
#endif	/* noisy */

static int
boot_hsfs_getdents(int fd, struct dirent *dep, unsigned size)
{
	/*
	 * Read directory entries from the file open on "fd" into the
	 * "size"-byte buffer at "dep" until the buffer is exhausted
	 * or we reach EOF on the directory.  Returns the number of
	 * entries read.
	 */
	int n;
	int cnt = 0;
	struct dirinfo dir;
	struct hs_direct *hdp;
	unsigned long oldoff, oldblok;

#define	SLOP (sizeof (struct dirent) - offsetof(struct dirent, d_name[1]))

	if (!(dir.fi = find_fp(fd)) ||
	    ((dir.fi->fi_inode->i_smode & IFMT) != IFDIR)) {
		/*
		 *  Bogus file descriptor, bail out now!
		 */
		return (-1);
	}

	oldoff = dir.loc = dir.fi->fi_offset;
	oldblok = dir.fi->fi_blocknum;

	for (hdp = readdir(&dir); hdp; hdp = readdir(&dir)) {
		/*
		 * Compute name length and break loop if there's not
		 * enough space in the output buffer for the next
		 * entry.
		 *
		 *  NOTE: "SLOP" is the number of bytes inserted into the dirent
		 *	  struct's "d_name" field by the compiler to preserve
		 *	  alignment.
		 */
		n = strlen(hdp->hs_ufs_dir.d_name);

		n = roundup((sizeof (struct dirent) + ((n > SLOP) ? n : 0)),
		    sizeof (off_t));

		if (n > size) {
			dir.fi->fi_blocknum = oldblok;
			dir.fi->fi_offset = oldoff;
			break;
		}

		oldblok = dir.fi->fi_blocknum;
		oldoff = dir.loc;
		size -= n;
		cnt += 1;

		(void) strlcpy(dep->d_name, hdp->hs_ufs_dir.d_name,
		    strlen(hdp->hs_ufs_dir.d_name) + 1);
		dep->d_ino = hdp->hs_ufs_dir.d_ino;
		dep->d_off = dir.loc;
		dep->d_reclen = (unsigned short)n;

		dep = (struct dirent *)((char *)dep + n);
	}

#undef SLOP

	return (cnt);
}

static void
hs_dodates(enum hs_vol_type type, struct hs_direntry *hdp, char *bufp)
{
	if (type == HS_VOL_TYPE_HS) {
		hs_parse_dirdate(HDE_cdate(bufp), &hdp->cdate);
		hs_parse_dirdate(HDE_cdate(bufp), &hdp->adate);
		hs_parse_dirdate(HDE_cdate(bufp), &hdp->mdate);
	} else if (type == HS_VOL_TYPE_ISO) {
		hs_parse_dirdate(IDE_cdate(bufp), &hdp->cdate);
		hs_parse_dirdate(IDE_cdate(bufp), &hdp->adate);
		hs_parse_dirdate(IDE_cdate(bufp), &hdp->mdate);
	} else
		prom_panic("hs_dodates:  bad volume type");
}

/*
 * hs_parse_dirdate
 *
 * Parse the short 'directory-format' date into a Unix timeval.
 * This is the date format used in Directory Entries.
 *
 * If the date is not representable, make something up.
 */
void
hs_parse_dirdate(uchar_t *dp, struct timeval *tvp)
{
	int year, month, day, hour, minute, sec, gmtoff;

	year = HDE_DATE_YEAR(dp);
	month = HDE_DATE_MONTH(dp);
	day = HDE_DATE_DAY(dp);
	hour = HDE_DATE_HOUR(dp);
	minute = HDE_DATE_MIN(dp);
	sec = HDE_DATE_SEC(dp);
	gmtoff = HDE_DATE_GMTOFF(dp);

	tvp->tv_usec = 0;
	if (year < THE_EPOCH) {
		tvp->tv_sec = 0;
	} else {
		tvp->tv_sec = hs_date_to_gmtime(year, month, day, gmtoff);
		if (tvp->tv_sec != -1) {
			tvp->tv_sec += ((hour * 60) + minute) * 60 + sec;
		}
	}

	return;

}

/*
 * hs_parse_longdate
 *
 * Parse the long 'user-oriented' date into a Unix timeval.
 * This is the date format used in the Volume Descriptor.
 *
 * If the date is not representable, make something up.
 */
void
hs_parse_longdate(uchar_t *dp, struct timeval *tvp)
{
	int year, month, day, hour, minute, sec, gmtoff;

	year = HSV_DATE_YEAR(dp);
	month = HSV_DATE_MONTH(dp);
	day = HSV_DATE_DAY(dp);
	hour = HSV_DATE_HOUR(dp);
	minute = HSV_DATE_MIN(dp);
	sec = HSV_DATE_SEC(dp);
	gmtoff = HSV_DATE_GMTOFF(dp);

	tvp->tv_usec = 0;
	if (year < THE_EPOCH) {
		tvp->tv_sec = 0;
	} else {
		tvp->tv_sec = hs_date_to_gmtime(year, month, day, gmtoff);
		if (tvp->tv_sec != -1) {
			tvp->tv_sec += ((hour * 60) + minute) * 60 + sec;
			tvp->tv_usec = HSV_DATE_HSEC(dp) * 10000;
		}
	}

}

/* cumulative number of seconds per month,  non-leap and leap-year versions */
static time_t cum_sec[] = {
	0x0, 0x28de80, 0x4dc880, 0x76a700, 0x9e3400, 0xc71280,
	0xee9f80, 0x1177e00, 0x1405c80, 0x167e980, 0x190c800, 0x1b85500
};
static time_t cum_sec_leap[] = {
	0x0, 0x28de80, 0x4f1a00, 0x77f880, 0x9f8580, 0xc86400,
	0xeff100, 0x118cf80, 0x141ae00, 0x1693b00, 0x1921980, 0x1b9a680
};
#define	SEC_PER_DAY	0x15180
#define	SEC_PER_YEAR	0x1e13380

/*
 * hs_date_to_gmtime
 *
 * Convert year(1970-2099)/month(1-12)/day(1-31) to seconds-since-1970/1/1.
 *
 * Returns -1 if the date is out of range.
 */
static time_t
hs_date_to_gmtime(int year, int mon, int day, int gmtoff)
{
	time_t sum;
	time_t *cp;
	int y;

	if ((year < THE_EPOCH) || (year > END_OF_TIME) ||
	    (mon < 1) || (mon > 12) ||
	    (day < 1) || (day > 31))
		return (-1);

	/*
	 * Figure seconds until this year and correct for leap years.
	 * Note: 2000 is a leap year but not 2100.
	 */
	y = year - THE_EPOCH;
	sum = y * SEC_PER_YEAR;
	sum += ((y + 1) / 4) * SEC_PER_DAY;
	/*
	 * Point to the correct table for this year and
	 * add in seconds until this month.
	 */
	cp = ((y + 2) % 4) ? cum_sec : cum_sec_leap;
	sum += cp[mon - 1];
	/*
	 * Add in seconds until 0:00 of this day.
	 * (days-per-month validation is not done here)
	 */
	sum += (day - 1) * SEC_PER_DAY;
	sum -= (gmtoff * 15 * 60);
	return (sum);
}
