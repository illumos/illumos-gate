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
 * Copyright 2025 MNX Cloud, Inc.
 */

/*
 * Basic file system reading code for standalone I/O system.
 * Simulates a primitive UNIX I/O system (read(), write(), open(), etc).
 * Does not support writes.
 */

#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_inode.h>

#include <sys/fs/hsfs_spec.h>
#include <sys/fs/hsfs_isospec.h>
#include <sys/fs/hsfs_node.h>
#include <sys/fs/hsfs_susp.h>
#include <sys/fs/hsfs_rrip.h>
#include <sys/bootvfs.h>
#include <sys/kobj.h>
#include <sys/filep.h>
#include <sys/sunddi.h>

#define	hdbtodb(n)	((ISO_SECTOR_SIZE / DEV_BSIZE) * (n))

#define	HSFS_NUM_SIG    14

#define	SUSP_SP_IX	0
#define	SUSP_CE_IX	1
#define	SUSP_PD_IX	2
#define	SUSP_ST_IX	3
#define	SUSP_ER_IX	4
#define	RRIP_PX_IX	5
#define	RRIP_PN_IX	6
#define	RRIP_SL_IX	7
#define	RRIP_CL_IX	8
#define	RRIP_PL_IX	9
#define	RRIP_RE_IX	10
#define	RRIP_RF_IX	11
#define	RRIP_RR_IX	12
#define	RRIP_NM_IX	13

extern int bootrd_debug;
extern void *bkmem_alloc(size_t);
extern void bkmem_free(void *, size_t);
extern int cf_check_compressed(fileid_t *);
extern void cf_close(fileid_t *);
extern void cf_seek(fileid_t *, off_t, int);
extern int cf_read(fileid_t *, caddr_t, size_t);

struct dirstuff {
	int loc;
	fileid_t *filep;
};

struct hs_direct {
    struct	direct  hs_ufs_dir;
    struct	hs_direntry hs_dir;
};

static uint_t root_ino = 0;
static struct hs_volume *hsfsp;
static fileid_t *head;

static char *hsfs_sig_tab[] = {
	SUSP_SP,
	SUSP_CE,
	SUSP_PD,
	SUSP_ST,
	SUSP_ER,
	RRIP_PX,
	RRIP_PN,
	RRIP_SL,
	RRIP_CL,
	RRIP_PL,
	RRIP_RE,
	RRIP_TF,
	RRIP_RR,
	RRIP_NM
};

static int hsfs_num_sig = sizeof (hsfs_sig_tab) / sizeof (hsfs_sig_tab[0]);

/*
 *  Local prototypes
 */
static struct hs_direct *readdir(struct dirstuff *);
static uint_t parse_dir(fileid_t *, int, struct hs_direct *);
static uint_t parse_susp(char *, uint_t *, struct hs_direct *);
static ino_t dlook(char *, fileid_t *);
static int opendir(ino_t, fileid_t *);
static ino_t find(char *, fileid_t *);

static int bhsfs_mountroot(char *str);
static int bhsfs_unmountroot(void);
static int bhsfs_open(char *str, int flags);
static int bhsfs_close(int fd);
static void bhsfs_closeall(void);
static ssize_t bhsfs_read(int fdesc, char *buf, size_t count);
static off_t bhsfs_lseek(int fdesc, off_t addr, int whence);
static int bhsfs_fstat(int fdesc, struct bootstat *stp);

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

static int
opendir(ino_t inode, fileid_t *filep)
{
	struct hs_direct hsdep;

	if (bootrd_debug)
		kobj_printf("opendir: inode = %ld\n", inode);
	/* Set up the IO request */
	filep->fi_offset = 0;
	filep->fi_blocknum = hdbtodb(inode);
	filep->fi_count = ISO_SECTOR_SIZE;
	filep->fi_memp = 0;

	if (diskread(filep))
		return (0);

	filep->fi_offset = 0;
	filep->fi_blocknum = hdbtodb(inode);

	if (inode != root_ino)
		return (0);

	if (parse_dir(filep, 0, &hsdep) > 0) {
		struct inode *ip;

		ip = filep->fi_inode;
		if (ip == NULL)
			ip = filep->fi_inode = bkmem_alloc(sizeof (*ip));

		ip->i_size = hsdep.hs_dir.ext_size;
		ip->i_smode = hsdep.hs_dir.mode;
		ip->i_number = inode;
		return (0);
	}
	return (1);
}

static ino_t
find(char *path, fileid_t *filep)
{
	char *q;
	char c;
	ino_t n;

	n = 0;
	if (bootrd_debug)
		kobj_printf("find: %s\n", path);
	if (path == NULL || *path == '\0')
		return (0);

	if (opendir(root_ino, filep))
		return (0);

	while (*path) {
		while (*path == '/')
			path++;
		q = path;
		while (*q != '/' && *q != '\0')
			q++;
		c = *q;
		*q = '\0';
		n = dlook(path, filep);
		*q = c;
		path = q;

		if (n != 0) {
			if (c == '\0')
				break;
			if (opendir(n, filep))
				return (0);
			continue;
		} else {
			return (0);
		}
	}
	return ((ino_t)n);
}

static ino_t
dlook(char *s, fileid_t *filep)
{
	struct hs_direct *hsdep;
	struct direct *udp;
	struct inode *ip;
	struct dirstuff dirp;
	int len;

	if (bootrd_debug)
		kobj_printf("dlook: %s\n", s);
	ip = filep->fi_inode;
	if (s == NULL || *s == '\0')
		return (0);
	if ((ip->i_smode & IFMT) != IFDIR) {
		return (0);
	}
	if (ip->i_size == 0) {
		return (0);
	}
	len = strlen(s);
	dirp.loc = 0;
	dirp.filep = filep;
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
		if (udp->d_namlen == len && (strcmp(s, udp->d_name)) == 0) {
			struct inode *ip = filep->fi_inode;

			filep->fi_offset = 0;
			filep->fi_blocknum = hdbtodb(udp->d_ino);

			bzero(filep->fi_inode, sizeof (struct inode));
			ip->i_size = hsdep->hs_dir.ext_size;
			ip->i_smode = hsdep->hs_dir.mode;
			ip->i_number = udp->d_ino;
			return (udp->d_ino);
		}
	}
	return (0);
}

/*
 * get next entry in a directory.
 */
static struct hs_direct *
readdir(struct dirstuff *dirp)
{
	static struct hs_direct hsdep;
	struct direct *udp = &hsdep.hs_ufs_dir;
	struct inode *ip;
	fileid_t *filep;
	daddr_t lbn;
	int off;

	if (bootrd_debug)
		kobj_printf("readdir: start\n");
	filep = dirp->filep;
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
			filep->fi_memp = 0;
			if (diskread(filep)) {
				if (bootrd_debug) {
					kobj_printf(
					    "readdir: diskread failed\n");
				}
				return (NULL);
			}
		}
		dirp->loc += parse_dir(filep, off, &hsdep);
		if (udp->d_reclen == 0 && dirp->loc <= ip->i_size) {
			dirp->loc = roundup(dirp->loc, ISO_SECTOR_SIZE);
			continue;
		}
		return (&hsdep);
	}
}

static int
getblock(fileid_t *filep)
{
	struct inode *ip = filep->fi_inode;
	int off, size, diff;
	daddr_t lbn;

	if (bootrd_debug)
		kobj_printf("getblock: start\n");
	diff = ip->i_size - filep->fi_offset;
	if (diff <= 0)
		return (-1);

	/* which block (or frag) in the file do we read? */
	lbn = hdbtodb(filep->fi_offset >> ISO_SECTOR_SHIFT);
	filep->fi_blocknum = lbn + hdbtodb(ip->i_number);

	off = filep->fi_offset & ((1 << ISO_SECTOR_SHIFT) - 1);
	size = filep->fi_count = ISO_SECTOR_SIZE;
	filep->fi_memp = 0;
	if (diskread(filep))	/* Trap errors */
		return (-1);

	if (filep->fi_offset - off + size >= ip->i_size)
		filep->fi_count = diff + off;
	filep->fi_count -= off;
	filep->fi_memp += off;
	if (bootrd_debug)
		kobj_printf("getblock: end\n");
	return (0);
}

static ssize_t
bhsfs_read(int fd, caddr_t buf, size_t count)
{
	int i, j;
	fileid_t *filep;
	struct inode *ip;
	caddr_t n;

	if (bootrd_debug)
		kobj_printf("bhsfs_read %d, count 0x%lx\n", fd, count);
	filep = find_fp(fd);
	if (filep == NULL)
		return (-1);

	ip = filep->fi_inode;
	n = buf;
	if ((filep->fi_flags & FI_COMPRESSED) == 0 &&
	    filep->fi_offset + count > ip->i_size)
		count = ip->i_size - filep->fi_offset;

	if ((i = count) <= 0)
		return (0);

	while (i > 0) {
		if (filep->fi_flags & FI_COMPRESSED) {
			if ((j = cf_read(filep, buf, count)) < 0)
				return (0); /* encountered an error */
			if (j < i)
				i = j; /* short read, must have hit EOF */
		} else {
			if (filep->fi_count == 0) {
				if (getblock(filep) == -1)
					return (0);
			}
			j = MIN(i, filep->fi_count);
			bcopy(filep->fi_memp, buf, (uint_t)j);
		}
		filep->fi_memp += j;
		filep->fi_offset += j;
		filep->fi_count -= j;
		buf += j;
		i -= j;
	}

	if (bootrd_debug)
		kobj_printf("bhsfs_read: read 0x%x\n", (int)(buf - n));
	return (buf - n);
}

static int
bhsfs_mountroot(char *str __unused)
{
	char *bufp;

	if (hsfsp != NULL)
		return (0);	/* already mounted */

	if (bootrd_debug)
		kobj_printf("mounting ramdisk as hsfs\n");

	hsfsp = bkmem_alloc(sizeof (*hsfsp));
	bzero(hsfsp, sizeof (*hsfsp));
	head = bkmem_alloc(sizeof (*head));
	bzero(head, sizeof (*head));
	head->fi_back = head->fi_forw = head;

	/* now read the superblock. */
	head->fi_blocknum = hdbtodb(ISO_VOLDESC_SEC);
	head->fi_offset = 0;
	head->fi_count = ISO_SECTOR_SIZE;
	head->fi_memp = head->fi_buf;
	if (diskread(head)) {
		kobj_printf("failed to read superblock\n");
		bhsfs_closeall();
		return (-1);
	}

	/* Since RRIP is based on ISO9660, that's where we start */
	bufp = head->fi_buf;
	if ((ISO_DESC_TYPE(bufp) != ISO_VD_PVD) ||
	    (strncmp((const char *)ISO_std_id(bufp), ISO_ID_STRING,
	    ISO_ID_STRLEN) != 0) || (ISO_STD_VER(bufp) != ISO_ID_VER)) {
		if (bootrd_debug)
			kobj_printf("volume type does not match\n");
		bhsfs_closeall();
		return (-1);
	}

	/* Now we fill in the volume descriptor */
	hsfsp->vol_size = ISO_VOL_SIZE(bufp);
	hsfsp->lbn_size = ISO_BLK_SIZE(bufp);
	hsfsp->lbn_shift = ISO_SECTOR_SHIFT;
	hsfsp->lbn_secshift = ISO_SECTOR_SHIFT;
	hsfsp->vol_set_size = (ushort_t)ISO_SET_SIZE(bufp);
	hsfsp->vol_set_seq = (ushort_t)ISO_SET_SEQ(bufp);

	/* Make sure we have a valid logical block size */
	if (hsfsp->lbn_size & ~(1 << hsfsp->lbn_shift)) {
		kobj_printf("%d invalid logical block size\n", hsfsp->lbn_size);
		bhsfs_closeall();
		return (-1);
	}

	/* Since an HSFS root could be located anywhere on the media! */
	root_ino = IDE_EXT_LBN(ISO_root_dir(bufp));
	return (0);
}

static int
bhsfs_unmountroot(void)
{
	if (hsfsp == NULL)
		return (-1);

	bhsfs_closeall();

	return (0);
}

/*
 * Open a file.
 */
int
bhsfs_open(char *str, int flags __unused)
{
	static int filedes = 1;

	fileid_t *filep;
	ino_t ino;

	if (bootrd_debug)
		kobj_printf("open %s\n", str);
	filep = (fileid_t *)bkmem_alloc(sizeof (fileid_t));
	filep->fi_back = head->fi_back;
	filep->fi_forw = head;
	head->fi_back->fi_forw = filep;
	head->fi_back = filep;
	filep->fi_filedes = filedes++;
	filep->fi_taken = 1;
	filep->fi_path = (char *)bkmem_alloc(strlen(str) + 1);
	(void) strcpy(filep->fi_path, str);
	filep->fi_inode = NULL;
	bzero(filep->fi_buf, MAXBSIZE);
	filep->fi_getblock = getblock;
	filep->fi_flags = 0;

	ino = find(str, filep);
	if (ino == 0) {
		(void) bhsfs_close(filep->fi_filedes);
		return (-1);
	}

	filep->fi_blocknum = hdbtodb(ino);
	filep->fi_offset = 0;
	filep->fi_count = 0;
	filep->fi_memp = 0;

	if (cf_check_compressed(filep) != 0)
		return (-1);
	if (bootrd_debug)
		kobj_printf("open done\n");
	return (filep->fi_filedes);
}

int
bhsfs_close(int fd)
{
	fileid_t *filep;

	if (bootrd_debug)
		kobj_printf("close %d\n", fd);
	if (!(filep = find_fp(fd)))
		return (-1);

	if (filep->fi_taken == 0 || filep == head) {
		kobj_printf("File descripter %d not allocated!\n", fd);
		return (-1);
	}

	cf_close(filep);
	/* unlink and deallocate node */
	filep->fi_forw->fi_back = filep->fi_back;
	filep->fi_back->fi_forw = filep->fi_forw;
	if (filep->fi_inode)
		bkmem_free(filep->fi_inode, sizeof (struct inode));
	bkmem_free(filep->fi_path, strlen(filep->fi_path) + 1);
	bkmem_free((char *)filep, sizeof (fileid_t));
	if (bootrd_debug)
		kobj_printf("close done\n");
	return (0);
}

static void
bhsfs_closeall(void)
{
	fileid_t *filep;

	while ((filep = head->fi_forw) != head)
		if (filep->fi_taken && bhsfs_close(filep->fi_filedes))
			kobj_printf("Filesystem may be inconsistent.\n");

	bkmem_free(hsfsp, sizeof (*hsfsp));
	bkmem_free(head, sizeof (fileid_t));
	hsfsp = NULL;
	head = NULL;
}

/*
 * This version of seek() only performs absolute seeks (whence == 0).
 */
static off_t
bhsfs_lseek(int fd, off_t addr, int whence)
{
	fileid_t *filep;

	if (bootrd_debug)
		kobj_printf("lseek %d, off = %lx\n", fd, addr);
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
			kobj_printf("lseek(): invalid whence value %d\n",
			    whence);
			break;
		}
		filep->fi_blocknum = addr / DEV_BSIZE;
	}

	filep->fi_count = 0;
	return (0);
}

static int
bhsfs_fstat(int fd, struct bootstat *stp)
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
	/*
	 * NOTE: this size will be the compressed size for a compressed file
	 * This could confuse the caller since we decompress the file behind
	 * the scenes when the file is read.
	 */
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
 * Parse a directory entry.
 *
 */
static uint_t
parse_dir(fileid_t *filep, int offset, struct hs_direct *hsdep)
{
	char *bufp = (char *)(filep->fi_memp + offset);
	struct direct *udp = &hsdep->hs_ufs_dir;  /* ufs-style dir info */
	struct hs_direntry *hdp = &hsdep->hs_dir; /* hsfs-style dir info */
	uint_t ce_lbn;
	uint_t ce_len;
	uint_t nmlen;
	uint_t i;
	uchar_t c;

	if (bootrd_debug)
		kobj_printf("parse_dir: offset = %d\n", offset);
	/* a zero length dir entry terminates the dir block */
	udp->d_reclen = IDE_DIR_LEN(bufp);
	if (udp->d_reclen == 0)
		return (0);

	/* fill in some basic hsfs info */
	hdp->ext_lbn  = IDE_EXT_LBN(bufp);
	hdp->ext_size = IDE_EXT_SIZE(bufp);
	hdp->xar_len  = IDE_XAR_LEN(bufp);
	hdp->intlf_sz = IDE_INTRLV_SIZE(bufp);
	hdp->intlf_sk = IDE_INTRLV_SKIP(bufp);
	hdp->sym_link = NULL;

	/* we use lbn of data extent as an inode # equivalent */
	udp->d_ino	= hdp->ext_lbn;

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
		kobj_printf("pd(): file type=0x%x unknown.\n", c);
	}

	/*
	 * Massage hsfs name, recognizing special entries for . and ..
	 * else lopping off version junk.
	 */

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

	if (ce_len == 0)
		return (udp->d_reclen);

	/* there is an SUA for this dir entry; go parse it */
	ce_lbn = parse_susp((char *)IDE_sys_use_area(bufp), &ce_len, hsdep);

	if (ce_lbn) {
		/*
		 * store away current position in dir,
		 * as we will be using the iobuf to reading SUA.
		 */
		daddr_t save_bn = filep->fi_blocknum;
		daddr_t save_offset = filep->fi_offset;
		caddr_t save_ma = filep->fi_memp;
		int save_cc = filep->fi_count;
		do {
			filep->fi_count = ISO_SECTOR_SIZE;
			filep->fi_offset = 0;
			filep->fi_blocknum = hdbtodb(ce_lbn);
			filep->fi_memp = 0;
			if (diskread(filep)) {
				kobj_printf("failed to read cont. area\n");
				ce_len = 0;
				ce_lbn = 0;
				break;
			}
			ce_lbn = parse_susp(filep->fi_memp, &ce_len,
			    hsdep);
		} while (ce_lbn);
		filep->fi_count = save_cc;
		filep->fi_offset = save_offset;
		filep->fi_blocknum = save_bn;
		filep->fi_memp = save_ma;
	}
	return (udp->d_reclen);
}

/*
 * Parse the System Use Fields in this System Use Area.
 * Return blk number of continuation/SUA, or 0 if no continuation/not a SUA.
 */
static uint_t
parse_susp(char *bufp, uint_t *len, struct hs_direct *hsdep)
{
	struct direct *udp = &hsdep->hs_ufs_dir; /* ufs-style info */
	char *susp;
	uint_t cur_off = 0;
	uint_t blk_len = *len;
	uint_t susp_len = 0;
	uint_t ce_lbn = 0;
	uint_t i;

	if (bootrd_debug)
		kobj_printf("parse_susp: len = %d\n", *len);
	while (cur_off < blk_len) {
		susp = (char *)(bufp + cur_off);

		/*
		 * A null entry, or an entry with zero length
		 * terminates the SUSP.
		 */
		if (susp[0] == '\0' || susp[1] == '\0' ||
		    (susp_len = SUF_LEN(susp)) == 0)
			break;

		/*
		 * Compare current entry to all known signatures.
		 */
		for (i = 0; i < hsfs_num_sig; i++)
			if (strncmp(hsfs_sig_tab[i], susp, SUF_SIG_LEN) == 0)
				break;
		switch (i) {
		case SUSP_CE_IX:
			/*
			 * CE signature: continuation of SUSP.
			 * will want to return new lbn, len.
			 */
			ce_lbn = CE_BLK_LOC(susp);
			*len = CE_CONT_LEN(susp);
			break;
		case RRIP_NM_IX:
			/* NM signature: POSIX-style file name */
			if (!RRIP_NAME_FLAGS(susp)) {
				udp->d_namlen = RRIP_NAME_LEN(susp);
				bcopy((char *)RRIP_name(susp),
				    udp->d_name, udp->d_namlen);
				udp->d_name[udp->d_namlen] = '\0';
			}
			break;
		case HSFS_NUM_SIG:
			/* couldn't find a legit susp, terminate loop */
		case SUSP_ST_IX:
			/* ST signature: terminates SUSP */
			return (ce_lbn);
		case SUSP_SP_IX:
		case RRIP_RR_IX:
		default:
			break;
		}
		cur_off += susp_len;
	}
	return (ce_lbn);
}

struct boot_fs_ops bhsfs_ops = {
	"boot_hsfs",
	bhsfs_mountroot,
	bhsfs_unmountroot,
	bhsfs_open,
	bhsfs_close,
	bhsfs_read,
	bhsfs_lseek,
	bhsfs_fstat,
	NULL
};
