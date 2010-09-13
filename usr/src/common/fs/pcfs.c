/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Basic file system reading code for standalone I/O system.
 * Simulates a primitive UNIX I/O system (read(), write(), open(), etc).
 * Does not support writes.
 */

/*
 * WARNING:
 * This is currently used by installgrub for creating bootable floppy.
 * The special part is diskread_callback/fileread_callback for gathering
 * fileblock list.
 */

#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/vnode.h>
#include <sys/fs/pc_label.h>
#include <sys/bootvfs.h>
#include <sys/filep.h>
#include "pcfilep.h"

#if	defined(_BOOT)
#include "../common/util.h"
#elif	defined(_KERNEL)
#include <sys/sunddi.h>
#else
#include <stdio.h>
#include <strings.h>
#include <ctype.h>
#endif

#if	defined(_BOOT)
#define	dprintf	if (bootrd_debug) printf
#elif	defined(_KERNEL)
#define	printf	kobj_printf
#define	dprintf	if (bootrd_debug) kobj_printf

/* PRINTLIKE */
extern void kobj_printf(char *, ...);
#else
#define	dprintf if (bootrd_debug) printf
#endif

#define	FI_STARTCLUST(fp)	(*(ushort_t *)(fp)->fi_buf)
#define	FI_LENGTH(fp)		(*(long *)((fp)->fi_buf + 4))

extern int bootrd_debug;
extern void *bkmem_alloc(size_t);
extern void bkmem_free(void *, size_t);

/*
 * NOTE: The fileread_callback is set by the calling program
 * during a file read. diskread_callback is set to fileread_callback
 * only if reading a file block. It needs to be NULL while reading
 * cluster blocks.
 */
extern int (*diskread_callback)(int, int);
extern int (*fileread_callback)(int, int);

/*
 *  Local prototypes
 */
static int lookuppn(char *, _dir_entry_p);
static fileid_t *find_fp(int);
static void *readblock(int, int);
static int fat_map(int, int);
static int cluster_valid(long, int);
static int fat_ctodb(int, int);

static int bpcfs_mountroot(char *str);
static int bpcfs_unmountroot(void);
static int bpcfs_open(char *str, int flags);
static int bpcfs_close(int fd);
static void bpcfs_closeall(void);
static ssize_t bpcfs_read(int fdesc, char *buf, size_t count);
static off_t bpcfs_lseek(int fdesc, off_t addr, int whence);

static fileid_t *head;
static _fat_controller_p pcfsp;

/* cache the cluster */
static int nsec_cache;
static int nsec_start;
static char *cluster_cache;

/*ARGSUSED*/
static int
bpcfs_mountroot(char *str)
{
	int ncluster;
	if (pcfsp != NULL)
		return (0);	/* already mounted */

	pcfsp = bkmem_alloc(sizeof (_fat_controller_t));
	head = (fileid_t *)bkmem_alloc(sizeof (fileid_t));
	head->fi_back = head->fi_forw = head;
	head->fi_filedes = 0;
	head->fi_taken = 0;

	/* read of first floppy sector */
	head->fi_blocknum = 0;
	head->fi_count = SECSIZ;
	head->fi_memp = (caddr_t)pcfsp->f_sector;
	if (diskread(head)) {
		printf("failed to read first sector\n");
		bkmem_free(pcfsp, sizeof (*pcfsp));
		pcfsp = NULL;
		return (-1);
	}

	if (pcfsp->f_bpb.bs_spc == 0) {
		printf("invalid bios paramet block\n");
		return (-1);
	}

	pcfsp->f_rootsec =
	    (pcfsp->f_bpb.bs_num_fats * ltohs(pcfsp->f_bpb.bs_spf)) +
	    ltohs(pcfsp->f_bpb.bs_resv_sectors);
	pcfsp->f_rootlen =
	    ltohs(pcfsp->f_bpb.bs_num_root_entries) *
	    sizeof (_dir_entry_t) / SECSIZ;
	pcfsp->f_adjust = 0;
	pcfsp->f_dclust = CLUSTER_ROOTDIR;
	pcfsp->f_filesec = pcfsp->f_rootsec + pcfsp->f_rootlen;
	pcfsp->f_nxtfree = CLUSTER_FIRST;

	/* figure out the number of clusters in this partition */
	ncluster = (((ulong_t)ltohs(pcfsp->f_bpb.bs_siv) ?
	    (ulong_t)ltohs(pcfsp->f_bpb.bs_siv) :
	    (ulong_t)ltohi(pcfsp->f_bpb.bs_siv)) -
	    pcfsp->f_filesec) / (ulong_t)pcfsp->f_bpb.bs_spc;
	pcfsp->f_16bit = ncluster >= CLUSTER_MAX_12;
	pcfsp->f_ncluster = ncluster;

	/* cache the cluster */
	if (pcfsp->f_16bit)
		nsec_cache = (((ncluster << 1) + 511) >> 9);
	else
		nsec_cache = (ncluster + ((ncluster + 1) >> 1) + 511) >> 9;
	cluster_cache = bkmem_alloc(nsec_cache * SECSIZ);
	if (cluster_cache == NULL) {
		printf("bpcfs_mountroot: out of memory\n");
		bkmem_free(pcfsp, sizeof (*pcfsp));
		pcfsp = NULL;
		return (-1);
	}

	head->fi_blocknum = nsec_start =
	    ltohs(pcfsp->f_bpb.bs_resv_sectors) + pcfsp->f_adjust;
	head->fi_count = nsec_cache * SECSIZ;
	head->fi_memp = cluster_cache;
	if (diskread(head)) {
		printf("bpcfs_mountroot: failed to read cluster\n");
		bkmem_free(pcfsp, sizeof (*pcfsp));
		pcfsp = NULL;
		return (-1);
	}
	dprintf("read cluster sectors %d starting at %d\n",
	    nsec_cache, nsec_start);
	return (0);
}

static int
bpcfs_unmountroot(void)
{
	if (pcfsp == NULL)
		return (-1);

	(void) bpcfs_closeall();

	return (0);
}

/*
 * Open a file.
 */
/*ARGSUSED*/
int
bpcfs_open(char *str, int flags)
{
	static int filedes = 1;

	fileid_t *filep;
	_dir_entry_t d;

	dprintf("open %s\n", str);
	filep = (fileid_t *)bkmem_alloc(sizeof (fileid_t));
	filep->fi_back = head->fi_back;
	filep->fi_forw = head;
	head->fi_back->fi_forw = filep;
	head->fi_back = filep;
	filep->fi_filedes = filedes++;
	filep->fi_taken = 1;
	filep->fi_path = (char *)bkmem_alloc(strlen(str) + 1);
	(void) strcpy(filep->fi_path, str);

	if (lookuppn(str, &d)) {
		(void) bpcfs_close(filep->fi_filedes);
		return (-1);
	}

	filep->fi_offset = 0;
	FI_STARTCLUST(filep) = d.d_cluster;
	FI_LENGTH(filep) = d.d_size;
	dprintf("file %s size = %ld\n", str, d.d_size);
	return (filep->fi_filedes);
}

int
bpcfs_close(int fd)
{
	fileid_t *filep;

	dprintf("close %d\n", fd);
	if (!(filep = find_fp(fd)))
		return (-1);

	if (filep->fi_taken == 0 || filep == head) {
		printf("File descripter %d no allocated!\n", fd);
		return (-1);
	}

	/* unlink and deallocate node */
	filep->fi_forw->fi_back = filep->fi_back;
	filep->fi_back->fi_forw = filep->fi_forw;
	bkmem_free(filep->fi_path, strlen(filep->fi_path) + 1);
	bkmem_free((char *)filep, sizeof (fileid_t));
	dprintf("close done\n");
	return (0);
}

static void
bpcfs_closeall(void)
{
	fileid_t *filep;

	while ((filep = head->fi_forw) != head)
		if (filep->fi_taken && bpcfs_close(filep->fi_filedes))
			printf("Filesystem may be inconsistent.\n");

	bkmem_free(pcfsp, sizeof (*pcfsp));
	bkmem_free(head, sizeof (fileid_t));
	pcfsp = NULL;
	head = NULL;
}

static ssize_t
bpcfs_read(int fd, caddr_t b, size_t c)
{
	ulong_t sector;
	uint_t count = 0, xfer, i;
	char *block;
	ulong_t off, blk;
	int rd, spc;
	fileid_t *fp;

	dprintf("bpcfs_read: fd = %d, buf = %p, size = %d\n",
		fd, (void *)b, c);
	fp = find_fp(fd);
	if (fp == NULL) {
		printf("invalid file descriptor %d\n", fd);
		return (-1);
	}

	spc = pcfsp->f_bpb.bs_spc;
	off = fp->fi_offset;
	blk = FI_STARTCLUST(fp);
	rd = blk == CLUSTER_ROOTDIR ? 1 : 0;

	spc = pcfsp->f_bpb.bs_spc;
	off = fp->fi_offset;
	blk = FI_STARTCLUST(fp);
	rd = (blk == CLUSTER_ROOTDIR) ? 1 : 0;

	if ((c = MIN(FI_LENGTH(fp) - off, c)) == 0)
		return (0);

	while (off >= pcfsp->f_bpb.bs_spc * SECSIZ) {
		blk = fat_map(blk, rd);
		off -= pcfsp->f_bpb.bs_spc * SECSIZ;

		if (!cluster_valid(blk, rd)) {
			printf("bpcfs_read: invalid cluster: %ld, %d\n",
			    blk, rd);
			return (-1);
		}
	}

	while (count < c) {
		sector = fat_ctodb(blk, rd);
		diskread_callback = fileread_callback;
		for (i = ((off / SECSIZ) % pcfsp->f_bpb.bs_spc); i < spc; i++) {
			xfer = MIN(SECSIZ - (off % SECSIZ), c - count);
			if (xfer == 0)
				break;	/* last sector done */

			block = (char *)readblock(sector + i, 1);
			if (block == NULL) {
				return (-1);
			}
			dprintf("bpcfs_read: read %d bytes\n", xfer);
			if (diskread_callback == NULL)
				(void) bcopy(&block[off % SECSIZ], b, xfer);
			count += xfer;
			off += xfer;
			b += xfer;
		}

		diskread_callback = NULL;
		if (count < c) {
			blk = fat_map(blk, rd);
			if (!cluster_valid(blk, rd)) {
				printf("bpcfs_read: invalid cluster: %ld, %d\n",
				    blk, rd);
				break;
			}
		}
	}

	fp->fi_offset += count;
	return (count);
}

/*
 * This version of seek() only performs absolute seeks (whence == 0).
 */
static off_t
bpcfs_lseek(int fd, off_t addr, int whence)
{
	fileid_t *filep;

	dprintf("lseek %d, off = %lx\n", fd, addr);
	if (!(filep = find_fp(fd)))
		return (-1);

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
	filep->fi_count = 0;
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

static int
cluster_valid(long c, int rd)
{
	return ((rd && (c == 0)) ? 1 : (c >= CLUSTER_RES_16_0 ? 0 : c));
}

static int
fat_ctodb(int blk, int r)
{
	uint_t s;

	s = r ? blk + pcfsp->f_rootsec + pcfsp->f_adjust :
	    ((blk - 2) * pcfsp->f_bpb.bs_spc) +
	    pcfsp->f_filesec + pcfsp->f_adjust;

	return (s);
}

static int
fat_map(int blk, int rootdir)
{
	ulong_t sectn, fat_index;
	uchar_t *fp;

	if (rootdir) {
		return (blk > pcfsp->f_rootlen ? CLUSTER_EOF : blk + 1);
	}

	/* ---- Find out what sector this cluster is in ---- */
	fat_index = (pcfsp->f_16bit) ? ((ulong_t)blk << 1) :
	    ((ulong_t)blk + ((uint_t)blk >> 1));

	sectn = (fat_index / SECSIZ) + ltohs(pcfsp->f_bpb.bs_resv_sectors)
	    + pcfsp->f_adjust;

	/*
	 * Read two sectors so that if our fat_index points at the last byte
	 * byte we'll have the data needed.  This is only a problem for fat12
	 * entries.
	 */
	if (!(fp = (uchar_t *)readblock(sectn, 2))) {
		printf("fat_map: bad cluster\n");
		return (CLUSTER_BAD_16);
	}

	fp += (fat_index % SECSIZ);

	if (pcfsp->f_16bit)
		blk = fp[0] | (fp[1] << 8);
	else {
		if (blk & 1)
			blk = ((fp[0] >> 4) & 0xf) | (fp[1] << 4);
		else
			blk = ((fp[1] & 0xf) << 8) | fp[0];

		/*
		 * This makes compares easier because we can just compare
		 * against one value instead of two.
		 */
		if (blk >= CLUSTER_RES_12_0)
			blk |= CLUSTER_RES_16_0;
	}
	return (blk);
}

static int
namecmp(char *pn, char *dn, int cs)
{
	dprintf("namecmp %s, %s, len = %d\n", pn, dn, cs);

	/* starting char must match */
	while (*pn && *dn) {
		--cs;
		if (toupper(*pn++) != toupper(*dn++))
			return (1);
	}

	dprintf("namecmp: cs = %d\n", cs);
	/* remainder should be either ~# or all spaces */
	if (cs > 0 && *dn == '~')
		return (0);
	while (cs > 0) {
		if (*dn++ != ' ')
			return (1);
		--cs;
	}
	return (0);
}

static int
dircmp(char *name, char *d_name, char *d_ext)
{
	int ret;
	char *sep, *ext;

	sep = (char *)strchr(name, '.');

	if (sep) {
		*sep = '\0';
		ext = sep + 1;
	} else
		ext = "   ";

	if (namecmp(name, d_name, NAMESIZ) || namecmp(ext, d_ext, EXTSIZ))
		ret = 1;
	else
		ret = 0;
	if (sep)
		*sep = '.';
	return (ret);
}

static int
lookup(char *n, _dir_entry_p dp, ulong_t dir_blk)
{
	int spc = pcfsp->f_bpb.bs_spc;
	int rd = (dir_blk == CLUSTER_ROOTDIR ? 1 : 0);
	_dir_entry_p dxp;
	int j, sector;

	dprintf("lookup: name = %s\n", n);

	while (cluster_valid(dir_blk, rd)) {
		sector = fat_ctodb(dir_blk, rd);
		dxp = readblock(sector, 1);	/* read one sector */
		if (dxp == NULL)
			return (0);
		for (j = 0; j < DIRENTS * spc; j++, dxp++) {
			dprintf("lookup: dir entry %s.%s;\n",
			    dxp->d_name, dxp->d_ext);
			if (dxp->d_name[0] == 0)
				return (0);
			if ((uchar_t)dxp->d_name[0] != 0xE5 &&
			    (dxp->d_attr & (DE_LABEL|DE_HIDDEN)) == 0 &&
			    dircmp(n, dxp->d_name, dxp->d_ext) == 0) {
				dprintf("lookup: match found\n");
				(void) bcopy(dxp, dp, sizeof (*dp));
				return (1);
			}
		}
		/* next cluster */
		dir_blk = fat_map(dir_blk, rd);
	}

	return (0);
}

static int
lookuppn(char *n, _dir_entry_p dp)
{
	long dir_blk;
	char name[8 + 1 + 3 + 1];	/* <8>.<3>'\0' */
	char *p, *ep;
	_dir_entry_t dd;

	dprintf("lookuppn: path = %s\n", n);
	dir_blk = pcfsp->f_dclust;
	if ((*n == '\\') || (*n == '/')) {
		dir_blk = CLUSTER_ROOTDIR;
		while ((*n == '\\') || (*n == '/'))
			n++;
		if (*n == '\0') {
			(void) bzero(dp, sizeof (*dp));
			dp->d_cluster = CLUSTER_ROOTDIR;
			dp->d_attr = DE_DIRECTORY;
			return (0);
		}
	}

	ep = &name[0] + sizeof (name);
	while (*n) {
		(void) bzero(name, sizeof (name));
		p = &name[0];
		while (*n && (*n != '\\') && (*n != '/'))
			if (p != ep)
				*p++ = *n++;
			else {
				dprintf("return, name %s is too long\n", name);
				return (-1);	/* name is too long */
			}
		while ((*n == '\\') || (*n == '/'))
			n++;
		if (lookup(name, &dd, dir_blk) == 0) {
			dprintf("return, name %s not found\n", name);
			return (-1);
		}
		dprintf("dd = %x:%x:%x attr = %x\n",
		    *(int *)&dd, *(((int *)&dd) + 1),
		    *(((int *)&dd) + 2), dd.d_attr);
		if (*n && ((dd.d_attr & DE_DIRECTORY) == 0)) {
			dprintf("return, not a directory\n");
			return (-1);
		}

		dir_blk = dd.d_cluster;
	}
	(void) bcopy(&dd, dp, sizeof (dd));
	return (0);
}

static void *
readblock(int sector, int nsec)
{
	if (sector >= nsec_start && sector + nsec <= nsec_start + nsec_cache)
		return (cluster_cache + (sector - nsec_start) * SECSIZ);

	/* read disk sectors */
	head->fi_blocknum = sector;
	head->fi_count = nsec * SECSIZ;
	head->fi_memp = head->fi_buf;
	if (diskread(head)) {
		printf("failed to %d sectors at %d\n", nsec, sector);
		return (NULL);
	}

	return (head->fi_buf);
}

struct boot_fs_ops bpcfs_ops = {
	"boot_pcfs",
	bpcfs_mountroot,
	bpcfs_unmountroot,
	bpcfs_open,
	bpcfs_close,
	bpcfs_read,
	bpcfs_lseek,
	NULL
};
