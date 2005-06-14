/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* From Solaris usr/src/stand/lib/fs/ufs/ufsops.c */

#ifdef	FSYS_UFS

#include "shared.h"
#include "filesys.h"

#include "ufs.h"

/* These are the pools of buffers, etc. */

#define SUPERBLOCK ((struct fs *)(FSYS_BUF + 0x2000))
#define	INODE ((struct icommon *)(FSYS_BUF + 0x1000))
#define DIRENT (FSYS_BUF + 0x4000)
#define INDIRBLK1 ((grub_daddr32_t *)(FSYS_BUF + 0x4000)) /* 2+ indir blk */
#define	INDIRBLK0 ((grub_daddr32_t *)(FSYS_BUF+ 0x6000))  /* 1st indirect blk */

static int indirblk0, indirblk1;

static int openi(grub_ino_t);
static grub_ino_t dlook(grub_ino_t, char *);
static grub_daddr32_t sbmap(grub_daddr32_t);

/* read superblock and check fs magic */
int
ufs_mount(void)
{
	if (! IS_PC_SLICE_TYPE_SOLARIS(current_slice) ||
	    !devread(UFS_SBLOCK, 0, UFS_SBSIZE, (char *)SUPERBLOCK) ||
	    SUPERBLOCK->fs_magic != UFS_MAGIC)
		return 0;

	return 1;
}


/*
 * searching for a file, if successful, inode will be loaded in INODE
 * The entry point should really be named ufs_open(char *pathname).
 * For now, keep it consistent with the rest of fsys modules.
 */
int
ufs_dir(char *dirname)
{
	grub_ino_t inode = ROOTINO;	/* start from root */
	char *fname, ch;

	indirblk0 = indirblk1 = 0;

	/* skip leading slashes */
	while (*dirname == '/')
		dirname++;

	while (inode && *dirname && !isspace(*dirname)) {
		if (!openi(inode))
			return 0;

		/* parse for next path component */
		fname = dirname;
		while (*dirname && !isspace(*dirname) && *dirname != '/')
			dirname++;
		ch = *dirname;
		*dirname = 0;	/* ensure null termination */

		inode = dlook(inode, fname);
		*dirname = ch;
		while (*dirname == '/')
			dirname++;
	}

	/* return 1 only if inode exists and is a regular file */
	if  (! openi(inode))
		return (0);
	filepos = 0;
	filemax = INODE->ic_sizelo;
	return (inode && ((INODE->ic_smode & IFMT) == IFREG));
}

/*
 * This is the high-level read function.
 */
int
ufs_read(char *buf, int len)
{
  	int off, size, ret = 0;
	grub_daddr32_t lblk, dblk;

  	while (len) {
	  	off = blkoff(SUPERBLOCK, filepos);
		lblk = lblkno(SUPERBLOCK, filepos);
		size = SUPERBLOCK->fs_bsize;
		if ((dblk = sbmap(lblk)) == 0)
		  	break;
		size -= off;
		if (size > len)
		  	size = len;

		if (!devread(fsbtodb(SUPERBLOCK, dblk), off, size, buf))
		  	return 0;
		buf += size;
		len -= size;
		filepos += size;
		ret += size;
	}

	return (ret);
}

int
ufs_embed (int *start_sector, int needed_sectors)
{
	if (needed_sectors > 14)
        	return 0;

	*start_sector = 2;
	return 1;
}

/* read inode and place content in INODE */
static int
openi(grub_ino_t inode)
{
	grub_daddr32_t dblk;
	int off;

	/* get block and byte offset into the block */
	dblk = fsbtodb(SUPERBLOCK, itod(SUPERBLOCK, inode));
	off = itoo(SUPERBLOCK, inode) * sizeof (struct icommon);

	return (devread(dblk, off, sizeof (struct icommon), (char *)INODE));
}

/* performs fileblock mapping. Convert file block no. to disk block no. */
grub_daddr32_t
sbmap(grub_daddr32_t bn)
{
  	int level, bound, i, index;
	grub_daddr32_t nb, blkno;
	grub_daddr32_t *db = INODE->ic_db;

	/* blocks 0..UFS_NDADDR are direct blocks */
	if (bn < UFS_NDADDR) {
		return db[bn];
	}

	/* determine how many levels of indirection. */
	level = 0;
	bn -= UFS_NDADDR;
	bound = UFS_NINDIR(SUPERBLOCK);
	while (bn >= bound) {
		level++;
		bn -= bound;
		bound *= UFS_NINDIR(SUPERBLOCK);
	}
	if (level >= UFS_NIADDR)	/* bn too big */
		return ((grub_daddr32_t)0);

	/* fetch the first indirect block */
	nb = INODE->ic_ib[level];
	if (nb == 0) {
		return ((grub_daddr32_t)0);
	}
	if (indirblk0 != nb) {
		indirblk0 = 0;
		blkno = fsbtodb(SUPERBLOCK, nb);
		if (!devread(blkno, 0, SUPERBLOCK->fs_bsize,
		    (char *)INDIRBLK0))
			return (0);
		indirblk0 = nb;
	}
	bound /= UFS_NINDIR(SUPERBLOCK);
	index = (bn / bound) % UFS_NINDIR(SUPERBLOCK);
	nb = INDIRBLK0[index];

	/* fetch through the indirect blocks */
	for (i = 1; i <= level; i++) {
		if (indirblk1 != nb) {
			blkno = fsbtodb(SUPERBLOCK, nb);
			if (!devread(blkno, 0, SUPERBLOCK->fs_bsize,
			    (char *)INDIRBLK1))
				return (0);
			indirblk1 = nb;
		}
		bound /= UFS_NINDIR(SUPERBLOCK);
		index = (bn / bound) % UFS_NINDIR(SUPERBLOCK);
		nb = INDIRBLK1[index];
		if (nb == 0)
			return ((grub_daddr32_t)0);
	}

	return (nb);
}

/* search directory content for name, return inode number */
static grub_ino_t
dlook(grub_ino_t dir_ino, char *name)
{
	int loc, off;
	grub_daddr32_t lbn, dbn, dblk;
	struct direct *dp;

	if ((INODE->ic_smode & IFMT) != IFDIR)
		return 0;

	loc = 0;
	while (loc < INODE->ic_sizelo) {
	  	/* offset into block */
		off = blkoff(SUPERBLOCK, loc);
		if (off == 0) {		/* need to read in a new block */

		  	/* get logical block number */
			lbn = lblkno(SUPERBLOCK, loc);
			/* resolve indrect blocks */
			dbn = sbmap(lbn);
			if (dbn == 0)
				return (0);

			dblk = fsbtodb(SUPERBLOCK, dbn);
			if (!devread(dblk, 0, SUPERBLOCK->fs_bsize,
			    (char *)DIRENT)) {
				return 0;
			}
		}

		dp = (struct direct *)(DIRENT + off);
		if (dp->d_ino && substring(name, dp->d_name) == 0)
			return (dp->d_ino);
		loc += dp->d_reclen;
	}
	return (0);
}

#endif /* FSYS_UFS */
