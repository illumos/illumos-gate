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
 * Copyright 1991, 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The routines in this file are called only after the PROM
 * version has been determined to be sunMON.
 *
 * Basic file system reading code for standalone I/O system.
 * Simulates a primitive UNIX I/O system (read(), write(), open(), etc).
 * Does not support writes.
 */

#include <sys/param.h>
#include <sys/saio.h>
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

#include <iob.h>
#include "hsfs_sig.h"

#define	hdbtodb(n)	((ISO_SECTOR_SIZE / DEV_BSIZE) * (n))

#define	NULL	0

#define	TRUE	1
#define	FALSE	0

char *bootname = "/hsfsboot";

extern int	(*printf_p)();

struct dirstuff {
	int loc;
	struct iob *io;
};

struct hs_direct {
    struct	direct  hs_ufs_dir;
    struct	hs_direntry hs_dir;
};

/* These are the pools of buffers, iob's, etc. */
struct iob		iob[1];

/*  This is the fd for the file(s) */
static i_fd = 1;

/* May not need this... */
static uint_t	root_ino = 0;

/*
 * Non-local prototypes
 */
extern int devread(struct saioreq *s);
extern int devopen(struct saioreq *s);
extern int devclose(struct saioreq *s);

/*
 *  Local prototypes
 */
static struct hs_direct *readdir(struct dirstuff *);
static ino_t dlook(char *, struct iob *);
static ino_t find(char *, struct iob *);
static uint_t parse_dir(struct iob *, int, struct hs_direct *);
static uint_t parse_susp(char *, uint_t *, struct hs_direct *);
static int opendir(ino_t, struct iob *);
static int mountroot(void);

extern int prom_type;		/* Determined in main() */
/*
 * Exported functions
 */
extern int open(char *str, int flags);
extern int close(int fd);
extern int read(int fdesc, char *buf, int count);
extern int lseek(int fdesc, off_t addr);

static int
opendir(ino_t inode, struct iob *io)
{
	struct hs_direct hsdep;
	uint_t i;
	int retval;

	/* Set up the saio request */
	io->i_offset = 0;
	io->i_bn = hdbtodb(inode);
	io->i_cc = ISO_SECTOR_SIZE;

	if ((retval = devread(&io->i_si)) != ISO_SECTOR_SIZE)
		return (0);

	io->i_offset = 0;
	io->i_bn = hdbtodb(inode);

	if (inode != root_ino)
	    return (0);

	if (parse_dir(io, 0, &hsdep) > 0) {
		register struct inode *ip = &io->i_ino;

		bzero(io->i_ino, sizeof (struct inode));
		ip->i_size = hsdep.hs_dir.ext_size;
		ip->i_smode = hsdep.hs_dir.mode;
		ip->i_number = inode;
		return (0);
	}
	return (1);
}

static ino_t
find(char *path, struct iob *file)
{
	char *q;
	char c;
	ino_t n;

	if (path == NULL || *path == '\0')
		return (0);

	if (opendir(root_ino, file))
		return (0);

	while (*path) {
		while (*path == '/')
			path++;
		q = path;
		while (*q != '/' && *q != '\0')
			q++;
		c = *q;
		*q = '\0';

		if ((n = dlook(path, file)) != 0) {
			if (c == '\0')
				break;
			if (opendir(n, file))
				return (0);
			*q = c;
			path = q;
			continue;
		} else {
			return (0);
		}
	}
	return ((ino_t)n);
}

static ino_t
dlook(char *s, struct iob *io)
{
	register struct hs_direct *hsdep;
	register struct direct *udp;
	register struct inode *ip;
	struct dirstuff dirp;
	register int len;

	ip = &io->i_ino;
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
	dirp.io = io;
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
			register struct inode *ip = &io->i_ino;

			io->i_offset = 0;
			io->i_bn = hdbtodb(udp->d_ino);

			bzero(io->i_ino, sizeof (struct inode));
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
	register struct direct *udp = &hsdep.hs_ufs_dir;
	struct inode *ip;
	struct iob *io;
	daddr_t lbn, d;
	int off;

	io = dirp->io;
	ip = &io->i_ino;
	for (;;) {
		if (dirp->loc >= ip->i_size) {
			return (NULL);
		}
		off = dirp->loc & ((1 << ISO_SECTOR_SHIFT) - 1);
		if (off == 0) {
			lbn = hdbtodb(dirp->loc >> ISO_SECTOR_SHIFT);
			io->i_bn = lbn + hdbtodb(ip->i_number);
			io->i_ma = io->i_buf;
			io->i_cc = ISO_SECTOR_SIZE;
			if (devread(&io->i_si) != io->i_cc) {
				return (NULL);
			}
		}
		dirp->loc += parse_dir(io, off, &hsdep);
		if (udp->d_reclen == 0 && dirp->loc <= ip->i_size) {
			dirp->loc = roundup(dirp->loc, ISO_SECTOR_SIZE);
			continue;
		}
		return (&hsdep);
	}
}

static int
getblock(struct iob *io)
{
	register struct hs_volume *fsp;
	register struct inode *ip = &io->i_ino;
	register int off, size, diff;
	register daddr_t lbn;
#ifdef SPIN_IND
	static int	pos;
	static char	ind[] = "|/-\\";
	static int	blks_read;
#endif	/* SPIN_IND */

	diff = ip->i_size - io->i_offset;
	if (diff <= 0)
		return (-1);

	fsp = &io->ui_hsfs;

	/* which block (or frag) in the file do we read? */
	lbn = hdbtodb(io->i_offset >> ISO_SECTOR_SHIFT);
	io->i_bn = lbn + hdbtodb(ip->i_number);

	off = io->i_offset & ((1 << ISO_SECTOR_SHIFT) - 1);
	size = sizeof (io->i_buf);
	io->i_ma = io->i_buf;
	io->i_cc = size;

	if (devread(&io->i_si) != size)	/* Trap errors */
		return (-1);

#ifdef SPIN_IND
	/*
	 * round and round she goes (though not on every block..
	 * - Even SunMON proms take some time to actually print stuff)
	 */
	if ((blks_read++ & 0x3) == 0)
		(*printf_p)("%c\b", ind[pos++ & 3]);
#endif	/* SPIN_IND */

	if (io->i_offset - off + size >= ip->i_size)
		io->i_cc = diff + off;
	io->i_cc -= off;

	io->i_ma = &io->i_buf[off];
	return (0);
}

int
read(int fd, caddr_t buf, int count)
{
	register i, j;
	register struct iob *io = &iob[fd];
	register struct inode *ip = &io->i_ino;
	caddr_t n;

	n = buf;

	if (io->i_offset + count > ip->i_size)
		count = ip->i_size - io->i_offset;

	if ((i = count) <= 0)
		return (0);

	while (i > 0) {
		if (io->i_cc <= 0) {
			if (getblock(io) == -1)
				return (0);
		}
		j = MIN(i, io->i_cc);
		bcopy(io->i_ma, buf, (unsigned)j);
		buf += j;
		io->i_ma += j;
		io->i_offset += j;
		io->i_cc -= j;
		i -= j;
	}
	return (buf - n);
}

/*
 * We use the token iob for reading the "super block".
 */
static int
mountroot()
{
	struct bootparam *bp;
	struct hs_volume *fsp;
	char *bufp;
	int err;
	int i;

	/* This really has to be done only once. */
	if (root_ino == 0) {

	    bp = *(romp->sunmon.v_bootparam);

	    fsp = &iob->ui_hsfs;
	    bufp = iob->i_buf;

	    iob->i_boottab = bp->bp_boottab;
	    iob->i_ino.i_dev = 0;
	    iob->i_ctlr = bp->bp_ctlr;
	    iob->i_unit = bp->bp_unit;
	    iob->i_boff = bp->bp_part;

	    /* make the prom open the device */
	    if (err = devopen(&iob->i_si))
		    return (-1);	/* if devopen fails, open fails */

	    /* now opening file system; read the superblock. */
	    iob->i_ma = iob->i_buf;
	    iob->i_cc = ISO_SECTOR_SIZE;
	    iob->i_bn = hdbtodb(ISO_VOLDESC_SEC);
	    iob->i_offset = 0;
	    if ((err = devread(&iob->i_si)) != ISO_SECTOR_SIZE)
		    return (-1);

	    bufp = iob->i_buf;
	    fsp = &iob->ui_hsfs;

	    /* Since RRIP is based on ISO9660, that's where we start */

	    if (ISO_DESC_TYPE(bufp) != ISO_VD_PVD)
		    return (-1);
	    if (strncmp(ISO_std_id(bufp), ISO_ID_STRING, ISO_ID_STRLEN) != 0)
		    return (-1);
	    if (ISO_STD_VER(bufp) != ISO_ID_VER)
		    return (-1);

	    /* Now we fill in the volume descriptor */
	    fsp->vol_size = ISO_VOL_SIZE(bufp);
	    fsp->lbn_size = ISO_BLK_SIZE(bufp);
	    fsp->lbn_shift = ISO_SECTOR_SHIFT;
	    fsp->lbn_secshift = ISO_SECTOR_SHIFT;
	    fsp->vol_set_size = (ushort_t)ISO_SET_SIZE(bufp);
	    fsp->vol_set_seq = (ushort_t)ISO_SET_SEQ(bufp);

	    /* Make sure we have a valid logical block size */
	    if (fsp->lbn_size & ~(1 << fsp->lbn_shift)) {
		    (*printf_p)("%d invalid logical block size\n",
				fsp->lbn_size);
		    return (-1);
	    }

	    /* Since an HSFS root could be located anywhere on the media! */
	    root_ino = IDE_EXT_LBN(ISO_root_dir(bufp));
	}
}

/*
 * Open a file. For the bootblock, we assume one file can be opened
 * on a ufs filesystem. The underlying device is the one we rode in on.
 */
int
open(char *str, int flags)
{
	register struct iob *ior;
	register struct bootparam *bp;
	register struct hs_volume *fsp;
	register struct hs_direntry *dirp;
	register char *bufp;
	ino_t ino;
	int err;

	/* Make sure we are set up */
	mountroot();

	bp = *(romp->sunmon.v_bootparam);

	ior = iob;
	fsp = &ior->ui_hsfs;
	dirp = &fsp->root_dir;
	bufp = ior->i_buf;

	ior->i_boottab = bp->bp_boottab;
	ior->i_ino.i_dev = 0;
	ior->i_ctlr = bp->bp_ctlr;
	ior->i_unit = bp->bp_unit;
	ior->i_boff = bp->bp_part;

	if ((ino = find(str, ior)) == 0) {
		(*printf_p)("%s not found\n", str);
		return (-1);
	}

	ior->i_bn = hdbtodb(ino);
	ior->i_offset = 0;
	ior->i_cc = 0;

	return (0);
}

int
close(int fd)
{
	struct iob *file = &iob[fd];

	return (devclose(&file->i_si));
}

/*
 * This version of seek() only performs absolute seeks (whence == 0).
 */
int
seek(int fd, off_t addr)
{
	struct iob *io = &iob[fd];

	io->i_offset = addr;
	io->i_bn = addr / DEV_BSIZE;
	io->i_cc = 0;
	return (0);
}

/*
 * Parse a directory entry.
 *
 */
static uint_t
parse_dir(
	struct iob *io,		/* current dir block */
	int offset,			/* offset into dir blk for dir entry */
	struct hs_direct *hsdep)	/* return value: parsed entry */
{
	char *bufp = (char *)(io->i_ma + offset);
	struct hs_volume *fsp = &io->ui_hsfs;
	struct direct *udp = &hsdep->hs_ufs_dir;  /* ufs-style dir info */
	struct hs_direntry *hdp = &hsdep->hs_dir; /* hsfs-style dir info */
	int ce_buf[ISO_SECTOR_SIZE/sizeof (int)]; /* continuation area buffer */
	uint_t ce_lbn;
	uint_t ce_len;
	uint_t nmlen;
	uint_t i;
	uchar_t c;
	int ret_code;

	/* a zero length dir entry terminates the dir block */
	if (!(udp->d_reclen = IDE_DIR_LEN(bufp)))
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
		(*printf_p)("pd(): file type=0x%x unknown.\n", c);
		return (-1);
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

	if (ce_len > 0) {
		/* there is an SUA for this dir entry; go parse it */
		ce_lbn = parse_susp((char *)IDE_sys_use_area(bufp),
		    &ce_len, hsdep);

		if (ce_lbn) {
			/*
			 * store away current position in dir,
			 * as we will be using the iobuf to reading SUA.
			 */
			daddr_t save_bn = io->i_bn;
			daddr_t save_offset = io->i_offset;
			caddr_t save_ma = io->i_ma;
			int save_cc = io->i_cc;
			do {
				io->i_cc = ISO_SECTOR_SIZE;
				io->i_offset = 0;
				io->i_bn = hdbtodb(ce_lbn);
				io->i_ma = (char *)ce_buf;
				ret_code = devread(&io->i_si);
				if (ret_code != ISO_SECTOR_SIZE) {
					ce_len = 0;
					ce_lbn = 0;
					break;
				}
				ce_lbn = parse_susp(io->i_ma, &ce_len, hsdep);
			} while (ce_lbn);
			io->i_bn = save_bn;
			io->i_offset = save_offset;
			io->i_ma = save_ma;
			io->i_cc = save_cc;
		}
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
	register struct direct *udp = &hsdep->hs_ufs_dir; /* ufs-style info */
	char *susp;
	uint_t cur_off = 0;
	uint_t blk_len = *len;
	uint_t susp_len = 0;
	uint_t ce_lbn = 0;
	uint_t i;

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
		case SUSP_SP_IX:
			/* SP signature: field tells us where SUA is */
			if (CHECK_BYTES_OK(susp)) {
				cur_off = SP_SUA_OFFSET(susp);
			}
			break;
		case SUSP_CE_IX:
			/*
			 * CE signature: continuation of SUSP.
			 * will want to return new lbn, len.
			 */
			ce_lbn = CE_BLK_LOC(susp);
			*len = CE_CONT_LEN(susp);
			cur_off += susp_len;
			break;
		case SUSP_ST_IX:
			/* ST signature: terminates SUSP */
			return (ce_lbn);
		case RRIP_RR_IX:
			/* XXX do we want to break when we see a RR? */
			cur_off += susp_len;
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
			(*printf_p)("parse_susp(): Bad SUSP\n");
			cur_off = blk_len;
			break;

		default:
			cur_off += susp_len;
		}
	}
	return (ce_lbn);
}
