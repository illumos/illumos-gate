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
 * Copyright (c) 1991-1994, Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* from  "@(#)boot/ufssys.c       1.1 90/03/28 SMI" */

/*
 * Basic file system reading code for standalone I/O system.
 */

/*
 * This code must be kept very small.  If space allows, you can
 * turn on the ability to handle continuations (and other signatures)
 * by #defining HANDLE_CONTINUATION.
 */

#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_inode.h>

#include <sys/fs/hsfs_spec.h>
#include <sys/fs/hsfs_isospec.h>
#include <sys/fs/hsfs_node.h>
#include <sys/fs/hsfs_susp.h>
#include <sys/fs/hsfs_rrip.h>

#include "iob.h"
#include "cbootblk.h"

#include "hsfs_sig.h"

#define	NULL	0

#define	TRUE	1
#define	FALSE	0

#define	hdbtodb(n)	((ISO_SECTOR_SIZE / DEV_BSIZE) * (n))

#ifdef DEBUG
/* debugging printfs */
#define	DEBUG_PRINTF0(s) \
	fprintf(stderr, s)
#define	DEBUG_PRINTF1(s, a1) \
	fprintf(stderr, s, (a1))
#define	DEBUG_PRINTF2(s, a1, a2) \
	fprintf(stderr, s, (a1), (a2))
#define	DEBUG_PRINTF3(s, a1, a2, a3) \
	fprintf(stderr, s, (a1), (a2), (a3))
#define	DEBUG_PRINTF4(s, a1, a2, a3, a4) \
	fprintf(stderr, s, (a1), (a2), (a3), (a4))
#define	DEBUG_PRINTF5(s, a1, a2, a3, a4, a5) \
	fprintf(stderr, s, (a1), (a2), (a3), (a4), (a5))
#else
#define	DEBUG_PRINTF0(s)
#define	DEBUG_PRINTF1(s, a1)
#define	DEBUG_PRINTF2(s, a1, a2)
#define	DEBUG_PRINTF3(s, a1, a2, a3)
#define	DEBUG_PRINTF4(s, a1, a2, a3, a4)
#define	DEBUG_PRINTF5(s, a1, a2, a3, a4, a5)
#endif

char fscompname[] = "hsfsboot";

static struct iob iob[1];		/* only one open file! */

static u_int dlook(char *, register struct iob *);
static int parse_dir(struct iob *, int, u_char *, u_int *, u_int *);
static u_int parse_susp(u_char *, u_int *, u_char *, u_int *, u_int *);
static int read_sector(struct iob *, u_int, char *, u_char);

static int
read_sector(struct iob *io, u_int iso_secno, char *buf, u_char next)
{
#ifdef DEBUG
	static char *msg = "rs:[%c] o=%d b=%d c=%d n=%d\n";
#endif
	DEBUG_PRINTF5(msg, 'I', io->i_offset, io->i_bn, io->i_cc, next);

	io->i_cc = ISO_SECTOR_SIZE;
	io->i_ma = buf;

	if (next == TRUE) {
		io->i_bn += (ISO_SECTOR_SIZE / DEV_BSIZE);
	} else {
		io->i_offset = 0;
		io->i_bn = hdbtodb(iso_secno);
	}

	if (devbread(&io->i_si, io->i_ma,
	    io->i_bn, io->i_cc) != ISO_SECTOR_SIZE) {
		DEBUG_PRINTF5(msg, '0', io->i_offset,
		    io->i_bn, io->i_cc, next);
		return (0);
	}

	DEBUG_PRINTF5(msg, '1', io->i_offset, io->i_bn, io->i_cc, next);
	return (1);
}

/*
 * Look up a file, pathname component by pathname component.
 * Return lbn of file if found, 0 otherwise.
 */
static u_int
find(char *path, struct iob *file)
{
	char *q;
	char c;
	u_int n;

	if (path == NULL || *path == '\0')
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
			DEBUG_PRINTF1("fnd: n=%d\n", n);
			if (c == '\0')
				break;
			if (!read_sector(file, n, file->i_buf, FALSE))
				return (0);
			*q = c;
			path = q;
			continue;
		} else {
			return (0);
		}
	}
	return (n);
}

/*
 * Look up the file in the directory.
 * Return lbn of file extent on success, 0 on failure.
 */
static u_int
dlook(char *s, struct iob *io)
{
	struct hs_volume *fsp = &io->ui_hsfs;
	struct hs_direntry *dirp = &fsp->root_dir;
	int dirsz = dirp->ext_size;
	u_char nameb[MAXPATHLEN];
	u_int nml;
	u_int blkloc = 0;
	u_int dirloc;
	u_int reclen;
	u_int len;
	u_int altnm;

	if (s == NULL || *s == '\0')
		return (0);

	if (dirp->type != VDIR)
		return (0);

	len = strlen(s);

	while (blkloc < dirsz) {
		dirloc = 0;
		while (dirloc < ISO_SECTOR_SIZE) {
			altnm = 0;
			nml = sizeof (nameb);
			reclen = parse_dir(io, dirloc, nameb, &nml, &altnm);
			dirloc += reclen;
			if (!reclen)
				break;
			if (altnm) {
				if (len != nml ||
				    strncmp(s, (char *)nameb, len) != 0)
					continue;
			} else {
				if (strncmp(s, (char *)nameb, len) != 0)
					continue;
			}
			DEBUG_PRINTF1("dl: ret lb=%d\n", dirp->ext_lbn);
			return ((u_int) dirp->ext_lbn);
		}
		if (blkloc + ISO_SECTOR_SIZE < dirsz) {
			if (!read_sector(io, 0, io->i_buf, TRUE))
				return (0);
		}
		blkloc += ISO_SECTOR_SIZE;
	}
	return (0);
}

static int
getblock(register struct iob *io)
{
	u_int lbn;
	int off, size, diff;
	struct hs_volume *fsp = &io->ui_hsfs;
	struct hs_direntry *dirp = &fsp->root_dir;

	diff = dirp->ext_size - io->i_offset;
	if (diff <= 0)
		return (-1);
	lbn = hdbtodb(io->i_offset >> ISO_SECTOR_SHIFT);
	io->i_bn = lbn + hdbtodb(dirp->ext_lbn);
	off = io->i_offset % ISO_SECTOR_SIZE;
	size = sizeof (io->i_buf);
	io->i_cc = size;
	io->i_ma = io->i_buf;

	if (devbread(&io->i_si, io->i_ma,
	    io->i_bn, io->i_cc) != io->i_cc)	/* Trap errors */
		return (-1);

	if (io->i_offset - off + size >= dirp->ext_size)
		io->i_cc = diff + off;
	io->i_cc -= off;

	io->i_ma = &io->i_buf[off];
	return (0);
}

int
readfile(int fd, char *buf, int count)
{
	int i, j;
	struct iob *io = &iob[fd];
	struct iob *file = io;
	struct hs_volume *fsp = &file->ui_hsfs;
	struct hs_direntry *dirp = &fsp->root_dir;

	if (file->i_offset + count > dirp->ext_size)
		count = dirp->ext_size - file->i_offset;
	if ((i = count) <= 0)
		return (0);
	while (i > 0) {
		if (file->i_cc <= 0) {
			if (getblock(file) == -1)
				return (0);
		}
		j = (i < file->i_cc) ? i : file->i_cc;
		bcopy(file->i_ma, buf, (unsigned)j);
		buf += j;
		file->i_ma += j;
		file->i_offset += j;
		file->i_cc -= j;
		i -= j;
	}
	return (count);
}

/*
 * Open a file. For the bootblock, we assume one file can be opened
 * on a hsfs filesystem. The underlying device is the one we rode in on.
 */
int
openfile(char *device, char *pathname)
{
	struct iob *io = &iob[0];	/* only one open file! */
	register struct hs_volume *fsp;
	register char *bufp;
	u_int lbn;

	DEBUG_PRINTF0("open\n");

	fsp = &io->ui_hsfs;
	bufp = io->i_buf;

	if ((io->i_si = devopen(device)) == NULL)
		return (-1);	/* if devopen fails, open fails */
	/*
	 * Pseudo-mount a file system; read the superblock.
	 */
	if (!read_sector(io, ISO_VOLDESC_SEC, bufp, FALSE))
		goto failed;

	/* Make sure we start with a clean slate. */
	(void) bzero((char *)fsp, sizeof (io->ui_hsfs));

	/* Since RRIP is based on ISO9660, that's where we start */

	if (ISO_DESC_TYPE(bufp) != ISO_VD_PVD ||
	    strncmp((char *)ISO_std_id(bufp), ISO_ID_STRING,
		ISO_ID_STRLEN) != 0 ||
	    ISO_STD_VER(bufp) != ISO_ID_VER) {
		puts("bootblk: not an ISO9660 file system.\n");
		goto failed;
	}

	/* Now we fill in the volume descriptor */
	fsp->vol_size = ISO_VOL_SIZE(bufp);
	fsp->lbn_size = ISO_BLK_SIZE(bufp);
	fsp->lbn_shift = ISO_SECTOR_SHIFT;
	fsp->lbn_secshift = ISO_SECTOR_SHIFT;
	fsp->vol_set_size = (u_short) ISO_SET_SIZE(bufp);
	fsp->vol_set_seq = (u_short) ISO_SET_SEQ(bufp);

	/* Make sure we have a valid logical block size */
	if (fsp->lbn_size & ~(1 << fsp->lbn_shift)) {
		DEBUG_PRINTF1("%d byte logical block size invalid.",
			fsp->lbn_size);
		goto failed;
	}

	/* Read the ROOT directory */
	if (!read_sector(io, IDE_EXT_LBN(ISO_root_dir(bufp)), bufp, FALSE))
		goto failed;

	/* Extract the ROOT directory information from the directory block */
	(void) parse_dir(io, 0, NULL, (u_int *) 0, (u_int *) 0);

	if (!(lbn = find(pathname, io)))
		goto failed;

	DEBUG_PRINTF1("lb=%d\n", lbn);

	io->i_bn = hdbtodb(lbn);
	io->i_offset = 0;
	io->i_cc = 0;

	return (0);			/* only one open file! */
failed:
	(void) devclose(io->i_si);
	return (-1);
}

int
closefile(int fd)
{
	struct iob *io = &iob[fd];

	return (devclose(io->i_si));
}

/*
 * This version of seek() only performs absolute seeks (whence == 0).
 */
void
seekfile(int fd, off_t addr)
{
	struct iob *io = &iob[fd];

	io->i_offset = addr;
	io->i_bn = addr >> DEV_BSHIFT;
	io->i_cc = 0;
}

/*
 * Return the next directory entry.
 * Return 0 if no next entry, length of directory entry otherwise.
 */
static int
parse_dir(
	struct iob *io,			/* current dir block */
	int offset,			/* dir entry offset into dir blk */
	u_char *namep,			/* output: name found */
	u_int *namelen,			/* output: length of name found */
	u_int *anm)			/* output: found RR (altrnt) nm flg */
{
	u_char *bufp = (u_char *)(io->i_buf + offset);
	struct hs_direntry *dirp = &(io->ui_hsfs.root_dir);
	static u_char ce_buf[ISO_SECTOR_SIZE];
	u_int ce_len;
	static u_char nmbuf[MAXPATHLEN];
	u_int nmlen;
	u_int altnm = 0;			/* found RR name flag */
	u_char c;
	u_int dir_len = IDE_DIR_LEN(bufp);

	DEBUG_PRINTF1("pd %d\n", dir_len);

	if (!dir_len)
		/* zero length directory, done */
		return (0);

	dirp->ext_lbn  = IDE_EXT_LBN(bufp);
	dirp->ext_size = IDE_EXT_SIZE(bufp);
	dirp->xar_len  = IDE_XAR_LEN(bufp);
	dirp->intlf_sz = IDE_INTRLV_SIZE(bufp);
	dirp->intlf_sk = IDE_INTRLV_SKIP(bufp);
	dirp->sym_link = NULL;

	c = IDE_FLAGS(bufp);
	if (IDE_REGULAR_FILE(c)) {
		dirp->type = VREG;
		dirp->mode = IFREG;
		dirp->nlink = 1;
	} else if (IDE_REGULAR_DIR(c)) {
		dirp->type = VDIR;
		dirp->mode = IFDIR;
		dirp->nlink = 2;
	} else {
		DEBUG_PRINTF1("pd: ftype=0x%x unknown.\n", c);
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
		nmbuf[0] = '.';
		nmbuf[1] = '\0';
		nmlen = 1;
		/* Special Case: Parent Directory */
	} else if (nmlen == 1 && c == '\001') {
		nmbuf[0] = '.';
		nmbuf[1] = '.';
		nmbuf[2] = '\0';
		nmlen = 2;
		/* Other file name */
	} else {
		register int l = nmlen;
		register int i;

		nmlen = 0;
		for (i = 0; i < l; i++) {
			c = *(IDE_name(bufp)+i);
			if (c == ';')
				break;
			else if (c == ' ')
				continue;
			else
				nmbuf[nmlen++] = c;
		}
		nmbuf[nmlen] = '\0';
	}

	DEBUG_PRINTF0("pd bf sua");

#ifdef HANDLE_CONTINUATION
	/* System Use Fields */
	ce_len = IDE_SUA_LEN(bufp);
	if (ce_len) {
		/* there is an SUA for this dir entry; go parse it */
		u_int ce_lbn;
		u_int nmbsz = sizeof (nmbuf);

		bcopy((char *)IDE_sys_use_area(bufp), (char *)ce_buf, ce_len);
		ce_lbn = parse_susp(ce_buf, &ce_len, nmbuf, &nmbsz, &altnm);

		while (ce_lbn) {
			/*
			 * Process continuation of SUA,
			 * saving current position in dir,
			 * as will be using iobuf to read SUA continuation.
			 */
			daddr_t save_bn = io->i_bn;
			daddr_t save_offset = io->i_offset;
			int save_cc = io->i_cc;
			int rd_ok;

			rd_ok = read_sector(io, ce_lbn, (char *)ce_buf, FALSE);

			io->i_bn = save_bn;
			io->i_offset = save_offset;
			io->i_cc = save_cc;

			if (!rd_ok)
				return (0);

			ce_lbn = parse_susp(ce_buf, &ce_len, nmbuf, &nmbsz,
					&altnm);
		}
		if (altnm)
			nmlen = nmbsz;
	}
#else /* HANDLE_CONTINUATION */
	/* System Use Fields */
	ce_len = IDE_SUA_LEN(bufp);
	if (ce_len) {
		/* there is an SUA for this dir entry; go parse it */

		u_int nmbsz = sizeof (nmbuf);

		bcopy((char *)IDE_sys_use_area(bufp), (char *)ce_buf, ce_len);
		(void) parse_susp(ce_buf, &ce_len, nmbuf, &nmbsz, &altnm);

		if (altnm)
			nmlen = nmbsz;
	}
#endif /* HANDLE_CONTINUATION */

	DEBUG_PRINTF0("pd af sua");

	if (anm != NULL)
		*anm = altnm;

	if (namep != NULL && namelen != NULL && *namelen) {
		/* assert(namelen >= nmlen) */
		bcopy((char *)nmbuf, (char *)namep, nmlen);
		*namelen = nmlen;
	}

#ifdef DEBUG
	if (altnm)
		nmbuf[nmlen] = '\0';
#endif /* DEBUG */

	DEBUG_PRINTF2("Nm(%d)=%s\n", nmlen, nmbuf);
	DEBUG_PRINTF2("  lbn/len = %d/%d\n", dirp->ext_lbn, dirp->ext_size);
	DEBUG_PRINTF0("pd end\n");

	return (dir_len);
}

#ifdef HANDLE_CONTINUATION
/*
 * Parse the System Use Fields in the System Use Area.
 * Return block number of continuation (if any),
 * or 0 if no continuation.
 */
static u_int
parse_susp(
	u_char *bufp,
	u_int *len,
	u_char *nmp,
	u_int *nmlen,
	u_int *altnm)			/* found RR name */
{
	u_char *susp;
	u_int cur_off = 0;
	u_int blk_len = *len;
	u_int susp_len = 0;
	u_int ce_lbn = 0;
	u_int i;

	DEBUG_PRINTF1("ps: l=%d\n", *len);

	while (cur_off < blk_len) {
		susp = (u_char *)(bufp + cur_off);
		/*
		 * A null entry, or an entry with zero length
		 * terminates the SUSP.
		 */
		if (susp[0] == '\0' || susp[1] == '\0' ||
		    (susp_len = SUF_LEN(susp)) == 0)
			break;

		/* Compare current entry to all known signatures */
		for (i = 0; i < HSFS_NUM_SIG; i++) {
			if (strncmp(hsfs_sig_tab[i], susp, SUF_SIG_LEN) == 0) {
				DEBUG_PRINTF3("SUSP_%c%c %d\n", susp[0],
					susp[1], susp_len);
				break;
			}
		}

		switch (i) {
		case SUSP_CE_IX:
			/*
			 * CE signature: continuation of SUSP.
			 * will want to return new lbn, len.
			 */
			ce_lbn = CE_BLK_LOC(susp);
			*len = CE_CONT_LEN(susp);
			break;
		case SUSP_ST_IX:
			/* ST signature: terminates SUSP */
			return (ce_lbn);
		case RRIP_RR_IX:
			/* XXX do we want to break when we see a RR? */
			break;
		case RRIP_NM_IX:
			/* NM signature: POSIX-style file name */
			DEBUG_PRINTF0("  NM\n");
			if (!RRIP_NAME_FLAGS(susp)) {
				/* copy out new name if requested */
				if (*nmlen) {
					*nmlen = RRIP_NAME_LEN(susp);
					/* assert(old(nmlen) >= new(nmlen)) */
					bcopy((char *)RRIP_name(susp),
						(char *)nmp, *nmlen);
					*altnm = 1;
				}
			}
			break;
		case HSFS_NUM_SIG:
			/* couldn't find a legit susp, complain and continue */
			(*printf_p)("parse_susp(): Bad SUSP\n");
			break;
		default:
			break;
		}

		cur_off += susp_len;
		DEBUG_PRINTF1("ps: o=%d\n", cur_off);
	}
	return (ce_lbn);
}

#else /* HANDLE_CONTINUATION */
/*
 * Parse the System Use Fields in the System Use Area.
 * Return block number of continuation (if any),
 * or 0 if no continuation.
 */
static u_int
parse_susp(
	u_char *bufp,
	u_int *len,
	u_char *nmp,
	u_int *nmlen,
	u_int *altnm)			/* found RR name */
{
	u_char *susp;
	u_int cur_off = 0;
	u_int blk_len = *len;
	u_int susp_len = 0;

	DEBUG_PRINTF1("ps: l=%d\n", *len);

	while (cur_off < blk_len) {
		susp = (u_char *)(bufp + cur_off);

		/*
		 * A null entry, or an entry with zero length
		 * terminates the SUSP.
		 */
		if (susp[0] == '\0' || susp[1] == '\0' ||
		    (susp_len = SUF_LEN(susp)) == 0)
			break;

		/* Compare current entry to all known signatures */
		if ((susp[0] == 'N' && susp[1] == 'M') &&
				!RRIP_NAME_FLAGS(susp)) {
			/* copy out new name if requested */
			if (*nmlen) {
				*nmlen = RRIP_NAME_LEN(susp);
				/* assert(old(nmlen) >= new(nmlen)) */
				bcopy((char *)RRIP_name(susp), (char *)nmp,
					*nmlen);
				*altnm = 1;
			}
			return (0);
		}
		cur_off += susp_len;
		DEBUG_PRINTF1("ps: o=%d\n", cur_off);
	}
	return (0);
}
#endif /* HANDLE_CONTINUATION */
