/*
 * Copyright (c) 1996, 1998 Robert Nordier
 * All rights reserved.
 * Copyright 2024 MNX Cloud, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>

/*
 * Readonly filesystem for Microsoft FAT12/FAT16/FAT32 filesystems,
 * also supports VFAT.
 */

#include <sys/types.h>
#include <sys/disk.h>
#include <string.h>
#include <stddef.h>

#include "stand.h"

#include "dosfs.h"


static int dos_open(const char *, struct open_file *);
static int dos_close(struct open_file *);
static int dos_read(struct open_file *, void *, size_t, size_t *);
static off_t dos_seek(struct open_file *, off_t offset, int);
static int dos_stat(struct open_file *, struct stat *);
static int dos_readdir(struct open_file *, struct dirent *);

struct fs_ops dosfs_fsops = {
	.fs_name = "dosfs",
	.fo_open = dos_open,
	.fo_close = dos_close,
	.fo_read = dos_read,
	.fo_write = null_write,
	.fo_seek = dos_seek,
	.fo_stat = dos_stat,
	.fo_readdir = dos_readdir
};

#define	LOCLUS	2		/* lowest cluster number */
#define	FATBLKSZ	0x20000	/* size of block in the FAT cache buffer */

/* DOS "BIOS Parameter Block" */
typedef struct {
	uchar_t secsiz[2];	/* sector size */
	uchar_t spc;		/* sectors per cluster */
	uchar_t ressec[2];	/* reserved sectors */
	uchar_t fats;		/* FATs */
	uchar_t dirents[2];	/* root directory entries */
	uchar_t secs[2];	/* total sectors */
	uchar_t media;		/* media descriptor */
	uchar_t spf[2];		/* sectors per FAT */
	uchar_t spt[2];		/* sectors per track */
	uchar_t heads[2];	/* drive heads */
	uchar_t hidsec[4];	/* hidden sectors */
	uchar_t lsecs[4];	/* huge sectors */
	union {
		struct {
			uchar_t drvnum;		/* Int 13 drive number */
			uchar_t rsvd1;		/* Reserved */
			uchar_t bootsig;	/* Boot signature (0x29) */
			uchar_t volid[4];	/* Volume serial number */
			uchar_t vollab[11];	/* Volume label */
			uchar_t fstype[8];	/* Informational */
		} f12_f16;
		struct {
			uchar_t lspf[4];	/* huge sectors per FAT */
			uchar_t xflg[2];	/* flags */
			uchar_t vers[2];	/* filesystem version */
			uchar_t rdcl[4];	/* root directory cluster */
			uchar_t infs[2];	/* filesystem info sector */
			uchar_t bkbs[2];	/* backup boot sector */
			uchar_t reserved[12];	/* Reserved */
			uchar_t drvnum;		/* Int 13 drive number */
			uchar_t rsvd1;		/* Reserved */
			uchar_t bootsig;	/* Boot signature (0x29) */
			uchar_t volid[4];	/* Volume serial number */
			uchar_t vollab[11];	/* Volume label */
			uchar_t fstype[8];	/* Informational */
		} f32;
	} fstype;
} DOS_BPB;

/* Initial portion of DOS boot sector */
typedef struct {
	uchar_t jmp[3];		/* usually 80x86 'jmp' opcode */
	uchar_t oem[8];		/* OEM name and version */
	DOS_BPB bpb;		/* BPB */
} DOS_BS;

typedef struct {
	uchar_t fsi_leadsig[4];		/* Value 0x41615252 */
	uchar_t fsi_reserved1[480];
	uchar_t fsi_structsig[4];	/* Value 0x61417272 */
	uchar_t fsi_free_count[4];	/* Last known free cluster count */
	uchar_t fsi_next_free[4];	/* First free cluster */
	uchar_t fsi_reserved2[12];
	uchar_t fsi_trailsig[4];	/* Value 0xAA550000 */
} DOS_FSINFO;

/* Supply missing "." and ".." root directory entries */
static const char *const dotstr[2] = {".", ".."};
static DOS_DE dot[2] = {
	{".       ", "   ", FA_DIR, {0, 0, {0, 0}, {0, 0}, {0, 0}, {0, 0}},
	{0, 0}, {0x21, 0}, {0, 0}, {0, 0, 0, 0}},
	{"..      ", "   ", FA_DIR, {0, 0, {0, 0}, {0, 0}, {0, 0}, {0, 0}},
	{0, 0}, {0x21, 0}, {0, 0}, {0, 0, 0, 0}}
};

/* The usual conversion macros to avoid multiplication and division */
#define	bytsec(fs, n)	((n) >> (fs)->sshift)
#define	secbyt(fs, s)	((s) << (fs)->sshift)
#define	depsec(fs)	(1U << (fs)->dshift)
#define	entsec(fs, e)	((e) >> (fs)->dshift)
#define	bytblk(fs, n)	((n) >> (fs)->bshift)
#define	blkbyt(fs, b)	((b) << (fs)->bshift)
#define	secblk(fs, s)	((s) >> ((fs)->bshift - (fs)->sshift))
#define	blksec(fs, b)	((b) << ((fs)->bshift - (fs)->sshift))

/* Convert cluster number to offset within filesystem */
#define	blkoff(fs, b)	(secbyt(fs, (fs)->lsndta) + \
				blkbyt(fs, (b) - LOCLUS))

/* Convert cluster number to logical sector number */
#define	blklsn(fs, b)	((fs)->lsndta + blksec(fs, (b) - LOCLUS))

/* Convert cluster number to offset within FAT */
#define	fatoff(sz, c)	((sz) == 12 ? (c) + ((c) >> 1) :  \
			(sz) == 16 ? (c) << 1 :          \
			(c) << 2)

/* Does cluster number reference a valid data cluster? */
#define	okclus(fs, c)	((c) >= LOCLUS && (c) <= (fs)->xclus)

/* Get start cluster from directory entry */
#define	stclus(sz, de)	((sz) != 32 ? (uint_t)cv2((de)->clus) :          \
			((uint_t)cv2((de)->dex.h_clus) << 16) |  \
			cv2((de)->clus))

static int parsebs(DOS_FS *, DOS_BS *);
static int namede(DOS_FS *, const char *, DOS_DE **);
static int lookup(DOS_FS *, uint_t, const char *, DOS_DE **);
static void cp_xdnm(uchar_t *, DOS_XDE *);
static void cp_sfn(uchar_t *, DOS_DE *);
static off_t fsize(DOS_FS *, DOS_DE *);
static int fatcnt(DOS_FS *, uint_t);
static int fatget(DOS_FS *, uint_t *);
static int fatend(uint_t, uint_t);
static int ioread(DOS_FS *, uint64_t, void *, size_t);
static int ioget(DOS_FS *, daddr_t, void *, size_t);

static int
dos_read_fatblk(DOS_FS *fs, uint_t blknum)
{
	int err;
	ssize_t io_size;
	daddr_t offset_in_fat, max_offset_in_fat;

	/*
	 * Because daddr_t is signed, we also use signed io_size
	 * so we can avoid type cast we would otherwise need
	 * because of promotion to unsigned.
	 */
	io_size = FATBLKSZ;
	offset_in_fat = ((daddr_t)blknum) * io_size;
	max_offset_in_fat = secbyt(fs, (daddr_t)fs->spf);
	if (offset_in_fat > max_offset_in_fat)
		offset_in_fat = max_offset_in_fat;
	if (offset_in_fat + io_size > max_offset_in_fat)
		io_size = (max_offset_in_fat - offset_in_fat);

	if (io_size != 0) {
		err = ioget(fs, fs->lsnfat + bytsec(fs, offset_in_fat),
		    fs->fatbuf, io_size);
		if (err != 0) {
			fs->fatbuf_blknum = ((uint_t)(-1));
			return (err);
		}
	}

	if (io_size < FATBLKSZ)
		memset(fs->fatbuf + io_size, 0, FATBLKSZ - io_size);

	fs->fatbuf_blknum = blknum;
	return (0);
}

/*
 * Mount DOS filesystem
 */
static int
dos_mount(DOS_FS **fsp, struct open_file *fd)
{
	int err;
	unsigned secsz;
	uchar_t *buf;
	DOS_FS *fs;

	/* Allocate mount structure, associate with open */
	fs = calloc(1, sizeof (DOS_FS));
	if (fs == NULL)
		return (errno);
	fs->fd = fd;

	err = ioctl(fd->f_id, DIOCGSECTORSIZE, &secsz);
	if (err != 0) {
		free(fs);
		return (err);
	}

	buf = malloc(secsz);
	if (buf == NULL) {
		free(fs);
		return (errno);
	}

	if ((err = ioget(fs, 0, buf, secsz)) ||
	    (err = parsebs(fs, (DOS_BS *)buf))) {
		free(buf);
		free(fs);
		return (err);
	}
	fs->secbuf = buf;

	fs->fatbuf = malloc(FATBLKSZ);
	if (fs->fatbuf == NULL) {
		free(buf);
		free(fs);
		return (errno);
	}
	err = dos_read_fatblk(fs, 0);
	if (err != 0) {
		free(fs->fatbuf);
		free(buf);
		free(fs);
		return (err);
	}

	fs->root = dot[0];
	fs->root.name[0] = ' ';
	if (fs->fatsz == 32) {
		fs->root.clus[0] = fs->rdcl & 0xff;
		fs->root.clus[1] = (fs->rdcl >> 8) & 0xff;
		fs->root.dex.h_clus[0] = (fs->rdcl >> 16) & 0xff;
		fs->root.dex.h_clus[1] = (fs->rdcl >> 24) & 0xff;
	}
	*fsp = fs;
	return (0);
}

/*
 * Unmount mounted filesystem
 */
static int
dos_unmount(DOS_FS *fs)
{
	if (fs->links)
		return (EBUSY);
	free(fs->secbuf);
	free(fs->fatbuf);
	free(fs);
	return (0);
}

/*
 * Open DOS file
 */
static int
dos_open(const char *path, struct open_file *fd)
{
	DOS_DE *de;
	DOS_FILE *f;
	DOS_FS *fs;
	uint_t size, clus;
	int err;

	if ((err = dos_mount(&fs, fd))) {
		return (err);
	}

	if ((err = namede(fs, path, &de))) {
		dos_unmount(fs);
		return (err);
	}

	clus = stclus(fs->fatsz, de);
	size = cv4(de->size);

	if ((!(de->attr & FA_DIR) && (!clus != !size)) ||
	    ((de->attr & FA_DIR) && size) ||
	    (clus && !okclus(fs, clus))) {
		dos_unmount(fs);
		return (EINVAL);
	}
	if ((f = malloc(sizeof (DOS_FILE))) == NULL) {
		err = errno;
		dos_unmount(fs);
		return (err);
	}
	bzero(f, sizeof (DOS_FILE));
	f->fs = fs;
	fs->links++;
	f->de = *de;
	fd->f_fsdata = f;
	return (0);
}

/*
 * Read from file
 */
static int
dos_read(struct open_file *fd, void *buf, size_t nbyte, size_t *resid)
{
	off_t size;
	uint64_t off;
	size_t nb;
	uint_t clus, c, cnt, n;
	DOS_FILE *f = (DOS_FILE *)fd->f_fsdata;
	int err = 0;

	/*
	 * as ioget() can be called *a lot*, use twiddle here.
	 * also 4 seems to be good value not to slow loading down too much:
	 * with 270MB file (~540k ioget() calls, twiddle can easily waste
	 * 4-5 sec.
	 */
	twiddle(4);
	nb = nbyte;
	if ((size = fsize(f->fs, &f->de)) == -1)
		return (EINVAL);
	if (nb > (n = size - f->offset))
		nb = n;
	off = f->offset;
	if ((clus = stclus(f->fs->fatsz, &f->de)))
		off &= f->fs->bsize - 1;
	c = f->c;
	cnt = nb;
	while (cnt) {
		n = 0;
		if (!c) {
			if ((c = clus))
				n = bytblk(f->fs, f->offset);
		} else if (!off)
			n++;
		while (n--) {
			if ((err = fatget(f->fs, &c)))
				goto out;
			if (!okclus(f->fs, c)) {
				err = EINVAL;
				goto out;
			}
		}
		if (!clus || (n = f->fs->bsize - off) > cnt)
			n = cnt;
		if (c != 0)
			off += blkoff(f->fs, (uint64_t)c);
		else
			off += secbyt(f->fs, f->fs->lsndir);
		err = ioread(f->fs, off, buf, n);
		if (err != 0)
			goto out;
		f->offset += n;
		f->c = c;
		off = 0;
		buf = (char *)buf + n;
		cnt -= n;
	}
out:
	if (resid)
		*resid = nbyte - nb + cnt;
	return (err);
}

/*
 * Reposition within file
 */
static off_t
dos_seek(struct open_file *fd, off_t offset, int whence)
{
	off_t off;
	uint_t size;
	DOS_FILE *f = (DOS_FILE *)fd->f_fsdata;

	size = cv4(f->de.size);
	switch (whence) {
	case SEEK_SET:
		off = 0;
		break;
	case SEEK_CUR:
		off = f->offset;
		break;
	case SEEK_END:
		off = size;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}
	off += offset;
	if (off < 0 || off > size) {
		errno = EINVAL;
		return (-1);
	}
	f->offset = (uint_t)off;
	f->c = 0;
	return (off);
}

/*
 * Close open file
 */
static int
dos_close(struct open_file *fd)
{
	DOS_FILE *f = (DOS_FILE *)fd->f_fsdata;
	DOS_FS *fs = f->fs;

	f->fs->links--;
	free(f);
	dos_unmount(fs);
	return (0);
}

/*
 * Return some stat information on a file.
 */
static int
dos_stat(struct open_file *fd, struct stat *sb)
{
	DOS_FILE *f = (DOS_FILE *)fd->f_fsdata;

	/* only important stuff */
	sb->st_mode = f->de.attr & FA_DIR ? S_IFDIR | 0555 : S_IFREG | 0444;
	sb->st_nlink = 1;
	sb->st_uid = 0;
	sb->st_gid = 0;
	if ((sb->st_size = fsize(f->fs, &f->de)) == -1)
		return (EINVAL);
	return (0);
}

static int
dos_checksum(unsigned char *name, unsigned char *ext)
{
	int x, i;
	char buf[11];

	bcopy(name, buf, 8);
	bcopy(ext, buf+8, 3);
	x = 0;
	for (i = 0; i < 11; i++) {
		x = ((x & 1) << 7) | (x >> 1);
		x += buf[i];
		x &= 0xff;
	}
	return (x);
}

static int
dos_readdir(struct open_file *fd, struct dirent *d)
{
	uchar_t fn[261];
	DOS_DIR dd;
	size_t res;
	uint_t chk, x, xdn;
	int err;

	x = chk = 0;
	while (1) {
		xdn = x;
		x = 0;
		err = dos_read(fd, &dd, sizeof (dd), &res);
		if (err)
			return (err);
		if (res == sizeof (dd))
			return (ENOENT);
		if (dd.de.name[0] == 0)
			return (ENOENT);

		/* Skip deleted entries */
		if (dd.de.name[0] == 0xe5)
			continue;

		/* Check if directory entry is volume label */
		if (dd.de.attr & FA_LABEL) {
			/*
			 * If volume label set, check if the current entry is
			 * extended entry (FA_XDE) for long file names.
			 */
			if ((dd.de.attr & FA_MASK) == FA_XDE) {
				/*
				 * Read through all following extended entries
				 * to get the long file name. 0x40 marks the
				 * last entry containing part of long file name.
				 */
				if (dd.xde.seq & 0x40)
					chk = dd.xde.chk;
				else if (dd.xde.seq != xdn - 1 ||
				    dd.xde.chk != chk)
					continue;
				x = dd.xde.seq & ~0x40;
				if (x < 1 || x > 20) {
					x = 0;
					continue;
				}
				cp_xdnm(fn, &dd.xde);
			} else {
				/* skip only volume label entries */
				continue;
			}
		} else {
			if (xdn == 1) {
				x = dos_checksum(dd.de.name, dd.de.ext);
				if (x == chk)
					break;
			} else {
				cp_sfn(fn, &dd.de);
				break;
			}
			x = 0;
		}
	}

	d->d_fileno = (dd.de.clus[1] << 8) + dd.de.clus[0];
	d->d_reclen = sizeof (*d);
	d->d_type = (dd.de.attr & FA_DIR) ? DT_DIR : DT_REG;
	memcpy(d->d_name, fn, sizeof (d->d_name));
	return (0);
}

/*
 * Parse DOS boot sector
 */
static int
parsebs(DOS_FS *fs, DOS_BS *bs)
{
	uint_t sc, RootDirSectors;

	if (bs->bpb.media < 0xf0)
		return (EINVAL);

	/* Check supported sector sizes */
	switch (cv2(bs->bpb.secsiz)) {
	case 512:
	case 1024:
	case 2048:
	case 4096:
		fs->sshift = ffs(cv2(bs->bpb.secsiz)) - 1;
		break;

	default:
		return (EINVAL);
	}

	if (!(fs->spc = bs->bpb.spc) || fs->spc & (fs->spc - 1))
		return (EINVAL);
	fs->bsize = secbyt(fs, fs->spc);
	fs->bshift = ffs(fs->bsize) - 1;
	fs->dshift = ffs(secbyt(fs, 1) / sizeof (DOS_DE)) - 1;
	fs->dirents = cv2(bs->bpb.dirents);
	fs->spf = cv2(bs->bpb.spf);
	fs->lsnfat = cv2(bs->bpb.ressec);

	if (fs->spf != 0) {
		if (bs->bpb.fats != 2)
			return (EINVAL);
		if (fs->dirents == 0)
			return (EINVAL);
	} else {
		fs->spf = cv4(bs->bpb.fstype.f32.lspf);
		if (fs->spf == 0)
			return (EINVAL);
		if (bs->bpb.fats == 0 || bs->bpb.fats > 16)
			return (EINVAL);
		fs->rdcl = cv4(bs->bpb.fstype.f32.rdcl);
		if (fs->rdcl < LOCLUS)
			return (EINVAL);
	}

	RootDirSectors = ((fs->dirents * sizeof (DOS_DE)) +
	    (secbyt(fs, 1) - 1)) / secbyt(fs, 1);

	fs->lsndir = fs->lsnfat + fs->spf * bs->bpb.fats;
	fs->lsndta = fs->lsndir + RootDirSectors;
	if (!(sc = cv2(bs->bpb.secs)) && !(sc = cv4(bs->bpb.lsecs)))
		return (EINVAL);
	if (fs->lsndta > sc)
		return (EINVAL);
	if ((fs->xclus = secblk(fs, sc - fs->lsndta) + 1) < LOCLUS)
		return (EINVAL);
	fs->fatsz = fs->dirents ? fs->xclus < 0xff6 ? 12 : 16 : 32;
	sc = (secbyt(fs, fs->spf) << 1) / (fs->fatsz >> 2) - 1;
	if (fs->xclus > sc)
		fs->xclus = sc;
	return (0);
}

/*
 * Return directory entry from path
 */
static int
namede(DOS_FS *fs, const char *path, DOS_DE **dep)
{
	char name[256];
	DOS_DE *de;
	char *s;
	size_t n;
	int err;

	err = 0;
	de = &fs->root;
	while (*path) {
		while (*path == '/')
			path++;
		if (*path == '\0')
			break;
		if (!(s = strchr(path, '/')))
			s = strchr(path, 0);
		if ((n = s - path) > 255)
			return (ENAMETOOLONG);
		memcpy(name, path, n);
		name[n] = 0;
		path = s;
		if (!(de->attr & FA_DIR))
			return (ENOTDIR);
		if ((err = lookup(fs, stclus(fs->fatsz, de), name, &de)))
			return (err);
	}
	*dep = de;
	return (0);
}

/*
 * Lookup path segment
 */
static int
lookup(DOS_FS *fs, uint_t clus, const char *name, DOS_DE **dep)
{
	DOS_DIR *dir;
	uchar_t lfn[261];
	uchar_t sfn[13];
	uint_t nsec, lsec, xdn, chk, sec, ent, x;
	int err, ok;

	if (!clus)
		for (ent = 0; ent < 2; ent++)
			if (!strcasecmp(name, dotstr[ent])) {
				*dep = dot + ent;
				return (0);
			}
	if (!clus && fs->fatsz == 32)
		clus = fs->rdcl;
	nsec = !clus ? entsec(fs, fs->dirents) : fs->spc;
	lsec = 0;
	xdn = chk = 0;
	dir = (DOS_DIR *)fs->secbuf;
	for (;;) {
		if (!clus && !lsec)
			lsec = fs->lsndir;
		else if (okclus(fs, clus))
			lsec = blklsn(fs, clus);
		else
			return (EINVAL);

		for (sec = 0; sec < nsec; sec++) {
			if ((err = ioget(fs, lsec + sec, dir,
			    secbyt(fs, 1))))
				return (err);
			for (ent = 0; ent < depsec(fs); ent++) {
				if (dir[ent].de.name[0] == 0)
					return (ENOENT);
				if (dir[ent].de.name[0] == 0xe5) {
					xdn = 0;
					continue;
				}
				if ((dir[ent].de.attr & FA_MASK) == FA_XDE) {
					x = dir[ent].xde.seq;
					if (x & 0x40 ||
					    (x + 1 == xdn &&
					    dir[ent].xde.chk == chk)) {
						if (x & 0x40) {
							chk = dir[ent].xde.chk;
							x &= ~0x40;
						}
						if (x >= 1 && x <= 20) {
							cp_xdnm(lfn,
							    &dir[ent].xde);
							xdn = x;
							continue;
						}
					}
				} else if (!(dir[ent].de.attr & FA_LABEL)) {
					if ((ok = xdn == 1)) {
						x = dos_checksum(
						    dir[ent].de.name,
						    dir[ent].de.ext);
						ok = chk == x &&
						    !strcasecmp(name,
						    (const char *)lfn);
					}
					if (!ok) {
						cp_sfn(sfn, &dir[ent].de);
						ok = !strcasecmp(name,
						    (const char *)sfn);
					}
					if (ok) {
						*dep = &dir[ent].de;
						return (0);
					}
				}
				xdn = 0;
			}
		}
		if (!clus)
			break;
		if ((err = fatget(fs, &clus)))
			return (err);
		if (fatend(fs->fatsz, clus))
			break;
	}
	return (ENOENT);
}

/*
 * Copy name from extended directory entry
 */
static void
cp_xdnm(uchar_t *lfn, DOS_XDE *xde)
{
	static struct {
		uint_t off;
		uint_t dim;
	} ix[3] = {
		{ offsetof(DOS_XDE, name1), sizeof (xde->name1) / 2},
		{ offsetof(DOS_XDE, name2), sizeof (xde->name2) / 2},
		{ offsetof(DOS_XDE, name3), sizeof (xde->name3) / 2}
	};
	uchar_t *p;
	uint_t n, x, c;

	lfn += 13 * ((xde->seq & ~0x40) - 1);
	for (n = 0; n < 3; n++)
		for (p = (uchar_t *)xde + ix[n].off, x = ix[n].dim; x;
		    p += 2, x--) {
			if ((c = cv2(p)) && (c < 32 || c > 127))
				c = '?';
			if (!(*lfn++ = c))
				return;
		}
	if (xde->seq & 0x40)
		*lfn = 0;
}

/*
 * Copy short filename
 */
static void
cp_sfn(uchar_t *sfn, DOS_DE *de)
{
	uchar_t *p;
	int j, i;

	p = sfn;
	if (*de->name != ' ') {
		for (j = 7; de->name[j] == ' '; j--)
			;
		for (i = 0; i <= j; i++)
			*p++ = de->name[i];
		if (*de->ext != ' ') {
			*p++ = '.';
			for (j = 2; de->ext[j] == ' '; j--)
				;
			for (i = 0; i <= j; i++)
				*p++ = de->ext[i];
		}
	}
	*p = '\0';
	if (*sfn == 5)
		*sfn = 0xe5;
}

/*
 * Return size of file in bytes
 */
static off_t
fsize(DOS_FS *fs, DOS_DE *de)
{
	ulong_t size;
	uint_t c;
	int n;

	if (!(size = cv4(de->size)) && de->attr & FA_DIR) {
		if (!(c = stclus(fs->fatsz, de)))
			size = fs->dirents * sizeof (DOS_DE);
		else {
			if ((n = fatcnt(fs, c)) == -1)
				return (n);
			size = blkbyt(fs, n);
		}
	}
	return (size);
}

/*
 * Count number of clusters in chain
 */
static int
fatcnt(DOS_FS *fs, uint_t c)
{
	int n;

	for (n = 0; okclus(fs, c); n++)
		if (fatget(fs, &c))
			return (-1);
	return (fatend(fs->fatsz, c) ? n : -1);
}

/*
 * Get next cluster in cluster chain. Use in core fat cache unless
 * the number of current 128K block in FAT has changed.
 */
static int
fatget(DOS_FS *fs, uint_t *c)
{
	uint_t val_in, val_out, offset, blknum, nbyte;
	const uchar_t *p_entry;
	int err;

	/* check input value to prevent overflow in fatoff() */
	val_in = *c;
	if (val_in & 0xf0000000)
		return (EINVAL);

	/* ensure that current 128K FAT block is cached */
	offset = fatoff(fs->fatsz, val_in);
	nbyte = fs->fatsz != 32 ? 2 : 4;
	if (offset + nbyte > secbyt(fs, fs->spf))
		return (EINVAL);
	blknum = offset / FATBLKSZ;
	offset %= FATBLKSZ;
	if (offset + nbyte > FATBLKSZ)
		return (EINVAL);
	if (blknum != fs->fatbuf_blknum) {
		err = dos_read_fatblk(fs, blknum);
		if (err != 0)
			return (err);
	}
	p_entry = fs->fatbuf + offset;

	/* extract cluster number from FAT entry */
	switch (fs->fatsz) {
	case 32:
		val_out = cv4(p_entry);
		val_out &= 0x0fffffff;
		break;
	case 16:
		val_out = cv2(p_entry);
		break;
	case 12:
		val_out = cv2(p_entry);
		if (val_in & 1)
			val_out >>= 4;
		else
			val_out &= 0xfff;
		break;
	default:
		return (EINVAL);
	}
	*c = val_out;
	return (0);
}

/*
 * Is cluster an end-of-chain marker?
 */
static int
fatend(uint_t sz, uint_t c)
{
	return (c > (sz == 12 ? 0xff7U : sz == 16 ? 0xfff7U : 0xffffff7));
}

/*
 * Offset-based I/O primitive
 */
static int
ioread(DOS_FS *fs, uint64_t offset, void *buf, size_t nbyte)
{
	char *s;
	size_t n, secsiz;
	int err;
	uint64_t off;

	secsiz = secbyt(fs, 1);
	s = buf;
	if ((off = offset & (secsiz - 1))) {
		offset -= off;
		if ((n = secsiz - off) > nbyte)
			n = nbyte;
		err = ioget(fs, bytsec(fs, offset), fs->secbuf, secsiz);
		if (err != 0)
			return (err);
		memcpy(s, fs->secbuf + off, n);
		offset += secsiz;
		s += n;
		nbyte -= n;
	}
	n = nbyte & (secsiz - 1);
	if (nbyte -= n) {
		if ((err = ioget(fs, bytsec(fs, offset), s, nbyte)))
			return (err);
		offset += nbyte;
		s += nbyte;
	}
	if (n != 0) {
		err = ioget(fs, bytsec(fs, offset), fs->secbuf, secsiz);
		if (err != 0)
			return (err);
		memcpy(s, fs->secbuf, n);
	}
	return (0);
}

/*
 * Sector-based I/O primitive. Note, since strategy functions are operating
 * in terms of 512B sectors, we need to do necessary conversion here.
 */
static int
ioget(DOS_FS *fs, daddr_t lsec, void *buf, size_t size)
{
	size_t rsize;
	int rv;
	struct open_file *fd = fs->fd;

	/* Make sure we get full read or error. */
	rsize = 0;
	/* convert native sector number to 512B sector number. */
	lsec = secbyt(fs, lsec) >> 9;
	rv = (fd->f_dev->dv_strategy)(fd->f_devdata, F_READ, lsec,
	    size, buf, &rsize);
	if ((rv == 0) && (size != rsize))
		rv = EIO;
	return (rv);
}
