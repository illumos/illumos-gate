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

#include <fcntl.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "iso_spec.h"
#include "iso_impl.h"

extern char *myname;

static void wrdirent(struct dlist *dp, int opt);

/* domkpath - creates an iso  path table based on the iso directory list */
/* worg denotes big or little endian machine */
/* write the path table to lbn */
/* return the next available lbn */
int
domkpath_iso(rootdp, lbn, worg, psize)
struct dlist *rootdp;
int lbn;
int worg;
int *psize;
{
int	totsize;
int	size;
struct	dlist *dp;
int	daddr;
char	buf[256];

	daddr = LBN_TO_BYTE(lbn);
	totsize = 0;
	size = 0;
	for (dp = rootdp; dp != NULL; dp = dp->idirnext) {
		/* obtain the offset in path table */
		dp->ipoffset = totsize;
		size = crpathent(dp, buf, worg, CD_ISO);
		putdisk(buf, daddr+totsize, size);
		totsize += size;
	}

	*psize = totsize;
	return (fillblkzero(lbn, totsize));
}

/* domkpath_unix - creates a path table based on the unix directory list */
/* worg denotes big or little endian machine */
/* write the path table to lbn */
/* return the next available lbn */
int
domkpath_unix(rootdp, lbn, worg, psize)
struct dlist *rootdp;
int lbn;
int worg;
int *psize;
{
int	totsize;
int	size;
struct	dlist *dp;
int	daddr;
char    buf[256];

	daddr = LBN_TO_BYTE(lbn);
	totsize = 0;
	size = 0;
	for (dp = rootdp; dp != NULL; dp = dp->udirnext) {
		/* obtain the offset in path table */
		dp->upoffset = totsize;
		size = crpathent(dp, buf, worg, CD_UNIX);
		putdisk(buf, daddr+totsize, size);
		totsize += size;
	}

	*psize = totsize;
	return (fillblkzero(lbn, totsize));

}

/* mkpath - create the path table */
/* return the next lbn that can be used to store data */
int
mkpath(rootdp, lbn, extension)
struct dlist *rootdp;
int lbn;
int extension;
{
int	nextlbn;
int	lbn_iso_msb, lbn_iso_lsb;
int	lbn_unix_msb, lbn_unix_lsb;
int	size_iso_ptable;
int	size_unix_ptable;


	/* build the path table for iso lsb first */
	lbn_iso_lsb = lbn;
	lbn_iso_msb = domkpath_iso(rootdp, lbn_iso_lsb, CD_LSB,
	    &size_iso_ptable);
	/* build the path table for iso msb */
	nextlbn = domkpath_iso(rootdp, lbn_iso_msb, CD_MSB,
	    &size_iso_ptable);

	if (extension) {
		/* build the path table for unix lsb first */
		lbn_unix_lsb = nextlbn;
		lbn_unix_msb = domkpath_unix(rootdp, lbn_unix_lsb, CD_LSB,
		    &size_unix_ptable);
		/* build the path table for iso msb */
		nextlbn = domkpath_unix(rootdp, lbn_unix_msb, CD_MSB,
		    &size_unix_ptable);
	}

	/* record the information in PVD for ISO */
	both_int(ISO_ptbl_size(v), size_iso_ptable);
	(void) lsb_int(ISO_ptbl_man_ls(v), lbn_iso_lsb);
	(void) msb_int(ISO_ptbl_man_ms(v), lbn_iso_msb);
	/* write the descriptor to disk */
	(void) PUTSECTOR(v, ISO_VOLDESC_SEC, 1);

	if (extension) {
		/* record the information is OSD for UNIX */
		both_int(ISO_ptbl_size(u), size_unix_ptable);
		(void) lsb_int(ISO_ptbl_man_ls(u), lbn_unix_lsb);
		(void) msb_int(ISO_ptbl_man_ms(u), lbn_unix_msb);
		/* write the descriptor to disk */
		(void) PUTSECTOR(u, unix_voldesc_sec, 1);
	}

	return (nextlbn);
}

/* domkdir_iso - creates a iso directory based on the directory list */
/* write the directory table to lbn */
/* return the next available lbn */
int
domkdir_iso(dirdp, startlbn)
struct dlist *dirdp;
int startlbn;
{
int	totsize;
int	size;
struct	dlist *dp;
int	daddr;
char    buf[256];
int lbn;

	daddr = LBN_TO_BYTE(startlbn);
	totsize = size = 0;
	/* create dot first */
	dirdp->idextlbn = lbn = startlbn;
	size = crdirent(dirdp, buf, CD_DOT, CD_ISO);
	putdisk(buf, daddr+totsize, size);

	totsize += size;
	/* then create dotdot (parent) first */
	size = crdirent(dirdp, buf, CD_DOTDOT, CD_ISO);
	putdisk(buf, daddr+totsize, size);
	totsize += size;

	for (dp = dirdp->icdp; dp != NULL; dp = dp->inext) {
		if ((dp->dmode & S_IFMT) == S_IFDIR);
		else if ((dp->dmode & S_IFMT) == S_IFREG);
		else continue;

		size = crdirent(dp, buf, CD_REGULAR, CD_ISO);
		/* directory entry cannot span across sector */
		if (totsize+size > ISO_SECTOR_SIZE) {
			/* fill the remaining block with zeros */
			lbn = fillblkzero(lbn, totsize);
			daddr = LBN_TO_BYTE(lbn);
			totsize = 0;
		}
		dp->idoffset = totsize;
		dp->idlbn = lbn;
		putdisk(buf, daddr+totsize, size);
		totsize += size;
	}

	dirdp->idsize = roundup(((lbn - startlbn) * blk_size + totsize),
	    ISO_SECTOR_SIZE);
	/* fill remaining space in the block, if needed */
	lbn = fillblkzero(lbn, totsize);
	/* add additional blocks to make it a sector boundary */
	lbn = fillzero(lbn);
	/* update directory entry */
	(void) wrdirent(dirdp, CD_ISO);
	return (lbn);

}

/* domkdir_unix - creates an unix directory based on the directory list */
/* write the directory table to lbn */
/* return the next available lbn */
int
domkdir_unix(dirdp, startlbn)
struct dlist *dirdp;
int startlbn;
{
int	totsize;
int	size;
struct	dlist *dp;
int	daddr;
char    buf[256];
int	lbn;

	daddr = LBN_TO_BYTE(startlbn);
	totsize = size = 0;
	/* create dot first */
	dirdp->udextlbn = lbn = startlbn;
	size = crdirent(dirdp, buf, CD_DOT, CD_UNIX);
	putdisk(buf, daddr+totsize, size);

	totsize += size;
	/* then create dotdot (parent) first */
	size = crdirent(dirdp, buf, CD_DOTDOT, CD_UNIX);
	putdisk(buf, daddr+totsize, size);
	totsize += size;

	for (dp = dirdp->ucdp; dp != NULL; dp = dp->unext) {
		size = crdirent(dp, buf, CD_REGULAR, CD_UNIX);
		/* directory entry cannot span across sector */
		if (totsize+size > ISO_SECTOR_SIZE) {
			/* fill the remaining block with zeros */
			lbn = fillblkzero(lbn, totsize);
			daddr = LBN_TO_BYTE(lbn);
			totsize = 0;
		}
		dp->udoffset = totsize;
		dp->udlbn = lbn;
		putdisk(buf, daddr+totsize, size);
		totsize += size;
	}

	dirdp->udsize = roundup(((lbn - startlbn) * blk_size + totsize),
	    ISO_SECTOR_SIZE);
	/* fill remaining space in the block, if needed */
	lbn = fillblkzero(lbn, totsize);
	/* add additional blocks to make it a sector boundary */
	lbn = fillzero(lbn);
	/* update directory entry */
	(void) wrdirent(dirdp, CD_UNIX);
	return (lbn);

}


/* mkdata - copy unix files to cdrom format */
int
mkdata(rootdp, lbn, extension)
struct dlist *rootdp;
int lbn;
int extension;
{
int nextlbn;

	if (extension)
		nextlbn =  mkdata_all(rootdp, lbn);
	else
		nextlbn = mkdata_iso(rootdp, lbn);
	/* make sure data ends at sector boundary */
	nextlbn = fillzero(nextlbn);
	return (nextlbn);
}

/* mkdata - copy unix files to cdrom unix extension format */
int
mkdata_all(rootdp, lbn)
struct dlist *rootdp;
int lbn;
{
int nextlbn;
struct dlist *dp;
struct dlist *fp;
int filesize;
char	path[1024];

	nextlbn = lbn;

	/* always process UNIX first */
	for (dp = rootdp; dp != NULL; dp = dp->udirnext) {
		/* create the directory for iso tree first */
		/* directory also in iso tree */
		if (dp->idno != 0) {
			/* make sure directory starts at sector boundary */
			nextlbn = fillzero(nextlbn);
			nextlbn = domkdir_iso(dp, nextlbn);
		}
		/* make sure directory entry starts at sector boundary */
		nextlbn = fillzero(nextlbn);
		nextlbn = domkdir_unix(dp, nextlbn);
		if (!prototype) {
			/* get the full path name */
			(void) getpath(dp, path);
			/* change directory */
			if (chdir(path) < 0) {
				fprintf(stderr, "%s: cannot chdir: ", myname);
				perror(path);
				continue;
			}
		}
		for (fp = dp->ucdp; fp != NULL; fp = fp->unext) {
			switch (fp->dmode & S_IFMT) {
				case S_IFDIR:
					break;
				case S_IFREG:
					/* get the next lbn of the data file */
					fp->extlbn = nextlbn;
					nextlbn = copyfile(fp, nextlbn,
					    &filesize);
					/*
					 * copyfile must return length
					 * to be updated in dir
					 */
					fp->fsize = filesize;
					(void) wrdirent(fp, CD_UNIX);
					/* file also in iso directory */
					if (fp->idlbn != 0)
						(void) wrdirent(fp, CD_ISO);
					break;
				case S_IFLNK:
					/* create symbolic link */
					fp->extlbn = nextlbn;
					nextlbn = makelnk(fp, nextlbn,
					    &filesize);
					/*
					 * copyfile must return length
					 * to be updated in dir
					 */
					fp->fsize = filesize;
					(void) wrdirent(fp, CD_UNIX);
					break;
				default:
					fprintf(stderr,
					    "%s: unknown file type\n", myname);
					break;
			}
		}
	}

	/* then process ISO next */
	for (dp = rootdp; dp != NULL; dp = dp->idirnext) {
		/* already processed */
		if (dp->udno != 0) continue;
		nextlbn = fillzero(nextlbn);
		nextlbn = domkdir_iso(dp, nextlbn);
		for (fp = dp->icdp; fp != NULL; fp = fp->inext) {
			/* we only have to deal with regular files */
			/* directories are handled separately */
			if ((fp->dmode & S_IFMT) != S_IFREG) continue;
			/* get the next lbn of the data file */
			fp->extlbn = nextlbn;
			nextlbn = copyfile(fp, nextlbn, &filesize);
			/* copyfile must return length to be updated in dir */
			fp->fsize = filesize;
			(void) wrdirent(fp, CD_ISO);
		}
	}
	return (nextlbn);
}

/* mkdata - copy unix files to cdrom iso 9660 format */
int
mkdata_iso(rootdp, lbn)
struct dlist *rootdp;
int lbn;
{
int nextlbn;
struct dlist *dp;
struct dlist *fp;
int filesize;
char	path[1024];

	nextlbn = lbn;

	for (dp = rootdp; dp != NULL; dp = dp->idirnext) {
		/* create the directory */
		if (dp->idno != 0) {
			/* make sure directory starts at sector boundary */
			nextlbn = fillzero(nextlbn);
			nextlbn = domkdir_iso(dp, nextlbn);
		}
		if (!prototype) {
			/* get the full path name */
			(void) getpath(dp, path);
			/* change directory */
			if (chdir(path) < 0) {
				fprintf(stderr, "%s: cannot chdir: ", myname);
				perror(path);
				continue;
			}
		}
		for (fp = dp->icdp; fp != NULL; fp = fp->inext) {
			/* we only have to deal with regular files */
			/* directories are handled separately */
			if ((fp->dmode & S_IFMT) != S_IFREG) continue;
			/* get the next lbn of the data file */
			fp->extlbn = nextlbn;
			nextlbn = copyfile(fp, nextlbn, &filesize);
			/* copyfile must return length to be updated in dir */
			fp->fsize = filesize;
			(void) wrdirent(fp, CD_ISO);
		}
	}
	return (nextlbn);
}

int
crpathent(dp, pep, wordorg, opt)
struct dlist *dp;
char *pep;
int wordorg;
int opt;
{
int	size;
short	dno, pdno;
char	*name;

	if (opt == CD_UNIX) {
		pdno = (short)dp -> pdp ->udno;
		dno = (short)dp -> udno;
		name = dp->unixfname;
	} else {
		pdno = (short)dp -> pdp ->idno;
		dno = (short)dp -> idno;
		name = dp->isofname;
	}

	if (wordorg == CD_MSB) {
		(void) msb_short(IPE_parent_no(pep), pdno);
		(void) msb_int(IPE_ext_lbn(pep), 0);
	} else {
		(void) lsb_short(IPE_parent_no(pep), pdno);
		(void) lsb_int(IPE_ext_lbn(pep), 0);
	}

	IPE_XAR_LEN(pep) = 0;

	/* root, ignore path name */
	if (dno == 1) {
		IPE_NAME_LEN(pep) = size = 1;
		*IPE_NAME(pep) = '\0';
	} else {
		IPE_NAME_LEN(pep) = size = strlen(name);
		strncpy(IPE_name(pep), (char *)name, size);
	}
	/* if size is an odd number, append a null char end of  name */
	size = (size << 1) - ((size >> 1) << 1);
	if (size != IPE_NAME_LEN(pep))
		*((char *)IPE_name(pep)+size) = '\0';

	if (opt == CD_UNIX) {
		/* now put in the unix extension */
		pep = pep + size;
		if (wordorg == CD_MSB) {
			(void) msb_int(IPE_UNIX_mode(pep), (int)dp->dmode);
			(void) msb_int(IPE_UNIX_uid(pep), (int)dp->duid);
			(void) msb_int(IPE_UNIX_gid(pep), (int)dp->dgid);
		} else {
			(void) lsb_int(IPE_UNIX_mode(pep), (int)dp->dmode);
			(void) lsb_int(IPE_UNIX_uid(pep), (int)dp->duid);
			(void) lsb_int(IPE_UNIX_gid(pep), (int)dp->dgid);
		}
		return (IPE_UNIX_FPESIZE+size);
	} else {
		return (IPE_FPESIZE+size);
	}

}

int
crdirent(dp, pep, type, opt)
struct dlist *dp;
char *pep;
int type;
int opt;
{
char *p;
static  uchar_t dot = '\0';
static  uchar_t dotdot = '\1';
int	dsize, dextlbn;
char	*name;
int	size;

	IDE_XAR_LEN(pep) = 0;
	(void) both_int(IDE_ext_lbn(pep), (int)0);
	(void) both_int(IDE_ext_size(pep), (int)0);
	(void) parse_unixdate(dp->mtime, IDE_cdate(pep));
	IDE_UNIX_RESERVED(pep) = 0;
	IDE_INTRLV_SIZE(pep) = 0;
	IDE_INTRLV_SKIP(pep) = 0;
	(void) both_short(IDE_vol_set(pep), (short)1); /* %% always 1 */

	switch (type) {
		case CD_DOT:
			size = 1;
			name = (char *)&dot;
			IDE_FLAGS(pep) = IDE_DIRECTORY;
			dextlbn = opt? dp->idextlbn : dp->udextlbn;
			dsize = 0;
			break;
		case CD_DOTDOT:
			size = 1;
			name = (char *)&dotdot;
			IDE_FLAGS(pep) = IDE_DIRECTORY;
			dextlbn = opt? dp->pdp->idextlbn: dp->pdp->udextlbn;
			dsize = opt? dp->pdp->idsize: dp->pdp->udsize;
			break;
		case CD_REGULAR:
			if (opt == CD_UNIX) {
				size = strlen(dp->unixfname);
				name = dp->unixfname;
			} else {
				size = strlen(dp->isofname);
				name = dp->isofname;
			}
			if ((dp -> dmode & S_IFMT) == S_IFDIR)
				IDE_FLAGS(pep) = IDE_DIRECTORY;
			else
				IDE_FLAGS(pep) = 0;
			dextlbn = dsize = 0;
			break;
		default:
			fprintf(stderr, "unknown type: panic\n");
			cleanup();
	}

	(void) both_int(IDE_ext_size(pep), dsize);
	(void) both_int(IDE_ext_lbn(pep), dextlbn);

	(void) memcpy(IDE_name(pep), name, size);
	IDE_NAME_LEN(pep) = size;

	/* add pending bute if size is even */
	if ((((uchar_t)size) & 0x01) == 0) {
		*((char *)IDE_name(pep) +size) = '\0';
		size++;
	}

	if (opt == CD_UNIX) {
		IDE_DIR_LEN(pep) = IDE_FDESIZE + size + IDE_UNIX_UX_LEN;
		p = (char *)pep + IDE_FDESIZE + size;
		(void) strncpy(IDE_UNIX_signature(p), IDE_UNIX_SIG_UX, 2);
		IDE_UNIX_EXT_LEN(p) = IDE_UNIX_UX_LEN;
		IDE_UNIX_USE_ID(p) = IDE_UNIX_USE_ID_VER;
		(void) both_int(IDE_UNIX_mode(p), (int)dp->dmode);
		(void) both_int(IDE_UNIX_uid(p), (int)dp->duid);
		(void) both_int(IDE_UNIX_gid(p), (int)dp->dgid);
		(void) both_int(IDE_UNIX_nlink(p), (int)dp->nlink);
		prntunixdir(pep);
	} else IDE_DIR_LEN(pep) = IDE_FDESIZE + size;

	return (IDE_DIR_LEN(pep));

}

/* magic_extlbn is used as extlbn by empty file */
/* to overcome a cdrom file system bug */
static int magic_extlbn = -1;

/* update dirctory entry */
static void
wrdirent(struct dlist *dp, int opt)
{
char *pep;
char buf[ISO_SECTOR_SIZE];
int	extlbn;
int	dlbn;
int	doffset;
int 	size;

	if (opt == CD_UNIX) {
		extlbn = dp->udextlbn;
		size = dp->udsize;
		dlbn = dp->udlbn;
		doffset = dp->udoffset;
	} else {
		extlbn = dp->idextlbn;
		size = dp->idsize;
		dlbn = dp->idlbn;
		doffset = dp->idoffset;
	}

	if ((dp->dmode & S_IFMT) == S_IFDIR) {
		/* update the current one */
		/* first entry (offset 0) is itself */
		GETLBN(buf, extlbn, nlbn_per_sec);
		pep = (char *)buf;
		(void) both_int(IDE_ext_size(pep), size);
		(void) both_int(IDE_ext_lbn(pep), extlbn);
		(void) PUTLBN(buf, extlbn, nlbn_per_sec);
		if (dp == dp->pdp) {
			/* update the dotdot's directory entry */
			/* rootdir does not have dotdot */
			/* assume dirent is still in buf[] */
			(void) memcpy(pep+IDE_DIR_LEN(pep), pep,
			    IDE_DIR_LEN(pep));
			/* dotdot has a name 01, dot is 00 */
			*IDE_name(pep+IDE_DIR_LEN(pep)) = '\01';
			(void) PUTLBN(buf, extlbn, nlbn_per_sec);
		} else {
			/* update parent directory's entry */
			GETLBN(buf, dlbn, nlbn_per_sec);
			pep = (char *)buf + doffset;
			(void) both_int(IDE_ext_size(pep), size);
			(void) both_int(IDE_ext_lbn(pep), extlbn);
			(void) PUTLBN(buf, dlbn, nlbn_per_sec);
		}
	} else {
		GETLBN(buf, dlbn, nlbn_per_sec);
		pep = (char *)buf + doffset;
		(void) both_int(IDE_ext_size(pep), dp->fsize);
		if (dp->fsize != 0)
			(void) both_int(IDE_ext_lbn(pep), dp->extlbn);
		else
			(void) both_int(IDE_ext_lbn(pep), magic_extlbn--);
		if (opt == CD_UNIX) prntunixdir(pep);
		else
			prntisodir(pep);
		(void) PUTLBN(buf, dlbn, nlbn_per_sec);
	}
}
