/*
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980, 1986, 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that: (1) source distributions retain this entire copyright
 * notice and comment, and (2) distributions including binaries display
 * the following acknowledgement:  ``This product includes software
 * developed by the University of California, Berkeley and its contributors''
 * in the documentation or other materials provided with the distribution
 * and in all advertising materials mentioning features or use of this
 * software. Neither the name of the University nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdio.h>
#include <strings.h>
#include <malloc.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/mntent.h>
#include <sys/vnode.h>
#include <sys/fs/udf_volume.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include "fsck.h"
#include "udfs.h"
#include <locale.h>

/*
 * for each large file ( size > MAXOFF_T) this global counter
 * gets incremented here.
 */

extern unsigned int largefile_count;
extern void	pwarn(char *, ...);
extern void	pfatal(char *, ...);
extern void	errexit(char *, ...);

extern int32_t	verifytag(struct tag *, uint32_t, struct tag *, int);
extern char	*tagerrs[];
extern void	maketag(struct tag *, struct tag *);
extern void	flush(int32_t, struct bufarea *);
extern void	putfilentry(struct bufarea *);
extern int32_t	bread(int32_t, char *, daddr_t, long);
extern void	bwrite(int, char *, daddr_t, long);
extern int32_t	dofix(struct inodesc *, char *);
extern int32_t	reply(char *);
extern void	ud_swap_short_ad(short_ad_t *);
extern void	ud_swap_long_ad(long_ad_t *);

extern void	dump16(char *, char *);

static void	adjust(struct fileinfo *);
static void	opndir(struct file_entry *);
static int32_t	getdir(struct file_entry *, struct bufarea **,
	u_offset_t *, struct file_id **);
static void ckinode(struct file_entry *);
struct bufarea *getfilentry();

/* Fields for traversing an allocation extent */
static uint32_t dir_adrsize;
static uint32_t dir_adrindx;
static uint32_t dir_naddrs;
static uint8_t *extbuf;
static uint8_t *dir_adrlist;

/* Keep track of where we are in the directory */
static u_offset_t dir_baseoff;
static uint32_t dir_basesize;
static uint8_t *dirbuf;
static uint8_t *dir_fidp;
static uint32_t baseblock;

#define	MAXFIDSIZE 2048

static uint8_t fidbuf[MAXFIDSIZE];

void
pass1()
{
	register struct file_entry *fp;
	register struct fileinfo *fip;
	register struct bufarea *bp;
	struct file_id *fidp;
	struct bufarea *fbp;
	int err;

	(void) cachefile(rootblock, rootlen);
	fip = &inphead[0];		/* The root */
	fip->fe_lseen = 0;		/* Didn't get here through directory */
	n_files = n_dirs = 0;
	while (fip->fe_block) {
		u_offset_t offset, end;

		markbusy(fip->fe_block, fip->fe_len);
		bp = getfilentry(fip->fe_block, fip->fe_len);
		if (bp == NULL) {
			pwarn(gettext("Unable to read file entry at %x\n"),
				fip->fe_block);
			goto next;
		}
		/* LINTED */
		fp = (struct file_entry *)bp->b_un.b_buf;
		fip->fe_lcount = fp->fe_lcount;
		fip->fe_type = fp->fe_icb_tag.itag_ftype;
		if (fp->fe_uniq_id >= maxuniqid)
			maxuniqid = fp->fe_uniq_id + 1;

		if (fip->fe_block == rootblock &&
				fip->fe_type != FTYPE_DIRECTORY)
			errexit(gettext("Root file entry is not a "
				"directory\n"));

		if (debug) {
			(void) printf("do %x len %d type %d lcount %d"
				" lseen %d end %llx\n",
				fip->fe_block, fip->fe_len,
				fip->fe_type, fip->fe_lcount,
				fip->fe_lseen, fp->fe_info_len);
		}
		switch (fip->fe_type) {
		case FTYPE_DIRECTORY:
			n_dirs++;
			offset = 0;
			end = fp->fe_info_len;
			fbp = NULL;
			opndir(fp);
			for (offset = 0; offset < end;
					offset += FID_LENGTH(fidp)) {
				err = getdir(fp, &fbp, &offset, &fidp);
				if (err) {
					pwarn(gettext("Bad directory entry in "
						"file %x at offset %llx\n"),
						fip->fe_block, offset);
					offset = end;
				}
				if (fidp->fid_flags & FID_DELETED)
					continue;
				(void) cachefile(fidp->fid_icb.lad_ext_loc,
					fidp->fid_icb.lad_ext_len);
			}
			if (dirbuf) {
				free(dirbuf);
				dirbuf = NULL;
			}
			if (fbp)
				fbp->b_flags &= ~B_INUSE;
			if (debug)
				(void) printf("Done %x\n", fip->fe_block);
			break;

		case FTYPE_FILE:
		case FTYPE_SYMLINK:
			ckinode(fp);
			/* FALLTHROUGH */
		default:
			n_files++;
			break;
		}
		putfilentry(bp);
		bp->b_flags &= ~B_INUSE;
	next:
		/* At end of this set of fips, get the next set */
		if ((++fip)->fe_block == (uint32_t)-1)
			fip = fip->fe_nexthash;
	}

	/* Find bad link counts */
	fip = &inphead[0];
	while (fip->fe_block) {
		if (fip->fe_lcount != fip->fe_lseen)
			adjust(fip);
		/* At end of this set of fips, get the next set */
		if ((++fip)->fe_block == (uint32_t)-1)
			fip = fip->fe_nexthash;
	}
}

static void
opndir(struct file_entry *fp)
{
	if (dirbuf) {
		free(dirbuf);
		dirbuf = NULL;
	}
	if (extbuf) {
		free(extbuf);
		extbuf = NULL;
	}

	dir_baseoff = 0;
	dir_basesize = 0;
	dir_adrindx = 0;

	switch (fp->fe_icb_tag.itag_flags & 0x3) {
	case ICB_FLAG_SHORT_AD:
		dir_adrsize = sizeof (short_ad_t);
		dir_naddrs = fp->fe_len_adesc / sizeof (short_ad_t);
		dir_adrlist = (uint8_t *)(fp->fe_spec + fp->fe_len_ear);
		break;
	case ICB_FLAG_LONG_AD:
		dir_adrsize = sizeof (long_ad_t);
		dir_naddrs = fp->fe_len_adesc / sizeof (long_ad_t);
		dir_adrlist = (uint8_t *)(fp->fe_spec + fp->fe_len_ear);
		break;
	case ICB_FLAG_EXT_AD:
		errexit(gettext("Can't handle ext_ads in directories/n"));
		break;
	case ICB_FLAG_ONE_AD:
		dir_adrsize = 0;
		dir_naddrs = 0;
		dir_adrlist = NULL;
		dir_basesize = fp->fe_len_adesc;
		dir_fidp = (uint8_t *)(fp->fe_spec + fp->fe_len_ear);
		baseblock = fp->fe_tag.tag_loc;
		break;
	}
}

/* Allocate and read in an allocation extent */
/* ARGSUSED */
int
getallocext(struct file_entry *fp, uint32_t loc, uint32_t len)
{
	uint32_t nb;
	uint8_t *ap;
	int i;
	int err;
	struct alloc_ext_desc *aep;

	if (debug)
		(void) printf(" allocext loc %x len %x\n", loc, len);
	nb = roundup(len, secsize);
	if (extbuf)
		free(extbuf);
	extbuf = (uint8_t *)malloc(nb);
	if (extbuf == NULL)
		errexit(gettext("Can't allocate directory extent buffer\n"));
	if (bread(fsreadfd, (char *)extbuf,
			fsbtodb(loc + part_start), nb) != 0) {
		(void) fprintf(stderr,
			gettext("Can't read allocation extent\n"));
		return (1);
	}
	/* LINTED */
	aep = (struct alloc_ext_desc *)extbuf;
	err = verifytag(&aep->aed_tag, loc, &aep->aed_tag, UD_ALLOC_EXT_DESC);
	if (err) {
		(void) printf(
			gettext("Bad tag on alloc extent: %s\n"), tagerrs[err]);
		free(extbuf);
		return (1);
	}
	dir_adrlist = (uint8_t *)(aep + 1);
	dir_naddrs = aep->aed_len_aed / dir_adrsize;
	dir_adrindx = 0;

	/* Swap the descriptors */
	for (i = 0, ap = dir_adrlist; i < dir_naddrs; i++, ap += dir_adrsize) {
		if (dir_adrsize == sizeof (short_ad_t)) {
			/* LINTED */
			ud_swap_short_ad((short_ad_t *)ap);
		} else if (dir_adrsize == sizeof (long_ad_t)) {
			/* LINTED */
			ud_swap_long_ad((long_ad_t *)ap);
		}
	}

	return (0);
}

/*
 * Variables used in this function and their relationships:
 *  *poffset - read pointer in the directory
 *  dir_baseoff - offset at start of dirbuf
 *  dir_baselen - length of valid data in current extent
 *  dir_adrindx - index into current allocation extent for location of
 *	dir_baseoff
 *  dir_naddrs - number of entries in current allocation extent
 *  dir_fidp - pointer to dirbuf or immediate data in file entry
 *  baseblock - block address of dir_baseoff
 *  newoff - *poffset - dir_baseoff
 */
/* ARGSUSED1 */
static int32_t
getdir(struct file_entry *fp, struct bufarea **fbp,
	u_offset_t *poffset, struct file_id **fidpp)
{
	/* LINTED */
	register struct file_id *fidp = (struct file_id *)fidbuf;
	register struct short_ad *sap;
	register struct long_ad *lap;
	register int i, newoff, xoff = 0;
	uint32_t block = 0, nb, len, left;
	u_offset_t offset;
	int err, type;


again:
	offset = *poffset;
again2:
	if (debug)
		(void) printf("getdir %llx\n", offset);
	newoff = offset - dir_baseoff;
	if (newoff >= dir_basesize) {
		if (dirbuf) {
			free(dirbuf);
			dirbuf = NULL;
		}
	} else {
		if (block == 0)
			block = baseblock + (newoff / secsize);
		goto nextone;
	}

again3:
	switch (fp->fe_icb_tag.itag_flags & 0x3) {
	case ICB_FLAG_SHORT_AD:
		/* LINTED */
		sap = &((short_ad_t *)dir_adrlist)[dir_adrindx];
		for (i = dir_adrindx; i < dir_naddrs; i++, sap++) {
			len = EXTLEN(sap->sad_ext_len);
			type = EXTYPE(sap->sad_ext_len);
			if (type == 3) {
				if (i < dir_naddrs - 1)
					errexit(gettext("Allocation extent not "
						"at end of list\n"));
				markbusy(sap->sad_ext_loc, len);
				if (getallocext(fp, sap->sad_ext_loc, len))
					return (1);
				goto again3;
			}
			if (newoff < len)
				break;
			newoff -= len;
			dir_baseoff += len;
			if (debug)
				(void) printf(
				    " loc %x len %x\n", sap->sad_ext_loc,
					len);
		}
		dir_adrindx = i;
		if (debug)
			(void) printf(" loc %x len %x\n", sap->sad_ext_loc,
				sap->sad_ext_len);
		baseblock = sap->sad_ext_loc;
		if (block == 0)
			block = baseblock;
		dir_basesize = len;
		if (type < 2)
			markbusy(sap->sad_ext_loc, len);
		if (type != 0) {
			*poffset += dir_basesize;
			goto again;
		}
		nb = roundup(len, secsize);
		dirbuf = (uint8_t *)malloc(nb);
		if (dirbuf == NULL)
			errexit(gettext("Can't allocate directory extent "
				"buffer\n"));
		if (bread(fsreadfd, (char *)dirbuf,
				fsbtodb(baseblock + part_start), nb) != 0) {
			errexit(gettext("Can't read directory extent\n"));
		}
		dir_fidp = dirbuf;
		break;
	case ICB_FLAG_LONG_AD:
		/* LINTED */
		lap = &((long_ad_t *)dir_adrlist)[dir_adrindx];
		for (i = dir_adrindx; i < dir_naddrs; i++, lap++) {
			len = EXTLEN(lap->lad_ext_len);
			type = EXTYPE(lap->lad_ext_len);
			if (type == 3) {
				if (i < dir_naddrs - 1)
					errexit(gettext("Allocation extent not "
						"at end of list\n"));
				markbusy(lap->lad_ext_loc, len);
				if (getallocext(fp, lap->lad_ext_loc, len))
					return (1);
				goto again3;
			}
			if (newoff < len)
				break;
			newoff -= len;
			dir_baseoff += len;
			if (debug)
				(void) printf(
				    " loc %x len %x\n", lap->lad_ext_loc,
					len);
		}
		dir_adrindx = i;
		if (debug)
			(void) printf(" loc %x len %x\n", lap->lad_ext_loc,
				lap->lad_ext_len);
		baseblock = lap->lad_ext_loc;
		if (block == 0)
			block = baseblock;
		dir_basesize = len;
		if (type < 2)
			markbusy(lap->lad_ext_loc, len);
		if (type != 0) {
			*poffset += dir_basesize;
			goto again;
		}
		nb = roundup(len, secsize);
		dirbuf = (uint8_t *)malloc(nb);
		if (dirbuf == NULL)
			errexit(gettext("Can't allocate directory extent "
				"buffer\n"));
		if (bread(fsreadfd, (char *)dirbuf,
				fsbtodb(baseblock + part_start), nb) != 0) {
			errexit(gettext("Can't read directory extent\n"));
		}
		dir_fidp = dirbuf;
		break;
	case ICB_FLAG_EXT_AD:
		break;
	case ICB_FLAG_ONE_AD:
		errexit(gettext("Logic error in getdir - at ICB_FLAG_ONE_AD "
			"case\n"));
		break;
	}
nextone:
	if (debug)
		(void) printf("getdirend blk %x dir_baseoff %llx newoff %x\n",
			block, dir_baseoff, newoff);
	left = dir_basesize - newoff;
	if (xoff + left > MAXFIDSIZE)
		left = MAXFIDSIZE - xoff;
	bcopy((char *)dir_fidp + newoff, (char *)fidbuf + xoff, left);
	xoff += left;
	/*
	 * If we have a fid that crosses an extent boundary, then force
	 * a read of the next extent, and fill up the rest of the fid.
	 */
	if (xoff < sizeof (fidp->fid_tag) ||
	    xoff < sizeof (fidp->fid_tag) + SWAP16(fidp->fid_tag.tag_crc_len)) {
		offset += left;
		if (debug)
			(void) printf("block crossing at offset %llx\n",
				offset);
		goto again2;
	}
	err = verifytag(&fidp->fid_tag, block, &fidp->fid_tag, UD_FILE_ID_DESC);
	if (debug) {
		dump16((char *)fidp, "\n");
	}
	if (err) {
		pwarn(gettext("Bad directory tag: %s\n"), tagerrs[err]);
		return (err);
	}
	*fidpp = fidp;
	return (0);
}

static void
ckinode(struct file_entry *fp)
{
	register struct short_ad *sap;
	register struct long_ad *lap;
	register int i, type, len;

	switch (fp->fe_icb_tag.itag_flags & 0x3) {
	case ICB_FLAG_SHORT_AD:
		dir_adrsize = sizeof (short_ad_t);
		dir_naddrs = fp->fe_len_adesc / sizeof (short_ad_t);
		/* LINTED */
		sap = (short_ad_t *)(fp->fe_spec + fp->fe_len_ear);
again1:
		for (i = 0; i < dir_naddrs; i++, sap++) {
			len = EXTLEN(sap->sad_ext_len);
			type = EXTYPE(sap->sad_ext_len);
			if (type < 2)
				markbusy(sap->sad_ext_loc, len);
			if (debug)
				(void) printf(
				    " loc %x len %x\n", sap->sad_ext_loc,
					sap->sad_ext_len);
			if (type == 3) {
				markbusy(sap->sad_ext_loc, len);
				/* This changes dir_naddrs and dir_adrlist */
				if (getallocext(fp, sap->sad_ext_loc, len))
					break;
				/* LINTED */
				sap = (short_ad_t *)dir_adrlist;
				goto again1;
			}
		}
		break;
	case ICB_FLAG_LONG_AD:
		dir_adrsize = sizeof (long_ad_t);
		dir_naddrs = fp->fe_len_adesc / sizeof (long_ad_t);
		/* LINTED */
		lap = (long_ad_t *)(fp->fe_spec + fp->fe_len_ear);
again2:
		for (i = 0; i < dir_naddrs; i++, lap++) {
			len = EXTLEN(lap->lad_ext_len);
			type = EXTYPE(lap->lad_ext_len);
			if (type < 2)
				markbusy(lap->lad_ext_loc, len);
			if (debug)
				(void) printf(
				    " loc %x len %x\n", lap->lad_ext_loc,
					lap->lad_ext_len);
			if (type == 3) {
				markbusy(sap->sad_ext_loc, len);
				/* This changes dir_naddrs and dir_adrlist */
				if (getallocext(fp, lap->lad_ext_loc, len))
					break;
				/* LINTED */
				lap = (long_ad_t *)dir_adrlist;
				goto again2;
			}
		}
		break;
	case ICB_FLAG_EXT_AD:
		break;
	case ICB_FLAG_ONE_AD:
		break;
	}
}

static void
adjust(struct fileinfo *fip)
{
	register struct file_entry *fp;
	register struct bufarea *bp;

	bp = getfilentry(fip->fe_block, fip->fe_len);
	if (bp == NULL)
		errexit(gettext("Unable to read file entry at %x\n"),
			fip->fe_block);
	/* LINTED */
	fp = (struct file_entry *)bp->b_un.b_buf;
	pwarn(gettext("LINK COUNT %s I=%x"),
		fip->fe_type == FTYPE_DIRECTORY ? "DIR" :
		fip->fe_type == FTYPE_SYMLINK ? "SYM" :
		fip->fe_type == FTYPE_FILE ? "FILE" : "???", fip->fe_block);
	(void) printf(gettext(" COUNT %d SHOULD BE %d"),
		fip->fe_lcount, fip->fe_lseen);
	if (preen) {
		if (fip->fe_lseen > fip->fe_lcount) {
			(void) printf("\n");
			pfatal(gettext("LINK COUNT INCREASING"));
		}
		(void) printf(gettext(" (ADJUSTED)\n"));
	}
	if (preen || reply(gettext("ADJUST")) == 1) {
		fp->fe_lcount = fip->fe_lseen;
		putfilentry(bp);
		dirty(bp);
		flush(fswritefd, bp);
	}
	bp->b_flags &= ~B_INUSE;
}

void
dofreemap()
{
	register int i;
	register char *bp, *fp;
	struct inodesc idesc;

	if (freemap == NULL)
		return;

	/* Flip bits in the busy map */
	bp = busymap;
	for (i = 0, bp = busymap; i < part_bmp_bytes; i++, bp++)
		*bp = ~*bp;

	/* Mark leftovers in byte as allocated */
	if (part_len % NBBY)
		bp[-1] &= (unsigned)0xff >> (NBBY - part_len % NBBY);
	bp = busymap;
	fp = freemap;
	bzero((char *)&idesc, sizeof (struct inodesc));
	idesc.id_type = ADDR;
	if (bcmp(bp, fp, part_bmp_bytes) != 0 &&
		dofix(&idesc, gettext("BLK(S) MISSING IN FREE BITMAP"))) {
		bcopy(bp, fp, part_bmp_bytes);
		maketag(&spacep->sbd_tag, &spacep->sbd_tag);
		bwrite(fswritefd, (char *)spacep, fsbtodb(part_bmp_loc),
			part_bmp_sectors * secsize);
	}
}

void
dolvint()
{
	struct lvid_iu *lviup;
	struct inodesc idesc;

	bzero((char *)&idesc, sizeof (struct inodesc));
	idesc.id_type = ADDR;
	lviup = (struct lvid_iu *)&lvintp->lvid_fst[2];
	if ((lvintp->lvid_fst[0] != part_len - n_blks ||
	    lvintp->lvid_int_type != LVI_CLOSE ||
	    lviup->lvidiu_nfiles != n_files ||
	    lviup->lvidiu_ndirs != n_dirs ||
	    lvintp->lvid_uniqid < maxuniqid) &&
	    dofix(&idesc, gettext("LOGICAL VOLUME INTEGRITY COUNTS WRONG"))) {
		lvintp->lvid_int_type = LVI_CLOSE;
		lvintp->lvid_fst[0] = part_len - n_blks;
		lviup->lvidiu_nfiles = n_files;
		lviup->lvidiu_ndirs = n_dirs;
		lvintp->lvid_uniqid = maxuniqid;
		maketag(&lvintp->lvid_tag, &lvintp->lvid_tag);
		bwrite(fswritefd, (char *)lvintp, fsbtodb(lvintblock),
			lvintlen);
	}
}
