/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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

#define	DKTYPENAMES
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ustat.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/dkio.h>
#include <sys/filio.h>
#include <sys/isa_defs.h>	/* for ENDIAN defines */
#include <sys/int_const.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <string.h>
#include <sys/vfstab.h>
#include <sys/fs/udf_volume.h>
#include <sys/vtoc.h>
#include <locale.h>

#include "fsck.h"

extern void	errexit(char *, ...);
extern int32_t	mounted(char *);
extern void	pwarn(char *, ...);
extern void	pfatal(char *, ...);
extern void	printclean();
extern void	bufinit();
extern void	ckfini();
extern int32_t	bread(int32_t, char *, daddr_t, long);
extern int32_t	reply(char *);

static int32_t	readvolseq(int32_t);
static uint32_t	get_last_block();
extern int32_t	verifytag(struct tag *, uint32_t, struct tag *, int);
extern char	*tagerrs[];

#define	POWEROF2(num)	(((num) & ((num) - 1)) == 0)

extern int	mflag;
extern char 	hotroot;

char avdbuf[MAXBSIZE];		/* buffer for anchor volume descriptor */
char *main_vdbuf;		/* buffer for entire main volume sequence */
char *res_vdbuf;		/* buffer for reserved volume sequence */
int serialnum = -1;		/* set from primary volume descriptor */

char *
setup(char *dev)
{
	dev_t rootdev;
	struct stat statb;
	static char devstr[MAXPATHLEN];
	char *raw, *rawname(), *unrawname();
	struct ustat ustatb;

	havesb = 0;
	if (stat("/", &statb) < 0)
		errexit(gettext("Can't stat root\n"));
	rootdev = statb.st_dev;

	devname = devstr;
	(void) strncpy(devstr, dev, sizeof (devstr));
restat:
	if (stat(devstr, &statb) < 0) {
		(void) printf(gettext("Can't stat %s\n"), devstr);
		exitstat = 34;
		return (0);
	}
	/*
	 * A mount point is specified. But the mount point doesn't
	 * match entries in the /etc/vfstab.
	 * Search mnttab, because if the fs is error locked, it is
	 * allowed to be fsck'd while mounted.
	 */
	if ((statb.st_mode & S_IFMT) == S_IFDIR) {
		(void) printf(gettext("%s is not a block or "
			"character device\n"), dev);
		return (0);
	}

	if ((statb.st_mode & S_IFMT) == S_IFBLK) {
		if (rootdev == statb.st_rdev)
			hotroot++;
		else if (ustat(statb.st_rdev, &ustatb) == 0) {
			(void) printf(gettext("%s is a mounted file system, "
				"ignored\n"), dev);
			exitstat = 33;
			return (0);
		}
	}
	if ((statb.st_mode & S_IFMT) == S_IFDIR) {
		FILE *vfstab;
		struct vfstab vfsbuf;
		/*
		 * Check vfstab for a mount point with this name
		 */
		if ((vfstab = fopen(VFSTAB, "r")) == NULL) {
			errexit(gettext("Can't open checklist file: %s\n"),
				VFSTAB);
		}
		while (getvfsent(vfstab, &vfsbuf) == NULL) {
			if (strcmp(devstr, vfsbuf.vfs_mountp) == 0) {
				if (strcmp(vfsbuf.vfs_fstype,
				    MNTTYPE_UDFS) != 0) {
					/*
					 * found the entry but it is not a
					 * udfs filesystem, don't check it
					 */
					(void) fclose(vfstab);
					return (0);
				}
				(void) strcpy(devstr, vfsbuf.vfs_special);
				if (rflag) {
					raw = rawname(
					    unrawname(vfsbuf.vfs_special));
					(void) strcpy(devstr, raw);
				}
				goto restat;
			}
		}
		(void) fclose(vfstab);

	} else if (((statb.st_mode & S_IFMT) != S_IFBLK) &&
	    ((statb.st_mode & S_IFMT) != S_IFCHR)) {
		if (preen)
			pwarn(gettext("file is not a block or "
				"character device.\n"));
		else if (reply(gettext("file is not a block or "
				"character device; OK"))
		    == 0)
			return (0);
		/*
		 * To fsck regular files (fs images)
		 * we need to clear the rflag since
		 * regular files don't have raw names.  --CW
		 */
		rflag = 0;
	}

	if (mounted(devstr)) {
		if (rflag)
			mountedfs++;
		else {
			(void) printf(gettext("%s is mounted, fsck on BLOCK "
				"device ignored\n"), devstr);
			exit(33);
		}
		sync();	/* call sync, only when devstr's mounted */
	}
	if (rflag) {
		char blockname[MAXPATHLEN];
		/*
		 * For root device check, must check
		 * block devices.
		 */
		(void) strcpy(blockname, devstr);
		if (stat(unrawname(blockname), &statb) < 0) {
			(void) printf(gettext("Can't stat %s\n"), blockname);
			exitstat = 34;
			return (0);
		}
	}
	if (rootdev == statb.st_rdev)
		hotroot++;
	if ((fsreadfd = open(devstr, O_RDONLY)) < 0) {
		(void) printf(gettext("Can't open %s\n"), devstr);
		exitstat = 34;
		return (0);
	}
	if (preen == 0 || debug != 0)
		(void) printf("** %s", devstr);

	if (nflag || (fswritefd = open(devstr, O_WRONLY)) < 0) {
		fswritefd = -1;
		if (preen && !debug)
			pfatal(gettext("(NO WRITE ACCESS)\n"));
		(void) printf(gettext(" (NO WRITE)"));
	}
	if (preen == 0)
		(void) printf("\n");
	if (debug && (hotroot || mountedfs)) {
		(void) printf("** %s", devstr);
		if (hotroot)
			(void) printf(" is root fs%s",
				mountedfs? " and": "");
		if (mountedfs)
			(void) printf(" is mounted");

		(void) printf(".\n");
	}
	fsmodified = 0;
	if (readvolseq(1) == 0)
		return (0);
	if (fflag == 0 && preen &&
		lvintp->lvid_int_type == LVI_CLOSE) {
		iscorrupt = 0;
		printclean();
		return (0);
	}
	listmax = FEGROW;
	inphash = (struct fileinfo **)calloc(FEGROW,
			sizeof (struct fileinfo *));
	inphead = (struct fileinfo *)calloc(FEGROW + 1,
			sizeof (struct fileinfo));
	if (inphead == NULL || inphash == NULL) {
		(void) printf(gettext("cannot alloc %ld bytes for inphead\n"),
			listmax * sizeof (struct fileinfo));
		goto badsb;
	}
	inpnext = inphead;
	inplast = &inphead[listmax];

	bufinit();
	return (devstr);

badsb:
	ckfini();
	exitstat = 39;
	return (0);
}

static int
check_pri_vol_desc(struct tag *tp)
{
	pvolp = (struct pri_vol_desc *)tp;
	return (0);
}

static int
check_avdp(struct tag *tp)
{
	avdp = (struct anch_vol_desc_ptr *)tp;
	return (0);
}

static int
check_vdp(struct tag *tp)
{
	volp = (struct vdp_desc *)tp;
	return (0);
}

static int
check_iuvd(struct tag *tp)
{
	iudp = (struct iuvd_desc *)tp;
	return (0);
}

static int
check_part_desc(struct tag *tp)
{
	partp = (struct part_desc *)tp;
	/* LINTED */
	pheadp = (struct phdr_desc *)&partp->pd_pc_use;
	part_start = partp->pd_part_start;
	part_len = partp->pd_part_length;
	if (debug)
		(void) printf("partition start %x len %x\n", part_start,
			part_len);
	return (0);
}

static int
check_log_desc(struct tag *tp)
{
	logvp = (struct log_vol_desc *)tp;
	return (0);
}

static int
check_unall_desc(struct tag *tp)
{
	unallp = (struct unall_desc *)tp;
	return (0);
}

/* ARGSUSED */
static int
check_term_desc(struct tag *tp)
{
	return (0);
}

static int
check_lvint(struct tag *tp)
{
	/* LINTED */
	lvintp = (struct log_vol_int_desc *)tp;
	return (0);
}

void
dump16(char *cp, char *nl)
{
	int i;
	long *ptr;


	for (i = 0; i < 16; i += 4) {
		/* LINTED */
		ptr = (long *)(cp + i);
		(void) printf("%08lx ", *ptr);
	}
	(void) printf(nl);
}

/*
 * Read in the super block and its summary info.
 */
/* ARGSUSED */
static int
readvolseq(int32_t listerr)
{
	struct tag *tp;
	long_ad_t *lap;
	struct anch_vol_desc_ptr *avp;
	uint8_t *cp, *end;
	daddr_t nextblock;
	int err;
	long	freelen;
	daddr_t avdp;

	disk_size = get_last_block();
	if (debug)
		(void) printf("Disk partition size: %x\n", disk_size);

	/* LINTED */
	avp = (struct anch_vol_desc_ptr *)avdbuf;
	tp = &avp->avd_tag;
	for (fsbsize = 512; fsbsize <= MAXBSIZE; fsbsize <<= 1) {
		avdp = FIRSTAVDP * fsbsize / DEV_BSIZE;
		if (bread(fsreadfd, avdbuf, avdp, fsbsize) != 0)
			return (0);
		err = verifytag(tp, FIRSTAVDP, tp, UD_ANCH_VOL_DESC);
		if (debug)
			(void) printf("bsize %ld tp->tag %d, %s\n", fsbsize,
				tp->tag_id, tagerrs[err]);
		if (err == 0)
			break;
	}
	if (fsbsize > MAXBSIZE)
		errexit(gettext("Can't find anchor volume descriptor\n"));
	secsize = fsbsize;
	if (debug)
		(void) printf("fsbsize = %ld\n", fsbsize);
	main_vdbuf = malloc(avp->avd_main_vdse.ext_len);
	res_vdbuf = malloc(avp->avd_res_vdse.ext_len);
	if (main_vdbuf == NULL || res_vdbuf == NULL)
		errexit("cannot allocate space for volume sequences\n");
	if (debug)
		(void) printf("reading volume sequences "
			"(%d bytes at %x and %x)\n",
			avp->avd_main_vdse.ext_len, avp->avd_main_vdse.ext_loc,
			avp->avd_res_vdse.ext_loc);
	if (bread(fsreadfd, main_vdbuf, fsbtodb(avp->avd_main_vdse.ext_loc),
		avp->avd_main_vdse.ext_len) != 0)
		return (0);
	if (bread(fsreadfd, res_vdbuf, fsbtodb(avp->avd_res_vdse.ext_loc),
		avp->avd_res_vdse.ext_len) != 0)
		return (0);
	end = (uint8_t *)main_vdbuf + avp->avd_main_vdse.ext_len;
	nextblock = avp->avd_main_vdse.ext_loc;
	for (cp = (uint8_t *)main_vdbuf; cp < end; cp += fsbsize, nextblock++) {
		/* LINTED */
		tp = (struct tag *)cp;
		err = verifytag(tp, nextblock, tp, 0);
		if (debug) {
			dump16((char *)cp, "");
			(void) printf("blk %lx err %s tag %d\n", nextblock,
				tagerrs[err], tp->tag_id);
		}
		if (err == 0) {
			if (serialnum >= 0 && tp->tag_sno != serialnum) {
				(void) printf(gettext("serial number mismatch "
					"tag type %d, block %lx\n"), tp->tag_id,
					nextblock);
				continue;
			}
			switch (tp->tag_id) {
			case UD_PRI_VOL_DESC:
				serialnum = tp->tag_sno;
				if (debug) {
					(void) printf("serial number = %d\n",
						serialnum);
				}
				err = check_pri_vol_desc(tp);
				break;
			case UD_ANCH_VOL_DESC:
				err = check_avdp(tp);
				break;
			case UD_VOL_DESC_PTR:
				err = check_vdp(tp);
				break;
			case UD_IMPL_USE_DESC:
				err = check_iuvd(tp);
				break;
			case UD_PART_DESC:
				err = check_part_desc(tp);
				break;
			case UD_LOG_VOL_DESC:
				err = check_log_desc(tp);
				break;
			case UD_UNALL_SPA_DESC:
				err = check_unall_desc(tp);
				break;
			case UD_TERM_DESC:
				err = check_term_desc(tp);
				goto done;
				break;
			case UD_LOG_VOL_INT:
				err = check_lvint(tp);
				break;
			default:
				(void) printf(gettext("Invalid volume "
					"sequence tag %d\n"), tp->tag_id);
			}
		} else {
			(void) printf(gettext("Volume sequence tag error %s\n"),
				tagerrs[err]);
		}
	}
done:
	if (!partp || !logvp) {
		(void) printf(gettext("Missing partition header or"
			" logical volume descriptor\n"));
		return (0);
	}

	/* Get the logical volume integrity descriptor */
	lvintblock = logvp->lvd_int_seq_ext.ext_loc;
	lvintlen = logvp->lvd_int_seq_ext.ext_len;
	lvintp = (struct log_vol_int_desc *)malloc(lvintlen);
	if (debug)
		(void) printf("Logvolint at %x for %d bytes\n", lvintblock,
			lvintlen);
	if (lvintp == NULL) {
		(void) printf(gettext("Can't allocate space for logical"
			" volume integrity sequence\n"));
		return (0);
	}
	if (bread(fsreadfd, (char *)lvintp,
			fsbtodb(lvintblock), lvintlen) != 0) {
		return (0);
	}
	err = verifytag(&lvintp->lvid_tag, lvintblock, &lvintp->lvid_tag,
		UD_LOG_VOL_INT);
	if (debug) {
		dump16((char *)lvintp, "\n");
	}
	if (err) {
		(void) printf(gettext("Log_vol_int tag error: %s, tag = %d\n"),
			tagerrs[err], lvintp->lvid_tag.tag_id);
		return (0);
	}

	/* Get pointer to implementation use area */
	lviup = (struct lvid_iu *)&lvintp->lvid_fst[lvintp->lvid_npart*2];
	if (debug) {
		(void) printf("free space %d total %d ", lvintp->lvid_fst[0],
			lvintp->lvid_fst[1]);
	(void) printf(gettext("nfiles %d ndirs %d\n"), lviup->lvidiu_nfiles,
			lviup->lvidiu_ndirs);
	}

	/* Set up free block map and read in the existing free space map */
	freelen = pheadp->phdr_usb.sad_ext_len;
	if (freelen == 0) {
		(void) printf(gettext("No partition free map\n"));
	}
	part_bmp_bytes = (part_len + NBBY - 1) / NBBY;
	busymap = calloc((unsigned)part_bmp_bytes, sizeof (char));
	if (busymap == NULL) {
		(void) printf(gettext("Can't allocate free block bitmap\n"));
		return (0);
	}
	if (freelen) {
		part_bmp_sectors =
			(part_bmp_bytes + SPACEMAP_OFF + secsize - 1) /
			secsize;
		part_bmp_loc = pheadp->phdr_usb.sad_ext_loc + part_start;

		/* Mark the partition map blocks busy */
		markbusy(pheadp->phdr_usb.sad_ext_loc,
			part_bmp_sectors * secsize);

		spacep = (struct space_bmap_desc *)
			malloc(secsize*part_bmp_sectors);
		if (spacep == NULL) {
			(void) printf(gettext("Can't allocate partition "
				"map\n"));
			return (0);
		}
		if (bread(fsreadfd, (char *)spacep, fsbtodb(part_bmp_loc),
			part_bmp_sectors * secsize) != 0)
			return (0);
		cp = (uint8_t *)spacep;
		err = verifytag(&spacep->sbd_tag, pheadp->phdr_usb.sad_ext_loc,
			&spacep->sbd_tag, UD_SPA_BMAP_DESC);
		if (debug) {
			dump16((char *)cp, "");
			(void) printf("blk %x err %s tag %d\n", part_bmp_loc,
				tagerrs[err], spacep->sbd_tag.tag_id);
		}
		freemap = (char *)cp + SPACEMAP_OFF;
		if (debug)
			(void) printf("err %s tag %x space bitmap at %x"
				" length %d nbits %d nbytes %d\n",
				tagerrs[err], spacep->sbd_tag.tag_id,
				part_bmp_loc, part_bmp_sectors,
				spacep->sbd_nbits, spacep->sbd_nbytes);
		if (err) {
			(void) printf(gettext("Space bitmap tag error, %s, "
				"tag = %d\n"),
				tagerrs[err], spacep->sbd_tag.tag_id);
			return (0);
		}
	}

	/* Get the fileset descriptor */
	lap = (long_ad_t *)&logvp->lvd_lvcu;
	filesetblock = lap->lad_ext_loc;
	filesetlen = lap->lad_ext_len;
	markbusy(filesetblock, filesetlen);
	if (debug)
		(void) printf("Fileset descriptor at %x for %d bytes\n",
			filesetblock, filesetlen);
	if (!filesetlen) {
		(void) printf(gettext("No file set descriptor found\n"));
		return (0);
	}
	fileset = (struct file_set_desc *)malloc(filesetlen);
	if (fileset == NULL) {
		(void) printf(gettext("Unable to allocate fileset\n"));
		return (0);
	}
	if (bread(fsreadfd, (char *)fileset, fsbtodb(filesetblock + part_start),
		filesetlen) != 0) {
		return (0);
	}
	err = verifytag(&fileset->fsd_tag, filesetblock, &fileset->fsd_tag,
		UD_FILE_SET_DESC);
	if (err) {
		(void) printf(gettext("Fileset tag error, tag = %d, %s\n"),
			fileset->fsd_tag.tag_id, tagerrs[err]);
		return (0);
	}

	/* Get the address of the root file entry */
	lap = (long_ad_t *)&fileset->fsd_root_icb;
	rootblock = lap->lad_ext_loc;
	rootlen = lap->lad_ext_len;
	if (debug)
		(void) printf("Root at %x for %d bytes\n", rootblock, rootlen);

	havesb = 1;
	return (1);
}

uint32_t
get_last_block()
{
	struct vtoc vtoc;
	struct dk_cinfo dki_info;

	if (ioctl(fsreadfd, DKIOCGVTOC, (intptr_t)&vtoc) != 0) {
		(void) fprintf(stderr, gettext("Unable to read VTOC\n"));
		return (0);
	}

	if (vtoc.v_sanity != VTOC_SANE) {
		(void) fprintf(stderr, gettext("Vtoc.v_sanity != VTOC_SANE\n"));
		return (0);
	}

	if (ioctl(fsreadfd, DKIOCINFO, (intptr_t)&dki_info) != 0) {
		(void) fprintf(stderr,
		    gettext("Could not get the slice information\n"));
		return (0);
	}

	if (dki_info.dki_partition > V_NUMPAR) {
		(void) fprintf(stderr,
		    gettext("dki_info.dki_partition > V_NUMPAR\n"));
		return (0);
	}

	return ((uint32_t)vtoc.v_part[dki_info.dki_partition].p_size);
}
