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
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/cdio.h>
#include <sys/dkio.h>
#include "hsfs_spec.h"
#include "iso_spec.h"
#include "iso_impl.h"

#define	GETCDSECTOR(buf, secno, nosec) (getdisk(buf, \
	((secno)+cdroff)*ISO_SECTOR_SIZE, \
	(nosec)*ISO_SECTOR_SIZE))
char hs_buf[ISO_SECTOR_SIZE];
int  hs_pvd_sec_no;
char iso_buf[ISO_SECTOR_SIZE];
int  iso_pvd_sec_no;
char unix_buf[ISO_SECTOR_SIZE];
int  unix_pvd_sec_no;

int vflag;
int  cdfd;

int cdroff = 0;

static int rdev_is_a_cd(int rdevfd);
static void getdisk(char *buf, int daddr, int size);
static void prntstring(char *heading, char *s, int maxlen);
static void prntlabel(int cd_type);
static void dumpfs(char *special);
static void usage(void);

int
main(int argc, char **argv)
{
	int c;
	char *special;
	int errflag = 0;

	while ((c = getopt(argc, argv, "v")) != EOF) {
		switch (c) {
			case 'v':
				vflag++;
				break;
			default:
				errflag++;
				break;
		}
	}

	if (errflag || (argc <= optind)) {
		usage();
		exit(1);
	}

	special = argv[optind];

	dumpfs(special);

	return (0);
}

static void
usage(void)
{
	fprintf(stderr, "Usage: fstyp -v special\n");
}

/*
 * findhsvol: check if the disk is in high sierra format
 *            return(1) if found, (0) otherwise
 *	      if found, volp will point to the descriptor
 *
 */
int
findhsvol(volp)
char *volp;
{
int secno;
int i;

	secno = HS_VOLDESC_SEC;
	GETCDSECTOR(volp, secno++, 1);
	while (HSV_DESC_TYPE(volp) != VD_EOV) {
		for (i = 0; i < HSV_ID_STRLEN; i++)
			if (HSV_STD_ID(volp)[i] != HSV_ID_STRING[i])
				goto cantfind;
		if (HSV_STD_VER(volp) != HSV_ID_VER)
			goto cantfind;
		switch (HSV_DESC_TYPE(volp)) {
		case VD_SFS:
			hs_pvd_sec_no = secno-1;
			return (1);
		case VD_EOV:
			goto cantfind;
		}
		GETCDSECTOR(volp, secno++, 1);
	}
cantfind:
	return (0);
}

/*
 * findisovol: check if the disk is in ISO 9660 format
 *            return(1) if found, (0) otherwise
 *	      if found, volp will point to the descriptor
 *
 */
int
findisovol(volp)
char *volp;
{
int secno;
int i;

	secno = ISO_VOLDESC_SEC;
	GETCDSECTOR(volp, secno++, 1);
	while (ISO_DESC_TYPE(volp) != ISO_VD_EOV) {
		for (i = 0; i < ISO_ID_STRLEN; i++)
			if (ISO_STD_ID(volp)[i] != ISO_ID_STRING[i])
				goto cantfind;
		if (ISO_STD_VER(volp) != ISO_ID_VER)
			goto cantfind;
		switch (ISO_DESC_TYPE(volp)) {
		case ISO_VD_PVD:
			iso_pvd_sec_no = secno-1;
			return (1);
		case ISO_VD_EOV:
			goto cantfind;
		}
		GETCDSECTOR(volp, secno++, 1);
	}
cantfind:
	return (0);
}

/*
 * findunixvol: check if the disk is in UNIX extension format
 *            return(1) if found, (0) otherwise
 *	      if found, volp will point to the descriptor
 *
 */
int
findunixvol(char *volp)
{
int secno;
int i;

	secno = ISO_VOLDESC_SEC;
	GETCDSECTOR(volp, secno++, 1);
	while (ISO_DESC_TYPE(volp) != ISO_VD_EOV) {
		for (i = 0; i < ISO_ID_STRLEN; i++)
			if (ISO_STD_ID(volp)[i] != ISO_ID_STRING[i])
				goto cantfind;
		if (ISO_STD_VER(volp) != ISO_ID_VER)
			goto cantfind;
		switch (ISO_DESC_TYPE(volp)) {
		case ISO_VD_UNIX:
			unix_pvd_sec_no = secno-1;
			return (1);
		case ISO_VD_EOV:
			goto cantfind;
		}
		GETCDSECTOR(volp, secno++, 1);
	}
cantfind:
	return (0);
}

int
ckvoldesc(void)
{
	int cd_type;

	if (findhsvol(hs_buf))
		cd_type = 0;
	else if (findisovol(iso_buf)) {
		if (findunixvol(unix_buf))
			cd_type = 2;
		else cd_type = 1;
	} else {
		cd_type = -1;
	}

	return (cd_type);

}

static void
dumpfs(char *special)
{
	int err;
	int cd_type;

	if ((cdfd = open(special, O_RDONLY)) < 0) {
		fprintf(stderr, "hsfs fstyp: cannot open <%s>\n", special);
		exit(1);
	}

#ifdef CDROMREADOFFSET
	if (rdev_is_a_cd(cdfd)) {
		err = ioctl(cdfd, CDROMREADOFFSET, &cdroff);
		if (err == -1)
			/*
			 *  This device doesn't support this ioctl.
			 *  That's OK.
			 */
			cdroff = 0;
	}
#endif
	/* check volume descriptor */
	cd_type = ckvoldesc();

	if (cd_type < 0)
		exit(1);
	else
		fprintf(stdout, "hsfs\n");

	if (vflag)
		prntlabel(cd_type);

	exit(0);
}

static void
prntlabel(int cd_type)
{
	char *vdp;
	char *sysid;
	char *volid;
	char *volsetid;
	char *pubid;
	char *prepid;
	char *applid;
	char *copyfile;
	char *absfile;
	char *bibfile;
	int volsetsize;
	int volsetseq;
	int blksize;
	int volsize;
	int i;

	switch (cd_type) {
	case 0:
		fprintf(stdout, "CD-ROM is in High Sierra format\n");
		sysid = (char *)HSV_sys_id(hs_buf);
		volid = (char *)HSV_vol_id(hs_buf);
		volsetid = (char *)HSV_vol_set_id(hs_buf);
		pubid = (char *)HSV_pub_id(hs_buf);
		prepid = (char *)HSV_prep_id(hs_buf);
		applid = (char *)HSV_appl_id(hs_buf);
		copyfile = (char *)HSV_copyr_id(hs_buf);
		absfile = (char *)HSV_abstr_id(hs_buf);
		bibfile = NULL;
		volsetsize = HSV_SET_SIZE(hs_buf);
		volsetseq = HSV_SET_SEQ(hs_buf);
		blksize = HSV_BLK_SIZE(hs_buf);
		volsize = HSV_VOL_SIZE(hs_buf);
		break;
	case 1:
		fprintf(stdout, "CD-ROM is in ISO 9660 format\n");
		sysid = (char *)ISO_sys_id(iso_buf);
		volid = (char *)ISO_vol_id(iso_buf);
		volsetid = (char *)ISO_vol_set_id(iso_buf);
		pubid = (char *)ISO_pub_id(iso_buf);
		prepid = (char *)ISO_prep_id(iso_buf);
		applid = (char *)ISO_appl_id(iso_buf);
		copyfile = (char *)ISO_copyr_id(iso_buf);
		absfile = (char *)ISO_abstr_id(iso_buf);
		bibfile = (char *)ISO_bibli_id(iso_buf);
		volsetsize = ISO_SET_SIZE(iso_buf);
		volsetseq = ISO_SET_SEQ(iso_buf);
		blksize = ISO_BLK_SIZE(iso_buf);
		volsize = ISO_VOL_SIZE(iso_buf);
		break;
	case 2:
		fprintf(stdout, "CD-ROM is in ISO 9660 format with"
		    " UNIX extension\n");
		sysid = (char *)ISO_sys_id(unix_buf);
		volid = (char *)ISO_vol_id(unix_buf);
		volsetid = (char *)ISO_vol_set_id(unix_buf);
		pubid = (char *)ISO_pub_id(unix_buf);
		prepid = (char *)ISO_prep_id(unix_buf);
		applid = (char *)ISO_appl_id(unix_buf);
		copyfile = (char *)ISO_copyr_id(unix_buf);
		absfile = (char *)ISO_abstr_id(unix_buf);
		bibfile = (char *)ISO_bibli_id(unix_buf);
		volsetsize = ISO_SET_SIZE(unix_buf);
		volsetseq = ISO_SET_SEQ(unix_buf);
		blksize = ISO_BLK_SIZE(unix_buf);
		volsize = ISO_VOL_SIZE(unix_buf);
		break;
	default:
		return;
	}
	/* system id */
	prntstring("System id", sysid, 32);
	/* read volume id */
	prntstring("Volume id", volid, 32);
	/* read volume set id */
	prntstring("Volume set id", volsetid, 128);
	/* publisher id */
	prntstring("Publisher id", pubid, 128);
	/* data preparer id */
	prntstring("Data preparer id", prepid, 128);
	/* application id */
	prntstring("Application id", applid, 128);
	/* copyright file identifier */
	prntstring("Copyright File id", copyfile, 37);
	/* Abstract file identifier */
	prntstring("Abstract File id", absfile, 37);
	/* Bibliographic file identifier */
	prntstring("Bibliographic File id", bibfile, 37);
	/* print volume set size */
	fprintf(stdout, "Volume set size is %d\n", volsetsize);
	/* print volume set sequnce number */
	fprintf(stdout, "Volume set sequence number is %d\n", volsetseq);
	/* print logical block size */
	fprintf(stdout, "Logical block size is %d\n", blksize);
	/* print volume size */
	fprintf(stdout, "Volume size is %d\n", volsize);
}

static void
prntstring(char *heading, char *s, int maxlen)
{
	int i;
	if (maxlen < 1)
		return;
	if (heading == NULL || s == NULL)
		return;
	/* print heading */
	fprintf(stdout, "%s: ", heading);

	/* strip off trailing zeros */
	for (i = maxlen-1; i >= 0; i--)
		if (s[i] != ' ') break;

	maxlen = i+1;
	for (i = 0; i < maxlen; i++)
		fprintf(stdout, "%c", s[i]);
	fprintf(stdout, "\n");
}

/* readdisk - read from cdrom image file */
static void
getdisk(char *buf, int daddr, int size)
{
	if (lseek(cdfd, daddr, L_SET) == -1) {
		perror("getdisk/lseek");
		exit(1);
	}
	if (read(cdfd, buf, size) != size) {
		perror("getdisk/read");
		exit(1);
	}
}

/*
 * rdev_is_a_cd  - return TRUE if the raw device identified by
 *		      a file descriptor is a CDROM device.
 *
 *		      return FALSE if the device can't be accessed
 *		      or is not a CDROM.
 */
static int
rdev_is_a_cd(int rdevfd)
{
	struct dk_cinfo dkc;

	if (ioctl(rdevfd, DKIOCINFO, &dkc) < 0)
		return (0);
	if (dkc.dki_ctype == DKC_CDROM)
		return (1);
	else
		return (0);
}
