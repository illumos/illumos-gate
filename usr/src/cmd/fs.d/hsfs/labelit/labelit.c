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

/*
 * labelit [option=value ...] cdimage
 * where options are:
 *      sysid		system identifier               (a characters, 32 max)
 *      volid:          volume identifier               (d-characters, 32 max)
 *      volsetid:       volume set identifier           (d-characters, 128 max)
 *      pubid:          publisher identifier            (d-characters, 128 max)
 *      prepid:         data preparer identifier        (d-charcter, 128 max)
 *      applid:         application identifier          (d-charcter, 128 max)
 *      copyfile:       copyright file identifier       (d-characters, 128 max)
 *      absfile:        abstract file identifier        (d-characters, 37 max)
 *      bibfile:        bibliographic file identifier   (d-charcters, 37 max)
 */

#include <fcntl.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/file.h>
#include <dirent.h>

#include <sys/fs/hsfs_isospec.h>
#include <sys/fs/hsfs_spec.h>

#define	PUTSECTOR(buf, secno, nosec) (putdisk(buf, (secno)*ISO_SECTOR_SIZE, \
	(nosec)*ISO_SECTOR_SIZE))
#define	GETSECTOR(buf, secno, nosec) (getdisk(buf, (secno)*ISO_SECTOR_SIZE, \
	(nosec)*ISO_SECTOR_SIZE))

char *string;
#define	MAXERRSTRNG	80
char	errstrng[MAXERRSTRNG];
char	callname[160];

int  cdfd;
int cd_type;
char hs_buf[ISO_SECTOR_SIZE];
int  hs_pvd_sec_no;
char iso_buf[ISO_SECTOR_SIZE];
int  iso_pvd_sec_no;
char unix_buf[ISO_SECTOR_SIZE];
int  unix_pvd_sec_no;
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

static int match(char *s);
static void usage(void);
static void putdisk(char *buf, int daddr, int size);
static void getdisk(char *buf, int daddr, int size);
static void prntstring(char *heading, char *s, int maxlen);
static void copystring(char *from, char *to, int size);
static void prntlabel(void);
static void updatelabel(void);
static void ckvoldesc(void);

int
main(int argc, char **argv)
{
	int c;
	int openopt;

	strcpy(callname, argv[0]);
	for (c = 1; c < argc; c++) {
		string = argv[c];
		if (match("sysid=")) {
			sysid = string;
			continue;
		}
		if (match("volid=")) {
			volid = string;
			continue;
		}
		if (match("volsetid=")) {
			volsetid = string;
			continue;
		}
		if (match("pubid=")) {
			pubid = string;
			continue;
		}
		if (match("prepid=")) {
			prepid = string;
			continue;
		}
		if (match("applid=")) {
			applid = string;
			continue;
		}
		if (match("copyfile=")) {
			copyfile = string;
			continue;
		}
		if (match("absfile=")) {
			absfile = string;
			continue;
		}
		if (match("bibfile=")) {
			bibfile = string;
			continue;
		}
		break;
	}
	/* the last argument must be the cdrom iamge file */
	if (argc != c+1) {
		if (argc > 1)
			fprintf(stderr, "%s: Illegal option %s in input\n",
			    callname, string);
		usage();
	}

	/* open image file in read write only if necessary */
	if (argc == 2) openopt = O_RDONLY;
	else openopt = O_RDWR;

	if ((cdfd = open(argv[c], openopt)) < 0) {
		if (strchr(argv[c], '=') ||
		    strchr(argv[c], '-')) {
			usage();
		}
		sprintf(errstrng, "%s: main: open(): ", callname);
		perror(errstrng);
		exit(32);
	}

	/* check volume descriptor */
	(void) ckvoldesc();

	if (cd_type < 0) {
		fprintf(stderr, "%s: unknown cdrom format label\n", callname);
		exit(32);
	}

	/* update label, if needed */
	if (argc != 2) updatelabel();

	/* print the (updated) image label */
	prntlabel();

	close(cdfd);
	return (0);
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-F ufs] [option=value ...] cdimage\n",
	    callname);
	exit(32);
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
	GETSECTOR(volp, secno++, 1);
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
		GETSECTOR(volp, secno++, 1);
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
	GETSECTOR(volp, secno++, 1);
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
		GETSECTOR(volp, secno++, 1);
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
findunixvol(volp)
char *volp;
{
int secno;
int i;

	secno = ISO_VOLDESC_SEC;
	GETSECTOR(volp, secno++, 1);
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
		GETSECTOR(volp, secno++, 1);
	}
cantfind:
	return (0);
}

static void
ckvoldesc(void)
{
	if (findhsvol(hs_buf))
		cd_type = 0;
	else if (findisovol(iso_buf)) {
		if (findunixvol(unix_buf))
			cd_type = 2;
		else cd_type = 1;
	} else {
		cd_type = -1;
	}
}

static void
updatelabel(void)
{
	switch (cd_type) {
	case 0:
		copystring(sysid, (char *)HSV_sys_id(hs_buf), 32);
		copystring(volid, (char *)HSV_vol_id(hs_buf), 32);
		copystring(volsetid, (char *)HSV_vol_set_id(hs_buf), 128);
		copystring(pubid, (char *)HSV_pub_id(hs_buf), 128);
		copystring(prepid, (char *)HSV_prep_id(hs_buf), 128);
		copystring(applid, (char *)HSV_appl_id(hs_buf), 128);
		copystring(copyfile, (char *)HSV_copyr_id(hs_buf), 37);
		copystring(absfile, (char *)HSV_abstr_id(hs_buf), 37);
		PUTSECTOR(hs_buf, hs_pvd_sec_no, 1);
		break;
	case 2:
		copystring(sysid, (char *)ISO_sys_id(unix_buf), 32);
		copystring(volid, (char *)ISO_vol_id(unix_buf), 32);
		copystring(volsetid, (char *)ISO_vol_set_id(unix_buf), 128);
		copystring(pubid, (char *)ISO_pub_id(unix_buf), 128);
		copystring(prepid, (char *)ISO_prep_id(unix_buf), 128);
		copystring(applid, (char *)ISO_appl_id(unix_buf), 128);
		copystring(copyfile, (char *)ISO_copyr_id(unix_buf), 37);
		copystring(absfile, (char *)ISO_abstr_id(unix_buf), 37);
		copystring(bibfile, (char *)ISO_bibli_id(unix_buf), 37);
		PUTSECTOR(unix_buf, unix_pvd_sec_no, 1);
		/*
		 * after update unix volume descriptor,
		 * fall thru to update the iso primary vol descriptor
		 */
		/* FALLTHROUGH */
	case 1:
		copystring(sysid, (char *)ISO_sys_id(iso_buf), 32);
		copystring(volid, (char *)ISO_vol_id(iso_buf), 32);
		copystring(volsetid, (char *)ISO_vol_set_id(iso_buf), 128);
		copystring(pubid, (char *)ISO_pub_id(iso_buf), 128);
		copystring(prepid, (char *)ISO_prep_id(iso_buf), 128);
		copystring(applid, (char *)ISO_appl_id(iso_buf), 128);
		copystring(copyfile, (char *)ISO_copyr_id(iso_buf), 37);
		copystring(absfile, (char *)ISO_abstr_id(iso_buf), 37);
		copystring(bibfile, (char *)ISO_bibli_id(iso_buf), 37);
		PUTSECTOR(iso_buf, iso_pvd_sec_no, 1);
		break;
	}
}

static void
prntlabel(void)
{
	int i;
	switch (cd_type) {
	case 0:
		printf("CD-ROM is in High Sierra format\n");
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
		printf("CD-ROM is in ISO 9660 format\n");
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
		printf("CD-ROM is in ISO 9660 format with UNIX extension\n");
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
	printf("Volume set size is %d\n", volsetsize);
	/* print volume set sequnce number */
	printf("Volume set sequence number is %d\n", volsetseq);
	/* print logical block size */
	printf("Logical block size is %d\n", blksize);
	/* print volume size */
	printf("Volume size is %d\n", volsize);
}

static void
copystring(char *from, char *to, int size)
{
	int i;

	if (from == NULL)
		return;
	for (i = 0; i < size; i++) {
		if (*from == '\0')
			break;
		else *to++ = *from++;
	}
	for (; i < size; i++) *to++ = ' ';
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
	printf("%s: ", heading);

	/* strip off trailing zeros */
	for (i = maxlen-1; i >= 0; i--)
		if (s[i] != ' ')
			break;

	maxlen = i+1;
	for (i = 0; i < maxlen; i++)
		printf("%c", s[i]);
	printf("\n");
}

static int
match(char *s)
{
	char *cs;

	cs = string;
	while (*cs++ == *s)
		if (*s++ == '\0')
			goto true;
	if (*s != '\0')
		return (0);

true:
	cs--;
	string = cs;
	return (1);
}

/* readdisk - read from cdrom image file */
static void
getdisk(char *buf, int daddr, int size)
{

	if (lseek(cdfd, daddr, L_SET) == -1) {
		sprintf(errstrng, "%s: getdisk: lseek()", callname);
		perror(errstrng);
		exit(32);
	}
	if (read(cdfd, buf, size) != size) {
		sprintf(errstrng, "%s: getdisk: read()", callname);
		perror(errstrng);
		exit(32);
	}
}

/* putdisk - write to cdrom image file */
static void
putdisk(char *buf, int daddr, int size)
{

	if (lseek(cdfd, daddr, L_SET) == -1) {
		sprintf(errstrng, "%s: putdisk: lseek()", callname);
		perror(errstrng);
		exit(32);
	}
	if (write(cdfd, buf, size) != size) {
		sprintf(errstrng, "%s: putdisk: write()", callname);
		perror(errstrng);
		exit(32);
	}
}
