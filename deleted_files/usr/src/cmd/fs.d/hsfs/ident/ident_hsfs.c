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
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<fcntl.h>
#include	<rpc/types.h>
#include	<sys/types.h>
#include	<sys/fs/hsfs_isospec.h>
#include	<sys/fs/hsfs_spec.h>
#include	<sys/cdio.h>
#include	<sys/dkio.h>
#include	<unistd.h>
#include	<rmmount.h>
#ifdef	DEBUG
#include	<errno.h>
#endif


#define	CDI_ID_STRING	"CD-I"
#define	CDI_ID_STRLEN	4

static int rdev_is_a_cd(int rdevfd);

/*
 * We call it an hsfs file system iff:
 *	The string "CD001" is present at the second byte of the PVD.
 *
 * NOTE:
 *	argument "verbose" not currently used (but required
 *	for compatibility, of course)
 */
/*ARGSUSED*/
bool_t
ident_fs(int fd, char *rawpath, int *clean, bool_t verbose)
{
	static bool_t	findcdivol(int, char *, bool_t, int);
	static bool_t	findhsvol(int, char *, bool_t, int);
	static bool_t	findisovol(int, char *, bool_t, int);
	char		volp_buf[ISO_SECTOR_SIZE];
	int		rfd;
	int		off = 0;

	rfd = open(rawpath, O_RDONLY, 0600);
	if (rfd == -1) {
#ifdef DEBUG
		fprintf(stderr,
			"hsfs ident: can't open rawpath %s: errno = %d\n",
			rawpath, errno);
#endif
		return (FALSE);
	}

#ifdef CDROMREADOFFSET
	if (rdev_is_a_cd(rfd))
		if ((ioctl(rfd, CDROMREADOFFSET, &off)) == -1)
			off = 0;
#endif

	close(rfd);

#ifdef	DEBUG
	(void) fprintf(stderr, "DEBUG: hsfs ident_fs(): entering\n");
#endif

	/* hsfs is always clean */
	*clean = TRUE;

	if (findcdivol(fd, volp_buf, verbose, off)) {
		return (TRUE);
	}
	if (findhsvol(fd, volp_buf, verbose, off)) {
		return (TRUE);
	}
	if (findisovol(fd, volp_buf, verbose, off)) {
		return (TRUE);
	}

	/* no match */
	return (FALSE);
}


/*ARGSUSED*/
static bool_t
findcdivol(int fd, char *buf, bool_t verbose, int off)
{
	static bool_t	getsector(int, char *, int);
	int		secno = ISO_VOLDESC_SEC + off;
	int		i;
	bool_t		found = FALSE;
#ifdef	DEBUG
	char		volid[ISO_VOL_ID_STRLEN+1];
#endif


#ifdef	DEBUG
	(void) fprintf(stderr, "DEBUG: hsfs findcdivol(): entering\n");
#endif

	while (getsector(fd, buf, secno++)) {

		/* if this is the end of volume descriptors then bail */
		if (ISO_DESC_TYPE(buf) == ISO_VD_EOV) {
			break;
		}

		/* do we have a "CD-I" string ?? */
		for (i = 0; i < CDI_ID_STRLEN; i++) {
			if (ISO_STD_ID(buf)[i] != CDI_ID_STRING[i]) {
				break;
			}
		}
		if (i < CDI_ID_STRLEN) {
			break;		/* string didn't match */
		}

		if (ISO_STD_VER(buf) != ISO_ID_VER) {
			continue;		/* not a valid sector? */
		}


		/* what type of sector is this */
		if (ISO_DESC_TYPE(buf) == ISO_VD_PVD) {
#ifdef	DEBUG
			memcpy(volid, ISO_vol_id(buf), ISO_VOL_ID_STRLEN);
			volid[ISO_VOL_ID_STRLEN] = '\0';
			(void) fprintf(stderr,
			    "DEBUG: ident_hsfs() CD-I vol id is \"%s\"\n",
			    volid);
#endif
			found = TRUE;
			break;
		}

		/* look at next sector */
	}

#ifdef	DEBUG
	(void) fprintf(stderr, "DEBUG: hsfs findcdivol(): returning %s\n",
	    found ? "TRUE" : "FALSE");
#endif
	return (found);
}


/*ARGSUSED*/
static bool_t
findhsvol(int fd, char *buf, bool_t verbose, int off)
{
	static bool_t	getsector(int, char *, int);
	int		secno = HS_VOLDESC_SEC + off;
	int		i;
	bool_t		found = FALSE;
#ifdef	DEBUG
	char		volid[HSV_VOL_ID_STRLEN+1];
#endif


#ifdef	DEBUG
	(void) fprintf(stderr, "DEBUG: hsfs findhsvol(): entering\n");
#endif

	/*
	 * look through the volume descriptors until we find an HSFS
	 * primary volume descriptor, or until we find the end of the
	 * volume descriptors
	 */
	while (getsector(fd, buf, secno++)) {

		if (HSV_DESC_TYPE(buf) == VD_EOV) {
			/* found the end of the vol descriptors */
			break;			/* not found */
		}

		for (i = 0; i < HSV_ID_STRLEN; i++) {
			if (HSV_STD_ID(buf)[i] != HSV_ID_STRING[i]) {
				break;		/* not a match */
			}
		}
		if (i < HSV_ID_STRLEN) {
			break;			/* not a match */
		}

		if (HSV_STD_VER(buf) != HSV_ID_VER) {
			break;			/* not a match */
		}

		if (HSV_DESC_TYPE(buf) == VD_SFS) {
#ifdef	DEBUG
			memcpy(volid, HSV_vol_id(buf), HSV_VOL_ID_STRLEN);
			volid[HSV_VOL_ID_STRLEN] = '\0';
			(void) fprintf(stderr,
			    "DEBUG: ident_hsfs() HS vol id is \"%s\"\n",
			    volid);
#endif
			found = TRUE;
			break;
		}

		/* go to the next sector */
	}

#ifdef	DEBUG
	(void) fprintf(stderr, "DEBUG: hsfs findhsvol(): returning %s\n",
	    found ? "TRUE" : "FALSE");
#endif
	return (found);
}


/*ARGSUSED*/
static bool_t
findisovol(int fd, char *buf, bool_t verbose, int off)
{
	static bool_t	getsector(int, char *, int);
	int		secno = ISO_VOLDESC_SEC + off;
	int		i;
	bool_t		found = FALSE;
#ifdef	DEBUG
	char		volid[ISO_VOL_ID_STRLEN+1];
#endif


#ifdef	DEBUG
	(void) fprintf(stderr, "DEBUG: hsfs findisovol(): entering\n");
#endif

	/*
	 * look through the volume descriptors until we find an ISO 9660
	 * primary volume descriptor, or until we find the end of the
	 * volume descriptors
	 */
	while (getsector(fd, buf, secno++)) {

		if (ISO_DESC_TYPE(buf) == ISO_VD_EOV) {
			/* found the end of the vol descriptors */
			break;			/* not found */
		}

		for (i = 0; i < ISO_ID_STRLEN; i++) {
			if (ISO_STD_ID(buf)[i] != ISO_ID_STRING[i]) {
				break;		/* not a match */
			}
		}
		if (i < ISO_ID_STRLEN) {
			break;			/* string didn't match */
		}

		if (ISO_STD_VER(buf) != ISO_ID_VER) {
			break;			/* not a match */
		}

		if (ISO_DESC_TYPE(buf) == ISO_VD_PVD) {
#ifdef	DEBUG
			memcpy(volid, ISO_vol_id(buf), ISO_VOL_ID_STRLEN);
			volid[ISO_VOL_ID_STRLEN] = '\0';
			(void) fprintf(stderr,
			    "DEBUG: ident_hsfs() ISO vol id is \"%s\"\n",
			    volid);
#endif
			found = TRUE;
			break;
		}

		/* no match -- go to the next sector */
	}

#ifdef	DEBUG
	(void) fprintf(stderr, "DEBUG: hsfs findisovol(): returning %s\n",
	    found ? "TRUE" : "FALSE");
#endif
	return (found);
}


static bool_t
getsector(int fd, char *buf, int secno)
{
	if (lseek(fd, secno * ISO_SECTOR_SIZE, SEEK_SET) < 0L) {
#ifdef	DEBUG
		(void) fprintf(stderr,
		    "error: lseek to sector %d failed: %d\n", secno, errno);
#endif
		return (FALSE);
	}

	if (read(fd, buf, ISO_SECTOR_SIZE) != ISO_SECTOR_SIZE) {
#ifdef	DEBUG
		(void) fprintf(stderr, "error: read of %d bytes failed: %d\n",
		    ISO_SECTOR_SIZE, errno);
#endif
		return (FALSE);
	}

	/* all went well */
	return (TRUE);
}

/*
 * rdev_is_a_cd  - return TRUE if the raw device identified by
 *  		      a file descriptor is a CDROM device.
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
