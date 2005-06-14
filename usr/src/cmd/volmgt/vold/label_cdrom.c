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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<errno.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/dkio.h>
#include	<sys/cdio.h>
#include	<sys/vtoc.h>
#include	<sys/fs/hsfs_isospec.h>
#include	<sys/fs/hsfs_spec.h>
#include	<fcntl.h>
#include	<string.h>
#include	"vold.h"


/*
 * This labeling code is for cdrom.  The fundamental
 * assumption is that you can't write to a cdrom, and that there
 * can easily be more than one of a particular cdrom.  So, what
 * we do is pick a few "interesting" sectors, create a crc of
 * them, and use our crc's to match them up.
 *
 * Currently, we just generate one checksum based on the first
 * 64kbytes of data.
 *
 */
#define	CD_MAXNAME	ISO_VOL_ID_STRLEN

struct	cd_label {
	u_short		cl_version;	/* version of this structure */
	u_long		cl_crc;		/* crc of the first 64kb */
	u_char		cl_type;	/* type of cdrom (audio &| data) */
	u_char		cl_nparts;	/* number of valid paritions */
	u_long		cl_parts;	/* partition mask */
	u_char		cl_au_start;	/* starting audio track */
	u_char		cl_au_end;	/* ending audio track */
					/* name derived from media */
	char		cl_name[CD_MAXNAME+1];
	u_longlong_t	cl_md4sig[2];	/* 128 bits of cdrom signature */
};

static char		*cdrom_key(label *);
static bool_t 		cdrom_compare(label *, label *);
static enum laread_res	cdrom_read(int, label *, struct devs *dp);
static void		cdrom_setup(vol_t *);
static void		cdrom_xdr(label *, enum xdr_op, void **);
static u_long		audio_crc(int);
static void		hsfs_findname(int, struct cd_label *, u_char *);
static bool_t		getdisk(int, u_char *, int, size_t);

#define	CDTYPE_DATA		1
#define	CDTYPE_AUDIO		2
#define	CDTYPE_MIXED		3

#define	CDROM_VERSION		1

#define	CDROM_SIZE		sizeof (struct cd_label)
#define	CDROM_DEFAULT_MODE	0444	/* read-only */

/* for CD-ROM "signature" -- must be a multiple of ISO_SECTOR_SIZE */
#define	CD_READSIZE		(16 * ISO_SECTOR_SIZE)	/* 32k */

/* use the md4 digital signature */
#define	CDROM_MD4

/* size of buffer used for printing longlong numbers */
#define	CDROM_NUMBUFLEN		512


/* for identifying "CD-I"-type CD-ROMs */
#define	CDI_ID_STRING		"CD-I"
#define	CDI_ID_STRLEN		4

/*
 * the vold interface structure
 */
static struct labsw cdromlabsw = {
	cdrom_key,		/* l_key */
	cdrom_compare, 		/* l_compare */
	cdrom_read, 		/* l_read */
	NULL, 			/* l_write */
	cdrom_setup, 		/* l_setup */
	cdrom_xdr, 		/* l_xdr */
	(size_t)0, 		/* l_size */
	(size_t)0,		/* l_xdrsize */
	ISO9660_LTYPE,		/* l_ident */
	(uint_t)0,		/* l_nll */
	NULL			/* l_ll */	/* don't need this for cdrom */
};


/*
 * Initialization function, called by the dso loader.
 */
bool_t
label_init()
{
	info(gettext("label_cdrom: init\n"));

	label_new(&cdromlabsw);
	return (TRUE);
}


/*
 * this routine tries to find out about the CD-ROM specified
 *
 * it creates and partially fills in the cdl private CD-ROM data structure
 *
 * if it appears as if the CD-ROM is music-only (see rmmount/audio_only())
 * it does not even try to find the name by reading data from the CD-ROM
 */
static enum laread_res
cdrom_read(int fd, label *la, struct devs *dp)
{
	struct cd_label		*cdl;
	u_char			cd_pvd[ISO_SECTOR_SIZE];
	u_char			*cd_readbuf;
	struct vtoc		vtoc;
	struct cdrom_tochdr	th;
	struct cdrom_tocentry	te;
	uchar_t			i;		/* track index */
	enum laread_res		res;		/* result to return */
	size_t			sz;
	bool_t			audio_only = TRUE;
	bool_t			we_have_mode_2_data = FALSE;



	(void) fcntl(fd, F_SETFD, 1);

	dp->dp_writeprot = TRUE;	/* always */

	la->l_label = (void *)calloc(1, sizeof (struct cd_label));
	cdl = (struct cd_label *)la->l_label;

	if (ioctl(fd, CDROMREADTOCHDR, &th) < 0) {
		/*
		 * can't even read the TOC header -- assume it's not music
		 * for now (the read attempt below will fail if it is)
		 */
		warning(gettext("cdrom: readtochdr on \"%s\"; %m\n"),
		    dp->dp_path);
		goto not_audio_only;
	}

	/*
	 * look through the tracks on the disk to see if we have
	 * any data (i.e. non-music) tracks
	 */

	cdl->cl_au_start = th.cdth_trk0;
	cdl->cl_au_end = th.cdth_trk1;

	/* if start track is greater than end track then assume not audio */
	if (cdl->cl_au_start > cdl->cl_au_end) {
		warning(gettext(
		    "cdrom: start track greater than end track\n"));
		goto not_audio_only;
	}

	te.cdte_format = CDROM_MSF;
	for (i = th.cdth_trk0; i <= th.cdth_trk1; i++) {

		/* look for data on this track */

		/* try to read the TOC entry for the ith track */
		te.cdte_track = i;
		if (ioctl(fd, CDROMREADTOCENTRY, &te) < 0) {

			/*
			 * oh oh: can't read track TOC entry - punt and
			 * try the LEADOUT track
			 */

			te.cdte_track = (unsigned char)CDROM_LEADOUT;
			if (ioctl(fd, CDROMREADTOCENTRY, &te) < 0) {
				/*
				 * we can read TOC hdr but not the TOC entry
				 * or the LEADOUT track -- assume not
				 * music for now (the read attempt
				 * below will fail if it is a music CD)
				 */
				warning(gettext(
				"cdrom: readtocentry LEADOUT on \"%s\"; %m\n"),
				    dp->dp_path);
				audio_only = FALSE;
				break;
			}

			/* if datamode is 2 then we have a mode 2 CD-ROM */
			if (te.cdte_datamode == 2) {
				we_have_mode_2_data = TRUE;
				debug(5,
			"cdrom_read: found Mode 2 data on LEADOUT track\n");
			}

			/*
			 * read TOC hdr succeeded but read of TOC entry for a
			 * track failed -- *guess* whether or not CD is audio
			 * only based on LEADOUT track
			 */
			if (te.cdte_ctrl & CDROM_DATA_TRACK) {
				audio_only = FALSE;
				break;
			}

			/* *guess* audio only */
			debug(1, "cdrom_read: audio-only cdrom\n");
			cdl->cl_type = CDTYPE_AUDIO;
			cdl->cl_crc = audio_crc(fd);
			debug(6, "cdrom: generated crc of %#x audio cd\n",
			    cdl->cl_crc);
			res = L_FOUND;
			goto dun;
		}

		/*
		 * read of the ith track succeeded
		 */

		/* if datamode is 2 then we have a mode 2 CD-ROM */
		if (te.cdte_datamode == 2) {
			we_have_mode_2_data = TRUE;
			debug(5, "cdrom_read: Mode 2 data on track %u\n",
			    (unsigned int)i);
		}

		/*
		 * if this (or any) track is non-audio then we set a flag
		 * saying this isn't a strickly-audio CD-ROM
		 */
		if (te.cdte_ctrl & CDROM_DATA_TRACK) {
			audio_only = FALSE;
		}

		/* go look at next one */
	}

	if (audio_only) {
		/* all tracks found were audio */
		debug(1, "cdrom_read: audio-only cdrom\n");
		cdl->cl_type = CDTYPE_AUDIO;
		cdl->cl_crc = audio_crc(fd);
		debug(6, "cdrom: generated crc of %#x audio cd\n",
		    cdl->cl_crc);
		res = L_FOUND;
		goto dun;
	}

not_audio_only:

	/* find the CD's "name" */
	hsfs_findname(fd, cdl, cd_pvd);

	/* set the type to data (since it is not music) */
	cdl->cl_type = CDTYPE_DATA;

	/*
	 * now get a bigger buffer to do the "signature" on (if possible)
	 *
	 * call read routine to read CD_READSIZE bytes (if possible) from
	 * the CD-ROM
	 */
	if (!we_have_mode_2_data) {

		/* just a "regular" ISO CD-ROM -- just read a hunk from it */

		sz = CD_READSIZE;
		cd_readbuf = (u_char *)malloc(sz);

		if (!getdisk(fd, cd_readbuf, HS_VOLDESC_SEC, sz)) {
			warning(gettext(
			    "cdrom_read: can't read the cdrom; %m\n"));
			res = L_ERROR;
			free(cd_readbuf);
			goto dun;
		}

	} else {

		/*
		 * use the sector we just read -- since Solaris doesn't
		 * seem able to handle non-2048 block mode 2 data (i.e.
		 * mode 2 form 2 -- it does handle form1, which are 2048
		 * byte blocks, like all mode 1 blocks) -- whew!
		 */

		debug(5, "cdrom_read: Mode 2 -> using orig HSFS pvd sector\n");

		sz = ISO_SECTOR_SIZE;
		cd_readbuf = (u_char *)malloc(sz);
		(void) memcpy(cd_readbuf, cd_pvd, ISO_SECTOR_SIZE);
	}

	/* calculate the "signature" */
#ifdef CDROM_MD4
	calc_md4(cd_readbuf, sz, cdl->cl_md4sig);
	debug(6, "cdrom: generated md4 signature of '%-0.16llx%-0.16llx'\n",
	    cdl->cl_md4sig[0], cdl->cl_md4sig[1]);
#else
	cdl->cl_crc = calc_crc(cd_readbuf, sz);
	debug(6, "cdrom: generated crc of 0x%lx for data cd\n", cdl->cl_crc);
#endif
	free(cd_readbuf);

	/* read the vtoc and convert that to #parts and a part bitmap */
	(void) ioctl(fd, DKIOCGVTOC, &vtoc);		/* assume this works */
	partition_conv_2(&vtoc, PART_MAXCDROM, &cdl->cl_parts,
	    &cdl->cl_nparts);

	res = L_FOUND;
dun:
#ifdef	DEBUG
	debug(6, "cdrom_read: returning %d\n", (int)res);
#endif
	return (res);
}

static char *
cdrom_key(label *la)
{
	char		buf[CDROM_NUMBUFLEN];	/* for printing numbers */
	struct cd_label	*cdl;

	cdl = (struct cd_label *)la->l_label;
	if (cdl->cl_type == CDTYPE_AUDIO) {
		(void) sprintf(buf, "0x%lx", cdl->cl_crc);
	} else {
#ifdef CDROM_MD4
		(void) sprintf(buf, "%-0.16llx%-0.16llx", cdl->cl_md4sig[0],
		    cdl->cl_md4sig[1]);
#else
		(void) sprintf(buf, "0x%lx", cdl->cl_crc);
#endif
	}

	return (strdup(buf));
}


static bool_t
cdrom_compare(label *la1, label *la2)
{
	struct cd_label	*cdl1, *cdl2;


	cdl1 = (struct cd_label *)la1->l_label;
	cdl2 = (struct cd_label *)la2->l_label;

	if (cdl1->cl_type != cdl2->cl_type) {
		return (FALSE);
	}

	if (cdl1->cl_type == CDTYPE_AUDIO) {
		if (cdl1->cl_crc == cdl2->cl_crc) {
			return (TRUE);
		}
		return (FALSE);
	}

	if (cdl1->cl_type == CDTYPE_DATA) {
#ifdef CDROM_MD4
		if ((cdl1->cl_md4sig[0] == cdl1->cl_md4sig[0]) &&
		    (cdl1->cl_md4sig[1] == cdl1->cl_md4sig[1])) {
			return (TRUE);
		}
		return (FALSE);
#else
		if (cdl1->cl_crc == cdl2->cl_crc) {
			return (TRUE);
		}
		return (FALSE);
#endif
	}
	return (FALSE);
}

static void

cdrom_setup(vol_t *v)
{
	struct cd_label *cdl = (struct cd_label *)v->v_label.l_label;
	char		unnamed_buf[MAXNAMELEN+1];


	if (cdl->cl_name[0] != NULLC) {
		v->v_obj.o_name = strdup(cdl->cl_name);
	} else {
		(void) sprintf(unnamed_buf, "%s%s", UNNAMED_PREFIX,
		    CDROM_MTYPE);
		v->v_obj.o_name = strdup(unnamed_buf);
	}
#ifdef	DEBUG
	debug(5, "cdrom_setup: CD-ROM given name: \"%s\"\n",
	    v->v_obj.o_name);
#endif
	v->v_flags |= V_NETWIDE|V_RDONLY;
	v->v_obj.o_mode = CDROM_DEFAULT_MODE;
	v->v_ndev = cdl->cl_nparts;
	v->v_parts = cdl->cl_parts;
}


void
cdrom_xdr(label *l, enum xdr_op op, void **data)
{
	XDR		xdrs;
	struct cd_label	*cdl, sdc;
	char		*s = NULL;


	if (cdromlabsw.l_xdrsize == 0) {
		cdromlabsw.l_xdrsize = 0;
		cdromlabsw.l_xdrsize += xdr_sizeof(xdr_u_short,
		    (void *)&sdc.cl_version);
		cdromlabsw.l_xdrsize += xdr_sizeof(xdr_u_long,
		    (void *)&sdc.cl_crc);
		cdromlabsw.l_xdrsize += xdr_sizeof(xdr_u_char,
		    (void *)&sdc.cl_type);
		cdromlabsw.l_xdrsize += xdr_sizeof(xdr_u_char,
		    (void *)&sdc.cl_nparts);
		cdromlabsw.l_xdrsize += xdr_sizeof(xdr_u_long,
		    (void *)&sdc.cl_parts);
		cdromlabsw.l_xdrsize += xdr_sizeof(xdr_u_char,
		    (void *)&sdc.cl_au_start);
		cdromlabsw.l_xdrsize += xdr_sizeof(xdr_u_char,
		    (void *)&sdc.cl_au_end);
		cdromlabsw.l_xdrsize += CD_MAXNAME+sizeof (int);
		cdromlabsw.l_xdrsize += xdr_sizeof(xdr_u_longlong_t,
		    (void *)&sdc.cl_md4sig[0]);
		cdromlabsw.l_xdrsize += xdr_sizeof(xdr_u_longlong_t,
		    (void *)&sdc.cl_md4sig[1]);
	}

	if (op == XDR_ENCODE) {
		cdl = (struct cd_label *)l->l_label;
		*data = malloc(cdromlabsw.l_xdrsize);
		xdrmem_create(&xdrs, *data, cdromlabsw.l_xdrsize, op);
		cdl->cl_version = CDROM_VERSION;
		(void) xdr_u_short(&xdrs, &cdl->cl_version);
		(void) xdr_u_long(&xdrs, &cdl->cl_crc);
		(void) xdr_u_char(&xdrs, &cdl->cl_type);
		(void) xdr_u_char(&xdrs, &cdl->cl_nparts);
		(void) xdr_u_long(&xdrs, &cdl->cl_parts);
		(void) xdr_u_char(&xdrs, &cdl->cl_au_start);
		(void) xdr_u_char(&xdrs, &cdl->cl_au_end);
		s = cdl->cl_name;
		(void) xdr_string(&xdrs, &s, CD_MAXNAME);
		(void) xdr_u_longlong_t(&xdrs, &cdl->cl_md4sig[0]);
		(void) xdr_u_longlong_t(&xdrs, &cdl->cl_md4sig[1]);

		xdr_destroy(&xdrs);
	} else if (op == XDR_DECODE) {
		xdrmem_create(&xdrs, *data, cdromlabsw.l_xdrsize, op);
		if (l->l_label == NULL) {
			l->l_label =
			    (void *)calloc(1, sizeof (struct cd_label));
		}
		cdl = (struct cd_label *)l->l_label;
		(void) xdr_u_short(&xdrs, &cdl->cl_version);
		if (cdl->cl_version == 1) {
			(void) xdr_u_long(&xdrs, &cdl->cl_crc);
			(void) xdr_u_char(&xdrs, &cdl->cl_type);
			(void) xdr_u_char(&xdrs, &cdl->cl_nparts);
			(void) xdr_u_long(&xdrs, &cdl->cl_parts);
			(void) xdr_u_char(&xdrs, &cdl->cl_au_start);
			(void) xdr_u_char(&xdrs, &cdl->cl_au_end);
			(void) xdr_string(&xdrs, &s, CD_MAXNAME);
			if (s) {
				(void) strncpy(cdl->cl_name, s, CD_MAXNAME);
				xdr_free(xdr_string, (void *)&s);
			}
			(void) xdr_u_longlong_t(&xdrs, &cdl->cl_md4sig[0]);
			(void) xdr_u_longlong_t(&xdrs, &cdl->cl_md4sig[1]);
		} else {
			debug(1,
			"label_cdrom: don't know how to decode version %d\n",
				cdl->cl_version);
		}
		xdr_destroy(&xdrs);
	}
}

struct audiosum {
	struct cdrom_tochdr	as_th;
	/* max number of tracks is 99 + 1 for lead-in */
	struct cdrom_tocentry	as_te[100];
};

static u_long
audio_crc(int fd)
{
	struct audiosum	*ap;
	u_long		crc;
	uchar_t		i;


	ap = (struct audiosum *)calloc(1, sizeof (struct audiosum));

	if (ioctl(fd, CDROMREADTOCHDR, &ap->as_th) < 0) {
		debug(1, "cdrom_audio: readtochdr; %m\n");
	}
	ap->as_te[0].cdte_track = CDROM_LEADOUT;
	ap->as_te[0].cdte_format = CDROM_MSF;
	if (ioctl(fd, CDROMREADTOCENTRY, &ap->as_te[0]) < 0) {
		debug(1, "cdrom_audio: readtocentry (leadout); %m\n");
	}

	for (i = ap->as_th.cdth_trk0; i <= ap->as_th.cdth_trk1; i++) {
		ap->as_te[i].cdte_track = i;
		ap->as_te[i].cdte_format = CDROM_MSF;
		if (ioctl(fd, CDROMREADTOCENTRY, &ap->as_te[i]) < 0) {
			debug(1, "cdrom_audio: readtocentry (%d); %m\n", i);
		}
	}
	crc = calc_crc((u_char *)ap, sizeof (struct audiosum));
	free(ap);
	return (crc);
}


/*
 * We've already read the data, so there's no reason not to check
 * and see if we have an HSFS disk with a nice name out there.
 */
static void
hsfs_findname(int fd, struct cd_label *cdl, u_char *pvd)
{
	static bool_t	findcdivol(int, u_char *, int);
	static bool_t	findhsvol(int, u_char *, int);
	static bool_t	findisovol(int, u_char *, int);
	char		*cd_nm_ptr = NULL;
	size_t		cd_nm_sz;
	char		*nm;
	int		err;
	int		off = 0;

#ifdef CDROMREADOFFSET
	if ((err = ioctl(fd,CDROMREADOFFSET, &off)) == -1)
		off = 0;
#endif

	if (findcdivol(fd, pvd, off)) {
		cd_nm_ptr = (char *)ISO_vol_id(pvd);
		cd_nm_sz = ISO_VOL_ID_STRLEN;
	} else if (findhsvol(fd, pvd, off)) {
		cd_nm_ptr = (char *)HSV_vol_id(pvd);
		cd_nm_sz = HSV_VOL_ID_STRLEN;
	} else if (findisovol(fd, pvd, off)) {
		cd_nm_ptr = (char *)ISO_vol_id(pvd);
		cd_nm_sz = ISO_VOL_ID_STRLEN;
	}

	if (cd_nm_ptr != NULL) {
		nm = makename(cd_nm_ptr, cd_nm_sz);
		(void) strncpy(cdl->cl_name, nm, CD_MAXNAME);
		free(nm);
		debug(3, "hsfs_findname: volume name is \"%s\"\n",
		    cdl->cl_name);
	}
#ifdef	DEBUG
	else {
		debug(3, "hsfs_findname: no volume name found!\n");
	}
#endif
}


static bool_t
findcdivol(int fd, u_char *buf, int off)
{
	int		secno = ISO_VOLDESC_SEC + off;
	int		i;
	bool_t		found = FALSE;
#ifdef	DEBUG
	char		*volid;
#endif


#ifdef	DEBUG
	debug(5, "findcdivol(): entering\n");
#endif

	while (getdisk(fd, buf, secno++, ISO_SECTOR_SIZE)) {

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
			volid = makename((char *)ISO_vol_id(buf),
			    ISO_VOL_ID_STRLEN);
			debug(5, "ident_hsfs() CD-I vol id is \"%s\"\n",
			    volid);
			free(volid);
#endif
			found = TRUE;
			break;
		}

		/* look at next sector */
	}

#ifdef	DEBUG
	debug(5, "findcdivol(): returning %s\n", found ? "TRUE" : "FALSE");
#endif
	return (found);
}


/*ARGSUSED*/
static bool_t
findhsvol(int fd, u_char *buf, int off)
{
	int		secno = HS_VOLDESC_SEC + off;
	int		i;
	bool_t		found = FALSE;
#ifdef	DEBUG
	char		*volid;
#endif


#ifdef	DEBUG
	debug(5, "findhsvol(): entering\n");
#endif

	/*
	 * look through the volume descriptors until we find an HSFS
	 * primary volume descriptor, or until we find the end of the
	 * volume descriptors
	 */
	while (getdisk(fd, buf, secno++, ISO_SECTOR_SIZE)) {

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
			volid = makename((char *)ISO_vol_id(buf),
			    ISO_VOL_ID_STRLEN);
			debug(5, "ident_hsfs() HS vol id is \"%s\"\n",
			    volid);
			free(volid);
#endif
			found = TRUE;
			break;
		}

		/* go to the next sector */
	}

#ifdef	DEBUG
	debug(5, "findhsvol(): returning %s\n", found ? "TRUE" : "FALSE");
#endif
	return (found);
}


/*ARGSUSED*/
static bool_t
findisovol(int fd, u_char *buf, int off)
{
	int		secno = ISO_VOLDESC_SEC + off;
	int		i;
	bool_t		found = FALSE;
#ifdef	DEBUG
	char		*volid;
#endif


#ifdef	DEBUG
	debug(5, "findisovol(): entering\n");
#endif

	/*
	 * look through the volume descriptors until we find an ISO 9660
	 * primary volume descriptor, or until we find the end of the
	 * volume descriptors
	 */
	while (getdisk(fd, buf, secno++, ISO_SECTOR_SIZE)) {

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
			volid = makename((char *)ISO_vol_id(buf),
			    ISO_VOL_ID_STRLEN);
			debug(5, "ident_hsfs() ISO vol id is \"%s\"\n",
			    volid);
			free(volid);
#endif
			found = TRUE;
			break;
		}

		/* no match -- go to the next sector */
	}

#ifdef	DEBUG
	debug(5, "findhsvol(): returning %s\n", found ? "TRUE" : "FALSE");
#endif
	return (found);
}


static bool_t
getdisk(int fd, u_char *buf, int secno, size_t sz)
{
	off_t	offset = secno * ISO_SECTOR_SIZE;


	debug(9, "getdisk: seeking to %ld\n", offset);
	if (lseek(fd, offset, SEEK_SET) < 0L) {
#ifdef	DEBUG
		debug(1, "error: lseek to sector %d failed: %d\n", secno,
		    errno);
#endif
		return (FALSE);
	}

	debug(9, "getdisk: reading %d bytes\n", sz);
	if (read(fd, buf, sz) != sz) {
#ifdef	DEBUG
		debug(1, "error: read of %ld bytes failed: %d\n", sz, errno);
#endif
		return (FALSE);
	}

	/* all went well */
	return (TRUE);
}
