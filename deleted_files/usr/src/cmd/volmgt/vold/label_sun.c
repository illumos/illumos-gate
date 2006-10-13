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
#include	<sys/types.h>
#include	<fcntl.h>
#include	<string.h>

#include	<sys/vtoc.h>
#include	<sys/dkio.h>
#include	<sys/dklabel.h>

#include	"vold.h"


static bool_t 		sun_compare(label *, label *);
static enum laread_res	sun_read(int, label *, struct devs *dp);
static void		sun_setup(vol_t *);
static char		*sun_key(label *);
static void		sun_xdr(label *, enum xdr_op, void **);

/*
 * this is the datastructure that we keep around for each sun
 * label to allow us to identify it.
 */

struct sun_label {
	u_short		sl_version;	/* version of this structure for db */
	u_long		sl_lcrc;	/* crc of label */
	u_long		sl_key;		/* key for label */
	u_char		sl_nparts;	/* number of partitions */
	u_long		sl_parts;	/* partition mask */
	u_char		sl_type; 	/* type of media */
	char		sl_vtocname[LEN_DKL_VVOL+1];	/* name from label */
};

/* sl_type: */
#define	SL_UNKNOWN	0
#define	SL_CDROM	1
#define	SL_MO		2
#define	SL_FLOPPY	3
#define	SL_DISK		4
#define	SL_PCMEM	5

#define	SUN_VERSION	1

#define	SUN_SIZE	sizeof (struct sun_label)

/*
 * XXX: what is this used for, and what size should really be used
 */
static struct label_loc	sun_labelloc = {0, sizeof (struct dk_label) };

static struct labsw	sunlabsw = {
	sun_key, 	/* l_key */
	sun_compare, 	/* l_compare */
	sun_read, 	/* l_read */
	NULL, 		/* l_write */
	sun_setup, 	/* l_setup */
	sun_xdr, 	/* l_xdr */
	SUN_SIZE, 	/* l_size */
	SUN_SIZE, 	/* l_xdrsize */
	UFS_LTYPE,	/* l_ident */
	1,		/* l_nll */
	&sun_labelloc	/* l_ll */
};



/*
 * Initialization function, called by the dso loader.
 */
bool_t
label_init(void)
{
	info(gettext("label_sun: init\n"));

	label_new(&sunlabsw);
	return (TRUE);
}

/*
 * Read the label off the disk and build an sl label structure
 * to represent it.
 *
 * XXX: the way in which we both read the sun label and we
 * "unique-ify" UFS media is non-standard at best (and
 * prone to break with new/different media types and/or
 * changes in media layout format
 */
static enum laread_res
sun_read(int fd, label *la, struct devs *dp)
{
	extern time_t		unique_time(char *, char *);
	extern char		*laread_res_to_str(enum laread_res);
	static bool_t		sun_get_dklabel(int, char *,
				    struct dk_label *);
	static bool_t		sun_put_dklabel(int, char *,
				    struct dk_label *);
	static void		checksum(struct dk_label *);
	struct vtoc		vtoc;
	struct dk_label		dkl;
	struct sun_label	*sl = 0;
	char			*type = dp->dp_dsw->d_mtype;
	enum laread_res		retval;



	debug(6, "sun_read: entering (fd=%d)\n", fd);

	/* get the label */
	if (!sun_get_dklabel(fd, type, &dkl)) {
		debug(3, "sun_read: can't read DK label from \"%s\"; %m\n",
		    dp->dp_path);
		retval = L_UNFORMATTED;
		goto out;
	}

	if (dkl.dkl_magic != DKL_MAGIC) {
		debug(3,
		    "sun_read: dkl_magic wrong # (%#x expected, %#x found)\n",
		    DKL_MAGIC, dkl.dkl_magic);
		retval = L_UNRECOG;
		goto out;
	}

	la->l_label = (void *)calloc(1, sizeof (struct sun_label));
	sl = (struct sun_label *)la->l_label;

	/* if we have a name then get it */
	if (dkl.dkl_vtoc.v_volume[0] != NULLC) {
		(void) strncpy(sl->sl_vtocname, dkl.dkl_vtoc.v_volume,
		    LEN_DKL_VVOL);
		debug(6, "sun_read: vtoc name = \"%s\"\n", sl->sl_vtocname);
	}

	/*
	 * ok, it is really ugly here -- we assume that if no one
	 * has set a time stamp that the label probably isn't very
	 * unique
	 *
	 * we make it unique, calculate a new checksum (else it will be off),
	 * and write it back out
	 */
	if (dkl.dkl_vtoc.v_timestamp[0] == (time_t)0) {

		/* are we allowed to unique-ify it ?? */
		if (dp->dp_writeprot || never_writeback) {
			retval = L_NOTUNIQUE;
			goto out;
		}

		/* unique-ify it */
		dkl.dkl_vtoc.v_timestamp[0] = unique_time(type, UFS_LTYPE);

		/* update the checksum */
		checksum(&dkl);

		/* write it back out */
		if (!sun_put_dklabel(fd, type, &dkl)) {
			retval = L_NOTUNIQUE;
			goto out;
		}

		debug(6, "sun_read: wroteback %#lx as unique thing\n",
		    dkl.dkl_vtoc.v_timestamp[0]);
	} else {
		debug(6, "sun_read: unique thing is %#lx\n",
		    dkl.dkl_vtoc.v_timestamp[0]);
	}

	sl->sl_lcrc = calc_crc((u_char *)&dkl,
	    sizeof (struct dk_label));
	sl->sl_key = dkl.dkl_vtoc.v_timestamp[0];

	/* set the "type" field */
	if (strcmp(type, FLOPPY_MTYPE) == 0) {
		sl->sl_type = SL_FLOPPY;
	} else if (strcmp(type, MO_MTYPE) == 0) {
		sl->sl_type = SL_MO;
	} else if (strcmp(type, RMDISK_MTYPE) == 0) {
		sl->sl_type = SL_DISK;
	} else if (strcmp(type, CDROM_MTYPE) == 0) {
		sl->sl_type = SL_CDROM;
	} else if (strcmp(type, PCMEM_MTYPE) == 0) {
		sl->sl_type = SL_PCMEM;
	} else {
		sl->sl_type = SL_UNKNOWN;
	}

	(void) ioctl(fd, DKIOCGVTOC, &vtoc);

	if (sl->sl_type == SL_CDROM) {
		/*
		 * cdrom is really the only known case of strange
		 * sizes in the label, so its the only one we should
		 * have to special case here.  Its also the only
		 * device type that can really be considered to be
		 * a "fixed" size.
		 */
		partition_conv_2(&vtoc, PART_MAXCDROM,
		    &sl->sl_parts, &sl->sl_nparts);
	} else {
		partition_conv_2(&vtoc, PART_INF,
		    &sl->sl_parts, &sl->sl_nparts);
	}
	retval = L_FOUND;
out:
	if ((retval != L_FOUND) && (retval != L_NOTUNIQUE)) {
		if (sl != NULL) {
			free(sl);
		}
		la->l_label = 0;
	}
	if (retval == L_FOUND) {
		debug(1, "sun_read: returning %s (%d) -- label = \"%s\"\n",
		    laread_res_to_str(retval), (int)retval, sl->sl_vtocname);
	} else {
		debug(1, "sun_read: returning %s (%d)\n",
		    laread_res_to_str(retval), (int)retval);
	}
	return (retval);
}


/*
 * return the offset for the sun label for a given media type
 *
 * XXX: I don't know how this should be done once SPARC starts handling
 * FDISK -- what will DK_LABEL_LOC be then?
 *
 * NOTE: this is centralized here since two routines use this number,
 * and it's *important* that they both use the same formula! (;-)
 *
 * XXX: volmgt shouldn't know *anything* about seperate media
 * types (but it certainly does)
 */
static daddr_t
dklabel_offset(char *type)
{
	daddr_t			offset;

	if ((strcmp(type, FLOPPY_MTYPE) == 0) ||
	    (strcmp(type, TEST_MTYPE) == 0) ||
	    (strcmp(type, PCMEM_MTYPE) == 0)) {
		offset = (daddr_t)0;
	} else {
		offset = DK_LABEL_LOC * DEV_BSIZE;
	}

	return (offset);
}


/*
 * try to get the "dk label" by reading directly from the disk
 */
static bool_t
sun_get_dklabel(int fd, char *type, struct dk_label *dklp)
{
	daddr_t			offset = dklabel_offset(type);
	bool_t			ret_res = FALSE;


	/* seek to the proper place */
	if (lseek(fd, offset, SEEK_SET) != offset) {
		debug(6,
		    "sun_get_dklabel: seek to %ld failed (for label); %m\n",
		    offset);
		goto dun;
	}

	/* read the label */
	debug(11, "sun_get_dklabel: reading %u bytes from offset %ld\n",
	    sizeof (struct dk_label), offset);
	if (read(fd, dklp, sizeof (struct dk_label)) !=
	    sizeof (struct dk_label)) {
		debug(6, "sun_get_dklabel: can't read DK label; %m\n");
		goto dun;
	}

	/* success (at reading where the label *should* be) */
	ret_res = TRUE;
dun:
	return (ret_res);
}


static bool_t
sun_put_dklabel(int fd, char *type, struct dk_label *dklp)
{
	daddr_t			offset = dklabel_offset(type);
	bool_t			ret_res = FALSE;


	/* seek to the proper place */
	if (lseek(fd, offset, SEEK_SET) != offset) {
		debug(6,
		    "sun_put_dklabel: seek to %ld failed (for label); %m\n",
		    offset);
		goto dun;
	}

	/* write back out the label */
	debug(11, "sun_put_dklabel: writing %u bytes at offset %ld\n",
	    sizeof (struct dk_label), offset);
	if (write(fd, dklp, sizeof (struct dk_label)) !=
	    sizeof (struct dk_label)) {
		debug(6, "sun_put_dklabel: can't write DK label; %m\n");
		goto dun;
	}

	ret_res = TRUE;
dun:
	return (ret_res);

}


static char *
sun_key(label *la)
{
	char	buf[MAXNAMELEN];
	struct sun_label *sl = (struct sun_label *)la->l_label;

	(void) sprintf(buf, "0x%lx", sl->sl_key);
	return (strdup(buf));
}


static bool_t
sun_compare(label *la1, label *la2)
{
	struct sun_label *sl1, *sl2;
	sl1 = (struct sun_label *)la1->l_label;
	sl2 = (struct sun_label *)la2->l_label;

	if (sl1->sl_key != sl2->sl_key) {
		return (FALSE);
	}
	if (sl1->sl_lcrc != sl2->sl_lcrc) {
		return (FALSE);
	}
	return (TRUE);
}


static void
sun_setup(vol_t *v)
{
	struct sun_label	*sl = (struct sun_label *)v->v_label.l_label;
	int			do_unnamed = 0;


	debug(6, "sun_setup: entering\n");

	if (sl->sl_vtocname[0] != NULLC) {
		v->v_obj.o_name = makename(sl->sl_vtocname, LEN_DKL_VVOL);
		if (v->v_obj.o_name[0] == NULLC) {
			/* makename() couldn't name a name */
			do_unnamed++;
			free(v->v_obj.o_name);
		}
	} else {
		do_unnamed++;
	}

	if (do_unnamed) {
		char	unnamed_buf[MAXNAMELEN+1];
		char	*mtype;

		switch (sl->sl_type) {
		case SL_FLOPPY:
			mtype = FLOPPY_MTYPE;
			break;
		case SL_CDROM:
			mtype = CDROM_MTYPE;
			break;
		case SL_MO:
			mtype = MO_MTYPE;
			break;
		case SL_DISK:
			mtype = RMDISK_MTYPE;
			break;
		case SL_UNKNOWN:
		default:
			if (v->v_mtype != NULL) {
				mtype = v->v_mtype;
			} else {
				mtype = OTHER_MTYPE;
			}
			break;
		}
		(void) sprintf(unnamed_buf, "%s%s", UNNAMED_PREFIX, mtype);
		v->v_obj.o_name = strdup(unnamed_buf);
	}

	debug(5, "sun_setup: SUN media given name \"%s\"\n",
	    v->v_obj.o_name);

	v->v_ndev = sl->sl_nparts;
	v->v_flags |= V_NETWIDE;
	v->v_parts = sl->sl_parts;

	/* if it's a CDROM, it's readonly */
	if (sl->sl_type == SL_CDROM) {
		v->v_flags |= V_RDONLY;
	}
	v->v_fstype = V_UFS;
}


static void
sun_xdr(label *l, enum xdr_op op, void **data)
{
	XDR		xdrs;
	struct sun_label *sl, ssl;
	char		*s = NULL;


	if (sunlabsw.l_xdrsize == 0) {
		sunlabsw.l_xdrsize = 0;
		sunlabsw.l_xdrsize += xdr_sizeof(xdr_u_short,
		    (void *)&ssl.sl_version);
		sunlabsw.l_xdrsize += xdr_sizeof(xdr_u_long,
		    (void *)&ssl.sl_lcrc);
		sunlabsw.l_xdrsize += xdr_sizeof(xdr_u_long,
		    (void *)&ssl.sl_key);
		sunlabsw.l_xdrsize += xdr_sizeof(xdr_u_char,
		    (void *)&ssl.sl_nparts);
		sunlabsw.l_xdrsize += xdr_sizeof(xdr_u_long,
		    (void *)&ssl.sl_parts);
		sunlabsw.l_xdrsize += xdr_sizeof(xdr_u_char,
		    (void *)&ssl.sl_type);
		/*
		 * yes, well, this is a bit of a hack here, but
		 * I don't know of any other way to do it.
		 * I know that xdr_string encodes the string
		 * as an int + the bytes, so I just allocate that
		 * much space.  silveri said it would work.
		 */
		sunlabsw.l_xdrsize += LEN_DKL_VVOL+sizeof (int);
	}

	if (op == XDR_ENCODE) {
		sl = (struct sun_label *)l->l_label;
		*data = malloc(sunlabsw.l_xdrsize);
		xdrmem_create(&xdrs, *data, sunlabsw.l_xdrsize, op);
		sl->sl_version = SUN_VERSION;
		(void) xdr_u_short(&xdrs, &sl->sl_version);
		(void) xdr_u_long(&xdrs, &sl->sl_lcrc);
		(void) xdr_u_long(&xdrs, &sl->sl_key);
		(void) xdr_u_char(&xdrs, &sl->sl_nparts);
		(void) xdr_u_long(&xdrs, &sl->sl_parts);
		(void) xdr_u_char(&xdrs, &sl->sl_type);
		s = sl->sl_vtocname;
		(void) xdr_string(&xdrs, &s, LEN_DKL_VVOL);
		xdr_destroy(&xdrs);
	} else if (op == XDR_DECODE) {
		xdrmem_create(&xdrs, *data, sunlabsw.l_xdrsize, op);
		if (l->l_label == NULL) {
			l->l_label =
			    (void *)calloc(1, sizeof (struct sun_label));
		}
		sl = (struct sun_label *)l->l_label;
		(void) xdr_u_short(&xdrs, &sl->sl_version);
		/*
		 * here's where we'll deal with other versions of this
		 * structure...
		 */
		ASSERT(sl->sl_version == SUN_VERSION);
		(void) xdr_u_long(&xdrs, &sl->sl_lcrc);
		(void) xdr_u_long(&xdrs, &sl->sl_key);
		(void) xdr_u_char(&xdrs, &sl->sl_nparts);
		(void) xdr_u_long(&xdrs, &sl->sl_parts);
		(void) xdr_u_char(&xdrs, &sl->sl_type);
		(void) xdr_string(&xdrs, &s, LEN_DKL_VVOL);
		/*
		 * xdr_string seems not to allocate any memory for
		 * a null string, and therefore s is null on return...
		 */
		if (s != NULL) {
			(void) strncpy(sl->sl_vtocname, s, LEN_DKL_VVOL);
			xdr_free(xdr_string, (void *)&s);
		}
		xdr_destroy(&xdrs);
	}
}

/*
 * this routine calculates the label checksum
 */
static void
checksum(struct dk_label *la)
{
	register short	*sp;
	register short	sum = 0;
	register short	count = (sizeof (struct dk_label)) / (sizeof (short));


	/*
	 * we are generating a checksum so don't include the checksum
	 * in the rolling xor
	 */
	count -= 1;
	sp = (short *)la;

	/*
	 * take the xor of all the half-words in the label
	 */
	while (count--) {
		sum ^= *sp++;
	}

	/* fill in the generated checksum */
	la->dkl_cksum = sum;
}
