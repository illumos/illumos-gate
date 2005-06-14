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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Label a file system volume.
 */


#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <locale.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mntent.h>

#include <sys/fs/udf_volume.h>
#include "ud_lib.h"

static uint8_t buf[MAXBSIZE];
static uint64_t off;
#define	BUF_LEN	0x200
static int8_t	lvinfo1_buf[BUF_LEN];
static int8_t	lvinfo2_buf[BUF_LEN];
static int8_t	lvinfo3_buf[BUF_LEN];
static int8_t	fsname[BUF_LEN];
static int8_t	volname[BUF_LEN];
static int32_t fsname_len;

#define	SET_LVINFO1	0x01
#define	SET_LVINFO2	0x02
#define	SET_LVINFO3	0x04
#define	SET_FSNAME	0x08
#define	SET_VOLNAME	0x10

typedef unsigned short unicode_t;

#define	FSNAME_STR_LEN	(8 + 2)
#define	VOLNAME_STR_LEN	32
#define	INFO_STR_LEN	36

static void usage();
static void label(int32_t, uint32_t);
static void print_info(struct vds *, char *, int32_t);
static void label_vds(struct vds *, uint32_t, int32_t);
static int32_t convert_string(int8_t *, int8_t *, int32_t, int32_t, int8_t *);
static int32_t ud_convert2unicode(int8_t *, int8_t *, int32_t);


int8_t *labelit_subopts[] = {
#define	LVINFO1	0x00
	"lvinfo1",
#define	LVINFO2	0x01
	"lvinfo2",
#define	LVINFO3	0x02
	"lvinfo3",
	NULL};


int
main(int32_t argc, char *argv[])
{
	int32_t		opt = 0;
	int32_t		fd = 0;
	int32_t		flags = 0;
	int32_t		ret = 0;
	int8_t		*options = NULL;
	int8_t		*value = NULL;
	uint32_t	set_flags = 0;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

	(void) textdomain(TEXT_DOMAIN);


	while ((opt = getopt(argc, argv, "F:o:")) != EOF) {
		switch (opt) {
		case 'F':
			if (strcmp(optarg, "udfs") != 0) {
				usage();
			}
			break;

		case 'o':
			/*
			 * UDFS specific options
			 */
			options = optarg;
			while (*options != '\0') {
				switch (getsubopt(&options, labelit_subopts,
						&value)) {
				case LVINFO1 :
					set_flags |= SET_LVINFO1;
					(void) convert_string(value,
						lvinfo1_buf, BUF_LEN,
						INFO_STR_LEN,
			gettext("udfs labelit: lvinfo1 should be less than "
			"36 bytes after converting to compressed unicode "
			"dstring\n"));
					break;
				case LVINFO2 :
					set_flags |= SET_LVINFO2;
					(void) convert_string(value,
						lvinfo2_buf, BUF_LEN,
						INFO_STR_LEN,
			gettext("udfs labelit: lvinfo2 should be less than "
			"36 bytes after converting to compressed unicode "
			"dstring\n"));
					break;
				case LVINFO3 :
					set_flags |= SET_LVINFO3;
					(void) convert_string(value,
						lvinfo3_buf, BUF_LEN,
						INFO_STR_LEN,
			gettext("udfs labelit: lvinfo3 should be less than "
			"36 bytes after converting to compressed unicode "
			"dstring\n"));
					break;
				default:
					(void) fprintf(stderr,
			gettext("udfs labelit: Unknown suboption %s\n"), value);
					usage();
					break;
				}
			}
			break;

		case '?':
			usage();
		}
	}

	if ((argc - optind) == 3) {

		/*
		 * There are restrictions on the
		 * length of the names
		 * fsname is 8 characters
		 * volume name is 32 characters
		 * The extra byte is for compression id
		 */
		fsname_len = convert_string(argv[optind + 1],
				fsname, BUF_LEN, FSNAME_STR_LEN,
	gettext("udfs labelit: fsname can not be longer than 8 characters\n"));

		(void) convert_string(argv[optind + 2],
				volname, BUF_LEN, VOLNAME_STR_LEN,
		gettext("udfs labelit: volname can not be longer "
			"than 32 bytes after converting to "
			"compressed unicode dstring\n"));
		set_flags |= SET_FSNAME | SET_VOLNAME;
	} else {
		if ((argc - optind) != 1) {
			usage();
		}
	}

	/*
	 * Open special device
	 */
	if (set_flags == 0) {
		flags = O_RDONLY;
	} else {
		flags = O_RDWR;
	}
	if ((fd = ud_open_dev(argv[optind], flags)) < 0) {
		(void) fprintf(stderr,
		gettext("udfs labelit: cannot open <%s> errorno <%d>\n"),
					argv[optind], errno);
		exit(1);
	}

	if ((ret = ud_fill_udfs_info(fd)) != 0) {
		goto close_dev;
	}

	if ((udfs.flags & VALID_UDFS) == 0) {
		ret = 1;
		goto close_dev;
	}

	label(fd, set_flags);

close_dev:
	ud_close_dev(fd);

	return (ret);
}

static void
usage()
{
	(void) fprintf(stderr, gettext(
		"udfs usage: labelit [-F udfs] [generic options] "
		"[ -o specific_options ] special [fsname volume]\n"));
	(void) fprintf(stderr, gettext(
		" -o : specific_options : [lvinfo1=string],"
		"[lvinfo2=string],[lvinfo3=string]\n"));
	(void) fprintf(stderr,
		gettext("NOTE that all -o suboptions: must"
		" be separated only by commas.\n"));
	exit(1);
}

static void
label(int32_t fd, uint32_t set_flags)
{
	if (set_flags == 0) {
		if (udfs.flags & VALID_MVDS) {
			print_info(&udfs.mvds, "mvds", fd);
		}
		if (udfs.flags & VALID_RVDS) {
			print_info(&udfs.rvds, "rvds", fd);
		}
		return;
	} else {

		if (udfs.flags & VALID_MVDS) {
			label_vds(&udfs.mvds, set_flags, fd);
		}
		if (udfs.flags & VALID_RVDS) {
			label_vds(&udfs.rvds, set_flags, fd);
		}
		if (((set_flags & (SET_FSNAME | SET_VOLNAME)) ==
			(SET_FSNAME | SET_VOLNAME)) &&
			(udfs.fsd_len != 0)) {
			struct file_set_desc *fsd;

			off = udfs.fsd_loc * udfs.lbsize;
			if (ud_read_dev(fd, off, buf, udfs.fsd_len) != 0) {
				return;
			}

			/* LINTED */
			fsd = (struct file_set_desc *)buf;

			set_dstring(fsd->fsd_lvid,
				volname, sizeof (fsd->fsd_lvid));
			set_dstring(fsd->fsd_fsi,
				volname, sizeof (fsd->fsd_fsi));

			ud_make_tag(&fsd->fsd_tag, UD_FILE_SET_DESC,
				SWAP_32(fsd->fsd_tag.tag_loc),
				SWAP_16(fsd->fsd_tag.tag_crc_len));

			(void) ud_write_dev(fd, off, buf, udfs.fsd_len);
		}
	}
}

static void
print_info(struct vds *v, char *name, int32_t fd)
{
	uint8_t		outbuf[BUF_LEN];

	if (v->pvd_len != 0) {
		off = v->pvd_loc * udfs.lbsize;
		if (ud_read_dev(fd, off, buf,
			sizeof (struct pri_vol_desc)) == 0) {

			struct pri_vol_desc *pvd;

			/* LINTED */
			pvd = (struct pri_vol_desc *)buf;

			bzero(outbuf, BUF_LEN);
			(void) ud_convert2local(
					(int8_t *)pvd->pvd_vsi,
					(int8_t *)outbuf, strlen(pvd->pvd_vsi));
			(void) fprintf(stdout,
				gettext("fsname in  %s : %s\n"),
					name, outbuf);

			bzero(outbuf, BUF_LEN);
			pvd->pvd_vol_id[31] = '\0';
			(void) ud_convert2local(
					(int8_t *)pvd->pvd_vol_id,
					(int8_t *)outbuf,
					strlen(pvd->pvd_vol_id));
			(void) fprintf(stdout,
				gettext("volume label in %s : %s\n"),
					name, outbuf);
		}
	}

	if (v->iud_len != 0) {
		off = v->iud_loc * udfs.lbsize;
		if (ud_read_dev(fd, off, buf,
			sizeof (struct iuvd_desc)) == 0) {

			struct iuvd_desc *iud;

			/* LINTED */
			iud = (struct iuvd_desc *)buf;
			bzero(outbuf, BUF_LEN);
			iud->iuvd_ifo1[35] = '\0';
			(void) ud_convert2local(
					(int8_t *)iud->iuvd_ifo1,
					(int8_t *)outbuf,
					strlen(iud->iuvd_ifo1));
			(void) fprintf(stdout,
				gettext("LVInfo1 in  %s : %s\n"),
					name, outbuf);

			bzero(outbuf, BUF_LEN);
			iud->iuvd_ifo2[35] = '\0';
			(void) ud_convert2local(
					(int8_t *)iud->iuvd_ifo2,
					(int8_t *)outbuf,
					strlen(iud->iuvd_ifo2));
			(void) fprintf(stdout,
				gettext("LVInfo2 in  %s : %s\n"),
					name, outbuf);

			bzero(outbuf, BUF_LEN);
			iud->iuvd_ifo3[35] = '\0';
			(void) ud_convert2local(
					(int8_t *)iud->iuvd_ifo3,
					(int8_t *)outbuf,
					strlen(iud->iuvd_ifo3));
			(void) fprintf(stdout,
				gettext("LVInfo3 in  %s : %s\n"),
					name, outbuf);
		}
	}
}

/* ARGSUSED */
static void
label_vds(struct vds *v, uint32_t set_flags, int32_t fd)
{

	if (((set_flags & (SET_FSNAME | SET_VOLNAME)) ==
		(SET_FSNAME | SET_VOLNAME)) &&
		(v->pvd_len)) {

		off = v->pvd_loc * udfs.lbsize;
		if (ud_read_dev(fd, off, buf,
			sizeof (struct pri_vol_desc)) == 0) {

			struct pri_vol_desc *pvd;

			/* LINTED */
			pvd = (struct pri_vol_desc *)buf;
			bzero((int8_t *)&pvd->pvd_vsi[9], 119);
			(void) strncpy((int8_t *)&pvd->pvd_vsi[9],
					&fsname[1], fsname_len - 1);

			set_dstring(pvd->pvd_vol_id,
				volname, sizeof (pvd->pvd_vol_id));

			ud_make_tag(&pvd->pvd_tag,
				SWAP_16(pvd->pvd_tag.tag_id),
				SWAP_32(pvd->pvd_tag.tag_loc),
				SWAP_16(pvd->pvd_tag.tag_crc_len));

			(void) ud_write_dev(fd, off, buf,
				sizeof (struct pri_vol_desc));
		}
	}

	if (set_flags && v->iud_len) {

		off = v->iud_loc * udfs.lbsize;
		if (ud_read_dev(fd, off, buf,
			sizeof (struct iuvd_desc)) == 0) {

			struct iuvd_desc *iuvd;

			/* LINTED */
			iuvd = (struct iuvd_desc *)buf;

			if ((set_flags & SET_VOLNAME) == SET_VOLNAME) {
				set_dstring(iuvd->iuvd_lvi,
					volname, sizeof (iuvd->iuvd_lvi));
			}
			if ((set_flags & SET_LVINFO1) == SET_LVINFO1) {
				set_dstring(iuvd->iuvd_ifo1,
					lvinfo1_buf, sizeof (iuvd->iuvd_ifo1));
			}
			if ((set_flags & SET_LVINFO2) == SET_LVINFO2) {
				set_dstring(iuvd->iuvd_ifo2,
					lvinfo2_buf, sizeof (iuvd->iuvd_ifo2));
			}
			if ((set_flags & SET_LVINFO3) == SET_LVINFO3) {
				set_dstring(iuvd->iuvd_ifo3,
					lvinfo3_buf, sizeof (iuvd->iuvd_ifo3));
			}

			ud_make_tag(&iuvd->iuvd_tag,
				SWAP_16(iuvd->iuvd_tag.tag_id),
				SWAP_32(iuvd->iuvd_tag.tag_loc),
				SWAP_16(iuvd->iuvd_tag.tag_crc_len));

			(void) ud_write_dev(fd, off, buf,
				sizeof (struct iuvd_desc));
		}
	}

	if (((set_flags & (SET_FSNAME | SET_VOLNAME)) ==
		(SET_FSNAME | SET_VOLNAME)) &&
		(v->lvd_len)) {

		off = v->lvd_loc * udfs.lbsize;
		if (ud_read_dev(fd, off, buf,
			sizeof (struct log_vol_desc)) == 0) {

			struct log_vol_desc *lvd;

			/* LINTED */
			lvd = (struct log_vol_desc *)buf;
			set_dstring(lvd->lvd_lvid,
				volname, sizeof (lvd->lvd_lvid));

			ud_make_tag(&lvd->lvd_tag,
				SWAP_16(lvd->lvd_tag.tag_id),
				SWAP_32(lvd->lvd_tag.tag_loc),
				SWAP_16(lvd->lvd_tag.tag_crc_len));

			(void) ud_write_dev(fd, off, buf,
				sizeof (struct log_vol_desc));
		}
	}
}


int32_t
convert_string(int8_t *value, int8_t *out_buf, int32_t out_len,
	int32_t len, int8_t *error_string)
{
	int32_t		out_length = 0;

	out_length = ud_convert2unicode(value, out_buf, out_len);
	if (out_length > len - 1) {
		(void) fprintf(stderr, "%s", error_string);
		exit(1);
	}

	return (out_length);
}

static int32_t
ud_convert2unicode(int8_t *mb, int8_t *comp, int32_t out_len)
{
	wchar_t		buf4c[128];
	int32_t		len = 0;
	int32_t		i = 0;
	int32_t		j = 0;
	uint8_t		c = 8;

	len = mbstowcs(buf4c, mb, 127);
	buf4c[127] = '\0';

	for (i = 0; i < len; i++) {
		if (buf4c[i] & 0xFFFFFF00) {
			c = 16;
			break;
		}
	}

	comp[0] = c;
	j = 1;
	for (i = 0; i < len && i < out_len; i++) {
		if (c == 16) {
			comp[j] = (buf4c[i] & 0xFF00) >> 8;
		}
		comp[j++] = buf4c[i] & 0xFF;
	}

	return (j);
}
