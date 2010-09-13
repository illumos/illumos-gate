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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * f_format.c :
 *      This file contains the format functions for floppy plug-in for
 * 	library libsm.so.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/dklabel.h>
#include <sys/dkio.h>
#include <sys/fdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <locale.h>
#include <errno.h>
#include <sys/param.h>
#include <stdlib.h>
#include <sys/smedia.h>
#include "../../../library/inc/rmedia.h"
#include "f_defines.h"

/*
 * extern functions
 */

extern void my_perror(char *err_string);
/*
 * local functions
 */
static void	restore_default_chars(int32_t fd,
				    struct fd_char save_fdchar,
				    struct dk_allmap save_allmap);
static int32_t
format_floppy(int32_t fd, void *ip)
{
	struct	format_track *ft = (struct format_track *)ip;
	int32_t format_flags;
	int32_t	transfer_rate = 1000;   /* transfer rate code */
	int32_t	sec_size = 512;		/* sector size */
	uchar_t	gap = 0x54;		/* format gap size */
	uchar_t  *fbuf, *p;
	int32_t	cyl_size;
	int32_t	i;
	int32_t	chgd;			/* for testing disk changed/present */
	int32_t	cyl, hd;
	int32_t	size_of_part, size_of_dev;
	int32_t	spt = 36;		/* sectors per track */
	int32_t	drive_size;
	uchar_t	num_cyl = 80;		/*  max number of cylinders */
	struct fd_char save_fdchar;	/* original diskette characteristics */
	struct dk_allmap save_allmap;	/* original diskette partition info */
	int32_t	D_flag = 0;	/* double (aka low) density flag */
	int32_t	E_flag = 0;	/* extended density */
	int32_t	H_flag = 0;	/* high density */
	int32_t	M_flag = 0;	/* medium density */
	struct fd_char 		fdchar;
	struct dk_geom 		fdgeom;
	struct dk_allmap 	allmap;
	struct dk_cinfo 	dkinfo;
	int32_t start_head, end_head, start_cyl, end_cyl;

	/* for verify buffers */
	static uchar_t	*obuf;


	/* FDRAW ioctl command structures for seeking and formatting */
	struct fd_raw fdr_seek = {
		FDRAW_SEEK, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		3,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0,
		0
	};

	struct fd_raw fdr_form = {
		0x4D, 0, 2, 0, 0x54, (char)0xA5, 0, 0, 0, 0,
		6,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0,	/* nbytes */
		0	/* addr */
	};

	format_flags = ft->flag;

	DPRINTF1("Format flag is %d\n", format_flags);
	if (format_flags == SM_FORMAT_HD) {
		H_flag = 1;
	} else if (format_flags == SM_FORMAT_DD) {
		D_flag = 1;
	} else if (format_flags == SM_FORMAT_ED) {
		E_flag = 1;
	} else if (format_flags == SM_FORMAT_MD) {
		M_flag = 1;
	} else {
		DPRINTF("Invalid operation \n");
		errno = ENOTSUP;
		return (-1);
	}


	/*
	 * restore drive to default geometry and characteristics
	 * (probably not implemented on sparc)
	 */
	(void) ioctl(fd, FDDEFGEOCHAR, NULL);


	if (ioctl(fd, DKIOCINFO, &dkinfo) < 0) {
		PERROR("DKIOCINFO failed.");
		exit(3);
	}


	/* get the default partititon maps */
	if (ioctl(fd, DKIOCGAPART, &allmap) < 0) {
		PERROR("DKIOCGAPART failed.");
		return (-1);
	}

	/* Save the original default partition maps */
	save_allmap = allmap;

	/* find out the characteristics of the default diskette */
	if (ioctl(fd, FDIOGCHAR, &fdchar) < 0) {
		PERROR("FDIOGCHAR failed.");
		return (-1);
	}

	/* Save the original characteristics of the default diskette */
	save_fdchar = fdchar;

	/*
	 * The user may only format the entire diskette.
	 * formatting partion a or b is not allowed
	 */
	size_of_part = allmap.dka_map[dkinfo.dki_partition].dkl_nblk
			* DEV_BSIZE;
	size_of_dev = fdchar.fdc_ncyl * fdchar.fdc_nhead
			* fdchar.fdc_secptrack * fdchar.fdc_sec_size;

	if (size_of_part != size_of_dev) {
		DPRINTF("The entire diskette must be formatted\n");
		DPRINTF1("size_of_part %d\n", size_of_part);
		DPRINTF1("size_of_dev %d\n", size_of_dev);
		errno = ENOTSUP;
		return (-1);
	}

	/* find out the geometry of the drive */
	if (ioctl(fd, DKIOCGGEOM, &fdgeom) < 0) {
		PERROR("DKIOCGGEOM failed.");
		return (-1);
	}

#ifdef sparc
	fdchar.fdc_medium = 3;
#endif
	if (fdchar.fdc_medium == 5)
		drive_size = 5;
	else
		drive_size = 3;

	/*
	 * set proper density flag in case we're formating to default
	 * characteristics because no density switch was input
	 */

/* XXX */
	if ((E_flag | H_flag | D_flag | M_flag) == 0) {
		switch (fdchar.fdc_transfer_rate) {
		case 1000:
			/* assumes only ED uses 1.0 MB/sec */
			E_flag++;
			break;
		case 500:
		default:
			/*
			 * default to HD even though High density and
			 * "medium" density both use 500 KB/sec
			 */
			H_flag++;
			break;
#ifndef sparc
		case 250:
			/* assumes only DD uses 250 KB/sec */
			D_flag++;
			break;
#endif
		}
	}

	if (H_flag) {
		transfer_rate = 500;
		num_cyl = 80;
		sec_size = 512;
		if (drive_size == 5) {
			spt = 15;
		} else {
			spt = 18;
		}
		gap = 0x54;
	} else if (D_flag) {
		transfer_rate = 250;
		if (drive_size == 5) {
			if (fdchar.fdc_transfer_rate == 500) {
				/*
				 * formatting a 360KB DD diskette in
				 * a 1.2MB drive is not a good idea
				 */
				transfer_rate = 300;
				fdchar.fdc_steps = 2;
			}
			num_cyl = 40;
			gap = 0x50;
		} else {
			num_cyl = 80;
			gap = 0x54;
		}
		sec_size = 512;
		spt = 9;
	} else if (M_flag) {
#ifdef sparc
		transfer_rate = 500;
#else
		/*
		 * 416.67 KB/sec is the effective transfer rate of a "medium"
		 * density diskette spun at 300 rpm instead of 360 rpm
		 */
		transfer_rate = 417;
#endif
		num_cyl = 77;
		sec_size = 1024;
		spt = 8;
		gap = 0x74;
	} else if (E_flag) {
		transfer_rate = 1000;
		num_cyl = 80;
		sec_size = 512;
		spt = 36;
		gap = 0x54;
	}

	/*
	 * Medium density diskettes have 1024 byte blocks.  The dk_map
	 * structure in dklabel.h assumes the blocks size is DEVBSIZE (512)
	 * bytes.  The dkl_nblk field is in terms of DEVBSIZE byte blocks
	 * while the spt variable is in terms of the true block size on
	 * the diskette.
	 */
	if (allmap.dka_map[2].dkl_nblk !=
		(2 * num_cyl * spt * (M_flag ? 2 : 1))) {
		allmap.dka_map[1].dkl_cylno = num_cyl - 1;
		allmap.dka_map[0].dkl_nblk = 2 * (num_cyl - 1) * spt *
			(M_flag ? 2 : 1);
		allmap.dka_map[1].dkl_nblk = 2 * spt * (M_flag ? 2 : 1);
		allmap.dka_map[2].dkl_nblk = 2 * num_cyl * spt *
			(M_flag ? 2 : 1);
		if (allmap.dka_map[3].dkl_nblk)
			allmap.dka_map[3].dkl_nblk = 2 * (num_cyl - 1) * spt *
				(M_flag ? 2 : 1);
		if (allmap.dka_map[4].dkl_nblk)
			allmap.dka_map[4].dkl_nblk =
				2 * spt * (M_flag ? 2 : 1);
	}



#ifndef sparc
	if (num_cyl > fdchar.fdc_ncyl || spt > fdchar.fdc_secptrack ||
	    transfer_rate > fdchar.fdc_transfer_rate) {
		PERROR("drive not capable of requested density");
		return (-1);
	}
#endif
	if (num_cyl != fdchar.fdc_ncyl || spt != fdchar.fdc_secptrack ||
	    transfer_rate != fdchar.fdc_transfer_rate) {
		/*
		 * -- CAUTION --
		 * The SPARC fd driver is using a non-zero value in
		 * fdc_medium to indicate the 360 rpm, 77 track,
		 * 9 sectors/track, 1024 bytes/sector mode of operation
		 * (similar to an 8", DS/DD, 1.2 MB floppy).
		 *
		 * The x86 fd driver uses fdc_medium as the diameter
		 * indicator, either 3 or 5.  It should not be modified.
		 */
#ifdef sparc
		fdchar.fdc_medium = M_flag ? 1 : 0;
#endif
		fdchar.fdc_transfer_rate = transfer_rate;
		fdchar.fdc_ncyl = num_cyl;
		fdchar.fdc_sec_size = sec_size;
		fdchar.fdc_secptrack = spt;

		if (ioctl(fd, FDIOSCHAR, &fdchar) < 0) {
			PERROR("FDIOSCHAR (density selection) failed");
			/* restore the default characteristics */
			restore_default_chars(fd, save_fdchar, save_allmap);
			return (-1);
		}
		if (ioctl(fd, DKIOCSAPART, &allmap) < 0) {
			PERROR("DKIOCSAPART failed");

			/* restore the default characteristics */
			restore_default_chars(fd, save_fdchar, save_allmap);
				return (-1);
		}
	}

	cyl_size = 2 * sec_size * spt;

	if ((obuf = (uchar_t *)malloc((size_t)cyl_size)) == 0) {
		PERROR("car't malloc verify buffer");
		/* restore the default characteristics */
		restore_default_chars(fd, save_fdchar, save_allmap);
		return (-1);
	}
	/*
	 * for those systems that support this ioctl, they will
	 * return whether or not a diskette is in the drive.
	 */
	if (ioctl(fd, FDGETCHANGE, &chgd) == 0) {
		if (chgd & FDGC_CURRENT) {
			(void) fprintf(stderr,
			    gettext("no diskette in drive \n"));

			/* restore the default characteristics */
			restore_default_chars(fd, save_fdchar, save_allmap);
			return (-1);
		}
		if (chgd & FDGC_CURWPROT) {
			(void) fprintf(stderr,
			    gettext("Media is write protected\n"));

			/* restore the default characteristics */
			restore_default_chars(fd, save_fdchar, save_allmap);
			return (-1);
		}
	}

	if ((fbuf = (uchar_t *)malloc((unsigned)(4 * spt))) == 0) {
		PERROR("Could not malloc format header buffer");
		restore_default_chars(fd, save_fdchar, save_allmap);
		return (-1);
	}
	/*
	 * do the format, a track at a time
	 */
	if (ft->track_no == -1) {
		start_cyl = 0;
		end_cyl	  = num_cyl;
		start_head =  0;
		end_head = fdchar.fdc_nhead;
	} else {
		start_cyl = ft->track_no;
		end_cyl = ft->track_no + 1;
		start_head = ft->head;
		end_head = ft->head + 1;
		if ((end_cyl > num_cyl) || (end_head > fdchar.fdc_nhead)) {
			errno = EINVAL;
			return (-1);
		}
	}

	for (cyl = start_cyl; cyl < (int32_t)end_cyl; cyl++) {
		/*
		 * This is not the optimal ioctl to format the floppy.
		 * The device driver should do do the work,
		 * instead of this program mucking with a lot
		 * of low-level, device-dependent code.
		 */
		fdr_seek.fdr_cmd[2] = cyl;
		if (ioctl(fd, FDRAW, &fdr_seek) < 0) {
			(void) fprintf(stderr,
			    gettext(" seek to cyl %d failed\n"),
			    cyl);

			/* restore the default characteristics */
			restore_default_chars(fd, save_fdchar, save_allmap);
			return (-1);
		}
		/*
		 * Assume that the fd driver has issued a SENSE_INT
		 * command to complete the seek operation.
		 */

		for (hd = start_head; hd < end_head; hd++) {
			p = (uchar_t *)fbuf;
			for (i = 1; i <= spt; i++) {
				*p++ = (uchar_t)cyl;
				*p++ = (uchar_t)hd;
				*p++ = (uchar_t)i; /* sector # */
				*p++ = (sec_size == 1024) ? 3 : 2;
			}
			/*
			 * ASSUME the fd driver is going to set drive-select
			 * bits in the second command byte
			 */
			fdr_form.fdr_cmd[1] = hd << 2;
			fdr_form.fdr_cmd[2] = (sec_size == 1024) ? 3 : 2;
			fdr_form.fdr_cmd[3] = spt;
			fdr_form.fdr_cmd[4] = gap;
			fdr_form.fdr_nbytes = 4 * spt;
			fdr_form.fdr_addr = (char *)fbuf;

			if (ioctl(fd, FDRAW, &fdr_form) < 0) {


				(void) fprintf(stderr,
					gettext(
					"format of cyl %d head %d failed\n"),
						cyl, hd);

				/* restore the default characteristics */
				restore_default_chars(fd, save_fdchar,
				    save_allmap);
				return (-1);
			}
			if (fdr_form.fdr_result[0] & 0xC0) {
				if (fdr_form.fdr_result[1] & 0x02) {
					(void) fprintf(stderr, gettext(
					/*CSTYLED*/
					"diskette is write protected\n"));

					/*
					 * restore the default
					 * characteristics
					 */
					restore_default_chars(fd, save_fdchar,
					    save_allmap);
					return (-1);
				}
				(void) fprintf(stderr,
					gettext(
					"format of cyl %d head %d failed\n"),
						cyl, hd);

				/* restore the default characteristics */
				restore_default_chars(fd, save_fdchar,
				    save_allmap);
				return (-1);
			}

		}

		/*
		 *  do a quick verify
		 */
		if (llseek(fd, cyl * cyl_size, 0) != cyl * cyl_size) {
			PERROR(" bad seek to format verify, ");
			/* restore the default characteristics */
			restore_default_chars(fd, save_fdchar,
			    save_allmap);
			return (-1);
		}
		if (fdchar.fdc_nhead == end_head) {
			if (read(fd, obuf, cyl_size) != cyl_size) {
				PERROR("Could not read format data");
				/* restore the default characteristics */
				restore_default_chars(fd, save_fdchar,
				    save_allmap);
				return (-1);
			}
		}
	}
	if (llseek(fd, (off_t)0, 0) != 0) {
		PERROR("seek to blk 0 failed");
		/* restore the default characteristics */
		restore_default_chars(fd, save_fdchar, save_allmap);
		return (-1);
	}
	return (0);
}


/*
 * Restore the default characteristics of the floppy diskette.
 * Fdformat changes the characteristics in the process of formatting.
 * If fdformat fails while in the process of doing the format, fdformat
 * should clean up after itself and reset the driver back to the original
 * state.
 */

static void
restore_default_chars(int32_t fd,
			struct fd_char save_fdchar,
			struct dk_allmap save_allmap)
{


	/*
	 * When this function is called, fdformat is failing anyways,
	 * so the errors are not processed.
	 */

	(void) ioctl(fd, FDIOSCHAR, &save_fdchar);

	(void) ioctl(fd, DKIOCSAPART, &save_allmap);

	/*
	 * Before looking at the diskette's characteristics, format_floppy()
	 * sets the x86 floppy driver to the default characteristics.
	 * restore drive to default geometry and
	 * characteristics.  This ioctl isn't implemented on
	 * sparc.
	 */
	(void) ioctl(fd, FDDEFGEOCHAR, NULL);

}

int32_t
_m_media_format(rmedia_handle_t *handle, void *ip) {
	struct format_track ft;

	/* Check for valid handle */
	if (handle == NULL) {
		DPRINTF("Null Handle\n");
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_signature != (int32_t)LIBSMEDIA_SIGNATURE) {
		DPRINTF("Invalid signature in handle.\n");
		DPRINTF2(
			"Signature expected=0x%x, found=0x%x\n",
				LIBSMEDIA_SIGNATURE, handle->sm_signature);
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_fd < 0) {
		DPRINTF("Invalid file handle.\n");
		errno = EINVAL;
		return (-1);
	}
	DPRINTF("Format floppy called \n");
	ft.track_no = (-1);
	ft.head = (-1);
	ft.flag = ((struct format_flags *)ip)->flavor;
	return (format_floppy(handle->sm_fd, &ft));

}

int32_t
_m_media_format_track(rmedia_handle_t *handle, void *ip)
{

	/* Check for valid handle */
	if (handle == NULL) {
		DPRINTF("Null Handle\n");
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_signature != (int32_t)LIBSMEDIA_SIGNATURE) {
		DPRINTF("Invalid signature in handle.\n");
		DPRINTF2(
			"Signature expected=0x%x, found=0x%x\n",
				LIBSMEDIA_SIGNATURE, handle->sm_signature);
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_fd < 0) {
		DPRINTF("Invalid file handle.\n");
		errno = EINVAL;
		return (-1);
	}
#ifdef DEBUG
	if (ip != NULL) {
		struct format_track *ft = (struct format_track *)ip;
		DPRINTF2("Format track %d head %d\n", ft->track_no, ft->head);
	}
#endif /* DEBUG */
	return (format_floppy(handle->sm_fd, ip));
}
