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
 * Miscellaneous support subroutines for High Sierra filesystem
 *
 * Copyright (c) 1990,2000,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/seg_map.h>
#include <sys/swap.h>
#include <vm/seg_kmem.h>

#include <sys/fs/hsfs_spec.h>
#include <sys/fs/hsfs_node.h>
#include <sys/fs/hsfs_impl.h>

#define	THE_EPOCH	1970
#define	END_OF_TIME	2099

#ifdef __STDC__
static time_t hs_date_to_gmtime(int year, int mon, int day, int gmtoff);
#else
static time_t hs_date_to_gmtime();
#endif

/*
 * Table used in logging non-fatal errors which should be recorded
 * once per mount.  Indexed by HSFS_ERR values (defined in hsfs_node.h).
 */
struct hsfs_error {
	char	*hdr_text;	/* msg prefix: general error type */
				/* must contain %s for mnt pt */
	char 	*err_text;	/* specific error message */
	uchar_t	multiple;	/* > 1 such error per fs possible? */
	uchar_t	n_printf_args;	/* if err_text printf-like, # addtl args */
} hsfs_error[] = {
	/* HSFS_ERR_TRAILING_JUNK */
	"hsfs: Warning: the file system mounted on %s\n"
		"does not conform to the ISO-9660 specification:",
	" trailing blanks or null characters in file or directory name.\n",
	1, 0,
	/* HSFS_ERR_LOWER_CASE_NM */
	"hsfs: Warning: the file system mounted on %s\n"
		"does not conform to the ISO-9660 specification: ",
	" lower case characters in file or directory name.\n",
	1, 0,
	/* HSFS_ERR_BAD_ROOT_DIR */
	"hsfs: Warning: the file system mounted on %s\n"
		"does not conform to the ISO-9660 specification:",
	" invalid root directory.\n",
	0,  0,
	/* HSFS_ERR_UNSUP_TYPE */
	"hsfs: Warning: the file system mounted on %s\n"
		"contains a file or directory with an unsupported type:",
	" 0x%x.\n",
	1, 1,
	/* HSFS_ERR_BAD_FILE_LEN */
	"hsfs: Warning: file system mounted on %s \n"
		"does not conform to the ISO-9660 specification:",
	"file len greater than max allowed\n",
	1, 0,
};



/*
 * hs_parse_dirdate
 *
 * Parse the short 'directory-format' date into a Unix timeval.
 * This is the date format used in Directory Entries.
 *
 * If the date is not representable, make something up.
 */
void
hs_parse_dirdate(dp, tvp)
	uchar_t *dp;
	struct timeval *tvp;
{
	int year, month, day, hour, minute, sec, gmtoff;

	year = HDE_DATE_YEAR(dp);
	month = HDE_DATE_MONTH(dp);
	day = HDE_DATE_DAY(dp);
	hour = HDE_DATE_HOUR(dp);
	minute = HDE_DATE_MIN(dp);
	sec = HDE_DATE_SEC(dp);
	gmtoff = HDE_DATE_GMTOFF(dp);

	tvp->tv_usec = 0;
	if (year < THE_EPOCH) {
		tvp->tv_sec = 0;
	} else {
		tvp->tv_sec = hs_date_to_gmtime(year, month, day, gmtoff);
		if (tvp->tv_sec != -1) {
			tvp->tv_sec += ((hour * 60) + minute) * 60 + sec;
		}
	}

	return;

}

/*
 * hs_parse_longdate
 *
 * Parse the long 'user-oriented' date into a Unix timeval.
 * This is the date format used in the Volume Descriptor.
 *
 * If the date is not representable, make something up.
 */
void
hs_parse_longdate(dp, tvp)
	uchar_t *dp;
	struct timeval *tvp;
{
	int year, month, day, hour, minute, sec, gmtoff;

	year = HSV_DATE_YEAR(dp);
	month = HSV_DATE_MONTH(dp);
	day = HSV_DATE_DAY(dp);
	hour = HSV_DATE_HOUR(dp);
	minute = HSV_DATE_MIN(dp);
	sec = HSV_DATE_SEC(dp);
	gmtoff = HSV_DATE_GMTOFF(dp);

	tvp->tv_usec = 0;
	if (year < THE_EPOCH) {
		tvp->tv_sec = 0;
	} else {
		tvp->tv_sec = hs_date_to_gmtime(year, month, day, gmtoff);
		if (tvp->tv_sec != -1) {
			tvp->tv_sec += ((hour * 60) + minute) * 60 + sec;
			tvp->tv_usec = HSV_DATE_HSEC(dp) * 10000;
		}
	}

}

/* cumulative number of seconds per month,  non-leap and leap-year versions */
static time_t cum_sec[] = {
	0x0, 0x28de80, 0x4dc880, 0x76a700, 0x9e3400, 0xc71280,
	0xee9f80, 0x1177e00, 0x1405c80, 0x167e980, 0x190c800, 0x1b85500
};
static time_t cum_sec_leap[] = {
	0x0, 0x28de80, 0x4f1a00, 0x77f880, 0x9f8580, 0xc86400,
	0xeff100, 0x118cf80, 0x141ae00, 0x1693b00, 0x1921980, 0x1b9a680
};
#define	SEC_PER_DAY	0x15180
#define	SEC_PER_YEAR	0x1e13380

/*
 * hs_date_to_gmtime
 *
 * Convert year(1970-2099)/month(1-12)/day(1-31) to seconds-since-1970/1/1.
 *
 * Returns -1 if the date is out of range.
 */
static time_t
hs_date_to_gmtime(year, mon, day, gmtoff)
	int year;
	int mon;
	int day;
	int gmtoff;
{
	time_t sum;
	time_t *cp;
	int y;

	if ((year < THE_EPOCH) || (year > END_OF_TIME) ||
	    (mon < 1) || (mon > 12) ||
	    (day < 1) || (day > 31))
		return (-1);

	/*
	 * Figure seconds until this year and correct for leap years.
	 * Note: 2000 is a leap year but not 2100.
	 */
	y = year - THE_EPOCH;
	sum = y * SEC_PER_YEAR;
	sum += ((y + 1) / 4) * SEC_PER_DAY;
	/*
	 * Point to the correct table for this year and
	 * add in seconds until this month.
	 */
	cp = ((y + 2) % 4) ? cum_sec : cum_sec_leap;
	sum += cp[mon - 1];
	/*
	 * Add in seconds until 0:00 of this day.
	 * (days-per-month validation is not done here)
	 */
	sum += (day - 1) * SEC_PER_DAY;
	sum -= (gmtoff * 15 * 60);
	return (sum);
}

/*
 * Indicate whether the directory is valid.
 */

int
hsfs_valid_dir(hd)
	struct hs_direntry *hd;
{
	/*
	 * check to see if this directory is not marked as a directory.
	 * check to see if data length is zero.
	 */

	if (hd->ext_size == 0)
		return (0);

	if (hd->type != VDIR)
		return (0);

	return (1);
}



/*
 * If we haven't complained about this error type yet, do.
 */
void
hs_log_bogus_disk_warning(fsp, errtype, data)
	struct hsfs	*fsp;
	int 		errtype;
	uint_t		data;
{

	if (fsp->hsfs_err_flags & (1 << errtype))
		return;		/* already complained */

	cmn_err(CE_NOTE, hsfs_error[errtype].hdr_text,
		fsp->hsfs_fsmnt);

	switch (hsfs_error[errtype].n_printf_args) {
	case 0:
		cmn_err(CE_CONT, hsfs_error[errtype].err_text);
		break;
	case 1:
		cmn_err(CE_CONT, hsfs_error[errtype].err_text, data);
		break;
	default:
		/* don't currently handle more than 1 arg */
		cmn_err(CE_CONT, "unknown problem; internal error.\n");
	}
	cmn_err(CE_CONT,
"Due to this error, the file system may not be correctly interpreted.\n");
	if (hsfs_error[errtype].multiple)
		cmn_err(CE_CONT,
"Other such errors in this file system will be silently ignored.\n\n");
	else
		cmn_err(CE_CONT, "\n");

	fsp->hsfs_err_flags |= (1 << errtype);
}
