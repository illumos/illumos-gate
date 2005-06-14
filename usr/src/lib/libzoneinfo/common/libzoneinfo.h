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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBZONEINFO_H
#define	_LIBZONEINFO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * WARNING:
 *
 * The interfaces defined in this header file are for Sun private use only.
 * The contents of this file are subject to change without notice for the
 * future releases.
 */

/*
 * Declarations for the functions in libzoneinfo
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	_TZBUFLEN	128		/* timezone name buffer length */
#define	_CCBUFLEN	32		/* country code buffer length */

#define	_GMT_MAX	(12*60*60)	/* The maximum GMT offset */
#define	_GMT_MIN	(-13*60*60)	/* The minimum GMT offset */

#define	_VTZ_INSTALL	0		/* zoneinfo or POSIX offset-from-GMT */
#define	_VTZ_ALL	1		/* zoneinfo or POSIX */
#define	_VTZ_POSIX	2		/* POSIX timezone */
#define	_VTZ_ZONEINFO	3		/* zoneinfo timezone */

struct tz_timezone {
	char tz_name[_TZBUFLEN];	/* timezone name */
	char tz_oname[_TZBUFLEN];
	char *tz_id_desc;		/* timezone description */
	char *tz_display_desc;		/* l10n timezone description */
	struct tz_coord {		/* coordinates */
		int lat_sign;
		unsigned int lat_degree;
		unsigned int lat_minute;
		unsigned int lat_second;
		int long_sign;
		unsigned int long_degree;
		unsigned int long_minute;
		unsigned int long_second;
	} tz_coord;
	struct tz_timezone *tz_next;	/* pointer to next element */
	void *tz_reserved;		/* reserved */
};

struct tz_continent {
	char ctnt_name[_TZBUFLEN];	/* continent name */
	char *ctnt_id_desc;		/* continent name (descriptive) */
	char *ctnt_display_desc;	/* localized continent name */
	struct tz_continent *ctnt_next;	/* pointer to next element */
	void *ctnt_reserved;		/* reserved */
};

struct tz_country {
	char ctry_code[_CCBUFLEN];	/* country code */
	char *ctry_id_desc;		/* country name (descriptive) */
	char *ctry_display_desc;	/* localized country name */
	int  ctry_status;		/* private use */
	struct tz_country *ctry_next;	/* pointer to next element */
	void *ctry_reserved;		/* reserved */
};

extern int get_tz_continents(struct tz_continent **);
extern int get_tz_countries(struct tz_country **, struct tz_continent *);
extern int get_timezones_by_country(struct tz_timezone **, struct tz_country *);
extern int free_tz_continents(struct tz_continent *);
extern int free_tz_countries(struct tz_country *);
extern int free_timezones(struct tz_timezone *);
extern char *conv_gmt(int, int);
extern char *get_system_tz(char *);
extern int set_system_tz(char *, char *);
extern int isvalid_tz(char *, char *, int);

#ifdef	__cplusplus
}
#endif

#endif /* _LIBZONEINFO_H */
