/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DSSTAT_H
#define	_DSSTAT_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct vslist_s
{
	char *volname;
	char *volhost;
	struct vslist_s *next;
} vslist_t;

extern int mode;
extern int interval;
extern int iterations;
extern int zflag;
extern int linesout;
extern short hflags;
extern short dflags;
extern short rflags;
extern vslist_t *vs_top;

/* kstat named character limit */
#define	NAMED_LEN	15

/* Mode */
#define	MULTI	0x01
#define	SNDR	0x02
#define	IIMG	0x04
#define	SDBC	0x08

/* Error codes */
#define	DSSTAT_SUCCESS	0	/* Success */
#define	DSSTAT_NOSTAT	1	/* No Statistics Avaiable */
#define	DSSTAT_EINVAL	2	/* Invalid Argument */
#define	DSSTAT_ENOMEM	3	/* No Memory Available To Get Statistics */
#define	DSSTAT_EUNKNWN	4	/* Unknown Error */
#define	DSSTAT_EMAP	5	/* Mapped kstat memory is invalid */

/* Report flags */
#define	IIMG_MST	0x01
#define	IIMG_SHD	0x02
#define	IIMG_BMP	0x04
#define	IIMG_OVR	0x08

#define	SNDR_PRI	0x10
#define	SNDR_NET	0x20
#define	SNDR_BMP	0x40

/* Display flags */
#define	SUMMARY		0x01
#define	READ		0x02
#define	WRITE		0x04
#define	TIMING		0x08
#define	FLAGS		0x10
#define	PCTS		0x20
#define	DESTAGED	0x40
#define	WRCANCEL	0x80
#define	RATIO		0x100
#define	ASYNC_QUEUE	0x200

/* Flag masks */
#define	SNDR_REP_MASK	(SNDR_PRI | SNDR_NET | SNDR_BMP)
#define	SNDR_DIS_MASK	(SUMMARY | READ | WRITE | TIMING | FLAGS | PCTS | \
    RATIO | ASYNC_QUEUE)

#define	IIMG_REP_MASK	(IIMG_MST | IIMG_SHD | IIMG_BMP | IIMG_OVR)
#define	IIMG_DIS_MASK	(SUMMARY | READ | WRITE | TIMING | FLAGS | PCTS | RATIO)

#define	CACHE_REP_MASK	0
#define	CACHE_DIS_MASK	(SUMMARY | READ | WRITE | FLAGS | DESTAGED | WRCANCEL)

/* Field header defines */
#define	DISPLAY_LINES	19
#define	HEADERS_OUT	0x01	/* flag to show headers output for cycle */
#define	HEADERS_BOR	0x02	/* field headers at beginning of run */
#define	HEADERS_ATT	0x04	/* field headers all the time */
#define	HEADERS_EXL	0x08	/* field headers every X lines */

#ifdef	__cplusplus
}
#endif

#endif	/* _DSSTAT_H */
