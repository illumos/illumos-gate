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

#ifndef _II_STATS_H
#define	_II_STATS_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	GOT_SETSTAT	0x01
#define	GOT_MSTSTAT	0x02
#define	GOT_SHDSTAT	0x04
#define	GOT_BMPSTAT	0x08
#define	GOT_OVRSTAT	0x10

#define	GOT_COMPLETE_IIMG (GOT_SETSTAT|GOT_MSTSTAT|GOT_SHDSTAT|GOT_BMPSTAT)

#define	IIMG_COMPLETE(x) (((x) & (GOT_COMPLETE_IIMG)) != (GOT_COMPLETE_IIMG))

/* II strings */
#define	II_KSTAT_MODULE	"ii"
#define	II_KSTAT_CLASS	"iiset"

#define	II_DISABLED	"<<set disabled>>"
#define	II_INDEPENDENT	"I"
#define	II_DEPENDENT	"D"
#define	II_COPYING	"C"
#define	II_MASTER	"mst"
#define	II_SHADOW	"shd"
#define	II_BITMAP	"bmp"
#define	II_OVERFLOW	"ovr"


typedef struct iistat_s
{
	kstat_t *pre_set;
	kstat_t *pre_mst;
	kstat_t *pre_shd;
	kstat_t *pre_bmp;
	kstat_t *pre_ovr;
	kstat_t *cur_set;
	kstat_t *cur_mst;
	kstat_t *cur_shd;
	kstat_t *cur_bmp;
	kstat_t *cur_ovr;
	int collected;
	struct iistat_s *next;
} iistat_t;

/* Prototypes */
int ii_discover(kstat_ctl_t *);
int ii_update(kstat_ctl_t *);
int ii_report();

#ifdef	__cplusplus
}
#endif

#endif /* _II_STATS_H */
