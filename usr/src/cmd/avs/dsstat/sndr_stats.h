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

#ifndef _SNDR_STATS_H
#define	_SNDR_STATS_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	GOT_SET_KSTAT	0x01
#define	GOT_BMP_KSTAT	0x02
#define	GOT_SEC_KSTAT	0x04

#define	GOT_COMPLETE_SNDR (GOT_SET_KSTAT|GOT_BMP_KSTAT|GOT_SEC_KSTAT)

#define	SNDR_COMPLETE(x) (((x) & (GOT_COMPLETE_SNDR)) != (GOT_COMPLETE_SNDR))

/* SNDR strings */
#define	RDC_KSTAT_RDCNAME	"sndr"
#define	RDC_KSTAT_BMPNAME	"sndrbmp"

#define	RDC_DISABLED		"<<set disabled>>"
#define	RDC_SECONDARY		"net"
#define	RDC_BITMAP		"bmp"

typedef struct sndrstat_s
{
	kstat_t *pre_set;
	kstat_t *pre_bmp;
	kstat_t *pre_sec;
	kstat_t *cur_set;
	kstat_t *cur_bmp;
	kstat_t *cur_sec;
	int collected;
	struct sndrstat_s *next;
} sndrstat_t;

/* Prototypes */
int sndr_discover(kstat_ctl_t *);
int sndr_update(kstat_ctl_t *);
int sndr_report();

#ifdef	__cplusplus
}
#endif

#endif /* _SNDR_STATS_H */
