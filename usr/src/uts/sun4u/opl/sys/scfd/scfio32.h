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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

#ifndef _SCFIO32_H
#define	_SCFIO32_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types32.h>

/* SCFIOCWRLCD 32bit */
typedef struct scfwrlcd32 {
	int		lcd_type;
	int		length;
	caddr32_t	string;
} scfwrlcd32_t;


/* SCFIOCGETREPORT 32bit */
typedef struct scfreport32 {
	int		flag;
	unsigned int	rci_addr;
	unsigned char	report_sense[4];
	time32_t	timestamp;
} scfreport32_t;


/* SCFIOCGETEVENT 32bit */
typedef struct scfevent32 {
	int		flag;
	unsigned int	rci_addr;
	unsigned char	code;
	unsigned char	size;
	unsigned char	rsv[2];
	unsigned char	event_sense[24];
	time32_t	timestamp;
} scfevent32_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SCFIO32_H */
