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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_UTIL_H
#define	_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include "device.h"
#include "trackio.h"
#include "bstream.h"

#define	EXIT_IF_CHECK_FAILED		0x80000000
#define	BUFSIZE				32
/*
 * Condition to be checked for a device
 */
#define	CHECK_TYPE_NOT_CDROM		1
#define	CHECK_DEVICE_NOT_READY		2
#define	CHECK_DEVICE_NOT_WRITABLE	4
#define	CHECK_NO_MEDIA			8
#define	CHECK_MEDIA_IS_NOT_WRITABLE	0x10
#define	CHECK_MEDIA_IS_NOT_BLANK	0x20
#define	CHECK_MEDIA_IS_NOT_ERASABLE	0x40

/*
 * audio types
 */
#define	AUDIO_TYPE_NONE	0
#define	AUDIO_TYPE_SUN	1
#define	AUDIO_TYPE_WAV	2
#define	AUDIO_TYPE_CDA	3
#define	AUDIO_TYPE_AUR	4

extern int progress_pos;
extern int priv_change_needed;

void *my_zalloc(size_t size);
int str_print(char *str, int pos);
void print_trackio_error(struct trackio_error *te);
char *get_err_str(void);
int get_audio_type(char *ext);
void init_progress(void);
int progress(int64_t arg, int64_t completed);
void raise_priv(void);
void lower_priv(void);
int check_auth(uid_t uid);
void ms_delay(uint_t ms);

#ifdef	__cplusplus
}
#endif

#endif /* _UTIL_H */
