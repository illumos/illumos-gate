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

#ifndef	_BOOTINFO_AUX_H
#define	_BOOTINFO_AUX_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The interfaces defined here are used by bootinfo.c. However, their
 * implementations in userland and standalone are quite different.
 * Therefore, their implementations can be found one of two places:
 *
 * usr/src/stand/lib/wanboot/bootinfo_aux.c
 * usr/src/lib/wanboot/common/bootinfo_aux.c
 */
extern boolean_t bi_init_bootinfo(void);
extern void bi_end_bootinfo(void);
extern boolean_t bi_get_chosen_prop(const char *, void *, size_t *);
extern boolean_t bi_get_dhcp_info(uchar_t, uint16_t, uint16_t,
    void *, size_t *);
#if	defined(_BOOT)
extern boolean_t bi_put_chosen_prop(const char *, const void *, size_t,
    boolean_t);
#else
extern boolean_t bi_put_bootmisc(const char *, const void *, size_t);
#endif	/* defined(_BOOT) */

#ifdef	__cplusplus
}
#endif

#endif	/* _BOOTINFO_AUX_H */
