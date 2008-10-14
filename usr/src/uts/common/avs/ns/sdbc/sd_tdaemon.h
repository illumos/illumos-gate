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

#ifndef _SD_TDAEMON_H
#define	_SD_TDAEMON_H

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_SD_DEBUG)
extern int _test_async_fail;
#endif

extern int _sdbc_tdaemon_load(void);
extern void _sdbc_tdaemon_unload(void);
extern int _sdbc_tdaemon_configure(int num);
extern void _sdbc_tdaemon_deconfigure(void);
extern int _sd_test_start(void *args, int *rvp);
extern int _sd_test_end(void);
extern int _sd_test_init(void *args);

#ifdef	__cplusplus
}
#endif

#endif /* _SD_TDAEMON_H */
