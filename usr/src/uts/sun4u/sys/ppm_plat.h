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

#ifndef _SYS_PPM_PLAT_H
#define	_SYS_PPM_PLAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/i2c/clients/i2c_gpio.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define	PPM_GET_IO_DELAY(dc, delay) { \
	if (dc->method == PPMDC_I2CKIO) \
		delay = dc->m_un.i2c.delay; \
	else if (dc->method == PPMDC_KIO) \
		delay = dc->m_un.kio.delay; \
}

#define	PPM_GET_IO_POST_DELAY(dc, delay) { \
	if (dc->method == PPMDC_I2CKIO) \
		delay = dc->m_un.i2c.post_delay; \
	else if (dc->method == PPMDC_KIO) \
		delay = dc->m_un.kio.post_delay; \
}

#ifdef  __cplusplus
}
#endif

#endif /* _SYS_PPM_PLAT_H */
