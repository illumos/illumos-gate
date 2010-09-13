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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PCA9556_IMPL_H
#define	_PCA9556_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/promif.h>

/*
 * Declarations for debug printing
 */
extern int pca9556_debug;

#define	PCA9556_NUM_PORTS	1
#define	PCA9555_NUM_PORTS	2
#define	PCA9556_NUM_REG		3
#define	PCA9556_MAX_REG		6

#define	PCA9556_BUSYFLAG	0x1
#define	PCA9556_MINORFLAG	0x2
#define	PCA9556_TBUFFLAG	0x4
#define	PCA9556_REGFLAG		0x8

#define	PCA9556_INPUT_REG	0x0
#define	PCA9556_OUTPUT_REG	0x1
#define	PCA9556_POLARITY_REG	0x2
#define	PCA9556_CONFIG_REG	0x3

#define	PCA9555_INPUT_REG	0x0
#define	PCA9555_OUTPUT_REG	0x2
#define	PCA9555_POLARITY_REG	0x4
#define	PCA9555_CONFIG_REG	0x6

#define	PCA9556_NODE_TYPE	"ddi_i2c:gpio_device"
#define	PCA9556_MAX_SIZE	8
#define	PCA9556_NAME_LEN	16

typedef struct pca9556_unit {
	dev_info_t		*pca9556_dip;
	i2c_transfer_t		*pca9556_transfer;
	kmutex_t		pca9556_mutex;
	kcondvar_t		pca9556_cv;
	uint8_t			pca9556_flags;
	i2c_client_hdl_t	pca9556_hdl;
	char			pca9556_name[PCA9556_NAME_LEN];
	uint16_t		pca9556_oflag;
	uint8_t			pca9556_cpr_state[PCA9556_MAX_REG];
	boolean_t		pca9555_device;
} pca9556_unit_t;

#ifdef	__cplusplus
}
#endif

#endif /* _PCA9556_IMPL_H */
