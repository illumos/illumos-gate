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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FWFLASH_H
#define	_FWFLASH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * fwflash.h
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "fwflash_ib.h"

/*
 * Debugging output level:
 *	DBG_NONE - no output
 *	DBG_INFO - informative debugging
 *		   output
 *	DBG_ERR - error output
 */
#define	DBG_NONE		0x00
#define	DBG_INFO		0x01
#define	DBG_ERR			0x02

/*
 * XXX Let's define DEBUG for now.  We can patch this binary if we need to,
 * changing 'fwflash_debug' in the field, if we really need to debug things.
 * By defining DEBUG, this enables us to do that on the fly.  May change later.
 */
#define	DEBUG
#ifdef	DEBUG
static int fwflash_debug = DBG_NONE;
/* static int fwflash_debug = DBG_INFO | DBG_ERR; */
#define	DPRINTF(DBG_LEVEL, ARGLIST) \
	if (DBG_LEVEL & fwflash_debug) (void) printf ARGLIST;
#else
#define	DPRINTF(DBG_LEVEL, ARGLIST)
#endif /* DEBUG */

#define	FWFLASH_SUCCESS		0
#define	FWFLASH_FAILURE		1

#define	FWFLASH_FLASH_IMAGES	2
#define	FWFLASH_VERSION		"1.2"
#define	FWFLASH_PGM_NAME	"fwflash"

typedef	struct fwflash_device_info_s {
	char			**device_list;
	int			*device_class;
} fwflash_device_info_t;

typedef struct fwflash_state_s {
	fwflash_ib_hdl_t	*ibhdl;
	fwflash_device_info_t	*devices;
	int			count;
	char			*filename;
	char			*device_name;
	int			device_class;
} fwflash_state_t;

/* Flags for argument parsing */
#define	FWFLASH_HELP_FLAG	0x01
#define	FWFLASH_VER_FLAG	0x02
#define	FWFLASH_YES_FLAG	0x04
#define	FWFLASH_LIST_FLAG	0x08
#define	FWFLASH_CLASS_FLAG	0x10
#define	FWFLASH_DEVICE_FLAG	0x20
#define	FWFLASH_FW_FLAG		0x40
#define	FWFLASH_READ_FLAG	0x80

#ifdef __cplusplus
}
#endif

#endif /* _FWFLASH_H */
