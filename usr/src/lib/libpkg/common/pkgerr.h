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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PKGERR_H
#define	_PKGERR_H


/*
 * Module:	pkgerr.h
 * Description:
 *
 *   Implements error routines to handle the creation,
 *   management, and destruction of error objects, which
 *   hold error messages and codes returned from libpkg
 *   routines that support the objects defined herein.
 */

#include <stdio.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Public Definitions
 */

typedef enum {
	PKGERR_OK = 0,
	PKGERR_EXIST,
	PKGERR_READ,
	PKGERR_CORRUPT,
	PKGERR_PARSE,
	PKGERR_BADPASS,
	PKGERR_BADALIAS,
	PKGERR_INTERNAL,
	PKGERR_UNSUP,
	PKGERR_NOALIAS,
	PKGERR_NOALIASMATCH,
	PKGERR_MULTIPLE,
	PKGERR_INCOMPLETE,
	PKGERR_NOPRIVKEY,
	PKGERR_NOPUBKEY,
	PKGERR_NOCACERT,
	PKGERR_NOMEM,
	PKGERR_CHAIN,
	PKGERR_LOCKED,
	PKGERR_WRITE,
	PKGERR_UNLOCK,
	PKGERR_TIME,
	PKGERR_DUPLICATE,
	PKGERR_WEB,
	PKGERR_VERIFY
} PKG_ERR_CODE;

/*
 * Public Structures
 */

/* external reference to PKG_ERR object (contents private) */
typedef PKG_ERR_CODE pkg_err_t;

typedef struct _pkg_err_struct PKG_ERR;

/*
 * Public Methods
 */

PKG_ERR		*pkgerr_new();
void		pkgerr_add(PKG_ERR *, PKG_ERR_CODE, char *, ...);
void		pkgerr_clear(PKG_ERR *);
int		pkgerr_dump(PKG_ERR *, FILE *);
int		pkgerr_num(PKG_ERR *);
char		*pkgerr_get(PKG_ERR *, int);
void		pkgerr_free(PKG_ERR *);

#ifdef	__cplusplus
}
#endif

#endif /* _PKGERR_H */
