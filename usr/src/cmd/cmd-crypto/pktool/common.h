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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PKTOOL_COMMON_H
#define	_PKTOOL_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains data and functions shared between all the
 * modules that comprise this tool.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <cryptoutil.h>

/* I18N helpers. */
#include <libintl.h>
#include <locale.h>

/* Error codes */
#define	PK_ERR_NONE		0
#define	PK_ERR_USAGE		1
#define	PK_ERR_QUIT		2
#define	PK_ERR_PK11INIT		3
#define	PK_ERR_PK11SLOTS	4
#define	PK_ERR_PK11SESSION	5
#define	PK_ERR_PK11LOGIN	6
#define	PK_ERR_PK11SETPIN	7
#define	PK_ERR_NOSLOTS		8
#define	PK_ERR_NOMEMORY		9
#define	PK_ERR_NOTFOUND		10
#define	PK_ERR_PASSPHRASE	11
#define	PK_ERR_NEWPIN		12
#define	PK_ERR_PINCONFIRM	13
#define	PK_ERR_PINMATCH		14
#define	PK_ERR_CHANGEPIN	15

extern int	pk11_errno;

extern int	get_password(char *prompt, char **password);
extern int	init_pk11(void);
extern int	find_token_slot(char *token_name, char *manuf_id,
		    char *serial_no, CK_SLOT_ID *slot_id, CK_FLAGS *pin_state);
extern int	login_token(CK_SLOT_ID slot_id, CK_UTF8CHAR_PTR pin,
		    CK_ULONG pinlen, CK_SESSION_HANDLE_PTR hdl);
extern void	logout_token(CK_SESSION_HANDLE hdl);

#ifdef __cplusplus
}
#endif

#endif /* _PKTOOL_COMMON_H */
