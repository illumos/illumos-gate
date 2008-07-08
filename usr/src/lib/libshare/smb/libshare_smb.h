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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * basic API declarations for share management
 */

#ifndef _LIBSHARE_SMB_H
#define	_LIBSHARE_SMB_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <smbsrv/smb_share.h>

/*
 * defined options types. These should be in a file rather than
 * compiled in. Until there is a plugin mechanism to add new types,
 * this is sufficient.
 */
#define	OPT_TYPE_ANY		0
#define	OPT_TYPE_STRING		1
#define	OPT_TYPE_BOOLEAN	2
#define	OPT_TYPE_NUMBER		3
#define	OPT_TYPE_PATH		4
#define	OPT_TYPE_PROTOCOL	5
#define	OPT_TYPE_NAME		6

struct option_defs {
	char *tag;
	int type;
	int share;	/* share only option */
	int (*check)(char *);
};

/*
 * Sharectl property refresh types. Bit mask to indicate which type(s)
 * of refresh might be needed on the service(s).
 */

#define	SMB_REFRESH_RESTART	0x0001	/* restart smb/server */
#define	SMB_REFRESH_REFRESH	0x0002	/* refresh smb/server */


#ifdef	__cplusplus
}
#endif

#endif /* _LIBSHARE_SMB_H */
