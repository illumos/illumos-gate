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

#ifndef _STMFADM_H
#define	_STMFADM_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <cmdparse.h>

/* DEFINES */

/* subcommands */
#define	ADD_MEMBER		SUBCOMMAND(0)
#define	ADD_VIEW		SUBCOMMAND(1)
#define	CREATE_I_GROUP		SUBCOMMAND(2)
#define	CREATE_T_GROUP		SUBCOMMAND(3)
#define	DELETE_GROUP		SUBCOMMAND(4)
#define	LIST_INIT		SUBCOMMAND(5)
#define	LIST_INIT_GROUP		SUBCOMMAND(6)
#define	LIST_TARGET_GROUP	SUBCOMMAND(7)
#define	LIST_VIEW		SUBCOMMAND(8)
#define	REMOVE_MEMBER		SUBCOMMAND(9)
#define	REMOVE_VIEW		SUBCOMMAND(10)


#define	OPERANDSTRING_INITIATOR	    "initiator-name"
#define	OPERANDSTRING_LU	    "LU-name"
#define	OPERANDSTRING_GROUP_MEMBER  "group-member"
#define	OPERANDSTRING_GROUP_NAME    "group-name"
#define	OPERANDSTRING_TARGET	    "target-name"
#define	OPERANDSTRING_VIEW_ENTRY    "ve-number"

#define	VERSION_STRING_MAX_LEN  10


#ifdef	__cplusplus
}
#endif

#endif /* _STMFADM_H */
