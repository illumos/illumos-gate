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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _DIS_H
#define	_DIS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <dis_tables.h>

#include <mdb/mdb_disasm_impl.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_io.h>
#include <mdb/mdb.h>

#define	NHEX	40	/* max # chars in object per line	*/
#define	NLINE	1024	/* max # chars in mnemonic per line	*/
#define	TRUE	1
#define	FALSE	0
#define	LEAD	1
#define	NOLEAD	0
#define	NOLEADSHORT 2

#define	DIS_IA32	0
#define	DIS_AMD64	1

#ifdef __cplusplus
}
#endif

#endif /* _DIS_H */
