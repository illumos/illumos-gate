/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	EURO_H
#define	EURO_H


#define	MAGIC_NUMBER			201201

/*
 * Excerpt from ../utf-8/common_defs.h
 */
#define	ICV_TYPE_ILLEGAL_CHAR		(-2)

typedef struct {
	unsigned char	ch;
	signed char	sz;
} table_component_t;


/*
 * Mapping table
 * tbl.h generated from tbls/ files using ./genincl script
 */
static const table_component_t tbl[256] = {

#include "tbl.h"

};

#endif	/* EURO_H */
