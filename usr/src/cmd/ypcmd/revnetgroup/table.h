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
 * Copyright 1995 Sun Microsystems Inc.
 * All rights reserved.
 */
							    

#ifndef	__TABLE_H
#define	__TABLE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"        /* SMI4.1 1.4 */

#ifdef	__cplusplus
extern "C" {
#endif

#define NUMLETTERS 27 /* 26 letters  + 1 for anything else */
#define TABLESIZE (NUMLETTERS*NUMLETTERS)

typedef struct tablenode *tablelist;
struct tablenode {
	char *key;
	char *datum;
	tablelist next;
};
typedef struct tablenode tablenode;

typedef tablelist stringtable[TABLESIZE];

int tablekey();
char *lookup();
void store();

#ifdef	__cplusplus
}
#endif

#endif	/* __TABLE_H */
