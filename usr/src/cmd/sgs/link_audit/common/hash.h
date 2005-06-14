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
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

/*
  @(#)SSM2 hash.h 1.2 90/11/13 
*/

/*
 * File: hash.h
 *
 * Copyright (C) 1990 Sun Microsystems Inc.
 * All Rights Reserved.
 */


/*
 *    Change Log
 * ============================================================================
 * Author      Date       Change 
 * barts     13 Nov 90	  Created.
 *
 */

#ifndef _hash_h
#define _hash_h

typedef struct hash_entry {
  struct hash_entry 
    * next_entry,
    * right_entry,
    * left_entry;
  char *       	key;
  char * 	data;
} hash_entry;

typedef struct hash {
  size_t	size;
  hash_entry ** table;
  hash_entry * 	start;   
  enum hash_type { String_Key = 0 , Integer_Key = 1} hash_type;
} hash;

hash * 		make_hash(size_t size);
hash * 		make_ihash(size_t size);
char ** 	get_hash(hash * tbl, char * key);
char **		find_hash(hash * tbl, const char * key);
char *		del_hash(hash * tbl, const char * key);
size_t 		operate_hash(hash * tbl, void (*ptr)(), const char * usr_arg);
void 		destroy_hash(hash * tbl, int (*ptr)(), const char * usr_arg);

#endif /* _hash_h */









