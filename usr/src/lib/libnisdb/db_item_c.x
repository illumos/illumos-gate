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
 *	db_item_c.x
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

%#pragma ident	"%Z%%M%	%I%	%E% SMI"

%
% /* A 'counted' string. */
%

#if RPC_HDR
%#ifndef _DB_ITEM_H
%#define _DB_ITEM_H
#endif /* RPC_HDR */

#if RPC_HDR || RPC_XDR
#ifdef USINGC
struct item{
  char itemvalue<>;
};
#endif /* USINGC */
#endif /* RPC_HDR */

#ifndef USINGC
#ifdef RPC_HDR
%class item {
%  int len;
%  char *value;
% public:
%/* Constructor: creates item using given character sequence and length */
%  item( char* str, int len);
%
%/* Constructor: creates item by copying given item */
%  item( item* );
%
%/* Constructor: creates empty item (zero length and null value). */
%  item() {len = 0; value = NULL;}
%
%/* Destructor: recover space occupied by characters and delete item. */
%  ~item() {delete value;}
%
%/* Equality test.  'casein' TRUE means case insensitive test. */
%  bool_t equal( item *, bool_t casein = FALSE );
%
%/* Equality test.  'casein' TRUE means case insensitive test. */
%  bool_t equal( char *, int, bool_t casein = FALSE );
%
%/* Assignment:  update item by setting pointers.  No space is allocated. */
%  void update( char* str, int n) {len = n; value = str;}
%
%/* Return contents of item. */
%  void get_value( char** s, int * n ) { *s = value; *n=len;}
%
%/* Prints contents of item to stdout */
%  void print();
%
%/* Return hash value.  'casein' TRUE means case insensitive test. */
%  unsigned int get_hashval( bool_t casein = FALSE );
%};
#endif /* RPC_HDR */
#endif /* USINGC */

#if RPC_HDR
%#endif /* _DB_ITEM_H */
#endif /* RPC_HDR */
