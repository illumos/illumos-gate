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
 *	db_vers_c.x
 *
 * Copyright 2015 Gary Mills
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#if RPC_XDR
%#include "ldap_xdr.h"
#endif /* RPC_XDR */

#if RPC_HDR
%#ifndef _DB_VERS_H
%#define _DB_VERS_H
#endif /* RPC_HDR */

%/* 'vers' is the version identifier.  */

%
%#include "nisdb_rw.h"
%
#if RPC_HDR || RPC_XDR
#ifdef USINGC
struct vers {
	u_int vers_high;
	u_int vers_low;
	u_int time_sec;
	u_int time_usec;
	__nisdb_rwlock_t vers_rwlock;
};
#endif /* USINGC */
#endif /* RPC_HDR */

#ifndef USINGC
#ifdef RPC_HDR
%class vers {
%  unsigned int vers_high;     /* major version number, tracks checkpoints */
%  unsigned int vers_low;      /* minor version number, tracks updates. */
%  unsigned int time_sec;      /* time stamp */
%  unsigned int time_usec;
%  STRUCTRWLOCK(vers);
% public:
%/* No argument constructor.  All entries initialized to zero. */
%  vers() {
%	vers_high = vers_low = time_sec = time_usec = 0;
%	INITRW(vers);
%  }
%
%/* Constructor that makes copy of 'other'. */
%  vers( vers *other );
%
%/* Constructor:  create version with specified version numbers */
%  vers( unsigned int high, unsigned int low) {
%	vers_high = high; vers_low = low; time_sec = time_usec = 0;
%	INITRW(vers);
%  } 
%
%/* Creates new 'vers' with next higher minor version.
%   If minor version exceeds MAXLOW, bump up major version instead.
%   Set timestamp to that of the current time. */
%  vers* nextminor();
%
%/* Creates new 'vers' with next higher major version.
%   Set timestamp to that of the current time. */
%  vers* nextmajor();
%
%/* Set this 'vers' to hold values found in 'others'. */
%  void assign( vers *other );
%
%/* Predicate indicating whether this vers is earlier than 'other' in
%   terms of version numbers. */
%  bool_t earlier_than( vers *other );
%
%/* Print the value of this 'vers' to specified file. */
%  void print( FILE *file );
%
%/* Zero out this vers. */
%  void zero();
%
%/* Predicate indicating whether this vers is equal to 'other'. */
%  bool_t  equal( vers *other);
%
%/* Locking methods */
%
%  int acqexcl(void) {
%	return (WLOCK(vers));
%  }
%
%  int relexcl(void) {
%	return (WULOCK(vers));
%  }
%
%  int acqnonexcl(void) {
%	return (RLOCK(vers));
%  }
%
%  int relnonexcl(void) {
%	return (RULOCK(vers));
%  }
%};
#endif /* RPC_HDR */
#endif /* USINGC */

#if RPC_HDR
%#endif /* VERS_H */
#endif /* RPC_HDR */
