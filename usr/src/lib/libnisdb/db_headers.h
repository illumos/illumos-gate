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
 *	db_headers.h
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _DB_HEADERS_H
#define	_DB_HEADERS_H

#include <rpc/rpc.h>
#include <syslog.h>
#include <stdlib.h>
#include <setjmp.h>

extern int verbose;
extern jmp_buf dbenv;

#define	FATAL(msg, fcode) \
	{ \
		syslog(LOG_ERR, "ERROR: %s", (msg)); \
		__nisdb_get_tsd()->fatalcode = (int)(fcode); \
		__nisdb_get_tsd()->fatalmsg = msg; \
		return; \
	}
#define	FATAL3(msg, fcode, retval) \
	{ \
		syslog(LOG_ERR, "ERROR: %s", (msg)); \
		__nisdb_get_tsd()->fatalcode = (int)(fcode); \
		__nisdb_get_tsd()->fatalmsg = msg; \
		return (retval); \
	}

#ifdef	NISDB_MT_DEBUG
#define	LOCKVAL(lockcall, msg, lockcode) \
	{ \
		lockcode = lockcall(); \
		if (lockcode != 0) { \
			__nisdb_get_tsd()->fatalcode = lockcode; \
			__nisdb_get_tsd()->fatalmsg = msg; \
			abort(); \
		} \
	}
#else
#define	LOCKVAL(lockcall, msg, lockcode) \
	{ \
		lockcode = lockcall(); \
		if (lockcode != 0) { \
			__nisdb_get_tsd()->fatalcode = lockcode; \
			__nisdb_get_tsd()->fatalmsg = msg; \
		} \
	}
#endif	/* NISDB_MT_DEBUG */

#define	LOCKV(lockcall, msg) \
	{ \
		int	lockcode; \
		LOCKVAL(lockcall, msg, lockcode); \
		if (lockcode != 0) \
			return; \
	}
#define	LOCK(lockcall, retval, msg) \
	{ \
		int	lockcode; \
		LOCKVAL(lockcall, msg, lockcode); \
		if (lockcode != 0) \
			return (retval); \
	}

/* Read lock/unlock 'this', return 'retval' is unsuccessful, and save 'msg' */
#define	READLOCK(this, retval, msg) \
	LOCK(this->acqnonexcl, retval, msg)
#define	READUNLOCK(this, retval, msg) \
	LOCK(this->relnonexcl, retval, msg)

/* Ditto, but return without a value (i.e., a "void" function */
#define	READLOCKV(this, msg) \
	LOCKV(this->acqnonexcl, msg)
#define	READUNLOCKV(this, msg) \
	LOCKV(this->relnonexcl, msg)

/* As READLOCK/READUNLOCK, but set rescode instead of returning on failure */
#define	READLOCKNR(this, rescode, msg) \
	LOCKVAL(this->acqnonexcl, msg, rescode)
#define	READUNLOCKNR(this, rescode, msg) \
	LOCKVAL(this->relnonexcl, msg, rescode)

/* As READLOCK/READUNLOCK, but use a write lock */
#define	WRITELOCK(this, retval, msg) \
	LOCK(this->acqexcl, retval, msg)
#define	WRITEUNLOCK(this, retval, msg) \
	LOCK(this->relexcl, retval, msg)

/* Non-blocking write lock */
#define	TRYWRITELOCK(this, rescode, msg) \
	LOCKVAL(this->tryacqexcl, msg, rescode)

/* Ditto, but return without a value */
#define	WRITELOCKV(this, msg) \
	LOCKV(this->acqexcl, msg)
#define	WRITEUNLOCKV(this, msg) \
	LOCKV(this->relexcl, msg)

/* As WRITELOCK/WRITEUNLOCK, but set rescode instead of returning on failure */
#define	WRITELOCKNR(this, rescode, msg) \
	LOCKVAL(this->acqexcl, msg, rescode)
#define	WRITEUNLOCKNR(this, rescode, msg) \
	LOCKVAL(this->relexcl, msg, rescode)

/* Apply a second write lock when already holding another write lock */
#define	WRITELOCK2(this, retval, msg, that) \
	if (this != 0) { \
		int	lockcode1, lockcode2; \
		WRITELOCKNR(this, lockcode2, msg); \
		if (lockcode2 != 0) { \
			if (that != 0) { \
				WRITEUNLOCKNR(that, lockcode1, msg); \
			} \
			return (retval); \
		} \
	}
/* Release two write locks */
#define	WRITEUNLOCK2(this, that, retval1, retval2, msg1, msg2) \
	{ \
		int	lockcode1 = 0, lockcode2 = 0; \
		if (this != 0) { \
			WRITEUNLOCKNR(this, lockcode1, msg1); \
		} \
		if (that != 0) { \
			WRITEUNLOCKNR(that, lockcode2, msg2); \
		} \
		if (lockcode2 != 0) { \
			return (retval2); \
		} else if (lockcode1 != 0) { \
			return (retval1); \
		} \
	}

/* Apply a second read lock when already holding another read lock */
#define	READLOCK2(this, retval, msg, that) \
	if (this != 0) { \
		int	lockcode1, lockcode2; \
		READLOCKNR(this, lockcode2, msg); \
		if (lockcode2 != 0) { \
			if (that != 0) { \
				READUNLOCKNR(that, lockcode1, msg); \
			} \
			return (retval); \
		} \
	}
/* Release two read locks */
#define	READUNLOCK2(this, that, retval1, retval2, msg1, msg2) \
	{ \
		int	lockcode1 = 0, lockcode2 = 0; \
		if (this != 0) { \
			READUNLOCKNR(this, lockcode1, msg1); \
		} \
		if (that != 0) { \
			READUNLOCKNR(that, lockcode2, msg2); \
		} \
		if (lockcode2 != 0) { \
			return (retval2); \
		} else if (lockcode1 != 0) { \
			return (retval1); \
		} \
	}

#define	ASSERTWRITELOCKHELD(lvar, retval, msg) \
	{ \
		int	lc; \
		if ((lc = __nisdb_assert_wheld(&lvar ## _rwlock)) != 0) { \
			__nisdb_get_tsd()->fatalcode = lc; \
			__nisdb_get_tsd()->fatalmsg = msg; \
			return (retval); \
		} \
	}

#define	WARNING(x) { syslog(LOG_ERR, "WARNING: %s", (x)); }

#define	WARNING_M(x) { syslog(LOG_ERR, "WARNING: %s: %m", (x)); }


enum db_status {DB_SUCCESS, DB_NOTFOUND, DB_NOTUNIQUE,
		    DB_BADTABLE, DB_BADQUERY, DB_BADOBJECT,
		DB_MEMORY_LIMIT, DB_STORAGE_LIMIT, DB_INTERNAL_ERROR,
		DB_BADDICTIONARY, DB_SYNC_FAILED, DB_LOCK_ERROR};
typedef enum db_status db_status;

enum db_action {DB_LOOKUP, DB_REMOVE, DB_ADD, DB_FIRST, DB_NEXT, DB_ALL,
			DB_RESET_NEXT, DB_ADD_NOLOG,
			DB_ADD_NOSYNC, DB_REMOVE_NOSYNC };
typedef enum db_action db_action;

#endif /* _DB_HEADERS_H */
