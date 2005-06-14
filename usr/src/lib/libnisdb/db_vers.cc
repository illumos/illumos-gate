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
 *	db_vers.cc
 *
 *	Copyright (c) 1988-2000 by Sun Microsystems, Inc.
 *	All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>

#include "db_headers.h"
#include "db_vers.h"
#include "nisdb_mt.h"

const long unsigned MAXLOW = 32768*32768;

/* Constructor that makes copy of 'other'. */
vers::vers(vers* other)
{
	INITRW(vers);
	assign(other);
}

void
vers::assign(vers* other)
{
	WRITELOCKV(this, "w vers::assign");
	if (other == NULL) {
		syslog(LOG_ERR, "vers::vers: making copy of null vers?");
		vers_high = vers_low = time_sec = time_usec = 0;
	} else {
		time_sec = other->time_sec;
		time_usec = other->time_usec;
		vers_low = other->vers_low;
		vers_high = other->vers_high;
	}
	WRITEUNLOCKV(this, "wu vers::assign");
}

/*
 * Creates new 'vers' with next higher minor version.
 * If minor version exceeds MAXLOW, bump up major version instead.
 * Set timestamp to that of the current time.
 */
vers*
vers::nextminor()
{
	READLOCK(this, NULL, "r vers::nextminor");

	vers * newvers = new vers;

	if (newvers == NULL) {
		READUNLOCK(this, NULL, "ru vers::nextminor DB_MEMORY_LIMIT");
		FATAL3("vers::nextminor: cannot allocation space",
			DB_MEMORY_LIMIT, NULL);
	}

	struct timeval mt;
	gettimeofday(&mt, NULL);

	newvers->time_sec = (unsigned int) mt.tv_sec;
	newvers->time_usec = (unsigned int) mt.tv_usec;
	newvers->vers_low = (this->vers_low + 1);
	newvers->vers_high = (this->vers_high);

	if (newvers->vers_low >= MAXLOW){
		newvers->vers_high++;
		newvers->vers_low = 0;
	}

	READUNLOCK(this, newvers, "ru vers::nextminor");
	return (newvers);
}

/*
 * Creates new 'vers' with next higher major version.
 * Set timestamp to that of the current time.
 */
vers*
vers::nextmajor()
{
	READLOCK(this, NULL, "r vers::nextmajor");

	vers * newvers = new vers;

	if (newvers == NULL) {
		READUNLOCK(this, NULL, "ru vers::nextmajor DB_MEMORY_LIMIT");
		FATAL3("vers::nextminor: cannot allocation space",
			DB_MEMORY_LIMIT, NULL);
	}

	struct timeval mt;
	gettimeofday(&mt, NULL);

	newvers->time_sec = (unsigned int) mt.tv_sec;
	newvers->time_usec = (unsigned int) mt.tv_usec;
	newvers->vers_low = 0;
	newvers->vers_high = (this->vers_high+1);

	READUNLOCK(this, newvers, "ru vers::nextmajor");
	return (newvers);
}

/*
 * Predicate indicating whether this vers is earlier than 'other' in
 * terms of version numbers.
*/
bool_t
vers::earlier_than(vers *other)
{
	int	ret, lret;

	if (other == NULL) {
		syslog(LOG_ERR,
			"vers::earlier_than: comparing against null vers");
		return (FALSE);
	}

	READLOCK(this, FALSE, "r vers::earlier_than");
	READLOCKNR(other, lret, "r other vers::earlier_than");
	if (lret != 0) {
		READUNLOCK(this, FALSE, "ru + r other vers::earlier_than");
		return (FALSE);
	}

	if (other->vers_high > vers_high) ret = TRUE;
	else if (other->vers_high < vers_high) ret = FALSE;
	else if (other->vers_low > vers_low) ret = TRUE;
	else ret = FALSE;

	READUNLOCKNR(other, lret, "ru other vers::earlier_than");
	READUNLOCK(this, ret, ((lret != 0) ?
				"ru + ru other vers::earlier_than" :
				"ru vers::earlier_than"));
	return (ret);
}

/* Print the value of this 'vers' to specified file. */
void
vers::print(FILE* file)
{
	char *thetime;
	thetime = ctime((long *) (&(time_sec)));
	thetime[strlen(thetime)-1] = 0;

	READLOCKV(this, "r vers::print");
	fprintf(file, "version=%u.%u %s:%u",
		vers_high,
		vers_low,
		/* time_sec, */
		thetime,
		time_usec);
	READUNLOCKV(this, "ru vers::print");
}

void
vers::zero() {
	WRITELOCKV(this, "r vers::zero");
	vers_high = vers_low = time_sec = time_usec = 0;
	WRITEUNLOCKV(this, "ru vers::zero");
}

bool_t
vers::equal( vers *other) {
	READLOCK(this, FALSE, "r vers::equal");
	bool_t ret = other != NULL &&
		vers_high == other->vers_high &&
		vers_low == other->vers_low &&
		time_sec == other->time_sec &&
		time_usec == other->time_usec;
	READUNLOCK(this, ret, "ru vers::equal");
	return (ret);
};
