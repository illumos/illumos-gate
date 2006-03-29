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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__MGR_CACHE_H
#define	__MGR_CACHE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mapped_cache.h"

#define	MIN_REFRESH_WAIT (5 * 60)	/* 5 minutes */
#define	PING_WAIT (15 * 60)		/* 15 minutes */
#define	CONFIG_WAIT (12 * 60 * 60)	/* 12 hours */

class NisMgrCache : public NisMappedCache {
    public:
	NisMgrCache(nis_error &error, int discardOldCache);
	~NisMgrCache();
	void start();
	uint32_t loadPreferredServers();

	uint32_t timers();
	uint32_t nextTime();
	uint32_t refreshCache();
	void ping();
	int checkUp();

	void *operator new(size_t bytes) { return calloc(1, bytes); }
	void operator delete(void *arg) { free(arg); }

    private:
	uint32_t refresh_time;
	uint32_t ping_time;
	uint32_t config_time;
	uint32_t config_interval;

	void refresh();
	uint32_t config();
	void parse_info(char *info, char **srvr, char **option);
	char *get_line(FILE *fp);
	uint32_t writeDotFile();
	uint32_t loadLocalFile();
	uint32_t loadNisTable();
};

#endif	/* __MGR_CACHE_H */
