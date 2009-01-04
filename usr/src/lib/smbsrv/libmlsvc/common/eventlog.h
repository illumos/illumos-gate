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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _eventlog_H
#define	_eventlog_H

#include <netdb.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/ndl/eventlog.ndl>

#ifdef	__cplusplus
extern "C" {
#endif

#define	LOGR_NMSGMASK	1023

typedef struct logr_entry {
	struct timeval	le_timestamp;			/* Time of log entry */
	int		le_pri;				/* Message priority */
	char		le_hostname[MAXHOSTNAMELEN];	/* Log hostname */
	char		le_msg[LOGR_MAXENTRYLEN];	/* Log message text */
} logr_entry_t;

typedef struct logr_info {
	logr_entry_t	li_entry[LOGR_NMSGMASK+1];	/* Array of log entry */
	int		li_idx;				/* Index */
} logr_info_t;

typedef struct logr_read_data {
	int		rd_tot_recnum;		/* Total no. of record read */
	int		rd_last_sentrec;	/* Last sentence read */
	char		rd_first_read;		/* First sentence read */
	logr_info_t	*rd_log;		/* Log information read */
} logr_read_data_t;

/* This structure provides the context for eventlog calls from clients. */
typedef struct logr_context {
	logr_read_data_t *lc_cached_read_data;
	char *lc_source_name;
} logr_context_t;

int logr_syslog_snapshot(logr_info_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _eventlog_H */
