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
 * Copyright (c) 1996 Sun Microsystems, Inc.
 */

/*
 * Definitions for nisbackup(1M) and nisrestore(1M). These are private
 * definitions and may change without notice.
 */

#ifndef _NIS_BKRST_H
#define	_NIS_BKRST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

extern int 	optind;
extern char	*optarg;

#if defined(__STDC__) || defined(__cplusplus)

extern bool_t db_copy_file(char *, char *);
extern bool_t db_extract_dict_entries(char *, char **, u_int);
extern bool_t db_in_dict_file(char *);
extern db_status db_begin_merge_dict(char *, char *, char *);
extern db_status db_end_merge_dict();
extern db_status db_abort_merge_dict();
extern char *db_perror(db_status);
extern void sync_header();

#else /* Non-prototype definitions */

extern bool_t db_copy_file();
extern bool_t db_extract_dict_entries();
extern bool_t db_in_dict_file();
extern db_status db_begin_merge_dict();
extern db_status db_end_merge_dict();
extern db_status db_abort_merge_dict();
extern char *db_perror();
extern void sync_header();

#endif /* defined(__STDC__) || defined(__cplusplus) */

/* 
 * verbose is must be defined for nis_log_common, but is not used, since  
 * the trans.log merge routines output way too much verbiage. Hence, the  
 * static flag, verbiage. 
 */ 
bool_t                  verbose = FALSE;

/*
 * BACKUPREV is the current revision number for the backup snap shot. If 
 * something changes with the NIS+ database or the nisbackup/nisrestore
 * snapshot, which effects backwards compatibility, this needs to be rev'd
 */
#define BACKUPREV  0xBACDEF01
#define BACKUPLIST "backup_list"
#define LASTUPDATE "last.upd"
#define MAXRETRIES 10	/* Max number of retries for contacting the server */
#define DOMAIN_ALL 1	/* Mask for -a option */

#ifdef __cplusplus
}
#endif

#endif	/* _NIS_BKRST_H */
