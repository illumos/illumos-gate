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

#ifndef	_MISC_H
#define	_MISC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol Defined Requests */
#define	PRINT_REQUEST		1	/* \1printer\n */
#define	XFER_REQUEST		2	/* \2printer\n */
#define	    XFER_CLEANUP	1 	/* \1 */
#define	    XFER_CONTROL	2	/* \2size name\n */
#define	    XFER_DATA		3	/* \3size name\n */

#define	SHOW_QUEUE_SHORT_REQUEST 3	/* \3printer [users|jobs ...]\n */
#define	SHOW_QUEUE_LONG_REQUEST  4	/* \4printer [users|jobs ...]\n */
#define	REMOVE_REQUEST	    5	/* \5printer person [users|jobs ...]\n */

#define	ACK_BYTE	0
#define	NACK_BYTE	1

#define	MASTER_NAME	"printd"
#define	MASTER_LOCK	"/var/spool/print/.printd.lock"
#define	SPOOL_DIR	"/var/spool/print"
#define	TBL_NAME	"printers.conf"


extern int check_client_spool(char *printer);
extern int get_lock(char *name, int write_pid);
extern uid_t get_user_id();
extern char *get_user_name();
extern char *strcdup(char *, char);
extern char *strndup(char *, int);
extern char **strsplit(char *, char *);
extern int  file_size(char *);
extern int  copy_file(char *src, char *dst);
extern int  map_in_file(const char *name, char **buf, int as_me);
extern int  write_buffer(char *name, char *buf, int len);
extern void start_daemon(int do_fork);
extern int  kill_process(char *file);

#ifdef __cplusplus
}
#endif

#endif /* _MISC_H */
