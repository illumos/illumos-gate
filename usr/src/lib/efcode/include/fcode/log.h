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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FCODE_LOG_H
#define	_FCODE_LOG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* Internal Message Levels */
#define	MSG_FATAL	0x01	/* Fatal Error -> LOG_ERR */
#define	MSG_ERROR	0x02	/* Error -> LOG_ERR */
#define	MSG_WARN	0x04	/* Warning -> LOG_WARN */
#define	MSG_NOTE	0x08	/* Notice -> LOG_NOTICE */
#define	MSG_INFO	0x10	/* Informational -> LOG_INFO */
#define	MSG_DEBUG	0x20	/* Debug -> LOG_DEBUG */
#define	MSG_FC_DEBUG	0x40	/* Fcode (Noisy) Debug -> LOG_DEBUG */
#define	MSG_EMIT	0x80	/* Fcode Emit -> LOG_DEBUG */

void log_message(int, char *, ...);
void log_perror(int, char *, ...);
void debug_msg(int, char *, ...);
void open_syslog_log(char *, int);
void open_error_log(char *, int);
void log_emit(char);
void set_daemon_log_flag(int);
void set_min_syslog_level(int);
int parse_msg_flags(char *);

#ifdef	__cplusplus
}
#endif

#endif /* _FCODE_LOG_H */
