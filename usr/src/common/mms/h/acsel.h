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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _ACSEL_
#define	_ACSEL_
#include <stdio.h>
#include "structs.h"

#define	EL_SELECT_FOREVER -1L
#define	EL_SELECT_TIMEOUT (long)(RETRY_TIMEOUT * 2)


#define	EL_ERROR_MSG_SIZE 256L
#define	FILE_PATHNAME_SIZE 256L
#define	MIN_LOG_SIZE	32L

#define	TRACE_DISABLED		0
#define	TRACE_ENABLED    (!TRACE_DISABLED)

#define	EVENT_MSG_WIDTH		78L
#define	INFORM_PERIOD	  60L


#define	LOG_EVENT_FILE_NAME "acsss_event.log"
#define	LOG_TRACE_FILE_NAME "acsss_trace.log"
#define	LOG_ARCHIVE_TEMPLATE "event%d.log"


#define	MIN_ARCHIVE_FILES	0
#define	MAX_ARCHIVE_FILES	10

extern EVENT_LOG_MESSAGE		acsel_input_buffer;

extern long	event_log_size;
extern int	event_log_full;
extern long	event_log_time;
extern long	event_file_time;
extern int 	trace_logging_off;

extern char	event_file[];
extern char	trace_file[];
extern char		archive_template[];

extern int		el_terminated;
extern long		el_select_timeout;

extern int		file_num;
extern long		el_clock;

STATUS		el_init();
STATUS		el_input();
STATUS		el_roll_file();
void	el_output();
void	el_format();
void	el_fwrite();
void	el_log_error();
void	el_sig_hdlr();

#endif /* _ACSEL_ */
