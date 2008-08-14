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


#ifndef _TRACE_H
#define	_TRACE_H

#include <stdarg.h>
#include <sys/types.h>

/*
 * mms_trace location define
 */
#define	MMS_HERE _SrcFile, __LINE__

/*
 * message severity
 */
enum mms_msg_sev {
	MMS_MSG_SEV_EMERG,		/* emergency */
	MMS_MSG_SEV_ALERT,		/* alert */
	MMS_MSG_SEV_CRIT,		/* critical */
	MMS_MSG_SEV_ERROR,		/* error */
	MMS_MSG_SEV_WARN,		/* warning */
	MMS_MSG_SEV_NOTICE,		/* notice */
	MMS_MSG_SEV_INFO,		/* information */
	MMS_MSG_SEV_DEBUG,		/* debug */
	MMS_MSG_SEV_DEVP		/* developer */
};
typedef enum mms_msg_sev mms_msg_sev_t;

/*
 * mms_trace severity
 */
enum mms_trace_sev {
	MMS_SEV_EMERG,		/* emergency */
	MMS_SEV_ALERT,		/* alert */
	MMS_SEV_CRIT,		/* critical */
	MMS_SEV_OPER,		/* operational */
	MMS_SEV_ERROR,		/* error */
	MMS_SEV_WARN,		/* warning */
	MMS_SEV_NOTICE,		/* notice */
	MMS_SEV_INFO,		/* information */
	MMS_SEV_DEBUG,		/* debug */
	MMS_SEV_DEVP		/* developer */
};
typedef enum mms_trace_sev mms_trace_sev_t;

/*
 * mms_trace function defines
 */
#define	MMS_EMERG	MMS_SEV_EMERG,	MMS_HERE /* emergency, file, line */
#define	MMS_ALERT	MMS_SEV_ALERT,	MMS_HERE /* alert, file, line */
#define	MMS_CRIT	MMS_SEV_CRIT,	MMS_HERE /* critical, file, line */
#define	MMS_OPER	MMS_SEV_OPER,	MMS_HERE /* operational, file, line */
#define	MMS_ERR		MMS_SEV_ERROR,	MMS_HERE /* error, file, line */
#define	MMS_WARN	MMS_SEV_WARN,	MMS_HERE /* warning, file, line */
#define	MMS_NOTICE	MMS_SEV_NOTICE,	MMS_HERE /* notice, file, line */
#define	MMS_INFO	MMS_SEV_INFO,	MMS_HERE /* information, file, line */
#define	MMS_DEBUG	MMS_SEV_DEBUG,	MMS_HERE /* debug, file, line */
#define	MMS_DEVP	MMS_SEV_DEVP,	MMS_HERE /* developer, file, line */

/*
 * mms_trace component ids
 */
typedef enum mms_trace_id mms_trace_id_t;
enum mms_trace_id {
	MMS_ID_MM,		/* media manager */
	MMS_ID_LM,		/* library manager */
	MMS_ID_DM,		/* drive manager */
	MMS_ID_DMD,		/* drive manager daemon */
	MMS_ID_WCR,		/* watcher */
	MMS_ID_API,		/* client api library */
	MMS_ID_ND,		/* non daemon mode, use stderr */
	MMS_ID_CLI		/* client application */
};


extern int		mms_trace_open(char *, mms_trace_id_t, int, int64_t,
    int, int);
extern int		mms_trace_get_fd(void);
extern void		mms_trace_set_id(mms_trace_id_t);
extern mms_trace_id_t	mms_trace_get_id(void);
extern mms_trace_sev_t	mms_trace_get_severity(void);
extern mms_msg_sev_t	mms_msg_get_severity(char *);
extern void		mms_trace(mms_trace_sev_t, char *, int,
			    const char *, ...);
extern void		mms_trace_va(mms_trace_sev_t, char *, int,
			    const char *, va_list);
extern void		mms_trace_close(void);
extern int		mms_trace_filter(mms_trace_sev_t);
extern int		mms_trace_str_filter(char *);
extern char		*mms_trace_dump(char *, int, char *, int);
extern void		mms_trace_flush(void);
extern int		mms_trace_set_fsize(char *);
extern int		mms_trace_str_to_fsize(char *string, uint64_t *size);
extern int		mms_trace_str2sev(char *level,
			    mms_trace_sev_t *severity);
extern char 		*mms_trace_sev2str(mms_trace_sev_t severity);

#define	MMS_CHAR_PER_LINE	16
#define	MMS_NUM_LINES(len)	(((len - 1) / MMS_CHAR_PER_LINE) + 1)
#define	MMS_CHAR_OFFSET		(6 + 9 * 4)
#define	MMS_DUMP_LINE_SIZE	(MMS_CHAR_OFFSET + MMS_CHAR_PER_LINE + 1)
#define	MMS_DUMPBUF_SIZE(len)	((MMS_NUM_LINES(len) * MMS_LINE_SIZE) + 1)
#define	MMS_LINE_SIZE		1000
#define	MMS_LOGADM		"/usr/sbin/logadm"
#define	MMS_LOGADM_CONF		"/var/log/mms/mms_logadm.conf"



#endif /* _TRACE_H */
