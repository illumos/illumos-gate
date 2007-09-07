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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_INET_NCALOGD_H
#define	_INET_NCALOGD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_URL_LEN	(8192)

#define	NCA_DEFAULT_LOG_BUF_SIZE (65536)

typedef struct log_buf {
	int8_t			buffer[NCA_DEFAULT_LOG_BUF_SIZE];
	uint32_t		size;
	uint32_t		cur_pos;
	struct log_buf		*next;
#ifndef _KERNEL
	mutex_t			log_lock;	/* threads-critical section */
#else
	kmutex_t		log_lock;	/* threads-critical section */
	frtn_t			ft;	/* free_func() for desballoc */
	void			*pad1;	/* padding so kernel and user-space */
	void			*pad2;	/* are the same size */
#endif /* _KERNEL */
} log_buf_t;

/*
 * Defines the data structures used by NCA and Webservers/log daemons.
 */


typedef struct {
	ipaddr_t	remote_host;	/* IP address of the remote host */

	/* size in bytes of nca_remote_user field */
	uint32_t	remote_user_len;

	nca_offset_t	remote_user;

	uint32_t	auth_user_len;
	nca_offset_t	auth_user;
#ifndef _KERNEL
	/* presumption: user space time_t is 32 bit long */
	time_t		start_process_time;
	time_t		end_process_time;
#else
	time32_t	start_process_time;
	time32_t	end_process_time;
#endif /* _KERNEL */
	/* length in bytes of first line of HTTP request */
	uint32_t	request_url_len;

	nca_offset_t	request_url;
	uint32_t	response_status; /* cast to/from nca_http_status_code */
	uint32_t	response_len;

	/* need for extended common log format */
	uint32_t	referer_len;
	nca_offset_t	referer;
	uint32_t	useragent_len;
	nca_offset_t	useragent;

	/* Need for ELF */
	uint32_t	method;	/* must be cast to nca_http_method_t */
	uint32_t	version; /* request HTTP version */

	/*
	 * This structure is optionally followed by null terminated strings
	 * that contain "remote_user","auth_user", etc.
	 */
} nca_request_log_t;

typedef	struct {
	nca_version_t		nca_version;
	nca_op_t		nca_op;
} nca_ver_op_t;

typedef struct {
	uint32_t	n_log_size;	/* size in bytes of log buf used */
	uint32_t	n_log_recs;	/* number of log recs in buffer */
	uint32_t	n_log_upcall;	/* NCA log buffer number */
} nca_log_stat_t;

typedef struct {
	nca_ver_op_t		nca_loghdr;
	nca_log_stat_t		nca_logstats;
} nca_log_buf_hdr_t;

/*
 * log_op_fiov ...
 */

#include <sys/door.h>

#ifdef _KERNEL
#define	NCA_FIOV_SZ	16

typedef struct {
	struct {
		int	ix;		/* Current log file [ix] */
		int	cnt;		/* Count of valid log file [ix]s */
	} hdr;
	struct {
		vnode_t	*vp;		/* The vnode pointer for the file */
		off64_t	size;		/* Configured maximum bytes to write */
		off64_t	offset;		/* Offset in fd for next write */
		int	file;		/* Index of file (for reference only) */
		caddr_t	name;		/* The name of file */
	} iov[NCA_FIOV_SZ];		/* The iov's for each desc[] */
	vnode_t	*dvp;			/* vnode of dir where symlink lives */
} nca_fio_t;

#define	nca_fio_vp(fiop)	(fiop)->iov[(fiop)->hdr.ix].vp
#define	nca_fio_name(fiop)	(fiop)->iov[(fiop)->hdr.ix].name
#define	nca_fio_size(fiop)	(fiop)->iov[(fiop)->hdr.ix].size
#define	nca_fio_offset(fiop)	(fiop)->iov[(fiop)->hdr.ix].offset
#define	nca_fio_file(fiop)	(fiop)->iov[(fiop)->hdr.ix].file
#define	nca_fio_ix(fiop)	(fiop)->hdr.ix
#define	nca_fio_cnt(fiop)	(fiop)->hdr.cnt
#define	nca_fio_dvp(fiop)	(fiop)->dvp
#endif /* _KERNEL */

/*
 *	Macro to get size of a log record
 */
#define	NCA_LOG_REC_SIZE(p)	 (sizeof (nca_request_log_t) + \
					p->remote_user_len + \
					p->auth_user_len + \
					p->request_url_len + \
					p->referer_len + p->useragent_len)

/*
 *	Used to align start of log record on a uint32_t boundary .
 */
#define	NCA_LOG_ALIGN(p)	(char *)(((size_t)p+(sizeof (uint32_t)-1)) & \
						~(sizeof (uint32_t)-1))

/*
 *	Macros to get at char string data given a pointer to a
 *	nca_request_log_t structure.
 */
#define	NCA_REQLOG_RDATA(p, name) ((char *)p + sizeof (nca_request_log_t) + \
					(p->name))

/* write data as offsets at end of nca_request_log_t buf */
#define	NCA_REQLOG_WDATA(val, p, n_used, len, off) {	\
	if (!(val)) {					\
		p->len = 0;				\
		p->off = 0;				\
	} else {					\
		p->len = strlen(val) + 1;		\
		bcopy(val, ((char *)p + sizeof (nca_request_log_t) \
				+ n_used), (p->len));	\
		p->off = n_used;			\
		n_used += (p->len);			\
		}					\
}

#ifdef	__cplusplus
}
#endif

#endif /* _INET_NCALOGD_H */
