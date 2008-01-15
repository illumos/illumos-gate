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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SIP_MISCDEFS_H
#define	_SIP_MISCDEFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <pthread.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>

#define	SIP_CR			'\r'
#define	SIP_SP			' '
#define	SIP_HCOLON		':'
#define	SIP_SEMI		';'
#define	SIP_COMMA		','
#define	SIP_LAQUOT		'<'
#define	SIP_RAQUOT		'>'
#define	SIP_QUOTE		'"'
#define	SIP_EQUAL		'='
#define	SIP_SLASH		'/'
#define	SIP_PERIOD		'.'
#define	SIP_LPAR		'('
#define	SIP_RPAR		')'

#define	SIP_BRANCHID_LEN	28	/* incl. the magic cookie */
#define	SIP_TAG_LEN		20
#define	SIP_URI_LEN		25
#define	SIP_DISPLAY_LEN		25
#define	SIP_DOMAIN_LEN		25
#define	SIP_MAX_FWDLEN		5
#define	SIP_TRANSPORT_LEN	5
#define	SIP_SIZE_OF_STATUS_CODE	3
#define	SIP_SPACE_LEN		sizeof (char)

#define	SIP_TRANSACTION_LOG		0x0001
#define	SIP_DIALOG_LOG			0x0002
#define	SIP_ASSERT_ERROR		0x0004

#define	SIP_MS			1L
#define	SIP_SECONDS		(1000 * SIP_MS)
#define	SIP_MINUTES		(60 * SIP_SECONDS)
#define	SIP_HOURS   		(60 * SIP_MINUTES)

/* timer granularity is in msecs */
#define	SIP_TIMER_T1		(1 * SIP_SECONDS)
#define	SIP_TIMER_T2		(4 * SIP_SECONDS)
#define	SIP_TIMER_T4		(5 * SIP_SECONDS)

#ifdef		__linux__
#define		SEC		1
#define		MILLISEC	1000
#define		MICROSEC	1000000
#define		NANOSEC		1000000000

typedef struct timespec	timestruc_t;
typedef	long long	hrtime_t;
#endif

extern int	sip_timer_T1;
extern int	sip_timer_T2;
extern int	sip_timer_T4;
extern int	sip_timer_TD;

/* Structure for SIP timers */
typedef struct sip_timer_s {
	uint_t		sip_timerid;
	struct timeval	sip_timeout_val;
}sip_timer_t;

/* time is in msec */
#define	SIP_SET_TIMEOUT(timer, time) {					\
	int	mtime = (time);						\
									\
	(timer).sip_timeout_val.tv_sec = mtime / MILLISEC;	\
	mtime -= (timer).sip_timeout_val.tv_sec * MILLISEC;	\
	(timer).sip_timeout_val.tv_usec = mtime * MILLISEC;		\
}

/* time is in msec */
#define	SIP_INIT_TIMER(timer, time) {				\
	SIP_SET_TIMEOUT(timer, time);				\
	(timer).sip_timerid = 0;				\
}

#define	SIP_SCHED_TIMER(timer, obj, func) {			\
	(timer).sip_timerid = sip_stack_timeout((void *)(obj),	\
	    (func), &((timer).sip_timeout_val));			\
}

#define	SIP_CANCEL_TIMER(timer) {				\
	if ((timer).sip_timerid != 0) {				\
		sip_stack_untimeout((timer).sip_timerid);	\
		(timer).sip_timerid = 0;			\
	}							\
}

/* returned time is in msec */
#define	SIP_GET_TIMEOUT(timer)					\
	((timer).sip_timeout_val.tv_sec * MILLISEC +		\
	(timer).sip_timeout_val.tv_usec / MILLISEC)

#define	SIP_IS_TIMER_RUNNING(timer)	((timer).sip_timerid != 0)

#define	SIP_UPDATE_COUNTERS(is_request, method, resp_code, outbound, size) {   \
	(void) pthread_mutex_lock(&sip_counters.sip_counter_mutex);	       \
	if (sip_counters.enabled) {					       \
		(void) sip_measure_traffic((is_request), (method), (resp_code),\
		    (outbound), (size));				       \
	}								       \
	(void) pthread_mutex_unlock(&sip_counters.sip_counter_mutex);	       \
}

/* This is the transaction list */
typedef struct sip_conn_cache_s {
	void			*obj;
	struct sip_conn_cache_s	*next;
	struct sip_conn_cache_s	*prev;
} sip_conn_cache_t;

/* TCP fragment entry */
typedef struct sip_reass_entry_s {
	char		*sip_reass_msg;
	int		sip_reass_msglen;
}sip_reass_entry_t;

/* Library data in stored in connection object */
typedef struct sip_conn_obj_pvt_s {
	sip_reass_entry_t	*sip_conn_obj_reass;
	pthread_mutex_t		sip_conn_obj_reass_lock;
	sip_conn_cache_t	*sip_conn_obj_cache;
	pthread_mutex_t		sip_conn_obj_cache_lock;
} sip_conn_obj_pvt_t;

/* SIP traffic counters structure */

typedef struct sip_traffic_counters_s {
	boolean_t	enabled;
	time_t		starttime;
	time_t		stoptime;
	uint64_t	sip_total_bytes_rcvd;
	uint64_t	sip_total_bytes_sent;
	uint64_t	sip_total_req_rcvd;
	uint64_t	sip_total_req_sent;
	uint64_t	sip_total_resp_rcvd;
	uint64_t	sip_total_resp_sent;
	uint64_t	sip_ack_req_rcvd;
	uint64_t	sip_ack_req_sent;
	uint64_t	sip_bye_req_rcvd;
	uint64_t	sip_bye_req_sent;
	uint64_t	sip_cancel_req_rcvd;
	uint64_t	sip_cancel_req_sent;
	uint64_t	sip_info_req_rcvd;
	uint64_t	sip_info_req_sent;
	uint64_t	sip_invite_req_rcvd;
	uint64_t	sip_invite_req_sent;
	uint64_t	sip_notify_req_rcvd;
	uint64_t	sip_notify_req_sent;
	uint64_t	sip_options_req_rcvd;
	uint64_t	sip_options_req_sent;
	uint64_t	sip_prack_req_rcvd;
	uint64_t	sip_prack_req_sent;
	uint64_t	sip_refer_req_rcvd;
	uint64_t	sip_refer_req_sent;
	uint64_t	sip_register_req_rcvd;
	uint64_t	sip_register_req_sent;
	uint64_t	sip_subscribe_req_rcvd;
	uint64_t	sip_subscribe_req_sent;
	uint64_t	sip_update_req_rcvd;
	uint64_t	sip_update_req_sent;
	uint64_t	sip_1xx_resp_rcvd;
	uint64_t	sip_1xx_resp_sent;
	uint64_t	sip_2xx_resp_rcvd;
	uint64_t	sip_2xx_resp_sent;
	uint64_t	sip_3xx_resp_rcvd;
	uint64_t	sip_3xx_resp_sent;
	uint64_t	sip_4xx_resp_rcvd;
	uint64_t	sip_4xx_resp_sent;
	uint64_t	sip_5xx_resp_rcvd;
	uint64_t	sip_5xx_resp_sent;
	uint64_t	sip_6xx_resp_rcvd;
	uint64_t	sip_6xx_resp_sent;
	pthread_mutex_t	sip_counter_mutex; /* Mutex should be always at end */
} sip_traffic_counters_t;

/* SIP logfile structure */
typedef struct sip_logfile_s {
	boolean_t	sip_logging_enabled;
	FILE		*sip_logfile;
	pthread_mutex_t	sip_logfile_mutex;
} sip_logfile_t;

typedef struct sip_msg_chain_s {
	char			*sip_msg;
	int			msg_seq;
	time_t			msg_timestamp;
	struct sip_msg_chain_s *next;
}sip_msg_chain_t;

typedef struct sip_log_s {
	sip_msg_chain_t	*sip_msgs;
	int		sip_msgcnt;
}sip_log_t;

extern sip_traffic_counters_t sip_counters;

extern sip_logfile_t trans_log;
extern sip_logfile_t dialog_log;

extern boolean_t sip_manage_dialog;

/* To salt the hash function */
extern uint64_t	sip_hash_salt;

extern void		sip_timeout_init();
extern uint_t		sip_timeout(void *, void (*)(void *), struct timeval *);
extern boolean_t	sip_untimeout(uint_t);
extern void		sip_md5_hash(char *, int, char *, int, char *, int,
			    char *, int, char *, int, char *, int, uchar_t *);
extern void		sip_measure_traffic(boolean_t, sip_method_t, int,
			    boolean_t, int);
extern void		sip_add_log(sip_log_t *, sip_msg_t, int, int);
extern void		sip_write_to_log(void *, int, char *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _SIP_MISCDEFS_H */
