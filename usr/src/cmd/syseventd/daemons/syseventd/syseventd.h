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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYSEVENTD_H
#define	_SYSEVENTD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_SLM			20	/* Max sysevent loadable modules */
#define	MAX_MODCTL_RETRY	3	/* Maximum number of modctl retries */
					/* for free and get data */
#define	LOGEVENT_BUFSIZE	1024	/* message size greater than this */
					/* requires another kernel trip */

/* Debug and errlogging stuff */
extern void syseventd_print(int level, char *message, ...);
extern void syseventd_err_print(char *message, ...);
extern void syseventd_exit(int status);
extern int debug_level;

/*
 * struct event_dispatch_pkg - per-client event dispatch package
 */
struct event_dispatch_pkg {
	hrtime_t			start_time; /* start time ev delivery */
	struct sysevent_client		*scp;	/* Client data */
	sysevent_t			*ev;	/* event buf to deliver */
	sema_t				*completion_sema;
	int				completion_state;
	int				completion_status;
	int				retry_count; /* running retry counter */
};

/* completion states */
#define	SE_NOT_DISPATCHED	0	/* Not yet dispatched to client */
#define	SE_OUTSTANDING		1	/* Dispatched and outstanding */
#define	SE_COMPLETE		2	/* Delivery complete */

/*
 * struct event_dispatchq - queue of dispatched event dispatch pacakges
 */
struct event_dispatchq {
	struct event_dispatchq		*next;
	struct event_dispatch_pkg	*d_pkg;
};

/*
 * struct ev_completion - event completion data
 *		This structure contains information regarding the
 *		event delivery status for each client dispatched.
 */
struct ev_completion {
	sysevent_t		*ev;		/* event */
	struct ev_completion   *next;
	struct event_dispatchq *dispatch_list; /* per_client dspatch packages */
	int			client_count;   /* Number of clients */
						/* event was dispatched to. */
	sema_t			client_sema;	/* Client completion */
						/* synchronization */
};

/*
 * module_t - SLM client module data
 */
typedef struct module {
struct module *next;
	char *name;
	void *dlhandle;
	int (*deliver_event)();
	struct slm_mod_ops *(*event_mod_init)();
	void (*event_mod_fini)();
} module_t;

/*
 * struct sysevent_client - per-client data
 */
struct sysevent_client {
	mutex_t			client_lock;	/* Lock for struct data */
	cond_t			client_cv;	/* Deliver cond variable */
	thread_t		tid;		/* Client deliver thread id */
	int			client_type;	/* SLM only */
	int			client_num;	/* Assigned at load time */
	int			client_flags;	/* Client flags */
	int			retry_limit;	/* Defined by slm_mod_ops */
	void			*client_data;	/* Client-type specific data */
	struct event_dispatchq	*eventq;	/* Client event queue */
};

/* Client types */
#define	SLM_CLIENT	0

/* Client flags */
#define	SE_CLIENT_UNLOADED	0
#define	SE_CLIENT_LOADED	0X00000001
#define	SE_CLIENT_SUSPENDED	0X00000002
#define	SE_CLIENT_THR_RUNNING	0X00000004

#define	SE_CLIENT_IS_UNLOADED(scp) \
	((scp)->client_flags == SE_CLIENT_UNLOADED)
#define	SE_CLIENT_IS_LOADED(scp) \
	((scp)->client_flags & SE_CLIENT_LOADED)
#define	SE_CLIENT_IS_SUSPENDED(scp) \
	((scp)->client_flags & SE_CLIENT_SUSPENDED)
#define	SE_CLIENT_IS_THR_RUNNING(scp) \
	((scp)->client_flags & SE_CLIENT_THR_RUNNING)


#ifdef	__cplusplus
}
#endif

#endif	/* _SYSEVENTD_H */
