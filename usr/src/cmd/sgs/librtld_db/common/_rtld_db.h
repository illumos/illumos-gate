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

#ifndef	__RTLD_DB_H
#define	__RTLD_DB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <proc_service.h>
#include <thread.h>
#include <synch.h>
#include <sgs.h>
#include <machdep.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct rd_agent {
	mutex_t				rd_mutex;
	struct ps_prochandle		*rd_psp;	/* prochandle pointer */
	psaddr_t			rd_rdebug;	/* rtld r_debug */
	psaddr_t			rd_preinit;	/* rtld_db_preinit */
	psaddr_t			rd_postinit;	/* rtld_db_postinit */
	psaddr_t			rd_dlact;	/* rtld_db_dlact */
	psaddr_t			rd_tbinder;	/* tail of binder */
	psaddr_t			rd_rtlddbpriv;	/* rtld rtld_db_priv */
	ulong_t				rd_flags;	/* flags */
	ulong_t				rd_rdebugvers;	/* rtld_db_priv.vers */
	int				rd_dmodel;	/* data model */
	rd_helper_t			rd_helper;	/* private to helper */
};

/*
 * Values for rd_flags
 */
#define	RDF_FL_COREFILE		0x0001		/* client is core file image */



#define	RDAGLOCK(x)	(void) mutex_lock(&(x->rd_mutex));
#define	RDAGUNLOCK(x)	(void) mutex_unlock(&(x->rd_mutex));
#define	LOG(func)	{						\
				(void) mutex_lock(&glob_mutex);		\
				if (rtld_db_logging)			\
					func;				\
				(void) mutex_unlock(&glob_mutex);	\
			}

extern mutex_t		glob_mutex;
extern int		rtld_db_version;
extern int		rtld_db_logging;

extern rd_err_e		rd_binder_exit_addr(struct rd_agent *, const char *,
				psaddr_t *);
extern rd_err_e		_rd_reset32(struct rd_agent *);
extern rd_err_e		_rd_event_enable32(rd_agent_t *, int);
extern rd_err_e		_rd_event_getmsg32(rd_agent_t *, rd_event_msg_t *);
extern rd_err_e		_rd_objpad_enable32(struct rd_agent *, size_t);
extern rd_err_e		_rd_loadobj_iter32(rd_agent_t *, rl_iter_f *, void *);
extern rd_err_e		find_dynamic_ent32(struct rd_agent *, psaddr_t,
			    Xword, Dyn *);

extern rd_err_e		plt32_resolution(rd_agent_t *, psaddr_t, lwpid_t,
			    psaddr_t, rd_plt_info_t *);
#ifdef _LP64
extern rd_err_e		_rd_reset64(struct rd_agent *);
extern rd_err_e		_rd_event_enable64(rd_agent_t *, int);
extern rd_err_e		_rd_event_getmsg64(rd_agent_t *, rd_event_msg_t *);
extern rd_err_e		_rd_objpad_enable64(struct rd_agent *, size_t);
extern rd_err_e		_rd_loadobj_iter64(rd_agent_t *, rl_iter_f *, void *);
extern rd_err_e		find_dynamic_ent64(struct rd_agent *, psaddr_t,
			    Xword, Elf64_Dyn *);
extern rd_err_e		plt64_resolution(rd_agent_t *, psaddr_t, lwpid_t,
			    psaddr_t, rd_plt_info_t *);
#endif

#ifdef	__cplusplus
}
#endif

#endif /* __RTLD_DB_H */
