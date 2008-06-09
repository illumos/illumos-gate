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

/*
 * Brand helper libraries must name their ops vector using this macro.
 */
#ifdef _LP64
#ifdef _ELF64
#define	RTLD_DB_BRAND_OPS rtld_db_brand_ops64
#else /* !_ELF64 */
#define	RTLD_DB_BRAND_OPS rtld_db_brand_ops32
#endif /* !_ELF64 */
#else /* !_LP64 */
#define	RTLD_DB_BRAND_OPS rtld_db_brand_ops32
#endif /* !_LP64 */

/*
 * State kept for brand helper libraries
 *
 * All librtld_db brand plugin libraries need to specify a Lmid_t value
 * that controls how link map ids are assigned to native solaris objects
 * (as pointed to by the processes aux vectors) which are enumerated by
 * librtld_db.  In most cases this value will either be LM_ID_NONE or
 * LM_ID_BRAND.
 *
 * If LM_ID_NONE is specified in the structure below, then when native solaris
 * objects are enumerated by librtld_db, their link map id values will match
 * the link map ids assigned to those objects by the solaris linker within
 * the target process.
 *
 * If LM_ID_BRAND is specified in the structure below, then when native solaris
 * objects are enumerated by librtld_db, their link map id value will be
 * explicity set to LM_ID_BRAND, regardless of the link map ids assigned to
 * those objects by the solaris linker within the target process.
 *
 * In all cases the librtld_db brand plugin library can report any link
 * map id value that it wants for objects that it enumerates via it's
 * rho_loadobj_iter() entry point.
 */
typedef struct __rd_helper_data	*rd_helper_data_t;
typedef struct rd_helper_ops {
	Lmid_t			rho_lmid;
	rd_helper_data_t	(*rho_init)(rd_agent_t *,
				    struct ps_prochandle *);
	void			(*rho_fini)(rd_helper_data_t);
	int			(*rho_loadobj_iter)(rd_helper_data_t,
				    rl_iter_f *, void *);
	rd_err_e		(*rho_get_dyns)(rd_helper_data_t,
				    psaddr_t, void **, size_t *);
} rd_helper_ops_t;

typedef struct rd_helper {
	void			*rh_dlhandle;
	rd_helper_ops_t		*rh_ops;
	rd_helper_data_t	rh_data;
} rd_helper_t;

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

extern rd_err_e		_rd_event_enable32(rd_agent_t *, int);
extern rd_err_e		_rd_event_getmsg32(rd_agent_t *, rd_event_msg_t *);
extern rd_err_e		_rd_get_dyns32(struct rd_agent *,
			    psaddr_t, Dyn **, size_t *);
extern rd_err_e		_rd_get_ehdr32(struct rd_agent *,
			    psaddr_t, Ehdr *, uint_t *);
extern rd_err_e		_rd_objpad_enable32(struct rd_agent *, size_t);
extern rd_err_e		_rd_loadobj_iter32(rd_agent_t *, rl_iter_f *, void *);
extern rd_err_e		_rd_reset32(struct rd_agent *);
extern rd_err_e		find_dynamic_ent32(struct rd_agent *, psaddr_t,
			    Xword, Dyn *);
extern rd_err_e		plt32_resolution(rd_agent_t *, psaddr_t, lwpid_t,
			    psaddr_t, rd_plt_info_t *);
extern rd_err_e		validate_rdebug32(struct rd_agent *rap);
#ifdef _LP64
extern rd_err_e		_rd_event_enable64(rd_agent_t *, int);
extern rd_err_e		_rd_event_getmsg64(rd_agent_t *, rd_event_msg_t *);
extern rd_err_e		_rd_get_dyns64(struct rd_agent *,
			    psaddr_t, Elf64_Dyn **, size_t *);
extern rd_err_e		_rd_get_ehdr64(struct rd_agent *,
			    psaddr_t, Elf64_Ehdr *, uint_t *);
extern rd_err_e		_rd_objpad_enable64(struct rd_agent *, size_t);
extern rd_err_e		_rd_loadobj_iter64(rd_agent_t *, rl_iter_f *, void *);
extern rd_err_e		_rd_reset64(struct rd_agent *);
extern rd_err_e		find_dynamic_ent64(struct rd_agent *, psaddr_t,
			    Xword, Elf64_Dyn *);
extern rd_err_e		plt64_resolution(rd_agent_t *, psaddr_t, lwpid_t,
			    psaddr_t, rd_plt_info_t *);
extern rd_err_e		validate_rdebug64(struct rd_agent *rap);
#endif

#ifdef	__cplusplus
}
#endif

#endif /* __RTLD_DB_H */
