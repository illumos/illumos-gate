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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_IPP_IPP_IMPL_H
#define	_IPP_IPP_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * IP Policy Framework (IPPF) implementation detail.
 *
 * WARNING: Everything in this file is private, belonging to the IPPF
 * subsystem.  The interfaces and declarations made here are subject
 * to change.
 */

#include <sys/stream.h>
#include <sys/thread.h>
#include <ipp/ipp.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

#define	IPP_ALIGN		64

#define	IPP_NBUCKET		23

#define	IPP_LOG2NACTION		16
#define	IPP_NACTION		(1 << IPP_LOG2NACTION)

#define	IPP_LOG2NMOD		6
#define	IPP_NMOD		(1 << IPP_LOG2NMOD)

#define	IPP_NCLASS		5
#define	IPP_NLOG		IPP_NMOD

typedef	struct ipp_ref	ipp_ref_t;

struct ipp_ref {
	ipp_ref_t		*ippr_nextp;
	uint_t			ippr_count;
	union {
	    ipp_mod_t		*u_mod;
	    ipp_action_t	*u_action;
	    void		*u_ptr;
	} ippr_u;
};

#define	ippr_action	ippr_u.u_action
#define	ippr_mod	ippr_u.u_mod
#define	ippr_ptr	ippr_u.u_ptr

typedef enum {
	IPP_MODSTATE_PROTO = 0x10,
	IPP_MODSTATE_AVAILABLE
} ipp_modstate_t;

struct ipp_mod {
	ipp_mod_id_t	ippm_id;
	ipp_ops_t	*ippm_ops;
	ipp_ref_t	*ippm_action;
	ipp_modstate_t	ippm_state;
	krwlock_t	ippm_lock[1];
	uint32_t	ippm_hold_count;
	boolean_t	ippm_destruct_pending;
	char		ippm_name[MAXNAMELEN];
};

typedef enum {
	IPP_ASTATE_PROTO = 0x20,
	IPP_ASTATE_CONFIG_PENDING,
	IPP_ASTATE_AVAILABLE
} ipp_astate_t;

typedef struct cfglock {
	kmutex_t	cl_mutex[1];
	kcondvar_t	cl_cv[1];
	uint_t		cl_writers;
	boolean_t	cl_reader;
	kthread_id_t	cl_owner;
} cfglock_t;

#ifndef	__lint

#define	CL_READ		0
#define	CL_WRITE	1

#define	CONFIG_LOCK_INIT(_clp)						\
	{								\
		mutex_init((_clp)->cl_mutex, NULL, MUTEX_DEFAULT,	\
		    (void *)ipltospl(LOCK_LEVEL));			\
		cv_init((_clp)->cl_cv, NULL, CV_DEFAULT, NULL);		\
	}

#define	CONFIG_LOCK_FINI(_clp)						\
	{								\
		mutex_destroy((_clp)->cl_mutex);			\
		cv_destroy((_clp)->cl_cv);				\
	}

#define	CONFIG_LOCK_ENTER(_clp, _rw)					\
	{								\
		mutex_enter((_clp)->cl_mutex);				\
		if ((_rw) == CL_WRITE) {				\
			while ((_clp)->cl_reader ||			\
			    ((_clp)->cl_owner != NULL &&		\
			    (_clp)->cl_owner != curthread))		\
				cv_wait((_clp)->cl_cv,			\
				    (_clp)->cl_mutex);			\
			(_clp)->cl_owner = curthread;			\
			(_clp)->cl_writers++;				\
		}							\
		else if ((_rw) == CL_READ) {				\
			while ((_clp)->cl_reader ||			\
			    (_clp)->cl_writers > 0) {			\
				ASSERT((_clp)->cl_owner != curthread);	\
				cv_wait((_clp)->cl_cv,			\
				    (_clp)->cl_mutex);			\
			}						\
			(_clp)->cl_owner = curthread;			\
			(_clp)->cl_reader = B_TRUE;			\
		}							\
		mutex_exit((_clp)->cl_mutex);				\
	}

#define	CONFIG_LOCK_EXIT(_clp)						\
	{								\
		mutex_enter((_clp)->cl_mutex);				\
		if ((_clp)->cl_reader) {				\
			(_clp)->cl_reader = B_FALSE;			\
			(_clp)->cl_owner = NULL;			\
			cv_broadcast((_clp)->cl_cv);			\
		} else {						\
			ASSERT((_clp)->cl_writers != 0);		\
			(_clp)->cl_writers--;				\
			if ((_clp)->cl_writers == 0) {			\
				(_clp)->cl_owner = NULL;		\
				cv_broadcast((_clp)->cl_cv);		\
			}						\
		}							\
		mutex_exit((_clp)->cl_mutex);				\
	}

#else	/* __lint */

#define	CONFIG_LOCK_INIT(_clp)
#define	CONFIG_LOCK_FINI(_clp)
#define	CONFIG_LOCK_ENTER(_clp, _rw)
#define	CONFIG_LOCK_EXIT(_clp)

#endif	/* __lint */

struct ipp_action {
	ipp_action_id_t	ippa_id;
	ipp_mod_t	*ippa_mod;
	ipp_ref_t	*ippa_ref;
	ipp_ref_t	*ippa_refby;
	void		*ippa_ptr;
	uint32_t	ippa_packets;
	ipp_astate_t	ippa_state;
	krwlock_t	ippa_lock[1];
	uint32_t	ippa_hold_count;
	boolean_t	ippa_destruct_pending;
	cfglock_t	ippa_config_lock[1];
	boolean_t	ippa_nameless;
	char		ippa_name[MAXNAMELEN];
	ipp_ref_t	**ippa_condemned;
};

struct ipp_class {
	ipp_action_id_t	ippc_aid;
	char		ippc_name[MAXNAMELEN];
};

struct ipp_log {
	ipp_action_id_t	ippl_aid;
	timespec_t	ippl_begin;
	timespec_t	ippl_end;
	char		ippl_name[MAXNAMELEN];
};

typedef struct ipp_stat_impl	ipp_stat_impl_t;

struct ipp_stat_impl {
	void		*ippsi_data;
	kstat_t		*ippsi_ksp;
	int		ippsi_limit;
	int		ippsi_count;
	int		(*ippsi_update)(ipp_stat_t *, void *, int);
	void		*ippsi_arg;
	kmutex_t	ippsi_lock[1];
	char		ippsi_name[MAXNAMELEN];
};

struct ipp_packet {
	mblk_t		*ippp_data;
	ipp_class_t	*ippp_class_array;
	uint_t		ippp_class_limit;
	uint_t		ippp_class_rindex;
	uint_t		ippp_class_windex;
	ipp_log_t	*ippp_log;
	uint_t		ippp_log_limit;
	uint_t		ippp_log_windex;
	void		*ippp_private;
	void		(*ippp_private_free)(void *);
};

extern void		ipp_init(void);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _IPP_IPP_IMPL_H */
