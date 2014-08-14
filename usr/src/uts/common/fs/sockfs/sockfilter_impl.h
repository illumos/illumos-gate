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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SOCKFS_SOCKFILTER_H
#define	_SOCKFS_SOCKFILTER_H

#include <sys/kstat.h>
#include <sys/list.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockfilter.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct sonode;
struct sockparams;

typedef struct sof_module	sof_module_t;
typedef struct sof_entry_kstat	sof_entry_kstat_t;
typedef struct sof_entry	sof_entry_t;
typedef struct sof_instance	sof_instance_t;
typedef struct sof_kstat	sof_kstat_t;

#define	SOF_MAXNAMELEN		FILNAME_MAX
#define	SOF_MAXSOCKTUPLECNT	32
#define	SOF_MODPATH		SOCKMOD_PATH

struct sof_module {
	char		*sofm_name;
	sof_ops_t	sofm_ops;
	uint_t		sofm_refcnt;
	list_node_t	sofm_node;
};

struct sof_kstat {
	kstat_named_t	sofks_defer_closed;
	kstat_named_t	sofks_defer_close_backlog;
	kstat_named_t	sofks_defer_close_failed_backlog_too_big;
};

#define	SOF_GLOBAL_STAT_BUMP(s) \
	atomic_inc_64(&sof_stat.sofks_##s.value.ui64)

/*
 * Per filter statistics.
 */
struct sof_entry_kstat {
	kstat_named_t	sofek_nactive;		/* # of consumers */
	kstat_named_t	sofek_tot_active_attach;
	kstat_named_t	sofek_tot_passive_attach;
	kstat_named_t	sofek_ndeferred; 	/* # of deferred conns */
	kstat_named_t	sofek_attach_failures;
};

/*
 * Socket filter entry - one for each configured filter (added and
 * removed by soconfig(1M)).
 *
 * sofe_flags, sofe_refcnt and sofe_mod are protected by sofe_lock, and all
 * other fields are write once.
 */
struct sof_entry {
	char		sofe_name[SOF_MAXNAMELEN];	/* filter name */
	char		sofe_modname[MODMAXNAMELEN];	/* filter module */
	sof_hint_t	sofe_hint;			/* order hint */
	char		*sofe_hintarg;			/* hint argument */
	list_node_t	sofe_node;			/* global list node */
	uint_t		sofe_socktuple_cnt;		/* # of socket tuples */
	sof_socktuple_t	*sofe_socktuple;		/* socket tuple list */

	sof_entry_kstat_t sofe_kstat;			/* filter stats */
	kstat_t		*sofe_ksp;

	kmutex_t	sofe_lock;
	char		sofe_flags;			/* SOFEF_* flags */
	uint_t		sofe_refcnt;			/* # of instances */
	sof_module_t	*sofe_mod;			/* filter module */
};

/* Filter entry flags */
#define	SOFEF_AUTO	0x1	/* automatic filter */
#define	SOFEF_PROG	0x2	/* programmatic filter */
#define	SOFEF_CONDEMED	0x4	/* removed by soconfig(1M) */

/*
 * Socket filter instance - one for each socket using a sof_entry_t
 */
struct sof_instance {
	sof_ops_t	*sofi_ops;	/* filter ops */
	void		*sofi_cookie;	/* filter cookie (from attach) */
	char		sofi_flags;	/* instance flags (SOFIF_*) */
	sof_instance_t	*sofi_prev;	/* up the stack */
	sof_instance_t	*sofi_next;	/* down the stack */
	struct sonode	*sofi_sonode;	/* socket instance is attached to */
	sof_entry_t	*sofi_filter;	/* filter this is an instance of */
};

/* Filter instance flags */
#define	SOFIF_BYPASS		0x1	/* filter does not want any callbacks */
#define	SOFIF_DEFER		0x2	/* defer notification of socket */
#define	SOFIF_RCV_FLOWCTRL	0x4	/* flow control recv path */
#define	SOFIF_SND_FLOWCTRL	0x8	/* flow control send path */

#define	SOF_STAT_ADD(i, s, v) \
	atomic_add_64(&(i)->sofi_filter->sofe_kstat.sofek_##s.value.ui64, (v))

extern void	sof_init(void);

extern void 	sof_entry_free(sof_entry_t *);
extern int	sof_entry_add(sof_entry_t *);
extern sof_entry_t *sof_entry_remove_by_name(const char *);
extern int 	sof_entry_proc_sockparams(sof_entry_t *, struct sockparams *);

extern int	sof_sockparams_init(struct sockparams *);
extern void	sof_sockparams_fini(struct sockparams *);

extern int	sof_sonode_autoattach_filters(struct sonode *, cred_t *);
extern int	sof_sonode_inherit_filters(struct sonode *, struct sonode *);
extern void	sof_sonode_closing(struct sonode *);
extern void	sof_sonode_cleanup(struct sonode *);
extern void	sof_sonode_notify_filters(struct sonode *, sof_event_t,
    uintptr_t);
extern boolean_t sof_sonode_drop_deferred(struct sonode *);

extern int 	sof_setsockopt(struct sonode *, int, const void *, socklen_t,
    struct cred *);
extern int 	sof_getsockopt(struct sonode *, int, void *, socklen_t *,
    struct cred *);

extern int	sof_rval2errno(sof_rval_t);

#define	SOF_INTERESTED(inst, op)			\
	(!((inst)->sofi_flags & SOFIF_BYPASS) &&	\
	(inst)->sofi_ops->sofop_##op != NULL)

/*
 * SOF_FILTER_OP traverses the filter stack for sonode `so' top-down,
 * calling `op' for each filter with the supplied `args'. A non-negative
 * return value indicates that a filter action was taken.
 */
#define	__SOF_FILTER_OP(so, op, cr, ...) 		\
	sof_instance_t *__inst;					\
	sof_rval_t __rval;					\
								\
	for (__inst = (so)->so_filter_top; __inst != NULL;	\
	    __inst = __inst->sofi_next) {			\
		if (!SOF_INTERESTED(__inst, op))		\
			continue;				\
		__rval = (__inst->sofi_ops->sofop_##op)((sof_handle_t)__inst,\
		    __inst->sofi_cookie, __VA_ARGS__, cr);	\
		DTRACE_PROBE2(filter__action, (sof_instance_t), __inst,\
		    (sof_rval_t), __rval);			\
		if (__rval != SOF_RVAL_CONTINUE) 		\
			return (sof_rval2errno(__rval));	\
	}							\
	return (-1);

extern mblk_t	*sof_filter_data_out_from(struct sonode *so,
    sof_instance_t *, mblk_t *, struct nmsghdr *, cred_t *, int *);
extern mblk_t	*sof_filter_data_in_proc(struct sonode *so,
    mblk_t *, mblk_t **);
extern int	sof_filter_bind(struct sonode *, struct sockaddr *,
    socklen_t *, cred_t *);
extern int	sof_filter_listen(struct sonode *, int *, cred_t *);
extern int	sof_filter_connect(struct sonode *, struct sockaddr *,
    socklen_t *, cred_t *);
extern int	sof_filter_accept(struct sonode *, cred_t *);
extern int	sof_filter_shutdown(struct sonode *, int *, cred_t *);
extern int 	sof_filter_getsockname(struct sonode *, struct sockaddr *,
    socklen_t *, cred_t *);
extern int 	sof_filter_getpeername(struct sonode *, struct sockaddr *,
    socklen_t *, cred_t *);
extern int	sof_filter_setsockopt(struct sonode *, int, int, void *,
    socklen_t *, cred_t *);
extern int	sof_filter_getsockopt(struct sonode *, int, int, void *,
    socklen_t *, cred_t *);
extern int	sof_filter_ioctl(struct sonode *, int, intptr_t, int,
    int32_t *, cred_t *);

#define	SOF_FILTER_DATA_OUT(so, mp, msg, cr, errp) \
	sof_filter_data_out_from(so, (so)->so_filter_top, mp, msg, cr, errp)
#define	SOF_FILTER_DATA_OUT_FROM(so, inst, mp, msg, cr, errp) \
	sof_filter_data_out_from(so, inst, mp, msg, cr, errp)

#ifdef	__cplusplus
}
#endif

#endif	/* _SOCKFS_SOCKFILTER_H */
