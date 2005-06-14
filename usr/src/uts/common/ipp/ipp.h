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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_IPP_IPP_H
#define	_IPP_IPP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * IP Policy Framework (IPPF)
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/nvpair.h>
#include <sys/stream.h>
#include <sys/kstat.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

typedef struct ipp_mod		ipp_mod_t;
typedef int32_t			ipp_mod_id_t;

#define	IPP_MOD_RESERVED	0	/* Upper limit of reserved values */
#define	IPP_MOD_INVAL		-1

typedef	struct ipp_action	ipp_action_t;
typedef	int32_t			ipp_action_id_t;

#define	IPP_ACTION_RESERVED	0	/* Upper limit of reserved values */
#define	IPP_ACTION_INVAL	-1
#define	IPP_ACTION_CONT		-2
#define	IPP_ACTION_DEFER	-3
#define	IPP_ACTION_DROP		-4

#endif	/* _KERNEL */

#define	IPP_ANAME_CONT		"ipp.continue"
#define	IPP_ANAME_DEFER		"ipp.defer"
#define	IPP_ANAME_DROP		"ipp.drop"

typedef enum ipp_flags {
	IPP_DESTROY_REF = 0x00000001
} ipp_flags_t;

#ifdef	_KERNEL

typedef struct ipp_stat		ipp_stat_t;

/*
 * NOTE: Semi-opaque alias for struct ipp_stat_impl in common/ipp/ipp_impl.h
 */
struct ipp_stat {
	void	*ipps_data;
};

#define	IPP_STAT_TAG		0x80

#define	IPP_STAT_INT32		(IPP_STAT_TAG | KSTAT_DATA_INT32)
#define	IPP_STAT_UINT32		(IPP_STAT_TAG | KSTAT_DATA_UINT32)
#define	IPP_STAT_INT64		(IPP_STAT_TAG | KSTAT_DATA_INT64)
#define	IPP_STAT_UINT64		(IPP_STAT_TAG | KSTAT_DATA_UINT64)
#define	IPP_STAT_STRING		(IPP_STAT_TAG | KSTAT_DATA_CHAR)

#define	IPP_STAT_READ		KSTAT_READ
#define	IPP_STAT_WRITE		KSTAT_WRITE

typedef kstat_named_t		ipp_named_t;

typedef	struct ipp_class	ipp_class_t;
typedef	struct ipp_log		ipp_log_t;

typedef struct ipp_packet	ipp_packet_t;

#define	IPPO_REV_1	1
#define	IPPO_REV	IPPO_REV_1	/* interface version */

typedef struct ipp_ops	ipp_ops_t;

struct ipp_ops {
	int	ippo_rev;
	int	(*ippo_action_create)(ipp_action_id_t, nvlist_t **,
	    ipp_flags_t);
	int	(*ippo_action_modify)(ipp_action_id_t, nvlist_t **,
	    ipp_flags_t);
	int	(*ippo_action_destroy)(ipp_action_id_t, ipp_flags_t);
	int	(*ippo_action_info)(ipp_action_id_t, int (*)(nvlist_t *,
	    void *), void *, ipp_flags_t);
	int	(*ippo_action_invoke)(ipp_action_id_t, ipp_packet_t *);
};

/*
 * IPPF client interface
 */

extern int		ipp_list_mods(ipp_mod_id_t **, int *);

extern ipp_mod_id_t	ipp_mod_lookup(const char *);
extern int		ipp_mod_name(ipp_mod_id_t, char **);
extern int		ipp_mod_register(const char *, ipp_ops_t *);
extern int		ipp_mod_unregister(ipp_mod_id_t);
extern int		ipp_mod_list_actions(ipp_mod_id_t, ipp_action_id_t **,
    int *);

extern ipp_action_id_t	ipp_action_lookup(const char *);
extern int		ipp_action_name(ipp_action_id_t, char **);
extern int		ipp_action_mod(ipp_action_id_t, ipp_mod_id_t *);
extern int		ipp_action_create(ipp_mod_id_t, const char *,
    nvlist_t **, ipp_flags_t, ipp_action_id_t *);
extern int		ipp_action_modify(ipp_action_id_t, nvlist_t **,
    ipp_flags_t);
extern int		ipp_action_destroy(ipp_action_id_t, ipp_flags_t);
extern int		ipp_action_info(ipp_action_id_t, int (*)(nvlist_t *,
    void *), void *, ipp_flags_t);
extern void		ipp_action_set_ptr(ipp_action_id_t, void *);
extern void		*ipp_action_get_ptr(ipp_action_id_t);
extern int		ipp_action_ref(ipp_action_id_t,	ipp_action_id_t,
    ipp_flags_t);
extern int		ipp_action_unref(ipp_action_id_t, ipp_action_id_t,
    ipp_flags_t);

extern int		ipp_packet_alloc(ipp_packet_t **, const char *,
    ipp_action_id_t);
extern void		ipp_packet_free(ipp_packet_t *);
extern int		ipp_packet_add_class(ipp_packet_t *, const char *,
    ipp_action_id_t);
extern int		ipp_packet_process(ipp_packet_t **);
extern int		ipp_packet_next(ipp_packet_t *, ipp_action_id_t);
extern void		ipp_packet_set_data(ipp_packet_t *, mblk_t *);
extern mblk_t		*ipp_packet_get_data(ipp_packet_t *);
extern void		ipp_packet_set_private(ipp_packet_t *, void *,
    void (*)(void *));
extern void		*ipp_packet_get_private(ipp_packet_t *);

extern int		ipp_stat_create(ipp_action_id_t, const char *, int,
    int (*)(ipp_stat_t *, void *, int), void *, ipp_stat_t **);
extern void		ipp_stat_install(ipp_stat_t *);
extern void		ipp_stat_destroy(ipp_stat_t *);
extern int		ipp_stat_named_init(ipp_stat_t *, const char *,
    uchar_t, ipp_named_t *);
extern int		ipp_stat_named_op(ipp_named_t *, void *, int);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _IPP_IPP_H */
