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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#ifndef	_SYS_ESUNDDI_H
#define	_SYS_ESUNDDI_H
#include <sys/sunddi.h>
#include <sys/proc.h>
#include <sys/autoconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/epm.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/*
 * esunddi.h:		Function prototypes for kernel ddi functions.
 *	Note that drivers calling these functions are not
 *	portable.
 */

int
e_ddi_prop_create(dev_t dev, dev_info_t *dip, int flag,
	char *name, caddr_t value, int length);

int
e_ddi_prop_modify(dev_t dev, dev_info_t *dip, int flag,
	char *name, caddr_t value, int length);

int
e_ddi_prop_update_int(dev_t match_dev, dev_info_t *dip,
	char *name, int data);

int
e_ddi_prop_update_int64(dev_t match_dev, dev_info_t *dip,
    char *name, int64_t data);

int
e_ddi_prop_update_int_array(dev_t match_dev, dev_info_t *dip,
    char *name, int *data, uint_t nelements);

int
e_ddi_prop_update_int64_array(dev_t match_dev, dev_info_t *dip,
    char *name, int64_t *data, uint_t nelements);

int
e_ddi_prop_update_string(dev_t match_dev, dev_info_t *dip,
	char *name, char *data);

int
e_ddi_prop_update_string_array(dev_t match_dev, dev_info_t *dip,
    char *name, char **data, uint_t nelements);

int
e_ddi_prop_update_byte_array(dev_t match_dev, dev_info_t *dip,
    char *name, uchar_t *data, uint_t nelements);

int
e_ddi_prop_remove(dev_t dev, dev_info_t *dip, char *name);

void
e_ddi_prop_remove_all(dev_info_t *dip);

int
e_ddi_prop_undefine(dev_t dev, dev_info_t *dip, int flag, char *name);

int
e_ddi_getprop(dev_t dev, vtype_t type, char *name, int flags, int defaultval);

int64_t
e_ddi_getprop_int64(dev_t dev, vtype_t type, char *name,
	int flags, int64_t defvalue);

int
e_ddi_getproplen(dev_t dev, vtype_t type, char *name, int flags, int *lengthp);

int
e_ddi_getlongprop(dev_t dev, vtype_t type, char *name, int flags,
	caddr_t valuep, int *lengthp);

int
e_ddi_getlongprop_buf(dev_t dev, vtype_t type, char *name, int flags,
	caddr_t valuep, int *lengthp);

int
e_ddi_parental_suspend_resume(dev_info_t *dip);

int
e_ddi_resume(dev_info_t *dip, ddi_attach_cmd_t);

int
e_ddi_suspend(dev_info_t *dip, ddi_detach_cmd_t cmd);

void
pm_init(void);

void
e_ddi_prop_list_delete(ddi_prop_t *proplist);

int
e_ddi_copyfromdev(dev_info_t *, off_t, const void *, void *, size_t);

int
e_ddi_copytodev(dev_info_t *, off_t, const void *, void *, size_t);

/*
 * return codes for devi_stillreferenced()
 *
 * DEVI_REFERENCED	- specfs has open minor device(s) for the devinfo
 * DEVI_NOT_REFERENCED	- specfs has no open minor device for the devinfo
 */
#define	DEVI_REFERENCED		1
#define	DEVI_NOT_REFERENCED	0

int
devi_stillreferenced(dev_info_t *dip);

extern int (*pm_platform_power)(power_req_t *);

/*
 * A consolidation private function which is essentially equivalent to
 * ddi_umem_lock but with the addition of arguments ops_vector and procp.
 * The procp argument can be eliminated eventually as part of proper
 * dynamic reconfiguration callback implementation.
 *
 * The valid flag values are those used for ddi_umem_lock plus an
 * additional flag (DDI_UMEMLOCK_LONGTERM) which must be set when the
 * locking will be maintained for an indefinitely long period (essentially
 * permanent), rather than for what would be required for a typical I/O
 * completion.  When DDI_UMEMLOCK_LONGTERM is set, umem_lockmemory will
 * return EFAULT if the memory pertains to a regular file which is
 * mapped MAP_SHARED.  This is to prevent a deadlock in the pvn routines
 * if a file truncation is attempted after the locking is done.
 */
int
umem_lockmemory(caddr_t addr, size_t size, int flags,
		ddi_umem_cookie_t *cookie,
		struct umem_callback_ops *ops_vector,
		proc_t *procp);

#define	DDI_UMEMLOCK_LONGTERM	0x04

/*
 * These are evolving forms of the ddi function ddi_hold_devi_by_instance.
 * Like ddi_hold_devi_by_instance, the hold should be released with
 * ddi_release_devi.
 */
dev_info_t	*
e_ddi_hold_devi_by_dev(dev_t dev, int flags);

dev_info_t	*
e_ddi_hold_devi_by_path(char *path, int flags);

/* {e_}ddi_hold_devi{_by{instance|dev|path}} flags */
#define	E_DDI_HOLD_DEVI_NOATTACH	0x01

void
e_ddi_hold_devi(dev_info_t *);

/*
 * Return the reference count on a devinfo node. The caller can determine,
 * with knowledge of its own holds, if the devinfo node is still in use.
 */
int
e_ddi_devi_holdcnt(dev_info_t *dip);

/*
 * Perform path reconstruction given a major and instance. Does not
 * drive attach of the path.
 */
int
e_ddi_majorinstance_to_path(major_t major, int instance, char *name);

/*
 * walk all devinfo nodes linked on the driver list
 */
void
e_ddi_walk_driver(char *, int (*f)(dev_info_t *, void *), void *);

/*
 * Given the nodeid for a persistent node, find the corresponding
 * devinfo node.
 * NOTE: .conf nodeids are not valid arguments to this function.
 */
dev_info_t *
e_ddi_nodeid_to_dip(pnode_t nodeid);

/*
 * Defines for DR interfaces
 */
#define	DEVI_BRANCH_CHILD	0x01	/* Walk immediate children of root  */
#define	DEVI_BRANCH_CONFIGURE	0x02	/* Configure branch after create    */
#define	DEVI_BRANCH_DESTROY	0x04	/* Destroy branch after unconfigure */
#define	DEVI_BRANCH_EVENT	0x08	/* Post NDI event		    */
#define	DEVI_BRANCH_PROM	0x10	/* Branches derived from PROM nodes */
#define	DEVI_BRANCH_SID		0x20	/* SID node branches		    */
#define	DEVI_BRANCH_ROOT	0x40	/* Node is the root of a branch	    */

typedef struct devi_branch {
	void		*arg;
	void		(*devi_branch_callback)(dev_info_t *, void *, uint_t);
	int		type;
	union {
		int	(*prom_branch_select)(pnode_t, void *, uint_t);
		int	(*sid_branch_create)(dev_info_t *, void *, uint_t);
	} create;
} devi_branch_t;

extern int e_ddi_branch_create(dev_info_t *pdip, devi_branch_t *bp,
    dev_info_t **dipp, uint_t flags);
extern int e_ddi_branch_configure(dev_info_t *rdip, dev_info_t **dipp,
    uint_t flags);
extern int e_ddi_branch_unconfigure(dev_info_t *rdip, dev_info_t **dipp,
    uint_t flags);
extern int e_ddi_branch_destroy(dev_info_t *rdip, dev_info_t **dipp,
    uint_t flags);
extern void e_ddi_branch_hold(dev_info_t *rdip);
extern void e_ddi_branch_rele(dev_info_t *rdip);
extern int e_ddi_branch_held(dev_info_t *rdip);
extern int e_ddi_branch_referenced(dev_info_t *rdip,
    int (*cb)(dev_info_t *dip, void *, uint_t), void *arg);

/*
 * Obsolete interfaces, no longer used, to be removed.
 * Retained only for driver compatibility.
 */
void
e_ddi_enter_driver_list(struct devnames *, int *);	/* obsolete */

int
e_ddi_tryenter_driver_list(struct devnames *, int *);	/* obsolete */

void
e_ddi_exit_driver_list(struct devnames *, int);		/* obsolete */


#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_ESUNDDI_H */
