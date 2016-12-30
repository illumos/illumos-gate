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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_HWCONF_H
#define	_SYS_HWCONF_H

#include <sys/dditypes.h>
#include <sys/ddipropdefs.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_HWC_LINESIZE 1024

struct hwc_class {
	struct hwc_class *class_next;
	char *class_exporter;
	char *class_name;
};

struct hwc_spec {
	struct hwc_spec *hwc_next;
	char		*hwc_parent_name;
	char		*hwc_class_name;
	char		*hwc_devi_name;
	ddi_prop_t	*hwc_devi_sys_prop_ptr;
	/* For hashing */
	struct hwc_spec	*hwc_hash_next;
	major_t		hwc_major;
};

/*
 * used to create sorted linked lists of hwc_spec structs for loading parents
 */
struct par_list {
	struct par_list	*par_next;
	struct hwc_spec	*par_specs;		/* List of prototype nodes */
	major_t		par_major;		/* Simple name of parent */
};

struct bind {
	struct bind 	*b_next;
	char		*b_name;
	char		*b_bind_name;
	int		b_num;
};

typedef struct mperm {
	struct mperm	*mp_next;
	char		*mp_minorname;
	mode_t		mp_mode;
	uid_t		mp_uid;
	gid_t		mp_gid;
#ifndef _KERNEL
	char		*mp_drvname;
	char		*mp_owner;
	char		*mp_group;
#endif	/* !_KERNEL */
} mperm_t;

#ifdef _KERNEL

extern struct bind *mb_hashtab[];
extern struct bind *sb_hashtab[];

extern int hwc_parse(char *, struct par_list **, ddi_prop_t **);
extern struct par_list *impl_make_parlist(major_t);
extern int impl_free_parlist(major_t);
extern void impl_delete_par_list(struct par_list *);
extern int impl_parlist_to_major(struct par_list *, char []);
extern struct hwc_spec *hwc_get_child_spec(dev_info_t *, major_t);
extern void hwc_free_spec_list(struct hwc_spec *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HWCONF_H */
