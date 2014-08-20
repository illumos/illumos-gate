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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * nislib.h
 *
 * This file contains the interfaces that are visible in the SunOS 5.x
 * implementation of NIS Plus.
 */

#ifndef	_RPCSVC_NISLIB_H
#define	_RPCSVC_NISLIB_H


#ifdef __cplusplus
extern "C" {
#endif

extern name_pos nis_dir_cmp(nis_name, nis_name);

extern nis_name nis_domain_of(nis_name);
extern nis_name nis_leaf_of(nis_name);
extern nis_name nis_leaf_of_r(const nis_name, char *, size_t);
extern nis_name nis_name_of(nis_name);
extern nis_name nis_local_group(void);
extern nis_name nis_local_directory(void);
extern nis_name nis_local_host(void);

extern void nis_destroy_object(nis_object *);
extern nis_object *nis_clone_object(nis_object *, nis_object *);
extern nis_object *nis_read_obj(char *);
extern int nis_write_obj(char *, nis_object *);

extern void *nis_get_static_storage(struct nis_sdata *, uint_t, uint_t);
extern nis_name __nis_rpc_domain(void);

CLIENT *__nis_clnt_create(int, struct netconfig *, char *, struct netbuf *,
			int, int, int, int, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _RPCSVC_NISLIB_H */
