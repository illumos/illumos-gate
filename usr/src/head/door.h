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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DOOR_H
#define	_DOOR_H

#include <sys/types.h>
#include <sys/door.h>
#include <ucred.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _ASM

/*
 * Doors API
 */

typedef void door_server_procedure_t(void *, char *, size_t, door_desc_t *,
    uint_t);

int	door_create(door_server_procedure_t *, void *, uint_t);
int	door_revoke(int);
int	door_info(int, door_info_t *);
int	door_call(int, door_arg_t *);
int	door_return(char *, size_t, door_desc_t *, uint_t);
int	door_cred(door_cred_t *);
int	door_ucred(ucred_t **);
int	door_bind(int);
int	door_unbind(void);
int	door_getparam(int, int, size_t *);
int	door_setparam(int, int, size_t);

typedef void door_server_func_t(door_info_t *);
door_server_func_t *door_server_create(door_server_func_t *);

typedef int door_xcreate_server_func_t(door_info_t *,
    void *(*)(void *), void *, void *);
typedef void door_xcreate_thrsetup_func_t(void *);

int	door_xcreate(door_server_procedure_t *, void *, uint_t,
	    door_xcreate_server_func_t *, door_xcreate_thrsetup_func_t *,
	    void *, int);

#endif /* _ASM */

#ifdef __cplusplus
}
#endif

#endif	/* _DOOR_H */
