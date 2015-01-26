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
 * Copyright 2012 Joshua M. Clulow <josh@sysmgr.org>
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_LIBDISASM_IMPL_H
#define	_LIBDISASM_IMPL_H

#include <stdarg.h>
#include <sys/sysmacros.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dis_arch {
	int (*da_supports_flags)(int);
	int (*da_handle_attach)(dis_handle_t *);
	void (*da_handle_detach)(dis_handle_t *);
	int (*da_disassemble)(dis_handle_t *, uint64_t, char *, size_t);
	uint64_t (*da_previnstr)(dis_handle_t *, uint64_t, int n);
	int (*da_min_instrlen)(dis_handle_t *);
	int (*da_max_instrlen)(dis_handle_t *);
	int (*da_instrlen)(dis_handle_t *, uint64_t);
} dis_arch_t;

struct dis_handle {
	void		*dh_data;
	int		dh_flags;
	dis_lookup_f	dh_lookup;
	dis_read_f	dh_read;
	uint64_t	dh_addr;

	dis_arch_t	*dh_arch;
	void		*dh_arch_private;
};

extern int dis_seterrno(int);

extern void *dis_zalloc(size_t);
extern void dis_free(void *, size_t);
extern int dis_vsnprintf(char *restrict, size_t, const char *restrict, va_list);
extern int dis_snprintf(char *restrict, size_t, const char *restrict, ...);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDISASM_IMPL_H */
