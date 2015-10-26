/*
 * Copyright 2015 Nexenta Systmes, Inc.  All rights reserved.
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright (c) 1995 Alex Tatmanjants <alex@elvisti.kiev.ua>
 *		at Electronni Visti IA, Kiev, Ukraine.
 *			All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _COLLATE_H_
#define	_COLLATE_H_

/*
 * This file defines the libc interface to LC_COLLATE data.
 */

#include <sys/types.h>
#include <limits.h>
#include "collatefile.h"
#include "localeimpl.h"

/*
 * This is the run-time (in-memory) form of LC_COLLATE data.
 */
struct lc_collate {
	int		lc_is_posix;

	uint8_t		lc_directive_count;
	uint8_t		lc_directive[COLL_WEIGHTS_MAX];
	int32_t		lc_pri_count[COLL_WEIGHTS_MAX];
	int32_t		lc_flags;
	int32_t		lc_chain_count;
	int32_t		lc_large_count;
	int32_t		lc_subst_count[COLL_WEIGHTS_MAX];
	int32_t		lc_undef_pri[COLL_WEIGHTS_MAX];

	collate_info_t	*lc_info;
	collate_char_t	*lc_char_table;
	collate_large_t	*lc_large_table;
	collate_chain_t	*lc_chain_table;
	collate_subst_t	*lc_subst_table[COLL_WEIGHTS_MAX];
};

void	_collate_lookup(const struct lc_collate *, const wchar_t *,
    int *, int *, int, const int **);
size_t	_collate_wxfrm(const struct lc_collate *, const wchar_t *,
    wchar_t *, size_t);
size_t	_collate_sxfrm(const wchar_t *, char *, size_t, locale_t);
int	_collate_range_cmp(wchar_t, wchar_t, locale_t);

#endif /* !_COLLATE_H_ */
