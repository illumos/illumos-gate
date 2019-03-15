/*
 * Copyright (c) 2000, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _RCFILE_PRIV_H
#define	_RCFILE_PRIV_H

/*
 * Private RC file support.
 */

#include <sys/queue.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rckey {
	SLIST_ENTRY(rckey)	rk_next;
	char			*rk_name;
	char			*rk_value;
};

struct rcsection {
	SLIST_ENTRY(rcsection)	rs_next;
	SLIST_HEAD(rckey_head, rckey) rs_keys;
	char			*rs_name;
};

struct rcfile {
	SLIST_ENTRY(rcfile)	rf_next;
	SLIST_HEAD(rcsec_head, rcsection) rf_sect;
	char			*rf_name;
	FILE			*rf_f;
	int			rf_flags;	/* RCFILE_... */
};

#define	RCFILE_HOME_NSMBRC 1
#define	RCFILE_IS_INSECURE 2
#define	RCFILE_DELETE_ON_CLOSE	4

int rc_scf_get_sharectl(FILE *);

#ifdef __cplusplus
}
#endif

#endif /* _RCFILE_PRIV_H */
