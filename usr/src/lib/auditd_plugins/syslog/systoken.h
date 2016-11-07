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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYSTOKEN_H
#define	_SYSTOKEN_H

#ifdef __cplusplus
extern "C" {
#endif

#include "sysplugin.h"
#include <bsm/adt.h>

/*
 * parse_context -- doc and cur are for XML input, chunk and
 * remaining for "plain text input, i.e., the traditiona
 * output from praudit
 */

struct parse_context {
	adr_t		adr;	/* input buffer pointers */
	uint64_t	id;	/* message sequence number */
	tosyslog_t	out;	/* output data */
};
typedef struct parse_context parse_context_t;

#define	AU_TEXT_NAME	" text "

#ifdef useless
/*
 * the following *_ar_token() functions parallel the *_token()(
 * functions defined in praudit/toktable.h
 */

/*
 * These tokens are the same for all versions of Solaris
 */

/*
 * Control tokens
 */

extern void	file_token(adr_t *, uint64_t, uint64_t);
extern void	trailer_token(adr_t *, parse_context_t *);
extern void	header_token(adr_t *, parse_context_t *);
extern void	header32_ex_token(adr_t *, parse_context_t *);

/*
 * Data tokens
 */

extern void	arbitrary_data_token(adr_t *, parse_context_t *);
extern void	fmri_token(adr_t *, parse_context_t *);
extern void	s5_IPC_token(adr_t *, parse_context_t *);
extern void	path_token(adr_t *, parse_context_t *);
extern void	subject32_token();
extern void	process32_token();
extern void	return_value32_token();
extern void	text_token(adr_t *, parse_context_t *);
extern void	opaque_token(adr_t *, parse_context_t *);
extern void	ip_addr_token();
extern void	ip_token(adr_t *, parse_context_t *);
extern void	iport_token(adr_t *, parse_context_t *);
extern void	argument32_token();
extern void	socket_token();
extern void	sequence_token(adr_t *, parse_context_t *);

/*
 * Modifier tokens
 */

extern void	acl_token(adr_t *, parse_context_t *);
extern void	attribute_token(adr_t *, parse_context_t *);
extern void	s5_IPC_perm_token(adr_t *, parse_context_t *);
extern void	group_token();
extern void	label_token(adr_t *, parse_context_t *);
extern void	privilege_token(adr_t *, parse_context_t *);
extern void	useofpriv_token(adr_t *, parse_context_t *);
extern void	secflags_token(adr_t *, parse_context_t *);
extern void	zonename_token(adr_t *, parse_context_t *);
extern void	liaison_token(adr_t *, parse_context_t *);
extern void	newgroup_token(adr_t *, parse_context_t *);
extern void	exec_args_token(adr_t *, parse_context_t *);
extern void	exec_env_token(adr_t *, parse_context_t *);
extern void	attribute32_token(adr_t *, parse_context_t *);
extern void	useofauth_token(adr_t *, parse_context_t *);
extern void	user_token(adr_t *, parse_context_t *);

/*
 * X windows tokens
 */

extern void	xatom_token(adr_t *, parse_context_t *);
extern void	xselect_token(adr_t *, parse_context_t *);
extern void	xcolormap_token(adr_t *, parse_context_t *);
extern void	xcursor_token(adr_t *, parse_context_t *);
extern void	xfont_token(adr_t *, parse_context_t *);
extern void	xgc_token(adr_t *, parse_context_t *);
extern void	xpixmap_token(adr_t *, parse_context_t *);
extern void	xproperty_token(adr_t *, parse_context_t *);
extern void	xwindow_token(adr_t *, parse_context_t *);
extern void	xclient_token(adr_t *, parse_context_t *);

/*
 * Command tokens
 */

extern void	cmd_token(adr_t *, parse_context_t *);
extern void	exit_token(adr_t *, parse_context_t *);

/*
 * Miscellaneous tokens
 */

extern void	host_token(adr_t *, parse_context_t *);

/*
 * Solaris64 tokens
 */

extern void	argument64_token(adr_t *, parse_context_t *);
extern void	return64_token(adr_t *, parse_context_t *);
extern void	attribute64_token(adr_t *, parse_context_t *);
extern void	header64_token(adr_t *, parse_context_t *);
extern void	subject64_token(adr_t *, parse_context_t *);
extern void	process64_token(adr_t *, parse_context_t *);
extern void	file64_token(adr_t *, parse_context_t *);

/*
 * Extended network address tokens
 */

extern void	header64_ex_token();
extern void	subject32_ex_token();
extern void	process32_ex_token();
extern void	subject64_ex_token(adr_t *, parse_context_t *);
extern void	process64_ex_token(adr_t *, parse_context_t *);
extern void	ip_addr_ex_token(adr_t *, parse_context_t *);
extern void	socket_ex_token(adr_t *, parse_context_t *);
extern void	tid_token(adr_t *, parse_context_t *);
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _SYSTOKEN_H */
