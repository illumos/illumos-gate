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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYSPLUGIN_H
#define	_SYSPLUGIN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <bsm/audit.h>

struct selected_fields {
	/* from header token */
	au_event_t	sf_eventid;	/* 0 if no value */
	uint32_t	sf_reclen;	/* 0 if no value */

	/* from exit or return token */
	int		sf_pass;	/* 0 no value, -1 fail, 1 pass */

	/* from subject token */
	uint32_t	sf_asid;	/* 0 no value */
	uid_t		sf_auid;	/* -2 no value, > -1 otherwise */
	uid_t		sf_euid;	/* -2 no value, > -1 otherwise */
	gid_t		sf_egid;	/* -2 no value, > -1 otherwise */
	au_tid_addr_t	sf_tid;		/* tid.at_type = 0 no value */

	/* from process token */
	uid_t		sf_pauid;	/* -2 no value */
	uid_t		sf_peuid;	/* -2 no value */

	/* data that may be truncated goes after this point */

	/* from uauth token */
	size_t		sf_uauthlen;
	char		*sf_uauth;	/* NULL no value */

	/* from text token */
	size_t		sf_textlen;
	char		*sf_text;	/* NULL no value */

	/* from path and atpath token */
	size_t		sf_pathlen;
	char		*sf_path;		/* NULL no value */
	size_t		sf_atpathlen;
	char		*sf_atpath;	/* NULL no value */

	/* from sequence token */
	int32_t		sf_sequence;	/* -1 no value */

	/* from zonename token */
	size_t		sf_zonelen;
	char		*sf_zonename;	/* NULL no value */
};
typedef struct selected_fields tosyslog_t;


#ifdef __cplusplus
}
#endif

#endif	/* _SYSPLUGIN_H */
