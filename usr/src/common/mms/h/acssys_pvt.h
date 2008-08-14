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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ACSSYS_PVT_
#define	_ACSSYS_PVT_

#ifdef ACS400
#define	acs_verify_ssi_running		ACS100
#define	acs_build_header		ACS101
#define	acs_error		ACS102
#define	acs_ipc_read		ACS103
#define	acs_ipc_write		ACS104
#define	acs_build_ipc_header		ACS105
#define	acs_get_sockname		ACS106

#define	acs_vary_response		ACS200
#define	acs_query_response		ACS201
#define	acs_audit_fin_response		ACS202
#define	acs_audit_int_response		ACS203
#define	acs_select_input		ACS205
#define	acs_register_int_response	ACS206
#endif

#ifndef ANY_PORT
#define	ANY_PORT "0"
#endif

#define	acs_error_msg(args)    do {     \
	acs_caller = ACSMOD; \
	acs_error args; } while (0)

#ifdef DEBUG
#define	acs_trace_entry() \
	printf("\n\nentering %s", SELF);
#else
#define	acs_trace_entry()
#endif

#ifdef DEBUG
#define	acs_trace_exit(a) \
	printf("\nexiting %s returncode = %d", SELF, a);
#else
#define	acs_trace_exit(a)
#endif

#ifdef DEBUG
#define	acs_trace_point(a) \
	printf("\ntracept in %s: %s", #a);
#else
#define	acs_trace_point(a)
#endif

#define	COPYRIGHT\
	static const char *CR = SELF\
	" " __FILE__\
	" " __DATE__\
	"/" __TIME__\
	" copyright (c) Storage Technology Corp. 1992, 1993-2001"


#ifndef ACS_ERROR_C
extern acs_caller;
#endif

void acs_error(ACSMESSAGES * msgNo, ...);

#endif /* _ACSSYS_PVT_ */
