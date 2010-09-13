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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */
#ifndef _LIBFMNOTIFY_H
#define	_LIBFMNOTIFY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>
#include <errno.h>
#include <libscf.h>
#include <limits.h>
#include <strings.h>
#include <sys/corectl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>
#include <fm/diagcode.h>
#include <fm/fmd_msg.h>
#include <fm/libfmevent.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	ND_DICTDIR "usr/lib/fm/dict"
#define	ND_UNKNOWN "UNKNOWN"

typedef struct nd_hdl {
	boolean_t	nh_debug;
	boolean_t	nh_is_daemon;
	boolean_t	nh_keep_running;
	/* handle for libfmevent calls */
	fmev_shdl_t	nh_evhdl;
	/* handle for libfmd_msg calls */
	fmd_msg_hdl_t	*nh_msghdl;
	FILE		*nh_log_fd;
	char		*nh_rootdir;
	const char	*nh_pname;
} nd_hdl_t;

const char FMNOTIFY_MSG_DOMAIN[] = "FMNOTIFY";

typedef struct nd_ev_info {
	fmev_t ei_ev;
	const char *ei_class;
	char *ei_descr;
	char *ei_severity;
	char *ei_diagcode;
	char *ei_url;
	char *ei_uuid;
	char *ei_fmri;
	char *ei_from_state;
	char *ei_to_state;
	char *ei_reason;
	nvlist_t *ei_payload;
} nd_ev_info_t;


void nd_cleanup(nd_hdl_t *);
void nd_dump_nvlist(nd_hdl_t *, nvlist_t *);
void nd_debug(nd_hdl_t *, const char *, ...);
void nd_error(nd_hdl_t *, const char *, ...);
void nd_abort(nd_hdl_t *, const char *, ...);
void nd_daemonize(nd_hdl_t *);
int nd_get_boolean_prop(nd_hdl_t *, const char *, const char *, const char *,
    uint8_t *);
int nd_get_astring_prop(nd_hdl_t *, const char *, const char *, const char *,
    char **);
char *nd_get_event_fmri(nd_hdl_t *, fmev_t);
int nd_get_event_info(nd_hdl_t *, const char *, fmev_t, nd_ev_info_t **);
int nd_get_notify_prefs(nd_hdl_t *, const char *, fmev_t, nvlist_t ***,
    uint_t *);
int nd_split_list(nd_hdl_t *, char *, char *, char ***, uint_t *);
int nd_join_strarray(nd_hdl_t *, char **, uint_t, char **);
int nd_merge_strarray(nd_hdl_t *, char **, uint_t, char **, uint_t, char ***);
void nd_free_event_info(nd_ev_info_t *);
void nd_free_nvlarray(nvlist_t **, uint_t);
void nd_free_strarray(char **, uint_t);
int nd_get_diagcode(nd_hdl_t *, const char *, const char *, char *, size_t);


#ifdef	__cplusplus
}
#endif

#endif	/* _LIBFMNOTIFY_H */
