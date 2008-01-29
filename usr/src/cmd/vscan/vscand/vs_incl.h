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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Includes private to the vscan daemon.
 * vs_icap.c also has its own private include file: vs_icap.h
 */

#ifndef _VS_INCL_H
#define	_VS_INCL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/vscan.h>
#include <libvscan.h>

/* vscan result code - "vsr_rc" field of vs_result_t */
#define	VS_RESULT_SE_ERROR    	-2 /* scan engine i/f error */
#define	VS_RESULT_ERROR    	-1
#define	VS_RESULT_UNDEFINED	0
#define	VS_RESULT_CLEAN		1 /* clean (no infection found) */
#define	VS_RESULT_CLEANED	2 /* infections found and cleaned */
#define	VS_RESULT_FORBIDDEN	3 /* infected and NOT cleaned */

/* "Resolution" field of violation_rec */
#define	VS_RES_FILE_NOT_REPAIRED	0
#define	VS_RES_FILE_REPAIRED		1
#define	VS_RES_POLICY_VIOLATION		2

#define	VS_MAX_VIOLATIONS		10
#define	VS_DESCRIPTION_MAX		64

/* number of retries on failure to communicate with a scan engine */
#define	VS_MAX_RETRY			1
#define	VS_ENG_WAIT_DFLT		30 /* seconds */

/* flags */
#define	VS_NO_REPAIR	0x01


/* vscan daemon state */
typedef enum {
	VS_STATE_INIT, VS_STATE_RUNNING, VS_STATE_SHUTDOWN
} vs_daemon_state_t;


/* violation record - populated as part of result returned from vs_icap.c */
typedef struct vs_vrec {
	int vr_id;
	int vr_res;
	char vr_desc[VS_DESCRIPTION_MAX];
} vs_vrec_t;


/* scan result - populate by vs_icap.c */
typedef struct vs_result {
	int vsr_rc;
	vs_scanstamp_t vsr_scanstamp;
	int vsr_nviolations;
	vs_vrec_t vsr_vrec[VS_MAX_VIOLATIONS];
} vs_result_t;


/* scan engine connection */
typedef struct vs_eng_conn {
	int vsc_idx;
	char vsc_engid[VS_SE_NAME_LEN];
	char vsc_host[MAXHOSTNAMELEN];
	int vsc_port;
	int vsc_sockfd;
	struct vs_eng_conn *vsc_next;
	struct vs_eng_conn *vsc_prev;
} vs_eng_conn_t;


/* file attributes used by virus scanning */
typedef struct vs_attr {
	int vsa_modified;
	int vsa_quarantined;
	uint64_t vsa_size;
	vs_scanstamp_t vsa_scanstamp;
}vs_attr_t;


/* Function Prototypes */
vs_daemon_state_t vscand_get_state(void);
char *vscand_viruslog(void);

int vs_door_init(void);
void vs_door_fini(void);

void vs_svc_init(void);
void vs_svc_fini(void);
int vs_svc_scan_file(char *, char *, vs_attr_t *, int, vs_scanstamp_t *);

void vs_eng_init(void);
void vs_eng_fini(void);
void vs_eng_config(vs_props_all_t *);
void vs_eng_set_error(vs_eng_conn_t *, int);
int vs_eng_get(vs_eng_conn_t *, int);
int vs_eng_connect(vs_eng_conn_t *);
void vs_eng_release(vs_eng_conn_t *);
int vs_eng_scanstamp_current(vs_scanstamp_t);

void vs_icap_init(void);
void vs_icap_fini(void);
void vs_icap_config(int, char *, int);
int vs_icap_scan_file(vs_eng_conn_t *, char *, char *, uint64_t,
    int, vs_result_t *);
void vs_icap_print_options(int);
int vs_icap_compare_scanstamp(int, vs_scanstamp_t);

int vs_stats_init();
void vs_stats_fini();
void vs_stats_set(int);
void vs_stats_eng_err(char *);
void vs_stats_config(vs_props_all_t *);

#ifdef __cplusplus
}
#endif

#endif /* _VS_INCL_H */
