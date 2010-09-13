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

#ifndef	_LIBCONTRACT_H
#define	_LIBCONTRACT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/contract.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *ct_stathdl_t;
typedef void *ct_evthdl_t;

/*
 * Common routines
 */
extern int ct_tmpl_activate(int);
extern int ct_tmpl_clear(int);
extern int ct_tmpl_create(int, ctid_t *);
extern int ct_tmpl_set_cookie(int, uint64_t);
extern int ct_tmpl_get_cookie(int, uint64_t *);
extern int ct_tmpl_set_critical(int, uint_t);
extern int ct_tmpl_get_critical(int, uint_t *);
extern int ct_tmpl_set_informative(int, uint_t);
extern int ct_tmpl_get_informative(int, uint_t *);

extern int ct_ctl_adopt(int);
extern int ct_ctl_abandon(int);
extern int ct_ctl_ack(int, ctevid_t);
extern int ct_ctl_nack(int, ctevid_t);
extern int ct_ctl_qack(int, ctevid_t);
extern int ct_ctl_newct(int, ctevid_t, int);

extern int ct_status_read(int, int, ct_stathdl_t *);
extern void ct_status_free(ct_stathdl_t);

extern ctid_t ct_status_get_id(ct_stathdl_t);
extern zoneid_t ct_status_get_zoneid(ct_stathdl_t);
extern const char *ct_status_get_type(ct_stathdl_t);
extern id_t ct_status_get_holder(ct_stathdl_t);
extern ctstate_t ct_status_get_state(ct_stathdl_t);
extern int ct_status_get_nevents(ct_stathdl_t);
extern int ct_status_get_ntime(ct_stathdl_t);
extern int ct_status_get_qtime(ct_stathdl_t);
extern ctevid_t ct_status_get_nevid(ct_stathdl_t);
extern uint_t ct_status_get_informative(ct_stathdl_t);
extern uint_t ct_status_get_critical(ct_stathdl_t);
extern uint64_t ct_status_get_cookie(ct_stathdl_t);

extern int ct_event_read(int, ct_evthdl_t *);
extern int ct_event_read_critical(int, ct_evthdl_t *);
extern int ct_event_reset(int);
extern int ct_event_reliable(int);
extern void ct_event_free(ct_evthdl_t);

extern uint_t ct_event_get_flags(ct_evthdl_t);
extern ctid_t ct_event_get_ctid(ct_evthdl_t);
extern ctevid_t ct_event_get_evid(ct_evthdl_t);
extern uint_t ct_event_get_type(ct_evthdl_t);
extern int ct_event_get_nevid(ct_evthdl_t, ctevid_t *);
extern int ct_event_get_newct(ct_evthdl_t, ctid_t *);

/*
 * Process contract routines
 */
extern int ct_pr_tmpl_set_transfer(int, ctid_t);
extern int ct_pr_tmpl_set_fatal(int, uint_t);
extern int ct_pr_tmpl_set_param(int, uint_t);
extern int ct_pr_tmpl_set_svc_fmri(int, const char *);
extern int ct_pr_tmpl_set_svc_aux(int, const char *);

extern int ct_pr_tmpl_get_transfer(int, ctid_t *);
extern int ct_pr_tmpl_get_fatal(int, uint_t *);
extern int ct_pr_tmpl_get_param(int, uint_t *);
extern int ct_pr_tmpl_get_svc_fmri(int, char *, size_t);
extern int ct_pr_tmpl_get_svc_aux(int, char *, size_t);

extern int ct_pr_event_get_pid(ct_evthdl_t, pid_t *);
extern int ct_pr_event_get_ppid(ct_evthdl_t, pid_t *);
extern int ct_pr_event_get_signal(ct_evthdl_t, int *);
extern int ct_pr_event_get_sender(ct_evthdl_t, pid_t *);
extern int ct_pr_event_get_senderct(ct_evthdl_t, ctid_t *);
extern int ct_pr_event_get_exitstatus(ct_evthdl_t, int *);
extern int ct_pr_event_get_pcorefile(ct_evthdl_t, const char **);
extern int ct_pr_event_get_gcorefile(ct_evthdl_t, const char **);
extern int ct_pr_event_get_zcorefile(ct_evthdl_t, const char **);

extern int ct_pr_status_get_param(ct_stathdl_t, uint_t *);
extern int ct_pr_status_get_fatal(ct_stathdl_t, uint_t *);
extern int ct_pr_status_get_members(ct_stathdl_t, pid_t **, uint_t *);
extern int ct_pr_status_get_contracts(ct_stathdl_t, ctid_t **, uint_t *);
extern int ct_pr_status_get_svc_fmri(ct_stathdl_t, char **);
extern int ct_pr_status_get_svc_aux(ct_stathdl_t, char **);
extern int ct_pr_status_get_svc_ctid(ct_stathdl_t, ctid_t *);
extern int ct_pr_status_get_svc_creator(ct_stathdl_t, char **);

/*
 * Device contract routines
 */
int ct_dev_tmpl_set_minor(int, char *);
int ct_dev_tmpl_set_aset(int, uint_t);
int ct_dev_tmpl_set_noneg(int);
int ct_dev_tmpl_clear_noneg(int);
int ct_dev_tmpl_get_minor(int, char *, size_t *);
int ct_dev_tmpl_get_aset(int, uint_t *);
int ct_dev_tmpl_get_noneg(int, uint_t *);
int ct_dev_status_get_aset(ct_stathdl_t, uint_t *);
int ct_dev_status_get_noneg(ct_stathdl_t, uint_t *);
int ct_dev_status_get_dev_state(ct_stathdl_t, uint_t *);
int ct_dev_status_get_minor(ct_stathdl_t, char **);


#ifdef __cplusplus
}
#endif

#endif /* _LIBCONTRACT_H */
