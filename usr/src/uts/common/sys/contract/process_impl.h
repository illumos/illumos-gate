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

#ifndef	_SYS_CONTRACT_PROCESS_IMPL_H
#define	_SYS_CONTRACT_PROCESS_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/contract.h>
#include <sys/contract_impl.h>
#include <sys/contract/process.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/refstr.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	PRCTID(pp) \
	((pp)->p_ct_process ? (pp)->p_ct_process->conp_contract.ct_id : 0)

struct ctmpl_process {
	ct_template_t	ctp_ctmpl;
	contract_t	*ctp_subsume;
	uint_t		ctp_params;
	uint_t		ctp_ev_fatal;
	refstr_t	*ctp_svc_fmri;	/* Service FMRI */
	refstr_t	*ctp_svc_aux;	/* Creator Auxiliary field */
};

struct cont_process {
	contract_t	conp_contract;	/* common contract data */
	cred_t		*conp_cred;
	list_t		conp_members;	/* member processes */
	list_t		conp_inherited;	/* unclaimed child contracts */
	uint_t		conp_params;	/* contract parameters */
	uint_t		conp_ev_fatal;	/* events to kill on */
	uint_t		conp_nmembers;
	uint_t		conp_ninherited;
	refstr_t	*conp_svc_fmri;		/* Service FMRI */
	ctid_t		conp_svc_ctid;		/* Service FMRI creator ctid */
	refstr_t	*conp_svc_creator;	/* contract creator */
	refstr_t	*conp_svc_aux;		/* Creator Auxiliary field */
	ctid_t		conp_svc_zone_enter;	/* zone_enter flag */
						/* requires ct_lock for */
						/* access */
};

/*
 * Kernel APIs
 */
ctmpl_process_t *sys_process_tmpl;
ct_type_t *process_type;

struct proc;
void contract_process_init(void);
cont_process_t *contract_process_fork(ctmpl_process_t *, struct proc *,
    struct proc *, int);
void contract_process_exit(cont_process_t *, struct proc *, int);
void contract_process_core(cont_process_t *, struct proc *, int,
    const char *, const char *, const char *);
void contract_process_hwerr(cont_process_t *, struct proc *);
void contract_process_sig(cont_process_t *, struct proc *, int, pid_t, ctid_t,
    zoneid_t);
void contract_process_take(contract_t *, contract_t *);
int contract_process_accept(contract_t *);
void contract_process_adopt(contract_t *, proc_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CONTRACT_PROCESS_IMPL_H */
