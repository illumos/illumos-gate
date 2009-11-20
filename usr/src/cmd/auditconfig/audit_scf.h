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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _AUDIT_SCF_H
#define	_AUDIT_SCF_H

/*
 * auditd smf(5)/libscf(3LIB) interface - set and display audit parameters
 */

#include <audit_plugin.h>
#include <audit_sig_infc.h>
#include <bsm/libbsm.h>
#include <libintl.h>
#include <libscf_priv.h>
#include <strings.h>
#include <sys/varargs.h>
#include <zone.h>

/* gettext() obfuscation routine for lint */
#ifdef __lint
#define	gettext(x)	x
#endif

#ifndef DEBUG
#define	DEBUG	0
#endif

#if DEBUG
FILE	*dbfp;		  /* debug file pointer */
#define	DPRINT(x)	{ if (dbfp == NULL) dbfp = __auditd_debug_file_open(); \
			    (void) fprintf x; (void) fflush(dbfp); }
#else	/* ! DEBUG */
#define	DPRINT(x)
#endif

/*
 * (ASI) Audit service instance (svc:/system/auditd:default) related
 * configuration parameters.
 */
#define	ASI_PGROUP_POLICY	"policy"
struct policy_sw {
	char		*policy;
	boolean_t	flag;
};
typedef struct policy_sw policy_sw_t;

#define	ASI_PGROUP_QUEUECTRL	"queuectrl"
#define	QUEUECTRL_QBUFSZ	"qbufsz"
#define	QUEUECTRL_QDELAY	"qdelay"
#define	QUEUECTRL_QHIWATER	"qhiwater"
#define	QUEUECTRL_QLOWATER	"qlowater"
struct scf_qctrl {
	uint64_t	scf_qhiwater;
	uint64_t	scf_qlowater;
	uint64_t	scf_qbufsz;
	uint64_t	scf_qdelay;
};
typedef struct scf_qctrl scf_qctrl_t;

/* Boundary checking macros for the queuectrl parameters. */
#define	AQ_MINLOW	1
#define	CHK_BDRY_QBUFSZ(x)	!((x) < AQ_BUFSZ || (x) > AQ_MAXBUFSZ)
#define	CHK_BDRY_QDELAY(x)	!((x) == 0 || (x) > AQ_MAXDELAY)
#define	CHK_BDRY_QLOWATER(low, high)	!((low) < AQ_MINLOW || (low) >= (high))
#define	CHK_BDRY_QHIWATER(low, high)	!((high) <= (low) || \
					    (high) < AQ_LOWATER || \
					    (high) > AQ_MAXHIGH)

/*
 * MAX_PROPVECS	maximum number of audit properties that will
 * 		fit in the uint32_t audit policy mask.
 */
#define	MAX_PROPVECS	32

/* defined in audit_scf_shared.c; used in auditd.c and auditconfig.c */
void add_prop_vect_scf(scf_propvec_t *, const char *, scf_type_t, void *);
boolean_t chk_policy_context(char *);
boolean_t do_getqctrl_scf(struct au_qctrl *);
boolean_t do_getpolicy_scf(uint32_t *);
uint32_t get_policy(char *);
boolean_t get_val_scf(scf_propvec_t *, char *);
void prt_error(char *, ...);
void prt_error_va(char *, va_list);
void prt_scf_err(void);

/* defined in audit_scf.c; used only in auditconfig.c */
boolean_t do_getqbufsz_scf(size_t *);
boolean_t do_getqdelay_scf(clock_t *);
boolean_t do_getqhiwater_scf(size_t *);
boolean_t do_getqlowater_scf(size_t *);
boolean_t do_setpolicy_scf(uint32_t);
boolean_t do_setqctrl_scf(struct au_qctrl *);
boolean_t do_setqbufsz_scf(size_t *);
boolean_t do_setqdelay_scf(clock_t *);
boolean_t do_setqhiwater_scf(size_t *);
boolean_t do_setqlowater_scf(size_t *);

#endif	/* _AUDIT_SCF_H */
