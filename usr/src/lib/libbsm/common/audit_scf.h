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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _AUDIT_SCF_H
#define	_AUDIT_SCF_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * auditd smf(5)/libscf(3LIB) interface - set and display audit parameters
 */

#include <audit_plugin.h>
#include <bsm/libbsm.h>
#include <ctype.h>
#include <libintl.h>
#include <libscf_priv.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/varargs.h>
#include <ucontext.h>
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

/* Audit subsystem service instances */
#define	AUDITD_FMRI	"svc:/system/auditd:default"
#define	AUDITSET_FMRI	"svc:/system/auditset:default"

/* (ASI) Audit service instance SCF handles - libscf(3LIB) */
struct asi_scfhandle {
	scf_handle_t		*hndl;	/* base scf handle */
	scf_instance_t		*inst;	/* service instance handle */
	scf_propertygroup_t	*pgrp;	/* property group handle */
	scf_property_t		*prop;	/* property handle */
};
typedef	struct asi_scfhandle asi_scfhandle_t;

struct asi_scfhandle_iter {
	scf_iter_t	*pgrp;		/* property group iter handle */
	scf_iter_t	*prop;		/* property iter handle */
	scf_value_t	*prop_val;	/* property value */
};
typedef struct asi_scfhandle_iter asi_scfhandle_iter_t;

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

#define	ASI_PGROUP_PRESELECTION	"preselection"
#define	PRESELECTION_FLAGS	"flags"
#define	PRESELECTION_NAFLAGS	"naflags"
#define	PRESELECTION_MAXBUF	256		/* max. length of na/flags */

/* auditd(1M) plugin related well known properties */
#define	PLUGIN_ACTIVE		"active"	/* plugin state */
#define	PLUGIN_PATH		"path"		/* plugin shared object */
#define	PLUGIN_QSIZE		"qsize"		/* plugin queue size */

#define	PLUGIN_MAX		256		/* max. amount of plugins */
#define	PLUGIN_MAXBUF		256		/* max. length of plugin name */
#define	PLUGIN_MAXATT		256		/* max. length of plugin attr */
#define	PLUGIN_MAXKEY		256		/* max. length of plugin key */
#define	PLUGIN_MAXVAL		256		/* max. length of plugin val */
struct scf_plugin_kva_node {
	struct scf_plugin_kva_node	*next;
	struct scf_plugin_kva_node	*prev;
	char				plugin_name[PLUGIN_MAXBUF];
	kva_t				*plugin_kva;
};
typedef struct scf_plugin_kva_node scf_plugin_kva_node_t;

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

boolean_t do_getflags_scf(char **);
boolean_t do_getnaflags_scf(char **);
boolean_t do_getpluginconfig_scf(char *, scf_plugin_kva_node_t **);
boolean_t do_getpolicy_scf(uint32_t *);
boolean_t do_getqbufsz_scf(size_t *);
boolean_t do_getqctrl_scf(struct au_qctrl *);
boolean_t do_getqdelay_scf(clock_t *);
boolean_t do_getqhiwater_scf(size_t *);
boolean_t do_getqlowater_scf(size_t *);
boolean_t do_setflags_scf(char *);
boolean_t do_setnaflags_scf(char *);
boolean_t do_setpluginconfig_scf(char *, boolean_t, char *, int);
boolean_t do_setpolicy_scf(uint32_t);
boolean_t do_setqbufsz_scf(size_t *);
boolean_t do_setqctrl_scf(struct au_qctrl *);
boolean_t do_setqdelay_scf(clock_t *);
boolean_t do_setqhiwater_scf(size_t *);
boolean_t do_setqlowater_scf(size_t *);
void free_static_att_kva(kva_t *);
uint32_t get_policy(char *);
boolean_t plugin_avail_scf(const char *);
void plugin_kva_ll_free(scf_plugin_kva_node_t *);
void prt_error_va(char *, va_list);

#ifdef	__cplusplus
}
#endif

#endif	/* _AUDIT_SCF_H */
