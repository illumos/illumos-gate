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

#ifndef	_DACF_IMPL_H
#define	_DACF_IMPL_H

/*
 * Implementation-Private definitions for Device autoconfiguration (dacf)
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/dacf.h>

typedef struct dacf_module {
	char *dm_name;			/* module name */
	krwlock_t dm_lock;		/* module lock */
	int dm_loaded;			/* whether dm_opsets is valid */
	dacf_opset_t *dm_opsets;	/* null-terminated array of op-sets */
} dacf_module_t;


#define	DACF_RULE_HASHSIZE	8
#define	DACF_MODULE_HASHSIZE	8
#define	DACF_INFO_HASHSIZE	16

/*
 * Flags to dacf_process_rsrvs
 */
#define	DACF_PROC_INVOKE	0x0001
#define	DACF_PROC_RELE		0x0002

typedef enum dacf_devspec {
	DACF_DS_ERROR = -1,		/* error state */
	DACF_DS_MIN_NT = 1,		/* match minor node-type */
	DACF_DS_DRV_MNAME = 2,		/* match driver minor name */
	DACF_DS_DEV_PATH = 3		/* match device path */
} dacf_devspec_t;

#define	DACF_NUM_DEVSPECS 3

typedef struct dacf_arg {
	char *arg_name;			/* operation argument name */
	char *arg_val;			/* operation argument value */
	struct dacf_arg *arg_next;	/* next arg in chain */
} dacf_arg_t;

typedef struct dacf_rule {
	char *r_devspec_data;		/* the dev-spec data to match against */
	char *r_module;			/* module implementing the operation */
	char *r_opset;			/* opset in module that impls. op */
	dacf_opid_t r_opid;		/* operation id for this rule */
	uint_t r_opts;			/* reserved for options */
	uint_t r_refs;			/* reference count */
	dacf_arg_t *r_args;		/* linked list of operation arguments */
} dacf_rule_t;

typedef struct dacf_rsrvlist {
	dacf_rule_t *rsrv_rule;		/* the rule being reserved for later */
	dacf_infohdl_t rsrv_ihdl;
	int rsrv_result;		/* retval of the last invoke */
	struct dacf_rsrvlist *rsrv_next;
} dacf_rsrvlist_t;

#ifdef _KERNEL

extern kmutex_t dacf_lock;

int dacf_module_register(char *, struct dacfsw *);
int dacf_module_unregister(char *);

int dacf_arg_insert(dacf_arg_t **, char *, char *);
void dacf_arglist_delete(dacf_arg_t **);

void dacf_init(void);
int read_dacf_binding_file(char *);
void dacf_clear_rules(void);

dacf_devspec_t dacf_get_devspec(char *);
const char *dacf_devspec_to_str(dacf_devspec_t);

dacf_opid_t dacf_get_op(char *);
const char *dacf_opid_to_str(dacf_opid_t);

int dacf_getopt(char *, uint_t *);

int dacf_rule_insert(dacf_devspec_t, char *, char *, char *,
    dacf_opid_t, uint_t, dacf_arg_t *);
void dacf_rule_hold(dacf_rule_t *);
void dacf_rule_rele(dacf_rule_t *);

struct ddi_minor_data;
void dacf_rsrv_make(dacf_rsrvlist_t *, dacf_rule_t *, void *,
    dacf_rsrvlist_t **);
void dacf_process_rsrvs(dacf_rsrvlist_t **, dacf_opid_t, int);
void dacf_clr_rsrvs(dev_info_t *, dacf_opid_t);

dacf_rule_t *dacf_match(dacf_opid_t, dacf_devspec_t, void *);

/*
 * Failure codes from dacf_op_invoke, assigned to dacf_rsrvlist_t.rsrv_result
 */
#define	DACF_ERR_MOD_NOTFOUND		-1
#define	DACF_ERR_OPSET_NOTFOUND		-2
#define	DACF_ERR_OP_NOTFOUND		-3
#define	DACF_ERR_OP_FAILED		-4

int dacf_op_invoke(dacf_rule_t *, dacf_infohdl_t, int);

/*
 * Debugging support
 */
#define	DACF_DBG_MSGS		0x00000001
#define	DACF_DBG_DEVI		0x00000002

extern int dacfdebug;


/*
 * dacf client support: definitions pertaining to the various kernel hooks
 * that utilize the dacf framework
 */

void dacfc_match_create_minor(char *, char *, dev_info_t *,
    struct ddi_minor_data *, int);

int dacfc_postattach(dev_info_t *);
int dacfc_predetach(dev_info_t *);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _DACF_IMPL_H */
