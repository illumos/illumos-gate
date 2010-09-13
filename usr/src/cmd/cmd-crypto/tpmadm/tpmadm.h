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

#ifndef _TPMADM_H
#define	_TPMADM_H

#define	ERR_FAIL 1
#define	ERR_USAGE 2

typedef int (*cmdfunc_t)(TSS_HCONTEXT hContext, TSS_HTPM hTPM,
    int argc, char *argv[]);

typedef struct {
	char *name;
	char *args;
	cmdfunc_t func;
} cmdtable_t;

/* Utility functions */
void print_bytes(BYTE *bytes, size_t len, int formatted);
void print_error(TSS_RESULT ret, char *msg);
int get_tpm_capability(TSS_HCONTEXT hContext, TSS_HOBJECT hTPM,
    UINT32 cap, UINT32 subcap, void *buf, size_t bufsize);
int set_policy_options(TSS_HPOLICY hPolicy, TSS_FLAG mode, char *prompt,
    UINT32 secret_len, BYTE *secret);
int set_object_policy(TSS_HOBJECT handle, TSS_FLAG mode, char *prompt,
    UINT32 secret_len, BYTE *secret);
int tpm_preamble(TSS_HCONTEXT *hContext, TSS_HOBJECT *hTPM);
int tpm_postamble(TSS_HCONTEXT hContext);

#define	UUID_PARSE(str, uuid)	uuid_parse(str, *(uuid_t *)&uuid)
#define	UUID_UNPARSE(uuid, str)	uuid_unparse(*(uuid_t *)&uuid, str)
#define	UUID_COPY(source, dest)  \
	bcopy((BYTE*)&(source), (BYTE*)&(dest), sizeof (TSS_UUID))
#endif /* _TPMADM_H */
