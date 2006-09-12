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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PROC_SERVICE_H
#define	_PROC_SERVICE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Description:
 *	Types, global variables, and function definitions for provider
 * of import functions for users of libc_db and librtld_db.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/procfs_isa.h>
#include <sys/lwp.h>
#include <sys/auxv.h>
#include <elf.h>
#if defined(__i386) || defined(__amd64)	/* for struct ssd */
#include <sys/segments.h>
#include <sys/sysi86.h>
#endif


typedef unsigned long	psaddr_t;

typedef enum {
	PS_OK,		/* generic "call succeeded" */
	PS_ERR,		/* generic error */
	PS_BADPID,	/* bad process handle */
	PS_BADLID,	/* bad lwp identifier */
	PS_BADADDR,	/* bad address */
	PS_NOSYM,	/* p_lookup() could not find given symbol */
	PS_NOFREGS	/* FPU register set not available for given lwp */
} ps_err_e;

struct ps_prochandle;

/*
 * See <sys/procfs_isa.h> for possible values of data_model.
 */
extern ps_err_e ps_pdmodel(struct ps_prochandle *, int *data_model);

/*
 * Special values for 'object_name' to refer to certain well-known objects.
 */
#define	PS_OBJ_EXEC	((const char *)0x0)	/* the executable file */
#define	PS_OBJ_LDSO	((const char *)0x1)	/* the dynamic linker */

extern ps_err_e ps_pglobal_lookup(struct ps_prochandle *,
	const char *object_name, const char *sym_name, psaddr_t *sym_addr);

#ifdef _LP64
typedef	Elf64_Sym	ps_sym_t;
#else
typedef	Elf32_Sym	ps_sym_t;
#endif
extern ps_err_e ps_pglobal_sym(struct ps_prochandle *,
	const char *object_name, const char *sym_name, ps_sym_t *sym);

/*
 * To read and write the process's address space.
 */
extern ps_err_e ps_pread(struct ps_prochandle *,
			psaddr_t, void *, size_t);
extern ps_err_e ps_pwrite(struct ps_prochandle *,
			psaddr_t, const void *, size_t);
/*
 * The following four functions can be implemented as simple aliases for
 * the corresponding primary two functions above (#pragma weak ...).
 * They are artifacts of history that must be maintained.
 */
extern ps_err_e ps_pdread(struct ps_prochandle *,
			psaddr_t, void *, size_t);
extern ps_err_e ps_pdwrite(struct ps_prochandle *,
			psaddr_t, const void *, size_t);
extern ps_err_e ps_ptread(struct ps_prochandle *,
			psaddr_t, void *, size_t);
extern ps_err_e ps_ptwrite(struct ps_prochandle *,
			psaddr_t, const void *, size_t);

extern ps_err_e ps_pstop(struct ps_prochandle *);
extern ps_err_e ps_pcontinue(struct ps_prochandle *);
extern ps_err_e ps_lstop(struct ps_prochandle *, lwpid_t);
extern ps_err_e ps_lcontinue(struct ps_prochandle *, lwpid_t);

extern ps_err_e ps_lgetregs(struct ps_prochandle *,
			lwpid_t, prgregset_t);
extern ps_err_e ps_lsetregs(struct ps_prochandle *,
			lwpid_t, const prgregset_t);
extern ps_err_e ps_lgetfpregs(struct ps_prochandle *,
			lwpid_t, prfpregset_t *);
extern ps_err_e ps_lsetfpregs(struct ps_prochandle *,
			lwpid_t, const prfpregset_t *);

#if defined(__sparc) || defined(__sparcv9)
extern ps_err_e ps_lgetxregsize(struct ps_prochandle *, lwpid_t, int *);
extern ps_err_e ps_lgetxregs(struct ps_prochandle *, lwpid_t, caddr_t);
extern ps_err_e ps_lsetxregs(struct ps_prochandle *, lwpid_t, caddr_t);
#endif

#if defined(__i386) || defined(__amd64)
extern ps_err_e ps_lgetLDT(struct ps_prochandle *, lwpid_t, struct ssd *);
#endif

extern ps_err_e ps_pauxv(struct ps_prochandle *, const auxv_t **);
extern ps_err_e ps_pbrandname(struct ps_prochandle *, char *, size_t);

extern ps_err_e ps_kill(struct ps_prochandle *, int sig);
extern ps_err_e ps_lrolltoaddr(struct ps_prochandle *,
			lwpid_t, psaddr_t go_addr, psaddr_t stop_addr);

extern void	ps_plog(const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif	/* _PROC_SERVICE_H */
