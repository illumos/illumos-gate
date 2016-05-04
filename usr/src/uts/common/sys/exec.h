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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef _SYS_EXEC_H
#define	_SYS_EXEC_H

#include <sys/systm.h>
#include <vm/seg.h>
#include <vm/seg_vn.h>
#include <sys/model.h>
#include <sys/uio.h>
#include <sys/corectl.h>
#include <sys/machelf.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Number of bytes to read for magic string
 */
#define	MAGIC_BYTES	8

#define	getexmag(x)	(((x)[0] << 8) + (x)[1])

typedef struct execa {
	const char *fname;
	const char **argp;
	const char **envp;
} execa_t;

typedef struct execenv {
	caddr_t ex_bssbase;
	caddr_t ex_brkbase;
	size_t	ex_brksize;
	vnode_t *ex_vp;
	short   ex_magic;
} execenv_t;

#ifdef _KERNEL

#define	LOADABLE_EXEC(e)	((e)->exec_lock)
#define	LOADED_EXEC(e)		((e)->exec_func)


/*
 * User argument structure for passing exec information around between the
 * common and machine-dependent portions of exec and the exec modules.
 */
typedef struct uarg {
	ssize_t	na;
	ssize_t	ne;
	ssize_t	nc;
	ssize_t arglen;
	char	*fname;
	char	*pathname;
	ssize_t	auxsize;
	caddr_t	stackend;
	size_t	stk_align;
	size_t	stk_size;
	char	*stk_base;
	char	*stk_strp;
	int	*stk_offp;
	size_t	usrstack_size;
	uint_t	stk_prot;
	uint_t	dat_prot;
	int	traceinval;
	int	addr32;
	model_t	to_model;
	model_t	from_model;
	size_t	to_ptrsize;
	size_t	from_ptrsize;
	size_t	ncargs;
	struct execsw *execswp;
	uintptr_t entry;
	uintptr_t thrptr;
	vnode_t	*ex_vp;
	char	*emulator;
	char	*brandname;
	char	*auxp_auxflags; /* addr of auxflags auxv on the user stack */
	char	*auxp_brand; /* address of first brand auxv on user stack */
	cred_t	*pfcred;
	boolean_t scrubenv;
} uarg_t;

/*
 * Possible brand actions for exec.
 */
#define	EBA_NONE	0
#define	EBA_NATIVE	1
#define	EBA_BRAND	2

/*
 * The following macro is a machine dependent encapsulation of
 * postfix processing to hide the stack direction from elf.c
 * thereby making the elf.c code machine independent.
 */
#define	execpoststack(ARGS, ARRAYADDR, BYTESIZE) \
	(copyout((caddr_t)(ARRAYADDR), (ARGS)->stackend, (BYTESIZE)) ? EFAULT \
		: (((ARGS)->stackend += (BYTESIZE)), 0))

/*
 * This provides the current user stack address for an object of size BYTESIZE.
 * Used to determine the stack address just before applying execpoststack().
 */
#define	stackaddress(ARGS, BYTESIZE)	((ARGS)->stackend)

/*
 * Macro to add attribute/values the aux vector under construction.
 */
/* BEGIN CSTYLED */
#if ((_LONG_ALIGNMENT == (2 * _INT_ALIGNMENT)) || \
     (_POINTER_ALIGNMENT == (2 * _INT_ALIGNMENT)))
/* END CSTYLED */
/*
 * This convoluted stuff is necessitated by the fact that there is
 * potential padding in the aux vector, but not necessarily and
 * without clearing the padding there is a small, but potential
 * security hole.
 */
#define	ADDAUX(p, a, v)	{		\
		(&(p)->a_type)[1] = 0;	\
		(p)->a_type = (a);	\
		(p)->a_un.a_val = (v);	\
		++(p);			\
	}
#else
#define	ADDAUX(p, a, v)	{			\
		(p)->a_type = (a);		\
		((p)++)->a_un.a_val = (v);	\
	}
#endif

#define	INTPSZ	MAXPATHLEN
#define	INTP_MAXDEPTH	5	/* Nested interpreter depth matches Linux */
typedef struct intpdata {
	char	*intp;
	char	*intp_name[INTP_MAXDEPTH];
	char	*intp_arg[INTP_MAXDEPTH];
} intpdata_t;

#define	EXECSETID_SETID		0x1 /* setid exec */
#define	EXECSETID_UGIDS		0x2 /* [ug]ids mismatch */
#define	EXECSETID_PRIVS		0x4 /* more privs than before */

struct execsw {
	char	*exec_magic;
	int	exec_magoff;
	int	exec_maglen;
	int	(*exec_func)(struct vnode *vp, struct execa *uap,
		    struct uarg *args, struct intpdata *idata, int level,
		    long *execsz, int setid, caddr_t exec_file,
		    struct cred *cred, int brand_action);
	int	(*exec_core)(struct vnode *vp, struct proc *p,
		    struct cred *cred, rlim64_t rlimit, int sig,
		    core_content_t content);
	krwlock_t	*exec_lock;
};

extern int nexectype;		/* number of elements in execsw */
extern struct execsw execsw[];
extern kmutex_t execsw_lock;

extern short elfmagic;
extern short intpmagic;
extern short javamagic;
#if defined(__sparc)
extern short aout_zmagic;
extern short aout_nmagic;
extern short aout_omagic;
#endif
extern short nomagic;

extern char elf32magicstr[];
extern char elf64magicstr[];
extern char intpmagicstr[];
extern char javamagicstr[];
#if defined(__sparc)
extern char aout_nmagicstr[];
extern char aout_zmagicstr[];
extern char aout_omagicstr[];
#endif
extern char nomagicstr[];

extern int exec_args(execa_t *, uarg_t *, intpdata_t *, void **);
extern int exece(const char *fname, const char **argp, const char **envp);
extern int exec_common(const char *fname, const char **argp,
    const char **envp, int brand_action);
extern int gexec(vnode_t **vp, struct execa *uap, struct uarg *args,
    struct intpdata *idata, int level, long *execsz, caddr_t exec_file,
    struct cred *cred, int brand_action);
extern struct execsw *allocate_execsw(char *name, char *magic,
    size_t magic_size);
extern struct execsw *findexecsw(char *magic);
extern struct execsw *findexec_by_hdr(char *header);
extern struct execsw *findexec_by_magic(char *magic);
extern int execpermissions(struct vnode *vp, struct vattr *vattrp,
    struct uarg *args);
extern int execmap(vnode_t *vp, caddr_t addr, size_t len, size_t zfodlen,
    off_t offset, int prot, int page, uint_t);
extern void setexecenv(struct execenv *ep);
extern int execopen(struct vnode **vpp, int *fdp);
extern int execclose(int fd);
extern void setregs(uarg_t *);
extern void exec_set_sp(size_t);

/*
 * Utility functions for branded process executing
 */
#if !defined(_ELF32_COMPAT)
/*
 * When compiling 64-bit kernels we don't want these definitions included
 * when compiling the 32-bit compatability elf code in the elfexec module.
 */
extern int elfexec(vnode_t *, execa_t *, uarg_t *, intpdata_t *, int,
    long *, int, caddr_t, cred_t *, int);
extern int mapexec_brand(vnode_t *, uarg_t *, Ehdr *, Addr *,
    intptr_t *, caddr_t, int *, caddr_t *, caddr_t *, size_t *, uintptr_t *);
#endif /* !_ELF32_COMPAT */

#if defined(_LP64)
extern int elf32exec(vnode_t *, execa_t *, uarg_t *, intpdata_t *, int,
    long *, int, caddr_t, cred_t *, int);
extern int mapexec32_brand(vnode_t *, uarg_t *, Elf32_Ehdr *, Elf32_Addr *,
    intptr_t *, caddr_t, int *, caddr_t *, caddr_t *, size_t *, uintptr_t *);
#endif  /* _LP64 */

/*
 * Utility functions for exec module core routines:
 */
extern int core_seg(proc_t *, vnode_t *, offset_t, caddr_t,
    size_t, rlim64_t, cred_t *);

extern int core_write(vnode_t *, enum uio_seg, offset_t,
    const void *, size_t, rlim64_t, cred_t *);

/* a.out stuff */

struct exec;

extern caddr_t gettmem(struct exec *exp);
extern caddr_t getdmem(struct exec *exp);
extern ulong_t getdfile(struct exec *exp);
extern uint_t gettfile(struct exec *exp);
extern int chkaout(struct exdata *exp);
extern void getexinfo(struct exdata *edp_in, struct exdata *edp_out,
    int *pagetext, int *pagedata);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_EXEC_H */
