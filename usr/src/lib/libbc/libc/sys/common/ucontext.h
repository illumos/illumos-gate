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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* 
 * This file contains all the type definitions necessary to
 * define the equivalent of SVR4 struct ucontext.
 */

/* Definition for alternate stack */
typedef struct sigaltstack {
	char *ss_sp;
	int  ss_size;
	int  ss_flags;
} stack_t;

/* Register window */
struct  rwindow {
        int  rw_local[8];            /* locals */
        int  rw_in[8];               /* ins */
};

#define   SPARC_MAXREGWINDOW      31 /* max windows in SPARC arch. */

struct gwindows {
        int             wbcnt;
        int             *spbuf[SPARC_MAXREGWINDOW];
        struct rwindow  wbuf[SPARC_MAXREGWINDOW];
};

typedef struct gwindows gwindows_t;

/* Floating point registers */
struct fpq {
        unsigned long *fpq_addr;        /* address */
        unsigned long fpq_instr;        /* instruction */
};
 
struct fq {
        union {                         /* FPU inst/addr queue */
                double whole;
                struct fpq fpq;
        } FQu;
};

struct fpu {
        union {                            /* FPU floating point regs */
                unsigned   fpu_regs[32];   /* 32 singles */
                double     fpu_dregs[16];  /* 16 doubles */
        } fpu_fr;
        struct fq       *fpu_q;             /* ptr to array of FQ entries */
        unsigned    fpu_fsr;                /* FPU status register */
        unsigned char   fpu_qcnt;           /* # of entries in saved FQ */
        unsigned char   fpu_q_entrysize;    /* # of bytes per FQ entry */
        unsigned char   fpu_en;             /* flag signifying fpu in use */
};

typedef struct fpu      fpregset_t;

/* Register set */
#define NGREG   19

typedef int  gregset_t[NGREG];

typedef struct mcontext{
        gregset_t       gregs;  /* general register set */
        gwindows_t      *gwins; /* POSSIBLE pointer to register windows */
        fpregset_t      fpregs; /* floating point register set */
        long            filler[21];
} mcontext_t;


typedef struct ucontext{
        unsigned long   uc_flags;
        struct ucontext *uc_link;
        unsigned long   uc_sigmask[4];
        stack_t         uc_stack;
        mcontext_t      uc_mcontext;
        long            uc_filler[23];
} ucontext_t;



/* The following is needed by the setjmp/longjmp routines */

#define _ABI_JBLEN	12	/* _JBLEN from base */

/*
 * The following structure MUST match the ABI size specifier _SIGJBLEN.
 * This is 19 (words). The ABI value for _JBLEN is 12 (words).
 * A sigset_t is 16 bytes and a stack_t is 12 bytes.  The layout must
 * match sigjmp_struct_t, defined in usr/src/lib/libc/inc/sigjmp_struct.h
 */
typedef struct setjmp_struct_t {
	int		sjs_flags;	/* JBUF[ 0]	*/
	int		sjs_sp;		/* JBUF[ 1]	*/
	int		sjs_pc;		/* JBUF[ 2]	*/
	int		sjs_fp;		/* JBUF[ 3]	*/
	int		sjs_i7;		/* JBUF[ 4]	*/
	void		*sjs_uclink;
	unsigned long	sjs_pad[_ABI_JBLEN - 6];
	unsigned long	sjs_sigmask[4];
	stack_t		sjs_stack;
} setjmp_struct_t;

typedef struct o_setjmp_struct_t {
	int		sjs_flags;	/* JBUF[ 0]	*/
	int		sjs_sp;		/* JBUF[ 1]	*/
	int		sjs_pc;		/* JBUF[ 2]	*/
	unsigned long	sjs_sigmask[3];
	stack_t		sjs_stack;
} o_setjmp_struct_t;

#define JB_SAVEMASK	0x1
#define UC_SIGMASK	001
#define UC_STACK	002

