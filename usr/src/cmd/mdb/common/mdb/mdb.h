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
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright (c) 2012 Joyent, Inc. All rights reserved.
 */

#ifndef	_MDB_H
#define	_MDB_H

#include <mdb/mdb_nv.h>
#include <mdb/mdb_io.h>
#include <mdb/mdb_gelf.h>
#include <mdb/mdb_addrvec.h>
#include <mdb/mdb_argvec.h>
#include <mdb/mdb_target.h>
#include <mdb/mdb_disasm.h>
#include <mdb/mdb_demangle.h>
#include <mdb/mdb_module.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_list.h>
#include <mdb/mdb_vcb.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_tab.h>
#ifdef _KMDB
#include <kmdb/kmdb_wr.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#define	MDB_ERR_PARSE	1	/* Error occurred in lexer or parser */
#define	MDB_ERR_NOMEM	2	/* Failed to allocate needed memory */
#define	MDB_ERR_PAGER	3	/* User quit current command from pager */
#define	MDB_ERR_SIGINT	4	/* User interrupt: abort current command */
#define	MDB_ERR_QUIT	5	/* User request: quit debugger */
#define	MDB_ERR_ASSERT	6	/* Assertion failure: abort current command */
#define	MDB_ERR_API	7	/* API function error: abort current command */
#define	MDB_ERR_ABORT	8	/* User abort or resume: abort to top level */
#define	MDB_ERR_OUTPUT	9	/* Write to m_out failed: abort to top level */

#define	MDB_ERR_IS_FATAL(err)	\
	((err) == MDB_ERR_QUIT || (err) == MDB_ERR_ABORT || \
	(err) == MDB_ERR_OUTPUT)

#define	MDB_DEF_RADIX	16	/* Default output radix */
#define	MDB_DEF_NARGS	6	/* Default # of arguments in stack trace */
#define	MDB_DEF_HISTLEN	128	/* Default length of command history */
#define	MDB_DEF_SYMDIST	0x8000	/* Default symbol distance for addresses */
#define	MDB_DEF_ARRMEM	32	/* Default number of array members to print */
#define	MDB_DEF_ARRSTR	1024	/* Default number of array chars to print */

#define	MDB_ARR_NOLIMIT	-1UL	/* No limit on number of array elements */

#define	MDB_FL_PSYM	0x00001	/* Print dot as symbol + offset when possible */
#define	MDB_FL_LOG	0x00002	/* Logging is enabled */
#define	MDB_FL_NOMODS	0x00004	/* Skip automatic mdb module loading */
#define	MDB_FL_USECUP	0x00008	/* Use terminal cup initialization sequences */
#define	MDB_FL_ADB	0x00010	/* Enable stricter adb(1) compatibility */
#define	MDB_FL_SHOWLMID	0x00020	/* Always show link map id with symbol names */
#define	MDB_FL_IGNEOF	0x00040	/* Ignore EOF as a synonym for ::quit */
#define	MDB_FL_REPLAST	0x00080	/* Naked newline repeats previous command */
#define	MDB_FL_PAGER	0x00100	/* Enable pager by default */
#define	MDB_FL_LATEST	0x00200	/* Replace version string with "latest" */
#define	MDB_FL_VCREATE	0x00400	/* Victim process was created by debugger */
#define	MDB_FL_JOBCTL	0x00800	/* Victim process jobctl stopped on same tty */
#define	MDB_FL_DEMANGLE	0x01000	/* Demangle symbols as part of %a processing */
#define	MDB_FL_EXEC	0x02000	/* Debugger exec'd by a previous instance */
#define	MDB_FL_NOCTF	0x04000	/* Skip automatic CTF data loading */
#define	MDB_FL_BPTNOSYMSTOP 0x08000 /* Stop on deferred bkpts for unk symbols */
#define	MDB_FL_TERMGUESS 0x10000 /* m_termtype derived from userland */
#define	MDB_FL_READBACK	0x20000	/* Read value back after write */
#ifdef _KMDB
#define	MDB_FL_NOUNLOAD	0x40000	/* Don't allow debugger unload */
#endif
#define	MDB_FL_LMRAW	0x80000	/* Show unresolved link map object names */

#define	MDB_FL_VOLATILE	0x0001	/* Mask of all volatile flags to save/restore */

#define	MDB_EM_ASK	0	/* Ask what to do on an exec */
#define	MDB_EM_STOP	1	/* Stop after an exec */
#define	MDB_EM_FOLLOW	2	/* Follow an exec */

#define	MDB_FM_ASK	0	/* Ask what to do on a fork */
#define	MDB_FM_PARENT	1	/* Follow parent process on a fork */
#define	MDB_FM_CHILD	2	/* Follow child process on a fork */

#define	MDB_PROMPTLEN	35	/* Maximum prompt length */

struct kmdb_promif;

typedef struct mdb {
	uint_t m_tgtflags;	/* Target open flags (see mdb_target.h) */
	uint_t m_flags;		/* Miscellaneous flags (see above) */
	uint_t m_debug;		/* Debugging flags (see mdb_debug.h) */
	int m_radix;		/* Default radix for output formatting */
	int m_nargs;		/* Default number of arguments in stack trace */
	int m_histlen;		/* Length of command history */
	size_t m_symdist;	/* Distance from sym for addr match (0=smart) */
	const char *m_pname;	/* Program basename from argv[0] */
	char m_promptraw[MDB_PROMPTLEN + 1]; /* Un-expanded prompt */
	char m_prompt[MDB_PROMPTLEN + 1]; /* Prompt for interactive mode */
	size_t m_promptlen;	/* Length of prompt in bytes */
	const char *m_shell;	/* Shell for ! commands and pipelines */
	char *m_root;		/* Root for path construction */
	char *m_ipathstr;	/* Path string for include path */
	char *m_lpathstr;	/* Path string for library path */
	const char **m_ipath;	/* Path for $< and $<< macro files */
	size_t m_ipathlen;	/* Length of underlying ipath buffer */
	const char **m_lpath;	/* Path for :: loadable modules */
	size_t m_lpathlen;	/* Length of underlying lpath buffer */
	mdb_modinfo_t m_rminfo;	/* Root debugger module information */
	mdb_module_t m_rmod;	/* Root debugger module (builtins) */
	mdb_module_t *m_mhead;	/* Head of module list (in load order) */
	mdb_module_t *m_mtail;	/* Tail of module list (in load order) */
	mdb_list_t m_tgtlist;	/* List of active target backends */
	mdb_tgt_t *m_target;	/* Current debugger target backend */
	mdb_nv_t m_disasms;	/* Hash of available disassemblers */
	mdb_disasm_t *m_disasm;	/* Current disassembler backend */
	char *m_defdisasm;	/* Deferred diassembler selection */
	mdb_nv_t m_modules;	/* Name/value hash for loadable modules */
	mdb_nv_t m_dcmds;	/* Name/value hash for extended commands */
	mdb_nv_t m_walkers;	/* Name/value hash for walk operations */
	mdb_nv_t m_nv;		/* Name/value hash for named variables */
	mdb_var_t *m_dot;	/* Variable reference for '.' */
	uintmax_t m_incr;	/* Current increment */
	uintmax_t m_raddr;	/* Most recent address specified to a dcmd */
	uintmax_t m_dcount;	/* Most recent count specified to a dcmd */
	mdb_var_t *m_rvalue;	/* Most recent value printed */
	mdb_var_t *m_roffset;	/* Most recent offset from an instruction */
	mdb_var_t *m_proffset;	/* Previous value of m_roffset */
	mdb_var_t *m_rcount;	/* Most recent count on $< dcmd */
	mdb_iob_t *m_in;	/* Input stream */
	mdb_iob_t *m_out;	/* Output stream */
	mdb_iob_t *m_err;	/* Error stream */
	mdb_iob_t *m_null;	/* Null stream */
	char *m_termtype;	/* Interactive mode terminal type */
	mdb_io_t *m_term;	/* Terminal for interactive mode */
	mdb_io_t *m_log;	/* Log file i/o backend (NULL if not logging) */
	mdb_module_t *m_lmod;	/* Pointer to loading module, if in load */
	mdb_list_t m_lastc;	/* Last executed command list */
	mdb_gelf_symtab_t *m_prsym;   /* Private symbol table */
	mdb_demangler_t *m_demangler; /* Demangler (see <mdb/mdb_demangle.h>) */
	mdb_list_t m_flist;	/* Stack of execution frames */
	struct mdb_frame *volatile m_frame; /* Current stack frame */
	struct mdb_frame *volatile m_fmark; /* Stack marker for pager */
	uint_t m_fid;		/* Next frame identifier number to assign */
	uint_t m_depth;		/* Depth of m_frame stack */
	volatile uint_t m_intr;	/* Don't allow SIGINT if set */
	volatile uint_t m_pend;	/* Pending SIGINT count */
	pid_t m_pgid;		/* Debugger process group id */
	uint_t m_rdvers;	/* Librtld_db version number */
	uint_t m_ctfvers;	/* Libctf version number */
	ulong_t m_armemlim;	/* Limit on number of array members to print */
	ulong_t m_arstrlim;	/* Limit on number of array chars to print */
	uchar_t m_execmode;	/* Follow exec behavior */
	uchar_t m_forkmode;	/* Follow fork behavior */
	char **m_env;		/* Current environment */
	mdb_list_t m_cblist;	/* List of callbacks */
	mdb_nv_t m_macaliases;	/* Name/value hash of ADB macro aliases */
	ctf_file_t *m_synth;	/* Container for synthetic types */
	int m_lastret;		/* Result of running the last command */
#ifdef _KMDB
	struct dpi_ops *m_dpi;	/* DPI ops vector */
	struct kdi *m_kdi;	/* KDI ops vector */
	size_t m_pagesize;	/* Base page size for this machine */
	caddr_t m_dseg;		/* Debugger segment address */
	size_t m_dsegsz;	/* Debugger segment size */
	mdb_nv_t m_dmodctl;	/* dmod name -> kmdb_modctl hash */
	kmdb_wr_t *m_drvwrhead;	/* Driver work request queue */
	kmdb_wr_t *m_drvwrtail;	/* Driver work request queue */
	kmdb_wr_t *m_dbgwrhead;	/* Debugger request queue */
	kmdb_wr_t *m_dbgwrtail;	/* Debugger request queue */
	struct cons_polledio *m_pio; /* Polled I/O struct from kernel */
	struct kmdb_promif *m_promif; /* Debugger/PROM interface state */
#endif
} mdb_t;

#ifdef _MDB_PRIVATE
mdb_t mdb;
#else
extern mdb_t mdb;
#endif

#ifdef _MDB

#define	MDB_CONFIG_ENV_VAR "_MDB_CONFIG"

extern void mdb_create(const char *, const char *);
extern void mdb_destroy(void);

extern int mdb_call_idcmd(mdb_idcmd_t *, uintmax_t, uintmax_t, uint_t,
    mdb_argvec_t *, mdb_addrvec_t *, mdb_vcb_t *);
extern void mdb_call_tab(mdb_idcmd_t *, mdb_tab_cookie_t *, uint_t, uintmax_t,
    mdb_arg_t *);

extern int mdb_call(uintmax_t, uintmax_t, uint_t);
extern int mdb_run(void);

extern const char *mdb_get_prompt(void);
extern int mdb_set_prompt(const char *);
extern void mdb_set_ipath(const char *);
extern void mdb_set_lpath(const char *);

extern const char **mdb_path_alloc(const char *, size_t *);
extern const char **mdb_path_dup(const char *[], size_t, size_t *);
extern void mdb_path_free(const char *[], size_t);

extern uintmax_t mdb_dot_incr(const char *);
extern uintmax_t mdb_dot_decr(const char *);

extern mdb_iwalker_t *mdb_walker_lookup(const char *);
extern mdb_idcmd_t *mdb_dcmd_lookup(const char *);
extern void mdb_dcmd_usage(const mdb_idcmd_t *, mdb_iob_t *);

extern void mdb_pservice_init(void);

extern void mdb_intr_enable(void);
extern void mdb_intr_disable(void);

extern char *mdb_get_config(void);
extern void mdb_set_config(const char *);

extern mdb_module_t *mdb_get_module(void);

#endif /* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_H */
