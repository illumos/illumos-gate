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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */
#ifndef	__RTLD_H
#define	__RTLD_H

/*
 * Common header for run-time linker.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/avl.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <synch.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <link.h>
#include <rtld.h>
#include <sgs.h>
#include <machdep.h>
#include <rtc.h>
#include <debug.h>
#include <msg.h>
#include <libc_int.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Dependency search rule order.
 */
#define	RPLENV		1		/* replaceable LD_LIBRARY_PATH */
#define	PRMENV		2		/* permanent LD_LIBRARY_PATH */
#define	RUNPATH		3		/* callers runpath */
#define	DEFAULT		4		/* default library path */

typedef struct fdesc	Fdesc;
typedef struct fct	Fct;
typedef	struct pdesc	Pdesc;

/*
 * Data structure for file class specific functions and data.
 */
struct fct {
	/* Verify that the object is of this class. */
	Fct	*(*fct_verify_file)(caddr_t, size_t, Fdesc *, const char *,
	    Rej_desc *);

	/* Generate a link-map to describe the loaded object. */
	Rt_map	*(*fct_new_lmp)(Lm_list *, Aliste, Fdesc *, Addr, size_t,
	    void *, Rt_map *, int *);

	/* Retrieve the entry point of the object. */
	Addr	(*fct_entry_pt)(void);

	/* Determine the objects dependencies (needed entries). */
	int	(*fct_needed)(Lm_list *, Aliste, Rt_map *, int *);

	/* Look up a symbol for the object. */
	int	(*fct_lookup_sym)(Slookup *, Sresult *, uint_t *, int *);

	/* Relocate the object. */
	int	(*fct_reloc)(Rt_map *, uint_t, int *, APlist **);

	/* List of default directories to search for dependencies. */
	Alist	**(*fct_get_def_dirs)(void);

	/* List of secure directories to search for dependencies. */
	Alist	**(*fct_get_sec_dirs)(void);

	/* Transpose the name of the object. */
	int	(*fct_fix_name)(const char *, Rt_map *, Alist **, Aliste,
	    uint_t);

	/* Get a shared object name */
	char	*(*fct_get_so)(const char *, const char *, size_t, size_t);

	/* Retrieve a symbolic address from the object. */
	void	(*fct_dladdr)(ulong_t, Rt_map *, Dl_info *, void **, int);

	/* Process a dlsym(3c) request within the object. */
	int	(*fct_dlsym)(Grp_hdl *, Slookup *, Sresult *, uint_t *, int *);
};

/*
 * Macros for getting to the file class table.
 */
#define	LM_ENTRY_PT(X)		((X)->rt_fct->fct_entry_pt)
#define	LM_NEEDED(X)		((X)->rt_fct->fct_needed)
#define	LM_LOOKUP_SYM(X)	((X)->rt_fct->fct_lookup_sym)
#define	LM_RELOC(X)		((X)->rt_fct->fct_reloc)
#define	LM_DEFAULT_DIRS(X)	((X)->rt_fct->fct_get_def_dirs)
#define	LM_SECURE_DIRS(X)	((X)->rt_fct->fct_get_sec_dirs)
#define	LM_FIX_NAME(X)		((X)->rt_fct->fct_fix_name)
#define	LM_GET_SO(X)		((X)->rt_fct->fct_get_so)
#define	LM_DLADDR(X)		((X)->rt_fct->fct_dladdr)
#define	LM_DLSYM(X)		((X)->rt_fct->fct_dlsym)

/*
 * Initial memory map allocation.  Typical ELF objects contain a text and data
 * segment, which can be augmented with a bss mapping.  Add a bunch more for
 * luck.
 */
#define	MMAPFD_NUM	10

/*
 * Define Alist initialization counts.
 */
#define	AL_CNT_ALIAS	2		/* ALIAS() */
#define	AL_CNT_DEPENDS	20		/* DEPENDS() */
#define	AL_CNT_CALLERS	20		/* CALLERS() */
#define	AL_CNT_GROUPS	20		/* GROUPS() */
#define	AL_CNT_COPYREL	10		/* COPY() */
#define	AL_CNT_LAZYFIND	10		/* elf_lazy_find_sym() */
#define	AL_CNT_GRPCLCT	10		/* gdp_collect() */
#define	AL_CNT_DEPCLCT	10		/* load_finish() */
#define	AL_CNT_RTLDINFO	1		/* RTLDINFO() */
#define	AL_CNT_FPNODE	4		/* FPNODE() */
#define	AL_CNT_LMLISTS	20		/* lm_lists */
#define	AL_CNT_LMNOW	8		/* lm_now */
#define	AL_CNT_RELBIND	20		/* relocation binding */
#define	AL_CNT_ACTAUDIT	2		/* lm_actaudit */
#define	AL_CNT_MOVES	10		/* move_data */
#define	AL_CNT_MPOBJS	4		/* elf_obj_file() */
#define	AL_CNT_TEXTREL	2		/* text relocation segment */
#define	AL_CNT_NEEDED	1		/* dependency path */
#define	AL_CNT_SEARCH	4		/* search path */
#define	AL_CNT_FILTEES	2		/* filtee path */
#define	AL_CNT_HANDLES	1		/* hdl_list[] */
#define	AL_CNT_FREELIST	80		/* free_alp */
#define	AL_CNT_CAP	10		/* capabilities candidate */
#define	AL_CNT_SPATH	4		/* search path */
#define	AL_CNT_DYNLIST	2		/* dynlm_list */
#define	AL_CNT_PENDING	2		/* pending tsort list (INITFIRST) */
#define	AL_CNT_PLTPAD	10		/* plt padding */
#define	AL_CNT_AUDITORS	2		/* auditing list */
#define	AL_CNT_ENVIRON	20		/* environment list (enough for ldd) */
#define	AL_CNT_COOKIES	2		/* head link-map list cookies */

/*
 * Size of buffer for building error messages.
 */
#define	ERRSIZE		2048		/* MAXPATHLEN * 2 */

/*
 * Configuration file information.
 */
typedef struct config {
	const char	*c_name;
	Addr		c_bgn;
	Addr		c_end;
	Word		*c_hashtbl;
	Word		*c_hashchain;
	const char	*c_strtbl;
	Rtc_obj		*c_objtbl;
	Rtc_fltr	*c_fltr;
	Rtc_flte	*c_flte;
} Config;

/*
 * Register symbol list.
 */
typedef struct reglist {
	Rt_map		*rl_lmp;	/* defining object */
	Sym		*rl_sym;	/* regsym */
	struct reglist	*rl_next;	/* next entry */
} Reglist;

/*
 * Data structure to hold interpreter information.
 */
typedef struct interp {
	char		*i_name;	/* interpreter name */
	caddr_t		i_faddr;	/* address interpreter is mapped at */
} Interp;

/*
 * Data structure used to keep track of copy relocations.  These relocations
 * are collected during initial relocation processing and maintained on the
 * COPY(lmp) list of the defining object.  Each copy list is also added to the
 * COPY(lmp) of the head object (normally the application dynamic executable)
 * from which they will be processed after all relocations are done.
 *
 * The use of RTLD_GROUP will also reference individual objects COPY(lmp) lists
 * in case a bound symbol must be assigned to it actual copy relocation.
 */
typedef struct {
	const char	*r_name;	/* symbol name */
	Sym		*r_rsym;	/* reference symbol table entry */
	Rt_map		*r_rlmp;	/* reference link map */
	Rt_map		*r_dlmp;	/* definition link map */
	Sym		*r_dsym;	/* definition symbol table entry */
	void		*r_radd;	/* copy to address */
	const void	*r_dadd;	/* copy from address */
	ulong_t		r_size;		/* copy size bytes */
} Rel_copy;

/*
 * Define a file descriptor, which maintains information regarding a pathname
 * that has been opened and minimally inspected.
 */
struct fdesc {
	Rt_map		*fd_lmp;	/* existing link-map pointer */
	Lm_list		*fd_lml;	/* callers link-map list */
	Fct		*fd_ftp;	/* file functions pointer */
	const char	*fd_oname;	/* original file name */
	const char	*fd_odir;	/* original directory name */
	const char	*fd_nname;	/* new file (expanded) name */
	const char	*fd_pname;	/* new path (resolved) name */
	dev_t		fd_dev;		/* file device number */
	rtld_ino_t	fd_ino;		/* file inode number */
	avl_index_t	fd_avlwhere;	/* avl tree insertion index */
	Syscapset	fd_scapset;	/* capabilities */
	mmapobj_result_t *fd_mapp;	/* mapping pointer */
	uint_t		fd_mapn;	/* mapping number */
	uint_t		fd_flags;
};

#define	FLG_FD_ALTER	0x0001		/* file is an alternate */
#define	FLG_FD_SLASH	0x0002		/* file contains a "/" */
#define	FLG_FD_RESOLVED	0x0004		/* fd_nname has been resolved */
#define	FLG_FD_ALTCHECK	0x0008		/* alternative system capabilities */
					/*	checked */
#define	FLG_FD_ALTCAP	0x0010		/* alternative system capabilities */
					/*	should be used */
#define	FLG_FD_IGNORE	0x0020		/* descriptor should be ignored */

/*
 * File descriptor availability flag.
 */
#define	FD_UNAVAIL	-1

/*
 * Disabled filter flag.  Filter objects are referenced using their .dynamic
 * index (DT_FILTER or DT_AUXILIARY).  This index is saved and used to lookup
 * the required filter.  Note that 0 is a valid .dynamic index.  The caller's
 * OBJFLTRNDX() element is initialized using the following flag, and should
 * the filter's initialization fail, is reset to this value to indicate the
 * filter is disabled.  UINT_MAX provides a convenient invalid .dynamic index.
 */
#define	FLTR_DISABLED	UINT_MAX

/*
 * Status flags for rtld_flags
 */
#define	RT_FL_THREADS	0x00000001	/* threads are enabled */
#define	RT_FL_WARNFLTR	0x00000002	/* warn of missing filtees (ldd) */
#define	RT_FL_DBNOTIF	0x00000004	/* binding activity going on */
#define	RT_FL_DEFERRED	0x00000008	/* load deferred dependencies (ldd) */
#define	RT_FL_NOBIND	0x00000010	/* don't carry out plt binding */
#define	RT_FL_NOVERSION	0x00000020	/* disable version checking */
#define	RT_FL_SECURE	0x00000040	/* setuid/segid flag */
#define	RT_FL_APPLIC	0x00000080	/* executing application code */
#define	RT_FL_NOENVIRON	0x00000100	/* don't process environment */
					/*	variables (ld.so.1 -e) */
#define	RT_FL_CONFGEN	0x00000200	/* don't relocate initiating object */
					/*	set by crle(1) */
#define	RT_FL_CONFAPP	0x00000400	/* application specific configuration */
					/*	cache required */
#define	RT_FL_DEBUGGER	0x00000800	/* a debugger is monitoring us */
#define	RT_FL_OPERATION	0x00001000	/* start recording operations */
#define	RT_FL_NEWLOCALE	0x00002000	/* message locale has changed */
#define	RT_FL_NOBAPLT	0x00004000	/* sparc: don't use ba plt's */
#define	RT_FL_NOAUXFLTR	0x00008000	/* disable auxiliary filters */

#define	RT_FL_NOAUDIT	0x00020000	/* disable auditing */
#define	RT_FL_ATEXIT	0x00040000	/* we're shutting down */
#define	RT_FL_SILENCERR	0x00080000	/* silence error messages */

#define	RT_FL_INITFIRST	0x00200000	/* processing a DT_INITFIRST object */

#define	RT_FL_DEMANGLE	0x01000000	/* demangle C++ symbol names */
#define	RT_FL_NOCFG	0x02000000	/* disable config file use */
#define	RT_FL_NODIRCFG	0x04000000	/* disable directory config use */
#define	RT_FL_NOOBJALT	0x08000000	/* disable object alternative use */
#define	RT_FL_NOENVCFG	0x10000000	/* disable config envars use */
#define	RT_FL_DIRCFG	0x20000000	/* directory config info available */
#define	RT_FL_OBJALT	0x40000000	/* object alternatives are available */
#define	RT_FL_MEMRESV	0x80000000	/* memory reservation established */

/*
 * Status flags for rtld_flags2
 */
#define	RT_FL2_HASAUDIT	0x00000001	/* auditing lm_list is present */
#define	RT_FL2_RTLDSEEN	0x00000002	/* rtldinfo has been set */
#define	RT_FL2_UNIFPROC	0x00000004	/* libc/libthread unified environment */

#define	RT_FL2_NOFLTCFG	0x00000010	/* disable config filter use */
#define	RT_FL2_FLTCFG	0x00000020	/* filter config info available */
#define	RT_FL2_HWCAP	0x00000040	/* hardware capabilities available */
#define	RT_FL2_FTL2WARN	0x00000080	/* convert fatal to warning messages */
#define	RT_FL2_BINDNOW	0x00000100	/* LD_BIND_NOW in effect */
#define	RT_FL2_BINDLAZY	0x00000200	/* disable RTLD_NOW (and LD_BIND_NOW) */
#define	RT_FL2_PLMSETUP	0x00000400	/* primary link-map set up complete */
#define	RT_FL2_BRANDED	0x00000800	/* process is branded */
#define	RT_FL2_NOPLM	0x00001000	/* process has no primary link map */
#define	RT_FL2_SETUID	0x00002000	/* ld.so.1 is setuid root */
#define	RT_FL2_ADDR32	0x00004000	/* 32-bit address space requirement */

/*
 * Information flags for env_info.
 */
#define	ENV_INF_PATHCFG	0x00000001	/* replaceable LD_LIBRARY_PATH */
					/*	originates from configuration */
					/*	file */
#define	ENV_INF_FLAGCFG	0x00000002	/* replaceable LD_FLAGS originates */
					/*	from configuration file */

/*
 * RTLDINFO descriptor.
 */
typedef struct {
	Rt_map		*rti_lmp;	/* RTLDINFO provider */
	Lc_interface	*rti_info;	/* RTLDINFO data */
} Rti_desc;

/*
 * Binding flags for the rt_bind_guard()/rt_bind_clear() routines.
 * These are defined in usr/src/lib/libc/inc/libc_int.h in the
 * latest version of the libc/rtld runtime interface (CI_V_FIVE).
 */
#if !defined(CI_V_FIVE)
#define	THR_FLG_RTLD	0x00000001	/* rtldlock bind guard flag */
#define	THR_FLG_NOLOCK	0x00000000	/* no-op before CI_V_FIVE */
#define	THR_FLG_REENTER	0x00000000	/* no-op before CI_V_FIVE */
#endif

#define	ROUND(x, a)	(((int)(x) + ((int)(a) - 1)) & ~((int)(a) - 1))

/*
 * Print buffer.
 */
typedef struct {
	char	*pr_buf;	/* pointer to beginning of buffer */
	char	*pr_cur;	/* pointer to next free char in buffer */
	size_t	pr_len;		/* buffer size */
	int	pr_fd;		/* output fd */
} Prfbuf;

/*
 * Path name descriptor.  Used to construct various path names such as search
 * paths, dependency paths, filter paths etc.  The pd_info element can be used
 * to hold various pointers, like Grp_hdl, Rtc_obj, etc.
 */
struct pdesc {
	const char	*pd_pname;	/* path name - may be expanded */
	const char	*pd_oname;	/* original name - unexpanded */
	void		*pd_info;	/* possible auxiliary information */
	size_t		pd_plen;	/* path name length */
	uint_t		pd_flags;	/* descriptor specific flags */
};

/*
 * Path name descriptors are passed to expand_path() and expand().  These
 * routines break down possible multiple path strings (separated with ":"),
 * and perform any reserved token expansion.  These routines are passed
 * information that indicates the use of the path, for example, search paths,
 * i.e., LD_LIBRARY_PATH, RPATHS, etc. are defined using la_objsearch()
 * information (see LA_SER flags in link.h).  This information is recorded in
 * the pd_flags field for later use.
 *
 * Define expansion path tokens.  These are used to prevent various expansions
 * from occurring, and record those expansions that do.  Any expansion
 * information is also recorded in the pd_flags field, and thus is or'd
 * together with any LA_SER flags.
 */
#define	PD_TKN_ORIGIN	0x00001000	/* $ORIGIN expansion has occurred */
#define	PD_TKN_PLATFORM	0x00002000	/* $PLATFORM expansion has occurred */
#define	PD_TKN_OSNAME	0x00004000	/* $OSNAME expansion has occurred */
#define	PD_TKN_OSREL	0x00008000	/* $OSREL expansion has occurred */
#define	PD_TKN_ISALIST	0x00010000	/* $ISALIST expansion has occurred */
#define	PD_TKN_CAP	0x00020000	/* $CAPABILITY/$HWCAP expansion has */
					/*	occurred */
#define	PD_TKN_MACHINE	0x00040000	/* $MACHINE expansion has occurred */
#define	PD_TKN_RESOLVED	0x00080000	/* resolvepath() expansion has */
					/*	occurred */
#define	PD_MSK_EXPAND	0x000ff000	/* mask for all expansions */

/*
 * Define additional path information.  These definitions extend the path
 * information, and may be passed into expand_path(), or set internally, or
 * inherited from expand().  These definitions are or'd together with any
 * LA_SER_ flags and PD_TKN_ flags.
 */
#define	PD_FLG_PNSLASH	0x00100000	/* pd_pname contains a slash */
#define	PD_FLG_DUPLICAT	0x00200000	/* path is a duplicate */
#define	PD_FLG_EXTLOAD	0x00400000	/* path defines extra loaded objects */
					/*	(preload, audit etc.) */
#define	PD_FLG_UNIQUE	0x00800000	/* ensure path is unique */
#define	PD_FLG_USED	0x01000000	/* indicate that path is used */
#define	PD_FLG_FULLPATH	0x02000000	/* ensure path is a full path */

#define	PD_MSK_INHERIT	0x0ffff000	/* mask for pd_flags incorporation */

/*
 * Additional token expansion information.  Although these flags may be set
 * within a token data item return from expand(), they are masked off with
 * PD_MSK_INHERIT prior to any expansion information being recorded in a path
 * name descriptor for later diagnostics.
 */
#define	TKN_NONE	0x00000001	/* no token expansion has occurred */
#define	TKN_DOTSLASH	0x00000002	/* path contains a "./" */

/*
 * dlopen() handle list size.
 */
#define	HDLIST_SZ	101	/* prime no. for hashing */
#define	HDLIST_ORP	102	/* orphan handle list */

/*
 * Define a path name search descriptor.  This "cookie" maintains state as
 * search paths are processed with get_next_dir().  Note, the path list is an
 * indirect pointer, as search paths can be reevaluated for secure applications
 * to provide better error diagnostics.
 */
typedef struct {
	uchar_t		*sp_rule;	/* present search rule */
	Alist		**sp_dalpp;	/* present path list within rule */
	Aliste		sp_idx;		/* present index within path list */
} Spath_desc;

/*
 * Define a path name definition descriptor.  Used to maintain initial ELF and
 * AOUT path name definitions.
 */
typedef struct {
	const char	*sd_name;	/* path name */
	size_t		sd_len;		/* path name size */
} Spath_defn;

/*
 * Define _caller flags.
 */
#define	CL_NONE		0
#define	CL_EXECDEF	1		/* supply the executable as a default */
					/* if the caller can't be determined */

/*
 * Binding information flags.  These flags are passed up from low level binding
 * routines to indicate "additional" information, such as why a binding has been
 * rejected.  These flags use the same data element as is used to record any
 * DBG_BINFO flags.  The DBG_BINFO flags are used to define the final bindings
 * information and are used to provide better binding diagnostics.
 */
#define	BINFO_REJDIRECT		0x010000	/* reject a direct binding */
#define	BINFO_REJSINGLE		0x100000	/* reject a singleton binding */
#define	BINFO_REJGROUP		0x200000	/* reject a group binding */

#define	BINFO_MSK_TRYAGAIN	0xf00000	/* a mask of bindings that */
						/*    should be retried */
#define	BINFO_MSK_REJECTED	0xff0000	/* a mask of bindings that */
						/*    have been rejected */

/*
 * The 32-bit version of rtld uses special stat() wrapper functions
 * that preserve the non-largefile semantics of stat()/fstat() while
 * allowing for large inode values. The 64-bit rtld uses stat() directly.
 */
#ifdef _LP64
#define	rtld_fstat	fstat
#define	rtld_stat	stat
typedef	struct stat	rtld_stat_t;
#else
typedef struct {
	dev_t		st_dev;
	rtld_ino_t	st_ino;
	mode_t		st_mode;
	uid_t		st_uid;
	off_t		st_size;
	timestruc_t	st_mtim;
#ifdef sparc
	blksize_t	st_blksize;
#endif
} rtld_stat_t;
#endif

/*
 * Some capabilities aux vector definitions have been removed over time.
 * However, existing objects may define these capabilities.  Establish
 * capability masks that provide for deleting any removed capabilities, so
 * that these capabilities are not used to validate the associated object.
 *
 * These masks are tightly coupled to the aux vector definitions in auxv_386.h
 * and auxv_SPARC.h, however they are maintained here, as only ld.so.1 needs
 * to remove these capabilities.  These definitions also describe where the
 * flags are associated and allow for providing multi-architecture definitions
 * should they become necessary, without having to pollute global header files.
 */
#if	defined(__x86)
#define	AV_HW1_IGNORE	(0x8000 | 0x2000)	/* withdrawn MON and PAUSE */
#else						/*    auxv_386.h flags */
#define	AV_HW1_IGNORE	0
#endif

/*
 * Error messages generated by ld.so.1 can be written to two different places.
 * During initial startup, messages are flushed to the stderr.  Once ld.so.1
 * has jumped to the application, messages are stored in an internal buffer for
 * retrieval by dlerror().  Between these two conditions, events such as libc's
 * callbacks, and calls to auditors, are effectively jumping to application
 * code.  These transitions from application code to ld.so.1 code are guarded by
 * the following macros to ensure any error messages are directed to the
 * appropriate output.  The single argument, "f", is a local variable that
 * can retain, and reinstate, the RT_FL_APPLIC flag of the global rtld_flags
 * variable.
 */
#define	APPLICATION_ENTER(f) \
	f = (rtld_flags & RT_FL_APPLIC) ? 0 : RT_FL_APPLIC; \
	rtld_flags |= f;
#define	APPLICATION_RETURN(f) \
	rtld_flags &= ~f;

/*
 * Data declarations.
 */
extern Lc_desc		glcs[];		/* global external interfaces */

extern	Rt_lock		rtldlock;	/* rtld lock */
extern	int		thr_flg_nolock;
extern	int		thr_flg_reenter;

extern APlist		*dynlm_list;	/* dynamic list of link-maps */
extern char		**environ;	/* environ pointer */

extern int		dyn_plt_ent_size; /* Size of dynamic plt's */
extern ulong_t		at_flags;	/* machine specific file flags */
extern const char	*procname;	/* file name of executing process */
extern Rtld_db_priv	r_debug;	/* debugging information */
extern char		*lasterr;	/* string describing last error */
extern Interp		*interp;	/* ELF executable interpreter info */
extern const char	*rtldname;	/* name of the dynamic linker */
extern APlist		*hdl_alp[];	/* dlopen() handle list */
extern size_t		syspagsz;	/* system page size */
extern Isa_desc		*isa;		/* isalist descriptor */
extern Uts_desc		*uts;		/* utsname descriptor */
extern uint_t		rtld_flags;	/* status flags for RTLD */
extern uint_t		rtld_flags2;	/* additional status flags for RTLD */
extern uint32_t		pltcnt21d;	/* cnt of 21d PLTs */
extern uint32_t		pltcnt24d;	/* cnt of 24d PLTs */
extern uint32_t		pltcntu32;	/* cnt of u32 PLTs */
extern uint32_t		pltcntu44;	/* cnt of u44 PLTs */
extern uint32_t		pltcntfull;	/* cnt of full PLTs */
extern uint32_t		pltcntfar;	/* cnt of far PLTs */
extern uchar_t		search_rules[];	/* dependency search rules */

extern Fct		elf_fct;	/* ELF file class dependent data */

#if	defined(__sparc) && !defined(__sparcv9)
extern Fct		aout_fct;	/* a.out (4.x) file class dependent */
					/*	data */
#endif

extern Config		*config;		/* configuration structure */
extern const char	*locale;		/* locale environment setting */

extern const char	*rpl_audit;	/* replaceable LD_AUDIT string */
extern const char	*rpl_debug;	/* replaceable LD_DEBUG string */
extern const char	*rpl_ldflags;	/* replaceable LD_FLAGS string */
extern const char	*rpl_libpath;	/* replaceable LD_LIBRARY string */
extern Alist		*rpl_libdirs;	/*	and its associated Pdesc list */
extern const char	*rpl_preload;	/* replaceable LD_PRELOAD string */
extern const char	*rpl_ldtoxic;	/* replaceable LD_TOXIC_PATH string */
extern Alist		*rpl_toxdirs;	/*    and associated Pdesc list */

extern const char	*prm_audit;	/* permanent LD_AUDIT string */
extern const char	*prm_debug;	/* permanent LD_DEBUG string */
extern const char	*prm_ldflags;	/* permanent LD_FLAGS string */
extern const char	*prm_libpath;	/* permanent LD_LIBRARY string */
extern Alist		*prm_libdirs;	/*	and its associated Pdesc list */
extern const char	*prm_preload;	/* permanent LD_PRELOAD string */

extern Alist		*elf_def_dirs;	/* ELF default directory seach paths */
extern Alist		*elf_sec_dirs;	/* ELF secure directory seach paths */
extern Alist		*aout_def_dirs;	/* AOUT default directory seach paths */
extern Alist		*aout_sec_dirs;	/* AOUT secure directory seach paths */

extern uint_t		env_info;	/* information regarding environment */
					/*	variables */
extern int		killsig;	/* signal sent on fatal exit */
extern APlist		*free_alp;	/* defragmentation list */

extern uint_t		audit_argcnt;	/* no. of stack args to copy */
extern Audit_desc	*auditors;	/* global auditors */
extern APlist		*aud_preinit;	/* list of objects defining local */
extern APlist		*aud_activity;	/*    preinit and activity auditors */

extern char		**_environ;	/* environ reference for libc */

extern const char	*dbg_file;	/* debugging directed to a file */

extern Reglist		*reglist;	/* list of register symbols */

extern const Msg	err_reject[];	/* rejection error message tables */
extern const Msg	ldd_reject[];
extern const Msg	ldd_warn[];

extern const char	*profile_name;	/* object being profiled */
extern const char	*profile_out;	/* profile output file */
extern const char	*profile_lib;	/* audit library to perform profile */

extern Dl_argsinfo	argsinfo;	/* process argument, environment and */
					/*	auxv information */

extern const char	*err_strs[ERR_NUM];
					/* diagnostic error string headers */
extern const char	*nosym_str;	/* MSG_GEN_NOSYM message cache */

extern Syscapset	*org_scapset;	/* original system capabilities */
extern Syscapset	*alt_scapset;	/* alternative system capabilities */

extern const char	*rpl_hwcap;	/* replaceable hwcap str */
extern const char	*rpl_sfcap;	/* replaceable sfcap str */
extern const char	*rpl_machcap;	/* replaceable machcap str */
extern const char	*rpl_platcap;	/* replaceable platcap str */
extern const char	*rpl_cap_files;	/* associated files */

extern const char	*prm_hwcap;	/* permanent hwcap str */
extern const char	*prm_sfcap;	/* permanent sfcap str */
extern const char	*prm_machcap;	/* permanent machcap str */
extern const char	*prm_platcap;	/* permanent platcap str */
extern const char	*prm_cap_files;	/* associated files */

extern avl_tree_t	*capavl;	/* capabilities files */
extern avl_tree_t	*nfavl;		/* not-found path names */
extern avl_tree_t	*spavl;		/* secure path names */

extern u_longlong_t	cnt_map;	/* Incr. for each object mapped */
extern u_longlong_t	cnt_unmap;	/* Incr. for each object unmapped */

/*
 * Function declarations.
 */
extern void		addfree(void *, size_t);
extern int		append_alias(Rt_map *, const char *, int *);
extern Rt_map		*analyze_lmc(Lm_list *, Aliste, Rt_map *, Rt_map *,
			    int *);
extern void		atexit_fini(void);
extern int		bind_one(Rt_map *, Rt_map *, uint_t);
extern int		bufprint(Prfbuf *, const char *, ...);
extern void		call_array(Addr *, uint_t, Rt_map *, Word);
extern void		call_fini(Lm_list *, Rt_map **, Rt_map *);
extern void		call_init(Rt_map **, int);
extern int		callable(Rt_map *, Rt_map *, Grp_hdl *, uint_t);
extern Rt_map		*_caller(caddr_t, int);
extern caddr_t		caller(void);
extern void		*calloc(size_t, size_t);
extern int		cap_alternative(void);
extern int		cap_check_fdesc(Fdesc *, Cap *, char *, Rej_desc *);
extern int		cap_check_lmp(Rt_map *, Rej_desc *);
extern int 		cap_filtees(Alist **, Aliste, const char *, Aliste,
			    Rt_map *, Rt_map *, const char *, int, uint_t,
			    int *);
extern int		cap_match(Sresult *, uint_t, Sym *, char *);
extern const char	*_conv_reloc_type(uint_t rel);
extern Aliste		create_cntl(Lm_list *, int);
extern void		defrag(void);
extern int		dbg_setup(const char *, Dbg_desc *);
extern const char	*demangle(const char *);
extern int		dlclose_intn(Grp_hdl *, Rt_map *);
extern int		dlclose_core(Grp_hdl *, Rt_map *, Lm_list *);
extern int		dlsym_handle(Grp_hdl *, Slookup *, Sresult *, uint_t *,
			    int *);
extern void		*dlsym_intn(void *, const char *, Rt_map *, Rt_map **);
extern Grp_hdl		*dlmopen_intn(Lm_list *, const char *, int, Rt_map *,
			    uint_t, uint_t);
extern size_t		doprf(const char *, va_list, Prfbuf *);
extern int		dowrite(Prfbuf *);
extern void		*dz_map(Lm_list *, caddr_t, size_t, int, int);
extern int		enter(int);
extern uint_t		expand(char **, size_t *, char **, uint_t, uint_t,
			    Rt_map *);
extern int		expand_paths(Rt_map *, const char *, Alist **, Aliste,
			    uint_t, uint_t);
extern void		free_hdl(Grp_hdl *);
extern void		file_notfound(Lm_list *, const char *, Rt_map *,
			    uint_t, Rej_desc *);
extern int		find_path(Lm_list *, Rt_map *, uint_t, Fdesc *,
			    Rej_desc *, int *);
extern int		fpavl_insert(Lm_list *, Rt_map *, const char *,
			    avl_index_t);
extern Rt_map		*fpavl_recorded(Lm_list *, const char *, uint_t,
			    avl_index_t *);
extern void		fpavl_remove(Rt_map *);
extern size_t		fullpath(Rt_map *, Fdesc *);
extern Lmid_t		get_linkmap_id(Lm_list *);
extern Pdesc		*get_next_dir(Spath_desc *, Rt_map *, uint_t);
extern Grp_desc		*hdl_add(Grp_hdl *, Rt_map *, uint_t, int *);
extern Grp_hdl		*hdl_create(Lm_list *, Rt_map *, Rt_map *, uint_t,
			    uint_t, uint_t);
extern int		hdl_initialize(Grp_hdl *, Rt_map *, int, int);
extern int		hwcap1_check(Syscapset *, Xword, Rej_desc *);
extern int		hwcap2_check(Syscapset *, Xword, Rej_desc *);
extern void		is_dep_init(Rt_map *, Rt_map *);
extern int		is_move_data(caddr_t);
extern int		is_path_secure(char *, Rt_map *, uint_t, uint_t);
extern int		is_rtld_setuid();
extern int		is_sym_interposer(Rt_map *, Sym *);
extern void		ldso_plt_init(Rt_map *);
extern void		leave(Lm_list *, int);
extern void		lm_append(Lm_list *, Aliste, Rt_map *);
extern void		lm_delete(Lm_list *, Rt_map *, Rt_map *);
extern void		lm_move(Lm_list *, Aliste, Aliste, Lm_cntl *,
			    Lm_cntl *);
extern Rt_map 		*load_cap(Lm_list *, Aliste, const char *, Rt_map *,
			    uint_t, uint_t, Grp_hdl **, Rej_desc *, int *);
extern void		load_completion(Rt_map *);
extern Rt_map		*load_file(Lm_list *, Aliste, Rt_map *, Fdesc *, int *);
extern Rt_map		*load_path(Lm_list *, Aliste, Rt_map *, int, uint_t,
			    Grp_hdl **, Fdesc *, Rej_desc *, int *);
extern Rt_map		*load_one(Lm_list *, Aliste, Alist *, Rt_map *, int,
			    uint_t, Grp_hdl **, int *);
extern const char	*load_trace(Lm_list *, Pdesc *, Rt_map *, Fdesc *);
extern void		nfavl_insert(const char *, avl_index_t);
extern void		*nu_map(Lm_list *, caddr_t, size_t, int, int);
extern Fct		*map_obj(Lm_list *, Fdesc *, size_t, const char *, int,
			    Rej_desc *);
extern void		*malloc(size_t);
extern int		machcap_check(Syscapset *, const char *, Rej_desc *);
extern void		machine_name(Syscapset *);
extern int		move_data(Rt_map *, APlist **);
extern int		platcap_check(Syscapset *, const char *, Rej_desc *);
extern void		platform_name(Syscapset *);
extern int		pnavl_recorded(avl_tree_t **, const char *, uint_t,
			    avl_index_t *);
extern int		procenv_user(APlist *, Word *, Word *, int);
extern void		rd_event(Lm_list *, rd_event_e, r_state_e);
extern int		readenv_user(const char **, APlist **);
extern int		readenv_config(Rtc_env *, Addr, int);
extern void		rejection_inherit(Rej_desc *, Rej_desc *);
extern int		relocate_lmc(Lm_list *, Aliste, Rt_map *, Rt_map *,
			    int *);
extern int		relocate_finish(Rt_map *, APlist *, int);
extern void		remove_alist(Alist **, int);
extern void		remove_cntl(Lm_list *, Aliste);
extern int		remove_hdl(Grp_hdl *, Rt_map *, int *);
extern void		remove_lmc(Lm_list *, Rt_map *, Aliste, const char *);
extern void		remove_lml(Lm_list *);
extern void		remove_so(Lm_list *, Rt_map *, Rt_map *);
extern int		rt_critical(void);
extern int		rt_bind_guard(int);
extern int		rt_bind_clear(int);
extern int		rt_get_extern(Lm_list *, Rt_map *);
extern int		rt_mutex_lock(Rt_lock *);
extern int		rt_mutex_unlock(Rt_lock *);
extern void		rt_thr_init(Lm_list *);
extern thread_t		rt_thr_self(void);
extern void		rtld_db_dlactivity(Lm_list *);
extern void		rtld_db_preinit(Lm_list *);
extern void		rtld_db_postinit(Lm_list *);
extern void		rtldexit(Lm_list *, int);
#ifndef _LP64
extern int		rtld_fstat(int, rtld_stat_t *restrict);
extern int		rtld_stat(const char *restrict, rtld_stat_t *restrict);
#endif
extern int		rtld_getopt(char **, char ***, auxv_t **, Word *,
			    Word *, int);
extern void		security(uid_t, uid_t, gid_t, gid_t, int);
extern void		set_environ(Lm_list *);
extern void		set_dirs(Alist **, Spath_defn *, uint_t);
extern int		set_prot(Rt_map *, mmapobj_result_t *, int);
extern Rt_map		*setup(char **, auxv_t *, Word, char *, int, char *,
			    ulong_t, ulong_t, int fd, Phdr *, char *, char **,
			    uid_t, uid_t, gid_t, gid_t, void *, int, uint_t *);
extern const char	*stravl_insert(const char *, uint_t, size_t, int);
extern void		spavl_insert(const char *);
extern int		sfcap1_check(Syscapset *, Xword, Rej_desc *);
extern int		tls_assign(Lm_list *, Rt_map *, Phdr *);
extern void		tls_modaddrem(Rt_map *, uint_t);
extern int		tls_statmod(Lm_list *, Rt_map *);
extern Rt_map		**tsort(Rt_map *, int, int);
extern void		unused(Lm_list *);
extern void		unmap_obj(mmapobj_result_t *, uint_t);
extern int		update_mode(Rt_map *, int, int);
extern void		zero(caddr_t, size_t);

#if	defined(__sparc)
/*
 * SPARC Register symbol support.
 */
extern int		elf_regsyms(Rt_map *);
extern void		set_sparc_g1(ulong_t);
extern void		set_sparc_g2(ulong_t);
extern void		set_sparc_g3(ulong_t);
extern void		set_sparc_g4(ulong_t);
extern void		set_sparc_g5(ulong_t);
extern void		set_sparc_g6(ulong_t);
extern void		set_sparc_g7(ulong_t);
#endif

extern long		_sysconfig(int);

#ifdef	__cplusplus
}
#endif

#endif /* __RTLD_H */
