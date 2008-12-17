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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__RTLD_H
#define	__RTLD_H

/*
 * Common header for run-time linker.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/avl.h>
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


/*
 * Data structure for file class specific functions and data.
 */
typedef struct fct {
	int	(*fct_are_u_this)(Rej_desc *);	/* determine type of object */
	ulong_t	(*fct_entry_pt)(void);		/* get entry point */
	Rt_map	*(*fct_map_so)(Lm_list *, Aliste, const char *, const char *,
		    int, int *);		/* map in a shared object */
	void	(*fct_unmap_so)(Rt_map *);	/* unmap a shared object */
	int	(*fct_needed)(Lm_list *, Aliste, Rt_map *, int *);
						/* determine needed objects */
	Sym	*(*fct_lookup_sym)(Slookup *, Rt_map **, uint_t *, int *);
						/* initialize symbol lookup */
	int	(*fct_reloc)(Rt_map *, uint_t, int *);
						/* relocate shared object */
	Pnode	*fct_dflt_dirs;			/* list of default dirs to */
						/*	search */
	Pnode	*fct_secure_dirs;		/* list of secure dirs to */
						/*	search (set[ug]id) */
	Pnode	*(*fct_fix_name)(const char *, Rt_map *, uint_t);
						/* transpose name */
	char	*(*fct_get_so)(const char *, const char *);
						/* get shared object */
	void	(*fct_dladdr)(ulong_t, Rt_map *, Dl_info *, void **, int);
						/* get symbolic address */
	Sym	*(*fct_dlsym)(Grp_hdl *, Slookup *, Rt_map **, uint_t *,
		    int *);			/* process dlsym request */
	int	(*fct_verify_vers)(const char *, Rt_map *, Rt_map *);
						/* verify versioning (ELF) */
	int	(*fct_set_prot)(Rt_map *, int);
						/* set protection */
} Fct;


/*
 * Return codes for util::anon_map().
 */
typedef enum {
	AM_OK,			/* mmap(MAP_ANON) succeeded */
	AM_NOSUP,		/* mmap(MAP_ANON) not supported (old OS) */
	AM_ERROR		/* mmap(MAP_ANON) failed */
} Am_ret;


/*
 * Macros for getting to the file class table.
 */
#define	LM_ENTRY_PT(X)		((X)->rt_fct->fct_entry_pt)
#define	LM_UNMAP_SO(X)		((X)->rt_fct->fct_unmap_so)
#define	LM_NEEDED(X)		((X)->rt_fct->fct_needed)
#define	LM_LOOKUP_SYM(X)	((X)->rt_fct->fct_lookup_sym)
#define	LM_RELOC(X)		((X)->rt_fct->fct_reloc)
#define	LM_DFLT_DIRS(X)		((X)->rt_fct->fct_dflt_dirs)
#define	LM_SECURE_DIRS(X)	((X)->rt_fct->fct_secure_dirs)
#define	LM_FIX_NAME(X)		((X)->rt_fct->fct_fix_name)
#define	LM_GET_SO(X)		((X)->rt_fct->fct_get_so)
#define	LM_DLADDR(X)		((X)->rt_fct->fct_dladdr)
#define	LM_DLSYM(X)		((X)->rt_fct->fct_dlsym)
#define	LM_VERIFY_VERS(X)	((X)->rt_fct->fct_verify_vers)
#define	LM_SET_PROT(X)		((X)->rt_fct->fct_set_prot)


/*
 * Define Alist initialization sizes.
 */
#define	AL_CNT_ALIAS	2		/* ALIAS() initial alist count */
#define	AL_CNT_DEPENDS	10		/* DEPENDS() initial alist count */
#define	AL_CNT_CALLERS	10		/* CALLERS() initial alist count */
#define	AL_CNT_GROUPS	4		/* GROUPS() initial alist count */
#define	AL_CNT_COPYREL	10		/* COPY() initial alist count */
#define	AL_CNT_LAZYFIND	10		/* elf_lazy_find_sym() initial alist */
					/*	count */
#define	AL_CNT_GRPCLCT	10		/* gdp_collect() initial alist count */
#define	AL_CNT_DEPCLCT	10		/* load_so() initial alist count */
#define	AL_CNT_RTLDINFO	1		/* RTLDINFO() initial alist count */
#define	AL_CNT_FPNODE	2		/* FPNODE() initial alist count */
#define	AL_CNT_LMLISTS	8		/* lm_lists initial alist count */
#define	AL_CNT_LMNOW	8		/* lm_now initial alist count */
#define	AL_CNT_RELBIND	20		/* relocation binding alist count */
#define	AL_CNT_ACTAUDIT	2		/* lm_actaudit alist count */
#define	AL_CNT_MOVES	10		/* move_data alist count */


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
 * Data structure to hold initial file mapping information.  Used to
 * communicate during initial object mapping and provide for error recovery.
 */
typedef struct {
	char		*fm_maddr;	/* address of initial mapping */
	size_t		fm_msize;	/* size of initial mapping */
	size_t		fm_fsize;	/* actual file size */
	ulong_t		fm_etext;	/* end of text segment */
	int		fm_mflags;	/* mapping flags */
	ulong_t		fm_hwptr;	/* hardware capabilities pointer */
} Fmap;

#define	FMAP_SIZE	0x8000		/* initial size to map from a file */
					/* big enough to capture standard */
					/* filters */
/*
 * Define a file descriptor, which maintains information regarding a pathname
 * that has been opened and minimally inspected.
 */
typedef struct {
	Rt_map		*fd_lmp;	/* existing link-map pointer */
	Fct		*fd_ftp;	/* file functions pointer */
	const char	*fd_oname;	/* original file name */
	const char	*fd_odir;	/* original directory name */
	const char	*fd_nname;	/* new file (expanded) name */
	const char	*fd_pname;	/* new path (resolved) name */
	dev_t		fd_dev;		/* file device number */
	ino_t		fd_ino;		/* file inode number */
	int		fd_fd;		/* open file descriptor */
	uint_t		fd_flags;
	avl_index_t	fd_avlwhere;	/* avl tree insertion index */
	Fmap		fd_fmap;	/* file mapping information */
} Fdesc;

#define	FLG_FD_ALTER	0x01		/* file is an alternate */
#define	FLG_FD_SLASH	0x02		/* file contains a "/" */

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

#ifdef	SIEBEL_DISABLE
#define	RT_FL_DISFIX_1	0x00000008	/* disable fix number 1 */
#endif

#define	RT_FL_NOBIND	0x00000010	/* don't carry out plt binding */
#define	RT_FL_NOVERSION	0x00000020	/* disable version checking */
#define	RT_FL_SECURE	0x00000040	/* setuid/segid flag */
#define	RT_FL_APPLIC	0x00000080	/* are we executing user code */
#define	RT_FL_CONCUR	0x00000100	/* thread concurrency checks required */
#define	RT_FL_CONFGEN	0x00000200	/* don't relocate initiating object */
					/*	set by crle(1). */
#define	RT_FL_CONFAPP	0x00000400	/* application specific configuration */
					/*	cache required */
#define	RT_FL_DEBUGGER	0x00000800	/* a debugger is monitoring us */
#define	RT_FL_OPERATION	0x00001000	/* start recording operations */
#define	RT_FL_NEWLOCALE	0x00002000	/* message locale has changed */
#define	RT_FL_NOBAPLT	0x00004000	/* sparc: don't use ba plt's */
#define	RT_FL_NOAUXFLTR	0x00008000	/* disable auxiliary filters */
#define	RT_FL_NOCONCUR	0x00010000	/* disable thread concurrency checks */
#define	RT_FL_NOAUDIT	0x00020000	/* disable auditing */
#define	RT_FL_ATEXIT	0x00040000	/* we're shutting down */
#define	RT_FL_SILENCERR	0x00080000	/* silence error messages */
#define	RT_FL_BREADTH	0x00100000	/* use breadth-first for .init/.fini */
#define	RT_FL_INITFIRST	0x00200000	/* processing a DT_INITFIRST object */
#define	RT_FL_RELATIVE	0x00400000	/* relative path expansion required */
#define	RT_FL_EXECNAME	0x00800000	/* AT_SUN_EXECNAME vector is avail */
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
#define	RT_FL2_NOMALIGN	0x00000008	/* mmap MAP_ALIGN isn't available */
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
 * Binding flags for the bindguard routines.
 * These are defined in usr/src/lib/libc/inc/libc_int.h in the
 * latest version of the libc/rtld runtime interface (CI_V_FIVE).
 */
#if !defined(CI_V_FIVE)
#define	THR_FLG_RTLD	0x00000001	/* rtldlock bind_guard() flag */
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
 * dlopen() handle list size.
 */
#define	HDLIST_SZ	101	/* prime no. for hashing */
#define	HDLIST_ORP	102	/* orphan handle list */

/*
 * Define expansion path information.  Search paths, i.e., LD_LIBRARY_PATH,
 * RPATHS, etc. are defined using la_objsearch() information (see LA_SER flags
 * in link.h).  Definitions here extend the path information to other uses of
 * pathname expansion, and are or'd together with any LA_SER_* flags.
 */
#define	PN_FLG_EXTLOAD	0x00001000	/* path defines extra loaded objects */
					/*	(preload, audit etc.) */
#define	PN_FLG_UNIQUE	0x00002000	/* ensure path is unique */
#define	PN_FLG_USED	0x00004000	/* indicate that path is used */
#define	PN_FLG_DUPLICAT	0x00008000	/* path is a duplicate */
#define	PN_FLG_FULLPATH	0x00010000	/* ensure path is a full path */

#define	PN_FLG_MASK	0x000ff000	/* mask for p_orig incorporation */

/*
 * Define reserved path tokens.  These are used to prevent various expansions
 * from occurring, and record those expansions that do.  Note that any expansion
 * information is also recorded in the p_orig field of a Pnode, and thus is
 * or'd together with any LA_SER, and PN_FLG flags.
 */
#define	PN_TKN_ORIGIN	0x00100000	/* $ORIGIN expansion has occurred */
#define	PN_TKN_PLATFORM	0x00200000	/* $PLATFORM expansion has occurred */
#define	PN_TKN_OSNAME	0x00400000	/* $OSNAME expansion has occurred */
#define	PN_TKN_OSREL	0x00800000	/* $OSREL expansion has occurred */
#define	PN_TKN_ISALIST	0x01000000	/* $ISALIST expansion has occurred */
#define	PN_TKN_HWCAP	0x02000000	/* $HWCAP expansion has occurred */

#define	PN_TKN_MASK	0xfff00000	/* mask for p_orig incorporation */

/*
 * Additional token expansion information.  Although these flags may be set
 * within a token data item they are masked off with PN_TKN_MASK prior to any
 * expansion information being recorded in a Pnode for later diagnostics.
 */
#define	TKN_NONE	0x00000001	/* no token expansion has occurred */
#define	TKN_DOTSLASH	0x00000002	/* path contains a "./" */

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
 * Data declarations.
 */
extern Lc_desc		glcs[];		/* global external interfaces */

extern	Rt_lock		rtldlock;	/* rtld lock */
extern	int		thr_flg_nolock;
extern	int		thr_flg_reenter;

extern List		dynlm_list;	/* dynamic list of link-maps */
extern char		**environ;	/* environ pointer */

extern int		dyn_plt_ent_size; /* Size of dynamic plt's */
extern ulong_t		at_flags;	/* machine specific file flags */
extern const char	*procname;	/* file name of executing process */
extern Rtld_db_priv	r_debug;	/* debugging information */
extern char		*lasterr;	/* string describing last error */
extern Interp		*interp;	/* ELF executable interpreter info */
extern const char	*rtldname;	/* name of the dynamic linker */
extern List		hdl_list[];	/* dlopen() handle list */
extern size_t		syspagsz;	/* system page size */
extern char		*platform; 	/* platform name */
extern size_t		platform_sz; 	/* platform name string size */
extern Isa_desc		*isa;		/* isalist descriptor */
extern Uts_desc		*uts;		/* utsname descriptor */
extern uint_t		rtld_flags;	/* status flags for RTLD */
extern uint_t		rtld_flags2;	/* additional status flags for RTLD */
extern Fmap		*fmap;		/* Initial file mapping info */
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

extern const char	*locale;		/* locale environment setting */

extern Config		*config;		/* configuration structure */
extern const char	*locale;		/* locale environment setting */

extern const char	*rpl_audit;	/* replaceable LD_AUDIT string */
extern const char	*rpl_debug;	/* replaceable LD_DEBUG string */
extern const char	*rpl_ldflags;	/* replaceable LD_FLAGS string */
extern const char	*rpl_libpath;	/* replaceable LD_LIBRARY string */
extern Pnode		*rpl_libdirs;	/*	and its associated Pnode list */
extern const char	*rpl_preload;	/* replaceable LD_PRELOAD string */

extern const char	*prm_audit;	/* permanent LD_AUDIT string */
extern const char	*prm_debug;	/* permanent LD_DEBUG string */
extern const char	*prm_ldflags;	/* permanent LD_FLAGS string */
extern const char	*prm_libpath;	/* permanent LD_LIBRARY string */
extern Pnode		*prm_libdirs;	/*	and its associated Pnode list */
extern const char	*prm_preload;	/* permanent LD_PRELOAD string */

extern uint_t		env_info;	/* information regarding environment */
					/*	variables */
extern int		killsig;	/* signal sent on fatal exit */

extern uint_t		audit_argcnt;	/* no. of stack args to copy */
extern Audit_desc	*auditors;	/* global auditors */

extern char		**_environ;

extern const char	*dbg_file;	/* debugging directed to a file */

extern Reglist		*reglist;	/* list of register symbols */

extern const Msg	err_reject[];	/* rejection error message tables */
extern const Msg	ldd_reject[];

extern const char	*profile_name;	/* object being profiled */
extern const char	*profile_out;	/* profile output file */
extern const char	*profile_lib;	/* audit library to perform profile */

extern Dl_argsinfo	argsinfo;	/* process argument, environment and */
					/*	auxv information */

extern const char	*err_strs[];	/* diagnostic error string headers */
extern const char	*nosym_str;	/* MSG_GEN_NOSYM message cache */

extern ulong_t		hwcap;		/* hardware capabilities */
extern ulong_t		sfcap;		/* software capabilities */

extern avl_tree_t	*nfavl;		/* not-found AVL path name tree */

/*
 * Function declarations.
 */
extern void		addfree(void *, size_t);
extern int		append_alias(Rt_map *, const char *, int *);
extern int		analyze_lmc(Lm_list *, Aliste, Rt_map *, int *);
extern Am_ret		anon_map(Lm_list *, caddr_t *, size_t, int, int);
extern Fct		*are_u_this(Rej_desc *, int, struct stat *,
			    const char *);
extern void		atexit_fini(void);
extern int		bind_one(Rt_map *, Rt_map *, uint_t);
extern int		bufprint(Prfbuf *, const char *, ...);
extern void		call_array(Addr *, uint_t, Rt_map *, Word);
extern void		call_fini(Lm_list *, Rt_map **);
extern void		call_init(Rt_map **, int);
extern int		callable(Rt_map *, Rt_map *, Grp_hdl *, uint_t);
extern Rt_map		*_caller(caddr_t, int);
extern caddr_t		caller(void);
extern void		*calloc(size_t, size_t);
extern void		cap_assign(Cap *, Rt_map *);
extern int		cap_check(Rej_desc *, Ehdr *);
extern const char	*_conv_reloc_type(uint_t rel);
extern uintptr_t	dbg_setup(const char *, Dbg_desc *);
extern const char	*demangle(const char *);
extern int		dlclose_intn(Grp_hdl *, Rt_map *);
extern int		dlclose_core(Grp_hdl *, Rt_map *, Lm_list *);
extern Sym		*dlsym_handle(Grp_hdl *, Slookup *, Rt_map **,
			    uint_t *, int *);
extern void		*dlsym_intn(void *, const char *, Rt_map *, Rt_map **);
extern Grp_hdl		*dlmopen_intn(Lm_list *, const char *, int, Rt_map *,
			    uint_t, uint_t);
extern size_t		doprf(const char *, va_list, Prfbuf *);
extern int		dowrite(Prfbuf *);
extern void		dz_init(int);
extern caddr_t		dz_map(Lm_list *, caddr_t, size_t, int, int);
extern int		elf_config(Rt_map *, int);
extern int		elf_mach_flags_check(Rej_desc *, Ehdr *);
extern Rtc_obj		*elf_config_ent(const char *, Word, int, const char **);
extern Pnode		*elf_config_flt(Lm_list *, const char *, const char *);
extern ulong_t		elf_hash(const char *);
extern void 		elf_reloc_bad(Rt_map *, void *, uchar_t, ulong_t,
			    ulong_t);
extern ulong_t		elf_reloc_relative(ulong_t, ulong_t, ulong_t,
			    ulong_t, ulong_t, ulong_t);
extern ulong_t		elf_reloc_relacount(ulong_t, ulong_t,
			    ulong_t, ulong_t);
extern long		elf_static_tls(Rt_map *, Sym *, void *, uchar_t, char *,
			    ulong_t, long);
extern int		enter(int);
extern uint_t		expand(char **, size_t *, char **, uint_t, uint_t,
			    Rt_map *);
extern Pnode		*expand_paths(Rt_map *, const char *, uint_t, uint_t);
extern void		free_hdl(Grp_hdl *, Rt_map *, uint_t);
extern void		file_notfound(Lm_list *, const char *, Rt_map *,
			    uint_t, Rej_desc *);
extern int		find_path(Lm_list *, const char *, Rt_map *, uint_t,
			    Fdesc *, Rej_desc *, int *);
extern int		fpavl_insert(Lm_list *, Rt_map *, const char *,
			    avl_index_t);
extern Rt_map		*fpavl_recorded(Lm_list *, const char *, avl_index_t *);
extern void		fpavl_remove(Rt_map *);
extern size_t		fullpath(Rt_map *, const char *);
extern void		fmap_setup();
extern void		get_lcinterface(Rt_map *, Lc_interface *);
extern Lmid_t		get_linkmap_id(Lm_list *);
extern Pnode		*get_next_dir(Pnode **, Rt_map *, uint_t);
extern int		hdl_add(Grp_hdl *, Rt_map *, uint_t);
extern Grp_hdl		*hdl_create(Lm_list *, Rt_map *, Rt_map *, uint_t,
			    uint_t, uint_t);
extern int		hdl_initialize(Grp_hdl *, Rt_map *, int, int);
extern Pnode 		*hwcap_filtees(Pnode **, Aliste, Lm_cntl *, Dyninfo *,
			    Rt_map *, const char *, int, uint_t, int *);
extern void		is_dep_ready(Rt_map *, Rt_map *, int);
extern void		is_dep_init(Rt_map *, Rt_map *);
extern int		is_move_data(caddr_t);
extern int		is_path_secure(char *, Rt_map *, uint_t, uint_t);
extern int		is_rtld_setuid();
extern int		is_sym_interposer(Rt_map *, Sym *);
extern void		ldso_plt_init(Rt_map *);
extern Listnode		*list_append(List *, const void *);
extern Listnode		*list_insert(List *, const void *, Listnode *);
extern Listnode		*list_prepend(List *, const void *);
extern void		list_delete(List *, void *);
extern void		leave(Lm_list *, int);
extern void		lm_append(Lm_list *, Aliste, Rt_map *);
extern void		lm_delete(Lm_list *, Rt_map *);
extern void		lm_move(Lm_list *, Aliste, Aliste, Lm_cntl *,
			    Lm_cntl *);
extern void		load_completion(Rt_map *);
extern Rt_map 		*load_hwcap(Lm_list *, Aliste, const char *, Rt_map *,
			    uint_t, uint_t, Grp_hdl **, Rej_desc *, int *);
extern Rt_map		*load_path(Lm_list *, Aliste, const char **, Rt_map *,
			    int, uint_t, Grp_hdl **, Fdesc *, Rej_desc *,
			    int *);
extern Rt_map		*load_one(Lm_list *, Aliste, Pnode *, Rt_map *, int,
			    uint_t, Grp_hdl **, int *);
extern int		load_trace(Lm_list *, const char **, Rt_map *);
extern void		nfavl_insert(const char *, avl_index_t);
extern int		nfavl_recorded(const char *, avl_index_t *);
extern caddr_t		nu_map(Lm_list *, caddr_t, size_t, int, int);
extern void		*malloc(size_t);
extern int		move_data(Rt_map *);
extern int		pr_open(Lm_list *);
extern void		rd_event(Lm_list *, rd_event_e, r_state_e);
extern int		readenv_user(const char **, Word *, Word *, int);
extern int		readenv_config(Rtc_env *, Addr, int);
extern void		rejection_inherit(Rej_desc *, Rej_desc *);
extern int		relocate_lmc(Lm_list *, Aliste, Rt_map *, Rt_map *,
			    int *);
extern int		relocate_finish(Rt_map *, APlist *, int, int);
extern void		remove_cntl(Lm_list *, Aliste);
extern int		remove_hdl(Grp_hdl *, Rt_map *, int *);
extern void		remove_lmc(Lm_list *, Rt_map *, Lm_cntl *, Aliste,
			    const char *);
extern void		remove_incomplete(Lm_list *, Aliste);
extern void		remove_lists(Rt_map *, int);
extern void		remove_lml(Lm_list *);
extern void		remove_pnode(Pnode *);
extern void		remove_rej(Rej_desc *);
extern void		remove_so(Lm_list *, Rt_map *);
extern int		rt_cond_broadcast(Rt_cond *);
extern Rt_cond		*rt_cond_create(void);
extern int		rt_cond_wait(Rt_cond *, Rt_lock *);
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
extern int		rtld_getopt(char **, char ***, auxv_t **, Word *,
			    Word *, int);
extern void		security(uid_t, uid_t, gid_t, gid_t, int);
extern void		set_environ(Lm_list *);
extern Rt_map		*setup(char **, auxv_t *, Word, char *, int, char *,
			    Dyn *, ulong_t, ulong_t, int fd, Phdr *, char *,
			    char **, int, uid_t, uid_t, gid_t, gid_t, void *,
			    int, uint_t);
extern void		spavl_insert(const char *);
extern int		spavl_recorded(const char *, avl_index_t *);
extern int		tls_assign(Lm_list *, Rt_map *, Phdr *);
extern void		tls_modaddrem(Rt_map *, uint_t);
extern int		tls_statmod(Lm_list *, Rt_map *);
extern Rt_map		**tsort(Rt_map *, int, int);
extern void		unused(Lm_list *);
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
