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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 *	Copyright (c) 1989 AT&T
 *	  All Rights Reserved
 *
 */

#ifndef _DLFCN_H
#define	_DLFCN_H

#include <sys/feature_tests.h>
#include <sys/types.h>
#if !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__)
#include <sys/auxv.h>
#include <sys/mman.h>
#endif /* !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__) */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Information structures for various dlinfo() requests.
 */
#if !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__)
typedef struct	dl_info {
	const char	*dli_fname;	/* file containing address range */
	void		*dli_fbase;	/* base address of file image */
	const char	*dli_sname;	/* symbol name */
	void		*dli_saddr;	/* symbol address */
} Dl_info;
typedef	Dl_info		Dl_info_t;

typedef struct	dl_serpath {
	char		*dls_name;	/* library search path name */
	uint_t		dls_flags;	/* path information */
} Dl_serpath;
typedef	Dl_serpath	Dl_serpath_t;

typedef struct	dl_serinfo {
	size_t		dls_size;	/* total buffer size */
	uint_t		dls_cnt;	/* number of path entries */
	Dl_serpath	dls_serpath[1];	/* there may be more than one */
} Dl_serinfo;
typedef	Dl_serinfo	Dl_serinfo_t;

typedef struct	dl_argsinfo {
	long		dla_argc;	/* process argument count */
	char		**dla_argv;	/* process arguments */
	char		**dla_envp;	/* process environment variables */
	auxv_t		*dla_auxv;	/* process auxv vectors */
} Dl_argsinfo;
typedef	Dl_argsinfo	Dl_argsinfo_t;

typedef struct {
	mmapobj_result_t *dlm_maps;	/* mapping information */
	uint_t		dlm_acnt;	/* number of dlm_maps mappings */
	uint_t		dlm_rcnt;	/* number of returned mappings */
} Dl_mapinfo_t;

typedef struct {
	uint_t		dlui_version;	/* version # */
	uint_t		dlui_flags;	/* flags */
	char		*dlui_objname;	/* path to object */
	void		*dlui_unwindstart; /* star of unwind hdr */
	void		*dlui_unwindend; /* end of unwind hdr */
	void		*dlui_segstart;	/* start of segment described */
					/*  by unwind block */
	void		*dlui_segend;	/* end of segment described */
					/*  by unwind block */
} Dl_amd64_unwindinfo;
typedef	Dl_amd64_unwindinfo	Dl_amd64_unwindinfo_t;

typedef	struct {
	const char	*dld_refname;	/* reference name */
	const char	*dld_depname;	/* new dependency name */
} Dl_definfo_t;

#endif /* !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__) */


typedef ulong_t		Lmid_t;

/*
 * Declarations used for dynamic linking support routines.
 */
extern void	*dlopen(const char *, int);
extern void	*dlsym(void *_RESTRICT_KYWD, const char *_RESTRICT_KYWD);
extern int	dlclose(void *);
extern char	*dlerror(void);
#if !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__)
extern void	*dlmopen(Lmid_t, const char *, int);
extern int	dladdr(void *, Dl_info *);
extern int	dladdr1(void *, Dl_info *, void **, int);
extern int	dldump(const char *, const char *, int);
extern int	dlinfo(void *, int, void *);
extern Dl_amd64_unwindinfo  *dlamd64getunwind(void *, Dl_amd64_unwindinfo *);
#endif /* !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__) */

#pragma unknown_control_flow(dlopen, dlsym, dlclose, dlerror)
#if !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__)
#pragma unknown_control_flow(dlmopen, dladdr, dladdr1, dldump, dlinfo)
#endif /* !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__) */

/*
 * Valid values for handle argument to dlsym(3x).
 */
#define	RTLD_NEXT		(void *)-1	/* look in `next' dependency */
#define	RTLD_DEFAULT		(void *)-2	/* look up symbol from scope */
						/*	of current object */
#define	RTLD_SELF		(void *)-3	/* look in `ourself' */
#define	RTLD_PROBE		(void *)-4	/* look up symbol from scope */
						/*	of current object, */
						/*	using currently */
						/*	loaded objects only. */
/*
 * Valid values for mode argument to dlopen.
 */
#define	RTLD_LAZY		0x00001		/* deferred function binding */
#define	RTLD_NOW		0x00002		/* immediate function binding */
#define	RTLD_NOLOAD		0x00004		/* don't load object */

#define	RTLD_GLOBAL		0x00100		/* export symbols to others */
#define	RTLD_LOCAL		0x00000		/* symbols are only available */
						/*	to group members */
#define	RTLD_PARENT		0x00200		/* add parent (caller) to */
						/*	a group dependencies */
#define	RTLD_GROUP		0x00400		/* resolve symbols within */
						/*	members of the group */
#define	RTLD_WORLD		0x00800		/* resolve symbols within */
						/*	global objects */
#define	RTLD_NODELETE		0x01000		/* do not remove members */
#define	RTLD_FIRST		0x02000		/* only first object is */
						/*	available for dlsym */
#define	RTLD_CONFGEN		0x10000		/* crle(1) config generation */
						/*	internal use only */

/*
 * Valid values for flag argument to dldump.
 */
#define	RTLD_REL_RELATIVE	0x00001		/* apply relative relocs */
#define	RTLD_REL_EXEC		0x00002		/* apply symbolic relocs that */
						/*	bind to main */
#define	RTLD_REL_DEPENDS	0x00004		/* apply symbolic relocs that */
						/*	bind to dependencies */
#define	RTLD_REL_PRELOAD	0x00008		/* apply symbolic relocs that */
						/*	bind to preload objs */
#define	RTLD_REL_SELF		0x00010		/* apply symbolic relocs that */
						/*	bind to ourself */
#define	RTLD_REL_WEAK		0x00020		/* apply symbolic weak relocs */
						/*	even if unresolved */
#define	RTLD_REL_ALL		0x00fff		/* apply all relocs */

#define	RTLD_MEMORY		0x01000		/* use memory sections */
#define	RTLD_STRIP		0x02000		/* retain allocable sections */
						/*	only */
#define	RTLD_NOHEAP		0x04000		/* do no save any heap */
#define	RTLD_CONFSET		0x10000		/* crle(1) config generation */
						/*	internal use only */

/*
 * Valid values for dladdr1() flags.
 */
#define	RTLD_DL_SYMENT		1		/* return symbol table entry */
#define	RTLD_DL_LINKMAP		2		/* return public link-map */
#define	RTLD_DL_MASK		0xffff


/*
 * Arguments for dlinfo()
 */
#define	RTLD_DI_LMID		1		/* obtain link-map id */
#define	RTLD_DI_LINKMAP		2		/* obtain link-map */
#define	RTLD_DI_CONFIGADDR	3		/* obtain config addr */
#define	RTLD_DI_SERINFO		4		/* obtain search path info or */
#define	RTLD_DI_SERINFOSIZE	5		/*    associated info size */
#define	RTLD_DI_ORIGIN		6		/* obtain objects origin */
#define	RTLD_DI_PROFILENAME	7		/* obtain profile object name */
						/*    internal use only */
#define	RTLD_DI_PROFILEOUT	8		/* obtain profile output name */
						/*    internal use only */
#define	RTLD_DI_GETSIGNAL	9		/* get termination signal */
#define	RTLD_DI_SETSIGNAL	10		/* set termination signal */
#define	RTLD_DI_ARGSINFO	11		/* get process arguments */
						/*    environment and auxv */
#define	RTLD_DI_MMAPS		12		/* obtain objects mappings or */
#define	RTLD_DI_MMAPCNT		13		/*    mapping count */
#define	RTLD_DI_DEFERRED	14		/* assign new dependency to a */
						/*    deferred dependency */
#define	RTLD_DI_DEFERRED_SYM	15		/* assign new dependency to a */
						/*    deferred dependency */
						/*    using a symbol name */
#define	RTLD_DI_MAX		15

#if !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__)
/*
 * Version information for Dl_amd64_unwindinfo.dlui_version
 */
#define	DLUI_VERS_1		1
#define	DLUI_VERS_CURRENT	DLUI_VERS_1

/*
 * Valid flags for Dl_amd64_unwindinfo.dlfi_flags
 */
#define	DLUI_FLG_NOUNWIND	0x0001		/* object has no Unwind info */
#define	DLUI_FLG_NOOBJ		0x0002		/* no object was found */
						/*  matching the pc provided */
#endif /* !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__) */

#ifdef	__cplusplus
}
#endif

#endif	/* _DLFCN_H */
