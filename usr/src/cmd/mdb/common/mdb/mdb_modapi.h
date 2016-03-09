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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 * Copyright (c) 2012 Joyent, Inc. All rights reserved.
 */

#ifndef	_MDB_MODAPI_H
#define	_MDB_MODAPI_H

/*
 * MDB Module API
 *
 * The debugger provides a set of interfaces for use in writing loadable
 * debugger modules.  Modules that call functions not listed in this header
 * file may not be compatible with future versions of the debugger.
 */

#include <sys/types.h>
#include <sys/null.h>
#include <gelf.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Make sure that TRUE, FALSE, MIN, and MAX have the usual definitions
 * so module writers can depend on these macros and defines.
 * Make sure NULL is available to module writers by including <sys/null.h>.
 */

#ifndef TRUE
#define	TRUE	1
#endif

#ifndef FALSE
#define	FALSE	0
#endif

#ifndef MIN
#define	MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifndef MAX
#define	MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#define	MDB_API_VERSION	4	/* Current API version number */

/*
 * Debugger command function flags:
 */
#define	DCMD_ADDRSPEC	0x01	/* Dcmd invoked with explicit address */
#define	DCMD_LOOP	0x02	/* Dcmd invoked in loop with ,cnt syntax */
#define	DCMD_LOOPFIRST	0x04	/* Dcmd invoked as first iteration of LOOP */
#define	DCMD_PIPE	0x08	/* Dcmd invoked with input from pipe */
#define	DCMD_PIPE_OUT	0x10	/* Dcmd invoked with output set to pipe */

#define	DCMD_HDRSPEC(fl)	(((fl) & DCMD_LOOPFIRST) || !((fl) & DCMD_LOOP))

/*
 * Debugger tab command function flags
 */
#define	DCMD_TAB_SPACE	0x01	/* Tab cb invoked with trailing space */

/*
 * Debugger command function return values:
 */
#define	DCMD_OK		0	/* Dcmd completed successfully */
#define	DCMD_ERR	1	/* Dcmd failed due to an error */
#define	DCMD_USAGE	2	/* Dcmd usage error; abort and print usage */
#define	DCMD_NEXT	3	/* Invoke next dcmd in precedence list */
#define	DCMD_ABORT	4	/* Dcmd failed; abort current loop or pipe */

#define	OFFSETOF(s, m)		(size_t)(&(((s *)0)->m))

extern int mdb_prop_postmortem;	/* Are we looking at a static dump? */
extern int mdb_prop_kernel;	/* Are we looking at a kernel? */

typedef enum {
	MDB_TYPE_STRING,	/* a_un.a_str is valid */
	MDB_TYPE_IMMEDIATE,	/* a_un.a_val is valid */
	MDB_TYPE_CHAR		/* a_un.a_char is valid */
} mdb_type_t;

typedef struct mdb_arg {
	mdb_type_t a_type;
	union {
		const char *a_str;
		uintmax_t a_val;
		char a_char;
	} a_un;
} mdb_arg_t;

typedef struct mdb_tab_cookie mdb_tab_cookie_t;
typedef int mdb_dcmd_f(uintptr_t, uint_t, int, const mdb_arg_t *);
typedef int mdb_dcmd_tab_f(mdb_tab_cookie_t *, uint_t, int,
    const mdb_arg_t *);

typedef struct mdb_dcmd {
	const char *dc_name;		/* Command name */
	const char *dc_usage;		/* Usage message (optional) */
	const char *dc_descr;		/* Description */
	mdb_dcmd_f *dc_funcp;		/* Command function */
	void (*dc_help)(void);		/* Command help function (or NULL) */
	mdb_dcmd_tab_f *dc_tabp;	/* Tab completion function */
} mdb_dcmd_t;

#define	WALK_ERR	-1		/* Walk fatal error (terminate walk) */
#define	WALK_NEXT	0		/* Walk should continue to next step */
#define	WALK_DONE	1		/* Walk is complete (no errors) */

typedef int (*mdb_walk_cb_t)(uintptr_t, const void *, void *);

typedef struct mdb_walk_state {
	mdb_walk_cb_t walk_callback;	/* Callback to issue */
	void *walk_cbdata;		/* Callback private data */
	uintptr_t walk_addr;		/* Current address */
	void *walk_data;		/* Walk private data */
	void *walk_arg;			/* Walk private argument */
	const void *walk_layer;		/* Data from underlying layer */
} mdb_walk_state_t;

typedef struct mdb_walker {
	const char *walk_name;		/* Walk type name */
	const char *walk_descr;		/* Walk description */
	int (*walk_init)(mdb_walk_state_t *);	/* Walk constructor */
	int (*walk_step)(mdb_walk_state_t *);	/* Walk iterator */
	void (*walk_fini)(mdb_walk_state_t *);	/* Walk destructor */
	void *walk_init_arg;		/* Walk constructor argument */
} mdb_walker_t;

typedef struct mdb_modinfo {
	ushort_t mi_dvers;		/* Debugger version number */
	const mdb_dcmd_t *mi_dcmds;	/* NULL-terminated list of dcmds */
	const mdb_walker_t *mi_walkers;	/* NULL-terminated list of walks */
} mdb_modinfo_t;

typedef struct mdb_bitmask {
	const char *bm_name;		/* String name to print */
	u_longlong_t bm_mask;		/* Mask for bits */
	u_longlong_t bm_bits;		/* Result required for value & mask */
} mdb_bitmask_t;

typedef struct mdb_pipe {
	uintptr_t *pipe_data;		/* Array of pipe values */
	size_t pipe_len;		/* Array length */
} mdb_pipe_t;

typedef struct mdb_object {
	const char *obj_name;		/* name of object */
	const char *obj_fullname;	/* full name of object */
	uintptr_t obj_base;		/* base address of object */
	uintptr_t obj_size;		/* in memory size of object in bytes */
} mdb_object_t;

typedef struct mdb_symbol {
	const char *sym_name;		/* name of symbol */
	const char *sym_object;		/* name of containing object */
	const GElf_Sym *sym_sym;	/* ELF symbol information */
	uint_t sym_table;		/* symbol table id */
	uint_t sym_id;			/* symbol identifier */
} mdb_symbol_t;

extern int mdb_pwalk(const char *, mdb_walk_cb_t, void *, uintptr_t);
extern int mdb_walk(const char *, mdb_walk_cb_t, void *);

extern int mdb_pwalk_dcmd(const char *, const char *,
	int, const mdb_arg_t *, uintptr_t);

extern int mdb_walk_dcmd(const char *, const char *, int, const mdb_arg_t *);

extern int mdb_layered_walk(const char *, mdb_walk_state_t *);

extern int mdb_call_dcmd(const char *, uintptr_t,
	uint_t, int, const mdb_arg_t *);

extern int mdb_add_walker(const mdb_walker_t *);
extern int mdb_remove_walker(const char *);

extern ssize_t mdb_vread(void *, size_t, uintptr_t);
extern ssize_t mdb_vwrite(const void *, size_t, uintptr_t);

extern ssize_t mdb_aread(void *, size_t, uintptr_t, void *);
extern ssize_t mdb_awrite(const void *, size_t, uintptr_t, void *);

extern ssize_t mdb_fread(void *, size_t, uintptr_t);
extern ssize_t mdb_fwrite(const void *, size_t, uintptr_t);

extern ssize_t mdb_pread(void *, size_t, uint64_t);
extern ssize_t mdb_pwrite(const void *, size_t, uint64_t);

extern ssize_t mdb_readstr(char *, size_t, uintptr_t);
extern ssize_t mdb_writestr(const char *, uintptr_t);

extern ssize_t mdb_readsym(void *, size_t, const char *);
extern ssize_t mdb_writesym(const void *, size_t, const char *);

extern ssize_t mdb_readvar(void *, const char *);
extern ssize_t mdb_writevar(const void *, const char *);

#define	MDB_SYM_NAMLEN	1024			/* Recommended max name len */

#define	MDB_SYM_FUZZY	0			/* Match closest address */
#define	MDB_SYM_EXACT	1			/* Match exact address only */

#define	MDB_OBJ_EXEC	((const char *)0L)	/* Primary executable file */
#define	MDB_OBJ_RTLD	((const char *)1L)	/* Run-time link-editor */
#define	MDB_OBJ_EVERY	((const char *)-1L)	/* All known symbols */

extern int mdb_lookup_by_name(const char *, GElf_Sym *);
extern int mdb_lookup_by_obj(const char *, const char *, GElf_Sym *);
extern int mdb_lookup_by_addr(uintptr_t, uint_t, char *, size_t, GElf_Sym *);

typedef uintptr_t mdb_tid_t;
typedef uint64_t mdb_reg_t;

extern int mdb_getareg(mdb_tid_t, const char *, mdb_reg_t *);

#define	MDB_OPT_SETBITS	1			/* Set specified flag bits */
#define	MDB_OPT_CLRBITS	2			/* Clear specified flag bits */
#define	MDB_OPT_STR	3			/* const char * argument */
#define	MDB_OPT_UINTPTR	4			/* uintptr_t argument */
#define	MDB_OPT_UINT64	5			/* uint64_t argument */
#define	MDB_OPT_UINTPTR_SET	6		/* boolean_t+uintptr_t args */

extern int mdb_getopts(int, const mdb_arg_t *, ...);

extern u_longlong_t mdb_strtoull(const char *);

#define	UM_NOSLEEP	0x0	/* Do not call failure handler; may fail */
#define	UM_SLEEP	0x1	/* Can block for memory; will always succeed */
#define	UM_GC		0x2	/* Garbage-collect this block automatically */

extern void *mdb_alloc(size_t, uint_t);
extern void *mdb_zalloc(size_t, uint_t);
extern void mdb_free(void *, size_t);

extern size_t mdb_snprintf(char *, size_t, const char *, ...);
extern void mdb_printf(const char *, ...);
extern void mdb_warn(const char *, ...);
extern void mdb_flush(void);

extern int mdb_ffs(uintmax_t);

extern void mdb_nhconvert(void *, const void *, size_t);

#define	MDB_DUMP_RELATIVE	0x0001	/* Start numbering at 0 */
#define	MDB_DUMP_ALIGN		0x0002	/* Enforce paragraph alignment */
#define	MDB_DUMP_PEDANT		0x0004	/* Full-width addresses */
#define	MDB_DUMP_ASCII		0x0008	/* Display ASCII values */
#define	MDB_DUMP_HEADER		0x0010	/* Display a header */
#define	MDB_DUMP_TRIM		0x0020	/* Trim at boundaries */
#define	MDB_DUMP_SQUISH		0x0040	/* Eliminate redundant lines */
#define	MDB_DUMP_NEWDOT		0x0080	/* Update dot when done */
#define	MDB_DUMP_ENDIAN		0x0100	/* Adjust for endianness */
#define	MDB_DUMP_WIDTH(x)	((((x) - 1) & 0xf) << 16) /* paragraphs/line */
#define	MDB_DUMP_GROUP(x)	((((x) - 1) & 0xff) << 20) /* bytes/group */

typedef ssize_t (*mdb_dumpptr_cb_t)(void *, size_t, uintptr_t, void *);
typedef ssize_t (*mdb_dump64_cb_t)(void *, size_t, uint64_t, void *);

extern int mdb_dumpptr(uintptr_t, size_t, uint_t, mdb_dumpptr_cb_t, void *);
extern int mdb_dump64(uint64_t, uint64_t, uint_t, mdb_dump64_cb_t, void *);

extern const char *mdb_one_bit(int, int, int);
extern const char *mdb_inval_bits(int, int, int);

extern ulong_t mdb_inc_indent(ulong_t);
extern ulong_t mdb_dec_indent(ulong_t);

extern int mdb_eval(const char *);
extern void mdb_set_dot(uintmax_t);
extern uintmax_t mdb_get_dot(void);

extern void mdb_get_pipe(mdb_pipe_t *);
extern void mdb_set_pipe(const mdb_pipe_t *);

extern ssize_t mdb_get_xdata(const char *, void *, size_t);

typedef int (*mdb_object_cb_t)(mdb_object_t *, void *);
extern int mdb_object_iter(mdb_object_cb_t, void *);

#define	MDB_SYMTAB		1	/* Normal symbol table (.symtab) */
#define	MDB_DYNSYM		2	/* Dynamic symbol table (.dynsym) */

#define	MDB_BIND_LOCAL		0x0001	/* Local (static-scope) symbols */
#define	MDB_BIND_GLOBAL		0x0002	/* Global symbols */
#define	MDB_BIND_WEAK		0x0004	/* Weak binding symbols */
#define	MDB_BIND_ANY		0x0007	/* Any of the above */

#define	MDB_TYPE_NOTYPE		0x0100	/* Symbol has no type */
#define	MDB_TYPE_OBJECT		0x0200	/* Symbol refers to data */
#define	MDB_TYPE_FUNC		0x0400	/* Symbol refers to text */
#define	MDB_TYPE_SECT		0x0800	/* Symbol refers to a section */
#define	MDB_TYPE_FILE		0x1000	/* Symbol refers to a source file */
#define	MDB_TYPE_COMMON		0x2000	/* Symbol refers to a common block */
#define	MDB_TYPE_TLS		0x4000	/* Symbol refers to TLS */

#define	MDB_TYPE_ANY		0x7f00	/* Any of the above */

typedef int (*mdb_symbol_cb_t)(mdb_symbol_t *, void *);
extern int mdb_symbol_iter(const char *, uint_t, uint_t, mdb_symbol_cb_t,
    void *);

#define	MDB_STATE_IDLE		0	/* Target is idle (not running yet) */
#define	MDB_STATE_RUNNING	1	/* Target is currently executing */
#define	MDB_STATE_STOPPED	2	/* Target is stopped */
#define	MDB_STATE_UNDEAD	3	/* Target is undead (zombie) */
#define	MDB_STATE_DEAD		4	/* Target is dead (core dump) */
#define	MDB_STATE_LOST		5	/* Target lost by debugger */

extern int mdb_get_state(void);

#define	MDB_CALLBACK_STCHG	1
#define	MDB_CALLBACK_PROMPT	2

typedef void (*mdb_callback_f)(void *);

extern void *mdb_callback_add(int, mdb_callback_f, void *);
extern void mdb_callback_remove(void *);

#define	MDB_TABC_ALL_TYPES	0x1	/* Include array types in type output */
#define	MDB_TABC_MEMBERS	0x2	/* Tab comp. types with members */
#define	MDB_TABC_NOPOINT	0x4	/* Tab comp. everything but pointers */
#define	MDB_TABC_NOARRAY	0x8	/* Don't include array data in output */

/*
 * Module's interaction path
 */
extern void mdb_tab_insert(mdb_tab_cookie_t *, const char *);
extern void mdb_tab_setmbase(mdb_tab_cookie_t *, const char *);

/*
 * Tab completion utility functions for modules.
 */
extern int mdb_tab_complete_type(mdb_tab_cookie_t *, const char *, uint_t);
extern int mdb_tab_complete_member(mdb_tab_cookie_t *, const char *,
    const char *);
extern int mdb_tab_typename(int *, const mdb_arg_t **, char *buf, size_t len);

/*
 * Tab completion functions for common signatures.
 */
extern int mdb_tab_complete_mt(mdb_tab_cookie_t *, uint_t, int,
    const mdb_arg_t *);

extern size_t strlcat(char *, const char *, size_t);
extern char *strcat(char *, const char *);
extern char *strcpy(char *, const char *);
extern char *strncpy(char *, const char *, size_t);

/* Need to be consistent with <string.h> C++ definitions */
#if __cplusplus >= 199711L
extern const char *strchr(const char *, int);
#ifndef	_STRCHR_INLINE
#define	_STRCHR_INLINE
extern "C++" {
	inline char *strchr(char *__s, int __c) {
		return (char *)strchr((const char *)__s, __c);
	}
}
#endif	/* _STRCHR_INLINE */
extern const char *strrchr(const char *, int);
#ifndef	_STRRCHR_INLINE
#define	_STRRCHR_INLINE
extern	"C++" {
	inline char *strrchr(char *__s, int __c) {
		return (char *)strrchr((const char *)__s, __c);
	}
}
#endif	/* _STRRCHR_INLINE */
extern const char *strstr(const char *, const char *);
#ifndef	_STRSTR_INLINE
#define	_STRSTR_INLINE
extern "C++" {
	inline char *strstr(char *__s1, const char *__s2) {
		return (char *)strstr((const char *)__s1, __s2);
	}
}
#endif	/* _STRSTR_INLINE */
#else
extern char *strchr(const char *, int);
extern char *strrchr(const char *, int);
extern char *strstr(const char *, const char *);
#endif	/* __cplusplus >= 199711L */

extern int strcmp(const char *, const char *);
extern int strncmp(const char *, const char *, size_t);
extern int strcasecmp(const char *, const char *);
extern int strncasecmp(const char *, const char *, size_t);

extern size_t strlen(const char *);

extern int bcmp(const void *, const void *, size_t);
extern void bcopy(const void *, void *, size_t);
extern void bzero(void *, size_t);

extern void *memcpy(void *, const void *, size_t);
extern void *memmove(void *, const void *, size_t);
extern int memcmp(const void *, const void *, size_t);
/* Need to be consistent with <string.h> C++ definitions */
#if __cplusplus >= 199711L
extern const void *memchr(const void *, int, size_t);
#ifndef _MEMCHR_INLINE
#define	_MEMCHR_INLINE
extern "C++" {
	inline void *memchr(void * __s, int __c, size_t __n) {
		return (void *)memchr((const void *)__s, __c, __n);
	}
}
#endif  /* _MEMCHR_INLINE */
#else
extern void *memchr(const void *, int, size_t);
#endif /* __cplusplus >= 199711L */
extern void *memset(void *, int, size_t);
extern void *memccpy(void *, const void *, int, size_t);

extern void *bsearch(const void *, const void *, size_t, size_t,
    int (*)(const void *, const void *));

extern void qsort(void *, size_t, size_t,
    int (*)(const void *, const void *));

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_MODAPI_H */
