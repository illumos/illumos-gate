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
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 */
#ifndef _RDB_H
#define	_RDB_H

#include <rtld_db.h>
#include <sys/types.h>
#include <procfs.h>
#include <proc_service.h>
#include <libelf.h>
#include <gelf.h>

#include <rdb_mach.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Definitions from 2.7 sys/procfs_isa.h.
 */
#ifndef	PR_MODEL_LP64
#define	PR_MODEL_UNKNOWN 0
#define	PR_MODEL_ILP32	1	/* process data model is ILP32 */
#define	PR_MODEL_LP64	2	/* process data model is LP64 */
#endif

#define	INTERPSECT	".interp"
#define	PLTSECT		".plt"

/*
 * Flags for step_n routine
 */
typedef enum {
	FLG_SN_NONE = 0,
	FLG_SN_VERBOSE = (1 << 0),	/* disassemble instructions */
	FLG_SN_PLTSKIP = (1 << 1)	/* step *over* PLTS */
} sn_flags_e;


typedef	enum {
	RET_FAILED = -1,
	RET_OK = 0
} retc_t;

/*
 * sym_tbl_t contains a primary and an (optional) auxiliary symbol table, which
 * we wish to treat as a single logical symbol table. In this logical table,
 * the data from the auxiliary table precedes that from the primary. Symbol
 * indices start at [0], which is the first item in the auxiliary table
 * if there is one. The sole purpose for this is so that we can treat the
 * combination of .SUNW_ldynsym and .dynsym sections as a logically single
 * entity without having to violate the public interface to libelf.
 *
 * Both tables must share the same string table section.
 *
 * The symtab_getsym() function serves as a gelf_getsym() replacement
 * that is aware of the two tables and makes them look like a single table
 * to the caller.
 *
 */
typedef struct sym_tbl {
	Elf_Data	*st_syms_pri;	/* start of primary table */
	Elf_Data	*st_syms_aux;	/* start of auxiliary table */
	char		*st_strs;	/* ptr to strings */
	size_t		st_symn;	/* Total # of entries in both tables */
	size_t		st_symn_aux;	/* # of entries in auxiliary table */
} sym_tbl_t;

typedef struct	map_info {
	char			*mi_name;	/* file info */
	char			*mi_refname;	/* filter reference name */
	ulong_t			mi_addr;	/* start address */
	ulong_t			mi_end;		/* end address */
	int			mi_mapfd;	/* file desc. for mapping */
	size_t			mi_pltentsz;	/* size of PLT entries */
	Elf			*mi_elf;	/* elf handle so we can close */
	GElf_Ehdr		mi_ehdr;
	sym_tbl_t		mi_symtab;	/* symbol table */
	sym_tbl_t		mi_dynsym;	/* dynamic symbol table */
	Lmid_t			mi_lmident;	/* Link Map Ident */
	ulong_t			mi_pltbase;	/* PLT base address */
	ulong_t			mi_pltsize;	/* size of PLT table */
	struct map_info		*mi_next;
	ulong_t			mi_flags;	/* misc flags */
	rd_loadobj_t		mi_loadobj;	/* keep the old loadobj for */
						/*	good luck */
} map_info_t;

#define	FLG_MI_EXEC		0x0001		/* is object an EXEC */

#define	FLG_PAP_SONAME		0x0001		/* embed SONAME in sym name */
#define	FLG_PAP_NOHEXNAME	0x0002		/* if no symbol return */
						/* null string */
#define	FLG_PAP_PLTDECOM	0x0004		/* decompe PLT name if */
						/* possible */
typedef struct map_list {
	map_info_t		*ml_head;
	map_info_t		*ml_tail;
} map_list_t;

/*
 * Break point information
 */
typedef struct bpt_struct {
	ulong_t			bl_addr;	/* address of breakpoint */
	bptinstr_t		bl_instr;	/* original instruction */
	unsigned		bl_flags;	/* break point flags */
	struct bpt_struct	*bl_next;
} bptlist_t;

#define	FLG_BP_USERDEF		0x0001		/* user defined BP */
#define	FLG_BP_RDPREINIT	0x0002		/* PREINIT BreakPoint */
#define	FLG_BP_RDPOSTINIT	0x0004		/* POSTINIT BreakPoint */
#define	FLG_BP_RDDLACT		0x0008		/* DLACT BreakPoint */
#define	FLG_BP_PLTRES		0x0010		/* PLT Resolve BP */

#define	MASK_BP_SPECIAL \
		(FLG_BP_RDPREINIT | FLG_BP_RDPOSTINIT | FLG_BP_RDDLACT)
#define	MASK_BP_STOP \
		(FLG_BP_USERDEF | FLG_BP_PLTRES)
#define	MASK_BP_ALL \
		(MASK_BP_SPECIAL | FLG_BP_USERDEF)

/*
 * Proc Services Structure
 */
struct ps_prochandle {
	pid_t		pp_pid;		/* debug process pid */
	rd_agent_t	*pp_rap;	/* rtld_db handle */
	int		pp_ctlfd;	/* open ctl proc fd */
	int		pp_statusfd;	/* open status proc fd */
	int		pp_asfd;	/* open as proc fd */
	int		pp_mapfd;	/* open map proc fd */
	uintptr_t	pp_ldsobase;	/* ld.so.1 base address */
	uintptr_t	pp_execphdr;	/* a.out phdr address */
	map_info_t	pp_ldsomap;	/* ld.so.1 map info */
	map_info_t	pp_execmap;	/* exec map info */
	map_list_t	pp_lmaplist;	/* list of link map infos */
	bptlist_t	*pp_breakpoints; /* break point list */
	void		*pp_auxvp;	/* pointer to AUX vectors */
	int		pp_flags;	/* misc flags */
	int		pp_dmodel;	/* data model */
};

#define	FLG_PP_PROMPT	0x0001		/* display debugger prompt */
#define	FLG_PP_LMAPS	0x0002		/* link maps available */
#define	FLG_PP_PACT	0x0004		/* active process being traced */
#define	FLG_PP_PLTSKIP	0x0008		/* PLT skipping is active */

/*
 * Debugging Structure
 */
typedef struct rtld_debug {
	int		rd_vers;
	caddr_t		rd_preinit;
	caddr_t		rd_postinit;
} rtld_debug_t;

#define	TRAPBREAK	0x91d02001	/* ta	ST_BREAKPOINT */

/*
 * values for rdb_flags
 */
#define	RDB_FL_EVENTS	0x0001		/* enable printing event information */

/*
 * Globals
 */

extern struct ps_prochandle	proch;
extern unsigned long		rdb_flags;

/*
 * Functions
 */
extern map_info_t	*addr_to_map(struct ps_prochandle *, ulong_t);
extern retc_t		addr_to_sym(struct ps_prochandle *, ulong_t,
				GElf_Sym *, char **);
extern void		CallStack(struct ps_prochandle *ph);
extern unsigned		continue_to_break(struct ps_prochandle *);
extern retc_t		delete_all_breakpoints(struct ps_prochandle *);
extern retc_t		delete_breakpoint(struct ps_prochandle *, ulong_t,
				unsigned);
extern void		disasm(struct ps_prochandle *, int);
extern retc_t		disasm_addr(struct ps_prochandle *, ulong_t, int);
extern retc_t		display_all_regs(struct ps_prochandle *);
extern retc_t		display_maps(struct ps_prochandle *);
extern retc_t		display_linkmaps(struct ps_prochandle *);
extern void		free_linkmaps(struct ps_prochandle *);
extern retc_t		get_linkmaps(struct ps_prochandle *);
extern ulong_t		hexstr_to_num(const char *);
extern ulong_t		is_plt(struct ps_prochandle *, ulong_t);
extern void		list_breakpoints(struct ps_prochandle *);
extern retc_t		load_map(struct ps_prochandle *, caddr_t,
				map_info_t *mp);
extern char		*print_address(unsigned long);
extern char		*print_address_ps(struct ps_prochandle *,
				unsigned long, unsigned);
extern void		print_mem(struct ps_prochandle *, ulong_t, int,
				char *);
extern void		print_varstring(struct ps_prochandle *, const char *);
extern void		print_mach_varstring(struct ps_prochandle *,
				const char *);
extern void		rdb_help(const char *);
extern void		rdb_prompt();
extern void		perr(char *);
extern retc_t		proc_string_read(struct ps_prochandle *,
				ulong_t, char *, int);
extern retc_t		ps_close(struct ps_prochandle *);
extern retc_t		ps_init(int, int, pid_t, struct ps_prochandle *);
extern retc_t		set_breakpoint(struct ps_prochandle *, ulong_t,
				unsigned);
extern retc_t		set_objpad(struct ps_prochandle *, size_t);
extern retc_t		step_n(struct ps_prochandle *, size_t, sn_flags_e);
extern void		step_to_addr(struct ps_prochandle *, ulong_t);
extern retc_t		str_map_sym(const char *, map_info_t *, GElf_Sym *,
				char **);
extern map_info_t	*str_to_map(struct ps_prochandle *, const char *);
extern retc_t		str_to_sym(struct ps_prochandle *, const char *,
				GElf_Sym *);
extern int		yyparse(void);
extern int		yyerror(const char *);
extern int		yylex(void);

#ifdef	__cplusplus
}
#endif

#endif /* _RDB_H */
