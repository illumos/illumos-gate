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
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#ifndef	_PCONTROL_H
#define	_PCONTROL_H

/*
 * Implemention-specific include file for libproc process management.
 * This is not to be seen by the clients of libproc.
 */

#include <stdio.h>
#include <gelf.h>
#include <synch.h>
#include <procfs.h>
#include <rtld_db.h>
#include <libproc.h>
#include <libctf.h>
#include <limits.h>
#include <libproc.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include "Putil.h"

/*
 * Definitions of the process control structures, internal to libproc.
 * These may change without affecting clients of libproc.
 */

/*
 * sym_tbl_t contains a primary and an (optional) auxiliary symbol table, which
 * we wish to treat as a single logical symbol table. In this logical table,
 * the data from the auxiliary table preceeds that from the primary. Symbol
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
typedef struct sym_tbl {	/* symbol table */
	Elf_Data *sym_data_pri;	/* primary table */
	Elf_Data *sym_data_aux;	/* auxiliary table */
	size_t	sym_symn_aux;	/* number of entries in auxiliary table */
	size_t	sym_symn;	/* total number of entries in both tables */
	char	*sym_strs;	/* ptr to strings */
	size_t	sym_strsz;	/* size of string table */
	GElf_Shdr sym_hdr_pri;	/* primary symbol table section header */
	GElf_Shdr sym_hdr_aux;	/* auxiliary symbol table section header */
	GElf_Shdr sym_strhdr;	/* string table section header */
	Elf	*sym_elf;	/* faked-up ELF handle from core file */
	void	*sym_elfmem;	/* data for faked-up ELF handle */
	uint_t	*sym_byname;	/* symbols sorted by name */
	uint_t	*sym_byaddr;	/* symbols sorted by addr */
	size_t	sym_count;	/* number of symbols in each sorted list */
} sym_tbl_t;

typedef struct file_info {	/* symbol information for a mapped file */
	plist_t	file_list;	/* linked list */
	char	file_pname[PRMAPSZ];	/* name from prmap_t */
	struct map_info *file_map;	/* primary (text) mapping */
	int	file_ref;	/* references from map_info_t structures */
	int	file_fd;	/* file descriptor for the mapped file */
	int	file_init;	/* 0: initialization yet to be performed */
	GElf_Half file_etype;	/* ELF e_type from ehdr */
	GElf_Half file_class;	/* ELF e_ident[EI_CLASS] from ehdr */
	rd_loadobj_t *file_lo;	/* load object structure from rtld_db */
	char	*file_lname;	/* load object name from rtld_db */
	char	*file_lbase;	/* pointer to basename of file_lname */
	char	*file_rname;	/* resolved on-disk object pathname */
	char	*file_rbase;	/* pointer to basename of file_rname */
	Elf	*file_elf;	/* ELF handle so we can close */
	void	*file_elfmem;	/* data for faked-up ELF handle */
	sym_tbl_t file_symtab;	/* symbol table */
	sym_tbl_t file_dynsym;	/* dynamic symbol table */
	uintptr_t file_dyn_base;	/* load address for ET_DYN files */
	uintptr_t file_plt_base;	/* base address for PLT */
	size_t	file_plt_size;	/* size of PLT region */
	uintptr_t file_jmp_rel;	/* base address of PLT relocations */
	uintptr_t file_ctf_off;	/* offset of CTF data in object file */
	size_t	file_ctf_size;	/* size of CTF data in object file */
	int	file_ctf_dyn;	/* does the CTF data reference the dynsym */
	void	*file_ctf_buf;	/* CTF data for this file */
	ctf_file_t *file_ctfp;	/* CTF container for this file */
	char	*file_shstrs;	/* section header string table */
	size_t	file_shstrsz;	/* section header string table size */
	uintptr_t *file_saddrs; /* section header addresses */
	uint_t  file_nsaddrs;   /* number of section header addresses */
} file_info_t;

typedef struct map_info {	/* description of an address space mapping */
	prmap_t	map_pmap;	/* /proc description of this mapping */
	file_info_t *map_file;	/* pointer into list of mapped files */
	off64_t map_offset;	/* offset into core file (if core) */
	int map_relocate;	/* associated file_map needs to be relocated */
} map_info_t;

typedef struct lwp_info {	/* per-lwp information from core file */
	plist_t	lwp_list;	/* linked list */
	lwpid_t	lwp_id;		/* lwp identifier */
	lwpsinfo_t lwp_psinfo;	/* /proc/<pid>/lwp/<lwpid>/lwpsinfo data */
	lwpstatus_t lwp_status;	/* /proc/<pid>/lwp/<lwpid>/lwpstatus data */
#if defined(sparc) || defined(__sparc)
	gwindows_t *lwp_gwins;	/* /proc/<pid>/lwp/<lwpid>/gwindows data */
	prxregset_t *lwp_xregs;	/* /proc/<pid>/lwp/<lwpid>/xregs data */
	int64_t *lwp_asrs;	/* /proc/<pid>/lwp/<lwpid>/asrs data */
#endif
} lwp_info_t;

typedef struct fd_info {
	plist_t	fd_list;	/* linked list */
	prfdinfo_t fd_info;	/* fd info */
} fd_info_t;

typedef struct core_info {	/* information specific to core files */
	char core_dmodel;	/* data model for core file */
	char core_osabi;	/* ELF OS ABI */
	int core_errno;		/* error during initialization if != 0 */
	plist_t core_lwp_head;	/* head of list of lwp info */
	lwp_info_t *core_lwp;	/* current lwp information */
	uint_t core_nlwp;	/* number of lwp's in list */
	off64_t core_size;	/* size of core file in bytes */
	char *core_platform;	/* platform string from core file */
	struct utsname *core_uts;	/* uname(2) data from core file */
	prcred_t *core_cred;	/* process credential from core file */
	core_content_t core_content;	/* content dumped to core file */
	prpriv_t *core_priv;	/* process privileges from core file */
	size_t core_priv_size;	/* size of the privileges */
	void *core_privinfo;	/* system privileges info from core file */
	priv_impl_info_t *core_ppii;	/* NOTE entry for core_privinfo */
	char *core_zonename;	/* zone name from core file */
#if defined(__i386) || defined(__amd64)
	struct ssd *core_ldt;	/* LDT entries from core file */
	uint_t core_nldt;	/* number of LDT entries in core file */
#endif
} core_info_t;

typedef struct elf_file_header { /* extended ELF header */
	unsigned char e_ident[EI_NIDENT];
	Elf64_Half e_type;
	Elf64_Half e_machine;
	Elf64_Word e_version;
	Elf64_Addr e_entry;
	Elf64_Off e_phoff;
	Elf64_Off e_shoff;
	Elf64_Word e_flags;
	Elf64_Half e_ehsize;
	Elf64_Half e_phentsize;
	Elf64_Half e_shentsize;
	Elf64_Word e_phnum;	/* phdr count extended to 32 bits */
	Elf64_Word e_shnum;	/* shdr count extended to 32 bits */
	Elf64_Word e_shstrndx;	/* shdr string index extended to 32 bits */
} elf_file_header_t;

typedef struct elf_file {	/* convenience for managing ELF files */
	elf_file_header_t e_hdr; /* Extended ELF header */
	Elf *e_elf;		/* ELF library handle */
	int e_fd;		/* file descriptor */
} elf_file_t;

#define	HASHSIZE		1024	/* hash table size, power of 2 */

struct ps_prochandle {
	struct ps_lwphandle **hashtab;	/* hash table for LWPs (Lgrab()) */
	mutex_t	proc_lock;	/* protects hash table; serializes Lgrab() */
	pstatus_t orig_status;	/* remembered status on Pgrab() */
	pstatus_t status;	/* status when stopped */
	psinfo_t psinfo;	/* psinfo_t from last Ppsinfo() request */
	uintptr_t sysaddr;	/* address of most recent syscall instruction */
	pid_t	pid;		/* process-ID */
	int	state;		/* state of the process, see "libproc.h" */
	uint_t	flags;		/* see defines below */
	uint_t	agentcnt;	/* Pcreate_agent()/Pdestroy_agent() ref count */
	int	asfd;		/* /proc/<pid>/as filedescriptor */
	int	ctlfd;		/* /proc/<pid>/ctl filedescriptor */
	int	statfd;		/* /proc/<pid>/status filedescriptor */
	int	agentctlfd;	/* /proc/<pid>/lwp/agent/ctl */
	int	agentstatfd;	/* /proc/<pid>/lwp/agent/status */
	int	info_valid;	/* if zero, map and file info need updating */
	map_info_t *mappings;	/* cached process mappings */
	size_t	map_count;	/* number of mappings */
	size_t	map_alloc;	/* number of mappings allocated */
	uint_t	num_files;	/* number of file elements in file_info */
	plist_t	file_head;	/* head of mapped files w/ symbol table info */
	char	*execname;	/* name of the executable file */
	auxv_t	*auxv;		/* the process's aux vector */
	int	nauxv;		/* number of aux vector entries */
	rd_agent_t *rap;	/* cookie for rtld_db */
	map_info_t *map_exec;	/* the mapping for the executable file */
	map_info_t *map_ldso;	/* the mapping for ld.so.1 */
	ps_ops_t ops;		/* ops-vector */
	uintptr_t *ucaddrs;	/* ucontext-list addresses */
	uint_t	ucnelems;	/* number of elements in the ucaddrs list */
	char	*zoneroot;	/* cached path to zone root */
	plist_t	fd_head;	/* head of file desc info list */
	int	num_fd;		/* number of file descs in list */
	uintptr_t map_missing;	/* first missing mapping in core due to sig */
	siginfo_t killinfo;	/* signal that interrupted core dump */
	psinfo_t spymaster;	/* agent LWP's spymaster, if any */
	void *data;		/* private data */
};

/* flags */
#define	CREATED		0x01	/* process was created by Pcreate() */
#define	SETSIG		0x02	/* set signal trace mask before continuing */
#define	SETFAULT	0x04	/* set fault trace mask before continuing */
#define	SETENTRY	0x08	/* set sysentry trace mask before continuing */
#define	SETEXIT		0x10	/* set sysexit trace mask before continuing */
#define	SETHOLD		0x20	/* set signal hold mask before continuing */
#define	SETREGS		0x40	/* set registers before continuing */
#define	INCORE		0x80	/* use in-core data to build symbol tables */

struct ps_lwphandle {
	struct ps_prochandle *lwp_proc;	/* process to which this lwp belongs */
	struct ps_lwphandle *lwp_hash;	/* hash table linked list */
	lwpstatus_t	lwp_status;	/* status when stopped */
	lwpsinfo_t	lwp_psinfo;	/* lwpsinfo_t from last Lpsinfo() */
	lwpid_t		lwp_id;		/* lwp identifier */
	int		lwp_state;	/* state of the lwp, see "libproc.h" */
	uint_t		lwp_flags;	/* SETHOLD and/or SETREGS */
	int		lwp_ctlfd;	/* /proc/<pid>/lwp/<lwpid>/lwpctl */
	int		lwp_statfd;	/* /proc/<pid>/lwp/<lwpid>/lwpstatus */
};

/*
 * Implementation functions in the process control library.
 * These are not exported to clients of the library.
 */
extern	void	prldump(const char *, lwpstatus_t *);
extern	int	dupfd(int, int);
extern	int	set_minfd(void);
extern	int	Pscantext(struct ps_prochandle *);
extern	void	Pinitsym(struct ps_prochandle *);
extern	void	Preadauxvec(struct ps_prochandle *);
extern	void	optimize_symtab(sym_tbl_t *);
extern	void	Pbuild_file_symtab(struct ps_prochandle *, file_info_t *);
extern	ctf_file_t *Pbuild_file_ctf(struct ps_prochandle *, file_info_t *);
extern	map_info_t *Paddr2mptr(struct ps_prochandle *, uintptr_t);
extern	char 	*Pfindexec(struct ps_prochandle *, const char *,
	int (*)(const char *, void *), void *);
extern	int	getlwpstatus(struct ps_prochandle *, lwpid_t, lwpstatus_t *);
int	Pstopstatus(struct ps_prochandle *, long, uint32_t);
extern	file_info_t *file_info_new(struct ps_prochandle *, map_info_t *);
extern	char	*Plofspath(const char *, char *, size_t);
extern	char	*Pzoneroot(struct ps_prochandle *, char *, size_t);
extern	char	*Pzonepath(struct ps_prochandle *, const char *, char *,
	size_t);
extern	fd_info_t *Pfd2info(struct ps_prochandle *, int);

extern	char	*Pfindmap(struct ps_prochandle *, map_info_t *, char *,
	size_t);

extern	int	Padd_mapping(struct ps_prochandle *, off64_t, file_info_t *,
    prmap_t *);
extern	void	Psort_mappings(struct ps_prochandle *);

extern char	procfs_path[PATH_MAX];

/*
 * Architecture-dependent definition of the breakpoint instruction.
 */
#if defined(sparc) || defined(__sparc)
#define	BPT	((instr_t)0x91d02001)
#elif defined(__i386) || defined(__amd64)
#define	BPT	((instr_t)0xcc)
#endif

/*
 * Simple convenience.
 */
#define	TRUE	1
#define	FALSE	0

#ifdef	__cplusplus
}
#endif

#endif	/* _PCONTROL_H */
