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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/link.h>
#include <libproc.h>
#include <proc_service.h>
#include <rtld_db.h>
#include <synch.h>
#include <sys/lx_brand.h>

static void *lx_ldb_client_init(struct ps_prochandle *);
static int lx_ldb_iter(struct ps_prochandle *, rl_iter_f *, void *, void *);
static void lx_ldb_fix_phdr(struct rd_agent *, Elf32_Dyn *, size_t,
    psaddr_t);

struct rd_agent {
	mutex_t				rd_mutex;
	struct ps_prochandle		*rd_psp;	/* prochandle pointer */
	psaddr_t			rd_rdebug;	/* rtld r_debug */
	psaddr_t			rd_preinit;	/* rtld_db_preinit */
	psaddr_t			rd_postinit;	/* rtld_db_postinit */
	psaddr_t			rd_dlact;	/* rtld_db_dlact */
	psaddr_t			rd_tbinder;	/* tail of binder */
	psaddr_t			rd_rtlddbpriv;	/* rtld rtld_db_priv */
	ulong_t				rd_flags;	/* flags */
	ulong_t				rd_rdebugvers;	/* rtld_db_priv.vers */
	int				rd_dmodel;	/* data model */
	rd_helper_t			rd_helper;	/* private to helper */
};

typedef struct lx_rd {
	struct ps_prochandle	*lr_php;	/* prochandle of target */
	uint32_t lr_rdebug;	/* address of lx r_debug */
	uint32_t lr_exec;	/* base address of main executable */
} lx_rd_t;

rd_helper_ops_t RTLD_DB_BRAND_OPS = {
	lx_ldb_client_init,
	lx_ldb_iter,
	lx_ldb_fix_phdr
};

struct lx_link_map
{
	uint32_t lxm_addr;	/* Base address shared object is loaded at.  */
	uint32_t lxm_name;	/* Absolute file name object was found in.  */
	uint32_t lxm_ld;	/* Dynamic section of the shared object.  */
	uint32_t lxm_next; /* Chain of loaded objects.  */
	uint32_t lxm_prev;
};

struct lx_r_debug
{
	int r_version;		/* Version number for this protocol.  */
	uint32_t	r_map;	/* Head of the chain of loaded objects. */

	/*
	 * This is the address of a function internal to the run-time linker,
	 * that will always be called when the linker begins to map in a
	 * library or unmap it, and again when the mapping change is complete.
	 * The debugger can set a breakpoint at this address if it wants to
	 * notice shared object mapping changes.
	 */
	uint32_t	r_brk;
	r_state_e	r_state; /* defined the same way between lx/solaris */
	uint32_t	r_ldbase; /* Base address the linker is loaded at. */
};

/*
 * A key difference between the linux linker and ours' is that the linux
 * linker adds the base address of segments to certain values in the
 * segments' ELF header. As an example, look at the address of the
 * DT_HASH hash table in a Solaris section - it is a relative address
 * which locates the start of the hash table, relative to the beginning
 * of the ELF file. However, when the linux linker loads a section, it
 * modifies the in-memory ELF image by changing address of the hash
 * table to be an absolute address. This is only done for libraries - not for
 * executables.
 *
 * Solaris tools expect the relative address to remain relative, so
 * here we will modify the in-memory ELF image so that it once again
 * contains relative addresses.
 *
 * To accomplish this, we walk through all sections in the target.
 * Linux sections are identified by pointing to the linux linker or libc in the
 * DT_NEEDED section. For all matching sections, we subtract the segment
 * base address to get back to relative addresses.
 */
static void
lx_ldb_fix_phdr(struct rd_agent *rap, Elf32_Dyn *dp, size_t size,
    psaddr_t addr)
{
	struct ps_prochandle	*php = rap->rd_psp;
	int			i;
	int			strsz = 0;
	uint32_t		strtab_p = NULL;
	char			*strtab;

	/* Make sure addr matches the current byte size */
	addr = (uint32_t)addr;

	/*
	 * First we need to find the address of the string table.
	 */
	for (i = 0; i < size / sizeof (Elf32_Dyn); i++) {
		if (dp[i].d_tag == DT_STRTAB)
			strtab_p = dp[i].d_un.d_ptr;
		if (dp[i].d_tag == DT_STRSZ)
			strsz = dp[i].d_un.d_val;
	}
	if (strtab_p == NULL) {
		ps_plog("lx_librtld_db: couldn't find strtab");
		return;
	}
	if (strsz == 0) {
		ps_plog("lx_librtld_db: couldn't find strsz");
		return;
	}

	if ((strtab = malloc(strsz)) == NULL)
		return;
	if (Pread(php, strtab, strsz, strtab_p) != strsz) {
		ps_plog("lx_librtld_db: couldn't read strtab at 0x%p",
		    strtab_p);
		free(strtab);
		return;
	}

	/*
	 * ELF binaries may have more than one DT_NEEDED entry - we must
	 * check them all. The linux linker segment also needs to be fixed,
	 * but it doesn't have a DT_NEEDED entry. Instead, look for a
	 * matching DT_SONAME.
	 */
	for (i = 0; i < size / sizeof (Elf32_Dyn); i++) {
		if (dp[i].d_tag == DT_SONAME &&
		    strncmp(strtab + dp[i].d_un.d_ptr, LX_LINKER_NAME,
		    sizeof (LX_LINKER_NAME)) == 0)
			break;

		if (dp[i].d_tag != DT_NEEDED)
			continue;

		if (strncmp(strtab + dp[i].d_un.d_ptr,
		    LX_LINKER_NAME, sizeof (LX_LINKER_NAME)) == 0 ||
		    strncmp(strtab + dp[i].d_un.d_ptr, LX_LIBC_NAME,
		    sizeof (LX_LIBC_NAME)) == 0)
			break;
	}
	free(strtab);
	if (i == size / sizeof (Elf32_Dyn)) {
		/*
		 * This is not a linux mapping, so we have nothing left to do.
		 */
		ps_plog("lx_librtld_db: "
		    "0x%p doesn't appear to be an lx object", addr);
		return;
	}

	/*
	 * The linux linker added the segment's base address to a bunch of the
	 * dynamic section addresses. Fix them back to their original, on-disk
	 * format so Solaris understands them.
	 */
	for (i = 0; i < size / sizeof (Elf32_Dyn); i++) {
		switch (dp[i].d_tag) {
		case DT_INIT:
		case DT_FINI:
		case DT_HASH:
		case DT_STRTAB:
		case DT_SYMTAB:
		case DT_DEBUG:
		case DT_PLTGOT:
		case DT_JMPREL:
		case DT_REL:
		case DT_VERNEED:
		case DT_VERSYM:
			if (dp[i].d_un.d_val > addr) {
				dp[i].d_un.d_ptr -= addr;
			}
			break;
		default:
			break;
		}
	}
}

/*
 * The linux linker has an r_debug structure somewhere in its data section that
 * contains the address of the head of the link map list. To find this, we will
 * use the DT_DEBUG token in the executable's dynamic section. The linux linker
 * wrote the address of its r_debug structure to the DT_DEBUG dynamic entry. We
 * get the address of the executable's program headers from the
 * AT_SUN_BRAND_LX_PHDR aux vector entry. From there, we calculate the
 * address of the Elf header, and from there we can easily get to the DT_DEBUG
 * entry.
 */
static void *
lx_ldb_client_init(struct ps_prochandle *php)
{
	lx_rd_t		*rd = calloc(sizeof (lx_rd_t), 1);
	uint32_t	phdr_addr, ehdr_addr, dp_addr;
	Elf32_Dyn	*dp;
	Elf32_Phdr	phdr, *ph, *phdrs;
	Elf32_Ehdr	ehdr;
	int		i, dp_count;

	rd->lr_rdebug = 0;

	if (rd == NULL) {
		ps_plog("lx_ldb_client_init: cannot allocate memory");
		return (NULL);
	}

	phdr_addr = Pgetauxval(php, AT_SUN_BRAND_LX_PHDR);
	if (phdr_addr == (uint32_t)-1) {
		ps_plog("lx_ldb_client_init: no LX_PHDR found in aux vector");
		return (NULL);
	}
	ps_plog("lx_ldb_client_init: found LX_PHDR auxv phdr at: 0x%p",
	    phdr_addr);

	if (ps_pread(php, phdr_addr, &phdr, sizeof (phdr)) != PS_OK) {
		ps_plog("lx_ldb_client_init: couldn't read phdr at 0x%p",
		    phdr_addr);
		free(rd);
		return (NULL);
	}

	/* The ELF headher should be before the program header in memory */
	rd->lr_exec = ehdr_addr = phdr_addr - phdr.p_offset;
	if (ps_pread(php, ehdr_addr, &ehdr, sizeof (ehdr)) !=
	    PS_OK) {
		ps_plog("lx_ldb_client_init: couldn't read ehdr at 0x%p",
		    rd->lr_exec);
		free(rd);
		return (NULL);
	}
	ps_plog("lx_ldb_client_init: read ehdr at: 0x%p", ehdr_addr);

	if ((phdrs = malloc(ehdr.e_phnum * ehdr.e_phentsize)) == NULL) {
		ps_plog("lx_ldb_client_init: couldn't alloc phdrs memory");
		free(rd);
		return (NULL);
	}

	if (ps_pread(php, phdr_addr, phdrs, ehdr.e_phnum * ehdr.e_phentsize) !=
	    PS_OK) {
		ps_plog("lx_ldb_client_init: couldn't read phdrs at 0x%p",
		    phdr_addr);
		free(rd);
		free(phdrs);
		return (NULL);
	}
	ps_plog("lx_ldb_client_init: read %d phdrs at: 0x%p",
	    ehdr.e_phnum, phdr_addr);

	for (i = 0, ph = phdrs; i < ehdr.e_phnum; i++,
	    /*LINTED */
	    ph = (Elf32_Phdr *)((char *)ph + ehdr.e_phentsize)) {
		if (ph->p_type == PT_DYNAMIC)
			break;
	}
	if (i == ehdr.e_phnum) {
		ps_plog("lx_ldb_client_init: no PT_DYNAMIC in executable");
		free(rd);
		free(phdrs);
		return (NULL);
	}
	ps_plog("lx_ldb_client_init: found PT_DYNAMIC phdr[%d] at: 0x%p",
	    i, (phdr_addr + ((char *)ph - (char *)phdrs)));

	if ((dp = malloc(ph->p_filesz)) == NULL) {
		ps_plog("lx_ldb_client_init: couldn't alloc for PT_DYNAMIC");
		free(rd);
		free(phdrs);
		return (NULL);
	}

	dp_addr = ehdr_addr + ph->p_offset;
	dp_count = ph->p_filesz / sizeof (Elf32_Dyn);
	if (ps_pread(php, dp_addr, dp, ph->p_filesz) != PS_OK) {
		ps_plog("lx_ldb_client_init: couldn't read dynamic at 0x%p",
		    dp_addr);
		free(rd);
		free(phdrs);
		free(dp);
		return (NULL);
	}
	ps_plog("lx_ldb_client_init: read %d dynamic headers at: 0x%p",
	    dp_count, dp_addr);

	for (i = 0; i < dp_count; i++) {
		if (dp[i].d_tag == DT_DEBUG) {
			rd->lr_rdebug = dp[i].d_un.d_ptr;
			break;
		}
	}
	free(phdrs);
	free(dp);

	if (rd->lr_rdebug == 0) {
		ps_plog("lx_ldb_client_init: no DT_DEBUG found in exe");
		free(rd);
		return (NULL);
	}
	ps_plog("lx_ldb_client_init: found DT_DEBUG: 0x%p", rd->lr_rdebug);

	return (rd);
}

/*
 * Given the address of an ELF object in the target, return its size and
 * the proper link map ID.
 */
static size_t
lx_elf_props(struct ps_prochandle *php, uint32_t addr, psaddr_t *data_addr)
{
	Elf32_Ehdr	ehdr;
	Elf32_Phdr	*phdrs, *ph;
	int		i;
	uint32_t	min = (uint32_t)-1;
	uint32_t	max = 0;
	size_t		sz;

	if (ps_pread(php, addr, &ehdr, sizeof (ehdr)) != PS_OK) {
		ps_plog("lx_elf_props: Couldn't read ELF header at 0x%p",
		    addr);
		return (0);
	}

	if ((phdrs = malloc(ehdr.e_phnum * ehdr.e_phentsize)) == NULL)
		return (0);

	if (ps_pread(php, addr + ehdr.e_phoff, phdrs, ehdr.e_phnum *
	    ehdr.e_phentsize) != PS_OK) {
		ps_plog("lx_elf_props: Couldn't read program headers at 0x%p",
		    addr + ehdr.e_phoff);
		return (0);
	}

	for (i = 0, ph = phdrs; i < ehdr.e_phnum; i++,
	    /*LINTED */
	    ph = (Elf32_Phdr *)((char *)ph + ehdr.e_phentsize)) {

		if (ph->p_type != PT_LOAD)
			continue;

		if ((ph->p_flags & (PF_W | PF_R)) == (PF_W | PF_R)) {
			*data_addr = ph->p_vaddr;
			if (ehdr.e_type == ET_DYN)
				*data_addr += addr;
			if (*data_addr & (ph->p_align - 1))
				*data_addr = *data_addr & (~(ph->p_align -1));
		}

		if (ph->p_vaddr < min)
			min = ph->p_vaddr;

		if (ph->p_vaddr > max) {
			max = ph->p_vaddr;
			sz = ph->p_memsz + max - min;
			if (sz & (ph->p_align - 1))
				sz = (sz & (~(ph->p_align - 1))) + ph->p_align;
		}
	}

	free(phdrs);
	return (sz);
}

static int
lx_ldb_iter(struct ps_prochandle *php, rl_iter_f *cb, void *client_data,
    void *rd_addr)
{
	lx_rd_t			*lx_rd = (lx_rd_t *)rd_addr;
	struct lx_r_debug	r_debug;
	struct lx_link_map	map;
	uint32_t		p = NULL;
	int			rc;
	rd_loadobj_t		exec;

	if ((rc = ps_pread(php, (psaddr_t)lx_rd->lr_rdebug, &r_debug,
	    sizeof (r_debug))) != PS_OK) {
		ps_plog("lx_ldb_iter: Couldn't read linux r_debug at 0x%p",
		    rd_addr);
		return (rc);
	}

	p = r_debug.r_map;

	/*
	 * The first item on the link map list is for the executable, but it
	 * doesn't give us any useful information about it. We need to
	 * synthesize a rd_loadobj_t for the client.
	 *
	 * Linux doesn't give us the executable name, so we'll get it from
	 * the AT_EXECNAME entry instead.
	 */
	if ((rc = ps_pread(php, (psaddr_t)p, &map, sizeof (map))) != PS_OK) {
		ps_plog("lx_ldb_iter: Couldn't read linux link map at 0x%p",
		    p);
		return (rc);
	}

	bzero(&exec, sizeof (exec));
	exec.rl_base = lx_rd->lr_exec;
	exec.rl_dynamic = map.lxm_ld;
	exec.rl_nameaddr = Pgetauxval(php, AT_SUN_EXECNAME);
	exec.rl_lmident = LM_ID_BASE;

	exec.rl_bend = exec.rl_base +
	    lx_elf_props(php, lx_rd->lr_exec, &exec.rl_data_base);

	if ((*cb)(&exec, client_data) == 0) {
		ps_plog("lx_ldb_iter: client callb failed for executable");
		return (PS_ERR);
	}

	for (p = map.lxm_next; p != NULL; p = map.lxm_next) {
		rd_loadobj_t	obj;

		if ((rc = ps_pread(php, (psaddr_t)p, &map, sizeof (map))) !=
		    PS_OK) {
			ps_plog("lx_ldb_iter: Couldn't read lk map at %p",
			    p);
			return (rc);
		}

		/*
		 * The linux link map has less information than the Solaris one.
		 * We need to go fetch the missing information from the ELF
		 * headers.
		 */

		obj.rl_nameaddr = (psaddr_t)map.lxm_name;
		obj.rl_base = map.lxm_addr;
		obj.rl_refnameaddr = (psaddr_t)map.lxm_name;
		obj.rl_plt_base = NULL;
		obj.rl_plt_size = 0;
		obj.rl_lmident = LM_ID_BASE;

		/*
		 * Ugh - we have to walk the ELF stuff, find the PT_LOAD
		 * sections, and calculate the end of the file's mappings
		 * ourselves.
		 */

		obj.rl_bend = map.lxm_addr +
		    lx_elf_props(php, map.lxm_addr, &obj.rl_data_base);
		obj.rl_padstart = obj.rl_base;
		obj.rl_padend = obj.rl_bend;
		obj.rl_dynamic = map.lxm_ld;
		obj.rl_tlsmodid = 0;

		ps_plog("lx_ldb_iter: 0x%p to 0x%p",
		    obj.rl_base, obj.rl_bend);

		if ((*cb)(&obj, client_data) == 0) {
			ps_plog("lx_ldb_iter: Client callback failed on %s",
			    map.lxm_name);
			return (rc);
		}
	}
	return (RD_OK);
}
