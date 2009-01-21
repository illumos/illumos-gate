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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/fault.h>
#include <sys/syscall.h>
#include <procfs.h>
#include <sys/auxv.h>
#include <libelf.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <link.h>
#include <sys/param.h>
#include <stdarg.h>

#include "rdb.h"

static char *
conv_lmid(Lmid_t ident, char *buf, size_t len)
{
	if (len < 17)
		return (NULL);
	if (ident == LM_ID_BASE)
		return (strncpy(buf, "  BASE  ", len));

	if (ident == LM_ID_LDSO)
		return (strncpy(buf, "  LDSO  ", len));

	(void) sprintf(buf, "0x%llx", (unsigned long long)ident);
	return (buf);
}

map_info_t *
str_to_map(struct ps_prochandle *ph, const char *soname)
{
	map_info_t *mip;

	if (soname == PS_OBJ_LDSO)
		mip = (map_info_t *)&(ph->pp_ldsomap);
	else if (soname == PS_OBJ_EXEC)
		mip = (map_info_t *)&(ph->pp_execmap);
	else {
		for (mip = ph->pp_lmaplist.ml_head; mip; mip = mip->mi_next)
			if (strcmp(soname, mip->mi_name) == 0)
				break;
	}
	return (mip);
}

map_info_t *
addr_to_map(struct ps_prochandle *ph, ulong_t addr)
{
	map_info_t *mip;
	if (ph->pp_lmaplist.ml_head == NULL) {
		/*
		 * To early to have the full Link Map info available
		 * so we use the initial info obtained from procfs
		 */
		if ((addr >= ph->pp_ldsomap.mi_addr) &&
		    (addr <= ph->pp_ldsomap.mi_end))
			return ((map_info_t *)&(ph->pp_ldsomap));

		if ((addr >= ph->pp_execmap.mi_addr) &&
		    (addr <= ph->pp_execmap.mi_end))
			return ((map_info_t *)&(ph->pp_execmap));

		return (NULL);
	}

	for (mip = ph->pp_lmaplist.ml_head; mip; mip = mip->mi_next)
		if ((addr >= mip->mi_addr) &&
		    (addr <= mip->mi_end))
			return (mip);

	return (NULL);
}

retc_t
display_linkmaps(struct ps_prochandle *ph)
{
	char	flagstr[1024];
	map_info_t *mip;

	if (ph->pp_lmaplist.ml_head == NULL) {
		(void) printf("link-maps not yet available\n");
		return (RET_FAILED);
	}
	(void) printf("Link Maps\n");
	(void) printf("---------\n");
	for (mip = ph->pp_lmaplist.ml_head; mip; mip = mip->mi_next) {
		char sbuf[32];
		rd_loadobj_t *lp = &mip->mi_loadobj;
		(void) printf("link-map: id: %s name: ",
		    conv_lmid(lp->rl_lmident, sbuf, 32));
		if (mip->mi_refname)
			(void) printf("%s(%s)\n", mip->mi_name,
			    mip->mi_refname);
		else
			(void) printf("%s\n", mip->mi_name);

		(void) printf("       base: 0x%08lx   padd_base: 0x%08lx\n",
		    lp->rl_base, lp->rl_padstart);
		(void) printf("  data_base: 0x%08llx\n",
		    (unsigned long long)lp->rl_data_base);
		(void) printf("        end: 0x%08lx    padd_end: 0x%08lx\n",
		    lp->rl_bend, lp->rl_padend);
		flagstr[0] = '\0';

		if (lp->rl_flags & RD_FLG_MEM_OBJECT) {
			(void) strcat(flagstr, " MEMOBJECT");
		}
		(void) printf("    dynamic: 0x%08lx       flags: "
		    "0x%08x:[%s ]\n", lp->rl_dynamic, lp->rl_flags, flagstr);
	}

	return (RET_OK);
}

retc_t
display_maps(struct ps_prochandle *ph)
{
	struct stat	stbuf;
	void 		*ptr;
	prmap_t 	*mapptr;

	if (fstat(ph->pp_mapfd, &stbuf) == -1)
		perr("stat map");

	ptr = malloc(stbuf.st_size);
	if (pread(ph->pp_mapfd, ptr, stbuf.st_size, 0) == -1)
		perr("dm: reading map");

	(void) puts("\nMappings");
	(void) puts("--------");
	if (ph->pp_dmodel == PR_MODEL_LP64)
		(void) puts("addr               size     prot ident name");
	else
		(void) puts("addr       size     prot ident name");

	for (mapptr = (prmap_t *)ptr;
	    (uintptr_t)mapptr < ((uintptr_t)ptr + stbuf.st_size);
	    mapptr++) {
		map_info_t *mip;

		if (ph->pp_dmodel == PR_MODEL_LP64)
			(void) printf("%#18lx %#08lx %#04x", mapptr->pr_vaddr,
			    mapptr->pr_size, mapptr->pr_mflags);
		else
			(void) printf("0x%08lx 0x%06lx 0x%02x",
			    mapptr->pr_vaddr, mapptr->pr_size,
			    mapptr->pr_mflags);

		if ((mip = addr_to_map(ph,
		    (ulong_t)(mapptr->pr_vaddr))) != NULL) {
			if (mip->mi_refname) {
				(void) printf(" 0x%02lx  %s(%s)",
				    mip->mi_lmident, mip->mi_name,
				    mip->mi_refname);
			} else
				(void) printf(" 0x%02lx  %s", mip->mi_lmident,
				    mip->mi_name);
		}
		(void) putchar('\n');
	}
	(void) putchar('\n');

	free(ptr);
	return (RET_OK);
}

retc_t
load_map(struct ps_prochandle *procp, caddr_t baddr, map_info_t *mp)
{
	Elf 		*elf;
	GElf_Ehdr 	ehdr;
	GElf_Phdr	phdr;
	Elf_Scn 	*scn = NULL;
	int		cnt;
	prmap_t 	*mapptr;
	void 		*ptr;
	struct stat	stbuf;
	int		filefd = -1;

	if (fstat(procp->pp_mapfd, &stbuf) == -1)
		perr("stat map");

	ptr = malloc(stbuf.st_size);
	if (pread(procp->pp_mapfd, ptr, stbuf.st_size, 0) == -1)
		perr("dm: reading map");

	for (mapptr = (prmap_t *)ptr;
	    (uintptr_t)mapptr < ((uintptr_t)ptr + stbuf.st_size);
	    mapptr++) {

		if ((mapptr->pr_vaddr <= (uintptr_t)baddr) &&
		    ((mapptr->pr_vaddr + mapptr->pr_size) >
		    (uintptr_t)baddr)) {
			if (mapptr->pr_mapname[0]) {
				char	procname[MAXPATHLEN];

				(void) snprintf(procname, MAXPATHLEN - 1,
				    "/proc/%d/object/%s", procp->pp_pid,
				    mapptr->pr_mapname);
				filefd = open(procname, O_RDONLY);
			}
			break;
		}
	}
	free(ptr);

	if (filefd == -1) {
		(void) fprintf(stderr, "unable to find file association to "
		    "maping address 0x%08lx\n", baddr);
		return (RET_FAILED);
	}

	if ((elf = elf_begin(filefd, ELF_C_READ, 0)) == NULL) {
		(void) fprintf(stderr, "elf_begin(): %s\n", elf_errmsg(-1));
		return (RET_FAILED);
	}

	if (elf_kind(elf) != ELF_K_ELF) {
		(void) printf("non-elf file\n");
		(void) elf_end(elf);
		return (RET_FAILED);
	}

	mp->mi_elf = elf;
	mp->mi_flags = 0;
	mp->mi_mapfd = filefd;

	if (gelf_getehdr(mp->mi_elf, &ehdr) == NULL) {
		(void) printf("gelf_getehdr(): %s\n", elf_errmsg(-1));
		(void) elf_end(mp->mi_elf);
		return (RET_FAILED);
	}
	mp->mi_ehdr = ehdr;
	if (ehdr.e_type == ET_EXEC)
		mp->mi_flags |= FLG_MI_EXEC;

	mp->mi_end = 0;
#if	defined(_ELF64)
	mp->mi_addr = (ulong_t)0xffffffffffffffff;
#else
	mp->mi_addr = (ulong_t)0xffffffff;
#endif
	for (cnt = 0; cnt < (int)(ehdr.e_phnum); cnt++) {
		if (gelf_getphdr(mp->mi_elf, cnt, &phdr) == NULL) {
			(void) printf("gelf_getphdr(): %s\n", elf_errmsg(-1));
			(void) elf_end(mp->mi_elf);
			return (RET_FAILED);
		}

		if (phdr.p_type == PT_LOAD) {
			if (mp->mi_end < (ulong_t)(phdr.p_vaddr +
			    phdr.p_memsz))
				mp->mi_end = (ulong_t)(phdr.p_vaddr +
				    phdr.p_memsz);
			if (mp->mi_addr > phdr.p_vaddr)
				mp->mi_addr = phdr.p_vaddr;
		}
	}

	mp->mi_pltbase = 0;
	mp->mi_pltsize = 0;
	mp->mi_pltentsz = 0;
	mp->mi_dynsym.st_symn = 0;
	while ((scn = elf_nextscn(mp->mi_elf, scn)) != NULL) {
		GElf_Shdr 	shdr;
		Elf_Data	*dp;
		Elf_Scn		*tscn = NULL;

		if (gelf_getshdr(scn, &shdr) == NULL) {
			(void) printf("gelf_getshdr(): %s\n", elf_errmsg(-1));
			(void) elf_end(mp->mi_elf);
			return (RET_FAILED);
		}

		switch (shdr.sh_type) {
		case SHT_DYNSYM:
			dp = elf_getdata(scn, 0);
			mp->mi_dynsym.st_syms_pri = dp;
			tscn = elf_getscn(mp->mi_elf, shdr.sh_link);
			mp->mi_dynsym.st_symn +=
			    shdr.sh_size / shdr.sh_entsize;
			dp = elf_getdata(tscn, 0);
			mp->mi_dynsym.st_strs = (char *)dp->d_buf;
			break;
		case SHT_SUNW_LDYNSYM:
			dp = elf_getdata(scn, 0);
			mp->mi_dynsym.st_syms_aux = dp;
			mp->mi_dynsym.st_symn_aux =
			    shdr.sh_size / shdr.sh_entsize;
			mp->mi_dynsym.st_symn += mp->mi_dynsym.st_symn_aux;
			break;
		case SHT_SYMTAB:
			dp = elf_getdata(scn, 0);
			mp->mi_symtab.st_syms_pri = dp;
			tscn = elf_getscn(mp->mi_elf, shdr.sh_link);
			mp->mi_symtab.st_symn =
			    shdr.sh_size / shdr.sh_entsize;
			dp = elf_getdata(tscn, 0);
			mp->mi_symtab.st_strs = (char *)dp->d_buf;
			break;
		case PLTSECTT:
			if (strcmp(PLTSECT, elf_strptr(mp->mi_elf,
			    ehdr.e_shstrndx, shdr.sh_name)) == 0) {
				mp->mi_pltbase = shdr.sh_addr;
				mp->mi_pltsize = shdr.sh_size;
				/* LINTED */
				mp->mi_pltentsz = (unsigned)shdr.sh_entsize;
			}
			break;
		default:
			/* nothing */
			break;
		}
	}
	return (RET_OK);
}

static int
map_iter(const rd_loadobj_t *lop, void *cd)
{
	struct ps_prochandle 	*ph = (struct ps_prochandle *)cd;
	map_info_t 		*mip;
	char			buf[MAXPATHLEN];

	if ((mip = (map_info_t *)calloc(1, sizeof (map_info_t))) == NULL) {
		(void) fprintf(stderr, "map_iter: memory error: allocation "
		    "failed\n");
		return (0);
	}

	mip->mi_loadobj = *lop;

	if (proc_string_read(ph, lop->rl_nameaddr,
	    buf, MAXPATHLEN) == RET_FAILED) {
		(void) fprintf(stderr, "mi: bad object name address "
		    "passed: 0x%lx\n", lop->rl_nameaddr);
		free(mip);
		return (0);
	}
	mip->mi_name = strdup(buf);


	if (lop->rl_refnameaddr) {
		if (proc_string_read(ph, lop->rl_refnameaddr, buf,
		    MAXPATHLEN) == RET_FAILED) {
			(void) fprintf(stderr, "mi1: bad object name address "
			    "passed: 0x%lx\n", lop->rl_refnameaddr);
			free(mip);
			return (0);
		}
		mip->mi_refname = strdup(buf);
	} else
		mip->mi_refname = NULL;

	/*
	 * Relocatable objects are processed to create in-memory shared objects,
	 * and as such have no file associated with the allocated memory shared
	 * object.
	 */
	if ((lop->rl_flags & RD_FLG_MEM_OBJECT) == 0)
		(void) load_map(ph, (caddr_t)lop->rl_base, mip);
	if ((mip->mi_flags & FLG_MI_EXEC) == 0) {
		mip->mi_end += lop->rl_base;
		mip->mi_addr += lop->rl_base;
	}
	mip->mi_lmident = lop->rl_lmident;
	mip->mi_next = NULL;

	if (ph->pp_lmaplist.ml_head == 0) {
		ph->pp_lmaplist.ml_head = ph->pp_lmaplist.ml_tail = mip;
		return (1);
	}

	ph->pp_lmaplist.ml_tail->mi_next = mip;
	ph->pp_lmaplist.ml_tail = mip;

	return (1);
}

void
free_linkmaps(struct ps_prochandle *ph)
{
	map_info_t *cur, *prev;

	for (cur = ph->pp_lmaplist.ml_head, prev = NULL; cur;
	    prev = cur, cur = cur->mi_next) {
		if (prev) {
			(void) elf_end(prev->mi_elf);
			(void) close(prev->mi_mapfd);
			free(prev->mi_name);
			if (prev->mi_refname)
				free(prev->mi_refname);
			free(prev);
		}
	}
	if (prev) {
		(void) elf_end(prev->mi_elf);
		(void) close(prev->mi_mapfd);
		free(prev->mi_name);
		if (prev->mi_refname)
			free(prev->mi_refname);
		free(prev);
	}
	ph->pp_lmaplist.ml_head = ph->pp_lmaplist.ml_tail = NULL;
}

retc_t
get_linkmaps(struct ps_prochandle *ph)
{
	free_linkmaps(ph);
	rd_loadobj_iter(ph->pp_rap, map_iter, ph);
	return (RET_OK);
}

retc_t
set_objpad(struct ps_prochandle *ph, size_t padsize)
{
	if (rd_objpad_enable(ph->pp_rap, padsize) != RD_OK) {
		(void) printf("rdb: error setting object padding\n");
		return (RET_FAILED);
	}
	return (RET_OK);
}
