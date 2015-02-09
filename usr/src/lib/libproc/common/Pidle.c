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
/*
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#include <stdlib.h>
#include <libelf.h>
#include <libgen.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/sysmacros.h>

#include "libproc.h"
#include "Pcontrol.h"

/*ARGSUSED*/
static ssize_t
Pread_idle(struct ps_prochandle *P, void *buf, size_t n, uintptr_t addr,
    void *data)
{
	size_t resid = n;

	while (resid > 0) {
		map_info_t *mp;
		uintptr_t mapoff;
		ssize_t len;
		off64_t off;

		if ((mp = Paddr2mptr(P, addr)) == NULL)
			break;

		mapoff = addr - mp->map_pmap.pr_vaddr;
		len = MIN(resid, mp->map_pmap.pr_size - mapoff);
		off = mp->map_offset + mapoff;

		if ((len = pread64(P->asfd, buf, len, off)) <= 0)
			break;

		resid -= len;
		addr += len;
		buf = (char *)buf + len;
	}

	return (n - resid);
}

/*ARGSUSED*/
static ssize_t
Pwrite_idle(struct ps_prochandle *P, const void *buf, size_t n, uintptr_t addr,
    void *data)
{
	errno = EIO;
	return (-1);
}

/*ARGSUSED*/
static int
Ppriv_idle(struct ps_prochandle *P, prpriv_t **pprv, void *data)
{
	prpriv_t *pp;

	pp = proc_get_priv(P->pid);
	if (pp == NULL) {
		return (-1);
	}

	*pprv = pp;
	return (0);
}

/* Default operations for the idl ops vector. */
static void *
Pidle_voidp()
{
	errno = ENODATA;
	return (NULL);
}

static int
Pidle_int()
{
	errno = ENODATA;
	return (-1);
}

static const ps_ops_t P_idle_ops = {
	.pop_pread	= Pread_idle,
	.pop_pwrite	= Pwrite_idle,
	.pop_cred	= (pop_cred_t)Pidle_int,
	.pop_priv	= Ppriv_idle,
	.pop_psinfo	= (pop_psinfo_t)Pidle_voidp,
	.pop_platform	= (pop_platform_t)Pidle_voidp,
	.pop_uname	= (pop_uname_t)Pidle_int,
	.pop_zonename	= (pop_zonename_t)Pidle_voidp,
#if defined(__i386) || defined(__amd64)
	.pop_ldt	= (pop_ldt_t)Pidle_int
#endif
};

static int
idle_add_mapping(struct ps_prochandle *P, GElf_Phdr *php, file_info_t *fp)
{
	prmap_t pmap;

	dprintf("mapping base %llx filesz %llu memsz %llu offset %llu\n",
	    (u_longlong_t)php->p_vaddr, (u_longlong_t)php->p_filesz,
	    (u_longlong_t)php->p_memsz, (u_longlong_t)php->p_offset);

	pmap.pr_vaddr = (uintptr_t)php->p_vaddr;
	pmap.pr_size = php->p_filesz;
	(void) strncpy(pmap.pr_mapname, fp->file_pname,
	    sizeof (pmap.pr_mapname));
	pmap.pr_offset = php->p_offset;

	pmap.pr_mflags = 0;
	if (php->p_flags & PF_R)
		pmap.pr_mflags |= MA_READ;
	if (php->p_flags & PF_W)
		pmap.pr_mflags |= MA_WRITE;
	if (php->p_flags & PF_X)
		pmap.pr_mflags |= MA_EXEC;

	pmap.pr_pagesize = 0;
	pmap.pr_shmid = -1;

	return (Padd_mapping(P, php->p_offset, fp, &pmap));
}

struct ps_prochandle *
Pgrab_file(const char *fname, int *perr)
{
	struct ps_prochandle *P = NULL;
	char buf[PATH_MAX];
	GElf_Ehdr ehdr;
	Elf *elf = NULL;
	size_t phnum;
	file_info_t *fp = NULL;
	int fd;
	int i;

	if ((fd = open64(fname, O_RDONLY)) < 0) {
		dprintf("couldn't open file");
		*perr = (errno == ENOENT) ? G_NOEXEC : G_STRANGE;
		return (NULL);
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		dprintf("libproc ELF version is more recent than libelf");
		*perr = G_ELF;
		goto err;
	}

	if ((P = calloc(1, sizeof (struct ps_prochandle))) == NULL) {
		*perr = G_STRANGE;
		goto err;
	}

	(void) mutex_init(&P->proc_lock, USYNC_THREAD, NULL);
	P->state = PS_IDLE;
	P->pid = (pid_t)-1;
	P->asfd = fd;
	P->ctlfd = -1;
	P->statfd = -1;
	P->agentctlfd = -1;
	P->agentstatfd = -1;
	P->info_valid = -1;
	Pinit_ops(&P->ops, &P_idle_ops);
	Pinitsym(P);

	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		*perr = G_ELF;
		return (NULL);
	}

	/*
	 * Construct a file_info_t that corresponds to this file.
	 */
	if ((fp = calloc(1, sizeof (file_info_t))) == NULL) {
		*perr = G_STRANGE;
		goto err;
	}

	if ((fp->file_lo = calloc(1, sizeof (rd_loadobj_t))) == NULL) {
		*perr = G_STRANGE;
		goto err;
	}

	if (*fname == '/') {
		(void) strncpy(fp->file_pname, fname, sizeof (fp->file_pname));
	} else {
		size_t sz;

		if (getcwd(fp->file_pname, sizeof (fp->file_pname) - 1) ==
		    NULL) {
			*perr = G_STRANGE;
			goto err;
		}

		sz = strlen(fp->file_pname);
		(void) snprintf(&fp->file_pname[sz],
		    sizeof (fp->file_pname) - sz, "/%s", fname);
	}

	fp->file_fd = fd;
	fp->file_dbgfile = -1;
	fp->file_lo->rl_lmident = LM_ID_BASE;
	if ((fp->file_lname = strdup(fp->file_pname)) == NULL) {
		*perr = G_STRANGE;
		goto err;
	}
	fp->file_lbase = basename(fp->file_lname);

	if ((P->execname = strdup(fp->file_pname)) == NULL) {
		*perr = G_STRANGE;
		goto err;
	}

	P->num_files++;
	list_link(fp, &P->file_head);

	if (gelf_getehdr(elf, &ehdr) == NULL) {
		*perr = G_STRANGE;
		goto err;
	}

	if (elf_getphdrnum(elf, &phnum) == -1) {
		*perr = G_STRANGE;
		goto err;
	}

	dprintf("Pgrab_file: program header count = %lu\n", (ulong_t)phnum);

	/*
	 * Sift through the program headers making the relevant maps.
	 */
	for (i = 0; i < phnum; i++) {
		GElf_Phdr phdr, *php;

		if ((php = gelf_getphdr(elf, i, &phdr)) == NULL) {
			*perr = G_STRANGE;
			goto err;
		}

		if (php->p_type != PT_LOAD)
			continue;

		if (idle_add_mapping(P, php, fp) != 0) {
			*perr = G_STRANGE;
			goto err;
		}
	}
	Psort_mappings(P);

	(void) elf_end(elf);

	P->map_exec = fp->file_map;

	P->status.pr_flags = PR_STOPPED;
	P->status.pr_nlwp = 0;
	P->status.pr_pid = (pid_t)-1;
	P->status.pr_ppid = (pid_t)-1;
	P->status.pr_pgid = (pid_t)-1;
	P->status.pr_sid = (pid_t)-1;
	P->status.pr_taskid = (taskid_t)-1;
	P->status.pr_projid = (projid_t)-1;
	P->status.pr_zoneid = (zoneid_t)-1;
	switch (ehdr.e_ident[EI_CLASS]) {
	case ELFCLASS32:
		P->status.pr_dmodel = PR_MODEL_ILP32;
		break;
	case ELFCLASS64:
		P->status.pr_dmodel = PR_MODEL_LP64;
		break;
	default:
		*perr = G_FORMAT;
		goto err;
	}

	/*
	 * Pfindobj() checks what zone a process is associated with, so
	 * we call it after initializing pr_zoneid to -1.  This ensures
	 * we don't get associated with any zone on the system.
	 */
	if (Pfindobj(P, fp->file_lname, buf, sizeof (buf)) != NULL) {
		free(P->execname);
		P->execname = strdup(buf);
		if ((fp->file_rname = strdup(buf)) != NULL)
			fp->file_rbase = basename(fp->file_rname);
	}

	/*
	 * The file and map lists are complete, and will never need to be
	 * adjusted.
	 */
	P->info_valid = 1;

	return (P);
err:
	(void) close(fd);
	if (P != NULL)
		Pfree(P);
	if (elf != NULL)
		(void) elf_end(elf);
	return (NULL);
}
