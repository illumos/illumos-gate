/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

/*
 * vdso_tool: a build-time tool for adjusting properties of the "lx_vdso.so.1"
 * object we build for VDSO emulation in the LX brand.
 *
 * This tool ensures that the shared object contains only one loadable program
 * header (PT_LOAD), and extends the size of that program header to induce the
 * loading of all sections into memory.  It also sets a few attributes in the
 * ELF header.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <libelf.h>
#include <gelf.h>

#define	PROG	"vdso_tool"

typedef enum vdso_flags {
	VDSO_UNLINK = 0x0001,
	VDSO_UPDATE = 0x0002
} vdso_flags_t;

typedef struct vdso {
	int v_fd;
	char *v_path;
	Elf *v_elf;
	vdso_flags_t v_flags;
	int v_ptload_phdr;
	Elf64_Off v_max_offset;
} vdso_t;

static int
open_vdso(vdso_t **vp, char *path)
{
	vdso_t *v;

	if ((v = calloc(1, sizeof (vdso_t))) == NULL ||
	    (v->v_path = strdup(path)) == NULL) {
		err(1, "could not allocate memory");
	}
	v->v_ptload_phdr = -1;
	v->v_fd = -1;
	*vp = v;

	/*
	 * Open shared object file.
	 */
	if ((v->v_fd = open(v->v_path, O_RDWR)) == -1) {
		(void) fprintf(stderr, "could not open: %s: %s\n", v->v_path,
		    strerror(errno));
		return (-1);
	}

	/*
	 * Attach libelf.
	 */
	if ((v->v_elf = elf_begin(v->v_fd, ELF_C_RDWR, NULL)) == NULL) {
		(void) fprintf(stderr, "could not attach libelf: %s\n",
		    elf_errmsg(-1));
		return (-1);
	}

	if (elf_kind(v->v_elf) != ELF_K_ELF) {
		(void) fprintf(stderr, "wrong elf type\n");
		return (-1);
	}

	return (0);
}

static int
close_vdso(vdso_t *v)
{
	int rval = 0;

	if (v == NULL) {
		return (0);
	}

	if (v->v_elf != NULL) {
		/*
		 * If we want to write to the file, do so now.
		 */
		if (v->v_flags & VDSO_UPDATE) {
			if (elf_update(v->v_elf, ELF_C_WRITE) == -1) {
				(void) fprintf(stderr, "ERROR: elf_update "
				    "failed: %s\n", elf_errmsg(-1));
				v->v_flags |= VDSO_UNLINK;
				rval = -1;
			}
		}

		/*
		 * Close the libelf handle for this file.
		 */
		if (elf_end(v->v_elf) == -1) {
			(void) fprintf(stderr, "ERROR: elf_end failed: %s\n",
			    elf_errmsg(-1));
			v->v_flags |= VDSO_UNLINK;
			rval = -1;
		}
	}

	if (v->v_fd > 0) {
		(void) close(v->v_fd);
	}

	if (v->v_flags & VDSO_UNLINK) {
		(void) fprintf(stderr, "unlinking file: %s\n", v->v_path);
		if (unlink(v->v_path) != 0) {
			(void) fprintf(stderr, "unlink failed: %s\n",
			    strerror(errno));
			rval = -1;
		}
	}

	free(v->v_path);
	free(v);

	return (rval);
}

static int
adjust_elf_ehdr(vdso_t *v)
{
	GElf_Ehdr ehdr;
	boolean_t dirty = B_FALSE;

	if (gelf_getehdr(v->v_elf, &ehdr) == NULL) {
		(void) fprintf(stderr, "could not get ehdr: %s\n",
		    elf_errmsg(-1));
		goto errout;
	}

	if (ehdr.e_ident[EI_OSABI] != ELFOSABI_NONE) {
		(void) fprintf(stdout, "set EI_OSABI = ELFOSABI_NONE\n");
		ehdr.e_ident[EI_OSABI] = ELFOSABI_NONE;
		dirty = B_TRUE;
	}

	if (ehdr.e_ident[EI_ABIVERSION] != 0) {
		(void) fprintf(stdout, "set EI_ABIVERSION = 0\n");
		ehdr.e_ident[EI_ABIVERSION] = 0;
		dirty = B_TRUE;
	}

	if (dirty && gelf_update_ehdr(v->v_elf, &ehdr) == 0) {
		(void) fprintf(stderr, "could not update ehdr: %s\n",
		    elf_errmsg(-1));
		goto errout;
	}

	v->v_flags |= VDSO_UPDATE;
	return (0);

errout:
	v->v_flags |= VDSO_UNLINK;
	return (-1);
}

static int
find_pt_load_phdr(vdso_t *v)
{
	size_t nphdr, nloadable = 0;
	int i;

	if (elf_getphdrnum(v->v_elf, &nphdr) != 0) {
		(void) fprintf(stderr, "could not get phdr count: %s\n",
		    elf_errmsg(-1));
		goto errout;
	}
	(void) fprintf(stdout, "phdr count: %d\n", nphdr);

	for (i = 0; i < nphdr; i++) {
		GElf_Phdr phdr;

		if (gelf_getphdr(v->v_elf, i, &phdr) == NULL) {
			(void) fprintf(stderr, "could not get phdr[%d] count: "
			    "%s\n", i, elf_errmsg(-1));
			goto errout;
		}

		if (phdr.p_type == PT_LOAD) {
			if (nloadable++ != 0) {
				(void) fprintf(stderr, "multiple PT_LOAD "
				    "phdrs\n");
				goto errout;
			}

			(void) fprintf(stdout, "PT_LOAD header is phdr[%d]\n",
			    i);
			v->v_ptload_phdr = i;

			if (phdr.p_filesz != phdr.p_memsz) {
				(void) fprintf(stderr, "mismatched filesz "
				    "(%llx) and memsz (%llx)\n", phdr.p_filesz,
				    phdr.p_memsz);
				goto errout;
			}

			if (phdr.p_filesz == 0) {
				(void) fprintf(stderr, "filesz was zero\n");
				goto errout;
			}
		}
	}

	return (0);

errout:
	v->v_flags |= VDSO_UNLINK;
	return (-1);
}

static int
find_maximum_offset(vdso_t *v)
{
	size_t nshdr;
	int i;

	if (elf_getshdrnum(v->v_elf, &nshdr) != 0) {
		(void) fprintf(stderr, "could not get shdr count: %s\n",
		    elf_errmsg(-1));
		v->v_flags |= VDSO_UNLINK;
		return (-1);
	}
	(void) fprintf(stdout, "shdr count: %d\n", nshdr);

	for (i = 0; i < nshdr; i++) {
		Elf_Scn *scn = elf_getscn(v->v_elf, i);
		GElf_Shdr shdr;
		Elf64_Off end;

		if (gelf_getshdr(scn, &shdr) == NULL) {
			(void) fprintf(stderr, "could not get shdr[%d] "
			    "count: %s\n", i, elf_errmsg(-1));
			goto errout;
		}

		end = shdr.sh_offset + shdr.sh_size;

		if (end > v->v_max_offset) {
			v->v_max_offset = end;
		}
	}

	(void) fprintf(stdout, "maximum offset: %llx\n", v->v_max_offset);

	return (0);

errout:
	v->v_flags |= VDSO_UNLINK;
	return (-1);
}

static int
update_pt_load_size(vdso_t *v)
{
	GElf_Phdr phdr;

	if (gelf_getphdr(v->v_elf, v->v_ptload_phdr, &phdr) == NULL) {
		(void) fprintf(stderr, "could not get phdr[%d] count: %s\n",
		    v->v_ptload_phdr, elf_errmsg(-1));
		goto errout;
	}

	(void) fprintf(stdout, "PT_LOAD size is currently %llx\n",
	    phdr.p_filesz);
	if (phdr.p_filesz < v->v_max_offset) {
		(void) fprintf(stdout, "extending PT_LOAD size from %llx "
		    "to %llx\n", phdr.p_filesz, v->v_max_offset);

		phdr.p_memsz = phdr.p_filesz = v->v_max_offset;

		if (gelf_update_phdr(v->v_elf, v->v_ptload_phdr, &phdr) == 0) {
			(void) fprintf(stderr, "could not update PT_LOAD "
			    "phdr: %s", elf_errmsg(-1));
			goto errout;
		}

		v->v_flags |= VDSO_UPDATE;
	}

	return (0);

errout:
	v->v_flags |= VDSO_UNLINK;
	return (-1);
}

int
main(int argc, char **argv)
{
	vdso_t *v;
	char *filen = NULL;
	int errflg = 0;
	int c;
	int status = 0;
	boolean_t do_update = B_TRUE;

	while ((c = getopt(argc, argv, ":nf:")) != -1) {
		switch (c) {
		case 'n':
			do_update = B_FALSE;
			break;
		case 'f':
			filen = optarg;
			break;
		case ':':
			(void) fprintf(stderr, "option -%c requires an "
			    "operand\n", optopt);
			errflg++;
			break;
		case '?':
			(void) fprintf(stderr, "unrecognised option: -%c\n",
			    optopt);
			errflg++;
			break;
		}
	}

	if (errflg != 0 || optind != argc || filen == NULL) {
		(void) fprintf(stderr, "usage: %s -f <vdso.so>\n", PROG);
		return (1);
	}

	(void) fprintf(stdout, "vdso file: %s\n", filen);

	if (elf_version(EV_CURRENT) == EV_NONE) {
		(void) fprintf(stderr, "libelf mismatch: %s\n", elf_errmsg(-1));
		return (2);
	}

	status = 3;
	if (open_vdso(&v, filen) == -1) {
		goto out;
	}

	status++;
	if (adjust_elf_ehdr(v) == -1) {
		goto out;
	}

	status++;
	if (find_pt_load_phdr(v) == -1) {
		goto out;
	}

	status++;
	if (find_maximum_offset(v) == -1) {
		goto out;
	}

	status++;
	if (do_update && update_pt_load_size(v) == -1) {
		goto out;
	}

out:
	status++;
	if (close_vdso(v) == 0) {
		status = 0;
	}

	return (status);
}
