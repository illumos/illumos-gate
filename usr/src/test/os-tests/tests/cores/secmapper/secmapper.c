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
 * Copyright 2021 Oxide Computer Company
 */

/*
 * Check that a given core dump generated as part of our test framework has the
 * sections that we'd expect. We have here the dumper binary. In that, we expect
 * to find the following libraries and sections:
 *
 *   a.out:		symtab, ctf, .debug_* (dwarf)
 *   ld.so.1:		symtab
 *   libc.so:		symtab, ctf
 *   libproc.so:	symtab, ctf
 *   libdumper.so:	symtab, ctf, .debug_* (dwarf)
 *
 * Note, there will also be additional libraries and things here can change over
 * time (e.g. deps of libproc, etc.), but we try to ignore them generally
 * speaking if we can know enough to do so.
 */

#include <err.h>
#include <stdlib.h>
#include <libproc.h>
#include <gelf.h>
#include <libelf.h>
#include <limits.h>
#include <string.h>
#include <libgen.h>

typedef enum {
	SECMAP_CTF,
	SECMAP_SYMTAB,
	SECMAP_DEBUG,
	SECMAP_MAX
} secmap_type_t;

typedef struct secmap_data {
	core_content_t	sd_content;
	const char	*sd_name;
} secmap_data_t;

secmap_data_t secmap_data[SECMAP_MAX] = {
	{ CC_CONTENT_CTF, ".SUNW_ctf" },
	{ CC_CONTENT_SYMTAB, ".symtab" },
	{ CC_CONTENT_DEBUG, ".debug_" }
};

typedef struct {
	uint64_t	sm_addr;
	char		sm_obj[PATH_MAX];
	size_t		sm_nfound[SECMAP_MAX];
	Elf		*sm_elf;
	GElf_Ehdr	sm_ehdr;
	boolean_t	sm_ctf;
	boolean_t	sm_debug;
	boolean_t	sm_symtab;
} secmap_t;

static secmap_t *secmaps;
static size_t secmap_count;
static core_content_t secmap_content;

static int secmap_exit = EXIT_SUCCESS;

static void
secmap_fail(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vwarnx(fmt, ap);
	va_end(ap);
	secmap_exit = EXIT_FAILURE;
}


static void
check_content(core_content_t content, struct ps_prochandle *Pr)
{
	secmap_content = Pcontent(Pr);

	if (secmap_content == CC_CONTENT_INVALID) {
		secmap_fail("TEST FAILED: failed to get core content");
		return;
	}

	if (secmap_content != content) {
		secmap_fail("TEST FAILED: core file contains different "
		    "content than expected, found 0x%x, expected 0x%x",
		    secmap_content, content);
	}
}

static secmap_t *
secmap_find(uint64_t addr)
{
	for (size_t i = 0; i < secmap_count; i++) {
		if (secmaps[i].sm_addr == addr) {
			return (&secmaps[i]);
		}
	}

	return (NULL);
}

static void
secmap_matches_content(secmap_type_t type)
{
	boolean_t exist = (secmap_data[type].sd_content & secmap_content) != 0;
	boolean_t found = B_FALSE;

	/*
	 * Dumping CTF data implies that some symbol tables will exist for CTF.
	 */
	if (type == SECMAP_SYMTAB && (secmap_content & CC_CONTENT_CTF) != 0) {
		exist = B_TRUE;
	}

	for (size_t i = 0; i < secmap_count; i++) {
		if (secmaps[i].sm_nfound[type] != 0) {
			found = B_TRUE;
		}
	}

	if (exist != found) {
		secmap_fail("content type mismatch for %s: expected %s, but "
		    "found %s", secmap_data[type].sd_name,
		    exist ? "some" : "none",
		    found ? "some" : "none");
	}
}

static secmap_t *
secmap_alloc(struct ps_prochandle *Pr, uint64_t addr)
{
	int fd;
	secmap_t *sm;
	char *base;

	sm = recallocarray(secmaps, secmap_count, secmap_count + 1,
	    sizeof (secmap_t));
	if (sm == NULL) {
		err(EXIT_FAILURE, "TEST FAILED: failed to allocate memory for "
		    "secmap %zu", secmap_count + 1);
	}

	secmaps = sm;
	sm = &secmaps[secmap_count];
	sm->sm_addr = addr;
	secmap_count++;

	/*
	 * We also have some tests that we don't expect to have anything here
	 * because we only include the relevant sections. Experimentally, we
	 * know that libproc needs both anon and data mappings for this to work.
	 * So if we don't have both, then we'll not warn on that.
	 */
	if (Pobjname(Pr, addr, sm->sm_obj, sizeof (sm->sm_obj)) == NULL) {
		core_content_t need = CC_CONTENT_ANON | CC_CONTENT_DATA;

		if ((secmap_content & need) == need) {
			secmap_fail("TEST FAILURE: object at address 0x%lx "
			    "has no name", addr);
		}

		return (sm);
	}

	/*
	 * Since we have a name, we should be able to open this elf object and
	 * identify it as well.
	 */
	fd = open(sm->sm_obj, O_RDONLY);
	if (fd < 0) {
		err(EXIT_FAILURE, "failed to open object %s", sm->sm_obj);
	}

	sm->sm_elf = elf_begin(fd, ELF_C_READ, NULL);
	if (sm->sm_elf == NULL) {
		err(EXIT_FAILURE, "failed to find open elf object %s: %s",
		    sm->sm_obj, elf_errmsg(elf_errno()));
	}

	if (gelf_getehdr(sm->sm_elf, &sm->sm_ehdr) == NULL) {
		err(EXIT_FAILURE, "failed to get ehdr for %s: %s",
		    sm->sm_obj, elf_errmsg(elf_errno()));
	}

	base = basename(sm->sm_obj);
	if (strcmp(base, "dumper.32") == 0 || strcmp(base, "dumper.64") == 0) {
		sm->sm_debug = sm->sm_symtab = sm->sm_ctf = B_TRUE;
	} else if (strcmp(base, "libc.so.1") == 0) {
		sm->sm_symtab = sm->sm_ctf = B_TRUE;
	} else if (strcmp(base, "ld.so.1") == 0) {
		sm->sm_symtab = B_TRUE;
	} else if (strcmp(base, "libproc.so.1") == 0) {
		sm->sm_symtab = sm->sm_ctf = B_TRUE;
	} else if (strcmp(base,  "libdumper.so.1") == 0) {
		sm->sm_debug = sm->sm_symtab = sm->sm_ctf = B_TRUE;
	} else {
		sm->sm_symtab = B_TRUE;
	}

	return (sm);
}

static void
secmap_data_cmp(secmap_t *sm, const char *sname, Elf_Scn *scn, GElf_Shdr *shdr)
{
	for (Elf_Scn *comp_scn = elf_nextscn(sm->sm_elf, NULL);
	    comp_scn != NULL; comp_scn = elf_nextscn(sm->sm_elf, comp_scn)) {
		GElf_Shdr comp_shdr;
		const char *comp_name;
		Elf_Data *src_data, *comp_data;

		if (gelf_getshdr(comp_scn, &comp_shdr) == NULL) {
			secmap_fail("failed to load section header from %s "
			    "during data comparison", sm->sm_obj);
			return;
		}

		comp_name = elf_strptr(sm->sm_elf, sm->sm_ehdr.e_shstrndx,
		    comp_shdr.sh_name);
		if (comp_name == NULL) {
			secmap_fail("failed to load section name from %s "
			    "with index %lu", sm->sm_obj, comp_shdr.sh_name);
			return;
		}

		if (strcmp(comp_name, sname) != 0)
			continue;

		if (comp_shdr.sh_type != shdr->sh_type ||
		    comp_shdr.sh_addralign != shdr->sh_addralign ||
		    comp_shdr.sh_size != shdr->sh_size ||
		    comp_shdr.sh_entsize != shdr->sh_entsize) {
			continue;
		}

		if ((src_data = elf_getdata(scn, NULL)) == NULL) {
			secmap_fail("failed to load section data from "
			    "source to compare to %s %s", sm->sm_obj, sname);
			return;
		}

		if ((comp_data = elf_getdata(comp_scn, NULL)) == NULL) {
			secmap_fail("failed to load section data from "
			    "source to compare to %s %s", sm->sm_obj, sname);
			return;
		}

		if (comp_data->d_size != src_data->d_size) {
			secmap_fail("data size mismatch for %s: %s, core: "
			    "%zu, file: %zu", sm->sm_obj, sname,
			    src_data->d_size, comp_data->d_size);
			return;
		}

		if (memcmp(comp_data->d_buf, src_data->d_buf,
		    comp_data->d_size) != 0) {
			secmap_fail("data mismatch between core and source "
			    "in %s: %s", sm->sm_obj, sname);
			return;
		}

		return;
	}

	secmap_fail("failed to find matching section for %s in %s",
	    sname, sm->sm_obj);
}

static void
secmap_file_check(secmap_t *sm)
{
	if (sm->sm_ctf && (secmap_content & CC_CONTENT_CTF) != 0 &&
	    sm->sm_nfound[SECMAP_CTF] == 0) {
		secmap_fail("expected object %s to have CTF, but it doesn't",
		    sm->sm_obj);
	}

	if (sm->sm_symtab && (secmap_content & CC_CONTENT_SYMTAB) != 0 &&
	    sm->sm_nfound[SECMAP_SYMTAB] == 0) {
		secmap_fail("expected object %s to have a symbol table, "
		    "but it doesn't", sm->sm_obj);
	}

	if (sm->sm_debug && (secmap_content & CC_CONTENT_DEBUG) != 0 &&
	    sm->sm_nfound[SECMAP_DEBUG] == 0) {
		secmap_fail("expected object %s to have debug sections, "
		    "but it doesn't", sm->sm_obj);
	}
}

int
main(int argc, char *argv[])
{
	core_content_t content;
	struct ps_prochandle *Pr;
	int perr, fd;
	Elf *elf;
	Elf_Scn *scn;
	GElf_Ehdr ehdr;

	if (argc != 3) {
		warnx("missing required file and core content");
		(void) fprintf(stderr, "Usage: secmapper file content\n");
		exit(EXIT_FAILURE);
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		errx(EXIT_FAILURE, "failed to init libelf");
	}

	Pr = Pgrab_core(argv[1], NULL, PGRAB_RDONLY, &perr);
	if (Pr == NULL) {
		errx(EXIT_FAILURE, "failed to open %s: %s", argv[1],
		    Pgrab_error(perr));
	}

	if ((fd = open(argv[1], O_RDONLY)) < 0) {
		err(EXIT_FAILURE, "failed to open %s\n", argv[1]);
	}

	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		errx(EXIT_FAILURE, "failed to open elf file %s: %s", argv[1],
		    elf_errmsg(elf_errno()));
	}

	if (proc_str2content(argv[2], &content) != 0) {
		err(EXIT_FAILURE, "failed to parse content %s", argv[2]);
	}

	if (gelf_getehdr(elf, &ehdr) == NULL) {
		errx(EXIT_FAILURE, "failed to get edr: %s",
		    elf_errmsg(elf_errno()));
	}

	/*
	 * Before we go futher, make sure that we have the content in this file
	 * that we expect.
	 */
	check_content(content, Pr);

	for (scn = elf_nextscn(elf, NULL); scn != NULL;
	    scn = elf_nextscn(elf, scn)) {
		const char *sname;
		GElf_Shdr shdr;
		size_t index;
		secmap_t *secmap;

		index = elf_ndxscn(scn);
		if (gelf_getshdr(scn, &shdr) ==  NULL) {
			errx(EXIT_FAILURE, "failed to get section header for "
			    "shdr %zu: %s", index, elf_errmsg(elf_errno()));
		}

		/*
		 * Skip the strtab.
		 */
		if (shdr.sh_type == SHT_STRTAB) {
			continue;
		}

		sname = elf_strptr(elf, ehdr.e_shstrndx, shdr.sh_name);
		if (sname == NULL) {
			secmap_fail("TEST FAILURE: string name missing for "
			    "shdr %zu", index);
			continue;
		}

		/*
		 * Find or cons up a new secmap for this object.
		 */
		secmap = secmap_find(shdr.sh_addr);
		if (secmap == NULL) {
			secmap = secmap_alloc(Pr, shdr.sh_addr);
		}

		if (strcmp(sname, ".symtab") == 0) {
			secmap->sm_nfound[SECMAP_SYMTAB]++;
		} else if (strcmp(sname, ".SUNW_ctf") == 0) {
			secmap->sm_nfound[SECMAP_CTF]++;
		} else if (strncmp(sname, ".debug_", strlen(".debug_")) == 0) {
			secmap->sm_nfound[SECMAP_DEBUG]++;
		} else {
			continue;
		}

		/*
		 * For one of our three primary sections, make sure that the
		 * data that is in the core file that we find in it actually
		 * matches the underlying object. That is, if the secmap
		 * actually has something here.
		 */
		if (secmap->sm_elf != NULL) {
			secmap_data_cmp(secmap, sname, scn, &shdr);
		}
	}

	/*
	 * Now that we have iterated over all of these sections, check and make
	 * sure certain things are true of them. In particular, go through some
	 * of the various types of data and make sure it exists at all or
	 * doesn't based on our core content.
	 */
	secmap_matches_content(SECMAP_CTF);
	secmap_matches_content(SECMAP_SYMTAB);
	secmap_matches_content(SECMAP_DEBUG);

	/*
	 * Finally, if we have enough information to know that we've found
	 * a file that we know it should at least have a given type of data,
	 * check for it. Here, it is OK for data to be present we don't expect
	 * (assuming the core content allows it). This makes this test less
	 * prone to broader changes in the system.
	 */
	for (size_t i = 0; i < secmap_count; i++) {
		secmap_file_check(&secmaps[i]);
	}

	return (secmap_exit);
}
