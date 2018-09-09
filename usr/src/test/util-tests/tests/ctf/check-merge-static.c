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
 * Copyright (c) 2019, Joyent, Inc.
 */

/*
 * Verify that various type information for static symbols is accurate for the
 * file in question. To run this test, there's a global and static version of a
 * symbol and function that exists on a per-file basis. These will all have been
 * reproduced in the output file. As such, we need to iterate the symbol table
 * to know which version should be which and use that to drive things.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <limits.h>
#include <strings.h>

#include "check-common.h"

typedef struct check_map {
	const char *map_file;
	const char *map_type;
} check_map_t;

static const char *global_type = "int";
static check_map_t map[] = {
	{ "test-a.c", "uint8_t" },
	{ "test-b.c", "uint16_t" },
	{ "test-c.c", "uint32_t" },
	{ "test-d.c", "uint64_t" },
	{ NULL }
};

static const char *
check_file_to_type(GElf_Sym *symp, const char *file, const char *name)
{
	uint_t i;

	if (ELF32_ST_BIND(symp->st_info) == STB_GLOBAL) {
		return (global_type);
	}

	if (file == NULL) {
		warnx("encountered non-global symbol without STT_FILE info: %s",
		    name);
		return (NULL);
	}

	for (i = 0; map[i].map_file != NULL; i++) {
		if (strcmp(map[i].map_file, file) == 0) {
			return (map[i].map_type);
		}
	}

	warnx("failed to find type mapping for symbol %s, file %s", name, file);
	return (NULL);
}

static int
check_global(ctf_file_t *fp, GElf_Sym *symp, int symid, const char *file,
    const char *name)
{
	const char *type;
	ctf_id_t tid;
	char buf[2048];

	if ((type = check_file_to_type(symp, file, name)) == NULL) {
		return (EXIT_FAILURE);
	}

	if ((tid = ctf_lookup_by_symbol(fp, symid)) == CTF_ERR) {
		warnx("failed to get type for symbol %s (%d): %s", name, symid,
		    ctf_errmsg(ctf_errno(fp)));
		return (EXIT_FAILURE);
	}

	if (ctf_type_name(fp, tid, buf, sizeof (buf)) == NULL) {
		warnx("failed to get type name for symbol %s (%d): %s",
		    name, symid, ctf_errmsg(ctf_errno(fp)));
		return (EXIT_FAILURE);
	}

	if (strcmp(buf, type) != 0) {
		warnx("type mismatch for symbol %s (%d): found %s, expected %s",
		    name, symid, buf, type);
		return (EXIT_FAILURE);
	}

	return (0);
}

static int
check_mumble(ctf_file_t *fp, GElf_Sym *symp, int symid, const char *file,
    const char *name)
{
	const char *type;
	ctf_funcinfo_t fi;
	ctf_id_t id, args;

	if ((type = check_file_to_type(symp, file, name)) == NULL) {
		return (EXIT_FAILURE);
	}

	if ((id = ctf_lookup_by_name(fp, type)) == CTF_ERR) {
		warnx("failed to lookup type id for %s: %s", type,
		    ctf_errmsg(ctf_errno(fp)));
		return (EXIT_FAILURE);
	}

	if (ctf_func_info(fp, symid, &fi) != 0) {
		warnx("failed to get function information for %s (%d): %s",
		    name, symid, ctf_errmsg(ctf_errno(fp)));
		return (EXIT_FAILURE);
	}

	if (fi.ctc_argc != 1) {
		warnx("argument count mismatch for symbol %s (%d): found %u, "
		    "expected %d", name, symid, fi.ctc_argc, 1);
		return (EXIT_FAILURE);
	}

	if (fi.ctc_flags != 0) {
		warnx("function flags mismatch for symbol %s (%d): found %u, "
		    "expected %d", name, symid, fi.ctc_flags, 0);
		return (EXIT_FAILURE);
	}

	if (fi.ctc_return != id) {
		warnx("return value mismatch for symbol %s (%d): found %ld, "
		    "expected %ld", name, symid, fi.ctc_return, id);
		return (EXIT_FAILURE);
	}

	if (ctf_func_args(fp, symid, 1, &args) != 0) {
		warnx("failed to get function arguments for symbol %s (%d): %s",
		    name, symid, ctf_errmsg(ctf_errno(fp)));
		return (EXIT_FAILURE);
	}

	if (args != id) {
		warnx("argument mismatch for symbol %s (%d): found %ld, "
		    "expected %ld", name, symid, args, id);
		return (EXIT_FAILURE);
	}

	return (0);
}

static int
check_merge_static(const char *file, ctf_file_t *fp, Elf *elf)
{
	Elf_Scn *scn = NULL, *symscn = NULL;
	Elf_Data *symdata = NULL;
	GElf_Shdr symhdr;
	ulong_t nsyms;
	int i;
	const char *curfile = NULL;
	int ret = 0;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if (gelf_getshdr(scn, &symhdr) == NULL) {
			warnx("failed to get section header: %s",
			    elf_errmsg(elf_errno()));
			return (EXIT_FAILURE);
		}

		if (symhdr.sh_type == SHT_SYMTAB) {
			symscn = scn;
			break;
		}
	}

	if (symscn == NULL) {
		warnx("failed to find symbol table for %s", file);
		return (EXIT_FAILURE);
	}

	if ((symdata = elf_getdata(symscn, NULL)) == NULL) {
		warnx("failed to get data for symbol table %s: %s", file,
		    elf_errmsg(elf_errno()));
		return (EXIT_FAILURE);
	}

	if (symhdr.sh_link == SHN_XINDEX) {
		warnx("test does not support extended ELF sections!");
		return (EXIT_FAILURE);
	}
	nsyms = symhdr.sh_size / symhdr.sh_entsize;
	if (nsyms > INT_MAX) {
		warnx("file contains more symbols than libelf can iterate");
		return (EXIT_FAILURE);
	}

	for (i = 1; i < (int)nsyms; i++) {
		GElf_Sym sym;
		const char *name;
		uint_t type;

		if (gelf_getsym(symdata, i, &sym) == NULL) {
			warnx("failed to get data about symbol %d", i);
			return (EXIT_FAILURE);
		}

		if ((name = elf_strptr(elf, symhdr.sh_link, sym.st_name)) ==
		    NULL) {
			warnx("failed to get name for symbol %d", i);
			return (EXIT_FAILURE);
		}

		type = GELF_ST_TYPE(sym.st_info);
		if (type == STT_FILE) {
			curfile = name;
			continue;
		}

		if (strcmp(name, "global") == 0) {
			ret |= check_global(fp, &sym, i, curfile, name);
		} else if (strcmp(name, "mumble") == 0) {
			ret |= check_mumble(fp, &sym, i, curfile, name);
		}
	}

	return (ret);
}

int
main(int argc, char *argv[])
{
	int i, ret = 0;

	if (argc < 2) {
		errx(EXIT_FAILURE, "missing test files");
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		errx(EXIT_FAILURE, "failed to initialize libelf");
	}

	for (i = 1; i < argc; i++) {
		int fd;
		ctf_file_t *fp;
		Elf *elf;

		if ((fd = open(argv[i], O_RDONLY)) < 0) {
			warn("failed to open %s", argv[i]);
			ret = EXIT_FAILURE;
			continue;
		}

		if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
			warnx("failed to open libelf handle to %s", argv[i]);
			ret = EXIT_FAILURE;
			(void) close(fd);
			continue;
		}

		if ((fp = ctf_open(argv[i], &ret)) == NULL) {
			warnx("failed to open %s: %s", argv[i],
			    ctf_errmsg(ret));
			ret = EXIT_FAILURE;
			(void) close(fd);
			(void) elf_end(elf);
			continue;
		}

		if (check_merge_static(argv[i], fp, elf) != 0) {
			ret = EXIT_FAILURE;
		}

		ctf_close(fp);
		(void) close(fd);
		(void) elf_end(elf);
	}

	return (ret);
}
