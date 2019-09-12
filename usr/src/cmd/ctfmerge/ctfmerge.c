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
 * merge CTF containers
 */

#include <stdio.h>
#include <libctf.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <strings.h>
#include <assert.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <stdlib.h>
#include <libelf.h>
#include <gelf.h>
#include <sys/mman.h>
#include <libgen.h>
#include <stdarg.h>
#include <limits.h>

static char *g_progname;
static char *g_unique;
static char *g_outfile;
static uint_t g_nctf;

#define	CTFMERGE_OK	0
#define	CTFMERGE_FATAL	1
#define	CTFMERGE_USAGE	2

#define	CTFMERGE_DEFAULT_NTHREADS	8

static void __attribute__((__noreturn__))
ctfmerge_fatal(const char *fmt, ...)
{
	va_list ap;

	(void) fprintf(stderr, "%s: ", g_progname);
	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);

	if (g_outfile != NULL)
		(void) unlink(g_outfile);

	exit(CTFMERGE_FATAL);
}

/*
 * We failed to find CTF for this file, check if it's OK. If we're not derived
 * from C, or we have the -m option, we let missing CTF pass.
 */
static void
ctfmerge_check_for_c(const char *name, Elf *elf, uint_t flags)
{
	char errmsg[1024];

	if (flags & CTF_ALLOW_MISSING_DEBUG)
		return;

	switch (ctf_has_c_source(elf, errmsg, sizeof (errmsg))) {
	case CHR_ERROR:
		ctfmerge_fatal("failed to open %s: %s\n", name, errmsg);
		break;

	case CHR_NO_C_SOURCE:
		return;

	default:
		ctfmerge_fatal("failed to open %s: %s\n", name,
		    ctf_errmsg(ECTF_NOCTFDATA));
		break;
	}
}

/*
 * Go through and construct enough information for this Elf Object to try and do
 * a ctf_bufopen().
 */
static int
ctfmerge_elfopen(const char *name, Elf *elf, ctf_merge_t *cmh, uint_t flags)
{
	GElf_Ehdr ehdr;
	GElf_Shdr shdr;
	Elf_Scn *scn;
	Elf_Data *ctf_data, *str_data, *sym_data;
	ctf_sect_t ctfsect, symsect, strsect;
	ctf_file_t *fp;
	int err;

	if (gelf_getehdr(elf, &ehdr) == NULL)
		ctfmerge_fatal("failed to get ELF header for %s: %s\n",
		    name, elf_errmsg(elf_errno()));

	bzero(&ctfsect, sizeof (ctf_sect_t));
	bzero(&symsect, sizeof (ctf_sect_t));
	bzero(&strsect, sizeof (ctf_sect_t));

	scn = NULL;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		const char *sname;

		if (gelf_getshdr(scn, &shdr) == NULL)
			ctfmerge_fatal("failed to get section header for "
			    "file %s: %s\n", name, elf_errmsg(elf_errno()));

		sname = elf_strptr(elf, ehdr.e_shstrndx, shdr.sh_name);
		if (shdr.sh_type == SHT_PROGBITS &&
		    strcmp(sname, ".SUNW_ctf") == 0) {
			ctfsect.cts_name = sname;
			ctfsect.cts_type = shdr.sh_type;
			ctfsect.cts_flags = shdr.sh_flags;
			ctfsect.cts_size = shdr.sh_size;
			ctfsect.cts_entsize = shdr.sh_entsize;
			ctfsect.cts_offset = (off64_t)shdr.sh_offset;

			ctf_data = elf_getdata(scn, NULL);
			if (ctf_data == NULL)
				ctfmerge_fatal("failed to get ELF CTF "
				    "data section for %s: %s\n", name,
				    elf_errmsg(elf_errno()));
			ctfsect.cts_data = ctf_data->d_buf;
		} else if (shdr.sh_type == SHT_SYMTAB) {
			Elf_Scn *strscn;
			GElf_Shdr strhdr;

			symsect.cts_name = sname;
			symsect.cts_type = shdr.sh_type;
			symsect.cts_flags = shdr.sh_flags;
			symsect.cts_size = shdr.sh_size;
			symsect.cts_entsize = shdr.sh_entsize;
			symsect.cts_offset = (off64_t)shdr.sh_offset;

			if ((strscn = elf_getscn(elf, shdr.sh_link)) == NULL ||
			    gelf_getshdr(strscn, &strhdr) == NULL)
				ctfmerge_fatal("failed to get "
				    "string table for file %s: %s\n", name,
				    elf_errmsg(elf_errno()));

			strsect.cts_name = elf_strptr(elf, ehdr.e_shstrndx,
			    strhdr.sh_name);
			strsect.cts_type = strhdr.sh_type;
			strsect.cts_flags = strhdr.sh_flags;
			strsect.cts_size = strhdr.sh_size;
			strsect.cts_entsize = strhdr.sh_entsize;
			strsect.cts_offset = (off64_t)strhdr.sh_offset;

			sym_data = elf_getdata(scn, NULL);
			if (sym_data == NULL)
				ctfmerge_fatal("failed to get ELF CTF "
				    "data section for %s: %s\n", name,
				    elf_errmsg(elf_errno()));
			symsect.cts_data = sym_data->d_buf;

			str_data = elf_getdata(strscn, NULL);
			if (str_data == NULL)
				ctfmerge_fatal("failed to get ELF CTF "
				    "data section for %s: %s\n", name,
				    elf_errmsg(elf_errno()));
			strsect.cts_data = str_data->d_buf;
		}
	}

	if (ctfsect.cts_type == SHT_NULL) {
		ctfmerge_check_for_c(name, elf, flags);
		return (ENOENT);
	}

	if (symsect.cts_type != SHT_NULL && strsect.cts_type != SHT_NULL) {
		fp = ctf_bufopen(&ctfsect, &symsect, &strsect, &err);
	} else {
		fp = ctf_bufopen(&ctfsect, NULL, NULL, &err);
	}

	if (fp == NULL) {
		ctfmerge_fatal("failed to open file %s: %s\n",
		    name, ctf_errmsg(err));
	}

	if ((err = ctf_merge_add(cmh, fp)) != 0) {
		ctfmerge_fatal("failed to add input %s: %s\n",
		    name, ctf_errmsg(err));
	}

	g_nctf++;
	return (0);
}

static void
ctfmerge_read_archive(const char *name, int fd, Elf *elf,
    ctf_merge_t *cmh, uint_t flags)
{
	Elf_Cmd cmd = ELF_C_READ;
	int cursec = 1;
	Elf *aelf;

	while ((aelf = elf_begin(fd, cmd, elf)) != NULL) {
		char *nname = NULL;
		Elf_Arhdr *arhdr;

		if ((arhdr = elf_getarhdr(aelf)) == NULL)
			ctfmerge_fatal("failed to get archive header %d for "
			    "%s: %s\n", cursec, name, elf_errmsg(elf_errno()));

		cmd = elf_next(aelf);

		if (*(arhdr->ar_name) == '/')
			goto next;

		if (asprintf(&nname, "%s.%s.%d", name, arhdr->ar_name,
		    cursec) < 0)
			ctfmerge_fatal("failed to allocate memory for archive "
			    "%d of file %s\n", cursec, name);

		switch (elf_kind(aelf)) {
		case ELF_K_AR:
			ctfmerge_read_archive(nname, fd, aelf, cmh, flags);
			break;
		case ELF_K_ELF:
			/* ctfmerge_elfopen() takes ownership of aelf. */
			if (ctfmerge_elfopen(nname, aelf, cmh, flags) == 0)
				aelf = NULL;
			break;
		default:
			ctfmerge_fatal("unknown elf kind (%d) in archive %d "
			    "for %s\n", elf_kind(aelf), cursec, name);
			break;
		}

next:
		(void) elf_end(aelf);
		free(nname);
		cursec++;
	}
}

static void
ctfmerge_file_add(ctf_merge_t *cmh, const char *file, uint_t flags)
{
	Elf *e;
	int fd;

	if ((fd = open(file, O_RDONLY)) < 0) {
		ctfmerge_fatal("failed to open file %s: %s\n",
		    file, strerror(errno));
	}

	if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		(void) close(fd);
		ctfmerge_fatal("failed to open %s: %s\n",
		    file, elf_errmsg(elf_errno()));
	}

	switch (elf_kind(e)) {
	case ELF_K_AR:
		ctfmerge_read_archive(file, fd, e, cmh, flags);
		break;

	case ELF_K_ELF:
		/* ctfmerge_elfopen() takes ownership of e. */
		if (ctfmerge_elfopen(file, e, cmh, flags) == 0)
			e = NULL;
		break;

	default:
		ctfmerge_fatal("unknown elf kind (%d) for %s\n",
		    elf_kind(e), file);
	}

	(void) elf_end(e);
	(void) close(fd);
}

static void
ctfmerge_usage(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		(void) fprintf(stderr, "%s: ", g_progname);
		va_start(ap, fmt);
		(void) vfprintf(stderr, fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage: %s [-m] [-d uniqfile] [-l label] "
	    "[-L labelenv] [-j nthrs] -o outfile file ...\n"
	    "\n"
	    "\t-d  uniquify merged output against uniqfile\n"
	    "\t-j  use nthrs threads to perform the merge\n"
	    "\t-l  set output container's label to specified value\n"
	    "\t-L  set output container's label to value from environment\n"
	    "\t-m  allow C-based input files to not have CTF\n"
	    "\t-o  file to add CTF data to\n",
	    g_progname);
}

int
main(int argc, char *argv[])
{
	int err, i, c, ofd;
	uint_t nthreads = CTFMERGE_DEFAULT_NTHREADS;
	char *tmpfile = NULL, *label = NULL;
	int wflags = CTF_ELFWRITE_F_COMPRESS;
	uint_t flags = 0;
	ctf_merge_t *cmh;
	ctf_file_t *ofp;
	long argj;
	char *eptr;

	g_progname = basename(argv[0]);

	/*
	 * We support a subset of the old CTF merge flags, mostly for
	 * compatibility.
	 */
	while ((c = getopt(argc, argv, ":d:fgj:l:L:mo:t")) != -1) {
		switch (c) {
		case 'd':
			g_unique = optarg;
			break;
		case 'f':
			/* Silently ignored for compatibility */
			break;
		case 'g':
			/* Silently ignored for compatibility */
			break;
		case 'j':
			errno = 0;
			argj = strtol(optarg, &eptr, 10);
			if (errno != 0 || argj == LONG_MAX ||
			    argj > 1024 || *eptr != '\0') {
				ctfmerge_fatal("invalid argument for -j: %s\n",
				    optarg);
			}
			nthreads = (uint_t)argj;
			break;
		case 'l':
			label = optarg;
			break;
		case 'L':
			label = getenv(optarg);
			break;
		case 'm':
			flags |= CTF_ALLOW_MISSING_DEBUG;
			break;
		case 'o':
			g_outfile = optarg;
			break;
		case 't':
			/* Silently ignored for compatibility */
			break;
		case ':':
			ctfmerge_usage("Option -%c requires an operand\n",
			    optopt);
			return (CTFMERGE_USAGE);
		case '?':
			ctfmerge_usage("Unknown option: -%c\n", optopt);
			return (CTFMERGE_USAGE);
		}
	}

	if (g_outfile == NULL) {
		ctfmerge_usage("missing required -o output file\n");
		return (CTFMERGE_USAGE);
	}

	(void) elf_version(EV_CURRENT);

	/*
	 * Obviously this isn't atomic, but at least gives us a good starting
	 * point.
	 */
	if ((ofd = open(g_outfile, O_RDWR)) < 0)
		ctfmerge_fatal("cannot open output file %s: %s\n", g_outfile,
		    strerror(errno));

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		ctfmerge_usage("no input files specified");
		return (CTFMERGE_USAGE);
	}

	cmh = ctf_merge_init(ofd, &err);
	if (cmh == NULL)
		ctfmerge_fatal("failed to create merge handle: %s\n",
		    ctf_errmsg(err));

	if ((err = ctf_merge_set_nthreads(cmh, nthreads)) != 0)
		ctfmerge_fatal("failed to set parallelism to %u: %s\n",
		    nthreads, ctf_errmsg(err));

	for (i = 0; i < argc; i++) {
		ctfmerge_file_add(cmh, argv[i], flags);
	}

	if (g_nctf == 0) {
		ctf_merge_fini(cmh);
		return (0);
	}

	if (g_unique != NULL) {
		ctf_file_t *ufp;
		char *base;

		ufp = ctf_open(g_unique, &err);
		if (ufp == NULL) {
			ctfmerge_fatal("failed to open uniquify file %s: %s\n",
			    g_unique, ctf_errmsg(err));
		}

		base = basename(g_unique);
		(void) ctf_merge_uniquify(cmh, ufp, base);
	}

	if (label != NULL) {
		if ((err = ctf_merge_label(cmh, label)) != 0)
			ctfmerge_fatal("failed to add label %s: %s\n", label,
			    ctf_errmsg(err));
	}

	err = ctf_merge_merge(cmh, &ofp);
	if (err != 0)
		ctfmerge_fatal("failed to merge types: %s\n", ctf_errmsg(err));
	ctf_merge_fini(cmh);

	if (asprintf(&tmpfile, "%s.ctf", g_outfile) == -1)
		ctfmerge_fatal("ran out of memory for temporary file name\n");
	err = ctf_elfwrite(ofp, g_outfile, tmpfile, wflags);
	if (err == CTF_ERR) {
		(void) unlink(tmpfile);
		free(tmpfile);
		ctfmerge_fatal("encountered a libctf error: %s!\n",
		    ctf_errmsg(ctf_errno(ofp)));
	}

	if (rename(tmpfile, g_outfile) != 0) {
		(void) unlink(tmpfile);
		free(tmpfile);
		ctfmerge_fatal("failed to rename temporary file: %s\n",
		    strerror(errno));
	}
	free(tmpfile);

	return (CTFMERGE_OK);
}
