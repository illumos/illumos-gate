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
 * Copyright (c) 2015, Joyent, Inc.
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
static boolean_t g_req;
static uint_t g_nctf;

#define	CTFMERGE_OK	0
#define	CTFMERGE_FATAL	1
#define	CTFMERGE_USAGE	2

#define	CTFMERGE_DEFAULT_NTHREADS	8
#define	CTFMERGE_ALTEXEC	"CTFMERGE_ALTEXEC"

static void
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

static boolean_t
ctfmerge_expect_ctf(const char *name, Elf *elf)
{
	Elf_Scn *scn, *strscn;
	Elf_Data *data, *strdata;
	GElf_Shdr shdr;
	ulong_t i;

	if (g_req == B_FALSE)
		return (B_FALSE);

	scn = NULL;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if (gelf_getshdr(scn, &shdr) == NULL) {
			ctfmerge_fatal("failed to get section header for file "
			    "%s: %s\n", name, elf_errmsg(elf_errno()));
		}

		if (shdr.sh_type == SHT_SYMTAB)
			break;
	}

	if (scn == NULL)
		return (B_FALSE);

	if ((strscn = elf_getscn(elf, shdr.sh_link)) == NULL)
		ctfmerge_fatal("failed to get section header for file %s: %s\n",
		    name, elf_errmsg(elf_errno()));

	if ((data = elf_getdata(scn, NULL)) == NULL)
		ctfmerge_fatal("failed to read symbol table for %s: %s\n",
		    name, elf_errmsg(elf_errno()));

	if ((strdata = elf_getdata(strscn, NULL)) == NULL)
		ctfmerge_fatal("failed to read string table for %s: %s\n",
		    name, elf_errmsg(elf_errno()));

	for (i = 0; i < shdr.sh_size / shdr.sh_entsize; i++) {
		GElf_Sym sym;
		const char *file;
		size_t len;

		if (gelf_getsym(data, i, &sym) == NULL)
			ctfmerge_fatal("failed to read symbol table entry %d "
			    "for %s: %s\n", i, name, elf_errmsg(elf_errno()));

		if (GELF_ST_TYPE(sym.st_info) != STT_FILE)
			continue;

		file = (const char *)((uintptr_t)strdata->d_buf + sym.st_name);
		len = strlen(file);
		if (len < 2 || name[len - 2] != '.')
			continue;

		if (name[len - 1] == 'c')
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Go through and construct enough information for this Elf Object to try and do
 * a ctf_bufopen().
 */
static void
ctfmerge_elfopen(const char *name, Elf *elf, ctf_merge_t *cmh)
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
		if (ctfmerge_expect_ctf(name, elf) == B_FALSE)
			return;
		ctfmerge_fatal("failed to open %s: %s\n", name,
		    ctf_errmsg(ECTF_NOCTFDATA));
	}

	if (symsect.cts_type != SHT_NULL && strsect.cts_type != SHT_NULL) {
		fp = ctf_bufopen(&ctfsect, &symsect, &strsect, &err);
	} else {
		fp = ctf_bufopen(&ctfsect, NULL, NULL, &err);
	}

	if (fp == NULL) {
		if (ctfmerge_expect_ctf(name, elf) == B_TRUE) {
			ctfmerge_fatal("failed to open file %s: %s\n",
			    name, ctf_errmsg(err));
		}
	} else {
		if ((err = ctf_merge_add(cmh, fp)) != 0) {
			ctfmerge_fatal("failed to add input %s: %s\n",
			    name, ctf_errmsg(err));
		}
		g_nctf++;
	}
}

static void
ctfmerge_read_archive(const char *name, int fd, Elf *elf,
    ctf_merge_t *cmh)
{
	Elf *aelf;
	Elf_Cmd cmd = ELF_C_READ;
	int cursec = 1;
	char *nname;

	while ((aelf = elf_begin(fd, cmd, elf)) != NULL) {
		Elf_Arhdr *arhdr;
		boolean_t leakelf = B_FALSE;

		if ((arhdr = elf_getarhdr(aelf)) == NULL)
			ctfmerge_fatal("failed to get archive header %d for "
			    "%s: %s\n", cursec, name, elf_errmsg(elf_errno()));

		if (*(arhdr->ar_name) == '/')
			goto next;

		if (asprintf(&nname, "%s.%s.%d", name, arhdr->ar_name,
		    cursec) < 0)
			ctfmerge_fatal("failed to allocate memory for archive "
			    "%d of file %s\n", cursec, name);

		switch (elf_kind(aelf)) {
		case ELF_K_AR:
			ctfmerge_read_archive(nname, fd, aelf, cmh);
			free(nname);
			break;
		case ELF_K_ELF:
			ctfmerge_elfopen(nname, aelf, cmh);
			free(nname);
			leakelf = B_TRUE;
			break;
		default:
			ctfmerge_fatal("unknown elf kind (%d) in archive %d "
			    "for %s\n", elf_kind(aelf), cursec, name);
		}

next:
		cmd = elf_next(aelf);
		if (leakelf == B_FALSE)
			(void) elf_end(aelf);
		cursec++;
	}
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

	(void) fprintf(stderr, "Usage: %s [-gt] [-d uniqfile] [-l label] "
	    "[-L labelenv] [-j nthrs] -o outfile file ...\n"
	    "\n"
	    "\t-d  uniquify merged output against uniqfile\n"
	    "\t-g  do not remove source debug information (STABS, DWARF)\n"
	    "\t-j  use nthrs threads to perform the merge\n"
	    "\t-l  set output container's label to specified value\n"
	    "\t-L  set output container's label to value from environment\n"
	    "\t-o  file to add CTF data to\n"
	    "\t-t  require CTF data from all inputs built from C sources\n",
	    g_progname);
}

static void
ctfmerge_altexec(char **argv)
{
	const char *alt;
	char *altexec;

	alt = getenv(CTFMERGE_ALTEXEC);
	if (alt == NULL || *alt == '\0')
		return;

	altexec = strdup(alt);
	if (altexec == NULL)
		ctfmerge_fatal("failed to allocate memory for altexec\n");
	if (unsetenv(CTFMERGE_ALTEXEC) != 0)
		ctfmerge_fatal("failed to unset %s from environment: %s\n",
		    CTFMERGE_ALTEXEC, strerror(errno));

	(void) execv(altexec, argv);
	ctfmerge_fatal("failed to execute alternate program %s: %s",
	    altexec, strerror(errno));
}

int
main(int argc, char *argv[])
{
	int err, i, c, ofd;
	uint_t nthreads = CTFMERGE_DEFAULT_NTHREADS;
	char *tmpfile = NULL, *label = NULL;
	int wflags = CTF_ELFWRITE_F_COMPRESS;
	ctf_file_t *ofp;
	ctf_merge_t *cmh;
	long argj;
	char *eptr;

	g_progname = basename(argv[0]);

	ctfmerge_altexec(argv);

	/*
	 * We support a subset of the old CTF merge flags, mostly for
	 * compatability.
	 */
	while ((c = getopt(argc, argv, ":d:fgj:L:o:t")) != -1) {
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
			    argj == LONG_MIN || argj <= 0 ||
			    argj > UINT_MAX || *eptr != '\0') {
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
		case 'o':
			g_outfile = optarg;
			break;
		case 't':
			g_req = B_TRUE;
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
		ctfmerge_fatal("failed to set parallelism to %d: %s\n",
		    nthreads, ctf_errmsg(err));

	for (i = 0; i < argc; i++) {
		ctf_file_t *ifp;
		int fd;

		if ((fd = open(argv[i], O_RDONLY)) < 0)
			ctfmerge_fatal("failed to open file %s: %s\n",
			    argv[i], strerror(errno));
		ifp = ctf_fdopen(fd, &err);
		if (ifp == NULL) {
			Elf *e;

			if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
				(void) close(fd);
				ctfmerge_fatal("failed to open %s: %s\n",
				    argv[i], ctf_errmsg(err));
			}

			/*
			 * It's an ELF file, check if we have an archive or if
			 * we're expecting CTF here.
			 */
			switch (elf_kind(e)) {
			case ELF_K_AR:
				break;
			case ELF_K_ELF:
				if (ctfmerge_expect_ctf(argv[i], e) == B_TRUE) {
					(void) elf_end(e);
					(void) close(fd);
					ctfmerge_fatal("failed to "
					    "open %s: file was built from C "
					    "sources, but missing CTF\n",
					    argv[i]);
				}
				(void) elf_end(e);
				(void) close(fd);
				continue;
			default:
				(void) elf_end(e);
				(void) close(fd);
				ctfmerge_fatal("failed to open %s: "
				    "unsupported ELF file type", argv[i]);
			}

			ctfmerge_read_archive(argv[i], fd, e, cmh);
			(void) elf_end(e);
			(void) close(fd);
			continue;
		}
		(void) close(fd);
		if ((err = ctf_merge_add(cmh, ifp)) != 0)
			ctfmerge_fatal("failed to add input %s: %s\n",
			    argv[i], ctf_errmsg(err));
		g_nctf++;
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
