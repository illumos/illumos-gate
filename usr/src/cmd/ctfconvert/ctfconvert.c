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
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * Create CTF from extant debugging information
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <libelf.h>
#include <libctf.h>
#include <string.h>
#include <libgen.h>
#include <limits.h>
#include <strings.h>
#include <sys/debug.h>

#define	CTFCONVERT_OK		0
#define	CTFCONVERT_FATAL	1
#define	CTFCONVERT_USAGE	2

static char *ctfconvert_progname;

static void
ctfconvert_fatal(const char *fmt, ...)
{
	va_list ap;

	(void) fprintf(stderr, "%s: ", ctfconvert_progname);
	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);

	exit(CTFCONVERT_FATAL);
}

static void
ctfconvert_warning(void *arg, const char *fmt, ...)
{
	va_list ap;
	char *buf;

	va_start(ap, fmt);
	if (vasprintf(&buf, fmt, ap) != -1) {
		(void) fprintf(stderr, "%s: WARNING: %s", ctfconvert_progname,
		    buf);
		free(buf);
	}
	va_end(ap);
}

static void
ctfconvert_usage(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		(void) fprintf(stderr, "%s: ", ctfconvert_progname);
		va_start(ap, fmt);
		(void) vfprintf(stderr, fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage: %s [-fikms] [-j nthrs] [-l label | "
	    "-L labelenv] [-b batchsize]\n"
	    "                  [-o outfile] [-M ignorefile] input\n"
	    "\n"
	    "\t-b  batch process this many dies at a time (default %d)\n"
	    "\t-f  always attempt to convert files\n"
	    "\t-i  ignore files not built partially from C sources\n"
	    "\t-j  use nthrs threads to perform the merge (default %d)\n"
	    "\t-k  keep around original input file on failure\n"
	    "\t-l  set output container's label to specified value\n"
	    "\t-L  set output container's label to value from environment\n"
	    "\t-m  allow input to have missing debug info\n"
	    "\t-M  allow files listed in ignorefile to have missing debug\n"
	    "\t-o  copy input to outfile and add CTF\n"
	    "\t-s  allow truncation of data that cannot be fully converted\n",
	    ctfconvert_progname,
	    CTF_CONVERT_DEFAULT_BATCHSIZE,
	    CTF_CONVERT_DEFAULT_NTHREADS);
}

/*
 * This is a bit unfortunate. Traditionally we do type uniquification across all
 * modules in the kernel, including ip and unix against genunix. However, when
 * _MACHDEP is defined, then the cpu_t ends up having an additional member
 * (cpu_m), thus changing the ability for us to uniquify against it. This in
 * turn causes a lot of type sprawl, as there's a lot of things that end up
 * referring to the cpu_t and it chains out from there.
 *
 * So, if we find that a cpu_t has been defined and it has a couple of useful
 * sentinel members and it does *not* have the cpu_m member, then we will try
 * and lookup or create a forward declaration to the machcpu, append it to the
 * end, and update the file.
 *
 * This currently is only invoked if an undocumented option -X is passed. This
 * value is private to illumos and it can be changed at any time inside of it,
 * so if -X wants to be used for something, it should be. The ability to rely on
 * -X for others is strictly not an interface in any way, shape, or form.
 *
 * The following struct contains most of the information that we care about and
 * that we want to validate exists before we decide what to do.
 */

typedef struct ctfconvert_fixup {
	boolean_t	cf_cyclic;	/* Do we have a cpu_cyclic member */
	boolean_t	cf_mcpu;	/* We have a cpu_m member */
	boolean_t	cf_lastpad;	/* Is the pad member the last entry */
	ulong_t		cf_padoff;	/* offset of the pad */
} ctfconvert_fixup_t;

/* ARGSUSED */
static int
ctfconvert_fixup_genunix_cb(const char *name, ctf_id_t tid, ulong_t off,
    void *arg)
{
	ctfconvert_fixup_t *cfp = arg;

	cfp->cf_lastpad = B_FALSE;
	if (strcmp(name, "cpu_cyclic") == 0) {
		cfp->cf_cyclic = B_TRUE;
		return (0);
	}

	if (strcmp(name, "cpu_m") == 0) {
		cfp->cf_mcpu = B_TRUE;
		return (0);
	}

	if (strcmp(name, "cpu_m_pad") == 0) {
		cfp->cf_lastpad = B_TRUE;
		cfp->cf_padoff = off;
		return (0);
	}

	return (0);
}

static void
ctfconvert_fixup_genunix(ctf_file_t *fp)
{
	ctf_id_t cpuid, mcpu;
	ssize_t sz;
	ctfconvert_fixup_t cf;
	int model, ptrsz;

	cpuid = ctf_lookup_by_name(fp, "struct cpu");
	if (cpuid == CTF_ERR)
		return;

	if (ctf_type_kind(fp, cpuid) != CTF_K_STRUCT)
		return;

	if ((sz = ctf_type_size(fp, cpuid)) == CTF_ERR)
		return;

	model = ctf_getmodel(fp);
	VERIFY(model == CTF_MODEL_ILP32 || model == CTF_MODEL_LP64);
	ptrsz = model == CTF_MODEL_ILP32 ? 4 : 8;

	bzero(&cf, sizeof (ctfconvert_fixup_t));
	if (ctf_member_iter(fp, cpuid, ctfconvert_fixup_genunix_cb, &cf) ==
	    CTF_ERR)
		return;

	/*
	 * Finally, we want to verify that the cpu_m is actually the last member
	 * that we have here.
	 */
	if (cf.cf_cyclic == B_FALSE || cf.cf_mcpu == B_TRUE ||
	    cf.cf_lastpad == B_FALSE) {
		return;
	}

	if (cf.cf_padoff + ptrsz * NBBY != sz * NBBY) {
		return;
	}

	/*
	 * Okay, we're going to do this, try to find a struct machcpu. We either
	 * want a forward or a struct. If we find something else, error. If we
	 * find nothing, add a forward and then add the member.
	 */
	mcpu = ctf_lookup_by_name(fp, "struct machcpu");
	if (mcpu == CTF_ERR) {
		mcpu = ctf_add_forward(fp, CTF_ADD_NONROOT, "machcpu",
		    CTF_K_STRUCT);
		if (mcpu == CTF_ERR) {
			ctfconvert_fatal("failed to add 'struct machcpu' "
			    "forward: %s\n", ctf_errmsg(ctf_errno(fp)));
		}
	} else {
		int kind;
		if ((kind = ctf_type_kind(fp, mcpu)) == CTF_ERR) {
			ctfconvert_fatal("failed to get the type kind for "
			    "the struct machcpu: %s\n",
			    ctf_errmsg(ctf_errno(fp)));
		}

		if (kind != CTF_K_STRUCT && kind != CTF_K_FORWARD)
			ctfconvert_fatal("encountered a struct machcpu of the "
			    "wrong type, found type kind %d\n", kind);
	}

	if (ctf_update(fp) == CTF_ERR) {
		ctfconvert_fatal("failed to update output file: %s\n",
		    ctf_errmsg(ctf_errno(fp)));
	}

	if (ctf_add_member(fp, cpuid, "cpu_m", mcpu, sz * NBBY) == CTF_ERR) {
		ctfconvert_fatal("failed to add the m_cpu member: %s\n",
		    ctf_errmsg(ctf_errno(fp)));
	}

	if (ctf_update(fp) == CTF_ERR) {
		ctfconvert_fatal("failed to update output file: %s\n",
		    ctf_errmsg(ctf_errno(fp)));
	}

	VERIFY(ctf_type_size(fp, cpuid) == sz);
}

int
main(int argc, char *argv[])
{
	int c, ifd, err;
	boolean_t keep = B_FALSE;
	ctf_convert_flag_t flags = 0;
	uint_t bsize = CTF_CONVERT_DEFAULT_BATCHSIZE;
	uint_t nthreads = CTF_CONVERT_DEFAULT_NTHREADS;
	const char *outfile = NULL;
	const char *label = NULL;
	const char *infile = NULL;
	const char *ignorefile = NULL;
	char *tmpfile;
	ctf_file_t *ofp;
	char buf[4096] = "";
	boolean_t optx = B_FALSE;
	boolean_t ignore_non_c = B_FALSE;
	ctf_convert_t *cch;

	ctfconvert_progname = basename(argv[0]);

	while ((c = getopt(argc, argv, ":b:fij:kl:L:mM:o:sX")) != -1) {
		switch (c) {
		case 'b': {
			long argno;
			const char *errstr;

			argno = strtonum(optarg, 1, UINT_MAX, &errstr);
			if (errstr != NULL) {
				ctfconvert_fatal("invalid argument for -b: "
				    "%s - %s\n", optarg, errstr);
			}
			bsize = (uint_t)argno;
			break;
		}
		case 'f':
			flags |= CTF_FORCE_CONVERSION;
			break;
		case 'i':
			ignore_non_c = B_TRUE;
			break;
		case 'j': {
			long argno;
			const char *errstr;

			argno = strtonum(optarg, 1, 1024, &errstr);
			if (errstr != NULL) {
				ctfconvert_fatal("invalid argument for -j: "
				    "%s - %s\n", optarg, errstr);
			}
			nthreads = (uint_t)argno;
			break;
		}
		case 'k':
			keep = B_TRUE;
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
		case 'M':
			ignorefile = optarg;
			break;
		case 'o':
			outfile = optarg;
			break;
		case 's':
			flags |= CTF_ALLOW_TRUNCATION;
			break;
		case 'X':
			optx = B_TRUE;
			break;
		case ':':
			ctfconvert_usage("Option -%c requires an operand\n",
			    optopt);
			return (CTFCONVERT_USAGE);
		case '?':
			ctfconvert_usage("Unknown option: -%c\n", optopt);
			return (CTFCONVERT_USAGE);
		}
	}

	argv += optind;
	argc -= optind;

	if (argc != 1) {
		ctfconvert_usage("Exactly one input file is required\n");
		return (CTFCONVERT_USAGE);
	}
	infile = argv[0];

	if (elf_version(EV_CURRENT) == EV_NONE)
		ctfconvert_fatal("failed to initialize libelf: library is "
		    "out of date\n");

	ifd = open(infile, O_RDONLY);
	if (ifd < 0) {
		ctfconvert_fatal("failed to open input file %s: %s\n", infile,
		    strerror(errno));
	}

	/*
	 * By default we remove the input file on failure unless we've been
	 * given an output file or -k has been specified.
	 */
	if (outfile != NULL && strcmp(infile, outfile) != 0)
		keep = B_TRUE;

	cch = ctf_convert_init(&err);
	if (cch == NULL) {
		ctfconvert_fatal(
		    "failed to create libctf conversion handle: %s\n",
		    strerror(err));
	}
	if ((err = ctf_convert_set_nthreads(cch, nthreads)) != 0)
		ctfconvert_fatal("Could not set number of threads: %s\n",
		    strerror(err));
	if ((err = ctf_convert_set_batchsize(cch, bsize)) != 0)
		ctfconvert_fatal("Could not set batch size: %s\n",
		    strerror(err));
	if ((err = ctf_convert_set_flags(cch, flags)) != 0)
		ctfconvert_fatal("Could not set conversion flags: %s\n",
		    strerror(err));
	if (label != NULL && (err = ctf_convert_set_label(cch, label)) != 0)
		ctfconvert_fatal("Could not set label: %s\n",
		    strerror(err));
	if ((err = ctf_convert_set_warncb(cch, ctfconvert_warning, NULL)) != 0)
		ctfconvert_fatal("Could not set warning callback: %s\n",
		    strerror(err));

	if (ignorefile != NULL) {
		char *buf = NULL;
		ssize_t cnt;
		size_t len = 0;
		FILE *fp;

		if ((fp = fopen(ignorefile, "r")) == NULL) {
			ctfconvert_fatal("Could not open ignorefile '%s': %s\n",
			    ignorefile, strerror(errno));
		}

		while ((cnt = getline(&buf, &len, fp)) != -1) {
			char *p = buf;

			if (cnt == 0 || *p == '#')
				continue;

			(void) strsep(&p, "\n");
			if ((err = ctf_convert_add_ignore(cch, buf)) != 0) {
				ctfconvert_fatal(
				    "Failed to add '%s' to ignore list: %s\n",
				    buf, strerror(err));
			}
		}
		free(buf);
		if (cnt == -1 && ferror(fp) != 0) {
			ctfconvert_fatal(
			    "Error reading from ignorefile '%s': %s\n",
			    ignorefile, strerror(errno));
		}

		(void) fclose(fp);
	}

	ofp = ctf_fdconvert(cch, ifd, &err, buf, sizeof (buf));

	ctf_convert_fini(cch);

	if (ofp == NULL) {
		/*
		 * Normally, ctfconvert requires that its input file has at
		 * least one C-source compilation unit, and that every C-source
		 * compilation unit has DWARF. This is to avoid accidentally
		 * leaving out useful CTF.
		 *
		 * However, for the benefit of intransigent build environments,
		 * the -i and -m options can be used to relax this.
		 */
		if (err == ECTF_CONVNOCSRC && ignore_non_c) {
			exit(CTFCONVERT_OK);
		}

		if (err == ECTF_CONVNODEBUG &&
		    (flags & CTF_ALLOW_MISSING_DEBUG) != 0) {
			exit(CTFCONVERT_OK);
		}

		if (keep == B_FALSE)
			(void) unlink(infile);

		/*
		 * Note, we expect libctf to include a newline it all of its
		 * error messages right now (though it perhaps shouldn't).
		 */
		switch (err) {
		case ECTF_CONVBKERR:
			ctfconvert_fatal("CTF conversion failed: %s", buf);
			break;
		case ECTF_CONVNODEBUG:
			ctfconvert_fatal("CTF conversion failed due to "
			    "missing debug data; use -m to override\n");
			break;
		default:
			if (*buf != '\0') {
				(void) fprintf(stderr, "%s: %s",
				    ctfconvert_progname, buf);
			}
			ctfconvert_fatal("CTF conversion failed: %s\n",
			    ctf_errmsg(err));
		}
	}

	if (optx == B_TRUE)
		ctfconvert_fixup_genunix(ofp);

	tmpfile = NULL;
	if (outfile == NULL || strcmp(infile, outfile) == 0) {
		if (asprintf(&tmpfile, "%s.ctf", infile) == -1) {
			if (keep == B_FALSE)
				(void) unlink(infile);
			ctfconvert_fatal("failed to allocate memory for "
			    "temporary file: %s\n", strerror(errno));
		}
		outfile = tmpfile;
	}
	err = ctf_elfwrite(ofp, infile, outfile, CTF_ELFWRITE_F_COMPRESS);
	if (err == CTF_ERR) {
		(void) unlink(outfile);
		if (keep == B_FALSE)
			(void) unlink(infile);
		ctfconvert_fatal("failed to write CTF section to output file: "
		    "%s\n", ctf_errmsg(ctf_errno(ofp)));
	}
	ctf_close(ofp);

	if (tmpfile != NULL) {
		if (rename(tmpfile, infile) != 0) {
			int e = errno;
			(void) unlink(outfile);
			if (keep == B_FALSE)
				(void) unlink(infile);
			ctfconvert_fatal("failed to rename temporary file: "
			    "%s\n", strerror(e));
		}
	}
	free(tmpfile);

	return (CTFCONVERT_OK);
}
