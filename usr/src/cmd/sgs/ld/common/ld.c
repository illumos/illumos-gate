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
 * Copyright (c) 1997, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2023 Oxide Computer Company
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <libintl.h>
#include <locale.h>
#include <fcntl.h>
#include <ar.h>
#include <gelf.h>
#include "conv.h"
#include "libld.h"
#include "machdep.h"
#include "msg.h"

typedef int (*ld_main_f)(int, char *[], Half);

static const char *errstr[ERR_NUM];

static void
init_strings(void)
{
	(void) setlocale(LC_MESSAGES, MSG_ORIG(MSG_STR_EMPTY));
	(void) textdomain(MSG_ORIG(MSG_SUNW_OST_SGS));

	/*
	 * For error types we issue a prefix for, make sure the necessary
	 * string has been internationalized and is ready.
	 */
	errstr[ERR_WARNING_NF] = MSG_INTL(MSG_ERR_WARNING);
	errstr[ERR_WARNING] = MSG_INTL(MSG_ERR_WARNING);
	errstr[ERR_GUIDANCE] = MSG_INTL(MSG_ERR_GUIDANCE);
	errstr[ERR_FATAL] = MSG_INTL(MSG_ERR_FATAL);
	errstr[ERR_ELF] = MSG_INTL(MSG_ERR_ELF);
}

/*
 * Returns a duplicate of the given environment variable, with
 * leading whitespace stripped off.  Returns NULL if the variable
 * is not in the environment, or if it is empty.  Allocation
 * failure terminates the program.
 */
static char *
getenv_nonempty(const char *name)
{
	char *var;

	var = getenv(name);
	if (var == NULL)
		return (NULL);
	while (isspace(*var))
		var++;
	if (*var == '\0')
		return (NULL);
	var = strdup(var);
	if (var == NULL) {
		eprintf(0, ERR_FATAL, MSG_INTL(MSG_SYS_ALLOC), strerror(errno));
		exit(EXIT_FAILURE);
	}

	return (var);
}

/*
 * Like strsep(3), but using `isspace` instead of
 * a separator string.
 */
static char *
strsep_ws(char **strp)
{
	char *str, *s;

	str = *strp;
	if (*str == '\0')
		return (NULL);
	s = str;
	while (*s != '\0' && !isspace(*s))
		s++;
	if (*s != '\0')
		*s++ = '\0';
	*strp = s;

	return (str);
}

/*
 * We examine ELF objects, and archives containing ELF objects, in order
 * to determine the ELFCLASS of the resulting object and/or the linker to be
 * used. We want to avoid the overhead of libelf for this, at least until
 * we are certain that we need it, so we start by reading bytes from
 * the beginning of the file. This type defines the buffer used to read
 * these initial bytes.
 *
 * A plain ELF object will start with an ELF header, whereas an archive
 * starts with a magic string (ARMAG) that is SARMAG bytes long. Any valid
 * ELF file or archive will contain more bytes than this buffer, so any
 * file shorter than this can be safely assummed not to be of interest.
 *
 * The ELF header for ELFCLASS32 and ELFCLASS64 are identical up through the
 * the e_version field, and all the information we require is found in this
 * common prefix. Furthermore, this cannot change, as the layout of an ELF
 * header is fixed by the ELF ABI. Hence, the ehdr part of this union is
 * not a full ELF header, but only the class-independent prefix that we need.
 *
 * As this is a raw (non-libelf) read, we are responsible for handling any
 * byte order difference between the object and the system running this
 * program when we read any datum larger than a byte (i.e. e_machine) from
 * this header.
 */
typedef union {
	struct {	/* Must match start of ELFxx_Ehdr in <sys/elf.h> */
		uchar_t		e_ident[EI_NIDENT];	/* ident bytes */
		Half		e_type;			/* file type */
		Half		e_machine;		/* target machine */
	} ehdr;
	char			armag[SARMAG];
} FILE_HDR;

/*
 * Print a message to stdout
 * The lml argument is only meaningful for diagnostics sent to ld.so.1,
 * and is ignored here.
 */
void
veprintf(Lm_list *lml __unused, Error error, const char *format, va_list args)
{
	const char *err;

	/* If strings[] element for our error type is non-NULL, issue prefix */
	err = errstr[error];
	if (err != NULL)
		(void) fprintf(stderr, "%s%s", MSG_ORIG(MSG_STR_LDDIAG), err);
	(void) vfprintf(stderr, format, args);

	if (error == ERR_ELF) {
		int elferr;

		elferr = elf_errno();
		if (elferr != 0) {
			err = elf_errmsg(elferr);
			(void) fprintf(stderr, MSG_ORIG(MSG_STR_ELFDIAG), err);
		}
	}
	(void) fprintf(stderr, MSG_ORIG(MSG_STR_NL));
	(void) fflush(stderr);
}

/*
 * Print a message to stderr
 */
/* VARARGS3 */
void
eprintf(Lm_list *lml, Error error, const char *format, ...)
{
	va_list	args;

	va_start(args, format);
	veprintf(lml, error, format, args);
	va_end(args);
}


/*
 * Examine the first object in an archive to determine its ELFCLASS
 * and machine type.
 *
 * entry:
 *	fd - Open file descriptor for file
 *	elf - libelf ELF descriptor
 *	class_ret, mach_ret - Address of variables to receive ELFCLASS
 *		and machine type.
 *
 * exit:
 *	On success, *class_ret and *mach_ret are filled in, and True (1)
 *	is returned. On failure, False (0) is returned.
 */
static bool
archive(int fd, Elf *elf, uchar_t *class_ret, Half *mach_ret)
{
	Elf_Cmd cmd;
	Elf *nelf;

	/*
	 * Process each item within the archive until we find the first
	 * ELF object, or alternatively another archive to recurse into.
	 * Stop after analyzing the first plain object found.
	 */
	for (cmd = ELF_C_READ, nelf = NULL;
	    (nelf = elf_begin(fd, cmd, elf)) != NULL;
	    cmd = elf_next(nelf), (void) elf_end(nelf)) {
		Elf_Arhdr *arhdr = elf_getarhdr(nelf);

		if (arhdr == NULL)
			return (false);
		if (*arhdr->ar_name == '/')
			continue;
		switch (elf_kind(nelf)) {
		case ELF_K_AR:
			if (archive(fd, nelf, class_ret, mach_ret))
				return (true);
			break;
		case ELF_K_ELF:
			if (gelf_getclass(nelf) == ELFCLASS64) {
				Elf64_Ehdr *ehdr = elf64_getehdr(nelf);

				if (ehdr == NULL)
					continue;
				*class_ret = ehdr->e_ident[EI_CLASS];
				*mach_ret = ehdr->e_machine;
			} else {
				Elf32_Ehdr *ehdr = elf32_getehdr(nelf);

				if (ehdr == NULL)
					continue;
				*class_ret = ehdr->e_ident[EI_CLASS];
				*mach_ret = ehdr->e_machine;
			}
			return (true);
		}
	}

	return (false);
}

/*
 * Determine:
 *	- ELFCLASS of resulting object (class)
 *	- ELF machine type of resulting object (m_mach)
 *
 * In order of priority, we determine this information as follows:
 *
 * -	Command line options (-32, -64 -z target).
 * -	From the first plain object seen on the command line. (This is
 *	by far the most common case.)
 * -	From the first object contained within the first archive
 *	on the command line.
 * -	If all else fails, we assume a 32-bit object for the native machine.
 *
 * entry:
 *	argc, argv - Command line argument vector
 *	class_ret - Address of variable to receive ELFCLASS of output object
 */
static ld_main_f
process_args(int argc, char *argv[], uchar_t *class_ret, Half *mach)
{
	Half mach32 = EM_NONE;
	Half mach64 = EM_NONE;
	bool ar_found = false;
	uint8_t class = ELFCLASSNONE;
	const char *targ_sparc = MSG_ORIG(MSG_TARG_SPARC);
	const char *targ_x86 = MSG_ORIG(MSG_TARG_X86);
	uint8_t ar_class;
	Half ar_mach;
	char *pstr;
	const char *err;
	int c;

	/*
	 * In general, libld.so is responsible for processing the
	 * command line options. The exception to this are those options
	 * that contain information about which linker to run and the
	 * class/machine of the output object. We examine the options
	 * here looking for the following:
	 *
	 *	-32	Produce an ELFCLASS32 object. This is the default, so
	 *		-32 is only needed when linking entirely from archives,
	 *		and the first archive contains a mix of 32 and 64-bit
	 *		objects, and the first object in that archive is 64-bit.
	 *		We do not expect this option to get much use, but it
	 *		ensures that the user can handle any situation.
	 *
	 *	-64	Produce an ELFCLASS64 object. (Note that this will
	 *		indirectly cause the use of the 64-bit linker if
	 *		the system is 64-bit capable). The most common need
	 *		for this option is when linking a filter object entirely
	 *		from a mapfile. The less common case is when linking
	 *		entirely from archives, and the first archive contains
	 *		a mix of 32 and 64-bit objects, and the first object
	 *		in that archive is 32-bit.
	 *
	 *	-z target=platform
	 *		Produce output object for the specified platform.
	 *		This option is needed when producing an object
	 *		for a non-native target entirely from a mapfile,
	 *		or when linking entirely from an archive containing
	 *		objects for multiple targets, and the first object
	 *		in the archive is not for the desired target.
	 *
	 * If we've already processed an object and we find -32/-64, and
	 * the object is of the wrong class, we have an error condition.
	 * We ignore it here, and let it fall through to libld, where the
	 * proper diagnosis and error message will occur.
	 *
	 * Note that these options can all be given more than once, even if
	 * doing so would be ambiguous: this is for backwards compatibility
	 * with Makefiles and shell scripts and so on that are themselves
	 * ambiguous.
	 */
	opterr = 0;
	optind = 1;

getmore:
	while ((c = ld_getopt(0, optind, argc, argv)) != -1) {
		switch (c) {
		case '3':
			/*
			 * MSG_ORIG(MSG_ARG_TWO) is just the non-localized
			 * string literal "2", but...ok.
			 */
			if (strcmp(optarg, MSG_ORIG(MSG_ARG_TWO)) != 0) {
				err = MSG_INTL(MSG_ERR_BADARG);
				eprintf(0, ERR_FATAL, err, '3', optarg);
				exit(EXIT_FAILURE);
			}
			class = ELFCLASS32;
			break;
		case '6':
			if (strcmp(optarg, MSG_ORIG(MSG_ARG_FOUR)) != 0) {
				err = MSG_INTL(MSG_ERR_BADARG);
				eprintf(0, ERR_FATAL, err, '6', optarg);
				exit(EXIT_FAILURE);
			}
			class = ELFCLASS64;
			break;
		case 'z':
			/* -z target=platform; silently skip everything else */
			if (strncmp(optarg, MSG_ORIG(MSG_ARG_TARGET),
			    MSG_ARG_TARGET_SIZE) != 0) {
				continue;
			}
			pstr = optarg + MSG_ARG_TARGET_SIZE;
			if (strcasecmp(pstr, targ_sparc) == 0) {
				mach32 = EM_SPARC;
				mach64 = EM_SPARCV9;
			} else if (strcasecmp(pstr, targ_x86) == 0) {
				mach32 = EM_386;
				mach64 = EM_AMD64;
			} else {
				err = MSG_INTL(MSG_ERR_BADTARG);
				eprintf(0, ERR_FATAL, err, pstr);
				exit(EXIT_FAILURE);
			}
			break;
		}
	}

	/*
	 * Continue to look for the first ELF object to determine the class of
	 * objects to operate on. At the same time, look for the first archive
	 * of ELF objects --- if no plain ELF object is specified, the type
	 * of the first ELF object in the first archive will be used. If
	 * there is no object, and no archive, then we fall back to a 32-bit
	 * object for the native machine.
	 */
	for (; optind < argc; optind++) {
		int		fd;
		FILE_HDR	hdr;

		/*
		 * If we detect some more options return to getopt().
		 * Checking argv[optind][1] against null prevents a forever
		 * loop if an unadorned `-' argument is passed to us.
		 */
		if (argv[optind][0] == '-') {
			if (argv[optind][1] != '\0')
				goto getmore;
			continue;
		}

		/*
		 * If we've already determined the object class and
		 * machine type, continue to the next argument. Only
		 * the first object contributes to this decision, and
		 * there's no value to opening or examing the subsequent
		 * ones. We do need to keep going though, because there
		 * may be additional options that might affect our
		 * class/machine decision.
		 */
		if (class != ELFCLASSNONE && mach32 != EM_NONE)
			continue;

		/*
		 * Open the file and determine if it is an object. We are
		 * looking for ELF objects, or archives of ELF objects.
		 *
		 * Plain objects are simple, and are the common case, so
		 * we examine them directly and avoid the map-unmap-map
		 * that would occur if we used libelf. Archives are too
		 * complex to be worth accessing directly, so if we identify
		 * an archive, we use libelf on it and accept the cost.
		 */
		if ((fd = open(argv[optind], O_RDONLY)) == -1) {
			int err = errno;

			eprintf(0, ERR_FATAL, MSG_INTL(MSG_SYS_OPEN),
			    argv[optind], strerror(err));
			exit(EXIT_FAILURE);
		}

		if (pread(fd, &hdr, sizeof (hdr), 0) != sizeof (hdr)) {
			(void) close(fd);
			continue;
		}

		if ((hdr.ehdr.e_ident[EI_MAG0] == ELFMAG0) &&
		    (hdr.ehdr.e_ident[EI_MAG1] == ELFMAG1) &&
		    (hdr.ehdr.e_ident[EI_MAG2] == ELFMAG2) &&
		    (hdr.ehdr.e_ident[EI_MAG3] == ELFMAG3)) {
			if (class == ELFCLASSNONE) {
				class = hdr.ehdr.e_ident[EI_CLASS];
				if ((class != ELFCLASS32) &&
				    (class != ELFCLASS64))
					class = ELFCLASSNONE;
			}

			if (mach32 == EM_NONE) {
				int	one = 1;
				uchar_t	*one_p = (uchar_t *)&one;
				int	ld_elfdata;

				ld_elfdata = (one_p[0] == 1) ?
				    ELFDATA2LSB : ELFDATA2MSB;
				/*
				 * Both the 32 and 64-bit versions get the
				 * type from the object. If the user has
				 * asked for an inconsistant class/machine
				 * combination, libld will catch it.
				 */
				mach32 = mach64 =
				    (ld_elfdata == hdr.ehdr.e_ident[EI_DATA]) ?
				    hdr.ehdr.e_machine :
				    BSWAP_HALF(hdr.ehdr.e_machine);
			}
		} else if (!ar_found &&
		    (memcmp(&hdr.armag, ARMAG, SARMAG) == 0)) {
			Elf	*elf;

			(void) elf_version(EV_CURRENT);
			if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
				(void) close(fd);
				continue;
			}
			if (elf_kind(elf) == ELF_K_AR)
				ar_found =
				    archive(fd, elf, &ar_class, &ar_mach);
			(void) elf_end(elf);
		}

		(void) close(fd);
	}

	/*
	 * ELFCLASS of output object: If we did not establish a class from a
	 * command option, or from the first plain object, then use the class
	 * from the first archive, and failing that, default to 32-bit.
	 */
	if (class == ELFCLASSNONE)
		class = ar_found ? ar_class : ELFCLASS32;
	*class_ret = class;

	/*
	 * Machine type of output object: If we did not establish a machine
	 * type from the command line, or from the first plain object, then
	 * use the machine established by the first archive, and failing that,
	 * use the native machine.
	 */
	*mach = (class == ELFCLASS64) ? mach64 : mach32;
	if (*mach == EM_NONE)
		if (ar_found)
			*mach = ar_mach;
		else
			*mach = (class == ELFCLASS64) ? M_MACH_64 : M_MACH_32;

	if (class == ELFCLASS32)
		return (ld32_main);

	return (ld64_main);
}

struct strlist {
	struct strlist *sl_next;
	char *sl_str;
};

/*
 * Parse an LD_OPTIONS environment string.  Returns a linked list of strings
 * parsed from the original list, or NULL if the list is empty.
 */
static struct strlist *
split_options(char *str)
{
	struct strlist *strs = NULL;
	struct strlist **nextp = &strs;
	struct strlist *next;
	char *arg;

	while ((arg = strsep_ws(&str)) != NULL) {
		if (*arg == '\0')
			continue;
		next = calloc(1, sizeof (struct strlist));
		if (next == NULL) {
			eprintf(0, ERR_FATAL,
			    MSG_INTL(MSG_SYS_ALLOC), strerror(errno));
			exit(EXIT_FAILURE);
		}
		next->sl_str = arg;
		*nextp = next;
		nextp = &next->sl_next;
	}

	return (strs);
}

/*
 * Determine whether an LD_OPTIONS environment variable is set, and if so,
 * prepend environment string as a series of options to the argv array.
 */
static void
prepend_ldoptions(int *argcp, char **argvp[])
{
	int argc, nargc;
	char **argv, **nargv, *ld_options;
	struct strlist *opts, *p, *t;

	ld_options = getenv_nonempty(MSG_ORIG(MSG_LD_OPTIONS));
	if (ld_options == NULL)
		return;

	/*
	 * Parse and count options.
	 */
	opts = split_options(ld_options);
	for (nargc = 0, p = opts; p != NULL; p = p->sl_next)
		nargc++;

	/*
	 * Allocate a new argument vector big enough to hold both the old
	 * and new arguments.
	 */
	argc = *argcp;
	argv = *argvp;
	nargv = calloc(nargc + argc + 1, sizeof (char *));
	if (nargv == NULL) {
		eprintf(0, ERR_FATAL, MSG_INTL(MSG_SYS_ALLOC), strerror(errno));
		exit(EXIT_FAILURE);
	}

	/*
	 * Initialize first element of new argv array to be the first element
	 * of the old argv array (ie. calling programs name).  Then add the new
	 * args obtained from the environment.
	 */
	nargv[0] = argv[0];
	for (nargc = 1, p = opts; p != NULL; nargc++, p = p->sl_next)
		nargv[nargc] = p->sl_str;

	/*
	 * Now add the original argv array (skipping argv[0]) to the end of the
	 * new argv array, and re-vector argc and argv to reference this new
	 * array
	 */
	for (int i = 1; i < argc; i++, nargc++)
		nargv[nargc] = argv[i];
	nargv[nargc] = NULL;

	/*
	 * Clean up the strlist.
	 */
	for (t = NULL, p = opts; p != NULL; p = t) {
		t = p->sl_next;
		free(p);
	}

	*argcp = nargc;
	*argvp = nargv;
}

/*
 * Check to see if there is a LD_ALTEXEC=<path to alternate ld> in the
 * environment.  If so, first null the environment variable out, and then
 * exec() the binary pointed to by the environment variable, passing the same
 * arguments as the originating process.  This mechanism permits using
 * alternate link-editors (debugging/developer copies) even in complex build
 * environments.
 */
static void
ld_altexec(int argc, char *argv[], char *envp[])
{
	char *bin;
	struct strlist *opts, *p, *t;
	char **nargv;
	int i;

	/*
	 * If LD_ALTEXEC isn't set, or is empty, return to continue executing
	 * the present link-editor.  Note that we unconditionally unset it.
	 */
	bin = getenv_nonempty(MSG_ORIG(MSG_LD_ALTEXEC));
	(void) unsetenv(MSG_ORIG(MSG_LD_ALTEXEC));
	if (bin == NULL)
		return;

	/* Parse and count options, including argv[0]. */
	opts = split_options(bin);
	if (opts == NULL)
		return;


	for (p = opts; p != NULL; p = p->sl_next)
		argc++;

	nargv = calloc(argc, sizeof (char *));
	if (nargv == NULL) {
		eprintf(0, ERR_FATAL, MSG_INTL(MSG_SYS_ALLOC), strerror(errno));
		exit(EXIT_FAILURE);
	}
	for (i = 0, p = opts; p != NULL; p = p->sl_next, i++)
		nargv[i] = p->sl_str;
	/* Note that `argc` now counts the NULL at the end of `nargv`. */
	for (; i < argc; i++)
		nargv[i] = *++argv;

	/*
	 * Clean up the strlist.
	 */
	for (t = NULL, p = opts; p != NULL; p = t) {
		t = p->sl_next;
		free(p);
	}

	/*
	 * Set argv[0] to point to our new linker And attempt to execute it.
	 */
	(void) execve(bin, nargv, envp);

	/*
	 * If the exec() fails, exit with failure.
	 */
	eprintf(0, ERR_FATAL, MSG_INTL(MSG_SYS_EXEC), bin, strerror(errno));
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[], char *envp[])
{
	uint8_t class;
	Half mach;
	ld_main_f ld_main;

	/*
	 * Establish locale and initialize error strings.
	 */
	init_strings();

	/*
	 * Maybe execute an alternate linker.  If the LD_ALTEXEC
	 * environment variable is set, we will try and run what it
	 * points to or fail.  If it is not set, we simply continue.
	 */
	ld_altexec(argc, argv, envp);

	/*
	 * Maybe process additional arguments.  If the LD_OPTIONS
	 * environment variable is set, and if present prepend
	 * the arguments specified to the command line argument list.
	 */
	prepend_ldoptions(&argc, &argv);

	/*
	 * Examine the command arguments to determine:
	 *	- object class
	 *	- link-editor class
	 *	- target machine
	 */
	ld_main = process_args(argc, argv, &class, &mach);

	/* Call the libld entry point for the specified ELFCLASS */
	return (ld_main(argc, argv, mach));
}

/*
 * We supply this function for the msg module
 */
const char *
_ld_msg(Msg mid)
{
	return (gettext(MSG_ORIG(mid)));
}
