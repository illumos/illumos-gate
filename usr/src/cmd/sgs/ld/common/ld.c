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
 */

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<stdarg.h>
#include	<string.h>
#include	<strings.h>
#include	<errno.h>
#include	<fcntl.h>
#include	<libintl.h>
#include	<locale.h>
#include	<fcntl.h>
#include	<ar.h>
#include	<gelf.h>
#include	"conv.h"
#include	"libld.h"
#include	"machdep.h"
#include	"msg.h"

/*
 * The following prevent us from having to include ctype.h which defines these
 * functions as macros which reference the __ctype[] array.  Go through .plt's
 * to get to these functions in libc rather than have every invocation of ld
 * have to suffer the R_SPARC_COPY overhead of the __ctype[] array.
 */
extern int	isspace(int);

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
 */
void
veprintf(Lm_list *lml, Error error, const char *format, va_list args)
{
	static const char	*strings[ERR_NUM];

#if	defined(lint)
	/*
	 * The lml argument is only meaningful for diagnostics sent to ld.so.1.
	 * Supress the lint error by making a dummy assignment.
	 */
	lml = 0;
#endif
	/*
	 * For error types we issue a prefix for, make sure the necessary
	 * string has been internationalized and is ready.
	 */
	switch (error) {
	case ERR_WARNING_NF:
		if (strings[ERR_WARNING_NF] == NULL)
			strings[ERR_WARNING_NF] = MSG_INTL(MSG_ERR_WARNING);
		break;
	case ERR_WARNING:
		if (strings[ERR_WARNING] == NULL)
			strings[ERR_WARNING] = MSG_INTL(MSG_ERR_WARNING);
		break;
	case ERR_GUIDANCE:
		if (strings[ERR_GUIDANCE] == NULL)
			strings[ERR_GUIDANCE] = MSG_INTL(MSG_ERR_GUIDANCE);
		break;
	case ERR_FATAL:
		if (strings[ERR_FATAL] == NULL)
			strings[ERR_FATAL] = MSG_INTL(MSG_ERR_FATAL);
		break;
	case ERR_ELF:
		if (strings[ERR_ELF] == NULL)
			strings[ERR_ELF] = MSG_INTL(MSG_ERR_ELF);
	}

	/* If strings[] element for our error type is non-NULL, issue prefix */
	if (strings[error] != NULL) {
		(void) fputs(MSG_ORIG(MSG_STR_LDDIAG), stderr);
		(void) fputs(strings[error], stderr);
	}

	(void) vfprintf(stderr, format, args);
	if (error == ERR_ELF) {
		int	elferr;

		if ((elferr = elf_errno()) != 0)
			(void) fprintf(stderr, MSG_ORIG(MSG_STR_ELFDIAG),
			    elf_errmsg(elferr));
	}
	(void) fprintf(stderr, MSG_ORIG(MSG_STR_NL));
	(void) fflush(stderr);
}


/*
 * Print a message to stdout
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
static int
archive(int fd, Elf *elf, uchar_t *class_ret, Half *mach_ret)
{
	Elf_Cmd		cmd = ELF_C_READ;
	Elf_Arhdr	*arhdr;
	Elf		*_elf = NULL;
	int		found = 0;

	/*
	 * Process each item within the archive until we find the first
	 * ELF object, or alternatively another archive to recurse into.
	 * Stop after analyzing the first plain object found.
	 */
	while (!found && ((_elf = elf_begin(fd, cmd, elf)) != NULL)) {
		if ((arhdr = elf_getarhdr(_elf)) == NULL)
			return (0);
		if (*arhdr->ar_name != '/') {
			switch (elf_kind(_elf)) {
			case ELF_K_AR:
				found = archive(fd, _elf, class_ret, mach_ret);
				break;
			case ELF_K_ELF:
				if (gelf_getclass(_elf) == ELFCLASS64) {
					Elf64_Ehdr *ehdr;

					if ((ehdr = elf64_getehdr(_elf)) ==
					    NULL)
						break;
					*class_ret = ehdr->e_ident[EI_CLASS];
					*mach_ret = ehdr->e_machine;
				} else {
					Elf32_Ehdr *ehdr;

					if ((ehdr = elf32_getehdr(_elf)) ==
					    NULL)
						break;
					*class_ret = ehdr->e_ident[EI_CLASS];
					*mach_ret = ehdr->e_machine;
				}
				found = 1;
				break;
			}
		}

		cmd = elf_next(_elf);
		(void) elf_end(_elf);
	}

	return (found);
}

/*
 * Determine:
 *	- ELFCLASS of resulting object (class)
 *	- Whether user specified class of the linker (ldclass)
 *	- ELF machine type of resulting object (m_mach)
 *
 * In order of priority, we determine this information as follows:
 *
 * -	Command line options (-32, -64, -z altexec64, -z target).
 * -	From the first plain object seen on the command line. (This is
 *	by far the most common case.)
 * -	From the first object contained within the first archive
 *	on the command line.
 * -	If all else fails, we assume a 32-bit object for the native machine.
 *
 * entry:
 *	argc, argv - Command line argument vector
 *	class_ret - Address of variable to receive ELFCLASS of output object
 *	ldclass_ret - Address of variable to receive ELFCLASS of
 *		linker to use. This will be ELFCLASS32/ELFCLASS64 if one
 *		is explicitly specified, and ELFCLASSNONE otherwise.
 *		ELFCLASSNONE therefore means that we should use the best
 *		link-editor that the system/kernel will allow.
 */
static int
process_args(int argc, char **argv, uchar_t *class_ret, uchar_t *ldclass_ret,
    Half *mach)
{
	uchar_t	ldclass = ELFCLASSNONE, class = ELFCLASSNONE, ar_class;
	Half	mach32 = EM_NONE, mach64 = EM_NONE, ar_mach;
	int	c, ar_found = 0;

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
	 *	-z altexec64
	 *		Use the 64-bit linker regardless of the class
	 *		of the output object.
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
	 */
	opterr = 0;
	optind = 1;
getmore:
	while ((c = ld_getopt(0, optind, argc, argv)) != -1) {
		switch (c) {
		case '3':
			if (strncmp(optarg, MSG_ORIG(MSG_ARG_TWO),
			    MSG_ARG_TWO_SIZE) == 0)
				class = ELFCLASS32;
			break;

		case '6':
			if (strncmp(optarg, MSG_ORIG(MSG_ARG_FOUR),
			    MSG_ARG_FOUR_SIZE) == 0)
				class = ELFCLASS64;
			break;

		case 'z':
#if	!defined(_LP64)
			/* -z altexec64 */
			if (strncmp(optarg, MSG_ORIG(MSG_ARG_ALTEXEC64),
			    MSG_ARG_ALTEXEC64_SIZE) == 0) {
				ldclass = ELFCLASS64;
				break;
			}
#endif
			/* -z target=platform */
			if (strncmp(optarg, MSG_ORIG(MSG_ARG_TARGET),
			    MSG_ARG_TARGET_SIZE) == 0) {
				char *pstr = optarg + MSG_ARG_TARGET_SIZE;

				if (strcasecmp(pstr,
				    MSG_ORIG(MSG_TARG_SPARC)) == 0) {
					mach32 = EM_SPARC;
					mach64 = EM_SPARCV9;
				} else if (strcasecmp(pstr,
				    MSG_ORIG(MSG_TARG_X86)) == 0) {
					mach32 = EM_386;
					mach64 = EM_AMD64;
				} else {
					eprintf(0, ERR_FATAL,
					    MSG_INTL(MSG_ERR_BADTARG), pstr);
					return (1);
				}
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
			if (argv[optind][1] == '\0')
				continue;
			else
				goto getmore;
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
		if ((class != ELFCLASSNONE) && (mach32 != EM_NONE))
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
			return (1);
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

	/* ELFCLASS of link-editor to use */
	*ldclass_ret = ldclass;

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

	return (0);
}

/*
 * Process an LD_OPTIONS environment string.  This routine is first called to
 * count the number of options, and second to initialize a new argument array
 * with each option.
 */
static int
process_ldoptions(char *str, char **nargv)
{
	int	argc = 0;
	char	*arg = str;

	/*
	 * Walk the environment string processing any arguments that are
	 * separated by white space.
	 */
	while (*str != '\0') {
		if (isspace(*str)) {
			/*
			 * If a new argument array has been provided, terminate
			 * the original environment string, and initialize the
			 * appropriate argument array entry.
			 */
			if (nargv) {
				*str++ = '\0';
				nargv[argc] = arg;
			}

			argc++;
			while (isspace(*str))
				str++;
			arg = str;
		} else
			str++;
	}
	if (arg != str) {
		/*
		 * If a new argument array has been provided, initialize the
		 * final argument array entry.
		 */
		if (nargv)
			nargv[argc] = arg;
		argc++;
	}

	return (argc);
}

/*
 * Determine whether an LD_OPTIONS environment variable is set, and if so,
 * prepend environment string as a series of options to the argv array.
 */
static int
prepend_ldoptions(int *argcp, char ***argvp)
{
	int	nargc;
	char	**nargv, *ld_options;
	int	err, count;

	if ((ld_options = getenv(MSG_ORIG(MSG_LD_OPTIONS))) == NULL)
		return (0);

	/*
	 * Get rid of any leading white space, and make sure the environment
	 * string has size.
	 */
	while (isspace(*ld_options))
		ld_options++;
	if (ld_options[0] == '\0')
		return (0);

	/*
	 * Prevent modification of actual environment strings.
	 */
	if ((ld_options = strdup(ld_options)) == NULL) {
		err = errno;
		eprintf(0, ERR_FATAL, MSG_INTL(MSG_SYS_ALLOC), strerror(err));
		return (1);
	}

	/*
	 * Determine the number of options provided.
	 */
	nargc = process_ldoptions(ld_options, NULL);

	/*
	 * Allocate a new argv array big enough to hold the new options from
	 * the environment string and the old argv options.
	 */
	if ((nargv = malloc((nargc + *argcp + 1) * sizeof (char *))) == NULL) {
		err = errno;
		eprintf(0, ERR_FATAL, MSG_INTL(MSG_SYS_ALLOC), strerror(err));
		return (1);
	}

	/*
	 * Initialize first element of new argv array to be the first element
	 * of the old argv array (ie. calling programs name).  Then add the new
	 * args obtained from the environment.
	 */
	nargc = 0;
	nargv[nargc++] = (*argvp)[0];
	nargc += process_ldoptions(ld_options, &nargv[nargc]);

	/*
	 * Now add the original argv array (skipping argv[0]) to the end of the
	 * new argv array, and re-vector argc and argv to reference this new
	 * array
	 */
	for (count = 1; count < *argcp; count++, nargc++)
		nargv[nargc] = (*argvp)[count];

	nargv[nargc] = NULL;

	*argcp = nargc;
	*argvp = nargv;

	return (0);
}

/*
 * Check to see if there is a LD_ALTEXEC=<path to alternate ld> in the
 * environment.  If so, first null the environment variable out, and then
 * exec() the binary pointed to by the environment variable, passing the same
 * arguments as the originating process.  This mechanism permits using
 * alternate link-editors (debugging/developer copies) even in complex build
 * environments.
 */
static int
ld_altexec(char **argv, char **envp)
{
	char	*execstr;
	char	**str;
	int	err;

	for (str = envp; *str; str++) {
		if (strncmp(*str, MSG_ORIG(MSG_LD_ALTEXEC),
		    MSG_LD_ALTEXEC_SIZE) == 0) {
			break;
		}
	}

	/*
	 * If LD_ALTEXEC isn't set, return to continue executing the present
	 * link-editor.
	 */
	if (*str == 0)
		return (0);

	/*
	 * Get a pointer to the actual string.  If it's a null entry, return.
	 */
	execstr = strdup(*str + MSG_LD_ALTEXEC_SIZE);
	if (*execstr == '\0')
		return (0);

	/*
	 * Null out the LD_ALTEXEC= environment entry.
	 */
	(*str)[MSG_LD_ALTEXEC_SIZE] = '\0';

	/*
	 * Set argv[0] to point to our new linker
	 */
	argv[0] = execstr;

	/*
	 * And attempt to execute it.
	 */
	(void) execve(execstr, argv, envp);

	/*
	 * If the exec() fails, return a failure indication.
	 */
	err = errno;
	eprintf(0, ERR_FATAL, MSG_INTL(MSG_SYS_EXEC), execstr,
	    strerror(err));
	return (1);
}

int
main(int argc, char **argv, char **envp)
{
	char		**oargv = argv;
	uchar_t 	class, ldclass, checkclass;
	Half		mach;

	/*
	 * Establish locale.
	 */
	(void) setlocale(LC_MESSAGES, MSG_ORIG(MSG_STR_EMPTY));
	(void) textdomain(MSG_ORIG(MSG_SUNW_OST_SGS));

	/*
	 * Execute an alternate linker if the LD_ALTEXEC environment variable is
	 * set.  If a specified alternative could not be found, bail.
	 */
	if (ld_altexec(argv, envp))
		return (1);

	/*
	 * Check the LD_OPTIONS environment variable, and if present prepend
	 * the arguments specified to the command line argument list.
	 */
	if (prepend_ldoptions(&argc, &argv))
		return (1);

	/*
	 * Examine the command arguments to determine:
	 *	- object class
	 *	- link-editor class
	 *	- target machine
	 */
	if (process_args(argc, argv, &class, &ldclass, &mach))
		return (1);

	/*
	 * Unless a 32-bit link-editor was explicitly requested, try
	 * to exec the 64-bit version.
	 */
	if (ldclass != ELFCLASS32)
		checkclass = conv_check_native(oargv, envp);

	/*
	 * If an attempt to exec the 64-bit link-editor fails:
	 * -	Bail if the 64-bit linker was explicitly requested
	 * -	Continue quietly if the 64-bit linker was not requested.
	 *	This is undoubtedly due to hardware/kernel limitations,
	 *	and therefore represents the best we can do. Note that
	 *	the 32-bit linker is capable of linking anything the
	 *	64-bit version is, subject to a 4GB limit on memory, and
	 *	2GB object size.
	 */
	if ((ldclass == ELFCLASS64) && (checkclass != ELFCLASS64)) {
		eprintf(0, ERR_FATAL, MSG_INTL(MSG_SYS_64));
		return (1);
	}

	/* Call the libld entry point for the specified ELFCLASS */
	if (class == ELFCLASS64)
		return (ld64_main(argc, argv, mach));
	else
		return (ld32_main(argc, argv, mach));
}

/*
 * We supply this function for the msg module
 */
const char *
_ld_msg(Msg mid)
{
	return (gettext(MSG_ORIG(mid)));
}
