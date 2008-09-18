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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
 * Print a message to stdout
 */
/* VARARGS3 */
void
eprintf(Lm_list *lml, Error error, const char *format, ...)
{
	va_list			args;
	static const char	*strings[ERR_NUM] = { MSG_ORIG(MSG_STR_EMPTY) };

#if	defined(lint)
	/*
	 * The lml argument is only meaningful for diagnostics sent to ld.so.1.
	 * Supress the lint error by making a dummy assignment.
	 */
	lml = 0;
#endif
	if (error > ERR_NONE) {
		if (error == ERR_WARNING) {
			if (strings[ERR_WARNING] == 0)
				strings[ERR_WARNING] =
				    MSG_INTL(MSG_ERR_WARNING);
		} else if (error == ERR_FATAL) {
			if (strings[ERR_FATAL] == 0)
				strings[ERR_FATAL] = MSG_INTL(MSG_ERR_FATAL);
		} else if (error == ERR_ELF) {
			if (strings[ERR_ELF] == 0)
				strings[ERR_ELF] = MSG_INTL(MSG_ERR_ELF);
		}
		(void) fputs(MSG_ORIG(MSG_STR_LDDIAG), stderr);
	}
	(void) fputs(strings[error], stderr);

	va_start(args, format);
	(void) vfprintf(stderr, format, args);
	if (error == ERR_ELF) {
		int	elferr;

		if ((elferr = elf_errno()) != 0)
			(void) fprintf(stderr, MSG_ORIG(MSG_STR_ELFDIAG),
			    elf_errmsg(elferr));
	}
	(void) fprintf(stderr, MSG_ORIG(MSG_STR_NL));
	(void) fflush(stderr);
	va_end(args);
}


/*
 * Determine:
 *	- ELFCLASS of resulting object (aoutclass)
 *	- Whether we need the 32 or 64-bit libld (ldclass)
 *	- ELF machine type of resulting object (m_mach)
 */
static int
process_args(int argc, char **argv, uchar_t *aoutclass, uchar_t *ldclass,
    Half *mach)
{
#if	defined(_LP64)
	uchar_t lclass = ELFCLASS64;
#else
	uchar_t	lclass = ELFCLASSNONE;
#endif
	uchar_t	aclass = ELFCLASSNONE;
	Half	mach32 = EM_NONE, mach64 = EM_NONE;
	int	c;

	/*
	 * In general, libld.so is responsible for processing the
	 * command line options. The exception to this are those options
	 * that contain information about which linker to run and the
	 * class/machine of the output object. We examine the options
	 * here looking for the following:
	 *
	 *	-64
	 *		Produce an ELFCLASS64 object. Use the 64-bit linker.
	 *
	 *	-z altexec64
	 *		Use the 64-bit linker regardless of the class
	 *		of the output object.
	 *
	 *	-z target=platform
	 *		Produce output object for the specified platform.
	 *
	 * The -64 and -ztarget options are used when the only input to
	 * ld() is a mapfile or archive, and a 64-bit or non-native output
	 * object is required.
	 *
	 * If we've already processed a 32-bit object and we find -64, we have
	 * an error condition, but let this fall through to libld to obtain the
	 * default error message.
	 */
	opterr = 0;
	optind = 1;
getmore:
	while ((c = ld_getopt(0, optind, argc, argv)) != -1) {
		switch (c) {
		case '6':
			if (strncmp(optarg, MSG_ORIG(MSG_ARG_FOUR),
			    MSG_ARG_FOUR_SIZE) == 0)
				aclass = ELFCLASS64;
			break;

		case 'z':
#if	!defined(_LP64)
			/* -z altexec64 */
			if (strncmp(optarg, MSG_ORIG(MSG_ARG_ALTEXEC64),
			    MSG_ARG_ALTEXEC64_SIZE) == 0) {
				lclass = ELFCLASS64;
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
	 * objects to operate on.
	 */
	for (; optind < argc; optind++) {
		int		fd;
		Elf32_Ehdr	ehdr32;

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
		if ((aclass != ELFCLASSNONE) && (mach32 != EM_NONE))
			continue;

		/*
		 * Open the file and determine the files ELF class.
		 */
		if ((fd = open(argv[optind], O_RDONLY)) == -1) {
			int err = errno;

			eprintf(0, ERR_FATAL, MSG_INTL(MSG_SYS_OPEN),
			    argv[optind], strerror(err));
			return (1);
		}

		/*
		 * Note that we read an entire 32-bit ELF header struct
		 * here, even though we have yet to determine that the
		 * file is an ELF object or that it is ELFCLASS32. We
		 * do this because:
		 *	- Any valid ELF object of any class must
		 *		have at least this number of bytes in it,
		 *		since an ELF header is manditory, and since
		 *		a 32-bit header is smaller than a 64-bit one.
		 *	- The 32 and 64-bit ELF headers are identical
		 *		up through the e_version field, so we can
		 *		obtain the e_machine value of a 64-bit
		 *		object via the e_machine value we read into
		 *		the 32-bit version. This cannot change, because
		 *		the layout of an ELF header is fixed by the ABI.
		 *
		 * Note however that we do have to worry about the byte
		 * order difference between the object and the system
		 * running this program when we read the e_machine value,
		 * since it is a multi-byte value;
		 */
		if ((read(fd, &ehdr32, sizeof (ehdr32)) == sizeof (ehdr32)) &&
		    (ehdr32.e_ident[EI_MAG0] == ELFMAG0) &&
		    (ehdr32.e_ident[EI_MAG1] == ELFMAG1) &&
		    (ehdr32.e_ident[EI_MAG2] == ELFMAG2) &&
		    (ehdr32.e_ident[EI_MAG3] == ELFMAG3)) {
			if (aclass == ELFCLASSNONE) {
				aclass = ehdr32.e_ident[EI_CLASS];
				if ((aclass != ELFCLASS32) &&
				    (aclass != ELFCLASS64))
					aclass = ELFCLASSNONE;
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
				    (ld_elfdata == ehdr32.e_ident[EI_DATA]) ?
				    ehdr32.e_machine :
				    BSWAP_HALF(ehdr32.e_machine);
			}
		}

		(void) close(fd);
	}

	/*
	 * If we couldn't establish a class, default to 32-bit.
	 */
	if (aclass == ELFCLASSNONE)
		aclass = ELFCLASS32;
	*aoutclass = aclass;

	if (lclass == ELFCLASSNONE)
		lclass = ELFCLASS32;
	*ldclass = lclass;

	/*
	 * Use the machine type that goes with the class we've determined.
	 * If we didn't find a usable machine type, use the native
	 * machine.
	 */
	*mach = (aclass == ELFCLASS64) ? mach64 : mach32;
	if (*mach == EM_NONE)
		*mach = (aclass == ELFCLASS64) ? M_MACH_64 : M_MACH_32;

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
	 * Prevent modification of actual environment strings.
	 */
	if ((ld_options = strdup(ld_options)) == NULL) {
		err = errno;
		eprintf(0, ERR_FATAL, MSG_INTL(MSG_SYS_ALLOC), strerror(err));
		return (1);
	}

	/*
	 * Get rid of any leading white space, and make sure the environment
	 * string has size.
	 */
	while (isspace(*ld_options))
		ld_options++;
	if (*ld_options == '\0')
		return (1);

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
	uchar_t 	aoutclass, ldclass, checkclass;
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
	if (process_args(argc, argv, &aoutclass, &ldclass, &mach))
		return (1);

	/*
	 * If we're processing 64-bit objects, or the user specifically asked
	 * for a 64-bit link-editor, determine if a 64-bit ld() can be executed.
	 * Bail if a 64-bit ld() was explicitly asked for, but one could not be
	 * found.
	 */
	if ((aoutclass == ELFCLASS64) || (ldclass == ELFCLASS64))
		checkclass = conv_check_native(oargv, envp);

	if ((ldclass == ELFCLASS64) && (checkclass != ELFCLASS64)) {
		eprintf(0, ERR_FATAL, MSG_INTL(MSG_SYS_64));
		return (1);
	}

	/*
	 * Reset the getopt(3c) error message flag, and call the generic entry
	 * point using the appropriate class.
	 */
	if (aoutclass == ELFCLASS64)
		return (ld64_main(argc, argv, mach));
	else
		return (ld32_main(argc, argv, mach));
}

/*
 * Exported interfaces required by our dependencies.  libld and friends bind to
 * the different implementations of these provided by either ld or ld.so.1.
 */
const char *
_ld_msg(Msg mid)
{
	return (gettext(MSG_ORIG(mid)));
}
