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

#include	<sys/types.h>
#include	<sys/stat.h>
#include	<fcntl.h>
#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
#include	<locale.h>
#include	<dlfcn.h>
#include	<errno.h>
#include	"_crle.h"
#include	"conv.h"
#include	"msg.h"


/*
 * crle(1) entry point and argument processing.
 *
 * Two passes of the arguments are carried out; the first collects any single
 * instance options and establishes defaults that might be appropriate for
 * other arguments:
 *
 *  -64		operate on, or apply, 64-bit objects (default is 32-bit).
 *
 *  -c file	defines the output configuration file.
 *
 *  -f flag	flags for dldump(3C).
 *
 *  -o dir	defines the output directory for any dldump(3C) objects
 *		that follow.  For backward compatibility (RTC_VER_ONE only
 *		allowed one output directory) allow the first occurrence of this
 *		specification to catch any previous files.  If not specified,
 *		the configuration files parent directory is used).
 *
 *  -u		update any existing configuration file.  Any additional
 *		arguments supplied will be added to the new configuration
 *		information.
 *
 *  -v		verbose mode.
 *
 * The second pass collects all other options and constructs an internal
 * string table which will be used to create the eventual configuration file.
 *
 *  -a name	add the individual name, with an alternative to the
 *		configuration cache.  No alternative is created via dldump(3C),
 *		it is the users responsibility to furnish the alternative.
 *
 *  -A name	add the individual name, with an optional alternative to the
 *		configuration cache.  No alternative is created via dldump(3C),
 *		it is the users responsibility to furnish the alternative.
 *
 *  -e envar	replaceable environment variable
 *
 *  -E envar	permanent environment variable
 *
 *  -i name	add the individual name to the configuration cache.  If name
 *		is a directory each shared object within the directory is added
 *		to the cache.
 *
 *  -I name	same as -i, but in addition any ELF objects are dldump(3C)'ed.
 *
 *  -g name	add the group name to the configuration cache.  Each object is
 *		expanded to determine its dependencies and these are added to
 *		the cache.  If name is a directory each shared object within the
 *		directory and its dependencies are added to the cache.
 *
 *  -G app	same as -g, but in addition any ELF objects are dldump(3C)'ed.
 *
 *  -l dir	library search directory
 *
 *  -s dir	trusted (secure) directory
 */

/*
 * Establish a structure for maintaining current object directory attributes.
 * We wish to validate the access of any object directory that will be written
 * to dldump(3C), and thus by maintaining a current object directory and its
 * intended use we can perform this validation later.
 */
typedef struct {
	char	*o_objdir;
	uint_t	o_flags;
} Objdir;

/*ARGSUSED2*/
int
main(int argc, char **argv, char **envp)
{
	Crle_desc	crle = { 0 };
	int		c, error = 0;
	char		**lib;
	Alist		*objdirs = NULL;
	Objdir		*objdir, *iobjdir;
	struct stat	ostatus, nstatus;
	int		c_class;

	if ((objdir = iobjdir = alist_append(&objdirs, NULL, sizeof (Objdir),
	    AL_CNT_CRLE)) == NULL)
		return (1);

	/*
	 * Establish locale.
	 */
	(void) setlocale(LC_MESSAGES, MSG_ORIG(MSG_STR_EMPTY));
	(void) textdomain(MSG_ORIG(MSG_SUNW_OST_SGS));

	/*
	 * Initialization configuration information.
	 */
	crle.c_name = argv[0];
	crle.c_flags |= CRLE_ADDID;
	crle.c_strbkts = 503;
	crle.c_inobkts = 251;
	c_class = M_CLASS;

	/*
	 * First argument pass.
	 */
	while ((c = getopt(argc, argv, MSG_ORIG(MSG_ARG_OPTIONS))) != -1) {
		switch (c) {

		case '6':			/* operate on 64-bit objects */
			if (optarg[0] != '4') {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ARG_ILLEGAL), crle.c_name,
				    MSG_ORIG(MSG_ARG_6), optarg);
				error = 1;
			}

			c_class = ELFCLASS64;
			break;

		case 'A':			/* create optional */
			/* FALLTHROUGH */	/*	alternative */
		case 'a':			/* create alternative */
			crle.c_flags |= (CRLE_CREAT | CRLE_ALTER);
			objdir->o_flags |= (CRLE_CREAT | CRLE_ALTER);
			break;

		case 'c':			/* define the config file */
			if (crle.c_confil) {
				(void) fprintf(stderr, MSG_INTL(MSG_ARG_MULT),
				    crle.c_name, MSG_ORIG(MSG_ARG_C));
				error = 1;
			}
			crle.c_confil = optarg;
			break;

		case 'e':			/* replaceable env variable */
			crle.c_flags |= (CRLE_RPLENV | CRLE_CREAT);
			break;

		case 'E':			/* permanent env variable */
			crle.c_flags |= (CRLE_PRMENV | CRLE_CREAT);
			break;

		case 'f':			/* dldump(3C) flags */
			if (crle.c_dlflags) {
				(void) fprintf(stderr, MSG_INTL(MSG_ARG_MULT),
				    crle.c_name, MSG_ORIG(MSG_ARG_F));
				error = 1;
			}
			if ((crle.c_dlflags = dlflags(&crle,
			    (const char *)optarg)) == 0)
				error = 1;
			break;

		case 'G':			/* group object */
			crle.c_flags |= (CRLE_DUMP | CRLE_ALTER);
			objdir->o_flags |= (CRLE_DUMP | CRLE_ALTER);
			/* FALLTHROUGH */
		case 'g':
			crle.c_flags |= CRLE_CREAT;
			objdir->o_flags |= CRLE_CREAT;
			break;

		case 'I':			/* individual object */
			crle.c_flags |= (CRLE_DUMP | CRLE_ALTER);
			objdir->o_flags |= (CRLE_DUMP | CRLE_ALTER);
			/* FALLTHROUGH */
		case 'i':
			crle.c_flags |= CRLE_CREAT;
			objdir->o_flags |= CRLE_CREAT;
			break;

		case 'l':			/* library search path */
			crle.c_flags |= (CRLE_EDLIB | CRLE_CREAT);
			break;

		case 'o':			/* define an object directory */
			if (objdir->o_objdir) {
				if ((objdir = alist_append(&objdirs, NULL,
				    sizeof (Objdir), AL_CNT_CRLE)) == NULL)
					return (1);
			}
			objdir->o_objdir = optarg;
			break;

		case 's':			/* trusted (secure) path */
			crle.c_flags |= (CRLE_ESLIB | CRLE_CREAT);
			break;

		/*
		 * Search path type, undocumented but left for compatibility.
		 * Previously used to select between AOUT and ELF, now
		 * anything other than ELF is an error.
		 */
		case 't':
			if (strcmp((const char *)optarg,
			    MSG_ORIG(MSG_STR_ELF)) != 0) {
				(void) fprintf(stderr, MSG_INTL(MSG_ARG_TYPE),
				    crle.c_name, optarg);
				error = 1;
			}
			break;

		case 'u':			/* update mode */
			crle.c_flags |= (CRLE_CREAT | CRLE_UPDATE);
			break;

		case 'v':			/* verbose mode */
			crle.c_flags |= CRLE_VERBOSE;
			break;

		default:
			error = 2;
		}
	}

	if (optind != argc)
		error = 2;

	/*
	 * Determine the configuration file, which in the case of an existing
	 * error condition is required in the final error message.
	 */
	if (crle.c_confil == NULL) {
		crle.c_flags |= CRLE_CONFDEF;
		if (c_class == ELFCLASS32) {
			crle.c_confil = (char *)MSG_ORIG(MSG_PTH_CONFIG);
		} else {
			crle.c_confil = (char *)MSG_ORIG(MSG_PTH_CONFIG_64);
		}
	}

	/*
	 * Now that we've generated as many file/directory processing errors
	 * as we can, return if any fatal error conditions occurred.
	 */
	if (error) {
		if (error == 2) {
			(void) fprintf(stderr, MSG_INTL(MSG_ARG_USAGE),
			    crle.c_name);
		} else if (crle.c_flags & CRLE_CREAT) {
			(void) fprintf(stderr, MSG_INTL(MSG_GEN_CREATE),
			    crle.c_name, crle.c_confil);
		}
		return (1);
	}

	/*
	 * Apply any additional defaults.
	 */
	if (crle.c_dlflags == 0)
		crle.c_dlflags = RTLD_REL_RELATIVE;

	crle.c_audit = (char *)MSG_ORIG(MSG_ENV_LD_AUDIT);

	(void) elf_version(EV_CURRENT);

	/*
	 * If we're updating an existing file or not creating a configuration
	 * file at all, investigate the original.
	 */
	if ((crle.c_flags & CRLE_UPDATE) ||
	    ((crle.c_flags & CRLE_CREAT) == 0)) {
		switch (inspectconfig(&crle, c_class)) {
		case INSCFG_RET_OK:
			if ((crle.c_flags & CRLE_UPDATE) == 0)
				return (0);
			break;
		case INSCFG_RET_FAIL:
			return (1);
		case INSCFG_RET_NEED64:
			c_class = ELFCLASS64;
			break;
		}
	}

	/*
	 * Ensure that the right version (32 or 64-bit) of this program
	 * is running. The 32 and 64-bit compilers may align fields within
	 * structures differently. Using the right version of crle for
	 * the config file ensures that all linker components will see
	 * the same layout, without the need for special code.
	 */
#ifdef _ELF64
	if (c_class == ELFCLASS32) {
		(void) fprintf(stderr, MSG_INTL(MSG_ARG_CLASS),
		    crle.c_name, crle.c_confil);
		return (1);
	}
#else
	if (c_class == ELFCLASS64) {
		(void) conv_check_native(argv, envp);

		/*
		 * conv_check_native() should not return, as we expect
		 * the 64-bit version to have executed on top of us.
		 * If it does, it means there is no 64-bit support
		 * available on this system.
		 */
		(void) fprintf(stderr, MSG_INTL(MSG_ISA32_NO64SUP),
		    crle.c_name);
		return (1);
	}
#endif

	if (crle.c_flags & CRLE_VERBOSE)
		(void) printf(MSG_INTL(MSG_DIA_CONFILE), crle.c_confil);

	/*
	 * Make sure the configuration file is accessible.  Stat the file to
	 * determine its dev number - this is used to determine whether the
	 * temporary configuration file we're about to build can be renamed or
	 * must be copied to its final destination.
	 */
	(void) umask(022);
	if (access(crle.c_confil, (R_OK | W_OK)) == 0) {
		crle.c_flags |= CRLE_EXISTS;

		if (stat(crle.c_confil, &ostatus) != 0) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN),
			    crle.c_name, crle.c_confil, strerror(err));
			return (1);
		}
	} else if (errno != ENOENT) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_ACCESS), crle.c_name,
		    crle.c_confil, strerror(err));
		return (1);
	} else {
		int	fd;

		/*
		 * Try opening the file now, if it works delete it, there may
		 * be a lot of processing ahead of us, so we'll come back and
		 * create the real thing later.
		 */
		if ((fd = open(crle.c_confil, (O_RDWR | O_CREAT | O_TRUNC),
		    0666)) == -1) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN),
			    crle.c_name, crle.c_confil, strerror(err));
			return (1);
		}
		if (fstat(fd, &ostatus) != 0) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN),
			    crle.c_name, crle.c_confil, strerror(err));
			return (1);
		}
		(void) close(fd);
		(void) unlink(crle.c_confil);
	}

	/*
	 * If an object directory is required to hold dldump(3C) output assign
	 * a default if necessary and insure we're able to write there.
	 */
	if (crle.c_flags & CRLE_ALTER) {
		if (objdir->o_objdir == NULL) {
			char	*str;

			/*
			 * Use the configuration files directory.
			 */
			if ((str = strrchr(crle.c_confil, '/')) == NULL)
				objdir->o_objdir =
				    (char *)MSG_ORIG(MSG_DIR_DOT);
			else {
				int	len = str - crle.c_confil;

				if ((objdir->o_objdir =
				    malloc(len + 1)) == NULL) {
					int err = errno;
					(void) fprintf(stderr,
					    MSG_INTL(MSG_SYS_MALLOC),
					    crle.c_name, strerror(err));
					return (1);
				}
				(void) strncpy(objdir->o_objdir,
				    crle.c_confil, len);
				objdir->o_objdir[len] = '\0';
			}
		}

		/*
		 * If we're going to dldump(3C) images ourself make sure we
		 * can access any directories.
		 */
		if (crle.c_flags & CRLE_DUMP) {
			Objdir	*objdir = NULL;
			Aliste	idx;
			int	err = 0;

			for (ALIST_TRAVERSE(objdirs, idx, objdir)) {
				if (crle.c_flags & CRLE_VERBOSE)
					(void) printf(MSG_INTL(MSG_DIA_OBJDIR),
					    objdir->o_objdir);

				if ((objdir->o_flags & CRLE_DUMP) == 0)
					continue;

				if (access(objdir->o_objdir,
				    (R_OK | W_OK)) != 0) {
					err = errno;
					(void) fprintf(stderr,
					    MSG_INTL(MSG_SYS_ACCESS),
					    crle.c_name, objdir->o_objdir,
					    strerror(err));
				}
			}
			if (err)
				return (1);
		}
	}

	/*
	 * Establish any initial object directory.
	 */
	crle.c_objdir = iobjdir->o_objdir;

	/*
	 * Create a temporary file name in which to build the configuration
	 * information.
	 */
	if ((crle.c_tempname = tempnam(MSG_ORIG(MSG_TMP_DIR),
	    MSG_ORIG(MSG_TMP_PFX))) == NULL) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_TEMPNAME),
		    crle.c_name, strerror(err));
		return (1);
	}
	if ((crle.c_tempfd = open(crle.c_tempname, (O_RDWR | O_CREAT),
	    0666)) == -1) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN),
		    crle.c_name, crle.c_tempname, strerror(err));
		return (1);
	}
	if (stat(crle.c_tempname, &nstatus) != 0) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN),
		    crle.c_name, crle.c_tempname, strerror(err));
		return (1);
	}
	if (ostatus.st_dev != nstatus.st_dev)
		crle.c_flags |= CRLE_DIFFDEV;

	/*
	 * Second pass.
	 */
	error = 0;
	optind = 1;
	while ((c = getopt(argc, argv, MSG_ORIG(MSG_ARG_OPTIONS))) != -1) {
		const char	*str;
		int		flag = 0;

		switch (c) {

		case '6':
			break;

		case 'A':			/* alternative is optional */
			flag = RTC_OBJ_OPTINAL;
			/* FALLTHROUGH */
		case 'a':			/* alternative required */
			flag |= (RTC_OBJ_ALTER | RTC_OBJ_CMDLINE);
			if (inspect(&crle, (const char *)optarg, flag) != 0)
				error = 1;
			break;

		case 'c':
			break;

		case 'e':
			if ((flag = addenv(&crle, (const char *)optarg,
			    RTC_ENV_REPLACE)) == 0)
				error = 1;
			else if ((crle.c_flags & CRLE_VERBOSE) && (flag == 1))
				(void) printf(MSG_INTL(MSG_DIA_RPLENV),
				    (const char *)optarg);
			break;

		case 'E':
			if ((flag = addenv(&crle, (const char *)optarg,
			    RTC_ENV_PERMANT)) == 0)
				error = 1;
			else if ((crle.c_flags & CRLE_VERBOSE) && (flag == 1))
				(void) printf(MSG_INTL(MSG_DIA_PRMENV),
				    (const char *)optarg);
			break;

		case 'f':
			break;

		case 'G':			/* group object */
			flag = (RTC_OBJ_DUMP | RTC_OBJ_ALTER);
			/* FALLTHROUGH */
		case 'g':
			flag |= (RTC_OBJ_GROUP | RTC_OBJ_CMDLINE);
			if (inspect(&crle, (const char *)optarg, flag) != 0)
				error = 1;
			break;

		case 'I':			/* individual object */
			flag = (RTC_OBJ_DUMP | RTC_OBJ_ALTER);
			/* FALLTHROUGH */
		case 'i':
			flag |= RTC_OBJ_CMDLINE;
			if (inspect(&crle, (const char *)optarg, flag) != 0)
				error = 1;
			break;

		case 'l':			/* library search path */
			str = MSG_ORIG(MSG_STR_ELF);
			lib = &crle.c_edlibpath;
			if (addlib(&crle, lib, (const char *)optarg) != 0)
				error = 1;
			else if (crle.c_flags & CRLE_VERBOSE)
				(void) printf(MSG_INTL(MSG_DIA_DLIBPTH),
				    str, (const char *)optarg);
			break;

		case 'o':
			crle.c_objdir = optarg;
			break;

		case 's':			/* trusted (secure) path */
			str = MSG_ORIG(MSG_STR_ELF);
			lib = &crle.c_eslibpath;
			if (addlib(&crle, lib, (const char *)optarg) != 0)
				error = 1;
			else if (crle.c_flags & CRLE_VERBOSE)
				(void) printf(MSG_INTL(MSG_DIA_TLIBPTH),
				    str, (const char *)optarg);
			break;

		case 't':
			break;

		case 'u':
			break;

		case 'v':
			break;
		}
	}

	/*
	 * Now that we've generated as many file/directory processing errors
	 * as we can, return if any fatal error conditions occurred.
	 */
	if (error) {
		(void) unlink(crle.c_tempname);
		if (crle.c_flags & CRLE_CREAT) {
			(void) fprintf(stderr, MSG_INTL(MSG_GEN_CREATE),
			    crle.c_name, crle.c_confil);
		}
		return (1);
	}

	/*
	 * Create a temporary configuration file.
	 */
	if (genconfig(&crle) != 0) {
		(void) unlink(crle.c_tempname);
		return (1);
	}

	/*
	 * If dldump(3C) images are required spawn a process to create them.
	 */
	if (crle.c_flags & CRLE_DUMP) {
		if (dump(&crle) != 0) {
			(void) unlink(crle.c_tempname);
			return (1);
		}
	}

	/*
	 * Copy the finished temporary configuration file to its final home.
	 */
	if (updateconfig(&crle) != 0)
		return (1);

	return (0);
}
