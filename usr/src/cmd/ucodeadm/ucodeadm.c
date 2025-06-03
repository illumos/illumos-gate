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

/*
 * Copyright (c) 2018, Joyent, Inc.
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/processor.h>
#include <sys/sysmacros.h>
#include <sys/ucode.h>
#include <sys/ucode_intel.h>
#include <sys/ucode_amd.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include <ctype.h>
#include <assert.h>
#include <libgen.h>
#include <limits.h>
#include <locale.h>
#include <libintl.h>
#include <ucode/ucode_errno.h>
#include <ucode/ucode_utils_intel.h>
#include <ucode/ucode_utils_amd.h>

#define	UCODE_OPT_INSTALL	0x0001
#define	UCODE_OPT_UPDATE	0x0002
#define	UCODE_OPT_VERSION	0x0004
#define	UCODE_OPT_LIST		0x0008

static const char ucode_dev[] = "/dev/" UCODE_DRIVER_NAME;

static char	*cmdname;

#define	UCODE_INSTALL_COMMON_PATH ".f"

/*
 * The maximum directory path length that can be provided via -R has
 * to allow for appending the files within the microcode bundles.
 */
#define	UCODE_MAX_PATH_LEN (PATH_MAX - \
    MAX(UCODE_MAX_NAME_LEN_INTEL, UCODE_MAX_NAME_LEN_AMD) - 1)

static bool ucode_debug = false;

static int ucode_convert_amd(const char *, uint8_t *, size_t);
static int ucode_convert_intel(const char *, uint8_t *, size_t);

static ucode_errno_t ucode_gen_files_amd(uint8_t *, int, char *);
static ucode_errno_t ucode_gen_files_intel(uint8_t *, int, char *);

static void ucode_list_amd(uint8_t *, int);
static void ucode_list_intel(uint8_t *, int);

typedef struct ucode_source {
	const char	*us_prefix;
	const char	*us_vendor;
	int		(*us_convert)(const char *, uint8_t *, size_t);
	ucode_errno_t	(*us_gen_files)(uint8_t *, int, char *);
	ucode_errno_t	(*us_validate)(uint8_t *, int);
	void		(*us_list)(uint8_t *, int);
} ucode_source_t;

static const ucode_source_t ucode_sources[] = {
	{
		.us_prefix	= "intel",
		.us_vendor	= "GenuineIntel",
		.us_convert	= ucode_convert_intel,
		.us_gen_files	= ucode_gen_files_intel,
		.us_validate	= ucode_validate_intel,
		.us_list	= ucode_list_intel,
	},
	{
		.us_prefix	= "amd",
		.us_vendor	= "AuthenticAMD",
		.us_convert	= ucode_convert_amd,
		.us_gen_files	= ucode_gen_files_amd,
		.us_validate	= ucode_validate_amd,
		.us_list	= ucode_list_amd,
	},
};

const ucode_source_t *ucode;

static void
dbgprintf(const char *format, ...)
{
	if (ucode_debug) {
		va_list alist;
		va_start(alist, format);
		(void) vfprintf(stderr, format, alist);
		va_end(alist);
	}
}

static void
usage(bool verbose)
{
	(void) fprintf(stderr, gettext("usage:\n"));
	(void) fprintf(stderr, "\t%s -v\n", cmdname);
	if (verbose) {
		(void) fprintf(stderr,
		    gettext("\t\t Shows running microcode version.\n\n"));
	}

	(void) fprintf(stderr, "\t%s -u [-t type] microcode-file\n", cmdname);
	if (verbose) {
		(void) fprintf(stderr, gettext("\t\t Updates microcode to the "
		    "latest matching version found in\n"
		    "\t\t microcode-file.\n\n"));
	}

	(void) fprintf(stderr, "\t%s -l [-t type] microcode-file\n", cmdname);
	if (verbose) {
		(void) fprintf(stderr, gettext("\t\t Displays details of the "
		    "microcode file's contents.\n\n"));
	}

	(void) fprintf(stderr,
	    "\t%s -i [-t type] [-R path] microcode-file\n", cmdname);
	if (verbose) {
		(void) fprintf(stderr, gettext("\t\t Installs microcode to be "
		    "used for subsequent boots.\n"));
	}
	(void) fprintf(stderr, gettext(
	    "\nThe type of the microcode file must either be specified with "
	    "the -t option\nor microcode-file must start with the vendor name "
	    "prefix, either \"intel\"\nor \"amd\", so that the type can be "
	    "inferred from it.\n\n"));
}

static void
ucode_perror(const char *str, ucode_errno_t rc)
{
	(void) fprintf(stderr, "%s: %s: %s\n", cmdname, str,
	    errno == 0 ? ucode_strerror(rc) : strerror(errno));
	errno = 0;
}

#define	LINESIZE	120	/* copyright line sometimes is longer than 80 */

/*
 * Convert text format microcode release into binary format.
 * Return the number of characters read.
 *
 * AMD microcode is already in binary format.
 */
static int
ucode_convert_amd(const char *infile, uint8_t *buf, size_t size)
{
	int fd;

	if (infile == NULL || buf == NULL || size == 0)
		return (0);

	if ((fd = open(infile, O_RDONLY)) < 0)
		return (0);

	size = read(fd, buf, size);

	(void) close(fd);

	return (size);
}

static int
ucode_convert_intel(const char *infile, uint8_t *buf, size_t size)
{
	char	linebuf[LINESIZE];
	FILE	*infd = NULL;
	int	count = 0, firstline = 1;
	uint32_t *intbuf = (uint32_t *)(uintptr_t)buf;

	if (infile == NULL || buf == NULL || size == 0)
		return (0);

	if ((infd = fopen(infile, "r")) == NULL)
		return (0);

	while (fgets(linebuf, LINESIZE, infd)) {

		/* Check to see if we are processing a binary file */
		if (firstline && !isprint(linebuf[0])) {
			if (fseek(infd, 0, SEEK_SET) == 0)
				count = fread(buf, 1, size, infd);

			(void) fclose(infd);
			return (count);
		}

		firstline = 0;

		/* Skip blank lines */
		if (strlen(linebuf) == 1)
			continue;

		/* Skip lines with all spaces or tabs */
		if (strcspn(linebuf, " \t") == 0)
			continue;

		/* Text file.  Skip comments. */
		if (linebuf[0] == '/')
			continue;

		if (sscanf(linebuf, "%x, %x, %x, %x",
		    &intbuf[count], &intbuf[count+1],
		    &intbuf[count+2], &intbuf[count+3]) != 4)
			break;

		count += 4;
	}

	(void) fclose(infd);

	/*
	 * If we get here, we are processing a text format file
	 * where "count" is used to count the number of integers
	 * read.  Convert it to number of characters read.
	 */
	return (count * sizeof (int));
}

/*
 * Returns 0 if no need to update the link; -1 otherwise
 */
static int
ucode_should_update_intel(char *filename, uint32_t new_rev)
{
	int		fd;
	struct stat	statbuf;
	ucode_header_intel_t header;

	/*
	 * If the file or link already exists, check to see if
	 * it is necessary to update it.
	 */
	if (stat(filename, &statbuf) == 0) {
		if ((fd = open(filename, O_RDONLY)) == -1)
			return (-1);

		if (read(fd, &header, sizeof (header)) == -1) {
			(void) close(fd);
			return (-1);
		}

		(void) close(fd);

		if (header.uh_rev >= new_rev)
			return (0);
	}

	return (-1);
}

/*
 * Generate microcode binary files.  Must be called after ucode_validate().
 */
static ucode_errno_t
ucode_gen_files_amd(uint8_t *buf, int size, char *path)
{
	uint32_t *ptr = (uint32_t *)buf;
	char common_path[PATH_MAX];
	int fd, count, counter = 0;
	ucode_header_amd_t *uh;
	int last_cpu_rev = 0;

	/* write container file */
	(void) snprintf(common_path, PATH_MAX, "%s/%s", path, "container");

	dbgprintf("path = %s\n", common_path);
	fd = open(common_path, O_WRONLY | O_CREAT | O_TRUNC,
	    S_IRUSR | S_IRGRP | S_IROTH);

	if (fd == -1) {
		ucode_perror(common_path, EM_SYS);
		return (EM_SYS);
	}

	if (write(fd, buf, size) != size) {
		(void) close(fd);
		ucode_perror(common_path, EM_SYS);
		return (EM_SYS);
	}

	(void) close(fd);

	/* skip over magic number & equivalence table header */
	ptr += 2; size -= 8;

	count = *ptr++; size -= 4;

	/* equivalence table uses special name */
	(void) snprintf(common_path, PATH_MAX, "%s/%s", path,
	    UCODE_AMD_EQUIVALENCE_TABLE_NAME);

	for (;;) {
		dbgprintf("path = %s\n", common_path);
		fd = open(common_path, O_WRONLY | O_CREAT | O_TRUNC,
		    S_IRUSR | S_IRGRP | S_IROTH);

		if (fd == -1) {
			ucode_perror(common_path, EM_SYS);
			return (EM_SYS);
		}

		if (write(fd, ptr, count) != count) {
			(void) close(fd);
			ucode_perror(common_path, EM_SYS);
			return (EM_SYS);
		}

		(void) close(fd);
		ptr += count >> 2; size -= count;

		if (!size)
			return (EM_OK);

		ptr++; size -= 4;
		count = *ptr++; size -= 4;

		/* construct name from header information */
		uh = (ucode_header_amd_t *)ptr;

		if (uh->uh_cpu_rev != last_cpu_rev) {
			last_cpu_rev = uh->uh_cpu_rev;
			counter = 0;
		}

		(void) snprintf(common_path, PATH_MAX, "%s/%04X-%02X", path,
		    uh->uh_cpu_rev, counter++);
	}
}

static ucode_errno_t
ucode_gen_files_intel(uint8_t *buf, int size, char *path)
{
	int	remaining;
	char	common_path[PATH_MAX];
	DIR	*dirp;
	struct dirent *dp;

	(void) snprintf(common_path, PATH_MAX, "%s/%s", path,
	    UCODE_INSTALL_COMMON_PATH);

	if (mkdirp(common_path, 0755) == -1 && errno != EEXIST) {
		ucode_perror(common_path, EM_SYS);
		return (EM_SYS);
	}

	for (remaining = size; remaining > 0; ) {
		uint32_t	total_size, body_size, offset;
		char		firstname[PATH_MAX];
		char		name[PATH_MAX];
		int		i;
		uint8_t		*curbuf = &buf[size - remaining];
		ucode_header_intel_t	*uhp;
		ucode_ext_table_intel_t *extp;

		uhp = (ucode_header_intel_t *)(uintptr_t)curbuf;

		total_size = UCODE_TOTAL_SIZE_INTEL(uhp->uh_total_size);
		body_size = UCODE_BODY_SIZE_INTEL(uhp->uh_body_size);

		remaining -= total_size;

		(void) snprintf(firstname, PATH_MAX, "%s/%08X-%02X",
		    common_path, uhp->uh_signature, uhp->uh_proc_flags);
		dbgprintf("firstname = %s\n", firstname);

		if (ucode_should_update_intel(firstname, uhp->uh_rev) != 0) {
			int fd;

			/* Remove the existing one first */
			(void) unlink(firstname);

			if ((fd = open(firstname, O_WRONLY | O_CREAT | O_TRUNC,
			    S_IRUSR | S_IRGRP | S_IROTH)) == -1) {
				ucode_perror(firstname, EM_SYS);
				return (EM_SYS);
			}

			if (write(fd, curbuf, total_size) != total_size) {
				(void) close(fd);
				ucode_perror(firstname, EM_SYS);
				return (EM_SYS);
			}

			(void) close(fd);
		}

		/*
		 * Only 1 byte of the proc_flags field is used, therefore
		 * we only need to match 8 potential platform ids.
		 */
		for (i = 0; i < 8; i++) {
			uint32_t platid = uhp->uh_proc_flags & (1 << i);

			if (platid == 0 && uhp->uh_proc_flags != 0)
				continue;

			(void) snprintf(name, PATH_MAX,
			    "%s/%08X-%02X", path, uhp->uh_signature, platid);

			dbgprintf("proc_flags = %x, platid = %x, name = %s\n",
			    uhp->uh_proc_flags, platid, name);

			if (ucode_should_update_intel(name,
			    uhp->uh_rev) != 0) {
				/* Remove the existing one first */
				(void) unlink(name);
				if (link(firstname, name) == -1) {
					ucode_perror(name, EM_SYS);
					return (EM_SYS);
				}
			}

			if (uhp->uh_proc_flags == 0)
				break;
		}

		offset = UCODE_HEADER_SIZE_INTEL + body_size;

		/* Check to see if there is extended signature table */
		if (total_size == offset)
			continue;

		/* There is extended signature table.  More processing. */
		extp = (ucode_ext_table_intel_t *)&curbuf[offset];

		for (i = 0; i < extp->uet_count; i++) {
			ucode_ext_sig_intel_t *uesp = &extp->uet_ext_sig[i];
			int j;

			for (j = 0; j < 8; j++) {
				uint32_t id = uesp->ues_proc_flags & (1 << j);

				if (id == 0 && uesp->ues_proc_flags)
					continue;

				(void) snprintf(name, PATH_MAX,
				    "%s/%08X-%02X", path,
				    uesp->ues_signature, id);

				dbgprintf("extsig: proc_flags = %x, "
				    "platid = %x, name = %s\n",
				    uesp->ues_proc_flags, id, name);

				if (ucode_should_update_intel(name,
				    uhp->uh_rev) != 0) {
					/* Remove the existing one first */
					(void) unlink(name);
					if (link(firstname, name) == -1) {
						ucode_perror(name, EM_SYS);
						return (EM_SYS);
					}
				}

				if (uesp->ues_proc_flags == 0)
					break;
			}
		}

	}

	/*
	 * Remove files with no links to them.  These are probably
	 * obsolete microcode files.
	 */
	if ((dirp = opendir(common_path)) == NULL) {
		ucode_perror(common_path, EM_SYS);
		return (EM_SYS);
	}

	while ((dp = readdir(dirp)) != NULL) {
		char filename[PATH_MAX];
		struct stat statbuf;

		(void) snprintf(filename, PATH_MAX,
		    "%s/%s", common_path, dp->d_name);
		if (stat(filename, &statbuf) == -1)
			continue;

		if ((statbuf.st_mode & S_IFMT) == S_IFREG) {
			if (statbuf.st_nlink == 1)
				(void) unlink(filename);
		}
	}

	(void) closedir(dirp);

	return (EM_OK);
}

static void
ucode_fms(uint32_t sig, uint8_t *family, uint8_t *model, uint8_t *stepping)
{
	*family = ((sig >> 8) & 0xf) + ((sig >> 20) & 0xff);
	*model = ((sig >> 4) & 0xf) | ((sig >> 12) & 0xf0);
	*stepping = sig & 0xf;
}

static void
ucode_list_intel(uint8_t *buf, int size)
{
	int	remaining;

	printf("Microcode patches:\n");
	for (remaining = size; remaining > 0; ) {
		uint8_t *curbuf = &buf[size - remaining];
		uint8_t family, model, stepping;
		uint32_t total_size, body_size, offset;
		ucode_header_intel_t *uhp;
		ucode_ext_table_intel_t *extp;

		uhp = (ucode_header_intel_t *)(uintptr_t)curbuf;

		total_size = UCODE_TOTAL_SIZE_INTEL(uhp->uh_total_size);
		body_size = UCODE_BODY_SIZE_INTEL(uhp->uh_body_size);

		remaining -= total_size;

		ucode_fms(uhp->uh_signature, &family, &model, &stepping);

		printf(
		    "    %08lX-%02lX -> Family=%02x Model=%02x Stepping=%02x\n",
		    uhp->uh_signature, uhp->uh_proc_flags,
		    family, model, stepping);
		printf(
		    "    %14s Date=%08lX Bytes=%lu\n", "",
		    uhp->uh_date, uhp->uh_body_size);

		offset = UCODE_HEADER_SIZE_INTEL + body_size;

		/* Check to see if there is extended signature table */
		if (total_size == offset)
			continue;

		printf("Extended Signature Table:\n");

		extp = (ucode_ext_table_intel_t *)&curbuf[offset];

		for (uint32_t i = 0; i < extp->uet_count; i++) {
			ucode_ext_sig_intel_t *uesp = &extp->uet_ext_sig[i];

			ucode_fms(uesp->ues_signature,
			    &family, &model, &stepping);

			printf(
			    "    %08lX-%02lX -> Family=%02x Model=%02x "
			    "Stepping=%02x\n",
			    uesp->ues_signature, uesp->ues_proc_flags,
			    family, model, stepping);
		}
	}
}

static void
ucode_list_amd(uint8_t *buf, int size)
{
	ucode_eqtbl_amd_t *eq;
	ucode_header_amd_t *uh;
	uint32_t tsz;

	/*
	 * The file has already been validated so we can skip straight to
	 * the equivalence table.
	 */
	tsz = *(uint32_t *)(buf + 8);
	eq = (ucode_eqtbl_amd_t *)(buf + 12);
	size -= 12;

	printf("Equivalence table:\n");
	while (size >= sizeof (ucode_eqtbl_amd_t) && eq->ue_inst_cpu != 0) {
		uint8_t family, model, stepping;

		ucode_fms(eq->ue_inst_cpu, &family, &model, &stepping);

		printf(
		    "    %08lX Family=%02x Model=%02x Stepping=%02x -> %04X\n",
		    eq->ue_inst_cpu, family, model, stepping, eq->ue_equiv_cpu);
		eq++;
		size -= sizeof (*eq);
	}

	/* Move past the equivalence table terminating record */
	eq++;
	size -= sizeof (*eq);
	buf = (uint8_t *)eq;

	printf("Microcode patches:\n");
	while (size > sizeof (ucode_header_amd_t) + 8) {
		tsz = *(uint32_t *)(buf + 4);
		uh = (ucode_header_amd_t *)(buf + 8);

		if (uh->uh_cpu_rev == 0)
			break;

		printf("    %4X -> Patch=%08lX Date=%08lX Bytes=%lu\n",
		    uh->uh_cpu_rev, uh->uh_patch_id, uh->uh_date, tsz);

		buf += (tsz + 8);
		size -= (tsz + 8);
	}
}

/*
 * Returns 0 on success, 2 on usage error, and 3 on operation error.
 */
int
main(int argc, char *argv[])
{
	int	c;
	int	action = 0;
	int	actcount = 0;
	int	typeindex = -1;
	char	*path = NULL;
	char	*filename = NULL;
	int	errflg = 0;
	int	dev_fd = -1;
	int	fd = -1;
	bool	verbose = false;
	bool	needfile = false;
	uint8_t	*buf = NULL;
	ucode_errno_t	rc = EM_OK;
	processorid_t	cpuid_max;
	struct stat filestat;
	int ucode_size = 0;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	cmdname = basename(argv[0]);

	while ((c = getopt(argc, argv, "idhluvVR:t:")) != EOF) {
		switch (c) {

		case 'd':
			ucode_debug = true;
			break;

		case 'i':
			action |= UCODE_OPT_INSTALL;
			actcount++;
			needfile = true;
			break;

		case 'l':
			action |= UCODE_OPT_LIST;
			actcount++;
			needfile = true;
			break;

		case 't':
			if (typeindex != -1) {
				(void) fprintf(stderr, gettext(
				    "-t can only be specified once\n"));
				errflg++;
				break;
			}
			for (uint_t i = 0; i < ARRAY_SIZE(ucode_sources); i++) {
				if (strcmp(optarg,
				    ucode_sources[i].us_prefix) == 0) {
					typeindex = i;
					break;
				}
			}
			if (typeindex == -1) {
				(void) fprintf(stderr,
				    gettext("Unknown microcode type, %s\n"),
				    optarg);
				errflg++;
			}
			break;

		case 'u':
			action |= UCODE_OPT_UPDATE;
			actcount++;
			needfile = true;
			break;

		case 'v':
			action |= UCODE_OPT_VERSION;
			actcount++;
			break;

		case 'R':
			if (optarg[0] == '-') {
				errflg++;
			} else if (strlen(optarg) > UCODE_MAX_PATH_LEN) {
				(void) fprintf(stderr,
				    gettext("Alternate path too long\n"));
				errflg++;
			} else if ((path = strdup(optarg)) == NULL) {
				errflg++;
			}

			break;

		case 'V':
			verbose = true;
			break;

		case 'h':
			usage(true);
			return (0);

		default:
			usage(verbose);
			return (2);
		}
	}

	if (actcount == 0) {
		(void) fprintf(stderr, gettext("%s: One of -i, -l, -u or -v "
		    "must be provided.\n"), cmdname);
		usage(verbose);
		return (2);
	}

	if (actcount != 1) {
		(void) fprintf(stderr, gettext("%s: options -i, -l, -u and -v "
		    "are mutually exclusive.\n"), cmdname);
		usage(verbose);
		return (2);
	}

	if (typeindex != -1 && !needfile) {
		(void) fprintf(stderr, gettext("%s: option -t requires one of "
		    "-i, -l or -u\n"), cmdname);
		usage(verbose);
		return (2);
	}

	if (optind <= argc - 1)
		filename = argv[optind];
	else if (needfile)
		errflg++;

	if (errflg || action == 0) {
		usage(verbose);
		return (2);
	}

	/*
	 * Convert from the vendor-shipped format to individual microcode files.
	 */
	if (needfile) {
		if (typeindex != -1) {
			ucode = &ucode_sources[typeindex];
		} else {
			for (uint_t i = 0; i < ARRAY_SIZE(ucode_sources); i++) {
				const ucode_source_t *src = &ucode_sources[i];

				dbgprintf("i = %d, filestr = %s, "
				    "filename = %s\n",
				    i, src->us_prefix, filename);
				if (strncasecmp(src->us_prefix,
				    basename(filename),
				    strlen(src->us_prefix)) == 0) {
					ucode = src;
					break;
				}
			}
		}

		if (ucode == NULL) {
			rc = EM_NOVENDOR;
			(void) fprintf(stderr, "%s: %s.\n\n"
			    "Either specify the type with the -t option, "
			    "or rename the file such that\nits name begins "
			    "with a vendor string.\n",
			    cmdname, ucode_strerror(rc));
			goto out;
		}

		dbgprintf("Selected microcode type %s (%s)\n",
		    ucode->us_prefix, ucode->us_vendor);

		if ((stat(filename, &filestat)) < 0) {
			rc = EM_SYS;
			ucode_perror(filename, rc);
			goto out;
		}

		if ((filestat.st_mode & S_IFMT) != S_IFREG &&
		    (filestat.st_mode & S_IFMT) != S_IFLNK) {
			rc = EM_FILEFORMAT;
			ucode_perror(filename, rc);
			goto out;
		}

		if ((buf = malloc(filestat.st_size)) == NULL) {
			rc = EM_SYS;
			ucode_perror(filename, rc);
			goto out;
		}

		ucode_size = ucode->us_convert(filename, buf, filestat.st_size);

		dbgprintf("ucode_size = %d\n", ucode_size);

		if (ucode_size == 0) {
			rc = EM_FILEFORMAT;
			ucode_perror(filename, rc);
			goto out;
		}

		if ((rc = ucode->us_validate(buf, ucode_size)) != EM_OK) {
			ucode_perror(filename, rc);
			goto out;
		}
	}

	if (action & UCODE_OPT_LIST) {
		ucode->us_list(buf, ucode_size);
		goto out;
	}

	if (action & UCODE_OPT_INSTALL) {
		/*
		 * If no path is provided by the -R option, put the files in
		 * /platform/<arch>/ucode/<ucode_vendor_str>/.
		 */
		if (path == NULL) {
			struct utsname uts;

			if (uname(&uts) == -1) {
				perror("Unable to retrieve system uname");
				goto out;
			}

			if ((path = malloc(PATH_MAX)) == NULL) {
				rc = EM_SYS;
				ucode_perror("malloc", rc);
				goto out;
			}

			(void) snprintf(path, PATH_MAX, "/platform/%s/ucode/%s",
			    uts.machine, ucode->us_vendor);
		}

		if (mkdirp(path, 0755) == -1 && errno != EEXIST) {
			rc = EM_SYS;
			ucode_perror(path, rc);
			goto out;
		}

		rc = ucode->us_gen_files(buf, ucode_size, path);

		goto out;
	}

	if ((dev_fd = open(ucode_dev, O_RDONLY)) == -1) {
		rc = EM_SYS;
		ucode_perror(ucode_dev, rc);
		goto out;
	}

	if (action & UCODE_OPT_VERSION) {
		int tmprc;
		uint32_t *revp = NULL;
		int i;
		struct ucode_get_rev_struct info;

		cpuid_max = (processorid_t)sysconf(_SC_CPUID_MAX);

		if ((revp = (uint32_t *)
		    malloc(cpuid_max * sizeof (uint32_t))) == NULL) {
			rc = EM_SYS;
			ucode_perror("malloc", rc);
			goto out;
		}

		for (i = 0; i < cpuid_max; i++)
			revp[i] = (uint32_t)-1;

		info.ugv_rev = revp;
		info.ugv_size = cpuid_max;
		info.ugv_errno = EM_OK;
		tmprc = ioctl(dev_fd, UCODE_GET_VERSION, &info);
		rc = info.ugv_errno;

		if (tmprc && rc == EM_OK) {
			rc = EM_SYS;
		}

		if (rc == EM_OK) {
			(void) printf(gettext("CPU\tMicrocode Version\n"));
			for (i = 0; i < cpuid_max; i++) {
				if (info.ugv_rev[i] == (uint32_t)-1)
					continue;
				(void) printf("%d\t0x%x\n", i, info.ugv_rev[i]);
			}
		} else {
			ucode_perror(gettext("get microcode version"), rc);
		}

		if (revp)
			free(revp);
	}

	if (action & UCODE_OPT_UPDATE) {
		int tmprc;
		struct ucode_write_struct uw_struct;

		uw_struct.uw_size = ucode_size;
		uw_struct.uw_ucode = buf;
		uw_struct.uw_errno = EM_OK;
		tmprc = ioctl(dev_fd, UCODE_UPDATE, &uw_struct);
		rc = uw_struct.uw_errno;

		if (rc == EM_OK) {
			if (tmprc) {
				rc = EM_SYS;
				ucode_perror(ucode_dev, rc);
			}
		} else if (rc == EM_NOMATCH || rc == EM_HIGHERREV) {
			ucode_perror(filename, rc);
		} else {
			ucode_perror(gettext("microcode update"), rc);
		}
	}

out:
	if (dev_fd != -1)
		(void) close(dev_fd);

	if (fd != -1)
		(void) close(fd);

	free(buf);
	free(path);

	if (rc != EM_OK)
		return (3);

	return (0);
}
