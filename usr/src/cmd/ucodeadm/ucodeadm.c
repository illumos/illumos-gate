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
 */

#include <sys/types.h>
#include <sys/processor.h>
#include <sys/ucode.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
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
#include <locale.h>
#include <libintl.h>

#define	UCODE_OPT_INSTALL	0x0001
#define	UCODE_OPT_UPDATE	0x0002
#define	UCODE_OPT_VERSION	0x0004

static const char ucode_dev[] = "/dev/" UCODE_DRIVER_NAME;

static char	*cmdname;

static char	ucode_vendor_str[UCODE_MAX_VENDORS_NAME_LEN];
static char	ucode_install_path[] = UCODE_INSTALL_PATH;

static int	ucode_debug = 0;

static int ucode_convert_amd(const char *, uint8_t *, size_t);
static int ucode_convert_intel(const char *, uint8_t *, size_t);

static ucode_errno_t ucode_gen_files_amd(uint8_t *, int, char *);
static ucode_errno_t ucode_gen_files_intel(uint8_t *, int, char *);

static const struct ucode_ops ucode_ops[] = {
	{ ucode_convert_intel, ucode_gen_files_intel, ucode_validate_intel },
	{ ucode_convert_amd, ucode_gen_files_amd, ucode_validate_amd },
};

const struct ucode_ops *ucode;

static void
dprintf(const char *format, ...)
{
	if (ucode_debug) {
		va_list alist;
		va_start(alist, format);
		(void) vfprintf(stderr, format, alist);
		va_end(alist);
	}
}

static void
usage(int verbose)
{
	(void) fprintf(stderr, gettext("usage:\n"));
	(void) fprintf(stderr, "\t%s -v\n", cmdname);
	if (verbose) {
		(void) fprintf(stderr,
		    gettext("\t\t Shows running microcode version.\n\n"));
	}

	(void) fprintf(stderr, "\t%s -u microcode-file\n", cmdname);
	if (verbose) {
		(void) fprintf(stderr, gettext("\t\t Updates microcode to the "
		    "latest matching version found in\n"
		    "\t\t microcode-file.\n\n"));
	}

	(void) fprintf(stderr, "\t%s -i [-R path] microcode-file\n", cmdname);
	if (verbose) {
		(void) fprintf(stderr, gettext("\t\t Installs microcode to be "
		    "used for subsequent boots.\n\n"));
		(void) fprintf(stderr, gettext("Microcode file name must start "
		    "with vendor name, such as \"intel\" or \"amd\".\n\n"));
	}
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
	uint32_t *intbuf = (uint32_t *)(intptr_t)buf;

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
	/* LINTED: pointer alignment */
	uint32_t *ptr = (uint32_t *)buf;
	char common_path[PATH_MAX];
	int fd, count, counter;
	ucode_header_amd_t *uh;
	int last_cpu_rev = 0;


	/* write container file */
	(void) snprintf(common_path, PATH_MAX, "%s/%s", path, "container");

	dprintf("path = %s\n", common_path);
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
	    "equivalence-table");

	for (;;) {
		dprintf("path = %s\n", common_path);
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

		uhp = (ucode_header_intel_t *)(intptr_t)curbuf;

		total_size = UCODE_TOTAL_SIZE_INTEL(uhp->uh_total_size);
		body_size = UCODE_BODY_SIZE_INTEL(uhp->uh_body_size);

		remaining -= total_size;

		(void) snprintf(firstname, PATH_MAX, "%s/%08X-%02X",
		    common_path, uhp->uh_signature, uhp->uh_proc_flags);
		dprintf("firstname = %s\n", firstname);

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

			dprintf("proc_flags = %x, platid = %x, name = %s\n",
			    uhp->uh_proc_flags, platid, name);

			if (ucode_should_update_intel(name, uhp->uh_rev) != 0) {

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
		extp = (ucode_ext_table_intel_t *)(uintptr_t)&curbuf[offset];

		for (i = 0; i < extp->uet_count; i++) {
			ucode_ext_sig_intel_t *uesp = &extp->uet_ext_sig[i];
			int j;

			for (j = 0; j < 8; j++) {
				uint32_t id = uesp->ues_proc_flags & (1 << j);

				if (id == 0 && uesp->ues_proc_flags)
					continue;

				(void) snprintf(name, PATH_MAX,
				    "%s/%08X-%02X", path, extp->uet_ext_sig[i],
				    id);

				if (ucode_should_update_intel(name, uhp->uh_rev)
				    != 0) {

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

/*
 * Returns 0 on success, 2 on usage error, and 3 on operation error.
 */
int
main(int argc, char *argv[])
{
	int	c;
	int	action = 0;
	int	actcount = 0;
	char	*path = NULL;
	char	*filename = NULL;
	int	errflg = 0;
	int	dev_fd = -1;
	int	fd = -1;
	int	verbose = 0;
	uint8_t	*buf = NULL;
	ucode_errno_t	rc = EM_OK;
	processorid_t	cpuid_max;
	struct stat filestat;
	uint32_t ucode_size;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	cmdname = basename(argv[0]);

	while ((c = getopt(argc, argv, "idhuvVR:")) != EOF) {
		switch (c) {

		case 'i':
			action |= UCODE_OPT_INSTALL;
			actcount++;
			break;

		case 'u':
			action |= UCODE_OPT_UPDATE;
			actcount++;
			break;

		case 'v':
			action |= UCODE_OPT_VERSION;
			actcount++;
			break;

		case 'd':
			ucode_debug = 1;
			break;

		case 'R':
			if (optarg[0] == '-')
				errflg++;
			else if (strlen(optarg) > UCODE_MAX_PATH_LEN) {
				(void) fprintf(stderr,
				    gettext("Alternate path too long\n"));
				errflg++;
			} else if ((path = strdup(optarg)) == NULL) {
				errflg++;
			}

			break;

		case 'V':
			verbose = 1;
			break;

		case 'h':
			usage(1);
			return (0);

		default:
			usage(verbose);
			return (2);
		}
	}

	if (actcount != 1) {
		(void) fprintf(stderr, gettext("%s: options -v, -i and -u "
		    "are mutually exclusive.\n"), cmdname);
		usage(verbose);
		return (2);
	}

	if (optind <= argc - 1)
		filename = argv[optind];
	else if (!(action & UCODE_OPT_VERSION))
		errflg++;

	if (errflg || action == 0) {
		usage(verbose);
		return (2);
	}

	/*
	 * Convert from text format to binary format
	 */
	if ((action & UCODE_OPT_INSTALL) || (action & UCODE_OPT_UPDATE)) {
		int i;
		UCODE_VENDORS;

		for (i = 0; ucode_vendors[i].filestr != NULL; i++) {
			dprintf("i = %d, filestr = %s, filename = %s\n",
			    i, ucode_vendors[i].filestr, filename);
			if (strncasecmp(ucode_vendors[i].filestr,
			    basename(filename),
			    strlen(ucode_vendors[i].filestr)) == 0) {
				ucode = &ucode_ops[i];
				(void) strncpy(ucode_vendor_str,
				    ucode_vendors[i].vendorstr,
				    sizeof (ucode_vendor_str));
				break;
			}
		}

		if (ucode_vendors[i].filestr == NULL) {
			rc = EM_NOVENDOR;
			ucode_perror(basename(filename), rc);
			goto err_out;
		}

		if ((stat(filename, &filestat)) < 0) {
			rc = EM_SYS;
			ucode_perror(filename, rc);
			goto err_out;
		}

		if ((filestat.st_mode & S_IFMT) != S_IFREG &&
		    (filestat.st_mode & S_IFMT) != S_IFLNK) {
			rc = EM_FILEFORMAT;
			ucode_perror(filename, rc);
			goto err_out;
		}

		if ((buf = malloc(filestat.st_size)) == NULL) {
			rc = EM_SYS;
			ucode_perror(filename, rc);
			goto err_out;
		}

		ucode_size = ucode->convert(filename, buf, filestat.st_size);

		dprintf("ucode_size = %d\n", ucode_size);

		if (ucode_size == 0) {
			rc = EM_FILEFORMAT;
			ucode_perror(filename, rc);
			goto err_out;
		}

		if ((rc = ucode->validate(buf, ucode_size)) != EM_OK) {
			ucode_perror(filename, rc);
			goto err_out;
		}
	}

	/*
	 * For the install option, the microcode file must start with
	 * "intel" for Intel microcode, and "amd" for AMD microcode.
	 */
	if (action & UCODE_OPT_INSTALL) {
		/*
		 * If no path is provided by the -R option, put the files in
		 * /ucode_install_path/ucode_vendor_str/.
		 */
		if (path == NULL) {
			if ((path = malloc(PATH_MAX)) == NULL) {
				rc = EM_SYS;
				ucode_perror("malloc", rc);
				goto err_out;
			}

			(void) snprintf(path, PATH_MAX, "/%s/%s",
			    ucode_install_path, ucode_vendor_str);
		}

		if (mkdirp(path, 0755) == -1 && errno != EEXIST) {
			rc = EM_SYS;
			ucode_perror(path, rc);
			goto err_out;
		}

		rc = ucode->gen_files(buf, ucode_size, path);

		goto err_out;
	}

	if ((dev_fd = open(ucode_dev, O_RDONLY)) == -1) {
		rc = EM_SYS;
		ucode_perror(ucode_dev, rc);
		goto err_out;
	}

	if (action & UCODE_OPT_VERSION) {
		int tmprc;
		uint32_t *revp = NULL;
		int i;
#if defined(_SYSCALL32_IMPL)
		struct ucode_get_rev_struct32 inf32;
#else
		struct ucode_get_rev_struct info;
#endif

		cpuid_max = (processorid_t)sysconf(_SC_CPUID_MAX);

		if ((revp = (uint32_t *)
		    malloc(cpuid_max * sizeof (uint32_t))) == NULL) {
			rc = EM_SYS;
			ucode_perror("malloc", rc);
			goto err_out;
		}

		for (i = 0; i < cpuid_max; i++)
			revp[i] = (uint32_t)-1;

#if defined(_SYSCALL32_IMPL)
		info32.ugv_rev = (caddr32_t)revp;
		info32.ugv_size = cpuid_max;
		info32.ugv_errno = EM_OK;
		tmprc = ioctl(dev_fd, UCODE_GET_VERSION, &info32);
		rc = info32.ugv_errno;
#else
		info.ugv_rev = revp;
		info.ugv_size = cpuid_max;
		info.ugv_errno = EM_OK;
		tmprc = ioctl(dev_fd, UCODE_GET_VERSION, &info);
		rc = info.ugv_errno;
#endif

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
#if defined(_SYSCALL32_IMPL)
		struct ucode_write_struct32 uw_struct32;
#else
		struct ucode_write_struct uw_struct;
#endif

#if defined(_SYSCALL32_IMPL)
		uw_struct32.uw_size = ucode_size;
		uw_struct32.uw_ucode = (caddr32_t)buf;
		uw_struct32.uw_errno = EM_OK;
		tmprc = ioctl(dev_fd, UCODE_UPDATE, &uw_struct32);
		rc = uw_struct32.uw_errno;

#else
		uw_struct.uw_size = ucode_size;
		uw_struct.uw_ucode = buf;
		uw_struct.uw_errno = EM_OK;
		tmprc = ioctl(dev_fd, UCODE_UPDATE, &uw_struct);
		rc = uw_struct.uw_errno;
#endif

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

err_out:
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
