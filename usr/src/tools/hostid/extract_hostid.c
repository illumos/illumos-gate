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
 *
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <locale.h>
#include <ctype.h>
#include <string.h>
#include <elf.h>

/*
 * These definitions historically lived in usr/src/uts/common/io/sysinit.c
 * in the ON consolidation.  They were used to generate the old style
 * hostid that was patched into the sysinit module by install.  They
 * are reproduced here so that we can read existing hostids from old
 * sysinit modules.
 */

#define	V1	0x38d4419a
#define	V1_K1	0x7a5fd043
#define	V1_K2	0x65cb612e


#define	A	16807
#define	M	2147483647
#define	Q	127773
#define	R	2836
#define	x() if ((s = ((A * (s % Q)) - (R * (s/Q)))) <= 0) s += M

static int32_t t[3] = {V1, V1_K1, V1_K2 };

/*
 * Private function prototypes
 */
static void Usage();
static int get_serial32(int fd, int32_t *value1, int32_t *value2);
static int get_serial64(int fd, int32_t *value1, int32_t *value2);

/*
 * extract_hostid - transitional utility designed to pull the existing
 * hostid value out of a sysinit module and write it to stdout.  Most
 * likely useful for use with bfu, when moving from old style hostid
 * to new style hostid on non-sparc
 */
int
main(int argc, char *argv[])
{
	Elf32_Ehdr Ehdr;
	int fd;
	int rc = 0;
	off_t offset;
	int opt;
	int32_t s, value1, value2;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((opt = getopt(argc, argv, "h")) != EOF) {
		switch (opt) {
		case 'h':
			Usage();
			break;

		default:
			Usage();
		}
	}

	if (argv[optind] == NULL)
		return (0);

	/* open the module file */
	if ((fd = open(argv[optind], O_RDWR)) < 0) {
		perror(argv[optind]);
		return (rc);
	}

	/* read the elf header */
	offset = 0;
	if (pread(fd, &Ehdr, sizeof (Ehdr), offset) < 0) {
		perror(argv[optind]);
		(void) close(fd);
		return (rc);
	}

	/* figure out if 32 or 64 bit */
	if (Ehdr.e_ident[EI_CLASS] == ELFCLASS32)
		rc = get_serial32(fd, &value1, &value2);
	else
		rc = get_serial64(fd, &value1, &value2);

	if (rc < 0) {
		(void) close(fd);
		return (rc);
	}

	s = value1;
	x();
	if (value2 == s) {
		x();
		s %= 1000000000;
	} else
		s = 0;

	(void) printf("%08lx\n", (unsigned long)s);

	(void) close(fd);
	return (rc);
}

static int
get_serial32(int fd, int32_t *value1, int32_t *value2)
{
	Elf32_Ehdr Ehdr;
	Elf32_Shdr Shdr;
	int rc;
	char name[6];
	off_t offset;
	off_t shstrtab_offset;
	off_t data_offset;
	int i;

	rc = -1;	/* assume module doesn't exist */

	/* read the elf header */
	offset = 0;
	if (pread(fd, &Ehdr, sizeof (Ehdr), offset) < 0) {
		goto out;
	}

	/* read the section header for the section string table */
	offset = Ehdr.e_shoff + (Ehdr.e_shstrndx * Ehdr.e_shentsize);
	if (pread(fd, &Shdr, sizeof (Shdr), offset) < 0) {
		goto out;
	}

	/* save the offset of the section string table */
	shstrtab_offset = Shdr.sh_offset;

	/* find the .data section header */
	/*CSTYLED*/
	for (i = 1; ; ) {
		offset = Ehdr.e_shoff + (i * Ehdr.e_shentsize);
		if (pread(fd, &Shdr, sizeof (Shdr), offset) < 0) {
			goto out;
		}
		offset = shstrtab_offset + Shdr.sh_name;
		if (pread(fd, name, sizeof (name), offset) < 0) {
			goto out;
		}
		if (strcmp(name, ".data") == 0)
			break;
		if (++i >= (int)Ehdr.e_shnum) {
			/* reached end of table */
			goto out;
		}
	}

	/* save the offset of the data section */
	data_offset = Shdr.sh_offset;

	/* read and check the version number and initial seed values */
	offset = data_offset;
	if (pread(fd, &t[0], sizeof (t[0]) * 3, offset) < 0) {
		goto out;
	}

	*value1 = t[1];
	*value2 = t[2];
	rc = 0;

out:	return (rc);
}

static int
get_serial64(int fd, int32_t *value1, int32_t *value2)
{
	Elf64_Ehdr Ehdr;
	Elf64_Shdr Shdr;
	int rc;
	char name[6];
	off_t offset;
	off_t shstrtab_offset;
	off_t data_offset;
	int i;

	rc = -1;	/* assume module doesn't exist */

	/* read the elf header */
	offset = 0;
	if (pread(fd, &Ehdr, sizeof (Ehdr), offset) < 0) {
		goto out;
	}

	/* read the section header for the section string table */
	offset = Ehdr.e_shoff + (Ehdr.e_shstrndx * Ehdr.e_shentsize);
	if (pread(fd, &Shdr, sizeof (Shdr), offset) < 0) {
		goto out;
	}

	/* save the offset of the section string table */
	shstrtab_offset = Shdr.sh_offset;

	/* find the .data section header */
	/*CSTYLED*/
	for (i = 1; ; ) {
		offset = Ehdr.e_shoff + (i * Ehdr.e_shentsize);
		if (pread(fd, &Shdr, sizeof (Shdr), offset) < 0) {
			goto out;
		}
		offset = shstrtab_offset + Shdr.sh_name;
		if (pread(fd, name, sizeof (name), offset) < 0) {
			goto out;
		}
		if (strcmp(name, ".data") == 0)
			break;
		if (++i >= (int)Ehdr.e_shnum) {
			/* reached end of table */
			goto out;
		}
	}

	/* save the offset of the data section */
	data_offset = Shdr.sh_offset;

	/* read and check the version number and initial seed values */
	offset = data_offset;
	if (pread(fd, &t[0], sizeof (t[0]) * 3, offset) < 0) {
		goto out;
	}

	*value1 = t[1];
	*value2 = t[2];
	rc = 0;

out:	return (rc);
}

static void
Usage()
{
	(void) printf(gettext("usage: extract_hostid [-h] filename\n"));
	exit(1);
}
