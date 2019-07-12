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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/systeminfo.h>
#include <sys/utsname.h>
#include <sys/stat.h>

#include <sys/auxv.h>
#include <sys/cpuid_drv.h>
#include <sys/elf.h>

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <libintl.h>
#include <locale.h>
#include <fcntl.h>

#include <elfcap.h>

static const char dev_cpu_self_cpuid[] = "/dev/" CPUID_SELF_NAME;
static char *pgmname;
static int mode = 0;

#define	BITS_MODE	0x1
#define	NATIVE_MODE	0x2
#define	KERN_MODE	0x4
#define	VERBOSE_MODE	0x8
#define	EXTN_MODE	0x10

static char *
getsysinfo(int cmd)
{
	char *buf;
	size_t bufsize = 20;	/* wild guess */
	long ret;

	if ((buf = malloc(bufsize)) == NULL)
		return (NULL);
	do {
		ret = sysinfo(cmd, buf, bufsize);
		if (ret == -1)
			return (NULL);
		if (ret > bufsize) {
			bufsize = ret;
			buf = realloc(buf, bufsize);
		} else
			break;
	} while (buf != NULL);

	return (buf);
}

/*
 * Classify isa's as to bitness of the corresponding ABIs.
 * isa's which have no "official" Solaris ABI are returned
 * unrecognised i.e. "zero bit".
 */
static uint_t
bitness(const char *isaname)
{
	if (strcmp(isaname, "sparc") == 0 ||
	    strcmp(isaname, "i386") == 0)
		return (32);

	if (strcmp(isaname, "sparcv9") == 0 ||
	    strcmp(isaname, "amd64") == 0)
		return (64);

	return (0);
}

static char *
report_abi(int cmd, const char *vfmt)
{
	uint_t bits;
	char *isa;

	if ((isa = getsysinfo(cmd)) == NULL)
		return (0);
	if ((bits = bitness(isa)) == 0) {
		(void) fprintf(stderr,
		    gettext("%s: unable to identify isa '%s'!\n"),
		    pgmname, isa);
		exit(3);
	}

	if (mode & VERBOSE_MODE)
		(void) printf(vfmt, bits, isa);
	else if (mode & BITS_MODE)
		(void) printf("%d\n", bits);
	else if (mode & (NATIVE_MODE|KERN_MODE))
		(void) printf("%s\n", isa);
	else
		(void) printf("%s", isa);
	return (isa);
}

/*
 * Classify isas as their machine type.
 */
static ushort_t
machtype(const char *isaname)
{
	if (strcmp(isaname, "sparc") == 0)
		return (EM_SPARC);
	if (strcmp(isaname, "sparcv9") == 0)
		return (EM_SPARCV9);
	if (strcmp(isaname, "i386") == 0)
		return (EM_386);
	if (strcmp(isaname, "amd64") == 0)
		return (EM_AMD64);

	return (0);
}

static void
report_hwcap(int d, const char *isa)
{
	struct cpuid_get_hwcap __cgh, *cgh = &__cgh;
	char buffer[1024], cap2[1024];

	cgh->cgh_archname = (char *)isa;
	if (ioctl(d, CPUID_GET_HWCAP, cgh) != 0)
		return;

	(void) elfcap_hw1_to_str(ELFCAP_STYLE_LC, cgh->cgh_hwcap[0],
	    buffer, sizeof (buffer), ELFCAP_FMT_SNGSPACE, machtype(isa));

	if (cgh->cgh_hwcap[1] != 0)
		(void) elfcap_hw2_to_str(ELFCAP_STYLE_LC, cgh->cgh_hwcap[1],
		    cap2, sizeof (cap2), ELFCAP_FMT_SNGSPACE, machtype(isa));
	else
		cap2[0] = '\0';

	if (mode & EXTN_MODE) {
		(void) printf(":");
		if (cgh->cgh_hwcap[1] != 0)
			(void) printf(" %s", cap2);
		(void) printf(" %s", buffer);
		(void) printf("\n");
	} else {
		char *p;
		int linecnt = 0;

		for (p = strtok(cap2, " "); p; p = strtok(NULL, " ")) {
			if (linecnt + strlen(p) > 68) {
				(void) printf("\n");
				linecnt = 0;
			}
			if (linecnt == 0)
				linecnt = printf("\t");
			linecnt += printf("%s ", p);
		}

		for (p = strtok(buffer, " "); p; p = strtok(NULL, " ")) {
			if (linecnt + strlen(p) > 68) {
				(void) printf("\n");
				linecnt = 0;
			}
			if (linecnt == 0)
				linecnt = printf("\t");
			linecnt += printf("%s ", p);
		}

		if (linecnt != 0)
			(void) printf("\n");
	}
}

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

int
main(int argc, char *argv[])
{
	int errflg = 0;
	int c;
	char *vfmt;
	char *isa, *isa32;
	int d = -1;
	const int excl_modes =	/* exclusive mode settings */
	    NATIVE_MODE | BITS_MODE | KERN_MODE | EXTN_MODE;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if ((pgmname = strrchr(*argv, '/')) == 0)
		pgmname = argv[0];
	else
		pgmname++;

	while ((c = getopt(argc, argv, "nbkvx")) != EOF)
		switch (c) {
		case 'n':
			if (mode & excl_modes)
				errflg++;
			mode |= NATIVE_MODE;
			break;
		case 'b':
			if (mode & excl_modes)
				errflg++;
			mode |= BITS_MODE;
			break;
		case 'k':
			if (mode & excl_modes)
				errflg++;
			mode |= KERN_MODE;
			break;
		case 'x':
			if (mode & excl_modes || mode & VERBOSE_MODE)
				errflg++;
			mode |= EXTN_MODE;
			break;
		case 'v':
			if (mode & EXTN_MODE)
				errflg++;
			mode |= VERBOSE_MODE;
			break;
		case '?':
		default:
			errflg++;
			break;
		}

	if (errflg || optind != argc) {
		(void) fprintf(stderr,
		    gettext("usage: %s [ [-v] [-b | -n | -k] | [-x] ]\n"),
		    pgmname);
		return (1);
	}

	/*
	 * We use dev_cpu_self_cpuid for discovering hardware capabilities;
	 * but we only complain if we can't open it if we've been
	 * asked to report on those capabilities.
	 */
	if ((mode & (VERBOSE_MODE|EXTN_MODE)) != 0 &&
	    (d = open(dev_cpu_self_cpuid, O_RDONLY)) == -1)
		perror(dev_cpu_self_cpuid), exit(1);

	if (mode & KERN_MODE) {
		vfmt = gettext("%d-bit %s kernel modules\n");
		(void) report_abi(SI_ARCHITECTURE_K, vfmt);
		return (0);
	}

	vfmt = gettext("%d-bit %s applications\n");

	if (mode & (BITS_MODE | NATIVE_MODE)) {
		if ((isa = report_abi(SI_ARCHITECTURE_64, vfmt)) == NULL)
			isa = report_abi(SI_ARCHITECTURE_32, vfmt);
		if (isa != NULL && (mode & VERBOSE_MODE) != 0)
			report_hwcap(d, isa);
	} else {
		if ((isa = report_abi(SI_ARCHITECTURE_64, vfmt)) != NULL) {
			if (mode & (EXTN_MODE|VERBOSE_MODE))
				report_hwcap(d, isa);
			else
				(void) putchar(' ');
		}

		if ((isa32 = report_abi(SI_ARCHITECTURE_32, vfmt)) != NULL) {
			if (mode & (EXTN_MODE|VERBOSE_MODE))
				report_hwcap(d, isa32);
		}

		if ((isa32 != NULL || isa != NULL) &&
		    (mode & (EXTN_MODE|VERBOSE_MODE)) == 0)
			(void) putchar('\n');
	}

	return (0);
}
