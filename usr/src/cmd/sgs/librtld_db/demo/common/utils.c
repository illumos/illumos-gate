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
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libelf.h>
#include <sys/param.h>

#include "rdb.h"

void
perr(char *s)
{
	perror(s);
	exit(1);
}

ulong_t
hexstr_to_num(const char *str)
{
	ulong_t		num = 0;
	size_t		i, len = strlen(str);

	for (i = 0; i < len; i++)
		if (str[i] >= '0' && str[i] <= '9')
			num = num * 16 +((int)str[i] - (int)'0');
		else if (str[i] >= 'a' && str[i] <= 'f')
			num = num * 16 +((int)str[i] - (int)'a' + 10);
		else if (str[i] >= 'A' && str[i] <= 'F')
			num = num * 16 + ((int)str[i] - (int)'A' + 10);
	return (num);
}

#define	STBUFSIZ	1024

retc_t
proc_string_read(struct ps_prochandle *ph, ulong_t addr, char *buf, int bufsiz)
{
	char	intbuf[STBUFSIZ];
	int	bufind = 0, intbufind = STBUFSIZ, cont = 1;
	ssize_t	bufbytes = 0;

	if (lseek(ph->pp_asfd, addr, SEEK_SET) == -1)
		return (RET_FAILED);
	while (cont && (bufind < bufsiz)) {
		if (intbufind >= bufbytes) {
			if ((bufbytes = read(ph->pp_asfd, intbuf,
			    STBUFSIZ)) == -1)
				return (RET_FAILED);
			intbufind = 0;
		}
		buf[bufind] = intbuf[intbufind];
		if (buf[bufind] == '\0')
			return (RET_OK);
		bufind++;
		intbufind++;
	}
	return (RET_FAILED);
}

void
print_varstring(struct ps_prochandle *ph, const char *varname)
{
	(void) printf("print_varstring: %s\n", varname);
	if (strcmp(varname, "regs") == 0) {
		(void) display_all_regs(ph);
		return;
	}
	print_mach_varstring(ph, varname);
}

void
print_mem(struct ps_prochandle *ph, ulong_t address, int count, char *format)
{
	(void) printf("\n%17s:", print_address_ps(ph, address, FLG_PAP_SONAME));

	if ((*format == 'X') || (*format == 'x')) {
		int	i;

		for (i = 0; i < count; i++) {
			unsigned long word;
			if ((i % 4) == 0)
				(void) printf("\n  0x%08lx: ", address);

			if (ps_pread(ph, address, (char *)&word,
			    sizeof (unsigned long)) != PS_OK) {
				(void) printf("\nfailed to read memory at: "
				    "0x%lx\n", address);
				return;
			}
			(void) printf("  0x%08lx", word);
			address += 4;
		}
		(void) putchar('\n');
		return;
	}

	if (*format == 'b') {
		int	i;

		for (i = 0; i < count; i++, address ++) {
			unsigned char	byte;

			if ((i % 8) == 0)
				(void) printf("\n 0x%08lx: ", address);

			if (ps_pread(ph, address, (char *)&byte,
			    sizeof (unsigned char)) != PS_OK) {
				(void) fprintf(stderr, "\nfailed to read byte "
				    "at: 0x%lx\n", address);
				return;
			}
			(void) printf("  %02x", (unsigned)byte);
		}
		(void) putchar('\n');
		return;
	}

	if (*format == 's') {
		char	buf[MAXPATHLEN];
		if (proc_string_read(ph, address, buf,
		    MAXPATHLEN) != RET_OK) {
			(void) printf("unable to read string at: %lx\n",
			    address);
			return;
		}
		(void) printf(" %s\n", buf);
		return;
	}
}
