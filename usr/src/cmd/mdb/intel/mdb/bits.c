/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 1988 AT&T
 * All rights reserved.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"dis.h"

/*
 * Minimum instruction name field width
 */
#define	INST_MINWIDTH	7

/* For communication to locsympr */
const char *const *regname;
static char mneu[256];  /* array to store disassembly for return */
static uchar_t curbyte;	/* result of getbyte() */

static	mdb_tgt_t 	*dis_target;
static	mdb_tgt_as_t	dis_as;
static	mdb_tgt_addr_t	dis_offset;
static	ssize_t		dis_size;
static	uchar_t		dis_buffer[64];

static	mdb_tgt_addr_t	curloc;


/*
 * Get next byte from the instruction stream,
 * set curbyte and increment curloc.
 */
/*ARGSUSED*/
static int
getbyte(void *notused)
{
	ulong_t index = (ulong_t)(curloc - dis_offset);

	if (index >= dis_size) {
		dis_size = mdb_tgt_aread(dis_target, dis_as, dis_buffer,
			sizeof (dis_buffer), curloc);

		if (dis_size <= 0) {
			dis_offset = 0;
			dis_size = 0;
			curbyte = 0;
			return (-1);
		}

		dis_offset = curloc;
		index = 0;
	}

	curbyte = dis_buffer[index];
	curloc++;
	return (curbyte);
}

static int
symlookup(uint64_t addr, char *buf, size_t len)
{
	(void) mdb_iob_snprintf(buf, len, "%a", (uintptr_t)addr);
	if (strncmp(buf, "0x", 2) == 0) {
		if (len > 0)
			*buf = '\0';
		return (-1);
	}
	return (0);
}

/*
 * disassemble an instruction. Mode can be DIS_IA32 or DIS_AMD64.
 */
/*ARGSUSED*/
static void
disasm(int mode)
{
	dis86_t		x86dis;
	uint_t		cpu_mode = SIZE32;

#ifdef __amd64
	if (mode == DIS_AMD64)
		cpu_mode = SIZE64;
#endif

	bzero(&x86dis, sizeof (dis86_t));
	x86dis.d86_check_func = NULL;
	x86dis.d86_get_byte = getbyte;
	x86dis.d86_sprintf_func =
	    (int (*)(char *, size_t, const char *, ...))mdb_iob_snprintf;
	x86dis.d86_sym_lookup = symlookup;

	if (dtrace_disx86(&x86dis, cpu_mode) != 0) {
		(void) strcpy(mneu, "***ERROR--unknown op code***");
		return;
	}

	dtrace_disx86_str(&x86dis, cpu_mode, curloc, mneu, sizeof (mneu));
}

/*ARGSUSED*/
mdb_tgt_addr_t
ia32dis_ins2str(mdb_disasm_t *dp, mdb_tgt_t *t, mdb_tgt_as_t as,
    char *buf, size_t len, mdb_tgt_addr_t pc)
{
	char *cp;

	dis_target = t;		/* target pointer */
	dis_as = as;		/* address space identifier */
	dis_offset = pc;	/* address of current instruction */
	dis_size = 1;		/* size of current instruction */

	if (mdb_tgt_aread(t, as, &dis_buffer[0], sizeof (char), pc) == -1) {
		warn("failed to read instruction at %llr", pc);
		return (pc);
	}

	/*
	 * Disassemble one instruction starting at curloc,
	 * increment curloc to the following location,
	 * and leave the ascii result in mneu[]. dp->dis_data
	 * holds the disassembly mode; DIS_AMD64 or DIS_IA32.
	 */
	curloc = pc;
	disasm((uintptr_t)dp->dis_data);

	cp = mneu + strlen(mneu);
	while (cp-- > mneu && *cp == ' ')
		*cp = '\0';
	(void) mdb_snprintf(buf, len, "%s", mneu);
	return (curloc);
}
