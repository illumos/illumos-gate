/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#ifndef _MDB_X86UTIL_H
#define	_MDB_X86UTIL_H

#include <sys/types.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mdb_x86_desc {
	uint64_t d_base;
	uint32_t d_lim;
	uint32_t d_acc;
} mdb_x86_desc_t;

struct sysregs {
	uint64_t sr_cr0;
	uint64_t sr_cr2;
	uint64_t sr_cr3;
	uint64_t sr_cr4;
	uint64_t sr_dr0;
	uint64_t sr_dr1;
	uint64_t sr_dr2;
	uint64_t sr_dr3;
	uint64_t sr_dr6;
	uint64_t sr_dr7;
	uint64_t sr_efer;
	uint64_t sr_pdpte0;
	uint64_t sr_pdpte1;
	uint64_t sr_pdpte2;
	uint64_t sr_pdpte3;
	uint64_t sr_intr_shadow;
	mdb_x86_desc_t sr_gdtr;
	mdb_x86_desc_t sr_idtr;
	mdb_x86_desc_t sr_ldtr;
	mdb_x86_desc_t sr_tr;
	mdb_x86_desc_t sr_cs;
	mdb_x86_desc_t sr_ss;
	mdb_x86_desc_t sr_ds;
	mdb_x86_desc_t sr_es;
	mdb_x86_desc_t sr_fs;
	mdb_x86_desc_t sr_gs;
};

extern void mdb_x86_print_sysregs(struct sysregs *, boolean_t);


#ifdef __cplusplus
}
#endif

#endif /* _MDB_X86UTIL_H */
