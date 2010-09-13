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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/* LINTLIBRARY */
/* PROTOLIB1 */

/*
 * Supplemental definitions for lint that help us avoid
 * options like `-x' that filter out things we want to
 * know about as well as things we don't.
 */

/*
 * The public interfaces are allowed to be "declared
 * but not used".
 */
#include <stdio.h>
#include <sys/auxv.h>
#include <libelf.h>
#include <link.h>
#include <demangle.h>
#include <elfcap.h>
#include <dwarf.h>
#include "sgs.h"
#include "rtld.h"
#include "libld.h"
#include "conv.h"

/*
 * Suppress the actual message codes from the sgsmsg headers.
 * With multiple string tables, we will have name collisions.
 */
#define	LINTSUP_SUPPRESS_STRINGS
#include "arch_msg.h"
#include "audit_msg.h"
#include "c_literal_msg.h"
#include "cap_msg.h"
#include "config_msg.h"
#include "corenote_msg.h"
#include "data_msg.h"
#include "deftag_msg.h"
#include "demangle_msg.h"
#include "dl_msg.h"
#include "dwarf_ehe_msg.h"
#include "dwarf_msg.h"
#include "dynamic_msg.h"
#include "elf_msg.h"
#include "entry_msg.h"
#include "globals_msg.h"
#include "group_msg.h"
#include "lddstub_msg.h"
#include "map_msg.h"
#include "phdr_msg.h"
#include "relocate_amd64_msg.h"
#include "relocate_i386_msg.h"
#include "relocate_sparc_msg.h"
#include "sections_msg.h"
#include "segments_msg.h"
#include "symbols_msg.h"
#include "symbols_sparc_msg.h"
#include "syminfo_msg.h"
#include "time_msg.h"
#include "version_msg.h"

void
foo()
{
#define	USE(name) (void) name((Msg)&_ ## name[0])

	USE(_sgs_msg_libconv_arch);
	USE(_sgs_msg_libconv_audit);
	USE(_sgs_msg_libconv_c_literal);
	USE(_sgs_msg_libconv_cap);
	USE(_sgs_msg_libconv_config);
	USE(_sgs_msg_libconv_corenote);
	USE(_sgs_msg_libconv_data);
	USE(_sgs_msg_libconv_deftag);
	USE(_sgs_msg_libconv_demangle);
	USE(_sgs_msg_libconv_dl);
	USE(_sgs_msg_libconv_dwarf_ehe);
	USE(_sgs_msg_libconv_dwarf);
	USE(_sgs_msg_libconv_dynamic);
	USE(_sgs_msg_libconv_elf);
	USE(_sgs_msg_libconv_entry);
	USE(_sgs_msg_libconv_globals);
	USE(_sgs_msg_libconv_group);
	USE(_sgs_msg_libconv_lddstub);
	USE(_sgs_msg_libconv_map);
	USE(_sgs_msg_libconv_phdr);
	USE(_sgs_msg_libconv_relocate_amd64);
	USE(_sgs_msg_libconv_relocate_i386);
	USE(_sgs_msg_libconv_relocate_sparc);
	USE(_sgs_msg_libconv_sections);
	USE(_sgs_msg_libconv_segments);
	USE(_sgs_msg_libconv_symbols);
	USE(_sgs_msg_libconv_symbols_sparc);
	USE(_sgs_msg_libconv_syminfo);
	USE(_sgs_msg_libconv_time);
	USE(_sgs_msg_libconv_version);

#undef USE
}
