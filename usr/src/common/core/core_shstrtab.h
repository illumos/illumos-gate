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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2021 Oxide Computer Company
 */

#ifndef _CORE_SHSTRTAB_H
#define	_CORE_SHSTRTAB_H

/*
 * This header contains common definitions that are used to generate a
 * shstrtab_t for core files. This is used by libproc and the kernel to generate
 * core files in a similar way.
 */

#include <sys/list.h>
#include <sys/stdint.h>
#include <sys/elf.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	STR_NONE,
	STR_CTF,
	STR_SYMTAB,
	STR_DYNSYM,
	STR_STRTAB,
	STR_DYNSTR,
	STR_SHSTRTAB,
	STR_NUM
} shstrtype_t;

extern const char *shstrtab_data[STR_NUM];

typedef struct shstrtab_ent {
	list_node_t	sste_link;
	char		*sste_name;
	size_t		sste_len;
	uint32_t	sste_offset;
} shstrtab_ent_t;

typedef struct shstrtab {
	list_t		sst_names;
	uint32_t	sst_len;
} shstrtab_t;

extern boolean_t shstrtab_init(shstrtab_t *s);
extern boolean_t shstrtab_ndx(shstrtab_t *, const char *, Elf32_Word *);
extern void shstrtab_fini(shstrtab_t *);
extern size_t shstrtab_size(const shstrtab_t *);
extern void shstrtab_dump(shstrtab_t *, void *);

#ifdef __cplusplus
}
#endif

#endif /* _CORE_SHSTRTAB_H */
