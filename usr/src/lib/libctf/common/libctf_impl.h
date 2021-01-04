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
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef _LIBCTF_IMPL_H
#define	_LIBCTF_IMPL_H

/*
 * Portions of libctf implementations that are only suitable for CTF's userland
 * library, eg. converting and merging related routines.
 */

#include <libelf.h>
#include <libctf.h>
#include <ctf_impl.h>
#include <sys/list.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ctf_convert_filelist {
	list_node_t ccf_node;
	char *ccf_basename;
} ctf_convert_filelist_t;

struct ctf_convert_handle {
	char *cch_label;
	uint_t cch_flags;
	uint_t cch_nthreads;
	uint_t cch_batchsize;
	ctf_convert_warn_f cch_warncb;
	list_t cch_nodebug;
	void *cch_warncb_arg;
};

typedef int (*ctf_convert_f)(ctf_convert_t *, int, Elf *, ctf_file_t **,
    char *, size_t);
extern int ctf_dwarf_convert(ctf_convert_t *, int, Elf *, ctf_file_t **,
    char *, size_t);

/*
 * Symbol walking
 */
typedef int (*ctf_symtab_f)(const Elf64_Sym *, ulong_t, const char *,
    const char *, boolean_t, void *);
extern int ctf_symtab_iter(ctf_file_t *, ctf_symtab_f, void *);

/*
 * zlib compression routines
 */
extern int ctf_compress(ctf_file_t *fp, void **, size_t *, size_t *);

extern int ctf_diff_self(ctf_diff_t *, ctf_diff_type_f, void *);

/*
 * Internal debugging aids
 */
extern void ctf_phase_dump(ctf_file_t *, const char *, const char *);
extern void ctf_phase_bump(void);

#ifdef __cplusplus
}
#endif

#endif /* _LIBCTF_IMPL_H */
