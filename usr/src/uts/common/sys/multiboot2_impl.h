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
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 */

#ifndef _SYS_MULTIBOOT2_IMPL_H
#define	_SYS_MULTIBOOT2_IMPL_H

/*
 * Multiboot 2 protocol implementation for dboot.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/multiboot2.h>

extern void *dboot_multiboot2_find_tag(multiboot2_info_header_t *, uint32_t);
extern char *dboot_multiboot2_cmdline(multiboot2_info_header_t *);
extern int dboot_multiboot2_modcount(multiboot2_info_header_t *);
extern uint32_t dboot_multiboot2_modstart(multiboot2_info_header_t *, int);
extern uint32_t dboot_multiboot2_modend(multiboot2_info_header_t *, int);
extern char *dboot_multiboot2_modcmdline(multiboot2_info_header_t *, int);
extern multiboot_tag_mmap_t *
    dboot_multiboot2_get_mmap_tagp(multiboot2_info_header_t *);
extern boolean_t dboot_multiboot2_basicmeminfo(multiboot2_info_header_t *,
    uint32_t *, uint32_t *);
extern uint64_t dboot_multiboot2_mmap_get_length(multiboot2_info_header_t *,
    multiboot_tag_mmap_t *, int);
extern uint64_t dboot_multiboot2_mmap_get_base(multiboot2_info_header_t *,
    multiboot_tag_mmap_t *, int);
extern uint32_t dboot_multiboot2_mmap_get_type(multiboot2_info_header_t *,
    multiboot_tag_mmap_t *, int);
extern int dboot_multiboot2_mmap_nentries(multiboot2_info_header_t *,
    multiboot_tag_mmap_t *);
extern paddr_t dboot_multiboot2_highest_addr(multiboot2_info_header_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_MULTIBOOT2_IMPL_H */
