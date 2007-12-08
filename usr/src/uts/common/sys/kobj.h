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

#ifndef _SYS_KOBJ_H
#define	_SYS_KOBJ_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/modctl.h>
#include <sys/elf.h>
#include <sys/machelf.h>
#include <sys/vmem.h>
#include <sys/sdt.h>
#include <sys/bootstat.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * List of modules maintained by kobj.c
 */
struct module_list {
	struct module_list *next;
	struct module *mp;
};

typedef unsigned short	symid_t;		/* symbol table index */
typedef unsigned char	*reloc_dest_t;

typedef	void	module_mach;

struct module {
	int total_allocated;

	Ehdr hdr;
	char *shdrs;
	Shdr *symhdr, *strhdr;

	char *depends_on;

	size_t symsize;
	char *symspace;	/* symbols + strings + hashtbl, or NULL */
	int flags;

	size_t text_size;
	size_t data_size;
	char *text;
	char *data;

	unsigned int symtbl_section;
	/* pointers into symspace, or NULL */
	char *symtbl;
	char *strings;

	unsigned int hashsize;
	symid_t *buckets;
	symid_t *chains;

	unsigned int nsyms;

	unsigned int bss_align;
	size_t bss_size;
	uintptr_t bss;

	char *filename;

	struct module_list *head, *tail;
	reloc_dest_t destination;
	module_mach * machdata;
	char *ctfdata;
	size_t ctfsize;

	char *fbt_tab;
	size_t fbt_size;
	size_t fbt_nentries;
	caddr_t textwin;
	caddr_t textwin_base;

	sdt_probedesc_t *sdt_probes;
	size_t sdt_nprobes;
	char *sdt_tab;
	size_t sdt_size;

	char *sigdata;
	size_t sigsize;
};

struct kobj_mem {
	struct kobj_mem	*km_next;
	struct kobj_mem *km_prev;
	uintptr_t	km_addr;
	size_t		km_size;
	uintptr_t	km_alloc_addr;
	size_t		km_alloc_size;
};

struct _buf {
	intptr_t	 _fd;
	char		*_ptr;
	char		*_base;
	char 		*_name;
	char		*_dbuf;
	int		 _size;
	int		_cnt;
	int		 _off;
	int		_ln;
	int		_bsize;
	int		_iscmp;
	int		_dsize;
};


/*
 * Statistical info.
 */
typedef struct {
	int nalloc;
	int nfree;
	int nalloc_calls;
	int nfree_calls;
} kobj_stat_t;

#define	kobj_filename(p) ((p)->_name)
#define	kobj_linenum(p)  ((p)->_ln)
#define	kobj_newline(p)	 ((p)->_ln++)
#define	kobj_getc(p)	(--(p)->_cnt >= 0 ? ((int)*(p)->_ptr++):kobj_filbuf(p))
#define	kobj_ungetc(p)	 (++(p)->_cnt > (p)->_size ? -1 : ((int)*(--(p)->_ptr)))
#define	kobj_comphdr(p)	((struct comphdr *)(p)->_dbuf)

/* Offset into buffer */
#define	B_OFFSET(file, off)	(off % (file)->_bsize)

/* Start of page */
#define	F_PAGE(file, off)	(off - B_OFFSET(file, off))

#define	F_BLKS(file, size)	((size / (file)->_bsize) * (file)->_bsize)

#if defined(_KERNEL)

extern int kobj_load_module(struct modctl *, int);
extern void kobj_unload_module(struct modctl *);
extern uintptr_t kobj_lookup(struct module *, const char *);
extern Sym *kobj_lookup_all(struct module *, char *, int);
extern int kobj_addrcheck(void *, caddr_t);
extern int kobj_module_to_id(void *);
extern void kobj_getmodinfo(void *, struct modinfo *);
extern int kobj_get_needed(void *, short *, int);
extern uintptr_t kobj_getsymvalue(char *, int);
extern char *kobj_getsymname(uintptr_t, ulong_t *);
extern char *kobj_searchsym(struct module *, uintptr_t, ulong_t *);

extern int kobj_fstat(intptr_t, struct bootstat *);
extern intptr_t kobj_open(char *);
extern int kobj_path_exists(char *, int);
extern struct _buf *kobj_open_path(char *, int, int);
extern int kobj_read(intptr_t, char *, unsigned int, unsigned int);
extern void kobj_close(intptr_t);
extern void *kobj_alloc(size_t, int);
extern void *kobj_zalloc(size_t, int);
extern void kobj_free(void *, size_t);
extern struct _buf *kobj_open_file(char *);
extern void kobj_close_file(struct _buf *);
extern int kobj_read_file(struct _buf *, char *, unsigned, unsigned);
extern int kobj_get_filesize(struct _buf *, uint64_t *size);
extern uintptr_t kobj_getelfsym(char *, void *, int *);
extern void kobj_set_ctf(struct module *, caddr_t data, size_t size);

extern int kobj_filbuf(struct _buf *);
extern void kobj_sync(void);
#if defined(__i386) || defined(__sparc) || defined(__amd64)
extern void kobj_vmem_init(vmem_t **, vmem_t **);
#else
#error "ISA not supported"
#endif
extern caddr_t kobj_text_alloc(vmem_t *, size_t);
extern caddr_t kobj_texthole_alloc(caddr_t, size_t);
extern void kobj_texthole_free(caddr_t, size_t);
extern void kobj_stat_get(kobj_stat_t *);
extern void kobj_textwin_alloc(struct module *);
extern void kobj_textwin_free(struct module *);

#endif	/* defined(_KERNEL) */

#ifdef	__cplusplus
}
#endif

#endif /* !_SYS_KOBJ_H */
