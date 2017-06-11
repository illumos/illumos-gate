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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_DECL_H
#define	_DECL_H

#include <thread.h>
#include <_libelf.h>
#include <sys/machelf.h>
#include <msg.h>


#ifdef	__cplusplus
extern "C" {
#endif

typedef struct Member	Member;
typedef struct Memlist	Memlist;
typedef struct Memident	Memident;
typedef struct Dnode	Dnode;
typedef struct Snode32	Snode32;
typedef struct Snode64	Snode64;


/*
 * Data alignment
 *	An elf file is defined to have its structures aligned on
 *	appropriate boundaries.  The following type lets the
 *	library test whether the file's alignment meets its own
 *	constraints in memory.  This assumes every machine uses
 *	an alignment that is no greater than an object's size.
 *	The pointer isn't relevant for the file, but the code uses
 *	it to get memory alignment.  ANSI C void * holds any pointer,
 *	making it appropriate here.
 */

typedef union
{
	Elf32_Word	w;
	Elf32_Addr	a;
	Elf32_Off	o;
} Elf32;

typedef union {
	Elf64_Xword	x;
	Elf64_Word	w;
	Elf64_Addr	a;
	Elf64_Off	o;
	Elf_Void	*p;
} Elf64;


/*
 * Memory allocation
 *	Structures are obtained several ways: file mapping,
 *	malloc(), from the user.  A status bit in the structures
 *	tells whether an object was obtained with malloc() and
 *	therefore should be released with free().  The bits
 *	named ...ALLOC indicate this.
 */


/*
 * Data descriptor
 *	db_data must be first in the Dnode structure, because
 *	&db_data must == &Dnode.
 *
 *	db_buf is a pointer to an allocated buffer.  The same value
 *	goes into db_data.d_buf originally, but the user can touch
 *	it.  If the data buffer is not to be freed, db_buf is null.
 *
 *	When "reading" an input file's buffer, the data are left
 *	alone until needed.  When they've been converted to internal
 *	form, the READY flag is set.
 *
 *	db_raw points to a parallel raw buffer.  Raw buffers
 *	have null db_raw.
 */

struct	Dnode
{
	Elf_Data	db_data;
	Elf_Scn		*db_scn;	/* section parent */
	Dnode		*db_next;
	Dnode		*db_raw;	/* raw data */
	off_t		db_off;		/* orig file offset, 0 o/w */
	size_t		db_fsz;		/* orig file size, 0 o/w */
	size_t		db_shsz;	/* orig shdr size, 0 o/w */
	size_t		db_osz;		/* output size for update */
	Elf_Void	*db_buf;	/* allocated data buffer */
	unsigned	db_uflags;	/* user flags: ELF_F_... */
	unsigned	db_myflags;	/* internal flags: DBF_... */
	Elf64_Off	db_xoff;	/* extended offset for 32-bit Elf64 */
};

#define	DBF_ALLOC	0x1	/* applies to Dnode itself */
#define	DBF_READY	0x2	/* buffer ready */


/*
 * Section descriptor
 *	These are sometimes allocated in a block.  If the SF_ALLOC
 *	bit is set in the flags, the Scn address may be passed to free.
 *	The caller must first follow the s_next list to the next freeable
 *	node, because free can clobber the s_next value in the block.
 */

struct	Elf_Scn
{
	mutex_t		s_mutex;
	Elf_Scn		*s_next;	/* next section */
	Elf		*s_elf; 	/* parent file */
	Dnode		*s_hdnode;	/* head Dnode */
	Dnode		*s_tlnode;	/* tail Dnode */
	Elf_Void	*s_shdr;	/* Elf32 or Elf64 scn header */
	size_t		s_index;	/* section index */
	int		s_err;		/* for delaying data error */
	unsigned	s_shflags;	/* user shdr flags */
	unsigned	s_uflags;	/* user flags */
	unsigned	s_myflags;	/* SF_... */
	Dnode		s_dnode;	/* every scn needs one */
};

/*
 * Designates whether or not we are in a threaded_app.
 */
extern int *_elf_libc_threaded;
#define	elf_threaded	(_elf_libc_threaded && *_elf_libc_threaded)

#define	SCNLOCK(x) \
	if (elf_threaded) \
		(void) mutex_lock(&((Elf_Scn *)x)->s_mutex);

#define	SCNUNLOCK(x) \
	if (elf_threaded) \
		(void) mutex_unlock(&((Elf_Scn *)x)->s_mutex);

#define	UPGRADELOCKS(e, s)\
	if (elf_threaded) { \
		(void) mutex_unlock(&((Elf_Scn *)s)->s_mutex); \
		(void) rw_unlock(&((Elf *)e)->ed_rwlock); \
		(void) rw_wrlock(&((Elf *)e)->ed_rwlock); \
	}

#define	DOWNGRADELOCKS(e, s)\
	if (elf_threaded) { \
		(void) rw_unlock(&((Elf *)e)->ed_rwlock); \
		(void) rw_rdlock(&((Elf *)e)->ed_rwlock); \
		(void) mutex_lock(&((Elf_Scn *)s)->s_mutex); \
	}

#define	READLOCKS(e, s) \
	if (elf_threaded) { \
		(void) rw_rdlock(&((Elf *)e)->ed_rwlock); \
		(void) mutex_lock(&((Elf_Scn *)s)->s_mutex); \
	}

#define	READUNLOCKS(e, s) \
	if (elf_threaded) { \
		(void) mutex_unlock(&((Elf_Scn *)s)->s_mutex); \
		(void) rw_unlock(&((Elf *)e)->ed_rwlock); \
	}

#define	SF_ALLOC	0x1	/* applies to Scn */
#define	SF_READY	0x2	/* has section been cooked */


struct	Snode32
{
	Elf_Scn		sb_scn;		/* must be first */
	Elf32_Shdr	sb_shdr;
};

struct	Snode64
{
	Elf_Scn		sb_scn;		/* must be first */
	Elf64_Shdr	sb_shdr;
};


/*
 *	A file's status controls how the library can use file data.
 *	This is important to keep "raw" operations and "cooked"
 *	operations from interfering with each other.
 *
 *	A file's status is "fresh" until something touches it.
 *	If the first thing is a raw operation, we freeze the data
 *	and force all cooking operations to make a copy.  If the
 *	first operation cooks, raw operations use the file system.
 */

typedef enum
{
	ES_FRESH = 0,	/* unchanged */
	ES_COOKED,	/* translated */
	ES_FROZEN	/* raw, can't be translated */
} Status;


/*
 * Elf descriptor
 *	The major handle between user code and the library.
 *
 *	Descriptors can have parents: archive members reference
 *	the archive itself.  Relevant "offsets:"
 *
 *	ed_baseoff	The file offset, relative to zero, to the first
 *			byte in the file.  For all files, this gives
 *			the lseek(fd, ed_baseoff, 0) value.
 *
 *	ed_memoff	The offset from the beginning of the nesting file
 *			to the bytes of a member.  For an archive member,
 *			this is the offset from the beginning of the
 *			archive to the member bytes (not the hdr).  If an
 *			archive member slides, memoff changes.
 *
 *	ed_siboff	Similar to ed_memoff, this gives the offset from
 *			the beginning of the nesting file to the following
 *			sibling's header (not the sibling's bytes).  This
 *			value is necessary, because of archive sliding.
 *
 *	ed_nextoff	For an archive, this gives the offset of the next
 *			member to process on elf_begin.  That is,
 *			(ed_ident + ed_nextoff) gives pointer to member hdr.
 *
 *	Keeping these absolute and relative offsets allows nesting of
 *	files, including archives within archives, etc.  The only current
 *	nesting file is archive, but others might be supported.
 *
 *	ed_image	This is a pointer to the base memory image holding
 *			the file.  Library code assumes the image is aligned
 *			to a boundary appropriate for any object.  This must
 *			be true, because we get an image only from malloc
 *			or mmap, both of which guarantee alignment.
 */

struct Elf
{
	rwlock_t	ed_rwlock;
	Elf		*ed_parent;	/* archive parent */
	int		ed_activ;	/* activation count */
	int		ed_fd;		/* file descriptor */
	Status		ed_status;	/* file's memory status */
	off_t		ed_baseoff;	/* base file offset, zero based */
	size_t		ed_memoff;	/* offset within archive */
	size_t		ed_siboff;	/* sibling offset with archive */
	size_t		ed_nextoff;	/* next archive member hdr offset */
	char		*ed_image;	/* pointer to file image */
	size_t		ed_imagesz;	/* # bytes in ed_image */
	char		*ed_wrimage;	/* pointer to output image */
	size_t		ed_wrimagesz;	/* # bytes in ed_wrimagesz */
	char		*ed_ident;	/* file start, getident() bytes */
	size_t		ed_identsz;	/* # bytes for getident() */
	char		*ed_raw;	/* raw file ptr */
	size_t		ed_fsz;		/* file size */
	unsigned	*ed_vm;		/* virtual memory map */
	size_t		ed_vmsz;	/* # regions in vm */
	unsigned	ed_encode;	/* data encoding */
	unsigned	ed_version;	/* file version */
	int		ed_class;	/* file class */
	Elf_Kind	ed_kind;	/* file type */
	Elf_Void	*ed_ehdr;	/* Elf{32,64}_Ehdr elf header */
	Elf_Void	*ed_phdr;	/* Elf{32,64}_Phdr phdr table */
	size_t		ed_phdrsz;	/* sizeof phdr table */
	Elf_Void	*ed_shdr;	/* Elf{32,64}_Shdr shdr table */
	Elf_Scn		*ed_hdscn;	/* head scn */
	Elf_Scn		*ed_tlscn;	/* tail scn */
	size_t		ed_scntabsz;	/* number sects. alloc. in table */
	Memlist		*ed_memlist;	/* list of archive member nodes */
	Member		*ed_armem;	/* archive member header */
	Elf_Void	*ed_arsym;	/* archive symbol table */
	size_t		ed_arsymsz;	/* archive symbol table size */
	size_t		ed_arsymoff;	/* archive symbol table hdr offset */
	char		*ed_arstr;	/* archive string table */
	size_t		ed_arstrsz;	/* archive string table size */
	size_t		ed_arstroff;	/* archive string table hdr offset */
	unsigned	ed_myflags;	/* EDF_... */
	unsigned	ed_ehflags;	/* ehdr flags */
	unsigned	ed_phflags;	/* phdr flags */
	unsigned	ed_uflags;	/* elf descriptor flags */
};

#define	ELFRLOCK(e) \
	if (elf_threaded) \
		(void) rw_rdlock(&((Elf *)e)->ed_rwlock);

#define	ELFWLOCK(e) \
	if (elf_threaded) \
		(void) rw_wrlock(&((Elf *)e)->ed_rwlock);

#define	ELFUNLOCK(e) \
	if (elf_threaded) \
		(void) rw_unlock(&((Elf *)e)->ed_rwlock);

#define	EDF_ASALLOC	0x1	/* applies to ed_arsym */
#define	EDF_EHALLOC	0x2	/* applies to ed_ehdr */
#define	EDF_PHALLOC	0x4	/* applies to ed_phdr */
#define	EDF_SHALLOC	0x8	/* applies to ed_shdr */
#define	EDF_COFFAOUT	0x10	/* original file was coff a.out */
#define	EDF_RAWALLOC	0x20	/* applies to ed_raw */
#define	EDF_READ	0x40	/* file can be read */
#define	EDF_WRITE	0x80	/* file can be written */
#define	EDF_MEMORY	0x100	/* file opened via elf_memory() */
#define	EDF_ASTRALLOC	0x200	/* applies to ed_arstr */
#define	EDF_MPROTECT	0x400	/* applies to slideable archives */
#define	EDF_IMALLOC	0x800	/* wrimage dynamically allocated */
#define	EDF_WRALLOC	0x1000	/* wrimage is to by dyn allocated */
#define	EDF_ARSYM64	0x2000	/* archive symbol table is 64-bit format */


typedef enum
{
	OK_YES = 0,
	OK_NO = ~0
} Okay;

#define	_(a)		a

/*
 * Max size for an Elf error message string
 */
#define	MAXELFERR	1024

/*
 * General thread management macros
 */
#define	ELFACCESSDATA(a, b) \
	if (elf_threaded) { \
		(void) mutex_lock(&_elf_globals_mutex); \
		a = b; \
		(void) mutex_unlock(&_elf_globals_mutex); \
	} else \
		a = b;

#define	ELFRWLOCKINIT(lock) \
	if (elf_threaded) { \
		(void) rwlock_init((lock), USYNC_THREAD, 0); \
	}

#define	ELFMUTEXINIT(lock) \
	if (elf_threaded) { \
		(void) mutex_init(lock, USYNC_THREAD, 0); \
	}

extern Member		*_elf_armem(Elf *, char *, size_t);
extern void		_elf_arinit(Elf *);
extern Okay		_elf_cook(Elf *);
extern Okay		_elf_cookscn(Elf_Scn * s);
extern Okay		_elf32_cookscn(Elf_Scn * s);
extern Okay		_elf64_cookscn(Elf_Scn * s);
extern Dnode		*_elf_dnode(void);
extern Elf_Data		*_elf_locked_getdata(Elf_Scn *, Elf_Data *);
extern size_t		_elf32_entsz(Elf *elf, Elf32_Word, unsigned);
extern size_t		_elf64_entsz(Elf *elf, Elf64_Word, unsigned);
extern Okay		_elf_inmap(Elf *);
extern char		*_elf_outmap(int, size_t, unsigned *);
extern size_t		_elf_outsync(int, char *, size_t, unsigned);
extern size_t		_elf32_msize(Elf_Type, unsigned);
extern size_t		_elf64_msize(Elf_Type, unsigned);
extern Elf_Type		_elf32_mtype(Elf *, Elf32_Word, unsigned);
extern Elf_Type		_elf64_mtype(Elf *, Elf64_Word, unsigned);
extern char		*_elf_read(int, off_t, size_t);
extern Snode32		*_elf32_snode(void);
extern Snode64		*_elf64_snode(void);
extern void		_elf_unmap(char *, size_t);
extern Okay		_elf_vm(Elf *, size_t, size_t);
extern int		_elf32_ehdr(Elf *, int);
extern int		_elf32_phdr(Elf *, int);
extern int		_elf32_shdr(Elf *, int);
extern int		_elf64_ehdr(Elf *, int);
extern int		_elf64_phdr(Elf *, int);
extern int		_elf64_shdr(Elf *, int);
extern int		_elf_byte;
extern const Elf32_Ehdr	_elf32_ehdr_init;
extern const Elf64_Ehdr	_elf64_ehdr_init;
extern unsigned		_elf_encode;
extern _elf_execfill_func_t *_elf_execfill_func;
extern void		_elf_seterr(Msg, int);
extern const Snode32	_elf32_snode_init;
extern const Snode64	_elf64_snode_init;
extern const Dnode	_elf_dnode_init;
extern unsigned		_elf_work;
extern mutex_t		_elf_globals_mutex;
extern off_t		_elf64_update(Elf * elf, Elf_Cmd cmd);
extern int		_elf64_swap_wrimage(Elf *elf);

#ifdef	__cplusplus
}
#endif

#endif	/* _DECL_H */
