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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FMD_CKPT_H
#define	_FMD_CKPT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Fault Manager Checkpoint Format (FCF)
 *
 * Fault manager modules can checkpoint state in the FCF format so that they
 * can survive restarts, module failures, and reboots.  The FCF format is
 * versioned and extensible so that it can be revised and so that internal data
 * structures can be modified or extended compatibly.  It is also specified as
 * a Project Private interface so that incompatible changes can occur as we see
 * fit.  All FCF structures use fixed-size types so that the 32-bit and 64-bit
 * forms are identical and consumers can use either data model transparently.
 *
 * The file layout is structured as follows:
 *
 * +---------------+-------------------+----- ... ----+---- ... ------+
 * |   fcf_hdr_t   |  fcf_sec_t[ ... ] |   section    |   section     |
 * | (file header) | (section headers) |   #1 data    |   #N data     |
 * +---------------+-------------------+----- ... ----+---- ... ------+
 * |<------------ fcf_hdr.fcfh_filesz ------------------------------->|
 *
 * The file header stores meta-data including a magic number, data model for
 * the checkpointed module, data encoding, and other miscellaneous properties.
 * The header describes its own size and the size of the section headers.  By
 * convention, an array of section headers follows the file header, and then
 * the data for all the individual sections listed in the section header table.
 *
 * The section headers describe the size, offset, alignment, and section type
 * for each section.  Sections are described using a set of #defines that tell
 * the consumer what kind of data is expected.  Sections can contain links to
 * other sections by storing a fcf_secidx_t, an index into the section header
 * array, inside of the section data structures.  The section header includes
 * an entry size so that sections with data arrays can grow their structures.
 *
 * Finally, strings are always stored in ELF-style string tables along with a
 * string table section index and string table offset.  Therefore strings in
 * FCF are always arbitrary-length and not bound to the current implementation.
 */

#define	FCF_ID_SIZE	16	/* total size of fcfh_ident[] in bytes */

typedef struct fcf_hdr {
	uint8_t fcfh_ident[FCF_ID_SIZE]; /* identification bytes (see below) */
	uint32_t fcfh_flags;		/* file attribute flags (if any) */
	uint32_t fcfh_hdrsize;		/* size of file header in bytes */
	uint32_t fcfh_secsize;		/* size of section header in bytes */
	uint32_t fcfh_secnum;		/* number of section headers */
	uint64_t fcfh_secoff;		/* file offset of section headers */
	uint64_t fcfh_filesz;		/* file size of entire FCF file */
	uint64_t fcfh_cgen;		/* checkpoint generation number */
	uint64_t fcfh_pad;		/* reserved for future use */
} fcf_hdr_t;

#define	FCF_ID_MAG0	0	/* first byte of magic number */
#define	FCF_ID_MAG1	1	/* second byte of magic number */
#define	FCF_ID_MAG2	2	/* third byte of magic number */
#define	FCF_ID_MAG3	3	/* fourth byte of magic number */
#define	FCF_ID_MODEL	4	/* FCF data model (see below) */
#define	FCF_ID_ENCODING	5	/* FCF data encoding (see below) */
#define	FCF_ID_VERSION	6	/* FCF file format major version (see below) */
#define	FCF_ID_PAD	7	/* start of padding bytes (all zeroes) */

#define	FCF_MAG_MAG0	0x7F	/* FCF_ID_MAG[0-3] */
#define	FCF_MAG_MAG1	'F'
#define	FCF_MAG_MAG2	'C'
#define	FCF_MAG_MAG3	'F'

#define	FCF_MAG_STRING	"\177FCF"
#define	FCF_MAG_STRLEN	4

#define	FCF_MODEL_NONE	0	/* FCF_ID_MODEL */
#define	FCF_MODEL_ILP32	1
#define	FCF_MODEL_LP64	2

#ifdef _LP64
#define	FCF_MODEL_NATIVE	FCF_MODEL_LP64
#else
#define	FCF_MODEL_NATIVE	FCF_MODEL_ILP32
#endif

#define	FCF_ENCODE_NONE	0	/* FCF_ID_ENCODING */
#define	FCF_ENCODE_LSB	1
#define	FCF_ENCODE_MSB	2

#ifdef _BIG_ENDIAN
#define	FCF_ENCODE_NATIVE	FCF_ENCODE_MSB
#else
#define	FCF_ENCODE_NATIVE	FCF_ENCODE_LSB
#endif

#define	FCF_VERSION_1	1	/* FCF_ID_VERSION */
#define	FCF_VERSION	FCF_VERSION_1

#define	FCF_FL_VALID	0	/* mask of all valid fcfh_flags bits */

typedef uint32_t fcf_secidx_t;	/* section header table index type */
typedef uint32_t fcf_stridx_t;	/* string table index type */

#define	FCF_SECIDX_NONE	0	/* null value for section indices */
#define	FCF_STRIDX_NONE	0	/* null value for string indices */

typedef struct fcf_sec {
	uint32_t fcfs_type;	/* section type (see below) */
	uint32_t fcfs_align;	/* section data memory alignment */
	uint32_t fcfs_flags;	/* section flags (if any) */
	uint32_t fcfs_entsize;	/* size of section entry (if table) */
	uint64_t fcfs_offset;	/* offset of section data within file */
	uint64_t fcfs_size;	/* size of section data in bytes */
} fcf_sec_t;

/*
 * Section types (fcfs_type values).  These #defines should be kept in sync
 * with the decoding table declared in fmd_mdb.c in the fcf_sec() dcmd, and
 * with the size and alignment table declared at the top of fmd_ckpt.c.
 */
#define	FCF_SECT_NONE		0	/* null section */
#define	FCF_SECT_STRTAB		1	/* string table */
#define	FCF_SECT_MODULE		2	/* module meta-data (fcf_mod_t) */
#define	FCF_SECT_CASE		3	/* case meta-data (fcf_case_t) */
#define	FCF_SECT_BUFS		4	/* buffer list (fcf_buf_t) */
#define	FCF_SECT_BUFFER		5	/* module data buffer */
#define	FCF_SECT_SERD		6	/* serd list (fcf_serd_t) */
#define	FCF_SECT_EVENTS		7	/* event list (fcf_event_t) */
#define	FCF_SECT_NVLISTS	8	/* nvlist list (fcf_nvl_t) */

typedef struct fcf_module {
	fcf_stridx_t fcfm_name;	/* module basename */
	fcf_stridx_t fcfm_path;	/* module path */
	fcf_stridx_t fcfm_desc;	/* description */
	fcf_stridx_t fcfm_vers;	/* version */
	fcf_secidx_t fcfm_bufs; /* FCF_SECT_BUFS containing global buffers */
} fcf_module_t;

typedef struct fcf_case {
	fcf_stridx_t fcfc_uuid;	/* case uuid */
	uint32_t fcfc_state;	/* case state (see below) */
	fcf_secidx_t fcfc_bufs;	/* FCF_SECT_BUFS containing buffers */
	fcf_secidx_t fcfc_principal; /* FCF_SECT_EVENTS containing principal */
	fcf_secidx_t fcfc_events; /* FCF_SECT_EVENTS containing events */
	fcf_secidx_t fcfc_suspects; /* FCF_SECT_NVLISTS containing suspects */
} fcf_case_t;

#define	FCF_CASE_UNSOLVED	0
#define	FCF_CASE_SOLVED		1
#define	FCF_CASE_CLOSE_WAIT	2

typedef struct fcf_buf {
	fcf_stridx_t fcfb_name;	/* buffer name */
	fcf_secidx_t fcfb_data;	/* FCF_SECT_BUFFER containing data */
} fcf_buf_t;

typedef struct fcf_serd {
	fcf_stridx_t fcfd_name;	/* engine name */
	fcf_secidx_t fcfd_events; /* FCF_SECT_EVENTS containing events */
	uint32_t fcfd_pad;	/* reserved for future use */
	uint32_t fcfd_n;	/* engine N parameter */
	uint64_t fcfd_t;	/* engine T parameter */
} fcf_serd_t;

typedef struct fcf_event {
	uint64_t fcfe_todsec;	/* seconds since gettimeofday(3C) epoch */
	uint64_t fcfe_todnsec;	/* nanoseconds past value of fcfe_todsec */
	uint32_t fcfe_major;	/* major number from log file st_dev */
	uint32_t fcfe_minor;	/* minor number from log file st_rdev */
	uint64_t fcfe_inode;	/* inode number from log file st_ino */
	uint64_t fcfe_offset;	/* event offset within log file */
} fcf_event_t;

typedef struct fcf_nvlist {
	uint64_t fcfn_size;	/* size of packed nvlist after this header */
} fcf_nvl_t;

/*
 * The checkpoint subsystem provides a very simple set of interfaces to the
 * reset of fmd: namely, checkpoints can be saved, restored, or deleted by mod.
 * In the reference implementation, these are implemented to use FCF files.
 */

struct fmd_module;		/* see <fmd_module.h> */

extern void fmd_ckpt_save(struct fmd_module *);
extern void fmd_ckpt_restore(struct fmd_module *);
extern void fmd_ckpt_delete(struct fmd_module *);
extern void fmd_ckpt_rename(struct fmd_module *);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_CKPT_H */
