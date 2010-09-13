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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SPCS_S_IMPL_H
#define	_SPCS_S_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	The SPCS Unistat private implementation definitions
 *
 *	Only modules spcs_s_u.c and spcs_s_k.c should be using this
 */

/*
 *	For Unistat, here are the definitions of the major and minor revisions:
 *
 *	Bump major revision and zero minor revision if: Any change made to
 *	spcs_s_pinfo_t in terms of size, changed fields, etc, or any user
 *	functional change to spcs_s.h definitions that is not backwards
 *	compatible.
 *
 *	Bump minor revision if: Any backwards compatible change to
 *	functionality but with no impact on interoperability between kernel and
 *	user level Unistat code having differing minor revs.
 *
 */

#define	SPCS_S_MAJOR_REV 1	/* Unistat major revision */
#define	SPCS_S_MINOR_REV 1	/* Unistat minor revision */
/*
 *	This is the format of a unistat status code. It must overlay
 *	an int.
 */
#if defined(__sparc)
typedef struct {
	/*
	 * If this flag is set the last supplemental item in idata is expected
	 * to be of type SU_BYTESTREAM and offset is a tdata index.
	 */
	unsigned char bytestream: 1;
	/*
	 * count of items of supporting information references in idata
	 * to accompany this error status code spcs.h define SPCS_S_MAXSUPP
	 * must be 2 raised to the bit size of this field. Also don't forget
	 * to update the sprintf in spcs_s_string.
	 */
	unsigned char reserved: 4;	/* reserved for future expansion */
	unsigned char sup_count: 3;
	unsigned char module:	8;	/* module code (see below) */
	unsigned short code:	16;	/* status code number (>0) */
} spcs_s_code_t;
#elif defined(__i386) || (__amd64)
typedef struct {
	/*
	 * count of items of supporting information references in idata
	 * to accompany this error status code spcs.h define SPCS_S_MAXSUPP
	 * must be 2 raised to the bit size of this field. Also don't forget
	 * to update the sprintf in spcs_s_string.
	 */
	unsigned short code:	16;	/* status code number (>0) */
	unsigned char module:	8;	/* module code (see below) */
	unsigned char sup_count: 3;
	unsigned char reserved: 4;	/* reserved for future expansion */
	/*
	 * If this flag is set the last supplemental item in idata is expected
	 * to be of type SU_BYTESTREAM and offset is a tdata index.
	 */
	unsigned char bytestream: 1;
} spcs_s_code_t;
#else
#error "instruction set architecture error"
#endif

/*
 *	The types of supplemental data references
 */

typedef enum {SU_STRING, 		/* character string reference */
		SU_BYTESTREAM,		/* bytestream data reference */
		SU_RES2,
		SU_RES3} suenum;
/*
 *	Supplemental data references. These follow status codes that have
 *	nonzero sup_count fields. The supplemental data references can
 *	currently be either a string reference or a bytestream data reference.
 *	In both cases the reference simply contains an offset into the
 *	sdata array (string) or tdata array (bytestream). This struct must be
 *	the size of an int.
 */

#if defined(__sparc)
typedef struct {
	suenum type: 3;			/* the supplemental data type */
	unsigned short reserved: 13;	/* unused, reserved */
	unsigned short offset:	16;	/* the sudata array offset of the */
					/* start of the supplemental data */
					/* or the tdata array offset for */
					/* bytestream data */
} spcs_s_sudata_t;
#elif defined(__i386) || (__amd64)
typedef struct {
	unsigned short offset:	16;	/* the sudata array offset of the */
					/* start of the supplemental data */
					/* or the tdata array offset for */
					/* bytestream data */
	unsigned short reserved: 13;	/* unused, reserved */
	suenum type: 3;			/* the supplemental data type */
} spcs_s_sudata_t;
#else
#error "instruction set architecture error"
#endif

/*
 *	Although bytestream data pointers are only used in the kernel layer
 *	and are converted to offsets prior to unistat data being made available
 *	to userspace (i.e. this never comes back via an ioctl), it is critical
 *	to keep the unistat data structure spcs_s_pinfo_t a constant size
 *	whether or not we're using LP64 or a 32 bit model. So we put the
 *	pointer in a union with a long long so it is fixed at 64 bits in size.
 *
 *	Prior to being transported through a pipe, unistat data containing
 *	tdata items (see below) must have its pointers eliminated. The pointers
 *	are simply nulled out and the actual bytestream data is sent out the
 *	pipe following the spcs_s_pinfo_t in the same order as its references
 *	in the sequential tdata elements.
 */

typedef union {
	uchar_t *data;			/* the pointer to the bytestream data */
	long long _fix_the_size;
} _fixed_char_pointer_t;

/*
 *	The bytestream data descriptor in a tdata array element
 */

typedef struct {
	uint32_t size;			/* byte size of the bytestream data */
	_fixed_char_pointer_t u_p;	/* union containing pointer inside */
					/* fixed length field */
} spcs_s_tdesc_t;

/*
 *	All the types that can occupy an idata array element.
 */

typedef union {
	spcs_s_status_t s;	/* as the public status type */
	spcs_s_code_t f;	/* as the internal status type */
	spcs_s_sudata_t su;	/* the supplemental data reference type */
	int i;			/* as integer: TEMPORARY */
} spcs_s_udata_t;

/*
 *	The number of idata array elements. This is the upper bound for the
 *	total status codes and supplemental data reference items that can be
 *	held by unistat at one time. It is IMPORTANT that this array be large
 *	enough to hold all the status and references for the worst case path
 *	through core software. This is currently trivial to do by inspection
 *	of the ioctl service code. However once unistat usage is deployed to
 *	the underlying layers of core software below the ioctl service call
 *	layer it may require special tools to validate this.
 */

#define	SPCS_S_IDSIZE	16		/* size of idata array */
/*
 *	The number of sdata array elements. This is the upper bound for the
 *	total characters of string data added to the unistat structure as
 *	supplemental info. Same cautions as for SPCS_S_IDSIZE.
 */

#define	SPCS_S_SDSIZE	512		/* size of sdata array */
/*
 *	The number of tdata array elements. This is the upper bound for the
 *	total bytestream data descriptors that can be held by unistat at one
 *	time. Same cautions as for SPCS_S_IDSIZE.
 */

#define	SPCS_S_TDSIZE	2		/* size of tdata array */

/*
 *	The Unistat private data structure. This is pointed to by the
 *	public opaque pointer spcs_s_info_t and holds all the status codes
 *	and supplemental data references. String data is also stored here
 *	but the body of bytestream data is stored elsewhere (see below).
 *
 *	If there is real concern about the overhead of ioctl copyouts they
 *	could be optimized such that only the scalars and the "used" elements
 *	of the idata, sdata and tdata arrays are moved. If this is done it is
 *	recommended that the scalars (i.e. major through spare) be moved into
 *	a structure to cut down on the chance of a coding error with manual
 *	size arithmetic.
 *
 *	The major and minor revs are currently supperfulous since unistat and
 *	all of its clients are contained within the same private consolidation.
 *	There is an assertion to BLOW UP if mismatched major revisions are
 *	detected between the kernel and user layers. If the consolidation
 *	policies of core software are relaxed in the future the assertion must
 *	be replaced by code designed to do something intelligent if possible.
 *
 */

#pragma pack()
typedef struct {
				/* The next two fields must stay shorts and */
				/* stay at the front and in this order */
				/* "forever" */
	short major;		/* Major unistat revision */
	short minor;		/* Minor unistat revision */
				/* this define should obviously never change */
#define	SPCS_S_REVSIZE (sizeof (short) + sizeof (short))
	short icount;		/* Number of items currently stored in idata */
				/* and the "next" index to store a new item */
				/* into */
	short scount;		/* Number of items currently stored in sdata */
				/* and the "next" index to store a new item */
				/* into */
	short tcount;		/* Number of items currently stored in tdata */
				/* and the "next" index to store a new item */
				/* into */
	short spare;		/* Unused, reserved */
	spcs_s_udata_t idata[SPCS_S_IDSIZE]; /* the status info and supp refs */
	char sdata[SPCS_S_SDSIZE]; /* the supplemental string data pool. */
				/* the supplemental bytestream data pool. */
	spcs_s_tdesc_t tdata[SPCS_S_TDSIZE];
} spcs_s_pinfo_t;

/*
 *	Module codes. These can be in any order except that Solaris MUST BE
 *	FIRST.
 */

enum 	{SPCS_M_Solaris,	/* Solaris module */
	SPCS_M_SPCS,		/* SPCS "module" (for codes that apply across */
				/* all controller modules */
	SPCS_M_DSW,		/* InstantImage Module */
	SPCS_M_SV,		/* Storage Volume Module */
	SPCS_M_RDC,		/* Remote Dual Copy Module */
	SPCS_M_SDBC,		/* Storage Device Block Cache Module */
	SPCS_M_STE,		/* SCSI Target Emulation Module */
	SPCS_M_SDCTL,		/* Storage Device Control Module */
	SPCS_M_MC,		/* Memory Channel Module */
	SPCS_M_SIMCKD,		/* CKD Simulation (SIMCKD) Module */
	SPCS_M_NVM};		/* Non-Volatile Memory Module */

#define	SPCS_M_MAX SPCS_M_NVM /* Highest defined module code */

/*
 *	The SPCS general status values
 */

/* the module name spellings */

#define	SPCS_M_NSOL	"SOLARIS"
#define	SPCS_M_NSPCS	"SPCS"
#define	SPCS_M_NDSW	"II"
#define	SPCS_M_NSV	"SV"
#define	SPCS_M_NRDC	"SNDR"
#define	SPCS_M_NSDBC	"SDBC"
#define	SPCS_M_NSTE	"STE"
#define	SPCS_M_NSDCTL	"NSCTL"
#define	SPCS_M_NMC	"MC"
#define	SPCS_M_NSIM	"SIMCKD"
#define	SPCS_M_NNVM	"NVM"

/* limits */

#define	SPCS_S_MAXKEY	256		/* max msg key length */
#define	SPCS_S_MAXTEXT	SPCS_S_MAXLINE	/* max msg text length */
#define	SPCS_S_MAXSIG	32		/* max format data signature length */
#define	SPCS_S_MAXPRE	32		/* max module prefix length */
#define	SPCS_S_MAXMODNAME	16	/* max module name length */

/* the module names in a lookup array */
#if !defined(_KERNEL)
static char *module_names[] = {SPCS_M_NSOL, SPCS_M_NSPCS, SPCS_M_NDSW,
	SPCS_M_NSV, SPCS_M_NRDC, SPCS_M_NSDBC, SPCS_M_NSTE, SPCS_M_NSDCTL,
	SPCS_M_NMC, SPCS_M_NSIM, SPCS_M_NNVM, NULL};
#endif

#ifdef __cplusplus
}
#endif

#endif /* _SPCS_S_IMPL_H */
