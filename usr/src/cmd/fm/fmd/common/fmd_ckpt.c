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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>

#include <strings.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>

#include <fmd_module.h>
#include <fmd_error.h>
#include <fmd_alloc.h>
#include <fmd_case.h>
#include <fmd_serd.h>
#include <fmd_subr.h>
#include <fmd_conf.h>
#include <fmd_event.h>
#include <fmd_log.h>
#include <fmd_api.h>
#include <fmd_ckpt.h>

#include <fmd.h>

#define	P2ROUNDUP(x, align)	(-(-(x) & -(align)))
#define	IS_P2ALIGNED(v, a)	((((uintptr_t)(v)) & ((uintptr_t)(a) - 1)) == 0)

/*
 * The fmd_ckpt_t structure is used to manage all of the state needed by the
 * various subroutines that save and restore checkpoints.  The structure is
 * initialized using fmd_ckpt_create() or fmd_ckpt_open() and is destroyed
 * by fmd_ckpt_destroy().  Refer to the subroutines below for more details.
 */
typedef struct fmd_ckpt {
	char ckp_src[PATH_MAX];	/* ckpt input or output filename */
	char ckp_dst[PATH_MAX];	/* ckpt rename filename */
	uchar_t *ckp_buf;	/* data buffer base address */
	fcf_hdr_t *ckp_hdr;	/* file header pointer */
	uchar_t *ckp_ptr;	/* data buffer pointer */
	size_t ckp_size;	/* data buffer size */
	fcf_sec_t *ckp_secp;	/* section header table pointer */
	fcf_sec_t *ckp_modp;	/* section header for module */
	uint_t ckp_secs;	/* number of sections */
	char *ckp_strs;		/* string table base pointer */
	char *ckp_strp;		/* string table pointer */
	size_t ckp_strn;	/* string table size */
	int ckp_fd;		/* output descriptor */
	fmd_module_t *ckp_mp;	/* checkpoint module */
	void *ckp_arg;		/* private arg for callbacks */
} fmd_ckpt_t;

typedef struct fmd_ckpt_desc {
	uint64_t secd_size;	/* minimum section size */
	uint32_t secd_entsize;	/* minimum section entry size */
	uint32_t secd_align;	/* section alignment */
} fmd_ckpt_desc_t;

/*
 * Table of FCF section descriptions.  Here we record the minimum size for each
 * section (for use during restore) and the expected entry size and alignment
 * for each section (for use during both checkpoint and restore).
 */
static const fmd_ckpt_desc_t _fmd_ckpt_sections[] = {
{ 0, 0, sizeof (uint8_t) },					   /* NONE */
{ 1, 0, sizeof (char) },					   /* STRTAB */
{ sizeof (fcf_module_t), 0, sizeof (uint32_t) },		   /* MODULE */
{ sizeof (fcf_case_t), 0, sizeof (uint32_t) },			   /* CASE */
{ sizeof (fcf_buf_t), sizeof (fcf_buf_t), sizeof (uint32_t) },	   /* BUFS */
{ 0, 0, _MAX_ALIGNMENT },					   /* BUFFER */
{ sizeof (fcf_serd_t), sizeof (fcf_serd_t), sizeof (uint64_t) },   /* SERD */
{ sizeof (fcf_event_t), sizeof (fcf_event_t), sizeof (uint64_t) }, /* EVENTS */
{ sizeof (fcf_nvl_t), sizeof (fcf_nvl_t), sizeof (uint64_t) },	   /* NVLISTS */
};

static int
fmd_ckpt_create(fmd_ckpt_t *ckp, fmd_module_t *mp)
{
	const char *dir = mp->mod_ckpt;
	const char *name = mp->mod_name;
	mode_t mode;

	bzero(ckp, sizeof (fmd_ckpt_t));
	ckp->ckp_mp = mp;

	ckp->ckp_size = sizeof (fcf_hdr_t);
	ckp->ckp_strn = 1; /* for \0 */

	(void) snprintf(ckp->ckp_src, PATH_MAX, "%s/%s+", dir, name);
	(void) snprintf(ckp->ckp_dst, PATH_MAX, "%s/%s", dir, name);

	(void) unlink(ckp->ckp_src);
	(void) fmd_conf_getprop(fmd.d_conf, "ckpt.mode", &mode);
	ckp->ckp_fd = open64(ckp->ckp_src, O_WRONLY | O_CREAT | O_EXCL, mode);

	return (ckp->ckp_fd);
}

/*PRINTFLIKE2*/
static int
fmd_ckpt_inval(fmd_ckpt_t *ckp, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	fmd_verror(EFMD_CKPT_INVAL, format, ap);
	va_end(ap);

	fmd_free(ckp->ckp_buf, ckp->ckp_size);
	return (fmd_set_errno(EFMD_CKPT_INVAL));
}

static int
fmd_ckpt_open(fmd_ckpt_t *ckp, fmd_module_t *mp)
{
	struct stat64 st;
	uint64_t seclen;
	uint_t i;
	int err;

	bzero(ckp, sizeof (fmd_ckpt_t));
	ckp->ckp_mp = mp;

	(void) snprintf(ckp->ckp_src, PATH_MAX, "%s/%s",
	    mp->mod_ckpt, mp->mod_name);

	if ((ckp->ckp_fd = open(ckp->ckp_src, O_RDONLY)) == -1)
		return (-1); /* failed to open checkpoint file */

	if (fstat64(ckp->ckp_fd, &st) == -1) {
		err = errno;
		(void) close(ckp->ckp_fd);
		return (fmd_set_errno(err));
	}

	ckp->ckp_buf = fmd_alloc(st.st_size, FMD_SLEEP);
	ckp->ckp_hdr = (void *)ckp->ckp_buf;
	ckp->ckp_size = read(ckp->ckp_fd, ckp->ckp_buf, st.st_size);

	if (ckp->ckp_size != st.st_size || ckp->ckp_size < sizeof (fcf_hdr_t) ||
	    ckp->ckp_size != ckp->ckp_hdr->fcfh_filesz) {
		err = ckp->ckp_size == (size_t)-1L ? errno : EFMD_CKPT_SHORT;
		fmd_free(ckp->ckp_buf, st.st_size);
		(void) close(ckp->ckp_fd);
		return (fmd_set_errno(err));
	}

	(void) close(ckp->ckp_fd);
	ckp->ckp_fd = -1;

	/*
	 * Once we've read in a consistent copy of the FCF file and we're sure
	 * the header can be accessed, go through it and make sure everything
	 * is valid.  We also check that unused bits are zero so we can expand
	 * to use them safely in the future and support old files if needed.
	 */
	if (bcmp(&ckp->ckp_hdr->fcfh_ident[FCF_ID_MAG0],
	    FCF_MAG_STRING, FCF_MAG_STRLEN) != 0)
		return (fmd_ckpt_inval(ckp, "bad checkpoint magic string\n"));

	if (ckp->ckp_hdr->fcfh_ident[FCF_ID_MODEL] != FCF_MODEL_NATIVE)
		return (fmd_ckpt_inval(ckp, "bad checkpoint data model\n"));

	if (ckp->ckp_hdr->fcfh_ident[FCF_ID_ENCODING] != FCF_ENCODE_NATIVE)
		return (fmd_ckpt_inval(ckp, "bad checkpoint data encoding\n"));

	if (ckp->ckp_hdr->fcfh_ident[FCF_ID_VERSION] != FCF_VERSION_1) {
		return (fmd_ckpt_inval(ckp, "bad checkpoint version %u\n",
		    ckp->ckp_hdr->fcfh_ident[FCF_ID_VERSION]));
	}

	for (i = FCF_ID_PAD; i < FCF_ID_SIZE; i++) {
		if (ckp->ckp_hdr->fcfh_ident[i] != 0) {
			return (fmd_ckpt_inval(ckp,
			    "bad checkpoint padding at id[%d]", i));
		}
	}

	if (ckp->ckp_hdr->fcfh_flags & ~FCF_FL_VALID)
		return (fmd_ckpt_inval(ckp, "bad checkpoint flags\n"));

	if (ckp->ckp_hdr->fcfh_pad != 0)
		return (fmd_ckpt_inval(ckp, "reserved field in use\n"));

	if (ckp->ckp_hdr->fcfh_hdrsize < sizeof (fcf_hdr_t) ||
	    ckp->ckp_hdr->fcfh_secsize < sizeof (fcf_sec_t)) {
		return (fmd_ckpt_inval(ckp,
		    "bad header and/or section size\n"));
	}

	seclen = (uint64_t)ckp->ckp_hdr->fcfh_secnum *
	    (uint64_t)ckp->ckp_hdr->fcfh_secsize;

	if (ckp->ckp_hdr->fcfh_secoff > ckp->ckp_size ||
	    seclen > ckp->ckp_size ||
	    ckp->ckp_hdr->fcfh_secoff + seclen > ckp->ckp_size ||
	    ckp->ckp_hdr->fcfh_secoff + seclen < ckp->ckp_hdr->fcfh_secoff)
		return (fmd_ckpt_inval(ckp, "truncated section headers\n"));

	if (!IS_P2ALIGNED(ckp->ckp_hdr->fcfh_secoff, sizeof (uint64_t)) ||
	    !IS_P2ALIGNED(ckp->ckp_hdr->fcfh_secsize, sizeof (uint64_t)))
		return (fmd_ckpt_inval(ckp, "misaligned section headers\n"));

	/*
	 * Once the header is validated, iterate over the section headers
	 * ensuring that each one is valid w.r.t. offset, alignment, and size.
	 * We also pick up the string table pointer during this pass.
	 */
	ckp->ckp_secp = (void *)(ckp->ckp_buf + ckp->ckp_hdr->fcfh_secoff);
	ckp->ckp_secs = ckp->ckp_hdr->fcfh_secnum;

	for (i = 0; i < ckp->ckp_secs; i++) {
		fcf_sec_t *sp = (void *)(ckp->ckp_buf +
		    ckp->ckp_hdr->fcfh_secoff + ckp->ckp_hdr->fcfh_secsize * i);

		const fmd_ckpt_desc_t *dp = &_fmd_ckpt_sections[sp->fcfs_type];

		if (sp->fcfs_flags != 0) {
			return (fmd_ckpt_inval(ckp, "section %u has invalid "
			    "section flags (0x%x)\n", i, sp->fcfs_flags));
		}

		if (sp->fcfs_align & (sp->fcfs_align - 1)) {
			return (fmd_ckpt_inval(ckp, "section %u has invalid "
			    "alignment (%u)\n", i, sp->fcfs_align));
		}

		if (sp->fcfs_offset & (sp->fcfs_align - 1)) {
			return (fmd_ckpt_inval(ckp, "section %u is not properly"
			    " aligned (offset %llu)\n", i, sp->fcfs_offset));
		}

		if (sp->fcfs_entsize != 0 &&
		    (sp->fcfs_entsize & (sp->fcfs_align - 1)) != 0) {
			return (fmd_ckpt_inval(ckp, "section %u has misaligned "
			    "entsize %u\n", i, sp->fcfs_entsize));
		}

		if (sp->fcfs_offset > ckp->ckp_size ||
		    sp->fcfs_size > ckp->ckp_size ||
		    sp->fcfs_offset + sp->fcfs_size > ckp->ckp_size ||
		    sp->fcfs_offset + sp->fcfs_size < sp->fcfs_offset) {
			return (fmd_ckpt_inval(ckp, "section %u has corrupt "
			    "size or offset\n", i));
		}

		if (sp->fcfs_type >= sizeof (_fmd_ckpt_sections) /
		    sizeof (_fmd_ckpt_sections[0])) {
			return (fmd_ckpt_inval(ckp, "section %u has unknown "
			    "section type %u\n", i, sp->fcfs_type));
		}

		if (sp->fcfs_align != dp->secd_align) {
			return (fmd_ckpt_inval(ckp, "section %u has align %u "
			    "(not %u)\n", i, sp->fcfs_align, dp->secd_align));
		}

		if (sp->fcfs_size < dp->secd_size ||
		    sp->fcfs_entsize < dp->secd_entsize) {
			return (fmd_ckpt_inval(ckp, "section %u has short "
			    "size or entsize\n", i));
		}

		switch (sp->fcfs_type) {
		case FCF_SECT_STRTAB:
			if (ckp->ckp_strs != NULL) {
				return (fmd_ckpt_inval(ckp, "multiple string "
				    "tables are present in checkpoint file\n"));
			}

			ckp->ckp_strs = (char *)ckp->ckp_buf + sp->fcfs_offset;
			ckp->ckp_strn = sp->fcfs_size;

			if (ckp->ckp_strs[ckp->ckp_strn - 1] != '\0') {
				return (fmd_ckpt_inval(ckp, "string table %u "
				    "is missing terminating nul byte\n", i));
			}
			break;

		case FCF_SECT_MODULE:
			if (ckp->ckp_modp != NULL) {
				return (fmd_ckpt_inval(ckp, "multiple module "
				    "sects are present in checkpoint file\n"));
			}
			ckp->ckp_modp = sp;
			break;
		}
	}

	/*
	 * Ensure that the first section is an empty one of type FCF_SECT_NONE.
	 * This is done to ensure that links can use index 0 as a null section.
	 */
	if (ckp->ckp_secs == 0 || ckp->ckp_secp->fcfs_type != FCF_SECT_NONE ||
	    ckp->ckp_secp->fcfs_entsize != 0 || ckp->ckp_secp->fcfs_size != 0) {
		return (fmd_ckpt_inval(ckp, "section 0 is not of the "
		    "appropriate size and/or attributes (SECT_NONE)\n"));
	}

	if (ckp->ckp_modp == NULL) {
		return (fmd_ckpt_inval(ckp,
		    "no module section found in file\n"));
	}

	return (0);
}

static void
fmd_ckpt_destroy(fmd_ckpt_t *ckp)
{
	if (ckp->ckp_buf != NULL)
		fmd_free(ckp->ckp_buf, ckp->ckp_size);
	if (ckp->ckp_fd >= 0)
		(void) close(ckp->ckp_fd);
}

/*
 * fmd_ckpt_error() is used as a wrapper around fmd_error() for ckpt routines.
 * It calls fmd_module_unlock() on behalf of its caller, logs the error, and
 * then aborts the API call and the surrounding module entry point by doing an
 * fmd_module_abort(), which longjmps to the place where we entered the module.
 * Depending on the type of error and conf settings, we will reset or fail.
 */
/*PRINTFLIKE3*/
static void
fmd_ckpt_error(fmd_ckpt_t *ckp, int err, const char *format, ...)
{
	fmd_module_t *mp = ckp->ckp_mp;
	va_list ap;

	va_start(ap, format);
	fmd_verror(err, format, ap);
	va_end(ap);

	if (fmd_module_locked(mp))
		fmd_module_unlock(mp);

	fmd_ckpt_destroy(ckp);
	fmd_module_abort(mp, err);
}

static fcf_secidx_t
fmd_ckpt_section(fmd_ckpt_t *ckp, const void *data, uint_t type, uint64_t size)
{
	const fmd_ckpt_desc_t *dp;

	ASSERT(type < sizeof (_fmd_ckpt_sections) / sizeof (fmd_ckpt_desc_t));
	dp = &_fmd_ckpt_sections[type];

	ckp->ckp_ptr = (uchar_t *)
	    P2ROUNDUP((uintptr_t)ckp->ckp_ptr, dp->secd_align);

	ckp->ckp_secp->fcfs_type = type;
	ckp->ckp_secp->fcfs_align = dp->secd_align;
	ckp->ckp_secp->fcfs_flags = 0;
	ckp->ckp_secp->fcfs_entsize = dp->secd_entsize;
	ckp->ckp_secp->fcfs_offset = (size_t)(ckp->ckp_ptr - ckp->ckp_buf);
	ckp->ckp_secp->fcfs_size = size;

	/*
	 * If the data pointer is non-NULL, copy the data to our buffer; else
	 * the caller is responsible for doing so and updating ckp->ckp_ptr.
	 */
	if (data != NULL) {
		bcopy(data, ckp->ckp_ptr, size);
		ckp->ckp_ptr += size;
	}

	ckp->ckp_secp++;
	return (ckp->ckp_secs++);
}

static fcf_stridx_t
fmd_ckpt_string(fmd_ckpt_t *ckp, const char *s)
{
	fcf_stridx_t idx = (fcf_stridx_t)(ckp->ckp_strp - ckp->ckp_strs);

	(void) strcpy(ckp->ckp_strp, s);
	ckp->ckp_strp += strlen(s) + 1;

	return (idx);
}

static int
fmd_ckpt_alloc(fmd_ckpt_t *ckp, uint64_t gen)
{
	/*
	 * We've added up all the sections by now: add two more for SECT_NONE
	 * and SECT_STRTAB, and add the size of the section header table and
	 * string table to the total size.  We know that the fcf_hdr_t is
	 * aligned so that that fcf_sec_t's can follow it, and that fcf_sec_t
	 * is aligned so that any section can follow it, so no extra padding
	 * bytes need to be allocated between any of these items.
	 */
	ckp->ckp_secs += 2; /* for FCF_SECT_NONE and FCF_SECT_STRTAB */
	ckp->ckp_size += sizeof (fcf_sec_t) * ckp->ckp_secs;
	ckp->ckp_size += ckp->ckp_strn;

	TRACE((FMD_DBG_CKPT, "alloc fcf buf size %u", ckp->ckp_size));
	ckp->ckp_buf = fmd_zalloc(ckp->ckp_size, FMD_NOSLEEP);

	if (ckp->ckp_buf == NULL)
		return (-1); /* errno is set for us */

	ckp->ckp_hdr = (void *)ckp->ckp_buf;

	ckp->ckp_hdr->fcfh_ident[FCF_ID_MAG0] = FCF_MAG_MAG0;
	ckp->ckp_hdr->fcfh_ident[FCF_ID_MAG1] = FCF_MAG_MAG1;
	ckp->ckp_hdr->fcfh_ident[FCF_ID_MAG2] = FCF_MAG_MAG2;
	ckp->ckp_hdr->fcfh_ident[FCF_ID_MAG3] = FCF_MAG_MAG3;
	ckp->ckp_hdr->fcfh_ident[FCF_ID_MODEL] = FCF_MODEL_NATIVE;
	ckp->ckp_hdr->fcfh_ident[FCF_ID_ENCODING] = FCF_ENCODE_NATIVE;
	ckp->ckp_hdr->fcfh_ident[FCF_ID_VERSION] = FCF_VERSION;

	ckp->ckp_hdr->fcfh_hdrsize = sizeof (fcf_hdr_t);
	ckp->ckp_hdr->fcfh_secsize = sizeof (fcf_sec_t);
	ckp->ckp_hdr->fcfh_secnum = ckp->ckp_secs;
	ckp->ckp_hdr->fcfh_secoff = sizeof (fcf_hdr_t);
	ckp->ckp_hdr->fcfh_filesz = ckp->ckp_size;
	ckp->ckp_hdr->fcfh_cgen = gen;

	ckp->ckp_secs = 0; /* reset section counter for second pass */
	ckp->ckp_secp = (void *)(ckp->ckp_buf + sizeof (fcf_hdr_t));
	ckp->ckp_strs = (char *)ckp->ckp_buf + ckp->ckp_size - ckp->ckp_strn;
	ckp->ckp_strp = ckp->ckp_strs + 1; /* use first byte as \0 */
	ckp->ckp_ptr = (uchar_t *)(ckp->ckp_secp + ckp->ckp_hdr->fcfh_secnum);

	(void) fmd_ckpt_section(ckp, NULL, FCF_SECT_NONE, 0);
	return (0);
}

static int
fmd_ckpt_commit(fmd_ckpt_t *ckp)
{
	fcf_sec_t *secbase = (void *)(ckp->ckp_buf + sizeof (fcf_hdr_t));
	size_t stroff = ckp->ckp_size - ckp->ckp_strn;

	/*
	 * Before committing the checkpoint, we assert that fmd_ckpt_t's sizes
	 * and current pointer locations all add up appropriately.  Any ASSERTs
	 * which trip here likely indicate an inconsistency in the code for the
	 * reservation pass and the buffer update pass of the FCF subroutines.
	 */
	ASSERT((size_t)(ckp->ckp_ptr - ckp->ckp_buf) == stroff);
	(void) fmd_ckpt_section(ckp, NULL, FCF_SECT_STRTAB, ckp->ckp_strn);
	ckp->ckp_ptr += ckp->ckp_strn; /* string table is already filled in */

	ASSERT(ckp->ckp_secs == ckp->ckp_hdr->fcfh_secnum);
	ASSERT(ckp->ckp_secp == secbase + ckp->ckp_hdr->fcfh_secnum);
	ASSERT(ckp->ckp_ptr == ckp->ckp_buf + ckp->ckp_hdr->fcfh_filesz);

	if (write(ckp->ckp_fd, ckp->ckp_buf, ckp->ckp_size) != ckp->ckp_size ||
	    fsync(ckp->ckp_fd) != 0 || close(ckp->ckp_fd) != 0)
		return (-1); /* errno is set for us */

	ckp->ckp_fd = -1; /* fd is now closed */
	return (rename(ckp->ckp_src, ckp->ckp_dst) != 0);
}

static void
fmd_ckpt_resv(fmd_ckpt_t *ckp, size_t size, size_t align)
{
	if (size != 0) {
		ckp->ckp_size = P2ROUNDUP(ckp->ckp_size, align) + size;
		ckp->ckp_secs++;
	}
}

static void
fmd_ckpt_resv_buf(fmd_buf_t *bp, fmd_ckpt_t *ckp)
{
	ckp->ckp_size = P2ROUNDUP(ckp->ckp_size, _MAX_ALIGNMENT) + bp->buf_size;
	ckp->ckp_strn += strlen(bp->buf_name) + 1;
	ckp->ckp_secs++;
}

static void
fmd_ckpt_save_buf(fmd_buf_t *bp, fmd_ckpt_t *ckp)
{
	fcf_buf_t *fcfb = ckp->ckp_arg;

	fcfb->fcfb_name = fmd_ckpt_string(ckp, bp->buf_name);
	fcfb->fcfb_data = fmd_ckpt_section(ckp,
	    bp->buf_data, FCF_SECT_BUFFER, bp->buf_size);

	ckp->ckp_arg = fcfb + 1;
}

static void
fmd_ckpt_save_event(fmd_ckpt_t *ckp, fmd_event_t *e)
{
	fcf_event_t *fcfe = (void *)ckp->ckp_ptr;
	fmd_event_impl_t *ep = (fmd_event_impl_t *)e;
	fmd_log_t *lp = ep->ev_log;

	fcfe->fcfe_todsec = ep->ev_time.ftv_sec;
	fcfe->fcfe_todnsec = ep->ev_time.ftv_nsec;
	fcfe->fcfe_major = lp ? major(lp->log_stat.st_dev) : -1U;
	fcfe->fcfe_minor = lp ? minor(lp->log_stat.st_dev) : -1U;
	fcfe->fcfe_inode = lp ? lp->log_stat.st_ino : -1ULL;
	fcfe->fcfe_offset = ep->ev_off;

	ckp->ckp_ptr += sizeof (fcf_event_t);
}

static void
fmd_ckpt_save_nvlist(fmd_ckpt_t *ckp, nvlist_t *nvl)
{
	fcf_nvl_t *fcfn = (void *)ckp->ckp_ptr;
	char *nvbuf = (char *)ckp->ckp_ptr + sizeof (fcf_nvl_t);
	size_t nvsize = 0;

	(void) nvlist_size(nvl, &nvsize, NV_ENCODE_NATIVE);
	fcfn->fcfn_size = (uint64_t)nvsize;

	(void) nvlist_pack(nvl, &nvbuf, &nvsize, NV_ENCODE_NATIVE, 0);
	ckp->ckp_ptr += sizeof (fcf_nvl_t) + nvsize;

	ckp->ckp_ptr = (uchar_t *)
	    P2ROUNDUP((uintptr_t)ckp->ckp_ptr, sizeof (uint64_t));
}

static void
fmd_ckpt_resv_serd(fmd_serd_eng_t *sgp, fmd_ckpt_t *ckp)
{
	fmd_ckpt_resv(ckp,
	    sizeof (fcf_event_t) * sgp->sg_count, sizeof (uint64_t));

	ckp->ckp_strn += strlen(sgp->sg_name) + 1;
}

static void
fmd_ckpt_save_serd(fmd_serd_eng_t *sgp, fmd_ckpt_t *ckp)
{
	fcf_serd_t *fcfd = ckp->ckp_arg;
	fcf_secidx_t evsec = FCF_SECT_NONE;
	fmd_serd_elem_t *sep;

	if (sgp->sg_count != 0) {
		evsec = fmd_ckpt_section(ckp, NULL, FCF_SECT_EVENTS,
		    sizeof (fcf_event_t) * sgp->sg_count);

		for (sep = fmd_list_next(&sgp->sg_list);
		    sep != NULL; sep = fmd_list_next(sep))
			fmd_ckpt_save_event(ckp, sep->se_event);
	}

	fcfd->fcfd_name = fmd_ckpt_string(ckp, sgp->sg_name);
	fcfd->fcfd_events = evsec;
	fcfd->fcfd_pad = 0;
	fcfd->fcfd_n = sgp->sg_n;
	fcfd->fcfd_t = sgp->sg_t;

	ckp->ckp_arg = fcfd + 1;
}

static void
fmd_ckpt_resv_case(fmd_ckpt_t *ckp, fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_susp_t *cis;
	uint_t n;

	if (cip->ci_xprt != NULL)
		return; /* do not checkpoint cases from remote transports */

	n = fmd_buf_hash_count(&cip->ci_bufs);
	fmd_buf_hash_apply(&cip->ci_bufs, (fmd_buf_f *)fmd_ckpt_resv_buf, ckp);
	fmd_ckpt_resv(ckp, sizeof (fcf_buf_t) * n, sizeof (uint32_t));

	if (cip->ci_principal != NULL)
		fmd_ckpt_resv(ckp, sizeof (fcf_event_t), sizeof (uint64_t));

	fmd_ckpt_resv(ckp,
	    sizeof (fcf_event_t) * cip->ci_nitems, sizeof (uint64_t));

	if (cip->ci_nsuspects != 0)
		ckp->ckp_size = P2ROUNDUP(ckp->ckp_size, sizeof (uint64_t));

	cip->ci_nvsz = 0; /* compute size of packed suspect nvlist array */

	for (cis = cip->ci_suspects; cis != NULL; cis = cis->cis_next) {
		size_t nvsize = 0;

		(void) nvlist_size(cis->cis_nvl, &nvsize, NV_ENCODE_NATIVE);
		cip->ci_nvsz += sizeof (fcf_nvl_t) + nvsize;
		cip->ci_nvsz = P2ROUNDUP(cip->ci_nvsz, sizeof (uint64_t));
	}

	fmd_ckpt_resv(ckp, cip->ci_nvsz, sizeof (uint64_t));
	fmd_ckpt_resv(ckp, sizeof (fcf_case_t), sizeof (uint32_t));
	ckp->ckp_strn += strlen(cip->ci_uuid) + 1;
}

static void
fmd_ckpt_save_case(fmd_ckpt_t *ckp, fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	fmd_case_item_t *cit;
	fmd_case_susp_t *cis;
	fcf_case_t fcfc;
	uint_t n;

	fcf_secidx_t bufsec = FCF_SECIDX_NONE;
	fcf_secidx_t evsec = FCF_SECIDX_NONE;
	fcf_secidx_t nvsec = FCF_SECIDX_NONE;
	fcf_secidx_t prsec = FCF_SECIDX_NONE;

	if (cip->ci_xprt != NULL)
		return; /* do not checkpoint cases from remote transports */

	if ((n = fmd_buf_hash_count(&cip->ci_bufs)) != 0) {
		size_t size = sizeof (fcf_buf_t) * n;
		fcf_buf_t *bufs = ckp->ckp_arg = fmd_alloc(size, FMD_SLEEP);

		fmd_buf_hash_apply(&cip->ci_bufs,
		    (fmd_buf_f *)fmd_ckpt_save_buf, ckp);

		bufsec = fmd_ckpt_section(ckp, bufs, FCF_SECT_BUFS, size);
		fmd_free(bufs, size);
	}

	if (cip->ci_principal != NULL) {
		prsec = fmd_ckpt_section(ckp, NULL, FCF_SECT_EVENTS,
		    sizeof (fcf_event_t));

		fmd_ckpt_save_event(ckp, cip->ci_principal);
	}

	if (cip->ci_nitems != 0) {
		evsec = fmd_ckpt_section(ckp, NULL, FCF_SECT_EVENTS,
		    sizeof (fcf_event_t) * cip->ci_nitems);

		for (cit = cip->ci_items; cit != NULL; cit = cit->cit_next)
			fmd_ckpt_save_event(ckp, cit->cit_event);
	}

	if (cip->ci_nsuspects != 0) {
		nvsec = fmd_ckpt_section(ckp, NULL,
		    FCF_SECT_NVLISTS, cip->ci_nvsz);

		for (cis = cip->ci_suspects; cis != NULL; cis = cis->cis_next)
			fmd_ckpt_save_nvlist(ckp, cis->cis_nvl);
	}

	fcfc.fcfc_uuid = fmd_ckpt_string(ckp, cip->ci_uuid);
	fcfc.fcfc_bufs = bufsec;
	fcfc.fcfc_principal = prsec;
	fcfc.fcfc_events = evsec;
	fcfc.fcfc_suspects = nvsec;

	switch (cip->ci_state) {
	case FMD_CASE_UNSOLVED:
		fcfc.fcfc_state = FCF_CASE_UNSOLVED;
		break;
	case FMD_CASE_SOLVED:
		fcfc.fcfc_state = FCF_CASE_SOLVED;
		break;
	case FMD_CASE_CLOSE_WAIT:
		fcfc.fcfc_state = FCF_CASE_CLOSE_WAIT;
		break;
	default:
		fmd_panic("case %p (%s) has invalid state %u",
		    (void *)cp, cip->ci_uuid, cip->ci_state);
	}

	(void) fmd_ckpt_section(ckp, &fcfc, FCF_SECT_CASE, sizeof (fcf_case_t));
}

static void
fmd_ckpt_resv_module(fmd_ckpt_t *ckp, fmd_module_t *mp)
{
	fmd_case_t *cp;
	uint_t n;

	for (cp = fmd_list_next(&mp->mod_cases); cp; cp = fmd_list_next(cp))
		fmd_ckpt_resv_case(ckp, cp);

	n = fmd_serd_hash_count(&mp->mod_serds);
	fmd_serd_hash_apply(&mp->mod_serds,
	    (fmd_serd_eng_f *)fmd_ckpt_resv_serd, ckp);
	fmd_ckpt_resv(ckp, sizeof (fcf_serd_t) * n, sizeof (uint64_t));

	n = fmd_buf_hash_count(&mp->mod_bufs);
	fmd_buf_hash_apply(&mp->mod_bufs, (fmd_buf_f *)fmd_ckpt_resv_buf, ckp);
	fmd_ckpt_resv(ckp, sizeof (fcf_buf_t) * n, sizeof (uint32_t));

	fmd_ckpt_resv(ckp, sizeof (fcf_module_t), sizeof (uint32_t));
	ckp->ckp_strn += strlen(mp->mod_name) + 1;
	ckp->ckp_strn += strlen(mp->mod_path) + 1;
	ckp->ckp_strn += strlen(mp->mod_info->fmdi_desc) + 1;
	ckp->ckp_strn += strlen(mp->mod_info->fmdi_vers) + 1;
}

static void
fmd_ckpt_save_module(fmd_ckpt_t *ckp, fmd_module_t *mp)
{
	fcf_secidx_t bufsec = FCF_SECIDX_NONE;
	fcf_module_t fcfm;
	fmd_case_t *cp;
	uint_t n;

	for (cp = fmd_list_next(&mp->mod_cases); cp; cp = fmd_list_next(cp))
		fmd_ckpt_save_case(ckp, cp);

	if ((n = fmd_serd_hash_count(&mp->mod_serds)) != 0) {
		size_t size = sizeof (fcf_serd_t) * n;
		fcf_serd_t *serds = ckp->ckp_arg = fmd_alloc(size, FMD_SLEEP);

		fmd_serd_hash_apply(&mp->mod_serds,
		    (fmd_serd_eng_f *)fmd_ckpt_save_serd, ckp);

		(void) fmd_ckpt_section(ckp, serds, FCF_SECT_SERD, size);
		fmd_free(serds, size);
	}

	if ((n = fmd_buf_hash_count(&mp->mod_bufs)) != 0) {
		size_t size = sizeof (fcf_buf_t) * n;
		fcf_buf_t *bufs = ckp->ckp_arg = fmd_alloc(size, FMD_SLEEP);

		fmd_buf_hash_apply(&mp->mod_bufs,
		    (fmd_buf_f *)fmd_ckpt_save_buf, ckp);

		bufsec = fmd_ckpt_section(ckp, bufs, FCF_SECT_BUFS, size);
		fmd_free(bufs, size);
	}

	fcfm.fcfm_name = fmd_ckpt_string(ckp, mp->mod_name);
	fcfm.fcfm_path = fmd_ckpt_string(ckp, mp->mod_path);
	fcfm.fcfm_desc = fmd_ckpt_string(ckp, mp->mod_info->fmdi_desc);
	fcfm.fcfm_vers = fmd_ckpt_string(ckp, mp->mod_info->fmdi_vers);
	fcfm.fcfm_bufs = bufsec;

	(void) fmd_ckpt_section(ckp, &fcfm,
	    FCF_SECT_MODULE, sizeof (fcf_module_t));
}

void
fmd_ckpt_save(fmd_module_t *mp)
{
	struct stat64 st;
	char path[PATH_MAX];
	mode_t dirmode;

	hrtime_t now = gethrtime();
	fmd_ckpt_t ckp;
	int err;

	ASSERT(fmd_module_locked(mp));

	/*
	 * If checkpointing is disabled for the module, just return.  We must
	 * commit the module state anyway to transition pending log events.
	 */
	if (mp->mod_stats->ms_ckpt_save.fmds_value.bool == FMD_B_FALSE) {
		fmd_module_commit(mp);
		return;
	}

	if (!(mp->mod_flags & (FMD_MOD_MDIRTY | FMD_MOD_CDIRTY)))
		return; /* no checkpoint is necessary for this module */

	TRACE((FMD_DBG_CKPT, "ckpt save begin %s %llu",
	    mp->mod_name, mp->mod_gen + 1));

	/*
	 * If the per-module checkpoint directory isn't found or isn't of type
	 * directory, move aside whatever is there (if anything) and attempt
	 * to mkdir(2) a new module checkpoint directory.  If this fails, we
	 * have no choice but to abort the checkpoint and try again later.
	 */
	if (stat64(mp->mod_ckpt, &st) != 0 || !S_ISDIR(st.st_mode)) {
		(void) snprintf(path, sizeof (path), "%s-", mp->mod_ckpt);
		(void) rename(mp->mod_ckpt, path);
		(void) fmd_conf_getprop(fmd.d_conf, "ckpt.dirmode", &dirmode);

		if (mkdir(mp->mod_ckpt, dirmode) != 0) {
			fmd_error(EFMD_CKPT_MKDIR,
			    "failed to mkdir %s", mp->mod_ckpt);
			return; /* return without clearing dirty bits */
		}
	}

	/*
	 * Create a temporary file to write out the checkpoint into, and create
	 * a fmd_ckpt_t structure to manage construction of the checkpoint.  We
	 * then figure out how much space will be required, and allocate it.
	 */
	if (fmd_ckpt_create(&ckp, mp) == -1) {
		fmd_error(EFMD_CKPT_CREATE, "failed to create %s", ckp.ckp_src);
		return;
	}

	fmd_ckpt_resv_module(&ckp, mp);

	if (fmd_ckpt_alloc(&ckp, mp->mod_gen + 1) != 0) {
		fmd_error(EFMD_CKPT_NOMEM, "failed to build %s", ckp.ckp_src);
		fmd_ckpt_destroy(&ckp);
		return;
	}

	/*
	 * Fill in the checkpoint content, write it to disk, sync it, and then
	 * atomically rename it to the destination path.  If this fails, we
	 * have no choice but to leave all our dirty bits set and return.
	 */
	fmd_ckpt_save_module(&ckp, mp);
	err = fmd_ckpt_commit(&ckp);
	fmd_ckpt_destroy(&ckp);

	if (err != 0) {
		fmd_error(EFMD_CKPT_COMMIT, "failed to commit %s", ckp.ckp_dst);
		return; /* return without clearing dirty bits */
	}

	fmd_module_commit(mp);
	TRACE((FMD_DBG_CKPT, "ckpt save end %s", mp->mod_name));

	mp->mod_stats->ms_ckpt_cnt.fmds_value.ui64++;
	mp->mod_stats->ms_ckpt_time.fmds_value.ui64 += gethrtime() - now;

	fmd_dprintf(FMD_DBG_CKPT, "saved checkpoint of %s (%llu)\n",
	    mp->mod_name, mp->mod_gen);
}

/*
 * Utility function to retrieve a pointer to a section's header and verify that
 * it is of the expected type or it is a FCF_SECT_NONE reference.
 */
static const fcf_sec_t *
fmd_ckpt_secptr(fmd_ckpt_t *ckp, fcf_secidx_t sid, uint_t type)
{
	const fcf_sec_t *sp = (void *)(ckp->ckp_buf +
	    ckp->ckp_hdr->fcfh_secoff + ckp->ckp_hdr->fcfh_secsize * sid);

	return (sid < ckp->ckp_secs && (sp->fcfs_type == type ||
	    sp->fcfs_type == FCF_SECT_NONE) ? sp : NULL);
}

/*
 * Utility function to retrieve the data pointer for a particular section.  The
 * validity of the header values has already been checked by fmd_ckpt_open().
 */
static const void *
fmd_ckpt_dataptr(fmd_ckpt_t *ckp, const fcf_sec_t *sp)
{
	return (ckp->ckp_buf + sp->fcfs_offset);
}

/*
 * Utility function to retrieve the end of the data region for a particular
 * section.  The validity of this value has been confirmed by fmd_ckpt_open().
 */
static const void *
fmd_ckpt_datalim(fmd_ckpt_t *ckp, const fcf_sec_t *sp)
{
	return (ckp->ckp_buf + sp->fcfs_offset + sp->fcfs_size);
}

/*
 * Utility function to retrieve a string pointer (fcf_stridx_t).  If the string
 * index is valid, the string data is returned; otherwise 'defstr' is returned.
 */
static const char *
fmd_ckpt_strptr(fmd_ckpt_t *ckp, fcf_stridx_t sid, const char *defstr)
{
	return (sid < ckp->ckp_strn ? ckp->ckp_strs + sid : defstr);
}

static void
fmd_ckpt_restore_events(fmd_ckpt_t *ckp, fcf_secidx_t sid,
    int (*func)(void *, fmd_event_t *), void *arg)
{
	const fcf_event_t *fcfe;
	const fcf_sec_t *sp;
	fmd_timeval_t ftv;
	fmd_log_t *lp, *errlp;
	uint_t i, n;
	uint32_t e_maj, e_min;
	uint64_t e_ino;

	if ((sp = fmd_ckpt_secptr(ckp, sid, FCF_SECT_EVENTS)) == NULL) {
		fmd_ckpt_error(ckp, EFMD_CKPT_INVAL,
		    "invalid link to section %u: expected events\n", sid);
	}

	if (sp->fcfs_size == 0)
		return; /* empty events section or type none */

	fcfe = fmd_ckpt_dataptr(ckp, sp);
	n = sp->fcfs_size / sp->fcfs_entsize;

	/*
	 * Hold the reader lock on log pointers to block log rotation during
	 * the section restore so that we can safely insert refs to d_errlog.
	 */
	(void) pthread_rwlock_rdlock(&fmd.d_log_lock);
	errlp = fmd.d_errlog;

	e_maj = major(errlp->log_stat.st_dev);
	e_min = minor(errlp->log_stat.st_dev);
	e_ino = errlp->log_stat.st_ino;

	for (i = 0; i < n; i++) {
		fmd_event_t *ep;

		ftv.ftv_sec = fcfe->fcfe_todsec;
		ftv.ftv_nsec = fcfe->fcfe_todnsec;

		if (e_ino == fcfe->fcfe_inode &&
		    e_maj == fcfe->fcfe_major &&
		    e_min == fcfe->fcfe_minor)
			lp = errlp;
		else
			lp = NULL;

		ep = fmd_event_recreate(FMD_EVT_PROTOCOL,
		    &ftv, NULL, NULL, lp, fcfe->fcfe_offset, 0);
		fmd_event_hold(ep);
		(void) func(arg, ep);
		fmd_event_rele(ep);

		fcfe = (fcf_event_t *)((uintptr_t)fcfe + sp->fcfs_entsize);
	}

	(void) pthread_rwlock_unlock(&fmd.d_log_lock);
}

static int
fmd_ckpt_restore_suspects(fmd_ckpt_t *ckp, fmd_case_t *cp, fcf_secidx_t sid)
{
	const fcf_nvl_t *fcfn, *endn;
	const fcf_sec_t *sp;
	nvlist_t *nvl;
	int err, i;

	if ((sp = fmd_ckpt_secptr(ckp, sid, FCF_SECT_NVLISTS)) == NULL) {
		fmd_ckpt_error(ckp, EFMD_CKPT_INVAL,
		    "invalid link to section %u: expected nvlists\n", sid);
	}

	fcfn = fmd_ckpt_dataptr(ckp, sp);
	endn = fmd_ckpt_datalim(ckp, sp);

	for (i = 0; fcfn < endn; i++) {
		char *data = (char *)fcfn + sp->fcfs_entsize;
		size_t size = (size_t)fcfn->fcfn_size;

		if (fcfn->fcfn_size > (size_t)((char *)endn - data)) {
			fmd_ckpt_error(ckp, EFMD_CKPT_INVAL, "nvlist %u [%d] "
			    "size %u exceeds buffer\n", sid, i, size);
		}

		if ((err = nvlist_xunpack(data, size, &nvl, &fmd.d_nva)) != 0) {
			fmd_ckpt_error(ckp, EFMD_CKPT_INVAL, "failed to "
			    "unpack nvlist %u [%d]: %s\n", sid, i,
			    fmd_strerror(err));
		}

		fmd_case_insert_suspect(cp, nvl);

		size = sp->fcfs_entsize + fcfn->fcfn_size;
		size = P2ROUNDUP(size, sizeof (uint64_t));
		fcfn = (fcf_nvl_t *)((uintptr_t)fcfn + size);
	}

	return (i);
}

static void
fmd_ckpt_restore_bufs(fmd_ckpt_t *ckp, fmd_module_t *mp,
    fmd_case_t *cp, fcf_secidx_t sid)
{
	const fcf_sec_t *sp, *dsp;
	const fcf_buf_t *fcfb;
	uint_t i, n;

	if ((sp = fmd_ckpt_secptr(ckp, sid, FCF_SECT_BUFS)) == NULL) {
		fmd_ckpt_error(ckp, EFMD_CKPT_INVAL,
		    "invalid link to section %u: expected bufs\n", sid);
	}

	if (sp->fcfs_size == 0)
		return; /* empty events section or type none */

	fcfb = fmd_ckpt_dataptr(ckp, sp);
	n = sp->fcfs_size / sp->fcfs_entsize;

	for (i = 0; i < n; i++) {
		dsp = fmd_ckpt_secptr(ckp, fcfb->fcfb_data, FCF_SECT_BUFFER);

		if (dsp == NULL) {
			fmd_ckpt_error(ckp, EFMD_CKPT_INVAL, "invalid %u "
			    "buffer link %u\n", sid, fcfb->fcfb_data);
		}

		fmd_buf_write((fmd_hdl_t *)mp, cp,
		    fmd_ckpt_strptr(ckp, fcfb->fcfb_name, "<CORRUPT>"),
		    ckp->ckp_buf + dsp->fcfs_offset, dsp->fcfs_size);

		fcfb = (fcf_buf_t *)((uintptr_t)fcfb + sp->fcfs_entsize);
	}
}

static void
fmd_ckpt_restore_case(fmd_ckpt_t *ckp, fmd_module_t *mp, const fcf_sec_t *sp)
{
	const fcf_case_t *fcfc = fmd_ckpt_dataptr(ckp, sp);
	const char *uuid = fmd_ckpt_strptr(ckp, fcfc->fcfc_uuid, NULL);
	fmd_case_t *cp;
	int n;

	if (uuid == NULL || fcfc->fcfc_state > FCF_CASE_CLOSE_WAIT) {
		fmd_ckpt_error(ckp, EFMD_CKPT_INVAL, "corrupt %u case uuid "
		    "and/or state\n", (uint_t)(sp - ckp->ckp_secp));
	}

	fmd_module_lock(mp);

	if ((cp = fmd_case_recreate(mp, NULL,
	    fcfc->fcfc_state != FCF_CASE_UNSOLVED ? FCF_CASE_SOLVED :
	    FMD_CASE_UNSOLVED, uuid, NULL)) == NULL) {
		fmd_ckpt_error(ckp, EFMD_CKPT_INVAL,
		    "duplicate case uuid: %s\n", uuid);
	}

	fmd_ckpt_restore_events(ckp, fcfc->fcfc_principal,
	    fmd_case_insert_principal, cp);

	fmd_ckpt_restore_events(ckp, fcfc->fcfc_events,
	    fmd_case_insert_event, cp);

	/*
	 * Once solved, treat suspects from resource cache as master copy.
	 *
	 * If !fmd.d_running, this module must be a builtin, and so we don't
	 * want to restore suspects or call fmd_case_transition_update() at this
	 * stage. The suspects will be added later from the resource cache.
	 * Calling fmd_case_transition("SOLVED") is OK here as the state is
	 * already solved, so all it does is update the case flags.
	 */
	if (fmd.d_running && (n = ((fmd_case_impl_t *)cp)->ci_nsuspects) == 0)
		n = fmd_ckpt_restore_suspects(ckp, cp, fcfc->fcfc_suspects);

	if (!fmd.d_running)
		fmd_case_transition(cp, FMD_CASE_SOLVED, FMD_CF_SOLVED);
	else if (fcfc->fcfc_state == FCF_CASE_SOLVED)
		fmd_case_transition_update(cp, FMD_CASE_SOLVED, FMD_CF_SOLVED);
	else if (fcfc->fcfc_state == FCF_CASE_CLOSE_WAIT && n != 0)
		fmd_case_transition(cp, FMD_CASE_CLOSE_WAIT, FMD_CF_SOLVED);
	else if (fcfc->fcfc_state == FCF_CASE_CLOSE_WAIT && n == 0)
		fmd_case_transition(cp, FMD_CASE_CLOSE_WAIT, 0);

	fmd_module_unlock(mp);
	fmd_ckpt_restore_bufs(ckp, mp, cp, fcfc->fcfc_bufs);
}

static void
fmd_ckpt_restore_serd(fmd_ckpt_t *ckp, fmd_module_t *mp, const fcf_sec_t *sp)
{
	const fcf_serd_t *fcfd = fmd_ckpt_dataptr(ckp, sp);
	uint_t i, n = sp->fcfs_size / sp->fcfs_entsize;
	const fcf_sec_t *esp;
	const char *s;

	for (i = 0; i < n; i++) {
		esp = fmd_ckpt_secptr(ckp, fcfd->fcfd_events, FCF_SECT_EVENTS);

		if (esp == NULL) {
			fmd_ckpt_error(ckp, EFMD_CKPT_INVAL,
			    "invalid events link %u\n", fcfd->fcfd_events);
		}

		if ((s = fmd_ckpt_strptr(ckp, fcfd->fcfd_name, NULL)) == NULL) {
			fmd_ckpt_error(ckp, EFMD_CKPT_INVAL,
			    "serd name %u is corrupt\n", fcfd->fcfd_name);
		}

		fmd_serd_create((fmd_hdl_t *)mp, s, fcfd->fcfd_n, fcfd->fcfd_t);
		fmd_module_lock(mp);

		fmd_ckpt_restore_events(ckp, fcfd->fcfd_events,
		    fmd_serd_eng_record,
		    fmd_serd_eng_lookup(&mp->mod_serds, s));

		fmd_module_unlock(mp);
		fcfd = (fcf_serd_t *)((uintptr_t)fcfd + sp->fcfs_entsize);
	}
}

static void
fmd_ckpt_restore_module(fmd_ckpt_t *ckp, fmd_module_t *mp)
{
	const fcf_module_t *fcfm = fmd_ckpt_dataptr(ckp, ckp->ckp_modp);
	const fcf_sec_t *sp;
	uint_t i;

	if (strcmp(mp->mod_name, fmd_ckpt_strptr(ckp, fcfm->fcfm_name, "")) ||
	    strcmp(mp->mod_path, fmd_ckpt_strptr(ckp, fcfm->fcfm_path, ""))) {
		fmd_ckpt_error(ckp, EFMD_CKPT_INVAL,
		    "checkpoint is not for module %s\n", mp->mod_name);
	}

	for (i = 0; i < ckp->ckp_secs; i++) {
		sp = (void *)(ckp->ckp_buf +
		    ckp->ckp_hdr->fcfh_secoff + ckp->ckp_hdr->fcfh_secsize * i);

		switch (sp->fcfs_type) {
		case FCF_SECT_CASE:
			fmd_ckpt_restore_case(ckp, mp, sp);
			break;
		case FCF_SECT_SERD:
			fmd_ckpt_restore_serd(ckp, mp, sp);
			break;
		}
	}

	fmd_ckpt_restore_bufs(ckp, mp, NULL, fcfm->fcfm_bufs);
	mp->mod_gen = ckp->ckp_hdr->fcfh_cgen;
}

/*
 * Restore a checkpoint for the specified module.  Any errors which occur
 * during restore will call fmd_ckpt_error() or trigger an fmd_api_error(),
 * either of which will automatically unlock the module and trigger an abort.
 */
void
fmd_ckpt_restore(fmd_module_t *mp)
{
	fmd_ckpt_t ckp;

	if (mp->mod_stats->ms_ckpt_restore.fmds_value.bool == FMD_B_FALSE)
		return; /* never restore checkpoints for this module */

	TRACE((FMD_DBG_CKPT, "ckpt restore begin %s", mp->mod_name));

	if (fmd_ckpt_open(&ckp, mp) == -1) {
		if (errno != ENOENT)
			fmd_error(EFMD_CKPT_OPEN, "can't open %s", ckp.ckp_src);
		TRACE((FMD_DBG_CKPT, "ckpt restore end %s", mp->mod_name));
		return;
	}

	ASSERT(!fmd_module_locked(mp));
	fmd_ckpt_restore_module(&ckp, mp);
	fmd_ckpt_destroy(&ckp);
	fmd_module_clrdirty(mp);

	TRACE((FMD_DBG_CKPT, "ckpt restore end %s", mp->mod_name));
	fmd_dprintf(FMD_DBG_CKPT, "restored checkpoint of %s\n", mp->mod_name);
}

/*
 * Delete the module's checkpoint file.  This is used by the ckpt.zero property
 * code or by the fmadm reset RPC service path to force a checkpoint delete.
 */
void
fmd_ckpt_delete(fmd_module_t *mp)
{
	char path[PATH_MAX];

	(void) snprintf(path, sizeof (path),
	    "%s/%s", mp->mod_ckpt, mp->mod_name);

	TRACE((FMD_DBG_CKPT, "delete %s ckpt", mp->mod_name));

	if (unlink(path) != 0 && errno != ENOENT)
		fmd_error(EFMD_CKPT_DELETE, "failed to delete %s", path);
}

/*
 * Move aside the module's checkpoint file if checkpoint restore has failed.
 * We rename the file rather than deleting it in the hopes that someone might
 * send it to us for post-mortem analysis of whether we have a checkpoint bug.
 */
void
fmd_ckpt_rename(fmd_module_t *mp)
{
	char src[PATH_MAX], dst[PATH_MAX];

	(void) snprintf(src, sizeof (src), "%s/%s", mp->mod_ckpt, mp->mod_name);
	(void) snprintf(dst, sizeof (dst), "%s-", src);

	TRACE((FMD_DBG_CKPT, "rename %s ckpt", mp->mod_name));

	if (rename(src, dst) != 0 && errno != ENOENT)
		fmd_error(EFMD_CKPT_DELETE, "failed to rename %s", src);
}
