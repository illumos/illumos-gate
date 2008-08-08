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

#ifndef	_SYS_SCSI_ADAPTERS_BLK2SCSA_H
#define	_SYS_SCSI_ADAPTERS_BLK2SCSA_H

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct b2s_nexus_info b2s_nexus_info_t;
typedef struct b2s_leaf_info b2s_leaf_info_t;
typedef struct b2s_media b2s_media_t;
typedef struct b2s_inquiry b2s_inquiry_t;
typedef struct b2s_request b2s_request_t;
typedef struct b2s_nexus b2s_nexus_t;
typedef struct b2s_leaf b2s_leaf_t;

struct b2s_media {
	uint64_t	media_blksz;
	uint64_t	media_nblks;
	uint64_t	media_flags;
};
#define	B2S_MEDIA_FLAG_READ_ONLY	(1U << 1)
#define	B2S_MEDIA_FLAG_LOCKED		(1U << 2)


struct b2s_inquiry {
	const char	*inq_vendor;
	const char	*inq_product;
	const char	*inq_revision;
	const char	*inq_serial;
};

struct b2s_nexus_info {
	int		nexus_version;
	dev_info_t	*nexus_dip;
	void		*nexus_private;
	ddi_dma_attr_t	*nexus_dma_attr;
	boolean_t	(*nexus_request)(void *, b2s_request_t *);
};

struct b2s_leaf_info {
	uint_t		leaf_target;
	uint_t		leaf_lun;
	uint32_t	leaf_flags;
	const char	*leaf_unique_id;
};

#define	B2S_LEAF_REMOVABLE	(1U << 0)
#define	B2S_LEAF_HOTPLUGGABLE	(1U << 1)
/* these values reserved! */
#define	B2S_LEAF_DETACHED	(1U << 16)

typedef enum {
	B2S_CMD_GETMEDIA = 0,	/* get content */
	B2S_CMD_FORMAT = 1,	/* format media */
	B2S_CMD_START = 2,	/* spin up */
	B2S_CMD_STOP = 3,	/* spin down */
	B2S_CMD_LOCK = 4,	/* lock media door */
	B2S_CMD_UNLOCK = 5,	/* unlock media door */
	B2S_CMD_READ = 6,	/* read blocks */
	B2S_CMD_WRITE = 7,	/* write blocks */
	B2S_CMD_SYNC = 8,	/* flush write cache */
	B2S_CMD_INQUIRY = 9,	/* inquiry data */
	B2S_CMD_RESET = 10,	/* reset of bus */
	B2S_CMD_ABORT = 11,	/* abort inflight commands */
} b2s_cmd_t;

typedef enum {
	B2S_EOK = 0,		/* success */
	B2S_ENOTSUP = 1,	/* operation not sup */
	B2S_EFORMATTING = 2,	/* busy formatting */
	B2S_ENOMEDIA = 3,	/* media not mounted */
	B2S_EMEDIACHG = 4,	/* media changed */
	B2S_ESTOPPED = 5,	/* unit not started */
	B2S_EBLKADDR = 6,	/* blkno invalid */
	B2S_EIO = 7,		/* general failure */
	B2S_EHARDWARE = 8,	/* hardware error */
	B2S_ENODEV = 9,		/* hardware removed */
	B2S_EMEDIA = 10,	/* media problem */
	B2S_EDOORLOCK = 11,	/* door lock engaged */
	B2S_EWPROTECT = 12,	/* write protected */
	B2S_ESTARTING = 13,	/* unit spinning up */
	B2S_ETIMEDOUT = 14,	/* request timed out */
	B2S_ENOMEM = 15,	/* out of memory */
	B2S_ERESET = 16,	/* reset aborted command */
	B2S_EABORT = 17,	/* aborted command */

	/* these are framework internal use only */
	B2S_ERSVD = 18,		/* unit reserved */
	B2S_EINVAL = 19,	/* invalid parameter */
	B2S_EPARAM = 20,	/* bad parameter */
	B2S_EBADMSG = 21,	/* malformed message */
	B2S_ENOSAV = 22,	/* no saveable parms */

	/* used internally for array sizing, must be last */
	B2S_NERRS = 23
} b2s_err_t;

#define	B2S_REQUEST_FLAG_POLL		(1U << 0)	/* use polled io */
#define	B2S_REQUEST_FLAG_HEAD		(1U << 1)
#define	B2S_REQUEST_FLAG_DONE		(1U << 2)
#define	B2S_REQUEST_FLAG_LOAD_EJECT	(1U << 3)	/* for start/stop */
#define	B2S_REQUEST_FLAG_IMMED		(1U << 4)	/* get status immed */
/* framework internal flags */
#define	B2S_REQUEST_FLAG_BLKS		(1U << 16)	/* block-oriented */
#define	B2S_REQUEST_FLAG_MAPIN		(1U << 17)	/* bp_mapin done */

struct b2s_request {
	b2s_cmd_t		br_cmd;
	b2s_err_t		br_errno;
	uint_t			br_target;
	uint_t			br_lun;
	uint32_t		br_flags;

	/* note that this member should come last for future expansion */
	union {
		uint64_t	a_ints[3];
		b2s_media_t	a_media;
		b2s_inquiry_t	a_inquiry;
	} br_args;
};
#define	br_lba			br_args.a_ints[0]
#define	br_nblks		br_args.a_ints[1]
#define	br_media		br_args.a_media
#define	br_inquiry		br_args.a_inquiry


int b2s_mod_init(struct modlinkage *);
void b2s_mod_fini(struct modlinkage *);

/* used as version to alloc_hba */
#define	B2S_VERSION_0	0

b2s_nexus_t *b2s_alloc_nexus(b2s_nexus_info_t *);
void b2s_free_nexus(b2s_nexus_t *);
int b2s_attach_nexus(b2s_nexus_t *);
int b2s_detach_nexus(b2s_nexus_t *);

b2s_leaf_t *b2s_attach_leaf(b2s_nexus_t *, b2s_leaf_info_t *);
void b2s_detach_leaf(b2s_leaf_t *);

/*
 * Address information.
 */
void b2s_request_mapin(b2s_request_t *, caddr_t *, size_t *);
void b2s_request_dma(b2s_request_t *, uint_t *, ddi_dma_cookie_t **);
void b2s_request_done(b2s_request_t *, b2s_err_t, size_t);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_SCSI_ADAPTERS_BLK2SCSA_H */
