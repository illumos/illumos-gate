/***************************************************************************
 *
 * cdutils.h : definitions for CD/DVD utilities
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef CDUTILS_H
#define CDUTILS_H

#include <sys/types.h>
#include <sys/dkio.h>
#include <sys/cdio.h>
#include <sys/scsi/impl/uscsi.h>

enum {
	CDUTIL_WALK_CONTINUE,
	CDUTIL_WALK_STOP
};

typedef struct intlist {
	int	val;
	struct intlist *next;
} intlist_t;

typedef struct disc_info {
	int	disc_status;
	int	erasable;
	uint_t	capacity;
} disc_info_t;

#define	min(a, b)	((a) < (b) ? (a) : (b))
#define	max(a, b)	((a) > (b) ? (a) : (b))

void		uscsi_cmd_init(struct uscsi_cmd *scmd, char *cdb, int cdblen);
int		uscsi(int fd, struct uscsi_cmd *scmd);
int		mode_sense(int fd, uchar_t pc, int dbd, int page_len,
		uchar_t *buffer);
int		get_mode_page(int fd, int page_no, int pc, int buf_len,
		uchar_t *buffer, int *plen);
int		get_configuration(int fd, uint16_t feature, int bufsize,
		uchar_t *buf);
boolean_t	get_current_profile(int fd, int *profile);
void		walk_profiles(int fd, int (*f)(void *, int, boolean_t), void *);
void		get_read_write_speeds(int fd, int *read_speed, int *write_speed,
		intlist_t **wspeeds, int *n_wspeeds, intlist_t **wspeeds_mem);
boolean_t	get_disc_info(int fd, disc_info_t *);
boolean_t	read_format_capacity(int fd, uint64_t *capacity);
boolean_t	get_media_info(int fd, struct dk_minfo *minfop);
boolean_t	get_disc_capacity_for_profile(int fd, int profile,
		uint64_t *capacity);
boolean_t	read_toc(int fd, int format, int trackno, int buflen,
		uchar_t *buf);

#endif /* CDUTILS_H */
