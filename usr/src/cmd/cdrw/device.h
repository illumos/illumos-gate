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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DEVICE_H
#define	_DEVICE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

#include "bstream.h"

#define	DEFAULT_CAPACITY	(74*60*75)

#define	DEV_CAP_EXTRACT_CDDA			1
#define	DEV_CAP_ACCURATE_CDDA			2
#define	DEV_CAP_SETTING_SPEED_NOT_ALLOWED	4

typedef struct _device {
	char		*d_node;
	char		*d_name;
	int		d_fd;
	uint_t		d_blksize;
	uchar_t		*d_inq;
	uint32_t	d_cap;
	int		(*d_read_audio)(struct _device *dev, uint_t start_blk,
			    uint_t nblks, uchar_t *buf);
	int		(*d_speed_ctrl)(struct _device *dev, int cmd,
			    int speed);
} cd_device;

/*
 * Speed commands
 */
#define	GET_READ_SPEED	1
#define	SET_READ_SPEED	2
#define	GET_WRITE_SPEED	3
#define	SET_WRITE_SPEED	4

#define	SCAN_ALL_CDS		0x00	/* scan and return all cd devices */
#define	SCAN_WRITERS		0x01	/* select only writable devices */
#define	SCAN_LISTDEVS		0x02	/* print out device listing */

#define	DVD_CONFIG_SIZE		0x20

cd_device *get_device(char *user_supplied, char *node);
int lookup_device(char *supplied, char *found);
void fini_device(cd_device *dev);
int scan_for_cd_device(int mode, cd_device **found);
void write_next_track(int mode, bstreamhandle h);
int check_device(cd_device *dev, int cond);
void get_media_type(int fd);

#ifdef	__cplusplus
}
#endif

#endif /* _DEVICE_H */
