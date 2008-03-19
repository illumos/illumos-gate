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

#ifndef	_MAIN_H
#define	_MAIN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include "device.h"
#include <hal/libhal.h>

extern int debug;

extern int		use_media_stated_capacity;
extern int		keep_disc_open;
extern int		requested_speed;
extern int		simulation;
extern int		verbose;
extern char		*image_file;
extern char		*blanking_type;
extern int		audio_type;
extern cd_device	*target;		/* Default target device */
extern int		extract_track_no;
extern char		*extract_file;
extern char		*alt_tmp_dir;
extern char		*copy_src;
extern int		vol_running;
extern int		cflag, tflag;
extern uid_t		ruid, cur_uid;
extern int		device_type;
extern int		write_mode;

typedef enum {DBUS_CONNECTION, HAL_CONTEXT, HAL_PAIRED,
    HAL_INITIALIZED} hal_state_t;

#define	TAO_MODE	0
#define	DAO_MODE	1	/* not implemented for CD yet only DVD */

#define	CD_RW		1		/* CD_RW/CD-R	*/
#define	DVD_MINUS	2		/* DVD-RW/DVD-R	*/

/*
 * DVD+RW is listed differently from DVD+R since DVD+RW requires
 * that we format the media prior to writing, this cannot be
 * done for DVD+R since it is write once media, we treat the
 * media as pre-formatted.
 */
#define	DVD_PLUS	3		/* DVD+R	*/
#define	DVD_PLUS_W	4		/* DVD+RW	*/

#define	ALL		0	/* erase the complete media, slow */
#define	FAST		1	/* only erases the leadin and TOC */
#define	SESSION		6	/* erases the last session */
#define	LEADOUT		5	/* erases the leadout of the media */
#define	CLEAR		1	/* same as fast, used for fixing media */

#define	HAL_RDSK_PROP	"block.solaris.raw_device"
#define	HAL_SYMDEV_PROP	"storage.solaris.legacy.symdev"

int setup_target(int flag);

int hald_running(void);
LibHalContext *attach_to_hald(void);
void detach_from_hald(LibHalContext *ctx, hal_state_t state);

void info(void);
void list(void);
void write_image(void);
void blank(void);
void write_audio(char **argv, int start_argc, int argc);
void extract_audio(void);
void copy_cd(void);

#ifdef	__cplusplus
}
#endif

#endif /* _MAIN_H */
