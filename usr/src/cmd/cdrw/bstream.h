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

#ifndef	_BSTREAM_H
#define	_BSTREAM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

struct _bstr_hndl {
	int bstr_fd;
	int (*bstr_read)(struct _bstr_hndl *h, uchar_t *buf, off_t size);
	int (*bstr_write)(struct _bstr_hndl *h, uchar_t *buf, off_t size);
	int (*bstr_close)(struct _bstr_hndl *h);
	int (*bstr_size)(struct _bstr_hndl *h, off_t *size);
	void (*bstr_rewind)(struct _bstr_hndl *h);
	void *bstr_private;
};
typedef struct _bstr_hndl *bstreamhandle;

extern int str_errno;
/*
 * str_errno values
 */
#define	STR_ERR_NO_ERR			0
#define	STR_ERR_NO_REG_FILE		1
#define	STR_ERR_NO_READ_STDIN		2
#define	STR_ERR_AU_READ_ERR		3
#define	STR_ERR_AU_UNSUPPORTED_FORMAT	4
#define	STR_ERR_AU_BAD_HEADER		5
#define	STR_ERR_WAV_READ_ERR		6
#define	STR_ERR_WAV_UNSUPPORTED_FORMAT	7
#define	STR_ERR_WAV_BAD_HEADER		8
#define	STR_ERR_ISO_BAD_HEADER		9
#define	STR_ERR_ISO_READ_ERR		10

/*
 * Constants for the ISO 9660 standard
 */
#define	ISO9660_HEADER_SIZE		34816
#define	ISO9660_BOOT_BLOCK_SIZE		32768
#define	ISO9660_PRIMARY_DESC_SIZE	2048
#define	ISO9660_STD_IDENT_OFFSET	1

bstreamhandle open_stdin_read_stream();
bstreamhandle open_file_read_stream(char *file);
bstreamhandle open_iso_read_stream(char *fname);
bstreamhandle open_au_read_stream(char *fname);
bstreamhandle open_wav_read_stream(char *fname);
bstreamhandle open_aur_read_stream(char *fname);
bstreamhandle open_au_write_stream(char *fname);
bstreamhandle open_wav_write_stream(char *fname);
bstreamhandle open_aur_write_stream(char *fname);
bstreamhandle open_file_write_stream(char *fname);
bstreamhandle open_temp_file_stream(void);

char *str_errno_to_string(int serrno);
int check_avail_temp_space(size_t req_size);
char *get_tmp_name(void);

#ifdef	__cplusplus
}
#endif

#endif /* _BSTREAM_H */
