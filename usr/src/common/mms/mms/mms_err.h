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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MMS_ERR_H
#define	_MMS_ERR_H


enum mms_err_type {
	MMS_ERR_SYS = 1,	/* errno */
	MMS_ERR_GAI,		/* get address info error */
	MMS_ERR_SSL		/* ssl error */
};
typedef enum mms_err_type mms_err_type_t; /* contents of error number */

typedef struct mms_err mms_err_t;
struct mms_err {
	mms_err_type_t	mms_type;	/* which error string func to use */
	int		mms_id;		/* mms error code */
	ulong_t		mms_num;	/* errno or ssl error number */
};

void mms_get_error_string(mms_err_t *err, char *ebuf, int ebuflen);


#endif /* _MMS_ERR_H */
