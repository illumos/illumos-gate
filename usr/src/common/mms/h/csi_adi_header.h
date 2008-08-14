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


#ifndef _CSI_ADI_HEADER_
#define	_CSI_ADI_HEADER_


#ifndef _CSI_HEADER_
#include "csi_header.h"
#endif

#define	CSI_ADI_NAME_SIZE	32

typedef struct {
	unsigned char client_name[CSI_ADI_NAME_SIZE];
	unsigned long proc;
} CSI_HANDLE_ADI;

typedef struct {
	unsigned char client_name[CSI_ADI_NAME_SIZE];
	unsigned long proc;
	unsigned int		pid;
	unsigned long seq_num;
} CSI_XID_ADI;


typedef struct {
	CSI_XID_ADI	xid;
	unsigned long	ssi_identifier;
	CSI_SYNTAX	csi_syntax;
	CSI_PROTOCOL	csi_proto;
	CSI_CONNECT	csi_ctype;
	CSI_HANDLE_ADI	csi_handle;
} CSI_HEADER_ADI;

#endif /* _CSI_ADI_HEADER_ */
