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



#ifndef	_CL_QM_
#define	_CL_QM_

#ifndef  _CL_QM_DEFS_
#include "cl_qm_defs.h"
#endif


#ifndef		MAX
#define	 MAX(a, b)  ((a) > (b) ? (a) : (b))
#endif

#ifndef		USHRT_MAX
#define	 USHRT_MAX		65535
#endif

#define	 QM_MAX_REMARK		128

typedef		struct member  {
	struct member  *prev;
	struct member  *next;
	QM_MSTATUS		status;
	ALIGNED_BYTES		data
	[(sizeof (int)) / (sizeof (ALIGNED_BYTES))];
	ALIGNED_BYTES		guard
	[(sizeof (int)) / (sizeof (ALIGNED_BYTES))];
} QM_MEMBER;

typedef		struct  {
	QM_MEMBER	*first;
	QM_MEMBER	*last;
	QM_MID		lowest;
	QM_MID		highest;
	QM_QSTATUS	status;
} QM_QCB;

typedef		struct  {
	QM_STATUS	status;
	QM_QCB		*(qcb [1]);
	ALIGNED_BYTES	remarks
	[(sizeof (int)) / (sizeof (ALIGNED_BYTES))];
} QM_MCB;

extern QM_MCB	*qm_mcb;
QM_MEMBER *cl_qm_create(QM_QCB *qcb, BOOLEAN before,
    QM_MEMBER *member, unsigned short size);
QM_MEMBER *cl_qm_find(QM_QCB *qcb, QM_POS position, QM_MID member);


#endif /* _CL_QM_ */
