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


#ifndef	_CL_QM_DEFS_
#define	_CL_QM_DEFS_

#ifndef _DEFS_
#include "defs.h"
#endif


typedef		unsigned char		BYTE;
typedef		unsigned short		QM_QID;
typedef		unsigned short		QM_MID;


typedef		enum {
	QM_POS_A = 0,
	QM_POS_FIRST,
	QM_POS_LAST,
	QM_POS_PREV,
	QM_POS_NEXT,
	QM_POS_BEFORE,
	QM_POS_AFTER,
	QM_POS_MEMBER,
	QM_POS_Z
} QM_POS;


typedef		struct qm_mstatus {
	QM_MID		mid;

	unsigned short		size;

	time_t		created;
	time_t		modified;


} QM_MSTATUS;


typedef		struct qm_qstatus {
	QM_QID		qid;
	unsigned short		max_members;


	unsigned short		members;

	QM_MID		last;

	time_t		created;
	time_t		modified;
	time_t		audited;
	ALIGNED_BYTES	remarks[(sizeof (int)) / (sizeof (ALIGNED_BYTES))];
} QM_QSTATUS;


typedef		struct qm_status  {
	unsigned short		max_queues;

	unsigned short		queues;

	time_t		created;

	time_t		modified;
	time_t		audited;
	char		*remarks;
} QM_STATUS;


int 		cl_qm_audit(void);
BOOLEAN 	cl_qm_init(unsigned short max_queues, char *remarks);
ALIGNED_BYTES 	cl_qm_maccess(QM_QID queue, QM_MID member);
QM_MID 		cl_qm_mcreate(QM_QID queue, QM_POS position, QM_MID member,
    unsigned short size);
BOOLEAN 	cl_qm_mdelete(QM_QID queue, QM_MID member);
QM_MID 		cl_qm_mlocate(QM_QID queue, QM_POS position, QM_MID member);
QM_MSTATUS	*cl_qm_mstatus(QM_QID queue, QM_MID member);
int 		cl_qm_qaudit(QM_QID queue);
QM_QID 		cl_qm_qcreate(unsigned short max_members, char *remarks);
BOOLEAN 	cl_qm_qdelete(QM_QID queue);
QM_QSTATUS 	*cl_qm_qstatus(QM_QID queue);
QM_STATUS 	*cl_qm_status(void);
BOOLEAN 	cl_qm_term(void);


#endif /* _CL_QM_DEFS_ */
