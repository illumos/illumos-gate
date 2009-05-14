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

#pragma	D depends_on module genunix
#pragma	D depends_on module stmf

/*
 * The scsicmd_t structure should be used by providers
 * to represent a SCSI command block (cdb).
 */
typedef struct scsicmd {
	uint64_t ic_len;	/* CDB length */
	uint8_t  *ic_cdb;	/* CDB data */
} scsicmd_t;

/*
 * Translator for scsicmd_t, translating from a scsi_task_t
 */ 
#pragma D binding "1.5" translator
translator scsicmd_t < scsi_task_t *T > {
	ic_len = T->task_cdb_length;
	ic_cdb = T->task_cdb;
};
