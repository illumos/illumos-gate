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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_SCSI_SCSI_FM_H
#define	_SYS_SCSI_SCSI_FM_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * fault management initialization and clean-up:
 * do init/fini from initchild/uninitchild?
 */
void scsi_fm_init(struct scsi_device *);
void scsi_fm_fini(struct scsi_device *);

/* ereport generation: */
void scsi_fm_ereport_post(struct scsi_device *sd, int path_instance,
    char *devpath, const char *error_class, uint64_t ena,
    char *devid, char *tpl0, int sflag, nvlist_t *pl, ...);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_SCSI_FM_H */
