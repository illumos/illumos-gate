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

#ifndef	_RDCADM_H
#define	_RDCADM_H

#ifdef	__cplusplus
extern "C" {
#endif


#define	MAXQFBAS	0
#define	MAXQITEMS	0
#define	ASYNCTHR	0
#define	AUTOSYNC	-1
#define	AUTOSYNC_OFF	0
#define	AUTOSYNC_ON	1
#define	QBLOCK		0

extern int maxqfbas;
extern int maxqitems;
extern int autosync;
extern int asyncthr;
extern int qblock;

extern char *rdc_decode_flag(int, int);
extern void rdc_err(spcs_s_info_t *status, char *string, ...);
extern void rdc_warn(spcs_s_info_t *status, char *string, ...);
extern int rdc_get_maxsets();
extern int mounted(char *device);
extern int get_cfg_setid(CFGFILE *cfg, char *ctag, char *tohost, char *tofile);
extern int get_new_cfg_setid(CFGFILE *cfg);
extern void get_group_diskq(CFGFILE *cfg, char *group, char *diskq);
extern int find_setnumber_in_libcfg(CFGFILE *, char *, char *, char *);
extern int sv_enable(char *, CFGFILE *, char *);
extern void block_sigs(void);
extern void unblock_sigs(void);

extern char *program;

#ifdef	__cplusplus
}
#endif

#endif	/* _RDCADM_H */
