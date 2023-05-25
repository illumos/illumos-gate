/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 RackTop Systems, Inc.
 */

#ifndef _SMBADM_H
#define	_SMBADM_H

/*
 * Declarations private to the smbadm command
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Commands in smbinfo.c */
extern int cmd_list_sess(int, char **);
extern int cmd_list_trees(int, char **);
extern int cmd_list_ofiles(int, char **);
extern int cmd_close_sess(int, char **);
extern int cmd_close_ofile(int, char **);

#ifdef __cplusplus
}
#endif

#endif /* _SMBADM_H */
