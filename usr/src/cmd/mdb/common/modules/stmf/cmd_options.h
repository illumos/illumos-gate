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
#ifndef _CMD_OPTIONS_H
#define	_CMD_OPTIONS_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct find_options {
	uint8_t	lpname[8];	/* local port name (port wwn) */
	uint8_t	lpname_defined;

	uint8_t	rpname[8];	/* remote port name */
	uint8_t	rpname_defined;

	void *	rp;		/* stmf_remote_port_t pointer */
	uint8_t	rp_defined;

	uint8_t	show_task_flags:1,
		show_lport:1;
} find_option_t;

extern struct find_options *parse_options(int argc, const mdb_arg_t *argv);

#ifdef	__cplusplus
}
#endif

#endif /* _CMD_OPTIONS_H */
