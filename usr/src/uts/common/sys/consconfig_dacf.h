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

#ifndef	_SYS_CONSCONFIG_DACF_H
#define	_SYS_CONSCONFIG_DACF_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	CONS_MS		1
#define	CONS_KBD	2

/*
 * This structure contains information about keyboard
 * and mouse used for auto-configuration.
 */
typedef struct cons_prop {
	struct cons_prop	*cp_next;
	int			cp_type;
	dev_t			cp_dev;
	int			cp_muxid;
	char			*cp_pushmod;
} cons_prop_t;

/*
 * This structure contains information about the console
 */
typedef struct cons_state {
	char	*cons_keyboard_path;	/* Keyboard path */
	char	*cons_mouse_path;	/* Mouse path */
	char	*cons_stdin_path;	/* Standard input path */
	char	*cons_stdout_path;	/* Standard output path */

	char	*cons_fb_path;		/* Frame Buffer path */

	int	cons_input_type;	/* Type of console input (See below) */
	int	cons_keyboard_problem;	/* problem with console keyboard */

	ldi_ident_t	cons_li;
	vnode_t		*cons_wc_vp;

	ldi_handle_t	conskbd_lh;
	int		conskbd_muxid;

	ldi_handle_t	consms_lh;
	dev_t		consms_dev;

	kmutex_t	cons_lock;

	cons_prop_t	*cons_km_prop;
	int		cons_tem_supported;
	int		cons_stdin_is_kbd;
	int		cons_stdout_is_fb;
	boolean_t	cons_initialized;
} cons_state_t;

/*
 * Types of console input
 */
#define	CONSOLE_LOCAL			0x1	/* keyboard */
#define	CONSOLE_TIP			0x2	/* serial line */
#define	CONSOLE_SERIAL_KEYBOARD		0x4	/* serial kbd */

/*
 * These macros indicate the state of the system while
 * the console configuration is running.
 * CONSCONFIG_BOOTING implies that the driver loading
 * is in process during boot.  CONSCONFIG_DRIVERS_LOADED
 * means that the driver loading during boot has completed.
 *
 * During driver loading while the boot is happening, the
 * keyboard and mouse minor nodes that are hooked into the console
 * stream must match those defined by the firmware.  After boot
 * minor nodes are hooked according to a first come first serve
 * basis.
 */
#define	CONSCONFIG_BOOTING			1
#define	CONSCONFIG_DRIVERS_LOADED		0

/*
 * Debug information
 * Severity levels for printing
 */
#define	DPRINT_L0	0	/* print every message */
#define	DPRINT_L1	1	/* debug */
#define	DPRINT_L2	2	/* minor errors */
#define	DPRINT_L3	3	/* major errors */
#define	DPRINT_L4	4	/* catastrophic errors */

#define	DPRINTF consconfig_dprintf

extern void	kadb_uses_kernel(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CONSCONFIG_DACF_H */
