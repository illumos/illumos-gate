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

#ifndef	_MENU_H
#define	_MENU_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file contains declarations pertaining to the menus.
 */
/*
 * This structure defines a menu entry.  It consists of a command
 * name, the function to run the command, and a function to determine
 * if the menu entry is enabled at this particular state in the program.
 * The descriptive text that appears after the command name in the menus
 * is actually part of the command name to the program.  Since
 * abbreviation is allowed for commands, the user never notices the
 * extra characters.
 */
struct menu_item {
	char	*menu_cmd;
	int	(*menu_func)();
	int	(*menu_state)();
};


/*
 *	Prototypes for ANSI C compilers
 */

char	**create_menu_list(struct menu_item *menu);
void	display_menu_list(char **list);
void	redisplay_menu_list(char **list);
void	run_menu(struct menu_item *, char *, char *, int);
int	true(void);
int	embedded_scsi(void);
int	not_embedded_scsi(void);
int	not_scsi(void);
int	not_efi(void);
int	disp_expert_change_expert_efi(void);
int	disp_expand_efi(void);
int	disp_all_change_expert_efi(void);
int	scsi(void);
int	scsi_expert(void);
int	expert(void);
int	developer(void);
int	support_fdisk_on_sparc(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _MENU_H */
