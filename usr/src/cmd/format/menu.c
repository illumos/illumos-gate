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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains routines relating to running the menus.
 */
#include <string.h>
#include "global.h"
#include "menu.h"
#include "misc.h"

#ifdef __STDC__

/* Function prototypes for ANSI C Compilers */
static int	(*find_enabled_menu_item())(struct menu_item *menu, int item);

#else	/* __STDC__ */

/* Function prototypes for non-ANSI C Compilers */
static int	(*find_enabled_menu_item())();

#endif	/* __STDC__ */

static char	cur_title[MAXPATHLEN];

/*
 * This routine takes a menu struct and concatenates the
 * command names into an array of strings describing the menu.
 * All menus have a 'quit' command at the bottom to exit the menu.
 */
char **
create_menu_list(menu)
	struct	menu_item *menu;
{
	register struct menu_item *mptr;
	register char	**cpptr;
	register char	**list;
	int		nitems;

	/*
	 * A minimum list consists of the quit command, followed
	 * by a terminating null.
	 */
	nitems = 2;
	/*
	 * Count the number of active commands in the menu and allocate
	 * space for the array of pointers.
	 */
	for (mptr = menu; mptr->menu_cmd != NULL; mptr++) {
		if ((*mptr->menu_state)())
			nitems++;
	}
	list = (char **)zalloc(nitems * sizeof (char *));
	cpptr = list;
	/*
	 * Fill in the array with the names of the menu commands.
	 */
	for (mptr = menu; mptr->menu_cmd != NULL; mptr++) {
		if ((*mptr->menu_state)()) {
			*cpptr++ = mptr->menu_cmd;
		}
	}
	/*
	 * Add the 'quit' command to the end.
	 */
	*cpptr = "quit";
	return (list);
}

/*
 * This routine takes a menu list created by the above routine and
 * prints it nicely on the screen.
 */
void
display_menu_list(list)
	char	**list;
{
	register char **str;

	for (str = list; *str != NULL; str++)
		fmt_print("        %s\n", *str);
}

/*
 * Find the "i"th enabled menu in a menu list.  This depends
 * on menu_state() returning the same status as when the
 * original list of enabled commands was constructed.
 */
static int (*
find_enabled_menu_item(menu, item))()
	struct menu_item	*menu;
	int			item;
{
	struct menu_item	*mp;

	for (mp = menu; mp->menu_cmd != NULL; mp++) {
		if ((*mp->menu_state)()) {
			if (item-- == 0) {
				return (mp->menu_func);
			}
		}
	}

	return (NULL);
}

/*
 * This routine 'runs' a menu.  It repeatedly requests a command and
 * executes the command chosen.  It exits when the 'quit' command is
 * executed.
 */
/*ARGSUSED*/
void
run_menu(menu, title, prompt, display_flag)
	struct	menu_item *menu;
	char	*title;
	char	*prompt;
	int	display_flag;
{
	char		**list;
	int		i;
	struct		env env;
	u_ioparam_t	ioparam;
	int		(*f)();


	/*
	 * Create the menu list and display it.
	 */
	list = create_menu_list(menu);
	(void) strcpy(cur_title, title);
	fmt_print("\n\n%s MENU:\n", title);
	display_menu_list(list);
	/*
	 * Save the environment so a ctrl-C out of a command lands here.
	 */
	saveenv(env);
	for (;;) {
		/*
		 * Ask the user which command they want to run.
		 */
		ioparam.io_charlist = list;
		i = input(FIO_MSTR, prompt, '>', &ioparam,
		    (int *)NULL, CMD_INPUT);
		/*
		 * If they choose 'quit', the party's over.
		 */
		if ((f = find_enabled_menu_item(menu, i)) == NULL)
			break;

		/*
		 * Mark the saved environment active so the user can now
		 * do a ctrl-C to get out of the command.
		 */
		useenv();
		/*
		 * Run the command.  If it returns an error and we are
		 * running out of a command file, the party's really over.
		 */
		if ((*f)() && option_f)
			fullabort();
		/*
		 * Mark the saved environment inactive so ctrl-C doesn't
		 * work at the menu itself.
		 */
		unuseenv();
		/*
		 * Since menu items are dynamic, some commands
		 * cause changes to occur.  Destroy the old menu,
		 * and rebuild it, so we're always up-to-date.
		 */
		destroy_data((char *)list);
		list = create_menu_list(menu);
		/*
		 * Redisplay menu, if we're returning to this one.
		 */
		if (cur_menu != last_menu) {
			last_menu = cur_menu;
			(void) strcpy(cur_title, title);
			fmt_print("\n\n%s MENU:\n", title);
			display_menu_list(list);
		}
	}
	/*
	 * Clean up the environment stack and throw away the menu list.
	 */
	clearenv();
	destroy_data((char *)list);
}

/*
 * re-display the screen after exiting from shell escape
 *
 */
void
redisplay_menu_list(list)
char **list;
{
	fmt_print("\n\n%s MENU:\n", cur_title);
	display_menu_list(list);
}


/*
 * Glue to always return true.  Used for menu items which
 * are always enabled.
 */
int
true()
{
	return (1);
}

/*
 * Note: The following functions are used to enable the inclusion
 * of device specific options (see init_menus.c). But when we are
 * running non interactively with commands taken from a script file,
 * current disk (cur_disk, cur_type, cur_ctype) may not be defined.
 * They get defined when the script selects a disk using "disk" option
 * in the main menu. However, in the normal interactive mode, the disk
 * selection happens before entering the main menu.
 */
/*
 * Return true for menu items enabled only for embedded SCSI controllers
 */
int
embedded_scsi()
{
	if (cur_ctype == NULL && option_f)
		return (0);
	return (EMBEDDED_SCSI);
}

/*
 * Return false for menu items disabled only for embedded SCSI controllers
 */
int
not_embedded_scsi()
{
	if (cur_ctype == NULL && option_f)
		return (0);
	return (!EMBEDDED_SCSI);
}

/*
 * Return false for menu items disabled for scsi controllers
 */
int
not_scsi()
{
	if (cur_ctype == NULL && option_f)
		return (0);
	return (!SCSI);
}

/*
 * Return false for menu items disabled for efi labels
 */
int
not_efi()
{
	if ((cur_disk == NULL) && option_f)
		return (0);
	if (cur_disk->label_type == L_TYPE_EFI)
		return (0);
	return (1);
}

int
disp_expert_change_expert_efi()
{
	if ((cur_disk == NULL) && option_f)
		return (0);
	if ((cur_disk->label_type == L_TYPE_EFI) && expert_mode)
		return (1);
	if (cur_disk->label_type != L_TYPE_EFI)
		return (1);
	return (0);
}

int
disp_expand_efi()
{
	if ((cur_disk == NULL) && option_f)
		return (0);
	if (cur_disk->label_type != L_TYPE_EFI)
		return (0);
	if (cur_parts == NULL)
		return (0);
	return (1);
}

int
disp_all_change_expert_efi()
{
	if ((cur_disk == NULL) && option_f)
		return (0);
	if ((cur_disk->label_type != L_TYPE_EFI) || (!expert_mode))
		return (0);
	return (1);
}

/*
 * Return true for menu items enabled scsi controllers
 */
int
scsi()
{
	if (cur_ctype == NULL && option_f)
		return (0);
	return (SCSI);
}


/*
 * Return true for menu items enabled if expert mode is enabled
 */
int
scsi_expert()
{
	if (cur_ctype == NULL && option_f)
		return (0);
	return (SCSI && expert_mode);
}

#if	defined(i386)
/*
 * Return true for menu items enabled if expert mode is enabled
 */
int
expert()
{
	return (expert_mode);
}
#endif	/* defined(i386) */

/*
 * Return true for menu items enabled if developer mode is enabled
 */
int
developer()
{
	return (dev_expert);
}

/*
 * For x86, always return true for menu items enabled
 *	since fdisk is already supported on these two platforms.
 * For Sparc, only return true for menu items enabled
 *	if a PCATA disk is selected.
 */
int
support_fdisk_on_sparc()
{
#if defined(sparc)
	/*
	 * If it's a SCSI disk then we don't support fdisk and we
	 * don't need to know the type cause we can ask the disk,
	 * therefore we return true only if we *KNOW* it's an ATA
	 * disk.
	 */
	if (cur_ctype && cur_ctype->ctype_ctype == DKC_PCMCIA_ATA) {
		return (1);
	} else {
		return (0);
	}
#elif defined(i386)
	return (1);
#else
#error  No Platform defined
#endif /* defined(sparc) */

}
