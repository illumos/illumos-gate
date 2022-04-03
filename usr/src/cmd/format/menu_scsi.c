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

/*
 * This file contains functions implementing the scsi menu commands.
 *
 * These functions are intended for expert use only, and provide
 * a raw access to a scsi device's mode pages.  The ability to
 * issue a raw format command is also provided, should a page be
 * changed that requires a format.
 */
#include "global.h"
#include <stdlib.h>
#include <ctype.h>

#include "io.h"
#include "menu.h"
#include "misc.h"
#include "menu_scsi.h"
#include "ctlr_scsi.h"
#include "startup.h"
#include "checkdev.h"

static int	do_mode_sense(int);
static int	do_mode_sense_all(void);
static int	do_mode_select(struct chg_list *);
static int	do_format(void);
static void	do_list(void);
static int	do_inquiry(void);
static void	do_apply(void);
static void	do_cancel(void);
static void	do_display(void);
static int	parse_change_spec(char *, char *, int, struct chg_list *);
static void	add_new_change_list_item(struct chg_list *);
static void	free_change_list(void);
static void	do_default(char *);
static void	default_all_pages(void);
static int	default_page(int);

/*
 * Menu data for the SCSI menu display
 */
static char	*scsi_menu_strings[] = {
	"p<n>                   - display a mode sense page",
	"p<n> b<n> <op> [~]<n>  - change a byte and issue mode select",
	"b<n> <op> [~]<n>       - add an operation to the mode select list",
	"                             for the current page",
	"",
	"        where:  p<n> specifies the page with page code <n>",
	"                b<n> specifies byte <n> of the page",
	"                <op> can be one of the following operators:",
	"                     =    (set specified value)",
	"                     |=   (bitwise OR with current value)",
	"                     &=   (bitwise AND with current value)",
	"                <n> can be a decimal value in the range 0-255,",
	"                or two hexadecimal digits, in the form 0x<xx>.",
	"                [~] complements the specified value",
	"",
	"apply                  - apply mode select list",
	"cancel                 - cancel mode select list",
	"display                - display mode select list",
	"all                    - display all supported mode sense pages",
	"default p<n>           - mode select page <n> to default values",
	"default all            - mode select all pages to default values",
	"format                 - format without standard mode selects",
	"inquiry                - display device's inquiry response",
	"list                   - list common SCSI-2 mode pages",
	"!<cmd>                 - execute <cmd> , then return"
};

#define	N_SCSI_STRINGS	(sizeof (scsi_menu_strings) / sizeof (char *))

/*
 * Command types
 */
#define	CMD_ALL			0
#define	CMD_FORMAT		1
#define	CMD_QUIT		2
#define	CMD_HELP		3
#define	CMD_LIST		4
#define	CMD_INQUIRY		5
#define	CMD_APPLY		6
#define	CMD_CANCEL		7
#define	CMD_DISPLAY		8

/*
 * SCSI menu commands for minimum recognition
 */
static struct slist	cmds_list[] = {
	{ "all",	NULL,	CMD_ALL },
	{ "format",	NULL,	CMD_FORMAT },
	{ "quit",	NULL,	CMD_QUIT },
	{ "help",	NULL,	CMD_HELP },
	{ "?",		NULL,	CMD_HELP },
	{ "list",	NULL,	CMD_LIST },
	{ "inquiry",	NULL,	CMD_INQUIRY },
	{ "apply",	NULL,	CMD_APPLY },
	{ "cancel",	NULL,	CMD_CANCEL },
	{ "display",	NULL,	CMD_DISPLAY },
	{ NULL	}
};

/*
 * Implied page for mode select change lists
 */
static	int		current_page;
static	struct chg_list	*change_list;

/*
 * Manage the SCSI menu.
 * Parse input and dispatch to the appropriate functions.
 * The commands we accept are not simple one-word commands,
 * so we cannot use the standard format menu-handling functions.
 */
int
c_scsi(void)
{
	int			i;
	struct env		env;
	char			**menu;
	struct menu_item	scsi_menu[N_SCSI_STRINGS+1];
	struct chg_list		change_item;
	struct chg_list		*chg_item;
	char			s[MAXPATHLEN], nclean[MAXPATHLEN];
	char			*p;
	char			*p2;
	int			cmd;
	int			pageno;
	int			help = 1;

	/*
	 * Warn casual users that maybe they should not be
	 * using this menu.
	 */
	fmt_print("\n"
"Warning:  these functions are intended for expert use only, for\n"
"debugging disk devices and for unusual configuration settings.\n"
"It is recommended that you do not use this menu for normal disk\n"
"configuration and formatting, unless you have explicit instructions,\n"
"or know exactly what you are doing.\n");

	/*
	 * Initialize change list and current page to empty
	 */
	current_page = -1;
	change_list = NULL;

	/*
	 * Build and display the menu.
	 * we only use this for display purposes.
	 */
	for (i = 0; i < N_SCSI_STRINGS; i++) {
		scsi_menu[i].menu_cmd = scsi_menu_strings[i];
		scsi_menu[i].menu_func = NULL;
		scsi_menu[i].menu_state = true;
	}
	scsi_menu[i].menu_cmd = NULL;
	menu = create_menu_list(scsi_menu);
	/*
	 * Save the environment so a ctrl-C out of a command lands here.
	 */
	saveenv(env);
	for (;;) {
		if (help) {
			help = 0;
			fmt_print("\n\nSCSI MENU:\n");
			display_menu_list(menu);
		}
		/*
		 * Prompt and get next input line.  We don't use the
		 * standard input routine, since we need a little
		 * more flexibility in parsing the input.
		 */
		fmt_print("scsi> ");
		get_inputline(nclean, sizeof (nclean));

		clean_token(s, nclean);

		/*
		 * Mark the saved environment active so the user can now
		 * do a ctrl-C to get out of the command.
		 */
		useenv();

		/*
		 * Figure out what the user chose
		 */
		i = find_value(cmds_list, s, &cmd);
		if (i == 1) {
			switch (cmd) {
			case CMD_ALL:
				(void) do_mode_sense_all();
				break;
			case CMD_FORMAT:
				(void) do_format();
				break;
			case CMD_QUIT:
				goto exit;
				/*NOTREACHED*/
			case CMD_HELP:
				fmt_print("\n\nSCSI MENU:\n");
				display_menu_list(menu);
				break;
			case CMD_LIST:
				do_list();
				break;
			case CMD_INQUIRY:
				(void) do_inquiry();
				break;
			case CMD_APPLY:
				do_apply();
				break;
			case CMD_CANCEL:
				do_cancel();
				break;
			case CMD_DISPLAY:
				do_display();
				break;
			}
		} else if (s[0] == 'd') {
			do_default(s);
		} else if (s[0] == 'p') {
			p = s + 1;
			pageno = (int)strtol(p, &p2, 0);
			if (p2 == p) {
				err_print("Syntax error: %s\n", s);
				goto error;
			}
			current_page = pageno;
			for (p = p2; *p == ' '; p++)
				;
			if (*p == 0) {
				(void) do_mode_sense(pageno);
			} else if (*p == 'b') {
				if (parse_change_spec(s, p, pageno,
				    &change_item)) {
					(void) do_mode_select(&change_item);
				}
			}
		} else if (s[0] == 'b') {
				if (current_page == -1) {
					err_print("\
Please display the page on which you'd like to do a mode select\n");
					goto error;
				}
				chg_item = (struct chg_list *)
				    zalloc(sizeof (struct chg_list));
				if (parse_change_spec(s, s, current_page,
				    chg_item)) {
					add_new_change_list_item(chg_item);
				} else {
					destroy_data((char *)chg_item);
				}
		} else if (s[0] == '!') {
			(void) execute_shell(&s[1], sizeof (s) - 1);
			help = 1;
		} else if (s[0] != 0) {
			err_print("Syntax error: %s\n", s);
		}
error:
		/*
		 * Mark the saved environment inactive so ctrl-C doesn't
		 * work at the menu itself.
		 */
		unuseenv();
	}
exit:
	/*
	 * Clean up the environment stack and free the menu
	 */
	clearenv();
	destroy_data((char *)menu);

	/*
	 * Clean up the change list, if anything left over
	 */
	free_change_list();

	/*
	 * Make sure user is prompted with previous menu
	 */
	last_menu++;

	return (0);
}


/*
 * Do a mode sense on a particular page, and dump the data.
 * Get all the various flavors:  default, current, saved, changeable.
 */
static int
do_mode_sense(int pageno)
{
	struct scsi_ms_header	header;
	struct mode_page	*pg;
	char			msbuf[MAX_MODE_SENSE_SIZE];
	int			result = 0;

	char	*default_msg	= "default:     ";
	char	*saved_msg	= "saved:       ";
	char	*current_msg	= "current:     ";
	char	*changeable_msg	= "changeable:  ";


	pg = (struct mode_page *)msbuf;

	fmt_print("\nPage 0x%x:\n", pageno);
	if (uscsi_mode_sense(cur_file, pageno, MODE_SENSE_PC_DEFAULT,
	    msbuf, MAX_MODE_SENSE_SIZE, &header)) {
		err_print("%sfailed\n", default_msg);
		result = 1;
	} else {
		dump(default_msg, msbuf, MODESENSE_PAGE_LEN(pg), HEX_ONLY);
	}

	if (uscsi_mode_sense(cur_file, pageno, MODE_SENSE_PC_CURRENT,
	    msbuf, MAX_MODE_SENSE_SIZE, &header)) {
		err_print("%sfailed\n", current_msg);
		result = 1;
	} else {
		dump(current_msg, msbuf, MODESENSE_PAGE_LEN(pg), HEX_ONLY);
	}

	if (uscsi_mode_sense(cur_file, pageno, MODE_SENSE_PC_SAVED,
	    msbuf, MAX_MODE_SENSE_SIZE, &header)) {
		err_print("%sfailed\n", saved_msg);
		result = 1;
	} else {
		dump(saved_msg, msbuf, MODESENSE_PAGE_LEN(pg), HEX_ONLY);
	}

	if (uscsi_mode_sense(cur_file, pageno, MODE_SENSE_PC_CHANGEABLE,
	    msbuf, MAX_MODE_SENSE_SIZE, &header)) {
		err_print("%sfailed\n", changeable_msg);
		result = 1;
	} else {
		dump(changeable_msg, msbuf, MODESENSE_PAGE_LEN(pg), HEX_ONLY);
	}

	fmt_print("\n");
	return (result);
}


/*
 * Dump all the pages a device supports
 */
static int
do_mode_sense_all(void)
{
	int	result = 0;

	if (scsi_dump_mode_sense_pages(MODE_SENSE_PC_DEFAULT)) {
		result = 1;
	}
	if (scsi_dump_mode_sense_pages(MODE_SENSE_PC_CURRENT)) {
		result = 1;
	}
	if (scsi_dump_mode_sense_pages(MODE_SENSE_PC_SAVED)) {
		result = 1;
	}
	if (scsi_dump_mode_sense_pages(MODE_SENSE_PC_CHANGEABLE)) {
		result = 1;
	}
	fmt_print("\n");
	return (result);
}


/*
 * Get the current mode sense for a particular page, change
 * a byte, and issue a mode select.  Note that we can only
 * change a value if the device indicates that those bits
 * are changeable.
 */
static int
do_mode_select(struct chg_list *change_item)
{
	struct scsi_ms_header	header;
	char			saved[MAX_MODE_SENSE_SIZE];
	char			changeable[MAX_MODE_SENSE_SIZE];
	struct mode_page	*pg;
	struct mode_page	*pg2;
	int			length;
	int			pageno;
	int			flags;
	int			result = 0;

	pageno = change_item->pageno;

	/*
	 * Get changeable mode sense
	 */
	if (uscsi_mode_sense(cur_file, pageno, MODE_SENSE_PC_CHANGEABLE,
	    changeable, MAX_MODE_SENSE_SIZE, &header)) {
		err_print("Mode sense on page %x (changeable) failed\n",
		    pageno);
		return (1);
	}

	/*
	 * Get saved mode sense.  If saved fails, use current values.
	 */
	if (uscsi_mode_sense(cur_file, pageno, MODE_SENSE_PC_SAVED,
	    saved, MAX_MODE_SENSE_SIZE, &header)) {
		err_print("Mode sense on page %x (saved) failed\n", pageno);
		if (uscsi_mode_sense(cur_file, pageno, MODE_SENSE_PC_CURRENT,
		    saved, MAX_MODE_SENSE_SIZE, &header)) {
			err_print("Mode sense on page %x (current) failed\n",
			    pageno);
			return (1);
		} else {
			err_print("Using current values instead\n");
		}
	}

	/*
	 * Use the intersection of the saved and changeable
	 */
	pg = (struct mode_page *)saved;
	pg2 = (struct mode_page *)changeable;
	length = min(MODESENSE_PAGE_LEN(pg), MODESENSE_PAGE_LEN(pg2));

	/*
	 * Try making this change to this page
	 */
	if (apply_chg_list(pageno, length, (uchar_t *)saved,
	    (uchar_t *)changeable, change_item)) {
		/*
		 * A change was made.  Do a mode select
		 * We always want to set the Page Format bit.
		 * Set the Save Page bit if the drive indicates
		 * that it can save this page.
		 */
		flags = MODE_SELECT_PF;
		if (pg->ps) {
			flags |= MODE_SELECT_SP;
		}
		pg->ps = 0;
		header.mode_header.length = 0;
		header.mode_header.device_specific = 0;
		if (uscsi_mode_select(cur_file, pageno, flags,
		    saved, length, &header)) {
			/*
			 * Failed - try not saving parameters,
			 * if possible.
			 */
			if (flags & MODE_SELECT_SP) {
				flags &= ~MODE_SELECT_SP;
				if (uscsi_mode_select(cur_file, pageno,
				    flags, saved, length, &header)) {
					result = 1;
				}
			} else {
				result = 1;
			}
		}

		if (result) {
			fmt_print("\n\
Mode select on page %x failed.\n", pageno);
		} else if ((flags & MODE_SELECT_SP) == 0) {
			fmt_print("\n\
Mode select on page %x ok, but unable to save change permanently.\n", pageno);
		} else {
			fmt_print("\n\
Mode select on page %x ok.\n", pageno);
		}
	} else {
		err_print("\nDevice cannot support this change\n");
	}

	fmt_print("\n");
	return (result);
}


/*
 * Format a device, without any of the standard mode selects.
 * Ask if we should format with the P or the P&G lists.
 */
static int
do_format(void)
{
	struct uscsi_cmd	ucmd;
	union scsi_cdb		cdb;
	struct scsi_defect_hdr	defect_hdr;
	int			status;
	u_ioparam_t		ioparam;
	int			deflt;
	int			grown_list;

	fmt_print("\n");
	/*
	 * Are there mounted partitions?
	 */
	if (checkmount((diskaddr_t)-1, (diskaddr_t)-1)) {
		err_print("Cannot format disk with mounted partitions\n\n");
		return (-1);
	}

	/*
	 * Is any of the partitions being used for swapping.
	 */
	if (checkswap((diskaddr_t)-1, (diskaddr_t)-1)) {
		err_print("Cannot format disk while its partitions are \
currently being used for swapping.\n\n");
		return (-1);
	}
	/*
	 * Are any being used for SVM, VxVM or live upgrade.
	 */
	if (checkdevinuse(cur_disk->disk_name, (diskaddr_t)-1,
	    (diskaddr_t)-1, 0, 0)) {
		err_print("Cannot format disk while its partitions are "
		    "currently being used as described.\n");
		return (-1);
	}

	/*
	 * Let the user choose between formatting with either
	 * the P, or the P&G lists.  Note that yes is 0, no is 1.
	 */
	deflt = 0;
	ioparam.io_charlist = confirm_list;
	grown_list = !input(FIO_MSTR, "Format with the Grown Defects list",
	    '?', &ioparam, &deflt, DATA_INPUT);

	/*
	 * Construct the uscsi format ioctl.
	 * To format with the P and G list, we set the fmtData
	 * and cmpLst bits to zero.  To format with just the
	 * P list, we set the fmtData bit (meaning that we will
	 * send down a defect list in the data phase) and the
	 * cmpLst bit (meaning that the list we send is the
	 * complete G list), and a defect list header with
	 * a defect list length of zero.
	 */
	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	(void) memset((char *)&cdb, 0, sizeof (union scsi_cdb));
	cdb.scc_cmd = SCMD_FORMAT;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	if (!grown_list) {
		/*
		 * No G list.   Send empty defect list to replace it.
		 */
		cdb.cdb_opaque[1] = FPB_DATA | FPB_CMPLT | FPB_BFI;
		(void) memset((char *)&defect_hdr, 0, sizeof (defect_hdr));
		ucmd.uscsi_bufaddr = (caddr_t)&defect_hdr;
		ucmd.uscsi_buflen = sizeof (defect_hdr);
	}

	/*
	 * Issue the format ioctl
	 */
	fmt_print("Formatting...\n");
	(void) fflush(stdout);
	status = uscsi_cmd(cur_file, &ucmd, F_NORMAL);
	fmt_print(status ? "Format failed\n\n" : "Format ok\n\n");
	return (status);
}


/*
 * List common SCSI-2 mode pages
 */
static void
do_list(void)
{
	fmt_print("\n\
Common SCSI-2 pages applicable to direct-access devices:\n\n");
	fmt_print("Page 0x1   - Read-Write Error Recovery Page\n");
	fmt_print("Page 0x2   - Disconnect-Reconnect Page\n");
	fmt_print("Page 0x3   - Format Device Page\n");
	fmt_print("Page 0x4   - Rigid Disk Geometry Page\n");
	fmt_print("Page 0x7   - Verify Error Recovery Page\n");
	fmt_print("Page 0x8   - Caching Page\n");
	fmt_print("Page 0xA   - Control Mode Page\n");
	fmt_print("\n");
}


/*
 * Labels for the various fields of the scsi_inquiry structure
 */
static char *scsi_inquiry_labels[] = {
	"Vendor:                     ",
	"Product:                    ",
	"Revision:                   ",
	"Removable media:            ",
	"Device type:                ",
	"ISO version:                ",
	"ECMA version:               ",
	"ANSI version:               ",
	"Async event notification:   ",
	"Terminate i/o process msg:  ",
	"Response data format:       ",
	"Additional length:          ",
	"Relative addressing:        ",
	"32 bit transfers:           ",
	"16 bit transfers:           ",
	"Synchronous transfers:      ",
	"Linked commands:            ",
	"Command queueing:           ",
	"Soft reset option:          "
};


/*
 * Dump the full inquiry as returned by the device
 */
static int
do_inquiry(void)
{
	char			inqbuf[255];
	struct scsi_inquiry	*inq;
	char			**p;

	inq = (struct scsi_inquiry *)inqbuf;

	if (uscsi_inquiry(cur_file, inqbuf, sizeof (inqbuf))) {
		err_print("\nInquiry failed\n");
		return (1);
	}

	fmt_print("\nInquiry:\n");
	/*
	 * The SCSI-2 spec defines "Additional length" as (n-4) bytes,
	 * where n is the last byte of the INQUIRY data.  Thus
	 * there are n+1 bytes of INQUIRY data.  We need to add 5 to
	 * inq_len in order to get all the INQUIRY data.
	 */
	dump("    ", inqbuf, inq->inq_len + 5, HEX_ASCII);
	fmt_print("\n");

	p = scsi_inquiry_labels;

	fmt_print("%s", *p++);
	print_buf(inq->inq_vid, sizeof (inq->inq_vid));
	fmt_print("\n%s", *p++);
	print_buf(inq->inq_pid, sizeof (inq->inq_pid));
	fmt_print("\n%s", *p++);
	print_buf(inq->inq_revision, sizeof (inq->inq_revision));

	fmt_print("\n%s%s\n", *p++, inq->inq_rmb ? "yes" : "no");
	fmt_print("%s%d\n", *p++, inq->inq_qual);
	fmt_print("%s%d\n", *p++, inq->inq_iso);
	fmt_print("%s%d\n", *p++, inq->inq_ecma);
	fmt_print("%s%d\n", *p++, inq->inq_ansi);
	fmt_print("%s%s\n", *p++, inq->inq_aenc ? "yes" : "no");
	fmt_print("%s%s\n", *p++, inq->inq_trmiop ? "yes" : "no");
	fmt_print("%s%d\n", *p++, inq->inq_rdf);
	fmt_print("%s%d\n", *p++, inq->inq_len);
	fmt_print("%s%s\n", *p++, inq->inq_reladdr ? "yes" : "no");
	fmt_print("%s%s\n", *p++, inq->inq_wbus32 ? "yes" : "no");
	fmt_print("%s%s\n", *p++, inq->inq_wbus16 ? "yes" : "no");
	fmt_print("%s%s\n", *p++, inq->inq_sync ? "yes" : "no");
	fmt_print("%s%s\n", *p++, inq->inq_linked ? "yes" : "no");
	fmt_print("%s%s\n", *p++, inq->inq_cmdque ? "yes" : "no");
	fmt_print("%s%s\n", *p++, inq->inq_sftre ? "yes" : "no");

	fmt_print("\n");
	return (0);
}


static void
do_apply(void)
{
	if (change_list == NULL) {
		fmt_print("\nlist empty.\n");
	} else {
		(void) do_mode_select(change_list);
		free_change_list();
	}
}


static void
do_cancel(void)
{
	if (change_list == NULL) {
		fmt_print("\nlist empty.\n");
	} else {
		free_change_list();
	}
}


static void
do_display(void)
{
	struct chg_list	*cp;

	if (change_list == NULL) {
		fmt_print("\nlist empty.\n");
	} else {
		fmt_print("\nPage 0x%x\n", current_page);
		for (cp = change_list; cp != NULL; cp = cp->next) {
			fmt_print("   b0x%x ", cp->byteno);
			switch (cp->mode) {
			case CHG_MODE_ABS:
				fmt_print("= 0x%x\n", cp->value);
				break;
			case CHG_MODE_SET:
				fmt_print("|= 0x%x\n", cp->value);
				break;
			case CHG_MODE_CLR:
				fmt_print("&= ~0x%x\n",
				    (~(cp->value)) & 0xff);
				break;
			default:
				impossible("do_display");
				/*NOTREACHED*/
			}
		}
		fmt_print("\n");
	}
}


static int
parse_change_spec(char *full_input, char *input, int pageno,
    struct chg_list *chg_item)
{
	char		*p;
	int		tilde;

	assert(*input == 'b');

	chg_item->pageno = pageno;
	chg_item->next = NULL;

	input++;
	chg_item->byteno = (int)strtol(input, &p, 0);
	if (p == input) {
		err_print("Syntax error: %s\n", full_input);
		return (0);
	}
	if (chg_item->byteno < 2) {
		err_print(" Unsupported byte offset: %d\n", chg_item->byteno);
		return (0);
	}
	for (input = p; *input == ' '; input++)
		;
	chg_item->mode = CHG_MODE_UNDEFINED;
	switch (*input++) {
	case '=':
		chg_item->mode = CHG_MODE_ABS;
		break;
	case '|':
		if (*input++ == '=') {
			chg_item->mode = CHG_MODE_SET;
		}
		break;
	case '&':
		if (*input++ == '=') {
			chg_item->mode = CHG_MODE_CLR;
		}
		break;
	}
	if (chg_item->mode == CHG_MODE_UNDEFINED) {
		err_print("Syntax error: %s\n", full_input);
		return (0);
	}
	for (; *input == ' '; input++)
		;
	if (*input == '~') {
		tilde = 1;
		for (input++; *input == ' '; input++)
			;
	} else {
		tilde = 0;
	}
	chg_item->value = (int)strtol(input, &p, 0);
	if (p == input || *p != 0) {
		err_print("Syntax error: %s\n", full_input);
		return (0);
	}
	/*
	 * Apply complement if selected.
	 * Constrain to a byte value.
	 */
	if (tilde) {
		chg_item->value = ~chg_item->value;
	}
	chg_item->value &= 0xff;

	return (1);
}


static void
add_new_change_list_item(struct chg_list *chg_item)
{
	struct chg_list	*cp;

	if (change_list == NULL) {
		change_list = chg_item;
	} else {
		for (cp = change_list; cp->next != NULL; cp = cp->next)
			;
		cp->next = chg_item;
	}
	chg_item->next = NULL;
}


static void
free_change_list(void)
{
	struct chg_list	*cp;
	struct chg_list	*cp2;

	cp = change_list;
	while (cp != NULL) {
		cp2 = cp->next;
		destroy_data((char *)cp);
		cp = cp2;
	}
	change_list = NULL;
}


static void
do_default(char *input)
{
	char		*s = input;
	char		*p;
	int		n;

	/*
	 * Reset current page indicator
	 */
	current_page = -1;

	/*
	 * Skip the leading "default" command, which we
	 * must have, or we wouldn't have come here,
	 * and any white space.
	 */
	while (isspace(*s)) {
		s++;
	}

	while (*s && isascii(*s) && isalpha(*s)) {
		s++;
	}

	while (isspace(*s)) {
		s++;
	}

	/*
	 * Subsequent modifier must be either "p<n>", or "all".
	 */
	if (*s == 'p') {
		s++;
		n = (int)strtol(s, &p, 0);
		if (p == s || *p != 0) {
			err_print("Syntax error: %s\n", input);
		} else {
			fmt_print("\n");
			(void) default_page(n);
			fmt_print("\n");
		}
	} else if (*s == 'a') {
		default_all_pages();
	} else {
		err_print("Syntax error: %s\n", input);
	}
}


static void
default_all_pages(void)
{
	char			*p;
	struct mode_header	*mh;
	struct mode_page	*mp;
	int			n;
	struct uscsi_cmd	ucmd;
	union scsi_cdb		cdb;
	char			msbuf[MAX_MODE_SENSE_SIZE];
	int			nbytes = sizeof (msbuf);
	int			status;

	/*
	 * Build and execute the uscsi ioctl.  Note that
	 * we cannot simply call uscsi_mode_sense() here,
	 * since that function attempts to valididate the
	 * returned data, and the page 0x3f has a unique
	 * format.
	 */
	nbytes = MAX_MODE_SENSE_SIZE;
	(void) memset(msbuf, 0, nbytes);
	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	(void) memset((char *)&cdb, 0, sizeof (union scsi_cdb));
	cdb.scc_cmd = SCMD_MODE_SENSE;
	FORMG0COUNT(&cdb, (uchar_t)nbytes);
	cdb.cdb_opaque[2] = MODE_SENSE_PC_DEFAULT | 0x3f;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = msbuf;
	ucmd.uscsi_buflen = nbytes;
	status = uscsi_cmd(cur_file, &ucmd, (option_msg) ? F_NORMAL : F_SILENT);
	if (status) {
		if (!option_msg) {
			err_print("\nMode sense page 0x3f failed\n");
		}
		return;
	}

	fmt_print("\n");

	/*
	 * Now parse the page 0x3f
	 */
	mh = (struct mode_header *)msbuf;
	nbytes = mh->length - sizeof (struct mode_header) -
	    mh->bdesc_length + 1;
	p = msbuf + sizeof (struct mode_header) + mh->bdesc_length;

	while (nbytes > 0) {
		mp = (struct mode_page *)p;
		n = mp->length + sizeof (struct mode_page);
		nbytes -= n;
		if (nbytes < 0)
			break;
		if (default_page(mp->code) == 0) {
			goto error;
		}
		p += n;
	}

	if (nbytes < 0) {
		err_print("Mode sense page 0x3f formatted incorrectly:\n");
	}
error:
	fmt_print("\n");
}


static int
default_page(int pageno)
{
	struct scsi_ms_header	header;
	char			saved[MAX_MODE_SENSE_SIZE];
	char			current[MAX_MODE_SENSE_SIZE];
	char			dfault[MAX_MODE_SENSE_SIZE];
	struct mode_page	*sp;
	struct mode_page	*cp;
	struct mode_page	*dp;
	int			length;
	int			flags;
	int			i;
	int			need_mode_select;

	/*
	 * Get default mode sense
	 */
	if (uscsi_mode_sense(cur_file, pageno, MODE_SENSE_PC_DEFAULT,
	    dfault, MAX_MODE_SENSE_SIZE, &header)) {
		err_print("Mode sense on page %x (dfault) failed\n", pageno);
		return (0);
	}

	/*
	 * Get the current mode sense.
	 */
	if (uscsi_mode_sense(cur_file, pageno, MODE_SENSE_PC_CURRENT,
	    current, MAX_MODE_SENSE_SIZE, &header)) {
		err_print("Mode sense on page %x (current) failed\n", pageno);
		return (0);
	}

	/*
	 * Get saved mode sense.  If this fails, assume it is
	 * the same as the current.
	 */
	if (uscsi_mode_sense(cur_file, pageno, MODE_SENSE_PC_SAVED,
	    saved, MAX_MODE_SENSE_SIZE, &header)) {
		(void) memcpy(saved, current, MAX_MODE_SENSE_SIZE);
	}

	/*
	 * Determine if we need a mode select on this page.
	 * Just deal with the intersection of the three pages.
	 */
	sp = (struct mode_page *)saved;
	cp = (struct mode_page *)current;
	dp = (struct mode_page *)dfault;
	length = min(MODESENSE_PAGE_LEN(sp), MODESENSE_PAGE_LEN(cp));
	length = min(length, MODESENSE_PAGE_LEN(dp));

	need_mode_select = 0;
	for (i = 2; i < length; i++) {
		if (current[i] != dfault[i] || saved[i] != dfault[i]) {
			current[i] = dfault[i];
			need_mode_select = 1;
		}
	}

	if (need_mode_select == 0) {
		fmt_print("Defaulting page 0x%x: ok\n", pageno);
		return (1);
	}

	/*
	 * A change was made.  Do a mode select
	 * We always want to set the Page Format bit.
	 * Set the Save Page bit if the drive indicates
	 * that it can save this page.
	 */
	length = MODESENSE_PAGE_LEN(cp);
	flags = MODE_SELECT_PF;
	if (cp->ps) {
		flags |= MODE_SELECT_SP;
	}
	cp->ps = 0;
	header.mode_header.length = 0;
	header.mode_header.device_specific = 0;
	if (uscsi_mode_select(cur_file, pageno, flags,
	    current, length, &header)) {
		/*
		 * Failed - try not saving parameters,
		 * if possible.
		 */
		if (flags & MODE_SELECT_SP) {
			flags &= ~MODE_SELECT_SP;
			if (uscsi_mode_select(cur_file, pageno, flags,
			    saved, length, &header)) {
				fmt_print("Defaulting page 0x%x: failed\n",
				    pageno);
			} else {
				fmt_print("Defaulting page 0x%x: ", pageno);
				fmt_print("cannot save page permanently\n");
			}
		} else {
			fmt_print("Defaulting page 0x%x: ", pageno);
			fmt_print("cannot save page permanently\n");
		}
	} else {
		fmt_print("Defaulting page 0x%x: mode select ok\n", pageno);
	}

	return (1);
}
