/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains functions that implement the cache menu commands.
 */
#include "global.h"
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/stat.h>

#include <sys/dklabel.h>

#include "main.h"
#include "analyze.h"
#include "menu.h"
#include "menu_cache.h"
#include "param.h"
#include "misc.h"
#include "label.h"
#include "startup.h"
#include "partition.h"
#include "prompts.h"
#include "checkdev.h"
#include "io.h"
#include "ctlr_scsi.h"
#include "auto_sense.h"
#include "hardware_structs.h"

extern	struct menu_item menu_cache[];
extern	struct menu_item menu_write_cache[];
extern	struct menu_item menu_read_cache[];


int
c_cache(void)
{
	cur_menu++;
	last_menu = cur_menu;
	run_menu(menu_cache, "CACHE", "cache", 0);
	cur_menu--;
	return (0);
}

int
ca_write_cache(void)
{
	cur_menu++;
	last_menu = cur_menu;
	run_menu(menu_write_cache, "WRITE_CACHE", "write_cache", 0);
	cur_menu--;
	return (0);
}

int
ca_read_cache(void)
{
	cur_menu++;
	last_menu = cur_menu;
	run_menu(menu_read_cache, "READ_CACHE", "read_cache", 0);
	cur_menu--;
	return (0);
}

int
ca_write_display(void)
{
	struct mode_cache		*page8;
	struct scsi_ms_header		header;
	int				status;
	union {
		struct mode_cache	page8;
		char			rawbuf[MAX_MODE_SENSE_SIZE];
	} u_page8;

	page8 = &u_page8.page8;

	status = uscsi_mode_sense(cur_file, DAD_MODE_CACHE,
	    MODE_SENSE_PC_CURRENT, (caddr_t)page8,
	    MAX_MODE_SENSE_SIZE, &header);

	if (status == 0) {
		if (page8->wce) {
			fmt_print("Write Cache is enabled\n");
		} else {
			fmt_print("Write Cache is disabled\n");
		}
	} else {
		err_print("Mode sense failed.\n");
	}
	return (0);
}

int
ca_write_enable(void)
{
	struct mode_cache		*page8;
	struct scsi_ms_header		header;
	int				status;
	int				length;
	int				sp_flags;
	union {
		struct mode_cache	page8;
		char			rawbuf[MAX_MODE_SENSE_SIZE];
	} u_page8;

	page8 = &u_page8.page8;

	status = uscsi_mode_sense(cur_file, DAD_MODE_CACHE,
	    MODE_SENSE_PC_CHANGEABLE, (caddr_t)page8,
	    MAX_MODE_SENSE_SIZE, &header);

	if (status == 0) {
		if (page8->wce) {
			status = uscsi_mode_sense(cur_file, DAD_MODE_CACHE,
			    MODE_SENSE_PC_SAVED, (caddr_t)page8,
			    MAX_MODE_SENSE_SIZE, &header);
			if (status != 0) {
				status = uscsi_mode_sense(cur_file,
				    DAD_MODE_CACHE, MODE_SENSE_PC_CURRENT,
				    (caddr_t)page8, MAX_MODE_SENSE_SIZE,
				    &header);
			}

			if (status == 0) {
				length = MODESENSE_PAGE_LEN(page8);
				sp_flags = MODE_SELECT_PF;
				if (page8->mode_page.ps) {
					sp_flags |= MODE_SELECT_SP;
				} else {
					err_print("\
This setting is valid until next reset only. It is not saved permanently.\n");
				}
				page8->mode_page.ps = 0;
				page8->wce = 1;
				header.mode_header.length = 0;
				header.mode_header.device_specific = 0;
				status = uscsi_mode_select(cur_file,
				    DAD_MODE_CACHE, sp_flags,
				    (caddr_t)page8, length, &header);
				if (status != 0) {
					err_print("Mode select failed\n");
					return (0);
				}
			}
		} else {
			err_print("Write cache setting is not changeable\n");
		}
	}
	if (status != 0) {
		err_print("Mode sense failed.\n");
	}
	return (0);
}

int
ca_write_disable(void)
{
	struct mode_cache		*page8;
	struct scsi_ms_header		header;
	int				status;
	int				length;
	int				sp_flags;
	union {
		struct mode_cache	page8;
		char			rawbuf[MAX_MODE_SENSE_SIZE];
	} u_page8;

	page8 = &u_page8.page8;

	status = uscsi_mode_sense(cur_file, DAD_MODE_CACHE,
	    MODE_SENSE_PC_CHANGEABLE, (caddr_t)page8,
	    MAX_MODE_SENSE_SIZE, &header);

	if (status == 0) {
		if (page8->wce) {
			status = uscsi_mode_sense(cur_file, DAD_MODE_CACHE,
			    MODE_SENSE_PC_SAVED, (caddr_t)page8,
			    MAX_MODE_SENSE_SIZE, &header);
			if (status != 0) {
				status = uscsi_mode_sense(cur_file,
				    DAD_MODE_CACHE, MODE_SENSE_PC_CURRENT,
				    (caddr_t)page8, MAX_MODE_SENSE_SIZE,
				    &header);
			}

			if (status == 0) {
				length = MODESENSE_PAGE_LEN(page8);
				sp_flags = MODE_SELECT_PF;
				if (page8->mode_page.ps) {
					sp_flags |= MODE_SELECT_SP;
				} else {
					err_print("\
This setting is valid until next reset only. It is not saved permanently.\n");
				}
				page8->mode_page.ps = 0;
				page8->wce = 0;
				header.mode_header.length = 0;
				header.mode_header.device_specific = 0;
				status = uscsi_mode_select(cur_file,
				    DAD_MODE_CACHE, sp_flags,
				    (caddr_t)page8, length, &header);
				if (status != 0) {
					err_print("Mode select failed\n");
					return (0);
				}
			}
		} else {
			err_print("Write cache setting is not changeable\n");
		}
	}
	if (status != 0) {
		err_print("Mode sense failed.\n");
	}
	return (0);
}

int
ca_read_display(void)
{
	struct mode_cache		*page8;
	struct scsi_ms_header		header;
	int				status;
	union {
		struct mode_cache	page8;
		char			rawbuf[MAX_MODE_SENSE_SIZE];
	} u_page8;

	page8 = &u_page8.page8;

	status = uscsi_mode_sense(cur_file, DAD_MODE_CACHE,
	    MODE_SENSE_PC_CURRENT, (caddr_t)page8,
	    MAX_MODE_SENSE_SIZE, &header);

	if (status == 0) {
		if (page8->rcd) {
			fmt_print("Read Cache is disabled\n");
		} else {
			fmt_print("Read Cache is enabled\n");
		}
	} else {
		err_print("Mode sense failed.\n");
	}
	return (0);
}

int
ca_read_enable(void)
{
	struct mode_cache		*page8;
	struct scsi_ms_header		header;
	int				status;
	int				length;
	int				sp_flags;
	union {
		struct mode_cache	page8;
		char			rawbuf[MAX_MODE_SENSE_SIZE];
	} u_page8;

	page8 = &u_page8.page8;

	status = uscsi_mode_sense(cur_file, DAD_MODE_CACHE,
	    MODE_SENSE_PC_CHANGEABLE, (caddr_t)page8,
	    MAX_MODE_SENSE_SIZE, &header);

	if (status == 0) {
		if (page8->rcd) {
			status = uscsi_mode_sense(cur_file, DAD_MODE_CACHE,
			    MODE_SENSE_PC_SAVED, (caddr_t)page8,
			    MAX_MODE_SENSE_SIZE, &header);
			if (status != 0) {
				status = uscsi_mode_sense(cur_file,
				    DAD_MODE_CACHE, MODE_SENSE_PC_CURRENT,
				    (caddr_t)page8, MAX_MODE_SENSE_SIZE,
				    &header);
			}

			if (status == 0) {
				length = MODESENSE_PAGE_LEN(page8);
				sp_flags = MODE_SELECT_PF;
				if (page8->mode_page.ps) {
					sp_flags |= MODE_SELECT_SP;
				} else {
					err_print("\
This setting is valid until next reset only. It is not saved permanently.\n");
				}
				page8->mode_page.ps = 0;
				page8->rcd = 0;
				header.mode_header.length = 0;
				header.mode_header.device_specific = 0;
				status = uscsi_mode_select(cur_file,
				    DAD_MODE_CACHE, sp_flags,
				    (caddr_t)page8, length, &header);
				if (status != 0) {
					err_print("Mode select failed\n");
					return (0);
				}
			}
		} else {
			err_print("Read cache setting is not changeable\n");
		}
	}
	if (status != 0) {
		err_print("Mode sense failed.\n");
	}
	return (0);
}

int
ca_read_disable(void)
{
	struct mode_cache		*page8;
	struct scsi_ms_header		header;
	int				status;
	int				length;
	int				sp_flags;
	union {
		struct mode_cache	page8;
		char			rawbuf[MAX_MODE_SENSE_SIZE];
	} u_page8;

	page8 = &u_page8.page8;

	status = uscsi_mode_sense(cur_file, DAD_MODE_CACHE,
	    MODE_SENSE_PC_CHANGEABLE, (caddr_t)page8,
	    MAX_MODE_SENSE_SIZE, &header);

	if (status == 0) {
		if (page8->rcd) {
			status = uscsi_mode_sense(cur_file, DAD_MODE_CACHE,
			    MODE_SENSE_PC_SAVED, (caddr_t)page8,
			    MAX_MODE_SENSE_SIZE, &header);
			if (status != 0) {
				status = uscsi_mode_sense(cur_file,
				    DAD_MODE_CACHE, MODE_SENSE_PC_CURRENT,
				    (caddr_t)page8, MAX_MODE_SENSE_SIZE,
				    &header);
			}

			if (status == 0) {
				length = MODESENSE_PAGE_LEN(page8);
				sp_flags = MODE_SELECT_PF;
				if (page8->mode_page.ps) {
					sp_flags |= MODE_SELECT_SP;
				} else {
					err_print("\
This setting is valid until next reset only. It is not saved permanently.\n");
				}
				page8->mode_page.ps = 0;
				page8->rcd = 1;
				header.mode_header.length = 0;
				header.mode_header.device_specific = 0;
				status = uscsi_mode_select(cur_file,
				    DAD_MODE_CACHE, sp_flags,
				    (caddr_t)page8, length, &header);
				if (status != 0) {
					err_print("Mode select failed\n");
					return (0);
				}
			}
		} else {
			err_print("Read cache setting is not changeable\n");
		}
	}
	if (status != 0) {
		err_print("Mode sense failed.\n");
	}
	return (0);
}
