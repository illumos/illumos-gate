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
 * Copyright 2015 Toomas Soome <tsoome@me.com>
 */

#ifndef _LOADER_EMU_H
#define	_LOADER_EMU_H

/*
 * BootFORTH emulator interface.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Commands and return values; nonzero return sets command_errmsg != NULL */
typedef int (bootblk_cmd_t)(int argc, char *argv[]);
extern char *command_errmsg;
extern char command_errbuf[];	/* XXX blah, length */
#define	CMD_OK		0
#define	CMD_ERROR	1

/*
 * Support for commands
 */
struct bootblk_command
{
	const char	*c_name;
	const char	*c_desc;
	bootblk_cmd_t	*c_fn;
	STAILQ_ENTRY(bootblk_command) next;
};

#ifdef __cplusplus
}
#endif

#endif /* _LOADER_EMU_H */
