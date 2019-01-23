/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Ifparse splits up an ifconfig command line, and was written for use
 * with the networking boot scripts; see $SRC/cmd/svc/shell/net_include.sh
 *
 * Ifparse can extract selected parts of the ifconfig command line,
 * such as failover address configuration ("ifparse -f"), or everything
 * except failover address configuration ("ifparse -s").  By default,
 * all parts of the command line are extracted (equivalent to ("ifparse -fs").
 *
 * Examples:
 *
 * The command:
 *
 * 	ifparse inet 1.2.3.4 up group two addif 1.2.3.5 up addif 1.2.3.6 up
 *
 * Produces the following on standard output:
 *
 *	set 1.2.3.4 up
 *	group two
 *	addif 1.2.3.5 up
 *	addif 1.2.3.6 up
 *
 * The optional "set" and "destination" keywords are added to make the
 * output easier to process by a script or another command.
 *
 * The command:
 *
 * 	ifparse -f inet 1.2.3.4 -failover up group two addif 1.2.3.5 up
 *
 * Produces:
 *
 *	addif 1.2.3.5  up
 *
 * Only failover address configuration has been requested.  Address
 * 1.2.3.4 is a non-failover address, and so isn't output.
 *
 * The "failover" and "-failover" commands can occur several times for
 * a given logical interface.  Only the last one counts.  For example:
 *
 *	ifparse -f inet 1.2.3.4 -failover failover -failover failover up
 *
 * Produces:
 *
 *	set 1.2.3.4 -failover failover -failover failover up
 *
 * No attempt is made to clean up such "pathological" command lines, by
 * removing redundant "failover" and "-failover" commands.
 */

#include	<sys/types.h>
#include	<stdlib.h>
#include	<stdio.h>
#include	<string.h>
#include	<assert.h>

/*
 * Parser flags:
 *
 *	PARSEFIXED
 *		Command should only appear if non-failover commands
 *		are requested.
 *	PARSEMOVABLE
 *		Command should only appear if failover commands are
 *		requested.
 *	PARSENOW
 *		Don't buffer the command, dump it to output immediately.
 * 	PARSEADD
 *		Indicates processing has moved on to additional
 *		logical interfaces.
 *		Dump the buffer to output and clear buffer contents.
 *	PARSESET
 * 		The "set" and "destination" keywords are optional.
 * 		This flag indicates that the next address not prefixed
 *		with a keyword will be a destination address.
 *	PARSELOG0
 *		Command not valid on additional logical interfaces.
 */

#define	PARSEFIXED	0x01
#define	PARSEMOVABLE	0x02
#define	PARSENOW	0x04
#define	PARSEADD	0x08
#define	PARSESET	0x10
#define	PARSELOG0	0x20

typedef enum { AF_UNSPEC, AF_INET, AF_INET6, AF_ANY } ac_t;

#define	NEXTARG		(-1)	/* command takes an argument */
#define	OPTARG		(-2)	/* command takes an optional argument */

#define	END_OF_TABLE	(-1)

/* Parsemode, the type of commands requested by the user. */
int	parsemode = 0;

/* Parsetype, the type of the command currently in the buffer. */
int	parsetype = PARSEFIXED | PARSEMOVABLE;

/* Parsebuf, pointer to the buffer. */
char	*parsebuf = NULL;

/* Parsebuflen, the size of the buffer area. */
unsigned parsebuflen = 0;

/* Parsedumplen, the amount of the buffer currently in use. */
unsigned parsedumplen = 0;

/*
 * Setaddr, used to decide whether an address without a keyword
 * prefix is a source or destination address.
 */
boolean_t setaddr = _B_FALSE;

/*
 * Some ifconfig commands are only valid on the first logical interface.
 * As soon as an "addif" command is seen, "addint" is set.
 */
boolean_t addint = _B_FALSE;

/*
 * The parser table is based on that in ifconfig.  A command may or
 * may not have an argument, as indicated by whether NEXTARG/OPTARG is
 * in the second column.  Some commands can only be used with certain
 * address families, as indicated in the third column.  The fourth column
 * contains flags that control parser action.
 *
 * Ifparse buffers logical interface configuration commands such as "set",
 * "netmask" and "broadcast".  This buffering continues until an "addif"
 * command is seen, at which point the buffer is emptied, and the process
 * starts again.
 *
 * Some commands do not relate to logical interface configuration and are
 * dumped to output as soon as they are seen, such as "group" and "standby".
 *
 */

struct	cmd {
	char	*c_name;
	int	c_parameter;		/* NEXTARG means next argv */
	int	c_af;			/* address family restrictions */
	int	c_parseflags;		/* parsing flags */
} cmds[] = {
	{ "up",			0,		AF_ANY, 0 },
	{ "down",		0,		AF_ANY, 0 },
	{ "trailers",		0, 		AF_ANY, PARSENOW },
	{ "-trailers",		0,		AF_ANY, PARSENOW },
	{ "arp",		0,		AF_INET, PARSENOW },
	{ "-arp",		0,		AF_INET, PARSENOW },
	{ "private",		0,		AF_ANY, 0 },
	{ "-private",		0,		AF_ANY, 0 },
	{ "router",		0,		AF_ANY, PARSELOG0 },
	{ "-router",		0,		AF_ANY, PARSELOG0 },
	{ "xmit",		0,		AF_ANY, 0 },
	{ "-xmit",		0,		AF_ANY, 0 },
	{ "-nud",		0,		AF_INET6, PARSENOW },
	{ "nud",		0,		AF_INET6, PARSENOW },
	{ "anycast",		0,		AF_ANY, 0 },
	{ "-anycast",		0,		AF_ANY, 0 },
	{ "local",		0,		AF_ANY, 0 },
	{ "-local",		0,		AF_ANY, 0 },
	{ "deprecated",		0,		AF_ANY, 0 },
	{ "-deprecated", 	0, 		AF_ANY, 0 },
	{ "preferred",		0,		AF_INET6, 0 },
	{ "-preferred",		0,		AF_INET6, 0 },
	{ "debug",		0,		AF_ANY, PARSENOW },
	{ "verbose",		0,		AF_ANY, PARSENOW },
	{ "netmask",		NEXTARG,	AF_INET, 0 },
	{ "metric",		NEXTARG,	AF_ANY, 0 },
	{ "mtu",		NEXTARG,	AF_ANY, 0 },
	{ "index",		NEXTARG,	AF_ANY, PARSELOG0 },
	{ "broadcast",		NEXTARG,	AF_INET, 0 },
	{ "auto-revarp", 	0,		AF_INET, PARSEFIXED},
	{ "plumb",		0,		AF_ANY, PARSENOW },
	{ "unplumb",		0,		AF_ANY, PARSENOW },
	{ "ipmp",		0,		AF_ANY, PARSELOG0 },
	{ "subnet",		NEXTARG,	AF_ANY, 0 },
	{ "token",		NEXTARG,	AF_INET6, PARSELOG0 },
	{ "tsrc",		NEXTARG,	AF_ANY, PARSELOG0 },
	{ "tdst",		NEXTARG,	AF_ANY, PARSELOG0 },
	{ "encr_auth_algs", 	NEXTARG,	AF_ANY, PARSELOG0 },
	{ "encr_algs",		NEXTARG,	AF_ANY, PARSELOG0 },
	{ "auth_algs",		NEXTARG,	AF_ANY, PARSELOG0 },
	{ "addif",		NEXTARG,	AF_ANY, PARSEADD },
	{ "removeif",		NEXTARG,	AF_ANY, PARSELOG0 },
	{ "modlist",		0,		AF_ANY, PARSENOW },
	{ "modinsert",		NEXTARG,	AF_ANY, PARSENOW },
	{ "modremove",		NEXTARG,	AF_ANY, PARSENOW },
	{ "failover",		0,		AF_ANY, PARSEMOVABLE },
	{ "-failover",		0, 		AF_ANY, PARSEFIXED },
	{ "standby",		0,		AF_ANY, PARSENOW },
	{ "-standby",		0,		AF_ANY, PARSENOW },
	{ "failed",		0,		AF_ANY, PARSENOW },
	{ "-failed",		0,		AF_ANY, PARSENOW },
	{ "group",		NEXTARG,	AF_ANY, PARSELOG0 },
	{ "configinfo",		0,		AF_ANY, PARSENOW },
	{ "encaplimit",		NEXTARG,	AF_ANY,	PARSELOG0 },
	{ "-encaplimit",	0,		AF_ANY,	PARSELOG0 },
	{ "thoplimit",		NEXTARG,	AF_ANY, PARSELOG0 },
	{ "set",		NEXTARG,	AF_ANY, PARSESET },
	{ "destination",	NEXTARG,	AF_ANY, 0 },
	{ "zone",		NEXTARG,	AF_ANY, 0 },
	{ "-zone",		0,		AF_ANY, 0 },
	{ "all-zones",		0,		AF_ANY, 0 },
	{ "ether",		OPTARG,		AF_ANY, PARSENOW },
	{ "usesrc",		NEXTARG,	AF_ANY, PARSENOW },
	{ 0 /* ether addr */,	0,		AF_UNSPEC, PARSELOG0 },
	{ 0 /* set */,		0,		AF_ANY, PARSESET },
	{ 0 /* destination */,	0,		AF_ANY, 0 },
	{ 0,			END_OF_TABLE,	END_OF_TABLE, END_OF_TABLE},
};


/* Known address families */
struct afswtch {
	char *af_name;
	short af_af;
} afs[] = {
	{ "inet",	AF_INET },
	{ "ether",	AF_UNSPEC },
	{ "inet6",	AF_INET6 },
	{ 0,		0 }
};

/*
 * Append "item" to the buffer.  If there isn't enough room in the buffer,
 * expand it.
 */
static void
parse_append_buf(char *item)
{
	unsigned itemlen;
	unsigned newdumplen;

	if (item == NULL)
		return;

	itemlen = strlen(item);
	newdumplen = parsedumplen + itemlen;

	/* Expand dump buffer as needed */
	if (parsebuflen < newdumplen)  {
		if ((parsebuf = realloc(parsebuf, newdumplen)) == NULL) {
			perror("ifparse");
			exit(1);
		}
		parsebuflen = newdumplen;
	}
	(void) memcpy(parsebuf + parsedumplen, item, itemlen);

	parsedumplen = newdumplen;
}

/*
 * Dump the buffer to output.
 */
static void
parse_dump_buf(void)
{
	/*
	 * When parsing, a set or addif command,  we may be some way into
	 * the command before we definitely know it is movable or fixed.
	 * If we get to the end of the command, and haven't seen a
	 * "failover" or "-failover" flag, the command is movable.
	 */
	if (!((parsemode == PARSEFIXED) && (parsetype & PARSEMOVABLE) != 0) &&
	    (parsemode & parsetype) != 0 && parsedumplen != 0) {
		unsigned i;

		if (parsebuf[parsedumplen] == ' ')
			parsedumplen--;

		for (i = 0; i < parsedumplen; i++)
			(void) putchar(parsebuf[i]);

		(void) putchar('\n');
	}
	/* The buffer is kept in case there is more parsing to do */
	parsedumplen = 0;
	parsetype = PARSEFIXED | PARSEMOVABLE;
}

/*
 * Process a command.  The command will either be put in the buffer,
 * or dumped directly to output.  The current contents of the buffer
 * may be dumped to output.
 *
 * The buffer holds commands relating to a particular logical interface.
 * For example, "set", "destination", "failover", "broadcast", all relate
 * to a particular interface.  Such commands have to be buffered until
 * all the "failover" and "-failover" commands for that interface have
 * been seen, only then will we know whether the command is movable
 * or not.  When the "addif" command is seen, we know we are about to
 * start processing a new logical interface, we've seen all the
 * "failover" and "-failover" commands for the previous interface, and
 * can decide whether the buffer contents are movable or not.
 *
 */
static void
parsedump(char *cmd, int param, int flags, char *arg)
{
	char *cmdname;	/* Command name	*/
	char *cmdarg;	/* Argument to command, if it takes one, or NULL */

	/*
	 * Is command only valid on logical interface 0?
	 * If processing commands on an additional logical interface, ignore
	 * the command.
	 * If processing commands on logical interface 0, don't buffer the
	 * command, dump it straight to output.
	 */
	if ((flags & PARSELOG0) != 0) {
		if (addint)
			return;
		flags |= PARSENOW;
	}

	/*
	 * If processing the "addif" command, a destination address may
	 * follow without the "destination" prefix.  Add PARSESET to the
	 * flags so that such an anonymous address is processed correctly.
	 */
	if ((flags & PARSEADD) != 0) {
		flags |= PARSESET;
		addint = _B_TRUE;
	}

	/*
	 * Commands that must be dumped straight to output are always fixed
	 * (non-movable) commands.
	 *
	 */
	if ((flags & PARSENOW) != 0)
		flags |= PARSEFIXED;

	/*
	 * Source and destination addresses do not have to be prefixed
	 * with the keywords "set" or "destination".  Ifparse always
	 * inserts the optional keyword.
	 */
	if (cmd == NULL) {
		cmdarg = arg;
		if ((flags & PARSESET) != 0)
			cmdname = "set";
		else if (setaddr) {
			cmdname = "destination";
			setaddr = _B_FALSE;
		} else
			cmdname = "";
	} else {
		cmdarg = (param == 0) ? NULL : arg;
		cmdname = cmd;
	}

	/*
	 * The next address without a prefix will be a destination
	 * address.
	 */
	if ((flags & PARSESET) != 0)
		setaddr = _B_TRUE;

	/*
	 * Dump the command straight to output?
	 * Only dump the command if the parse mode specified on
	 * the command line matches the type of the command.
	 */
	if ((flags & PARSENOW) != 0) {
		if ((parsemode & flags) != 0)  {
			(void) fputs(cmdname, stdout);
			if (cmdarg != NULL) {
				(void) fputc(' ', stdout);
				(void) fputs(cmdarg, stdout);
			}
			(void) fputc('\n', stdout);
		}
		return;
	}

	/*
	 * Only the commands relating to a particular logical interface
	 * are buffered.  When an "addif" command is seen, processing is
	 * about to start on a new logical interface, so dump the
	 * buffer to output.
	 */
	if ((flags & PARSEADD) != 0)
		parse_dump_buf();

	/*
	 * If the command flags indicate the command is fixed or
	 * movable, update the type of the interface in the buffer
	 * accordingly.  For example, "-failover" has the "PARSEFIXED"
	 * flag, and the contents of the buffer are not movable if
	 * "-failover" is seen.
	 */
	if ((flags & PARSEFIXED) != 0)
		parsetype &= ~PARSEMOVABLE;

	if ((flags & PARSEMOVABLE) != 0)
		parsetype &= ~PARSEFIXED;

	parsetype |= flags & (PARSEFIXED | PARSEMOVABLE);

	parse_append_buf(cmdname);

	if (cmdarg != NULL) {
		parse_append_buf(" ");
		parse_append_buf(cmdarg);
	}

	parse_append_buf(" ");
}

/*
 * Parse the part of the command line following the address family
 * specification, if any.
 *
 * This function is a modified version of the function "ifconfig" in
 * ifconfig.c.
 */
static int
ifparse(int argc, char *argv[], struct afswtch *afp)
{
	int af = afp->af_af;

	if (argc == 0)
		return (0);

	if (strcmp(*argv, "auto-dhcp") == 0 || strcmp(*argv, "dhcp") == 0) {
		if ((parsemode & PARSEFIXED) != 0) {
			while (argc) {
				(void) fputs(*argv++, stdout);
				if (--argc != 0)
					(void) fputc(' ', stdout);
				else
					(void) fputc('\n', stdout);
			}
		}
		return (0);
	}

	while (argc > 0) {
		struct cmd *p;
		boolean_t found_cmd;

		found_cmd = _B_FALSE;
		for (p = cmds; ; p++) {
			assert(p->c_parseflags != END_OF_TABLE);
			if (p->c_name) {
				if (strcmp(*argv, p->c_name) == 0) {
					/*
					 * indicate that the command was
					 * found and check to see if
					 * the address family is valid
					 */
					found_cmd = _B_TRUE;
					if (p->c_af == AF_ANY ||
					    af == p->c_af)
						break;
				}
			} else {
				if (p->c_af == AF_ANY ||
				    af == p->c_af)
					break;
			}
		}
		assert(p->c_parseflags != END_OF_TABLE);
		/*
		 * If we found the keyword, but the address family
		 * did not match spit out an error
		 */
		if (found_cmd && p->c_name == 0) {
			(void) fprintf(stderr, "ifparse: Operation %s not"
			    " supported for %s\n", *argv, afp->af_name);
			return (1);
		}
		/*
		 * else (no keyword found), we assume it's an address
		 * of some sort
		 */
		if (p->c_name == 0 && setaddr) {
			p++;	/* got src, do dst */
			assert(p->c_parseflags != END_OF_TABLE);
		}

		if (p->c_parameter == NEXTARG || p->c_parameter == OPTARG) {
			argc--, argv++;
			if (argc == 0 && p->c_parameter == NEXTARG) {
				(void) fprintf(stderr,
				    "ifparse: no argument for %s\n",
				    p->c_name);
				return (1);
			}
		}

		/*
		 *	Dump the command if:
		 *
		 *		there's no address family
		 *		restriction
		 *	OR
		 *		there is a restriction AND
		 *		the address families match
		 */
		if ((p->c_af == AF_ANY)	|| (af == p->c_af))
			parsedump(p->c_name, p->c_parameter, p->c_parseflags,
			    *argv);
		argc--, argv++;
	}
	parse_dump_buf();

	return (0);
}

/*
 * Print command usage on standard error.
 */
static void
usage(void)
{
	(void) fprintf(stderr,
	    "usage: ifparse [ -fs ] <addr_family> <commands>\n");
}

int
main(int argc, char *argv[])
{
	int c;
	struct afswtch *afp;

	while ((c = getopt(argc, argv, "fs")) != -1) {
		switch ((char)c) {
		case 'f':
			parsemode |= PARSEMOVABLE;
			break;
		case 's':
			parsemode |= PARSEFIXED;
			break;
		case '?':
			usage();
			exit(1);
		}
	}

	if (parsemode == 0)
		parsemode = PARSEFIXED | PARSEMOVABLE;

	argc -= optind;
	argv += optind;

	afp = afs;
	if (argc > 0) {
		struct afswtch *aftp;
		for (aftp = afs; aftp->af_name; aftp++) {
			if (strcmp(aftp->af_name, *argv) == 0) {
				argc--; argv++;
				afp = aftp;
				break;
			}
		}
	}

	return (ifparse(argc, argv, afp));
}
