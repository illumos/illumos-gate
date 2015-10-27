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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */


#include <stdio.h>
#include <libintl.h>
#include <stdlib.h>
#include <strings.h>
#include <err.h>
#include <ads/dsgetdc.h>
#include <smb/nterror.h>
#include <uuid/uuid.h>


static void dclist_usage(void);
static int cmd_dclist(char *);
static void dcname_usage(void);
static int cmd_dcname(char *);
static void dsgetdc_usage(void);
static int cmd_dsgetdc(char *);
static void dsgetdcname_usage(void);
static int cmd_dsgetdcname(char *);
static void kick_usage(void);
static int cmd_kick(char *);
static void help(void);

typedef int cmd_fn_t (char *);
typedef void cmd_usage_t (void);


static struct commands {
	const char	*name;	/* name of subcommand */
	cmd_fn_t	*fn;	/* pointer to subcommand handler function */
	cmd_usage_t	*usage;	/* pointer to subcommand help function */
	int		optreq; /* does this have a required optval */
} commands[] = {
	{"dclist", cmd_dclist, dclist_usage, 0},
	{"dcname", cmd_dcname, dcname_usage, 0},
	{"dsgetdc", cmd_dsgetdc, dsgetdc_usage, 0},
	{"dsgetdcname", cmd_dsgetdcname, dsgetdcname_usage, 0},
	{"kick", cmd_kick, kick_usage, 0},
	{NULL, NULL, NULL, 0}
};


/*
 * lookupcmd
 */
static struct commands *
lookupcmd(const char *name)
{
	struct commands *cmd;

	for (cmd = commands; cmd->name; cmd++) {
		if (strcasecmp(cmd->name, name) == 0)
			return (cmd);
	}
	return (NULL);
}

/*
 * dclist
 */
static void
dclist_usage(void)
{
	(void) printf(gettext("usage: nltest dclist... \n"));
	exit(1);
}

/* ARGSUSED */
static int
cmd_dclist(char *optval)
{
	(void) printf("cmd_dclist() \n");
	return (0);
}

/*
 * dcname
 */
static void
dcname_usage(void)
{
	(void) printf(gettext("usage: nltest dcname... \n"));
	exit(1);
}

/* ARGSUSED */
static int
cmd_dcname(char *optval)
{
	(void) printf("cmd_dcname() \n");
	return (0);
}

/*
 * dsgetdc
 */
static void
dsgetdc_usage(void)
{
	(void) printf(gettext("usage: nltest dsgetdc... \n"));
	exit(1);
}

/* ARGSUSED */
static int
cmd_dsgetdc(char *optval)
{
	(void) printf("cmd_dsgetdc() \n");
	return (0);
}

/*
 * dsgetdcname
 */
static void
dsgetdcname_usage(void)
{
	(void) printf(gettext("usage: nltest dsgetdcname domainname \n"));
	exit(1);
}

static int
cmd_dsgetdcname(char *domname)
{
	char uuid_buf[UUID_PRINTABLE_STRING_LENGTH];
	int err = 0;
	char *atype;
	DOMAIN_CONTROLLER_INFO *dcinfo;

	if (domname != NULL)
		(void) printf("  Domain name supplied:  %s \n", domname);

	err = DsGetDcName(NULL, domname, NULL, NULL, 0, &dcinfo);

	switch (err) {
	case 0:
		break;
	case ERROR_NO_SUCH_DOMAIN:
		(void) printf("Domain controller not found.\n");
		(void) printf("See: /var/run/idmap/discovery.log\n");
		exit(1);
	default:
		(void) printf("Unexpected error %d\n", err);
		exit(1);
	}

	switch (dcinfo->DomainControllerAddressType) {
	case DS_INET_ADDRESS:
		atype = "inet";
		break;
	case DS_NETBIOS_ADDRESS:
		atype = "netbios";
		break;
	default:
		atype = "?";
		break;
	}

	uuid_unparse(dcinfo->DomainGuid, uuid_buf);

	(void) printf("Data Returned from DsGetDcName() call: \n");
	(void) printf("  DC Name:  %s \n", dcinfo->DomainControllerName);
	(void) printf("  DC Addr:  %s \n", dcinfo->DomainControllerAddress);
	(void) printf("  DC Addr Type:  %s \n", atype);
	(void) printf("  Domain Name:  %s \n", dcinfo->DomainName);
	(void) printf("  Domain GUID:  %s \n", uuid_buf);
	(void) printf("  DNS Forest Name:  %s \n", dcinfo->DnsForestName);
	(void) printf("  Flags:  0x%x \n", dcinfo->Flags);
	(void) printf("  DC Site Name:  %s \n", dcinfo->DcSiteName);
	(void) printf("  Client Site Name:  %s \n", dcinfo->ClientSiteName);

	return (0);
}

/*
 * kick
 */
static void
kick_usage(void)
{
	(void) printf(gettext("usage: nltest /KICK \n"));
	exit(1);
}


static int
cmd_kick(char *domname)
{
	int flags = 0;
	int result;

	result = _DsForceRediscovery(domname, flags);

	return (result);
}

/*
 * help functions
 */

static void
help(void) {
	(void) printf("\n");
	/*
	 * TODO: We may want to revise this help text.  It's basically
	 * a copy-paste from:
	 *   http://technet.microsoft.com/en-us/library/cc731935.aspx
	 */
	(void) printf(gettext("usage: %s /subcommand\n"),
	    (char *)getexecname());
	(void) printf(gettext("where subcommands are:\n"
#if 0	/* not yet */
		" dclist        Lists all domain controllers in the domain.\n"
		" dcname        Lists the PDC or PDC emulator.\n"
		" dsgetdc       Queries DNS server for list of DCs and"
			" their IP addresses and contacts each DC to check"
			" for connectivity.\n"
#endif
		" dsgetdcname   returns the name of a domain controller in a"
			" specified domain\n"
		" help          display help on specified subcommand\n"
		" kick          trigger domain controller re-discovery\n"
		"\n"));
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct commands *cmd;
	int err = 0;
	char *option_cmd = NULL;
	char *arg;
	char *p;
	char *optname;
	char *optval = NULL;
	int i;
	int optind = 1;

	/*
	 * Parse options.
	 */
	while (optind < argc) {
		arg = argv[optind];
		optname = NULL;
		optval = NULL;

		/* Is this an option? */
		if (arg[0] == '/') {
			optname = arg + 1;
			optind++;

			/*
			 * May have  /optname:value
			 */
			if ((p = strchr(optname, ':')) != NULL) {
				*p++ = '\0';
				optval = p;
			}
		} else if (arg[0] == '-' && arg[1] == '-') {
			optname = arg + 2;
			optind++;

			/*
			 * May have  --optname=value
			 */
			if ((p = strchr(optname, '=')) != NULL) {
				*p++ = '\0';
				optval = p;
			}
		} else {
			/* Not an option.  Stop parsing. */
			break;
		}

		/*
		 * Handle each optname (and maybe its optval)
		 * Might put this logic in a table of options.
		 * (including a flag for "optval required",
		 * so that check could be factored out)
		 */
		for (cmd = commands; cmd->name; cmd++) {
			if (!strcasecmp(optname, cmd->name)) {
				/* cmd->name  requires an optval */
				if (optval == NULL && optind < argc)
					optval = argv[optind++];

				if (optval == NULL && cmd->optreq > 0) {
					(void) fprintf(stderr,
					    "%s: option %s requires a value\n",
					    argv[0], optname);
					return (1);
				}
				option_cmd = optname;
			}
		}
	}

	/*
	 * Handle remaining non-option arguments
	 */
	for (i = optind; i < argc; i++) {
		(void) printf("arg: %s\n", argv[i]);
	}

	if (option_cmd == NULL)
		help();

	cmd = lookupcmd(option_cmd);
	if (cmd == NULL)
		err = 1;
	else
		err = cmd->fn(optval);

	return (err);
}
