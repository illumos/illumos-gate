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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "sysidnfs4.h"
#include "config_nfs4.h"

static char		*term;
static char		*progname;

/*
 * Validate entered domain using the
 * same rules applied by nfsmapid(1m).
 */
static n4err_t
domain_validate(char *ds)
{
	int	 i;

	for (i = 0; *ds && i < NS_MAXCDNAME; i++, ds++) {
		if (!isalpha(*ds) && !isdigit(*ds) && (*ds != '.') &&
				(*ds != '-') && (*ds != '_')) {
			return (NFS4_ERROR_BAD_DOMAIN);
		}
	}
	return (i == NS_MAXCDNAME ? NFS4_ERROR_DOMAIN_LEN : NFS4_SUCCESS);
}

/*
 * set TERM env var to something sane
 */
static int
set_term(void)
{
	if ((term = getenv("TERM")) == NULL) {
		if (putenv(TERM_DEFAULT)) {
			fprintf(stderr, PUTTERM_ERR, TERM_DEFAULT);
			return (1);
		}
	}
	return (0);
}

static void
clear_state(void)
{
	/*
	 * remove the state file so the user gets prompted again
	 */
	(void) unlink(NFS4STE_FILE);
}

static void
touch_state(void)
{
	int	fd;
	mode_t	mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

	/*
	 * create the state file so we don't get prompted again
	 */
	errno = 0;
	if ((fd = creat(NFS4STE_FILE, mode)) < 0) {
		if (errno == EDQUOT || errno == ENOSPC || errno == EROFS)
			fprintf(stdout, NFS4_STATE_FILE_ERR, strerror(errno),
			    NFS4STE_FILE);
	} else
		(void) close(fd);
}

/*
 * Prompt user for whether the default NFSv4 derived domainname
 * should be overriden (ie. Manual) or used (ie. Auto).
 */
static n4act_t
prompt_for_action(void)
{
	char	 ibuf[MAX_IBUF];
	char	*p;

	/*
	 * Issue first prompt for action
	 */
	fprintf(stdout, NFS4_ACTION_TEXT_OK);
	do {
		fprintf(stdout, NFS4_ACTION_PROMPT);

		if ((p = fgets(ibuf, MAX_IBUF, stdin)) != NULL) {
			if (ibuf[0] == '\n' || ibuf[0] == 'n' ||
			    ibuf[0] == 'N') {
				fprintf(stdout, NFS4_ACTION_TEXT_NOTE);
				return (NFS4_AUTO);

			} else if (ibuf[0] == 'y' || ibuf[0] == 'Y')
				return (NFS4_MANUAL);
		} else {
			/*
			 * Ctrl-D
			 */
			fprintf(stdout, "\n");
			clear_state();
			exit(0);
		}

		/*
		 * Unrecognized value
		 */
		fprintf(stdout, NFS4_ACTION_ERR_VALUES);

	/* CONSTCOND */
	} while (1);
	/* NOTREACHED */
}

/*
 * Remove any trailing newlines or carriage returns. Note that we _must_
 * make a copy of the working buffer since the one pointed to by str is
 * an array w/in the caller's stack and we need to continue using it long
 * after our caller has returned.
 */
char *
chomp(char *str)
{
	int	 i;
	int	 len;
	char	*cs;
	char	*p;

	if (str == (char *)NULL)
		return (NULL);

	len = strlen(cs = strdup(str));
	for (i = 0, p = cs; *p && i < len; i++, p++)
		if (*p == '\n' || *p == '\r')
			*p = '\0';
	return (cs);
}

/*
 * Prompt user for the domain to use for inbound and outbound 'owner'
 * and 'owner_group' attribute strings. The domain specified is run
 * thru validation checks and if valid, the NFSMAPID_DOMAIN setting
 * in /etc/default/nfs will be activated/modified with this value.
 */
static char *
prompt_for_domain(void)
{
	char	 ibuf[NS_MAXCDNAME];
	char	*p;
	char	*domain;
	n4err_t	 rv;

	/*
	 * Issue first prompt for domain
	 */
	fprintf(stdout, NFS4_DOMAIN_TEXT_OK);
	do {
		fprintf(stdout, NFS4_DOMAIN_PROMPT,
			cur_domain[0] != '\0' ? cur_domain : "");

		if ((p = fgets(ibuf, NS_MAXCDNAME, stdin)) == NULL) {
			/*
			 * Ctrl-D
			 */
			fprintf(stdout, "\n");
			clear_state();
			exit(0);

		} else if (ibuf[0] == '\n' || ibuf[0] == '\r') {
			/*
			 * We're presenting the user with the NFSMAPID_DOMAIN
			 * value (if available). If user hits <enter> and we
			 * have a valid cur_domain, we're done. Otherwise,
			 * we keep on nagging.
			 */
			if (ibuf[0] == '\n' && cur_domain[0] != '\0')
				return (cur_domain);

		} else {
			rv = domain_validate(domain = chomp(ibuf));
			if (rv == NFS4_SUCCESS)
				return (domain);
		}
		fprintf(stdout, NFS4_DOMAIN_INVALID);

	/* CONSTCOND */
	} while (1);
	/* NOTREACHED */
}

void
usage(int es)
{
	fprintf(stderr, USAGE_MSG, progname);
	exit(es);
}

int
main(int argc, char **argv)
{
	const char	*pattern = "NFSMAPID_DOMAIN";
	char		*dom;
	struct stat	 stb;
	int		 c;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);
	(void) set_term();

	/*
	 * When called from sysidconfig(1m), the '-c' flag is specified;
	 * however, to follow a specific ordering after a sys-unconfig
	 * reboot, '-c' should be no-op'd so that no prompts are emitted
	 * until after the system has been fully configured. This requires
	 * sysidnfs4 to be called directly (ie. w/o any flags) from the
	 * /lib/svc/method/sysidtool-system script for first boot after
	 * either fresh install _or_ sys-unconfig.
	 */
	progname = argv[0];
	while ((c = getopt(argc, argv, "cu?h")) != EOF) {
		switch (c) {
			case 'c':
				/* silent no-op */
				exit(0);
				/* NOTREACHED */

			case 'u':
				/*
				 * sysidnfs4 needs to continue to respond to
				 * the '-u' flag when sys-unconfig is called
				 * so the NFS4STE_FILE is removed and thus,
				 * the prompts are re-issued on reboot.
				 */
				clear_state();
				exit(0);
				/* NOTREACHED */

			case 'h':
			case '?':
			default:
				usage(-1);
				/*NOTREACHED*/
		}
	}

	/*
	 * Check config file first. If there is an active NFSMAPID_DOMAIN
	 * line, we use the value as the default to prompt the user with.
	 * If by any chance, the value is "Auto", we just comment the line
	 * and bail.
	 */
	if (config_nfs4(NFS4CMD_CHECK, pattern, NULL)) {
		config_nfs4(NFS4CMD_COMMENT, pattern, NULL);
		goto done;
	}

	/*
	 * To prompt or not to prompt... that is the question. If we have
	 * done this successfully already, the state file should exist !
	 */
	errno = 0;
	if (stat(NFS4STE_FILE, &stb) == 0 || errno != ENOENT)
		exit(0);

	switch (prompt_for_action()) {
		case NFS4_AUTO:
			config_nfs4(NFS4CMD_COMMENT, pattern, NULL);
			break;

		case NFS4_MANUAL:
			dom = prompt_for_domain();
			if (strcasecmp(dom, "Auto") == 0)
				config_nfs4(NFS4CMD_COMMENT, pattern, NULL);
			else
				config_nfs4(NFS4CMD_CONFIG, pattern, dom);

			if (cur_domain[0] == '\0')
				free(dom);	/* alloc'd in chomp() */
			break;

		default:
			break;
	}
	fprintf(stdout, "\n\n");
done:
	touch_state();
	exit(0);
}
