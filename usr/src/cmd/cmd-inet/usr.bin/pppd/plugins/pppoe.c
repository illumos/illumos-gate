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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * pppoe.c - pppd plugin to handle PPPoE operation.
 */

#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <strings.h>
#include <sys/stropts.h>
#include <netinet/in.h>
#include <net/pppio.h>
#include <net/sppptun.h>
#include <net/pppoe.h>

#include "pppd.h"
#include "pathnames.h"

/* Saved hook pointers */
static int (*old_check_options)(uid_t uid);
static int (*old_updown_script)(const char ***argsp);
static int (*old_sys_read_packet)(int retv, struct strbuf *ctrl,
    struct strbuf *data, int flags);

/* Room for 3 IPv4 addresses and metric */
#define	RTE_MSG_LEN	(3*16 + 10 + 1)

/* Environment string for routes */
#define	RTE_STR	"ROUTE_%d"

/*
 * strioctl()
 *
 * wrapper for STREAMS I_STR ioctl.
 */
static int
strioctl(int fd, int cmd, void *ptr, int ilen, int olen)
{
	struct strioctl	str;

	str.ic_cmd = cmd;
	str.ic_timout = 0;	/* Use default timer; 15 seconds */
	str.ic_len = ilen;
	str.ic_dp = ptr;

	if (ioctl(fd, I_STR, &str) == -1) {
		return (-1);
	}
	if (str.ic_len != olen) {
		return (-1);
	}
	return (0);
}

/*
 * If the user named the tunneling device, check that it is
 * reasonable; otherwise check that standard input is the tunnel.
 */
static int
pppoe_check_options(uid_t uid)
{
	int tstfd;	/* fd for device being checked */
	int err;	/* saved errno value */
	int retv;	/* return value */
	int intv;	/* integer return value (from ioctl) */
	union ppptun_name ptn;

	if (devnam[0] != '\0') {
		/*
		 * Open as real user so that modes on device can be
		 * used to limit access.
		 */
		if (!devnam_info.priv)
			(void) seteuid(uid);
		tstfd = open(devnam, O_NONBLOCK | O_RDWR, 0);
		err = errno;
		if (!devnam_info.priv)
			(void) seteuid(0);
		if (tstfd == -1) {
			errno = err;
			option_error("unable to open %s: %m", devnam);
			return (-1);
		}
		retv = strioctl(tstfd, PPPTUN_GDATA, &ptn, 0, sizeof (ptn));
		(void) close(tstfd);
		if (retv == -1) {
			option_error("device %s is not a PPP tunneling device",
			    devnam);
			return (-1);
		}
	} else {
		retv = strioctl(0, PPPIO_GTYPE, &intv, 0, sizeof (intv));
		if (retv == -1) {
			option_error("standard input is not a PPP device");
			return (-1);
		}
		retv = strioctl(0, PPPTUN_GDATA, &ptn, 0, sizeof (ptn));
		if (retv == -1) {
			option_error("standard input is not a PPP tunnel");
			return (-1);
		}
		if (strcmp(ptn.ptn_name + strlen(ptn.ptn_name) - 6,
		    ":pppoe") != 0) {
			option_error("standard input not connected to PPPoE");
			return (-1);
		}
	}
	if (old_check_options != NULL &&
	    old_check_options != pppoe_check_options)
		return ((*old_check_options)(uid));
	return (0);
}

/*
 * When we're about to call one of the up or down scripts, change the
 * second argument to contain the interface name and selected PPPoE
 * service.
 */
static int
pppoe_updown_script(const char ***argsp)
{
	const char *cp;

	if ((*argsp)[2] == devnam &&
	    (cp = script_getenv("IF_AND_SERVICE")) != NULL)
		(*argsp)[2] = cp;
	if (old_updown_script != NULL &&
	    old_updown_script != pppoe_updown_script)
		return ((*old_updown_script)(argsp));
	return (0);
}

/*
 * Concatenate and save strings from command line into environment
 * variable.
 */
static void
cat_save_env(char **argv, char idchar, const char *envname)
{
	char **argp;
	int totlen;
	char *str;
	char *cp;

	totlen = 0;
	for (argp = argv; argp[0] != NULL; argp += 2)
		if (*argp[0] == idchar)
			totlen += strlen(argp[1]) + 1;
	if ((str = malloc(totlen + 1)) == NULL) {
		error("cannot malloc PPPoE environment for %s", envname);
		return;
	}
	cp = str;
	for (argp = argv; argp[0] != NULL; argp += 2)
		if (*argp[0] == idchar) {
			(void) strcpy(cp, argp[1]);
			cp += strlen(cp);
			*cp++ = '\n';
		}
	*cp = '\0';
	script_setenv(envname, str, 0);
}

/*
 * Convert Message Of The Moment (MOTM) and Host Uniform Resource
 * Locator (HURL) strings into environment variables and command-line
 * arguments for script.
 */
static void
handle_motm_hurl(char **argv, int argc, const uint8_t *tagp, int pktlen)
{
	int ttype;
	int tlen;
	char *str;
	char **oargv = argv;

	/* Must have room for two strings and NULL terminator. */
	while (argc >= 3) {
		str = NULL;
		while (pktlen >= POET_HDRLEN) {
			ttype = POET_GET_TYPE(tagp);
			if (ttype == POETT_END)
				break;
			tlen = POET_GET_LENG(tagp);
			if (tlen > pktlen - POET_HDRLEN)
				break;
			if (ttype == POETT_HURL || ttype == POETT_MOTM) {
				if ((str = malloc(tlen + 1)) == NULL) {
					error("cannot malloc PPPoE message");
					break;
				}
				(void) memcpy(str, POET_DATA(tagp), tlen);
				str[tlen] = '\0';
			}
			pktlen -= POET_HDRLEN + tlen;
			tagp += POET_HDRLEN + tlen;
			if (str != NULL)
				break;
		}
		if (str == NULL)
			break;
		*argv++ = ttype == POETT_HURL ? "hurl" : "motm";
		*argv++ = str;
		argc -= 2;
	}
	*argv = NULL;
	cat_save_env(oargv, 'h', "HURL");
	cat_save_env(oargv, 'm', "MOTM");
}

/*
 * Convert IP Route Add structures into environment variables and
 * command-line arguments for script.
 */
static void
handle_ip_route_add(char **argv, int argc, const uint8_t *tagp, int pktlen)
{
	int ttype;
	int tlen;
	char *str;
	poer_t poer;
	int idx;
	char envname[sizeof (RTE_STR) + 10];

	idx = 0;

	/* Must have room for four strings and NULL terminator. */
	while (argc >= 5) {
		str = NULL;
		while (pktlen >= POET_HDRLEN) {
			ttype = POET_GET_TYPE(tagp);
			if (ttype == POETT_END)
				break;
			tlen = POET_GET_LENG(tagp);
			if (tlen > pktlen - POET_HDRLEN)
				break;
			if (ttype == POETT_RTEADD && tlen >= sizeof (poer) &&
			    (str = malloc(RTE_MSG_LEN)) == NULL) {
				error("cannot malloc PPPoE route");
				break;
			}
			pktlen -= POET_HDRLEN + tlen;
			tagp += POET_HDRLEN + tlen;
			if (str != NULL)
				break;
		}
		if (str == NULL)
			break;
		/* No alignment restrictions on source; copy to local. */
		(void) memcpy(&poer, POET_DATA(tagp), sizeof (poer));
		(void) slprintf(str, RTE_MSG_LEN, "%I %I %I %d",
		    poer.poer_dest_network, poer.poer_subnet_mask,
		    poer.poer_gateway, (int)poer.poer_metric);
		/* Save off the environment variable version of this. */
		(void) slprintf(envname, sizeof (envname), RTE_STR, ++idx);
		script_setenv(envname, str, 0);
		*argv++ = str;	/* Destination */
		str = strchr(str, ' ');
		*str++ = '\0';
		*argv++ = str;	/* Subnet mask */
		str = strchr(str, ' ');
		*str++ = '\0';
		*argv++ = str;	/* Gateway */
		str = strchr(str, ' ');
		*str++ = '\0';
		*argv++ = str;	/* Metric */
		argc -= 4;
	}
	*argv = NULL;
}

/*
 * If we get here, then the driver has already validated the sender,
 * the PPPoE version, the message length, and session ID.  The code
 * number is known not to be zero.
 */
static int
handle_pppoe_input(const ppptun_atype *pma, struct strbuf *ctrl,
    struct strbuf *data)
{
	const poep_t *poep;
	struct ppp_ls *plp;
	const char *mname;
	const char *cstr;
	char *str;
	char *cp;
	char *argv[64];
	pid_t rpid;
	char **argp;
	int idx;
	char envname[sizeof (RTE_STR) + 10];
	const uint8_t *tagp;
	int pktlen;

	/*
	 * Warning: the data->buf pointer here is not necessarily properly
	 * aligned for access to the poep_session_id or poep_length members.
	 */
	/* LINTED: alignment */
	poep = (const poep_t *)data->buf;
	tagp = (const uint8_t *)poep + offsetof(poep_t, poep_length);
	pktlen = (tagp[0] << 8) + tagp[1];
	tagp = (const uint8_t *)(poep + 1);
	switch (poep->poep_code) {
	case POECODE_PADT:
		dbglog("received PPPoE PADT; connection has been closed");
		/* LINTED: alignment */
		plp = (struct ppp_ls *)ctrl->buf;
		plp->magic = PPPLSMAGIC;
		plp->ppp_message = PPP_LINKSTAT_HANGUP;
		ctrl->len = sizeof (*plp);
		return (0);

		/* Active Discovery Message and Network extensions */
	case POECODE_PADM:
	case POECODE_PADN:
		if (poep->poep_code == POECODE_PADM) {
			argv[0] = _ROOT_PATH "/etc/ppp/pppoe-msg";
			mname = "PADM";
			handle_motm_hurl(argv + 4, Dim(argv) - 4, tagp, pktlen);
		} else {
			argv[0] = _ROOT_PATH "/etc/ppp/pppoe-network";
			mname = "PADN";
			handle_ip_route_add(argv + 4, Dim(argv) - 4, tagp,
			    pktlen);
		}
		argv[1] = ifname;
		/* Note: strdup doesn't handle NULL input. */
		str = NULL;
		if ((cstr = script_getenv("IF_AND_SERVICE")) == NULL ||
		    (str = strdup(cstr)) == NULL) {
			argv[2] = argv[3] = "";
		} else {
			if ((cp = strrchr(str, ':')) == NULL)
				cp = str + strlen(str);
			else
				*cp++ = '\0';
			argv[2] = str;
			argv[3] = cp;
		}
		rpid = run_program(argv[0], argv, 0, NULL, NULL);
		if (rpid == (pid_t)0)
			dbglog("ignored PPPoE %s; no %s script", mname,
			    argv[0]);
		else if (rpid != (pid_t)-1)
			dbglog("PPPoE %s: started PID %d", mname, rpid);
		if (str != NULL)
			free(str);
		/* Free storage allocated by handle_{motm_hurl,ip_route_add} */
		idx = 0;
		for (argp = argv + 4; *argp != NULL; ) {
			if (poep->poep_code == POECODE_PADM) {
				free(argp[1]);
				argp += 2;
			} else {
				free(argp[0]);
				argp += 4;
				(void) slprintf(envname, sizeof (envname),
				    RTE_STR, ++idx);
				script_unsetenv(envname);
			}
		}
		if (poep->poep_code == POECODE_PADM) {
			script_unsetenv("HURL");
			script_unsetenv("MOTM");
		}
		break;

	default:
		warn("unexpected PPPoE code %d from %s", poep->poep_code,
		    ether_ntoa(&pma->pta_pppoe.ptma_mac_ether_addr));
		break;
	}
	return (-1);
}

/*
 * sys-solaris has just read in a packet; grovel through it and see if
 * it's something we need to handle ourselves.
 */
static int
pppoe_sys_read_packet(int retv, struct strbuf *ctrl, struct strbuf *data,
    int flags)
{
	struct ppptun_control *ptc;

	if (retv >= 0 && !(retv & MORECTL) && ctrl->len >= sizeof (uint32_t)) {
		/* LINTED: alignment */
		ptc = (struct ppptun_control *)ctrl->buf;
		/* ptc_discrim is the first uint32_t of the structure. */
		if (ptc->ptc_discrim == PPPOE_DISCRIM) {
			retv = -1;
			if (ctrl->len == sizeof (*ptc) &&
			    ptc->ptc_action == PTCA_CONTROL)
				retv = handle_pppoe_input(&ptc->ptc_address,
				    ctrl, data);
			if (retv < 0)
				errno = EAGAIN;
			return (retv);
		}
	}
	/* Forward along to other plug-ins */
	if (old_sys_read_packet != NULL &&
	    old_sys_read_packet != pppoe_sys_read_packet)
		return ((*old_sys_read_packet)(retv, ctrl, data, flags));
	return (retv);
}

/*
 * Get an environment variable from the chat script.
 */
static int
saveenv(FILE *fd, const char *envname)
{
	char envstr[1024];
	int len;

	if (fgets(envstr, sizeof (envstr), fd) == NULL)
		return (-1);
	len = strlen(envstr);
	if (len <= 1)
		return (0);
	envstr[len-1] = '\0';
	script_setenv(envname, envstr, 0);
	return (1);
}

/*
 * Read environment variables exported by chat script.
 */
static void
pppoe_device_pipe(int pipefd)
{
	FILE *fd;
	int i;
	char envname[32];

	fd = fdopen(pipefd, "r");
	if (fd == NULL)
		fatal("unable to open environment file: %m");
	(void) saveenv(fd, "IF_AND_SERVICE");
	(void) saveenv(fd, "SERVICE_NAME");
	(void) saveenv(fd, "AC_NAME");
	(void) saveenv(fd, "AC_MAC");
	(void) saveenv(fd, "SESSION_ID");
	for (i = 1; ; i++) {
		slprintf(envname, sizeof (envname), "VENDOR_SPECIFIC_%d", i);
		if (saveenv(fd, envname) <= 0)
			break;
	}
	(void) fclose(fd);
}

void
plugin_init(void)
{
	if (absmax_mtu > 1492)
		absmax_mtu = 1492;
	if (absmax_mru > 1492)
		absmax_mru = 1492;
	old_check_options = check_options_hook;
	check_options_hook = pppoe_check_options;
	old_updown_script = updown_script_hook;
	updown_script_hook = pppoe_updown_script;
	old_sys_read_packet = sys_read_packet_hook;
	sys_read_packet_hook = pppoe_sys_read_packet;
	device_pipe_hook = pppoe_device_pipe;
	already_ppp = 1;
}
