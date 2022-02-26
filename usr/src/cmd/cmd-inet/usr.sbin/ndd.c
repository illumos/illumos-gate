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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/* Copyright (c) 1990 Mentat Inc. */

#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <stropts.h>
#include <inet/tunables.h>
#include <inet/nd.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <libdllink.h>
#include <libintl.h>
#include <libipadm.h>

static boolean_t do_getset(int fd, int cmd, char *buf, int buf_len);
static int	get_value(char *msg, char *buf, int buf_len);
static void	name_print(char *buf);
static void	getset_interactive(int fd);
static int	open_device(void);
static char	*errmsg(int err);
static void	fatal(char *fmt, ...);
static void	printe(boolean_t print_errno, char *fmt, ...);

static char	modpath[128];	/* path to module */
static char	gbuf[65536];	/* need large buffer to retrieve all names */
static char	usage_str[] =	"usage: ndd -set device_name name value\n"
				"       ndd [-get] device_name name [name ...]";

/*
 * Maps old ndd_name to the new ipadm_name. Any ndd property that is moved to
 * libipadm should have an entry here to ensure backward compatibility
 */
typedef struct ndd2ipadm_map {
	char	*ndd_name;
	char	*ipadm_name;
	uint_t	ipadm_proto;
	uint_t	ipadm_flags;
	uint_t	ndd_perm;
} ndd2ipadm_map_t;

static ndd2ipadm_map_t map[] = {
	{ "ip_def_ttl",			"ttl",		MOD_PROTO_IPV4, 0, 0 },
	{ "ip6_def_hops",		"hoplimit",	MOD_PROTO_IPV6, 0, 0 },
	{ "ip_forwarding",		"forwarding",	MOD_PROTO_IPV4, 0, 0 },
	{ "ip6_forwarding",		"forwarding",	MOD_PROTO_IPV6, 0, 0 },
	{ "icmp_recv_hiwat",		"recv_maxbuf",	MOD_PROTO_RAWIP, 0, 0 },
	{ "icmp_xmit_hiwat",		"send_maxbuf",	MOD_PROTO_RAWIP, 0, 0 },
	{ "tcp_ecn_permitted",		"ecn",		MOD_PROTO_TCP, 0, 0 },
	{ "tcp_extra_priv_ports_add",	"extra_priv_ports",	MOD_PROTO_TCP,
	    IPADM_OPT_APPEND, MOD_PROP_PERM_WRITE },
	{ "tcp_extra_priv_ports_del",	"extra_priv_ports",	MOD_PROTO_TCP,
	    IPADM_OPT_REMOVE, MOD_PROP_PERM_WRITE },
	{ "tcp_extra_priv_ports",	"extra_priv_ports",	MOD_PROTO_TCP,
	    0, MOD_PROP_PERM_READ },
	{ "tcp_largest_anon_port",	"largest_anon_port",	MOD_PROTO_TCP,
	    0, 0 },
	{ "tcp_recv_hiwat",		"recv_maxbuf",	MOD_PROTO_TCP, 0, 0 },
	{ "tcp_sack_permitted",		"sack",		MOD_PROTO_TCP, 0, 0 },
	{ "tcp_xmit_hiwat",		"send_maxbuf",	MOD_PROTO_TCP, 0, 0 },
	{ "tcp_smallest_anon_port",	"smallest_anon_port",	MOD_PROTO_TCP,
	    0, 0 },
	{ "tcp_smallest_nonpriv_port",	"smallest_nonpriv_port", MOD_PROTO_TCP,
	    0, 0 },
	{ "udp_extra_priv_ports_add",	"extra_priv_ports",	MOD_PROTO_UDP,
	    IPADM_OPT_APPEND, MOD_PROP_PERM_WRITE },
	{ "udp_extra_priv_ports_del",	"extra_priv_ports",	MOD_PROTO_UDP,
	    IPADM_OPT_REMOVE, MOD_PROP_PERM_WRITE },
	{ "udp_extra_priv_ports",	"extra_priv_ports",	MOD_PROTO_UDP,
	    0, MOD_PROP_PERM_READ },
	{ "udp_largest_anon_port",	"largest_anon_port",    MOD_PROTO_UDP,
	    0, 0 },
	{ "udp_recv_hiwat",		"recv_maxbuf",	MOD_PROTO_UDP, 0, 0 },
	{ "udp_xmit_hiwat",		"send_maxbuf",	MOD_PROTO_UDP, 0, 0 },
	{ "udp_smallest_anon_port",	"smallest_anon_port",	MOD_PROTO_UDP,
	    0, 0 },
	{ "udp_smallest_nonpriv_port",	"smallest_nonpriv_port", MOD_PROTO_UDP,
	    0, 0 },
	{ "sctp_extra_priv_ports_add",	"extra_priv_ports",	MOD_PROTO_SCTP,
	    IPADM_OPT_APPEND, MOD_PROP_PERM_WRITE },
	{ "sctp_extra_priv_ports_del",	"extra_priv_ports",	MOD_PROTO_SCTP,
	    IPADM_OPT_REMOVE, MOD_PROP_PERM_WRITE },
	{ "sctp_extra_priv_ports",	"extra_priv_ports",	MOD_PROTO_SCTP,
	    0, MOD_PROP_PERM_READ },
	{ "sctp_largest_anon_port",	"largest_anon_port",	MOD_PROTO_SCTP,
	    0, 0 },
	{ "sctp_recv_hiwat",		"recv_maxbuf",	MOD_PROTO_SCTP, 0, 0 },
	{ "sctp_xmit_hiwat",		"send_maxbuf",	MOD_PROTO_SCTP, 0, 0 },
	{ "sctp_smallest_anon_port",	"smallest_anon_port",	MOD_PROTO_SCTP,
	    0, 0 },
	{ "sctp_smallest_nonpriv_port",	"smallest_nonpriv_port", MOD_PROTO_SCTP,
	    0, 0 },
	{ NULL, NULL, 0, 0, 0 }
};

static uint_t
ndd_str2proto(const char *protostr)
{
	if (strcmp(protostr, "tcp") == 0 ||
	    strcmp(protostr, "tcp6") == 0) {
		return (MOD_PROTO_TCP);
	} else if (strcmp(protostr, "udp") == 0 ||
	    strcmp(protostr, "udp6") == 0) {
		return (MOD_PROTO_UDP);
	} else if (strcmp(protostr, "ip") == 0 ||
	    strcmp(protostr, "ip6") == 0 ||
	    strcmp(protostr, "arp") == 0) {
		return (MOD_PROTO_IP);
	} else if (strcmp(protostr, "icmp") == 0 ||
	    strcmp(protostr, "icmp6") == 0) {
		return (MOD_PROTO_RAWIP);
	} else if (strcmp(protostr, "sctp") == 0 ||
	    strcmp(protostr, "sctp6") == 0) {
		return (MOD_PROTO_SCTP);
	}
	return (MOD_PROTO_NONE);
}

static char *
ndd_perm2str(uint_t perm)
{
	switch (perm) {
	case MOD_PROP_PERM_READ:
		return ("read only");
	case MOD_PROP_PERM_WRITE:
		return ("write only");
	case MOD_PROP_PERM_RW:
		return ("read and write");
	}

	return (NULL);
}

/*
 * Print all the protocol properties for the given protocol name. The kernel
 * returns all the properties for the given protocol therefore we have to
 * apply some filters before we print them.
 *
 *	- convert any new ipadm name to old ndd name using the table.
 *	  For example: `sack' --> `tcp_sack_permitted'.
 *
 *	- replace leading underscores with protocol name.
 *	  For example: `_strong_iss' --> `tcp_strong_iss'
 *
 *	- don't print new public properties that are supported only by ipadm(8)
 *	  For example: `hostmodel' should be supported only from ipadm(8).
 *	  Such properties are identified by not having leading '_' and not
 *	  being present in the mapping table.
 */
static void
print_ipadm2ndd(char *oldbuf, uint_t obufsize)
{
	ndd2ipadm_map_t	*nimap;
	char		*pname, *rwtag, *protostr;
	uint_t		proto, perm;
	boolean_t	matched;

	pname = oldbuf;
	while (pname[0] && pname < (oldbuf + obufsize - 1)) {
		for (protostr = pname; !isspace(*protostr); protostr++)
			;
		*protostr++ = '\0';
		/* protostr now points to protocol */

		for (rwtag = protostr; !isspace(*rwtag); rwtag++)
			;
		*rwtag++ = '\0';
		/* rwtag now points to permissions */

		proto = atoi(protostr);
		perm = atoi(rwtag);
		matched = B_FALSE;
		for (nimap = map; nimap->ndd_name != NULL; nimap++) {
			if (strcmp(pname, nimap->ipadm_name) != 0 ||
			    !(nimap->ipadm_proto & proto))
				continue;

			matched = B_TRUE;
			if (nimap->ndd_perm != 0)
				perm = nimap->ndd_perm;
			(void) printf("%-30s (%s)\n", nimap->ndd_name,
			    ndd_perm2str(perm));
		}
		/*
		 * print only if it's a private property. We should
		 * not be printing any new public property in ndd(8)
		 * output.
		 */
		if (!matched && pname[0] == '_') {
			char	tmpstr[512];
			int	err;

			err = ipadm_new2legacy_propname(pname, tmpstr,
			    sizeof (tmpstr), proto);
			assert(err != -1);

			(void) printf("%-30s (%s)\n", tmpstr,
			    ndd_perm2str(perm));
		}
		for (pname = rwtag; *pname++; )
			;
	}
}

/*
 * get/set the value for a given property by calling into libipadm. The
 * IPH_LEGACY flag is used by libipadm for special handling. For some
 * properties, libipadm.so displays strings (for e.g., on/off,
 * never/passive/active, et al) instead of numerals. However ndd(8) always
 * printed numberals. This flag will help in avoiding printing strings.
 */
static boolean_t
do_ipadm_getset(int cmd, char *buf, int buflen)
{
	ndd2ipadm_map_t	*nimap;
	ipadm_handle_t	iph = NULL;
	ipadm_status_t	status;
	char		*mod;
	uint_t		proto, perm = 0, flags = 0;
	char		*pname, *pvalp, nname[512];
	int		i;

	if ((mod = strrchr(modpath, '/')) == NULL)
		mod = modpath;
	else
		++mod;
	if ((proto = ndd_str2proto(mod)) == MOD_PROTO_NONE)
		return (B_FALSE);

	if ((status = ipadm_open(&iph, IPH_LEGACY)) != IPADM_SUCCESS)
		goto fail;

	pname = buf;
	for (nimap = map; nimap->ndd_name != NULL; nimap++) {
		if (strcmp(pname, nimap->ndd_name) == 0) {
			pname = nimap->ipadm_name;
			proto = nimap->ipadm_proto;
			flags = nimap->ipadm_flags;
			perm = nimap->ndd_perm;
			break;
		}
	}

	if (nimap->ndd_name == NULL && strcmp(pname, "?") != 0) {
		/* do not allow set/get of public properties from ndd(8) */
		if (ipadm_legacy2new_propname(pname, nname, sizeof (nname),
		    &proto) != 0) {
			status = IPADM_PROP_UNKNOWN;
			goto fail;
		} else {
			pname = nname;
		}
	}

	if (cmd == ND_GET) {
		char		propval[MAXPROPVALLEN], allprop[64536];
		uint_t		pvalsz;
		sa_family_t	af = AF_UNSPEC;
		int		err;

		if (perm == MOD_PROP_PERM_WRITE)
			fatal("operation failed: Permission denied");

		if (strcmp(pname, "?") == 0) {
			pvalp = allprop;
			pvalsz = sizeof (allprop);
		} else {
			pvalp = propval;
			pvalsz = sizeof (propval);
		}

		status = ipadm_get_prop(iph, pname, pvalp, &pvalsz, proto,
		    IPADM_OPT_ACTIVE);
		if (status != IPADM_SUCCESS)
			goto fail;

		if (strcmp(pname, "?") == 0) {
			(void) print_ipadm2ndd(pvalp, pvalsz);
		} else {
			char *tmp = pvalp;

			/*
			 * For backward compatibility if there are multiple
			 * values print each value in it's own line.
			 */
			while (*tmp != '\0') {
				if (*tmp == ',')
					*tmp = '\n';
				tmp++;
			}
			(void) printf("%s\n", pvalp);
		}
		(void) fflush(stdout);
	} else {
		if (perm == MOD_PROP_PERM_READ)
			fatal("operation failed: Permission denied");

		/* walk past the property name to find the property value */
		for (i = 0; buf[i] != '\0'; i++)
			;

		pvalp = &buf[++i];
		status = ipadm_set_prop(iph, pname, pvalp, proto,
		    flags|IPADM_OPT_ACTIVE);
	}
fail:
	ipadm_close(iph);
	if (status != IPADM_SUCCESS)
		fatal("operation failed: %s", ipadm_status2str(status));
	return (B_TRUE);
}

/*
 * gldv3_warning() catches the case of /sbin/ndd abuse to administer
 * ethernet/MII props. Note that /sbin/ndd has not been abused
 * for administration of other datalink types, which makes it permissible
 * to test for support of the flowctrl property.
 */
static void
gldv3_warning(char *module)
{
	datalink_id_t	linkid;
	dladm_status_t	status;
	char		buf[DLADM_PROP_VAL_MAX], *cp;
	uint_t		cnt = 1;
	char		*link;
	dladm_handle_t	handle;

	link = strrchr(module, '/');
	if (link == NULL)
		return;

	if (dladm_open(&handle) != DLADM_STATUS_OK)
		return;

	status = dladm_name2info(handle, ++link, &linkid, NULL, NULL, NULL);
	if (status == DLADM_STATUS_OK) {
		cp = buf;
		status = dladm_get_linkprop(handle, linkid,
		    DLADM_PROP_VAL_CURRENT, "flowctrl", &cp, &cnt);
		if (status == DLADM_STATUS_OK) {
			(void) fprintf(stderr, gettext(
			    "WARNING: The ndd commands for datalink "
			    "administration are obsolete and may be "
			    "removed in a future release of Solaris. "
			    "Use dladm(8) to manage datalink tunables.\n"));
		}
	}
	dladm_close(handle);
}

/* ARGSUSED */
int
main(int argc, char **argv)
{
	char	*cp, *value, *mod;
	int	cmd;
	int	fd = 0;

	if (!(cp = *++argv)) {
		while ((fd = open_device()) != -1) {
			getset_interactive(fd);
			(void) close(fd);
		}
		return (EXIT_SUCCESS);
	}

	cmd = ND_GET;
	if (cp[0] == '-') {
		if (strncmp(&cp[1], "set", 3) == 0)
			cmd = ND_SET;
		else if (strncmp(&cp[1], "get", 3) != 0)
			fatal(usage_str);
		if (!(cp = *++argv))
			fatal(usage_str);
	}

	gldv3_warning(cp);

	mod = strrchr(cp, '/');
	if (mod != NULL)
		mod++;
	else
		mod = cp;

	if (ndd_str2proto(mod) == MOD_PROTO_NONE) {
		if ((fd = open(cp, O_RDWR)) == -1)
			fatal("open of %s failed: %s", cp, errmsg(errno));
		if (!isastream(fd))
			fatal("%s is not a streams device", cp);
	}

	(void) strlcpy(modpath, cp, sizeof (modpath));
	if (!(cp = *++argv)) {
		getset_interactive(fd);
		(void) close(fd);
		return (EXIT_SUCCESS);
	}

	if (cmd == ND_SET) {
		if (!(value = *++argv))
			fatal(usage_str);
		(void) snprintf(gbuf, sizeof (gbuf), "%s%c%s%c", cp, '\0',
		    value, '\0');
		if (!do_getset(fd, cmd, gbuf, sizeof (gbuf)))
			return (EXIT_FAILURE);
	} else {
		do {
			(void) memset(gbuf, '\0', sizeof (gbuf));
			(void) strlcpy(gbuf, cp, sizeof (gbuf));
			if (!do_getset(fd, cmd, gbuf, sizeof (gbuf)))
				return (EXIT_FAILURE);
			if (cp = *++argv)
				(void) putchar('\n');
		} while (cp);
	}

	(void) close(fd);
	return (EXIT_SUCCESS);
}

static void
name_print(char *buf)
{
	char *cp, *rwtag;

	for (cp = buf; cp[0]; ) {
		for (rwtag = cp; !isspace(*rwtag); rwtag++)
			;
		*rwtag++ = '\0';
		while (isspace(*rwtag))
			rwtag++;
		(void) printf("%-30s%s\n", cp, rwtag);
		for (cp = rwtag; *cp++; )
			;
	}
}

/*
 * This function is vile, but it's better here than in the kernel.
 */
static boolean_t
is_obsolete(const char *param)
{
	if (strcmp(param, "ip_enable_group_ifs") == 0 ||
	    strcmp(param, "ifgrp_status") == 0) {
		(void) fprintf(stderr, "The \"%s\" tunable has been superseded "
		    "by IP Multipathing.\nPlease see the IP Network "
		    "Multipathing Administration Guide for details.\n", param);
		return (B_TRUE);
	}
	return (B_FALSE);
}

static boolean_t
do_getset(int fd, int cmd, char *buf, int buf_len)
{
	char	*cp;
	struct strioctl	stri;
	boolean_t	is_name_get;

	if (is_obsolete(buf))
		return (B_TRUE);

	/*
	 * See if libipadm can handle this request, i.e., properties on
	 * following modules arp, ip, ipv4, ipv6, tcp, udp and sctp
	 */
	if (do_ipadm_getset(cmd, buf, buf_len))
		return (B_TRUE);

	stri.ic_cmd = cmd;
	stri.ic_timout = 0;
	stri.ic_len = buf_len;
	stri.ic_dp = buf;
	is_name_get = stri.ic_cmd == ND_GET && buf[0] == '?' && buf[1] == '\0';

	if (ioctl(fd, I_STR, &stri) == -1) {
		if (errno == ENOENT)
			(void) printf("name is non-existent for this module\n"
			    "for a list of valid names, use name '?'\n");
		else
			(void) printf("operation failed: %s\n", errmsg(errno));
		return (B_FALSE);
	}
	if (is_name_get)
		name_print(buf);
	else if (stri.ic_cmd == ND_GET) {
		for (cp = buf; *cp != '\0'; cp += strlen(cp) + 1)
			(void) puts(cp);
	}
	(void) fflush(stdout);
	return (B_TRUE);
}

static int
get_value(char *msg, char *buf, int buf_len)
{
	int	len;

	(void) printf("%s", msg);
	(void) fflush(stdout);

	buf[buf_len-1] = '\0';
	if (fgets(buf, buf_len-1, stdin) == NULL)
		exit(EXIT_SUCCESS);
	len = strlen(buf);
	if (buf[len-1] == '\n')
		buf[len - 1] = '\0';
	else
		len++;
	return (len);
}

static void
getset_interactive(int fd)
{
	int	cmd;
	char	*cp;
	int	len, buf_len;
	char	len_buf[10];

	for (;;) {
		(void) memset(gbuf, '\0', sizeof (gbuf));
		len = get_value("name to get/set ? ", gbuf, sizeof (gbuf));
		if (len == 1 || (gbuf[0] == 'q' && gbuf[1] == '\0'))
			return;
		for (cp = gbuf; cp < &gbuf[len]; cp++) {
			if (isspace(*cp))
				*cp = '\0';
		}
		cmd = ND_GET;
		if (gbuf[0] != '?' &&
		    get_value("value ? ", &gbuf[len], sizeof (gbuf) - len) > 1)
			cmd = ND_SET;
		if (cmd == ND_GET && gbuf[0] != '?' &&
		    get_value("length ? ", len_buf, sizeof (len_buf)) > 1) {
			if (!isdigit(len_buf[0])) {
				(void) printf("invalid length\n");
				continue;
			}
			buf_len = atoi(len_buf);
		} else
			buf_len = sizeof (gbuf);
		(void) do_getset(fd, cmd, gbuf, buf_len);
	}
}

static void
printe(boolean_t print_errno, char *fmt, ...)
{
	va_list	ap;
	int error = errno;

	va_start(ap, fmt);
	(void) printf("*ERROR* ");
	(void) vprintf(fmt, ap);
	va_end(ap);

	if (print_errno)
		(void) printf(": %s\n", errmsg(error));
	else
		(void) printf("\n");
}

static int
open_device()
{
	int	fd, len;
	char	*mod;

	for (;;) {
		len = get_value("module to query ? ", modpath,
		    sizeof (modpath));
		if (len <= 1 ||
		    (len == 2 && (modpath[0] == 'q' || modpath[0] == 'Q')))
			return (-1);

		mod = strrchr(modpath, '/');
		if (mod != NULL)
			mod++;
		else
			mod = modpath;
		if (ndd_str2proto(mod) == MOD_PROTO_NONE) {
			if ((fd = open(modpath, O_RDWR)) == -1) {
				printe(B_TRUE, "open of %s failed", modpath);
				continue;
			}
		} else {
			return (0);
		}

		gldv3_warning(modpath);

		if (isastream(fd))
			return (fd);

		(void) close(fd);
		printe(B_FALSE, "%s is not a streams device", modpath);
	}
}

static void
fatal(char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
	(void) fprintf(stderr, "\n");

	exit(EXIT_FAILURE);
}

static char *
errmsg(int error)
{
	char *msg = strerror(error);

	return (msg != NULL ? msg : "unknown error");
}
