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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>
#include <malloc.h>
#include <libintl.h>
#include <stdio.h>
#include <netinet/dhcp.h>
#include <rpcsvc/nis.h>
#include <netdb.h>
#include <errno.h>
#include <sys/sockio.h>
#include <dirent.h>
#include <procfs.h>
#include <netdir.h>
#include <arpa/inet.h>
#include <rpcsvc/ypclnt.h>

#include "dd_misc.h"
#include "dd_opt.h"

#define	RDISC_FNAME	"in.rdisc"

static struct dhcp_option opt_nomem = { ENOMEM, NULL };

/*
 * Free an allocated dhcp option structure.
 */
void
dd_freeopt(struct dhcp_option *opt)
{
	int i;

	if (opt->error_code == 0) {
		switch (opt->u.ret.datatype) {
		case ASCII_OPTION:
			for (i = 0; i < opt->u.ret.count; ++i) {
				free(opt->u.ret.data.strings[i]);
			}
			free(opt->u.ret.data.strings);
			break;
		case BOOLEAN_OPTION:
			break;
		case IP_OPTION:
			for (i = 0; i < opt->u.ret.count; ++i) {
				free(opt->u.ret.data.addrs[i]);
			}
			free(opt->u.ret.data.addrs);
			break;
		case NUMBER_OPTION:
			free(opt->u.ret.data.numbers);
			break;
		case OCTET_OPTION:
			for (i = 0; i < opt->u.ret.count; ++i) {
				free(opt->u.ret.data.octets[i]);
			}
			free(opt->u.ret.data.octets);
			break;
		default:
			return;
		}
	}
	/* Don't free the static no-memory error return */
	if (opt != &opt_nomem) {
		free(opt);
	}
}

/*
 * Allocate an option structure.
 */

static struct dhcp_option *
newopt(enum option_type ot, ushort_t count)
{
	struct dhcp_option *opt;

	opt = malloc(sizeof (struct dhcp_option));
	if ((opt != NULL) && (ot != ERROR_OPTION)) {
		opt->error_code = 0;
		opt->u.ret.datatype = ot;
		switch (ot) {
		case ASCII_OPTION:
			opt->u.ret.data.strings =
			    calloc(count, sizeof (char *));
			if (opt->u.ret.data.strings == NULL) {
				free(opt);
				opt = NULL;
			} else {
				opt->u.ret.count = count;
			}
			break;
		case BOOLEAN_OPTION:
			opt->u.ret.count = count;
			break;
		case IP_OPTION:
			opt->u.ret.data.addrs = calloc(count,
			    sizeof (struct in_addr *));
			if (opt->u.ret.data.addrs == NULL) {
				free(opt);
				opt = NULL;
			} else {
				opt->u.ret.count = count;
			}
			break;
		case NUMBER_OPTION:
			opt->u.ret.data.numbers = calloc(count,
			    sizeof (int64_t));
			if (opt->u.ret.data.numbers == NULL) {
				free(opt);
				opt = NULL;
			} else {
				opt->u.ret.count = count;
			}
			break;
		case OCTET_OPTION:
			opt->u.ret.data.octets = calloc(count,
			    sizeof (uchar_t *));
			if (opt->u.ret.data.octets == NULL) {
				free(opt);
				opt = NULL;
			} else {
				opt->u.ret.count = count;
			}
			break;
		default:
			free(opt);
			opt = NULL;
		}
	}
	return (opt);
}

/*
 * Return an out of memory error
 */
static struct dhcp_option *
malloc_failure()
{
	if (opt_nomem.u.msg == NULL) {
		opt_nomem.u.msg = strerror(opt_nomem.error_code);
	}
	return (&opt_nomem);
}

/*
 * Return an error based on errno value
 */
static struct dhcp_option *
errno_opt() {
	struct dhcp_option *opt;
	int serrno;

	/* Save errno value before allocation attempt */
	serrno = errno;
	opt = newopt(ERROR_OPTION, 0);
	if (opt == NULL) {
		return (malloc_failure());
	}
	opt->error_code = serrno;
	opt->u.msg = strerror(serrno);
	return (opt);
}
/*
 * Construct list of default routers.
 */
/*ARGSUSED*/
static struct dhcp_option *
get_default_routers(const char *arg)
{
	struct dhcp_option *opt;
	FILE *fp;
	char rbuff[BUFSIZ];
	struct in_addr **addrs = NULL;
	struct in_addr **tmpaddrs;
	int addrcnt = 0;
	char *cp;
	int i;

	/*
	 * Method here is completely bogus; read output from netstat and
	 * grab lines with destination of 'default'.  Look at the netstat
	 * code if you think there's a better way...
	 */
	if ((fp = popen("netstat -r -n -f inet", "r")) == NULL) {
		return (errno_opt());
	}

	while (fgets(rbuff, BUFSIZ, fp) != NULL) {
		cp = strtok(rbuff, " \t");
		if (cp == NULL)
			continue;
		if (strcmp(cp, "default") == 0) {
			/* got one, add to list */
			tmpaddrs = realloc(addrs,
			    (addrcnt+1) * sizeof (struct in_addr *));
			if (tmpaddrs == NULL) {
				opt = errno_opt();
				for (i = addrcnt - 1; i >= 0; --i) {
					free(addrs[i]);
				}
				free(addrs);
				(void) pclose(fp);
				return (opt);
			}
			addrs = tmpaddrs;
			addrs[addrcnt] = malloc(sizeof (struct in_addr));
			if (addrs[addrcnt] == NULL) {
				opt = errno_opt();
				for (i = addrcnt - 1; i >= 0; --i) {
					free(addrs[i]);
				}
				free(addrs);
				(void) pclose(fp);
				return (opt);
			}

			cp = strtok(NULL, " \t");
			addrs[addrcnt]->s_addr = inet_addr(cp);
			/* LINTED - comparison */
			if (addrs[addrcnt]->s_addr == -1) {
				/* inet_addr didn't like it */
				opt = newopt(ERROR_OPTION, 0);
				if (opt != NULL) {
					opt->error_code = EINVAL;
					opt->u.msg = strerror(EINVAL);
				}
				while (--addrcnt >= 0)
					free(addrs[addrcnt]);
				free(addrs);
				(void) pclose(fp);
				return (opt);
			}
			++addrcnt;
		}
	}
	(void) pclose(fp);
	/*
	 * Return all the routers we found.
	 */
	if (addrcnt != 0) {
		opt = newopt(IP_OPTION, addrcnt);
		if (opt == NULL) {
			for (i = 0; i < addrcnt; ++i) {
				free(addrs[i]);
				free(addrs);
			}
			return (opt);
		}
		for (i = 0; i < addrcnt; ++i) {
			opt->u.ret.data.addrs[i] = addrs[i];
		}
		free(addrs);
	} else {
		opt = newopt(ERROR_OPTION, 0);
		if (opt != NULL) {
			opt->error_code = 1;
			opt->u.msg = gettext("No default router found");
		}
	}
	return (opt);
}

/*ARGSUSED*/
static struct dhcp_option *
get_dns_domain(const char *arg)
{
	struct dhcp_option *opt;
	res_state statp;

	statp = calloc(1, sizeof (*statp));
	if (statp == NULL) {
		opt = malloc_failure();
	} else if (res_ninit(statp) == -1) {
		/* Resolver failed initialization */
		opt = errno_opt();
	} else {
		/* Initialized OK, copy domain name to return structure */
		opt = newopt(ASCII_OPTION, 1);
		if (opt != NULL) {
			/*
			 * If first one is loopback address, we return empty
			 * as this almost certainly means that DNS is not
			 * configured.
			 */
			if (statp->nsaddr_list[0].sin_family == AF_INET &&
			    statp->nsaddr_list[0].sin_addr.s_addr ==
			    ntohl(INADDR_LOOPBACK))
				opt->u.ret.data.strings[0] = strdup("");
			else
				opt->u.ret.data.strings[0] =
				    strdup(statp->defdname);
			if (opt->u.ret.data.strings[0] == NULL) {
				/* Couldn't allocate return memory */
				dd_freeopt(opt);
				opt = malloc_failure();
			}
		}
	}
	if (statp != NULL) {
		(void) res_ndestroy(statp);
		free(statp);
	}
	return (opt);
}

/*ARGSUSED*/
static struct dhcp_option *
get_dns_servers(const char *arg)
{
	struct dhcp_option *opt;
	int i, j;
	res_state statp;

	statp = calloc(1, sizeof (*statp));
	if (statp == NULL) {
		opt = malloc_failure();
	} else if (res_ninit(statp) == -1) {
		/* Resolver initialization failed */
		opt = errno_opt();
	} else if (statp->nsaddr_list[0].sin_family == AF_INET &&
	    statp->nsaddr_list[0].sin_addr.s_addr == ntohl(INADDR_LOOPBACK)) {
		/*
		 * If first one is loopback address, we ignore as this
		 * almost certainly means that DNS is not configured.
		 */
		opt = newopt(IP_OPTION, 0);
	} else {
		/* Success, copy the data into our return structure */
		opt = newopt(IP_OPTION, statp->nscount);
		if (opt != NULL) {
			for (i = 0, j = 0; i < statp->nscount; ++i) {
				if (statp->nsaddr_list[i].sin_family != AF_INET)
					/* IPv4 only, thanks */
					continue;
				opt->u.ret.data.addrs[j] = malloc(
				    sizeof (struct in_addr));
				if (opt->u.ret.data.addrs[j] == NULL) {
					/* Out of memory, return immediately */
					dd_freeopt(opt);
					free(statp);
					return (malloc_failure());
				}
				*opt->u.ret.data.addrs[j++] =
				    statp->nsaddr_list[i].sin_addr;
			}
			/* Adjust number of addresses returned to real count */
			opt->u.ret.count = j;
		}
	}
	if (statp != NULL) {
		(void) res_ndestroy(statp);
		free(statp);
	}
	return (opt);
}

/* Get parameters related to a specific interface */
static struct dhcp_option *
get_if_param(int code, const char *arg)
{
	int s;
	struct ifconf ifc;
	int num_ifs;
	int i;
	struct ifreq *ifr;
	struct dhcp_option *opt;
#define	MY_TRUE	1
#define	MY_FALSE	0
	int found = MY_FALSE;
	struct sockaddr_in *sin;

	/*
	 * Open socket, needed for doing the ioctls.  Then get number of
	 * interfaces so we know how much memory to allocate, then get
	 * all the interface configurations.
	 */
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (ioctl(s, SIOCGIFNUM, &num_ifs) < 0) {
		return (errno_opt());
	}
	ifc.ifc_len = num_ifs * sizeof (struct ifreq);
	ifc.ifc_buf = malloc(ifc.ifc_len);
	if (ifc.ifc_buf == NULL) {
		return (malloc_failure());
	}
	if (ioctl(s, SIOCGIFCONF, &ifc) < 0) {
		opt = errno_opt();
		free(ifc.ifc_buf);
		(void) close(s);
		return (opt);
	}

	/*
	 * Find the interface which matches the one requested, and then
	 * return the parameter requested.
	 */
	for (i = 0, ifr = ifc.ifc_req; i < num_ifs; ++i, ++ifr) {
		if (strcmp(ifr->ifr_name, arg) != 0) {
			continue;
		}
		found = MY_TRUE;
		switch (code) {
		case CD_SUBNETMASK:
			if (ioctl(s, SIOCGIFNETMASK, ifr) < 0) {
				opt = errno_opt();
				free(ifc.ifc_buf);
				(void) close(s);
				return (opt);
			}
			opt = newopt(IP_OPTION, 1);
			if (opt == NULL) {
				free(ifc.ifc_buf);
				(void) close(s);
				return (malloc_failure());
			}
			opt->u.ret.data.addrs[0] =
			    malloc(sizeof (struct in_addr));
			if (opt->u.ret.data.addrs[0] == NULL) {
				free(ifc.ifc_buf);
				(void) close(s);
				return (malloc_failure());
			}
			/*LINTED - alignment*/
			sin = (struct sockaddr_in *)&ifr->ifr_addr;
			*opt->u.ret.data.addrs[0] = sin->sin_addr;
			break;
		case CD_MTU:
			if (ioctl(s, SIOCGIFMTU, ifr) < 0) {
				opt = errno_opt();
				free(ifc.ifc_buf);
				(void) close(s);
				return (opt);
			}
			opt = newopt(NUMBER_OPTION, 1);
			if (opt == NULL) {
				free(ifc.ifc_buf);
				(void) close(s);
				return (malloc_failure());
			}
			opt->u.ret.data.numbers[0] = ifr->ifr_metric;
			break;
		case CD_BROADCASTADDR:
			if (ioctl(s, SIOCGIFBRDADDR, ifr) < 0) {
				opt = errno_opt();
				free(ifc.ifc_buf);
				(void) close(s);
				return (opt);
			}
			opt = newopt(IP_OPTION, 1);
			if (opt == NULL) {
				free(ifc.ifc_buf);
				(void) close(s);
				return (malloc_failure());
			}
			opt->u.ret.data.addrs[0] =
			    malloc(sizeof (struct in_addr));
			if (opt->u.ret.data.addrs[0] == NULL) {
				free(ifc.ifc_buf);
				(void) close(s);
				return (malloc_failure());
			}
			/*LINTED - alignment*/
			sin = (struct sockaddr_in *)&ifr->ifr_addr;
			*opt->u.ret.data.addrs[0] = sin->sin_addr;
			break;
		default:
			opt = newopt(ERROR_OPTION, 0);
			opt->error_code = 1;
			opt->u.msg = gettext("Bad option code in get_if_param");
		}
		break;
	}
	free(ifc.ifc_buf);
	(void) close(s);
	if (found == MY_FALSE) {
		opt = newopt(ERROR_OPTION, 0);
		opt->error_code = 1;
		opt->u.msg = gettext("No such interface");
	}
	return (opt);
}

/*
 * See if we are using router discovery on this system.  Method is to
 * read procfs and find out if the in.rdisc daemon is running.
 */
/*ARGSUSED*/
static struct dhcp_option *
get_router_discovery(const char *arg)
{
	struct dhcp_option *opt;

	opt = newopt(NUMBER_OPTION, 1);
	if (opt == NULL) {
		return (malloc_failure());
	}
	if (dd_getpid(RDISC_FNAME) != -1) {
		opt->u.ret.data.numbers[0] = 1;
	} else {
		opt->u.ret.data.numbers[0] = 0;
	}
	return (opt);
}

/*ARGSUSED*/
static struct dhcp_option *
get_nis_domain(const char *arg)
{
	struct dhcp_option *opt;
	char *d;
	int err;

	err = yp_get_default_domain(&d);
	if (err != 0) {
		opt = newopt(ERROR_OPTION, 0);
		if (opt != NULL) {
			opt->error_code = err;
			opt->u.msg = gettext("Error in yp_get_default_domain");
		}
	} else {
		opt = newopt(ASCII_OPTION, 1);
		if (opt == NULL) {
			return (malloc_failure());
		}
		opt->u.ret.data.strings[0] = strdup(d);
		if (opt->u.ret.data.strings[0] == NULL) {
			dd_freeopt(opt);
			return (malloc_failure());
		}
	}
	return (opt);
}

/*
 * Provide a default for the NISserv option.  We can only reliably
 * find out the master (as that's the only API) so that's what we provide.
 */
/*ARGSUSED*/
static struct dhcp_option *
get_nis_servers(const char *arg)
{
	struct dhcp_option *opt;
	int err;
	char *d;
	char *m;
	struct hostent *hent;

	/*
	 * Get the default domain name, ask for master of hosts table,
	 * look master up in hosts table to get address.
	 */
	err = yp_get_default_domain(&d);
	if (err != 0) {
		opt = newopt(ERROR_OPTION, 0);
		if (opt != NULL) {
			opt->error_code = err;
			opt->u.msg = gettext("Error in yp_get_default_domain");
		}
	} else if ((err = yp_master(d, "hosts.byname", &m)) != 0) {
		opt = newopt(ERROR_OPTION, 0);
		if (opt != NULL) {
			opt->error_code = err;
			opt->u.msg = gettext("Error in yp_master");
		}
	} else if ((hent = gethostbyname(m)) == NULL) {
		free(m);
		opt = newopt(ERROR_OPTION, 0);
		if (opt != NULL) {
			opt->error_code = h_errno;
			opt->u.msg = gettext("Error in gethostbyname()");
		}
	} else {
		free(m);
		opt = newopt(IP_OPTION, 1);
		if (opt == NULL) {
			return (malloc_failure());
		}
		opt->u.ret.data.addrs[0] = malloc(sizeof (struct in_addr));
		if (opt->u.ret.data.addrs[0] == NULL) {
			dd_freeopt(opt);
			return (malloc_failure());
		}
		/*LINTED - alignment*/
		*opt->u.ret.data.addrs[0] = *(struct in_addr *)hent->h_addr;
	}
	return (opt);
}

/*
 * Retrieve the default value for a specified DHCP option.  Option code is
 * from the lst in dhcp.h, arg is an option-specific string argument, and
 * context is a presently unused parameter intended to allow this mechanism
 * to extend to vendor options in the future.  For now, only standard options
 * are supported.  Note that in some cases the returned pointer may be NULL,
 * so the caller must check for this case.
 */

/*ARGSUSED*/
struct dhcp_option *
dd_getopt(ushort_t code, const char *arg, const char *context)
{
	struct dhcp_option *opt;

	switch (code) {
	case CD_SUBNETMASK:
	case CD_MTU:
	case CD_BROADCASTADDR:
		return (get_if_param(code, arg));
	case CD_ROUTER:
		return (get_default_routers(arg));
	case CD_DNSSERV:
		return (get_dns_servers(arg));
	case CD_DNSDOMAIN:
		return (get_dns_domain(arg));
	case CD_ROUTER_DISCVRY_ON:
		return (get_router_discovery(arg));
	case CD_NIS_DOMAIN:
		return (get_nis_domain(arg));
	case CD_NIS_SERV:
		return (get_nis_servers(arg));
	default:
		opt = newopt(ERROR_OPTION, 0);
		if (opt != NULL) {
			opt->error_code = 1;
			opt->u.msg = gettext("Unimplemented option requested");
		}
		return (opt);
	}
}
