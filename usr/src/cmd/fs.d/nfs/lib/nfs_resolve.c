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


/*
 * Helper routines for  nfsmapid and autod daemon
 * to translate hostname to IP address and Netinfo.
 */
#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>
#include <signal.h>
#include <libintl.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <memory.h>
#include <pwd.h>
#include <grp.h>
#include <door.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <deflt.h>
#include <netdir.h>
#include <nfs/nfs4.h>
#include <nfs/nfssys.h>
#include <nfs/nfsid_map.h>
#include <nfs/mapid.h>
#include <nfs/nfs_sec.h>
#include <sys/sdt.h>
#include <sys/idmap.h>
#include <idmap.h>
#include <sys/fs/autofs.h>
#include "nfs_resolve.h"

void
free_knconf(struct knetconfig *k)
{
	if (k == NULL)
		return;
	if (k->knc_protofmly)
		free(k->knc_protofmly);
	if (k->knc_proto)
		free(k->knc_proto);
	free(k);
}

struct knetconfig *
get_knconf(struct netconfig *nconf)
{
	struct stat stbuf;
	struct knetconfig *k = NULL;
	int len;

	if (stat(nconf->nc_device, &stbuf) < 0) {
		syslog(LOG_ERR, "get_knconf: stat %s: %m", nconf->nc_device);
		return (NULL);
	}
	k = (struct knetconfig *)malloc(sizeof (*k));
	if (k == NULL)
		goto nomem;
	k->knc_semantics = nconf->nc_semantics;

	len = strlen(nconf->nc_protofmly);
	if (len <= 0)
		goto err_out;
	k->knc_protofmly = malloc(KNC_STRSIZE);
	if (k->knc_protofmly == NULL)
		goto nomem;
	bzero(k->knc_protofmly, KNC_STRSIZE);
	bcopy(nconf->nc_protofmly, k->knc_protofmly, len);

	len = strlen(nconf->nc_proto);
	if (len <= 0)
		goto err_out;
	k->knc_proto = malloc(KNC_STRSIZE);
	if (k->knc_proto == NULL)
		goto nomem;
	bzero(k->knc_proto, KNC_STRSIZE);
	bcopy(nconf->nc_proto, k->knc_proto, len);

	k->knc_rdev = stbuf.st_rdev;

	return (k);

nomem:
	syslog(LOG_ERR, "get_knconf: no memory");
err_out:
	if (k != NULL)
		(void) free_knconf(k);
	return (NULL);
}

/*
 * Get the information needed for an NFSv4.x referral. This
 * information includes the netbuf, netname and knconfig.
 */
struct nfs_fsl_info *
get_nfs4ref_info(char *host, int port, int nfsver)
{
	char netname[MAXNETNAMELEN + 1];
	enum clnt_stat cstat;
	struct nfs_fsl_info *fsl_retp = NULL;
	struct netconfig *netconf = NULL;
	char *nametemp, *namex = NULL;
	struct netbuf *nb = NULL;
	NCONF_HANDLE *nc = NULL;

	fsl_retp = calloc(1, sizeof (struct nfs_fsl_info));
	if (fsl_retp == NULL) {
		syslog(LOG_ERR, "get_nfs4ref_info: no memory\n");
		return (NULL);
	}

	nametemp = malloc(MAXNETNAMELEN + 1);
	if (nametemp == NULL) {
		free(fsl_retp);
		return (NULL);
	}
	host2netname(nametemp, host, NULL);
	namex = calloc(1, strlen(nametemp) + 1);
	if (namex == NULL) {
		free(nametemp);
		free(fsl_retp);
		return (NULL);
	}
	strncpy(namex, nametemp, strlen(nametemp));
	free(nametemp);
	fsl_retp->netname = namex;
	fsl_retp->netnm_len = strlen(namex) + 1;

	fsl_retp->addr = resolve_netconf(host, NFS_PROGRAM, nfsver,
	    &netconf, port, NULL, NULL, TRUE, NULL, &cstat);

	if (netconf == NULL || fsl_retp->addr == NULL)
		goto done;

	fsl_retp->knconf = get_knconf(netconf);
	if (fsl_retp->knconf == NULL)
		goto done;
	fsl_retp->knconf_len = (sizeof (struct knetconfig) +
	    (KNC_STRSIZE * 2));
	fsl_retp->netbuf_len = (sizeof (struct netbuf) +
	    fsl_retp->addr->maxlen);
	return (fsl_retp);
done:
	free_nfs4ref_info(fsl_retp);
	return (NULL);
}

void
free_nfs4ref_info(struct nfs_fsl_info *fsl_retp)
{
	if (fsl_retp == NULL)
		return;
	free_knconf(fsl_retp->knconf);
	free(fsl_retp->netname);
	if (fsl_retp->addr != NULL) {
		free(fsl_retp->addr->buf);
		free(fsl_retp->addr);
	}
	free(fsl_retp);
}

void
cleanup_tli_parms(struct t_bind *tbind, int fd)
{
	if (tbind != NULL) {
		t_free((char *)tbind, T_BIND);
		tbind = NULL;
	}
	if (fd >= 0)
		(void) t_close(fd);
	fd = -1;
}

struct netbuf *
resolve_netconf(char *host, rpcprog_t prog, rpcvers_t nfsver,
    struct netconfig **netconf, ushort_t port,
    struct t_info *tinfo, caddr_t *fhp, bool_t direct_to_server,
    char *fspath, enum clnt_stat *cstatp)
{
	NCONF_HANDLE *nc;
	struct netconfig *nconf = NULL;
	int nthtry = FIRST_TRY;
	struct netbuf *nb;
	enum clnt_stat cstat;

	nc = setnetpath();
	if (nc == NULL)
		goto done;
retry:
	while (nconf = getnetpath(nc)) {
		if (nconf->nc_flag & NC_VISIBLE) {
			if (nthtry == FIRST_TRY) {
				if ((nconf->nc_semantics ==
				    NC_TPI_COTS_ORD) ||
				    (nconf->nc_semantics ==
				    NC_TPI_COTS)) {
					if (port == 0)
						break;
					if ((strcmp(nconf->nc_protofmly,
					    NC_INET) == 0 ||
					    strcmp(nconf->nc_protofmly,
					    NC_INET6) == 0) &&
					    (strcmp(nconf->nc_proto,
					    NC_TCP) == 0))
						break;
				}
			}
			if (nthtry == SECOND_TRY) {
				if (nconf->nc_semantics ==
				    NC_TPI_CLTS) {
					if (port == 0)
						break;
					if ((strcmp(nconf->nc_protofmly,
					    NC_INET) == 0 ||
					    strcmp(nconf->nc_protofmly,
					    NC_INET6) == 0) &&
					    (strcmp(nconf->nc_proto,
					    NC_UDP) == 0))
						break;
					}
			}
		}
	} /* while */
	if (nconf == NULL) {
		if (++nthtry <= MNT_PREF_LISTLEN) {
			endnetpath(nc);
			if ((nc = setnetpath()) == NULL)
				goto done;
			goto retry;
		} else
			return (NULL);
	} else {
		nb = get_server_addr(host, NFS_PROGRAM, nfsver,
		    nconf, port, NULL, NULL, TRUE, NULL, &cstat);
		if (cstat != RPC_SUCCESS)
			goto retry;
	}
done:
	*netconf = nconf;
	*cstatp = cstat;
	if (nc)
		endnetpath(nc);
	return (nb);
}

int
setup_nb_parms(struct netconfig *nconf, struct t_bind *tbind,
    struct t_info *tinfo, char *hostname, int fd, bool_t direct_to_server,
    ushort_t port, rpcprog_t prog, rpcvers_t vers, bool_t file_handle)
{
	if (nconf == NULL) {
		return (-1);
	}
	if (direct_to_server == TRUE) {
		struct nd_hostserv hs;
		struct nd_addrlist *retaddrs;
		hs.h_host = hostname;

		if (port == 0)
			hs.h_serv = "nfs";
		else
			hs.h_serv = NULL;

		if (netdir_getbyname(nconf, &hs, &retaddrs) != ND_OK) {
			return (-1);
		}
		memcpy(tbind->addr.buf, retaddrs->n_addrs->buf,
		    retaddrs->n_addrs->len);
		tbind->addr.len = retaddrs->n_addrs->len;
		tbind->addr.maxlen = retaddrs->n_addrs->maxlen;
		netdir_free((void *)retaddrs, ND_ADDRLIST);
		if (port) {
			/* LINTED pointer alignment */
			if (strcmp(nconf->nc_protofmly, NC_INET) == 0)
				((struct sockaddr_in *)
				    tbind->addr.buf)->sin_port =
				    htons((ushort_t)port);
			else if (strcmp(nconf->nc_protofmly, NC_INET6) == 0)
				((struct sockaddr_in6 *)
				    tbind->addr.buf)->sin6_port =
				    htons((ushort_t)port);
		}

		if (file_handle) {
			if (netdir_options(nconf, ND_SET_RESERVEDPORT, fd,
			    NULL) == -1)
				return (-1);
		}
	} else if (!file_handle) {
		if (port) {
			/* LINTED pointer alignment */
			if (strcmp(nconf->nc_protofmly, NC_INET) == 0)
				((struct sockaddr_in *)
				    tbind->addr.buf)->sin_port =
				    htons((ushort_t)port);
			else if (strcmp(nconf->nc_protofmly, NC_INET6) == 0)
				((struct sockaddr_in6 *)
				    tbind->addr.buf)->sin6_port =
				    htons((ushort_t)port);
		}
	} else {
		return (-1);
	}
	return (1);
}

/*
 * Sets up TLI interface and finds the address withe netdir_getbyname().
 * returns the address returned from the call.
 * Caller frees up the memory allocated here.
 */
struct netbuf *
get_server_addr(char *hostname, rpcprog_t prog, rpcvers_t vers,
    struct netconfig *nconf, ushort_t port,
    struct t_info *tinfo, caddr_t *fhp, bool_t direct_to_server,
    char *fspath, enum clnt_stat *cstat)
{
	int fd = -1;
	struct t_bind *tbind = NULL;
	enum clnt_stat cs = RPC_SYSTEMERROR;
	struct netbuf *nb = NULL;
	int ret = -1;

	if (prog == NFS_PROGRAM && vers == NFS_V4)
		if (strncasecmp(nconf->nc_proto, NC_UDP, strlen(NC_UDP)) == 0)
			goto done;

	if ((fd = t_open(nconf->nc_device, O_RDWR, tinfo)) < 0)
		goto done;

	if ((tbind = (struct t_bind *)t_alloc(fd, T_BIND, T_ADDR)) == NULL)
		goto done;

	if (setup_nb_parms(nconf, tbind, tinfo, hostname, fd, direct_to_server,
	    port, prog, vers, 0) < 0)
		goto done;

	nb = (struct netbuf *)malloc(sizeof (struct netbuf));
	if (nb == NULL) {
		syslog(LOG_ERR, "no memory\n");
		goto done;
	}
	nb->buf = (char *)malloc(tbind->addr.maxlen);
	if (nb->buf == NULL) {
		syslog(LOG_ERR, "no memory\n");
		free(nb);
		nb = NULL;
		goto done;
	}
	(void) memcpy(nb->buf, tbind->addr.buf, tbind->addr.len);
	nb->len = tbind->addr.len;
	nb->maxlen = tbind->addr.maxlen;
	cs = RPC_SUCCESS;
done:
	*cstat = cs;
	cleanup_tli_parms(tbind, fd);
	return (nb);
}
