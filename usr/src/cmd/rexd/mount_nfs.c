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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

/*
 *  mount_nfs.c - procedural interface to the NFS mount operation
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	NFSCLIENT
#include <sys/types.h>
#include <memory.h>
#include <netconfig.h>
#include <netdb.h>
#include <netdir.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

#include <rpc/rpc.h>
#include <rpc/clnt_soc.h>
#include <rpc/pmap_prot.h>
#include <nfs/nfs.h>
#include <nfs/mount.h>
#include <rpcsvc/mount.h>
#include <errno.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <deflt.h>

static struct knetconfig *get_knconf(struct netconfig *nconf);
static int bindudp_resvport(CLIENT *client);
static void free_knconf(struct knetconfig *k);
static void freemnttab(struct mnttab *mnt);
static enum clnt_stat pingnfs(char *hostname, rpcvers_t *versp);
static void netbuf_free(struct netbuf *nb);
static struct netbuf *get_addr(char *hostname, int prog, int vers,
    struct netconfig **nconfp);

extern void set_nfsv4_ephemeral_mount_to(void);

#define	TIME_MAX	16

extern	int	Debug;
extern  time_t	time_now;

extern	FILE	*setmntent(char *, char *);
extern	void	errprintf(char *, char *, ...);

FILE		*setmntent(char *, char *);
void		endmntent(FILE *);
enum clnt_stat	pingnfs(char *, rpcvers_t *);
struct netbuf	*get_addr(char *, int, int, struct netconfig **);
struct knetconfig *get_knconf(struct netconfig *);
void		netbuf_free(struct netbuf *);
void		free_knconf(struct knetconfig *);

/*
 * mount_nfs - mount a file system using NFS
 *
 * Returns: 0 if OK, 1 if error.
 * 	The "error" string returns the error message.
 */
int
mount_nfs(char *fsname, char *dir, char *error)
{
	struct sockaddr_in sin;
	struct hostent *hp;
	struct fhstatus fhs;
	char host[256];
	char *path;
	char opts[32];
	struct stat st;
	int s = -1;
	struct timeval timeout;
	CLIENT *client;
	enum clnt_stat rpc_stat;
	int printed1 = 0;
	int printed2 = 0;
	unsigned winks = 1;	/* seconds of sleep time */
	struct mnttab mnt;
	FILE *mnted;
	int flags;
	struct nfs_args args;
	struct netconfig *nconf, *udpnconf;
	char tbuf[TIME_MAX];
	rpcvers_t vers;
	rpcvers_t nfsvers;
	char *fstype;
	struct mountres3 res3;
	nfs_fh3 fh3;
	int *auths;
	int count;

	if (Debug)
		printf("mount_nfs request: mount %s\tdir %s\n", fsname, dir);

	if (Debug && errno)
		printf("ERRNO set on mount_nfs entry: %d\n", errno);

	path = strchr(fsname, ':');
	if (path == NULL) {
		errprintf(error, "No host name in %s\n", fsname);
		return (1);
	}
	*path = '\0';
	strcpy(host, fsname);
	*path++ = ':';
	if (*path == '\0') {
		/*
		 * handle the special case of importing a root file system
		 */
		strcpy(path, "/");
	}

	if (Debug) {
		printf("mount_nfs:\tpath == %s\n", path);
		printf("\t\tdir == %s\n", dir);
		printf("\t\tgethostbyname host == %s\n", host);
	}

	/*
	 * Get server's address
	 */
	if ((hp = gethostbyname(host)) == NULL) {
		errprintf(error, "mount %s: %s not in hosts database\n",
		    fsname, host);
		return (1);
	}

	if (Debug && errno)
		printf("ERRNO set after gethostbyname: %d\n", errno);

	if (Debug) {
		fprintf(stderr, "gethostbyname:\n\th_name %s\n\t", hp->h_name);
		if (hp->h_aliases[0] && *hp->h_aliases[0])
			fprintf(stderr, "h_aliases %s\n\t", hp->h_aliases[0]);
		else
			fprintf(stderr, "h_aliases %s\n\t", "<none>");
		if (hp->h_addrtype == AF_INET)
			fprintf(stderr,
			    "h_addrtype AF_INET\n\th_adth_length %u\n\t",
			    hp->h_length);
		else
			fprintf(stderr, "h_addrtype %u\n\th_adth_length %u\n\t",
			    hp->h_addrtype, hp->h_length);
		if (hp->h_addr_list[0] && *hp->h_addr_list[0])
			fprintf(stderr, "h_addr_list <apparent list>\n");
		else
			fprintf(stderr, "h_addr_list %s\n", "<none>");
	}

	if (pingnfs(host, &nfsvers) != RPC_SUCCESS) {
		errprintf(error, "host %s not responding to ping\n", host);
		return (1);
	}

	if (Debug)
		printf("pingnfs: succeeds.\n");

	vers = nfsvers;

	if (Debug)
		printf("clnt_create for mountproc (%d)\n", errno);

	client = clnt_create_vers(host, MOUNTPROG, &vers, MOUNTVERS, vers,
	    "udp");
	if (client == NULL) {
		errprintf(error, "%s %s\n", host,
		    clnt_spcreateerror("mount server not responding"));
		return (1);
	}

	if (Debug)
		printf("call bindudp_resvport for mountproc (%d)\n", errno);

	if (bindudp_resvport(client) < 0) {
		errprintf(error, "mount %s:%s: %s\n", host, path,
		    "Couldn't bind to reserved port");
		if (Debug)
			printf("could not bind to reserved port\n");
		clnt_destroy(client);
		return (1);
	}

	if (client->cl_auth)
		auth_destroy(client->cl_auth);
	if ((client->cl_auth = authsys_create_default()) == NULL) {
		errprintf(error, "mount %s:%s: %s\n", host, path,
		    "Couldn't create authsys structure");
		if (Debug)
			printf("could not create authsys structure\n");
		clnt_destroy(client);
		return (1);
	}
/*
 * #ifdef	NOWAY
 *	if (Debug)
 *		printf("authsys_create_default called for mountproc\n");
 *	client->cl_auth = authsys_create_default();
 * #endif
 */

	/* set mount args */
	memset(&args, 0, sizeof (args));

	/* Get fhandle of remote path from server's mountd */

	timeout.tv_usec = 0;
	timeout.tv_sec = 25;

	switch (vers) {
	case MOUNTVERS:
	case MOUNTVERS_POSIX:
		rpc_stat = clnt_call(client, MOUNTPROC_MNT,
		    xdr_dirpath, (caddr_t)&path,
		    xdr_fhstatus, (caddr_t)&fhs, timeout);

		if (rpc_stat != RPC_SUCCESS) {
			/*
			 * Given the way "clnt_sperror" works, the "%s"
			 * following the "not responding" is correct.
			 */
			errprintf(error, "mount server %s not responding %s\n",
			    host, clnt_sperror(client, ""));
			clnt_destroy(client);
			return (1);
		}

		clnt_destroy(client);

		if ((errno = fhs.fhs_status) != MNT_OK) {
			if (errno == EACCES) {
				errprintf(error,
				    "rexd mount: not in EXPORT list for %s\n",
				    fsname);
			} else {
				errprintf(error, "rexd mount: error %d %s\n",
				    errno, strerror(errno));
			}
			return (1);
		}

		args.fh = (caddr_t)&fhs.fhstatus_u.fhs_fhandle;
		fstype = MNTTYPE_NFS;
		break;
	case MOUNTVERS3:
		memset((char *)&res3, '\0', sizeof (res3));
		rpc_stat = clnt_call(client, MOUNTPROC_MNT,
		    xdr_dirpath, (char *)&path,
		    xdr_mountres3, (char *)&res3, timeout);

		if (rpc_stat != RPC_SUCCESS) {
			/*
			 * Given the way "clnt_sperror" works, the "%s"
			 * following the "not responding" is correct.
			 */
			errprintf(error, "mount server %s not responding %s\n",
			    host, clnt_sperror(client, ""));
			clnt_destroy(client);
			return (1);
		}

		clnt_destroy(client);

		if ((errno = res3.fhs_status) != MNT_OK) {
			if (errno == EACCES) {
				errprintf(error,
				    "rexd mount: not in EXPORT list for %s\n",
				    fsname);
			} else {
				errprintf(error, "rexd mount: error %d %s\n",
				    errno, strerror(errno));
			}
			return (1);
		}

		auths =
		    res3.mountres3_u.mountinfo.auth_flavors.auth_flavors_val;
		count =
		    res3.mountres3_u.mountinfo.auth_flavors.auth_flavors_len;
		if (count > 0) {
			if (auths[0] == AUTH_DES)
				args.flags |= NFSMNT_SECURE;
		}

		fh3.fh3_length =
		    res3.mountres3_u.mountinfo.fhandle.fhandle3_len;
		memcpy(fh3.fh3_u.data,
		    res3.mountres3_u.mountinfo.fhandle.fhandle3_val,
		    fh3.fh3_length);
		args.fh = (caddr_t)&fh3;
		fstype = MNTTYPE_NFS3;
		break;
	default:
		errprintf(error, "rexd mount: unknown MOUNT version %ld\n",
		    vers);
		return (1);
	}


	/*
	 * remote mount the fhandle on the local path.
	 */

	args.hostname = host;
	args.flags = NFSMNT_HOSTNAME;
	args.flags |= NFSMNT_INT; /* default is "intr" */

	args.addr = get_addr(host, NFS_PROGRAM, nfsvers, &nconf);
	if (args.addr == NULL) {
		errprintf(error, "%s: no NFS service", host);
		return (1);
	}

	args.flags |=  NFSMNT_KNCONF;
	args.knconf = get_knconf(nconf);
	if (args.knconf == NULL) {
		netbuf_free(args.addr);
		return (1);
	}

	if (Debug)
		printf("start mount system call (%d)\n", errno);

	flags = MS_NOSUID | MS_DATA;

	/*
	 * And make sure that we have the ephemeral mount_to
	 * set for this zone.
	 */
	set_nfsv4_ephemeral_mount_to();

	/* Provide the mounted resource name when mounting. */
	if (mount(fsname, dir, flags, fstype, &args, sizeof (args)) < 0) {
		netbuf_free(args.addr);
		free_knconf(args.knconf);
		errprintf(error, "unable to mount %s on %s: %s\n",
		    fsname, dir, strerror(errno));
		return (1);
	}

	if (Debug)
		printf("end mount system call (%d)\n", errno);

	/*
	 * stat the new mount and get its dev
	 */
	if (stat(dir, &st) < 0) {
		errprintf(error, "couldn't stat %s\n", dir);
		return (1);
	}

	if (Debug)
		printf("stat of new mount (%d)\n", errno);

	(void) sprintf(opts, "rw,noquota,hard,intr,dev=%x", st.st_dev);

	/*
	 * update /etc/mtab
	 */

	mnt.mnt_special = fsname;
	mnt.mnt_mountp = dir;
	mnt.mnt_fstype = MNTTYPE_NFS;
	mnt.mnt_mntopts = opts;
	(void) sprintf(tbuf, "%ld", time(0L));
	mnt.mnt_time = tbuf;

	return (0);
}

#define	UNMOUNTTRIES 6
/*
 * umount_nfs - unmount a file system when finished
 */
int
umount_nfs(char *fsname, char *dir)
{
	char *p;
	char *hostname;
	int s = -1;
	struct timeval timeout;
	CLIENT *client;
	enum clnt_stat rpc_stat;
	int count = 0;

	if (Debug)
		printf("umount: fsname %s dir %s\n", fsname, dir);
	/*
	 * Give the filesystem time to become un-busy when unmounting.
	 * If child aborted and is takes a core dump, we may receive the
	 * SIGCHLD before the core dump is completed.
	 */
	while (umount(dir) == -1) {
		if (errno != EBUSY) {
			perror(dir);
			return (1);
		}

		if (++count > UNMOUNTTRIES)
			return (1);
		sleep(10);
	}

	if (Debug)
		printf("umount_nfs: unmounting %s\n", dir);

	if ((p = strchr(fsname, ':')) == NULL)
		return (1);
	*p++ = 0;
	hostname = fsname;


	if ((client = clnt_create(hostname, MOUNTPROG, MOUNTVERS, "udp"))
	    == NULL) {
		clnt_spcreateerror("Warning on umount create:");
		fprintf(stderr, "\n\r");
		return (1);
	}
	if (bindudp_resvport(client) < 0) {
		errprintf(NULL, "umount %s:%s:%s", hostname, p,
		    "Could not bind to reserved port\n");
		clnt_destroy(client);
		return (1);
	}
/*
 * #ifdef		NOWAWY
 * 	client->cl_auth = authunix_create_default();
 * #endif
 */

	timeout.tv_usec = 0;
	timeout.tv_sec = 25;

	rpc_stat = clnt_call(client, MOUNTPROC_UMNT, xdr_dirpath, (caddr_t)&p,
	    xdr_void, (char *)NULL, timeout);

	clnt_destroy(client);

	if (rpc_stat != RPC_SUCCESS) {
		clnt_perror(client, "Warning: umount:");
		fprintf(stderr, "\n\r");
		return (1);
	}

	return (0);
}

static struct mnttab *
dupmnttab(struct mnttab *mnt)
{
	struct mnttab *new;
	void freemnttab();

	new = (struct mnttab *)malloc(sizeof (*new));
	if (new == NULL)
		goto alloc_failed;
	memset((char *)new, 0, sizeof (*new));
	new->mnt_special = strdup(mnt->mnt_special);
	if (new->mnt_special == NULL)
		goto alloc_failed;
	new->mnt_mountp = strdup(mnt->mnt_mountp);
	if (new->mnt_mountp == NULL)
		goto alloc_failed;
	new->mnt_fstype = strdup(mnt->mnt_fstype);
	if (new->mnt_fstype == NULL)
		goto alloc_failed;
	if (mnt->mnt_mntopts != NULL)
		if ((new->mnt_mntopts = strdup(mnt->mnt_mntopts)) == NULL)
			goto alloc_failed;
	if (mnt->mnt_time != NULL)
		if ((new->mnt_time = strdup(mnt->mnt_time)) == NULL)
			goto alloc_failed;

	return (new);

alloc_failed:

	errprintf(NULL, "dupmnttab: memory allocation failed\n");
	freemnttab(new);
	return (NULL);
}



/*
 * Free a single mnttab structure
 */
static void
freemnttab(struct mnttab *mnt)
{
	if (mnt) {
		if (mnt->mnt_special)
			free(mnt->mnt_special);
		if (mnt->mnt_mountp)
			free(mnt->mnt_mountp);
		if (mnt->mnt_fstype)
			free(mnt->mnt_fstype);
		if (mnt->mnt_mntopts)
			free(mnt->mnt_mntopts);
		if (mnt->mnt_time)
			free(mnt->mnt_time);
		free(mnt);
	}
}


/* the following structure is used to build a list of */
/* mnttab structures from /etc/mnttab. */
struct mntlist {
	struct mnttab *mntl_mnt;
	struct mntlist *mntl_next;
};


/*
 * Free a list of mnttab structures
 */
static void
freemntlist(struct mntlist *mntl)
{
	struct mntlist *mntl_tmp;

	while (mntl) {
		freemnttab(mntl->mntl_mnt);
		mntl_tmp = mntl;
		mntl = mntl->mntl_next;
		free(mntl_tmp);
	}
}


/*
 * parsefs - given a name of the form host:/path/name/for/file
 *	connect to the give host and look for the exported file system
 *	that matches.
 * Returns: pointer to string containing the part of the pathname
 *	within the exported directory.
 *	Returns NULL on errors.
 */
char *
parsefs(char *fullname, char *error)
{
	char	*dir, *subdir;
	struct exportnode	*ex = NULL;
	int	err;
	int	bestlen = 0;
	int	len, dirlen;

	if (Debug && errno)
		printf("parsefs of %s entered with errno %d %s\n",
		    fullname, errno, strerror(errno));

	dir = strchr(fullname, ':');
	if (dir == NULL) {
		errprintf(error, "No host name in %s\n", fullname);
		return (NULL);
	}
	*dir++ = '\0';

	if (Debug)
		printf("parsefs before rpc_call: ERRNO:%d\n", errno);

	if (err = rpc_call(fullname, MOUNTPROG, MOUNTVERS, MOUNTPROC_EXPORT,
	    xdr_void, 0, xdr_exports, (char *)&ex, "udp")) {

		if (err == (int)RPC_TIMEDOUT)
			errprintf(error, "Host %s is not running mountd\n",
			    fullname);
		else
			errprintf(error, "RPC error %d with host %s (%s)\n",
			    err, fullname, clnt_sperrno(err));

		if (Debug && errno) {
			printf("parsefs: mount call to %s returned %d %s\n",
			    fullname, err, clnt_sperrno(err));
			printf("with errno %d:\t%s\n",	errno, strerror(errno));
		}
		return (NULL);
	}

	if (Debug)
		printf("parsefs after rpc_call: ERRNO:%d\n", errno);

	dirlen = strlen(dir);

	if (Debug && errno) {
		printf("parsefs: mount call to %s returned %d %s\n",
		    fullname, err, clnt_sperrno(err));
		printf("with errno %d:\t%s\n", errno, strerror(errno));
	}

	if (Debug)
		printf("parsefs: checking export list:\n");

	for (; ex; ex = ex->ex_next) {
		len = strlen(ex->ex_dir);
		if (len > bestlen && len <= dirlen &&
		    strncmp(dir, ex->ex_dir, len) == 0 &&
		    (dir[len] == '/' || dir[len] == '\0'))
			bestlen = len;

		if (Debug)
			printf("\t%d\t%s\n", bestlen, ex->ex_dir);
	}

	if (bestlen == 0) {
		errprintf(error, "%s not exported by %s\n",
		    dir, fullname);
		return (NULL);
	}

	if (dir[bestlen] == '\0')
		subdir = &dir[bestlen];
	else {
		dir[bestlen] = '\0';
		subdir = &dir[bestlen+1];
	}
	*--dir = ':';

	return (subdir);
}

/*
 * Get the network address for the service identified by "prog"
 * and "vers" on "hostname".  The netconfig address is returned
 * in the value of "nconfp".
 * If the hostname is the same as the last call, then the same
 * transport is used as last time (same netconfig entry).
 */
static struct netbuf *
get_addr(char *hostname, int prog, int vers, struct netconfig **nconfp)
{
	static char prevhost[MAXHOSTNAMELEN+1];
	static struct netconfig *nconf;
	static NCONF_HANDLE *nc = NULL;
	struct netbuf *nb = NULL;
	struct t_bind *tbind = NULL;
	struct netconfig *getnetconfig();
	struct netconfig *getnetconfigent();
	enum clnt_stat cs;
	struct timeval tv;
	int fd = -1;

	if (strcmp(hostname, prevhost) != 0) {
		if (nc)
			endnetconfig(nc);
		nc = setnetconfig();
		if (nc == NULL)
			goto done;
	retry:
		/*
		 * If the port number is specified then UDP is needed.
		 * Otherwise any connectionless transport will do.
		 */
		while (nconf = getnetconfig(nc)) {
			if ((nconf->nc_flag & NC_VISIBLE) &&
			    nconf->nc_semantics == NC_TPI_CLTS) {
				break;
			}
		}
		if (nconf == NULL)
			goto done;
		(void) strcpy(prevhost, hostname);
	}

	fd = t_open(nconf->nc_device, O_RDWR, NULL);
	if (fd < 0)
		goto done;

	tbind = (struct t_bind *)t_alloc(fd, T_BIND, T_ADDR);
	if (tbind == NULL)
		goto done;

	if (rpcb_getaddr(prog, vers, nconf, &tbind->addr, hostname) == 0) {
		t_free((char *)tbind, T_BIND);
		tbind = NULL;
		goto retry;
	}
	*nconfp = nconf;

	/*
	 * Make a copy of the netbuf to return
	 */
	nb = (struct netbuf *)malloc(sizeof (struct netbuf));
	if (nb == NULL) {
		errprintf(NULL, "no memory");
		goto done;
	}
	*nb = tbind->addr;
	nb->buf = (char *)malloc(nb->len);
	if (nb->buf == NULL) {
		errprintf(NULL, "no memory");
		free(nb);
		nb = NULL;
		goto done;
	}
	(void) memcpy(nb->buf, tbind->addr.buf, tbind->addr.len);

done:
	if (tbind)
		t_free((char *)tbind, T_BIND);
	if (fd >= 0)
		(void) t_close(fd);
	return (nb);
}

static struct knetconfig *
get_knconf(struct netconfig *nconf)
{
	struct stat stbuf;
	struct knetconfig *k;

	if (stat(nconf->nc_device, &stbuf) < 0) {
		errprintf(NULL, "get_knconf: stat %s: %m", nconf->nc_device);
		return (NULL);
	}
	k = (struct knetconfig *)malloc(sizeof (*k));
	if (k == NULL)
		goto nomem;
	k->knc_semantics = nconf->nc_semantics;
	k->knc_protofmly = strdup(nconf->nc_protofmly);
	if (k->knc_protofmly == NULL)
		goto nomem;
	k->knc_proto = strdup(nconf->nc_proto);
	if (k->knc_proto == NULL)
		goto nomem;
	k->knc_rdev = stbuf.st_rdev;

	return (k);

nomem:
	errprintf(NULL, "get_knconf: no memory");
	free_knconf(k);
	return (NULL);
}

static void
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

static void
netbuf_free(struct netbuf *nb)
{
	if (nb == NULL)
		return;
	if (nb->buf)
		free(nb->buf);
	free(nb);
}


static enum clnt_stat
pingnfs(char *hostname, rpcvers_t *versp)
{
	CLIENT *cl;
	enum clnt_stat clnt_stat;
	static char goodhost[MAXHOSTNAMELEN+1];
	static char deadhost[MAXHOSTNAMELEN+1];
	static time_t goodtime, deadtime;
	int cache_time = 60;	/* sec */

	if (goodtime > time_now && strcmp(hostname, goodhost) == 0)
		return (RPC_SUCCESS);
	if (deadtime > time_now && strcmp(hostname, deadhost) == 0)
		return (RPC_TIMEDOUT);

	if (Debug)
		printf("ping %s ", hostname);

	/* ping the NFS nullproc on the server */

	cl = clnt_create_vers(hostname, NFS_PROGRAM, versp, NFS_VERSMIN,
	    NFS_VERSMAX, "udp");
	if (cl == NULL) {
		errprintf(NULL, "pingnfs: %s%s",
		    hostname, clnt_spcreateerror(""));
		if (Debug)
			printf("clnt_create failed\n");
		clnt_stat = RPC_TIMEDOUT;
	} else {
		clnt_stat = RPC_SUCCESS;
		clnt_destroy(cl);
	}

	if (clnt_stat == RPC_SUCCESS) {
		(void) strcpy(goodhost, hostname);
		goodtime = time_now + cache_time;
	} else {
		(void) strcpy(deadhost, hostname);
		deadtime = time_now + cache_time;
	}

	if (Debug)
		(void) printf("%s\n", clnt_stat == RPC_SUCCESS ?
		    "OK" : "NO RESPONSE");

	return (clnt_stat);
}

static int bindudp_resvport(CLIENT *client)
{
	struct netconfig *udpnconf;
	int clfd;
	int rv;

	/* check for superuser as reserved ports are for superuser only */
	if (geteuid()) {
		errno = EACCES;
		return (-1);
	}

	if (clnt_control(client, CLGET_FD, (char *)&clfd) == FALSE) {
		errprintf(NULL,
		    "Could not get file dscriptor for client handle\n");
		return (-1);
	}

	if (Debug)
		printf("Clnt_control success, clfd = %d\n", clfd);

	if (t_getstate(clfd) != T_UNBND) {
		if (t_unbind(clfd) < 0) {
			return (-1);
		}
	}

	if ((udpnconf = getnetconfigent("udp")) == (struct netconfig *)NULL) {
		errprintf(NULL, "no netconfig information about \"udp\"\n");
		return (-1);
	}

	if (Debug) {
		printf("getnetconfigent success\n");
	}

	if ((rv = netdir_options(udpnconf, ND_SET_RESERVEDPORT, clfd,
	    (char *)NULL)) == -1) {
		if (Debug) {
			printf("netdir_options fails rv=%d\n", rv);
		}

		errprintf(NULL, netdir_sperror());
		return (-1);
	}

	if (Debug)
		printf("netdir_options success rv = %d\n", rv);

	freenetconfigent(udpnconf);
	return (0);
}
