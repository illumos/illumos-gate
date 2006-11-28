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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <stropts.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <dirent.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/dld.h>
#include <libdlpi.h>
#include <libdevinfo.h>
#include <libdladm_impl.h>
#include <libintl.h>

typedef struct dladm_dev {
	char			dd_name[IFNAMSIZ];
	struct dladm_dev	*dd_next;
} dladm_dev_t;

typedef struct dladm_walk {
	dladm_dev_t		*dw_dev_list;
} dladm_walk_t;

static char		dladm_rootdir[MAXPATHLEN] = "/";

/*
 * Issue an ioctl to the specified file descriptor attached to the
 * DLD control driver interface.
 */
int
i_dladm_ioctl(int fd, int ic_cmd, void *ic_dp, int ic_len)
{
	struct strioctl	iocb;

	iocb.ic_cmd = ic_cmd;
	iocb.ic_timout = 0;
	iocb.ic_len = ic_len;
	iocb.ic_dp = (char *)ic_dp;

	return (ioctl(fd, I_STR, &iocb));
}

/*
 * Return the attributes of the specified datalink from the DLD driver.
 */
static int
i_dladm_info(int fd, const char *name, dladm_attr_t *dap)
{
	dld_ioc_attr_t	dia;

	if (strlen(name) >= IFNAMSIZ) {
		errno = EINVAL;
		return (-1);
	}

	(void) strlcpy(dia.dia_name, name, IFNAMSIZ);

	if (i_dladm_ioctl(fd, DLDIOCATTR, &dia, sizeof (dia)) < 0)
		return (-1);

	(void) strlcpy(dap->da_dev, dia.dia_dev, MAXNAMELEN);
	dap->da_max_sdu = dia.dia_max_sdu;
	dap->da_vid = dia.dia_vid;

	return (0);
}

/*
 * Adds a datalink to the array corresponding to arg.
 */
static void
i_dladm_nt_net_add(void *arg, char *name)
{
	dladm_walk_t	*dwp = arg;
	dladm_dev_t	*ddp = dwp->dw_dev_list;
	dladm_dev_t	**lastp = &dwp->dw_dev_list;

	while (ddp) {
		/*
		 * Skip duplicates.
		 */
		if (strcmp(ddp->dd_name, name) == 0)
			return;

		lastp = &ddp->dd_next;
		ddp = ddp->dd_next;
	}

	if ((ddp = malloc(sizeof (*ddp))) == NULL)
		return;

	(void) strlcpy(ddp->dd_name, name, IFNAMSIZ);
	ddp->dd_next = NULL;
	*lastp = ddp;
}

/*
 * Walker callback invoked for each DDI_NT_NET node.
 */
static int
i_dladm_nt_net_walk(di_node_t node, di_minor_t minor, void *arg)
{
	dl_info_ack_t	dlia;
	char		name[IFNAMSIZ];
	int		fd;
	char		*provider;
	uint_t		ppa;

	provider = di_minor_name(minor);

	if ((fd = dlpi_open(provider)) < 0)
		return (DI_WALK_CONTINUE);

	if (dlpi_info(fd, -1, &dlia, NULL, NULL, NULL, NULL, NULL, NULL) < 0) {
		(void) dlpi_close(fd);
		return (DI_WALK_CONTINUE);
	}

	if (dlia.dl_provider_style == DL_STYLE1) {
		i_dladm_nt_net_add(arg, provider);
		(void) dlpi_close(fd);
		return (DI_WALK_CONTINUE);
	}

	ppa = di_instance(node);

	if (dlpi_attach(fd, -1, ppa) < 0) {
		(void) dlpi_close(fd);
		return (DI_WALK_CONTINUE);
	}
	(void) snprintf(name, IFNAMSIZ - 1, "%s%d", provider, ppa);
	i_dladm_nt_net_add(arg, name);
	(void) dlpi_close(fd);
	return (DI_WALK_CONTINUE);
}

/*
 * Invoke the specified callback function for each active DDI_NT_NET
 * node.
 */
int
dladm_walk(void (*fn)(void *, const char *), void *arg)
{
	di_node_t	root;
	dladm_walk_t	dw;
	dladm_dev_t	*ddp, *last_ddp;

	if ((root = di_init("/", DINFOCACHE)) == DI_NODE_NIL) {
		errno = EFAULT;
		return (-1);
	}
	dw.dw_dev_list = NULL;

	(void) di_walk_minor(root, DDI_NT_NET, DI_CHECK_ALIAS, &dw,
	    i_dladm_nt_net_walk);

	di_fini(root);

	ddp = dw.dw_dev_list;
	while (ddp) {
		fn(arg, ddp->dd_name);
		(void) dladm_walk_vlan(fn, arg, ddp->dd_name);
		last_ddp = ddp;
		ddp = ddp->dd_next;
		free(last_ddp);
	}

	return (0);
}

/*
 * Invoke the specified callback function for each vlan managed by dld
 */
int
dladm_walk_vlan(void (*fn)(void *, const char *), void *arg, const char *name)
{
	int		fd, bufsize, i;
	int		nvlan = 4094;
	dld_ioc_vlan_t	*iocp = NULL;
	dld_vlan_info_t	*dvip;

	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0)
		return (-1);

	bufsize = sizeof (dld_ioc_vlan_t) + nvlan * sizeof (dld_vlan_info_t);

	if ((iocp = (dld_ioc_vlan_t *)calloc(1, bufsize)) == NULL)
		return (-1);

	(void) strlcpy((char *)iocp->div_name, name, IFNAMSIZ);
	if (i_dladm_ioctl(fd, DLDIOCVLAN, iocp, bufsize) == 0) {
		dvip = (dld_vlan_info_t *)(iocp + 1);
		for (i = 0; i < iocp->div_count; i++)
			(*fn)(arg, dvip[i].dvi_name);
	}
	/*
	 * Note: Callers of dladm_walk_vlan() ignore the return
	 * value of this routine. So ignoring ioctl failure case
	 * and just returning 0.
	 */
	free(iocp);
	(void) close(fd);
	return (0);
}


/*
 * Returns the current attributes of the specified datalink.
 */
int
dladm_info(const char *name, dladm_attr_t *dap)
{
	int		fd;

	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0)
		return (-1);

	if (i_dladm_info(fd, name, dap) < 0)
		goto failed;

	(void) close(fd);
	return (0);

failed:
	(void) close(fd);
	return (-1);
}

const char *
dladm_status2str(dladm_status_t status, char *buf)
{
	const char	*s;

	switch (status) {
	case DLADM_STATUS_OK:
		s = "ok";
		break;
	case DLADM_STATUS_BADARG:
		s = "invalid argument";
		break;
	case DLADM_STATUS_FAILED:
		s = "operation failed";
		break;
	case DLADM_STATUS_TOOSMALL:
		s = "buffer size too small";
		break;
	case DLADM_STATUS_NOTSUP:
		s = "operation not supported";
		break;
	case DLADM_STATUS_NOTFOUND:
		s = "object not found";
		break;
	case DLADM_STATUS_BADVAL:
		s = "invalid value";
		break;
	case DLADM_STATUS_NOMEM:
		s = "insufficient memory";
		break;
	case DLADM_STATUS_EXIST:
		s = "object already exists";
		break;
	case DLADM_STATUS_LINKINVAL:
		s = "invalid link";
		break;
	case DLADM_STATUS_PROPRDONLY:
		s = "read-only property";
		break;
	case DLADM_STATUS_BADVALCNT:
		s = "invalid number of values";
		break;
	case DLADM_STATUS_DBNOTFOUND:
		s = "database not found";
		break;
	case DLADM_STATUS_DENIED:
		s = "permission denied";
		break;
	case DLADM_STATUS_IOERR:
		s = "I/O error";
		break;
	default:
		s = "<unknown error>";
		break;
	}
	(void) snprintf(buf, DLADM_STRSIZE, "%s", dgettext(TEXT_DOMAIN, s));
	return (buf);
}

/*
 * Convert a unix errno to a dladm_status_t.
 * We only convert errnos that are likely to be encountered. All others
 * are mapped to DLADM_STATUS_FAILED.
 */
dladm_status_t
dladm_errno2status(int err)
{
	switch (err) {
	case EINVAL:
		return (DLADM_STATUS_BADARG);
	case EEXIST:
		return (DLADM_STATUS_EXIST);
	case ENOENT:
		return (DLADM_STATUS_NOTFOUND);
	case ENOSPC:
		return (DLADM_STATUS_TOOSMALL);
	case ENOMEM:
		return (DLADM_STATUS_NOMEM);
	case ENOTSUP:
		return (DLADM_STATUS_NOTSUP);
	case EACCES:
		return (DLADM_STATUS_DENIED);
	case EIO:
		return (DLADM_STATUS_IOERR);
	default:
		return (DLADM_STATUS_FAILED);
	}
}

/*
 * These are the uid and gid of the user 'dladm'.
 * The directory /etc/dladm and all files under it are owned by this user.
 */
#define	DLADM_DB_OWNER		15
#define	DLADM_DB_GROUP		3
#define	LOCK_DB_PERMS		S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH

static int
i_dladm_lock_db(const char *lock_file, short type)
{
	int	lock_fd;
	struct  flock lock;

	if ((lock_fd = open(lock_file, O_RDWR | O_CREAT | O_TRUNC,
	    LOCK_DB_PERMS)) < 0)
		return (-1);

	lock.l_type = type;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(lock_fd, F_SETLKW, &lock) < 0) {
		int err = errno;

		(void) close(lock_fd);
		(void) unlink(lock_file);
		errno = err;
		return (-1);
	}
	return (lock_fd);
}

static void
i_dladm_unlock_db(const char *lock_file, int fd)
{
	struct flock lock;

	if (fd < 0)
		return;

	lock.l_type = F_UNLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	(void) fcntl(fd, F_SETLKW, &lock);
	(void) close(fd);
	(void) unlink(lock_file);
}

dladm_status_t
i_dladm_rw_db(const char *db_file, mode_t db_perms,
    dladm_status_t (*process_db)(void *, FILE *, FILE *),
    void *arg, boolean_t writeop)
{
	dladm_status_t	status = DLADM_STATUS_OK;
	FILE		*fp, *nfp = NULL;
	char		lock[MAXPATHLEN];
	char		file[MAXPATHLEN];
	char		newfile[MAXPATHLEN];
	char		*db_basename;
	int		nfd, lock_fd;

	/*
	 * If we are called from a boot script such as net-physical,
	 * it's quite likely that the root fs is still not writable.
	 * For this case, it's ok for the lock creation to fail since
	 * no one else could be accessing our configuration file.
	 */
	db_basename = strrchr(db_file, '/');
	if (db_basename == NULL || db_basename[1] == '\0')
		return (dladm_errno2status(EINVAL));
	db_basename++;
	(void) snprintf(lock, MAXPATHLEN, "/tmp/%s.lock", db_basename);
	if ((lock_fd = i_dladm_lock_db
	    (lock, (writeop ? F_WRLCK : F_RDLCK))) < 0 && errno != EROFS)
		return (dladm_errno2status(errno));

	(void) snprintf(file, MAXPATHLEN, "%s/%s", dladm_rootdir, db_file);
	if ((fp = fopen(file, (writeop ? "r+" : "r"))) == NULL) {
		int	err = errno;

		i_dladm_unlock_db(lock, lock_fd);
		if (err == ENOENT)
			return (DLADM_STATUS_DBNOTFOUND);

		return (dladm_errno2status(err));
	}

	if (writeop) {
		(void) snprintf(newfile, MAXPATHLEN, "%s/%s.new",
		    dladm_rootdir, db_file);
		if ((nfd = open(newfile, O_WRONLY | O_CREAT | O_TRUNC,
		    db_perms)) < 0) {
			(void) fclose(fp);
			i_dladm_unlock_db(lock, lock_fd);
			return (dladm_errno2status(errno));
		}

		if ((nfp = fdopen(nfd, "w")) == NULL) {
			(void) close(nfd);
			(void) fclose(fp);
			(void) unlink(newfile);
			i_dladm_unlock_db(lock, lock_fd);
			return (dladm_errno2status(errno));
		}
	}
	status = (*process_db)(arg, fp, nfp);
	if (!writeop || status != DLADM_STATUS_OK)
		goto done;

	/*
	 * Configuration files need to be owned by the 'dladm' user.
	 * If we are invoked by root, the file ownership needs to be fixed.
	 */
	if (getuid() == 0 || geteuid() == 0) {
		if (fchown(nfd, DLADM_DB_OWNER, DLADM_DB_GROUP) < 0) {
			status = dladm_errno2status(errno);
			goto done;
		}
	}

	if (fflush(nfp) == EOF) {
		status = dladm_errno2status(errno);
		goto done;
	}
	(void) fclose(fp);
	(void) fclose(nfp);

	if (rename(newfile, file) < 0) {
		(void) unlink(newfile);
		i_dladm_unlock_db(lock, lock_fd);
		return (dladm_errno2status(errno));
	}

	i_dladm_unlock_db(lock, lock_fd);
	return (DLADM_STATUS_OK);

done:
	if (nfp != NULL) {
		(void) fclose(nfp);
		if (status != DLADM_STATUS_OK)
			(void) unlink(newfile);
	}
	(void) fclose(fp);
	i_dladm_unlock_db(lock, lock_fd);
	return (status);
}

dladm_status_t
dladm_set_rootdir(const char *rootdir)
{
	DIR	*dp;

	if (rootdir == NULL || *rootdir != '/' ||
	    (dp = opendir(rootdir)) == NULL)
		return (DLADM_STATUS_BADARG);

	(void) strncpy(dladm_rootdir, rootdir, MAXPATHLEN);
	(void) closedir(dp);
	return (DLADM_STATUS_OK);
}
