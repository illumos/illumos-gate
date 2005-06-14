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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <stdlib.h>
#include <errno.h>
#include <libdevinfo.h>
#include <libdlpi.h>
#include <libdladm.h>
#include <libintl.h>
#include <sys/dld.h>
#include <net/if.h>

#define	DLADM_DB	"/etc/datalink.conf"
#define	DLADM_DB_TMP	"/etc/datalink.conf.new"
#define	DLADM_DB_LOCK	"/tmp/datalink.conf.lock"
#define	DLADM_DB_PERMS	S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH

#define	MAXLINELEN	1024
#define	LISTSZ		1024
#define	MAXPATHLEN	1024

#define	BLANK_LINE(s)	((s[0] == '\0') || (s[0] == '#') || (s[0] == '\n'))

typedef	struct i_dladm_walk {
	int		fd;
	boolean_t	found;
	const char	*name;
} i_dladm_walk_t;

/*
 * Open and lock the aggregation configuration file lock. The lock is
 * acquired as a reader (F_RDLCK) or writer (F_WRLCK).
 */
static int
i_dladm_lock_db(short type)
{
	int lock_fd;
	struct flock lock;

	if ((lock_fd = open(DLADM_DB_LOCK, O_RDWR | O_CREAT | O_TRUNC,
	    DLADM_DB_PERMS)) < 0)
		return (-1);

	lock.l_type = type;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(lock_fd, F_SETLKW, &lock) < 0) {
		(void) close(lock_fd);
		(void) unlink(DLADM_DB_LOCK);
		return (-1);
	}
	return (lock_fd);
}

/*
 * Unlock and close the specified file.
 */
static void
i_dladm_unlock_db(int fd)
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
	(void) unlink(DLADM_DB_LOCK);
}

/*
 * Parse a line of the configuration file, returns -1 if an error
 * occured.
 */
static int
i_dladm_db_decode(char *buf, char *name, dladm_attr_t *dap)
{
	char		*attr[DLADM_NATTR + 1];
	char		*endp = NULL;
	char		*lasts = NULL;
	uint_t		i;

	attr[0] = strtok_r(buf, " \t\n", &lasts);
	for (i = 1; i < DLADM_NATTR + 1; i++) {
		if ((attr[i] = strtok_r(NULL, " \t\n", &lasts)) == NULL)
			return (-1);
	}

	if (i != DLADM_NATTR + 1) {
		errno = EINVAL;
		return (-1);
	}

	(void) strlcpy(name, attr[0], IFNAMSIZ);
	(void) strlcpy(dap->da_dev, attr[1], MAXNAMELEN);

	errno = 0;
	dap->da_port = (int)strtol(attr[2], &endp, 10);
	if (errno != 0 || *endp != '\0') {
		return (-1);
	}

	errno = 0;
	dap->da_vid = (int)strtol(attr[3], &endp, 10);
	if (errno != 0 || *endp != '\0') {
		return (-1);
	}

	return (0);
}

/*
 * Add a datalink of the specified name and attributes to
 * the configuration repository.
 */
static int
i_dladm_db_add(const char *name, dladm_attr_t *dap, const char *root,
    dladm_diag_t *diag)
{
	FILE		*fp;
	int		lock_fd, retval = -1;
	char		line[MAXLINELEN];
	char		dl_name[IFNAMSIZ];
	dladm_attr_t	da;
	char		*db_file;
	char		db_file_buf[MAXPATHLEN];

	if (root == NULL) {
		db_file = DLADM_DB;
	} else {
		(void) snprintf(db_file_buf, MAXPATHLEN, "%s%s", root,
		    DLADM_DB);
		db_file = db_file_buf;
	}

	if ((lock_fd = i_dladm_lock_db(F_WRLCK)) < 0)
		return (-1);

	if ((fp = fopen(db_file, "r+")) == NULL &&
	    (fp = fopen(db_file, "w")) == NULL) {
		*diag = DLADM_DIAG_REPOSITORY_OPENFAIL;
		i_dladm_unlock_db(lock_fd);
		return (-1);
	}

	while (fgets(line, MAXLINELEN, fp) != NULL) {
		/* skip comments and blank lines */
		if (BLANK_LINE(line))
			continue;

		/* skip corrupted lines */
		if (i_dladm_db_decode(line, dl_name, &da) < 0)
			continue;

		if (strcmp(dl_name, name) == 0) {
			errno = EEXIST;
			goto failed;
		}

		if (strcmp(da.da_dev, dap->da_dev) == 0 &&
		    da.da_port == dap->da_port &&
		    da.da_vid == dap->da_vid) {
			errno = EEXIST;
			goto failed;
		}
	}

	(void) snprintf(line, MAXPATHLEN, "%s\t%s\t%u\t%u\n",
	    name, dap->da_dev, dap->da_port, dap->da_vid);

	if (fputs(line, fp) == EOF) {
		*diag = DLADM_DIAG_REPOSITORY_WRITEFAIL;
		goto failed;
	}

	if (fflush(fp) == EOF)
		goto failed;

	retval = 0;

failed:
	(void) fclose(fp);
	i_dladm_unlock_db(lock_fd);
	return (retval);
}

/*
 * Remove the datalink of the specified name from the configuration repository.
 */
static int
i_dladm_db_remove(const char *name, const char *root)
{
	FILE		*fp;
	FILE		*nfp;
	int		nfd, lock_fd;
	char		line[MAXLINELEN];
	char		copy[MAXLINELEN];
	char		dl_name[IFNAMSIZ];
	dladm_attr_t	da;
	boolean_t	found = B_FALSE;
	char		*db_file, *tmp_db_file;
	char		db_file_buf[MAXPATHLEN];
	char		tmp_db_file_buf[MAXPATHLEN];

	if (root == NULL) {
		db_file = DLADM_DB;
		tmp_db_file = DLADM_DB_TMP;
	} else {
		(void) snprintf(db_file_buf, MAXPATHLEN, "%s%s", root,
		    DLADM_DB);
		(void) snprintf(tmp_db_file_buf, MAXPATHLEN, "%s%s", root,
		    DLADM_DB_TMP);
		db_file = db_file_buf;
		tmp_db_file = tmp_db_file_buf;
	}

	if ((lock_fd = i_dladm_lock_db(F_WRLCK)) < 0)
		return (-1);

	if ((fp = fopen(db_file, "r")) == NULL) {
		i_dladm_unlock_db(lock_fd);
		return (-1);
	}

	if ((nfd = open(tmp_db_file, O_WRONLY | O_CREAT | O_TRUNC,
	    DLADM_DB_PERMS)) < 0) {
		(void) fclose(fp);
		i_dladm_unlock_db(lock_fd);
		return (-1);
	}

	if ((nfp = fdopen(nfd, "w")) == NULL) {
		(void) close(nfd);
		(void) fclose(fp);
		(void) unlink(tmp_db_file);
		i_dladm_unlock_db(lock_fd);
		return (-1);
	}

	while (fgets(line, MAXLINELEN, fp) != NULL) {
		(void) strlcpy(copy, line, MAXLINELEN);

		/* skip comments */
		if (!BLANK_LINE(line)) {
			if (i_dladm_db_decode(line, dl_name, &da) < 0) {
				continue;
			}

			if (strcmp(dl_name, name) == 0) {
				found = B_TRUE;
				continue;
			}
		}

		if (fputs(copy, nfp) == EOF)
			goto failed;
	}

	if (!found) {
		errno = ENOENT;
		goto failed;
	}

	if (fflush(nfp) == EOF)
		goto failed;

	(void) fclose(fp);
	(void) fclose(nfp);
	if (rename(tmp_db_file, db_file) < 0) {
		(void) unlink(tmp_db_file);
		i_dladm_unlock_db(lock_fd);
		return (-1);
	}

	i_dladm_unlock_db(lock_fd);
	return (0);

failed:
	(void) fclose(fp);
	(void) fclose(nfp);
	(void) unlink(tmp_db_file);
	i_dladm_unlock_db(lock_fd);

	return (-1);
}

/*
 * For each datalink in the configuration repository, invoke the specified
 * callback. If the datalink name is specified, the callback is invoked
 * only for datalink of the matching name.
 */
static void
i_dladm_db_walk(void (*fn)(void *, const char *, dladm_attr_t *),
    const char *name, void *arg)
{
	FILE		*fp;
	int		lock_fd;
	char		line[MAXLINELEN];
	char		dl_name[IFNAMSIZ];
	dladm_attr_t	da;

	lock_fd = i_dladm_lock_db(F_RDLCK);

	if ((fp = fopen(DLADM_DB, "r")) == NULL) {
		i_dladm_unlock_db(lock_fd);
		return;
	}

	while (fgets(line, MAXLINELEN, fp) != NULL) {
		/* skip comments */
		if (BLANK_LINE(line))
			continue;

		if (i_dladm_db_decode(line, dl_name, &da) < 0)
			continue;

		if (name != NULL && strcmp(name, dl_name) != 0)
			continue;

		fn(arg, dl_name, &da);
	}

	(void) fclose(fp);
	i_dladm_unlock_db(lock_fd);
}

/*
 * For each datalink in the configuration repository, invoke the
 * specified callback.
 */
void
dladm_db_walk(void (*fn)(void *, const char *, dladm_attr_t *),
    void *arg)
{
	i_dladm_db_walk(fn, NULL, arg);
}

/*
 * Issue an ioctl to the specified file descriptor attached to the
 * DLD control driver interface.
 */
static int
i_dladm_ioctl(int fd, char *ic_dp, int ic_cmd, int ic_len)
{
	struct strioctl	iocb;

	iocb.ic_cmd = ic_cmd;
	iocb.ic_timout = 0;
	iocb.ic_len = ic_len;
	iocb.ic_dp = ic_dp;

	return (ioctl(fd, I_STR, &iocb));
}

/*
 * Issue a DLDIOCCREATE ioctl command.
 */
static int
i_dladm_create(int fd, const char *name, dladm_attr_t *dap)
{
	dld_ioc_create_t	dic;

	if (strlen(name) >= IFNAMSIZ) {
		errno = EINVAL;
		return (-1);
	}

	(void) strlcpy(dic.dic_name, name, IFNAMSIZ);
	(void) strlcpy(dic.dic_dev, dap->da_dev, MAXNAMELEN);
	dic.dic_port = dap->da_port;
	dic.dic_vid = dap->da_vid;

	return (i_dladm_ioctl(fd, (char *)&dic, DLDIOCCREATE, sizeof (dic)));
}

/*
 * Datalink bringup callback. Brings up the specified datalink.
 */
static void
i_dladm_up(void *arg, const char *name, dladm_attr_t *dap)
{
	i_dladm_walk_t	*wp = arg;

	wp->found = B_TRUE;
	(void) i_dladm_create(wp->fd, name, dap);
}

/*
 * Bring down the datalink of the specified name.
 */
static int
i_dladm_destroy(int fd, const char *name)
{
	dld_ioc_destroy_t	did;

	if (strlen(name) >= IFNAMSIZ) {
		errno = EINVAL;
		return (-1);
	}

	(void) strlcpy(did.did_name, name, IFNAMSIZ);

	return (i_dladm_ioctl(fd, (char *)&did, DLDIOCDESTROY, sizeof (did)));
}

/*
 * Bring down one or all currently active datalinks.
 */
/*ARGSUSED*/
static void
i_dladm_down(void *arg, const char *name)
{
	i_dladm_walk_t	*wp = (i_dladm_walk_t *)arg;

	wp->found = B_TRUE;

	if (wp->name != NULL && strcmp(name, wp->name) != 0)
		return;

	(void) i_dladm_destroy(wp->fd, name);
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

	if (i_dladm_ioctl(fd, (char *)&dia, DLDIOCATTR, sizeof (dia)) < 0)
		return (-1);

	(void) strlcpy(dap->da_dev, dia.dia_dev, MAXNAMELEN);
	dap->da_port = dia.dia_port;
	dap->da_vid = dia.dia_vid;

	return (0);
}

/*
 * Callback function used to count the number of DDI_NT_NET.
 */
/* ARGSUSED */
static int
i_dladm_nt_net_count(di_node_t node, di_minor_t minor, void *arg)
{
	uint_t		*countp = arg;

	(*countp)++;
	return (DI_WALK_CONTINUE);
}

/*
 * Adds a datalink to the array corresponding to arg.
 */
static void
i_dladm_nt_net_add(void *arg, char *name)
{
	char		**array = arg;
	char		*elem;

	for (;;) {
		elem = *(array++);
		if (elem[0] == '\0')
			break;
		if (strcmp(elem, name) == 0)
			return;
	}

	(void) strlcpy(elem, name, MAXNAMELEN);
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
	uint_t		count;
	char		**array;
	char		*elem;
	int		i;

	if ((root = di_init("/", DINFOCACHE)) == DI_NODE_NIL) {
		errno = EFAULT;
		return (-1);
	}

	count = 0;
	(void) di_walk_minor(root, DDI_NT_NET, DI_CHECK_ALIAS, (void *)&count,
	    i_dladm_nt_net_count);

	if (count == 0)
		return (0);

	if ((array = malloc(count * sizeof (char *))) == NULL)
		goto done;

	for (i = 0; i < count; i++) {
		if ((array[i] = malloc(IFNAMSIZ)) != NULL) {
			(void) memset(array[i], '\0', IFNAMSIZ);
			continue;
		}

		while (--i >= 0)
			free(array[i]);
		goto done;
	}

	(void) di_walk_minor(root, DDI_NT_NET, DI_CHECK_ALIAS, (void *)array,
	    i_dladm_nt_net_walk);
	di_fini(root);

	for (i = 0; i < count; i++) {
		elem = array[i];
		if (elem[0] != '\0')
			fn(arg, (const char *)elem);
		free(elem);
	}

done:
	free(array);
	return (0);
}

/*
 * Create the link of specified name and attributes. Adds it to the
 * configuration repository if DLADM_LINK_TEMP is not set. Errors
 * will be ignored if DLADM_LINK_FORCED is set.
 */
int
dladm_link(const char *name, dladm_attr_t *dap, int flags,
    const char *root, dladm_diag_t *diag)
{
	int		fd;
	boolean_t	tempop = (flags & DLADM_LINK_TEMP);
	boolean_t	forced = (flags & DLADM_LINK_FORCED);

	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0) {
		*diag = DLADM_DIAG_DEVICE_OPENFAIL;
		return (-1);
	}

	if (!tempop) {
		if (i_dladm_db_add(name, dap, root, diag) < 0 && !forced)
			goto failed;
	}

	if (i_dladm_create(fd, name, dap) < 0 && !forced) {
		if (errno == EINVAL) {
			*diag = DLADM_DIAG_INVALID_INTFNAME;
		}
		if (!tempop)
			(void) i_dladm_db_remove(name, root);
		goto failed;
	}

	(void) close(fd);
	return (0);

failed:
	(void) close(fd);
	return (-1);
}

/*
 * Instantiate the datalink of specified name. Brings up all datalinks
 * if name is NULL.
 */
int
dladm_up(const char *name, dladm_diag_t *diag)
{
	i_dladm_walk_t	walk;

	if ((walk.fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0) {
		*diag =
		    DLADM_DIAG_DEVICE_OPENFAIL;
		return (-1);
	}

	walk.found = B_FALSE;
	i_dladm_db_walk(i_dladm_up, name, (void *)&walk);
	if (name != NULL && !walk.found) {
		(void) close(walk.fd);
		errno = ENOENT;
		return (-1);
	}

	(void) close(walk.fd);
	return (0);
}

/*
 * Deletes the link of specified name.
 */
int
dladm_unlink(const char *name, boolean_t tempop, const char *root,
    dladm_diag_t *diag)
{
	int		fd;

	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0) {
		*diag = DLADM_DIAG_DEVICE_OPENFAIL;
		return (-1);
	}

	if (i_dladm_destroy(fd, name) < 0) {
		if (errno == EINVAL)
			*diag = DLADM_DIAG_INVALID_LINKNAME;
		goto failed;
	}

	if (!tempop)
		(void) i_dladm_db_remove(name, root);
	(void) close(fd);
	return (0);

failed:
	(void) close(fd);
	return (-1);
}

/*
 * Brings down the datalink of specified name. Brings down all datalinks
 * if name == NULL.
 */
int
dladm_down(const char *name, dladm_diag_t *diag)
{
	i_dladm_walk_t	walk;

	if ((walk.fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0) {
		*diag = DLADM_DIAG_DEVICE_OPENFAIL;
		return (-1);
	}
	walk.found = B_FALSE;
	walk.name = name;

	if (dladm_walk(i_dladm_down, (void *)&walk) < 0) {
		(void) close(walk.fd);
		return (-1);
	}

	if (name != NULL && !walk.found) {
		(void) close(walk.fd);
		errno = ENOENT;
		return (-1);
	}

	(void) close(walk.fd);
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

/*
 * Causes the nodes corresponding to created or deleted datalinks to
 * be created or deleted.
 */
int
dladm_sync(void)
{
	di_devlink_handle_t	hdl;

	if ((hdl = di_devlink_init(DLD_DRIVER_NAME, DI_MAKE_LINK)) == NULL)
		return (-1);

	if (di_devlink_fini(&hdl) < 0)
		return (-1);

	return (0);
}

const char *
dladm_diag(dladm_diag_t diag) {
	switch (diag) {
	case DLADM_DIAG_INVALID_LINKNAME:
		return (gettext("invalid datalink name"));
	case DLADM_DIAG_INVALID_INTFNAME:
		return (gettext("invalid interface name"));
	case DLADM_DIAG_CORRUPT_REPOSITORY:
		return (gettext("configuration repository corrupt"));
	case DLADM_DIAG_REPOSITORY_OPENFAIL:
		return (gettext("configuration repository open failed"));
	case DLADM_DIAG_REPOSITORY_WRITEFAIL:
		return (gettext("write to configuration repository failed"));
	case DLADM_DIAG_REPOSITORY_CLOSEFAIL:
		return (gettext("configuration repository close failed"));
	case DLADM_DIAG_DEVICE_OPENFAIL:
		return (gettext("dld device open fail"));
	default:
		return (gettext("unknown diagnostic"));
	}
}
