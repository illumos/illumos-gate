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

/*
 * the file is volmgt's interface to possible PCMCIA slots under Solaris
 *
 * this version talks to pcmciad directly through a named pipe (rather than
 * pcmciad using SIGHUP to talk to vold)
 *
 * the name of the named pipe to use is gotten from the config file
 * "use pcmpipe ..." line
 */


#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/mkdev.h>
#include	<sys/dkio.h>
#include	<sys/fdio.h>
#include	<sys/cdio.h>
#include	<sys/vtoc.h>

#include	<errno.h>
#include	<string.h>
#include	<dirent.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<ctype.h>
#include	<thread.h>
#include	<synch.h>
#include	<sys/signal.h>

#include	"vold.h"

extern void		vol_event(struct vioc_event *, struct devs *);

/*
 * thread stack size
 */
#define	PCMEM_STKSIZE		(32 * 1024)

/*
 * size of buf read from named pipe
 */
#define	PCMEM_PBUF_SZ		100

/*
 * this is the seperator between params sent down the pipe
 */
#define	PCMEM_PIPE_SEP		','

/*
 * path of the named pipe that PCMCIA uses
 */
#define	PCMEM_PIPE_PATH		"/var/run/pcmcia/pcram"

/*
 * symname used from proutine that reads from pipe as symname for pcmem
 * cards
 *
 * must match symname on "use pcmem ..." line in config file
 */
#define	PCMEM_SYMNAME		"pcmem%d"

/*
 * path to devices directories
 */
#define	PCMEM_RDSK_PATH		"/dev/rdsk"
#define	PCMEM_DSK_PATH		"/dev/dsk"

#define	PCMEM_DEVICES_DIR	"/devices/pcmcia"

#define	PCMEM_NAMEPROTO_DEFD	"%sd0s%d"
#define	PCMEM_BASEPART		2

#define	PCMEM_NAMEPROTO		"%ss%d"

#define	PCMEM_MODE_BUF_LEN	10

#define	PCMEM_PIPE_ACTION	"insert"

#define	PCMEM_OVERLAP_TIMEOUT_SECS	15


static bool_t	pcmem_use(char *, char *);
static bool_t	pcmem_error(struct ve_error *);
static int	pcmem_getfd(dev_t);
static void	pcmem_devmap(vol_t *, int, int);
static void	pcmem_close(char *, dev_t);
static bool_t	pcmem_testpath(char *);
static int	pcmem_check(struct devs *);
static void	pcmem_eject(struct devs *);
static bool_t	pcmem_remount(vol_t *);

extern bool_t	support_nomedia;

static struct devsw pcmemdevsw = {
	pcmem_use,		/* d_use -- use a device */
	pcmem_error,		/* d_error -- handle an error */
	pcmem_getfd,		/* d_getfd -- return open fd for drive */
	NULL,			/* d_poll -- poll device */
	pcmem_devmap,		/* d_devmap --  map device */
	pcmem_close,		/* d_close -- end use of device */
	pcmem_eject,		/* d_eject -- eject media */
	NULL,			/* d_find */
	pcmem_check,		/* d_check -- volcheck device */
	PCMEM_MTYPE,		/* d_mtype -- media type */
	DRIVE_CLASS,		/* d_dtype -- drive type */
	(ulong_t)0,		/* d_flags -- default flags */
	(uid_t)0,		/* d_uid -- default user id */
	(gid_t)0,		/* d_gid -- default group id */
	(mode_t)0,		/* d_mode -- default file mode */
	pcmem_testpath,		/* d_test -- test for a named pipe */
	pcmem_remount		/* d_remount -- find the new default fd */
};


struct mem_priv {
	char		*mem_blockpath;	/* block device for pcmem */
	char		*mem_rawpath;	/* character device for pcmem */
	int		mem_tid;	/* thread id of watcher thread */
	int		mem_fd;		/* real file descriptor */
	mutex_t		mem_mutex;	/* to protect most of this struct */
	mutex_t		mem_inserted_mutex; /* to protect mem_inserted */
	bool_t		mem_inserted;	/* media is in the drive */
};


/*
 * the struct passed to pcmp_thread
 */
struct pcmp_priv {
	struct mem_priv	*pcmp_mem;
	char		*pcmp_symname;
};



/*
 * this routine is called by dso_load() right after this library is loaded,
 * i.e. a line of the form "use pcmem ..." has been seen
 *
 * put any library initialization here
 */
bool_t
dev_init(void)
{
	static void	pipe_thread(void);

	/* register our routines */
	dev_new(&pcmemdevsw);

	/* ensure a thread exists to watch the named pipe */
	pipe_thread();

	return (TRUE);
}

static int started = 0; /* Pipe thread running? */

/*
 * start up a thread that watches the named pipe
 */
static void
pipe_thread(void)
{
	static char		*pcmp_dirname(char *);
	static void		pcmp_thread(struct pcmp_priv *);
	void			*pcmp_thr_stk;
	struct stat		sb;
	struct mem_priv		*mem = NULL;
	char			*p = PCMEM_PIPE_PATH;
	char			*bn;
	struct pcmp_priv	*pcmp;

	if (started)
		return;

	debug(1, "pipe_thread: entering\n");

	/*
	 * we don't do an open for the named pipe, since pcmp_thread() does
	 * that.  Instead, we just stat the device and make sure it's
	 * there and is a reasonable type
	 */

	/* just take a path if they hand it to us. */
	if (stat(p, &sb) < 0) {

		if (errno != ENOENT) {
			debug(5,
			    "pipe_thread: stat failed for: %s; %m\n",
			    p);
			goto dun;
		}

		/*
		 * the pipe doesn't exist -- create it (and the directory
		 * it goes in if needed)
		 */
		if ((bn = pcmp_dirname(p)) != NULL) {
			if (makepath(bn, 0755) < 0) {
				debug(5, "pipe_thread: "
				    "makepath failed for: %s\n", bn);
				free(bn);
				goto dun;
			}
			free(bn);
		}
		if (mknod((const char *)p, S_IFIFO|0600, NULL) < 0) {
			debug(5, "pipe_thread: mknod failed for: %s; %m\n",
			    p);
			goto dun;
		}
		if (stat(p, &sb) < 0) {
			debug(5, "pipe_thread: stat failed for: %s; %m\n",
			    p);
			goto dun;
		}
	} else {
		if (!S_ISFIFO(sb.st_mode)) {
			debug(5, "pipe_thread: not a FIFO: %s; %m\n", p);
			goto dun;
		}
	}

	/* create an empty pcmp-private data structure */
	mem = (struct mem_priv *)calloc(1, sizeof (struct mem_priv));
	mem->mem_fd = -1;

	/* stick some good stuff in the device hierarchy */
	mem->mem_rawpath = strdup(p);
	mem->mem_blockpath = mem->mem_rawpath;

	/* create the pcmp priv struct (so we only pass one param to thread) */
	pcmp = (struct pcmp_priv *)calloc(1, sizeof (struct pcmp_priv));
	pcmp->pcmp_mem = mem;
	pcmp->pcmp_symname = strdup(PCMEM_SYMNAME);

	pcmp_thr_stk = (void *)malloc(PCMEM_STKSIZE);
	if (thr_create(pcmp_thr_stk, PCMEM_STKSIZE,
	    (void *(*)(void *))pcmp_thread, (void *)pcmp, THR_BOUND,
	    (thread_t *)&mem->mem_tid) != 0) {
		warning(gettext("pcmp thread create failed; %m\n"));
		goto dun;
	}
	started = 1;
#ifdef	DEBUG
	debug(6, "pipe_thread: pcmp_thread id %d created\n", mem->mem_tid);
#endif

dun:
	debug(5, "pipe_thread: returning\n");
}


static void
pcmp_thread(struct pcmp_priv *pcmp)
{
	static bool_t		parse_pipe_str(char *, char *, char *, int *);
	extern int		vold_running;
	extern cond_t		running_cv;
	extern mutex_t		running_mutex;
	struct mem_priv		*mem = pcmp->pcmp_mem;
	char			*symname = pcmp->pcmp_symname;
	char			pipe_buf[PCMEM_PBUF_SZ+1];
	char			dev_buf[PCMEM_PBUF_SZ+1];
	char			act_buf[PCMEM_PBUF_SZ+1];
	int			sym_num;
	char			sym_buf[PCMEM_PBUF_SZ+1];
	register char		*cp;
	int			ret_val;
	char			mode_buf[PCMEM_MODE_BUF_LEN];



	/* ensure that the main loop is ready */
	(void) mutex_lock(&running_mutex);
	while (vold_running == 0) {
		(void) cond_wait(&running_cv, &running_mutex);
	}
	(void) mutex_unlock(&running_mutex);

	debug(5, "pcmp_thread: entering for path \"%s\"\n",
	    mem->mem_rawpath);

open_again:
	/* ensure the pipe is open */
	if (mem->mem_fd >= 0) {
		(void) close(mem->mem_fd);
	}
	if ((mem->mem_fd = open(mem->mem_rawpath, O_RDONLY)) < 0) {
		warning(gettext("pcmem: can't open %s; %m\n"),
		    mem->mem_rawpath);
		goto errout;
	}

	/*CONSTCOND*/
	for (;;) {

		/*
		 * this blocks until pcmciad sends us a line
		 */

#ifdef	DEBUG
		debug(5, "pcmp_thread: reading from pipe\n");
#endif

		cp = pipe_buf;
		while ((ret_val = read(mem->mem_fd, (void *)cp, 1)) == 1) {
			if (*cp == '\n') {
				*cp = NULLC;
				break;
			}
			if (*cp == NULLC) {
				break;
			}
			cp++;
			if (cp >= pipe_buf + sizeof (pipe_buf))
				goto open_again;
		}
		if (ret_val < 0) {
			debug(1, "pcmp_thread: read from \"%s\" failed; %m\n",
			    mem->mem_rawpath);
			goto open_again;
		}
		if (ret_val == 0) {
			debug(1, "pcmp_thread: EOF read from \"%s\"\n",
			    mem->mem_rawpath);
			goto open_again;
		}

		debug(9, "pcmp_thread: line read from pipe: \"%s\"\n",
		    pipe_buf);

		if (!parse_pipe_str(pipe_buf, act_buf, dev_buf, &sym_num)) {
			/* oh oh -- not in correct format! */
			continue;
		}

		if (strcmp(act_buf, PCMEM_PIPE_ACTION) == 0) {

			/* set up the symname to use */
			/*LINTED var_fmt*/
			(void) snprintf(sym_buf, sizeof (sym_buf),
			    symname, sym_num);

			/* set up the mode */
			(void) snprintf(mode_buf, sizeof (mode_buf),
			    "0%o", DEFAULT_MODE);

			/* register this device */
			if (dev_use(PCMEM_MTYPE, DRIVE_CLASS, dev_buf, sym_buf,
			    DEFAULT_USER, DEFAULT_GROUP, mode_buf, FALSE,
			    FALSE) == FALSE) {
				/* may be already managed */
				debug(1,
	"pcmp_thread: warning: dev_use on \"%s\" failed (already managed?)\n",
				    dev_buf);
			}

		} else {
			warning(
			    gettext("pcmem: unknown message from pcmciad\n"));
		}
	}

	/*NOTREACHED*/

errout:
	/* this thread is exiting! */
	if (mem->mem_fd >= 0) {
		(void) close(mem->mem_fd);
		mem->mem_fd = -1;
	}

	started = 0;
}


/*
 * return the directory part of a path (like dirname(1))
 *
 * assume we have a well formed path, i.e. no "/abc/" or "/"
 */
static char *
pcmp_dirname(char *path)
{
	char		*s;
	char		*res = NULL;
	register char	*cpi;
	register char	*cpo;

	/* find the last slash in the path */
	if ((s = strrchr(path, '/')) != NULL) {
		res = malloc((size_t)(s - path + 1));
		if (res == NULL)
			return (NULL);
		for (cpi = path, cpo = res; cpi < s; cpi++, cpo++) {
			*cpo = *cpi;
		}
		*cpo = NULLC;
	}
	return (res);
}



/*
 * called because a line of the form "use pcmem ... PATH_REGEX ..." was
 * found in the config file, and a path has been found that
 * matches PATH_REGEX
 *
 * return true if the path points at a pcmem device,
 * as it's understood by this code
 */
static bool_t
pcmem_testpath(char *p)
{
	struct stat		sb;
	int			fd = -1;
	char			*rp = NULL;
	struct dk_cinfo		dkc;
	int			res = FALSE;
	struct devs		*dp;

	debug(7, "pcmem_testpath: scanning \"%s\"\n", p);

	/* stat it (if we can) */
	if (stat(p, &sb) < 0) {
		debug(5, "pcmem_testpath: stat of \"%s\"; %m\n", p);
		goto mem_dun;
	}

	/* see if device already being used */
	if ((dp = dev_getdp(sb.st_rdev)) != NULL) {
		if (dp->dp_dsw == &pcmemdevsw) {
			debug(5, "pcmem_testpath: %s already in use\n", p);
			return (TRUE);
		} else {
			debug(5, "pcmem_testpath: %s already managed by %s\n",
				p, dp->dp_dsw->d_mtype);
			return (FALSE);
		}
	}

	/* make sure our path is a raw device */
	if ((rp = rawpath(p)) == NULL) {
		debug(5, "pcmem_testpath: can't rawpath(): \"%s\"\n", p);
		goto mem_dun;
	}

	/* try to open it */
	if ((fd = open(p, O_RDONLY|O_NDELAY)) < 0) {
		debug(5, "pcmem_testpath: open of \"%s\"; %m\n", rp);
		goto mem_dun;
	}

	/* check for memird octl handling */
	if (ioctl(fd, DKIOCINFO, &dkc) < 0) {
		debug(5, "pcmem_testpath: ioctl(DKIOCINFO) on \"%s\"; %m\n",
		    rp);
		goto mem_dun;
	}
	if (dkc.dki_ctype != DKC_PCMCIA_MEM) {
		debug(5, "pcmem_testpath: type != PCMEM on \"%s\"\n", rp);
		goto mem_dun;
	}

	/* we suceeded */
	res = TRUE;
	debug(5, "pcmem_testpath: we've got a pcmem \"%s\"\n", p);

mem_dun:
	/* clean up if needed */
	if (fd >= 0) {
		(void) close(fd);
	}
	if (rp) {
		free(rp);
	}
	return (res);
}

static bool_t
pcmem_remount(vol_t *volumep)
{
	/*
	 * There's no need to find the new default file
	 * descriptor for a PCMCIA card after it has been
	 * formatted and repartitioned.  The default
	 * file descriptor for a PCMCIA card never changes.
	 */

	/*
	 * We need to confound lint while creating a dummy
	 * function that does nothing with its argument.
	 */
	if (volumep != NULL) {
		return (TRUE);
	} else {
		return (FALSE);
	}
}

/*
 * called for one of two reasons:
 * (1) the pcmcia daemon has sent a message down the named pipe
 *	saying to use a particular device, or
 * (2) pcmem_testpath() has found a suitable pcmem pathname
 */
/*ARGSUSED*/
static bool_t
pcmem_use(char *path, char *symname)
{
	static void		pcmem_thread(struct devs *);
	void			*pcmem_thr_stk;
	struct stat		statbuf;
	char			full_path[MAXPATHLEN];
	char			*path_trunc = path; /* "path" gets truncated */
	char			namebuf[MAXPATHLEN]; /* name buffer */
	char			namebuf1[MAXPATHLEN];	/* 2nd name buffer */
	struct devs		*dp;
	struct mem_priv		*mem;
	char			*s;
	char			*p;
	vvnode_t		*bvn;
	vvnode_t		*rvn;
	char			path_save[MAXPATHLEN];
	bool_t			res = FALSE;
	struct dk_cinfo		dkc;
	int			fd;

	info(gettext("pcmem_use: %s\n"), path);

	/*
	 * we don't do an open for the pcmem because it returns ENODEV
	 * if there isn't a device there.  Instead, we just stat the
	 * device and make sure it's there and is a reasonable type
	 */

	/* just take a path if they hand it to us */
	if (stat(path, &statbuf) < 0) {
		/*
		 * We expect a path of the form:
		 * 	/dev/{rdsk, dsk}/c#t#
		 * We fill in the rest.
		 */
		(void) snprintf(full_path, sizeof (full_path),
		    PCMEM_NAMEPROTO_DEFD, path, PCMEM_BASEPART);
		if (stat(full_path, &statbuf) < 0) {
			debug(1, "pcmem_use: stat of \"%s\"; %m\n", full_path);
			goto dun;
		}
		/* the device was found */
	} else {

		/*
		 * got a good path -- truncate the "slice" part of the name
		 *
		 * XXX: assume all PCMEM pathnames end in "sN"
		 */
		(void) strlcpy(full_path, path, sizeof (full_path));
		if ((s = strrchr(path, 's')) == 0) {
			/* the full path didn't have a "s" in it! */
			warning(gettext("pcmem: %s is an invalid path\n"),
			    path);
			goto dun;
		}
		/* XXX: should make sure a slice number follows */
		*s = NULLC;
#ifdef	DEBUG
		debug(1, "pcmem_use: path_trunc=\"%s\"\n", path_trunc);
#endif
	}

	/* check to see if this guy is already configured */
	if ((dp = dev_getdp(statbuf.st_rdev)) != NULL) {
		if (dp->dp_dsw == &pcmemdevsw) {
			/*
			 * Remove "nomedia" node if support has changed.
			 * By sending a HUP signal to vold, dev_use()
			 * will call here.
			 */
			if (!support_nomedia && dp->dp_cvn) {
				dev_remove_ctldev(dp);
			}
			/*
			 * Create "nomedia" node if support has changed.
			 */
			if (support_nomedia && !dp->dp_cvn && !dp->dp_vol) {
				dev_create_ctldev(dp);
			}
			debug(1, "pcmem_use: %s already in use\n", full_path);
			return (TRUE);
		} else {
			debug(1, "pcmem_use: %s already managed by %s\n",
				full_path, dp->dp_dsw->d_mtype);
			return (FALSE);
		}
	}

	/* ensure it's a block or char spcl device */
	if (!S_ISCHR(statbuf.st_mode) && !S_ISBLK(statbuf.st_mode)) {
		warning(gettext(
		    "pcmem: %s not block or char device (mode 0x%x)\n"),
		    full_path, statbuf.st_mode);
		goto dun;
	}

	/* create an empty memory-private data structure */
	mem = (struct mem_priv *)calloc(1, sizeof (struct mem_priv));
	mem->mem_fd = -1;
	mem->mem_inserted = FALSE;

	/* save a copy of the pathname */
	(void) strcpy(path_save, full_path);

	/* stick some good stuff in the device hierarchy */
	if ((s = strstr(path_trunc, "rdsk")) != 0) {

		/* got a raw path (i.e. "rdsk" in it) */

		/* save a pointer to the raw vv-node */
		rvn = dev_dirpath(path_trunc);

		/* create the name for rawpath */
		(void) snprintf(namebuf, sizeof (namebuf),
		    PCMEM_NAMEPROTO, path_trunc, PCMEM_BASEPART);
		mem->mem_rawpath = strdup(namebuf);

		/* get the block path now from the raw one */

		/* skip past "rdsk/" */
		if ((p = strchr(s, '/')) != 0) {
			p++;
			(void) snprintf(namebuf, sizeof (namebuf),
			    "%s/%s", PCMEM_DSK_PATH, p);
		} else {
			/* no slash after rdsk? */
			debug(1,
		"pcmem_use: using malformed pathname (no '/') \"%s\"\n",
			    path_trunc);
			/* what else can we do? */
			(void) strlcpy(namebuf, path_trunc, sizeof (namebuf));
		}

		/* get the block vv-node */
		bvn = dev_dirpath(namebuf);

		/* create the name for blockpath */
		(void) snprintf(namebuf1, sizeof (namebuf1),
		    PCMEM_NAMEPROTO, namebuf, PCMEM_BASEPART);
		mem->mem_blockpath = strdup(namebuf1);

	} else if (s = strstr(path_trunc, "dsk")) {

		/* he gave us the block path (i.e. "dsk" in it) */

		/* save pointer to block vv-node */
		bvn = dev_dirpath(path_trunc);

		/* create the name for blockpath */
		(void) snprintf(namebuf, sizeof (namebuf),
		    PCMEM_NAMEPROTO, path_trunc, PCMEM_BASEPART);
		mem->mem_blockpath = strdup(namebuf);

		/* get the chr patch now from the block one */

		/* skip past "dsk/" */
		if ((p = strchr(s, '/')) != 0) {
			p++;
			(void) snprintf(namebuf, sizeof (namebuf),
			    "%s/%s", PCMEM_RDSK_PATH, p);
		} else {
			/* no slash after "dsk"? */
			debug(1,
		"pcmem_use: using malformed pathname (no '/') \"%s\"\n",
			    path);
			/* what else can we do? */
			(void) strlcpy(namebuf, path, sizeof (namebuf));
		}

		/* save a pointer to the raw vv-node */
		rvn = dev_dirpath(namebuf);

		/* create the name for rawpath */
		(void) snprintf(namebuf1, sizeof (namebuf1),
		    PCMEM_NAMEPROTO, namebuf, PCMEM_BASEPART);
		mem->mem_rawpath = strdup(namebuf1);

	} else {
		debug(1,
		    "pcmem_use: malformed pathname (no '[r]dsk') \"%s\"\n",
		    path);
		goto dun;
	}

	if ((dp = dev_makedp(&pcmemdevsw, mem->mem_rawpath)) == NULL) {
		debug(1, "pcmem_use: dev_makedp failed for \"%s\"\n",
		    mem->mem_rawpath);
		goto dun;
	}

	dp->dp_priv = (void *)mem;
	dp->dp_bvn = bvn;
	dp->dp_rvn = rvn;

	/*
	 * Get socket number information which is from
	 *	dki_unit in DKIOCINFO structure
	 */
	if ((fd = open(path_save, O_RDONLY)) < 0) {
		warning(gettext("pcmem: can't open %s; %m\n"),
		    path_save);
		goto dun;
	}

	if (ioctl(fd, DKIOCINFO, &dkc) < 0) {
		noise(gettext("pcmem: Failed DKIOCINFO ioctl on %s\n"),
			path_save);
		(void) close(fd);
		goto dun;
	}

	debug(6, "pcmem_use: Found socket number %d\n", dkc.dki_unit);
	(void) snprintf(namebuf, sizeof (namebuf), PCMEM_SYMNAME, dkc.dki_unit);
	dp->dp_symname = strdup(namebuf);
	(void) close(fd);

	/* create a thread to manage this device */
	(void) mutex_init(&mem->mem_mutex, USYNC_THREAD, 0);
	(void) mutex_init(&mem->mem_inserted_mutex, USYNC_THREAD, 0);
	pcmem_thr_stk = (void *)malloc(PCMEM_STKSIZE);
	if (thr_create(pcmem_thr_stk, PCMEM_STKSIZE,
	    (void *(*)(void *))pcmem_thread, (void *)dp, THR_BOUND,
	    (thread_t *)&mem->mem_tid) != 0) {
		warning(gettext("pcmem thread create failed; %m\n"));
		goto dun;
	}
#ifdef	DEBUG
	debug(6, "pcmem_use: pcmem_thread id %d created\n", mem->mem_tid);
#endif

	res = TRUE;
dun:
	return (res);
}


/*ARGSUSED*/
static void
pcmem_devmap(vol_t *v, int part, int off)
{
	struct devs	*dp;
	struct mem_priv	*mem;

	dp = dev_getdp(v->v_basedev);
	mem = (struct mem_priv *)dp->dp_priv;
	/*
	 * don't really need to lock mem here, since rawpath doesn't
	 * change much
	 */
	v->v_devmap[off].dm_path = strdup(mem->mem_rawpath);
	debug(1, "pcmem_devmap: v->v_devmap[%d].dm_path = \"%s\"\n",
	    off, v->v_devmap[off].dm_path);
}


static int
pcmem_getfd(dev_t dev)
{
	struct devs	*dp;
	struct mem_priv	*mem;
	int		fd;

	dp = dev_getdp(dev);
	ASSERT(dp != NULL);
	mem = (struct mem_priv *)dp->dp_priv;
	ASSERT(mem->mem_fd != -1);
	(void) mutex_lock(&mem->mem_mutex);
	fd = mem->mem_fd;
	(void) mutex_unlock(&mem->mem_mutex);
	debug(1, "pcmem_devmap: mem->mem_fd=%d\n", fd);
	return (fd);
}


/*ARGSUSED*/
static bool_t
pcmem_error(struct ve_error *vie)
{
	debug(1, "pcmem_error\n");
	return (TRUE);
}


/*
 * State that must be cleaned up:
 *	name in the name space
 *	the "dp"
 *	any pointers to the media
 *	eject any existing media
 *	the priv structure
 */
/*
 * XXX: a bug still exists here.  we have a thread polling on this
 * XXX: device in the kernel, we need to get rid of this also.
 * XXX: since we're going to move the waiter thread up to the
 * XXX: user level, it'll be easier to kill off as part of the
 * XXX: cleanup of the device private data.
 */

static void
pcmem_close(char *path, dev_t rdev)
{
	extern bool_t		dev_present(struct devs *);
	char			namebuf[MAXPATHLEN];
	struct	stat		sb;
	struct devs		*dp;
	struct mem_priv		*mem;

	debug(1, "pcmem_close(): entering for \"%s\"\n", path);

	if (stat(path, &sb) < 0) {
		(void) snprintf(namebuf, sizeof (namebuf),
		    PCMEM_NAMEPROTO, path, PCMEM_BASEPART);
		if (stat(namebuf, &sb) < 0) {
			if (rdev == NODEV) {
				warning(gettext("pcmem_close: %s; %m\n"),
					namebuf);
				return;
			}
		} else {
			rdev = sb.st_rdev;
		}
	} else {
		rdev = sb.st_rdev;
	}

	if ((dp = dev_getdp(rdev)) == NULL) {
		debug(1, "pcmem_close: \"%s\" not being managed\n", path);
		return;
	}

	/* get our private data */
	mem = (struct mem_priv *)dp->dp_priv;

	/* take care of the listner thread */
	(void) mutex_lock(&mem->mem_mutex);
	(void) thr_kill(mem->mem_tid, SIGUSR1);
	/* apparently we have to kick it out of the cond_wait */
	(void) mutex_unlock(&mem->mem_mutex);
	(void) thr_join(mem->mem_tid, 0, 0);
	debug(1, "pcmem thread (id %d) reaped\n", mem->mem_tid);


	/*
	 * XXX: NOTE: we still have the pipe thread running
	 */

	/*
	 * there is no longer a listener thread, so the mutex
	 * no longer needs to be acquired
	 */

	/* if there is a volume inserted in this device ... */
	if (dev_present(dp)) {
		/*
		 * clean up the name space and the device maps
		 * to remove references to any volume that might
		 * be in the device right now
		 *
		 * this crap with the flags is to keep the
		 * "poll" from being relaunched by this function
		 *
		 * yes, its a hack and there should be a better way.
		 */
		if (dp->dp_dsw->d_flags & D_POLL) {
			dp->dp_dsw->d_flags &= ~D_POLL;
			dev_eject(dp->dp_vol, TRUE);
			dp->dp_dsw->d_flags |= D_POLL;
		} else {
			dev_eject(dp->dp_vol, TRUE);
		}
		if (dp->dp_vol != NULL) {
			return;
		}
		(void) ioctl(mem->mem_fd, DKIOCEJECT, 0);
	}

	/* clean up the names in the name space */
	node_unlink(dp->dp_bvn);
	node_unlink(dp->dp_rvn);

	/* close the file descriptor we're holding open */
	(void) close(mem->mem_fd);

	/* free the private data we've allocated */
	if (mem->mem_blockpath) {
		free(mem->mem_blockpath);
	}
	if (mem->mem_rawpath) {
		free(mem->mem_rawpath);
	}
	free(mem);

	/* free the dp, so no one points at us anymore */
	dev_freedp(dp);
}


static void
pcmem_eject(struct devs *dp)
{
	struct mem_priv	*mem = (struct mem_priv *)dp->dp_priv;


	debug(10, "pcmem_eject: clearing inserted flag\n");
	(void) mutex_lock(&mem->mem_inserted_mutex);
	mem->mem_inserted = FALSE;
	(void) mutex_unlock(&mem->mem_inserted_mutex);
}


/*
 * check for a PCMCIA memory card
 *
 * return:
 *	0 if we didn't find any media
 *	1 if we already knew media was there
 *	2 if we found media and generated an event
 *
 * NOTE: this routine hogs the mem mutex for it's whole existence,
 * so be sure not to call any routine that may need it (with a little
 * work this could hog the mutex a lot less).
 */
static int
pcmem_check(struct devs *dp)
{
	static bool_t		reopen_pcmem(struct mem_priv *);
	struct mem_priv		*mem = (struct mem_priv *)dp->dp_priv;
	struct vioc_event	vie;
	extern int		vold_running;
	extern cond_t 		running_cv;
	extern mutex_t		running_mutex;
	int			rval = 0;
	int			ret_val = 0; /* default return value is 0 */



#ifdef	DEBUG
	debug(1, "pcmem_check: entering for \"%s\"\n",
	    mem->mem_rawpath ? mem->mem_rawpath : "<null ptr>");
#endif

	/* ensure the vold main loop is running */
	(void) mutex_lock(&running_mutex);
	while (vold_running == 0) {
		(void) cond_wait(&running_cv, &running_mutex);
	}
	(void) mutex_unlock(&running_mutex);

	/* if we know the media is there there's no need to check again */
	(void) mutex_lock(&mem->mem_inserted_mutex);
	if (mem->mem_inserted) {
		(void) mutex_unlock(&mem->mem_inserted_mutex);
		debug(9, "pcmem_check: already inserted\n");
		ret_val = 1;
		goto out;
	}
	(void) mutex_unlock(&mem->mem_inserted_mutex);

	/* ensure media is open */
	(void) mutex_lock(&mem->mem_mutex);
	if (mem->mem_fd < 0) {
		dp->dp_writeprot = reopen_pcmem(mem);
		if (mem->mem_fd < 0) {
			/* an error [re]opening */
			(void) mutex_unlock(&mem->mem_mutex);
			goto out;
		}
	}

	/* try to see if media is present */
	if (ioctl(mem->mem_fd, FDGETCHANGE, &rval) < 0) {
		(void) mutex_unlock(&mem->mem_mutex);
		debug(1, "pcmem_check: ioctl(DKIOCSTATE) failed; %m\n");
		goto out;
	}

	(void) mutex_unlock(&mem->mem_mutex);

#ifdef	DEBUG
	debug(5, "pcmem_check: FDGETCHANGE return value: %#x\n", rval);
#endif

	if ((rval & FDGC_CURRENT) == 0) {
		/*
		 * A memory card is IN the drive
		 * and we didn't know therewas  anything there ...
		 */
		ret_val = 2;		/* we generated an event */
		(void) mutex_lock(&mem->mem_inserted_mutex);
		mem->mem_inserted = TRUE;
		(void) mutex_unlock(&mem->mem_inserted_mutex);
		(void) memset(&vie, 0, sizeof (struct vioc_event));
		vie.vie_type = VIE_INSERT;
		vie.vie_insert.viei_dev = dp->dp_dev;
		vol_event(&vie, dp);
		dp->dp_writeprot = (rval & FDGC_CURWPROT) ? TRUE : FALSE;
		debug(5, "pcmem_check: generated INSERT event\n");
	}

out:

#ifdef	DEBUG
	debug(1, "pcmem_check: returning %d\n", ret_val);
#endif

	return (ret_val);
}


static void
pcmem_thread(struct devs *dp)
{
	static bool_t		reopen_pcmem(struct mem_priv *);
	extern bool_t		dev_present(struct devs *);
	static void		wait_til_signalled(struct devs *);
#ifdef	DEBUG
	static char		*state_to_str(enum dkio_state);
#endif
	extern int		vold_running;
	extern cond_t		running_cv;
	extern mutex_t		running_mutex;
	struct mem_priv		*mem = (struct mem_priv *)dp->dp_priv;
	struct dk_cinfo		dkc;
	enum dkio_state		mem_state;
	struct vioc_event	vie;
	struct fd_drive		fdchar;
	dev_t			dev;



	/* ensure that the main loop is ready */
	(void) mutex_lock(&running_mutex);
	while (vold_running == 0) {
		(void) cond_wait(&running_cv, &running_mutex);
	}
	(void) mutex_unlock(&running_mutex);

	/* ensure the memory card is open */
	(void) mutex_lock(&mem->mem_mutex);
	dp->dp_writeprot = reopen_pcmem(mem);
	if (mem->mem_fd < 0) {
		(void) mutex_unlock(&mem->mem_mutex);
		goto errout;
	}

	/* check to make sure this is a PCMCIA memory card */
	if (ioctl(mem->mem_fd, DKIOCINFO, &dkc) < 0) {
		noise(gettext("pcmem: Failed DKIOCINFO ioctl on %s; %m\n"),
		    mem->mem_rawpath);
		(void) mutex_unlock(&mem->mem_mutex);
		goto errout;
	}
	(void) mutex_unlock(&mem->mem_mutex);

	if (dkc.dki_ctype != DKC_PCMCIA_MEM) {
		noise(gettext("pcmem: %s is not a PCMCIA memory card\n"),
		    mem->mem_rawpath);
		goto errout;
	}

	/* see how device ejects */
	(void) mutex_lock(&mem->mem_mutex);
	if (ioctl(mem->mem_fd, FDGETDRIVECHAR, &fdchar) < 0) {
		(void) mutex_unlock(&mem->mem_mutex);
		debug(1, "pcmem_thread: FDGETDRIVECHAR; %m\n");
	} else {
		(void) mutex_unlock(&mem->mem_mutex);
		if (fdchar.fdd_ejectable == 0) {
			debug(1, "pcmem_thread: \"%s\" manually ejectable\n",
			    mem->mem_rawpath);
			dp->dp_flags |= DP_MEJECTABLE;
		}
	}

	mem_state = DKIO_NONE;

	/*CONSTCOND*/
	while (1) {

		/*
		 * this ioctl blocks until state changes
		 */
#ifdef	DEBUG
		debug(3, "pcmem_thread: ioctl(DKIOCSTATE, \"%s\") on \"%s\"\n",
		    state_to_str(mem_state), mem->mem_rawpath);
#else
		debug(3, "pcmem_thread: ioctl(DKIOCSTATE) on \"%s\"\n",
		    mem->mem_rawpath);
#endif

		/* normally we are blocked here waiting for state to change */
		if (ioctl(mem->mem_fd, DKIOCSTATE, &mem_state) < 0) {
			debug(1, "pcmem_thread: DKIOCSTATE; %m\n");
			if (errno == ENOTTY) {
				break;
			}
			(void) sleep(1);		/* forever ?? */
			continue;
		}

#ifdef  DEBUG
		debug(5, "pcmem_thread: new state = \"%s\"\n",
		    state_to_str(mem_state));
#endif

		if (mem_state == DKIO_NONE) {
			continue;	/* steady state -- ignore */
		}

		/* prepare to create an event */
		(void) memset(&vie, 0, sizeof (struct vioc_event));

		(void) mutex_lock(&mem->mem_inserted_mutex);

		if ((mem_state == DKIO_INSERTED) && !mem->mem_inserted) {

			/*
			 * We have media in the drive -- generate
			 *  an "insert" event
			 */
			mem->mem_inserted = TRUE;
			(void) mutex_unlock(&mem->mem_inserted_mutex);

			(void) mutex_lock(&mem->mem_mutex);
			dp->dp_writeprot = reopen_pcmem(mem);
			if (mem->mem_fd < 0) {
				/*
				 * [re]open failed -- could be because
				 * card was removed *immediately* after
				 * insertion
				 */
				(void) mutex_unlock(&mem->mem_mutex);
				(void) mutex_lock(&mem->mem_inserted_mutex);
				mem->mem_inserted = TRUE;
				(void) mutex_unlock(&mem->mem_inserted_mutex);
				break;
			}
			(void) mutex_unlock(&mem->mem_mutex);

			/* generate an insert event */
			dev = dp->dp_dev;
			debug(2,
			"pcmem_thread: generating INSERT event for (%d,%d)\n",
			    major(dev), minor(dev));
			vie.vie_type = VIE_INSERT;
			vie.vie_insert.viei_dev = dev;
			vol_event(&vie, dp);

		} else if (mem_state == DKIO_EJECTED) {

			/*
			 * We have NO media in the drive (it's just
			 *  been ejected), so generate an "eject" event
			 * if we already know about the ejection,
			 *  then just continue on our happy loop
			 */
#ifdef	DEBUG
			debug(1,
	"pcmem_thread: handling EJECT state: dp=%#x, dp->dp_vol = %#x\n",
			    (char *)dp, (char *)(dp->dp_vol));
#endif

			/* keep track of removal */
			mem->mem_inserted = FALSE;
			(void) mutex_unlock(&mem->mem_inserted_mutex);

			(void) mutex_lock(&vold_main_mutex);

			if (dev_present(dp)) {
				/* generate an eject event */
				dev = dp->dp_vol->v_devmap[0].dm_voldev;
				debug(2,
			"pcmem_thread: generating EJECT event for (%d,%d)\n",
				    major(dev), minor(dev));
				vie.vie_type = VIE_EJECT;
				vie.vie_eject.viej_force = TRUE;
				vie.vie_eject.viej_unit = minor(dev);
				vol_event(&vie, dp);

				(void) mutex_unlock(&vold_main_mutex);

				/* wait til ejection is done */
				wait_til_signalled(dp);

				/* check for all okay */
				if (dev_present(dp)) {
					/* timeout or other problem */
					debug(1,
				"pcmem_thread: EJECT didn't complete\n");
					continue;	/* try again */
				}

			} else {
				/*
				 * Create "nomedia" device node for empty
				 * removable media device.
				 */
				if (support_nomedia && !dp->dp_cvn) {
					dev_create_ctldev(dp);
				}
				(void) mutex_unlock(&vold_main_mutex);
				debug(2,
				"pcmem_thread: EJECT but vol already gone\n");
			}
		}

	}

errout:
	/* this thread is exiting! */
	debug(10, "pcmem_thread: thread is exiting!\n");
	(void) mutex_lock(&mem->mem_mutex);
	if (mem->mem_fd >= 0) {
		(void) close(mem->mem_fd);
		mem->mem_fd = -1;
	}
	(void) mutex_unlock(&mem->mem_mutex);

	/* clean up the names in the name space */
	node_unlink(dp->dp_bvn);
	node_unlink(dp->dp_rvn);

	/* free the dp, so no one points at us anymore */
	dev_freedp(dp);

	/* XXX: should we free "mem" ? */
}


/*
 * wait until signaled (or timeout occurs) that the dev is no longer
 * prsent
 */
static void
wait_til_signalled(struct devs *dp)
{
	extern bool_t		dev_present(struct devs *);
	timestruc_t		ts;
	int			ret_val;


	(void) mutex_lock(&dp->dp_lock->dp_vol_vg_mutex);

	/* if dev is already done then we're already done */
	if (!dev_present(dp)) {
		(void) mutex_unlock(&dp->dp_lock->dp_vol_vg_mutex);
		return;
	}

	/* set up time delay */
	ts.tv_sec = PCMEM_OVERLAP_TIMEOUT_SECS;
	ts.tv_nsec = 0;

	debug(10,
	    "wait_til_signalled: waiting for ejection (%d sec timeout)\n",
	    PCMEM_OVERLAP_TIMEOUT_SECS);

	if ((ret_val = cond_reltimedwait(&dp->dp_lock->dp_vol_vg_cv,
	    &dp->dp_lock->dp_vol_vg_mutex, &ts)) != 0) {
		(void) mutex_unlock(&dp->dp_lock->dp_vol_vg_mutex);
		debug(10, "wait_til_signalled: cond_reltimedwait error: %d\n",
		    ret_val);
		return;
	}

	(void) mutex_unlock(&dp->dp_lock->dp_vol_vg_mutex);

	debug(10, "wait_til_signalled: cond_reltimedwait succeeded\n");
}


/*
 * [re]open the memory card, returning whether or not it's write protected
 *
 * NOTE: should normally be called with the memory structure locked
 */
static bool_t
reopen_pcmem(struct mem_priv *mem)
{
	bool_t		rdonly = FALSE;
	bool_t		try_again = TRUE;


	/*
	 * when a pcmem card is openend O_NDELAY and no memory card is there,
	 * but then a read-only card is inserted, this is needed to
	 * reopen the devicd
	 */

#ifdef	DEBUG
	debug(10, "reopen_pcmem: entering (fd = %d)\n", mem->mem_fd);
#endif

	/* ensure it's closed to start with */
	if (mem->mem_fd >= 0) {
		(void) close(mem->mem_fd);
	}

again:
	/* try a blocking open, in read-write mode */
	if ((mem->mem_fd = open(mem->mem_rawpath,
	    O_RDWR|O_NDELAY|O_EXCL)) < 0) {
		/* try read-only mode */
		if (errno == EROFS) {
			mem->mem_fd = open(mem->mem_rawpath,
			    O_RDONLY|O_NDELAY|O_EXCL);
			rdonly = TRUE;
		}
	}

	if (mem->mem_fd < 0) {
		warning(gettext("pcmem: open error on %s; %m\n"),
		    mem->mem_rawpath);
		/* if we get EAGAIN then try again -- once */
		if (errno == EAGAIN) {
			if (try_again) {
				(void) sleep(1);
				try_again = FALSE;
				goto again;
			}
		}
	} else {
		(void) fcntl(mem->mem_fd, F_SETFD, 1);	/* close-on-exec */
	}

#ifdef	DEBUG
	debug(10, "reopen_pcmem: fd=%d, rdonly=%s\n", mem->mem_fd,
	    rdonly ? "TRUE" : "FALSE");
#endif

	return (rdonly);
}


#ifdef  DEBUG

static char *
state_to_str(enum dkio_state st)
{
	static char		state_buf[30];



	switch (st) {
	case DKIO_NONE:
		(void) sprintf(state_buf, "DKIO_NONE");
		break;
	case DKIO_INSERTED:
		(void) sprintf(state_buf, "DKIO_INSERTED");
		break;
	case DKIO_EJECTED:
		(void) sprintf(state_buf, "DKIO_EJECTED");
		break;
	default:
		(void) sprintf(state_buf, "?unknown? (%d)", (int)st);
		break;
	}

	return (state_buf);
}

#endif  /* DEBUG */



/*
 * parse the line read from the pipe, in the format:
 *		"ACTION, PATH, SOCKET_NUM"
 * e.g.:
 *		"insert, /dev/rdsk/c1t0d0s2, 0"
 */
static bool_t
parse_pipe_str(char *pipe_buf, char *act_buf, char *path_buf,
    int *socket_num_ptr)
{
	register char	*cpi = pipe_buf;
	register char	*cpo;
	bool_t		res = FALSE;


	/* ensure there's a seperator */
	if (strchr(cpi, PCMEM_PIPE_SEP) == NULL) {
		debug(1,
	"parse_pipe_str: malformed pipe str \"%s\" (no '%c' seperator)\n",
		    cpi, PCMEM_PIPE_SEP);
		goto dun;
	}

	/* copy up to the seperator into the action buf */
	for (cpo = act_buf; *cpi != NULLC; cpi++, cpo++) {
		if (*cpi == PCMEM_PIPE_SEP) {
			*cpo = NULLC;
			cpi++;			/* skip the seperator */
			break;
		}
		*cpo = *cpi;
	}

	/* skip white space */
	while (*cpi != NULLC) {
		if (!isspace(*cpi)) {
			break;
		}
		cpi++;
	}
	if (*cpi == NULLC) {
		debug(1,
		"parse_pipe_str: malformed pipe str \"%s\" (premature EOF)\n",
		    pipe_buf);
		goto dun;
	}

	/* ensure there's a seperator */
	if (strchr(cpi, PCMEM_PIPE_SEP) == NULL) {
		debug(1,
	"parse_pipe_str: malformed pipe str \"%s\" (no '%c' seperator)\n",
		    cpi, PCMEM_PIPE_SEP);
		goto dun;
	}

	/* copy up to the seperator into the action buf */
	for (cpo = path_buf; *cpi != NULLC; cpi++, cpo++) {
		if (*cpi == PCMEM_PIPE_SEP) {
			*cpo = NULLC;
			cpi++;			/* skip the seperator */
			break;
		}
		*cpo = *cpi;
	}

	/* skip white space */
	while (*cpi != NULLC) {
		if (!isspace(*cpi)) {
			break;
		}
		cpi++;
	}
	if (*cpi == NULLC) {
		debug(1,
		"parse_pipe_str: malformed pipe str \"%s\" (premature EOF)\n",
		    pipe_buf);
		goto dun;
	}

	/* get the last param: socket number */
	if ((*socket_num_ptr = atoi(cpi)) < 0L) {
		debug(1,
		"parse_pipe_str: malformed pipe str \"%s\" (no socket num?)\n",
		    pipe_buf);
		goto dun;
	}

	/* we have the info! */
	res = TRUE;

dun:
#ifdef	DEBUG
	if (res) {
		debug(1, "parse_pipe_str: returning (\"%s\", \"%s\", %d)\n",
		    act_buf, path_buf, *socket_num_ptr);
	}
#endif
	return (res);
}
