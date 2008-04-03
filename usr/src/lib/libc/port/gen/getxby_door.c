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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "synonyms.h"
#include <mtlib.h>
#include <sys/types.h>
#include <errno.h>
#include <pwd.h>
#include <nss_dbdefs.h>
#include <stdio.h>
#include <string.h>
#include <synch.h>
#include <sys/param.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <getxby_door.h>
#include <sys/door.h>
#include <procfs.h>
#include <door.h>
#include <sys/mman.h>
#include "libc.h"
#include "tsd.h"
#include "base_conversion.h"

/* nss<->door hints */
static mutex_t	hints_lock = DEFAULTMUTEX;
static size_t	door_bsize = 0;
static size_t	door_nbsize = 0;
static int	proc_is_cache = -1;

/* library<->nscd door interaction apis */

/*
 *
 * Routine that actually performs the door call.
 * Note that we cache a file descriptor.  We do
 * the following to prevent disasters:
 *
 * 1) Never use 0,1 or 2; if we get this from the open
 *    we dup it upwards.
 *
 * 2) Set the close on exec flags so descriptor remains available
 *    to child processes.
 *
 * 3) Verify that the door is still the same one we had before
 *    by using door_info on the client side.
 *
 *	Note that we never close the file descriptor if it isn't one
 *	we allocated; we check this with door info.  The rather tricky
 *	logic is designed to be fast in the normal case (fd is already
 *	allocated and is ok) while handling the case where the application
 *	closed it underneath us or where the nscd dies or re-execs itself
 *	and we're a multi-threaded application.  Note that we cannot protect
 *	the application if it closes the fd and it is multi-threaded.
 *
 *  int _nsc_trydoorcall(void *dptr, size_t *bufsize, size_t *actualsize);
 *
 *      *dptr           IN: points to arg buffer OUT: points to results buffer
 *      *bufsize        IN: overall size of buffer OUT: overall size of buffer
 *      *actualsize     IN: size of call data OUT: size of return data
 *
 *  Note that *dptr may change if provided space as defined by *bufsize is
 *  inadequate.  In this case the door call mmaps more space and places
 *  the answer there and sets dptr to contain a pointer to the space, which
 *  should be freed with munmap.
 *
 *  Returns 0 if the door call reached the server, -1 if contact was not made.
 *
 */

/*
 * Max size for list of db names supported by the private nscd
 * No implied max here, any size will do, fixed size chosen to
 * reduce yet another malloc
 */

#define	BD_BUFSIZE	1024
#define	BD_SEP		','

typedef struct _nsc_door_t {
	int 		doorfd;
	mutex_t		door_lock;
	door_info_t 	doori;
} nsc_door_t;

static nsc_door_t	nsc_door[2] = {
	{ -1, DEFAULTMUTEX, { 0 } },		/* front (fattached) door */
	{ -1, DEFAULTMUTEX, { 0 } },		/* back (private) door */
};

/* assumed to be locked by using nsc_door[1] mutex */
static char	*nsc_db_buf = NULL;
static char	**nsc_db_list = NULL;

/*
 * Check for a valid and matching db in the list.
 * assume list is in the locked state.
 */

static int
_nsc_use_backdoor(char *db)
{
	char 	**ndb;

	if (db && nsc_db_buf != NULL && nsc_db_list != NULL) {
		for (ndb = nsc_db_list; *ndb; ndb++) {
			if (strcmp(db, *ndb) == 0)
				return (1);
		}
	}
	return (0);
}

/*
 * flush private db lists
 */
static void
_nsc_flush_private_db()
{
	if (nsc_db_buf != NULL) {
		libc_free((void *)nsc_db_buf);
		nsc_db_buf = NULL;
	}
	if (nsc_db_list != NULL) {
		libc_free((void *)nsc_db_list);
		nsc_db_list = NULL;
	}
}

/*
 * init/update nsc_db_buf given buff containing list of
 * db's to be processed by a private nscd.
 * This function assumes it has a well formed string from nscd.
 */

static int
_nsc_init_private_db(char *dblist)
{
	char	*cp, **lp;
	int	buflen = 0;
	int	arrlen = 0;

	if (dblist == NULL)
		return (0);

	/* reset db list */
	_nsc_flush_private_db();

	/* rebuild fresh list */
	buflen = strlen(dblist) + 1;
	for (cp = dblist; *cp; cp++)
		if (*cp == BD_SEP)
			arrlen++;
	if (cp == dblist)
		return (0);
	arrlen += 2;
	nsc_db_buf = (char *)libc_malloc(buflen);
	if (nsc_db_buf == (char *)NULL)
		return (0);
	nsc_db_list = (char **)libc_malloc(arrlen * sizeof (char *));
	if (nsc_db_list == (char **)NULL) {
		libc_free((void *)nsc_db_buf);
		nsc_db_buf = NULL;
		return (0);
	}
	(void) memcpy(nsc_db_buf, dblist, buflen);
	lp = nsc_db_list;
	*lp++ = nsc_db_buf;
	for (cp = nsc_db_buf; *cp; ) {
		if (*cp == BD_SEP) {
			*cp++ = '\0';
			*lp++ = cp;
		} else
			cp++;
	}
	*lp = NULL;
	return (1);
}

/*
 * _nsc_initdoor_fp attempts to validate the given door and
 * confirm that it is still available for use.  The options are:
 *	Front door:
 *		If it's not open, attempt to open or error
 *		If it's open attempt to validate.
 *		If it's not validatable, reset fd and try again.
 *		Other wise it open and validated, return success
 *	Per user (back) door:
 *		This door is passed to the client through th front door
 *		attempt to validate it.  If it can't be validated, it
 *		must be reset. Then send a NSS_ALTRESET error, so nscd can
 *		forward another fd if desired.
 */

static nss_status_t
_nsc_initdoor_fp(nsc_door_t *dp)
{

	door_info_t 		my_door;

	if (dp == NULL) {
		errno = ENOTCONN;
		return (NSS_ERROR);
	}

	/*
	 * the first time in we try and open and validate the front door.
	 * A front door request may return an alternate private back door
	 * that the client should use instead.
	 *
	 * To validate a door the door must have been created with
	 * the name service door cookie. The front door is file
	 * attached, owned by root and readonly by user, group and
	 * other.  If any of these validations fail we refuse to use
	 * the door.  A back door is delivered from the front door
	 * via a door_desc_t, and have the same cooke notification.
	 */

	lmutex_lock(&dp->door_lock);

try_again:

	if (dp->doorfd == -1 && dp == &nsc_door[0]) {	/* open front door */
		int		tbc[3];
		int		i;

		dp->doorfd = open64(NAME_SERVICE_DOOR, O_RDONLY, 0);
		if (dp->doorfd == -1) {
			lmutex_unlock(&dp->door_lock);
			return (NSS_ERROR);
		}

		/*
		 * dup up the file descriptor if we have 0 - 2
		 * to avoid problems with shells stdin/out/err
		 */
		i = 0;

		while (dp->doorfd < 3) { /* we have a reserved fd */
			tbc[i++] = dp->doorfd;
			if ((dp->doorfd = dup(dp->doorfd)) < 0) {
				while (i--)
					(void) close(tbc[i]);
				dp->doorfd = -1;
				lmutex_unlock(&dp->door_lock);
				return (NSS_ERROR);
			}
		}

		while (i--)
			(void) close(tbc[i]);

		/*
		 * mark this door descriptor as close on exec
		 */
		(void) fcntl(dp->doorfd, F_SETFD, FD_CLOEXEC);
		if (__door_info(dp->doorfd, &dp->doori) < 0 ||
		    (dp->doori.di_attributes & DOOR_REVOKED) ||
		    dp->doori.di_data != (uintptr_t)NAME_SERVICE_DOOR_COOKIE) {
			/*
			 * we should close doorfd because we just opened it
			 */
			(void) close(dp->doorfd);
			dp->doorfd = -1;
			(void) memset((void *)&dp->doori,
			    '\0', sizeof (door_info_t));
			lmutex_unlock(&dp->door_lock);
			errno = ECONNREFUSED;
			return (NSS_ERROR);
		}
	} else {
		if (__door_info(dp->doorfd, &my_door) < 0 ||
		    my_door.di_data != (uintptr_t)NAME_SERVICE_DOOR_COOKIE ||
		    my_door.di_uniquifier != dp->doori.di_uniquifier) {
			/*
			 * don't close it -
			 * someone else has clobbered fd
			 */
			dp->doorfd = -1;
			(void) memset((void *)&dp->doori,
			    '\0', sizeof (door_info_t));
			if (dp == &nsc_door[1]) {	/* reset back door */
				/* flush invalid db list */
				_nsc_flush_private_db();
				lmutex_unlock(&dp->door_lock);
				return (NSS_ALTRESET);
			}
			goto try_again;
		}

		if (my_door.di_attributes & DOOR_REVOKED) {
			(void) close(dp->doorfd);	/* nscd exited .... */
			dp->doorfd = -1;	/* try and restart connection */
			(void) memset((void *)&dp->doori,
			    '\0', sizeof (door_info_t));
			if (dp == &nsc_door[1]) {	/* back door reset */
				/* flush invalid db list */
				_nsc_flush_private_db();
				lmutex_unlock(&dp->door_lock);
				return (NSS_ALTRESET);
			}
			goto try_again;
		}
	}

	lmutex_unlock(&dp->door_lock);
	return (NSS_SUCCESS);
}

/*
 * Try the door request once only, to the specified connection.
 * return the results or error.
 */

static nss_status_t
_nsc_try1door(nsc_door_t *dp, void **dptr, size_t *ndata,
			size_t *adata, int *pdesc)
{
	door_arg_t		param;
	int			ret;
	nss_pheader_t		*rp;

	ret = _nsc_initdoor_fp(dp);
	if (ret != NSS_SUCCESS)
		return (ret);

	param.rbuf = (char *)*dptr;
	param.rsize = *ndata;
	param.data_ptr = (char *)*dptr;
	param.data_size = *adata;
	param.desc_ptr = NULL;
	param.desc_num = 0;
	ret = __door_call(dp->doorfd, &param);
	if (ret < 0) {
		return (NSS_ERROR);
	}
	*adata = param.data_size;
	*ndata = param.rsize;
	*dptr = (void *)param.data_ptr;
	rp = (nss_pheader_t *)((void *)param.rbuf);
	if (pdesc != NULL && rp && rp->p_status == NSS_ALTRETRY &&
	    param.desc_ptr != NULL && param.desc_num > 0) {
		if ((param.desc_ptr->d_attributes & DOOR_DESCRIPTOR) &&
		    param.desc_ptr->d_data.d_desc.d_descriptor >= 0 &&
		    param.desc_ptr->d_data.d_desc.d_id != 0) {
			/* have an alt descriptor */
			*pdesc = param.desc_ptr->d_data.d_desc.d_descriptor;
			/* got a NSS_ALTRETRY command */
			return (NSS_ALTRETRY);
		}
		errno = EINVAL;
		return (NSS_ERROR);		/* other error? */
	}
	if (*adata == 0 || *dptr == NULL) {
		errno = ENOTCONN;
		return (NSS_ERROR);
	}

	if (rp->p_status == NSS_ALTRESET ||
	    rp->p_status == NSS_ALTRETRY ||
	    rp->p_status == NSS_TRYLOCAL)
		return (rp->p_status);

	return (NSS_SUCCESS);
}

/*
 * Backwards compatible API
 */

nss_status_t
_nsc_trydoorcall(void **dptr, size_t *ndata, size_t *adata)
{
	return (_nsc_try1door(&nsc_door[0], dptr, ndata, adata, NULL));
}

/*
 * Send the request to the designated door, based on the supplied db
 * Retry on the alternate door fd if possible.
 */

nss_status_t
_nsc_trydoorcall_ext(void **dptr, size_t *ndata, size_t *adata)
{
	int		ret = NSS_ALTRETRY;
	nsc_door_t	*frontd = &nsc_door[0];
	nsc_door_t	*backd = &nsc_door[1];
	int		fd;

	nss_pheader_t	*ph, ph_save;
	char		*dbl;
	char		*db = NULL;
	nss_dbd_t	*dbd;
	int		fb2frontd = 0;
	int		reset_frontd = 0;
	size_t		ndata_save = *ndata, adata_save = *adata;
	void		*dptr_save = *dptr;

	ph = (nss_pheader_t *)*dptr;
	dbd = (nss_dbd_t *)((void *)((char *)ph + ph->dbd_off));
	if (dbd->o_name != 0)
		db = (char *)dbd + dbd->o_name;

	/*
	 * save away a copy of the header, in case the request needs
	 * to be sent to nscd more than once. In that case, this
	 * original header can be copied back to the door buffer
	 * to replace the possibly changed header
	 */
	ph_save = *ph;

	while (ret == NSS_ALTRETRY || ret == NSS_ALTRESET) {
		/* try private (back) door first if it exists and applies */
		if (db != NULL && backd->doorfd > 0 && fb2frontd == 0 &&
		    _nsc_use_backdoor(db)) {
			ret = _nsc_try1door(backd, dptr, ndata, adata, NULL);
			if (ret == NSS_ALTRESET) {
				/*
				 * received NSS_ALTRESET command,
				 * retry on front door
				 */
				lmutex_lock(&backd->door_lock);
				backd->doorfd = -1;
				(void) memset((void *)&backd->doori,
				    '\0', sizeof (door_info_t));
				/* flush now invalid db list */
				_nsc_flush_private_db();
				lmutex_unlock(&backd->door_lock);
				continue;
			} else if (ret == NSS_ALTRETRY) {
				/*
				 * received NSS_ALTRETRY command,
				 * fall back and retry on front door
				 */
				fb2frontd = 1;
				if (*dptr != dptr_save)
					(void) munmap((void *)*dptr, *ndata);

				/*
				 * restore the buffer size and header
				 * data so that the front door will
				 * see the original request
				 */
				*ndata = ndata_save;
				*adata = adata_save;
				*dptr = dptr_save;
				ph =  (nss_pheader_t *)*dptr;
				*ph = ph_save;
				/*
				 * tell the front door server, this is
				 * a fallback call
				 */
				ph->p_status = NSS_ALTRETRY;
				continue;
			}

			/* return the result or error */
			break;
		}

		/* try the front door */
		fd = -1;
		ret = _nsc_try1door(frontd, dptr, ndata, adata, &fd);

		if (ret != NSS_ALTRETRY) {
			/*
			 * got a success or failure result.
			 * but front door should never send NSS_ALTRESET
			 */
			if (ret == NSS_ALTRESET)
				/* reset the front door */
				reset_frontd = 1;
			else
				/*
				 * not NSS_ALTRETRY and not NSS_ALTRESET
				 * return the result or error
				 */
				break;
		} else if (fb2frontd == 1) {
			/*
			 * front door should never send NSS_ALTRETRY
			 * in a fallback call. Reset the front door.
			 */
			reset_frontd = 1;
		}

		if (reset_frontd == 1) {
			lmutex_lock(&frontd->door_lock);
			frontd->doorfd = -1;
			(void) memset((void *)&frontd->doori,
			    '\0', sizeof (door_info_t));
			lmutex_unlock(&frontd->door_lock);
			/* error out */
			ret = NSS_ERROR;
			break;
		}

		/* process NSS_ALTRETRY request from front door */
		if (fd < 0)
			continue;	/* no new door given, try again */

		/* update and try alternate door */
		lmutex_lock(&backd->door_lock);
		if (backd->doorfd >= 0) {
			/* unexpected open alt door - clean up, continue */
			_nsc_flush_private_db();
			(void) close(backd->doorfd);
		}

		/* set up back door fd */
		backd->doorfd = fd;

		/* set up back door db list */
		ph =  (nss_pheader_t *)*dptr;
		dbl = ((char *)ph) + ph->data_off;

		if (_nsc_init_private_db(dbl) == 0) {
			/* could not init db list, try again */
			(void) close(backd->doorfd);
			backd->doorfd = -1;
			lmutex_unlock(&backd->door_lock);
			continue;
		}
		if (door_info(backd->doorfd, &backd->doori) < 0 ||
		    (backd->doori.di_attributes & DOOR_REVOKED) ||
		    backd->doori.di_data !=
		    (uintptr_t)NAME_SERVICE_DOOR_COOKIE) {
			/* doorfd bad, or must not really be open */
			(void) close(backd->doorfd);
			backd->doorfd = -1;
			(void) memset((void *)&backd->doori,
			    '\0', sizeof (door_info_t));
		}
		(void) fcntl(backd->doorfd, F_SETFD, FD_CLOEXEC);
		lmutex_unlock(&backd->door_lock);
		/* NSS_ALTRETRY new back door */
		if (*dptr != dptr_save)
			(void) munmap((void *)*dptr, *ndata);

		/*
		 * restore the buffer size and header
		 * data so that the back door will
		 * see the original request
		 */
		*ndata = ndata_save;
		*adata = adata_save;
		*dptr = dptr_save;
		ph =  (nss_pheader_t *)*dptr;
		*ph = ph_save;
	}
	return (ret);
}

/*
 * Get the current (but growable) buffer size for a NSS2 packet.
 * Heuristic algorithm used:
 *	1) Make sure it's at least NSS_BUFLEN_DOOR in length (16k default)
 *	2) if an incoming user buffer is > larger than the current size
 *	   Make the buffer at least NSS_BUFLEN_DOOR/2+user buffer size
 *	   This should account for any reasonable nss_pheader, keys
 *	   extended area etc.
 *	3) keep the prototype/debugging (private)NSS_BUFLEN option
 *	   to change any preconfigured value if needed(?)
 */

static size_t
_nsc_getdoorbsize(size_t min_size)
{
	if (!door_bsize) {
		lmutex_lock(&hints_lock);
		if (!door_bsize) {
			/* future work - get nscd hint & use hint size */
			door_bsize = ROUND_UP(door_bsize, NSS_BUFSIZ);
			if (door_bsize < NSS_BUFLEN_DOOR) {
				door_bsize = NSS_BUFLEN_DOOR;
			}
		}
		lmutex_unlock(&hints_lock);
	}
	if (min_size && door_bsize < (min_size + NSS_BUFLEN_DOOR/2)) {
		lmutex_lock(&hints_lock);
		if (door_bsize < (min_size + NSS_BUFLEN_DOOR/2)) {
			min_size += NSS_BUFLEN_DOOR;
			door_bsize = ROUND_UP(min_size, NSS_BUFSIZ);
		}
		lmutex_unlock(&hints_lock);
	}
	return (door_bsize);
}

static void
_nsc_freedbuf(void *arg)
{
	nss_XbyY_buf_t *tsdbuf = arg;

	if (tsdbuf != NULL && tsdbuf->buffer != NULL) {
		lfree(tsdbuf->buffer, (size_t)tsdbuf->buflen);
		tsdbuf->result = NULL;
		tsdbuf->buffer = NULL;
		tsdbuf->buflen = 0;
	}
}

/*
 * _nsc_getdoorbuf - return the client side per thread door buffer
 * Elsewhere, it is assumed that the header is 0'd upon return from here.
 */

int
_nsc_getdoorbuf(void **doorptr, size_t *bufsize)
{
	nss_XbyY_buf_t *tsdbuf;
	char *bp;
	size_t dsize;

	if (doorptr == NULL || bufsize == NULL)
		return (-1);

	/* Get thread specific pointer to door buffer */
	tsdbuf = tsdalloc(_T_DOORBUF, sizeof (nss_XbyY_buf_t), _nsc_freedbuf);
	if (tsdbuf == NULL)
		return (-1);

	/* if door buffer does not exist create it */
	if (tsdbuf->buffer == NULL) {
		dsize = _nsc_getdoorbsize(*bufsize);

		/* setup a door buffer with a total length of dsize */
		bp = lmalloc(dsize);
		if (bp == NULL)
			return (-1);
		tsdbuf->buffer = bp;
		tsdbuf->buflen = dsize;
	} else {
		/* check old buffer size and resize if needed */
		if (*bufsize) {
			dsize = _nsc_getdoorbsize(*bufsize);
			if (tsdbuf->buflen < dsize) {
				lfree(tsdbuf->buffer, (size_t)tsdbuf->buflen);
				bp = lmalloc(dsize);
				if (bp == NULL)
					return (-1);
				tsdbuf->buffer = bp;
				tsdbuf->buflen = dsize;
			}
		}
		/* freshly malloc'd door bufs are 0'd */
		/* 0 header for now.  Zero entire buf(?) TDB */
		(void) memset((void *)tsdbuf->buffer, 0,
		    (size_t)sizeof (nss_pheader_t));

	}
	*doorptr = (void *)tsdbuf->buffer;
	*bufsize = tsdbuf->buflen;
	return (0);
}

void
_nsc_resizedoorbuf(size_t bsize)
{
	/* signal to update if new door size is desired */
	lmutex_lock(&hints_lock);
	if (bsize > door_bsize && door_nbsize < bsize)
		door_nbsize = bsize;
	lmutex_unlock(&hints_lock);
}

/*
 * Check uid and /proc/PID/psinfo to see if this process is nscd
 * If it is set the appropriate flags and allow policy reconfiguration.
 */
int
_nsc_proc_is_cache()
{
	psinfo_t	pinfo;
	char		fname[128];
	int		ret;
	int		fd;

	if (proc_is_cache >= 0)
		return (proc_is_cache);
	lmutex_lock(&hints_lock);
	if (proc_is_cache >= 0) {
		lmutex_unlock(&hints_lock);
		return (proc_is_cache);
	}
	proc_is_cache = 0;
	/* It can't be nscd if it's not running as root... */
	if (getuid() != 0) {
		lmutex_unlock(&hints_lock);
		return (0);
	}
	ret = snprintf(fname, 128, "/proc/%d/psinfo", getpid());
	if (ret > 0 && ret < 128) {
		if ((fd = open(fname,  O_RDONLY)) >= 0) {
			ret = read(fd, &pinfo, sizeof (psinfo_t));
			(void) close(fd);
			if (ret == sizeof (psinfo_t) &&
			    (strcmp(pinfo.pr_fname, "nscd") == 0)) {
				/* process runs as root and is named nscd */
				/* that's good enough for now */
				proc_is_cache = 1;
			}
		}
	}
	lmutex_unlock(&hints_lock);
	return (proc_is_cache);
}
