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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/sysmacros.h>
#include <sys/resource.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sched.h>
#include <stropts.h>
#include <poll.h>

#include <rsmapi.h>
#include <sys/rsm/rsmndi.h>
#include <rsmlib_in.h>
#include <sys/rsm/rsm.h>

/* lint -w2 */
extern void __rsmloopback_init_ops(rsm_segops_t *);
extern void __rsmdefault_setops(rsm_segops_t *);

typedef void (*rsm_access_func_t)(void *, void *, rsm_access_size_t);

#ifdef DEBUG

#define	RSMLOG_BUF_SIZE 256
FILE *rsmlog_fd = NULL;
static mutex_t rsmlog_lock;
int rsmlibdbg_category = RSM_LIBRARY;
int rsmlibdbg_level = RSM_ERR;
void dbg_printf(int category, int level, char *fmt, ...);

#endif /* DEBUG */

rsm_node_id_t rsm_local_nodeid = 0;

static rsm_controller_t *controller_list = NULL;

static rsm_segops_t loopback_ops;

#define	MAX_STRLEN	80

#define	RSM_IOTYPE_PUTGET	1
#define	RSM_IOTYPE_SCATGATH	2

#define	RSMFILE_BUFSIZE		256

#pragma init(_rsm_librsm_init)

static mutex_t _rsm_lock;

static int _rsm_fd = -1;
static rsm_gnum_t *bar_va, bar_fixed = 0;
static rsm_pollfd_table_t pollfd_table;

static int _rsm_get_hwaddr(rsmapi_controller_handle_t handle,
rsm_node_id_t, rsm_addr_t *hwaddrp);
static int _rsm_get_nodeid(rsmapi_controller_handle_t,
rsm_addr_t, rsm_node_id_t *);
static int __rsm_import_implicit_map(rsmseg_handle_t *, int);
static int __rsm_intr_signal_wait_common(struct pollfd [], minor_t [],
    nfds_t, int, int *);

static	rsm_lib_funcs_t lib_functions = {
	RSM_LIB_FUNCS_VERSION,
	_rsm_get_hwaddr,
	_rsm_get_nodeid
};

rsm_topology_t *tp;


/*
 * service module function templates:
 */

/*
 * The _rsm_librsm_init function is called the first time an application
 * references the RSMAPI library
 */
int
_rsm_librsm_init()
{
	rsm_ioctlmsg_t 		msg;
	int e, tmpfd;
	int i;
	char logname[MAXNAMELEN];

	mutex_init(&_rsm_lock, USYNC_THREAD, NULL);

#ifdef DEBUG
	mutex_init(&rsmlog_lock, USYNC_THREAD, NULL);
	sprintf(logname, "%s.%d", TRACELOG, getpid());
	rsmlog_fd = fopen(logname, "w+F");
	if (rsmlog_fd == NULL) {
		fprintf(stderr, "Log file open failed\n");
		return (errno);
	}

#endif /* DEBUG */

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "_rsm_librsm_init: enter\n"));

	/* initialize the pollfd_table */
	mutex_init(&pollfd_table.lock, USYNC_THREAD, NULL);

	for (i = 0; i < RSM_MAX_BUCKETS; i++) {
		pollfd_table.buckets[i] = NULL;
	}

	/* open /dev/rsm and mmap barrier generation pages */
	mutex_lock(&_rsm_lock);
	_rsm_fd = open(DEVRSM, O_RDONLY);
	if (_rsm_fd < 0) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "unable to open /dev/rsm\n"));
		mutex_unlock(&_rsm_lock);
		return (errno);
	}

	/*
	 * DUP the opened file descriptor to something greater than
	 * STDERR_FILENO so that we never use the STDIN_FILENO,
	 * STDOUT_FILENO or STDERR_FILENO.
	 */
	tmpfd = fcntl(_rsm_fd, F_DUPFD, 3);
	if (tmpfd < 0) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "F_DUPFD failed\n"));
	} else {
		(void) close(_rsm_fd);
		_rsm_fd = tmpfd;
	}

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "_rsm_fd is %d\n", _rsm_fd));

	if (fcntl(_rsm_fd, F_SETFD, FD_CLOEXEC) < 0) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		"F_SETFD failed\n"));
	}

	/* get mapping generation number page info */
	if (ioctl(_rsm_fd, RSM_IOCTL_BAR_INFO, &msg) < 0) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "RSM_IOCTL_BAR_INFO failed\n"));
		mutex_unlock(&_rsm_lock);
		return (errno);
	}

	/*
	 * bar_va is mapped to the mapping generation number page
	 * in order to support close barrier
	 */
	/* LINTED */
	bar_va = (rsm_gnum_t *)mmap(NULL, msg.len,
	    PROT_READ, MAP_SHARED, _rsm_fd, msg.off);
	if (bar_va == (rsm_gnum_t *)MAP_FAILED) {
		bar_va = NULL;
		mutex_unlock(&_rsm_lock);
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "unable to map barrier page\n"));
		return (RSMERR_MAP_FAILED);
	}

	mutex_unlock(&_rsm_lock);

	/* get local nodeid */
	e = rsm_get_interconnect_topology(&tp);
	if (e != RSM_SUCCESS) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "unable to obtain topology data\n"));
		return (e);
	} else
		rsm_local_nodeid = tp->topology_hdr.local_nodeid;

	rsm_free_interconnect_topology(tp);

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "_rsm_librsm_init: exit\n"));

	return (RSM_SUCCESS);
}

static int
_rsm_loopbackload(caddr_t name, int unit, rsm_controller_t **chdl)
{
	rsm_controller_t *p;
	rsm_ioctlmsg_t msg;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "_rsm_loopbackload: enter\n"));
	/*
	 * For now do this, but we should open some file and read the
	 * list of supported controllers and there numbers.
	 */

	p = (rsm_controller_t *)malloc(sizeof (*p) + strlen(name) + 1);
	if (!p) {
		DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_ERR,
		    "not enough memory\n"));
		return (RSMERR_INSUFFICIENT_MEM);
	}

	msg.cname = name;
	msg.cname_len = strlen(name) +1;
	msg.cnum = unit;
	msg.arg = (caddr_t)&p->cntr_attr;
	if (ioctl(_rsm_fd, RSM_IOCTL_ATTR, &msg) < 0) {
		int error = errno;
		free((void *)p);
		DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_ERR,
		    "RSM_IOCTL_ATTR failed\n"));
		return (error);
	}

	__rsmloopback_init_ops(&loopback_ops);
	__rsmdefault_setops(&loopback_ops);
	p->cntr_segops = &loopback_ops;

	/*
	 * Should add this entry into list
	 */
	p->cntr_fd = _rsm_fd;
	p->cntr_name = strcpy((char *)(p+1), name);
	p->cntr_unit = unit;
	p->cntr_refcnt = 1;


	mutex_init(&p->cntr_lock, USYNC_THREAD, NULL);
	cond_init(&p->cntr_cv, USYNC_THREAD, NULL);
	p->cntr_rqlist = NULL;
	p->cntr_segops->rsm_get_lib_attr(&p->cntr_lib_attr);
	p->cntr_next = controller_list;
	controller_list = p;

	*chdl = p;

	DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_DEBUG_VERBOSE,
	    "_rsm_loopbackload: exit\n"));
	return (RSM_SUCCESS);

}

static int
_rsm_modload(caddr_t name, int unit, rsmapi_controller_handle_t *controller)
{
	int error = RSM_SUCCESS;
	char clib[MAX_STRLEN];
	rsm_controller_t *p = NULL;
	void *dlh;
	rsm_attach_entry_t fptr;
	rsm_ioctlmsg_t msg;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "_rsm_modload: enter\n"));

	(void) sprintf(clib, "%s.so", name);

	/* found entry, try to load library */
	dlh = dlopen(clib, RTLD_LAZY);
	if (dlh == NULL) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "unable to find plugin library\n"));
		error = RSMERR_CTLR_NOT_PRESENT;
		goto skiplib;
	}

	(void) sprintf(clib, "%s_opendevice", name);

	fptr = (rsm_attach_entry_t)dlsym(dlh, clib); /* lint !e611 */
	if (fptr != NULL) {
		/* allocate new lib structure */
		/* get ops handler, attr and ops */
		p = (rsm_controller_t *)malloc(sizeof (*p) + strlen(name) + 1);
		if (p != NULL) {
			error = fptr(unit, &p->cntr_segops);
		} else {
			error = RSMERR_INSUFFICIENT_MEM;
			DBPRINTF((RSM_LIBRARY, RSM_ERR,
			    "not enough memory\n"));
		}
	} else {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "can't find symbol %s\n", clib));
		error = RSMERR_CTLR_NOT_PRESENT;
		(void) dlclose(dlh);
	}

skiplib:
	if ((error != RSM_SUCCESS) || (p == NULL)) {
		if (p != NULL)
			free((void *)p);
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "_rsm_modload error %d\n", error));
		return (error);
	}

	/* check the version number */
	if (p->cntr_segops->rsm_version != RSM_LIB_VERSION) {
		/* bad version number */
		DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
		    "wrong version; "
		    "found %d, expected %d\n",
		    p->cntr_segops->rsm_version, RSM_LIB_VERSION));
		free(p);
		return (RSMERR_BAD_LIBRARY_VERSION);
	} else {
		/* pass the fuctions to NDI library */
		if ((p->cntr_segops->rsm_register_lib_funcs == NULL) ||
		    (p->cntr_segops->rsm_register_lib_funcs(
		    &lib_functions) != RSM_SUCCESS)) {
			DBPRINTF((RSM_LIBRARY, RSM_ERR,
			    "RSMNDI library not registering lib functions\n"));
		}

		/* get controller attributes */
		msg.cnum = unit;
		msg.cname = name;
		msg.cname_len = strlen(name) +1;
		msg.arg = (caddr_t)&p->cntr_attr;
		if (ioctl(_rsm_fd, RSM_IOCTL_ATTR, &msg) < 0) {
			error = errno;
			free((void *)p);
			DBPRINTF((RSM_LIBRARY, RSM_ERR,
			    "RSM_IOCTL_ATTR failed\n"));
			return (error);
		}

		/* set controller access functions */
		__rsmdefault_setops(p->cntr_segops);

		mutex_init(&p->cntr_lock, USYNC_THREAD, NULL);
		cond_init(&p->cntr_cv, USYNC_THREAD, NULL);
		p->cntr_rqlist = NULL;
		p->cntr_segops->rsm_get_lib_attr(&p->cntr_lib_attr);
		/* insert into list of controllers */
		p->cntr_name = strcpy((char *)(p+1), name);
		p->cntr_fd = _rsm_fd;
		p->cntr_unit = unit;
		p->cntr_refcnt = 1;	/* first reference */
		p->cntr_next = controller_list;
		controller_list = p;
		*controller = (rsmapi_controller_handle_t)p;
		errno = RSM_SUCCESS;
	}

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "_rsm_modload: exit\n"));
	return (error);
}

/*
 * inserts a given segment handle into the pollfd table, this is called
 * when rsm_memseg_get_pollfd() is called the first time on a segment handle.
 * Returns RSM_SUCCESS if successful otherwise the error code is returned
 */
static int
_rsm_insert_pollfd_table(int segfd, minor_t segrnum)
{
	int i;
	int hash;
	rsm_pollfd_chunk_t *chunk;

	hash = RSM_POLLFD_HASH(segfd);

	mutex_lock(&pollfd_table.lock);

	chunk = pollfd_table.buckets[hash];
	while (chunk) {
		if (chunk->nfree > 0)
			break;
		chunk = chunk->next;
	}

	if (!chunk) { /* couldn't find a free chunk - allocate a new one */
		chunk = malloc(sizeof (rsm_pollfd_chunk_t));
		if (!chunk) {
			mutex_unlock(&pollfd_table.lock);
			return (RSMERR_INSUFFICIENT_MEM);
		}
		chunk->nfree = RSM_POLLFD_PER_CHUNK - 1;
		chunk->fdarray[0].fd = segfd;
		chunk->fdarray[0].segrnum = segrnum;
		for (i = 1; i < RSM_POLLFD_PER_CHUNK; i++) {
			chunk->fdarray[i].fd = -1;
			chunk->fdarray[i].segrnum = 0;
		}
		/* insert this into the hash table */
		chunk->next = pollfd_table.buckets[hash];
		pollfd_table.buckets[hash] = chunk;
		DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
		    "rsm_insert_pollfd: new chunk(%p) @ %d for %d:%d\n",
		    chunk, hash, segfd, segrnum));
	} else { /* a chunk with free slot was found */
		for (i = 0; i < RSM_POLLFD_PER_CHUNK; i++) {
			if (chunk->fdarray[i].fd == -1) {
				chunk->fdarray[i].fd = segfd;
				chunk->fdarray[i].segrnum = segrnum;
				chunk->nfree--;
				break;
			}
		}
		DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
		    "rsm_insert_pollfd: inserted @ %d for %d:%d chunk(%p)\n",
		    hash, segfd, segrnum, chunk));
		assert(i < RSM_POLLFD_PER_CHUNK);
	}

	mutex_unlock(&pollfd_table.lock);
	return (RSM_SUCCESS);
}

/*
 * Given a file descriptor returns the corresponding segment handles
 * resource number, if the fd is not found returns 0. 0 is not a valid
 * minor number for a rsmapi segment since it is used for the barrier
 * resource.
 */
static minor_t
_rsm_lookup_pollfd_table(int segfd)
{
	int i;
	rsm_pollfd_chunk_t	*chunk;

	if (segfd < 0)
		return (0);

	mutex_lock(&pollfd_table.lock);

	chunk = pollfd_table.buckets[RSM_POLLFD_HASH(segfd)];
	while (chunk) {
		assert(chunk->nfree < RSM_POLLFD_PER_CHUNK);

		for (i = 0; i < RSM_POLLFD_PER_CHUNK; i++) {
			if (chunk->fdarray[i].fd == segfd) {
				mutex_unlock(&pollfd_table.lock);
				DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
				    "rsm_lookup_pollfd: found(%d) rnum(%d)\n",
				    segfd, chunk->fdarray[i].segrnum));
				return (chunk->fdarray[i].segrnum);
			}
		}
		chunk = chunk->next;
	}

	mutex_unlock(&pollfd_table.lock);

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsm_lookup_pollfd: not found(%d)\n", segfd));

	return (0);
}

/*
 * Remove the entry corresponding to the given file descriptor from the
 * pollfd table.
 */
static void
_rsm_remove_pollfd_table(int segfd)
{
	int i;
	int hash;
	rsm_pollfd_chunk_t	*chunk;
	rsm_pollfd_chunk_t	*prev_chunk;

	if (segfd < 0)
		return;

	hash = RSM_POLLFD_HASH(segfd);

	mutex_lock(&pollfd_table.lock);

	prev_chunk = chunk = pollfd_table.buckets[hash];
	while (chunk) {
		assert(chunk->nfree < RSM_POLLFD_PER_CHUNK);

		for (i = 0; i < RSM_POLLFD_PER_CHUNK; i++) {
			if (chunk->fdarray[i].fd == segfd) {
				DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
				    "rsm_remove_pollfd: %d:%d\n",
				    chunk->fdarray[i].fd,
				    chunk->fdarray[i].segrnum));
				chunk->fdarray[i].fd = -1;
				chunk->fdarray[i].segrnum = 0;
				chunk->nfree++;
				if (chunk->nfree == RSM_POLLFD_PER_CHUNK) {
					/* chunk is empty free it */
					if (prev_chunk == chunk) {
						pollfd_table.buckets[hash] =
						    chunk->next;
					} else {
						prev_chunk->next = chunk->next;
					}
					DBPRINTF((RSM_LIBRARY,
					    RSM_DEBUG_VERBOSE,
					    "rsm_remove_pollfd:free(%p)\n",
					    chunk));
					free(chunk);
					mutex_unlock(&pollfd_table.lock);
					return;
				}
			}
		}
		prev_chunk = chunk;
		chunk = chunk->next;
	}

	mutex_unlock(&pollfd_table.lock);
}

int
rsm_get_controller(char *name, rsmapi_controller_handle_t *chdl)
{
	rsm_controller_t *p;
	char	cntr_name[MAXNAMELEN];	/* cntr_name=<cntr_type><unit> */
	char	*cntr_type;
	int	unit = 0;
	int	i, e;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsm_get_controller: enter\n"));
	/*
	 * Lookup controller name and return ops vector and controller
	 * structure
	 */

	if (!chdl) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "Invalid controller handle\n"));
		return (RSMERR_BAD_CTLR_HNDL);
	}
	if (!name) {
		/* use loopback if null */
		cntr_type = LOOPBACK;
	} else {
		(void) strcpy(cntr_name, name);
		/* scan from the end till a non-digit is found */
		for (i = strlen(cntr_name) - 1; i >= 0; i--) {
			if (! isdigit((int)cntr_name[i]))
				break;
		}
		i++;
		unit = atoi((char *)cntr_name+i);
		cntr_name[i] = '\0';	/* null terminate the cntr_type part */
		cntr_type = (char *)cntr_name;
		DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
		    "cntr_type=%s, instance=%d\n",
		    cntr_type, unit));
	}

	/* protect the controller_list by locking the device/library */
	mutex_lock(&_rsm_lock);

	for (p = controller_list; p; p = p->cntr_next) {
		if (!strcasecmp(p->cntr_name, cntr_type) &&
		    !strcasecmp(cntr_type, LOOPBACK)) {
			p->cntr_refcnt++;
			*chdl = (rsmapi_controller_handle_t)p;
			mutex_unlock(&_rsm_lock);
			DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
			    "rsm_get_controller: exit\n"));
			return (RSM_SUCCESS);
		} else if (!strcasecmp(p->cntr_name, cntr_type) &&
		    (p->cntr_unit == unit)) {
			p->cntr_refcnt++;
			*chdl = (rsmapi_controller_handle_t)p;
			mutex_unlock(&_rsm_lock);
			DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
			    "rsm_get_controller: exit\n"));
			return (RSM_SUCCESS);
		}
	}


	if (!strcasecmp(cntr_type, LOOPBACK)) {
		e = _rsm_loopbackload(cntr_type, unit,
		    (rsm_controller_t **)chdl);
	} else {
		e = _rsm_modload(cntr_type, unit, chdl);
	}

	mutex_unlock(&_rsm_lock);

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    " rsm_get_controller: exit\n"));
	return (e);
}

int
rsm_release_controller(rsmapi_controller_handle_t cntr_handle)
{
	int			e = RSM_SUCCESS;
	rsm_controller_t	*chdl = (rsm_controller_t *)cntr_handle;
	rsm_controller_t	*curr, *prev;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsm_release_controller: enter\n"));

	mutex_lock(&_rsm_lock);

	if (chdl->cntr_refcnt == 0) {
		mutex_unlock(&_rsm_lock);
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "controller reference count is zero\n"));
		return (RSMERR_BAD_CTLR_HNDL);
	}

	chdl->cntr_refcnt--;

	if (chdl->cntr_refcnt > 0) {
		mutex_unlock(&_rsm_lock);
		DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
		    "rsm_release_controller: exit\n"));
		return (RSM_SUCCESS);
	}

	e = chdl->cntr_segops->rsm_closedevice(cntr_handle);

	/*
	 * remove the controller in any case from the controller list
	 */

	prev = curr = controller_list;
	while (curr != NULL) {
		if (curr == chdl) {
			if (curr == prev) {
				controller_list = curr->cntr_next;
			} else {
				prev->cntr_next = curr->cntr_next;
			}
			free(curr);
			break;
		}
		prev = curr;
		curr = curr->cntr_next;
	}
	mutex_unlock(&_rsm_lock);

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsm_release_controller: exit\n"));

	return (e);
}

int
rsm_get_controller_attr(rsmapi_controller_handle_t chandle,
    rsmapi_controller_attr_t *attr)
{
	rsm_controller_t *p;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsm_get_controller_attr: enter\n"));

	if (!chandle) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid controller handle\n"));
		return (RSMERR_BAD_CTLR_HNDL);
	}

	if (!attr) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid attribute pointer\n"));
		return (RSMERR_BAD_ADDR);
	}

	p = (rsm_controller_t *)chandle;

	mutex_lock(&_rsm_lock);
	if (p->cntr_refcnt == 0) {
		mutex_unlock(&_rsm_lock);
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "cntr refcnt is 0\n"));
		return (RSMERR_CTLR_NOT_PRESENT);
	}

	/* copy only the user part of the attr structure */
	attr->attr_direct_access_sizes =
	    p->cntr_attr.attr_direct_access_sizes;
	attr->attr_atomic_sizes =
	    p->cntr_attr.attr_atomic_sizes;
	attr->attr_page_size =
	    p->cntr_attr.attr_page_size;
	attr->attr_max_export_segment_size =
	    p->cntr_attr.attr_max_export_segment_size;
	attr->attr_tot_export_segment_size =
	    p->cntr_attr.attr_tot_export_segment_size;
	attr->attr_max_export_segments =
	    p->cntr_attr.attr_max_export_segments;
	attr->attr_max_import_map_size =
	    p->cntr_attr.attr_max_import_map_size;
	attr->attr_tot_import_map_size =
	    p->cntr_attr.attr_tot_import_map_size;
	attr->attr_max_import_segments =
	    p->cntr_attr.attr_max_import_segments;

	mutex_unlock(&_rsm_lock);

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsm_get_controller_attr: exit\n"));

	return (RSM_SUCCESS);
}



/*
 * Create a segment handle for the virtual address range specified
 * by vaddr and size
 */
int
rsm_memseg_export_create(rsmapi_controller_handle_t controller,
    rsm_memseg_export_handle_t *memseg,
    void *vaddr,
    size_t length,
    uint_t flags)
{

	rsm_controller_t *chdl = (rsm_controller_t *)controller;
	rsmseg_handle_t *p;
	rsm_ioctlmsg_t msg;
	int e;
#ifndef	_LP64
	int tmpfd;
#endif

	DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_export_create: enter\n"));

	if (!controller) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid controller handle\n"));
		return (RSMERR_BAD_CTLR_HNDL);
	}
	if (!memseg) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid segment handle\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}

	*memseg = 0;

	/*
	 * Check vaddr and size alignment, both must be mmu page size
	 * aligned
	 */
	if (!vaddr) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid arguments\n"));
		return (RSMERR_BAD_ADDR);
	}

	if (!length) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid arguments\n"));
		return (RSMERR_BAD_LENGTH);
	}

	if (((size_t)vaddr & (PAGESIZE - 1)) ||
	    (length & (PAGESIZE - 1))) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid mem alignment for vaddr or length\n"));
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	/*
	 * The following check does not apply for loopback controller
	 * since for the loopback adapter, the attr_max_export_segment_size
	 * is always 0.
	 */
	if (strcasecmp(chdl->cntr_name, LOOPBACK)) {
		if (length > chdl->cntr_attr.attr_max_export_segment_size) {
			DBPRINTF((RSM_LIBRARY, RSM_ERR,
			    "length exceeds controller limits\n"));
			DBPRINTF((RSM_LIBRARY, RSM_ERR,
			    "controller limits %d\n",
			    chdl->cntr_attr.attr_max_export_segment_size));
			return (RSMERR_BAD_LENGTH);
		}
	}

	p = (rsmseg_handle_t *)malloc(sizeof (*p));
	if (p == NULL) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "not enough memory\n"));
		return (RSMERR_INSUFFICIENT_MEM);
	}

	p->rsmseg_fd = open(DEVRSM, O_RDWR);
	if (p->rsmseg_fd < 0) {
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "unable to open device /dev/rsm\n"));
		free((void *)p);
		return (RSMERR_INSUFFICIENT_RESOURCES);
	}

#ifndef	_LP64
	/*
	 * libc can't handle fd's greater than 255,  in order to
	 * insure that these values remain available make /dev/rsm
	 * fd > 255. Note: not needed for LP64
	 */
	tmpfd = fcntl(p->rsmseg_fd, F_DUPFD, 256);
	e = errno;
	if (tmpfd < 0) {
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "F_DUPFD failed\n"));
	} else {
		(void) close(p->rsmseg_fd);
		p->rsmseg_fd = tmpfd;
	}
#endif	/*	_LP64	*/

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE, ""
	    "rsmseg_fd is %d\n", p->rsmseg_fd));

	if (fcntl(p->rsmseg_fd, F_SETFD, FD_CLOEXEC) < 0) {
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "F_SETFD failed\n"));
	}

	p->rsmseg_state = EXPORT_CREATE;
	p->rsmseg_size = length;
	/* increment controller handle */
	p->rsmseg_controller = chdl;

	/* try to bind user address range */
	msg.cnum = chdl->cntr_unit;
	msg.cname = chdl->cntr_name;
	msg.cname_len = strlen(chdl->cntr_name) +1;
	msg.vaddr = vaddr;
	msg.len = length;
	msg.perm = flags;
	msg.off = 0;
	e = RSM_IOCTL_BIND;

	/* Try to bind */
	if (ioctl(p->rsmseg_fd, e, &msg) < 0) {
		e = errno;
		(void) close(p->rsmseg_fd);
		free((void *)p);
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "RSM_IOCTL_BIND failed\n"));
		return (e);
	}
	/* OK */
	p->rsmseg_type = RSM_EXPORT_SEG;
	p->rsmseg_vaddr = vaddr;
	p->rsmseg_size = length;
	p->rsmseg_state = EXPORT_BIND;
	p->rsmseg_pollfd_refcnt = 0;
	p->rsmseg_rnum = msg.rnum;

	mutex_init(&p->rsmseg_lock, USYNC_THREAD, NULL);

	*memseg = (rsm_memseg_export_handle_t)p;

	DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_export_create: exit\n"));

	return (RSM_SUCCESS);
}

int
rsm_memseg_export_destroy(rsm_memseg_export_handle_t memseg)
{
	rsmseg_handle_t *seg;

	DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_export_destroy: enter\n"));

	if (!memseg) {
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "invalid segment handle\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}

	seg = (rsmseg_handle_t *)memseg;

	mutex_lock(&seg->rsmseg_lock);
	if (seg->rsmseg_pollfd_refcnt) {
		mutex_unlock(&seg->rsmseg_lock);
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "segment reference count not zero\n"));
		return (RSMERR_POLLFD_IN_USE);
	}
	else
		seg->rsmseg_state = EXPORT_BIND;

	mutex_unlock(&seg->rsmseg_lock);

	(void) close(seg->rsmseg_fd);
	mutex_destroy(&seg->rsmseg_lock);
	free((void *)seg);

	DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_export_destroy: exit\n"));

	return (RSM_SUCCESS);
}

int
rsm_memseg_export_rebind(rsm_memseg_export_handle_t memseg, void *vaddr,
    offset_t off, size_t length)
{
	rsm_ioctlmsg_t msg;
	rsmseg_handle_t *seg = (rsmseg_handle_t *)memseg;

	DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_export_rebind: enter\n"));

	off = off;

	if (!seg) {
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "invalid segment handle\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}
	if (!vaddr) {
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "invalid vaddr\n"));
		return (RSMERR_BAD_ADDR);
	}

	/*
	 * Same as bind except it's ok to have elimint in list.
	 * Call into driver to remove any existing mappings.
	 */
	msg.vaddr = vaddr;
	msg.len = length;
	msg.off = 0;

	mutex_lock(&seg->rsmseg_lock);
	if (ioctl(seg->rsmseg_fd, RSM_IOCTL_REBIND, &msg) < 0) {
		mutex_unlock(&seg->rsmseg_lock);
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "RSM_IOCTL_REBIND failed\n"));
		return (errno);
	}

	mutex_unlock(&seg->rsmseg_lock);

	DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_export_rebind: exit\n"));

	return (RSM_SUCCESS);
}

int
rsm_memseg_export_publish(rsm_memseg_export_handle_t memseg,
    rsm_memseg_id_t *seg_id,
    rsmapi_access_entry_t access_list[],
    uint_t access_list_length)

{
	rsm_ioctlmsg_t msg;
	rsmseg_handle_t *seg = (rsmseg_handle_t *)memseg;

	DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_export_publish: enter\n"));

	if (seg_id == NULL) {
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "invalid segment id\n"));
		return (RSMERR_BAD_SEGID);
	}

	if (!seg) {
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "invalid segment handle\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}

	if (access_list_length > 0 && !access_list) {
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "invalid access control list\n"));
		return (RSMERR_BAD_ACL);
	}

	mutex_lock(&seg->rsmseg_lock);
	if (seg->rsmseg_state != EXPORT_BIND) {
		mutex_unlock(&seg->rsmseg_lock);
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "invalid segment state\n"));
		return (RSMERR_SEG_ALREADY_PUBLISHED);
	}

	/*
	 * seg id < RSM_DLPI_END and in the RSM_USER_APP_ID range
	 * are reserved for internal use.
	 */
	if ((*seg_id > 0) &&
	    ((*seg_id <= RSM_DLPI_ID_END) ||
	    BETWEEN (*seg_id, RSM_USER_APP_ID_BASE, RSM_USER_APP_ID_END))) {
		mutex_unlock(&seg->rsmseg_lock);
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "invalid segment id\n"));
		return (RSMERR_RESERVED_SEGID);
	}

	msg.key = *seg_id;
	msg.acl = access_list;
	msg.acl_len = access_list_length;

	if (ioctl(seg->rsmseg_fd, RSM_IOCTL_PUBLISH, &msg) < 0) {
		mutex_unlock(&seg->rsmseg_lock);
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "RSM_IOCTL_PUBLISH failed\n"));
		return (errno);
	}

	seg->rsmseg_keyid = msg.key;
	seg->rsmseg_state = EXPORT_PUBLISH;
	mutex_unlock(&seg->rsmseg_lock);

	if (*seg_id == 0)
		*seg_id = msg.key;

	DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_export_publish: exit\n"));

	return (RSM_SUCCESS);

}

int
rsm_memseg_export_unpublish(rsm_memseg_export_handle_t memseg)
{
	rsm_ioctlmsg_t msg;
	rsmseg_handle_t *seg = (rsmseg_handle_t *)memseg;

	DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_export_unpublish: enter\n"));

	if (!seg) {
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "invalid arguments\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}

	mutex_lock(&seg->rsmseg_lock);
	if (seg->rsmseg_state != EXPORT_PUBLISH) {
		mutex_unlock(&seg->rsmseg_lock);
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "segment not published %d\n",
		    seg->rsmseg_keyid));
		return (RSMERR_SEG_NOT_PUBLISHED);
	}

	msg.key = seg->rsmseg_keyid;
	if (ioctl(seg->rsmseg_fd, RSM_IOCTL_UNPUBLISH, &msg) < 0) {
		mutex_unlock(&seg->rsmseg_lock);
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "RSM_IOCTL_UNPUBLISH failed\n"));
		return (errno);
	}

	seg->rsmseg_state = EXPORT_BIND;
	mutex_unlock(&seg->rsmseg_lock);

	DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_export_unpublish: exit\n"));

	return (RSM_SUCCESS);
}


int
rsm_memseg_export_republish(rsm_memseg_export_handle_t memseg,
    rsmapi_access_entry_t access_list[],
    uint_t access_list_length)
{
	rsm_ioctlmsg_t msg;
	rsmseg_handle_t *seg = (rsmseg_handle_t *)memseg;

	DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_export_republish: enter\n"));

	if (!seg) {
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "invalid segment or segment state\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}

	mutex_lock(&seg->rsmseg_lock);
	if (seg->rsmseg_state != EXPORT_PUBLISH) {
		mutex_unlock(&seg->rsmseg_lock);
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "segment not published\n"));
		return (RSMERR_SEG_NOT_PUBLISHED);
	}

	if (access_list_length > 0 && !access_list) {
		mutex_unlock(&seg->rsmseg_lock);
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "invalid access control list\n"));
		return (RSMERR_BAD_ACL);
	}

	msg.key = seg->rsmseg_keyid;
	msg.acl = access_list;
	msg.acl_len = access_list_length;

	if (ioctl(seg->rsmseg_fd, RSM_IOCTL_REPUBLISH, &msg) < 0) {
		mutex_unlock(&seg->rsmseg_lock);
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "RSM_IOCTL_REPUBLISH failed\n"));
		return (errno);
	}
	mutex_unlock(&seg->rsmseg_lock);

	DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_export_republish: exit\n"));

	return (RSM_SUCCESS);
}


	/*
	 * import side memory segment operations:
	 */
int
rsm_memseg_import_connect(rsmapi_controller_handle_t controller,
    rsm_node_id_t node_id,
    rsm_memseg_id_t segment_id,
    rsm_permission_t perm,
    rsm_memseg_import_handle_t *im_memseg)
{
	rsm_ioctlmsg_t msg;
	rsmseg_handle_t *p;
	rsm_controller_t *cntr = (rsm_controller_t *)controller;
#ifndef	_LP64		/* added for fd > 255 fix */
	int tmpfd;
#endif
	int e;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_connect: enter\n"));

	if (!cntr) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid controller handle\n"));
		return (RSMERR_BAD_CTLR_HNDL);
	}

	*im_memseg = 0;

	p = (rsmseg_handle_t *)malloc(sizeof (*p));
	if (!p) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "not enough memory\n"));
		return (RSMERR_INSUFFICIENT_MEM);
	}

	if (perm & ~RSM_PERM_RDWR) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid permissions\n"));
		return (RSMERR_PERM_DENIED);
	}

	/*
	 * Get size, va from driver
	 */
	msg.cnum = cntr->cntr_unit;
	msg.cname = cntr->cntr_name;
	msg.cname_len = strlen(cntr->cntr_name) +1;
	msg.nodeid = node_id;
	msg.key = segment_id;
	msg.perm = perm;

	p->rsmseg_fd = open(DEVRSM, O_RDWR);
	if (p->rsmseg_fd < 0) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "unable to open /dev/rsm"));
		free((void *)p);
		return (RSMERR_INSUFFICIENT_RESOURCES);
	}

#ifndef	_LP64
	/*
	 * libc can't handle fd's greater than 255,  in order to
	 * insure that these values remain available make /dev/rsm
	 * fd > 255. Note: not needed for LP64
	 */
	tmpfd = fcntl(p->rsmseg_fd, F_DUPFD, 256); /* make fd > 255 */
	e = errno;
	if (tmpfd < 0) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "F_DUPFD failed\n"));
	} else {
		(void) close(p->rsmseg_fd);
		p->rsmseg_fd = tmpfd;
	}
#endif	/* _LP64 */

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsmseg_fd is %d\n", p->rsmseg_fd));

	if (fcntl(p->rsmseg_fd, F_SETFD, FD_CLOEXEC) < 0) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "F_SETFD failed\n"));
	}
	if (ioctl(p->rsmseg_fd, RSM_IOCTL_CONNECT, &msg) < 0) {
		e = errno;
		(void) close(p->rsmseg_fd);
		free((void *)p);
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "RSM_IOCTL_CONNECT failed\n"));
		return (e);
	}

	/*
	 * We connected ok.
	 */
	p->rsmseg_type = RSM_IMPORT_SEG;
	p->rsmseg_state = IMPORT_CONNECT;
	p->rsmseg_keyid = segment_id;
	p->rsmseg_nodeid = node_id;
	p->rsmseg_size = msg.len;
	p->rsmseg_perm = perm;
	p->rsmseg_controller = cntr;
	p->rsmseg_barrier = NULL;
	p->rsmseg_barmode = RSM_BARRIER_MODE_IMPLICIT;
	p->rsmseg_bar = (bar_va ? bar_va + msg.off : &bar_fixed);
	p->rsmseg_gnum = msg.gnum;
	p->rsmseg_pollfd_refcnt = 0;
	p->rsmseg_maplen = 0;    /* initialized, set in import_map */
	p->rsmseg_mapoffset = 0;
	p->rsmseg_flags = 0;
	p->rsmseg_rnum = msg.rnum;
	mutex_init(&p->rsmseg_lock, USYNC_THREAD, NULL);

	p->rsmseg_ops = cntr->cntr_segops;

	/*
	 * XXX: Based on permission and controller direct_access attribute
	 * we fix the segment ops vector
	 */

	p->rsmseg_vaddr = 0; /* defer mapping till using maps or trys to rw */

	*im_memseg = (rsm_memseg_import_handle_t)p;

	e =  p->rsmseg_ops->rsm_memseg_import_connect(controller,
	    node_id, segment_id, perm, im_memseg);

	if (e != RSM_SUCCESS) {
		(void) close(p->rsmseg_fd);
		mutex_destroy(&p->rsmseg_lock);
		free((void *)p);
	}

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_connect: exit\n"));

	return (e);
}


int
rsm_memseg_import_disconnect(rsm_memseg_import_handle_t im_memseg)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	int e;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_disconnect: enter\n"));

	if (!seg) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid segment handle\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}

	if (seg->rsmseg_state != IMPORT_CONNECT) {
		if (seg->rsmseg_flags & RSM_IMPLICIT_MAP) {
			e = rsm_memseg_import_unmap(im_memseg);
			if (e != RSM_SUCCESS) {
				DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
				    "unmap failure\n"));
				return (e);
			}
		} else {
			DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
			    "segment busy\n"));
			return (RSMERR_SEG_STILL_MAPPED);
		}
	}

	mutex_lock(&seg->rsmseg_lock);
	if (seg->rsmseg_pollfd_refcnt) {
		mutex_unlock(&seg->rsmseg_lock);
		DBPRINTF((RSM_LIBRARY|RSM_EXPORT, RSM_ERR,
		    "segment reference count not zero\n"));
		return (RSMERR_POLLFD_IN_USE);
	}
	mutex_unlock(&seg->rsmseg_lock);

	e =  seg->rsmseg_ops->rsm_memseg_import_disconnect(im_memseg);

	if (e == RSM_SUCCESS) {
		(void) close(seg->rsmseg_fd);
		mutex_destroy(&seg->rsmseg_lock);
		free((void *)seg);
	}

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_disconnect: exit\n"));

	return (e);
}

/*
 * import side memory segment operations (read access functions):
 */

static int
__rsm_import_verify_access(rsmseg_handle_t *seg,
    off_t offset,
    caddr_t datap,
    size_t len,
    rsm_permission_t perm,
    rsm_access_size_t das)
{
	int	error;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    " __rsm_import_verify_access: enter\n"));

	if (!seg) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid segment handle\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}
	if (!datap) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid data pointer\n"));
		return (RSMERR_BAD_ADDR);
	}

	/*
	 * Check alignment of pointer
	 */
	if ((uintptr_t)datap & (das - 1)) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid alignment of data pointer\n"));
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	if (offset & (das - 1)) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid offset\n"));
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	/* make sure that the import seg is connected */
	if (seg->rsmseg_state != IMPORT_CONNECT &&
	    seg->rsmseg_state != IMPORT_MAP) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "incorrect segment state\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}

	/* do an implicit map if required */
	if (seg->rsmseg_state == IMPORT_CONNECT) {
		error = __rsm_import_implicit_map(seg, RSM_IOTYPE_PUTGET);
		if (error != RSM_SUCCESS) {
			DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
			    "implicit map failure\n"));
			return (error);
		}
	}

	if ((seg->rsmseg_perm & perm) != perm) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid permissions\n"));
		return (RSMERR_PERM_DENIED);
	}

	if (seg->rsmseg_state == IMPORT_MAP) {
		if ((offset < seg->rsmseg_mapoffset) ||
		    (offset + len > seg->rsmseg_mapoffset +
		    seg->rsmseg_maplen)) {
			DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
			    "incorrect offset+length\n"));
			return (RSMERR_BAD_OFFSET);
		}
	} else { /* IMPORT_CONNECT */
		if ((len + offset) > seg->rsmseg_size) {
			DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
			    "incorrect offset+length\n"));
			return (RSMERR_BAD_LENGTH);
		}
	}

	if ((seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) &&
	    (seg->rsmseg_barrier == NULL)) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid barrier\n"));
		return (RSMERR_BARRIER_UNINITIALIZED);
	}

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    " __rsm_import_verify_access: exit\n"));

	return (RSM_SUCCESS);
}

static int
__rsm_import_implicit_map(rsmseg_handle_t *seg, int iotype)
{
	caddr_t va;
	int flag = MAP_SHARED;
	int prot = PROT_READ|PROT_WRITE;
	int mapping_reqd = 0;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    " __rsm_import_implicit_map: enter\n"));

	if (iotype == RSM_IOTYPE_PUTGET)
		mapping_reqd = seg->rsmseg_controller->cntr_lib_attr->
		    rsm_putget_map_reqd;
	else if (iotype == RSM_IOTYPE_SCATGATH)
		mapping_reqd = seg->rsmseg_controller->cntr_lib_attr->
		    rsm_scatgath_map_reqd;


	if (mapping_reqd) {
		va = mmap(NULL, seg->rsmseg_size, prot,
		    flag, seg->rsmseg_fd, 0);

		if (va == MAP_FAILED) {
			DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
			    "implicit map failed\n"));
			if (errno == ENOMEM || errno == ENXIO ||
			    errno == EOVERFLOW)
				return (RSMERR_BAD_LENGTH);
			else if (errno == ENODEV)
				return (RSMERR_CONN_ABORTED);
			else if (errno == EAGAIN)
				return (RSMERR_INSUFFICIENT_RESOURCES);
			else if (errno == ENOTSUP)
				return (RSMERR_MAP_FAILED);
			else if (errno == EACCES)
				return (RSMERR_BAD_PERMS);
			else
				return (RSMERR_MAP_FAILED);
		}
		seg->rsmseg_vaddr = va;
		seg->rsmseg_maplen = seg->rsmseg_size;
		seg->rsmseg_mapoffset = 0;
		seg->rsmseg_state = IMPORT_MAP;
		seg->rsmseg_flags |= RSM_IMPLICIT_MAP;
	}

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    " __rsm_import_implicit_map: exit\n"));

	return (RSM_SUCCESS);
}

int
rsm_memseg_import_get8(rsm_memseg_import_handle_t im_memseg,
    off_t offset,
    uint8_t *datap,
    ulong_t rep_cnt)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	int e;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_get8: enter\n"));

	e = __rsm_import_verify_access(seg, offset, (caddr_t)datap, rep_cnt,
	    RSM_PERM_READ,
	    RSM_DAS8);
	if (e == RSM_SUCCESS) {
		rsm_segops_t *ops = seg->rsmseg_ops;
		rsmbar_handle_t *bar = (rsmbar_handle_t *)seg->rsmseg_barrier;

		if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
			/* generation number snapshot */
			bar->rsmbar_gen = bar->rsmbar_seg->rsmseg_gnum;
		}

		e = ops->rsm_memseg_import_get8(im_memseg, offset, datap,
		    rep_cnt, 0);

		if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
			/* check the generation number for force disconnects */
			if (bar->rsmbar_gen != bar->rsmbar_seg->rsmseg_bar[0]) {
				return (RSMERR_CONN_ABORTED);
			}
		}
	}

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_get8: exit\n"));

	return (e);
}

int
rsm_memseg_import_get16(rsm_memseg_import_handle_t im_memseg,
    off_t offset,
    uint16_t *datap,
    ulong_t rep_cnt)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	int e;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_get16: enter\n"));

	e = __rsm_import_verify_access(seg, offset, (caddr_t)datap, rep_cnt*2,
	    RSM_PERM_READ,
	    RSM_DAS16);
	if (e == RSM_SUCCESS) {
		rsm_segops_t *ops = seg->rsmseg_ops;
		rsmbar_handle_t *bar = (rsmbar_handle_t *)seg->rsmseg_barrier;

		if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
			/* generation number snapshot */
			bar->rsmbar_gen = bar->rsmbar_seg->rsmseg_gnum;
		}

		e = ops->rsm_memseg_import_get16(im_memseg, offset, datap,
		    rep_cnt, 0);

		if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
			/* check the generation number for force disconnects */
			if (bar->rsmbar_gen != bar->rsmbar_seg->rsmseg_bar[0]) {
				return (RSMERR_CONN_ABORTED);
			}
		}

	}

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_get16: exit\n"));

	return (e);
}

int
rsm_memseg_import_get32(rsm_memseg_import_handle_t im_memseg,
    off_t offset,
    uint32_t *datap,
    ulong_t rep_cnt)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	int e;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_get32: enter\n"));

	e = __rsm_import_verify_access(seg, offset, (caddr_t)datap, rep_cnt*4,
	    RSM_PERM_READ,
	    RSM_DAS32);
	if (e == RSM_SUCCESS) {
		rsm_segops_t *ops = seg->rsmseg_ops;
		rsmbar_handle_t *bar = (rsmbar_handle_t *)seg->rsmseg_barrier;

		if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
			/* generation number snapshot */
			bar->rsmbar_gen = bar->rsmbar_seg->rsmseg_gnum;
		}

		e = ops->rsm_memseg_import_get32(im_memseg, offset, datap,
		    rep_cnt, 0);

		if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
			/* check the generation number for force disconnects */
			if (bar->rsmbar_gen != bar->rsmbar_seg->rsmseg_bar[0]) {
				return (RSMERR_CONN_ABORTED);
			}
		}
	}

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_get32: exit\n"));

	return (e);
}

int
rsm_memseg_import_get64(rsm_memseg_import_handle_t im_memseg,
    off_t offset,
    uint64_t *datap,
    ulong_t rep_cnt)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	int e;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_get64: enter\n"));

	e = __rsm_import_verify_access(seg, offset, (caddr_t)datap, rep_cnt*8,
	    RSM_PERM_READ,
	    RSM_DAS64);
	if (e == RSM_SUCCESS) {
		rsm_segops_t *ops = seg->rsmseg_ops;
		rsmbar_handle_t *bar = (rsmbar_handle_t *)seg->rsmseg_barrier;

		if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
			/* generation number snapshot */
			bar->rsmbar_gen = bar->rsmbar_seg->rsmseg_gnum;
		}

		e = ops->rsm_memseg_import_get64(im_memseg, offset, datap,
		    rep_cnt, 0);

		if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
			/* check the generation number for force disconnects */
			if (bar->rsmbar_gen != bar->rsmbar_seg->rsmseg_bar[0]) {
				return (RSMERR_CONN_ABORTED);
			}
		}
	}

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_get64: exit\n"));

	return (e);
}

int
rsm_memseg_import_get(rsm_memseg_import_handle_t im_memseg,
    off_t offset,
    void *dst_addr,
    size_t length)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	int e;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_get: enter\n"));

	e = __rsm_import_verify_access(seg, offset, (caddr_t)dst_addr, length,
	    RSM_PERM_READ,
	    RSM_DAS8);
	if (e == RSM_SUCCESS) {
		rsm_segops_t *ops = seg->rsmseg_ops;
		rsmbar_handle_t *bar = (rsmbar_handle_t *)seg->rsmseg_barrier;

		if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
			/* generation number snapshot */
			bar->rsmbar_gen = bar->rsmbar_seg->rsmseg_gnum;
		}

		e = ops->rsm_memseg_import_get(im_memseg, offset, dst_addr,
		    length);

		if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
			/* check the generation number for force disconnects */
			if (bar->rsmbar_gen != bar->rsmbar_seg->rsmseg_bar[0]) {
				return (RSMERR_CONN_ABORTED);
			}
		}
	}

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_get: exit\n"));

	return (e);
}


int
rsm_memseg_import_getv(rsm_scat_gath_t *sg_io)
{
	rsm_controller_t *cntrl;
	rsmseg_handle_t *seg;
	uint_t save_sg_io_flags;

	int e;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_getv: enter\n"));

	if (sg_io == NULL) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid sg_io structure\n"));
		return (RSMERR_BAD_SGIO);
	}

	seg = (rsmseg_handle_t *)sg_io->remote_handle;
	if (seg == NULL) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid remote segment handle in sg_io\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}

	cntrl = (rsm_controller_t *)seg->rsmseg_controller;
	if (cntrl == NULL) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid controller handle\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}

	if ((sg_io->io_request_count > RSM_MAX_SGIOREQS) ||
	    (sg_io->io_request_count == 0)) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "io_request_count value incorrect\n"));
		return (RSMERR_BAD_SGIO);
	}

	if (seg->rsmseg_state == IMPORT_CONNECT) {
		e = __rsm_import_implicit_map(seg, RSM_IOTYPE_SCATGATH);
		if (e != RSM_SUCCESS) {
			DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
			    "implicit map failure\n"));
			return (e);
		}
	}

	/*
	 * Copy the flags field of the sg_io structure in a local
	 * variable.
	 * This is required since the flags field can be
	 * changed by the plugin library routine to indicate that
	 * the signal post was done.
	 * This change in the flags field of the sg_io structure
	 * should not be reflected to the user. Hence once the flags
	 * field has been used for the purpose of determining whether
	 * the plugin executed a signal post, it must be restored to
	 * its original value which is stored in the local variable.
	 */
	save_sg_io_flags = sg_io->flags;

	e = cntrl->cntr_segops->rsm_memseg_import_getv(sg_io);

	/*
	 * At this point, if an implicit signal post was requested by
	 * the user, there could be two possibilities that arise:
	 * 1. the plugin routine has already executed the implicit
	 *    signal post either successfully or unsuccessfully
	 * 2. the plugin does not have the capability of doing an
	 *    implicit signal post and hence the signal post needs
	 *    to be done here.
	 * The above two cases can be idenfied by the flags
	 * field within the sg_io structure as follows:
	 * In case 1, the RSM_IMPLICIT_SIGPOST bit is reset to 0 by the
	 * plugin, indicating that the signal post was done.
	 * In case 2, the bit remains set to a 1 as originally given
	 * by the user, and hence a signal post needs to be done here.
	 */
	if (sg_io->flags & RSM_IMPLICIT_SIGPOST &&
	    e == RSM_SUCCESS) {
		/* Do the implicit signal post */

		/*
		 * The value of the second argument to this call
		 * depends on the value of the sg_io->flags field.
		 * If the RSM_SIGPOST_NO_ACCUMULATE flag has been
		 * ored into the sg_io->flags field, this indicates
		 * that the rsm_intr_signal_post is to be done with
		 * the flags argument set to RSM_SIGPOST_NO_ACCUMULATE
		 * Else, the flags argument is set to 0. These
		 * semantics can be achieved simply by masking off
		 * all other bits in the sg_io->flags field except the
		 * RSM_SIGPOST_NO_ACCUMULATE bit and using the result
		 * as the flags argument for the rsm_intr_signal_post.
		 */

		int sigpost_flags = sg_io->flags & RSM_SIGPOST_NO_ACCUMULATE;
		e = rsm_intr_signal_post(seg, sigpost_flags);
	}

	/* Restore the flags field within the users scatter gather structure */
	sg_io->flags = save_sg_io_flags;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_getv: exit\n"));

	return (e);

}

	/*
	 * import side memory segment operations (write access functions):
	 */

int
rsm_memseg_import_put8(rsm_memseg_import_handle_t im_memseg,
    off_t offset,
    uint8_t *datap,
    ulong_t rep_cnt)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	int e;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_put8: enter\n"));

	/* addr of data will always pass the alignment check, avoids	*/
	/* need for a special case in verify_access for PUTs		*/
	e = __rsm_import_verify_access(seg, offset, (caddr_t)datap, rep_cnt,
	    RSM_PERM_WRITE,
	    RSM_DAS8);
	if (e == RSM_SUCCESS) {
		rsm_segops_t *ops = seg->rsmseg_ops;
		rsmbar_handle_t *bar = (rsmbar_handle_t *)seg->rsmseg_barrier;

		if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
			/* generation number snapshot */
			bar->rsmbar_gen = bar->rsmbar_seg->rsmseg_gnum;
		}

		e = ops->rsm_memseg_import_put8(im_memseg, offset, datap,
		    rep_cnt, 0);

		if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
			/* check the generation number for force disconnects */
			if (bar->rsmbar_gen != bar->rsmbar_seg->rsmseg_bar[0]) {
				return (RSMERR_CONN_ABORTED);
			}
		}
	}

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_put8: exit\n"));

	return (e);
}

int
rsm_memseg_import_put16(rsm_memseg_import_handle_t im_memseg,
    off_t offset,
    uint16_t *datap,
    ulong_t rep_cnt)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	int e;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_put16: enter\n"));

	/* addr of data will always pass the alignment check, avoids	*/
	/* need for a special case in verify_access for PUTs		*/
	e = __rsm_import_verify_access(seg, offset, (caddr_t)datap, rep_cnt*2,
	    RSM_PERM_WRITE,
	    RSM_DAS16);
	if (e == RSM_SUCCESS) {
		rsm_segops_t *ops = seg->rsmseg_ops;
		rsmbar_handle_t *bar = (rsmbar_handle_t *)seg->rsmseg_barrier;

		if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
			/* generation number snapshot */
			bar->rsmbar_gen = bar->rsmbar_seg->rsmseg_gnum;
		}

		e = ops->rsm_memseg_import_put16(im_memseg, offset, datap,
		    rep_cnt, 0);

		if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
			/* check the generation number for force disconnects */
			if (bar->rsmbar_gen != bar->rsmbar_seg->rsmseg_bar[0]) {
				return (RSMERR_CONN_ABORTED);
			}
		}

	}

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_put16: exit\n"));

	return (e);
}

int
rsm_memseg_import_put32(rsm_memseg_import_handle_t im_memseg,
    off_t offset,
    uint32_t *datap,
    ulong_t rep_cnt)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	int e;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_put32: enter\n"));

	/* addr of data will always pass the alignment check, avoids	*/
	/* need for a special case in verify_access for PUTs		*/
	e = __rsm_import_verify_access(seg, offset, (caddr_t)datap, rep_cnt*4,
	    RSM_PERM_WRITE,
	    RSM_DAS32);
	if (e == RSM_SUCCESS) {
		rsm_segops_t *ops = seg->rsmseg_ops;
		rsmbar_handle_t *bar = (rsmbar_handle_t *)seg->rsmseg_barrier;

		if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
			/* generation number snapshot */
			bar->rsmbar_gen = bar->rsmbar_seg->rsmseg_gnum;
		}

		e = ops->rsm_memseg_import_put32(im_memseg, offset, datap,
		    rep_cnt, 0);

		if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
			/* check the generation number for force disconnects */
			if (bar->rsmbar_gen != bar->rsmbar_seg->rsmseg_bar[0]) {
				return (RSMERR_CONN_ABORTED);
			}
		}
	}

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_put32: exit\n"));

	return (e);
}

int
rsm_memseg_import_put64(rsm_memseg_import_handle_t im_memseg,
    off_t offset,
    uint64_t *datap,
    ulong_t rep_cnt)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	int		e;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_put64: enter\n"));

	/* addr of data will always pass the alignment check, avoids	*/
	/* need for a special case in verify_access for PUTs		*/
	e = __rsm_import_verify_access(seg, offset, (caddr_t)datap, rep_cnt*8,
	    RSM_PERM_WRITE,
	    RSM_DAS64);
	if (e == RSM_SUCCESS) {
		rsm_segops_t *ops = seg->rsmseg_ops;
		rsmbar_handle_t *bar = (rsmbar_handle_t *)seg->rsmseg_barrier;

		if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
			/* generation number snapshot */
			bar->rsmbar_gen = bar->rsmbar_seg->rsmseg_gnum;
		}

		e = ops->rsm_memseg_import_put64(im_memseg, offset, datap,
		    rep_cnt, 0);

		if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
			/* check the generation number for force disconnects */
			if (bar->rsmbar_gen != bar->rsmbar_seg->rsmseg_bar[0]) {
				return (RSMERR_CONN_ABORTED);
			}
		}
	}

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_put64: exit\n"));

	return (e);
}

int
rsm_memseg_import_put(rsm_memseg_import_handle_t im_memseg,
    off_t offset,
    void *src_addr,
    size_t length)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	int e;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_put: enter\n"));

	e = __rsm_import_verify_access(seg, offset, (caddr_t)src_addr, length,
	    RSM_PERM_WRITE,
	    RSM_DAS8);
	if (e == RSM_SUCCESS) {
		rsm_segops_t *ops = seg->rsmseg_ops;
		rsmbar_handle_t *bar = (rsmbar_handle_t *)seg->rsmseg_barrier;

		if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
			/* generation number snapshot */
			bar->rsmbar_gen = bar->rsmbar_seg->rsmseg_gnum;
		}

		e = ops->rsm_memseg_import_put(im_memseg, offset, src_addr,
		    length);

		if (seg->rsmseg_barmode == RSM_BARRIER_MODE_IMPLICIT) {
			/* check the generation number for force disconnects */
			if (bar->rsmbar_gen != bar->rsmbar_seg->rsmseg_bar[0]) {
				return (RSMERR_CONN_ABORTED);
			}
		}

	}

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_put: exit\n"));
	return (e);
}


int
rsm_memseg_import_putv(rsm_scat_gath_t *sg_io)
{
	rsm_controller_t *cntrl;
	rsmseg_handle_t *seg;
	uint_t save_sg_io_flags;

	int e;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_putv: enter\n"));


	if (sg_io == NULL) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid sg_io structure\n"));
		return (RSMERR_BAD_SGIO);
	}

	seg = (rsmseg_handle_t *)sg_io->remote_handle;
	if (seg == NULL) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid remote segment handle in sg_io\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}

	cntrl = (rsm_controller_t *)seg->rsmseg_controller;
	if (cntrl == NULL) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid controller handle\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}

	if ((sg_io->io_request_count > RSM_MAX_SGIOREQS) ||
	    (sg_io->io_request_count == 0)) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "io_request_count value incorrect\n"));
		return (RSMERR_BAD_SGIO);
	}

	/* do an implicit map if required */
	if (seg->rsmseg_state == IMPORT_CONNECT) {
		e = __rsm_import_implicit_map(seg, RSM_IOTYPE_SCATGATH);
		if (e != RSM_SUCCESS) {
			DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
			    "implicit map failed\n"));
			return (e);
		}
	}

	/*
	 * Copy the flags field of the sg_io structure in a local
	 * variable.
	 * This is required since the flags field can be
	 * changed by the plugin library routine to indicate that
	 * the signal post was done.
	 * This change in the flags field of the sg_io structure
	 * should not be reflected to the user. Hence once the flags
	 * field has been used for the purpose of determining whether
	 * the plugin executed a signal post, it must be restored to
	 * its original value which is stored in the local variable.
	 */
	save_sg_io_flags = sg_io->flags;

	e = cntrl->cntr_segops->rsm_memseg_import_putv(sg_io);

	/*
	 * At this point, if an implicit signal post was requested by
	 * the user, there could be two possibilities that arise:
	 * 1. the plugin routine has already executed the implicit
	 *    signal post either successfully or unsuccessfully
	 * 2. the plugin does not have the capability of doing an
	 *    implicit signal post and hence the signal post needs
	 *    to be done here.
	 * The above two cases can be idenfied by the flags
	 * field within the sg_io structure as follows:
	 * In case 1, the RSM_IMPLICIT_SIGPOST bit is reset to 0 by the
	 * plugin, indicating that the signal post was done.
	 * In case 2, the bit remains set to a 1 as originally given
	 * by the user, and hence a signal post needs to be done here.
	 */
	if (sg_io->flags & RSM_IMPLICIT_SIGPOST &&
	    e == RSM_SUCCESS) {
		/* Do the implicit signal post */

		/*
		 * The value of the second argument to this call
		 * depends on the value of the sg_io->flags field.
		 * If the RSM_SIGPOST_NO_ACCUMULATE flag has been
		 * ored into the sg_io->flags field, this indicates
		 * that the rsm_intr_signal_post is to be done with
		 * the flags argument set to RSM_SIGPOST_NO_ACCUMULATE
		 * Else, the flags argument is set to 0. These
		 * semantics can be achieved simply by masking off
		 * all other bits in the sg_io->flags field except the
		 * RSM_SIGPOST_NO_ACCUMULATE bit and using the result
		 * as the flags argument for the rsm_intr_signal_post.
		 */

		int sigpost_flags = sg_io->flags & RSM_SIGPOST_NO_ACCUMULATE;
		e = rsm_intr_signal_post(seg, sigpost_flags);

	}

	/* Restore the flags field within the users scatter gather structure */
	sg_io->flags = save_sg_io_flags;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_putv: exit\n"));

	return (e);
}


	/*
	 * import side memory segment operations (mapping):
	 */
int
rsm_memseg_import_map(rsm_memseg_import_handle_t im_memseg,
    void **address,
    rsm_attribute_t attr,
    rsm_permission_t perm,
    off_t offset,
    size_t length)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	int flag = MAP_SHARED;
	int prot;
	caddr_t va;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_map: enter\n"));

	if (!seg) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid segment\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}
	if (!address) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid address\n"));
		return (RSMERR_BAD_ADDR);
	}

	/*
	 * Only one map per segment handle!
	 * XXX need to take a lock here
	 */
	mutex_lock(&seg->rsmseg_lock);

	if (seg->rsmseg_state == IMPORT_MAP) {
		mutex_unlock(&seg->rsmseg_lock);
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "segment already mapped\n"));
		return (RSMERR_SEG_ALREADY_MAPPED);
	}

	/* Only import segments allowed to map */
	if (seg->rsmseg_state != IMPORT_CONNECT) {
		mutex_unlock(&seg->rsmseg_lock);
		return (RSMERR_BAD_SEG_HNDL);
	}

	/* check for permissions */
	if (perm > RSM_PERM_RDWR) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "bad permissions when mapping\n"));
		mutex_unlock(&seg->rsmseg_lock);
		return (RSMERR_BAD_PERMS);
	}

	if (length == 0) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "mapping with length 0\n"));
		mutex_unlock(&seg->rsmseg_lock);
		return (RSMERR_BAD_LENGTH);
	}

	if (offset + length > seg->rsmseg_size) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "map length + offset exceed segment size\n"));
		mutex_unlock(&seg->rsmseg_lock);
		return (RSMERR_BAD_LENGTH);
	}

	if ((size_t)offset & (PAGESIZE - 1)) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "bad mem alignment\n"));
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}

	if (attr & RSM_MAP_FIXED) {
		if ((uintptr_t)(*address) & (PAGESIZE - 1)) {
			DBPRINTF((RSM_LIBRARY, RSM_ERR,
			    "bad mem alignment\n"));
			return (RSMERR_BAD_MEM_ALIGNMENT);
		}
		flag |= MAP_FIXED;
	}

	prot = PROT_NONE;
	if (perm & RSM_PERM_READ)
		prot |= PROT_READ;
	if (perm & RSM_PERM_WRITE)
		prot |= PROT_WRITE;

	va = mmap(*address, length, prot, flag, seg->rsmseg_fd, offset);
	if (va == MAP_FAILED) {
		int e = errno;
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "error %d during map\n", e));

		mutex_unlock(&seg->rsmseg_lock);
		if (e == ENXIO || e == EOVERFLOW ||
		    e == ENOMEM)
			return (RSMERR_BAD_LENGTH);
		else if (e == ENODEV)
			return (RSMERR_CONN_ABORTED);
		else if (e == EAGAIN)
			return (RSMERR_INSUFFICIENT_RESOURCES);
		else if (e == ENOTSUP)
			return (RSMERR_MAP_FAILED);
		else if (e == EACCES)
			return (RSMERR_BAD_PERMS);
		else
			return (RSMERR_MAP_FAILED);
	}
	*address = va;

	/*
	 * Fix segment ops vector to handle direct access.
	 */
	/*
	 * XXX: Set this only for full segment mapping. Keep a list
	 * of mappings to use for access functions
	 */
	seg->rsmseg_vaddr = va;
	seg->rsmseg_maplen = length;
	seg->rsmseg_mapoffset = offset;
	seg->rsmseg_state = IMPORT_MAP;

	mutex_unlock(&seg->rsmseg_lock);

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_map: exit\n"));

	return (RSM_SUCCESS);
}

int
rsm_memseg_import_unmap(rsm_memseg_import_handle_t im_memseg)
{
	/*
	 * Until we fix the rsm driver to catch unload, we unload
	 * the whole segment.
	 */

	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_unmap: enter\n"));

	if (!seg) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid segment or segment state\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}

	mutex_lock(&seg->rsmseg_lock);
	if (seg->rsmseg_state != IMPORT_MAP) {
		mutex_unlock(&seg->rsmseg_lock);
		return (RSMERR_SEG_NOT_MAPPED);
	}

	seg->rsmseg_mapoffset = 0;   /* reset the offset */
	seg->rsmseg_state = IMPORT_CONNECT;
	seg->rsmseg_flags &= ~RSM_IMPLICIT_MAP;
	(void) munmap(seg->rsmseg_vaddr, seg->rsmseg_maplen);

	mutex_unlock(&seg->rsmseg_lock);

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_unmap: exit\n"));

	return (RSM_SUCCESS);
}


	/*
	 * import side memory segment operations (barriers):
	 */
int
rsm_memseg_import_init_barrier(rsm_memseg_import_handle_t im_memseg,
    rsm_barrier_type_t type,
    rsmapi_barrier_t *barrier)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;
	rsmbar_handle_t *bar;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_init_barrier: enter\n"));

	if (!seg) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid segment or barrier\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}
	if (!barrier) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid barrier pointer\n"));
		return (RSMERR_BAD_BARRIER_PTR);
	}

	bar = (rsmbar_handle_t *)barrier;
	bar->rsmbar_seg = seg;

	seg->rsmseg_barrier = barrier;  /* used in put/get fns */

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_init_barrier: exit\n"));

	return (seg->rsmseg_ops->rsm_memseg_import_init_barrier(im_memseg,
	    type, (rsm_barrier_handle_t)barrier));
}

int
rsm_memseg_import_open_barrier(rsmapi_barrier_t *barrier)
{
	rsmbar_handle_t *bar = (rsmbar_handle_t *)barrier;
	rsm_segops_t *ops;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_open_barrier: enter\n"));

	if (!bar) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid barrier\n"));
		return (RSMERR_BAD_BARRIER_PTR);
	}
	if (!bar->rsmbar_seg) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "uninitialized barrier\n"));
		return (RSMERR_BARRIER_UNINITIALIZED);
	}

	/* generation number snapshot */
	bar->rsmbar_gen = bar->rsmbar_seg->rsmseg_gnum; /* bar[0] */

	ops = bar->rsmbar_seg->rsmseg_ops;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_open_barrier: exit\n"));

	return (ops->rsm_memseg_import_open_barrier(
	    (rsm_barrier_handle_t)barrier));
}

int
rsm_memseg_import_order_barrier(rsmapi_barrier_t *barrier)
{
	rsmbar_handle_t *bar = (rsmbar_handle_t *)barrier;
	rsm_segops_t *ops;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_order_barrier: enter\n"));

	if (!bar) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid barrier\n"));
		return (RSMERR_BAD_BARRIER_PTR);
	}
	if (!bar->rsmbar_seg) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "uninitialized barrier\n"));
		return (RSMERR_BARRIER_UNINITIALIZED);
	}

	ops = bar->rsmbar_seg->rsmseg_ops;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_order_barrier: exit\n"));

	return (ops->rsm_memseg_import_order_barrier(
	    (rsm_barrier_handle_t)barrier));
}

int
rsm_memseg_import_close_barrier(rsmapi_barrier_t *barrier)
{
	rsmbar_handle_t *bar = (rsmbar_handle_t *)barrier;
	rsm_segops_t *ops;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_close_barrier: enter\n"));

	if (!bar) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid barrier\n"));
		return (RSMERR_BAD_BARRIER_PTR);
	}
	if (!bar->rsmbar_seg) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "uninitialized barrier\n"));
		return (RSMERR_BARRIER_UNINITIALIZED);
	}

	/* generation number snapshot */
	if (bar->rsmbar_gen != bar->rsmbar_seg->rsmseg_bar[0]) {
		return (RSMERR_CONN_ABORTED);
	}

	ops = bar->rsmbar_seg->rsmseg_ops;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_close_barrier: exit\n"));

	return (ops->rsm_memseg_import_close_barrier(
	    (rsm_barrier_handle_t)barrier));
}

int
rsm_memseg_import_destroy_barrier(rsmapi_barrier_t *barrier)
{
	rsmbar_handle_t *bar = (rsmbar_handle_t *)barrier;
	rsm_segops_t *ops;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_destroy_barrier: enter\n"));

	if (!bar) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "invalid barrier\n"));
		return (RSMERR_BAD_BARRIER_PTR);
	}
	if (!bar->rsmbar_seg) {
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
		    "uninitialized barrier\n"));
		return (RSMERR_BARRIER_UNINITIALIZED);
	}

	bar->rsmbar_seg->rsmseg_barrier = NULL;

	ops = bar->rsmbar_seg->rsmseg_ops;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_destroy_barrier: exit\n"));

	return (ops->rsm_memseg_import_destroy_barrier
	    ((rsm_barrier_handle_t)barrier));
}

int
rsm_memseg_import_get_mode(rsm_memseg_import_handle_t im_memseg,
    rsm_barrier_mode_t *mode)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_get_mode: enter\n"));

	if (seg) {
		*mode = seg->rsmseg_barmode;
		DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
		    "rsm_memseg_import_get_mode: exit\n"));

		return (seg->rsmseg_ops->rsm_memseg_import_get_mode(im_memseg,
		    mode));
	}

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
	    "invalid arguments \n"));

	return (RSMERR_BAD_SEG_HNDL);

}

int
rsm_memseg_import_set_mode(rsm_memseg_import_handle_t im_memseg,
    rsm_barrier_mode_t mode)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)im_memseg;

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_import_set_mode: enter\n"));
	if (seg) {
		if ((mode == RSM_BARRIER_MODE_IMPLICIT ||
		    mode == RSM_BARRIER_MODE_EXPLICIT)) {
			seg->rsmseg_barmode = mode;
			DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
			    "rsm_memseg_import_set_mode: exit\n"));

			return (seg->rsmseg_ops->rsm_memseg_import_set_mode(
			    im_memseg,
			    mode));
		} else {
			DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_DEBUG_VERBOSE,
			    "bad barrier mode\n"));
			return (RSMERR_BAD_MODE);
		}
	}

	DBPRINTF((RSM_LIBRARY|RSM_IMPORT, RSM_ERR,
	    "invalid arguments\n"));

	return (RSMERR_BAD_SEG_HNDL);
}

int
rsm_intr_signal_post(void *memseg, uint_t flags)
{
	rsm_ioctlmsg_t msg;
	rsmseg_handle_t *seg = (rsmseg_handle_t *)memseg;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsm_intr_signal_post: enter\n"));

	flags = flags;

	if (!seg) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid segment handle\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}

	if (ioctl(seg->rsmseg_fd, RSM_IOCTL_RING_BELL, &msg) < 0) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "RSM_IOCTL_RING_BELL failed\n"));
		return (errno);
	}

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsm_intr_signal_post: exit\n"));

	return (RSM_SUCCESS);
}

int
rsm_intr_signal_wait(void *memseg, int timeout)
{
	rsmseg_handle_t *seg = (rsmseg_handle_t *)memseg;
	struct pollfd fds;
	minor_t	rnum;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsm_intr_signal_wait: enter\n"));

	if (!seg) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid segment\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}

	fds.fd = seg->rsmseg_fd;
	fds.events = POLLRDNORM;

	rnum = seg->rsmseg_rnum;

	return (__rsm_intr_signal_wait_common(&fds, &rnum, 1, timeout, NULL));
}

int
rsm_intr_signal_wait_pollfd(struct pollfd fds[], nfds_t nfds, int timeout,
	int *numfdsp)
{
	return (__rsm_intr_signal_wait_common(fds, NULL, nfds, timeout,
	    numfdsp));
}

/*
 * This is the generic wait routine, it takes the following arguments
 *	- pollfd array
 *	- rnums array corresponding to the pollfd if known, if this is
 *	NULL then the fds are looked up from the pollfd_table.
 *	- number of fds in pollfd array,
 *	- timeout
 *	- pointer to a location where the number of fds with successful
 *	events is returned.
 */
static int
__rsm_intr_signal_wait_common(struct pollfd fds[], minor_t rnums[],
    nfds_t nfds, int timeout, int *numfdsp)
{
	int	i;
	int	numsegs = 0;
	int	numfd;
	int	fds_processed = 0;
	minor_t	segrnum;
	rsm_poll_event_t	event_arr[RSM_MAX_POLLFDS];
	rsm_poll_event_t	*event_list = NULL;
	rsm_poll_event_t	*events;
	rsm_consume_event_msg_t msg;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE, "wait_common enter\n"));

	if (numfdsp) {
		*numfdsp = 0;
	}

	numfd = poll(fds, nfds, timeout);

	switch (numfd) {
	case -1: /* poll returned error - map to RSMERR_... */
		DBPRINTF((RSM_LIBRARY, RSM_ERR, "signal wait pollfd err\n"));
		switch (errno) {
		case EAGAIN:
			return (RSMERR_INSUFFICIENT_RESOURCES);
		case EFAULT:
			return (RSMERR_BAD_ADDR);
		case EINTR:
			return (RSMERR_INTERRUPTED);
		case EINVAL:
		default:
			return (RSMERR_BAD_ARGS_ERRORS);
		}
	case 0: /* timedout - return from here */
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "signal wait timed out\n"));
		return (RSMERR_TIMEOUT);
	default:
		break;
	}

	if (numfd <= RSM_MAX_POLLFDS) {
		/* use the event array on the stack */
		events = (rsm_poll_event_t *)event_arr;
	} else {
		/*
		 * actual number of fds corresponding to rsmapi segments might
		 * be < numfd, don't want to scan the list to figure that out
		 * lets just allocate on the heap
		 */
		event_list = (rsm_poll_event_t *)malloc(
		    sizeof (rsm_poll_event_t)*numfd);
		if (!event_list) {
			/*
			 * return with error even if poll might have succeeded
			 * since the application can retry and the events will
			 * still be available.
			 */
			return (RSMERR_INSUFFICIENT_MEM);
		}
		events = event_list;
	}

	/*
	 * process the fds for events and if it corresponds to an rsmapi
	 * segment consume the event
	 */
	for (i = 0; i < nfds; i++) {
		if (fds[i].revents == POLLRDNORM) {
			/*
			 * poll returned an event and if its POLLRDNORM, it
			 * might correspond to an rsmapi segment
			 */
			if (rnums) { /* resource num is passed in */
				segrnum = rnums[i];
			} else { /* lookup pollfd table to get resource num */
				segrnum = _rsm_lookup_pollfd_table(fds[i].fd);
			}
			if (segrnum) {
				events[numsegs].rnum = segrnum;
				events[numsegs].revent = 0;
				events[numsegs].fdsidx = i; /* fdlist index */
				numsegs++;
			}
		}

		if ((fds[i].revents) && (++fds_processed == numfd)) {
			/*
			 * only "numfd" events have revents field set, once we
			 * process that many break out of the loop
			 */
			break;
		}
	}

	if (numsegs == 0) { /* No events for rsmapi segs in the fdlist */
		if (event_list) {
			free(event_list);
		}
		if (numfdsp) {
			*numfdsp = numfd;
		}
		DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
		    "wait_common exit: no rsmapi segs\n"));
		return (RSM_SUCCESS);
	}

	msg.seglist = (caddr_t)events;
	msg.numents = numsegs;

	if (ioctl(_rsm_fd, RSM_IOCTL_CONSUMEEVENT, &msg) < 0) {
		int error = errno;
		if (event_list) {
			free(event_list);
		}
		DBPRINTF((RSM_LIBRARY|RSM_LOOPBACK, RSM_ERR,
		    "RSM_IOCTL_CONSUMEEVENT failed(%d)\n", error));
		return (error);
	}

	/* count the number of segs for which consumeevent was successful */
	numfd -= numsegs;

	for (i = 0; i < numsegs; i++) {
		if (events[i].revent != 0) {
			fds[events[i].fdsidx].revents = POLLRDNORM;
			numfd++;
		} else { /* failed to consume event so set revents to 0 */
			fds[events[i].fdsidx].revents = 0;
		}
	}

	if (event_list) {
		free(event_list);
	}

	if (numfd > 0) {
		if (numfdsp) {
			*numfdsp = numfd;
		}
		DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
		    "wait_common exit\n"));
		return (RSM_SUCCESS);
	} else {
		DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
		    "wait_common exit\n"));
		return (RSMERR_TIMEOUT);
	}
}

/*
 * This function provides the data (file descriptor and event) for
 * the specified pollfd struct.  The pollfd struct may then be
 * subsequently used with the poll system call to wait for an event
 * signalled by rsm_intr_signal_post.  The memory segment must be
 * currently published for a successful return with a valid pollfd.
 * A reference count for the descriptor is incremented.
 */
int
rsm_memseg_get_pollfd(void *memseg,
			struct pollfd *poll_fd)
{
	int	i;
	int	err = RSM_SUCCESS;
	rsmseg_handle_t *seg = (rsmseg_handle_t *)memseg;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_get_pollfd: enter\n"));

	if (!seg) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid segment\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}

	mutex_lock(&seg->rsmseg_lock);

	poll_fd->fd = seg->rsmseg_fd;
	poll_fd->events = POLLRDNORM;
	seg->rsmseg_pollfd_refcnt++;
	if (seg->rsmseg_pollfd_refcnt == 1) {
		/* insert the segment into the pollfd table */
		err = _rsm_insert_pollfd_table(seg->rsmseg_fd,
		    seg->rsmseg_rnum);
	}

	mutex_unlock(&seg->rsmseg_lock);

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_get_pollfd: exit(%d)\n", err));

	return (err);
}

/*
 * This function decrements the segment pollfd reference count.
 * A segment unpublish or destroy operation will fail if the reference count is
 * non zero.
 */
int
rsm_memseg_release_pollfd(void * memseg)
{
	int	i;
	rsmseg_handle_t *seg = (rsmseg_handle_t *)memseg;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_release_pollfd: enter\n"));

	if (!seg) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid segment handle\n"));
		return (RSMERR_BAD_SEG_HNDL);
	}

	mutex_lock(&seg->rsmseg_lock);

	if (seg->rsmseg_pollfd_refcnt) {
		seg->rsmseg_pollfd_refcnt--;
		if (seg->rsmseg_pollfd_refcnt == 0) {
			/* last reference removed - update the pollfd_table */
			_rsm_remove_pollfd_table(seg->rsmseg_fd);
		}
	}

	mutex_unlock(&seg->rsmseg_lock);

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsm_memseg_release_pollfd: exit\n"));

	return (RSM_SUCCESS);
}

/*
 * The interconnect topology data is obtained from the Kernel Agent
 * and stored in a memory buffer allocated by this function.  A pointer
 * to the buffer is stored in the location specified by the caller in
 * the function argument.  It is the callers responsibility to
 * call rsm_free_interconnect_topolgy() to free the allocated memory.
 */
int
rsm_get_interconnect_topology(rsm_topology_t **topology_data)
{
	uint32_t		topology_data_size;
	rsm_topology_t		*topology_ptr;
	int			error;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsm_get_interconnect_topology: enter\n"));

	if (topology_data == NULL)
		return (RSMERR_BAD_TOPOLOGY_PTR);

	*topology_data = NULL;

again:
	/* obtain the size of the topology data */
	if (ioctl(_rsm_fd, RSM_IOCTL_TOPOLOGY_SIZE, &topology_data_size) < 0) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "RSM_IOCTL_TOPOLOGY_SIZE failed\n"));
		return (errno);
	}

	/* allocate double-word aligned memory to hold the topology data */
	topology_ptr = (rsm_topology_t *)memalign(8, topology_data_size);
	if (topology_ptr == NULL) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "not enough memory\n"));
		return (RSMERR_INSUFFICIENT_MEM);
	}

	/*
	 * Request the topology data.
	 * Pass in the size to be used as a check in case
	 * the data has grown since the size was obtained - if
	 * it has, the errno value will be E2BIG.
	 */
	topology_ptr->topology_hdr.local_nodeid =
	    (rsm_node_id_t)topology_data_size;
	if (ioctl(_rsm_fd, RSM_IOCTL_TOPOLOGY_DATA, topology_ptr) < 0) {
		error = errno;
		free((void *)topology_ptr);
		if (error == E2BIG)
			goto again;
		else {
			DBPRINTF((RSM_LIBRARY, RSM_ERR,
			    "RSM_IOCTL_TOPOLOGY_DATA failed\n"));
			return (error);
		}
	} else
		*topology_data = topology_ptr;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    " rsm_get_interconnect_topology: exit\n"));

	return (RSM_SUCCESS);
}


void
rsm_free_interconnect_topology(rsm_topology_t *topology_ptr)
{

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsm_free_interconnect_topology: enter\n"));

	if (topology_ptr) {
		free((void *)topology_ptr);
	}

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsm_free_interconnect_topology: exit\n"));
}

int
rsm_create_localmemory_handle(rsmapi_controller_handle_t cntrl_handle,
				rsm_localmemory_handle_t *local_hndl_p,
				caddr_t local_vaddr, size_t len)
{
	int e;
	rsm_controller_t *cntrl = (rsm_controller_t *)cntrl_handle;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsm_create_localmemory_handle: enter\n"));

	if ((size_t)local_vaddr & (PAGESIZE - 1)) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid arguments\n"));
		return (RSMERR_BAD_ADDR);
	}

	if (!cntrl_handle) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid controller handle\n"));
		return (RSMERR_BAD_CTLR_HNDL);
	}
	if (!local_hndl_p) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid local memory handle pointer\n"));
		return (RSMERR_BAD_LOCALMEM_HNDL);
	}
	if (len == 0) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid length\n"));
		return (RSMERR_BAD_LENGTH);
	}

	e = cntrl->cntr_segops->rsm_create_localmemory_handle(
	    cntrl_handle,
	    local_hndl_p,
	    local_vaddr,
	    len);

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsm_create_localmemory_handle: exit\n"));

	return (e);
}

int
rsm_free_localmemory_handle(rsmapi_controller_handle_t cntrl_handle,
    rsm_localmemory_handle_t local_handle)
{
	int e;

	rsm_controller_t *cntrl = (rsm_controller_t *)cntrl_handle;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsm_free_localmemory_handle: enter\n"));


	if (!cntrl_handle) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid controller handle\n"));
		return (RSMERR_BAD_CTLR_HNDL);
	}

	if (!local_handle) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid localmemory handle\n"));
		return (RSMERR_BAD_LOCALMEM_HNDL);
	}

	e = cntrl->cntr_segops->rsm_free_localmemory_handle(local_handle);

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "rsm_free_localmemory_handle: exit\n"));

	return (e);
}

int
rsm_get_segmentid_range(const char *appid, rsm_memseg_id_t *baseid,
	uint32_t *length)
{
	char    buf[RSMFILE_BUFSIZE];
	char	*s;
	char	*fieldv[4];
	int	fieldc = 0;
	int	found = 0;
	int	err = RSMERR_BAD_APPID;
	FILE    *fp;

	if (appid == NULL || baseid == NULL || length == NULL)
		return (RSMERR_BAD_ADDR);

	if ((fp = fopen(RSMSEGIDFILE, "rF")) == NULL) {
		DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
		    "cannot open <%s>\n", RSMSEGIDFILE));
		return (RSMERR_BAD_CONF);
	}

	while (s = fgets(buf, RSMFILE_BUFSIZE, fp)) {
		fieldc = 0;
		while (isspace(*s))	/* skip the leading spaces */
			s++;

		if (*s == '#') {	/* comment line - skip it */
			continue;
		}

		/*
		 * parse the reserved segid file and
		 * set the pointers appropriately.
		 * fieldv[0] :  keyword
		 * fieldv[1] :  application identifier
		 * fieldv[2] :  baseid
		 * fieldv[3] :  length
		 */
		while ((*s != '\n') && (*s != '\0') && (fieldc < 4)) {

			while (isspace(*s)) /* skip the leading spaces */
				s++;

			fieldv[fieldc++] = s;

			if (fieldc == 4) {
				if (fieldv[3][strlen(fieldv[3])-1] == '\n')
					fieldv[3][strlen(fieldv[3])-1] = '\0';
				break;
			}

			while (*s && !isspace(*s))
				++s;	/* move to the next white space */

			if (*s)
				*s++ = '\0';
		}

		if (fieldc < 4) {	/* some fields are missing */
			err = RSMERR_BAD_CONF;
			break;
		}

		if (strcasecmp(fieldv[1], appid) == 0) { /* found a match */
			if (strcasecmp(fieldv[0], RSMSEG_RESERVED) == 0) {
				errno = 0;
				*baseid = strtol(fieldv[2], (char **)NULL, 16);
				if (errno != 0) {
					err = RSMERR_BAD_CONF;
					break;
				}

				errno = 0;
				*length = (int)strtol(fieldv[3],
				    (char **)NULL, 10);
				if (errno != 0) {
					err = RSMERR_BAD_CONF;
					break;
				}

				found = 1;
			} else {	/* error in format */
				err = RSMERR_BAD_CONF;
			}
			break;
		}
	}

	(void) fclose(fp);

	if (found)
		return (RSM_SUCCESS);

	return (err);
}

static 	int
_rsm_get_hwaddr(rsmapi_controller_handle_t handle, rsm_node_id_t nodeid,
    rsm_addr_t *hwaddrp)
{
	rsm_ioctlmsg_t	msg = {0};
	rsm_controller_t *ctrlp;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "_rsm_get_hwaddr: enter\n"));

	ctrlp = (rsm_controller_t *)handle;

	if (ctrlp == NULL) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid controller handle\n"));
		return (RSMERR_BAD_CTLR_HNDL);
	}

	msg.cname = ctrlp->cntr_name;
	msg.cname_len = strlen(ctrlp->cntr_name) +1;
	msg.cnum = ctrlp->cntr_unit;
	msg.nodeid = nodeid;

	if (ioctl(_rsm_fd, RSM_IOCTL_MAP_TO_ADDR, &msg) < 0) {
		int error = errno;
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "RSM_IOCTL_MAP_TO_ADDR failed\n"));
		return (error);
	}

	*hwaddrp = msg.hwaddr;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "_rsm_get_hwaddr: exit\n"));

	return (RSM_SUCCESS);

}

static	int
_rsm_get_nodeid(rsmapi_controller_handle_t handle, rsm_addr_t hwaddr,
    rsm_node_id_t *nodeidp)
{

	rsm_ioctlmsg_t	msg = {0};
	rsm_controller_t *ctrlp;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "_rsm_get_nodeid: enter\n"));

	ctrlp = (rsm_controller_t *)handle;

	if (ctrlp == NULL) {
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "invalid arguments\n"));
		return (RSMERR_BAD_CTLR_HNDL);
	}

	msg.cname = ctrlp->cntr_name;
	msg.cname_len = strlen(ctrlp->cntr_name) +1;
	msg.cnum = ctrlp->cntr_unit;
	msg.hwaddr = hwaddr;

	if (ioctl(_rsm_fd, RSM_IOCTL_MAP_TO_NODEID, &msg) < 0) {
		int error = errno;
		DBPRINTF((RSM_LIBRARY, RSM_ERR,
		    "RSM_IOCTL_MAP_TO_NODEID failed\n"));
		return (error);
	}

	*nodeidp = msg.nodeid;

	DBPRINTF((RSM_LIBRARY, RSM_DEBUG_VERBOSE,
	    "_rsm_get_nodeid: exit\n"));

	return (RSM_SUCCESS);

}

#ifdef DEBUG
void
dbg_printf(int msg_category, int msg_level, char *fmt, ...)
{
	if ((msg_category & rsmlibdbg_category) &&
	    (msg_level <= rsmlibdbg_level)) {
		va_list arg_list;
		va_start(arg_list, fmt);
		mutex_lock(&rsmlog_lock);
		fprintf(rsmlog_fd, "Thread %d ", thr_self());
		vfprintf(rsmlog_fd, fmt, arg_list);
		fflush(rsmlog_fd);
		mutex_unlock(&rsmlog_lock);
		va_end(arg_list);
	}
}
#endif /* DEBUG */
