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

/*
 * l_misc.c :
 *      This file contains the miscelleneous routines for libsm.so
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/dktp/fdisk.h>
#include <dirent.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <strings.h>
#include "l_defines.h"
#include <rpc/rpc.h>
#include "smed.h"
#include <sys/smedia.h>
#include "../inc/rmedia.h"
#include <smserver.h>
#include <sys/mman.h>
#include <utmpx.h>
#include <limits.h>

#ifdef _LP64
#ifdef __sparc
#define	PATHNAME "/usr/lib/smedia/sparcv9"
#else
#define	PATHNAME "/usr/lib/smedia/amd64"
#endif
#else
#define	PATHNAME "/usr/lib/smedia"
#endif

#define	PERROR(string)	my_perror(gettext(string))
#define	RUN_LIBSMEDIA_SERVER	"	/usr/lib/smedia/rpc.smserverd &\n"

static void
my_perror(char *err_string)
{

	int error_no;
	if (errno == 0)
		return;

	error_no = errno;
	(void) fprintf(stderr, gettext(err_string));
	(void) fprintf(stderr, gettext(" : "));
	errno = error_no;
	perror("");
}

static int
is_server_running(rmedia_handle_t *handle)
{
	door_arg_t	door_args;
	smedia_reqping_t	reqping;
	smedia_retping_t	*retping;
	int		ret_val;
	int		door_fd;
	CLIENT		*clnt;
	char	rbuf[sizeof (smedia_services_t) + sizeof (door_desc_t)];
	smserver_info	*server_info;

	/*
	 * We will assume that we are running at level 2 or greater
	 * and attempt to contact the server using RPC mecahnisms.
	 * If that fails then we will attempt to contact the server
	 * using non-rpc mechanism. This will enable the libsmedia
	 * to be used in SINGLE user mode when inetd is not running.
	 * We expect the server to have been started manually by user.
	 *
	 * Note that "localhost" is used (vs hostname (eg, "uname -n")),
	 * as this minimizes interference with common IPSec rules.
	 */

	clnt = clnt_create("localhost", SMSERVERPROG, SMSERVERVERS,
	    "circuit_v");
	if (clnt == (CLIENT *)NULL) {
		/*
		 * The failure could be that we are running at level 1
		 */
		door_fd = open(smedia_service, O_RDONLY, 0644);
		if (door_fd < 0) {
			DPRINTF1("Error in opening %s\n",
			    smedia_service);
			return (0);
		}

		DPRINTF1("rbuf address=%p\n", rbuf);
		reqping.cnum = SMEDIA_CNUM_PING;
		door_args.data_ptr = (char *)&reqping;
		door_args.data_size = sizeof (smedia_services_t);
		door_args.desc_ptr = NULL;
		door_args.desc_num = 0;
		door_args.rbuf = rbuf;
		door_args.rsize = sizeof (rbuf);

		ret_val = door_call(door_fd, &door_args);
		(void) close(door_fd);
		if (ret_val < 0) {
			return (0);
		}
		DPRINTF3("rsize = %d data_size = %d data_ptr = %p \n",
		    door_args.rsize, door_args.data_size,
		    door_args.data_ptr);
		retping = (smedia_retping_t *)(
		    (void *)door_args.data_ptr);
		if (retping->cnum != SMEDIA_CNUM_PING) {
			DPRINTF1("*** door call failed *** cnum "
			    "returned = 0x%x\n", retping->cnum);
			return (0);
		}
		return (1);
	}
	server_info = smserverproc_get_serverinfo_1(NULL, clnt);
	if (server_info == NULL) {
		if (clnt)
			clnt_destroy(clnt);
		return (0);
	}
	if (server_info->status != 0) {
		if (clnt)
			clnt_destroy(clnt);
		DPRINTF1("get server_info call failed. "
		    "status = %d\n", server_info->status);
		return (0);
	}
	if (server_info->vernum != SMSERVERVERS) {
		if (clnt)
			clnt_destroy(clnt);
		DPRINTF2("version expected = %d version "
		    "returned = %d\n", SMSERVERVERS,
		    server_info->vernum);
		return (0);
	}

	door_fd = open(smedia_service, O_RDONLY, 0644);
	if (door_fd < 0) {
		DPRINTF1("Error in opening %s\n", smedia_service);
		return (0);
	}

	DPRINTF1("rbuf address=%p\n", rbuf);
	reqping.cnum = SMEDIA_CNUM_PING;
	door_args.data_ptr = (char *)&reqping;
	door_args.data_size = sizeof (smedia_services_t);
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;
	door_args.rbuf = rbuf;
	door_args.rsize = sizeof (rbuf);

	ret_val = door_call(door_fd, &door_args);
	(void) close(door_fd);
	if (ret_val < 0) {
		return (0);
	}
	DPRINTF3("rsize = %d data_size = %d data_ptr = %p \n",
	    door_args.rsize, door_args.data_size,
	    door_args.data_ptr);
	retping = (smedia_retping_t *)((void *)door_args.data_ptr);
	if (retping->cnum != SMEDIA_CNUM_PING) {
		DPRINTF1("*** door call failed *** cnum returned "
		    "= 0x%x\n", retping->cnum);
		return (0);
	}
	handle->sm_clnt = clnt;
	return (1);
}

static void *
get_dev_library_handle(int32_t fd)
{
	void *handle;
	void *old_handle = NULL;
	struct dk_cinfo dkinfo;
	DIR *dirp;
	struct dirent *dp;
	char *pathname;
	int32_t (*d_fcn_ptr)(ushort_t, ushort_t);
	int32_t (*v_fcn_ptr)(void);
	int32_t ret_val;

	if (ioctl(fd, DKIOCINFO, &dkinfo) == -1) {
		PERROR("DKIOCINFO failed");
		return (NULL);
	}
	DPRINTF1("dki_ctype = 0x%x\n", dkinfo.dki_ctype);

	if ((pathname = malloc(PATH_MAX)) == NULL) {
		PERROR("malloc failed");
		return (NULL);
	}

	dirp = opendir(PATHNAME);
	if (dirp == NULL) {
		(void) fprintf(stderr, gettext("Couldnot open %s\n"), PATHNAME);
		free(pathname);
		return (NULL);
	}

	while ((dp = readdir(dirp)) != NULL) {
		if (strncmp("sm_", dp->d_name, 3) != 0) {
			DPRINTF1("not a library %s\n", dp->d_name);
			continue;
		}
		if (snprintf(pathname, PATH_MAX, "%s/%s",
		    PATHNAME, dp->d_name) >= PATH_MAX) {
			continue;
		}

		handle = dlopen(pathname, RTLD_LAZY);
		if (handle == NULL) {
			PERROR("Error opening library file");
			continue;
		}
		d_fcn_ptr = (int32_t (*)(ushort_t, ushort_t))dlsym(handle,
		    "_m_device_type");
		if (d_fcn_ptr == NULL) {
			DPRINTF("Could not find _m_device_type\n");
			(void) dlclose(handle);
			continue;
		}
		ret_val = (*d_fcn_ptr)(dkinfo.dki_ctype, 0);
		if (ret_val == 0) {
			DPRINTF1("NAME %s\n", dp->d_name);
			v_fcn_ptr = (int32_t (*)(void))dlsym(handle,
			    "_m_version_no");
			if (v_fcn_ptr == NULL) {
				DPRINTF("Could not find _m_version_no\n");
				(void) dlclose(handle);
				continue;
			}
			ret_val = (*v_fcn_ptr)();
			if ((ret_val >= 0) &&
			    (ret_val >= SM_PLUGIN_VERSION)) {
				if (old_handle != NULL)
					(void) dlclose(old_handle);
				old_handle = handle;
				continue;
			} else {
				(void) dlclose(handle);
			}
		} else {
			(void) dlclose(handle);
		}
	}
	free(pathname);
	(void) closedir(dirp);
	return (old_handle);
}

int32_t
call_function(rmedia_handle_t *handle, void *ip, char *func_name)
{

	int32_t ret_val;
	int32_t (*fcn_ptr)(rmedia_handle_t *handle, void *ip);
	void *lib_handle;

	if (handle == NULL) {
		DPRINTF("Handle is NULL\n");
		errno = EINVAL;
		return (-1);
	}
	lib_handle = handle->sm_lib_handle;
	if (handle->sm_signature != LIBSMEDIA_SIGNATURE) {
		DPRINTF2("call_function:signature expected=0x%x, found=0x%x\n",
		    LIBSMEDIA_SIGNATURE, handle->sm_signature);
		errno = EINVAL;
		return (-1);
	}

	fcn_ptr = (int32_t (*)(rmedia_handle_t *, void*))
	    dlsym(lib_handle, func_name);
	if (fcn_ptr == NULL) {
		DPRINTF1("Could not find %s\n", func_name);
		errno = ENOTSUP;
		return (-1);
	}
	ret_val = (*fcn_ptr)(handle, ip);
	return (ret_val);
}

int32_t
release_handle(rmedia_handle_t *handle)
{
	if (handle == NULL) {
		DPRINTF("Handle is NULL\n");
		errno = EINVAL;
		return (-1);
	}
	if ((handle->sm_dkinfo.dki_ctype == DKC_SCSI_CCS) ||
	    (handle->sm_dkinfo.dki_ctype == DKC_MD21) ||
	    (handle->sm_dkinfo.dki_ctype == DKC_CDROM)) {
		(void) close(handle->sm_door);
		(void) close(handle->sm_death_door);
		if (handle->sm_buf != NULL)
			(void) munmap(handle->sm_buf, handle->sm_bufsize);
		if (handle->sm_clnt != NULL)
			clnt_destroy(handle->sm_clnt);
	}
	(void) close(handle->sm_buffd);
	handle->sm_signature = 0;
	(void) dlclose(handle->sm_lib_handle);
	free(handle);
	return (0);
}

smedia_handle_t
get_handle_from_fd(int32_t fd)
{
	rmedia_handle_t	*handle;
	void	*lib_handle;
	int	door_fd, door_server;
	int	ret_val;
	door_arg_t	door_args;
	smedia_reqopen_t	reqopen;
	smedia_reterror_t	*reterror;
	door_desc_t	ddesc[2];
	char	rbuf[sizeof (smedia_services_t) + sizeof (door_desc_t)];
	struct stat	stat;

	DPRINTF("smedia_get_handle called\n");
	handle = (rmedia_handle_t *)malloc(sizeof (rmedia_handle_t));
	if (handle == NULL) {
		DPRINTF("Could not allocate memory for handle\n");
		return (NULL);
	}
	(void) memset((void *) handle, 0, sizeof (rmedia_handle_t));
	handle->sm_fd = -1;
	handle->sm_door = -1;
	handle->sm_death_door = -1;
	handle->sm_buffd = -1;
	handle->sm_buf = NULL;
	handle->sm_bufsize = 0;

	if (ioctl(fd, DKIOCINFO, &handle->sm_dkinfo) == -1) {
		free(handle);
		PERROR("DKIOCINFO failed");
		return (NULL);
	}
	lib_handle = get_dev_library_handle(fd);
	if (lib_handle == NULL) {
		free(handle);
		DPRINTF("lib_Handle is NULL\n");
		errno = ENOTSUP;
		return (NULL);
	}
	DPRINTF("Handle initialised successfully.\n");
	/* Initialise the handle elements */
	handle->sm_lib_handle = lib_handle;
	handle->sm_signature = LIBSMEDIA_SIGNATURE;
	DPRINTF2("fd=%d signature=0x%x\n", handle->sm_fd, handle->sm_signature);

	if ((handle->sm_dkinfo.dki_ctype == DKC_SCSI_CCS) ||
	    (handle->sm_dkinfo.dki_ctype == DKC_MD21) ||
	    (handle->sm_dkinfo.dki_ctype == DKC_CDROM)) {

		ret_val = is_server_running(handle);
		if (ret_val == 0) {
			(void) dlclose(handle->sm_lib_handle);
			free(handle);
			return (NULL);
		}
		door_fd = open(smedia_service, O_RDONLY, 0644);
		if (door_fd < 0) {
			(void) dlclose(handle->sm_lib_handle);
			free(handle);
			if (handle->sm_clnt)
				clnt_destroy(handle->sm_clnt);
			DPRINTF1("Error in opening %s\n", smedia_service);
			PERROR(smedia_service);
			return (NULL);
		}

		DPRINTF1("rbuf address=%p\n", rbuf);
		ddesc[0].d_data.d_desc.d_descriptor = fd;
		ddesc[0].d_attributes = DOOR_DESCRIPTOR;
		reqopen.cnum = SMEDIA_CNUM_OPEN_FD;
		door_args.data_ptr = (char *)&reqopen;
		door_args.data_size = sizeof (smedia_services_t);
		door_args.desc_ptr = &ddesc[0];
		door_args.desc_num = 1;
		door_args.rbuf = rbuf;
		door_args.rsize = sizeof (rbuf);

		ret_val = door_call(door_fd, &door_args);
		(void) close(door_fd);
		if (ret_val < 0) {
			(void) dlclose(handle->sm_lib_handle);
			free(handle);
			if (handle->sm_clnt)
				clnt_destroy(handle->sm_clnt);
			PERROR("door_call");
			return (NULL);
		}
		DPRINTF3("rsize = %d data_size = %d data_ptr = %p \n",
		    door_args.rsize, door_args.data_size,
		    door_args.data_ptr);
		reterror = (smedia_reterror_t *)((void *)door_args.data_ptr);
		if (reterror->cnum != SMEDIA_CNUM_OPEN_FD) {
			(void) dlclose(handle->sm_lib_handle);
			free(handle);
			if (handle->sm_clnt)
				clnt_destroy(handle->sm_clnt);
			DPRINTF1(
	"*** door call failed *** cnum returned = 0x%x\n", reterror->cnum);
			errno = reterror->errnum;
			return (NULL);
		}
		/*
		 * 2 door descriptors are returned after the above door call.
		 * The first door descriptor is the one that will be used
		 * in subsequent smedia calls. A dedicated thread is
		 * associated with this door to handle client calls.
		 * The second door descriptor is needed to signal unexpected
		 * death of the client to the server. This will help the server
		 * to do the necessary cleanup.
		 */
		if (door_args.desc_num != 2) {
			(void) dlclose(handle->sm_lib_handle);
			free(handle);
			if (handle->sm_clnt)
				clnt_destroy(handle->sm_clnt);
			DPRINTF("Num of door descriptors returned by "
			    "server is not 2");
			if (door_args.desc_num)
				(void) close(door_args.desc_ptr->\
				    d_data.d_desc.d_descriptor);
			return (NULL);
		}
		door_server = door_args.desc_ptr->d_data.d_desc.d_descriptor;
		/* Check if the descriptor returned is S_IFDOOR */
		if (fstat(door_server, &stat) < 0) {
			PERROR("fstat");
			(void) dlclose(handle->sm_lib_handle);
			free(handle);
			if (handle->sm_clnt)
				clnt_destroy(handle->sm_clnt);
			return (NULL);
		}
		if (!S_ISDOOR(stat.st_mode)) {
			DPRINTF(
		"Descriptor returned by door_call is not of type DOOR\n");
			(void) dlclose(handle->sm_lib_handle);
			free(handle);
			if (handle->sm_clnt)
				clnt_destroy(handle->sm_clnt);
			return (NULL);
		}
		handle->sm_door = door_server;
		handle->sm_fd = fd;
		door_args.desc_ptr++;
		handle->sm_death_door =
		    door_args.desc_ptr->d_data.d_desc.d_descriptor;
		DPRINTF("door call succeeded.\n");
		return ((smedia_handle_t)handle);

	} else {
		handle->sm_fd = fd;
		return ((smedia_handle_t)handle);
	}

}
