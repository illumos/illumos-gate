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

#include <stdio.h>
#include <stdio_ext.h>
#include <errno.h>
#include <ctype.h>
#include <syslog.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <fcntl.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/generic/commands.h>
#include <string.h>
#include <door.h>
#include <pwd.h>
#include <thread.h>
#include <synch.h>
#include <pthread.h>
#include <locale.h>
#include <sys/resource.h>
#include <netconfig.h>
#include <sys/smedia.h>
#include "smserver.h"
#include <rpc/rpc.h>
#include "smed.h"
#include "myaudit.h"
#include <bsm/libbsm.h>
#include <bsm/audit_uevents.h>
#include <utmpx.h>


/*
 * The comments below would help in understanding what is being attempted
 * in the server.
 *
 * The server can be started either by inetd or by the client directly.
 * Normally the server is started by inetd when the client invokes the
 * appropriate libsmedia library call(smedia_get_handle).
 * However since the inetd runs only at init level 2 and above a mechanism
 * is provided for the server to be started if an attempt is made to use
 * the libsmedia calls in maintenence mode(init level 1).
 * The main() routine determines how the server was invoked and takes
 * the necessary action.
 * When started by inetd it registers itself as an RPC program.
 * The server also implements a mechanism by which it removes itself
 * after a period of inactivity. The period of inactivity is specified
 * by SVC_CLOSEDOWN which is set at 180 secs.
 * The logic of detecting inactivity is as follows:
 *
 * Two variables svcstate and svccount are used to determine if the server
 * is IDLE.
 * The svcstate is set to 1(_SERVED) when ever the server does any operation
 * on behalf of the client.
 * The svccount indicates the number of active clients who have established
 * a connection with the server. A connection is established when the
 * libsmedia call smedia_get_handle() succeeds.
 * The connection is broken when the client calls smedia_free_handle() OR
 * exits.
 * A thread called closedown is started up when server is started.
 * This thread runs periodically and monitors both svcstate and svccount.
 * If svcstate is IDLE and svccount is 0 then server exits.
 * The svcstate is set to IDLE by the closedown thread. It is set to _SERVED
 * by server. It is possible for the state to be _SERVED and the svccount
 * to be 0. The server could be kept busy by client calls of smedia_get_handle
 * that do not succeed. This is the reason for using both svcstate and svccount
 * to determine the true server state.
 *
 * The communication between client and server is thru door calls.
 * Below are the door descriptors available to communicate to the server.
 *
 * main_door_descriptor:
 * ---------------------
 * 	This is a predefined descriptor used by client to establish a
 * connection with the server. This descriptor is available to the client
 * as /var/adm/smedia_svc
 * The client uses the main_door_descriptor to obtain a dedicated
 * client_door_descriptor for itself. The smedia_get_handle call communicates
 * to the server using the main_door_descriptor and obtains the
 * client_door_descriptor which is stored in the handle structure.
 * All other libsmedia calls use the client_door_descriptor to communicate
 * with the server.
 *
 * client_door_descriptor:
 * -----------------------
 *	This is the door descriptor that is used by the clients to
 * request server to perform the necessary tasks. This door descriptor is
 * available only to the client for whom it was created.
 *
 * death_door_descriptor:
 * ----------------------
 * 	The sole function of this descriptor HAD been to inform the server of
 * the untimely death of the client. This descriptor is no longer used, though
 * it is still created, as libsmedia expects to use it.  This descriptor's
 * service procedure had used pthread cancellation(7) to terminate the thread of
 * the associated client_door_descriptor.  The client_door_descriptor now
 * handles the scenarios where a door_call/client are aborted/terminated.
 *
 * main_servproc()
 * -------------
 *	This is the routine associated with the main_door_descriptor.
 * This is the routine that handles the smedia_get_handle() call
 * of the client. If the door call to this routine succeeds it creates a
 * client_door_descriptor that is used by the client in subsequent library
 * calls.
 * This client_door_descriptor is passed to the client thru the door_return
 * call. This client_door_descriptor cannot be used by any other process other
 * than the client process that obtained it.
 * In addition to the client_door_descriptor a death_door_descriptor is also
 * created by the main server and passed on to the client. The client does not
 * use the death_door_descriptor.
 *
 * client_servproc()
 * ---------------
 *	This is the routine that handles the libsmedia calls of the
 * client. In the current implementation the server takes control of the
 * number of threads that handle the door calls. This is done by creating the
 * door descriptor as DOOR_PRIVATE.
 * The server runs only one thread per handle. This makes the implementation
 * simple as we do not have to use mutex to make the code MT safe.
 * The server thread has a data structure door_data_t associated with it.
 *
 * door_data_t
 * -----------
 * This is the data structure that is created by the main_servproc when it
 * creates the client_door_descriptor. The door mechanism has a way to associate
 * a cookie with the door descriptor. door_data_t is the cookie for the
 * client_door_descriptor. This cookie is passed to the server function that
 * handles the client_door_descriptor calls. In our case it is the
 * client_servproc routine.
 * The key elements of the door_data_t are the following:
 *
 *	dd_fd		file descriptor for the device.
 *	dd_buf		The shared memory buffer between client-server.
 *	dd_thread	The thread that handles the door_calls.
 *
 * signal handling:
 * ----------------
 *		The main purpose of trapping the signals is to exit gracefully
 * from the server after recording the appropriate message in the syslog.
 * This will help the administrator to determine the cause of failure of the
 * server by examining the log file.
 *
 * cleanup()
 * ---------
 *	This routine frees up all the resources allocated for the client.
 * Resources include the file descriptor, shared memory, threads.
 *
 * shared memory
 * -------------
 *	In order to reduce the overheads of moving large amounts of data
 * during raw read/write operations, the server uses the mmapped data of
 * client. The smedia_raw_read, smedia_raw_write library calls mmap the
 * memory and pass on the file descriptor that maps the memory to the server.
 * The server subsequently uses this mmapped memory during the IO.
 * If the mmapped memory changes in size, the server is informed and it
 * remaps the memory to the changed size.
 */
#ifdef DEBUG
#define	DEFAULT_VERBOSE		1
#define	DEFAULT_DEBUG		1
#else
#define	DEFAULT_VERBOSE		0
#define	DEFAULT_DEBUG		0
#endif

#define	N_BADSIGS		(sizeof (badsigs)/sizeof (badsigs[0]))
#define	MD_LEN			30
#define	MAXUGNAME		10
#define	SVC_CLOSEDOWN 		180

/*
 * We will NOT be permitting the following USCI cmd options.
 *
 * RESET of target
 * RESET of  Bus.
 * Tagged commands to device
 * Explicitly setting SYNC/ASYNC mode of operations.
 * POLLED MODE of operation.
 * Explicitly setting NO DISCONNECT features.
 * use of RESERVED flags.
 */
#define	FORBIDDEN_FLAGS		(USCSI_RESET | USCSI_RESET_ALL | USCSI_RENEGOT \
				| USCSI_ASYNC  | USCSI_SYNC | USCSI_NOINTR | \
				USCSI_NOTAG | USCSI_NOPARITY | USCSI_NODISCON \
				| USCSI_RESERVED)

/* States a server can be in wrt request */

#define	_IDLE 0
#define	_SERVED 1

static char		*prog_name;
static int svcstate = _IDLE;	/* Set when a request is serviced */
static int svccount = 0;	/* Number of requests being serviced */
static int svcstart_level = 0;	/* init level when server was started */
static mutex_t svcstate_lock;	/* lock for svcstate, svccount */

extern	void smserverprog_1(struct svc_req *, SVCXPRT *);

/*
 * Log messages
 */
#define	SIGACT_FAILED	"Failed to install signal handler for %s: %s"
#define	BADSIG_MSG	"Thread %d Caught signal %d addr=%p trapno=%d pc=%p"

static int	badsigs[] = {SIGSEGV, SIGBUS, SIGFPE, SIGILL};

/* global variables */
int		verbose		= DEFAULT_VERBOSE;
int		debug_level	= DEFAULT_DEBUG;
char		*smediad_devdir = DEFAULT_SMEDIAD_DEVDIR;

thread_key_t	door_key;

server_data_t	server_data;

static int	server_door, server_fd;

static int32_t do_uscsi_cmd(int32_t file, struct uscsi_cmd *uscsi_cmd,
		int32_t flag);
static void client_servproc(void *cookie, char *argp, size_t arg_size,
		door_desc_t *dp, uint_t ndesc);
static void cleanup(door_data_t *);
static void *init_server(void *);
static int32_t scsi_reassign_block(int32_t fd, diskaddr_t);
static int32_t get_mode_page(int32_t fd, uchar_t pc, uchar_t page_code,
	uchar_t *md_data, uchar_t data_len);
static int32_t get_device_type(char *v_name);
static int32_t get_device_type_scsi(int32_t fd, struct scsi_inquiry *inq);

static int32_t scsi_format(int32_t fd, uint_t flavor, uint_t mode);
static int32_t scsi_media_status(int32_t fd);
static int32_t scsi_write_protect(int32_t fd, smwp_state_t *wp);
static int32_t scsi_floppy_media_status(int32_t fd);
static int32_t scsi_floppy_write_protect(int32_t fd, smwp_state_t *wp);
static int32_t scsi_floppy_format(int32_t, uint_t, uint_t);
static int32_t get_floppy_geom(int32_t fd, uint32_t capacity,
			struct dk_geom *dkgeom);
static int32_t get_media_capacity(int32_t fd, uint32_t *capacity,
			uint32_t *blocksize);

static int32_t scsi_ls120_format(uint_t fd, uint_t flavor, uint32_t capacity,
			uint32_t blocksize);

static void *sm_server_thread(void *arg);
static void sm_door_server_create(door_info_t *dip);
static void term_handler(int sig, siginfo_t *siginfo, void *sigctx);
static void hup_handler(int sig, siginfo_t *siginfo, void *sigctx);
static void sig_handler(int sig, siginfo_t *siginfo, void *sigctx);
static void badsig_handler(int sig, siginfo_t *siginfo, void *sigctx);
static void server_badsig_handler(int sig, siginfo_t *siginfo, void *sigctx);
static char *xlate_state(int32_t);
static uint32_t	get_sector_size(int fd);
static int32_t raw_read(door_data_t *door_dp, smedia_services_t *req);
static int32_t raw_write(door_data_t *door_dp, smedia_services_t *req);
static int32_t reassign_block(door_data_t *door_dp, smedia_services_t *req);
static int32_t set_protection_status(door_data_t *door_dp,
			smedia_services_t *req);
static int32_t set_shfd(door_data_t *door_dp, int32_t fd,
			smedia_services_t *req);

static void door_ret_err(smedia_reterror_t *reterror, int32_t err);
static void my_door_return(char *data_ptr, size_t data_size,
			door_desc_t *desc_ptr, uint_t num_desc);
static int32_t invalid_uscsi_operation(door_data_t *, struct uscsi_cmd *);

#define	W_E_MASK	0x80

static smserver_info server_info;

static int32_t
invalid_uscsi_operation(door_data_t *door_dp, struct uscsi_cmd *ucmd)
{

	if (door_dp->dd_dkinfo.dki_ctype != DKC_CDROM) {
		debug(5,
		"Invalid device type(0x%x) found for uscsi cmd.\n",
			door_dp->dd_dkinfo.dki_ctype);
		errno = EINVAL;
		return (EINVAL);
	}
	if (ucmd->uscsi_flags & FORBIDDEN_FLAGS) {
		debug(5,
		"Invalid flags(0x%x) set in uscsi cmd. cdb[0]=0x%x\n",
		ucmd->uscsi_flags,  ucmd->uscsi_cdb[0]);
		errno = EINVAL;
		return (EINVAL);
	}
	if (ucmd->uscsi_cdb[0] == SCMD_COPY ||
	    ucmd->uscsi_cdb[0] == SCMD_COPY_VERIFY ||
	    ucmd->uscsi_cdb[0] == SCMD_COMPARE ||
	    ucmd->uscsi_cdb[0] == SCMD_WRITE_BUFFER) {
		debug(5,
		"Invalid command(0x%x) found in cdb.\n",
		ucmd->uscsi_cdb[0]);
		errno = EINVAL;
		return (EINVAL);
	}
	return (0);
}

static uint32_t
get_sector_size(int fd)
{
	uint32_t	sector_size;
	struct uscsi_cmd	ucmd;
	union scsi_cdb		cdb;
	int32_t		ret_val;
	uint32_t rc_data[2];
	char rq_data[RQ_LEN];

	cdb.scc_cmd = SCMD_READ_CAPACITY;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP1;
	ucmd.uscsi_bufaddr = (caddr_t)&rc_data;
	ucmd.uscsi_buflen = sizeof (rc_data);
	ucmd.uscsi_timeout = 120; /* If 0, HBA hangs forever */
	ucmd.uscsi_rqlen = RQ_LEN;
	ucmd.uscsi_rqbuf = rq_data;

	ret_val = do_uscsi_cmd(fd,
		&ucmd, USCSI_READ|USCSI_RQENABLE);
	if (ret_val || ucmd.uscsi_status) {
		debug(5, "Read capacity : %d - %d errno = %d\n",
			ret_val, ucmd.uscsi_status, errno);
		sector_size = 512;
	} else {
		sector_size = ntohl(rc_data[1]);
	}
	debug(5, "sector size = 0x%x(%d)\n",
		sector_size, sector_size);
	return (sector_size);
}

static char *
xlate_state(int32_t state)
{
	switch (state) {

	case SM_WRITE_PROTECT_DISABLE:
		return ("PROTECTION_DISABLED");
	case SM_WRITE_PROTECT_PASSWD:
		return ("WRITE_PROTECT_PASSWD");
	case SM_WRITE_PROTECT_NOPASSWD:
		return ("WRITE_PROTECT_NOPASSWD");
	case SM_READ_WRITE_PROTECT:
		return ("READ_WRITE_PROTECT");
	case SM_TEMP_UNLOCK_MODE:
		return ("PROTECTION DISABLED");
	default:
		return ("UNKNOWN_STATE");
	}
}

static char *
xlate_cnum(smedia_callnumber_t cnum)
{
	switch (cnum) {

	case SMEDIA_CNUM_OPEN_FD:
		return ("SMEDIA_CNUM_OPEN_FD");
	case SMEDIA_CNUM_GET_DEVICE_INFO:
		return ("SMEDIA_CNUM_GET_DEVICE_INFO");
	case SMEDIA_CNUM_GET_MEDIUM_PROPERTY:
		return ("SMEDIA_CNUM_GET_MEDIUM_PROPERTY");
	case SMEDIA_CNUM_GET_PROTECTION_STATUS:
		return ("SMEDIA_CNUM_GET_PROTECTION_STATUS");
	case SMEDIA_CNUM_SET_PROTECTION_STATUS:
		return ("SMEDIA_CNUM_SET_PROTECTION_STATUS");
	case SMEDIA_CNUM_RAW_READ:
		return ("SMEDIA_CNUM_RAW_READ");
	case SMEDIA_CNUM_RAW_WRITE:
		return (" SMEDIA_CNUM_RAW_WRITE");
	case SMEDIA_CNUM_FORMAT:
		return ("SMEDIA_CNUM_FORMAT");
	case SMEDIA_CNUM_CHECK_FORMAT_STATUS:
		return ("SMEDIA_CNUM_CHECK_FORMAT_STATUS");
	case SMEDIA_CNUM_EJECT:
		return ("SMEDIA_CNUM_EJECT");
	case SMEDIA_CNUM_REASSIGN_BLOCK:
		return ("SMEDIA_CNUM_REASSIGN_BLOCK");
	case SMEDIA_CNUM_SET_SHFD:
		return ("SMEDIA_CNUM_SET_SHFD");
	case SMEDIA_CNUM_PING:
		return ("SMEDIA_CNUM_PING");
	case SMEDIA_CNUM_USCSI_CMD:
		return ("SMEDIA_CNUM_USCSI_CMD");
	default:
		return ("UNKNOWN_CNUM");
	}
}

/*ARGSUSED*/
smserver_info *
smserverproc_get_serverinfo_1(void *argp, CLIENT *clnt)
{
	(void) mutex_lock(&svcstate_lock);
	svcstate = _SERVED;
	(void) mutex_unlock(&svcstate_lock);
	server_info.vernum = SMSERVERVERS;
	server_info.status = 0;
	(void) mutex_lock(&server_data.sd_init_lock);
	if (server_data.sd_init_state == INIT_NOT_DONE) {
		server_data.sd_init_state = INIT_IN_PROGRESS;
		debug(5, "Initialising server\n");
		(void) init_server(NULL);
	}
	if (server_data.sd_init_state != INIT_DONE) {
		debug(1, "init_server did not do the job. "
		    "init_state=%d\n", server_data.sd_init_state);
		server_data.sd_init_state = INIT_NOT_DONE;
		(void) mutex_unlock(&server_data.sd_init_lock);
		server_info.status = -1;
		return (&server_info);
	}
	(void) mutex_unlock(&server_data.sd_init_lock);

	debug(5, "smserverproc thread %d running....\n", pthread_self());
	return (&server_info);
}

/*ARGSUSED*/
static void
server_badsig_handler(int sig, siginfo_t *siginfo, void *sigctx)
{

	fatal(gettext(BADSIG_MSG), pthread_self(), sig, siginfo->si_addr,
		siginfo->si_trapno,
		siginfo->si_pc);
}

static int32_t
do_uscsi_cmd(int32_t file, struct uscsi_cmd *uscsi_cmd, int32_t	flag)
{
	int32_t	ret_val;

	/*
	 * Set function flags for driver.
	 */
	uscsi_cmd->uscsi_flags = USCSI_ISOLATE;

#ifdef DEBUG
	uscsi_cmd->uscsi_flags |= USCSI_DIAGNOSE;
#else
	uscsi_cmd->uscsi_flags |= USCSI_SILENT;
#endif /* DEBUG */

	uscsi_cmd->uscsi_flags |= flag;

	errno = 0;
	ret_val = ioctl(file, USCSICMD, uscsi_cmd);
	if (ret_val == 0 && uscsi_cmd->uscsi_status == 0) {
		return (ret_val);
	}
	if (!errno)
		errno = EIO;
	return (-1);
}

static int32_t
get_device_type(char *v_name)
{
	int32_t i;

	for (i = 0; i < 8; i++) {
		v_name[i] = toupper(v_name[i]);
	}
	if (strstr(v_name, "IOMEGA")) {
		return (SCSI_IOMEGA);
	}
	if (strstr(v_name, "FD") ||
	    strstr(v_name, "LS-120")) {
		return (SCSI_FLOPPY);
	}
	return (SCSI_GENERIC);

}

static int32_t
get_device_type_scsi(int32_t fd, struct scsi_inquiry *inq)
{
	int32_t dev_type;
	struct uscsi_cmd ucmd;
	union scsi_cdb  cdb;
	int32_t	ret_val;
	char rq_data[RQ_LEN];

	(void) memset((void *) inq, 0, sizeof (struct scsi_inquiry));
	(void) memset((void *) &ucmd, 0, sizeof (ucmd));
	(void) memset((void *) &cdb, 0, sizeof (union scsi_cdb));
	cdb.scc_cmd = SCMD_INQUIRY;
	FORMG0COUNT(&cdb, sizeof (struct scsi_inquiry));
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = (caddr_t)inq;
	ucmd.uscsi_buflen = sizeof (struct scsi_inquiry);
	ucmd.uscsi_timeout = 120;	/* If 0, HBA hangs forever */
	ucmd.uscsi_rqlen = RQ_LEN;
	ucmd.uscsi_rqbuf = rq_data;
	ret_val = do_uscsi_cmd(fd, &ucmd, USCSI_READ|USCSI_RQENABLE);
	if (ret_val || ucmd.uscsi_status) {
		debug(5, "INQUIRY failed: rv = %d  uscsi_status = "
		    "%d  errno = %d\n", ret_val, ucmd.uscsi_status, errno);
		return (-1);
	}

	dev_type = get_device_type(inq->inq_vid);

	debug(5, "dev_type %d\n", dev_type);
	return (dev_type);

}

static int32_t
get_media_capacity(int32_t fd, uint32_t *capacity, uint32_t *blocksize)
{
	struct uscsi_cmd ucmd;
	uchar_t cdb[12];
	int32_t ret_val;
	uchar_t data[20];
	char rq_data[RQ_LEN];

	debug(5, "get_media_capacity:\n");

	(void) memset((void *)&data, 0, sizeof (data));
	(void) memset((void *)&ucmd, 0, sizeof (ucmd));
	(void) memset((void *)&cdb, 0, sizeof (cdb));

	/* retrieve size discriptor of inserted media */
	cdb[0] = SCMD_READ_FORMAT_CAP;
	cdb[8] = 0x14;  /* data size */

	/* Fill in the USCSI fields */
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP5;
	ucmd.uscsi_bufaddr = (caddr_t)data;
	ucmd.uscsi_buflen = sizeof (data);
	ucmd.uscsi_timeout = 120;
	ucmd.uscsi_rqlen = RQ_LEN;
	ucmd.uscsi_rqbuf = rq_data;
	ret_val = do_uscsi_cmd(fd, &ucmd, USCSI_READ|USCSI_RQENABLE);

	if (ret_val || ucmd.uscsi_status) {
		debug(5, "Retrieving media info failed: %d - %d\n", ret_val,
		    ucmd.uscsi_status);

		if ((rq_data[2] == KEY_DATA_PROTECT) && (rq_data[12] == 0x30) &&
		    (rq_data[13] == 0)) {
			(void) debug(1, "Invalid command for media\n");
			errno = EINVAL;
		}
		return (-1);
	}

	/* No media, bail out */
	if (data[8] == 0x3) {
		(void) debug(5, "no media in drive\n");
		return (-1);
	}

	/*
	 * Generate capacity and blocksize information
	 */

	*capacity =  (uint32_t)((data[4] << 24) + (data[5] << 16) +
	    (data[6] << 8) + data[7]);

	debug(1, "capacity is %x %x %x %x = %x", data[4], data[5], data[6],
	    data[7], *capacity);

	*blocksize = (uint32_t)((data[9] << 16) + (data[10] << 8) + data[11]);

	return (0);
}

static int32_t
scsi_zip_format(int32_t fd, uint_t flavor, uint_t mode)
{
	struct uscsi_cmd ucmd;
	struct scsi_inquiry inq;
	uchar_t cdb[12];
	int32_t   ret_val;
	uchar_t data[4];
	uint32_t rc_data[2];
	char rq_data[RQ_LEN];
	uint32_t capacity;


	if ((mode != SM_FORMAT_IMMEDIATE) &&
		(mode != SM_FORMAT_BLOCKED)) {
		errno = ENOTSUP;
		return (ENOTSUP);
	}
	/*
	 * Do an inquiry and try to figure out if it an
	 * IOMEGA JAZ 2GB device.
	 */

	(void) memset((void *) &inq, 0, sizeof (inq));
	(void) memset((void *) &ucmd, 0, sizeof (ucmd));
	(void) memset((void *) &cdb, 0, sizeof (cdb));
	(void) memset((void *) &rq_data, 0, sizeof (rq_data));
	cdb[0] = SCMD_INQUIRY;
	cdb[4] = sizeof (inq);
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = (caddr_t)&inq;
	ucmd.uscsi_buflen = sizeof (inq);
	ucmd.uscsi_timeout = 120;	/* If 0, HBA hangs forever */
	ucmd.uscsi_rqlen = RQ_LEN;
	ucmd.uscsi_rqbuf = rq_data;
	ret_val = do_uscsi_cmd(fd, &ucmd, USCSI_READ|USCSI_RQENABLE);
	if (ret_val || ucmd.uscsi_status) {
		debug(5, "inquiry failed: %d - %d errno = %d\n",
			ret_val, ucmd.uscsi_status, errno);
		return (ucmd.uscsi_status);
	}

	(void) memset((void *) &rc_data, 0, sizeof (rc_data));
	(void) memset((void *) &ucmd, 0, sizeof (ucmd));
	(void) memset((void *) &cdb, 0, sizeof (cdb));
	cdb[0] = SCMD_READ_CAPACITY;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP1;
	ucmd.uscsi_bufaddr = (caddr_t)&rc_data;
	ucmd.uscsi_buflen = sizeof (rc_data);
	ucmd.uscsi_timeout = 120;	/* If 0, HBA hangs forever */

	ret_val = do_uscsi_cmd(fd, &ucmd, USCSI_READ);
	if (ret_val || ucmd.uscsi_status) {
		debug(5, "Read capacity : %d - %d errno = %d\n",
			ret_val, ucmd.uscsi_status, errno);
		return (ucmd.uscsi_status);
	}

	capacity = ntohl(rc_data[0]);

	(void) memset((void *)&data, 0, sizeof (data));
	(void) memset((void *)&ucmd, 0, sizeof (ucmd));
	(void) memset((void *)&cdb, 0, sizeof (cdb));
	cdb[0] =  SCMD_FORMAT;
	/*
	 * Defect list sent by initiator is a complete list of defects.
	 */
	cdb[1] = (FMTDATA | CMPLIST);
	/*
	 * Target should examine the setting of the DPRY, DCRT, STPF, IP
	 * and DSP bits.
	 */
	data[1] = FOV;

	switch (flavor) {
		case SM_FORMAT_QUICK :
			/*
			 * Target should not perform any vendor specific
			 * medium certification process or format verification
			 */
			data[1] = (FOV | DCRT);
			/*
			 * Defect list sent is an addition to the existing
			 * list of defects.
			 */
			cdb[1] =  FMTDATA;
			break;
		case SM_FORMAT_FORCE :
			if (strstr(inq.inq_pid, "jaz")) {
				debug(1,
				"LONG Format of JAZ media not supported\n");
				errno = ENOTSUP;
				return (ENOTSUP);
			}
			/*
			 * Formatting a write-protected or read/write
			 * protected cartridge is allowed.
			 * This is a vendor specific Format Option.
			 */
			cdb[2] = 0x20;
			break;
		case SM_FORMAT_LONG :
			if (strstr(inq.inq_pid, "jaz")) {
				debug(1,
				"LONG Format of JAZ media not supported\n");
				errno = ENOTSUP;
				return (ENOTSUP);
			}
			/*
			 * Defect list sent is an addition to the existing
			 * list of defects.
			 */
			cdb[1] = FMTDATA;
			break;
		default :
			debug(1, "Format option %d not supported!!\n",
			flavor);
			errno = ENOTSUP;
			return (ENOTSUP);
	}

	if (mode == SM_FORMAT_IMMEDIATE) {
		data[1] |= IMMED;
		debug(5, "immediate_flag set\n");
	}

	ucmd.uscsi_cdb = (caddr_t)&cdb;
	debug(5, "cdb: %x ", cdb[0]);
	debug(5, "%x %x ", cdb[1], cdb[2]);
	debug(5, "%x %x %x\n", cdb[3], cdb[4], cdb[5]);
	debug(5, "data: %x %x %x %x\n", data[0], data[1], data[2], data[3]);

	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = (caddr_t)data;
	ucmd.uscsi_buflen = sizeof (data);
	ucmd.uscsi_timeout = FORMAT_TIMEOUT(capacity);
	ucmd.uscsi_rqlen = RQ_LEN;
	ucmd.uscsi_rqbuf = rq_data;
	ret_val = do_uscsi_cmd(fd, &ucmd, USCSI_WRITE|USCSI_RQENABLE);
	if (ret_val || ucmd.uscsi_status) {
		debug(5, "Format failed : %d - uscsi_status = %d errno = %d\n",
			ret_val,
			ucmd.uscsi_status, errno);
		if ((rq_data[2] == KEY_DATA_PROTECT) ||
			(rq_data[2] == KEY_ILLEGAL_REQUEST))
			errno = EINVAL;
		if ((rq_data[2] == KEY_MEDIUM_ERROR) ||
			(rq_data[2] == KEY_HARDWARE_ERROR))
			errno = EIO;
		return (errno);
	}

	return (0);
}

static int32_t
scsi_ls120_format(uint_t fd, uint_t flavor, uint32_t capacity,
    uint32_t blocksize)
{
	struct uscsi_cmd ucmd;
	uchar_t cdb[12];
	int32_t ret_val;
	uchar_t data[12];
	char	rq_data[RQ_LEN];

	debug(5, "scsi_ls120_format:\n");

	(void) memset((void *) &ucmd, 0, sizeof (ucmd));
	(void) memset((void *) &cdb, 0, sizeof (cdb));
	(void) memset((void *) &rq_data, 0, sizeof (rq_data));

	cdb[0] = SCMD_FORMAT;
	cdb[1] = (FMTDATA | 0x7);
	cdb[8] = 0x0C; /* parameter list length */

	data[1] = 0x80;
	data[3] = 0x08;


	data[4] = (capacity >> 24) & 0xff;
	data[5] = (capacity >> 16) & 0xff;
	data[6] = (capacity >> 8) & 0xff;
	data[7] = capacity & 0xff;


	data[9] =  (blocksize >> 16) & 0xff;
	data[10] = (blocksize >> 8) & 0xff;
	data[11] = blocksize & 0xff;

	debug(5, "cdb: %x %x %x ... %x", cdb[0], cdb[1], cdb[2], cdb[8]);
	debug(5, "data: %x %x %x %x\n", data[0], data[1], data[2], data[3]);
	debug(5, "    : %x %x %x %x\n", data[4], data[5], data[6], data[7]);
	debug(5, "    : %x %x %x %x\n", data[8], data[9], data[10], data[11]);

	switch (flavor) {
		case SM_FORMAT_QUICK :
			debug(1, "Format not supported\n");
			errno = ENOTSUP;
			return (-1);
		case SM_FORMAT_FORCE :
			break;
		case SM_FORMAT_LONG :
			break;
		default :
			debug(1, "Format option not specified!!\n");
			errno = ENOTSUP;
			return (-1);
	}

	ucmd.uscsi_cdb = (caddr_t)&cdb;


	ucmd.uscsi_cdblen = CDB_GROUP5;
	ucmd.uscsi_bufaddr = (caddr_t)data;
	ucmd.uscsi_buflen = sizeof (data);
	ucmd.uscsi_timeout = 0x12c0;
	ucmd.uscsi_rqlen = RQ_LEN;
	ucmd.uscsi_rqbuf = rq_data;
	(void) fflush(stdout);

	ret_val = do_uscsi_cmd(fd, &ucmd, USCSI_WRITE|USCSI_RQENABLE);
	if (ret_val || ucmd.uscsi_status) {
		debug(1, "Format failed failed: %d - %d\n", ret_val,
		    ucmd.uscsi_status);

		if ((rq_data[2] == KEY_DATA_PROTECT) &&
		    (rq_data[12] == 0x30) && (rq_data[13] == 0)) {

			debug(1, "Invalid command for media\n");
			errno = EINVAL;
		}

		if ((rq_data[2] == KEY_NOT_READY) && (rq_data[12] == 0x30)) {
			debug(1, "Incompatible media.\n");
			errno = EINVAL;
		}

		return (-1);
	}

	return (0);
}

static int32_t
scsi_format(int32_t fd, uint_t flavor, uint_t mode)
{
	struct uscsi_cmd ucmd;
	struct scsi_inquiry inq;
	uchar_t cdb[12];
	int32_t   ret_val;
	uchar_t data[4];
	char rq_data[RQ_LEN];
	uint32_t rc_data[2];
	uint32_t capacity;



	if ((mode != SM_FORMAT_IMMEDIATE) &&
		(mode != SM_FORMAT_BLOCKED)) {
		errno = ENOTSUP;
		return (-1);
	}

	/*
	 * Do an inquiry and try to figure out if it an
	 * IOMEGA JAZ 2GB device.
	 */

	(void) memset((void *) &inq, 0, sizeof (inq));
	(void) memset((void *) &ucmd, 0, sizeof (ucmd));
	(void) memset((void *) &cdb, 0, sizeof (cdb));
	(void) memset((void *) &rq_data, 0, sizeof (rq_data));
	cdb[0] = SCMD_INQUIRY;
	cdb[4] = sizeof (inq);
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = (caddr_t)&inq;
	ucmd.uscsi_buflen = sizeof (inq);
	ucmd.uscsi_timeout = 120;	/* If 0, HBA hangs forever */
	ucmd.uscsi_rqlen = RQ_LEN;
	ucmd.uscsi_rqbuf = rq_data;
	ret_val = do_uscsi_cmd(fd, &ucmd, USCSI_READ|USCSI_RQENABLE);
	if (ret_val || ucmd.uscsi_status) {
		debug(5, "inquiry failed: %d - %d errno = %d\n",
			ret_val, ucmd.uscsi_status, errno);
		return (ucmd.uscsi_status);
	}

	(void) memset((void *) &rc_data, 0, sizeof (rc_data));
	(void) memset((void *) &ucmd, 0, sizeof (ucmd));
	(void) memset((void *) &cdb, 0, sizeof (cdb));
	cdb[0] = SCMD_READ_CAPACITY;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP1;
	ucmd.uscsi_bufaddr = (caddr_t)&rc_data;
	ucmd.uscsi_buflen = sizeof (rc_data);
	ucmd.uscsi_timeout = 120;	/* If 0, HBA hangs forever */

	ret_val = do_uscsi_cmd(fd, &ucmd, USCSI_READ);
	if (ret_val || ucmd.uscsi_status) {
		debug(5, "Read capacity : %d - %d errno = %d\n",
			ret_val, ucmd.uscsi_status, errno);
		return (ucmd.uscsi_status);
	}

	capacity = ntohl(rc_data[0]);

	(void) memset((void *)&data, 0, sizeof (data));
	(void) memset((void *)&ucmd, 0, sizeof (ucmd));
	(void) memset((void *)&cdb, 0, sizeof (cdb));
	cdb[0] =  SCMD_FORMAT;
	/*
	 * Defect list sent is an addition to the existing
	 * list of defects.
	 */
	cdb[1] =  FMTDATA;
	/*
	 * Target should examine the setting of the DPRY, DCRT, STPF, IP
	 * and DSP bits.
	 */
	data[1] = FOV;

	if (mode == SM_FORMAT_IMMEDIATE) {
		debug(5,
	"SM_FORMAT_IMMEDIATE specified ignored. Performing a long format!\n");
	}

	switch (flavor) {
		case SM_FORMAT_LONG :
			if (strstr(inq.inq_pid, "jaz")) {
				debug(1,
				"LONG Format of JAZ media not supported\n");
				errno = ENOTSUP;
				return (ENOTSUP);
			}
			/*
			 * Defect list sent is an addition to the existing
			 * list of defects.
			 */
			cdb[1] = FMTDATA;
			break;
		default :
			debug(1, "Format option %d  not supported!!\n",
			flavor);
			errno = ENOTSUP;
			return (ENOTSUP);
	}


	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = (caddr_t)data;
	ucmd.uscsi_buflen = sizeof (data);
	ucmd.uscsi_timeout = FORMAT_TIMEOUT(capacity);
	ucmd.uscsi_rqlen = RQ_LEN;
	ucmd.uscsi_rqbuf = rq_data;
	ret_val = do_uscsi_cmd(fd, &ucmd, USCSI_WRITE|USCSI_RQENABLE);
	if (ret_val || ucmd.uscsi_status) {
		debug(5, "Format failed failed: %d - %d errno = %d\n",
			ret_val, ucmd.uscsi_status, errno);
		return (ucmd.uscsi_status);
	}

	return (0);
}

static int32_t
scsi_media_status(int32_t fd)
{
	struct mode_header modeh;
	struct uscsi_cmd ucmd;
	union scsi_cdb  cdb;
	int32_t ret_val;
	int32_t cur_status;
	char rq_data[RQ_LEN];

	debug(10, "SCSI MEDIA STATUS CALLED \n");

	(void) memset((void *) &modeh, 0, sizeof (modeh));
	(void) memset((void *) &ucmd, 0, sizeof (ucmd));
	(void) memset((void *) &cdb, 0, sizeof (union scsi_cdb));
	cdb.scc_cmd = SCMD_MODE_SENSE;
	cdb.cdb_opaque[2] = MODEPAGE_ALLPAGES;
	FORMG0COUNT(&cdb, sizeof (modeh));

	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = (caddr_t)&modeh;
	ucmd.uscsi_buflen = sizeof (modeh);
	ucmd.uscsi_timeout = 120;	/* If 0, HBA hangs forever */
	ucmd.uscsi_rqlen = RQ_LEN;
	ucmd.uscsi_rqbuf = rq_data;
	ret_val = do_uscsi_cmd(fd, &ucmd, USCSI_READ|USCSI_RQENABLE);
	if (ret_val || ucmd.uscsi_status) {
		debug(5, "Modesense for 0x3f pages failed: %d-%d errno=%d\n",
			ret_val, ucmd.uscsi_status, errno);
		cdb.cdb_opaque[2] = 0;
		ucmd.uscsi_rqlen = RQ_LEN;
		FORMG0COUNT(&cdb, sizeof (modeh));
		ret_val = do_uscsi_cmd(fd, &ucmd, USCSI_READ|USCSI_RQENABLE);
		if (ret_val || ucmd.uscsi_status) {
			debug(5, "Modesense failed: %d - %d errno = %d\n",
				ret_val, ucmd.uscsi_status, errno);
			return (-1);
		}
	}

	if (modeh.device_specific & W_E_MASK) {
		cur_status = SM_WRITE_PROTECT_NOPASSWD;
	} else {
		cur_status = SM_WRITE_PROTECT_DISABLE;
	}
	debug(5, "cur status %d\n", cur_status);

	return (cur_status);
}

static int32_t
scsi_zip_media_status(int32_t fd)
{
	struct uscsi_cmd ucmd;
	uchar_t cdb[12];
	int32_t	status;
	int32_t mode;
	uchar_t data[64];
	char rq_data[RQ_LEN];

	debug(10, "Getting media status\n");

	(void) memset((void *)&ucmd, 0, sizeof (ucmd));
	(void) memset((void *)&cdb, 0, sizeof (cdb));

	cdb[0] = IOMEGA_NONSENSE_CMD;
	cdb[2] = CARTRIDGE_STATUS_PAGE;
	cdb[4] = ND_LENGTH;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = (caddr_t)data;
	ucmd.uscsi_buflen = 64;
	ucmd.uscsi_timeout = 120;	/* If 0, HBA hangs forever */
	ucmd.uscsi_rqlen = RQ_LEN;
	ucmd.uscsi_rqbuf = rq_data;
	status = do_uscsi_cmd(fd, &ucmd, USCSI_READ|USCSI_RQENABLE);
	if (status || ucmd.uscsi_status) {
		debug(5, "Cartridge protect operation failed: "
		    "rv = %d  uscsi_status = %d  errno = %d\n",
		    status, ucmd.uscsi_status, errno);
		return (-1);
	}

	if (data[DISK_STATUS_OFFSET + NON_SENSE_HDR_LEN] == 4) {
		debug(1, "Disk not present. \n");
		return (-1);
	}
	mode = data[PROTECT_MODE_OFFSET + NON_SENSE_HDR_LEN] & 0xF;

	debug(5, "MODE 0x%x / %d.\n", mode, mode);

	switch (mode) {
		case UNLOCK_MODE:
			status = SM_WRITE_PROTECT_DISABLE;
			break;
		case WRITE_PROTECT_MODE:
			status = SM_WRITE_PROTECT_NOPASSWD;
			break;
		case PASSWD_WRITE_PROTECT_MODE:
			status = SM_WRITE_PROTECT_PASSWD;
			break;
		case READ_WRITE_PROTECT_MODE:
			status = SM_READ_WRITE_PROTECT;
			break;
		default :
			if (mode & TEMP_UNLOCK_MODE)
				status = SM_TEMP_UNLOCK_MODE;
			else
				status = SM_STATUS_UNKNOWN;
			break;
	}

	debug(5, "status %d \n", status);
	return (status);
}

static int32_t
scsi_reassign_block(int32_t fd, diskaddr_t block)
{
	uchar_t data[8];
	struct uscsi_cmd ucmd;
	char cdb[12];
	int32_t	ret_val;
	char rq_data[RQ_LEN];

	debug(5, "SCSI REASSIGN CALLED block = %lld\n", block);

	(void) memset((void *) &data, 0, sizeof (data));
	(void) memset((void *) &ucmd, 0, sizeof (ucmd));
	(void) memset((void *) &cdb, 0, sizeof (cdb));
	cdb[0] = SCMD_REASSIGN_BLOCK;
	data[3] = 4;
	data[4] = ((block & 0xFF000000) >> 24);
	data[5] = ((block & 0xFF0000) >> 16);
	data[6] = ((block & 0xFF00) >> 8);
	data[7] = block & 0xFF;

	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = (caddr_t)data;
	ucmd.uscsi_buflen = sizeof (data);
	ucmd.uscsi_timeout = 120;	/* If 0, HBA hangs forever */
	ucmd.uscsi_rqlen = RQ_LEN;
	ucmd.uscsi_rqbuf = rq_data;
	ret_val = do_uscsi_cmd(fd, &ucmd, USCSI_WRITE|USCSI_RQENABLE);
	if (ret_val || ucmd.uscsi_status) {
		debug(5, "Reassign block failed: %d - %d errno = %d\n",
			ret_val, ucmd.uscsi_status, errno);
		return (-1);
	}

	return (0);
}

static int32_t
get_mode_page(int32_t fd, uchar_t pc, uchar_t page_code,
    uchar_t *md_data, uchar_t data_len)
{
	struct uscsi_cmd ucmd;
	uchar_t cdb[12];
	int32_t	ret_val;
	char rq_data[RQ_LEN];

	debug(10, "MODE SENSE(6) - page_code = 0x%x\n", page_code);

	(void) memset((void *) md_data, 0, sizeof (data_len));
	(void) memset((void *) &ucmd, 0, sizeof (ucmd));
	(void) memset((void *) &cdb, 0, sizeof (cdb));
	cdb[0] = SCMD_MODE_SENSE;
	cdb[2] = (pc << 6) | page_code;
	cdb[4] = data_len;

	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = (caddr_t)md_data;
	ucmd.uscsi_buflen = data_len;
	ucmd.uscsi_timeout = 120;	/* If 0, HBA hangs forever */
	ucmd.uscsi_rqlen = RQ_LEN;
	ucmd.uscsi_rqbuf = rq_data;
	ret_val = do_uscsi_cmd(fd, &ucmd, USCSI_READ|USCSI_RQENABLE);
	if (ret_val || ucmd.uscsi_status) {
		debug(5, "Modesense failed: %d - %d errno = %d\n",
			ret_val, ucmd.uscsi_status, errno);
		return (-2);
	}

	return (0);
}

static int32_t
scsi_zip_write_protect(int32_t fd, smwp_state_t *wp)
{
	struct uscsi_cmd ucmd;
	struct scsi_inquiry inq;
	uchar_t cdb[12];
	int32_t	status;
	int32_t new_mode;
	char rq_data[RQ_LEN];
	int32_t wa_bit;
	char *tmp_passwd = NULL;

	debug(10, "SCSI ZIP WRITE PROTECT CALLED \n");

	/*
	 * Do an inquiry and try to figure out if it an
	 * ATAPI or SCSI device.
	 */

	(void) memset((void *) &inq, 0, sizeof (inq));
	(void) memset((void *) &ucmd, 0, sizeof (ucmd));
	(void) memset((void *) &cdb, 0, sizeof (cdb));
	(void) memset((void *) &rq_data, 0, sizeof (rq_data));
	cdb[0] = SCMD_INQUIRY;
	cdb[4] = sizeof (inq);
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = (caddr_t)&inq;
	ucmd.uscsi_buflen = sizeof (inq);
	ucmd.uscsi_timeout = 120;	/* If 0, HBA hangs forever */
	ucmd.uscsi_rqlen = RQ_LEN;
	ucmd.uscsi_rqbuf = rq_data;
	status = do_uscsi_cmd(fd, &ucmd, USCSI_READ|USCSI_RQENABLE);
	if (status || ucmd.uscsi_status) {
		debug(5, "inquiry failed: %d - %d errno = %d\n",
			status, ucmd.uscsi_status, errno);
		return (-1);
	}

	if (inq.inq_ansi > 0) {
		wa_bit = 0;
		debug(5, "SCSI device\n");
	} else {
		wa_bit = 1;
		debug(5, "ATAPI device\n");
	}

	switch (wp->sm_new_state) {
		case SM_WRITE_PROTECT_DISABLE :
			new_mode = 0x0;
			break;
		case SM_WRITE_PROTECT_NOPASSWD :
			new_mode = 0x2;
			break;
		case SM_WRITE_PROTECT_PASSWD :
			new_mode = 0x3;
			break;
		case SM_READ_WRITE_PROTECT :
			new_mode = 0x5;
			break;
		case SM_TEMP_UNLOCK_MODE :
			new_mode = 0x8;
			break;
		default :
			debug(1, "Invalid mode 0x%x specified\n",
			wp->sm_new_state);
			errno = ENOTSUP;
			return (-1);
	}


	(void) memset((void *)&ucmd, 0, sizeof (ucmd));
	(void) memset((void *)&cdb, 0, sizeof (cdb));
	(void) memset((void *) &rq_data, 0, sizeof (rq_data));
	cdb[0] = IOMEGA_CATRIDGE_PROTECT;
	cdb[1] |= new_mode;
	if (wa_bit)
		cdb[1] |= WA_BIT;
	cdb[4] = wp->sm_passwd_len;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	if (wa_bit && (wp->sm_passwd_len & 1)) {
		/*
		 * Oops, ATAPI device with an odd length passwd!
		 * Allocate a buffer to hold one extra byte.
		 */
		debug(5, "Odd len passwd for ATAPI device!\n");
		errno = 0;
		tmp_passwd = (char *)malloc(wp->sm_passwd_len+1);
		if (tmp_passwd == NULL) {
			if (errno == 0)
				errno = ENOMEM;
			return (-1);
		}
		(void) memset(tmp_passwd, 0, wp->sm_passwd_len+1);
		(void) memcpy(tmp_passwd, wp->sm_passwd, wp->sm_passwd_len);
		ucmd.uscsi_bufaddr = (caddr_t)tmp_passwd;
		ucmd.uscsi_buflen = wp->sm_passwd_len+1;
	} else {
		ucmd.uscsi_bufaddr = (caddr_t)wp->sm_passwd;
		ucmd.uscsi_buflen = wp->sm_passwd_len;
	}
	ucmd.uscsi_timeout = 120;	/* If 0, HBA hangs forever */
	ucmd.uscsi_rqlen = RQ_LEN;
	ucmd.uscsi_rqbuf = rq_data;
	status = do_uscsi_cmd(fd, &ucmd, USCSI_WRITE|USCSI_RQENABLE);
	if (tmp_passwd != NULL) {
		free(tmp_passwd);
	}
	if (status || ucmd.uscsi_status) {
		debug(5, "Cartridge-protect operation failed: rv "
		    "= %d  uscsi_status = %d  errno = %d\n", status,
		    ucmd.uscsi_status, errno);
		if ((rq_data[2] & 0xF) == KEY_ILLEGAL_REQUEST) {
			if (rq_data[12] == 0x26) {
				/* Wrong passwd */
				debug(5, "Protection Request with wrong "
				    "passwd. errno is being set to EACCES.\n");
				errno = EACCES;
			}
		}
		return (-1);
	}

	return (0);
}

/*ARGSUSED*/
static int32_t
scsi_write_protect(int32_t fd, smwp_state_t *wp)
{
	errno = ENOTSUP;
	return (-1);
}

/*
 * This thread becomes the server-side thread used in
 * the implementation of a door_call between a client
 * and the Client Door.
 *
 * This thread is customized both by the door_server_create(3c)
 * function sm_door_server_create, as well as by itself.
 *
 * This thread needs to synchronize with the
 * main_servproc[SMEDIA_CNUM_OPEN_FD] door_call in terms of
 * both successful and failure scenarios.  main_servproc
 * locks dd_lock before calling door_create.  This thread
 * then attempts to lock, but will block until main_servproc
 * has either created all doors it requires, or until a
 * door_create has failed (door_create's return and the
 * creation of an associated thread are asynchronous).
 *
 * If door_create failed, this thread will be able to obtain
 * dd_lock and call pthread_exit.  If all door_create's succeed,
 * this thread will obtain dd_lock and commence with
 * customizing the thread's attributes.  door_bind is called to
 * bind this thread to the per-door private thread pool, and
 * main_servproc is cond_signal'd to avail it of this fact.
 *
 * Finally, this thread calls door_return, which causes it to
 * commence its lifetime as a server-side thread in implementation
 * of a Client Door door_call.
 */
static void *
sm_server_thread(void *arg)
{
	door_data_t	*door_dp;
	struct		sigaction act;
	int		i;
	int		err;

	door_dp = (door_data_t *)arg;

	if (door_dp == NULL) {
		fatal("sm_server_thread[%d]: argument is NULL!!\n",
		    pthread_self());
		exit(-1);
	}

	/* Wait for Client Door to be created */
	(void) mutex_lock(&door_dp->dd_lock);
	if (door_dp->dd_cdoor_descriptor < 0) {
		debug(5, "sm_server_thread[%d]: door_create() failed",
		    pthread_self());
		(void) mutex_unlock(&door_dp->dd_lock);
		pthread_exit((void *)-2);
	}
	(void) mutex_unlock(&door_dp->dd_lock);

	for (i = 0; i < N_BADSIGS; i++) {
		act.sa_sigaction = server_badsig_handler;
		(void) sigemptyset(&act.sa_mask);
		act.sa_flags = SA_SIGINFO;
		if (sigaction(badsigs[i], &act, NULL) == -1)
			warning(gettext(SIGACT_FAILED), strsignal(badsigs[i]),
			    strerror(errno));
	}
	if (sigemptyset(&door_dp->dd_newset) != 0)
		warning(gettext("sigemptyset failed. errno = %d\n"),
		    errno);
	if ((err = pthread_sigmask(SIG_BLOCK, &door_dp->dd_newset, NULL)) != 0)
		warning(gettext("pthread_sigmask failed = %d\n"), err);

	/* Bind thread with pool associated with Client Door */

	if (door_bind(door_dp->dd_cdoor_descriptor) < 0) {
		fatal("door_bind");
		exit(-1);
	}
	debug(5, "thr[%d] bound to Client Door[%d]", pthread_self(),
	    door_dp->dd_cdoor_descriptor);

	/*
	 * Set these two cancellation(7) attributes.  Ensure that the
	 * pthread we create has cancellation(7) DISABLED and DEFERRED,
	 * as our implementation is based on this.  DEFERRED is the
	 * default, but set it anyways, in case the defaults change in
	 * the future.
	 */
	if ((err = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL)) != 0)
		warning(gettext("pthread_setcancelstate(PTHREAD_CANCEL_DISABLE)"
		    " failed = %d\n"), err);
	if ((err = pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED,
	    NULL)) != 0)
		warning(gettext("pthread_setcanceltype(DEFERRED) "
		    "failed = %d\n"), err);

	/* Inform main_servproc that door_bind() is complete. */
	(void) cond_signal(&door_dp->dd_cv_bind);

	/*
	 * Per doors protocol, transfer control to the doors-runtime in
	 * order to make this thread available to answer future door_call()'s.
	 */
	(void) door_return(NULL, 0, NULL, 0);
	return (NULL);
}

/*
 * This function cleans up all per-connection resources.
 *
 * This function is called when the Client Door's service procedure
 * (client_servproc) is called w/ DOOR_UNREF_DATA, which is the
 * doors protocol convention stating that the number of file
 * descriptors referring to this door has dropped to one.
 * client_servproc is passed DOOR_UNREF_DATA because the Client Door
 * was door_create'd with the DOOR_UNREF bitflag.
 */
static void
cleanup(door_data_t *door_dp)
{
	/* do door_revoke() of Death Door */
	if (door_dp->dd_ddoor_descriptor >= 0) {
		debug(1, "cleanup[%d]: door_revoke() Death Door[%d]",
		    pthread_self(), door_dp->dd_ddoor_descriptor);

		if (door_revoke(door_dp->dd_ddoor_descriptor) < 0) {
			warning(gettext("cleanup[%d]: door_revoke() of Death "
			    "Door(%d) failed = %d"), pthread_self(),
			    door_dp->dd_ddoor_descriptor, errno);
		} else {
			door_dp->dd_ddoor_descriptor = -1;
		}
	}

	/* release memory that is shared between client and (our) server */
	if (door_dp->dd_buffd >= 0) {
		debug(1, "cleanup[%d]: release shared memory", pthread_self());
		(void) munmap(door_dp->dd_buf, door_dp->dd_buf_len);
		(void) close(door_dp->dd_buffd);

		door_dp->dd_buffd = -1;
		door_dp->dd_buf = NULL;
		door_dp->dd_buf_len = 0;
	}

	/* close the (target) device that the Client is operating on */
	if (door_dp->dd_fd >= 0) {
		debug(1, "cleanup[%d]: close(%d) target device", pthread_self(),
		    door_dp->dd_fd);
		if (close(door_dp->dd_fd) < 0) {
			warning(gettext("cleanup[%d]: close() of target device"
			    "failed = %d\n"), pthread_self(), errno);
		}
	}

	/*
	 * Unbind the current thread from the Client Door's private
	 * thread pool.
	 */
	debug(1, "cleanup[%d]: door_unbind() of Client Door[%d]",
	    pthread_self(), door_dp->dd_cdoor_descriptor);
	if (door_unbind() < 0)
		warning("door_unbind() of Client Door[%d] failed = "
		    "%d", door_dp->dd_cdoor_descriptor, errno);

	/* Disallow any future requests to the Client Door */
	if (door_dp->dd_cdoor_descriptor >= 0) {
		debug(1, "cleanup[%d]: door_revoke() Client Door[%d]",
		    pthread_self(), door_dp->dd_cdoor_descriptor);

		if (door_revoke(door_dp->dd_cdoor_descriptor) < 0) {
			warning(gettext("cleanup[%d]: door_revoke() of "
			    "Client Door[%d] failed = %d"), pthread_self(),
			    door_dp->dd_cdoor_descriptor, errno);
		}
	}

	free(door_dp);
	debug(5, "cleanup[%d] ...exiting\n", pthread_self());
}

/*
 * This is the door_server_create(3c) function used to customize
 * creation of the threads used in the handling of our daemon's
 * door_call(3c)'s.
 *
 * This function is called synchronously as part of door_create(3c).
 * Note that door_create(), however, is not synchronous; it can return
 * with the created door file descriptor before any associated
 * thread has been created.  As a result, synchronization is needed
 * between door_create() caller and the created pthread.  This is
 * needed both when each activity succeeds or when either activity
 * fails.
 *
 * Specifically, this function ensures that each "connection"
 * with the client creates only one thread in the per-door,
 * private thread pool.  This function locks dd_threadlock and
 * then calls pthread_create().  If that succeeds, dd_thread
 * is assigned the thread id, and dd_threadlock is unlocked.
 * Any per-connection door_create that causes control to flow
 * to this function will eventually find that dd_thread is
 * non-zero, and control will exit this function.
 *
 * In the current implementation, the door_create for the Client Door
 * is called first, and the Death Door is door_create'd second.
 * As a result, the following function can safely make the static
 * assumption that the first door (within a connection) is the
 * Client Door.  A connection's Client Door and Death Door share
 * the same thread as well as the same door_data_t instance.
 */
static void
sm_door_server_create(door_info_t *dip)
{
	door_data_t	*door_dp;
	pthread_t	tid;
	pthread_attr_t	attr;
	int		ret_val;
	int		err;

	if (dip == NULL) {
		return;
	}
	door_dp = (door_data_t *)(uintptr_t)dip->di_data;

	debug(10, "sm_door_server_create[%d]: entering...\n", pthread_self());

	/* create one thread for this door */

	(void) mutex_lock(&door_dp->dd_threadlock);

	if (door_dp->dd_thread != 0) {
		debug(8, "sm_door_server_create[%d]: Exiting without creating "
		    "thread.\n", pthread_self());
		(void) mutex_unlock(&door_dp->dd_threadlock);
		return;
	}

	(void) pthread_attr_init(&attr);

	if ((err = pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM)) != 0)
		warning(gettext("pthread_attr_setscope failed = %d\n"), err);
	if ((err = pthread_attr_setdetachstate(&attr,
	    PTHREAD_CREATE_DETACHED)) != 0)
		warning(gettext("pthread_attr_setdetachstate failed = %d\n"),
		    err);

	ret_val = pthread_create(&tid, &attr, sm_server_thread,
	    (void *)(uintptr_t)(dip->di_data));
	if (ret_val != 0) {
		warning(gettext("sm_door_server_create[%d]: pthread_create "
		    "failed = %d\n"), pthread_self(), ret_val);
		(void) mutex_unlock(&door_dp->dd_threadlock);
		(void) pthread_attr_destroy(&attr);
		return;
	}
	(void) pthread_attr_destroy(&attr);
	door_dp->dd_thread = tid;

	(void) mutex_unlock(&door_dp->dd_threadlock);
	debug(5, "Exiting sm_door_server_create[%d] after creating thr[%d].\n",
	    pthread_self(), tid);
}

static void
door_ret_err(smedia_reterror_t *reterror, int32_t err)
{
	reterror->cnum = SMEDIA_CNUM_ERROR;
	reterror->errnum = err;
	(void) door_return((char *)reterror, sizeof (smedia_reterror_t), 0, 0);
}

static void
my_door_return(char *data_ptr, size_t data_size,
	door_desc_t *desc_ptr, uint_t num_desc)
{
	(void) door_return(data_ptr, data_size, desc_ptr, num_desc);
}

static int32_t
raw_read(door_data_t *door_dp, smedia_services_t *req)
{
	struct uscsi_cmd	ucmd;
	union scsi_cdb		cdb;
	int32_t			ret_val;
	int32_t			num_sectors, sector_size;
	int32_t			rc_data[2];
	char			rq_data[RQ_LEN];

	(void) memset((void *) &rc_data, 0, sizeof (rc_data));
	(void) memset((void *) &ucmd, 0, sizeof (ucmd));
	(void) memset((void *) &cdb, 0, sizeof (union scsi_cdb));

	if (door_dp->dd_sector_size == 0) {
		sector_size = get_sector_size(door_dp->dd_fd);
		door_dp->dd_sector_size = sector_size;
	} else sector_size = door_dp->dd_sector_size;

	if ((req->reqraw_read.nbytes > door_dp->dd_buf_len) ||
		(door_dp->dd_buf == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	if ((!req->reqraw_read.nbytes) ||
		(req->reqraw_read.nbytes % sector_size)) {
		errno = EINVAL;
		return (-1);
	}

	(void) memset((void *) &cdb, 0, sizeof (cdb));
	num_sectors = (uint32_t)req->reqraw_read.nbytes/sector_size;

	cdb.scc_cmd = SCMD_READ_G1;
	FORMG1ADDR(&cdb, (uint32_t)req->reqraw_read.blockno);
	FORMG1COUNT(&cdb, num_sectors);

	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP1;
	ucmd.uscsi_bufaddr = (caddr_t)door_dp->dd_buf;
	ucmd.uscsi_buflen = (uint32_t)req->reqraw_read.nbytes;
	ucmd.uscsi_timeout = 120;	/* If 0, HBA hangs forever */
	ucmd.uscsi_rqlen = RQ_LEN;
	ucmd.uscsi_rqbuf = rq_data;
	ret_val = do_uscsi_cmd(door_dp->dd_fd,
		&ucmd, USCSI_READ|USCSI_RQENABLE);
	if (ret_val || ucmd.uscsi_status) {
		debug(5, "read failed: %d - %d errno = %d\n",
			ret_val, ucmd.uscsi_status, errno);
		debug(5, "buflen = 0x%x resid = 0x%x sector size = %d\n",
			ucmd.uscsi_buflen, ucmd.uscsi_resid, sector_size);
		debug(5, "cdb addr: %x %x %x %x \n", cdb.g1_addr3,
			cdb.g1_addr2, cdb.g1_addr1, cdb.g1_addr0);
		debug(5, "cdb count: %x %x\n", cdb.g1_count1,
			cdb.g1_count0);
		return (-1);
	}
	ret_val = ucmd.uscsi_buflen - ucmd.uscsi_resid;
	return (ret_val);
}

static int32_t
raw_write(door_data_t *door_dp, smedia_services_t *req)
{
	struct uscsi_cmd	ucmd;
	union scsi_cdb		cdb;
	int32_t			ret_val;
	int32_t			num_sectors, sector_size;
	int32_t			rc_data[2];
	char			rq_data[RQ_LEN];

	(void) memset((void *) &rc_data, 0, sizeof (rc_data));
	(void) memset((void *) &ucmd, 0, sizeof (ucmd));
	(void) memset((void *) &cdb, 0, sizeof (union scsi_cdb));

	if (door_dp->dd_sector_size == 0) {
		sector_size = get_sector_size(door_dp->dd_fd);
		door_dp->dd_sector_size = sector_size;
	} else sector_size = door_dp->dd_sector_size;


	if ((req->reqraw_write.nbytes > door_dp->dd_buf_len) ||
		(door_dp->dd_buf == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	if ((req->reqraw_write.nbytes % sector_size)) {
		errno = EINVAL;
		return (-1);
	}

	(void) memset((void *) &cdb, 0, sizeof (cdb));
	num_sectors = (uint32_t)req->reqraw_write.nbytes/sector_size;

	cdb.scc_cmd = SCMD_WRITE_G1;
	FORMG1ADDR(&cdb, (uint32_t)req->reqraw_write.blockno);
	FORMG1COUNT(&cdb, num_sectors);

	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP1;
	ucmd.uscsi_bufaddr = (caddr_t)door_dp->dd_buf;
	ucmd.uscsi_buflen = (uint32_t)req->reqraw_write.nbytes;
	ucmd.uscsi_timeout = 120;	/* If 0, HBA hangs forever */
	ucmd.uscsi_rqlen = RQ_LEN;
	ucmd.uscsi_rqbuf = rq_data;
	ret_val = do_uscsi_cmd(door_dp->dd_fd,
		&ucmd, USCSI_WRITE|USCSI_RQENABLE);
	if (ret_val || ucmd.uscsi_status) {
		debug(5, "write failed: %d - %d errno = %d\n",
			ret_val, ucmd.uscsi_status, errno);
		debug(5, "buflen = 0x%x resid = 0x%x sector size = %d\n",
			ucmd.uscsi_buflen, ucmd.uscsi_resid, sector_size);
		debug(5, "cdb addr: %x %x %x %x \n", cdb.g1_addr3,
			cdb.g1_addr2, cdb.g1_addr1, cdb.g1_addr0);
		debug(5, "cdb count: %x %x\n", cdb.g1_count1,
			cdb.g1_count0);
		return (-1);
	}
	ret_val = ucmd.uscsi_buflen - ucmd.uscsi_resid;
	return (ret_val);
}

static int32_t
set_protection_status(door_data_t *door_dp, smedia_services_t *req)
{
	int32_t			ret_val, saved_errno, status;
	struct scsi_inquiry	inq;
	char			vid[9];
	char			pid[17];
	struct passwd		*pwd;
	char			uname[MAXUGNAME + 1];
	char			*new_state, *old_state;

	/*
	 * Read the current protection state before modifiying.
	 * Needed for audit purposes.
	 */
	switch (get_device_type_scsi(door_dp->dd_fd, &inq)) {
	case SCSI_IOMEGA:
		status = scsi_zip_media_status(door_dp->dd_fd);
		ret_val = scsi_zip_write_protect(door_dp->dd_fd,
			&req->reqset_protection_status.prot_state);
		break;
	case SCSI_FLOPPY:
		info("Formatting floppy");
		status = scsi_floppy_media_status(door_dp->dd_fd);
		ret_val = scsi_floppy_write_protect(door_dp->dd_fd,
			&req->reqset_protection_status.prot_state);
		break;
	case SCSI_GENERIC:
		status = scsi_media_status(door_dp->dd_fd);
		ret_val = scsi_write_protect(door_dp->dd_fd,
			&req->reqset_protection_status.prot_state);
		break;
	}

	saved_errno = errno;
	new_state = xlate_state(
	    req->reqset_protection_status.prot_state.sm_new_state);
	old_state = xlate_state(status);

	if (can_audit()) {
		(void) audit_save_me(door_dp);
		door_dp->audit_text[0] = 0;
		door_dp->audit_text1[0] = 0;
		door_dp->audit_event = AUE_smserverd;
	}
	(void) strlcpy(vid, inq.inq_vid, sizeof (vid));
	(void) strlcpy(pid, inq.inq_pid, sizeof (pid));
	if (ret_val < 0) {
	    if (errno == EACCES) {
		pwd = getpwuid(door_dp->dd_cred.dc_ruid);
		if (pwd != NULL) {
			(void) strlcpy(uname,
				pwd->pw_name, MAXUGNAME);
		} else uname[0] = 0;

		if (can_audit()) {
			(void) snprintf(door_dp->audit_text,
				sizeof (door_dp->audit_text),
				dgettext(TEXT_DOMAIN, "from %s to %s"),
				old_state, new_state);

			(void) snprintf(door_dp->audit_text1,
				sizeof (door_dp->audit_text1),
				"%s %s (%d,%d)", vid, pid,
				(int)major(door_dp->dd_stat.st_rdev),
				(int)minor(door_dp->dd_stat.st_rdev));

			door_dp->audit_sorf = 1;
			if (audit_audit(door_dp) == -1)
			    warning("Error in writing audit info\n");
		}
	    } /* errno == EACCES */
	    errno = saved_errno;
	    return (-1);
	}
	if (can_audit()) {
		(void) snprintf(door_dp->audit_text,
			sizeof (door_dp->audit_text),
			dgettext(TEXT_DOMAIN, "from %s to %s"),
			old_state, new_state);

		(void) snprintf(door_dp->audit_text1,
			sizeof (door_dp->audit_text1),
			"%s %s (%d,%d)", vid, pid,
			(int)major(door_dp->dd_stat.st_rdev),
			(int)minor(door_dp->dd_stat.st_rdev));

		door_dp->audit_sorf = 0;
		if (audit_audit(door_dp) == -1)
		    warning("Error in writing audit info\n");
	}
	errno = saved_errno;
	return (0);
}

static int32_t
set_shfd(door_data_t *door_dp, int32_t fd, smedia_services_t *req)
{
	void	*fbuf;
	int32_t ret_val = 0;

	if ((door_dp->dd_buffd != -1) && (door_dp->dd_buf != NULL)) {
		ret_val = munmap(door_dp->dd_buf, door_dp->dd_buf_len);
		if (ret_val == -1)
			warning(gettext("munmap failed. errno=%d\n"),
			    errno);
		(void) close(door_dp->dd_buffd);

		door_dp->dd_buffd = -1;
		door_dp->dd_buf = 0;
		door_dp->dd_buf_len = 0;
	}

	fbuf = mmap(0, req->reqset_shfd.fdbuf_len,
	    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (fbuf == MAP_FAILED) {
		ret_val = errno;
		debug(5, "mmap failed. errno=%d\n", errno);
		return (ret_val);
	}
	door_dp->dd_buffd = fd;
	door_dp->dd_buf = fbuf;
	door_dp->dd_buf_len = req->reqset_shfd.fdbuf_len;

	return (0);
}

static int32_t
reassign_block(door_data_t *door_dp, smedia_services_t *req)
{
	struct uscsi_cmd	ucmd;
	union scsi_cdb		cdb;
	int32_t			ret_val;
	int32_t			sector_size;
	char			*read_buf;
	uchar_t			mode_data[MD_LEN];

	if (get_mode_page(door_dp->dd_fd, 0, 1,
	    mode_data, MD_LEN) < 0) {
		debug(5, "Mode sense failed\n");
		ret_val =  scsi_reassign_block(door_dp->dd_fd,
		    req->reqreassign_block.blockno);
		if (ret_val != 0)
			return (-1);
		return (0);
	}

	/*
	 * No need to check if enough data is returned for
	 * AWRE bit or not.
	 * It will be 0 otherwise which needs to reassign the block.
	 */
	if (!(mode_data[AWRE_OFFSET] & AWRE)) {
		debug(5, "AWRE bit not set\n");
		ret_val =  scsi_reassign_block(door_dp->dd_fd,
			req->reqreassign_block.blockno);
		if (ret_val != 0)
			return (-1);
		return (0);
	}
	sector_size = (mode_data[BLOCK_LEN_OFFSET] << 16) |
		(mode_data[BLOCK_LEN_OFFSET + 1] << 8) |
		mode_data[BLOCK_LEN_OFFSET + 2];

	debug(5, "REASSIGN BLOCK: sec size = 0x%x\n", sector_size);
	read_buf = (char *)malloc(sector_size);
	if (read_buf == NULL) {
		/* Alloc failed. Atleast reassign the block */
		ret_val =  scsi_reassign_block(door_dp->dd_fd,
			req->reqreassign_block.blockno);
		if (ret_val != 0)
			return (-1);
		return (0);
	}

	(void) memset(read_buf, 0, sector_size);
	/* Read the sector */
	debug(5, "Reading the block %d\n",
		(uint32_t)req->reqreassign_block.blockno);

	(void) memset((void *) &ucmd, 0, sizeof (ucmd));
	(void) memset((void *) &cdb, 0, sizeof (union scsi_cdb));

	cdb.scc_cmd = SCMD_READ_G1;
	FORMG1ADDR(&cdb, req->reqreassign_block.blockno);
	FORMG1COUNT(&cdb, 1);	/* One block */

	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP1;
	ucmd.uscsi_bufaddr = (caddr_t)read_buf;
	ucmd.uscsi_buflen = sector_size;
	ucmd.uscsi_timeout = 120;	/* If 0, HBA hangs forever */
	(void) do_uscsi_cmd(door_dp->dd_fd, &ucmd, USCSI_READ);

	/* Write the data back */

	debug(5, "Writing the block %d\n",
		(uint32_t)req->reqreassign_block.blockno);
	(void) memset((void *) &ucmd, 0, sizeof (ucmd));
	(void) memset((void *) &cdb, 0, sizeof (cdb));

	cdb.scc_cmd = SCMD_WRITE_G1;
	FORMG1ADDR(&cdb, req->reqreassign_block.blockno);
	FORMG1COUNT(&cdb, 1);	/* One block */

	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP1;
	ucmd.uscsi_bufaddr = (caddr_t)read_buf;
	ucmd.uscsi_buflen = sector_size;
	ucmd.uscsi_timeout = 120;	/* If 0, HBA hangs forever */
	ret_val = do_uscsi_cmd(door_dp->dd_fd, &ucmd, USCSI_WRITE);
	free(read_buf);
	if (ret_val || ucmd.uscsi_status) {
		debug(5, "Reassign failed: %d - %d errno = %d\n",
			ret_val, ucmd.uscsi_status, errno);
		ret_val = scsi_reassign_block(door_dp->dd_fd,
			req->reqreassign_block.blockno);
		if (ret_val != 0)
			return (-1);
		return (0);
	}

	return (0);
}

static void
close_door_descs(door_desc_t *dp, uint_t ndesc)
{
	while (ndesc > 0) {
		int fd = dp->d_data.d_desc.d_descriptor;
		if (dp->d_attributes & DOOR_DESCRIPTOR)
			(void) close(fd);
		dp++;
		ndesc--;
	}
}

/*
 * This is a Death Door's service procedure.
 *
 * This procedure is a NOP because the Death Door functionality
 * is no longer used and will be removed in the future.
 */
/*ARGSUSED*/
static void
death_servproc(void *cookie, char *argp, size_t arg_size,
    door_desc_t *dp, uint_t ndesc)
{
	debug(1, "death_servproc[%d]: argp = 0x%p  "
	    "Death Door[%d]\n", pthread_self(), (void *)argp,
	    ((door_data_t *)cookie)->dd_ddoor_descriptor);

	(void) door_return(NULL, 0, NULL, 0);
}

/*
 * This is a Client Door's service procedure.
 *
 * This procedure is specified in the door_create() of a Client Door,
 * and its functionality represents the bulk of services that the
 * rpc.smserverd daemon offers.
 */
static void
client_servproc(void *cookie, char *argp, size_t arg_size,
    door_desc_t *dp, uint_t ndesc)
{
	smedia_services_t	*req;
	smedia_services_t	rmsvc;
	smedia_reterror_t	reterror;
	smedia_retraw_read_t	retraw_read;
	struct scsi_inquiry	inq;
	struct dk_minfo		media_info;
	struct dk_geom		dkgeom;
	int32_t			status;
	uchar_t			data[18];
	int32_t			completed = 0;
	door_data_t		*door_dp;
	size_t			retbuf_size;
	struct uscsi_cmd	ucmd;
	union scsi_cdb		cdb;
	int32_t			ret_val, err;
	char			rq_data[RQ_LEN];
	uint_t			nexpected_desc;
	struct vtoc		vtoc;
	struct extvtoc		extvtoc;

	door_dp = (door_data_t *)cookie;
	req = (smedia_services_t *)((void *)argp);

	debug(10, "client_servproc[%d]...\n", pthread_self());

	if (argp == DOOR_UNREF_DATA) {
		debug(5, "client_servproc[%d]: req = DOOR_UNREF_DATA\n",
		    pthread_self());
		debug(5, "Client has exited. Cleaning up resources\n");

		(void) mutex_lock(&svcstate_lock);
		svccount--;
		(void) mutex_unlock(&svcstate_lock);

		cleanup(door_dp);
		return;
	}

	(void) mutex_lock(&svcstate_lock);
	svcstate = _SERVED;
	(void) mutex_unlock(&svcstate_lock);

	rmsvc.in.cnum = req->in.cnum;
	debug(5, "client_servproc[%d]: req = %s\n", pthread_self(),
	    xlate_cnum(req->in.cnum));

	/*
	 * Our caller may have passed more descriptors than we expected.
	 * If so, we silently close (and ignore) them.
	 */
	nexpected_desc = (req->in.cnum == SMEDIA_CNUM_SET_SHFD) ? 1 : 0;
	if (ndesc > nexpected_desc) {
		close_door_descs(dp + nexpected_desc, ndesc - nexpected_desc);
	}

	switch (req->in.cnum) {
	default:
		debug(5, "client_servproc: unknown command %d\n", req->in.cnum);
		door_ret_err(&reterror, ENOTSUP);
		break;

	case SMEDIA_CNUM_SET_SHFD:
		if (ndesc == 0)
			door_ret_err(&reterror, EINVAL);
		/*
		 * Allocate shared memory for this connection.
		 * If this connection already has shared memory,
		 * deallocate before doing the allocation.
		 */
		ret_val = set_shfd(door_dp, dp->d_data.d_desc.d_descriptor,
		    req);
		if (ret_val == 0) {
			reterror.cnum = SMEDIA_CNUM_SET_SHFD;
			reterror.errnum = 0;

			my_door_return((char *)&reterror,
				sizeof (smedia_reterror_t), 0, 0);
		} else {
			(void) close(dp->d_data.d_desc.d_descriptor);
			door_ret_err(&reterror, ret_val);
		}
		break;

	case SMEDIA_CNUM_RAW_READ:
		debug(10, " arg size = %d blk num=0x%x nbytes = 0x%x \n",
			(int)arg_size,
			(uint32_t)req->reqraw_read.blockno,
			req->reqraw_read.nbytes);
		retbuf_size = sizeof (smedia_retraw_read_t);
		if (req->reqraw_read.nbytes == 0) {
			/* Nothing to write */
			rmsvc.retraw_write.nbytes = 0;
			my_door_return((char *)&rmsvc,
				sizeof (smedia_retraw_write_t), 0, 0);
		}
		retraw_read.cnum = SMEDIA_CNUM_RAW_READ;
		ret_val = raw_read(door_dp, req);
		if (ret_val == -1) {
			door_ret_err(&reterror, errno);
		}
		retraw_read.nbytes = ret_val;
		my_door_return((char *)&retraw_read, retbuf_size, 0, 0);
		break;

	case	SMEDIA_CNUM_USCSI_CMD:
		retbuf_size = sizeof (smedia_retuscsi_cmd_t);
		rmsvc.retuscsi_cmd.cnum = SMEDIA_CNUM_USCSI_CMD;
		ucmd.uscsi_flags = req->requscsi_cmd.uscsi_flags;
		ucmd.uscsi_cdb = (caddr_t)&req->requscsi_cmd.uscsi_cdb;
		ucmd.uscsi_cdblen = req->requscsi_cmd.uscsi_cdblen;
		ucmd.uscsi_bufaddr = (caddr_t)door_dp->dd_buf;
		ucmd.uscsi_buflen = req->requscsi_cmd.uscsi_buflen;
		ucmd.uscsi_timeout = req->requscsi_cmd.uscsi_timeout;
		ucmd.uscsi_rqlen = req->requscsi_cmd.uscsi_rqlen;
		ucmd.uscsi_rqbuf = (caddr_t)&rmsvc.retuscsi_cmd.uscsi_rqbuf;
		debug(5, "USCSI CMD 0x%x requested.\n",
		    req->requscsi_cmd.uscsi_cdb[0]);
		/*
		 * Check the device type and invalid flags specified.
		 * We permit operations only on CDROM devices types.
		 */
		errno = invalid_uscsi_operation(door_dp, &ucmd);
		if (errno) {
			door_ret_err(&reterror, errno);
		}

		if ((req->requscsi_cmd.uscsi_buflen) &&
		    ((req->requscsi_cmd.uscsi_buflen > door_dp->dd_buf_len) ||
		    (door_dp->dd_buf == NULL))) {
			debug(5, "uscsi_cmd failed: uscsi_buflen=0x%x "
			    "dd_buf_len=0x%x dd_buf=0x%p\n",
			    req->requscsi_cmd.uscsi_buflen,
			    door_dp->dd_buf_len,
			    door_dp->dd_buf);
			errno = EINVAL;
			door_ret_err(&reterror, errno);
		}
		ret_val = do_uscsi_cmd(door_dp->dd_fd,
			&ucmd, req->requscsi_cmd.uscsi_flags);
		rmsvc.retuscsi_cmd.uscsi_status = ucmd.uscsi_status;
		rmsvc.retuscsi_cmd.uscsi_resid = ucmd.uscsi_resid;
		rmsvc.retuscsi_cmd.uscsi_rqstatus = ucmd.uscsi_rqstatus;
		rmsvc.retuscsi_cmd.uscsi_rqresid = ucmd.uscsi_rqresid;
		rmsvc.retuscsi_cmd.uscsi_retval = ret_val;
		rmsvc.retuscsi_cmd.uscsi_errno = errno;
		if (ret_val || ucmd.uscsi_status) {
			debug(5, "uscsi_cmd failed: %d - %d errno = %d\n",
				ret_val, ucmd.uscsi_status, errno);
		}
		my_door_return((char *)&rmsvc, retbuf_size, 0, 0);
		break;

	case SMEDIA_CNUM_RAW_WRITE:
		if (req->reqraw_write.nbytes == 0) {
			/* Nothing to write */
			rmsvc.retraw_write.nbytes = 0;
			my_door_return((char *)&rmsvc,
				sizeof (smedia_retraw_write_t), 0, 0);
		}
		ret_val = raw_write(door_dp, req);
		if (ret_val == -1)
			door_ret_err(&reterror, errno);
		rmsvc.retraw_write.nbytes = ret_val;
		my_door_return((char *)&rmsvc, sizeof (smedia_retraw_write_t),
			0, 0);
		break;

	case SMEDIA_CNUM_GET_DEVICE_INFO:

		(void) memset((void *) &inq, 0, sizeof (inq));
		(void) memset((void *) &ucmd, 0, sizeof (ucmd));
		(void) memset((void *) &cdb, 0, sizeof (union scsi_cdb));
		cdb.scc_cmd = SCMD_INQUIRY;
		FORMG0COUNT(&cdb, sizeof (inq));
		ucmd.uscsi_cdb = (caddr_t)&cdb;
		ucmd.uscsi_cdblen = CDB_GROUP0;
		ucmd.uscsi_bufaddr = (caddr_t)&inq;
		ucmd.uscsi_buflen = sizeof (inq);
		ucmd.uscsi_timeout = 120;	/* If 0, HBA hangs forever */
		ucmd.uscsi_rqlen = RQ_LEN;
		ucmd.uscsi_rqbuf = rq_data;
		ret_val = do_uscsi_cmd(door_dp->dd_fd,
			&ucmd, USCSI_READ|USCSI_RQENABLE);
		if (ret_val || ucmd.uscsi_status) {
			debug(5, "inquiry failed: %d - %d errno = %d\n",
				ret_val, ucmd.uscsi_status, errno);
			door_ret_err(&reterror, errno);
		}

		debug(5, "%s\n", inq.inq_vid);
		debug(5, "%s\n", rmsvc.retget_device_info.sm_vendor_name);

		(void) strlcpy(rmsvc.retget_device_info.sm_vendor_name,
			inq.inq_vid, 8);
		rmsvc.retget_device_info.sm_vendor_name[8] = 0;
		(void) strlcpy(rmsvc.retget_device_info.sm_product_name,
			inq.inq_pid, 16);
		rmsvc.retget_device_info.sm_product_name[16] = 0;
		(void) strlcpy(rmsvc.retget_device_info.sm_firmware_version,
			inq.inq_revision, 4);
		rmsvc.retget_device_info.sm_firmware_version[4] = ' ';
		(void) strlcpy(
			&rmsvc.retget_device_info.sm_firmware_version[5],
				inq.inq_serial, 12);
		rmsvc.retget_device_info.sm_product_name[17] = 0;

		rmsvc.retget_device_info.sm_interface_type = IF_SCSI;

		debug(5, "Vendor name = %s\n",
		    rmsvc.retget_device_info.sm_vendor_name);
		debug(5, "product name = %s\n",
		    rmsvc.retget_device_info.sm_product_name);
		debug(5, "Firmware revision = %s\n",
		    rmsvc.retget_device_info.sm_firmware_version);

		my_door_return((char *)&rmsvc.retget_device_info,
			sizeof (smedia_retget_device_info_t), 0, 0);
		break;

	case	SMEDIA_CNUM_GET_MEDIUM_PROPERTY:

		(void) memset((void *)&rmsvc.retget_medium_property.smprop,
			0, sizeof (smmedium_prop_t));

		ret_val = ioctl(door_dp->dd_fd, DKIOCGMEDIAINFO, &media_info);

		if (ret_val < 0) {
			uint32_t capacity;
			uint32_t blocksize;
			/*
			 * Devices may fail DKIOCGMEDIAINFO if an unformed
			 * media is inserted. We can get the capacity
			 * information from the SCMD_READ_FORMAT_CAP command.
			 */

			debug(5, "DKIOCGMEDIAINFO failed; using "
			    "SCMD_READ_FORMAT_CAP");
			ret_val = get_media_capacity(door_dp->dd_fd,
			    &capacity, &blocksize);

			if (ret_val >= 0) {
				media_info.dki_lbsize =	blocksize;
				media_info.dki_capacity = capacity;
			} else {
				debug(5, "SCMD_READ_FORMAT_CAP failed");
				door_ret_err(&reterror, errno);
			}
		}
		rmsvc.retget_medium_property.smprop.sm_blocksize =
		    media_info.dki_lbsize;
		rmsvc.retget_medium_property.smprop.sm_capacity =
		    media_info.dki_capacity;

		rmsvc.retget_medium_property.smprop.sm_media_type =
		    media_info.dki_media_type;
		/*
		 * These devices show as SCSI devices but we need to treat it
		 * differently. so we need a seperate class.
		 */
		if (get_device_type_scsi(door_dp->dd_fd, &inq) == SCSI_FLOPPY) {
			rmsvc.retget_medium_property.smprop.sm_media_type =
			    SM_SCSI_FLOPPY;
		}

		/* Check for EFI type because DKIOCGGEOM does not support EFI */
		ret_val = ioctl(door_dp->dd_fd, DKIOCGEXTVTOC, &extvtoc);
		if (ret_val < 0 && errno == ENOTTY)
			ret_val = ioctl(door_dp->dd_fd, DKIOCGVTOC, &vtoc);

		if (!((ret_val < 0) && (errno == ENOTSUP))) {
			ret_val = ioctl(door_dp->dd_fd, DKIOCGGEOM, &dkgeom);
			if (ret_val < 0)  {
				/*
				 * DKIOCGGEOM may fail for unformed floppies.
				 * We need to generate the appropriate geometry
				 * information.
				 */
				if (rmsvc.retget_medium_property.smprop.
				    sm_media_type == SM_SCSI_FLOPPY) {
					ret_val = get_floppy_geom(
					    door_dp->dd_fd,
					    media_info.dki_capacity, &dkgeom);

					if (ret_val < 0) {
						debug(5, "Cannot determine "
						    "media size");
						door_ret_err(&reterror, errno);
					}
				} else {
#ifdef sparc
					debug(5, "DKIOCGGEOM ioctl failed");
					door_ret_err(&reterror, errno);
#else /* !sparc */
					/*
					 * Try getting Physical geometry on x86.
					 */
					ret_val = ioctl(door_dp->dd_fd,
					    DKIOCG_PHYGEOM, &dkgeom);
					if (ret_val < 0) {
						debug(5, "DKIOCG_PHYGEOM "
						    "ioctl failed");
						door_ret_err(&reterror, errno);
					}
#endif /* sparc */
				}
			}


			/*
			 * Some faked geometry may not have pcyl filled in so
			 * later calculations using this field will be
			 * incorrect.  We will substitute it with the number of
			 * available cylinders.
			 */
			if (dkgeom.dkg_pcyl == 0)
				rmsvc.retget_medium_property.smprop.sm_pcyl =
				    dkgeom.dkg_ncyl;
			else
				rmsvc.retget_medium_property.smprop.sm_pcyl =
				    dkgeom.dkg_pcyl;

			rmsvc.retget_medium_property.smprop.sm_nhead =
			    dkgeom.dkg_nhead;
			rmsvc.retget_medium_property.smprop.sm_nsect =
			    dkgeom.dkg_nsect;
		}

		debug(1, "properties are: lbasize = %d, cap = %llu",
		    media_info.dki_lbsize, media_info.dki_capacity);

		my_door_return((char *)&rmsvc.retget_medium_property,
			sizeof (smedia_retget_medium_property_t), 0, 0);
		break;

	case	SMEDIA_CNUM_GET_PROTECTION_STATUS:
		switch (get_device_type_scsi(door_dp->dd_fd, &inq)) {
		case SCSI_FLOPPY:
			status = scsi_floppy_media_status(door_dp->dd_fd);
			break;
		case SCSI_IOMEGA:
			status = scsi_zip_media_status(door_dp->dd_fd);
			break;
		case SCSI_GENERIC:
			status = scsi_media_status(door_dp->dd_fd);
			break;
		default:
			door_ret_err(&reterror, errno);
		}
		if (status < 0)
			door_ret_err(&reterror, errno);

		rmsvc.retget_protection_status.prot_state.sm_new_state  =
			status;

		my_door_return((char *)&rmsvc.retget_protection_status,
			sizeof (smedia_retget_protection_status_t), 0, 0);
		break;

	case	SMEDIA_CNUM_SET_PROTECTION_STATUS:

		ret_val = set_protection_status(door_dp, req);
		if (ret_val == -1)
			door_ret_err(&reterror, errno);
		else
			my_door_return((char *)&rmsvc.retset_protection_status,
				sizeof (smedia_retset_protection_status_t),
				0, 0);
		break;

	case SMEDIA_CNUM_FORMAT:
		switch (get_device_type_scsi(door_dp->dd_fd, &inq)) {
		case SCSI_FLOPPY:
			info("formatting floppy");
			err = scsi_floppy_format(door_dp->dd_fd,
				req->reqformat.flavor, req->reqformat.mode);

			break;
		case SCSI_IOMEGA:
			err = scsi_zip_format(door_dp->dd_fd,
				req->reqformat.flavor, req->reqformat.mode);
			break;
		case SCSI_GENERIC:
			err = scsi_format(door_dp->dd_fd,
				req->reqformat.flavor, req->reqformat.mode);
			break;
		default:
			door_ret_err(&reterror, ENOTSUP);
		}

		if (err)
			door_ret_err(&reterror, errno);
		my_door_return((char *)&rmsvc.retformat,
			sizeof (smedia_retformat_t), 0, 0);

		break;

	case SMEDIA_CNUM_CHECK_FORMAT_STATUS:

		(void) memset((void *) &cdb, 0, sizeof (union scsi_cdb));
		(void) memset((void *) &ucmd, 0, sizeof (ucmd));
		(void) memset((void *) &data, 0, sizeof (data));
		cdb.scc_cmd = SCMD_REQUEST_SENSE;
		cdb.g0_count0 = sizeof (data);
		ucmd.uscsi_cdb = (caddr_t)&cdb;
		ucmd.uscsi_cdblen = CDB_GROUP0;
		ucmd.uscsi_bufaddr = (caddr_t)&data;
		ucmd.uscsi_buflen = sizeof (data);
		ucmd.uscsi_timeout = 120;	/* If 0, HBA hangs forever */
		ucmd.uscsi_rqlen = RQ_LEN;
		ucmd.uscsi_rqbuf = rq_data;
		ret_val = do_uscsi_cmd(door_dp->dd_fd,
			&ucmd, USCSI_READ|USCSI_RQENABLE);
		if (ret_val || ucmd.uscsi_status) {
			debug(5, "Request sense failed: %d - %d errno = %d\n",
				ret_val, ucmd.uscsi_status, errno);
			door_ret_err(&reterror, errno);
		}

		if ((data[0] & 0x7F) == DEFERRED_ERROR) {
		/* Deffered error. The format must have failed */
			debug(5, "format failed!\n");
			door_ret_err(&reterror, EIO);
		}

		if (data[SKSV_OFFSET] & SKSV_FIELD) {
			completed =
				(data[FORMAT_PROGRESS_INDICATOR_OFFSET_0] << 8)
				| data[FORMAT_PROGRESS_INDICATOR_OFFSET_1];
			completed = (completed*100/65536);
		} else {
			completed = (100);
		}
		rmsvc.retcheck_format_status.percent_complete = completed;
		my_door_return((char *)&rmsvc.retcheck_format_status,
			sizeof (smedia_retcheck_format_status_t), 0, 0);
		break;

	case SMEDIA_CNUM_REASSIGN_BLOCK:

		ret_val = reassign_block(door_dp, req);
		if (ret_val == -1)
			door_ret_err(&reterror, errno);
		my_door_return((char *)&rmsvc.retreassign_block,
			sizeof (smedia_retreassign_block_t), 0, 0);
		break;

	}	/* end of switch */

	debug(10, "Exiting client server...\n");
	my_door_return((char *)&reterror, sizeof (smedia_reterror_t), 0, 0);
}

/*
 * This is the service procedure for the door that is associated with
 * the (doorfs) filesystem Door that is created at 'smedia_service'.
 */
/*ARGSUSED*/
static void
main_servproc(void *server_data, char *argp, size_t arg_size,
    door_desc_t *dp, uint_t ndesc)
{
	smedia_services_t	*req;
	door_cred_t	door_credentials;
	int		ret_val;
	door_data_t	*ddata;
	smedia_reterror_t	reterror;
	smedia_reterror_t	retok;
	struct	stat	stat;
	door_desc_t	*didpp;
	struct dk_cinfo dkinfo;
	uint_t		nexpected_desc;

	debug(10, "Entering main_servproc[%d].\n", pthread_self());

	didpp = dp;
	(void) mutex_lock(&svcstate_lock);
	svcstate = _SERVED;
	(void) mutex_unlock(&svcstate_lock);

	reterror.cnum = SMEDIA_CNUM_ERROR;
	reterror.errnum = SMEDIA_FAILURE;

	if (argp == NULL) {
		debug(5, "argp is NULL\n");
		if (ndesc > 0)
			close_door_descs(dp, ndesc);
		my_door_return((char *)&reterror,
		    sizeof (smedia_reterror_t), 0, 0);
	}

	req = (smedia_services_t *)((void *)argp);

	retok.cnum = req->in.cnum;
	retok.errnum = 0;

	debug(5, "req = %s arg_size = 0x%x \n",
	    xlate_cnum(req->reqopen.cnum), arg_size);

	/*
	 * Our caller may have passed more descriptors than we expected.
	 * If so, we silently close (and ignore) them.
	 */
	nexpected_desc = (req->in.cnum == SMEDIA_CNUM_OPEN_FD) ? 1 : 0;
	if (ndesc > nexpected_desc) {
		close_door_descs(dp + nexpected_desc, ndesc - nexpected_desc);
	}

	switch (req->in.cnum) {
	default:
		debug(5, "main_servproc: unknown command 0x%x\n",
		    req->reqopen.cnum);
		break;

	case SMEDIA_CNUM_PING:
		/*
		 * This service is to indicate that server is up and
		 * running. It is usually called from another instance of
		 * server that is started.
		 */
		reterror.cnum = SMEDIA_CNUM_PING;
		reterror.errnum = 0;
		my_door_return((char *)&reterror,
		    sizeof (smedia_reterror_t), 0, 0);
		break;


	case SMEDIA_CNUM_OPEN_FD:

		debug(5, "ndesc = %d\n", ndesc);
		if (ndesc == 0) {
			my_door_return((char *)&reterror,
			    sizeof (smedia_reterror_t), 0, 0);
		}
		debug(5, "Checking file descriptor of target device\n");
		if (fstat(didpp->d_data.d_desc.d_descriptor, &stat) < 0) {
			warning(gettext("main_servproc:fstat failed. "
			    "errno = %d\n"), errno);
			(void) close(didpp->d_data.d_desc.d_descriptor);
			my_door_return((char *)&reterror,
			    sizeof (smedia_reterror_t), 0, 0);
		}
		debug(5, "descriptor = %d st_mode = 0x%lx\n",
		    didpp->d_data.d_desc.d_descriptor,
		    stat.st_mode);

		/* Obtain the credentials of the user */
		ret_val = door_cred(&door_credentials);
		if (ret_val < 0) {
			warning(gettext("main_servproc:door_cred "
			    "failed. errno = %d\n"), errno);
			(void) close(didpp->d_data.d_desc.d_descriptor);
			my_door_return((char *)&reterror,
			    sizeof (smedia_reterror_t), 0, 0);
		}
		if (ioctl(didpp->d_data.d_desc.d_descriptor, DKIOCINFO,
			&dkinfo) == -1) {
			warning(gettext("main_servproc:DKIOCINFO failed. "
			    "errno = %d\n"), errno);
			(void) close(didpp->d_data.d_desc.d_descriptor);
			my_door_return((char *)&reterror,
			    sizeof (smedia_reterror_t), 0, 0);
		}

		ddata = (door_data_t *)calloc(1, sizeof (door_data_t));
		if (ddata == NULL) {
			warning(gettext("main_servproc:calloc failed. "
			    "errno = %d\n"), errno);
			(void) close(didpp->d_data.d_desc.d_descriptor);
			my_door_return((char *)&reterror,
			    sizeof (smedia_reterror_t), 0, 0);
		}
		ddata->dd_stat = stat;
		ddata->dd_cred = door_credentials;
		ddata->dd_fd = didpp->d_data.d_desc.d_descriptor;
		ddata->dd_buf = NULL;
		ddata->dd_buf_len = 0;
		ddata->dd_buffd = -1;
		ddata->dd_sector_size = 0;
		ddata->dd_dkinfo = dkinfo;
		debug(5, "ddata = 0x%p \n", (void *)ddata);

		/* specify a function that'll customize our door threads */
		(void) door_server_create(sm_door_server_create);
		debug(5, "door_server_create called.\n");

		(void) mutex_lock(&ddata->dd_lock);

		/* create Client Door */
		ddata->dd_cdoor_descriptor =
		    door_create(client_servproc,
		    (void *)ddata, DOOR_PRIVATE | DOOR_NO_CANCEL | DOOR_UNREF);

		if (ddata->dd_cdoor_descriptor < 0) {
			/* then door_create() failed */
			int err = errno;

			(void) mutex_unlock(&ddata->dd_lock);

			warning(gettext("main_servproc: door_create of Client "
			    "Door failed = %d\n"), err);
			free(ddata);

			/* close target device */
			(void) close(didpp->d_data.d_desc.d_descriptor);
			my_door_return((char *)&reterror,
			    sizeof (smedia_reterror_t), 0, 0);
		}

		/* create Death Door */
		ddata->dd_ddoor_descriptor =
		    door_create(death_servproc, (void *)ddata,
		    DOOR_REFUSE_DESC | DOOR_NO_CANCEL);
		if (ddata->dd_ddoor_descriptor < 0) {
			warning(gettext("main_servproc: door_create of Death "
			    "Door failed = %d\n"), errno);
		} else {
			(void) door_setparam(ddata->dd_ddoor_descriptor,
			    DOOR_PARAM_DATA_MAX, 0);
		}

		debug(5, "main_servproc[%d]: Client Door = %d, "
		    "Death Door = %d", pthread_self(),
		    ddata->dd_cdoor_descriptor, ddata->dd_ddoor_descriptor);

		audit_init(ddata);

		/* wait until sm_server_thread does door_bind() */
		(void) cond_wait(&ddata->dd_cv_bind, &ddata->dd_lock);

		(void) mutex_unlock(&ddata->dd_lock);

		(void) mutex_lock(&svcstate_lock);
		svccount++;
		(void) mutex_unlock(&svcstate_lock);

		if (ddata->dd_ddoor_descriptor < 0) {
			/* Return only the Client Door to the client. */
			ddata->dd_cdoor.d_attributes = (DOOR_DESCRIPTOR);
			my_door_return((char *)&reterror,
			    sizeof (smedia_reterror_t), &ddata->dd_desc[0], 1);
		} else {
			/*
			 * Return the Client Door and Death Door
			 * to the client.
			 */
			debug(5, "retok.cnum = 0x%x\n", retok.cnum);
			ddata->dd_cdoor.d_attributes = (DOOR_DESCRIPTOR);
			ddata->dd_ddoor.d_attributes = (DOOR_DESCRIPTOR);
			my_door_return((char *)&retok,
			    sizeof (smedia_reterror_t), &ddata->dd_desc[0], 2);
		}
		break;
	}

	debug(10, "exiting main_servproc. \n");
	my_door_return((char *)&reterror, sizeof (smedia_reterror_t), 0, 0);
}

/* ARGSUSED */
static void
term_handler(int sig, siginfo_t *siginfo, void *sigctx)
{
	warning(gettext("thread[%d]: Received signal %d. Ignoring it.\n"),
	    pthread_self(),
	    sig);
}

/* ARGSUSED */
static void
hup_handler(int sig, siginfo_t *siginfo, void *sigctx)
{
	warning(gettext("thread[%d]: Received signal %d. Ignoring it.\n"),
	    pthread_self(),
	    sig);
}

/*ARGSUSED*/
static void
sig_handler(int sig, siginfo_t *siginfo, void *sigctx)
{
	warning(gettext("thread[%d]: Received signal %d. Ignoring it.\n"),
	    pthread_self(),
	    sig);
}

/*ARGSUSED*/
static void
badsig_handler(int sig, siginfo_t *siginfo, void *sigctx)
{
	fatal(BADSIG_MSG, pthread_self(), sig, siginfo->si_addr,
	    siginfo->si_trapno,
	    siginfo->si_pc);
}

/*ARGSUSED*/
static void *
init_server(void *argp)
{
	int	i, fd;
	struct	sigaction	act;
	struct	rlimit		rlim;

	debug(10, "init_server  running\n");

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);


	if (geteuid() != 0) fatal("Must be root to execute smserverd\n");


	/*
	 * setup signal handlers.
	 */

	for (i = 0; i < N_BADSIGS; i++) {
		act.sa_sigaction = badsig_handler;
		(void) sigemptyset(&act.sa_mask);
		act.sa_flags = SA_SIGINFO;
		if (sigaction(badsigs[i], &act, NULL) == -1)
			warning(gettext(SIGACT_FAILED), strsignal(badsigs[i]),
				strerror(errno));
	}

	/*
	 * Ignore SIGHUP until all the initialization is done.
	 */
	act.sa_handler = SIG_IGN;
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (sigaction(SIGHUP, &act, NULL) == -1)
		warning(gettext(SIGACT_FAILED), strsignal(SIGHUP),
			strerror(errno));
	/*
	 * Increase file descriptor limit to the most it can possibly
	 * be.
	 */
	if (getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
		warning(gettext("getrlimit for fd's failed; %m\n"));
	}

	rlim.rlim_cur = rlim.rlim_max;

	if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
		warning(gettext("setrlimit for fd's failed; %m\n"));
	}
	(void) enable_extended_FILE_stdio(-1, -1);

	server_door = door_create(main_servproc, (void *)&server_data, 0);
	if (server_door == -1) {
		debug(1, "main door_create");
		exit(1);
	}

	(void) unlink(smedia_service);
	fd = open(smedia_service, O_RDWR|O_CREAT|O_EXCL, 0644);
	if (fd < 0) {
		debug(5, "could not open %s.\n", smedia_service);
		exit(1);
	}
	(void) close(fd);
	server_fd = fattach(server_door, smedia_service);
	if (server_fd == -1) {
		debug(1, "main fattach");
		exit(1);
	}
	server_data.sd_door = server_door;
	server_data.sd_fd = server_fd;

	/*
	 * setup signal handlers for post-init
	 */

	act.sa_sigaction = hup_handler;
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = SA_SIGINFO;
	if (sigaction(SIGHUP, &act, NULL) == -1)
		warning(gettext(SIGACT_FAILED), strsignal(SIGHUP),
		    strerror(errno));

	act.sa_sigaction = term_handler;
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = SA_SIGINFO;
	if (sigaction(SIGTERM, &act, NULL) == -1)
		warning(gettext(SIGACT_FAILED), strsignal(SIGTERM),
		    strerror(errno));

	act.sa_sigaction = sig_handler;
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = SA_SIGINFO;
	if (sigaction(SIGINT, &act, NULL) == -1)
		warning(gettext(SIGACT_FAILED), strsignal(SIGHUP),
		    strerror(errno));

	act.sa_sigaction = sig_handler;
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = SA_SIGINFO;
	if (sigaction(SIGQUIT, &act, NULL) == -1)
		warning(gettext(SIGACT_FAILED), strsignal(SIGHUP),
		    strerror(errno));
	debug(10, "init_server completed successfully\n");

	server_data.sd_init_state = INIT_DONE;
	return (NULL);
}

static int
server_exists()
{
	door_arg_t		darg;
	smedia_reqping_t	req_ping;
	smedia_retping_t	*ret_ping;
	int			doorh;
	door_info_t		dinfo;
	char    rbuf[sizeof (smedia_services_t) + sizeof (door_desc_t)];

	doorh = open(smedia_service, O_RDONLY);
	if (doorh < 0)
		return (0);
	if (door_info(doorh, &dinfo) < 0) {
		(void) close(doorh);
		return (0);
	}
	if (dinfo.di_attributes & DOOR_REVOKED) {
		(void) close(doorh);
		return (0);
	}

	req_ping.cnum = SMEDIA_CNUM_PING;

	darg.data_ptr = (char *)&req_ping;
	darg.data_size = sizeof (smedia_reqping_t);
	darg.desc_ptr = NULL;
	darg.desc_num = 0;
	darg.rbuf = rbuf;
	darg.rsize = sizeof (rbuf);

	if (door_call(doorh, &darg) < 0) {
		(void) close(doorh);
		return (0);
	}
	ret_ping = (smedia_retping_t *)((void *)darg.data_ptr);
	if (ret_ping->cnum != SMEDIA_CNUM_PING) {
		(void) close(doorh);
		return (0);
	}

	(void) close(doorh);
	return (1);
}

static int
get_run_level()
{
	int	run_level;
	struct utmpx	*utmpp;

	setutxent();
	while ((utmpp = getutxent()) != NULL) {
		if (utmpp->ut_type == RUN_LVL) {
			run_level = atoi(
				&utmpp->ut_line[strlen("run-level ")]);
		}
	}
	return (run_level);
}

/*ARGSUSED*/
static void *
closedown(void *arg)
{

	int	current_run_level;

	/*CONSTCOND*/
#ifndef lint
	while (1) {
#endif
		(void) sleep(SVC_CLOSEDOWN/2);

		/*
		 * If the server was started at init level 1
		 * and the current init level is 1 then
		 * do not exit from server. This server will run
		 * until it is explicitly stopped by the user.
		 */
		if (svcstart_level == 1) {
			current_run_level = get_run_level();
			if (current_run_level == 1)
#ifndef lint
				continue;
#else
				return (NULL);
#endif
			/*
			 * who ever started the server at level 1 has
			 * forgotten to stop the server. we will kill ourself.
			 */
			debug(5,
			"Terminating the server started at init level 1\n");
			exit(0);
		}

		if (mutex_trylock(&svcstate_lock) != 0)
#ifndef lint
			continue;
#else
			return (NULL);
#endif
		if (svcstate == _IDLE && svccount == 0) {
			int size;
			int i, openfd = 0;

			size = svc_max_pollfd;
			for (i = 0; i < size && openfd < 2; i++)
				if (svc_pollfd[i].fd >= 0)
					openfd++;
			if (openfd <= 1) {
				debug(5,
				"Exiting the server from closedown routine.\n");
				exit(0);
			}
		} else
			svcstate = _IDLE;

		(void) mutex_unlock(&svcstate_lock);
#ifndef lint
	}
#else
	return (NULL);
#endif

}

static void
usage()
{
	warning(gettext("usage: %s [-L loglevel] level of debug information\n"),
		prog_name);
}


/*ARGSUSED*/
int
main(int argc, char **argv)
{
	int c;
	pthread_attr_t	attr;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	prog_name = argv[0];

	(void) sigset(SIGPIPE, SIG_IGN);

	while ((c = getopt(argc, argv, "L:")) != -1) {
		switch (c) {
		case 'L':
			debug_level = atoi((char *)optarg);
			break;
		default:
			usage();
			break;
		}
	}

	/*
	 * If stdin looks like a TLI endpoint, we assume
	 * that we were started by a port monitor. If
	 * t_getstate fails with TBADF, this is not a
	 * TLI endpoint.
	 */
	if (t_getstate(0) != -1 || t_errno != TBADF) {
		char *netid;
		struct netconfig *nconf = NULL;
		SVCXPRT *transp;
		int pmclose;

		openlog(prog_name, LOG_PID, LOG_DAEMON);

		debug(1, gettext("server started by port monitor.\n"));
		if ((netid = getenv("NLSPROVIDER")) == NULL) {
		/* started from inetd */
			pmclose = 1;
		} else {
			if ((nconf = getnetconfigent(netid)) == NULL)
				syslog(LOG_ERR, gettext(
					"cannot get transport info"));

			pmclose = (t_getstate(0) != T_DATAXFER);
		}
		if ((transp = svc_tli_create(0, nconf, NULL, 0, 0)) == NULL) {
			syslog(LOG_ERR, gettext("cannot create server handle"));
			exit(1);
		}
		if (nconf)
			freenetconfigent(nconf);
		if (!svc_reg(transp, SMSERVERPROG, SMSERVERVERS,
			smserverprog_1, 0)) {
			syslog(LOG_ERR, gettext(
			"unable to register (SMSERVERPROG, SMSERVERVERS)."));
			exit(1);
		}
		svcstart_level = get_run_level();
		if (pmclose) {
			(void) pthread_attr_init(&attr);
			(void) pthread_attr_setscope(&attr,
			    PTHREAD_SCOPE_SYSTEM);
			(void) pthread_attr_setdetachstate(&attr,
			    PTHREAD_CREATE_DETACHED);
			if (pthread_create(NULL, &attr, closedown, NULL) != 0) {
				syslog(LOG_ERR, gettext(
					"cannot create closedown thread"));
				exit(1);
			}
			(void) pthread_attr_destroy(&attr);
		}
		svc_run();
		exit(1);
		/* NOTREACHED */
	} else {
		/*
		 * Started by library or manually.
		 */
		/*
		 * Check to see if the server is already running.
		 * There is no need to log messages in the syslog file
		 * because server will get launched each time libsmedia
		 * library calls are made at init 1 level.
		 * We ensure that only one copy will run.
		 */
		debug(1, gettext("server started manually.\n"));
		if (server_exists()) {
			exit(0);
		}
		svcstart_level = get_run_level();
		(void) pthread_attr_init(&attr);
		(void) pthread_attr_setscope(&attr,
		    PTHREAD_SCOPE_SYSTEM);
		(void) pthread_attr_setdetachstate(&attr,
		    PTHREAD_CREATE_DETACHED);
		if (pthread_create(NULL, &attr, closedown, NULL) != 0) {
			syslog(LOG_ERR, gettext(
				"cannot create closedown thread"));
			exit(1);
		}
		(void) pthread_attr_destroy(&attr);
		(void) init_server(NULL);
		for (;;) (void) pause();
	}
	return (0);
}


/*ARGSUSED*/
static int32_t
scsi_floppy_write_protect(int32_t fd, smwp_state_t *wp)
{
	debug(5, "Invalid mode\n");
	errno = ENOTSUP;

	return (-1);
}

/*
 * Generate standard geometry information for SCSI floppy devices. And
 * register the geometry with the SCSI driver. This will expand as more
 * formats are added.
 */

/*ARGSUSED*/
static int32_t
get_floppy_geom(int32_t fd, uint32_t capacity, struct dk_geom *dkgeom)
{


	debug(5, "get_floppy_geom: capacity = 0x%x\n", capacity);

	switch (capacity) {

		case 0x5A0:
			/* Double Density 720K */
			dkgeom->dkg_pcyl = 80;
			dkgeom->dkg_ncyl = 80;
			dkgeom->dkg_nhead = 2;
			dkgeom->dkg_nsect = 9;
			break;
		case 0x4D0:
			/* High Density 1.25MB */
			dkgeom->dkg_pcyl = 77;
			dkgeom->dkg_ncyl = 77;
			dkgeom->dkg_nhead = 2;
			dkgeom->dkg_nsect = 9;
			break;
		case 0xB40:
			/* High Density 1.44MB */

			dkgeom->dkg_pcyl = 80;
			dkgeom->dkg_ncyl = 80;
			dkgeom->dkg_nhead = 2;
			dkgeom->dkg_nsect = 18;
			break;
		case 0x3C300:
			/* Ultra High density ls-120 120MB */
			dkgeom->dkg_pcyl = 963;
			dkgeom->dkg_ncyl = 963;
			dkgeom->dkg_nhead = 8;
			dkgeom->dkg_nsect = 32;
			break;
		default:
			debug(5, "unknown capacity type %d\n", capacity);
			return (-1);

	}
	debug(5, "get_floppy_geom: setting cyl = %d, nsect = %d, head = %d",
		dkgeom->dkg_pcyl, dkgeom->dkg_nhead, dkgeom->dkg_nsect);
	return (0);

}
/* ARGSUSED */
static int32_t
scsi_floppy_format(int32_t fd, uint_t flavor, uint_t mode)
{
	struct uscsi_cmd ucmd;
	uchar_t		cdb[12];
	int32_t		ret_val;
	uint32_t	capacity, blocksize;
	uchar_t		data[12];
	char 		rq_data[RQ_LEN];
	int		i;
	struct dk_geom	dkgeom;

	debug(5, "scsi_floppy_format:\n");

	if ((mode != SM_FORMAT_IMMEDIATE) && (mode != SM_FORMAT_BLOCKED)) {
		errno = ENOTSUP;

		return (-1);
	}

	switch (flavor) {
		case SM_FORMAT_QUICK :
			debug(1, "Format not supported\n");
			errno = ENOTSUP;
			return (-1);
		case SM_FORMAT_FORCE :
			break;
		case SM_FORMAT_LONG :
			break;

		default :
			debug(1, "Format option not specified!!\n");
			errno = ENOTSUP;
			return (-1);
	}

	ret_val = get_media_capacity(fd, &capacity, &blocksize);

	if (capacity >= 0x3C300) {
		/*
		 * It's an LS-120 media, it does not support track
		 * formatting.
		 */
		return (scsi_ls120_format(fd, flavor, capacity, blocksize));
	}

	ret_val = get_floppy_geom(fd, capacity, &dkgeom);
		if (ret_val) {
			errno = ENOTSUP;
			return (-1);
		}

	(void) memset((void *)&data, 0, sizeof (data));
	(void) memset((void *)&ucmd, 0, sizeof (ucmd));
	(void) memset((void *)&cdb, 0, sizeof (cdb));

	/* retrieve size discriptor of inserted media */
	cdb[0] = SCMD_FORMAT;	/* format */

	/*
	 * Defect list sent by initiator is a complete list of defects.
	 */

	cdb[1] = (FMTDATA | 0x7);

	cdb[8] = 0xC;   /* parameter list length */
	data[3] = 0x8;	/* should be always 8 */

	data[4] = (uchar_t)(capacity >> 24);
	data[5] = (uchar_t)(capacity >> 16);
	data[6] = (uchar_t)(capacity >> 8);
	data[7] = (uchar_t)capacity;

	data[9] = (uchar_t)(blocksize >> 16);
	data[10] = (uchar_t)(blocksize >> 8);
	data[11] = (uchar_t)blocksize;

	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP5;
	ucmd.uscsi_bufaddr = (caddr_t)data;
	ucmd.uscsi_buflen = sizeof (data);
	ucmd.uscsi_timeout = 0x15;
	ucmd.uscsi_rqlen = RQ_LEN;
	ucmd.uscsi_rqbuf = rq_data;

	debug(5, "cdb: %x %x %x ... %x", cdb[0], cdb[1], cdb[2], cdb[8]);
	debug(5, "data: %x %x %x %x\n", data[0], data[1], data[2], data[3]);
	debug(5, "    : %x %x %x %x\n", data[4], data[5], data[6], data[7]);
	debug(5, "    : %x %x %x %x\n", data[8], data[9], data[10], data[11]);

	for (i = 0; i < dkgeom.dkg_pcyl; i++) {	/* number of tracks */
		data[1] = (0xb0 | FOV);
		cdb[2] = i;

		(void) fflush(stdout);
		ret_val = do_uscsi_cmd(fd, &ucmd, USCSI_WRITE|USCSI_RQENABLE);
		info("format side 0 returned : 0x%x\n", ret_val);

		if (ret_val || ucmd.uscsi_status) {
			debug(5, "Retrieving media info failed: %d - %d\n",
			    ret_val, ucmd.uscsi_status);
			if ((rq_data[2] == KEY_DATA_PROTECT) &&
			    (rq_data[12] == 0x30) && (rq_data[13] == 0)) {
				debug(5, "Invalid command for media\n");
				errno = EINVAL;
			}

			if ((rq_data[2] == KEY_NOT_READY) &&
			    (rq_data[12] == 0x30)) {
				debug(5, "Incompatible media.\n");
				errno = EINVAL;
			}

			return (-1);
		}
		data[1] = (0xb0 | FOV) + 1;
		ret_val = do_uscsi_cmd(fd, &ucmd, USCSI_WRITE|USCSI_RQENABLE);
		info("format side 1 returned : 0x%x\n", ret_val);

		if (ret_val || ucmd.uscsi_status) {
			debug(5, "Retrieving media info failed: %d - %d\n",
			    ret_val, ucmd.uscsi_status);
			if ((rq_data[2] == KEY_DATA_PROTECT) &&
			    (rq_data[12] == 0x30) && (rq_data[13] == 0)) {
				(void) info("Invalid command for media\n");
				errno = EINVAL;
			}

			if ((rq_data[2] == KEY_NOT_READY) &&
			    (rq_data[12] == 0x30)) {
				debug(5, "Incompatible media.\n");
				errno = EINVAL;
			}

			return (-1);
		}
	}

	debug(5, "formatting done!");
	return (0);
}


/* ARGSUSED */
static int32_t
scsi_floppy_media_status(int32_t fd)
{
	struct mode_header_g1 modeh;
	struct uscsi_cmd ucmd;
	uchar_t cdb[10];
	int32_t ret_val;
	int32_t cur_status;
	char rq_data[RQ_LEN];

	debug(5, "SCSI MEDIA STATUS CALLED \n");

	(void) memset((void *) &modeh, 0, sizeof (modeh));
	(void) memset((void *) &ucmd, 0, sizeof (ucmd));
	(void) memset(cdb, 0, sizeof (cdb));
	/*
	 * issue 10 byte mode sense (0x5A)
	 */
	cdb[0] = SCMD_MODE_SENSE_G1;
	cdb[7] = sizeof (modeh) >> 8;
	cdb[8] = sizeof (modeh) & 0xff;

	ucmd.uscsi_cdb = (caddr_t)cdb;
	ucmd.uscsi_cdblen = CDB_GROUP1;
	ucmd.uscsi_bufaddr = (caddr_t)&modeh;
	ucmd.uscsi_buflen = sizeof (modeh);
	ucmd.uscsi_timeout = 120;	/* If 0, HBA hangs forever */
	ucmd.uscsi_rqlen = RQ_LEN;
	ucmd.uscsi_rqbuf = rq_data;
	ret_val = do_uscsi_cmd(fd, &ucmd, USCSI_READ|USCSI_RQENABLE);
	if (ret_val || ucmd.uscsi_status) {
		/*
		 * UFI devices may not respond to the 0 mode page.
		 * retry with the error recovery page(0x01)
		 */
		if (ucmd.uscsi_status & STATUS_CHECK) {
			cdb[2] = 0x1;	/* page code */
			ret_val = do_uscsi_cmd(fd, &ucmd,
					USCSI_READ|USCSI_RQENABLE);
		}
		if (ret_val || ucmd.uscsi_status) {
			debug(1, "Modesense failed: %d - %d\n",
				ret_val, ucmd.uscsi_status);
			return (-1);
		}
	}
	debug(5, "Modesense succeeded: 0x%x\n", modeh.device_specific);

	if (modeh.device_specific & 0x80) {
		cur_status = SM_WRITE_PROTECT_NOPASSWD;
	} else {
		cur_status = SM_WRITE_PROTECT_DISABLE;
	}
	return (cur_status);
}
