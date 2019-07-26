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
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright 2018 Joyent, Inc.
 * Copyright 2019 Nexenta Systems, Inc.
 */

#include <stdlib.h>
#include <alloca.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <door.h>
#include <zone.h>
#include <resolv.h>
#include <sys/socket.h>
#include <net/route.h>
#include <string.h>
#include <net/if.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "nscd_common.h"
#include "nscd_door.h"
#include "nscd_config.h"
#include "nscd_switch.h"
#include "nscd_log.h"
#include "nscd_selfcred.h"
#include "nscd_frontend.h"
#include "nscd_admin.h"

static void rts_mon(void);
static void keep_open_dns_socket(void);

extern nsc_ctx_t *cache_ctx_p[];

/*
 * Current active Configuration data for the frontend component
 */
static nscd_cfg_global_frontend_t	frontend_cfg_g;
static nscd_cfg_frontend_t		*frontend_cfg;

static int	max_servers = 0;
static int	max_servers_set = 0;
static int	per_user_is_on = 1;

static char	*main_execname;
static char	**main_argv;
extern int	_whoami;
extern long	activity;
extern mutex_t	activity_lock;

static sema_t	common_sema;

static thread_key_t	lookup_state_key;
static mutex_t		create_lock = DEFAULTMUTEX;
static int		num_servers = 0;
static thread_key_t	server_key;

/*
 * Bind a TSD value to a server thread. This enables the destructor to
 * be called if/when this thread exits.  This would be a programming
 * error, but better safe than sorry.
 */
/*ARGSUSED*/
static void *
server_tsd_bind(void *arg)
{
	static void *value = "NON-NULL TSD";

	(void) thr_setname(thr_self(), "server_tsd_bind");

	/* disable cancellation to avoid hangs if server threads disappear */
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	(void) thr_setspecific(server_key, value);
	(void) door_return(NULL, 0, NULL, 0);

	/* make lint happy */
	return (NULL);
}

/*
 * Server threads are created here.
 */
/*ARGSUSED*/
static void
server_create(door_info_t *dip)
{
	(void) mutex_lock(&create_lock);
	if (++num_servers > max_servers) {
		num_servers--;
		(void) mutex_unlock(&create_lock);
		return;
	}
	(void) mutex_unlock(&create_lock);
	(void) thr_create(NULL, 0, server_tsd_bind, NULL,
	    THR_BOUND|THR_DETACHED, NULL);
}

/*
 * Server thread are destroyed here
 */
/*ARGSUSED*/
static void
server_destroy(void *arg)
{
	(void) mutex_lock(&create_lock);
	num_servers--;
	(void) mutex_unlock(&create_lock);
	(void) thr_setspecific(server_key, NULL);
}

/*
 * get clearance
 */
int
_nscd_get_clearance(sema_t *sema)
{
	if (sema_trywait(&common_sema) == 0) {
		(void) thr_setspecific(lookup_state_key, NULL);
		return (0);
	}

	if (sema_trywait(sema) == 0) {
		(void) thr_setspecific(lookup_state_key, (void*)1);
		return (0);
	}

	return (1);
}


/*
 * release clearance
 */
int
_nscd_release_clearance(sema_t *sema)
{
	int	which;

	(void) thr_getspecific(lookup_state_key, (void**)&which);
	if (which == 0) /* from common pool */ {
		(void) sema_post(&common_sema);
		return (0);
	}

	(void) sema_post(sema);
	return (1);
}

static void
dozip(void)
{
	/* not much here */
}

/*
 * _nscd_restart_if_cfgfile_changed()
 * Restart if modification times of nsswitch.conf or resolv.conf have changed.
 *
 * If nsswitch.conf has changed then it is possible that sources for
 * various backends have changed and therefore the current cached
 * data may not be consistent with the new data sources.  By
 * restarting the cache will be cleared and the new configuration will
 * be used.
 *
 * The check for resolv.conf is made as only the first call to
 * res_gethostbyname() or res_getaddrbyname() causes a call to
 * res_ninit() to occur which in turn parses resolv.conf.  Therefore
 * to benefit from changes to resolv.conf nscd must be restarted when
 * resolv.conf is updated, removed or created.  If res_getXbyY calls
 * are removed from NSS then this check could be removed.
 *
 */
void
_nscd_restart_if_cfgfile_changed()
{

	static mutex_t		nsswitch_lock = DEFAULTMUTEX;
	static timestruc_t	last_nsswitch_check = { 0 };
	static timestruc_t	last_nsswitch_modified = { 0 };
	static timestruc_t	last_resolv_modified = { -1, 0 };
	static mutex_t		restarting_lock = DEFAULTMUTEX;
	static int		restarting = 0;
	int			restart = 0;
	time_t			now = time(NULL);
	char			*me = "_nscd_restart_if_cfgfile_changed";

#define	FLAG_RESTART_REQUIRED	if (restarting == 0) {\
					(void) mutex_lock(&restarting_lock);\
					if (restarting == 0) {\
						restarting = 1;\
						restart = 1;\
					}\
					(void) mutex_unlock(&restarting_lock);\
				}

	if (restarting == 1)
		return;

	if (now - last_nsswitch_check.tv_sec < _NSC_FILE_CHECK_TIME)
		return;

	(void) mutex_lock(&nsswitch_lock);

	if (now - last_nsswitch_check.tv_sec >= _NSC_FILE_CHECK_TIME) {
		struct stat nss_buf;
		struct stat res_buf;

		last_nsswitch_check.tv_sec = now;
		last_nsswitch_check.tv_nsec = 0;

		(void) mutex_unlock(&nsswitch_lock); /* let others continue */

		if (stat("/etc/nsswitch.conf", &nss_buf) < 0) {
			return;
		} else if (last_nsswitch_modified.tv_sec == 0) {
			last_nsswitch_modified = nss_buf.st_mtim;
		}

		if (last_nsswitch_modified.tv_sec < nss_buf.st_mtim.tv_sec ||
		    (last_nsswitch_modified.tv_sec == nss_buf.st_mtim.tv_sec &&
		    last_nsswitch_modified.tv_nsec < nss_buf.st_mtim.tv_nsec)) {
			FLAG_RESTART_REQUIRED;
		}

		if (restart == 0) {
			if (stat("/etc/resolv.conf", &res_buf) < 0) {
				/* Unable to stat file, were we previously? */
				if (last_resolv_modified.tv_sec > 0) {
					/* Yes, it must have been removed. */
					FLAG_RESTART_REQUIRED;
				} else if (last_resolv_modified.tv_sec == -1) {
					/* No, then we've never seen it. */
					last_resolv_modified.tv_sec = 0;
				}
			} else if (last_resolv_modified.tv_sec == -1) {
				/* We've just started and file is present. */
				last_resolv_modified = res_buf.st_mtim;
			} else if (last_resolv_modified.tv_sec == 0) {
				/* Wasn't there at start-up. */
				FLAG_RESTART_REQUIRED;
			} else if (last_resolv_modified.tv_sec <
			    res_buf.st_mtim.tv_sec ||
			    (last_resolv_modified.tv_sec ==
			    res_buf.st_mtim.tv_sec &&
			    last_resolv_modified.tv_nsec <
			    res_buf.st_mtim.tv_nsec)) {
				FLAG_RESTART_REQUIRED;
			}
		}

		if (restart == 1) {
			char *fmri;

			/*
			 * if in self cred mode, kill the forker and
			 * child nscds
			 */
			if (_nscd_is_self_cred_on(0, NULL)) {
				_nscd_kill_forker();
				_nscd_kill_all_children();
			}

			/*
			 * time for restart
			 */
			_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_INFO)
			(me, "nscd restart due to %s or %s change\n",
			    "/etc/nsswitch.conf", "resolv.conf");
			/*
			 * try to restart under smf
			 */
			if ((fmri = getenv("SMF_FMRI")) == NULL) {
				/* not running under smf - reexec */
				(void) execv(main_execname, main_argv);
				exit(1); /* just in case */
			}

			if (smf_restart_instance(fmri) == 0)
				(void) sleep(10); /* wait a bit */
			exit(1); /* give up waiting for resurrection */
		}

	} else
		(void) mutex_unlock(&nsswitch_lock);
}

uid_t
_nscd_get_client_euid()
{
	ucred_t	*uc = NULL;
	uid_t	id;
	char	*me = "get_client_euid";

	if (door_ucred(&uc) != 0) {
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_DEBUG)
		(me, "door_ucred: %s\n", strerror(errno));
		return ((uid_t)-1);
	}

	id = ucred_geteuid(uc);
	ucred_free(uc);
	return (id);
}

/*
 * Check to see if the door client's euid is 0 or if it has required_priv
 * privilege. Return 0 if yes, -1 otherwise.
 * Supported values for required_priv are:
 *    - NSCD_ALL_PRIV: for all zones privileges
 *    - NSCD_READ_PRIV: for PRIV_FILE_DAC_READ privilege
 */
int
_nscd_check_client_priv(int required_priv)
{
	int			rc = 0;
	ucred_t			*uc = NULL;
	const priv_set_t	*eset;
	char			*me = "_nscd_check_client_read_priv";
	priv_set_t		*zs;	/* zone */

	if (door_ucred(&uc) != 0) {
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
		(me, "door_ucred: %s\n", strerror(errno));
		return (-1);
	}

	if (ucred_geteuid(uc) == 0) {
		ucred_free(uc);
		return (0);
	}

	eset = ucred_getprivset(uc, PRIV_EFFECTIVE);
	switch (required_priv) {
		case NSCD_ALL_PRIV:
			zs = priv_str_to_set("zone", ",", NULL);
			if (!priv_isequalset(eset, zs)) {
				_NSCD_LOG(NSCD_LOG_FRONT_END,
				    NSCD_LOG_LEVEL_ERROR)
				(me, "missing all zones privileges\n");
				rc = -1;
			}
			priv_freeset(zs);
			break;
		case NSCD_READ_PRIV:
			if (!priv_ismember(eset, PRIV_FILE_DAC_READ))
				rc = -1;
			break;
		default:
			_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
			(me, "unknown required_priv: %d\n", required_priv);
			rc = -1;
			break;
	}
	ucred_free(uc);
	return (rc);
}

static void
N2N_check_priv(
	void			*buf,
	char			*dc_str)
{
	nss_pheader_t		*phdr = (nss_pheader_t *)buf;
	ucred_t			*uc = NULL;
	const priv_set_t	*eset;
	zoneid_t		zoneid;
	int			errnum;
	char			*me = "N2N_check_priv";

	if (door_ucred(&uc) != 0) {
		errnum = errno;
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_DEBUG)
		(me, "door_ucred: %s\n", strerror(errno));

		NSCD_SET_STATUS(phdr, NSS_ERROR, errnum);
		return;
	}

	eset = ucred_getprivset(uc, PRIV_EFFECTIVE);
	zoneid = ucred_getzoneid(uc);

	if ((zoneid != GLOBAL_ZONEID && zoneid != getzoneid()) ||
	    eset != NULL ? !priv_ismember(eset, PRIV_SYS_ADMIN) :
	    ucred_geteuid(uc) != 0) {

		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ALERT)
		(me, "%s call failed(cred): caller pid %d, uid %d, "
		    "euid %d, zoneid %d\n", dc_str, ucred_getpid(uc),
		    ucred_getruid(uc), ucred_geteuid(uc), zoneid);
		ucred_free(uc);

		NSCD_SET_STATUS(phdr, NSS_ERROR, EACCES);
		return;
	}

	_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_DEBUG)
	(me, "nscd received %s cmd from pid %d, uid %d, "
	    "euid %d, zoneid %d\n", dc_str, ucred_getpid(uc),
	    ucred_getruid(uc), ucred_geteuid(uc), zoneid);

	ucred_free(uc);

	NSCD_SET_STATUS_SUCCESS(phdr);
}

void
_nscd_APP_check_cred(
	void		*buf,
	pid_t		*pidp,
	char		*dc_str,
	int		log_comp,
	int		log_level)
{
	nss_pheader_t	*phdr = (nss_pheader_t *)buf;
	ucred_t		*uc = NULL;
	uid_t		ruid;
	uid_t		euid;
	pid_t		pid;
	int		errnum;
	char		*me = "_nscd_APP_check_cred";

	if (door_ucred(&uc) != 0) {
		errnum = errno;
		_NSCD_LOG(log_comp, NSCD_LOG_LEVEL_ERROR)
		(me, "door_ucred: %s\n", strerror(errno));

		NSCD_SET_STATUS(phdr, NSS_ERROR, errnum);
		return;
	}

	NSCD_SET_STATUS_SUCCESS(phdr);
	pid = ucred_getpid(uc);
	if (NSS_PACKED_CRED_CHECK(buf, ruid = ucred_getruid(uc),
	    euid = ucred_geteuid(uc))) {
		if (pidp != NULL) {
			if (*pidp == (pid_t)-1)
				*pidp = pid;
			else if (*pidp != pid) {
				NSCD_SET_STATUS(phdr, NSS_ERROR, EACCES);
			}
		}
	} else {
		NSCD_SET_STATUS(phdr, NSS_ERROR, EACCES);
	}

	ucred_free(uc);

	if (NSCD_STATUS_IS_NOT_OK(phdr)) {
		_NSCD_LOG(log_comp, log_level)
		(me, "%s call failed: caller pid %d (input pid = %d), ruid %d, "
		    "euid %d, header ruid %d, header euid %d\n", dc_str,
		    pid, (pidp != NULL) ? *pidp : -1, ruid, euid,
		    ((nss_pheader_t *)(buf))->p_ruid,
		    ((nss_pheader_t *)(buf))->p_euid);
	}
}

/* log error and return -1 when an invalid packed buffer header is found */
static int
pheader_error(nss_pheader_t *phdr, uint32_t call_number)
{
	char *call_num_str;

	switch (call_number) {
	case NSCD_SEARCH:
		call_num_str = "NSCD_SEARCH";
		break;
	case NSCD_SETENT:
		call_num_str = "NSCD_SETENT";
		break;
	case NSCD_GETENT:
		call_num_str = "NSCD_GETENT";
		break;
	case NSCD_ENDENT:
		call_num_str = "NSCD_ENDENT";
		break;
	case NSCD_PUT:
		call_num_str = "NSCD_PUT";
		break;
	case NSCD_GETHINTS:
		call_num_str = "NSCD_GETHINTS";
		break;
	default:
		call_num_str = "UNKNOWN";
		break;
	}

	_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ALERT)
	("pheader_error", "call number %s: invalid packed buffer header\n",
	    call_num_str);

	NSCD_SET_STATUS(phdr, NSS_ERROR, EINVAL);
	return (-1);
}

/*
 * Validate the header of a getXbyY or setent/getent/endent request.
 * Return 0 if good, -1 otherwise.
 *
 * A valid header looks like the following (size is arg_size, does
 * not include the output area):
 * +----------------------------------+ --
 * | nss_pheader_t (header fixed part)| ^
 * |                                  | |
 * | pbufsiz, dbd,off, key_off,       | len = sizeof(nss_pheader_t)
 * | data_off ....                    | |
 * |                                  | v
 * +----------------------------------+ <----- dbd_off
 * | dbd (database description)       | ^
 * | nss_dbd_t + up to 3 strings      | |
 * | length = sizeof(nss_dbd_t) +     | len = key_off - dbd_off
 * |          length of 3 strings +   | |
 * |          length of padding       | |
 * | (total length in multiple of 4)  | v
 * +----------------------------------+ <----- key_off
 * | lookup key                       | ^
 * | nss_XbyY_key_t, content varies,  | |
 * | based on database and lookup op  | len = data_off - key_off
 * | length = data_off - key_off      | |
 * | including padding, multiple of 4 | v
 * +----------------------------------+ <----- data_off (= arg_size)
 * |                                  | ^
 * | area to hold results             | |
 * |                                  | len = data_len (= pbufsiz -
 * |                                  | |                 data_off)
 * |                                  | v
 * +----------------------------------+ <----- pbufsiz
 */
static int
validate_pheader(
	void		*argp,
	size_t		arg_size,
	uint32_t	call_number)
{
	nss_pheader_t	*phdr = (nss_pheader_t *)(void *)argp;
	nssuint_t	l1, l2;

	/*
	 * current version is NSCD_HEADER_REV, length of the fixed part
	 * of the header must match the size of nss_pheader_t
	 */
	if (phdr->p_version != NSCD_HEADER_REV ||
	    phdr->dbd_off != sizeof (nss_pheader_t))
		return (pheader_error(phdr, call_number));

	/*
	 * buffer size and offsets must be in multiple of 4
	 */
	if ((arg_size & 3) || (phdr->dbd_off & 3) || (phdr->key_off & 3) ||
	    (phdr->data_off & 3))
		return (pheader_error(phdr, call_number));

	/*
	 * the input arg_size is the length of the request header
	 * and should be less than NSCD_PHDR_MAXLEN
	 */
	if (phdr->data_off != arg_size || arg_size > NSCD_PHDR_MAXLEN)
		return (pheader_error(phdr, call_number));

	/* get length of the dbd area */
	l1 = phdr->key_off - phdr-> dbd_off;

	/*
	 * dbd area may contain padding, so length of dbd should
	 * not be less than the length of the actual data
	 */
	if (l1 < phdr->dbd_len)
		return (pheader_error(phdr, call_number));

	/* get length of the key area */
	l2 = phdr->data_off - phdr->key_off;

	/*
	 * key area may contain padding, so length of key area should
	 * not be less than the length of the actual data
	 */
	if (l2 < phdr->key_len)
		return (pheader_error(phdr, call_number));

	/*
	 * length of fixed part + lengths of dbd and key area = length of
	 * the request header
	 */
	if (sizeof (nss_pheader_t) + l1 + l2 != phdr->data_off)
		return (pheader_error(phdr, call_number));

	/* header length + data length = buffer length */
	if (phdr->data_off + phdr->data_len != phdr->pbufsiz)
		return (pheader_error(phdr, call_number));

	return (0);
}

/* log error and return -1 when an invalid nscd to nscd buffer is found */
static int
N2Nbuf_error(nss_pheader_t *phdr, uint32_t call_number)
{
	char *call_num_str;

	switch (call_number) {
	case NSCD_PING:
		call_num_str = "NSCD_PING";
		break;

	case NSCD_IMHERE:
		call_num_str = "NSCD_IMHERE";
		break;

	case NSCD_PULSE:
		call_num_str = "NSCD_PULSE";
		break;

	case NSCD_FORK:
		call_num_str = "NSCD_FORK";
		break;

	case NSCD_KILL:
		call_num_str = "NSCD_KILL";
		break;

	case NSCD_REFRESH:
		call_num_str = "NSCD_REFRESH";
		break;

	case NSCD_GETPUADMIN:
		call_num_str = "NSCD_GETPUADMIN";
		break;

	case NSCD_GETADMIN:
		call_num_str = "NSCD_GETADMIN";
		break;

	case NSCD_SETADMIN:
		call_num_str = "NSCD_SETADMIN";
		break;

	case NSCD_KILLSERVER:
		call_num_str = "NSCD_KILLSERVER";
		break;
	default:
		call_num_str = "UNKNOWN";
		break;
	}

	_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ALERT)
	("N2Nbuf_error", "call number %s: invalid N2N buffer\n", call_num_str);

	NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0,
	    NSCD_DOOR_BUFFER_CHECK_FAILED);

	return (-1);
}

/*
 * Validate the buffer of an nscd to nscd request.
 * Return 0 if good, -1 otherwise.
 *
 * A valid buffer looks like the following (size is arg_size):
 * +----------------------------------+ --
 * | nss_pheader_t (header fixed part)| ^
 * |                                  | |
 * | pbufsiz, dbd,off, key_off,       | len = sizeof(nss_pheader_t)
 * | data_off ....                    | |
 * |                                  | v
 * +----------------------------------+ <---dbd_off = key_off = data_off
 * |                                  | ^
 * | input data/output data           | |
 * | OR no data                       | len = data_len (= pbufsiz -
 * |                                  | |                 data_off)
 * |                                  | | len could be zero
 * |                                  | v
 * +----------------------------------+ <--- pbufsiz
 */
static int
validate_N2Nbuf(
	void		*argp,
	size_t		arg_size,
	uint32_t	call_number)
{
	nss_pheader_t	*phdr = (nss_pheader_t *)(void *)argp;

	/*
	 * current version is NSCD_HEADER_REV, length of the fixed part
	 * of the header must match the size of nss_pheader_t
	 */
	if (phdr->p_version != NSCD_HEADER_REV ||
	    phdr->dbd_off != sizeof (nss_pheader_t))
		return (N2Nbuf_error(phdr, call_number));

	/*
	 * There are no dbd and key data, so the dbd, key, data
	 * offsets should be equal
	 */
	if (phdr->dbd_off != phdr->key_off ||
	    phdr->dbd_off != phdr->data_off)
		return (N2Nbuf_error(phdr, call_number));

	/*
	 * the input arg_size is the buffer length and should
	 * be less or equal than NSCD_N2NBUF_MAXLEN
	 */
	if (phdr->pbufsiz != arg_size || arg_size > NSCD_N2NBUF_MAXLEN)
		return (N2Nbuf_error(phdr, call_number));

	/* header length + data length = buffer length */
	if (phdr->data_off + phdr->data_len != phdr->pbufsiz)
		return (N2Nbuf_error(phdr, call_number));

	return (0);
}

static void
lookup(char *argp, size_t arg_size)
{
	nsc_lookup_args_t	largs;
	char			space[NSCD_LOOKUP_BUFSIZE];
	nss_pheader_t		*phdr = (nss_pheader_t *)(void *)argp;

	NSCD_ALLOC_LOOKUP_BUFFER(argp, arg_size, phdr, space,
	    sizeof (space));

	/*
	 * make sure the first couple bytes of the data area is null,
	 * so that bad strings in the packed header stop here
	 */
	(void) memset((char *)phdr + phdr->data_off, 0, 16);

	(void) memset(&largs, 0, sizeof (largs));
	largs.buffer = argp;
	largs.bufsize = arg_size;
	nsc_lookup(&largs, 0);

	/*
	 * only the PUN needs to keep track of the
	 * activity count to determine when to
	 * terminate itself
	 */
	if (_whoami == NSCD_CHILD) {
		(void) mutex_lock(&activity_lock);
		++activity;
		(void) mutex_unlock(&activity_lock);
	}

	NSCD_SET_RETURN_ARG(phdr, arg_size);
	(void) door_return(argp, arg_size, NULL, 0);
}

static void
getent(char *argp, size_t arg_size)
{
	char			space[NSCD_LOOKUP_BUFSIZE];
	nss_pheader_t		*phdr = (nss_pheader_t *)(void *)argp;

	NSCD_ALLOC_LOOKUP_BUFFER(argp, arg_size, phdr, space, sizeof (space));

	nss_pgetent(argp, arg_size);

	NSCD_SET_RETURN_ARG(phdr, arg_size);
	(void) door_return(argp, arg_size, NULL, 0);
}

static int
is_db_per_user(void *buf, char *dblist)
{
	nss_pheader_t	*phdr = (nss_pheader_t *)buf;
	nss_dbd_t	*pdbd;
	char		*dbname, *dbn;
	int		len;

	/* copy db name into a temp buffer */
	pdbd = (nss_dbd_t *)((void *)((char *)buf + phdr->dbd_off));
	dbname = (char *)pdbd + pdbd->o_name;
	len = strlen(dbname);
	dbn = alloca(len + 2);
	(void) memcpy(dbn, dbname, len);

	/* check if <dbname> + ',' can be found in the dblist string */
	dbn[len] = ',';
	dbn[len + 1] = '\0';
	if (strstr(dblist, dbn) != NULL)
		return (1);

	/*
	 * check if <dbname> can be found in the last part
	 * of the dblist string
	 */
	dbn[len] = '\0';
	if (strstr(dblist, dbn) != NULL)
		return (1);

	return (0);
}

/*
 * Check to see if all conditions are met for processing per-user
 * requests. Returns 1 if yes, -1 if backend is not configured,
 * 0 otherwise.
 */
static int
need_per_user_door(void *buf, int whoami, uid_t uid, char **dblist)
{
	nss_pheader_t	*phdr = (nss_pheader_t *)buf;

	NSCD_SET_STATUS_SUCCESS(phdr);

	/* if already a per-user nscd, no need to get per-user door */
	if (whoami == NSCD_CHILD)
		return (0);

	/* forker shouldn't be asked */
	if (whoami == NSCD_FORKER) {
		NSCD_SET_STATUS(phdr, NSS_ERROR, ENOTSUP);
		return (0);
	}

	/* if door client is root, no need for a per-user door */
	if (uid == 0)
		return (0);

	/*
	 * if per-user lookup is not configured, no per-user
	 * door available
	 */
	if (_nscd_is_self_cred_on(0, dblist) == 0)
		return (-1);

	/*
	 * if per-user lookup is not configured for the db,
	 * don't bother
	 */
	if (is_db_per_user(phdr, *dblist) == 0)
		return (0);

	return (1);
}

static void
if_selfcred_return_per_user_door(char *argp, size_t arg_size,
    door_desc_t *dp, int whoami)
{
	nss_pheader_t	*phdr = (nss_pheader_t *)((void *)argp);
	char		*dblist;
	int		door = -1;
	int		rc = 0;
	door_desc_t	desc;
	char		*space;
	int		len;

	/*
	 * check to see if self-cred is configured and
	 * need to return an alternate PUN door
	 */
	if (per_user_is_on == 1) {
		rc = need_per_user_door(argp, whoami,
		    _nscd_get_client_euid(), &dblist);
		if (rc == -1)
			per_user_is_on = 0;
	}
	if (rc <= 0) {
		/*
		 * self-cred not configured, and no error detected,
		 * return to continue the door call processing
		 */
		if (NSCD_STATUS_IS_OK(phdr))
			return;
		else
			/*
			 * configured but error detected,
			 * stop the door call processing
			 */
			(void) door_return(argp, phdr->data_off, NULL, 0);
	}

	/* get the alternate PUN door */
	_nscd_proc_alt_get(argp, &door);
	if (NSCD_GET_STATUS(phdr) != NSS_ALTRETRY) {
		(void) door_return(argp, phdr->data_off, NULL, 0);
	}

	/* return the alternate door descriptor */
	len = strlen(dblist) + 1;
	space = alloca(arg_size + len);
	phdr->data_len = len;
	(void) memcpy(space, phdr, arg_size);
	(void) strncpy((char *)space + arg_size, dblist, len);
	dp = &desc;
	dp->d_attributes = DOOR_DESCRIPTOR;
	dp->d_data.d_desc.d_descriptor = door;
	arg_size += len;
	(void) door_return(space, arg_size, dp, 1);
}

/*ARGSUSED*/
static void
switcher(void *cookie, char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc)
{
	int			iam;
	pid_t			ent_pid = -1;
	nss_pheader_t		*phdr = (nss_pheader_t *)((void *)argp);
	void			*uptr;
	int			len;
	size_t			buflen;
	int			callnum;
	char			*me = "switcher";

	_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_DEBUG)
	(me, "switcher ...\n");

	if (argp == DOOR_UNREF_DATA) {
		(void) printf("Door Slam... exiting\n");
		exit(0);
	}

	if (argp == NULL) { /* empty door call */
		(void) door_return(NULL, 0, 0, 0); /* return the favor */
	}

	/*
	 *  need to restart if main nscd and config file(s) changed
	 */
	if (_whoami == NSCD_MAIN)
		_nscd_restart_if_cfgfile_changed();

	if ((phdr->nsc_callnumber & NSCDV2CATMASK) == NSCD_CALLCAT_APP) {

		/* make sure the packed buffer header is good */
		if (validate_pheader(argp, arg_size,
		    phdr->nsc_callnumber) == -1)
			(void) door_return(argp, arg_size, NULL, 0);

		switch (phdr->nsc_callnumber) {

		case NSCD_SEARCH:

		/* if a fallback to main nscd, skip per-user setup */
		if (phdr->p_status != NSS_ALTRETRY)
			if_selfcred_return_per_user_door(argp, arg_size,
			    dp, _whoami);
		lookup(argp, arg_size);

		break;

		case NSCD_SETENT:

		_nscd_APP_check_cred(argp, &ent_pid, "NSCD_SETENT",
		    NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ALERT);
		if (NSCD_STATUS_IS_OK(phdr)) {
			if_selfcred_return_per_user_door(argp, arg_size,
			    dp, _whoami);
			nss_psetent(argp, arg_size, ent_pid);
		}
		break;

		case NSCD_GETENT:

		getent(argp, arg_size);
		break;

		case NSCD_ENDENT:

		nss_pendent(argp, arg_size);
		break;

		case NSCD_PUT:

		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
		(me, "door call NSCD_PUT not supported yet\n");

		NSCD_SET_STATUS(phdr, NSS_ERROR, ENOTSUP);
		break;

		case NSCD_GETHINTS:

		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
		(me, "door call NSCD_GETHINTS not supported yet\n");

		NSCD_SET_STATUS(phdr, NSS_ERROR, ENOTSUP);
		break;

		default:

		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
		(me, "Unknown name service door call op %x\n",
		    phdr->nsc_callnumber);

		NSCD_SET_STATUS(phdr, NSS_ERROR, EINVAL);
		break;
		}

		(void) door_return(argp, arg_size, NULL, 0);
	}

	iam = NSCD_MAIN;
	callnum = phdr->nsc_callnumber & ~NSCD_WHOAMI;
	if (callnum == NSCD_IMHERE ||
	    callnum == NSCD_PULSE || callnum == NSCD_FORK)
		iam = phdr->nsc_callnumber & NSCD_WHOAMI;
	else
		callnum = phdr->nsc_callnumber;

	/* nscd -> nscd v2 calls */

	/* make sure the buffer is good */
	if (validate_N2Nbuf(argp, arg_size, callnum) == -1)
		(void) door_return(argp, arg_size, NULL, 0);

	switch (callnum) {

	case NSCD_PING:
		NSCD_SET_STATUS_SUCCESS(phdr);
		break;

	case NSCD_IMHERE:
		_nscd_proc_iamhere(argp, dp, n_desc, iam);
		break;

	case NSCD_PULSE:
		N2N_check_priv(argp, "NSCD_PULSE");
		if (NSCD_STATUS_IS_OK(phdr))
			_nscd_proc_pulse(argp, iam);
		break;

	case NSCD_FORK:
		N2N_check_priv(argp, "NSCD_FORK");
		if (NSCD_STATUS_IS_OK(phdr))
			_nscd_proc_fork(argp, iam);
		break;

	case NSCD_KILL:
		N2N_check_priv(argp, "NSCD_KILL");
		if (NSCD_STATUS_IS_OK(phdr))
			exit(0);
		break;

	case NSCD_REFRESH:
		N2N_check_priv(argp, "NSCD_REFRESH");
		if (NSCD_STATUS_IS_OK(phdr)) {
			if (_nscd_refresh() != NSCD_SUCCESS)
				exit(1);
			NSCD_SET_STATUS_SUCCESS(phdr);
		}
		break;

	case NSCD_GETPUADMIN:

		if (_nscd_is_self_cred_on(0, NULL)) {
			_nscd_peruser_getadmin(argp, sizeof (nscd_admin_t));
		} else {
			NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0,
			    NSCD_SELF_CRED_NOT_CONFIGURED);
		}
		break;

	case NSCD_GETADMIN:

		len = _nscd_door_getadmin((void *)argp);
		if (len == 0)
			break;

		/* size of door buffer not big enough, allocate one */
		NSCD_ALLOC_DOORBUF(NSCD_GETADMIN, len, uptr, buflen);

		/* copy packed header */
		*(nss_pheader_t *)uptr = *(nss_pheader_t *)((void *)argp);

		/* set new buffer size */
		((nss_pheader_t *)uptr)->pbufsiz = buflen;

		/* try one more time */
		(void) _nscd_door_getadmin((void *)uptr);
		(void) door_return(uptr, buflen, NULL, 0);
		break;

	case NSCD_SETADMIN:
		N2N_check_priv(argp, "NSCD_SETADMIN");
		if (NSCD_STATUS_IS_OK(phdr))
			_nscd_door_setadmin(argp);
		break;

	case NSCD_KILLSERVER:
		N2N_check_priv(argp, "NSCD_KILLSERVER");
		if (NSCD_STATUS_IS_OK(phdr)) {
			/* also kill the forker nscd if one is running */
			_nscd_kill_forker();
			exit(0);
		}
		break;

	default:
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
		(me, "Unknown name service door call op %d\n",
		    phdr->nsc_callnumber);

		NSCD_SET_STATUS(phdr, NSS_ERROR, EINVAL);

		(void) door_return(argp, arg_size, NULL, 0);
		break;

	}
	(void) door_return(argp, arg_size, NULL, 0);
}

int
_nscd_setup_server(char *execname, char **argv)
{

	int		fd;
	int		errnum;
	int		bind_failed = 0;
	mode_t		old_mask;
	struct stat	buf;
	sigset_t	myset;
	struct sigaction action;
	char		*me = "_nscd_setup_server";

	main_execname = execname;
	main_argv = argv;

	/* Any nscd process is to ignore SIGPIPE */
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		errnum = errno;
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
		(me, "signal (SIGPIPE): %s\n", strerror(errnum));
		return (-1);
	}

	keep_open_dns_socket();

	/*
	 * the max number of server threads should be fixed now, so
	 * set flag to indicate that no in-flight change is allowed
	 */
	max_servers_set = 1;

	(void) thr_keycreate(&lookup_state_key, NULL);
	(void) sema_init(&common_sema, frontend_cfg_g.common_worker_threads,
	    USYNC_THREAD, 0);

	/* Establish server thread pool */
	(void) door_server_create(server_create);
	if (thr_keycreate(&server_key, server_destroy) != 0) {
		errnum = errno;
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
		(me, "thr_keycreate (server thread): %s\n",
		    strerror(errnum));
		return (-1);
	}

	/* Create a door */
	if ((fd = door_create(switcher, NAME_SERVICE_DOOR_COOKIE,
	    DOOR_UNREF | DOOR_NO_CANCEL)) < 0) {
		errnum = errno;
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
		(me, "door_create: %s\n", strerror(errnum));
		return (-1);
	}

	/* if not main nscd, no more setup to do */
	if (_whoami != NSCD_MAIN)
		return (fd);

	/* bind to file system */
	if (is_system_labeled() && (getzoneid() == GLOBAL_ZONEID)) {
		if (stat(TSOL_NAME_SERVICE_DOOR, &buf) < 0) {
			int	newfd;

			/* make sure the door will be readable by all */
			old_mask = umask(0);
			if ((newfd = creat(TSOL_NAME_SERVICE_DOOR, 0444)) < 0) {
				errnum = errno;
				_NSCD_LOG(NSCD_LOG_FRONT_END,
				    NSCD_LOG_LEVEL_ERROR)
				(me, "Cannot create %s: %s\n",
				    TSOL_NAME_SERVICE_DOOR,
				    strerror(errnum));
				bind_failed = 1;
			}
			/* rstore the old file mode creation mask */
			(void) umask(old_mask);
			(void) close(newfd);
		}
		if (symlink(TSOL_NAME_SERVICE_DOOR, NAME_SERVICE_DOOR) != 0) {
			if (errno != EEXIST) {
				errnum = errno;
				_NSCD_LOG(NSCD_LOG_FRONT_END,
				    NSCD_LOG_LEVEL_ERROR)
				(me, "Cannot symlink %s: %s\n",
				    NAME_SERVICE_DOOR, strerror(errnum));
				bind_failed = 1;
			}
		}
	} else if (stat(NAME_SERVICE_DOOR, &buf) < 0) {
		int	newfd;

		/* make sure the door will be readable by all */
		old_mask = umask(0);
		if ((newfd = creat(NAME_SERVICE_DOOR, 0444)) < 0) {
			errnum = errno;
			_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
			(me, "Cannot create %s: %s\n", NAME_SERVICE_DOOR,
			    strerror(errnum));
			bind_failed = 1;
		}
		/* rstore the old file mode creation mask */
		(void) umask(old_mask);
		(void) close(newfd);
	}

	if (bind_failed == 1) {
		(void) door_revoke(fd);
		return (-1);
	}

	if (fattach(fd, NAME_SERVICE_DOOR) < 0) {
		if ((errno != EBUSY) ||
		    (fdetach(NAME_SERVICE_DOOR) <  0) ||
		    (fattach(fd, NAME_SERVICE_DOOR) < 0)) {
			errnum = errno;
			_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
			(me, "fattach: %s\n", strerror(errnum));
			(void) door_revoke(fd);
			return (-1);
		}
	}

	/*
	 * kick off routing socket monitor thread
	 */
	if (thr_create(NULL, 0,
	    (void *(*)(void *))rts_mon, 0, 0, NULL) != 0) {
		errnum = errno;
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
		(me, "thr_create (routing socket monitor): %s\n",
		    strerror(errnum));

		(void) door_revoke(fd);
		return (-1);
	}

	/*
	 * set up signal handler for SIGHUP
	 */
	action.sa_handler = dozip;
	action.sa_flags = 0;
	(void) sigemptyset(&action.sa_mask);
	(void) sigemptyset(&myset);
	(void) sigaddset(&myset, SIGHUP);

	if (sigaction(SIGHUP, &action, NULL) < 0) {
		errnum = errno;
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
		(me, "sigaction (SIGHUP): %s\n", strerror(errnum));

		(void) door_revoke(fd);
		return (-1);
	}

	return (fd);
}

int
_nscd_setup_child_server(int did)
{

	int		errnum;
	int		fd;
	nscd_rc_t	rc;
	char		*me = "_nscd_setup_child_server";

	/* Re-establish our own server thread pool */
	(void) door_server_create(server_create);
	if (thr_keycreate(&server_key, server_destroy) != 0) {
		errnum = errno;
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_DEBUG)
		(me, "thr_keycreate failed: %s", strerror(errnum));
		return (-1);
	}

	/*
	 * Create a new door.
	 * Keep DOOR_REFUSE_DESC (self-cred nscds don't fork)
	 */
	(void) close(did);
	if ((fd = door_create(switcher, NAME_SERVICE_DOOR_COOKIE,
	    DOOR_REFUSE_DESC|DOOR_UNREF|DOOR_NO_CANCEL)) < 0) {
		errnum = errno;
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_DEBUG)
		(me, "door_create failed: %s", strerror(errnum));
		return (-1);
	}

	/*
	 * kick off routing socket monitor thread
	 */
	if (thr_create(NULL, 0,
	    (void *(*)(void *))rts_mon, 0, 0, NULL) != 0) {
		errnum = errno;
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
		(me, "thr_create (routing socket monitor): %s\n",
		    strerror(errnum));
		(void) door_revoke(fd);
		return (-1);
	}

	/*
	 * start monitoring the states of the name service clients
	 */
	rc = _nscd_init_smf_monitor();
	if (rc != NSCD_SUCCESS) {
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
	(me, "unable to start the SMF monitor (rc = %d)\n", rc);

		(void) door_revoke(fd);
		return (-1);
	}

	return (fd);
}

nscd_rc_t
_nscd_alloc_frontend_cfg()
{
	frontend_cfg  = calloc(NSCD_NUM_DB, sizeof (nscd_cfg_frontend_t));
	if (frontend_cfg == NULL)
		return (NSCD_NO_MEMORY);

	return (NSCD_SUCCESS);
}


/* ARGSUSED */
nscd_rc_t
_nscd_cfg_frontend_notify(
	void				*data,
	struct nscd_cfg_param_desc	*pdesc,
	nscd_cfg_id_t			*nswdb,
	nscd_cfg_flag_t			dflag,
	nscd_cfg_error_t		**errorp,
	void				*cookie)
{
	void				*dp;

	/*
	 * At init time, the whole group of config params are received.
	 * At update time, group or individual parameter value could
	 * be received.
	 */

	if (_nscd_cfg_flag_is_set(dflag, NSCD_CFG_DFLAG_INIT) ||
	    _nscd_cfg_flag_is_set(dflag, NSCD_CFG_DFLAG_GROUP)) {
		/*
		 * group data is received, copy in the
		 * entire strcture
		 */
		if (_nscd_cfg_flag_is_set(pdesc->pflag, NSCD_CFG_PFLAG_GLOBAL))
			frontend_cfg_g = *(nscd_cfg_global_frontend_t *)data;
		else
			frontend_cfg[nswdb->index] =
			    *(nscd_cfg_frontend_t *)data;

	} else {
		/*
		 * individual paramater is received: copy in the
		 * parameter value.
		 */
		if (_nscd_cfg_flag_is_set(pdesc->pflag, NSCD_CFG_PFLAG_GLOBAL))
			dp = (char *)&frontend_cfg_g + pdesc->p_offset;
		else
			dp = (char *)&frontend_cfg[nswdb->index] +
			    pdesc->p_offset;
		(void) memcpy(dp, data, pdesc->p_size);
	}

	return (NSCD_SUCCESS);
}

/* ARGSUSED */
nscd_rc_t
_nscd_cfg_frontend_verify(
	void				*data,
	struct	nscd_cfg_param_desc	*pdesc,
	nscd_cfg_id_t			*nswdb,
	nscd_cfg_flag_t			dflag,
	nscd_cfg_error_t		**errorp,
	void				**cookie)
{

	char				*me = "_nscd_cfg_frontend_verify";

	/*
	 * if max. number of server threads is set and in effect,
	 * don't allow changing of the frontend configuration
	 */
	if (max_servers_set) {
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_INFO)
	(me, "changing of the frontend configuration not allowed now");

		return (NSCD_CFG_CHANGE_NOT_ALLOWED);
	}

	return (NSCD_SUCCESS);
}

/* ARGSUSED */
nscd_rc_t
_nscd_cfg_frontend_get_stat(
	void				**stat,
	struct nscd_cfg_stat_desc	*sdesc,
	nscd_cfg_id_t			*nswdb,
	nscd_cfg_flag_t			*dflag,
	void				(**free_stat)(void *stat),
	nscd_cfg_error_t		**errorp)
{
	return (NSCD_SUCCESS);
}

void
_nscd_init_cache_sema(sema_t *sema, char *cache_name)
{
	int	i, j;
	char	*dbn;

	if (max_servers == 0)
		max_servers = frontend_cfg_g.common_worker_threads +
		    frontend_cfg_g.cache_hit_threads;

	for (i = 0; i < NSCD_NUM_DB; i++) {

		dbn = NSCD_NSW_DB_NAME(i);
		if (strcasecmp(dbn, cache_name) == 0) {
			j = frontend_cfg[i].worker_thread_per_nsw_db;
			(void) sema_init(sema, j, USYNC_THREAD, 0);
			max_servers += j;
			break;
		}
	}
}

/*
 * Monitor the routing socket.  Address lists stored in the ipnodes
 * cache are sorted based on destination address selection rules,
 * so when things change that could affect that sorting (interfaces
 * go up or down, flags change, etc.), we clear that cache so the
 * list will be re-ordered the next time the hostname is resolved.
 */
static void
rts_mon(void)
{
	int	rt_sock, rdlen, idx;
	union {
		struct {
			struct rt_msghdr rtm;
			struct sockaddr_storage addrs[RTA_NUMBITS];
		} r;
		struct if_msghdr ifm;
		struct ifa_msghdr ifam;
	} mbuf;
	struct ifa_msghdr *ifam = &mbuf.ifam;
	char	*me = "rts_mon";

	(void) thr_setname(thr_self(), me);

	rt_sock = socket(PF_ROUTE, SOCK_RAW, 0);
	if (rt_sock < 0) {
		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
		(me, "Failed to open routing socket: %s\n", strerror(errno));
		thr_exit(0);
	}

	for (;;) {
		rdlen = read(rt_sock, &mbuf, sizeof (mbuf));
		if (rdlen <= 0) {
			if (rdlen == 0 || (errno != EINTR && errno != EAGAIN)) {
				_NSCD_LOG(NSCD_LOG_FRONT_END,
				    NSCD_LOG_LEVEL_ERROR)
				(me, "routing socket read: %s\n",
				    strerror(errno));
				thr_exit(0);
			}
			continue;
		}
		if (ifam->ifam_version != RTM_VERSION) {
				_NSCD_LOG(NSCD_LOG_FRONT_END,
				    NSCD_LOG_LEVEL_ERROR)
				(me, "rx unknown version (%d) on "
				    "routing socket.\n",
				    ifam->ifam_version);
			continue;
		}
		switch (ifam->ifam_type) {
		case RTM_NEWADDR:
		case RTM_DELADDR:
			/* if no ipnodes cache, then nothing to do */
			idx = get_cache_idx("ipnodes");
			if (cache_ctx_p[idx] == NULL ||
			    cache_ctx_p[idx]->reaper_on != nscd_true)
				break;
			nsc_invalidate(cache_ctx_p[idx], NULL, NULL);
			break;
		case RTM_ADD:
		case RTM_DELETE:
		case RTM_CHANGE:
		case RTM_GET:
		case RTM_LOSING:
		case RTM_REDIRECT:
		case RTM_MISS:
		case RTM_LOCK:
		case RTM_OLDADD:
		case RTM_OLDDEL:
		case RTM_RESOLVE:
		case RTM_IFINFO:
		case RTM_CHGADDR:
		case RTM_FREEADDR:
			break;
		default:
			_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
			(me, "rx unknown msg type (%d) on routing socket.\n",
			    ifam->ifam_type);
			break;
		}
	}
}

static void
keep_open_dns_socket(void)
{
	_res.options |= RES_STAYOPEN; /* just keep this udp socket open */
}
