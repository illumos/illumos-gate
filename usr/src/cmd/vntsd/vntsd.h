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
 * vntsd uses configuration information provided by vcc to export access
 * to Ldom console access over regular TCP sockets. When it starts, it opens
 * the vcc driver control port and obtains the list of ports that have been
 * created by the vcc driver as well as TCP port number and group associated
 * with each port.
 * vntsd consists of multiple components as the follows:
 *
 * vntsd.c
 * This module initializes vnts daemon, process user options such as instance
 * number, ip address and etc., and provides main thread to poll any console
 * port change.
 *
 * vntsdvcc.c
 * This module provides vcc driver interface. It opens vcc driver control
 * ports, read initial configuration, and provides interface to read, write and
 * ioctl virtual console ports. This module creates a listen thread for each
 * console group. It further dynamically adds and removes virtual consoles
 * and groups following instructions of the vcc driver. This module
 * is executed in the same thread as vntsd.c which is blocked on vcc control
 * poll interface.
 *
 * listen.c
 * This is a group listen thread. Each group's tcp-port has a listen thread
 * associated with it. The thread is created when a console is associated with
 * a new group and is removed when all consoles in the group are removed.
 *
 * console.c
 * This is a console selection thread. The thread is created when a client
 * connects to a group TCP port and exited when client disconnects. If there is
 * only one console in the group, the client is connected to that console. If
 * there are multiple consoles in the group, the client is asked to select a
 * console. After determining which console to connect to, this thread
 * a write thread if the cient is a writer and it self read in client input.
 *
 * read.c
 * it reads input from a TCP client, processes
 * special daemon and telent commands and write to vcc driver if the client
 * is a writer. The client is a writer if the client is the first one connects
 * to the console. Read thread print out an error message if a reader attempt
 * to input to vcc. Read thread exits if console is deleted, client
 * disconnects, or there is a fatal error.
 *
 * Write.c
 * Write thread is creaed when first client connects to a console. It reads
 * from vcc and writes to all clients that connect to the same console.
 * Write thread exits when all clients disconnect from the console.
 *
 * cmd.c
 * This is a supporting module for handling special daemon and telnet commands.
 *
 * common.c
 * supporting modules shared by threads modules.
 *
 * queue.c
 * This is a moudle supporting queue operations. Vntsd organizes its data
 * in multiple queues <see data structure below>.
 *
 * vntsd.xml
 * This is a manifest to support SMF interfaces.
 *
 * Data structures
 * each group has a vntsd_group_t structure, which contains a queue of
 * all console in that group.
 * each console has a vntsd_cons_t structure, which contains a queue of
 * all clients that connected to the console.
 *
 *     +----------+   +----------+   +----------+
 *     |  group	  |-->|  group   |-->|   group  |-->....
 *     +----------+   +----------+   +----------+
 *          |
 *          |<-----------------------------------------+
 *          |<------------------------+                |
 *          |<--------+               |                |
 *          |         |               |                |
 *          |      +----------+     +----------+     +----------+
 *          +----->| console  |---->| console  |---->| lconsole |---> ....
 *                 +----------+     +----------+     +----------+
 *                     |  |
 *		       |  |     +----------+      +----------+
 *		       |  +---->|  client  |----->|   client |----->......
 *		       |	+----------+      +----------+
 *		       |	     |                 |
 *		       |<------------+                 |
 *		       |<------------------------------+
 *
 * Locks
 *  Each vntsd has one lock to protect the group queue
 *  Each group has one lock to protect the console queue,  the queue for
 *  clients without a console connection and status.
 *  Each console has one lock to protect client queue and status.
 *  Each client has one lock to protect the state of the client. The client
 *  states are:
 *
 *  VCC_CLIENT_READER
 *	A client is connected to a console as either a writer or a reader.
 *	if this client is the first one connects the console, the client is
 *	a writer, otherwise the client is a reader. A writer' write thread
 *	reads from vcc and send output to all readers connected to the
 *	same console. a reader's write thread is blocked until a reader becomes
 *	a writer.
 *
 *	When a client selected a console, the client becomes a reader if
 *	there is another client connected to the console before the client.
 *	A client will be a writer if
 *	1. client is the first one connected to the console or
 *	2. client has entered a ~w daemon command or
 *	3. all clients connected to the console before the client have
 *	   disconnected from the console.
 *
 *  VCC_CLIENT_MOVE_CONS_FORWARD
 *  VCC_CLIENT_MOVE_CONS_BACKWOARD
 *	A client is disconnecting from one console and move to the next or
 *	previous console in the group queue.
 *	A client is in one of these state if
 *	1. the client has entered the daemon command and
 *	2. the vntsd is in process of switching the client from one
 *	   console to another.
 *
 *  VCC_CLIENT_DISABLE_DAEMON_CMD
 *	vntsd is in processing of a client's daemon command or the client is
 *	in selecting console.
 *	A client is in this state if
 *	1. the client has not selected a console or
 *	2. the vntsd is processing a client's daemon command.
 *
 *  VCC_CLIENT_ACQUIRE_WRITER
 *	A reader forces to become a writer via vntsd special command.
 *	A client is in this state if
 *	1. the client is a reader and
 *	2. client has entered a daemon command to become a writer.
 *
 *  VCC_CLIENT_CONS_DELETED
 *	The console that the client is connected to is being deleted and
 *	waiting for the client to disconnect.
 *	A client is in this state if
 *	1. the console a client is connected to is being removed and
 *	2. the vntsd is in process of disconnecting the client from the console.
 *
 */

#ifndef _VNTSD_H
#define	_VNTSD_H

#ifdef __cplusplus
extern "C" {
#endif

#include	<sys/shm.h>
#include	<strings.h>
#include	<assert.h>
#include	<sys/wait.h>
#include	<sys/stat.h>
#include	<fcntl.h>
#include	<stropts.h>
#include	<errno.h>
#include	<sys/param.h>
#include	"../../uts/sun4v/sys/vcc.h"

#define	DEBUG

/* vntsd limits */
#define	    VNTSD_MAX_BUF_SIZE		128
#define	    VNTSD_LINE_LEN		100
#define	    VNTSD_MAX_SOCKETS		5
#define	    VNTSD_EOL_LEN		2

/* secons before re-send signal for cv_wait */
#define	    VNTSD_CV_WAIT_DELTIME	10

#define	    VCC_PATH_PREFIX     \
		"/devices/virtual-devices@100/channel-devices@200/"
#define	    VCC_DEVICE_PATH			"/devices%s"
#define	    VCC_DEVICE_CTL_PATH VCC_PATH_PREFIX "%s:ctl"

/* common messages */
#define	    VNTSD_NO_WRITE_ACCESS_MSG	"You do not have write access"

/* vntsd options */
#define	    VNTSD_OPT_DAEMON_OFF	0x1
#define	    VNTSD_OPT_AUTH_CHECK	0x2	/* Enable auth checking */

/*
 * group states
 * When a console is removed or vntsd is exiting, main thread
 * notifies listen, read and write thread to exit.
 * After those threads exit, main thread clears up group structurre.
 *
 * VNTSD_GROUP_SIG_WAIT
 * The main thread is waiting for listen thread to exit.
 * VNTSD_GROUP_CLEAN_CONS
 * There are console(s) in the group that are being removed.
 * This is a transition state where the corresponding vcc port has been
 * removed, but vntsd has not done its clean up yet.
 * VNTSD_GROUP_IN_CLEANUP
 * vntsd main thread has started cleaning up the group.
 */

#define	    VNTSD_GROUP_SIG_WAIT	0x1
#define	    VNTSD_GROUP_CLEAN_CONS	0x2
#define	    VNTSD_GROUP_IN_CLEANUP	0x4





/*
 * console states
 * There are two states when a console is removed
 * VNTSD_CONS_DELETED
 * the console is being deleted
 * VNTSD_CONS_SIG_WAIT
 * console is waiting for all clients to exit.
 */

#define	    VNTSD_CONS_DELETED		0x1	/* deleted */
#define	    VNTSD_CONS_SIG_WAIT		0x2	/* waiting for signal */


#define	    VNTSD_CLIENT_IO_ERR		    0x1	    /* reader */
#define	    VNTSD_CLIENT_DISABLE_DAEMON_CMD 0x2	    /* disable daemon cmd */
#define	    VNTSD_CLIENT_TIMEOUT	    0x4	    /* timeout */
#define	    VNTSD_CLIENT_CONS_DELETED	    0x8	    /* console deleted */

/* generic que structure */
typedef	struct vntsd_que {
	void			*handle;	/* element in queue */
	struct vntsd_que	*nextp;		/* next queue element */
	struct vntsd_que	*prevp;		/* previous queue element */
} vntsd_que_t;

struct vntsd_cons;
struct vntsd_group;
struct vntsd;

/* client structure  */
typedef struct vntsd_client {
	mutex_t	    lock;	    /* protect the client */
	uint_t	    status;	    /* client's state */

	int	    sockfd;	    /* connection socket */
	thread_t    cons_tid;	    /* console thread */

	struct vntsd_cons    *cons; /* back link to console configuration */

	char	    prev_char;	    /* previous char read by this client */

} vntsd_client_t;

/* console structure */
typedef struct vntsd_cons {
	mutex_t		lock;			    /* protect console port */
	cond_t		cvp;			    /* sync between threads */

	vntsd_que_t	*clientpq;		    /* client que */
	uint_t		status;			    /* client's state */
	int		vcc_fd;			    /* vcc console port */
	thread_t	wr_tid;			    /* write thread */

	uint_t		cons_no;		    /* console port number  */
	char		domain_name[MAXPATHLEN];    /* domain name */
	char		dev_name[MAXPATHLEN];

	struct vntsd_group   *group;		    /* back link to group */
} vntsd_cons_t;

/* group structure  */
typedef struct vntsd_group {
	mutex_t	    lock;		    /* protect group */
	cond_t	    cvp;		    /* sync remove group */

	uint_t	    status;		    /* group status */
	char	    group_name[MAXPATHLEN];
	uint64_t    tcp_port;		    /* telnet port */

	thread_t    listen_tid;		    /* listen thread */
	int	    sockfd;		    /* listen socket */

	vntsd_que_t *conspq;		    /* console queue */
	uint_t	    num_cons;		    /* num console */

	/* clients have no console connection */
	vntsd_que_t *no_cons_clientpq;
	struct vntsd   *vntsd;

} vntsd_group_t;

/* daemon structure */
typedef struct vntsd {

	mutex_t		lock;			/* protect vntsd */
	mutex_t		tmo_lock;		/* protect tmo queue */

	int		instance;		/* vcc instance */
	struct in_addr  ip_addr;		/* ip address to listen */
	uint64_t	options;		/* daemon options */
	int		timeout;		/* connection timeout */

	char		*devinst;		/* device name */
	int		ctrl_fd;		/* vcc ctrl port */

	vntsd_que_t	*grouppq;		/* group queue */
	uint_t		num_grps;		/* num groups */

	vntsd_que_t	*tmoq;			/* timeout queue */
	thread_t	tid;			/* main thread id */

} vntsd_t;

/* handle for creating thread */
typedef	struct vntsd_thr_arg {
	void	*handle;
	void	*arg;
} vntsd_thr_arg_t;

/* timeout structure */
typedef struct vntsd_timeout {
	thread_t	tid;		    /* thread tid */
	uint_t		minutes;	    /* idle minutes */
	vntsd_client_t	*clientp;	    /* client */
} vntsd_timeout_t;

/* vntsd status and error  definitions */
typedef enum {

	/* status */
	VNTSD_SUCCESS = 0,		/* success */
	VNTSD_STATUS_CONTINUE,		/* continue to execute */
	VNTSD_STATUS_EXIT_SIG,		/* exit siginal */
	VNTSD_STATUS_SIG,		/* known signal */
	VNTSD_STATUS_NO_HOST_NAME,	/* no host name set */
	VNTSD_STATUS_CLIENT_QUIT,	/* client disconnected from group */
	VNTSD_STATUS_RESELECT_CONS,	/* client re-selecting console */
	VNTSD_STATUS_VCC_IO_ERR,	/* a vcc io error occurs */
	VNTSD_STATUS_MOV_CONS_FORWARD,	/* down arrow  */
	VNTSD_STATUS_MOV_CONS_BACKWARD,	/* up  arrow  */
	VNTSD_STATUS_ACQUIRE_WRITER,	/* force become the writer */
	VNTSD_STATUS_INTR,		/* thread receive a signal */
	VNTSD_STATUS_DISCONN_CONS,	/* disconnect a client from cons */
	VNTSD_STATUS_NO_CONS,		/* disconnect a client from cons */
	VNTSD_STATUS_AUTH_ENABLED,	/* auth enabled; can't process '-p' */

	/* resource errors */
	VNTSD_ERR_NO_MEM,		/* memory allocation error */
	VNTSD_ERR_NO_DRV,		/* cannot open vcc port */

	/* vcc errors */
	VNTSD_ERR_VCC_CTRL_DATA,	/* vcc ctrl data error */
	VNTSD_ERR_VCC_POLL,		/* error poll vcc driver */
	VNTSD_ERR_VCC_IOCTL,		/* vcc ioctl call error */
	VNTSD_ERR_VCC_GRP_NAME,		/* group name differs from database */
	VNTSD_ERR_ADD_CONS_FAILED,	/* addition of a console failed */

	/* create thread errors */
	VNTSD_ERR_CREATE_LISTEN_THR,	/* listen thread creation failed */
	VNTSD_ERR_CREATE_CONS_THR,	/* create console thread err  */
	VNTSD_ERR_CREATE_WR_THR,	/* listen thread creation failed */

	/* listen thread errors */
	VNTSD_ERR_LISTEN_SOCKET,	/* can not create tcp socket */
	VNTSD_ERR_LISTEN_OPTS,		/* can not set socket opt */
	VNTSD_ERR_LISTEN_BIND,		/* can not bind socket */
	VNTSD_STATUS_ACCEPT_ERR,	/* accept error  */

	/* tcp client read and write errors */
	VNTSD_ERR_WRITE_CLIENT,		/* writing tcp client err */

	/* tcp client timeout */
	VNTSD_ERR_CLIENT_TIMEOUT,	/* client has no activity for timeout */

	/* signal errors */
	VNTSD_ERR_SIG,			/* unknown signal */

	/* user input error */
	VNTSD_ERR_INVALID_INPUT,	/* client typed in */

	/* internal errors */
	VNTSD_ERR_EL_NOT_FOUND,		/* element not found */
	VNTSD_ERR_UNKNOWN_CMD		/* unknown error/cmd */

} vntsd_status_t;

/* function prototype defines */
typedef	int	    (*compare_func_t)(void *el, void *data);
typedef	int	    (*el_func_t)(void *el);
typedef	void	    (*clean_func_t)(void *el);
typedef	void	    (*sig_handler_t)(int sig);
typedef	void	    *(*thr_func_t)(void *);



/* function prototype */
void		vntsd_log(vntsd_status_t err, char *msg);
struct in_addr	vntsd_ip_addr(void);

void		vntsd_get_config(vntsd_t *vntsdp);
void		vntsd_daemon_wakeup(vntsd_t *vntsdp);
int		vntsd_open_vcc(char *domain_name, uint_t cons_no);
void		vntsd_delete_cons(vntsd_t *vntsdp);
void		vntsd_clean_group(vntsd_group_t *groupp);


void		*vntsd_listen_thread(vntsd_group_t *groupp);
void		*vntsd_console_thread(vntsd_thr_arg_t *argp);
int		vntsd_read(vntsd_client_t *clientp);
void		*vntsd_write_thread(vntsd_cons_t *consp);

boolean_t	vntsd_cons_by_consno(vntsd_cons_t *consp, int *cons_id);

int		vntsd_que_append(vntsd_que_t **que_hd, void *handle);
int		vntsd_que_rm(vntsd_que_t **que_hd, void *handle);
void		*vntsd_que_find(vntsd_que_t *que_hd, compare_func_t
			compare_func, void *data);
void		*vntsd_que_walk(vntsd_que_t *que_hd, el_func_t el_func);

int		vntsd_que_insert_after(vntsd_que_t *que, void *handle,
			void *next);
void		*vntsd_que_pos(vntsd_que_t *que_hd, void *handle, int pos);
void		vntsd_free_que(vntsd_que_t **q, clean_func_t clean_func);

int		vntsd_read_char(vntsd_client_t *clientp, char *c);
int		vntsd_read_line(vntsd_client_t *clientp, char *buf, int *size);
int		vntsd_read_data(vntsd_client_t *clientp, char *c);
int		vntsd_get_yes_no(vntsd_client_t *clientp, char *msg,
			int *yes_no);
int		vntsd_ctrl_cmd(vntsd_client_t *clientp, char c);
int		vntsd_process_daemon_cmd(vntsd_client_t *clientp, char c);
int		vntsd_telnet_cmd(vntsd_client_t *clientp, char c);

int		vntsd_set_telnet_options(int fd);
int		vntsd_write_client(vntsd_client_t *client, char *buffer,
	size_t sz);
int		vntsd_write_fd(int fd, void *buffer, size_t sz);
int		vntsd_write_line(vntsd_client_t *clientp, char *line);
int		vntsd_write_lines(vntsd_client_t *clientp, char *lines);
extern char	vntsd_eol[];

void		vntsd_clean_group(vntsd_group_t *portp);
void		vntsd_free_client(vntsd_client_t *clientp);
int		vntsd_attach_timer(vntsd_timeout_t *tmop);
int		vntsd_detach_timer(vntsd_timeout_t *tmop);
void		vntsd_reset_timer(thread_t tid);
void		vntsd_init_esctable_msgs(void);
int		vntsd_vcc_ioctl(int ioctl_code, uint_t portno, void *buf);
int		vntsd_vcc_err(vntsd_cons_t *consp);
int		vntsd_cons_chk_intr(vntsd_client_t *clientp);
boolean_t	vntsd_vcc_cons_alive(vntsd_cons_t *consp);
boolean_t	vntsd_notify_client_cons_del(vntsd_client_t *clientp);
int		vntsd_chk_group_total_cons(vntsd_group_t *groupp);
boolean_t	vntsd_mark_deleted_cons(vntsd_cons_t *consp);
boolean_t	auth_check_fd(int sock_fd, char *group_name);

#ifdef	DEBUG

extern int vntsddbg;

#define	D1 	if (vntsddbg & 0x01) (void) fprintf
#define	D2	if (vntsddbg & 0x02) (void) fprintf
#define	D3 	if (vntsddbg & 0x04) (void) fprintf
#define	DERR 	if (vntsddbg & 0x08) (void) fprintf

#else  /* not DEBUG */

#define	D1
#define	D2
#define	D3
#define	DERR

#endif /* not DEBUG */

#ifdef __cplusplus
}
#endif

#endif /* _VNTSD_H */
