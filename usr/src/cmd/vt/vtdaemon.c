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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * vtdaemon is responsible for the session secure switch via hotkeys.
 *
 * vtdaemon itself, like ttymon(8), is also running on a virtual
 * console device (/dev/vt/1), and provides a text console session
 * for password input and authentication. The /dev/vt/1 special text
 * console is reserved and end users cannot switch to it via hotkeys.
 *
 *
 * The hotkey event request can come from either kernel or Xserver,
 * and a door server is setup to handle the request:
 *
 *   1) All text console hotkeys (e.g. "Alt + F#") are intercepted by
 *      the kernel console driver which sends a door upcall to the
 *      vtdaemon via door_upcall (target_vt).
 *
 *   2) All Xserver hotkeys ("Alt + Ctrl + F#") are intercepted by
 *      Xserver which sends a door call to the vtdaemon via
 *      door_call (target_vt).
 *
 *
 * server_for_door receives and handles any door server requests:
 *
 *   Firstly, check source session:
 *
 *      . If it's from kernel for a text console source session,
 *        then directly go to check the target session.
 *
 *      . If it's from Xserver for a graphical source session and the vt
 *        associated with the Xserver is currently active:
 *          check if a user has logged in, if true, issue an internal
 *          VT_EV_LOCK event to the main thread to request lock for
 *          the graphical source session; else, directly go to check
 *          the target session.
 *
 *      . otherwise, discard this request.
 *
 *
 *    Secondly, check the target session
 *
 *      . if the target session is a text one that no one has logged in
 *        or a graphical one, issue an internal VT_EV_ACTIVATE event to
 *        the main thread to request the actual VT switch.
 *
 *      . otherwise, the target session is a text one that someone has
 *        logged in, issue an internal VT_EV_AUTH event to the main
 *        thread to request authentication for the target session.
 *
 *
 * The main thread of vtdaemon is a loop waiting for internal events
 * which come from door call threads:
 *
 *   1)  VT_EV_AUTH      to authenticate for target session:
 *
 *                       firstly switch to the vtdaemon special text console;
 *                       then prompt for password (target_owner on target_vt),
 *                       e.g. "User Bob's password on vt/#: ".
 *
 *                       if the password is correct (authentication succeeds),
 *                       then actually issue the VT switch; otherwise, ignore
 *                       the request.
 *
 *   2)  VT_EV_LOCK      to lock the graphical source session:
 *
 *                       activate screenlock for this graphical session.
 *                       vtdaemon just invokes existing front-end command line
 *                       tools (e.g. xscreensaver-command -lock for JDS) to
 *                       lock the display.
 *
 *   3)  VT_EV_ACTIVATE  to directly switch to the target session
 *
 *
 * There is a system/vtdaemon:default SMF service for vtdaemon.
 *
 *	There's a "hotkeys" property (BOOLEAN) in the
 *	system/vtdaemon:default SMF service, which allows authorized
 *	users to dynamically enable or disable VT switch via hotkeys.
 *      Its default value is TRUE (enabled).
 *
 *	There's a "secure" property (BOOLEAN) in the
 *	system/vtdaemon:default SMF service, which allows authorized
 *	users to dynamically enable or disable hotkeys are secure.
 *	If disabled, the user can freely switch to any session without
 *	authentication. Its default value is TRUE (enabled).
 *
 *
 *  By default, there's only 16 virtual console device nodes (from
 *  /dev/vt/0 to /dev/vt/15). There's a property "nodecount"
 *  (default value is 16) in the system/vtdaemon:default SMF
 *  service, so authorized users can configure it to have more
 *  or less virtual console device nodes.
 *
 *  Xserver needs to switch back to previous active vt via VT_EV_X_EXIT
 *  door event request when it's exiting, so vtdaemon always needs to
 *  be there even if the hotkeys switch is disabled, otherwise the screen
 *  will be just blank when Xserver exits.
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <syslog.h>
#include <deflt.h>

#include <bsm/adt.h>
#include <bsm/adt_event.h>

#include <alloca.h>
#include <assert.h>
#include <errno.h>
#include <door.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <synch.h>
#include <thread.h>
#include <unistd.h>
#include <wait.h>
#include <limits.h>
#include <zone.h>
#include <priv.h>
#include <pwd.h>
#include <utmpx.h>
#include <procfs.h>
#include <poll.h>
#include <termio.h>
#include <security/pam_appl.h>
#include <time.h>
#include <sys/console.h>
#include <assert.h>
#include <syslog.h>

#include <sys/vt.h>
#include <sys/vtdaemon.h>

/*
 * The door file /var/run/vt/vtdaemon_door
 */
#define	VT_TMPDIR "/var/run/vt"

#define	VT_DAEMON_ARG	0
#define	VT_DAEMON_CONSOLE_FILE	"/dev/vt/1"

#define	VT_IS_SYSTEM_CONSOLE(vtno)	((vtno) == 1)

/* Defaults for updating expired passwords */
#define	DEF_ATTEMPTS	3

int daemonfd;

static boolean_t vt_hotkeys = B_TRUE;		/* '-k' option to disable */
static boolean_t vt_secure = B_TRUE;		/* '-s' option to disable */

static char	vt_door_path[MAXPATHLEN];
static int	vt_door = -1;

/* protecting vt_hotkeys_pending and vt_auth_doing */
static mutex_t	vt_mutex = DEFAULTMUTEX;

static boolean_t vt_hotkeys_pending = B_FALSE;
static boolean_t vt_auth_doing = B_FALSE;

static adt_session_data_t **vt_ah_array = NULL;
static int vtnodecount = 0;

static int vt_audit_start(adt_session_data_t **, pid_t);
static void vt_audit_event(adt_session_data_t *, au_event_t, int);
static void vt_check_source_audit(void);

static int
vt_setup_signal(int signo, int mask)
{
	sigset_t set;

	(void) sigemptyset(&set);
	(void) sigaddset(&set, signo);

	if (mask)
		return (sigprocmask(SIG_BLOCK, &set, NULL));
	else
		return (sigprocmask(SIG_UNBLOCK, &set, NULL));
}

static void
do_activate_screenlock(int display_num)
{
	char dpy[16];

	(void) snprintf(dpy, sizeof (dpy), "%d", display_num);
	(void) execl("/usr/lib/vtxlock", "vtxlock", dpy, NULL);
}

static void
vt_activate_screenlock(int display)
{
	pid_t pid;

	if ((pid = fork()) == -1)
		return;

	if (pid == 0) { /* child */
		do_activate_screenlock(display);
		exit(0);
	}

	/* parent */
	while (waitpid(pid, (int *)0, 0) != pid)
		continue;
}

/*
 * Find the login process and user logged in on the target vt.
 */
static void
vt_read_utx(int target_vt, pid_t *pid, char name[])
{
	struct utmpx  *u;
	char ttyntail[sizeof (u->ut_line)];

	*pid = (pid_t)-1;

	if (VT_IS_SYSTEM_CONSOLE(target_vt)) /* system console */
		(void) snprintf(ttyntail, sizeof (ttyntail),
		    "%s", "console");
	else
		(void) snprintf(ttyntail, sizeof (ttyntail),
		    "%s%d", "vt/", target_vt);

	setutxent();
	while ((u = getutxent()) != NULL)
		/* see if this is the entry we want */
		if ((u->ut_type == USER_PROCESS) &&
		    (!nonuserx(*u)) &&
		    (u->ut_host[0] == '\0') &&
		    (strncmp(u->ut_line, ttyntail, sizeof (u->ut_line)) == 0)) {

			*pid = u->ut_pid;
			if (name != NULL) {
				(void) strncpy(name, u->ut_user,
				    sizeof (u->ut_user));
				name[sizeof (u->ut_user)] = '\0';
			}
			break;
		}

	endutxent();
}

static boolean_t
vt_is_tipline(void)
{
	static int is_tipline = 0;
	int fd;
	static char termbuf[MAX_TERM_TYPE_LEN];
	static struct cons_getterm cons_term = { sizeof (termbuf), termbuf};

	if (is_tipline != 0)
		return (is_tipline == 1);

	if ((fd = open("/dev/console", O_RDONLY)) < 0)
		return (B_FALSE);

	if (ioctl(fd, CONS_GETTERM, &cons_term) != 0 &&
	    errno == ENODEV) {
		is_tipline = 1;
	} else {
		is_tipline = -1;
	}

	(void) close(fd);
	return (is_tipline == 1);
}

static int
validate_target_vt(int target_vt)
{
	int fd;
	struct vt_stat state;

	if (target_vt < 1)
		return (-1);

	if ((fd = open(VT_DAEMON_CONSOLE_FILE, O_WRONLY)) < 0)
		return (-1);

	if (ioctl(fd, VT_GETSTATE, &state) != 0) {
		(void) close(fd);
		return (-1);
	}

	(void) close(fd);

	if (state.v_active == target_vt) {
		return (1);	/* it's current active vt */
	}

	if (target_vt == 1) {
		/*
		 * In tipline case, the system console is always
		 * available, so ignore this request.
		 */
		if (vt_is_tipline())
			return (-1);

		target_vt = 0;
	}

	/*
	 * The hotkey request and corresponding target_vt number can come
	 * from either kernel or Xserver (or other user applications).
	 * In kernel we've validated the hotkey request, but Xserver (or
	 * other user applications) cannot do it, so here we still try
	 * to validate it.
	 *
	 * VT_GETSTATE is only valid for first 16 VTs for historical reasons.
	 * Fortunately, in practice, Xserver can only send the hotkey
	 * request of target_vt number from 1 to 12 (Ctrl + Alt + F1 to F2).
	 */
	if (target_vt < 8 * sizeof (state.v_state)) {
		if ((state.v_state & (1 << target_vt)) != 0) {
			return (0);
		} else {
			return (-1);
		}
	}

	return (0);
}

static void
vt_do_activate(int target_vt)
{
	(void) ioctl(daemonfd, VT_ACTIVATE, target_vt);
	(void) mutex_lock(&vt_mutex);
	vt_hotkeys_pending = B_FALSE;
	(void) mutex_unlock(&vt_mutex);
}

/* events written to fd 0 and read from fd 1 */
#define	VT_EV_AUTH	1
#define	VT_EV_LOCK	2
#define	VT_EV_ACTIVATE	3

/* events written to fd 1 and read from fd 0 */
#define	VT_EV_TERMINATE_AUTH	4

typedef struct vt_evt {
	int	ve_cmd;
	int	ve_info;	/* vtno or display num */
} vt_evt_t;

static int eventstream[2];

boolean_t
eventstream_init(void)
{
	if (pipe(eventstream) == -1)
		return (B_FALSE);
	return (B_TRUE);
}

void
eventstream_write(int channel, vt_evt_t *pevt)
{
	(void) write(eventstream[channel], pevt, sizeof (vt_evt_t));
}

static boolean_t
eventstream_read(int channel, vt_evt_t *pevt)
{
	ssize_t rval;

	rval = read(eventstream[channel], pevt, sizeof (vt_evt_t));
	return (rval > 0);
}

static void
vt_ev_request(int cmd, int info)
{
	int channel;
	vt_evt_t ve;

	ve.ve_cmd = cmd;
	ve.ve_info = info;

	channel = (cmd == VT_EV_TERMINATE_AUTH) ? 1 : 0;
	eventstream_write(channel, &ve);
}

static void
vt_clear_events(void)
{
	int rval = 0;
	struct stat buf;
	vt_evt_t evt;

	while (rval == 0) {
		rval = fstat(eventstream[0], &buf);
		if (rval != -1 && buf.st_size > 0)
			(void) eventstream_read(0, &evt);
		else
			break;
	}
}

static int vt_conv(int, struct pam_message **,
    struct pam_response **, void *);

/*ARGSUSED*/
static void
catch(int x)
{
	(void) signal(SIGINT, catch);
}

/*
 * The SIGINT (ctl_c) will restart the authentication, and re-prompt
 * the end user to input the password.
 */
static int
vt_poll()
{
	struct pollfd pollfds[2];
	vt_evt_t ve;
	int ret;

	pollfds[0].fd = eventstream[0];
	pollfds[1].fd = daemonfd;
	pollfds[0].events = pollfds[1].events =
	    POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI;

	for (;;) {
		pollfds[0].revents = pollfds[1].revents = 0;

		ret = poll(pollfds,
		    sizeof (pollfds) / sizeof (struct pollfd), -1);
		if (ret == -1 && errno != EINTR) {
			continue;
		}

		if (ret == -1 && errno == EINTR)
			return (-1);

		if (pollfds[0].revents) {
			(void) eventstream_read(0, &ve);
			return (0);
		}

		if (pollfds[1].revents)
			return (1);

		return (0);

	}
}

static char
vt_getchar(int fd)
{
	char c;
	int cnt;

	cnt = read(fd, &c, 1);
	if (cnt > 0) {
		return (c);
	}

	return (EOF);
}

static char *
vt_getinput(int noecho)
{
	int c;
	int i = 0;
	struct termio tty;
	tcflag_t tty_flags;
	char input[PAM_MAX_RESP_SIZE];

	if (noecho) {
		(void) ioctl(daemonfd, TCGETA, &tty);
		tty_flags = tty.c_lflag;
		tty.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
		(void) ioctl(daemonfd, TCSETAF, &tty);
	}

	while ((vt_poll()) == 1) {
		if ((c = vt_getchar(daemonfd)) != '\n' && c != '\r' &&
		    c != EOF && (i < PAM_MAX_RESP_SIZE - 1))
			input[i++] = (char)c;
		else
			break;
	}

	input[i] = '\0';

	if (noecho) {
		tty.c_lflag = tty_flags;
		(void) ioctl(daemonfd, TCSETAW, &tty);
		(void) fputc('\n', stdout);
	}

	return (strdup(input));
}

/*
 * vt_conv: vtdaemon PAM conversation function.
 * SIGINT/EINTR is handled in vt_getinput()/vt_poll().
 */

/*ARGSUSED*/
static int
vt_conv(int num_msg, struct pam_message **msg,
    struct pam_response **response, void *appdata_ptr)
{
	struct pam_message	*m;
	struct pam_response	*r;
	int			i, k;

	if (num_msg >= PAM_MAX_NUM_MSG) {
		syslog(LOG_ERR, "too many messages %d >= %d",
		    num_msg, PAM_MAX_NUM_MSG);
		*response = NULL;
		return (PAM_CONV_ERR);
	}

	*response = calloc(num_msg, sizeof (struct pam_response));
	if (*response == NULL)
		return (PAM_BUF_ERR);

	m = *msg;
	r = *response;
	for (i = 0; i < num_msg; i++) {
		int echo_off = 0;

		/* Bad message */
		if (m->msg == NULL) {
			syslog(LOG_ERR, "message[%d]: %d/NULL\n",
			    i, m->msg_style);
			goto err;
		}

		/*
		 * Fix up final newline:
		 * remove from prompts, add back for messages.
		 */
		if (m->msg[strlen(m->msg)] == '\n')
			m->msg[strlen(m->msg)] = '\0';

		r->resp = NULL;
		r->resp_retcode = 0;

		switch (m->msg_style) {

		case PAM_PROMPT_ECHO_OFF:
			echo_off = 1;
			/* FALLTHROUGH */

		case PAM_PROMPT_ECHO_ON:
			(void) fputs(m->msg, stdout);

			r->resp = vt_getinput(echo_off);
			break;

		case PAM_ERROR_MSG:
			/* the user may want to see this */
			(void) fputs(m->msg, stdout);
			(void) fputs("\n", stdout);
			break;

		case PAM_TEXT_INFO:
			(void) fputs(m->msg, stdout);
			(void) fputs("\n", stdout);
			break;

		default:
			syslog(LOG_ERR, "message[%d]: unknown type"
			    "%d/val=\"%s\"", i, m->msg_style, m->msg);

			/* error, service module won't clean up */
			goto err;
		}

		/* Next message/response */
		m++;
		r++;

	}
	return (PAM_SUCCESS);

err:
	/*
	 * Service modules don't clean up responses if an error is returned.
	 * Free responses here.
	 */
	r = *response;
	for (k = 0; k < i; k++, r++) {
		if (r->resp) {
			/* Clear before freeing -- maybe a password */
			bzero(r->resp, strlen(r->resp));
			free(r->resp);
			r->resp = NULL;
		}
	}

	free(*response);
	*response = NULL;
	return (PAM_CONV_ERR);
}

#define	DEF_FILE	"/etc/default/login"

/* Get PASSREQ from default file */
static boolean_t
vt_default(void)
{
	int flags;
	char *ptr;
	boolean_t retval = B_FALSE;

	if ((defopen(DEF_FILE)) == 0) {
		/* ignore case */
		flags = defcntl(DC_GETFLAGS, 0);
		TURNOFF(flags, DC_CASE);
		(void) defcntl(DC_SETFLAGS, flags);

		if ((ptr = defread("PASSREQ=")) != NULL &&
		    strcasecmp("YES", ptr) == 0)
			retval = B_TRUE;

		(void) defopen(NULL);
	}

	return (retval);
}

/*
 * VT_CLEAR_SCREEN_STR is the console terminal escape sequence used to
 * clear the current screen.  The vt special console (/dev/vt/1) is
 * just reserved for vtdaemon, and the TERM/termcap of it is always
 * the local sun-color, which is always supported by our kernel terminal
 * emulator.
 */
#define	VT_CLEAR_SCREEN_STR	"\033[2J\033[1;1H"

static void
vt_do_auth(int target_vt)
{
	char	user_name[sizeof (((struct utmpx *)0)->ut_line) + 1] = {'\0'};
	pam_handle_t	*vt_pamh;
	int		err;
	int		pam_flag = 0;
	int		chpasswd_tries;
	struct pam_conv pam_conv = {vt_conv, NULL};
	pid_t		pid;
	adt_session_data_t	*ah;

	vt_read_utx(target_vt, &pid, user_name);

	if (pid == (pid_t)-1 || user_name[0] == '\0')
		return;

	if ((err = pam_start("vtdaemon", user_name, &pam_conv,
	    &vt_pamh)) != PAM_SUCCESS)
		return;

	/*
	 * firstly switch to the vtdaemon special console
	 * and clear the current screen
	 */
	(void) ioctl(daemonfd, VT_ACTIVATE, VT_DAEMON_ARG);
	(void) write(daemonfd, VT_CLEAR_SCREEN_STR,
	    strlen(VT_CLEAR_SCREEN_STR));
	(void) ioctl(daemonfd, VT_SET_TARGET, target_vt);

	(void) mutex_lock(&vt_mutex);
	vt_auth_doing = B_TRUE;
	vt_hotkeys_pending = B_FALSE;
	(void) mutex_unlock(&vt_mutex);

	/*
	 * Fetch audit handle.
	 */
	ah = vt_ah_array[target_vt - 1];

	if (vt_default())
		pam_flag = PAM_DISALLOW_NULL_AUTHTOK;

	do {
		if (VT_IS_SYSTEM_CONSOLE(target_vt))
			(void) fprintf(stdout,
			    "\nUnlock user %s on the system console\n",
			    user_name);
		else
			(void) fprintf(stdout,
			    "\nUnlock user %s on vt/%d\n", user_name,
			    target_vt);

		err = pam_authenticate(vt_pamh, pam_flag);

		(void) mutex_lock(&vt_mutex);
		if (vt_hotkeys_pending) {
			(void) mutex_unlock(&vt_mutex);
			break;
		}
		(void) mutex_unlock(&vt_mutex);

		if (err == PAM_SUCCESS) {
			err = pam_acct_mgmt(vt_pamh, pam_flag);

			(void) mutex_lock(&vt_mutex);
			if (vt_hotkeys_pending) {
				(void) mutex_unlock(&vt_mutex);
				break;
			}
			(void) mutex_unlock(&vt_mutex);

			if (err == PAM_NEW_AUTHTOK_REQD) {
				chpasswd_tries = 0;

				do {
					err = pam_chauthtok(vt_pamh,
					    PAM_CHANGE_EXPIRED_AUTHTOK);
					chpasswd_tries++;

					(void) mutex_lock(&vt_mutex);
					if (vt_hotkeys_pending) {
						(void) mutex_unlock(&vt_mutex);
						break;
					}
					(void) mutex_unlock(&vt_mutex);

				} while ((err == PAM_AUTHTOK_ERR ||
				    err == PAM_TRY_AGAIN) &&
				    chpasswd_tries < DEF_ATTEMPTS);

				(void) mutex_lock(&vt_mutex);
				if (vt_hotkeys_pending) {
					(void) mutex_unlock(&vt_mutex);
					break;
				}
				(void) mutex_unlock(&vt_mutex);

				vt_audit_event(ah, ADT_passwd, err);
			}
		}

		/*
		 * Only audit failed unlock here, successful unlock
		 * will be audited after switching to target vt.
		 */
		if (err != PAM_SUCCESS) {
			(void) fprintf(stdout, "%s",
			    pam_strerror(vt_pamh, err));

			vt_audit_event(ah, ADT_screenunlock, err);
		}

		(void) mutex_lock(&vt_mutex);
		if (vt_hotkeys_pending) {
			(void) mutex_unlock(&vt_mutex);
			break;
		}
		(void) mutex_unlock(&vt_mutex);

	} while (err != PAM_SUCCESS);

	(void) mutex_lock(&vt_mutex);
	if (!vt_hotkeys_pending) {
		/*
		 * Should be PAM_SUCCESS to reach here.
		 */
		(void) ioctl(daemonfd, VT_ACTIVATE, target_vt);

		vt_audit_event(ah, ADT_screenunlock, err);

		/*
		 * Free audit handle.
		 */
		(void) adt_end_session(ah);
		vt_ah_array[target_vt - 1] = NULL;
	}
	(void) mutex_unlock(&vt_mutex);

	(void) pam_end(vt_pamh, err);

	(void) mutex_lock(&vt_mutex);
	vt_auth_doing = B_FALSE;
	vt_clear_events();
	(void) mutex_unlock(&vt_mutex);
}

/* main thread (lock and auth) */
static void __NORETURN
vt_serve_events(void)
{
	struct pollfd pollfds[1];
	int ret;
	vt_evt_t ve;

	pollfds[0].fd = eventstream[1];
	pollfds[0].events = POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI;

	for (;;) {
		pollfds[0].revents = 0;
		ret = poll(pollfds,
		    sizeof (pollfds) / sizeof (struct pollfd), -1);
		if (ret == -1 && errno == EINTR) {
			continue;
		}

		if (pollfds[0].revents && eventstream_read(1, &ve)) {
			/* new request */
			switch (ve.ve_cmd) {
			case VT_EV_AUTH:
				vt_do_auth(ve.ve_info);
				break;

			case VT_EV_LOCK:
				vt_activate_screenlock(ve.ve_info);
				break;

			case VT_EV_ACTIVATE:
				/* directly activate target vt */
				vt_do_activate(ve.ve_info);
				break;
			}
		}
	}
}

static void
vt_check_target_session(uint32_t target_vt)
{
	pid_t	pid = (pid_t)-1;

	if (!vt_secure) {
		vt_ev_request(VT_EV_ACTIVATE, target_vt);
		return;
	}

	/* check the target session */
	vt_read_utx(target_vt, &pid, NULL);
	if (pid  == (pid_t)-1) {
		vt_ev_request(VT_EV_ACTIVATE, target_vt);
		return;
	}

	vt_ev_request(VT_EV_AUTH, target_vt);
}

static boolean_t
vt_get_active_disp_info(struct vt_dispinfo *vd)
{
	int fd;
	struct vt_stat state;
	char vtname[16];

	if ((fd = open(VT_DAEMON_CONSOLE_FILE, O_RDONLY)) < 0)
		return (B_FALSE);

	if (ioctl(fd, VT_GETSTATE, &state) != 0) {
		(void) close(fd);
		return (B_FALSE);
	}
	(void) close(fd);

	(void) snprintf(vtname, sizeof (vtname), "/dev/vt/%d", state.v_active);
	if ((fd = open(vtname, O_RDONLY)) < 0)
		return (B_FALSE);

	if (ioctl(fd, VT_GETDISPINFO, vd) != 0) {
		(void) close(fd);
		return (B_FALSE);
	}

	(void) close(fd);
	return (B_TRUE);
}

/*
 * Xserver registers its pid into kernel to associate it with
 * its vt upon startup for each graphical display. So here we can
 * check if the pid is of the Xserver for the current active
 * display when we receive a special VT_EV_X_EXIT request from
 * a process. If the request does not come from the current
 * active Xserver, it is discarded.
 */
static boolean_t
vt_check_disp_active(pid_t x_pid)
{
	struct vt_dispinfo vd;

	if (vt_get_active_disp_info(&vd) &&
	    vd.v_pid == x_pid)
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * check if the pid is of the Xserver for the current active display,
 * return true when it is, and then also return other associated
 * information with the Xserver.
 */
static boolean_t
vt_get_disp_info(pid_t x_pid, int *logged_in, int *display_num)
{
	struct vt_dispinfo vd;

	if (!vt_get_active_disp_info(&vd) ||
	    vd.v_pid != x_pid)
		return (B_FALSE);

	*logged_in = vd.v_login;
	*display_num = vd.v_dispnum;
	return (B_TRUE);
}

static void
vt_terminate_auth(void)
{
	struct timespec sleeptime;

	sleeptime.tv_sec = 0;
	sleeptime.tv_nsec = 1000000; /* 1ms */

	(void) mutex_lock(&vt_mutex);
	while (vt_auth_doing) {
		vt_ev_request(VT_EV_TERMINATE_AUTH, 0);

		if (vt_auth_doing) {
			(void) mutex_unlock(&vt_mutex);
			(void) nanosleep(&sleeptime, NULL);
			sleeptime.tv_nsec *= 2;
			(void) mutex_lock(&vt_mutex);
		}
	}
	(void) mutex_unlock(&vt_mutex);
}

static void
vt_do_hotkeys(pid_t pid, uint32_t target_vt)
{
	int		logged_in;
	int		display_num;

	if (validate_target_vt(target_vt) != 0)
		return;

	/*
	 * Maybe last switch action is being taken and the lock is ongoing,
	 * here we must reject the newly request.
	 */
	(void) mutex_lock(&vt_mutex);
	if (vt_hotkeys_pending) {
		(void) mutex_unlock(&vt_mutex);
		return;
	}

	/* cleared in vt_do_active and vt_do_auth */
	vt_hotkeys_pending = B_TRUE;
	(void) mutex_unlock(&vt_mutex);

	vt_terminate_auth();

	/* check source session for this hotkeys request */
	if (pid == 0) {
		/* ok, it comes from kernel. */
		if (vt_secure)
			vt_check_source_audit();

		/* then only need to check target session */
		vt_check_target_session(target_vt);
		return;
	}

	/*
	 * check if it comes from current active X graphical session,
	 * if not, ignore this request.
	 */
	if (!vt_get_disp_info(pid, &logged_in, &display_num)) {
		(void) mutex_lock(&vt_mutex);
		vt_hotkeys_pending = B_FALSE;
		(void) mutex_unlock(&vt_mutex);
		return;
	}

	if (logged_in && vt_secure)
		vt_ev_request(VT_EV_LOCK, display_num);

	vt_check_target_session(target_vt);
}

/*
 * The main routine for the door server that deals with secure hotkeys
 */
/* ARGSUSED */
static void
server_for_door(void *cookie, char *args, size_t alen, door_desc_t *dp,
    uint_t n_desc)
{
	ucred_t *uc = NULL;
	vt_cmd_arg_t *vtargp;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	vtargp = (vt_cmd_arg_t *)args;

	if (vtargp == NULL ||
	    alen != sizeof (vt_cmd_arg_t) ||
	    door_ucred(&uc) != 0) {
		(void) door_return(NULL, 0, NULL, 0);
		return;
	}

	switch (vtargp->vt_ev) {
	case VT_EV_X_EXIT:
		/*
		 * Xserver will issue this event requesting to switch back
		 * to previous active vt when it's exiting and the associated
		 * vt is currently active.
		 */
		if (vt_check_disp_active(ucred_getpid(uc)))
			vt_do_hotkeys(0, vtargp->vt_num);
		break;

	case VT_EV_HOTKEYS:
		if (!vt_hotkeys)	/* hotkeys are disabled? */
			break;

		vt_do_hotkeys(ucred_getpid(uc), vtargp->vt_num);
		break;

	default:
		break;
	}

	ucred_free(uc);
	(void) door_return(NULL, 0, NULL, 0);
}

static boolean_t
setup_door(void)
{
	if ((vt_door = door_create(server_for_door, NULL,
	    DOOR_UNREF | DOOR_REFUSE_DESC | DOOR_NO_CANCEL)) < 0) {
		syslog(LOG_ERR, "door_create failed: %s", strerror(errno));
		return (B_FALSE);
	}

	(void) fdetach(vt_door_path);

	if (fattach(vt_door, vt_door_path) != 0) {
		syslog(LOG_ERR, "fattach to %s failed: %s",
		    vt_door_path, strerror(errno));
		(void) door_revoke(vt_door);
		(void) fdetach(vt_door_path);
		vt_door = -1;
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * check to see if vtdaemon is already running.
 *
 * The idea here is that we want to open the path to which we will
 * attach our door, lock it, and then make sure that no-one has beat us
 * to fattach(3c)ing onto it.
 *
 * fattach(3c) is really a mount, so there are actually two possible
 * vnodes we could be dealing with.  Our strategy is as follows:
 *
 * - If the file we opened is a regular file (common case):
 * 	There is no fattach(3c)ed door, so we have a chance of becoming
 * 	the running vtdaemon. We attempt to lock the file: if it is
 * 	already locked, that means someone else raced us here, so we
 * 	lose and give up.
 *
 * - If the file we opened is a namefs file:
 * 	This means there is already an established door fattach(3c)'ed
 * 	to the rendezvous path.  We've lost the race, so we give up.
 * 	Note that in this case we also try to grab the file lock, and
 * 	will succeed in acquiring it since the vnode locked by the
 * 	"winning" vtdaemon was a regular one, and the one we locked was
 * 	the fattach(3c)'ed door node.  At any rate, no harm is done.
 */
static boolean_t
make_daemon_exclusive(void)
{
	int doorfd = -1;
	boolean_t ret = B_FALSE;
	struct stat st;
	struct flock flock;

top:
	if ((doorfd = open(vt_door_path, O_CREAT|O_RDWR,
	    S_IREAD|S_IWRITE|S_IRGRP|S_IROTH)) < 0) {
		syslog(LOG_ERR, "failed to open %s", vt_door_path);
		goto out;
	}
	if (fstat(doorfd, &st) < 0) {
		syslog(LOG_ERR, "failed to stat %s", vt_door_path);
		goto out;
	}
	/*
	 * Lock the file to synchronize
	 */
	flock.l_type = F_WRLCK;
	flock.l_whence = SEEK_SET;
	flock.l_start = (off_t)0;
	flock.l_len = (off_t)0;
	if (fcntl(doorfd, F_SETLK, &flock) < 0) {
		/*
		 * Someone else raced us here and grabbed the lock file
		 * first.  A warning here and exit.
		 */
		syslog(LOG_ERR, "vtdaemon is already running!");
		goto out;
	}

	if (strcmp(st.st_fstype, "namefs") == 0) {
		struct door_info info;

		/*
		 * There is already something fattach()'ed to this file.
		 * Lets see what the door is up to.
		 */
		if (door_info(doorfd, &info) == 0 && info.di_target != -1) {
			syslog(LOG_ERR, "vtdaemon is already running!");
			goto out;
		}

		(void) fdetach(vt_door_path);
		(void) close(doorfd);
		goto top;
	}

	ret = setup_door();

out:
	(void) close(doorfd);
	return (ret);
}

static boolean_t
mkvtdir(void)
{
	struct stat st;
	/*
	 * We must create and lock everyone but root out of VT_TMPDIR
	 * since anyone can open any UNIX domain socket, regardless of
	 * its file system permissions.
	 */
	if (mkdir(VT_TMPDIR, S_IRWXU|S_IROTH|S_IXOTH|S_IRGRP|S_IXGRP) < 0 &&
	    errno != EEXIST) {
		syslog(LOG_ERR, "could not mkdir '%s'", VT_TMPDIR);
		return (B_FALSE);
	}
	/* paranoia */
	if ((stat(VT_TMPDIR, &st) < 0) || !S_ISDIR(st.st_mode)) {
		syslog(LOG_ERR, "'%s' is not a directory", VT_TMPDIR);
		return (B_FALSE);
	}
	(void) chmod(VT_TMPDIR, S_IRWXU|S_IROTH|S_IXOTH|S_IRGRP|S_IXGRP);
	return (B_TRUE);
}

int
main(int argc, char *argv[])
{
	int i;
	int opt;
	priv_set_t *privset;
	int active;

	openlog("vtdaemon", LOG_PID | LOG_CONS, 0);

	/*
	 * Check that we have all privileges.  It would be nice to pare
	 * this down, but this is at least a first cut.
	 */
	if ((privset = priv_allocset()) == NULL) {
		syslog(LOG_ERR, "priv_allocset failed");
		return (1);
	}

	if (getppriv(PRIV_EFFECTIVE, privset) != 0) {
		syslog(LOG_ERR, "getppriv failed", "getppriv");
		priv_freeset(privset);
		return (1);
	}

	if (priv_isfullset(privset) == B_FALSE) {
		syslog(LOG_ERR, "You lack sufficient privilege "
		    "to run this command (all privs required)");
		priv_freeset(privset);
		return (1);
	}
	priv_freeset(privset);

	while ((opt = getopt(argc, argv, "ksrc:")) != EOF) {
		switch (opt) {
		case 'k':
			vt_hotkeys = B_FALSE;
			break;
		case 's':
			vt_secure = B_FALSE;
			break;
		case 'c':
			vtnodecount = atoi(optarg);
			break;
		default:
			break;
		}
	}

	(void) vt_setup_signal(SIGINT, 1);

	if (!mkvtdir())
		return (1);

	if (!eventstream_init())
		return (1);

	(void) snprintf(vt_door_path, sizeof (vt_door_path),
	    VT_TMPDIR "/vtdaemon_door");

	if (!make_daemon_exclusive())
		return (1);

	/* only the main thread accepts SIGINT */
	(void) vt_setup_signal(SIGINT, 0);
	(void) sigset(SIGPIPE, SIG_IGN);
	(void) signal(SIGQUIT, SIG_IGN);
	(void) signal(SIGINT, catch);

	for (i = 0; i < 3; i++)
		(void) close(i);
	(void) setsid();

	if ((daemonfd = open(VT_DAEMON_CONSOLE_FILE, O_RDWR)) < 0) {
		return (1);
	}

	if (daemonfd != 0)
		(void) dup2(daemonfd, STDIN_FILENO);
	if (daemonfd != 1)
		(void) dup2(daemonfd, STDOUT_FILENO);

	if (vtnodecount >= 2)
		(void) ioctl(daemonfd, VT_CONFIG, vtnodecount);

	if ((vt_ah_array = calloc(vtnodecount - 1,
	    sizeof (adt_session_data_t *))) == NULL)
		return (1);

	(void) ioctl(daemonfd, VT_GETACTIVE, &active);

	if (active == 1) {
		/*
		 * This is for someone who restarts vtdaemon while vtdaemon
		 * is doing authentication on /dev/vt/1.
		 * A better way is to continue the authentication, but there
		 * are chances that the status of the target VT has changed.
		 * So we just clear the screen here.
		 */
		(void) write(daemonfd, VT_CLEAR_SCREEN_STR,
		    strlen(VT_CLEAR_SCREEN_STR));
	}

	vt_serve_events();
	/*NOTREACHED*/
}

static int
vt_audit_start(adt_session_data_t **ah, pid_t pid)
{
	ucred_t *uc;

	if (adt_start_session(ah, NULL, 0))
		return (-1);

	if ((uc = ucred_get(pid)) == NULL) {
		(void) adt_end_session(*ah);
		return (-1);
	}

	if (adt_set_from_ucred(*ah, uc, ADT_NEW)) {
		ucred_free(uc);
		(void) adt_end_session(*ah);
		return (-1);
	}

	ucred_free(uc);
	return (0);
}

/*
 * Write audit event
 */
static void
vt_audit_event(adt_session_data_t *ah, au_event_t event_id, int status)
{
	adt_event_data_t	*event;


	if ((event = adt_alloc_event(ah, event_id)) == NULL) {
		return;
	}

	(void) adt_put_event(event,
	    status == PAM_SUCCESS ? ADT_SUCCESS : ADT_FAILURE,
	    status == PAM_SUCCESS ? ADT_SUCCESS : ADT_FAIL_PAM + status);

	adt_free_event(event);
}

static void
vt_check_source_audit(void)
{
	int	fd;
	int	source_vt;
	int	real_vt;
	struct vt_stat state;
	pid_t	pid;
	adt_session_data_t *ah;

	if ((fd = open(VT_DAEMON_CONSOLE_FILE, O_WRONLY)) < 0)
		return;

	if (ioctl(fd, VT_GETSTATE, &state) != 0 ||
	    ioctl(fd, VT_GETACTIVE, &real_vt) != 0) {
		(void) close(fd);
		return;
	}

	source_vt = state.v_active;	/* 1..n */
	(void) close(fd);

	/* check if it's already locked */
	if (real_vt == 1)	/* vtdaemon is taking over the screen */
		return;

	vt_read_utx(source_vt, &pid, NULL);
	if (pid == (pid_t)-1)
		return;

	if (vt_audit_start(&ah, pid) != 0) {
		syslog(LOG_ERR, "audit start failed ");
		return;
	}

	/*
	 * In case the previous session terminated abnormally.
	 */
	if (vt_ah_array[source_vt - 1] != NULL)
		(void) adt_end_session(vt_ah_array[source_vt - 1]);

	vt_ah_array[source_vt - 1] = ah;

	vt_audit_event(ah, ADT_screenlock, PAM_SUCCESS);
}
