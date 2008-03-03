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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SMB Service State Machine
 *
 *                              _____________
 *               T21           |             |      T1
 *           +---------------->|     INIT    |------------------+
 *           |                 |_____________|                  |
 *     ______|_____                  /|\                  _____\|/_____
 *    |            |               T14|       T22        |             |
 *    |   ERROR    |    +------------ | -----------------|   OPENING   |
 *    |____________|    |             |                  |_____________|
 *          /|\         |       ______|______                   |
 *           |          |      |             |   T23            |
 *           |T20       |  +-->|   CLOSING   |<--------+        | T2
 *           |          |  |   |_____________|<-------+|        |
 *    _______|_______   |  |         /|\              ||  _____\|/_____
 *   |               |<-+  |T19       |               || |             |
 *   | ERROR CLOSING |-----+       T13|               |+-| CONFIG WAIT |
 *   |_______________|                |               |  |_____________|
 *          /|\                       |               |         |
 *           |                 _______|_______        |         |
 *           |                |               |       |         |
 *           |    +---------->| SESSION CLOSE |--+    |         |
 *           |    |           |_______________|  |    |         | T3
 *           |    |                  /|\  /|\    |    |T24      |
 *           |    |                T11|    |T12  |    |         |
 *           |    |                   |    +-----+    |         |
 *           |    |            _______|_______        |    ____\|/_____
 *           |    |           |               |       |   |            |
 *           |    |           | DISCONNECTING |       +---| CONNECTING |
 *           |T18 |T17        |_______________|           |____________|
 *           |    |                  /|\  /|\                   |
 *           |    |                   |    |                    | T4
 *           |    |                   |    |                    |
 *     ______|____|___                |    |      T9        ___\|/___
 *    |               |               |    +---------------|         |
 *    | ERROR SESSION |               |T10                 |  ONLINE |<-+
 * +->|     CLOSE     |               |    +-------------->|_________|  |
 * |  |_______________|               |    |      T8         |  |  |    |
 * |T16  |  /|\ /|\             ______|____|_                |  |  |____| T5
 * +-----+   |   |    T25      |             |               |  |
 *           |   +-------------| RECONFIGURE |<--------------+  |
 *           |            +----|_____________|       T6         |
 *           |            |     /|\                             |
 *           |          T7|      |                              |
 *           |            +------+                              |
 *           |                                        T15       |
 *           +--------------------------------------------------+
 *
 *
 * State Descriptions:
 *
 * Init
 *
 *     Ready for device open.  This is the initial service state and the
 *     service returns to this state when cleanup has completed after a
 *     device close.  The pseudo-driver can only be unloaded or opened in
 *     this state.
 *
 * Opening
 *
 *     The pseudo-driver has been opened and SMB initialization is underway
 *
 * Config Wait
 *
 *     Waiting for smbd to provide configuration information.  XXX Today
 *     the kernel/user sychronization is not completely implemented and
 *     some changes might be appropriate in the future.  The current
 *     code pulls configuration from smbd (see smb_get_kconfig).  For
 *     dynamic configuration updates smbd will need to push config information
 *     to the kernel.  This could be handled with either an ioctl or a door
 *     call.  When this change is made we should change the state machine so
 *     that it also relies on the pull model.  One way to handle this is to
 *     have the state machine end up in "config wait" instead of "online"
 *     when the open of the pseudo-device returns.  Smbd will then know
 *     to push the current config after it has successfully opened the
 *     device.  Such a change would require tweaks to the handling of
 *     svc_sm->ssc_started.
 *
 * Connecting
 *
 *     Connecting to SMB port and starting service listener thread
 *
 * Online
 *
 *     Online and accepting SMB sessions
 *
 * Reconfiguring
 *
 *     Updating configuration after receiving a config update from smbd.  This
 *     state is very similar to "online" state except that new session requests
 *     get place on a queue and initialization for those requests is deferred
 *     until configuration is complete.  XXX Since dymamic configuration
 *     updates have not been implemented this state is never exercised.
 *     It's possible that we could completely eliminate it by simply grabbing
 *     a mutex for the duration of the config update.  If the config update
 *     will take a long time or require sleeping then this state will
 *     be useful.
 *
 * Disconnecting
 *
 *     Disconnecting from the SMB port and stopping the service listener
 *     thread.
 *
 * Session Close
 *
 *     Waiting for any open sessions to close
 *
 * Closing
 *
 *     Quiesce service and release any associated resources.  This is the
 *     inverse of the "opening" state.
 *
 * Error Session Close
 *
 *     The connection was unexpectedly dropped due to an error of some kind.
 *     Waiting for any open session to close (identical to Session Close
 *     except that we enter this state involuntarily)
 *
 * Error Closing
 *
 *     Similar to Closing except that we enter this state as the result of
 *     an error (either during initialization or runtime)
 *
 * Error
 *
 *     An error occurred that caused the service to shutdown but the
 *     pseudo-device is still open.
 *
 *
 * State Transitions:
 *
 *  T1 - The state machine is started by a call to smb_svcstate_sm_start.  This
 *       causes a SMB_SVCEVT_OPEN event which forces a transition to "opening"
 *       state.
 *
 *  T2 - SMB_SVCEVT_OPEN_SUCCESS indicates that the open actions completed
 *       successfully and the state machine transitions to "config wait" state.
 *
 *  T3 - Configuration received from smbd (SMB_SVCEVT_CONFIG_SUCCESS)
 *
 *  T4 - SMB service listener thread started and successfully bound to the
 *       socket (SMB_SVCEVT_CONNECT).
 *
 *  T5 - Any SMB_SVCEVT_SESSION_CREATE/SMB_SVCEVT_SESSION_DELETE events are
 *       tracked on the svc_sm->ssc_active_sessions list and reflected in
 *       the svc_sm->ssc_active_session_count but we stay in "online" state
 *
 *  T6 - Reconfiguration event (SMB_SVCEVT_CONFIG) cause a transition to
 *       "reconfiguring" state.
 *
 *  T7 - SMB_SVCEVT_SESSION_CREATE/SMB_SVCEVT_SESSION_DELETE
 *
 *  T8 - Configuration received from smbd (SMB_SVCEVT_CONFIG_SUCCESS) drives us
 *       back to "online" state.
 *
 *  T9 - SMB_SVCEVT_CLOSE starts the shutdown process, starting with
 *       "disconnecting" state.
 *
 * T10 - SMB_SVCEVT_CLOSE starts the shutdown process, starting with
 *       "disconnecting" state.
 *
 * T11 - After socket disconnect SMB_SVCEVT_DISCONNECT drives the state machine
 *       to "session close" state.
 *
 * T12 - SMB_SVCEVT_SESSION_CLOSE does not cause a state transition if more
 *       sessions remain.
 *
 * T13 - When no more session remain SMB_SVCEVT_SESSION_CLOSE causes a
 *       transition to "closing" state.
 *
 * T14 - All close actions completed successfully (SMB_SVCEVT_CLOSE_SUCCESS).
 *       Close operations are not allowed to fail so the transition from
 *       "closing" to "init" is guaranteed.
 *
 * T15 - If the SMB service connection is unexpectedly dropped,
 *       SMB_SVCEVT_DISCONNECT drives the state machine to
 *       "error session close" state.
 *
 * T16 - SMB_SVCEVT_SESSION_CLOSE does not cause a state transition if more
 *       sessions remain.
 *
 * T17 - SMB_SVCEVT_CLOSE causes a state change to "session close" state.  The
 *       difference between "error session close" and "session close" state is
 *       whether the pseudo device is open.
 *
 * T18 - When no more session remain SMB_SVCEVT_SESSION_CLOSE causes a
 *       transition to "error closing" state.
 *
 * T19 - SMB_SVCEVT_CLOSE causes a state change to "closing" state.  The
 *       difference between "error closing" and "closing" state is
 *       whether the pseudo device is open.
 *
 * T20 - All close actions completed successfully (SMB_SVCEVT_CLOSE_SUCCESS).
 *       Close operations are not allowed to fail so the transition from
 *       "error closing" to "error" is guaranteed.
 *
 * T21 - SMB_SVCEVT_CLOSE moves everything back to "init" state
 *
 * T22 - SMB_SVCEVT_OPEN_FAILED causes a state change to "error closing".
 *       Moving to "error closing" state instead of "closing" causes the
 *       state machine to ultimately stop in "error" state (instead of
 *       "init").
 *
 * T23 - SMB_SVCEVT_CLOSE
 *
 * T24 - SMB_SVCEVT_CLOSE in "connecting" state causes a transition
 *       to "closing" state since the connection has not yet been established.
 *
 * T25 - If the SMB service connection is unexpectedly dropped,
 *       SMB_SVCEVT_DISCONNECT drives the state machine to
 *       "error session close" state.
 *
 * Overview:
 *
 * When the SMB pseudo-device gets open the state machine gets started with a
 * call to smb_svcstate_sm_start which will block until initialization either
 * succeeds or fails.
 *
 * SMB code external to the state machine generates events (defined above) by
 * calling smb_svcstate_event and the state machine determines the new state
 * based on the events and the current state.
 *
 * When the pseudo-device is closed, the state machine gets stopped with
 * a call to smb_svcstate_sm_stop.
 *
 * This state machine also keeps track of the active session list.  The
 * list of sessions can be queried using the following services:
 *
 *     smb_svcstate_lock_read(svc_sm);
 *     smb_svcstate_session_getnext(svc_sm, prev_session);
 *         (repeat until NULL is returned)
 *     smb_svcstate_unlock(svc_sm);
 *
 *
 * Implemention Details:
 *
 * States are named SMB_SVCSTATE_<state name>
 *
 * Events are named SMB_SVCEVT_<event name>
 *
 * Each state has an associated function: smb_svcstate_<state name>
 *
 * This state machine implements four types of actions:
 *
 *     State entry actions - State-specific actions that are taken when a
 *     state is entered (transitions like T5 that do not result in a real
 *     state change are not actually coded as state transitions (no call to
 *     smb_svcstate_update) and therefore will not cause state entry actions.
 *     These actions are implemented in smb_svcstate_update.
 *
 *     Immediate event actions - An action specific to a particular event
 *     that is taken immediately, before the event is placed on the task
 *     queue.  The action does not depend on the current state.  These should
 *     only be implemented when absolutely necessary since the code path for
 *     immediate actions is multithreaded (smb_svcstate_event_locked).
 *
 *     Deferred event actions - An action specific to a particular event
 *     that is handled by the taskq thread.  The action does not depend on
 *     the current state and the code implementing the actions is single
 *     threaded since the taskq only has one thread.  Implemented in
 *     smb_svcstate_event_handler.
 *
 *     State specific event actions - Actions specific to events that
 *     depend on the current state.  These actions are implemented
 *     in the state-specific event handler functions
 *     (smb_svcstate_<event name>)
 *
 * The description above makes things sound more complicated than they really
 * are.  Deferred event actions are really just a special case of state
 * specific event actions.  To find out what happens when a specific event
 * occurs in a specific state:
 *
 * 1. Look at smb_svcstate_event_locked and find matching event actions (rare)
 * 2. Look at smb_svcstate_event_handler and find matching event actions
 * 3. Look at smb_svcstate_<current state> and find matching event actions
 *
 * If the event causes a state transition (this will always be found in
 * smb_svcstate_<current_state>) then look up the new state in
 * smb_svcstate_update which will show the state entry actions for the new
 * state.
 */

#include <smbsrv/smb_incl.h>
#include <sys/note.h>
#include <sys/sdt.h>

static void smb_svcstate_event_locked(smb_svc_sm_ctx_t *svc_sm,
    smb_svcevt_t event, uintptr_t event_info);

static void smb_svcstate_event_handler(void *event_ctx);

static void smb_svcstate_init(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx);

static void smb_svcstate_opening(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx);

static void smb_svcstate_config_wait(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx);

static void smb_svcstate_connecting(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx);

static void smb_svcstate_online(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx);

static void smb_svcstate_reconfiguring(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx);

static void smb_svcstate_disconnecting(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx);

static void smb_svcstate_session_close(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx);

static void smb_svcstate_error_session_close(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx);

static void smb_svcstate_closing(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx);

static void smb_svcstate_error_closing(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx);

static void smb_svcstate_error(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx);

static void smb_svcstate_update(smb_svc_sm_ctx_t *svc_sm,
    smb_svcstate_t newstate);

static void smb_svcstate_set_started(smb_svc_sm_ctx_t *svc_sm,
    int started);

static void smb_svcstate_session_start(smb_svc_sm_ctx_t *svc_sm,
    smb_session_t *new_session);

static void smb_svcstate_session_defer(smb_svc_sm_ctx_t *svc_sm,
    smb_session_t *new_session);

static void smb_svcstate_session_reject_active(smb_svc_sm_ctx_t *svc_sm,
    smb_session_t *session, char *reason);

static void
smb_svcstate_start_deferred_sessions(smb_svc_sm_ctx_t *svc_sm);

static void
smb_svcstate_reject_deferred_sessions(smb_svc_sm_ctx_t *svc_sm);

static void
smb_svcstate_close_active_sessions(smb_svc_sm_ctx_t *svc_sm);

extern void smb_wakeup_session_daemon(smb_thread_t *thread, void *arg);
extern void smb_session_daemon(smb_thread_t *thread, void *arg);
extern int smb_get_kconfig(smb_kmod_cfg_t *cfg);

char *smb_svcstate_event_name[SMB_SVCEVT_MAX_EVENT];
char *smb_svcstate_state_name[SMB_SVCSTATE_MAX_STATE];

/*
 * SMB Service State Machine
 */

#define	SMB_STOPPED		0
#define	SMB_START_SUCCESS	1
#define	SMB_START_FAILED	2

int
smb_svcstate_sm_init(smb_svc_sm_ctx_t *svc_sm)
{
	bzero(svc_sm, sizeof (*svc_sm));

	/* Protects state context except for ssc_state and ssc_last_state */
	rw_init(&svc_sm->ssc_state_rwlock, NULL, RW_DEFAULT, NULL);

	/* Protects ssc_state and ssc_last_state */
	mutex_init(&svc_sm->ssc_state_cv_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&svc_sm->ssc_state_cv, NULL, CV_DEFAULT, NULL);

	svc_sm->ssc_state = SMB_SVCSTATE_INIT;
	svc_sm->ssc_last_state = SMB_SVCSTATE_INIT;

	list_create(&svc_sm->ssc_active_sessions, sizeof (smb_session_t),
	    offsetof(smb_session_t, s_lnd));
	list_create(&svc_sm->ssc_deferred_sessions, sizeof (smb_session_t),
	    offsetof(smb_session_t, s_lnd));

	/* Service state machine is single threaded by design */
	svc_sm->ssc_taskq = taskq_create("smb_svc_sm", 1, minclsyspri,
	    1, 1, 0);
	if (svc_sm->ssc_taskq == NULL) {
		return (ENOMEM);
	}

	/*
	 * Setup event and state name tables.  Use for debug logging
	 * and/or dtrace scripts
	 */
	smb_svcstate_event_name[SMB_SVCEVT_UNDEFINED] = "UNDEFINED";
	smb_svcstate_event_name[SMB_SVCEVT_OPEN] = "OPEN";
	smb_svcstate_event_name[SMB_SVCEVT_CLOSE] = "CLOSE";
	smb_svcstate_event_name[SMB_SVCEVT_OPEN_SUCCESS] = "OPEN_SUCCESS";
	smb_svcstate_event_name[SMB_SVCEVT_OPEN_FAILED] = "OPEN_FAILED";
	smb_svcstate_event_name[SMB_SVCEVT_CLOSE_SUCCESS] = "CLOSE_SUCCESS";
	smb_svcstate_event_name[SMB_SVCEVT_CONNECT] = "CONNECT";
	smb_svcstate_event_name[SMB_SVCEVT_DISCONNECT] = "DISCONNECT";
	smb_svcstate_event_name[SMB_SVCEVT_CONFIG] = "CONFIG";
	smb_svcstate_event_name[SMB_SVCEVT_CONFIG_SUCCESS] = "CONFIG_SUCCESS";
	smb_svcstate_event_name[SMB_SVCEVT_CONFIG_FAILED] = "CONFIG_FAILED";
	smb_svcstate_event_name[SMB_SVCEVT_SESSION_CREATE] = "SESSION_CREATE";
	smb_svcstate_event_name[SMB_SVCEVT_SESSION_DELETE] = "SESSION_DELETE";

	smb_svcstate_state_name[SMB_SVCSTATE_UNDEFINED] = "UNDEFINED";
	smb_svcstate_state_name[SMB_SVCSTATE_INIT] = "INIT";
	smb_svcstate_state_name[SMB_SVCSTATE_OPENING] = "OPENING";
	smb_svcstate_state_name[SMB_SVCSTATE_CONFIG_WAIT] = "CONFIG_WAIT";
	smb_svcstate_state_name[SMB_SVCSTATE_CONNECTING] = "CONNECTING";
	smb_svcstate_state_name[SMB_SVCSTATE_ONLINE] = "ONLINE";
	smb_svcstate_state_name[SMB_SVCSTATE_RECONFIGURING] = "RECONFIGURING";
	smb_svcstate_state_name[SMB_SVCSTATE_DISCONNECTING] = "DISCONNECTING";
	smb_svcstate_state_name[SMB_SVCSTATE_SESSION_CLOSE] = "SESSION_CLOSE";
	smb_svcstate_state_name[SMB_SVCSTATE_ERROR_SESSION_CLOSE] =
	    "ERROR_SESSION_CLOSE";
	smb_svcstate_state_name[SMB_SVCSTATE_CLOSING] = "CLOSING";
	smb_svcstate_state_name[SMB_SVCSTATE_ERROR_CLOSING] = "ERROR_CLOSING";
	smb_svcstate_state_name[SMB_SVCSTATE_ERROR] = "ERROR";

	return (0);
}

void
smb_svcstate_sm_fini(smb_svc_sm_ctx_t *svc_sm)
{
	taskq_destroy(svc_sm->ssc_taskq);

	list_destroy(&svc_sm->ssc_deferred_sessions);
	list_destroy(&svc_sm->ssc_active_sessions);

	cv_destroy(&svc_sm->ssc_state_cv);
	mutex_destroy(&svc_sm->ssc_state_cv_mutex);
	rw_destroy(&svc_sm->ssc_state_rwlock);
}

int
smb_svcstate_sm_start(smb_svc_sm_ctx_t *svc_sm)
{
	clock_t wait_result;
	int result;

	/*
	 * Make sure state machine is idle and ready to be started.
	 */
	mutex_enter(&svc_sm->ssc_state_cv_mutex);
	while (svc_sm->ssc_started) {
		/*
		 * Already started, possibly because we're still trying to
		 * shutdown.  Wait for up to 30 seconds then return EBUSY.
		 */
		wait_result = cv_timedwait(&svc_sm->ssc_state_cv,
		    &svc_sm->ssc_state_cv_mutex,
		    lbolt + SEC_TO_TICK(30));
		if (wait_result == -1) {
			/* Timeout */
			mutex_exit(&svc_sm->ssc_state_cv_mutex);
			return (EBUSY);
		}
	}

	/*
	 * SMB_SVCEVT_OPEN will get the state machine moving
	 */
	smb_svcstate_event_locked(svc_sm, SMB_SVCEVT_OPEN, NULL);

	/*
	 * Wait for the state machine to signal either a successful
	 * start or a start failure.
	 */
	while (!svc_sm->ssc_started) {
		cv_wait(&svc_sm->ssc_state_cv, &svc_sm->ssc_state_cv_mutex);
	}

	result = (svc_sm->ssc_started == SMB_START_FAILED) ?
	    svc_sm->ssc_start_error : 0;

	/*
	 * If the open failed we will end up in "Error" state.  Since we
	 * are returning failure to the open request on the pseudo-device
	 * we will never see a close so we need to force the device closed.
	 *
	 * A careful look at the state machine will should that we could
	 * avoid this step by transitioning from opening --> closing
	 * instead of opening --> error_closing when there is an initialization
	 * problem.  The reason we shouldn't do this is because
	 * smb_svcstate_sm_busy returns "false" (not busy) when the state
	 * machine is in init state and we don't want to mistakenly indicate
	 * that we are not busy.
	 */
	if (result != 0) {
		smb_svcstate_event_locked(svc_sm, SMB_SVCEVT_CLOSE, NULL);
	}

	mutex_exit(&svc_sm->ssc_state_cv_mutex);

	return (result);
}

/*ARGSUSED*/
void
smb_svcstate_sm_stop(smb_svc_sm_ctx_t *svc_sm)
{
	smb_svcstate_event(SMB_SVCEVT_CLOSE, NULL);
}

boolean_t
smb_svcstate_sm_busy(void)
{
	return (smb_info.si_svc_sm_ctx.ssc_state != SMB_SVCSTATE_INIT);
}

void
smb_svcstate_event(smb_svcevt_t event, uintptr_t event_info)
{
	smb_svc_sm_ctx_t	*svc_sm = &smb_info.si_svc_sm_ctx;

	mutex_enter(&svc_sm->ssc_state_cv_mutex);
	smb_svcstate_event_locked(svc_sm, event, event_info);
	mutex_exit(&svc_sm->ssc_state_cv_mutex);
}

void
smb_svcstate_lock_read(smb_svc_sm_ctx_t *svc_sm)
{
	rw_enter(&svc_sm->ssc_state_rwlock, RW_READER);

}

void
smb_svcstate_unlock(smb_svc_sm_ctx_t *svc_sm)
{
	rw_exit(&svc_sm->ssc_state_rwlock);
}

smb_session_t *
smb_svcstate_session_getnext(smb_svc_sm_ctx_t *svc_sm, smb_session_t *prev)
{
	smb_session_t *result;

	/* Skip sessions in "terminated" state */
	do {
		if (prev == NULL) {
			result = list_head(&svc_sm->ssc_active_sessions);
		} else {
			result = list_next(&svc_sm->ssc_active_sessions, prev);
		}
		prev = result;
	} while ((result != NULL) &&
	    (result->s_state == SMB_SESSION_STATE_TERMINATED));

	return (result);
}

int
smb_svcstate_session_count(smb_svc_sm_ctx_t *svc_sm)
{
	return (svc_sm->ssc_active_session_count);
}

/*
 * Internal use only by state machine code
 */

static void
smb_svcstate_event_locked(smb_svc_sm_ctx_t *svc_sm,
    smb_svcevt_t event, uintptr_t event_info)
{
	smb_event_ctx_t		*event_ctx;

	event_ctx = kmem_zalloc(sizeof (*event_ctx), KM_SLEEP);
	event_ctx->sec_event = event;
	event_ctx->sec_info = event_info;

	/*
	 * Immediate event actions that are independent of state.
	 * This code is multi-threaded and is in the context of
	 * the thread that generated the event.
	 *
	 * Don't generate events from this function (recursive mutex
	 * enter).
	 */
	switch (event_ctx->sec_event) {
	case SMB_SVCEVT_SESSION_CREATE:
		/*
		 * We don't necessarily want to reflect this session in the
		 * session count just yet.  We do, however, want to know
		 * that its waiting so that we can properly close down
		 * all the outstanding session as we are closing the service.
		 * The ssc_session_creates_waiting counter represents
		 * the sessions that have been dispatched to the taskq
		 * but not yet processed.
		 *
		 * Session delete events don't have the same issue because
		 * the session count won't go to zero until they are all
		 * processed.
		 */
		svc_sm->ssc_session_creates_waiting++;
		break;
	default:
		break;
	}

	(void) taskq_dispatch(svc_sm->ssc_taskq, &smb_svcstate_event_handler,
	    event_ctx, TQ_SLEEP);
}

/*
 * Task queue gets created with only one thread so this code is inherently
 * single threaded.  State changes should still be protected with a mutex
 * since other threads might read the state value.
 */
static void
smb_svcstate_event_handler(void *event_ctx_opaque)
{
	smb_svc_sm_ctx_t	*svc_sm = &smb_info.si_svc_sm_ctx;
	smb_event_ctx_t		*event_ctx = event_ctx_opaque;
	smb_session_t		*session;

	DTRACE_PROBE2(service__event,
	    smb_svc_sm_ctx_t *, svc_sm, smb_event_ctx_t *, event_ctx);

	/*
	 * Validate event
	 */
	ASSERT(event_ctx->sec_event != SMB_SVCEVT_UNDEFINED);
	ASSERT3U(event_ctx->sec_event, <, SMB_SVCEVT_MAX_EVENT);

	/*
	 * Validate current state
	 */
	ASSERT(svc_sm->ssc_state != SMB_SVCSTATE_UNDEFINED);
	ASSERT3U(svc_sm->ssc_state, <, SMB_SVCSTATE_MAX_STATE);

	/*
	 * Deferred event actions that are independent of state.
	 * This code is single-threaded and is in the context of
	 * the task-queue thread.
	 */
	switch (event_ctx->sec_event) {
	case SMB_SVCEVT_DISCONNECT:
		svc_sm->ssc_disconnect_error = (int)event_ctx->sec_info;
		break;
	case SMB_SVCEVT_SESSION_CREATE:
		mutex_enter(&svc_sm->ssc_state_cv_mutex);
		svc_sm->ssc_session_creates_waiting--;
		mutex_exit(&svc_sm->ssc_state_cv_mutex);
		break;
	case SMB_SVCEVT_SESSION_DELETE:
		session = (smb_session_t *)event_ctx->sec_info;
		ASSERT(session->s_state == SMB_SESSION_STATE_TERMINATED);
		rw_enter(&svc_sm->ssc_state_rwlock, RW_WRITER);
		list_remove(&svc_sm->ssc_active_sessions, session);
		svc_sm->ssc_active_session_count--;
		rw_exit(&svc_sm->ssc_state_rwlock);

		/*
		 * Make sure thread has exited
		 */
		smb_thread_stop(&session->s_thread);

		smb_session_delete(session);

		/*
		 * State specific handlers will also process the event
		 * but the event info (session) is no longer valid.
		 */
		event_ctx->sec_info = NULL;
		break;
	default:
		break;
	}

	/*
	 * Call state-specific event handler.
	 */
	switch (svc_sm->ssc_state) {
	case SMB_SVCSTATE_INIT:
		smb_svcstate_init(svc_sm, event_ctx);
		break;
	case SMB_SVCSTATE_OPENING:
		smb_svcstate_opening(svc_sm, event_ctx);
		break;
	case SMB_SVCSTATE_CONFIG_WAIT:
		smb_svcstate_config_wait(svc_sm, event_ctx);
		break;
	case SMB_SVCSTATE_CONNECTING:
		smb_svcstate_connecting(svc_sm, event_ctx);
		break;
	case SMB_SVCSTATE_ONLINE:
		smb_svcstate_online(svc_sm, event_ctx);
		break;
	case SMB_SVCSTATE_RECONFIGURING:
		smb_svcstate_reconfiguring(svc_sm, event_ctx);
		break;
	case SMB_SVCSTATE_DISCONNECTING:
		smb_svcstate_disconnecting(svc_sm, event_ctx);
		break;
	case SMB_SVCSTATE_SESSION_CLOSE:
		smb_svcstate_session_close(svc_sm, event_ctx);
		break;
	case SMB_SVCSTATE_ERROR_SESSION_CLOSE:
		smb_svcstate_error_session_close(svc_sm, event_ctx);
		break;
	case SMB_SVCSTATE_CLOSING:
		smb_svcstate_closing(svc_sm, event_ctx);
		break;
	case SMB_SVCSTATE_ERROR_CLOSING:
		smb_svcstate_error_closing(svc_sm, event_ctx);
		break;
	case SMB_SVCSTATE_ERROR:
		smb_svcstate_error(svc_sm, event_ctx);
		break;
	default:
		ASSERT(0);
		break;
	}

	kmem_free(event_ctx, sizeof (*event_ctx));
}

static void
smb_svcstate_init(smb_svc_sm_ctx_t *svc_sm, smb_event_ctx_t *event_ctx)
{
	switch (event_ctx->sec_event) {
	case SMB_SVCEVT_OPEN:
		smb_svcstate_update(svc_sm, SMB_SVCSTATE_OPENING);
		break;
	default:
		break;
	}
}

static void
smb_svcstate_opening(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx)
{
	switch (event_ctx->sec_event) {
	case SMB_SVCEVT_OPEN_SUCCESS:
		smb_svcstate_update(svc_sm, SMB_SVCSTATE_CONFIG_WAIT);
		break;
	case SMB_SVCEVT_OPEN_FAILED:
		/*
		 * Go to error_closed state, cleanup anything we did in open
		 * and then back to init state.  We want to end up in "error"
		 * state instead of "init" state.
		 */
		smb_svcstate_update(svc_sm, SMB_SVCSTATE_ERROR_CLOSING);
		smb_svcstate_set_started(svc_sm, SMB_START_FAILED);
		break;

	default:
		ASSERT(0);
		break;
	}
}

static void
smb_svcstate_config_wait(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx)
{
	switch (event_ctx->sec_event) {
	case SMB_SVCEVT_CONFIG:
		/*
		 * Update our configuration.  A successful config update
		 * will trigger SMB_SVCEVT_CONFIG_SUCCESS and drive us
		 * into online state.
		 */
		(void) smb_get_kconfig(&smb_info.si); /* XXX */
		break;
	case SMB_SVCEVT_CONFIG_SUCCESS:
		smb_svcstate_update(svc_sm, SMB_SVCSTATE_CONNECTING);
		break;
	case SMB_SVCEVT_CONFIG_FAILED:
		/* Don't care, wait for another config attempt */
		break;
	case SMB_SVCEVT_CLOSE:
		smb_svcstate_update(svc_sm,
		    SMB_SVCSTATE_CLOSING);
		break;
	default:
		ASSERT(0);
		break;
	}
}

static void
smb_svcstate_connecting(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx)
{
	switch (event_ctx->sec_event) {
	case SMB_SVCEVT_CONNECT:
		/*
		 * Wait until both NBT and TCP transport services
		 * are connected before going online.
		 */
		if ((smb_info.si_connect_progress & SMB_SI_NBT_CONNECTED) &&
		    (smb_info.si_connect_progress & SMB_SI_TCP_CONNECTED)) {
			smb_svcstate_update(svc_sm, SMB_SVCSTATE_ONLINE);
			smb_svcstate_set_started(svc_sm, SMB_START_SUCCESS);
		}
		break;
	case SMB_SVCEVT_DISCONNECT:
		svc_sm->ssc_start_error = svc_sm->ssc_disconnect_error;
		smb_svcstate_update(svc_sm, SMB_SVCSTATE_ERROR_CLOSING);
		smb_svcstate_set_started(svc_sm, SMB_START_FAILED);
		break;
	case SMB_SVCEVT_CLOSE:
		smb_svcstate_update(svc_sm, SMB_SVCSTATE_CLOSING);
		break;
	case SMB_SVCEVT_SESSION_CREATE:
		smb_svcstate_session_defer(svc_sm,
		    (smb_session_t *)event_ctx->sec_info);
		break;
	default:
		ASSERT(0);
		break;
	}
}

static void
smb_svcstate_online(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx)
{
	smb_session_t		*new_session;

	switch (event_ctx->sec_event) {
	case SMB_SVCEVT_SESSION_CREATE:
		/* Event context is the new socket */
		new_session = (smb_session_t *)event_ctx->sec_info;
#if 0 /* XXX PGD */
		smb_session_config(new_session);
#endif
		smb_svcstate_session_start(svc_sm, new_session);
		break;
	case SMB_SVCEVT_CONNECT:
	case SMB_SVCEVT_SESSION_DELETE:
		/* No state-specific action required */
		break;
	case SMB_SVCEVT_CONFIG:
		smb_svcstate_update(svc_sm, SMB_SVCSTATE_RECONFIGURING);
		break;
	case SMB_SVCEVT_CLOSE:
		smb_svcstate_update(svc_sm,
		    SMB_SVCSTATE_DISCONNECTING);
		break;
	case SMB_SVCEVT_DISCONNECT:
		/*
		 * The session service daemon unexpectedly stopped.  Looks
		 * like we're done talking SMB for the day.
		 */
		smb_svcstate_update(svc_sm, SMB_SVCSTATE_ERROR_SESSION_CLOSE);
		break;
	default:
		ASSERT(0);
		break;
	}
}

static void
smb_svcstate_reconfiguring(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx)
{
	smb_session_t		*new_session;

	switch (event_ctx->sec_event) {
	case SMB_SVCEVT_SESSION_CREATE:
		/* Event context is the new socket */
		new_session = (smb_session_t *)event_ctx->sec_info;
		smb_svcstate_session_defer(svc_sm, new_session);
		break;
	case SMB_SVCEVT_SESSION_DELETE:
		/* No state-specific action required */
		break;
	case SMB_SVCEVT_CONFIG:
		/* Hopefully this won't happen but if it does we ignore it */
		break;
	case SMB_SVCEVT_CONFIG_SUCCESS:
	case SMB_SVCEVT_CONFIG_FAILED:
		smb_svcstate_update(svc_sm, SMB_SVCSTATE_ONLINE);
		break;
	case SMB_SVCEVT_CLOSE:
		smb_svcstate_update(svc_sm,
		    SMB_SVCSTATE_DISCONNECTING);
		break;
	case SMB_SVCEVT_DISCONNECT:
		/*
		 * The session service daemon unexpectedly stopped.  Looks
		 * like we're done talking SMB for the day.
		 */
		smb_svcstate_update(svc_sm, SMB_SVCSTATE_ERROR_SESSION_CLOSE);
		break;
	default:
		ASSERT(0);
		break;
	}
}

static void
smb_svcstate_disconnecting(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx)
{
	smb_session_t		*session;

	switch (event_ctx->sec_event) {
	case SMB_SVCEVT_SESSION_CREATE:
		/* Event context is the new socket */
		session = (smb_session_t *)event_ctx->sec_info;

		/* We're not online so reject the connection */
		smb_session_reject(session, "SMB service is shutting down.");
		smb_session_delete(session);
		break;
	case SMB_SVCEVT_CONNECT:
	case SMB_SVCEVT_SESSION_DELETE:
		/* No state-specific action required */
		break;
	case SMB_SVCEVT_DISCONNECT:
		smb_svcstate_update(svc_sm, SMB_SVCSTATE_SESSION_CLOSE);
		break;
	default:
		ASSERT(0);
		break;
	}
}

static void
smb_svcstate_session_close(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx)
{
	smb_session_t *session;

	/*
	 * We continue to accept "session creates" because we might
	 * accept a connection while the SMB_SVCEVT_CLOSE is
	 * queued but not yet handled.
	 */
	switch (event_ctx->sec_event) {
	case SMB_SVCEVT_SESSION_CREATE:
		/* Event context is the new socket */
		session = (smb_session_t *)event_ctx->sec_info;

		/* We're not online so reject the connection */
		smb_session_reject(session, "Not configured");
		smb_session_delete(session);
		/*FALLTHROUGH*/
	case SMB_SVCEVT_SESSION_DELETE:
		if ((svc_sm->ssc_active_session_count == 0) &&
		    (svc_sm->ssc_session_creates_waiting == 0)) {
			smb_svcstate_update(svc_sm,
			    SMB_SVCSTATE_CLOSING);
		}
		break;
	case SMB_SVCEVT_DISCONNECT:
		/* No state-specific action required */
		break;
	default:
		ASSERT(0);
		break;
	}
}

static void
smb_svcstate_error_session_close(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx)
{
	/*
	 * Since our connection dropped we shouldn't see any more
	 * "creates" in this state
	 */
	switch (event_ctx->sec_event) {
	case SMB_SVCEVT_CLOSE:
		smb_svcstate_update(svc_sm, SMB_SVCSTATE_SESSION_CLOSE);
		break;
	case SMB_SVCEVT_SESSION_DELETE:
		if ((svc_sm->ssc_active_session_count == 0) &&
		    (svc_sm->ssc_session_creates_waiting == 0)) {
			smb_svcstate_update(svc_sm,
			    SMB_SVCSTATE_ERROR_CLOSING);
		}
		break;
	default:
		ASSERT(0);
		break;
	}
}

static void
smb_svcstate_closing(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx)
{
	switch (event_ctx->sec_event) {
	case SMB_SVCEVT_CLOSE_SUCCESS:
		smb_svcstate_update(svc_sm, SMB_SVCSTATE_INIT);
		break;
	default:
		break;
	}
}

static void
smb_svcstate_error_closing(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx)
{
	switch (event_ctx->sec_event) {
	case SMB_SVCEVT_CLOSE:
		smb_svcstate_update(svc_sm, SMB_SVCSTATE_CLOSING);
		break;
	case SMB_SVCEVT_CLOSE_SUCCESS:
		smb_svcstate_update(svc_sm, SMB_SVCSTATE_ERROR);
		break;
	default:
		break;
	}
}

static void
smb_svcstate_error(smb_svc_sm_ctx_t *svc_sm,
    smb_event_ctx_t *event_ctx)
{
	ASSERT(event_ctx->sec_event == SMB_SVCEVT_CLOSE);

	switch (event_ctx->sec_event) {
	case SMB_SVCEVT_CLOSE:
		smb_svcstate_update(svc_sm, SMB_SVCSTATE_INIT);
		break;
	default:
		break;
	}
}

static void
smb_svcstate_update(smb_svc_sm_ctx_t *svc_sm, smb_svcstate_t new_state_arg)
{
	smb_svcstate_t new_state;
	int error;

	/*
	 * Validate new state
	 */
	ASSERT(new_state_arg != SMB_SVCSTATE_UNDEFINED);
	ASSERT3U(new_state_arg, <, SMB_SVCSTATE_MAX_STATE);

	/*
	 * Update state in context.  We protect this with a mutex
	 * even though the state machine code is single threaded so that
	 * other threads can check the state value atomically.
	 */
	new_state = (new_state_arg < SMB_SVCSTATE_MAX_STATE) ?
	    new_state_arg: SMB_SVCSTATE_UNDEFINED;

	DTRACE_PROBE2(service__state__change,
	    smb_svc_sm_ctx_t *, svc_sm, smb_svcstate_t, new_state);
	mutex_enter(&svc_sm->ssc_state_cv_mutex);
	svc_sm->ssc_last_state = svc_sm->ssc_state;
	svc_sm->ssc_state = new_state;
	cv_signal(&svc_sm->ssc_state_cv);
	mutex_exit(&svc_sm->ssc_state_cv_mutex);

	/*
	 * Now perform the appropiate actions for the new state
	 */
	switch (new_state) {
	case SMB_SVCSTATE_INIT:
		smb_svcstate_set_started(svc_sm, SMB_STOPPED);
		break;
	case SMB_SVCSTATE_OPENING:
		/*
		 * Start all SMB subsystems and connect to socket
		 */
		svc_sm->ssc_start_error = smb_service_open(&smb_info);
		if (svc_sm->ssc_start_error != 0) {
			smb_svcstate_event(SMB_SVCEVT_OPEN_FAILED, NULL);
		} else {
			/* Open actions successful */
			smb_svcstate_event(SMB_SVCEVT_OPEN_SUCCESS, NULL);
		}
		break;
	case SMB_SVCSTATE_CONFIG_WAIT:
		/*
		 * Nothing in particular to do here except to note the
		 * state change.  Now we wait for smbd to provide
		 * our configuration.
		 */
		/*
		 * XXX For now this is done as part of smb_service_open()
		 * so just send the "success" event.
		 */
		smb_svcstate_event(SMB_SVCEVT_CONFIG_SUCCESS, NULL);
		break;
	case SMB_SVCSTATE_CONNECTING:
		/*
		 * When we move to a userland thread model we will rely
		 * on smbd to start the SMB socket service thread.
		 */
		error = smb_service_connect(&smb_info);
		if (error != 0)
			smb_svcstate_event(SMB_SVCEVT_DISCONNECT,
			    (uintptr_t)error);
		break;
	case SMB_SVCSTATE_ONLINE:
		smb_svcstate_start_deferred_sessions(svc_sm);
		/* No actions */
		break;
	case SMB_SVCSTATE_RECONFIGURING:
		(void) smb_get_kconfig(&smb_info.si); /* XXX */
		break;
	case SMB_SVCSTATE_DISCONNECTING:
		smb_svcstate_reject_deferred_sessions(svc_sm);
		smb_service_disconnect(&smb_info);
		break;
	case SMB_SVCSTATE_ERROR_SESSION_CLOSE:
		smb_svcstate_reject_deferred_sessions(svc_sm);
		if ((svc_sm->ssc_active_session_count == 0) &&
		    (svc_sm->ssc_session_creates_waiting == 0)) {
			smb_svcstate_update(svc_sm,
			    SMB_SVCSTATE_ERROR_CLOSING);
		} else {
			smb_svcstate_close_active_sessions(svc_sm);
		}
		break;
	case SMB_SVCSTATE_SESSION_CLOSE:
		if ((svc_sm->ssc_active_session_count == 0) &&
		    (svc_sm->ssc_session_creates_waiting == 0)) {
			smb_svcstate_update(svc_sm, SMB_SVCSTATE_CLOSING);
		} else {
			smb_svcstate_close_active_sessions(svc_sm);
		}
		break;
	case SMB_SVCSTATE_ERROR_CLOSING:
	case SMB_SVCSTATE_CLOSING:
		smb_service_close(&smb_info);
		smb_svcstate_event(SMB_SVCEVT_CLOSE_SUCCESS, NULL);
		break;
	case SMB_SVCSTATE_ERROR:
		/* No actions */
		break;
	default:
		ASSERT(0);
		break;
	}
}

static void
smb_svcstate_set_started(smb_svc_sm_ctx_t *svc_sm, int started)
{
	mutex_enter(&svc_sm->ssc_state_cv_mutex);
	/* Make sure we have an error code if we failed to start */
	ASSERT(started != SMB_START_FAILED || svc_sm->ssc_start_error != 0);
	svc_sm->ssc_started = started;
	cv_signal(&svc_sm->ssc_state_cv);
	mutex_exit(&svc_sm->ssc_state_cv_mutex);
}

static void
smb_svcstate_session_start(smb_svc_sm_ctx_t *svc_sm,
    smb_session_t *new_session)
{
	rw_enter(&svc_sm->ssc_state_rwlock, RW_WRITER);
	if (svc_sm->ssc_active_session_count >=
	    smb_info.si.skc_maxconnections) {
		svc_sm->ssc_error_no_resources++;
		rw_exit(&svc_sm->ssc_state_rwlock);

		smb_session_reject(new_session, "Too many open sessions");
		smb_session_delete(new_session);
	} else {
		new_session->s_state = SMB_SESSION_STATE_CONNECTED;
		list_insert_tail(&svc_sm->ssc_active_sessions, new_session);
		svc_sm->ssc_active_session_count++;
		rw_exit(&svc_sm->ssc_state_rwlock);

		/*
		 * Blocks until thread has started
		 */
		if (smb_thread_start(&new_session->s_thread) != 0) {
			smb_svcstate_session_reject_active(svc_sm, new_session,
			    "Session thread creation failed");
		} else {
			DTRACE_PROBE1(session__create,
			    struct session *, new_session);
		}
	}
}

static void
smb_svcstate_session_defer(smb_svc_sm_ctx_t *svc_sm,
    smb_session_t *new_session)
{
	list_insert_tail(&svc_sm->ssc_deferred_sessions, new_session);
	svc_sm->ssc_deferred_session_count++;
}

/*ARGSUSED*/
static void
smb_svcstate_session_reject_active(smb_svc_sm_ctx_t *svc_sm,
    smb_session_t *session, char *reason)
{
	smb_session_reject(session, reason);

	smb_svcstate_event(SMB_SVCEVT_SESSION_DELETE, (uintptr_t)session);
}

static void
smb_svcstate_start_deferred_sessions(smb_svc_sm_ctx_t *svc_sm)
{
	smb_session_t *session, *next_session;

	/*
	 * svc_sm->ssc_deferred_sessions is private to the (single-threaded)
	 * state machine so we don't need to lock it.
	 */
	session = list_head(&svc_sm->ssc_deferred_sessions);
	while (session != NULL) {
		next_session =
		    list_next(&svc_sm->ssc_deferred_sessions, session);
		list_remove(&svc_sm->ssc_deferred_sessions, session);
		svc_sm->ssc_deferred_session_count--;
		smb_svcstate_session_start(svc_sm, session);
		session = next_session;
	}
}

static void
smb_svcstate_reject_deferred_sessions(smb_svc_sm_ctx_t *svc_sm)
{
	smb_session_t *session, *next_session;


	/*
	 * svc_sm->ssc_deferred_sessions is private to the (single-threaded)
	 * state machine so we don't need to lock it.
	 */
	session = list_head(&svc_sm->ssc_deferred_sessions);
	while (session != NULL) {
		next_session =
		    list_next(&svc_sm->ssc_deferred_sessions, session);
		list_remove(&svc_sm->ssc_deferred_sessions, session);
		svc_sm->ssc_deferred_session_count--;
		smb_svcstate_session_reject_active(svc_sm, session,
		    "SMB service is shutting down (deferred)");
		session = next_session;
	}
}

static void
smb_svcstate_close_active_sessions(smb_svc_sm_ctx_t *svc_sm)
{
	smb_session_t *session;

	rw_enter(&svc_sm->ssc_state_rwlock, RW_WRITER);
	for (session = list_head(&svc_sm->ssc_active_sessions);
	    session != NULL;
	    session = list_next(&svc_sm->ssc_active_sessions, session)) {
		ASSERT(session->s_magic == SMB_SESSION_MAGIC);
		rw_exit(&svc_sm->ssc_state_rwlock);

		/*
		 * As each session thread terminates it will generate
		 * a "session delete" event.
		 */
		smb_thread_stop(&session->s_thread);

		rw_enter(&svc_sm->ssc_state_rwlock, RW_WRITER);
	}
	rw_exit(&svc_sm->ssc_state_rwlock);
}
