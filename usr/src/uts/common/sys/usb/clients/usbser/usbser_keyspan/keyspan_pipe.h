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

#ifndef _SYS_USB_USBSER_KEYSPAN_PIPE_H
#define	_SYS_USB_USBSER_KEYSPAN_PIPE_H


/*
 * USB pipe management (mostly device-neutral)
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * pipe structure
 */
typedef struct keyspan_pipe {
	kmutex_t		pipe_mutex;	/* structure lock */
	keyspan_state_t		*pipe_ksp;	/* backpointer to state */
	usb_pipe_handle_t	pipe_handle;	/* pipe handle */
	usb_ep_descr_t		pipe_ep_descr;	/* endpoint descriptor */
	usb_pipe_policy_t	pipe_policy;	/* pipe policy */
	int			pipe_state;	/* pipe state */
	usb_log_handle_t	pipe_lh;	/* log handle */
} keyspan_pipe_t;

_NOTE(MUTEX_PROTECTS_DATA(keyspan_pipe::pipe_mutex, keyspan_pipe))
_NOTE(DATA_READABLE_WITHOUT_LOCK(keyspan_pipe::{
	pipe_ksp
	pipe_handle
	pipe_lh
	pipe_ep_descr
	pipe_policy
}))

/* pipe states */
enum {
	KEYSPAN_PIPE_NOT_INIT = 0,
	KEYSPAN_PIPE_CLOSED,
	KEYSPAN_PIPE_OPEN
};


int	keyspan_init_pipes(keyspan_state_t *);
int	keyspan_init_pipes_usa49wg(keyspan_state_t *);
void	keyspan_fini_pipes(keyspan_state_t *);
int	keyspansp_open_pipes(keyspan_state_t *);
void	keyspansp_close_pipes(keyspan_state_t *);
int	keyspan_open_dev_pipes(keyspan_state_t *);
void	keyspan_close_dev_pipes(keyspan_state_t *);
int	keyspan_open_port_pipes(keyspan_port_t *);
void	keyspan_close_port_pipes(keyspan_port_t *);
int	keyspan_reopen_pipes(keyspan_state_t *);
void	keyspan_close_pipes(keyspan_state_t *);
void	keyspan_close_open_pipes(keyspan_state_t *esp);

int	keyspan_receive_data(keyspan_pipe_t *, int, void *);
int	keyspan_send_data(keyspan_pipe_t *, mblk_t **, void *);
int	keyspan_send_data_port0(keyspan_pipe_t *, mblk_t **, void *);

int	keyspan_receive_status(keyspan_state_t	*);
void	keyspan_pipe_start_polling(keyspan_pipe_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_USBSER_KEYSPAN_PIPE_H */
