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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4.1.2	*/

# include	<time.h>

# include	"lpsched.h"

void		s_accept_dest ( char * , MESG * );
void		s_alloc_files ( char * , MESG * );
void		s_cancel ( char * , MESG * );
void		s_cancel_request ( char * , MESG * );
void		s_complete_job ( char * , MESG * );
void		s_disable_dest ( char * , MESG * );
void		s_enable_dest ( char * , MESG * );
void		s_end_change_request ( char * , MESG * );
void		s_inquire_class ( char * , MESG * );
void		s_inquire_printer_status ( char * , MESG * );
void		s_inquire_request_rank ( char * , MESG * );
void		s_load_class ( char * , MESG * );
void		s_load_filter_table ( char * , MESG * );
void		s_load_form ( char * , MESG * );
void		s_load_printer ( char * , MESG * );
void		s_load_printwheel ( char * , MESG * );
void		s_load_system ( char * , MESG * );
void		s_load_user_file ( char * , MESG * );
void		s_mount ( char * , MESG * );
void		s_move_dest  ( char * , MESG * );
void		s_move_request ( char * , MESG * );
void		s_print_request ( char * , MESG * );
void		s_quiet_alert ( char * , MESG * );
void		s_reject_dest ( char * , MESG * );
void		s_send_fault ( char * , MESG * );
void		s_clear_fault ( char * , MESG * );
void		s_shutdown ( char * , MESG * );
void		s_start_change_request ( char * , MESG * );
void		s_unload_class ( char * , MESG * );
void		s_unload_filter_table ( char * , MESG * );
void		s_unload_form ( char * , MESG * );
void		s_unload_printer ( char * , MESG * );
void		s_unload_printwheel ( char * , MESG * );
void		s_unload_system ( char * , MESG * );
void		s_unload_user_file ( char * , MESG * );
void		s_unmount ( char * , MESG * );
void		r_new_child ( char * , MESG * );
void		r_send_job ( char * , MESG * );
void		s_job_completed ( char * , MESG * );
void		s_child_done ( char * , MESG * );
void		s_get_fault_message ( char * , MESG * );
void		s_max_trays ( char * , MESG *);
void		s_mount_tray ( char *, MESG * );
void		s_unmount_tray ( char *, MESG *);
void		s_paper_changed ( char *, MESG *);
void		s_paper_allowed ( char *, MESG *);
void		s_pass_peer_connection ( char * , MESG * );
	
/**
 ** dispatch_table[]
 **/

/*
 * The dispatch table is used to decide if we should handle
 * a message and which function should be used to handle it.
 *
 * D_ADMIN is set for messages that should be handled
 * only if it came from an administrator. These entries should
 * have a corresponding entry for the R_... message case, that
 * provides a routine for sending back a MNOPERM message to those
 * that aren't administrators. This is needed because the response
 * message varies in size with the message type.
 */

typedef struct DISPATCH {
	void			(*fncp)();
	ushort			flags;
}			DISPATCH;

#define	D_ADMIN		0x01	/* Only "lp" or "root" can use msg. */
#define D_BADMSG	0x02	/* We should never get this message */
#define	D_SYSTEM	0x04	/* Only siblings may use this message */
