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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef __ADM_H__
#define	__ADM_H__

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * adm.h: defines and function prototypes for scadm
 */

#include <stdio.h>
#include <time.h>

#include "librsc.h"


/* DEFINES */
#define	ADM_TIMEOUT		2  /* RX timeout for normal messages */
#define	ADM_SEPROM_TIMEOUT	10 /* timeout for messages requiring serial */
				    /* eprom update */
#define	ADM_BOOT_INIT_TIMEOUT	1  /* RX timeout for BOOT_INIT message */
#define	ADM_BOOT_LOAD_TIMEOUT	10 /* RX timeout for BOOT s-record message */
#define	ADM_BOOT_RETRY		5  /* Number of times to retry BOOT messages */
#define	ADM_LINE_SIZE		1024 /* Max s-record line size */
#define	ADM_BP_BUFF_SIZE	20

/*
 * By default, how much of an extended log will be displayed (for character-
 * based logs.)
 */
#define	ADM_DEFAULT_LOG_LENGTH	8192

/* Default number of events we ask ALOM for (for event-based logs.) */
#define	DEFAULT_NUM_EVENTS 100


/* Return values for ADM_Valid_srecord() */
#define	SREC_OK			0
#define	SREC_ERR_LINE_TOO_BIG	-1
#define	SREC_ERR_LINE_TOO_SMALL	-2
#define	SREC_ERR_BAD_HEADER	-3
#define	SREC_ERR_WRONG_LENGTH	-4
#define	SREC_ERR_BAD_CRC	-5


/* SPEC'S */
void  ADM_Init();
void  ADM_Cleanup();
void  ADM_Exit(int errorCode);

void  ADM_Process_command(int argc, char *argv[]);
void  ADM_Process_help();
void  ADM_Process_modem_setup();
void  ADM_Process_status();
void  ADM_Process_send_event(int argc, char *argv[]);
void  ADM_Process_date(int argc, char *argv[]);
void  ADM_Process_set(int argc, char *argv[]);
void  ADM_Process_show(int argc, char *argv[]);
void  ADM_Process_reset(int argc, char *argv[]);
void  ADM_Process_download(int argc, char *argv[]);
void  ADM_Process_useradd(int argc, char *argv[]);
void  ADM_Process_userdel(int argc, char *argv[]);
void  ADM_Process_usershow(int argc, char *argv[]);
void  ADM_Process_userpassword(int argc, char *argv[]);
void  ADM_Process_userperm(int argc, char *argv[]);
void  ADM_Process_show_network();
void  ADM_Process_event_log(int all);
void  ADM_Process_console_log(int all);
void  ADM_Process_fru_log(int all);

void  ADM_Usage();
void  ADM_Callback(bp_msg_t *Message);
int   ADM_Valid_srecord(FILE  *FilePtr);
int   ADM_Send_file(FILE  *FilePtr);
void  ADM_Display_download_error(int cmd, int dat1); /* in send_file.c */

/* rscp_register_bpmsg_cb() must be called before using */
/* rscp_send_bpmsg() or ADM_Boot_Recv() */
int  ADM_Boot_recv(bp_msg_t *MessagePtr, struct timespec *Timeout);


/* Wrappers for rscp routines */
void ADM_Start();
void ADM_Send(rscp_msg_t *msg);
int ADM_Send_ret(rscp_msg_t *msg);
void ADM_Recv(rscp_msg_t *msg, struct timespec *timeout, int expectType,
    int expectSize);
void ADM_Free(rscp_msg_t  *msg);

#ifdef	__cplusplus
}
#endif

#endif /* __ADM_H__ */
