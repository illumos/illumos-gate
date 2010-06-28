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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */


#ifndef DEBUG_H
#define DEBUG_H

/************************** START OF MODULE PROLOGUE ***************************
*
* Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
*
*-------------------------------------------------------------------------------
*
*  FUNCTION NAME:  di_debug
*
*  FUNCTION TITLE:  Display debug information
*
*  TASK/PROCESS NAME: Encryption
*
*  MODULE DESCRIPTION: Define globals and prototypes for displaying debug 
*                      information.
*
* HISTORY:
* -------
* 05/13/10  JHD  xxxxxxx  Added Prologue and prototype for log_cond_printf().
*                
***************************** END OF MODULE PROLOGUE **************************/

#ifdef DEBUG
#warn "DEBUG is on"
#endif

#ifdef DEBUG
#define START_STACK_CHECK                       \
   volatile unsigned long check1 = 0xDEADBABE;  \
   volatile unsigned long check2 = 0xFEEDF00D; 
   
#define END_STACK_CHECK                                                  \
{                                                                        \
   if (check1 != 0xDEADBABE)                                             \
      log_printf("stack check 1 failed at %s %c\n", __FILE__, __LINE__); \
   if (check2 != 0xFEEDF00D)                                             \
      log_printf("stack check 2 failed at %s %c\n", __FILE__, __LINE__); \
}
#else
#define START_STACK_CHECK
#define END_STACK_CHECK
#endif


#ifdef __cplusplus
extern "C"
{
#endif
   
#define OUTMSG_SIZE 256


/*-------------------------------------------------------------------
 * Use the following to define whether memory is actually
 * going to be allocated for these definitions.
 *------------------------------------------------------------------*/
#undef EXTERNAL

#ifdef ALLOCATE_ECPT_TRACE             /* This set means we are allocating   */
   #define EXTERNAL
#else
   #define EXTERNAL extern
#endif

#define ECPT_MAX_TRACE           2048
#define ECPT_TRACE_CHAR          111

typedef struct
{
   int         task;                         /* which thread         */
   int         tod;                          /* Time of Day Stamp    */
   int         function;                     /* Function name        */
   int         len;                          /* num chars in buffer  */
   char        buf[ ECPT_TRACE_CHAR + 1 ];   /* trace message buffer */

}  ECPT_TRACE_ENTRY;


typedef struct
{
   int                  index;                     /* Index to next entry */

   int                  tx_wait;
   int                  tx_ds_main;
   int                  tx_rsv1;                   /* unused */
   int                  tx_rsv2;                   /* unused */
   int                  tx_rsv3;                   /* unused */
   int                  tx_rsv4;                   /* unused */
   int                  tx_rsv5;                   /* unused */

   ECPT_TRACE_ENTRY     entry[ ECPT_MAX_TRACE ];   /* Telnet trace entries */

} ECPT_TRACE_STRUCT;


EXTERNAL ECPT_TRACE_STRUCT   Ecpt_trace_table;

/*--------------------------------------------------------------------------
 * Define ECPT KMS Agent communications to include in log to telnet clients.
 *-------------------------------------------------------------------------*/
EXTERNAL int                 Ecpt_log_to_telnet;

#define ECPT_LOG_SSL_CB          0x0001
#define ECPT_LOG_TCP_CONNECT     0x0002
#define ECPT_LOG_TCP_DISCONNECT  0x0004
#define ECPT_LOG_TCP_SHUTDOWN    0x0008
#define ECPT_LOG_TCP_SEND        0x0010
#define ECPT_LOG_TCP_FRECV       0x0020
#define ECPT_LOG_TCP_CLOSE       0x0040
#define ECPT_LOG_SSL_CLIENT      0x0080
#define ECPT_LOG_AGENT           0x0100


extern char outmsg[OUTMSG_SIZE];

void serial_debug_msg(char*, int);
int  log_fprintf(FILE *, const char *, ...);
int  log_sprintf(char*, const char *, ...);
int  log_printf(const char *, ...);
int  log_error_printf(const char *, ...);
void log_cond_printf(int, const char *, ...);

ECPT_TRACE_ENTRY    *ecpt_trace( int     function,
                                 char   *func );

#define ECPT_TRACE( trace, func )  trace = ecpt_trace( (int)func, #func );
   
#ifdef __cplusplus
}
#endif

   
#endif
