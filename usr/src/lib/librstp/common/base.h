/************************************************************************
 * RSTP library - Rapid Spanning Tree (802.1t, 802.1w)
 * Copyright (C) 2001-2003 Optical Access
 * Author: Alex Rozin
 *
 * This file is part of RSTP library.
 *
 * RSTP library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; version 2.1
 *
 * RSTP library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with RSTP library; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 **********************************************************************/

/* Mutual RSTP definitions */

#ifndef _STP_BASE_H__
#define _STP_BASE_H__

#include <stdlib.h>
#include <string.h>

#define STP_DBG 1

#if defined(__LINUX__) || defined(__SUN__)
#  include <stddef.h>
#  include <stdio.h>
#  include <netinet/in.h>
#  include "uid_stp.h"
#else
#  include <psos.h>
#  include "comdef.h"
#  include "comdef.x"
#  include "Bitmap/bitmap.h"
#  include "Bitmap/bitmap.x"
#  include "Ui/uid_stp.h"
#endif

#ifndef INOUT
#  define IN      /* consider as comments near 'input' parameters */
#  define OUT     /* consider as comments near 'output' parameters */
#  define INOUT   /* consider as comments near 'input/output' parameters */
#endif

#ifndef Zero
#  define Zero        0
#  define One         1
#endif

#ifndef Bool
#  define Bool        int
#  define False       0
#  define True        1
#endif

#include "stp_bpdu.h"
#include "vector.h"
#include "times.h"

#define RSTP_ERRORS { \
  CHOOSE(STP_OK),                                       \
  CHOOSE(STP_Cannot_Find_Vlan),         \
  CHOOSE(STP_Implicit_Instance_Create_Failed),          \
  CHOOSE(STP_Small_Bridge_Priority),                    \
  CHOOSE(STP_Large_Bridge_Priority),                    \
  CHOOSE(STP_Small_Hello_Time),                         \
  CHOOSE(STP_Large_Hello_Time),                         \
  CHOOSE(STP_Small_Max_Age),                            \
  CHOOSE(STP_Large_Max_Age),                            \
  CHOOSE(STP_Small_Forward_Delay),                      \
  CHOOSE(STP_Large_Forward_Delay),                      \
  CHOOSE(STP_Forward_Delay_And_Max_Age_Are_Inconsistent),\
  CHOOSE(STP_Hello_Time_And_Max_Age_Are_Inconsistent),  \
  CHOOSE(STP_Vlan_Had_Not_Yet_Been_Created),            \
  CHOOSE(STP_Port_Is_Absent_In_The_Vlan),               \
  CHOOSE(STP_Big_len8023_Format),                       \
  CHOOSE(STP_Small_len8023_Format),                     \
  CHOOSE(STP_len8023_Format_Gt_Len),                    \
  CHOOSE(STP_Not_Proper_802_3_Packet),                  \
  CHOOSE(STP_Invalid_Protocol),                         \
  CHOOSE(STP_Invalid_Version),                          \
  CHOOSE(STP_Had_Not_Yet_Been_Enabled_On_The_Vlan),     \
  CHOOSE(STP_Cannot_Create_Instance_For_Vlan),          \
  CHOOSE(STP_Cannot_Create_Instance_For_Port),          \
  CHOOSE(STP_Invalid_Bridge_Priority),                  \
  CHOOSE(STP_There_Are_No_Ports),                       \
  CHOOSE(STP_Cannot_Compute_Bridge_Prio),               \
  CHOOSE(STP_Another_Error),                            \
  CHOOSE(STP_Nothing_To_Do),                            \
  CHOOSE(STP_No_Such_State_Machine),                    \
  CHOOSE(STP_LAST_DUMMY)                                \
}

#define CHOOSE(a) a
typedef enum RSTP_ERRORS RSTP_ERRORS_T;
#undef CHOOSE

#if !defined(__LINUX__) && !defined(__SUN__)
extern char* strdup (const char *s);

extern USHORT Ntohs (USHORT n);
extern ULONG Htonl (ULONG h);
extern USHORT Htons (USHORT h);
extern ULONG Ntohl (ULONG n);

#define htonl Htonl
#define htons Htons
#define ntohl Ntohl
#define ntohs Ntohs

#endif

#if defined(__LINUX__) || defined(__SUN__)
#ifdef STP_DBG
#define STP_FATAL(TXT, MSG, EXCOD)                      \
      {stp_trace ("FATAL:%s failed: %s:%d", TXT, MSG, EXCOD);  \
      exit (EXCOD);}
#else
#define STP_FATAL(TXT, MSG, EXCOD)                      \
      abort();
#endif
#else
#define STP_FATAL(TXT, MSG, EXCOD)                      \
      printf("FATAL: %s code %s:%d\n", TXT, MSG, EXCOD)
#endif

#define STP_MALLOC(PTR, TYPE, MSG)              \
  {                                             \
    PTR = (TYPE*) calloc (1, sizeof (TYPE));    \
    if (! PTR) {                                \
      STP_FATAL("malloc", MSG, -6);             \
    }                                           \
  }

#define STP_FREE(PTR, MSG)              \
  {                                     \
    if (! PTR) {                        \
      STP_FATAL("free", MSG, -66);      \
    }                                   \
    free (PTR);                         \
    PTR = NULL;                         \
  }

#define STP_STRDUP(PTR, SRC, MSG)       \
  {                                     \
    PTR = strdup (SRC);                 \
    if (! PTR) {                        \
      STP_FATAL("strdup", MSG, -7);     \
    }                                   \
  }

#define STP_NEW_IN_LIST(WHAT, TYPE, LIST, MSG)  \
  {                                             \
    STP_MALLOC(WHAT, TYPE, MSG);                \
    WHAT->next = LIST;                          \
    LIST = WHAT;                                \
  }

/* for debug trace messages */

#ifdef STP_DBG
#if defined(__LINUX__)
extern char* sprint_time_stump (void);
#define stp_trace(F, B...) printf("%s:" F "\n", sprint_time_stump(), ##B)
#elif defined(__SUN__)
#define	stp_trace	(*stp_vectors->trace)
#else
extern ULONG stp_trace (const char* fmt, ...);
#endif
#else /* !STP_DBG */
#define stp_trace(F, B...) ((void)0)
#endif /* STP_DBG */


/* Inner usage definitions & functions */

#if defined(__LINUX__) || defined(__SUN__)
#  define RSTP_INIT_CRITICAL_PATH_PROTECTIO
#  define RSTP_CRITICAL_PATH_START
#  define RSTP_CRITICAL_PATH_END
#else
#  define RSTP_INIT_CRITICAL_PATH_PROTECTIO STP_OUT_psos_init_semaphore ()
#  define RSTP_CRITICAL_PATH_START          STP_OUT_psos_close_semaphore ()
#  define RSTP_CRITICAL_PATH_END            STP_OUT_psos_open_semaphore ()
   extern void STP_OUT_psos_init_semaphore (void);
   extern void STP_OUT_psos_close_semaphore (void);
   extern void STP_OUT_psos_open_semaphore (void);
#endif

#endif /*  _STP_BASE_H__ */
