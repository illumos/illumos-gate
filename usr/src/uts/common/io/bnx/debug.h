/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _DEBUG_H
#define	_DEBUG_H



/*
 * Debug break and output routines.
 */

void
debug_break(void *ctx);

void debug_msg(void *ctx, unsigned long level, char *file, unsigned long line,
    char *msg, ...);

void debug_msgx(void *ctx, unsigned long level, char *msg, ...);



/*
 * Debug macros
 */

/* Code paths. */
#define	CP_INIT			0x010000    /* Initialization */
#define	CP_SEND			0x020000    /* Transmit */
#define	CP_RCV			0x040000    /* Recieve */
#define	CP_INT			0x080000    /* Interrupt */
#define	CP_UINIT		0x100000    /* Unload */
#define	CP_RESET		0x200000    /* Reset */
#define	CP_GEN_BUF		0x400000    /* Generic buffer. */
#define	CP_ALL			0xffff0000  /* All code path */

#define	CP_MASK			0xffff0000


/* Mess	ge levels. */
#define	LV_VERBOSE		0x03
#define	LV_INFORM		0x02
#define	LV_WARN			0x01
#define	LV_FATAL		0x00

#define	LV_MASK			0xffff


/*
 * Code path and messsage level combined.  These are the first argument
 * of the DbgMessage macro.
 */

#define	VERBOSEi		(CP_INIT | LV_VERBOSE)
#define	INFORMi			(CP_INIT | LV_INFORM)
#define	WARNi			(CP_INIT | LV_WARN)

#define	VERBOSEtx		(CP_SEND | LV_VERBOSE)
#define	INFORMtx		(CP_SEND | LV_INFORM)
#define	WARNtx			(CP_SEND | LV_WARN)

#define	VERBOSErx		(CP_RCV | LV_VERBOSE)
#define	INFORMrx		(CP_RCV | LV_INFORM)
#define	WARNrx			(CP_RCV | LV_WARN)

#define	VERBOSEint		(CP_INT | LV_VERBOSE)
#define	INFORMint		(CP_INT | LV_INFORM)
#define	WARNint			(CP_INT | LV_WARN)

#define	VERBOSEu		(CP_UINIT | LV_VERBOSE)
#define	INFORMu			(CP_UINIT | LV_INFORM)
#define	WARNu			(CP_UINIT | LV_WARN)

#define	VERBOSErs		(CP_RESET | LV_VERBOSE)
#define	INFORMrs		(CP_RESET | LV_INFORM)
#define	WARNrs			(CP_RESET | LV_WARN)

#define	VERBOSEgb		(CP_GEN_BUF | LV_VERBOSE)
#define	INFORMgb		(CP_GEN_BUF | LV_INFORM)
#define	WARNgb			(CP_GEN_BUF | LV_WARN)


#define	FATAL			(CP_ALL | LV_FATAL)
#define	WARN			(CP_ALL | LV_WARN)
#define	INFORM			(CP_ALL | LV_INFORM)
#define	VERBOSE			(CP_ALL | LV_VERBOSE)


#if DBG

/*
 * These constants control the output of messages.
 * Set your debug message output level and code path here.
 */
#ifndef	DBG_MSG_CP
#define	DBG_MSG_CP		CP_ALL	/* Where to output messages. */
#endif

#ifndef	DBG_MSG_LV
#define	DBG_MSG_LV		LV_VERBOSE	/* Level of message output. */
#endif


/* CSTYLED */
#define	STATIC
#define	DbgBreak(_c)		debug_break(_c)


#define	CODE_PATH(_m)		((_m) & DBG_MSG_CP)
#define	MSG_LEVEL(_m)		((_m) & LV_MASK)
#define	LOG_MSG(_m)		(CODE_PATH(_m) && \
				    MSG_LEVEL(_m) <= DBG_MSG_LV)


/* BEGIN CSTYLED */
#define	DbgMessage(_c, _m, _s)                                              \
    if (LOG_MSG(_m))                                                        \
    {                                                                       \
        debug_msg(_c, _m, __FILE__, __LINE__, _s);                          \
    }
#define	DbgMessage1(_c, _m, _s, _d1)                                        \
    if (LOG_MSG(_m))                                                        \
    {                                                                       \
        debug_msg(_c, _m, __FILE__, __LINE__, _s, _d1);                     \
    }
#define	DbgMessage2(_c, _m, _s, _d1, _d2)                                   \
    if (LOG_MSG(_m))                                                        \
    {                                                                       \
        debug_msg(_c, _m, __FILE__, __LINE__, _s, _d1, _d2);                \
    }
#define	DbgMessage3(_c, _m, _s, _d1, _d2, _d3)                              \
    if (LOG_MSG(_m))                                                        \
    {                                                                       \
        debug_msg(_c, _m, __FILE__, __LINE__, _s, _d1, _d2, _d3);           \
    }
#define	DbgMessage4(_c, _m, _s, _d1, _d2, _d3, _d4)                         \
    if (LOG_MSG(_m))                                                        \
    {                                                                       \
        debug_msg(_c, _m, __FILE__, __LINE__, _s, _d1, _d2, _d3, _d4);      \
    }
#define	DbgMessage5(_c, _m, _s, _d1, _d2, _d3, _d4, _d5)                    \
    if (LOG_MSG(_m))                                                        \
    {                                                                       \
        debug_msg(_c, _m, __FILE__, __LINE__, _s, _d1, _d2, _d3, _d4, _d5); \
    }
#define	DbgMessage6(_c, _m, _s, _d1, _d2, _d3, _d4, _d5, _d6)               \
    if (LOG_MSG(_m))                                                        \
    {                                                                       \
        debug_msg(_c, _m, __FILE__, __LINE__, _s, _d1,_d2,_d3,_d4,_d5,_d6); \
    }

#define	DbgMessageX(_c, _m, _s)                                             \
    if (LOG_MSG(_m))                                                        \
    {                                                                       \
        debug_msgx(_c, _m, _s);                                             \
    }
#define	DbgMessageX1(_c, _m, _s, _d1)                                       \
    if (LOG_MSG(_m))                                                        \
    {                                                                       \
        debug_msgx(_c, _m, _s, _d1);                                        \
    }
#define	DbgMessageX2(_c, _m, _s, _d1, _d2)                                  \
    if (LOG_MSG(_m))                                                        \
    {                                                                       \
        debug_msgx(_c, _m, _s, _d1, _d2);                                   \
    }
#define	DbgMessageX3(_c, _m, _s, _d1, _d2, _d3)                             \
    if (LOG_MSG(_m))                                                        \
    {                                                                       \
        debug_msgx(_c, _m, _s, _d1, _d2, _d3);                              \
    }
#define	DbgMessageX4(_c, _m, _s, _d1, _d2, _d3, _d4)                        \
    if (LOG_MSG(_m))                                                        \
    {                                                                       \
        debug_msgx(_c, _m, _s, _d1, _d2, _d3, _d4);                         \
    }
#define	DbgMessageX5(_c, _m, _s, _d1, _d2, _d3, _d4, _d5)                   \
    if (LOG_MSG(_m))                                                        \
    {                                                                       \
        debug_msgx(_c, _m, _s, _d1, _d2, _d3, _d4, _d5);                    \
    }
#define	DbgMessageX6(_c, _m, _s, _d1, _d2, _d3, _d4, _d5, _d6)              \
    if (LOG_MSG(_m))                                                        \
    {                                                                       \
        debug_msgx(_c, _m, _s, _d1,_d2,_d3,_d4,_d5,_d6);                    \
    }

#define	DbgBreakIf(_c)							\
    if (_c)								\
    {									\
        debug_msg(NULL, FATAL, __FILE__, __LINE__, "if("#_c##")\n");	\
        debug_break(NULL);						\
    }

#define	DbgBreakMsg(_m)	debug_msg(NULL, FATAL, __FILE__, __LINE__, _m); \
    debug_break(NULL)
/* END CSTYLED */


#else

/* CSTYLED */
#define	STATIC static

#define	DbgBreak(_c)

#define	DbgMessage(_c, _m, _s)
#define	DbgMessage1(_c, _m, _s, _d1)
#define	DbgMessage2(_c, _m, _s, _d1, _d2)
#define	DbgMessage3(_c, _m, _s, _d1, _d2, _d3)
#define	DbgMessage4(_c, _m, _s, _d1, _d2, _d3, _d4)
#define	DbgMessage5(_c, _m, _s, _d1, _d2, _d3, _d4, _d5)
#define	DbgMessage6(_c, _m, _s, _d1, _d2, _d3, _d4, _d5, _d6)

#define	DbgMessageX(_c, _m, _s)
#define	DbgMessageX1(_c, _m, _s, _d1)
#define	DbgMessageX2(_c, _m, _s, _d1, _d2)
#define	DbgMessageX3(_c, _m, _s, _d1, _d2, _d3)
#define	DbgMessageX4(_c, _m, _s, _d1, _d2, _d3, _d4)
#define	DbgMessageX5(_c, _m, _s, _d1, _d2, _d3, _d4, _d5)
#define	DbgMessageX6(_c, _m, _s, _d1, _d2, _d3, _d4, _d5, _d6)

#define	DbgBreakIf(_c)
#define	DbgBreakMsg(_m)

#endif

#endif /* _DEBUG_H */
