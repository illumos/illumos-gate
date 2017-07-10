/*
 * Copyright (c) 2000, 2001, 2002, 2003, 2004 by Martin C. Shepherd.
 *
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, and/or sell copies of the Software, and to permit persons
 * to whom the Software is furnished to do so, provided that the above
 * copyright notice(s) and this permission notice appear in all copies of
 * the Software and that both the above copyright notice(s) and this
 * permission notice appear in supporting documentation.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
 * OF THIRD PARTY RIGHTS. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * HOLDERS INCLUDED IN THIS NOTICE BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL
 * INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Except as contained in this notice, the name of a copyright holder
 * shall not be used in advertising or otherwise to promote the sale, use
 * or other dealings in this Software without prior written authorization
 * of the copyright holder.
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * Standard headers.
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <setjmp.h>
#include <stdarg.h>

/*
 * UNIX headers.
 */
#include <sys/ioctl.h>
#ifdef HAVE_SELECT
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <sys/time.h>
#include <sys/types.h>
#endif

/*
 * Handle the different sources of terminal control string and size
 * information. Note that if no terminal information database is available,
 * ANSI VT100 control sequences are used.
 */
#if defined(USE_TERMINFO) || defined(USE_TERMCAP)
/*
 * Include curses.h or ncurses/curses.h depending on which is available.
 */
#ifdef HAVE_CURSES_H
#include <curses.h>
#elif defined(HAVE_NCURSES_CURSES_H)
#include <ncurses/curses.h>
#endif
/*
 * Include term.h where available.
 */
#if defined(HAVE_TERM_H)
#include <term.h>
#elif defined(HAVE_NCURSES_TERM_H)
#include <ncurses/term.h>
#endif
/*
 * When using termcap, include termcap.h on systems that have it.
 * Otherwise assume that all prototypes are provided by curses.h.
 */
#if defined(USE_TERMCAP) && defined(HAVE_TERMCAP_H)
#include <termcap.h>
#endif

/*
 * Under Solaris default Curses the output function that tputs takes is
 * declared to have a char argument. On all other systems and on Solaris
 * X/Open Curses (Issue 4, Version 2) it expects an int argument (using
 * c89 or options -I /usr/xpg4/include -L /usr/xpg4/lib -R /usr/xpg4/lib
 * selects XPG4v2 Curses on Solaris 2.6 and later).
 *
 * Similarly, under Mac OS X, the return value of the tputs output
 * function is declared as void, whereas it is declared as int on
 * other systems.
 */
#if defined __sun && defined __SVR4 && !defined _XOPEN_CURSES
typedef int TputsRetType;
typedef char TputsArgType;              /* int tputs(char c, FILE *fp) */
#define TPUTS_RETURNS_VALUE 1
#elif defined(__APPLE__) && defined(__MACH__)
typedef void TputsRetType;
typedef int TputsArgType;               /* void tputs(int c, FILE *fp) */
#define TPUTS_RETURNS_VALUE 0
#else
typedef int TputsRetType;
typedef int TputsArgType;               /* int tputs(int c, FILE *fp) */
#define TPUTS_RETURNS_VALUE 1
#endif

/*
 * Use the above specifications to prototype our tputs callback function.
 */
static TputsRetType gl_tputs_putchar(TputsArgType c);

#endif  /* defined(USE_TERMINFO) || defined(USE_TERMCAP) */

/*
 * If the library is being compiled without filesystem access facilities,
 * ensure that none of the action functions that normally do access the
 * filesystem are bound by default, and that it they do get bound, that
 * they don't do anything.
 */
#if WITHOUT_FILE_SYSTEM
#define HIDE_FILE_SYSTEM
#endif

/*
 * POSIX headers.
 */
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>

/*
 * Provide typedefs for standard POSIX structures.
 */
typedef struct sigaction SigAction;
typedef struct termios Termios;

/*
 * Which flag is used to select non-blocking I/O with fcntl()?
 */
#undef NON_BLOCKING_FLAG
#if defined(O_NONBLOCK)
#define NON_BLOCKING_FLAG (O_NONBLOCK)
#elif defined(O_NDELAY)
#define NON_BLOCKING_FLAG (O_NDELAY)
#endif

/*
 * What value should we give errno if I/O blocks when it shouldn't.
 */
#undef BLOCKED_ERRNO
#if defined(EAGAIN)
#define BLOCKED_ERRNO (EAGAIN)
#elif defined(EWOULDBLOCK)
#define BLOCKED_ERRNO (EWOULDBLOCK)
#elif defined(EIO)
#define BLOCKED_ERRNO (EIO)
#else
#define BLOCKED_ERRNO 0
#endif

/*
 * Local headers.
 */
#ifndef WITHOUT_FILE_SYSTEM
#include "pathutil.h"
#endif
#include "libtecla.h"
#include "keytab.h"
#include "getline.h"
#include "ioutil.h"
#include "history.h"
#include "freelist.h"
#include "stringrp.h"
#include "chrqueue.h"
#include "cplmatch.h"
#ifndef WITHOUT_FILE_SYSTEM
#include "expand.h"
#endif
#include "errmsg.h"

/*
 * Enumerate the available editing styles.
 */
typedef enum {
  GL_EMACS_MODE,   /* Emacs style editing */
  GL_VI_MODE,      /* Vi style editing */
  GL_NO_EDITOR     /* Fall back to the basic OS-provided editing */
} GlEditor;

/*
 * Set the largest key-sequence that can be handled.
 */
#define GL_KEY_MAX 64

/*
 * In vi mode, the following datatype is used to implement the
 * undo command. It records a copy of the input line from before
 * the command-mode action which edited the input line.
 */
typedef struct {
  char *line;        /* A historical copy of the input line */
  int buff_curpos;   /* The historical location of the cursor in */
                     /*  line[] when the line was modified. */
  int ntotal;        /* The number of characters in line[] */
  int saved;         /* True once a line has been saved after the */
                     /*  last call to gl_interpret_char(). */
} ViUndo;

/*
 * In vi mode, the following datatype is used to record information
 * needed by the vi-repeat-change command.
 */
typedef struct {
  KtAction action;           /* The last action function that made a */
                             /*  change to the line. */
  int count;                 /* The repeat count that was passed to the */
                             /*  above command. */
  int input_curpos;          /* Whenever vi command mode is entered, the */
                             /*  the position at which it was first left */
                             /*  is recorded here. */
  int command_curpos;        /* Whenever vi command mode is entered, the */
                             /*  the location of the cursor is recorded */
                             /*  here. */
  char input_char;           /* Commands that call gl_read_terminal() */
                             /*  record the character here, so that it can */
                             /*  used on repeating the function. */
  int saved;                 /* True if a function has been saved since the */
                             /*  last call to gl_interpret_char(). */
  int active;                /* True while a function is being repeated. */
} ViRepeat;

/*
 * The following datatype is used to encapsulate information specific
 * to vi mode.
 */
typedef struct {
  ViUndo undo;               /* Information needed to implement the vi */
                             /*  undo command. */
  ViRepeat repeat;           /* Information needed to implement the vi */
                             /*  repeat command. */
  int command;               /* True in vi command-mode */
  int find_forward;          /* True if the last character search was in the */
                             /*  forward direction. */
  int find_onto;             /* True if the last character search left the */
                             /*  on top of the located character, as opposed */
                             /*  to just before or after it. */
  char find_char;            /* The last character sought, or '\0' if no */
                             /*  searches have been performed yet. */
} ViMode;

#ifdef HAVE_SELECT
/*
 * Define a type for recording a file-descriptor callback and its associated
 * data.
 */
typedef struct {
  GlFdEventFn *fn;   /* The callback function */
  void *data;        /* Anonymous data to pass to the callback function */
} GlFdHandler;

/*
 * A list of nodes of the following type is used to record file-activity
 * event handlers, but only on systems that have the select() system call.
 */
typedef struct GlFdNode GlFdNode;
struct GlFdNode {
  GlFdNode *next;    /* The next in the list of nodes */
  int fd;            /* The file descriptor being watched */
  GlFdHandler rd;    /* The callback to call when fd is readable */
  GlFdHandler wr;    /* The callback to call when fd is writable */
  GlFdHandler ur;    /* The callback to call when fd has urgent data */
};

/*
 * Set the number of the above structures to allocate every time that
 * the freelist of GlFdNode's becomes exhausted.
 */
#define GLFD_FREELIST_BLOCKING 10


static int gl_call_fd_handler(GetLine *gl, GlFdHandler *gfh, int fd,
			      GlFdEvent event);

static int gl_call_timeout_handler(GetLine *gl);

#endif

/*
 * Each signal that gl_get_line() traps is described by a list node
 * of the following type.
 */
typedef struct GlSignalNode GlSignalNode;
struct GlSignalNode {
  GlSignalNode *next;  /* The next signal in the list */
  int signo;           /* The number of the signal */
  sigset_t proc_mask;  /* A process mask which only includes signo */
  SigAction original;  /* The signal disposition of the calling program */
                       /*  for this signal. */
  unsigned flags;      /* A bitwise union of GlSignalFlags enumerators */
  GlAfterSignal after; /* What to do after the signal has been handled */
  int errno_value;     /* What to set errno to */
};

/*
 * Set the number of the above structures to allocate every time that
 * the freelist of GlSignalNode's becomes exhausted.
 */
#define GLS_FREELIST_BLOCKING 30

/*
 * Completion handlers and their callback data are recorded in
 * nodes of the following type.
 */
typedef struct GlCplCallback GlCplCallback;
struct GlCplCallback {
  CplMatchFn *fn;            /* The completion callback function */
  void *data;                /* Arbitrary callback data */
};

/*
 * The following function is used as the default completion handler when
 * the filesystem is to be hidden. It simply reports no completions.
 */
#ifdef HIDE_FILE_SYSTEM
static CPL_MATCH_FN(gl_no_completions);
#endif

/*
 * Specify how many GlCplCallback nodes are added to the GlCplCallback freelist
 * whenever it becomes exhausted.
 */
#define GL_CPL_FREELIST_BLOCKING 10

/*
 * External action functions and their callback data are recorded in
 * nodes of the following type.
 */
typedef struct GlExternalAction GlExternalAction;
struct GlExternalAction {
  GlActionFn *fn;          /* The function which implements the action */
  void *data;              /* Arbitrary callback data */
};

/*
 * Specify how many GlExternalAction nodes are added to the
 * GlExternalAction freelist whenever it becomes exhausted.
 */
#define GL_EXT_ACT_FREELIST_BLOCKING 10

/*
 * Define the contents of the GetLine object.
 * Note that the typedef for this object can be found in libtecla.h.
 */
struct GetLine {
  ErrMsg *err;               /* The error-reporting buffer */
  GlHistory *glh;            /* The line-history buffer */
  WordCompletion *cpl;       /* String completion resource object */
  GlCplCallback cplfn;       /* The completion callback */
#ifndef WITHOUT_FILE_SYSTEM
  ExpandFile *ef;            /* ~user/, $envvar and wildcard expansion */
                             /*  resource object. */
#endif
  StringGroup *capmem;       /* Memory for recording terminal capability */
                             /*  strings. */
  GlCharQueue *cq;           /* The terminal output character queue */
  int input_fd;              /* The file descriptor to read on */
  int output_fd;             /* The file descriptor to write to */
  FILE *input_fp;            /* A stream wrapper around input_fd */
  FILE *output_fp;           /* A stream wrapper around output_fd */
  FILE *file_fp;             /* When input is being temporarily taken from */
                             /*  a file, this is its file-pointer. Otherwise */
                             /*  it is NULL. */
  char *term;                /* The terminal type specified on the last call */
                             /*  to gl_change_terminal(). */
  int is_term;               /* True if stdin is a terminal */
  GlWriteFn *flush_fn;       /* The function to call to write to the terminal */
  GlIOMode io_mode;          /* The I/O mode established by gl_io_mode() */
  int raw_mode;              /* True while the terminal is in raw mode */
  GlPendingIO pending_io;    /* The type of I/O that is currently pending */
  GlReturnStatus rtn_status; /* The reason why gl_get_line() returned */
  int rtn_errno;             /* THe value of errno associated with rtn_status */
  size_t linelen;            /* The max number of characters per line */
  char *line;                /* A line-input buffer of allocated size */
                             /*  linelen+2. The extra 2 characters are */
                             /*  reserved for "\n\0". */
  char *cutbuf;              /* A cut-buffer of the same size as line[] */
  char *prompt;              /* The current prompt string */
  int prompt_len;            /* The length of the prompt string */
  int prompt_changed;        /* True after a callback changes the prompt */
  int prompt_style;          /* How the prompt string is displayed */
  FreeList *cpl_mem;         /* Memory for GlCplCallback objects */
  FreeList *ext_act_mem;     /* Memory for GlExternalAction objects */
  FreeList *sig_mem;         /* Memory for nodes of the signal list */
  GlSignalNode *sigs;        /* The head of the list of signals */
  int signals_masked;        /* True between calls to gl_mask_signals() and */
                             /*  gl_unmask_signals() */
  int signals_overriden;     /* True between calls to gl_override_signals() */
                             /*  and gl_restore_signals() */
  sigset_t all_signal_set;   /* The set of all signals that we are trapping */
  sigset_t old_signal_set;   /* The set of blocked signals on entry to */
                             /*  gl_get_line(). */
  sigset_t use_signal_set;   /* The subset of all_signal_set to unblock */
                             /*  while waiting for key-strokes */
  Termios oldattr;           /* Saved terminal attributes. */
  KeyTab *bindings;          /* A table of key-bindings */
  int ntotal;                /* The number of characters in gl->line[] */
  int buff_curpos;           /* The cursor position within gl->line[] */
  int term_curpos;           /* The cursor position on the terminal */
  int term_len;              /* The number of terminal characters used to */
                             /*  display the current input line. */
  int buff_mark;             /* A marker location in the buffer */
  int insert_curpos;         /* The cursor position at start of insert */
  int insert;                /* True in insert mode */
  int number;                /* If >= 0, a numeric argument is being read */
  int endline;               /* True to tell gl_get_input_line() to return */
                             /*  the current contents of gl->line[] */
  int displayed;             /* True if an input line is currently displayed */
  int redisplay;             /* If true, the input line will be redrawn */
                             /*  either after the current action function */
                             /*  returns, or when gl_get_input_line() */
                             /*  is next called. */
  int postpone;              /* _gl_normal_io() sets this flag, to */
                             /*  postpone any redisplays until */
                             /*  is next called, to resume line editing. */
  char keybuf[GL_KEY_MAX+1]; /* A buffer of currently unprocessed key presses */
  int nbuf;                  /* The number of characters in keybuf[] */
  int nread;                 /* The number of characters read from keybuf[] */
  KtAction current_action;   /* The action function that is being invoked */
  int current_count;         /* The repeat count passed to */
                             /*  current_acction.fn() */
  GlhLineID preload_id;      /* When not zero, this should be the ID of a */
                             /*  line in the history buffer for potential */
                             /*  recall. */
  int preload_history;       /* If true, preload the above history line when */
                             /*  gl_get_input_line() is next called. */
  long keyseq_count;         /* The number of key sequences entered by the */
                             /*  the user since new_GetLine() was called. */
  long last_search;          /* The value of keyseq_count during the last */
                             /*  history search operation. */
  GlEditor editor;           /* The style of editing, (eg. vi or emacs) */
  int silence_bell;          /* True if gl_ring_bell() should do nothing. */
  int automatic_history;     /* True to automatically archive entered lines */
                             /*  in the history list. */
  ViMode vi;                 /* Parameters used when editing in vi mode */
  const char *left;          /* The string that moves the cursor 1 character */
                             /*  left. */
  const char *right;         /* The string that moves the cursor 1 character */
                             /*  right. */
  const char *up;            /* The string that moves the cursor 1 character */
                             /*  up. */
  const char *down;          /* The string that moves the cursor 1 character */
                             /*  down. */
  const char *home;          /* The string that moves the cursor home */
  const char *bol;           /* Move cursor to beginning of line */
  const char *clear_eol;     /* The string that clears from the cursor to */
                             /*  the end of the line. */
  const char *clear_eod;     /* The string that clears from the cursor to */
                             /*  the end of the display. */
  const char *u_arrow;       /* The string returned by the up-arrow key */
  const char *d_arrow;       /* The string returned by the down-arrow key */
  const char *l_arrow;       /* The string returned by the left-arrow key */
  const char *r_arrow;       /* The string returned by the right-arrow key */
  const char *sound_bell;    /* The string needed to ring the terminal bell */
  const char *bold;          /* Switch to the bold font */
  const char *underline;     /* Underline subsequent characters */
  const char *standout;      /* Turn on standout mode */
  const char *dim;           /* Switch to a dim font */
  const char *reverse;       /* Turn on reverse video */
  const char *blink;         /* Switch to a blinking font */
  const char *text_attr_off; /* Turn off all text attributes */
  int nline;                 /* The height of the terminal in lines */
  int ncolumn;               /* The width of the terminal in columns */
#ifdef USE_TERMCAP
  char *tgetent_buf;         /* The buffer that is used by tgetent() to */
                             /*  store a terminal description. */
  char *tgetstr_buf;         /* The buffer that is used by tgetstr() to */
                             /*  store terminal capabilities. */
#endif
#ifdef USE_TERMINFO
  const char *left_n;        /* The parameter string that moves the cursor */
                             /*  n characters left. */
  const char *right_n;       /* The parameter string that moves the cursor */
                             /*  n characters right. */
#endif
  char *app_file;            /* The pathname of the application-specific */
                             /*  .teclarc configuration file, or NULL. */
  char *user_file;           /* The pathname of the user-specific */
                             /*  .teclarc configuration file, or NULL. */
  int configured;            /* True as soon as any teclarc configuration */
                             /*  file has been read. */
  int echo;                  /* True to display the line as it is being */
                             /*  entered. If 0, only the prompt will be */
                             /*  displayed, and the line will not be */
                             /*  archived in the history list. */
  int last_signal;           /* The last signal that was caught by */
                             /*  the last call to gl_get_line(), or -1 */
                             /*  if no signal has been caught yet. */
#ifdef HAVE_SELECT
  FreeList *fd_node_mem;     /* A freelist of GlFdNode structures */
  GlFdNode *fd_nodes;        /* The list of fd event descriptions */
  fd_set rfds;               /* The set of fds to watch for readability */
  fd_set wfds;               /* The set of fds to watch for writability */
  fd_set ufds;               /* The set of fds to watch for urgent data */
  int max_fd;                /* The maximum file-descriptor being watched */
  struct {                   /* Inactivity timeout related data */
    struct timeval dt;       /* The inactivity timeout when timer.fn() */
                             /*  isn't 0 */
    GlTimeoutFn *fn;         /* The application callback to call when */
                             /*  the inactivity timer expires, or 0 if */
                             /*  timeouts are not required. */
    void *data;              /* Application provided data to be passed to */
                             /*  timer.fn(). */
  } timer;
#endif
};

/*
 * Define the max amount of space needed to store a termcap terminal
 * description. Unfortunately this has to be done by guesswork, so
 * there is the potential for buffer overflows if we guess too small.
 * Fortunately termcap has been replaced by terminfo on most
 * platforms, and with terminfo this isn't an issue. The value that I
 * am using here is the conventional value, as recommended by certain
 * web references.
 */
#ifdef USE_TERMCAP
#define TERMCAP_BUF_SIZE 2048
#endif

/*
 * Set the size of the string segments used to store terminal capability
 * strings.
 */
#define CAPMEM_SEGMENT_SIZE 512

/*
 * If no terminal size information is available, substitute the
 * following vt100 default sizes.
 */
#define GL_DEF_NLINE 24
#define GL_DEF_NCOLUMN 80

/*
 * Enumerate the attributes needed to classify different types of
 * signals. These attributes reflect the standard default
 * characteristics of these signals (according to Richard Steven's
 * Advanced Programming in the UNIX Environment). Note that these values
 * are all powers of 2, so that they can be combined in a bitwise union.
 */
typedef enum {
  GLSA_TERM=1,   /* A signal that terminates processes */
  GLSA_SUSP=2,   /* A signal that suspends processes */
  GLSA_CONT=4,   /* A signal that is sent when suspended processes resume */
  GLSA_IGN=8,    /* A signal that is ignored */
  GLSA_CORE=16,  /* A signal that generates a core dump */
  GLSA_HARD=32,  /* A signal generated by a hardware exception */
  GLSA_SIZE=64   /* A signal indicating terminal size changes */
} GlSigAttr;

/*
 * List the signals that we need to catch. In general these are
 * those that by default terminate or suspend the process, since
 * in such cases we need to restore terminal settings.
 */
static const struct GlDefSignal {
  int signo;            /* The number of the signal */
  unsigned flags;       /* A bitwise union of GlSignalFlags enumerators */
  GlAfterSignal after;  /* What to do after the signal has been delivered */
  int attr;             /* The default attributes of this signal, expressed */
                        /* as a bitwise union of GlSigAttr enumerators */
  int errno_value;      /* What to set errno to */
} gl_signal_list[] = {
  {SIGABRT,   GLS_SUSPEND_INPUT,    GLS_ABORT, GLSA_TERM|GLSA_CORE, EINTR},
  {SIGALRM,   GLS_RESTORE_ENV,   GLS_CONTINUE, GLSA_TERM,           0},
  {SIGCONT,   GLS_RESTORE_ENV,   GLS_CONTINUE, GLSA_CONT|GLSA_IGN,  0},
#if defined(SIGHUP)
#ifdef ENOTTY
  {SIGHUP,    GLS_SUSPEND_INPUT,    GLS_ABORT, GLSA_TERM,           ENOTTY},
#else
  {SIGHUP,    GLS_SUSPEND_INPUT,    GLS_ABORT, GLSA_TERM,           EINTR},
#endif
#endif
  {SIGINT,    GLS_SUSPEND_INPUT,    GLS_ABORT, GLSA_TERM,           EINTR},
#if defined(SIGPIPE)
#ifdef EPIPE
  {SIGPIPE,   GLS_SUSPEND_INPUT,    GLS_ABORT, GLSA_TERM,           EPIPE},
#else
  {SIGPIPE,   GLS_SUSPEND_INPUT,    GLS_ABORT, GLSA_TERM,           EINTR},
#endif
#endif
#ifdef SIGPOLL
  {SIGPOLL,   GLS_SUSPEND_INPUT,    GLS_ABORT, GLSA_TERM,           EINTR},
#endif
#ifdef SIGPWR
  {SIGPWR,    GLS_RESTORE_ENV,   GLS_CONTINUE, GLSA_IGN,            0},
#endif
#ifdef SIGQUIT
  {SIGQUIT,   GLS_SUSPEND_INPUT,    GLS_ABORT, GLSA_TERM|GLSA_CORE, EINTR},
#endif
  {SIGTERM,   GLS_SUSPEND_INPUT,    GLS_ABORT, GLSA_TERM,           EINTR},
#ifdef SIGTSTP
  {SIGTSTP,   GLS_SUSPEND_INPUT, GLS_CONTINUE, GLSA_SUSP,           0},
#endif
#ifdef SIGTTIN
  {SIGTTIN,   GLS_SUSPEND_INPUT, GLS_CONTINUE, GLSA_SUSP,           0},
#endif
#ifdef SIGTTOU
  {SIGTTOU,   GLS_SUSPEND_INPUT, GLS_CONTINUE, GLSA_SUSP,           0},
#endif
#ifdef SIGUSR1
  {SIGUSR1,   GLS_RESTORE_ENV,   GLS_CONTINUE, GLSA_TERM,           0},
#endif
#ifdef SIGUSR2
  {SIGUSR2,   GLS_RESTORE_ENV,   GLS_CONTINUE, GLSA_TERM,           0},
#endif
#ifdef SIGVTALRM
  {SIGVTALRM, GLS_RESTORE_ENV,   GLS_CONTINUE, GLSA_TERM,           0},
#endif
#ifdef SIGWINCH
  {SIGWINCH,  GLS_RESTORE_ENV,   GLS_CONTINUE, GLSA_SIZE|GLSA_IGN,  0},
#endif
#ifdef SIGXCPU
  {SIGXCPU,   GLS_RESTORE_ENV,   GLS_CONTINUE, GLSA_TERM|GLSA_CORE, 0},
#endif
#ifdef SIGXFSZ
  {SIGXFSZ,   GLS_RESTORE_ENV,   GLS_CONTINUE, GLSA_TERM|GLSA_CORE, 0},
#endif
};

/*
 * Define file-scope variables for use in signal handlers.
 */
static volatile sig_atomic_t gl_pending_signal = -1;
static sigjmp_buf gl_setjmp_buffer;

static void gl_signal_handler(int signo);

static int gl_check_caught_signal(GetLine *gl);

/*
 * Respond to an externally caught process suspension or
 * termination signal.
 */
static void gl_suspend_process(int signo, GetLine *gl, int ngl);

/* Return the default attributes of a given signal */

static int gl_classify_signal(int signo);

/*
 * Unfortunately both terminfo and termcap require one to use the tputs()
 * function to output terminal control characters, and this function
 * doesn't allow one to specify a file stream. As a result, the following
 * file-scope variable is used to pass the current output file stream.
 * This is bad, but there doesn't seem to be any alternative.
 */
static GetLine *tputs_gl = NULL;

/*
 * Define a tab to be a string of 8 spaces.
 */
#define TAB_WIDTH 8

/*
 * Lookup the current size of the terminal.
 */
static void gl_query_size(GetLine *gl, int *ncolumn, int *nline);

/*
 * Getline calls this to temporarily override certain signal handlers
 * of the calling program.
 */
static int gl_override_signal_handlers(GetLine *gl);

/*
 * Getline calls this to restore the signal handlers of the calling
 * program.
 */
static int gl_restore_signal_handlers(GetLine *gl);

/*
 * Temporarily block the delivery of all signals that gl_get_line()
 * is currently configured to trap.
 */
static int gl_mask_signals(GetLine *gl, sigset_t *oldset);

/*
 * Restore the process signal mask that was overriden by a previous
 * call to gl_mask_signals().
 */
static int gl_unmask_signals(GetLine *gl, sigset_t *oldset);

/*
 * Unblock the signals that gl_get_line() has been configured to catch.
 */
static int gl_catch_signals(GetLine *gl);

/*
 * Return the set of all trappable signals.
 */
static void gl_list_trappable_signals(sigset_t *signals);

/*
 * Put the terminal into raw input mode, after saving the original
 * terminal attributes in gl->oldattr.
 */
static int gl_raw_terminal_mode(GetLine *gl);

/*
 * Restore the terminal attributes from gl->oldattr.
 */
static int gl_restore_terminal_attributes(GetLine *gl);

/*
 * Switch to non-blocking I/O if possible.
 */
static int gl_nonblocking_io(GetLine *gl, int fd);

/*
 * Switch to blocking I/O if possible.
 */
static int gl_blocking_io(GetLine *gl, int fd);

/*
 * Read a line from the user in raw mode.
 */
static int gl_get_input_line(GetLine *gl, const char *prompt,
			     const char *start_line, int start_pos);

/*
 * Query the user for a single character.
 */
static int gl_get_query_char(GetLine *gl, const char *prompt, int defchar);

/*
 * Read input from a non-interactive input stream.
 */
static int gl_read_stream_line(GetLine *gl);

/*
 * Read a single character from a non-interactive input stream.
 */
static int gl_read_stream_char(GetLine *gl);

/*
 * Prepare to edit a new line.
 */
static int gl_present_line(GetLine *gl, const char *prompt,
			   const char *start_line, int start_pos);

/*
 * Reset all line input parameters for a new input line.
 */
static void gl_reset_input_line(GetLine *gl);

/*
 * Handle the receipt of the potential start of a new key-sequence from
 * the user.
 */
static int gl_interpret_char(GetLine *gl, char c);

/*
 * Bind a single control or meta character to an action.
 */
static int gl_bind_control_char(GetLine *gl, KtBinder binder,
				char c, const char *action);

/*
 * Set up terminal-specific key bindings.
 */
static int gl_bind_terminal_keys(GetLine *gl);

/*
 * Lookup terminal control string and size information.
 */
static int gl_control_strings(GetLine *gl, const char *term);

/*
 * Wrappers around the terminfo and termcap functions that lookup
 * strings in the terminal information databases.
 */
#ifdef USE_TERMINFO
static const char *gl_tigetstr(GetLine *gl, const char *name);
#elif defined(USE_TERMCAP)
static const char *gl_tgetstr(GetLine *gl, const char *name, char **bufptr);
#endif

/*
 * Output a binary string directly to the terminal.
 */
static int gl_print_raw_string(GetLine *gl, int buffered,
			       const char *string, int n);

/*
 * Print an informational message, starting and finishing on new lines.
 * After the list of strings to be printed, the last argument MUST be
 * GL_END_INFO.
 */
static int gl_print_info(GetLine *gl, ...);
#define GL_END_INFO ((const char *)0)

/*
 * Start a newline and place the cursor at its start.
 */
static int gl_start_newline(GetLine *gl, int buffered);

/*
 * Output a terminal control sequence.
 */
static int gl_print_control_sequence(GetLine *gl, int nline,
				     const char *string);

/*
 * Output a character or string to the terminal after converting tabs
 * to spaces and control characters to a caret followed by the modified
 * character.
 */
static int gl_print_char(GetLine *gl, char c, char pad);
static int gl_print_string(GetLine *gl, const char *string, char pad);

/*
 * Delete nc characters starting from the one under the cursor.
 * Optionally copy the deleted characters to the cut buffer.
 */
static int gl_delete_chars(GetLine *gl, int nc, int cut);

/*
 * Add a character to the line buffer at the current cursor position,
 * inserting or overwriting according the current mode.
 */
static int gl_add_char_to_line(GetLine *gl, char c);

/*
 * Insert/append a string to the line buffer and terminal at the current
 * cursor position.
 */
static int gl_add_string_to_line(GetLine *gl, const char *s);

/*
 * Record a new character in the input-line buffer.
 */
static int gl_buffer_char(GetLine *gl, char c, int bufpos);

/*
 * Record a string in the input-line buffer.
 */
static int gl_buffer_string(GetLine *gl, const char *s, int n, int bufpos);

/*
 * Make way to insert a string in the input-line buffer.
 */
static int gl_make_gap_in_buffer(GetLine *gl, int start, int n);

/*
 * Remove characters from the input-line buffer, and move any characters
 * that followed them to the start of the vacated space.
 */
static void gl_remove_from_buffer(GetLine *gl, int start, int n);

/*
 * Terminate the input-line buffer after a specified number of characters.
 */
static int gl_truncate_buffer(GetLine *gl, int n);

/*
 * Delete the displayed part of the input line that follows the current
 * terminal cursor position.
 */
static int gl_truncate_display(GetLine *gl);

/*
 * Accomodate changes to the contents of the input line buffer
 * that weren't made by the above gl_*buffer functions.
 */
static void gl_update_buffer(GetLine *gl);

/*
 * Read a single character from the terminal.
 */
static int gl_read_terminal(GetLine *gl, int keep, char *c);

/*
 * Discard processed characters from the key-press lookahead buffer.
 */
static void gl_discard_chars(GetLine *gl, int nused);

/*
 * Move the terminal cursor n positions to the left or right.
 */
static int gl_terminal_move_cursor(GetLine *gl, int n);

/*
 * Move the terminal cursor to a given position.
 */
static int gl_set_term_curpos(GetLine *gl, int term_curpos);

/*
 * Set the position of the cursor both in the line input buffer and on the
 * terminal.
 */
static int gl_place_cursor(GetLine *gl, int buff_curpos);

/*
 * How many characters are needed to write a number as an octal string?
 */
static int gl_octal_width(unsigned num);

/*
 * Return the number of spaces needed to display a tab character at
 * a given location of the terminal.
 */
static int gl_displayed_tab_width(GetLine *gl, int term_curpos);

/*
 * Return the number of terminal characters needed to display a
 * given raw character.
 */
static int gl_displayed_char_width(GetLine *gl, char c, int term_curpos);

/*
 * Return the number of terminal characters needed to display a
 * given substring.
 */
static int gl_displayed_string_width(GetLine *gl, const char *string, int nc,
				     int term_curpos);

/*
 * Return non-zero if 'c' is to be considered part of a word.
 */
static int gl_is_word_char(int c);

/*
 * Read a tecla configuration file.
 */
static int _gl_read_config_file(GetLine *gl, const char *filename, KtBinder who);

/*
 * Read a tecla configuration string.
 */
static int _gl_read_config_string(GetLine *gl, const char *buffer, KtBinder who);

/*
 * Define the callback function used by _gl_parse_config_line() to
 * read the next character of a configuration stream.
 */
#define GLC_GETC_FN(fn) int (fn)(void *stream)
typedef GLC_GETC_FN(GlcGetcFn);

static GLC_GETC_FN(glc_file_getc);  /* Read from a file */
static GLC_GETC_FN(glc_buff_getc);  /* Read from a string */

/*
 * Parse a single configuration command line.
 */
static int _gl_parse_config_line(GetLine *gl, void *stream, GlcGetcFn *getc_fn,
				 const char *origin, KtBinder who, int *lineno);
static int gl_report_config_error(GetLine *gl, const char *origin, int lineno,
				  const char *errmsg);

/*
 * Bind the actual arrow key bindings to match those of the symbolic
 * arrow-key bindings.
 */
static int _gl_bind_arrow_keys(GetLine *gl);

/*
 * Copy the binding of the specified symbolic arrow-key binding to
 * the terminal specific, and default arrow-key key-sequences.
 */
static int _gl_rebind_arrow_key(GetLine *gl, const char *name,
				const char *term_seq,
				const char *def_seq1,
				const char *def_seq2);

/*
 * After the gl_read_from_file() action has been used to tell gl_get_line()
 * to temporarily read input from a file, gl_revert_input() arranges
 * for input to be reverted to the input stream last registered with
 * gl_change_terminal().
 */
static void gl_revert_input(GetLine *gl);

/*
 * Flush unwritten characters to the terminal.
 */
static int gl_flush_output(GetLine *gl);

/*
 * The callback through which all terminal output is routed.
 * This simply appends characters to a queue buffer, which is
 * subsequently flushed to the output channel by gl_flush_output().
 */
static GL_WRITE_FN(gl_write_fn);

/*
 * The callback function which the output character queue object
 * calls to transfer characters to the output channel.
 */
static GL_WRITE_FN(gl_flush_terminal);

/*
 * Enumerate the possible return statuses of gl_read_input().
 */
typedef enum {
  GL_READ_OK,      /* A character was read successfully */
  GL_READ_ERROR,   /* A read-error occurred */
  GL_READ_BLOCKED, /* The read would have blocked the caller */
  GL_READ_EOF      /* The end of the current input file was reached */
} GlReadStatus;

static GlReadStatus gl_read_input(GetLine *gl, char *c);
/*
 * Private functions of gl_read_input().
 */
static int gl_event_handler(GetLine *gl, int fd);
static int gl_read_unmasked(GetLine *gl, int fd, char *c);


/*
 * A private function of gl_tty_signals().
 */
static int gl_set_tty_signal(int signo, void (*handler)(int));

/*
 * Change the editor style being emulated.
 */
static int gl_change_editor(GetLine *gl, GlEditor editor);

/*
 * Searching in a given direction, return the index of a given (or
 * read) character in the input line, or the character that precedes
 * it in the specified search direction. Return -1 if not found.
 */
static int gl_find_char(GetLine *gl, int count, int forward, int onto, char c);

/*
 * Return the buffer index of the nth word ending after the cursor.
 */
static int gl_nth_word_end_forward(GetLine *gl, int n);

/*
 * Return the buffer index of the nth word start after the cursor.
 */
static int gl_nth_word_start_forward(GetLine *gl, int n);

/*
 * Return the buffer index of the nth word start before the cursor.
 */
static int gl_nth_word_start_backward(GetLine *gl, int n);

/*
 * When called when vi command mode is enabled, this function saves the
 * current line and cursor position for potential restoration later
 * by the vi undo command.
 */
static void gl_save_for_undo(GetLine *gl);

/*
 * If in vi mode, switch to vi command mode.
 */
static void gl_vi_command_mode(GetLine *gl);

/*
 * In vi mode this is used to delete up to or onto a given or read
 * character in the input line. Also switch to insert mode if requested
 * after the deletion.
 */
static int gl_delete_find(GetLine *gl, int count, char c, int forward,
			  int onto, int change);

/*
 * Copy the characters between the cursor and the count'th instance of
 * a specified (or read) character in the input line, into the cut buffer.
 */
static int gl_copy_find(GetLine *gl, int count, char c, int forward, int onto);

/*
 * Return the line index of the parenthesis that either matches the one under
 * the cursor, or not over a parenthesis character, the index of the next
 * close parenthesis. Return -1 if not found.
 */
static int gl_index_of_matching_paren(GetLine *gl);

/*
 * Replace a malloc'd string (or NULL), with another malloc'd copy of
 * a string (or NULL).
 */
static int gl_record_string(char **sptr, const char *string);

/*
 * Enumerate text display attributes as powers of two, suitable for
 * use in a bit-mask.
 */
typedef enum {
  GL_TXT_STANDOUT=1,   /* Display text highlighted */
  GL_TXT_UNDERLINE=2,  /* Display text underlined */
  GL_TXT_REVERSE=4,    /* Display text with reverse video */
  GL_TXT_BLINK=8,      /* Display blinking text */
  GL_TXT_DIM=16,       /* Display text in a dim font */
  GL_TXT_BOLD=32       /* Display text using a bold font */
} GlTextAttr;

/*
 * Display the prompt regardless of the current visibility mode.
 */
static int gl_display_prompt(GetLine *gl);

/*
 * Return the number of characters used by the prompt on the terminal.
 */
static int gl_displayed_prompt_width(GetLine *gl);

/*
 * Prepare to return the current input line to the caller of gl_get_line().
 */
static int gl_line_ended(GetLine *gl, int newline_char);

/*
 * Arrange for the input line to be redisplayed when the current contents
 * of the output queue have been flushed.
 */
static void gl_queue_redisplay(GetLine *gl);

/*
 * Erase the displayed representation of the input line, without
 * touching the buffered copy.
 */
static int gl_erase_line(GetLine *gl);

/*
 * This function is called whenever the input line has been erased.
 */
static void gl_line_erased(GetLine *gl);

/*
 * Arrange for the current input line to be discarded.
 */
void _gl_abandon_line(GetLine *gl);

/*
 * The following are private internally callable versions of pertinent
 * public functions. Unlike their public wrapper functions, they don't
 * block signals while running, and assume that their arguments are valid.
 * They are designed to be called from places where signals are already
 * blocked, and where simple sanity checks have already been applied to
 * their arguments.
 */
static char *_gl_get_line(GetLine *gl, const char *prompt,
			  const char *start_line, int start_pos);
static int _gl_query_char(GetLine *gl, const char *prompt, char defchar);
static int _gl_read_char(GetLine *gl);
static int _gl_update_size(GetLine *gl);
/*
 * Redraw the current input line to account for a change in the terminal
 * size. Also install the new size in gl.
 */
static int gl_handle_tty_resize(GetLine *gl, int ncolumn, int nline);

static int _gl_change_terminal(GetLine *gl, FILE *input_fp, FILE *output_fp,
			       const char *term);
static int _gl_configure_getline(GetLine *gl, const char *app_string,
				 const char *app_file, const char *user_file);
static int _gl_save_history(GetLine *gl, const char *filename,
			    const char *comment, int max_lines);
static int _gl_load_history(GetLine *gl, const char *filename,
			    const char *comment);
static int _gl_watch_fd(GetLine *gl, int fd, GlFdEvent event,
			GlFdEventFn *callback, void *data);
static void _gl_terminal_size(GetLine *gl, int def_ncolumn, int def_nline,
			      GlTerminalSize *size);
static void _gl_replace_prompt(GetLine *gl, const char *prompt);
static int _gl_trap_signal(GetLine *gl, int signo, unsigned flags,
			   GlAfterSignal after, int errno_value);
static int _gl_raw_io(GetLine *gl, int redisplay);
static int _gl_normal_io(GetLine *gl);
static int _gl_completion_action(GetLine *gl, void *data, CplMatchFn *match_fn,
				 int list_only, const char *name,
				 const char *keyseq);
static int _gl_register_action(GetLine *gl, void *data, GlActionFn *fn,
			       const char *name, const char *keyseq);
static int _gl_io_mode(GetLine *gl, GlIOMode mode);
static int _gl_set_term_size(GetLine *gl, int ncolumn, int nline);
static int _gl_append_history(GetLine *gl, const char *line);

/*
 * Reset the completion status and associated errno value in
 * gl->rtn_status and gl->rtn_errno.
 */
static void gl_clear_status(GetLine *gl);

/*
 * Record a completion status, unless a previous abnormal completion
 * status has already been recorded for the current call.
 */
static void gl_record_status(GetLine *gl, GlReturnStatus rtn_status,
			     int rtn_errno);

/*
 * Set the maximum length of a line in a user's tecla configuration
 * file (not counting comments).
 */
#define GL_CONF_BUFLEN 100

/*
 * Set the maximum number of arguments supported by individual commands
 * in tecla configuration files.
 */
#define GL_CONF_MAXARG 10

/*
 * Prototype the available action functions.
 */
static KT_KEY_FN(gl_user_interrupt);
static KT_KEY_FN(gl_abort);
static KT_KEY_FN(gl_suspend);
static KT_KEY_FN(gl_stop_output);
static KT_KEY_FN(gl_start_output);
static KT_KEY_FN(gl_literal_next);
static KT_KEY_FN(gl_cursor_left);
static KT_KEY_FN(gl_cursor_right);
static KT_KEY_FN(gl_insert_mode);
static KT_KEY_FN(gl_beginning_of_line);
static KT_KEY_FN(gl_end_of_line);
static KT_KEY_FN(gl_delete_line);
static KT_KEY_FN(gl_kill_line);
static KT_KEY_FN(gl_forward_word);
static KT_KEY_FN(gl_backward_word);
static KT_KEY_FN(gl_forward_delete_char);
static KT_KEY_FN(gl_backward_delete_char);
static KT_KEY_FN(gl_forward_delete_word);
static KT_KEY_FN(gl_backward_delete_word);
static KT_KEY_FN(gl_delete_refind);
static KT_KEY_FN(gl_delete_invert_refind);
static KT_KEY_FN(gl_delete_to_column);
static KT_KEY_FN(gl_delete_to_parenthesis);
static KT_KEY_FN(gl_forward_delete_find);
static KT_KEY_FN(gl_backward_delete_find);
static KT_KEY_FN(gl_forward_delete_to);
static KT_KEY_FN(gl_backward_delete_to);
static KT_KEY_FN(gl_upcase_word);
static KT_KEY_FN(gl_downcase_word);
static KT_KEY_FN(gl_capitalize_word);
static KT_KEY_FN(gl_redisplay);
static KT_KEY_FN(gl_clear_screen);
static KT_KEY_FN(gl_transpose_chars);
static KT_KEY_FN(gl_set_mark);
static KT_KEY_FN(gl_exchange_point_and_mark);
static KT_KEY_FN(gl_kill_region);
static KT_KEY_FN(gl_copy_region_as_kill);
static KT_KEY_FN(gl_yank);
static KT_KEY_FN(gl_up_history);
static KT_KEY_FN(gl_down_history);
static KT_KEY_FN(gl_history_search_backward);
static KT_KEY_FN(gl_history_re_search_backward);
static KT_KEY_FN(gl_history_search_forward);
static KT_KEY_FN(gl_history_re_search_forward);
static KT_KEY_FN(gl_complete_word);
#ifndef HIDE_FILE_SYSTEM
static KT_KEY_FN(gl_expand_filename);
static KT_KEY_FN(gl_read_from_file);
static KT_KEY_FN(gl_read_init_files);
static KT_KEY_FN(gl_list_glob);
#endif
static KT_KEY_FN(gl_del_char_or_list_or_eof);
static KT_KEY_FN(gl_list_or_eof);
static KT_KEY_FN(gl_beginning_of_history);
static KT_KEY_FN(gl_end_of_history);
static KT_KEY_FN(gl_digit_argument);
static KT_KEY_FN(gl_newline);
static KT_KEY_FN(gl_repeat_history);
static KT_KEY_FN(gl_vi_insert);
static KT_KEY_FN(gl_vi_overwrite);
static KT_KEY_FN(gl_change_case);
static KT_KEY_FN(gl_vi_insert_at_bol);
static KT_KEY_FN(gl_vi_append_at_eol);
static KT_KEY_FN(gl_vi_append);
static KT_KEY_FN(gl_backward_kill_line);
static KT_KEY_FN(gl_goto_column);
static KT_KEY_FN(gl_forward_to_word);
static KT_KEY_FN(gl_vi_replace_char);
static KT_KEY_FN(gl_vi_change_rest_of_line);
static KT_KEY_FN(gl_vi_change_line);
static KT_KEY_FN(gl_vi_change_to_bol);
static KT_KEY_FN(gl_vi_change_refind);
static KT_KEY_FN(gl_vi_change_invert_refind);
static KT_KEY_FN(gl_vi_change_to_column);
static KT_KEY_FN(gl_vi_change_to_parenthesis);
static KT_KEY_FN(gl_vi_forward_change_word);
static KT_KEY_FN(gl_vi_backward_change_word);
static KT_KEY_FN(gl_vi_forward_change_find);
static KT_KEY_FN(gl_vi_backward_change_find);
static KT_KEY_FN(gl_vi_forward_change_to);
static KT_KEY_FN(gl_vi_backward_change_to);
static KT_KEY_FN(gl_vi_forward_change_char);
static KT_KEY_FN(gl_vi_backward_change_char);
static KT_KEY_FN(gl_forward_copy_char);
static KT_KEY_FN(gl_backward_copy_char);
static KT_KEY_FN(gl_forward_find_char);
static KT_KEY_FN(gl_backward_find_char);
static KT_KEY_FN(gl_forward_to_char);
static KT_KEY_FN(gl_backward_to_char);
static KT_KEY_FN(gl_repeat_find_char);
static KT_KEY_FN(gl_invert_refind_char);
static KT_KEY_FN(gl_append_yank);
static KT_KEY_FN(gl_backward_copy_word);
static KT_KEY_FN(gl_forward_copy_word);
static KT_KEY_FN(gl_copy_to_bol);
static KT_KEY_FN(gl_copy_refind);
static KT_KEY_FN(gl_copy_invert_refind);
static KT_KEY_FN(gl_copy_to_column);
static KT_KEY_FN(gl_copy_to_parenthesis);
static KT_KEY_FN(gl_copy_rest_of_line);
static KT_KEY_FN(gl_copy_line);
static KT_KEY_FN(gl_backward_copy_find);
static KT_KEY_FN(gl_forward_copy_find);
static KT_KEY_FN(gl_backward_copy_to);
static KT_KEY_FN(gl_forward_copy_to);
static KT_KEY_FN(gl_vi_undo);
static KT_KEY_FN(gl_emacs_editing_mode);
static KT_KEY_FN(gl_vi_editing_mode);
static KT_KEY_FN(gl_ring_bell);
static KT_KEY_FN(gl_vi_repeat_change);
static KT_KEY_FN(gl_find_parenthesis);
static KT_KEY_FN(gl_list_history);
static KT_KEY_FN(gl_list_completions);
static KT_KEY_FN(gl_run_external_action);

/*
 * Name the available action functions.
 */
static const struct {const char *name; KT_KEY_FN(*fn);} gl_actions[] = {
  {"user-interrupt",             gl_user_interrupt},
  {"abort",                      gl_abort},
  {"suspend",                    gl_suspend},
  {"stop-output",                gl_stop_output},
  {"start-output",               gl_start_output},
  {"literal-next",               gl_literal_next},
  {"cursor-right",               gl_cursor_right},
  {"cursor-left",                gl_cursor_left},
  {"insert-mode",                gl_insert_mode},
  {"beginning-of-line",          gl_beginning_of_line},
  {"end-of-line",                gl_end_of_line},
  {"delete-line",                gl_delete_line},
  {"kill-line",                  gl_kill_line},
  {"forward-word",               gl_forward_word},
  {"backward-word",              gl_backward_word},
  {"forward-delete-char",        gl_forward_delete_char},
  {"backward-delete-char",       gl_backward_delete_char},
  {"forward-delete-word",        gl_forward_delete_word},
  {"backward-delete-word",       gl_backward_delete_word},
  {"delete-refind",              gl_delete_refind},
  {"delete-invert-refind",       gl_delete_invert_refind},
  {"delete-to-column",           gl_delete_to_column},
  {"delete-to-parenthesis",      gl_delete_to_parenthesis},
  {"forward-delete-find",        gl_forward_delete_find},
  {"backward-delete-find",       gl_backward_delete_find},
  {"forward-delete-to",          gl_forward_delete_to},
  {"backward-delete-to",         gl_backward_delete_to},
  {"upcase-word",                gl_upcase_word},
  {"downcase-word",              gl_downcase_word},
  {"capitalize-word",            gl_capitalize_word},
  {"redisplay",                  gl_redisplay},
  {"clear-screen",               gl_clear_screen},
  {"transpose-chars",            gl_transpose_chars},
  {"set-mark",                   gl_set_mark},
  {"exchange-point-and-mark",    gl_exchange_point_and_mark},
  {"kill-region",                gl_kill_region},
  {"copy-region-as-kill",        gl_copy_region_as_kill},
  {"yank",                       gl_yank},
  {"up-history",                 gl_up_history},
  {"down-history",               gl_down_history},
  {"history-search-backward",    gl_history_search_backward},
  {"history-re-search-backward", gl_history_re_search_backward},
  {"history-search-forward",     gl_history_search_forward},
  {"history-re-search-forward",  gl_history_re_search_forward},
  {"complete-word",              gl_complete_word},
#ifndef HIDE_FILE_SYSTEM
  {"expand-filename",            gl_expand_filename},
  {"read-from-file",             gl_read_from_file},
  {"read-init-files",            gl_read_init_files},
  {"list-glob",                  gl_list_glob},
#endif
  {"del-char-or-list-or-eof",    gl_del_char_or_list_or_eof},
  {"beginning-of-history",       gl_beginning_of_history},
  {"end-of-history",             gl_end_of_history},
  {"digit-argument",             gl_digit_argument},
  {"newline",                    gl_newline},
  {"repeat-history",             gl_repeat_history},
  {"vi-insert",                  gl_vi_insert},
  {"vi-overwrite",               gl_vi_overwrite},
  {"vi-insert-at-bol",           gl_vi_insert_at_bol},
  {"vi-append-at-eol",           gl_vi_append_at_eol},
  {"vi-append",                  gl_vi_append},
  {"change-case",                gl_change_case},
  {"backward-kill-line",         gl_backward_kill_line},
  {"goto-column",                gl_goto_column},
  {"forward-to-word",            gl_forward_to_word},
  {"vi-replace-char",            gl_vi_replace_char},
  {"vi-change-rest-of-line",     gl_vi_change_rest_of_line},
  {"vi-change-line",             gl_vi_change_line},
  {"vi-change-to-bol",           gl_vi_change_to_bol},
  {"vi-change-refind",           gl_vi_change_refind},
  {"vi-change-invert-refind",    gl_vi_change_invert_refind},
  {"vi-change-to-column",        gl_vi_change_to_column},
  {"vi-change-to-parenthesis",   gl_vi_change_to_parenthesis},
  {"forward-copy-char",          gl_forward_copy_char},
  {"backward-copy-char",         gl_backward_copy_char},
  {"forward-find-char",          gl_forward_find_char},
  {"backward-find-char",         gl_backward_find_char},
  {"forward-to-char",            gl_forward_to_char},
  {"backward-to-char",           gl_backward_to_char},
  {"repeat-find-char",           gl_repeat_find_char},
  {"invert-refind-char",         gl_invert_refind_char},
  {"append-yank",                gl_append_yank},
  {"backward-copy-word",         gl_backward_copy_word},
  {"forward-copy-word",          gl_forward_copy_word},
  {"copy-to-bol",                gl_copy_to_bol},
  {"copy-refind",                gl_copy_refind},
  {"copy-invert-refind",         gl_copy_invert_refind},
  {"copy-to-column",             gl_copy_to_column},
  {"copy-to-parenthesis",        gl_copy_to_parenthesis},
  {"copy-rest-of-line",          gl_copy_rest_of_line},
  {"copy-line",                  gl_copy_line},
  {"backward-copy-find",         gl_backward_copy_find},
  {"forward-copy-find",          gl_forward_copy_find},
  {"backward-copy-to",           gl_backward_copy_to},
  {"forward-copy-to",            gl_forward_copy_to},
  {"list-or-eof",                gl_list_or_eof},
  {"vi-undo",                    gl_vi_undo},
  {"vi-backward-change-word",    gl_vi_backward_change_word},
  {"vi-forward-change-word",     gl_vi_forward_change_word},
  {"vi-backward-change-find",    gl_vi_backward_change_find},
  {"vi-forward-change-find",     gl_vi_forward_change_find},
  {"vi-backward-change-to",      gl_vi_backward_change_to},
  {"vi-forward-change-to",       gl_vi_forward_change_to},
  {"vi-backward-change-char",    gl_vi_backward_change_char},
  {"vi-forward-change-char",     gl_vi_forward_change_char},
  {"emacs-mode",                 gl_emacs_editing_mode},
  {"vi-mode",                    gl_vi_editing_mode},
  {"ring-bell",                  gl_ring_bell},
  {"vi-repeat-change",           gl_vi_repeat_change},
  {"find-parenthesis",           gl_find_parenthesis},
  {"list-history",               gl_list_history},
};

/*
 * Define the default key-bindings in emacs mode.
 */
static const KtKeyBinding gl_emacs_bindings[] = {
  {"right",        "cursor-right"},
  {"^F",           "cursor-right"},
  {"left",         "cursor-left"},
  {"^B",           "cursor-left"},
  {"M-i",          "insert-mode"},
  {"M-I",          "insert-mode"},
  {"^A",           "beginning-of-line"},
  {"^E",           "end-of-line"},
  {"^U",           "delete-line"},
  {"^K",           "kill-line"},
  {"M-f",          "forward-word"},
  {"M-F",          "forward-word"},
  {"M-b",          "backward-word"},
  {"M-B",          "backward-word"},
  {"^D",           "del-char-or-list-or-eof"},
  {"^H",           "backward-delete-char"},
  {"^?",           "backward-delete-char"},
  {"M-d",          "forward-delete-word"},
  {"M-D",          "forward-delete-word"},
  {"M-^H",         "backward-delete-word"},
  {"M-^?",         "backward-delete-word"},
  {"M-u",          "upcase-word"},
  {"M-U",          "upcase-word"},
  {"M-l",          "downcase-word"},
  {"M-L",          "downcase-word"},
  {"M-c",          "capitalize-word"},
  {"M-C",          "capitalize-word"},
  {"^R",           "redisplay"},
  {"^L",           "clear-screen"},
  {"^T",           "transpose-chars"},
  {"^@",           "set-mark"},
  {"^X^X",         "exchange-point-and-mark"},
  {"^W",           "kill-region"},
  {"M-w",          "copy-region-as-kill"},
  {"M-W",          "copy-region-as-kill"},
  {"^Y",           "yank"},
  {"^P",           "up-history"},
  {"up",           "up-history"},
  {"^N",           "down-history"},
  {"down",         "down-history"},
  {"M-p",          "history-search-backward"},
  {"M-P",          "history-search-backward"},
  {"M-n",          "history-search-forward"},
  {"M-N",          "history-search-forward"},
  {"\t",           "complete-word"},
#ifndef HIDE_FILE_SYSTEM
  {"^X*",          "expand-filename"},
  {"^X^F",         "read-from-file"},
  {"^X^R",         "read-init-files"},
  {"^Xg",          "list-glob"},
  {"^XG",          "list-glob"},
#endif
  {"^Xh",          "list-history"},
  {"^XH",          "list-history"},
  {"M-<",          "beginning-of-history"},
  {"M->",          "end-of-history"},
  {"M-0",          "digit-argument"},
  {"M-1",          "digit-argument"},
  {"M-2",          "digit-argument"},
  {"M-3",          "digit-argument"},
  {"M-4",          "digit-argument"},
  {"M-5",          "digit-argument"},
  {"M-6",          "digit-argument"},
  {"M-7",          "digit-argument"},
  {"M-8",          "digit-argument"},
  {"M-9",          "digit-argument"},
  {"\r",           "newline"},
  {"\n",           "newline"},
  {"M-o",          "repeat-history"},
  {"M-C-v",        "vi-mode"},
};

/*
 * Define the default key-bindings in vi mode. Note that in vi-mode
 * meta-key bindings are command-mode bindings. For example M-i first
 * switches to command mode if not already in that mode, then moves
 * the cursor one position right, as in vi.
 */
static const KtKeyBinding gl_vi_bindings[] = {
  {"^D",           "list-or-eof"},
#ifndef HIDE_FILE_SYSTEM
  {"^G",           "list-glob"},
#endif
  {"^H",           "backward-delete-char"},
  {"\t",           "complete-word"},
  {"\r",           "newline"},
  {"\n",           "newline"},
  {"^L",           "clear-screen"},
  {"^N",           "down-history"},
  {"^P",           "up-history"},
  {"^R",           "redisplay"},
  {"^U",           "backward-kill-line"},
  {"^W",           "backward-delete-word"},
#ifndef HIDE_FILE_SYSTEM
  {"^X^F",         "read-from-file"},
  {"^X^R",         "read-init-files"},
  {"^X*",          "expand-filename"},
#endif
  {"^?",           "backward-delete-char"},
  {"M- ",          "cursor-right"},
  {"M-$",          "end-of-line"},
#ifndef HIDE_FILE_SYSTEM
  {"M-*",          "expand-filename"},
#endif
  {"M-+",          "down-history"},
  {"M--",          "up-history"},
  {"M-<",          "beginning-of-history"},
  {"M->",          "end-of-history"},
  {"M-^",          "beginning-of-line"},
  {"M-;",          "repeat-find-char"},
  {"M-,",          "invert-refind-char"},
  {"M-|",          "goto-column"},
  {"M-~",          "change-case"},
  {"M-.",          "vi-repeat-change"},
  {"M-%",          "find-parenthesis"},
  {"M-0",          "digit-argument"},
  {"M-1",          "digit-argument"},
  {"M-2",          "digit-argument"},
  {"M-3",          "digit-argument"},
  {"M-4",          "digit-argument"},
  {"M-5",          "digit-argument"},
  {"M-6",          "digit-argument"},
  {"M-7",          "digit-argument"},
  {"M-8",          "digit-argument"},
  {"M-9",          "digit-argument"},
  {"M-a",          "vi-append"},
  {"M-A",          "vi-append-at-eol"},
  {"M-b",          "backward-word"},
  {"M-B",          "backward-word"},
  {"M-C",          "vi-change-rest-of-line"},
  {"M-cb",         "vi-backward-change-word"},
  {"M-cB",         "vi-backward-change-word"},
  {"M-cc",         "vi-change-line"},
  {"M-ce",         "vi-forward-change-word"},
  {"M-cE",         "vi-forward-change-word"},
  {"M-cw",         "vi-forward-change-word"},
  {"M-cW",         "vi-forward-change-word"},
  {"M-cF",         "vi-backward-change-find"},
  {"M-cf",         "vi-forward-change-find"},
  {"M-cT",         "vi-backward-change-to"},
  {"M-ct",         "vi-forward-change-to"},
  {"M-c;",         "vi-change-refind"},
  {"M-c,",         "vi-change-invert-refind"},
  {"M-ch",         "vi-backward-change-char"},
  {"M-c^H",        "vi-backward-change-char"},
  {"M-c^?",        "vi-backward-change-char"},
  {"M-cl",         "vi-forward-change-char"},
  {"M-c ",         "vi-forward-change-char"},
  {"M-c^",         "vi-change-to-bol"},
  {"M-c0",         "vi-change-to-bol"},
  {"M-c$",         "vi-change-rest-of-line"},
  {"M-c|",         "vi-change-to-column"},
  {"M-c%",         "vi-change-to-parenthesis"},
  {"M-dh",         "backward-delete-char"},
  {"M-d^H",        "backward-delete-char"},
  {"M-d^?",        "backward-delete-char"},
  {"M-dl",         "forward-delete-char"},
  {"M-d ",         "forward-delete-char"},
  {"M-dd",         "delete-line"},
  {"M-db",         "backward-delete-word"},
  {"M-dB",         "backward-delete-word"},
  {"M-de",         "forward-delete-word"},
  {"M-dE",         "forward-delete-word"},
  {"M-dw",         "forward-delete-word"},
  {"M-dW",         "forward-delete-word"},
  {"M-dF",         "backward-delete-find"},
  {"M-df",         "forward-delete-find"},
  {"M-dT",         "backward-delete-to"},
  {"M-dt",         "forward-delete-to"},
  {"M-d;",         "delete-refind"},
  {"M-d,",         "delete-invert-refind"},
  {"M-d^",         "backward-kill-line"},
  {"M-d0",         "backward-kill-line"},
  {"M-d$",         "kill-line"},
  {"M-D",          "kill-line"},
  {"M-d|",         "delete-to-column"},
  {"M-d%",         "delete-to-parenthesis"},
  {"M-e",          "forward-word"},
  {"M-E",          "forward-word"},
  {"M-f",          "forward-find-char"},
  {"M-F",          "backward-find-char"},
  {"M--",          "up-history"},
  {"M-h",          "cursor-left"},
  {"M-H",          "beginning-of-history"},
  {"M-i",          "vi-insert"},
  {"M-I",          "vi-insert-at-bol"},
  {"M-j",          "down-history"},
  {"M-J",          "history-search-forward"},
  {"M-k",          "up-history"},
  {"M-K",          "history-search-backward"},
  {"M-l",          "cursor-right"},
  {"M-L",          "end-of-history"},
  {"M-n",          "history-re-search-forward"},
  {"M-N",          "history-re-search-backward"},
  {"M-p",          "append-yank"},
  {"M-P",          "yank"},
  {"M-r",          "vi-replace-char"},
  {"M-R",          "vi-overwrite"},
  {"M-s",          "vi-forward-change-char"},
  {"M-S",          "vi-change-line"},
  {"M-t",          "forward-to-char"},
  {"M-T",          "backward-to-char"},
  {"M-u",          "vi-undo"},
  {"M-w",          "forward-to-word"},
  {"M-W",          "forward-to-word"},
  {"M-x",          "forward-delete-char"},
  {"M-X",          "backward-delete-char"},
  {"M-yh",         "backward-copy-char"},
  {"M-y^H",        "backward-copy-char"},
  {"M-y^?",        "backward-copy-char"},
  {"M-yl",         "forward-copy-char"},
  {"M-y ",         "forward-copy-char"},
  {"M-ye",         "forward-copy-word"},
  {"M-yE",         "forward-copy-word"},
  {"M-yw",         "forward-copy-word"},
  {"M-yW",         "forward-copy-word"},
  {"M-yb",         "backward-copy-word"},
  {"M-yB",         "backward-copy-word"},
  {"M-yf",         "forward-copy-find"},
  {"M-yF",         "backward-copy-find"},
  {"M-yt",         "forward-copy-to"},
  {"M-yT",         "backward-copy-to"},
  {"M-y;",         "copy-refind"},
  {"M-y,",         "copy-invert-refind"},
  {"M-y^",         "copy-to-bol"},
  {"M-y0",         "copy-to-bol"},
  {"M-y$",         "copy-rest-of-line"},
  {"M-yy",         "copy-line"},
  {"M-Y",          "copy-line"},
  {"M-y|",         "copy-to-column"},
  {"M-y%",         "copy-to-parenthesis"},
  {"M-^E",         "emacs-mode"},
  {"M-^H",         "cursor-left"},
  {"M-^?",         "cursor-left"},
  {"M-^L",         "clear-screen"},
  {"M-^N",         "down-history"},
  {"M-^P",         "up-history"},
  {"M-^R",         "redisplay"},
  {"M-^D",         "list-or-eof"},
  {"M-\r",         "newline"},
  {"M-\t",         "complete-word"},
  {"M-\n",         "newline"},
#ifndef HIDE_FILE_SYSTEM
  {"M-^X^R",       "read-init-files"},
#endif
  {"M-^Xh",        "list-history"},
  {"M-^XH",        "list-history"},
  {"down",         "down-history"},
  {"up",           "up-history"},
  {"left",         "cursor-left"},
  {"right",        "cursor-right"},
};

/*.......................................................................
 * Create a new GetLine object.
 *
 * Input:
 *  linelen  size_t    The maximum line length to allow for.
 *  histlen  size_t    The number of bytes to allocate for recording
 *                     a circular buffer of history lines.
 * Output:
 *  return  GetLine *  The new object, or NULL on error.
 */
GetLine *new_GetLine(size_t linelen, size_t histlen)
{
  GetLine *gl;  /* The object to be returned */
  int i;
/*
 * Check the arguments.
 */
  if(linelen < 10) {
    errno = ENOMEM;
    return NULL;
  };
/*
 * Allocate the container.
 */
  gl = (GetLine *) malloc(sizeof(GetLine));
  if(!gl) {
    errno = ENOMEM;
    return NULL;
  };
/*
 * Before attempting any operation that might fail, initialize the
 * container at least up to the point at which it can safely be passed
 * to del_GetLine().
 */
  gl->err = NULL;
  gl->glh = NULL;
  gl->cpl = NULL;
#ifndef HIDE_FILE_SYSTEM
  gl->cplfn.fn = cpl_file_completions;
#else
  gl->cplfn.fn = gl_no_completions;
#endif
  gl->cplfn.data = NULL;
#ifndef WITHOUT_FILE_SYSTEM
  gl->ef = NULL;
#endif
  gl->capmem = NULL;
  gl->cq = NULL;
  gl->input_fd = -1;
  gl->output_fd = -1;
  gl->input_fp = NULL;
  gl->output_fp = NULL;
  gl->file_fp = NULL;
  gl->term = NULL;
  gl->is_term = 0;
  gl->flush_fn = gl_flush_terminal;
  gl->io_mode = GL_NORMAL_MODE;
  gl->raw_mode = 0;
  gl->pending_io = GLP_WRITE;  /* We will start by writing the prompt */
  gl_clear_status(gl);
  gl->linelen = linelen;
  gl->line = NULL;
  gl->cutbuf = NULL;
  gl->prompt = NULL;
  gl->prompt_len = 0;
  gl->prompt_changed = 0;
  gl->prompt_style = GL_LITERAL_PROMPT;
  gl->cpl_mem = NULL;
  gl->ext_act_mem = NULL;
  gl->sig_mem = NULL;
  gl->sigs = NULL;
  gl->signals_masked = 0;
  gl->signals_overriden = 0;
  sigemptyset(&gl->all_signal_set);
  sigemptyset(&gl->old_signal_set);
  sigemptyset(&gl->use_signal_set);
  gl->bindings = NULL;
  gl->ntotal = 0;
  gl->buff_curpos = 0;
  gl->term_curpos = 0;
  gl->term_len = 0;
  gl->buff_mark = 0;
  gl->insert_curpos = 0;
  gl->insert = 1;
  gl->number = -1;
  gl->endline = 1;
  gl->displayed = 0;
  gl->redisplay = 0;
  gl->postpone = 0;
  gl->keybuf[0]='\0';
  gl->nbuf = 0;
  gl->nread = 0;
  gl->current_action.fn = 0;
  gl->current_action.data = NULL;
  gl->current_count = 0;
  gl->preload_id = 0;
  gl->preload_history = 0;
  gl->keyseq_count = 0;
  gl->last_search = -1;
  gl->editor = GL_EMACS_MODE;
  gl->silence_bell = 0;
  gl->automatic_history = 1;
  gl->vi.undo.line = NULL;
  gl->vi.undo.buff_curpos = 0;
  gl->vi.undo.ntotal = 0;
  gl->vi.undo.saved = 0;
  gl->vi.repeat.action.fn = 0;
  gl->vi.repeat.action.data = 0;
  gl->vi.repeat.count = 0;
  gl->vi.repeat.input_curpos = 0;
  gl->vi.repeat.command_curpos = 0;
  gl->vi.repeat.input_char = '\0';
  gl->vi.repeat.saved = 0;
  gl->vi.repeat.active = 0;
  gl->vi.command = 0;
  gl->vi.find_forward = 0;
  gl->vi.find_onto = 0;
  gl->vi.find_char = '\0';
  gl->left = NULL;
  gl->right = NULL;
  gl->up = NULL;
  gl->down = NULL;
  gl->home = NULL;
  gl->bol = 0;
  gl->clear_eol = NULL;
  gl->clear_eod = NULL;
  gl->u_arrow = NULL;
  gl->d_arrow = NULL;
  gl->l_arrow = NULL;
  gl->r_arrow = NULL;
  gl->sound_bell = NULL;
  gl->bold = NULL;
  gl->underline = NULL;
  gl->standout = NULL;
  gl->dim = NULL;
  gl->reverse = NULL;
  gl->blink = NULL;
  gl->text_attr_off = NULL;
  gl->nline = 0;
  gl->ncolumn = 0;
#ifdef USE_TERMINFO
  gl->left_n = NULL;
  gl->right_n = NULL;
#elif defined(USE_TERMCAP)
  gl->tgetent_buf = NULL;
  gl->tgetstr_buf = NULL;
#endif
  gl->app_file = NULL;
  gl->user_file = NULL;
  gl->configured = 0;
  gl->echo = 1;
  gl->last_signal = -1;
#ifdef HAVE_SELECT
  gl->fd_node_mem = NULL;
  gl->fd_nodes = NULL;
  FD_ZERO(&gl->rfds);
  FD_ZERO(&gl->wfds);
  FD_ZERO(&gl->ufds);
  gl->max_fd = 0;
  gl->timer.dt.tv_sec = 0;
  gl->timer.dt.tv_usec = 0;
  gl->timer.fn = 0;
  gl->timer.data = NULL;
#endif
/*
 * Allocate an error reporting buffer.
 */
  gl->err = _new_ErrMsg();
  if(!gl->err)
    return del_GetLine(gl);
/*
 * Allocate the history buffer.
 */
  gl->glh = _new_GlHistory(histlen);
  if(!gl->glh)
    return del_GetLine(gl);
/*
 * Allocate the resource object for file-completion.
 */
  gl->cpl = new_WordCompletion();
  if(!gl->cpl)
    return del_GetLine(gl);
/*
 * Allocate the resource object for file-completion.
 */
#ifndef WITHOUT_FILE_SYSTEM
  gl->ef = new_ExpandFile();
  if(!gl->ef)
    return del_GetLine(gl);
#endif
/*
 * Allocate a string-segment memory allocator for use in storing terminal
 * capablity strings.
 */
  gl->capmem = _new_StringGroup(CAPMEM_SEGMENT_SIZE);
  if(!gl->capmem)
    return del_GetLine(gl);
/*
 * Allocate the character queue that is used to buffer terminal output.
 */
  gl->cq = _new_GlCharQueue();
  if(!gl->cq)
    return del_GetLine(gl);
/*
 * Allocate a line buffer, leaving 2 extra characters for the terminating
 * '\n' and '\0' characters
 */
  gl->line = (char *) malloc(linelen + 2);
  if(!gl->line) {
    errno = ENOMEM;
    return del_GetLine(gl);
  };
/*
 * Start with an empty input line.
 */
  gl_truncate_buffer(gl, 0);
/*
 * Allocate a cut buffer.
 */
  gl->cutbuf = (char *) malloc(linelen + 2);
  if(!gl->cutbuf) {
    errno = ENOMEM;
    return del_GetLine(gl);
  };
  gl->cutbuf[0] = '\0';
/*
 * Allocate an initial empty prompt.
 */
  _gl_replace_prompt(gl, NULL);
  if(!gl->prompt) {
    errno = ENOMEM;
    return del_GetLine(gl);
  };
/*
 * Allocate a vi undo buffer.
 */
  gl->vi.undo.line = (char *) malloc(linelen + 2);
  if(!gl->vi.undo.line) {
    errno = ENOMEM;
    return del_GetLine(gl);
  };
  gl->vi.undo.line[0] = '\0';
/*
 * Allocate a freelist from which to allocate nodes for the list
 * of completion functions.
 */
  gl->cpl_mem = _new_FreeList(sizeof(GlCplCallback), GL_CPL_FREELIST_BLOCKING);
  if(!gl->cpl_mem)
    return del_GetLine(gl);
/*
 * Allocate a freelist from which to allocate nodes for the list
 * of external action functions.
 */
  gl->ext_act_mem = _new_FreeList(sizeof(GlExternalAction),
				  GL_EXT_ACT_FREELIST_BLOCKING);
  if(!gl->ext_act_mem)
    return del_GetLine(gl);
/*
 * Allocate a freelist from which to allocate nodes for the list
 * of signals.
 */
  gl->sig_mem = _new_FreeList(sizeof(GlSignalNode), GLS_FREELIST_BLOCKING);
  if(!gl->sig_mem)
    return del_GetLine(gl);
/*
 * Install initial dispositions for the default list of signals that
 * gl_get_line() traps.
 */
  for(i=0; i<sizeof(gl_signal_list)/sizeof(gl_signal_list[0]); i++) {
    const struct GlDefSignal *sig = gl_signal_list + i;
    if(_gl_trap_signal(gl, sig->signo, sig->flags, sig->after,
		       sig->errno_value))
      return del_GetLine(gl);
  };
/*
 * Allocate an empty table of key bindings.
 */
  gl->bindings = _new_KeyTab();
  if(!gl->bindings)
    return del_GetLine(gl);
/*
 * Define the available actions that can be bound to key sequences.
 */
  for(i=0; i<sizeof(gl_actions)/sizeof(gl_actions[0]); i++) {
    if(_kt_set_action(gl->bindings, gl_actions[i].name, gl_actions[i].fn, NULL))
      return del_GetLine(gl);
  };
/*
 * Set up the default bindings.
 */
  if(gl_change_editor(gl, gl->editor))
    return del_GetLine(gl);
/*
 * Allocate termcap buffers.
 */
#ifdef USE_TERMCAP
  gl->tgetent_buf = (char *) malloc(TERMCAP_BUF_SIZE);
  gl->tgetstr_buf = (char *) malloc(TERMCAP_BUF_SIZE);
  if(!gl->tgetent_buf || !gl->tgetstr_buf) {
    errno = ENOMEM;
    return del_GetLine(gl);
  };
#endif
/*
 * Set up for I/O assuming stdin and stdout.
 */
  if(_gl_change_terminal(gl, stdin, stdout, getenv("TERM")))
    return del_GetLine(gl);
/*
 * Create a freelist for use in allocating GlFdNode list nodes.
 */
#ifdef HAVE_SELECT
  gl->fd_node_mem = _new_FreeList(sizeof(GlFdNode), GLFD_FREELIST_BLOCKING);
  if(!gl->fd_node_mem)
    return del_GetLine(gl);
#endif
/*
 * We are done for now.
 */
  return gl;
}

/*.......................................................................
 * Delete a GetLine object.
 *
 * Input:
 *  gl     GetLine *  The object to be deleted.
 * Output:
 *  return GetLine *  The deleted object (always NULL).
 */
GetLine *del_GetLine(GetLine *gl)
{
  if(gl) {
/*
 * If the terminal is in raw server mode, reset it.
 */
    _gl_normal_io(gl);
/*
 * Deallocate all objects contained by gl.
 */
    gl->err = _del_ErrMsg(gl->err);
    gl->glh = _del_GlHistory(gl->glh);
    gl->cpl = del_WordCompletion(gl->cpl);
#ifndef WITHOUT_FILE_SYSTEM
    gl->ef = del_ExpandFile(gl->ef);
#endif
    gl->capmem = _del_StringGroup(gl->capmem);
    gl->cq = _del_GlCharQueue(gl->cq);
    if(gl->file_fp)
      fclose(gl->file_fp);
    if(gl->term)
      free(gl->term);
    if(gl->line)
      free(gl->line);
    if(gl->cutbuf)
      free(gl->cutbuf);
    if(gl->prompt)
      free(gl->prompt);
    gl->cpl_mem = _del_FreeList(gl->cpl_mem, 1);
    gl->ext_act_mem = _del_FreeList(gl->ext_act_mem, 1);
    gl->sig_mem = _del_FreeList(gl->sig_mem, 1);
    gl->sigs = NULL;       /* Already freed by freeing sig_mem */
    gl->bindings = _del_KeyTab(gl->bindings);
    if(gl->vi.undo.line)
      free(gl->vi.undo.line);
#ifdef USE_TERMCAP
    if(gl->tgetent_buf)
      free(gl->tgetent_buf);
    if(gl->tgetstr_buf)
      free(gl->tgetstr_buf);
#endif
    if(gl->app_file)
      free(gl->app_file);
    if(gl->user_file)
      free(gl->user_file);
#ifdef HAVE_SELECT
    gl->fd_node_mem = _del_FreeList(gl->fd_node_mem, 1);
    gl->fd_nodes = NULL;  /* Already freed by freeing gl->fd_node_mem */
#endif
/*
 * Delete the now empty container.
 */
    free(gl);
  };
  return NULL;
}

/*.......................................................................
 * Bind a control or meta character to an action.
 *
 * Input:
 *  gl         GetLine *  The resource object of this program.
 *  binder    KtBinder    The source of the binding.
 *  c             char    The control or meta character.
 *                        If this is '\0', the call is ignored.
 *  action  const char *  The action name to bind the key to.
 * Output:
 *  return         int    0 - OK.
 *                        1 - Error.
 */
static int gl_bind_control_char(GetLine *gl, KtBinder binder, char c,
				const char *action)
{
  char keyseq[2];
/*
 * Quietly reject binding to the NUL control character, since this
 * is an ambiguous prefix of all bindings.
 */
  if(c == '\0')
    return 0;
/*
 * Making sure not to bind characters which aren't either control or
 * meta characters.
 */
  if(IS_CTRL_CHAR(c) || IS_META_CHAR(c)) {
    keyseq[0] = c;
    keyseq[1] = '\0';
  } else {
    return 0;
  };
/*
 * Install the binding.
 */
  if(_kt_set_keybinding(gl->bindings, binder, keyseq, action)) {
    _err_record_msg(gl->err, _kt_last_error(gl->bindings), END_ERR_MSG);
    return 1;
  };
  return 0;
}

/*.......................................................................
 * Read a line from the user.
 *
 * Input:
 *  gl       GetLine *  A resource object returned by new_GetLine().
 *  prompt      char *  The prompt to prefix the line with.
 *  start_line  char *  The initial contents of the input line, or NULL
 *                      if it should start out empty.
 *  start_pos    int    If start_line isn't NULL, this specifies the
 *                      index of the character over which the cursor
 *                      should initially be positioned within the line.
 *                      If you just want it to follow the last character
 *                      of the line, send -1.
 * Output:
 *  return      char *  An internal buffer containing the input line, or
 *                      NULL at the end of input. If the line fitted in
 *                      the buffer there will be a '\n' newline character
 *                      before the terminating '\0'. If it was truncated
 *                      there will be no newline character, and the remains
 *                      of the line should be retrieved via further calls
 *                      to this function.
 */
char *gl_get_line(GetLine *gl, const char *prompt,
		  const char *start_line, int start_pos)
{
  char *retval;   /* The return value of _gl_get_line() */
/*
 * Check the arguments.
 */
  if(!gl) {
    errno = EINVAL;
    return NULL;
  };
/*
 * Temporarily block all of the signals that we have been asked to trap.
 */
  if(gl_mask_signals(gl, &gl->old_signal_set))
    return NULL;
/*
 * Perform the command-line editing task.
 */
  retval = _gl_get_line(gl, prompt, start_line, start_pos);
/*
 * Restore the process signal mask to how it was when this function was
 * first called.
 */
  gl_unmask_signals(gl, &gl->old_signal_set);
  return retval;
}


/*.......................................................................
 * This is the main body of the public function gl_get_line().
 */
static char *_gl_get_line(GetLine *gl, const char *prompt,
			  const char *start_line, int start_pos)
{
  int waserr = 0;    /* True if an error occurs */
/*
 * Assume that this call will successfully complete the input
 * line until proven otherwise.
 */
  gl_clear_status(gl);
/*
 * If this is the first call to this function since new_GetLine(),
 * complete any postponed configuration.
 */
  if(!gl->configured) {
    (void) _gl_configure_getline(gl, NULL, NULL, TECLA_CONFIG_FILE);
    gl->configured = 1;
  };
/*
 * Before installing our signal handler functions, record the fact
 * that there are no pending signals.
 */
  gl_pending_signal = -1;
/*
 * Temporarily override the signal handlers of the calling program,
 * so that we can intercept signals that would leave the terminal
 * in a bad state.
 */
  waserr = gl_override_signal_handlers(gl);
/*
 * After recording the current terminal settings, switch the terminal
 * into raw input mode.
 */
  waserr = waserr || _gl_raw_io(gl, 1);
/*
 * Attempt to read the line. This will require more than one attempt if
 * either a current temporary input file is opened by gl_get_input_line()
 * or the end of a temporary input file is reached by gl_read_stream_line().
 */
  while(!waserr) {
/*
 * Read a line from a non-interactive stream?
 */
    if(gl->file_fp || !gl->is_term) {
      if(gl_read_stream_line(gl)==0) {
	break;
      } else if(gl->file_fp) {
	gl_revert_input(gl);
	gl_record_status(gl, GLR_NEWLINE, 0);
      } else {
	waserr = 1;
	break;
      };
    };
/*
 * Read from the terminal? Note that the above if() block may have
 * changed gl->file_fp, so it is necessary to retest it here, rather
 * than using an else statement.
 */
    if(!gl->file_fp && gl->is_term) {
      if(gl_get_input_line(gl, prompt, start_line, start_pos))
	waserr = 1;
      else
	break;
    };
  };
/*
 * If an error occurred, but gl->rtn_status is still set to
 * GLR_NEWLINE, change the status to GLR_ERROR. Otherwise
 * leave it at whatever specific value was assigned by the function
 * that aborted input. This means that only functions that trap
 * non-generic errors have to remember to update gl->rtn_status
 * themselves.
 */
  if(waserr && gl->rtn_status == GLR_NEWLINE)
    gl_record_status(gl, GLR_ERROR, errno);
/*
 * Restore terminal settings.
 */
  if(gl->io_mode != GL_SERVER_MODE)
    _gl_normal_io(gl);
/*
 * Restore the signal handlers.
 */
  gl_restore_signal_handlers(gl);
/*
 * If gl_get_line() gets aborted early, the errno value associated
 * with the event that caused this to happen is recorded in
 * gl->rtn_errno. Since errno may have been overwritten by cleanup
 * functions after this, restore its value to the value that it had
 * when the error condition occured, so that the caller can examine it
 * to find out what happened.
 */
  errno = gl->rtn_errno;
/*
 * Check the completion status to see how to return.
 */
  switch(gl->rtn_status) {
  case GLR_NEWLINE:    /* Success */
    return gl->line;
  case GLR_BLOCKED:    /* These events abort the current input line, */
  case GLR_SIGNAL:     /*  when in normal blocking I/O mode, but only */
  case GLR_TIMEOUT:    /*  temporarily pause line editing when in */
  case GLR_FDABORT:    /*  non-blocking server I/O mode. */
    if(gl->io_mode != GL_SERVER_MODE)
      _gl_abandon_line(gl);
    return NULL;
  case GLR_ERROR:      /* Unrecoverable errors abort the input line, */
  case GLR_EOF:        /*  regardless of the I/O mode. */
  default:
    _gl_abandon_line(gl);
    return NULL;
  };
}

/*.......................................................................
 * Read a single character from the user.
 *
 * Input:
 *  gl       GetLine *  A resource object returned by new_GetLine().
 *  prompt      char *  The prompt to prefix the line with, or NULL if
 *                      no prompt is required.
 *  defchar     char    The character to substitute if the
 *                      user simply hits return, or '\n' if you don't
 *                      need to substitute anything.
 * Output:
 *  return       int    The character that was read, or EOF if the read
 *                      had to be aborted (in which case you can call
 *                      gl_return_status() to find out why).
 */
int gl_query_char(GetLine *gl, const char *prompt, char defchar)
{
  int retval;   /* The return value of _gl_query_char() */
/*
 * Check the arguments.
 */
  if(!gl) {
    errno = EINVAL;
    return EOF;
  };
/*
 * Temporarily block all of the signals that we have been asked to trap.
 */
  if(gl_mask_signals(gl, &gl->old_signal_set))
    return EOF;
/*
 * Perform the character reading task.
 */
  retval = _gl_query_char(gl, prompt, defchar);
/*
 * Restore the process signal mask to how it was when this function was
 * first called.
 */
  gl_unmask_signals(gl, &gl->old_signal_set);
  return retval;
}

/*.......................................................................
 * This is the main body of the public function gl_query_char().
 */
static int _gl_query_char(GetLine *gl, const char *prompt, char defchar)
{
  int c = EOF;       /* The character to be returned */
  int waserr = 0;    /* True if an error occurs */
/*
 * Assume that this call will successfully complete the input operation
 * until proven otherwise.
 */
  gl_clear_status(gl);
/*
 * If this is the first call to this function or gl_get_line(),
 * since new_GetLine(), complete any postponed configuration.
 */
  if(!gl->configured) {
    (void) _gl_configure_getline(gl, NULL, NULL, TECLA_CONFIG_FILE);
    gl->configured = 1;
  };
/*
 * Before installing our signal handler functions, record the fact
 * that there are no pending signals.
 */
  gl_pending_signal = -1;
/*
 * Temporarily override the signal handlers of the calling program,
 * so that we can intercept signals that would leave the terminal
 * in a bad state.
 */
  waserr = gl_override_signal_handlers(gl);
/*
 * After recording the current terminal settings, switch the terminal
 * into raw input mode without redisplaying any partially entered
 * input line.
 */
  waserr = waserr || _gl_raw_io(gl, 0);
/*
 * Attempt to read the line. This will require more than one attempt if
 * either a current temporary input file is opened by gl_get_input_line()
 * or the end of a temporary input file is reached by gl_read_stream_line().
 */
  while(!waserr) {
/*
 * Read a line from a non-interactive stream?
 */
    if(gl->file_fp || !gl->is_term) {
      c = gl_read_stream_char(gl);
      if(c != EOF) {            /* Success? */
	if(c=='\n') c = defchar;
	break;
      } else if(gl->file_fp) {  /* End of temporary input file? */
	gl_revert_input(gl);
	gl_record_status(gl, GLR_NEWLINE, 0);
      } else {                  /* An error? */
	waserr = 1;
	break;
      };
    };
/*
 * Read from the terminal? Note that the above if() block may have
 * changed gl->file_fp, so it is necessary to retest it here, rather
 * than using an else statement.
 */
    if(!gl->file_fp && gl->is_term) {
      c = gl_get_query_char(gl, prompt, defchar);
      if(c==EOF)
	waserr = 1;
      else
	break;
    };
  };
/*
 * If an error occurred, but gl->rtn_status is still set to
 * GLR_NEWLINE, change the status to GLR_ERROR. Otherwise
 * leave it at whatever specific value was assigned by the function
 * that aborted input. This means that only functions that trap
 * non-generic errors have to remember to update gl->rtn_status
 * themselves.
 */
  if(waserr && gl->rtn_status == GLR_NEWLINE)
    gl_record_status(gl, GLR_ERROR, errno);
/*
 * Restore terminal settings.
 */
  if(gl->io_mode != GL_SERVER_MODE)
    _gl_normal_io(gl);
/*
 * Restore the signal handlers.
 */
  gl_restore_signal_handlers(gl);
/*
 * If this function gets aborted early, the errno value associated
 * with the event that caused this to happen is recorded in
 * gl->rtn_errno. Since errno may have been overwritten by cleanup
 * functions after this, restore its value to the value that it had
 * when the error condition occured, so that the caller can examine it
 * to find out what happened.
 */
  errno = gl->rtn_errno;
/*
 * Error conditions are signalled to the caller, by setting the returned
 * character to EOF.
 */
  if(gl->rtn_status != GLR_NEWLINE)
    c = EOF;
/*
 * In this mode, every character that is read is a completed
 * transaction, just like reading a completed input line, so prepare
 * for the next input line or character.
 */
  _gl_abandon_line(gl);
/*
 * Return the acquired character.
 */
  return c;
}

/*.......................................................................
 * Record of the signal handlers of the calling program, so that they
 * can be restored later.
 *
 * Input:
 *  gl    GetLine *   The resource object of this library.
 * Output:
 *  return    int     0 - OK.
 *                    1 - Error.
 */
static int gl_override_signal_handlers(GetLine *gl)
{
  GlSignalNode *sig;   /* A node in the list of signals to be caught */
/*
 * Set up our signal handler.
 */
  SigAction act;
  act.sa_handler = gl_signal_handler;
  memcpy(&act.sa_mask, &gl->all_signal_set, sizeof(sigset_t));
  act.sa_flags = 0;
/*
 * Get the subset of the signals that we are supposed to trap that
 * should actually be trapped.
 */
  sigemptyset(&gl->use_signal_set);
  for(sig=gl->sigs; sig; sig=sig->next) {
/*
 * Trap this signal? If it is blocked by the calling program and we
 * haven't been told to unblock it, don't arrange to trap this signal.
 */
    if(sig->flags & GLS_UNBLOCK_SIG ||
       !sigismember(&gl->old_signal_set, sig->signo)) {
      if(sigaddset(&gl->use_signal_set, sig->signo) == -1) {
	_err_record_msg(gl->err, "sigaddset error", END_ERR_MSG);
	return 1;
      };
    };
  };
/*
 * Override the actions of the signals that we are trapping.
 */
  for(sig=gl->sigs; sig; sig=sig->next) {
    if(sigismember(&gl->use_signal_set, sig->signo)) {
      sigdelset(&act.sa_mask, sig->signo);
      if(sigaction(sig->signo, &act, &sig->original)) {
	_err_record_msg(gl->err, "sigaction error", END_ERR_MSG);
	return 1;
      };
      sigaddset(&act.sa_mask, sig->signo);
    };
  };
/*
 * Record the fact that the application's signal handlers have now
 * been overriden.
 */
  gl->signals_overriden = 1;
/*
 * Just in case a SIGWINCH signal was sent to the process while our
 * SIGWINCH signal handler wasn't in place, check to see if the terminal
 * size needs updating.
 */
  if(_gl_update_size(gl))
    return 1;
  return 0;
}

/*.......................................................................
 * Restore the signal handlers of the calling program.
 *
 * Input:
 *  gl     GetLine *  The resource object of this library.
 * Output:
 *  return     int    0 - OK.
 *                    1 - Error.
 */
static int gl_restore_signal_handlers(GetLine *gl)
{
  GlSignalNode *sig;   /* A node in the list of signals to be caught */
/*
 * Restore application signal handlers that were overriden
 * by gl_override_signal_handlers().
 */
  for(sig=gl->sigs; sig; sig=sig->next) {
    if(sigismember(&gl->use_signal_set, sig->signo) &&
       sigaction(sig->signo, &sig->original, NULL)) {
      _err_record_msg(gl->err, "sigaction error", END_ERR_MSG);
      return 1;
    };
  };
/*
 * Record the fact that the application's signal handlers have now
 * been restored.
 */
  gl->signals_overriden = 0;
  return 0;
}

/*.......................................................................
 * This signal handler simply records the fact that a given signal was
 * caught in the file-scope gl_pending_signal variable.
 */
static void gl_signal_handler(int signo)
{
  gl_pending_signal = signo;
  siglongjmp(gl_setjmp_buffer, 1);
}

/*.......................................................................
 * Switch the terminal into raw mode after storing the previous terminal
 * settings in gl->attributes.
 *
 * Input:
 *  gl     GetLine *   The resource object of this program.
 * Output:
 *  return     int     0 - OK.
 *                     1 - Error.
 */
static int gl_raw_terminal_mode(GetLine *gl)
{
  Termios newattr;   /* The new terminal attributes */
/*
 * If the terminal is already in raw mode, do nothing.
 */
  if(gl->raw_mode)
    return 0;
/*
 * Record the current terminal attributes.
 */
  if(tcgetattr(gl->input_fd, &gl->oldattr)) {
    _err_record_msg(gl->err, "tcgetattr error", END_ERR_MSG);
    return 1;
  };
/*
 * This function shouldn't do anything but record the current terminal
 * attritubes if editing has been disabled.
 */
  if(gl->editor == GL_NO_EDITOR)
    return 0;
/*
 * Modify the existing attributes.
 */
  newattr = gl->oldattr;
/*
 * Turn off local echo, canonical input mode and extended input processing.
 */
  newattr.c_lflag &= ~(ECHO | ICANON | IEXTEN);
/*
 * Don't translate carriage return to newline, turn off input parity
 * checking, don't strip off 8th bit, turn off output flow control.
 */
  newattr.c_iflag &= ~(ICRNL | INPCK | ISTRIP);
/*
 * Clear size bits, turn off parity checking, and allow 8-bit characters.
 */
  newattr.c_cflag &= ~(CSIZE | PARENB);
  newattr.c_cflag |= CS8;
/*
 * Turn off output processing.
 */
  newattr.c_oflag &= ~(OPOST);
/*
 * Request one byte at a time, without waiting.
 */
  newattr.c_cc[VMIN] = gl->io_mode==GL_SERVER_MODE ? 0:1;
  newattr.c_cc[VTIME] = 0;
/*
 * Install the new terminal modes.
 */
  while(tcsetattr(gl->input_fd, TCSADRAIN, &newattr)) {
    if(errno != EINTR) {
      _err_record_msg(gl->err, "tcsetattr error", END_ERR_MSG);
      return 1;
    };
  };
/*
 * Record the new terminal mode.
 */
  gl->raw_mode = 1;
  return 0;
}

/*.......................................................................
 * Restore the terminal attributes recorded in gl->oldattr.
 *
 * Input:
 *  gl     GetLine *   The resource object of this library.
 * Output:
 *  return     int     0 - OK.
 *                     1 - Error.
 */
static int gl_restore_terminal_attributes(GetLine *gl)
{
  int waserr = 0;
/*
 * If not in raw mode, do nothing.
 */
  if(!gl->raw_mode)
    return 0;
/*
 * Before changing the terminal attributes, make sure that all output
 * has been passed to the terminal.
 */
  if(gl_flush_output(gl))
    waserr = 1;
/*
 * Reset the terminal attributes to the values that they had on
 * entry to gl_get_line().
 */
  while(tcsetattr(gl->input_fd, TCSADRAIN, &gl->oldattr)) {
    if(errno != EINTR) {
      _err_record_msg(gl->err, "tcsetattr error", END_ERR_MSG);
      waserr = 1;
      break;
    };
  };
/*
 * Record the new terminal mode.
 */
  gl->raw_mode = 0;
  return waserr;
}

/*.......................................................................
 * Switch the terminal file descriptor to use non-blocking I/O.
 *
 * Input:
 *  gl         GetLine *  The resource object of gl_get_line().
 *  fd             int    The file descriptor to make non-blocking.
 */
static int gl_nonblocking_io(GetLine *gl, int fd)
{
  int fcntl_flags;   /* The new file-descriptor control flags */
/*
 * Is non-blocking I/O supported on this system?  Note that even
 * without non-blocking I/O, the terminal will probably still act as
 * though it was non-blocking, because we also set the terminal
 * attributes to return immediately if no input is available and we
 * use select() to wait to be able to write. If select() also isn't
 * available, then input will probably remain fine, but output could
 * block, depending on the behaviour of the terminal driver.
 */
#if defined(NON_BLOCKING_FLAG)
/*
 * Query the current file-control flags, and add the
 * non-blocking I/O flag.
 */
  fcntl_flags = fcntl(fd, F_GETFL) | NON_BLOCKING_FLAG;
/*
 * Install the new control flags.
 */
  if(fcntl(fd, F_SETFL, fcntl_flags) == -1) {
    _err_record_msg(gl->err, "fcntl error", END_ERR_MSG);
    return 1;
  };
#endif
  return 0;
}

/*.......................................................................
 * Switch to blocking terminal I/O.
 *
 * Input:
 *  gl         GetLine *  The resource object of gl_get_line().
 *  fd             int    The file descriptor to make blocking.
 */
static int gl_blocking_io(GetLine *gl, int fd)
{
  int fcntl_flags;   /* The new file-descriptor control flags */
/*
 * Is non-blocking I/O implemented on this system?
 */
#if defined(NON_BLOCKING_FLAG)
/*
 * Query the current file control flags and remove the non-blocking
 * I/O flag.
 */
  fcntl_flags = fcntl(fd, F_GETFL) & ~NON_BLOCKING_FLAG;
/*
 * Install the modified control flags.
 */
  if(fcntl(fd, F_SETFL, fcntl_flags) == -1) {
    _err_record_msg(gl->err, "fcntl error", END_ERR_MSG);
    return 1;
  };
#endif
  return 0;
}

/*.......................................................................
 * Read a new input line from the user.
 *
 * Input:
 *  gl         GetLine *  The resource object of this library.
 *  prompt        char *  The prompt to prefix the line with, or NULL to
 *                        use the same prompt that was used by the previous
 *                        line.
 *  start_line    char *  The initial contents of the input line, or NULL
 *                        if it should start out empty.
 *  start_pos      int    If start_line isn't NULL, this specifies the
 *                        index of the character over which the cursor
 *                        should initially be positioned within the line.
 *                        If you just want it to follow the last character
 *                        of the line, send -1.
 * Output:
 *  return    int    0 - OK.
 *                   1 - Error.
 */
static int gl_get_input_line(GetLine *gl, const char *prompt,
			     const char *start_line, int start_pos)
{
  char c;               /* The character being read */
/*
 * Flush any pending output to the terminal.
 */
  if(_glq_char_count(gl->cq) > 0 && gl_flush_output(gl))
    return 1;
/*
 * Are we starting a new line?
 */
  if(gl->endline) {
/*
 * Delete any incompletely enterred line.
 */
    if(gl_erase_line(gl))
      return 1;
/*
 * Display the new line to be edited.
 */
    if(gl_present_line(gl, prompt, start_line, start_pos))
      return 1;
  };
/*
 * Read one character at a time.
 */
  while(gl_read_terminal(gl, 1, &c) == 0) {
/*
 * Increment the count of the number of key sequences entered.
 */
    gl->keyseq_count++;
/*
 * Interpret the character either as the start of a new key-sequence,
 * as a continuation of a repeat count, or as a printable character
 * to be added to the line.
 */
    if(gl_interpret_char(gl, c))
      break;
/*
 * If we just ran an action function which temporarily asked for
 * input to be taken from a file, abort this call.
 */
    if(gl->file_fp)
      return 0;
/*
 * Has the line been completed?
 */
    if(gl->endline)
      return gl_line_ended(gl, c);
  };
/*
 * To get here, gl_read_terminal() must have returned non-zero. See
 * whether a signal was caught that requested that the current line
 * be returned.
 */
  if(gl->endline)
    return gl_line_ended(gl, '\n');
/*
 * If I/O blocked while attempting to get the latest character
 * of the key sequence, rewind the key buffer to allow interpretation of
 * the current key sequence to be restarted on the next call to this
 * function.
 */
  if(gl->rtn_status == GLR_BLOCKED && gl->pending_io == GLP_READ)
    gl->nread = 0;
  return 1;
}

/*.......................................................................
 * This is the private function of gl_query_char() that handles
 * prompting the user, reading a character from the terminal, and
 * displaying what the user entered.
 *
 * Input:
 *  gl         GetLine *  The resource object of this library.
 *  prompt        char *  The prompt to prefix the line with.
 *  defchar       char    The character to substitute if the
 *                        user simply hits return, or '\n' if you don't
 *                        need to substitute anything.
 * Output:
 *  return         int    The character that was read, or EOF if something
 *                        prevented a character from being read.
 */
static int gl_get_query_char(GetLine *gl, const char *prompt, int defchar)
{
  char c;               /* The character being read */
  int retval;           /* The return value of this function */
/*
 * Flush any pending output to the terminal.
 */
  if(_glq_char_count(gl->cq) > 0 && gl_flush_output(gl))
    return EOF;
/*
 * Delete any incompletely entered line.
 */
  if(gl_erase_line(gl))
    return EOF;
/*
 * Reset the line input parameters and display the prompt, if any.
 */
  if(gl_present_line(gl, prompt, NULL, 0))
    return EOF;
/*
 * Read one character.
 */
  if(gl_read_terminal(gl, 1, &c) == 0) {
/*
 * In this mode, count each character as being a new key-sequence.
 */
    gl->keyseq_count++;
/*
 * Delete the character that was read, from the key-press buffer.
 */
    gl_discard_chars(gl, gl->nread);
/*
 * Convert carriage returns to newlines.
 */
    if(c == '\r')
      c = '\n';
/*
 * If the user just hit return, subsitute the default character.
 */
    if(c == '\n')
      c = defchar;
/*
 * Display the entered character to the right of the prompt.
 */
    if(c!='\n') {
      if(gl_end_of_line(gl, 1, NULL)==0)
	gl_print_char(gl, c, ' ');
    };
/*
 * Record the return character, and mark the call as successful.
 */
    retval = c;
    gl_record_status(gl, GLR_NEWLINE, 0);
/*
 * Was a signal caught whose disposition is to cause the current input
 * line to be returned? If so return a newline character.
 */
  } else if(gl->endline) {
    retval = '\n';
    gl_record_status(gl, GLR_NEWLINE, 0);
  } else {
    retval = EOF;
  };
/*
 * Start a new line.
 */
  if(gl_start_newline(gl, 1))
    return EOF;
/*
 * Attempt to flush any pending output.
 */
  (void) gl_flush_output(gl);
/*
 * Return either the character that was read, or EOF if an error occurred.
 */
  return retval;
}

/*.......................................................................
 * Add a character to the line buffer at the current cursor position,
 * inserting or overwriting according the current mode.
 *
 * Input:
 *  gl   GetLine *   The resource object of this library.
 *  c       char     The character to be added.
 * Output:
 *  return   int     0 - OK.
 *                   1 - Insufficient room.
 */
static int gl_add_char_to_line(GetLine *gl, char c)
{
/*
 * Keep a record of the current cursor position.
 */
  int buff_curpos = gl->buff_curpos;
  int term_curpos = gl->term_curpos;
/*
 * Work out the displayed width of the new character.
 */
  int width = gl_displayed_char_width(gl, c, term_curpos);
/*
 * If we are in insert mode, or at the end of the line,
 * check that we can accomodate a new character in the buffer.
 * If not, simply return, leaving it up to the calling program
 * to check for the absence of a newline character.
 */
  if((gl->insert || buff_curpos >= gl->ntotal) && gl->ntotal >= gl->linelen)
    return 0;
/*
 * Are we adding characters to the line (ie. inserting or appending)?
 */
  if(gl->insert || buff_curpos >= gl->ntotal) {
/*
 * If inserting, make room for the new character.
 */
    if(buff_curpos < gl->ntotal)
      gl_make_gap_in_buffer(gl, buff_curpos, 1);
/*
 * Copy the character into the buffer.
 */
    gl_buffer_char(gl, c, buff_curpos);
    gl->buff_curpos++;
/*
 * Redraw the line from the cursor position to the end of the line,
 * and move the cursor to just after the added character.
 */
    if(gl_print_string(gl, gl->line + buff_curpos, '\0') ||
       gl_set_term_curpos(gl, term_curpos + width))
      return 1;
/*
 * Are we overwriting an existing character?
 */
  } else {
/*
 * Get the width of the character being overwritten.
 */
    int old_width = gl_displayed_char_width(gl, gl->line[buff_curpos],
					    term_curpos);
/*
 * Overwrite the character in the buffer.
 */
    gl_buffer_char(gl, c, buff_curpos);
/*
 * If we are replacing with a narrower character, we need to
 * redraw the terminal string to the end of the line, then
 * overwrite the trailing old_width - width characters
 * with spaces.
 */
    if(old_width > width) {
      if(gl_print_string(gl, gl->line + buff_curpos, '\0'))
	return 1;
/*
 * Clear to the end of the terminal.
 */
      if(gl_truncate_display(gl))
	return 1;
/*
 * Move the cursor to the end of the new character.
 */
      if(gl_set_term_curpos(gl, term_curpos + width))
	return 1;
      gl->buff_curpos++;
/*
 * If we are replacing with a wider character, then we will be
 * inserting new characters, and thus extending the line.
 */
    } else if(width > old_width) {
/*
 * Redraw the line from the cursor position to the end of the line,
 * and move the cursor to just after the added character.
 */
      if(gl_print_string(gl, gl->line + buff_curpos, '\0') ||
	 gl_set_term_curpos(gl, term_curpos + width))
	return 1;
      gl->buff_curpos++;
/*
 * The original and replacement characters have the same width,
 * so simply overwrite.
 */
    } else {
/*
 * Copy the character into the buffer.
 */
      gl_buffer_char(gl, c, buff_curpos);
      gl->buff_curpos++;
/*
 * Overwrite the original character.
 */
      if(gl_print_char(gl, c, gl->line[gl->buff_curpos]))
	return 1;
    };
  };
  return 0;
}

/*.......................................................................
 * Insert/append a string to the line buffer and terminal at the current
 * cursor position.
 *
 * Input:
 *  gl   GetLine *   The resource object of this library.
 *  s       char *   The string to be added.
 * Output:
 *  return   int     0 - OK.
 *                   1 - Insufficient room.
 */
static int gl_add_string_to_line(GetLine *gl, const char *s)
{
  int buff_slen;   /* The length of the string being added to line[] */
  int term_slen;   /* The length of the string being written to the terminal */
  int buff_curpos; /* The original value of gl->buff_curpos */
  int term_curpos; /* The original value of gl->term_curpos */
/*
 * Keep a record of the current cursor position.
 */
  buff_curpos = gl->buff_curpos;
  term_curpos = gl->term_curpos;
/*
 * How long is the string to be added?
 */
  buff_slen = strlen(s);
  term_slen = gl_displayed_string_width(gl, s, buff_slen, term_curpos);
/*
 * Check that we can accomodate the string in the buffer.
 * If not, simply return, leaving it up to the calling program
 * to check for the absence of a newline character.
 */
  if(gl->ntotal + buff_slen > gl->linelen)
    return 0;
/*
 * Move the characters that follow the cursor in the buffer by
 * buff_slen characters to the right.
 */
  if(gl->ntotal > gl->buff_curpos)
    gl_make_gap_in_buffer(gl, gl->buff_curpos, buff_slen);
/*
 * Copy the string into the buffer.
 */
  gl_buffer_string(gl, s, buff_slen, gl->buff_curpos);
  gl->buff_curpos += buff_slen;
/*
 * Write the modified part of the line to the terminal, then move
 * the terminal cursor to the end of the displayed input string.
 */
  if(gl_print_string(gl, gl->line + buff_curpos, '\0') ||
     gl_set_term_curpos(gl, term_curpos + term_slen))
    return 1;
  return 0;
}

/*.......................................................................
 * Read a single character from the terminal.
 *
 * Input:
 *  gl    GetLine *   The resource object of this library.
 *  keep      int     If true, the returned character will be kept in
 *                    the input buffer, for potential replays. It should
 *                    subsequently be removed from the buffer when the
 *                    key sequence that it belongs to has been fully
 *                    processed, by calling gl_discard_chars().
 * Input/Output:
 *  c        char *   The character that is read, is assigned to *c.
 * Output:
 *  return    int     0 - OK.
 *                    1 - Either an I/O error occurred, or a signal was
 *                        caught who's disposition is to abort gl_get_line()
 *                        or to have gl_get_line() return the current line
 *                        as though the user had pressed return. In the
 *                        latter case gl->endline will be non-zero.
 */
static int gl_read_terminal(GetLine *gl, int keep, char *c)
{
/*
 * Before waiting for a new character to be input, flush unwritten
 * characters to the terminal.
 */
  if(gl_flush_output(gl))
    return 1;
/*
 * Record the fact that we are about to read from the terminal.
 */
  gl->pending_io = GLP_READ;
/*
 * If there is already an unread character in the buffer,
 * return it.
 */
  if(gl->nread < gl->nbuf) {
    *c = gl->keybuf[gl->nread];
/*
 * Retain the character in the key buffer, but mark it as having been read?
 */
    if(keep) {
      gl->nread++;
/*
 * Completely remove the character from the key buffer?
 */
    } else {
      memmove(gl->keybuf + gl->nread, gl->keybuf + gl->nread + 1,
	      gl->nbuf - gl->nread - 1);
    };
    return 0;
  };
/*
 * Make sure that there is space in the key buffer for one more character.
 * This should always be true if gl_interpret_char() is called for each
 * new character added, since it will clear the buffer once it has recognized
 * or rejected a key sequence.
 */
  if(gl->nbuf + 1 > GL_KEY_MAX) {
    gl_print_info(gl, "gl_read_terminal: Buffer overflow avoided.",
		  GL_END_INFO);
    errno = EIO;
    return 1;
  };
/*
 * Read one character from the terminal.
 */
  switch(gl_read_input(gl, c)) {
  case GL_READ_OK:
    break;
  case GL_READ_BLOCKED:
    gl_record_status(gl, GLR_BLOCKED, BLOCKED_ERRNO);
    return 1;
    break;
  default:
    return 1;
    break;
  };
/*
 * Append the character to the key buffer?
 */
  if(keep) {
    gl->keybuf[gl->nbuf] = *c;
    gl->nread = ++gl->nbuf;
  };
  return 0;
}

/*.......................................................................
 * Read one or more keypresses from the terminal of an input stream.
 *
 * Input:
 *  gl           GetLine *  The resource object of this module.
 *  c               char *  The character that was read is assigned to *c.
 * Output:
 *  return  GlReadStatus    The completion status of the read operation.
 */
static GlReadStatus gl_read_input(GetLine *gl, char *c)
{
/*
 * We may have to repeat the read if window change signals are received.
 */
  for(;;) {
/*
 * Which file descriptor should we read from? Mark this volatile, so
 * that siglongjmp() can't clobber it.
 */
    volatile int fd = gl->file_fp ? fileno(gl->file_fp) : gl->input_fd;
/*
 * If the endline flag becomes set, don't wait for another character.
 */
    if(gl->endline)
      return GL_READ_ERROR;
/*
 * Since the code in this function can block, trap signals.
 */
    if(sigsetjmp(gl_setjmp_buffer, 1)==0) {
/*
 * Handle the different I/O modes.
 */
      switch(gl->io_mode) {
/*
 * In normal I/O mode, we call the event handler before attempting
 * to read, since read() blocks.
 */
      case GL_NORMAL_MODE:
	if(gl_event_handler(gl, fd))
	  return GL_READ_ERROR;
	return gl_read_unmasked(gl, fd, c);  /* Read one character */
	break;
/*
 * In non-blocking server I/O mode, we attempt to read a character,
 * and only if this fails, call the event handler to wait for a any
 * user-configured timeout and any other user-configured events.  In
 * addition, we turn off the fcntl() non-blocking flag when reading
 * from the terminal, to work around a bug in Solaris. We can do this
 * without causing the read() to block, because when in non-blocking
 * server-I/O mode, gl_raw_io() sets the VMIN terminal attribute to 0,
 * which tells the terminal driver to return immediately if no
 * characters are available to be read.
 */
      case GL_SERVER_MODE:
	{
	  GlReadStatus status;        /* The return status */
	  if(isatty(fd))              /* If we reading from a terminal, */
	     gl_blocking_io(gl, fd);  /* switch to blocking I/O */
	  status = gl_read_unmasked(gl, fd, c); /* Try reading */
	  if(status == GL_READ_BLOCKED) {       /* Nothing readable yet */
	    if(gl_event_handler(gl, fd))        /* Wait for input */
	      status = GL_READ_ERROR;
	    else
	      status = gl_read_unmasked(gl, fd, c); /* Try reading again */
	  };
	  gl_nonblocking_io(gl, fd); /* Restore non-blocking I/O */
	  return status;
	};
	break;
      };
    };
/*
 * To get here, one of the signals that we are trapping must have
 * been received. Note that by using sigsetjmp() instead of setjmp()
 * the signal mask that was blocking these signals will have been
 * reinstated, so we can be sure that no more of these signals will
 * be received until we explicitly unblock them again.
 *
 * First, if non-blocking I/O was temporarily disabled, reinstate it.
 */
    if(gl->io_mode == GL_SERVER_MODE)
      gl_nonblocking_io(gl, fd);
/*
 * Now respond to the signal that was caught.
 */
    if(gl_check_caught_signal(gl))
      return GL_READ_ERROR;
  };
}

/*.......................................................................
 * This is a private function of gl_read_input(), which unblocks signals
 * temporarily while it reads a single character from the specified file
 * descriptor.
 *
 * Input:
 *  gl          GetLine *  The resource object of this module.
 *  fd              int    The file descriptor to read from.
 *  c              char *  The character that was read is assigned to *c.
 * Output:
 *  return GlReadStatus    The completion status of the read.
 */
static int gl_read_unmasked(GetLine *gl, int fd, char *c)
{
  int nread;  /* The return value of read() */
/*
 * Unblock the signals that we are trapping, while waiting for I/O.
 */
  gl_catch_signals(gl);
/*
 * Attempt to read one character from the terminal, restarting the read
 * if any signals that we aren't trapping, are received.
 */
  do {
    errno = 0;
    nread = read(fd, c, 1);
  } while(nread < 0 && errno==EINTR);
/*
 * Block all of the signals that we are trapping.
 */
  gl_mask_signals(gl, NULL);
/*
 * Check the completion status of the read.
 */
  switch(nread) {
  case 1:
    return GL_READ_OK;
  case 0:
    return (isatty(fd) || errno != 0) ? GL_READ_BLOCKED : GL_READ_EOF;
  default:
    return GL_READ_ERROR;
  };
}

/*.......................................................................
 * Remove a specified number of characters from the start of the
 * key-press lookahead buffer, gl->keybuf[], and arrange for the next
 * read to start from the character at the start of the shifted buffer.
 *
 * Input:
 *  gl      GetLine *  The resource object of this module.
 *  nused       int    The number of characters to discard from the start
 *                     of the buffer.
 */
static void gl_discard_chars(GetLine *gl, int nused)
{
  int nkeep = gl->nbuf - nused;
  if(nkeep > 0) {
    memmove(gl->keybuf, gl->keybuf + nused, nkeep);
    gl->nbuf = nkeep;
    gl->nread = 0;
  } else {
    gl->nbuf = gl->nread = 0;
  };
}

/*.......................................................................
 * This function is called to handle signals caught between calls to
 * sigsetjmp() and siglongjmp().
 *
 * Input:
 *  gl      GetLine *   The resource object of this library.
 * Output:
 *  return      int     0 - Signal handled internally.
 *                      1 - Signal requires gl_get_line() to abort.
 */
static int gl_check_caught_signal(GetLine *gl)
{
  GlSignalNode *sig;      /* The signal disposition */
  SigAction keep_action;  /* The signal disposition of tecla signal handlers */
  unsigned flags;         /* The signal processing flags to use */
  int signo;              /* The signal to be handled */
/*
 * Was no signal caught?
 */
  if(gl_pending_signal == -1)
    return 0;
/*
 * Get the signal to be handled.
 */
  signo = gl_pending_signal;
/*
 * Mark the signal as handled. Note that at this point, all of
 * the signals that we are trapping are blocked from delivery.
 */
  gl_pending_signal = -1;
/*
 * Record the signal that was caught, so that the user can query it later.
 */
  gl->last_signal = signo;
/*
 * In non-blocking server mode, the application is responsible for
 * responding to terminal signals, and we don't want gl_get_line()s
 * normal signal handling to clash with this, so whenever a signal
 * is caught, we arrange for gl_get_line() to abort and requeue the
 * signal while signals are still blocked. If the application
 * had the signal unblocked when gl_get_line() was called, the signal
 * will be delivered again as soon as gl_get_line() restores the
 * process signal mask, just before returning to the application.
 * Note that the caller of this function should set gl->pending_io
 * to the appropriate choice of GLP_READ and GLP_WRITE, before returning.
 */
  if(gl->io_mode==GL_SERVER_MODE) {
    gl_record_status(gl, GLR_SIGNAL, EINTR);
    raise(signo);
    return 1;
  };
/*
 * Lookup the requested disposition of this signal.
 */
  for(sig=gl->sigs; sig && sig->signo != signo; sig=sig->next)
    ;
  if(!sig)
    return 0;
/*
 * Get the signal response flags for this signal.
 */
  flags = sig->flags;
/*
 * Did we receive a terminal size signal?
 */
#ifdef SIGWINCH
  if(signo == SIGWINCH && _gl_update_size(gl))
    return 1;
#endif
/*
 * Start a fresh line?
 */
  if(flags & GLS_RESTORE_LINE) {
    if(gl_start_newline(gl, 0))
      return 1;
  };
/*
 * Restore terminal settings to how they were before gl_get_line() was
 * called?
 */
  if(flags & GLS_RESTORE_TTY)
    gl_restore_terminal_attributes(gl);
/*
 * Restore signal handlers to how they were before gl_get_line() was
 * called? If this hasn't been requested, only reinstate the signal
 * handler of the signal that we are handling.
 */
  if(flags & GLS_RESTORE_SIG) {
    gl_restore_signal_handlers(gl);
    gl_unmask_signals(gl, &gl->old_signal_set);
  } else {
    (void) sigaction(sig->signo, &sig->original, &keep_action);
    (void) sigprocmask(SIG_UNBLOCK, &sig->proc_mask, NULL);
  };
/*
 * Forward the signal to the application's signal handler.
 */
  if(!(flags & GLS_DONT_FORWARD))
    raise(signo);
/*
 * Reinstate our signal handlers.
 */
  if(flags & GLS_RESTORE_SIG) {
    gl_mask_signals(gl, NULL);
    gl_override_signal_handlers(gl);
  } else {
    (void) sigaction(sig->signo, &keep_action, NULL);
    (void) sigprocmask(SIG_BLOCK, &sig->proc_mask, NULL);
  };
/*
 * Do we need to reinstate our terminal settings?
 */
  if(flags & GLS_RESTORE_TTY)
    gl_raw_terminal_mode(gl);
/*
 * Redraw the line?
 */
  if(flags & GLS_REDRAW_LINE)
    gl_queue_redisplay(gl);
/*
 * What next?
 */
  switch(sig->after) {
  case GLS_RETURN:
    gl_newline(gl, 1, NULL);
    return gl_flush_output(gl);
    break;
  case GLS_ABORT:
    gl_record_status(gl, GLR_SIGNAL, sig->errno_value);
    return 1;
    break;
  case GLS_CONTINUE:
    return gl_flush_output(gl);
    break;
  };
  return 0;
}

/*.......................................................................
 * Get pertinent terminal control strings and the initial terminal size.
 *
 * Input:
 *  gl     GetLine *  The resource object of this library.
 *  term      char *  The type of the terminal.
 * Output:
 *  return     int    0 - OK.
 *                    1 - Error.
 */
static int gl_control_strings(GetLine *gl, const char *term)
{
  int bad_term = 0;   /* True if term is unusable */
/*
 * Discard any existing control strings from a previous terminal.
 */
  gl->left = NULL;
  gl->right = NULL;
  gl->up = NULL;
  gl->down = NULL;
  gl->home = NULL;
  gl->bol = 0;
  gl->clear_eol = NULL;
  gl->clear_eod = NULL;
  gl->u_arrow = NULL;
  gl->d_arrow = NULL;
  gl->l_arrow = NULL;
  gl->r_arrow = NULL;
  gl->sound_bell = NULL;
  gl->bold = NULL;
  gl->underline = NULL;
  gl->standout = NULL;
  gl->dim = NULL;
  gl->reverse = NULL;
  gl->blink = NULL;
  gl->text_attr_off = NULL;
  gl->nline = 0;
  gl->ncolumn = 0;
#ifdef USE_TERMINFO
  gl->left_n = NULL;
  gl->right_n = NULL;
#endif
/*
 * If possible lookup the information in a terminal information
 * database.
 */
#ifdef USE_TERMINFO
  {
    int errret;
    if(!term || setupterm((char *)term, gl->input_fd, &errret) == ERR) {
      bad_term = 1;
    } else {
      _clr_StringGroup(gl->capmem);
      gl->left = gl_tigetstr(gl, "cub1");
      gl->right = gl_tigetstr(gl, "cuf1");
      gl->up = gl_tigetstr(gl, "cuu1");
      gl->down = gl_tigetstr(gl, "cud1");
      gl->home = gl_tigetstr(gl, "home");
      gl->clear_eol = gl_tigetstr(gl, "el");
      gl->clear_eod = gl_tigetstr(gl, "ed");
      gl->u_arrow = gl_tigetstr(gl, "kcuu1");
      gl->d_arrow = gl_tigetstr(gl, "kcud1");
      gl->l_arrow = gl_tigetstr(gl, "kcub1");
      gl->r_arrow = gl_tigetstr(gl, "kcuf1");
      gl->left_n = gl_tigetstr(gl, "cub");
      gl->right_n = gl_tigetstr(gl, "cuf");
      gl->sound_bell = gl_tigetstr(gl, "bel");
      gl->bold = gl_tigetstr(gl, "bold");
      gl->underline = gl_tigetstr(gl, "smul");
      gl->standout = gl_tigetstr(gl, "smso");
      gl->dim = gl_tigetstr(gl, "dim");
      gl->reverse = gl_tigetstr(gl, "rev");
      gl->blink = gl_tigetstr(gl, "blink");
      gl->text_attr_off = gl_tigetstr(gl, "sgr0");
    };
  };
#elif defined(USE_TERMCAP)
  if(!term || tgetent(gl->tgetent_buf, (char *)term) < 0) {
    bad_term = 1;
  } else {
    char *tgetstr_buf_ptr = gl->tgetstr_buf;
    _clr_StringGroup(gl->capmem);
    gl->left = gl_tgetstr(gl, "le", &tgetstr_buf_ptr);
    gl->right = gl_tgetstr(gl, "nd", &tgetstr_buf_ptr);
    gl->up = gl_tgetstr(gl, "up", &tgetstr_buf_ptr);
    gl->down = gl_tgetstr(gl, "do", &tgetstr_buf_ptr);
    gl->home = gl_tgetstr(gl, "ho", &tgetstr_buf_ptr);
    gl->clear_eol = gl_tgetstr(gl, "ce", &tgetstr_buf_ptr);
    gl->clear_eod = gl_tgetstr(gl, "cd", &tgetstr_buf_ptr);
    gl->u_arrow = gl_tgetstr(gl, "ku", &tgetstr_buf_ptr);
    gl->d_arrow = gl_tgetstr(gl, "kd", &tgetstr_buf_ptr);
    gl->l_arrow = gl_tgetstr(gl, "kl", &tgetstr_buf_ptr);
    gl->r_arrow = gl_tgetstr(gl, "kr", &tgetstr_buf_ptr);
    gl->sound_bell = gl_tgetstr(gl, "bl", &tgetstr_buf_ptr);
    gl->bold = gl_tgetstr(gl, "md", &tgetstr_buf_ptr);
    gl->underline = gl_tgetstr(gl, "us", &tgetstr_buf_ptr);
    gl->standout = gl_tgetstr(gl, "so", &tgetstr_buf_ptr);
    gl->dim = gl_tgetstr(gl, "mh", &tgetstr_buf_ptr);
    gl->reverse = gl_tgetstr(gl, "mr", &tgetstr_buf_ptr);
    gl->blink = gl_tgetstr(gl, "mb", &tgetstr_buf_ptr);
    gl->text_attr_off = gl_tgetstr(gl, "me", &tgetstr_buf_ptr);
  };
#endif
/*
 * Report term being unusable.
 */
  if(bad_term) {
    gl_print_info(gl, "Bad terminal type: \"", term ? term : "(null)",
		  "\". Will assume vt100.", GL_END_INFO);
  };
/*
 * Fill in missing information with ANSI VT100 strings.
 */
  if(!gl->left)
    gl->left = "\b";    /* ^H */
  if(!gl->right)
    gl->right = GL_ESC_STR "[C";
  if(!gl->up)
    gl->up = GL_ESC_STR "[A";
  if(!gl->down)
    gl->down = "\n";
  if(!gl->home)
    gl->home = GL_ESC_STR "[H";
  if(!gl->bol)
    gl->bol = "\r";
  if(!gl->clear_eol)
    gl->clear_eol = GL_ESC_STR "[K";
  if(!gl->clear_eod)
    gl->clear_eod = GL_ESC_STR "[J";
  if(!gl->u_arrow)
    gl->u_arrow = GL_ESC_STR "[A";
  if(!gl->d_arrow)
    gl->d_arrow = GL_ESC_STR "[B";
  if(!gl->l_arrow)
    gl->l_arrow = GL_ESC_STR "[D";
  if(!gl->r_arrow)
    gl->r_arrow = GL_ESC_STR "[C";
  if(!gl->sound_bell)
    gl->sound_bell = "\a";
  if(!gl->bold)
    gl->bold = GL_ESC_STR "[1m";
  if(!gl->underline)
    gl->underline = GL_ESC_STR "[4m";
  if(!gl->standout)
    gl->standout = GL_ESC_STR "[1;7m";
  if(!gl->dim)
    gl->dim = "";  /* Not available */
  if(!gl->reverse)
    gl->reverse = GL_ESC_STR "[7m";
  if(!gl->blink)
    gl->blink = GL_ESC_STR "[5m";
  if(!gl->text_attr_off)
    gl->text_attr_off = GL_ESC_STR "[m";
/*
 * Find out the current terminal size.
 */
  (void) _gl_terminal_size(gl, GL_DEF_NCOLUMN, GL_DEF_NLINE, NULL);
  return 0;
}

#ifdef USE_TERMINFO
/*.......................................................................
 * This is a private function of gl_control_strings() used to look up
 * a termninal capability string from the terminfo database and make
 * a private copy of it.
 *
 * Input:
 *  gl         GetLine *  The resource object of gl_get_line().
 *  name    const char *  The name of the terminfo string to look up.
 * Output:
 *  return  const char *  The local copy of the capability, or NULL
 *                        if not available.
 */
static const char *gl_tigetstr(GetLine *gl, const char *name)
{
  const char *value = tigetstr((char *)name);
  if(!value || value == (char *) -1)
    return NULL;
  return _sg_store_string(gl->capmem, value, 0);
}
#elif defined(USE_TERMCAP)
/*.......................................................................
 * This is a private function of gl_control_strings() used to look up
 * a termninal capability string from the termcap database and make
 * a private copy of it. Note that some emulations of tgetstr(), such
 * as that used by Solaris, ignores the buffer pointer that is past to
 * it, so we can't assume that a private copy has been made that won't
 * be trashed by another call to gl_control_strings() by another
 * GetLine object. So we make what may be a redundant private copy
 * of the string in gl->capmem.
 *
 * Input:
 *  gl         GetLine *  The resource object of gl_get_line().
 *  name    const char *  The name of the terminfo string to look up.
 * Input/Output:
 *  bufptr        char ** On input *bufptr points to the location in
 *                        gl->tgetstr_buf at which to record the
 *                        capability string. On output *bufptr is
 *                        incremented over the stored string.
 * Output:
 *  return  const char *  The local copy of the capability, or NULL
 *                        on error.
 */
static const char *gl_tgetstr(GetLine *gl, const char *name, char **bufptr)
{
  const char *value = tgetstr((char *)name, bufptr);
  if(!value || value == (char *) -1)
    return NULL;
  return _sg_store_string(gl->capmem, value, 0);
}
#endif

/*.......................................................................
 * This is an action function that implements a user interrupt (eg. ^C).
 */
static KT_KEY_FN(gl_user_interrupt)
{
  raise(SIGINT);
  return 1;
}

/*.......................................................................
 * This is an action function that implements the abort signal.
 */
static KT_KEY_FN(gl_abort)
{
  raise(SIGABRT);
  return 1;
}

/*.......................................................................
 * This is an action function that sends a suspend signal (eg. ^Z) to the
 * the parent process.
 */
static KT_KEY_FN(gl_suspend)
{
  raise(SIGTSTP);
  return 0;
}

/*.......................................................................
 * This is an action function that halts output to the terminal.
 */
static KT_KEY_FN(gl_stop_output)
{
  tcflow(gl->output_fd, TCOOFF);
  return 0;
}

/*.......................................................................
 * This is an action function that resumes halted terminal output.
 */
static KT_KEY_FN(gl_start_output)
{
  tcflow(gl->output_fd, TCOON);
  return 0;
}

/*.......................................................................
 * This is an action function that allows the next character to be accepted
 * without any interpretation as a special character.
 */
static KT_KEY_FN(gl_literal_next)
{
  char c;   /* The character to be added to the line */
  int i;
/*
 * Get the character to be inserted literally.
 */
  if(gl_read_terminal(gl, 1, &c))
    return 1;
/*
 * Add the character to the line 'count' times.
 */
  for(i=0; i<count; i++)
    gl_add_char_to_line(gl, c);
  return 0;
}

/*.......................................................................
 * Return the width of a tab character at a given position when
 * displayed at a given position on the terminal. This is needed
 * because the width of tab characters depends on where they are,
 * relative to the preceding tab stops.
 *
 * Input:
 *  gl       GetLine *  The resource object of this library.
 *  term_curpos  int    The destination terminal location of the character.
 * Output:
 *  return       int    The number of terminal charaters needed.
 */
static int gl_displayed_tab_width(GetLine *gl, int term_curpos)
{
  return TAB_WIDTH - ((term_curpos % gl->ncolumn) % TAB_WIDTH);
}

/*.......................................................................
 * Return the number of characters needed to display a given character
 * on the screen. Tab characters require eight spaces, and control
 * characters are represented by a caret followed by the modified
 * character.
 *
 * Input:
 *  gl       GetLine *  The resource object of this library.
 *  c           char    The character to be displayed.
 *  term_curpos  int    The destination terminal location of the character.
 *                      This is needed because the width of tab characters
 *                      depends on where they are, relative to the
 *                      preceding tab stops.
 * Output:
 *  return       int    The number of terminal charaters needed.
 */
static int gl_displayed_char_width(GetLine *gl, char c, int term_curpos)
{
  if(c=='\t')
    return gl_displayed_tab_width(gl, term_curpos);
  if(IS_CTRL_CHAR(c))
    return 2;
  if(!isprint((int)(unsigned char) c))
    return gl_octal_width((int)(unsigned char)c) + 1;
  return 1;
}


/*.......................................................................
 * Work out the length of given string of characters on the terminal.
 *
 * Input:
 *  gl       GetLine *  The resource object of this library.
 *  string      char *  The string to be measured.
 *  nc           int    The number of characters to be measured, or -1
 *                      to measure the whole string.
 *  term_curpos  int    The destination terminal location of the character.
 *                      This is needed because the width of tab characters
 *                      depends on where they are, relative to the
 *                      preceding tab stops.
 * Output:
 *  return       int    The number of displayed characters.
 */
static int gl_displayed_string_width(GetLine *gl, const char *string, int nc,
				     int term_curpos)
{
  int slen = 0;   /* The displayed number of characters */
  int i;
/*
 * How many characters are to be measured?
 */
  if(nc < 0)
    nc = strlen(string);
/*
 * Add up the length of the displayed string.
 */
  for(i=0; i<nc; i++)
    slen += gl_displayed_char_width(gl, string[i], term_curpos + slen);
  return slen;
}

/*.......................................................................
 * Write a string verbatim to the current terminal or output stream.
 *
 * Note that when async-signal safety is required, the 'buffered'
 * argument must be 0, and n must not be -1.
 *
 * Input:
 *  gl         GetLine *  The resource object of the gl_get_line().
 *  buffered       int    If true, used buffered I/O when writing to
 *                        the terminal. Otherwise use async-signal-safe
 *                        unbuffered I/O.
 *  string  const char *  The string to be written (this need not be
 *                        '\0' terminated unless n<0).
 *  n              int    The number of characters to write from the
 *                        prefix of string[], or -1 to request that
 *                        gl_print_raw_string() use strlen() to figure
 *                        out the length.
 * Output:
 *  return         int    0 - OK.
 *                        1 - Error.
 */
static int gl_print_raw_string(GetLine *gl, int buffered,
			       const char *string, int n)
{
  GlWriteFn *write_fn = buffered ? gl_write_fn : gl->flush_fn;
/*
 * Only display output when echoing is turned on.
 */
  if(gl->echo) {
    int ndone = 0;   /* The number of characters written so far */
/*
 * When using un-buffered I/O, flush pending output first.
 */
    if(!buffered) {
      if(gl_flush_output(gl))
	return 1;
    };
/*
 * If no length has been provided, measure the length of the string.
 */
    if(n < 0)
      n = strlen(string);
/*
 * Write the string.
 */
    if(write_fn(gl, string + ndone, n-ndone) != n)
      return 1;
  };
  return 0;
}

/*.......................................................................
 * Output a terminal control sequence. When using terminfo,
 * this must be a sequence returned by tgetstr() or tigetstr()
 * respectively.
 *
 * Input:
 *  gl     GetLine *   The resource object of this library.
 *  nline      int     The number of lines affected by the operation,
 *                     or 1 if not relevant.
 *  string    char *   The control sequence to be sent.
 * Output:
 *  return     int     0 - OK.
 *                     1 - Error.
 */
static int gl_print_control_sequence(GetLine *gl, int nline, const char *string)
{
  int waserr = 0;   /* True if an error occurs */
/*
 * Only write characters to the terminal when echoing is enabled.
 */
  if(gl->echo) {
#if defined(USE_TERMINFO) || defined(USE_TERMCAP)
    tputs_gl = gl;
    errno = 0;
    tputs((char *)string, nline, gl_tputs_putchar);
    waserr = errno != 0;
#else
    waserr = gl_print_raw_string(gl, 1, string, -1);
#endif
  };
  return waserr;
}

#if defined(USE_TERMINFO) || defined(USE_TERMCAP)
/*.......................................................................
 * The following callback function is called by tputs() to output a raw
 * control character to the terminal.
 */
static TputsRetType gl_tputs_putchar(TputsArgType c)
{
  char ch = c;
#if TPUTS_RETURNS_VALUE
  return gl_print_raw_string(tputs_gl, 1, &ch, 1);
#else
  (void) gl_print_raw_string(tputs_gl, 1, &ch, 1);
#endif
}
#endif

/*.......................................................................
 * Move the terminal cursor n characters to the left or right.
 *
 * Input:
 *  gl     GetLine *   The resource object of this program.
 *  n          int     number of positions to the right (> 0) or left (< 0).
 * Output:
 *  return     int     0 - OK.
 *                     1 - Error.
 */
static int gl_terminal_move_cursor(GetLine *gl, int n)
{
  int cur_row, cur_col; /* The current terminal row and column index of */
                        /*  the cursor wrt the start of the input line. */
  int new_row, new_col; /* The target terminal row and column index of */
                        /*  the cursor wrt the start of the input line. */
/*
 * Do nothing if the input line isn't currently displayed. In this
 * case, the cursor will be moved to the right place when the line
 * is next redisplayed.
 */
  if(!gl->displayed)
    return 0;
/*
 * How far can we move left?
 */
  if(gl->term_curpos + n < 0)
    n = gl->term_curpos;
/*
 * Break down the current and target cursor locations into rows and columns.
 */
  cur_row = gl->term_curpos / gl->ncolumn;
  cur_col = gl->term_curpos % gl->ncolumn;
  new_row = (gl->term_curpos + n) / gl->ncolumn;
  new_col = (gl->term_curpos + n) % gl->ncolumn;
/*
 * Move down to the next line.
 */
  for(; cur_row < new_row; cur_row++) {
    if(gl_print_control_sequence(gl, 1, gl->down))
      return 1;
  };
/*
 * Move up to the previous line.
 */
  for(; cur_row > new_row; cur_row--) {
    if(gl_print_control_sequence(gl, 1, gl->up))
      return 1;
  };
/*
 * Move to the right within the target line?
 */
  if(cur_col < new_col) {
#ifdef USE_TERMINFO
/*
 * Use a parameterized control sequence if it generates less control
 * characters (guess based on ANSI terminal termcap entry).
 */
    if(gl->right_n != NULL && new_col - cur_col > 1) {
      if(gl_print_control_sequence(gl, 1, tparm((char *)gl->right_n,
           (long)(new_col - cur_col), 0l, 0l, 0l, 0l, 0l, 0l, 0l, 0l)))
	return 1;
    } else
#endif
    {
      for(; cur_col < new_col; cur_col++) {
        if(gl_print_control_sequence(gl, 1, gl->right))
          return 1;
      };
    };
/*
 * Move to the left within the target line?
 */
  } else if(cur_col > new_col) {
#ifdef USE_TERMINFO
/*
 * Use a parameterized control sequence if it generates less control
 * characters (guess based on ANSI terminal termcap entry).
 */
    if(gl->left_n != NULL && cur_col - new_col > 3) {
      if(gl_print_control_sequence(gl, 1, tparm((char *)gl->left_n,
           (long)(cur_col - new_col), 0l, 0l, 0l, 0l, 0l, 0l, 0l, 0l)))
	return 1;
    } else
#endif
    {
      for(; cur_col > new_col; cur_col--) {
        if(gl_print_control_sequence(gl, 1, gl->left))
          return 1;
      };
    };
  }
/*
 * Update the recorded position of the terminal cursor.
 */
  gl->term_curpos += n;
  return 0;
}

/*.......................................................................
 * Write a character to the terminal after expanding tabs and control
 * characters to their multi-character representations.
 *
 * Input:
 *  gl    GetLine *   The resource object of this program.
 *  c        char     The character to be output.
 *  pad      char     Many terminals have the irritating feature that
 *                    when one writes a character in the last column of
 *                    of the terminal, the cursor isn't wrapped to the
 *                    start of the next line until one more character
 *                    is written. Some terminals don't do this, so
 *                    after such a write, we don't know where the
 *                    terminal is unless we output an extra character.
 *                    This argument specifies the character to write.
 *                    If at the end of the input line send '\0' or a
 *                    space, and a space will be written. Otherwise,
 *                    pass the next character in the input line
 *                    following the one being written.
 * Output:
 *  return    int     0 - OK.
 */
static int gl_print_char(GetLine *gl, char c, char pad)
{
  char string[TAB_WIDTH + 4]; /* A work area for composing compound strings */
  int nchar;                  /* The number of terminal characters */
  int i;
/*
 * Check for special characters.
 */
  if(c == '\t') {
/*
 * How many spaces do we need to represent a tab at the current terminal
 * column?
 */
    nchar = gl_displayed_tab_width(gl, gl->term_curpos);
/*
 * Compose the tab string.
 */
    for(i=0; i<nchar; i++)
      string[i] = ' ';
  } else if(IS_CTRL_CHAR(c)) {
    string[0] = '^';
    string[1] = CTRL_TO_CHAR(c);
    nchar = 2;
  } else if(!isprint((int)(unsigned char) c)) {
    snprintf(string, sizeof(string), "\\%o", (int)(unsigned char)c);
    nchar = strlen(string);
  } else {
    string[0] = c;
    nchar = 1;
  };
/*
 * Terminate the string.
 */
  string[nchar] = '\0';
/*
 * Write the string to the terminal.
 */
  if(gl_print_raw_string(gl, 1, string, -1))
    return 1;
/*
 * Except for one exception to be described in a moment, the cursor should
 * now have been positioned after the character that was just output.
 */
  gl->term_curpos += nchar;
/*
 * Keep a record of the number of characters in the terminal version
 * of the input line.
 */
  if(gl->term_curpos > gl->term_len)
    gl->term_len = gl->term_curpos;
/*
 * If the new character ended exactly at the end of a line,
 * most terminals won't move the cursor onto the next line until we
 * have written a character on the next line, so append an extra
 * space then move the cursor back.
 */
  if(gl->term_curpos % gl->ncolumn == 0) {
    int term_curpos = gl->term_curpos;
    if(gl_print_char(gl, pad ? pad : ' ', ' ') ||
       gl_set_term_curpos(gl, term_curpos))
      return 1;
  };
  return 0;
}

/*.......................................................................
 * Write a string to the terminal after expanding tabs and control
 * characters to their multi-character representations.
 *
 * Input:
 *  gl    GetLine *   The resource object of this program.
 *  string   char *   The string to be output.
 *  pad      char     Many terminals have the irritating feature that
 *                    when one writes a character in the last column of
 *                    of the terminal, the cursor isn't wrapped to the
 *                    start of the next line until one more character
 *                    is written. Some terminals don't do this, so
 *                    after such a write, we don't know where the
 *                    terminal is unless we output an extra character.
 *                    This argument specifies the character to write.
 *                    If at the end of the input line send '\0' or a
 *                    space, and a space will be written. Otherwise,
 *                    pass the next character in the input line
 *                    following the one being written.
 * Output:
 *  return    int     0 - OK.
 */
static int gl_print_string(GetLine *gl, const char *string, char pad)
{
  const char *cptr;   /* A pointer into string[] */
  for(cptr=string; *cptr; cptr++) {
    char nextc = cptr[1];
    if(gl_print_char(gl, *cptr, nextc ? nextc : pad))
      return 1;
  };
  return 0;
}

/*.......................................................................
 * Move the terminal cursor position.
 *
 * Input:
 *  gl      GetLine *  The resource object of this library.
 *  term_curpos int    The destination terminal cursor position.
 * Output:
 *  return      int    0 - OK.
 *                     1 - Error.
 */
static int gl_set_term_curpos(GetLine *gl, int term_curpos)
{
  return gl_terminal_move_cursor(gl, term_curpos - gl->term_curpos);
}

/*.......................................................................
 * This is an action function that moves the buffer cursor one character
 * left, and updates the terminal cursor to match.
 */
static KT_KEY_FN(gl_cursor_left)
{
  return gl_place_cursor(gl, gl->buff_curpos - count);
}

/*.......................................................................
 * This is an action function that moves the buffer cursor one character
 * right, and updates the terminal cursor to match.
 */
static KT_KEY_FN(gl_cursor_right)
{
  return gl_place_cursor(gl, gl->buff_curpos + count);
}

/*.......................................................................
 * This is an action function that toggles between overwrite and insert
 * mode.
 */
static KT_KEY_FN(gl_insert_mode)
{
  gl->insert = !gl->insert;
  return 0;
}

/*.......................................................................
 * This is an action function which moves the cursor to the beginning of
 * the line.
 */
static KT_KEY_FN(gl_beginning_of_line)
{
  return gl_place_cursor(gl, 0);
}

/*.......................................................................
 * This is an action function which moves the cursor to the end of
 * the line.
 */
static KT_KEY_FN(gl_end_of_line)
{
  return gl_place_cursor(gl, gl->ntotal);
}

/*.......................................................................
 * This is an action function which deletes the entire contents of the
 * current line.
 */
static KT_KEY_FN(gl_delete_line)
{
/*
 * If in vi command mode, preserve the current line for potential
 * use by vi-undo.
 */
  gl_save_for_undo(gl);
/*
 * Copy the contents of the line to the cut buffer.
 */
  strlcpy(gl->cutbuf, gl->line, gl->linelen);
/*
 * Clear the buffer.
 */
  gl_truncate_buffer(gl, 0);
/*
 * Move the terminal cursor to just after the prompt.
 */
  if(gl_place_cursor(gl, 0))
    return 1;
/*
 * Clear from the end of the prompt to the end of the terminal.
 */
  if(gl_truncate_display(gl))
    return 1;
  return 0;
}

/*.......................................................................
 * This is an action function which deletes all characters between the
 * current cursor position and the end of the line.
 */
static KT_KEY_FN(gl_kill_line)
{
/*
 * If in vi command mode, preserve the current line for potential
 * use by vi-undo.
 */
  gl_save_for_undo(gl);
/*
 * Copy the part of the line that is about to be deleted to the cut buffer.
 */
  strlcpy(gl->cutbuf, gl->line + gl->buff_curpos, gl->linelen);
/*
 * Terminate the buffered line at the current cursor position.
 */
  gl_truncate_buffer(gl, gl->buff_curpos);
/*
 * Clear the part of the line that follows the cursor.
 */
  if(gl_truncate_display(gl))
    return 1;
/*
 * Explicitly reset the cursor position to allow vi command mode
 * constraints on its position to be set.
 */
  return gl_place_cursor(gl, gl->buff_curpos);
}

/*.......................................................................
 * This is an action function which deletes all characters between the
 * start of the line and the current cursor position.
 */
static KT_KEY_FN(gl_backward_kill_line)
{
/*
 * How many characters are to be deleted from before the cursor?
 */
  int nc = gl->buff_curpos - gl->insert_curpos;
  if (!nc)
    return 0;
/*
 * Move the cursor to the start of the line, or in vi input mode,
 * the start of the sub-line at which insertion started, and delete
 * up to the old cursor position.
 */
  return gl_place_cursor(gl, gl->insert_curpos) ||
         gl_delete_chars(gl, nc, gl->editor == GL_EMACS_MODE || gl->vi.command);
}

/*.......................................................................
 * This is an action function which moves the cursor forward by a word.
 */
static KT_KEY_FN(gl_forward_word)
{
  return gl_place_cursor(gl, gl_nth_word_end_forward(gl, count) +
			 (gl->editor==GL_EMACS_MODE));
}

/*.......................................................................
 * This is an action function which moves the cursor forward to the start
 * of the next word.
 */
static KT_KEY_FN(gl_forward_to_word)
{
  return gl_place_cursor(gl, gl_nth_word_start_forward(gl, count));
}

/*.......................................................................
 * This is an action function which moves the cursor backward by a word.
 */
static KT_KEY_FN(gl_backward_word)
{
  return gl_place_cursor(gl, gl_nth_word_start_backward(gl, count));
}

/*.......................................................................
 * Delete one or more characters, starting with the one under the cursor.
 *
 * Input:
 *  gl     GetLine *  The resource object of this library.
 *  nc         int    The number of characters to delete.
 *  cut        int    If true, copy the characters to the cut buffer.
 * Output:
 *  return     int    0 - OK.
 *                    1 - Error.
 */
static int gl_delete_chars(GetLine *gl, int nc, int cut)
{
/*
 * If in vi command mode, preserve the current line for potential
 * use by vi-undo.
 */
  gl_save_for_undo(gl);
/*
 * If there are fewer than nc characters following the cursor, limit
 * nc to the number available.
 */
  if(gl->buff_curpos + nc > gl->ntotal)
    nc = gl->ntotal - gl->buff_curpos;
/*
 * Copy the about to be deleted region to the cut buffer.
 */
  if(cut) {
    memcpy(gl->cutbuf, gl->line + gl->buff_curpos, nc);
    gl->cutbuf[nc] = '\0';
  }
/*
 * Nothing to delete?
 */
  if(nc <= 0)
    return 0;
/*
 * In vi overwrite mode, restore any previously overwritten characters
 * from the undo buffer.
 */
  if(gl->editor == GL_VI_MODE && !gl->vi.command && !gl->insert) {
/*
 * How many of the characters being deleted can be restored from the
 * undo buffer?
 */
    int nrestore = gl->buff_curpos + nc <= gl->vi.undo.ntotal ?
      nc : gl->vi.undo.ntotal - gl->buff_curpos;
/*
 * Restore any available characters.
 */
    if(nrestore > 0) {
      gl_buffer_string(gl, gl->vi.undo.line + gl->buff_curpos, nrestore,
		       gl->buff_curpos);
    };
/*
 * If their were insufficient characters in the undo buffer, then this
 * implies that we are deleting from the end of the line, so we need
 * to terminate the line either where the undo buffer ran out, or if
 * we are deleting from beyond the end of the undo buffer, at the current
 * cursor position.
 */
    if(nc != nrestore) {
      gl_truncate_buffer(gl, (gl->vi.undo.ntotal > gl->buff_curpos) ?
			 gl->vi.undo.ntotal : gl->buff_curpos);
    };
  } else {
/*
 * Copy the remaining part of the line back over the deleted characters.
 */
    gl_remove_from_buffer(gl, gl->buff_curpos, nc);
  };
/*
 * Redraw the remaining characters following the cursor.
 */
  if(gl_print_string(gl, gl->line + gl->buff_curpos, '\0'))
    return 1;
/*
 * Clear to the end of the terminal.
 */
  if(gl_truncate_display(gl))
    return 1;
/*
 * Place the cursor at the start of where the deletion was performed.
 */
  return gl_place_cursor(gl, gl->buff_curpos);
}

/*.......................................................................
 * This is an action function which deletes character(s) under the
 * cursor without moving the cursor.
 */
static KT_KEY_FN(gl_forward_delete_char)
{
/*
 * Delete 'count' characters.
 */
  return gl_delete_chars(gl, count, gl->vi.command);
}

/*.......................................................................
 * This is an action function which deletes character(s) under the
 * cursor and moves the cursor back one character.
 */
static KT_KEY_FN(gl_backward_delete_char)
{
/*
 * Restrict the deletion count to the number of characters that
 * precede the insertion point.
 */
  if(count > gl->buff_curpos - gl->insert_curpos)
    count = gl->buff_curpos - gl->insert_curpos;
/*
 * If in vi command mode, preserve the current line for potential
 * use by vi-undo.
 */
  gl_save_for_undo(gl);
  return gl_cursor_left(gl, count, NULL) ||
    gl_delete_chars(gl, count, gl->vi.command);
}

/*.......................................................................
 * Starting from the cursor position delete to the specified column.
 */
static KT_KEY_FN(gl_delete_to_column)
{
  if (--count >= gl->buff_curpos)
    return gl_forward_delete_char(gl, count - gl->buff_curpos, NULL);
  else
    return gl_backward_delete_char(gl, gl->buff_curpos - count, NULL);
}

/*.......................................................................
 * Starting from the cursor position delete characters to a matching
 * parenthesis.
 */
static KT_KEY_FN(gl_delete_to_parenthesis)
{
  int curpos = gl_index_of_matching_paren(gl);
  if(curpos >= 0) {
    gl_save_for_undo(gl);
    if(curpos >= gl->buff_curpos)
      return gl_forward_delete_char(gl, curpos - gl->buff_curpos + 1, NULL);
    else
      return gl_backward_delete_char(gl, ++gl->buff_curpos - curpos + 1, NULL);
  };
  return 0;
}

/*.......................................................................
 * This is an action function which deletes from the cursor to the end
 * of the word that the cursor is either in or precedes.
 */
static KT_KEY_FN(gl_forward_delete_word)
{
/*
 * If in vi command mode, preserve the current line for potential
 * use by vi-undo.
 */
  gl_save_for_undo(gl);
/*
 * In emacs mode delete to the end of the word. In vi mode delete to the
 * start of the net word.
 */
  if(gl->editor == GL_EMACS_MODE) {
    return gl_delete_chars(gl,
		gl_nth_word_end_forward(gl,count) - gl->buff_curpos + 1, 1);
  } else {
    return gl_delete_chars(gl,
		gl_nth_word_start_forward(gl,count) - gl->buff_curpos,
		gl->vi.command);
  };
}

/*.......................................................................
 * This is an action function which deletes the word that precedes the
 * cursor.
 */
static KT_KEY_FN(gl_backward_delete_word)
{
/*
 * Keep a record of the current cursor position.
 */
  int buff_curpos = gl->buff_curpos;
/*
 * If in vi command mode, preserve the current line for potential
 * use by vi-undo.
 */
  gl_save_for_undo(gl);
/*
 * Move back 'count' words.
 */
  if(gl_backward_word(gl, count, NULL))
    return 1;
/*
 * Delete from the new cursor position to the original one.
 */
  return gl_delete_chars(gl, buff_curpos - gl->buff_curpos,
  			 gl->editor == GL_EMACS_MODE || gl->vi.command);
}

/*.......................................................................
 * Searching in a given direction, delete to the count'th
 * instance of a specified or queried character, in the input line.
 *
 * Input:
 *  gl       GetLine *  The getline resource object.
 *  count        int    The number of times to search.
 *  c           char    The character to be searched for, or '\0' if
 *                      the character should be read from the user.
 *  forward      int    True if searching forward.
 *  onto         int    True if the search should end on top of the
 *                      character, false if the search should stop
 *                      one character before the character in the
 *                      specified search direction.
 *  change       int    If true, this function is being called upon
 *                      to do a vi change command, in which case the
 *                      user will be left in insert mode after the
 *                      deletion.
 * Output:
 *  return       int    0 - OK.
 *                      1 - Error.
 */
static int gl_delete_find(GetLine *gl, int count, char c, int forward,
			  int onto, int change)
{
/*
 * Search for the character, and abort the deletion if not found.
 */
  int pos = gl_find_char(gl, count, forward, onto, c);
  if(pos < 0)
    return 0;
/*
 * If in vi command mode, preserve the current line for potential
 * use by vi-undo.
 */
  gl_save_for_undo(gl);
/*
 * Allow the cursor to be at the end of the line if this is a change
 * command.
 */
  if(change)
    gl->vi.command = 0;
/*
 * Delete the appropriate span of characters.
 */
  if(forward) {
    if(gl_delete_chars(gl, pos - gl->buff_curpos + 1, 1))
      return 1;
  } else {
    int buff_curpos = gl->buff_curpos;
    if(gl_place_cursor(gl, pos) ||
       gl_delete_chars(gl, buff_curpos - gl->buff_curpos, 1))
      return 1;
  };
/*
 * If this is a change operation, switch the insert mode.
 */
  if(change && gl_vi_insert(gl, 0, NULL))
    return 1;
  return 0;
}

/*.......................................................................
 * This is an action function which deletes forward from the cursor up to and
 * including a specified character.
 */
static KT_KEY_FN(gl_forward_delete_find)
{
  return gl_delete_find(gl, count, '\0', 1, 1, 0);
}

/*.......................................................................
 * This is an action function which deletes backward from the cursor back to
 * and including a specified character.
 */
static KT_KEY_FN(gl_backward_delete_find)
{
  return gl_delete_find(gl, count, '\0', 0, 1, 0);
}

/*.......................................................................
 * This is an action function which deletes forward from the cursor up to but
 * not including a specified character.
 */
static KT_KEY_FN(gl_forward_delete_to)
{
  return gl_delete_find(gl, count, '\0', 1, 0, 0);
}

/*.......................................................................
 * This is an action function which deletes backward from the cursor back to
 * but not including a specified character.
 */
static KT_KEY_FN(gl_backward_delete_to)
{
  return gl_delete_find(gl, count, '\0', 0, 0, 0);
}

/*.......................................................................
 * This is an action function which deletes to a character specified by a
 * previous search.
 */
static KT_KEY_FN(gl_delete_refind)
{
  return gl_delete_find(gl, count, gl->vi.find_char, gl->vi.find_forward,
			gl->vi.find_onto, 0);
}

/*.......................................................................
 * This is an action function which deletes to a character specified by a
 * previous search, but in the opposite direction.
 */
static KT_KEY_FN(gl_delete_invert_refind)
{
  return gl_delete_find(gl, count, gl->vi.find_char,
			!gl->vi.find_forward, gl->vi.find_onto, 0);
}

/*.......................................................................
 * This is an action function which converts the characters in the word
 * following the cursor to upper case.
 */
static KT_KEY_FN(gl_upcase_word)
{
/*
 * Locate the count'th word ending after the cursor.
 */
  int last = gl_nth_word_end_forward(gl, count);
/*
 * If in vi command mode, preserve the current line for potential
 * use by vi-undo.
 */
  gl_save_for_undo(gl);
/*
 * Upcase characters from the current cursor position to 'last'.
 */
  while(gl->buff_curpos <= last) {
    char *cptr = gl->line + gl->buff_curpos;
/*
 * Convert the character to upper case?
 */
    if(islower((int)(unsigned char) *cptr))
      gl_buffer_char(gl, toupper((int) *cptr), gl->buff_curpos);
    gl->buff_curpos++;
/*
 * Write the possibly modified character back. Note that for non-modified
 * characters we want to do this as well, so as to advance the cursor.
 */
    if(gl_print_char(gl, *cptr, cptr[1]))
      return 1;
  };
  return gl_place_cursor(gl, gl->buff_curpos);	/* bounds check */
}

/*.......................................................................
 * This is an action function which converts the characters in the word
 * following the cursor to lower case.
 */
static KT_KEY_FN(gl_downcase_word)
{
/*
 * Locate the count'th word ending after the cursor.
 */
  int last = gl_nth_word_end_forward(gl, count);
/*
 * If in vi command mode, preserve the current line for potential
 * use by vi-undo.
 */
  gl_save_for_undo(gl);
/*
 * Upcase characters from the current cursor position to 'last'.
 */
  while(gl->buff_curpos <= last) {
    char *cptr = gl->line + gl->buff_curpos;
/*
 * Convert the character to upper case?
 */
    if(isupper((int)(unsigned char) *cptr))
      gl_buffer_char(gl, tolower((int) *cptr), gl->buff_curpos);
    gl->buff_curpos++;
/*
 * Write the possibly modified character back. Note that for non-modified
 * characters we want to do this as well, so as to advance the cursor.
 */
    if(gl_print_char(gl, *cptr, cptr[1]))
      return 1;
  };
  return gl_place_cursor(gl, gl->buff_curpos);	/* bounds check */
}

/*.......................................................................
 * This is an action function which converts the first character of the
 * following word to upper case, in order to capitalize the word, and
 * leaves the cursor at the end of the word.
 */
static KT_KEY_FN(gl_capitalize_word)
{
  char *cptr;   /* &gl->line[gl->buff_curpos] */
  int first;    /* True for the first letter of the word */
  int i;
/*
 * Keep a record of the current insert mode and the cursor position.
 */
  int insert = gl->insert;
/*
 * If in vi command mode, preserve the current line for potential
 * use by vi-undo.
 */
  gl_save_for_undo(gl);
/*
 * We want to overwrite the modified word.
 */
  gl->insert = 0;
/*
 * Capitalize 'count' words.
 */
  for(i=0; i<count && gl->buff_curpos < gl->ntotal; i++) {
    int pos = gl->buff_curpos;
/*
 * If we are not already within a word, skip to the start of the word.
 */
    for(cptr = gl->line + pos ; pos<gl->ntotal && !gl_is_word_char((int) *cptr);
	pos++, cptr++)
      ;
/*
 * Move the cursor to the new position.
 */
    if(gl_place_cursor(gl, pos))
      return 1;
/*
 * While searching for the end of the word, change lower case letters
 * to upper case.
 */
    for(first=1; gl->buff_curpos<gl->ntotal && gl_is_word_char((int) *cptr);
	gl->buff_curpos++, cptr++) {
/*
 * Convert the character to upper case?
 */
      if(first) {
	if(islower((int)(unsigned char) *cptr))
	  gl_buffer_char(gl, toupper((int) *cptr), cptr - gl->line);
      } else {
	if(isupper((int)(unsigned char) *cptr))
	  gl_buffer_char(gl, tolower((int) *cptr), cptr - gl->line);
      };
      first = 0;
/*
 * Write the possibly modified character back. Note that for non-modified
 * characters we want to do this as well, so as to advance the cursor.
 */
      if(gl_print_char(gl, *cptr, cptr[1]))
	return 1;
    };
  };
/*
 * Restore the insertion mode.
 */
  gl->insert = insert;
  return gl_place_cursor(gl, gl->buff_curpos);	/* bounds check */
}

/*.......................................................................
 * This is an action function which redraws the current line.
 */
static KT_KEY_FN(gl_redisplay)
{
/*
 * Keep a record of the current cursor position.
 */
  int buff_curpos = gl->buff_curpos;
/*
 * Do nothing if there is no line to be redisplayed.
 */
  if(gl->endline)
    return 0;
/*
 * Erase the current input line.
 */
  if(gl_erase_line(gl))
    return 1;
/*
 * Display the current prompt.
 */
  if(gl_display_prompt(gl))
    return 1;
/*
 * Render the part of the line that the user has typed in so far.
 */
  if(gl_print_string(gl, gl->line, '\0'))
    return 1;
/*
 * Restore the cursor position.
 */
  if(gl_place_cursor(gl, buff_curpos))
    return 1;
/*
 * Mark the redisplay operation as having been completed.
 */
  gl->redisplay = 0;
/*
 * Flush the redisplayed line to the terminal.
 */
  return gl_flush_output(gl);
}

/*.......................................................................
 * This is an action function which clears the display and redraws the
 * input line from the home position.
 */
static KT_KEY_FN(gl_clear_screen)
{
/*
 * Home the cursor and clear from there to the end of the display.
 */
  if(gl_print_control_sequence(gl, gl->nline, gl->home) ||
     gl_print_control_sequence(gl, gl->nline, gl->clear_eod))
    return 1;
/*
 * The input line is no longer displayed.
 */
  gl_line_erased(gl);
/*
 * Arrange for the input line to be redisplayed.
 */
  gl_queue_redisplay(gl);
  return 0;
}

/*.......................................................................
 * This is an action function which swaps the character under the cursor
 * with the character to the left of the cursor.
 */
static KT_KEY_FN(gl_transpose_chars)
{
  char from[3];     /* The original string of 2 characters */
  char swap[3];     /* The swapped string of two characters */
/*
 * If we are at the beginning or end of the line, there aren't two
 * characters to swap.
 */
  if(gl->buff_curpos < 1 || gl->buff_curpos >= gl->ntotal)
    return 0;
/*
 * If in vi command mode, preserve the current line for potential
 * use by vi-undo.
 */
  gl_save_for_undo(gl);
/*
 * Get the original and swapped strings of the two characters.
 */
  from[0] = gl->line[gl->buff_curpos - 1];
  from[1] = gl->line[gl->buff_curpos];
  from[2] = '\0';
  swap[0] = gl->line[gl->buff_curpos];
  swap[1] = gl->line[gl->buff_curpos - 1];
  swap[2] = '\0';
/*
 * Move the cursor to the start of the two characters.
 */
  if(gl_place_cursor(gl, gl->buff_curpos-1))
    return 1;
/*
 * Swap the two characters in the buffer.
 */
  gl_buffer_char(gl, swap[0], gl->buff_curpos);
  gl_buffer_char(gl, swap[1], gl->buff_curpos+1);
/*
 * If the sum of the displayed width of the two characters
 * in their current and final positions is the same, swapping can
 * be done by just overwriting with the two swapped characters.
 */
  if(gl_displayed_string_width(gl, from, -1, gl->term_curpos) ==
     gl_displayed_string_width(gl, swap, -1, gl->term_curpos)) {
    int insert = gl->insert;
    gl->insert = 0;
    if(gl_print_char(gl, swap[0], swap[1]) ||
       gl_print_char(gl, swap[1], gl->line[gl->buff_curpos+2]))
      return 1;
    gl->insert = insert;
/*
 * If the swapped substring has a different displayed size, we need to
 * redraw everything after the first of the characters.
 */
  } else {
    if(gl_print_string(gl, gl->line + gl->buff_curpos, '\0') ||
       gl_truncate_display(gl))
      return 1;
  };
/*
 * Advance the cursor to the character after the swapped pair.
 */
  return gl_place_cursor(gl, gl->buff_curpos + 2);
}

/*.......................................................................
 * This is an action function which sets a mark at the current cursor
 * location.
 */
static KT_KEY_FN(gl_set_mark)
{
  gl->buff_mark = gl->buff_curpos;
  return 0;
}

/*.......................................................................
 * This is an action function which swaps the mark location for the
 * cursor location.
 */
static KT_KEY_FN(gl_exchange_point_and_mark)
{
/*
 * Get the old mark position, and limit to the extent of the input
 * line.
 */
  int old_mark = gl->buff_mark <= gl->ntotal ? gl->buff_mark : gl->ntotal;
/*
 * Make the current cursor position the new mark.
 */
  gl->buff_mark = gl->buff_curpos;
/*
 * Move the cursor to the old mark position.
 */
  return gl_place_cursor(gl, old_mark);
}

/*.......................................................................
 * This is an action function which deletes the characters between the
 * mark and the cursor, recording them in gl->cutbuf for later pasting.
 */
static KT_KEY_FN(gl_kill_region)
{
/*
 * If in vi command mode, preserve the current line for potential
 * use by vi-undo.
 */
  gl_save_for_undo(gl);
/*
 * Limit the mark to be within the line.
 */
  if(gl->buff_mark > gl->ntotal)
    gl->buff_mark = gl->ntotal;
/*
 * If there are no characters between the cursor and the mark, simply clear
 * the cut buffer.
 */
  if(gl->buff_mark == gl->buff_curpos) {
    gl->cutbuf[0] = '\0';
    return 0;
  };
/*
 * If the mark is before the cursor, swap the cursor and the mark.
 */
  if(gl->buff_mark < gl->buff_curpos && gl_exchange_point_and_mark(gl,1,NULL))
    return 1;
/*
 * Delete the characters.
 */
  if(gl_delete_chars(gl, gl->buff_mark - gl->buff_curpos, 1))
    return 1;
/*
 * Make the mark the same as the cursor position.
 */
  gl->buff_mark = gl->buff_curpos;
  return 0;
}

/*.......................................................................
 * This is an action function which records the characters between the
 * mark and the cursor, in gl->cutbuf for later pasting.
 */
static KT_KEY_FN(gl_copy_region_as_kill)
{
  int ca, cb;  /* The indexes of the first and last characters in the region */
  int mark;    /* The position of the mark */
/*
 * Get the position of the mark, limiting it to lie within the line.
 */
  mark = gl->buff_mark > gl->ntotal ? gl->ntotal : gl->buff_mark;
/*
 * If there are no characters between the cursor and the mark, clear
 * the cut buffer.
 */
  if(mark == gl->buff_curpos) {
    gl->cutbuf[0] = '\0';
    return 0;
  };
/*
 * Get the line indexes of the first and last characters in the region.
 */
  if(mark < gl->buff_curpos) {
    ca = mark;
    cb = gl->buff_curpos - 1;
  } else {
    ca = gl->buff_curpos;
    cb = mark - 1;
  };
/*
 * Copy the region to the cut buffer.
 */
  memcpy(gl->cutbuf, gl->line + ca, cb + 1 - ca);
  gl->cutbuf[cb + 1 - ca] = '\0';
  return 0;
}

/*.......................................................................
 * This is an action function which inserts the contents of the cut
 * buffer at the current cursor location.
 */
static KT_KEY_FN(gl_yank)
{
  int i;
/*
 * Set the mark at the current location.
 */
  gl->buff_mark = gl->buff_curpos;
/*
 * Do nothing else if the cut buffer is empty.
 */
  if(gl->cutbuf[0] == '\0')
    return gl_ring_bell(gl, 1, NULL);
/*
 * If in vi command mode, preserve the current line for potential
 * use by vi-undo.
 */
  gl_save_for_undo(gl);
/*
 * Insert the string count times.
 */
  for(i=0; i<count; i++) {
    if(gl_add_string_to_line(gl, gl->cutbuf))
      return 1;
  };
/*
 * gl_add_string_to_line() leaves the cursor after the last character that
 * was pasted, whereas vi leaves the cursor over the last character pasted.
 */
  if(gl->editor == GL_VI_MODE && gl_cursor_left(gl, 1, NULL))
    return 1;
  return 0;
}

/*.......................................................................
 * This is an action function which inserts the contents of the cut
 * buffer one character beyond the current cursor location.
 */
static KT_KEY_FN(gl_append_yank)
{
  int was_command = gl->vi.command;
  int i;
/*
 * If the cut buffer is empty, ring the terminal bell.
 */
  if(gl->cutbuf[0] == '\0')
    return gl_ring_bell(gl, 1, NULL);
/*
 * Set the mark at the current location + 1.
 */
  gl->buff_mark = gl->buff_curpos + 1;
/*
 * If in vi command mode, preserve the current line for potential
 * use by vi-undo.
 */
  gl_save_for_undo(gl);
/*
 * Arrange to paste the text in insert mode after the current character.
 */
  if(gl_vi_append(gl, 0, NULL))
    return 1;
/*
 * Insert the string count times.
 */
  for(i=0; i<count; i++) {
    if(gl_add_string_to_line(gl, gl->cutbuf))
      return 1;
  };
/*
 * Switch back to command mode if necessary.
 */
  if(was_command)
    gl_vi_command_mode(gl);
  return 0;
}

/*.......................................................................
 * Attempt to ask the terminal for its current size. On systems that
 * don't support the TIOCWINSZ ioctl() for querying the terminal size,
 * the current values of gl->ncolumn and gl->nrow are returned.
 *
 * Input:
 *  gl     GetLine *  The resource object of gl_get_line().
 * Input/Output:
 *  ncolumn    int *  The number of columns will be assigned to *ncolumn.
 *  nline      int *  The number of lines will be assigned to *nline.
 */
static void gl_query_size(GetLine *gl, int *ncolumn, int *nline)
{
#ifdef TIOCGWINSZ
/*
 * Query the new terminal window size. Ignore invalid responses.
 */
  struct winsize size;
  if(ioctl(gl->output_fd, TIOCGWINSZ, &size) == 0 &&
     size.ws_row > 0 && size.ws_col > 0) {
    *ncolumn = size.ws_col;
    *nline = size.ws_row;
    return;
  };
#endif
/*
 * Return the existing values.
 */
  *ncolumn = gl->ncolumn;
  *nline = gl->nline;
  return;
}

/*.......................................................................
 * Query the size of the terminal, and if it has changed, redraw the
 * current input line accordingly.
 *
 * Input:
 *  gl     GetLine *  The resource object of gl_get_line().
 * Output:
 *  return     int    0 - OK.
 *                    1 - Error.
 */
static int _gl_update_size(GetLine *gl)
{
  int ncolumn, nline;    /* The new size of the terminal */
/*
 * Query the new terminal window size.
 */
  gl_query_size(gl, &ncolumn, &nline);
/*
 * Update gl and the displayed line to fit the new dimensions.
 */
  return gl_handle_tty_resize(gl, ncolumn, nline);
}

/*.......................................................................
 * Redraw the current input line to account for a change in the terminal
 * size. Also install the new size in gl.
 *
 * Input:
 *  gl     GetLine *  The resource object of gl_get_line().
 *  ncolumn    int    The new number of columns.
 *  nline      int    The new number of lines.
 * Output:
 *  return     int    0 - OK.
 *                    1 - Error.
 */
static int gl_handle_tty_resize(GetLine *gl, int ncolumn, int nline)
{
/*
 * If the input device isn't a terminal, just record the new size.
 */
  if(!gl->is_term) {
    gl->nline = nline;
    gl->ncolumn = ncolumn;
/*
 * Has the size actually changed?
 */
  } else if(ncolumn != gl->ncolumn || nline != gl->nline) {
/*
 * If we are currently editing a line, erase it.
 */
    if(gl_erase_line(gl))
      return 1;
/*
 * Update the recorded window size.
 */
    gl->nline = nline;
    gl->ncolumn = ncolumn;
/*
 * Arrange for the input line to be redrawn before the next character
 * is read from the terminal.
 */
    gl_queue_redisplay(gl);
  };
  return 0;
}

/*.......................................................................
 * This is the action function that recalls the previous line in the
 * history buffer.
 */
static KT_KEY_FN(gl_up_history)
{
/*
 * In vi mode, switch to command mode, since the user is very
 * likely to want to move around newly recalled lines.
 */
  gl_vi_command_mode(gl);
/*
 * Forget any previous recall session.
 */
  gl->preload_id = 0;
/*
 * Record the key sequence number of this search action.
 */
  gl->last_search = gl->keyseq_count;
/*
 * We don't want a search prefix for this function.
 */
  if(_glh_search_prefix(gl->glh, gl->line, 0)) {
    _err_record_msg(gl->err, _glh_last_error(gl->glh), END_ERR_MSG);
    return 1;
  };
/*
 * Recall the count'th next older line in the history list. If the first one
 * fails we can return since nothing has changed, otherwise we must continue
 * and update the line state.
 */
  if(_glh_find_backwards(gl->glh, gl->line, gl->linelen+1) == NULL)
    return 0;
  while(--count && _glh_find_backwards(gl->glh, gl->line, gl->linelen+1))
    ;
/*
 * Accomodate the new contents of gl->line[].
 */
  gl_update_buffer(gl);
/*
 * Arrange to have the cursor placed at the end of the new line.
 */
  gl->buff_curpos = gl->ntotal;
/*
 * Erase and display the new line.
 */
  gl_queue_redisplay(gl);
  return 0;
}

/*.......................................................................
 * This is the action function that recalls the next line in the
 * history buffer.
 */
static KT_KEY_FN(gl_down_history)
{
/*
 * In vi mode, switch to command mode, since the user is very
 * likely to want to move around newly recalled lines.
 */
  gl_vi_command_mode(gl);
/*
 * Record the key sequence number of this search action.
 */
  gl->last_search = gl->keyseq_count;
/*
 * If no search is currently in progress continue a previous recall
 * session from a previous entered line if possible.
 */
  if(_glh_line_id(gl->glh, 0) == 0 && gl->preload_id) {
    _glh_recall_line(gl->glh, gl->preload_id, gl->line, gl->linelen+1);
    gl->preload_id = 0;
  } else {
/*
 * We don't want a search prefix for this function.
 */
    if(_glh_search_prefix(gl->glh, gl->line, 0)) {
      _err_record_msg(gl->err, _glh_last_error(gl->glh), END_ERR_MSG);
      return 1;
    };
/*
 * Recall the count'th next newer line in the history list. If the first one
 * fails we can return since nothing has changed otherwise we must continue
 * and update the line state.
 */
    if(_glh_find_forwards(gl->glh, gl->line, gl->linelen+1) == NULL)
      return 0;
    while(--count && _glh_find_forwards(gl->glh, gl->line, gl->linelen+1))
      ;
  };
/*
 * Accomodate the new contents of gl->line[].
 */
  gl_update_buffer(gl);
/*
 * Arrange to have the cursor placed at the end of the new line.
 */
  gl->buff_curpos = gl->ntotal;
/*
 * Erase and display the new line.
 */
  gl_queue_redisplay(gl);
  return 0;
}

/*.......................................................................
 * This is the action function that recalls the previous line in the
 * history buffer whos prefix matches the characters that currently
 * precede the cursor. By setting count=-1, this can be used internally
 * to force searching for the prefix used in the last search.
 */
static KT_KEY_FN(gl_history_search_backward)
{
/*
 * In vi mode, switch to command mode, since the user is very
 * likely to want to move around newly recalled lines.
 */
  gl_vi_command_mode(gl);
/*
 * Forget any previous recall session.
 */
  gl->preload_id = 0;
/*
 * Record the key sequence number of this search action.
 */
  gl->last_search = gl->keyseq_count;
/*
 * If a prefix search isn't already in progress, replace the search
 * prefix to the string that precedes the cursor. In vi command mode
 * include the character that is under the cursor in the string.  If
 * count<0 keep the previous search prefix regardless, so as to force
 * a repeat search even if the last command wasn't a history command.
 */
  if(count >= 0 && !_glh_search_active(gl->glh) &&
     _glh_search_prefix(gl->glh, gl->line, gl->buff_curpos +
			(gl->editor==GL_VI_MODE && gl->ntotal>0))) {
    _err_record_msg(gl->err, _glh_last_error(gl->glh), END_ERR_MSG);
    return 1;
  };
/*
 * Search backwards for a match to the part of the line which precedes the
 * cursor.
 */
  if(_glh_find_backwards(gl->glh, gl->line, gl->linelen+1) == NULL)
    return 0;
/*
 * Accomodate the new contents of gl->line[].
 */
  gl_update_buffer(gl);
/*
 * Arrange to have the cursor placed at the end of the new line.
 */
  gl->buff_curpos = gl->ntotal;
/*
 * Erase and display the new line.
 */
  gl_queue_redisplay(gl);
  return 0;
}

/*.......................................................................
 * This is the action function that recalls the previous line in the
 * history buffer who's prefix matches that specified in an earlier call
 * to gl_history_search_backward() or gl_history_search_forward().
 */
static KT_KEY_FN(gl_history_re_search_backward)
{
  return gl_history_search_backward(gl, -1, NULL);
}

/*.......................................................................
 * This is the action function that recalls the next line in the
 * history buffer who's prefix matches that specified in the earlier call
 * to gl_history_search_backward) which started the history search.
 * By setting count=-1, this can be used internally to force searching
 * for the prefix used in the last search.
 */
static KT_KEY_FN(gl_history_search_forward)
{
/*
 * In vi mode, switch to command mode, since the user is very
 * likely to want to move around newly recalled lines.
 */
  gl_vi_command_mode(gl);
/*
 * Record the key sequence number of this search action.
 */
  gl->last_search = gl->keyseq_count;
/*
 * If a prefix search isn't already in progress, replace the search
 * prefix to the string that precedes the cursor. In vi command mode
 * include the character that is under the cursor in the string.  If
 * count<0 keep the previous search prefix regardless, so as to force
 * a repeat search even if the last command wasn't a history command.
 */
  if(count >= 0 && !_glh_search_active(gl->glh) &&
     _glh_search_prefix(gl->glh, gl->line, gl->buff_curpos +
			(gl->editor==GL_VI_MODE && gl->ntotal>0))) {
    _err_record_msg(gl->err, _glh_last_error(gl->glh), END_ERR_MSG);
    return 1;
  };
/*
 * Search forwards for the next matching line.
 */
  if(_glh_find_forwards(gl->glh, gl->line, gl->linelen+1) == NULL)
    return 0;
/*
 * Accomodate the new contents of gl->line[].
 */
  gl_update_buffer(gl);
/*
 * Arrange for the cursor to be placed at the end of the new line.
 */
  gl->buff_curpos = gl->ntotal;
/*
 * Erase and display the new line.
 */
  gl_queue_redisplay(gl);
  return 0;
}

/*.......................................................................
 * This is the action function that recalls the next line in the
 * history buffer who's prefix matches that specified in an earlier call
 * to gl_history_search_backward() or gl_history_search_forward().
 */
static KT_KEY_FN(gl_history_re_search_forward)
{
  return gl_history_search_forward(gl, -1, NULL);
}

#ifdef HIDE_FILE_SYSTEM
/*.......................................................................
 * The following function is used as the default completion handler when
 * the filesystem is to be hidden. It simply reports no completions.
 */
static CPL_MATCH_FN(gl_no_completions)
{
  return 0;
}
#endif

/*.......................................................................
 * This is the tab completion function that completes the filename that
 * precedes the cursor position. Its callback data argument must be a
 * pointer to a GlCplCallback containing the completion callback function
 * and its callback data, or NULL to use the builtin filename completer.
 */
static KT_KEY_FN(gl_complete_word)
{
  CplMatches *matches;    /* The possible completions */
  int suffix_len;         /* The length of the completion extension */
  int cont_len;           /* The length of any continuation suffix */
  int nextra;             /* The number of characters being added to the */
                          /*  total length of the line. */
  int buff_pos;           /* The buffer index at which the completion is */
                          /*  to be inserted. */
  int waserr = 0;         /* True after errors */
/*
 * Get the container of the completion callback and its callback data.
 */
  GlCplCallback *cb = data ? (GlCplCallback *) data : &gl->cplfn;
/*
 * In vi command mode, switch to append mode so that the character under
 * the cursor is included in the completion (otherwise people can't
 * complete at the end of the line).
 */
  if(gl->vi.command && gl_vi_append(gl, 0, NULL))
    return 1;
/*
 * Get the cursor position at which the completion is to be inserted.
 */
  buff_pos = gl->buff_curpos;
/*
 * Perform the completion.
 */
  matches = cpl_complete_word(gl->cpl, gl->line, gl->buff_curpos, cb->data,
			      cb->fn);
/*
 * No matching completions?
 */
  if(!matches) {
    waserr = gl_print_info(gl, cpl_last_error(gl->cpl), GL_END_INFO);
/*
 * Are there any completions?
 */
  } else if(matches->nmatch >= 1) {
/*
 * If there any ambiguous matches, report them, starting on a new line.
 */
    if(matches->nmatch > 1 && gl->echo) {
      if(_gl_normal_io(gl) ||
	 _cpl_output_completions(matches, gl_write_fn, gl, gl->ncolumn))
	waserr = 1;
    };
/*
 * Get the length of the suffix and any continuation suffix to add to it.
 */
    suffix_len = strlen(matches->suffix);
    cont_len = strlen(matches->cont_suffix);
/*
 * If there is an unambiguous match, and the continuation suffix ends in
 * a newline, strip that newline and arrange to have getline return
 * after this action function returns.
 */
    if(matches->nmatch==1 && cont_len > 0 &&
       matches->cont_suffix[cont_len - 1] == '\n') {
      cont_len--;
      if(gl_newline(gl, 1, NULL))
	waserr = 1;
    };
/*
 * Work out the number of characters that are to be added.
 */
    nextra = suffix_len + cont_len;
/*
 * Is there anything to be added?
 */
    if(!waserr && nextra) {
/*
 * Will there be space for the expansion in the line buffer?
 */
      if(gl->ntotal + nextra < gl->linelen) {
/*
 * Make room to insert the filename extension.
 */
	gl_make_gap_in_buffer(gl, gl->buff_curpos, nextra);
/*
 * Insert the filename extension.
 */
	gl_buffer_string(gl, matches->suffix, suffix_len, gl->buff_curpos);
/*
 * Add the terminating characters.
 */
	gl_buffer_string(gl, matches->cont_suffix, cont_len,
			 gl->buff_curpos + suffix_len);
/*
 * Place the cursor position at the end of the completion.
 */
	gl->buff_curpos += nextra;
/*
 * If we don't have to redisplay the whole line, redisplay the part
 * of the line which follows the original cursor position, and place
 * the cursor at the end of the completion.
 */
	if(gl->displayed) {
	  if(gl_truncate_display(gl) ||
	     gl_print_string(gl, gl->line + buff_pos, '\0') ||
	     gl_place_cursor(gl, gl->buff_curpos))
	    waserr = 1;
	};
      } else {
	(void) gl_print_info(gl,
			     "Insufficient room in line for file completion.",
			     GL_END_INFO);
	waserr = 1;
      };
    };
  };
/*
 * If any output had to be written to the terminal, then editing will
 * have been suspended, make sure that we are back in raw line editing
 * mode before returning.
 */
  if(_gl_raw_io(gl, 1))
    waserr = 1;
  return 0;
}

#ifndef HIDE_FILE_SYSTEM
/*.......................................................................
 * This is the function that expands the filename that precedes the
 * cursor position. It expands ~user/ expressions, $envvar expressions,
 * and wildcards.
 */
static KT_KEY_FN(gl_expand_filename)
{
  char *start_path;      /* The pointer to the start of the pathname in */
                         /*  gl->line[]. */
  FileExpansion *result; /* The results of the filename expansion */
  int pathlen;           /* The length of the pathname being expanded */
  int length;            /* The number of characters needed to display the */
                         /*  expanded files. */
  int nextra;            /* The number of characters to be added */
  int i,j;
/*
 * In vi command mode, switch to append mode so that the character under
 * the cursor is included in the completion (otherwise people can't
 * complete at the end of the line).
 */
  if(gl->vi.command && gl_vi_append(gl, 0, NULL))
    return 1;
/*
 * Locate the start of the filename that precedes the cursor position.
 */
  start_path = _pu_start_of_path(gl->line, gl->buff_curpos);
  if(!start_path)
    return 1;
/*
 * Get the length of the string that is to be expanded.
 */
  pathlen = gl->buff_curpos - (start_path - gl->line);
/*
 * Attempt to expand it.
 */
  result = ef_expand_file(gl->ef, start_path, pathlen);
/*
 * If there was an error, report the error on a new line.
 */
  if(!result)
    return gl_print_info(gl, ef_last_error(gl->ef), GL_END_INFO);
/*
 * If no files matched, report this as well.
 */
  if(result->nfile == 0 || !result->exists)
    return gl_print_info(gl, "No files match.", GL_END_INFO);
/*
 * If in vi command mode, preserve the current line for potential use by
 * vi-undo.
 */
  gl_save_for_undo(gl);
/*
 * Work out how much space we will need to display all of the matching
 * filenames, taking account of the space that we need to place between
 * them, and the number of additional '\' characters needed to escape
 * spaces, tabs and backslash characters in the individual filenames.
 */
  length = 0;
  for(i=0; i<result->nfile; i++) {
    char *file = result->files[i];
    while(*file) {
      int c = *file++;
      switch(c) {
      case ' ': case '\t': case '\\': case '*': case '?': case '[':
	length++;  /* Count extra backslash characters */
      };
      length++;    /* Count the character itself */
    };
    length++;      /* Count the space that follows each filename */
  };
/*
 * Work out the number of characters that are to be added.
 */
  nextra = length - pathlen;
/*
 * Will there be space for the expansion in the line buffer?
 */
  if(gl->ntotal + nextra >= gl->linelen) {
    return gl_print_info(gl, "Insufficient room in line for file expansion.",
			 GL_END_INFO);
  } else {
/*
 * Do we need to move the part of the line that followed the unexpanded
 * filename?
 */
    if(nextra > 0) {
      gl_make_gap_in_buffer(gl, gl->buff_curpos, nextra);
    } else if(nextra < 0) {
      gl->buff_curpos += nextra;
      gl_remove_from_buffer(gl, gl->buff_curpos, -nextra);
    };
/*
 * Insert the filenames, separated by spaces, and with internal spaces,
 * tabs and backslashes escaped with backslashes.
 */
    for(i=0,j=start_path - gl->line; i<result->nfile; i++) {
      char *file = result->files[i];
      while(*file) {
	int c = *file++;
	switch(c) {
	case ' ': case '\t': case '\\': case '*': case '?': case '[':
	  gl_buffer_char(gl, '\\', j++);
	};
	gl_buffer_char(gl, c, j++);
      };
      gl_buffer_char(gl, ' ', j++);
    };
  };
/*
 * Redisplay the part of the line which follows the start of
 * the original filename.
 */
  if(gl_place_cursor(gl, start_path - gl->line) ||
     gl_truncate_display(gl) ||
     gl_print_string(gl, start_path, start_path[length]))
    return 1;
/*
 * Move the cursor to the end of the expansion.
 */
  return gl_place_cursor(gl, (start_path - gl->line) + length);
}
#endif

#ifndef HIDE_FILE_SYSTEM
/*.......................................................................
 * This is the action function that lists glob expansions of the
 * filename that precedes the cursor position. It expands ~user/
 * expressions, $envvar expressions, and wildcards.
 */
static KT_KEY_FN(gl_list_glob)
{
  char *start_path;      /* The pointer to the start of the pathname in */
                         /*  gl->line[]. */
  FileExpansion *result; /* The results of the filename expansion */
  int pathlen;           /* The length of the pathname being expanded */
/*
 * Locate the start of the filename that precedes the cursor position.
 */
  start_path = _pu_start_of_path(gl->line, gl->buff_curpos);
  if(!start_path)
    return 1;
/*
 * Get the length of the string that is to be expanded.
 */
  pathlen = gl->buff_curpos - (start_path - gl->line);
/*
 * Attempt to expand it.
 */
  result = ef_expand_file(gl->ef, start_path, pathlen);
/*
 * If there was an error, report it.
 */
  if(!result) {
    return gl_print_info(gl,  ef_last_error(gl->ef), GL_END_INFO);
/*
 * If no files matched, report this as well.
 */
  } else if(result->nfile == 0 || !result->exists) {
    return gl_print_info(gl, "No files match.", GL_END_INFO);
/*
 * List the matching expansions.
 */
  } else if(gl->echo) {
    if(gl_start_newline(gl, 1) ||
       _ef_output_expansions(result, gl_write_fn, gl, gl->ncolumn))
      return 1;
    gl_queue_redisplay(gl);
  };
  return 0;
}
#endif

/*.......................................................................
 * Return non-zero if a character should be considered a part of a word.
 *
 * Input:
 *  c       int  The character to be tested.
 * Output:
 *  return  int  True if the character should be considered part of a word.
 */
static int gl_is_word_char(int c)
{
  return isalnum((int)(unsigned char)c) || strchr(GL_WORD_CHARS, c) != NULL;
}

/*.......................................................................
 * Override the builtin file-completion callback that is bound to the
 * "complete_word" action function.
 *
 * Input:
 *  gl            GetLine *  The resource object of the command-line input
 *                           module.
 *  data             void *  This is passed to match_fn() whenever it is
 *                           called. It could, for example, point to a
 *                           symbol table where match_fn() could look
 *                           for possible completions.
 *  match_fn   CplMatchFn *  The function that will identify the prefix
 *                           to be completed from the input line, and
 *                           report matching symbols.
 * Output:
 *  return            int    0 - OK.
 *                           1 - Error.
 */
int gl_customize_completion(GetLine *gl, void *data, CplMatchFn *match_fn)
{
  sigset_t oldset; /* The signals that were blocked on entry to this function */
/*
 * Check the arguments.
 */
  if(!gl || !match_fn) {
    if(gl)
      _err_record_msg(gl->err, "NULL argument", END_ERR_MSG);
    errno = EINVAL;
    return 1;
  };
/*
 * Temporarily block all signals.
 */
  gl_mask_signals(gl, &oldset);
/*
 * Record the new completion function and its callback data.
 */
  gl->cplfn.fn = match_fn;
  gl->cplfn.data = data;
/*
 * Restore the process signal mask before returning.
 */
  gl_unmask_signals(gl, &oldset);
  return 0;
}

/*.......................................................................
 * Change the terminal (or stream) that getline interacts with.
 *
 * Input:
 *  gl            GetLine *  The resource object of the command-line input
 *                           module.
 *  input_fp         FILE *  The stdio stream to read from.
 *  output_fp        FILE *  The stdio stream to write to.
 *  term             char *  The terminal type. This can be NULL if
 *                           either or both of input_fp and output_fp don't
 *                           refer to a terminal. Otherwise it should refer
 *                           to an entry in the terminal information database.
 * Output:
 *  return            int    0 - OK.
 *                           1 - Error.
 */
int gl_change_terminal(GetLine *gl, FILE *input_fp, FILE *output_fp,
		       const char *term)
{
  sigset_t oldset; /* The signals that were blocked on entry to this function */
  int status;      /* The return status of _gl_change_terminal() */
/*
 * Check the arguments.
 */
  if(!gl) {
    errno = EINVAL;
    return 1;
  };
/*
 * Block all signals.
 */
  if(gl_mask_signals(gl, &oldset))
    return 1;
/*
 * Execute the private body of the function while signals are blocked.
 */
  status = _gl_change_terminal(gl, input_fp, output_fp, term);
/*
 * Restore the process signal mask.
 */
  gl_unmask_signals(gl, &oldset);
  return status;
}

/*.......................................................................
 * This is the private body of the gl_change_terminal() function. It
 * assumes that the caller has checked its arguments and blocked the
 * delivery of signals.
 */
static int _gl_change_terminal(GetLine *gl, FILE *input_fp, FILE *output_fp,
			       const char *term)
{
  int is_term = 0;   /* True if both input_fd and output_fd are associated */
                     /*  with a terminal. */
/*
 * Require that input_fp and output_fp both be valid.
 */
  if(!input_fp || !output_fp) {
    gl_print_info(gl, "Can't change terminal. Bad input/output stream(s).",
		  GL_END_INFO);
    return 1;
  };
/*
 * Are we displacing an existing terminal (as opposed to setting the
 * initial terminal)?
 */
  if(gl->input_fd >= 0) {
/*
 * Make sure to leave the previous terminal in a usable state.
 */
    if(_gl_normal_io(gl))
      return 1;
/*
 * Remove the displaced terminal from the list of fds to watch.
 */
#ifdef HAVE_SELECT
    FD_CLR(gl->input_fd, &gl->rfds);
#endif
  };
/*
 * Record the file descriptors and streams.
 */
  gl->input_fp = input_fp;
  gl->input_fd = fileno(input_fp);
  gl->output_fp = output_fp;
  gl->output_fd = fileno(output_fp);
/*
 * If needed, expand the record of the maximum file-descriptor that might
 * need to be monitored with select().
 */
#ifdef HAVE_SELECT
  if(gl->input_fd > gl->max_fd)
    gl->max_fd = gl->input_fd;
#endif
/*
 * Disable terminal interaction until we have enough info to interact
 * with the terminal.
 */
  gl->is_term = 0;
/*
 * For terminal editing, we need both output_fd and input_fd to refer to
 * a terminal. While we can't verify that they both point to the same
 * terminal, we can verify that they point to terminals.
 */
  is_term = isatty(gl->input_fd) && isatty(gl->output_fd);
/*
 * If we are interacting with a terminal and no terminal type has been
 * specified, treat it as a generic ANSI terminal.
 */
  if(is_term && !term)
    term = "ansi";
/*
 * Make a copy of the terminal type string.
 */
  if(term != gl->term) {
/*
 * Delete any old terminal type string.
 */
    if(gl->term) {
      free(gl->term);
      gl->term = NULL;
    };
/*
 * Make a copy of the new terminal-type string, if any.
 */
    if(term) {
      size_t termsz = strlen(term)+1;

      gl->term = (char *) malloc(termsz);
      if(gl->term)
	strlcpy(gl->term, term, termsz);
    };
  };
/*
 * Clear any terminal-specific key bindings that were taken from the
 * settings of the last terminal.
 */
  _kt_clear_bindings(gl->bindings, KTB_TERM);
/*
 * If we have a terminal install new bindings for it.
 */
  if(is_term) {
/*
 * Get the current settings of the terminal.
 */
    if(tcgetattr(gl->input_fd, &gl->oldattr)) {
      _err_record_msg(gl->err, "tcgetattr error", END_ERR_MSG);
      return 1;
    };
/*
 * If we don't set this now, gl_control_strings() won't know
 * that it is talking to a terminal.
 */
    gl->is_term = 1;
/*
 * Lookup the terminal control string and size information.
 */
    if(gl_control_strings(gl, term)) {
      gl->is_term = 0;
      return 1;
    };
/*
 * Bind terminal-specific keys.
 */
    if(gl_bind_terminal_keys(gl))
      return 1;
  };
/*
 * Assume that the caller has given us a terminal in a sane state.
 */
  gl->io_mode = GL_NORMAL_MODE;
/*
 * Switch into the currently configured I/O mode.
 */
  if(_gl_io_mode(gl, gl->io_mode))
    return 1;
  return 0;
}

/*.......................................................................
 * Set up terminal-specific key bindings.
 *
 * Input:
 *  gl            GetLine *  The resource object of the command-line input
 *                           module.
 * Output:
 *  return            int    0 - OK.
 *                           1 - Error.
 */
static int gl_bind_terminal_keys(GetLine *gl)
{
/*
 * Install key-bindings for the special terminal characters.
 */
  if(gl_bind_control_char(gl, KTB_TERM, gl->oldattr.c_cc[VINTR],
			  "user-interrupt") ||
     gl_bind_control_char(gl, KTB_TERM, gl->oldattr.c_cc[VQUIT], "abort") ||
     gl_bind_control_char(gl, KTB_TERM, gl->oldattr.c_cc[VSUSP], "suspend"))
    return 1;
/*
 * In vi-mode, arrange for the above characters to be seen in command
 * mode.
 */
  if(gl->editor == GL_VI_MODE) {
    if(gl_bind_control_char(gl, KTB_TERM, MAKE_META(gl->oldattr.c_cc[VINTR]),
			    "user-interrupt") ||
       gl_bind_control_char(gl, KTB_TERM, MAKE_META(gl->oldattr.c_cc[VQUIT]),
			    "abort") ||
       gl_bind_control_char(gl, KTB_TERM, MAKE_META(gl->oldattr.c_cc[VSUSP]),
			    "suspend"))
      return 1;
  };
/*
 * Non-universal special keys.
 */
#ifdef VLNEXT
  if(gl_bind_control_char(gl, KTB_TERM, gl->oldattr.c_cc[VLNEXT],
			  "literal-next"))
    return 1;
#else
  if(_kt_set_keybinding(gl->bindings, KTB_TERM, "^V", "literal-next")) {
    _err_record_msg(gl->err, _kt_last_error(gl->bindings), END_ERR_MSG);
    return 1;
  };
#endif
/*
 * Bind action functions to the terminal-specific arrow keys
 * looked up by gl_control_strings().
 */
  if(_gl_bind_arrow_keys(gl))
    return 1;
  return 0;
}

/*.......................................................................
 * This function is normally bound to control-D. When it is invoked within
 * a line it deletes the character which follows the cursor. When invoked
 * at the end of the line it lists possible file completions, and when
 * invoked on an empty line it causes gl_get_line() to return EOF. This
 * function emulates the one that is normally bound to control-D by tcsh.
 */
static KT_KEY_FN(gl_del_char_or_list_or_eof)
{
/*
 * If we have an empty line arrange to return EOF.
 */
  if(gl->ntotal < 1) {
    gl_record_status(gl, GLR_EOF, 0);
    return 1;
/*
 * If we are at the end of the line list possible completions.
 */
  } else if(gl->buff_curpos >= gl->ntotal) {
    return gl_list_completions(gl, 1, NULL);
/*
 * Within the line delete the character that follows the cursor.
 */
  } else {
/*
 * If in vi command mode, first preserve the current line for potential use
 * by vi-undo.
 */
    gl_save_for_undo(gl);
/*
 * Delete 'count' characters.
 */
    return gl_forward_delete_char(gl, count, NULL);
  };
}

/*.......................................................................
 * This function is normally bound to control-D in vi mode. When it is
 * invoked within a line it lists possible file completions, and when
 * invoked on an empty line it causes gl_get_line() to return EOF. This
 * function emulates the one that is normally bound to control-D by tcsh.
 */
static KT_KEY_FN(gl_list_or_eof)
{
/*
 * If we have an empty line arrange to return EOF.
 */
  if(gl->ntotal < 1) {
    gl_record_status(gl, GLR_EOF, 0);
    return 1;
/*
 * Otherwise list possible completions.
 */
  } else {
    return gl_list_completions(gl, 1, NULL);
  };
}

/*.......................................................................
 * List possible completions of the word that precedes the cursor. The
 * callback data argument must either be NULL to select the default
 * file completion callback, or be a GlCplCallback object containing the
 * completion callback function to call.
 */
static KT_KEY_FN(gl_list_completions)
{
  int waserr = 0;   /* True after errors */
/*
 * Get the container of the completion callback and its callback data.
 */
  GlCplCallback *cb = data ? (GlCplCallback *) data : &gl->cplfn;
/*
 * Get the list of possible completions.
 */
  CplMatches *matches = cpl_complete_word(gl->cpl, gl->line, gl->buff_curpos,
					  cb->data, cb->fn);
/*
 * No matching completions?
 */
  if(!matches) {
    waserr = gl_print_info(gl, cpl_last_error(gl->cpl), GL_END_INFO);
/*
 * List the matches.
 */
  } else if(matches->nmatch > 0 && gl->echo) {
    if(_gl_normal_io(gl) ||
       _cpl_output_completions(matches, gl_write_fn, gl, gl->ncolumn))
      waserr = 1;
  };
/*
 * If any output had to be written to the terminal, then editing will
 * have been suspended, make sure that we are back in raw line editing
 * mode before returning.
 */
  if(_gl_raw_io(gl, 1))
    waserr = 1;
  return waserr;
}

/*.......................................................................
 * Where the user has used the symbolic arrow-key names to specify
 * arrow key bindings, bind the specified action functions to the default
 * and terminal specific arrow key sequences.
 *
 * Input:
 *  gl     GetLine *   The getline resource object.
 * Output:
 *  return     int     0 - OK.
 *                     1 - Error.
 */
static int _gl_bind_arrow_keys(GetLine *gl)
{
/*
 * Process each of the arrow keys.
 */
  if(_gl_rebind_arrow_key(gl, "up", gl->u_arrow, "^[[A", "^[OA") ||
     _gl_rebind_arrow_key(gl, "down", gl->d_arrow, "^[[B", "^[OB") ||
     _gl_rebind_arrow_key(gl, "left", gl->l_arrow, "^[[D", "^[OD") ||
     _gl_rebind_arrow_key(gl, "right", gl->r_arrow, "^[[C", "^[OC"))
    return 1;
  return 0;
}

/*.......................................................................
 * Lookup the action function of a symbolic arrow-key binding, and bind
 * it to the terminal-specific and default arrow-key sequences. Note that
 * we don't trust the terminal-specified key sequences to be correct.
 * The main reason for this is that on some machines the xterm terminfo
 * entry is for hardware X-terminals, rather than xterm terminal emulators
 * and the two terminal types emit different character sequences when the
 * their cursor keys are pressed. As a result we also supply a couple
 * of default key sequences.
 *
 * Input:
 *  gl          GetLine *   The resource object of gl_get_line().
 *  name           char *   The symbolic name of the arrow key.
 *  term_seq       char *   The terminal-specific arrow-key sequence.
 *  def_seq1       char *   The first default arrow-key sequence.
 *  def_seq2       char *   The second arrow-key sequence.
 * Output:
 *  return          int     0 - OK.
 *                          1 - Error.
 */
static int _gl_rebind_arrow_key(GetLine *gl, const char *name,
				const char *term_seq, const char *def_seq1,
				const char *def_seq2)
{
  KeySym *keysym;  /* The binding-table entry matching the arrow-key name */
  int nsym;        /* The number of ambiguous matches */
/*
 * Lookup the key binding for the symbolic name of the arrow key. This
 * will either be the default action, or a user provided one.
 */
  if(_kt_lookup_keybinding(gl->bindings, name, strlen(name), &keysym, &nsym)
     == KT_EXACT_MATCH) {
/*
 * Get the action function.
 */
    KtAction *action = keysym->actions + keysym->binder;
    KtKeyFn *fn = action->fn;
    void *data = action->data;
/*
 * Bind this to each of the specified key sequences.
 */
    if((term_seq &&
	_kt_set_keyfn(gl->bindings, KTB_TERM, term_seq, fn, data)) ||
       (def_seq1 &&
	_kt_set_keyfn(gl->bindings, KTB_NORM, def_seq1, fn, data)) ||
       (def_seq2 &&
	_kt_set_keyfn(gl->bindings, KTB_NORM, def_seq2, fn, data))) {
      _err_record_msg(gl->err, _kt_last_error(gl->bindings), END_ERR_MSG);
      return 1;
    };
  };
  return 0;
}

/*.......................................................................
 * Read getline configuration information from a given file.
 *
 * Input:
 *  gl           GetLine *  The getline resource object.
 *  filename  const char *  The name of the file to read configuration
 *                          information from. The contents of this file
 *                          are as described in the gl_get_line(3) man
 *                          page for the default ~/.teclarc configuration
 *                          file.
 *  who         KtBinder    Who bindings are to be installed for.
 * Output:
 *  return           int    0 - OK.
 *                          1 - Irrecoverable error.
 */
static int _gl_read_config_file(GetLine *gl, const char *filename, KtBinder who)
{
/*
 * If filesystem access is to be excluded, configuration files can't
 * be read.
 */
#ifdef WITHOUT_FILE_SYSTEM
  _err_record_msg(gl->err,
		  "Can't read configuration files without filesystem access",
		  END_ERR_MSG);
  errno = EINVAL;
  return 1;
#else
  FileExpansion *expansion; /* The expansion of the filename */
  FILE *fp;                 /* The opened file */
  int waserr = 0;           /* True if an error occurred while reading */
  int lineno = 1;           /* The line number being processed */
/*
 * Check the arguments.
 */
  if(!gl || !filename) {
    if(gl)
      _err_record_msg(gl->err, "NULL argument(s)", END_ERR_MSG);
    errno = EINVAL;
    return 1;
  };
/*
 * Expand the filename.
 */
  expansion = ef_expand_file(gl->ef, filename, -1);
  if(!expansion) {
    gl_print_info(gl, "Unable to expand ", filename, " (",
		  ef_last_error(gl->ef), ").", GL_END_INFO);
    return 1;
  };
/*
 * Attempt to open the file.
 */
  fp = fopen(expansion->files[0], "r");
/*
 * It isn't an error for there to be no configuration file.
 */
  if(!fp)
    return 0;
/*
 * Parse the contents of the file.
 */
  while(!waserr && !feof(fp))
    waserr = _gl_parse_config_line(gl, fp, glc_file_getc, filename, who,
				   &lineno);
/*
 * Bind action functions to the terminal-specific arrow keys.
 */
  if(_gl_bind_arrow_keys(gl))
    return 1;
/*
 * Clean up.
 */
  (void) fclose(fp);
  return waserr;
#endif
}

/*.......................................................................
 * Read GetLine configuration information from a string. The contents of
 * the string are the same as those described in the gl_get_line(3)
 * man page for the contents of the ~/.teclarc configuration file.
 */
static int _gl_read_config_string(GetLine *gl, const char *buffer, KtBinder who)
{
  const char *bptr;         /* A pointer into buffer[] */
  int waserr = 0;           /* True if an error occurred while reading */
  int lineno = 1;           /* The line number being processed */
/*
 * Check the arguments.
 */
  if(!gl || !buffer) {
    if(gl)
      _err_record_msg(gl->err, "NULL argument(s)", END_ERR_MSG);
    errno = EINVAL;
    return 1;
  };
/*
 * Get a pointer to the start of the buffer.
 */
  bptr = buffer;
/*
 * Parse the contents of the buffer.
 */
  while(!waserr && *bptr)
    waserr = _gl_parse_config_line(gl, &bptr, glc_buff_getc, "", who, &lineno);
/*
 * Bind action functions to the terminal-specific arrow keys.
 */
  if(_gl_bind_arrow_keys(gl))
    return 1;
  return waserr;
}

/*.......................................................................
 * Parse the next line of a getline configuration file.
 *
 * Input:
 *  gl         GetLine *  The getline resource object.
 *  stream        void *  The pointer representing the stream to be read
 *                        by getc_fn().
 *  getc_fn  GlcGetcFn *  A callback function which when called with
 *                       'stream' as its argument, returns the next
 *                        unread character from the stream.
 *  origin  const char *  The name of the entity being read (eg. a
 *                        file name).
 *  who       KtBinder    Who bindings are to be installed for.
 * Input/Output:
 *  lineno         int *  The line number being processed is to be
 *                        maintained in *lineno.
 * Output:
 *  return         int    0 - OK.
 *                        1 - Irrecoverable error.
 */
static int _gl_parse_config_line(GetLine *gl, void *stream, GlcGetcFn *getc_fn,
				 const char *origin, KtBinder who, int *lineno)
{
  char buffer[GL_CONF_BUFLEN+1];  /* The input line buffer */
  char *argv[GL_CONF_MAXARG];     /* The argument list */
  int argc = 0;                   /* The number of arguments in argv[] */
  int c;                          /* A character from the file */
  int escaped = 0;                /* True if the next character is escaped */
  int i;
/*
 * Skip spaces and tabs.
 */
  do c = getc_fn(stream); while(c==' ' || c=='\t');
/*
 * Comments extend to the end of the line.
 */
  if(c=='#')
    do c = getc_fn(stream); while(c != '\n' && c != EOF);
/*
 * Ignore empty lines.
 */
  if(c=='\n' || c==EOF) {
    (*lineno)++;
    return 0;
  };
/*
 * Record the buffer location of the start of the first argument.
 */
  argv[argc] = buffer;
/*
 * Read the rest of the line, stopping early if a comment is seen, or
 * the buffer overflows, and replacing sequences of spaces with a
 * '\0', and recording the thus terminated string as an argument.
 */
  i = 0;
  while(i<GL_CONF_BUFLEN) {
/*
 * Did we hit the end of the latest argument?
 */
    if(c==EOF || (!escaped && (c==' ' || c=='\n' || c=='\t' || c=='#'))) {
/*
 * Terminate the argument.
 */
      buffer[i++] = '\0';
      argc++;
/*
 * Skip spaces and tabs.
 */
      while(c==' ' || c=='\t')
	c = getc_fn(stream);
/*
 * If we hit the end of the line, or the start of a comment, exit the loop.
 */
      if(c==EOF || c=='\n' || c=='#')
	break;
/*
 * Start recording the next argument.
 */
      if(argc >= GL_CONF_MAXARG) {
	gl_report_config_error(gl, origin, *lineno, "Too many arguments.");
	do c = getc_fn(stream); while(c!='\n' && c!=EOF);  /* Skip past eol */
	return 0;
      };
      argv[argc] = buffer + i;
/*
 * The next character was preceded by spaces, so it isn't escaped.
 */
      escaped = 0;
    } else {
/*
 * If we hit an unescaped backslash, this means that we should arrange
 * to treat the next character like a simple alphabetical character.
 */
      if(c=='\\' && !escaped) {
	escaped = 1;
/*
 * Splice lines where the newline is escaped.
 */
      } else if(c=='\n' && escaped) {
	(*lineno)++;
/*
 * Record a normal character, preserving any preceding backslash.
 */
      } else {
	if(escaped)
	  buffer[i++] = '\\';
	if(i>=GL_CONF_BUFLEN)
	  break;
	escaped = 0;
	buffer[i++] = c;
      };
/*
 * Get the next character.
 */
      c = getc_fn(stream);
    };
  };
/*
 * Did the buffer overflow?
 */
  if(i>=GL_CONF_BUFLEN) {
    gl_report_config_error(gl, origin, *lineno, "Line too long.");
    return 0;
  };
/*
 * The first argument should be a command name.
 */
  if(strcmp(argv[0], "bind") == 0) {
    const char *action = NULL; /* A NULL action removes a keybinding */
    const char *keyseq = NULL;
    switch(argc) {
    case 3:
      action = argv[2];
      /* FALLTHROUGH */
    case 2:              /* Note the intentional fallthrough */
      keyseq = argv[1];
/*
 * Attempt to record the new keybinding.
 */
      if(_kt_set_keybinding(gl->bindings, who, keyseq, action)) {
	gl_report_config_error(gl, origin, *lineno,
			       _kt_last_error(gl->bindings));
      };
      break;
    default:
      gl_report_config_error(gl, origin, *lineno, "Wrong number of arguments.");
    };
  } else if(strcmp(argv[0], "edit-mode") == 0) {
    if(argc == 2 && strcmp(argv[1], "emacs") == 0) {
      gl_change_editor(gl, GL_EMACS_MODE);
    } else if(argc == 2 && strcmp(argv[1], "vi") == 0) {
      gl_change_editor(gl, GL_VI_MODE);
    } else if(argc == 2 && strcmp(argv[1], "none") == 0) {
      gl_change_editor(gl, GL_NO_EDITOR);
    } else {
      gl_report_config_error(gl, origin, *lineno,
			     "The argument of editor should be vi or emacs.");
    };
  } else if(strcmp(argv[0], "nobeep") == 0) {
    gl->silence_bell = 1;
  } else {
    gl_report_config_error(gl, origin, *lineno, "Unknown command name.");
  };
/*
 * Skip any trailing comment.
 */
  while(c != '\n' && c != EOF)
    c = getc_fn(stream);
  (*lineno)++;
  return 0;
}

/*.......................................................................
 * This is a private function of _gl_parse_config_line() which prints
 * out an error message about the contents of the line, prefixed by the
 * name of the origin of the line and its line number.
 *
 * Input:
 *  gl         GetLine *  The resource object of gl_get_line().
 *  origin  const char *  The name of the entity being read (eg. a
 *                        file name).
 *  lineno         int    The line number at which the error occurred.
 *  errmsg  const char *  The error message.
 * Output:
 *  return         int    0 - OK.
 *                        1 - Error.
 */
static int gl_report_config_error(GetLine *gl, const char *origin, int lineno,
				  const char *errmsg)
{
  char lnum[20];   /* A buffer in which to render a single integer */
/*
 * Convert the line number into a string.
 */
  snprintf(lnum, sizeof(lnum), "%d", lineno);
/*
 * Have the string printed on the terminal.
 */
  return gl_print_info(gl, origin, ":", lnum, ": ", errmsg, GL_END_INFO);
}

/*.......................................................................
 * This is the _gl_parse_config_line() callback function which reads the
 * next character from a configuration file.
 */
static GLC_GETC_FN(glc_file_getc)
{
  return fgetc((FILE *) stream);
}

/*.......................................................................
 * This is the _gl_parse_config_line() callback function which reads the
 * next character from a buffer. Its stream argument is a pointer to a
 * variable which is, in turn, a pointer into the buffer being read from.
 */
static GLC_GETC_FN(glc_buff_getc)
{
  const char **lptr = (char const **) stream;
  return **lptr ? *(*lptr)++ : EOF;
}

#ifndef HIDE_FILE_SYSTEM
/*.......................................................................
 * When this action is triggered, it arranges to temporarily read command
 * lines from the regular file whos name precedes the cursor.
 * The current line is first discarded.
 */
static KT_KEY_FN(gl_read_from_file)
{
  char *start_path;       /* The pointer to the start of the pathname in */
                          /*  gl->line[]. */
  FileExpansion *result;  /* The results of the filename expansion */
  int pathlen;            /* The length of the pathname being expanded */
/*
 * Locate the start of the filename that precedes the cursor position.
 */
  start_path = _pu_start_of_path(gl->line, gl->buff_curpos);
  if(!start_path)
    return 1;
/*
 * Get the length of the pathname string.
 */
  pathlen = gl->buff_curpos - (start_path - gl->line);
/*
 * Attempt to expand the pathname.
 */
  result = ef_expand_file(gl->ef, start_path, pathlen);
/*
 * If there was an error, report the error on a new line.
 */
  if(!result) {
    return gl_print_info(gl, ef_last_error(gl->ef), GL_END_INFO);
/*
 * If no files matched, report this as well.
 */
  } else if(result->nfile == 0 || !result->exists) {
    return gl_print_info(gl, "No files match.", GL_END_INFO);
/*
 * Complain if more than one file matches.
 */
  } else if(result->nfile > 1) {
    return gl_print_info(gl, "More than one file matches.", GL_END_INFO);
/*
 * Disallow input from anything but normal files. In principle we could
 * also support input from named pipes. Terminal files would be a problem
 * since we wouldn't know the terminal type, and other types of files
 * might cause the library to lock up.
 */
  } else if(!_pu_path_is_file(result->files[0])) {
    return gl_print_info(gl, "Not a normal file.", GL_END_INFO);
  } else {
/*
 * Attempt to open and install the specified file for reading.
 */
    gl->file_fp = fopen(result->files[0], "r");
    if(!gl->file_fp) {
      return gl_print_info(gl, "Unable to open: ", result->files[0],
			   GL_END_INFO);
    };
/*
 * If needed, expand the record of the maximum file-descriptor that might
 * need to be monitored with select().
 */
#ifdef HAVE_SELECT
    if(fileno(gl->file_fp) > gl->max_fd)
      gl->max_fd = fileno(gl->file_fp);
#endif
/*
 * Is non-blocking I/O needed?
 */
    if(gl->raw_mode && gl->io_mode==GL_SERVER_MODE &&
       gl_nonblocking_io(gl, fileno(gl->file_fp))) {
      gl_revert_input(gl);
      return gl_print_info(gl, "Can't read file %s with non-blocking I/O",
			   result->files[0]);
    };
/*
 * Inform the user what is happening.
 */
    if(gl_print_info(gl, "<Taking input from ", result->files[0], ">",
		     GL_END_INFO))
      return 1;
  };
  return 0;
}
#endif

/*.......................................................................
 * Close any temporary file that is being used for input.
 *
 * Input:
 *  gl     GetLine *  The getline resource object.
 */
static void gl_revert_input(GetLine *gl)
{
  if(gl->file_fp)
    fclose(gl->file_fp);
  gl->file_fp = NULL;
  gl->endline = 1;
}

/*.......................................................................
 * This is the action function that recalls the oldest line in the
 * history buffer.
 */
static KT_KEY_FN(gl_beginning_of_history)
{
/*
 * In vi mode, switch to command mode, since the user is very
 * likely to want to move around newly recalled lines.
 */
  gl_vi_command_mode(gl);
/*
 * Forget any previous recall session.
 */
  gl->preload_id = 0;
/*
 * Record the key sequence number of this search action.
 */
  gl->last_search = gl->keyseq_count;
/*
 * Recall the next oldest line in the history list.
 */
  if(_glh_oldest_line(gl->glh, gl->line, gl->linelen+1) == NULL)
    return 0;
/*
 * Accomodate the new contents of gl->line[].
 */
  gl_update_buffer(gl);
/*
 * Arrange to have the cursor placed at the end of the new line.
 */
  gl->buff_curpos = gl->ntotal;
/*
 * Erase and display the new line.
 */
  gl_queue_redisplay(gl);
  return 0;
}

/*.......................................................................
 * If a history session is currently in progress, this action function
 * recalls the line that was being edited when the session started. If
 * no history session is in progress, it does nothing.
 */
static KT_KEY_FN(gl_end_of_history)
{
/*
 * In vi mode, switch to command mode, since the user is very
 * likely to want to move around newly recalled lines.
 */
  gl_vi_command_mode(gl);
/*
 * Forget any previous recall session.
 */
  gl->preload_id = 0;
/*
 * Record the key sequence number of this search action.
 */
  gl->last_search = gl->keyseq_count;
/*
 * Recall the next oldest line in the history list.
 */
  if(_glh_current_line(gl->glh, gl->line, gl->linelen+1) == NULL)
    return 0;
/*
 * Accomodate the new contents of gl->line[].
 */
  gl_update_buffer(gl);
/*
 * Arrange to have the cursor placed at the end of the new line.
 */
  gl->buff_curpos = gl->ntotal;
/*
 * Erase and display the new line.
 */
  gl_queue_redisplay(gl);
  return 0;
}

/*.......................................................................
 * This action function is treated specially, in that its count argument
 * is set to the end keystroke of the keysequence that activated it.
 * It accumulates a numeric argument, adding one digit on each call in
 * which the last keystroke was a numeric digit.
 */
static KT_KEY_FN(gl_digit_argument)
{
/*
 * Was the last keystroke a digit?
 */
  int is_digit = isdigit((int)(unsigned char) count);
/*
 * In vi command mode, a lone '0' means goto-start-of-line.
 */
  if(gl->vi.command && gl->number < 0 && count == '0')
    return gl_beginning_of_line(gl, count, NULL);
/*
 * Are we starting to accumulate a new number?
 */
  if(gl->number < 0 || !is_digit)
    gl->number = 0;
/*
 * Was the last keystroke a digit?
 */
  if(is_digit) {
/*
 * Read the numeric value of the digit, without assuming ASCII.
 */
    int n;
    char s[2]; s[0] = count; s[1] = '\0';
    n = atoi(s);
/*
 * Append the new digit.
 */
    gl->number = gl->number * 10 + n;
  };
  return 0;
}

/*.......................................................................
 * The newline action function sets gl->endline to tell
 * gl_get_input_line() that the line is now complete.
 */
static KT_KEY_FN(gl_newline)
{
  GlhLineID id;    /* The last history line recalled while entering this line */
/*
 * Flag the line as ended.
 */
  gl->endline = 1;
/*
 * Record the next position in the history buffer, for potential
 * recall by an action function on the next call to gl_get_line().
 */
  id = _glh_line_id(gl->glh, 1);
  if(id)
    gl->preload_id = id;
  return 0;
}

/*.......................................................................
 * The 'repeat' action function sets gl->endline to tell
 * gl_get_input_line() that the line is now complete, and records the
 * ID of the next history line in gl->preload_id so that the next call
 * to gl_get_input_line() will preload the line with that history line.
 */
static KT_KEY_FN(gl_repeat_history)
{
  gl->endline = 1;
  gl->preload_id = _glh_line_id(gl->glh, 1);
  gl->preload_history = 1;
  return 0;
}

/*.......................................................................
 * Flush unwritten characters to the terminal.
 *
 * Input:
 *  gl     GetLine *  The getline resource object.
 * Output:
 *  return     int    0 - OK.
 *                    1 - Either an error occured, or the output
 *                        blocked and non-blocking I/O is being used.
 *                        See gl->rtn_status for details.
 */
static int gl_flush_output(GetLine *gl)
{
/*
 * Record the fact that we are about to write to the terminal.
 */
  gl->pending_io = GLP_WRITE;
/*
 * Attempt to flush the output to the terminal.
 */
  errno = 0;
  switch(_glq_flush_queue(gl->cq, gl->flush_fn, gl)) {
  case GLQ_FLUSH_DONE:
    return gl->redisplay && !gl->postpone && gl_redisplay(gl, 1, NULL);
    break;
  case GLQ_FLUSH_AGAIN:      /* Output blocked */
    gl_record_status(gl, GLR_BLOCKED, BLOCKED_ERRNO);
    return 1;
    break;
  default:                   /* Abort the line if an error occurs */
    gl_record_status(gl, errno==EINTR ? GLR_SIGNAL : GLR_ERROR, errno);
    return 1;
    break;
  };
}

/*.......................................................................
 * This is the callback which _glq_flush_queue() uses to write buffered
 * characters to the terminal.
 */
static GL_WRITE_FN(gl_flush_terminal)
{
  int ndone = 0;    /* The number of characters written so far */
/*
 * Get the line-editor resource object.
 */
  GetLine *gl = (GetLine *) data;
/*
 * Transfer the latest array of characters to stdio.
 */
  while(ndone < n) {
    int nnew = write(gl->output_fd, s, n-ndone);
/*
 * If the write was successful, add to the recorded number of bytes
 * that have now been written.
 */
    if(nnew > 0) {
      ndone += nnew;
/*
 * If a signal interrupted the call, restart the write(), since all of
 * the signals that gl_get_line() has been told to watch for are
 * currently blocked.
 */
    } else if(errno == EINTR) {
      continue;
/*
 * If we managed to write something before an I/O error occurred, or
 * output blocked before anything was written, report the number of
 * bytes that were successfully written before this happened.
 */
    } else if(ndone > 0
#if defined(EAGAIN)
	      || errno==EAGAIN
#endif
#if defined(EWOULDBLOCK)
	      || errno==EWOULDBLOCK
#endif
	      ) {
      return ndone;

/*
 * To get here, an error must have occurred before anything new could
 * be written.
 */
    } else {
      return -1;
    };
  };
/*
 * To get here, we must have successfully written the number of
 * bytes that was specified.
 */
  return n;
}

/*.......................................................................
 * Change the style of editing to emulate a given editor.
 *
 * Input:
 *  gl       GetLine *  The getline resource object.
 *  editor  GlEditor    The type of editor to emulate.
 * Output:
 *  return       int    0 - OK.
 *                      1 - Error.
 */
static int gl_change_editor(GetLine *gl, GlEditor editor)
{
/*
 * Install the default key-bindings of the requested editor.
 */
  switch(editor) {
  case GL_EMACS_MODE:
    _kt_clear_bindings(gl->bindings, KTB_NORM);
    _kt_clear_bindings(gl->bindings, KTB_TERM);
    (void) _kt_add_bindings(gl->bindings, KTB_NORM, gl_emacs_bindings,
		   sizeof(gl_emacs_bindings)/sizeof(gl_emacs_bindings[0]));
    break;
  case GL_VI_MODE:
    _kt_clear_bindings(gl->bindings, KTB_NORM);
    _kt_clear_bindings(gl->bindings, KTB_TERM);
    (void) _kt_add_bindings(gl->bindings, KTB_NORM, gl_vi_bindings,
			    sizeof(gl_vi_bindings)/sizeof(gl_vi_bindings[0]));
    break;
  case GL_NO_EDITOR:
    break;
  default:
    _err_record_msg(gl->err, "Unknown editor", END_ERR_MSG);
    errno = EINVAL;
    return 1;
  };
/*
 * Record the new editing mode.
 */
  gl->editor = editor;
  gl->vi.command = 0;     /* Start in input mode */
  gl->insert_curpos = 0;
/*
 * Reinstate terminal-specific bindings.
 */
  if(gl->editor != GL_NO_EDITOR && gl->input_fp)
    (void) gl_bind_terminal_keys(gl);
  return 0;
}

/*.......................................................................
 * This is an action function that switches to editing using emacs bindings
 */
static KT_KEY_FN(gl_emacs_editing_mode)
{
  return gl_change_editor(gl, GL_EMACS_MODE);
}

/*.......................................................................
 * This is an action function that switches to editing using vi bindings
 */
static KT_KEY_FN(gl_vi_editing_mode)
{
  return gl_change_editor(gl, GL_VI_MODE);
}

/*.......................................................................
 * This is the action function that switches to insert mode.
 */
static KT_KEY_FN(gl_vi_insert)
{
/*
 * If in vi command mode, preserve the current line for potential
 * use by vi-undo.
 */
  gl_save_for_undo(gl);
/*
 * Switch to vi insert mode.
 */
  gl->insert = 1;
  gl->vi.command = 0;
  gl->insert_curpos = gl->buff_curpos;
  return 0;
}

/*.......................................................................
 * This is an action function that switches to overwrite mode.
 */
static KT_KEY_FN(gl_vi_overwrite)
{
/*
 * If in vi command mode, preserve the current line for potential
 * use by vi-undo.
 */
  gl_save_for_undo(gl);
/*
 * Switch to vi overwrite mode.
 */
  gl->insert = 0;
  gl->vi.command = 0;
  gl->insert_curpos = gl->buff_curpos;
  return 0;
}

/*.......................................................................
 * This action function toggles the case of the character under the
 * cursor.
 */
static KT_KEY_FN(gl_change_case)
{
  int i;
/*
 * Keep a record of the current insert mode and the cursor position.
 */
  int insert = gl->insert;
/*
 * If in vi command mode, preserve the current line for potential
 * use by vi-undo.
 */
  gl_save_for_undo(gl);
/*
 * We want to overwrite the modified word.
 */
  gl->insert = 0;
/*
 * Toggle the case of 'count' characters.
 */
  for(i=0; i<count && gl->buff_curpos < gl->ntotal; i++) {
    char *cptr = gl->line + gl->buff_curpos++;
/*
 * Convert the character to upper case?
 */
    if(islower((int)(unsigned char) *cptr))
      gl_buffer_char(gl, toupper((int) *cptr), cptr - gl->line);
    else if(isupper((int)(unsigned char) *cptr))
      gl_buffer_char(gl, tolower((int) *cptr), cptr - gl->line);
/*
 * Write the possibly modified character back. Note that for non-modified
 * characters we want to do this as well, so as to advance the cursor.
 */
      if(gl_print_char(gl, *cptr, cptr[1]))
	return 1;
  };
/*
 * Restore the insertion mode.
 */
  gl->insert = insert;
  return gl_place_cursor(gl, gl->buff_curpos);	/* bounds check */
}

/*.......................................................................
 * This is the action function which implements the vi-style action which
 * moves the cursor to the start of the line, then switches to insert mode.
 */
static KT_KEY_FN(gl_vi_insert_at_bol)
{
  gl_save_for_undo(gl);
  return gl_beginning_of_line(gl, 0, NULL) ||
         gl_vi_insert(gl, 0, NULL);

}

/*.......................................................................
 * This is the action function which implements the vi-style action which
 * moves the cursor to the end of the line, then switches to insert mode
 * to allow text to be appended to the line.
 */
static KT_KEY_FN(gl_vi_append_at_eol)
{
  gl_save_for_undo(gl);
  gl->vi.command = 0;	/* Allow cursor at EOL */
  return gl_end_of_line(gl, 0, NULL) ||
         gl_vi_insert(gl, 0, NULL);
}

/*.......................................................................
 * This is the action function which implements the vi-style action which
 * moves the cursor to right one then switches to insert mode, thus
 * allowing text to be appended after the next character.
 */
static KT_KEY_FN(gl_vi_append)
{
  gl_save_for_undo(gl);
  gl->vi.command = 0;	/* Allow cursor at EOL */
  return gl_cursor_right(gl, 1, NULL) ||
         gl_vi_insert(gl, 0, NULL);
}

/*.......................................................................
 * This action function moves the cursor to the column specified by the
 * numeric argument. Column indexes start at 1.
 */
static KT_KEY_FN(gl_goto_column)
{
  return gl_place_cursor(gl, count - 1);
}

/*.......................................................................
 * Starting with the character under the cursor, replace 'count'
 * characters with the next character that the user types.
 */
static KT_KEY_FN(gl_vi_replace_char)
{
  char c;  /* The replacement character */
  int i;
/*
 * Keep a record of the current insert mode.
 */
  int insert = gl->insert;
/*
 * Get the replacement character.
 */
  if(gl->vi.repeat.active) {
    c = gl->vi.repeat.input_char;
  } else {
    if(gl_read_terminal(gl, 1, &c))
      return 1;
    gl->vi.repeat.input_char = c;
  };
/*
 * Are there 'count' characters to be replaced?
 */
  if(gl->ntotal - gl->buff_curpos >= count) {
/*
 * If in vi command mode, preserve the current line for potential
 * use by vi-undo.
 */
    gl_save_for_undo(gl);
/*
 * Temporarily switch to overwrite mode.
 */
    gl->insert = 0;
/*
 * Overwrite the current character plus count-1 subsequent characters
 * with the replacement character.
 */
    for(i=0; i<count; i++)
      gl_add_char_to_line(gl, c);
/*
 * Restore the original insert/overwrite mode.
 */
    gl->insert = insert;
  };
  return gl_place_cursor(gl, gl->buff_curpos);	/* bounds check */
}

/*.......................................................................
 * This is an action function which changes all characters between the
 * current cursor position and the end of the line.
 */
static KT_KEY_FN(gl_vi_change_rest_of_line)
{
  gl_save_for_undo(gl);
  gl->vi.command = 0;	/* Allow cursor at EOL */
  return gl_kill_line(gl, count, NULL) || gl_vi_insert(gl, 0, NULL);
}

/*.......................................................................
 * This is an action function which changes all characters between the
 * start of the line and the current cursor position.
 */
static KT_KEY_FN(gl_vi_change_to_bol)
{
  return gl_backward_kill_line(gl,count,NULL) || gl_vi_insert(gl,0,NULL);
}

/*.......................................................................
 * This is an action function which deletes the entire contents of the
 * current line and switches to insert mode.
 */
static KT_KEY_FN(gl_vi_change_line)
{
  return gl_delete_line(gl,count,NULL) || gl_vi_insert(gl,0,NULL);
}

/*.......................................................................
 * Starting from the cursor position and looking towards the end of the
 * line, copy 'count' characters to the cut buffer.
 */
static KT_KEY_FN(gl_forward_copy_char)
{
/*
 * Limit the count to the number of characters available.
 */
  if(gl->buff_curpos + count >= gl->ntotal)
    count = gl->ntotal - gl->buff_curpos;
  if(count < 0)
    count = 0;
/*
 * Copy the characters to the cut buffer.
 */
  memcpy(gl->cutbuf, gl->line + gl->buff_curpos, count);
  gl->cutbuf[count] = '\0';
  return 0;
}

/*.......................................................................
 * Starting from the character before the cursor position and looking
 * backwards towards the start of the line, copy 'count' characters to
 * the cut buffer.
 */
static KT_KEY_FN(gl_backward_copy_char)
{
/*
 * Limit the count to the number of characters available.
 */
  if(count > gl->buff_curpos)
    count = gl->buff_curpos;
  if(count < 0)
    count = 0;
  gl_place_cursor(gl, gl->buff_curpos - count);
/*
 * Copy the characters to the cut buffer.
 */
  memcpy(gl->cutbuf, gl->line + gl->buff_curpos, count);
  gl->cutbuf[count] = '\0';
  return 0;
}

/*.......................................................................
 * Starting from the cursor position copy to the specified column into the
 * cut buffer.
 */
static KT_KEY_FN(gl_copy_to_column)
{
  if (--count >= gl->buff_curpos)
    return gl_forward_copy_char(gl, count - gl->buff_curpos, NULL);
  else
    return gl_backward_copy_char(gl, gl->buff_curpos - count, NULL);
}

/*.......................................................................
 * Starting from the cursor position copy characters up to a matching
 * parenthesis into the cut buffer.
 */
static KT_KEY_FN(gl_copy_to_parenthesis)
{
  int curpos = gl_index_of_matching_paren(gl);
  if(curpos >= 0) {
    gl_save_for_undo(gl);
    if(curpos >= gl->buff_curpos)
      return gl_forward_copy_char(gl, curpos - gl->buff_curpos + 1, NULL);
    else
      return gl_backward_copy_char(gl, ++gl->buff_curpos - curpos + 1, NULL);
  };
  return 0;
}

/*.......................................................................
 * Starting from the cursor position copy the rest of the line into the
 * cut buffer.
 */
static KT_KEY_FN(gl_copy_rest_of_line)
{
/*
 * Copy the characters to the cut buffer.
 */
  memcpy(gl->cutbuf, gl->line + gl->buff_curpos, gl->ntotal - gl->buff_curpos);
  gl->cutbuf[gl->ntotal - gl->buff_curpos] = '\0';
  return 0;
}

/*.......................................................................
 * Copy from the beginning of the line to the cursor position into the
 * cut buffer.
 */
static KT_KEY_FN(gl_copy_to_bol)
{
/*
 * Copy the characters to the cut buffer.
 */
  memcpy(gl->cutbuf, gl->line, gl->buff_curpos);
  gl->cutbuf[gl->buff_curpos] = '\0';
  gl_place_cursor(gl, 0);
  return 0;
}

/*.......................................................................
 * Copy the entire line into the cut buffer.
 */
static KT_KEY_FN(gl_copy_line)
{
/*
 * Copy the characters to the cut buffer.
 */
  memcpy(gl->cutbuf, gl->line, gl->ntotal);
  gl->cutbuf[gl->ntotal] = '\0';
  return 0;
}

/*.......................................................................
 * Search forwards for the next character that the user enters.
 */
static KT_KEY_FN(gl_forward_find_char)
{
  int pos = gl_find_char(gl, count, 1, 1, '\0');
  return pos >= 0 && gl_place_cursor(gl, pos);
}

/*.......................................................................
 * Search backwards for the next character that the user enters.
 */
static KT_KEY_FN(gl_backward_find_char)
{
  int pos = gl_find_char(gl, count, 0, 1, '\0');
  return pos >= 0 && gl_place_cursor(gl, pos);
}

/*.......................................................................
 * Search forwards for the next character that the user enters. Move up to,
 * but not onto, the found character.
 */
static KT_KEY_FN(gl_forward_to_char)
{
  int pos = gl_find_char(gl, count, 1, 0, '\0');
  return pos >= 0 && gl_place_cursor(gl, pos);
}

/*.......................................................................
 * Search backwards for the next character that the user enters. Move back to,
 * but not onto, the found character.
 */
static KT_KEY_FN(gl_backward_to_char)
{
  int pos = gl_find_char(gl, count, 0, 0, '\0');
  return pos >= 0 && gl_place_cursor(gl, pos);
}

/*.......................................................................
 * Searching in a given direction, return the index of a given (or
 * read) character in the input line, or the character that precedes
 * it in the specified search direction. Return -1 if not found.
 *
 * Input:
 *  gl       GetLine *  The getline resource object.
 *  count        int    The number of times to search.
 *  forward      int    True if searching forward.
 *  onto         int    True if the search should end on top of the
 *                      character, false if the search should stop
 *                      one character before the character in the
 *                      specified search direction.
 *  c           char    The character to be sought, or '\0' if the
 *                      character should be read from the user.
 * Output:
 *  return       int    The index of the character in gl->line[], or
 *                      -1 if not found.
 */
static int gl_find_char(GetLine *gl, int count, int forward, int onto, char c)
{
  int pos;     /* The index reached in searching the input line */
  int i;
/*
 * Get a character from the user?
 */
  if(!c) {
/*
 * If we are in the process of repeating a previous change command, substitute
 * the last find character.
 */
    if(gl->vi.repeat.active) {
      c = gl->vi.find_char;
    } else {
      if(gl_read_terminal(gl, 1, &c))
	return -1;
/*
 * Record the details of the new search, for use by repeat finds.
 */
      gl->vi.find_forward = forward;
      gl->vi.find_onto = onto;
      gl->vi.find_char = c;
    };
  };
/*
 * Which direction should we search?
 */
  if(forward) {
/*
 * Search forwards 'count' times for the character, starting with the
 * character that follows the cursor.
 */
    for(i=0, pos=gl->buff_curpos; i<count && pos < gl->ntotal; i++) {
/*
 * Advance past the last match (or past the current cursor position
 * on the first search).
 */
      pos++;
/*
 * Search for the next instance of c.
 */
      for( ; pos<gl->ntotal && c!=gl->line[pos]; pos++)
	;
    };
/*
 * If the character was found and we have been requested to return the
 * position of the character that precedes the desired character, then
 * we have gone one character too far.
 */
    if(!onto && pos<gl->ntotal)
      pos--;
  } else {
/*
 * Search backwards 'count' times for the character, starting with the
 * character that precedes the cursor.
 */
    for(i=0, pos=gl->buff_curpos; i<count && pos >= gl->insert_curpos; i++) {
/*
 * Step back one from the last match (or from the current cursor
 * position on the first search).
 */
      pos--;
/*
 * Search for the next instance of c.
 */
      for( ; pos>=gl->insert_curpos && c!=gl->line[pos]; pos--)
	;
    };
/*
 * If the character was found and we have been requested to return the
 * position of the character that precedes the desired character, then
 * we have gone one character too far.
 */
    if(!onto && pos>=gl->insert_curpos)
      pos++;
  };
/*
 * If found, return the cursor position of the count'th match.
 * Otherwise ring the terminal bell.
 */
  if(pos >= gl->insert_curpos && pos < gl->ntotal) {
    return pos;
  } else {
    (void) gl_ring_bell(gl, 1, NULL);
    return -1;
  }
}

/*.......................................................................
 * Repeat the last character search in the same direction as the last
 * search.
 */
static KT_KEY_FN(gl_repeat_find_char)
{
  int pos = gl->vi.find_char ?
    gl_find_char(gl, count, gl->vi.find_forward, gl->vi.find_onto,
		 gl->vi.find_char) : -1;
  return pos >= 0 && gl_place_cursor(gl, pos);
}

/*.......................................................................
 * Repeat the last character search in the opposite direction as the last
 * search.
 */
static KT_KEY_FN(gl_invert_refind_char)
{
  int pos = gl->vi.find_char ?
    gl_find_char(gl, count, !gl->vi.find_forward, gl->vi.find_onto,
		 gl->vi.find_char) : -1;
  return pos >= 0 && gl_place_cursor(gl, pos);
}

/*.......................................................................
 * Search forward from the current position of the cursor for 'count'
 * word endings, returning the index of the last one found, or the end of
 * the line if there were less than 'count' words.
 *
 * Input:
 *  gl       GetLine *  The getline resource object.
 *  n            int    The number of word boundaries to search for.
 * Output:
 *  return       int    The buffer index of the located position.
 */
static int gl_nth_word_end_forward(GetLine *gl, int n)
{
  int bufpos;   /* The buffer index being checked. */
  int i;
/*
 * In order to guarantee forward motion to the next word ending,
 * we need to start from one position to the right of the cursor
 * position, since this may already be at the end of a word.
 */
  bufpos = gl->buff_curpos + 1;
/*
 * If we are at the end of the line, return the index of the last
 * real character on the line. Note that this will be -1 if the line
 * is empty.
 */
  if(bufpos >= gl->ntotal)
    return gl->ntotal - 1;
/*
 * Search 'n' times, unless the end of the input line is reached first.
 */
  for(i=0; i<n && bufpos<gl->ntotal; i++) {
/*
 * If we are not already within a word, skip to the start of the next word.
 */
    for( ; bufpos<gl->ntotal && !gl_is_word_char((int)gl->line[bufpos]);
	bufpos++)
      ;
/*
 * Find the end of the next word.
 */
    for( ; bufpos<gl->ntotal && gl_is_word_char((int)gl->line[bufpos]);
	bufpos++)
      ;
  };
/*
 * We will have overshot.
 */
  return bufpos > 0 ? bufpos-1 : bufpos;
}

/*.......................................................................
 * Search forward from the current position of the cursor for 'count'
 * word starts, returning the index of the last one found, or the end of
 * the line if there were less than 'count' words.
 *
 * Input:
 *  gl       GetLine *  The getline resource object.
 *  n            int    The number of word boundaries to search for.
 * Output:
 *  return       int    The buffer index of the located position.
 */
static int gl_nth_word_start_forward(GetLine *gl, int n)
{
  int bufpos;   /* The buffer index being checked. */
  int i;
/*
 * Get the current cursor position.
 */
  bufpos = gl->buff_curpos;
/*
 * Search 'n' times, unless the end of the input line is reached first.
 */
  for(i=0; i<n && bufpos<gl->ntotal; i++) {
/*
 * Find the end of the current word.
 */
    for( ; bufpos<gl->ntotal && gl_is_word_char((int)gl->line[bufpos]);
	bufpos++)
      ;
/*
 * Skip to the start of the next word.
 */
    for( ; bufpos<gl->ntotal && !gl_is_word_char((int)gl->line[bufpos]);
	bufpos++)
      ;
  };
  return bufpos;
}

/*.......................................................................
 * Search backward from the current position of the cursor for 'count'
 * word starts, returning the index of the last one found, or the start
 * of the line if there were less than 'count' words.
 *
 * Input:
 *  gl       GetLine *  The getline resource object.
 *  n            int    The number of word boundaries to search for.
 * Output:
 *  return       int    The buffer index of the located position.
 */
static int gl_nth_word_start_backward(GetLine *gl, int n)
{
  int bufpos;   /* The buffer index being checked. */
  int i;
/*
 * Get the current cursor position.
 */
  bufpos = gl->buff_curpos;
/*
 * Search 'n' times, unless the beginning of the input line (or vi insertion
 * point) is reached first.
 */
  for(i=0; i<n && bufpos > gl->insert_curpos; i++) {
/*
 * Starting one character back from the last search, so as not to keep
 * settling on the same word-start, search backwards until finding a
 * word character.
 */
    while(--bufpos >= gl->insert_curpos &&
          !gl_is_word_char((int)gl->line[bufpos]))
      ;
/*
 * Find the start of the word.
 */
    while(--bufpos >= gl->insert_curpos &&
          gl_is_word_char((int)gl->line[bufpos]))
      ;
/*
 * We will have gone one character too far.
 */
    bufpos++;
  };
  return bufpos >= gl->insert_curpos ? bufpos : gl->insert_curpos;
}

/*.......................................................................
 * Copy one or more words into the cut buffer without moving the cursor
 * or deleting text.
 */
static KT_KEY_FN(gl_forward_copy_word)
{
/*
 * Find the location of the count'th start or end of a word
 * after the cursor, depending on whether in emacs or vi mode.
 */
  int next = gl->editor == GL_EMACS_MODE ?
    gl_nth_word_end_forward(gl, count) :
    gl_nth_word_start_forward(gl, count);
/*
 * How many characters are to be copied into the cut buffer?
 */
  int n = next - gl->buff_curpos;
/*
 * Copy the specified segment and terminate the string.
 */
  memcpy(gl->cutbuf, gl->line + gl->buff_curpos, n);
  gl->cutbuf[n] = '\0';
  return 0;
}

/*.......................................................................
 * Copy one or more words preceding the cursor into the cut buffer,
 * without moving the cursor or deleting text.
 */
static KT_KEY_FN(gl_backward_copy_word)
{
/*
 * Find the location of the count'th start of word before the cursor.
 */
  int next = gl_nth_word_start_backward(gl, count);
/*
 * How many characters are to be copied into the cut buffer?
 */
  int n = gl->buff_curpos - next;
  gl_place_cursor(gl, next);
/*
 * Copy the specified segment and terminate the string.
 */
  memcpy(gl->cutbuf, gl->line + next, n);
  gl->cutbuf[n] = '\0';
  return 0;
}

/*.......................................................................
 * Copy the characters between the cursor and the count'th instance of
 * a specified character in the input line, into the cut buffer.
 *
 * Input:
 *  gl       GetLine *  The getline resource object.
 *  count        int    The number of times to search.
 *  c           char    The character to be searched for, or '\0' if
 *                      the character should be read from the user.
 *  forward      int    True if searching forward.
 *  onto         int    True if the search should end on top of the
 *                      character, false if the search should stop
 *                      one character before the character in the
 *                      specified search direction.
 * Output:
 *  return       int    0 - OK.
 *                      1 - Error.
 *
 */
static int gl_copy_find(GetLine *gl, int count, char c, int forward, int onto)
{
  int n;  /* The number of characters in the cut buffer */
/*
 * Search for the character, and abort the operation if not found.
 */
  int pos = gl_find_char(gl, count, forward, onto, c);
  if(pos < 0)
    return 0;
/*
 * Copy the specified segment.
 */
  if(forward) {
    n = pos + 1 - gl->buff_curpos;
    memcpy(gl->cutbuf, gl->line + gl->buff_curpos, n);
  } else {
    n = gl->buff_curpos - pos;
    memcpy(gl->cutbuf, gl->line + pos, n);
    if(gl->editor == GL_VI_MODE)
      gl_place_cursor(gl, pos);
  }
/*
 * Terminate the copy.
 */
  gl->cutbuf[n] = '\0';
  return 0;
}

/*.......................................................................
 * Copy a section up to and including a specified character into the cut
 * buffer without moving the cursor or deleting text.
 */
static KT_KEY_FN(gl_forward_copy_find)
{
  return gl_copy_find(gl, count, '\0', 1, 1);
}

/*.......................................................................
 * Copy a section back to and including a specified character into the cut
 * buffer without moving the cursor or deleting text.
 */
static KT_KEY_FN(gl_backward_copy_find)
{
  return gl_copy_find(gl, count, '\0', 0, 1);
}

/*.......................................................................
 * Copy a section up to and not including a specified character into the cut
 * buffer without moving the cursor or deleting text.
 */
static KT_KEY_FN(gl_forward_copy_to)
{
  return gl_copy_find(gl, count, '\0', 1, 0);
}

/*.......................................................................
 * Copy a section back to and not including a specified character into the cut
 * buffer without moving the cursor or deleting text.
 */
static KT_KEY_FN(gl_backward_copy_to)
{
  return gl_copy_find(gl, count, '\0', 0, 0);
}

/*.......................................................................
 * Copy to a character specified in a previous search into the cut
 * buffer without moving the cursor or deleting text.
 */
static KT_KEY_FN(gl_copy_refind)
{
  return gl_copy_find(gl, count, gl->vi.find_char, gl->vi.find_forward,
		      gl->vi.find_onto);
}

/*.......................................................................
 * Copy to a character specified in a previous search, but in the opposite
 * direction, into the cut buffer without moving the cursor or deleting text.
 */
static KT_KEY_FN(gl_copy_invert_refind)
{
  return gl_copy_find(gl, count, gl->vi.find_char, !gl->vi.find_forward,
		      gl->vi.find_onto);
}

/*.......................................................................
 * Set the position of the cursor in the line input buffer and the
 * terminal.
 *
 * Input:
 *  gl       GetLine *  The getline resource object.
 *  buff_curpos  int    The new buffer cursor position.
 * Output:
 *  return       int    0 - OK.
 *                      1 - Error.
 */
static int gl_place_cursor(GetLine *gl, int buff_curpos)
{
/*
 * Don't allow the cursor position to go out of the bounds of the input
 * line.
 */
  if(buff_curpos >= gl->ntotal)
    buff_curpos = gl->vi.command ? gl->ntotal-1 : gl->ntotal;
  if(buff_curpos < 0)
    buff_curpos = 0;
/*
 * Record the new buffer position.
 */
  gl->buff_curpos = buff_curpos;
/*
 * Move the terminal cursor to the corresponding character.
 */
  return gl_set_term_curpos(gl, gl->prompt_len +
    gl_displayed_string_width(gl, gl->line, buff_curpos, gl->prompt_len));
}

/*.......................................................................
 * In vi command mode, this function saves the current line to the
 * historical buffer needed by the undo command. In emacs mode it does
 * nothing. In order to allow action functions to call other action
 * functions, gl_interpret_char() sets gl->vi.undo.saved to 0 before
 * invoking an action, and thereafter once any call to this function
 * has set it to 1, further calls are ignored.
 *
 * Input:
 *  gl       GetLine *  The getline resource object.
 */
static void gl_save_for_undo(GetLine *gl)
{
  if(gl->vi.command && !gl->vi.undo.saved) {
    strlcpy(gl->vi.undo.line, gl->line, gl->linelen);
    gl->vi.undo.buff_curpos = gl->buff_curpos;
    gl->vi.undo.ntotal = gl->ntotal;
    gl->vi.undo.saved = 1;
  };
  if(gl->vi.command && !gl->vi.repeat.saved &&
     gl->current_action.fn != gl_vi_repeat_change) {
    gl->vi.repeat.action = gl->current_action;
    gl->vi.repeat.count = gl->current_count;
    gl->vi.repeat.saved = 1;
  };
  return;
}

/*.......................................................................
 * In vi mode, restore the line to the way it was before the last command
 * mode operation, storing the current line in the buffer so that the
 * undo operation itself can subsequently be undone.
 */
static KT_KEY_FN(gl_vi_undo)
{
/*
 * Get pointers into the two lines.
 */
  char *undo_ptr = gl->vi.undo.line;
  char *line_ptr = gl->line;
/*
 * Swap the characters of the two buffers up to the length of the shortest
 * line.
 */
  while(*undo_ptr && *line_ptr) {
    char c = *undo_ptr;
    *undo_ptr++ = *line_ptr;
    *line_ptr++ = c;
  };
/*
 * Copy the rest directly.
 */
  if(gl->ntotal > gl->vi.undo.ntotal) {
    strlcpy(undo_ptr, line_ptr, gl->linelen);
    *line_ptr = '\0';
  } else {
    strlcpy(line_ptr, undo_ptr, gl->linelen);
    *undo_ptr = '\0';
  };
/*
 * Record the length of the stored string.
 */
  gl->vi.undo.ntotal = gl->ntotal;
/*
 * Accomodate the new contents of gl->line[].
 */
  gl_update_buffer(gl);
/*
 * Set both cursor positions to the leftmost of the saved and current
 * cursor positions to emulate what vi does.
 */
  if(gl->buff_curpos < gl->vi.undo.buff_curpos)
    gl->vi.undo.buff_curpos = gl->buff_curpos;
  else
    gl->buff_curpos = gl->vi.undo.buff_curpos;
/*
 * Since we have bipassed calling gl_save_for_undo(), record repeat
 * information inline.
 */
  gl->vi.repeat.action.fn = gl_vi_undo;
  gl->vi.repeat.action.data = NULL;
  gl->vi.repeat.count = 1;
/*
 * Display the restored line.
 */
  gl_queue_redisplay(gl);
  return 0;
}

/*.......................................................................
 * Delete the following word and leave the user in vi insert mode.
 */
static KT_KEY_FN(gl_vi_forward_change_word)
{
  gl_save_for_undo(gl);
  gl->vi.command = 0;	/* Allow cursor at EOL */
  return gl_forward_delete_word(gl, count, NULL) || gl_vi_insert(gl, 0, NULL);
}

/*.......................................................................
 * Delete the preceding word and leave the user in vi insert mode.
 */
static KT_KEY_FN(gl_vi_backward_change_word)
{
  return gl_backward_delete_word(gl, count, NULL) || gl_vi_insert(gl, 0, NULL);
}

/*.......................................................................
 * Delete the following section and leave the user in vi insert mode.
 */
static KT_KEY_FN(gl_vi_forward_change_find)
{
  return gl_delete_find(gl, count, '\0', 1, 1, 1);
}

/*.......................................................................
 * Delete the preceding section and leave the user in vi insert mode.
 */
static KT_KEY_FN(gl_vi_backward_change_find)
{
  return gl_delete_find(gl, count, '\0', 0, 1, 1);
}

/*.......................................................................
 * Delete the following section and leave the user in vi insert mode.
 */
static KT_KEY_FN(gl_vi_forward_change_to)
{
  return gl_delete_find(gl, count, '\0', 1, 0, 1);
}

/*.......................................................................
 * Delete the preceding section and leave the user in vi insert mode.
 */
static KT_KEY_FN(gl_vi_backward_change_to)
{
  return gl_delete_find(gl, count, '\0', 0, 0, 1);
}

/*.......................................................................
 * Delete to a character specified by a previous search and leave the user
 * in vi insert mode.
 */
static KT_KEY_FN(gl_vi_change_refind)
{
  return gl_delete_find(gl, count, gl->vi.find_char, gl->vi.find_forward,
			gl->vi.find_onto, 1);
}

/*.......................................................................
 * Delete to a character specified by a previous search, but in the opposite
 * direction, and leave the user in vi insert mode.
 */
static KT_KEY_FN(gl_vi_change_invert_refind)
{
  return gl_delete_find(gl, count, gl->vi.find_char, !gl->vi.find_forward,
			gl->vi.find_onto, 1);
}

/*.......................................................................
 * Delete the following character and leave the user in vi insert mode.
 */
static KT_KEY_FN(gl_vi_forward_change_char)
{
  gl_save_for_undo(gl);
  gl->vi.command = 0;	/* Allow cursor at EOL */
  return gl_delete_chars(gl, count, 1) || gl_vi_insert(gl, 0, NULL);
}

/*.......................................................................
 * Delete the preceding character and leave the user in vi insert mode.
 */
static KT_KEY_FN(gl_vi_backward_change_char)
{
  return gl_backward_delete_char(gl, count, NULL) || gl_vi_insert(gl, 0, NULL);
}

/*.......................................................................
 * Starting from the cursor position change characters to the specified column.
 */
static KT_KEY_FN(gl_vi_change_to_column)
{
  if (--count >= gl->buff_curpos)
    return gl_vi_forward_change_char(gl, count - gl->buff_curpos, NULL);
  else
    return gl_vi_backward_change_char(gl, gl->buff_curpos - count, NULL);
}

/*.......................................................................
 * Starting from the cursor position change characters to a matching
 * parenthesis.
 */
static KT_KEY_FN(gl_vi_change_to_parenthesis)
{
  int curpos = gl_index_of_matching_paren(gl);
  if(curpos >= 0) {
    gl_save_for_undo(gl);
    if(curpos >= gl->buff_curpos)
      return gl_vi_forward_change_char(gl, curpos - gl->buff_curpos + 1, NULL);
    else
      return gl_vi_backward_change_char(gl, ++gl->buff_curpos - curpos + 1,
					NULL);
  };
  return 0;
}

/*.......................................................................
 * If in vi mode, switch to vi command mode.
 *
 * Input:
 *  gl       GetLine *  The getline resource object.
 */
static void gl_vi_command_mode(GetLine *gl)
{
  if(gl->editor == GL_VI_MODE && !gl->vi.command) {
    gl->insert = 1;
    gl->vi.command = 1;
    gl->vi.repeat.input_curpos = gl->insert_curpos;
    gl->vi.repeat.command_curpos = gl->buff_curpos;
    gl->insert_curpos = 0;	 /* unrestrict left motion boundary */
    gl_cursor_left(gl, 1, NULL); /* Vi moves 1 left on entering command mode */
  };
}

/*.......................................................................
 * This is an action function which rings the terminal bell.
 */
static KT_KEY_FN(gl_ring_bell)
{
  return gl->silence_bell ? 0 :
    gl_print_control_sequence(gl, 1, gl->sound_bell);
}

/*.......................................................................
 * This is the action function which implements the vi-repeat-change
 * action.
 */
static KT_KEY_FN(gl_vi_repeat_change)
{
  int status;   /* The return status of the repeated action function */
  int i;
/*
 * Nothing to repeat?
 */
  if(!gl->vi.repeat.action.fn)
    return gl_ring_bell(gl, 1, NULL);
/*
 * Provide a way for action functions to know whether they are being
 * called by us.
 */
  gl->vi.repeat.active = 1;
/*
 * Re-run the recorded function.
 */
  status = gl->vi.repeat.action.fn(gl, gl->vi.repeat.count,
				   gl->vi.repeat.action.data);
/*
 * Mark the repeat as completed.
 */
  gl->vi.repeat.active = 0;
/*
 * Is we are repeating a function that has just switched to input
 * mode to allow the user to type, re-enter the text that the user
 * previously entered.
 */
  if(status==0 && !gl->vi.command) {
/*
 * Make sure that the current line has been saved.
 */
    gl_save_for_undo(gl);
/*
 * Repeat a previous insertion or overwrite?
 */
    if(gl->vi.repeat.input_curpos >= 0 &&
       gl->vi.repeat.input_curpos <= gl->vi.repeat.command_curpos &&
       gl->vi.repeat.command_curpos <= gl->vi.undo.ntotal) {
/*
 * Using the current line which is saved in the undo buffer, plus
 * the range of characters therein, as recorded by gl_vi_command_mode(),
 * add the characters that the user previously entered, to the input
 * line.
 */
      for(i=gl->vi.repeat.input_curpos; i<gl->vi.repeat.command_curpos; i++) {
	if(gl_add_char_to_line(gl, gl->vi.undo.line[i]))
	  return 1;
      };
    };
/*
 * Switch back to command mode, now that the insertion has been repeated.
 */
    gl_vi_command_mode(gl);
  };
  return status;
}

/*.......................................................................
 * If the cursor is currently over a parenthesis character, return the
 * index of its matching parenthesis. If not currently over a parenthesis
 * character, return the next close parenthesis character to the right of
 * the cursor. If the respective parenthesis character isn't found,
 * ring the terminal bell and return -1.
 *
 * Input:
 *  gl       GetLine *  The getline resource object.
 * Output:
 *  return       int    Either the index of the matching parenthesis,
 *                      or -1 if not found.
 */
static int gl_index_of_matching_paren(GetLine *gl)
{
  int i;
/*
 * List the recognized parentheses, and their matches.
 */
  const char *o_paren = "([{";
  const char *c_paren = ")]}";
  const char *cptr;
/*
 * Get the character that is currently under the cursor.
 */
  char c = gl->line[gl->buff_curpos];
/*
 * If the character under the cursor is an open parenthesis, look forward
 * for the matching close parenthesis.
 */
  if((cptr=strchr(o_paren, c))) {
    char match = c_paren[cptr - o_paren];
    int matches_needed = 1;
    for(i=gl->buff_curpos+1; i<gl->ntotal; i++) {
      if(gl->line[i] == c)
	matches_needed++;
      else if(gl->line[i] == match && --matches_needed==0)
	return i;
    };
/*
 * If the character under the cursor is an close parenthesis, look forward
 * for the matching open parenthesis.
 */
  } else if((cptr=strchr(c_paren, c))) {
    char match = o_paren[cptr - c_paren];
    int matches_needed = 1;
    for(i=gl->buff_curpos-1; i>=0; i--) {
      if(gl->line[i] == c)
	matches_needed++;
      else if(gl->line[i] == match && --matches_needed==0)
	return i;
    };
/*
 * If not currently over a parenthesis character, search forwards for
 * the first close parenthesis (this is what the vi % binding does).
 */
  } else {
    for(i=gl->buff_curpos+1; i<gl->ntotal; i++)
      if(strchr(c_paren, gl->line[i]) != NULL)
	return i;
  };
/*
 * Not found.
 */
  (void) gl_ring_bell(gl, 1, NULL);
  return -1;
}

/*.......................................................................
 * If the cursor is currently over a parenthesis character, this action
 * function moves the cursor to its matching parenthesis.
 */
static KT_KEY_FN(gl_find_parenthesis)
{
  int curpos = gl_index_of_matching_paren(gl);
  if(curpos >= 0)
    return gl_place_cursor(gl, curpos);
  return 0;
}

/*.......................................................................
 * Handle the receipt of the potential start of a new key-sequence from
 * the user.
 *
 * Input:
 *  gl      GetLine *   The resource object of this library.
 *  first_char char     The first character of the sequence.
 * Output:
 *  return      int     0 - OK.
 *                      1 - Error.
 */
static int gl_interpret_char(GetLine *gl, char first_char)
{
  char keyseq[GL_KEY_MAX+1]; /* A special key sequence being read */
  int nkey=0;                /* The number of characters in the key sequence */
  int count;                 /* The repeat count of an action function */
  int ret;                   /* The return value of an action function */
  int i;
/*
 * Get the first character.
 */
  char c = first_char;
/*
 * If editing is disabled, just add newly entered characters to the
 * input line buffer, and watch for the end of the line.
 */
  if(gl->editor == GL_NO_EDITOR) {
    gl_discard_chars(gl, 1);
    if(gl->ntotal >= gl->linelen)
      return 0;
    if(c == '\n' || c == '\r')
      return gl_newline(gl, 1, NULL);
    gl_buffer_char(gl, c, gl->ntotal);
    return 0;
  };
/*
 * If the user is in the process of specifying a repeat count and the
 * new character is a digit, increment the repeat count accordingly.
 */
  if(gl->number >= 0 && isdigit((int)(unsigned char) c)) {
    gl_discard_chars(gl, 1);
    return gl_digit_argument(gl, c, NULL);
/*
 * In vi command mode, all key-sequences entered need to be
 * either implicitly or explicitly prefixed with an escape character.
 */
  } else if(gl->vi.command && c != GL_ESC_CHAR) {
    keyseq[nkey++] = GL_ESC_CHAR;
/*
 * If the first character of the sequence is a printable character,
 * then to avoid confusion with the special "up", "down", "left"
 * or "right" cursor key bindings, we need to prefix the
 * printable character with a backslash escape before looking it up.
 */
  } else if(!IS_META_CHAR(c) && !IS_CTRL_CHAR(c)) {
    keyseq[nkey++] = '\\';
  };
/*
 * Compose a potentially multiple key-sequence in gl->keyseq.
 */
  while(nkey < GL_KEY_MAX) {
    KtAction *action; /* An action function */
    KeySym *keysym;   /* The symbol-table entry of a key-sequence */
    int nsym;         /* The number of ambiguously matching key-sequences */
/*
 * If the character is an unprintable meta character, split it
 * into two characters, an escape character and the character
 * that was modified by the meta key.
 */
    if(IS_META_CHAR(c)) {
      keyseq[nkey++] = GL_ESC_CHAR;
      c = META_TO_CHAR(c);
      continue;
    };
/*
 * Append the latest character to the key sequence.
 */
    keyseq[nkey++] = c;
/*
 * When doing vi-style editing, an escape at the beginning of any binding
 * switches to command mode.
 */
    if(keyseq[0] == GL_ESC_CHAR && !gl->vi.command)
      gl_vi_command_mode(gl);
/*
 * Lookup the key sequence.
 */
    switch(_kt_lookup_keybinding(gl->bindings, keyseq, nkey, &keysym, &nsym)) {
    case KT_EXACT_MATCH:
/*
 * Get the matching action function.
 */
      action = keysym->actions + keysym->binder;
/*
 * Get the repeat count, passing the last keystroke if executing the
 * digit-argument action.
 */
      if(action->fn == gl_digit_argument) {
	count = c;
      } else {
	count = gl->number >= 0 ? gl->number : 1;
      };
/*
 * Record the function that is being invoked.
 */
      gl->current_action = *action;
      gl->current_count = count;
/*
 * Mark the current line as not yet preserved for use by the vi undo command.
 */
      gl->vi.undo.saved = 0;
      gl->vi.repeat.saved = 0;
/*
 * Execute the action function. Note the action function can tell
 * whether the provided repeat count was defaulted or specified
 * explicitly by looking at whether gl->number is -1 or not. If
 * it is negative, then no repeat count was specified by the user.
 */
      ret = action->fn(gl, count, action->data);
/*
 * In server mode, the action will return immediately if it tries to
 * read input from the terminal, and no input is currently available.
 * If this happens, abort. Note that gl_get_input_line() will rewind
 * the read-ahead buffer to allow the next call to redo the function
 * from scratch.
 */
      if(gl->rtn_status == GLR_BLOCKED && gl->pending_io==GLP_READ)
	return 1;
/*
 * Discard the now processed characters from the key sequence buffer.
 */
      gl_discard_chars(gl, gl->nread);
/*
 * If the latest action function wasn't a history action, cancel any
 * current history search.
 */
      if(gl->last_search != gl->keyseq_count)
	_glh_cancel_search(gl->glh);
/*
 * Reset the repeat count after running action functions.
 */
      if(action->fn != gl_digit_argument)
	gl->number = -1;
      return ret ? 1 : 0;
      break;
    case KT_AMBIG_MATCH:    /* Ambiguous match - so read the next character */
      if(gl_read_terminal(gl, 1, &c))
	return 1;
      break;
    case KT_NO_MATCH:
/*
 * If the first character looked like it might be a prefix of a key-sequence
 * but it turned out not to be, ring the bell to tell the user that it
 * wasn't recognised.
 */
      if(keyseq[0] != '\\' && keyseq[0] != '\t') {
	gl_ring_bell(gl, 1, NULL);
      } else {
/*
 * The user typed a single printable character that doesn't match
 * the start of any keysequence, so add it to the line in accordance
 * with the current repeat count.
 */
	count = gl->number >= 0 ? gl->number : 1;
	for(i=0; i<count; i++)
	  gl_add_char_to_line(gl, first_char);
	gl->number = -1;
      };
      gl_discard_chars(gl, 1);
      _glh_cancel_search(gl->glh);
      return 0;
      break;
    case KT_BAD_MATCH:
      gl_ring_bell(gl, 1, NULL);
      gl_discard_chars(gl, gl->nread);
      _glh_cancel_search(gl->glh);
      return 1;
      break;
    };
  };
/*
 * If the key sequence was too long to match, ring the bell, then
 * discard the first character, so that the next attempt to match a
 * key-sequence continues with the next key press. In practice this
 * shouldn't happen, since one isn't allowed to bind action functions
 * to keysequences that are longer than GL_KEY_MAX.
 */
  gl_ring_bell(gl, 1, NULL);
  gl_discard_chars(gl, 1);
  return 0;
}

/*.......................................................................
 * Configure the application and/or user-specific behavior of
 * gl_get_line().
 *
 * Note that calling this function between calling new_GetLine() and
 * the first call to gl_get_line(), disables the otherwise automatic
 * reading of ~/.teclarc on the first call to gl_get_line().
 *
 * Input:
 *  gl             GetLine *  The resource object of this library.
 *  app_string  const char *  Either NULL, or a string containing one
 *                            or more .teclarc command lines, separated
 *                            by newline characters. This can be used to
 *                            establish an application-specific
 *                            configuration, without the need for an external
 *                            file. This is particularly useful in embedded
 *                            environments where there is no filesystem.
 *  app_file    const char *  Either NULL, or the pathname of an
 *                            application-specific .teclarc file. The
 *                            contents of this file, if provided, are
 *                            read after the contents of app_string[].
 *  user_file   const char *  Either NULL, or the pathname of a
 *                            user-specific .teclarc file. Except in
 *                            embedded applications, this should
 *                            usually be "~/.teclarc".
 * Output:
 *  return             int    0 - OK.
 *                            1 - Bad argument(s).
 */
int gl_configure_getline(GetLine *gl, const char *app_string,
			 const char *app_file, const char *user_file)
{
  sigset_t oldset; /* The signals that were blocked on entry to this function */
  int status;      /* The return status of _gl_configure_getline() */
/*
 * Check the arguments.
 */
  if(!gl) {
    errno = EINVAL;
    return 1;
  };
/*
 * Block all signals.
 */
  if(gl_mask_signals(gl, &oldset))
    return 1;
/*
 * Execute the private body of the function while signals are blocked.
 */
  status = _gl_configure_getline(gl, app_string, app_file, user_file);
/*
 * Restore the process signal mask.
 */
  gl_unmask_signals(gl, &oldset);
  return status;
}

/*.......................................................................
 * This is the private body of the gl_configure_getline() function. It
 * assumes that the caller has checked its arguments and blocked the
 * delivery of signals.
 */
static int _gl_configure_getline(GetLine *gl, const char *app_string,
				 const char *app_file, const char *user_file)
{
/*
 * Mark getline as having been explicitly configured.
 */
  gl->configured = 1;
/*
 * Start by parsing the configuration string, if provided.
 */
  if(app_string)
    (void) _gl_read_config_string(gl, app_string, KTB_NORM);
/*
 * Now parse the application-specific configuration file, if provided.
 */
  if(app_file)
    (void) _gl_read_config_file(gl, app_file, KTB_NORM);
/*
 * Finally, parse the user-specific configuration file, if provided.
 */
  if(user_file)
    (void) _gl_read_config_file(gl, user_file, KTB_USER);
/*
 * Record the names of the configuration files to allow them to
 * be re-read if requested at a later time.
 */
  if(gl_record_string(&gl->app_file, app_file) ||
     gl_record_string(&gl->user_file, user_file)) {
    errno = ENOMEM;
    _err_record_msg(gl->err,
	   "Insufficient memory to record tecla configuration file names",
	   END_ERR_MSG);
    return 1;
  };
  return 0;
}

/*.......................................................................
 * Replace a malloc'd string (or NULL), with another malloc'd copy of
 * a string (or NULL).
 *
 * Input:
 *  sptr          char **  On input if *sptr!=NULL, *sptr will be
 *                         free'd and *sptr will be set to NULL. Then,
 *                         on output, if string!=NULL a malloc'd copy
 *                         of this string will be assigned to *sptr.
 *  string  const char *   The string to be copied, or NULL to simply
 *                         discard any existing string.
 * Output:
 *  return         int     0 - OK.
 *                         1 - Malloc failure (no error message is generated).
 */
static int gl_record_string(char **sptr, const char *string)
{
/*
 * If the original string is the same string, don't do anything.
 */
  if(*sptr == string || (*sptr && string && strcmp(*sptr, string)==0))
    return 0;
/*
 * Discard any existing cached string.
 */
  if(*sptr) {
    free(*sptr);
    *sptr = NULL;
  };
/*
 * Allocate memory for a copy of the specified string.
 */
  if(string) {
    size_t ssz = strlen(string) + 1;
    *sptr = (char *) malloc(ssz);
    if(!*sptr)
      return 1;
/*
 * Copy the string.
 */
    strlcpy(*sptr, string, ssz);
  };
  return 0;
}

#ifndef HIDE_FILE_SYSTEM
/*.......................................................................
 * Re-read any application-specific and user-specific files previously
 * specified via the gl_configure_getline() function.
 */
static KT_KEY_FN(gl_read_init_files)
{
  return _gl_configure_getline(gl, NULL, gl->app_file, gl->user_file);
}
#endif

/*.......................................................................
 * Save the contents of the history buffer to a given new file.
 *
 * Input:
 *  gl             GetLine *  The resource object of this library.
 *  filename    const char *  The name of the new file to write to.
 *  comment     const char *  Extra information such as timestamps will
 *                            be recorded on a line started with this
 *                            string, the idea being that the file can
 *                            double as a command file. Specify "" if
 *                            you don't care.
 *  max_lines          int    The maximum number of lines to save, or -1
 *                            to save all of the lines in the history
 *                            list.
 * Output:
 *  return             int     0 - OK.
 *                             1 - Error.
 */
int gl_save_history(GetLine *gl, const char *filename, const char *comment,
		    int max_lines)
{
  sigset_t oldset; /* The signals that were blocked on entry to this function */
  int status;      /* The return status of _gl_save_history() */
/*
 * Check the arguments.
 */
  if(!gl || !filename || !comment) {
    if(gl)
      _err_record_msg(gl->err, "NULL argument(s)", END_ERR_MSG);
    errno = EINVAL;
    return 1;
  };
/*
 * Block all signals.
 */
  if(gl_mask_signals(gl, &oldset))
    return 1;
/*
 * Execute the private body of the function while signals are blocked.
 */
  status = _gl_save_history(gl, filename, comment, max_lines);
/*
 * Restore the process signal mask.
 */
  gl_unmask_signals(gl, &oldset);
  return status;
}

/*.......................................................................
 * This is the private body of the gl_save_history() function. It
 * assumes that the caller has checked its arguments and blocked the
 * delivery of signals.
 */
static int _gl_save_history(GetLine *gl, const char *filename,
			    const char *comment, int max_lines)
{
/*
 * If filesystem access is to be excluded, then history files can't
 * be written.
 */
#ifdef WITHOUT_FILE_SYSTEM
  _err_record_msg(gl->err, "Can't save history without filesystem access",
		  END_ERR_MSG);
  errno = EINVAL;
  return 1;
#else
  FileExpansion *expansion; /* The expansion of the filename */
/*
 * Expand the filename.
 */
  expansion = ef_expand_file(gl->ef, filename, -1);
  if(!expansion) {
    gl_print_info(gl, "Unable to expand ", filename, " (",
		  ef_last_error(gl->ef), ").", GL_END_INFO);
    return 1;
  };
/*
 * Attempt to save to the specified file.
 */
  if(_glh_save_history(gl->glh, expansion->files[0], comment, max_lines)) {
    _err_record_msg(gl->err, _glh_last_error(gl->glh), END_ERR_MSG);
    return 1;
  };
  return 0;
#endif
}

/*.......................................................................
 * Restore the contents of the history buffer from a given new file.
 *
 * Input:
 *  gl             GetLine *  The resource object of this library.
 *  filename    const char *  The name of the new file to write to.
 *  comment     const char *  This must be the same string that was
 *                            passed to gl_save_history() when the file
 *                            was written.
 * Output:
 *  return             int     0 - OK.
 *                             1 - Error.
 */
int gl_load_history(GetLine *gl, const char *filename, const char *comment)
{
  sigset_t oldset; /* The signals that were blocked on entry to this function */
  int status;      /* The return status of _gl_load_history() */
/*
 * Check the arguments.
 */
  if(!gl || !filename || !comment) {
    if(gl)
      _err_record_msg(gl->err, "NULL argument(s)", END_ERR_MSG);
    errno = EINVAL;
    return 1;
  };
/*
 * Block all signals.
 */
  if(gl_mask_signals(gl, &oldset))
    return 1;
/*
 * Execute the private body of the function while signals are blocked.
 */
  status = _gl_load_history(gl, filename, comment);
/*
 * Restore the process signal mask.
 */
  gl_unmask_signals(gl, &oldset);
  return status;
}

/*.......................................................................
 * This is the private body of the gl_load_history() function. It
 * assumes that the caller has checked its arguments and blocked the
 * delivery of signals.
 */
static int _gl_load_history(GetLine *gl, const char *filename,
			    const char *comment)
{
/*
 * If filesystem access is to be excluded, then history files can't
 * be read.
 */
#ifdef WITHOUT_FILE_SYSTEM
  _err_record_msg(gl->err, "Can't load history without filesystem access",
		  END_ERR_MSG);
  errno = EINVAL;
  return 1;
#else
  FileExpansion *expansion; /* The expansion of the filename */
/*
 * Expand the filename.
 */
  expansion = ef_expand_file(gl->ef, filename, -1);
  if(!expansion) {
    gl_print_info(gl, "Unable to expand ", filename, " (",
		  ef_last_error(gl->ef), ").", GL_END_INFO);
    return 1;
  };
/*
 * Attempt to load from the specified file.
 */
  if(_glh_load_history(gl->glh, expansion->files[0], comment,
		       gl->cutbuf, gl->linelen+1)) {
    _err_record_msg(gl->err, _glh_last_error(gl->glh), END_ERR_MSG);
    gl->cutbuf[0] = '\0';
    return 1;
  };
  gl->cutbuf[0] = '\0';
  return 0;
#endif
}

/*.......................................................................
 * Where possible, register a function and associated data to be called
 * whenever a specified event is seen on a file descriptor.
 *
 * Input:
 *  gl            GetLine *  The resource object of the command-line input
 *                           module.
 *  fd                int    The file descriptor to watch.
 *  event       GlFdEvent    The type of activity to watch for.
 *  callback  GlFdEventFn *  The function to call when the specified
 *                           event occurs. Setting this to 0 removes
 *                           any existing callback.
 *  data             void *  A pointer to arbitrary data to pass to the
 *                           callback function.
 * Output:
 *  return            int    0 - OK.
 *                           1 - Either gl==NULL, or this facility isn't
 *                               available on the the host system
 *                               (ie. select() isn't available). No
 *                               error message is generated in the latter
 *                               case.
 */
int gl_watch_fd(GetLine *gl, int fd, GlFdEvent event,
		GlFdEventFn *callback, void *data)
{
  sigset_t oldset; /* The signals that were blocked on entry to this function */
  int status;      /* The return status of _gl_watch_fd() */
/*
 * Check the arguments.
 */
  if(!gl) {
    errno = EINVAL;
    return 1;
  };
  if(fd < 0) {
    _err_record_msg(gl->err, "Error: fd < 0", END_ERR_MSG);
    errno = EINVAL;
    return 1;
  };
/*
 * Block all signals.
 */
  if(gl_mask_signals(gl, &oldset))
    return 1;
/*
 * Execute the private body of the function while signals are blocked.
 */
  status = _gl_watch_fd(gl, fd, event, callback, data);
/*
 * Restore the process signal mask.
 */
  gl_unmask_signals(gl, &oldset);
  return status;
}

/*.......................................................................
 * This is the private body of the gl_watch_fd() function. It
 * assumes that the caller has checked its arguments and blocked the
 * delivery of signals.
 */
static int _gl_watch_fd(GetLine *gl, int fd, GlFdEvent event,
			GlFdEventFn *callback, void *data)
#if !defined(HAVE_SELECT)
{return 1;}               /* The facility isn't supported on this system */
#else
{
  GlFdNode *prev;  /* The node that precedes 'node' in gl->fd_nodes */
  GlFdNode *node;  /* The file-descriptor node being checked */
/*
 * Search the list of already registered fd activity nodes for the specified
 * file descriptor.
 */
  for(prev=NULL,node=gl->fd_nodes; node && node->fd != fd;
      prev=node, node=node->next)
    ;
/*
 * Hasn't a node been allocated for this fd yet?
 */
  if(!node) {
/*
 * If there is no callback to record, just ignore the call.
 */
    if(!callback)
      return 0;
/*
 * Allocate the new node.
 */
    node = (GlFdNode *) _new_FreeListNode(gl->fd_node_mem);
    if(!node) {
      errno = ENOMEM;
      _err_record_msg(gl->err, "Insufficient memory", END_ERR_MSG);
      return 1;
    };
/*
 * Prepend the node to the list.
 */
    node->next = gl->fd_nodes;
    gl->fd_nodes = node;
/*
 * Initialize the node.
 */
    node->fd = fd;
    node->rd.fn = 0;
    node->rd.data = NULL;
    node->ur = node->wr = node->rd;
  };
/*
 * Record the new callback.
 */
  switch(event) {
  case GLFD_READ:
    node->rd.fn = callback;
    node->rd.data = data;
    if(callback)
      FD_SET(fd, &gl->rfds);
    else
      FD_CLR(fd, &gl->rfds);
    break;
  case GLFD_WRITE:
    node->wr.fn = callback;
    node->wr.data = data;
    if(callback)
      FD_SET(fd, &gl->wfds);
    else
      FD_CLR(fd, &gl->wfds);
    break;
  case GLFD_URGENT:
    node->ur.fn = callback;
    node->ur.data = data;
    if(callback)
      FD_SET(fd, &gl->ufds);
    else
      FD_CLR(fd, &gl->ufds);
    break;
  };
/*
 * Keep a record of the largest file descriptor being watched.
 */
  if(fd > gl->max_fd)
    gl->max_fd = fd;
/*
 * If we are deleting an existing callback, also delete the parent
 * activity node if no callbacks are registered to the fd anymore.
 */
  if(!callback) {
    if(!node->rd.fn && !node->wr.fn && !node->ur.fn) {
      if(prev)
	prev->next = node->next;
      else
	gl->fd_nodes = node->next;
      node = (GlFdNode *) _del_FreeListNode(gl->fd_node_mem, node);
    };
  };
  return 0;
}
#endif

/*.......................................................................
 * On systems with the select() system call, the gl_inactivity_timeout()
 * function provides the option of setting (or cancelling) an
 * inactivity timeout. Inactivity, in this case, refers both to
 * terminal input received from the user, and to I/O on any file
 * descriptors registered by calls to gl_watch_fd(). If at any time,
 * no activity is seen for the requested time period, the specified
 * timeout callback function is called. On returning, this callback
 * returns a code which tells gl_get_line() what to do next. Note that
 * each call to gl_inactivity_timeout() replaces any previously installed
 * timeout callback, and that specifying a callback of 0, turns off
 * inactivity timing.
 *
 * Beware that although the timeout argument includes a nano-second
 * component, few computer clocks presently have resolutions finer
 * than a few milliseconds, so asking for less than a few milliseconds
 * is equivalent to zero on a lot of systems.
 *
 * Input:
 *  gl            GetLine *  The resource object of the command-line input
 *                           module.
 *  callback  GlTimeoutFn *  The function to call when the inactivity
 *                           timeout is exceeded. To turn off
 *                           inactivity timeouts altogether, send 0.
 *  data             void *  A pointer to arbitrary data to pass to the
 *                           callback function.
 *  sec     unsigned long    The number of whole seconds in the timeout.
 *  nsec    unsigned long    The fractional number of seconds in the
 *                           timeout, expressed in nano-seconds (see
 *                           the caveat above).
 * Output:
 *  return            int    0 - OK.
 *                           1 - Either gl==NULL, or this facility isn't
 *                               available on the the host system
 *                               (ie. select() isn't available). No
 *                               error message is generated in the latter
 *                               case.
 */
int gl_inactivity_timeout(GetLine *gl, GlTimeoutFn *timeout_fn, void *data,
		   unsigned long sec, unsigned long nsec)
#if !defined(HAVE_SELECT)
{return 1;}               /* The facility isn't supported on this system */
#else
{
  sigset_t oldset; /* The signals that were blocked on entry to this function */
/*
 * Check the arguments.
 */
  if(!gl) {
    errno = EINVAL;
    return 1;
  };
/*
 * Block all signals.
 */
  if(gl_mask_signals(gl, &oldset))
    return 1;
/*
 * Install a new timeout?
 */
  if(timeout_fn) {
    gl->timer.dt.tv_sec = sec;
    gl->timer.dt.tv_usec = nsec / 1000;
    gl->timer.fn = timeout_fn;
    gl->timer.data = data;
  } else {
    gl->timer.fn = 0;
    gl->timer.data = NULL;
  };
/*
 * Restore the process signal mask.
 */
  gl_unmask_signals(gl, &oldset);
  return 0;
}
#endif

/*.......................................................................
 * When select() is available, this is a private function of
 * gl_read_input() which responds to file-descriptor events registered by
 * the caller. Note that it assumes that it is being called from within
 * gl_read_input()'s sigsetjump() clause.
 *
 * Input:
 *  gl    GetLine *  The resource object of this module.
 *  fd        int    The file descriptor to be watched for user input.
 * Output:
 *  return    int    0 - OK.
 *                   1 - An error occurred.
 */
static int gl_event_handler(GetLine *gl, int fd)
{
#if !defined(HAVE_SELECT)
  return 0;
#else
/*
 * Set up a zero-second timeout.
 */
  struct timeval zero;
  zero.tv_sec = zero.tv_usec = 0;
/*
 * If at any time no external callbacks remain, quit the loop return,
 * so that we can simply wait in read(). This is designed as an
 * optimization for when no callbacks have been registered on entry to
 * this function, but since callbacks can delete themselves, it can
 * also help later.
 */
  while(gl->fd_nodes || gl->timer.fn) {
    int nready;   /* The number of file descriptors that are ready for I/O */
/*
 * Get the set of descriptors to be watched.
 */
    fd_set rfds = gl->rfds;
    fd_set wfds = gl->wfds;
    fd_set ufds = gl->ufds;
/*
 * Get the appropriate timeout.
 */
    struct timeval dt = gl->timer.fn ? gl->timer.dt : zero;
/*
 * Add the specified user-input file descriptor to the set that is to
 * be watched.
 */
    FD_SET(fd, &rfds);
/*
 * Unblock the signals that we are watching, while select is blocked
 * waiting for I/O.
 */
    gl_catch_signals(gl);
/*
 * Wait for activity on any of the file descriptors.
 */
    nready = select(gl->max_fd+1, &rfds, &wfds, &ufds,
	    (gl->timer.fn || gl->io_mode==GL_SERVER_MODE) ? &dt : NULL);
/*
 * We don't want to do a longjmp in the middle of a callback that
 * might be modifying global or heap data, so block all the signals
 * that we are trapping before executing callback functions. Note that
 * the caller will unblock them again when it needs to, so there is
 * no need to undo this before returning.
 */
    gl_mask_signals(gl, NULL);
/*
 * If select() returns but none of the file descriptors are reported
 * to have activity, then select() timed out.
 */
    if(nready == 0) {
/*
 * Note that in non-blocking server mode, the inactivity timer is used
 * to allow I/O to block for a specified amount of time, so in this
 * mode we return the postponed blocked status when an abort is
 * requested.
 */
      if(gl_call_timeout_handler(gl)) {
	return 1;
      } else if(gl->io_mode == GL_SERVER_MODE) {
	gl_record_status(gl, GLR_BLOCKED, BLOCKED_ERRNO);
	return 1;
      };
/*
 * If nready < 0, this means an error occurred.
 */
    } else if(nready < 0) {
      if(errno != EINTR) {
	gl_record_status(gl, GLR_ERROR, errno);
	return 1;
      };
/*
 * If the user-input file descriptor has data available, return.
 */
    } else if(FD_ISSET(fd, &rfds)) {
      return 0;
/*
 * Check for activity on any of the file descriptors registered by the
 * calling application, and call the associated callback functions.
 */
    } else {
      GlFdNode *node;   /* The fd event node being checked */
/*
 * Search the list for the file descriptor that caused select() to return.
 */
      for(node=gl->fd_nodes; node; node=node->next) {
/*
 * Is there urgent out of band data waiting to be read on fd?
 */
	if(node->ur.fn && FD_ISSET(node->fd, &ufds)) {
	  if(gl_call_fd_handler(gl, &node->ur, node->fd, GLFD_URGENT))
	    return 1;
	  break;  /* The callback may have changed the list of nodes */
/*
 * Is the fd readable?
 */
	} else if(node->rd.fn && FD_ISSET(node->fd, &rfds)) {
	  if(gl_call_fd_handler(gl, &node->rd, node->fd, GLFD_READ))
	    return 1;
	  break;  /* The callback may have changed the list of nodes */
/*
 * Is the fd writable?
 */
	} else if(node->wr.fn && FD_ISSET(node->fd, &wfds)) {
	  if(gl_call_fd_handler(gl, &node->wr, node->fd, GLFD_WRITE))
	    return 1;
	  break;  /* The callback may have changed the list of nodes */
	};
      };
    };
/*
 * Just in case the above event handlers asked for the input line to
 * be redrawn, flush any pending output.
 */
    if(gl_flush_output(gl))
      return 1;
  };
  return 0;
}
#endif

#if defined(HAVE_SELECT)
/*.......................................................................
 * This is a private function of gl_event_handler(), used to call a
 * file-descriptor callback.
 *
 * Input:
 *  gl       GetLine *  The resource object of gl_get_line().
 *  gfh  GlFdHandler *  The I/O handler.
 *  fd           int    The file-descriptor being reported.
 *  event  GlFdEvent    The I/O event being reported.
 * Output:
 *  return       int    0 - OK.
 *                      1 - Error.
 */
static int gl_call_fd_handler(GetLine *gl, GlFdHandler *gfh, int fd,
			      GlFdEvent event)
{
  Termios attr;       /* The terminal attributes */
  int waserr = 0;     /* True after any error */
/*
 * Re-enable conversion of newline characters to carriage-return/linefeed,
 * so that the callback can write to the terminal without having to do
 * anything special.
 */
  if(tcgetattr(gl->input_fd, &attr)) {
    _err_record_msg(gl->err, "tcgetattr error", END_ERR_MSG);
    return 1;
  };
  attr.c_oflag |= OPOST;
  while(tcsetattr(gl->input_fd, TCSADRAIN, &attr)) {
    if(errno != EINTR) {
      _err_record_msg(gl->err, "tcsetattr error", END_ERR_MSG);
      return 1;
    };
  };
/*
 * Invoke the application's callback function.
 */
  switch(gfh->fn(gl, gfh->data, fd, event)) {
  default:
  case GLFD_ABORT:
    gl_record_status(gl, GLR_FDABORT, 0);
    waserr = 1;
    break;
  case GLFD_REFRESH:
    gl_queue_redisplay(gl);
    break;
  case GLFD_CONTINUE:
    break;
  };
/*
 * Disable conversion of newline characters to carriage-return/linefeed.
 */
  attr.c_oflag &= ~(OPOST);
  while(tcsetattr(gl->input_fd, TCSADRAIN, &attr)) {
    if(errno != EINTR) {
      _err_record_msg(gl->err, "tcsetattr error", END_ERR_MSG);
      return 1;
    };
  };
  return waserr;
}

/*.......................................................................
 * This is a private function of gl_event_handler(), used to call a
 * inactivity timer callbacks.
 *
 * Input:
 *  gl       GetLine *  The resource object of gl_get_line().
 * Output:
 *  return       int    0 - OK.
 *                      1 - Error.
 */
static int gl_call_timeout_handler(GetLine *gl)
{
  Termios attr;       /* The terminal attributes */
  int waserr = 0;     /* True after any error */
/*
 * Make sure that there is an inactivity timeout callback.
 */
  if(!gl->timer.fn)
    return 0;
/*
 * Re-enable conversion of newline characters to carriage-return/linefeed,
 * so that the callback can write to the terminal without having to do
 * anything special.
 */
  if(tcgetattr(gl->input_fd, &attr)) {
    _err_record_msg(gl->err, "tcgetattr error", END_ERR_MSG);
    return 1;
  };
  attr.c_oflag |= OPOST;
  while(tcsetattr(gl->input_fd, TCSADRAIN, &attr)) {
    if(errno != EINTR) {
      _err_record_msg(gl->err, "tcsetattr error", END_ERR_MSG);
      return 1;
    };
  };
/*
 * Invoke the application's callback function.
 */
  switch(gl->timer.fn(gl, gl->timer.data)) {
  default:
  case GLTO_ABORT:
    gl_record_status(gl, GLR_TIMEOUT, 0);
    waserr = 1;
    break;
  case GLTO_REFRESH:
    gl_queue_redisplay(gl);
    break;
  case GLTO_CONTINUE:
    break;
  };
/*
 * Disable conversion of newline characters to carriage-return/linefeed.
 */
  attr.c_oflag &= ~(OPOST);
  while(tcsetattr(gl->input_fd, TCSADRAIN, &attr)) {
    if(errno != EINTR) {
      _err_record_msg(gl->err, "tcsetattr error", END_ERR_MSG);
      return 1;
    };
  };
  return waserr;
}
#endif  /* HAVE_SELECT */

/*.......................................................................
 * Switch history groups. History groups represent separate history
 * lists recorded within a single history buffer. Different groups
 * are distinguished by integer identifiers chosen by the calling
 * appplicaton. Initially new_GetLine() sets the group identifier to
 * 0. Whenever a new line is appended to the history list, the current
 * group identifier is recorded with it, and history lookups only
 * consider lines marked with the current group identifier.
 *
 * Input:
 *  gl      GetLine *  The resource object of gl_get_line().
 *  id     unsigned    The new history group identifier.
 * Output:
 *  return      int    0 - OK.
 *                     1 - Error.
 */
int gl_group_history(GetLine *gl, unsigned id)
{
  sigset_t oldset; /* The signals that were blocked on entry to this function */
  int status;      /* The return status of this function */
/*
 * Check the arguments.
 */
  if(!gl) {
    errno = EINVAL;
    return 1;
  };
/*
 * Block all signals while we install the new configuration.
 */
  if(gl_mask_signals(gl, &oldset))
    return 1;
/*
 * If the group isn't being changed, do nothing.
 */
  if(_glh_get_group(gl->glh) == id) {
    status = 0;
/*
 * Establish the new group.
 */
  } else if(_glh_set_group(gl->glh, id)) {
    _err_record_msg(gl->err, _glh_last_error(gl->glh), END_ERR_MSG);
    status = 1;
/*
 * Prevent history information from the previous group being
 * inappropriately used by the next call to gl_get_line().
 */
  } else {
    gl->preload_history = 0;
    gl->last_search = -1;
    status = 0;
  };
/*
 * Restore the process signal mask.
 */
  gl_unmask_signals(gl, &oldset);
  return status;
}

/*.......................................................................
 * Display the contents of the history list.
 *
 * Input:
 *  gl      GetLine *  The resource object of gl_get_line().
 *  fp         FILE *  The stdio output stream to write to.
 *  fmt  const char *  A format string. This containing characters to be
 *                     written verbatim, plus any of the following
 *                     format directives:
 *                       %D  -  The date, formatted like 2001-11-20
 *                       %T  -  The time of day, formatted like 23:59:59
 *                       %N  -  The sequential entry number of the
 *                              line in the history buffer.
 *                       %G  -  The number of the history group that
 *                              the line belongs to.
 *                       %%  -  A literal % character.
 *                       %H  -  The history line itself.
 *                     Note that a '\n' newline character is not
 *                     appended by default.
 *  all_groups  int    If true, display history lines from all
 *                     history groups. Otherwise only display
 *                     those of the current history group.
 *  max_lines   int    If max_lines is < 0, all available lines
 *                     are displayed. Otherwise only the most
 *                     recent max_lines lines will be displayed.
 * Output:
 *  return      int    0 - OK.
 *                     1 - Error.
 */
int gl_show_history(GetLine *gl, FILE *fp, const char *fmt, int all_groups,
		    int max_lines)
{
  sigset_t oldset; /* The signals that were blocked on entry to this function */
  int status;      /* The return status of this function */
/*
 * Check the arguments.
 */
  if(!gl || !fp || !fmt) {
    if(gl)
      _err_record_msg(gl->err, "NULL argument(s)", END_ERR_MSG);
    errno = EINVAL;
    return 1;
  };
/*
 * Block all signals.
 */
  if(gl_mask_signals(gl, &oldset))
    return 1;
/*
 * Display the specified history group(s) while signals are blocked.
 */
  status = _glh_show_history(gl->glh, _io_write_stdio, fp, fmt, all_groups,
			     max_lines) || fflush(fp)==EOF;
  if(!status)
    _err_record_msg(gl->err, _glh_last_error(gl->glh), END_ERR_MSG);
/*
 * Restore the process signal mask.
 */
  gl_unmask_signals(gl, &oldset);
  return status;
}

/*.......................................................................
 * Update if necessary, and return the current size of the terminal.
 *
 * Input:
 *  gl            GetLine *  The resource object of gl_get_line().
 *  def_ncolumn       int    If the number of columns in the terminal
 *                           can't be determined, substitute this number.
 *  def_nline         int    If the number of lines in the terminal can't
 *                           be determined, substitute this number.
 * Output:
 *  return GlTerminalSize    The current terminal size.
 */
GlTerminalSize gl_terminal_size(GetLine *gl, int def_ncolumn, int def_nline)
{
  GlTerminalSize size;  /* The object to be returned */
  sigset_t oldset;      /* The signals that were blocked on entry */
                        /*  to this function */
/*
 * Block all signals while accessing gl.
 */
  gl_mask_signals(gl, &oldset);
/*
 * Lookup/configure the terminal size.
 */
  _gl_terminal_size(gl, def_ncolumn, def_nline, &size);
/*
 * Restore the process signal mask before returning.
 */
  gl_unmask_signals(gl, &oldset);
  return size;
}

/*.......................................................................
 * This is the private body of the gl_terminal_size() function. It
 * assumes that the caller has checked its arguments and blocked the
 * delivery of signals.
 */
static void _gl_terminal_size(GetLine *gl, int def_ncolumn, int def_nline,
			      GlTerminalSize *size)
{
  const char *env;      /* The value of an environment variable */
  int n;                /* A number read from env[] */
/*
 * Set the number of lines and columns to non-sensical values so that
 * we know later if they have been set.
 */
  gl->nline = 0;
  gl->ncolumn = 0;
/*
 * Are we reading from a terminal?
 */
  if(gl->is_term) {
/*
 * Ask the terminal directly if possible.
 */
    (void) _gl_update_size(gl);
/*
 * If gl_update_size() couldn't ask the terminal, it will have
 * left gl->nrow and gl->ncolumn unchanged. If these values haven't
 * been changed from their initial values of zero, we need to find
 * a different method to get the terminal size.
 *
 * If the number of lines isn't known yet, first see if the
 * LINES environment ariable exists and specifies a believable number.
 * If this doesn't work, look up the default size in the terminal
 * information database.
 */
    if(gl->nline < 1) {
      if((env = getenv("LINES")) && (n=atoi(env)) > 0)
	gl->nline = n;
#ifdef USE_TERMINFO
      else
	gl->nline = tigetnum((char *)"lines");
#elif defined(USE_TERMCAP)
      else
        gl->nline = tgetnum("li");
#endif
    };
/*
 * If the number of lines isn't known yet, first see if the COLUMNS
 * environment ariable exists and specifies a believable number.  If
 * this doesn't work, look up the default size in the terminal
 * information database.
 */
    if(gl->ncolumn < 1) {
      if((env = getenv("COLUMNS")) && (n=atoi(env)) > 0)
	gl->ncolumn = n;
#ifdef USE_TERMINFO
      else
	gl->ncolumn = tigetnum((char *)"cols");
#elif defined(USE_TERMCAP)
      else
	gl->ncolumn = tgetnum("co");
#endif
    };
  };
/*
 * If we still haven't been able to acquire reasonable values, substitute
 * the default values specified by the caller.
 */
  if(gl->nline <= 0)
    gl->nline = def_nline;
  if(gl->ncolumn <= 0)
    gl->ncolumn = def_ncolumn;
/*
 * Copy the new size into the return value.
 */
  if(size) {
    size->nline = gl->nline;
    size->ncolumn = gl->ncolumn;
  };
  return;
}

/*.......................................................................
 * Resize or delete the history buffer.
 *
 * Input:
 *  gl      GetLine *  The resource object of gl_get_line().
 *  bufsize  size_t    The number of bytes in the history buffer, or 0
 *                     to delete the buffer completely.
 * Output:
 *  return      int    0 - OK.
 *                     1 - Insufficient memory (the previous buffer
 *                         will have been retained). No error message
 *                         will be displayed.
 */
int gl_resize_history(GetLine *gl, size_t bufsize)
{
  sigset_t oldset; /* The signals that were blocked on entry to this function */
  int status;      /* The return status of this function */
/*
 * Check the arguments.
 */
  if(!gl)
    return 1;
/*
 * Block all signals while modifying the contents of gl.
 */
  if(gl_mask_signals(gl, &oldset))
    return 1;
/*
 * Perform the resize while signals are blocked.
 */
  status = _glh_resize_history(gl->glh, bufsize);
  if(status)
    _err_record_msg(gl->err, _glh_last_error(gl->glh), END_ERR_MSG);
/*
 * Restore the process signal mask before returning.
 */
  gl_unmask_signals(gl, &oldset);
  return status;
}

/*.......................................................................
 * Set an upper limit to the number of lines that can be recorded in the
 * history list, or remove a previously specified limit.
 *
 * Input:
 *  gl      GetLine *  The resource object of gl_get_line().
 *  max_lines   int    The maximum number of lines to allow, or -1 to
 *                     cancel a previous limit and allow as many lines
 *                     as will fit in the current history buffer size.
 */
void gl_limit_history(GetLine *gl, int max_lines)
{
  if(gl) {
    sigset_t oldset; /* The signals that were blocked on entry to this block */
/*
 * Temporarily block all signals.
 */
    gl_mask_signals(gl, &oldset);
/*
 * Apply the limit while signals are blocked.
 */
    _glh_limit_history(gl->glh, max_lines);
/*
 * Restore the process signal mask before returning.
 */
    gl_unmask_signals(gl, &oldset);
  };
}

/*.......................................................................
 * Discard either all historical lines, or just those associated with the
 * current history group.
 *
 * Input:
 *  gl      GetLine *  The resource object of gl_get_line().
 *  all_groups  int    If true, clear all of the history. If false,
 *                     clear only the stored lines associated with the
 *                     currently selected history group.
 */
void gl_clear_history(GetLine *gl, int all_groups)
{
  if(gl) {
    sigset_t oldset; /* The signals that were blocked on entry to this block */
/*
 * Temporarily block all signals.
 */
    gl_mask_signals(gl, &oldset);
/*
 * Clear the history buffer while signals are blocked.
 */
    _glh_clear_history(gl->glh, all_groups);
/*
 * Restore the process signal mask before returning.
 */
    gl_unmask_signals(gl, &oldset);
  };
}

/*.......................................................................
 * Temporarily enable or disable the gl_get_line() history mechanism.
 *
 * Input:
 *  gl      GetLine *  The resource object of gl_get_line().
 *  enable      int    If true, turn on the history mechanism. If
 *                     false, disable it.
 */
void gl_toggle_history(GetLine *gl, int enable)
{
  if(gl) {
    sigset_t oldset; /* The signals that were blocked on entry to this block */
/*
 * Temporarily block all signals.
 */
    gl_mask_signals(gl, &oldset);
/*
 * Change the history recording mode while signals are blocked.
 */
    _glh_toggle_history(gl->glh, enable);
/*
 * Restore the process signal mask before returning.
 */
    gl_unmask_signals(gl, &oldset);
  };
}

/*.......................................................................
 * Lookup a history line by its sequential number of entry in the
 * history buffer.
 *
 * Input:
 *  gl            GetLine *  The resource object of gl_get_line().
 *  id      unsigned long    The identification number of the line to
 *                           be returned, where 0 denotes the first line
 *                           that was entered in the history list, and
 *                           each subsequently added line has a number
 *                           one greater than the previous one. For
 *                           the range of lines currently in the list,
 *                           see the gl_range_of_history() function.
 * Input/Output:
 *  line    GlHistoryLine *  A pointer to the variable in which to
 *                           return the details of the line.
 * Output:
 *  return            int    0 - The line is no longer in the history
 *                               list, and *line has not been changed.
 *                           1 - The requested line can be found in
 *                               *line. Note that line->line is part
 *                               of the history buffer, so a
 *                               private copy should be made if you
 *                               wish to use it after subsequent calls
 *                               to any functions that take *gl as an
 *                               argument.
 */
int gl_lookup_history(GetLine *gl, unsigned long id, GlHistoryLine *line)
{
  sigset_t oldset; /* The signals that were blocked on entry to this function */
  int status;      /* The return status of this function */
/*
 * Check the arguments.
 */
  if(!gl)
    return 0;
/*
 * Block all signals while modifying the contents of gl.
 */
  if(gl_mask_signals(gl, &oldset))
    return 1;
/*
 * Perform the lookup while signals are blocked.
 */
  status = _glh_lookup_history(gl->glh, (GlhLineID) id, &line->line,
			       &line->group, &line->timestamp);
  if(status)
    _err_record_msg(gl->err, _glh_last_error(gl->glh), END_ERR_MSG);
/*
 * Restore the process signal mask before returning.
 */
  gl_unmask_signals(gl, &oldset);
  return status;
}

/*.......................................................................
 * Query the state of the history list. Note that any of the input/output
 * pointers can be specified as NULL.
 *
 * Input:
 *  gl            GetLine *  The resource object of gl_get_line().
 * Input/Output:
 *  state  GlHistoryState *  A pointer to the variable in which to record
 *                           the return values.
 */
void gl_state_of_history(GetLine *gl, GlHistoryState *state)
{
  if(gl && state) {
    sigset_t oldset; /* The signals that were blocked on entry to this block */
/*
 * Temporarily block all signals.
 */
    gl_mask_signals(gl, &oldset);
/*
 * Lookup the status while signals are blocked.
 */
    _glh_state_of_history(gl->glh, &state->enabled, &state->group,
			  &state->max_lines);
/*
 * Restore the process signal mask before returning.
 */
    gl_unmask_signals(gl, &oldset);
  };
}

/*.......................................................................
 * Query the number and range of lines in the history buffer.
 *
 * Input:
 *  gl            GetLine *  The resource object of gl_get_line().
 *  range  GlHistoryRange *  A pointer to the variable in which to record
 *                           the return values. If range->nline=0, the
 *                           range of lines will be given as 0-0.
 */
void gl_range_of_history(GetLine *gl, GlHistoryRange *range)
{
  if(gl && range) {
    sigset_t oldset; /* The signals that were blocked on entry to this block */
/*
 * Temporarily block all signals.
 */
    gl_mask_signals(gl, &oldset);
/*
 * Lookup the information while signals are blocked.
 */
    _glh_range_of_history(gl->glh, &range->oldest, &range->newest,
			  &range->nlines);
/*
 * Restore the process signal mask before returning.
 */
    gl_unmask_signals(gl, &oldset);
  };
}

/*.......................................................................
 * Return the size of the history buffer and the amount of the
 * buffer that is currently in use.
 *
 * Input:
 *  gl         GetLine *  The gl_get_line() resource object.
 * Input/Output:
 *  GlHistorySize size *  A pointer to the variable in which to return
 *                        the results.
 */
void gl_size_of_history(GetLine *gl, GlHistorySize *size)
{
  if(gl && size) {
    sigset_t oldset; /* The signals that were blocked on entry to this block */
/*
 * Temporarily block all signals.
 */
    gl_mask_signals(gl, &oldset);
/*
 * Lookup the information while signals are blocked.
 */
    _glh_size_of_history(gl->glh, &size->size, &size->used);
/*
 * Restore the process signal mask before returning.
 */
    gl_unmask_signals(gl, &oldset);
  };
}

/*.......................................................................
 * This is the action function that lists the contents of the history
 * list.
 */
static KT_KEY_FN(gl_list_history)
{
/*
 * Start a new line.
 */
  if(gl_start_newline(gl, 1))
    return 1;
/*
 * List history lines that belong to the current group.
 */
  _glh_show_history(gl->glh, gl_write_fn, gl, "%N  %T   %H\r\n", 0,
		    count<=1 ? -1 : count);
/*
 * Arrange for the input line to be redisplayed.
 */
  gl_queue_redisplay(gl);
  return 0;
}

/*.......................................................................
 * Specify whether text that users type should be displayed or hidden.
 * In the latter case, only the prompt is displayed, and the final
 * input line is not archived in the history list.
 *
 * Input:
 *  gl         GetLine *  The gl_get_line() resource object.
 *  enable         int     0 - Disable echoing.
 *                         1 - Enable echoing.
 *                        -1 - Just query the mode without changing it.
 * Output:
 *  return         int    The echoing disposition that was in effect
 *                        before this function was called:
 *                         0 - Echoing was disabled.
 *                         1 - Echoing was enabled.
 */
int gl_echo_mode(GetLine *gl, int enable)
{
  if(gl) {
    sigset_t oldset; /* The signals that were blocked on entry to this block */
    int was_echoing; /* The echoing disposition on entry to this function */
/*
 * Temporarily block all signals.
 */
    gl_mask_signals(gl, &oldset);
/*
 * Install the new disposition while signals are blocked.
 */
    was_echoing = gl->echo;
    if(enable >= 0)
      gl->echo = enable;
/*
 * Restore the process signal mask before returning.
 */
    gl_unmask_signals(gl, &oldset);
/*
 * Return the original echoing disposition.
 */
    return was_echoing;
  };
  return 1;
}

/*.......................................................................
 * Display the prompt.
 *
 * Input:
 *  gl         GetLine *  The resource object of gl_get_line().
 * Output:
 *  return         int    0 - OK.
 *                        1 - Error.
 */
static int gl_display_prompt(GetLine *gl)
{
  const char *pptr;       /* A pointer into gl->prompt[] */
  unsigned old_attr=0;    /* The current text display attributes */
  unsigned new_attr=0;    /* The requested text display attributes */
/*
 * Temporarily switch to echoing output characters.
 */
  int kept_echo = gl->echo;
  gl->echo = 1;
/*
 * In case the screen got messed up, send a carriage return to
 * put the cursor at the beginning of the current terminal line.
 */
  if(gl_print_control_sequence(gl, 1, gl->bol))
    return 1;
/*
 * Mark the line as partially displayed.
 */
  gl->displayed = 1;
/*
 * Write the prompt, using the currently selected prompt style.
 */
  switch(gl->prompt_style) {
  case GL_LITERAL_PROMPT:
    if(gl_print_string(gl, gl->prompt, '\0'))
      return 1;
    break;
  case GL_FORMAT_PROMPT:
    for(pptr=gl->prompt; *pptr; pptr++) {
/*
 * Does the latest character appear to be the start of a directive?
 */
      if(*pptr == '%') {
/*
 * Check for and act on attribute changing directives.
 */
	switch(pptr[1]) {
/*
 * Add or remove a text attribute from the new set of attributes.
 */
	case 'B': case 'U': case 'S': case 'P': case 'F': case 'V':
	case 'b': case 'u': case 's': case 'p': case 'f': case 'v':
	  switch(*++pptr) {
	  case 'B':           /* Switch to a bold font */
	    new_attr |= GL_TXT_BOLD;
	    break;
	  case 'b':           /* Switch to a non-bold font */
	    new_attr &= ~GL_TXT_BOLD;
	    break;
	  case 'U':           /* Start underlining */
	    new_attr |= GL_TXT_UNDERLINE;
	    break;
	  case 'u':           /* Stop underlining */
	    new_attr &= ~GL_TXT_UNDERLINE;
	    break;
	  case 'S':           /* Start highlighting */
	    new_attr |= GL_TXT_STANDOUT;
	    break;
	  case 's':           /* Stop highlighting */
	    new_attr &= ~GL_TXT_STANDOUT;
	    break;
	  case 'P':           /* Switch to a pale font */
	    new_attr |= GL_TXT_DIM;
	    break;
	  case 'p':           /* Switch to a non-pale font */
	    new_attr &= ~GL_TXT_DIM;
	    break;
	  case 'F':           /* Switch to a flashing font */
	    new_attr |= GL_TXT_BLINK;
	    break;
	  case 'f':           /* Switch to a steady font */
	    new_attr &= ~GL_TXT_BLINK;
	    break;
	  case 'V':           /* Switch to reverse video */
	    new_attr |= GL_TXT_REVERSE;
	    break;
	  case 'v':           /* Switch out of reverse video */
	    new_attr &= ~GL_TXT_REVERSE;
	    break;
	  };
	  continue;
/*
 * A literal % is represented by %%. Skip the leading %.
 */
	case '%':
	  pptr++;
	  break;
	};
      };
/*
 * Many terminals, when asked to turn off a single text attribute, turn
 * them all off, so the portable way to turn one off individually is to
 * explicitly turn them all off, then specify those that we want from
 * scratch.
 */
      if(old_attr & ~new_attr) {
	if(gl_print_control_sequence(gl, 1, gl->text_attr_off))
	  return 1;
	old_attr = 0;
      };
/*
 * Install new text attributes?
 */
      if(new_attr != old_attr) {
	if(new_attr & GL_TXT_BOLD && !(old_attr & GL_TXT_BOLD) &&
	   gl_print_control_sequence(gl, 1, gl->bold))
	  return 1;
	if(new_attr & GL_TXT_UNDERLINE && !(old_attr & GL_TXT_UNDERLINE) &&
	   gl_print_control_sequence(gl, 1, gl->underline))
	  return 1;
	if(new_attr & GL_TXT_STANDOUT && !(old_attr & GL_TXT_STANDOUT) &&
	   gl_print_control_sequence(gl, 1, gl->standout))
	  return 1;
	if(new_attr & GL_TXT_DIM && !(old_attr & GL_TXT_DIM) &&
	   gl_print_control_sequence(gl, 1, gl->dim))
	  return 1;
	if(new_attr & GL_TXT_REVERSE && !(old_attr & GL_TXT_REVERSE) &&
	   gl_print_control_sequence(gl, 1, gl->reverse))
	  return 1;
	if(new_attr & GL_TXT_BLINK && !(old_attr & GL_TXT_BLINK) &&
	   gl_print_control_sequence(gl, 1, gl->blink))
	  return 1;
	old_attr = new_attr;
      };
/*
 * Display the latest character.
 */
      if(gl_print_char(gl, *pptr, pptr[1]))
	return 1;
    };
/*
 * Turn off all text attributes now that we have finished drawing
 * the prompt.
 */
    if(gl_print_control_sequence(gl, 1, gl->text_attr_off))
      return 1;
    break;
  };
/*
 * Restore the original echo mode.
 */
  gl->echo = kept_echo;
/*
 * The prompt has now been displayed at least once.
 */
  gl->prompt_changed = 0;
  return 0;
}

/*.......................................................................
 * This function can be called from gl_get_line() callbacks to have
 * the prompt changed when they return. It has no effect if gl_get_line()
 * is not currently being invoked.
 *
 * Input:
 *  gl         GetLine *  The resource object of gl_get_line().
 *  prompt  const char *  The new prompt.
 */
void gl_replace_prompt(GetLine *gl, const char *prompt)
{
  if(gl) {
    sigset_t oldset; /* The signals that were blocked on entry to this block */
/*
 * Temporarily block all signals.
 */
    gl_mask_signals(gl, &oldset);
/*
 * Replace the prompt.
 */
    _gl_replace_prompt(gl, prompt);
/*
 * Restore the process signal mask before returning.
 */
    gl_unmask_signals(gl, &oldset);
  };
}

/*.......................................................................
 * This is the private body of the gl_replace_prompt() function. It
 * assumes that the caller has checked its arguments and blocked the
 * delivery of signals.
 */
static void _gl_replace_prompt(GetLine *gl, const char *prompt)
{
  size_t size;

/*
 * Substitute an empty prompt?
 */
  if(!prompt)
    prompt = "";
/*
 * Gaurd against aliasing between prompt and gl->prompt.
 */
  if(gl->prompt != prompt) {
/*
 * Get the length of the new prompt string.
 */
    size_t slen = strlen(prompt);
/*
 * If needed, allocate a new buffer for the prompt string.
 */
    size = sizeof(char) * (slen + 1);
    if(!gl->prompt || slen > strlen(gl->prompt)) {
      char *new_prompt = gl->prompt ? realloc(gl->prompt, size) : malloc(size);
      if(!new_prompt)
	return;
      gl->prompt = new_prompt;
    };
/*
 * Make a copy of the new prompt.
 */
    strlcpy(gl->prompt, prompt, size);
  };
/*
 * Record the statistics of the new prompt.
 */
  gl->prompt_len = gl_displayed_prompt_width(gl);
  gl->prompt_changed = 1;
  gl_queue_redisplay(gl);
  return;
}

/*.......................................................................
 * Work out the length of the current prompt on the terminal, according
 * to the current prompt formatting style.
 *
 * Input:
 *  gl       GetLine *  The resource object of this library.
 * Output:
 *  return       int    The number of displayed characters.
 */
static int gl_displayed_prompt_width(GetLine *gl)
{
  int slen=0;         /* The displayed number of characters */
  const char *pptr;   /* A pointer into prompt[] */
/*
 * The length differs according to the prompt display style.
 */
  switch(gl->prompt_style) {
  case GL_LITERAL_PROMPT:
    return gl_displayed_string_width(gl, gl->prompt, -1, 0);
    break;
  case GL_FORMAT_PROMPT:
/*
 * Add up the length of the displayed string, while filtering out
 * attribute directives.
 */
    for(pptr=gl->prompt; *pptr; pptr++) {
/*
 * Does the latest character appear to be the start of a directive?
 */
      if(*pptr == '%') {
/*
 * Check for and skip attribute changing directives.
 */
	switch(pptr[1]) {
	case 'B': case 'b': case 'U': case 'u': case 'S': case 's':
	  pptr++;
	  continue;
/*
 * A literal % is represented by %%. Skip the leading %.
 */
	case '%':
	  pptr++;
	  break;
	};
      };
      slen += gl_displayed_char_width(gl, *pptr, slen);
    };
    break;
  };
  return slen;
}

/*.......................................................................
 * Specify whether to heed text attribute directives within prompt
 * strings.
 *
 * Input:
 *  gl           GetLine *  The resource object of gl_get_line().
 *  style  GlPromptStyle    The style of prompt (see the definition of
 *                          GlPromptStyle in libtecla.h for details).
 */
void gl_prompt_style(GetLine *gl, GlPromptStyle style)
{
  if(gl) {
    sigset_t oldset; /* The signals that were blocked on entry to this block */
/*
 * Temporarily block all signals.
 */
    gl_mask_signals(gl, &oldset);
/*
 * Install the new style in gl while signals are blocked.
 */
    if(style != gl->prompt_style) {
      gl->prompt_style = style;
      gl->prompt_len = gl_displayed_prompt_width(gl);
      gl->prompt_changed = 1;
      gl_queue_redisplay(gl);
    };
/*
 * Restore the process signal mask before returning.
 */
    gl_unmask_signals(gl, &oldset);
  };
}

/*.......................................................................
 * Tell gl_get_line() how to respond to a given signal. This can be used
 * both to override the default responses to signals that gl_get_line()
 * normally catches and to add new signals to the list that are to be
 * caught.
 *
 * Input:
 *  gl           GetLine *  The resource object of gl_get_line().
 *  signo            int    The number of the signal to be caught.
 *  flags       unsigned    A bitwise union of GlSignalFlags enumerators.
 *  after  GlAfterSignal    What to do after the application's signal
 *                          handler has been called.
 *  errno_value      int    The value to set errno to.
 * Output:
 *  return           int    0 - OK.
 *                          1 - Error.
 */
int gl_trap_signal(GetLine *gl, int signo, unsigned flags,
		   GlAfterSignal after, int errno_value)
{
  sigset_t oldset; /* The signals that were blocked on entry to this function */
  int status;      /* The return status of this function */
/*
 * Check the arguments.
 */
  if(!gl) {
    errno = EINVAL;
    return 1;
  };
/*
 * Block all signals while modifying the contents of gl.
 */
  if(gl_mask_signals(gl, &oldset))
    return 1;
/*
 * Perform the modification while signals are blocked.
 */
  status = _gl_trap_signal(gl, signo, flags, after, errno_value);
/*
 * Restore the process signal mask before returning.
 */
  gl_unmask_signals(gl, &oldset);
  return status;
}

/*.......................................................................
 * This is the private body of the gl_trap_signal() function. It
 * assumes that the caller has checked its arguments and blocked the
 * delivery of signals.
 */
static int _gl_trap_signal(GetLine *gl, int signo, unsigned flags,
			   GlAfterSignal after, int errno_value)
{
  GlSignalNode *sig;
/*
 * Complain if an attempt is made to trap untrappable signals.
 * These would otherwise cause errors later in gl_mask_signals().
 */
  if(0
#ifdef SIGKILL
     || signo==SIGKILL
#endif
#ifdef SIGBLOCK
     || signo==SIGBLOCK
#endif
     ) {
    return 1;
  };
/*
 * See if the signal has already been registered.
 */
  for(sig=gl->sigs; sig && sig->signo != signo; sig = sig->next)
    ;
/*
 * If the signal hasn't already been registered, allocate a node for
 * it.
 */
  if(!sig) {
    sig = (GlSignalNode *) _new_FreeListNode(gl->sig_mem);
    if(!sig)
      return 1;
/*
 * Add the new node to the head of the list.
 */
    sig->next = gl->sigs;
    gl->sigs = sig;
/*
 * Record the signal number.
 */
    sig->signo = signo;
/*
 * Create a signal set that includes just this signal.
 */
    sigemptyset(&sig->proc_mask);
    if(sigaddset(&sig->proc_mask, signo) == -1) {
      _err_record_msg(gl->err, "sigaddset error", END_ERR_MSG);
      sig = (GlSignalNode *) _del_FreeListNode(gl->sig_mem, sig);
      return 1;
    };
/*
 * Add the signal to the bit-mask of signals being trapped.
 */
    sigaddset(&gl->all_signal_set, signo);
  };
/*
 * Record the new signal attributes.
 */
  sig->flags = flags;
  sig->after = after;
  sig->errno_value = errno_value;
  return 0;
}

/*.......................................................................
 * Remove a signal from the list of signals that gl_get_line() traps.
 *
 * Input:
 *  gl           GetLine *  The resource object of gl_get_line().
 *  signo            int    The number of the signal to be ignored.
 * Output:
 *  return           int    0 - OK.
 *                          1 - Error.
 */
int gl_ignore_signal(GetLine *gl, int signo)
{
  GlSignalNode *sig;  /* The gl->sigs list node of the specified signal */
  GlSignalNode *prev; /* The node that precedes sig in the list */
  sigset_t oldset;    /* The signals that were blocked on entry to this */
                      /*  function. */
/*
 * Check the arguments.
 */
  if(!gl) {
    errno = EINVAL;
    return 1;
  };
/*
 * Block all signals while modifying the contents of gl.
 */
  if(gl_mask_signals(gl, &oldset))
    return 1;
/*
 * Find the node of the gl->sigs list which records the disposition
 * of the specified signal.
 */
  for(prev=NULL,sig=gl->sigs; sig && sig->signo != signo;
      prev=sig,sig=sig->next)
    ;
  if(sig) {
/*
 * Remove the node from the list.
 */
    if(prev)
      prev->next = sig->next;
    else
      gl->sigs = sig->next;
/*
 * Return the node to the freelist.
 */
    sig = (GlSignalNode *) _del_FreeListNode(gl->sig_mem, sig);
/*
 * Remove the signal from the bit-mask union of signals being trapped.
 */
    sigdelset(&gl->all_signal_set, signo);
  };
/*
 * Restore the process signal mask before returning.
 */
  gl_unmask_signals(gl, &oldset);
  return 0;
}

/*.......................................................................
 * This function is called when an input line has been completed. It
 * appends the specified newline character, terminates the line,
 * records the line in the history buffer if appropriate, and positions
 * the terminal cursor at the start of the next line.
 *
 * Input:
 *  gl           GetLine *  The resource object of gl_get_line().
 *  newline_char     int    The newline character to add to the end
 *                          of the line.
 * Output:
 *  return           int    0 - OK.
 *                          1 - Error.
 */
static int gl_line_ended(GetLine *gl, int newline_char)
{
/*
 * If the newline character is printable, display it at the end of
 * the line, and add it to the input line buffer.
 */
  if(isprint((int)(unsigned char) newline_char)) {
    if(gl_end_of_line(gl, 1, NULL) || gl_add_char_to_line(gl, newline_char))
      return 1;
  } else {
/*
 * Otherwise just append a newline character to the input line buffer.
 */
    newline_char = '\n';
    gl_buffer_char(gl, newline_char, gl->ntotal);
  };
/*
 * Add the line to the history buffer if it was entered with a
 * newline character.
 */
  if(gl->echo && gl->automatic_history && newline_char=='\n')
    (void) _gl_append_history(gl, gl->line);
/*
 * Except when depending on the system-provided line editing, start a new
 * line after the end of the line that has just been entered.
 */
  if(gl->editor != GL_NO_EDITOR && gl_start_newline(gl, 1))
    return 1;
/*
 * Record the successful return status.
 */
  gl_record_status(gl, GLR_NEWLINE, 0);
/*
 * Attempt to flush any pending output.
 */
  (void) gl_flush_output(gl);
/*
 * The next call to gl_get_line() will write the prompt for a new line
 * (or continue the above flush if incomplete), so if we manage to
 * flush the terminal now, report that we are waiting to write to the
 * terminal.
 */
  gl->pending_io = GLP_WRITE;
  return 0;
}

/*.......................................................................
 * Return the last signal that was caught by the most recent call to
 * gl_get_line(), or -1 if no signals were caught. This is useful if
 * gl_get_line() returns errno=EINTR and you need to find out what signal
 * caused it to abort.
 *
 * Input:
 *  gl           GetLine *  The resource object of gl_get_line().
 * Output:
 *  return           int    The last signal caught by the most recent
 *                          call to gl_get_line(), or -1 if no signals
 *                          were caught.
 */
int gl_last_signal(GetLine *gl)
{
  int signo = -1;   /* The requested signal number */
  if(gl) {
    sigset_t oldset; /* The signals that were blocked on entry to this block */
/*
 * Temporarily block all signals.
 */
    gl_mask_signals(gl, &oldset);
/*
 * Access gl now that signals are blocked.
 */
    signo = gl->last_signal;
/*
 * Restore the process signal mask before returning.
 */
    gl_unmask_signals(gl, &oldset);
  };
  return signo;
}

/*.......................................................................
 * Prepare to edit a new line.
 *
 * Input:
 *  gl         GetLine *  The resource object of this library.
 *  prompt        char *  The prompt to prefix the line with, or NULL to
 *                        use the same prompt that was used by the previous
 *                        line.
 *  start_line    char *  The initial contents of the input line, or NULL
 *                        if it should start out empty.
 *  start_pos      int    If start_line isn't NULL, this specifies the
 *                        index of the character over which the cursor
 *                        should initially be positioned within the line.
 *                        If you just want it to follow the last character
 *                        of the line, send -1.
 * Output:
 *  return    int    0 - OK.
 *                   1 - Error.
 */
static int gl_present_line(GetLine *gl, const char *prompt,
			   const char *start_line, int start_pos)
{
/*
 * Reset the properties of the line.
 */
  gl_reset_input_line(gl);
/*
 * Record the new prompt and its displayed width.
 */
  if(prompt)
    _gl_replace_prompt(gl, prompt);
/*
 * Reset the history search pointers.
 */
  if(_glh_cancel_search(gl->glh)) {
    _err_record_msg(gl->err, _glh_last_error(gl->glh), END_ERR_MSG);
    return 1;
  };
/*
 * If the previous line was entered via the repeat-history action,
 * preload the specified history line.
 */
  if(gl->preload_history) {
    gl->preload_history = 0;
    if(gl->preload_id) {
      if(_glh_recall_line(gl->glh, gl->preload_id, gl->line, gl->linelen+1)) {
	gl_update_buffer(gl);          /* Compute gl->ntotal etc.. */
	gl->buff_curpos = gl->ntotal;
      } else {
	gl_truncate_buffer(gl, 0);
      };
      gl->preload_id = 0;
    };
/*
 * Present a specified initial line?
 */
  } else if(start_line) {
    char *cptr;      /* A pointer into gl->line[] */
/*
 * Measure the length of the starting line.
 */
    int start_len = strlen(start_line);
/*
 * If the length of the line is greater than the available space,
 * truncate it.
 */
    if(start_len > gl->linelen)
      start_len = gl->linelen;
/*
 * Load the line into the buffer.
 */
    if(start_line != gl->line)
      gl_buffer_string(gl, start_line, start_len, 0);
/*
 * Strip off any trailing newline and carriage return characters.
 */
    for(cptr=gl->line + gl->ntotal - 1; cptr >= gl->line &&
	(*cptr=='\n' || *cptr=='\r'); cptr--,gl->ntotal--)
      ;
    gl_truncate_buffer(gl, gl->ntotal < 0 ? 0 : gl->ntotal);
/*
 * Where should the cursor be placed within the line?
 */
    if(start_pos < 0 || start_pos > gl->ntotal) {
      if(gl_place_cursor(gl, gl->ntotal))
	return 1;
    } else {
      if(gl_place_cursor(gl, start_pos))
	return 1;
    };
/*
 * Clear the input line?
 */
  } else {
    gl_truncate_buffer(gl, 0);
  };
/*
 * Arrange for the line to be displayed by gl_flush_output().
 */
  gl_queue_redisplay(gl);
/*
 * Update the display.
 */
  return gl_flush_output(gl);
}

/*.......................................................................
 * Reset all line input parameters for a new input line.
 *
 * Input:
 *  gl      GetLine *  The line editor resource object.
 */
static void gl_reset_input_line(GetLine *gl)
{
  gl->ntotal = 0;
  gl->line[0] = '\0';
  gl->buff_curpos = 0;
  gl->term_curpos = 0;
  gl->term_len = 0;
  gl->insert_curpos = 0;
  gl->number = -1;
  gl->displayed = 0;
  gl->endline = 0;
  gl->redisplay = 0;
  gl->postpone = 0;
  gl->nbuf = 0;
  gl->nread = 0;
  gl->vi.command = 0;
  gl->vi.undo.line[0] = '\0';
  gl->vi.undo.ntotal = 0;
  gl->vi.undo.buff_curpos = 0;
  gl->vi.repeat.action.fn = 0;
  gl->vi.repeat.action.data = 0;
  gl->last_signal = -1;
}

/*.......................................................................
 * Print an informational message to the terminal, after starting a new
 * line.
 *
 * Input:
 *  gl      GetLine *  The line editor resource object.
 *  ...  const char *  Zero or more strings to be printed.
 *  ...        void *  The last argument must always be GL_END_INFO.
 * Output:
 *  return      int    0 - OK.
 *                     1 - Error.
 */
static int gl_print_info(GetLine *gl, ...)
{
  va_list ap;     /* The variable argument list */
  const char *s;  /* The string being printed */
  int waserr = 0; /* True after an error */
/*
 * Only display output when echoing is on.
 */
  if(gl->echo) {
/*
 * Skip to the start of the next empty line before displaying the message.
 */
    if(gl_start_newline(gl, 1))
      return 1;
/*
 * Display the list of provided messages.
 */
    va_start(ap, gl);
    while(!waserr && (s = va_arg(ap, const char *)) != GL_END_INFO)
      waserr = gl_print_raw_string(gl, 1, s, -1);
    va_end(ap);
/*
 * Start a newline.
 */
    waserr = waserr || gl_print_raw_string(gl, 1, "\n\r", -1);
/*
 * Arrange for the input line to be redrawn.
 */
    gl_queue_redisplay(gl);
  };
  return waserr;
}

/*.......................................................................
 * Go to the start of the next empty line, ready to output miscellaneous
 * text to the screen.
 *
 * Note that when async-signal safety is required, the 'buffered'
 * argument must be 0.
 *
 * Input:
 *  gl          GetLine *  The line editor resource object.
 *  buffered        int    If true, used buffered I/O when writing to
 *                         the terminal. Otherwise use async-signal-safe
 *                         unbuffered I/O.
 * Output:
 *  return          int    0 - OK.
 *                         1 - Error.
 */
static int gl_start_newline(GetLine *gl, int buffered)
{
  int waserr = 0;  /* True after any I/O error */
/*
 * Move the cursor to the start of the terminal line that follows the
 * last line of the partially enterred line. In order that this
 * function remain async-signal safe when write_fn is signal safe, we
 * can't call our normal output functions, since they call tputs(),
 * who's signal saftey isn't defined. Fortunately, we can simply use
 * \r and \n to move the cursor to the right place.
 */
  if(gl->displayed) {   /* Is an input line currently displayed? */
/*
 * On which terminal lines are the cursor and the last character of the
 * input line?
 */
    int curs_line = gl->term_curpos / gl->ncolumn;
    int last_line = gl->term_len / gl->ncolumn;
/*
 * Move the cursor to the start of the line that follows the last
 * terminal line that is occupied by the input line.
 */
    for( ; curs_line < last_line + 1; curs_line++)
      waserr = waserr || gl_print_raw_string(gl, buffered, "\n", 1);
    waserr = waserr || gl_print_raw_string(gl, buffered, "\r", 1);
/*
 * Mark the line as no longer displayed.
 */
    gl_line_erased(gl);
  };
  return waserr;
}

/*.......................................................................
 * The callback through which all terminal output is routed.
 * This simply appends characters to a queue buffer, which is
 * subsequently flushed to the output channel by gl_flush_output().
 *
 * Input:
 *  data     void *  The pointer to a GetLine line editor resource object
 *                   cast to (void *).
 *  s  const char *  The string to be written.
 *  n         int    The number of characters to write from s[].
 * Output:
 *  return    int    The number of characters written. This will always
 *                   be equal to 'n' unless an error occurs.
 */
static GL_WRITE_FN(gl_write_fn)
{
  GetLine *gl = (GetLine *) data;
  int ndone = _glq_append_chars(gl->cq, s, n, gl->flush_fn, gl);
  if(ndone != n)
    _err_record_msg(gl->err, _glq_last_error(gl->cq), END_ERR_MSG);
  return ndone;
}

/*.......................................................................
 * Ask gl_get_line() what caused it to return.
 *
 * Input:
 *  gl             GetLine *  The line editor resource object.
 * Output:
 *  return  GlReturnStatus    The return status of the last call to
 *                            gl_get_line().
 */
GlReturnStatus gl_return_status(GetLine *gl)
{
  GlReturnStatus rtn_status = GLR_ERROR;   /* The requested status */
  if(gl) {
    sigset_t oldset; /* The signals that were blocked on entry to this block */
/*
 * Temporarily block all signals.
 */
    gl_mask_signals(gl, &oldset);
/*
 * Access gl while signals are blocked.
 */
    rtn_status = gl->rtn_status;
/*
 * Restore the process signal mask before returning.
 */
    gl_unmask_signals(gl, &oldset);
  };
  return rtn_status;
}

/*.......................................................................
 * In non-blocking server-I/O mode, this function should be called
 * from the application's external event loop to see what type of
 * terminal I/O is being waited for by gl_get_line(), and thus what
 * direction of I/O to wait for with select() or poll().
 *
 * Input:
 *  gl          GetLine *  The resource object of gl_get_line().
 * Output:
 *  return  GlPendingIO    The type of pending I/O being waited for.
 */
GlPendingIO gl_pending_io(GetLine *gl)
{
  GlPendingIO pending_io = GLP_WRITE;   /* The requested information */
  if(gl) {
    sigset_t oldset; /* The signals that were blocked on entry to this block */
/*
 * Temporarily block all signals.
 */
    gl_mask_signals(gl, &oldset);
/*
 * Access gl while signals are blocked.
 */
    pending_io = gl->pending_io;
/*
 * Restore the process signal mask before returning.
 */
    gl_unmask_signals(gl, &oldset);
  };
  return pending_io;
}

/*.......................................................................
 * In server mode, this function configures the terminal for non-blocking
 * raw terminal I/O. In normal I/O mode it does nothing.
 *
 * Callers of this function must be careful to trap all signals that
 * terminate or suspend the program, and call gl_normal_io()
 * from the corresponding signal handlers in order to restore the
 * terminal to its original settings before the program is terminated
 * or suspended. They should also trap the SIGCONT signal to detect
 * when the program resumes, and ensure that its signal handler
 * call gl_raw_io() to redisplay the line and resume editing.
 *
 * This function is async signal safe.
 *
 * Input:
 *  gl      GetLine *  The line editor resource object.
 * Output:
 *  return      int    0 - OK.
 *                     1 - Error.
 */
int gl_raw_io(GetLine *gl)
{
  sigset_t oldset; /* The signals that were blocked on entry to this function */
  int status;      /* The return status of _gl_raw_io() */
/*
 * Check the arguments.
 */
  if(!gl) {
    errno = EINVAL;
    return 1;
  };
/*
 * Block all signals.
 */
  if(gl_mask_signals(gl, &oldset))
    return 1;
/*
 * Don't allow applications to switch into raw mode unless in server mode.
 */
  if(gl->io_mode != GL_SERVER_MODE) {
    _err_record_msg(gl->err, "Can't switch to raw I/O unless in server mode",
		    END_ERR_MSG);
    errno = EPERM;
    status = 1;
  } else {
/*
 * Execute the private body of the function while signals are blocked.
 */
    status = _gl_raw_io(gl, 1);
  };
/*
 * Restore the process signal mask.
 */
  gl_unmask_signals(gl, &oldset);
  return status;
}

/*.......................................................................
 * This is the private body of the public function, gl_raw_io().
 * It assumes that the caller has checked its arguments and blocked the
 * delivery of signals.
 *
 * This function is async signal safe.
 */
static int _gl_raw_io(GetLine *gl, int redisplay)
{
/*
 * If we are already in the correct mode, do nothing.
 */
  if(gl->raw_mode)
    return 0;
/*
 * Switch the terminal to raw mode.
 */
  if(gl->is_term && gl_raw_terminal_mode(gl))
    return 1;
/*
 * Switch to non-blocking I/O mode?
 */
  if(gl->io_mode==GL_SERVER_MODE &&
     (gl_nonblocking_io(gl, gl->input_fd) ||
      gl_nonblocking_io(gl, gl->output_fd) ||
      (gl->file_fp && gl_nonblocking_io(gl, fileno(gl->file_fp))))) {
    if(gl->is_term)
      gl_restore_terminal_attributes(gl);
    return 1;
  };
/*
 * If an input line is being entered, arrange for it to be
 * displayed.
 */
  if(redisplay) {
    gl->postpone = 0;
    gl_queue_redisplay(gl);
  };
  return 0;
}

/*.......................................................................
 * Restore the terminal to the state that it had when
 * gl_raw_io() was last called. After calling
 * gl_raw_io(), this function must be called before
 * terminating or suspending the program, and before attempting other
 * uses of the terminal from within the program. See gl_raw_io()
 * for more details.
 *
 * Input:
 *  gl      GetLine *  The line editor resource object.
 * Output:
 *  return      int    0 - OK.
 *                     1 - Error.
 */
int gl_normal_io(GetLine *gl)
{
  sigset_t oldset; /* The signals that were blocked on entry to this function */
  int status;      /* The return status of _gl_normal_io() */
/*
 * Check the arguments.
 */
  if(!gl) {
    errno = EINVAL;
    return 1;
  };
/*
 * Block all signals.
 */
  if(gl_mask_signals(gl, &oldset))
    return 1;
/*
 * Execute the private body of the function while signals are blocked.
 */
  status = _gl_normal_io(gl);
/*
 * Restore the process signal mask.
 */
  gl_unmask_signals(gl, &oldset);
  return status;
}

/*.......................................................................
 * This is the private body of the public function, gl_normal_io().
 * It assumes that the caller has checked its arguments and blocked the
 * delivery of signals.
 */
static int _gl_normal_io(GetLine *gl)
{
/*
 * If we are already in normal mode, do nothing.
 */
  if(!gl->raw_mode)
    return 0;
/*
 * Postpone subsequent redisplays until after _gl_raw_io(gl, 1)
 * is next called.
 */
  gl->postpone = 1;
/*
 * Switch back to blocking I/O. Note that this is essential to do
 * here, because when using non-blocking I/O, the terminal output
 * buffering code can't always make room for new output without calling
 * malloc(), and a call to malloc() would mean that this function
 * couldn't safely be called from signal handlers.
 */
  if(gl->io_mode==GL_SERVER_MODE &&
     (gl_blocking_io(gl, gl->input_fd) ||
      gl_blocking_io(gl, gl->output_fd) ||
      (gl->file_fp && gl_blocking_io(gl, fileno(gl->file_fp)))))
    return 1;
/*
 * Move the cursor to the next empty terminal line. Note that
 * unbuffered I/O is requested, to ensure that gl_start_newline() be
 * async-signal-safe.
 */
  if(gl->is_term && gl_start_newline(gl, 0))
    return 1;
/*
 * Switch the terminal to normal mode.
 */
  if(gl->is_term && gl_restore_terminal_attributes(gl)) {
/*
 * On error, revert to non-blocking I/O if needed, so that on failure
 * we remain in raw mode.
 */
    if(gl->io_mode==GL_SERVER_MODE) {
      gl_nonblocking_io(gl, gl->input_fd);
      gl_nonblocking_io(gl, gl->output_fd);
      if(gl->file_fp)
	gl_nonblocking_io(gl, fileno(gl->file_fp));
    };
    return 1;
  };
  return 0;
}

/*.......................................................................
 * This function allows you to install an additional completion
 * action, or to change the completion function of an existing
 * one. This should be called before the first call to gl_get_line()
 * so that the name of the action be defined before the user's
 * configuration file is read.
 *
 * Input:
 *  gl            GetLine *  The resource object of the command-line input
 *                           module.
 *  data             void *  This is passed to match_fn() whenever it is
 *                           called. It could, for example, point to a
 *                           symbol table that match_fn() would look up
 *                           matches in.
 *  match_fn   CplMatchFn *  The function that will identify the prefix
 *                           to be completed from the input line, and
 *                           report matching symbols.
 *  list_only         int    If non-zero, install an action that only lists
 *                           possible completions, rather than attempting
 *                           to perform the completion.
 *  name       const char *  The name with which users can refer to the
 *                           binding in tecla configuration files.
 *  keyseq     const char *  Either NULL, or a key sequence with which
 *                           to invoke the binding. This should be
 *                           specified in the same manner as key-sequences
 *                           in tecla configuration files (eg. "M-^I").
 * Output:
 *  return            int    0 - OK.
 *                           1 - Error.
 */
int gl_completion_action(GetLine *gl, void *data, CplMatchFn *match_fn,
			 int list_only, const char *name, const char *keyseq)
{
  sigset_t oldset; /* The signals that were blocked on entry to this function */
  int status;      /* The return status of _gl_completion_action() */
/*
 * Check the arguments.
 */
  if(!gl || !name || !match_fn) {
    errno = EINVAL;
    return 1;
  };
/*
 * Block all signals.
 */
  if(gl_mask_signals(gl, &oldset))
    return 1;
/*
 * Install the new action while signals are blocked.
 */
  status = _gl_completion_action(gl, data, match_fn, list_only, name, keyseq);
/*
 * Restore the process signal mask.
 */
  gl_unmask_signals(gl, &oldset);
  return status;
}

/*.......................................................................
 * This is the private body of the public function, gl_completion_action().
 * It assumes that the caller has checked its arguments and blocked the
 * delivery of signals.
 */
static int _gl_completion_action(GetLine *gl, void *data, CplMatchFn *match_fn,
				 int list_only, const char *name,
				 const char *keyseq)
{
  KtKeyFn *current_fn;      /* An existing action function */
  void *current_data;       /* The action-function callback data */
/*
 * Which action function is desired?
 */
  KtKeyFn *action_fn = list_only ? gl_list_completions : gl_complete_word;
/*
 * Is there already an action of the specified name?
 */
  if(_kt_lookup_action(gl->bindings, name, &current_fn, &current_data) == 0) {
/*
 * If the action has the same type as the one being requested,
 * simply change the contents of its GlCplCallback callback data.
 */
    if(current_fn == action_fn) {
      GlCplCallback *cb = (GlCplCallback *) current_data;
      cb->fn = match_fn;
      cb->data = data;
    } else {
      errno = EINVAL;
      _err_record_msg(gl->err,
        "Illegal attempt to change the type of an existing completion action",
        END_ERR_MSG);
      return 1;
    };
/*
 * No existing action has the specified name.
 */
  } else {
/*
 * Allocate a new GlCplCallback callback object.
 */
    GlCplCallback *cb = (GlCplCallback *) _new_FreeListNode(gl->cpl_mem);
    if(!cb) {
      errno = ENOMEM;
      _err_record_msg(gl->err, "Insufficient memory to add completion action",
		      END_ERR_MSG);
      return 1;
    };
/*
 * Record the completion callback data.
 */
    cb->fn = match_fn;
    cb->data = data;
/*
 * Attempt to register the new action.
 */
    if(_kt_set_action(gl->bindings, name, action_fn, cb)) {
      _err_record_msg(gl->err, _kt_last_error(gl->bindings), END_ERR_MSG);
      _del_FreeListNode(gl->cpl_mem, (void *) cb);
      return 1;
    };
  };
/*
 * Bind the action to a given key-sequence?
 */
  if(keyseq && _kt_set_keybinding(gl->bindings, KTB_NORM, keyseq, name)) {
    _err_record_msg(gl->err, _kt_last_error(gl->bindings), END_ERR_MSG);
    return 1;
  };
  return 0;
}

/*.......................................................................
 * Register an application-provided function as an action function.
 * This should preferably be called before the first call to gl_get_line()
 * so that the name of the action becomes defined before the user's
 * configuration file is read.
 *
 * Input:
 *  gl            GetLine *  The resource object of the command-line input
 *                           module.
 *  data             void *  Arbitrary application-specific callback
 *                           data to be passed to the callback
 *                           function, fn().
 *  fn         GlActionFn *  The application-specific function that
 *                           implements the action. This will be invoked
 *                           whenever the user presses any
 *                           key-sequence which is bound to this action.
 *  name       const char *  The name with which users can refer to the
 *                           binding in tecla configuration files.
 *  keyseq     const char *  The key sequence with which to invoke
 *                           the binding. This should be specified in the
 *                           same manner as key-sequences in tecla
 *                           configuration files (eg. "M-^I").
 * Output:
 *  return            int    0 - OK.
 *                           1 - Error.
 */
int gl_register_action(GetLine *gl, void *data, GlActionFn *fn,
                       const char *name, const char *keyseq)
{
  sigset_t oldset; /* The signals that were blocked on entry to this function */
  int status;      /* The return status of _gl_register_action() */
/*
 * Check the arguments.
 */
  if(!gl || !name || !fn) {
    errno = EINVAL;
    return 1;
  };
/*
 * Block all signals.
 */
  if(gl_mask_signals(gl, &oldset))
    return 1;
/*
 * Install the new action while signals are blocked.
 */
  status = _gl_register_action(gl, data, fn, name, keyseq);
/*
 * Restore the process signal mask.
 */
  gl_unmask_signals(gl, &oldset);
  return status;
}

/*.......................................................................
 * This is the private body of the public function, gl_register_action().
 * It assumes that the caller has checked its arguments and blocked the
 * delivery of signals.
 */
static int _gl_register_action(GetLine *gl, void *data, GlActionFn *fn,
			       const char *name, const char *keyseq)
{
  KtKeyFn *current_fn;      /* An existing action function */
  void *current_data;       /* The action-function callback data */
/*
 * Get the action function which actually runs the application-provided
 * function.
 */
  KtKeyFn *action_fn = gl_run_external_action;
/*
 * Is there already an action of the specified name?
 */
  if(_kt_lookup_action(gl->bindings, name, &current_fn, &current_data) == 0) {
/*
 * If the action has the same type as the one being requested,
 * simply change the contents of its GlCplCallback callback data.
 */
    if(current_fn == action_fn) {
      GlExternalAction *a = (GlExternalAction *) current_data;
      a->fn = fn;
      a->data = data;
    } else {
      errno = EINVAL;
      _err_record_msg(gl->err,
        "Illegal attempt to change the type of an existing action",
		      END_ERR_MSG);
      return 1;
    };
/*
 * No existing action has the specified name.
 */
  } else {
/*
 * Allocate a new GlCplCallback callback object.
 */
    GlExternalAction *a =
      (GlExternalAction *) _new_FreeListNode(gl->ext_act_mem);
    if(!a) {
      errno = ENOMEM;
      _err_record_msg(gl->err, "Insufficient memory to add completion action",
		      END_ERR_MSG);
      return 1;
    };
/*
 * Record the completion callback data.
 */
    a->fn = fn;
    a->data = data;
/*
 * Attempt to register the new action.
 */
    if(_kt_set_action(gl->bindings, name, action_fn, a)) {
      _err_record_msg(gl->err, _kt_last_error(gl->bindings), END_ERR_MSG);
      _del_FreeListNode(gl->cpl_mem, (void *) a);
      return 1;
    };
  };
/*
 * Bind the action to a given key-sequence?
 */
  if(keyseq && _kt_set_keybinding(gl->bindings, KTB_NORM, keyseq, name)) {
    _err_record_msg(gl->err, _kt_last_error(gl->bindings), END_ERR_MSG);
    return 1;
  };
  return 0;
}

/*.......................................................................
 * Invoke an action function previously registered by a call to
 * gl_register_action().
 */
static KT_KEY_FN(gl_run_external_action)
{
  GlAfterAction status;  /* The return value of the action function */
/*
 * Get the container of the action function and associated callback data.
 */
  GlExternalAction *a = (GlExternalAction *) data;
/*
 * Invoke the action function.
 */
  status = a->fn(gl, a->data, count, gl->buff_curpos, gl->line);
/*
 * If the callback took us out of raw (possibly non-blocking) input
 * mode, restore this mode, and queue a redisplay of the input line.
 */
  if(_gl_raw_io(gl, 1))
    return 1;
/*
 * Finally, check to see what the action function wants us to do next.
 */
  switch(status) {
  default:
  case GLA_ABORT:
    gl_record_status(gl, GLR_ERROR, errno);
    return 1;
    break;
  case GLA_RETURN:
    return gl_newline(gl, 1, NULL);
    break;
  case GLA_CONTINUE:
    break;
  };
  return 0;
}

/*.......................................................................
 * In server-I/O mode the terminal is left in raw mode between calls
 * to gl_get_line(), so it is necessary for the application to install
 * terminal restoring signal handlers for signals that could terminate
 * or suspend the process, plus a terminal reconfiguration handler to
 * be called when a process resumption signal is received, and finally
 * a handler to be called when a terminal-resize signal is received.
 *
 * Since there are many signals that by default terminate or suspend
 * processes, and different systems support different sub-sets of
 * these signals, this function provides a convenient wrapper around
 * sigaction() for assigning the specified handlers to all appropriate
 * signals. It also arranges that when any one of these signals is
 * being handled, all other catchable signals are blocked. This is
 * necessary so that the specified signal handlers can safely call
 * gl_raw_io(), gl_normal_io() and gl_update_size() without
 * reentrancy issues.
 *
 * Input:
 *  term_handler  void (*)(int)  The signal handler to invoke when
 *                               a process terminating signal is
 *                               received.
 *  susp_handler  void (*)(int)  The signal handler to invoke when
 *                               a process suspending signal is
 *                               received.
 *  cont_handler  void (*)(int)  The signal handler to invoke when
 *                               a process resumption signal is
 *                               received (ie. SIGCONT).
 *  size_handler  void (*)(int)  The signal handler to invoke when
 *                               a terminal-resize signal (ie. SIGWINCH)
 *                               is received.
 * Output:
 *  return                  int  0 - OK.
 *                               1 - Error.
 */
int gl_tty_signals(void (*term_handler)(int), void (*susp_handler)(int),
		   void (*cont_handler)(int), void (*size_handler)(int))
{
  int i;
/*
 * Search for signals of the specified classes, and assign the
 * associated signal handler to them.
 */
  for(i=0; i<sizeof(gl_signal_list)/sizeof(gl_signal_list[0]); i++) {
    const struct GlDefSignal *sig = gl_signal_list + i;
    if(sig->attr & GLSA_SUSP) {
      if(gl_set_tty_signal(sig->signo, term_handler))
	return 1;
    } else if(sig->attr & GLSA_TERM) {
      if(gl_set_tty_signal(sig->signo, susp_handler))
	return 1;
    } else if(sig->attr & GLSA_CONT) {
      if(gl_set_tty_signal(sig->signo, cont_handler))
	return 1;
    } else if(sig->attr & GLSA_SIZE) {
      if(gl_set_tty_signal(sig->signo, size_handler))
	return 1;
    };
  };
  return 0;
}

/*.......................................................................
 * This is a private function of gl_tty_signals(). It installs a given
 * signal handler, and arranges that when that signal handler is being
 * invoked other signals are blocked. The latter is important to allow
 * functions like gl_normal_io(), gl_raw_io() and gl_update_size()
 * to be called from signal handlers.
 *
 * Input:
 *  signo     int           The signal to be trapped.
 *  handler  void (*)(int)  The signal handler to assign to the signal.
 */
static int gl_set_tty_signal(int signo, void (*handler)(int))
{
  SigAction act;   /* The signal handler configuation */
/*
 * Arrange to block all trappable signals except the one that is being
 * assigned (the trapped signal will be blocked automatically by the
 * system).
 */
  gl_list_trappable_signals(&act.sa_mask);
  sigdelset(&act.sa_mask, signo);
/*
 * Assign the signal handler.
 */
  act.sa_handler = handler;
/*
 * There is only one portable signal handling flag, and it isn't
 * relevant to us, so don't specify any flags.
 */
  act.sa_flags = 0;
/*
 * Register the signal handler.
 */
  if(sigaction(signo, &act, NULL))
    return 1;
  return 0;
}

/*.......................................................................
 * Display a left-justified string over multiple terminal lines,
 * taking account of the current width of the terminal. Optional
 * indentation and an optional prefix string can be specified to be
 * displayed at the start of each new terminal line used. Similarly,
 * an optional suffix can be specified to be displayed at the end of
 * each terminal line.  If needed, a single paragraph can be broken
 * across multiple calls.  Note that literal newlines in the input
 * string can be used to force a newline at any point and that you
 * should use this feature to explicitly end all paragraphs, including
 * at the end of the last string that you write. Note that when a new
 * line is started between two words that are separated by spaces,
 * those spaces are not output, whereas when a new line is started
 * because a newline character was found in the string, only the
 * spaces before the newline character are discarded.
 *
 * Input:
 *  gl         GetLine *  The resource object of gl_get_line().
 *  indentation    int    The number of spaces of indentation to write
 *                        at the beginning of each new terminal line.
 *  prefix  const char *  An optional prefix string to write after the
 *                        indentation margin at the start of each new
 *                        terminal line. You can specify NULL if no
 *                        prefix is required.
 *  suffix  const char *  An optional suffix string to draw at the end
 *                        of the terminal line. Spaces will be added
 *                        where necessary to ensure that the suffix ends
 *                        in the last column of the terminal line. If
 *                        no suffix is desired, specify NULL.
 *  fill_char      int    The padding character to use when indenting
 *                        the line or padding up to the suffix.
 *  def_width      int    If the terminal width isn't known, such as when
 *                        writing to a pipe or redirecting to a file,
 *                        this number specifies what width to assume.
 *  start          int    The number of characters already written to
 *                        the start of the current terminal line. This
 *                        is primarily used to allow individual
 *                        paragraphs to be written over multiple calls
 *                        to this function, but can also be used to
 *                        allow you to start the first line of a
 *                        paragraph with a different prefix or
 *                        indentation than those specified above.
 *  string  const char *  The string to be written.
 * Output:
 *  return         int    On error -1 is returned. Otherwise the
 *                        return value is the terminal column index at
 *                        which the cursor was left after writing the
 *                        final word in the string. Successful return
 *                        values can thus be passed verbatim to the
 *                        'start' arguments of subsequent calls to
 *                        gl_display_text() to allow the printing of a
 *                        paragraph to be broken across multiple calls
 *                        to gl_display_text().
 */
int gl_display_text(GetLine *gl, int indentation, const char *prefix,
		    const char *suffix, int fill_char,
		    int def_width, int start, const char *string)
{
  sigset_t oldset; /* The signals that were blocked on entry to this function */
  int status;      /* The return status of _gl_completion_action() */
/*
 * Check the arguments?
 */
  if(!gl || !string) {
    errno = EINVAL;
    return -1;
  };
/*
 * Block all signals.
 */
  if(gl_mask_signals(gl, &oldset))
    return -1;
/*
 * Display the text while signals are blocked.
 */
  status = _io_display_text(_io_write_stdio, gl->output_fp, indentation,
			    prefix, suffix, fill_char,
			    gl->ncolumn > 0 ? gl->ncolumn : def_width,
			    start, string);
/*
 * Restore the process signal mask.
 */
  gl_unmask_signals(gl, &oldset);
  return status;
}

/*.......................................................................
 * Block all of the signals that we are currently trapping.
 *
 * Input:
 *  gl       GetLine *   The resource object of gl_get_line().
 * Input/Output:
 *  oldset   sigset_t *   The superseded process signal mask
 *                        will be return in *oldset unless oldset is
 *                        NULL.
 * Output:
 *  return        int     0 - OK.
 *                        1 - Error.
 */
static int gl_mask_signals(GetLine *gl, sigset_t *oldset)
{
/*
 * Block all signals in all_signal_set, along with any others that are
 * already blocked by the application.
 */
  if(sigprocmask(SIG_BLOCK, &gl->all_signal_set, oldset) >= 0) {
    gl->signals_masked = 1;
    return 0;
  };
/*
 * On error attempt to query the current process signal mask, so
 * that oldset be the correct process signal mask to restore later
 * if the caller of this function ignores the error return value.
 */
  if(oldset)
    (void) sigprocmask(SIG_SETMASK, NULL, oldset);
  gl->signals_masked = 0;
  return 1;
}

/*.......................................................................
 * Restore a process signal mask that was previously returned via the
 * oldset argument of gl_mask_signals().
 *
 * Input:
 *  gl        GetLine *   The resource object of gl_get_line().
 * Input/Output:
 *  oldset   sigset_t *   The process signal mask to be restored.
 * Output:
 *  return        int     0 - OK.
 *                        1 - Error.
 */
static int gl_unmask_signals(GetLine *gl, sigset_t *oldset)
{
  gl->signals_masked = 0;
  return sigprocmask(SIG_SETMASK, oldset, NULL) < 0;
}

/*.......................................................................
 * Arrange to temporarily catch the signals marked in gl->use_signal_set.
 *
 * Input:
 *  gl        GetLine *   The resource object of gl_get_line().
 * Output:
 *  return        int     0 - OK.
 *                        1 - Error.
 */
static int gl_catch_signals(GetLine *gl)
{
  return sigprocmask(SIG_UNBLOCK, &gl->use_signal_set, NULL) < 0;
}

/*.......................................................................
 * Select the I/O mode to be used by gl_get_line().
 *
 * Input:
 *  gl         GetLine *  The resource object of gl_get_line().
 *  mode      GlIOMode    The I/O mode to establish.
 * Output:
 *  return         int    0 - OK.
 *                        1 - Error.
 */
int gl_io_mode(GetLine *gl, GlIOMode mode)
{
  sigset_t oldset; /* The signals that were blocked on entry to this function */
  int status;      /* The return status of _gl_io_mode() */
/*
 * Check the arguments.
 */
  if(!gl) {
    errno = EINVAL;
    return 1;
  };
/*
 * Check that the requested mode is known.
 */
  switch(mode) {
  case GL_NORMAL_MODE:
  case GL_SERVER_MODE:
    break;
  default:
    errno = EINVAL;
    _err_record_msg(gl->err, "Unknown gl_get_line() I/O mode requested.",
		    END_ERR_MSG);
    return 1;
  };
/*
 * Block all signals.
 */
  if(gl_mask_signals(gl, &oldset))
    return 1;
/*
 * Invoke the private body of this function.
 */
  status = _gl_io_mode(gl, mode);
/*
 * Restore the process signal mask.
 */
  gl_unmask_signals(gl, &oldset);
  return status;
}

/*.......................................................................
 * This is the private body of the public function, gl_io_mode().
 * It assumes that the caller has checked its arguments and blocked the
 * delivery of signals.
 */
static int _gl_io_mode(GetLine *gl, GlIOMode mode)
{
/*
 * Are we already in the specified mode?
 */
  if(mode == gl->io_mode)
    return 0;
/*
 * First revert to normal I/O in the current I/O mode.
 */
  _gl_normal_io(gl);
/*
 * Record the new mode.
 */
  gl->io_mode = mode;
/*
 * Perform any actions needed by the new mode.
 */
  if(mode==GL_SERVER_MODE) {
    if(_gl_raw_io(gl, 1))
      return 1;
  };
  return 0;
}

/*.......................................................................
 * Return extra information (ie. in addition to that provided by errno)
 * about the last error to occur in either gl_get_line() or its
 * associated public functions.
 *
 * Input:
 *  gl         GetLine *  The resource object of gl_get_line().
 * Input/Output:
 *  buff          char *  An optional output buffer. Note that if the
 *                        calling application calls any gl_*()
 *                        functions from signal handlers, it should
 *                        provide a buffer here, so that a copy of
 *                        the latest error message can safely be made
 *                        while signals are blocked.
 *  n           size_t    The allocated size of buff[].
 * Output:
 *  return  const char *  A pointer to the error message. This will
 *                        be the buff argument, unless buff==NULL, in
 *                        which case it will be a pointer to an
 *                        internal error buffer. In the latter case,
 *                        note that the contents of the returned buffer
 *                        will change on subsequent calls to any gl_*()
 *                        functions.
 */
const char *gl_error_message(GetLine *gl, char *buff, size_t n)
{
  if(!gl) {
    static const char *msg = "NULL GetLine argument";
    if(buff) {
      strncpy(buff, msg, n);
      buff[n-1] = '\0';
    } else {
      return msg;
    };
  } else if(buff) {
    sigset_t oldset; /* The signals that were blocked on entry to this block */
/*
 * Temporarily block all signals.
 */
    gl_mask_signals(gl, &oldset);
/*
 * Copy the error message into the specified buffer.
 */
    if(buff && n > 0) {
      strncpy(buff, _err_get_msg(gl->err), n);
      buff[n-1] = '\0';
    };
/*
 * Restore the process signal mask before returning.
 */
    gl_unmask_signals(gl, &oldset);
  } else {
    return _err_get_msg(gl->err);
  };
  return buff;
}

/*.......................................................................
 * Return the signal mask used by gl_get_line(). This is the set of
 * signals that gl_get_line() is currently configured to trap.
 *
 * Input:
 *  gl         GetLine *  The resource object of gl_get_line().
 * Input/Output:
 *  set       sigset_t *  The set of signals will be returned in *set,
 *                        in the form of a signal process mask, as
 *                        used by sigaction(), sigprocmask(),
 *                        sigpending(), sigsuspend(), sigsetjmp() and
 *                        other standard POSIX signal-aware
 *                        functions.
 * Output:
 *  return         int    0 - OK.
 *                        1 - Error (examine errno for reason).
 */
int gl_list_signals(GetLine *gl, sigset_t *set)
{
/*
 * Check the arguments.
 */
  if(!gl || !set) {
    if(gl)
      _err_record_msg(gl->err, "NULL argument(s)", END_ERR_MSG);
    errno = EINVAL;
    return 1;
  };
/*
 * Copy the signal mask into *set.
 */
  memcpy(set, &gl->all_signal_set, sizeof(*set));
  return 0;
}

/*.......................................................................
 * By default, gl_get_line() doesn't trap signals that are blocked
 * when it is called. This default can be changed either on a
 * per-signal basis by calling gl_trap_signal(), or on a global basis
 * by calling this function. What this function does is add the
 * GLS_UNBLOCK_SIG flag to all signals that are currently configured
 * to be trapped by gl_get_line(), such that when subsequent calls to
 * gl_get_line() wait for I/O, these signals are temporarily
 * unblocked. This behavior is useful in non-blocking server-I/O mode,
 * where it is used to avoid race conditions related to handling these
 * signals externally to gl_get_line(). See the demonstration code in
 * demo3.c, or the gl_handle_signal() man page for further
 * information.
 *
 * Input:
 *  gl         GetLine *   The resource object of gl_get_line().
 */
void gl_catch_blocked(GetLine *gl)
{
  sigset_t oldset;    /* The process signal mask to restore */
  GlSignalNode *sig;  /* A signal node in gl->sigs */
/*
 * Check the arguments.
 */
  if(!gl) {
    errno = EINVAL;
    return;
  };
/*
 * Temporarily block all signals while we modify the contents of gl.
 */
  gl_mask_signals(gl, &oldset);
/*
 * Add the GLS_UNBLOCK_SIG flag to all configured signals.
 */
  for(sig=gl->sigs; sig; sig=sig->next)
    sig->flags |= GLS_UNBLOCK_SIG;
/*
 * Restore the process signal mask that was superseded by the call
 * to gl_mask_signals().
 */
  gl_unmask_signals(gl, &oldset);
  return;
}

/*.......................................................................
 * Respond to signals who's default effects have important
 * consequences to gl_get_line(). This is intended for use in
 * non-blocking server mode, where the external event loop is
 * responsible for catching signals. Signals that are handled include
 * those that by default terminate or suspend the process, and the
 * signal that indicates that the terminal size has changed. Note that
 * this function is not signal safe and should thus not be called from
 * a signal handler itself. See the gl_io_mode() man page for how it
 * should be used.
 *
 * In the case of signals that by default terminate or suspend
 * processes, command-line editing will be suspended, the terminal
 * returned to a usable state, then the default disposition of the
 * signal restored and the signal resent, in order to suspend or
 * terminate the process.  If the process subsequently resumes,
 * command-line editing is resumed.
 *
 * In the case of signals that indicate that the terminal has been
 * resized, the new size will be queried, and any input line that is
 * being edited will be redrawn to fit the new dimensions of the
 * terminal.
 *
 * Input:
 *  signo    int    The number of the signal to respond to.
 *  gl   GetLine *  The first element of an array of 'ngl' GetLine
 *                  objects.
 *  ngl      int    The number of elements in the gl[] array. Normally
 *                  this will be one.
 */
void gl_handle_signal(int signo, GetLine *gl, int ngl)
{
  int attr;             /* The attributes of the specified signal */
  sigset_t all_signals; /* The set of trappable signals */
  sigset_t oldset;      /* The process signal mask to restore */
  int i;
/*
 * NULL operation?
 */
  if(ngl < 1 || !gl)
    return;
/*
 * Look up the default attributes of the specified signal.
 */
  attr = gl_classify_signal(signo);
/*
 * If the signal isn't known, we are done.
 */
  if(!attr)
    return;
/*
 * Temporarily block all signals while we modify the gl objects.
 */
  gl_list_trappable_signals(&all_signals);
  sigprocmask(SIG_BLOCK, &all_signals, &oldset);
/*
 * Suspend or terminate the process?
 */
  if(attr & (GLSA_SUSP | GLSA_TERM)) {
    gl_suspend_process(signo, gl, ngl);
/*
 * Resize the terminal? Note that ioctl() isn't defined as being
 * signal safe, so we can't call gl_update_size() here. However,
 * gl_get_line() checks for resizes on each call, so simply arrange
 * for the application's event loop to call gl_get_line() as soon as
 * it becomes possible to write to the terminal. Note that if the
 * caller is calling select() or poll when this happens, these functions
 * get interrupted, since a signal has been caught.
 */
  } else if(attr & GLSA_SIZE) {
    for(i=0; i<ngl; i++)
      gl[i].pending_io = GLP_WRITE;
  };
/*
 * Restore the process signal mask that was superseded by the call
 * to gl_mask_signals().
 */
  sigprocmask(SIG_SETMASK, &oldset, NULL);
  return;
}

/*.......................................................................
 * Respond to an externally caught process suspension or
 * termination signal.
 *
 * After restoring the terminal to a usable state, suspend or
 * terminate the calling process, using the original signal with its
 * default disposition restored to do so. If the process subsequently
 * resumes, resume editing any input lines that were being entered.
 *
 * Input:
 *  signo    int    The signal number to suspend the process with. Note
 *                  that the default disposition of this signal will be
 *                  restored before the signal is sent, so provided
 *                  that the default disposition of this signal is to
 *                  either suspend or terminate the application,
 *                  that is what wil happen, regardless of what signal
 *                  handler is currently assigned to this signal.
 *  gl   GetLine *  The first element of an array of 'ngl' GetLine objects
 *                  whose terminals should be restored to a sane state
 *                  while the application is suspended.
 *  ngl      int    The number of elements in the gl[] array.
 */
static void gl_suspend_process(int signo, GetLine *gl, int ngl)
{
  sigset_t only_signo;          /* A signal set containing just signo */
  sigset_t oldset;              /* The signal mask on entry to this function */
  sigset_t all_signals;         /* A signal set containing all signals */
  struct sigaction old_action;  /* The current signal handler */
  struct sigaction def_action;  /* The default signal handler */
  int i;
/*
 * Create a signal mask containing the signal that was trapped.
 */
  sigemptyset(&only_signo);
  sigaddset(&only_signo, signo);
/*
 * Temporarily block all signals.
 */
  gl_list_trappable_signals(&all_signals);
  sigprocmask(SIG_BLOCK, &all_signals, &oldset);
/*
 * Restore the terminal to a usable state.
 */
  for(i=0; i<ngl; i++) {
    GetLine *obj = gl + i;
    if(obj->raw_mode) {
      _gl_normal_io(obj);
      if(!obj->raw_mode)        /* Check that gl_normal_io() succeded */
	obj->raw_mode = -1;     /* Flag raw mode as needing to be restored */
    };
  };
/*
 * Restore the system default disposition of the signal that we
 * caught.  Note that this signal is currently blocked. Note that we
 * don't use memcpy() to copy signal sets here, because the signal safety
 * of memcpy() is undefined.
 */
  def_action.sa_handler = SIG_DFL;
  {
    char *orig = (char *) &all_signals;
    char *dest = (char *) &def_action.sa_mask;
    for(i=0; i<sizeof(sigset_t); i++)
      *dest++ = *orig++;
  };
  sigaction(signo, &def_action, &old_action);
/*
 * Resend the signal, and unblock it so that it gets delivered to
 * the application. This will invoke the default action of this signal.
 */
  raise(signo);
  sigprocmask(SIG_UNBLOCK, &only_signo, NULL);
/*
 * If the process resumes again, it will resume here.
 * Block the signal again, then restore our signal handler.
 */
  sigprocmask(SIG_BLOCK, &only_signo, NULL);
  sigaction(signo, &old_action, NULL);
/*
 * Resume command-line editing.
 */
  for(i=0; i<ngl; i++) {
    GetLine *obj = gl + i;
    if(obj->raw_mode == -1) { /* Did we flag the need to restore raw mode? */
      obj->raw_mode = 0;      /* gl_raw_io() does nothing unless raw_mode==0 */
      _gl_raw_io(obj, 1);
    };
  };
/*
 * Restore the process signal mask to the way it was when this function
 * was called.
 */
  sigprocmask(SIG_SETMASK, &oldset, NULL);
  return;
}

/*.......................................................................
 * Return the information about the default attributes of a given signal.
 * The attributes that are returned are as defined by the standards that
 * created them, including POSIX, SVR4 and 4.3+BSD, and are taken from a
 * table in Richard Steven's book, "Advanced programming in the UNIX
 * environment".
 *
 * Input:
 *  signo        int   The signal to be characterized.
 * Output:
 *  return       int   A bitwise union of GlSigAttr enumerators, or 0
 *                     if the signal isn't known.
 */
static int gl_classify_signal(int signo)
{
  int i;
/*
 * Search for the specified signal in the gl_signal_list[] table.
 */
  for(i=0; i<sizeof(gl_signal_list)/sizeof(gl_signal_list[0]); i++) {
    const struct GlDefSignal *sig = gl_signal_list + i;
    if(sig->signo == signo)
      return sig->attr;
  };
/*
 * Signal not known.
 */
  return 0;
}

/*.......................................................................
 * When in non-blocking server mode, this function can be used to abandon
 * the current incompletely entered input line, and prepare to start
 * editing a new line on the next call to gl_get_line().
 *
 * Input:
 *  gl      GetLine *  The line editor resource object.
 */
void gl_abandon_line(GetLine *gl)
{
  sigset_t oldset;    /* The process signal mask to restore */
/*
 * Check the arguments.
 */
  if(!gl) {
    errno = EINVAL;
    return;
  };
/*
 * Temporarily block all signals while we modify the contents of gl.
 */
  gl_mask_signals(gl, &oldset);
/*
 * Mark the input line as discarded.
 */
  _gl_abandon_line(gl);
/*
 * Restore the process signal mask that was superseded by the call
 * to gl_mask_signals().
 */
  gl_unmask_signals(gl, &oldset);
  return;
}

/*.......................................................................
 * This is the private body of the gl_abandon_line() function. It
 * assumes that the caller has checked its arguments and blocked the
 * delivery of signals.
 */
void _gl_abandon_line(GetLine *gl)
{
  gl->endline = 1;
  gl->pending_io = GLP_WRITE;
}

/*.......................................................................
 * How many characters are needed to write a number as an octal string?
 *
 * Input:
 *  num   unsigned   The to be measured.
 * Output:
 *  return     int   The number of characters needed.
 */
static int gl_octal_width(unsigned num)
{
  int n;    /* The number of characters needed to render the number */
  for(n=1; num /= 8; n++)
    ;
  return n;
}

/*.......................................................................
 * Tell gl_get_line() the current terminal size. Note that this is only
 * necessary on systems where changes in terminal size aren't reported
 * via SIGWINCH.
 *
 * Input:
 *  gl            GetLine *  The resource object of gl_get_line().
 *  ncolumn           int    The number of columns in the terminal.
 *  nline             int    The number of lines in the terminal.
 * Output:
 *  return            int    0 - OK.
 *                           1 - Error.
 */
int gl_set_term_size(GetLine *gl, int ncolumn, int nline)
{
  sigset_t oldset;      /* The signals that were blocked on entry */
                        /*  to this function */
  int status;           /* The return status */
/*
 * Block all signals while accessing gl.
 */
  gl_mask_signals(gl, &oldset);
/*
 * Install the new terminal size.
 */
  status = _gl_set_term_size(gl, ncolumn, nline);
/*
 * Restore the process signal mask before returning.
 */
  gl_unmask_signals(gl, &oldset);
  return status;
}

/*.......................................................................
 * This is the private body of the gl_set_term_size() function. It
 * assumes that the caller has checked its arguments and blocked the
 * delivery of signals.
 */
static int _gl_set_term_size(GetLine *gl, int ncolumn, int nline)
{
/*
 * Check the arguments.
 */
  if(!gl) {
    errno = EINVAL;
    return 1;
  };
/*
 * Reject non-sensical dimensions.
 */
  if(ncolumn <= 0 || nline <= 0) {
    _err_record_msg(gl->err, "Invalid terminal size", END_ERR_MSG);
    errno = EINVAL;
    return 1;
  };
/*
 * Install the new dimensions in the terminal driver if possible, so
 * that future calls to gl_query_size() get the new value.
 */
#ifdef TIOCSWINSZ
  if(gl->is_term) {
    struct winsize size;
    size.ws_row = nline;
    size.ws_col = ncolumn;
    size.ws_xpixel = 0;
    size.ws_ypixel = 0;
    if(ioctl(gl->output_fd, TIOCSWINSZ, &size) == -1) {
      _err_record_msg(gl->err, "Can't change terminal size", END_ERR_MSG);
      return 1;
    };
  };
#endif
/*
 * If an input line is in the process of being edited, redisplay it to
 * accomodate the new dimensions, and record the new dimensions in
 * gl->nline and gl->ncolumn.
 */
  return gl_handle_tty_resize(gl, ncolumn, nline);
}

/*.......................................................................
 * Record a character in the input line buffer at a given position.
 *
 * Input:
 *  gl    GetLine *   The resource object of gl_get_line().
 *  c        char     The character to be recorded.
 *  bufpos    int     The index in the buffer at which to record the
 *                    character.
 * Output:
 *  return    int     0 - OK.
 *                    1 - Insufficient room.
 */
static int gl_buffer_char(GetLine *gl, char c, int bufpos)
{
/*
 * Guard against buffer overruns.
 */
  if(bufpos >= gl->linelen)
    return 1;
/*
 * Record the new character.
 */
  gl->line[bufpos] = c;
/*
 * If the new character was placed beyond the end of the current input
 * line, update gl->ntotal to reflect the increased number of characters
 * that are in gl->line, and terminate the string.
 */
  if(bufpos >= gl->ntotal) {
    gl->ntotal = bufpos+1;
    gl->line[gl->ntotal] = '\0';
  };
  return 0;
}

/*.......................................................................
 * Copy a given string into the input buffer, overwriting the current
 * contents.
 *
 * Input:
 *  gl    GetLine *   The resource object of gl_get_line().
 *  s  const char *   The string to be recorded.
 *  n         int     The number of characters to be copied from the
 *                    string.
 *  bufpos    int     The index in the buffer at which to place the
 *                    the first character of the string.
 * Output:
 *  return    int     0 - OK.
 *                    1 - String truncated to fit.
 */
static int gl_buffer_string(GetLine *gl, const char *s, int n, int bufpos)
{
  int nnew;  /* The number of characters actually recorded */
  int i;
/*
 * How many of the characters will fit within the buffer?
 */
  nnew = bufpos + n <= gl->linelen ? n : (gl->linelen - bufpos);
/*
 * Record the first nnew characters of s[] in the buffer.
 */
  for(i=0; i<nnew; i++)
    gl_buffer_char(gl, s[i], bufpos + i);
/*
 * Was the string truncated?
 */
  return nnew < n;
}

/*.......................................................................
 * Make room in the input buffer for a string to be inserted. This
 * involves moving the characters that follow a specified point, towards
 * the end of the buffer.
 *
 * Input:
 *  gl    GetLine *   The resource object of gl_get_line().
 *  start     int     The index of the first character to be moved.
 *  n         int     The width of the gap.
 * Output:
 *  return    int     0 - OK.
 *                    1 - Insufficient room.
 */
static int gl_make_gap_in_buffer(GetLine *gl, int start, int n)
{
/*
 * Ensure that the buffer has sufficient space.
 */
  if(gl->ntotal + n > gl->linelen)
    return 1;
/*
 * Move everything including and beyond the character at 'start'
 * towards the end of the string.
 */
  memmove(gl->line + start + n, gl->line + start, gl->ntotal - start + 1);
/*
 * Update the recorded size of the line.
 */
  gl->ntotal += n;
  return 1;
}

/*.......................................................................
 * Remove a given number of characters from the input buffer. This
 * involves moving the characters that follow the removed characters to
 * where the removed sub-string started in the input buffer.
 *
 * Input:
 *  gl    GetLine *   The resource object of gl_get_line().
 *  start     int     The first character to be removed.
 *  n         int     The number of characters to remove.
 */
static void gl_remove_from_buffer(GetLine *gl, int start, int n)
{
  memmove(gl->line + start, gl->line + start + n, gl->ntotal - start - n + 1);
/*
 * Update the recorded size of the line.
 */
  gl->ntotal -= n;
}

/*.......................................................................
 * Truncate the string in the input line buffer after a given number of
 * characters.
 *
 * Input:
 *  gl       GetLine *   The resource object of gl_get_line().
 *  n            int     The new length of the line.
 * Output:
 *  return       int     0 - OK.
 *                       1 - n > gl->linelen.
 */
static int gl_truncate_buffer(GetLine *gl, int n)
{
  if(n > gl->linelen)
    return 1;
  gl->line[n] = '\0';
  gl->ntotal = n;
  return 0;
}

/*.......................................................................
 * When the contents of gl->line[] are changed without calling any of the
 * gl_ buffer manipulation functions, this function must be called to
 * compute the length of this string, and ancillary information.
 *
 * Input:
 *  gl      GetLine *   The resource object of gl_get_line().
 */
static void gl_update_buffer(GetLine *gl)
{
  int len;  /* The length of the line */
/*
 * Measure the length of the input line.
 */
  for(len=0; len <= gl->linelen && gl->line[len]; len++)
    ;
/*
 * Just in case the string wasn't correctly terminated, do so here.
 */
  gl->line[len] = '\0';
/*
 * Record the number of characters that are now in gl->line[].
 */
  gl->ntotal = len;
/*
 * Ensure that the cursor stays within the bounds of the modified
 * input line.
 */
  if(gl->buff_curpos > gl->ntotal)
    gl->buff_curpos = gl->ntotal;
/*
 * Arrange for the input line to be redrawn.
 */
  gl_queue_redisplay(gl);
  return;
}

/*.......................................................................
 * Erase the displayed input line, including its prompt, and leave the
 * cursor where the erased line started. Note that to allow this
 * function to be used when responding to a terminal resize, this
 * function is designed to work even if the horizontal cursor position
 * doesn't match the internally recorded position.
 *
 * Input:
 *  gl      GetLine *   The resource object of gl_get_line().
 * Output:
 *  return      int     0 - OK.
 *                      1 - Error.
 */
static int gl_erase_line(GetLine *gl)
{
/*
 * Is a line currently displayed?
 */
  if(gl->displayed) {
/*
 * Relative the the start of the input line, which terminal line of
 * the current input line is the cursor currently on?
 */
    int cursor_line = gl->term_curpos / gl->ncolumn;
/*
 * Move the cursor to the start of the line.
 */
    for( ; cursor_line > 0; cursor_line--) {
      if(gl_print_control_sequence(gl, 1, gl->up))
	return 1;
    };
    if(gl_print_control_sequence(gl, 1, gl->bol))
      return 1;
/*
 * Clear from the start of the line to the end of the terminal.
 */
    if(gl_print_control_sequence(gl, gl->nline, gl->clear_eod))
      return 1;
/*
 * Mark the line as no longer displayed.
 */
    gl_line_erased(gl);
  };
  return 0;
}

/*.......................................................................
 * Arrange for the input line to be redisplayed by gl_flush_output(),
 * as soon as the output queue becomes empty.
 *
 * Input:
 *  gl          GetLine *   The resource object of gl_get_line().
 */
static void gl_queue_redisplay(GetLine *gl)
{
  gl->redisplay = 1;
  gl->pending_io = GLP_WRITE;
}

/*.......................................................................
 * Truncate the displayed input line starting from the current
 * terminal cursor position, and leave the cursor at the end of the
 * truncated line. The input-line buffer is not affected.
 *
 * Input:
 *  gl     GetLine *   The resource object of gl_get_line().
 * Output:
 *  return     int     0 - OK.
 *                     1 - Error.
 */
static int gl_truncate_display(GetLine *gl)
{
/*
 * Keep a record of the current terminal cursor position.
 */
  int term_curpos = gl->term_curpos;
/*
 * First clear from the cursor to the end of the current input line.
 */
  if(gl_print_control_sequence(gl, 1, gl->clear_eol))
    return 1;
/*
 * If there is more than one line displayed, go to the start of the
 * next line and clear from there to the end of the display. Note that
 * we can't use clear_eod to do the whole job of clearing from the
 * current cursor position to the end of the terminal because
 * clear_eod is only defined when used at the start of a terminal line
 * (eg. with gnome terminals, clear_eod clears from the start of the
 * current terminal line, rather than from the current cursor
 * position).
 */
  if(gl->term_len / gl->ncolumn > gl->term_curpos / gl->ncolumn) {
    if(gl_print_control_sequence(gl, 1, gl->down) ||
       gl_print_control_sequence(gl, 1, gl->bol) ||
       gl_print_control_sequence(gl, gl->nline, gl->clear_eod))
      return 1;
/*
 * Where is the cursor now?
 */
    gl->term_curpos = gl->ncolumn * (term_curpos / gl->ncolumn + 1);
/*
 * Restore the cursor position.
 */
    gl_set_term_curpos(gl, term_curpos);
  };
/*
 * Update the recorded position of the final character.
 */
  gl->term_len = gl->term_curpos;
  return 0;
}

/*.......................................................................
 * Return the set of all trappable signals.
 *
 * Input:
 *  signals   sigset_t *  The set of signals will be recorded in
 *                        *signals.
 */
static void gl_list_trappable_signals(sigset_t *signals)
{
/*
 * Start with the set of all signals.
 */
  sigfillset(signals);
/*
 * Remove un-trappable signals from this set.
 */
#ifdef SIGKILL
  sigdelset(signals, SIGKILL);
#endif
#ifdef SIGSTOP
  sigdelset(signals, SIGSTOP);
#endif
}

/*.......................................................................
 * Read an input line from a non-interactive input stream.
 *
 * Input:
 *  gl     GetLine *   The resource object of gl_get_line().
 * Output:
 *  return     int     0 - OK
 *                     1 - Error.
 */
static int gl_read_stream_line(GetLine *gl)
{
  char c = '\0'; /* The latest character read from fp */
/*
 * Record the fact that we are about to read input.
 */
  gl->pending_io = GLP_READ;
/*
 * If we are starting a new line, reset the line-input parameters.
 */
  if(gl->endline)
    gl_reset_input_line(gl);
/*
 * Read one character at a time.
 */
  while(gl->ntotal < gl->linelen && c != '\n') {
/*
 * Attempt to read one more character.
 */
    switch(gl_read_input(gl, &c)) {
    case GL_READ_OK:
      break;
    case GL_READ_EOF:        /* Reached end-of-file? */
/*
 * If any characters were read before the end-of-file condition,
 * interpolate a newline character, so that the caller sees a
 * properly terminated line. Otherwise return an end-of-file
 * condition.
 */
      if(gl->ntotal > 0) {
	c = '\n';
      } else {
	gl_record_status(gl, GLR_EOF, 0);
	return 1;
      };
      break;
    case GL_READ_BLOCKED:    /* Input blocked? */
      gl_record_status(gl, GLR_BLOCKED, BLOCKED_ERRNO);
      return 1;
      break;
    case GL_READ_ERROR:     /* I/O error? */
      return 1;
      break;
    };
/*
 * Append the character to the line buffer.
 */
    if(gl_buffer_char(gl, c, gl->ntotal))
      return 1;
  };
/*
 * Was the end of the input line reached before running out of buffer space?
 */
  gl->endline = (c == '\n');
  return 0;
}

/*.......................................................................
 * Read a single character from a non-interactive input stream.
 *
 * Input:
 *  gl     GetLine *   The resource object of gl_get_line().
 * Output:
 *  return     int     The character, or EOF on error.
 */
static int gl_read_stream_char(GetLine *gl)
{
  char c = '\0';    /* The latest character read from fp */
  int retval = EOF; /* The return value of this function */
/*
 * Arrange to discard any incomplete input line.
 */
  _gl_abandon_line(gl);
/*
 * Record the fact that we are about to read input.
 */
  gl->pending_io = GLP_READ;
/*
 * Attempt to read one more character.
 */
  switch(gl_read_input(gl, &c)) {
  case GL_READ_OK:      /* Success */
    retval = c;
    break;
  case GL_READ_BLOCKED: /* The read blocked */
    gl_record_status(gl, GLR_BLOCKED, BLOCKED_ERRNO);
    retval = EOF;  /* Failure */
    break;
  case GL_READ_EOF:     /* End of file reached */
    gl_record_status(gl, GLR_EOF, 0);
    retval = EOF;  /* Failure */
    break;
  case GL_READ_ERROR:
    retval = EOF;  /* Failure */
    break;
  };
  return retval;
}

/*.......................................................................
 * Bind a key sequence to a given action.
 *
 * Input:
 *  gl          GetLine *   The resource object of gl_get_line().
 *  origin  GlKeyOrigin     The originator of the key binding.
 *  key      const char *   The key-sequence to be bound (or unbound).
 *  action   const char *   The name of the action to bind the key to,
 *                          or either NULL or "" to unbind the
 *                          key-sequence.
 * Output:
 *  return          int     0 - OK
 *                          1 - Error.
 */
int gl_bind_keyseq(GetLine *gl, GlKeyOrigin origin, const char *keyseq,
		   const char *action)
{
  KtBinder binder;  /* The private internal equivalent of 'origin' */
/*
 * Check the arguments.
 */
  if(!gl || !keyseq) {
    errno = EINVAL;
    if(gl)
      _err_record_msg(gl->err, "NULL argument(s)", END_ERR_MSG);
    return 1;
  };
/*
 * An empty action string requests that the key-sequence be unbound.
 * This is indicated to _kt_set_keybinding() by passing a NULL action
 * string, so convert an empty string to a NULL action pointer.
 */
  if(action && *action=='\0')
    action = NULL;
/*
 * Translate the public originator enumeration to the private equivalent.
 */
  binder = origin==GL_USER_KEY ? KTB_USER : KTB_NORM;
/*
 * Bind the action to a given key-sequence?
 */
  if(keyseq && _kt_set_keybinding(gl->bindings, binder, keyseq, action)) {
    _err_record_msg(gl->err, _kt_last_error(gl->bindings), END_ERR_MSG);
    return 1;
  };
  return 0;
}

/*.......................................................................
 * This is the public wrapper around the gl_clear_termina() function.
 * It clears the terminal and leaves the cursor at the home position.
 * In server I/O mode, the next call to gl_get_line() will also
 * redisplay the current input line.
 *
 * Input:
 *  gl          GetLine *   The resource object of gl_get_line().
 * Output:
 *  return          int     0 - OK.
 *                          1 - Error.
 */
int gl_erase_terminal(GetLine *gl)
{
  sigset_t oldset;      /* The signals that were blocked on entry */
                        /*  to this function */
  int status;           /* The return status */
/*
 * Block all signals while accessing gl.
 */
  gl_mask_signals(gl, &oldset);
/*
 * Clear the terminal.
 */
  status = gl_clear_screen(gl, 1, NULL);
/*
 * Attempt to flush the clear-screen control codes to the terminal.
 * If this doesn't complete the job, the next call to gl_get_line()
 * will.
 */
  (void) gl_flush_output(gl);
/*
 * Restore the process signal mask before returning.
 */
  gl_unmask_signals(gl, &oldset);
  return status;
}

/*.......................................................................
 * This function must be called by any function that erases the input
 * line.
 *
 * Input:
 *  gl          GetLine *   The resource object of gl_get_line().
 */
static void gl_line_erased(GetLine *gl)
{
  gl->displayed = 0;
  gl->term_curpos = 0;
  gl->term_len = 0;
}

/*.......................................................................
 * Append a specified line to the history list.
 *
 * Input:
 *  gl          GetLine *   The resource object of gl_get_line().
 *  line     const char *   The line to be added.
 * Output:
 *  return          int     0 - OK.
 *                          1 - Error.
 */
int gl_append_history(GetLine *gl, const char *line)
{
  sigset_t oldset;      /* The signals that were blocked on entry */
                        /*  to this function */
  int status;           /* The return status */
/*
 * Check the arguments.
 */
  if(!gl || !line) {
    errno = EINVAL;
    return 1;
  };
/*
 * Block all signals.
 */
  if(gl_mask_signals(gl, &oldset))
    return 1;
/*
 * Execute the private body of the function while signals are blocked.
 */
  status = _gl_append_history(gl, line);
/*
 * Restore the process signal mask.
 */
  gl_unmask_signals(gl, &oldset);
  return status;
}

/*.......................................................................
 * This is the private body of the public function, gl_append_history().
 * It assumes that the caller has checked its arguments and blocked the
 * delivery of signals.
 */
static int _gl_append_history(GetLine *gl, const char *line)
{
  int status =_glh_add_history(gl->glh, line, 0);
  if(status)
    _err_record_msg(gl->err, _glh_last_error(gl->glh), END_ERR_MSG);
  return status;
}

/*.......................................................................
 * Enable or disable the automatic addition of newly entered lines to the
 * history list.
 *
 * Input:
 *  gl          GetLine *   The resource object of gl_get_line().
 *  enable          int     If true, subsequently entered lines will
 *                          automatically be added to the history list
 *                          before they are returned to the caller of
 *                          gl_get_line(). If 0, the choice of how and
 *                          when to archive lines in the history list,
 *                          is left up to the calling application, which
 *                          can do so via calls to gl_append_history().
 * Output:
 *  return          int     0 - OK.
 *                          1 - Error.
 */
int gl_automatic_history(GetLine *gl, int enable)
{
  sigset_t oldset;      /* The signals that were blocked on entry */
                        /*  to this function */
/*
 * Check the arguments.
 */
  if(!gl) {
    errno = EINVAL;
    return 1;
  };
/*
 * Block all signals.
 */
  if(gl_mask_signals(gl, &oldset))
    return 1;
/*
 * Execute the private body of the function while signals are blocked.
 */
  gl->automatic_history = enable;
/*
 * Restore the process signal mask.
 */
  gl_unmask_signals(gl, &oldset);
  return 0;
}

/*.......................................................................
 * This is a public function that reads a single uninterpretted
 * character from the user, without displaying anything.
 *
 * Input:
 *  gl     GetLine *  A resource object previously returned by
 *                    new_GetLine().
 * Output:
 *  return     int    The character that was read, or EOF if the read
 *                    had to be aborted (in which case you can call
 *                    gl_return_status() to find out why).
 */
int gl_read_char(GetLine *gl)
{
  int retval;   /* The return value of _gl_read_char() */
/*
 * This function can be called from application callback functions,
 * so check whether signals have already been masked, so that we don't
 * do it again, and overwrite gl->old_signal_set.
 */
  int was_masked = gl->signals_masked;
/*
 * Check the arguments.
 */
  if(!gl) {
    errno = EINVAL;
    return EOF;
  };
/*
 * Temporarily block all of the signals that we have been asked to trap.
 */
  if(!was_masked && gl_mask_signals(gl, &gl->old_signal_set))
    return EOF;
/*
 * Perform the character reading task.
 */
  retval = _gl_read_char(gl);
/*
 * Restore the process signal mask to how it was when this function was
 * first called.
 */
  if(!was_masked)
    gl_unmask_signals(gl, &gl->old_signal_set);
  return retval;
}

/*.......................................................................
 * This is the main body of the public function gl_read_char().
 */
static int _gl_read_char(GetLine *gl)
{
  int retval = EOF;  /* The return value */
  int waserr = 0;    /* True if an error occurs */
  char c;            /* The character read */
/*
 * This function can be called from application callback functions,
 * so check whether signals have already been overriden, so that we don't
 * overwrite the preserved signal handlers with gl_get_line()s. Also
 * record whether we are currently in raw I/O mode or not, so that this
 * can be left in the same state on leaving this function.
 */
  int was_overriden = gl->signals_overriden;
  int was_raw = gl->raw_mode;
/*
 * Also keep a record of the direction of any I/O that gl_get_line()
 * is awaiting, so that we can restore this status on return.
 */
  GlPendingIO old_pending_io = gl->pending_io;
/*
 * Assume that this call will successfully complete the input operation
 * until proven otherwise.
 */
  gl_clear_status(gl);
/*
 * If this is the first call to this function or gl_get_line(),
 * since new_GetLine(), complete any postponed configuration.
 */
  if(!gl->configured) {
    (void) _gl_configure_getline(gl, NULL, NULL, TECLA_CONFIG_FILE);
    gl->configured = 1;
  };
/*
 * Before installing our signal handler functions, record the fact
 * that there are no pending signals.
 */
  gl_pending_signal = -1;
/*
 * Temporarily override the signal handlers of the calling program,
 * so that we can intercept signals that would leave the terminal
 * in a bad state.
 */
  if(!was_overriden)
    waserr = gl_override_signal_handlers(gl);
/*
 * After recording the current terminal settings, switch the terminal
 * into raw input mode, without redisplaying any partially entered input
 * line.
 */
  if(!was_raw)
    waserr = waserr || _gl_raw_io(gl, 0);
/*
 * Attempt to read the line. This will require more than one attempt if
 * either a current temporary input file is opened by gl_get_input_line()
 * or the end of a temporary input file is reached by gl_read_stream_line().
 */
  while(!waserr) {
/*
 * Read a line from a non-interactive stream?
 */
    if(gl->file_fp || !gl->is_term) {
      retval = gl_read_stream_char(gl);
      if(retval != EOF) {            /* Success? */
	break;
      } else if(gl->file_fp) {  /* End of temporary input file? */
	gl_revert_input(gl);
	gl_record_status(gl, GLR_NEWLINE, 0);
      } else {                  /* An error? */
	waserr = 1;
	break;
      };
    };
/*
 * Read from the terminal? Note that the above if() block may have
 * changed gl->file_fp, so it is necessary to retest it here, rather
 * than using an else statement.
 */
    if(!gl->file_fp && gl->is_term) {
/*
 * Flush any pending output to the terminal before waiting
 * for the user to type a character.
 */
      if(_glq_char_count(gl->cq) > 0 && gl_flush_output(gl)) {
	retval = EOF;
/*
 * Read one character. Don't append it to the key buffer, since
 * this would subseuqnely appear as bogus input to the line editor.
 */
      } else if(gl_read_terminal(gl, 0, &c) == 0) {
/*
 * Record the character for return.
 */
	retval = c;
/*
 * In this mode, count each character as being a new key-sequence.
 */
	gl->keyseq_count++;
/*
 * Delete the character that was read, from the key-press buffer.
 */
	gl_discard_chars(gl, 1);
      };
      if(retval==EOF)
	waserr = 1;
      else
	break;
    };
  };
/*
 * If an error occurred, but gl->rtn_status is still set to
 * GLR_NEWLINE, change the status to GLR_ERROR. Otherwise
 * leave it at whatever specific value was assigned by the function
 * that aborted input. This means that only functions that trap
 * non-generic errors have to remember to update gl->rtn_status
 * themselves.
 */
  if(waserr && gl->rtn_status == GLR_NEWLINE)
    gl_record_status(gl, GLR_ERROR, errno);
/*
 * Restore terminal settings, if they were changed by this function.
 */
  if(!was_raw && gl->io_mode != GL_SERVER_MODE)
    _gl_normal_io(gl);
/*
 * Restore the signal handlers, if they were overriden by this function.
 */
  if(!was_overriden)
    gl_restore_signal_handlers(gl);
/*
 * If this function gets aborted early, the errno value associated
 * with the event that caused this to happen is recorded in
 * gl->rtn_errno. Since errno may have been overwritten by cleanup
 * functions after this, restore its value to the value that it had
 * when the error condition occured, so that the caller can examine it
 * to find out what happened.
 */
  errno = gl->rtn_errno;
/*
 * Error conditions are signalled to the caller, by setting the returned
 * character to EOF.
 */
  if(gl->rtn_status != GLR_NEWLINE)
    retval = EOF;
/*
 * Restore the indication of what direction of I/O gl_get_line()
 * was awaiting before this call.
 */
  gl->pending_io = old_pending_io;
/*
 * Return the acquired character.
 */
  return retval;
}

/*.......................................................................
 * Reset the GetLine completion status. This function should be called
 * at the start of gl_get_line(), gl_read_char() and gl_query_char()
 * to discard the completion status and non-zero errno value of any
 * preceding calls to these functions.
 *
 * Input:
 *  gl       GetLine *  The resource object of this module.
 */
static void gl_clear_status(GetLine *gl)
{
  gl_record_status(gl, GLR_NEWLINE, 0);
}

/*.......................................................................
 * When an error or other event causes gl_get_line() to return, this
 * function should be called to record information about what
 * happened, including the value of errno and the value that
 * gl_return_status() should return.
 *
 * Input:
 *  gl                GetLine *  The resource object of this module.
 *  rtn_status GlReturnStatus    The completion status. To clear a
 *                               previous abnormal completion status,
 *                               specify GLR_NEWLINE (this is what
 *                               gl_clear_status() does).
 *  rtn_errno             int    The associated value of errno.
 */
static void gl_record_status(GetLine *gl, GlReturnStatus rtn_status,
			     int rtn_errno)
{
/*
 * If rtn_status==GLR_NEWLINE, then this resets the completion status, so we
 * should always heed this. Otherwise, only record the first abnormal
 * condition that occurs after such a reset.
 */
  if(rtn_status == GLR_NEWLINE || gl->rtn_status == GLR_NEWLINE) {
    gl->rtn_status = rtn_status;
    gl->rtn_errno = rtn_errno;
  };
}

