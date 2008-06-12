/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2003-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 * Sun elects to license this software under the BSD license.
 * See README for more details.
 */
#ifndef __ELOOP_H
#define	__ELOOP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* Magic number for eloop_cancel_timeout() */
#define	ELOOP_ALL_CTX		(void *) -1
#define	MAX_POLLFDS		32

struct eloop_sock {
	int sock;
	void *eloop_data;
	void *user_data;
	void (*handler)(int, void *, void *);
};

struct eloop_timeout {
	struct timeval time;
	void *eloop_data;
	void *user_data;
	void (*handler)(void *, void *);
	struct eloop_timeout *next;
};

struct eloop_signal {
	int sig;
	void *user_data;
	void (*handler)(int, void *, void *);
	int signaled;
};

struct eloop_data {
	void *user_data;

	int max_sock, reader_count;
	struct eloop_sock *readers;

	struct eloop_timeout *timeout;

	int signal_count;
	struct eloop_signal *signals;
	int signaled;

	int terminate;
};

void eloop_init(void *);

int eloop_register_read_sock(int,
	void (*handler)(int, void *, void *), void *, void *);

void eloop_unregister_read_sock(int);

int eloop_register_timeout(unsigned int, unsigned int,
	void (*handler)(void *, void *), void *, void *);

void eloop_cancel_timeout(void (*handler)(void *, void *), void *, void *);
int eloop_register_signal(int, void (*handler)(int, void *, void *), void *);

void eloop_run(void);
void eloop_terminate(void);
void eloop_destroy(void);

#ifdef __cplusplus
}
#endif

#endif /* __ELOOP_H */
