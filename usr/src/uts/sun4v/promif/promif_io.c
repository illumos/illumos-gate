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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif_impl.h>
#include <sys/systm.h>
#include <sys/hypervisor_api.h>
#include <sys/consdev.h>
#ifndef _KMDB
#include <sys/kmem.h>
#endif

/*
 * Definitions for using Polled I/O.
 *
 * The usage of Polled I/O is different when we are in kmdb. In that case,
 * we can not directly invoke the polled I/O functions and we have to use
 * the kmdb DPI interface. Also we don't need to enter/exit the polled I/O
 * mode because this is already managed by kmdb when entering/exiting the
 * debugger.
 *
 * When we are not in kmdb then we can directly call the polled I/O functions
 * but we have to enter the polled I/O mode first. After using polled I/O
 * functions we have to exit the polled I/O mode. Note that entering/exiting
 * the polled I/O mode is time consuming so this should be avoided when
 * possible.
 */
#ifdef _KMDB
extern struct cons_polledio *kmdb_kdi_get_polled_io(void);
extern uintptr_t kmdb_dpi_call(uintptr_t, uint_t, const uintptr_t *);

#define	PROMIF_PIO (kmdb_kdi_get_polled_io())

#define	PROMIF_PIO_CALL1(fn, arg)					\
	(kmdb_dpi_call((uintptr_t)fn, 1, (uintptr_t *)&arg))

#define	PROMIF_PIO_CALL2(fn, arg1, arg2)				\
	{								\
		uintptr_t args[2];					\
		args[0] = (uintptr_t)arg1;				\
		args[1] = (uintptr_t)arg2;				\
		(void) (kmdb_dpi_call((uintptr_t)fn, 2, (uintptr_t *)args)); \
	}

#define	PROMIF_PIO_ENTER(pio)
#define	PROMIF_PIO_EXIT(pio)

#else  /* _KMDB */

#define	PROMIF_PIO				(cons_polledio)
#define	PROMIF_PIO_CALL1(fn, arg)		(fn(arg))
#define	PROMIF_PIO_CALL2(fn, arg1, arg2)	(fn(arg1, arg2))

#define	PROMIF_PIO_ENTER(pio)						\
	if (pio->cons_polledio_enter != NULL) {				\
		pio->cons_polledio_enter(pio->cons_polledio_argument);	\
	}

#define	PROMIF_PIO_EXIT(pio)						\
	if (pio->cons_polledio_exit != NULL) {				\
		pio->cons_polledio_exit(pio->cons_polledio_argument);	\
	}

#endif	/* _KMDB */

#define	PROM_REG_TO_UNIT_ADDR(r)	((r) & ~(0xful << 28))

static pnode_t instance_to_package(ihandle_t ih);

/* cached copies of IO params */
static phandle_t pstdin;
static phandle_t pstdout;

static ihandle_t istdin;
static ihandle_t istdout;

static struct cons_polledio *promif_polledio = NULL;

int
promif_instance_to_package(void *p)
{
	cell_t		*ci = (cell_t *)p;
	ihandle_t	ih;
	phandle_t	ph;

	ih = p1275_cell2ihandle(ci[3]);

	ph = instance_to_package(ih);

	ci[4] = p1275_phandle2cell(ph);

	return (0);
}

/* This function is not used but it is convenient for debugging I/O problems */
static void
/* LINTED */
promif_hv_print(char *str)
{
	size_t i, len = strlen(str);

	for (i = 0; i < len; i++) {
		while (hv_cnputchar((uint8_t)str[i]) == H_EWOULDBLOCK)
			/* try forever */;
	}
}

static void
promif_pio_enter(void)
{
	ASSERT(promif_polledio == NULL);

	promif_polledio = PROMIF_PIO;
	ASSERT(promif_polledio != NULL);

	PROMIF_PIO_ENTER(promif_polledio);
}

static void
promif_pio_exit(void)
{
	ASSERT(promif_polledio != NULL);

	PROMIF_PIO_EXIT(promif_polledio);
	promif_polledio = NULL;
}

static int
promif_do_read(char *buf, size_t len, boolean_t wait)
{
	int rlen;
	int (*getchar)(cons_polledio_arg_t);
	boolean_t (*ischar)(cons_polledio_arg_t);
	cons_polledio_arg_t arg;

	promif_pio_enter();

	if ((ischar = promif_polledio->cons_polledio_ischar) == NULL)
		return (0);
	if ((getchar = promif_polledio->cons_polledio_getchar) == NULL)
		return (0);

	arg = promif_polledio->cons_polledio_argument;

	for (rlen = 0; rlen < len; ) {
		if (PROMIF_PIO_CALL1(ischar, arg)) {
			buf[rlen] = PROMIF_PIO_CALL1(getchar, arg);
			rlen++;
			continue;
		}

		if (!wait)
			break;
	}

	promif_pio_exit();

	return (rlen);
}

static int
promif_do_write(char *buf, size_t len)
{
	int rlen;
	void (*putchar)(cons_polledio_arg_t, uchar_t);
	cons_polledio_arg_t arg;

	promif_pio_enter();

	if ((putchar = promif_polledio->cons_polledio_putchar) == NULL)
		return (0);

	arg = promif_polledio->cons_polledio_argument;

	for (rlen = 0; rlen < len; rlen++)
		PROMIF_PIO_CALL2(putchar, arg, buf[rlen]);

	promif_pio_exit();

	return (rlen);
}

char
promif_getchar(void)
{
	char c;

	(void) promif_do_read(&c, 1, B_TRUE);
	return (c);
}

int
promif_write(void *p)
{
	cell_t	*ci = (cell_t *)p;
	uint_t	fd;
	char	*buf;
	size_t	len;
	size_t	rlen;

	ASSERT(ci[1] == 3);

	fd  = p1275_cell2uint(ci[3]);
	buf = p1275_cell2ptr(ci[4]);
	len = p1275_cell2size(ci[5]);

	/* only support stdout (console) */
	ASSERT(fd == istdout);

	rlen = promif_do_write(buf, len);

	/* return the length written */
	ci[6] = p1275_size2cell(rlen);

	return (0);
}

int
promif_read(void *p)
{
	cell_t	*ci = (cell_t *)p;
	uint_t	fd;
	char	*buf;
	size_t	len;
	size_t	rlen;

	ASSERT(ci[1] == 3);

	/* unpack arguments */
	fd  = p1275_cell2uint(ci[3]);
	buf = p1275_cell2ptr(ci[4]);
	len = p1275_cell2size(ci[5]);

	/* only support stdin (console) */
	ASSERT(fd == istdin);

	rlen = promif_do_read(buf, len, B_FALSE);

	/* return the length read */
	ci[6] = p1275_size2cell(rlen);

	return (0);
}

static pnode_t
instance_to_package(ihandle_t ih)
{
	/* only support stdin and stdout */
	ASSERT((ih == istdin) || (ih == istdout));

	if (ih == istdin)
		return (pstdin);

	if (ih == istdout)
		return (pstdout);

	return (OBP_BADNODE);
}

#ifdef _KMDB

void
promif_io_init(ihandle_t in, ihandle_t out, phandle_t pin, phandle_t pout)
{
	istdin = in;
	istdout = out;
	pstdin = pin;
	pstdout = pout;
}

#else

void
promif_io_init(void)
{
	/*
	 * Cache the mapping between the stdin and stdout
	 * ihandles and their respective phandles.
	 */
	pstdin = prom_stdin_node();
	pstdout = prom_stdout_node();

	istdin = prom_stdin_ihandle();
	istdout = prom_stdout_ihandle();
}

int
promif_instance_to_path(void *p)
{
	cell_t		*ci = (cell_t *)p;
	pnode_t		node;
	ihandle_t	ih;
	char		*buf;
	int		rlen;
	char		*regval;
	uint_t		*csaddr;
	char		name[OBP_MAXPROPNAME];
	char		scratch[OBP_MAXPATHLEN];
	int		rvlen;

	ih = p1275_cell2ihandle(ci[3]);
	buf = p1275_cell2ptr(ci[4]);

	ci[6] = p1275_uint2cell(0);

	node = instance_to_package(ih);

	*buf = '\0';

	while (node != prom_rootnode()) {
		if (prom_getprop(node, OBP_NAME, name) == -1) {
			prom_printf("instance_to_path: no name property "
			    "node=0x%x\n", node);
			return (-1);
		}

		/* construct the unit address from the 'reg' property */
		if ((rlen = prom_getproplen(node, OBP_REG)) == -1)
			return (-1);

		/*
		 * Make sure we don't get dispatched onto a different
		 * cpu if we happen to sleep.  See kern_postprom().
		 */
		thread_affinity_set(curthread, CPU->cpu_id);
		regval = kmem_zalloc(rlen, KM_SLEEP);

		(void) prom_getprop(node, OBP_REG, regval);

		csaddr = (uint_t *)regval;

		(void) prom_sprintf(scratch, "/%s@%lx%s", name,
		    PROM_REG_TO_UNIT_ADDR(*csaddr), buf);

		kmem_free(regval, rlen);
		thread_affinity_clear(curthread);

		(void) prom_strcpy(buf, scratch);

		node = prom_parentnode(node);
	}

	rvlen = prom_strlen(buf);
	ci[6] = p1275_uint2cell(rvlen);

	return (0);
}

#endif	/* _KMDB */
