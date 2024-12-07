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
 * Copyright 2019 Peter Tribble.
 */

#ifndef	_SYS_PROMIF_H
#define	_SYS_PROMIF_H

#include <sys/types.h>
#include <sys/obpdefs.h>

#if defined(_KERNEL) || defined(_KMDB)
#include <sys/va_list.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *  These are for V0 ops only.  We sometimes have to specify
 *  to promif which type of operation we need to perform
 *  and since we can't get such a property from a V0 prom, we
 *  sometimes just assume it.  V2 and later proms do the right thing.
 */
#define	BLOCK	0
#define	NETWORK	1
#define	BYTE	2


#if defined(_KERNEL) || defined(_KMDB)

#if !defined(_BOOT)
/*
 * Due to FCode on sun4u machines running in a pseudo-32-bit environment
 * we need to enable code in several of the promif routines to ensure
 * that 64-bit pointers from the kernel are not passed through the CIF
 * to OpenBoot.
 *
 * Client programs defining this token need to provide two callbacks to
 * allow the promif routines to allocate and free memory allocated from
 * the bottom 32-bits of the 64-bit address space:
 *
 *	void *promplat_alloc(size_t);
 *	void promplat_free(void *, size_t);
 *
 * The alloc function should guarantee that it will never return an
 * invalid pointer.
 */
#define	PROM_32BIT_ADDRS
#endif /* _BOOT */

typedef void promif_preprom_f(void);
typedef void promif_postprom_f(void);

/*
 * resource allocation group: OBP and IEEE 1275-1994.
 * prom_alloc is platform dependent on SPARC.
 */
extern	caddr_t		prom_alloc(caddr_t virthint, size_t size, uint_t align);
extern	void		prom_free(caddr_t virt, size_t size);

/*
 * Device tree and property group: OBP and IEEE 1275-1994.
 */
extern	pnode_t		prom_childnode(pnode_t nodeid);
extern	pnode_t		prom_nextnode(pnode_t nodeid);
extern	pnode_t		prom_parentnode(pnode_t nodeid);
extern	pnode_t		prom_rootnode(void);
extern	pnode_t		prom_chosennode(void);
extern	pnode_t		prom_alias_node(void);
extern	pnode_t		prom_optionsnode(void);

extern	int		prom_asr_list_keys_len();
extern	int		prom_asr_list_keys(caddr_t value);
extern	int		prom_asr_export_len();
extern	int		prom_asr_export(caddr_t value);
extern	int		prom_asr_disable(char *keystr, int keystr_len,
			    char *reason, int reason_len);
extern	int		prom_asr_enable(char *keystr, int keystr_len);

extern	int		prom_getproplen(pnode_t nodeid, caddr_t name);
extern	int		prom_getprop(pnode_t nodeid, caddr_t name,
			    caddr_t value);
extern	caddr_t		prom_nextprop(pnode_t nodeid, caddr_t previous,
			    caddr_t next);
extern	int		prom_setprop(pnode_t nodeid, caddr_t name,
			    caddr_t value, int len);

extern	int		prom_getnode_byname(pnode_t id, char *name);
extern	int		prom_devicetype(pnode_t id, char *type);

extern	char		*prom_decode_composite_string(void *buf,
			    size_t buflen, char *prev);

/*
 * Device tree and property group: IEEE 1275-1994 Only.
 */
extern	pnode_t		prom_finddevice(char *path);	/* Also on obp2.x */

extern	int		prom_bounded_getprop(pnode_t nodeid,
			    caddr_t name, caddr_t buffer, int buflen);

extern	phandle_t	prom_getphandle(ihandle_t i);

/*
 * Device pathnames and pathname conversion: OBP and IEEE 1275-1994.
 */
extern	int		prom_devname_from_pathname(char *path, char *buffer);
extern	char		*prom_path_options(char *pathname);
extern	char		*prom_path_gettoken(char *from, char *to);
extern	void		prom_pathname(char *pathname);
extern	void		prom_strip_options(char *from, char *to);

/*
 * Device pathnames and pathname conversion: IEEE 1275-1994 only.
 */
extern	int		prom_ihandle_to_path(ihandle_t, char *buf,
			    uint_t buflen);
extern	int		prom_phandle_to_path(phandle_t, char *buf,
			    uint_t buflen);

/*
 * Special device nodes: OBP and IEEE 1275-1994.
 */
extern	ihandle_t	prom_stdin_ihandle(void);
extern	ihandle_t	prom_stdout_ihandle(void);
extern	pnode_t		prom_stdin_node(void);
extern	pnode_t		prom_stdout_node(void);
extern	char		*prom_stdinpath(void);
extern	char		*prom_stdoutpath(void);
extern	int		prom_stdin_devname(char *buffer);
extern	int		prom_stdout_devname(char *buffer);
extern	int		prom_stdin_is_keyboard(void);
extern	int		prom_stdout_is_framebuffer(void);
extern	int		prom_stdin_stdout_equivalence(void);

extern void		prom_get_tem_inverses(int *, int *);
extern void		prom_get_tem_size(size_t *, size_t *);
extern void		prom_get_tem_pos(uint32_t *, uint32_t *);
extern void		prom_get_term_font_size(int *, int *);
extern void		prom_hide_cursor(void);

/*
 * Special device nodes: IEEE 1275-1994 only.
 */
extern	ihandle_t	prom_memory_ihandle(void);
extern	ihandle_t	prom_mmu_ihandle(void);

/*
 * Administrative group: OBP and IEEE 1275-1994.
 */
extern	void		prom_enter_mon(void);
extern	void		prom_exit_to_mon(void)
	__NORETURN;
extern	void		prom_reboot(char *bootstr);

extern	void		prom_panic(char *string)
	__NORETURN;

extern	int		prom_getversion(void);
extern	int		prom_is_openprom(void);
extern	int		prom_is_p1275(void);
extern	int		prom_version_name(char *buf, int buflen);

extern	void		*prom_mon_id(void);	/* SMCC/OBP platform centric */

extern	uint_t		prom_gettime(void);

extern	char		*prom_bootpath(void);
extern	char		*prom_bootargs(void);

extern	void		prom_interpret(char *str, uintptr_t arg1,
			    uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
			    uintptr_t arg5);

/*
 * Administrative group: OBP only.
 */
extern	int		prom_sethandler(void (*v0_func)(), void (*v2_func)());

extern	struct bootparam *prom_bootparam(void);

/*
 * Administrative group: IEEE 1275-1994 only.
 */
extern void		*prom_set_callback(void *handler);
extern void		prom_set_symbol_lookup(void *sym2val, void *val2sym);

/*
 * Administrative group: IEEE 1275 only.
 */
extern	int		prom_test(char *service);
extern	int		prom_test_method(char *method, pnode_t node);

/*
 * Promif support group: Generic.
 */
extern	void		prom_init(char *progname, void *prom_cookie);

extern	void		prom_set_preprom(promif_preprom_f *);
extern	void		prom_set_postprom(promif_postprom_f *);

extern  void		prom_get_tem_pos(uint32_t *, uint32_t *);
extern	void		prom_get_tem_size(size_t *, size_t *);

typedef struct		__promif_redir_arg *promif_redir_arg_t;
typedef ssize_t		(*promif_redir_t)(promif_redir_arg_t,
				uchar_t *, size_t);
extern  void		prom_set_stdout_redirect(promif_redir_t,
				promif_redir_arg_t);

extern	void		prom_suspend_prepost(void);
extern	void		prom_resume_prepost(void);

extern	void		(*prom_set_nextprop_preprom(void (*)(void)))(void);
extern	void		(*prom_set_nextprop_postprom(void (*)(void)))(void);

extern	void		prom_montrap(void (*funcptr)());

typedef uint_t		prom_generation_cookie_t;

extern	int		prom_tree_access(int (*callback)(void *arg,
				int has_changed), void *arg,
				prom_generation_cookie_t *);
extern	int		prom_tree_update(int (*callback)(void *arg), void *arg);

/*
 * I/O Group: OBP and IEEE 1275.
 */
extern	uchar_t		prom_getchar(void);
extern	void		prom_putchar(char c);
extern	int		prom_mayget(void);
extern	int		prom_mayput(char c);

extern  int		prom_open(char *name);
extern  int		prom_close(int fd);
extern  ssize_t		prom_read(ihandle_t fd, caddr_t buf, size_t len,
			    uint_t startblk, char type);
extern  ssize_t		prom_write(ihandle_t fd, caddr_t buf, size_t len,
			    uint_t startblk, char type);
extern	int		prom_seek(int fd, u_longlong_t offset);

extern	void		prom_writestr(const char *buf, size_t bufsize);
extern	void		prom_pnode_to_pathname(pnode_t, char *);

extern	void		prom_printf(const char *fmt, ...)
	__KPRINTFLIKE(1);
#pragma rarely_called(prom_printf)

extern	void		prom_vprintf(const char *fmt, __va_list adx)
	__KVPRINTFLIKE(1);
#pragma rarely_called(prom_vprintf)

extern	char		*prom_sprintf(char *s, const char *fmt, ...)
	__KPRINTFLIKE(2);
extern	char		*prom_vsprintf(char *s, const char *fmt, __va_list adx)
	__KVPRINTFLIKE(2);

#define	PROM_WALK_CONTINUE	0	/* keep walking to next node */
#define	PROM_WALK_TERMINATE	1	/* abort walk now */

extern	void		prom_walk_devs(pnode_t node,
			    int (*f)(pnode_t, void *, void *),
			    void *arg, void *result);

extern	pnode_t		prom_findnode_byname(pnode_t id, char *name);
extern	pnode_t		prom_findnode_bydevtype(pnode_t id, char *devtype);

#define	PROM_STOP	{	\
	prom_printf("File %s line %d\n", __FILE__, __LINE__); \
	prom_enter_mon();	\
}

/*
 * file IO
 */
extern	int		prom_fopen(ihandle_t, char *);
extern	int		prom_volopen(ihandle_t, char *);
extern	int		prom_fseek(ihandle_t, int, unsigned long long);
extern	int		prom_fread(ihandle_t, int, caddr_t, size_t);
extern	int		prom_fsize(ihandle_t, int, size_t *);
extern	int		prom_compinfo(ihandle_t, int, int *,
			    size_t *, size_t *);
extern	void		prom_fclose(ihandle_t, int);


#endif	/* _KERNEL || _KMDB */

#ifdef _KERNEL

/*
 * Used by wrappers which bring up console frame buffer before prom_printf()
 * and other prom calls that may output to the console.  Struct is filled in
 * in prom_env.c and in sunpm.c
 */

typedef struct promif_owrap {
	void (*preout)(void);
	void (*postout)(void);
} promif_owrap_t;

/*
 * WAN boot key storage interface
 */
int prom_set_security_key(char *keyname, caddr_t buf, int buflen, int *reslen,
    int *status);
int prom_get_security_key(char *keyname, caddr_t buf, int buflen, int *keylen,
    int *status);
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_PROMIF_H */
