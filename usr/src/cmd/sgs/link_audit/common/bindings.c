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
 * Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
 */
#include	<link.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/regset.h>
#include	<sys/frame.h>
#include	<sys/lwp.h>
#include	<fcntl.h>
#include	<stdio.h>
#include	<sys/mman.h>
#include	<errno.h>
#include	<signal.h>
#include	<synch.h>
#include	<string.h>

#include	"bindings.h"
#include	"env.h"

static Elist		*bindto_list = NULL;
static Elist		*bindfrom_list = NULL;

static bindhead		*bhp = NULL;
static unsigned int	current_map_len = 0;
static char		*buffer_name;
static const sigset_t	iset = { ~0U, ~0U, ~0U, ~0U };
static lwp_mutex_t	sharedmutex = SHAREDMUTEX;

/*
 * This routine was stolen from libelf.so.1
 */
static unsigned long
ehash(const char *name)
{
	unsigned int		g, h = 0;
	const unsigned char	*nm = (unsigned char *)name;

	while (*nm != '\0') {
		h = (h << 4) + *nm++;
		/* LINTED */
		if ((g = (unsigned int)(h & MASK)) != 0)
			h ^= g >> 24;
		h &= ~MASK;
	}
	return ((unsigned long)h);
}


static void
output_err_message(const char *msg)
{
	int fd;
	if ((fd = open("/tmp/bind_err", O_RDWR | O_CREAT, 0666)) == -1) {
		(void) fprintf(stderr, "bindings.so: unable to open err_log\n");
		perror("open");
	}
	(void) lseek(fd, 0, SEEK_END);
	(void) write(fd, msg, strlen(msg));
	(void) close(fd);
}

/*
 * common mutex locking & unlocking routines for this module.  This is to
 * control the setting of 'lock_held'.
 */
static void
bt_lock(lwp_mutex_t *lock)
{
	if (_lwp_mutex_lock(lock) != 0) {
		output_err_message("bt_lock failed!!\n");
		(void) fprintf(stderr, "bindings.so: unable to obtain lock\n");
		perror("_lwp_mutex_lock");
	}
}

static void
bt_unlock(lwp_mutex_t *lock)
{
	if (_lwp_mutex_unlock(lock) != 0) {
		output_err_message("bt_unlock failed!!\n");
		(void) fprintf(stderr, "bindings.so: unable to unlock lock\n");
		perror("_lwp_mutex_unlock");
	}
}



/*
 * It's always possible that another process sharing our buffer
 * has caused it to grow.  If this is the case we must adjust our
 * mappings to compensate.
 */
static void
remap_buffer(int fd)
{
	void *	new_bhp;
	if ((new_bhp = mmap(0, bhp->bh_size, PROT_READ | PROT_WRITE,
	    MAP_SHARED, fd, 0)) == MAP_FAILED) {
		(void) fprintf(stderr, "bindings: remap: mmap failed\n");
		perror("mmap");

		bt_unlock(&bhp->bh_lock);
		exit(1);
	}
	/*
	 * clean up old mapping
	 */
	(void) munmap((caddr_t)bhp, current_map_len);
	bhp = (bindhead *)new_bhp;
	current_map_len = bhp->bh_size;
}

static void
grow_buffer(void)
{
	int	fd;
	if ((fd = open(buffer_name, O_RDWR)) == -1) {
		(void) fprintf(stderr,
		    "bidings: grow_buffer: open failed: %s\n", buffer_name);
		perror("open");
		bt_unlock(&bhp->bh_lock);
		exit(1);
	}
	if (ftruncate(fd, bhp->bh_size + BLKSIZE) == -1) {
		(void) fprintf(stderr, "grow_buffer failed\n");
		perror("ftruncate");
		bt_unlock(&bhp->bh_lock);
		exit(1);
	}
	bhp->bh_size += BLKSIZE;
	remap_buffer(fd);
	(void) close(fd);
}

static void
get_new_strbuf(void)
{
	bt_lock(&bhp->bh_lock);
	while (bhp->bh_end + STRBLKSIZE > bhp->bh_size)
		grow_buffer();

	bhp->bh_strcur = bhp->bh_end;
	bhp->bh_end = bhp->bh_strend = bhp->bh_strcur + STRBLKSIZE;
	bt_unlock(&bhp->bh_lock);
}

static unsigned int
save_str(const char *str)
{
	char		*sptr;
	unsigned int	bptr;
	unsigned int	slen;

	bt_lock(&bhp->bh_strlock);
	/* LINTED */
	slen = (unsigned int)strlen(str);

	/*
	 * will string fit into our current string buffer?
	 */
	if ((slen + 1) > (bhp->bh_strend - bhp->bh_strcur))
		get_new_strbuf();
	bptr = bhp->bh_strcur;
	sptr = (char *)bhp + bhp->bh_strcur;
	bhp->bh_strcur += slen + 1;
	(void) strncpy(sptr, str, slen);
	sptr[slen] = '\0';
	bt_unlock(&bhp->bh_strlock);
	return (bptr);
}


static unsigned int
get_new_entry(void)
{
	unsigned int	new_ent;
	bt_lock(&bhp->bh_lock);
	while ((sizeof (binding_entry) + bhp->bh_end) > bhp->bh_size)
		grow_buffer();
	new_ent = bhp->bh_end;
	bhp->bh_end += sizeof (binding_entry);
	bt_unlock(&bhp->bh_lock);
	return (new_ent);
}



static void
init_locks(void)
{
	int i;

	(void) memcpy(&bhp->bh_lock, &sharedmutex, sizeof (lwp_mutex_t));
	for (i = 0; i < DEFBKTS; i++)
		(void) memcpy(&bhp->bh_bkts[i].bb_lock, &sharedmutex,
		    sizeof (lwp_mutex_t));

	(void) memcpy(&bhp->bh_strlock, &sharedmutex, sizeof (lwp_mutex_t));
}

uint_t
la_version(uint_t version)
{
	int	fd;
	sigset_t	omask;

	if (version < LAV_CURRENT) {
		(void) fprintf(stderr,
		    "bindings.so: unexpected link_audit version: %d\n",
		    version);
		return (0);
	}

	build_env_list(&bindto_list, (const char *)"BT_BINDTO");
	build_env_list(&bindfrom_list, (const char *)"BT_BINDFROM");

	if ((buffer_name = getenv(FILEENV)) == NULL)
		buffer_name = DEFFILE;

	(void) sigprocmask(SIG_BLOCK, &iset, &omask);
	if ((fd = open(buffer_name, O_RDWR | O_CREAT | O_EXCL, 0666)) != -1) {
		int	init_size = sizeof (bindhead) + BLKSIZE;

		if (ftruncate(fd, init_size) == -1) {
			perror("ftruncate");
			return (0);
		}

		/* LINTED */
		if ((bhp = (bindhead *)mmap(0, init_size,
		    PROT_READ | PROT_WRITE,
		    MAP_SHARED, fd, 0)) == MAP_FAILED) {
			perror("bindings.so: mmap");
			return (0);
		}

		(void) close(fd);

		init_locks();
		/*
		 * Lock our structure and then initialize the data
		 */
		bt_lock(&bhp->bh_lock);
		bhp->bh_vers = BINDCURVERS;
		current_map_len = bhp->bh_size = init_size;
		bhp->bh_end = sizeof (bindhead);
		bhp->bh_bktcnt = DEFBKTS;
		bt_unlock(&bhp->bh_lock);
		/*
		 * Set up our initial string buffer
		 */
		get_new_strbuf();
	} else if ((fd = open(buffer_name, O_RDWR)) != -1) {
		struct stat	stbuf;
		int		i;
		for (i = 0; i < 4; i++) {
			if (fstat(fd, &stbuf) == -1) {
				(void) sleep(1);
				continue;
			}
			if (stbuf.st_size < sizeof (bindhead)) {
				(void) sleep(1);
				continue;
			}
			/* LINTED */
			if ((bhp = (bindhead *)mmap(0, stbuf.st_size,
			    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) ==
			    MAP_FAILED) {
				(void) fprintf(stderr,
				    "bindings: mmap failed\n");
				perror("mmap");
				return (0);
			}

			/* LINTED */
			current_map_len = (unsigned int)stbuf.st_size;
		}
		if (bhp == NULL) {
			(void) fprintf(stderr,
			    "bindings: buffer mapping timed out\n");
			return (0);
		}
		for (i = 0; i < 4; i++) {
			if (bhp->bh_vers == 0) {
				(void) sleep(1);
				continue;
			}
		}
		if (bhp->bh_vers == 0) {
			(void) fprintf(stderr,
			    "bindings: %s not initialized\n", buffer_name);
			return (0);
		}

		bt_lock(&bhp->bh_lock);

		if (bhp->bh_size != current_map_len)
			remap_buffer(fd);
		(void) close(fd);
	} else {
		(void) fprintf(stderr, "bindings: unable to open %s\n",
		    buffer_name);
		perror("open");
		return (0);
	}

	(void) sigprocmask(SIG_SETMASK, &omask, NULL);
	bt_unlock(&bhp->bh_lock);

	return (LAV_CURRENT);
}

/* ARGSUSED 0 */
uint_t
la_objopen(Link_map *lmp, Lmid_t lmid, uintptr_t *cookie)
{
	uint_t	flags;

	if ((bindto_list == NULL) ||
	    (check_list(bindto_list, lmp->l_name)))
		flags = LA_FLG_BINDTO;
	else
		flags = 0;

	if ((bindfrom_list == NULL) ||
	    (check_list(bindfrom_list, lmp->l_name)))
		flags |= LA_FLG_BINDFROM;

	return (flags);
}


/* ARGSUSED 1 */
#if	defined(__sparcv9)
uintptr_t
la_sparcv9_pltenter(Elf64_Sym *symp, uint_t symndx, uintptr_t *refcooke,
	uintptr_t *defcook, La_sparcv9_regs *regset, uint_t *sb_flags,
	const char *sym_name)
#elif	defined(__sparc)
uintptr_t
la_sparcv8_pltenter(Elf32_Sym *symp, uint_t symndx, uintptr_t *refcooke,
	uintptr_t *defcook, La_sparcv8_regs *regset, uint_t *sb_flags)
#elif	defined(__amd64)
uintptr_t
la_amd64_pltenter(Elf64_Sym *symp, uint_t symndx, uintptr_t *refcooke,
	uintptr_t *defcook, La_amd64_regs *regset, uint_t *sb_flags,
	const char *sym_name)
#elif	defined(__i386)
uintptr_t
la_i86_pltenter(Elf32_Sym *symp, uint_t symndx, uintptr_t *refcooke,
	uintptr_t *defcook, La_i86_regs *regset, uint_t *sb_flags)
#endif
{
	unsigned long	bktno;
	Link_map	*dlmp = (Link_map *)*defcook;
	const char	*lib_name;
	sigset_t	omask;
#if	!defined(_LP64)
	const char	*sym_name = (const char *)symp->st_name;
#endif


	lib_name = dlmp->l_name;

	(void) sigprocmask(SIG_BLOCK, &iset, &omask);
	if (sym_name == NULL) {
		output_err_message("null symname\n");
		return (symp->st_value);
	}

	bktno = ehash(sym_name) % bhp->bh_bktcnt;

	bt_lock(&bhp->bh_bkts[bktno].bb_lock);

	/*
	 * The buffer has been grown (by another process) and
	 * we need to remap it into memory.
	 */
	if (bhp->bh_size != current_map_len) {
		int fd;
		if ((fd = open(buffer_name, O_RDWR)) == -1) {
			(void) fprintf(stderr,
				"bidings: plt_enter: open failed: %s\n",
				buffer_name);
			perror("open");
			bt_unlock(&bhp->bh_lock);
			exit(1);
		}
		bt_lock(&bhp->bh_lock);
		remap_buffer(fd);
		bt_unlock(&bhp->bh_lock);
		(void) close(fd);
	}

	if (bhp->bh_bkts[bktno].bb_head == 0) {
		binding_entry *	bep;
		unsigned int	be_off;
		unsigned int	sym_off;
		unsigned int	lib_off;

		be_off = get_new_entry();
		sym_off = save_str(sym_name);
		lib_off = save_str(lib_name);
		/* LINTED */
		bep = (binding_entry *)((char *)bhp + be_off);
		bep->be_next = 0;
		bep->be_sym_name = sym_off;
		bep->be_lib_name = lib_off;
		bep->be_count = 1;
		bhp->bh_bkts[bktno].bb_head = be_off;
	} else {
		int		strcmp_res;
		unsigned int	prev_off = 0;
		binding_entry	*prev_bep = NULL;
		unsigned int	cur_off;
		binding_entry	*cur_bep;
		unsigned int	lib_off = 0;

		/*
		 * Once we get to the bucket, we do a two tiered
		 * search.  First we search for a library match, then
		 * we search for a symbol match.
		 */
		cur_off = bhp->bh_bkts[bktno].bb_head;
		/* LINTED */
		cur_bep = (binding_entry *)((char *)bhp +
			cur_off);
		while (cur_off && (strcmp_res = strcmp((char *)bhp +
		    cur_bep->be_lib_name, lib_name)) < 0) {
			prev_off = cur_off;
			cur_off = cur_bep->be_next;
			/* LINTED */
			cur_bep = (binding_entry *)((char *)bhp +
				cur_off);
		}
		if (cur_off && (strcmp_res == 0)) {
			/*
			 * This is a small optimization.  For
			 * each bucket we will only record a library
			 * name once.  Once it has been recorded in
			 * a bucket we will just re-use the same
			 * string.
			 */
			lib_off = cur_bep->be_lib_name;
			while (cur_off && (strcmp_res = strcmp((char *)bhp +
			    cur_bep->be_sym_name, sym_name)) < 0) {
				prev_off = cur_off;
				cur_off = cur_bep->be_next;
				/* LINTED */
				cur_bep = (binding_entry *)((char *)bhp +
					cur_off);
			}
		}
		if (strcmp_res == 0) {
			/*
			 * We've got a match
			 */
			cur_bep->be_count++;
		} else {
			unsigned int	new_off;
			binding_entry *	new_bep;
			unsigned int	sym_off;

			new_off = get_new_entry();
			if (lib_off == 0)
				lib_off = save_str(lib_name);
			sym_off = save_str(sym_name);

			/* LINTED */
			new_bep = (binding_entry *)((char *)bhp +
				new_off);
			new_bep->be_sym_name = sym_off;
			new_bep->be_lib_name = lib_off;
			new_bep->be_count = 1;
			new_bep->be_next = cur_off;
			if (prev_off) {
				/* LINTED */
				prev_bep = (binding_entry *)((char *)bhp +
					prev_off);
				prev_bep->be_next = new_off;
			} else
				/*
				 * Insert at head of list.
				 */
				bhp->bh_bkts[bktno].bb_head = new_off;

		}
	}
	bt_unlock(&bhp->bh_bkts[bktno].bb_lock);
	(void) sigprocmask(SIG_SETMASK, &omask, NULL);
	return (symp->st_value);
}
