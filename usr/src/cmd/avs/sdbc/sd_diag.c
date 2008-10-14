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

/* #include <version.h> SKK */
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/inttypes.h>
#include <stdio.h>
#include <strings.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <unistd.h>
#include <nsctl.h>

#include <sys/nsctl/sd_cache.h>
#include <sys/nsctl/sd_conf.h>

#include <stdlib.h>
#include <thread.h>
#include <synch.h>

#define	MAXPARTS	100	/* Max disks */
#define	MAXBUF	65536	/* Max buffer size in long words */
#define	DISKLIST	"disk_config"	/* Default config file */
#define	DEF_SIZE	8192	/* Default buffer size */
#define	DEF_LOOP	1000	/* Loops for test */
#define	RAND_LOOPS	DEF_LOOP	/* # of random ios to do */

/*
 *  >>>>>>>>> USER LEVEL SD CACHE DIAGNOSTICS <<<<<<<<<<
 *
 *  Write and read data blocks w/multiple processes
 *  Starts one process for each partition specified in
 *  the config file
 */

int  buf1[MAXBUF];
int  buf2[MAXBUF];
char name[MAXPARTS][80];
int  pattern[MAXPARTS];
int  bufsize = DEF_SIZE;
int  fba_num_bufsize;
nsc_size_t  loops   = DEF_LOOP;
nsc_size_t  r_loops   = RAND_LOOPS;
int  fsize   = -1;
int  readercount = 3;
int  Rflag = O_EXCL;
char config_file[32];

int
read_parts()
{
	FILE *dfile;
	int   partitions = 0;
	int i;

	dfile = fopen(config_file, "r");
	if (dfile == NULL) {
		(void) printf("cannot open file: %s\n", config_file);
		perror("fopen");
		exit(errno);
	}
	for (i = 0; i < MAXPARTS; i++) {
		if (fscanf(dfile, "%s %x", name[i], (uint_t *)&pattern[i]) ==
		    EOF) {
			break;
		} else
			if (name[i][0] == '#' || strchr(name[i], '/') == NULL) {
				i--;
				continue;
			}
		partitions++;
	}
	(void) fclose(dfile);
	(void) printf("No. of partitions listed in file '%s' = %d\n\n",
			config_file, partitions);
	return (partitions);
}

void
print_usage()
{
	(void) printf("Usage:\n");
	(void) printf(
"sd_diag [-R] [-b <bufsize>] [-d <datasize>] [-l <loops>] [-r <readers>]\n");
	(void) printf(
"        [-f <disk_config_file>] <test#>\n");
	(void) printf(" test 1 = random read/write\n");
	(void) printf("      2 = random read/write/verify, read after write\n");
	(void) printf("      3 = random read/write/verify,");
	(void) printf(" all reads after all writes\n");
	(void) printf("      4 = sequential read/write\n");
	(void) printf("      5 = sequential write/read/verify,");
	(void) printf(" all reads after all writes\n");
	(void) printf(
	"      6 = altenating top/bottom sequential read/write/verify\n");
	(void) printf("      7 = multiple readers/1 random writer\n");
	(void) printf("      8 = random writes\n");
	(void) printf("      9 = sequential write of known data\n");
	(void) printf("      10 = sequential copy of datasize disk/verify\n");
	(void) printf("      11 = sequential read/verify test 9 data -");
	(void) printf(" then clear data with timestamp\n");
	(void) printf("      12 = sequential read/verify test 9 data -");
	(void) printf(" no clear data\n");
	(void) printf("\n");
	(void) printf("  <bufsize> in bytes (minimum is 512 bytes)\n");
	(void) printf("  <datasize> in Mbytes per disk\n");
	(void) printf("  <loops> is count of reads/writes,\n");
	(void) printf("          loops = 0 tests entire datasize disk");
	(void) printf(" for sequential tests.\n");
	(void) printf("          loops = 0 performs %d I/Os for the random "
	    "tests\n", RAND_LOOPS);
	(void) printf("  <readers> is count of readers for test #7 (default "
	    "is 3).\n");
	(void) printf(" [ defaults: bufsize = %d bytes, loops = %d,",
			DEF_SIZE, DEF_LOOP);
	(void) printf(" datasize = disksize ]\n");
	(void) printf("\n");
	(void) printf("  -R : do nsc_reserve(), nsc_release(0 around each "
	    "I/O\n");
}

void
parse_opts(int argc, char *argv[])
{
	extern char *optarg;
	int c;

	while ((c = getopt(argc, argv, "b:d:l:r:Rf:")) != -1) {
		switch (c) {
			case 'f':
			/* printf("\n%s", optarg); */
			strcpy(config_file, optarg);
			break;
		case 'b':
			/* bufsize between 1*512 and 512*512 */
			bufsize = strtol(optarg, 0, 0);
			if (bufsize > (MAXBUF*4))
				bufsize = MAXBUF*4;
			else if (bufsize < FBA_SIZE(1))
			    bufsize = FBA_SIZE(1);
			break;
		case 'd':
			/* convert datasize from Mb's to fba */
			fsize = strtol(optarg, 0, 0) *  FBA_NUM(1 << 20);
			break;
		case 'l':
			loops = (nsc_size_t)strtoll(optarg, 0, 0);
			break;
		case 'r':
			/* count of readers for test 7 */
			readercount = strtol(optarg, 0, 0);
			break;
		case 'R':
			/* do reserve, release on a per io basis */
			Rflag = 0;
			break;
		case '?':
			print_usage();
			exit(0);
		}
	}
	bufsize &= ~FBA_MASK; /* multiple of 512 bytes for SECTMODE I/O */
	fba_num_bufsize = FBA_NUM(bufsize);

	/*  set #ios for random io tests */
	if (loops != 0)
		r_loops = loops;

}

nsc_size_t
set_part_size(char *path, nsc_fd_t *sdfd)
{
	nsc_size_t filesize;
	int rc;

	rc = nsc_partsize(sdfd, &filesize); /* partsize in FBAs (512 bytes) */
	if (rc < 0 || filesize == 0) {
		(void) fprintf(stderr,
		    "set_part_size: cannot access partition size");
		(void) fprintf(stderr, " for %s\n", path);
		(void) nsc_close(sdfd);
		exit(1);
	}

	(void) printf("Partition %s, size:%" NSC_SZFMT " blocks\n", path,
	    filesize);

	if (fsize != -1 && fsize < filesize)
		filesize = fsize;
	filesize -= fba_num_bufsize;
	if (filesize < fba_num_bufsize) {
		(void) printf("ERROR: Max block size %" NSC_SZFMT "\n",
		    filesize);
		(void) nsc_close(sdfd);
		exit(0);
	}

	return (filesize);
}

int
do_sdtest1(int fd, nsc_size_t loops, nsc_size_t filesize)
{
	nsc_off_t seekpos;
	nsc_size_t i;
	ssize_t r;

	for (i = 0; i < loops; i++) {
		seekpos = (
#ifdef NSC_MULTI_TERABYTE
		    ((nsc_off_t)rand() << 48) | ((nsc_off_t)rand() << 32) |
#endif
		    (rand() << 16) | rand()) % filesize;
		r = pwrite(fd, buf1, bufsize, (off_t)(seekpos << SCTRSHFT));
		if (r <= 0) {
			perror("Test1: write");
			return (1);
		}
		seekpos = (
#ifdef NSC_MULTI_TERABYTE
		    ((nsc_off_t)rand() << 48) | ((nsc_off_t)rand() << 32) |
#endif
		    (rand() << 16) | rand()) % filesize;
		r = pread(fd, buf2, bufsize, (off_t)(seekpos << SCTRSHFT));
		if (r <= 0) {
			perror("Test1: read");
			return (1);
		}
	}
	return (0);
}

void
gen_data(int *buffer, int size)
{
	int i;

	size /= 4;
	for (i = 0; i < size; i++)
		buffer[i] = rand() << 16 | rand();
}

int
do_sdtest2(int fd, nsc_size_t loops, nsc_size_t filesize, int h)
{
	nsc_off_t seekpos;
	int err = 0;
	ssize_t r;
	nsc_size_t i;

	for (i = 0; i < loops; i++) {
		seekpos = (
#ifdef NSC_MULTI_TERABYTE
		    ((nsc_off_t)rand() << 48) | ((nsc_off_t)rand() << 32) |
#endif
		    (rand() << 16) | rand()) % filesize;
		gen_data(buf1, bufsize);
		r = pwrite(fd, buf1, bufsize, (off_t)(seekpos << SCTRSHFT));
		if (r <= 0) {
			perror("Test2: write");
			err++;
			return (err);
		}
		r = pread(fd, buf2, bufsize, (off_t)(seekpos << SCTRSHFT));
		if (r <= 0) {
			perror("Test2: read");
			err++;
			return (err);
		}
		if (memcmp(buf1, buf2, bufsize)) {
			(void) printf("Test2: Data corruption,"
			    " fd:%s, fpos:%" PRId64 ", len:%d\n",
			    name[h], (int64_t)(seekpos << SCTRSHFT),
			    bufsize);
			err++;
		}
	}
	return (err);
}

int
do_sdtest3(int fd, nsc_size_t loops, nsc_size_t filesize, int h, nsc_fd_t *sdfd)
{
	nsc_off_t *seekpos;
	int err = 0;
	nsc_size_t i;
	ssize_t r;

	seekpos = malloc(loops*sizeof (nsc_off_t));
	if (seekpos == NULL) {
		perror("Test3: malloc");
		(void) nsc_close(sdfd);
		exit(errno);
	}
	gen_data(buf1, bufsize);

	for (i = 0; i < loops; i++) {
		seekpos[i] = (
#ifdef NSC_MULTI_TERABYTE
		    ((nsc_off_t)rand() << 48) | ((nsc_off_t)rand() << 32) |
#endif
		    (rand() << 16) | rand()) % filesize;
		seekpos[i] -= seekpos[i] % fba_num_bufsize;
		r = pwrite(fd, buf1, bufsize, (off_t)(seekpos[i] << SCTRSHFT));
		if (r <= 0) {
			perror("Test3: write");
			err++;
			goto cleanup;
		}
	}
	for (i = 0; i < loops; i++) {
		buf2[0] = '\0';	/* clear buf to make sure something is read */
		r = pread(fd, buf2, bufsize, (off_t)(seekpos[i] << SCTRSHFT));
		if (r <= 0) {
			perror("Test3: read");
			err++;
			goto cleanup;
		}
		if (memcmp(buf1, buf2, bufsize)) {
			(void) printf("Data corruption, fd:%s, fpos:%" PRId64
			    ", len:%d\n", name[h],
			    (int64_t)(seekpos[i] << SCTRSHFT), bufsize);
			err++;
		}
	}

cleanup:
	free(seekpos);
	return (err);
}

int
do_sdtest4(int fd, nsc_size_t loops, nsc_size_t filesize)
{
	ssize_t r;
	nsc_size_t i;

	/*
	 * Do sequential reads/writes for loops number
	 * of bufsize chunks, unless loops == 0, then do
	 * entire disk.
	 * 1. sequential reads from the top down,
	 * 2. sequential writes from the top down,
	 * 3. sequential reads from the bottom up,
	 * 4. sequential writes from the bottom up.
	 */
	if ((loops > (filesize / fba_num_bufsize)) || (!loops))
	    loops = filesize / fba_num_bufsize; /* entire disk */

	for (i = 0; i < loops; i++) {
		r = pread(fd, buf2, bufsize, (i*fba_num_bufsize) << SCTRSHFT);
		if (r <= 0) {
			perror("Test4: read");
			return (1);
		}
	}
	for (i = 0; i < loops; i++) {
		r = pwrite(fd, buf1, bufsize, (i*fba_num_bufsize) << SCTRSHFT);
		if (r <= 0) {
			perror("Test4: write");
			return (1);
		}
	}
	for (i = loops - 1; i + 1 > 0; i--) {
		r = pread(fd, buf2, bufsize, (i*fba_num_bufsize) << SCTRSHFT);
		if (r <= 0) {
			perror("Test4: read");
			return (1);
		}
	}
	for (i = loops - 1; i + 1 > 0; i--) {
		r = pwrite(fd, buf1, bufsize, (i*fba_num_bufsize) << SCTRSHFT);
		if (r <= 0) {
			perror("Test4: write");
			return (1);
		}
	}
	return (0);
}

int
do_sdtest5(int fd, nsc_size_t loops, nsc_size_t filesize, int h)
{
	int err = 0;
	ssize_t r;
	nsc_size_t i;

	/*
	 * Do sequential writes with verify reads for loops number
	 * of bufsize chunks, unless loops == 0, then do
	 * entire disk.
	 * 1. sequential writes from the top down,
	 * 2. sequential reads from the top down with verify,
	 * 3. sequential writes from the bottom up,
	 * 4. sequential reads from the bottom up with verify.
	 */
	if ((loops > (filesize / fba_num_bufsize)) || (!loops))
	    loops = filesize / fba_num_bufsize; /* entire disk */

	gen_data(buf1, bufsize);

	for (i = 0; i < loops; i++) {
		r = pwrite(fd, buf1, bufsize, (i*fba_num_bufsize) << SCTRSHFT);
		if (r <= 0) {
			perror("Test5: write");
			err++;
			return (err);
		}
	}
	for (i = 0; i < loops; i++) {
		buf2[0] = '\0';	/* clear buf to make sure something is read */
		r = pread(fd, buf2, bufsize, (i*fba_num_bufsize) << SCTRSHFT);
		if (r <= 0) {
			perror("Test5: read");
			err++;
			return (err);
		}
		if (memcmp(buf1, buf2, bufsize)) {
			(void) printf("Test5: Data corruption,"
			    " fd:%s, fpos:%" NSC_SZFMT ", len:%d\n",
			    name[h], i, bufsize);
			err++;
		}
	}

	gen_data(buf1, bufsize);

	for (i = loops - 1; i + 1 > 0; i--) {
		r = pwrite(fd, buf1, bufsize, (i*fba_num_bufsize) << SCTRSHFT);
		if (r <= 0) {
			perror("Test5: write");
			err++;
			return (err);
		}
	}
	for (i = loops - 1; i + 1 > 0; i--) {
		buf2[0] = '\0';	/* clear buf to make sure something is read */
		r = pread(fd, buf2, bufsize, (i*fba_num_bufsize) << SCTRSHFT);
		if (r <= 0) {
			perror("Test5: read");
			err++;
			return (err);
		}
		if (memcmp(buf1, buf2, bufsize)) {
			(void) printf("Test5: Data corruption,"
			    " fd:%s, fpos:%" NSC_SZFMT ", len:%d\n",
			    name[h], i, bufsize);
			err++;
		}
	}
	return (err);
}


int
do_sdtest6(int fd, nsc_size_t loops, nsc_size_t filesize, int h)
{
	int err = 0;
	nsc_size_t i;
	ssize_t r;
	nsc_size_t endloop = filesize / fba_num_bufsize;
	int  buf3[MAXBUF];
	int  buf4[MAXBUF];
	nsc_off_t  top_pos, bottom_pos;

	/*
	 * Do alternating top down and bottom up sequential writes
	 * (working towards middle) and verify with reads
	 * for loops number of bufsize chunks, unless loops == 0, then do
	 * entire disk.
	 */
	if ((loops > (filesize / fba_num_bufsize)) || (!loops))
	    loops = filesize / fba_num_bufsize; /* entire disk */

	for (i = 0; i < loops; i++) {
		gen_data(buf1, bufsize);
		bottom_pos = i*fba_num_bufsize;
		r = pwrite(fd, buf1, bufsize, (off_t)(bottom_pos << SCTRSHFT));
		if (r <= 0) {
			perror("Test6: write");
			err++;
			return (err);
		}
		gen_data(buf2, bufsize);
		top_pos = (endloop - i - 1)*fba_num_bufsize;

		/* Make sure we don't collide in the middle */

		if (abs(top_pos - bottom_pos) < fba_num_bufsize)
			top_pos = bottom_pos + fba_num_bufsize;

		r = pwrite(fd, buf2, bufsize, (off_t)(top_pos << SCTRSHFT));
		if (r <= 0) {
			perror("Test6: write");
			err++;
			return (err);
		}
		r = pread(fd, buf3, bufsize, (off_t)(bottom_pos << SCTRSHFT));
		if (r <= 0) {
			perror("Test6: read");
			err++;
			return (err);
		}
		if (memcmp(buf1, buf3, bufsize)) {
			(void) printf("Data corruption(1), fd:%s, fpos:%"
			    PRId64 ", len:%d\n", name[h],
			    (int64_t)(bottom_pos << SCTRSHFT), bufsize);
			err++;
		}
		r = pread(fd, buf4, bufsize, (off_t)(top_pos << SCTRSHFT));
		if (r <= 0) {
			perror("Test6: read");
			return (1);
		}
		if (memcmp(buf2, buf4, bufsize)) {
			(void) printf("Test6: Data corruption(2),"
			    " fd:%s, fpos:%" PRId64 ", len:%d\n",
			    name[h], (int64_t)(top_pos << SCTRSHFT), bufsize);
			err++;
		}
	}
	return (err);
}

int shmid;

#define	MAXREADERS 32

struct shm_struct {
	int writebuf[MAXBUF];
	volatile nsc_off_t writepos;
	int quit;
	int err;
	mutex_t err_mutex;
	int rd_done[MAXREADERS];
	int rd_done_mask[MAXREADERS];
} *shm;

#define	WRITEBUF (shm->writebuf)
#define	WRITEPOS (shm->writepos)

#define	QUIT	(shm->quit)
#define	ERR	(shm->err)
#define	ERRMUTEX (shm->err_mutex)
#define	RD_DONE (shm->rd_done)
#define	RD_DONE_MASK (shm->rd_done_mask)

#define	LOCKWRITE
#define	LOCKREAD(i)

/*  Clear RD_DONE and Set WRITEPOS  */
#define	FREEWRITE { \
	bzero(RD_DONE, sizeof (RD_DONE)); \
	WRITEPOS = wr_pos; }

/*  Reader i+1 marks himself as finished  */
#define	FREEREAD(i) (RD_DONE[(i)] = 1)


int
do_sdtest7read(int fd, int h, int which)
{
	int err;
	ssize_t r_rd;
	nsc_off_t curr_pos;
	nsc_size_t loop_cnt;
	err = 0; curr_pos = 0; loop_cnt = 0;
	for (;;) {
		/* Already read this? */
		if (curr_pos == WRITEPOS) {
			if (!QUIT) {
				continue;
			} else {
				/*  Time to go!  */
				/* printf("Quitting [%d]\n", which+1); */
				break;
			}
		}

		/* get location to read from */
		curr_pos = WRITEPOS;

		r_rd = pread(fd, buf1, bufsize, (curr_pos << SCTRSHFT));
		loop_cnt += 1;
		if (r_rd <= 0) {
			FREEREAD(which);
			perror("Test7: read");
			err += 1;
			continue;
		}

		if (memcmp(buf1, WRITEBUF, bufsize)) {
			FREEREAD(which);
			(void) printf("\nTest7: Data corruption, reader #%d, "
			    "fd:%s, \
				fpos:%" PRId64 ", len:%d\n", which + 1, name[h],
				(int64_t)(curr_pos << SCTRSHFT), bufsize);
			err += 1;
			continue;
		}

		FREEREAD(which);
	}

	(void) printf(
	    "Partition %s, Test 7, reader #%d:  %d errors %lld loops\n",
		name[h], which+1, err, loop_cnt);

	if (err > 0) {
		(void) mutex_lock(&ERRMUTEX);
		ERR += err;
		(void) mutex_unlock(&ERRMUTEX);
	}

	if (err)
		return (1);
	else
		return (0);
}


int
do_sdtest7write(int fd, nsc_size_t filesize, int h)
{
	int err = 0;
	ssize_t r;
	nsc_off_t wr_pos;

	/*  Wait for readers to finish  */
	while (memcmp(RD_DONE, RD_DONE_MASK, readercount*sizeof (int)))
		;

	gen_data(WRITEBUF, bufsize);
	wr_pos = (
#ifdef NSC_MULTI_TERABYTE
	    ((nsc_off_t)rand() << 48) | ((nsc_off_t)rand() << 32) |
#endif
	    (rand() << 16) | rand()) % filesize;
	r = pwrite(fd, WRITEBUF, bufsize, (off_t)(wr_pos << SCTRSHFT));
	if (r <= 0) {
		FREEWRITE;
		perror("Test7: write");
		return (1);
	}
	FREEWRITE;

	/* verify write */
	r = pread(fd, buf1, bufsize, (off_t)(wr_pos << SCTRSHFT));
	if (r <= 0) {
		perror("Test7: writer: read");
		return (1);
	}


	if (memcmp(buf1, WRITEBUF, bufsize)) {
		(void) printf("\nTest7: Data corruption in writer,"
		    " fd:%s, fpos:%" PRId64 ", len:%d\n",
		    name[h], (int64_t)(wr_pos << SCTRSHFT), bufsize);
		err++;
	}


	return (err);
}

void
init_shm()
{
	int i;

	/*  Clear out everything  */
	bzero(shm, sizeof (struct shm_struct));

	(void) mutex_init(&ERRMUTEX, USYNC_PROCESS, NULL);

	/*   Set up mask (constant) to test reader doneness  */
	for (i = 0; i < readercount; i++)
		RD_DONE_MASK[i] = 1;

	/* Mark all readers done - so writer can start  */
	for (i = 0; i < readercount; i++)
		RD_DONE[i] = 1;
}

int
do_sdtest7(int fd, nsc_size_t loops, nsc_size_t filesize, int h, nsc_fd_t *sdfd)
{
	int r, i, err;
	nsc_size_t j;

	if ((shmid = shmget(IPC_PRIVATE, sizeof (struct shm_struct),
				IPC_CREAT | 0666)) < 0) {
		perror("shmget error: ");
		(void) nsc_close(sdfd);
		exit(1);
	}

	shm = (struct shm_struct *)shmat(shmid, NULL, 0);
	if (shm == (struct shm_struct *)-1) {
		perror("shmat error: ");
		(void) nsc_close(sdfd);
		exit(1); /* cleanup exits */
	}

	init_shm();

	/*  Start Readers  */
	for (i = 0; i < readercount; i++) {
		r = fork();
		if (r == 0) { /* child */
			(void) do_sdtest7read(fd, h, i);
			(void) nsc_close(sdfd);
			exit(0);
		} else
			continue;
	}

	/*  Start Writer  */
	srand(getpid()); err = 0;
	for (j = 0; j < loops; j++) {
		err += do_sdtest7write(fd, filesize, h);
	}
	QUIT = 1;

	(void) printf("\n\nPartition %s, Test 7, writer:  %d errors\n",
	    name[h], err);

	for (i = 0; i < readercount; i++)
		wait(0);

	/*  No lock needed here - everybody's finished  */
	err += ERR;

	(void) mutex_destroy(&ERRMUTEX);
	shmctl(shmid, IPC_RMID, 0);
	return (err);
}

int
do_sdtest8(int fd, nsc_size_t loops, nsc_size_t filesize)
{
	nsc_off_t seekpos;
	int err = 0;
	ssize_t r;
	nsc_size_t i;

	for (i = 0; i < loops; i++) {
		seekpos = (
#ifdef NSC_MULTI_TERABYTE
		    ((nsc_off_t)rand() << 48) | ((nsc_off_t)rand() << 32) |
#endif
		    (rand() << 16) | rand()) % filesize;
		gen_data(buf1, bufsize);
		r = pwrite(fd, buf1, bufsize, (off_t)(seekpos << SCTRSHFT));
		if (r <= 0) {
			perror("Test8: write");
			err++;
			return (err);
		}
	}
	return (err);
}

void
gen_data_known(int *buffer, int size, int data)
{
	int i;

	size /= 4;
	for (i = 0; i < size; i++)
		buffer[i] = data;
}

int
do_sdtest9(int fd, nsc_size_t loops, nsc_size_t filesize, int h)
{
	int err = 0;
	ssize_t r;
	nsc_off_t fba_offset;
	nsc_size_t i, wrapval;

	/*
	 * Test 9 will write a given pattern over and over Test 11 or
	 * Test 12 will read same pattern.
	 */
	/* Large loop value that would cause write overflow will wrap */

	gen_data_known(buf1, bufsize, pattern[h]);

	wrapval = filesize / fba_num_bufsize;

	if (loops == 0)
		loops = wrapval;  /* entire disk */

	for (i = 0; i < loops; i++) {
		fba_offset = i % wrapval;
		r = pwrite(fd, buf1, bufsize,
		    (off_t)(fba_offset * fba_num_bufsize) << SCTRSHFT);
		if (r <= 0) {
			perror("Test9: write");
			err++;
			return (err);
		}
	}
	return (err);
}

int
do_sdtest10(int fd1, int fd2, nsc_size_t loops, nsc_size_t filesize1,
    nsc_size_t filesize2, int h)
{
	nsc_size_t filesize;
	int err = 0;
	nsc_size_t i;
	ssize_t r;

	/*
	 * Do sequential copy of disk1 to disk2 for loops number
	 * of bufsize chunks, unless loops == 0, then copy size of
	 * the smaller disk.
	 * Go back and verify that the two disks are identical.
	 */

	filesize = (filesize1 < filesize2) ? filesize1 : filesize2;
	if ((loops > (filesize / fba_num_bufsize)) || (!loops))
	    loops = filesize / fba_num_bufsize;

	/* copy disk1 to to disk2 */
	for (i = 0; i < loops; i++) {
		r = pread(fd1, buf1, bufsize,
		    (off_t)(i*fba_num_bufsize) << SCTRSHFT);
		if (r <= 0) {
			perror("Test10: read");
			return (1);
		}
		r = pwrite(fd2, buf1, bufsize,
		    (off_t)(i*fba_num_bufsize) << SCTRSHFT);
		if (r <= 0) {
			perror("Test10: write");
			return (1);
		}
	}

	/* verify disks are identical */
	for (i = 0; i < loops; i++) {
		buf1[0] = '\0';	/* clear buf to make sure something is read */
		r = pread(fd1, buf1, bufsize,
		    (off_t)(i * fba_num_bufsize) << SCTRSHFT);
		if (r <= 0) {
			perror("Test10: read");
			return (1);
		}
		buf2[0] = 'x';	/* make sure something is read */
		r = pread(fd2, buf2, bufsize,
		    (off_t)(i * fba_num_bufsize) << SCTRSHFT);
		if (r <= 0) {
			perror("Test10: read");
			return (1);
		}
		if (memcmp(buf1, buf2, bufsize)) {
			(void) printf("Test10: Data corruption,"
			    " fd1:%s, fd2:%s fpos:%" NSC_SZFMT ", len:%d\n",
			    name[2*h], name[2*h+1], i, bufsize);
			err++;
		}
	}
	return (err);
}

int
buffcmp(int *b1, int *b2, int size)
{
	int i;

	for (i = 0; i < size/4; i++) {
		if (b1[i] != b2[i]) {
			(void) printf("Word %d does not match b1=0x%x, "
			    "b2=0x%x\n", i, b1[i], b2[i]);
			return (1);
		}
	}
	return (0);

}

int
do_sdtest11(int fd, nsc_size_t loops, nsc_size_t filesize, int h)
{
	int err = 0;
	nsc_size_t i;
	ssize_t r;
	int buf3[MAXBUF];
	int buf4[MAXBUF];
	int timestamp;
	time_t clock;
	struct tm *tm;


	/*
	 * Test 9 will write a given pattern over and over Test 11 will read
	 * same pattern and clear with timestamp data (MM:SS).
	 */

	clock = time(NULL);
	tm  = localtime(&clock);
	(void) ascftime((char *)&timestamp, "%M""%S", tm);

	gen_data_known(buf1, bufsize, pattern[h]);
	gen_data_known(buf4, bufsize, timestamp);
	if ((loops > filesize / fba_num_bufsize) || (!loops))
		loops = filesize / fba_num_bufsize;  /* entire disk */

	for (i = 0; i < loops; i++) {
		r = pread(fd, buf3, bufsize,
		    (off_t)(i*fba_num_bufsize) << SCTRSHFT);
		if (r <= 0) {
			perror("Test11: read");
			err++;
			return (err);
		}
		if (buffcmp(buf1, buf3, bufsize)) {
			(void) printf("Data corr, fd:%s, fpos:%" NSC_SZFMT
			", len:%d\n", name[h], i, bufsize);
			err++;
			return (err);
		}
		r = pwrite(fd, buf4, bufsize,
		    (off_t)(i*fba_num_bufsize) << SCTRSHFT);
		if (r <= 0) {
			perror("Test11: write");
			err++;
			return (err);
		}
	}
	return (err);
}

int
do_sdtest12(int fd, nsc_size_t loops, nsc_size_t filesize, int h)
{
	int err = 0;
	nsc_size_t i;
	ssize_t r;
	int buf3[MAXBUF];

	/*
	 * Test 9 will write a given pattern over and over Test 12 will read
	 * same pattern
	 */

	gen_data_known(buf1, bufsize, pattern[h]);
	if ((loops > filesize / fba_num_bufsize) || (!loops))
		loops = filesize / fba_num_bufsize;  /* entire disk */

	for (i = 0; i < loops; i++) {
		r = pread(fd, buf3, bufsize,
		    (off_t)(i*fba_num_bufsize) << SCTRSHFT);
		if (r <= 0) {
			perror("Test12: read");
			err++;
			return (err);
		}
		if (buffcmp(buf1, buf3, bufsize)) {
			(void) printf("Data corr, fd:%s, fpos:%" NSC_SZFMT
			", len:%d\n", name[h], i, bufsize);
			err++;
			return (err);
		}
	}
	return (err);
}

#ifdef lint
int
sd_diag_lintmain(int argc, char *argv[])
#else
int
main(int argc, char *argv[])
#endif
{
	int procs;
	nsc_size_t filesize, filesize2;
	int fd, fd2, r, id, h, i;
	nsc_fd_t *sdfd, *sdfd2;

	if (argc < 2) {
		print_usage();
		exit(0);
	}
	strcpy(config_file, DISKLIST);
	parse_opts(argc, argv);

	_nsc_nocheck();
	if ((procs = read_parts()) == 0)
		exit(0);

	id = strtol(argv[optind], 0, 0);
	if (id == 10) {
		/*
		 * each process gets 2 disks and copies disk1 to disk2,
		 * then goes back and verifies that the two disks are
		 * identical.
		 */
		if (procs < 2) {
		(void) printf("%s requires having at least 2 disks for test "
		    "#10.\n", config_file);
		exit(0);
		}

	    for (h = 0; h < procs/2; h++) {
		r = fork();
		if (r == 0) {
			srand(getpid());


			if (!(sdfd = nsc_open(name[2*h], NSC_CACHE,
					O_RDWR | Rflag))) {
				(void) fprintf(stderr,
				    "sd_diag: Error opening %s\n", name[2*h]);
				exit(1);
			}
			fd = nsc_fileno(sdfd);
			if (fd == -1) {
				(void) fprintf(stderr,
				    "sd_diag: Error opening %s\n", name[2*h]);
				(void) nsc_close(sdfd);
				exit(1);
			}
			filesize = set_part_size(name[2*h], sdfd);
			if (!(sdfd2 = nsc_open(name[2*h+1], NSC_CACHE,
					O_RDWR | Rflag))) {
				(void) fprintf(stderr,
				    "sd_diag: Error opening %s\n", name[2*h+1]);
				exit(1);
			}
			fd2 = nsc_fileno(sdfd2);
			if (fd2 == -1) {
				(void) fprintf(stderr,
				    "sd_diag: Error opening %s\n", name[2*h+1]);
				(void) nsc_close(sdfd2);
				exit(1);
			}
			filesize2 = set_part_size(name[2*h+1], sdfd2);
			(void) sleep(2);
			r = do_sdtest10(fd, fd2, loops, filesize, filesize2, h);

			(void) printf("Partitions %s and %s, Test %d,"
			    " Completed %d errors\n",
			    name[2*h], name[2*h+1], id, r);
			(void) nsc_close(sdfd);
			(void) nsc_close(sdfd2);
			exit(0);
		} else if (r == -1) {
			perror("fork");
			break;
		} else
			continue;
	    } /* for */
	    for (i = 0; i < h; i++)
		wait(0);
	} else {

	for (h = 0; h < procs; h++) {
		r = fork();
		if (r == 0) {
			srand(getpid());

			id = strtol(argv[optind], 0, 0);
			if (!(sdfd = nsc_open(name[h], NSC_CACHE,
					O_RDWR | Rflag))) {
				(void) fprintf(stderr,
				    "sd_diag: Error opening %s\n", name[h]);
				exit(1);
			}
			fd = nsc_fileno(sdfd);

			if (fd == -1) {
				(void) fprintf(stderr,
				    "sd_diag: Error opening %s\n", name[h]);
				(void) nsc_close(sdfd);
				exit(1);
			}
			filesize = set_part_size(name[h], sdfd);

			(void) sleep(2);


			switch (id) {
			    case 1:
				r = do_sdtest1(fd, r_loops, filesize);
				break;
			    case 2:
				r = do_sdtest2(fd, r_loops, filesize, h);
				break;
			    case 3:
				r = do_sdtest3(fd, r_loops, filesize, h, sdfd);
				break;
			    case 4:
				r = do_sdtest4(fd, loops, filesize);
				break;
			    case 5:
				r = do_sdtest5(fd, loops, filesize, h);
				break;
			    case 6:
				r = do_sdtest6(fd, loops, filesize, h);
				break;
			    case 7:
				r = do_sdtest7(fd, r_loops, filesize, h, sdfd);
				break;
			    case 8:
				r = do_sdtest8(fd, r_loops, filesize);
				break;
			    case 9:
				r = do_sdtest9(fd, loops, filesize, h);
				break;
			    case 11:
				r = do_sdtest11(fd, loops, filesize, h);
				break;
			    case 12:
				r = do_sdtest12(fd, loops, filesize, h);
				break;
			    default:
				break;
			}

			(void) printf("Partition %s, Test %d, Completed %d "
			    "errors\n", name[h], id, r);
			(void) nsc_close(sdfd);
			exit(r ? 1 : 0);
		} else if (r == -1) {
			perror("fork");
			break;
		} else
			continue;
	}
	for (i = 0; i < h; i++)
		wait(0);
	}

	return (0);
}
