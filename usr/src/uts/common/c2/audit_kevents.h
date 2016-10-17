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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _BSM_AUDIT_KEVENTS_H
#define	_BSM_AUDIT_KEVENTS_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Audit event numbers.
 *
 *	0		Reserved as an invalid event number.
 *	1 -   511	Allocated for Solaris kernel
 *	512 -  2047	(reserved but not allocated)
 *	2048 - 32767	Reserved for the Solaris TCB application.
 *	32768 - 65535	Available for third party applications.
 *
 *	NOTE:	libbsm/audit_event.txt must be updated elsewhere when changes
 *		are made to kernel events.
 */

#define	AUE_NULL		0	/* =no indir system call */
#define	AUE_EXIT		1	/* =ps exit(2) */
#define	AUE_FORKALL		2	/* =ps forkall(2) */
#define	AUE_OPEN		3	/* =no open(2): place holder */
#define	AUE_CREAT		4	/* =no obsolete */
#define	AUE_LINK		5	/* =fc link(2) */
#define	AUE_UNLINK		6	/* =fd unlink(2) */
#define	AUE_EXEC		7	/* =no obsolete */
#define	AUE_CHDIR		8	/* =pm chdir(2) */
#define	AUE_MKNOD		9	/* =fc mknod(2) */
#define	AUE_CHMOD		10	/* =fm chmod(2) */
#define	AUE_CHOWN		11	/* =fm chown(2) */
#define	AUE_UMOUNT		12	/* =as umount(2): old version */
#define	AUE_JUNK		13	/* =no non existant event */
#define	AUE_ACCESS		14	/* =fa access(2) */
#define	AUE_KILL		15	/* =pm kill(2) */
#define	AUE_STAT		16	/* =fa stat(2) */
#define	AUE_LSTAT		17	/* =fa lstat(2) */
#define	AUE_ACCT		18	/* =as acct(2) */
#define	AUE_MCTL		19	/* =no mctl(2) */
#define	AUE_REBOOT		20	/* =no reboot(2) */
#define	AUE_SYMLINK		21	/* =fc symlink(2) */
#define	AUE_READLINK		22	/* =fr readlink(2) */
#define	AUE_EXECVE		23	/* =ps,ex execve(2) */
#define	AUE_CHROOT		24	/* =pm chroot(2) */
#define	AUE_VFORK		25	/* =ps vfork(2) */
#define	AUE_SETGROUPS		26	/* =pm setgroups(2) */
#define	AUE_SETPGRP		27	/* =pm setpgrp(2) */
#define	AUE_SWAPON		28	/* =no swapon(2) */
#define	AUE_SETHOSTNAME		29	/* =no sethostname(2) */
#define	AUE_FCNTL		30	/* =fm fcntl(2) */
#define	AUE_SETPRIORITY		31	/* =no setpriority(2) */
#define	AUE_CONNECT		32	/* =nt connect(2) */
#define	AUE_ACCEPT		33	/* =nt accept(2) */
#define	AUE_BIND		34	/* =nt bind(2) */
#define	AUE_SETSOCKOPT		35	/* =nt setsockopt(2) */
#define	AUE_VTRACE		36	/* =no vtrace(2) */
#define	AUE_SETTIMEOFDAY	37	/* =no settimeofday(2) */
#define	AUE_FCHOWN		38	/* =fm fchown(2) */
#define	AUE_FCHMOD		39	/* =fm fchmod(2) */
#define	AUE_SETREUID		40	/* =pm setreuid(2) */
#define	AUE_SETREGID		41	/* =pm setregid(2) */
#define	AUE_RENAME		42	/* =fc,fd rename(2) */
#define	AUE_TRUNCATE		43	/* =no truncate(2) */
#define	AUE_FTRUNCATE		44	/* =no ftruncate(2) */
#define	AUE_FLOCK		45	/* =no flock(2) */
#define	AUE_SHUTDOWN		46	/* =nt shutdown(2) */
#define	AUE_MKDIR		47	/* =fc mkdir(2) */
#define	AUE_RMDIR		48	/* =fd rmdir(2) */
#define	AUE_UTIMES		49	/* =fm futimens(2), utimensat(2) */
#define	AUE_ADJTIME		50	/* =as adjtime(2) */
#define	AUE_SETRLIMIT		51	/* =ua setrlimit(2) */
#define	AUE_KILLPG		52	/* =no killpg(2) */
#define	AUE_NFS_SVC		53	/* =no nfs_svc(2) */
#define	AUE_STATFS		54	/* =fa statfs(2) */
#define	AUE_FSTATFS		55	/* =fa fstatfs(2) */
#define	AUE_UNMOUNT		56	/* =no unmount(2) */
#define	AUE_ASYNC_DAEMON	57	/* =no async_daemon(2) */
#define	AUE_NFS_GETFH		58	/* =no nfs_getfh(2) */
#define	AUE_SETDOMAINNAME	59	/* =no setdomainname(2) */
#define	AUE_QUOTACTL		60	/* =no quotactl(2) */
#define	AUE_EXPORTFS		61	/* =no exportfs(2) */
#define	AUE_MOUNT		62	/* =as mount(2) */
#define	AUE_SEMSYS		63	/* =no semsys(2): place holder */
#define	AUE_MSGSYS		64	/* =no msgsys(2): place holder */
#define	AUE_SHMSYS		65	/* =no shmsys(2): place holder */
#define	AUE_BSMSYS		66	/* =no bsmsys(2): place holder */
#define	AUE_RFSSYS		67	/* =no rfssys(2): place holder */
#define	AUE_FCHDIR		68	/* =pm fchdir(2) */
#define	AUE_FCHROOT		69	/* =pm fchroot(2) */
#define	AUE_VPIXSYS		70	/* =no obsolete */
#define	AUE_PATHCONF		71	/* =fa pathconf(2) */
#define	AUE_OPEN_R		72	/* =fr open(2): read */
#define	AUE_OPEN_RC		73	/* =fc,fr open(2): read,creat */
#define	AUE_OPEN_RT		74	/* =fd,fr open(2): read,trunc */
#define	AUE_OPEN_RTC		75	/* =fc,fd,fr open(2): rd,cr,tr */
#define	AUE_OPEN_W		76	/* =fw open(2): write */
#define	AUE_OPEN_WC		77	/* =fc,fw open(2): write,creat */
#define	AUE_OPEN_WT		78	/* =fd,fw open(2): write,trunc */
#define	AUE_OPEN_WTC		79	/* =fc,fd,fw open(2): wr,cr,tr */
#define	AUE_OPEN_RW		80	/* =fr,fw open(2): read,write */
#define	AUE_OPEN_RWC		81	/* =fc,fw,fr open(2): rd,wr,cr */
#define	AUE_OPEN_RWT		82	/* =fd,fr,fw open(2): rd,wr,tr */
#define	AUE_OPEN_RWTC		83	/* =fc,fd,fw,fr open(2): rd,wr,cr,tr */
#define	AUE_MSGCTL		84	/* =ip msgctl(2): illegal command */
#define	AUE_MSGCTL_RMID		85	/* =ip msgctl(2): IPC_RMID command */
#define	AUE_MSGCTL_SET		86	/* =ip msgctl(2): IPC_SET command */
#define	AUE_MSGCTL_STAT		87	/* =ip msgctl(2): IPC_STAT command */
#define	AUE_MSGGET		88	/* =ip msgget(2) */
#define	AUE_MSGRCV		89	/* =ip msgrcv(2) */
#define	AUE_MSGSND		90	/* =ip msgsnd(2) */
#define	AUE_SHMCTL		91	/* =ip shmctl(2): Illegal command */
#define	AUE_SHMCTL_RMID		92	/* =ip shmctl(2): IPC_RMID command */
#define	AUE_SHMCTL_SET		93	/* =ip shmctl(2): IPC_SET command */
#define	AUE_SHMCTL_STAT		94	/* =ip shmctl(2): IPC_STAT command */
#define	AUE_SHMGET		95	/* =ip shmget(2) */
#define	AUE_SHMAT 		96	/* =ip shmat(2) */
#define	AUE_SHMDT 		97	/* =ip shmdt(2) */
#define	AUE_SEMCTL		98	/* =ip semctl(2): illegal command */
#define	AUE_SEMCTL_RMID		99	/* =ip semctl(2): IPC_RMID command */
#define	AUE_SEMCTL_SET		100	/* =ip semctl(2): IPC_SET command */
#define	AUE_SEMCTL_STAT		101	/* =ip semctl(2): IPC_STAT command */
#define	AUE_SEMCTL_GETNCNT	102	/* =ip semctl(2): GETNCNT command */
#define	AUE_SEMCTL_GETPID	103	/* =ip semctl(2): GETPID command */
#define	AUE_SEMCTL_GETVAL	104	/* =ip semctl(2): GETVAL command */
#define	AUE_SEMCTL_GETALL	105	/* =ip semctl(2): GETALL command */
#define	AUE_SEMCTL_GETZCNT	106	/* =ip semctl(2): GETZCNT command */
#define	AUE_SEMCTL_SETVAL	107	/* =ip semctl(2): SETVAL command */
#define	AUE_SEMCTL_SETALL	108	/* =ip semctl(2): SETALL command */
#define	AUE_SEMGET		109	/* =ip semget(2) */
#define	AUE_SEMOP		110	/* =ip semop(2) */
#define	AUE_CORE		111	/* =fc process dumped core */
#define	AUE_CLOSE		112	/* =cl close(2) */
#define	AUE_SYSTEMBOOT		113	/* =na system booted */
#define	AUE_ASYNC_DAEMON_EXIT	114	/* =no async_daemon(2) exited */
#define	AUE_NFSSVC_EXIT		115	/* =no nfssvc(2) exited */
#define	AUE_PFEXEC		116	/* =ps,ex,ua,as execve(2) w/ pfexec */
#define	AUE_OPEN_S		117	/* =fr open(2): search */
#define	AUE_OPEN_E		118	/* =fr open(2): exec */
/*
 * 119 - 129 are available for future growth (old SunOS_CMW events
 * that had no libbsm or praudit support or references)
 */
#define	AUE_GETAUID		130	/* =aa getauid(2) */
#define	AUE_SETAUID		131	/* =aa setauid(2) */
#define	AUE_GETAUDIT		132	/* =aa getaudit(2) */
#define	AUE_SETAUDIT		133	/* =aa setaudit(2) */
/*				134	    OBSOLETE */
/*				135	    OBSOLETE */
#define	AUE_AUDITSVC		136	/* =no obsolete */
/*				137	    OBSOLETE */
#define	AUE_AUDITON		138	/* =no auditon(2) */
#define	AUE_AUDITON_GTERMID	139	/* =no auditctl(2): GETTERMID */
#define	AUE_AUDITON_STERMID	140	/* =no auditctl(2): SETTERMID */
#define	AUE_AUDITON_GPOLICY	141	/* =aa auditctl(2): GETPOLICY */
#define	AUE_AUDITON_SPOLICY	142	/* =as auditctl(2): SETPOLICY */
#define	AUE_AUDITON_GESTATE	143	/* =no auditctl(2): GETESTATE */
#define	AUE_AUDITON_SESTATE	144	/* =no auditctl(2): SETESTATE */
#define	AUE_AUDITON_GQCTRL	145	/* =as auditctl(2): GETQCTRL */
#define	AUE_AUDITON_SQCTRL	146	/* =as auditctl(2): SETQCTRL */
/*				147	    OBSOLETE */
/*				148	    OBSOLETE */
/*				149	    OBSOLETE */
/*				150	    OBSOLETE */
/*				151	    OBSOLETE */
/*				152	    OBSOLETE */
#define	AUE_ENTERPROM		153	/* =na enter prom */
#define	AUE_EXITPROM		154	/* =na exit prom */
/*				155	    OBSOLETE */
/*				156	    OBSOLETE */
/*				157	    OBSOLETE */
#define	AUE_IOCTL		158	/* =io ioctl(2) */
/*				159	    OBSOLETE */
/*				160	    OBSOLETE */
/*				161	    OBSOLETE */
/*				162	    OBSOLETE */
/*				163	    OBSOLETE */
/*				164	    OBSOLETE */
/*				165	    OBSOLETE */
/*				166	    OBSOLETE */
/*				167	    OBSOLETE */
/*				168	    OBSOLETE */
/*				169	    OBSOLETE */
/*				170	    OBSOLETE */
/*				171	    OBSOLETE */
/*				172	    OBSOLETE */
#define	AUE_ONESIDE		173	/* =no one-sided session record */
#define	AUE_MSGGETL		174	/* =no msggetl(2) */
#define	AUE_MSGRCVL		175	/* =no msgrcvl(2) */
#define	AUE_MSGSNDL		176	/* =no msgsndl(2) */
#define	AUE_SEMGETL		177	/* =no semgetl(2) */
#define	AUE_SHMGETL		178	/* =no shmgetl(2) */
/*				179	    OBSOLETE */
/*				180	    OBSOLETE */
/*				181	    OBSOLETE */
/*				182	    OBSOLETE */
#define	AUE_SOCKET		183	/* =nt socket(2) */
#define	AUE_SENDTO		184	/* =nt sendto(2) */
#define	AUE_PIPE		185	/* =no pipe(2) */
#define	AUE_SOCKETPAIR		186	/* =no socketpair(2) */
#define	AUE_SEND		187	/* =no send(2) */
#define	AUE_SENDMSG		188	/* =nt sendmsg(2) */
#define	AUE_RECV		189	/* =no recv(2) */
#define	AUE_RECVMSG		190	/* =nt recvmsg(2) */
#define	AUE_RECVFROM		191	/* =nt recvfrom(2) */
#define	AUE_READ		192	/* =no read(2) */
#define	AUE_GETDENTS		193	/* =no getdents(2) */
#define	AUE_LSEEK		194	/* =no lseek(2) */
#define	AUE_WRITE		195	/* =no write(2) */
#define	AUE_WRITEV		196	/* =no writev(2) */
#define	AUE_NFS			197	/* =no NFS server */
#define	AUE_READV		198	/* =no readv(2) */
#define	AUE_OSTAT		199	/* =no obsolete */
#define	AUE_SETUID		200	/* =pm old setuid(2) */
#define	AUE_STIME		201	/* =as old stime(2) */
#define	AUE_UTIME		202	/* =no obsolete */
#define	AUE_NICE		203	/* =pm old nice(2) */
#define	AUE_OSETPGRP		204	/* =no old setpgrp(2) */
#define	AUE_SETGID		205	/* =pm old setgid(2) */
#define	AUE_READL		206	/* =no readl(2) */
#define	AUE_READVL		207	/* =no readvl(2) */
#define	AUE_FSTAT		208	/* =no fstat(2) */
#define	AUE_DUP2		209	/* =no obsolete */
#define	AUE_MMAP		210	/* =no mmap(2) u-o-p */
#define	AUE_AUDIT		211	/* =no audit(2) u-o-p */
#define	AUE_PRIOCNTLSYS		212	/* =pm priocntlsys */
#define	AUE_MUNMAP		213	/* =cl munmap(2) u-o-p */
#define	AUE_SETEGID		214	/* =pm setegid(2) */
#define	AUE_SETEUID		215	/* =pm seteuid(2) */
#define	AUE_PUTMSG		216	/* =nt */
#define	AUE_GETMSG		217	/* =nt */
#define	AUE_PUTPMSG		218	/* =nt */
#define	AUE_GETPMSG		219	/* =nt */
#define	AUE_AUDITSYS		220	/* =no place holder */
#define	AUE_AUDITON_GETKMASK	221	/* =aa */
#define	AUE_AUDITON_SETKMASK	222	/* =as */
#define	AUE_AUDITON_GETCWD	223	/* =aa,as */
#define	AUE_AUDITON_GETCAR	224	/* =aa,as */
#define	AUE_AUDITON_GETSTAT	225	/* =as */
#define	AUE_AUDITON_SETSTAT	226	/* =as */
#define	AUE_AUDITON_SETUMASK	227	/* =as */
#define	AUE_AUDITON_SETSMASK	228	/* =as */
#define	AUE_AUDITON_GETCOND	229	/* =aa */
#define	AUE_AUDITON_SETCOND	230	/* =as */
#define	AUE_AUDITON_GETCLASS	231	/* =aa,as */
#define	AUE_AUDITON_SETCLASS	232	/* =as */
#define	AUE_FUSERS		233	/* =fa */
#define	AUE_STATVFS		234	/* =fa */
#define	AUE_XSTAT		235	/* =no obsolete */
#define	AUE_LXSTAT		236	/* =no obsolete */
#define	AUE_LCHOWN		237	/* =fm */
#define	AUE_MEMCNTL		238	/* =ot */
#define	AUE_SYSINFO		239	/* =as */
#define	AUE_XMKNOD		240	/* =no obsolete */
#define	AUE_FORK1		241	/* =ps */
#define	AUE_MODCTL		242	/* =no */
#define	AUE_MODLOAD		243	/* =as */
#define	AUE_MODUNLOAD		244	/* =as */
#define	AUE_MODCONFIG		245	/* =no obsolete */
#define	AUE_MODADDMAJ		246	/* =as */
#define	AUE_SOCKACCEPT		247	/* =nt */
#define	AUE_SOCKCONNECT		248	/* =nt */
#define	AUE_SOCKSEND		249	/* =nt */
#define	AUE_SOCKRECEIVE		250	/* =nt */
#define	AUE_ACLSET		251	/* =fm */
#define	AUE_FACLSET		252	/* =fm */
#define	AUE_DOORFS		253	/* =no */
#define	AUE_DOORFS_DOOR_CALL	254	/* =ip */
#define	AUE_DOORFS_DOOR_RETURN	255	/* =ip */
#define	AUE_DOORFS_DOOR_CREATE	256	/* =ip */
#define	AUE_DOORFS_DOOR_REVOKE	257	/* =ip */
#define	AUE_DOORFS_DOOR_INFO	258	/* =ip */
#define	AUE_DOORFS_DOOR_CRED	259	/* =ip */
#define	AUE_DOORFS_DOOR_BIND	260	/* =ip */
#define	AUE_DOORFS_DOOR_UNBIND	261	/* =ip */
#define	AUE_P_ONLINE		262	/* =as */
#define	AUE_PROCESSOR_BIND	263	/* =as */
#define	AUE_INST_SYNC		264	/* =as */
#define	AUE_SOCKCONFIG		265	/* =nt */
#define	AUE_SETAUDIT_ADDR	266	/* =aa setaudit_addr(2) */
#define	AUE_GETAUDIT_ADDR	267	/* =aa getaudit_addr(2) */
#define	AUE_UMOUNT2		268	/* =as umount2(2) */
#define	AUE_FSAT		269	/* =no obsolete */
#define	AUE_OPENAT_R		270	/* =no obsolete */
#define	AUE_OPENAT_RC		271	/* =no obsolete */
#define	AUE_OPENAT_RT		272	/* =no obsolete */
#define	AUE_OPENAT_RTC		273	/* =no obsolete */
#define	AUE_OPENAT_W		274	/* =no obsolete */
#define	AUE_OPENAT_WC		275	/* =no obsolete */
#define	AUE_OPENAT_WT		276	/* =no obsolete */
#define	AUE_OPENAT_WTC		277	/* =no obsolete */
#define	AUE_OPENAT_RW		278	/* =no obsolete */
#define	AUE_OPENAT_RWC		279	/* =no obsolete */
#define	AUE_OPENAT_RWT		280	/* =no obsolete */
#define	AUE_OPENAT_RWTC		281	/* =no obsolete */
#define	AUE_RENAMEAT		282	/* =no obsolete */
#define	AUE_FSTATAT		283	/* =no obsolete */
#define	AUE_FCHOWNAT		284	/* =no obsolete */
#define	AUE_FUTIMESAT		285	/* =no obsolete */
#define	AUE_UNLINKAT		286	/* =no obsolete */
#define	AUE_CLOCK_SETTIME	287	/* =as clock_settime(3RT) */
#define	AUE_NTP_ADJTIME		288	/* =as ntp_adjtime(2) */
#define	AUE_SETPPRIV		289	/* =pm setppriv(2) */
#define	AUE_MODDEVPLCY		290	/* =as modctl(2) */
#define	AUE_MODADDPRIV		291	/* =as modctl(2) */
#define	AUE_CRYPTOADM		292	/* =as kernel cryptographic framework */
#define	AUE_CONFIGKSSL		293	/* =as kernel SSL */
#define	AUE_BRANDSYS		294	/* =ot */
#define	AUE_PF_POLICY_ADDRULE	295	/* =as Add IPsec policy rule */
#define	AUE_PF_POLICY_DELRULE	296	/* =as Delete IPsec policy rule */
#define	AUE_PF_POLICY_CLONE	297	/* =as Clone IPsec policy */
#define	AUE_PF_POLICY_FLIP	298	/* =as Flip IPsec policy */
#define	AUE_PF_POLICY_FLUSH	299	/* =as Flush IPsec policy rules */
#define	AUE_PF_POLICY_ALGS	300	/* =as Update IPsec algorithms */
#define	AUE_PORTFS		301	/* =no portfs(2) - place holder */
#define	AUE_LABELSYS_TNRH	302	/* =as tnrh(2) */
#define	AUE_LABELSYS_TNRHTP	303	/* =as tnrhtp(2) */
#define	AUE_LABELSYS_TNMLP	304	/* =as tnmlp(2) */
#define	AUE_PORTFS_ASSOCIATE	305	/* =fa portfs(2) - port associate */
#define	AUE_PORTFS_DISSOCIATE	306	/* =fa portfs(2) - port disassociate */
#define	AUE_SETSID		307	/* =pm setsid(2) */
#define	AUE_SETPGID		308	/* =pm setpgid(2) */
#define	AUE_FACCESSAT		309	/* =no obsolete */
#define	AUE_AUDITON_GETAMASK	310	/* =aa */
#define	AUE_AUDITON_SETAMASK	311	/* =as */
#define	AUE_PSECFLAGS		312	/* =pm psecflags */

/* NOTE: update MAX_KEVENTS below if events are added. */
#define	MAX_KEVENTS		312

#ifdef __cplusplus
}
#endif

#endif /* _BSM_AUDIT_KEVENTS_H */
