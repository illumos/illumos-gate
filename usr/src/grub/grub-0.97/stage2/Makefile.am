# For test target.
TESTS = size_test
noinst_SCRIPTS = $(TESTS)

# For dist target.
noinst_HEADERS = apic.h defs.h dir.h disk_inode.h disk_inode_ffs.h \
        fat.h filesys.h freebsd.h fs.h hercules.h i386-elf.h \
	imgact_aout.h iso9660.h jfs.h mb_header.h mb_info.h md5.h \
	nbi.h pc_slice.h serial.h shared.h smp-imps.h term.h \
	terminfo.h tparm.h nbi.h ufs.h ufs2.h vstafs.h xfs.h graphics.h \
	fsys_zfs.h
EXTRA_DIST = setjmp.S apm.S $(noinst_SCRIPTS)

# For <stage1.h>.
INCLUDES = -I$(top_srcdir)/stage1

# The library for /sbin/grub.
noinst_LIBRARIES = libgrub.a
libgrub_a_SOURCES = boot.c builtins.c char_io.c cmdline.c common.c \
	disk_io.c fsys_ext2fs.c fsys_fat.c fsys_ffs.c fsys_iso9660.c \
	fsys_jfs.c fsys_minix.c fsys_reiserfs.c fsys_ufs.c fsys_ufs2.c \
	fsys_zfs.c zfs_fletcher.c zfs_lzjb.c zfs_sha256.c \
	fsys_vstafs.c fsys_xfs.c gunzip.c md5.c serial.c stage2.c \
	terminfo.c tparm.c graphics.c
libgrub_a_CFLAGS = $(GRUB_CFLAGS) -I$(top_srcdir)/lib \
	-DGRUB_UTIL=1 -DFSYS_EXT2FS=1 -DFSYS_FAT=1 -DFSYS_FFS=1 \
	-DFSYS_ISO9660=1 -DFSYS_JFS=1 -DFSYS_MINIX=1 -DFSYS_REISERFS=1 \
	-DFSYS_UFS=1 -DFSYS_UFS2=1 -DFSYS_ZFS=1 -DFSYS_VSTAFS=1 -DFSYS_XFS=1 \
	-DUSE_MD5_PASSWORDS=1 -DSUPPORT_SERIAL=1 -DSUPPORT_HERCULES=1 \

# Stage 2 and Stage 1.5's.
pkglibdir = $(libdir)/$(PACKAGE)/$(host_cpu)-$(host_vendor)

EXTRA_PROGRAMS = nbloader.exec pxeloader.exec diskless.exec

if DISKLESS_SUPPORT
pkglib_DATA = stage2 stage2_eltorito e2fs_stage1_5 fat_stage1_5 \
	ffs_stage1_5 iso9660_stage1_5 jfs_stage1_5 minix_stage1_5 \
	reiserfs_stage1_5 ufs_stage1_5 ufs2_stage1_5 zfs_stage1_5 vstafs_stage1_5 \
	xfs_stage1_5 nbgrub pxegrub
noinst_DATA = pre_stage2 start start_eltorito nbloader pxeloader diskless
noinst_PROGRAMS = pre_stage2.exec start.exec start_eltorito.exec \
	e2fs_stage1_5.exec fat_stage1_5.exec ffs_stage1_5.exec \
	iso9660_stage1_5.exec jfs_stage1_5.exec minix_stage1_5.exec \
	reiserfs_stage1_5.exec ufs_stage1_5.exec ufs2_stage1_5.exec \
	zfs_stage1_5.exec \
	vstafs_stage1_5.exec xfs_stage1_5.exec \
	nbloader.exec pxeloader.exec diskless.exec
else
pkglib_DATA = stage2 stage2_eltorito e2fs_stage1_5 fat_stage1_5 \
	ffs_stage1_5 iso9660_stage1_5 jfs_stage1_5 minix_stage1_5 \
	reiserfs_stage1_5 ufs_stage1_5 ufs2_stage1_5 zfs_stage1_5 vstafs_stage1_5 \
	xfs_stage1_5
noinst_DATA = pre_stage2 start start_eltorito
noinst_PROGRAMS = pre_stage2.exec start.exec start_eltorito.exec \
	e2fs_stage1_5.exec fat_stage1_5.exec ffs_stage1_5.exec \
	iso9660_stage1_5.exec jfs_stage1_5.exec minix_stage1_5.exec \
	reiserfs_stage1_5.exec ufs_stage1_5.exec ufs2_stage1_5.exec \
	zfs_stage1_5.exec vstafs_stage1_5.exec xfs_stage1_5.exec
endif
MOSTLYCLEANFILES = $(noinst_PROGRAMS)

PRE_STAGE2_LINK = -nostdlib -Wl,-N -Wl,-Ttext -Wl,8200
START_LINK = -nostdlib -Wl,-N -Wl,-Ttext -Wl,8000
NBLOADER_LINK = -nostdlib -Wl,-N -Wl,-Ttext -Wl,0
PXELOADER_LINK = -nostdlib -Wl,-N -Wl,-Ttext -Wl,7C00
START_ELTORITO_LINK = -nostdlib -Wl,-N -Wl,-Ttext -Wl,7C00

if NETBOOT_SUPPORT
NETBOOT_FLAGS = -I$(top_srcdir)/netboot -DSUPPORT_NETBOOT=1
else
NETBOOT_FLAGS =
endif

if SERIAL_SUPPORT
SERIAL_FLAGS = -DSUPPORT_SERIAL=1
else
SERIAL_FLAGS =
endif

if HERCULES_SUPPORT
HERCULES_FLAGS = -DSUPPORT_HERCULES=1
else
HERCULES_FLAGS =
endif

if GRAPHICS_SUPPORT
GRAPHICS_FLAGS = -DSUPPORT_GRAPHICS=1
else
GRAPHICS_FLAGS =
endif

STAGE2_COMPILE = $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	$(NETBOOT_FLAGS) $(SERIAL_FLAGS) $(HERCULES_FLAGS) $(GRAPHICS_FLAGS)

STAGE1_5_LINK = -nostdlib -Wl,-N -Wl,-Ttext -Wl,2000
STAGE1_5_COMPILE = $(STAGE2_COMPILE) -DNO_DECOMPRESSION=1 -DSTAGE1_5=1

# For stage2 target.
pre_stage2_exec_SOURCES = asm.S bios.c boot.c builtins.c char_io.c \
	cmdline.c common.c console.c disk_io.c fsys_ext2fs.c \
	fsys_fat.c fsys_ffs.c fsys_iso9660.c fsys_jfs.c fsys_minix.c \
	fsys_reiserfs.c fsys_ufs.c fsys_ufs2.c fsys_vstafs.c fsys_xfs.c \
	fsys_zfs.c zfs_fletcher.c zfs_lzjb.c zfs_sha256.c \
	gunzip.c hercules.c md5.c serial.c smp-imps.c stage2.c terminfo.c \
	tparm.c graphics.c
pre_stage2_exec_CFLAGS = $(STAGE2_COMPILE) $(FSYS_CFLAGS)
pre_stage2_exec_CCASFLAGS = $(STAGE2_COMPILE) $(FSYS_CFLAGS)
pre_stage2_exec_LDFLAGS = $(PRE_STAGE2_LINK)

if NETBOOT_SUPPORT
pre_stage2_exec_LDADD = ../netboot/libdrivers.a
endif

if DISKLESS_SUPPORT
BUILT_SOURCES = stage2_size.h diskless_size.h
else
BUILT_SOURCES = stage2_size.h
endif

CLEANFILES = $(pkglib_DATA) $(noinst_DATA) $(BUILT_SOURCES)

stage2_size.h: pre_stage2
	-rm -f stage2_size.h
	set dummy `ls -l pre_stage2`; \
	echo "#define STAGE2_SIZE $$6" > stage2_size.h

start_exec_SOURCES = start.S
start_exec_CCASFLAGS = $(STAGE2_COMPILE)
start_exec_LDFLAGS = $(START_LINK)

# XXX: automake doesn't provide a way to specify dependencies for object
# files explicitly, so we must write this by a general Makefile scheme.
# If automake change the naming scheme for per-executable objects, this
# will be broken.
start_exec-start.$(OBJEXT): stage2_size.h

stage2: pre_stage2 start
	-rm -f stage2
	cat start pre_stage2 > stage2

start_eltorito_exec_SOURCES = start_eltorito.S
start_eltorito_exec_CCASFLAGS = $(STAGE2_COMPILE)
start_eltorito_exec_LDFLAGS = $(START_ELTORITO_LINK)

start_eltorito_exec-start.$(OBJEXT): stage2_size.h

stage2_eltorito: pre_stage2 start_eltorito
	-rm -f stage2_eltorito
	cat start_eltorito pre_stage2 > stage2_eltorito

# For e2fs_stage1_5 target.
e2fs_stage1_5_exec_SOURCES = start.S asm.S common.c char_io.c disk_io.c \
	stage1_5.c fsys_ext2fs.c bios.c
e2fs_stage1_5_exec_CFLAGS = $(STAGE1_5_COMPILE) -DFSYS_EXT2FS=1 \
	-DNO_BLOCK_FILES=1
e2fs_stage1_5_exec_CCASFLAGS = $(STAGE1_5_COMPILE) -DFSYS_EXT2FS=1 \
	-DNO_BLOCK_FILES=1
e2fs_stage1_5_exec_LDFLAGS = $(STAGE1_5_LINK)

# For fat_stage1_5 target.
fat_stage1_5_exec_SOURCES = start.S asm.S common.c char_io.c disk_io.c \
	stage1_5.c fsys_fat.c bios.c
fat_stage1_5_exec_CFLAGS = $(STAGE1_5_COMPILE) -DFSYS_FAT=1 \
	-DNO_BLOCK_FILES=1
fat_stage1_5_exec_CCASFLAGS = $(STAGE1_5_COMPILE) -DFSYS_FAT=1 \
	-DNO_BLOCK_FILES=1
fat_stage1_5_exec_LDFLAGS = $(STAGE1_5_LINK)

# For ffs_stage1_5 target.
ffs_stage1_5_exec_SOURCES = start.S asm.S common.c char_io.c disk_io.c \
	stage1_5.c fsys_ffs.c bios.c
ffs_stage1_5_exec_CFLAGS = $(STAGE1_5_COMPILE) -DFSYS_FFS=1 \
	-DNO_BLOCK_FILES=1
ffs_stage1_5_exec_CCASFLAGS = $(STAGE1_5_COMPILE) -DFSYS_FFS=1 \
	-DNO_BLOCK_FILES=1
ffs_stage1_5_exec_LDFLAGS = $(STAGE1_5_LINK)

# For ufs_stage1_5 target.
ufs_stage1_5_exec_SOURCES = start.S asm.S common.c char_io.c disk_io.c \
	stage1_5.c fsys_ufs.c bios.c
ufs_stage1_5_exec_CFLAGS = $(STAGE1_5_COMPILE) -DFSYS_UFS=1 \
	-DNO_BLOCK_FILES=1
ufs_stage1_5_exec_CCASFLAGS = $(STAGE1_5_COMPILE) -DFSYS_UFS=1 \
	-DNO_BLOCK_FILES=1
ufs_stage1_5_exec_LDFLAGS = $(STAGE1_5_LINK)

# For ufs2_stage1_5 target.
ufs2_stage1_5_exec_SOURCES = start.S asm.S common.c char_io.c disk_io.c \
	stage1_5.c fsys_ufs2.c bios.c
ufs2_stage1_5_exec_CFLAGS = $(STAGE1_5_COMPILE) -DFSYS_UFS2=1 \
	-DNO_BLOCK_FILES=1
ufs2_stage1_5_exec_CCASFLAGS = $(STAGE1_5_COMPILE) -DFSYS_UFS2=1 \
	-DNO_BLOCK_FILES=1
ufs2_stage1_5_exec_LDFLAGS = $(STAGE1_5_LINK)

# For zfs_stage1_5 target.
zfs_stage1_5_exec_SOURCES = start.S asm.S common.c char_io.c disk_io.c \
	stage1_5.c fsys_zfs.c zfs_fletcher.c zfs_lzjb.c zfs_sha256.c bios.c
zfs_stage1_5_exec_CFLAGS = $(STAGE1_5_COMPILE) -DFSYS_ZFS=1 \
	-DNO_BLOCK_FILES=1
zfs_stage1_5_exec_CCASFLAGS = $(STAGE1_5_COMPILE) -DFSYS_ZFS=1 \
	-DNO_BLOCK_FILES=1
zfs_stage1_5_exec_LDFLAGS = $(STAGE1_5_LINK)

# For minix_stage1_5 target.
minix_stage1_5_exec_SOURCES = start.S asm.S common.c char_io.c disk_io.c \
	stage1_5.c fsys_minix.c bios.c
minix_stage1_5_exec_CFLAGS = $(STAGE1_5_COMPILE) -DFSYS_MINIX=1 \
	-DNO_BLOCK_FILES=1
minix_stage1_5_exec_CCASFLAGS = $(STAGE1_5_COMPILE) -DFSYS_MINIX=1 \
	-DNO_BLOCK_FILES=1
minix_stage1_5_exec_LDFLAGS = $(STAGE1_5_LINK)

# For reiserfs_stage1_5 target.
reiserfs_stage1_5_exec_SOURCES = start.S asm.S common.c char_io.c \
	disk_io.c stage1_5.c fsys_reiserfs.c bios.c
reiserfs_stage1_5_exec_CFLAGS = $(STAGE1_5_COMPILE) -DFSYS_REISERFS=1 \
	-DNO_BLOCK_FILES=1
reiserfs_stage1_5_exec_CCASFLAGS = $(STAGE1_5_COMPILE) -DFSYS_REISERFS=1 \
	-DNO_BLOCK_FILES=1
reiserfs_stage1_5_exec_LDFLAGS = $(STAGE1_5_LINK)

# For vstafs_stage1_5 target.
vstafs_stage1_5_exec_SOURCES = start.S asm.S common.c char_io.c \
	disk_io.c stage1_5.c fsys_vstafs.c bios.c
vstafs_stage1_5_exec_CFLAGS = $(STAGE1_5_COMPILE) -DFSYS_VSTAFS=1 \
	-DNO_BLOCK_FILES=1
vstafs_stage1_5_exec_CCASFLAGS = $(STAGE1_5_COMPILE) -DFSYS_VSTAFS=1 \
	-DNO_BLOCK_FILES=1
vstafs_stage1_5_exec_LDFLAGS = $(STAGE1_5_LINK)

# For jfs_stage1_5 target.
jfs_stage1_5_exec_SOURCES = start.S asm.S common.c char_io.c \
	disk_io.c stage1_5.c fsys_jfs.c bios.c
jfs_stage1_5_exec_CFLAGS = $(STAGE1_5_COMPILE) -DFSYS_JFS=1 \
	-DNO_BLOCK_FILES=1
jfs_stage1_5_exec_CCASFLAGS = $(STAGE1_5_COMPILE) -DFSYS_JFS=1 \
	-DNO_BLOCK_FILES=1
jfs_stage1_5_exec_LDFLAGS = $(STAGE1_5_LINK)

# For xfs_stage1_5 target.
xfs_stage1_5_exec_SOURCES = start.S asm.S common.c char_io.c \
	disk_io.c stage1_5.c fsys_xfs.c bios.c
xfs_stage1_5_exec_CFLAGS = $(STAGE1_5_COMPILE) -DFSYS_XFS=1 \
	-DNO_BLOCK_FILES=1
xfs_stage1_5_exec_CCASFLAGS = $(STAGE1_5_COMPILE) -DFSYS_XFS=1 \
	-DNO_BLOCK_FILES=1
xfs_stage1_5_exec_LDFLAGS = $(STAGE1_5_LINK)

# For iso9660_stage1_5 target.
iso9660_stage1_5_exec_SOURCES = start_eltorito.S asm.S common.c char_io.c \
	disk_io.c stage1_5.c fsys_iso9660.c bios.c
iso9660_stage1_5_exec_CFLAGS = $(STAGE1_5_COMPILE) -DFSYS_ISO9660=1 \
	-DNO_BLOCK_FILES=1
iso9660_stage1_5_exec_CCASFLAGS = $(STAGE1_5_COMPILE) -DFSYS_ISO9660=1 \
	-DNO_BLOCK_FILES=1
iso9660_stage1_5_exec_LDFLAGS = $(STAGE1_5_LINK)

# For diskless target.
diskless_exec_SOURCES = $(pre_stage2_exec_SOURCES)
diskless_exec_CFLAGS = $(STAGE2_COMPILE) $(FSYS_CFLAGS) \
	-DSUPPORT_DISKLESS=1
diskless_exec_CCASFLAGS = $(STAGE2_COMPILE) $(FSYS_CFLAGS) \
	-DSUPPORT_DISKLESS=1
diskless_exec_LDFLAGS = $(PRE_STAGE2_LINK)
diskless_exec_LDADD = ../netboot/libdrivers.a

diskless_size.h: diskless
	-rm -f $@
	set dummy `ls -l $^`; \
	echo "#define DISKLESS_SIZE $$6" > $@

# For nbloader target.
nbloader_exec_SOURCES = nbloader.S
nbloader_exec_CCASFLAGS = $(STAGE2_COMPILE)
nbloader_exec_LDFLAGS = $(NBLOADER_LINK)

# XXX: See the comment for start_exec-start.o.
nbloader_exec-nbloader.$(OBJEXT): diskless_size.h

# For nbgrub target.
nbgrub: nbloader diskless
	-rm -f $@
	cat $^ > $@

# For pxeloader target.
pxeloader_exec_SOURCES = pxeloader.S
pxeloader_exec_CCASFLAGS = $(STAGE2_COMPILE)
pxeloader_exec_LDFLAGS = $(PXELOADER_LINK)

# XXX: See the comment for start_exec-start.o.
pxeloader_exec-pxeloader.$(OBJEXT): diskless_size.h

# For pxegrub target.
pxegrub: pxeloader diskless
	-rm -f $@
	cat $^ > $@

# General rule for making a raw binary.
SUFFIXES = .exec
.exec:
	$(OBJCOPY) -O binary $< $@
