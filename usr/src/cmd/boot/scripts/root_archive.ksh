#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"

# utility to pack and unpack a boot/root archive
# both ufs and hsfs (iso9660) format archives are unpacked
# only ufs archives are generated
#
# usage: pack   <archive> <root>
#        unpack <archive> <root>
#        packmedia   <solaris_image> <root>
#        unpackmedia <solaris_image> <root>
#
#   Where <root> is the directory to unpack to and will be cleaned out
#   if it exists.
#
#   In the case of (un)packmedia, the image is packed or unpacked to/from
#   Solaris media and all the things that don't go into the ramdisk image
#   are (un)cpio'd as well
#
# This utility is also used to pack parts (in essence the window system,
# usr/dt and usr/openwin) of the non ramdisk SPARC
# miniroot. (un)packmedia will recognize that they are being run a SPARC
# miniroot and do the appropriate work.
#

usage()
{
	printf "usage: root_archive pack <archive> <root>\n"
	printf "       root_archive unpack <archive> <root>\n"
	printf "       root_archive packmedia   <solaris_image> <root>\n"
	printf "       root_archive unpackmedia <solaris_image> <root>\n"
}

cleanup()
{
	if [ -d $MNT ] ; then
		umount $MNT 2> /dev/null
		rmdir $MNT
	fi

	lofiadm -d "$TMR" 2>/dev/null
        if [ "$REALTHING" != true ] ; then
		rm -f "$TMR"
	fi
	rm -f "$TMR.gz"
}

preload_Gnome()
{
	MEDIA="$1"
	MINIROOT="$2"

	
	(
		# Prepopulate the gconf database. This needs to be done and
		# done first for several reasons. 1) Archiving out the gnome
		# libraries and binaries causes the gconftool-2 to not run
		# appropriately at boot time. 2) The binaries and libraries
		# needed to run this are big and thus we want to archive
		# them separately. 3) Having schemas prepopluated in the
		# miniroot means faster boot times.
		#

		cd "$MINIROOT"
		HOME="./tmp/root"
		export HOME
		umask 0022
		mumble=.tmp_proto/root/etc/gconf/gconf.xml.defaults
		GCONF_CONFIG_SOURCE="xml:merged:$MINIROOT/$mumble"
		export GCONF_CONFIG_SOURCE
		SCHEMADIR="$MINIROOT/.tmp_proto/root/etc/gconf/schemas"
		export SCHEMADIR
		/usr/bin/gconftool-2 --makefile-install-rule \
		    $SCHEMADIR/*.schemas >/dev/null 2>&1
		echo '
		xml:readwrite:/tmp/root/.gconf
		xml:readonly:/etc/gconf/gconf.xml.defaults
		' > /"$MINIROOT"/.tmp_proto/root/etc/gconf/2/path
	)
}

archive_Gnome()
{
	MEDIA="$1"
	MINIROOT="$2"

	RELEASE=`/bin/ls -d "$MEDIA/Solaris_"*`
	RELEASE=`basename "$RELEASE"`
	CPIO_DIR="$MEDIA/$RELEASE/Tools/Boot"

	# Create the gnome archive
	#
	(
		# usr/share gnome stuff
		cd "$MINIROOT"
		find usr/share/GConf usr/share/application-registry \
		    usr/share/autostart usr/share/dbus-1 usr/share/dtds \
		    usr/share/emacs usr/share/gnome usr/share/gnome-2.0 \
		    usr/share/gnome-background-properties \
		    usr/share/gtk-engines usr/share/gui-install \
		    usr/share/icon-naming-utils usr/share/control-center \
		    usr/share/icons usr/share/locale usr/share/metacity \
		    usr/share/mime usr/share/mime-info usr/share/pixmaps \
		    usr/share/scrollkeeper usr/share/sgml usr/share/themes \
		    usr/share/xml \
		    -print > /tmp/gnome_share.$$ 2>/dev/null

		if [ ! -f /tmp/gnome_share.$$ ] ; then
			echo "/tmp/gnome_share.$$ file list not found."
			return
		fi

		# usr/lib gnome stuff

		find usr/lib/libgnome*\.so\.* \
		    usr/lib/libgst*\.so\.* usr/lib/libgconf*\.so\.* \
		    usr/lib/libgdk*\.so\.* usr/lib/libgtk*\.so\.* \
		    usr/lib/libglade*\.so\.* usr/lib/libmetacity*\.so\.* \
		    usr/lib/libfontconfig*\.so\.* usr/lib/libgmodule*\.so\.* \
		    usr/lib/libgobject*\.so\.* usr/lib/libgthread*\.so\.* \
		    usr/lib/libpopt*\.so\.* usr/lib/libstartup*\.so\.* \
		    usr/lib/libexif*\.so\.* usr/lib/libtiff*\.so\.* \
		    usr/lib/libdbus*\.so\.* usr/lib/libstartup*\.so\.* \
		    usr/lib/libexif*\.so\.* usr/lib/libORBit*\.so\.* \
	 	    usr/lib/libmlib*\.so\.* usr/lib/libxsl*\.so\.* \
		    usr/lib/libpango*\.so\.* usr/lib/libpng*\.so\.* \
		    usr/lib/liboil*\.so\.* usr/lib/libbonobo*\.so\.* \
		    usr/lib/libart*\.so\.* usr/lib/libcairo*\.so\.* \
		    usr/lib/libjpeg*\.so\.* \
		    usr/lib/libpolkit*\.so\.* \
			-print | egrep -v '\.so\.[0]$' > \
		       /tmp/gnome_lib.$$ 2>/dev/null

		find usr/lib/nautilus usr/lib/pango usr/lib/iconv \
		    usr/lib/metacity-dialog usr/lib/window-manager-settings \
		    usr/lib/bonobo-2.0 usr/lib/bononbo usr/lib/gtk-2.0 \
		    usr/lib/GConf usr/lib/bonobo-activation-server \
		    usr/lib/python2.4 usr/lib/gstreamer-0.10 \
		    usr/lib/gconf-sanity-check-2 usr/lib/gconfd \
		    usr/lib/gnome-vfs-2.0 usr/lib/dbus-daemon \
		    usr/lib/gnome-vfs-daemon usr/lib/gnome-settings-daemon \
		    usr/lib/gnome_segv2 usr/lib/orbit-2.0 \
		    usr/lib/libmlib \
		    print > /tmp/gnome_libdir.$$ 2>/dev/null

		if [ ! -f /tmp/gnome_lib.$$  -a ! -f gnome_libdir.$$ ] ; then
			echo "/tmp/gnome_lib.$$ file list not found."
			return
		fi

		# /usr/sfw gnome stuff
		find usr/sfw/bin usr/sfw/include usr/sfw/share usr/sfw/src \
		    -print > /tmp/gnome_sfw.$$ 2>/dev/null

		if [ ! -f /tmp/gnome_sfw.$$ ] ; then
			echo "/tmp/gnome_sfw.$$ file list not found."
			return
		fi

		# gnome app binaries usr/bin
		find usr/bin/gnome* usr/bin/gui-install usr/bin/bonobo* \
		    usr/bin/gtk-* usr/bin/fax* usr/bin/gdk* usr/bin/gif2tiff \
		    usr/bin/install-lan \
		    usr/bin/metacity* usr/bin/gst-* usr/bin/gconftool-2 \
		    usr/bin/pango* usr/bin/desktop* usr/bin/djpeg \
		    usr/bin/notify-send usr/bin/oil-bugreport \
		    usr/bin/bmp2tiff usr/bin/thembus-theme-applier \
		    usr/bin/thumbnail usr/lib/update-* \
		    usr/bin/ras2tiff usr/bin/raw2tiff usr/bin/rdjpgcom \
		    usr/bin/thumbnail usr/bin/dbus* \
		    usr/bin/tiff* usr/bin/rgb2ycbcr \
		    usr/bin/fc-cache usr/bin/fc-list \
			-print > /tmp/gnome_bin.$$ 2>/dev/null

		if [ ! -f /tmp/gnome_bin.$$ ] ; then
			echo "/tmp/gnome_bin.$$ file list not found."
			return
		fi

		# Cat all the files together and create the gnome archive
		#

		cat /tmp/gnome_libdir.$$ /tmp/gnome_lib.$$ \
		     /tmp/gnome_share.$$ /tmp/gnome_sfw.$$ /tmp/gnome_bin.$$ \
		    > /tmp/gnome.$$

		if [ ! -f /tmp/gnome.$$ ] ; then
			echo "/tmp/gnome.$$ file not found."
			return
		fi
		# Save off this file in the miniroot for use later
		# when unpacking. Clean up old cruft if there.
		#

		if [ -f .tmp_proto/gnome_saved ]; then
			rm -f .tmp_proto/gnome_saved
		fi

		cp /tmp/gnome.$$ .tmp_proto/gnome_saved

		# Create gnome archive
		#

		cpio -ocmPuB < /tmp/gnome.$$ 2>/dev/null | bzip2 > \
		    "$CPIO_DIR/gnome.cpio.bz2"

		# Remove files from miniroot that are in archive.
		# Create symlinks for files in archive
		
		rm -rf `cat /tmp/gnome_share.$$`

		for i in `cat /tmp/gnome_share.$$`
		do
			ln -s /tmp/root/$i $i 2>/dev/null
		done

		rm -rf `cat /tmp/gnome_lib.$$`
		for i in `cat /tmp/gnome_lib.$$`
		do	
			ln -s /tmp/root/$i $i 2>/dev/null
		done

		rm -rf `cat /tmp/gnome_libdir.$$`
		for i in `cat /tmp/gnome_libdir.$$`
		do
			ln -s /tmp/root/$i $i 2>/dev/null
		done

		rm -rf `cat /tmp/gnome_sfw.$$`
		for i in `cat /tmp/gnome_sfw.$$`
		do
			ln -s /tmp/root/$i $i 2>/dev/null
		done

		rm -rf `cat /tmp/gnome_bin.$$`
		for i in `cat /tmp/gnome_bin.$$`
		do
			ln -s /tmp/root/$i $i 2>/dev/null
		done
		rm -f /tmp/gnome_share.$$
		rm -f /tmp/gnome_lib.$$
		rm -f /tmp/gnome_libdir.$$
		rm -f /tmp/gnome_bin.$$
	)
}

archive_JavaGUI()
{
	MEDIA="$1"
	MINIROOT="$2"

	RELEASE=`/bin/ls -d "$MEDIA/Solaris_"*`
	RELEASE=`basename "$RELEASE"`

	CPIO_DIR="$MEDIA/$RELEASE/Tools/Boot"
	
	# Archive the java wizard components that are only used in the
	# non developer express path.
	#
	(
		# path is usr/lib/install/data
		cd "$MINIROOT"
		find usr/lib/install/data/wizards \
		    -print > /tmp/java_ui.$$ 2>/dev/null

		if [ ! -f /tmp/java_ui.$$ ] ; then
			echo "/tmp/java_ui.$$ file list not found."
			return
		fi

		cpio -ocmPuB < /tmp/java_ui.$$ 2>/dev/null | bzip2 > \
		    "$CPIO_DIR/javaui.cpio.bz2"

		rm -rf `cat /tmp/java_ui.$$`
		ln -s /tmp/root/usr/lib/install/data/wizards \
		    usr/lib/install/data/wizards 2>/dev/null

		rm -f /tmp/java_ui.$$
	
	)
}

archive_Misc()
{
	MEDIA="$1"
	MINIROOT="$2"

	RELEASE=`/bin/ls -d "$MEDIA/Solaris_"*`
	RELEASE=`basename "$RELEASE"`

	CPIO_DIR="$MEDIA/$RELEASE/Tools/Boot"

	# Archive misc stuff that is needed by non devex installer
	#
	(
		# usr/lib stuff
		cd "$MINIROOT"
		find usr/lib/lp -print > /tmp/lp.$$ 2>/dev/null
		if [ ! -f /tmp/lp.$$ ] ; then
			echo "/tmp/lp.$$ file list not found."
			return
		fi

		cpio -ocmPuB < /tmp/lp.$$ 2>/dev/null | bzip2 > \
		    "$CPIO_DIR/lpmisc.cpio.bz2"

		rm -rf `cat /tmp/lp.$$`
		ln -s /tmp/root/usr/lib/lp usr/lib/lp 2>/dev/null
		
		rm -f /tmp/lp.$$
	)

}

archive_Perl()
{
	MEDIA="$1"
	MINIROOT="$2"

	RELEASE=`/bin/ls -d "$MEDIA/Solaris_"*`
	RELEASE=`basename "$RELEASE"`

	CPIO_DIR="$MEDIA/$RELEASE/Tools/Boot"

	# Archive perl, it is only needed by gnome gui.
	#
	(
		# in usr
		cd "$MINIROOT"
		find usr/perl5 -print > /tmp/perl.$$ 2>/dev/null

		if [ ! -f /tmp/perl.$$ ] ; then
			echo "/tmp/perl.$$ file list not found."
			return
		fi
		cpio -ocmPuB < /tmp/perl.$$ 2>/dev/null | bzip2 > \
		    "$CPIO_DIR/perl.cpio.bz2"

		rm -rf `cat /tmp/perl.$$` 2>/dev/null
		ln -s /tmp/root/usr/perl5 usr/perl5 2>/dev/null

		rm -f /tmp/perl.$$
	)
}
archive_X()
{
	MEDIA="$1"
	MINIROOT="$2"

	RELEASE=`/bin/ls -d "$MEDIA/Solaris_"*`
	RELEASE=`basename "$RELEASE"`

	CPIO_DIR="$MEDIA/$RELEASE/Tools/Boot"

	# create the graphics and non-graphics X archive
	#
	(
		cd "$MINIROOT"
		find usr/openwin usr/dt usr/X11 -print 2> /dev/null |\
		    cpio -ocmPuB 2> /dev/null | bzip2 > "$CPIO_DIR/X.cpio.bz2"

		find usr/openwin/bin/mkfontdir \
		     usr/openwin/lib/installalias \
		     usr/openwin/server/lib/libfont.so.1 \
		     usr/openwin/server/lib/libtypesclr.so.0 \
			 -print | cpio -ocmPuB 2> /dev/null | bzip2 > \
			 "$CPIO_DIR/X_small.cpio.bz2"

		rm -rf usr/dt usr/openwin usr/X11
		ln -s /tmp/root/usr/dt usr/dt
		ln -s /tmp/root/usr/openwin usr/openwin
		ln -s /tmp/root/usr/X11 usr/X11
	)
}

archive_lu()
{
	MEDIA="$1"
	MINIROOT="$2"

	RELEASE=`/bin/ls -d "$MEDIA/Solaris_"*`
	RELEASE=`basename "$RELEASE"`

	CPIO_DIR="$MEDIA/$RELEASE/Tools/Boot"

	(
		cd "$MINIROOT"
		find usr/lib/install usr/snadm usr/sbin | \
		    cpio -ocmPuB 2> /dev/null | bzip2 > "$CPIO_DIR"/lu.cpio.bz2
		ls platform > "$CPIO_DIR/lu.platforms"
	)
}

packmedia()
{
	MEDIA="$1"
	MINIROOT="$2"

	RELEASE=`/bin/ls -d "$MEDIA/Solaris_"*`
	RELEASE=`basename "$RELEASE"`
	ARCHIVES="X X_small perl lpmisc javaui gnome"

	mkdir -p "$MEDIA/$RELEASE/Tools/Boot"

	if [ -d "$MINIROOT/platform/i86pc" ] ; then
		mkdir -p "$MEDIA/boot/amd64"
		mkdir -p "$MEDIA/boot/platform/i86pc/kernel"
		mkdir -p "$MEDIA/boot/platform/i86pc/kernel/amd64"
		mkdir -p "$MEDIA/boot/platform/i86xpv/kernel"
		mkdir -p "$MEDIA/boot/platform/i86xpv/kernel/amd64"
		cp "$MINIROOT/platform/i86pc/multiboot" "$MEDIA/boot"
		cp "$MINIROOT/platform/i86pc/kernel/unix" \
		    "$MEDIA/boot/platform/i86pc/kernel/unix"
		cp "$MINIROOT/platform/i86pc/kernel/amd64/unix" \
		    "$MEDIA/boot/platform/i86pc/kernel/amd64/unix"
		cp "$MINIROOT/platform/i86xpv/kernel/unix" \
		    "$MEDIA/boot/platform/i86xpv/kernel/unix"
		cp "$MINIROOT/platform/i86xpv/kernel/amd64/unix" \
		    "$MEDIA/boot/platform/i86xpv/kernel/amd64/unix"
		(
			cd "$MEDIA/$RELEASE/Tools/Boot"
			ln -sf ../../../boot/x86.miniroot
			ln -sf ../../../boot/multiboot
			ln -sf ../../../boot/platform/i86pc/kernel/unix
			ln -sf ../../../boot/platform/i86pc/kernel/amd64/unix
			ln -sf ../../../boot/platform/i86xpv/kernel/unix
			ln -sf ../../../boot/platform/i86xpv/kernel/amd64/unix
			ln -sf ../../../boot/grub/pxegrub
		)
	fi

	if [ -d "$MINIROOT/platform/sun4u" ] ; then
		mkdir -p "$MEDIA/boot"
		dd if="$MINIROOT/platform/sun4u/lib/fs/hsfs/bootblk" \
		    of="$MEDIA/boot/hsfs.bootblock" \
		    bs=1b oseek=1 count=15 conv=sync 2> /dev/null
	fi

	for arch in sun4u sun4v ; do
		if [ -d "$MINIROOT/platform/$arch" ] ; then
			archdir="$MEDIA/$RELEASE/Tools/Boot/platform/$arch"
			mkdir -p $archdir
			ln -sf ../../../../../boot/sparc.miniroot \
			    "$archdir/boot_archive"
			cp "$MINIROOT/usr/platform/$arch/lib/fs/nfs/inetboot" \
			    "$archdir"
			cp "$MINIROOT/platform/$arch/wanboot" \
			    "$archdir"
			mkdir -p "$MEDIA/platform/$arch"
			ln -sf ../../boot/sparc.miniroot \
			    "$MEDIA/platform/$arch/boot_archive"
		fi
	done

	# archive package databases to conserve memory
	#
	(
		cd "$MINIROOT"
		find tmp/root/var/sadm/install tmp/root/var/sadm/pkg -print | \
		    cpio -ocmPuB 2> /dev/null | bzip2 > \
		    "$MEDIA/$RELEASE/Tools/Boot/pkg_db.cpio.bz2"
	)
	rm -rf "$MINIROOT/tmp/root/var/sadm/install"
	rm -rf "$MINIROOT/tmp/root/var/sadm/pkg"

	if [ -d "$MINIROOT/kernel/drv/sparcv9" ] ; then
		archive_lu "$MEDIA" "$MINIROOT"
	fi

	archive_X "$MEDIA" "$MINIROOT"

	# Take out the gnome and java parts of the installer from
	# the miniroot. These are not required to boot the system
	# and start the installers.

	if [ -d "$MINIROOT/platform/i86pc" ] ; then
		preload_Gnome "$MEDIA" "$MINIROOT"
		archive_Gnome "$MEDIA" "$MINIROOT"
		archive_JavaGUI "$MEDIA" "$MINIROOT"
		archive_Misc "$MEDIA" "$MINIROOT"
		archive_Perl "$MEDIA" "$MINIROOT"
		MR="$MEDIA/boot/amd64/x86.miniroot"
		pack

        	# Now that the 64-bit archives & miniroot have been created,
        	# restore the files from archives and save the 64-bit
        	# archives. Strip the 64-bit objects and create the
		# 32-bit archives and miniroot

		unpackmedia "$MEDIA" "$MINIROOT"
		mkdir -p "$MEDIA/$RELEASE/Tools/Boot/amd64"
		for i in $ARCHIVES; do
			mv "$MEDIA/$RELEASE/Tools/Boot/${i}.cpio.bz2" \
				"$MEDIA/$RELEASE/Tools/Boot/amd64"
		done
		if [ -z "$STRIP_AMD64" ]; then
			strip_amd64
		fi

		archive_X "$MEDIA" "$MINIROOT"
		archive_Gnome "$MEDIA" "$MINIROOT"
		archive_JavaGUI "$MEDIA" "$MINIROOT"
		archive_Perl "$MEDIA" "$MINIROOT"
		archive_Misc "$MEDIA" "$MINIROOT"
		MR="$MEDIA/boot/x86.miniroot"
	fi

	# copy the install menu to menu.lst so we have a menu
	# on the install media
	#
	if [ -f "$MINIROOT/boot/grub/install_menu" ] ; then
		cp $MINIROOT/boot/grub/install_menu \
		    $MEDIA/boot/grub/menu.lst
	fi
}

unarchive_X()
{
	MEDIA="$1"
	UNPACKED_ROOT="$2"

	RELEASE=`/bin/ls -d "$MEDIA/Solaris_"*`
	RELEASE=`basename "$RELEASE"`

	CPIO_DIR="$MEDIA/$RELEASE/Tools/Boot"

	# unpack X
	#
	(
		cd "$UNPACKED_ROOT"
		rm -rf usr/dt usr/openwin usr/X11
		bzcat "$CPIO_DIR/X.cpio.bz2" | cpio -icdmu 2> /dev/null
	)
}

unpackmedia()
{
	MEDIA="$1"
	UNPACKED_ROOT="$2"

	RELEASE=`/bin/ls -d "$MEDIA/Solaris_"*`
	RELEASE=`basename "$RELEASE"`

	unarchive_X "$MEDIA" "$UNPACKED_ROOT"

	# unpack package databases
	#
	(
		cd "$UNPACKED_ROOT"
		bzcat "$MEDIA/$RELEASE/Tools/Boot/pkg_db.cpio.bz2" |
		    cpio -icdmu 2> /dev/null

		# unpack gnome, perl, java and misc
		# Remove symlinks left from unpacking x86.miniroot so that
		# unpacking subsequent archives will populate appropriately.
		#
		rm -rf usr/perl5
		rm -rf usr/lib/install/data/wizards
		rm -rf usr/lib/lp

		# Gnome list saved off from packmedia
		for i in `cat .tmp_proto/gnome_saved`
		do
			rm -rf $i
		done
		
		bzcat "$MEDIA/$RELEASE/Tools/Boot/gnome.cpio.bz2" |
		    cpio -icdmu 2>/dev/null
		bzcat "$MEDIA/$RELEASE/Tools/Boot/javaui.cpio.bz2" |
		    cpio -icdmu 2>/dev/null
		bzcat "$MEDIA/$RELEASE/Tools/Boot/lpmisc.cpio.bz2" |
		    cpio -icdmu 2>/dev/null
		bzcat "$MEDIA/$RELEASE/Tools/Boot/perl.cpio.bz2" |
		    cpio -icdmu 2>/dev/null
	)
}

do_unpack()
{
	rm -rf "$UNPACKED_ROOT"
	mkdir -p "$UNPACKED_ROOT"
	(
		cd $MNT
		find . -print | cpio -pdum "$UNPACKED_ROOT" 2> /dev/null
	)
	umount $MNT
}

unpack()
{

	if [ ! -f "$MR" ] ; then
		usage
		exit 1
	fi

	if [ `basename $MR` = x86.miniroot ] ; then
		gzcat "$MR" > $TMR
	else
		REALTHING=true ; export REALTHING
		TMR="$MR"
	fi

	LOFIDEV=`/usr/sbin/lofiadm -a $TMR`
	if [ $? != 0 ] ; then
		echo lofi plumb failed
		exit 2
	fi

	mkdir -p $MNT

	FSTYP=`fstyp $LOFIDEV`

	if [ "$FSTYP" = ufs ] ; then
		/usr/sbin/mount -o ro,nologging $LOFIDEV $MNT
		do_unpack
	elif [ "$FSTYP" = hsfs ] ; then
		/usr/sbin/mount -F hsfs -o ro $LOFIDEV $MNT
		do_unpack
	else
		printf "invalid root archive\n"
	fi


	rmdir $MNT
	lofiadm -d $TMR ; LOFIDEV=
	if [ "$REALTHING" != true ] ; then
		rm $TMR
	fi
}

compress()
{
	SRC=$1
	DST=$2

	(
		cd $SRC
		filelist=`find .`

		for file in $filelist ; do

			file=`echo $file | sed s#^./##`

			# copy all files over to preserve hard links
			#
			echo $file | cpio -pdum $DST 2> /dev/null

			if [ -f $file ] && [ -s $file ] && [ ! -h $file ] ; then
				fiocompress -mc $file $DST/$file &
			fi

		done

		# now re-copy a couple of uncompressed files
		#

		find kernel platform -name unix | cpio -pdum $DST 2> /dev/null
		find kernel platform -name genunix | cpio -pdum $DST \
		    2> /dev/null
		find kernel platform -name platmod | cpio -pdum $DST \
		    2> /dev/null
		find `find kernel platform -name cpu` | cpio -pdum $DST \
		    2> /dev/null
		find `find kernel platform -name kmdb\*` | cpio -pdum $DST \
		    2> /dev/null
		find kernel/misc/sparcv9/ctf kernel/fs/sparcv9/dcfs \
		    etc/system etc/name_to_major etc/path_to_inst \
		    etc/name_to_sysnum | cpio -pdum $DST 2> /dev/null
	)
}

root_is_ramdisk()
{
	grep -v "set root_is_ramdisk=" "$UNPACKED_ROOT"/etc/system | \
	    grep -v "set ramdisk_size=" > /tmp/system.$$
	cat /tmp/system.$$ > "$UNPACKED_ROOT"/etc/system
	rm /tmp/system.$$

	echo set root_is_ramdisk=1 >> "$UNPACKED_ROOT"/etc/system
	echo set ramdisk_size=$1 >> "$UNPACKED_ROOT"/etc/system
}

pack()
{
	if [ ! -d "$UNPACKED_ROOT" -o -z "$MR" ] ; then
		usage
		exit 1
	fi

	# always compress on sparc if fiocompress exists
	#
	if [ -d "$UNPACKED_ROOT/kernel/drv/sparcv9" ] && \
	    [ -x /usr/sbin/fiocompress ] ; then
		COMPRESS=true
	fi

	# Estimate image size and add %10 overhead for ufs stuff.
	# Note, we can't use du here in case $UNPACKED_ROOT is on a filesystem,
	# e.g. zfs, in which the disk usage is less than the sum of the file
	# sizes.  The nawk code
	#
	#	{t += ($7 % 1024) ? (int($7 / 1024) + 1) * 1024 : $7}
	#
	# below rounds up the size of a file/directory, in bytes, to the
	# next multiple of 1024.  This mimics the behavior of ufs especially
	# with directories.  This results in a total size that's slightly
	# bigger than if du was called on a ufs directory.
	#
	# if the operation in turn is compressing the files the amount
	# of typical shrinkage is used to come up with a useful archive
	# size
	size=$(find "$UNPACKED_ROOT" -ls | nawk '
	    {t += ($7 % 1024) ? (int($7 / 1024) + 1) * 1024 : $7}
	    END {print int(t * 1.10 / 1024)}')
	if [ "$COMPRESS" = true ] ; then
		size=`echo $size | nawk '{s = $1} END {print int(s * .53)}'`
	fi

	/usr/sbin/mkfile ${size}k "$TMR"

	LOFIDEV=`/usr/sbin/lofiadm -a "$TMR"`
	if [ $? != 0 ] ; then
		echo lofi plumb failed
		exit 2
	fi

	RLOFIDEV=`echo $LOFIDEV | sed s/lofi/rlofi/`
	newfs $RLOFIDEV < /dev/null 2> /dev/null
	mkdir -p $MNT
	mount -o nologging $LOFIDEV $MNT
	rmdir $MNT/lost+found

	if [ -d "$UNPACKED_ROOT/kernel/drv/sparcv9" ] ; then
		root_is_ramdisk $size
	fi

	(
		cd "$UNPACKED_ROOT"
		if [ "$COMPRESS" = true ] ; then
			compress . $MNT
		else
			find . -print | cpio -pdum $MNT 2> /dev/null
		fi
	)
	lockfs -f $MNT
	umount $MNT
	rmdir $MNT

	if [ -d "$UNPACKED_ROOT/kernel/drv/sparcv9" ] ; then
		"$UNPACKED_ROOT/usr/sbin/installboot" \
		    "$UNPACKED_ROOT/platform/sun4u/lib/fs/ufs/bootblk" \
		    $RLOFIDEV
	fi

	lofiadm -d $LOFIDEV
	LOFIDEV=

	rm -f "$TMR.gz"

	if [ -d "$UNPACKED_ROOT/kernel/drv/sparcv9" ] ; then
		mv "$TMR" "$MR"
	else
		gzip -f "$TMR"
		mv "$TMR.gz" "$MR"
	fi

	chmod a+r "$MR"
}

strip_amd64()
{
	find "$UNPACKED_ROOT" -name amd64 -type directory | xargs rm -rf
}

# main
#

EXTRA_SPACE=0
STRIP_AMD64=
COMPRESS=

PATH=/usr/sbin:/usr/bin:/opt/sfw/bin ; export PATH

while getopts s:6c opt ; do
	case $opt in
	s)	EXTRA_SPACE="$OPTARG"
		;;
	6)	STRIP_AMD64=false
		;;
	c)	COMPRESS=true
		;;
	*)	usage
		exit 1
		;;
	esac
done
shift `expr $OPTIND - 1`

if [ $# != 3 ] ; then
	usage
	exit 1
fi

UNPACKED_ROOT="$3"
BASE="`pwd`"
MNT=/tmp/mnt$$
TMR=/tmp/mr$$
LOFIDEV=
MR="$2"

if [ "`dirname $MR`" = . ] ; then
	MR="$BASE/$MR"
fi
if [ "`dirname $UNPACKED_ROOT`" = . ] ; then
	UNPACKED_ROOT="$BASE/$UNPACKED_ROOT"
fi


MEDIA="$MR"

trap cleanup EXIT

case $1 in
	packmedia)
		if [ -d "$UNPACKED_ROOT/kernel/drv/sparcv9" ] ; then
			ARCHIVE=sparc.miniroot
		else
			ARCHIVE=x86.miniroot
		fi
		MR="$MEDIA/boot/$ARCHIVE"

		packmedia "$MEDIA" "$UNPACKED_ROOT"
		pack

		;;
	unpackmedia)
		if [ -f "$MEDIA/boot/sparc.miniroot" ] ; then
			ARCHIVE=sparc.miniroot
		else
			ARCHIVE=x86.miniroot
		fi
		MR="$MEDIA/boot/$ARCHIVE"
		unpack
		unpackmedia "$MEDIA" "$UNPACKED_ROOT"
		;;
	pack)	pack
		;;
	unpack)	unpack
		;;
	*)	usage
		;;
esac
