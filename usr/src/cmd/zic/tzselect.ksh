#! /usr/bin/ksh
#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# '@(#)tzselect.ksh	1.8'

# Ask the user about the time zone, and output the resulting TZ value to stdout.
# Interact with the user via stderr and stdin.

# Contributed by Paul Eggert

# Porting notes:
#
# This script requires several features of the Korn shell.
# If your host lacks the Korn shell,
# you can use either of the following free programs instead:
#
#	<a href=ftp://ftp.gnu.org/pub/gnu/>
#	Bourne-Again shell (bash)
#	</a>
#
#	<a href=ftp://ftp.cs.mun.ca/pub/pdksh/pdksh.tar.gz>
#	Public domain ksh
#	</a>
#
# This script also uses several features of modern awk programs.
# If your host lacks awk, or has an old awk that does not conform to POSIX.2,
# you can use either of the following free programs instead:
#
#	<a href=ftp://ftp.gnu.org/pub/gnu/>
#	GNU awk (gawk)
#	</a>
#
#	<a href=ftp://ftp.whidbey.net/pub/brennan/>
#	mawk
#	</a>

AWK=/usr/bin/nawk
GREP=/usr/bin/grep
EXPR=/usr/bin/expr
LOCALE=/usr/bin/locale
SORT=/usr/bin/sort
PRINTF=/usr/bin/printf
DATE=/usr/bin/date
GETTEXT=/usr/bin/gettext

TZDIR=/usr/share/lib/zoneinfo

# Messages
ERR_NO_SETUP="%s: time zone files are not set up correctly"
INFO_LOCATION="Please identify a location so that time zone rules \
can be set correctly."
INFO_SELECT_CONT="Please select a continent or ocean."
INFO_POSIX="none - I want to specify the time zone using the POSIX \
TZ format."
WARN_ENTER_NUM="Please enter a number in range."
INFO_ENTER_POSIX="Please enter the desired value of the TZ environment \
variable."
INFO_POSIX_EX="For example, GST-10 is a zone named GST that is 10 hours \
ahead (east) of UTC."
ERR_INV_POSIX="\`%s\' is not a conforming POSIX time zone string."
INFO_SELECT_CNTRY="Please select a country or region."
INFO_SELECT_TZ="Please select one of the following time zone regions."
INFO_EXTRA1="Local time is now:       %s"
INFO_EXTRA2="Universal Time is now:   %s"
INFO_INFO="The following information has been given:"
INFO_TZ="Therefore TZ='%s' will be used."
INFO_OK="Is the above information OK?"
INFO_YES="Yes"
INFO_NO="No"
WARN_ENTER_YORN="Please enter 1 for Yes, or 2 for No."
INFO_FINE="Here is the TZ value again, this time on standard output:"

# I18n support
TEXTDOMAINDIR=/usr/lib/locale; export TEXTDOMAINDIR
TEXTDOMAIN=SUNW_OST_OSCMD; export TEXTDOMAIN
DOMAIN2=SUNW_OST_ZONEINFO

# Make sure the tables are readable.
TZ_COUNTRY_TABLE=$TZDIR/tab/country.tab
TZ_ZONE_TABLE=$TZDIR/tab/zone_sun.tab
for f in $TZ_COUNTRY_TABLE $TZ_ZONE_TABLE
do
	<$f || {
		$PRINTF >&2 "`$GETTEXT "$ERR_NO_SETUP"`\n"  $0
		exit 1
	}
done

newline='
'
IFS=$newline

# For C locale, don't need to call gettext(1)
loc_messages=`$LOCALE | $GREP LC_MESSAGES | $AWK -F"=" '{print $2}`
if [ "$loc_messages" = "\"C\""  -o "$loc_messages" = "C" ]; then
	is_C=1
else
	is_C=0
fi

iafrica=`$GETTEXT $DOMAIN2 Africa`
iamerica=`$GETTEXT $DOMAIN2 Americas`
iantarctica=`$GETTEXT $DOMAIN2 Antarctica`
iarcticocean=`$GETTEXT $DOMAIN2 "Arctic Ocean"`
iasia=`$GETTEXT $DOMAIN2 Asia`
iatlanticocean=`$GETTEXT $DOMAIN2 "Atlantic Ocean"`
iaustralia=`$GETTEXT $DOMAIN2 Australia`
ieurope=`$GETTEXT $DOMAIN2 Europe`
ipacificocean=`$GETTEXT $DOMAIN2 "Pacific Ocean"`
iindianocean=`$GETTEXT $DOMAIN2 "Indian Ocean"`
none=`$GETTEXT "$INFO_POSIX"`

# Begin the main loop.  We come back here if the user wants to retry.
while
	$PRINTF >&2 "`$GETTEXT "$INFO_LOCATION"`\n"

	continent=
	country=
	region=

	# Ask the user for continent or ocean.
	$PRINTF >&2 "`$GETTEXT "$INFO_SELECT_CONT"`\n"

	select continent in \
	    $iafrica \
	    $iamerica \
	    $iantarctica \
	    $iarcticocean \
	    $iasia \
	    $iatlanticocean \
	    $iaustralia \
	    $ieurope \
	    $iindianocean \
	    $ipacificocean \
	    $none

	do
	    case $continent in
	    '')
		$PRINTF >&2 "`$GETTEXT "$WARN_ENTER_NUM"`\n";;

	    ?*)
		case $continent in
	    $iafrica) continent=Africa;;
	    $iamerica) continent=America;;
	    $iantarctica) continent=Antarctica;;
	    $iarcticocean) continent=Arctic;;
	    $iasia) continent=Asia;;
	    $iatlanticocean) continent=Atlantic;;
	    $iaustralia) continent=Australia;;
	    $ieurope) continent=Europe;;
	    $iindianocean) continent=Indian;;
	    $ipacificocean) continent=Pacific;;
	    $none) continent=none;;
		esac
		break
	    esac
	done
	case $continent in
	'')
		exit 1;;
	none)
		# Ask the user for a POSIX TZ string.  Check that it conforms.
		while
			$PRINTF >&2 "`$GETTEXT "$INFO_ENTER_POSIX"`\n"
			$PRINTF >&2 "`$GETTEXT "$INFO_POSIX_EX"`\n"

			read TZ
			env LC_ALL=C $AWK -v TZ="$TZ" 'BEGIN {
				tzname = "[^-+,0-9][^-+,0-9][^-+,0-9]+"
				time = "[0-2]?[0-9](:[0-5][0-9](:[0-5][0-9])?)?"
				offset = "[-+]?" time
				date = "(J?[0-9]+|M[0-9]+\.[0-9]+\.[0-9]+)"
				datetime = "," date "(/" time ")?"
				tzpattern = "^(:.*|" tzname offset "(" tzname \
				  "(" offset ")?(" datetime datetime ")?)?)$"
				if (TZ ~ tzpattern) exit 1
				exit 0
			}'
		do
			$PRINTF >&2 "`$GETTEXT "$ERR_INV_POSIX"`\n" $TZ

		done
		TZ_for_date=$TZ;;
	*)
		# Get list of names of countries in the continent or ocean.
		countries=$($AWK -F'\t' \
			-v continent="$continent" \
			-v TZ_COUNTRY_TABLE="$TZ_COUNTRY_TABLE" \
		'
			/^#/ { next }
			$3 ~ ("^" continent "/") {
				if (!cc_seen[$1]++) cc_list[++ccs] = $1
			}
			END {
				while (getline <TZ_COUNTRY_TABLE) {
					if ($0 !~ /^#/) cc_name[$1] = $2
				}
				for (i = 1; i <= ccs; i++) {
					country = cc_list[i]
					if (cc_name[country]) {
					  country = cc_name[country]
					}
					print country
				}
			}
		' <$TZ_ZONE_TABLE | $SORT -f)

		# i18n country names
		c=0
		set -A icountry
		for country in $countries
		do
			if [ $is_C -eq 1 ]; then
				icountry[c]=$country
			else
				icountry[c]=`${GETTEXT} ${DOMAIN2} $country`
			fi
			ocountry[c]="$country"
			c=$(( $c + 1 ))
		done
		maxnum=$c

		# If there's more than one country, ask the user which one.
		case $countries in
		*"$newline"*)
			$PRINTF >&2 "`$GETTEXT "$INFO_SELECT_CNTRY"`\n"
			select xcountry in ${icountry[*]}
			do
			    case $xcountry in
			    '')
				$PRINTF >&2 "`$GETTEXT "$WARN_ENTER_NUM"`\n"
				;;
			    ?*)   c=0
				  while true; do
                		    if [ "$xcountry" = "${icountry[$c]}" ];
				    then
					    country="${ocountry[$c]}"
                        		    break
                		    fi
                		    if [ $c -lt $maxnum ]; then
					    c=$(( $c + 1 ))
                		    else
                        		    break
                		    fi
        		         done
				 break
			     esac
			done

			case $xcountry in
			'') exit 1
			esac;;
		*)
			country=$countries
			xcountry=$countries
		esac


		# Get list of names of time zone rule regions in the country.
		regions=$($AWK -F'\t' \
			-v country="$country" \
			-v TZ_COUNTRY_TABLE="$TZ_COUNTRY_TABLE" \
		'
			BEGIN {
				cc = country
				while (getline <TZ_COUNTRY_TABLE) {
					if ($0 !~ /^#/  &&  country == $2) {
						cc = $1
						break
					}
				}
			}
			$1 == cc { print $5 }
		' <$TZ_ZONE_TABLE)

		# I18n region names
		c=0
		set -A iregion
		for region in $regions
		do
			if [ $is_C -eq 1 ]; then
				iregion[c]=$region
			else
				iregion[c]=`${GETTEXT} ${DOMAIN2} $region`
			fi
			oregion[c]="$region"
			c=$(( $c + 1 ))
		done
		maxnum=$c

		# If there's more than one region, ask the user which one.
		case $regions in
		*"$newline"*)
			$PRINTF >&2 "`$GETTEXT "$INFO_SELECT_TZ"`\n"

			select xregion in ${iregion[*]}
			do
				case $xregion in
				'') 
				$PRINTF >&2 "`$GETTEXT "$WARN_ENTER_NUM"`\n"
				;;
				?*) c=0
                                    while true; do
                                       if [ "$xregion" = "${iregion[$c]}" ];
				       then
                                            region="${oregion[$c]}"
                                            break
                                       fi
                                       if [ $c -lt $maxnum ]; then
					    c=$(( $c + 1 ))
                                       else
                                            break
                                       fi
                                    done
				    break
				esac
			done

			case $region in
			'') exit 1
			esac;;
		*)
			region=$regions
			xregion=$regions
		esac

		# Determine TZ from country and region.
		TZ=$($AWK -F'\t' \
			-v country="$country" \
			-v region="$region" \
			-v TZ_COUNTRY_TABLE="$TZ_COUNTRY_TABLE" \
		'
			BEGIN {
				cc = country
				while (getline <TZ_COUNTRY_TABLE) {
					if ($0 !~ /^#/  &&  country == $2) {
						cc = $1
						break
					}
				}
			}

			$1 == cc && $5 == region { 
				# Check if tzname mapped to 
				# backward compatible tzname
				if ($4 == "-") {
					print $3
				} else {
					print $4
				}
			}
		' <$TZ_ZONE_TABLE)

		# Make sure the corresponding zoneinfo file exists.
		TZ_for_date=$TZDIR/$TZ
		<$TZ_for_date || {
			$PRINTF >&2 "`$GETTEXT "$ERR_NO_SETUP"`\n" $0
			exit 1
		}
		# Absolute path TZ's not supported
		TZ_for_date=$TZ
	esac


	# Use the proposed TZ to output the current date relative to UTC.
	# Loop until they agree in seconds.
	# Give up after 8 unsuccessful tries.

	extra_info1=
	extra_info2=
	for i in 1 2 3 4 5 6 7 8
	do
		TZdate=$(LANG=C TZ="$TZ_for_date" $DATE)
		UTdate=$(LANG=C TZ=UTC0 $DATE)
		TZsec=$($EXPR "$TZdate" : '.*:\([0-5][0-9]\)')
		UTsec=$($EXPR "$UTdate" : '.*:\([0-5][0-9]\)')
		case $TZsec in
		$UTsec)
			extra_info1=$($PRINTF "`$GETTEXT "$INFO_EXTRA1"`" \
			"$TZdate")
			extra_info2=$($PRINTF "`$GETTEXT "$INFO_EXTRA2"`" \
			"$UTdate")
			break
		esac
	done


	# Output TZ info and ask the user to confirm.

	$PRINTF >&2 "\n"
	$PRINTF >&2 "`$GETTEXT "$INFO_INFO"`\n"
	$PRINTF >&2 "\n"

	case $country+$region in
	?*+?*)	$PRINTF >&2 "	$xcountry$newline	$xregion\n";;
	?*+)	$PRINTF >&2 "	$xcountry\n";;
	+)	$PRINTF >&2 "	TZ='$TZ'\n"
	esac
	$PRINTF >&2 "\n"
	$PRINTF >&2 "`$GETTEXT "$INFO_TZ"`\n" "$TZ"
	$PRINTF >&2 "$extra_info1\n"
	$PRINTF >&2 "$extra_info2\n"
	$PRINTF >&2 "`$GETTEXT "$INFO_OK"`\n"

	ok=
	# select ok in Yes No
	Yes="`$GETTEXT "$INFO_YES"`"
	No="`$GETTEXT "$INFO_NO"`"
	select ok in $Yes $No
	do
	    case $ok in
	    '') 
		$PRINTF >&2 "`$GETTEXT "$WARN_ENTER_YORN"`\n"
		;;
	    ?*) break
	    esac
	done
	case $ok in
	'') exit 1;;
	$Yes) break
	esac
do :
done

$PRINTF >&2 "`$GETTEXT "$INFO_FINE"`\n"

$PRINTF "%s\n" "$TZ"
