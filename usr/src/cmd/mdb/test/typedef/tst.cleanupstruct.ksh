#
# One of the problems that we can encounter involves trying to typedef a struct
# that has an error in it. The problem here is that we actually create the type
# itself for the struct before we add members. So what we need is something that
# will fail validation. So here we go!
#

TMPFILE="/tmp/$(mktemp mtest.XXXXXX)"
if [[ -z "$TMPFILE" ]]; then
	echo "Failed to get a temp file" 2>&1
	exit 1
fi

$MDB <<EOF
::typedef "struct foo { int r; }" foo_t
::typedef -l ! cat > $TMPFILE
EOF

DATA=$(cat $TMPFILE)
rm -f $TMPFILE

[[ -z $DATA ]]
