#!/bin/bash -e

TMP_DIR=/tmp

help()
{
    echo "Usage: $0 [--no-compile|--amend] <filename>"
    echo "You must be at the base of the kernel tree to run this."
    exit 1
}

continue_yn()
{
    echo -n "Do you want to fix these issues now? "
    read ans
    if ! echo $ans | grep -iq ^n ; then
	exit 1;
    fi
}

qc()
{
    local msg=$1
    local ans

    echo -n "$msg:  "
    read ans
    if ! echo $ans | grep -qi ^y ; then
	exit 1
    fi
}

NO_COMPILE=false
AMEND=""

while true ; do
    if [[ "$1" == "--no-compile" ]] ; then
        NO_COMPILE=true
        shift
    elif [[ "$1" == "--amend" ]] ; then
        AMEND="--amend"
        shift
    else
        break
    fi
done

if [ ! -f $1 ] ; then
    help
fi

fullname=$1
filename=$(basename $fullname)
oname=$(echo ${fullname/.c/.o})

MSG_FILE=$TMP_DIR/${filename}.msg
MAIL_FILE=$TMP_DIR/${filename}.mail

# heat up the disk cache
#git log --oneline $fullname | head -n 10 > /dev/null &

echo "QC checklist"
qc "Have you handled all the errors properly?"
if git diff $fullname | grep ^+ | grep -qi alloc ; then
    qc "Have you freed all your mallocs?"
fi
if git diff $fullname | grep ^+ | grep -qi alloc ; then
    qc "Have you check all your mallocs for NULL returns?"
fi

if [ "$NO_COMPILE" != "true" ] ; then
    kchecker --spammy $fullname
    kchecker --sparse --endian $fullname
#    rm $oname
#    make C=1 CHECK="scripts/coccicheck" $oname
fi

for file in $(grep -l $fullname ~/var/mail/sent-*) ; do
    grepmail $fullname $file | grep -i ^subject || echo -n ""
done
qc "Looks OK?"

git add $fullname

cat /dev/null > $MSG_FILE
if [ "$AMEND" != "" ] ; then
    git format-patch HEAD^ --stdout >> $MSG_FILE
else
    echo "" >> $MSG_FILE
    echo "Signed-off-by: Dan Carpenter <dan.carpenter@oracle.com>" >> $MSG_FILE
    echo "" >> $MSG_FILE
    echo "# $sm_err" >> $MSG_FILE
fi
git log -10 --oneline $fullname | sed -e 's/^/# /' >> $MSG_FILE
vim $MSG_FILE

grep -v '^#' $MSG_FILE > $MSG_FILE.1
mv $MSG_FILE.1 $MSG_FILE

git commit $AMEND -F $MSG_FILE

git format-patch HEAD^ --stdout >> $MSG_FILE

to_addr=$(./scripts/get_maintainer.pl --noroles --norolestats $MSG_FILE | head -n 1)
cc_addr=$(./scripts/get_maintainer.pl --noroles --norolestats $MSG_FILE | tail -n +2 | \
    perl -ne 's/\n$/, /; print')
cc_addr="$cc_addr, kernel-janitors@vger.kernel.org"

echo -n "To:  "  > $MAIL_FILE
echo "$to_addr" >> $MAIL_FILE
echo -n "CC:  " >> $MAIL_FILE
echo "$cc_addr" >> $MAIL_FILE
echo "X-Mailer: git-send-email haha only kidding" >> $MAIL_FILE

git format-patch HEAD^ --stdout >> $MAIL_FILE

./scripts/checkpatch.pl $MAIL_FILE || continue_yn

echo "Press ENTER to continue"
read unused

mutt -H $MAIL_FILE
rm -f $MSG_FILE
