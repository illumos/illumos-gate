lp64m="lp64 Lp64 LP64 lP64"
lp32m="lp32 Lp32 LP32 lP32"
ilp32m="ilp32 ilP32 iLp32 iLP32 Ilp32 IlP32 ILp32 ILP32"
for m in $lp64m $lp32m $ilp32m; do
	$MDB -e "::typedef -c $m"
	if [[ ! $? -eq 0 ]]; then
		echo "failed to create model $m" 2>&1
		exit 1
	fi
done
exit 0
