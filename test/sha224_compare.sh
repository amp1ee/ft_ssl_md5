#!/bin/bash

binary="./ft_ssl"
[ "x" != "x$1" ] && binary=$1

for f in test/efile*; do
	etalon=$(cat $f | sha224sum | awk '{print $1}')
	subj=$(${binary} sha224 -q -s "$(cat ${f})" )
	ret=$?
	if [ "$etalon" = "$subj" ]; then
		echo "${f}: $etalon -- OK"
	else
		if [ "$ret" -eq 139 ]; then subj="SegFault"; fi
		echo "${f}: $etalon -> $subj -- FAIL"
	fi
done
