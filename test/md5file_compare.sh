#!/bin/bash

binar="./ft_ssl"
[ "x" != "x$1" ] && binar="$1"

for i in {1..2000}; do
	f=test/efile${i}
	if [ ! -e ${f} ]; then continue; fi
	etalon=$(md5sum $f | awk '{print $1}')
	subj=$(${binar} md5 -q ${f} )
	if [ "$etalon" = "$subj" ]; then
		echo "${f}: $etalon -- OK"
	else
		echo "${f}: $etalon -> $subj -- FAIL"
	fi
done
