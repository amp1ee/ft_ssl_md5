#!/bin/bash

for f in test/efile*; do
	etalon=$(cat $f | md5sum | awk '{print $1}')
	subj=$(./ft_ssl md5 -s "$(cat ${f})" )
	if [ "$etalon" = "$subj" ]; then
		echo "${f}: $etalon -- OK"
	else
		echo "${f}: $etalon -> $subj -- FAIL"
	fi
done
