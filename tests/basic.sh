#!/bin/sh

set -e

_TCMD="/usr/bin/time"

linux_time()
{
  "${_TCMD}" -f "\t%e real\t%U user\t%s sys" "${@}"
}

if "${_TCMD}" -f "" echo 2>/dev/null >/dev/null
then
  TCMD="linux_time"
else
  TCMD="${_TCMD}"
fi
  
TCASE="basic_lowres"
TFNAME="${TCASE}.timings"
RESFILE="${TFNAME}"
CORRFILE="../tests/${TFNAME}"
PFILE="../tests/${TCASE}.pcap"

rm -f "${RESFILE}"
for speed in 0.095 0.255 0.502 0.75 0.997 1.0 1.245 1.506 1.753 1.899
do
  printf "%s replaying ${TCASE} @ speed (1 / ~%.2f)x...\n" "-" "${speed}"
  "${TCMD}" ./udpreplay -s ${speed} "${PFILE}" 2>&1 | \
   awk '{print $1}' | sed 's|[0-9]$||' >> "${RESFILE}" &
done
wait
diff -u "${CORRFILE}" "${RESFILE}"
echo "Looks good!"
