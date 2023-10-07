#!/bin/sh

version=`cat CMakeLists.txt | grep -E "set\(PKTMINERG_(MAJOR|MINOR|PATCH)_VERSION \"" | sed 's/"/ /g'| awk '{ver=ver".";(ver=ver""$2)}END{print substr(ver,2)}'`

sfile=netis-packet-agent-$version.Windows.AMD64.zip
dfile=$sfile

if [ $3 == "Yes" ]; then
  dfile=netis-packet-agent-$version.Windows.AMD64.`date +%Y%m%d%H%M`.zip
  cp -f build/_CPack_Packages/win64/ZIP/$sfile build/_CPack_Packages/win64/ZIP/$dfile
fi
echo "wget http://10.1.1.34/pktminerg/release/$dfile"
scp build/_CPack_Packages/win64/ZIP/$dfile root@$1:$2
