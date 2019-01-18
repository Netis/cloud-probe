
if "%1" == "" (
    set NIC=\Device\NPF_{BB09EECF-E0EB-4E5B-9EE8-0EBD558026FD}
) else (
    set NIC=%1
)
echo NIC: %NIC%

if "%2" == "nocompare" (
    set COMPARE=nocompare
) else (
    set COMPARE=compare
)
echo %COMPARE%

del gredump.pcap
del pktminer_dump.pcap

start ..\bin\gredump.exe -i %NIC% -o gredump.pcap
..\bin\pktminerg.exe -i %NIC% -r 172.16.14.249 -c 10 --dump

ping -n 1 127.0.0.1 > nul

rem taskkill /IM pktminerg.exe
taskkill /IM gredump.exe

ping -n 3 127.0.0.1 > nul

if "%COMPARE%" == "compare" (
    ..\bin\pcapcompare pktminer_dump.pcap gredump.pcap && exit 0
    exit -1
)

