#!/bin/sh
# Запускать вручную: sudo ./capture.sh en0 data/capture.pcap 10000
set -eu
if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "Usage: $0 INTERFACE OUTPUT.pcap [PACKET_COUNT]" >&2
    exit 1
fi
if [ -e "$2" ]; then
    echo "Output already exists: $2" >&2
    exit 1
fi
# Нужен Ethernet-интерфейс. Ctrl+C тоже завершает запись корректно.
exec tcpdump -i "$1" -s 65535 -c "${3:-10000}" -w "$2"
