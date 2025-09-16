#!/bin/bash

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <ALGORITHM> <ZONE> <FILENAME>" >&2
    exit 1
fi

rm *.key
rm *.private

output_ZSK=$(dnssec-keygen -a $1 -n ZONE $2 2>&1)
output_KSK=$(dnssec-keygen -a $1 -n ZONE -f KSK $2 2>&1)

if [[ "$output_ZSK" == *"unknown algorithm"* ]]; then
    echo "Error: ZSK Algorithm not recognised!" >&2
elif [[ "$output_KSK" == *"another error"* ]]; then
    echo "Error: KSK Algorithm not recognised!" >&2
else
    dnssec-signzone -o $2 -N INCREMENT -t -S $3
    dnssec-verify -o $2 $3.signed
fi
