#!/bin/bash

DEVICES=`adb devices | tail -n +2 | cut -d $'\t' -f 1`

for i in $DEVICES;
do
    echo $i;
    adb -s $i install -rg $1
done
