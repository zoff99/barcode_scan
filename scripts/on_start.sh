#! /bin/bash

pi_model=$(tr -d '\0' </proc/device-tree/model)
echo $pi_model|grep 'Raspberry Pi Zero W' >/dev/null 2> /dev/null
pizero_w=$?
if [ $pizero_w == 0 ]; then

    # set led to steady light (yes its "none" on the pi zero!)
    echo none | sudo tee /sys/class/leds/led0/trigger
else
    # green
    echo default-on | sudo tee /sys/class/leds/led0/trigger
    # red
    echo none | sudo tee /sys/class/leds/led1/trigger

    # set GPIO for external LED
    echo "26" | sudo tee /sys/class/gpio/export
    echo "out" | sudo tee /sys/class/gpio/gpio26/direction
    echo "0" | sudo tee /sys/class/gpio/gpio26/value

fi
