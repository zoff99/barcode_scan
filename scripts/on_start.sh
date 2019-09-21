#! /bin/bash

# set led to steady light (yes its "none" on the pi zero!)
echo none | sudo tee /sys/class/leds/led0/trigger
