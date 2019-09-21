#! /bin/bash

# set led to blinking
echo heartbeat | sudo tee /sys/class/leds/led1/trigger
