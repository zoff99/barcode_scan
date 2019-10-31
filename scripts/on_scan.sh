#! /bin/bash

# set blink external LED
echo "1" | sudo tee /sys/class/gpio/gpio26/value
sleep 0.3
echo "0" | sudo tee /sys/class/gpio/gpio26/value

