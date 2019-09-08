#! /bin/bash

#*********************************
#
# barcode_scan - loop script
# (C)Zoff in 2019
#
# https://github.com/zoff99/barcode_scan
#
#*********************************

function clean_up
{
	pkill scan_bar_codes
	sleep 2
	pkill -9 scan_bar_codes
	pkill -9 scan_bar_codes
	exit
}

cd $(dirname "$0")

# ---- only for RASPI ----
sudo sed -i -e 's#BLANK_TIME=.*#BLANK_TIME=0#' /etc/kbd/config
sudo sed -i -e 's#POWERDOWN_TIME=.*#POWERDOWN_TIME=0#' /etc/kbd/config
sudo setterm -blank 0 > /dev/null 2>&1
sudo setterm -powerdown 0 > /dev/null 2>&1

openvt -- sudo sh -c "/bin/chvt 1 >/dev/null 2>/dev/null"
sudo sh -c "TERM=linux setterm -blank 0 >/dev/tty0"
# ---- only for RASPI ----

trap clean_up SIGHUP SIGINT SIGTERM SIGKILL

chmod u+x scripts/*.sh
chmod u+x *.sh
chmod u+x scan_bar_codes

while [ 1 == 1 ]; do
    # just in case, so that udev scripts really really work
    sudo systemctl daemon-reload
    sudo systemctl restart systemd-udevd

	setterm -cursor off
    mkdir -p ./db/

    if [ -f "OPTION_USE_STDLOG" ]; then
        std_log=stdlog.log
    else
        std_log=/dev/null
    fi

    ulimit -c 99999
	./scan_bar_codes > "$std_log" 2>&1
    scripts/on_offline.sh
    #
    if [ -f "OPTION_USE_STDLOG" ]; then
        # save debug info ---------------
        mv ./scan_bar_codes.2 ./scan_bar_codes.3
        mv ./core.2 ./core.3
        mv ./stdlog.log.2 ./stdlog.log.3
        # -------------------------------
        mv ./scan_bar_codes.1 ./scan_bar_codes.2
        mv ./core.1 ./core.2
        mv ./stdlog.log.1 ./stdlog.log.2
        # -------------------------------
        cp ./scan_bar_codes ./scan_bar_codes.1
        mv ./core ./core.1
        mv ./stdlog.log ./stdlog.log.1
        # save debug info ---------------
    fi
    #
	sleep 4

    if [ -f "OPTION_NOLOOP" ]; then
        # do not loop/restart
        clean_up
        exit 1
    fi

done

