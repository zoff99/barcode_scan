#! /bin/bash

#*********************************
#
# barcode_scan - udev script to process usb drives
# (C)Zoff in 2019
#
# https://github.com/zoff99/barcode_scan
#
#
#*********************************


export usb_device="$1"
export mount_dir="/usb_device___/"
export dst_dir=$(dirname "$0")
export logfile="$dst_dir""/tox_usbmount.log"

touch /tmp/usb_stick.txt

sleep 2

touch "$logfile"
chmod a+rw "$logfile" 2> /dev/null # file owned by root (since this is an udev script)
chown pi:pi "$logfile" 2> /dev/null # file owned by root (since this is an udev script)

echo "UDEV-CALL:DRIVE:$2:$3" >> "$logfile"

if [ "$3""x" != "drivex" ]; then
    # only process usb-drives in this script
    exit 0
fi

if [ "$2""x" == "removex" ]; then
    # drive was removed - do nothing
    # just in case turn off the blinking red led
    echo none | sudo tee /sys/class/leds/led1/trigger
    bash "$dst_dir"/scripts/on_usb_remove.sh
    exit 0
elif [ "$2""x" == "addx" ]; then
    # drive inserted - start blinking the led
    echo heartbeat | sudo tee /sys/class/leds/led1/trigger
    bash "$dst_dir"/scripts/on_usb_insert.sh
fi


function import_data_phonebook_and_wlan
{
    usb_device_to_use="$1"

    if [ -e "$mount_dir""/""wlan_ssid.txt" ]; then

        wpa_net_country="AT" # TODO: also make this a parameter?
        wpa_net_id_rand=$(( ( RANDOM % 100000 )  + 1 ))

        ########-------------------------------------

        wpa_conf_file_location="/etc/wpa_supplicant/wpa_supplicant.conf"
        wpa_conf_file_mode="600"
        wpa_conf_file_content_001='country=@NETCOUNTRY@
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
network={
    ssid="'

        wpa_conf_file_content_002='"
    scan_ssid=1
    psk="'

        wpa_conf_file_content_003='"
    key_mgmt=WPA-PSK
    mode=0
    proto=WPA2
    pairwise=CCMP
    group=CCMP
    auth_alg=OPEN
    id_str="ToxPhone@RAND@"
    priority=1
}
'

        wpa_conf_file_content_openwlan='
network={
    key_mgmt=NONE
    priority=-999
}
'

        ########-------------------------------------

        rm -f "/tmp/abc.txt"

        rm -f "/tmp/abc001.txt"

        echo -n "$wpa_conf_file_content_001" \
          | sed -e 's#@NETCOUNTRY@#'"$wpa_net_country"'#' \
          > "/tmp/abc001.txt"

        chmod og-rwx "/tmp/abc001.txt"

        rm -f "/tmp/abc003.txt"

        echo -n "$wpa_conf_file_content_003" \
          | sed -e 's#@RAND@#'"$wpa_net_id_rand"'#' \
          > "/tmp/abc003.txt"

        chmod og-rwx "/tmp/abc003.txt"

        cat "/tmp/abc001.txt" > "/tmp/abc.txt"
        cat "$mount_dir""/""wlan_ssid.txt"|head -1|tr -d '\r'|tr -d '\n' >> "/tmp/abc.txt"
        echo -n "$wpa_conf_file_content_002" >> "/tmp/abc.txt"
        cat "$mount_dir""/""wlan_pass.txt"|head -1|tr -d '\r'|tr -d '\n' >> "/tmp/abc.txt"
        cat "/tmp/abc003.txt" >> "/tmp/abc.txt"

        rm -f "/tmp/abc001.txt" "/tmp/abc003.txt"

        if [ -e "$mount_dir""/""wlan_public.txt" ]; then
            echo "$wpa_conf_file_content_openwlan" >> "/tmp/abc.txt"
        fi

        chmod $wpa_conf_file_mode "/tmp/abc.txt"

        mv -v "/tmp/abc.txt" "$wpa_conf_file_location"
        rm -f "/tmp/abc.txt" # just to be safe

        wpa_action wlan0 reload
        systemctl restart ifup@wlan0.service

    fi

    return 0
}

function export_data_phonebook
{
    return 0
}

function export_data_toxid
{
    return 0
}

function export_data_pipa
{
    usb_device_to_use="$1"

    mkdir -p "$mount_dir""/""backup/"
    echo "backing up:PIPA" >> "$logfile"
    if [ -e /etc/pipa.txt ]; then
        cp -v "/etc/pipa.txt" "$mount_dir""/""backup/"pipa.txt >> "$logfile" 2>&1
        chmod a+r "$mount_dir""/""backup/"pipa.txt  >> "$logfile" 2>&1
    fi

    return 0
}

function export_data_toxsave
{
    usb_device_to_use="$1"

    mkdir -p "$mount_dir""/""backup/"
    echo "backing up:Data" >> "$logfile"
    cp -rv "$dst_dir""/db" "$mount_dir""/""backup/" >> "$logfile" 2>&1

    return 0
}

function check_if_paired_usb_device
{
    usb_device_to_use="$1"

    # check if we have already generated our secret hash
    if [ -e "$dst_dir""/""usb_auth_hash.txt" ]; then
        echo "USB AUTH HASH found .. OK" >> "$logfile"
        # check if there is a hash file on the USB device aswell
        if [ -e "$mount_dir""/""usb_auth_hash.txt" ]; then
            echo "USB AUTH HASH found on USB device .. OK" >> "$logfile"
            hash_file_size=$(stat --format="%s" "$dst_dir""/""usb_auth_hash.txt" 2>/dev/null|tr -d " " 2>/dev/null)
            if [ "$hash_file_size""x" == "129x" ]; then
                cmp "$dst_dir""/""usb_auth_hash.txt" "$mount_dir""/""usb_auth_hash.txt" >> "$logfile" 2>&1
                res2=$?
                if [ $res2 -eq 0 ]; then
                    echo "USB AUTH HASH equal to saved hash ... SUCCESS" >> "$logfile"
                    return 0
                else
                    echo "USB AUTH HASH does not match" >> "$logfile"
                fi
            else
                echo "USB AUTH HASH broken" >> "$logfile"
            fi
        fi
    fi

    return 1
}

function pair_usb_device
{
    usb_device_to_use="$1"

    # check if we have already generated our secret hash
    if [ -e "$dst_dir""/""usb_auth_hash.txt" ]; then
        echo "USB AUTH HASH already generated" >> "$logfile"
    else
        echo "generating USB AUTH HASH ..." >> "$logfile"
        hash_=$(dd if=/dev/urandom count=1024 bs=20 2>/dev/null | sha512sum -b - 2>/dev/null| cut -c1-128 2>/dev/null)
        hash_real_len_=$(echo "$hash_" 2>/dev/null|wc -c 2>/dev/null|tr -d " " 2>/dev/null)
        if [ "$hash_real_len_""x" == "129x" ]; then
            echo "writing USB AUTH HASH" >> "$logfile"
            echo "$hash_" > "$dst_dir""/""usb_auth_hash.txt"
            chmod a+rw "$dst_dir""/""usb_auth_hash.txt" # file owned by root (since this is an udev script)
            chown pi:pi "$dst_dir""/""usb_auth_hash.txt" # file owned by root (since this is an udev script)
            if [ ! -e "$mount_dir""/""usb_auth_hash.txt" ]; then
                cp -v "$dst_dir""/""usb_auth_hash.txt" "$mount_dir""/""usb_auth_hash.txt" >> "$logfile" 2>&1
                res1=$?
                if [ $res1 -ne 0 ]; then
                    echo "writing USB AUTH HASH error" >> "$logfile"
                    rm -f "$dst_dir""/""usb_auth_hash.txt" >> "$logfile" 2>&1
                else
                    echo "writing USB AUTH HASH ... SUCCESS" >> "$logfile"
                fi
            else
                echo "USB AUTH HASH already exists on USB device" >> "$logfile"
            fi
        else
            echo "USB AUTH HASH error len=$hash_real_len_" >> "$logfile"
        fi
    fi

    return 0
}

function import_data_name
{
}


function import_data_toxsave
{
}

#
#
#
#
#
#
#
#
## Main Program ------

usb_device_to_use="$usb_device""1"
rm -Rf "$mount_dir"/ >> "$logfile" 2>&1
mkdir -p "$mount_dir" >> "$logfile" 2>&1
echo "mounting $usb_device_to_use ..." >> "$logfile"
echo mount "$usb_device_to_use" "$mount_dir" >> "$logfile"
mount "$usb_device_to_use" "$mount_dir" >> "$logfile" 2>&1
res=$?

if [ $res -ne 0 ]; then
    echo "ERROR:mounting $usb_device_to_use" >> "$logfile"
    echo "UNmounting $usb_device_to_use ..." >> "$logfile"
    umount -f "$mount_dir" >> "$logfile" 2>&1
    echo umount -f "$usb_device_to_use" >> "$logfile"
    umount -f "$usb_device_to_use" >> "$logfile" 2>&1
    rm -Rf "$mount_dir"/ >> "$logfile" 2>&1
    exit 1
fi


# --------- PAIR USB DEVICE ---------
echo "pair usb device:$usb_device""1" >> "$logfile"
pair_usb_device "$usb_device""1"
# --------- PAIR USB DEVICE ---------

# --------- CHECK USB DEVICE PAIR HASH ---------
usb_is_paired=0
echo "check pair usb device:$usb_device""1" >> "$logfile"
check_if_paired_usb_device "$usb_device""1"
res=$?
if [ $res -ne 0 ]; then
    echo "++ USB Device NOT paired:""$usb_device""1"" ++" >> "$logfile"
else
    echo "** USB Device is paired:""$usb_device""1"" **" >> "$logfile"
    usb_is_paired=1
fi
# --------- CHECK USB DEVICE PAIR HASH ---------

# --------- EXPORT ---------

if [ "$usb_is_paired""x" == "1x" ]; then
    echo "export data phonebook:$usb_device""1" >> "$logfile"
    export_data_phonebook "$usb_device""1"

    echo "export data toxid:$usb_device""1" >> "$logfile"
    export_data_toxid "$usb_device""1"

    echo "export data toxsave:$usb_device""1" >> "$logfile"
    export_data_toxsave "$usb_device""1"

    echo "export data pipa:$usb_device""1" >> "$logfile"
    export_data_pipa "$usb_device""1"
fi
# --------- EXPORT ---------

# --------- IMPORT ---------
if [ "$usb_is_paired""x" == "1x" ]; then
    echo "import data phonebook and wlan:$usb_device""1" >> "$logfile"
    import_data_phonebook_and_wlan "$usb_device""1"

    echo "import data name:$usb_device""1" >> "$logfile"
    import_data_name "$usb_device""1"

    echo "import data toxsave:$usb_device""1" >> "$logfile"
    import_data_toxsave "$usb_device""1"
fi
# --------- IMPORT ---------

echo "UNmounting $usb_device_to_use ..." >> "$logfile"
umount -f "$mount_dir" >> "$logfile" 2>&1
echo umount -f "$usb_device_to_use" >> "$logfile"
umount -f "$usb_device_to_use" >> "$logfile" 2>&1
rm -Rf "$mount_dir"/ >> "$logfile" 2>&1


# turn off blinking red led
sleep 1
echo none | sudo tee /sys/class/leds/led1/trigger


