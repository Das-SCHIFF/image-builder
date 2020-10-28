#!/usr/bin/env bash
declare -A ratios
declare -A freespace
declare -A units
declare -r DRY_RUN="${1}"
declare HIDDEN_PARTITION="${2}"
declare LVM_PARTITION="${3}"

# These are the Partitions on which LVM lives ensure that you first define the hidden one.
grow_partitions=("${HIDDEN_PARTITION:=/dev/sda2}" "${LVM_PARTITION:=/dev/sda5}")

ratios=( [lv_log]=0.1 [lv_var]=0.7 [lv_home]=0 [lv_root]=0.2 [lv_tmp]=0)  # should be 1 in total,
units=( [b]=0 [k]=0 [m]=1 [g]=1024 [t]="1024*1024" [p]="1024*1024*1024" [e]="1024*1024*1024*1024")
# freespace of byte and kilobyte will be completely ignored.


initial_ratio=0
for key in "${!ratios[@]}"
do
    echo "RUN:     lv   : $key"
    echo "RUN:     ratio: ${ratios[${key}]}"
    initial_ratio=$(awk -vn="${ratios[${key}]}" -vinitial="${initial_ratio}" "BEGIN{print(n+initial)}")
done
if [ "${initial_ratio}" != "1" ]; then
    echo "RUN:     Please make sure ratios sum up to 1 you currently have ${initial_ratio}."
    exit 1
fi


# Do Rescanning of all blockdevices
block_devices=$(ls /sys/class/block/ | grep -Ev "(sr|loop|fd|dm)")
for block_device in $block_devices
do
    if [ -f "/sys/class/block/${block_device}/device/rescan" ]; then
        echo "RUN:     Rescan the device ${block_device} into the kernel."
        if [ "${DRY_RUN}" == "true" ]; then
            echo "-------------------------------------------------------------------------"
            echo "DRY_RUN: INITIATE Rescan of ${block_device}"
            echo "DRY_RUN: echo 1 > /sys/class/block/${block_device}/device/rescan"
            echo "-------------------------------------------------------------------------"
        else
            echo "RUN:     INITIATE Rescan of ${block_device}"
            echo 1 > "/sys/class/block/${block_device}/device/rescan"
        fi
    fi
done

partprobe

for grow_partition in "${grow_partitions[@]}"
do
    block="${grow_partition::-1}"
    partition="${grow_partition: -1}"
    if [ "${DRY_RUN}" == "true" ]; then
        echo "-------------------------------------------------------------------------"
        echo "DRY_RUN: Resizing on SD=${block}, PARTITION=${partition}"
        echo "DRY_RUN: growpart ${block} ${partition}"
        echo "-------------------------------------------------------------------------" 
    else
        growpart "${block}" "${partition}"
    fi
done

lvm lvmdiskscan > /dev/null

pvs=$(lvm pvs | tail -n +2 | awk '{ print $1 }')
for pv in $pvs
do
    # Get the vg to expand
    vg=$(lvm pvs "${pv}" | tail -n +2 | awk '{ print $2 }')
    echo "RUN:     Found PV=${pv}, VG=${vg}"

    if [ "${DRY_RUN}" == "true" ]; then
        echo "-------------------------------------------------------------------------"
        echo "DRY_RUN: Resizing of PV=${pv} and Extension of VG=${vg}"
        echo "DRY_RUN: lvm pvresize ${pv}"
        echo "DRY_RUN: lvm vgextend ${vg} ${pv}"
        echo "-------------------------------------------------------------------------"
    else
        echo "RUN:     Resizing of PV=${pv} and Extension of VG=${vg}"
        lvm pvresize "${pv}"
        lvm vgextend "${vg}" "${pv}"
        retVal=$?
        if [ $retVal -eq 5 ]; then
            echo "RUN:     The PV ${pv} is already in VG ${vg}"
        fi
    fi
done

lvm lvmdiskscan > /dev/null

lvs=($(lvm lvs | tail -n +2 | awk '{ printf $1 " " $2 " " }'))
vgs=($(lvm vgs | tail -n +2 | awk '{ print $1 " " $7 " "}'))

# Get all the freespace.
for ((i=0; i<${#vgs[@]}; i+=2))
do
    vg=${vgs[i]}
    size=${vgs[i+1]}
    stripped_size=${size/,/.}
    freespace[${vg}]=${stripped_size}
    echo "RUN:     VG=${vg} SIZE=${size} CONVERTED_SIZE=${stripped_size}"
done

for ((i=0; i<${#lvs[@]}; i+=2))
do
    lv="${lvs[i]}"
    vg="${lvs[i+1]}"
    fullpath_lv=/dev/${vg}/${lv}
    echo "RUN:     Found LV=${fullpath_lv}"
    space_available="${freespace[${vg}]}"
    unit="${space_available: -1}"
    echo "RUN:     INITIAL_SPACE_AVAILABLE=${space_available} UNIT=${unit} on VG=${vg}"
    echo "RUN:     RATIO=${ratios[${lv}]:=0} LV=${lv}"
    calculated_space=$(awk -vn="${space_available::-1}" -vratio="${ratios[${lv}]:=0}" -vunit="${units[${unit}]}" 'BEGIN{printf("%.0f", n*ratio*unit)}')
    calculated_space_unit="+${calculated_space}m"
    if [ "${DRY_RUN}" == "true" ]; then
        echo "-------------------------------------------------------------------------"
        echo "DRY_RUN: Extending LV=${fullpath_lv} with ${calculated_space_unit} in VG=${vg}"
        echo "DRY_RUN: lvm lvextend --resizefs -L ${calculated_space_unit} ${fullpath_lv}"
        echo "-------------------------------------------------------------------------"
    else
        echo "RUN:     Extending LV=${fullpath_lv} with ${calculated_space_unit} in VG=${vg}"
        if [ "${calculated_space}" == "0" ]; then
            echo "RUN:     No Operation for LV=${lv} in VG=${vg}"
        else
            lvm lvextend --resizefs -L "${calculated_space_unit}" "${fullpath_lv}"
        fi
    fi
done
