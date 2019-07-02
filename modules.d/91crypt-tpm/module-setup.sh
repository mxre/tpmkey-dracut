#!/bin/sh

check() {
    if [[ -c /dev/tpm0 ]]; then
        return 255
    else
        return 1
    fi
}

depends() {
    echo crypt
}

installkernel() {
    instmods =drivers/char/tpm
}

install() {
    inst "$moddir/tpmkey" "/usr/bin/tpmkey"
    inst_script "$moddir/crypt-tpm-lib.sh" /lib/dracut-crypt-tpm-lib.sh
}
