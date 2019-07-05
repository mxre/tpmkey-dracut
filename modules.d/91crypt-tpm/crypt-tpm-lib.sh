#!/bin/sh

tpm_decrypt() {
    local mntp="$1"
    local keypath="$2"
    local keydev="$3"
    local device="$4"

    tpmkey "$mntp/$keypath" || return 1
}