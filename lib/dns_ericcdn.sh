#!/usr/bin/env bash
# acme.sh dns hook. Provider secrets remain on EricServic.es Admin.
dns_ericcdn_add() { /usr/local/sbin/ericcdn-sync dns add "$1" "$2"; }
dns_ericcdn_rm() { /usr/local/sbin/ericcdn-sync dns remove "$1" "$2"; }
