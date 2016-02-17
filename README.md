# iptdomain

The `iptdomain` utility is a blacklist based network traffic filter
for `iptables` via `libnetfilter-queue`.
It filters HTTP and SSL traffic based on targeted domain name, and
drops the "request" or "hello" packets for blacklisted domain names.

The domain database is built from a given collection of acl files
(access control list files), where each file is dealt with on a line
by line basis: each line that starts with a period is taken to hold a
domain name to block as its first token, with optional commentary text
following. The acl file format is ameniable to the
[Squidblacklist.org](http://squidblacklist.org) blacklists, which are
loadable without pre-processing.

## Dendencies

Operationally `iptdomain` depends on `iptables` and
`libnetfilter-queue-dev`. For building, you'll also need a C build
environment including `make`.

## Build and Install

`iptdomain` is built at top level using `make`.

    $ make

This will build the binary filter daemon int the bin directory.

You install by typing

    # make install

This installs the `iptdomain` daemon and its contrl script
`iptdomainctl` to `/usr/sbin`. It also sets up the configuration
directory `/etc/iptdomain` with the two sub directories `acl`
(intended for all available acl files), and `blocked` (intended for
enabled acl files).

## Setup and Confguration

The configuration directory `/etc/iptdomain` has a directory `acl`
that is intended to hold all available access control lists, and a
directory `blocked` that should be set up with links to the access
control list files to use. Example:

    # cd /etc/iptdomain/blocked
    # ln -s ../acl/youtube-google-videos.acl
    # ln -s ../acl/strictdomains.acl

That would set up `youtube-google-videos.acl` and `strictdomains.acl`
to be included blacklists.

Do the opposite to remove. Example:

    # cd /etc/iptdomain/blocked
	# rm blocked/youtube-google-videos.acl

## Running

The `iptdomain` is started with the following command:

    # iptdomainctl start

With the `start` argument, the script adds appropriate `iptables`
rules to direct tcp traffic to netfilter queue 99, and it starts the
`iptdomain` daemon as a background process for handling that queue.

    # iptdomainctl reload

With the `reload` argument, the control script stops and restarts the
daemon without changing `iptables` rules.

    # iptdomainctl stop

With the `stop` argument, the control script removes the `iptables`
rules and terminates the filtering daemon.

