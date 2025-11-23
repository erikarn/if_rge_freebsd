porting if_rge from openbsd to freebsd
--------------------------------------

Welcome!

This is adrian's port of if_rge from OpenBSD to FreeBSD.

Specifically from this commit:

```
commit 43364d4e1c2a13238d1fb7a792065fa1d8d34e65 (HEAD -> master, origin/master, origin/HEAD)
Author: afresh1 <afresh1@openbsd.org>
Date:   Sun Oct 26 22:44:53 2025 +0000

    Adjust disk partition regex based on kern.maxpartitions
```

The goal is to get this driver cleaned up enough to push into
FreeBSD-HEAD as an in-tree driver.

# How do I build it?

```
$ cd src
$ ./build clean all
```

# How do I load it?

```
 # kldload ./if_rge.ko
```

# What hardware is supported?

 * RTL8125
 * RTL8126
 * RTL8127
 * Killer E3000 NIC (RTL8125B)

# What features are supported ?

 * TX/RX IPv4 checksum offload (tested)
 * RX TCP/UDP checksum offload (tested)
 * VLAN tag offload (not yet tested)
 * Jumbo frames up to 9216 bytes (not yet tested)

# Who do I contact with questions?

Please contact Adrian Chadd at <adrian@FreeBSD.org>.
