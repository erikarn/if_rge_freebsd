/*	$OpenBSD: if_rge.c,v 1.38 2025/09/19 00:41:14 kevlo Exp $	*/

/*
 * Copyright (c) 2019, 2020, 2023-2025
 *	Kevin Lo <kevlo@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/endian.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_media.h>
#include <sys/queue.h>
#include <sys/taskqueue.h>
#include <sys/bus.h>
#include <sys/module.h>
#include <sys/rman.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/if_vlan_var.h>

#include <machine/bus.h>
#include <machine/resource.h>
//#include <machine/intr.h>

#include <dev/mii/mii.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>
//#include <dev/pci/pcidevs.h>

#include "if_rge_vendor.h"
#include "if_rgereg.h"
#include "if_rgevar.h"
#include "if_rge_microcode.h"
#include "if_rge_debug.h"
#include "if_rge_sysctl.h"

void
rge_sysctl_attach(struct rge_softc *sc)
{
	struct sysctl_ctx_list *ctx = device_get_sysctl_ctx(sc->sc_dev);
	struct sysctl_oid *tree = device_get_sysctl_tree(sc->sc_dev);

	SYSCTL_ADD_UINT(ctx, SYSCTL_CHILDREN(tree), OID_AUTO,
	    "debug", CTLFLAG_RW, &sc->sc_debug, 0,
	    "control debugging printfs");
}
