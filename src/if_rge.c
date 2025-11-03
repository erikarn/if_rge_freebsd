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
#include "if_rge_microcode.h"

#ifdef RGE_DEBUG
#define DPRINTF(x)	do { if (rge_debug > 0) printf x; } while (0)
int rge_debug = 0;
#else
#define DPRINTF(x)
#endif

static int		rge_attach(device_t);
static int		rge_detach(device_t);

#if 0
int		rge_activate(struct device *, int);
#endif
static void	rge_intr_msi(void *);
static int	rge_ioctl(struct ifnet *, u_long, caddr_t);
#if 0
void		rge_start(struct ifqueue *);
void		rge_watchdog(struct ifnet *);
#endif
static int	rge_transmit_if(if_t, struct mbuf *);
static void	rge_qflush_if(if_t);
static void	rge_init_if(void *);
static void	rge_init_locked(struct rge_softc *);
static void	rge_stop_locked(struct rge_softc *);
static int		rge_ifmedia_upd(if_t);
static void		rge_ifmedia_sts(if_t, struct ifmediareq *);
static int		rge_allocmem(struct rge_softc *);
static int		rge_freemem(struct rge_softc *);
static int		rge_newbuf(struct rge_queues *);
static void	rge_rx_list_init(struct rge_queues *);
static void	rge_tx_list_init(struct rge_queues *);
static void	rge_fill_rx_ring(struct rge_queues *);
static int	rge_rxeof(struct rge_queues *, struct mbufq *);
#if 0
int		rge_txeof(struct rge_queues *);
#endif
static int		rge_reset(struct rge_softc *);
static void		rge_iff_locked(struct rge_softc *);
static int		rge_chipinit(struct rge_softc *);
static void		rge_set_phy_power(struct rge_softc *, int);
static void		rge_ephy_config(struct rge_softc *);
static void		rge_ephy_config_mac_r25(struct rge_softc *);
static void		rge_ephy_config_mac_r25b(struct rge_softc *);
static void		rge_ephy_config_mac_r27(struct rge_softc *);
static void		rge_mac_config_mcu(struct rge_softc *, enum rge_mac_type);
static uint64_t	rge_mcu_get_bin_version(uint16_t);
static void		rge_mcu_set_version(struct rge_softc *, uint64_t);
static int		rge_phy_config(struct rge_softc *);
static void		rge_phy_config_mac_r27(struct rge_softc *);
static void		rge_phy_config_mac_r26(struct rge_softc *);
static void		rge_phy_config_mac_r25(struct rge_softc *);
static void		rge_phy_config_mac_r25b(struct rge_softc *);
static void		rge_phy_config_mac_r25d(struct rge_softc *);
static void		rge_phy_config_mcu(struct rge_softc *, uint16_t);
static void		rge_set_macaddr(struct rge_softc *, const uint8_t *);
static void		rge_get_macaddr(struct rge_softc *, uint8_t *);
static void		rge_hw_init(struct rge_softc *);
static void		rge_hw_reset(struct rge_softc *);
static void		rge_disable_phy_ocp_pwrsave(struct rge_softc *);
static void		rge_patch_phy_mcu(struct rge_softc *, int);
static void		rge_add_media_types(struct rge_softc *);
static void		rge_config_imtype(struct rge_softc *, int);
static void		rge_disable_aspm_clkreq(struct rge_softc *);
static void		rge_disable_hw_im(struct rge_softc *);
static void		rge_disable_sim_im(struct rge_softc *);
static void		rge_setup_sim_im(struct rge_softc *);
static void		rge_setup_intr(struct rge_softc *, int);
static void		rge_switch_mcu_ram_page(struct rge_softc *, int);
static int		rge_exit_oob(struct rge_softc *);
static void		rge_write_csi(struct rge_softc *, uint32_t, uint32_t);
static uint32_t	rge_read_csi(struct rge_softc *, uint32_t);
static void		rge_write_mac_ocp(struct rge_softc *, uint16_t, uint16_t);
static uint16_t	rge_read_mac_ocp(struct rge_softc *, uint16_t);
static void		rge_write_ephy(struct rge_softc *, uint16_t, uint16_t);
static uint16_t	rge_read_ephy(struct rge_softc *, uint16_t);
static uint16_t	rge_check_ephy_ext_add(struct rge_softc *, uint16_t);
static void		rge_r27_write_ephy(struct rge_softc *, uint16_t, uint16_t);
static void		rge_write_phy(struct rge_softc *, uint16_t, uint16_t, uint16_t);
static uint16_t	rge_read_phy(struct rge_softc *, uint16_t, uint16_t);
static void		rge_write_phy_ocp(struct rge_softc *, uint16_t, uint16_t);
static uint16_t	rge_read_phy_ocp(struct rge_softc *, uint16_t);
static int		rge_get_link_status(struct rge_softc *);
#if 0
void		rge_txstart(void *);
#endif
static void	rge_tick(void *);
static void	rge_link_state(struct rge_softc *);
#if 0
#ifndef SMALL_KERNEL
int		rge_wol(struct ifnet *, int);
void		rge_wol_power(struct rge_softc *);
#endif
#endif

static const struct {
	uint16_t reg;
	uint16_t val;
}  mac_r25_mcu[] = {
	MAC_R25_MCU
}, mac_r25b_mcu[] = {
	MAC_R25B_MCU
}, mac_r25d_mcu[] = {
	MAC_R25D_MCU
}, mac_r26_mcu[] = {
	MAC_R26_MCU
};

struct rge_matchid {
	uint16_t vendor;
	uint16_t device;
	const char *name;
};

const struct rge_matchid rge_devices[] = {
	{ PCI_VENDOR_REALTEK, PCI_PRODUCT_REALTEK_E3000, "Killer E3000" },
	{ PCI_VENDOR_REALTEK, PCI_PRODUCT_REALTEK_RTL8125, "RTL8125" },
	{ PCI_VENDOR_REALTEK, PCI_PRODUCT_REALTEK_RTL8126, "RTL8126", },
	{ PCI_VENDOR_REALTEK, PCI_PRODUCT_REALTEK_RTL8127, "RTL8127" },
	{ 0, 0, NULL }
};

static int
rge_probe(device_t dev)
{
	uint16_t vendor, device;
	const struct rge_matchid *ri;

	vendor = pci_get_vendor(dev);
	device = pci_get_device(dev);

	for (ri = rge_devices; ri->name != NULL; ri++) {
		if ((vendor == ri->vendor) && (device == ri->device)) {
			device_set_desc(dev, ri->name);
			return (BUS_PROBE_DEFAULT);
		}
	}

	return (ENXIO);
}

static void
rge_attach_if(struct rge_softc *sc, const char *eaddr)
{
	if_initname(sc->sc_ifp, device_get_name(sc->sc_dev),
	    device_get_unit(sc->sc_dev));
	if_setdev(sc->sc_ifp, sc->sc_dev);
	if_setinitfn(sc->sc_ifp, rge_init_if);
	if_setsoftc(sc->sc_ifp, sc);
	if_setflags(sc->sc_ifp, IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST);
	if_setioctlfn(sc->sc_ifp, rge_ioctl);
	if_settransmitfn(sc->sc_ifp, rge_transmit_if);
	if_setqflushfn(sc->sc_ifp, rge_qflush_if);
	if_setcapabilities(sc->sc_ifp, 0);
	if_setcapenable(sc->sc_ifp, 0);

	/* Attach interface */
	ether_ifattach(sc->sc_ifp, eaddr);
	sc->sc_ether_attached = true;

	/* TODO: set offload/TSO as appropriate */
	/* TODO: set jumbo tx/rx; max MTU */
	/* TODO: set WOL */
	/* TODO: set vlan as appropriate */

	if_setsendqlen(sc->sc_ifp, RGE_TX_LIST_CNT - 1);
	if_setsendqready(sc->sc_ifp);
}

static int
rge_attach(device_t dev)
{
	uint8_t eaddr[ETHER_ADDR_LEN];
	struct rge_softc *sc;
	struct rge_queues *q;
	uint32_t hwrev, reg;
	int i, rid;
	int error;
	int msic;

	sc = device_get_softc(dev);
	sc->sc_dev = dev;
	sc->sc_ifp = if_gethandle(IFT_ETHER);
	mtx_init(&sc->sc_mtx, device_get_nameunit(dev), MTX_NETWORK_LOCK,
	    MTX_DEF);

#if 0
	struct rge_softc *sc = (struct rge_softc *)self;
	struct pci_attach_args *pa = aux;
	pci_chipset_tag_t pc = pa->pa_pc;
	pci_intr_handle_t ih;
	const char *intrstr = NULL;
	struct ifnet *ifp;
	struct rge_queues *q;
	pcireg_t reg;
	uint32_t hwrev;
	uint8_t eaddr[ETHER_ADDR_LEN];
	int offset;

	pci_set_powerstate(pa->pa_pc, pa->pa_tag, PCI_PMCSR_STATE_D0);
#endif
	/* Enable bus mastering */
	pci_enable_busmaster(dev);

	/*
	 * Map control/status registers.
	 */

	/*
	 * The openbsd driver (and my E3000 NIC) handle registering three
	 * kinds of BARs - a 64 bit MMIO BAR, a 32 bit MMIO BAR, and then
	 * a legacy IO port BAR.
	 *
	 * To simplify bring-up, I'm going to request resources for the first
	 * MMIO BAR (BAR2) which should be a 32 bit BAR.
	 */
	rid = PCIR_BAR(2);
	sc->sc_bres = bus_alloc_resource_any(dev, SYS_RES_MEMORY, &rid,
	    RF_ACTIVE);
	if (sc->sc_bres == NULL) {
		device_printf(dev, "Unable to allocate bus resource: memory\n");
		goto fail;
	}
	sc->rge_bhandle = rman_get_bushandle(sc->sc_bres);
	sc->rge_btag = rman_get_bustag(sc->sc_bres);
	sc->rge_bsize = rman_get_size(sc->sc_bres);

#if 0
	if (pci_mapreg_map(pa, RGE_PCI_BAR2, PCI_MAPREG_TYPE_MEM |
	    PCI_MAPREG_MEM_TYPE_64BIT, 0, &sc->rge_btag, &sc->rge_bhandle,
	    NULL, &sc->rge_bsize, 0)) {
		if (pci_mapreg_map(pa, RGE_PCI_BAR1, PCI_MAPREG_TYPE_MEM |
		    PCI_MAPREG_MEM_TYPE_32BIT, 0, &sc->rge_btag,
		    &sc->rge_bhandle, NULL, &sc->rge_bsize, 0)) {
			if (pci_mapreg_map(pa, RGE_PCI_BAR0, PCI_MAPREG_TYPE_IO,
			    0, &sc->rge_btag, &sc->rge_bhandle, NULL,
			    &sc->rge_bsize, 0)) {
				printf(": can't map mem or i/o space\n");
				return;
			}
		}
	}
#endif

	q = malloc(sizeof(struct rge_queues), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (q == NULL) {
		device_printf(dev, "Unable to malloc rge_queues memory\n");
		goto fail;
	}
	q->q_sc = sc;
	q->q_index = 0;

	sc->sc_queues = q;
	sc->sc_nqueues = 1;

	/* Check if PCIe */
	if (pci_find_cap(dev, PCIY_EXPRESS, &reg) == 0) {
		sc->rge_flags |= RGE_FLAG_PCIE;
		sc->sc_expcap = reg;
	}

	/* Allocate MSI */
	msic = pci_msi_count(dev);
	if (msic == 0) {
		device_printf(sc->sc_dev, "%s: only MSI interrupts supported\n",
		    __func__);
		goto fail;
	}

	msic = RGE_MSI_MESSAGES;
	if (pci_alloc_msi(dev, &msic) != 0) {
		device_printf(sc->sc_dev, "%s: failed to allocate MSI\n",
		    __func__);
		goto fail;
	}

	sc->rge_flags |= RGE_FLAG_MSI;

	/* We need at least one MSI */
	if (msic < RGE_MSI_MESSAGES) {
		device_printf(sc->sc_dev, "%s: didn't allocate enough MSI\n",
		    __func__);
		goto fail;
	}

	/*
	 * Allocate interrupt entries.
	 */
	for (i = 0, rid = 1; i < RGE_MSI_MESSAGES; i++, rid++) {
		sc->sc_irq[i] = bus_alloc_resource_any(dev, SYS_RES_IRQ,
		    &rid, RF_ACTIVE);
		if (sc->sc_irq[i] == NULL) {
			device_printf(dev, "%s: couldn't allocate MSI %d",
			    __func__, rid);
			goto fail;
		}
	}

	/* Hook interrupts */
	for (i = 0; i < RGE_MSI_MESSAGES; i++) {
		error = bus_setup_intr(dev, sc->sc_irq[i],
		    INTR_TYPE_NET | INTR_MPSAFE, NULL, rge_intr_msi,
		    sc, &sc->sc_ih[i]);
	}

#if 0
	/*
	 * Allocate interrupt.
	 */
	if (pci_intr_map_msix(pa, 0, &ih) == 0 ||
	    pci_intr_map_msi(pa, &ih) == 0)
		sc->rge_flags |= RGE_FLAG_MSI;
	else if (pci_intr_map(pa, &ih) != 0) {
		printf(": couldn't map interrupt\n");
		return;
	}
	intrstr = pci_intr_string(pc, ih);
	sc->sc_ih = pci_intr_establish(pc, ih, IPL_NET | IPL_MPSAFE, rge_intr,
	    sc, sc->sc_dev.dv_xname);
	if (sc->sc_ih == NULL) {
		printf(": couldn't establish interrupt");
		if (intrstr != NULL)
			printf(" at %s", intrstr);
		printf("\n");
		return;
	}
	printf(": %s", intrstr);
#endif

#if 0
	sc->sc_dmat = pa->pa_dmat;
	sc->sc_pc = pa->pa_pc;
	sc->sc_tag = pa->pa_tag;
#endif

	/* Allocate top level bus DMA tag */
	error = bus_dma_tag_create(bus_get_dma_tag(dev), 1, 0,
	    BUS_SPACE_MAXADDR_32BIT, BUS_SPACE_MAXADDR, NULL,
	    NULL,
	    0x00ffffff, /* XXX maxsize */
	    64, /* XXX nsegments */
	    0x00ffffff, /* XXX maxsegsize */
	    BUS_DMA_ALLOCNOW, /* flags */
	    NULL, NULL, /* lockfunc, lockarg */
	    &sc->sc_dmat);
	if (error) {
		device_printf(dev,
		    "couldn't allocate device DMA tag (error %d)\n", error);
		    goto fail;
	}

	/* Allocate TX/RX descriptor and buffer tags */
	error = bus_dma_tag_create(sc->sc_dmat,
	    RGE_ALIGN, /* alignment */
	    0, /* boundary */
	    BUS_SPACE_MAXADDR_32BIT, BUS_SPACE_MAXADDR, NULL,
	    NULL,
	    0x3ffff, /* XXX maxsize */
	    64, /* XXX nsegments */
	    0x3ffff, /* XXX maxsegsize */
	    BUS_DMA_ALLOCNOW, /* flags */
	    NULL, NULL, /* lockfunc, lockarg */
	    &sc->sc_dmat_tx_desc);
	if (error) {
		device_printf(dev,
		    "couldn't allocate device TX descriptor DMA tag (error %d)\n", error);
		    goto fail;
	}

	error = bus_dma_tag_create(sc->sc_dmat,
	    1, /* alignment */
	    0, /* boundary */
	    BUS_SPACE_MAXADDR_32BIT, BUS_SPACE_MAXADDR, NULL,
	    NULL,
	    RGE_JUMBO_FRAMELEN, /* XXX maxsize */
	    RGE_TX_NSEGS, /* XXX nsegments */
	    RGE_JUMBO_FRAMELEN, /* XXX maxsegsize */
	    BUS_DMA_ALLOCNOW, /* flags */
	    NULL, NULL, /* lockfunc, lockarg */
	    &sc->sc_dmat_tx_buf);
	if (error) {
		device_printf(dev,
		    "couldn't allocate device TX buffer DMA tag (error %d)\n", error);
		    goto fail;
	}

	error = bus_dma_tag_create(sc->sc_dmat,
	    RGE_ALIGN, /* alignment */
	    0, /* boundary */
	    BUS_SPACE_MAXADDR_32BIT, BUS_SPACE_MAXADDR, NULL,
	    NULL,
	    0x3ffff, /* XXX maxsize */
	    64, /* XXX nsegments */
	    0x3ffff, /* XXX maxsegsize */
	    BUS_DMA_ALLOCNOW, /* flags */
	    NULL, NULL, /* lockfunc, lockarg */
	    &sc->sc_dmat_rx_desc);
	if (error) {
		device_printf(dev,
		    "couldn't allocate device RX descriptor DMA tag (error %d)\n", error);
		    goto fail;
	}

	error = bus_dma_tag_create(sc->sc_dmat,
	    1, /* alignment */
	    0, /* boundary */
	    BUS_SPACE_MAXADDR_32BIT, BUS_SPACE_MAXADDR, NULL,
	    NULL,
	    0x3ffff, /* XXX maxsize */
	    64, /* XXX nsegments */
	    0x3ffff, /* XXX maxsegsize */
	    BUS_DMA_ALLOCNOW, /* flags */
	    NULL, NULL, /* lockfunc, lockarg */
	    &sc->sc_dmat_rx_buf);
	if (error) {
		device_printf(dev,
		    "couldn't allocate device RX buffer DMA tag (error %d)\n", error);
		    goto fail;
	}


	/* Determine hardware revision */
	hwrev = RGE_READ_4(sc, RGE_TXCFG) & RGE_TXCFG_HWREV;
	switch (hwrev) {
	case 0x60900000:
		sc->rge_type = MAC_R25;
		device_printf(dev, "RTL8125\n");
		break;
	case 0x64100000:
		sc->rge_type = MAC_R25B;
		device_printf(dev, "RTL8125B\n");
		break;
	case 0x64900000:
		sc->rge_type = MAC_R26;
		device_printf(dev, "RTL8126\n");
		break;
	case 0x68800000:
		sc->rge_type = MAC_R25D;
		device_printf(dev, "RTL8125D\n");
		break;
	case 0x6c900000:
		sc->rge_type = MAC_R27;
		device_printf(dev, "RTL8127\n");
		break;
	default:
		device_printf(dev, "unknown version 0x%08x\n", hwrev);
		goto fail;
	}

	device_printf(dev, "HWREV: 0x%08x; rge_type=%d\n", hwrev, sc->rge_type);

	rge_config_imtype(sc, RGE_IMTYPE_SIM);

#if 0
	/*
	 * PCI Express check.
	 */
	if (pci_get_capability(pa->pa_pc, pa->pa_tag, PCI_CAP_PCIEXPRESS,
	    &offset, NULL)) {
		/* Disable PCIe ASPM and ECPM. */
		reg = pci_conf_read(pa->pa_pc, pa->pa_tag,
		    offset + PCI_PCIE_LCSR);
		reg &= ~(PCI_PCIE_LCSR_ASPM_L0S | PCI_PCIE_LCSR_ASPM_L1 |
		    PCI_PCIE_LCSR_ECPM);
		pci_conf_write(pa->pa_pc, pa->pa_tag, offset + PCI_PCIE_LCSR,
		    reg);
	}
#endif

	RGE_LOCK(sc);
	if (rge_chipinit(sc)) {
		RGE_UNLOCK(sc);
		goto fail;
	}

	rge_get_macaddr(sc, eaddr);
	RGE_UNLOCK(sc);

	device_printf(dev, "MAC address %6D\n", eaddr, ":");

#if 0
	memcpy(sc->sc_arpcom.ac_enaddr, eaddr, ETHER_ADDR_LEN);
#endif
	if (rge_allocmem(sc))
		goto fail;

	/* Initialize ifmedia structures. */
	ifmedia_init(&sc->sc_media, IFM_IMASK, rge_ifmedia_upd,
	    rge_ifmedia_sts);
	rge_add_media_types(sc);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_AUTO, 0, NULL);
	ifmedia_set(&sc->sc_media, IFM_ETHER | IFM_AUTO);
	sc->sc_media.ifm_media = sc->sc_media.ifm_cur->ifm_media;

	rge_attach_if(sc, eaddr);

#if 0
	ifp = &sc->sc_arpcom.ac_if;
	ifp->if_softc = sc;
	strlcpy(ifp->if_xname, sc->sc_dev.dv_xname, IFNAMSIZ);
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_xflags = IFXF_MPSAFE;
	ifp->if_ioctl = rge_ioctl;
	ifp->if_qstart = rge_start;
	ifp->if_watchdog = rge_watchdog;
	ifq_init_maxlen(&ifp->if_snd, RGE_TX_LIST_CNT - 1);
	ifp->if_hardmtu = RGE_JUMBO_MTU;

	ifp->if_capabilities = IFCAP_VLAN_MTU | IFCAP_CSUM_IPv4 |
	    IFCAP_CSUM_TCPv4 | IFCAP_CSUM_UDPv4;

#if NVLAN > 0
	ifp->if_capabilities |= IFCAP_VLAN_HWTAGGING;
#endif

#ifndef SMALL_KERNEL
	ifp->if_capabilities |= IFCAP_WOL;
	ifp->if_wol = rge_wol;
	rge_wol(ifp, 0);
#endif

#endif

#if 0
	task_set(&sc->sc_task, rge_txstart, sc);
#endif
	callout_init_mtx(&sc->sc_timeout, &sc->sc_mtx, 0);

#if 0
	/* Initialize ifmedia structures. */
	ifmedia_init(&sc->sc_media, IFM_IMASK, rge_ifmedia_upd,
	    rge_ifmedia_sts);
	rge_add_media_types(sc);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_AUTO, 0, NULL);
	ifmedia_set(&sc->sc_media, IFM_ETHER | IFM_AUTO);
	sc->sc_media.ifm_media = sc->sc_media.ifm_cur->ifm_media;
#endif

#if 0
	if_attach(ifp);
	ether_ifattach(ifp);
#endif
	return (0);
fail:
	rge_detach(dev);
	return (ENXIO);
}

static int
rge_detach(device_t dev)
{
	struct rge_softc *sc = device_get_softc(dev);
	int i, rid;

	/* TODO: global flag, detaching */

	/* TODO: stop/drain network interface */
	callout_drain(&sc->sc_timeout);

	RGE_LOCK(sc);
	callout_stop(&sc->sc_timeout);

	/* TODO: stop NIC */
	rge_stop_locked(sc);

	/* TODO: stop DMA */

	/* TODO: wait for completion */

	/* TODO: free pending TX mbufs */

	/* TODO: free RX mbuf ring */

	RGE_UNLOCK(sc);

	/* Free descriptor memory */
	device_printf(sc->sc_dev, "%s: freemem\n", __func__);
	rge_freemem(sc);

	if (sc->sc_ifp) {
		device_printf(sc->sc_dev, "%s: ifdetach/if_free\n", __func__);
		if (sc->sc_ether_attached)
			ether_ifdetach(sc->sc_ifp);
		if_free(sc->sc_ifp);
	}

	device_printf(sc->sc_dev, "%s: sc_dmat_tx_desc\n", __func__);
	if (sc->sc_dmat_tx_desc)
		bus_dma_tag_destroy(sc->sc_dmat_tx_desc);
	device_printf(sc->sc_dev, "%s: sc_dmat_tx_buf\n", __func__);
	if (sc->sc_dmat_tx_buf)
		bus_dma_tag_destroy(sc->sc_dmat_tx_buf);
	device_printf(sc->sc_dev, "%s: sc_dmat_rx_desc\n", __func__);
	if (sc->sc_dmat_rx_desc)
		bus_dma_tag_destroy(sc->sc_dmat_rx_desc);
	device_printf(sc->sc_dev, "%s: sc_dmat_rx_buf\n", __func__);
	if (sc->sc_dmat_rx_buf)
		bus_dma_tag_destroy(sc->sc_dmat_rx_buf);
	device_printf(sc->sc_dev, "%s: sc_dmat\n", __func__);
	if (sc->sc_dmat)
		bus_dma_tag_destroy(sc->sc_dmat);

	/* Teardown interrupts */
	for (i = 0; i < RGE_MSI_MESSAGES; i++) {
		if (sc->sc_ih[i] != NULL) {
			bus_teardown_intr(sc->sc_dev, sc->sc_irq[i],
			    sc->sc_ih[i]);
			sc->sc_ih[i] = NULL;
		}
	}

	/* Free interrupt resources */
	for (i = 0, rid = 1; i < RGE_MSI_MESSAGES; i++, rid++) {
		if (sc->sc_irq[i] != NULL) {
			bus_release_resource(sc->sc_dev, SYS_RES_IRQ,
			    rid, sc->sc_irq[i]);
			sc->sc_irq[i] = NULL;
		}
	}

	/* Free MSI allocation */
	if (sc->rge_flags & RGE_FLAG_MSI)
		pci_release_msi(dev);

	if (sc->sc_bres) {
		device_printf(sc->sc_dev, "%s: release mmio\n", __func__);
		bus_release_resource(dev, SYS_RES_MEMORY,
		    rman_get_rid(sc->sc_bres), sc->sc_bres);
		sc->sc_bres = NULL;
	}

	if (sc->sc_queues) {
		free(sc->sc_queues, M_DEVBUF);
		sc->sc_queues = NULL;
	}

	mtx_destroy(&sc->sc_mtx);

	return (0);
}

#if 0

int
rge_activate(struct device *self, int act)
{
#ifndef SMALL_KERNEL
	struct rge_softc *sc = (struct rge_softc *)self;
#endif

	switch (act) {
	case DVACT_POWERDOWN:
#ifndef SMALL_KERNEL
		rge_wol_power(sc);
#endif
		break;
	}
	return (0);
}
#endif

static void
rge_intr_msi(void *arg)
{
	struct mbufq rx_mq;
	struct mbuf *m;
	struct rge_softc *sc = arg;
	struct rge_queues *q = sc->sc_queues;
	uint32_t status;
	int claimed = 0, rv;

	/* TODO: counter */

	mbufq_init(&rx_mq, RGE_RX_LIST_CNT);

	if ((if_getdrvflags(sc->sc_ifp) & IFF_DRV_RUNNING) == 0)
		return;

	RGE_LOCK(sc);

	/* Disable interrupts. */
	RGE_WRITE_4(sc, RGE_IMR, 0);

	if (!(sc->rge_flags & RGE_FLAG_MSI)) {
		if ((RGE_READ_4(sc, RGE_ISR) & sc->rge_intrs) == 0)
			goto done;
	}

	status = RGE_READ_4(sc, RGE_ISR);
	if (status)
		RGE_WRITE_4(sc, RGE_ISR, status);

	if (status & RGE_ISR_PCS_TIMEOUT)
		claimed = 1;

	rv = 0;
	if (status & sc->rge_intrs) {

		(void) q;
		rv |= rge_rxeof(q, &rx_mq);
#if 0
		rv |= rge_txeof(q);
#endif

		if (status & RGE_ISR_SYSTEM_ERR) {
			/* XXX TODO: error log? count? */
			rge_init_locked(sc);
		}
		claimed = 1;
	}

	if (sc->rge_timerintr) {
		if (!rv) {
			/*
			 * Nothing needs to be processed, fallback
			 * to use TX/RX interrupts.
			 */
			rge_setup_intr(sc, RGE_IMTYPE_NONE);

			/*
			 * Recollect, mainly to avoid the possible
			 * race introduced by changing interrupt
			 * masks.
			 */
			rge_rxeof(q, &rx_mq);
#if 0
			rge_txeof(q);
#endif
		} else
			RGE_WRITE_4(sc, RGE_TIMERCNT, 1);
	} else if (rv) {
		/*
		 * Assume that using simulated interrupt moderation
		 * (hardware timer based) could reduce the interrupt
		 * rate.
		 */
		rge_setup_intr(sc, RGE_IMTYPE_SIM);
	}

	RGE_WRITE_4(sc, RGE_IMR, sc->rge_intrs);

done:
	RGE_UNLOCK(sc);

	/* Handle any RX frames, outside of the driver lock */
	while ((m = mbufq_dequeue(&rx_mq)) != NULL)
		if_input(sc->sc_ifp, m);

	(void) claimed;
}

#if 0
static inline void
rge_tx_list_sync(struct rge_softc *sc, struct rge_queues *q,
    unsigned int idx, unsigned int len, int ops)
{
	bus_dmamap_sync(sc->sc_dmat, q->q_tx.rge_tx_list_map,
	    idx * sizeof(struct rge_tx_desc), len * sizeof(struct rge_tx_desc),
	    ops);
}

static int
rge_encap(struct ifnet *ifp, struct rge_queues *q, struct mbuf *m, int idx)
{
	struct rge_softc *sc = q->q_sc;
	struct rge_tx_desc *d = NULL;
	struct rge_txq *txq;
	bus_dmamap_t txmap;
	uint32_t cmdsts, cflags = 0;
	int cur, error, i;
#if NBPFILTER > 0
	caddr_t if_bpf;
#endif

	txq = &q->q_tx.rge_txq[idx];
	txmap = txq->txq_dmamap;

	error = bus_dmamap_load_mbuf(sc->sc_dmat, txmap, m, BUS_DMA_NOWAIT);
	switch (error) {
	case 0:
		break;
	case EFBIG: /* mbuf chain is too fragmented */
		if (m_defrag(m, M_DONTWAIT) == 0 &&
		    bus_dmamap_load_mbuf(sc->sc_dmat, txmap, m,
		    BUS_DMA_NOWAIT) == 0)
			break;

		/* FALLTHROUGH */
	default:
		return (0);
	}

#if NBPFILTER > 0
	if_bpf = READ_ONCE(ifp->if_bpf);
	if (if_bpf)
		bpf_mtap_ether(if_bpf, m, BPF_DIRECTION_OUT);
#endif

	bus_dmamap_sync(sc->sc_dmat, txmap, 0, txmap->dm_mapsize,
	    BUS_DMASYNC_PREWRITE);

	/*
	 * Set RGE_TDEXTSTS_IPCSUM if any checksum offloading is requested.
	 * Otherwise, RGE_TDEXTSTS_TCPCSUM / RGE_TDEXTSTS_UDPCSUM does not
	 * take affect.
	 */
	if ((m->m_pkthdr.csum_flags &
	    (M_IPV4_CSUM_OUT | M_TCP_CSUM_OUT | M_UDP_CSUM_OUT)) != 0) {
		cflags |= RGE_TDEXTSTS_IPCSUM;
		if (m->m_pkthdr.csum_flags & M_TCP_CSUM_OUT)
			cflags |= RGE_TDEXTSTS_TCPCSUM;
		if (m->m_pkthdr.csum_flags & M_UDP_CSUM_OUT)
			cflags |= RGE_TDEXTSTS_UDPCSUM;
	}

	/* Set up hardware VLAN tagging. */
#if NVLAN > 0
	if (m->m_flags & M_VLANTAG)
		cflags |= swap16(m->m_pkthdr.ether_vtag) | RGE_TDEXTSTS_VTAG;
#endif

	cur = idx;
	for (i = 1; i < txmap->dm_nsegs; i++) {
		cur = RGE_NEXT_TX_DESC(cur);

		cmdsts = RGE_TDCMDSTS_OWN;
		cmdsts |= txmap->dm_segs[i].ds_len;

		if (cur == RGE_TX_LIST_CNT - 1)
			cmdsts |= RGE_TDCMDSTS_EOR;
		if (i == txmap->dm_nsegs - 1)
			cmdsts |= RGE_TDCMDSTS_EOF;

		d = &q->q_tx.rge_tx_list[cur];
		d->rge_cmdsts = htole32(cmdsts);
		d->rge_extsts = htole32(cflags);
		d->rge_addr = htole64(txmap->dm_segs[i].ds_addr);
	}

	/* Update info of TX queue and descriptors. */
	txq->txq_mbuf = m;
	txq->txq_descidx = cur;

	cmdsts = RGE_TDCMDSTS_SOF;
	cmdsts |= txmap->dm_segs[0].ds_len;

	if (idx == RGE_TX_LIST_CNT - 1)
		cmdsts |= RGE_TDCMDSTS_EOR;
	if (txmap->dm_nsegs == 1)
		cmdsts |= RGE_TDCMDSTS_EOF;

	d = &q->q_tx.rge_tx_list[idx];
	d->rge_cmdsts = htole32(cmdsts);
	d->rge_extsts = htole32(cflags);
	d->rge_addr = htole64(txmap->dm_segs[0].ds_addr);

	if (cur >= idx) {
		rge_tx_list_sync(sc, q, idx, txmap->dm_nsegs,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
	} else {
		rge_tx_list_sync(sc, q, idx, RGE_TX_LIST_CNT - idx,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
		rge_tx_list_sync(sc, q, 0, cur + 1,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
	}

	/* Transfer ownership of packet to the chip. */
	cmdsts |= RGE_TDCMDSTS_OWN;
	rge_tx_list_sync(sc, q, idx, 1, BUS_DMASYNC_POSTWRITE);
	d->rge_cmdsts = htole32(cmdsts);
	rge_tx_list_sync(sc, q, idx, 1, BUS_DMASYNC_PREWRITE);

	return (txmap->dm_nsegs);
}
#endif

static int
rge_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct rge_softc *sc = if_getsoftc(ifp);
	struct ifreq *ifr = (struct ifreq *)data;
	int error = 0;

	switch (cmd) {
	/* TODO:SIOCSIFMTU */
	case SIOCSIFFLAGS:
		RGE_LOCK(sc);
		if ((if_getflags(ifp) & IFF_UP) != 0) {
			if ((if_getdrvflags(ifp) & IFF_DRV_RUNNING) == 0) {
				/*
				 * TODO: handle promisc/iffmulti changing
				 * without reprogramming everything.
				 */
				rge_init_locked(sc);
			} else {
				/* Reinit promisc/multi just in case */
				rge_iff_locked(sc);
			}
		} else {
			if ((if_getdrvflags(ifp) & IFF_DRV_RUNNING) != 0) {
				rge_stop_locked(sc);
			}
		}
		RGE_UNLOCK(sc);
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		RGE_LOCK(sc);
		if ((if_getflags(ifp) & IFF_DRV_RUNNING) != 0) {
			rge_iff_locked(sc);
		}
		RGE_UNLOCK(sc);
		break;
	case SIOCGIFMEDIA:
	case SIOCSIFMEDIA:
		error = ifmedia_ioctl(ifp, ifr, &sc->sc_media, cmd);
		break;
	/* TODO: SIOCSIFCAP */
	default:
		error = ether_ioctl(ifp, cmd, data);
		break;
	}

	return (error);
}

#if 0
void
rge_start(struct ifqueue *ifq)
{
	struct ifnet *ifp = ifq->ifq_if;
	struct rge_softc *sc = ifp->if_softc;
	struct rge_queues *q = sc->sc_queues;
	struct mbuf *m;
	int free, idx, used;
	int queued = 0;

	if (!LINK_STATE_IS_UP(ifp->if_link_state)) {
		ifq_purge(ifq);
		return;
	}

	/* Calculate free space. */
	idx = q->q_tx.rge_txq_prodidx;
	free = q->q_tx.rge_txq_considx;
	if (free <= idx)
		free += RGE_TX_LIST_CNT;
	free -= idx;

	for (;;) {
		if (free < RGE_TX_NSEGS + 2) {
			ifq_set_oactive(&ifp->if_snd);
			break;
		}

		m = ifq_dequeue(ifq);
		if (m == NULL)
			break;

		used = rge_encap(ifp, q, m, idx);
		if (used == 0) {
			m_freem(m);
			continue;
		}

		KASSERT(used < free);
		free -= used;

		idx += used;
		if (idx >= RGE_TX_LIST_CNT)
			idx -= RGE_TX_LIST_CNT;

		queued++;
	}

	if (queued == 0)
		return;

	/* Set a timeout in case the chip goes out to lunch. */
	ifp->if_timer = 5;

	q->q_tx.rge_txq_prodidx = idx;
	ifq_serialize(ifq, &sc->sc_task);
}

void
rge_watchdog(struct ifnet *ifp)
{
	struct rge_softc *sc = ifp->if_softc;

	printf("%s: watchdog timeout\n", sc->sc_dev.dv_xname);
	ifp->if_oerrors++;

	rge_init(ifp);
}
#endif

static void
rge_qflush_if(if_t ifp)
{
	struct rge_softc *sc = if_getsoftc(ifp);

	device_printf(sc->sc_dev, "%s: called!\n", __func__);
}

static int
rge_transmit_if(if_t ifp, struct mbuf *m)
{
	struct rge_softc *sc = if_getsoftc(ifp);

	device_printf(sc->sc_dev, "%s: called!\n", __func__);
	/* Remember, don't free the mbuf on error! */
	return (ENXIO);
}

static void
rge_init_if(void *xsc)
{
	struct rge_softc *sc = xsc;

	RGE_LOCK(sc);
	rge_init_locked(sc);
	RGE_UNLOCK(sc);
}

static void
rge_init_locked(struct rge_softc *sc)
{
	struct rge_queues *q = sc->sc_queues;
	uint32_t rxconf, val;
	int i, num_miti;

	RGE_ASSERT_LOCKED(sc);

	device_printf(sc->sc_dev, "%s: called!\n", __func__);

	/*
	 * XXX TODO: calling stop before start feels hacky?
	 * Does if_re / if_rl do it?  I'd rather track driver start
	 * and stop state, and make sure I explicitly call them?
	 */
	rge_stop_locked(sc);

	/* Set MAC address. */
	rge_set_macaddr(sc, if_getlladdr(sc->sc_ifp));

	/* Initialize RX and TX descriptors lists. */
	rge_rx_list_init(q);
	rge_tx_list_init(q);

	if (rge_chipinit(sc)) {
		device_printf(sc->sc_dev, "%s: ERROR: chip init fail!\n",
		    __func__);
		return;
	}

	if (rge_phy_config(sc))
		return;

	RGE_SETBIT_1(sc, RGE_EECMD, RGE_EECMD_WRITECFG);

	RGE_CLRBIT_1(sc, 0xf1, 0x80);
	rge_disable_aspm_clkreq(sc);
	RGE_WRITE_2(sc, RGE_EEE_TXIDLE_TIMER,
	    RGE_JUMBO_MTU + ETHER_HDR_LEN + 32);

	/* Load the addresses of the RX and TX lists into the chip. */
	RGE_WRITE_4(sc, RGE_RXDESC_ADDR_LO,
	    RGE_ADDR_LO(q->q_rx.rge_rx_list_paddr));
	RGE_WRITE_4(sc, RGE_RXDESC_ADDR_HI,
	    RGE_ADDR_HI(q->q_rx.rge_rx_list_paddr));
	RGE_WRITE_4(sc, RGE_TXDESC_ADDR_LO,
	    RGE_ADDR_LO(q->q_tx.rge_tx_list_paddr));
	RGE_WRITE_4(sc, RGE_TXDESC_ADDR_HI,
	    RGE_ADDR_HI(q->q_tx.rge_tx_list_paddr));

	/* Set the initial RX and TX configurations. */
	if (sc->rge_type == MAC_R25)
		rxconf = RGE_RXCFG_CONFIG;
	else if (sc->rge_type == MAC_R25B)
		rxconf = RGE_RXCFG_CONFIG_8125B;
	else if (sc->rge_type == MAC_R25D)
		rxconf = RGE_RXCFG_CONFIG_8125D;
	else
		rxconf = RGE_RXCFG_CONFIG_8126;
	RGE_WRITE_4(sc, RGE_RXCFG, rxconf);
	RGE_WRITE_4(sc, RGE_TXCFG, RGE_TXCFG_CONFIG);

	val = rge_read_csi(sc, 0x70c) & ~0x3f000000;
	rge_write_csi(sc, 0x70c, val | 0x27000000);

	if (sc->rge_type == MAC_R26 || sc->rge_type == MAC_R27) {
		/* Disable L1 timeout. */
		val = rge_read_csi(sc, 0x890) & ~0x00000001;
		rge_write_csi(sc, 0x890, val);
	} else if (sc->rge_type != MAC_R25D)
		RGE_WRITE_2(sc, 0x0382, 0x221b);

	RGE_WRITE_1(sc, RGE_RSS_CTRL, 0);

	val = RGE_READ_2(sc, RGE_RXQUEUE_CTRL) & ~0x001c;
	RGE_WRITE_2(sc, RGE_RXQUEUE_CTRL, val | (fls(sc->sc_nqueues) - 1) << 2);

	RGE_CLRBIT_1(sc, RGE_CFG1, RGE_CFG1_SPEED_DOWN);

	rge_write_mac_ocp(sc, 0xc140, 0xffff);
	rge_write_mac_ocp(sc, 0xc142, 0xffff);

	RGE_MAC_SETBIT(sc, 0xeb58, 0x0001);

	if (sc->rge_type == MAC_R26 || sc->rge_type == MAC_R27) {
		RGE_CLRBIT_1(sc, 0xd8, 0x02);
		if (sc->rge_type == MAC_R27) {
			RGE_CLRBIT_1(sc, 0x20e4, 0x04);
			RGE_MAC_CLRBIT(sc, 0xe00c, 0x1000);
			RGE_MAC_CLRBIT(sc, 0xc0c2, 0x0040);
		}
	}

	val = rge_read_mac_ocp(sc, 0xe614);
	val &= (sc->rge_type == MAC_R27) ? ~0x0f00 : ~0x0700;
	if (sc->rge_type == MAC_R25 || sc->rge_type == MAC_R25D)
		rge_write_mac_ocp(sc, 0xe614, val | 0x0300);
	else if (sc->rge_type == MAC_R25B)
		rge_write_mac_ocp(sc, 0xe614, val | 0x0200);
	else if (sc->rge_type == MAC_R26)
		rge_write_mac_ocp(sc, 0xe614, val | 0x0300);
	else
		rge_write_mac_ocp(sc, 0xe614, val | 0x0f00);

	val = rge_read_mac_ocp(sc, 0xe63e) & ~0x0c00;
	rge_write_mac_ocp(sc, 0xe63e, val |
	    ((fls(sc->sc_nqueues) - 1) & 0x03) << 10);

	val = rge_read_mac_ocp(sc, 0xe63e) & ~0x0030;
	rge_write_mac_ocp(sc, 0xe63e, val | 0x0020);

	RGE_MAC_CLRBIT(sc, 0xc0b4, 0x0001);
	RGE_MAC_SETBIT(sc, 0xc0b4, 0x0001);

	RGE_MAC_SETBIT(sc, 0xc0b4, 0x000c);

	val = rge_read_mac_ocp(sc, 0xeb6a) & ~0x00ff;
	rge_write_mac_ocp(sc, 0xeb6a, val | 0x0033);

	val = rge_read_mac_ocp(sc, 0xeb50) & ~0x03e0;
	rge_write_mac_ocp(sc, 0xeb50, val | 0x0040);

	RGE_MAC_CLRBIT(sc, 0xe056, 0x00f0);

	RGE_WRITE_1(sc, RGE_TDFNR, 0x10);

	RGE_MAC_CLRBIT(sc, 0xe040, 0x1000);

	val = rge_read_mac_ocp(sc, 0xea1c) & ~0x0003;
	rge_write_mac_ocp(sc, 0xea1c, val | 0x0001);

	if (sc->rge_type == MAC_R25D)
		rge_write_mac_ocp(sc, 0xe0c0, 0x4403);
	else
		rge_write_mac_ocp(sc, 0xe0c0, 0x4000);

	RGE_MAC_SETBIT(sc, 0xe052, 0x0060);
	RGE_MAC_CLRBIT(sc, 0xe052, 0x0088);

	val = rge_read_mac_ocp(sc, 0xd430) & ~0x0fff;
	rge_write_mac_ocp(sc, 0xd430, val | 0x045f);

	RGE_SETBIT_1(sc, RGE_DLLPR, RGE_DLLPR_PFM_EN | RGE_DLLPR_TX_10M_PS_EN);

	if (sc->rge_type == MAC_R25)
		RGE_SETBIT_1(sc, RGE_MCUCMD, 0x01);

	if (sc->rge_type != MAC_R25D) {
		/* Disable EEE plus. */
		RGE_MAC_CLRBIT(sc, 0xe080, 0x0002);
	}

	if (sc->rge_type == MAC_R26 || sc->rge_type == MAC_R27)
		RGE_MAC_CLRBIT(sc, 0xea1c, 0x0304);
	else
		RGE_MAC_CLRBIT(sc, 0xea1c, 0x0004);

	/* Clear tcam entries. */
	RGE_MAC_SETBIT(sc, 0xeb54, 0x0001);
	DELAY(1);
	RGE_MAC_CLRBIT(sc, 0xeb54, 0x0001);

	RGE_CLRBIT_2(sc, 0x1880, 0x0030);

	if (sc->rge_type == MAC_R27) {
		val = rge_read_mac_ocp(sc, 0xd40c) & ~0xe038;
		rge_write_phy_ocp(sc, 0xd40c, val | 0x8020);
	}

	/* Config interrupt type. */
	if (sc->rge_type == MAC_R27)
		RGE_CLRBIT_1(sc, RGE_INT_CFG0, RGE_INT_CFG0_AVOID_MISS_INTR);
	else if (sc->rge_type != MAC_R25)
		RGE_CLRBIT_1(sc, RGE_INT_CFG0, RGE_INT_CFG0_EN);

	/* Clear timer interrupts. */
	RGE_WRITE_4(sc, RGE_TIMERINT0, 0);
	RGE_WRITE_4(sc, RGE_TIMERINT1, 0);
	RGE_WRITE_4(sc, RGE_TIMERINT2, 0);
	RGE_WRITE_4(sc, RGE_TIMERINT3, 0);

	num_miti =
	    (sc->rge_type == MAC_R25B || sc->rge_type == MAC_R26) ? 32 : 64;
	/* Clear interrupt moderation timer. */
	for (i = 0; i < num_miti; i++)
		RGE_WRITE_4(sc, RGE_INTMITI(i), 0);

	if (sc->rge_type == MAC_R26) {
		RGE_CLRBIT_1(sc, RGE_INT_CFG0,
		    RGE_INT_CFG0_TIMEOUT_BYPASS | RGE_INT_CFG0_RDU_BYPASS_8126 |
		    RGE_INT_CFG0_MITIGATION_BYPASS);
		RGE_WRITE_2(sc, RGE_INT_CFG1, 0);
	}

	RGE_MAC_SETBIT(sc, 0xc0ac, 0x1f80);

	rge_write_mac_ocp(sc, 0xe098, 0xc302);

	RGE_MAC_CLRBIT(sc, 0xe032, 0x0003);
	val = rge_read_csi(sc, 0x98) & ~0x0000ff00;
	rge_write_csi(sc, 0x98, val);

	if (sc->rge_type == MAC_R25D) {
		val = rge_read_mac_ocp(sc, 0xe092) & ~0x00ff;
		rge_write_mac_ocp(sc, 0xe092, val | 0x0008);
	} else
		RGE_MAC_CLRBIT(sc, 0xe092, 0x00ff);

	if (if_getcapabilities(sc->sc_ifp) & IFCAP_VLAN_HWTAGGING)
		RGE_SETBIT_4(sc, RGE_RXCFG, RGE_RXCFG_VLANSTRIP);

	RGE_SETBIT_2(sc, RGE_CPLUSCMD, RGE_CPLUSCMD_RXCSUM);
	RGE_READ_2(sc, RGE_CPLUSCMD);

	/* Set Maximum frame size. */
	RGE_WRITE_2(sc, RGE_RXMAXSIZE, RGE_JUMBO_FRAMELEN);

	/* Disable RXDV gate. */
	RGE_CLRBIT_1(sc, RGE_PPSW, 0x08);
	DELAY(2000);

	/* Program promiscuous mode and multicast filters. */
	rge_iff_locked(sc);

	if (sc->rge_type == MAC_R27)
		RGE_CLRBIT_1(sc, RGE_RADMFIFO_PROTECT, 0x2001);

	rge_disable_aspm_clkreq(sc);

	RGE_CLRBIT_1(sc, RGE_EECMD, RGE_EECMD_WRITECFG);
	DELAY(10);

	rge_ifmedia_upd(sc->sc_ifp);

	/* Enable transmit and receive. */
	RGE_WRITE_1(sc, RGE_CMD, RGE_CMD_TXENB | RGE_CMD_RXENB);

	/* Enable interrupts. */
	rge_setup_intr(sc, RGE_IMTYPE_SIM);

	if_setdrvflagbits(sc->sc_ifp, IFF_DRV_RUNNING, 0);
	if_setdrvflagbits(sc->sc_ifp, 0, IFF_DRV_OACTIVE);

	callout_reset(&sc->sc_timeout, hz, rge_tick, sc);

	device_printf(sc->sc_dev, "%s: init completed!\n", __func__);
}

/*
 * @brief Stop the adapter and free any mbufs allocated to the RX and TX lists.
 *
 * Must be called with the driver lock held.
 */
void
rge_stop_locked(struct rge_softc *sc)
{
	struct rge_queues *q = sc->sc_queues;
	int i;

	RGE_ASSERT_LOCKED(sc);

	callout_stop(&sc->sc_timeout);

	device_printf(sc->sc_dev, "%s: called!\n", __func__);

#if 0
	ifp->if_timer = 0;
	ifp->if_flags &= ~IFF_RUNNING;
#endif
	if_setdrvflagbits(sc->sc_ifp, 0, IFF_DRV_RUNNING);
	sc->rge_timerintr = 0;

	RGE_CLRBIT_4(sc, RGE_RXCFG, RGE_RXCFG_ALLPHYS | RGE_RXCFG_INDIV |
	    RGE_RXCFG_MULTI | RGE_RXCFG_BROAD | RGE_RXCFG_RUNT |
	    RGE_RXCFG_ERRPKT);

	rge_hw_reset(sc);

	RGE_MAC_CLRBIT(sc, 0xc0ac, 0x1f80);

#if 0
	intr_barrier(sc->sc_ih);
	ifq_barrier(&ifp->if_snd);
#endif
	if_setdrvflagbits(sc->sc_ifp, 0, IFF_DRV_OACTIVE);

	if (q->q_rx.rge_head != NULL) {
		m_freem(q->q_rx.rge_head);
		q->q_rx.rge_head = NULL;
		q->q_rx.rge_tail = &q->q_rx.rge_head;
	}

	/* Free the TX list buffers. */
	for (i = 0; i < RGE_TX_LIST_CNT; i++) {
		if (q->q_tx.rge_txq[i].txq_mbuf != NULL) {
			bus_dmamap_unload(sc->sc_dmat,
			    q->q_tx.rge_txq[i].txq_dmamap);
			m_freem(q->q_tx.rge_txq[i].txq_mbuf);
			q->q_tx.rge_txq[i].txq_mbuf = NULL;
		}
	}

	/* Free the RX list buffers. */
	for (i = 0; i < RGE_RX_LIST_CNT; i++) {
		if (q->q_rx.rge_rxq[i].rxq_mbuf != NULL) {
			bus_dmamap_unload(sc->sc_dmat,
			    q->q_rx.rge_rxq[i].rxq_dmamap);
			m_freem(q->q_rx.rge_rxq[i].rxq_mbuf);
			q->q_rx.rge_rxq[i].rxq_mbuf = NULL;
		}
	}
}

/*
 * Set media options.
 */
static int
rge_ifmedia_upd(if_t ifp)
{
	struct rge_softc *sc = if_getsoftc(ifp);
	struct ifmedia *ifm = &sc->sc_media;
	int anar, gig, val;

	if (IFM_TYPE(ifm->ifm_media) != IFM_ETHER)
		return (EINVAL);

	/* Disable Gigabit Lite. */
	RGE_PHY_CLRBIT(sc, 0xa428, 0x0200);
	RGE_PHY_CLRBIT(sc, 0xa5ea, 0x0001);
	if (sc->rge_type == MAC_R26 || sc->rge_type == MAC_R27)
		RGE_PHY_CLRBIT(sc, 0xa5ea, 0x0007);

	val = rge_read_phy_ocp(sc, 0xa5d4);
	switch (sc->rge_type) {
	case MAC_R27:
		val &= ~RGE_ADV_10000TFDX;
                /* fallthrough */
	case MAC_R26:
		val &= ~RGE_ADV_5000TFDX;
                /* fallthrough */
        default:
                val &= ~RGE_ADV_2500TFDX;
                break;
        }

	anar = ANAR_TX_FD | ANAR_TX | ANAR_10_FD | ANAR_10;
	gig = GTCR_ADV_1000TFDX | GTCR_ADV_1000THDX;

	switch (IFM_SUBTYPE(ifm->ifm_media)) {
	case IFM_AUTO:
		val |= RGE_ADV_2500TFDX;
		if (sc->rge_type == MAC_R26)
			val |= RGE_ADV_5000TFDX;
		else if (sc->rge_type == MAC_R27)
			val |= RGE_ADV_5000TFDX | RGE_ADV_10000TFDX;
		break;
	case IFM_10G_T:
		val |= RGE_ADV_10000TFDX;
		if_setbaudrate(ifp, IF_Gbps(10));
		break;
	case IFM_5000_T:
		val |= RGE_ADV_5000TFDX;
		if_setbaudrate(ifp, IF_Gbps(5));
		break;
	case IFM_2500_T:
		val |= RGE_ADV_2500TFDX;
		if_setbaudrate(ifp, IF_Mbps(2500));
		break;
	case IFM_1000_T:
		if_setbaudrate(ifp, IF_Gbps(1));
		break;
	case IFM_100_TX:
		gig = rge_read_phy(sc, 0, MII_100T2CR) &
		    ~(GTCR_ADV_1000TFDX | GTCR_ADV_1000THDX);
		anar = ((ifm->ifm_media & IFM_GMASK) == IFM_FDX) ?
		    ANAR_TX | ANAR_TX_FD | ANAR_10_FD | ANAR_10 :
		    ANAR_TX | ANAR_10_FD | ANAR_10;
		if_setbaudrate(ifp, IF_Mbps(100));
		break;
	case IFM_10_T:
		gig = rge_read_phy(sc, 0, MII_100T2CR) &
		    ~(GTCR_ADV_1000TFDX | GTCR_ADV_1000THDX);
		anar = ((ifm->ifm_media & IFM_GMASK) == IFM_FDX) ?
		    ANAR_10_FD | ANAR_10 : ANAR_10;
		if_setbaudrate(ifp, IF_Mbps(10));
		break;
	default:
		device_printf(sc->sc_dev, "unsupported media type\n");
		return (EINVAL);
	}

	rge_write_phy(sc, 0, MII_ANAR, anar | ANAR_PAUSE_ASYM | ANAR_FC);
	rge_write_phy(sc, 0, MII_100T2CR, gig);
	rge_write_phy_ocp(sc, 0xa5d4, val);
	rge_write_phy(sc, 0, MII_BMCR, BMCR_RESET | BMCR_AUTOEN |
	    BMCR_STARTNEG);

	return (0);
}

/*
 * Report current media status.
 */
static void
rge_ifmedia_sts(if_t ifp, struct ifmediareq *ifmr)
{
	struct rge_softc *sc = if_getsoftc(ifp);
	uint16_t status = 0;

	ifmr->ifm_status = IFM_AVALID;
	ifmr->ifm_active = IFM_ETHER;

	if (rge_get_link_status(sc)) {
		ifmr->ifm_status |= IFM_ACTIVE;

		status = RGE_READ_2(sc, RGE_PHYSTAT);
		if ((status & RGE_PHYSTAT_FDX) ||
		    (status & (RGE_PHYSTAT_1000MBPS | RGE_PHYSTAT_2500MBPS |
		    RGE_PHYSTAT_5000MBPS | RGE_PHYSTAT_10000MBPS)))
			ifmr->ifm_active |= IFM_FDX;
		else
			ifmr->ifm_active |= IFM_HDX;

		if (status & RGE_PHYSTAT_10MBPS)
			ifmr->ifm_active |= IFM_10_T;
		else if (status & RGE_PHYSTAT_100MBPS)
			ifmr->ifm_active |= IFM_100_TX;
		else if (status & RGE_PHYSTAT_1000MBPS)
			ifmr->ifm_active |= IFM_1000_T;
		else if (status & RGE_PHYSTAT_2500MBPS)
			ifmr->ifm_active |= IFM_2500_T;
		else if (status & RGE_PHYSTAT_5000MBPS)
			ifmr->ifm_active |= IFM_5000_T;
		else if (status & RGE_PHYSTAT_5000MBPS)
			ifmr->ifm_active |= IFM_5000_T;
		else if (status & RGE_PHYSTAT_10000MBPS)
			ifmr->ifm_active |= IFM_10G_T;
	}
}

/**
 * @brief callback to load/populate a single physical address
 */
static void
rge_dma_load_cb(void *arg, bus_dma_segment_t *segs, int nsegs, int error)
{
	int i;
	bus_addr_t *paddr = (bus_addr_t *) arg;

	printf("%s: called; segs=%p, nsegs=%d, error=%d\n",
	    __func__, segs, nsegs, error);

	*paddr = 0;

	if (error)
		return;

	if (nsegs != 1) {
		printf("%s: too many segs (got %d)\n", __func__, nsegs);
		return;
	}

	if (segs != 0)
		for (i = 0; i < nsegs; i++)
			printf("  segs[%d]=%p\n", i, segs);

	*paddr = segs[0].ds_addr;
}

/**
 * @brief Allocate memory for RX/TX rings.
 *
 * Called with the driver lock NOT held.
 */
static int
rge_allocmem(struct rge_softc *sc)
{
	struct rge_queues *q = sc->sc_queues;
	int error;
	int i;

	RGE_ASSERT_UNLOCKED(sc);

	/* Allocate DMA'able memory for the TX ring. */
	error = bus_dmamap_create(sc->sc_dmat, BUS_DMA_COHERENT,
	    &q->q_tx.rge_tx_list_map);
	if (error) {
		device_printf(sc->sc_dev, "%s: error (create tx_list.map) (%d)\n",
		    __func__, error);
		goto error;
	}
	error = bus_dmamem_alloc(sc->sc_dmat_tx_desc,
	    (void **) &q->q_tx.rge_tx_list,
	        BUS_DMA_NOWAIT | BUS_DMA_ZERO| BUS_DMA_COHERENT,
	    &q->q_tx.rge_tx_list_map);
	if (error) {
		device_printf(sc->sc_dev, "%s: error (alloc tx_list.map) (%d)\n",
		    __func__, error);
		goto error;
	}

	device_printf(sc->sc_dev, "%s: tx_list=%p\n", __func__,
	    q->q_tx.rge_tx_list);
	device_printf(sc->sc_dev, "%s: tx_list_map=%p\n", __func__,
	    q->q_tx.rge_tx_list_map);

	/* Load the map for the TX ring. */
	error = bus_dmamap_load(sc->sc_dmat_tx_desc,
	    q->q_tx.rge_tx_list_map,
	    &q->q_tx.rge_tx_list,
	    RGE_TX_LIST_SZ,
	    rge_dma_load_cb,
	    (void *) &q->q_tx.rge_tx_list_paddr,
	    BUS_DMA_NOWAIT);

	if ((error != 0) || (q->q_tx.rge_tx_list_paddr == 0)) {
		device_printf(sc->sc_dev, "%s: error (load tx_list.map) (%d)\n",
		    __func__, error);
		goto error;
	}

	/* Create DMA maps for TX buffers. */
	for (i = 0; i < RGE_TX_LIST_CNT; i++) {
		error = bus_dmamap_create(sc->sc_dmat_tx_buf,
		    BUS_DMA_NOWAIT, &q->q_tx.rge_txq[i].txq_dmamap);
		if (error) {
			device_printf(sc->sc_dev,
			    "can't create DMA map for TX (%d)\n", error);
			goto error;
		}
	}

	/* Allocate DMA'able memory for the RX ring. */
	error = bus_dmamap_create(sc->sc_dmat, BUS_DMA_COHERENT,
	    &q->q_rx.rge_rx_list_map);
	if (error) {
		device_printf(sc->sc_dev,
		    "%s: error (create rx_list.map) (%d)\n", __func__, error);
		goto error;
	}
	error = bus_dmamem_alloc(sc->sc_dmat_rx_desc,
	    (void **) &q->q_rx.rge_rx_list,
	    BUS_DMA_NOWAIT | BUS_DMA_ZERO | BUS_DMA_COHERENT,
	    &q->q_rx.rge_rx_list_map);
	if (error) {
		device_printf(sc->sc_dev,
		    "%s: error (alloc rx_list.map) (%d)\n",
		    __func__, error);
		goto error;
	}

	device_printf(sc->sc_dev, "%s: rx_list=%p\n", __func__,
	    q->q_rx.rge_rx_list);
	device_printf(sc->sc_dev, "%s: rx_list_map=%p\n", __func__,
	    q->q_rx.rge_rx_list_map);

	/* Load the map for the RX ring. */
	error = bus_dmamap_load(sc->sc_dmat_rx_desc,
	    q->q_rx.rge_rx_list_map,
	    q->q_rx.rge_rx_list,
	    RGE_RX_LIST_SZ,
	    rge_dma_load_cb,
	    (void *) &q->q_rx.rge_rx_list_paddr,
	    BUS_DMA_NOWAIT);

	if ((error != 0) || (q->q_rx.rge_rx_list_paddr == 0)) {
		device_printf(sc->sc_dev, "%s: error (load rx_list.map) (%d)\n",
		    __func__, error);
		goto error;
	}

	/* Create DMA maps for RX buffers. */
	for (i = 0; i < RGE_RX_LIST_CNT; i++) {
		error = bus_dmamap_create(sc->sc_dmat_rx_buf,
		    BUS_DMA_NOWAIT, &q->q_rx.rge_rxq[i].rxq_dmamap);
		if (error) {
			device_printf(sc->sc_dev,
			    "can't create DMA map for RX (%d)\n", error);
			goto error;
		}
	}

	return (0);
error:

	rge_freemem(sc);

	return (error);
}

/**
 * @brief Free the TX/RX DMA buffers and mbufs.
 *
 * Called with the driver lock NOT held.
 */
static int
rge_freemem(struct rge_softc *sc)
{
	struct rge_queues *q = sc->sc_queues;
	int i;

	RGE_ASSERT_UNLOCKED(sc);

	/* TX desc */
	bus_dmamap_unload(sc->sc_dmat_tx_desc, q->q_tx.rge_tx_list_map);
	if (q->q_tx.rge_tx_list != NULL)
		bus_dmamem_free(sc->sc_dmat_tx_desc, q->q_tx.rge_tx_list,
		    q->q_tx.rge_tx_list_map);
	bus_dmamap_destroy(sc->sc_dmat_tx_desc, q->q_tx.rge_tx_list_map);
	memset(&q->q_tx, 0, sizeof(q->q_tx));

	/* TX buf */
	for (i = 0; i < RGE_TX_LIST_CNT; i++) {
		struct rge_txq *tx = &q->q_tx.rge_txq[i];

		/* unmap/free mbuf if it's still alloc'ed and mapped */
		if (tx->txq_mbuf != NULL) {
			static bool do_warning = false;

			if (do_warning == false) {
				device_printf(sc->sc_dev,
				    "%s: TX mbuf should've been freed!\n",
				    __func__);
				do_warning = true;
			}
			if (tx->txq_dmamap != NULL) {
				bus_dmamap_sync(sc->sc_dmat_tx_buf,
				    tx->txq_dmamap, BUS_DMASYNC_POSTREAD);
				bus_dmamap_unload(sc->sc_dmat_tx_buf,
				    tx->txq_dmamap);
			}
			m_free(tx->txq_mbuf);
			tx->txq_mbuf = NULL;
		}

		/* Destroy the dmamap if it's allocated */
		if (tx->txq_dmamap != NULL) {
			bus_dmamap_destroy(sc->sc_dmat_tx_buf, tx->txq_dmamap);
			tx->txq_dmamap = NULL;
		}
	}

	/* RX desc */
	bus_dmamap_unload(sc->sc_dmat_rx_desc, q->q_rx.rge_rx_list_map);
	if (q->q_rx.rge_rx_list != 0)
		bus_dmamem_free(sc->sc_dmat_rx_desc, q->q_rx.rge_rx_list,
		    q->q_rx.rge_rx_list_map);
	bus_dmamap_destroy(sc->sc_dmat_rx_desc, q->q_rx.rge_rx_list_map);
	memset(&q->q_rx, 0, sizeof(q->q_tx));

	/* RX buf */
	for (i = 0; i < RGE_RX_LIST_CNT; i++) {
		struct rge_rxq *rx = &q->q_rx.rge_rxq[i];

		/* unmap/free mbuf if it's still alloc'ed and mapped */
		if (rx->rxq_mbuf != NULL) {
			if (rx->rxq_dmamap != NULL) {
				bus_dmamap_sync(sc->sc_dmat_rx_buf,
				    rx->rxq_dmamap, BUS_DMASYNC_POSTREAD);
				bus_dmamap_unload(sc->sc_dmat_rx_buf,
				    rx->rxq_dmamap);
			}
			m_free(rx->rxq_mbuf);
			rx->rxq_mbuf = NULL;
		}

		/* Destroy the dmamap if it's allocated */
		if (rx->rxq_dmamap != NULL) {
			bus_dmamap_destroy(sc->sc_dmat_rx_buf, rx->rxq_dmamap);
			rx->rxq_dmamap = NULL;
		}
	}

	return (0);
}

/*
 * Initialize the RX descriptor and attach an mbuf cluster.
 *
 * Note: this relies on the rxr ring buffer abstraction to not
 * over-fill the RX ring.  For FreeBSD we'll need to use the
 * prod/cons RX indexes to know how much RX ring space to
 * populate.
 *
 * This must be called with the driver lock held.
 */
static int
rge_newbuf(struct rge_queues *q)
{
	struct rge_softc *sc = q->q_sc;
	struct mbuf *m;
	struct rge_rx_desc *r;
	struct rge_rxq *rxq;
	bus_dmamap_t rxmap;
	bus_dma_segment_t seg[1];
	uint32_t cmdsts;
	int idx, nsegs;

	RGE_ASSERT_LOCKED(sc);

	/*
	 * TODO: Verify we have enough space in the ring; error out
	 * if we do not.
	 */


	/* Allocate single buffer backed mbuf of MCLBYTES */
	m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL)
		return (ENOBUFS);

	m->m_len = m->m_pkthdr.len = MCLBYTES;
	m_adj(m, ETHER_ALIGN);

	idx = q->q_rx.rge_rxq_prodidx;
	rxq = &q->q_rx.rge_rxq[idx];
	rxmap = rxq->rxq_dmamap;

	nsegs = 1;
	if (bus_dmamap_load_mbuf_sg(sc->sc_dmat, rxmap, m, seg, &nsegs,
	    BUS_DMA_NOWAIT)) {
		m_freem(m);
		return (ENOBUFS);
	}

	bus_dmamap_sync(sc->sc_dmat, rxmap, BUS_DMASYNC_PREREAD);

	/* Map the segments into RX descriptors. */
	r = &q->q_rx.rge_rx_list[idx];

	rxq->rxq_mbuf = m;

	cmdsts = seg[0].ds_len;
	if (idx == RGE_RX_LIST_CNT - 1)
		cmdsts |= RGE_RDCMDSTS_EOR;

	r->hi_qword1.rx_qword4.rge_cmdsts = htole32(cmdsts);
	r->hi_qword1.rx_qword4.rge_extsts = htole32(0);
	r->hi_qword0.rge_addr = htole64(seg[0].ds_addr);

	bus_dmamap_sync(sc->sc_dmat, q->q_rx.rge_rx_list_map,
	    BUS_DMASYNC_PREWRITE);

	bus_dmamap_sync(sc->sc_dmat, q->q_rx.rge_rx_list_map,
	    BUS_DMASYNC_POSTWRITE);
	cmdsts |= RGE_RDCMDSTS_OWN;
	r->hi_qword1.rx_qword4.rge_cmdsts = htole32(cmdsts);
	bus_dmamap_sync(sc->sc_dmat, q->q_rx.rge_rx_list_map,
	    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

	q->q_rx.rge_rxq_prodidx = RGE_NEXT_RX_DESC(idx);

	return (0);
}

static void
rge_rx_list_init(struct rge_queues *q)
{
	memset(q->q_rx.rge_rx_list, 0, RGE_RX_LIST_SZ);

	RGE_ASSERT_LOCKED(sc);

	q->q_rx.rge_rxq_prodidx = q->q_rx.rge_rxq_considx = 0;
	q->q_rx.rge_head = NULL;
	q->q_rx.rge_tail = &q->q_rx.rge_head;

	rge_fill_rx_ring(q);
}

static void
rge_fill_rx_ring(struct rge_queues *q)
{
	int i;

	RGE_ASSERT_LOCKED(sc);

	for (i = 0; i < RGE_RX_LIST_CNT; i++) {
		if (rge_newbuf(q))
			break;
	}
}

static void
rge_tx_list_init(struct rge_queues *q)
{
	struct rge_softc *sc = q->q_sc;
	struct rge_tx_desc *d;
	int i;

	RGE_ASSERT_LOCKED(sc);

	memset(q->q_tx.rge_tx_list, 0, RGE_TX_LIST_SZ);

	for (i = 0; i < RGE_TX_LIST_CNT; i++)
		q->q_tx.rge_txq[i].txq_mbuf = NULL;

	d = &q->q_tx.rge_tx_list[RGE_TX_LIST_CNT - 1];
	d->rge_cmdsts = htole32(RGE_TDCMDSTS_EOR);

	bus_dmamap_sync(sc->sc_dmat, q->q_tx.rge_tx_list_map,
	    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

	q->q_tx.rge_txq_prodidx = q->q_tx.rge_txq_considx = 0;
}

int
rge_rxeof(struct rge_queues *q, struct mbufq *mq)
{
	struct rge_softc *sc = q->q_sc;
	struct mbuf *m;
	struct rge_rx_desc *cur_rx;
	struct rge_rxq *rxq;
	uint32_t rxstat, extsts;
	int i, mlen, rx = 0;
	int cons;
	int maxpkt = 32;

	RGE_ASSERT_LOCKED(sc);

	/* Note: if_re is POSTREAD/WRITE, rge is only POSTWRITE */
	bus_dmamap_sync(sc->sc_dmat, q->q_rx.rge_rx_list_map,
	    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

	/*
	 * Note: this isn't the best loop invariant; need to revisit this.
	 */
	for (i = cons = q->q_rx.rge_rxq_considx;
	    maxpkt > 0; i = RGE_NEXT_RX_DESC(i)) {
		/* break out of loop if we're not running */
		if ((if_getdrvflags(sc->sc_ifp) & IFF_DRV_RUNNING) == 0)
			break;

		/* get the current rx descriptor to check descriptor status */
		cur_rx = &q->q_rx.rge_rx_list[i];
		rxstat = le32toh(cur_rx->hi_qword1.rx_qword4.rge_cmdsts);
		if ((rxstat & RGE_RDCMDSTS_OWN) != 0) {
			break;
		}

		/* Get the current rx buffer, sync */
		rxq = &q->q_rx.rge_rxq[i];
		/* XXX double check */
		bus_dmamap_sync(sc->sc_dmat, rxq->rxq_dmamap,
		    BUS_DMASYNC_POSTREAD);
		bus_dmamap_unload(sc->sc_dmat, rxq->rxq_dmamap);
		m = rxq->rxq_mbuf;
		rxq->rxq_mbuf = NULL;

		rx = 1;

		if ((rxstat & RGE_RDCMDSTS_SOF) != 0) {
			if (q->q_rx.rge_head != NULL) {
				if_inc_counter(sc->sc_ifp, IFCOUNTER_IERRORS,
				    1);
				m_freem(q->q_rx.rge_head);
				q->q_rx.rge_tail = &q->q_rx.rge_head;
			}

			m->m_pkthdr.len = 0;
		} else if (q->q_rx.rge_head == NULL) {
			m_freem(m);
			continue;
		} else
			m->m_flags &= ~M_PKTHDR;

		*q->q_rx.rge_tail = m;
		q->q_rx.rge_tail = &m->m_next;

		mlen = rxstat & RGE_RDCMDSTS_FRAGLEN;
		m->m_len = mlen;

		m = q->q_rx.rge_head;
		m->m_pkthdr.len += mlen;

		if (rxstat & RGE_RDCMDSTS_RXERRSUM) {
			if_inc_counter(sc->sc_ifp, IFCOUNTER_IERRORS, 1);
			m_freem(m);
			q->q_rx.rge_head = NULL;
			q->q_rx.rge_tail = &q->q_rx.rge_head;
			continue;
		}

		if ((rxstat & RGE_RDCMDSTS_EOF) == 0)
			continue;

		q->q_rx.rge_head = NULL;
		q->q_rx.rge_tail = &q->q_rx.rge_head;

		m_adj(m, -ETHER_CRC_LEN);
		m->m_pkthdr.rcvif = sc->sc_ifp;
		if_inc_counter(sc->sc_ifp, IFCOUNTER_IPACKETS, 1);

		extsts = le32toh(cur_rx->hi_qword1.rx_qword4.rge_extsts);

		/* Check IP header checksum. */
		if ((if_getcapenable(sc->sc_ifp) & IFCAP_RXCSUM) != 0) {
#if 0
			/* Does it exist for IPv4? */
			if (extsts & RGE_RDEXTSTS_IPV4)
				m->m_pkthdr.csum_flags |=
				    CSUM_IP_CHECKED;
			if (((extsts & RGE_RDEXTSTS_IPCSUMERR) == 0)
			    && ((extsts & RGE_RDEXTSTS_IPV4) != 0))
				m->m_pkthdr.csum_flags |=
				    CSUM_IP_VALID;
#endif

#if 0
		/* XXX TODO: this is still openbsd code */
		/* Check TCP/UDP checksum. */
		if ((extsts & (RGE_RDEXTSTS_IPV4 | RGE_RDEXTSTS_IPV6)) &&
		    (((extsts & RGE_RDEXTSTS_TCPPKT) &&
		    !(extsts & RGE_RDEXTSTS_TCPCSUMERR)) ||
		    ((extsts & RGE_RDEXTSTS_UDPPKT) &&
		    !(extsts & RGE_RDEXTSTS_UDPCSUMERR))))
			m->m_pkthdr.csum_flags |= M_TCP_CSUM_IN_OK |
			    M_UDP_CSUM_IN_OK;
#endif

		}

		if (extsts & RGE_RDEXTSTS_VTAG) {
			m->m_pkthdr.ether_vtag =
			    ntohs(extsts & RGE_RDEXTSTS_VLAN_MASK);
			m->m_flags |= M_VLANTAG;
		}

		mbufq_enqueue(mq, m);
	}

	if (!rx)
		return (0);

	/* XXX check */
	bus_dmamap_sync(sc->sc_dmat, q->q_rx.rge_rx_list_map,
	    BUS_DMASYNC_POSTWRITE);

	/* Update the consumer index, refill the RX ring */
	q->q_rx.rge_rxq_considx = i;
	rge_fill_rx_ring(q);

	return (1);
}

#if 0
int
rge_txeof(struct rge_queues *q)
{
	struct rge_softc *sc = q->q_sc;
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	struct rge_txq *txq;
	uint32_t txstat;
	int cons, prod, cur, idx;
	int free = 0;

	prod = q->q_tx.rge_txq_prodidx;
	cons = q->q_tx.rge_txq_considx;

	idx = cons;
	while (idx != prod) {
		txq = &q->q_tx.rge_txq[idx];
		cur = txq->txq_descidx;

		rge_tx_list_sync(sc, q, cur, 1, BUS_DMASYNC_POSTREAD);
		txstat = q->q_tx.rge_tx_list[cur].rge_cmdsts;
		rge_tx_list_sync(sc, q, cur, 1, BUS_DMASYNC_PREREAD);
		if (ISSET(txstat, htole32(RGE_TDCMDSTS_OWN))) {
			free = 2;
			break;
		}

		bus_dmamap_sync(sc->sc_dmat, txq->txq_dmamap, 0,
		    txq->txq_dmamap->dm_mapsize, BUS_DMASYNC_POSTWRITE);
		bus_dmamap_unload(sc->sc_dmat, txq->txq_dmamap);
		m_freem(txq->txq_mbuf);
		txq->txq_mbuf = NULL;

		if (ISSET(txstat,
		    htole32(RGE_TDCMDSTS_EXCESSCOLL | RGE_TDCMDSTS_COLL)))
			ifp->if_collisions++;
		if (ISSET(txstat, htole32(RGE_TDCMDSTS_TXERR)))
			ifp->if_oerrors++;

		idx = RGE_NEXT_TX_DESC(cur);
		free = 1;
	}

	if (free == 0)
		return (0);

	if (idx >= cons) {
		rge_tx_list_sync(sc, q, cons, idx - cons,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
	} else {
		rge_tx_list_sync(sc, q, cons, RGE_TX_LIST_CNT - cons,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
		rge_tx_list_sync(sc, q, 0, idx,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
	}

	q->q_tx.rge_txq_considx = idx;

	if (ifq_is_oactive(&ifp->if_snd))
		ifq_restart(&ifp->if_snd);
	else if (free == 2)
		ifq_serialize(&ifp->if_snd, &sc->sc_task);
	else
		ifp->if_timer = 0;

	return (1);
}
#endif

static int
rge_reset(struct rge_softc *sc)
{
	int i;

	RGE_CLRBIT_4(sc, RGE_RXCFG, RGE_RXCFG_ALLPHYS | RGE_RXCFG_INDIV |
	    RGE_RXCFG_MULTI | RGE_RXCFG_BROAD | RGE_RXCFG_RUNT |
	    RGE_RXCFG_ERRPKT);

	/* Enable RXDV gate. */
	RGE_SETBIT_1(sc, RGE_PPSW, 0x08);

	RGE_SETBIT_1(sc, RGE_CMD, RGE_CMD_STOPREQ);
	if (sc->rge_type == MAC_R25) {
		for (i = 0; i < 20; i++) {
			DELAY(10);
			if (!(RGE_READ_1(sc, RGE_CMD) & RGE_CMD_STOPREQ))
				break;
		}
		if (i == 20) {
			device_printf(sc->sc_dev,
			    "failed to stop all requests\n");
			return ETIMEDOUT;
		}
	} else
		DELAY(200);

	for (i = 0; i < 3000; i++) {
		DELAY(50);
		if ((RGE_READ_1(sc, RGE_MCUCMD) & (RGE_MCUCMD_RXFIFO_EMPTY |
		    RGE_MCUCMD_TXFIFO_EMPTY)) == (RGE_MCUCMD_RXFIFO_EMPTY |
		    RGE_MCUCMD_TXFIFO_EMPTY))
			break;
	}
	if (sc->rge_type != MAC_R25) {
		for (i = 0; i < 3000; i++) {
			DELAY(50);
			if ((RGE_READ_2(sc, RGE_IM) & 0x0103) == 0x0103)
				break;
		}
	}

	RGE_WRITE_1(sc, RGE_CMD,
	    RGE_READ_1(sc, RGE_CMD) & (RGE_CMD_TXENB | RGE_CMD_RXENB));

	/* Soft reset. */
	RGE_WRITE_1(sc, RGE_CMD, RGE_CMD_RESET);

	for (i = 0; i < RGE_TIMEOUT; i++) {
		DELAY(100);
		if (!(RGE_READ_1(sc, RGE_CMD) & RGE_CMD_RESET))
			break;
	}
	if (i == RGE_TIMEOUT) {
		device_printf(sc->sc_dev, "reset never completed!\n");
		return ETIMEDOUT;
	}

	return 0;
}

static u_int
rge_hash_maddr(void *arg, struct sockaddr_dl *sdl, u_int cnt)
{
	uint32_t crc, *hashes = arg;

	// XXX TODO: validate this does addrlo? */
	crc = ether_crc32_be(LLADDR(sdl), ETHER_ADDR_LEN) >> 26;
	crc &= 0x3f;

	if (crc < 32)
		hashes[0] |= (1 << crc);
	else
		hashes[1] |= (1 << (crc - 32));

	return (1);
}

/**
 * @brief Configure the RX filter and multicast filter.
 *
 * This must be called with the driver lock held.
 */
static void
rge_iff_locked(struct rge_softc *sc)
{
	uint32_t hashes[2];
	uint32_t rxfilt;

	RGE_ASSERT_LOCKED(sc);

	rxfilt = RGE_READ_4(sc, RGE_RXCFG);
	rxfilt &= ~(RGE_RXCFG_ALLPHYS | RGE_RXCFG_MULTI);

	/*
	 * Always accept frames destined to our station address.
	 * Always accept broadcast frames.
	 */
	rxfilt |= RGE_RXCFG_INDIV | RGE_RXCFG_BROAD;

	if ((if_getflags(sc->sc_ifp) & (IFF_PROMISC | IFF_ALLMULTI)) != 0) {
		rxfilt |= RGE_RXCFG_MULTI;
		if ((if_getflags(sc->sc_ifp) & IFF_PROMISC) != 0)
			rxfilt |= RGE_RXCFG_ALLPHYS;
		hashes[0] = hashes[1] = 0xffffffff;
	} else {
		rxfilt |= RGE_RXCFG_MULTI;
		/* Program new filter. */
		memset(hashes, 0, sizeof(hashes));
		if_foreach_llmaddr(sc->sc_ifp, rge_hash_maddr, &hashes);
	}

	RGE_WRITE_4(sc, RGE_RXCFG, rxfilt);
	RGE_WRITE_4(sc, RGE_MAR0, bswap32(hashes[1]));
	RGE_WRITE_4(sc, RGE_MAR4, bswap32(hashes[0]));
}

/**
 * @brief Do initial chip power-on and setup.
 *
 * Must be called with the driver lock held.
 */
static int
rge_chipinit(struct rge_softc *sc)
{
	int error;

	RGE_ASSERT_LOCKED(sc);

	if ((error = rge_exit_oob(sc)) != 0)
		return error;
	rge_set_phy_power(sc, 1);
	rge_hw_init(sc);
	rge_hw_reset(sc);

	return 0;
}

static void
rge_set_phy_power(struct rge_softc *sc, int on)
{
	int i;

	if (on) {
		RGE_SETBIT_1(sc, RGE_PMCH, 0xc0);

		rge_write_phy(sc, 0, MII_BMCR, BMCR_AUTOEN);

		for (i = 0; i < RGE_TIMEOUT; i++) {
			if ((rge_read_phy_ocp(sc, 0xa420) & 0x0007) == 3)
				break;
			DELAY(1000);
		}
	} else {
		rge_write_phy(sc, 0, MII_BMCR, BMCR_AUTOEN | BMCR_PDOWN);
		RGE_CLRBIT_1(sc, RGE_PMCH, 0x80);
		RGE_CLRBIT_1(sc, RGE_PPSW, 0x40);
	}
}

static void
rge_mac_config_mcu(struct rge_softc *sc, enum rge_mac_type type)
{
	uint64_t mcodever;
	uint16_t reg;
	int i, npages;

	if (type == MAC_R25) {
		for (npages = 0; npages < 3; npages++) {
			rge_switch_mcu_ram_page(sc, npages);
			for (i = 0; i < nitems(rtl8125_mac_bps); i++) {
				if (npages == 0)
					rge_write_mac_ocp(sc,
					    rtl8125_mac_bps[i].reg,
					    rtl8125_mac_bps[i].val);
				else if (npages == 1)
					rge_write_mac_ocp(sc,
					    rtl8125_mac_bps[i].reg, 0);
				else {
					if (rtl8125_mac_bps[i].reg < 0xf9f8)
						rge_write_mac_ocp(sc,
						    rtl8125_mac_bps[i].reg, 0);
				}
			}
			if (npages == 2) {
				rge_write_mac_ocp(sc, 0xf9f8, 0x6486);
				rge_write_mac_ocp(sc, 0xf9fa, 0x0b15);
				rge_write_mac_ocp(sc, 0xf9fc, 0x090e);
				rge_write_mac_ocp(sc, 0xf9fe, 0x1139);
			}
		}
		rge_write_mac_ocp(sc, 0xfc26, 0x8000);
		rge_write_mac_ocp(sc, 0xfc2a, 0x0540);
		rge_write_mac_ocp(sc, 0xfc2e, 0x0a06);
		rge_write_mac_ocp(sc, 0xfc30, 0x0eb8);
		rge_write_mac_ocp(sc, 0xfc32, 0x3a5c);
		rge_write_mac_ocp(sc, 0xfc34, 0x10a8);
		rge_write_mac_ocp(sc, 0xfc40, 0x0d54);
		rge_write_mac_ocp(sc, 0xfc42, 0x0e24);
		rge_write_mac_ocp(sc, 0xfc48, 0x307a);
	} else if (type == MAC_R25B) {
		rge_switch_mcu_ram_page(sc, 0);
		for (i = 0; i < nitems(rtl8125b_mac_bps); i++) {
			rge_write_mac_ocp(sc, rtl8125b_mac_bps[i].reg,
			    rtl8125b_mac_bps[i].val);
		}
	} else if (type == MAC_R25D) {
		for (npages = 0; npages < 3; npages++) {
			rge_switch_mcu_ram_page(sc, npages);

			rge_write_mac_ocp(sc, 0xf800,
			    (npages == 0) ? 0xe002 : 0);
			rge_write_mac_ocp(sc, 0xf802,
			    (npages == 0) ? 0xe006 : 0);
			rge_write_mac_ocp(sc, 0xf804,
			    (npages == 0) ? 0x4166 : 0);
			rge_write_mac_ocp(sc, 0xf806,
			    (npages == 0) ? 0x9cf6 : 0);
			rge_write_mac_ocp(sc, 0xf808,
			    (npages == 0) ? 0xc002 : 0);
			rge_write_mac_ocp(sc, 0xf80a,
			    (npages == 0) ? 0xb800 : 0);
			rge_write_mac_ocp(sc, 0xf80c,
			    (npages == 0) ? 0x14a4 : 0);
			rge_write_mac_ocp(sc, 0xf80e,
			    (npages == 0) ? 0xc102 : 0);
			rge_write_mac_ocp(sc, 0xf810,
			    (npages == 0) ? 0xb900 : 0);

			for (reg = 0xf812; reg <= 0xf9f6; reg += 2)
				rge_write_mac_ocp(sc, reg, 0);

			rge_write_mac_ocp(sc, 0xf9f8,
			    (npages == 2) ? 0x6938 : 0);
			rge_write_mac_ocp(sc, 0xf9fa,
			    (npages == 2) ? 0x0a18 : 0);
			rge_write_mac_ocp(sc, 0xf9fc,
			    (npages == 2) ? 0x0217 : 0);
			rge_write_mac_ocp(sc, 0xf9fe,
			    (npages == 2) ? 0x0d2a : 0);
		}
		rge_write_mac_ocp(sc, 0xfc26, 0x8000);
		rge_write_mac_ocp(sc, 0xfc28, 0x14a2);
		rge_write_mac_ocp(sc, 0xfc48, 0x0001);
	} else if (type == MAC_R27) {
		mcodever = rge_mcu_get_bin_version(nitems(rtl8127_mac_bps));
		if (sc->rge_mcodever != mcodever) {
		    	/* Switch to page 0. */
			rge_switch_mcu_ram_page(sc, 0);
			for (i = 0; i < 256; i++)
				rge_write_mac_ocp(sc, rtl8127_mac_bps[i].reg,
				    rtl8127_mac_bps[i].val);
		    	/* Switch to page 1. */
			rge_switch_mcu_ram_page(sc, 1);
			for (; i < nitems(rtl8127_mac_bps); i++)
				rge_write_mac_ocp(sc, rtl8127_mac_bps[i].reg,
				    rtl8127_mac_bps[i].val);
		}
		rge_write_mac_ocp(sc, 0xfc26, 0x8000);
		rge_write_mac_ocp(sc, 0xfc28, 0x1520);
		rge_write_mac_ocp(sc, 0xfc2a, 0x41e0);
		rge_write_mac_ocp(sc, 0xfc2c, 0x508c);
		rge_write_mac_ocp(sc, 0xfc2e, 0x50f6);
		rge_write_mac_ocp(sc, 0xfc30, 0x34fa);
		rge_write_mac_ocp(sc, 0xfc32, 0x0166);
		rge_write_mac_ocp(sc, 0xfc34, 0x1a6a);
		rge_write_mac_ocp(sc, 0xfc36, 0x1a2c);
		rge_write_mac_ocp(sc, 0xfc48, 0x00ff);

		/* Write microcode version. */
		rge_mcu_set_version(sc, mcodever);
	}
}

static uint64_t
rge_mcu_get_bin_version(uint16_t entries)
{
	uint64_t binver = 0;
	int i;

	for (i = 0; i < 4; i++) {
		binver <<= 16;
		binver |= rtl8127_mac_bps[entries - 4 + i].val;
	}

	return binver;
}

static void
rge_mcu_set_version(struct rge_softc *sc, uint64_t mcodever)
{
	int i;

	/* Switch to page 2. */
	rge_switch_mcu_ram_page(sc, 2);

	for (i = 0; i < 8; i += 2) {
		rge_write_mac_ocp(sc, 0xf9f8 + 6 - i, (uint16_t)mcodever);
		mcodever >>= 16;
	}

	/* Switch back to page 0. */
	rge_switch_mcu_ram_page(sc, 0);
}

static void
rge_ephy_config(struct rge_softc *sc)
{
	switch (sc->rge_type) {
	case MAC_R25:
		rge_ephy_config_mac_r25(sc);
		break;
	case MAC_R25B:
		rge_ephy_config_mac_r25b(sc);
		break;
	case MAC_R27:
		rge_ephy_config_mac_r27(sc);
		break;
	default:
		break;	/* Nothing to do. */
	}
}

static void
rge_ephy_config_mac_r25(struct rge_softc *sc)
{
	uint16_t val;
	int i;

	for (i = 0; i < nitems(mac_r25_ephy); i++)
		rge_write_ephy(sc, mac_r25_ephy[i].reg, mac_r25_ephy[i].val);

	val = rge_read_ephy(sc, 0x002a) & ~0x7000;
	rge_write_ephy(sc, 0x002a, val | 0x3000);
	RGE_EPHY_CLRBIT(sc, 0x0019, 0x0040);
	RGE_EPHY_SETBIT(sc, 0x001b, 0x0e00);
	RGE_EPHY_CLRBIT(sc, 0x001b, 0x7000);
	rge_write_ephy(sc, 0x0002, 0x6042);
	rge_write_ephy(sc, 0x0006, 0x0014);
	val = rge_read_ephy(sc, 0x006a) & ~0x7000;
	rge_write_ephy(sc, 0x006a, val | 0x3000);
	RGE_EPHY_CLRBIT(sc, 0x0059, 0x0040);
	RGE_EPHY_SETBIT(sc, 0x005b, 0x0e00);
	RGE_EPHY_CLRBIT(sc, 0x005b, 0x7000);
	rge_write_ephy(sc, 0x0042, 0x6042);
	rge_write_ephy(sc, 0x0046, 0x0014);
}

static void
rge_ephy_config_mac_r25b(struct rge_softc *sc)
{
	int i;

	for (i = 0; i < nitems(mac_r25b_ephy); i++)
		rge_write_ephy(sc, mac_r25b_ephy[i].reg, mac_r25b_ephy[i].val);
}

static void
rge_ephy_config_mac_r27(struct rge_softc *sc)
{
	int i;

	for (i = 0; i < nitems(mac_r27_ephy); i++)
		rge_r27_write_ephy(sc, mac_r27_ephy[i].reg,
		    mac_r27_ephy[i].val);

	/* Clear extended address. */
	rge_write_ephy(sc, RGE_EPHYAR_EXT_ADDR, 0);
}

static int
rge_phy_config(struct rge_softc *sc)
{
	uint16_t val = 0;
	int i;

	rge_ephy_config(sc);

	/* PHY reset. */
	rge_write_phy(sc, 0, MII_ANAR,
	    rge_read_phy(sc, 0, MII_ANAR) &
	    ~(ANAR_TX_FD | ANAR_TX | ANAR_10_FD | ANAR_10));
	rge_write_phy(sc, 0, MII_100T2CR,
	    rge_read_phy(sc, 0, MII_100T2CR) &
	    ~(GTCR_ADV_1000TFDX | GTCR_ADV_1000THDX));
	switch (sc->rge_type) {
	case MAC_R27:
		val |= RGE_ADV_10000TFDX;
		/* fallthrough */
	case MAC_R26:
		val |= RGE_ADV_5000TFDX;
		/* fallthrough */
	default:
		val |= RGE_ADV_2500TFDX;
		break;
	}
	RGE_PHY_CLRBIT(sc, 0xa5d4, val);
	rge_write_phy(sc, 0, MII_BMCR, BMCR_RESET | BMCR_AUTOEN |
	    BMCR_STARTNEG);
	for (i = 0; i < 2500; i++) {
		if (!(rge_read_phy(sc, 0, MII_BMCR) & BMCR_RESET))
			break;
		DELAY(1000);
	}
	if (i == 2500) {
		device_printf(sc->sc_dev, "PHY reset failed\n");
		return (ETIMEDOUT);
	}

	/* Read ram code version. */
	rge_write_phy_ocp(sc, 0xa436, 0x801e);
	sc->rge_rcodever = rge_read_phy_ocp(sc, 0xa438);

	switch (sc->rge_type) {
	case MAC_R25:
		rge_phy_config_mac_r25(sc);
		break;
	case MAC_R25B:
		rge_phy_config_mac_r25b(sc);
		break;
	case MAC_R25D:
		rge_phy_config_mac_r25d(sc);
		break;
	case MAC_R26:
		rge_phy_config_mac_r26(sc);
		break;
	case MAC_R27:
		rge_phy_config_mac_r27(sc);
		break;
	default:
		break;	/* Can't happen. */
	}

	RGE_PHY_CLRBIT(sc, 0xa5b4, 0x8000);

	/* Disable EEE. */
	RGE_MAC_CLRBIT(sc, 0xe040, 0x0003);
	if (sc->rge_type == MAC_R25) {
		RGE_MAC_CLRBIT(sc, 0xeb62, 0x0006);
		RGE_PHY_CLRBIT(sc, 0xa432, 0x0010);
	} else if (sc->rge_type == MAC_R25B || sc->rge_type == MAC_R25D)
		RGE_PHY_SETBIT(sc, 0xa432, 0x0010);

	RGE_PHY_CLRBIT(sc, 0xa5d0, (sc->rge_type == MAC_R27) ? 0x000e : 0x0006);
	RGE_PHY_CLRBIT(sc, 0xa6d4, 0x0001);
	if (sc->rge_type == MAC_R26 || sc->rge_type == MAC_R27)
		RGE_PHY_CLRBIT(sc, 0xa6d4, 0x0002);
	RGE_PHY_CLRBIT(sc, 0xa6d8, 0x0010);
	RGE_PHY_CLRBIT(sc, 0xa428, 0x0080);
	RGE_PHY_CLRBIT(sc, 0xa4a2, 0x0200);

	/* Disable advanced EEE. */
	RGE_MAC_CLRBIT(sc, 0xe052, 0x0001);
	RGE_PHY_CLRBIT(sc, 0xa442, 0x3000);
	RGE_PHY_CLRBIT(sc, 0xa430, 0x8000);

	return (0);
}

static void
rge_phy_config_mac_r27(struct rge_softc *sc)
{
	uint16_t val;
	int i;
	static const uint16_t mac_cfg_value[] =
	    { 0x815a, 0x0150, 0x81f4, 0x0150, 0x828e, 0x0150, 0x81b1, 0x0000,
	      0x824b, 0x0000, 0x82e5, 0x0000 };

	static const uint16_t mac_cfg2_value[] =
	    { 0x88d7, 0x01a0, 0x88d9, 0x01a0, 0x8ffa, 0x002a, 0x8fee, 0xffdf,
	      0x8ff0, 0xffff, 0x8ff2, 0x0a4a, 0x8ff4, 0xaa5a, 0x8ff6, 0x0a4a,
	      0x8ff8, 0xaa5a };

	static const uint16_t mac_cfg_a438_value[] =
	    { 0x003b, 0x0086, 0x00b7, 0x00db, 0x00fe, 0x00fe, 0x00fe, 0x00fe,
	      0x00c3, 0x0078, 0x0047, 0x0023 };

	rge_phy_config_mcu(sc, RGE_MAC_R27_RCODE_VER);

	rge_write_phy_ocp(sc, 0xa4d2, 0x0000);
	rge_read_phy_ocp(sc, 0xa4d4);

	RGE_PHY_CLRBIT(sc, 0xa442, 0x0800);
	rge_write_phy_ocp(sc, 0xa436, 0x8415);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x9300);
	rge_write_phy_ocp(sc, 0xa436, 0x81a3);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x0f00);
	rge_write_phy_ocp(sc, 0xa436, 0x81ae);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x0f00);
	rge_write_phy_ocp(sc, 0xa436, 0x81b9);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0xb900);
	rge_write_phy_ocp(sc, 0xb87c, 0x83b0);
	RGE_PHY_CLRBIT(sc,0xb87e, 0x0e00);
	rge_write_phy_ocp(sc, 0xb87c, 0x83c5);
	RGE_PHY_CLRBIT(sc, 0xb87e, 0x0e00);
	rge_write_phy_ocp(sc, 0xb87c, 0x83da);
	RGE_PHY_CLRBIT(sc, 0xb87e, 0x0e00);
	rge_write_phy_ocp(sc, 0xb87c, 0x83ef);
	RGE_PHY_CLRBIT(sc, 0xb87e, 0x0e00);
	val = rge_read_phy_ocp(sc, 0xbf38) & ~0x01f0;
	rge_write_phy_ocp(sc, 0xbf38, val | 0x0160);
	val = rge_read_phy_ocp(sc, 0xbf3a) & ~0x001f;
	rge_write_phy_ocp(sc, 0xbf3a, val | 0x0014);
	RGE_PHY_CLRBIT(sc, 0xbf28, 0x6000);
	RGE_PHY_CLRBIT(sc, 0xbf2c, 0xc000);
	val = rge_read_phy_ocp(sc, 0xbf28) & ~0x1fff;
	rge_write_phy_ocp(sc, 0xbf28, val | 0x0187);
	val = rge_read_phy_ocp(sc, 0xbf2a) & ~0x003f;
	rge_write_phy_ocp(sc, 0xbf2a, val | 0x0003);
	rge_write_phy_ocp(sc, 0xa436, 0x8173);
	rge_write_phy_ocp(sc, 0xa438, 0x8620);
	rge_write_phy_ocp(sc, 0xa436, 0x8175);
	rge_write_phy_ocp(sc, 0xa438, 0x8671);
	rge_write_phy_ocp(sc, 0xa436, 0x817c);
	RGE_PHY_SETBIT(sc, 0xa438, 0x2000);
	rge_write_phy_ocp(sc, 0xa436, 0x8187);
	RGE_PHY_SETBIT(sc, 0xa438, 0x2000);
	rge_write_phy_ocp(sc, 0xA436, 0x8192);
	RGE_PHY_SETBIT(sc, 0xA438, 0x2000);
	rge_write_phy_ocp(sc, 0xA436, 0x819D);
	RGE_PHY_SETBIT(sc, 0xA438, 0x2000);
	rge_write_phy_ocp(sc, 0xA436, 0x81A8);
	RGE_PHY_CLRBIT(sc, 0xA438, 0x2000);
	rge_write_phy_ocp(sc, 0xA436, 0x81B3);
	RGE_PHY_CLRBIT(sc, 0xA438, 0x2000);
	rge_write_phy_ocp(sc, 0xA436, 0x81BE);
	RGE_PHY_SETBIT(sc, 0xA438, 0x2000);
	rge_write_phy_ocp(sc, 0xa436, 0x817d);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0xa600);
	rge_write_phy_ocp(sc, 0xa436, 0x8188);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0xa600);
	rge_write_phy_ocp(sc, 0xa436, 0x8193);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0xa600);
	rge_write_phy_ocp(sc, 0xa436, 0x819e);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0xa600);
	rge_write_phy_ocp(sc, 0xa436, 0x81a9);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x1400);
	rge_write_phy_ocp(sc, 0xa436, 0x81b4);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x1400);
	rge_write_phy_ocp(sc, 0xa436, 0x81bf);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0xa600);
	RGE_PHY_CLRBIT(sc, 0xaeaa, 0x0028);
	rge_write_phy_ocp(sc, 0xb87c, 0x84f0);
	rge_write_phy_ocp(sc, 0xb87e, 0x201c);
	rge_write_phy_ocp(sc, 0xb87c, 0x84f2);
	rge_write_phy_ocp(sc, 0xb87e, 0x3117);
	rge_write_phy_ocp(sc, 0xaec6, 0x0000);
	rge_write_phy_ocp(sc, 0xae20, 0xffff);
	rge_write_phy_ocp(sc, 0xaece, 0xffff);
	rge_write_phy_ocp(sc, 0xaed2, 0xffff);
	rge_write_phy_ocp(sc, 0xaec8, 0x0000);
	RGE_PHY_CLRBIT(sc, 0xaed0, 0x0001);
	rge_write_phy_ocp(sc, 0xadb8, 0x0150);
	rge_write_phy_ocp(sc, 0xb87c, 0x8197);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x5000);
	rge_write_phy_ocp(sc, 0xb87c, 0x8231);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x5000);
	rge_write_phy_ocp(sc, 0xb87c, 0x82cb);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x5000);
	rge_write_phy_ocp(sc, 0xb87c, 0x82cd);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x5700);
	rge_write_phy_ocp(sc, 0xb87c, 0x8233);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x5700);
	rge_write_phy_ocp(sc, 0xb87c, 0x8199);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x5700);
	for (i = 0; i < nitems(mac_cfg_value); i+=2) {
		rge_write_phy_ocp(sc, 0xb87c, mac_cfg_value[i]);
		rge_write_phy_ocp(sc, 0xb87e, mac_cfg_value[i + 1]);
	}
	rge_write_phy_ocp(sc, 0xb87c, 0x84f7);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x2800);
	RGE_PHY_SETBIT(sc, 0xaec2, 0x1000);
	rge_write_phy_ocp(sc, 0xb87c, 0x81b3);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0xad00);
	rge_write_phy_ocp(sc, 0xb87c, 0x824d);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0xad00);
	rge_write_phy_ocp(sc, 0xb87c, 0x82e7);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0xad00);
	val = rge_read_phy_ocp(sc, 0xae4e) & ~0x000f;
	rge_write_phy_ocp(sc, 0xae4e, val | 0x0001);
	rge_write_phy_ocp(sc, 0xb87c, 0x82ce);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xf000;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x4000);
	rge_write_phy_ocp(sc, 0xb87c, 0x84ac);
	rge_write_phy_ocp(sc, 0xb87e, 0x0000);
	rge_write_phy_ocp(sc, 0xb87c, 0x84ae);
	rge_write_phy_ocp(sc, 0xb87e, 0x0000);
	rge_write_phy_ocp(sc, 0xb87c, 0x84b0);
	rge_write_phy_ocp(sc, 0xb87e, 0xf818);
	rge_write_phy_ocp(sc, 0xb87c, 0x84b2);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x6000);
	rge_write_phy_ocp(sc, 0xb87c, 0x8ffc);
	rge_write_phy_ocp(sc, 0xb87e, 0x6008);
	rge_write_phy_ocp(sc, 0xb87c, 0x8ffe);
	rge_write_phy_ocp(sc, 0xb87e, 0xf450);
	rge_write_phy_ocp(sc, 0xb87c, 0x8015);
	RGE_PHY_SETBIT(sc, 0xb87e, 0x0200);
	rge_write_phy_ocp(sc, 0xb87c, 0x8016);
	RGE_PHY_CLRBIT(sc, 0xb87e, 0x0800);
	rge_write_phy_ocp(sc, 0xb87c, 0x8fe6);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0800);
	rge_write_phy_ocp(sc, 0xb87c, 0x8fe4);
	rge_write_phy_ocp(sc, 0xb87e, 0x2114);
	rge_write_phy_ocp(sc, 0xb87c, 0x8647);
	rge_write_phy_ocp(sc, 0xb87e, 0xa7B1);
	rge_write_phy_ocp(sc, 0xb87c, 0x8649);
	rge_write_phy_ocp(sc, 0xb87e, 0xbbca);
	rge_write_phy_ocp(sc, 0xb87c, 0x864b);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0xdc00);
	rge_write_phy_ocp(sc, 0xb87c, 0x8154);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xc000;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x4000);
	rge_write_phy_ocp(sc, 0xb87c, 0x8158);
	RGE_PHY_CLRBIT(sc, 0xb87e, 0xc000);
	rge_write_phy_ocp(sc, 0xb87c, 0x826c);
	rge_write_phy_ocp(sc, 0xb87e, 0xffff);
	rge_write_phy_ocp(sc, 0xb87c, 0x826e);
	rge_write_phy_ocp(sc, 0xb87e, 0xffff);
	rge_write_phy_ocp(sc, 0xb87c, 0x8872);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0e00);
	rge_write_phy_ocp(sc, 0xa436, 0x8012);
	RGE_PHY_SETBIT(sc, 0xa438, 0x0800);
	rge_write_phy_ocp(sc, 0xa436, 0x8012);
	RGE_PHY_SETBIT(sc, 0xa438, 0x4000);
	RGE_PHY_SETBIT(sc, 0xb576, 0x0001);
	rge_write_phy_ocp(sc, 0xa436, 0x834a);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x0700);
	rge_write_phy_ocp(sc, 0xb87c, 0x8217);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0x3f00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x2a00);
	rge_write_phy_ocp(sc, 0xa436, 0x81b1);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x0b00);
	rge_write_phy_ocp(sc, 0xb87c, 0x8fed);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x4e00);
	rge_write_phy_ocp(sc, 0xb87c, 0x88ac);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x2300);
	RGE_PHY_SETBIT(sc, 0xbf0c, 0x3800);
	rge_write_phy_ocp(sc, 0xb87c, 0x88de);
	RGE_PHY_CLRBIT(sc, 0xb87e, 0xFF00);
	rge_write_phy_ocp(sc, 0xb87c, 0x80B4);
	rge_write_phy_ocp(sc, 0xb87e, 0x5195);
	rge_write_phy_ocp(sc, 0xa436, 0x8370);
	rge_write_phy_ocp(sc, 0xa438, 0x8671);
	rge_write_phy_ocp(sc, 0xa436, 0x8372);
	rge_write_phy_ocp(sc, 0xa438, 0x86c8);
	rge_write_phy_ocp(sc, 0xa436, 0x8401);
	rge_write_phy_ocp(sc, 0xa438, 0x86c8);
	rge_write_phy_ocp(sc, 0xa436, 0x8403);
	rge_write_phy_ocp(sc, 0xa438, 0x86da);
	rge_write_phy_ocp(sc, 0xa436, 0x8406);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0x1800;
	rge_write_phy_ocp(sc, 0xa438, val | 0x1000);
	rge_write_phy_ocp(sc, 0xa436, 0x8408);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0x1800;
	rge_write_phy_ocp(sc, 0xa438, val | 0x1000);
	rge_write_phy_ocp(sc, 0xa436, 0x840a);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0x1800;
	rge_write_phy_ocp(sc, 0xa438, val | 0x1000);
	rge_write_phy_ocp(sc, 0xa436, 0x840c);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0x1800;
	rge_write_phy_ocp(sc, 0xa438, val | 0x1000);
	rge_write_phy_ocp(sc, 0xa436, 0x840e);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0x1800;
	rge_write_phy_ocp(sc, 0xa438, val | 0x1000);
	rge_write_phy_ocp(sc, 0xa436, 0x8410);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0x1800;
	rge_write_phy_ocp(sc, 0xa438, val | 0x1000);
	rge_write_phy_ocp(sc, 0xa436, 0x8412);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0x1800;
	rge_write_phy_ocp(sc, 0xa438, val | 0x1000);
	rge_write_phy_ocp(sc, 0xa436, 0x8414);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0x1800;
	rge_write_phy_ocp(sc, 0xa438, val | 0x1000);
	rge_write_phy_ocp(sc, 0xa436, 0x8416);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0x1800;
	rge_write_phy_ocp(sc, 0xa438, val | 0x1000);
	rge_write_phy_ocp(sc, 0xa436, 0x82bd);
	rge_write_phy_ocp(sc, 0xa438, 0x1f40);
	val = rge_read_phy_ocp(sc, 0xbfb4) & ~0x07ff;
	rge_write_phy_ocp(sc, 0xbfb4, val | 0x0328);
	rge_write_phy_ocp(sc, 0xbfb6, 0x3e14);
	rge_write_phy_ocp(sc, 0xa436, 0x81c4);
	for (i = 0; i < nitems(mac_cfg_a438_value); i++)
		rge_write_phy_ocp(sc, 0xa438, mac_cfg_a438_value[i]);
	for (i = 0; i < nitems(mac_cfg2_value); i+=2) {
		rge_write_phy_ocp(sc, 0xb87c, mac_cfg2_value[i]);
		rge_write_phy_ocp(sc, 0xb87e, mac_cfg2_value[i + 1]);
	}
	rge_write_phy_ocp(sc, 0xb87c, 0x88d5);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0200);
	rge_write_phy_ocp(sc, 0xa436, 0x84bb);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x0a00);
	rge_write_phy_ocp(sc, 0xa436, 0x84c0);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x1600);
	RGE_PHY_SETBIT(sc, 0xa430, 0x0003);
}

static void
rge_phy_config_mac_r26(struct rge_softc *sc)
{
	uint16_t val;
	int i;
	static const uint16_t mac_cfg2_a438_value[] =
	    { 0x0044, 0x00a8, 0x00d6, 0x00ec, 0x00f6, 0x00fc, 0x00fe,
	      0x00fe, 0x00bc, 0x0058, 0x002a, 0x003f, 0x3f02, 0x023c,
	      0x3b0a, 0x1c00, 0x0000, 0x0000, 0x0000, 0x0000 };

	static const uint16_t mac_cfg2_b87e_value[] =
	    { 0x03ed, 0x03ff, 0x0009, 0x03fe, 0x000b, 0x0021, 0x03f7,
	      0x03b8, 0x03e0, 0x0049, 0x0049, 0x03e0, 0x03b8, 0x03f7,
	      0x0021, 0x000b, 0x03fe, 0x0009, 0x03ff, 0x03ed, 0x000e,
	      0x03fe, 0x03ed, 0x0006, 0x001a, 0x03f1, 0x03d8, 0x0023,
	      0x0054, 0x0322, 0x00dd, 0x03ab, 0x03dc, 0x0027, 0x000e,
	      0x03e5, 0x03f9, 0x0012, 0x0001, 0x03f1 };

	rge_phy_config_mcu(sc, RGE_MAC_R26_RCODE_VER);

	RGE_PHY_SETBIT(sc, 0xa442, 0x0800);
	rge_write_phy_ocp(sc, 0xa436, 0x80bf);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0xed00);
	rge_write_phy_ocp(sc, 0xa436, 0x80cd);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x1000);
	rge_write_phy_ocp(sc, 0xa436, 0x80d1);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0xc800);
	rge_write_phy_ocp(sc, 0xa436, 0x80d4);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0xc800);
	rge_write_phy_ocp(sc, 0xa436, 0x80e1);
	rge_write_phy_ocp(sc, 0xa438, 0x10cc);
	rge_write_phy_ocp(sc, 0xa436, 0x80e5);
	rge_write_phy_ocp(sc, 0xa438, 0x4f0c);
	rge_write_phy_ocp(sc, 0xa436, 0x8387);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x4700);
	val = rge_read_phy_ocp(sc, 0xa80c) & ~0x00c0;
	rge_write_phy_ocp(sc, 0xa80c, val | 0x0080);
	RGE_PHY_CLRBIT(sc, 0xac90, 0x0010);
	RGE_PHY_CLRBIT(sc, 0xad2c, 0x8000);
	rge_write_phy_ocp(sc, 0xb87c, 0x8321);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x1100);
	RGE_PHY_SETBIT(sc, 0xacf8, 0x000c);
	rge_write_phy_ocp(sc, 0xa436, 0x8183);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x5900);
	RGE_PHY_SETBIT(sc, 0xad94, 0x0020);
	RGE_PHY_CLRBIT(sc, 0xa654, 0x0800);
	RGE_PHY_SETBIT(sc, 0xb648, 0x4000);
	rge_write_phy_ocp(sc, 0xb87c, 0x839e);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x2f00);
	rge_write_phy_ocp(sc, 0xb87c, 0x83f2);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0800);
	RGE_PHY_SETBIT(sc, 0xada0, 0x0002);
	rge_write_phy_ocp(sc, 0xb87c, 0x80f3);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x9900);
	rge_write_phy_ocp(sc, 0xb87c, 0x8126);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0xc100);
	rge_write_phy_ocp(sc, 0xb87c, 0x893a);
	rge_write_phy_ocp(sc, 0xb87e, 0x8080);
	rge_write_phy_ocp(sc, 0xb87c, 0x8647);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0xe600);
	rge_write_phy_ocp(sc, 0xb87c, 0x862c);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x1200);
	rge_write_phy_ocp(sc, 0xb87c, 0x864a);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0xe600);
	rge_write_phy_ocp(sc, 0xb87c, 0x80a0);
	rge_write_phy_ocp(sc, 0xb87e, 0xbcbc);
	rge_write_phy_ocp(sc, 0xb87c, 0x805e);
	rge_write_phy_ocp(sc, 0xb87e, 0xbcbc);
	rge_write_phy_ocp(sc, 0xb87c, 0x8056);
	rge_write_phy_ocp(sc, 0xb87e, 0x3077);
	rge_write_phy_ocp(sc, 0xb87c, 0x8058);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x5a00);
	rge_write_phy_ocp(sc, 0xb87c, 0x8098);
	rge_write_phy_ocp(sc, 0xb87e, 0x3077);
	rge_write_phy_ocp(sc, 0xb87c, 0x809a);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x5a00);
	rge_write_phy_ocp(sc, 0xb87c, 0x8052);
	rge_write_phy_ocp(sc, 0xb87e, 0x3733);
	rge_write_phy_ocp(sc, 0xb87c, 0x8094);
	rge_write_phy_ocp(sc, 0xb87e, 0x3733);
	rge_write_phy_ocp(sc, 0xb87c, 0x807f);
	rge_write_phy_ocp(sc, 0xb87e, 0x7c75);
	rge_write_phy_ocp(sc, 0xb87c, 0x803d);
	rge_write_phy_ocp(sc, 0xb87e, 0x7c75);
	rge_write_phy_ocp(sc, 0xb87c, 0x8036);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x3000);
	rge_write_phy_ocp(sc, 0xb87c, 0x8078);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x3000);
	rge_write_phy_ocp(sc, 0xb87c, 0x8031);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x3300);
	rge_write_phy_ocp(sc, 0xb87c, 0x8073);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x3300);
	val = rge_read_phy_ocp(sc, 0xae06) & ~0xfc00;
	rge_write_phy_ocp(sc, 0xae06, val | 0x7c00);
	rge_write_phy_ocp(sc, 0xb87c, 0x89D1);
	rge_write_phy_ocp(sc, 0xb87e, 0x0004);
	rge_write_phy_ocp(sc, 0xa436, 0x8fbd);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x0a00);
	rge_write_phy_ocp(sc, 0xa436, 0x8fbe);
	rge_write_phy_ocp(sc, 0xa438, 0x0d09);
	rge_write_phy_ocp(sc, 0xb87c, 0x89cd);
	rge_write_phy_ocp(sc, 0xb87e, 0x0f0f);
	rge_write_phy_ocp(sc, 0xb87c, 0x89cf);
	rge_write_phy_ocp(sc, 0xb87e, 0x0f0f);
	rge_write_phy_ocp(sc, 0xb87c, 0x83a4);
	rge_write_phy_ocp(sc, 0xb87e, 0x6600);
	rge_write_phy_ocp(sc, 0xb87c, 0x83a6);
	rge_write_phy_ocp(sc, 0xb87e, 0x6601);
	rge_write_phy_ocp(sc, 0xb87c, 0x83c0);
	rge_write_phy_ocp(sc, 0xb87e, 0x6600);
	rge_write_phy_ocp(sc, 0xb87c, 0x83c2);
	rge_write_phy_ocp(sc, 0xb87e, 0x6601);
	rge_write_phy_ocp(sc, 0xb87c, 0x8414);
	rge_write_phy_ocp(sc, 0xb87e, 0x6600);
	rge_write_phy_ocp(sc, 0xb87c, 0x8416);
	rge_write_phy_ocp(sc, 0xb87e, 0x6601);
	rge_write_phy_ocp(sc, 0xb87c, 0x83f8);
	rge_write_phy_ocp(sc, 0xb87e, 0x6600);
	rge_write_phy_ocp(sc, 0xb87c, 0x83fa);
	rge_write_phy_ocp(sc, 0xb87e, 0x6601);

	rge_patch_phy_mcu(sc, 1);
	val = rge_read_phy_ocp(sc, 0xbd96) & ~0x1f00;
	rge_write_phy_ocp(sc, 0xbd96, val | 0x1000);
	val = rge_read_phy_ocp(sc, 0xbf1c) & ~0x0007;
	rge_write_phy_ocp(sc, 0xbf1c, val | 0x0007);
	RGE_PHY_CLRBIT(sc, 0xbfbe, 0x8000);
	val = rge_read_phy_ocp(sc, 0xbf40) & ~0x0380;
	rge_write_phy_ocp(sc, 0xbf40, val | 0x0280);
	val = rge_read_phy_ocp(sc, 0xbf90) & ~0x0080;
	rge_write_phy_ocp(sc, 0xbf90, val | 0x0060);
	val = rge_read_phy_ocp(sc, 0xbf90) & ~0x0010;
	rge_write_phy_ocp(sc, 0xbf90, val | 0x000c);
	rge_patch_phy_mcu(sc, 0);

	rge_write_phy_ocp(sc, 0xa436, 0x843b);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x2000);
	rge_write_phy_ocp(sc, 0xa436, 0x843d);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x2000);
	RGE_PHY_CLRBIT(sc, 0xb516, 0x007f);
	RGE_PHY_CLRBIT(sc, 0xbf80, 0x0030);

	rge_write_phy_ocp(sc, 0xa436, 0x8188);
	for (i = 0; i < 11; i++)
		rge_write_phy_ocp(sc, 0xa438, mac_cfg2_a438_value[i]);

	rge_write_phy_ocp(sc, 0xb87c, 0x8015);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0800);
	rge_write_phy_ocp(sc, 0xb87c, 0x8ffd);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0);
	rge_write_phy_ocp(sc, 0xb87c, 0x8fff);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x7f00);
	rge_write_phy_ocp(sc, 0xb87c, 0x8ffb);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0100);
	rge_write_phy_ocp(sc, 0xb87c, 0x8fe9);
	rge_write_phy_ocp(sc, 0xb87e, 0x0002);
	rge_write_phy_ocp(sc, 0xb87c, 0x8fef);
	rge_write_phy_ocp(sc, 0xb87e, 0x00a5);
	rge_write_phy_ocp(sc, 0xb87c, 0x8ff1);
	rge_write_phy_ocp(sc, 0xb87e, 0x0106);
	rge_write_phy_ocp(sc, 0xb87c, 0x8fe1);
	rge_write_phy_ocp(sc, 0xb87e, 0x0102);
	rge_write_phy_ocp(sc, 0xb87c, 0x8fe3);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0400);
	RGE_PHY_SETBIT(sc, 0xa654, 0x0800);
	RGE_PHY_CLRBIT(sc, 0xa654, 0x0003);
	rge_write_phy_ocp(sc, 0xac3a, 0x5851);
	val = rge_read_phy_ocp(sc, 0xac3c) & ~0xd000;
	rge_write_phy_ocp(sc, 0xac3c, val | 0x2000);
	val = rge_read_phy_ocp(sc, 0xac42) & ~0x0200;
	rge_write_phy_ocp(sc, 0xac42, val | 0x01c0);
	RGE_PHY_CLRBIT(sc, 0xac3e, 0xe000);
	RGE_PHY_CLRBIT(sc, 0xac42, 0x0038);
	val = rge_read_phy_ocp(sc, 0xac42) & ~0x0002;
	rge_write_phy_ocp(sc, 0xac42, val | 0x0005);
	rge_write_phy_ocp(sc, 0xac1a, 0x00db);
	rge_write_phy_ocp(sc, 0xade4, 0x01b5);
	RGE_PHY_CLRBIT(sc, 0xad9c, 0x0c00);
	rge_write_phy_ocp(sc, 0xb87c, 0x814b);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x1100);
	rge_write_phy_ocp(sc, 0xb87c, 0x814d);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x1100);
	rge_write_phy_ocp(sc, 0xb87c, 0x814f);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0b00);
	rge_write_phy_ocp(sc, 0xb87c, 0x8142);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0100);
	rge_write_phy_ocp(sc, 0xb87c, 0x8144);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0100);
	rge_write_phy_ocp(sc, 0xb87c, 0x8150);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0100);
	rge_write_phy_ocp(sc, 0xb87c, 0x8118);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0700);
	rge_write_phy_ocp(sc, 0xb87c, 0x811a);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0700);
	rge_write_phy_ocp(sc, 0xb87c, 0x811c);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0500);
	rge_write_phy_ocp(sc, 0xb87c, 0x810f);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0100);
	rge_write_phy_ocp(sc, 0xb87c, 0x8111);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0100);
	rge_write_phy_ocp(sc, 0xb87c, 0x811d);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0100);
	RGE_PHY_SETBIT(sc, 0xac36, 0x1000);
	RGE_PHY_CLRBIT(sc, 0xad1c, 0x0100);
	val = rge_read_phy_ocp(sc, 0xade8) & ~0xffc0;
	rge_write_phy_ocp(sc, 0xade8, val | 0x1400);
	rge_write_phy_ocp(sc, 0xb87c, 0x864b);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x9d00);

	rge_write_phy_ocp(sc, 0xa436, 0x8f97);
	for (; i < nitems(mac_cfg2_a438_value); i++)
		rge_write_phy_ocp(sc, 0xa438, mac_cfg2_a438_value[i]);

	RGE_PHY_SETBIT(sc, 0xad9c, 0x0020);
	rge_write_phy_ocp(sc, 0xb87c, 0x8122);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0c00);

	rge_write_phy_ocp(sc, 0xb87c, 0x82c8);
	for (i = 0; i < 20; i++)
		rge_write_phy_ocp(sc, 0xb87e, mac_cfg2_b87e_value[i]);

	rge_write_phy_ocp(sc, 0xb87c, 0x80ef);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0c00);

	rge_write_phy_ocp(sc, 0xb87c, 0x82a0);
	for (; i < nitems(mac_cfg2_b87e_value); i++)
		rge_write_phy_ocp(sc, 0xb87e, mac_cfg2_b87e_value[i]);

	rge_write_phy_ocp(sc, 0xa436, 0x8018);
	RGE_PHY_SETBIT(sc, 0xa438, 0x2000);
	rge_write_phy_ocp(sc, 0xb87c, 0x8fe4);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0);
	val = rge_read_phy_ocp(sc, 0xb54c) & ~0xffc0;
	rge_write_phy_ocp(sc, 0xb54c, val | 0x3700);
}

static void
rge_phy_config_mac_r25(struct rge_softc *sc)
{
	uint16_t val;
	int i;
	static const uint16_t mac_cfg3_a438_value[] =
	    { 0x0043, 0x00a7, 0x00d6, 0x00ec, 0x00f6, 0x00fb, 0x00fd, 0x00ff,
	      0x00bb, 0x0058, 0x0029, 0x0013, 0x0009, 0x0004, 0x0002 };

	static const uint16_t mac_cfg3_b88e_value[] =
	    { 0xc091, 0x6e12, 0xc092, 0x1214, 0xc094, 0x1516, 0xc096, 0x171b,
	      0xc098, 0x1b1c, 0xc09a, 0x1f1f, 0xc09c, 0x2021, 0xc09e, 0x2224,
	      0xc0a0, 0x2424, 0xc0a2, 0x2424, 0xc0a4, 0x2424, 0xc018, 0x0af2,
	      0xc01a, 0x0d4a, 0xc01c, 0x0f26, 0xc01e, 0x118d, 0xc020, 0x14f3,
	      0xc022, 0x175a, 0xc024, 0x19c0, 0xc026, 0x1c26, 0xc089, 0x6050,
	      0xc08a, 0x5f6e, 0xc08c, 0x6e6e, 0xc08e, 0x6e6e, 0xc090, 0x6e12 };

	rge_phy_config_mcu(sc, RGE_MAC_R25_RCODE_VER);

	RGE_PHY_SETBIT(sc, 0xad4e, 0x0010);
	val = rge_read_phy_ocp(sc, 0xad16) & ~0x03ff;
	rge_write_phy_ocp(sc, 0xad16, val | 0x03ff);
	val = rge_read_phy_ocp(sc, 0xad32) & ~0x003f;
	rge_write_phy_ocp(sc, 0xad32, val | 0x0006);
	RGE_PHY_CLRBIT(sc, 0xac08, 0x1000);
	RGE_PHY_CLRBIT(sc, 0xac08, 0x0100);
	val = rge_read_phy_ocp(sc, 0xacc0) & ~0x0003;
	rge_write_phy_ocp(sc, 0xacc0, val | 0x0002);
	val = rge_read_phy_ocp(sc, 0xad40) & ~0x00e0;
	rge_write_phy_ocp(sc, 0xad40, val | 0x0040);
	val = rge_read_phy_ocp(sc, 0xad40) & ~0x0007;
	rge_write_phy_ocp(sc, 0xad40, val | 0x0004);
	RGE_PHY_CLRBIT(sc, 0xac14, 0x0080);
	RGE_PHY_CLRBIT(sc, 0xac80, 0x0300);
	val = rge_read_phy_ocp(sc, 0xac5e) & ~0x0007;
	rge_write_phy_ocp(sc, 0xac5e, val | 0x0002);
	rge_write_phy_ocp(sc, 0xad4c, 0x00a8);
	rge_write_phy_ocp(sc, 0xac5c, 0x01ff);
	val = rge_read_phy_ocp(sc, 0xac8a) & ~0x00f0;
	rge_write_phy_ocp(sc, 0xac8a, val | 0x0030);
	rge_write_phy_ocp(sc, 0xb87c, 0x8157);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0500);
	rge_write_phy_ocp(sc, 0xb87c, 0x8159);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0700);
	rge_write_phy_ocp(sc, 0xb87c, 0x80a2);
	rge_write_phy_ocp(sc, 0xb87e, 0x0153);
	rge_write_phy_ocp(sc, 0xb87c, 0x809c);
	rge_write_phy_ocp(sc, 0xb87e, 0x0153);

	rge_write_phy_ocp(sc, 0xa436, 0x81b3);
	for (i = 0; i < nitems(mac_cfg3_a438_value); i++)
		rge_write_phy_ocp(sc, 0xa438, mac_cfg3_a438_value[i]);
	for (i = 0; i < 26; i++)
		rge_write_phy_ocp(sc, 0xa438, 0);
	rge_write_phy_ocp(sc, 0xa436, 0x8257);
	rge_write_phy_ocp(sc, 0xa438, 0x020f);
	rge_write_phy_ocp(sc, 0xa436, 0x80ea);
	rge_write_phy_ocp(sc, 0xa438, 0x7843);

	rge_patch_phy_mcu(sc, 1);
	RGE_PHY_CLRBIT(sc, 0xb896, 0x0001);
	RGE_PHY_CLRBIT(sc, 0xb892, 0xff00);
	for (i = 0; i < nitems(mac_cfg3_b88e_value); i += 2) {
		rge_write_phy_ocp(sc, 0xb88e, mac_cfg3_b88e_value[i]);
		rge_write_phy_ocp(sc, 0xb890, mac_cfg3_b88e_value[i + 1]);
	}
	RGE_PHY_SETBIT(sc, 0xb896, 0x0001);
	rge_patch_phy_mcu(sc, 0);

	RGE_PHY_SETBIT(sc, 0xd068, 0x2000);
	rge_write_phy_ocp(sc, 0xa436, 0x81a2);
	RGE_PHY_SETBIT(sc, 0xa438, 0x0100);
	val = rge_read_phy_ocp(sc, 0xb54c) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb54c, val | 0xdb00);
	RGE_PHY_CLRBIT(sc, 0xa454, 0x0001);
	RGE_PHY_SETBIT(sc, 0xa5d4, 0x0020);
	RGE_PHY_CLRBIT(sc, 0xad4e, 0x0010);
	RGE_PHY_CLRBIT(sc, 0xa86a, 0x0001);
	RGE_PHY_SETBIT(sc, 0xa442, 0x0800);
	RGE_PHY_SETBIT(sc, 0xa424, 0x0008);
}

static void
rge_phy_config_mac_r25b(struct rge_softc *sc)
{
	uint16_t val;
	int i;

	rge_phy_config_mcu(sc, RGE_MAC_R25B_RCODE_VER);

	RGE_PHY_SETBIT(sc, 0xa442, 0x0800);
	val = rge_read_phy_ocp(sc, 0xac46) & ~0x00f0;
	rge_write_phy_ocp(sc, 0xac46, val | 0x0090);
	val = rge_read_phy_ocp(sc, 0xad30) & ~0x0003;
	rge_write_phy_ocp(sc, 0xad30, val | 0x0001);
	rge_write_phy_ocp(sc, 0xb87c, 0x80f5);
	rge_write_phy_ocp(sc, 0xb87e, 0x760e);
	rge_write_phy_ocp(sc, 0xb87c, 0x8107);
	rge_write_phy_ocp(sc, 0xb87e, 0x360e);
	rge_write_phy_ocp(sc, 0xb87c, 0x8551);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0800);
	val = rge_read_phy_ocp(sc, 0xbf00) & ~0xe000;
	rge_write_phy_ocp(sc, 0xbf00, val | 0xa000);
	val = rge_read_phy_ocp(sc, 0xbf46) & ~0x0f00;
	rge_write_phy_ocp(sc, 0xbf46, val | 0x0300);
	for (i = 0; i < 10; i++) {
		rge_write_phy_ocp(sc, 0xa436, 0x8044 + i * 6);
		rge_write_phy_ocp(sc, 0xa438, 0x2417);
	}
	RGE_PHY_SETBIT(sc, 0xa4ca, 0x0040);
	val = rge_read_phy_ocp(sc, 0xbf84) & ~0xe000;
	rge_write_phy_ocp(sc, 0xbf84, val | 0xa000);
	rge_write_phy_ocp(sc, 0xa436, 0x8170);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0x2700;
	rge_write_phy_ocp(sc, 0xa438, val | 0xd800);
	RGE_PHY_SETBIT(sc, 0xa424, 0x0008);
}

static void
rge_phy_config_mac_r25d(struct rge_softc *sc)
{
	uint16_t val;
	int i;

	rge_phy_config_mcu(sc, RGE_MAC_R25D_RCODE_VER);

	RGE_PHY_SETBIT(sc, 0xa442, 0x0800);

	rge_patch_phy_mcu(sc, 1);
	RGE_PHY_SETBIT(sc, 0xbf96, 0x8000);
	val = rge_read_phy_ocp(sc, 0xbf94) & ~0x0007;
	rge_write_phy_ocp(sc, 0xbf94, val | 0x0005);
	val = rge_read_phy_ocp(sc, 0xbf8e) & ~0x3c00;
	rge_write_phy_ocp(sc, 0xbf8e, val | 0x2800);
	val = rge_read_phy_ocp(sc, 0xbcd8) & ~0xc000;
	rge_write_phy_ocp(sc, 0xbcd8, val | 0x4000);
	RGE_PHY_SETBIT(sc, 0xbcd8, 0xc000);
	val = rge_read_phy_ocp(sc, 0xbcd8) & ~0xc000;
	rge_write_phy_ocp(sc, 0xbcd8, val | 0x4000);
	val = rge_read_phy_ocp(sc, 0xbc80) & ~0x001f;
	rge_write_phy_ocp(sc, 0xbc80, val | 0x0004);
	RGE_PHY_SETBIT(sc, 0xbc82, 0xe000);
	RGE_PHY_SETBIT(sc, 0xbc82, 0x1c00);
	val = rge_read_phy_ocp(sc, 0xbc80) & ~0x001f;
	rge_write_phy_ocp(sc, 0xbc80, val | 0x0005);
	val = rge_read_phy_ocp(sc, 0xbc82) & ~0x00e0;
	rge_write_phy_ocp(sc, 0xbc82, val | 0x0040);
	RGE_PHY_SETBIT(sc, 0xbc82, 0x001c);
	RGE_PHY_CLRBIT(sc, 0xbcd8, 0xc000);
	val = rge_read_phy_ocp(sc, 0xbcd8) & ~0xc000;
	rge_write_phy_ocp(sc, 0xbcd8, val | 0x8000);
	RGE_PHY_CLRBIT(sc, 0xbcd8, 0xc000);
	RGE_PHY_CLRBIT(sc, 0xbd70, 0x0100);
	RGE_PHY_SETBIT(sc, 0xa466, 0x0002);
	rge_write_phy_ocp(sc, 0xa436, 0x836a);
	RGE_PHY_CLRBIT(sc, 0xa438, 0xff00);
	rge_patch_phy_mcu(sc, 0);

	rge_write_phy_ocp(sc, 0xb87c, 0x832c);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0500);
	val = rge_read_phy_ocp(sc, 0xb106) & ~0x0700;
	rge_write_phy_ocp(sc, 0xb106, val | 0x0100);
	val = rge_read_phy_ocp(sc, 0xb206) & ~0x0700;
	rge_write_phy_ocp(sc, 0xb206, val | 0x0200);
	val = rge_read_phy_ocp(sc, 0xb306) & ~0x0700;
	rge_write_phy_ocp(sc, 0xb306, val | 0x0300);
	rge_write_phy_ocp(sc, 0xb87c, 0x80cb);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0300);
	rge_write_phy_ocp(sc, 0xbcf4, 0x0000);
	rge_write_phy_ocp(sc, 0xbcf6, 0x0000);
	rge_write_phy_ocp(sc, 0xbc12, 0x0000);
	rge_write_phy_ocp(sc, 0xb87c, 0x844d);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0200);

	rge_write_phy_ocp(sc, 0xb87c, 0x8feb);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0100);
	rge_write_phy_ocp(sc, 0xb87c, 0x8fe9);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x0600);

	val = rge_read_phy_ocp(sc, 0xac7e) & ~0x01fc;
	rge_write_phy_ocp(sc, 0xac7e, val | 0x00B4);
	rge_write_phy_ocp(sc, 0xb87c, 0x8105);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x7a00);
	rge_write_phy_ocp(sc, 0xb87c, 0x8117);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x3a00);
	rge_write_phy_ocp(sc, 0xb87c, 0x8103);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x7400);
	rge_write_phy_ocp(sc, 0xb87c, 0x8115);
	val = rge_read_phy_ocp(sc, 0xb87e) & ~0xff00;
	rge_write_phy_ocp(sc, 0xb87e, val | 0x3400);
	RGE_PHY_CLRBIT(sc, 0xad40, 0x0030);
	val = rge_read_phy_ocp(sc, 0xad66) & ~0x000f;
	rge_write_phy_ocp(sc, 0xad66, val | 0x0007);
	val = rge_read_phy_ocp(sc, 0xad68) & ~0xf000;
	rge_write_phy_ocp(sc, 0xad68, val | 0x8000);
	val = rge_read_phy_ocp(sc, 0xad68) & ~0x0f00;
	rge_write_phy_ocp(sc, 0xad68, val | 0x0500);
	val = rge_read_phy_ocp(sc, 0xad68) & ~0x000f;
	rge_write_phy_ocp(sc, 0xad68, val | 0x0002);
	val = rge_read_phy_ocp(sc, 0xad6a) & ~0xf000;
	rge_write_phy_ocp(sc, 0xad6a, val | 0x7000);
	rge_write_phy_ocp(sc, 0xac50, 0x01e8);
	rge_write_phy_ocp(sc, 0xa436, 0x81fa);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x5400);
	val = rge_read_phy_ocp(sc, 0xa864) & ~0x00f0;
	rge_write_phy_ocp(sc, 0xa864, val | 0x00c0);
	val = rge_read_phy_ocp(sc, 0xa42c) & ~0x00ff;
	rge_write_phy_ocp(sc, 0xa42c, val | 0x0002);
	rge_write_phy_ocp(sc, 0xa436, 0x80e1);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x0f00);
	rge_write_phy_ocp(sc, 0xa436, 0x80de);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xf000;
	rge_write_phy_ocp(sc, 0xa438, val | 0x0700);
	RGE_PHY_SETBIT(sc, 0xa846, 0x0080);
	rge_write_phy_ocp(sc, 0xa436, 0x80ba);
	rge_write_phy_ocp(sc, 0xa438, 0x8a04);
	rge_write_phy_ocp(sc, 0xa436, 0x80bd);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0xca00);
	rge_write_phy_ocp(sc, 0xa436, 0x80b7);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0xb300);
	rge_write_phy_ocp(sc, 0xa436, 0x80ce);
	rge_write_phy_ocp(sc, 0xa438, 0x8a04);
	rge_write_phy_ocp(sc, 0xa436, 0x80d1);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0xca00);
	rge_write_phy_ocp(sc, 0xa436, 0x80cb);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0xbb00);
	rge_write_phy_ocp(sc, 0xa436, 0x80a6);
	rge_write_phy_ocp(sc, 0xa438, 0x4909);
	rge_write_phy_ocp(sc, 0xa436, 0x80a8);
	rge_write_phy_ocp(sc, 0xa438, 0x05b8);
	rge_write_phy_ocp(sc, 0xa436, 0x8200);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x5800);
	rge_write_phy_ocp(sc, 0xa436, 0x8ff1);
	rge_write_phy_ocp(sc, 0xa438, 0x7078);
	rge_write_phy_ocp(sc, 0xa436, 0x8ff3);
	rge_write_phy_ocp(sc, 0xa438, 0x5d78);
	rge_write_phy_ocp(sc, 0xa436, 0x8ff5);
	rge_write_phy_ocp(sc, 0xa438, 0x7862);
	rge_write_phy_ocp(sc, 0xa436, 0x8ff7);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x1400);

	rge_write_phy_ocp(sc, 0xa436, 0x814c);
	rge_write_phy_ocp(sc, 0xa438, 0x8455);
	rge_write_phy_ocp(sc, 0xa436, 0x814e);
	rge_write_phy_ocp(sc, 0xa438, 0x84a6);
	rge_write_phy_ocp(sc, 0xa436, 0x8163);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x0600);
	rge_write_phy_ocp(sc, 0xa436, 0x816a);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x0500);
	rge_write_phy_ocp(sc, 0xa436, 0x8171);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x1f00);

	val = rge_read_phy_ocp(sc, 0xbc3a) & ~0x000f;
	rge_write_phy_ocp(sc, 0xbc3a, val | 0x0006);
	for (i = 0; i < 10; i++) {
		rge_write_phy_ocp(sc, 0xa436, 0x8064 + i * 3);
		RGE_PHY_CLRBIT(sc, 0xa438, 0x0700);
	}
	val = rge_read_phy_ocp(sc, 0xbfa0) & ~0xff70;
	rge_write_phy_ocp(sc, 0xbfa0, val | 0x5500);
	rge_write_phy_ocp(sc, 0xbfa2, 0x9d00);
	rge_write_phy_ocp(sc, 0xa436, 0x8165);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0x0700;
	rge_write_phy_ocp(sc, 0xa438, val | 0x0200);

	rge_write_phy_ocp(sc, 0xa436, 0x8019);
	RGE_PHY_SETBIT(sc, 0xa438, 0x0100);
	rge_write_phy_ocp(sc, 0xa436, 0x8fe3);
	rge_write_phy_ocp(sc, 0xa438, 0x0005);
	rge_write_phy_ocp(sc, 0xa438, 0x0000);
	rge_write_phy_ocp(sc, 0xa438, 0x00ed);
	rge_write_phy_ocp(sc, 0xa438, 0x0502);
	rge_write_phy_ocp(sc, 0xa438, 0x0b00);
	rge_write_phy_ocp(sc, 0xa438, 0xd401);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x2900);

	rge_write_phy_ocp(sc, 0xa436, 0x8018);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x1700);

	rge_write_phy_ocp(sc, 0xa436, 0x815b);
	val = rge_read_phy_ocp(sc, 0xa438) & ~0xff00;
	rge_write_phy_ocp(sc, 0xa438, val | 0x1700);

	RGE_PHY_CLRBIT(sc, 0xa4e0, 0x8000);
	RGE_PHY_CLRBIT(sc, 0xa5d4, 0x0020);
	RGE_PHY_CLRBIT(sc, 0xa654, 0x0800);
	RGE_PHY_SETBIT(sc, 0xa430, 0x1001);
	RGE_PHY_SETBIT(sc, 0xa442, 0x0080);
}

static void
rge_phy_config_mcu(struct rge_softc *sc, uint16_t rcodever)
{
	if (sc->rge_rcodever != rcodever) {
		int i;

		rge_patch_phy_mcu(sc, 1);

		if (sc->rge_type == MAC_R25) {
			rge_write_phy_ocp(sc, 0xa436, 0x8024);
			rge_write_phy_ocp(sc, 0xa438, 0x8601);
			rge_write_phy_ocp(sc, 0xa436, 0xb82e);
			rge_write_phy_ocp(sc, 0xa438, 0x0001);

			RGE_PHY_SETBIT(sc, 0xb820, 0x0080);

			for (i = 0; i < nitems(mac_r25_mcu); i++)
				rge_write_phy_ocp(sc,
				    mac_r25_mcu[i].reg, mac_r25_mcu[i].val);

			RGE_PHY_CLRBIT(sc, 0xb820, 0x0080);

			rge_write_phy_ocp(sc, 0xa436, 0);
			rge_write_phy_ocp(sc, 0xa438, 0);
			RGE_PHY_CLRBIT(sc, 0xb82e, 0x0001);
			rge_write_phy_ocp(sc, 0xa436, 0x8024);
			rge_write_phy_ocp(sc, 0xa438, 0);
		} else if (sc->rge_type == MAC_R25B) {
			for (i = 0; i < nitems(mac_r25b_mcu); i++)
				rge_write_phy_ocp(sc,
				    mac_r25b_mcu[i].reg, mac_r25b_mcu[i].val);
		} else if (sc->rge_type == MAC_R25D) {
			for (i = 0; i < 2403; i++)
				rge_write_phy_ocp(sc,
				    mac_r25d_mcu[i].reg, mac_r25d_mcu[i].val);
			rge_patch_phy_mcu(sc, 0);

			rge_patch_phy_mcu(sc, 1);
			for (; i < 2528; i++)
				rge_write_phy_ocp(sc,
				    mac_r25d_mcu[i].reg, mac_r25d_mcu[i].val);
			rge_patch_phy_mcu(sc, 0);

			rge_patch_phy_mcu(sc, 1);
			for (; i < nitems(mac_r25d_mcu); i++)
				rge_write_phy_ocp(sc,
				    mac_r25d_mcu[i].reg, mac_r25d_mcu[i].val);
		} else if (sc->rge_type == MAC_R26) {
			for (i = 0; i < nitems(mac_r26_mcu); i++)
				rge_write_phy_ocp(sc,
				    mac_r26_mcu[i].reg, mac_r26_mcu[i].val);
		} else if (sc->rge_type == MAC_R27) {
			for (i = 0; i < 1887; i++)
				rge_write_phy_ocp(sc,
				    mac_r27_mcu[i].reg, mac_r27_mcu[i].val);
			rge_patch_phy_mcu(sc, 0);

			rge_patch_phy_mcu(sc, 1);
			for (; i < nitems(mac_r27_mcu); i++)
				rge_write_phy_ocp(sc,
				    mac_r27_mcu[i].reg, mac_r27_mcu[i].val);
		}

		rge_patch_phy_mcu(sc, 0);

		/* Write ram code version. */
		rge_write_phy_ocp(sc, 0xa436, 0x801e);
		rge_write_phy_ocp(sc, 0xa438, rcodever);
	}
}

static void
rge_set_macaddr(struct rge_softc *sc, const uint8_t *addr)
{
	RGE_SETBIT_1(sc, RGE_EECMD, RGE_EECMD_WRITECFG);
	RGE_WRITE_4(sc, RGE_MAC0,
	    addr[3] << 24 | addr[2] << 16 | addr[1] << 8 | addr[0]);
	RGE_WRITE_4(sc, RGE_MAC4,
	    addr[5] <<  8 | addr[4]);
	RGE_CLRBIT_1(sc, RGE_EECMD, RGE_EECMD_WRITECFG);
}

/**
 * @brief Read the mac address from the NIC EEPROM.
 *
 * Note this also calls rge_set_macaddr() which programs
 * it into the PPROM; I'm not sure why.
 *
 * Must be called with the driver lock held.
 */
static void
rge_get_macaddr(struct rge_softc *sc, uint8_t *addr)
{
	int i;

	RGE_ASSERT_LOCKED(sc);

	for (i = 0; i < ETHER_ADDR_LEN; i++)
		addr[i] = RGE_READ_1(sc, RGE_MAC0 + i);

	*(uint32_t *)&addr[0] = RGE_READ_4(sc, RGE_ADDR0);
	*(uint16_t *)&addr[4] = RGE_READ_2(sc, RGE_ADDR1);

	rge_set_macaddr(sc, addr);
}

/**
 * @brief MAC hardware initialisation
 *
 * Must be called with the driver lock held.
 */
static void
rge_hw_init(struct rge_softc *sc)
{
	uint16_t reg;
	int i;

	RGE_ASSERT_LOCKED(sc);

	rge_disable_aspm_clkreq(sc);
	RGE_CLRBIT_1(sc, 0xf1, 0x80);

	/* Disable UPS. */
	RGE_MAC_CLRBIT(sc, 0xd40a, 0x0010);

	/* Disable MAC MCU. */
	rge_disable_aspm_clkreq(sc);
	rge_write_mac_ocp(sc, 0xfc48, 0);
	for (reg = 0xfc28; reg < 0xfc48; reg += 2)
		rge_write_mac_ocp(sc, reg, 0);
	DELAY(3000);
	rge_write_mac_ocp(sc, 0xfc26, 0);

	/* Read microcode version. */
	rge_switch_mcu_ram_page(sc, 2);
	sc->rge_mcodever = 0;
	for (i = 0; i < 8; i += 2) {
		sc->rge_mcodever <<= 16;
		sc->rge_mcodever |= rge_read_mac_ocp(sc, 0xf9f8 + i);
	}
	rge_switch_mcu_ram_page(sc, 0);

	rge_mac_config_mcu(sc, sc->rge_type);

	/* Disable PHY power saving. */
	if (sc->rge_type == MAC_R25)
		rge_disable_phy_ocp_pwrsave(sc);

	/* Set PCIe uncorrectable error status. */
	rge_write_csi(sc, 0x108,
	    rge_read_csi(sc, 0x108) | 0x00100000);
}

static void
rge_hw_reset(struct rge_softc *sc)
{
	/* Disable interrupts */
	RGE_WRITE_4(sc, RGE_IMR, 0);
	RGE_WRITE_4(sc, RGE_ISR, RGE_READ_4(sc, RGE_ISR));

	/* Clear timer interrupts. */
	RGE_WRITE_4(sc, RGE_TIMERINT0, 0);
	RGE_WRITE_4(sc, RGE_TIMERINT1, 0);
	RGE_WRITE_4(sc, RGE_TIMERINT2, 0);
	RGE_WRITE_4(sc, RGE_TIMERINT3, 0);

	rge_reset(sc);
}

static void
rge_disable_phy_ocp_pwrsave(struct rge_softc *sc)
{
	if (rge_read_phy_ocp(sc, 0xc416) != 0x0500) {
		rge_patch_phy_mcu(sc, 1);
		rge_write_phy_ocp(sc, 0xc416, 0);
		rge_write_phy_ocp(sc, 0xc416, 0x0500);
		rge_patch_phy_mcu(sc, 0);
	}
}

static void
rge_patch_phy_mcu(struct rge_softc *sc, int set)
{
	int i;

	if (set)
		RGE_PHY_SETBIT(sc, 0xb820, 0x0010);
	else
		RGE_PHY_CLRBIT(sc, 0xb820, 0x0010);

	for (i = 0; i < 1000; i++) {
		if (set) {
			if ((rge_read_phy_ocp(sc, 0xb800) & 0x0040) != 0)
				break;
		} else {
			if (!(rge_read_phy_ocp(sc, 0xb800) & 0x0040))
				break;
		}
		DELAY(100);
	}
	if (i == 1000)
		device_printf(sc->sc_dev,
		    "timeout waiting to patch phy mcu\n");
}

static void
rge_add_media_types(struct rge_softc *sc)
{
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_10_T, 0, NULL);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_10_T | IFM_FDX, 0, NULL);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_100_TX, 0, NULL);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_100_TX | IFM_FDX, 0, NULL);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_1000_T, 0, NULL);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_1000_T | IFM_FDX, 0, NULL);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_2500_T, 0, NULL);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_2500_T | IFM_FDX, 0, NULL);

	if (sc->rge_type == MAC_R26) {
		ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_5000_T, 0, NULL);
		ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_5000_T | IFM_FDX,
		    0, NULL);
	} else if (sc->rge_type == MAC_R27) {
		ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_10G_T, 0, NULL);
		ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_10G_T | IFM_FDX,
		    0, NULL);
	}
}

static void
rge_config_imtype(struct rge_softc *sc, int imtype)
{
	switch (imtype) {
	case RGE_IMTYPE_NONE:
		sc->rge_intrs = RGE_INTRS;
		break;
	case RGE_IMTYPE_SIM:
		sc->rge_intrs = RGE_INTRS_TIMER;
		break;
	default:
		device_printf(sc->sc_dev, "unknown imtype %d", imtype);
	}
}

static void
rge_disable_aspm_clkreq(struct rge_softc *sc)
{
	int unlock = 1;

	if ((RGE_READ_1(sc, RGE_EECMD) & RGE_EECMD_WRITECFG) ==
	    RGE_EECMD_WRITECFG)
		unlock = 0;

	if (unlock)
		RGE_SETBIT_1(sc, RGE_EECMD, RGE_EECMD_WRITECFG);

	if (sc->rge_type == MAC_R26 || sc->rge_type == MAC_R27)
		RGE_CLRBIT_1(sc, RGE_INT_CFG0, 0x08);
	else
		RGE_CLRBIT_1(sc, RGE_CFG2, RGE_CFG2_CLKREQ_EN);
	RGE_CLRBIT_1(sc, RGE_CFG5, RGE_CFG5_PME_STS);

	if (unlock)
		RGE_CLRBIT_1(sc, RGE_EECMD, RGE_EECMD_WRITECFG);
}

static void
rge_disable_hw_im(struct rge_softc *sc)
{
	RGE_WRITE_2(sc, RGE_IM, 0);
}

static void
rge_disable_sim_im(struct rge_softc *sc)
{
	RGE_WRITE_4(sc, RGE_TIMERINT0, 0);
	sc->rge_timerintr = 0;
}

static void
rge_setup_sim_im(struct rge_softc *sc)
{
	RGE_WRITE_4(sc, RGE_TIMERINT0, 0x2600);
	RGE_WRITE_4(sc, RGE_TIMERCNT, 1);
	sc->rge_timerintr = 1;
}

static void
rge_setup_intr(struct rge_softc *sc, int imtype)
{
	rge_config_imtype(sc, imtype);

	/* Enable interrupts. */
	RGE_WRITE_4(sc, RGE_IMR, sc->rge_intrs);

	switch (imtype) {
	case RGE_IMTYPE_NONE:
		rge_disable_sim_im(sc);
		rge_disable_hw_im(sc);
		break;
	case RGE_IMTYPE_SIM:
		rge_disable_hw_im(sc);
		rge_setup_sim_im(sc);
		break;
	default:
		device_printf(sc->sc_dev, "unknown imtype %d", imtype);
	}
}

static void
rge_switch_mcu_ram_page(struct rge_softc *sc, int page)
{
	uint16_t val;

	val = rge_read_mac_ocp(sc, 0xe446) & ~0x0003;
	val |= page;
	rge_write_mac_ocp(sc, 0xe446, val);
}

static int
rge_exit_oob(struct rge_softc *sc)
{
	int error, i;

	/* Disable RealWoW. */
	rge_write_mac_ocp(sc, 0xc0bc, 0x00ff);

	if ((error = rge_reset(sc)) != 0)
		return error;

	/* Disable OOB. */
	RGE_CLRBIT_1(sc, RGE_MCUCMD, RGE_MCUCMD_IS_OOB);

	RGE_MAC_CLRBIT(sc, 0xe8de, 0x4000);

	for (i = 0; i < 10; i++) {
		DELAY(100);
		if (RGE_READ_2(sc, RGE_TWICMD) & 0x0200)
			break;
	}

	rge_write_mac_ocp(sc, 0xc0aa, 0x07d0);
	rge_write_mac_ocp(sc, 0xc0a6, 0x01b5);
	rge_write_mac_ocp(sc, 0xc01e, 0x5555);

	for (i = 0; i < 10; i++) {
		DELAY(100);
		if (RGE_READ_2(sc, RGE_TWICMD) & 0x0200)
			break;
	}

	if (rge_read_mac_ocp(sc, 0xd42c) & 0x0100) {
		for (i = 0; i < RGE_TIMEOUT; i++) {
			if ((rge_read_phy_ocp(sc, 0xa420) & 0x0007) == 2)
				break;
			DELAY(1000);
		}
		RGE_MAC_CLRBIT(sc, 0xd42c, 0x0100);
		if (sc->rge_type != MAC_R25)
			RGE_PHY_CLRBIT(sc, 0xa466, 0x0001);
		RGE_PHY_CLRBIT(sc, 0xa468, 0x000a);
	}

	return 0;
}

static void
rge_write_csi(struct rge_softc *sc, uint32_t reg, uint32_t val)
{
	int i;

	RGE_WRITE_4(sc, RGE_CSIDR, val);
	RGE_WRITE_4(sc, RGE_CSIAR, (reg & RGE_CSIAR_ADDR_MASK) |
	    (RGE_CSIAR_BYTE_EN << RGE_CSIAR_BYTE_EN_SHIFT) | RGE_CSIAR_BUSY);

	for (i = 0; i < 20000; i++) {
		 DELAY(1);
		 if (!(RGE_READ_4(sc, RGE_CSIAR) & RGE_CSIAR_BUSY))
			break;
	}

	DELAY(20);
}

static uint32_t
rge_read_csi(struct rge_softc *sc, uint32_t reg)
{
	int i;

	RGE_WRITE_4(sc, RGE_CSIAR, (reg & RGE_CSIAR_ADDR_MASK) |
	    (RGE_CSIAR_BYTE_EN << RGE_CSIAR_BYTE_EN_SHIFT));

	for (i = 0; i < 20000; i++) {
		 DELAY(1);
		 if (RGE_READ_4(sc, RGE_CSIAR) & RGE_CSIAR_BUSY)
			break;
	}

	DELAY(20);

	return (RGE_READ_4(sc, RGE_CSIDR));
}

static void
rge_write_mac_ocp(struct rge_softc *sc, uint16_t reg, uint16_t val)
{
	uint32_t tmp;

	tmp = (reg >> 1) << RGE_MACOCP_ADDR_SHIFT;
	tmp += val;
	tmp |= RGE_MACOCP_BUSY;
	RGE_WRITE_4(sc, RGE_MACOCP, tmp);
}

static uint16_t
rge_read_mac_ocp(struct rge_softc *sc, uint16_t reg)
{
	uint32_t val;

	val = (reg >> 1) << RGE_MACOCP_ADDR_SHIFT;
	RGE_WRITE_4(sc, RGE_MACOCP, val);

	return (RGE_READ_4(sc, RGE_MACOCP) & RGE_MACOCP_DATA_MASK);
}

static void
rge_write_ephy(struct rge_softc *sc, uint16_t reg, uint16_t val)
{
	uint32_t tmp;
	int i;

	tmp = (reg & RGE_EPHYAR_ADDR_MASK) << RGE_EPHYAR_ADDR_SHIFT;
	tmp |= RGE_EPHYAR_BUSY | (val & RGE_EPHYAR_DATA_MASK);
	RGE_WRITE_4(sc, RGE_EPHYAR, tmp);

	for (i = 0; i < 20000; i++) {
		DELAY(1);
		if (!(RGE_READ_4(sc, RGE_EPHYAR) & RGE_EPHYAR_BUSY))
			break;
	}

	DELAY(20);
}

static uint16_t
rge_read_ephy(struct rge_softc *sc, uint16_t reg)
{
	uint32_t val;
	int i;

	val = (reg & RGE_EPHYAR_ADDR_MASK) << RGE_EPHYAR_ADDR_SHIFT;
	RGE_WRITE_4(sc, RGE_EPHYAR, val);

	for (i = 0; i < 20000; i++) {
		DELAY(1);
		val = RGE_READ_4(sc, RGE_EPHYAR);
		if (val & RGE_EPHYAR_BUSY)
			break;
	}

	DELAY(20);

	return (val & RGE_EPHYAR_DATA_MASK);
}

static uint16_t
rge_check_ephy_ext_add(struct rge_softc *sc, uint16_t reg)
{
	uint16_t val;

	val = (reg >> 12);
	rge_write_ephy(sc, RGE_EPHYAR_EXT_ADDR, val);

	return reg & 0x0fff;
}

static void
rge_r27_write_ephy(struct rge_softc *sc, uint16_t reg, uint16_t val)
{
	rge_write_ephy(sc, rge_check_ephy_ext_add(sc, reg), val);
}

static void
rge_write_phy(struct rge_softc *sc, uint16_t addr, uint16_t reg, uint16_t val)
{
	uint16_t off, phyaddr;

	phyaddr = addr ? addr : RGE_PHYBASE + (reg / 8);
	phyaddr <<= 4;

	off = addr ? reg : 0x10 + (reg % 8);

	phyaddr += (off - 16) << 1;

	rge_write_phy_ocp(sc, phyaddr, val);
}

static uint16_t
rge_read_phy(struct rge_softc *sc, uint16_t addr, uint16_t reg)
{
	uint16_t off, phyaddr;

	phyaddr = addr ? addr : RGE_PHYBASE + (reg / 8);
	phyaddr <<= 4;

	off = addr ? reg : 0x10 + (reg % 8);

	phyaddr += (off - 16) << 1;

	return (rge_read_phy_ocp(sc, phyaddr));
}

static void
rge_write_phy_ocp(struct rge_softc *sc, uint16_t reg, uint16_t val)
{
	uint32_t tmp;
	int i;

	tmp = (reg >> 1) << RGE_PHYOCP_ADDR_SHIFT;
	tmp |= RGE_PHYOCP_BUSY | val;
	RGE_WRITE_4(sc, RGE_PHYOCP, tmp);

	for (i = 0; i < 20000; i++) {
		DELAY(1);
		if (!(RGE_READ_4(sc, RGE_PHYOCP) & RGE_PHYOCP_BUSY))
			break;
	}
}

static uint16_t
rge_read_phy_ocp(struct rge_softc *sc, uint16_t reg)
{
	uint32_t val;
	int i;

	val = (reg >> 1) << RGE_PHYOCP_ADDR_SHIFT;
	RGE_WRITE_4(sc, RGE_PHYOCP, val);

	for (i = 0; i < 20000; i++) {
		DELAY(1);
		val = RGE_READ_4(sc, RGE_PHYOCP);
		if (val & RGE_PHYOCP_BUSY)
			break;
	}

	return (val & RGE_PHYOCP_DATA_MASK);
}

static int
rge_get_link_status(struct rge_softc *sc)
{
	return ((RGE_READ_2(sc, RGE_PHYSTAT) & RGE_PHYSTAT_LINK) ? 1 : 0);
}

#if 0
void
rge_txstart(void *arg)
{
	struct rge_softc *sc = arg;

	RGE_WRITE_2(sc, RGE_TXSTART, RGE_TXSTART_START);
}
#endif

/**
 * @brief Called by the sc_timeout callout.
 *
 * This is called by the callout code with the driver lock held.
 */
void
rge_tick(void *arg)
{
	struct rge_softc *sc = arg;

	RGE_ASSERT_LOCKED(sc);

	rge_link_state(sc);
	callout_reset(&sc->sc_timeout, hz, rge_tick, sc);
}

/**
 * @brief process a link state change.
 *
 * Must be called with the driver lock held.
 */
void
rge_link_state(struct rge_softc *sc)
{
	int link = LINK_STATE_DOWN;

	RGE_ASSERT_LOCKED(sc);

	if (rge_get_link_status(sc))
		link = LINK_STATE_UP;

	if (if_getlinkstate(sc->sc_ifp) != link)
		if_link_state_change(sc->sc_ifp, link);
}

#if 0
#ifndef SMALL_KERNEL
int
rge_wol(struct ifnet *ifp, int enable)
{
	struct rge_softc *sc = ifp->if_softc;

	if (enable) {
		if (!(RGE_READ_1(sc, RGE_CFG1) & RGE_CFG1_PM_EN)) {
			printf("%s: power management is disabled, "
			    "cannot do WOL\n", sc->sc_dev.dv_xname);
			return (ENOTSUP);
		}

	}

	rge_iff(sc);

	if (enable)
		RGE_MAC_SETBIT(sc, 0xc0b6, 0x0001);
	else
		RGE_MAC_CLRBIT(sc, 0xc0b6, 0x0001);

	RGE_SETBIT_1(sc, RGE_EECMD, RGE_EECMD_WRITECFG);
	RGE_CLRBIT_1(sc, RGE_CFG5, RGE_CFG5_WOL_LANWAKE | RGE_CFG5_WOL_UCAST |
	    RGE_CFG5_WOL_MCAST | RGE_CFG5_WOL_BCAST);
	RGE_CLRBIT_1(sc, RGE_CFG3, RGE_CFG3_WOL_LINK | RGE_CFG3_WOL_MAGIC);
	if (enable)
		RGE_SETBIT_1(sc, RGE_CFG5, RGE_CFG5_WOL_LANWAKE);
	RGE_CLRBIT_1(sc, RGE_EECMD, RGE_EECMD_WRITECFG);

	return (0);
}

void
rge_wol_power(struct rge_softc *sc)
{
	/* Disable RXDV gate. */
	RGE_CLRBIT_1(sc, RGE_PPSW, 0x08);
	DELAY(2000);

	RGE_SETBIT_1(sc, RGE_CFG1, RGE_CFG1_PM_EN);
	RGE_SETBIT_1(sc, RGE_CFG2, RGE_CFG2_PMSTS_EN);
}
#endif

#endif

static device_method_t rge_methods[] = {
	DEVMETHOD(device_probe,			rge_probe),
	DEVMETHOD(device_attach,		rge_attach),
	DEVMETHOD(device_detach,		rge_detach),
#if 0
	DEVMETHOD(device_suspend,		rge_suspend),
	DEVMETHOD(device_resume,		rge_resume),
	DEVMETHOD(device_shutdown,		rge_shutdown),
#endif

	/* TODO: does this require MII bus stuff? */
#if 0
	DEVMETHOD(miibus_readreg,		rge_miibus_readreg),
	DEVMETHOD(miibus_writereg,		rge_miibus_writereg),
	DEVMETHOD(miibus_statchg,		rge_miibus_statchg),
#endif

	DEVMETHOD_END
};

static driver_t rge_driver = {
	"rge",
	rge_methods,
	sizeof(struct rge_softc)
};

MODULE_DEPEND(rge, pci, 1, 1, 1);
MODULE_DEPEND(rge, ether, 1, 1, 1);
#if 0
MODULE_DEPEND(rge, miibus, 1, 1, 1);
#endif

DRIVER_MODULE_ORDERED(rge, pci, rge_driver, NULL, NULL, SI_ORDER_ANY);
#if 0
DRIVER_MODULE(miibus, rl, miibus_driver, 0, 0);
#endif
