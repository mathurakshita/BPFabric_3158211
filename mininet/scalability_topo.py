#!/usr/bin/env python3

import argparse

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.topo import Topo

from eBPFSwitch import eBPFSwitch, eBPFHost


class ScalabilityTopo(Topo):
    def build(self, switches=1):
        for number in range(1, switches + 1):
            switch = self.addSwitch(
                f"s{number}",
                dpid=number,
                switch_path="../softswitch/softswitch",
            )

            # One interface is required by the BPFabric softswitch.
            host = self.addHost(
                f"h{number}",
                ip=f"10.0.{(number - 1) // 254}.{((number - 1) % 254) + 1}/8",
            )

            self.addLink(host, switch)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--switches",
        type=int,
        default=1,
        help="Number of emulated BPFabric switches",
    )
    args = parser.parse_args()

    if args.switches < 1:
        parser.error("--switches must be at least 1")

    topo = ScalabilityTopo(switches=args.switches)
    net = Mininet(
        topo=topo,
        host=eBPFHost,
        switch=eBPFSwitch,
        controller=None,
    )

    try:
        net.start()
        print(f"Started {args.switches} BPFabric switch instances")
        CLI(net)
    finally:
        net.stop()


if __name__ == "__main__":
    main()
