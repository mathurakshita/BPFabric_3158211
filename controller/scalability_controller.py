#!/usr/bin/env python3

import argparse
import csv
import os
import statistics
import time

from twisted.internet import reactor

from core import eBPFCoreApplication, set_event_handler
from core.packets import Header, FunctionAddRequest, FunctionAddReply
from signature_utils import (
    load_signature_for_object,
    load_signer_certificate,
)


class ScalabilityController(eBPFCoreApplication):
    def __init__(self, args):
        super().__init__()

        self.args = args
        self.started_at = time.monotonic()
        self.dpids = []
        self.round_index = 0
        self.total_rounds = args.warmups + args.repetitions

        self.pending = set()
        self.sent_ns = {}
        self.round_rows = []
        self.results = []
        self.timeout_call = None

        with open(args.elf, "rb") as file:
            self.elf = file.read()

        self.signature = load_signature_for_object(args.elf)
        self.certificate = load_signer_certificate()

        print(
            f"Waiting for {args.switches} switch connections "
            f"on controller port 9000..."
        )

        reactor.callLater(0.25, self.wait_for_switches)

    def wait_for_switches(self):
        connected = len(self.connections)

        if connected >= self.args.switches:
            self.dpids = sorted(self.connections)[:self.args.switches]
            print(f"All switches connected: {self.dpids}")
            reactor.callLater(1.0, self.start_round)
            return

        if time.monotonic() - self.started_at > self.args.connection_timeout:
            print(
                f"Timed out: expected {self.args.switches}, "
                f"but only {connected} switches connected."
            )
            reactor.stop()
            return

        print(
            f"\rConnected switches: {connected}/{self.args.switches}",
            end="",
            flush=True,
        )
        reactor.callLater(0.25, self.wait_for_switches)

    def start_round(self):
        display_round = self.round_index + 1
        measured = self.round_index >= self.args.warmups

        phase = "measurement" if measured else "warm-up"
        print(
            f"\nStarting round {display_round}/{self.total_rounds} "
            f"({phase})"
        )

        self.pending = set(self.dpids)
        self.sent_ns = {}
        self.round_rows = []
        self.batch_start_ns = time.perf_counter_ns()

        request = FunctionAddRequest(
            name=self.args.name,
            index=self.args.index,
            elf=self.elf,
            signature=self.signature,
            certificate=self.certificate,
        )

        # Parallel fan-out: send one request to every switch.
        for dpid in self.dpids:
            self.sent_ns[dpid] = time.perf_counter_ns()
            self.connections[dpid].send(request)

        self.timeout_call = reactor.callLater(
            self.args.reply_timeout,
            self.round_timed_out,
            display_round,
        )

    @set_event_handler(Header.FUNCTION_ADD_REPLY)
    def function_add_reply(self, connection, packet):
        dpid = connection.dpid

        if dpid not in self.pending:
            return

        end_ns = time.perf_counter_ns()
        latency_us = (end_ns - self.sent_ns[dpid]) / 1000.0
        status = FunctionAddReply.FunctionAddStatus.Name(packet.status)

        self.round_rows.append(
            {
                "dpid": dpid,
                "status": status,
                "latency_us": latency_us,
            }
        )
        self.pending.remove(dpid)

        if self.pending:
            return

        if self.timeout_call and self.timeout_call.active():
            self.timeout_call.cancel()

        batch_us = (
            time.perf_counter_ns() - self.batch_start_ns
        ) / 1000.0

        measured = self.round_index >= self.args.warmups

        if measured:
            repetition = self.round_index - self.args.warmups + 1

            for row in self.round_rows:
                self.results.append(
                    {
                        "configuration": self.args.configuration,
                        "switches": self.args.switches,
                        "repetition": repetition,
                        "dpid": row["dpid"],
                        "status": row["status"],
                        "per_switch_us": f"{row['latency_us']:.3f}",
                        "batch_us": f"{batch_us:.3f}",
                    }
                )

        print(
            f"Round completed: switches={self.args.switches}, "
            f"batch_us={batch_us:.3f}"
        )

        self.round_index += 1

        if self.round_index < self.total_rounds:
            reactor.callLater(0.25, self.start_round)
        else:
            self.finish()

    def round_timed_out(self, round_number):
        print(
            f"\nRound {round_number} timed out. "
            f"Missing replies from DPIDs: {sorted(self.pending)}"
        )
        self.finish()

    def finish(self):
        output_directory = os.path.dirname(self.args.output)

        if output_directory:
            os.makedirs(output_directory, exist_ok=True)

        fields = [
            "configuration",
            "switches",
            "repetition",
            "dpid",
            "status",
            "per_switch_us",
            "batch_us",
        ]

        with open(self.args.output, "w", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            writer.writerows(self.results)

        successful = [
            float(row["per_switch_us"])
            for row in self.results
            if row["status"] == "OK"
        ]

        batches = list(
            {
                row["repetition"]: float(row["batch_us"])
                for row in self.results
            }.values()
        )

        print(f"\nResults written to: {self.args.output}")
        print(f"Successful installations: {len(successful)}")

        if successful:
            print(
                f"Mean per-switch latency: "
                f"{statistics.mean(successful):.3f} us"
            )
            print(
                f"Median per-switch latency: "
                f"{statistics.median(successful):.3f} us"
            )

        if batches:
            print(
                f"Mean batch latency: "
                f"{statistics.mean(batches):.3f} us"
            )
            print(
                f"Median batch latency: "
                f"{statistics.median(batches):.3f} us"
            )

        print("\nMeasurement complete.")
        print("Stop Mininet first, then press Ctrl+C in this controller.")

def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument("--switches", type=int, required=True)
    parser.add_argument("--elf", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--configuration", choices=["x509", "baseline"],
                        required=True)

    parser.add_argument("--name", default="flood")
    parser.add_argument("--index", type=int, default=0)
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--connection-timeout", type=float, default=60)
    parser.add_argument("--reply-timeout", type=float, default=30)

    return parser.parse_args()


if __name__ == "__main__":
    arguments = parse_arguments()
    ScalabilityController(arguments)
    reactor.run()
