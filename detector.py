import sys
import math
import sqlite3
from collections import Counter, defaultdict
from scapy.all import rdpcap, DNSQR

LEN_MIN = 50
ENTROPY_MIN = 3.5
RATE_MIN = 10


def entropy(s):
    if not s:
        return 0

    counts = Counter(s)
    n = len(s)

    return -sum(
        (v / n) * math.log2(v / n)
        for v in counts.values()
    )


def init_db():
    conn = sqlite3.connect("incidents.db")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            qname TEXT,
            length INTEGER,
            entropy REAL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def save_incident(source, qname, length, ent):
    conn = sqlite3.connect("incidents.db")

    conn.execute(
        """
        INSERT INTO incidents
        (source, qname, length, entropy)
        VALUES (?, ?, ?, ?)
        """,
        (source, qname, length, ent)
    )

    conn.commit()
    conn.close()


def main():

    if len(sys.argv) < 2:
        print("Usage: python3 detector.py <capture.pcap>")
        return

    init_db()

    packets = rdpcap(sys.argv[1])
    counts = defaultdict(int)
    flagged = False

    for pkt in packets:

        if pkt.haslayer(DNSQR):

            qname = (
                pkt[DNSQR]
                .qname
                .decode(errors="ignore")
                .rstrip(".")
            )

            label = qname.split(".")[0]

            src = (
                pkt[0].src
                if hasattr(pkt[0], "src")
                else "unknown"
            )

            counts[src] += 1

            if (
                len(label) > LEN_MIN
                and entropy(label) > ENTROPY_MIN
                and counts[src] > RATE_MIN
            ):

                print(
                    f"TUNNEL ALERT: {src} sent "
                    f"long/high-entropy query "
                    f"{qname[:40]} "
                    f"(count {counts[src]})"
                )

                save_incident(
                    src,
                    qname,
                    len(label),
                    entropy(label)
                )

                flagged = True

    if not flagged:
        print(
            "No tunnel pattern found in",
            sys.argv[1]
        )


if __name__ == "__main__":
    main()
