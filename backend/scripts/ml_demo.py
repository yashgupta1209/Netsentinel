"""NetSentinel quick ML demo: Random Forest on synthetic training data.

IMPORTANT: Training/evaluation data here are synthetic, not a real labelled
intrusion dataset. This is a review prototype, not a production IDS model.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import random
import sys

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from app.analyzer.packet_reader import read_pcap

FEATURES = ["packet_count", "unique_dst_ports", "unique_dst_ips", "packets_per_second", "mean_packet_length", "tcp_fraction"]
LABELS = {0: "NORMAL", 1: "SUSPICIOUS"}


def make_synthetic_training_data(n_per_class: int = 1200, seed: int = 42):
    rng = random.Random(seed)
    X, y = [], []
    # Synthetic normal source-level traffic profiles.
    for _ in range(n_per_class):
        packet_count = rng.randint(1, 80)
        unique_ports = rng.randint(1, min(8, packet_count))
        unique_dst_ips = rng.randint(1, min(8, packet_count))
        duration = rng.uniform(1.0, 60.0)
        pps = packet_count / duration
        mean_len = rng.uniform(60, 1100)
        tcp_fraction = rng.uniform(0.0, 1.0)
        X.append([packet_count, unique_ports, unique_dst_ips, pps, mean_len, tcp_fraction])
        y.append(0)
    # Synthetic suspicious profiles: scans, bursts, or unusually broad fan-out.
    for _ in range(n_per_class):
        kind = rng.choice(["scan", "burst", "fanout"])
        if kind == "scan":
            packet_count = rng.randint(20, 120)
            unique_ports = rng.randint(15, min(60, packet_count))
            unique_dst_ips = rng.randint(1, 4)
            duration = rng.uniform(1.0, 60.0)
            pps = packet_count / duration
        elif kind == "burst":
            packet_count = rng.randint(20, 300)
            unique_ports = rng.randint(1, min(5, packet_count))
            unique_dst_ips = rng.randint(1, min(5, packet_count))
            duration = rng.uniform(0.05, 1.5)
            pps = packet_count / duration
        else:
            packet_count = rng.randint(30, 180)
            unique_ports = rng.randint(1, min(10, packet_count))
            unique_dst_ips = rng.randint(10, min(50, packet_count))
            duration = rng.uniform(1.0, 30.0)
            pps = packet_count / duration
        mean_len = rng.uniform(60, 1400)
        tcp_fraction = rng.uniform(0.2, 1.0)
        X.append([packet_count, unique_ports, unique_dst_ips, pps, mean_len, tcp_fraction])
        y.append(1)
    return X, y


def extract_source_features(pcap_path: Path):
    packets = read_pcap(str(pcap_path))
    by_src = defaultdict(list)
    for p in packets:
        src = p.get("src_ip")
        if src:
            by_src[str(src)].append(p)
    results = []
    for src, rows in sorted(by_src.items()):
        times = [float(r["timestamp"]) for r in rows if r.get("timestamp") is not None]
        span = max(times) - min(times) if len(times) >= 2 else 1.0
        span = max(span, 0.001)
        ports = {int(r["dst_port"]) for r in rows if r.get("dst_port") is not None}
        dst_ips = {r["dst_ip"] for r in rows if r.get("dst_ip")}
        lengths = [float(r.get("length") or 0) for r in rows]
        tcp_count = sum(1 for r in rows if r.get("protocol") == "TCP")
        features = [len(rows), len(ports), len(dst_ips), len(rows) / span,
                    sum(lengths) / max(len(lengths), 1), tcp_count / max(len(rows), 1)]
        results.append((src, features))
    return results


def main():
    backend = Path(__file__).resolve().parents[1]
    data_dir = backend / "data"
    X, y = make_synthetic_training_data()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    model = RandomForestClassifier(n_estimators=120, random_state=42, class_weight="balanced")
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    print("=== NetSentinel ML Demo: Random Forest ===")
    print("Training data: synthetic source-level traffic profiles (not a real dataset)")
    print(f"Synthetic holdout accuracy: {accuracy_score(y_test, pred):.3f}")
    print(classification_report(y_test, pred, target_names=["NORMAL", "SUSPICIOUS"], digits=3))
    print("Feature importance:")
    for name, score in sorted(zip(FEATURES, model.feature_importances_), key=lambda z: z[1], reverse=True):
        print(f"  {name}: {score:.3f}")

    print("\n=== PCAP predictions by source IP ===")
    for filename in ("normal_traffic.pcap", "suspicious_traffic.pcap"):
        path = data_dir / filename
        if not path.exists():
            print(f"Missing {path}; run python -m scripts.generate_demo_pcaps first")
            continue
        print(f"\n{filename}")
        for src, features in extract_source_features(path):
            label = int(model.predict([features])[0])
            probs = model.predict_proba([features])[0]
            suspicious_prob = float(probs[list(model.classes_).index(1)])
            print(f"  {src:16s} -> {LABELS[label]:10s} (model score={suspicious_prob:.1%}; packets={int(features[0])}, unique_ports={int(features[1])}, rate={features[3]:.1f} pkt/s)")
    print("\nNOTE: Scores are for a quick educational prototype trained on synthetic data; do not interpret them as real-world calibrated probabilities.")


if __name__ == "__main__":
    main()
