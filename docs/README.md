# Lightweight Encryption Protocol for UAV Communication Systems

A secure, lightweight image encryption and session key agreement protocol designed for resource-constrained UAV (Unmanned Aerial Vehicle) communication systems. This project implements a PUF-seeded (Physical Unclonable Function) chaotic cipher running on real **ESP32** hardware using **ESP-NOW** wireless communication.

---

## Project Overview

UAVs streaming camera feeds to a base station over standard radio links are vulnerable to interception. While traditional ciphers like AES are strong, they often rely on pre-shared or stored long-term keys that can be extracted if a drone is physically captured. 

This project solves that by:
1. **Deriving fresh session keys on demand** using an emulated PUF response and a public per-session nonce. The key is never transmitted or permanently stored.
2. **Utilizing an integer-only chaos-based cipher** (a bank of 5 Duffing maps combined with Arnold cat-map permutation and chained diffusion) to encrypt $128 \times 128$ grayscale frames efficiently on an ESP32.

---

## Key Features

* **Zero-Storage Secret Management:** Session keys are dynamically derived via `R \oplus \text{Nonce}` and discarded after use.
* **Hardware-Tested Implementation:** Fully operational on two ESP32 microcontrollers communicating wirelessly via ESP-NOW[cite: 5, 7, 8].
* **Bit-Exact Python Reference:** Includes host scripts for verification, testing, and comparative analysis against theoretical standards[cite: 3].
* **High Security Metrics:** Achieves near-ideal cryptographic performance (Entropy $\approx 7.99/8.0$, strong NPCR/UACI test results, and minimal adjacent-pixel correlation).

---

## System Architecture

```text
[UAV Laptop / Webcam] --(USB)--> [UAV ESP32] --(ESP-NOW Radio)--> [Base ESP32] --(USB)--> [Base Laptop / Console]