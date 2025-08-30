# wfbX Mesh Time Sync & TDMA — Minimal Viable Spec (v1)

This document fixes the baseline design for **mesh operation on one RF channel** using **software timestamps** and a **TDMA superframe** without a central leader. It is concise on purpose and aligned with current `wfbx_rx.c` / `wfbx_tx.c` architecture.

> All comments and code examples are in English. Microsecond units are used unless explicitly stated otherwise.

---

## 1) Assumptions & scope

- Adapters run in **monitor mode**; we inject raw 802.11 frames.
- **No TSFT** is provided by driver/firmware on TX or RX. We rely on **software timestamps** only.
- On RX we can read **radiotap** fields to recover actual PHY (MCS / GI / BW / STBC / LDPC).  
- Each node has a **preconfigured superframe** and **its own slot** (one slot per node per superframe).
- Time base for software timestamps: `clock_gettime(CLOCK_MONOTONIC_RAW)`.
- We aim at **few hundreds of microseconds** timing accuracy with a reasonable slot guard.


## 2) Agreed baseline

1. **Single summed latency `δ_us`** (TX stack + RX stack).  
   - Obtained empirically (TX and RX on the same host with the same monotonic clock).  
   - Typical values observed: **1400–1600 µs**; jitter within “a few hundred µs”.

2. **RX timestamp anchor = end of PPDU** → we **always subtract airtime `A_us`** in calculations.

3. **Payload trailer carries only `TS_tx`** (4 bytes, **little‑endian**, microseconds).  
   - `TS_tx` is the **offset of this frame inside the superframe on TX**:
     ```c
     // On TX, inside current superframe:
     uint32_t TS_tx_us = now_us - T_epoch_us;  // 0 <= TS_tx_us < T_epoch_len
     ```

4. **Local superframe start estimation on RX**:
   - Notation:  
     `t_loc` – local software timestamp of RX delivery;  
     `δ_us` – summed TX+RX latency (config param);  
     `A_us` – PPDU airtime computed from *actual* PHY (radiotap);  
     `τ_us` – propagation delay (usually 0; configurable);  
     `TS_tx_us` – TX’s offset in its superframe (from trailer).
   - Instant estimate:
     ```text
     T_epoch_instant = t_loc − δ_us − A_us − τ_us − TS_tx_us
     ```
   - Smooth (optional EMA):
     ```text
     T̂_epoch = (1 − α) * T̂_epoch_prev + α * T_epoch_instant   // α in [0..1], e.g. 0.3
     ```

5. **Superframe & slot semantics** (all µs):
   - Superframe: start `T_epoch`, length `T_epoch_len`, inter‑superframe guard `T_epoch_gi`.
   - A node owns **one TX slot** per superframe with parameters:  
     `T_tx_start` (offset from `T_epoch`), `T_tx_len` (slot length), `GI_tx` (slot guard at the **tail**).
   - Open/close times:
     ```text
     T_open  = T_epoch + T_tx_start
     T_close = T_open + T_tx_len − GI_tx   // tail guard inside the slot
     ```
   - `T_epoch` is the **start of the current superframe** (common reference). It updates only at the superframe boundary:
     ```text
     T_epoch_next = T_epoch + T_epoch_len + T_epoch_gi
     // switch to T_epoch_next at the boundary; do NOT advance T_epoch “after our slot”
     ```

6. **Fit‑before‑send check** (TX shall not overrun the slot tail):
   - Let `A_us` be airtime of the pending MPDU (computed from **TX’s configured** PHY), `ε_us` a small scheduler margin (default 250 µs), and `τ_max_us` optional max propagation delay.  
   - Send **now** iff:
     ```text
     now_us + δ_us + A_us + τ_max_us + ε_us <= T_close
     ```
   - Otherwise buffer and send in **our next slot** in the next superframe.


## 3) Wire format — trailer in payload

Put the 4‑byte trailer **at the very end of the payload** (little‑endian). TX must remove it before forwarding to UDP (if needed) or ensure the receiver upstream is aware of the extra 4 bytes.

```c
// Trailing 4B at the very end of payload.
//
// Semantics: offset of this frame relative to the start of the current superframe on TX.
// Units: microseconds. Endian: little-endian.
struct wfbx_mesh_ts_trailer {
    uint32_t ts_tx_us_le;
} __attribute__((packed));
```

> This is intentionally minimal. No other mesh control fields are emitted in v1.


## 4) Airtime computation (`A_us`)

- RX side: compute `A_us` from **actual** radiotap PHY (HT/VHT/HE), including preambles (L‑SIG + HT/VHT/HE‑SIG), SERVICE/TAIL, and integer number of OFDM symbols.  
- TX side (fit‑check): compute `A_us` from **TX’s configured** PHY parameters (the ones used for injection).  
- **Aggregation is disabled** for mesh frames (fixed, predictable airtime).


## 5) Recommended parameters (initial)

- `δ_us` = 1500 (tune per platform; stable per host/driver)  
- `τ_us` (RX calc) = 0 (or set by distance)  
- `τ_max_us` (fit‑check) = 0 (or set by max distance)  
- `ε_us` = 250  
- `α` (EMA) = 0.3 (set to 1.0 to disable smoothing)  
- Example superframe: `T_epoch_len = 50_000`, `T_epoch_gi = 0..2_000`  
- Example slot: `T_tx_start` assigned offline; `T_tx_len` sized for target bitrate; `GI_tx = 600..800` (tighten later).


## 6) TX procedure (pseudo)

```c
// Time source: CLOCK_MONOTONIC_RAW
uint64_t now_us = mono_now_us();

uint64_t T_open  = T_epoch + T_tx_start;
uint64_t T_close = T_open + T_tx_len - GI_tx;

// Gate by slot window:
if (now_us < T_open) {
    sleep_until_us(T_open);
    now_us = mono_now_us();
}
if (now_us > T_close) {
    // Missed this slot -> schedule for next superframe
    schedule_next_superframe();
    return;
}

// Fit-before-send:
uint32_t A_us = airtime_us_tx(mpdu_len, phy_cfg);
if (now_us + delta_us + A_us + tau_max_us + eps_us > T_close) {
    schedule_next_superframe();
    return;
}

// Emit trailer:
uint32_t TS_tx = (uint32_t)(now_us - T_epoch);  // expected 0..T_epoch_len
append_trailer_le(payload, TS_tx);

// Inject 802.11 frame (fixed rate, no aggregation, no seq/ack)
pcap_inject(...);
```


## 7) RX procedure (pseudo)

```c
// On each received frame:
uint64_t t_loc = mono_now_us();                  // CLOCK_MONOTONIC_RAW

radiotap_info phy = parse_radiotap(pkt);         // actual PHY fields
uint32_t A_us = airtime_us_rx(mpdu_len, phy);    // PPDU airtime

uint32_t TS_tx_us = read_trailer_le(pkt);        // 4B at payload end
strip_trailer(pkt);                               // before UDP forward (if needed)

uint64_t T_epoch_instant =
    t_loc - delta_us - A_us - tau_us - TS_tx_us;

// Optional EMA smoothing:
if (!have_epoch) T_epoch_hat = T_epoch_instant;
else T_epoch_hat = ema(T_epoch_hat, T_epoch_instant, alpha);

// Telemetry (optional):
int64_t e_us = (int64_t)(T_epoch_instant - T_epoch_hat);
stats_push_error_us(e_us);
```


## 8) Calibration of `δ_us`

1. Run TX and RX on the **same host** (two interfaces).  
2. Transmit several known MPDU sizes and PHY settings.  
3. Adjust `δ_us` to minimize the median residual error `e_us = T_epoch_instant − T̂_epoch`.  
4. Validate with the slot‑fit headroom (% late sends should be ~0 at GI_tx ≥ 600–800 µs).


## 9) Telemetry (minimal)

Track per‑node and global:
- `e_us` residual (mean / 95‑percentile),
- slot hit‑rate (on‑time / late / early counts),
- current `GI_tx` (if auto‑tuned later),
- PHY profile distribution (MCS / GI / BW).


## 10) Safety checks & edge cases

- Clip `TS_tx` into `[0, T_epoch_len)` if superframe boundary and send coincide:
  ```c
  uint32_t TS_tx = now_us - T_epoch;
  if ((int32_t)TS_tx < 0)      TS_tx += T_epoch_len;
  if (TS_tx >= T_epoch_len)    TS_tx -= T_epoch_len;
  ```
- Use **monotonic raw clock** only; do not mix wall‑clock / NTP‑adjusted times.  
- If traffic is sparse, EMA helps to reduce jitter; further “PLL” (ppm skew) can be added later if needed for long holdover.


## 11) Future extensions (out of scope for v1)

- Optional two‑sided slot guard (`GI_pre` + `GI_post`).  
- Auto‑tuning of `GI_tx` from late/early statistics.  
- Lightweight skew (ppm) estimation for long no‑traffic intervals.  
- Security (HMAC over trailer or a dedicated control header).


---

**This spec is fixed as the base for implementation.**  
Next steps: wire the 4‑byte trailer in TX, implement RX epoch estimation + EMA, add TX fit‑check against `T_close`.
