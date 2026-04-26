# V2 Security Evaluation Details / V2 安全性评估详情

---

All 10,000 traces were collected under the ELMO simulator. No physical hardware
traces are available for V2.

全部 10,000 条迹线均来自 ELMO 模拟器，V2 暂无实机数据。

V2 extends V1 by tracking the data flow through ALU, registers, and the data bus
(including bus buffers) across all instructions. Through careful instruction
scheduling, HD-model leakage from all three sources is theoretically eliminated —
not only the bus-level share collision addressed in V1, but also register and ALU
operand interactions.

V2 在 V1 的基础上，对所有指令的 ALU、寄存器、数据总线（含缓冲区）数据流进行了
全面追踪，通过指令调度理论上消除了三条路径上的 HD 模型泄漏——不仅涵盖 V1 已处理
的总线层 share 碰撞，还包括寄存器和 ALU 操作数的交互泄漏。

---

## Test Results / 测试结果

### V2 — On-device PRNG / 片上随机数策略

| Test / 测试              | Exceeding samples / 超限采样点数 | Total samples / 总采样点数 | Coverage / 覆盖范围 |
| ------------------------ | -------------------------------- | -------------------------- | ------------------- |
| Mean-level TVLA / 均值   | 4,303                            | 26,411                     | Entire flow / 全流程 |
| Variance-level TVLA / 方差 | 5,297                          | 26,411                     | Entire flow / 全流程 |

**CPA:** First round / 首轮 — 16 / 16 (raw traces not retained / 原始数据未保存，依据记录)

The on-device PRNG completely fails NIST SP 800-22 statistical tests; see
`prng_verify.py` for details. The widespread TVLA failure and complete CPA
compromise are consistent with the broken random number quality.

片上 PRNG 完全未能通过 NIST SP 800-22 统计测试，详见 `prng_verify.py`。
TVLA 全面崩溃和 CPA 完全被破解与随机数质量的严重缺陷高度一致。

---

### V2 — AES-CTR PRNG \*

| Test / 测试              | Exceeding samples / 超限采样点数 | Total samples / 总采样点数 | Coverage / 覆盖范围      |
| ------------------------ | -------------------------------- | -------------------------- | ------------------------ |
| Mean-level TVLA / 均值   | 721                              | 26,411                     | S-box region only / 仅 S-box 区域 |
| Variance-level TVLA / 方差 | 347                            | 26,411                     | S-box region only / 仅 S-box 区域 |

**CPA:**

| Round / 轮次       | Model / 模型     | Key bytes recovered / 命中字节数 |
| ------------------ | ---------------- | -------------------------------- |
| First round / 首轮 | S-box model / S-box 模型 | 12 / 16               |
| Last round / 尾轮  | S-box model / S-box 模型 | 0 / 16                |
| Last round / 尾轮  | ARK model / ARK 模型     | 1 / 16                |

Compared to the on-device PRNG variant, replacing with AES-CTR reduces mean-level
TVLA failures by approximately 83% (4,303 → 721) and confines remaining leakage
to the S-box region. However, first-round CPA still recovers 12 of 16 key bytes,
which is discussed further in the summary below.

相比片上随机数方案，换用 AES-CTR 后均值 TVLA 超限点减少约 83%（4,303 → 721），
剩余泄漏集中于 S-box 区域。然而首轮 CPA 仍能命中 12/16 字节密钥，详见下方总结。

---

### V2 — AES-CTR PRNG, with additional LDR/STR insertion / 大量 LDR/STR 插入

Additional load/store instructions were inserted before every LDR to flush the
bus state, at significant performance cost.

在每条 LDR 之前插入额外的 load/store 指令以刷新总线状态，性能代价显著。

| Test / 测试              | Exceeding samples / 超限采样点数 | Total samples / 总采样点数 | Coverage / 覆盖范围      |
| ------------------------ | -------------------------------- | -------------------------- | ------------------------ |
| Mean-level TVLA / 均值   | 551                              | 33,931                     | S-box region only / 仅 S-box 区域 |
| Variance-level TVLA / 方差 | 413                            | 33,931                     | S-box region only / 仅 S-box 区域 |

**CPA:**

| Round / 轮次       | Model / 模型     | Key bytes recovered / 命中字节数 |
| ------------------ | ---------------- | -------------------------------- |
| First round / 首轮 | S-box model / S-box 模型 | 7 / 16                |
| Last round / 尾轮  | S-box model / S-box 模型 | 0 / 16                |
| Last round / 尾轮  | ARK model / ARK 模型     | 1 / 16                |

TVLA failures decrease further (721 → 551), and CPA drops from 12/16 to 7/16,
confirming that bus-state interactions contribute to the leakage. Nevertheless,
7 bytes remain recoverable, indicating residual leakage sources beyond LDR bus
transitions.

TVLA 超限点进一步减少（721 → 551），CPA 从 12/16 降至 7/16，证实总线状态交互
确实贡献了部分泄漏。然而仍有 7 个字节可被恢复，说明存在 LDR 总线切换之外的
残余泄漏源。

---

### Fatal Version (V0) — Reference \* / 参照测试 \*

The fatal version contains a known critical implementation flaw and was included
as a reference point.

Fatal 版本含有一个已知的致命实现缺陷，此处作为参照基准进行测试。

| Test / 测试              | Exceeding samples / 超限采样点数 | Total samples / 总采样点数 | Coverage / 覆盖范围      |
| ------------------------ | -------------------------------- | -------------------------- | ------------------------ |
| Mean-level TVLA / 均值   | 110                              | 25,975                     | Entire flow / 全流程     |
| Variance-level TVLA / 方差 | 5,917                          | 25,975                     | Entire flow / 全流程     |

**CPA:**

| Round / 轮次       | Model / 模型     | Key bytes recovered / 命中字节数 |
| ------------------ | ---------------- | -------------------------------- |
| First round / 首轮 | S-box model / S-box 模型 | 2 / 16                |
| Last round / 尾轮  | S-box model / S-box 模型 | 0 / 16                |
| Last round / 尾轮  | ARK model / ARK 模型     | 1 / 16                |

The mean-level TVLA result appears deceptively good (only 110 exceeding samples),
but the variance-level result (5,917 exceeding samples, covering the entire flow)
immediately reveals the underlying problem. After applying variance-based
preprocessing to the traces, first-order CPA is expected to recover all key bytes
trivially. This illustrates that mean-level TVLA alone is insufficient for
security evaluation.

均值 TVLA 结果表面上看起来相当不错（仅 110 个超限点），但方差 TVLA 的结果
（5,917 个超限点，覆盖全流程）立即揭露了其深层问题。对迹线进行方差预处理后，
一阶 CPA 理论上可以轻易破解全部密钥。这说明仅凭均值 TVLA 进行安全评估是不充分的。

---

## Summary / 总结

From the perspective of TVLA failure counts and CPA key recovery rates, V2
(baseline, without additional LDR/STR insertion) represents a meaningful security
improvement over V1 at negligible performance cost: mean-level TVLA failures drop
from 2,477 to 721, and first-round CPA recovery drops from 16/16 to 12/16.
The linear layers are clean; all remaining leakage is confined to the S-box region.

从 TVLA 超限点数量和 CPA 密钥破解成功率来看，V2 基础版本（未插入额外 LDR/STR）
相比 V1 实现了有意义的安全性提升，且几乎未付出性能代价：均值 TVLA 超限点从
2,477 降至 721，首轮 CPA 命中率从 16/16 降至 12/16。
线性层完全干净，剩余泄漏全部集中于 S-box 区域。

That said, the results are frustrating. In theory, the instruction scheduling
should have closed all exploitable first-order leakage paths: ALU operands,
register transitions, and bus state were all tracked at the bit level, and no
share collision of the same variable was permitted at any point. Yet ELMO still
recovers 12 of 16 key bytes. Even after inserting additional LDR/STR instructions
at every load site — a brute-force bus-flush approach with significant performance
cost — 7 bytes remain recoverable.

话虽如此，结果确实令人沮丧。理论上，指令调度应当已经封堵了所有可利用的一阶泄漏
路径：ALU 操作数、寄存器翻转、总线状态均在比特级别进行了追踪，且任何时刻都不允许
同一变量的两个 share 发生碰撞。然而 ELMO 仍能命中 12/16 的密钥字节。即便以显著的
性能代价为代价，在每一条 LDR 前暴力插入 LDR/STR 刷新总线状态，仍有 7 个字节可被
恢复。

Attempting to map the best-correlation sample indices back to specific
instructions revealed further puzzling cases that defy straightforward
explanation under standard leakage models:

尝试将最佳相关系数对应的采样点映射回具体指令，发现了若干在标准泄漏模型下
难以解释的匪夷所思的情况：

- **`W2.0` overwriting `W7.0` via MOV** — two independently masked values of
  different variables; their HD should carry no sensitive information under any
  standard model. / 
  
  **MOV 指令 `W2.0` 覆盖 `W7.0`** —— 两个不同变量的独立掩码值，
  其 HD 在任何标准模型下都不应携带敏感信息。

- **`HD_BUS(M23.1, M20.1) + HD_REG(M23.1, COMPLEX)`** — `COMPLEX` is the
  residual cross-product term left by the preceding AND operation, and contains
  neither `M23` nor `M20`. Why this combination produces a statistically
  significant correlation is unclear. /

  **`HD_BUS(M23.1, M20.1) + HD_REG(M23.1, COMPLEX)`** —— `COMPLEX` 来自前一个
  AND 操作遗留的乘积项，其表达式中既不含 `M23` 也不含 `M20`。
  为何这一组合会产生统计显著的相关性，目前尚不清楚。

- **LDR loading `M41.0`, with `W6.0` and `T2.1` on the read bus and `W6.1` in
  the destination register** — the only conceivable explanation is that the bus
  coverage of `W6.0` and the register coverage of `W6.1` interact within ELMO's
  joint model to partially reconstruct `W6`. /

  **LDR 加载 `M41.0`，读总线覆盖 `W6.0` 和 `T2.1`，目标寄存器覆盖 `W6.1`** ——
  唯一能想到的解释是总线上的 `W6.0` 与寄存器端的 `W6.1` 在 ELMO 的联合模型中
  发生了某种交互，部分还原了 `W6` 的信息。

Whether these represent genuine physical leakage paths or something beyond
the publicly documented microarchitecture — as I was informed on Reddit,
the actual behaviour inside the chip does not always match its published
specification, and ELMO is modelled from real hardware measurements —
remains deeply puzzling and frankly discouraging. The V1 physical hardware
results (TVLA pass, CPA 2/16 top-10) suggest that real-world noise provides
substantial protection, and a physical evaluation of V2 is needed to draw
a definitive conclusion.

这些究竟是真实的物理泄漏路径，还是源于芯片内部行为与其公开规格之间的差异——
正如我在 Reddit 上被告知的那样，芯片内部的真实情况并不总是与其公布的结构完全
一致，而 ELMO 正是基于真实芯片的测量数据建模的——目前仍令人沮丧且匪夷所思。
V1 的实机结果（TVLA 通过，CPA top-10 命中 2/16）表明真实硬件噪声提供了相当显著
的防护，V2 的最终结论有待实机评估。

---

> \* AES-CTR random numbers were injected externally into the ELMO simulator
> in place of the on-device PRNG, in order to isolate the masking implementation
> from random number quality issues during simulation.
>
> \* AES-CTR 随机数在 ELMO 模拟器中以外部注入方式替代片上 PRNG，
> 目的是在模拟评估中将掩码实现与随机数质量问题相互隔离。