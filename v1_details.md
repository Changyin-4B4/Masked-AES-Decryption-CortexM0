# V1 Security Evaluation Details / V1 安全性评估详情

---

## Physical Hardware Testing / 实机测试（STM32F051）

Traces were collected on a physical STM32F051 board.
All analysis scripts are in the `test/` directory (no inline comments).
In V1, instruction scheduling was applied within the S-box routine to prevent
HD leakage on the data bus caused by the two shares of the same variable
overwriting each other in successive bus transactions.

迹线采集于实际 STM32F051 硬件。所有分析脚本见 `test/` 目录（无内联注释）。
V1 版本在 S-box 例程中通过指令调度，避免了同一数据的两个 share 在连续总线
事务中相互覆盖所引发的 HD 泄漏。

---

### Fixed-vs-Random TVLA (5,000 traces, random input)

Intermediate targets analyzed: ciphertext, InvSubBytes output for rounds 10–1,
and plaintext, across all 16 bytes.

分析目标：密文、第 10 至第 1 轮 InvSubBytes 输出、明文，覆盖全部 16 字节。

| Stage / 阶段          | Result / 结果                                    |
| --------------------- | ------------------------------------------------ |
| Ciphertext (ct)       | ✓ Pass                                          |
| invsb_r10 ~ invsb_r2  | ✓ Pass — no statistically significant leakage  |
| invsb_r1 / plaintext  | ✗ Fail (sample ~73,000 onward)                  |

The leakage at invsb_r1 and plaintext is expected and theoretically unavoidable:
both correspond to the unmasking boundary where the final state is written out
in unmasked form. Since invsb_r1 and plaintext differ only by a constant round
key XOR, their TVLA curves are identical — they represent the same physical
operation. This leakage does not enable key recovery.

invsb_r1 和 plaintext 的泄漏是理论必然的端点泄漏（endpoint leakage）：
两者对应去掩码边界，最终状态以非掩码形式写出。由于两者仅相差一个固定轮密钥的
异或，TVLA 曲线完全一致，本质上是同一操作的两种视角。此泄漏不能用于恢复密钥。

Detailed results: `tlva_all_bytes_summary.csv`

---

### Fixed-vs-Fixed TVLA (1,500 × 3 traces, fixed input)

The three fixed input groups have different Hamming weights (HW = 59 / 65 / 71),
which introduces a systematic power baseline difference unrelated to the masking
scheme. This is believed to be the primary cause of the observed leakage.
A corrected evaluation using inputs with identical Hamming weight is recommended
for reproduction.

三组固定输入的汉明重量不同（HW = 59 / 65 / 71），导致功耗基线存在系统性差异，
与掩码方案无关，猜测这是观察到泄漏的主要原因。
建议复现时使用汉明重量相同的输入进行 Fixed-vs-Fixed 测试。

Comparison plots: `test/fvf_group_0_vs_group_1.png`, `test/fvf_group_0_vs_group_2.png`, `test/fvf_group_1_vs_group_2.png`

---

### CPA (5,000 traces, random input)

Single-bit CPA was performed against the random-input traces.
Among the top-10 key byte candidates for all 16 bytes, **2 bytes** contained
the correct key in both the first round and the last round respectively.

针对随机输入迹线进行了单 bit CPA 攻击。在全部 16 字节的 top-10 候选中，
首轮和尾轮各有 **2 个字节**的正确密钥出现在候选列表内。

---

## ELMO Simulation Testing / ELMO 模拟器测试 \*

10,000 traces were collected under the ELMO simulator for analysis.

在 ELMO 模拟器下采集了 10,000 条迹线进行分析。

### TVLA (10,000 traces)

| Test / 测试              | Exceeding samples / 超限采样点数 | Total samples / 总采样点数 |
| ------------------------ | -------------------------------- | -------------------------- |
| Mean-level / 均值        | 2,477                            | 26,451                     |
| Variance-level / 方差    | 2,178                            | 26,451                     |

### CPA (10,000 traces)

| Round / 轮次         | Key bytes recovered / 命中字节数 |
| -------------------- | -------------------------------- |
| First round / 首轮   | 16 / 16                          |
| Last round / 尾轮    | 4 / 16                           |

---

### Summary / 总结

Under ELMO with a higher-quality random number source, the implementation
completely fails against first-order CPA — ELMO's noiseless environment
leaves no room for the masking scheme to hide. In contrast, on real hardware
with the flawed original PRNG, both TVLA and first-order CPA fail entirely.
This strongly suggests that real-hardware noise provides substantial protection
on its own, independently of the masking scheme's theoretical guarantees.
For a comparison of the old and new random number strategies under ELMO,
see [v2_details.md](v2_details.md), which includes dedicated contrast tests.

在 ELMO 使用质量更好的随机数的情况下，由于模拟器无噪音干扰，实现在一阶 CPA
面前完全失败。然而在真机环境下，即便使用的是漏洞百出的旧随机数策略，TVLA
和一阶 CPA 均告失败。这表明真机噪音本身提供了相当显著的防护效果，独立于
掩码方案的理论保证之外。关于旧随机数在 ELMO 上的表现及新旧随机数的对比测试，
参见 [v2_details.md](v2_details.md)。

---

> \* The ELMO simulation uses an externally injected AES-CTR random number
> generator in place of the on-device PRNG, in order to isolate the masking
> implementation from random number quality issues.
>
> \* 此处 ELMO 模拟器测试使用了外部注入的 AES-CTR 随机数生成器替代片上 PRNG，
> 目的是将掩码实现的评估与随机数质量问题相互隔离。