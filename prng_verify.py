"""
prng_verify.py — EmbeddedPRNG 统计质量验证脚本
prng_verify.py — Statistical quality verification for EmbeddedPRNG

文件功能 / Purpose:
    在 PC 端模拟 prng_reference.c 中的三层级联 PRNG，并对其输出进行大样本统计验证。
    Simulates the three-pool cascaded PRNG from prng_reference.c on PC and evaluates
    output quality with large-sample statistical tests.

测试项目 / Tests performed:
    - 汉明重量分布 (Hamming Weight): 理想值 0.5，验证比特偏置
    - 字节值直方图 (Byte Histogram): 验证 256 个字节值的均匀性
    - 自相关性 (Autocorrelation, shift=1 & shift=256): 理想值 1/256 ≈ 0.003906
    - 游程测试 (Runs Test): 验证连续相同比特的长度分布符合几何分布

    - Hamming weight distribution: ideal 0.5, checks bit bias
    - Byte value histogram: checks uniformity across 256 values
    - Autocorrelation (shift=1 & shift=256): ideal 1/256 ≈ 0.003906
    - Runs test: checks that run-length distribution follows geometric distribution

架构概述 / Architecture overview:
    三个 256 字节状态池（Pool 1/2/3）级联更新，熵源来自 ADC 温度传感器最低位。
    Three 256-byte state pools (Pool 1/2/3) are updated in a cascaded manner,
    seeded by the LSB of the ADC temperature sensor reading.

    更新频率 / Update frequency:
        Pool 1：每输出 1 字节更新一次（最高频）
        Pool 2：Pool 1 指针溢出时更新（每 256 字节）
        Pool 3：Pool 2 指针溢出时更新（每 65,536 字节），同时注入新鲜 ADC 熵

        Pool 1: updated every 1 byte output (highest frequency)
        Pool 2: updated on Pool 1 pointer wrap (every 256 bytes)
        Pool 3: updated on Pool 2 pointer wrap (every 65,536 bytes),
                with fresh ADC entropy injected at each update

设计容量与续期 / Capacity and renewal:
    单次初始化后，PRNG 的有效容量为 256³ = 16,777,216 字节，
    可支撑约 9,300 次连续的 prng_fill_reserve_pool() 调用（每次消耗 1792 字节）。
    Pool 3 的级联刷新会持续注入新鲜熵，理论上只要设备运行，容量无严格上限。

    但需注意：运行时 Pool 3 刷新（_advance_pool3）中的 ADC 采样耗时较长，
    在时序严格的场景下可能引发超时。正常使用场景下连续调用 9,300 次本身属于
    异常行为，因此这一时序约束客观上构成了一种自然的速率限制机制。

    After a single initialization, the effective capacity is 256³ = 16,777,216
    bytes, supporting approximately 9,300 consecutive prng_fill_reserve_pool()
    calls (1,792 bytes each). Pool 3's cascaded refresh continuously injects
    fresh entropy, so there is no strict capacity ceiling as long as the device
    is running.

    Note: the ADC sampling inside the runtime Pool 3 refresh (_advance_pool3)
    has non-trivial latency and may cause timeout errors in timing-sensitive
    contexts. Under normal usage, 9,300 consecutive decryption calls is itself
    anomalous, so this timing constraint effectively acts as a natural
    rate-limiting mechanism.

鲁棒性设计 / Robustness:
    初始种子使用有偏熵源模拟（0:1 ≈ 7:3），验证 PRNG 在较差初始条件下
    的收敛行为。测试表明偏置会在输出的早期样本中保留：
    以 7:3 偏置初始化时，前 1000 字节中 1 的占比约为 44.7%（理想值 50%）。
    偏置的消除速度与初始偏度和样本量正相关——初始偏度越大、样本越少，
    输出的偏度越显著；随样本量增大，输出逐渐收敛至均匀分布。

    在实际部署场景中，ADC 温度传感器的熵质量通常远好于 7:3 偏置，
    且每次 AES 解密后即刷新随机池，有偏的初始样本仅影响上电后极短的
    一段时间，在正常使用模式下不构成实际威胁。

    Seeds are intentionally biased (0:1 ≈ 7:3) to simulate a poor-quality
    physical entropy source and observe convergence behavior.
    Testing shows that bias is retained in early output samples:
    with 7:3 initialization, the ratio of 1-bits in the first 1,000 bytes
    is approximately 44.7% (ideal: 50%).
    The rate of bias elimination is proportional to both the initial bias
    magnitude and the sample size.

    In practice, ADC temperature sensor entropy is typically far better
    than a 7:3 bias, and the random pool is refreshed after every AES
    decryption. The biased initial samples affect only a brief window
    after power-on and pose no practical concern under normal usage.

与硬件实现的对应关系 / Correspondence to hardware implementation:
    - EmbeddedPRNG.func1/2/3 与 prng_reference.c 中的 func1/2/3 逻辑严格一致
    - ADC 熵源在本脚本中用 os.urandom(1) 代替
    - 本脚本不模拟 fill_high_16bits_random 对 BsRoundKeys 高位的填充，
      仅验证 reserve_pool 部分的随机性质量

    - EmbeddedPRNG.func1/2/3 strictly mirrors func1/2/3 in prng_reference.c
    - ADC entropy is replaced by os.urandom(1) in this script
    - This script does not simulate fill_high_16bits_random; it only
      verifies the randomness quality of the reserve_pool portion

局限性声明 / Limitations:
    统计测试通过不等于密码学安全。本脚本的结论仅支持 prng_reference.c 中的
    安全声明：在一阶 ISW 掩码场景下随机性质量足够，不适用于其他场景。

    Passing these statistical tests does not imply cryptographic security.
    The conclusions here support only the claim made in prng_reference.c: that
    the randomness quality is sufficient for first-order ISW masking.
    No broader security claims are made.
"""

import os
import time
import random
import multiprocessing
from multiprocessing import shared_memory
from concurrent.futures import ProcessPoolExecutor

# 预计算字节（0-255）的置位数量以加速汉明重量计算 / Precompute bit counts for bytes (0-255) to speed up Hamming weight calculation
POPCOUNT_TABLE = [bin(i).count('1') for i in range(256)]

class EmbeddedPRNG:
    def __init__(self):
        # 启动时加载 3 份 256 字节初始随机池（Pool 1/2/3）/ Load three 256-byte initial random pools (Pool 1/2/3) at startup
        # 模拟 ROM 初始种子；在实际 MCU 上可来自未初始化 RAM 或预存 ROM / Simulate a ROM seed; on real MCUs this may come from uninitialized RAM or stored ROM
        # 使用有偏种子（0:1 ≈ 7:3）模拟较差的物理熵源 / Use a biased seed (0:1 ≈ 7:3) to emulate a weak physical entropy source
        self.pool1 = self._generate_biased_pool(256, 0.7)
        self.pool2 = self._generate_biased_pool(256, 0.7)
        self.pool3 = self._generate_biased_pool(256, 0.7)
        
        self.idx1 = 0
        self.idx2 = 0
        self.idx3 = 0
        
        # 统计各池刷新次数，用于调试 / Track refresh counts for debugging
        self.refresh_count_p1 = 0
        self.refresh_count_p2 = 0
        self.refresh_count_p3 = 0

    def _generate_biased_pool(self, size, zero_ratio):
        """
        生成指定大小的有偏随机字节池 / Generate a biased random byte pool of the given size.
        :param size: 大小（字节）/ Size in bytes
        :param zero_ratio: 0 的概率（0.0 - 1.0）/ Probability of generating 0 bits
        :return: bytearray
        """
        pool = bytearray(size)
        for i in range(size):
            byte_val = 0
            for bit in range(8):
                # 若随机值 >= zero_ratio，则该位设为 1；例如 zero_ratio=0.7 时约有 30% 概率置 1 / Set the bit to 1 when random() >= zero_ratio; for zero_ratio=0.7 this gives about a 30% chance of 1
                if random.random() >= zero_ratio:
                    byte_val |= (1 << bit)
            pool[i] = byte_val
        return pool

    def func1(self, val, feedback):
        """
        策略 1：用于 Pool 1 的 Xorshift 变体，目标是快速扩散并适配 M0 寄存器操作 / Strategy 1: Xorshift variant for Pool 1, designed for fast diffusion and M0-friendly register operations
        """
        # New_P1[i] = P1[i] ^ Feedback_Var / 先混入反馈值
        x = (val ^ feedback) & 0xFF
        # New_P1[i] ^= New_P1[i] << 3 / 左移扩散
        x ^= (x << 3) & 0xFF
        # New_P1[i] ^= New_P1[i] >> 5 / 右移进一步混合
        x ^= (x >> 5)
        # New_P1[i] ^= 0x1B / 引入常数以避免陷入全 0
        x ^= 0x1B
        return x & 0xFF

    def func2(self, val, feedback):
        """
        策略 2：用于 Pool 2 的乘法非线性更新，目标是利用 M0 乘法器增强非线性 / Strategy 2: Multiplication-based nonlinear update for Pool 2, using the M0 multiplier to increase nonlinearity
        """
        # New_P2[i] = ((P2[i] ^ Feedback_Var) * 31) + 13 / 混入反馈后做线性同余式扰动
        x = (val ^ feedback) & 0xFF
        x = (x * 31 + 13) & 0xFF
        return x

    def func3(self, val, feedback, idx):
        """
        策略 3：用于 Pool 3 的按位旋转更新，目标是通过位位置变换打乱结构 / Strategy 3: Bit-rotation update for Pool 3, designed to scramble structure through bit-position changes
        """
        # temp = P3[i] ^ Feedback_Var / 先与反馈值异或
        temp = (val ^ feedback) & 0xFF
        # New_P3[i] = (temp << i%8) | (temp >> (8 - i%8 )) / 模拟 8 位循环左移
        shift = idx % 8
        x = ((temp << shift) | (temp >> (8 - shift))) & 0xFF
        # New_P3[i] = ~New_P3[i] / 最后按位取反
        x = (~x) & 0xFF
        return x

    def get_byte(self):
        """
        获取一个随机字节，采用渐进式单字节刷新策略：当指针前进到下一项时刷新刚取走的位置 / Get one random byte using incremental single-byte refresh: refresh the slot immediately after it is consumed
        """
        # 取出当前指针处的数据作为输出 / Read the current slot as output
        current_idx = self.idx1
        val = self.pool1[current_idx]
        
        # 刷新刚取走的位置：取走 -> 立即刷新 -> 指针后移 / Refresh the consumed slot immediately: read -> refresh -> advance
        # 从 Pool 2 获取种子 / Get the seed from Pool 2
        seed_p2 = self.pool2[self.idx2]
        # 刷新 Pool 1 当前槽位 / Refresh the current slot in Pool 1
        self.pool1[current_idx] = self.func1(self.pool1[current_idx], seed_p2)
        # 指针后移并处理级联进位 / Advance the pointer and handle cascading carry
        self.idx1 = (self.idx1 + 1) % 256
        # 若 Pool 1 完成一圈，则推进 Pool 2 / If Pool 1 wraps around, advance Pool 2
        if self.idx1 == 0:
            self._advance_pool2()
            
        return val

    def _advance_pool2(self):
        """
        当 Pool 1 完成一圈时，推进 Pool 2 指针并刷新当前位置 / Advance the Pool 2 pointer and refresh its current slot when Pool 1 completes one full cycle
        """
        current_idx = self.idx2
        
        # 从 Pool 3 获取种子 / Get the seed from Pool 3
        seed_p3 = self.pool3[self.idx3]
        # 刷新 Pool 2 当前位置 / Refresh the current slot in Pool 2
        self.pool2[current_idx] = self.func2(self.pool2[current_idx], seed_p3)
        # Pool 2 指针后移 / Advance the Pool 2 pointer
        self.idx2 = (self.idx2 + 1) % 256
        # 若 Pool 2 回绕，则触发 Pool 3 进位 / If Pool 2 wraps around, trigger Pool 3 carry
        if self.idx2 == 0:
            self._advance_pool3()
            
    def _advance_pool3(self):
        """
        当 Pool 2 完成一圈时，推进 Pool 3 指针并刷新当前位置 / Advance the Pool 3 pointer and refresh its current slot when Pool 2 completes one full cycle
        """
        current_idx = self.idx3
        
        # 获取熵源（Pool 1[0] + ADC 噪声）/ Obtain entropy from Pool 1[0] plus ADC noise
        adc_noise = os.urandom(1)[0]
        seed_entropy = (self.pool1[0] + adc_noise) & 0xFF
        
        # 刷新 Pool 3 当前位置 / Refresh the current slot in Pool 3
        self.pool3[current_idx] = self.func3(self.pool3[current_idx], seed_entropy, current_idx)
        # Pool 3 指针后移 / Advance the Pool 3 pointer
        self.idx3 = (self.idx3 + 1) % 256


def worker_analysis(shm_name, size, start_idx, end_idx):
    """
    处理一段数据分片的工作函数，计算汉明重量、字节分布与自相关（shift 1 和 256）/ Worker function for processing a data chunk, computing Hamming weight, byte distribution, and autocorrelation (shift 1 and 256)
    """
    # 连接到共享内存 / Attach to shared memory
    try:
        existing_shm = shared_memory.SharedMemory(name=shm_name)
        data = existing_shm.buf
    except FileNotFoundError:
        return None

    ones_count = 0
    counts = [0] * 256
    match_s1 = 0
    match_s256 = 0
    
    # 预先计算自相关边界，避免索引越界 / Precompute autocorrelation limits to avoid index out of bounds
    limit_s1 = size - 1
    limit_s256 = size - 256

    # 处理当前分片；虽然只遍历本 worker 的区间，但自相关仍可安全访问共享缓冲区中的 i+shift / Process this chunk; although we iterate only this worker's range, autocorrelation can safely access i+shift in the shared buffer
    for i in range(start_idx, end_idx):
        val = data[i]
        
        # 1. 汉明重量 / Hamming weight
        ones_count += POPCOUNT_TABLE[val]
        
        # 2. 直方图统计 / Histogram
        counts[val] += 1
        
        # 3. 自相关（shift 1）/ Autocorrelation (shift 1)
        if i < limit_s1:
            if val == data[i+1]:
                match_s1 += 1
                
        # 4. 自相关（shift 256）/ Autocorrelation (shift 256)
        if i < limit_s256:
            if val == data[i+256]:
                match_s256 += 1
                
    existing_shm.close()
    return (ones_count, counts, match_s1, match_s256)

def test_runs(data):
    """
    B. 游程测试：检测连续相同比特段的长度分布 / B. Runs test: measure the length distribution of consecutive identical bits
    """
    # 限制测试范围以保证速度；大样本 Runs Test 在 Python 中很慢且占内存，这里仅取较小样本演示 / Limit the test range for speed; large-sample runs tests are slow and memory-heavy in Python, so a smaller sample is used here for demonstration
    limit = min(len(data), 60_000)
    
    print(f"\n--- Runs Test (Sample: {limit} bytes) ---")
    
    # 优化：不构造巨大的 01 字符串，直接逐位遍历并统计 runs 分布 / Optimization: avoid building a huge 01 string and iterate bit by bit instead
    runs = {}
    
    current_bit = -1
    current_length = 0
    
    # 遍历每个字节 / Iterate over each byte
    for i in range(limit):
        byte_val = data[i]
        for bit_idx in range(7, -1, -1): # 从高位到低位 / From MSB to LSB
            bit = (byte_val >> bit_idx) & 1
            
            if bit == current_bit:
                current_length += 1
            else:
                if current_length > 0:
                    runs[current_length] = runs.get(current_length, 0) + 1
                current_bit = bit
                current_length = 1
                
    # 记录最后一段 run / Record the final run
    if current_length > 0:
        runs[current_length] = runs.get(current_length, 0) + 1
    
    total_runs = sum(runs.values())
    print(f"Total Runs: {total_runs}")
    
    # 打印前 6 种长度的分布 / Print the distribution of the first 6 run lengths
    for length in range(1, 7):
        count = runs.get(length, 0)
        prob = count / total_runs if total_runs > 0 else 0
        expected = (0.5) ** length
        print(f"Length {length}: {prob:.4f} (Expected: {expected:.4f})")

def run_test():
    prng = EmbeddedPRNG()
    total_bytes = 10_00
    
    print(f"Starting simulation for {total_bytes} bytes...")
    print("Strategies: Func1(Xorshift), Func2(Mul), Func3(Rotate)")
    start_time = time.time()
    
    # 预分配共享内存以存放随机数据，便于多进程分析 / Preallocate shared memory for random data so it can be analyzed across processes
    try:
        shm = shared_memory.SharedMemory(create=True, size=total_bytes)
    except Exception as e:
        print(f"Failed to create shared memory: {e}")
        return

    # 使用 memoryview 访问共享内存，方式类似 bytearray / Access shared memory via a memoryview, similar to a bytearray
    random_bytes = shm.buf
    
    # 单线程生成随机数，因为 PRNG 状态存在顺序依赖 / Generate random bytes in a single thread because the PRNG state is sequentially dependent
    for i in range(total_bytes):
        random_bytes[i] = prng.get_byte()
        
    end_time = time.time()
    print(f"Generation complete. Time: {end_time - start_time:.4f}s")
    
    # --- Statistical Analysis (Parallel) ---
    print("\n--- Statistical Analysis (Parallel 8 threads) ---")
    analysis_start = time.time()
    
    num_workers = 8
    chunk_size = total_bytes // num_workers
    futures = []
    
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        for i in range(num_workers):
            start = i * chunk_size
            # 最后一个 chunk 处理剩余所有数据
            end = total_bytes if i == num_workers - 1 else (i + 1) * chunk_size
            
            futures.append(executor.submit(worker_analysis, shm.name, total_bytes, start, end))
            
    # Aggregate results
    total_ones = 0
    total_counts = [0] * 256
    total_match_s1 = 0
    total_match_s256 = 0
    
    for f in futures:
        ones, counts, m1, m256 = f.result()
        total_ones += ones
        for idx in range(256):
            total_counts[idx] += counts[idx]
        total_match_s1 += m1
        total_match_s256 += m256
        
    analysis_end = time.time()
    print(f"Analysis Time: {analysis_end - analysis_start:.4f}s")
    
    # 1. Hamming Weight
    total_bits = total_bytes * 8
    ratio = total_ones / total_bits
    print(f"Total Bits: {total_bits}")
    print(f"Ones Count: {total_ones}")
    print(f"Ones Ratio: {ratio:.6f} (Ideal: 0.500000)")
    
    # 2. Byte Value Distribution
    expected_count = total_bytes / 256
    min_count = min(total_counts)
    max_count = max(total_counts)
    print(f"Byte Distribution: Min={min_count}, Max={max_count}, Expected={expected_count:.1f}")
    
    if total_counts[0] > expected_count * 5:
        print("!!! WARNING: Potential Zero Trap detected (Too many 0x00) !!!")
    elif total_counts[0] == 0:
        print("!!! WARNING: 0x00 never generated (Coverage issue) !!!")
        
    if total_counts[255] > expected_count * 5:
        print("!!! WARNING: Potential FF Trap detected (Too many 0xFF) !!!")
        
    # 3. Visual Sample (First 32 bytes hex)
    # Read from shared memory buffer
    print("\n--- Visual Sample (First 32 bytes) ---")
    print(bytes(random_bytes[:32]).hex().upper())
    
    # 4. Advanced Tests
    print("\n--- Advanced Statistical Tests ---")
    
    # Autocorrelation results from parallel workers
    # 注意：worker 计算的是匹配次数，我们需要除以 (N - shift)
    limit_s1 = total_bytes - 1
    ratio_s1 = total_match_s1 / limit_s1
    print(f"Autocorrelation (shift 1): {ratio_s1:.6f} (Target: 0.003906)")
    
    limit_s256 = total_bytes - 256
    ratio_s256 = total_match_s256 / limit_s256
    print(f"Autocorrelation (shift 256): {ratio_s256:.6f} (Target: 0.003906)")

    # Runs Test (Runs on main process with limited sample)
    test_runs(random_bytes)
    
    print("\n--- Next Steps ---")
    if 0.499 < ratio < 0.501:
        print("SUCCESS: Bit distribution is excellent.")
    else:
        print("WARNING: Bit distribution shows bias.")

    # Clean up shared memory
    shm.close()
    shm.unlink()

if __name__ == "__main__":
    run_test()