// --------------------------------------------------------
// EmbeddedPRNG Implementation
// 嵌入式三层级联 PRNG 实现
// --------------------------------------------------------
//
// 设计概述 / Design Overview:
//
//   三个 256 字节的状态池（Pool 1/2/3）级联更新，熵源来自 ADC 温度传感器最低位。
//   Three 256-byte state pools (Pool 1/2/3) are updated in a cascaded manner,
//   seeded by the LSB of the ADC temperature sensor reading.
//
//   更新频率 / Update frequency:
//     Pool 1：每输出 1 字节更新一次（最高频）
//     Pool 2：Pool 1 指针溢出（每 256 字节）时更新一次
//     Pool 3：Pool 2 指针溢出（每 65536 字节）时更新一次（最低频）
//
//     Pool 1: updated every 1 byte output (highest frequency)
//     Pool 2: updated every 256 bytes (on Pool 1 pointer wrap)
//     Pool 3: updated every 65536 bytes (on Pool 2 pointer wrap)
//
//   每次调用 prng_fill_reserve_pool() 输出 1792 字节，
//   Pool 3 在单次调用中不会触发更新（1792 < 65536）。
//   Each call to prng_fill_reserve_pool() outputs 1792 bytes;
//   Pool 3 is not triggered within a single call (1792 < 65536).
//
// ⚠️  安全声明 / Security Notice:
//   本方案未经正式密码学分析，但在大样本下通过了统计质量测试（详见 prng_verify.py）。
//   设计目标是在资源受限的 Cortex-M0 上为一阶 ISW 掩码提供足够的随机性。
//   不建议直接用于其他安全场景，如需复用请先针对目标场景进行独立评估。
//
//   This PRNG has not undergone formal cryptographic analysis, but has passed
//   statistical quality tests on large sample sizes (see prng_verify.py).
//   It is designed to provide sufficient randomness for first-order ISW masking
//   on a resource-constrained Cortex-M0.
//   It is NOT recommended for other security-critical applications without
//   independent evaluation for the target use case.
// --------------------------------------------------------

uint8_t pool1[256] __attribute__((aligned(4))); // 主输出池 / Primary output pool
uint8_t pool2[256];                              // 二级种子池 / Secondary seed pool
uint8_t pool3[256];                              // 三级熵池，ADC 直接注入 / Tertiary entropy pool, fed directly by ADC
uint8_t reserve_pool[1792] __attribute__((aligned(4))); // 对齐要求来自 asm_aes 的 LDMIA/STMIA / Alignment required by LDMIA/STMIA in asm_aes

uint8_t idx1 = 0;    // Pool 1 当前指针，溢出自动模 256 / Pool 1 pointer, wraps mod 256 automatically
uint8_t idx2 = 0;    // Pool 2 当前指针 / Pool 2 pointer
uint8_t idx3 = 0;    // Pool 3 当前指针 / Pool 3 pointer
uint16_t reserve_idx = 0; // reserve_pool 填充进度（当前未使用） / Fill progress for reserve_pool (currently unused)

static uint8_t func1(uint8_t val, uint8_t feedback) {
    // 非线性混合：异或 + 位移 + 常数扰动
    // Nonlinear mixing: XOR + bit shifts + constant perturbation
    uint8_t x = (val ^ feedback);
    x ^= (x << 3);
    x ^= (x >> 5);
    x ^= 0x1B; // AES 域的不可约多项式常数，无特殊含义，仅作扰动
                // Irreducible polynomial constant from AES field, used as perturbation only
    return x;
}

static uint8_t func2(uint8_t val, uint8_t feedback) {
    // 非线性混合：乘法 + 加法（利用 uint8_t 自动模 256）
    // Nonlinear mixing: multiplication + addition (mod 256 via uint8_t overflow)
    uint8_t x = (val ^ feedback);
    x = (x * 31 + 13);
    return x;
}

static uint8_t func3(uint8_t val, uint8_t feedback, uint8_t idx) {
    // 非线性混合：位旋转 + 取反，旋转量随索引变化
    // Nonlinear mixing: bit rotation + bitwise NOT, rotation amount varies with index
    uint8_t temp = (val ^ feedback);
    uint8_t shift = idx % 8;
    uint8_t x = (temp << shift) | (temp >> (8 - shift));
    x = ~x;
    return x;
}

static void prng_init(void) {
    // 用 ADC 采样填充三个池子的初始状态
    // Initialize all three pools with ADC samples
    // 注：每次采样的最低位作为熵，其余位也保留（增加初始状态多样性）
    // Note: LSB of each sample carries entropy; higher bits are retained for diversity
    for (int i = 0; i < 256; i++) {
        pool1[i] = adc_read_raw() & 0xFF;
        pool2[i] = adc_read_raw() & 0xFF;
        pool3[i] = adc_read_raw() & 0xFF;
    }
}

static void _advance_pool3(void) {
    uint8_t current_idx = idx3;

    // 混合 Pool 1[0] 和新鲜 ADC 采样作为熵注入
    // Mix Pool 1[0] with a fresh ADC sample as entropy input
    uint8_t adc_noise = adc_read_raw() & 0xFF;
    uint8_t seed_entropy = (pool1[0] + adc_noise);

    pool3[current_idx] = func3(pool3[current_idx], seed_entropy, current_idx);
    idx3++; // uint8_t 自动模 256 / Implicit mod 256 for uint8_t
}

static void _advance_pool2(void) {
    uint8_t current_idx = idx2;

    // 以 Pool 3 当前位置的值作为种子，取完即触发 Pool 3 刷新该位置。
    // 这是有意为之的"拿即刷"设计：Pool 2 消费 Pool 3[idx3] 的旧值，
    // 消费行为本身触发了对该位置的更新，而非取更新后的新值。
    //
    // Use the current Pool 3 value as seed; this read is immediately
    // followed by a Pool 3 refresh of that same position.
    // This is intentional "read-then-refresh" design: Pool 2 consumes
    // the old value at Pool 3[idx3], and that consumption triggers
    // the update of that position — not the value after the update.
    uint8_t seed_p3 = pool3[idx3];

    pool2[current_idx] = func2(pool2[current_idx], seed_p3);
    idx2++;

    // Pool 2 溢出时级联触发 Pool 3 更新
    // Cascade: trigger Pool 3 advance when Pool 2 wraps
    if (idx2 == 0) {
        _advance_pool3();
    }
}

void prng_fill_reserve_pool(void) {
    // 填充 reserve_pool，供下一次 asm_aes 调用使用
    // Fill reserve_pool for the next asm_aes call
    //
    // 输出逻辑：读取 Pool 1 当前值后立即用 Pool 2 的种子更新它，
    // 保证输出值与下一次更新解耦。
    // Output logic: the current Pool 1 value is read BEFORE being updated
    // with Pool 2's seed, decoupling the output from the next update.
    reserve_idx = 0;

    for (int i = 0; i < 1792; i++) {
        uint8_t val      = pool1[idx1];
        uint8_t seed_p2  = pool2[idx2];

        pool1[idx1] = func1(val, seed_p2); // 更新后不影响本次输出 / Update does not affect current output

        reserve_pool[i] = val;

        idx1++;
        // Pool 1 溢出时级联触发 Pool 2 更新
        // Cascade: trigger Pool 2 advance when Pool 1 wraps
        if (idx1 == 0) {
            _advance_pool2();
        }
    }
}