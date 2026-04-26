#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import os
import re
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np


SCRIPT_DIR = Path(__file__).resolve().parent
CACHE_DIR_NAME = ".cpa_cache_v2"
RESULT_DIR_NAME = "cpa_results_v2"

WINDOWS = {
    "1": {
        "name": "roi1",
        "label": "区间1",
        "start": 1000,
        "end": 4000,
        "round_key_type": "round10",
        "desc": "800..3000，默认视为第10轮轮密钥泄漏",
    },
    "2": {
        "name": "roi2",
        "label": "区间2",
        "start": 30500,
        "end": None,
        "round_key_type": "round0",
        "desc": "24000..trace末尾，默认视为第0轮轮密钥泄漏",
    },
}

INV_SBOX = np.array([
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
], dtype=np.uint8)

SBOX = np.array([
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
], dtype=np.uint8)

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
HW = np.array([bin(i).count("1") for i in range(256)], dtype=np.uint8)

EXPECTED_WINDOW_KEYS = {
    "1": bytes([0xD0, 0x14, 0xF9, 0xA8, 0xC9, 0xEE, 0x25, 0x89, 0xE1, 0x3F, 0x0C, 0xC8, 0xB6, 0x63, 0x0C, 0xA6]),
    "2": bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C]),
}

MODEL_VARIANTS = {
    "sbox_input": "SBox(P ^ K0)",
    "ark_output": "P ^ K0",
}


@dataclass
class ByteAttackResult:
    byte_index: int
    best_key: int
    best_corr: float
    best_location: int | None
    mean_top10: list[tuple[int, float]]
    max_key: int
    max_corr: float
    max_top10: list[tuple[int, float]]
    order: str
    window_name: str
    window_label: str
    location_kind: str
    bit_peaks: list[float]


@dataclass
class RunPaths:
    base_dir: Path
    trace_dir: Path
    io_path: Path
    cache_dir: Path
    result_dir: Path


def prompt_choice(prompt: str, valid: set[str], default: str | None = None) -> str:
    while True:
        suffix = f" [{default}]" if default is not None else ""
        ans = input(f"{prompt}{suffix}: ").strip().lower()
        if not ans and default is not None:
            return default
        if ans in valid:
            return ans
        print(f"请输入 {sorted(valid)} 之一。")


def prompt_int(prompt: str, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    while True:
        raw = input(f"{prompt} [{default}]: ").strip()
        if raw == "":
            value = default
        else:
            try:
                value = int(raw)
            except ValueError:
                print("请输入整数。")
                continue
        if min_value is not None and value < min_value:
            print(f"不能小于 {min_value}")
            continue
        if max_value is not None and value > max_value:
            print(f"不能大于 {max_value}")
            continue
        return value


def resolve_run_paths() -> RunPaths:
    while True:
        raw = input("请输入包含 trace 的文件夹路径: ").strip()
        if not raw:
            print("路径不能为空。")
            continue

        base_dir = Path(raw).expanduser().resolve()
        if not base_dir.exists() or not base_dir.is_dir():
            print(f"目录不存在: {base_dir}")
            continue

        trace_dir_candidates = [base_dir, base_dir / "traces"]
        trace_dir = next((p for p in trace_dir_candidates if p.exists() and any(p.glob("*.trc"))), None)
        if trace_dir is None:
            print(f"在 {base_dir} 及其 traces/ 子目录下都没有找到 .trc 文件")
            continue

        io_candidates = [base_dir / "io_pairs.csv", trace_dir / "io_pairs.csv", trace_dir.parent / "io_pairs.csv"]
        io_path = next((p for p in io_candidates if p.exists() and p.is_file()), None)
        if io_path is None:
            print(f"未找到 io_pairs.csv，已检查: {', '.join(str(p) for p in io_candidates)}")
            continue

        return RunPaths(
            base_dir=base_dir,
            trace_dir=trace_dir,
            io_path=io_path,
            cache_dir=base_dir / CACHE_DIR_NAME,
            result_dir=base_dir / RESULT_DIR_NAME,
        )


def ensure_dirs(paths: RunPaths) -> None:
    paths.cache_dir.mkdir(parents=True, exist_ok=True)
    paths.result_dir.mkdir(parents=True, exist_ok=True)


def parse_hex_16(hex_text: str) -> np.ndarray:
    data = bytes.fromhex(hex_text)
    if len(data) != 16:
        raise ValueError(f"期望 16 字节十六进制字符串，实际 {len(data)} 字节: {hex_text}")
    return np.frombuffer(data, dtype=np.uint8).copy()


def load_io_pairs(csv_path: Path) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    rows: list[tuple[int, np.ndarray, np.ndarray]] = []
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            idx = int(row["index"])
            ciphertext = parse_hex_16(row["input_hex"])
            plaintext = parse_hex_16(row["expected_output_hex"])
            rows.append((idx, ciphertext, plaintext))

    rows.sort(key=lambda x: x[0])
    indices = np.array([x[0] for x in rows], dtype=np.int32)
    ciphertexts = np.stack([x[1] for x in rows], axis=0)
    plaintexts = np.stack([x[2] for x in rows], axis=0)
    return indices, ciphertexts, plaintexts


def trace_sort_key(path: Path) -> tuple[int, int | str]:
    m = re.search(r"(\d+)", path.stem)
    if m:
        return (0, int(m.group(1)))
    return (1, path.name)


def discover_trace_files(trace_dir: Path) -> list[Path]:
    files = sorted(trace_dir.glob("*.trc"), key=trace_sort_key)
    if not files:
        raise FileNotFoundError(f"未在 {trace_dir} 下找到 `.trc` 文件")
    return files


def get_total_samples(trace_path: Path) -> int:
    data = np.loadtxt(trace_path, dtype=np.float32)
    if data.ndim == 0:
        return 1
    return int(data.shape[0])


def build_window_points(window_key: str, total_samples: int, step: int) -> np.ndarray:
    spec = WINDOWS[window_key]
    start = max(0, spec["start"])
    end = total_samples - 1 if spec["end"] is None else min(total_samples - 1, spec["end"])
    if start > end:
        return np.empty(0, dtype=np.int32)
    return np.arange(start, end + 1, step, dtype=np.int32)


def cache_file_paths(cache_dir: Path, window_key: str, num_traces: int, total_samples: int, step: int, num_points: int) -> tuple[Path, Path]:
    name = WINDOWS[window_key]["name"]
    tag = f"{name}_n{num_traces}_len{total_samples}_step{step}_pts{num_points}"
    return cache_dir / f"{tag}.npy", cache_dir / f"{tag}.json"


def load_or_build_window_cache(
    trace_files: list[Path],
    cache_dir: Path,
    window_key: str,
    total_samples: int,
    step: int,
) -> tuple[Path, np.ndarray]:
    points = build_window_points(window_key, total_samples, step)
    if points.size == 0:
        raise ValueError(f"{WINDOWS[window_key]['label']} 在当前迹线长度下为空")

    cache_npy, cache_meta = cache_file_paths(cache_dir, window_key, len(trace_files), total_samples, step, int(points.size))

    if cache_npy.exists() and cache_meta.exists():
        try:
            meta = json.loads(cache_meta.read_text(encoding="utf-8"))
            valid = (
                meta.get("window_key") == window_key
                and meta.get("num_traces") == len(trace_files)
                and meta.get("total_samples") == total_samples
                and meta.get("step") == step
                and meta.get("num_points") == int(points.size)
                and meta.get("first_trace") == trace_files[0].name
                and meta.get("last_trace") == trace_files[-1].name
            )
            if valid:
                print(f"[+] 使用缓存: {cache_npy.name}")
                return cache_npy, points
        except Exception:
            pass

    print(f"[+] 构建 {WINDOWS[window_key]['label']} ROI 缓存，首次运行会较慢...")
    traces = np.empty((len(trace_files), points.size), dtype=np.float32)

    for i, path in enumerate(trace_files, start=1):
        full_trace = np.loadtxt(path, dtype=np.float32)
        if full_trace.ndim == 0:
            full_trace = np.array([full_trace], dtype=np.float32)
        if full_trace.shape[0] < total_samples:
            raise ValueError(f"迹线长度不一致: {path}")
        traces[i - 1, :] = full_trace[points]
        if i % 200 == 0 or i == len(trace_files):
            print(f"    已加载 {i}/{len(trace_files)} 条")

    np.save(cache_npy, traces)
    cache_meta.write_text(
        json.dumps(
            {
                "window_key": window_key,
                "num_traces": len(trace_files),
                "total_samples": total_samples,
                "step": step,
                "num_points": int(points.size),
                "first_trace": trace_files[0].name,
                "last_trace": trace_files[-1].name,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"[+] 已写入缓存: {cache_npy}")
    return cache_npy, points


def build_intermediate_values(
    window_key: str,
    cipher_column: np.ndarray,
    plain_column: np.ndarray,
    model_variant: str,
) -> np.ndarray:
    guesses = np.arange(256, dtype=np.uint8)[:, None]
    if window_key == "1":
        return INV_SBOX[np.bitwise_xor(guesses, cipher_column[None, :])]
    if window_key == "2":
        x = np.bitwise_xor(guesses, plain_column[None, :])
        if model_variant == "sbox_input":
            return SBOX[x]
        if model_variant == "ark_output":
            return x
        raise ValueError(f"未知模型: {model_variant}")
    raise ValueError(f"未知窗口: {window_key}")


def build_bit_hypothesis(values: np.ndarray, bit_index: int) -> tuple[np.ndarray, np.ndarray]:
    hyp = ((values >> bit_index) & 1).astype(np.float64)
    hyp -= hyp.mean(axis=1, keepdims=True)
    hyp_norm = np.linalg.norm(hyp, axis=1)
    hyp_norm[hyp_norm == 0.0] = np.nan
    return hyp, hyp_norm


def centered_block(block: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    blk = np.asarray(block, dtype=np.float64)
    blk -= blk.mean(axis=0, keepdims=True)
    norms = np.linalg.norm(blk, axis=0)
    return blk, norms


def top10_from_scores(scores: np.ndarray) -> list[tuple[int, float]]:
    order = np.argsort(scores)[-10:][::-1]
    return [(int(k), float(scores[k])) for k in order]


def first_order_worker(args: dict[str, Any]) -> ByteAttackResult:
    trace_cache = Path(args["trace_cache"])
    points = np.array(args["points"], dtype=np.int32)
    ciphertexts = np.array(args["ciphertexts"], dtype=np.uint8)
    plaintexts = np.array(args["plaintexts"], dtype=np.uint8)
    byte_index = int(args["byte_index"])
    block_size = int(args["block_size"])
    window_key = str(args["window_key"])
    model_variant = str(args["model_variant"])
    window_name = str(args["window_name"])
    window_label = str(args["window_label"])

    traces = np.load(trace_cache, mmap_mode="r")
    values = build_intermediate_values(window_key, ciphertexts[:, byte_index], plaintexts[:, byte_index], model_variant)

    bit_scores = np.full((256, 8), -np.inf, dtype=np.float64)
    bit_locs = np.zeros((256, 8), dtype=np.int32)

    total_cols = traces.shape[1]
    for bit in range(8):
        hyp, hyp_norm = build_bit_hypothesis(values, bit)
        best_score = np.full(256, -np.inf, dtype=np.float64)
        best_loc = np.zeros(256, dtype=np.int32)

        for start in range(0, total_cols, block_size):
            end = min(start + block_size, total_cols)
            blk, blk_norm = centered_block(traces[:, start:end])
            valid = blk_norm > 0.0
            if not np.any(valid):
                continue

            corr = (hyp @ blk[:, valid]) / (hyp_norm[:, None] * blk_norm[valid][None, :])
            abs_corr = np.abs(corr)
            local_idx = np.argmax(abs_corr, axis=1)
            local_score = abs_corr[np.arange(256), local_idx]
            local_loc = points[start:end][valid][local_idx]

            better = local_score > best_score
            best_score[better] = local_score[better]
            best_loc[better] = local_loc[better]

        bit_scores[:, bit] = best_score
        bit_locs[:, bit] = best_loc

    mean_scores = np.mean(bit_scores, axis=1)
    max_scores = np.max(bit_scores, axis=1)
    best_key = int(np.argmax(mean_scores))
    max_key = int(np.argmax(max_scores))
    best_bit = int(np.argmax(bit_scores[best_key]))
    return ByteAttackResult(
        byte_index=byte_index,
        best_key=best_key,
        best_corr=float(mean_scores[best_key]),
        best_location=int(bit_locs[best_key, best_bit]),
        mean_top10=top10_from_scores(mean_scores),
        max_key=max_key,
        max_corr=float(max_scores[max_key]),
        max_top10=top10_from_scores(max_scores),
        order="first",
        window_name=window_name,
        window_label=window_label,
        location_kind="sample",
        bit_peaks=[float(x) for x in bit_scores[best_key]],
    )


def choose_points_by_variance(trace_cache: Path, points: np.ndarray, top_k: int) -> tuple[np.ndarray, np.ndarray]:
    traces = np.load(trace_cache, mmap_mode="r")
    work = np.asarray(traces, dtype=np.float64)
    var = np.var(work, axis=0)
    k = min(top_k, work.shape[1])
    idx = np.argsort(var)[-k:][::-1]
    selected_points = points[idx]
    selected = work[:, idx]
    selected -= selected.mean(axis=0, keepdims=True)
    return selected_points, selected


def second_order_worker(args: dict[str, Any]) -> ByteAttackResult:
    trace_cache = Path(args["trace_cache"])
    points = np.array(args["points"], dtype=np.int32)
    ciphertexts = np.array(args["ciphertexts"], dtype=np.uint8)
    plaintexts = np.array(args["plaintexts"], dtype=np.uint8)
    byte_index = int(args["byte_index"])
    top_k = int(args["top_k"])
    window_key = str(args["window_key"])
    model_variant = str(args["model_variant"])
    window_name = str(args["window_name"])
    window_label = str(args["window_label"])

    selected_points, selected = choose_points_by_variance(trace_cache, points, top_k)
    if selected.shape[1] < 2:
        raise ValueError(f"{window_label} 可用于二阶组合的点数不足 2")

    values = build_intermediate_values(window_key, ciphertexts[:, byte_index], plaintexts[:, byte_index], model_variant)

    bit_scores = np.full((256, 8), -np.inf, dtype=np.float64)
    bit_left = np.zeros((256, 8), dtype=np.int32)
    bit_right = np.zeros((256, 8), dtype=np.int32)

    k = selected.shape[1]
    for bit in range(8):
        hyp, hyp_norm = build_bit_hypothesis(values, bit)
        best_score = np.full(256, -np.inf, dtype=np.float64)
        best_left = np.zeros(256, dtype=np.int32)
        best_right = np.zeros(256, dtype=np.int32)

        for i in range(k - 1):
            prod = selected[:, [i]] * selected[:, i + 1 :]
            prod -= prod.mean(axis=0, keepdims=True)
            prod_norm = np.linalg.norm(prod, axis=0)
            valid = prod_norm > 0.0
            if not np.any(valid):
                continue

            corr = (hyp @ prod[:, valid]) / (hyp_norm[:, None] * prod_norm[valid][None, :])
            abs_corr = np.abs(corr)

            local_idx = np.argmax(abs_corr, axis=1)
            local_score = abs_corr[np.arange(256), local_idx]
            valid_local = np.flatnonzero(valid)[local_idx] + i + 1

            better = local_score > best_score
            best_score[better] = local_score[better]
            best_left[better] = i
            best_right[better] = valid_local[better]

        bit_scores[:, bit] = best_score
        bit_left[:, bit] = best_left
        bit_right[:, bit] = best_right

    mean_scores = np.mean(bit_scores, axis=1)
    max_scores = np.max(bit_scores, axis=1)
    best_key = int(np.argmax(mean_scores))
    max_key = int(np.argmax(max_scores))
    best_bit = int(np.argmax(bit_scores[best_key]))
    left_pt = int(selected_points[bit_left[best_key, best_bit]])
    right_pt = int(selected_points[bit_right[best_key, best_bit]])
    pair_marker = left_pt * 1_000_000 + right_pt

    return ByteAttackResult(
        byte_index=byte_index,
        best_key=best_key,
        best_corr=float(mean_scores[best_key]),
        best_location=pair_marker,
        mean_top10=top10_from_scores(mean_scores),
        max_key=max_key,
        max_corr=float(max_scores[max_key]),
        max_top10=top10_from_scores(max_scores),
        order="second",
        window_name=window_name,
        window_label=window_label,
        location_kind="pair",
        bit_peaks=[float(x) for x in bit_scores[best_key]],
    )


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def rot_word(word: bytes) -> bytes:
    return word[1:] + word[:1]


def sub_word(word: bytes) -> bytes:
    return bytes(int(SBOX[b]) for b in word)


def reverse_round10_key_to_master(round10_key: bytes) -> bytes:
    if len(round10_key) != 16:
        raise ValueError("round10_key 必须为 16 字节")

    words = [round10_key[i : i + 4] for i in range(0, 16, 4)]
    for rnd in range(10, 0, -1):
        c0, c1, c2, c3 = words
        p3 = xor_bytes(c3, c2)
        p2 = xor_bytes(c2, c1)
        p1 = xor_bytes(c1, c0)
        g = bytearray(sub_word(rot_word(p3)))
        g[0] ^= RCON[rnd]
        p0 = xor_bytes(c0, bytes(g))
        words = [p0, p1, p2, p3]

    return b"".join(words)


def derive_master_key_if_possible(window_key: str, results: list[ByteAttackResult]) -> tuple[str | None, str]:
    if len(results) != 16:
        return None, "仅恢复了部分字节，无法给出完整主密钥"

    ordered = sorted(results, key=lambda x: x.byte_index)
    key_bytes = bytes(r.best_key for r in ordered)
    rk_type = WINDOWS[window_key]["round_key_type"]

    if rk_type == "round0":
        return key_bytes.hex(), "该区间默认对应第0轮轮密钥，直接视为主密钥"
    if rk_type == "round10":
        master = reverse_round10_key_to_master(key_bytes)
        return master.hex(), "该区间默认对应第10轮轮密钥，已自动反推 AES-128 主密钥"
    return None, "未知轮密钥类型，未执行主密钥推导"


def print_window_results(window_key: str, results: list[ByteAttackResult]) -> None:
    print()
    print("=" * 56)
    print(f"{WINDOWS[window_key]['label']} 结果")
    print(f"说明: {WINDOWS[window_key]['desc']}")
    print("=" * 56)

    for r in sorted(results, key=lambda x: x.byte_index):
        print(f"Byte {r.byte_index:02d}: key=0x{r.best_key:02X}, corr={r.best_corr:+.6f}")
        if r.location_kind == "sample":
            print(f"    最佳采样点: {r.best_location}")
        else:
            left = r.best_location // 1_000_000
            right = r.best_location % 1_000_000
            print(f"    最佳同窗二阶点对: ({left}, {right})")
        print("    bit_peaks:", ", ".join([f"b{i}={v:.6f}" for i, v in enumerate(r.bit_peaks)]))
        mean10_text = ", ".join([f"0x{k:02X}:{s:.6f}" for k, s in r.mean_top10])
        max10_text = ", ".join([f"0x{k:02X}:{s:.6f}" for k, s in r.max_top10])
        print(f"    Mean Top10: {mean10_text}")
        print(f"    Max  Top10: {max10_text}")
        print(f"    Max-best key: 0x{r.max_key:02X}, score={r.max_corr:.6f}")

    print_hit_report(window_key, results)

    master_key_hex, note = derive_master_key_if_possible(window_key, results)
    print()
    print(f"[+] 主密钥推导: {note}")
    if master_key_hex is not None:
        print(f"[+] 主密钥候选: {master_key_hex}")


def build_hit_report(window_key: str, results: list[ByteAttackResult]) -> dict[str, Any]:
    expected = EXPECTED_WINDOW_KEYS.get(window_key)
    if expected is None:
        return {"available": False}

    ordered = sorted(results, key=lambda x: x.byte_index)
    per_byte: list[dict[str, Any]] = []
    mean_hits = 0
    max_hits = 0
    for r in ordered:
        exp = int(expected[r.byte_index])
        mean_hit = any(k == exp for k, _ in r.mean_top10)
        max_hit = any(k == exp for k, _ in r.max_top10)
        mean_hits += int(mean_hit)
        max_hits += int(max_hit)
        per_byte.append({
            "byte_index": r.byte_index,
            "expected_key": f"0x{exp:02X}",
            "mean_hit": mean_hit,
            "max_hit": max_hit,
            "mean_ranked_keys": [f"0x{k:02X}" for k, _ in r.mean_top10],
            "max_ranked_keys": [f"0x{k:02X}" for k, _ in r.max_top10],
        })

    return {
        "available": True,
        "expected_key_hex": expected.hex(),
        "mean_hit_count": mean_hits,
        "max_hit_count": max_hits,
        "total_bytes": len(ordered),
        "per_byte": per_byte,
    }


def print_hit_report(window_key: str, results: list[ByteAttackResult]) -> None:
    report = build_hit_report(window_key, results)
    if not report.get("available"):
        return

    print()
    print("[+] 命中报告")
    print(f"    目标轮密钥: {report['expected_key_hex']}")
    print(f"    Mean Top10 命中: {report['mean_hit_count']}/{report['total_bytes']}")
    print(f"    Max  Top10命中: {report['max_hit_count']}/{report['total_bytes']}")
    for item in report["per_byte"]:
        print(
            f"    Byte {item['byte_index']:02d} | exp={item['expected_key']} | "
            f"Mean={'Y' if item['mean_hit'] else 'N'} | Max={'Y' if item['max_hit'] else 'N'}"
        )


def save_window_results(
    result_dir: Path,
    run_tag: str,
    window_key: str,
    results: list[ByteAttackResult],
    step: int,
    workers: int,
    mode: str,
    top_k: int | None,
) -> tuple[Path, Path]:
    window_name = WINDOWS[window_key]["name"]
    csv_path = result_dir / f"{run_tag}_{window_name}_{mode}.csv"
    json_path = result_dir / f"{run_tag}_{window_name}_{mode}.json"

    ordered = sorted(results, key=lambda x: x.byte_index)
    master_key_hex, note = derive_master_key_if_possible(window_key, ordered)

    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["byte_index", "best_key_hex", "best_corr", "max_key_hex", "max_corr", "best_location", "bit_peaks", "mean_top10", "max_top10"])
        for r in ordered:
            loc_text = (
                str(r.best_location)
                if r.location_kind == "sample"
                else f"{r.best_location // 1_000_000}:{r.best_location % 1_000_000}"
            )
            writer.writerow([
                r.byte_index,
                f"0x{r.best_key:02X}",
                f"{r.best_corr:.10f}",
                f"0x{r.max_key:02X}",
                f"{r.max_corr:.10f}",
                loc_text,
                " | ".join([f"b{i}={v:.6f}" for i, v in enumerate(r.bit_peaks)]),
                " | ".join([f"0x{k:02X}:{s:.6f}" for k, s in r.mean_top10]),
                " | ".join([f"0x{k:02X}:{s:.6f}" for k, s in r.max_top10]),
            ])

    payload = {
        "run_tag": run_tag,
        "window_key": window_key,
        "window_label": WINDOWS[window_key]["label"],
        "window_desc": WINDOWS[window_key]["desc"],
        "mode": mode,
        "step": step,
        "workers": workers,
        "top_k": top_k,
        "round_key_type": WINDOWS[window_key]["round_key_type"],
        "master_key_note": note,
        "master_key_hex": master_key_hex,
        "hit_report": build_hit_report(window_key, ordered),
        "results": [asdict(r) for r in ordered],
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return csv_path, json_path


def attack_window_parallel(
    window_key: str,
    model_variant: str,
    cache_path: Path,
    points: np.ndarray,
    ciphertexts: np.ndarray,
    plaintexts: np.ndarray,
    byte_indices: list[int],
    mode: str,
    workers: int,
    block_size: int,
    top_k: int | None,
) -> list[ByteAttackResult]:
    task_common = {
        "trace_cache": str(cache_path),
        "points": points.tolist(),
        "ciphertexts": ciphertexts,
        "plaintexts": plaintexts,
        "window_key": window_key,
        "model_variant": model_variant,
        "window_name": WINDOWS[window_key]["name"],
        "window_label": WINDOWS[window_key]["label"],
    }

    futures = []
    results: list[ByteAttackResult] = []

    worker_fn = first_order_worker if mode == "first" else second_order_worker

    with ProcessPoolExecutor(max_workers=workers) as ex:
        for byte_index in byte_indices:
            task = dict(task_common)
            task["byte_index"] = byte_index
            if mode == "first":
                task["block_size"] = block_size
            else:
                task["top_k"] = int(top_k if top_k is not None else 24)
            futures.append(ex.submit(worker_fn, task))

        for fut in as_completed(futures):
            results.append(fut.result())

    return sorted(results, key=lambda x: x.byte_index)


def choose_byte_indices() -> list[int]:
    byte_mode = prompt_choice("分析字节：s=单字节, a=全部16字节", {"s", "a"}, default="s")
    if byte_mode == "s":
        return [prompt_int("输入目标字节编号", 0, 0, 15)]
    return list(range(16))


def choose_windows() -> list[str]:
    print("选择兴趣区间：")
    print("  1 -> 区间1: 800..3000，默认对应第10轮轮密钥")
    print("  2 -> 区间2: 24000..trace末尾，默认对应第0轮轮密钥")
    print("  a -> 两个区间分别独立跑两次 CPA")
    win = prompt_choice("你的选择", {"1", "2", "a"}, default="a")
    if win == "a":
        return ["1", "2"]
    return [win]


def main() -> None:
    run_paths = resolve_run_paths()
    ensure_dirs(run_paths)

    print("=" * 56)
    print("AES 解密 CPA 工具 V2")
    print("=" * 56)
    print("[*] 这个版本会把两个兴趣区间完全分开分析")
    print("[*] 区间1 模型: bit(InvSBox(C ^ K10))，ROI=800..3000")
    print("[*] 区间2 会自动跑两种模型: bit(SBox(P ^ K0)) 与 bit(P ^ K0)，ROI=24000..trace末尾")
    print("[*] 每个 key 对 bit0..bit7 分别做 CPA，再按 8 个 bit 峰值均值的 Top10 排名输出")
    print()
    print(f"[*] 数据根目录: {run_paths.base_dir}")
    print(f"[*] trace 目录: {run_paths.trace_dir}")
    print(f"[*] IO 文件: {run_paths.io_path}")
    print(f"[*] 缓存目录: {run_paths.cache_dir}")
    print(f"[*] 结果目录: {run_paths.result_dir}")
    print()

    order_choice = prompt_choice("选择分析阶数：1=一阶 CPA, 2=二阶 CPA", {"1", "2"}, default="1")
    mode = "first" if order_choice == "1" else "second"

    window_keys = choose_windows()
    byte_indices = choose_byte_indices()
    step = prompt_int("ROI 采样步长（>1 可加速）", 1, 1)
    workers = prompt_int("并行进程数", max(1, (os.cpu_count() or 2) // 2), 1)
    block_size = 512
    top_k = None

    if mode == "first":
        block_size = prompt_int("一阶相关分块大小", 512, 32)
    else:
        top_k = prompt_int("二阶每个窗口保留的候选点数", 24, 2)

    print()
    print("[+] 读取输入输出对...")
    indices, ciphertexts, plaintexts = load_io_pairs(run_paths.io_path)
    trace_files = discover_trace_files(run_paths.trace_dir)

    n = min(len(indices), len(trace_files))
    if n == 0:
        raise ValueError("没有可用数据")
    if len(indices) != len(trace_files):
        print(f"[!] 警告: io_pairs={len(indices)} 条, traces={len(trace_files)} 条，仅使用前 {n} 条")

    ciphertexts = ciphertexts[:n]
    plaintexts = plaintexts[:n]
    trace_files = trace_files[:n]

    print(f"[+] 使用迹线数: {n}")
    total_samples = get_total_samples(trace_files[0])
    print(f"[+] 单条迹线长度: {total_samples}")

    run_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
    all_master_candidates: dict[str, str] = {}

    for window_key in window_keys:
        print()
        print(f"[+] 准备 {WINDOWS[window_key]['label']} ...")
        cache_path, points = load_or_build_window_cache(trace_files, run_paths.cache_dir, window_key, total_samples, step)
        print(f"[+] {WINDOWS[window_key]['label']} 点数: {points.size}")

        model_variants = ["sbox_input"] if window_key == "1" else ["sbox_input", "ark_output"]
        for model_variant in model_variants:
            print(f"[+] 启动并行攻击: workers={workers}, mode={mode}, model={MODEL_VARIANTS[model_variant]}")
            results = attack_window_parallel(
                window_key=window_key,
                model_variant=model_variant,
                cache_path=cache_path,
                points=points,
                ciphertexts=ciphertexts,
                plaintexts=plaintexts,
                byte_indices=byte_indices,
                mode=mode,
                workers=workers,
                block_size=block_size,
                top_k=top_k,
            )

            print(f"[+] 当前模型: {MODEL_VARIANTS[model_variant]}")
            print_window_results(window_key, results)
            csv_path, json_path = save_window_results(
                result_dir=run_paths.result_dir,
                run_tag=f"{run_tag}_{model_variant}",
                window_key=window_key,
                results=results,
                step=step,
                workers=workers,
                mode=mode,
                top_k=top_k,
            )
            print(f"[+] CSV 已保存: {csv_path}")
            print(f"[+] JSON 已保存: {json_path}")

            master_key_hex, note = derive_master_key_if_possible(window_key, results)
            if master_key_hex is not None:
                all_master_candidates[f"{window_key}:{model_variant}"] = master_key_hex
                print(f"[+] {WINDOWS[window_key]['label']} 主密钥候选: {master_key_hex}")
            else:
                print(f"[+] {WINDOWS[window_key]['label']} 主密钥状态: {note}")

    if len(all_master_candidates) == 2:
        mk1 = all_master_candidates.get("1")
        mk2 = all_master_candidates.get("2")
        print()
        print("=" * 56)
        print("跨区间主密钥一致性检查")
        print("=" * 56)
        print(f"区间1 反推主密钥: {mk1}")
        print(f"区间2 直接主密钥: {mk2}")
        if mk1 == mk2:
            print("[+] 两个区间给出的主密钥一致")
        else:
            print("[!] 两个区间给出的主密钥不一致，请检查 ROI、点选择或泄漏模型")

    print()
    print("[+] 全部完成")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n用户中断")
        sys.exit(130)
    except Exception as exc:
        print(f"\n[ERROR] {exc}")
        sys.exit(1)