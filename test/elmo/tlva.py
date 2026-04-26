#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np


DEFAULT_OUT_BASENAME = "tvla_10k"
DEFAULT_NUM_TRACES = 10000
DEFAULT_THRESHOLD = 4.5
DEFAULT_REPORT_EVERY = 500


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="从控制台输入 random/fix 两组 trace 目录，计算均值层面和方差层面的 TVLA。"
    )
    p.add_argument("--num-traces", type=int, default=DEFAULT_NUM_TRACES, help="每组读取多少条 trace，默认 10000")
    p.add_argument("--offset", type=int, default=0, help="从排序后的第几条开始取，默认 0")
    p.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD, help="TVLA 阈值，默认 4.5")
    p.add_argument(
        "--report-every",
        type=int,
        default=DEFAULT_REPORT_EVERY,
        help="每处理多少条打印一次进度，默认 500",
    )
    return p.parse_args()


def prompt_trace_dir(prompt: str) -> Path:
    raw = input(prompt).strip()
    if not raw:
        raise ValueError("trace 目录不能为空")
    trace_dir = Path(raw).expanduser().resolve()
    if not trace_dir.is_dir():
        raise NotADirectoryError(f"目录不存在: {trace_dir}")
    return trace_dir


def list_trace_files(trace_dir: Path) -> list[Path]:
    files = sorted(trace_dir.glob("trace*.trc"))
    if not files:
        raise FileNotFoundError(f"目录下没有找到 trace*.trc: {trace_dir}")
    return files


def select_trace_files(trace_dir: Path, num_traces: int, offset: int) -> list[Path]:
    files = list_trace_files(trace_dir)
    selected = files[offset : offset + num_traces]
    if len(selected) < num_traces:
        raise ValueError(
            f"{trace_dir} 可用 trace 不足：需要 {num_traces} 条，"
            f"offset={offset} 后只剩 {len(selected)} 条。"
        )
    return selected


def read_trace_file(path: Path) -> np.ndarray:
    data = np.loadtxt(path, dtype=np.float64, ndmin=1)
    if data.ndim != 1:
        raise ValueError(f"trace 文件不是一维浮点序列: {path}")
    return data


@dataclass
class GroupStats:
    name: str
    n: int
    mean: np.ndarray
    M2: np.ndarray
    M3: np.ndarray
    M4: np.ndarray

    @property
    def sample_var(self) -> np.ndarray:
        if self.n < 2:
            raise ValueError("样本数不足，无法计算 sample variance")
        return self.M2 / (self.n - 1)

    @property
    def centered_sq_mean(self) -> np.ndarray:
        # y_i = (x_i - mean)^2 的样本均值
        return self.M2 / self.n

    @property
    def centered_sq_sample_var(self) -> np.ndarray:
        # y_i = (x_i - mean)^2 的样本方差
        if self.n < 2:
            raise ValueError("样本数不足，无法计算方差层面的 sample variance")
        return (self.M4 - (self.M2 ** 2) / self.n) / (self.n - 1)


def init_stats(name: str, first_trace: np.ndarray) -> GroupStats:
    dim = first_trace.shape[0]
    return GroupStats(
        name=name,
        n=0,
        mean=np.zeros(dim, dtype=np.float64),
        M2=np.zeros(dim, dtype=np.float64),
        M3=np.zeros(dim, dtype=np.float64),
        M4=np.zeros(dim, dtype=np.float64),
    )


def update_stats(stats: GroupStats, x: np.ndarray) -> None:
    n1 = stats.n
    stats.n += 1
    n = stats.n

    delta = x - stats.mean
    delta_n = delta / n
    delta_n2 = delta_n * delta_n
    term1 = delta * delta_n * n1

    stats.M4 += (
        term1 * delta_n2 * (n * n - 3 * n + 3)
        + 6 * delta_n2 * stats.M2
        - 4 * delta_n * stats.M3
    )
    stats.M3 += term1 * delta_n * (n - 2) - 3 * delta_n * stats.M2
    stats.M2 += term1
    stats.mean += delta_n


def build_group_stats(files: list[Path], name: str, report_every: int) -> GroupStats:
    first = read_trace_file(files[0])
    stats = init_stats(name, first)

    for idx, path in enumerate(files, start=1):
        x = read_trace_file(path)
        if x.shape != first.shape:
            raise ValueError(
                f"{name} 组 trace 长度不一致: {path} 长度={x.shape[0]}, "
                f"首条长度={first.shape[0]}"
            )
        update_stats(stats, x)

        if idx == 1 or idx % report_every == 0 or idx == len(files):
            print(f"[{name}] {idx}/{len(files)}")

    return stats


def welch_t(mean_a: np.ndarray, mean_b: np.ndarray,
            var_a: np.ndarray, var_b: np.ndarray,
            n_a: int, n_b: int) -> np.ndarray:
    denom = np.sqrt(var_a / n_a + var_b / n_b)
    diff = mean_a - mean_b

    t = np.zeros_like(diff, dtype=np.float64)
    mask = denom > 0
    t[mask] = diff[mask] / denom[mask]

    zero_mask = ~mask
    if np.any(zero_mask):
        t[zero_mask] = 0.0
        inf_mask = zero_mask & (diff != 0)
        t[inf_mask] = np.sign(diff[inf_mask]) * np.inf

    return t


def summarize_t(t: np.ndarray, threshold: float) -> dict:
    abs_t = np.abs(t)
    exceed = np.flatnonzero(abs_t > threshold)
    return {
        "max_abs_t": float(np.nanmax(abs_t)),
        "argmax": int(np.nanargmax(abs_t)),
        "exceed_count": int(exceed.size),
        "first_20_exceed_indexes": exceed[:20].tolist(),
    }


def main() -> None:
    args = parse_args()

    random_dir = prompt_trace_dir("请输入 random trace 目录: ")
    fixed_dir = prompt_trace_dir("请输入 fixed trace 目录: ")
    out_prefix = random_dir / DEFAULT_OUT_BASENAME

    if args.num_traces <= 1:
        raise ValueError("num-traces 必须大于 1")
    if args.offset < 0:
        raise ValueError("offset 不能为负数")

    random_files = select_trace_files(random_dir, args.num_traces, args.offset)
    fixed_files = select_trace_files(fixed_dir, args.num_traces, args.offset)

    print("[info] 开始读取 random 组")
    random_stats = build_group_stats(random_files, "random", args.report_every)

    print("[info] 开始读取 fix 组")
    fixed_stats = build_group_stats(fixed_files, "fix", args.report_every)

    if random_stats.mean.shape != fixed_stats.mean.shape:
        raise ValueError(
            f"两组 trace 长度不一致: random={random_stats.mean.shape[0]}, "
            f"fix={fixed_stats.mean.shape[0]}"
        )

    t_mean = welch_t(
        random_stats.mean,
        fixed_stats.mean,
        random_stats.sample_var,
        fixed_stats.sample_var,
        random_stats.n,
        fixed_stats.n,
    )

    t_var = welch_t(
        random_stats.centered_sq_mean,
        fixed_stats.centered_sq_mean,
        random_stats.centered_sq_sample_var,
        fixed_stats.centered_sq_sample_var,
        random_stats.n,
        fixed_stats.n,
    )

    summary = {
        "random_dir": str(random_dir),
        "fixed_dir": str(fixed_dir),
        "num_traces_per_group": args.num_traces,
        "offset": args.offset,
        "trace_length": int(random_stats.mean.shape[0]),
        "threshold": args.threshold,
        "output_prefix": str(out_prefix),
        "mean_level": summarize_t(t_mean, args.threshold),
        "variance_level": summarize_t(t_var, args.threshold),
    }

    out_prefix.parent.mkdir(parents=True, exist_ok=True)

    np.savez_compressed(
        str(out_prefix) + ".npz",
        t_mean=t_mean,
        t_var=t_var,
        random_mean=random_stats.mean,
        fixed_mean=fixed_stats.mean,
        random_var=random_stats.sample_var,
        fixed_var=fixed_stats.sample_var,
        random_centered_sq_mean=random_stats.centered_sq_mean,
        fixed_centered_sq_mean=fixed_stats.centered_sq_mean,
        random_centered_sq_var=random_stats.centered_sq_sample_var,
        fixed_centered_sq_var=fixed_stats.centered_sq_sample_var,
    )

    with open(str(out_prefix) + ".json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print("\n[OK] TVLA 计算完成")
    print(f"  - random 目录: {random_dir}")
    print(f"  - fixed 目录: {fixed_dir}")
    print(f"  - 输出: {out_prefix}.npz")
    print(f"  - 输出: {out_prefix}.json")
    print(f"  - trace_length: {summary['trace_length']}")
    print(f"  - mean-level   max|t| = {summary['mean_level']['max_abs_t']:.6f}")
    print(f"  - variance-level max|t| = {summary['variance_level']['max_abs_t']:.6f}")
    print(f"  - mean-level exceed count (> {args.threshold}) = {summary['mean_level']['exceed_count']}")
    print(f"  - variance-level exceed count (> {args.threshold}) = {summary['variance_level']['exceed_count']}")


if __name__ == "__main__":
    main() 