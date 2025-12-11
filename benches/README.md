# Benchmarks: strict-path Performance Analysis

This directory contains **two complementary benchmark suites** that measure different aspects of strict-path's performance.

## 📚 Documentation

For detailed analysis and overhead tables:
- **[docs/OVERHEAD_QUICK_REFERENCE.md](docs/OVERHEAD_QUICK_REFERENCE.md)** — Quick-reference tables with all overhead numbers
- **[docs/PERFORMANCE_OVERHEAD_ANALYSIS.md](docs/PERFORMANCE_OVERHEAD_ANALYSIS.md)** — Comprehensive analysis (500+ lines, 6 detailed tables)
- **[docs/CACHING_BENEFITS_REPORT.md](docs/CACHING_BENEFITS_REPORT.md)** — Real-world batch performance analysis
- **[docs/BENCHMARK_ANALYSIS.md](docs/BENCHMARK_ANALYSIS.md)** — Initial benchmark analysis (historical)

---

## 📊 Benchmark Suites

### 1. `performance_comparison.rs` — **Security Overhead**

**Purpose:** Measures the **cost** of security validation vs raw canonicalization.

**Question Answered:** *"How much overhead does the security layer add?"*

**Methodology:**
- Fair comparison: all approaches receive identical inputs (relative path segments)
- Measures: untrusted string → validated path (full workflow)
- Includes both validation + I/O operations

**Benchmarks:**
- `soft_canonicalize` — Baseline (join + canonicalize)
- `strict_path_from_boundary` — Security overhead (boundary check + escape detection)
- `strict_path_join` — Chaining from validated path
- `virtual_path_from_root` — Virtual overhead (anchored canonicalization + clamping)
- `virtual_path_join` — Virtual chaining
- `io_operations` — End-to-end validation + filesystem operations
- `comparison_summary` — Side-by-side comparison
- `repeated_operations` — 100x operations showing caching benefits

**Expected Results:**
- **StrictPath:** +5-15% overhead (security validation cost)
- **VirtualPath:** +20-40% overhead (virtual isolation + clamping)
- **Repeated ops:** StrictPath 20-30% FASTER (boundary caching kicks in)

**Run:**
```powershell
cargo bench --bench performance_comparison
```

---

### 2. `caching_benefits.rs` — **Real-World Performance Gains**

**Purpose:** Demonstrates how StrictPath/VirtualPath are **faster** than manual validation in realistic workloads.

**Question Answered:** *"Should I use StrictPath or keep manually calling soft-canonicalize?"*

**Methodology:**
- Simulates real scenarios: web servers, archive extraction, directory scanning
- Compares manual pattern (repeated soft-canonicalize) vs cached pattern (PathBoundary reuse)
- Batch sizes: 10, 100, 1000 files
- Multi-user and I/O-heavy workloads

**Benchmarks:**
- `small_batch_10_files` — Typical single-request workload
- `medium_batch_100_files` — Archive extraction scenario
- `large_batch_1000_files` — Large archive (npm packages, system images)
- `directory_scanning` — read_dir + validate each entry
- `multi_user_10x10` — Multi-tenant system (10 users, 10 files each)
- `io_heavy_exists_metadata` — Validation + I/O operations combined

**Expected Results:**
- **10 files:** StrictPath 15-25% faster
- **100 files:** StrictPath 25-35% faster
- **1000 files:** StrictPath 30-40% faster
- **Directory scanning:** 20-30% faster
- **Multi-user:** 25-35% faster

**Run:**
```powershell
cargo bench --bench caching_benefits
```

---

## 🎯 Key Insight: Two Different Metrics

### Overhead vs. Amortized Cost

| Metric             | Benchmark                   | What It Measures             | Typical Result           |
| ------------------ | --------------------------- | ---------------------------- | ------------------------ |
| **Overhead**       | `performance_comparison.rs` | Cost for ONE path validation | StrictPath +5-15% slower |
| **Amortized Cost** | `caching_benefits.rs`       | Cost for MANY paths (batch)  | StrictPath 20-40% FASTER |

**Why the difference?**

- **Overhead benchmark:** Measures the raw cost of security validation (boundary check, escape detection)
- **Caching benchmark:** Measures real-world usage where boundary is validated once and reused

**Real-world applications almost never validate just ONE path.** They validate many paths under the same boundary:
- Web servers: 100s-1000s of uploads to `/var/uploads/`
- Archive extraction: 500-5000 files to `/tmp/extract/`
- Directory scanning: 10-100s of entries in `/home/user/Documents/`

The caching benefits dominate the overhead cost in these scenarios.

---

## 🚀 Running Benchmarks

### Run all benchmarks
```powershell
# From repository root
cd benches
cargo bench

# Runs both performance_comparison and caching_benefits
```

### Run specific suite
```powershell
# Overhead measurements only
cargo bench --bench performance_comparison

# Caching benefits only
cargo bench --bench caching_benefits
```

### Save baseline for regression testing
```powershell
# Save current results as baseline
cargo bench -- --save-baseline main

# After making changes, compare against baseline
cargo bench -- --baseline main
```

### Generate HTML reports
```powershell
# Criterion automatically generates reports in:
# target/criterion/*/report/index.html
#
# Open in browser to see detailed charts and statistics
```

---

## 📈 Understanding Results

### Criterion Output Format

```
small_batch_10_files/manual_soft_canonicalize
                        time:   [848.32 µs 851.12 µs 854.08 µs]
                        thrpt:  [11.71K elem/s 11.75K elem/s 11.79K elem/s]

small_batch_10_files/strict_path_cached
                        time:   [679.45 µs 682.31 µs 685.42 µs]
                        thrpt:  [14.59K elem/s 14.66K elem/s 14.72K elem/s]
                        change: [-20.12% -19.82% -19.51%] (p = 0.00 < 0.05)
                        Performance has improved.
```

**Reading this:**
- **time:** Median time with 95% confidence interval
- **thrpt:** Throughput (operations per second)
- **change:** Percent difference vs previous run (or baseline)
- **Performance has improved:** StrictPath is 19.82% faster!

### Key Metrics to Watch

1. **Median time:** Primary metric (middle value after sorting samples)
2. **Confidence interval:** Narrower = more consistent results
3. **Throughput:** Operations per second (higher = better)
4. **Change %:** Regression detection (negative = faster, positive = slower)

---

## ⚠️ Platform Considerations

### Windows-Specific

- **8.3 short names:** Benchmarks handle both `Program Files` and `PROGRA~1` forms
- **UNC paths:** Network paths (`\\server\share\`) may show larger caching benefits
- **Junctions:** Windows directory junctions are handled identically to symlinks

### Cross-Platform Expectations

- **Linux/macOS:** Caching benefits may be slightly lower (5-15%) due to simpler path semantics
- **WSL:** Hybrid behavior (Windows-like on `/mnt/c/`, Unix-like on native paths)
- **Network filesystems:** Larger caching benefits (40-60%) due to remote canonicalization cost

---

## 🔍 Interpreting Results

### Expected Patterns

**performance_comparison.rs:**
- `soft_canonicalize` (baseline): Fastest for single operations
- `strict_path_from_boundary`: Slightly slower (+5-15%) due to boundary validation
- `virtual_path_from_root`: Slower (+20-40%) due to virtual coordinate computation
- `repeated_operations`: StrictPath becomes FASTER due to caching

**caching_benefits.rs:**
- `manual_soft_canonicalize`: Slowest (redundant boundary validation)
- `strict_path_cached`: Fastest (boundary validated once, reused)
- `virtual_path_cached`: Slightly slower than StrictPath (clamping overhead)
- **Gap increases with batch size** (more files = more redundant work avoided)

### Red Flags

⚠️ **Investigate if you see:**
- StrictPath slower than 25% vs baseline in caching_benefits
- VirtualPath slower than 50% vs baseline in performance_comparison
- Variance >10% between runs (unstable benchmarks)
- Throughput decreasing after code changes (regression)

---

## 📚 Related Documentation

- **[CACHING_BENEFITS_REPORT.md](docs/CACHING_BENEFITS_REPORT.md)** — Detailed analysis of real-world performance gains
- **[PERFORMANCE_OVERHEAD_ANALYSIS.md](docs/PERFORMANCE_OVERHEAD_ANALYSIS.md)** — Comprehensive overhead analysis with 6 detailed tables
- **[OVERHEAD_QUICK_REFERENCE.md](docs/OVERHEAD_QUICK_REFERENCE.md)** — Quick-reference tables for all overhead numbers
- **[BENCHMARK_ANALYSIS.md](docs/BENCHMARK_ANALYSIS.md)** — Initial benchmark analysis (historical)
- **[LLM_CONTEXT_FULL.md](../LLM_CONTEXT_FULL.md)** — API design decisions affecting performance

---

## 🎓 Best Practices

### For Contributors

1. **Always run benchmarks before/after changes** that touch `PathHistory`, `PathBoundary`, or `VirtualRoot`
2. **Save baseline before refactoring:** `cargo bench -- --save-baseline before-refactor`
3. **Check variance:** If >10%, investigate (noisy system, background processes)
4. **Run on same machine:** Cross-machine comparisons are unreliable
5. **Warm up system:** First run after reboot may be slower

### For Users

1. **Run both suites** to understand overhead AND real-world benefits
2. **Focus on your workload:** If you validate 1000s of paths, caching_benefits matters most
3. **Consider I/O cost:** Validation is often <10% of total time (disk I/O dominates)
4. **Profile your app:** Benchmarks show potential; measure your actual usage

---

## 🔧 Troubleshooting

### Benchmarks fail to compile

```powershell
# Ensure virtual-path feature is enabled
cargo bench --features virtual-path

# Check for missing dependencies
cargo clean
cargo bench --features virtual-path
```

### Unstable results (high variance)

- Close background applications (browsers, IDEs, builds)
- Disable power-saving mode (CPU throttling)
- Run multiple times: `for ($i=0; $i -lt 5; $i++) { cargo bench --features virtual-path }`
- Check for thermal throttling (CPU temperature)

### Benchmarks timeout

- Criterion default: 5 seconds measurement, 10 seconds warmup
- Large batches may need longer: increase sample count in code
- Or filter to specific benchmarks: `cargo bench --features virtual-path -- small_batch`

---

## 📝 Adding New Benchmarks

### When to add benchmarks

- New API surface (e.g., new join method, conversion helper)
- Performance-sensitive path (e.g., escape detection logic)
- Platform-specific behavior (e.g., Windows junctions, Unix symlinks)
- Regression fix (add benchmark that would have caught the regression)

### Benchmark design principles

1. **Use black_box:** Prevent compiler from optimizing away work
2. **Measure equivalent operations:** All approaches do the same work
3. **Include setup cost fairly:** If baseline creates temp dir, so should StrictPath
4. **Use realistic inputs:** Paths users actually encounter (not just "a/b/c")
5. **Document expected results:** Future maintainers need context

### Template

```rust
fn bench_my_feature(c: &mut Criterion) {
    let fixture = create_fixture();
    
    let mut group = c.benchmark_group("my_feature");
    group.throughput(Throughput::Elements(fixture.items().len() as u64));
    
    group.bench_function("baseline", |b| {
        b.iter(|| {
            for item in fixture.items() {
                let result = baseline_approach(black_box(item));
                black_box(result);
            }
        });
    });
    
    group.bench_function("strict_path", |b| {
        b.iter(|| {
            for item in fixture.items() {
                let result = strict_path_approach(black_box(item));
                black_box(result);
            }
        });
    });
    
    group.finish();
}
```

---

## 🏆 Benchmark Goals

### Performance Targets

- **Overhead:** StrictPath <20% slower than baseline for single operations
- **Caching:** StrictPath >20% faster than manual for batch operations (100+ files)
- **Memory:** Zero allocation overhead (Marker is zero-sized)
- **Scalability:** O(n) with path depth (no worse than baseline)

### Quality Targets

- **Variance:** <5% between runs on same machine
- **Coverage:** >80% of API surface has benchmarks
- **Documentation:** Every benchmark has clear purpose and expected results
- **Regression detection:** PRs that worsen performance >10% are flagged

---

**Questions?** Open an issue or see [CONTRIBUTING.md](../../CONTRIBUTING.md) for how to contribute benchmarks!
