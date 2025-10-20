//! Performance Comparison: soft-canonicalize vs. StrictPath vs. VirtualPath
//!
//! This benchmark properly measures the OVERHEAD of security validation by ensuring
//! all three approaches start from the same inputs (relative path segments) and
//! perform equivalent work (resolve to canonicalized paths within a boundary).
//!
//! Key principle: Measure the cost to go from "untrusted string" → "validated path"
//! for each approach on equal footing.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use soft_canonicalize::soft_canonicalize;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::{fs, io};
use strict_path::{PathBoundary, StrictPath, VirtualPath, VirtualRoot};
use tempfile::TempDir;

/// Test structure representing realistic mixed workload
struct TestStructure {
    _temp_dir: TempDir,
    base_path: PathBuf,
    /// Relative path segments (the untrusted input all approaches must validate)
    relative_segments: Vec<String>,
}

impl TestStructure {
    fn new() -> io::Result<Self> {
        let temp_dir = TempDir::new()?;
        let base_path = temp_dir.path().to_path_buf();

        // Create directory structure matching real-world usage
        fs::create_dir_all(base_path.join("existing/nested/deep"))?;
        fs::create_dir_all(base_path.join("symlinks"))?;
        fs::create_dir_all(base_path.join("config"))?;
        fs::create_dir_all(base_path.join("data"))?;

        // Create test files
        fs::write(base_path.join("existing/file1.txt"), "test")?;
        fs::write(base_path.join("existing/nested/file2.txt"), "test")?;
        fs::write(base_path.join("config/app.json"), "{}")?;
        fs::write(base_path.join("data/records.db"), "data")?;

        // CRITICAL: All benchmarks receive the SAME relative segments
        // This ensures we measure overhead, not different workloads
        let relative_segments = vec![
            "existing/file1.txt".to_string(),
            "existing/nested/file2.txt".to_string(),
            "nonexistent/file.txt".to_string(),
            "existing/../existing/file1.txt".to_string(),
            "existing/./nested/../file1.txt".to_string(),
            "symlinks/../existing/nested/deep/../../file1.txt".to_string(),
            "very/deeply/nested/nonexistent/path/file.txt".to_string(),
            "existing/nested/../../existing/nested/file2.txt".to_string(),
            "config/../config/app.json".to_string(),
            "data/./records.db".to_string(),
        ];

        Ok(Self {
            _temp_dir: temp_dir,
            base_path,
            relative_segments,
        })
    }

    fn base_path(&self) -> &Path {
        &self.base_path
    }

    fn relative_segments(&self) -> &[String] {
        &self.relative_segments
    }
}

// Marker type for benchmarks
struct BenchRoot;

/// Benchmark soft-canonicalize baseline
///
/// Measures: base.join(segment) -> soft_canonicalize() -> Result<PathBuf>
/// This is the "raw" cost without any security validation.
fn bench_soft_canonicalize(c: &mut Criterion) {
    let structure = TestStructure::new().expect("Failed to create test structure");
    let base = structure.base_path();

    let mut group = c.benchmark_group("soft_canonicalize");
    group.throughput(Throughput::Elements(
        structure.relative_segments().len() as u64
    ));

    group.bench_function("mixed_workload", |b| {
        b.iter(|| {
            for segment in structure.relative_segments() {
                // Equivalent to what a user would do: join base + segment, then canonicalize
                let full_path = base.join(black_box(segment));
                let _ = black_box(soft_canonicalize(black_box(&full_path)));
            }
        });
    });

    group.finish();
}

/// Benchmark PathBoundary::strict_join (StrictPath creation from boundary)
///
/// Measures: boundary.strict_join(segment) -> Result<StrictPath>
/// This includes boundary check + escape detection.
fn bench_strict_path_from_boundary(c: &mut Criterion) {
    let structure = TestStructure::new().expect("Failed to create test structure");
    let boundary: PathBoundary<BenchRoot> =
        PathBoundary::try_new(structure.base_path()).expect("Failed to create boundary");

    let mut group = c.benchmark_group("strict_path_from_boundary");
    group.throughput(Throughput::Elements(
        structure.relative_segments().len() as u64
    ));

    group.bench_function("mixed_workload", |b| {
        b.iter(|| {
            for segment in structure.relative_segments() {
                // StrictPath validation from boundary
                let _ = black_box(boundary.strict_join(black_box(segment)));
            }
        });
    });

    group.finish();
}

/// Benchmark StrictPath::strict_join (subsequent joins from existing StrictPath)
///
/// Measures: strict_path.strict_join(segment) -> Result<StrictPath>
/// This shows the cost of joining from an already-validated path.
fn bench_strict_path_join(c: &mut Criterion) {
    let structure = TestStructure::new().expect("Failed to create test structure");
    let boundary: PathBoundary<BenchRoot> =
        PathBoundary::try_new(structure.base_path()).expect("Failed to create boundary");
    let root: StrictPath<BenchRoot> = boundary.into_strictpath().expect("Failed to get root");

    let mut group = c.benchmark_group("strict_path_join");
    group.throughput(Throughput::Elements(
        structure.relative_segments().len() as u64
    ));

    group.bench_function("mixed_workload", |b| {
        b.iter(|| {
            for segment in structure.relative_segments() {
                let _ = black_box(root.strict_join(black_box(segment)));
            }
        });
    });

    group.finish();
}

/// Benchmark VirtualRoot::virtual_join (VirtualPath creation from root)
///
/// Measures: vroot.virtual_join(segment) -> Result<VirtualPath>
/// This includes anchored canonicalization + clamping logic.
fn bench_virtual_path_from_root(c: &mut Criterion) {
    let structure = TestStructure::new().expect("Failed to create test structure");
    let vroot: VirtualRoot<BenchRoot> =
        VirtualRoot::try_new(structure.base_path()).expect("Failed to create virtual root");

    let mut group = c.benchmark_group("virtual_path_from_root");
    group.throughput(Throughput::Elements(
        structure.relative_segments().len() as u64
    ));

    group.bench_function("mixed_workload", |b| {
        b.iter(|| {
            for segment in structure.relative_segments() {
                let _ = black_box(vroot.virtual_join(black_box(segment)));
            }
        });
    });

    group.finish();
}

/// Benchmark VirtualPath::virtual_join (subsequent joins from existing VirtualPath)
///
/// Measures: vpath.virtual_join(segment) -> Result<VirtualPath>
/// This shows the cost of joining from an already-validated virtual path.
fn bench_virtual_path_join(c: &mut Criterion) {
    let structure = TestStructure::new().expect("Failed to create test structure");
    let vroot: VirtualRoot<BenchRoot> =
        VirtualRoot::try_new(structure.base_path()).expect("Failed to create virtual root");
    let root: VirtualPath<BenchRoot> = vroot.into_virtualpath().expect("Failed to get root vpath");

    let mut group = c.benchmark_group("virtual_path_join");
    group.throughput(Throughput::Elements(
        structure.relative_segments().len() as u64
    ));

    group.bench_function("mixed_workload", |b| {
        b.iter(|| {
            for segment in structure.relative_segments() {
                let _ = black_box(root.virtual_join(black_box(segment)));
            }
        });
    });

    group.finish();
}

/// Benchmark I/O operations: Apples-to-apples comparison
///
/// CRITICAL FIX: All approaches now perform the SAME work:
/// - Baseline: join + canonicalize + I/O operation
/// - StrictPath: strict_join + I/O operation
///
/// This measures the true end-to-end cost including validation.
fn bench_io_operations(c: &mut Criterion) {
    let structure = TestStructure::new().expect("Failed to create test structure");
    let base = structure.base_path();
    let boundary: PathBoundary<BenchRoot> =
        PathBoundary::try_new(base).expect("Failed to create boundary");

    let mut group = c.benchmark_group("io_operations");

    let test_segment = "existing/file1.txt";

    // Benchmark: exists() check (full workflow)
    group.bench_function("exists_soft_canonicalize", |b| {
        b.iter(|| {
            let full_path = base.join(black_box(test_segment));
            let canon = soft_canonicalize(black_box(&full_path)).unwrap();
            black_box(canon.exists())
        });
    });

    group.bench_function("exists_strict_path", |b| {
        b.iter(|| {
            let strict = boundary.strict_join(black_box(test_segment)).unwrap();
            black_box(strict.exists())
        });
    });

    // Benchmark: metadata() check (full workflow)
    group.bench_function("metadata_soft_canonicalize", |b| {
        b.iter(|| {
            let full_path = base.join(black_box(test_segment));
            let canon = soft_canonicalize(black_box(&full_path)).unwrap();
            let _ = black_box(fs::metadata(&canon));
        });
    });

    group.bench_function("metadata_strict_path", |b| {
        b.iter(|| {
            let strict = boundary.strict_join(black_box(test_segment)).unwrap();
            let _ = black_box(strict.metadata());
        });
    });

    group.finish();
}

/// Comparison benchmark showing all three approaches side-by-side
fn bench_comparison_summary(c: &mut Criterion) {
    let structure = TestStructure::new().expect("Failed to create test structure");

    let boundary: PathBoundary<BenchRoot> =
        PathBoundary::try_new(structure.base_path()).expect("Failed to create boundary");
    let vroot: VirtualRoot<BenchRoot> =
        VirtualRoot::try_new(structure.base_path()).expect("Failed to create virtual root");

    let segments = vec![
        "existing/file1.txt",
        "nonexistent/file.txt",
        "existing/../existing/file1.txt",
        "existing/./nested/../file1.txt",
    ];

    let mut group = c.benchmark_group("comparison_summary");
    group.throughput(Throughput::Elements(segments.len() as u64));

    group.bench_with_input(
        BenchmarkId::new("approach", "soft_canonicalize"),
        &segments,
        |b, segments| {
            b.iter(|| {
                for segment in segments {
                    let full_path = structure.base_path().join(segment);
                    let _ = black_box(soft_canonicalize(black_box(&full_path)));
                }
            });
        },
    );

    group.bench_with_input(
        BenchmarkId::new("approach", "strict_path"),
        &segments,
        |b, segments| {
            b.iter(|| {
                for segment in segments {
                    let _ = black_box(boundary.strict_join(black_box(segment)));
                }
            });
        },
    );

    group.bench_with_input(
        BenchmarkId::new("approach", "virtual_path"),
        &segments,
        |b, segments| {
            b.iter(|| {
                for segment in segments {
                    let _ = black_box(vroot.virtual_join(black_box(segment)));
                }
            });
        },
    );

    group.finish();
}

/// Benchmark: Repeated operations (caching benefits)
///
/// This benchmark measures what happens when you perform MANY operations
/// under the same boundary/root. It shows the amortized cost benefits.
///
/// Scenario: Web server processing 100 file requests under /var/uploads/
fn bench_repeated_operations(c: &mut Criterion) {
    let structure = TestStructure::new().expect("Failed to create test structure");
    let base = structure.base_path();
    let boundary: PathBoundary<BenchRoot> =
        PathBoundary::try_new(base).expect("Failed to create boundary");
    let vroot: VirtualRoot<BenchRoot> =
        VirtualRoot::try_new(base).expect("Failed to create virtual root");

    // Simulate 100 requests with the same segments repeated
    let request_count = 100;
    let segment = "existing/file1.txt";

    let mut group = c.benchmark_group("repeated_operations");
    group.throughput(Throughput::Elements(request_count));

    group.bench_function("soft_canonicalize_100x", |b| {
        b.iter(|| {
            for _ in 0..request_count {
                let full_path = base.join(black_box(segment));
                let _ = black_box(soft_canonicalize(black_box(&full_path)));
            }
        });
    });

    group.bench_function("strict_path_100x", |b| {
        b.iter(|| {
            for _ in 0..request_count {
                let _ = black_box(boundary.strict_join(black_box(segment)));
            }
        });
    });

    group.bench_function("virtual_path_100x", |b| {
        b.iter(|| {
            for _ in 0..request_count {
                let _ = black_box(vroot.virtual_join(black_box(segment)));
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_soft_canonicalize,
    bench_strict_path_from_boundary,
    bench_strict_path_join,
    bench_virtual_path_from_root,
    bench_virtual_path_join,
    bench_io_operations,
    bench_comparison_summary,
    bench_repeated_operations
);
criterion_main!(benches);
