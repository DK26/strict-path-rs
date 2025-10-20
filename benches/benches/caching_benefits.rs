//! Caching Benefits: StrictPath/VirtualPath vs. Manual soft-canonicalize
//!
//! This benchmark demonstrates the PERFORMANCE BENEFITS of using StrictPath/VirtualPath
//! over manually calling soft-canonicalize repeatedly.
//!
//! **Key Insight:** In real-world applications, you don't validate a path once—you validate
//! MANY paths under the same boundary (e.g., web server handling file uploads, archive
//! extraction, directory scanning).
//!
//! This benchmark shows:
//! 1. Manual approach: Call soft-canonicalize + boundary check for EVERY path
//! 2. StrictPath approach: Create boundary once, reuse for all subsequent paths
//! 3. VirtualPath approach: Create virtual root once, reuse with automatic clamping
//!
//! **Expected Result:** StrictPath/VirtualPath should be significantly FASTER than
//! the manual approach in realistic workloads due to boundary caching.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use soft_canonicalize::soft_canonicalize;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::{fs, io};
use strict_path::{PathBoundary, VirtualRoot};
use tempfile::TempDir;

// Marker type for benchmarks
struct BenchRoot;

/// Realistic workload: web server handling file uploads
struct WebServerWorkload {
    _temp_dir: TempDir,
    upload_root: PathBuf,
    incoming_files: Vec<String>,
}

impl WebServerWorkload {
    fn new(file_count: usize) -> io::Result<Self> {
        let temp_dir = TempDir::new()?;
        let upload_root = temp_dir.path().join("uploads");
        fs::create_dir_all(&upload_root)?;

        // Simulate incoming upload requests
        let incoming_files = (0..file_count)
            .map(|i| format!("user_{}/document_{}.pdf", i % 10, i))
            .collect();

        Ok(Self {
            _temp_dir: temp_dir,
            upload_root,
            incoming_files,
        })
    }

    fn upload_root(&self) -> &Path {
        &self.upload_root
    }

    fn incoming_files(&self) -> &[String] {
        &self.incoming_files
    }
}

/// Manual approach: Validate every path independently with soft-canonicalize
///
/// This is what developers might write WITHOUT using strict-path:
/// ```rust
/// for file in uploads {
///     let full_path = upload_root.join(file);
///     let canon = soft_canonicalize(&full_path)?;
///     
///     // Manual boundary check
///     if !canon.starts_with(&upload_root_canon) {
///         return Err("Path escape!");
///     }
///     
///     // Process file...
/// }
/// ```
fn manual_validation_pattern(upload_root: &Path, files: &[String]) {
    // Need to canonicalize the boundary too!
    let boundary_canon = soft_canonicalize(upload_root).unwrap();

    for file in files {
        let full_path = upload_root.join(black_box(file));
        let canon = soft_canonicalize(black_box(&full_path)).unwrap();

        // Manual boundary check
        if !canon.starts_with(&boundary_canon) {
            panic!("Escape attempt!");
        }

        // Simulate file processing (already have validated path)
        black_box(&canon);
    }
}

/// StrictPath approach: Validate boundary once, reuse for all files
///
/// This is the strict-path way:
/// ```rust
/// let boundary = PathBoundary::try_new(upload_root)?;
///
/// for file in uploads {
///     let validated = boundary.strict_join(file)?;
///     // Process file... (validated is StrictPath, guaranteed safe)
/// }
/// ```
fn strict_path_pattern(upload_root: &Path, files: &[String]) {
    let boundary: PathBoundary<BenchRoot> = PathBoundary::try_new(upload_root).unwrap();

    for file in files {
        let validated = boundary.strict_join(black_box(file)).unwrap();
        black_box(&validated);
    }
}

/// VirtualPath approach: Validate root once, automatic clamping
fn virtual_path_pattern(upload_root: &Path, files: &[String]) {
    let vroot: VirtualRoot<BenchRoot> = VirtualRoot::try_new(upload_root).unwrap();

    for file in files {
        let validated = vroot.virtual_join(black_box(file)).unwrap();
        black_box(&validated);
    }
}

/// Benchmark: 10 file uploads (small batch)
fn bench_small_batch(c: &mut Criterion) {
    let workload = WebServerWorkload::new(10).expect("Failed to create workload");

    let mut group = c.benchmark_group("small_batch_10_files");
    group.throughput(Throughput::Elements(10));

    group.bench_function("manual_soft_canonicalize", |b| {
        b.iter(|| manual_validation_pattern(workload.upload_root(), workload.incoming_files()));
    });

    group.bench_function("strict_path_cached", |b| {
        b.iter(|| strict_path_pattern(workload.upload_root(), workload.incoming_files()));
    });

    group.bench_function("virtual_path_cached", |b| {
        b.iter(|| virtual_path_pattern(workload.upload_root(), workload.incoming_files()));
    });

    group.finish();
}

/// Benchmark: 100 file uploads (typical request burst)
fn bench_medium_batch(c: &mut Criterion) {
    let workload = WebServerWorkload::new(100).expect("Failed to create workload");

    let mut group = c.benchmark_group("medium_batch_100_files");
    group.throughput(Throughput::Elements(100));

    group.bench_function("manual_soft_canonicalize", |b| {
        b.iter(|| manual_validation_pattern(workload.upload_root(), workload.incoming_files()));
    });

    group.bench_function("strict_path_cached", |b| {
        b.iter(|| strict_path_pattern(workload.upload_root(), workload.incoming_files()));
    });

    group.bench_function("virtual_path_cached", |b| {
        b.iter(|| virtual_path_pattern(workload.upload_root(), workload.incoming_files()));
    });

    group.finish();
}

/// Benchmark: 1000 file uploads (large archive extraction)
fn bench_large_batch(c: &mut Criterion) {
    let workload = WebServerWorkload::new(1000).expect("Failed to create workload");

    let mut group = c.benchmark_group("large_batch_1000_files");
    group.throughput(Throughput::Elements(1000));

    group.bench_function("manual_soft_canonicalize", |b| {
        b.iter(|| manual_validation_pattern(workload.upload_root(), workload.incoming_files()));
    });

    group.bench_function("strict_path_cached", |b| {
        b.iter(|| strict_path_pattern(workload.upload_root(), workload.incoming_files()));
    });

    group.bench_function("virtual_path_cached", |b| {
        b.iter(|| virtual_path_pattern(workload.upload_root(), workload.incoming_files()));
    });

    group.finish();
}

/// Benchmark: Directory scanning (read_dir + validate each entry)
fn bench_directory_scanning(c: &mut Criterion) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let scan_root = temp_dir.path().to_path_buf();

    // Create 50 files to scan
    for i in 0..50 {
        fs::write(scan_root.join(format!("file_{}.txt", i)), "data").unwrap();
    }

    let mut group = c.benchmark_group("directory_scanning");
    group.throughput(Throughput::Elements(50));

    group.bench_function("manual_read_dir_validate", |b| {
        b.iter(|| {
            let boundary_canon = soft_canonicalize(&scan_root).unwrap();

            for entry in fs::read_dir(&scan_root).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let canon = soft_canonicalize(&path).unwrap();

                if !canon.starts_with(&boundary_canon) {
                    panic!("Escape!");
                }

                black_box(&canon);
            }
        });
    });

    group.bench_function("strict_path_read_dir", |b| {
        b.iter(|| {
            let boundary: PathBoundary<BenchRoot> = PathBoundary::try_new(&scan_root).unwrap();
            let root = boundary.into_strictpath().unwrap();

            for entry in root.read_dir().unwrap() {
                let entry = entry.unwrap();
                let validated = entry.path(); // Already StrictPath!
                black_box(&validated);
            }
        });
    });

    group.bench_function("virtual_path_read_dir", |b| {
        b.iter(|| {
            let vroot: VirtualRoot<BenchRoot> = VirtualRoot::try_new(&scan_root).unwrap();
            let root = vroot.into_virtualpath().unwrap();

            for entry in root.read_dir().unwrap() {
                let entry = entry.unwrap();
                let validated = entry.path(); // Already VirtualPath!
                black_box(&validated);
            }
        });
    });

    group.finish();
}

/// Benchmark: Multi-user scenario (10 users, 10 files each)
fn bench_multi_user_scenario(c: &mut Criterion) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let base_root = temp_dir.path().to_path_buf();

    // Create user directories
    for user_id in 0..10 {
        fs::create_dir_all(base_root.join(format!("user_{}", user_id))).unwrap();
    }

    let user_files: Vec<String> = (0..10)
        .flat_map(|user_id| {
            (0..10).map(move |file_id| format!("user_{}/file_{}.dat", user_id, file_id))
        })
        .collect();

    let mut group = c.benchmark_group("multi_user_10x10");
    group.throughput(Throughput::Elements(100));

    group.bench_function("manual_per_user_validation", |b| {
        b.iter(|| {
            let base_canon = soft_canonicalize(&base_root).unwrap();

            for file in &user_files {
                let full_path = base_root.join(black_box(file));
                let canon = soft_canonicalize(&full_path).unwrap();

                if !canon.starts_with(&base_canon) {
                    panic!("Escape!");
                }

                black_box(&canon);
            }
        });
    });

    group.bench_function("strict_path_shared_boundary", |b| {
        b.iter(|| {
            let boundary: PathBoundary<BenchRoot> = PathBoundary::try_new(&base_root).unwrap();

            for file in &user_files {
                let validated = boundary.strict_join(black_box(file)).unwrap();
                black_box(&validated);
            }
        });
    });

    group.bench_function("virtual_path_shared_root", |b| {
        b.iter(|| {
            let vroot: VirtualRoot<BenchRoot> = VirtualRoot::try_new(&base_root).unwrap();

            for file in &user_files {
                let validated = vroot.virtual_join(black_box(file)).unwrap();
                black_box(&validated);
            }
        });
    });

    group.finish();
}

/// Benchmark: I/O-heavy workload (validation + file operations)
fn bench_io_heavy_workload(c: &mut Criterion) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let work_root = temp_dir.path().to_path_buf();

    // Create test files
    for i in 0..20 {
        fs::write(work_root.join(format!("file_{}.txt", i)), "test data").unwrap();
    }

    let files: Vec<String> = (0..20).map(|i| format!("file_{}.txt", i)).collect();

    let mut group = c.benchmark_group("io_heavy_exists_metadata");
    group.throughput(Throughput::Elements(20));

    group.bench_function("manual_validate_then_io", |b| {
        b.iter(|| {
            let boundary_canon = soft_canonicalize(&work_root).unwrap();

            for file in &files {
                let full_path = work_root.join(black_box(file));
                let canon = soft_canonicalize(&full_path).unwrap();

                if !canon.starts_with(&boundary_canon) {
                    panic!("Escape!");
                }

                // I/O operations
                black_box(canon.exists());
                black_box(fs::metadata(&canon).ok());
            }
        });
    });

    group.bench_function("strict_path_io", |b| {
        b.iter(|| {
            let boundary: PathBoundary<BenchRoot> = PathBoundary::try_new(&work_root).unwrap();

            for file in &files {
                let validated = boundary.strict_join(black_box(file)).unwrap();

                // I/O operations (path already validated!)
                black_box(validated.exists());
                black_box(validated.metadata().ok());
            }
        });
    });

    group.bench_function("virtual_path_io", |b| {
        b.iter(|| {
            let vroot: VirtualRoot<BenchRoot> = VirtualRoot::try_new(&work_root).unwrap();

            for file in &files {
                let validated = vroot.virtual_join(black_box(file)).unwrap();

                // I/O operations
                black_box(validated.exists());
                black_box(validated.metadata().ok());
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_small_batch,
    bench_medium_batch,
    bench_large_batch,
    bench_directory_scanning,
    bench_multi_user_scenario,
    bench_io_heavy_workload
);
criterion_main!(benches);
