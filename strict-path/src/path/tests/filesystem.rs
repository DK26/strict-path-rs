#[cfg(feature = "virtual-path")]
use crate::VirtualRoot;
use crate::{path::strict_path::StrictPath, PathBoundary};
use std::path::PathBuf;

#[test]
fn test_strict_path_collections() {
    use std::collections::{BTreeMap, HashMap};

    let temp = tempfile::tempdir().unwrap();
    let temp_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();
    let test_path = PathBuf::from("path/file.txt");
    let stated_path = crate::validator::path_history::PathHistory::new(test_path);
    let entry_path: StrictPath = temp_dir
        .strict_join(stated_path.virtualize_to_restriction(&temp_dir))
        .unwrap();

    let mut map: HashMap<StrictPath, &str> = HashMap::new();
    map.insert(entry_path.clone(), "value");
    assert_eq!(map.get(&entry_path), Some(&"value"));

    let mut btree: BTreeMap<StrictPath, &str> = BTreeMap::new();
    btree.insert(entry_path.clone(), "btree");
    assert_eq!(btree.get(&entry_path), Some(&"btree"));
}

#[test]
fn strict_copy_file_in_same_boundary() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let src = boundary.strict_join("a.txt").unwrap();
    src.write("hello").unwrap();

    // Copy to sibling name
    let dst = boundary.strict_join("b.txt").unwrap();
    let bytes = src.strict_copy("b.txt").unwrap();
    assert_eq!(bytes, "hello".len() as u64);
    assert!(src.exists());
    assert!(dst.exists());
    assert_eq!(dst.read_to_string().unwrap(), "hello");
}

#[test]
fn strict_copy_absolute_inside_boundary() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let src = boundary.strict_join("docs/file.txt").unwrap();
    src.create_parent_dir_all().unwrap();
    src.write("x").unwrap();

    let abs_inside = td.path().join("copy_here.txt");
    let dst = boundary.strict_join("copy_here.txt").unwrap();
    let bytes = src.strict_copy(&abs_inside).unwrap();
    assert_eq!(bytes, 1);
    assert!(dst.exists());
    assert_eq!(dst.read_to_string().unwrap(), "x");
}

#[test]
fn strict_copy_rejects_escape_outside_boundary() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let src = boundary.strict_join("a.txt").unwrap();
    src.write("x").unwrap();
    let outside = td.path().parent().unwrap().join("oops.txt");
    let err = src.strict_copy(&outside).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Other);
}

#[test]
#[cfg(feature = "virtual-path")]
fn virtual_copy_file_simple() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let src = boundary.strict_join("docs/a.txt").unwrap();
    src.create_parent_dir_all().unwrap();
    src.write("v").unwrap();
    let v = src.virtualize();

    // Relative sibling copy
    let vdst = boundary.strict_join("docs/b.txt").unwrap().virtualize();
    let bytes = v.virtual_copy("b.txt").unwrap();
    assert_eq!(bytes, "v".len() as u64);
    assert_eq!(format!("{}", vdst.virtualpath_display()), "/docs/b.txt");
    assert!(vdst.exists());
    assert_eq!(vdst.read_to_string().unwrap(), "v");
    // Source still exists
    assert!(v.exists());
}

#[test]
#[cfg(feature = "virtual-path")]
fn virtual_copy_absolute_under_root() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let src = boundary.strict_join("docs/a.txt").unwrap();
    src.create_parent_dir_all().unwrap();
    src.write("v").unwrap();
    let v = src.virtualize();

    let vdst = boundary.strict_join("rooted.txt").unwrap().virtualize();
    let bytes = v.virtual_copy("/rooted.txt").unwrap();
    assert_eq!(bytes, "v".len() as u64);
    assert_eq!(format!("{}", vdst.virtualpath_display()), "/rooted.txt");
    assert!(vdst.exists());
    assert_eq!(vdst.read_to_string().unwrap(), "v");
}

#[test]
fn strict_copy_fails_when_parent_missing() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let src = boundary.strict_join("a.txt").unwrap();
    src.write("x").unwrap();
    // Parent for destination missing
    let err = src.strict_copy("missing_dir/b.txt").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[test]
#[cfg(feature = "virtual-path")]
fn virtual_copy_fails_when_parent_missing() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let src = boundary.strict_join("docs/a.txt").unwrap();
    src.create_parent_dir_all().unwrap();
    src.write("v").unwrap();
    let v = src.virtualize();
    let err = v.virtual_copy("sub/b.txt").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn strict_copy_directory_is_error() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let dir = boundary.strict_join("dir").unwrap();
    dir.create_dir_all().unwrap();
    let dst = boundary.strict_join("dir2").unwrap();
    let err = dir.strict_copy("dir2").unwrap_err();
    // Cross-platform and MSRV-friendly: assert a failure kind from a known stable set,
    // and on Unix also accept a direct EISDIR mapping via raw_os_error (21).
    let kind = err.kind();
    let acceptable = matches!(
        kind,
        std::io::ErrorKind::Other
            | std::io::ErrorKind::PermissionDenied
            | std::io::ErrorKind::InvalidInput
            | std::io::ErrorKind::Unsupported
    );
    #[cfg(unix)]
    {
        const EISDIR_CODE: i32 = 21; // POSIX EISDIR
        let acceptable =
            acceptable || matches!(err.raw_os_error(), Some(code) if code == EISDIR_CODE);
        assert!(
            acceptable,
            "unexpected error kind: {:?}, raw: {:?}",
            kind,
            err.raw_os_error()
        );
    }
    #[cfg(not(unix))]
    {
        assert!(
            acceptable,
            "unexpected error kind: {:?}, raw: {:?}",
            kind,
            err.raw_os_error()
        );
    }
    // No destination was created
    assert!(dir.is_dir());
    assert!(!dst.exists());
}

#[test]
#[cfg(feature = "virtual-path")]
fn virtual_copy_with_parent_components_is_clamped() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let src = boundary.strict_join("docs/file.txt").unwrap();
    src.create_parent_dir_all().unwrap();
    src.write("v").unwrap();
    let v = src.virtualize();
    let v2 = boundary.strict_join("outside.txt").unwrap().virtualize();
    let bytes = v.virtual_copy("../outside.txt").unwrap();
    assert_eq!(bytes, "v".len() as u64);
    assert_eq!(format!("{}", v2.virtualpath_display()), "/outside.txt");
}

#[test]
fn strict_copy_overwrites_existing_destination() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let src = boundary.strict_join("src.txt").unwrap();
    src.write("NEW").unwrap();
    let dst = boundary.strict_join("dst.txt").unwrap();
    dst.write("OLD").unwrap();
    let dst = boundary.strict_join("dst.txt").unwrap();
    let bytes = src.strict_copy("dst.txt").unwrap();
    assert_eq!(bytes, "NEW".len() as u64);
    assert_eq!(dst.read_to_string().unwrap(), "NEW");
}
#[test]
#[cfg(feature = "virtual-path")]
fn test_strict_path_display_formatting() {
    let temp = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();
    let vpath = vroot.virtual_join("path/file.txt").unwrap();

    let display_output = format!("{}", vpath.virtualpath_display());
    assert_eq!(display_output, "/path/file.txt");
}

#[test]
fn test_strict_path_equality_and_hash() {
    let path1 = PathBuf::from("path");
    let path2 = PathBuf::from("path");
    let path3 = PathBuf::from("different/path");
    let temp = tempfile::tempdir().unwrap();
    let temp_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let stated_path1 = crate::validator::path_history::PathHistory::new(path1);
    let jailed1: StrictPath = temp_dir
        .strict_join(stated_path1.virtualize_to_restriction(&temp_dir))
        .unwrap();
    let stated_path2 = crate::validator::path_history::PathHistory::new(path2);
    let jailed2: StrictPath = temp_dir
        .strict_join(stated_path2.virtualize_to_restriction(&temp_dir))
        .unwrap();
    let stated_path3 = crate::validator::path_history::PathHistory::new(path3);
    let jailed3: StrictPath = temp_dir
        .strict_join(stated_path3.virtualize_to_restriction(&temp_dir))
        .unwrap();

    assert_eq!(jailed1, jailed2);
    assert_ne!(jailed1, jailed3);

    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert(jailed1, "value");
    assert_eq!(map.get(&jailed2), Some(&"value"));
}
#[test]
fn test_strict_path_metadata_behavior() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();
    let strict_file: StrictPath = boundary.strict_join("file.txt").unwrap();

    std::fs::write(strict_file.interop_path(), b"hello").unwrap();
    let metadata = strict_file.metadata().unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.len(), 5);

    strict_file.remove_file().unwrap();
    assert!(strict_file.metadata().is_err());
}

#[test]
#[cfg(feature = "virtual-path")]
fn test_virtual_path_metadata_behavior() {
    let temp = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();
    let vpath = vroot.virtual_join("file.txt").unwrap();

    std::fs::write(vpath.as_unvirtual().interop_path(), b"abc").unwrap();
    let metadata = vpath.metadata().unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.len(), 3);

    vpath.remove_file().unwrap();
    assert!(vpath.metadata().is_err());
}

#[test]
fn test_strict_path_remove_dir_variants() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    // remove_dir removes an empty directory
    let empty_dir = boundary.strict_join("dir_one").unwrap();
    empty_dir.create_dir_all().unwrap();
    assert!(empty_dir.is_dir());
    empty_dir.remove_dir().unwrap();
    assert!(!empty_dir.exists());

    // remove_dir_all removes a directory tree
    let dir_root = boundary.strict_join("dir_two").unwrap();
    let nested = dir_root.strict_join("nested").unwrap();
    nested.create_dir_all().unwrap();
    assert!(nested.is_dir());
    dir_root.remove_dir_all().unwrap();
    assert!(!dir_root.exists());
}

#[test]
#[cfg(feature = "virtual-path")]
fn test_virtual_path_remove_dir_variants() {
    let temp = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();

    // remove_dir removes an empty directory
    let empty_dir = vroot.virtual_join("dir_one").unwrap();
    empty_dir.create_dir_all().unwrap();
    assert!(empty_dir.is_dir());
    empty_dir.remove_dir().unwrap();
    assert!(!empty_dir.exists());

    // remove_dir_all removes a directory tree
    let dir_root = vroot.virtual_join("dir_two").unwrap();
    let nested = dir_root.virtual_join("nested").unwrap();
    nested.create_dir_all().unwrap();
    assert!(nested.is_dir());
    dir_root.remove_dir_all().unwrap();
    assert!(!dir_root.exists());
}

// ============================================================
// append() tests
// ============================================================

#[test]
fn test_strict_path_append_creates_file_if_missing() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let log_file = boundary.strict_join("new.log").unwrap();
    assert!(!log_file.exists());

    log_file.append("first line\n").unwrap();
    assert!(log_file.exists());
    assert_eq!(log_file.read_to_string().unwrap(), "first line\n");
}

#[test]
fn test_strict_path_append_appends_to_existing() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let log_file = boundary.strict_join("existing.log").unwrap();
    log_file.write("line 1\n").unwrap();

    log_file.append("line 2\n").unwrap();
    log_file.append("line 3\n").unwrap();

    let contents = log_file.read_to_string().unwrap();
    assert_eq!(contents, "line 1\nline 2\nline 3\n");
}

#[test]
fn test_strict_path_append_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let bin_file = boundary.strict_join("data.bin").unwrap();
    bin_file.append([0x01, 0x02]).unwrap();
    bin_file.append([0x03, 0x04]).unwrap();

    assert_eq!(bin_file.read().unwrap(), vec![0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn test_strict_path_append_on_directory_errors() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let dir = boundary.strict_join("mydir").unwrap();
    dir.create_dir_all().unwrap();

    let err = dir.append("data").unwrap_err();
    // Attempting to append to a directory should fail (platform-dependent error)
    assert!(
        err.kind() == std::io::ErrorKind::PermissionDenied
            || err.kind() == std::io::ErrorKind::Other
            || err.kind() == std::io::ErrorKind::IsADirectory
    );
}

#[test]
#[cfg(feature = "virtual-path")]
fn test_virtual_path_append_creates_file_if_missing() {
    let temp = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();

    let log_file = vroot.virtual_join("logs/audit.log").unwrap();
    log_file.create_parent_dir_all().unwrap();
    assert!(!log_file.exists());

    log_file.append("event 1\n").unwrap();
    assert!(log_file.exists());
    assert_eq!(log_file.read_to_string().unwrap(), "event 1\n");
}

#[test]
#[cfg(feature = "virtual-path")]
fn test_virtual_path_append_appends_to_existing() {
    let temp = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();

    let log_file = vroot.virtual_join("data.log").unwrap();
    log_file.write("a\n").unwrap();

    log_file.append("b\n").unwrap();
    log_file.append("c\n").unwrap();

    assert_eq!(log_file.read_to_string().unwrap(), "a\nb\nc\n");
}

// ============================================================
// open_with() tests
// ============================================================

#[test]
fn test_strict_path_open_with_read_write() {
    use std::io::{Read, Seek, SeekFrom, Write};

    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let data_file = boundary.strict_join("rw.bin").unwrap();

    // Create with read+write
    let mut file = data_file
        .open_with()
        .read(true)
        .write(true)
        .create(true)
        .open()
        .unwrap();

    file.write_all(b"hello").unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();

    let mut buf = [0u8; 5];
    file.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"hello");
}

#[test]
fn test_strict_path_open_with_append_mode() {
    use std::io::Write;

    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let log_file = boundary.strict_join("append.log").unwrap();

    // First write
    {
        let mut file = log_file
            .open_with()
            .create(true)
            .append(true)
            .open()
            .unwrap();
        file.write_all(b"line1\n").unwrap();
    }

    // Second append
    {
        let mut file = log_file.open_with().append(true).open().unwrap();
        file.write_all(b"line2\n").unwrap();
    }

    assert_eq!(log_file.read_to_string().unwrap(), "line1\nline2\n");
}

#[test]
fn test_strict_path_open_with_create_new_fails_if_exists() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let existing_file = boundary.strict_join("exists.txt").unwrap();
    existing_file.write("already here").unwrap();

    // create_new should fail because file exists
    let result = existing_file
        .open_with()
        .write(true)
        .create_new(true)
        .open();

    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
}

#[test]
fn test_strict_path_open_with_create_new_succeeds_if_missing() {
    use std::io::Write;

    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let new_file = boundary.strict_join("brand_new.txt").unwrap();
    assert!(!new_file.exists());

    let mut file = new_file
        .open_with()
        .write(true)
        .create_new(true)
        .open()
        .unwrap();
    file.write_all(b"exclusive").unwrap();
    drop(file);

    assert_eq!(new_file.read_to_string().unwrap(), "exclusive");
}

#[test]
fn test_strict_path_open_with_truncate() {
    use std::io::Write;

    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let file_path = boundary.strict_join("truncate.txt").unwrap();
    file_path.write("original content that is long").unwrap();

    // Open with truncate
    {
        let mut file = file_path
            .open_with()
            .write(true)
            .truncate(true)
            .open()
            .unwrap();
        file.write_all(b"short").unwrap();
    }

    assert_eq!(file_path.read_to_string().unwrap(), "short");
}

#[test]
#[cfg(feature = "virtual-path")]
fn test_virtual_path_open_with_read_write() {
    use std::io::{Read, Seek, SeekFrom, Write};

    let temp = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();

    let data_file = vroot.virtual_join("cache/state.bin").unwrap();
    data_file.create_parent_dir_all().unwrap();

    let mut file = data_file
        .open_with()
        .read(true)
        .write(true)
        .create(true)
        .open()
        .unwrap();

    file.write_all(b"state").unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();

    let mut buf = [0u8; 5];
    file.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"state");
}

#[test]
#[cfg(feature = "virtual-path")]
fn test_virtual_path_open_with_append_mode() {
    use std::io::Write;

    let temp = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();

    let log_file = vroot.virtual_join("events.log").unwrap();

    // First write
    {
        let mut file = log_file
            .open_with()
            .create(true)
            .append(true)
            .open()
            .unwrap();
        file.write_all(b"event1\n").unwrap();
    }

    // Second append
    {
        let mut file = log_file.open_with().append(true).open().unwrap();
        file.write_all(b"event2\n").unwrap();
    }

    assert_eq!(log_file.read_to_string().unwrap(), "event1\nevent2\n");
}

// ============================================================
// strict_read_dir() / virtual_read_dir() tests
// ============================================================

#[test]
fn test_strict_read_dir_iterates_files() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let dir = boundary.strict_join("docs").unwrap();
    dir.create_dir_all().unwrap();

    // Create some files
    boundary
        .strict_join("docs/readme.md")
        .unwrap()
        .write("# Readme")
        .unwrap();
    boundary
        .strict_join("docs/guide.md")
        .unwrap()
        .write("# Guide")
        .unwrap();
    boundary
        .strict_join("docs/api.md")
        .unwrap()
        .write("# API")
        .unwrap();

    // Iterate and collect
    let entries: Vec<_> = dir
        .strict_read_dir()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(entries.len(), 3);
    // All entries should be files
    for entry in &entries {
        assert!(entry.is_file());
    }
}

#[test]
fn test_strict_read_dir_mixed_files_and_dirs() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let root = boundary.strict_join("project").unwrap();
    root.create_dir_all().unwrap();

    // Create files
    boundary
        .strict_join("project/file.txt")
        .unwrap()
        .write("content")
        .unwrap();
    // Create subdirectory
    boundary
        .strict_join("project/subdir")
        .unwrap()
        .create_dir_all()
        .unwrap();

    let entries: Vec<_> = root
        .strict_read_dir()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(entries.len(), 2);

    let files: Vec<_> = entries.iter().filter(|e| e.is_file()).collect();
    let dirs: Vec<_> = entries.iter().filter(|e| e.is_dir()).collect();

    assert_eq!(files.len(), 1);
    assert_eq!(dirs.len(), 1);
}

#[test]
fn test_strict_read_dir_empty_directory() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let empty = boundary.strict_join("empty").unwrap();
    empty.create_dir_all().unwrap();

    let entries: Vec<_> = empty
        .strict_read_dir()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert!(entries.is_empty());
}

#[test]
fn test_strict_read_dir_on_file_errors() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let file = boundary.strict_join("not_a_dir.txt").unwrap();
    file.write("content").unwrap();

    // strict_read_dir on a file should error
    let err = file.strict_read_dir().unwrap_err();
    // The exact error varies by platform, but it should fail
    assert!(
        err.kind() == std::io::ErrorKind::NotADirectory || err.kind() == std::io::ErrorKind::Other
    );
}

#[test]
#[cfg(feature = "virtual-path")]
fn test_virtual_read_dir_iterates_files() {
    let temp = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();

    let dir = vroot.virtual_join("uploads").unwrap();
    dir.create_dir_all().unwrap();

    // Create some files
    vroot
        .virtual_join("uploads/photo.jpg")
        .unwrap()
        .write(b"JPG")
        .unwrap();
    vroot
        .virtual_join("uploads/doc.pdf")
        .unwrap()
        .write(b"PDF")
        .unwrap();

    let entries: Vec<_> = dir
        .virtual_read_dir()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(entries.len(), 2);
    for entry in &entries {
        assert!(entry.is_file());
        // Verify virtual display format
        let display = entry.virtualpath_display().to_string();
        assert!(display.starts_with("/uploads/"));
    }
}

#[test]
#[cfg(feature = "virtual-path")]
fn test_virtual_read_dir_preserves_virtual_paths() {
    let temp = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();

    let dir = vroot.virtual_join("nested/deep").unwrap();
    dir.create_dir_all().unwrap();
    vroot
        .virtual_join("nested/deep/file.txt")
        .unwrap()
        .write("test")
        .unwrap();

    let entries: Vec<_> = dir
        .virtual_read_dir()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(entries.len(), 1);
    let entry = &entries[0];

    // Virtual display should show the full virtual path
    assert_eq!(
        entry.virtualpath_display().to_string(),
        "/nested/deep/file.txt"
    );
}
