use crate::PathBoundary;
#[cfg(feature = "virtual-path")]
use crate::VirtualRoot;

// ============================================================
// append() tests
// ============================================================

#[test]
fn test_strict_path_append_creates_file_if_missing() {
    let temp = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let log_file = test_dir.strict_join("new.log").unwrap();
    assert!(!log_file.exists());

    log_file.append("first line\n").unwrap();
    assert!(log_file.exists());
    assert_eq!(log_file.read_to_string().unwrap(), "first line\n");
}

#[test]
fn test_strict_path_append_appends_to_existing() {
    let temp = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let log_file = test_dir.strict_join("existing.log").unwrap();
    log_file.write("line 1\n").unwrap();

    log_file.append("line 2\n").unwrap();
    log_file.append("line 3\n").unwrap();

    let contents = log_file.read_to_string().unwrap();
    assert_eq!(contents, "line 1\nline 2\nline 3\n");
}

#[test]
fn test_strict_path_append_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let bin_file = test_dir.strict_join("data.bin").unwrap();
    bin_file.append([0x01, 0x02]).unwrap();
    bin_file.append([0x03, 0x04]).unwrap();

    assert_eq!(bin_file.read().unwrap(), vec![0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn test_strict_path_append_on_directory_errors() {
    let temp = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let dir = test_dir.strict_join("mydir").unwrap();
    dir.create_dir_all().unwrap();

    // Attempting to append to a directory must fail; the exact error kind is platform-dependent
    // (Windows: PermissionDenied, Linux: EISDIR → Other on stable MSRV).
    dir.append("data").unwrap_err();
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
    let test_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let data_file = test_dir.strict_join("rw.bin").unwrap();

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
    let test_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let log_file = test_dir.strict_join("append.log").unwrap();

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
    let test_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let existing_file = test_dir.strict_join("exists.txt").unwrap();
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
    let test_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let new_file = test_dir.strict_join("brand_new.txt").unwrap();
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
    let test_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let file_path = test_dir.strict_join("truncate.txt").unwrap();
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
