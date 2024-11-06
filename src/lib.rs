//! LIBNFS is a client library for accessing NFS shares over a network
//! NFSv3 is the default but NFSv4 can be selected either by using the URL argument
//! version=4 or programatically calling nfs_set_version(nfs, NFS_V4) before
//! connecting to the server/share.
//!
use libnfs_sys::*;
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;

use std::ffi::{CStr, CString};
use std::io::{Error, ErrorKind, Result};
use std::mem::zeroed;
use std::os::raw::{c_int, c_char};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct NfsPtr(Arc<Mutex<*mut nfs_context>>);
// Safe because nfs_context in NfsPtr is enclosed within a Mutex
unsafe impl Send for NfsPtr{}
unsafe impl Sync for NfsPtr{}

impl Drop for NfsPtr {
    fn drop(&mut self) {
        let ctx_ref = self.0.lock().unwrap();
        let ctx = *ctx_ref;
        if !ctx.is_null() {
            unsafe {
                nfs_destroy_context(ctx);
            }
        }
    }
}

fn check_mut_ptr<T>(ptr: *mut T) -> Result<*mut T> {
    if ptr.is_null() {
        Err(Error::last_os_error())
    } else {
        Ok(ptr)
    }
}

fn check_retcode(ctx: *mut nfs_context, code: i32) -> Result<()> {
    if code < 0 {
        unsafe {
            let err_str = nfs_get_error(ctx);
            let e = CStr::from_ptr(err_str).to_string_lossy().into_owned();
            Err(Error::new(ErrorKind::Other, e))
        }
    } else {
        Ok(())
    }
}

#[derive(Clone)]
pub struct Nfs {
    context: Arc<NfsPtr>,
}

#[derive(Clone, Debug)]
pub enum EntryType {
    Block,
    Character,
    Directory,
    File,
    NamedPipe,
    Symlink,
    Socket,
}

impl EntryType {
    fn from(t: ftype3) -> Result<EntryType> {
        match t {
            // explicitly specifying libnfs_sys:: for below cases to get rid of warnings about non-uppercase globals
            // even though these constants are usable without specifying libnfs_sys:: due to the `use libnfs_sys::*`
            // for some reason it doesn't work to put #[allow(non_upper_case_globals)] above each case
            libnfs_sys::ftype3_NF3BLK => Ok(EntryType::Block),
            libnfs_sys::ftype3_NF3CHR => Ok(EntryType::Character),
            libnfs_sys::ftype3_NF3DIR => Ok(EntryType::Directory),
            libnfs_sys::ftype3_NF3REG => Ok(EntryType::File),
            libnfs_sys::ftype3_NF3FIFO => Ok(EntryType::NamedPipe),
            libnfs_sys::ftype3_NF3LNK => Ok(EntryType::Symlink),
            libnfs_sys::ftype3_NF3SOCK => Ok(EntryType::Socket),
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unknown file type: {}", t),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub path: PathBuf,
    pub inode: u64,
    pub d_type: EntryType,
    pub mode: Mode,
    pub size: u64,
    pub atime: timeval,
    pub mtime: timeval,
    pub ctime: timeval,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub dev: u64,
    pub rdev: u64,
    pub blksize: u64,
    pub blocks: u64,
    pub used: u64,
    pub atime_nsec: u32,
    pub mtime_nsec: u32,
    pub ctime_nsec: u32,
}

#[derive(Clone)]
pub struct NfsDirectory {
    nfs: Arc<NfsPtr>,
    handle: *mut nfsdir,
}

impl Drop for NfsDirectory {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                let ctx_ref = self.nfs.0.lock().unwrap();
                let ctx = *ctx_ref;
                nfs_closedir(ctx, self.handle);
            }
        }
    }
}

#[derive(Clone)]
pub struct NfsFile {
    nfs: Arc<NfsPtr>,
    handle: *mut nfsfh,
}

impl Drop for NfsFile {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                let ctx_ref = self.nfs.0.lock().unwrap();
                let ctx = *ctx_ref;
                nfs_close(ctx, self.handle);
            }
        }
    }
}


pub struct NfsUrl {
    url: *mut nfs_url,
}


impl Drop for NfsUrl {
    fn drop(&mut self) {
        if !self.url.is_null() {
            unsafe {
                nfs_destroy_url(self.url);
            }
        }
    }
}


impl Nfs {
    pub fn new() -> Result<Self> {
        unsafe {
            let ctx = check_mut_ptr(nfs_init_context())?;
            Ok(Nfs {
                context: Arc::new(NfsPtr(Arc::new(Mutex::new(ctx)))),
            })
        }
    }

    pub fn set_version(&self, version: i32) -> Result<()> {
        unsafe {
            let ctx_ref = self.context.0.lock().unwrap();
            let ctx = *ctx_ref;
            check_retcode(
                ctx,
                nfs_set_version(ctx, version),
            )?;
            Ok(())
        }
    }

    pub fn access(&self, path: &Path, mode: i32) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        unsafe {
            let ctx_ref = self.context.0.lock().unwrap();
            let ctx = *ctx_ref;
            check_retcode(
                ctx,
                nfs_access(ctx, path.as_ptr(), mode),
            )?;
            Ok(())
        }
    }

    pub fn access2(&self, path: &Path) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            check_retcode(ctx, nfs_access2(ctx, path.as_ptr()))?;
            Ok(())
        }
    }

    pub fn chdir(&self, path: &Path) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            check_retcode(ctx, nfs_chdir(ctx, path.as_ptr()))?;
            Ok(())
        }
    }

    pub fn chown(&self, path: &Path, uid: i32, gid: i32) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            check_retcode(
                ctx,
                nfs_chown(ctx, path.as_ptr(), uid, gid),
            )?;
            Ok(())
        }
    }

    /// Supported flags:
    /// O_APPEND
    /// O_SYNC
    /// O_EXCL
    /// O_TRUNC
    pub fn create(&mut self, path: &Path, _flags: OFlag, mode: Mode) -> Result<NfsFile> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            let mut file_handle: *mut nfsfh = ptr::null_mut();
            check_retcode(
                ctx,
                nfs_creat(
                    ctx,
                    path.as_ptr(),
                    mode.bits() as i32,
                    &mut file_handle,
                ),
            )?;
            Ok(NfsFile {
                nfs: Arc::clone(&self.context),
                handle: file_handle,
            })
        }
    }

    pub fn getcwd(&self) -> Result<PathBuf> {
        let mut cwd = ptr::null();
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            nfs_getcwd(ctx, &mut cwd);
            let path_tmp = CStr::from_ptr(cwd).to_string_lossy().into_owned();

            Ok(PathBuf::from(path_tmp))
        }
    }

    /// Get the maximum supported READ3 size by the server
    pub fn get_readmax(&self) -> Result<u64> {
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            let max = nfs_get_readmax(ctx) as u64;
            Ok(max)
        }
    }

    /// Get the maximum supported WRITE3 size by the server
    pub fn get_writemax(&self) -> Result<u64> {
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            let max = nfs_get_writemax(ctx) as u64;
            Ok(max)
        }
    }

    pub fn lchmod(&self, path: &Path, mode: Mode) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            check_retcode(
                ctx,
                nfs_lchmod(ctx, path.as_ptr(), mode.bits() as c_int),
            )?;
            Ok(())
        }
    }

    pub fn lchown(&self, path: &Path, uid: i32, gid: i32) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            check_retcode(
                ctx,
                nfs_lchown(ctx, path.as_ptr(), uid, gid),
            )?;
            Ok(())
        }
    }

    pub fn link(&self, oldpath: &Path, newpath: &Path) -> Result<()> {
        let old_path = CString::new(oldpath.as_os_str().as_bytes())?;
        let new_path = CString::new(newpath.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;

        unsafe {
            check_retcode(
                ctx,
                nfs_link(ctx, old_path.as_ptr(), new_path.as_ptr()),
            )?;
            Ok(())
        }
    }

    pub fn lstat64(&self, path: &Path) -> Result<nfs_stat_64> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            let mut stat_buf: nfs_stat_64 = zeroed();
            check_retcode(
                ctx,
                nfs_lstat64(ctx, path.as_ptr(), &mut stat_buf),
            )?;
            Ok(stat_buf)
        }
    }

    pub fn mkdir(&self, path: &Path) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            check_retcode(ctx, nfs_mkdir(ctx, path.as_ptr()))?;
            Ok(())
        }
    }

    pub fn mknod(&self, path: &Path, mode: i32, dev: i32) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            check_retcode(
                ctx,
                nfs_mknod(ctx, path.as_ptr(), mode, dev),
            )?;
            Ok(())
        }
    }

    pub fn mount(&self, server: &str, export_name: &str) -> Result<()> {
        let server = CString::new(server.as_bytes())?;
        let export = CString::new(export_name.as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            check_retcode(
                ctx,
                nfs_mount(ctx, server.as_ptr(), export.as_ptr()),
            )?;
            Ok(())
        }
    }

    /// Supported flags are
    /// O_APPEND
    /// O_RDONLY
    /// O_WRONLY
    /// O_RDWR
    /// O_SYNC
    /// O_TRUNC (Only valid with O_RDWR or O_WRONLY. Ignored otherwise.)
    pub fn open(&mut self, path: &Path, flags: OFlag) -> Result<NfsFile> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            let mut file_handle: *mut nfsfh = ptr::null_mut();
            check_retcode(
                ctx,
                nfs_open(
                    ctx,
                    path.as_ptr(),
                    flags.bits(),
                    &mut file_handle,
                ),
            )?;
            Ok(NfsFile {
                nfs: Arc::clone(&self.context),
                handle: file_handle,
            })
        }
    }

    pub fn opendir(&mut self, path: &Path) -> Result<NfsDirectory> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            let mut dir_handle: *mut nfsdir = ptr::null_mut();
            check_retcode(
                ctx,
                nfs_opendir(ctx, path.as_ptr(), &mut dir_handle),
            )?;
            Ok(NfsDirectory {
                nfs: Arc::clone(&self.context),
                handle: dir_handle,
            })
        }
    }

    /// Parse an NFS URL, but do not split path and file. File
    /// in the resulting struct remains NULL.
    pub fn parse_url_dir(&mut self, url: &str) -> Result<NfsUrl> {
        let url = CString::new(url.as_bytes())?;
        unsafe {
            let ctx_ref = self.context.0.lock().unwrap();
            let ctx = *ctx_ref;
            let nfs_url = check_mut_ptr(nfs_parse_url_dir(ctx, url.as_ptr()))?;
            Ok(NfsUrl {
                url: nfs_url,
            })
        }
    }

    /// Parse an NFS URL, but do not fail if file, path or even server is missing.
    /// Check elements of the resulting struct for NULL.
    pub fn parse_url_incomplete(&mut self, url: &str) -> Result<NfsUrl> {
        let url: CString = CString::new(url.as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            let nfs_url = check_mut_ptr(nfs_parse_url_incomplete(ctx, url.as_ptr()))?;
            Ok(NfsUrl {
                url: nfs_url,
            })
        }
    }

    /// URL parsing functions.
    /// These functions all parse a URL of the form
    /// nfs://server/path/file?argv=val[&arg=val]*
    /// and returns a nfs_url.
    ///
    /// Apart from parsing the URL the functions will also update
    /// the nfs context to reflect settings controlled via url arguments.
    ///
    /// Current URL arguments are :
    /// tcp-syncnt=<int>  : Number of SYNs to send during the seccion establish
    ///                     before failing settin up the tcp connection to the
    ///                     server.
    /// uid=<int>         : UID value to use when talking to the server.
    ///                     default it 65534 on Windows and getuid() on unixen.
    /// gid=<int>         : GID value to use when talking to the server.
    ///                     default it 65534 on Windows and getgid() on unixen.
    /// readahead=<int>   : Enable readahead for files and set the maximum amount
    ///                     of readahead to <int>.
    ///
    /// Parse a complete NFS URL including, server, path and
    /// filename. Fail if any component is missing.
    pub fn parse_url_full(&mut self, url: &str) -> Result<NfsUrl> {
        let url = CString::new(url.as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            let nfs_url = check_mut_ptr(nfs_parse_url_full(ctx, url.as_ptr()))?;
            Ok(NfsUrl {
                url: nfs_url,
            })
        }
    }
    

    pub fn parse_url_mount(&mut self, url: &str) -> Result<()> {
        unsafe {
            let n_url = self.parse_url_full(url)?;
            let url = *n_url.url;
            let server = url.server;
            let export = url.path;
            let ctx_ref = self.context.0.lock().unwrap();
            let ctx = *ctx_ref;
            check_retcode(
                ctx,
                nfs_mount(ctx, server, export),
            )?;
            Ok(())
        }
    }

    /*fn convert_cb(
        &self,
        f: &extern "C" fn(c_int, *mut nfs_ctx, *mut c_void, *mut c_void) -> (),
    ) -> unsafe extern "C" fn(c_int, *mut nfs_ctx, *mut c_void, *mut c_void) {
        *f
    }*/

    pub fn readlink(&self, path: &Path, buf: &mut [u8]) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;

        unsafe {
            check_retcode(
                ctx,
                nfs_readlink(
                    ctx,
                    path.as_ptr(),
                    buf.as_mut_ptr() as *mut c_char,
                    buf.len() as c_int,
                ),
            )?;
            Ok(())
        }
    }

    pub fn rename(&self, oldpath: &Path, newpath: &Path) -> Result<()> {
        let old_path = CString::new(oldpath.as_os_str().as_bytes())?;
        let new_path = CString::new(newpath.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            check_retcode(
                ctx,
                nfs_rename(ctx, old_path.as_ptr(), new_path.as_ptr()),
            )?;
            Ok(())
        }
    }

    pub fn rmdir(&self, path: &Path) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            check_retcode(ctx, nfs_rmdir(ctx, path.as_ptr()))?;
            Ok(())
        }
    }

    pub fn set_auth(&self, auth: &mut AUTH) -> Result<()> {
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            nfs_set_auth(ctx, auth);
        }
        Ok(())
    }

    /// Modify Connect Parameters
    pub fn set_tcp_syncnt(&self, syncnt: i32) -> Result<()> {
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            nfs_set_tcp_syncnt(ctx, syncnt);
        }
        Ok(())
    }

    /// Modify Connect Parameters
    pub fn set_uid(&self, uid: i32) -> Result<()> {
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            nfs_set_uid(ctx, uid);
        }
        Ok(())
    }

    /// Modify Connect Parameters
    pub fn set_gid(&self, gid: i32) -> Result<()> {
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            nfs_set_gid(ctx, gid);
        }
        Ok(())
    }

    /// Modify Connect Parameters
    pub fn set_readahead(&self, size: u32) -> Result<()> {
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            nfs_set_readmax(ctx, size as usize);
        }
        Ok(())
    }

    /// Modify Connect Parameters
    pub fn set_debug(&self, level: i32) -> Result<()> {
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            nfs_set_debug(ctx, level);
        }
        Ok(())
    }

    pub fn stat64(&self, path: &Path) -> Result<nfs_stat_64> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            let mut stat_buf: nfs_stat_64 = zeroed();
            check_retcode(
                ctx,
                nfs_stat64(ctx, path.as_ptr(), &mut stat_buf),
            )?;
            Ok(stat_buf)
        }
    }

    pub fn statvfs(&self, path: &Path) -> Result<statvfs> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            let mut stat_buf: statvfs = zeroed();
            check_retcode(
                ctx,
                nfs_statvfs(ctx, path.as_ptr(), &mut stat_buf),
            )?;
            Ok(stat_buf)
        }
    }

    pub fn symlink(&self, oldpath: &Path, newpath: &Path) -> Result<()> {
        let old_path = CString::new(oldpath.as_os_str().as_bytes())?;
        let new_path = CString::new(newpath.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            check_retcode(
                ctx,
                nfs_symlink(ctx, old_path.as_ptr(), new_path.as_ptr()),
            )?;
            Ok(())
        }
    }

    pub fn truncate(&self, path: &Path, len: u64) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            check_retcode(
                ctx,
                nfs_truncate(ctx, path.as_ptr(), len),
            )?;
            Ok(())
        }
    }

    pub fn umask(&self, mask: u16) -> Result<u16> {
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            let mask = nfs_umask(ctx, mask);
            Ok(mask)
        }
    }

    pub fn unlink(&self, path: &Path) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            check_retcode(ctx, nfs_unlink(ctx, path.as_ptr()))?;
            Ok(())
        }
    }

    // Set the access and modified times
    pub fn utimes(&self, path: &Path, times: &mut [timeval; 2]) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let ctx_ref = self.context.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            check_retcode(
                ctx,
                nfs_utimes(ctx, path.as_ptr(), times.as_mut_ptr()),
            )?;
            Ok(())
        }
    }
}

impl NfsFile {
    pub fn fchmod(&self, mode: i32) -> Result<()> {
        let ctx_ref = self.nfs.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            check_retcode(ctx, nfs_fchmod(ctx, self.handle, mode))?;

            Ok(())
        }
    }

    pub fn fchown(&self, uid: i32, gid: i32) -> Result<()> {
        let ctx_ref = self.nfs.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            check_retcode(ctx, nfs_fchown(ctx, self.handle, uid, gid))?;
            Ok(())
        }
    }

    pub fn ftruncate(&self, len: u64) -> Result<()> {
        let ctx_ref = self.nfs.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            check_retcode(ctx, nfs_ftruncate(ctx, self.handle, len))?;
            Ok(())
        }
    }

    /// 64 bit version of fstat. All fields are always 64bit.
    pub fn fstat64(&self) -> Result<nfs_stat_64> {
        let ctx_ref = self.nfs.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            let mut stat_buf: nfs_stat_64 = zeroed();
            check_retcode(
                ctx,
                nfs_fstat64(ctx, self.handle, &mut stat_buf),
            )?;
            Ok(stat_buf)
        }
    }

    pub fn fsync(&self) -> Result<()> {
        let ctx_ref = self.nfs.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            check_retcode(ctx, nfs_fsync(ctx, self.handle))?;
            Ok(())
        }
    }

    pub fn pread(&self, count: u64, offset: u64) -> Result<Vec<u8>> {
        let mut buffer: Vec<u8> = Vec::with_capacity(count as usize);
        let read_size = self.pread_into(count, offset, &mut buffer)?;
        unsafe {
            buffer.set_len(read_size as usize);
        }
        Ok(buffer)
    }

    pub fn pread_into(&self, count: u64, offset: u64, buffer: &mut [u8]) -> Result<i32> {
        let ctx_ref = self.nfs.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            let read_size = nfs_pread(
                ctx,
                self.handle,
                buffer.as_mut_ptr() as *mut _,
                count as usize,
                offset,
            );
            check_retcode(ctx, read_size)?;
            Ok(read_size)
        }
    }

    pub fn pwrite(&self, buffer: &[u8], offset: u64) -> Result<i32> {
        let ctx_ref = self.nfs.0.lock().unwrap();
        let ctx = *ctx_ref;
        unsafe {
            let write_size = nfs_pwrite(
                ctx,
                self.handle,
                buffer.as_ptr() as *mut _,
                buffer.len() as usize,
                offset,
            );
            check_retcode(ctx, write_size)?;
            Ok(write_size)
        }
    }

    pub fn read(&self, count: u64) -> Result<Vec<u8>> {
        self.pread(count, 0)
    }

    pub fn write(&self, buffer: &[u8]) -> Result<i32> {
        self.pwrite(buffer, 0)
    }

    /*
    pub fn lseek(&self, offset: i64, whence: i32, current_offset: u64) -> Result<()> {
        unsafe {
            check_retcode(ctx.nfs, nfs_lseek(*self.nfs.context, self.handle, offset, whence, current_offset))?;
            Ok(())
        }
    }
    */
}

impl Iterator for NfsDirectory {
    type Item = Result<DirEntry>;
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let ctx_ref = self.nfs.0.lock().unwrap();
            let ctx = *ctx_ref;
            let dirent = nfs_readdir(ctx, self.handle);
            if dirent.is_null() {
                return None;
            }

            let file_name = CStr::from_ptr((*dirent).name);
            let d_type = match EntryType::from((*dirent).type_) {
                Ok(ty) => ty,
                Err(e) => {
                    return Some(Err(e));
                }
            };
            let mode = Mode::from_bits_truncate(((*dirent).mode as u16).into());
            Some(Ok(DirEntry {
                path: PathBuf::from(file_name.to_string_lossy().into_owned()),
                inode: (*dirent).inode,
                d_type,
                mode,
                size: (*dirent).size,
                atime: (*dirent).atime,
                mtime: (*dirent).mtime,
                ctime: (*dirent).ctime,
                uid: (*dirent).uid,
                gid: (*dirent).gid,
                nlink: (*dirent).nlink,
                dev: (*dirent).dev,
                rdev: (*dirent).rdev,
                blksize: (*dirent).blksize,
                blocks: (*dirent).blocks,
                used: (*dirent).used,
                atime_nsec: (*dirent).atime_nsec,
                mtime_nsec: (*dirent).mtime_nsec,
                ctime_nsec: (*dirent).ctime_nsec,
            }))
        }
    }
}
