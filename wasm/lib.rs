#![no_std]
#![feature(core_intrinsics, lang_items, alloc_error_handler)]

use argon2::{Algorithm, Argon2, Version};

extern crate alloc;
extern crate wee_alloc;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

extern "C" {
  fn panic(ptr: *mut u8, len: usize);
}

#[panic_handler]
#[no_mangle]
pub fn panic_handler(info: &core::panic::PanicInfo) -> ! {
  let mut msg = alloc::format!("{}", info);
  let ptr = msg.as_mut_ptr();
  let len = msg.len();
  unsafe { panic(ptr, len) };

  loop {}
}

#[alloc_error_handler]
#[no_mangle]
pub fn oom_handler(layout: core::alloc::Layout) -> ! {
  panic!("memory allocation of {} bytes failed", layout.size());
}

#[no_mangle]
pub unsafe fn alloc(size: usize) -> *mut u8 {
  let align = core::mem::align_of::<usize>();
  let layout = alloc::alloc::Layout::from_size_align_unchecked(size, align);
  alloc::alloc::alloc(layout)
}

#[no_mangle]
pub unsafe fn dealloc(ptr: *mut u8, size: usize) {
  let align = core::mem::align_of::<usize>();
  let layout = alloc::alloc::Layout::from_size_align_unchecked(size, align);
  alloc::alloc::dealloc(ptr, layout);
}

#[no_mangle]
pub unsafe fn hash_raw(
  pwd_ptr: *const u8,
  pwd_len: usize,
  salt_ptr: *const u8,
  salt_len: usize,
  secret_ptr: *const u8,
  secret_len: usize,
  ad_ptr: *const u8,
  ad_len: usize,

  alg: usize,
  time_cost: u32,
  memory_cost: u32,
  lanes: u32,
  out_len: usize,
  version: usize,
) -> *const u8 {
  let pwd = core::slice::from_raw_parts(pwd_ptr, pwd_len);
  let salt = core::slice::from_raw_parts(salt_ptr, salt_len);
  let secret = if secret_len > 0 {
    Some(core::slice::from_raw_parts(secret_ptr, secret_len))
  } else {
    None
  };
  let ad = core::slice::from_raw_parts(ad_ptr, ad_len);

  let alg = match alg {
    0 => Algorithm::Argon2d,
    1 => Algorithm::Argon2i,
    _ => Algorithm::Argon2id,
  };
  let version = match version {
    0 => Version::V0x10,
    _ => Version::V0x13,
  };

  let argon2 =
    Argon2::new(secret, time_cost, memory_cost, lanes, version).unwrap();
  let out_ptr = alloc(out_len);
  let out = core::slice::from_raw_parts_mut(out_ptr, out_len);

  argon2.hash_password_into(alg, pwd, salt, ad, out).unwrap();

  out_ptr
}
