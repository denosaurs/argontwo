#![no_std]
#![feature(core_intrinsics, alloc_error_handler, const_mut_refs, allocator_api)]

extern crate alloc;

use argon2::Argon2;

use talc::*;

#[global_allocator] static TALC: talc::TalckWasm = unsafe { talc::TalckWasm::new_global() };

extern "C" {
  fn panic(ptr: *const u8, len: usize);
}

#[panic_handler]
#[no_mangle]
pub fn panic_handler(info: &core::panic::PanicInfo) -> ! {
  let msg = alloc::format!("{info}");
  let ptr = msg.as_ptr();
  let len = msg.len();
  unsafe { panic(ptr, len) };

  loop {}
}

#[alloc_error_handler]
#[no_mangle]
pub fn alloc_error_handler(layout: core::alloc::Layout) -> ! {
  panic!("Memory allocation of {} bytes failed", layout.size());
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
pub unsafe fn hash(
  password_ptr: *const u8,
  password_len: usize,

  salt_ptr: *const u8,
  salt_len: usize,

  secret_ptr: *const u8,
  secret_len: usize,

  output_ptr: *mut u8,
  output_len: usize,

  algorithm: u32,
  version: u32,

  m_cost: u32,
  t_cost: u32,
  p_cost: u32,
) {
  let password = core::slice::from_raw_parts(password_ptr, password_len);
  let salt = core::slice::from_raw_parts(salt_ptr, salt_len);
  let secret = if !secret_ptr.is_null() {
    Some(core::slice::from_raw_parts(secret_ptr, secret_len))
  } else {
    None
  };
  let output = core::slice::from_raw_parts_mut(output_ptr, output_len);

  let algorithm = match algorithm {
    0 => argon2::Algorithm::Argon2d,
    1 => argon2::Algorithm::Argon2i,
    2 => argon2::Algorithm::Argon2id,
    _ => panic!("Invalid algorithm"),
  };
  let version = argon2::Version::try_from(version).unwrap();
  let params = argon2::Params::new(m_cost, t_cost, p_cost, None).unwrap();

  // panic!("{m_cost}");

  let hasher = if let Some(secret) = secret {
    Argon2::new_with_secret(secret, algorithm, version, params).unwrap()
  } else {
    Argon2::new(algorithm, version, params)
  };

  hasher.hash_password_into(password, salt, output).unwrap();
}
