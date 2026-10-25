//! The local store's browser half, in the harness worker: its directory in the origin-private
//! file system, and WebCrypto's PBKDF2. wasm32 only.

use super::{DIRECTORY, ITERATIONS, Kdf, Salt, Storage};
use crate::credential::{LocalPassphrase, WrappingKey};
use js_sys::{Array, ArrayBuffer, Function, Promise, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    Blob, CryptoKey, FileSystemDirectoryHandle, FileSystemFileHandle,
    FileSystemGetDirectoryOptions, FileSystemGetFileOptions, FileSystemWritableFileStream,
    Pbkdf2Params, WorkerGlobalScope,
};

fn scope() -> WorkerGlobalScope {
    js_sys::global().unchecked_into()
}

fn why(context: &str) -> impl Fn(JsValue) -> String + '_ {
    move |e| match e.dyn_ref::<js_sys::Error>() {
        Some(error) => format!("{context}: {}", String::from(error.message())),
        None => format!("{context}: {e:?}"),
    }
}

async fn wait(promise: Promise, context: &str) -> Result<JsValue, String> {
    JsFuture::from(promise).await.map_err(why(context))
}

/// The store's directory in OPFS.
#[derive(Clone, Default)]
pub struct Opfs {
    /// The tracer's `fail_append`: the next move is made to a name OPFS rejects, so the real
    /// append fails at a storage call.
    #[cfg(feature = "tracer")]
    pub fail_next_move: std::rc::Rc<std::cell::Cell<bool>>,
}

impl Opfs {
    /// The directory, or `None` if it does not exist and `create` is not set.
    async fn directory(&self, create: bool) -> Result<Option<FileSystemDirectoryHandle>, String> {
        let root = wait(scope().navigator().storage().get_directory(), "OPFS").await?;
        let root: FileSystemDirectoryHandle = root.unchecked_into();
        let options = FileSystemGetDirectoryOptions::new();
        options.set_create(create);
        match JsFuture::from(root.get_directory_handle_with_options(DIRECTORY, &options)).await {
            Ok(directory) => Ok(Some(directory.unchecked_into())),
            Err(e)
                if !create
                    && Reflect::get(&e, &"name".into()).ok() == Some("NotFoundError".into()) =>
            {
                Ok(None)
            }
            Err(e) => Err(why(DIRECTORY)(e)),
        }
    }

    async fn file(&self, name: &str, create: bool) -> Result<FileSystemFileHandle, String> {
        let directory = self
            .directory(create)
            .await?
            .ok_or_else(|| format!("{DIRECTORY}: not found"))?;
        let options = FileSystemGetFileOptions::new();
        options.set_create(create);
        let file = wait(directory.get_file_handle_with_options(name, &options), name).await?;
        Ok(file.unchecked_into())
    }
}

impl Storage for Opfs {
    async fn list(&self) -> Result<Vec<String>, String> {
        let Some(directory) = self.directory(false).await? else {
            return Ok(Vec::new());
        };
        let names = directory.keys();
        let mut found = Vec::new();
        loop {
            let next = wait(names.next().map_err(why("list"))?, "list").await?;
            if Reflect::get(&next, &"done".into()).map_err(why("list"))? == JsValue::TRUE {
                return Ok(found);
            }
            let name = Reflect::get(&next, &"value".into()).map_err(why("list"))?;
            found.push(
                name.as_string()
                    .ok_or("list: a name that is not a string")?,
            );
        }
    }

    async fn read(&self, name: &str) -> Result<Vec<u8>, String> {
        let file = wait(self.file(name, false).await?.get_file(), name).await?;
        let bytes = wait(file.unchecked_into::<Blob>().array_buffer(), name).await?;
        Ok(Uint8Array::new(&bytes).to_vec())
    }

    async fn write(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        let file = self.file(name, true).await?;
        let stream = wait(file.create_writable(), name).await?;
        let stream: FileSystemWritableFileStream = stream.unchecked_into();
        wait(stream.write_with_u8_array(bytes).map_err(why(name))?, name).await?;
        wait(stream.close(), name).await?;
        Ok(())
    }

    /// `FileSystemHandle.move()`, which web-sys does not bind.
    async fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        #[cfg(feature = "tracer")]
        let to = if self.fail_next_move.replace(false) {
            ".."
        } else {
            to
        };
        #[cfg(feature = "tracer")]
        crate::testonly::hold_move().await?;
        let file = self.file(from, false).await?;
        let move_to: Function = Reflect::get(&file, &"move".into())
            .map_err(why("move"))?
            .dyn_into()
            .map_err(|_| "move: FileSystemHandle.move() is not available".to_string())?;
        let promise = move_to.call1(&file, &to.into()).map_err(why("move"))?;
        wait(promise.unchecked_into(), &format!("move {from} to {to}")).await?;
        Ok(())
    }
}

/// WebCrypto's PBKDF2-HMAC-SHA-256 (credential format v1: "This uses WebCrypto's native KDF").
pub struct WebCrypto;

impl Kdf for WebCrypto {
    async fn derive(
        &self,
        passphrase: LocalPassphrase,
        salt: &Salt,
    ) -> Result<WrappingKey, String> {
        // JavaScript's garbage collector clears nothing, so the copy handed to `importKey` and the
        // buffer `deriveBits` returns are zero-filled here (`SEC-5` rows 18 and 19).
        let bytes = Uint8Array::from(&passphrase.0[..]);
        let derived = async {
            let subtle = scope().crypto().map_err(why("crypto"))?.subtle();
            let usages = Array::of1(&"deriveBits".into());
            let imported = subtle
                .import_key_with_str("raw", &bytes, "PBKDF2", false, &usages)
                .map_err(why("importKey"))?;
            let key: CryptoKey = wait(imported, "importKey").await?.unchecked_into();
            let params = Pbkdf2Params::new_with_str(
                "PBKDF2",
                "SHA-256",
                ITERATIONS,
                &Uint8Array::from(&salt.0[..]),
            );
            let bits = subtle
                .derive_bits_with_object(&params, &key, 256)
                .map_err(why("deriveBits"))?;
            wait(bits, "deriveBits").await
        }
        .await;
        bytes.fill(0, 0, bytes.length());
        drop(passphrase);
        let bits = Uint8Array::new(&derived?.unchecked_into::<ArrayBuffer>());
        let mut key = WrappingKey([0; 32]);
        if bits.length() != 32 {
            bits.fill(0, 0, bits.length());
            return Err(format!("deriveBits: {} bytes, not 32", bits.length()));
        }
        bits.copy_to(&mut key.0);
        bits.fill(0, 0, 32);
        Ok(key)
    }
}
