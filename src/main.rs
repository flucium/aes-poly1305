//https://github.com/RustCrypto/AEADs/blob/master/aes-gcm/LICENSE-APACHE
//https://github.com/RustCrypto/AEADs/blob/master/aes-gcm/LICENSE-MIT
//https://github.com/RustCrypto/AEADs/
//https://github.com/RustCrypto/AEADs/blob/master/aes-gcm/src/lib.rs
//https://github.com/flucium/aespoly1305/blob/main/LICENSE
use aead::{
    consts::{U0, U12, U16},
    generic_array::{ArrayLength, GenericArray},
    AeadCore, AeadInPlace, KeyInit, KeySizeUser,
};

use core::marker::PhantomData;
use subtle::ConstantTimeEq;

use aes::{Aes128, Aes192, Aes256};

use ctr::{
    cipher::{BlockCipher, BlockEncrypt, BlockSizeUser, InnerIvInit, StreamCipherCore},
    flavors::Ctr32BE as flavorsCtr32BE,
    CtrCore,
};

use poly1305::{universal_hash::{typenum::Unsigned, UniversalHash}, Block, Poly1305};

type Ctr32BE<C> = CtrCore<C, flavorsCtr32BE>;

struct AesPoly1305<C, N, T: ArrayLength<u8> = U16> {
    cipher: C,
    hasher: Poly1305,
    nonce_size: PhantomData<N>,
    tag_size: PhantomData<T>,
}

//https://github.com/RustCrypto/AEADs/blob/da7afb36855df5c69acae08d9b74c47cb55fbd6a/aes-gcm/src/lib.rs#L251
impl<C, N, T> AeadCore for AesPoly1305<C, N, T>
where
    N: ArrayLength<u8>,
    T: ArrayLength<u8> + Unsigned,
{
    type NonceSize = N;

    type TagSize = T;

    type CiphertextOverhead = U0;
}

//https://github.com/RustCrypto/AEADs/blob/da7afb36855df5c69acae08d9b74c47cb55fbd6a/aes-gcm/src/lib.rs#L228
impl<C, N, T> From<C> for AesPoly1305<C, N, T>
where
    C: BlockSizeUser<BlockSize = U16> + BlockEncrypt,
    T: ArrayLength<u8> + Unsigned,
{
    fn from(cipher: C) -> Self {
        cipher.encrypt_block(&mut GenericArray::default());

        let hasher = Poly1305::new(&GenericArray::default());

        Self {
            cipher,
            hasher,
            nonce_size: PhantomData,
            tag_size: PhantomData,
        }
    }
}

//https://github.com/RustCrypto/AEADs/blob/da7afb36855df5c69acae08d9b74c47cb55fbd6a/aes-gcm/src/lib.rs#L210
impl<C, N, T> KeySizeUser for AesPoly1305<C, N, T>
where
    C: KeySizeUser,
    T: ArrayLength<u8> + Unsigned,
{
    type KeySize = C::KeySize;
}

//https://github.com/RustCrypto/AEADs/blob/da7afb36855df5c69acae08d9b74c47cb55fbd6a/aes-gcm/src/lib.rs#L218
impl<C, N, T> KeyInit for AesPoly1305<C, N, T>
where
    C: BlockSizeUser<BlockSize = U16> + BlockEncrypt + KeyInit,
    T: ArrayLength<u8> + Unsigned,
{
    fn new(key: &aead::Key<Self>) -> Self {
        C::new(key).into()
    }
}

//https://github.com/RustCrypto/AEADs/blob/da7afb36855df5c69acae08d9b74c47cb55fbd6a/aes-gcm/src/lib.rs#L314
impl<C, N, T> AesPoly1305<C, N, T>
where
    C: BlockCipher + BlockSizeUser<BlockSize = aead::consts::U16> + BlockEncrypt,
    N: ArrayLength<u8>,
    T: ArrayLength<u8> + Unsigned,
{
    fn init_ctr(&self, nonce: &aead::Nonce<Self>) -> (Ctr32BE<&C>, Block) {
        let mut ctr = Ctr32BE::inner_iv_init(
            &self.cipher,
            &match N::to_usize() {
                12 => {
                    let mut block = Block::default();
                    block[..12].copy_from_slice(nonce);
                    block[15] = 1;
                    block
                }
                _ => {
                    let mut hasher = self.hasher.clone();
                    hasher.update_padded(nonce);
                    let mut block = Block::default();
                    let nbits = (N::to_usize() as u64) * 8;
                    block[8..].copy_from_slice(&nbits.to_be_bytes());
                    hasher.update(&[block]);
                    hasher.finalize()
                }
            },
        );

        let mut mask = Block::default();

        ctr.write_keystream_block(&mut mask);

        (ctr, mask)
    }

    fn compute_tag(
        &self,
        mask: Block,
        associated_data: &[u8],
        buffer: &[u8],
    ) -> GenericArray<u8, U16> {
        let mut hasher = self.hasher.clone();

        hasher.update_padded(associated_data);

        hasher.update_padded(buffer);

        let mut block = Block::default();

        block[..8].copy_from_slice(&((associated_data.len() as u64) * 8).to_be_bytes());

        block[8..].copy_from_slice(&((buffer.len() as u64) * 8).to_be_bytes());

        hasher.update(&[block]);

        let mut tag = hasher.finalize();

        tag.as_mut_slice()
            .iter_mut()
            .zip(mask.as_slice())
            .for_each(|(x, y)| {
                *x ^= *y;
            });

        tag
    }
}

//https://github.com/RustCrypto/AEADs/blob/da7afb36855df5c69acae08d9b74c47cb55fbd6a/aes-gcm/src/lib.rs#L261
impl<C, N, T> AeadInPlace for AesPoly1305<C, N, T>
where
    C: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
    N: ArrayLength<u8>,
    T: ArrayLength<u8> + Unsigned,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Result<aead::Tag<Self>> {
        let (ctr, mask) = self.init_ctr(nonce);

        ctr.apply_keystream_partial(buffer.into());

        Ok(GenericArray::clone_from_slice(
            &self.compute_tag(mask, associated_data, buffer)[..T::to_usize()],
        ))
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &aead::Tag<Self>,
    ) -> aead::Result<()> {
        let (ctr, mask) = self.init_ctr(nonce);

        let expected_tag = self.compute_tag(mask, associated_data, buffer);

        ctr.apply_keystream_partial(buffer.into());

        match expected_tag[..T::to_usize()].ct_eq(tag).into() {
            true => Ok(()),
            false => Err(aead::Error),
        }
    }
}

type Aes128Poly1305 = AesPoly1305<Aes128, U12>;
type Aes192Poly1305 = AesPoly1305<Aes192, U12>;
type Aes256Poly1305 = AesPoly1305<Aes256, U12>;

fn main() {}
