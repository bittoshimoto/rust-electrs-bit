// SPDX-License-Identifier: CC0-1.0

//! Blockdata constants matching chainparams.cpp exactly.

use core::default::Default;

use hashes::{sha256d, Hash};
use hex_lit::hex;
use internals::impl_array_newtype;

use crate::blockdata::block::{self, Block};
use crate::blockdata::locktime::absolute;
use crate::blockdata::opcodes::all::*;
use crate::blockdata::script;
use crate::blockdata::transaction::{self, OutPoint, Sequence, Transaction, TxIn, TxOut};
use crate::blockdata::witness::Witness;
use crate::hash_types::TxMerkleNode;
use crate::internal_macros::impl_bytes_newtype;
use crate::network::Network;
use crate::pow::CompactTarget;
use crate::Amount;

/// How many seconds between blocks we expect on average.
pub const TARGET_BLOCK_SPACING: u32 = 60;
/// How many blocks between diffchanges.
pub const DIFFCHANGE_INTERVAL: u32 = 1;
/// How much time on average should occur between diffchanges.
pub const DIFFCHANGE_TIMESPAN: u32 = 60;

#[deprecated(since = "0.31.0", note = "Use Weight::MAX_BLOCK instead")]
pub const MAX_BLOCK_WEIGHT: u32 = 10_000_000;
#[deprecated(since = "0.31.0", note = "Use Weight::MIN_TRANSACTION instead")]
pub const MIN_TRANSACTION_WEIGHT: u32 = 4 * 60;

pub const WITNESS_SCALE_FACTOR: usize = 4;
pub const MAX_BLOCK_SIGOPS_COST: i64 = 80_000;

/// Mainnet pubkey address prefix ('B').
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 25; // 'B'
/// Mainnet script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 22; // 0x16
/// Testnet pubkey address prefix ('T').
pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 65; // 'T'
/// Testnet script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 196; // 0xc4
/// Regtest pubkey address prefix ('R').
pub const PUBKEY_ADDRESS_PREFIX_REGTEST: u8 = 61; // 'R'

pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
pub const SUBSIDY_HALVING_INTERVAL: u32 = 210_000;
pub const MAX_SCRIPTNUM_VALUE: u32 = 0x80000000;
pub const COINBASE_MATURITY: u32 = 240;

fn bitcoin_genesis_tx() -> Transaction {
    let mut ret = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    let in_script = script::Builder::new()
        .push_int(486604799)
        .push_int_non_minimal(4)
        .push_slice(b"Follow The White Rabbit")
        .into_script();
    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: in_script,
        sequence: Sequence::MAX,
        witness: Witness::default(),
    });

    let out_script = script::Builder::new()
        .push_slice(hex!(
            "042e8ae07eee20bacb42b873bb1e9f7c507089d1826de4eaed5109a238a1f329df87c5dc06d3fe1c7cb4f6d8325ea333f3a2519cdcd4327ce240da348a257f6585"
        ))
        .push_opcode(OP_CHECKSIG)
        .into_script();
    ret.output.push(TxOut { value: Amount::from_sat(5 * 100_000_000), script_pubkey: out_script });

    ret
}

pub fn genesis_block(network: Network) -> Block {
    let txdata = vec![bitcoin_genesis_tx()];
    let merkle_root = TxMerkleNode::from_slice(
        &hex!("486770e6985452307f42a711d2cd9d2e35fe2a2da0737da92616e2d3a0a97aa9")
    ).unwrap();

    match network {
        Network::Bitcoin => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1751109927,
                bits: CompactTarget::from_consensus(0x1e0ffff0),
                nonce: 411785,
                aux_data: None,
            },
            txdata,
        },
        Network::Testnet => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1751110035,
                bits: CompactTarget::from_consensus(0x1e0ffff0),
                nonce: 916278,
                aux_data: None,
            },
            txdata,
        },
        Network::Regtest => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: Hash::all_zeros(),
                merkle_root,
                time: 1751110269,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 1,
                aux_data: None,
            },
            txdata,
        },
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainHash([u8; 32]);
impl_array_newtype!(ChainHash, u8, 32);
impl_bytes_newtype!(ChainHash, 32);

impl ChainHash {
    pub const BITCOIN: Self = Self([98, 152, 37, 130, 36, 154, 4, 172, 40, 18, 1, 254, 92, 113, 123, 205, 222, 29, 85, 44, 62, 142, 67, 150, 122, 139, 214, 93, 75, 249, 110, 69]);
    pub const TESTNET: Self = Self([171, 195, 25, 185, 73, 227, 37, 125, 127, 196, 113, 203, 51, 108, 136, 14, 119, 147, 129, 47, 98, 160, 171, 15, 246, 113, 159, 115, 112, 174, 215, 119]);
    pub const REGTEST: Self = Self([102, 59, 76, 100, 236, 90, 252, 94, 153, 94, 94, 224, 115, 50, 32, 131, 22, 141, 229, 34, 206, 210, 179, 137, 188, 243, 157, 187, 109, 95, 242, 228]);

    pub const fn using_genesis_block(network: Network) -> Self {
        let hashes = [Self::BITCOIN, Self::TESTNET, Self::REGTEST];
        hashes[network as usize]
    }

    pub fn from_genesis_block_hash(block_hash: crate::BlockHash) -> Self {
        ChainHash(block_hash.to_byte_array())
    }
}


#[cfg(test)]
mod test {
    use core::str::FromStr;

    use hex::test_hex_unwrap as hex;

    use super::*;
    use crate::blockdata::locktime::absolute;
    use crate::blockdata::transaction;
    use crate::consensus::encode::serialize;
    use crate::network::Network;

    #[test]
    fn bitcoin_genesis_first_transaction() {
        let gen = bitcoin_genesis_tx();

        assert_eq!(gen.version, transaction::Version::ONE);
        assert_eq!(gen.input.len(), 1);
        assert_eq!(gen.input[0].previous_output.txid, Hash::all_zeros());
        assert_eq!(gen.input[0].previous_output.vout, 0xFFFFFFFF);
        assert_eq!(serialize(&gen.input[0].script_sig),
                   hex!("1f04ffff001d010417466f6c6c6f772054686520576869746520526162626974"));

        assert_eq!(gen.input[0].sequence, Sequence::MAX);
        assert_eq!(gen.output.len(), 1);
        assert_eq!(serialize(&gen.output[0].script_pubkey),
                   hex!("4341042e8ae07eee20bacb42b873bb1e9f7c507089d1826de4eaed5109a238a1f329df87c5dc06d3fe1c7cb4f6d8325ea333f3a2519cdcd4327ce240da348a257f6585ac"));
        assert_eq!(gen.output[0].value, Amount::from_str("5 BTC").unwrap());
        assert_eq!(gen.lock_time, absolute::LockTime::ZERO);

        assert_eq!(
            gen.wtxid().to_string(),
            "a97aa9a0d3e21626a97d73a02d2afe352e9dcdd211a7427f30525498e6706748"
        );
    }

    #[test]
    fn bitcoin_genesis_full_block() {
        let gen = genesis_block(Network::Bitcoin);

        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(
            gen.header.merkle_root.to_string(),
            "a97aa9a0d3e21626a97d73a02d2afe352e9dcdd211a7427f30525498e6706748"
        );

        assert_eq!(gen.header.time, 1751109927);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1e0ffff0));
        assert_eq!(gen.header.nonce, 411785);
        assert_eq!(
            gen.header.block_hash().to_string(),
            "456ef94b5dd68b7a96438e3e2c551ddecd7b715cfe011228ac049a2482259862"
        );
    }

    #[test]
    fn testnet_genesis_full_block() {
        let gen = genesis_block(Network::Testnet);
        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(
            gen.header.merkle_root.to_string(),
            "a97aa9a0d3e21626a97d73a02d2afe352e9dcdd211a7427f30525498e6706748"
        );
        assert_eq!(gen.header.time, 1751110035);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1e0ffff0));
        assert_eq!(gen.header.nonce, 916278);
        assert_eq!(
            gen.header.block_hash().to_string(),
            "77d7ae70739f71f60faba0622f8193770e886c33cb71c47f7d25e349b919c3ab"
        );
    }


    // The *_chain_hash tests are sanity/regression tests, they verify that the const byte array
    // representing the genesis block is the same as that created by hashing the genesis block.
    fn chain_hash_and_genesis_block(network: Network) {
        use hashes::sha256;

        // The genesis block hash is a double-sha256 and it is displayed backwards.
        let genesis_hash = genesis_block(network).block_hash();
        // We abuse the sha256 hash here so we get a LowerHex impl that does not print the hex backwards.
        let hash = sha256::Hash::from_slice(genesis_hash.as_byte_array()).unwrap();
        let want = format!("{:02x}", hash);

        let chain_hash = ChainHash::using_genesis_block(network);
        let got = format!("{:02x}", chain_hash);

        // Compare strings because the spec specifically states how the chain hash must encode to hex.
        assert_eq!(got, want);

        #[allow(unreachable_patterns)] // This is specifically trying to catch later added variants.
        match network {
            Network::Bitcoin => {},
            Network::Testnet => {},
            Network::Regtest => {},
            _ => panic!("Update ChainHash::using_genesis_block and chain_hash_genesis_block with new variants"),
        }
    }

    macro_rules! chain_hash_genesis_block {
        ($($test_name:ident, $network:expr);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    chain_hash_and_genesis_block($network);
                }
            )*
        }
    }

    chain_hash_genesis_block! {
        mainnet_chain_hash_genesis_block, Network::Bitcoin;
        testnet_chain_hash_genesis_block, Network::Testnet;
        regtest_chain_hash_genesis_block, Network::Regtest;
    }

    // Test vector aligned with our chain's mainnet genesis.
    #[test]
    fn mainnet_chain_hash_test_vector() {
        let got = ChainHash::using_genesis_block(Network::Bitcoin).to_string();
        let want = "62982582249a04ac281201fe5c717bcdde1d552c3e8e43967a8bd65d4bf96e45";
        assert_eq!(got, want);
    }
}
