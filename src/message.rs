use std::{
    io::{Read, Cursor, Seek, Write},
    marker::PhantomData,
    net::SocketAddr,
    str::FromStr
};

use anyhow::{anyhow, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use bytes::{Buf, BufMut, BytesMut};
use snarkvm::{
    dpc::{testnet2::Testnet2, Address, BlockTemplate, PoSWProof},
    traits::Network,
    utilities::{FromBytes, ToBytes},
};
use tokio_util::codec::{Decoder, Encoder};
use serde_json;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum Code {
    Success = 0,
    InvalidProof,
    Stale,
    ProxyException
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ProverMessage {
    // as in stratum, with an additional protocol version field
    /// Authorize := (account, worker, password, version)
    Authorize(String, String, String, u16),
    AuthorizeResult(bool, Option<String>),
    // combine notify and pool_target to be consistent
    Notify(BlockTemplate<Testnet2>, u64),
    // include block height to detect stales faster
    Submit(u32, <Testnet2 as Network>::PoSWNonce, PoSWProof<Testnet2>),
    // miners might want to know the stale rate, optionally provide a message
    /// SubmitResult := (code, reason)
    SubmitResult(Code, Option<String>),
    /// ProofRate := (p/s * 100)
    ProofRate(u64),

    Canary,
}

#[allow(dead_code)]
static VERSION: u16 = 1;

impl ProverMessage {
    #[allow(dead_code)]
    pub fn version() -> &'static u16 {
        &VERSION
    }

    pub fn id(&self) -> u8 {
        match self {
            ProverMessage::Authorize(..) => 0,
            ProverMessage::AuthorizeResult(..) => 1,
            ProverMessage::Notify(..) => 2,
            ProverMessage::Submit(..) => 3,
            ProverMessage::SubmitResult(..) => 4,
            ProverMessage::ProofRate(..) => 6,

            ProverMessage::Canary => 5,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ProverMessage::Authorize(..) => "Authorize",
            ProverMessage::AuthorizeResult(..) => "AuthorizeResult",
            ProverMessage::Notify(..) => "Notify",
            ProverMessage::Submit(..) => "Submit",
            ProverMessage::SubmitResult(..) => "SubmitResult",
            ProverMessage::ProofRate(..) => "ProofRate",

            ProverMessage::Canary => "Canary",
        }
    }

    #[inline]
    pub fn serialize_into<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Self::Authorize(account, worker, password, version) => {
                bincode::serialize_into(&mut *writer, &account)?;
                bincode::serialize_into(&mut *writer, &worker)?;
                bincode::serialize_into(&mut *writer, &password)?;
                let version = version.to_string();
                bincode::serialize_into(&mut *writer, &version)?;
                Ok(())
            }
            Self::AuthorizeResult(result, message) => {
                writer.write_all(&[match result {
                    true => 1,
                    false => 0,
                }])?;
                if let Some(message) = message {
                    writer.write_all(&[1])?;
                    bincode::serialize_into(&mut *writer, &message)?;
                } else {
                    writer.write_all(&[0])?;
                }
                Ok(())
            }
            Self::Notify(template, pool_target) => {
                template.write_le(&mut *writer)?;
                writer.write_all(&pool_target.to_le_bytes())?;
                Ok(())
            }
            Self::Submit(height, nonce, proof) => {
                writer.write_all(&height.to_le_bytes())?;
                nonce.write_le(&mut *writer)?;
                proof.write_le(&mut *writer)?;
                Ok(())
            }
            Self::ProofRate(proof_rate) => {
                writer.write_all(&proof_rate.to_le_bytes())?;
                Ok(())
            }
            Self::SubmitResult(code, message) => {
                bincode::serialize_into(&mut *writer, &code)?;
                if let Some(message) = message {
                    writer.write_all(&[1])?;
                    bincode::serialize_into(&mut *writer, &message)?;
                } else {
                    writer.write_all(&[0])?;
                }
                Ok(())
            }
            Self::Canary => Ok(()),
        }
    }

    #[inline]
    pub fn serialize_into_json<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Self::Authorize(account, worker, password, version) => {
                let version = version.to_string();
                serde_json::to_writer(writer, &(account, worker, password, version))?;
                Ok(())
            }
            Self::AuthorizeResult(result, message) => {
                writer.write_all(&[match result {
                    true => 1,
                    false => 0,
                }])?;
                if let Some(message) = message {
                    writer.write_all(&[1])?;
                    serde_json::to_writer(&mut *writer, message)?;
                } else {
                    writer.write_all(&[0])?;
                }
                Ok(())
            }
            Self::Notify(template, pool_target) => {
                serde_json::to_writer(&mut *writer, &(template, pool_target))?;
                Ok(())
            }
            Self::Submit(height, nonce, proof) => {
                serde_json::to_writer(&mut *writer, &(height, nonce, proof))?;
                Ok(())
            }
            Self::ProofRate(proof_rate) => {
                serde_json::to_writer(&mut *writer, &proof_rate)?;
                Ok(())
            }
            Self::SubmitResult(code, message) => {
                serde_json::to_writer(&mut *writer, code)?;
                if let Some(message) = message {
                    writer.write_all(&[1])?;
                    serde_json::to_writer(&mut *writer, message)?;
                } else {
                    writer.write_all(&[0])?;
                }
                Ok(())
            }
            Self::Canary => Ok(()),
        }
    }

    #[inline]
    pub fn deserialize<R: Read + Seek>(reader: &mut R) -> Result<Self> {
        let msg_id = reader.read_u8()?;

        let message = match msg_id {
            0 => {
                let account = bincode::deserialize_from(&mut *reader)?;
                let worker = bincode::deserialize_from(&mut *reader)?;
                let password = bincode::deserialize_from(&mut *reader)?;
                let version: String = bincode::deserialize_from(&mut *reader)?;
                Self::Authorize(account, worker, password, version.parse::<u16>().unwrap())
            }
            1 => {
                let result = reader.read_u8()? == 1;
                let message = if reader.read_u8()? == 1 {
                    Some(bincode::deserialize_from(reader)?)
                } else {
                    None
                };
                Self::AuthorizeResult(result, message)
            }
            2 => {
                let template = BlockTemplate::<Testnet2>::read_le(&mut *reader)?;
                let pool_target = reader.read_u64::<LittleEndian>()?;
                Self::Notify(template, pool_target)
            }
            3 => {
                let height = reader.read_u32::<LittleEndian>()?;
                let nonce = <Testnet2 as Network>::PoSWNonce::read_le(&mut *reader)?;
                let proof = PoSWProof::<Testnet2>::read_le(&mut *reader)?;
                Self::Submit(height, nonce, proof)
            }
            4 => {
                let code = bincode::deserialize_from(&mut *reader)?;
                let message = if reader.read_u8()? == 1 {
                    Some(bincode::deserialize_from(reader)?)
                } else {
                    None
                };
                Self::SubmitResult(code, message)
            }
            _ => {
                return Err(anyhow!("Unknown message id: {}", msg_id));
            }
        };

        Ok(message)
    }

    #[inline]
    pub fn deserialize_json<R: Read + Seek>(reader: &mut R) -> Result<Self> {
        let msg_id = reader.read_u8()?;

        let message = match msg_id {
            0 => {
                let (account, worker, password, version): (String, String, String, String) = serde_json::from_reader(&mut *reader)?;
                let version = u16::from_str(&version).unwrap();
                Self::Authorize(account, worker, password, version)
            }
            1 => {
                let result = reader.read_u8()? == 1;
                let message = if reader.read_u8()? == 1 {
                    Some(serde_json::from_reader(&mut *reader)?)
                } else {
                    None
                };
                Self::AuthorizeResult(result, message)
            }
            2 => {
                let (template, pool_target) = serde_json::from_reader(&mut *reader)?;
                Self::Notify(template, pool_target)
            }
            3 => {
                let (height, nonce, proof) = serde_json::from_reader(&mut *reader)?;
                Self::Submit(height, nonce, proof)
            }
            4 => {
                let code = serde_json::from_reader(&mut *reader)?;
                let message = if reader.read_u8()? == 1 {
                    Some(serde_json::from_reader(&mut *reader)?)
                } else {
                    None
                };
                Self::SubmitResult(code, message)
            }
            _ => {
                return Err(anyhow!("Unknown message id: {}", msg_id));
            }
        };

        Ok(message)
    }
}

impl Encoder<ProverMessage> for ProverMessage {
    type Error = anyhow::Error;

    fn encode(&mut self, item: ProverMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&0u32.to_le_bytes());

        let mut writer = dst.writer();
        writer.write_all(&[item.id()])?;

        match item {
            ProverMessage::ProofRate(..) => item.serialize_into(&mut writer)?,
            _ => item.serialize_into_json(&mut writer)?
        }

        let msg_len = dst.len() - 4;
        dst[..4].copy_from_slice(&(msg_len as u32).to_le_bytes());

        #[cfg(debug_assertions)]
        println!("Encode {}: {:?}", item.name(), dst);

        Ok(())
    }
}

impl Decoder for ProverMessage {
    type Error = anyhow::Error;
    type Item = ProverMessage;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }
        let length = u32::from_le_bytes(src[..4].try_into().unwrap()) as usize;
        if length > 128 * 1024 * 1024 { // 128 Mib
            return Err(anyhow!("Message too long"));
        }
        if src.len() < 4 + length {
            return Ok(None);
        }

        let msg_id = u8::from_le_bytes(src[4..5].try_into().unwrap()) as usize;
        let msg = match msg_id {
            4 => match ProverMessage::deserialize(&mut Cursor::new(&src[4..][..length])) {
                Ok(msg) => Ok(Some(msg)),
                Err(error) => Err(anyhow!(error)),
            }
            _ => match ProverMessage::deserialize_json(&mut Cursor::new(&src[4..][..length])) {
                Ok(msg) => Ok(Some(msg)),
                Err(error) => Err(anyhow!(error)),
            }
        };

        src.advance(4 + length);
        
        msg
    }
}
