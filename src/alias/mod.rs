/// Stores the various datatypes required to manage aliases
/// 

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub(crate) struct AliasId(u64);

impl AliasId {
	pub fn generate() -> Self {
		AliasId(rand::random())
	}
}


mod alias;
pub(crate) use alias::{*};

use crate::id::ChordPublicKey;
pub(crate) mod manager;
mod listen_handle;

mod listen_path;
