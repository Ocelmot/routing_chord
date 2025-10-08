use std::{num::NonZeroUsize, path::PathBuf, time::Duration};

use lru::LruCache;
use serde::{self, ser::SerializeTuple, Deserialize, Deserializer, Serialize, Serializer};
use tokio::fs;

use crate::{
    error::{ChordResult, ErrorKind, ProblemWrap}, id::LOCATION_BYTE_SIZE, processor::ChordProcessor, ChordHandle
};

static DEFAULT_LISTEN: &str = "0.0.0.0:1931";
static DEFAULT_STABILIZE_INTERVAL: Duration = Duration::from_secs(30);
static DEFAULT_FIX_FINGERS_INTERVAL: Duration = Duration::from_secs(30);
static DEFAULT_CHECK_PREDECESSOR_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Serialize, Deserialize)]
pub struct ChordState {
    #[serde(skip)]
    path: Option<PathBuf>,
    /// The address to bind the listener to
    listen_addr: String,
    stabilize_interval: Duration,
    fix_fingers_interval: Duration,
    check_predecessor_interval: Duration,
    
    /// list of known chord addrs for reconnection
    #[serde(
        skip_serializing_if = "LruCache::is_empty",
        default = "default_lru",
        serialize_with = "serialize_lru",
        deserialize_with = "deserialize_lru"
    )]
    chord_addrs: LruCache<String, ()>,
}

impl ChordState {
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        let mut state = Self::temp();
        state.path = Some(path.into());
        state
    }

    pub fn temp() -> Self {
        Self {
            path: None,
            listen_addr: String::from(DEFAULT_LISTEN),
            stabilize_interval: DEFAULT_STABILIZE_INTERVAL,
            fix_fingers_interval: DEFAULT_FIX_FINGERS_INTERVAL,
            check_predecessor_interval: DEFAULT_CHECK_PREDECESSOR_INTERVAL,
            chord_addrs: default_lru()
        }
    }

    pub async fn load<P: Into<PathBuf>>(path: P) -> ChordResult<Self> {
        let path = path.into();
        let state = fs::read_to_string(&path)
            .await
            .problem_wrap(ErrorKind::LoadFailure)?;
        let mut state: ChordState =
            serde_json::from_str(&state).problem_wrap(ErrorKind::LoadFailure)?;
        state.path = Some(path);
        Ok(state)
    }

    pub async fn save(&self) -> ChordResult {
        if let Some(path) = &self.path {
            let data = serde_json::to_string_pretty(self).problem_wrap(ErrorKind::SaveFailure)?;
            fs::write(path, data).await?;
        }
        Ok(())
    }

    // getters, setters
    pub fn path(&self) -> Option<&PathBuf> {
        self.path.as_ref()
    }

    pub fn listen_addr(&self) -> &String {
        &self.listen_addr
    }

    pub fn set_listen_addr<S: Into<String>>(&mut self, listen_addr: S) {
        self.listen_addr = listen_addr.into();
    }

    pub fn stabilize_interval(&self) -> &Duration {
        &self.stabilize_interval
    }

    pub fn set_stabilize_interval(&mut self, interval: Duration) {
        self.stabilize_interval = interval;
    }

    pub fn fix_fingers_interval(&self) -> &Duration {
        &self.fix_fingers_interval
    }

    pub fn set_fix_fingers_interval(&mut self, interval: Duration) {
        self.fix_fingers_interval = interval;
    }

    pub fn check_predecessor_interval(&self) -> &Duration {
        &self.check_predecessor_interval
    }

    pub fn set_predecessor_interval(&mut self, interval: Duration) {
        self.check_predecessor_interval = interval;
    }

    pub fn chord_addrs(&self) -> impl Iterator<Item = &String>{
        self.chord_addrs.iter().map(|(addr, _)| addr)
    }

    pub fn resize_chord_addrs(&mut self, cap: NonZeroUsize) {
        self.chord_addrs.resize(cap);
    }

    pub fn insert_chord_addr(&mut self, addr: String) {
        self.chord_addrs.push(addr, ());
    }

    // Start, etc
    pub fn host(self) -> ChordResult<ChordHandle> {
        ChordProcessor::host(self)
    }
    pub async fn join(self, join_addrs: Vec<String>) -> ChordResult<ChordHandle> {
        ChordProcessor::join(self, join_addrs).await
    }
    pub async fn join_or_host(self, join_addrs: Vec<String>) -> ChordResult<ChordHandle> {
        ChordProcessor::join_or_host(self, join_addrs).await
    }
}


fn default_lru() -> LruCache<String, ()> {
    LruCache::new(NonZeroUsize::new(LOCATION_BYTE_SIZE * 3).unwrap())
}

fn deserialize_lru<'de, D>(deserializer: D) -> Result<LruCache<String, ()>, D::Error>
where
    D: Deserializer<'de>,
{
    let data: (usize, Vec<String>) = Deserialize::deserialize(deserializer)?;

    let cap = NonZeroUsize::new(data.0).ok_or(serde::de::Error::invalid_value(
        serde::de::Unexpected::Unsigned(data.0 as u64),
        &"lru must have a non-zero length",
    ))?;

    let mut lru = LruCache::new(cap);
    for item in data.1.into_iter().rev() {
        lru.push(item, ());
    }

    Ok(lru)
}

fn serialize_lru<S>(lru: &LruCache<String, ()>, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer{
    let mut tup = serializer.serialize_tuple(2)?;
    tup.serialize_element(&lru.len())?;
    let mut vec = Vec::with_capacity(lru.len());
    for (item, _) in lru {
        vec.push(item);
    }
    tup.serialize_element(&vec)?;
    tup.end()
}