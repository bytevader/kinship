/// Size limits enforced by the codec, matching the `udp_max_payload`, `max_stream_frame` and
/// `max_meta_bytes` config fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Limits {
    /// Largest datagram, header and tag included.
    pub udp_max_payload: usize,
    /// Largest stream frame, header and tag included, excluding the 4-byte length prefix.
    pub max_stream_frame: usize,
    /// Largest metadata blob in an Alive record.
    pub max_meta_bytes: usize,
}

impl Limits {
    pub const DEFAULT_UDP_MAX_PAYLOAD: usize = 1400;
    pub const DEFAULT_MAX_STREAM_FRAME: usize = 8 * 1024 * 1024;
    pub const DEFAULT_MAX_META_BYTES: usize = 512;
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            udp_max_payload: Self::DEFAULT_UDP_MAX_PAYLOAD,
            max_stream_frame: Self::DEFAULT_MAX_STREAM_FRAME,
            max_meta_bytes: Self::DEFAULT_MAX_META_BYTES,
        }
    }
}
