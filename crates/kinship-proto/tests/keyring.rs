//! Runtime changes to a codec's keys: install, use and remove, and every refusal.

use kinship_proto::{
    Codec, DecodeError, Key, KeyId, KeyringError, Limits, Message, PacketKind, Payload,
};

fn key(n: u8) -> Key {
    Key::from_bytes([n; 32])
}

fn enc(keys: &[u8]) -> Codec {
    Codec::encrypted(
        b"c",
        Limits::default(),
        keys.iter().map(|&n| key(n)).collect(),
    )
    .unwrap()
}

fn seal(codec: &Codec) -> Vec<u8> {
    let mut out = Vec::new();
    codec
        .seal(
            PacketKind::Datagram,
            &[Message::Ack { seq: 1 }],
            &[5; 24],
            &mut out,
        )
        .unwrap();
    out
}

fn opens(codec: &Codec, packet: &[u8]) -> Result<(), DecodeError> {
    let mut buf = packet.to_vec();
    codec
        .open(PacketKind::Datagram, &mut buf)
        .map(|_: Payload<'_>| ())
}

fn ids(codec: &Codec) -> Vec<KeyId> {
    codec.key_ids()
}

#[test]
fn install_adds_a_key_that_opens_but_does_not_seal() {
    let mut codec = enc(&[1]);
    let before = seal(&codec);
    codec.install_key(key(2)).unwrap();
    assert_eq!(ids(&codec), [key(1).key_id(), key(2).key_id()]);
    assert_eq!(seal(&codec), before, "the sealing key did not change");
    assert!(opens(&codec, &seal(&enc(&[2]))).is_ok());
}

#[test]
fn install_twice_changes_nothing() {
    let mut codec = enc(&[1]);
    codec.install_key(key(2)).unwrap();
    codec.install_key(key(2)).unwrap();
    codec.install_key(key(1)).unwrap();
    assert_eq!(ids(&codec), [key(1).key_id(), key(2).key_id()]);
}

#[test]
fn use_moves_an_installed_key_to_the_front() {
    let mut codec = enc(&[1, 2, 3]);
    codec.use_key(&key(3)).unwrap();
    assert_eq!(
        ids(&codec),
        [key(3).key_id(), key(1).key_id(), key(2).key_id()]
    );
    assert_eq!(seal(&codec), seal(&enc(&[3])), "the new key seals");
    assert!(opens(&codec, &seal(&enc(&[1]))).is_ok(), "old keys open");
    // Using the key already in use is fine.
    codec.use_key(&key(3)).unwrap();
    assert_eq!(ids(&codec)[0], key(3).key_id());
}

#[test]
fn remove_drops_a_spare_key() {
    let mut codec = enc(&[1, 2]);
    codec.remove_key(&key(2)).unwrap();
    assert_eq!(ids(&codec), [key(1).key_id()]);
    assert!(matches!(
        opens(&codec, &seal(&enc(&[2]))),
        Err(DecodeError::UnknownKey(_))
    ));
}

#[test]
fn remove_of_an_unknown_key_is_already_done() {
    let mut codec = enc(&[1]);
    codec.remove_key(&key(9)).unwrap();
    assert_eq!(ids(&codec), [key(1).key_id()]);
}

#[test]
fn use_refuses_a_key_that_is_not_installed() {
    let mut codec = enc(&[1]);
    assert_eq!(codec.use_key(&key(2)), Err(KeyringError::NotInstalled));
    assert_eq!(ids(&codec), [key(1).key_id()]);
}

#[test]
fn remove_refuses_the_key_in_use() {
    let mut codec = enc(&[1, 2]);
    assert_eq!(codec.remove_key(&key(1)), Err(KeyringError::InUse));
    assert_eq!(ids(&codec), [key(1).key_id(), key(2).key_id()]);
}

#[test]
fn remove_refuses_the_last_key() {
    let mut codec = enc(&[1]);
    assert_eq!(codec.remove_key(&key(1)), Err(KeyringError::LastKey));
    assert_eq!(ids(&codec), [key(1).key_id()]);
}

#[test]
fn a_plaintext_codec_refuses_all_of_it() {
    let mut codec = Codec::insecure_plaintext(b"c", Limits::default()).unwrap();
    assert_eq!(codec.install_key(key(1)), Err(KeyringError::Plaintext));
    assert_eq!(codec.use_key(&key(1)), Err(KeyringError::Plaintext));
    assert_eq!(codec.remove_key(&key(1)), Err(KeyringError::Plaintext));
    assert!(codec.key_ids().is_empty());
    assert!(!codec.is_encrypted());
}

#[test]
fn key_ids_print_as_eight_hex_characters() {
    let id = KeyId::from_raw(0x00ab_cdef);
    assert_eq!(id.to_string(), "00abcdef");
    assert_eq!(format!("{id:?}"), "KeyId(00abcdef)");
    assert_eq!(key(1).key_id().to_string().len(), 8);
}
