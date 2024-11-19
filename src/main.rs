use aes::Aes128;
use bluer::{gatt::remote::Characteristic, AdapterEvent, Address, Device, Result};
use ccm::{
    aead::{generic_array::GenericArray, Aead, Buffer},
    consts::{U12, U4},
    Ccm,
};
use futures::{pin_mut, Stream, StreamExt};
use prost::Message as _;
use std::time::Duration;
use tokio::time::sleep;
use uuid::{uuid, Uuid};

use hmac::{Hmac, Mac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;
type Aes128Ccm = Ccm<Aes128, U4, U12>;

mod protocol;

const SERVICE_UUID: Uuid = uuid!("0000fe95-0000-1000-8000-00805f9b34fb");

const READ_UUID: Uuid = uuid!("00000051-0000-1000-8000-00805f9b34fb");
const WRITE_UUID: Uuid = uuid!("00000052-0000-1000-8000-00805f9b34fb");
const _: Uuid = uuid!("00000053-0000-1000-8000-00805f9b34fb");
const _: Uuid = uuid!("00000055-0000-1000-8000-00805f9b34fb");

const SECRET_KEY: [u8; 16] = [
    0x37, 0x95, 0x61, 0xdf, 0xa6, 0x36, 0x99, 0xda, 0x5d, 0xaf, 0x61, 0x1e, 0x10, 0x68, 0xf8, 0x54
];
const NONCE: [u8; 16] = [
    140, 210, 82, 3, 45, 85, 214, 149, 233, 195, 235, 140, 127, 46, 186, 180,
];

fn phone_nonce_cmd(nonce: Vec<u8>) -> protocol::Command {
    protocol::Command {
        r#type: 1,
        subtype: Some(26),
        auth: Some(protocol::Auth {
            user_id: None,
            status: None,
            phone_nonce: Some(protocol::PhoneNonce { nonce }),
            watch_nonce: None,
            auth_step3: None,
            auth_step4: None,
        }),
        system: None,
        watchface: None,
        health: None,
        calendar: None,
        music: None,
        notification: None,
        weather: None,
        schedule: None,
        phonebook: None,
        data_upload: None,
        status: None,
    }
}

fn auth_step3_cmd(encrypted_nonces: Vec<u8>, encrypted_device_info: Vec<u8>) -> protocol::Command {
    protocol::Command {
        r#type: 1,
        subtype: Some(27),
        auth: Some(protocol::Auth {
            user_id: None,
            status: None,
            phone_nonce: None,
            watch_nonce: None,
            auth_step3: Some(protocol::AuthStep3 {
                encrypted_nonces,
                encrypted_device_info,
            }),
            auth_step4: None,
        }),
        system: None,
        watchface: None,
        health: None,
        calendar: None,
        music: None,
        notification: None,
        weather: None,
        schedule: None,
        phonebook: None,
        data_upload: None,
        status: None,
    }
}

fn find_device_cmd() -> protocol::Command {
    protocol::Command {
        r#type: 2,
        subtype: Some(18),
        auth: None,
        system: Some(protocol::System {
            power: None,
            device_info: None,
            clock: None,
            find_device: Some(0),
            display_items: None,
            dnd_status: None,
            workout_types: None,
            firmware_install_request: None,
            firmware_install_response: None,
            password: None,
            camera: None,
            language: None,
            widget_screens: None,
            widget_parts: None,
            misc_setting_get: None,
            misc_setting_set: None,
            phone_silent_mode_get: None,
            phone_silent_mode_set: None,
            vibration_patterns: None,
            vibration_set_preset: None,
            vibration_pattern_create: None,
            vibration_test_custom: None,
            vibration_pattern_ack: None,
            basic_device_state: None,
            device_state: None,
        }),
        watchface: None,
        health: None,
        calendar: None,
        music: None,
        notification: None,
        weather: None,
        schedule: None,
        phonebook: None,
        data_upload: None,
        status: None,
    }
}

#[derive(Debug)]
struct MiBand8Device {
    read: Characteristic,
    write: Characteristic,
}

async fn find_our_characteristic(device: &Device) -> Result<Option<MiBand8Device>> {
    let uuids = device.uuids().await?.unwrap_or_default();
    println!("{:?}", uuids);

    if uuids.contains(&SERVICE_UUID) {
        println!("    Device provides our service!");
        println!("    Connected: {}", device.is_connected().await?);

        // if !device.is_connected().await? {
        //     device.connect().await?;
        // }
        // println!("    Connected: {}", device.is_connected().await?);

        for service in device.services().await? {
            let uuid = service.uuid().await?;
            if uuid == SERVICE_UUID {
                let mut read = None;
                let mut write = None;
                for char in service.characteristics().await? {
                    let uuid = char.uuid().await?;
                    if uuid == READ_UUID {
                        read = Some(char);
                    } else if uuid == WRITE_UUID {
                        write = Some(char);
                    }
                }
                return Ok(Some(MiBand8Device {
                    read: read.unwrap(),
                    write: write.unwrap(),
                }));
            }
        }
    } else {
        println!("Service UUID Not found!")
    }

    Ok(None)
}

const AUTH_STEP_1_REQUEST: &str = "0801101A1A15F201120A108CD252032D55D695E9C3EB8C7F2EBAB4";

// const AUTH_STEP_1_REQUEST: [u8; 27] = [
//     0x08, 0x01, 0x10, 0x1a, 0x1a, 0x15, 0xf2, 0x01, 0x12, 0x0a, 0x10, 0x8c, 0xd2, 0x52, 0x03, 0x2d,
//     0x55, 0xd6, 0x95, 0xe9, 0xc3, 0xeb, 0x8c, 0x7f, 0x2e, 0xba, 0xb4,
// ];
const AUTH_STEP_1_RESPONSE: &str=  "0801101A1A37FA01340A1002FAAC759395FB5F265110E137F967431220EF1A6C2F6756ED69DA3BA1EB23A05CBD6975E4D37E1C4F543711C6B16A0418CB";
const AUTH_STEP_2_REQUEST: &str = "0801101B1A4282023F0A204C590B85E2D8D8A24A3D2FF64F63899F10E40E0D1E6EC1265D106300813C5CC4121B5B8712F82727ED9CC6E04F4D3BCFBCEE884C004DE9479B56CF7B44";
const AUTH_STEP_2_RESPONSE: &str = "0801101B1A098A0206080110BFFE01";

const SOME_REQUEST: &str = "08021003222D222B0A0708E80F1005181E120908121019182A20CD021A13080810081A0D4575726F70652F5761727361772000";

const ACK: &[u8] = &[0x00, 0x00, 0x03, 0x00];

use std::num::ParseIntError;

pub fn decode_hex(s: &str) -> std::result::Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn msg_with_header(body: &[u8], encrypted: bool, encrypted_index: u16) -> Vec<u8> {
    let mut buff = Vec::new();
    buff.push(0); // ?
    buff.push(0); // ?

    buff.push(2); // Type command

    if encrypted {
        buff.push(1);
    } else {
        buff.push(2);
    }

    if encrypted {
        buff.extend_from_slice(&encrypted_index.to_le_bytes());
    }

    buff.extend_from_slice(body);
    buff
}

async fn wait_for_ack(mut stream: impl Stream<Item = Vec<u8>> + Unpin) {
    let ack = stream.next().await;
    assert!(ack.as_deref() == Some(ACK));
}

async fn send_ack(char: &Characteristic) -> bluer::Result<()> {
    char.write(ACK).await
}

fn get_msg_ty(bytes: &[u8]) -> u8 {
    bytes[2]
}

fn is_msg_command(bytes: &[u8]) -> bool {
    get_msg_ty(bytes) == 2
}

async fn start(device: MiBand8Device) -> bluer::Result<()> {
    let write_notify = device.write.notify().await?;
    let read_notify = device.read.notify().await?;
    pin_mut!(write_notify, read_notify);

    let msg = phone_nonce_cmd(NONCE.to_vec());
    println!("-> {msg:?}");
    let phone_nonce = NONCE.to_vec();
    let msg = msg.encode_to_vec();
    let msg = msg_with_header(&msg, false, 0);
    device.write.write(&msg).await?;
    wait_for_ack(&mut write_notify).await;

    let res = read_notify.next().await.unwrap();
    assert_eq!(get_msg_ty(&res), 2, "expected command");
    send_ack(&device.read).await?;
    let command = protocol::Command::decode(&res[4..]).unwrap();
    println!("  <- {command:?}");

    let watch_nonce = command.auth.unwrap().watch_nonce.unwrap();
    let watch_hmac = watch_nonce.hmac;
    let watch_nonce = watch_nonce.nonce;

    let output = compute_auth_step3(&phone_nonce, &watch_nonce);
    let (decryption_key, encryption_key, decryption_nonce, encryption_nonce) = unpack_64(&output);

    // auth_sanity_check(&phone_nonce, &watch_nonce, decryption_key, &watch_hmac);

    let encrypted_nonces = {
        let nonce = join_nonce(&phone_nonce, &watch_nonce);
        let mut mac = HmacSha256::new_from_slice(encryption_key).unwrap();
        mac.update(&nonce);
        mac.finalize().into_bytes()
    };

    let encrypted_device_info = encrypted_auth_device_info(encryption_nonce, encryption_key);

    let msg = auth_step3_cmd(encrypted_nonces.to_vec(), encrypted_device_info);
    let msg = msg.encode_to_vec();
    let msg = msg_with_header(&msg, false, 0);
    device.write.write(&msg).await?;
    wait_for_ack(&mut write_notify).await;

    // Finalize

    let res = read_notify.next().await.unwrap();
    assert_eq!(get_msg_ty(&res), 2, "expected command");
    send_ack(&device.read).await?;
    let command = protocol::Command::decode(&res[4..]).unwrap();
    println!("  <- {command:?}");

    // {
    //     let msg = find_device_cmd();
    //     let msg = msg.encode_to_vec();
    // 
    //     let nonce = build_nonce(encryption_nonce, 1);
    //     let nonce = GenericArray::from_slice(&nonce);
    //     let encryption_key = GenericArray::from_slice(encryption_key);
    // 
    //     let cipher: Aes128Ccm = ccm::KeyInit::new(encryption_key);
    //     let plain = msg.as_ref();
    //     let msg = cipher.encrypt(nonce, plain).unwrap();
    // 
    //     let msg = msg_with_header(&msg, true, 1);
    //     device.write.write(&msg).await?;
    //     wait_for_ack(&mut write_notify).await;
    // }

    Ok(())
}

fn join_nonce(phone_nonce: &[u8], watch_nonce: &[u8]) -> Vec<u8> {
    // TODO: Do this on stack
    let mut full_nonce = phone_nonce.to_vec();
    full_nonce.extend(watch_nonce);
    full_nonce
}

fn compute_auth_step3(phone_nonce: &[u8], watch_nonce: &[u8]) -> [u8; 64] {
    let full_nonce = join_nonce(phone_nonce, watch_nonce);

    let mut mac = HmacSha256::new_from_slice(&full_nonce).unwrap();
    mac.update(&SECRET_KEY);
    let hmac_key_bytes = mac.finalize().into_bytes();

    let mut output = [0; 64];
    let mut tmp = vec![];
    let mut b = 1;
    let mut i = 0;

    while i < output.len() {
        let mut mac = HmacSha256::new_from_slice(&hmac_key_bytes).unwrap();

        mac.update(&tmp);
        mac.update("miwear-auth".as_bytes());
        mac.update(&[b]);
        tmp = mac.finalize().into_bytes().to_vec();

        let mut j = 0;
        while j < tmp.len() && i < output.len() {
            output[i] = tmp[j];
            j += 1;
            i += 1;
        }

        b += 1;
    }
    output
}

fn build_nonce(encryption_nonce: &[u8], id: i32) -> [u8; 12] {
    // TODO: Do this on stack
    let mut nonce = Vec::with_capacity(12);
    nonce.extend_from_slice(encryption_nonce);
    nonce.extend_from_slice(&[0, 0, 0, 0]);
    nonce.extend_from_slice(&id.to_le_bytes());
    nonce.try_into().unwrap()
}

fn unpack_64(output: &[u8; 64]) -> (&[u8], &[u8], &[u8], &[u8]) {
    let decryption_key = &output[0..16];
    let output = &output[16..];

    let encryption_key = &output[0..16];
    let output = &output[16..];

    let decryption_nonce = &output[0..4];
    let output = &output[4..];

    let encryption_nonce = &output[0..4];

    (
        decryption_key,
        encryption_key,
        decryption_nonce,
        encryption_nonce,
    )
}

fn auth_sanity_check(
    phone_nonce: &[u8],
    watch_nonce: &[u8],
    decryption_key: &[u8],
    watch_hmac: &[u8],
) {
    let nonce = join_nonce(watch_nonce, phone_nonce);
    let mut mac = HmacSha256::new_from_slice(decryption_key).unwrap();
    mac.update(&nonce);
    let res = mac.finalize().into_bytes();
    assert_eq!(res.as_slice(), watch_hmac);
}

fn encrypted_auth_device_info(encryption_nonce: &[u8], encryption_key: &[u8]) -> Vec<u8> {
    let device_info = protocol::AuthDeviceInfo {
        unknown1: 0,
        phone_api_level: 34.0,
        phone_name: "Pixel 7".to_string(),
        unknown3: 224,
        region: "EN".to_string(),
    };
    let device_info = device_info.encode_to_vec();

    let nonce = build_nonce(encryption_nonce, 0);
    let nonce = GenericArray::from_slice(&nonce);
    let encryption_key = GenericArray::from_slice(encryption_key);

    let cipher: Aes128Ccm = ccm::KeyInit::new(encryption_key);
    let plain = device_info.as_ref();
    cipher.encrypt(nonce, plain).unwrap()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> bluer::Result<()> {
    // let bytes = decode_hex(AUTH_STEP_1_REQUEST).unwrap();
    // let command = protocol::Command::decode(bytes.as_ref()).unwrap();
    // println!("step 1 req -> {:#?}", command);
    // let phone_nonce = command.auth.unwrap().phone_nonce.unwrap().nonce;
    //
    // let bytes = decode_hex(AUTH_STEP_1_RESPONSE).unwrap();
    // let command = protocol::Command::decode(bytes.as_ref()).unwrap();
    // println!("step 1 res <- {:#?}", command);
    // let watch_nonce = command.auth.unwrap().watch_nonce.unwrap();
    // let watch_hmac = watch_nonce.hmac;
    // let watch_nonce = watch_nonce.nonce;
    //
    // let bytes = decode_hex(AUTH_STEP_2_REQUEST).unwrap();
    // let command = protocol::Command::decode(bytes.as_ref()).unwrap();
    // println!("step 2 req -> {:#?}", command);
    // let encrypted_nonces = command.auth.unwrap().auth_step3.unwrap().encrypted_nonces;
    //
    // let bytes = decode_hex(AUTH_STEP_2_RESPONSE).unwrap();
    // let command = protocol::Command::decode(bytes.as_ref()).unwrap();
    // println!("step 2 res <- {:#?}", command);
    //
    // // TODO: Figure out wtf is this
    // let output = compute_auth_step3(&phone_nonce, &watch_nonce);
    // let (decryption_key, encryption_key, decryption_nonce, encryption_nonce) = unpack_64(&output);
    //
    // auth_sanity_check(&phone_nonce, &watch_nonce, decryption_key, &watch_hmac);
    //
    // let my_encrypted_nonces = {
    //     let nonce = join_nonce(&phone_nonce, &watch_nonce);
    //     let mut mac = HmacSha256::new_from_slice(encryption_key).unwrap();
    //     mac.update(&nonce);
    //     mac.finalize().into_bytes()
    // };
    //
    // assert_eq!(encrypted_nonces, my_encrypted_nonces.as_slice());
    //
    // {
    //     let device_info = encrypted_auth_device_info(encryption_nonce, encryption_key);
    //     dbg!(device_info);
    // }
    //
    // // let bytes = decode_hex(SOME_REQUEST).unwrap();
    // // let command = protocol::Command::decode(bytes.as_ref()).unwrap();
    // // println!("-> {:#?}", command);
    //
    // return Ok(());

    env_logger::init();
    let session = bluer::Session::new().await?;
    println!("{:?}", session.adapter_names().await?);
    let adapter = session.default_adapter().await?;
    adapter.set_powered(true).await?;

    // let discover = adapter.discover_devices().await?;
    // pin_mut!(discover);

    // while let Some(evt) = discover.next().await {
    //     println!("{:?}", evt);
    //     if let AdapterEvent::DeviceAdded(address) = evt {
    //         if address == mac_address {
    //             break
    //         }
    //     }
    // }

    let mac_address = Address::new([0xD0, 0x62, 0x2C, 0x5A, 0x69, 0x05]);
    let device = adapter.device(mac_address)?;
    // let service = device.service(256).await?;
    // let read = service.characteristic(259).await?;
    // let write = service.characteristic(262).await?;

    // let device = MiBand8Device { read, write };

    // println!("Found: {device:#?}");
    // start(device).await.unwrap();

    match find_our_characteristic(&device).await {
        Ok(Some(char)) => {
            println!("Found: {char:#?}");
            start(char).await.unwrap();
        }
        Ok(None) => (),
        Err(err) => {
            println!("    Device failed: {}", &err);
            let _ = adapter.remove_device(device.address()).await;
        }
    }

    // {
    //     println!(
    //         "Discovering on Bluetooth adapter {} with address {}\n",
    //         adapter.name(),
    //         adapter.address().await?
    //     );
    //     let discover = adapter.discover_devices().await?;
    //     pin_mut!(discover);
    //     while let Some(evt) = discover.next().await {
    //         match evt {
    //             AdapterEvent::DeviceAdded(addr) => {
    //                 let device = adapter.device(addr)?;
    //                 match find_our_characteristic(&device).await {
    //                     Ok(Some(char)) => {
    //                         println!("Found: {char:#?}");
    //                         start(char).await.unwrap();
    //                         break;
    //                     }
    //                     Ok(None) => (),
    //                     Err(err) => {
    //                         println!("    Device failed: {}", &err);
    //                         let _ = adapter.remove_device(device.address()).await;
    //                     }
    //                 }
    //             }
    //             AdapterEvent::DeviceRemoved(addr) => {
    //                 println!("Device removed {addr}");
    //             }
    //             _ => (),
    //         }
    //     }
    //     println!("Stopping discovery");
    // }

    sleep(Duration::from_secs(1)).await;
    Ok(())
}
