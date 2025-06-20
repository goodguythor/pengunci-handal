#[derive(Debug, Clone)]
pub enum Message {
    PathChanged(String),
    PasswordChanged(String),
    ChangeTab(bool),
    Close,
    Encrypt,
    Decrypt,
    Browse,
}

use std::{fs::File, io::{Read, Write}};
use orion::hazardous::{
    aead::xchacha20poly1305::{open, seal, Nonce, SecretKey}, mac::poly1305::POLY1305_OUTSIZE, stream::xchacha20::XCHACHA_NONCESIZE
};
use orion::hazardous::stream::chacha20::CHACHA_KEYSIZE;
use orion::kdf::{derive_key, Password, Salt};
use rand_core::{OsRng, TryRngCore};
use iced::widget::{button, column, row, text, text_input, container, Column, Space};

#[derive(Default)]
struct FileEncryptor {
    file_path: String,
    password: String,
    error_message: String,
    decrypt: bool,
}

impl FileEncryptor {
    pub fn view(&self) -> Column<Message> {
        column![
            row![
                button("Encrypt File").on_press(Message::ChangeTab(false)),
                button("Decrypt File").on_press(Message::ChangeTab(true)),
            ],
            text("Pengunci Handal")
                .size(64)
                .width(iced::Length::Fill)
                .center(),
            row![
                text("Enter File Path: ")
                    .size(24),
                text_input("File path", &self.file_path)
                    .on_input(Message::PathChanged)
                    .padding(10),
                button("Select File").on_press(Message::Browse),
            ],
            row![
                text("Password: ")
                    .size(24),
                text_input("Enter password", &self.password)
                    .on_input(Message::PasswordChanged)
                    .padding(10),
            ],
            if self.decrypt == false {
                button("Encrypt").on_press(Message::Encrypt)
            } else {
                button("Decrypt").on_press(Message::Decrypt)
            },
            if !self.error_message.is_empty() {
                container(
                    row![
                        text(format!("{}", self.error_message)),
                        button("Ok").on_press(Message::Close)
                    ]
                )
                .padding(10)
            } 
            else {
                container(
                    row![
                        
                    ]
                )
            },
        ]
    }

    pub fn update(&mut self, message: Message) {
        match message {
            Message::PathChanged(content) => {
                self.file_path = content;
            }
            Message::PasswordChanged(content) => {
                self.password = content;
            }
            Message::ChangeTab(condition) => {
                self.decrypt = condition;
            }
            Message::Close => {
                self.error_message.clear();
            }
            Message::Browse => {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.file_path = path.display().to_string();
                }
            }
            Message::Encrypt => {
                if self.file_path.is_empty() {
                    self.error_message = "Error: File path is empty.".to_string();
                    eprintln!("{}", self.error_message);
                    return;
                }

                if self.password.is_empty() {
                    self.error_message = "Error: Password is empty.".to_string();
                    eprintln!("{}", self.error_message);
                    return;
                }

                let mut file = match File::open(&self.file_path) {
                    Ok(f) => f,
                    Err(e) => {
                        self.error_message = format!("Failed to open file: {}", e);
                        eprintln!("{}", self.error_message);
                        return;
                    }
                };
                let output_path = format!("{}.enc", &self.file_path);
                let mut encrypted_file = match File::create(&output_path) {
                    Ok(f) => f,
                    Err(e) => {
                        self.error_message = format!("Failed to create encrypted file: {}", e);
                        eprintln!("{}", self.error_message);
                        return;
                    }
                };

                let mut src = Vec::new();
                if let Err(e) = file.read_to_end(&mut src) {
                    self.error_message = format!("Failed to read file: {}", e);
                    eprintln!("{}", self.error_message);
                    return;
                }

                let mut nonce_bytes = [0u8; XCHACHA_NONCESIZE];
                OsRng.try_fill_bytes(&mut nonce_bytes);
                if let Err(e) = encrypted_file.write_all(&nonce_bytes) {
                    self.error_message = format!("Failed to write nonce: {}", e);
                    eprintln!("{}", self.error_message);
                    return;
                }

                let pass = Password::from_slice(self.password.as_bytes()).unwrap();
                let salt = Salt::from_slice(&nonce_bytes).unwrap();
                let kdf_key = derive_key(&pass, &salt, 15, 1024, CHACHA_KEYSIZE as u32).unwrap();
                let key = SecretKey::from_slice(kdf_key.unprotected_as_bytes()).unwrap();

                let nonce = Nonce::from_slice(&nonce_bytes).unwrap();

                for chunk in src.chunks(128) {
                    let mut ad = [0u8; 32];
                    OsRng.try_fill_bytes(&mut ad);

                    let mut output = vec![0u8; ad.len() + POLY1305_OUTSIZE + chunk.len()];
                    output[..ad.len()].copy_from_slice(&ad);

                    let seal_result = seal(
                        &key,
                        &nonce,
                        chunk,
                        Some(&ad),
                        &mut output[ad.len()..],
                    );

                    if let Err(e) = seal_result {
                        self.error_message = format!("Encryption failed: {}", e);
                        eprintln!("{}", self.error_message);
                        return;
                    }

                    if let Err(e) = encrypted_file.write_all(&output) {
                        self.error_message = format!("Failed to write encrypted chunk: {}", e);
                        eprintln!("{}", self.error_message);
                        return;
                    }
                }

                self.file_path.clear();
                self.password.clear();
            }
            Message::Decrypt => {
                if self.file_path.is_empty() {
                    self.error_message = "Error: File path is empty.".to_string();
                    eprintln!("{}", self.error_message);
                    return;
                }

                if self.password.is_empty() {
                    self.error_message = "Error: Password is empty.".to_string();
                    eprintln!("{}", self.error_message);
                    return;
                }

                let mut file = match File::open(&self.file_path) {
                    Ok(f) => f,
                    Err(e) => {
                        self.error_message = format!("Failed to open file: {}", e);
                        eprintln!("{}", self.error_message);
                        return;
                    }
                };
                let output_path = if let Some(stripped) = self.file_path.strip_suffix(".enc") {
                    stripped.to_string()
                } 
                else {
                    self.error_message = "Error: The selected file is not an .enc file.".to_string();
                    eprintln!("{}", self.error_message);
                    return;
                };
                let mut decrypted_file = match File::create(&output_path) {
                    Ok(f) => f,
                    Err(e) => {
                        self.error_message = format!("Failed to create decrypted file: {}", e);
                        eprintln!("{}", self.error_message);
                        return;
                    }
                };

                let mut src = Vec::new();
                if let Err(e) = file.read_to_end(&mut src) {
                    self.error_message = format!("Failed to create encrypted file: {}", e);
                    eprintln!("{}", self.error_message);
                    return;
                }

                let nonce_bytes = &src[..XCHACHA_NONCESIZE];
                let encrypted_data = &src[XCHACHA_NONCESIZE..];

                let pass = Password::from_slice(self.password.as_bytes()).unwrap();
                let salt = Salt::from_slice(nonce_bytes).unwrap();
                let kdf_key = derive_key(&pass, &salt, 15, 1024, CHACHA_KEYSIZE as u32).unwrap();
                let key = SecretKey::from_slice(kdf_key.unprotected_as_bytes()).unwrap();

                let nonce = Nonce::from_slice(nonce_bytes).unwrap();

                let ad_len = 32;
                for chunk in encrypted_data.chunks(ad_len + 128 + POLY1305_OUTSIZE) {
                    if chunk.len() < ad_len + POLY1305_OUTSIZE {
                        continue; 
                    }

                    let (ad, ciphertext) = chunk.split_at(ad_len);
                    let mut output = vec![0u8; ciphertext.len() - POLY1305_OUTSIZE];

                    match open(&key, &nonce, ciphertext, Some(ad), &mut output) {
                        Ok(_) => {},
                        Err(e) => {
                            self.error_message = format!("Decryption failed: {} (wrong password)", e);
                            eprintln!("{}", self.error_message);
                            return;
                        }
                    }

                    if let Err(e) = decrypted_file.write_all(&output) {
                        self.error_message = format!("Failed to write decrypted chunk: {}", e);
                        eprintln!("{}", self.error_message);
                        return;
                    }
                }

                self.file_path.clear();
                self.password.clear();
            }
        }
    }
}

fn main() -> iced::Result {
    iced::run(FileEncryptor::update, FileEncryptor::view)
}