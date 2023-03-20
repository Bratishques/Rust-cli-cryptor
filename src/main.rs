use base64::engine::general_purpose;
use clap::{arg, command, ArgAction, Arg};
use crypto::buffer::{BufferResult, WriteBuffer, ReadBuffer};
use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use serde::{Serialize, Deserialize};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::io::Write;
use std::{str, io};
use base64::{encode, Engine};
use openssl::symm::*;

#[derive(Serialize, Deserialize)]
struct InputData {
    id: String,
    direction: String,
    data: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct CryptorOutputData {
    id: String,
    result: Vec<String>
}

fn main() {
    let matches = command!() // requires `cargo` feature
        .next_line_help(true)
        .arg(arg!(-v --vector <VALUE>).required(true).action(ArgAction::Set))
        .arg(arg!(-s --secret <VALUE>).required(true).action(ArgAction::Set))
        .get_matches();

    let vector = matches.get_one::<String>("vector").expect("required");
    let secret: &String = matches.get_one::<String>("secret").expect("required");

    println!(
        "vector: {vector:?}"
    );
    println!(
        "secret: {secret:?}",
    );

    loop {
        let mut buffer = String::new();
        let input = io::stdin().read_line(&mut buffer).unwrap().to_string();
        let data: InputData = serde_json::from_str(&buffer).unwrap();
        let mut result: Vec<String> = [].to_vec();
        if data.direction == "encrypt" {
            for x in &data.data {
                result.push(encryptor_aes(&secret, &vector, &x))
            }
        }
        if data.direction == "decrypt" {
            for x in &data.data {
                result.push(decryptor_aes(&secret, &vector, &x))
            }
        }
        let output = CryptorOutputData {
            id: data.id,
            result
        };
        let j = serde_json::to_string(&output).unwrap();
        io::stdout().write_all(j.as_bytes());
    }


}

fn encryptor_aes(secret: &str, vector: &str, data: &str) -> String {
    let bytes = encrypt(Cipher::aes_256_cbc(), secret.as_bytes(), Some(vector.as_bytes()), data.as_bytes());
    match bytes {
        Ok(result) => {
            let base64_encoded = general_purpose::STANDARD_NO_PAD.encode(&result);
            return base64_encoded;
        }
        Err(_e) => {
            panic!("Error unwrapping")
        }
    }
}

fn decryptor_aes(secret: &str, vector: &str, data: &str) -> String {
    let decoded_input = general_purpose::STANDARD_NO_PAD.decode(data).expect("error");
    let result = decrypt(Cipher::aes_256_cbc(), secret.as_bytes(), Some(vector.as_bytes()), &decoded_input).unwrap();
    let str = String::from_utf8(result).expect("error");
    return str; 
}

// fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {

//     // Create an encryptor instance of the best performing
//     // type available for the platform.
//     let mut encryptor = aes::cbc_encryptor(
//             aes::KeySize::KeySize256,
//             key,
//             iv,
//             blockmodes::PkcsPadding);

//     // Each encryption operation encrypts some data from
//     // an input buffer into an output buffer. Those buffers
//     // must be instances of RefReaderBuffer and RefWriteBuffer
//     // (respectively) which keep track of how much data has been
//     // read from or written to them.
//     let mut final_result = Vec::<u8>::new();
//     let mut read_buffer = buffer::RefReadBuffer::new(data);
//     let mut buffer = [0; 4096];
//     let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

//     // Each encryption operation will "make progress". "Making progress"
//     // is a bit loosely defined, but basically, at the end of each operation
//     // either BufferUnderflow or BufferOverflow will be returned (unless
//     // there was an error). If the return value is BufferUnderflow, it means
//     // that the operation ended while wanting more input data. If the return
//     // value is BufferOverflow, it means that the operation ended because it
//     // needed more space to output data. As long as the next call to the encryption
//     // operation provides the space that was requested (either more input data
//     // or more output space), the operation is guaranteed to get closer to
//     // completing the full operation - ie: "make progress".
//     //
//     // Here, we pass the data to encrypt to the enryptor along with a fixed-size
//     // output buffer. The 'true' flag indicates that the end of the data that
//     // is to be encrypted is included in the input buffer (which is true, since
//     // the input data includes all the data to encrypt). After each call, we copy
//     // any output data to our result Vec. If we get a BufferOverflow, we keep
//     // going in the loop since it means that there is more work to do. We can
//     // complete as soon as we get a BufferUnderflow since the encryptor is telling
//     // us that it stopped processing data due to not having any more data in the
//     // input buffer.
//     loop {
//         let result = r#try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));

//         // "write_buffer.take_read_buffer().take_remaining()" means:
//         // from the writable buffer, create a new readable buffer which
//         // contains all data that has been written, and then access all
//         // of that data as a slice.
//         final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

//         match result {
//             BufferResult::BufferUnderflow => break,
//             BufferResult::BufferOverflow => { }
//         }
//     }

//     Ok(final_result)
// }

// fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
//     let mut decryptor = aes::cbc_decryptor(
//             aes::KeySize::KeySize256,
//             key,
//             iv,
//             blockmodes::PkcsPadding);

//     let mut final_result = Vec::<u8>::new();
//     let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
//     let mut buffer = [0; 4096];
//     let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

//     loop {
//         let result = r#try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
//         final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
//         match result {
//             BufferResult::BufferUnderflow => break,
//             BufferResult::BufferOverflow => { }
//         }
//     }

//     Ok(final_result)
// }

