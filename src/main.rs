extern crate hyper_openssl;
extern crate openssl;
extern crate hyper;

use std::io::{Read, Write, BufReader};
use std::process;
use std::env;
use std::sync::Arc;
use std::error::Error;
use std::net::TcpStream;
use hyper::Client;
use hyper::net::HttpsConnector;
use hyper_openssl::OpensslClient;
use hyper::net::NetworkConnector;
use openssl::ssl::{SslConnectorBuilder, SslMethod};

const DEFAULT_CIPHERS: &'static str = concat!(
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
    "DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:",
    "ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:",
    "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:",
    "ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:",
    "DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:",
    "ECDHE-ECDSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:",
    "AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA"
);

enum Verdict {
    Accept,
    Reject(hyper::Error),
}

fn parse_args(args: &Vec<String>) -> Result<(String, u16, Option<&String>), Box<Error>> {
	let mut ca_file = None;
	match args.len() {
		3 => (),
		4 => ca_file = Some(&args[3]),
		_ => return Err(From::from("Incorrect number of args"))
	}
    let port = try!(args[2].parse());
    Ok((args[1].clone(), port, ca_file))
}

fn communicate(host: String, port: u16, ca_file: Option<&String>) -> Result<Verdict, Box<Error>> {
	let ssl = match ca_file {
		Some(file) => {
			let mut ssl_connector_builder = SslConnectorBuilder::new(SslMethod::tls()).unwrap();
			{
				let context = ssl_connector_builder.builder_mut();
				context.set_ca_file(file).expect("could not set ca file");
				context.set_cipher_list(DEFAULT_CIPHERS).expect("could not set ciphers");
			}
			hyper_openssl::OpensslClient::from(ssl_connector_builder.build())
		},
		None => OpensslClient::new().unwrap(),
	};
    let connector = HttpsConnector::new(ssl);
    //let client = Client::with_connector(connector.clone());

	match connector.connect(&host, port, "https") {
		Ok(_) => Ok(Verdict::Accept),
		Err(err) => Ok(Verdict::Reject(err)),
	}

}

fn main() {
    let args: Vec<String> = env::args().collect();
    let (host, port, ca_file) = parse_args(&args).unwrap_or_else(|err| {
        println!("Argument error: {}", err);
        process::exit(2);
    });

    match communicate(host, port, ca_file) {
        Ok(Verdict::Accept) => {
            println!("ACCEPT");
            process::exit(0);
        }
        Ok(Verdict::Reject(reason)) => {
            println!("{:?}", reason);
            println!("REJECT");
            process::exit(0);
        }
        Err(err) => {
            println!("{}", err);
            process::exit(1);
        }
    }
}
