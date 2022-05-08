use anyhow::Result;
use clap::Parser;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt::Display;
use std::io::{BufRead, Write};
use std::net::IpAddr;
use std::str::FromStr;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use tokio::runtime::Runtime;
use trust_dns_resolver::config::*;
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::error::ResolveErrorKind;
use trust_dns_resolver::lookup_ip::LookupIp;
use trust_dns_resolver::proto::op::ResponseCode;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::TokioAsyncResolver;

#[derive(PartialEq, Serialize)]
enum LookupResult {
    Safe,
    MaybeVulnerable,
    LookupError,
}

impl Display for LookupResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            LookupResult::Safe => write!(f, "Safe"),
            LookupResult::MaybeVulnerable => write!(f, "MaybeVulnerable"),
            LookupResult::LookupError => write!(f, "LookupError"),
        }
    }
}

fn is_vulnerable(lookup_result: &Result<LookupIp, ResolveError>) -> LookupResult {
    match lookup_result {
        Ok(_) => LookupResult::Safe,
        Err(err) => match err.kind() {
            ResolveErrorKind::Message(_) => LookupResult::Safe,
            ResolveErrorKind::Msg(_) => LookupResult::Safe,
            ResolveErrorKind::NoConnections => LookupResult::Safe,
            ResolveErrorKind::NoRecordsFound {
                query: _,
                soa: _,
                negative_ttl: _,
                response_code,
                trusted: _,
            } => match response_code {
                ResponseCode::NoError => LookupResult::Safe,
                ResponseCode::FormErr => LookupResult::Safe,
                ResponseCode::ServFail => LookupResult::MaybeVulnerable,
                ResponseCode::NXDomain => LookupResult::Safe,
                ResponseCode::NotImp => LookupResult::Safe,
                ResponseCode::Refused => LookupResult::Safe,
                ResponseCode::YXDomain => LookupResult::Safe,
                ResponseCode::YXRRSet => LookupResult::Safe,
                ResponseCode::NXRRSet => LookupResult::Safe,
                ResponseCode::NotAuth => LookupResult::Safe,
                ResponseCode::NotZone => LookupResult::Safe,
                ResponseCode::BADVERS => LookupResult::Safe,
                ResponseCode::BADSIG => LookupResult::Safe,
                ResponseCode::BADKEY => LookupResult::Safe,
                ResponseCode::BADTIME => LookupResult::Safe,
                ResponseCode::BADMODE => LookupResult::Safe,
                ResponseCode::BADNAME => LookupResult::Safe,
                ResponseCode::BADALG => LookupResult::Safe,
                ResponseCode::BADTRUNC => LookupResult::Safe,
                ResponseCode::BADCOOKIE => LookupResult::Safe,
                ResponseCode::Unknown(_number) => LookupResult::Safe,
            },
            ResolveErrorKind::Io(_) => LookupResult::Safe,
            ResolveErrorKind::Proto(_) => LookupResult::LookupError,
            ResolveErrorKind::Timeout => LookupResult::Safe,
            _ => LookupResult::Safe,
        },
    }
}

/// Tool to detect if a domain is vulnerable to domain server takeover.
/// If neither of -d or -i is specified, the list of domains will be read
/// from stdin.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Filename with a list of domains to check
    #[clap(short, long)]
    input_file: Option<String>,
    /// Domain to do the lookup for
    #[clap(short, long)]
    domain: Option<String>,
    /// If the lookups should be perfomed asynchronously or not
    #[clap(short, long)]
    r#async: bool,
    /// If the output should be printed in color or not
    #[clap(short, long)]
    color: bool,
    /// Combined option json_input and json_output, if this one is set, then those are assumed to be set also
    #[clap(short, long)]
    json: bool,
    /// If the input should be parsed as json
    #[clap(long)]
    json_input: bool,
    /// If the output should be printed as json, in case both this value and --color is set at the same time, this one takes precedence
    #[clap(long)]
    json_output: bool,
    /// The ip address of the name server to use, defaults to google's servers
    #[clap(short, long)]
    name_server: Option<String>,
}

fn check_async(to_check: &[String], color: bool, json: bool, ns: Option<String>) -> Result<()> {
    let io_loop = Runtime::new().unwrap();

    let ns = ns.map(|ns| IpAddr::from_str(&ns).unwrap());

    let resolver = io_loop
        .block_on(async {
            if let Some(ns) = ns {
                TokioAsyncResolver::tokio(
                    ResolverConfig::from_parts(
                        None,
                        vec![],
                        NameServerConfigGroup::from_ips_clear(&[ns], 53, true),
                    ),
                    ResolverOpts::default(),
                )
            } else {
                TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
            }
        })
        .expect("failed to connect resolver");

    let futures: Vec<_> = to_check.iter().map(|l| resolver.lookup_ip(l)).collect();

    // do these futures concurrently and return them
    let results = to_check
        .iter()
        .zip(
            io_loop
                .block_on(futures::future::join_all(futures))
                .into_iter()
                .map(|res| is_vulnerable(&res)),
        )
        .collect::<HashMap<&String, LookupResult>>();

    print_results(results, color, json)
}

fn check(to_check: &[String], color: bool, json: bool, ns: Option<String>) -> Result<()> {
    let ns = ns.map(|ns| IpAddr::from_str(&ns).unwrap());

    let resolver = if let Some(ns) = ns {
        Resolver::new(
            ResolverConfig::from_parts(
                None,
                vec![],
                NameServerConfigGroup::from_ips_clear(&[ns], 53, true),
            ),
            ResolverOpts::default(),
        )
        .unwrap()
    } else {
        Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap()
    };

    let results = to_check
        .iter()
        .map(|l| {
            let is_vulnerable = is_vulnerable(&resolver.lookup_ip(l));
            (l, is_vulnerable)
        })
        .collect::<HashMap<&String, LookupResult>>();

    print_results(results, color, json)
}

fn print_results(results: HashMap<&String, LookupResult>, color: bool, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        for (domain, is_vulnerable) in results.iter() {
            print(domain, is_vulnerable, color)?;
        }
    }

    Ok(())
}

fn print(domain: &str, is_vulnerable: &LookupResult, color: bool) -> Result<()> {
    if color {
        let mut stdout = StandardStream::stdout(ColorChoice::Always);
        write!(&mut stdout, "{} : ", domain)?;

        match *is_vulnerable {
            LookupResult::MaybeVulnerable => {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?
            }
            LookupResult::Safe => stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?,
            LookupResult::LookupError => {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)))?
            }
        };
        writeln!(&mut stdout, "{}", *is_vulnerable)?;
        stdout.reset()?;
    } else {
        println!("{} : {}", domain, *is_vulnerable);
    }

    Ok(())
}

fn main() {
    let args = Args::parse();

    if args.input_file.is_some() && args.domain.is_some() {
        eprintln!("the --input_file option and the --domain option are mutually exclusive");
        std::process::exit(1);
    }

    let mut to_check: Vec<String> = vec![];

    if args.input_file.is_none() && args.domain.is_none() {
        if args.json || args.json_input {
            let datas: Vec<String> = serde_json::from_reader(std::io::stdin()).unwrap();
            to_check.extend(datas);
        } else {
            for input in std::io::stdin().lock().lines() {
                to_check.push(input.unwrap().trim().to_string());
            }
        }
    }

    if args.input_file.is_some() {
        let list = std::fs::read_to_string(&args.input_file.unwrap()).unwrap();

        for l in list.split('\n') {
            to_check.push(l.trim().to_string());
        }
    } else if args.domain.is_some() {
        to_check.push(args.domain.unwrap());
    }

    if args.r#async {
        check_async(
            &to_check,
            args.color,
            args.json || args.json_output,
            args.name_server,
        )
        .unwrap();
    } else {
        check(
            &to_check,
            args.color,
            args.json || args.json_output,
            args.name_server,
        )
        .unwrap();
    }
}
