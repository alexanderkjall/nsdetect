# NSDetect: A Rust Utility To Detect AWS NS Takeover

![https://www.rust-lang.org/static/images/rust-logo-blk.svg](https://www.rust-lang.org/static/images/rust-logo-blk.svg)

This is a rewrite of [NSDetect](https://github.com/shivsahni/NSDetect) in rust, since that tool requires python2
which is increasingly hard to use on a modern linux distribution.

## Installation
### Prerequisites
- Cargo installed, for example via [rustup](https://rustup.rs/)
### Installation
```shell
cargo install nsdetect
```

### Reading Suggestions
* If you are unaware of AWS NS Takeover and want to know more about it read [this](https://medium.com/@shivsahni2/aws-ns-takeover-356d2a293bca) 
  Medium story describing the misconfiguration and providing the walkthrough for automated exploitation. 
* If you are already aware of NS Takeover, have a look at [this](https://medium.com/@shivsahni2/nsdetect-a-tool-to-discover-potential-aws-domain-takeovers-fd0ff1a8b68a) 
  Medium story providing the detailed walkthrough on NSDetect.

## Usage
The program takes a file with a list of domains as an input, scans each one of them(skipping duplicates) against this
vulnerability and at last reports a list of vulnerable domains. For help you can run it with *-h* or *--help* option as shown below:
```
nsdetect  -h
```

The input file should simply be a list of domains, one per line

Once we have done sufficient recon on the target and have prepared the list of domains/subdomains, we can provide the
list as an input to the tool in order to scan each domain in the list. The script shows the results in the real-time
such that the domains highlighted with red colour are vulnerable domains. We can use *-i* or *--input* option to provide the
input file as shown below:
```
nsdetect -i ~/Desktop/temp.csv
```

For the takeover of the vulnerable domains, we can use [**NSBrute](https://github.com/shivsahni/NSBrute)**, 
which requires AWS Programmatic Access:
```
python NSBrute.py -d vulnerabledomain.com -a ThisIsNotMyAccessKey -s ThisIsNotMySecretKet
```

**Note:** While you are doing the POC for NSDetect locally, please keep in mind that
[DNS Propagation Issues](https://www.siteground.com/kb/what_is_dns_propagation_and_why_it_takes_so_long/) might lead to 
unexpected results. You may need to provide  sufficient time for DNS changes to propagate. In case you still observe 
the problem, feel free to raise an issue, we can fix it **together**!
