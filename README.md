<img width="1280" height="300" alt="subpeek" src="https://github.com/user-attachments/assets/85276400-992d-45a9-924b-8e5f8c6f2335" />


SubPeek is a subdomain enumeration tool that uses a Rust core for speed and Python for the CLI.

It gathers subdomains from various passive sources (crt.sh, Anubis, etc), checking valid records and filtering out wildcards. It also proves they are alive by checking HTTP responses.

## Features

- Multi-threaded DNS resolution
- Passive discovery from 5 different sources
- Wildcard DNS/False positive filtering
- HTTP status and title grabbing
- JSON output

## Setup

You need Rust and Python installed.

1. Build the binary
```bash
cargo build --release
```

2. Install dependencies
```bash
pip install rich
```

3. Run
```bash
python run.py
```

## Usage

Run the script, enter a domain name. 

Results show the status code, page title and server header. You can save everything to a file at the end.

## License
MIT
