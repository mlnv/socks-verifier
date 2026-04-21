# socks-verifier

A one-shot Spring Boot CLI for verifying SOCKS5 connectivity with username and password authentication.

## Features

- Verifies SOCKS5 username and password authentication
- Supports HTTP and HTTPS URL probes
- Supports raw TCP connect checks
- Prints human-readable or JSON output
- Shows the authentication method and status without printing secrets
- Exits with stable status codes for automation

## Build

Windows PowerShell:

```powershell
.\gradlew.bat check
.\gradlew.bat bootJar
```

macOS or Linux:

```bash
./gradlew check
./gradlew bootJar
```

## Usage

HTTP or HTTPS probe:

Windows PowerShell:

```powershell
.\gradlew.bat bootRun --args="--proxy-host 127.0.0.1 --proxy-port 1080 --username demo --password secret --url http://example.com --output text"
```

macOS or Linux:

```bash
./gradlew bootRun --args="--proxy-host 127.0.0.1 --proxy-port 1080 --username demo --password secret --url http://example.com --output text"
```

TCP connect probe:

Windows PowerShell:

```powershell
.\gradlew.bat bootRun --args="--proxy-host 127.0.0.1 --proxy-port 1080 --username demo --password secret --target-host example.com --target-port 443 --output json"
```

macOS or Linux:

```bash
./gradlew bootRun --args="--proxy-host 127.0.0.1 --proxy-port 1080 --username demo --password secret --target-host example.com --target-port 443 --output json"
```

## Exit codes

- `0` - verification succeeded
- `2` - invalid arguments
- `10` - authentication failed
- `11` - proxy connection failed
- `12` - target connection or probe failed
- `13` - internal error

## Output notes

The CLI never prints the actual username or password. It reports only safe authentication metadata such as:

- `Authentication: USERNAME_PASSWORD`
- `Authentication status: SUCCEEDED`, `FAILED`, or `NOT_ATTEMPTED`
