# Network Monitor

A Windows network monitoring project built with Node.js, TShark, JavaScript, HTML and CSS. It captures traffic in 30-second batches, converts captures to JSON, and produces reports containing heuristic alerts and related packet numbers in a dashboard.
## Features

- Automated TShark capture and PCAPNG-to-JSON conversion.
- IPv4 analysis for selected TCP ports, possible port scans, multiple destination IPs, connection attempts, DNS query bursts, and DNS failure bursts.
- JSON reports with capture statistics and packet references.
- Browser dashboard with expandable packet details.
- Report discovery through `reports.json`, polled every three seconds.

## How it works

TShark capture -> PCAPNG -> packet JSON -> analysis -> security report -> reports.json -> dashboard

`monitor.js` manages capture, conversion, analysis, and report creation.
`public/dashboard.js` loads reports and builds the table.
`public/index.html` and `public/style.css` provide the page and styling.

## Requirements

- Windows.
- Node.js
- Wireshark with TShark and a working packet capture driver such as Npcap.
- Permission to capture on the selected network interface.
- A local HTTP server for the dashboard.

The monitor uses Node.js built-in modules and does not require npm packages.

## Setup and usage

Run the following commands from the project root in PowerShell.

### 1. Select TShark

If TShark is on PATH, verify it with:

```powershell
tshark --version
tshark -D
```

Otherwise, set its installation path for this terminal session:

```powershell
$env:TSHARK_PATH = "C:\Program Files\Wireshark\tshark.exe"
& $env:TSHARK_PATH --version
& $env:TSHARK_PATH -D
```

### 2. Select a capture interface

Find the desired interface in the `-D` output. In `monitor.js`, replace `9` in the capture arguments with that interface's number:

```js
'-i', '9',
```

The capture duration is controlled by `CAPTURE_TIME`, currently 30 seconds.

### 3. Start the monitor

```powershell
node monitor.js
```

The monitor continues capturing successive batches. Stop it with `Ctrl+C`.

### 4. Open the dashboard

In a second terminal at the project root, start a local server:

```powershell
py -3 -m http.server 8000 --bind 127.0.0.1 --directory public
```

Open [the local dashboard](http://127.0.0.1:8000).

Reports become available after capture, conversion, and analysis finish. Allow more than 30 seconds for the first report. Stop the server with `Ctrl+C`.
Keep the terminal open while using the dashboard.

## Detection rules

Rules are evaluated separately for each capture batch.

| Finding | Current trigger |
| --- | --- |
| Suspicious Port | TCP destination port is 21, 23, 2323, 3389, or 4444 |
| Possible Port Scan | One source sends initial TCP SYN packets to at least 3 unique destination ports, across all destinations |
| Many Destination IPs | One source sends initial TCP SYN packets to at least 3 unique destination IPv4 addresses |
| Connection Burst | At least 3 initial TCP SYN packets from one source |
| DNS Query Burst | At least 5 DNS queries from one client |
| DNS Failure Burst | At least 3 DNS responses with a nonzero response code directed to one client |

Initial SYN packets are counted when SYN is set and ACK is not set. These low thresholds make alerts easy to demonstrate and may flag ordinary activity. Thresholds and the selected port list can be edited in `monitor.js`.

## Generated files

```text
public/
├── reports.json
└── MonitorLogs/
    └── <date>/
        └── TWIN-<time>/
            ├── Traffic-<time>.pcapng
            ├── Traffic-<time>.json
            └── SecurityReport-<time>.json
```

Report packet numbers refer to the associated capture file. The report's packet count represents the complete converted capture, including packets skipped by the IPv4 detection rules.
If clearing old output, stop the monitor first and remove both the capture folders and the corresponding report list so the dashboard does not request deleted reports.

## Limitations and troubleshooting

- Detection currently handles IPv4; it does not analyze IPv6 traffic.
- Counters reset for every batch. Activity spanning batches can be missed, and capture/conversion introduces gaps between batches.
- DNS analysis depends on DNS fields exposed by TShark; encrypted DNS is not decoded by these rules.
- Selected ports and burst thresholds can produce false positives. Findings require investigation.
- Reports accumulate without automatic retention limits, and packet JSON is loaded into memory for analysis.