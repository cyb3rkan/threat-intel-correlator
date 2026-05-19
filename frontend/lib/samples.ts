// frontend/lib/samples.ts
// Safe, locally generated example files for the input guide.
//
// Rules:
// - Documentation/test data only. No real malicious infrastructure.
// - The sample IPs are TEST-NET / RFC 5737 ranges and IETF documentation
//   examples; they are not real C2 / malware addresses.
// - The sample domains use the IETF "example.com" reservation.
// - The sample hashes are zero-padded placeholders, never real malware hashes.
// - No secrets, tokens or credentials anywhere.

const SAMPLE_IOCS_CSV = `value,confidence,source,tags
198.51.100.23,80,sample-feed,doc;ipv4
203.0.113.45,75,sample-feed,doc;ipv4
2001:db8::5,60,sample-feed,doc;ipv6
malware.example.com,90,sample-feed,doc;domain
phish.example.org,85,sample-feed,doc;domain
http://evil.example.net/payload.exe,95,sample-feed,doc;url
0123456789abcdef0123456789abcdef,55,sample-feed,doc;md5
0000000000000000000000000000000000000000,40,sample-feed,doc;sha1
0000000000000000000000000000000000000000000000000000000000000000,50,sample-feed,doc;sha256
`;

// Each line is a JSON object containing one of the IOC values from the CSV.
// The Aho-Corasick correlator scans the full JSON text of each line.
const SAMPLE_EVENTS_NDJSON = [
  {
    "@timestamp": "2025-01-12T08:14:02Z",
    source: "firewall",
    src_ip: "10.0.0.42",
    dst_ip: "198.51.100.23",
    action: "allow",
    bytes: 8421,
  },
  {
    "@timestamp": "2025-01-12T08:14:30Z",
    source: "proxy",
    user: "alice",
    url: "http://malware.example.com/login",
    status: 200,
  },
  {
    "@timestamp": "2025-01-12T08:15:11Z",
    source: "edr",
    host: "WS-042",
    process: "powershell.exe",
    download_url: "http://evil.example.net/payload.exe",
  },
  {
    "@timestamp": "2025-01-12T08:16:00Z",
    source: "dns",
    query: "phish.example.org",
    qtype: "A",
    answer: "203.0.113.45",
  },
  {
    "@timestamp": "2025-01-12T08:17:45Z",
    source: "edr",
    host: "WS-007",
    file_hash_md5: "0123456789abcdef0123456789abcdef",
    path: "C:/Users/Public/sample.bin",
  },
  {
    "@timestamp": "2025-01-12T08:18:09Z",
    source: "ipv6-firewall",
    src_ip: "2001:db8::5",
    dst_ip: "fd00::1",
    action: "block",
  },
]
  .map((o) => JSON.stringify(o))
  .join("\n") + "\n";

export const SAMPLE_IOCS_FILENAME = "sample_iocs.csv";
export const SAMPLE_EVENTS_FILENAME = "sample_events.ndjson";

export function getSampleIocsCsv(): string {
  return SAMPLE_IOCS_CSV;
}

export function getSampleEventsNdjson(): string {
  return SAMPLE_EVENTS_NDJSON;
}
