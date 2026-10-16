/** A small made-up company, in the import format. Hosts are listed with who can reach whom; findings use real CVE ids. */
export const IMPORT_EXAMPLE = {
  hosts: [
    { id: "lb-public", software: "nginx 1.18", role: "Public load balancer", exposed: true },
    { id: "web-app", software: "Node 14 / Express", role: "Customer web app" },
    { id: "api", software: "Spring Boot / Log4j 2.14", role: "Internal API" },
    { id: "vpn", software: "OpenVPN 2.4", role: "Employee VPN", exposed: true },
    { id: "jump-host", software: "OpenSSH 7.4", role: "Bastion" },
    { id: "old-batch", software: "bash 4.2 CGI", role: "Decommissioned batch server" },
  ],
  datastores: [
    { id: "prod-db", crown: true, software: "PostgreSQL 13", role: "Customer database" },
    { id: "backups", crown: false, software: "S3-compatible bucket", role: "Backups" },
  ],
  edges: [
    ["lb-public", "web-app"], ["web-app", "api"], ["api", "prod-db"], ["api", "backups"],
    ["vpn", "jump-host"], ["jump-host", "prod-db"], ["old-batch", "prod-db"],
  ],
  findings: [
    { host: "lb-public", cve: "CVE-2021-23017", cvss: 8.1, product: "nginx", summary: "Off-by-one in the nginx DNS resolver" },
    { host: "web-app", cve: "CVE-2022-24999", cvss: 7.5, product: "qs", summary: "Prototype pollution in qs" },
    { host: "api", cve: "CVE-2021-44228", cvss: 10.0, product: "Apache Log4j 2", summary: "Log4Shell remote code execution" },
    { host: "vpn", cve: "CVE-2018-9207", cvss: 7.5, product: "OpenVPN", summary: "Example finding on the VPN" },
    { host: "jump-host", cve: "CVE-2018-15473", cvss: 5.3, product: "OpenSSH", summary: "Username enumeration" },
    { host: "old-batch", cve: "CVE-2014-6271", cvss: 9.8, product: "GNU Bash", summary: "Shellshock" },
  ],
};
