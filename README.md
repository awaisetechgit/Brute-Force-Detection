# Incident Response Case Study: Brute-Force Attempts on Azure VMs

## 🕵️‍♂️ Incident Overview

We conducted an investigation after identifying **16 virtual machines (VMs)** targeted by brute-force attacks originating from **12 public IP addresses**.

### Objective

Determine whether the brute-force attempts led to any **successful logons**, and if so, assess the extent of the compromise.

---

## Analysis

### Initial Query: Successful Logons from Suspicious IPs


```sql
DeviceLogonEvents
| where RemoteIP in ("92.53.90.248", "194.180.49.127", "185.243.96.116", "185.243.96.107", "185.156.73.169", "178.128.95.238", "154.94.234.47", "148.72.141.37", "141.98.11.143", "10.0.0.8")
| where ActionType != "LogonFailed"
| summarize count() by RemoteIP, AccountName
| order by count_ desc
```

This query revealed potential successful logons from the IPs. To further analyze devices, accounts, and logon types, we refined the query.

### Refined Query: Detailed Logon Activity

```sql
DeviceLogonEvents
| where RemoteIP in ("92.53.90.248", "194.180.49.127", "185.243.96.116", "185.243.96.107", "185.156.73.169", "178.128.95.238", "154.94.234.47", "148.72.141.37", "141.98.11.143", "10.0.0.8")
| where ActionType != "LogonFailed"
| summarize LoginCount = count(), FirstLogin = min(TimeGenerated), LastLogin = max(TimeGenerated) by DeviceName, AccountName, LogonType, RemoteIP
| order by LastLogin desc

```

---

## Key Findings

- **No successful logons from public IPs** — all brute-force attempts failed.
- **All successful logons were from internal IP `10.0.0.8`**, using the **"Network" LogonType**.
- This internal activity is unusual and **requires further investigation** to rule out insider threats or misconfigurations.

---

## Containment Measures

To mitigate risk, the following actions were taken:

- **Device Isolation**: All 16 affected VMs were **isolated in Microsoft Defender for Endpoint (MDE)**.
- **AV Scan**: Comprehensive **antivirus scans initiated via MDE** on each isolated device.
- **NSG Hardening**: Updated **Network Security Groups to block all RDP access from the public internet**.
- **Policy Enforcement Proposal**: Suggested enforcing strict NSG rules for **all VMs** moving forward to improve baseline security.

---

## Conclusion

While no external compromise occurred, the unusual internal activity suggests the need for deeper internal monitoring and proactive threat hunting. This case highlights the importance of layered defenses and monitoring even for internal traffic.
