# OWASP TOP 10 Risks (2021) by Kyrillos Nady

- **Date:** 2/1/2024
- **Topic:** [OWASP TOP 10 Risks (2021)](https://owasp.org/Top10/)
- **LinkedIn:** [Kyrillos Nady](https://www.linkedin.com/in/kyrillos-nady-804003297)
- **References:**
  - [TryHackMe OWASP TOP 10 Room](https://tryhackme.com/room/owasptop102021)
  - [OWASP TOP 10 Documentation](https://owasp.org/Top10/)

---

## OWASP TOP 10 Risks (2021):

1. **Broken Access Control**
2. **Cryptographic Failures**
3. **Injection**
4. **Insecure Design**
5. **Security Misconfiguration**
6. **Vulnerable and Outdated Components**
7. **Identification and Authentication Failures**
8. **Software and Data Integrity Failures**
9. **Security Logging & Monitoring Failures**
10. **Server-Side Request Forgery (SSRF)**

---

### 1. Broken Access Control:

Websites often have protected pages for specific users. If regular visitors can access these protected pages, it indicates broken access control. Consequences include:

- Viewing sensitive information from other users.
- Accessing unauthorized functionality.

---

### 2. Cryptographic Failures:

Cryptographic failures result from the misuse or absence of cryptographic algorithms, leading to vulnerabilities in confidentiality. Examples include encrypting data in transit and at rest. Cryptographic failures can expose sensitive data, requiring protection against techniques like "Man in The Middle Attacks."

---

### 3. Injection:

Injection flaws occur when user-controlled input is treated as commands or parameters. Examples include:

- **SQL Injection:** Manipulating SQL queries to access, modify, or delete database information.
- **Command Injection:** Executing arbitrary system commands on application servers.

Defenses include using allow lists and stripping input to prevent unauthorized execution of queries or commands.

---

### 4. Insecure Design:

Insecure design vulnerabilities stem from flawed application architecture during planning or implementation. Examples include insecure password resets, as seen in the Instagram incident.

---

### 5. Security Misconfiguration:

Security misconfigurations happen when security settings could have been appropriately configured but weren't. This includes poorly configured permissions, unnecessary features enabled, default accounts with unchanged passwords, and exposing debugging interfaces.

---

### 6. Vulnerable and Outdated Components:

Companies using outdated or vulnerable software are at risk. Attackers exploit known vulnerabilities, requiring vigilant monitoring and regular updates to prevent potential attacks.

---

### 7. Identification and Authentication Failures:

Authentication and session management are crucial. Flaws, such as brute force attacks and weak credentials, can lead to unauthorized access. Implementing multi-factor authentication is a recommended defense.

---

### 8. Software and Data Integrity Failures:

Integrity ensures data remains unmodified. Software integrity failures result from using external libraries without integrity checks. Data integrity failures can occur in web applications relying on session tokens. Utilizing mechanisms like Subresource Integrity (SRI) and JSON Web Tokens (JWT) can prevent such failures.

---

### 9. Security Logging & Monitoring Failures:

Logging every user action is vital for tracing and determining the impact of an incident. Monitoring detects suspicious activities, and it's essential to rate them according to their impact level for a timely response.

---

### 10. Server-Side Request Forgery (SSRF):

SSRF vulnerabilities arise when an attacker coerces a web application to send requests on their behalf. Exploiting third-party services, attackers can gain unauthorized access, enumerate internal networks, and even achieve remote code execution.

---
