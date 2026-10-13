# AI-Based DNS Attack Detection System
### Intelligent Detection of DNS Tunneling, Amplification, and Cache Poisoning Attacks

## 1. Project Overview

The **AI-Based DNS Attack Detection System** is a Computer Networks and cybersecurity project that aims to identify suspicious activities targeting the Domain Name System (DNS).

Whenever we visit a website, such as `www.google.com`, our computer needs to find the IP address associated with that domain name. DNS performs this task, allowing us to use easy-to-remember website names instead of numerical IP addresses.

However, attackers can misuse or manipulate DNS communication to hide information, overwhelm servers, or redirect users to incorrect destinations.

This project aims to analyse DNS network traffic and identify three types of attacks:

1. DNS Tunneling
2. DNS Amplification
3. DNS Cache Poisoning

The proposed system will combine network traffic analysis, machine learning and DNS security checks to identify suspicious behaviour. A dashboard will display detection results, supporting evidence and performance statistics.

**Project status:** Initial setup and research phase. The detection methods, datasets and final implementation are yet to be established.

---

## 2. Understanding DNS in Simple Terms

Imagine that the internet is a city and websites are buildings.

Every building has an address, but people usually remember the building's name rather than its complete address.

DNS works like an internet phonebook. It translates a domain name into the IP address needed to reach the correct server.

### Example: How DNS works

1. A user enters `www.example.com` in a browser.
2. The computer sends a DNS query asking for the website's IP address.
3. A DNS resolver finds the required information.
4. The resolver returns the IP address.
5. The browser connects to the website's server.

### Simple diagram

```text
User opens a website
         |
         v
DNS query for the domain
         |
         v
DNS resolver finds the IP
         |
         v
IP address returned
         |
         v
Browser connects to website
```

DNS is essential for everyday internet usage. If DNS is attacked, the consequences can include information theft, service disruption and incorrect website redirection.

---

## 3. The Problem We Are Addressing

DNS was designed primarily to help computers locate services on a network. However, attackers can exploit weaknesses in DNS configurations, resolver behaviour and traffic patterns.

Many DNS requests are legitimate, and suspicious activity can sometimes resemble normal network behaviour. Therefore, identifying attacks accurately is a challenging problem.

This project investigates whether network traffic analysis, machine learning and DNS-specific security checks can help distinguish legitimate DNS activity from malicious behaviour.

The system will focus on three different attack categories, each of which requires a different detection strategy.

---

## 4. The Three DNS Attacks

### 4.1 DNS Tunneling

**What is it?**

DNS tunneling involves hiding data inside DNS queries or responses to create a communication channel through DNS.

**Simple example:**

Imagine someone secretly sending information inside messages that appear to be ordinary requests for website addresses.

An attacker may encode data into unusual domain-name strings and use DNS communication to transfer information to an external server.

**Why is it dangerous?**

- It may be used to steal confidential information.
- It may allow malware to communicate with an external server.
- It can be difficult to identify when the traffic resembles legitimate DNS requests.

**What will our system investigate?**

- Unusually long domain names.
- Unusual character patterns or high-entropy strings.
- Unexpected query frequencies.
- Repeated or suspicious communication patterns.

Machine learning may help identify combinations of these characteristics that differ from normal DNS activity.

### 4.2 DNS Amplification Attack

**What is it?**

DNS amplification is a type of distributed denial-of-service (DDoS) attack in which attackers exploit DNS servers to direct large amounts of traffic towards a victim.

A DDoS attack attempts to make a website, server or network unavailable by overwhelming it with traffic.

**Simple example:**

Imagine someone sending a small request to a service that responds with a much larger message, while making the response go to an unsuspecting victim.

By repeating this process, the attacker can cause a large volume of unwanted traffic to reach the victim.

**Why is it dangerous?**

- It can overwhelm network bandwidth.
- It can make services slow or unavailable.
- It can consume server and network resources.

**What will our system investigate?**

- Unusual DNS traffic rates.
- Large volumes of DNS responses.
- Request-response size patterns.
- Abnormal traffic flows involving DNS servers and potential victims.

The system will investigate whether these characteristics can help distinguish amplification attacks from legitimate traffic bursts.

### 4.3 DNS Cache Poisoning

**What is it?**

DNS cache poisoning occurs when false DNS information is inserted into a DNS resolver's cache.

A cache temporarily stores DNS results so that repeated requests can be answered faster.

**Simple example:**

Imagine that a phonebook contains the wrong phone number for a person. Whenever someone looks up that person's name, they receive the incorrect number.

Similarly, a poisoned DNS cache may associate a legitimate domain with an incorrect IP address.

**Why is it dangerous?**

- Users may be redirected to malicious websites.
- Attackers may attempt to impersonate legitimate services.
- Incorrect DNS records may affect multiple users of the same resolver.

**What will our system investigate?**

- Unexpected changes in DNS records.
- Inconsistent DNS responses.
- Differences between cached records and trusted authoritative DNS information.
- Other suspicious resolver behaviour.

This attack may require DNS record integrity checks and resolver-level information in addition to machine learning. Packet-level traffic alone may not provide enough evidence to detect every poisoning attempt.

---

## 5. Project Objectives

The main objectives of this project are:

1. **Understand DNS traffic:** Study how DNS queries and responses behave during normal communication.
2. **Collect suitable data:** Identify publicly available datasets and capture traffic in a controlled laboratory environment.
3. **Extract useful features:** Analyse domain names, packet sizes, query frequency, response patterns and other relevant characteristics.
4. **Develop detection methods:** Investigate machine-learning models for traffic classification and complementary checks for DNS integrity.
5. **Detect three attack categories:** Develop and evaluate methods for DNS tunneling, DNS amplification and DNS cache poisoning.
6. **Evaluate performance:** Measure precision, recall, F1-score, false-positive rate and detection latency where applicable.
7. **Build a dashboard:** Display suspicious traffic, attack classifications, supporting evidence and evaluation results.
8. **Study limitations:** Investigate false alarms, previously unseen attacks and the limitations of the available datasets and detection methods.

These are planned objectives. Their successful completion will depend on the research findings, available data and implementation results.

---

## 6. Proposed System Architecture

The system is planned as a pipeline that collects DNS traffic, analyses it and presents its findings.

```text
       DNS DATA SOURCES
               |
               v
   Dataset / Packet Captures
               |
               v
       Traffic Processing
               |
               v
       Feature Extraction
               |
               v
        Detection Engine
          /     |      \
         /      |       \
        v       v        v
    Tunneling Amplification Cache
    Detection  Detection  Poisoning
                         Checks
         \       |       /
          \      |      /
           v     v     v
          Alert Generation
                 |
                 v
          Dashboard & Reports
```

### Planned components

**1. Data collection**

Obtain suitable labelled datasets and controlled packet captures containing normal and relevant suspicious DNS traffic.

**2. Traffic processing**

Read DNS packet captures or dataset records and prepare the data for analysis.

**3. Feature extraction**

Convert network observations into measurable characteristics that detection algorithms can analyse.

**4. Detection engine**

Use machine-learning models where appropriate, together with attack-specific detection logic and DNS integrity checks.

**5. Alert generation**

Produce alerts containing the suspected attack category and the evidence supporting the decision.

**6. Dashboard**

Present alerts, traffic summaries, evaluation metrics and visualisations through a simple interface.

This architecture is a proposed design and may be refined after reviewing the research papers.

---

## 7. Technology Stack

The following technologies are being considered for implementation.

| Technology | Planned purpose |
|---|---|
| Python | Main programming language |
| Visual Studio Code | Development environment |
| Wireshark | Inspect and capture network packets |
| Scapy | Read and process packet data |
| Pandas | Organise and analyse datasets |
| NumPy | Numerical computations |
| Scikit-learn | Train and evaluate machine-learning models |
| Matplotlib and Seaborn | Visualise traffic patterns and evaluation results |
| Streamlit | Develop the dashboard |
| Git and GitHub | Version control and project collaboration |

The final technology stack will be selected based on compatibility, dataset requirements and the results of the research phase.

---

## 8. Dataset and Research Plan

The system requires data representing legitimate DNS traffic and relevant attack behaviour.

Potential data sources include:

- Publicly available DNS tunneling and exfiltration datasets.
- DNS traffic datasets suitable for studying amplification attacks.
- Controlled DNS resolver experiments for investigating cache poisoning.
- Benign DNS packet captures collected in an authorised laboratory environment.

A dataset containing one attack type will not automatically be sufficient to train a detector for all three attacks.

Before selecting the final datasets, we will examine:

- The number of records and packet captures available.
- The labels and attack categories represented.
- The features provided by the dataset.
- Whether the data contains enough information to support the intended detection method.
- Whether independent testing data is available.
- Whether the dataset realistically represents the traffic conditions we want to detect.

The datasets, model choices and final experimental design remain to be confirmed.

---

## 9. Evaluation and Performance Measurement

A successful system must be evaluated using evidence rather than simply demonstrating that the code runs.

The following metrics will be considered:

**Accuracy:** The proportion of all predictions that are correct.

**Precision:** Among the activities flagged as attacks, how many are actually attacks?

**Recall:** Among the attacks present in the test data, how many does the system detect?

**F1-score:** A combined measure of precision and recall.

**False-positive rate:** How often legitimate activity is incorrectly flagged as malicious.

**Detection latency:** How long the system takes to identify suspicious activity.

We will also examine confusion matrices and compare suitable baseline methods with our proposed approach.

Results will be reported separately for each attack category wherever the available data supports reliable evaluation. No performance figures will be claimed until experiments have been conducted.

---

## 10. Expected Outcomes

The intended outcome is a working prototype that can:

- Analyse DNS traffic from supported data sources.
- Identify suspicious DNS patterns.
- Investigate DNS tunneling and amplification using suitable detection methods.
- Check DNS record consistency for potential cache poisoning.
- Display alerts with understandable supporting evidence.
- Report model performance and limitations.
- Demonstrate the relationship between Computer Networks concepts and practical network security.

The project is intended to support detection and analysis. It is not assumed to prevent every attack or replace existing network security systems.

---

## 11. Connection to the Computer Networks Course

This project applies concepts from the Computer Networks syllabus:

- **Module 1 — Networking Foundations:** Protocols, encapsulation, network architecture and performance metrics.
- **Module 3 — Internetworking:** IP addressing, packet forwarding and routing.
- **Module 4 — End-to-End Protocols:** UDP, TCP and transport-layer communication.
- **Module 5 — End-to-End Data:** DNS, security attacks, trust, threats and firewalls.

The primary connection is Module 5 because the project investigates DNS and network security. Other modules help explain how DNS traffic travels across a network and how we analyse its behaviour.

---

## 12. Project Development Roadmap

The project will be developed in stages:

1. **Research and planning:** Study DNS attacks, review related research papers and identify the research gap.
2. **Environment setup:** Prepare the Python environment and development tools.
3. **Data collection:** Obtain suitable datasets and controlled packet captures.
4. **Exploratory analysis:** Examine traffic characteristics and select useful features.
5. **Detection development:** Build and evaluate attack-specific detection methods.
6. **Integration:** Combine the detection components into one system.
7. **Dashboard development:** Display alerts and evaluation results.
8. **Testing:** Evaluate detection performance, false alarms and limitations.
9. **Documentation and demonstration:** Prepare the final report, presentation and working demonstration.

Each stage will be completed and tested before moving to the next.

---

## 13. Safety and Responsible Testing

All experiments will be conducted using authorised datasets, owned systems or controlled laboratory environments.

The project will not involve attacking public DNS resolvers, poisoning third-party caches or directing unwanted traffic at external systems.

Any attack simulations will be isolated and designed for defensive testing.

---

## 14. Current Project Status

**Current stage: Initial setup and research.**

The project folder and initial Python entry point are being prepared. Research paper analysis, dataset selection, detection implementation and model evaluation remain pending.

The next priority is to understand the existing research and determine which detection approaches are practical to implement and evaluate.

---

## Conclusion

The AI-Based DNS Attack Detection System aims to combine Computer Networks concepts, traffic analysis, machine learning and DNS security checks into one explainable monitoring framework.

By studying three different DNS attack categories, the project investigates how suspicious network behaviour can be identified and how detection results can be presented in a way that is understandable to both technical and non-technical users.

The ultimate goal is to develop a research-backed, measurable and demonstrable prototype rather than merely a theoretical description of DNS attacks.
