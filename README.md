[![codecov](https://codecov.io/gh/center-for-threat-informed-defense/cwe-calculator/graph/badge.svg)](https://codecov.io/gh/center-for-threat-informed-defense/cwe-calculator)

# CWE with Environmental CVSS Calculator

The CWE with Environmental CVSS Calculator computes an average CVSS score for the CVEs
associated with a given CWE, which serves as an estimate of its severity. The
calculation uses data from the [National Vulnerability Database
(NVD)](https://nvd.nist.gov/). You can customize the calculator in several ways,
including timeboxing, CWE normalization, and supplying CVSS environmental modifiers.

**Table Of Contents:**

- [Getting Started](#getting-started)
- [Getting Involved](#getting-involved)
- [Questions and Feedback](#questions-and-feedback)
- [Notice](#notice)

## Getting Started

| Resource                                                                                                         | Description                                                                                  |
| ---------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| [Command Line Tool](https://github.com/center-for-threat-informed-defense/cwe-calculator/wiki/Command-Line-Tool) | Learn about the command line interface for the CWE calculator.                               |
| [Web Service](https://github.com/center-for-threat-informed-defense/cwe-calculator/wiki/Web-Service)             | Learn about the web service form of the calculator that you can host in your own datacenter. |

## Getting Involved

There are several ways that you can get involved with this project and help
advance threat-informed defense:

- **Run the command line tool.** Try using the command line tool to score CWEs using
  your own CVSS environmental modifiers.
- **Learn about the web service.** You can run the web service on-prem in support of
  CI/CD platforms.


## Questions and Feedback

Please submit [issues on
GitHub](https://github.com/center-for-threat-informed-defense/cwe-calculator/issues) for
any technical questions or requests. You may also contact
[ctid@mitre-engenuity.org](mailto:ctid@mitre-engenuity.org?subject=Question%20about%20cwe-calculator)
directly for more general inquiries about the Center for Threat-Informed Defense.

We welcome your contributions to help advance CWE with Environmental CVSS Calculator in
the form of [pull
requests](https://github.com/center-for-threat-informed-defense/cwe-calculator/pulls).
Please review the [contributor
notice](https://github.com/center-for-threat-informed-defense/cwe-calculator/blob/main/CONTRIBUTING.md)
before making a pull request.

## Notice

© 2024 MITRE Engenuity. Approved for public release. Document number(s) CT0119.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
