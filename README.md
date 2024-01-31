# CWE with Environmental CVSS Calculator

The Environmental CWE CVSS Calculator (ec3) is used to calculate a mean CVSS score for a provided CWE Identifier. 
Data from the [National Vulnerability Database](https://nvd.nist.gov/) (NVD) is pulled via the 2.0 API and stored for later re-use.
Optional target date range parameters may be provided to limit the scope of obtained data.

This work was inspired by the methodologies used for calculating the 
[CWE Top 25](https://cwe.mitre.org/top25/archive/2023/2023_methodology.html)

**Table Of Contents:**

- [Getting Started](#getting-started)
- [Getting Involved](#getting-involved)
- [Questions and Feedback](#questions-and-feedback)
- [How Do I Contribute?](#how-do-i-contribute)
- [Notice](#notice)

## Getting Started

Developers would first look to obtain an API key from the [NVD website](https://nvd.nist.gov/developers/request-an-api-key).
Obtaining an API key enables improved performance during queries by raising the rate limits set by NVD. 
An API key may be provided to ec3 using the `--key` or `--keyfile` parameters.
The user is encouraged to research [CWE-1003](https://cwe.mitre.org/data/definitions/1003.html) 
("Weaknesses for Simplified Mapping of Published Vulnerabilities"). This View is used by NVD for most of their 
provided mappings and is more likely to appear




| Resource        | Description              |
| --------------- | ------------------------ |
| [Resource 1](#) | Description of resource. |
| [Resource 2](#) | Description of resource. |
| [Resource 3](#) | Description of resource. |

<!--
## Getting Involved

There are several ways that you can get involved with this project and help
advance threat-informed defense:

- **Way to get involved 1.** 
- **Way to get involved 2.** Contribute to the [nvdlib](https://github.com/Vehemont/nvdlib) project.
-->

## Questions and Feedback

Please submit issues for any technical questions/concerns or contact
[ctid@mitre-engenuity.org](mailto:ctid@mitre-engenuity.org?subject=Question%20about%20cwe-calculator)
directly for more general inquiries.

Also see the guidance for contributors if are you interested in contributing or simply
reporting issues.

## How Do I Contribute?

We welcome your feedback and contributions to help advance
CWE with Environmental CVSS Calculator. Please see the guidance for contributors if are you
interested in [contributing or simply reporting issues.](/CONTRIBUTING.md)

Please submit
[issues](https://github.com/center-for-threat-informed-defense/cwe-calculator/issues) for
any technical questions/concerns or contact
[ctid@mitre-engenuity.org](mailto:ctid@mitre-engenuity.org?subject=subject=Question%20about%20cwe-calculator)
directly for more general inquiries.

## Notice

<!-- TODO Add PRS prior to publication. -->

Copyright 2024 MITRE Engenuity. Approved for public release. Document number REPLACE_WITH_PRS_NUMBER

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
