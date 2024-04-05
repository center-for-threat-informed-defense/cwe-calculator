# CWE with Environmental CVSS Calculator

The Environmental CWE CVSS Calculator (ec3) is used to calculate a potential CVSS score
for a provided CWE
Identifier. Data from the [National Vulnerability Database](https://nvd.nist.gov/) (NVD)
is pulled via the 2.0 API and
stored for later re-use. Optional target date range parameters may be provided to limit
the scope of obtained data.

This work was inspired by the methodologies used for calculating the
[CWE Top 25](https://cwe.mitre.org/top25/archive/2023/2023_methodology.html)

[![codecov](https://codecov.io/gh/center-for-threat-informed-defense/cwe-calculator/graph/badge.svg?token=3RTp6e74Oh)](https://codecov.io/gh/center-for-threat-informed-defense/cwe-calculator)

**Table Of Contents:**

- [Getting Started](#getting-started)
- [Getting Involved](#getting-involved)
- [Questions and Feedback](#questions-and-feedback)
- [How Do I Contribute?](#how-do-i-contribute)
- [Notice](#notice)

## Getting Started

Developers would first look to obtain an API key from
the [NVD website](https://nvd.nist.gov/developers/request-an-api-key).
Obtaining an API key enables improved performance during queries by raising the rate
limits set by NVD.
An API key may be provided to ec3 using the `--key` or `--keyfile` parameters.

The user is encouraged to
research [CWE-1003](https://cwe.mitre.org/data/definitions/1003.html)
("Weaknesses for Simplified Mapping of Published Vulnerabilities"). This View is used by
NVD for most of their
provided mappings and is more likely to be used.

### Installing ec3

From your local directory containing ec3, use one of the following commands to install
the required dependencies:

#### Installing with poetry

`poetry install`

#### Installing with pip

From your local directory containing ec3, run the following command to install the
required dependencies:

`pip install .`

### Running ec3

You may see all the available command line flags by running the following from the
project root:

`ec3-cli --help`

The two sub-commands are `calculate` and `update`. See their respective `--help` menus
for more information.

Some examples of common commands would include:

** Downloading a set of NVD data **

`ec3-cli update`

`ec3-cli update --keyfile [path_to_key] --start-date 2023-01-01 --end-date 2024-01-01`

** Running CWE-only query **

`ec3-cli calculate 787`

`ec3-cli calculate 121 -v`

** Running more advanced queries such as normalization or modifying metrics **

`ec3-cli calculate 121 --normalize_file ./data/normalized.csv -v`

`ec3-cli calculate 787 -e U -mpr H -v`

### Understanding the Process

The CVSS Calculator uses the following methodology when providing potential CVSS scores:

Pre-requisites:

- The desired environmental and temporal CVSS v3.1 metrics have been
  provided.
- A valid CWE Identifier has been provided.

If normalization was requested, a simple lookup is performed to determine whether a
higher-level CWE ID might be more applicable. This new value replaces the requested CWE
Identifier.

For each CVE Record that contains a CVSS v3.1 base score:

- Apply the environmental and temporal metrics to the base CVSS.
- Associate the CVE Record ID and CVSS metrics to each related CWE Identifier.

When calculating the results for a specific CWE Identifier:

- Provide the projected CVSS score from the environmental+temporal+base CVSS
  calculation (See 'CVSS Equations' in resource table below).
    - This is a statistical mean of all numeric CVSS scores.
- Provide min/max/average/stdev from the base CVSS calculation.
- Additionally list each CVE Record associated with the CWE Identifer.

| Resource                                                                                     | Description                                                                      |
|----------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| [NVD API Request](https://nvd.nist.gov/developers/request-an-api-key)                        | The form for developers to request an API key.                                   |
| [NVD API Rate Limits](https://nvd.nist.gov/developers/start-here#divRateLimits)              | Description of the NVD API rate limits                                           |
| [CVSS Equations](https://www.first.org/cvss/v3.1/specification-document#CVSS-v3-1-Equations) | CVSS 3.1 Base/Temporal/Environmental Metrics Equations                           |
| [CWE-1003](https://cwe.mitre.org/data/definitions/1003.html)                                 | CWE View 1003 ("Weaknesses for Simplified Mapping of Published Vulnerabilities") |

## Getting Involved

There are several ways that you can get involved with this project and help
advance threat-informed defense:

- Join the MITRE Engenuity Center for Threat Informed
  Defense [Discourse channel](https://center-for-threat-informed-defense.discourse.group/)

## Questions and Feedback

Please submit issues for any technical questions/concerns or contact
[ctid@mitre-engenuity.org](mailto:ctid@mitre-engenuity.org?subject=Question%20about%20cwe-calculator)
directly for more general inquiries.

Also see the guidance for contributors if are you interested in contributing or simply
reporting issues.

## How Do I Contribute?

We welcome your feedback and contributions to help advance
CWE with Environmental CVSS Calculator. Please see the guidance for contributors if are
you
interested in [contributing or simply reporting issues.](/CONTRIBUTING.md)

Please submit
[issues](https://github.com/center-for-threat-informed-defense/cwe-calculator/issues)
for
any technical questions/concerns or contact
[ctid@mitre-engenuity.org](mailto:ctid@mitre-engenuity.org?subject=subject=Question%20about%20cwe-calculator)
directly for more general inquiries.

## Notice

<!-- TODO Add PRS prior to publication. -->

Copyright 2024 MITRE Engenuity. Approved for public release. Document number
REPLACE_WITH_PRS_NUMBER

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
