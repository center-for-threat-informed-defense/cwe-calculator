"""Utility class to handle CVSS structures and calculations.

Currently only supports the CVSS 3.1 format via the Cvss31 class.

Typical usage example:
    // Assumes a single record from pulled NVD API data is assigned to variable 'cve'
    base_cvss = Cvss31.from_cve(cve=cve)
    // Update an environmental metric (e.g., modified confidentiality)
    base_cvss.set_mc("L")
    base_score = base_cvss.get_base_score(),
    base_cvss.
    cvss_data.get_environmental_score(),

Copyright (c) 2024 The MITRE Corporation. All rights reserved.
"""

import logging
import math

from nvdlib import classes as nvd_classes  # type: ignore

logger = logging.getLogger(__name__)


class Cvss31:
    """Set individual fields covering the CVSS 3.1 model (base/temporal/environmental).

    All fields should be represented by the uppercase shorthand letter value internally.
    Some long form values are accepted in multiple representations due to differences
    between the specification documentation and the NVD API return results.

    Values sourced from:
        https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.1.json
        https://www.first.org/cvss/v3.1/specification-document
    """

    __version: str = "3.1"
    AV_LOOKUP: dict[str, float] = {
        "N": 0.85,
        "A": 0.62,
        "L": 0.55,
        "P": 0.2,
        "X": 1,
    }
    AC_LOOKUP: dict[str, float] = {
        "L": 0.77,
        "H": 0.44,
        "X": 1,
    }
    PR_CHANGED_LOOKUP: dict[str, float] = {
        "N": 0.85,
        "L": 0.68,
        "H": 0.5,
        "X": 1,
    }
    PR_UNCHANGED_LOOKUP: dict[str, float] = {
        "N": 0.85,
        "L": 0.62,
        "H": 0.27,
        "X": 1,
    }
    UI_LOOKUP: dict[str, float] = {
        "N": 0.85,
        "R": 0.62,
        "X": 1,
    }
    ISS_LOOKUP: dict[str, float] = {"H": 0.56, "L": 0.22, "N": 0, "X": 1}
    E_LOOKUP: dict[str, float] = {
        "X": 1,
        "H": 1,
        "F": 0.97,
        "P": 0.94,
        "U": 0.91,
    }
    RL_LOOKUP: dict[str, float] = {
        "X": 1,
        "U": 1,
        "W": 0.97,
        "T": 0.96,
        "O": 0.95,
    }
    RC_LOOKUP: dict[str, float] = {
        "X": 1,
        "C": 1,
        "R": 0.96,
        "U": 0.92,
    }
    ENVIRONMENTAL_REQ_LOOKUP: dict[str, float] = {
        "X": 1,
        "H": 1.5,
        "M": 1,
        "L": 0.5,
    }

    def __init__(
        self,
        av: str = "X",
        ac: str = "X",
        pr: str = "X",
        ui: str = "X",
        s: str = "X",
        c: str = "X",
        i: str = "X",
        a: str = "X",
        e: str = "X",
        rl: str = "X",
        rc: str = "X",
        cr: str = "X",
        ir: str = "X",
        ar: str = "X",
        mav: str = "X",
        mac: str = "X",
        mpr: str = "X",
        mui: str = "X",
        ms: str = "X",
        mc: str = "X",
        mi: str = "X",
        ma: str = "X",
    ) -> None:
        """Initialize default values, validate all fields passed in through individual
        setter functions.

        Accepts shorthand character or case-insensitive full text representation.
        (e.g. 'N'/'NETWORK'/'network' for AV field)

        Args:
            //Base exploitability/impact metrics.
            //Note: The default value of "X" will throw a ValueError during setting.
            av: Attack Vector (AV)
            ac: Attack Complexity (AC)
            pr: Privileges Required (PR)
            ui: User Interaction (UI)
            s: Scope (S)
            c: Confidentiality (C)
            i: Integrity (I)
            a: Availability (A)

            //Temporal metrics:
            e: Exploit Code Maturity (E)
            rl: Remediation Level (RL)
            rc: Report Confidence (RC)

            //Environmental metrics:
            cr: Confidentiality Requirement (CR)
            ir: Integrity Requirement (IR)
            ar: Availability Requirement (AR)
            mav: Modified Attack Vector (MAV)
            mac: Modified Attack Complexity (MAC)
            mpr: Modified Privileges Required (MPR)
            mui: Modified User Interaction (MUI)
            ms: Modified Scope (MS)
            mc: Modified Confidentiality (MC)
            mi: Modified Integrity (MI)
            ma: Modified Availability (MA)

        Returns:
            A NvdCollector instance with the default/specified dates adjusted to valid
                ranges. The api_key will be stored for later use when calling the API.

        Raises:
            ValueError: An invalid metric modifier was used during assignment.
        """
        self.av: str = ""
        self.ac: str = ""
        self.pr: str = ""
        self.ui: str = ""
        self.s: str = ""
        self.c: str = ""
        self.i: str = ""
        self.a: str = ""

        self.e: str = "X"
        self.rl: str = "X"
        self.rc: str = "X"

        self.cr: str = "X"
        self.ir: str = "X"
        self.ar: str = "X"
        self.mav: str = "X"
        self.mac: str = "X"
        self.mpr: str = "X"
        self.mui: str = "X"
        self.ms: str = "X"
        self.mc: str = "X"
        self.mi: str = "X"
        self.ma: str = "X"

        try:
            self.set_av(av)
            self.set_ac(ac)
            self.set_pr(pr)
            self.set_ui(ui)
            self.set_s(s)
            self.set_c(c)
            self.set_i(i)
            self.set_a(a)

            self.set_e(e)
            self.set_rl(rl)
            self.set_rc(rc)

            self.set_cr(cr)
            self.set_ir(ir)
            self.set_ar(ar)
            self.set_mav(mav)
            self.set_mac(mac)
            self.set_mpr(mpr)
            self.set_mui(mui)
            self.set_ms(ms)
            self.set_mc(mc)
            self.set_mi(mi)
            self.set_ma(ma)

        except ValueError:
            logger.warning("Caught ValueError. Error while initializing Cvss31 values.")
            raise

    @classmethod
    def from_cve(cls, cve: nvd_classes.CVE):
        """Construct a Cvss31 instance using values obtained from a CVE record.

        Args:
            cve: A single CVE record.

        Returns:
            An instance of the cls Class using values obtained from a CVE object.

        Raises:
            ValueError: An invalid metric modifier was attempted during assignment.
        """
        try:
            return cls(
                av=cve.v31attackVector,
                ac=cve.v31attackComplexity,
                pr=cve.v31privilegesRequired,
                ui=cve.v31userInteraction,
                s=cve.v31scope,
                c=cve.v31confidentialityImpact,
                i=cve.v31integrityImpact,
                a=cve.v31availabilityImpact,
            )

        # An AttributeError caught here indicates no CVSS31 data, so a default Cvss31
        # initialization with unknown values ("X") would have raised a ValueError
        # during assignment.
        except (ValueError, AttributeError):
            logger.error(
                "Caught ValueError. "
                "Error while initializing Cvss31 values from CVE object."
            )
            raise ValueError

    def __repr__(self) -> str:
        """Returns the textual representation of the ec3 CVSS object.

        This is the full vector format.
        """
        return "'" + self.__str__() + "'"

    def __str__(self) -> str:
        """Returns the string representation of the ec3 CVSS object.

        This is the full vector format.
        """
        base_vector: str = (
            "CVSS:"
            + self.__version
            + "/"
            + "/".join(
                [
                    ":".join(["AV", self.av]),
                    ":".join(["AC", self.ac]),
                    ":".join(["PR", self.pr]),
                    ":".join(["UI", self.ui]),
                    ":".join(["S", self.s]),
                    ":".join(["C", self.c]),
                    ":".join(["I", self.i]),
                    ":".join(["A", self.a]),
                ]
            )
        )

        temporal_vector: str = (
            (f"/E:{self.e}" if self.e != "X" else "")
            + (f"/RL:{self.rl}" if self.rl != "X" else "")
            + (f"/RC:{self.rc}" if self.rc != "X" else "")
        )

        environmental_vector: str = (
            (f"/CR:{self.cr}" if self.cr != "X" else "")
            + (f"/IR:{self.ir}" if self.ir != "X" else "")
            + (f"/AR:{self.ar}" if self.ar != "X" else "")
            + (f"/MAV:{self.mav}" if self.mav != "X" else "")
            + (f"/MAC:{self.mac}" if self.mac != "X" else "")
            + (f"/MPR:{self.mpr}" if self.mpr != "X" else "")
            + (f"/MUI:{self.mui}" if self.mui != "X" else "")
            + (f"/MS:{self.ms}" if self.ms != "X" else "")
            + (f"/MC:{self.mc}" if self.mc != "X" else "")
            + (f"/MI:{self.mi}" if self.mi != "X" else "")
            + (f"/MA:{self.ma}" if self.ma != "X" else "")
        )

        return base_vector + temporal_vector + environmental_vector

    def set_av(self, av: str) -> None:
        """Set CVSS 3.1 Attack Vector (AV).

        Valid values: Network (N), Adjacent (A), Local (L), Physical (P)

        Args:
            av: String representing the desired value for the Attack Vector
                exploitability metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if av is None:
            raise ValueError(
                "Attack vector (AV) exploitability metric is not provided."
            )

        match av.upper():
            case "N" | "A" | "L" | "P":
                self.av = av
            case "NETWORK" | "ADJACENT" | "ADJACENT_NETWORK" | "LOCAL" | "PHYSICAL":
                self.av = av[0]
            case _:
                raise ValueError(
                    "Bad value provided for Attack vector (AV) exploitability metric."
                )

        return None

    def set_ac(self, ac: str) -> None:
        """Set CVSS 3.1 Attack Complexity (AC).

        Valid values: Low (L), High (H)

        Args:
            ac: String representing the desired value for the Attack Complexity
                exploitability metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if ac is None:
            raise ValueError(
                "Attack Complexity (AC) exploitability metric is not provided."
            )

        match ac.upper():
            case "L" | "H":
                self.ac = ac
            case "LOW" | "HIGH":
                self.ac = ac[0]
            case _:
                raise ValueError(
                    "Bad value provided for Attack Complexity (AC) "
                    "exploitability metric."
                )

        return None

    def set_pr(self, pr: str) -> None:
        """Set CVSS 3.1 Privileges Required (PR).

        Valid values: None (N), Low (L), High (H)

        Args:
            pr: String representing the desired value for the Privileges Required
                exploitability metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if pr is None:
            raise ValueError(
                "Privileges Required (PR) exploitability metric is not provided."
            )

        match pr.upper():
            case "N" | "L" | "H":
                self.pr = pr
            case "NONE" | "LOW" | "HIGH":
                self.pr = pr[0]
            case _:
                raise ValueError(
                    "Bad value provided for Privileges Required (PR) "
                    "exploitability metric."
                )

        return None

    def set_ui(self, ui: str) -> None:
        """Set CVSS 3.1 User Interaction (UI).

        Valid values: None (N), Required (R)

        Args:
            ui: String representing the desired value for the User Interaction
                exploitability metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if ui is None:
            raise ValueError(
                "User Interaction (UI) exploitability metric is not provided."
            )

        match ui.upper():
            case "N" | "R":
                self.ui = ui
            case "NONE" | "REQUIRED":
                self.ui = ui[0]
            case _:
                raise ValueError(
                    "Bad value provided for User Interaction (UI) "
                    "exploitability metric."
                )

        return None

    def set_s(self, s: str) -> None:
        """Set CVSS 3.1 Scope (S).

        Valid values: Unchanged (U), Changed (C)

        Args:
            s: String representing the desired value for the Scope exploitability
                metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if s is None:
            raise ValueError("Scope (S) exploitability metric is not provided.")

        match s.upper():
            case "U" | "C":
                self.s = s
            case "UNCHANGED" | "CHANGED":
                self.s = s[0]
            case _:
                raise ValueError(
                    "Bad value provided for Scope (S) exploitability metric."
                )

        return None

    def set_c(self, c: str) -> None:
        """Set CVSS 3.1 Confidentiality (C).

        Valid values: High (H), Low (L), None (N)

        Args:
            c: String representing the desired value for the Confidentiality
                impact metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if c is None:
            raise ValueError("Confidentiality (C) impact metric is not provided.")

        match c.upper():
            case "H" | "L" | "N":
                self.c = c
            case "HIGH" | "LOW" | "NONE":
                self.c = c[0]
            case _:
                raise ValueError(
                    "Bad value provided for Confidentiality (C) impact metric."
                )

        return None

    def set_i(self, i: str) -> None:
        """Set CVSS 3.1 Integrity (I).

        Valid values: High (H), Low (L), None (N)

        Args:
            i: String representing the desired value for the Integrity impact metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if i is None:
            raise ValueError("Integrity (I) impact metric is not provided.")

        match i.upper():
            case "H" | "L" | "N":
                self.i = i
            case "HIGH" | "LOW" | "NONE":
                self.i = i[0]
            case _:
                raise ValueError("Bad value provided for Integrity (I) impact metric.")

        return None

    def set_a(self, a: str) -> None:
        """Set CVSS 3.1 Availability (A).

        Valid values: High (H), Low (L), None (N)

        Args:
            a: String representing the desired value for the Availability impact metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if a is None:
            raise ValueError("Availability (A) impact metric is not provided.")

        match a.upper():
            case "H" | "L" | "N":
                self.a = a
            case "HIGH" | "LOW" | "NONE":
                self.a = a[0]
            case _:
                raise ValueError(
                    "Bad value provided for Availability (A) impact metric."
                )

        return None

    def set_e(self, e: str) -> None:
        """Set CVSS 3.1 Exploit Code Maturity (E).

        Valid values: Not Defined (X), High (H), Functional (F), Proof-of-Concept (P),
            Unproven (U)

        Args:
            e: String representing the desired value for the Exploit Code Maturity
                temporal metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if e is None:
            e = "X"

        match e.upper():
            case "X" | "H" | "F" | "P" | "U":
                self.e = e
            case (
                "HIGH"
                | "FUNCTIONAL"
                | "PROOF OF CONCEPT"
                | "PROOF-OF-CONCEPT"
                | "PROOF_OF_CONCEPT"
                | "UNPROVEN"
            ):
                self.e = e[0]
            case "NOT DEFINED" | "NOT_DEFINED":
                self.e = "X"
            case _:
                raise ValueError(
                    "Bad value provided for Exploit Code Maturity (E) temporal metric."
                )

        return None

    def set_rl(self, rl: str) -> None:
        """Set CVSS 3.1 Remediation Level (RL).

        Valid values: Not Defined (X), Unavailable (U), Workaround (W),
            Temporary Fix (T), Official Fix (O)

        Args:
            rl: String representing the desired value for the Remediation Level
                temporal metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if rl is None:
            rl = "X"

        match rl.upper():
            case "X" | "U" | "W" | "T" | "O":
                self.rl = rl
            case (
                "UNAVAILABLE"
                | "WORKAROUND"
                | "TEMPORARY FIX"
                | "TEMPORARY_FIX"
                | "OFFICIAL FIX"
                | "OFFICIAL_FIX"
            ):
                self.rl = rl[0]
            case "NOT DEFINED" | "NOT_DEFINED":
                self.rl = "X"
            case _:
                raise ValueError(
                    "Bad value provided for Remediation Level (RL) temporal metric."
                )

        return None

    def set_rc(self, rc: str) -> None:
        """Set CVSS 3.1 Report Confidence (RC).

        Valid values: Not Defined (X), Confirmed (C), Reasonable (R), Unknown (U)

        Args:
            rc: String representing the desired value for the Report Confidence
                temporal metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if rc is None:
            rc = "X"

        match rc.upper():
            case "X" | "C" | "R" | "U":
                self.rc = rc
            case "CONFIRMED" | "REASONABLE" | "UNKNOWN":
                self.rc = rc[0]
            case "NOT DEFINED" | "NOT_DEFINED":
                self.rc = "X"
            case _:
                raise ValueError(
                    "Bad value provided for Report Confidence (RC) temporal metric."
                )

        return None

    def set_cr(self, cr: str) -> None:
        """Set CVSS 3.1 Confidentiality Requirement (CR).

        Valid values: Not Defined (X), High (H), Medium (M), Low (L)

        Args:
            cr: String representing the desired value for the Confidentiality
                Requirement environmental metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if cr is None:
            cr = "X"

        match cr.upper():
            case "X" | "H" | "M" | "L":
                self.cr = cr
            case "HIGH" | "MEDIUM" | "LOW":
                self.cr = cr[0]
            case "NOT DEFINED" | "NOT_DEFINED":
                self.cr = "X"
            case _:
                raise ValueError(
                    "Bad value provided for Confidentiality Requirement (CR) "
                    "environmental metric."
                )

        return None

    def set_ir(self, ir: str) -> None:
        """Set CVSS 3.1 Integrity Requirement (IR).

        Valid values: Not Defined (X), High (H), Medium (M), Low (L)

        Args:
            ir: String representing the desired value for the Integrity Requirement
                environmental metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if ir is None:
            ir = "X"

        match ir.upper():
            case "X" | "H" | "M" | "L":
                self.ir = ir
            case "HIGH" | "MEDIUM" | "LOW":
                self.ir = ir[0]
            case "NOT DEFINED" | "NOT_DEFINED":
                self.ir = "X"
            case _:
                raise ValueError(
                    "Bad value provided for Integrity Requirement (IR) "
                    "environmental metric."
                )

        return None

    def set_ar(self, ar: str) -> None:
        """Set CVSS 3.1 Availability Requirement (AR).

        Valid values: Not Defined (X), High (H), Medium (M), Low (L)

        Args:
            ar: String representing the desired value for the Availability Requirement
                environmental metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if ar is None:
            ar = "X"

        match ar.upper():
            case "X" | "H" | "M" | "L":
                self.ar = ar
            case "HIGH" | "MEDIUM" | "LOW":
                self.ar = ar[0]
            case "NOT DEFINED" | "NOT_DEFINED":
                self.ar = "X"
            case _:
                raise ValueError(
                    "Bad value provided for Availability Requirement (AR) "
                    "environmental metric."
                )

        return None

    def set_mav(self, mav: str) -> None:
        """Set CVSS 3.1 Modified Attack Vector (MAV).

        Valid values: Not Defined (X), Network (N), Adjacent (A), Local (L),
            Physical (P)

        Args:
            mav: String representing the desired value for the Modified Attack Vector
                exploitability metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if mav is None:
            mav = "X"

        match mav.upper():
            case "X" | "N" | "A" | "L" | "P":
                self.mav = mav
            case "NETWORK" | "ADJACENT" | "LOCAL" | "PHYSICAL":
                self.mav = mav[0]
            case "NOT DEFINED" | "NOT_DEFINED":
                self.mav = "X"
            case _:
                raise ValueError(
                    "Bad value provided for Modified Attack vector (MAV) "
                    "environmental metric."
                )

        return None

    def set_mac(self, mac: str) -> None:
        """Set CVSS 3.1 Modified Attack Complexity (MAC).

        Valid values: Not Defined (X), Low (L), High (H)

        Args:
            mac: String representing the desired value for the Modified Attack
                Complexity environmental metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if mac is None:
            mac = "X"

        match mac.upper():
            case "X" | "L" | "H":
                self.mac = mac
            case "LOW" | "HIGH":
                self.mac = mac[0]
            case "NOT DEFINED" | "NOT_DEFINED":
                self.mac = "X"
            case _:
                raise ValueError(
                    "Bad value provided for Modified Attack Complexity (MAC) "
                    "environmental metric."
                )

        return None

    def set_mpr(self, mpr: str) -> None:
        """Set CVSS 3.1 Modified Privileges Required (MPR).

        Valid values: Not Defined (X), None (N), Low (L), High (H)

        Args:
            mpr: String representing the desired value for the Modified Privileges
                Required environmental metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if mpr is None:
            mpr = "X"

        match mpr.upper():
            case "X" | "N" | "L" | "H":
                self.mpr = mpr
            case "NONE" | "LOW" | "HIGH":
                self.mpr = mpr[0]
            case "NOT DEFINED" | "NOT_DEFINED":
                self.mpr = "X"
            case _:
                raise ValueError(
                    "Bad value provided for Modified Privileges Required (MPR) "
                    "environmental metric."
                )

        return None

    def set_mui(self, mui: str) -> None:
        """Set CVSS 3.1 Modified User Interaction (MUI).

        Valid values: Not Defined (X), None (N), Required (R)

        Args:
            mui: String representing the desired value for the Modified User
                Interaction environmental metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if mui is None:
            mui = "X"

        match mui.upper():
            case "X" | "N" | "R":
                self.mui = mui
            case "NONE" | "REQUIRED":
                self.mui = mui[0]
            case "NOT DEFINED" | "NOT_DEFINED":
                self.mui = "X"
            case _:
                raise ValueError(
                    "Bad value provided for Modified User Interaction (MUI) "
                    "environmental metric."
                )

        return None

    def set_ms(self, ms: str) -> None:
        """Set CVSS 3.1 Modified Scope (MS).

        Valid values: Not Defined (X), Unchanged (U), Changed (C)

        Args:
            ms: String representing the desired value for the Modified Scope
                environmental metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if ms is None:
            ms = "X"

        match ms.upper():
            case "X" | "U" | "C":
                self.ms = ms
            case "UNCHANGED" | "CHANGED":
                self.ms = ms[0]
            case "NOT DEFINED" | "NOT_DEFINED":
                self.ms = "X"
            case _:
                raise ValueError(
                    "Bad value provided for Modified Scope (MS) environmental metric."
                )

        return None

    def set_mc(self, mc: str) -> None:
        """Set CVSS 3.1 Modified Confidentiality (MC).

        Valid values: Not Defined (X), High (H), Low (L), None (N)

        Args:
            mc: String representing the desired value for the Modified Confidentiality
                impact metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if mc is None:
            mc = "X"

        match mc.upper():
            case "X" | "H" | "L" | "N":
                self.mc = mc
            case "HIGH" | "LOW" | "NONE":
                self.mc = mc[0]
            case "NOT DEFINED" | "NOT_DEFINED":
                self.mc = "X"
            case _:
                raise ValueError(
                    "Bad value provided for Modified Confidentiality (MC) "
                    "environmental metric."
                )

        return None

    def set_mi(self, mi: str) -> None:
        """Set CVSS 3.1 Modified Integrity (MI).

        Valid values: Not Defined (X), High (H), Low (L), None (N)

        Args:
            mi: String representing the desired value for the Modified Integrity
                environmental metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if mi is None:
            mi = "X"

        match mi.upper():
            case "X" | "H" | "L" | "N":
                self.mi = mi
            case "HIGH" | "LOW" | "NONE":
                self.mi = mi[0]
            case "NOT DEFINED" | "NOT_DEFINED":
                self.mi = "X"
            case _:
                raise ValueError(
                    "Bad value provided for Modified Integrity (MI) "
                    "environmental metric."
                )

        return None

    def set_ma(self, ma: str) -> None:
        """Set CVSS 3.1 Modified Availability (MA).

        Valid values: Not Defined (X), High (H), Low (L), None (N)

        Args:
            ma: String representing the desired value for the Modified Availability
                environmental metric.

        Returns:
            None

        Raises:
            ValueError: A missing or invalid value was attempted to be set for this
                metric.
        """

        if ma is None:
            ma = "X"

        match ma.upper():
            case "X" | "H" | "L" | "N":
                self.ma = ma
            case "HIGH" | "LOW" | "NONE":
                self.ma = ma[0]
            case "NOT DEFINED" | "NOT_DEFINED":
                self.ma = "X"
            case _:
                raise ValueError(
                    "Bad value provided for Modified Availability (MA) "
                    "environmental metric."
                )

        return None

    def base_valid(self) -> bool:
        """Determine whether the mandatory values for this CVSS are all present and
            have valid values.

        Table 15 from https://www.first.org/cvss/v3.1/specification-document, denotes
        the following as mandatory:

            Attack Vector (AV), Attack Complexity (AC), Privileges Required (PR),
            User Interaction (UI), Scope (S), Confidentiality (C), Integrity (I),
            Availability (A)

        Returns:
            True if all 8 base metrics are present and have valid values, or
                False otherwise.
        """

        # Validation occurs within the set_* functions to determine whether each value
        # is allowed.
        try:
            self.set_av(self.av)
            self.set_ac(self.ac)
            self.set_pr(self.pr)
            self.set_ui(self.ui)
            self.set_s(self.s)
            self.set_c(self.c)
            self.set_i(self.i)
            self.set_a(self.a)
            return True
        except ValueError:
            return False

    def get_base_score(self) -> float:
        """Calculate the CVSS 3.1 base score.

        If the base metric values are valid, calculate the base score according to the
        equations found in section 7.1 of :
            https://www.first.org/cvss/v3.1/specification-document

        This calculation uses values obtained from section 7.4 of:
            https://www.first.org/cvss/v3.1/specification-document

        Returns:
            The base score for the current CVSS class.

        Raises:
            ValueError: An invalid value was found among the base metrics.
        """

        # if self.base_valid(), then Scope (self.s) was set to "U" or "C" for the
        # following checks below
        if not self.base_valid():
            raise ValueError(
                "ValueError: Can not calculate base CVSS score when base values "
                "are not valid."
            )

        impact_sub_score: float = 1 - (1 - self.ISS_LOOKUP[self.c]) * (
            1 - self.ISS_LOOKUP[self.i]
        ) * (1 - self.ISS_LOOKUP[self.a])

        impact_score: float = (
            (7.52 * (impact_sub_score - 0.029) - 3.25 * (impact_sub_score - 0.02) ** 15)
            if self.s == "C"
            else (6.42 * impact_sub_score)
        )

        exploitability_score = (
            8.22
            * self.AV_LOOKUP[self.av]
            * self.AC_LOOKUP[self.ac]
            * (
                self.PR_CHANGED_LOOKUP[self.pr]
                if (self.s == "C")
                else self.PR_UNCHANGED_LOOKUP[self.pr]
            )
            * self.UI_LOOKUP[self.ui]
        )

        base_score = (
            0
            if impact_score <= 0
            else self.__roundup(min(impact_score + exploitability_score, 10))
            if self.s == "U"
            else self.__roundup(min(1.08 * (impact_score + exploitability_score), 10))
        )

        return base_score

    def get_temporal_score(self) -> float:
        """Calculate the CVSS 3.1 temporal score.

        Calculate the temporal score according to the equations found in section 7.2 of:
            https://www.first.org/cvss/v3.1/specification-document

        Uses values obtained from section 7.4 of:
            https://www.first.org/cvss/v3.1/specification-document

        Returns:
            The temporal score for the current CVSS class.

        Raises:
            ValueError: An invalid value was found among the base metrics.
        """

        # if self.base_valid(), then Scope (self.s) was set to "U" or "C" for the
        # following checks below
        try:
            base_score = self.get_base_score()
        except ValueError:
            raise

        temporal_score = self.__roundup(
            base_score
            * self.E_LOOKUP[self.e]
            * self.RL_LOOKUP[self.rl]
            * self.RC_LOOKUP[self.rc]
        )

        return temporal_score

    def get_environmental_score(self) -> float:
        """Calculate the CVSS 3.1 environmental score.

        Calculate the environmental score according to the equations found in
        section 7.3 of:
            https://www.first.org/cvss/v3.1/specification-document

        Uses values obtained from section 7.4 of:
            https://www.first.org/cvss/v3.1/specification-document

        Returns:
            The environmental score for the current CVSS class.

        Raises:
            ValueError: An invalid value was found among the base metrics.
        """

        # if self.base_valid(), then Scope (self.s) was set to "U" or "C" for the
        # following checks below
        if not self.base_valid():
            raise ValueError(
                "ValueError: Can not calculate environmental CVSS score when "
                "base values are not valid."
            )

        modified_impact_sub_score = min(
            1
            - (
                (
                    1
                    - self.ENVIRONMENTAL_REQ_LOOKUP[self.cr]
                    * self.ISS_LOOKUP[self.__get_modified_or_base(self.mc, self.c)]
                )
                * (
                    1
                    - self.ENVIRONMENTAL_REQ_LOOKUP[self.ir]
                    * self.ISS_LOOKUP[self.__get_modified_or_base(self.mi, self.i)]
                )
                * (
                    1
                    - self.ENVIRONMENTAL_REQ_LOOKUP[self.ar]
                    * self.ISS_LOOKUP[self.__get_modified_or_base(self.ma, self.a)]
                )
            ),
            0.915,
        )

        modified_impact_score: float = (
            (
                7.52 * (modified_impact_sub_score - 0.029)
                - 3.25 * (modified_impact_sub_score * 0.9731 - 0.02) ** 13
            )
            if self.__get_modified_or_base(self.ms, self.s) == "C"
            else (6.42 * modified_impact_sub_score)
        )

        modified_exploitability_score = (
            8.22
            * self.AV_LOOKUP[self.__get_modified_or_base(self.mav, self.av)]
            * self.AC_LOOKUP[self.__get_modified_or_base(self.mac, self.ac)]
            * (
                self.PR_CHANGED_LOOKUP[self.__get_modified_or_base(self.mpr, self.pr)]
                if (self.__get_modified_or_base(self.ms, self.s) == "C")
                else self.PR_UNCHANGED_LOOKUP[
                    self.__get_modified_or_base(self.mpr, self.pr)
                ]
            )
            * self.UI_LOOKUP[self.__get_modified_or_base(self.mui, self.ui)]
        )

        environmental_score = (
            0
            if modified_impact_score <= 0
            else self.__roundup(
                self.__roundup(
                    min(modified_impact_score + modified_exploitability_score, 10)
                )
                * self.E_LOOKUP[self.e]
                * self.RL_LOOKUP[self.rl]
                * self.RC_LOOKUP[self.rc]
            )
            if (self.__get_modified_or_base(self.ms, self.s) == "U")
            else self.__roundup(
                self.__roundup(
                    min(
                        1.08 * (modified_impact_score + modified_exploitability_score),
                        10,
                    )
                )
                * self.E_LOOKUP[self.e]
                * self.RL_LOOKUP[self.rl]
                * self.RC_LOOKUP[self.rc]
            )
        )

        return environmental_score

    @staticmethod
    def __get_modified_or_base(modified: str, base: str) -> str:
        """Determine which value to use during CVSS scoring lookups based on whether
            the modified metric value was set.

        Section 4.2 of the following link indicates to use the associated
        base metric when the environmental modified base metric is "Not Defined".
            https://www.first.org/cvss/v3.1/specification-document

        Args:
            modified: The shorthand string value from the modified parameter.
            base: The shorthand string value from the base parameter.

        Returns:
            The shorthand value from the modified base metric if the modified value is
                a value other than "Not Defined" ("X"). Otherwise, returns the
                base value.
        """
        return modified if modified != "X" else base

    @staticmethod
    def __roundup(value: float) -> float:
        """Obtain a float value rounded up with 1 decimal precision.

        Intended to remove implementation specific rounding errors. See the proposed
        algorithm in Appendix A at:
            https://www.first.org/cvss/v3.1/specification-document

        Args:
            value: Float value to be rounded up.

        Returns:
            A float rounded up to the nearest .1 value.
        """
        int_input = round(value * 100000)
        if (int_input % 10000) == 0:
            return int_input / 100000.0
        else:
            return (math.floor(int_input / 10000) + 1) / 10.0
