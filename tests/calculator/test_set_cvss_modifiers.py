def test_set_cvss_modifiers(example_calculator):

    # Default vector for calculation:
    # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/
    assert example_calculator.calculate_results(125).get("Projected CVSS") == 7.5
    example_calculator.set_cvss_modifiers(mav="P", cr="H")

    # Modified vector for calculation:
    # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/CR:H/MAV:P
    assert example_calculator.calculate_results(125).get("Projected CVSS") == 6.4


def test_set_cvss_modifiers_all(example_calculator):

    # Override all metric values.
    # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/
    #   E:F/RL:U/RC:R/
    #   CR:H/IR:M/AR:M/MAV:P/MAC:L/MPR:L/MUI:R/MS:U/MC:L/MI:L/MA:L
    example_calculator.set_cvss_modifiers(
        e="F",
        rl="U",
        rc="R",
        cr="H",
        ir="M",
        ar="M",
        mav="P",
        mac="L",
        mpr="L",
        mui="R",
        ms="U",
        mc="L",
        mi="L",
        ma="L",
    )
    assert example_calculator.calculate_results(125).get("Projected CVSS") == 4.1
