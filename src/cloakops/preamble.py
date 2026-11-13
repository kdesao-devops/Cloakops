"""Instruction prepended to the pseudonymized content (`--preamble`, ADR 0010).

It tells the model that values are consistent pseudonyms, so it reasons on them as real values,
and asks it to reuse them verbatim, which is what makes re-injection work (drift, ADR 0011).
"""

PREAMBLE = """\
Some identifiers in the content below (IP addresses, ARNs, account and resource IDs, hostnames,
names, secrets) have been replaced with consistent pseudonyms. The same pseudonym always denotes
the same real entity, and network relationships such as subnet membership are preserved. Treat
them as real values. Do not comment on them looking fake, and reuse them verbatim (no
truncation, no reformatting) whenever you refer to them.
"""
