"""Turn overlapping detections into a set of disjoint spans to pseudonymize.

Detectors run independently, so their spans overlap: an ARN detector and an account-ID detector
both fire on `arn:aws:iam::123456789012:role/x`; a key/value heuristic and an access-key rule
both fire on the same `AKIA...` value. Replacement needs disjoint spans.

Security invariant (property-tested): the resolved spans cover EXACTLY the characters covered by
the input spans. Resolution may relabel or fuse, never uncover. See ADR 0006.
"""

from __future__ import annotations

from collections.abc import Iterable

from cloakops.model import Span

MERGED_DETECTOR_SEPARATOR = "+"


def _priority(span: Span) -> tuple[int, int, float, str, str]:
    # Category, then specific-over-generic, then confidence. The two string keys only make the
    # choice deterministic when everything else ties.
    category, specificity = span.entity_type.rank
    return (category, specificity, span.confidence, span.entity_type.value, span.detector)


def _resolve_cluster(cluster: list[Span]) -> Span:
    start = min(s.start for s in cluster)
    end = max(s.end for s in cluster)

    covering = [s for s in cluster if s.start == start and s.end == end]
    if covering:
        # One detection covers the whole cluster (e.g. the ARN around its account ID): keep it.
        # Its pseudonymizer is responsible for the parts it contains.
        return max(covering, key=_priority)

    # Partial overlaps, no detection covers everything: fuse into one span so that no detected
    # character is left in clear. The fused text has no known format: mark it as merged.
    best = max(cluster, key=_priority)
    detectors = sorted({s.detector for s in cluster})
    return Span(
        start=start,
        end=end,
        entity_type=best.entity_type,
        detector=MERGED_DETECTOR_SEPARATOR.join(detectors),
        confidence=best.confidence,
        merged=True,
    )


def resolve_overlaps(spans: Iterable[Span]) -> list[Span]:
    """Return disjoint spans, sorted by position.

    Overlapping spans are grouped into clusters (transitively: A overlaps B, B overlaps C puts
    all three together). Each cluster becomes one span:
    - if some detection covers the whole cluster, the highest-priority such detection;
    - otherwise a merged span over the union, typed after the highest-priority member.
    """
    ordered = sorted(spans, key=lambda s: (s.start, -s.end))
    resolved: list[Span] = []
    cluster: list[Span] = []
    cluster_end = -1

    for span in ordered:
        if cluster and span.start < cluster_end:
            cluster.append(span)
            cluster_end = max(cluster_end, span.end)
            continue
        if cluster:
            resolved.append(_resolve_cluster(cluster))
        cluster = [span]
        cluster_end = span.end

    if cluster:
        resolved.append(_resolve_cluster(cluster))
    return resolved
