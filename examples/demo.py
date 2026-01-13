#!/usr/bin/env python3
"""
ATIP Demo - Show the system in action

This demonstrates the complete intelligence lifecycle:
Collection → Processing → Analysis → Dissemination
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from atip.collectors.cve.nvd_collector import NVDCollector
from atip.collectors.osint.osint_collector import OSINTCollector
from atip.core.pipeline.processor import ThreatPipeline
from atip.dissemination.reports.markdown_report import MarkdownReportGenerator
from atip.core.stride_lm.classifier import StridelMClassifier


def demo_classification():
    """Demonstrate STRIDE-LM classification"""
    print("=" * 70)
    print("STRIDE-LM CLASSIFICATION DEMO")
    print("=" * 70)
    print()

    classifier = StridelMClassifier()

    # Test cases
    test_cases = [
        {
            "text": "SQL injection vulnerability allows remote code execution",
            "cwe_ids": [89],
        },
        {
            "text": "Authentication bypass allows unauthorized access to admin panel",
            "cwe_ids": [287],
        },
        {
            "text": "Buffer overflow in network service leads to denial of service",
            "cwe_ids": [400],
        },
        {
            "text": "Malware sample communicating with C2 server using encrypted channel",
            "cwe_ids": [506],
        },
    ]

    for i, test in enumerate(test_cases, 1):
        print(f"Test {i}: {test['text']}")
        print("-" * 70)

        profile = classifier.classify(
            text=test["text"],
            cwe_ids=test.get("cwe_ids"),
        )

        print(f"Primary Category: {profile.primary_category.full_name}")
        print(f"  Question: {profile.primary_category.question}")
        print(f"  Confidence: {profile.get_score(profile.primary_category):.2f}")

        if profile.secondary_categories:
            print(f"\nSecondary Categories:")
            for cat in profile.secondary_categories:
                print(f"  - {cat.full_name} (confidence: {profile.get_score(cat):.2f})")

        print("\nTop Detection Strategies:")
        for strategy in profile.primary_category.detection_strategies[:3]:
            print(f"  • {strategy}")

        print("\nTop Mitigation Strategies:")
        for strategy in profile.primary_category.mitigation_strategies[:3]:
            print(f"  • {strategy}")

        print()
        print()


def demo_collection_and_processing():
    """Demonstrate threat collection and processing"""
    print("=" * 70)
    print("COLLECTION & PROCESSING DEMO")
    print("=" * 70)
    print()

    # Create collectors
    nvd_collector = NVDCollector()
    osint_collector = OSINTCollector()

    # Collect
    print("Collecting from NVD...")
    nvd_threats = nvd_collector.collect()
    print(f"  ✓ Collected {len(nvd_threats)} threats from NVD")
    print()

    print("Collecting from OSINT...")
    osint_threats = osint_collector.collect()
    print(f"  ✓ Collected {len(osint_threats)} threats from OSINT")
    print()

    # Combine
    all_threats = nvd_threats + osint_threats
    print(f"Total raw threats: {len(all_threats)}")
    print()

    # Process through pipeline
    print("Processing through pipeline...")
    pipeline = ThreatPipeline()
    processed_threats = pipeline.process(all_threats)
    print(f"  ✓ Pipeline complete: {len(processed_threats)} threats remain")
    print()

    # Show metrics
    metrics = pipeline.get_metrics()
    print("Pipeline Metrics:")
    for key, value in metrics.items():
        print(f"  {key}: {value}")
    print()

    # Show top threats
    print("Top 5 Threats by Priority:")
    print("-" * 70)
    for i, threat in enumerate(processed_threats[:5], 1):
        stride = f" [{threat.stride_profile}]" if threat.stride_profile else ""
        print(f"{i}. [{threat.severity.value.upper()}]{stride}")
        print(f"   {threat.title}")
        print(f"   Priority: {threat.priority_score:.2f}")
        print()

    # Generate report
    print("Generating markdown report...")
    report_gen = MarkdownReportGenerator()
    report_path = report_gen.generate(processed_threats)
    print(f"  ✓ Report generated: {report_path}")
    print()


def demo_threat_lifecycle():
    """Demonstrate the complete threat lifecycle"""
    print("=" * 70)
    print("THREAT INTELLIGENCE LIFECYCLE DEMO")
    print("=" * 70)
    print()

    from atip.core.models.threat import (
        Threat,
        ThreatIndicator,
        ThreatContext,
        ThreatSeverity,
        IndicatorType,
        ExploitationStatus,
    )

    # Create a threat manually
    print("1. COLLECTION - Creating threat from raw data")
    print("-" * 70)

    indicator = ThreatIndicator(
        type=IndicatorType.CVE,
        value="CVE-2024-9999",
        description="Critical authentication bypass",
        confidence=1.0,
        source="NVD",
    )

    context = ThreatContext(
        affects_known_assets=True,
        exposure_level="internet",
        attack_complexity="low",
        privileges_required="none",
        user_interaction_required=False,
        exploitation_status=ExploitationStatus.ACTIVE,
        patch_available=True,
    )

    threat = Threat(
        title="CVE-2024-9999: Critical Auth Bypass in Web Framework",
        description="Authentication bypass vulnerability allows remote attackers to gain admin access",
        severity=ThreatSeverity.CRITICAL,
        indicators=[indicator],
        context=context,
        cve_ids=["CVE-2024-9999"],
    )

    print(f"Created: {threat}")
    print()

    # Classify
    print("2. ANALYSIS - Classifying with STRIDE-LM")
    print("-" * 70)

    classifier = StridelMClassifier()
    threat.stride_profile = classifier.classify(
        text=f"{threat.title} {threat.description}",
        cve_id="CVE-2024-9999",
        cwe_ids=[287],
    )

    print(f"Primary Category: {threat.stride_profile.primary_category.full_name}")
    print(f"Question: {threat.stride_profile.primary_category.question}")
    print()

    # Prioritize
    print("3. PRIORITIZATION - Calculating priority score")
    print("-" * 70)

    threat.update_priority()
    print(f"Priority Score: {threat.priority_score:.2f}")
    print()
    print("Score factors:")
    print(f"  - Severity: {threat.severity.value.upper()} ({threat.severity.score}/10)")
    print(f"  - Urgency: {threat.context.calculate_urgency_score():.2f}")
    print(f"  - Exploitation: {threat.context.exploitation_status.value}")
    print(f"  - Exposure: {threat.context.exposure_level}")
    print()

    # Generate recommendations
    print("4. DISSEMINATION - Generating actionable recommendations")
    print("-" * 70)

    threat.recommended_actions = [
        "URGENT: Apply patch immediately - active exploitation detected",
        "Implement MFA across all systems as defense-in-depth",
        "Check logs for indicators of compromise from last 30 days",
        "Enable enhanced authentication monitoring",
    ]

    for i, action in enumerate(threat.recommended_actions, 1):
        print(f"  {i}. {action}")
    print()

    # Full threat output
    print("5. FINAL INTELLIGENCE OUTPUT")
    print("-" * 70)
    print()
    print(threat.to_dict())
    print()


def main():
    """Run all demos"""
    print()
    print("█████╗ ████████╗██╗██████╗ ")
    print("██╔══██╗╚══██╔══╝██║██╔══██╗")
    print("███████║   ██║   ██║██████╔╝")
    print("██╔══██║   ██║   ██║██╔═══╝ ")
    print("██║  ██║   ██║   ██║██║     ")
    print("╚═╝  ╚═╝   ╚═╝   ╚═╝╚═╝     ")
    print()
    print("Advanced Threat Intelligence Platform")
    print("An intelligence organism that transforms chaos into clarity")
    print()

    demos = [
        ("STRIDE-LM Classification", demo_classification),
        ("Collection & Processing", demo_collection_and_processing),
        ("Threat Lifecycle", demo_threat_lifecycle),
    ]

    for name, demo_func in demos:
        try:
            demo_func()
        except KeyboardInterrupt:
            print("\n\nDemo interrupted by user")
            sys.exit(0)
        except Exception as e:
            print(f"\n✗ Demo failed: {e}")
            import traceback
            traceback.print_exc()

    print()
    print("=" * 70)
    print("DEMO COMPLETE")
    print("=" * 70)
    print()
    print("Next steps:")
    print("  1. Install: pip install -e .")
    print("  2. Configure: atip init-config")
    print("  3. Collect: atip collect --all")
    print("  4. Report: atip report")
    print()


if __name__ == "__main__":
    main()
