# Paper

**Enhancing software-defined perimeters with integrated identity solutions and threat detection for robust zero trust security**
Antonio Payá, Vicente García-Díaz, Alberto Gómez.
*International Journal of Information Security* 24, 178 (2025). [doi:10.1007/s10207-025-01099-9](https://doi.org/10.1007/s10207-025-01099-9)

## Abstract

> As cyber threats continue to evolve, modern organizations face increasing challenges in securing their digital infrastructure. Traditional security approaches like Virtual Private Networks (VPNs) often fall short due to their inherent trust assumptions and broad access once authenticated, which can be exploited if credentials are compromised. To address these limitations, this paper proposes an enhanced Software-Defined Perimeter (SDP) architecture that aligns with Zero Trust security principles. By integrating Identity and Access Management (IAM) using Keycloak and Intrusion Detection Systems (IDS), the architecture strengthens authentication processes and introduces continuous monitoring and real-time threat detection. This integration mitigates risks associated with credential theft, unauthorized access, and insider threats while ensuring dynamic access control. However, these enhancements introduce a slight performance overhead. Evaluation across various network topologies shows that while connection setup time increases by approximately 75-100ms, the overall network throughput remains largely unaffected. The findings suggest that the enhanced SDP architecture offers a robust security solution for modern enterprises adopting Zero Trust, balancing advanced threat mitigation with minimal performance trade-offs. This work provides valuable insights into integrating IAM and IDS within SDP frameworks, reinforcing the need for adaptable and resilient cybersecurity strategies.

*(Abstract quoted from the article.)*

## Contributions, in brief

- An SDP in which the initiating host must authenticate with an IAM (Keycloak, with MFA and RBAC) before establishing the mTLS tunnel with the controller, and the controller validates both the session token and the device key pair.
- Accepting hosts that verify identity and permissions on their own instead of trusting the controller blindly, which reduces the controller's role as a single point of failure and supports partial decentralisation.
- Continuous monitoring with an IDS (Apollon) fed with identity context, giving UEBA-like behaviour analysis without a separate UEBA product, and automatic isolation or termination of suspicious sessions.
- An evaluation of the overhead on four network topologies (connection set-up time, request size, throughput) and of the security impact against credential theft and denial-of-service scenarios.

How each part maps to this code: [Architecture](architecture.md). Results: [Security evaluation](security-evaluation.md), [Performance evaluation](performance.md).

## How to cite

```bibtex
@article{paya2025enhancing,
  title   = {Enhancing software-defined perimeters with integrated identity solutions and threat detection for robust zero trust security},
  author  = {Pay{\'a}, Antonio and Garc{\'i}a-D{\'i}az, Vicente and G{\'o}mez, Alberto},
  journal = {International Journal of Information Security},
  volume  = {24},
  number  = {4},
  pages   = {178},
  year    = {2025},
  doi     = {10.1007/s10207-025-01099-9}
}
```

The repository also has a [`CITATION.cff`](https://github.com/antoniopaya22/iam-ids-sdp/blob/main/CITATION.cff) whose preferred citation is this article.

## Related work by the authors

The IDS integrated in the paper is Apollon:

```bibtex
@article{paya2024apollon,
  title   = {Apollon: A robust defense system against Adversarial Machine Learning attacks in Intrusion Detection Systems},
  author  = {Pay{\'a}, Antonio and Arroni, Sergio and Garc{\'i}a-D{\'i}az, Vicente and G{\'o}mez, Alberto},
  journal = {Computers \& Security},
  volume  = {136},
  pages   = {103546},
  year    = {2024},
  doi     = {10.1016/j.cose.2023.103546}
}
```

The SDP it extends is SecureSDP:

```bibtex
@article{paya2024securesdp,
  title   = {SecureSDP: a novel software-defined perimeter implementation for enhanced network security and scalability},
  author  = {Pay{\'a}, Antonio and Garc{\'i}a-D{\'i}az, Vicente and G{\'o}mez, Alberto},
  journal = {International Journal of Information Security},
  volume  = {23},
  number  = {4},
  pages   = {2793--2808},
  year    = {2024},
  doi     = {10.1007/s10207-024-00863-7}
}
```

See the [Research line](research-line.md) for the full sequence of works.
