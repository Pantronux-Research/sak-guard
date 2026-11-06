# Qurrat Ul Ain — paper most compatible with sak-guard

**Author confirmed:** OpenAlex `A5050950060` — *Qurrat Ul Ain*, Victoria University of Wellington,
**28 works, 894 citations**. Profile: Senior Lecturer in Cyber Security; PhD CS (VUW); ex-Postdoc
Research Fellow in AI. Topics: Evolutionary Algorithms and Applications; AI in cancer detection;
Image Retrieval and Classification Techniques.

Her corpus is **entirely genetic programming for medical image classification** (skin cancer,
melanoma, breast cancer, mammography). **Nothing in security, static analysis, or provenance.**
So the compatible axis is not the application domain — it is the *methodological* claim about how an
opaque input is made auditable.

---

## Rank 1 — the recommendation

**Automatically Evolving Interpretable Feature Vectors Using Genetic Programming for an Ensemble
Classifier in Skin Cancer Image Classification**

- Authors: Ain, Q. U.; Al-Sahaf, H.; Xue, B.; Zhang, M.
- **IEEE Computational Intelligence Magazine, vol. 19, no. 3, pp. 26–41, 2024**
- DOI `10.1109/mci.2024.3401342`

Why this one: the title states the argument directly — **interpretable** feature vectors, *evolved*
rather than selected. Her point is that a classifier's decision becomes auditable only when the input
has been deliberately re-expressed as a structure a human can inspect. That is the same move our
provenance gate performs on a model completion: an opaque completion is not auditable in its raw
form, so we parse it into a structure and follow the dataflow.

Also: IEEE venue (matches our target), 2024 (recency), 16 pages in a magazine — a readable
exposition of the interpretability position rather than a narrow result.

## Rank 2 — prestige alternative

**Automatically Diagnosing Skin Cancers From Multimodality Images Using Two-Stage Genetic
Programming** — *IEEE Transactions on Cybernetics*, vol. 53, no. 5, pp. 2727–2740, 2023.
DOI `10.1109/tcyb.2022.3182474`

Higher-prestige journal, and its *two-stage* pipeline mirrors our source→propagation→sink structure.
But it is a results paper; the interpretability argument is not its subject.

## Rank 3 — the "knowledge-guided representation" angle

**Generating Knowledge-Guided Discriminative Features Using Genetic Programming for Melanoma
Detection** — *IEEE Trans. Emerging Topics in Computational Intelligence*, vol. 5, no. 4,
pp. 554–569, 2021. DOI `10.1109/tetci.2020.2983426`

Closest in spirit to constructing inspectable features under an explicit prior, but 2021 and less
direct than Rank 1.

## Currently cited (to be replaced)

**Skin Cancer Detection with Multimodal Data: A Feature Selection Approach Using Genetic
Programming** — *Communications in Computer and Information Science*, pp. 254–269, 2024.
DOI `10.1007/978-981-99-8696-5_18`

This is a **feature *selection*** paper — choosing among existing features. Our argument is that we
**construct** an inspectable structure rather than select one, so the CIM paper is both the stronger
and the more accurate citation for the sentence in §II-B.

---

## Note on verification

All metadata above resolved from CrossRef. OpenAlex dates the CCIS chapter 2023 where CrossRef says
2024; CrossRef is authoritative for the DOI, so 2024 stands.

On retrieval: `10.1109/mci.2024.3401342` is IEEE Xplore (paywalled; abstract and front matter are
open). If you cannot obtain the full text, the abstract and first page are enough — the citation
needs the *claim*, not the method, so a verified abstract is sufficient to keep the sentence honest.
