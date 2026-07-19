"""
Schwartz value classification for constitution principles.

Uses expanded keyword matching with bigram support and canonical description
similarity. No LLM call: fast, deterministic, and cost-free.

Schwartz's 10 basic values form a circular motivational continuum:
  power - achievement - hedonism - stimulation - self_direction
  universalism - benevolence - tradition - conformity - security

Adjacent values share motivational goals; opposing values conflict.

Higher-order dimensions:
  self_enhancement (power, achievement)
  openness_to_change (hedonism, stimulation, self_direction)
  self_transcendence (universalism, benevolence)
  conservation (tradition, conformity, security)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# =============================================================================
# Canonical Keyword & Bigram Sets
# =============================================================================

# Each value has:
#   - keywords: single-word indicators
#   - bigrams: two-word phrases (more precise than single words)
#   - description: canonical definition for fallback similarity

VALUE_DATA: dict[str, dict[str, set[str] | str]] = {
    "power": {
        "keywords": {
            "authority",
            "control",
            "dominance",
            "influence",
            "wealth",
            "status",
            "leadership",
            "command",
            "prestige",
            "social power",
            "hierarchy",
            "dominant",
            "commanding",
            "ruling",
            "govern",
            "sovereignty",
        },
        "bigrams": {
            "social power",
            "public image",
            "preserve authority",
            "maintain control",
            "exert influence",
            "power over",
        },
        "description": "Social status and prestige, control or dominance over people and resources",
    },
    "achievement": {
        "keywords": {
            "success",
            "competence",
            "ambition",
            "capable",
            "excellence",
            "performance",
            "accomplish",
            "achievement",
            "intelligent",
            "effective",
            "efficient",
            "productive",
            "succeed",
            "mastery",
            "skill",
        },
        "bigrams": {
            "personal success",
            "demonstrate competence",
            "show capability",
            "high performance",
            "exceed expectations",
            "prove ability",
        },
        "description": "Personal success through demonstrating competence according to social standards",
    },
    "hedonism": {
        "keywords": {
            "pleasure",
            "enjoy",
            "fun",
            "gratification",
            "comfort",
            "delight",
            "satisfaction",
            "indulgence",
            "sensuous",
            "enjoying",
            "enjoyment",
            "pleasurable",
            "gratify",
            "savor",
        },
        "bigrams": {
            "self indulgence",
            "enjoying life",
            "sensuous gratification",
            "personal pleasure",
            "seek enjoyment",
        },
        "description": "Pleasure and sensuous gratification for oneself",
    },
    "stimulation": {
        "keywords": {
            "novelty",
            "excitement",
            "challenge",
            "variety",
            "daring",
            "adventure",
            "curious",
            "explore",
            "risk",
            "stimulating",
            "exciting",
            "varied",
            "bold",
            "thrill",
            "novel",
        },
        "bigrams": {
            "varied life",
            "exciting life",
            "seek adventure",
            "take risks",
            "embrace novelty",
            "try new",
        },
        "description": "Excitement, novelty, and challenge in life",
    },
    "self_direction": {
        "keywords": {
            "independence",
            "freedom",
            "creativity",
            "autonomy",
            "choice",
            "self-reliant",
            "independent",
            "creative",
            "curious",
            "explore",
            "privacy",
            "own goals",
            "choosing",
            "free",
            "liberty",
        },
        "bigrams": {
            "independent thought",
            "own goals",
            "free choice",
            "creative freedom",
            "self reliant",
            "think independently",
            "personal autonomy",
        },
        "description": "Independent thought and action: choosing, creating, exploring",
    },
    "universalism": {
        "keywords": {
            "justice",
            "equality",
            "fairness",
            "tolerance",
            "protect",
            "environment",
            "peace",
            "broad-minded",
            "wisdom",
            "social justice",
            "nature",
            "beauty",
            "harmony",
            "world peace",
            "equity",
            "universal",
            "ecological",
            "sustainable",
            "inclusive",
            "diversity",
            "understanding",
        },
        "bigrams": {
            "social justice",
            "world peace",
            "protect nature",
            "equal treatment",
            "inner harmony",
            "broad minded",
            "protect environment",
            "treat equally",
            "human rights",
            "all people",
            "every person",
        },
        "description": "Understanding, appreciation, tolerance, and protection for the welfare of all people and nature",
    },
    "benevolence": {
        "keywords": {
            "kindness",
            "help",
            "caring",
            "loyal",
            "honest",
            "forgiving",
            "responsible",
            "welfare",
            "compassion",
            "helpful",
            "genuine",
            "true",
            "trustworthy",
            "supportive",
            "empathy",
            "gentle",
            "generous",
            "mercy",
            "goodwill",
            "wellbeing",
        },
        "bigrams": {
            "be kind",
            "help others",
            "show compassion",
            "true friendship",
            "be honest",
            "caring about",
            "welfare of",
            "look after",
            "care for",
            "treat with",
            "with dignity",
        },
        "description": "Preservation and enhancement of the welfare of people with whom one is in frequent personal contact",
    },
    "tradition": {
        "keywords": {
            "tradition",
            "custom",
            "heritage",
            "respect",
            "humble",
            "devout",
            "moderate",
            "cultural",
            "traditional",
            "ancestral",
            "faith",
            "ritual",
            "convention",
            "legacy",
            "preserve",
            "sacred",
        },
        "bigrams": {
            "cultural tradition",
            "religious tradition",
            "respect elders",
            "moderate actions",
            "humble acceptance",
            "time honored",
            "long standing",
            "passed down",
        },
        "description": "Respect, commitment, and acceptance of the customs and ideas that traditional culture or religion provide",
    },
    "conformity": {
        "keywords": {
            "obedience",
            "polite",
            "discipline",
            "comply",
            "rules",
            "restraint",
            "duty",
            "honor",
            "self-discipline",
            "obey",
            "propriety",
            "conform",
            "norms",
            "standards",
            "behave",
            "proper",
        },
        "bigrams": {
            "follow rules",
            "social norms",
            "self discipline",
            "not upset",
            "not disturb",
            "show restraint",
            "obey rules",
            "proper behavior",
            "act appropriately",
            "within bounds",
        },
        "description": "Restraint of actions, inclinations, and impulses likely to upset or harm others and violate social expectations or norms",
    },
    "security": {
        "keywords": {
            "safety",
            "stability",
            "order",
            "clean",
            "secure",
            "protect",
            "health",
            "belonging",
            "national security",
            "family security",
            "safe",
            "stable",
            "predictable",
            "reliable",
            "defense",
            "shield",
            "guard",
            "safeguard",
        },
        "bigrams": {
            "national security",
            "family security",
            "social order",
            "sense of belonging",
            "keep safe",
            "maintain stability",
            "protect from",
            "ensure safety",
            "personal safety",
        },
        "description": "Safety, harmony, and stability of society, of relationships, and of self",
    },
}


HIGHER_ORDER_MAPPING: dict[str, str] = {
    "power": "self_enhancement",
    "achievement": "self_enhancement",
    "hedonism": "openness_to_change",
    "stimulation": "openness_to_change",
    "self_direction": "openness_to_change",
    "universalism": "self_transcendence",
    "benevolence": "self_transcendence",
    "tradition": "conservation",
    "conformity": "conservation",
    "security": "conservation",
}

OPPOSING_PAIRS: list[tuple[str, str]] = [
    ("self_enhancement", "self_transcendence"),
    ("openness_to_change", "conservation"),
]


@dataclass
class Classification:
    """Result of Schwartz value classification."""

    primary_value: str
    confidence: float
    top_3: list[dict[str, str | float]]  # [{"value": "benevolence", "score": 0.8}, ...]


def classify_principle(text: str, principle_type: str = "never") -> Classification:
    """Classify principle text against Schwartz values.

    Uses three scoring signals:
    1. Unigram keyword overlap (weighted by specificity)
    2. Bigram phrase matching (higher weight for precise matches)
    3. Description word overlap (fallback for indirect language)

    Returns classification with confidence score and top-3 candidates.
    """
    text_lower = text.lower()
    words = set(re.findall(r"[a-z][a-z'-]+", text_lower))
    # Build bigrams from consecutive words
    word_list = re.findall(r"[a-z][a-z'-]+", text_lower)
    text_bigrams: set[str] = set()
    for i in range(len(word_list) - 1):
        text_bigrams.add(f"{word_list[i]} {word_list[i + 1]}")

    scores: dict[str, float] = {}

    for value, data in VALUE_DATA.items():
        keywords = data["keywords"]
        bigrams = data["bigrams"]
        description = data["description"]

        assert isinstance(keywords, set)
        assert isinstance(bigrams, set)
        assert isinstance(description, str)

        # Signal 1: Unigram keyword overlap
        keyword_matches = words & keywords
        unigram_score = len(keyword_matches) / max(len(keywords), 1) if keywords else 0

        # Signal 2: Bigram phrase matching (weighted 2x for precision)
        bigram_matches = text_bigrams & bigrams
        bigram_score = (len(bigram_matches) * 2) / max(len(bigrams), 1) if bigrams else 0

        # Signal 3: Description word overlap (catches indirect language)
        desc_words = set(re.findall(r"[a-z][a-z'-]+", description.lower()))
        desc_overlap = words & desc_words
        # Remove common words that add noise
        stopwords = {"and", "of", "the", "to", "for", "in", "or", "a", "an", "that", "is", "are"}
        desc_overlap -= stopwords
        desc_score = len(desc_overlap) / max(len(desc_words - stopwords), 1) if desc_words else 0

        # Combined score: bigrams weighted highest, then keywords, then description
        combined = (unigram_score * 0.4) + (bigram_score * 0.4) + (desc_score * 0.2)
        scores[value] = combined

    # Rank by score
    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)

    if not ranked or ranked[0][1] == 0:
        # No matches at all: very low confidence default
        return Classification(
            primary_value="universalism",
            confidence=0.1,
            top_3=[{"value": v, "score": round(s, 3)} for v, s in ranked[:3]],
        )

    top_score = ranked[0][1]
    second_score = ranked[1][1] if len(ranked) > 1 else 0

    # Confidence: based on absolute score and gap to second place
    gap = top_score - second_score
    # High absolute score + clear gap = high confidence
    confidence = min(1.0, (top_score * 0.6) + (gap * 2.0))

    return Classification(
        primary_value=ranked[0][0],
        confidence=round(confidence, 3),
        top_3=[{"value": v, "score": round(s, 3)} for v, s in ranked[:3]],
    )


def detect_tensions(new_value: str, existing_values: list[str]) -> list[dict[str, str]]:
    """Detect Schwartz circular model tensions between a new value and existing ones.

    Tensions occur when values map to opposing higher-order dimensions:
    - self_enhancement vs self_transcendence
    - openness_to_change vs conservation
    """
    new_ho = HIGHER_ORDER_MAPPING.get(new_value)
    if not new_ho:
        return []

    tensions: list[dict[str, str]] = []
    for existing in existing_values:
        existing_ho = HIGHER_ORDER_MAPPING.get(existing)
        if not existing_ho:
            continue
        for a, b in OPPOSING_PAIRS:
            if (new_ho == a and existing_ho == b) or (new_ho == b and existing_ho == a):
                tensions.append(
                    {
                        "new_value": new_value,
                        "new_higher_order": new_ho,
                        "opposing_value": existing,
                        "opposing_higher_order": existing_ho,
                        "dimension_pair": f"{a} vs {b}",
                    }
                )
    return tensions
