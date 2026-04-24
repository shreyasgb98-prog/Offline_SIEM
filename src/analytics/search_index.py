"""Search indexing for efficient log queries."""

import logging
import re
from collections import defaultdict
from typing import Dict, List, Set

from src.schema import NormalizedLog

logger = logging.getLogger(__name__)


class LogIndex:
    """Inverted index for efficient log searching.

    Supports:
    - Keyword search: O(1) lookup vs O(n) linear scan
    - Field-based indexing: IP, timestamp, event type
    - Position tracking for fast retrieval

    Time Complexity:
    - Indexing: O(n) where n is number of logs
    - Search: O(1) for exact matches, O(k) for result retrieval where k is result size
    - Space Complexity: O(unique_terms + total_positions + n*avg_serialised_bytes)

    Memory design:
    - NormalizedLog objects are NOT stored in full. Only a compact pickle of
      each entry is kept in self._log_store (bytes). This avoids holding the
      entire object graph in RAM for large files. Retrieval costs one
      pickle.loads() per result, acceptable for search workloads.
    - For datasets >> millions of entries consider an on-disk store (sqlite /
      mmap); this in-memory store suits files up to ~1-2 GB of parsed logs.
    """

    def __init__(self):
        import pickle
        self._pickle = pickle

        # Inverted index: term -> list of (log_id, position_in_log)
        self.term_index: Dict[str, List[tuple]] = defaultdict(list)

        # Field-specific indexes
        self.ip_index: Dict[str, Set[int]] = defaultdict(set)   # IP -> log_ids
        self.timestamp_index: Dict[str, Set[int]] = defaultdict(set)  # date -> log_ids
        self.level_index: Dict[str, Set[int]] = defaultdict(set)  # level -> log_ids

        # Compact log store: id -> serialised bytes (NOT full NormalizedLog objects)
        self._log_store: Dict[int, bytes] = {}
        self.log_id_counter = 0

    @property
    def logs(self) -> list:
        """Read-only view: deserialises all stored logs on demand (use sparingly)."""
        return [self._pickle.loads(self._log_store[i]) for i in range(self.log_id_counter)]

    def _retrieve(self, log_id: int) -> "NormalizedLog":
        """Deserialise a single log entry by ID."""
        return self._pickle.loads(self._log_store[log_id])

    def add_log(self, log: NormalizedLog) -> int:
        """Add a log to the index. Returns the log ID."""
        log_id = self.log_id_counter
        # Store compact serialised bytes instead of the live object
        self._log_store[log_id] = self._pickle.dumps(log, protocol=self._pickle.HIGHEST_PROTOCOL)
        self.log_id_counter += 1

        # Index keywords from message and raw_line
        self._index_text(log.message, log_id)
        self._index_text(log.raw_line, log_id)

        # Index structured fields
        self._index_fields(log, log_id)

        return log_id

    def _index_text(self, text: str, log_id: int) -> None:
        """Index individual words/terms from text."""
        # Simple tokenization: split on whitespace and punctuation
        words = re.findall(r'\b\w+\b', text.lower())

        for i, word in enumerate(words):
            self.term_index[word].append((log_id, i))

    def _index_fields(self, log: NormalizedLog, log_id: int) -> None:
        """Index structured fields for fast filtering."""
        # IP indexing
        ip = self._extract_ip(log)
        if ip:
            self.ip_index[ip].add(log_id)

        # Timestamp indexing (by date)
        date_str = log.timestamp.date().isoformat()
        self.timestamp_index[date_str].add(log_id)

        # Level indexing
        self.level_index[log.level.value].add(log_id)

    def _extract_ip(self, log: NormalizedLog) -> str | None:
        """Extract IP address from log."""
        # Try metadata first
        if ip := log.metadata.get("ip") or log.metadata.get("source_ip"):
            return ip

        # Try to extract from raw line
        ip_pattern = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")
        match = ip_pattern.search(log.raw_line)
        return match.group(0) if match else None

    def search(self, query: str, filters: Dict = None) -> List[NormalizedLog]:
        """Search logs using the index.

        Args:
            query: Search query (space-separated keywords)
            filters: Optional filters like {"ip": "192.168.1.1", "level": "ERROR"}

        Returns:
            Matching logs
        """
        filters = filters or {}

        # Get candidate log IDs from keyword search
        keyword_candidates = self._search_keywords(query)

        # Apply filters
        filtered_candidates = self._apply_filters(keyword_candidates, filters)

        # Retrieve and return matching logs (deserialise on demand)
        return [self._retrieve(log_id) for log_id in sorted(filtered_candidates)]

    def _search_keywords(self, query: str) -> Set[int]:
        """Search for logs containing all keywords in query."""
        if not query.strip():
            return set(range(self.log_id_counter))  # Return all if no query

        # Tokenize query
        keywords = re.findall(r'\b\w+\b', query.lower())

        if not keywords:
            return set()

        # Find logs containing ALL keywords (AND search)
        candidate_sets = []
        for keyword in keywords:
            log_ids = {log_id for log_id, _ in self.term_index.get(keyword, [])}
            candidate_sets.append(log_ids)

        if not candidate_sets:
            return set()

        # Intersect all candidate sets
        result = candidate_sets[0]
        for candidate_set in candidate_sets[1:]:
            result = result.intersection(candidate_set)

        return result

    def _apply_filters(self, candidate_log_ids: Set[int], filters: Dict) -> Set[int]:
        """Apply field filters to candidate log IDs."""
        filtered_ids = candidate_log_ids.copy()

        # IP filter
        if ip_filter := filters.get("ip"):
            ip_matches = self.ip_index.get(ip_filter, set())
            filtered_ids = filtered_ids.intersection(ip_matches)

        # Level filter
        if level_filter := filters.get("level"):
            level_matches = self.level_index.get(level_filter.upper(), set())
            filtered_ids = filtered_ids.intersection(level_matches)

        # Date filter
        if date_filter := filters.get("date"):
            date_matches = self.timestamp_index.get(date_filter, set())
            filtered_ids = filtered_ids.intersection(date_matches)

        return filtered_ids

    def get_stats(self) -> Dict:
        """Get index statistics."""
        return {
            "total_logs": self.log_id_counter,
            "unique_terms": len(self.term_index),
            "total_term_positions": sum(len(positions) for positions in self.term_index.values()),
            "unique_ips": len(self.ip_index),
            "unique_dates": len(self.timestamp_index),
            "unique_levels": len(self.level_index),
        }


class SearchEngine:
    """High-level search interface with indexing."""

    def __init__(self):
        self.index = LogIndex()

    def index_logs(self, logs: List[NormalizedLog]) -> None:
        """Index a batch of logs."""
        for log in logs:
            self.index.add_log(log)

    def search(self, query: str, **filters) -> List[NormalizedLog]:
        """Search indexed logs.

        Args:
            query: Keyword search query
            **filters: Field filters (ip, level, date, etc.)

        Returns:
            Matching logs
        """
        return self.index.search(query, filters)

    def get_search_stats(self) -> Dict:
        """Get search performance statistics."""
        stats = self.index.get_stats()

        # Calculate space complexity
        term_space = stats["unique_terms"] * 50  # Rough estimate: 50 bytes per term entry
        position_space = stats["total_term_positions"] * 16  # 16 bytes per (log_id, position) tuple
        field_space = (stats["unique_ips"] + stats["unique_dates"] + stats["unique_levels"]) * 32

        stats["estimated_memory_mb"] = (term_space + position_space + field_space) / (1024 * 1024)

        return stats