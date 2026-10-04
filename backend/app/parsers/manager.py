import time
from typing import Generator, Tuple, Optional, List
from app.parsers.base import BaseLogParser, ParsedEvent
from app.parsers.linux_auth import LinuxAuthParser
from app.parsers.apache_nginx import ApacheNginxParser
from app.parsers.generic import GenericParser
from app.core.logging import logger

class LogParserManager:
    def __init__(self):
        self.parsers: List[BaseLogParser] = [
            LinuxAuthParser(),
            ApacheNginxParser(),
            GenericParser()
        ]

    def detect_format(self, sample_lines: List[str]) -> str:
        """
        Inspect sample lines to determine the best matching parser format.
        Returns: 'LINUX_AUTH', 'APACHE_NGINX', or 'GENERIC'
        """
        non_empty = [line.strip() for line in sample_lines if line.strip()]
        if not non_empty:
            return "GENERIC"

        for parser in self.parsers[:-1]:  # Exclude Generic fallback initially
            if parser.can_parse(non_empty):
                return parser.parser_name

        return "GENERIC"

    def get_parser(self, format_type: str) -> BaseLogParser:
        normalized = (format_type or "").upper()
        for parser in self.parsers:
            if parser.parser_name == normalized:
                return parser
        return self.parsers[-1]  # Generic fallback

    def parse_file_stream(
        self,
        file_path: str,
        format_type: Optional[str] = None
    ) -> Tuple[Generator[ParsedEvent, None, None], dict]:
        """
        Streams log entries one by one, yielding ParsedEvent objects.
        Returns generator and metadata stats dict.
        """
        # Read small sample to detect format if format_type is AUTO or not provided
        sample_lines = []
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for _ in range(50):
                line = f.readline()
                if not line:
                    break
                sample_lines.append(line)

        detected = self.detect_format(sample_lines) if (not format_type or format_type.upper() == "AUTO") else format_type.upper()
        parser = self.get_parser(detected)

        stats = {
            "parser_type": detected,
            "total_lines": 0,
            "parsed_lines": 0,
            "failed_lines": 0,
            "duration_seconds": 0.0
        }

        def event_generator() -> Generator[ParsedEvent, None, None]:
            start_time = time.time()
            line_no = 0
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for raw_line in f:
                    line_no += 1
                    stats["total_lines"] += 1
                    if not raw_line.strip():
                        continue
                    try:
                        event = parser.parse_line(raw_line, line_number=line_no)
                        if event:
                            stats["parsed_lines"] += 1
                            yield event
                        else:
                            # Malformed line that parser couldn't recognize
                            stats["failed_lines"] += 1
                    except Exception as ex:
                        stats["failed_lines"] += 1
                        logger.debug(f"Error parsing line {line_no}: {ex}")

            stats["duration_seconds"] = round(time.time() - start_time, 4)

        return event_generator(), stats

parser_manager = LogParserManager()
