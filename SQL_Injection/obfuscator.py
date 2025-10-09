import random
import json
import re
import base64
from urllib.parse import quote
from xml.sax.saxutils import escape as _xml_escape
from utils import escape_html
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Obfuscator:
    def __init__(self, dbms=None):
        self.encoding_policy = None
        self.dbms = dbms or "generic"
        self.default_intensity = 0.5
        self.techniques = {
            "case_change": self._case_change,
            "inline_comments": self._inline_comments,
            "hex_encoding": self._hex_encoding,
            "char_encoding": self._char_encoding,
            "unicode_entities": self._unicode_entities,
            "xml_entities": self._xml_entities,
            "string_concat": self._string_concat,
            "parentheses": self._parentheses,
            "alternative_keywords": self._alternative_keywords,
            "whitespace_tricks": self._whitespace_tricks,
            "multi_encoding": self._multi_encoding,
            "json_injection": self._json_injection
        }
        self.safety_rules = {
            "preserve_token_boundaries": True,
            "max_length_increase": 2.0,
            "forbidden_patterns": [r"\/\*!\d+", r"--\s*[^\s]"],
            "preserve_key_positions": ["SELECT", "FROM", "WHERE", "UNION"]
        }
        self.token_boundaries = {
            "start": ["'", "\"", "(", " ", "\t", "\n", ",", "=", "<", ">"],
            "end": ["'", "\"", ")", " ", "\t", "\n", ",", ";", "--", "#", "/*"]
        }
        self.dbms_config = {
            "MySQL": {
                "comment_style": ["/**/", "#", "-- ", "-- -", "/*!00000", "/*!50000", "/*! */"],
                "string_concat": ["CONCAT", "||", " ", "+"],
                "alternative_keywords": {
                    "SELECT": ["SELECT", "SeLeCt", "SELECt", "select", "/*!SELECT*/", "/*!50000SELECT*/"],
                    "FROM": ["FROM", "FrOm", "from", "/*!FROM*/"],
                    "WHERE": ["WHERE", "WhErE", "where", "/*!WHERE*/", "WHERE/*!50000*/"],
                    "UNION": ["UNION", "UnIoN", "union", "/*!UNION*/", "UNiOn all", "UNiOn distinct"],
                    "OR": ["OR", "||", "or", "/*!OR*/", "Or"],
                    "AND": ["AND", "&&", "and", "/*!AND*/", "And", "aND"],
                    "INSERT": ["INSERT", "insert", "/*!INSERT*/", "iNsErT"],
                    "UPDATE": ["UPDATE", "update", "/*!UPDATE*/", "UpDaTe"],
                    "DELETE": ["DELETE", "delete", "/*!DELETE*/", "DeLeTe"],
                    "EXEC": ["EXEC", "exec", "EXECUTE", "execute", "/*!EXEC*/"],
                    "SLEEP": ["SLEEP", "sleep", "/*!SLEEP*/", "BENCHMARK", "benchmark"],
                    "INFORMATION_SCHEMA": ["INFORMATION_SCHEMA", "information_schema", "/*!INFORMATION_SCHEMA*/", "infoschema"]
                },
                "functions": {
                    "version": ["version()", "@@version", "/*!version*/()"],
                    "user": ["user()", "current_user()", "system_user()", "/*!user*/()"],
                    "database": ["database()", "/*!database*/()"],
                    "concat": ["CONCAT", "CONCAT_WS", "GROUP_CONCAT", "/*!CONCAT*/"]
                },
                "time_func": "SLEEP({})"
            },
            "PostgreSQL": {
                "comment_style": ["/**/", "-- ", "-- -"],
                "string_concat": ["||", "CONCAT", " "],
                "alternative_keywords": {
                    "SELECT": ["SELECT", "select", "SeLeCt"],
                    "FROM": ["FROM", "from", "FrOm"],
                    "WHERE": ["WHERE", "where", "WhErE"],
                    "UNION": ["UNION", "union", "UnIoN", "UNION ALL", "UNION DISTINCT"],
                    "OR": ["OR", "or", "Or"],
                    "AND": ["AND", "and", "aND"],
                    "CURRENT_DATABASE": ["CURRENT_DATABASE", "current_database"],
                    "VERSION": ["VERSION", "version"]
                },
                "time_func": "pg_sleep({})"
            },
            "MSSQL": {
                "comment_style": ["-- ", "/* */"],
                "string_concat": ["+", "CONCAT"],
                "alternative_keywords": {
                    "SELECT": ["SELECT", "select"],
                    "FROM": ["FROM", "from"],
                    "WHERE": ["WHERE", "where"],
                    "UNION": ["UNION", "union", "UNION ALL"],
                    "OR": ["OR", "or"],
                    "AND": ["AND", "and"],
                },
                "time_func": "WAITFOR DELAY '0:0:{}'"
            },
            "Oracle": {
                "comment_style": ["-- ", "/* */"],
                "string_concat": ["||", "CONCAT"],
                "alternative_keywords": {
                    "SELECT": ["SELECT", "select"],
                    "FROM": ["FROM", "from"],
                    "WHERE": ["WHERE", "where"],
                    "UNION": ["UNION", "union", "UNION ALL"],
                    "OR": ["OR", "or"],
                    "AND": ["AND", "and"],
                },
                "time_func": "DBMS_LOCK.SLEEP({})"
            },
            "SQLite": {
                "comment_style": ["-- ", "/* */"],
                "string_concat": ["||"],
                "alternative_keywords": {
                    "SELECT": ["SELECT", "select"],
                    "FROM": ["FROM", "from"],
                    "WHERE": ["WHERE", "where"],
                    "UNION": ["UNION", "union", "UNION ALL"],
                    "OR": ["OR", "or"],
                    "AND": ["AND", "and"],
                },
                "time_func": "sleep({})"
            },
            "generic": {
                "comment_style": ["/**/", "-- ", "#"],
                "string_concat": ["||", "CONCAT", "+"],
                "alternative_keywords": {
                    "SELECT": ["SELECT", "select"],
                    "FROM": ["FROM", "from"],
                    "WHERE": ["WHERE", "where"],
                    "UNION": ["UNION", "union"],
                    "OR": ["OR", "or"],
                    "AND": ["AND", "and"]
                },
                "time_func": "SLEEP({})"
            }
        }

    def _case_change(self, text, intensity=0.5):
        config = self.dbms_config.get(self.dbms, self.dbms_config["generic"])
        words = text.split()
        result = []
        for word in words:
            if word.upper() in config["alternative_keywords"] and random.random() < intensity:
                result.append(random.choice(config["alternative_keywords"][word.upper()]))
            else:
                result.append(word)
        logger.debug(f"Applied case_change to {text}")
        return ' '.join(result)

    def _inline_comments(self, text, intensity=0.5):
        config = self.dbms_config.get(self.dbms, self.dbms_config["generic"])
        words = text.split()
        result = []
        for i, word in enumerate(words):
            result.append(word)
            if random.random() < intensity and i < len(words) - 1:
                comment = random.choice(config["comment_style"])
                result.append(comment)
        logger.debug(f"Applied inline_comments to {text}")
        return ' '.join(result)

    def _hex_encoding(self, text, intensity=0.2):
        if len(text) < 3:
            return text
        result = []
        i = 0
        while i < len(text):
            if random.random() < intensity and i + 2 < len(text):
                length = random.randint(2, 4)
                segment = text[i:i+length]
                hex_segment = ''.join([f"{ord(c):02x}" for c in segment])
                result.append(f"0x{hex_segment}")
                i += length
            else:
                result.append(text[i])
                i += 1
        logger.debug(f"Applied hex_encoding to {text}")
        return ''.join(result)

    def _char_encoding(self, text, intensity=0.2):
        if not text:
            return text
        result = []
        for char in text:
            if random.random() < intensity and char.isprintable():
                if self.dbms in ["MySQL", "MSSQL", "SQLite"]:
                    result.append(f"CHAR({ord(char)})")
                else:
                    result.append(char)
            else:
                result.append(char)
        logger.debug(f"Applied char_encoding to {text}")
        return ''.join(result)

    def _unicode_entities(self, text, intensity=0.1):
        result = []
        for char in text:
            if random.random() < intensity:
                result.append(f"&#{ord(char)};")
            else:
                result.append(char)
        logger.debug(f"Applied unicode_entities to {text}")
        return ''.join(result)

    def _xml_entities(self, text, intensity=0.1):
        xml_entities = {
            '<': '&lt;',
            '>': '&gt;',
            '&': '&amp;',
            '"': '&quot;',
            "'": '&apos;'
        }
        result = []
        for char in text:
            if random.random() < intensity and char in xml_entities:
                result.append(xml_entities[char])
            else:
                result.append(char)
        logger.debug(f"Applied xml_entities to {text}")
        return ''.join(result)

    def _string_concat(self, text, intensity=0.3):
        if len(text) < 4:
            return text
        config = self.dbms_config.get(self.dbms, self.dbms_config["generic"])
        concat_op = random.choice(config["string_concat"])
        parts = []
        current = ""
        for char in text:
            if random.random() < intensity and current:
                parts.append(f"'{current}'")
                current = ""
            current += char
        if current:
            parts.append(f"'{current}'")
        if len(parts) > 1:
            logger.debug(f"Applied string_concat to {text}")
            return concat_op.join(parts)
        return text

    def _parentheses(self, text, intensity=0.4):
        words = text.split()
        if len(words) < 2:
            return text
        result = []
        open_count = 0
        for i, word in enumerate(words):
            if random.random() < intensity and open_count == 0:
                result.append(f"({word}")
                open_count += 1
            elif random.random() < intensity and open_count > 0 and i > 0:
                result.append(f"{word})")
                open_count -= 1
            else:
                result.append(word)
        while open_count > 0:
            result[-1] = result[-1] + ")"
            open_count -= 1
        logger.debug(f"Applied parentheses to {text}")
        return ' '.join(result)

    def _alternative_keywords(self, text, intensity=0.3):
        config = self.dbms_config.get(self.dbms, self.dbms_config["generic"])
        words = text.split()
        result = []
        for word in words:
            upper_word = word.upper()
            if upper_word in config["alternative_keywords"] and random.random() < intensity:
                result.append(random.choice(config["alternative_keywords"][upper_word]))
            else:
                result.append(word)
        logger.debug(f"Applied alternative_keywords to {text}")
        return ' '.join(result)

    def _whitespace_tricks(self, text, intensity=0.5):
        result = []
        for char in text:
            result.append(char)
            if random.random() < intensity:
                whitespace = random.choice([' ', '\t', '\n', '\r', '\x0b', '\x0c'])
                result.append(whitespace)
        logger.debug(f"Applied whitespace_tricks to {text}")
        return ''.join(result)

    def _multi_encoding(self, text, intensity=0.3):
        if len(text) < 3:
            return text
        result = []
        i = 0
        while i < len(text):
            if random.random() < intensity and i + 2 < len(text):
                length = random.randint(2, 4)
                segment = text[i:i+length]
                if random.random() < 0.5:
                    hex_segment = ''.join([f"{ord(c):02x}" for c in segment])
                    result.append(f"0x{hex_segment}")
                else:
                    b64_segment = base64.b64encode(segment.encode()).decode()
                    result.append(f"UNHEX(HEX('{b64_segment}'))")
                i += length
            else:
                result.append(text[i])
                i += 1
        logger.debug(f"Applied multi_encoding to {text}")
        return ''.join(result)

    def _json_injection(self, text, intensity=0.2):
        if random.random() < intensity:
            json_payload = json.dumps({"payload": text})
            return f"JSON_UNQUOTE(JSON_EXTRACT('{json_payload}', '$.payload'))"
        logger.debug(f"Applied json_injection to {text}")
        return text

    def obfuscate(self, payload, techniques=None, intensity=0.5, max_iterations=3):
        if not techniques:
            techniques = list(self.techniques.keys())
        current = payload
        applied_techniques = []
        for _ in range(max_iterations):
            technique_name = random.choice(techniques)
            if random.random() < intensity:
                technique = self.techniques[technique_name]
                new_payload = technique(current, intensity)
                if new_payload != current:
                    current = new_payload
                    applied_techniques.append(technique_name)
        return current, applied_techniques

    def obfuscate_advanced(self, payload, char_budget=50, dbms=None):
        if dbms:
            self.dbms = dbms
        current = payload
        applied_techniques = []
        max_iterations = 5
        techniques = list(self.techniques.keys())
        for _ in range(max_iterations):
            technique_name = random.choice(techniques)
            technique = self.techniques[technique_name]
            new_payload = technique(current, intensity=self.default_intensity)
            if new_payload != current and len(new_payload) <= len(payload) * self.safety_rules["max_length_increase"]:
                forbidden = any(re.search(p, new_payload) for p in self.safety_rules["forbidden_patterns"])
                if not forbidden:
                    current = new_payload
                    applied_techniques.append(technique_name)
            if len(current) > char_budget:
                break
        logger.info(f"Advanced obfuscation applied to {payload}: {current} (techniques: {', '.join(applied_techniques)})")
        return current, applied_techniques

    def generate_variants(self, payload, count=5, techniques=None, intensity=0.5):
        variants = []
        for i in range(count):
            variant, techniques_used = self.obfuscate(payload, techniques, intensity)
            variants.append({
                "payload": variant,
                "techniques": techniques_used,
                "label": f"obf_{i+1}"
            })
        logger.info(f"Generated {len(variants)} variants for {payload}")
        return variants