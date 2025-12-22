# -*- coding: utf-8 -*-
"""Permissions as classes"""
from __future__ import absolute_import

import abc
import hashlib
import logging
import time
import urllib.parse

from django.conf import settings

from seb_openedx.seb_keys_sources import (
    get_config_by_course,
    get_ordered_seb_keys_sources,
)

LOG = logging.getLogger(__name__)


class Permission(metaclass=abc.ABCMeta):
    """Abstract class Permission"""

    @abc.abstractmethod
    def check(self, request, course_key, masquerade=None):
        """Abstract method check"""


class AlwaysAllowStaff(Permission):
    """Always allow when user.is_staff"""

    def check(self, request, course_key, masquerade=None):
        """check"""
        if masquerade and masquerade.role != "staff":
            return False
        if (
            hasattr(request, "user")
            and request.user.is_authenticated
            and request.user.is_staff
        ):
            LOG.info("SEB AlwaysAllowStaff check passed for user: %s", request.user)
            return True
        return False


class CheckSEBHash:
    """Mixin to implement the hash checking"""

    def get_seb_keys(self, course_key):
        """
        Find the seb keys both in the detailed and the compact format
        """
        all_keys = []
        for source_function in get_ordered_seb_keys_sources():
            seb_keys = source_function(course_key)
            if isinstance(seb_keys, dict):
                seb_keys = seb_keys.get(self.detailed_config_key, None)
            if seb_keys and settings.SEB_USE_ALL_SOURCES:
                all_keys += seb_keys
            elif seb_keys:
                return seb_keys

        return list(set(all_keys))

    def check(self, request, course_key, *args, **kwargs):
        """
        Проверка SEB с поддержкой JS API и Iframes через сессию.

        FIX1: кэш “валидированности” хранится как словарь по курсам:
              request.session["seb_validated_courses"][<course_id>] = {"ts": ...}

        FIX2: опциональный TTL:
              settings.SEB_SESSION_VALIDATION_TTL_SECONDS = <int>  (например 3600)

        FIX3 (важно для MFE/SPА без F5):
              если нет HTTP_X_SAFEEXAMBROWSER_REQUESTURL, пробуем HTTP_REFERER как URL для хеша
        """
        try:
            course_key_str = str(course_key)

            # OPTIONS (CORS preflight) лучше не блокировать SEB’ом
            # (контент не выдаёт, но может ломать SPA на первом заходе)
            if getattr(request, "method", "").upper() == "OPTIONS":
                return True

            # --- 0) Сессионный кэш (по курсам) + TTL ---
            course_cfg = get_config_by_course(course_key) or {}
            ttl_seconds = course_cfg.get("SEB_SESSION_VALIDATION_TTL_SECONDS", None)
            if ttl_seconds is None:
                ttl_seconds = getattr(
                    settings, "SEB_SESSION_VALIDATION_TTL_SECONDS", None
                )

            try:
                ttl_seconds = int(ttl_seconds) if ttl_seconds is not None else None
            except Exception:
                ttl_seconds = None

            # Миграция со старого ключа (одно значение) — чтобы не ломать текущие сессии
            old_single = request.session.get("seb_validated_for_course")
            if old_single == course_key_str:
                validated = request.session.get("seb_validated_courses", {})
                if not isinstance(validated, dict):
                    validated = {}
                validated[course_key_str] = {"ts": int(time.time())}
                request.session["seb_validated_courses"] = validated
                try:
                    del request.session["seb_validated_for_course"]
                except KeyError:
                    pass
                request.session.modified = True
                return True

            validated = request.session.get("seb_validated_courses", {})
            if isinstance(validated, dict) and course_key_str in validated:
                entry = validated.get(course_key_str)
                ts = None
                if isinstance(entry, dict):
                    ts = entry.get("ts")

                if ttl_seconds is None:
                    return True

                # TTL включён — проверяем протухание
                try:
                    if ts is not None and (time.time() - float(ts)) <= float(
                        ttl_seconds
                    ):
                        return True
                except Exception:
                    pass

                # протухло — чистим запись и продолжаем обычную проверку
                validated.pop(course_key_str, None)
                request.session["seb_validated_courses"] = validated
                request.session.modified = True

            seb_keys = self.get_seb_keys(course_key)
            if not seb_keys:
                return True

            # 1. Получаем хеш от клиента
            header_hash_value = request.META.get(self.http_header)

            # Если заголовка нет - сразу отказ (сессию мы проверили выше)
            if not header_hash_value:
                return False

            header_hash_value = header_hash_value.strip().lower()

            # 2. Определяем URL (JS API или Classic)
            js_provided_url = request.META.get("HTTP_X_SAFEEXAMBROWSER_REQUESTURL")

            # Собираем список кандидатов URL, по которым попробуем посчитать хеш.
            # Для SPA это важно: иногда SEB считает хеш по URL страницы (Referer),
            # даже если реальный запрос идёт в /api/...
            url_candidates = []

            if js_provided_url:
                url_candidates.append(js_provided_url)
            else:
                # Classic (прямой запрос)
                url_candidates.append(request.build_absolute_uri())

                # FIX для MFE: fallback на Referer (часто там SPA route)
                referer = request.META.get("HTTP_REFERER")
                if referer:
                    # минимальная защита: если referer вообще есть
                    url_candidates.append(referer)

            # Нормализуем кандидаты: убираем пробелы
            url_candidates = [u.strip() for u in url_candidates if u and u.strip()]

            # Security: Проверка хоста для JS API URL и для referer fallback
            allowed_hosts = [
                "apps.local.openedx.io:2000",
                "local.openedx.io:8000",
                "asdebug.ru",
                "apps.asdebug.ru",
                "courses.openedu.urfu.ru",
                "apps.courses.openedu.urfu.ru",
                request.get_host(),
            ]

            filtered_candidates = []
            for u in url_candidates:
                try:
                    parsed = urllib.parse.urlparse(u)
                    # если netloc задан — проверим
                    if parsed.netloc and parsed.netloc not in allowed_hosts:
                        continue
                    filtered_candidates.append(u)
                except Exception:
                    continue

            url_candidates = filtered_candidates

            if not url_candidates:
                return False

            # 3. Проверка хеша
            is_valid = False
            matched_url = None

            for url_to_hash in url_candidates:
                for key in seb_keys:
                    clean_key = str(key).strip()

                    # Стандарт SEB: SHA256(URL + Key)
                    to_hash = url_to_hash.encode("utf-8") + clean_key.encode("utf-8")
                    expected = hashlib.sha256(to_hash).hexdigest().lower()

                    if expected == header_hash_value:
                        is_valid = True
                        matched_url = url_to_hash
                        break

                    # Попытка (иногда пропадает/добавляется слеш) — полезно и для SPA, и для classic
                    alt_url = (
                        url_to_hash[:-1]
                        if url_to_hash.endswith("/")
                        else (url_to_hash + "/")
                    )
                    to_hash_alt = alt_url.encode("utf-8") + clean_key.encode("utf-8")
                    expected_alt = hashlib.sha256(to_hash_alt).hexdigest().lower()
                    if expected_alt == header_hash_value:
                        is_valid = True
                        matched_url = alt_url
                        break

                if is_valid:
                    break

            # 4. Если проверка прошла успешно - ЗАПОМИНАЕМ ЭТО В СЕССИИ (по курсам)
            if is_valid:
                validated = request.session.get("seb_validated_courses", {})
                if not isinstance(validated, dict):
                    validated = {}
                validated[course_key_str] = {"ts": int(time.time())}
                request.session["seb_validated_courses"] = validated
                request.session.modified = True

                LOG.info(
                    "[SEB] Validated and cached in session. course=%s via=%s matched_url=%s path=%s",
                    course_key_str,
                    self.http_header,
                    matched_url,
                    request.path,
                )
                return True

            LOG.warning(
                "[SEB] Hash mismatch. course=%s via=%s path=%s client=%s candidates=%s",
                course_key_str,
                self.http_header,
                request.path,
                header_hash_value,
                url_candidates,
            )
            return False

        except Exception as e:
            LOG.error(f"[SEB Check] Error: {str(e)}", exc_info=True)
            return False


class CheckSEBHashBrowserExamKey(CheckSEBHash, Permission):
    """Check for SEB Browser keys, allow if there are none configured"""

    http_header = "HTTP_X_SAFEEXAMBROWSER_REQUESTHASH"
    detailed_config_key = "BROWSER_KEYS"


class CheckSEBHashConfigKey(CheckSEBHash, Permission):
    """Check for SEB Config keys, allow if there are none configured"""

    http_header = "HTTP_X_SAFEEXAMBROWSER_CONFIGKEYHASH"
    detailed_config_key = "CONFIG_KEYS"


class CheckSEBHashBrowserExamKeyOrConfigKey(Permission):
    """
    Check for either Browser exam keys or Config keys.
    Allow if either is valid
    """

    def check(self, request, course_key, masquerade=None):
        """Check both hashes and return the boolean OR from both"""
        browser_exam_key = CheckSEBHashBrowserExamKey().check(
            request, course_key, masquerade
        )
        config_key = CheckSEBHashConfigKey().check(request, course_key, masquerade)

        LOG.warning(
            f"[SEB Check] Combined result: Browser={browser_exam_key}, Config={config_key}, Final={config_key or browser_exam_key}"
        )

        return config_key or browser_exam_key


class AlwaysDenyAccess(Permission):
    """Always deny access"""

    def check(self, request, course_key, masquerade=None):
        """Don't even check, just block"""
        return False


class AlwaysGrantAccess(Permission):
    """Always grant access"""

    def check(self, request, course_key, masquerade=None):
        """Don't even check, just grant"""
        return True


def get_enabled_permission_classes(course_key=None):
    """retrieve ordered permissions from settings if available, otherwise use defaults"""

    try:
        if course_key:
            _config = get_config_by_course(course_key)
            components = _config.get("PERMISSION_COMPONENTS", None)
            if components:
                return [globals()[comp] for comp in components]
    except Exception:  # pylint: disable=broad-except
        LOG.error(
            "Error trying to retrieve the permission classes for course %s", course_key
        )

    if hasattr(settings, "SEB_PERMISSION_COMPONENTS"):
        return [globals()[comp] for comp in settings.SEB_PERMISSION_COMPONENTS]

    return [AlwaysAllowStaff]
