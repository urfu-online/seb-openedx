# -*- coding: utf-8 -*-
"""Permissions as classes"""
from __future__ import absolute_import

import abc
import hashlib
import logging
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
        """
        try:
            # 0. Сначала проверим, не подтвержден ли уже пользователь в этой сессии
            # Это позволяет IFRAME работать, так как они не могут передать заголовки,
            # но передают сессионную куку.
            if request.session.get("seb_validated_for_course") == str(course_key):
                # Дополнительно можно проверить User-Agent, чтобы убедиться, что это всё ещё SEB
                # но для modern WebView это не всегда надежно.
                return True

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
            url_to_hash = ""

            if js_provided_url:
                # Режим JS API (SPA)
                url_to_hash = js_provided_url
                # Security: Проверка хоста (укажите ваши домены!)
                allowed_hosts = [
                    "apps.local.openedx.io:2000",
                    "local.openedx.io:8000",
                    request.get_host(),
                ]
                try:
                    parsed = urllib.parse.urlparse(url_to_hash)
                    if parsed.netloc and parsed.netloc not in allowed_hosts:
                        return False
                except:
                    return False
            else:
                # Режим Classic (прямой запрос)
                url_to_hash = request.build_absolute_uri()

            # 3. Проверка хеша
            is_valid = False
            for key in seb_keys:
                clean_key = str(key).strip()
                # Стандарт SEB: SHA256(URL + Key)
                to_hash = url_to_hash.encode("utf-8") + clean_key.encode("utf-8")
                expected = hashlib.sha256(to_hash).hexdigest().lower()

                if expected == header_hash_value:
                    is_valid = True
                    break

                # Попытка для React (иногда пропадает слеш)
                if js_provided_url:
                    alt_url = (
                        url_to_hash[:-1]
                        if url_to_hash.endswith("/")
                        else url_to_hash + "/"
                    )
                    to_hash_alt = alt_url.encode("utf-8") + clean_key.encode("utf-8")
                    if (
                        hashlib.sha256(to_hash_alt).hexdigest().lower()
                        == header_hash_value
                    ):
                        is_valid = True
                        break

            # 4. Если проверка прошла успешно - ЗАПОМИНАЕМ ЭТО В СЕССИИ
            if is_valid:
                # Ставим метку, что для этого курса в этой сессии SEB проверен
                request.session["seb_validated_for_course"] = str(course_key)
                # Важно: помечаем сессию как измененную, чтобы Django сохранил её
                request.session.modified = True
                return True

            LOG.warning(
                f"[SEB] Hash mismatch. Client: {header_hash_value} vs URL: {url_to_hash}"
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
