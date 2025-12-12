# -*- coding: utf-8 -*-
"""Permissions as classes"""
from __future__ import absolute_import

import abc
import hashlib
import logging

from django.conf import settings

from seb_openedx.seb_keys_sources import (
    get_config_by_course,
    get_ordered_seb_keys_sources,
)

LOG = logging.getLogger(__name__)


class Permission(metaclass=abc.ABCMeta):
    """Abstract class Permision"""

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
        ... (оставляем старый код этого метода без изменений) ...
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
        Perform the check
        1. Get the keys
        2. Determine the URL to hash (Native API URL or JS Frontend URL)
        3. Compare calculated hash with the header value
        """
        seb_keys = self.get_seb_keys(course_key)

        # Если ключей для курса нет - доступ разрешен
        if not seb_keys:
            return True

        # 1. Получаем хеш, который прислал клиент (Браузер или JS)
        header_hash_value = request.META.get(self.http_header, None)

        if not header_hash_value:
            # Нет заголовка с хешем - сразу отказ
            return False

        # 2. Определяем, какой URL использовать для проверки
        # Django преобразует дефисы в подчеркивания и добавляет HTTP_:
        # X-SafeExamBrowser-RequestUrl -> HTTP_X_SAFEEXAMBROWSER_REQUESTURL
        js_provided_url = request.META.get("HTTP_X_SAFEEXAMBROWSER_REQUESTURL", None)

        if js_provided_url:
            # Режим JS API: Хешируем URL страницы, который нам прислал фронтенд
            url_to_hash = urllib.parse.urlparse(js_provided_url).path
            LOG.warning(f"[SEB Check] Using JS Provided URL: {url_to_hash}")
        else:
            # Режим Native: Хешируем текущий URL API запроса
            url_to_hash = request.build_absolute_uri()
            LOG.warning(f"[SEB Check] Using Native API URL: {url_to_hash}")

        # 3. Проверка
        for key in seb_keys:
            # Формируем строку для хеширования: URL + Key
            # Важно: кодировка utf-8
            tohash = url_to_hash.encode("utf-8") + key.encode("utf-8")
            calculated_hash = hashlib.sha256(tohash).hexdigest()

            # Логируем для отладки (потом можно убрать)
            LOG.warning(
                f"[SEB Debug] Key: ...{key[-6:]} | Calculated: {calculated_hash} | Received: {header_hash_value}"
            )

            if calculated_hash == header_hash_value:
                LOG.warning("[SEB Check] SUCCESS")
                return True

        # Ни один ключ не подошел
        LOG.warning("[SEB Check] FAILED: Hash mismatch")
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
    Check for either Browser examk keys or Config keys.
    Allow if either is valid
    """

    def check(self, request, course_key, masquerade=None):
        """Check both hashes and return the boolean OR from both"""
        browser_exam_key = CheckSEBHashBrowserExamKey().check(
            request, course_key, masquerade
        )
        config_key = CheckSEBHashConfigKey().check(request, course_key, masquerade)

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
