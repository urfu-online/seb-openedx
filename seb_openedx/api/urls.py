"""
Defines the entry point for all versions of the API
"""

from django.urls import re_path, include, path
from seb_openedx.api.v2.views import sequence_status

app_name = "seb-api"  # pylint: disable=invalid-name

urlpatterns = [  # pylint: disable=invalid-name
    re_path(r"^v1/", include("seb_openedx.api.v1.urls", namespace="seb-api-v1")),
    path("sequence_status/", sequence_status, name="seb_sequence_status"),
]
