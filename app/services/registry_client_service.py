# app/services/registry_client_service.py
import httpx
import logging
from typing import Optional, List, Dict, Any, Tuple

from app.core.config import settings
from app.models.audit_actions import AuditAction # 필요시 사용
from functools import lru_cache

logger = logging.getLogger(__name__)

# Docker Manifest 관련 Accept 헤더 상수
ACCEPT_MANIFEST_V2 = "application/vnd.docker.distribution.manifest.v2+json" #
ACCEPT_MANIFEST_OCI = "application/vnd.oci.image.manifest.v1+json" #
ACCEPT_MANIFEST_LIST_V2 = "application/vnd.docker.distribution.manifest.list.v2+json" #
ACCEPT_OCI_INDEX_V1 = "application/vnd.oci.image.index.v1+json" #

COMMON_MANIFEST_ACCEPT_HEADERS = ", ".join([
    ACCEPT_MANIFEST_V2,
    ACCEPT_MANIFEST_LIST_V2,
    ACCEPT_MANIFEST_OCI,
    ACCEPT_OCI_INDEX_V1,
])

class RegistryClientError(Exception):
    """Base exception for registry client errors."""
    def __init__(self, message: str, status_code: Optional[int] = None, image_name: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.image_name = image_name

class RegistryImageNotFoundError(RegistryClientError):
    """Image or tag not found in the registry."""
    pass

class RegistryPermissionError(RegistryClientError):
    """Permission denied by the registry (e.g., deletion not allowed)."""
    pass

class RegistryService:
    def __init__(self, base_url: str = settings.DISTRIBUTION_REGISTRY_URL, timeout: int = settings.API_TIMEOUT_SECONDS):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout

    async def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict[str, Any]] = None, # For PUT/POST
        image_name_for_error: Optional[str] = None # For better error messages
    ) -> httpx.Response:
        url = f"{self.base_url}{path}"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                logger.debug(f"Registry Service Request: {method} {url} Params: {params} Headers: {headers}")
                response = await client.request(method, url, params=params, headers=headers, json=json_data)
                response.raise_for_status() # Raise HTTPStatusError for 4xx/5xx responses
                logger.debug(f"Registry Service Response: {response.status_code} {response.headers.get('Content-Type')}")
                return response
            except httpx.HTTPStatusError as exc:
                status_code = exc.response.status_code
                error_detail = exc.response.text
                logger.error(
                    f"Registry API error for {method} {url}: {status_code} - {error_detail}",
                    exc_info=True
                )
                if status_code == 404:
                    raise RegistryImageNotFoundError(
                        f"Resource not found: {path}",
                        status_code=status_code,
                        image_name=image_name_for_error
                    ) from exc
                if status_code == 405: # Method Not Allowed (e.g., delete not enabled)
                    raise RegistryPermissionError(
                        f"Operation not allowed for {path}: {error_detail}",
                        status_code=status_code,
                        image_name=image_name_for_error
                    ) from exc
                raise RegistryClientError(
                    f"Registry API request failed: {status_code} - {error_detail}",
                    status_code=status_code,
                    image_name=image_name_for_error
                ) from exc
            except httpx.RequestError as exc: # Network errors
                logger.error(f"Registry network error for {method} {url}: {exc}", exc_info=True)
                raise RegistryClientError(f"Network error accessing registry: {exc}") from exc


    async def list_image_tags(self, image_name: str) -> Dict[str, Any]: #
        path = f"/v2/{image_name}/tags/list"
        response = await self._request("GET", path, image_name_for_error=image_name)
        return response.json()

    async def list_repositories(self, n: Optional[int] = None, last: Optional[str] = None) -> Tuple[List[str], Optional[str]]: #
        path = "/v2/_catalog"
        params = {}
        if n is not None: params["n"] = n
        if last is not None: params["last"] = last
        response = await self._request("GET", path, params=params)

        repositories = response.json().get("repositories", [])
        link_header = response.headers.get("Link")
        # Basic parsing for 'next' link, can be more robust
        next_last = None
        if link_header and 'rel="next"' in link_header:
            try:
                # Example Link: </v2/_catalog?last=myimage&n=100>; rel="next"
                parts = link_header.split(';')
                url_part = parts[0].strip('<>')
                if 'last=' in url_part:
                    next_last = url_part.split('last=')[-1].split('&')[0]
            except Exception as e:
                logger.warning(f"Could not parse 'Link' header for pagination: {link_header}, Error: {e}")
        return repositories, next_last


    async def get_manifest_digest(self, image_name: str, reference: str) -> Optional[str]: #
        path = f"/v2/{image_name}/manifests/{reference}"
        headers = {"Accept": COMMON_MANIFEST_ACCEPT_HEADERS} #
        try:
            # Use HEAD request to get digest without downloading manifest body
            response = await self._request("HEAD", path, headers=headers, image_name_for_error=f"{image_name}:{reference}")
            return response.headers.get("Docker-Content-Digest")
        except RegistryImageNotFoundError: # If HEAD fails with 404, it means image/tag not found
            logger.warning(f"Manifest digest not found for {image_name}:{reference} (HEAD request failed with 404).")
            return None


    async def delete_manifest(self, image_name: str, digest: str) -> bool: #
        # Deleting a manifest is by digest. The registry ensures this is allowed.
        path = f"/v2/{image_name}/manifests/{digest}"
        try:
            # Docker Registry API expects DELETE requests to this endpoint.
            # A 202 Accepted response means the deletion was successful.
            response = await self._request("DELETE", path, image_name_for_error=image_name)
            return response.status_code == 202 # Accepted
        except RegistryImageNotFoundError:
            logger.warning(f"Manifest {digest} for image {image_name} not found for deletion (already deleted or never existed).")
            return False # Or True if "not found means success"
        except RegistryPermissionError as e:
            logger.error(f"Permission denied deleting manifest {digest} for {image_name}: {e}")
            raise # Re-raise to be handled by caller
        except RegistryClientError as e:
            logger.error(f"Error deleting manifest {digest} for {image_name}: {e}")
            return False


@lru_cache()
def get_registry_service():
    return RegistryService()