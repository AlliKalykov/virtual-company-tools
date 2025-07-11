from abc import ABC, abstractmethod
from datetime import datetime
from typing import Annotated, Literal
from urllib.parse import quote

import httpx
from httpx import Auth

from pydantic import JsonValue
from tenacity import AsyncRetrying, retry_if_exception, stop_after_attempt, wait_fixed

import logging
from pydantic import BaseModel


from typing import Any, ClassVar, Self, TypeVar, override


AuthType = Literal['oauth', 'pat', 'service_account']

SCHEMA_REPLACE_KEY = '__tolagent_replace'


T = TypeVar('T')


class ProviderArgument(BaseModel):
    valid_ids_key: ClassVar[str | None] = None

    @classmethod
    def replace_argument_schema(cls, argument_type: type) -> type | None | AuthType:
        return argument_type

    @classmethod
    # TODO: make schema immutable
    def replace_before_completion(cls, schema: dict[str, Any], valid_ids: dict[str, Any]) -> dict[str, Any]:
        if cls.valid_ids_key is None:
            return schema

        for value in [*schema.get('$defs', {}).values(), *schema.get('properties', {}).values()]:
            if value.get(SCHEMA_REPLACE_KEY) == cls.valid_ids_key:
                _ = cls.replace_in_defs_before_completion(value, valid_ids)
                del value[SCHEMA_REPLACE_KEY]

        return schema

    @classmethod
    def replace_in_defs_before_completion(cls, def_schema: dict[str, Any], valid_ids: dict[str, Any]) -> dict[str, Any]:  # pyright: ignore[reportUnusedParameter]
        return def_schema

    @classmethod
    async def replace_before_call(cls, argument_value: Any, providers: dict[str, Any]) -> Any:  # pyright: ignore[reportUnusedParameter]
        return argument_value


class ProviderImplementation(ProviderArgument):
    provider_key: ClassVar[str] = 'undefined'

    @override
    @classmethod
    async def replace_before_call(cls, argument_value: Any, providers: dict[str, Any]) -> Self:
        return cls.find_in(providers)

    @classmethod
    def find_in(cls, provider_implementations: dict[str, Any]) -> Self:
        if cls.provider_key == 'undefined':
            raise ValueError(f'You must override provider_key in {cls.__name__}')

        if cls.provider_key not in provider_implementations:
            raise ValueError(f'Provider impl {cls.provider_key} not found in {provider_implementations.keys()}')

        return provider_implementations[cls.provider_key]



# -------------------------------------------------------------------------------------------------
# AUTH Tool arguments
# -------------------------------------------------------------------------------------------------
class Token(BaseModel):
    token: str
    expires_at: Annotated[
        datetime,
        'The time when the token expires, if you don`t know'
        + '- you have a refresh token => use an hour from now.'
        + '- you don`t have a refresh token => use a month from now.',
    ]
    meta: Annotated[
        dict[str, Any],
        'Metadata for this specific token, you will receive it in function call',
    ] = {}


class AuthService(ProviderImplementation):
    provider_key: ClassVar[str] = 'auth_service'

    async def get_token(
        self,
    ) -> Token:
        raise NotImplementedError()


class TokenAuth(ProviderArgument):
    service: str | None
    token: str
    meta: dict[str, Any] = {}

    @override
    @classmethod
    def replace_argument_schema(cls, argument_type: type):
        return 'pat'

    @override
    @classmethod
    async def replace_before_call(cls, argument_value: dict[str, Any], providers: dict[str, Any]) -> 'TokenAuth':
        provider = AuthService.find_in(providers)

        token = await provider.get_token()

        return TokenAuth(
            service=None,
            token=token.token,
            meta=token.meta,
        )


class OAuthAuth(ProviderArgument):
    """
    OAuth token for a specific service. When used as argument type indicates that function need auth to function.
    You can omit Annotated[OAuthAuth, ''] when declaring your function since llms don't see this argument.
    """

    service: str | None
    token: str
    meta: dict[str, Any] = {}

    @override
    @classmethod
    def replace_argument_schema(cls, argument_type: type):
        return 'oauth'

    @override
    @classmethod
    async def replace_before_call(cls, argument_value: dict[str, Any], providers: dict[str, Any]) -> 'OAuthAuth':
        provider = AuthService.find_in(providers)

        token = await provider.get_token()

        return OAuthAuth(
            service=None,
            token=token.token,
            meta=token.meta,
        )


# -------------------------------------------------------------------------------------------------
# AUTH service implementations
# -------------------------------------------------------------------------------------------------


class SingleTokenAuthService(AuthService):
    """
    Used by tools server to add tokens for a single call id
    """

    token: Token

    @override
    async def get_token(self) -> Token:
        return self.token


# -------------------------------------------------------------------------------------------------
# AUTH handlers
# -------------------------------------------------------------------------------------------------


# Please keep all arguments mandatory so that people are propted to think about refresh tokens and expiration dates
class ProtoTokenMeta(BaseModel):
    token_meta: dict[str, Any]
    refresh_token: Token | None
    additional_info: str


class AuthSuccess(BaseModel):
    success: Literal[True] = True
    token: Token
    refresh_token: Token | None
    additional_info: Annotated[
        str,
        'Any additional info you obtained during the auth process, preferably json serializable',
    ]


class AuthFail(BaseModel):
    success: Literal[False] = False
    error: str


AuthResult = AuthSuccess | AuthFail


class IOAuthHandler(ABC):
    @staticmethod
    def get_auth_type() -> Literal['oauth']:
        return 'oauth'

    def __init__(self, base_redirect_uri: str, base_hash_uri: str, secrets: dict[str, str]):
        self.base_redirect_uri: str = base_redirect_uri
        self.base_hash_uri: str = base_hash_uri
        self.secrets: dict[str, str] = {k.lower(): v for k, v in secrets.items()}

    def get_secret(self, secret_name: str) -> str:
        """Get a secret like client_id or client_secret"""
        key = secret_name.lower()
        if key not in self.secrets:
            raise ValueError(f'Secret {key} was not provided for {self.__class__.__name__}')
        return self.secrets[key]

    def get_redirect_uri(self, service_name: str, url_quote: bool = True) -> str:
        """Fills in redirect_uri template with service_name"""
        uri = self.base_redirect_uri.format(service=service_name)

        if url_quote:
            return quote(uri)
        return uri

    def get_hash_uri(self, service_name: str, url_quote: bool = True) -> str:
        """
        Fills in hash_uri template with service_name.
        Hash uri is an endpoint with no side effects.
        It returns html page with javascript that does the following:
        - parses current url, like example.com/hash-converter/<service_name>#code=<code>
        - redirects to the normal redirect_uri, like example.com/auth-callback/<service_name>?code=<code>
        """
        uri = self.base_hash_uri.format(service=service_name)

        if url_quote:
            return quote(uri)
        return uri

    @abstractmethod
    def get_authorization_page_url(self) -> str:
        """Should return an URL of an approval page (https://developers.google.com/static/identity/protocols/images/oauth2/device/approval.png)
        ❗️ THIS METHOD MUST INCLUDE redirect_uri from self.get_redirect_uri() in the URL ❗️
        """
        pass

    @abstractmethod
    async def get_token(self, query_string: str) -> AuthResult:
        """Should ❗️ parse ❗️ query_string, maybe call a few endpoints and return a token.
        If you collect any additional info, return it in additional_info field"""
        pass

    @abstractmethod
    async def exchange_refresh_for_access_token(self, token: Token, refresh_token: Token) -> AuthResult:
        """
        Exchange refresh token for a new access token.
        Will be called when the access token expires according to expires_at.
        Will be called only if refresh_token was returned form get_token.
        If you return additional_info / refresh_token, it will override the one returned from get_token.
        """
        pass


class IPATHandler(ABC):
    def __init__(self):
        pass

    @staticmethod
    def get_auth_type() -> Literal['pat']:
        return 'pat'

    @abstractmethod
    def get_request_md(self) -> str:
        """Should return markdown guide for the user to issue a personal access token / API key / etc."""
        pass

    @abstractmethod
    async def validate_token(self, token: str) -> AuthResult:
        """Should make sure that the token provided by the user is valid, try calling some API endpoint with it"""
        pass


AuthHandler = IOAuthHandler | IPATHandler


class IntegrationBase(ABC):
    """Common settings and methods for integrations"""

    def __init__(self, api_url: str = ''):
        """api_url (str | None, optional): api url address to connect"""
        self.creds: str | None = None
        if not api_url:
            raise Exception('API URL is required')

        self.client: httpx.AsyncClient = httpx.AsyncClient()
        self.api_url: str = api_url
        self.authorisationStrategy: Auth | None = None
        self.logger: logging.Logger = logging.getLogger(self.__class__.__name__)
        self.httpx_request_timeout: int = 30
        # tenacity retry settings
        self.http_error_retry_codes: list[int] = []
        self.retry_attempts_count: int = 3
        self.delay_in_seconds_between_retries: int = 1

    @abstractmethod
    async def get_auth_headers(self) -> dict[str, str]:
        """Get auth headers for the API call"""
        return {}

    async def call_api(
        self,
        endpoint: str,
        method: Literal['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] = 'GET',
        data: dict[str, JsonValue] | None = None,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """
        Make a non-blocking API call to the specified endpoint.
        Retries the call if errors occur, and logs any 400 errors.

        Args:
            endpoint (str): The endpoint to make the API call to
            method (Literal["GET", "POST", "PUT", "DELETE", "PATCH"], optional):
            The HTTP method to use. Defaults to "GET".
            data (dict[str, Any] | None, optional): The data to send with the request. Defaults to None.
            params (dict[str, Any] | None, optional): The query parameters to send with the request.
            Defaults to None.

        Returns:
            httpx.Response: The response from the API call
        """
        url = f'{self.api_url}{endpoint}'
        headers = await self.get_auth_headers()
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(self.retry_attempts_count),
            wait=wait_fixed(self.delay_in_seconds_between_retries),
            retry=retry_if_exception(
                lambda r: isinstance(r, httpx.HTTPStatusError)
                and r.response.status_code in self.http_error_retry_codes,
            ),
        ):
            response = None
            with attempt:
                attempt = 0
                try:
                    self.logger.debug(f'Calling API at {url} using {method}')
                    response = await self.client.request(
                        method,
                        url,
                        headers=headers,
                        json=data,
                        params=params,
                        auth=self.authorisationStrategy,
                        timeout=self.httpx_request_timeout,
                    )
                    self.logger.debug(f'response status code {response.status_code}, response text: {response.text}')
                    # raise an exception if status code 4** or 5**
                    _ = response.raise_for_status()
                    return response

                except httpx.HTTPStatusError as http_err:
                    # handle error from response.raise_for_status()
                    self.logger.error(
                        f'HTTP error: {http_err} response: {response.text if response else "No response"} {data}',
                        exc_info=http_err,
                    )
                    raise http_err

                except Exception as err:
                    # handle all other errors
                    self.logger.exception(f'Unexpected error: {err}')
                    self.logger.error(f'Unexpected error: {err}', exc_info=err)
                    raise err
        raise Exception('Max retries reached')
