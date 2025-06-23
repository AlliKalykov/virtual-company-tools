import os
import base64
import json
import logging
import asyncio

from dotenv import load_dotenv
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Dict, List

from auth import Token, TokenAuth, IntegrationBase

load_dotenv()
logger = logging.getLogger(__name__)


class _JiraIntegration(IntegrationBase):
    def __init__(self, api_url: str):
        super().__init__(api_url)

    def initialize_integration(self, token, email):
        self.creds = token
        self.email = email

    async def get_auth_headers(self) -> Dict[str, str]:
        auth_str = f'{self.email}:{self.creds}'
        encoded_auth = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
        return {
            'Authorization': f'Basic {encoded_auth}',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }


def _get_integration(token, api_url, email) -> _JiraIntegration:
    integration = _JiraIntegration(api_url)
    integration.initialize_integration(token, email)
    return integration


async def jira_get_board_issues(
    auth: Annotated[TokenAuth, 'Authorisation instance'],
    board_id: Annotated[int, 'ID Jira-доски (board)'],
    max_results: Annotated[int, 'максимум issues на запрос'] = 50,
) -> List[Dict[str, Any]]:
    """
    Возвращает список задач доски в формате, близком к примеру jira_issues.json.
    """
    integration = _get_integration(
        auth.token,
        auth.meta['api_url'],
        auth.meta['email'],
    )

    params = {
        'maxResults': max_results,
        'expand': 'fields.comment',
    }
    endpoint = f'/rest/agile/1.0/board/{board_id}/issue'

    # вот здесь важно await
    resp = await integration.call_api(endpoint, method='GET', params=params)
    data = resp.json()  # если resp.json() синхронный

    issues_normalized: List[Dict[str, Any]] = []
    for issue in data.get('issues', []):
        f = issue['fields']
        comments = [
            {
                'author': c['author'].get('displayName'),
                'body': c.get('body'),
                'created_at': c.get('created'),
            }
            for c in f.get('comment', {}).get('comments', [])
        ]

        issues_normalized.append({
            'key': issue.get('key'),
            'summary': f.get('summary'),
            'status': f.get('status', {}).get('name'),
            'description': f.get('description'),
            'assignee': f.get('assignee', {}).get('displayName') if f.get('assignee') else None,
            'reporter': f.get('reporter', {}).get('displayName') if f.get('reporter') else None,
            'type': f.get('issuetype', {}).get('name'),
            'priority': f.get('priority', {}).get('name') if f.get('priority') else None,
            'created_at': f.get('created'),
            'updated_at': f.get('updated'),
            'epic_link': f.get('customfield_10008'),
            'comments': comments,
        })

    return issues_normalized


def write_issues_to_file(
    issues: List[Dict[str, Any]],
    path: Annotated[Path, 'Путь до файла, например Path("jira_issues.json")']
) -> None:
    """
    Сохраняет список задач в JSON-файл.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as f:
        json.dump(issues, f, ensure_ascii=False, indent=2)


async def export_board_issues_to_file(
    auth: Annotated[TokenAuth, 'Authorisation instance'],
    board_id: Annotated[int, 'ID Jira-доски'],
    file_path: Annotated[str, 'Имя или путь файла для сохранения'] = 'jira_issues.json',
) -> None:
    """
    Получает задачи доски и записывает их в файл.
    """
    issues = await jira_get_board_issues(auth, board_id)
    write_issues_to_file(issues, Path(file_path))


if __name__ == '__main__':
    JIRA_TOKEN = os.environ.get("JIRA_TOKEN")
    if not JIRA_TOKEN:
        raise EnvironmentError("JIRA_TOKEN must be set in environment variables")
    JIRA_API_URL = os.environ.get("JIRA_API_URL")
    if not JIRA_API_URL:
        raise EnvironmentError("JIRA_URL must be set in environment variables")
    JIRA_EMAIL = os.environ.get("JIRA_EMAIL")
    if not JIRA_EMAIL:
        raise EnvironmentError("JIRA_EMAIL must be set in environment variables")
    token = Token(
        token=JIRA_TOKEN,
        expires_at=datetime.now() + timedelta(weeks=30),
        meta={
            'api_url': JIRA_API_URL,
            'email': JIRA_EMAIL ,
        },
    )
    auth = TokenAuth(
        service='jira',
        token=token.token,
        meta=token.meta,
    )
    JIRA_BOARD_ID = int(os.environ.get("JIRA_BOARD_ID"))
    if not JIRA_BOARD_ID:
        raise EnvironmentError("JIRA_BOARD_ID must be set in environment variables")
    # запускаем весь экспорт
    asyncio.run(export_board_issues_to_file(auth, JIRA_BOARD_ID, "jira_issues.json"))
