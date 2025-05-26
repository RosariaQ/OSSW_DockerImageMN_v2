# app/services/htpasswd_service.py
import subprocess
import shlex
import logging
from pathlib import Path
from typing import List, Optional
from functools import lru_cache

from passlib.apache import HtpasswdFile #
from app.core.config import settings
from app.models.audit_actions import AuditAction # AuditAction 사용 고려 (로깅용)
# from app.db.database import log_audit_event # 직접 여기서 감사로그를 남길 수도 있으나, 보통 호출부에서 남김
# from app.models.audit import AuditLogDBCreate # 위와 동일

logger = logging.getLogger(__name__)

class HtpasswdError(Exception):
    """Base exception for htpasswd operations."""
    pass

class HtpasswdCommandError(HtpasswdError):
    """Exception for errors during htpasswd command execution."""
    def __init__(self, message, stderr=None):
        super().__init__(message)
        self.stderr = stderr

class HtpasswdUtilityNotFoundError(HtpasswdError):
    """Exception if htpasswd utility is not found."""
    pass

class HtpasswdFileAccessError(HtpasswdError):
    """Exception if the .htpasswd file itself is not accessible or readable."""
    pass


class HtpasswdService:
    def __init__(self, htpasswd_file_path: Path):
        self.htpasswd_file_path = htpasswd_file_path
        if not self.htpasswd_file_path.parent.exists():
            # 운영 환경에서는 치명적일 수 있으므로 경고 수준을 높이거나 예외 발생
            logger.warning(
                f"Parent directory for htpasswd file {self.htpasswd_file_path} does not exist. "
                "Htpasswd operations may fail if the directory is not created."
            )

    def _get_htfile(self) -> Optional[HtpasswdFile]:
        """Loads the HtpasswdFile object, returning None if not found or error."""
        try:
            if self.htpasswd_file_path.exists():
                return HtpasswdFile(str(self.htpasswd_file_path)) #
            else:
                logger.warning(f"Htpasswd file not found at: {self.htpasswd_file_path}")
                return None
        except Exception as e:
            logger.error(f"Error loading Htpasswd file ({self.htpasswd_file_path}): {e}", exc_info=True)
            # HtpasswdFileAccessError를 발생시켜 호출부에서 처리하도록 할 수 있음
            # raise HtpasswdFileAccessError(f"Error loading Htpasswd file: {e}")
            return None

    def _run_command(self, command_args: List[str], password_to_mask: Optional[str] = None) -> str:
        # 명령어 로깅 시 비밀번호 마스킹
        log_command_args = list(command_args)
        if password_to_mask:
            try:
                idx = log_command_args.index(password_to_mask)
                log_command_args[idx] = '********'
            except ValueError:
                pass # 비밀번호가 명시적으로 리스트에 없는 경우 (shlex.quote 등으로 인해)

        logger.info(f"Executing htpasswd command: {' '.join(log_command_args)}")
        try:
            process = subprocess.run(
                command_args,
                capture_output=True,
                text=True,
                check=True, # Raises CalledProcessError on non-zero exit
                encoding='utf-8'
            )
            logger.info(f"htpasswd command successful. Output: {process.stdout.strip()}")
            return process.stdout.strip()
        except subprocess.CalledProcessError as e:
            error_output = (e.stderr or e.stdout or "Unknown htpasswd error").strip()
            logger.error(f"htpasswd command failed. Error: {error_output}. Command: {' '.join(log_command_args)}")
            raise HtpasswdCommandError(f"htpasswd command execution failed: {error_output}", stderr=error_output)
        except FileNotFoundError:
            logger.error(f"htpasswd command not found. Ensure apache2-utils is installed and htpasswd is in PATH.")
            raise HtpasswdUtilityNotFoundError("htpasswd command not found. Server configuration issue.")
        except Exception as e: # Catch any other unexpected errors
            logger.error(f"Unexpected error during htpasswd command execution: {e}. Command: {' '.join(log_command_args)}", exc_info=True)
            raise HtpasswdError(f"An unexpected error occurred with htpasswd: {e}")

    def add_user(self, username: str, password: str) -> None:
        # htpasswd 명령어는 파일이 없으면 -c 옵션과 함께 사용될 때 파일을 생성합니다.
        # 사용자를 추가할 때는 일반적으로 파일이 이미 존재한다고 가정합니다.
        # 만약 파일이 없을 수도 있다면, 첫 사용자 추가 시 -c 옵션을 동적으로 추가하는 로직이 필요합니다.
        # 현재 코드는 settings.HTPASSWD_FILE이 존재하거나 htpasswd가 적절히 처리한다고 가정합니다.
        command = [
            "htpasswd",
            "-B",  # bcrypt 사용
            "-b",  # 배치 모드 (명령줄에서 비밀번호 전달)
            shlex.quote(str(self.htpasswd_file_path)),
            shlex.quote(username),
            shlex.quote(password) # 실제 비밀번호 전달
        ]
        self._run_command(command, password_to_mask=password)

    def delete_user(self, username: str) -> None:
        command = [
            "htpasswd",
            "-D",  # 사용자 삭제
            shlex.quote(str(self.htpasswd_file_path)),
            shlex.quote(username)
        ]
        self._run_command(command)

    def list_users(self) -> List[str]:
        ht_file = self._get_htfile()
        if ht_file:
            return ht_file.users() #
        # 파일이 없거나 로드 오류 시 HtpasswdFileAccessError 발생 또는 빈 리스트 반환
        # 여기서는 기존 동작과 유사하게 빈 리스트 반환 (오류는 _get_htfile에서 로깅됨)
        raise HtpasswdFileAccessError(f"Htpasswd file {self.htpasswd_file_path} not found or unreadable for listing users.")


    def check_password(self, username: str, password: str) -> bool:
        ht_file = self._get_htfile()
        if ht_file is None:
            # 이 경우 시스템 설정 오류로 간주하고 인증 실패 처리
            logger.error(f"Cannot check password for '{username}'. Htpasswd file system unavailable.")
            # AuditLogDBCreate 이벤트를 여기서 직접 발생시키거나, 호출 측에서 처리
            # 예: await log_audit_event(AuditLogDBCreate(action=AuditAction.SYSTEM_HTPASSWD_UNAVAILABLE, ...))
            return False
        return ht_file.check_password(username, password) #

    def user_exists(self, username: str) -> bool:
        ht_file = self._get_htfile()
        if ht_file is None:
            # 위와 동일하게 시스템 오류로 간주 가능
            logger.error(f"Cannot check existence of user '{username}'. Htpasswd file system unavailable.")
            return False
        return username in ht_file.users()


@lru_cache()
def get_htpasswd_service():
    return HtpasswdService(settings.HTPASSWD_FILE)