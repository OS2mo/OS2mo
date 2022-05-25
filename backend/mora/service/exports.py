# SPDX-FileCopyrightText: 2018-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0
from typing import Optional

from fastapi import APIRouter
from fastapi import Cookie
from fastapi import HTTPException
from fastapi.responses import FileResponse

from mora import exceptions
from mora.auth.keycloak.oidc import validate_token
from mora.graphapi.files import get_export_dir


router = APIRouter()


async def _check_auth_cookie(auth_cookie=Optional[str]) -> None:
    if auth_cookie is None:
        raise HTTPException(status_code=401, detail="Missing download cookie!")
    await validate_token(str(auth_cookie))


@router.get(
    "/exports/{file_name}",
    responses={"500": {"description": "Directory does not exist"}},
)
async def download_export_file(
    file_name: str,
    mo_file_download: Optional[str] = Cookie(None, alias="MO_FILE_DOWNLOAD"),
):
    """Download an export file with a given name.

    :param string file_name: Name of the export file.
    :param string mo_file_download: OIDC Token used for authentication.

    :return: The file data corresponding to the given export file name.
    """
    await _check_auth_cookie(mo_file_download)

    export_dir = get_export_dir()
    file_path = export_dir / file_name
    if not file_path.is_file():
        exceptions.ErrorCodes.E_NOT_FOUND(filename=file_name)

    return FileResponse(file_path)
