# SPDX-FileCopyrightText: 2018-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0

import mock
from tests import util

from mora.config import Settings

import tests.cases


class Tests(tests.cases.AsyncTestCase):
    maxDiff = None

    @mock.patch("mora.service.exports.os.path.isdir", lambda x: False)
    async def test_list_export_files_raises_on_invalid_dir(self):
        """Ensure we handle missing export dir"""
        await self.assertRequestResponse(
            "/service/exports/",
            {
                "description": "Directory does not exist.",
                "error": True,
                "error_key": "E_DIR_NOT_FOUND",
                "status": 500,
            },
            status_code=500,
        )

    # TODO: AssertionError: Lists differ: ['file1', 'file2'] != []
    @util.override_config(Settings(query_export_dir=""))
    @mock.patch("mora.service.exports.os.path.isdir", lambda x: True)
    @mock.patch("mora.service.exports.os.path.isfile")
    @mock.patch("mora.service.exports.os.listdir")
    async def test_list_export_files_returns_filenames(self, mock_listdir, mock_isfile):
        """Ensure that we only return filenames from the export directory"""
        filenames = ["file1", "file2"]

        def mocked_isfile(filename):
            return filename in filenames

        mock_listdir.return_value = filenames + ["dir"]

        mock_isfile.side_effect = mocked_isfile

        await self.assertRequestResponse("/service/exports/", filenames)

    @mock.patch("mora.service.exports.os.path.isdir", lambda x: False)
    async def test_get_export_file_raises_on_invalid_dir(self):
        """Ensure we handle missing export dir"""
        await self.assertRequestResponse(
            "/service/exports/whatever",
            {
                "description": "Directory does not exist.",
                "error": True,
                "error_key": "E_DIR_NOT_FOUND",
                "status": 500,
            },
            status_code=500,
        )

    @mock.patch("mora.service.exports.os.path.isdir", lambda x: True)
    @mock.patch("mora.service.exports.os.path.isfile", lambda x: False)
    async def test_get_export_file_raises_on_file_not_found(self):
        """Ensure we handle nonexistent files"""
        await self.assertRequestResponse(
            "/service/exports/whatever",
            {
                "description": "Not found.",
                "error": True,
                "error_key": "E_NOT_FOUND",
                "filename": "whatever",
                "status": 404,
            },
            status_code=404,
        )

    @mock.patch("mora.service.exports.os.path.isdir", lambda x: True)
    @mock.patch("mora.service.exports.os.path.isfile", lambda x: True)
    @mock.patch("mora.service.exports.FileResponse")
    async def test_get_export_file_returns_file(self, mock_send_file):
        """Ensure we return a file if found"""

        mock_send_file.return_value = "I am a file"

        await self.assertRequestResponse("/service/exports/whatever", "I am a file")
        mock_send_file.assert_called_once()
