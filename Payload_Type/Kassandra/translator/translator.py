import json
import logging

from mythic_container.TranslationBase import *

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class KassandraTranslation(TranslationContainer):
    name = "KassandraTranslator"
    description = "Passthrough translator for Kassandra"
    author = "@PatchRequest"

    async def generate_keys(self, inputMsg: TrGenerateEncryptionKeysMessage) -> TrGenerateEncryptionKeysMessageResponse:
        response = TrGenerateEncryptionKeysMessageResponse(Success=True)
        response.DecryptionKey = b""
        response.EncryptionKey = b""
        return response

    async def translate_to_c2_format(self, inputMsg: TrMythicC2ToCustomMessageFormatMessage) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        response = TrMythicC2ToCustomMessageFormatMessageResponse(Success=True)
        response.Message = json.dumps(inputMsg.Message).encode()
        return response

    async def translate_from_c2_format(self, inputMsg: TrCustomMessageToMythicC2FormatMessage) -> TrCustomMessageToMythicC2FormatMessageResponse:
        response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)
        try:
            if isinstance(inputMsg.Message, bytes):
                response.Message = json.loads(inputMsg.Message)
            else:
                response.Message = json.loads(inputMsg.Message)
        except Exception as e:
            logger.error(f'[TRANSLATOR] JSON parse failed: {e}')
            raise
        return response
