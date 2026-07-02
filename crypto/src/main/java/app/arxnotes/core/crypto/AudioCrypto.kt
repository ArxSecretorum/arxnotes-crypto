/*
 * Copyright 2026 Arx Secretorum
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package app.arxnotes.core.crypto

import javax.crypto.spec.SecretKeySpec

/**
 * Шифрование/расшифровка байтов голосовых заметок (AES-256-GCM, формат [AeadBlob]).
 *
 * Ключ — отдельный HKDF-подключ домена «audio» из мастер-секрета
 * ([MasterKeyManager.audioKey]); он не совпадает с ключом БД.
 *
 * Расшифровка возвращает null при битом/чужом блобе (неверный тег, обрезка, чужая версия).
 */
class AudioCrypto(keyManager: MasterKeyManager) {

    private val key by lazy { SecretKeySpec(keyManager.audioKey(), "AES") }

    fun encrypt(plaintext: ByteArray): ByteArray = AeadBlob.seal(key, plaintext, VERSION)

    fun decrypt(blob: ByteArray): ByteArray? = AeadBlob.open(key, blob, VERSION)

    private companion object {
        const val VERSION: Byte = 1
    }
}
