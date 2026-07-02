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

import android.security.keystore.KeyPermanentlyInvalidatedException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Общий AES-256-GCM примитив для самоописывающих блобов одного формата:
 *
 *     [версия (1 байт)][IV (12 байт)][шифртекст + GCM-тег (16 байт)]
 *
 * Используется в двух местах с разными ключами:
 *  - обёртка мастер-секрета — ключ из Android Keystore ([MasterKeyManager]);
 *  - голосовые заметки — сырой HKDF-подключ домена «audio» ([AudioCrypto]).
 *
 * IV генерирует сам GCM-провайдер (криптослучайный, 12 байт) — мы его не задаём.
 * [open] возвращает null на любом коротком/чужом/битом блобе. Единственное исключение —
 * KeyPermanentlyInvalidatedException для аннулированного Keystore-ключа (обёртка мастера):
 * оно пробрасывается, чтобы вызывающий отличил невосстановимость ключа от порчи данных.
 * Сырые HKDF-ключи (аудио) этого исключения не вызывают — для них open никогда не бросает.
 */
internal object AeadBlob {

    const val IV_SIZE = 12          // GCM nonce
    const val TAG_BITS = 128        // полный 16-байтовый тег
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val MIN_SIZE = 1 + IV_SIZE + TAG_BITS / 8

    /** Запечатать [plaintext] под [key], пометив байтом [version]. */
    fun seal(key: SecretKey, plaintext: ByteArray, version: Byte): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }
        val iv = cipher.iv
        check(iv.size == IV_SIZE) { "Unexpected GCM IV size ${iv.size}" }
        val ciphertext = cipher.doFinal(plaintext)
        return ByteArray(1 + iv.size + ciphertext.size).also { out ->
            out[0] = version
            System.arraycopy(iv, 0, out, 1, iv.size)
            System.arraycopy(ciphertext, 0, out, 1 + iv.size, ciphertext.size)
        }
    }

    /** Открыть [blob]; вернёт null если он короче минимума, версия не [version] или тег не сошёлся. */
    fun open(key: SecretKey, blob: ByteArray, version: Byte): ByteArray? {
        if (blob.size < MIN_SIZE || blob[0] != version) return null
        val iv = blob.copyOfRange(1, 1 + IV_SIZE)
        val ciphertext = blob.copyOfRange(1 + IV_SIZE, blob.size)
        return try {
            Cipher.getInstance(TRANSFORMATION).run {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
                doFinal(ciphertext)
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            // Только для Keystore-ключа (обёртка мастера): система аннулировала ключ.
            // Это НЕ «битый блоб» — пробрасываем, чтобы вызывающий отличил
            // невосстановимость от порчи. Сырые HKDF-ключи (аудио) этого не бросают.
            throw e
        } catch (e: Exception) {
            null   // короткий/чужой/битый блоб или неверный ключ → тег не сошёлся
        }
    }
}
