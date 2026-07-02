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

import java.io.ByteArrayOutputStream
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HKDF на HMAC-SHA256 (RFC 5869) — для доменного разделения ключей.
 *
 * Из одного мастер-секрета получаем независимые подключи под каждое назначение
 * (БД, аудио, …) через [info]-метку. Компрометация одного подключа не раскрывает
 * мастер и другие подключи. Реализация на стандартном [Mac] — без сторонних
 * зависимостей и проста для аудита.
 */
internal object Hkdf {

    private const val HMAC = "HmacSHA256"
    private const val HASH_LEN = 32

    /**
     * Полный HKDF: extract(salt, ikm) → expand(prk, info, length).
     * @param ikm   входной секрет (мастер-ключ)
     * @param salt  соль (необязательна; null → нулевая соль длины хеша, как в RFC)
     * @param info  контекст/назначение подключа (домен)
     * @param length длина результата в байтах (≤ 255*32)
     */
    fun derive(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray {
        require(length in 1..(255 * HASH_LEN)) { "Invalid HKDF length: $length" }
        val prk = extract(salt ?: ByteArray(HASH_LEN), ikm)
        return expand(prk, info, length)
    }

    private fun extract(salt: ByteArray, ikm: ByteArray): ByteArray =
        hmac(salt).doFinal(ikm)

    private fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = hmac(prk)
        val out = ByteArrayOutputStream(length)
        var block = ByteArray(0)
        var counter = 1
        while (out.size() < length) {
            mac.reset()
            mac.update(block)
            mac.update(info)
            mac.update(counter.toByte())
            block = mac.doFinal()
            out.write(block)
            counter++
        }
        return out.toByteArray().copyOf(length)
    }

    private fun hmac(key: ByteArray): Mac =
        Mac.getInstance(HMAC).apply { init(SecretKeySpec(key, HMAC)) }
}
