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

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Общие помощники для модульных тестов `:crypto`.
 *
 * ВАЖНО: всё здесь — СИНТЕТИЧЕСКИЕ, ДЕТЕРМИНИРОВАННЫЕ данные исключительно для тестов.
 * Ни одного настоящего ключа, пароля или PIN. Тестовые ключи НЕ происходят из Keystore
 * и пригодны только для прямой проверки примитивов ([AeadBlob], [Hkdf]).
 */
internal object TestSupport {

    /**
     * Синтетический детерминированный AES-256 ключ для тестов примитивов.
     * НЕ имеет отношения к продакшн-ключам (те приходят из Android Keystore/HKDF).
     */
    fun testAesKey(seed: Int = 0x2A): SecretKey =
        SecretKeySpec(ByteArray(32) { (seed + it).toByte() }, "AES")

    /** Разбор hex-строки в байты — для эталонных тест-векторов (KAT). */
    fun hex(s: String): ByteArray {
        require(s.length % 2 == 0) { "hex длины нечётной: ${s.length}" }
        return ByteArray(s.length / 2) {
            ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte()
        }
    }

    /** Копия [data] с инвертированным одним битом в байте [index] — для тестов тамперинга. */
    fun withFlippedBit(data: ByteArray, index: Int): ByteArray =
        data.copyOf().also { it[index] = (it[index].toInt() xor 0x01).toByte() }

    // Помеченные как ТЕСТОВЫЕ синтетические учётные данные (не настоящие секреты).
    const val TEST_PASSWORD = "correct horse battery staple" // пример из xkcd 936, заведомо публичный
    const val TEST_PIN = "1234"
}
