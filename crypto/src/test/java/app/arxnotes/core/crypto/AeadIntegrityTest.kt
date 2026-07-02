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

import app.arxnotes.core.crypto.TestSupport.testAesKey
import app.arxnotes.core.crypto.TestSupport.withFlippedBit
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Тесты ЦЕЛОСТНОСТИ и негативные сценарии для [AeadBlob] (AES-256-GCM).
 *
 * Главное проверяемое свойство: при ЛЮБОЙ модификации блоба — будь то шифртекст,
 * GCM-тег, IV, байт версии, длина или сам ключ — [AeadBlob.open] обязан вернуть
 * `null` и не отдать ни байта частичного/исходного текста. GCM аутентифицирует
 * весь шифртекст разом: тег проверяется ДО выдачи данных, поэтому «частичной
 * расшифровки» в принципе не существует — провал целостности означает ровно `null`.
 *
 * Формат блоба (см. [AeadBlob]):
 *
 *     [версия: 1][IV: IV_SIZE][шифртекст + GCM-тег: 16]
 *
 * Все ключи здесь — синтетические тестовые ([TestSupport.testAesKey]); это сырые
 * AES-ключи, для которых [AeadBlob.open] по контракту НИКОГДА не бросает исключений.
 */
class AeadIntegrityTest {

    private companion object {
        /** Версия блоба для тестов — значение произвольно, важна лишь согласованность seal/open. */
        const val BLOB_VERSION: Byte = 1
        /** Чужая версия, заведомо не равная [BLOB_VERSION], для проверки отказа по версии. */
        const val OTHER_VERSION: Byte = 2

        /** Смещение первого байта шифртекста: сразу после [версия][IV]. */
        const val CIPHERTEXT_OFFSET = 1 + AeadBlob.IV_SIZE
        /** Размер GCM-тега в байтах (последние байты блоба). */
        const val TAG_BYTES = AeadBlob.TAG_BITS / 8
    }

    private val key = testAesKey()
    private val plaintext = "целостность важнее всего 🔐".toByteArray()

    /** Контрольный путь: нетронутый блоб открывается и даёт ровно исходный текст. */
    @Test
    fun untamperedBlob_opensToOriginalPlaintext() {
        val blob = AeadBlob.seal(key, plaintext, BLOB_VERSION)
        assertArrayEquals(plaintext, AeadBlob.open(key, blob, BLOB_VERSION))
    }

    /** Флип одного бита в ШИФРТЕКСТЕ ломает GCM-тег → open == null (никаких частичных данных). */
    @Test
    fun flippedCiphertextBit_returnsNull() {
        val blob = AeadBlob.seal(key, plaintext, BLOB_VERSION)
        // Берём байт внутри области шифртекста (после [версия][IV]), но до тега.
        val tampered = withFlippedBit(blob, CIPHERTEXT_OFFSET)
        assertNull(AeadBlob.open(key, tampered, BLOB_VERSION))
    }

    /** Флип бита в GCM-ТЕГЕ (последние 16 байт) → проверка тега не сходится → null. */
    @Test
    fun flippedTagBit_returnsNull() {
        val blob = AeadBlob.seal(key, plaintext, BLOB_VERSION)
        val tampered = withFlippedBit(blob, blob.size - 1)   // последний байт лежит внутри тега
        assertNull(AeadBlob.open(key, tampered, BLOB_VERSION))
    }

    /** Флип бита в IV меняет nonce → пересчитанный тег не сходится с записанным → null. */
    @Test
    fun flippedIvBit_returnsNull() {
        val blob = AeadBlob.seal(key, plaintext, BLOB_VERSION)
        val tampered = withFlippedBit(blob, 1)               // первый байт IV, сразу за версией
        assertNull(AeadBlob.open(key, tampered, BLOB_VERSION))
    }

    /** Порча байта ВЕРСИИ (blob[0]) → запрошенная версия не совпадает → null до всякой криптографии. */
    @Test
    fun corruptedVersionByte_returnsNull() {
        val blob = AeadBlob.seal(key, plaintext, BLOB_VERSION)
        val tampered = withFlippedBit(blob, 0)               // меняем байт версии
        assertNull(AeadBlob.open(key, tampered, BLOB_VERSION))
    }

    /** Усечение до различных длин префикса → блоб неполный → null (нет частичной расшифровки). */
    @Test
    fun truncatedToVariousPrefixLengths_returnsNull() {
        val blob = AeadBlob.seal(key, plaintext, BLOB_VERSION)
        // 0 — пусто; 1 — только версия; 13 — версия+IV без шифртекста; size-1 — обрезан тег.
        for (length in intArrayOf(0, 1, 1 + AeadBlob.IV_SIZE, blob.size - 1)) {
            assertNull("длина префикса=$length", AeadBlob.open(key, blob.copyOf(length), BLOB_VERSION))
        }
    }

    /** Блоб короче минимально возможного (даже пустой) → null, без исключений. */
    @Test
    fun belowMinimumSize_returnsNull() {
        // Минимум — [версия][IV][тег]; всё короче не может содержать аутентифицированных данных.
        assertNull(AeadBlob.open(key, ByteArray(0), BLOB_VERSION))
        assertNull(AeadBlob.open(key, ByteArray(AeadBlob.IV_SIZE), BLOB_VERSION))
        assertNull(AeadBlob.open(key, ByteArray(CIPHERTEXT_OFFSET + TAG_BYTES - 1), BLOB_VERSION))
    }

    /** Открытие ДРУГИМ ключом (A запечатал, B открывает) → тег не сходится → null. */
    @Test
    fun wrongKey_returnsNull() {
        val blob = AeadBlob.seal(testAesKey(0x2A), plaintext, BLOB_VERSION)
        // Другое зерно → другой 256-битный ключ; GCM-тег под ним не подтвердится.
        assertNull(AeadBlob.open(testAesKey(0x99), blob, BLOB_VERSION))
    }

    /** Запрос ДРУГОЙ версии в open (seal v1, open v2) → отказ по версии → null. */
    @Test
    fun mismatchedVersionRequested_returnsNull() {
        val blob = AeadBlob.seal(key, plaintext, BLOB_VERSION)
        assertNull(AeadBlob.open(key, blob, OTHER_VERSION))
    }

    /**
     * Сводное свойство: НИ в одном негативном сценарии не утекают частичные/исходные данные.
     *
     * GCM не выдаёт расшифрованный текст до успешной проверки тега, поэтому корректный
     * отказ — это именно `null`, а не «кусок открытого текста». Здесь мы перебираем
     * представительный набор порч и для каждого требуем строго `null` (а не, например,
     * пустой или частичный массив), фиксируя контракт «всё или ничего».
     */
    @Test
    fun noNegativeCaseLeaksPlaintext_alwaysExactlyNull() {
        val blob = AeadBlob.seal(key, plaintext, BLOB_VERSION)
        val tamperedVariants = listOf(
            withFlippedBit(blob, 0),                    // версия
            withFlippedBit(blob, 1),                    // IV
            withFlippedBit(blob, CIPHERTEXT_OFFSET),    // шифртекст
            withFlippedBit(blob, blob.size - 1),        // тег
            blob.copyOf(blob.size - 1),                 // усечение
        )
        for (variant in tamperedVariants) {
            // assertNull достаточно: контракт GCM исключает частичную выдачу,
            // поэтому отсутствие исключения + строгий null = отсутствие утечки.
            assertNull(AeadBlob.open(key, variant, BLOB_VERSION))
        }
    }
}
