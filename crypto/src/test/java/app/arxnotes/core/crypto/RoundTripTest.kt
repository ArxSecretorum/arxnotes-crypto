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

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

/**
 * Round-trip (туда-обратно) набор для всех крипто-путей `:crypto`.
 *
 * Проверяемое свойство: для каждого пути `зашифровать → расшифровать` возвращает
 * ровно те же байты, что и на входе (побайтовая идентичность через [assertArrayEquals]).
 * Это базовая гарантия корректности и бинарной безопасности — данные не теряются,
 * не «дополняются» и не искажаются на любом содержимом (юникод, нули, весь диапазон байта).
 *
 * Для HKDF round-trip как такового нет (это однонаправленный KDF), поэтому здесь
 * проверяются его инвариантные свойства: детерминизм, доменное разделение и точная длина.
 *
 * Все ключи/пароли — синтетика из [TestSupport]; реальных секретов нет.
 * Аргон2id в [BackupCrypto] дорогой (m=64 MiB, t=3), поэтому число вызовов
 * `encrypt` намеренно держим минимальным.
 */
class RoundTripTest {

    /** Версия блоба для seal/open в тестах — само значение неважно, важна согласованность. */
    private val blobVersion: Byte = 1

    // --- AeadBlob: AES-256-GCM на синтетическом ключе -------------------------------------

    /** AeadBlob: обычный текст с кириллицей и эмодзи восстанавливается побайтово. */
    @Test
    fun aeadBlob_unicodeText_roundTrips() {
        val key = TestSupport.testAesKey()
        val plaintext = "Привет, Arx Notes! Заметка с эмодзи 🔐📝".toByteArray(Charsets.UTF_8)

        val blob = AeadBlob.seal(key, plaintext, blobVersion)
        val opened = AeadBlob.open(key, blob, blobVersion)

        assertArrayEquals(plaintext, opened)
    }

    /** AeadBlob: пустой ByteArray(0) — корректный вырожденный случай (нечего шифровать, но тег есть). */
    @Test
    fun aeadBlob_emptyInput_roundTrips() {
        val key = TestSupport.testAesKey()
        val empty = ByteArray(0)

        val blob = AeadBlob.seal(key, empty, blobVersion)
        val opened = AeadBlob.open(key, blob, blobVersion)

        assertArrayEquals(empty, opened)
    }

    /**
     * AeadBlob: все 256 значений байта проходят без искажений — гарантия бинарной
     * безопасности (шифр не «спотыкается» на 0x00, 0xFF или управляющих байтах).
     */
    @Test
    fun aeadBlob_allByteValues_roundTrip() {
        val key = TestSupport.testAesKey()
        val allBytes = ByteArray(256) { it.toByte() }

        val blob = AeadBlob.seal(key, allBytes, blobVersion)
        val opened = AeadBlob.open(key, blob, blobVersion)

        assertArrayEquals(allBytes, opened)
    }

    /**
     * AeadBlob: большой буфер (1 MiB) восстанавливается побайтово — проверяем, что
     * потоковая обработка GCM не ломается на размере, заметно большем одного блока.
     * RNG детерминирован (фикс. seed) ради воспроизводимости при падении теста.
     */
    @Test
    fun aeadBlob_largeBuffer_roundTrips() {
        val key = TestSupport.testAesKey()
        val large = ByteArray(1 shl 20).also { Random(0xBADC0DE).nextBytes(it) } // 1 MiB

        val blob = AeadBlob.seal(key, large, blobVersion)
        val opened = AeadBlob.open(key, blob, blobVersion)

        assertArrayEquals(large, opened)
    }

    // --- BackupCrypto: Argon2id + AES-256-GCM (дорогой KDF → мало вызовов) -----------------

    /** BackupCrypto: текст с кириллицей и эмодзи под паролем восстанавливается побайтово. */
    @Test
    fun backupCrypto_unicodeText_roundTrips() {
        val plaintext = "Резервная копия 📦 заметок и задач".toByteArray(Charsets.UTF_8)

        val blob = BackupCrypto.encrypt(plaintext, TestSupport.TEST_PASSWORD)
        val opened = BackupCrypto.decrypt(blob, TestSupport.TEST_PASSWORD)

        assertArrayEquals(plaintext, opened)
    }

    /** BackupCrypto: пустые данные — заголовок и тег формируются, расшифровка даёт пустоту. */
    @Test
    fun backupCrypto_emptyInput_roundTrips() {
        val empty = ByteArray(0)

        val blob = BackupCrypto.encrypt(empty, TestSupport.TEST_PASSWORD)
        val opened = BackupCrypto.decrypt(blob, TestSupport.TEST_PASSWORD)

        assertArrayEquals(empty, opened)
    }

    /**
     * BackupCrypto: умеренно большой буфер (100 KiB) восстанавливается побайтово —
     * реалистичный размер файла бэкапа. RNG детерминирован ради воспроизводимости.
     */
    @Test
    fun backupCrypto_largeBuffer_roundTrips() {
        val data = ByteArray(100 * 1024).also { Random(0x5AFE).nextBytes(it) } // 100 KiB

        val blob = BackupCrypto.encrypt(data, TestSupport.TEST_PASSWORD)
        val opened = BackupCrypto.decrypt(blob, TestSupport.TEST_PASSWORD)

        assertArrayEquals(data, opened)
    }

    // --- Hkdf: инвариантные свойства (round-trip неприменим к одностороннему KDF) -----------

    /** Hkdf: одинаковые входы дают идентичный выход — KDF детерминирован. */
    @Test
    fun hkdf_deterministic_sameInputsSameOutput() {
        val ikm = ByteArray(32) { it.toByte() }
        val info = "app.safenote/db/v1".toByteArray(Charsets.US_ASCII)

        val first = Hkdf.derive(ikm = ikm, salt = null, info = info, length = 32)
        val second = Hkdf.derive(ikm = ikm, salt = null, info = info, length = 32)

        assertArrayEquals(first, second)
    }

    /**
     * Hkdf: разный info (домен) при одном ikm даёт разные подключи — доменное разделение,
     * на котором держится изоляция ключей БД и аудио (компрометация одного не раскрывает другой).
     */
    @Test
    fun hkdf_domainSeparation_differentInfoDifferentKey() {
        val ikm = ByteArray(32) { 0x11 }

        val dbKey = Hkdf.derive(ikm, salt = null, "app.safenote/db/v1".toByteArray(Charsets.US_ASCII), 32)
        val audioKey = Hkdf.derive(ikm, salt = null, "app.safenote/audio/v1".toByteArray(Charsets.US_ASCII), 32)

        assertFalse(
            "Подключи разных доменов не должны совпадать",
            dbKey.contentEquals(audioKey)
        )
    }

    /**
     * Hkdf: выход имеет ровно запрошенную длину для разных значений, включая
     * нижнюю (1), типичные (32, 64) и верхнюю границу RFC 5869 (255 * 32 = 8160 байт).
     */
    @Test
    fun hkdf_outputHasExactRequestedLength() {
        val ikm = ByteArray(32) { 0x33 }
        val info = "len".toByteArray(Charsets.US_ASCII)

        for (length in intArrayOf(1, 32, 64, 255 * 32)) {
            val okm = Hkdf.derive(ikm, salt = null, info = info, length = length)
            assertEquals("HKDF должен вернуть ровно $length байт", length, okm.size)
        }
    }

    /**
     * Hkdf: запрошенная длина вне диапазона RFC 5869 (≤ 0 либо > 255*HashLen) отвергается
     * требованием [Hkdf.derive] — контракт длины не обходится молча выдачей мусора/пустоты.
     */
    @Test
    fun hkdf_invalidLength_isRejected() {
        val ikm = ByteArray(32) { 0x44 }
        val info = "len".toByteArray(Charsets.US_ASCII)
        for (badLength in intArrayOf(0, -1, 255 * 32 + 1)) {
            val threw = try {
                Hkdf.derive(ikm, salt = null, info = info, length = badLength)
                false
            } catch (e: IllegalArgumentException) {
                true   // ожидаемо: require(length in 1..255*HashLen) в Hkdf.derive
            }
            assertTrue("HKDF должен отвергать недопустимую длину $badLength", threw)
        }
    }
}
