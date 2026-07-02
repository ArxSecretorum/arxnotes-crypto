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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * Свойство «уникальность IV/nonce» для AES-256-GCM примитивов модуля `:crypto`.
 *
 * Для GCM повтор пары (ключ, IV) на двух разных шифртекстах — катастрофа: он
 * полностью ломает конфиденциальность и позволяет подделать тег. Поэтому при
 * фиксированном ключе IV ОБЯЗАН быть уникальным на каждый вызов, и притом
 * криптослучайным — не предсказуемым счётчиком, который при перезапуске процесса
 * начал бы заново с нуля и выдал бы те же значения.
 *
 * Здесь мы проверяем НАБЛЮДАЕМОЕ свойство: точную уникальность множества IV/nonce
 * и их неравенство тривиальному значению (нулям/счётчику от нуля). Что именно за
 * генератор стоит внутри (SecureRandom и т.п.) напрямую не проверяется — только
 * его следствия. Тесты детерминированы: утверждаются строгие свойства (точные
 * размеры множеств, неравенство нулю), без статистических порогов «примерно».
 *
 * [AeadBlob] (дешёвый AES-GCM) гоняем на больших N; [BackupCrypto.encrypt]
 * запускает Argon2id m=64MiB,t=3 на каждый вызов и потому берётся малым N —
 * для проверки уникальности соли/nonce этого достаточно.
 */
class NonceUniquenessTest {

    /** Версия самоописывающего блоба — для теста подойдёт любой байт. */
    private val blobVersion: Byte = 1

    /** Синтетический детерминированный AES-ключ; см. [TestSupport.testAesKey]. */
    private val key = TestSupport.testAesKey()

    /** Фиксированный открытый текст: повторяем один и тот же вход, меняться должен только IV. */
    private val plaintext = "одинаковые данные / same plaintext".toByteArray()

    /** Извлечь IV из блоба формата [version:1][IV:12][ct+tag]; ключ для множеств — список байт. */
    private fun ivOf(blob: ByteArray): List<Byte> =
        blob.copyOfRange(1, 1 + AeadBlob.IV_SIZE).toList()

    /**
     * Свойство: при N=10000 запечатываниях одних и тех же данных тем же ключом
     * ни один IV не повторяется (множество IV имеет размер ровно N).
     */
    @Test
    fun aeadBlob_iv_isUniqueAcross10000Seals() {
        val n = 10_000
        val seenIvs = HashSet<List<Byte>>(n * 2)
        repeat(n) {
            val blob = AeadBlob.seal(key, plaintext, blobVersion)
            seenIvs.add(ivOf(blob))
        }
        // Любой повтор схлопнул бы множество → размер стал бы < N.
        assertEquals("IV должен быть уникален на каждый seal (повтор IV ломает GCM)", n, seenIvs.size)
    }

    /**
     * Свойство: IV не является счётчиком, стартующим с нуля при каждом «запуске».
     *
     * Зачем именно две партии: счётчик, обнуляемый на старте, выдал бы в обеих
     * партиях одну и ту же последовательность 0,1,2,… → при объединении были бы
     * массовые коллизии (уникальных оказалось бы M, а не 2*M). Криптослучайный IV
     * коллизий между партиями практически не даёт. Дополнительно убеждаемся, что
     * ни один IV не равен 12 нулевым байтам — нулём начинался бы счётчик от нуля.
     */
    @Test
    fun aeadBlob_iv_isNotZeroBasedCounter() {
        val m = 2_000
        val zeroIv = List(AeadBlob.IV_SIZE) { 0.toByte() }

        // Две независимые партии, имитирующие два отдельных «запуска» шифрования.
        val combined = HashSet<List<Byte>>(2 * m * 2)
        repeat(2) {
            repeat(m) {
                val iv = ivOf(AeadBlob.seal(key, plaintext, blobVersion))
                assertFalse("IV не должен быть 12 нулями (так начинался бы счётчик от нуля)", iv == zeroIv)
                combined.add(iv)
            }
        }

        // Счётчик-от-нуля дал бы здесь ровно M уникальных; криптослучайный IV — 2*M.
        assertEquals(
            "IV двух «запусков» не должны пересекаться — иначе это предсказуемый счётчик от нуля",
            2 * m,
            combined.size
        )
    }

    /**
     * Свойство: [BackupCrypto.encrypt] на одинаковых данных и пароле каждый раз даёт
     * свежие соль и nonce — все соли уникальны, все nonce уникальны, ни один nonce
     * не равен нулям. Это гарантирует разный ключ и разный GCM-IV для каждого бэкапа.
     *
     * N намеренно мало: encrypt запускает Argon2id (m=64MiB, t=3) на каждый вызов.
     * Для проверки уникальности соли/nonce малого N достаточно.
     */
    @Test
    fun backupCrypto_saltAndNonce_areUniqueAndRandom() {
        val n = 200
        // Смещения внутри файла бэкапа: magic|ver|kdf|memKiB|iters|par|salt[12..44)|nonce[44..56).
        val saltStart = 12
        val saltEnd = 44
        val nonceStart = 44
        val nonceEnd = 56
        val zeroNonce = List(nonceEnd - nonceStart) { 0.toByte() }

        val salts = HashSet<List<Byte>>(n * 2)
        val nonces = HashSet<List<Byte>>(n * 2)
        repeat(n) {
            val blob = BackupCrypto.encrypt(plaintext, TestSupport.TEST_PASSWORD)
            val nonce = blob.copyOfRange(nonceStart, nonceEnd).toList()
            assertFalse("nonce не должен быть 12 нулями", nonce == zeroNonce)
            salts.add(blob.copyOfRange(saltStart, saltEnd).toList())
            nonces.add(nonce)
        }

        // Любое повторение соли или nonce схлопнуло бы соответствующее множество.
        assertEquals("Соль бэкапа должна быть уникальной на каждый encrypt", n, salts.size)
        assertEquals("Nonce бэкапа должен быть уникальным на каждый encrypt", n, nonces.size)
    }
}
