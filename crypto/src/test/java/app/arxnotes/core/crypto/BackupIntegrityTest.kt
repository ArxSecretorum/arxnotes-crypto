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

import app.arxnotes.core.crypto.TestSupport.TEST_PASSWORD
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.nio.ByteBuffer
import java.util.Random

/**
 * Тесты ЦЕЛОСТНОСТИ и негативные сценарии для [BackupCrypto]
 * (формат файла бэкапа: Argon2id + AES-256-GCM).
 *
 * Главное проверяемое свойство: файл бэкапа — это НЕДОВЕРЕННЫЙ вход. При любой порче,
 * неверном пароле, неподдерживаемом/искажённом заголовке или произвольном мусоре
 * [BackupCrypto.decrypt] обязан вернуть `null` — не бросить исключение, не зависнуть
 * и не отдать частичные данные. Дополнительно проверяется защита от DoS: абсурдные
 * параметры Argon2 из заголовка отсекаются ДО запуска дорогого KDF.
 *
 * Раскладка заголовка (HEADER_SIZE = 56 байт):
 *
 *     [0..3]   magic "SNBK"
 *     [4]      version = 2
 *     [5]      kdf id  = 1 (Argon2id)
 *     [6..9]   memKiB (big-endian int)
 *     [10]     iterations
 *     [11]     parallelism
 *     [12..43] соль (32)
 *     [44..55] nonce (12)
 *     [56..]   шифртекст + GCM-тег (16+)
 *
 * Argon2id здесь намеренно дорогой (m=64 MiB, t=3), поэтому валидный `encrypt`
 * выполняется ОДИН раз в [setUpOnce], а все тесты тамперинга портят его копии.
 */
class BackupIntegrityTest {

    companion object {
        // Смещения внутри заголовка — держим как именованные константы ради читаемости тестов.
        private const val OFFSET_MAGIC = 0
        private const val OFFSET_VERSION = 4
        private const val OFFSET_KDF = 5
        private const val OFFSET_MEMORY_KIB = 6
        private const val OFFSET_ITERATIONS = 10
        private const val OFFSET_PARALLELISM = 11
        private const val OFFSET_SALT = 12      // [12..43]
        private const val OFFSET_NONCE = 44     // [44..55]
        private const val HEADER_SIZE = 56

        /** Эталонный открытый текст; смесь алфавитов и эмодзи проверяет байтовую честность. */
        private val PLAINTEXT = "резервная копия 🔐 mixed текст".toByteArray()

        /**
         * ЕДИНСТВЕННЫЙ валидный блок бэкапа на весь класс.
         *
         * Создаётся один раз: каждый `encrypt` гоняет Argon2id (m=64 MiB, t=3), а тесты
         * целостности работают на КОПИЯХ этого блока — поэтому повторных дорогих
         * шифрований не происходит. Сам decrypt валидного блока в негативном наборе не вызывается.
         */
        private lateinit var validBlob: ByteArray

        @BeforeClass
        @JvmStatic
        fun setUpOnce() {
            validBlob = BackupCrypto.encrypt(PLAINTEXT, TEST_PASSWORD)
        }
    }

    /** Копия эталонного блока — чтобы порча в одном тесте не влияла на остальные. */
    private fun freshBlob(): ByteArray = validBlob.copyOf()

    /** Копия эталонного блока с инвертированным одним битом в байте [index]. */
    private fun blobWithFlippedBit(index: Int): ByteArray =
        freshBlob().also { it[index] = (it[index].toInt() xor 0x01).toByte() }

    /** Неверный пароль → GCM-тег не сходится → null (исходный текст не выдаётся). */
    @Test
    fun wrongPassword_returnsNull() {
        assertNull(BackupCrypto.decrypt(freshBlob(), TEST_PASSWORD + "x"))
    }

    /** Флип бита в области шифртекста/тега (последний байт) → провал тега → null. */
    @Test
    fun flippedCiphertextOrTagBit_returnsNull() {
        val blob = freshBlob()
        blob[blob.size - 1] = (blob[blob.size - 1].toInt() xor 0x01).toByte()
        assertNull(BackupCrypto.decrypt(blob, TEST_PASSWORD))
    }

    /** Модификация СОЛИ → Argon2 выводит другой ключ → GCM-тег под ним не подтвердится → null. */
    @Test
    fun modifiedSalt_returnsNull() {
        // Любой байт внутри соли [12..43]; берём первый.
        assertNull(BackupCrypto.decrypt(blobWithFlippedBit(OFFSET_SALT), TEST_PASSWORD))
    }

    /** Модификация NONCE → GCM считает тег для другого nonce → расхождение → null. */
    @Test
    fun modifiedNonce_returnsNull() {
        // Любой байт внутри nonce [44..55]; берём первый.
        assertNull(BackupCrypto.decrypt(blobWithFlippedBit(OFFSET_NONCE), TEST_PASSWORD))
    }

    /** Усечение (10 байт и HEADER-1) → данных не хватает даже на заголовок/тег → null. */
    @Test
    fun truncatedData_returnsNull() {
        assertNull("усечён до 10 байт", BackupCrypto.decrypt(freshBlob().copyOf(10), TEST_PASSWORD))
        assertNull(
            "усечён до HEADER-1",
            BackupCrypto.decrypt(freshBlob().copyOf(HEADER_SIZE - 1), TEST_PASSWORD)
        )
    }

    /** Неверный magic (blob[0]='X') → формат не распознан → null. */
    @Test
    fun wrongMagic_returnsNull() {
        val blob = freshBlob().also { it[OFFSET_MAGIC] = 'X'.code.toByte() }
        assertNull(BackupCrypto.decrypt(blob, TEST_PASSWORD))
    }

    /** Неподдерживаемая версия (2 → 1) → отказ по версии заголовка → null. */
    @Test
    fun unsupportedVersion_returnsNull() {
        val blob = freshBlob().also { it[OFFSET_VERSION] = 1 }
        assertNull(BackupCrypto.decrypt(blob, TEST_PASSWORD))
    }

    /** Неизвестный kdf id (1 → 9) → нечем выводить ключ → null. */
    @Test
    fun unknownKdfId_returnsNull() {
        val blob = freshBlob().also { it[OFFSET_KDF] = 9 }
        assertNull(BackupCrypto.decrypt(blob, TEST_PASSWORD))
    }

    /**
     * Защита от DoS: абсурдные параметры Argon2 из заголовка отсекаются ДО запуска KDF.
     *
     * Ставим memKiB = Int.MAX_VALUE (~2 ТиБ в KiB). Если бы Argon2 реально стартовал,
     * это были бы секунды работы и попытка выделить гигантскую память (вплоть до OOM).
     * Корректная реализация валидирует параметры заголовка заранее и возвращает `null`
     * мгновенно — поэтому проверяем, что вызов уложился в порог < 1000 мс.
     */
    @Test
    fun absurdArgon2Params_rejectedInstantly_withoutRunningKdf() {
        val evil = freshBlob()
        ByteBuffer.wrap(evil).putInt(OFFSET_MEMORY_KIB, Int.MAX_VALUE)
        val startMs = System.currentTimeMillis()
        assertNull(BackupCrypto.decrypt(evil, TEST_PASSWORD))
        val elapsedMs = System.currentTimeMillis() - startMs
        // Мгновенный отказ означает, что дорогой Argon2 так и не был запущен.
        assertTrue("decrypt занял $elapsedMs мс — похоже, Argon2 реально запустился", elapsedMs < 1000)
    }

    /**
     * Кламп параметра iterations: значение выше потолка (MAX_ITERATIONS = 10) отсекается
     * диапазонной проверкой ДО запуска Argon2 → null. Дополняет DoS-тест по памяти, закрывая
     * второй параметр стоимости (а не только memory).
     */
    @Test
    fun headerIterationsAboveMax_returnsNull() {
        val evil = freshBlob().also { it[OFFSET_ITERATIONS] = 11 }   // потолок = 10
        assertNull(BackupCrypto.decrypt(evil, TEST_PASSWORD))
    }

    /**
     * Кламп параметра parallelism: значение выше потолка (MAX_PARALLELISM = 4) отсекается → null.
     * Закрывает третий параметр стоимости Argon2 из недоверенного заголовка.
     */
    @Test
    fun headerParallelismAboveMax_returnsNull() {
        val evil = freshBlob().also { it[OFFSET_PARALLELISM] = 5 }   // потолок = 4
        assertNull(BackupCrypto.decrypt(evil, TEST_PASSWORD))
    }

    /**
     * Нулевые KDF-параметры недопустимы: допустимый диапазон — 1..MAX, поэтому memory=0,
     * iterations=0 и parallelism=0 каждый по отдельности должны давать null (нижняя граница клампа).
     */
    @Test
    fun headerZeroParams_returnsNull() {
        val zeroMemory = freshBlob().also { ByteBuffer.wrap(it).putInt(OFFSET_MEMORY_KIB, 0) }
        assertNull("memory=0 должно отвергаться", BackupCrypto.decrypt(zeroMemory, TEST_PASSWORD))

        val zeroIters = freshBlob().also { it[OFFSET_ITERATIONS] = 0 }
        assertNull("iterations=0 должно отвергаться", BackupCrypto.decrypt(zeroIters, TEST_PASSWORD))

        val zeroPar = freshBlob().also { it[OFFSET_PARALLELISM] = 0 }
        assertNull("parallelism=0 должно отвергаться", BackupCrypto.decrypt(zeroPar, TEST_PASSWORD))
    }

    /**
     * Фазз: на произвольных байтах decrypt никогда не бросает и не зависает, всегда null.
     *
     * Argon2 здесь практически не запускается: KDF стартует лишь если случайно совпали
     * magic+версия+kdf и параметры попали в допустимые диапазоны — на случайных данных
     * это исчезающе маловероятно, поэтому фаззинг быстрый.
     */
    @Test
    fun decrypt_neverThrows_onArbitraryBytes() {
        val rnd = Random(0xC0FFEE)   // фиксированное зерно → воспроизводимый прогон
        repeat(5000) {
            val data = ByteArray(rnd.nextInt(200)).also { rnd.nextBytes(it) }
            assertNull(BackupCrypto.decrypt(data, TEST_PASSWORD))
        }
    }

    /**
     * Фазз с валидным заголовком: тело (соль/nonce/шифртекст) затёрто мусором → null.
     *
     * Это заставляет реализацию пройти разбор заголовка и (т.к. magic/версия/параметры
     * корректны) фактически вывести ключ Argon2 — но GCM-тег на испорченном теле не сойдётся.
     * Несколько повторов с разным мусором; ни один не должен бросить или зависнуть.
     */
    @Test
    fun decrypt_neverThrows_onValidHeaderRandomBody() {
        val rnd = Random(0xBADC0DE)
        repeat(3) {
            val forged = freshBlob()
            for (i in HEADER_SIZE until forged.size) forged[i] = rnd.nextInt().toByte()
            assertNull(BackupCrypto.decrypt(forged, TEST_PASSWORD))
        }
    }

    /** Пустой и заведомо частичный/битый вход → null, без краша. */
    @Test
    fun emptyAndClearlyBrokenInput_returnsNull() {
        assertNull("пустой массив", BackupCrypto.decrypt(ByteArray(0), TEST_PASSWORD))
        assertNull("один байт", BackupCrypto.decrypt(byteArrayOf(0x53), TEST_PASSWORD)) // 'S' из SNBK, но обрыв
        assertNull("частичный заголовок", BackupCrypto.decrypt(ByteArray(HEADER_SIZE / 2), TEST_PASSWORD))
    }
}
