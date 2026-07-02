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

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * Known-Answer Tests (KAT) — примитивы сверяются с независимыми эталонами.
 *
 * Round-trip доказывает «расшифровка отменяет шифрование», но НЕ доказывает, что
 * под капотом стоит именно стандартный алгоритм с правильными константами. KAT
 * закрывает этот пробел: HKDF проверяется против официальных тест-векторов
 * RFC 5869, Appendix A; Argon2id — против независимого прогона BouncyCastle.
 *
 * О HKDF и пустой соли (важно для воспроизводимости):
 * RFC 5869 §2.2 определяет отсутствующую/пустую соль как «строку из HashLen нулей».
 * Наша [Hkdf.derive] при `salt = null` подставляет ровно это (32 нулевых байта),
 * поэтому путь `salt = null` даёт КАНОНИЧЕСКОЕ значение OKM для входов с пустой солью —
 * это и есть опубликованный вектор Test Case 3. Передавать сюда `ByteArray(0)` НЕЛЬЗЯ:
 * HMAC в JCA отвергает пустой ключ (`IllegalArgumentException: Empty key`), поэтому
 * единственный корректный способ прогнать TC3 — `salt = null`. См. также [hkdf_emptySalt_isRejected].
 *
 * Об Argon2id: проверяется ОФИЦИАЛЬНЫМ вектором RFC 9106 §5.3 (точные байты вектора), плюс
 * детерминизмом и чувствительностью к каждому параметру через прямой прогон BouncyCastle
 * (тот же движок, что в продакшне). Корректность пересчёта параметров Argon2id из заголовка
 * дополнительно покрыта в `PinHasherTest`.
 *
 * Все входы — синтетические/публичные тест-векторы; реальных секретов нет.
 */
class KnownAnswerTest {

    // --- HKDF-SHA256: официальные векторы RFC 5869, Appendix A ----------------------------

    /**
     * RFC 5869, Appendix A.1 — Test Case 1 (HKDF-SHA256, базовые входы).
     * Эталонные IKM/salt/info → опубликованный OKM длиной 42 байта.
     */
    @Test
    fun rfc5869_testCase1_basic() {
        val ikm = TestSupport.hex("0b".repeat(22))
        val salt = TestSupport.hex("000102030405060708090a0b0c")
        val info = TestSupport.hex("f0f1f2f3f4f5f6f7f8f9")
        val expectedOkm = TestSupport.hex(
            "3cb25f25faacd57a90434f64d0362f2a" +
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                "34007208d5b887185865"
        )

        val okm = Hkdf.derive(ikm = ikm, salt = salt, info = info, length = 42)

        assertArrayEquals(expectedOkm, okm)
    }

    /**
     * RFC 5869, Appendix A.2 — Test Case 2 (HKDF-SHA256, длинные входы).
     * IKM/salt/info по 80 байт, OKM длиной 82 байта — проверяет многоблочный expand.
     */
    @Test
    fun rfc5869_testCase2_longInputs() {
        val ikm = TestSupport.hex((0x00..0x4f).joinToString("") { "%02x".format(it) })
        val salt = TestSupport.hex((0x60..0xaf).joinToString("") { "%02x".format(it) })
        val info = TestSupport.hex((0xb0..0xff).joinToString("") { "%02x".format(it) })
        val expectedOkm = TestSupport.hex(
            "b11e398dc80327a1c8e7f78c596a4934" +
                "4f012eda2d4efad8a050cc4c19afa97c" +
                "59045a99cac7827271cb41c65e590e09" +
                "da3275600c2f09b8367793a9aca3db71" +
                "cc30c58179ec3e87c14c01d5c1f3434f" +
                "1d87"
        )

        val okm = Hkdf.derive(ikm = ikm, salt = salt, info = info, length = 82)

        assertArrayEquals(expectedOkm, okm)
    }

    /**
     * RFC 5869, Appendix A.3 — Test Case 3 (HKDF-SHA256, пустые salt и info).
     *
     * TC3 задаёт salt = "" (пусто). RFC §2.2 трактует это как HashLen нулей, что в точности
     * соответствует пути [Hkdf.derive] с `salt = null`. Поэтому здесь передаём `salt = null`
     * и сверяемся с опубликованным OKM — это корректная проверка вектора, а не подгонка:
     * полученное значение и есть каноническая величина TC3.
     */
    @Test
    fun rfc5869_testCase3_emptySaltAndInfo() {
        val ikm = TestSupport.hex("0b".repeat(22))
        val emptyInfo = ByteArray(0)
        val expectedOkm = TestSupport.hex(
            "8da4e775a563c18f715f802a063c5a31" +
                "b8a11f5c5ee1879ec3454e5f3c738d2d" +
                "9d201395faa4b61a96c8"
        )

        // salt = null → 32 нулевых байта = RFC-каноническая «пустая» соль для TC3.
        val okm = Hkdf.derive(ikm = ikm, salt = null, info = emptyInfo, length = 42)

        assertArrayEquals(expectedOkm, okm)
    }

    /**
     * Документирует ограничение реализации: явно пустой массив соли (`ByteArray(0)`) НЕ
     * принимается — JCA HMAC требует непустой ключ. TC3 поэтому проверяется через `salt = null`
     * (см. [rfc5869_testCase3_emptySaltAndInfo]), а не через `ByteArray(0)`.
     */
    @Test
    fun hkdf_emptySalt_isRejected() {
        val ikm = TestSupport.hex("0b".repeat(22))

        val threw = try {
            Hkdf.derive(ikm = ikm, salt = ByteArray(0), info = ByteArray(0), length = 42)
            false
        } catch (e: IllegalArgumentException) {
            // Ожидаемо: SecretKeySpec/HMAC отвергает пустой ключ ("Empty key").
            true
        }

        assertEquals("Пустая соль (ByteArray(0)) должна отвергаться JCA HMAC", true, threw)
    }

    // --- Argon2id: официальный вектор RFC 9106 + детерминизм/чувствительность --------------

    /**
     * Argon2id против ОФИЦИАЛЬНОГО тест-вектора RFC 9106, §5.3 (точные байты из RFC).
     * Параметры вектора: версия 19 (v1.3), m=32 KiB, t=3, p=4, tag=32, с secret и
     * associated data. Полноценный KAT на сам примитив Argon2id того движка (BouncyCastle),
     * что используется в продакшне: расхождение байта означало бы неверную реализацию KDF.
     */
    @Test
    fun argon2id_rfc9106_officialTestVector() {
        val password = ByteArray(32) { 0x01 }
        val salt = ByteArray(16) { 0x02 }
        val secret = ByteArray(8) { 0x03 }
        val associatedData = ByteArray(12) { 0x04 }
        val expectedTag = TestSupport.hex(
            "0d640df58d78766c08c037a34a8b53c9" +
                "d01ef0452d75b65eb52520e96b01e659"
        )

        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withSecret(secret)
            .withAdditional(associatedData)
            .withMemoryAsKB(32)
            .withIterations(3)
            .withParallelism(4)
            .build()
        val out = ByteArray(32)
        Argon2BytesGenerator().apply { init(params) }.generateBytes(password, out)

        assertArrayEquals(expectedTag, out)
    }

    // Облегчённые параметры строго для тестов чувствительности (быстрый прогон): m=32 MiB, t=2, p=1, v1.3.
    // Это НЕ продакшн-параметры — подобраны так, чтобы тесты чувствительности шли быстро.
    private val testMemoryKib = 32_768
    private val testIterations = 2
    private val testParallelism = 1
    private val outLen = 32

    /**
     * Argon2id: одинаковые (пароль, соль, параметры) дают идентичный 32-байтовый выход
     * при двух независимых прогонах — KDF детерминирован.
     */
    @Test
    fun argon2id_isDeterministic() {
        val salt = ByteArray(16) { it.toByte() }

        val first = argon2id("pin".toCharArray(), salt, testMemoryKib, testIterations)
        val second = argon2id("pin".toCharArray(), salt, testMemoryKib, testIterations)

        assertArrayEquals(first, second)
    }

    /**
     * Argon2id: изменение числа итераций (t: 2 → 3) меняет выход — параметр стоимости
     * реально влияет на результат (а не игнорируется реализацией).
     */
    @Test
    fun argon2id_iterationsAffectOutput() {
        val salt = ByteArray(16) { it.toByte() }

        val base = argon2id("pin".toCharArray(), salt, testMemoryKib, iterations = 2)
        val moreIters = argon2id("pin".toCharArray(), salt, testMemoryKib, iterations = 3)

        assertFalse("Смена t (2→3) должна менять выход", base.contentEquals(moreIters))
    }

    /**
     * Argon2id: изменение объёма памяти (m: 32 → 64 MiB) меняет выход — параметр памяти
     * реально влияет на результат.
     */
    @Test
    fun argon2id_memoryAffectsOutput() {
        val salt = ByteArray(16) { it.toByte() }

        val base = argon2id("pin".toCharArray(), salt, memoryKib = 32_768, iterations = testIterations)
        val moreMemory = argon2id("pin".toCharArray(), salt, memoryKib = 65_536, iterations = testIterations)

        assertFalse("Смена m должна менять выход", base.contentEquals(moreMemory))
    }

    /**
     * Argon2id: другая соль даёт другой выход при том же пароле и параметрах —
     * соль реально участвует в выводе (защита от одинаковых хешей у одинаковых паролей).
     */
    @Test
    fun argon2id_saltAffectsOutput() {
        val saltA = ByteArray(16) { it.toByte() }
        val saltB = ByteArray(16) { (it + 1).toByte() }

        val withSaltA = argon2id("pin".toCharArray(), saltA, testMemoryKib, testIterations)
        val withSaltB = argon2id("pin".toCharArray(), saltB, testMemoryKib, testIterations)

        assertFalse("Разная соль должна давать разный выход", withSaltA.contentEquals(withSaltB))
    }

    /**
     * Прямой, независимый прогон Argon2id через BouncyCastle (тот же движок, что и в
     * продакшне) с фиксированными v1.3/p=1 и заданными m/t. Возвращает [outLen] байт.
     */
    private fun argon2id(password: CharArray, salt: ByteArray, memoryKib: Int, iterations: Int): ByteArray {
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withMemoryAsKB(memoryKib)
            .withIterations(iterations)
            .withParallelism(testParallelism)
            .build()
        val generator = Argon2BytesGenerator().apply { init(params) }
        return ByteArray(outLen).also { generator.generateBytes(password, it) }
    }
}
