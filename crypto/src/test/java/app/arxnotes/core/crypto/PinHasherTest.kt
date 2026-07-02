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

import app.arxnotes.core.crypto.TestSupport.TEST_PIN
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Тесты [PinHasher] — одностороннего хеша PIN блокировки приложения.
 *
 * Проверяется контракт хранилища `[соль(16)][Argon2id-хеш(32)]` (48 байт): корректный
 * приём/отклонение PIN, посоленность (на каждый вызов новая соль) и устойчивость к битому
 * входу при проверке. Ключевой тест — KAT на параметры: storedHash пересчитывается
 * независимой реализацией Argon2id (BouncyCastle) с ЗАЯВЛЕННЫМИ параметрами и сверяется
 * байт-в-байт, поэтому любое расхождение в m/t/p/версии в продакшне будет поймано без
 * правок самого продакшн-кода.
 *
 * Свойство constant-time. Сравнение хешей в [PinHasher.verify] выполняется через
 * `java.security.MessageDigest.isEqual` — это гарантия времени выполнения уровня JDK, а не
 * наша собственная реализация. Отдельным таймингом она НЕ проверяется намеренно: такие
 * тесты флакают на разделяемом CI (джиттер планировщика/JIT/GC превышает измеряемую разницу)
 * и дают ложные падения. Вместо тайминга ниже есть поведенческий тест, фиксирующий
 * отсутствие раннего ложного приёма для PIN, отличающихся в разных позициях (он НЕ
 * доказывает постоянство времени, см. комментарий в самом тесте).
 *
 * Argon2id затратен (32 MiB на вызов), поэтому число вызовов [PinHasher.hash] здесь
 * намеренно держится небольшим: read-only тесты переиспользуют один общий блоб [stored].
 */
class PinHasherTest {

    // Объявленные размеры PIN-хеша (из PinHasher): соль 16 Б, хеш 32 Б, итого 48 Б.
    private val saltLen = 16
    private val hashLen = 32
    private val blobLen = saltLen + hashLen

    // Параметры Argon2id, заявленные в коде/доке PinHasher; используются для KAT-пересчёта.
    private val memoryKib = 32_768 // 32 MiB
    private val iterations = 2
    private val parallelism = 1

    /** Корректный PIN, проверенный против собственного хеша, принимается. */
    @Test
    fun verify_acceptsCorrectPin() {
        assertTrue("hash затем verify тем же PIN должны давать совпадение", PinHasher.verify(TEST_PIN, stored))
    }

    /** Неверный PIN (в т.ч. пустой) отвергается при проверке против чужого хеша. */
    @Test
    fun verify_rejectsWrongPin() {
        assertFalse("другой PIN не должен проходить проверку", PinHasher.verify("9999", stored))
        assertFalse("пустой PIN не должен проходить проверку", PinHasher.verify("", stored))
    }

    /**
     * Хеш посолен: два вызова hash() для одного PIN дают РАЗНЫЕ 48-байтовые блобы
     * (разная случайная соль), при этом оба корректно проходят verify().
     */
    @Test
    fun hash_isSalted_differentBlobsSamePinBothVerify() {
        val first = PinHasher.hash(TEST_PIN)
        val second = PinHasher.hash(TEST_PIN)

        // Разная соль на каждый вызов => блобы не должны совпадать (защита от радужных таблиц
        // и от вывода, что у двух пользователей одинаковый PIN).
        assertFalse("два хеша одного PIN не должны быть байт-в-байт равны", first.contentEquals(second))

        // Несмотря на разные блобы, исходный PIN проходит проверку против каждого из них.
        assertTrue("первый блоб должен принимать исходный PIN", PinHasher.verify(TEST_PIN, first))
        assertTrue("второй блоб должен принимать исходный PIN", PinHasher.verify(TEST_PIN, second))
    }

    /** Длина результата hash() равна 48 байтам = соль(16) + хеш(32). */
    @Test
    fun hash_outputLength_isSaltPlusHash() {
        assertEquals("блоб должен быть соль(16) + хеш(32)", blobLen, stored.size)
    }

    /**
     * Битый [stored] (любая длина, отличная от 48) отвергается без бросков:
     * пустой, слишком короткий и на один байт длиннее ожидаемого.
     */
    @Test
    fun verify_rejectsMalformedStored() {
        // Длина != 48 — единственное, что verify обязан отбросить до запуска Argon2id.
        assertFalse("пустой stored должен отвергаться", PinHasher.verify(TEST_PIN, ByteArray(0)))
        assertFalse("слишком короткий stored должен отвергаться", PinHasher.verify(TEST_PIN, ByteArray(10)))
        assertFalse("stored длиной 49 (на 1 больше) должен отвергаться", PinHasher.verify(TEST_PIN, ByteArray(blobLen + 1)))
    }

    /**
     * KAT на параметры: storedHash, выданный продакшном, пересчитывается независимой
     * реализацией Argon2id (BouncyCastle) с ЗАЯВЛЕННЫМИ параметрами и должен совпасть
     * байт-в-байт.
     *
     * Зачем: если бы продакшн втихаря использовал другие m/t/p или версию Argon2, пересчёт
     * с заявленными параметрами не совпал бы и тест упал бы — это и есть проверка параметров
     * PIN-хеша без правок продакшн-кода.
     */
    @Test
    fun pinHash_usesDeclaredArgon2Params_verifiedByRecompute() {
        val salt = stored.copyOfRange(0, saltLen)
        val storedHash = stored.copyOfRange(saltLen, blobLen)

        val expected = recomputeArgon2id(TEST_PIN, salt, iterations)

        assertArrayEquals("storedHash должен совпасть с Argon2id по заявленным параметрам", expected, storedHash)
    }

    /**
     * Чувствительность к параметрам: тот же PIN и та же соль, но t=3 вместо t=2 дают
     * ДРУГОЙ хеш — подтверждает, что KAT выше реально привязан к числу итераций, а не
     * совпадает «случайно».
     */
    @Test
    fun pinHash_wrongParamsDoNotMatch() {
        val salt = stored.copyOfRange(0, saltLen)
        val storedHash = stored.copyOfRange(saltLen, blobLen)

        val wrong = recomputeArgon2id(TEST_PIN, salt, iterations + 1) // t=3

        assertFalse(
            "пересчёт с иным числом итераций не должен совпадать с продакшн-хешем",
            wrong.contentEquals(storedHash),
        )
    }

    /**
     * Поведенческая проверка отсутствия раннего ложного приёма: несколько неверных PIN,
     * отличающихся от верного в разных позициях (и по длине), все отвергаются.
     *
     * ВАЖНО: это НЕ доказательство constant-time (тайминг здесь не измеряется, см. KDoc
     * класса). Тест лишь фиксирует, что verify не «зашортит» на раннем расхождении и не
     * примет неверный PIN, у которого совпадает часть символов.
     */
    @Test
    fun verify_rejectsPinsDifferingAtVariousPositions() {
        // Верный PIN = TEST_PIN ("1234"). Отличие в первой, средней, последней позиции и по длине.
        val wrongPins = listOf("9234", "1294", "1239", "123", "12345")
        for (pin in wrongPins) {
            assertFalse("неверный PIN '$pin' не должен приниматься", PinHasher.verify(pin, stored))
        }
    }

    /**
     * Независимый пересчёт Argon2id той же конфигурацией параметров, что заявлена в PinHasher,
     * через BouncyCastle. Вынесен в helper, чтобы KAT и тест на чувствительность не дублировали
     * настройку и отличались только числом [iterations].
     */
    private fun recomputeArgon2id(pin: String, salt: ByteArray, iterations: Int): ByteArray {
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withMemoryAsKB(memoryKib)
            .withIterations(iterations)
            .withParallelism(parallelism)
            .build()
        val generator = Argon2BytesGenerator().apply { init(params) }
        val out = ByteArray(hashLen)
        generator.generateBytes(pin.toCharArray(), out)
        return out
    }

    companion object {
        /**
         * Один общий блоб `hash(TEST_PIN)` для всех read-only тестов (приём/отклонение,
         * длина, malformed, KAT). Считается один раз на класс, чтобы не платить за Argon2id
         * (32 MiB) в каждом тесте. Тест посоленности намеренно НЕ использует его — ему нужны
         * два свежих вызова hash().
         */
        private val stored: ByteArray = PinHasher.hash(TEST_PIN)
    }
}
