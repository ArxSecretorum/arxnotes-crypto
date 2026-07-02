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

import org.junit.Assert.assertNull
import org.junit.Test
import java.util.Random

/**
 * Фазз для [AeadBlob.open] на недоверенном вводе.
 *
 * С СЫРЫМ AES-ключом (не из Keystore) `open` по контракту НИКОГДА не бросает исключение
 * и НИКОГДА не отдаёт частичные данные — на любом мусоре возвращает `null`. (Ложное
 * совпадение 128-битного GCM-тега имеет вероятность ~2^-128 и на практике не встречается,
 * поэтому уникальный «успех» на случайных байтах здесь невозможен.)
 *
 * Дополняет интегрити-тесты `AeadIntegrityTest` именно случайным/битым потоком байт.
 */
class AeadFuzzTest {

    private val key = TestSupport.testAesKey()
    private val version: Byte = 1

    /** Произвольные байты разной длины (в т.ч. короче минимума) → null, без throw/hang. */
    @Test
    fun open_neverThrows_onArbitraryBytes() {
        val rnd = Random(0xA11CE)
        repeat(20_000) {
            val blob = ByteArray(rnd.nextInt(80)).also { rnd.nextBytes(it) }
            assertNull(AeadBlob.open(key, blob, version))
        }
    }

    /** Корректный байт версии + случайный хвост → всё равно null (GCM-тег не сойдётся). */
    @Test
    fun open_validVersionByte_randomRest_returnsNull() {
        val rnd = Random(0xBEEF)
        repeat(20_000) {
            val blob = ByteArray(1 + AeadBlob.IV_SIZE + 16 + rnd.nextInt(32))
            rnd.nextBytes(blob)
            blob[0] = version
            assertNull(AeadBlob.open(key, blob, version))
        }
    }

    /** Граничные длины вокруг минимума: ничего не бросает, всё null. */
    @Test
    fun open_boundaryLengths_returnNull() {
        for (len in 0..(1 + AeadBlob.IV_SIZE + 16 + 4)) {
            assertNull("len=$len", AeadBlob.open(key, ByteArray(len), version))
        }
    }
}
