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
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Одностороннее хеширование короткого секрета (PIN блокировки приложения).
 *
 * PIN НЕ хранится в восстановимом виде: сохраняем `[соль(16)][Argon2id-хеш(32)]`,
 * при проверке пересчитываем хеш с той же солью и сравниваем за постоянное время.
 * Это надёжнее обратимого шифрования: даже при доступе к ключам приложения сам PIN
 * из хранилища не извлекается, а перебор замедлен Argon2id.
 */
object PinHasher {

    private const val SALT_LEN = 16
    private const val HASH_LEN = 32
    // PIN короткий и проверяется на «горячем» пути разблокировки (в т.ч. на слабых
    // устройствах), поэтому параметры умереннее, чем у бэкапа: m=32 MiB, t=2 — выше
    // floor OWASP и достаточно при UI-троттлинге попыток.
    private const val MEMORY_KIB = 32_768  // 32 MiB
    private const val ITERATIONS = 2
    private const val PARALLELISM = 1

    /** Возвращает `[соль(16)][хеш(32)]` для нового PIN. */
    fun hash(pin: String): ByteArray {
        val salt = ByteArray(SALT_LEN).also { SecureRandom().nextBytes(it) }
        return salt + derive(pin, salt)
    }

    /** Проверяет [pin] против ранее сохранённого [stored] (`[соль][хеш]`); constant-time. */
    fun verify(pin: String, stored: ByteArray): Boolean {
        if (stored.size != SALT_LEN + HASH_LEN) return false
        val salt = stored.copyOfRange(0, SALT_LEN)
        val expected = stored.copyOfRange(SALT_LEN, stored.size)
        val actual = derive(pin, salt)
        return MessageDigest.isEqual(expected, actual).also {   // сравнение за постоянное время
            actual.fill(0)     // затираем транзитные буферы хеша после сравнения
            expected.fill(0)
        }
    }

    private fun derive(pin: String, salt: ByteArray): ByteArray {
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withMemoryAsKB(MEMORY_KIB)
            .withIterations(ITERATIONS)
            .withParallelism(PARALLELISM)
            .build()
        val generator = Argon2BytesGenerator().apply { init(params) }
        val out = ByteArray(HASH_LEN)
        val pw = pin.toCharArray()
        try {
            generator.generateBytes(pw, out)
            return out
        } finally {
            pw.fill(' ')   // затираем копию PIN (в т.ч. на пути исключения)
        }
    }
}
